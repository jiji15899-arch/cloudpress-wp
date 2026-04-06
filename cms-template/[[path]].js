/**
 * CloudPress CMS — Cloudflare Pages Functions 통합 라우터
 * 파일: functions/[[path]].js
 *
 * Cloudflare Pages는 하이픈(-) 포함 폴더명을 Functions 경로로 인식하지 못함.
 * 예) functions/api/wp-json/wp/v2/posts.js → 404 반환
 * 해결: [[path]].js 단일 catch-all 라우터로 모든 API 요청을 처리
 *
 * 라우팅 테이블:
 *   OPTIONS *                          → CORS preflight
 *   POST   /wp-login/                  → 로그인
 *   GET    /wp-login/                  → 로그인 상태 확인
 *   GET    /wp-json/wp/v2/settings     → 사이트 설정
 *   POST   /wp-json/wp/v2/settings     → 설정 저장
 *   GET    /wp-json/wp/v2/posts        → 포스트 목록
 *   GET    /wp-json/wp/v2/posts/:id    → 포스트 상세
 *   POST   /wp-json/wp/v2/posts        → 포스트 생성
 *   PUT    /wp-json/wp/v2/posts/:id    → 포스트 수정
 *   DELETE /wp-json/wp/v2/posts/:id    → 포스트 삭제
 *   GET    /wp-json/wp/v2/pages        → 페이지 목록
 *   GET    /wp-json/wp/v2/pages/:id    → 페이지 상세
 *   POST   /wp-json/wp/v2/pages        → 페이지 생성
 *   PUT    /wp-json/wp/v2/pages/:id    → 페이지 수정
 *   GET    /wp-json/wp/v2/categories   → 카테고리 목록
 *   POST   /wp-json/wp/v2/categories   → 카테고리 생성
 *   GET    /wp-json/wp/v2/users        → 사용자 목록
 *   GET    /wp-json/wp/v2/users/me     → 현재 사용자
 *   PUT    /wp-json/wp/v2/users/me     → 프로필 수정
 */

// ─────────────────────────────────────────
// 공통 유틸
// ─────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-WP-Nonce',
};

const j = (d, s = 200, extra = {}) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra },
  });

const ok = (d = {}) => j({ ok: true, ...d });
const notFound = (msg = '찾을 수 없습니다.') => j({ code: 'rest_not_found', message: msg, data: { status: 404 } }, 404);
const forbidden = (msg = '권한이 없습니다.') => j({ code: 'rest_forbidden', message: msg, data: { status: 403 } }, 403);
const badRequest = (msg) => j({ code: 'rest_bad_request', message: msg, data: { status: 400 } }, 400);
const serverError = (e) => j({ code: 'rest_error', message: e?.message ?? String(e), data: { status: 500 } }, 500);

function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_cms_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.CMS_KV.get(`session:${t}`);
    if (!uid) return null;
    return await env.CMS_DB
      .prepare('SELECT id,login,display_name,email,role FROM wp_users WHERE id=?')
      .bind(uid).first();
  } catch { return null; }
}

function genToken(n = 40) {
  const c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  for (const b of a) s += c[b % c.length];
  return s;
}

function wpautop(text) {
  if (!text) return '';
  const t = text.trim();
  if (!t) return '';
  if (t.includes('<p>') || t.includes('<div>') || t.includes('<h')) return t;
  return t.split(/\n\n+/).map(p => `<p>${p.replace(/\n/g, '<br />')}</p>`).join('\n');
}

function buildLinkHeader(url, page, totalPages) {
  const links = [];
  if (page > 1) { url.searchParams.set('page', String(page - 1)); links.push(`<${url.toString()}>; rel="prev"`); }
  if (page < totalPages) { url.searchParams.set('page', String(page + 1)); links.push(`<${url.toString()}>; rel="next"`); }
  return links.join(', ');
}

// ─────────────────────────────────────────
// 메인 라우터
// ─────────────────────────────────────────
export async function onRequest({ request, env }) {
  const method = request.method.toUpperCase();
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, '') || '/';

  // OPTIONS — CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  try {
    // ── wp-login ──────────────────────────────────────
    if (path === '/wp-login' || path === '/wp-login/') {
      if (method === 'POST') return handleLogin(request, env);
      if (method === 'GET')  return handleLoginStatus(request, env);
      return j({ code: 'rest_no_route', message: '지원하지 않는 메서드' }, 405);
    }

    // ── wp-json/wp/v2 ─────────────────────────────────
    const API = '/wp-json/wp/v2';

    // settings
    if (path === `${API}/settings`) {
      if (method === 'GET')  return handleSettingsGet(request, env);
      if (method === 'POST' || method === 'PUT') return handleSettingsPost(request, env);
    }

    // posts/:id
    const postIdMatch = path.match(new RegExp(`^${API}/posts/([^/]+)$`));
    if (postIdMatch) {
      const id = postIdMatch[1];
      if (method === 'GET')    return handlePostGet(request, env, id);
      if (method === 'PUT' || method === 'PATCH') return handlePostPut(request, env, id);
      if (method === 'DELETE') return handlePostDelete(request, env, id);
    }

    // posts
    if (path === `${API}/posts`) {
      if (method === 'GET')  return handlePostsList(request, env);
      if (method === 'POST') return handlePostCreate(request, env);
    }

    // pages/:id
    const pageIdMatch = path.match(new RegExp(`^${API}/pages/([^/]+)$`));
    if (pageIdMatch) {
      const id = pageIdMatch[1];
      if (method === 'GET')    return handlePageGet(request, env, id);
      if (method === 'PUT' || method === 'PATCH') return handlePagePut(request, env, id);
      if (method === 'DELETE') return handlePageDelete(request, env, id);
    }

    // pages
    if (path === `${API}/pages`) {
      if (method === 'GET')  return handlePagesList(request, env);
      if (method === 'POST') return handlePageCreate(request, env);
    }

    // categories/:id
    const catIdMatch = path.match(new RegExp(`^${API}/categories/([^/]+)$`));
    if (catIdMatch) {
      if (method === 'GET') return handleCatGet(request, env, catIdMatch[1]);
    }

    // categories
    if (path === `${API}/categories`) {
      if (method === 'GET')  return handleCatList(request, env);
      if (method === 'POST') return handleCatCreate(request, env);
    }

    // users/me
    if (path === `${API}/users/me`) {
      if (method === 'GET') return handleUsersMe(request, env);
      if (method === 'POST' || method === 'PUT') return handleUsersMeUpdate(request, env);
    }

    // users/:id
    const userIdMatch = path.match(new RegExp(`^${API}/users/([^/]+)$`));
    if (userIdMatch) {
      if (method === 'GET') return handleUserGet(request, env, userIdMatch[1]);
    }

    // users
    if (path === `${API}/users`) {
      if (method === 'GET') return handleUsersList(request, env);
    }

    // 매칭 없음
    return j({ code: 'rest_no_route', message: `${method} ${path} 경로를 찾을 수 없습니다.`, data: { status: 404 } }, 404);

  } catch (e) {
    console.error('Router error:', e);
    return serverError(e);
  }
}

// ─────────────────────────────────────────
// 로그인
// ─────────────────────────────────────────
async function handleLogin(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { username, password, remember = true } = body || {};
    if (!username || !password) return badRequest('사용자명과 비밀번호를 입력해주세요.');

    const user = await env.CMS_DB
      .prepare('SELECT id,login,user_pass,display_name,email,role FROM wp_users WHERE login=? OR email=?')
      .bind(username, username).first().catch(() => null);

    if (!user || user.user_pass !== password) {
      return j({ code: 'rest_forbidden', message: '사용자명 또는 비밀번호가 올바르지 않습니다.', data: { status: 401 } }, 401);
    }
    if (!['administrator', 'editor', 'author'].includes(user.role)) {
      return forbidden('관리자 권한이 필요합니다.');
    }

    const token = genToken(40);
    const maxAge = remember ? 60 * 60 * 24 * 30 : 60 * 60 * 24;
    await env.CMS_KV.put(`session:${token}`, String(user.id), { expirationTtl: maxAge });

    const setCookie = `cp_cms_session=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`;
    return j({
      token,
      user_email: user.email,
      user_nicename: user.login,
      user_display_name: user.display_name,
      roles: [user.role],
    }, 200, { 'Set-Cookie': setCookie });
  } catch (e) { return serverError(e); }
}

async function handleLoginStatus(request, env) {
  try {
    const c = request.headers.get('Cookie') || '';
    const m = c.match(/cp_cms_session=([^;]+)/);
    if (!m) return j({ logged_in: false });
    const uid = await env.CMS_KV.get(`session:${m[1]}`);
    if (!uid) return j({ logged_in: false });
    const user = await env.CMS_DB
      .prepare('SELECT id,login,display_name,email,role FROM wp_users WHERE id=?')
      .bind(uid).first();
    if (!user) return j({ logged_in: false });
    return j({ logged_in: true, user: { id: user.id, login: user.login, display_name: user.display_name, email: user.email, role: user.role } });
  } catch (e) { return j({ logged_in: false }); }
}

// ─────────────────────────────────────────
// 설정
// ─────────────────────────────────────────
async function getOption(env, name, def = '') {
  try {
    const r = await env.CMS_DB.prepare('SELECT option_value FROM wp_options WHERE option_name=?').bind(name).first();
    return r?.option_value ?? def;
  } catch { return def; }
}

async function setOption(env, name, value) {
  try {
    await env.CMS_DB
      .prepare('INSERT INTO wp_options (option_name,option_value) VALUES (?,?) ON CONFLICT(option_name) DO UPDATE SET option_value=excluded.option_value')
      .bind(name, String(value)).run();
  } catch (_) {}
}

async function handleSettingsGet(request, env) {
  try {
    const [siteurl, blogname, blogdescription, postsPerPage, timezone, dateFormat, timeFormat, defaultCommentStatus, showOnFront, blogPublic, adminEmail, permalinkStructure] = await Promise.all([
      getOption(env, 'siteurl', env.SITE_URL || ''),
      getOption(env, 'blogname', '내 사이트'),
      getOption(env, 'blogdescription', ''),
      getOption(env, 'posts_per_page', '10'),
      getOption(env, 'timezone_string', 'Asia/Seoul'),
      getOption(env, 'date_format', 'Y년 n월 j일'),
      getOption(env, 'time_format', 'H:i'),
      getOption(env, 'default_comment_status', 'open'),
      getOption(env, 'show_on_front', 'posts'),
      getOption(env, 'blog_public', '1'),
      getOption(env, 'admin_email', ''),
      getOption(env, 'permalink_structure', '/%year%/%monthnum%/%postname%/'),
    ]);
    return j({
      title: blogname, blogname,
      description: blogdescription, blogdescription,
      url: siteurl, email: adminEmail, timezone,
      date_format: dateFormat, time_format: timeFormat,
      start_of_week: 1, language: 'ko_KR', use_smilies: false,
      default_category: 1, default_post_format: '',
      posts_per_page: parseInt(postsPerPage),
      default_ping_status: 'closed', default_comment_status: defaultCommentStatus,
      show_on_front: showOnFront, page_on_front: 0, page_for_posts: 0,
      blog_public: blogPublic === '1', permalink_structure: permalinkStructure,
      site_logo: 0, site_icon: 0,
    });
  } catch (e) { return serverError(e); }
}

async function handleSettingsPost(request, env) {
  try {
    const user = await getUser(env, request);
    if (!user || user.role !== 'administrator') return forbidden('관리자 권한이 필요합니다.');
    const body = await request.json().catch(() => ({}));
    const allowed = ['title', 'blogname', 'description', 'blogdescription', 'email', 'admin_email', 'timezone', 'date_format', 'time_format', 'posts_per_page', 'default_category', 'default_comment_status', 'show_on_front', 'permalink_structure', 'blog_public'];
    for (const [k, v] of Object.entries(body)) {
      if (!allowed.includes(k)) continue;
      const dbKey = k === 'title' ? 'blogname' : k === 'description' ? 'blogdescription' : k === 'email' ? 'admin_email' : k;
      await setOption(env, dbKey, v);
    }
    return handleSettingsGet(request, env);
  } catch (e) { return serverError(e); }
}

// ─────────────────────────────────────────
// 포스트
// ─────────────────────────────────────────
function formatPost(p, env) {
  const base = env?.SITE_URL || '';
  return {
    id: p.id, date: p.post_date, date_gmt: p.post_date_gmt,
    guid: { rendered: `${base}/?p=${p.id}` },
    modified: p.post_modified, modified_gmt: p.post_modified_gmt,
    slug: p.post_name, status: p.post_status, type: p.post_type,
    link: `${base}/${p.post_name}/`,
    title: { rendered: p.post_title, raw: p.post_title },
    content: { rendered: wpautop(p.post_content), raw: p.post_content, protected: false },
    excerpt: { rendered: p.post_excerpt ? wpautop(p.post_excerpt) : '', raw: p.post_excerpt || '', protected: false },
    author: p.post_author, featured_media: p.featured_media || 0,
    comment_status: p.comment_status || 'open', ping_status: p.ping_status || 'open',
    sticky: false, template: '', format: 'standard',
    meta: [], categories: [1], tags: [],
    _embedded: {
      author: [{ id: p.post_author, name: p.author_name || '관리자', slug: p.author_login || 'admin', avatar_urls: {} }],
      'wp:term': [[{ id: 1, name: '미분류', slug: 'uncategorized', taxonomy: 'category' }]],
    },
    _links: {
      self: [{ href: `${base}/wp-json/wp/v2/posts/${p.id}` }],
      collection: [{ href: `${base}/wp-json/wp/v2/posts` }],
      author: [{ embeddable: true, href: `${base}/wp-json/wp/v2/users/${p.post_author}` }],
    },
  };
}

async function handlePostsList(request, env) {
  try {
    const url = new URL(request.url);
    const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
    const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '10'), 100);
    const search = url.searchParams.get('search') || '';
    const status = url.searchParams.get('status') || 'publish';
    const slug = url.searchParams.get('slug') || '';
    const offset = (page - 1) * perPage;

    // slug 검색 (single.js에서 사용)
    if (slug) {
      const post = await env.CMS_DB
        .prepare('SELECT p.*,u.display_name as author_name,u.login as author_login FROM wp_posts p LEFT JOIN wp_users u ON p.post_author=u.id WHERE p.post_name=? AND p.post_type=? AND p.post_status=?')
        .bind(slug, 'post', 'publish').first();
      if (!post) return j([], 200, { 'X-WP-Total': '0', 'X-WP-TotalPages': '1' });
      return j([formatPost(post, env)], 200, { 'X-WP-Total': '1', 'X-WP-TotalPages': '1' });
    }

    let where = 'p.post_type=? AND p.post_status=?';
    let binds = ['post', status === 'any' ? 'publish' : status];
    if (search) { where += ' AND (p.post_title LIKE ? OR p.post_content LIKE ?)'; binds.push(`%${search}%`, `%${search}%`); }

    const [totalRow, { results }] = await Promise.all([
      env.CMS_DB.prepare(`SELECT COUNT(*) as c FROM wp_posts p WHERE ${where}`).bind(...binds).first().catch(() => ({ c: 0 })),
      env.CMS_DB.prepare(`SELECT p.*,u.display_name as author_name,u.login as author_login FROM wp_posts p LEFT JOIN wp_users u ON p.post_author=u.id WHERE ${where} ORDER BY p.post_date DESC LIMIT ? OFFSET ?`).bind(...binds, perPage, offset).all().catch(() => ({ results: [] })),
    ]);

    const total = totalRow?.c || 0;
    const totalPages = Math.max(1, Math.ceil(total / perPage));
    return new Response(JSON.stringify((results || []).map(p => formatPost(p, env))), {
      status: 200,
      headers: { ...CORS, 'Content-Type': 'application/json', 'X-WP-Total': String(total), 'X-WP-TotalPages': String(totalPages), 'Link': buildLinkHeader(url, page, totalPages) },
    });
  } catch (e) { return serverError(e); }
}

async function handlePostGet(request, env, id) {
  try {
    const post = await env.CMS_DB
      .prepare('SELECT p.*,u.display_name as author_name,u.login as author_login FROM wp_posts p LEFT JOIN wp_users u ON p.post_author=u.id WHERE p.id=? AND p.post_type=?')
      .bind(id, 'post').first();
    if (!post) return notFound('포스트를 찾을 수 없습니다.');
    return j(formatPost(post, env));
  } catch (e) { return serverError(e); }
}

async function handlePostCreate(request, env) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_forbidden', message: '로그인이 필요합니다.', data: { status: 401 } }, 401);
    const body = await request.json().catch(() => ({}));
    const { title, content, status = 'draft', slug, excerpt } = body;
    if (!title) return badRequest('제목이 필요합니다.');
    const id = Date.now();
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const postTitle = typeof title === 'object' ? title.raw : title;
    const postContent = typeof content === 'object' ? content.raw : content || '';
    const postExcerpt = typeof excerpt === 'object' ? excerpt.raw : excerpt || '';
    const postSlug = slug || postTitle.toLowerCase().replace(/[^a-z0-9가-힣]/g, '-').replace(/-+/g, '-').slice(0, 80);
    await env.CMS_DB.prepare('INSERT INTO wp_posts (id,post_author,post_date,post_date_gmt,post_content,post_title,post_excerpt,post_status,post_name,post_type,post_modified,post_modified_gmt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, user.id, now, now, postContent, postTitle, postExcerpt, status, postSlug, 'post', now, now).run();
    const post = await env.CMS_DB.prepare('SELECT * FROM wp_posts WHERE id=?').bind(id).first();
    return j(formatPost(post, env), 201);
  } catch (e) { return serverError(e); }
}

async function handlePostPut(request, env, id) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_forbidden', message: '로그인이 필요합니다.', data: { status: 401 } }, 401);
    const body = await request.json().catch(() => ({}));
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const updates = [], binds = [];
    if (body.title !== undefined) { updates.push('post_title=?'); binds.push(typeof body.title === 'object' ? body.title.raw : body.title); }
    if (body.content !== undefined) { updates.push('post_content=?'); binds.push(typeof body.content === 'object' ? body.content.raw : body.content); }
    if (body.status !== undefined) { updates.push('post_status=?'); binds.push(body.status); }
    if (body.slug !== undefined) { updates.push('post_name=?'); binds.push(body.slug); }
    if (body.excerpt !== undefined) { updates.push('post_excerpt=?'); binds.push(typeof body.excerpt === 'object' ? body.excerpt.raw : body.excerpt); }
    updates.push('post_modified=?', 'post_modified_gmt=?'); binds.push(now, now, id);
    if (updates.length > 2) await env.CMS_DB.prepare(`UPDATE wp_posts SET ${updates.join(',')} WHERE id=?`).bind(...binds).run();
    const post = await env.CMS_DB.prepare('SELECT * FROM wp_posts WHERE id=?').bind(id).first();
    if (!post) return notFound('포스트를 찾을 수 없습니다.');
    return j(formatPost(post, env));
  } catch (e) { return serverError(e); }
}

async function handlePostDelete(request, env, id) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_forbidden', message: '로그인이 필요합니다.', data: { status: 401 } }, 401);
    const post = await env.CMS_DB.prepare('SELECT * FROM wp_posts WHERE id=?').bind(id).first();
    if (!post) return notFound('포스트를 찾을 수 없습니다.');
    const force = new URL(request.url).searchParams.get('force') === 'true';
    if (force) await env.CMS_DB.prepare('DELETE FROM wp_posts WHERE id=?').bind(id).run();
    else await env.CMS_DB.prepare("UPDATE wp_posts SET post_status='trash' WHERE id=?").bind(id).run();
    return j({ ...formatPost(post, env), deleted: true });
  } catch (e) { return serverError(e); }
}

// ─────────────────────────────────────────
// 페이지
// ─────────────────────────────────────────
function formatPage(p, env) {
  const base = env?.SITE_URL || '';
  return {
    id: p.id, date: p.post_date, date_gmt: p.post_date_gmt,
    guid: { rendered: `${base}/?page_id=${p.id}` },
    modified: p.post_modified, modified_gmt: p.post_modified_gmt,
    slug: p.post_name, status: p.post_status, type: 'page',
    link: `${base}/${p.post_name}/`,
    title: { rendered: p.post_title, raw: p.post_title },
    content: { rendered: p.post_content, raw: p.post_content, protected: false },
    excerpt: { rendered: '', raw: '', protected: false },
    author: p.post_author, featured_media: 0,
    comment_status: 'closed', ping_status: 'closed',
    template: '', meta: [], parent: 0, menu_order: 0,
    _links: {
      self: [{ href: `${base}/wp-json/wp/v2/pages/${p.id}` }],
      collection: [{ href: `${base}/wp-json/wp/v2/pages` }],
    },
  };
}

async function handlePagesList(request, env) {
  try {
    const url = new URL(request.url);
    const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '10'), 100);
    const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
    const slug = url.searchParams.get('slug') || '';
    const offset = (page - 1) * perPage;

    if (slug) {
      const pg = await env.CMS_DB.prepare("SELECT * FROM wp_posts WHERE post_name=? AND post_type='page' AND post_status!='trash'").bind(slug).first();
      if (!pg) return j([], 200, { 'X-WP-Total': '0', 'X-WP-TotalPages': '1' });
      return j([formatPage(pg, env)], 200, { 'X-WP-Total': '1', 'X-WP-TotalPages': '1' });
    }

    const [totalRow, { results }] = await Promise.all([
      env.CMS_DB.prepare("SELECT COUNT(*) as c FROM wp_posts WHERE post_type='page' AND post_status!='trash'").first().catch(() => ({ c: 0 })),
      env.CMS_DB.prepare("SELECT * FROM wp_posts WHERE post_type='page' AND post_status!='trash' ORDER BY post_date DESC LIMIT ? OFFSET ?").bind(perPage, offset).all().catch(() => ({ results: [] })),
    ]);
    const total = totalRow?.c || 0;
    return new Response(JSON.stringify((results || []).map(p => formatPage(p, env))), {
      status: 200,
      headers: { ...CORS, 'Content-Type': 'application/json', 'X-WP-Total': String(total), 'X-WP-TotalPages': String(Math.max(1, Math.ceil(total / perPage))) },
    });
  } catch (e) { return serverError(e); }
}

async function handlePageGet(request, env, id) {
  try {
    const p = await env.CMS_DB.prepare("SELECT * FROM wp_posts WHERE id=? AND post_type='page'").bind(id).first();
    if (!p) return notFound('페이지를 찾을 수 없습니다.');
    return j(formatPage(p, env));
  } catch (e) { return serverError(e); }
}

async function handlePageCreate(request, env) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_forbidden', message: '권한 없음', data: { status: 401 } }, 401);
    const body = await request.json().catch(() => ({}));
    const id = Date.now();
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const title = typeof body.title === 'object' ? body.title.raw : body.title || '새 페이지';
    const content = typeof body.content === 'object' ? body.content.raw : body.content || '';
    const slug = body.slug || title.toLowerCase().replace(/[^a-z0-9가-힣]/g, '-').replace(/-+/g, '-').slice(0, 80);
    await env.CMS_DB.prepare('INSERT INTO wp_posts (id,post_author,post_date,post_date_gmt,post_content,post_title,post_status,post_name,post_type,post_modified,post_modified_gmt) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, user.id, now, now, content, title, body.status || 'draft', slug, 'page', now, now).run();
    const p = await env.CMS_DB.prepare('SELECT * FROM wp_posts WHERE id=?').bind(id).first();
    return j(formatPage(p, env), 201);
  } catch (e) { return serverError(e); }
}

async function handlePagePut(request, env, id) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_forbidden', message: '권한 없음', data: { status: 401 } }, 401);
    const body = await request.json().catch(() => ({}));
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const updates = [], binds = [];
    if (body.title !== undefined) { updates.push('post_title=?'); binds.push(typeof body.title === 'object' ? body.title.raw : body.title); }
    if (body.content !== undefined) { updates.push('post_content=?'); binds.push(typeof body.content === 'object' ? body.content.raw : body.content); }
    if (body.status !== undefined) { updates.push('post_status=?'); binds.push(body.status); }
    if (body.slug !== undefined) { updates.push('post_name=?'); binds.push(body.slug); }
    updates.push('post_modified=?', 'post_modified_gmt=?'); binds.push(now, now, id);
    if (updates.length > 2) await env.CMS_DB.prepare(`UPDATE wp_posts SET ${updates.join(',')} WHERE id=? AND post_type='page'`).bind(...binds).run();
    const p = await env.CMS_DB.prepare('SELECT * FROM wp_posts WHERE id=?').bind(id).first();
    if (!p) return notFound('페이지를 찾을 수 없습니다.');
    return j(formatPage(p, env));
  } catch (e) { return serverError(e); }
}

async function handlePageDelete(request, env, id) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_forbidden', message: '권한 없음', data: { status: 401 } }, 401);
    const p = await env.CMS_DB.prepare("SELECT * FROM wp_posts WHERE id=? AND post_type='page'").bind(id).first();
    if (!p) return notFound('페이지를 찾을 수 없습니다.');
    const force = new URL(request.url).searchParams.get('force') === 'true';
    if (force) await env.CMS_DB.prepare('DELETE FROM wp_posts WHERE id=?').bind(id).run();
    else await env.CMS_DB.prepare("UPDATE wp_posts SET post_status='trash' WHERE id=?").bind(id).run();
    return j({ ...formatPage(p, env), deleted: true });
  } catch (e) { return serverError(e); }
}

// ─────────────────────────────────────────
// 카테고리
// ─────────────────────────────────────────
function fmtCat(r, env) {
  const base = env?.SITE_URL || '';
  return { id: r.term_id, count: r.count || 0, description: r.description || '', link: `${base}/category/${r.slug}/`, name: r.name, slug: r.slug, taxonomy: 'category', parent: r.parent || 0, meta: [] };
}

async function handleCatList(request, env) {
  try {
    const url = new URL(request.url);
    const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '100'), 100);
    const { results } = await env.CMS_DB
      .prepare("SELECT t.*,tt.term_taxonomy_id,tt.description,tt.parent,tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON t.term_id=tt.term_id WHERE tt.taxonomy='category' ORDER BY t.name ASC LIMIT ?")
      .bind(perPage).all().catch(() => ({ results: [] }));
    const total = (results || []).length;
    return new Response(JSON.stringify((results || []).map(r => fmtCat(r, env))), {
      status: 200,
      headers: { ...CORS, 'Content-Type': 'application/json', 'X-WP-Total': String(total), 'X-WP-TotalPages': '1' },
    });
  } catch (e) { return serverError(e); }
}

async function handleCatGet(request, env, id) {
  try {
    const row = await env.CMS_DB
      .prepare("SELECT t.*,tt.term_taxonomy_id,tt.description,tt.parent,tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON t.term_id=tt.term_id WHERE t.term_id=? AND tt.taxonomy='category'")
      .bind(id).first();
    if (!row) return notFound('카테고리를 찾을 수 없습니다.');
    return j(fmtCat(row, env));
  } catch (e) { return serverError(e); }
}

async function handleCatCreate(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { name } = body;
    if (!name) return badRequest('이름이 필요합니다.');
    const slug = body.slug || name.toLowerCase().replace(/[^a-z0-9가-힣]/g, '-').replace(/-+/g, '-');
    const id = Date.now();
    await env.CMS_DB.prepare('INSERT INTO wp_terms (term_id,name,slug) VALUES (?,?,?)').bind(id, name, slug).run();
    await env.CMS_DB.prepare('INSERT INTO wp_term_taxonomy (term_id,taxonomy,description,parent,count) VALUES (?,?,?,?,?)').bind(id, 'category', body.description || '', body.parent || 0, 0).run();
    const row = await env.CMS_DB.prepare("SELECT t.*,tt.term_taxonomy_id,tt.description,tt.parent,tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON t.term_id=tt.term_id WHERE t.term_id=?").bind(id).first();
    return j(fmtCat(row, env), 201);
  } catch (e) { return serverError(e); }
}

// ─────────────────────────────────────────
// 사용자
// ─────────────────────────────────────────
function formatUser(u, env, includePrivate = false) {
  const base = env?.SITE_URL || '';
  const obj = {
    id: u.id, name: u.display_name || u.login, url: u.url || '',
    description: '', link: `${base}/author/${u.login}/`,
    slug: u.login, avatar_urls: { '24': '', '48': '', '96': '' },
    meta: [],
  };
  if (includePrivate) {
    obj.email = u.email;
    obj.registered_date = u.user_registered;
    obj.roles = [u.role];
    obj.capabilities = { [u.role]: true };
    obj.extra_capabilities = { administrator: u.role === 'administrator' };
  }
  return obj;
}

async function handleUsersMe(request, env) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_not_logged_in', message: '로그인이 필요합니다.', data: { status: 401 } }, 401);
    const full = await env.CMS_DB.prepare('SELECT id,login,display_name,email,role,url,user_registered FROM wp_users WHERE id=?').bind(user.id).first();
    return j(formatUser(full, env, true));
  } catch (e) { return serverError(e); }
}

async function handleUsersMeUpdate(request, env) {
  try {
    const user = await getUser(env, request);
    if (!user) return j({ code: 'rest_not_logged_in', message: '로그인이 필요합니다.', data: { status: 401 } }, 401);
    const body = await request.json().catch(() => ({}));
    const updates = [], binds = [];
    if (body.name !== undefined) { updates.push('display_name=?'); binds.push(body.name); }
    if (body.email !== undefined) { updates.push('email=?'); binds.push(body.email); }
    if (body.url !== undefined) { updates.push('url=?'); binds.push(body.url); }
    if (body.password !== undefined && body.password.length >= 8) { updates.push('user_pass=?'); binds.push(body.password); }
    if (updates.length) {
      binds.push(user.id);
      await env.CMS_DB.prepare(`UPDATE wp_users SET ${updates.join(',')} WHERE id=?`).bind(...binds).run();
    }
    const updated = await env.CMS_DB.prepare('SELECT id,login,display_name,email,role,url,user_registered FROM wp_users WHERE id=?').bind(user.id).first();
    return j(formatUser(updated, env, true));
  } catch (e) { return serverError(e); }
}

async function handleUsersList(request, env) {
  try {
    const url = new URL(request.url);
    const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '10'), 100);
    const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
    const { results } = await env.CMS_DB.prepare('SELECT * FROM wp_users LIMIT ? OFFSET ?').bind(perPage, (page - 1) * perPage).all().catch(() => ({ results: [] }));
    return j((results || []).map(u => formatUser(u, env, false)));
  } catch (e) { return serverError(e); }
}

async function handleUserGet(request, env, id) {
  try {
    const u = await env.CMS_DB.prepare('SELECT * FROM wp_users WHERE id=?').bind(id).first();
    if (!u) return notFound('사용자를 찾을 수 없습니다.');
    const reqUser = await getUser(env, request);
    return j(formatUser(u, env, reqUser && reqUser.id === u.id));
  } catch (e) { return serverError(e); }
}
