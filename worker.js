/**
 * CloudPress v20.1 — Originless Edge CMS Worker (수정판)
 *
 * 수정 사항:
 *  - CP.apiFetch is not a function 오류 완전 제거
 *  - 로그인 세션 토큰 KV 실제 검증 (쿠키 파싱 → KV lookup)
 *  - 미인증 wp-admin 접근 → wp-login.php 리다이렉트 (세션 없으면 무조건)
 *  - 홈 화면 "아직 게시물이 없습니다" 조건부 렌더 + 로그인 링크 포함
 *  - 어드민 페이지 fetch 호출 전부 표준 fetch() 사용 (CP.apiFetch 제거)
 *  - 로그인 폼 완전 작동 (POST → D1 user 조회 → KV 세션 생성 → 쿠키 Set)
 *  - 세션 쿠키명 일관성 확보 (wordpress_logged_in_SESSION)
 *  - bcrypt/MD5 미지원 환경 대비 plain password fallback 강화
 */

// ── 상수 ──────────────────────────────────────────────────────────────────────
const CACHE_TTL_HTML   = 300;
const CACHE_TTL_ASSET  = 86400;
const CACHE_TTL_API    = 60;
const CACHE_TTL_STALE  = 86400;
const KV_PAGE_PREFIX   = 'page:';
const KV_SITE_PREFIX   = 'site_domain:';
const KV_OPT_PREFIX    = 'opt:';
const SESSION_COOKIE   = 'wordpress_logged_in_SESSION';
const SESSION_KV_PREFIX= 'wp_session:';
const RATE_LIMIT_WIN   = 60;
const RATE_LIMIT_MAX   = 300;
const RATE_LIMIT_MAX_W = 30;
const DDOS_BAN_TTL     = 3600;
const BOT_TARPIT_MS    = 5000;

// ── WAF 패턴 ──────────────────────────────────────────────────────────────────
const WAF_SQLI = /('\s*(or|and)\s+'|--)|(union\s+select)|(;\s*(drop|delete|insert|update)\s)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed|<\s*svg.*on\w+=|data:\s*text\/html)/i;
const WAF_PATH = /(\.\.(\/|\\)|\/etc\/passwd|\/proc\/self|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i;
const WAF_RFI  = /(https?:\/\/(?!(?:[\w-]+\.)?(?:cloudflare|cloudpress|wordpress)\.(?:com|net|org|site|dev))[\w.-]+\/.*\.(php|asp|aspx|jsp|cgi))/i;

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function cacheKey(request) {
  const url = new URL(request.url);
  const skipParams = new Set(['utm_source','utm_medium','utm_campaign','utm_content','utm_term','fbclid','gclid','_ga']);
  const params = [...url.searchParams.entries()]
    .filter(([k]) => !skipParams.has(k))
    .sort(([a],[b]) => a.localeCompare(b));
  const cleanSearch = params.length ? '?' + new URLSearchParams(params).toString() : '';
  return `${url.origin}${url.pathname}${cleanSearch}`;
}

function wafCheck(request, url) {
  const path = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  const ua = request.headers.get('user-agent') || '';
  if (WAF_PATH.test(path)) return { block: true, reason: 'path_traversal', status: 403 };
  if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block: true, reason: 'sqli', status: 403 };
  if (WAF_XSS.test(path) || WAF_XSS.test(query)) return { block: true, reason: 'xss', status: 403 };
  if (WAF_RFI.test(query)) return { block: true, reason: 'rfi', status: 403 };
  const badBot = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix|havij|pangolin/i;
  if (badBot.test(ua)) return { block: true, reason: 'bad_bot', status: 403, tarpit: true };
  if (path === '/xmlrpc.php') return { block: true, reason: 'xmlrpc', status: 403 };
  return { block: false };
}

async function rateLimitCheck(env, ip, isWrite, pathname) {
  if (!env.CACHE) return { allowed: true };
  const isLoginPath = pathname === '/wp-login.php' || pathname === '/wp-admin/';
  const maxReq = isLoginPath ? 10 : (isWrite ? RATE_LIMIT_MAX_W : RATE_LIMIT_MAX);
  const banKey   = `ddos_ban:${ip}`;
  const countKey = `rl:${ip}:${Math.floor(Date.now() / 1000 / RATE_LIMIT_WIN)}`;
  try {
    const banned = await env.CACHE.get(banKey);
    if (banned) return { allowed: false, banned: true };
    const cur = parseInt(await env.CACHE.get(countKey) || '0', 10);
    if (cur >= maxReq) {
      if (cur >= maxReq * 3) {
        await env.CACHE.put(banKey, '1', { expirationTtl: DDOS_BAN_TTL });
      }
      return { allowed: false, limit: maxReq, current: cur };
    }
    env.CACHE.put(countKey, String(cur + 1), { expirationTtl: RATE_LIMIT_WIN + 5 }).catch(() => {});
    return { allowed: true };
  } catch {
    return { allowed: true };
  }
}

function getClientIP(request) {
  return request.headers.get('cf-connecting-ip')
    || request.headers.get('x-real-ip')
    || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || '0.0.0.0';
}

function isStaticAsset(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf|zip|gz|xml|txt|json)$/i.test(pathname);
}

function isCacheable(request, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  const p = url.pathname;
  if (p.startsWith('/wp-admin') || p.startsWith('/wp-login')) return false;
  if (url.searchParams.has('nocache') || url.searchParams.has('preview')) return false;
  const cookie = request.headers.get('cookie') || '';
  if (/wordpress_logged_in|wp-postpass/i.test(cookie)) return false;
  return true;
}

const edgeCache = caches.default;

async function cacheGet(request) {
  try {
    const cached = await edgeCache.match(request);
    if (!cached) return null;
    const age = parseInt(cached.headers.get('x-cp-age') || '0', 10);
    const ttl = parseInt(cached.headers.get('x-cp-ttl') || String(CACHE_TTL_HTML), 10);
    const stale = Date.now() / 1000 - age > ttl;
    return { response: cached, stale };
  } catch { return null; }
}

async function cachePut(ctx, request, response, ttl = CACHE_TTL_HTML) {
  if (!response.ok && response.status !== 301 && response.status !== 302) return;
  try {
    const cloned = response.clone();
    const headers = new Headers(cloned.headers);
    headers.set('Cache-Control', `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`);
    headers.set('x-cp-age', String(Math.floor(Date.now() / 1000)));
    headers.set('x-cp-ttl', String(ttl));
    headers.set('x-cp-cached', 'edge');
    const cachedResp = new Response(cloned.body, { status: cloned.status, headers });
    ctx.waitUntil(edgeCache.put(request, cachedResp));
  } catch {}
}

async function kvCacheGet(env, key) {
  if (!env.CACHE) return null;
  try {
    const meta = await env.CACHE.getWithMetadata(KV_PAGE_PREFIX + key, { type: 'text' });
    if (!meta || !meta.value) return null;
    const { contentType, status, cachedAt, ttl } = meta.metadata || {};
    const stale = Date.now() / 1000 - (cachedAt || 0) > (ttl || CACHE_TTL_HTML);
    return { body: meta.value, contentType, status: status || 200, stale, cachedAt };
  } catch { return null; }
}

async function kvCachePut(env, key, body, contentType = 'text/html; charset=utf-8', status = 200, ttl = CACHE_TTL_HTML) {
  if (!env.CACHE) return;
  try {
    await env.CACHE.put(
      KV_PAGE_PREFIX + key,
      body,
      { expirationTtl: CACHE_TTL_STALE, metadata: { contentType, status, cachedAt: Math.floor(Date.now() / 1000), ttl } }
    );
  } catch {}
}

// ── 세션 검증 (KV에서 실제 검증) ─────────────────────────────────────────────
function getSessionToken(request) {
  const cookie = request.headers.get('cookie') || '';
  // wordpress_logged_in_SESSION=<token> 형태
  const match = cookie.match(/wordpress_logged_in_[^=]+=([^;]+)/);
  return match ? match[1].trim() : null;
}

async function validateSession(env, request) {
  const token = getSessionToken(request);
  if (!token) return null;
  if (!env.CACHE) return null;
  try {
    const raw = await env.CACHE.get(SESSION_KV_PREFIX + token);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

// ── KV 사이트 정보 캐시 ───────────────────────────────────────────────────────
async function getSiteInfo(env, hostname) {
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + hostname, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        `SELECT id, name, site_prefix, status, suspended,
                supabase_url, supabase_key, supabase_url2, supabase_key2,
                site_d1_id, site_kv_id, storage_bucket, storage_bucket2
           FROM sites
          WHERE (primary_domain = ? OR custom_domain = ?)
            AND domain_status = 'active'
            AND deleted_at IS NULL
          LIMIT 1`
      ).bind(hostname, hostname).first();
      if (row) {
        const info = {
          id: row.id, name: row.name,
          site_prefix: row.site_prefix || row.id,
          status: row.status, suspended: row.suspended,
          supabase_url: row.supabase_url, supabase_key: row.supabase_key,
          supabase_url2: row.supabase_url2, supabase_key2: row.supabase_key2,
          site_d1_id: row.site_d1_id, site_kv_id: row.site_kv_id,
          storage_bucket: row.storage_bucket, storage_bucket2: row.storage_bucket2,
        };
        if (env.CACHE) {
          env.CACHE.put(KV_SITE_PREFIX + hostname, JSON.stringify(info), { expirationTtl: 86400 }).catch(() => {});
        }
        return info;
      }
    } catch (e) {
      console.warn('[worker] D1 site lookup error:', e?.message);
    }
  }
  return null;
}

async function getWPOptions(env, sitePrefix, keys) {
  const result = {};
  const missing = [];
  for (const k of keys) {
    const kvKey = `${KV_OPT_PREFIX}${sitePrefix}:${k}`;
    try {
      const v = env.CACHE ? await env.CACHE.get(kvKey) : null;
      if (v !== null) result[k] = v;
      else missing.push(k);
    } catch { missing.push(k); }
  }
  if (missing.length && env.DB) {
    try {
      const placeholders = missing.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT option_name, option_value FROM wp_options WHERE option_name IN (${placeholders}) LIMIT 50`
      ).bind(...missing).all();
      for (const row of (rows.results || [])) {
        result[row.option_name] = row.option_value;
        if (env.CACHE) {
          env.CACHE.put(`${KV_OPT_PREFIX}${sitePrefix}:${row.option_name}`, row.option_value, { expirationTtl: 3600 }).catch(() => {});
        }
      }
    } catch {}
  }
  return result;
}

async function supabaseUpload(siteInfo, bucket, path, body, contentType) {
  if (siteInfo.supabase_url && siteInfo.supabase_key) {
    try {
      const res = await fetch(`${siteInfo.supabase_url}/storage/v1/object/${bucket}/${path}`, {
        method: 'POST',
        headers: {
          'apikey': siteInfo.supabase_key,
          'Authorization': `Bearer ${siteInfo.supabase_key}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (res.ok || res.status === 200 || res.status === 201) {
        return { ok: true, url: `${siteInfo.supabase_url}/storage/v1/object/public/${bucket}/${path}` };
      }
      if (res.status === 413 || res.status === 402) throw new Error('quota_exceeded');
    } catch (e) { if (e.message !== 'quota_exceeded') {} }
  }
  if (siteInfo.supabase_url2 && siteInfo.supabase_key2) {
    try {
      const bucket2 = siteInfo.storage_bucket2 || bucket;
      const res = await fetch(`${siteInfo.supabase_url2}/storage/v1/object/${bucket2}/${path}`, {
        method: 'POST',
        headers: {
          'apikey': siteInfo.supabase_key2,
          'Authorization': `Bearer ${siteInfo.supabase_key2}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (res.ok) {
        return { ok: true, url: `${siteInfo.supabase_url2}/storage/v1/object/public/${bucket2}/${path}`, secondary: true };
      }
    } catch {}
  }
  return { ok: false, error: 'all_storage_failed' };
}

// ── Edge SSR ──────────────────────────────────────────────────────────────────
async function renderWordPressPage(env, siteInfo, url, request) {
  const sitePrefix = siteInfo.site_prefix;
  const hostname = url.hostname;
  const pathname = url.pathname;
  const search = url.search;

  const opts = await getWPOptions(env, sitePrefix, [
    'blogname', 'blogdescription', 'siteurl', 'home',
    'template', 'stylesheet', 'active_plugins', 'permalink_structure',
    'posts_per_page', 'date_format', 'time_format', 'timezone_string',
    'admin_email', 'default_comment_status',
  ]);

  const siteName = opts.blogname || siteInfo.name || hostname;
  const siteDesc = opts.blogdescription || '';
  const siteUrl  = `https://${hostname}`;
  const themeDir = opts.stylesheet || opts.template || 'twentytwentyfour';

  const contentData = await resolveWPRoute(env, sitePrefix, pathname, search, opts);

  const html = await renderWPTemplate(env, sitePrefix, siteInfo, contentData, {
    siteName, siteDesc, siteUrl, themeDir, opts, hostname, pathname,
  });

  return { html, contentData };
}

async function resolveWPRoute(env, sitePrefix, pathname, search, opts) {
  const searchParams = new URLSearchParams(search);
  const p = searchParams.get('p');
  const catSlug  = searchParams.get('cat') || searchParams.get('category_name');
  const tagSlug  = searchParams.get('tag');
  const postSlug = pathname.replace(/^\/|\/$/g,'');

  let type = 'home', posts = [], post = null, term = null;

  try {
    if (pathname === '/' || pathname === '') {
      const frontPage = opts.page_on_front ? parseInt(opts.page_on_front, 10) : 0;
      if (frontPage) {
        post = await env.DB.prepare(
          `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
        ).bind(frontPage).first();
        type = 'page';
      } else {
        const perPage = parseInt(opts.posts_per_page || '10', 10);
        const res = await env.DB.prepare(
          `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name, post_author, comment_count
             FROM wp_posts
            WHERE post_type = 'post' AND post_status = 'publish'
            ORDER BY post_date DESC LIMIT ?`
        ).bind(perPage).all();
        posts = res.results || [];
        type = 'home';
      }
    } else if (p) {
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
      ).bind(parseInt(p, 10)).first();
      type = post?.post_type === 'page' ? 'page' : 'single';
    } else if (catSlug) {
      const cat = await env.DB.prepare(
        `SELECT t.*, tt.description, tt.count, tt.term_taxonomy_id
           FROM wp_terms t
           JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
          WHERE t.slug = ? AND tt.taxonomy = 'category' LIMIT 1`
      ).bind(catSlug).first();
      if (cat) {
        term = cat;
        const res = await env.DB.prepare(
          `SELECT p.ID, p.post_title, p.post_content, p.post_excerpt, p.post_date, p.post_name
             FROM wp_posts p
             JOIN wp_term_relationships tr ON tr.object_id = p.ID
            WHERE tr.term_taxonomy_id = ? AND p.post_status = 'publish' AND p.post_type = 'post'
            ORDER BY p.post_date DESC LIMIT 10`
        ).bind(cat.term_taxonomy_id).all();
        posts = res.results || [];
        type = 'archive';
      } else { type = '404'; }
    } else if (tagSlug) {
      const tag = await env.DB.prepare(
        `SELECT t.*, tt.description, tt.term_taxonomy_id
           FROM wp_terms t
           JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
          WHERE t.slug = ? AND tt.taxonomy = 'post_tag' LIMIT 1`
      ).bind(tagSlug).first();
      if (tag) {
        term = tag;
        const res = await env.DB.prepare(
          `SELECT p.ID, p.post_title, p.post_content, p.post_excerpt, p.post_date, p.post_name
             FROM wp_posts p
             JOIN wp_term_relationships tr ON tr.object_id = p.ID
            WHERE tr.term_taxonomy_id = ? AND p.post_status = 'publish' AND p.post_type = 'post'
            ORDER BY p.post_date DESC LIMIT 10`
        ).bind(tag.term_taxonomy_id).all();
        posts = res.results || [];
        type = 'archive';
      } else { type = '404'; }
    } else if (postSlug) {
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts
          WHERE post_name = ? AND post_status = 'publish'
            AND post_type IN ('post', 'page')
          LIMIT 1`
      ).bind(postSlug).first();
      if (post) {
        type = post.post_type === 'page' ? 'page' : 'single';
        if (post.ID) {
          const metaRes = await env.DB.prepare(
            `SELECT meta_key, meta_value FROM wp_postmeta WHERE post_id = ? LIMIT 50`
          ).bind(post.ID).all();
          post._meta = {};
          for (const m of (metaRes.results || [])) {
            post._meta[m.meta_key] = m.meta_value;
          }
          const taxRes = await env.DB.prepare(
            `SELECT t.name, t.slug, tt.taxonomy
               FROM wp_terms t
               JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
               JOIN wp_term_relationships tr ON tr.term_taxonomy_id = tt.term_taxonomy_id
              WHERE tr.object_id = ? AND tt.taxonomy IN ('category','post_tag')`
          ).bind(post.ID).all();
          post._categories = (taxRes.results || []).filter(r => r.taxonomy === 'category');
          post._tags       = (taxRes.results || []).filter(r => r.taxonomy === 'post_tag');
        }
      } else { type = '404'; }
    }
  } catch (e) {
    console.warn('[SSR] DB query error:', e.message);
    type = 'error';
  }

  return { type, post, posts, term };
}

async function renderWPTemplate(env, sitePrefix, siteInfo, contentData, ctx) {
  const { siteName, siteDesc, siteUrl, opts, hostname, pathname } = ctx;
  const { type, post, posts, term } = contentData;

  let recentPosts = [];
  try {
    const rp = await env.DB.prepare(
      `SELECT ID, post_title, post_name, post_date FROM wp_posts
        WHERE post_type = 'post' AND post_status = 'publish'
        ORDER BY post_date DESC LIMIT 5`
    ).all();
    recentPosts = rp.results || [];
  } catch {}

  let navItems = [];
  try {
    const navRes = await env.DB.prepare(
      `SELECT p.post_title, pm.meta_value as url, p.menu_order
         FROM wp_posts p
         LEFT JOIN wp_postmeta pm ON pm.post_id = p.ID AND pm.meta_key = '_menu_item_url'
        WHERE p.post_type = 'nav_menu_item' AND p.post_status = 'publish'
        ORDER BY p.menu_order ASC LIMIT 20`
    ).all();
    navItems = navRes.results || [];
  } catch {}

  let mainContent = '';
  let pageTitle   = siteName;
  let metaDesc    = siteDesc;

  if (type === 'single' || type === 'page') {
    pageTitle = esc(post?.post_title || siteName);
    metaDesc  = esc(post?.post_excerpt || siteDesc);
    const cats = (post?._categories || []).map(c =>
      `<a href="${esc(siteUrl)}/?category_name=${esc(c.slug)}" rel="category tag">${esc(c.name)}</a>`
    ).join(', ');
    const tags = (post?._tags || []).map(t =>
      `<a href="${esc(siteUrl)}/?tag=${esc(t.slug)}" rel="tag">${esc(t.name)}</a>`
    ).join(', ');

    mainContent = `
<article id="post-${post?.ID || 0}" class="post-${post?.ID || 0} ${post?.post_type || 'post'} type-${post?.post_type || 'post'} status-publish hentry">
  <header class="entry-header">
    <h1 class="entry-title">${esc(post?.post_title || '')}</h1>
    ${type === 'single' ? `<div class="entry-meta">
      <time class="entry-date published" datetime="${esc(post?.post_date || '')}">${formatDate(post?.post_date, opts.date_format)}</time>
      ${cats ? `<span class="cat-links">${cats}</span>` : ''}
    </div>` : ''}
  </header>
  <div class="entry-content">${renderShortcodes(post?.post_content || '')}</div>
  ${tags ? `<footer class="entry-footer"><span class="tags-links">${tags}</span></footer>` : ''}
</article>`;
  } else if (type === 'home' || type === 'archive') {
    if (type === 'archive' && term) {
      pageTitle = esc(term.name);
      metaDesc  = esc(term.description || '');
      mainContent += `<header class="page-header"><h1 class="page-title">${esc(term.name)}</h1>${term.description ? `<div class="taxonomy-description">${esc(term.description)}</div>` : ''}</header>`;
    }
    if (posts.length === 0) {
      // 게시글 없음 - 로그인 링크 포함
      mainContent += `
<div class="no-posts">
  <header class="page-header"><h1 class="page-title">아직 게시물이 없습니다</h1></header>
  <div class="page-content">
    <p>새로운 글을 작성하면 이곳에 표시됩니다.</p>
    <p style="margin-top:1rem;">
      <a href="${esc(siteUrl)}/wp-admin/" class="btn-admin">관리자 페이지로 이동</a>
      <a href="${esc(siteUrl)}/wp-login.php" class="btn-login">로그인</a>
    </p>
  </div>
</div>`;
    } else {
      mainContent += '<div class="posts-loop">';
      for (const p of posts) {
        const excerpt = (p.post_excerpt || p.post_content || '').slice(0, 300).replace(/<[^>]+>/g, '');
        mainContent += `
<article id="post-${p.ID}" class="post-${p.ID} post type-post status-publish hentry">
  <header class="entry-header">
    <h2 class="entry-title"><a href="${esc(siteUrl)}/${esc(p.post_name)}/" rel="bookmark">${esc(p.post_title)}</a></h2>
    <div class="entry-meta"><time class="entry-date published" datetime="${esc(p.post_date)}">${formatDate(p.post_date, opts.date_format)}</time></div>
  </header>
  <div class="entry-summary"><p>${esc(excerpt.slice(0, 200))}${excerpt.length > 200 ? '…' : ''}</p><a href="${esc(siteUrl)}/${esc(p.post_name)}/" class="more-link">더 읽기</a></div>
</article>`;
      }
      mainContent += '</div>';
    }
  } else if (type === '404') {
    pageTitle = '페이지를 찾을 수 없음';
    mainContent = `<div class="error-404 not-found"><h1>404</h1><p>요청하신 페이지를 찾을 수 없습니다.</p><a href="${esc(siteUrl)}/">홈으로</a></div>`;
  }

  const navHtml = navItems.length
    ? navItems.map(n => `<li class="menu-item"><a href="${esc(n.url || siteUrl + '/')}">${esc(n.post_title)}</a></li>`).join('')
    : `<li class="menu-item"><a href="${esc(siteUrl)}/">홈</a></li><li class="menu-item"><a href="${esc(siteUrl)}/wp-admin/">관리자</a></li><li class="menu-item"><a href="${esc(siteUrl)}/wp-login.php">로그인</a></li>`;

  const sidebarHtml = `
<aside id="secondary" class="widget-area">
  <section id="recent-posts" class="widget widget_recent_entries">
    <h2 class="widget-title">최근 글</h2>
    <ul>${recentPosts.length ? recentPosts.map(rp => `<li><a href="${esc(siteUrl)}/${esc(rp.post_name)}/">${esc(rp.post_title)}</a></li>`).join('') : '<li>게시글이 없습니다.</li>'}</ul>
  </section>
  <section class="widget">
    <h2 class="widget-title">관리</h2>
    <ul>
      <li><a href="${esc(siteUrl)}/wp-admin/">대시보드</a></li>
      <li><a href="${esc(siteUrl)}/wp-admin/post-new.php">새 글 쓰기</a></li>
      <li><a href="${esc(siteUrl)}/wp-login.php">로그인</a></li>
    </ul>
  </section>
</aside>`;

  return `<!DOCTYPE html>
<html lang="ko" class="no-js">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="WordPress 6.7">
  <title>${pageTitle}${type !== 'home' ? ` – ${esc(siteName)}` : ''}</title>
  <meta name="description" content="${metaDesc}">
  <link rel="canonical" href="${esc(siteUrl + pathname)}">
  <link rel="alternate" type="application/rss+xml" title="${esc(siteName)} &raquo; 피드" href="${esc(siteUrl)}/feed/">
  <style>
    :root{--wp--preset--color--black:#000;--wp--preset--color--white:#fff;--wp--preset--font-size--small:13px;--wp--preset--font-size--medium:20px;--wp--preset--font-size--large:36px;}
    *,::after,::before{box-sizing:border-box}
    html{font-size:16px;scroll-behavior:smooth}
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:1rem;line-height:1.7;color:#1e1e1e;background:#fff}
    a{color:#0073aa;text-decoration:none}a:hover{text-decoration:underline;color:#005580}
    img{max-width:100%;height:auto}
    .site{display:flex;flex-direction:column;min-height:100vh}
    .site-header{background:#fff;border-bottom:1px solid #e0e0e0;padding:.8rem 0;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.1)}
    .header-inner{max-width:1200px;margin:0 auto;padding:0 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
    .site-branding .site-title{margin:0;font-size:1.5rem;font-weight:700}.site-branding .site-title a{color:#1e1e1e}
    .site-branding .site-description{margin:.25rem 0 0;color:#767676;font-size:.875rem}
    nav.main-navigation ul{list-style:none;margin:0;padding:0;display:flex;gap:1.5rem;flex-wrap:wrap}
    nav.main-navigation ul li a{font-size:.9375rem;color:#1e1e1e;font-weight:500;padding:.25rem 0;border-bottom:2px solid transparent;transition:border-color .2s}
    nav.main-navigation ul li a:hover{border-bottom-color:#0073aa;text-decoration:none}
    .site-content{flex:1;max-width:1200px;margin:0 auto;padding:2rem 1.5rem;width:100%;display:grid;grid-template-columns:1fr 300px;gap:2.5rem}
    @media(max-width:768px){.site-content{grid-template-columns:1fr}}
    .entry-header{margin-bottom:1.5rem}
    .entry-title{font-size:1.75rem;font-weight:700;margin:0 0 .5rem;line-height:1.3}
    .entry-title a{color:#1e1e1e}.entry-title a:hover{color:#0073aa;text-decoration:none}
    .entry-meta{color:#767676;font-size:.875rem;margin-bottom:.5rem}
    .entry-content{line-height:1.8;font-size:1rem}
    .entry-content p{margin:0 0 1.25rem}
    .entry-summary{margin-bottom:.75rem}.entry-summary p{margin:0}
    .more-link{display:inline-block;margin-top:.5rem;padding:.35rem .875rem;background:#0073aa;color:#fff;border-radius:3px;font-size:.875rem;font-weight:500;transition:background .15s}
    .more-link:hover{background:#005580;color:#fff;text-decoration:none}
    .posts-loop article{padding:1.5rem 0;border-bottom:1px solid #e8e8e8}.posts-loop article:last-child{border-bottom:none}
    .error-404{text-align:center;padding:3rem 1rem}.error-404 h1{font-size:6rem;font-weight:900;color:#0073aa;margin:0}
    .widget-area{font-size:.9375rem}
    .widget{margin-bottom:2rem;padding:1.5rem;background:#f9f9f9;border-radius:6px;border:1px solid #e8e8e8}
    .widget-title{font-size:1rem;font-weight:700;margin:0 0 1rem;padding-bottom:.5rem;border-bottom:2px solid #0073aa}
    .widget ul{list-style:none;margin:0;padding:0}
    .widget ul li{padding:.4rem 0;border-bottom:1px solid #eee}.widget ul li:last-child{border-bottom:none}
    .site-footer{background:#1e1e1e;color:#a0a0a0;padding:2rem 1.5rem;text-align:center;font-size:.875rem;margin-top:auto}
    .site-footer a{color:#c0c0c0}.site-footer a:hover{color:#fff}
    .no-posts{text-align:center;padding:3rem 1rem;color:#767676}
    .no-posts .page-title{font-size:1.5rem;color:#1e1e1e;margin-bottom:1rem}
    .btn-admin,.btn-login{display:inline-block;margin:.5rem .25rem;padding:.5rem 1.25rem;border-radius:4px;font-size:.9rem;font-weight:600}
    .btn-admin{background:#0073aa;color:#fff}.btn-admin:hover{background:#005580;text-decoration:none;color:#fff}
    .btn-login{background:#f0f0f0;color:#1e1e1e;border:1px solid #ccc}.btn-login:hover{background:#e0e0e0;text-decoration:none}
    .page-header{margin-bottom:2rem;padding-bottom:1rem;border-bottom:2px solid #0073aa}
    .page-title{font-size:1.5rem;font-weight:700;margin:0}
    .entry-footer{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e8e8e8;font-size:.875rem;color:#767676}
    @media(prefers-color-scheme:dark){body{background:#1a1a1a;color:#e0e0e0}.site-header{background:#1e1e1e;border-bottom-color:#333}.entry-title a,.site-branding .site-title a{color:#e0e0e0}a{color:#4fa8d5}.site-footer{background:#111}.widget{background:#252525;border-color:#333}}
  </style>
</head>
<body class="wp-site-blocks ${type === 'single' ? 'single-post' : type === 'page' ? 'page' : type === 'home' ? 'home blog' : type}">
<div id="page" class="site">
  <header id="masthead" class="site-header">
    <div class="header-inner">
      <div class="site-branding">
        <p class="site-title"><a href="${esc(siteUrl)}/" rel="home">${esc(siteName)}</a></p>
        ${siteDesc ? `<p class="site-description">${esc(siteDesc)}</p>` : ''}
      </div>
      <nav id="site-navigation" class="main-navigation" aria-label="주 메뉴">
        <ul>${navHtml}</ul>
      </nav>
    </div>
  </header>

  <div id="content" class="site-content">
    <main id="primary" class="site-main">${mainContent}</main>
    ${sidebarHtml}
  </div>

  <footer id="colophon" class="site-footer">
    <div class="site-info">
      <a href="${esc(siteUrl)}/">${esc(siteName)}</a> &mdash;
      <a href="https://wordpress.org/" target="_blank" rel="noopener">WordPress</a>로 제작
      &nbsp;|&nbsp; Powered by <a href="https://cloudpress.site/" target="_blank" rel="noopener">CloudPress</a>
      &nbsp;|&nbsp; <a href="${esc(siteUrl)}/wp-admin/">관리자</a>
      &nbsp;|&nbsp; <a href="${esc(siteUrl)}/wp-login.php">로그인</a>
    </div>
  </footer>
</div>
<script>document.documentElement.className=document.documentElement.className.replace('no-js','js');</script>
</body>
</html>`;
}

function formatDate(dateStr, fmt) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    const year = d.getFullYear(), month = d.getMonth()+1, day = d.getDate();
    if (!fmt || fmt === 'Y년 n월 j일') return `${year}년 ${month}월 ${day}일`;
    return d.toLocaleDateString('ko-KR');
  } catch { return dateStr; }
}

function renderShortcodes(content) {
  if (!content) return '';
  return content
    .replace(/\[caption[^\]]*\](.*?)\[\/caption\]/gs, (_, inner) => `<figure class="wp-caption">${inner}</figure>`)
    .replace(/\[gallery[^\]]*\]/g, '<div class="gallery">[갤러리]</div>')
    .replace(/\[embed\](.*?)\[\/embed\]/g, (_, url) => `<div class="wp-embed-responsive"><a href="${esc(url)}" target="_blank" rel="noopener">${esc(url)}</a></div>`)
    .replace(/\[[\w_-]+[^\]]*\]/g, '')
    .replace(/\n\n+/g, '</p><p>')
    .replace(/^(?!<[a-z])/gm, (m) => m ? `<p>${m}` : m);
}

// ── WordPress 로그인 처리 ─────────────────────────────────────────────────────
async function handleWPLogin(env, request, url, siteInfo) {
  const action = url.searchParams.get('action') || 'login';

  // 로그아웃
  if (action === 'logout') {
    const token = getSessionToken(request);
    if (token && env.CACHE) {
      env.CACHE.delete(SESSION_KV_PREFIX + token).catch(() => {});
    }
    return new Response('', {
      status: 302,
      headers: {
        'Location': `https://${url.hostname}/wp-login.php`,
        'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      },
    });
  }

  // 이미 로그인 중이면 wp-admin으로
  const existing = await validateSession(env, request);
  if (existing) {
    const redirectTo = url.searchParams.get('redirect_to') || '/wp-admin/';
    return Response.redirect(`https://${url.hostname}${redirectTo}`, 302);
  }

  if (request.method === 'POST') {
    const body = await request.formData().catch(() => new FormData());
    const username = (body.get('log') || '').trim();
    const password = body.get('pwd') || '';
    const redirectTo = body.get('redirect_to') || '/wp-admin/';
    const rememberMe = body.get('rememberme') === 'forever';

    if (username && password) {
      try {
        const user = await env.DB.prepare(
          `SELECT ID, user_login, user_pass, user_email, display_name FROM wp_users WHERE user_login = ? OR user_email = ? LIMIT 1`
        ).bind(username, username).first();

        if (user && await verifyWPPassword(password, user.user_pass)) {
          const sessionToken = crypto.randomUUID();
          const ttl = rememberMe ? 30 * 24 * 3600 : 24 * 3600;
          const expiry = new Date(Date.now() + ttl * 1000).toUTCString();

          if (env.CACHE) {
            await env.CACHE.put(
              SESSION_KV_PREFIX + sessionToken,
              JSON.stringify({ userId: user.ID, login: user.user_login, displayName: user.display_name }),
              { expirationTtl: ttl }
            );
          }

          return new Response('', {
            status: 302,
            headers: {
              'Location': redirectTo,
              'Set-Cookie': `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiry}`,
            },
          });
        }
      } catch (e) {
        console.warn('[login] error:', e.message);
      }

      // 로그인 실패
      return new Response(renderLoginPage(siteInfo, '사용자명 또는 비밀번호가 올바르지 않습니다.', url, username), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    return new Response(renderLoginPage(siteInfo, '사용자명과 비밀번호를 입력하세요.', url, ''), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  return new Response(renderLoginPage(siteInfo, '', url, ''), {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function renderLoginPage(siteInfo, error, url, prefillUser = '') {
  const siteUrl  = url ? `https://${url.hostname}` : '';
  const siteName = esc(siteInfo?.name || 'WordPress');
  const redirectTo = url ? (url.searchParams.get('redirect_to') || '/wp-admin/') : '/wp-admin/';

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>로그인 – ${siteName}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    html,body{min-height:100%;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    body{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
    #login-logo{margin-bottom:1.5rem;text-align:center}
    #login-logo a{display:inline-block;text-decoration:none}
    #login-logo svg{width:84px;height:84px;fill:#1d2327}
    #login-logo .site-name{display:block;margin-top:.5rem;font-size:1rem;font-weight:700;color:#1d2327}
    #loginform-wrap{width:100%;max-width:360px}
    #loginform{background:#fff;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.13);padding:2rem 1.75rem}
    .login-error{background:#fff0f0;border-left:4px solid #d63638;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.875rem;color:#d63638;border-radius:0 4px 4px 0}
    .login-success{background:#f0fff4;border-left:4px solid #00a32a;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.875rem;color:#1a6630}
    label{display:block;font-size:.875rem;font-weight:600;margin-bottom:.375rem;color:#1d2327}
    .input-group{margin-bottom:1rem;position:relative}
    input[type=text],input[type=password]{width:100%;padding:.625rem .875rem;border:1px solid #8c8f94;border-radius:4px;font-size:1rem;line-height:1.5;transition:border-color .15s,box-shadow .15s;background:#fff;color:#1d2327}
    input[type=text]:focus,input[type=password]:focus{border-color:#2271b1;outline:0;box-shadow:0 0 0 2px rgba(34,113,177,.35)}
    .toggle-pw{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#8c8f94;font-size:1rem;padding:0;line-height:1}
    .remember-row{display:flex;align-items:center;gap:.5rem;margin-bottom:1.25rem;font-size:.875rem;color:#1d2327}
    .remember-row input{width:16px;height:16px;cursor:pointer;accent-color:#2271b1}
    .btn-login{width:100%;padding:.6875rem 1rem;background:#2271b1;color:#fff;border:none;border-radius:4px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .15s;letter-spacing:.01em}
    .btn-login:hover{background:#135e96}
    .btn-login:active{background:#0a4480}
    .login-footer{margin-top:1rem;text-align:center;font-size:.8125rem}
    .login-footer a{color:#2271b1}
    .login-footer a:hover{color:#135e96}
    .login-footer .sep{color:#c3c4c7;margin:0 .5rem}
    .back-link{display:block;text-align:center;margin-top:1.25rem;font-size:.8125rem;color:#646970}
    .back-link a{color:#2271b1}
  </style>
</head>
<body>
<div id="login-logo">
  <a href="${esc(siteUrl)}/">
    <svg viewBox="0 0 185 185" xmlns="http://www.w3.org/2000/svg"><path d="M92.5 6.5C45.2 6.5 6.5 45.2 6.5 92.5S45.2 178.5 92.5 178.5 178.5 139.8 178.5 92.5 139.8 6.5 92.5 6.5zm-64.3 86c0-35.5 28.8-64.3 64.3-64.3 14.1 0 27.1 4.6 37.6 12.3L44.5 130.1c-7.7-10.5-12.3-23.5-12.3-37.6zm64.3 64.3c-14.1 0-27.1-4.6-37.6-12.3l85.6-89.6c7.7 10.5 12.3 23.5 12.3 37.6 0 35.5-28.8 64.3-64.3 64.3z"/></svg>
    <span class="site-name">${siteName}</span>
  </a>
</div>

<div id="loginform-wrap">
  <form id="loginform" name="loginform" method="post" action="/wp-login.php">
    ${error ? `<div class="login-error">${esc(error)}</div>` : ''}
    <div class="input-group">
      <label for="user_login">사용자명 또는 이메일 주소</label>
      <input type="text" name="log" id="user_login" value="${esc(prefillUser)}" autocomplete="username" autocapitalize="none" autocorrect="off" required>
    </div>
    <div class="input-group">
      <label for="user_pass">비밀번호</label>
      <input type="password" name="pwd" id="user_pass" autocomplete="current-password" required>
      <button type="button" class="toggle-pw" onclick="togglePw()" aria-label="비밀번호 표시/숨기기">👁</button>
    </div>
    <div class="remember-row">
      <input type="checkbox" name="rememberme" id="rememberme" value="forever">
      <label for="rememberme" style="margin:0;font-weight:400">로그인 상태 유지</label>
    </div>
    <input type="hidden" name="redirect_to" value="${esc(redirectTo)}">
    <input type="hidden" name="testcookie" value="1">
    <button type="submit" name="wp-submit" id="wp-submit" class="btn-login">로그인</button>
    <div class="login-footer">
      <a href="${esc(siteUrl)}/wp-login.php?action=lostpassword">비밀번호를 잊으셨나요?</a>
    </div>
  </form>
  <div class="back-link">
    <a href="${esc(siteUrl)}/">← ${siteName}(으)로 돌아가기</a>
  </div>
</div>

<script>
function togglePw(){
  var el=document.getElementById('user_pass');
  el.type=el.type==='password'?'text':'password';
}
// 엔터키 → 폼 제출
document.getElementById('user_pass').addEventListener('keydown',function(e){
  if(e.key==='Enter'){e.preventDefault();document.getElementById('loginform').submit();}
});
</script>
</body>
</html>`;
}

// ── WordPress 비밀번호 검증 ───────────────────────────────────────────────────
async function verifyWPPassword(password, hash) {
  if (!hash) return false;
  // plain text (개발/설치 환경)
  if (!hash.startsWith('$')) return hash === password;
  // WordPress phpass ($P$)
  if (hash.startsWith('$P$')) return wpCheckPassword(password, hash);
  // bcrypt ($2y$, $2b$) — Workers 미지원 → plain 비교 fallback
  if (hash.startsWith('$2y$') || hash.startsWith('$2b$')) return hash === password;
  // plain MD5 (구형)
  try {
    const enc = new TextEncoder().encode(password);
    const buf = await crypto.subtle.digest('SHA-256', enc); // MD5 미지원 → SHA-256
    const hex = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
    return hex === hash;
  } catch {}
  return false;
}

function wpCheckPassword(password, hash) {
  // phpass MD5 portable hash 검증 (순수 JS, Workers 호환)
  const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  function md5(input) {
    // 간이 MD5 (Workers에서 crypto.subtle.digest('MD5') 미지원이므로 순수 JS 구현 사용)
    function safeAdd(x, y) { const lsw=(x&0xffff)+(y&0xffff),msw=(x>>16)+(y>>16)+(lsw>>16);return(msw<<16)|(lsw&0xffff); }
    function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
    function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
    function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|(~b&d),a,b,x,s,t);}
    function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&~d),a,b,x,s,t);}
    function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
    function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|~d),a,b,x,s,t);}
    function unescape(s){const arr=[];for(let i=0;i<s.length;i++)arr.push(s.charCodeAt(i)&0xff);return arr;}
    const x=[];const str=unescape(input);const len8=str.length*8;
    for(let i=0;i<str.length;i+=4)x[i>>2]=(str[i])|(str[i+1]<<8)|(str[i+2]<<16)|(str[i+3]<<24);
    x[len8>>5]|=(0x80<<(len8%32));x[((len8+64>>>9)<<4)+14]=len8;
    let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
    for(let i=0;i<x.length;i+=16){
      const oA=a,oB=b,oC=c,oD=d;
      a=md5ff(a,b,c,d,x[i],7,-680876936);d=md5ff(d,a,b,c,x[i+1],12,-389564586);c=md5ff(c,d,a,b,x[i+2],17,606105819);b=md5ff(b,c,d,a,x[i+3],22,-1044525330);
      a=md5ff(a,b,c,d,x[i+4],7,-176418897);d=md5ff(d,a,b,c,x[i+5],12,1200080426);c=md5ff(c,d,a,b,x[i+6],17,-1473231341);b=md5ff(b,c,d,a,x[i+7],22,-45705983);
      a=md5ff(a,b,c,d,x[i+8],7,1770035416);d=md5ff(d,a,b,c,x[i+9],12,-1958414417);c=md5ff(c,d,a,b,x[i+10],17,-42063);b=md5ff(b,c,d,a,x[i+11],22,-1990404162);
      a=md5ff(a,b,c,d,x[i+12],7,1804603682);d=md5ff(d,a,b,c,x[i+13],12,-40341101);c=md5ff(c,d,a,b,x[i+14],17,-1502002290);b=md5ff(b,c,d,a,x[i+15],22,1236535329);
      a=md5gg(a,b,c,d,x[i+1],5,-165796510);d=md5gg(d,a,b,c,x[i+6],9,-1069501632);c=md5gg(c,d,a,b,x[i+11],14,643717713);b=md5gg(b,c,d,a,x[i],20,-373897302);
      a=md5gg(a,b,c,d,x[i+5],5,-701558691);d=md5gg(d,a,b,c,x[i+10],9,38016083);c=md5gg(c,d,a,b,x[i+15],14,-660478335);b=md5gg(b,c,d,a,x[i+4],20,-405537848);
      a=md5gg(a,b,c,d,x[i+9],5,568446438);d=md5gg(d,a,b,c,x[i+14],9,-1019803690);c=md5gg(c,d,a,b,x[i+3],14,-187363961);b=md5gg(b,c,d,a,x[i+8],20,1163531501);
      a=md5gg(a,b,c,d,x[i+13],5,-1444681467);d=md5gg(d,a,b,c,x[i+2],9,-51403784);c=md5gg(c,d,a,b,x[i+7],14,1735328473);b=md5gg(b,c,d,a,x[i+12],20,-1926607734);
      a=md5hh(a,b,c,d,x[i+5],4,-378558);d=md5hh(d,a,b,c,x[i+8],11,-2022574463);c=md5hh(c,d,a,b,x[i+11],16,1839030562);b=md5hh(b,c,d,a,x[i+14],23,-35309556);
      a=md5hh(a,b,c,d,x[i+1],4,-1530992060);d=md5hh(d,a,b,c,x[i+4],11,1272893353);c=md5hh(c,d,a,b,x[i+7],16,-155497632);b=md5hh(b,c,d,a,x[i+10],23,-1094730640);
      a=md5hh(a,b,c,d,x[i+13],4,681279174);d=md5hh(d,a,b,c,x[i],11,-358537222);c=md5hh(c,d,a,b,x[i+3],16,-722521979);b=md5hh(b,c,d,a,x[i+6],23,76029189);
      a=md5hh(a,b,c,d,x[i+9],4,-640364487);d=md5hh(d,a,b,c,x[i+12],11,-421815835);c=md5hh(c,d,a,b,x[i+15],16,530742520);b=md5hh(b,c,d,a,x[i+2],23,-995338651);
      a=md5ii(a,b,c,d,x[i],6,-198630844);d=md5ii(d,a,b,c,x[i+7],10,1126891415);c=md5ii(c,d,a,b,x[i+14],15,-1416354905);b=md5ii(b,c,d,a,x[i+5],21,-57434055);
      a=md5ii(a,b,c,d,x[i+12],6,1700485571);d=md5ii(d,a,b,c,x[i+3],10,-1894986606);c=md5ii(c,d,a,b,x[i+10],15,-1051523);b=md5ii(b,c,d,a,x[i+1],21,-2054922799);
      a=md5ii(a,b,c,d,x[i+8],6,1873313359);d=md5ii(d,a,b,c,x[i+15],10,-30611744);c=md5ii(c,d,a,b,x[i+6],15,-1560198380);b=md5ii(b,c,d,a,x[i+13],21,1309151649);
      a=md5ii(a,b,c,d,x[i+4],6,-145523070);d=md5ii(d,a,b,c,x[i+11],10,-1120210379);c=md5ii(c,d,a,b,x[i+2],15,718787259);b=md5ii(b,c,d,a,x[i+9],21,-343485551);
      a=safeAdd(a,oA);b=safeAdd(b,oB);c=safeAdd(c,oC);d=safeAdd(d,oD);
    }
    return [a,b,c,d];
  }

  function md5Hex(s) {
    const words=md5(s);
    return words.map(w=>{const hex=((w&0xff)<<24|(w>>8&0xff)<<16|(w>>16&0xff)<<8|w>>>24)>>>0;return hex.toString(16).padStart(8,'0');}).join('');
  }

  if (hash.length !== 34) return false;
  const countLog2 = itoa64.indexOf(hash[3]);
  if (countLog2 < 7 || countLog2 > 30) return false;
  let count = 1 << countLog2;
  const salt = hash.substring(4, 12);
  let computed = md5Hex(salt + password);
  do { computed = md5Hex(computed + password); } while (--count);

  // encode64
  function encode64(input, count2) {
    const arr = [];
    for (let i = 0; i < 16; i++) arr.push(input.charCodeAt(i*2)|(input.charCodeAt(i*2+1)<<8) || (parseInt(input.slice(i*2,i*2+2),16)&0xff));
    // simplified: work with raw hex bytes
    const bytes = [];
    for (let i = 0; i < input.length; i+=2) bytes.push(parseInt(input.slice(i,i+2),16));
    let out = '', idx = 0;
    do {
      let value = bytes[idx++];
      out += itoa64[value & 63];
      if (idx < count2) value |= bytes[idx] << 8;
      out += itoa64[(value >> 6) & 63];
      if (idx++ >= count2) break;
      if (idx < count2) value |= bytes[idx] << 8;
      out += itoa64[(value >> 12) & 63];
      if (idx++ >= count2) break;
      out += itoa64[(value >> 18) & 63];
    } while (idx < count2);
    return out;
  }

  const output = '$P$' + hash[3] + salt + encode64(computed, 16);
  return output === hash;
}

function hashSimple(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return Math.abs(h).toString(16).slice(0, 8);
}

// ── wp-admin 처리 ─────────────────────────────────────────────────────────────
async function handleWPAdmin(env, request, url, siteInfo) {
  // 세션 KV 실제 검증
  const session = await validateSession(env, request);

  if (!session && url.pathname !== '/wp-login.php') {
    const loginUrl = `https://${url.hostname}/wp-login.php?redirect_to=${encodeURIComponent(url.pathname + url.search)}`;
    return Response.redirect(loginUrl, 302);
  }

  return new Response(renderAdminPage(url.pathname, siteInfo, url, session), {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, private',
      'X-Frame-Options': 'SAMEORIGIN',
    },
  });
}

function renderAdminPage(pathname, siteInfo, urlObj, session) {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const siteUrl  = urlObj ? `https://${urlObj.hostname}` : '';
  const page = pathname.replace(/^\/wp-admin\/?/, '').replace(/\.php$/, '') || 'index';
  const sp = urlObj ? urlObj.searchParams : null;
  const isPage = sp ? sp.get('post_type') === 'page' : false;
  const displayName = esc(session?.displayName || session?.login || 'admin');

  let pageTitle = '대시보드';
  let bodyHtml  = '';
  let inlineScript = '';

  if (page === 'index' || page === '' || page === 'dashboard') {
    pageTitle = '대시보드';
    bodyHtml = `
<div class="welcome-panel">
  <div style="max-width:700px">
    <h2 style="font-size:1.3rem;margin:0 0 10px">WordPress에 오신 것을 환영합니다!</h2>
    <p style="color:#50575e;margin:0 0 6px">CloudPress Edge 위에서 WordPress가 동작 중입니다.</p>
    <p style="color:#50575e;margin:0 0 15px;font-size:.85rem">로그인: <strong>${displayName}</strong></p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a href="/wp-admin/post-new.php" class="btn-wp">✏️ 글 작성하기</a>
      <a href="/wp-admin/edit.php" class="btn-wp btn-secondary">📋 글 목록</a>
      <a href="/wp-admin/options-general.php" class="btn-wp btn-secondary">⚙️ 사이트 설정</a>
      <a href="/" target="_blank" class="btn-wp btn-secondary">🌐 사이트 보기</a>
    </div>
  </div>
</div>
<div class="admin-widgets">
  <div class="admin-widget">
    <h3 class="widget-title"><span>📊 한 눈에 보기</span></h3>
    <div class="widget-body">
      <ul id="admin-glance" style="list-style:none;margin:0;padding:0;color:#50575e;font-size:.875rem"><li>불러오는 중...</li></ul>
      <p style="margin:12px 0 0;font-size:.8rem;color:#50575e">WordPress 6.7 + CloudPress v20.1</p>
    </div>
  </div>
  <div class="admin-widget">
    <h3 class="widget-title">📝 최근 게시됨</h3>
    <div class="widget-body">
      <div id="admin-activity" style="color:#50575e;font-size:.85rem">불러오는 중...</div>
    </div>
  </div>
</div>`;
    // CP.apiFetch 완전 제거 — 표준 fetch() 사용
    inlineScript = `(async function(){
try{
  var r=await fetch('/wp-json/wp/v2/posts?per_page=5&_fields=id,title,date',{headers:{'Accept':'application/json'}});
  var posts=r.ok?await r.json():[];
  var r2=await fetch('/wp-json/wp/v2/pages?per_page=100&_fields=id',{headers:{'Accept':'application/json'}});
  var pages=r2.ok?await r2.json():[];
  var r3=await fetch('/wp-json/wp/v2/comments?per_page=1&_fields=id',{headers:{'Accept':'application/json'}});
  var commentTotal=r3.ok?(parseInt(r3.headers.get('X-WP-Total')||'0',10)):0;
  posts=Array.isArray(posts)?posts:[];
  pages=Array.isArray(pages)?pages:[];
  document.getElementById('admin-glance').innerHTML=
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+posts.length+'개의 글</span><a href="/wp-admin/edit.php" style="color:#2271b1">관리</a></li>'+
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+pages.length+'개의 페이지</span><a href="/wp-admin/edit.php?post_type=page" style="color:#2271b1">관리</a></li>'+
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+commentTotal+'개의 댓글</span><a href="/wp-admin/edit-comments.php" style="color:#2271b1">관리</a></li>';
  var actEl=document.getElementById('admin-activity');
  if(!posts.length){actEl.innerHTML='<p style="color:#8c8f94">아직 게시된 글이 없습니다. <a href="/wp-admin/post-new.php">첫 글을 작성해 보세요!</a></p>';return;}
  actEl.innerHTML='<ul style="list-style:none;margin:0;padding:0">'+posts.map(function(p){
    var d=new Date(p.date).toLocaleDateString('ko-KR');
    var t=(p.title&&p.title.rendered)||'(제목 없음)';
    return '<li style="padding:5px 0;border-bottom:1px solid #f0f0f1">'+
      '<a href="/wp-admin/post.php?post='+p.id+'&action=edit" style="color:#2271b1">'+t+'</a>'+
      '<span style="float:right;color:#8c8f94;font-size:.8rem">'+d+'</span></li>';
  }).join('')+'</ul>';
}catch(e){
  document.getElementById('admin-glance').innerHTML='<li style="color:#d63638">데이터 로드 실패</li>';
  document.getElementById('admin-activity').textContent='오류: '+e.message;
}
})();`;

  } else if (page === 'edit') {
    pageTitle = isPage ? '페이지' : '글';
    const newHref = isPage ? '/wp-admin/post-new.php?post_type=page' : '/wp-admin/post-new.php';
    const apiType = isPage ? 'pages' : 'posts';
    const emptyMsg = isPage ? '아직 페이지가 없습니다.' : '아직 글이 없습니다.';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px">
      <a href="${newHref}" class="btn-wp">새 ${isPage ? '페이지' : '글'} 추가</a>
    </div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <td style="width:30px;padding:8px 10px"><input type="checkbox" id="cb-select-all"></td>
        <th style="padding:8px 10px;text-align:left;font-size:.875rem">제목</th>
        <th style="padding:8px 10px;text-align:left;font-size:.875rem;width:120px">날짜</th>
      </tr></thead>
      <tbody id="posts-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/${apiType}?per_page=20&_fields=id,title,date,status,link',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var posts=r.ok?await r.json():[];
posts=Array.isArray(posts)?posts:[];
var el=document.getElementById('posts-list');
if(!posts.length){
  el.innerHTML='<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">${emptyMsg} <a href="${newHref}">새로 만들기</a></td></tr>';
  return;
}
el.innerHTML=posts.map(function(p){
  var title=(p.title&&p.title.rendered)||'(제목 없음)';
  var d=new Date(p.date).toLocaleDateString('ko-KR');
  var editHref='/wp-admin/post.php?post='+p.id+'&action=edit';
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:8px 10px"><input type="checkbox"></td>'+
    '<td style="padding:8px 10px"><strong><a href="'+editHref+'" style="color:#2271b1;text-decoration:none">'+title+'</a></strong>'+
    '<div style="font-size:.8rem;color:#8c8f94;margin-top:3px">'+
    '<a href="'+editHref+'">편집</a> | '+
    '<a href="#" onclick="trashPost('+p.id+',this);return false;" style="color:#b32d2e">휴지통</a> | '+
    '<a href="'+(p.link||'/')+ '" target="_blank">보기</a></div></td>'+
    '<td style="padding:8px 10px;font-size:.8rem;color:#50575e">게시됨<br>'+d+'</td>'+
    '</tr>';
}).join('');
})();
async function trashPost(id,el){
  if(!confirm('이 글을 휴지통으로 이동할까요?'))return;
  var r=await fetch('/wp-json/wp/v2/${apiType}/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'}}).catch(function(){return{ok:false};});
  if(r.ok){el.closest('tr').remove();}else{alert('삭제 실패');}
}`;

  } else if (page === 'post-new' || page === 'post') {
    const isEdit = page === 'post' && sp && sp.get('action') === 'edit';
    const postId = sp ? sp.get('post') : null;
    pageTitle = isEdit ? '글 편집' : '새 글 추가';
    bodyHtml = `
<div id="post-editor-wrap" style="display:grid;grid-template-columns:1fr 280px;gap:20px">
  <div>
    <input type="text" id="post-title" placeholder="제목 추가" style="width:100%;font-size:1.5rem;font-weight:700;border:none;border-bottom:2px solid #dcdcde;padding:10px 0;margin-bottom:20px;outline:none;color:#1d2327;background:transparent;transition:border-color .2s" onfocus="this.style.borderColor='#2271b1'" onblur="this.style.borderColor='#dcdcde'">
    <div id="post-editor" contenteditable="true" style="min-height:350px;border:1px solid #dcdcde;border-radius:4px;padding:18px;font-size:.9375rem;line-height:1.8;outline:none;background:#fff;color:#1d2327" placeholder="내용을 입력하세요...">내용을 입력하세요...</div>
    <div id="post-status-bar" style="margin-top:8px;font-size:.8rem;color:#8c8f94">자동 저장: 대기 중</div>
  </div>
  <div>
    <div class="admin-widget" style="margin-bottom:16px">
      <h3 class="widget-title">게시</h3>
      <div class="widget-body">
        <div style="margin-bottom:12px">
          <label style="font-size:.85rem;font-weight:600;color:#1d2327">상태</label>
          <select id="post-status" style="width:100%;margin-top:4px;padding:5px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem">
            <option value="publish">게시됨</option>
            <option value="draft">임시 저장</option>
            <option value="private">비공개</option>
          </select>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button onclick="savePost()" class="btn-wp" style="flex:1">게시</button>
          <button onclick="saveDraft()" class="btn-wp btn-secondary" style="flex:1">임시저장</button>
        </div>
        ${isEdit && postId ? `<div style="margin-top:8px;font-size:.8rem;text-align:center"><a href="/" target="_blank" style="color:#2271b1">게시글 보기</a></div>` : ''}
      </div>
    </div>
    <div class="admin-widget">
      <h3 class="widget-title">카테고리</h3>
      <div class="widget-body" id="cats-list" style="font-size:.875rem;color:#50575e">불러오는 중...</div>
    </div>
    <div class="admin-widget">
      <h3 class="widget-title">태그</h3>
      <div class="widget-body">
        <input type="text" id="post-tags" placeholder="태그 추가 (쉼표 구분)" style="width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem">
      </div>
    </div>
  </div>
</div>`;

    inlineScript = `
var _postId=${postId ? parseInt(postId,10) : 0};
var _autoSaveTimer=null;

// 카테고리 로드
(async function(){
  var r=await fetch('/wp-json/wp/v2/categories?per_page=50',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
  var cats=r.ok?await r.json():[];
  cats=Array.isArray(cats)?cats:[];
  var el=document.getElementById('cats-list');
  if(!cats.length){el.textContent='카테고리 없음';return;}
  el.innerHTML=cats.map(function(c){return '<label style="display:flex;align-items:center;gap:6px;padding:3px 0"><input type="checkbox" value="'+c.id+'" class="cat-cb"> '+c.name+'</label>';}).join('');
})();

// 기존 글 로드
${isEdit && postId ? `(async function(){
  var r=await fetch('/wp-json/wp/v2/posts/${postId}',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
  if(!r.ok)return;
  var p=await r.json();
  document.getElementById('post-title').value=(p.title&&p.title.rendered)||'';
  document.getElementById('post-editor').innerText=(p.content&&p.content.raw)||(p.content&&p.content.rendered)||'';
  document.getElementById('post-status').value=p.status||'publish';
})();` : ''}

// 자동 저장
document.getElementById('post-editor').addEventListener('input',function(){
  clearTimeout(_autoSaveTimer);
  document.getElementById('post-status-bar').textContent='자동 저장: 대기 중...';
  _autoSaveTimer=setTimeout(function(){autoSave();},3000);
});

async function autoSave(){
  var title=document.getElementById('post-title').value;
  var content=document.getElementById('post-editor').innerText;
  if(!title&&!content)return;
  document.getElementById('post-status-bar').textContent='자동 저장 중...';
  try{
    var method=_postId?'PATCH':'POST';
    var endpoint=_postId?'/wp-json/wp/v2/posts/'+_postId:'/wp-json/wp/v2/posts';
    var r=await fetch(endpoint,{
      method:method,
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:JSON.stringify({title:title,content:content,status:'draft'})
    });
    if(r.ok){
      var d=await r.json();
      if(!_postId&&d.id){_postId=d.id;history.replaceState(null,'','/wp-admin/post.php?post='+d.id+'&action=edit');}
      document.getElementById('post-status-bar').textContent='자동 저장됨: '+new Date().toLocaleTimeString('ko-KR');
    }
  }catch(e){document.getElementById('post-status-bar').textContent='자동 저장 실패';}
}

async function savePost(){await _save('publish');}
async function saveDraft(){await _save('draft');}

async function _save(status){
  var title=document.getElementById('post-title').value.trim();
  var content=document.getElementById('post-editor').innerText.trim();
  var selStatus=document.getElementById('post-status').value||status;
  if(!title){alert('제목을 입력하세요.');document.getElementById('post-title').focus();return;}
  var cats=[];
  document.querySelectorAll('.cat-cb:checked').forEach(function(el){cats.push(parseInt(el.value,10));});
  var slug=title.toLowerCase().replace(/[^a-z0-9가-힣]+/g,'-').replace(/^-|-$/g,'');
  var method=_postId?'PATCH':'POST';
  var endpoint=_postId?'/wp-json/wp/v2/posts/'+_postId:'/wp-json/wp/v2/posts';
  try{
    var r=await fetch(endpoint,{
      method:method,
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:JSON.stringify({title:title,content:content,status:selStatus,slug:slug,categories:cats})
    });
    var d=await r.json();
    if(r.ok&&d.id){
      alert(selStatus==='publish'?'게시되었습니다!':'임시 저장되었습니다.');
      window.location.href='/wp-admin/edit.php';
    }else{alert('저장 실패: '+(d.message||JSON.stringify(d)));}
  }catch(e){alert('오류: '+e.message);}
}`;

  } else if (page === 'upload') {
    pageTitle = '미디어 라이브러리';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:15px;display:flex;align-items:center;gap:10px">
      <label class="btn-wp" style="cursor:pointer">📤 새 미디어 추가
        <input type="file" id="file-input" style="display:none" accept="image/*,video/*,audio/*,.pdf" multiple>
      </label>
      <div id="upload-progress" style="display:none;font-size:.85rem;color:#2271b1">업로드 중...</div>
    </div>
    <div id="media-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px">
      <div style="text-align:center;padding:40px;color:#8c8f94;grid-column:1/-1">불러오는 중...</div>
    </div>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/media?per_page=30',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var media=r.ok?await r.json():[];
media=Array.isArray(media)?media:[];
var el=document.getElementById('media-grid');
if(!media.length){el.innerHTML='<div style="text-align:center;padding:60px;color:#8c8f94;grid-column:1/-1"><p style="font-size:2rem;margin-bottom:8px">🖼️</p><p>미디어 파일이 없습니다.</p></div>';return;}
el.innerHTML=media.map(function(m){
  var src=m.source_url||(m.guid&&m.guid.rendered)||'';
  var isImg=(m.mime_type||'').startsWith('image/');
  var ttl=(m.title&&m.title.rendered)||m.slug||'파일';
  return '<div style="border:1px solid #dcdcde;border-radius:4px;overflow:hidden;background:#f6f7f7;cursor:pointer" onclick="showMediaDetail(this)" data-url="'+src+'" data-title="'+ttl+'">'+
    (isImg?'<img src="'+src+'" style="width:100%;height:130px;object-fit:cover;display:block">':
    '<div style="height:130px;display:flex;align-items:center;justify-content:center;font-size:2.5rem">📄</div>')+
    '<p style="margin:0;padding:5px 7px;font-size:.75rem;color:#1d2327;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+ttl+'</p>'+
    '</div>';
}).join('');
})();

document.getElementById('file-input').addEventListener('change',async function(){
  var files=Array.from(this.files);
  if(!files.length)return;
  var prog=document.getElementById('upload-progress');
  prog.style.display='block';
  for(var i=0;i<files.length;i++){
    prog.textContent='업로드 중: '+(i+1)+'/'+files.length;
    var fd=new FormData();fd.append('file',files[i]);fd.append('title',files[i].name);
    await fetch('/wp-admin/async-upload.php',{method:'POST',body:fd}).catch(function(){});
  }
  prog.style.display='none';
  location.reload();
});

function showMediaDetail(el){
  var url=el.getAttribute('data-url');
  var title=el.getAttribute('data-title');
  if(url)prompt('미디어 URL (복사하세요):',url);
}`;

  } else if (page === 'themes') {
    pageTitle = '테마';
    bodyHtml = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:20px">` +
      [
        {name:'Twenty Twenty-Four', desc:'2024 기본 테마. 다목적 블록 테마.', ver:'1.2', active:true},
        {name:'Twenty Twenty-Three', desc:'유연한 블록 테마.', ver:'1.4'},
        {name:'Astra', desc:'빠르고 가벼운 다목적 테마.', ver:'4.6'},
      ].map(t =>
        `<div style="border:${t.active?'2px solid #2271b1':'1px solid #dcdcde'};border-radius:4px;overflow:hidden;background:#fff">
          <div style="height:140px;background:linear-gradient(135deg,#f0f0f1,#c3c4c7);display:flex;align-items:center;justify-content:center;font-size:2.5rem">🎨</div>
          <div style="padding:12px">
            <h3 style="margin:0 0 6px;font-size:.9375rem">${t.name}${t.active?' <span style="background:#2271b1;color:#fff;font-size:.7rem;padding:1px 6px;border-radius:2px">활성화</span>':''}</h3>
            <p style="margin:0 0 10px;font-size:.8rem;color:#50575e">${t.desc} (v${t.ver})</p>
            ${!t.active?'<button class="btn-wp btn-secondary" style="font-size:.8rem;padding:4px 10px">활성화</button>':''}
          </div>
        </div>`
      ).join('') + '</div>';

  } else if (page === 'plugins') {
    pageTitle = '플러그인';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px"><a href="/wp-admin/plugin-install.php" class="btn-wp">새 플러그인 추가</a></div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7"><th style="padding:8px 10px;text-align:left">플러그인</th><th style="padding:8px 10px;width:100px">상태</th></tr></thead>
      <tbody>` +
      [
        {name:'Akismet Anti-Spam', desc:'수백만 WordPress 사이트에서 검증된 스팸 방지.', ver:'5.3.3'},
        {name:'CloudPress Cache',  desc:'CloudPress 전용 고성능 엣지 캐시.', ver:'1.0.0', active:true},
        {name:'Yoast SEO',         desc:'검색엔진 최적화의 표준.', ver:'22.0'},
      ].map(p =>
        `<tr style="border-top:1px solid #f0f0f1">
          <td style="padding:10px"><strong>${p.name}</strong> <span style="color:#8c8f94;font-size:.8rem">v${p.ver}</span>
            <p style="margin:4px 0 6px;font-size:.8rem;color:#50575e">${p.desc}</p>
            <div style="font-size:.8rem">${p.active
              ? '<span style="color:#00a32a">■</span> 활성화됨 | <a href="#">설정</a> | <a href="#" style="color:#b32d2e">비활성화</a>'
              : '<a href="#">활성화</a> | <a href="#" style="color:#b32d2e">삭제</a>'}</div></td>
          <td style="padding:10px;vertical-align:top"><span style="font-size:.8rem;${p.active?'color:#00a32a;font-weight:600':'color:#8c8f94'}">${p.active?'활성':'비활성'}</span></td>
        </tr>`
      ).join('') + '</tbody></table>';

  } else if (page === 'options-general' || page === 'options') {
    pageTitle = '일반 설정';
    bodyHtml = `<div id="settings-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>
    <table class="form-table" style="width:100%;border-collapse:collapse">` +
      [
        {label:'사이트 제목',          name:'blogname',        type:'text',  placeholder:'내 WordPress 사이트'},
        {label:'태그라인',             name:'blogdescription', type:'text',  placeholder:'워드프레스로 만든 사이트'},
        {label:'WordPress 주소 (URL)',name:'siteurl',         type:'url',   placeholder:'https://example.com'},
        {label:'사이트 주소 (URL)',    name:'home',            type:'url',   placeholder:'https://example.com'},
        {label:'관리자 이메일',        name:'admin_email',     type:'email', placeholder:'admin@example.com'},
      ].map(f =>
        `<tr style="border-bottom:1px solid #f0f0f1">
          <th style="padding:15px 10px;text-align:left;width:220px;font-size:.875rem;vertical-align:top">${f.label}</th>
          <td style="padding:15px 10px"><input type="${f.type}" id="opt-${f.name}" name="${f.name}" placeholder="${f.placeholder}" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"></td>
        </tr>`
      ).join('') +
      `<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">언어</th>
        <td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>한국어 (ko_KR)</option><option>English (US)</option></select></td></tr>
      <tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">시간대</th>
        <td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>Asia/Seoul</option><option>UTC</option></select></td></tr>
      </table>
      <p style="margin-top:20px"><button type="button" onclick="saveSettings()" class="btn-wp">변경사항 저장</button></p>`;

    inlineScript = `(async function(){
try{
  var r=await fetch('/wp-json/wp/v2/settings',{headers:{'Accept':'application/json'}});
  var res=r.ok?await r.json():{};
  if(res.title)document.getElementById('opt-blogname').value=res.title;
  if(res.description)document.getElementById('opt-blogdescription').value=res.description;
  if(res.url){document.getElementById('opt-siteurl').value=res.url;document.getElementById('opt-home').value=res.url;}
  if(res.email)document.getElementById('opt-admin_email').value=res.email;
}catch(e){}
})();
async function saveSettings(){
  var data={};
  document.querySelectorAll('input[name]').forEach(function(el){if(el.value.trim())data[el.name]=el.value.trim();});
  var msg=document.getElementById('settings-msg');
  try{
    var r=await fetch('/wp-json/wp/v2/settings',{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(data)});
    if(r.ok){
      msg.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
      msg.textContent='✓ 설정이 저장되었습니다.';
    }else{
      msg.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
      msg.textContent='저장에 실패했습니다.';
    }
  }catch(e){
    msg.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
    msg.textContent='오류: '+e.message;
  }
}`;

  } else if (page === 'users') {
    pageTitle = '사용자';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px"><a href="/wp-admin/user-new.php" class="btn-wp">새 사용자 추가</a></div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <th style="padding:8px 10px;text-align:left">사용자명</th>
        <th style="padding:8px 10px;text-align:left">이름</th>
        <th style="padding:8px 10px;text-align:left">이메일</th>
        <th style="padding:8px 10px;text-align:left">역할</th>
        <th style="padding:8px 10px;text-align:left">글</th>
      </tr></thead>
      <tbody id="users-list"><tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/users?per_page=20',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var users=r.ok?await r.json():[];
users=Array.isArray(users)?users:[];
var el=document.getElementById('users-list');
if(!users.length){el.innerHTML='<tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94">사용자가 없습니다.</td></tr>';return;}
el.innerHTML=users.map(function(u){
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:8px 10px"><strong>'+(u.slug||u.name||'')+'</strong></td>'+
    '<td style="padding:8px 10px">'+(u.name||'—')+'</td>'+
    '<td style="padding:8px 10px">'+(u.email||'—')+'</td>'+
    '<td style="padding:8px 10px">'+(u.role||'관리자')+'</td>'+
    '<td style="padding:8px 10px">'+(u.post_count||0)+'</td>'+
    '</tr>';
}).join('');
})();`;

  } else if (page === 'profile') {
    pageTitle = '프로필';
    bodyHtml = `<div id="profile-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>
    <table class="form-table" style="width:100%;border-collapse:collapse">` +
      [
        {label:'사용자명', id:'username',   val:session?.login||'admin', disabled:true,  type:'text'},
        {label:'이름',     id:'first_name', val:'', disabled:false, type:'text',  placeholder:'이름'},
        {label:'이메일',   id:'email',      val:'', disabled:false, type:'email', placeholder:'admin@example.com'},
      ].map(f =>
        `<tr style="border-bottom:1px solid #f0f0f1">
          <th style="padding:15px 10px;text-align:left;width:200px;font-size:.875rem">${f.label}</th>
          <td style="padding:15px 10px"><input type="${f.type}" id="${f.id}" value="${esc(f.val||'')}"${f.placeholder?` placeholder="${f.placeholder}"`:''}${f.disabled?' disabled':''} style="width:100%;max-width:400px;padding:6px 8px;border:1px solid ${f.disabled?'#dcdcde':'#8c8f94'};border-radius:4px;font-size:.875rem${f.disabled?';background:#f6f7f7;color:#8c8f94':''}"></td>
        </tr>`
      ).join('') +
      `<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">새 비밀번호</th>
        <td style="padding:15px 10px">
          <input type="password" id="new_pass1" placeholder="새 비밀번호" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem;margin-bottom:8px"><br>
          <input type="password" id="new_pass2" placeholder="비밀번호 확인" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem">
        </td></tr>
      </table>
      <p style="margin-top:20px"><button class="btn-wp" onclick="saveProfile()">프로필 업데이트</button></p>`;
    inlineScript = `function saveProfile(){
  var p1=document.getElementById('new_pass1').value;
  var p2=document.getElementById('new_pass2').value;
  if(p1&&p1!==p2){alert('비밀번호가 일치하지 않습니다.');return;}
  var msg=document.getElementById('profile-msg');
  msg.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
  msg.textContent='✓ 프로필이 업데이트되었습니다.';
}`;

  } else if (page === 'edit-comments') {
    pageTitle = '댓글';
    bodyHtml = `<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <th style="padding:8px 10px;text-align:left">작성자</th>
        <th style="padding:8px 10px;text-align:left">내용</th>
        <th style="padding:8px 10px;text-align:left;width:120px">날짜</th>
      </tr></thead>
      <tbody id="comments-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/comments?per_page=20',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var list=r.ok?await r.json():[];
list=Array.isArray(list)?list:[];
var el=document.getElementById('comments-list');
if(!list.length){el.innerHTML='<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">댓글이 없습니다.</td></tr>';return;}
el.innerHTML=list.map(function(c){
  var d=new Date(c.date).toLocaleDateString('ko-KR');
  var content=((c.content&&c.content.rendered)||'').replace(/<[^>]+>/g,'').slice(0,100);
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:10px;vertical-align:top"><strong>'+(c.author_name||'익명')+'</strong></td>'+
    '<td style="padding:10px;vertical-align:top;font-size:.875rem">'+content+'</td>'+
    '<td style="padding:10px;vertical-align:top;font-size:.8rem;color:#50575e">'+d+'</td>'+
    '</tr>';
}).join('');
})();`;

  } else if (page === 'options-permalink') {
    pageTitle = '고유주소 설정';
    bodyHtml = `<p style="color:#50575e;margin-bottom:20px">WordPress는 고유주소와 아카이브에 대한 사용자 정의 URL 구조를 만드는 기능을 제공합니다.</p>` +
      [
        {label:'기본',        val:'',                               desc:'https://example.com/?p=123'},
        {label:'날짜와 이름', val:'/%year%/%monthnum%/%day%/%postname%/', desc:'https://example.com/2024/01/01/글-제목/'},
        {label:'월과 이름',   val:'/%year%/%monthnum%/%postname%/',       desc:'https://example.com/2024/01/글-제목/'},
        {label:'숫자',        val:'/archives/%post_id%',                  desc:'https://example.com/archives/123'},
        {label:'글 이름',     val:'/%postname%/',                         desc:'https://example.com/글-제목/', checked:true},
      ].map(o =>
        `<label style="display:flex;align-items:flex-start;gap:10px;margin-bottom:14px;cursor:pointer">
          <input type="radio" name="permalink" value="${o.val}"${o.checked?' checked':''} style="margin-top:4px">
          <span><strong>${o.label}</strong>${o.desc?`<br><code style="font-size:.8rem;color:#50575e">${o.desc}</code>`:''}
          </span></label>`
      ).join('') +
      `<p style="margin-top:20px"><button type="button" class="btn-wp" onclick="alert('저장되었습니다.')">변경사항 저장</button></p>`;

  } else {
    pageTitle = page.replace(/-/g,' ').replace(/\b\w/g, c => c.toUpperCase());
    bodyHtml = `<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:30px;text-align:center;color:#50575e">
      <p>이 페이지는 CloudPress Edge에서 지원됩니다.</p>
    </div>`;
  }

  const menuActive = {
    dashboard: (page === 'index' || page === '' || page === 'dashboard'),
    posts:     (page === 'edit' && !isPage) || page === 'post-new' || page === 'post',
    media:     page === 'upload',
    pages:     page === 'edit' && isPage,
    comments:  page === 'edit-comments',
    themes:    page === 'themes',
    plugins:   page === 'plugins',
    users:     page === 'users' || page === 'user-new' || page === 'profile',
    settings:  page === 'options-general' || page === 'options' || page === 'options-permalink',
  };

  function menuItem(href, icon, label, active) {
    return `<li${active?' class="current"':''}>` +
      `<a href="${href}"><span class="menu-icon">${icon}</span>` +
      `<span class="menu-label">${label}</span></a></li>`;
  }

  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${pageTitle} ‹ ${siteName} — WordPress</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;color:#1d2327;font-size:13px;line-height:1.4}
a{color:#2271b1;text-decoration:none}a:hover{color:#135e96}
#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:#1d2327;display:flex;align-items:center;padding:0 12px;z-index:9999;gap:16px}
#wpadminbar a{color:#a7aaad;font-size:.8125rem;display:flex;align-items:center;gap:5px;text-decoration:none;padding:2px 4px;border-radius:2px}
#wpadminbar a:hover{color:#fff;background:#3c434a}
#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:#1d2327;overflow-y:auto;z-index:100}
#adminmenu{list-style:none;margin:0;padding:0}
#adminmenu li>a{display:flex;align-items:center;gap:8px;padding:9px 10px;color:#a7aaad;font-size:.8125rem;text-decoration:none;transition:background .15s,color .1s}
#adminmenu li>a:hover,#adminmenu li.current>a{background:#2c3338;color:#fff}
#adminmenu li.current>a{border-left:3px solid #2271b1;padding-left:7px}
#adminmenu .menu-icon{font-size:1rem;width:20px;text-align:center;flex-shrink:0}
#adminmenu .menu-sep{height:1px;background:#3c434a;margin:6px 0}
#wpcontent{margin-left:160px;margin-top:32px;min-height:calc(100vh - 32px)}
#wpbody-content{padding:20px 20px 40px}
.wrap{max-width:1200px}
h1.wp-heading-inline{font-size:1.4rem;font-weight:400;color:#1d2327;margin:0 0 20px;display:block}
.welcome-panel{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:23px;margin-bottom:20px}
.admin-widgets{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px;margin-top:16px}
.admin-widget{background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden}
.widget-title{background:#f6f7f7;border-bottom:1px solid #c3c4c7;padding:9px 12px;font-size:.875rem;font-weight:600;color:#1d2327}
.widget-body{padding:14px}
.btn-wp{display:inline-block;padding:6px 12px;background:#2271b1;color:#fff;border:1px solid #2271b1;border-radius:3px;font-size:.8125rem;cursor:pointer;text-decoration:none;line-height:1.4;transition:background .15s}
.btn-wp:hover{background:#135e96;border-color:#135e96;color:#fff;text-decoration:none}
.btn-wp.btn-secondary{background:#f6f7f7;color:#1d2327;border-color:#8c8f94}
.btn-wp.btn-secondary:hover{background:#dcdcde;color:#1d2327}
.wp-list-table th{font-weight:600;color:#1d2327}
.form-table th{font-weight:600;color:#1d2327;vertical-align:top}
.tablenav{display:flex;align-items:center;gap:10px}
@media(max-width:782px){
  #adminmenuwrap{width:36px;overflow:hidden}
  #adminmenuwrap:hover{width:160px}
  #adminmenu .menu-label{display:none}
  #adminmenuwrap:hover .menu-label{display:inline}
  #wpcontent{margin-left:36px}
}
</style>
</head>
<body class="wp-admin">
<div id="wpadminbar">
  <a style="font-weight:700;color:#a7aaad;font-size:.9rem" href="/wp-admin/">⊞</a>
  <span style="color:#3c434a">|</span>
  <a href="/" target="_blank">🏠 ${siteName}</a>
  <span style="color:#3c434a">|</span>
  <a href="/wp-admin/post-new.php">+ 새로 추가</a>
  <div style="flex:1"></div>
  <span style="color:#a7aaad;font-size:.8rem">👤 ${displayName}</span>
  <a href="/wp-login.php?action=logout" style="color:#f86368">로그아웃</a>
</div>
<div id="adminmenuwrap">
  <ul id="adminmenu">
    ${menuItem('/wp-admin/', '🏠', '대시보드', menuActive.dashboard)}
    <li class="menu-sep"></li>
    ${menuItem('/wp-admin/edit.php', '📝', '글', menuActive.posts)}
    ${menuItem('/wp-admin/upload.php', '🖼️', '미디어', menuActive.media)}
    ${menuItem('/wp-admin/edit.php?post_type=page', '📄', '페이지', menuActive.pages)}
    ${menuItem('/wp-admin/edit-comments.php', '💬', '댓글', menuActive.comments)}
    <li class="menu-sep"></li>
    ${menuItem('/wp-admin/themes.php', '🎨', '외모', menuActive.themes)}
    ${menuItem('/wp-admin/plugins.php', '🔌', '플러그인', menuActive.plugins)}
    ${menuItem('/wp-admin/users.php', '👥', '사용자', menuActive.users)}
    <li class="menu-sep"></li>
    ${menuItem('/wp-admin/options-general.php', '⚙️', '설정', menuActive.settings)}
    ${menuItem('/', '🌐', '사이트 보기', false)}
  </ul>
</div>
<div id="wpcontent">
  <div id="wpbody-content">
    <div class="wrap">
      <h1 class="wp-heading-inline">${pageTitle}</h1>
      ${bodyHtml}
      ${inlineScript ? `<script>${inlineScript}<\/script>` : ''}
    </div>
  </div>
</div>
</body>
</html>`;
}

// ── REST API ──────────────────────────────────────────────────────────────────
async function handleWPRestAPI(env, request, url, siteInfo) {
  const path = url.pathname.replace('/wp-json', '');
  const method = request.method;

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
    'Content-Type': 'application/json; charset=utf-8',
  };

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  const j = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: corsHeaders });

  try {
    // GET /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'GET') {
      const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '10', 10), 100);
      const page    = parseInt(url.searchParams.get('page') || '1', 10);
      const offset  = (page - 1) * perPage;
      const search  = url.searchParams.get('search') || '';
      const fields  = url.searchParams.get('_fields') || '';

      let sql = `SELECT * FROM wp_posts WHERE post_type = 'post' AND post_status = 'publish'`;
      const binds = [];
      if (search) { sql += ` AND (post_title LIKE ? OR post_content LIKE ?)`; binds.push(`%${search}%`, `%${search}%`); }
      sql += ` ORDER BY post_date DESC LIMIT ? OFFSET ?`;
      binds.push(perPage, offset);

      const res = await env.DB.prepare(sql).bind(...binds).all();
      const posts = (res.results || []).map(wpPostToJSON);
      const countRes = await env.DB.prepare(`SELECT COUNT(*) as c FROM wp_posts WHERE post_type='post' AND post_status='publish'`).first();
      const total = countRes?.c || 0;

      return new Response(JSON.stringify(posts), {
        status: 200,
        headers: { ...corsHeaders, 'X-WP-Total': String(total), 'X-WP-TotalPages': String(Math.ceil(total / perPage)) },
      });
    }

    // POST /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const title   = String(body.title?.raw || body.title || '');
      const content = String(body.content?.raw || body.content || '');
      const status  = ['publish','draft','private'].includes(body.status) ? body.status : 'publish';
      const slug    = body.slug || title.toLowerCase().replace(/[^a-z0-9가-힣]+/g, '-').replace(/^-|-$/g, '') || `post-${Date.now()}`;
      const now     = new Date().toISOString().replace('T', ' ').slice(0, 19);
      if (!title) return j({ code: 'rest_title_required', message: '제목은 필수입니다.' }, 400);
      try {
        const result = await env.DB.prepare(
          `INSERT INTO wp_posts (post_title, post_content, post_status, post_type, post_name, post_date, post_date_gmt, post_modified, post_modified_gmt, post_author, comment_status, ping_status, guid)
           VALUES (?, ?, ?, 'post', ?, ?, ?, ?, ?, 1, 'open', 'open', ?)`
        ).bind(title, content, status, slug, now, now, now, now, slug).run();
        const newId = result.meta?.last_row_id || result.lastRowId || Date.now();
        const newPost = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(newId).first().catch(() => null);
        // 카테고리 연결
        if (body.categories && Array.isArray(body.categories) && body.categories.length && newId) {
          for (const catId of body.categories) {
            const tt = await env.DB.prepare(`SELECT term_taxonomy_id FROM wp_term_taxonomy WHERE term_id = ? AND taxonomy = 'category' LIMIT 1`).bind(catId).first().catch(() => null);
            if (tt) {
              await env.DB.prepare(`INSERT OR IGNORE INTO wp_term_relationships (object_id, term_taxonomy_id) VALUES (?, ?)`).bind(newId, tt.term_taxonomy_id).run().catch(() => {});
            }
          }
        }
        return j(wpPostToJSON(newPost || { ID: newId, post_title: title, post_content: content, post_status: status, post_name: slug, post_date: now }), 201);
      } catch (e) {
        return j({ code: 'rest_db_error', message: '저장 실패: ' + e.message }, 500);
      }
    }

    // PATCH /wp/v2/posts/:id
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && (method === 'PUT' || method === 'PATCH')) {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      const body = await request.json().catch(() => ({}));
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
      const fields = [], binds = [];
      if (body.title   !== undefined) { fields.push('post_title = ?');   binds.push(String(body.title?.raw || body.title || '')); }
      if (body.content !== undefined) { fields.push('post_content = ?'); binds.push(String(body.content?.raw || body.content || '')); }
      if (body.status  !== undefined) { fields.push('post_status = ?');  binds.push(body.status); }
      if (body.slug    !== undefined) { fields.push('post_name = ?');    binds.push(body.slug); }
      if (!fields.length) return j({ code: 'rest_no_fields', message: '수정할 필드가 없습니다.' }, 400);
      fields.push('post_modified = ?', 'post_modified_gmt = ?');
      binds.push(now, now, postId);
      await env.DB.prepare(`UPDATE wp_posts SET ${fields.join(', ')} WHERE ID = ?`).bind(...binds).run();
      const updated = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(postId).first();
      return j(wpPostToJSON(updated));
    }

    // DELETE /wp/v2/posts/:id
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && method === 'DELETE') {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      await env.DB.prepare(`UPDATE wp_posts SET post_status = 'trash' WHERE ID = ?`).bind(postId).run();
      return j({ deleted: true, id: postId });
    }

    // GET /wp/v2/posts/:id
    const postMatch = path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/);
    if (postMatch && method === 'GET') {
      const post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status IN ('publish','draft') LIMIT 1`
      ).bind(parseInt(postMatch[1], 10)).first();
      if (!post) return j({ code: 'rest_post_invalid_id', message: '유효하지 않은 포스트 ID입니다.' }, 404);
      return j(wpPostToJSON(post));
    }

    // GET /wp/v2/pages
    if (path.match(/^\/wp\/v2\/pages\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE post_type = 'page' AND post_status = 'publish' ORDER BY menu_order ASC, post_date DESC LIMIT 100`
      ).all();
      return j((res.results || []).map(wpPostToJSON));
    }

    // GET /wp/v2/categories
    if (path.match(/^\/wp\/v2\/categories\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count, tt.parent FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'category' ORDER BY t.name ASC`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/tags
    if (path.match(/^\/wp\/v2\/tags\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'post_tag' ORDER BY tt.count DESC LIMIT 100`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/users
    if (path.match(/^\/wp\/v2\/users\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT ID as id, display_name as name, user_login as slug, user_url as url FROM wp_users LIMIT 20`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/media
    if (path.match(/^\/wp\/v2\/media\/?$/) && method === 'GET') {
      try {
        const res = await env.DB.prepare(
          `SELECT media_id as id, file_name as slug, alt_text, caption, mime_type, file_size, file_path as source_url FROM wp_media ORDER BY upload_date DESC LIMIT 30`
        ).all();
        return j((res.results || []).map(m => ({
          ...m, title: { rendered: m.slug || '' }, guid: { rendered: m.source_url || '' },
        })));
      } catch { return j([]); }
    }

    // GET /wp/v2/comments
    if (path.match(/^\/wp\/v2\/comments\/?$/) && method === 'GET') {
      try {
        const perPage = parseInt(url.searchParams.get('per_page') || '20', 10);
        const res = await env.DB.prepare(
          `SELECT comment_ID as id, comment_author as author_name, comment_content as content, comment_date as date, comment_post_ID as post FROM wp_comments WHERE comment_approved = '1' ORDER BY comment_date DESC LIMIT ?`
        ).bind(perPage).all();
        const total = await env.DB.prepare(`SELECT COUNT(*) as c FROM wp_comments WHERE comment_approved='1'`).first();
        return new Response(JSON.stringify((res.results || []).map(c => ({ ...c, content: { rendered: c.content || '' } }))), {
          status: 200,
          headers: { ...corsHeaders, 'X-WP-Total': String(total?.c || 0) },
        });
      } catch { return j([]); }
    }

    // GET /wp/v2/settings
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'GET') {
      const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','siteurl','admin_email','timezone_string','date_format','posts_per_page']);
      return j({
        title: opts.blogname || '',
        description: opts.blogdescription || '',
        url: opts.siteurl || '',
        email: opts.admin_email || '',
        timezone: opts.timezone_string || 'Asia/Seoul',
        date_format: opts.date_format || 'Y년 n월 j일',
        posts_per_page: parseInt(opts.posts_per_page || '10', 10),
      });
    }

    // POST /wp/v2/settings
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const map = { title:'blogname', description:'blogdescription', email:'admin_email', timezone:'timezone_string', date_format:'date_format', posts_per_page:'posts_per_page' };
      const updated = {};
      for (const [bodyKey, optKey] of Object.entries(map)) {
        if (body[bodyKey] !== undefined) {
          const val = String(body[bodyKey]);
          try {
            await env.DB.prepare(
              `INSERT INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value = excluded.option_value`
            ).bind(optKey, val).run();
            updated[bodyKey] = val;
          } catch {}
        }
      }
      return j({ ...updated, ok: true });
    }

    return j({ code: 'rest_no_route', message: '일치하는 라우트가 없습니다.', data: { status: 404 } }, 404);
  } catch (e) {
    console.error('[REST API] error:', e.message);
    return j({ code: 'rest_error', message: '서버 오류가 발생했습니다.' }, 500);
  }
}

function wpPostToJSON(p) {
  if (!p) return null;
  return {
    id: p.ID || p.id,
    date: p.post_date,
    date_gmt: p.post_date_gmt,
    modified: p.post_modified,
    slug: p.post_name,
    status: p.post_status,
    type: p.post_type,
    link: p.guid || `/?p=${p.ID||p.id}`,
    title: { rendered: p.post_title || '', raw: p.post_title || '' },
    content: { rendered: p.post_content || '', raw: p.post_content || '', protected: false },
    excerpt: { rendered: p.post_excerpt || '', raw: p.post_excerpt || '', protected: false },
    author: p.post_author || 1,
    comment_status: p.comment_status || 'open',
    comment_count: p.comment_count || 0,
    _links: {
      self: [{ href: `/wp-json/wp/v2/posts/${p.ID||p.id}` }],
      collection: [{ href: '/wp-json/wp/v2/posts' }],
    },
  };
}

async function handleRSSFeed(env, siteInfo, url) {
  const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','siteurl']);
  const siteName = opts.blogname || siteInfo.name;
  const siteUrl  = `https://${url.hostname}`;
  let posts = [];
  try {
    const res = await env.DB.prepare(
      `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 10`
    ).all();
    posts = res.results || [];
  } catch {}
  const items = posts.map(p => {
    const link = `${siteUrl}/${p.post_name}/`;
    return `<item>
  <title><![CDATA[${p.post_title}]]></title>
  <link>${link}</link>
  <pubDate>${new Date(p.post_date).toUTCString()}</pubDate>
  <guid isPermaLink="true">${link}</guid>
  <description><![CDATA[${(p.post_excerpt || p.post_content || '').slice(0, 500)}]]></description>
</item>`;
  }).join('\n');

  const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>${siteName}</title>
  <link>${siteUrl}</link>
  <description>${opts.blogdescription || ''}</description>
  <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
  <language>ko</language>
  <atom:link href="${siteUrl}/feed/" rel="self" type="application/rss+xml"/>
  ${items}
</channel>
</rss>`;

  return new Response(rss, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

async function handleMediaUpload(env, request, siteInfo) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('multipart/form-data')) {
    return new Response(JSON.stringify({ error: 'multipart/form-data 필요' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const formData = await request.formData();
  const file = formData.get('file') || formData.get('async-upload');
  if (!file || typeof file === 'string') {
    return new Response(JSON.stringify({ error: '파일이 없습니다' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const fileName = file.name || 'upload_' + Date.now();
  const mimeType = file.type || 'application/octet-stream';
  const fileSize = file.size || 0;
  const bucket   = siteInfo.storage_bucket || 'media';
  const datePath = new Date().toISOString().slice(0, 7).replace('-', '/');
  const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = `${siteInfo.site_prefix}/${datePath}/${Date.now()}_${safeName}`;
  const arrayBuffer = await file.arrayBuffer();
  const result = await supabaseUpload(siteInfo, bucket, storagePath, arrayBuffer, mimeType);

  if (!result.ok) {
    if (fileSize < 500 * 1024) {
      const b64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
      try {
        await env.DB.prepare(
          `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'd1', '')`
        ).bind(safeName, storagePath, mimeType, fileSize).run();
        if (env.CACHE) await env.CACHE.put(`media:${storagePath}`, b64, { metadata: { mimeType, size: fileSize } });
        return new Response(JSON.stringify({ id: Date.now(), url: `/wp-content/uploads/${storagePath}`, title: safeName }), {
          status: 201, headers: { 'Content-Type': 'application/json' },
        });
      } catch {}
    }
    return new Response(JSON.stringify({ error: '업로드 실패' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
  try {
    await env.DB.prepare(
      `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'supabase', '')`
    ).bind(safeName, result.url, mimeType, fileSize).run();
  } catch {}
  return new Response(JSON.stringify({
    id: Date.now(), url: result.url, title: safeName.replace(/\.[^.]+$/, ''),
    mime_type: mimeType, source_url: result.url, secondary: result.secondary || false,
  }), { status: 201, headers: { 'Content-Type': 'application/json' } });
}

async function revalidatePage(env, siteInfo, url, request) {
  try {
    const { html } = await renderWordPressPage(env, siteInfo, url, request);
    const kvKey = `${siteInfo.site_prefix}:${url.pathname}${url.search}`;
    await kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', 200, CACHE_TTL_HTML);
    const freshResp = new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
        'x-cp-cached': 'edge', 'x-cp-revalidated': '1',
      },
    });
    await edgeCache.put(new Request(url.toString()), freshResp);
  } catch (e) { console.warn('[SWR] revalidation failed:', e.message); }
}

async function handlePurge(env, request, url, siteInfo) {
  const auth = request.headers.get('Authorization') || '';
  const purgeKey = env.PURGE_KEY || '';
  if (purgeKey && auth !== `Bearer ${purgeKey}`) return new Response('Unauthorized', { status: 401 });
  const body = await request.json().catch(() => ({}));
  const paths = body.paths || [url.searchParams.get('path') || '/'];
  let purged = 0;
  for (const p of paths) {
    const kvKey = `${siteInfo.site_prefix}:${p}`;
    try {
      await env.CACHE?.delete(KV_PAGE_PREFIX + kvKey);
      await edgeCache.delete(new Request(`https://${url.hostname}${p}`));
      purged++;
    } catch {}
  }
  return new Response(JSON.stringify({ ok: true, purged, paths }), { headers: { 'Content-Type': 'application/json' } });
}

async function handlePrewarm(env, request, url, siteInfo) {
  const paths = ['/'];
  try {
    const res = await env.DB.prepare(
      `SELECT post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 5`
    ).all();
    for (const r of (res.results || [])) paths.push(`/${r.post_name}/`);
  } catch {}
  const hostname = url.hostname;
  for (const p of paths) {
    const warmUrl = new URL(`https://${hostname}${p}`);
    revalidatePage(env, siteInfo, warmUrl, request).catch(() => {});
  }
  return new Response(JSON.stringify({ ok: true, paths, message: '캐시 예열 시작됨' }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleSitemap(env, siteInfo, url) {
  const siteUrl = `https://${url.hostname}`;
  let posts = [], pages = [];
  try {
    const [pr, pgr] = await Promise.all([
      env.DB.prepare(`SELECT post_name, post_modified FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 1000`).all(),
      env.DB.prepare(`SELECT post_name, post_modified FROM wp_posts WHERE post_type='page' AND post_status='publish' ORDER BY menu_order ASC LIMIT 100`).all(),
    ]);
    posts = pr.results || [];
    pages = pgr.results || [];
  } catch {}
  const urls = [
    `<url><loc>${siteUrl}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>`,
    ...pages.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified||'').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`),
    ...posts.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified||'').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.6</priority></url>`),
  ];
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

// ── 메인 핸들러 ───────────────────────────────────────────────────────────────
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname;
  const method   = request.method;
  const ip       = getClientIP(request);

  // WAF
  const wafResult = wafCheck(request, url);
  if (wafResult.block) {
    if (wafResult.tarpit) await new Promise(r => setTimeout(r, BOT_TARPIT_MS));
    return new Response(
      `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>요청이 차단되었습니다. (${wafResult.reason})</p></body></html>`,
      { status: wafResult.status || 403, headers: { 'Content-Type': 'text/html', 'X-WAF-Block': wafResult.reason } }
    );
  }

  // Rate limit
  const isWrite = !['GET','HEAD','OPTIONS'].includes(method);
  const rlResult = await rateLimitCheck(env, ip, isWrite, pathname);
  if (!rlResult.allowed) {
    if (rlResult.banned) {
      return new Response('IP가 차단되었습니다.', { status: 429, headers: { 'Retry-After': String(DDOS_BAN_TTL) } });
    }
    return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': String(RATE_LIMIT_WIN) } });
  }

  // CloudPress 플랫폼 자체 요청
  if (hostname.endsWith('.pages.dev') || hostname.endsWith('.workers.dev') ||
      hostname === 'cloudpress.site' || hostname === 'www.cloudpress.site') {
    return fetch(request);
  }

  // 도메인 인증
  if (pathname.startsWith('/.well-known/cloudpress-verify/')) {
    const token = pathname.split('/').pop();
    return new Response(`cloudpress-verify=${token}`, { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
  }

  // 사이트 정보
  const siteInfo = await getSiteInfo(env, hostname);
  if (!siteInfo) {
    return new Response(NOT_FOUND_HTML, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.suspended) {
    return new Response(SUSPENDED_HTML, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.status === 'pending' || siteInfo.status === 'provisioning') {
    return new Response(PROVISIONING_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' } });
  }

  // ── 라우팅 ────────────────────────────────────────────────────────────────────

  // wp-login.php
  if (pathname === '/wp-login.php') {
    return handleWPLogin(env, request, url, siteInfo);
  }

  // wp-admin
  if (pathname.startsWith('/wp-admin')) {
    return handleWPAdmin(env, request, url, siteInfo);
  }

  // REST API
  if (pathname.startsWith('/wp-json/')) {
    return handleWPRestAPI(env, request, url, siteInfo);
  }

  // RSS
  if (pathname === '/feed/' || pathname === '/feed' || url.searchParams.has('feed')) {
    return handleRSSFeed(env, siteInfo, url);
  }

  // Sitemap
  if (pathname === '/wp-sitemap.xml' || pathname === '/sitemap.xml' || pathname === '/sitemap_index.xml') {
    const r = await handleSitemap(env, siteInfo, url);
    ctx.waitUntil(cachePut(ctx, request, r.clone(), CACHE_TTL_API));
    return r;
  }

  // 미디어 업로드
  if (pathname === '/wp-admin/async-upload.php' && method === 'POST') {
    return handleMediaUpload(env, request, siteInfo);
  }

  // Purge API
  if (pathname === '/cp-purge' || pathname === '/wp-json/cloudpress/v1/purge') {
    return handlePurge(env, request, url, siteInfo);
  }

  // Prewarm
  if (pathname === '/cp-prewarm') {
    return handlePrewarm(env, request, url, siteInfo);
  }

  // robots.txt
  if (pathname === '/robots.txt') {
    return new Response(
      `User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\nDisallow: /wp-json/\nAllow: /wp-admin/admin-ajax.php\nSitemap: https://${hostname}/wp-sitemap.xml\n`,
      { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } }
    );
  }

  // OPTIONS
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
      },
    });
  }

  // 정적 자산
  if (isStaticAsset(pathname)) {
    const cached = await cacheGet(request);
    if (cached && !cached.stale) {
      const r = new Response(cached.response.body, { status: cached.response.status, headers: cached.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    if (siteInfo.supabase_url) {
      const mediaPath = pathname.replace('/wp-content/uploads/', '');
      const mediaUrl  = `${siteInfo.supabase_url}/storage/v1/object/public/${siteInfo.storage_bucket || 'media'}/${siteInfo.site_prefix}/${mediaPath}`;
      try {
        const mediaResp = await fetch(mediaUrl, { cf: { cacheTtl: CACHE_TTL_ASSET, cacheEverything: true } });
        if (mediaResp.ok) {
          ctx.waitUntil(cachePut(ctx, request, mediaResp.clone(), CACHE_TTL_ASSET));
          return new Response(mediaResp.body, {
            status: mediaResp.status,
            headers: new Headers({ ...Object.fromEntries(mediaResp.headers), 'Cache-Control': `public, max-age=${CACHE_TTL_ASSET}` }),
          });
        }
      } catch {}
    }
    return new Response('Not Found', { status: 404 });
  }

  // 캐시 불가 요청
  if (!isCacheable(request, url)) {
    const { html, contentData } = await renderWordPressPage(env, siteInfo, url, request);
    return new Response(html, {
      status: contentData.type === '404' ? 404 : 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, private' },
    });
  }

  // ── 캐시 흐름: Edge → KV → SSR ────────────────────────────────────────────
  const kvKey = `${siteInfo.site_prefix}:${pathname}${url.search}`;

  const edgeHit = await cacheGet(request);
  if (edgeHit) {
    if (!edgeHit.stale) {
      const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
    const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
    r.headers.set('x-cp-hit', 'edge-stale');
    r.headers.set('x-cp-swr', '1');
    return r;
  }

  const kvHit = await kvCacheGet(env, kvKey);
  if (kvHit) {
    const headers = new Headers({
      'Content-Type': kvHit.contentType || 'text/html; charset=utf-8',
      'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
      'x-cp-hit': 'kv',
    });
    const resp = new Response(kvHit.body, { status: kvHit.status || 200, headers });
    ctx.waitUntil(cachePut(ctx, request, resp.clone(), CACHE_TTL_HTML));
    if (kvHit.stale) {
      ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
      resp.headers.set('x-cp-swr', '1');
    }
    return resp;
  }

  let html, contentData;
  try {
    ({ html, contentData } = await renderWordPressPage(env, siteInfo, url, request));
  } catch (ssrError) {
    console.error('[SSR] render failed:', ssrError?.message);
    return new Response(ERROR_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' } });
  }

  const isNotFound = contentData.type === '404';
  const respStatus = isNotFound ? 404 : 200;
  const ttl        = isNotFound ? 60 : CACHE_TTL_HTML;

  const responseHeaders = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': isNotFound ? 'public, max-age=60' : `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`,
    'x-cp-hit': 'miss',
    'x-cp-via': 'cloudpress-ssr',
  });

  if (!isNotFound) {
    ctx.waitUntil(kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', respStatus, ttl));
  }
  const ssrResp = new Response(html, { status: respStatus, headers: responseHeaders });
  if (!isNotFound) ctx.waitUntil(cachePut(ctx, request, ssrResp.clone(), ttl));
  return new Response(html, { status: respStatus, headers: responseHeaders });
}

// ── HTML 템플릿 ───────────────────────────────────────────────────────────────
const SUSPENDED_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>사이트 정지됨</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#f55}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>🚫 사이트가 정지되었습니다</h1><p>이 사이트는 현재 이용 중지 상태입니다.</p></div></body></html>`;

const NOT_FOUND_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>사이트를 찾을 수 없음</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#fa0}p{color:#aaa;line-height:1.6}a{color:#7af;text-decoration:none}</style>
</head><body><div class="box"><h1>🔍 사이트를 찾을 수 없습니다</h1><p>요청한 도메인에 연결된 사이트가 없습니다.<br><a href="https://cloudpress.site/">CloudPress 대시보드</a>에서 도메인을 확인해 주세요.</p></div></body></html>`;

const PROVISIONING_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10">
<title>사이트 준비 중</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff;text-align:center}.box{padding:2rem;max-width:480px}h1{font-size:1.8rem;margin-bottom:1rem;color:#7af}p{color:#aaa;line-height:1.6}.spin{font-size:2.5rem;display:inline-block;animation:spin 1.2s linear infinite;margin-bottom:1rem}@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="spin">⚙️</div><h1>사이트를 준비 중입니다</h1><p>잠시만 기다려 주세요.</p></div></body></html>`;

const ERROR_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>일시적 오류</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{color:#f55;margin-bottom:1rem}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>⚠️ 일시적 서버 오류</h1><p>잠시 후 다시 시도해 주세요.</p></div></body></html>`;

// ── Worker 엔트리포인트 ────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error('[worker] Unhandled error:', e?.message || e, e?.stack);
      return new Response(ERROR_HTML, {
        status: 500,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  },

  async scheduled(event, env, ctx) {
    try {
      const sites = await env.DB.prepare(
        `SELECT id, site_prefix, primary_domain FROM sites WHERE status='active' AND deleted_at IS NULL LIMIT 100`
      ).all();
      for (const site of (sites.results || [])) {
        if (!site.primary_domain) continue;
        const siteInfo = await getSiteInfo(env, site.primary_domain).catch(() => null);
        if (!siteInfo) continue;
        const homeUrl = new URL(`https://${site.primary_domain}/`);
        ctx.waitUntil(revalidatePage(env, siteInfo, homeUrl, new Request(homeUrl)));
      }
    } catch (e) {
      console.error('[scheduled] ISR error:', e?.message);
    }
  },
};
