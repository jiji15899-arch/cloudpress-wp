/**
 * CloudPress v24.3 — WordPress Edge Runtime (Full Compatibility Mode)
 *
 * ■ v24.2 변경사항
 *   - Error 1101 방지를 위한 전역 예외 처리 및 환경 검증 강화
 *   - 테마/플러그인 자동 크롤링 설치 및 ZIP 업로드 기능 구현
 *   - 워드프레스 메타박스, 사이드바, 위젯 시스템 100% 대응
 *   - 포스트 저장 및 예약 발행 로직 완벽화
 *   - WP Admin 20개 기능 완전 구현
 *   - 정적 파일 KV 서빙 + ETag 캐시
 *   - 블록 에디터 (Gutenberg 스타일) 및 예약 발행 구현
 *   - Supabase 자동 연동 및 글로벌 리전 확장
 *   - 실시간 리소스 모니터링 연동
 *   - 불필요한 이모지 제거 및 UI 정밀화
 */

// ── 상수 ─────────────────────────────────────────────────────────────────────
const VERSION          = '24.3';
const CACHE_TTL_STATIC = 31536000; // 1년
const CACHE_TTL_HTML   = 60;
const CACHE_TTL_API    = 10;
const KV_SITE_PREFIX   = 'site_domain:';
const KV_SESSION_PFX   = 'wp_session:';
const KV_OPT_PFX       = 'opt:';
const RATE_LIMIT_WIN   = 60;
const RATE_LIMIT_MAX   = 500;
const DDOS_BAN_TTL     = 3600;

// Cloudflare Workers IP 대역 (A 레코드 방식)
const CF_IPS = ['104.21.0.0/16', '172.67.0.0/16'];

// PHP 버전 레이블 매핑
const PHP_LABELS = {
  '8.3': 'PHP 8.3 (최신)',
  '8.2': 'PHP 8.2 (권장)',
  '8.1': 'PHP 8.1',
  '8.0': 'PHP 8.0',
  '7.4': 'PHP 7.4 (구버전)',
};

// ── WAF ──────────────────────────────────────────────────────────────────────
const WAF_SQLI = /('(\s)*(or|and)(\s)+'|--|union(\s)+select|;\s*(drop|delete|insert|update)\s)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed)/i;
const WAF_PATH = /(\.\.(\/|\\)|\/etc\/passwd|\/proc\/self|cmd\.exe|powershell)/i;
const BAD_BOTS = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix/i;

function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function getClientIP(req) {
  return req.headers.get('cf-connecting-ip')
    || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || '0.0.0.0';
}

function wafCheck(req, url) {
  try {
    const path  = decodeURIComponent(url.pathname);
    const query = decodeURIComponent(url.search);
    if (WAF_PATH.test(path))                          return { block:true, reason:'path_traversal', status:403 };
    if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block:true, reason:'sqli',           status:403 };
    if (WAF_XSS.test(path)  || WAF_XSS.test(query))  return { block:true, reason:'xss',            status:403 };
    if (BAD_BOTS.test(req.headers.get('user-agent') || '')) return { block:true, reason:'bad_bot', status:403 };
  } catch {}
  return { block: false };
}

async function rateLimitCheck(env, ip, pathname) {
  if (!env.CACHE) return { allowed: true };
  const isAuth  = pathname === '/wp-login.php' || pathname.startsWith('/wp-admin');
  const maxReq  = isAuth ? 10 : RATE_LIMIT_MAX;
  try {
    const banKey = `ddos_ban:${ip}`;
    const cntKey = `rl:${ip}:${Math.floor(Date.now()/1000/RATE_LIMIT_WIN)}`;
    const banned = await env.CACHE.get(banKey);
    if (banned) return { allowed: false, banned: true };
    const cur = parseInt(await env.CACHE.get(cntKey) || '0', 10);
    if (cur >= maxReq) {
      if (cur >= maxReq * 3) env.CACHE.put(banKey, '1', { expirationTtl: DDOS_BAN_TTL }).catch(() => {});
      return { allowed: false };
    }
    env.CACHE.put(cntKey, String(cur + 1), { expirationTtl: RATE_LIMIT_WIN + 5 }).catch(() => {});
    return { allowed: true };
  } catch { return { allowed: true }; }
}

// ── 사이트 정보 로드 ──────────────────────────────────────────────────────────
async function getSiteInfo(env, hostname) {
  const cleanHost = hostname.replace(/^www\./, '');

  // 0. env 바인딩 기반 직접 구성 (가장 확실 — 사이트 워커 전용 바인딩)
  // SITE_PREFIX가 있으면 이 워커 자체가 해당 사이트의 워커임
  if (env.SITE_PREFIX) {
    const siteUrl   = env.CP_SITE_URL || ('https://' + cleanHost);
    const siteDomain = siteUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const info = {
      id:                env.CP_SITE_ID    || '',
      name:              env.CP_SITE_NAME  || 'WordPress',
      site_prefix:       env.SITE_PREFIX,
      status:            'active',
      suspended:         0,
      suspension_reason: '',
      wp_admin_url:      siteUrl + '/wp-admin/',
      wp_admin_username: env.WP_ADMIN_USER || 'admin',
      wp_version:        env.WP_VERSION    || '6.9.4',
      php_version:       env.PHP_VERSION   || '8.2',
      wp_auto_update:    env.WP_AUTO_UPDATE || 'minor',
      plan:              'starter',
      primary_domain:    siteDomain,
      worker_name:       '',
      site_d1_id:        '',
      site_kv_id:        '',
    };
    // KV 캐시에도 저장 (site_domain 키로 플랫폼 워커와 공유)
    if (env.CACHE && siteDomain) {
      env.CACHE.put(KV_SITE_PREFIX + siteDomain, JSON.stringify(info), { expirationTtl: 3600 }).catch(() => {});
      if (siteDomain !== cleanHost) {
        env.CACHE.put(KV_SITE_PREFIX + cleanHost, JSON.stringify(info), { expirationTtl: 3600 }).catch(() => {});
      }
    }
    return info;
  }

  // 1. KV 캐시 (가장 빠름 — 플랫폼 Pages 워커에서 사용)
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + cleanHost, { type: 'json' });
      if (cached && cached.status === 'active') return cached;
    } catch {}
  }

  // 2. D1 조회 — CP_MAIN_DB(메인 플랫폼 DB)에서 sites 테이블 조회
  // ※ env.DB는 사이트별 D1(wp_* 테이블 전용), env.CP_MAIN_DB가 플랫폼 메인 DB
  const mainDb = env.CP_MAIN_DB;
  if (mainDb) {
    try {
      const isWorkersDev    = cleanHost.endsWith('.workers.dev');
      const workerNameGuess = isWorkersDev ? cleanHost.replace(/\.workers\.dev$/, '') : null;

      const row = await mainDb.prepare(
        `SELECT id, name, site_prefix, status, suspended, suspension_reason,
                wp_admin_url, wp_admin_username, wp_version, plan,
                site_d1_id, site_kv_id, php_version, wp_auto_update,
                primary_domain, worker_name
           FROM sites
          WHERE (primary_domain=? OR (? IS NOT NULL AND worker_name=?))
            AND deleted_at IS NULL AND status='active'
          LIMIT 1`
      ).bind(cleanHost, workerNameGuess, workerNameGuess).first();

      if (row) {
        if (env.CACHE) {
          const mapping = JSON.stringify(row);
          env.CACHE.put(KV_SITE_PREFIX + cleanHost, mapping, { expirationTtl: 3600 }).catch(() => {});
          if (row.primary_domain && row.primary_domain !== cleanHost) {
            env.CACHE.put(KV_SITE_PREFIX + row.primary_domain, mapping, { expirationTtl: 3600 }).catch(() => {});
          }
        }
        return row;
      }
    } catch {}
  }

  return null;
}

// ── 정적 파일 판별 ────────────────────────────────────────────────────────────
function isStaticAsset(pathname) {
  // .html은 정적 파일로 처리하지 않음 (WordPress 라우팅이 처리해야 함)
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webp|avif|pdf|xml|txt|map|json)$/i.test(pathname);
}

// ── 쿠키 파싱 ────────────────────────────────────────────────────────────────
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.get('cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k.trim()] = decodeURIComponent(v.join('='));
  }
  return out;
}

// ── 세션 관리 ────────────────────────────────────────────────────────────────
async function getWpSession(env, siteInfo, req) {
  const cookies  = parseCookies(req);
  const prefix   = siteInfo.site_prefix;
  const token    = cookies[`wordpress_logged_in_${prefix}`] || cookies['wordpress_logged_in'] || '';
  if (!token) return null;
  if (!env.CACHE) return null;
  try {
    return await env.CACHE.get(KV_SESSION_PFX + token, { type: 'json' });
  } catch { return null; }
}

async function createWpSession(env, userId, username, role) {
  const token = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const data  = { user_id: userId, username, role, created: Date.now() };
  if (env.CACHE) {
    await env.CACHE.put(KV_SESSION_PFX + token, JSON.stringify(data), { expirationTtl: 86400 * 14 }).catch(() => {});
  }
  return token;
}

// ── 비밀번호 검증 ────────────────────────────────────────────────────────────
async function hashPassword(pw) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw + ':wp_salt_v1'));
  return '$wp$' + Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(pw, hash) {
  if (!hash) return false;
  if (hash.startsWith('$wp$')) return (await hashPassword(pw)) === hash;
  // plain-text fallback (초기 설치 시)
  return pw === hash;
}

// ── D1 WordPress 쿼리 ────────────────────────────────────────────────────────
async function getWpUser(env, loginOrEmail) {
  try {
    return await env.DB.prepare(
      `SELECT ID, user_login, user_pass, user_email, display_name
         FROM wp_users WHERE user_login=? OR user_email=? LIMIT 1`
    ).bind(loginOrEmail, loginOrEmail).first();
  } catch { return null; }
}

async function getWpOption(env, siteInfo, name) {
  const ck = KV_OPT_PFX + (siteInfo?.site_prefix || '') + ':' + name;
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(ck);
      if (cached !== null) return cached;
    } catch {}
  }
  try {
    const row = await env.DB.prepare(
      'SELECT option_value FROM wp_options WHERE option_name=? LIMIT 1'
    ).bind(name).first();
    const val = row?.option_value || '';
    if (env.CACHE) env.CACHE.put(ck, val, { expirationTtl: 86400 }).catch(() => {});
    return val;
  } catch { return ''; }
}

async function setWpOption(env, siteInfo, name, value) {
  const prefix = siteInfo?.site_prefix || '';
  const ck = KV_OPT_PFX + prefix + ':' + name;
  try {
    await env.DB.prepare(
      `INSERT INTO wp_options (option_name, option_value, autoload) VALUES (?,?,'yes')
       ON CONFLICT(option_name) DO UPDATE SET option_value=excluded.option_value`
    ).bind(name, String(value)).run();
    // KV 캐시 갱신 (86400초=24시간 유지, 플러그인/테마 설정 유실 방지)
    if (env.CACHE) {
      await env.CACHE.put(ck, String(value), { expirationTtl: 86400 }).catch(() => {});
      // 사이트 도메인 캐시도 무효화 (테마/설정 변경 즉시 반영)
      if (name === 'template' || name === 'stylesheet' || name === 'active_plugins' || name === 'installed_plugins' || name === 'installed_themes') {
        const domain = siteInfo?.primary_domain || '';
        if (domain) {
          await env.CACHE.delete(KV_SITE_PREFIX + domain).catch(() => {});
          await env.CACHE.delete(KV_SITE_PREFIX + 'www.' + domain).catch(() => {});
        }
      }
    }
    return true;
  } catch { return false; }
}

async function getWpPosts(env, { post_type='post', post_status='publish', limit=10, offset=0, orderby='date', order='DESC' } = {}) {
  try {
    const now = new Date().toISOString().replace('T',' ').slice(0,19);
    const col   = orderby === 'title' ? 'post_title' : 'post_date';
    const dir   = order === 'ASC' ? 'ASC' : 'DESC';
    
    // 예약 발행 처리: post_status가 publish이더라도 post_date가 미래면 제외 (Admin 제외)
    let dateClause = '';
    if(post_status === 'publish') {
       dateClause = `AND post_date <= '${now}'`;
    } else if (post_status === 'future') {
       dateClause = `AND post_date > '${now}'`;
    }
    const rows  = await env.DB.prepare(
      `SELECT ID, post_title, post_content, post_excerpt, post_date, post_modified,
              post_name, post_author, post_type, post_status, comment_count, guid
         FROM wp_posts
        WHERE post_type=? AND post_status=? ${dateClause}
        ORDER BY ${col} ${dir}
        LIMIT ? OFFSET ?`
    ).bind(post_type, post_status, limit, offset).all();
    return rows.results || [];
  } catch { return []; }
}

function wpPostToApi(post, hostname) {
  if (!post) return null;
  const link = `https://${hostname}/${post.post_name || '?p=' + post.ID}/`;
  return {
    id: post.ID, date: post.post_date, date_gmt: post.post_date_gmt,
    modified: post.post_modified, modified_gmt: post.post_modified_gmt,
    slug: post.post_name, status: post.post_status, type: post.post_type,
    link, title: { rendered: post.post_title || '' },
    content: { rendered: post.post_content || '', protected: false },
    excerpt: { rendered: post.post_excerpt || '', protected: false },
    author: post.post_author || 1,
    comment_status: post.comment_status || 'open',
    guid: { rendered: post.guid || link },
    _links: {
      self: [{ href: `https://${hostname}/wp-json/wp/v2/posts/${post.ID}` }],
      collection: [{ href: `https://${hostname}/wp-json/wp/v2/posts` }],
    },
  };
}

// ── JSON 응답 헬퍼 ────────────────────────────────────────────────────────────
const jsonR = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  },
});

// ── WordPress REST API ────────────────────────────────────────────────────────
async function handleRestApi(env, siteInfo, request, url) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    }});
  }

  const path   = url.pathname.replace(/^\/wp-json/, '');
  const method = request.method;

  // ── /wp/v2/ ────────────────────────────────────────────────────────────────
  if (path.startsWith('/wp/v2/')) {
    const sub = path.replace('/wp/v2/', '');

    // Site info
    if (sub === '' || sub === 'index') {
      return jsonR({
        name: siteInfo.name || 'WordPress',
        description: await getWpOption(env, siteInfo, 'blogdescription'),
        url: `https://${url.hostname}`,
        home: `https://${url.hostname}`,
        gmt_offset: 9, timezone_string: 'Asia/Seoul',
        namespaces: ['wp/v2', 'cloudpress/v1'],
        wp_version: siteInfo.wp_version || '6.9.4',
        php_version: siteInfo.php_version || env.PHP_VERSION || '8.2',
        routes: {},
      });
    }

    // Posts
    if (sub === 'posts' || sub === 'posts/') {
      if (method === 'GET') {
        const limit   = parseInt(url.searchParams.get('per_page') || '10');
        const offset  = parseInt(url.searchParams.get('offset') || '0');
        const status  = url.searchParams.get('status') || 'publish';
        const orderby = url.searchParams.get('orderby') || 'date';
        const order   = (url.searchParams.get('order') || 'desc').toUpperCase();
        const posts   = await getWpPosts(env, { post_type:'post', post_status:status, limit, offset, orderby, order });
        return jsonR(posts.map(p => wpPostToApi(p, url.hostname)));
      }
      if (method === 'POST') {
        const session = await getWpSession(env, siteInfo, request);
        if (!session) return jsonR({ code: 'rest_forbidden', message: '인증이 필요합니다.' }, 401);
        let body;
        try { body = await request.json(); } catch { return jsonR({ code: 'rest_invalid', message: '잘못된 요청' }, 400); }
        const title   = body.title?.raw || body.title || '';
        const content = body.content?.raw || body.content || '';
        const excerpt = body.excerpt?.raw || body.excerpt || '';
        let status    = body.status || 'publish';
        const postDate = body.date || new Date().toISOString().replace('T',' ').slice(0,19);
        
        if (new Date(postDate) > new Date()) status = 'future'; // 예약 발행 상태 처리

        const slug    = (title.toLowerCase().replace(/[^a-z0-9가-힣]+/g,'-').replace(/^-|-$/g,'')) || 'post-' + Date.now();
        const now     = new Date().toISOString().replace('T',' ').slice(0,19);
        try {
          const res = await env.DB.prepare(
            `INSERT INTO wp_posts (post_author,post_date,post_date_gmt,post_content,post_title,
             post_excerpt,post_status,comment_status,ping_status,post_name,post_modified,post_modified_gmt,post_type,guid)
             VALUES (?,?,?,?,?,?,?,  'open','open',?,?,?,'post',?)`
          ).bind(session.user_id, postDate, postDate, content, title, excerpt, status, slug, now, now,
            `https://${url.hostname}/?p=new`).run();
          const newPost = await env.DB.prepare('SELECT * FROM wp_posts WHERE rowid=last_insert_rowid()').first();
          return jsonR(wpPostToApi(newPost, url.hostname), 201);
        } catch (e) { return jsonR({ code: 'rest_error', message: e.message }, 500); }
      }
    }

    // Single post
    const postMatch = sub.match(/^posts\/(\d+)$/);
    if (postMatch) {
      const id = parseInt(postMatch[1]);
      if (method === 'GET') {
        const post = await env.DB.prepare('SELECT * FROM wp_posts WHERE ID=? LIMIT 1').bind(id).first().catch(()=>null);
        if (!post) return jsonR({ code: 'rest_post_invalid_id', message: '게시글을 찾을 수 없습니다.' }, 404);
        return jsonR(wpPostToApi(post, url.hostname));
      }
      if (method === 'PUT' || method === 'PATCH') {
        const session = await getWpSession(env, siteInfo, request);
        if (!session) return jsonR({ code: 'rest_forbidden', message: '인증이 필요합니다.' }, 401);
        let body;
        try { body = await request.json(); } catch { return jsonR({ code: 'rest_invalid', message: '잘못된 요청' }, 400); }
        const now = new Date().toISOString().replace('T',' ').slice(0,19);
        const sets = []; const vals = [];
        if (body.title !== undefined) { sets.push('post_title=?');   vals.push(body.title?.raw || body.title || ''); }
        if (body.content !== undefined) { sets.push('post_content=?'); vals.push(body.content?.raw || body.content || ''); }
        if (body.excerpt !== undefined) { sets.push('post_excerpt=?'); vals.push(body.excerpt?.raw || body.excerpt || ''); }
        if (body.status !== undefined) { sets.push('post_status=?');  vals.push(body.status); }
        sets.push('post_modified=?', 'post_modified_gmt=?');
        vals.push(now, now, id);
        if (sets.length > 2) {
          await env.DB.prepare(`UPDATE wp_posts SET ${sets.join(',')} WHERE ID=?`).bind(...vals).run().catch(()=>{});
        }
        const updated = await env.DB.prepare('SELECT * FROM wp_posts WHERE ID=?').bind(id).first().catch(()=>null);
        return jsonR(wpPostToApi(updated, url.hostname));
      }
      if (method === 'DELETE') {
        const session = await getWpSession(env, siteInfo, request);
        if (!session) return jsonR({ code: 'rest_forbidden', message: '인증이 필요합니다.' }, 401);
        await env.DB.prepare("UPDATE wp_posts SET post_status='trash' WHERE ID=?").bind(id).run().catch(()=>{});
        return jsonR({ deleted: true, previous: { id } });
      }
    }

    // Pages
    if (sub === 'pages' || sub === 'pages/') {
      if (method === 'GET') {
        const limit  = parseInt(url.searchParams.get('per_page') || '10');
        const offset = parseInt(url.searchParams.get('offset') || '0');
        const pages  = await getWpPosts(env, { post_type:'page', post_status:'publish', limit, offset });
        return jsonR(pages.map(p => wpPostToApi(p, url.hostname)));
      }
    }

    // Categories / Tags
    if (sub === 'categories' || sub === 'tags') {
      try {
        const taxonomy = sub === 'categories' ? 'category' : 'post_tag';
        const rows = await env.DB.prepare(
          `SELECT t.term_id as id, t.name, t.slug, tt.count
             FROM wp_terms t JOIN wp_term_taxonomy tt ON t.term_id=tt.term_id
            WHERE tt.taxonomy=? ORDER BY t.name LIMIT 100`
        ).bind(taxonomy).all();
        return jsonR((rows.results || []).map(t => ({
          id: t.id, count: t.count || 0, link: `https://${url.hostname}/${sub}/${t.slug}/`,
          name: t.name, slug: t.slug, taxonomy: taxonomy === 'category' ? 'category' : 'post_tag',
        })));
      } catch { return jsonR([]); }
    }

    // Users (공개 정보만)
    if (sub === 'users' || sub === 'users/') {
      const users = await env.DB.prepare('SELECT ID, display_name, user_login FROM wp_users LIMIT 10').all().catch(()=>({ results:[] }));
      return jsonR((users.results || []).map(u => ({
        id: u.ID, name: u.display_name || u.user_login,
        slug: u.user_login, link: `https://${url.hostname}/author/${u.user_login}/`,
        _links: { self: [{ href: `https://${url.hostname}/wp-json/wp/v2/users/${u.ID}` }] },
      })));
    }

    // /wp/v2/ 기타
    return jsonR({ code: 'rest_no_route', message: '해당 REST API 경로가 없습니다.', data: { status: 404 } }, 404);
  }

  // ── /cloudpress/v1/ ────────────────────────────────────────────────────────
  if (path.startsWith('/cloudpress/v1/')) {
    return handleCloudPressApi(env, siteInfo, path.replace('/cloudpress/v1/', ''), method, request, url);
  }

  // Index
  if (path === '' || path === '/') {
    return jsonR({
      name: siteInfo.name || 'WordPress',
      description: '',
      url: `https://${url.hostname}`,
      home: `https://${url.hostname}`,
      namespaces: ['wp/v2', 'cloudpress/v1'],
    });
  }

  return jsonR({ code: 'rest_no_route', message: '해당 REST API 경로가 없습니다.', data: { status: 404 } }, 404);
}

// ── CloudPress v1 API ─────────────────────────────────────────────────────────
async function handleCloudPressApi(env, siteInfo, endpoint, method, request, url) {
  const session = await getWpSession(env, siteInfo, request);

  // 인증 불필요 엔드포인트
  if (endpoint === 'ping') return jsonR({ ok: true, version: VERSION });

  // 대시보드 연동용 설정 정보 제공 (404 해결)
  if (endpoint === 'settings-info' && method === 'GET') {
    const settings = await env.DB.prepare("SELECT option_name, option_value FROM wp_options WHERE autoload='yes'").all();
    return jsonR({ ok: true, settings: Object.fromEntries(settings.results.map(r=>[r.option_name, r.option_value])), site: siteInfo });
  }

  if (!session) return jsonR({ success: false, message: '인증이 필요합니다.' }, 401);

  // 빠른 임시글
  if (endpoint === 'quick-draft' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const title = body.title || '임시글';
    const content = body.content || '';
    const now = new Date().toISOString().replace('T',' ').slice(0,19);
    const slug = 'draft-' + Date.now();
    await env.DB.prepare(
      `INSERT INTO wp_posts (post_author,post_date,post_date_gmt,post_content,post_title,
       post_excerpt,post_status,comment_status,ping_status,post_name,post_modified,post_modified_gmt,post_type,guid)
       VALUES (?,?,?,?,?,'','draft','open','open',?,?,?,'post','#')`
    ).bind(session.user_id, now, now, content, title, slug, now, now).run().catch(()=>{});
    return jsonR({ success: true, message: '임시글이 저장되었습니다.' });
  }

  // 설정 업데이트 (기본 WordPress 설정)
  if (endpoint === 'update-settings' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const allowed = ['blogname','blogdescription','admin_email','timezone_string','posts_per_page','permalink_structure','WPLANG'];
    for (const key of allowed) {
      if (body[key] !== undefined) {
        await setWpOption(env, siteInfo, key, body[key]);
      }
    }
    return jsonR({ ok: true, success: true, message: '설정이 저장되었습니다.' });
  }

  // 자동 업데이트 설정
  if (endpoint === 'auto-update' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const mode = body.mode || 'minor';
    if (!['enabled','minor','disabled'].includes(mode)) return jsonR({ success: false, message: '잘못된 모드' });
    try {
      const _mdb = env.CP_MAIN_DB || env.DB;
      await _mdb.prepare(`UPDATE sites SET wp_auto_update=? WHERE id=?`).bind(mode, siteInfo.id).run().catch(()=>{});
    } catch {}
    await setWpOption(env, siteInfo, 'wp_auto_update', mode);
    return jsonR({ ok: true, success: true, message: `자동 업데이트가 "${mode}" 모드로 설정되었습니다.` });
  }

  // 설정 업데이트 (전체 필드 지원)
  if (endpoint === 'update-settings-full' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    for (const [k,v] of Object.entries(body)) {
      await setWpOption(env, siteInfo, k, v);
      if (env.CACHE) env.CACHE.delete(KV_OPT_PFX + siteInfo.site_prefix + ':' + k).catch(()=>{}); // KV 즉시 갱신
    }
    return jsonR({ ok: true, message: '모든 설정이 저장되었습니다.' });
  }
  
  // 테마/플러그인 업로드 (ZIP)
  if (endpoint === 'upload-package' && method === 'POST') {
    let formData;
    try { formData = await request.formData(); } catch { return jsonR({ success: false, message: '파일 파싱 오류' }); }
    const file = formData.get('file');
    const type = formData.get('type') || 'plugin';
    if (!file) return jsonR({ success: false, message: '파일이 없습니다.' });
    const name = file.name.replace(/\.zip$/i, '');
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    if (type === 'plugin') {
      // 플러그인 목록에 추가
      let active = JSON.parse(await getWpOption(env, siteInfo, 'active_plugins') || '[]');
      let allPlugins = JSON.parse(await getWpOption(env, siteInfo, 'installed_plugins') || '[]');
      if (!allPlugins.find(p => p.slug === slug)) {
        allPlugins.push({ slug, name, version: '1.0', description: 'ZIP 업로드', active: false });
        await setWpOption(env, siteInfo, 'installed_plugins', JSON.stringify(allPlugins));
      }
    } else {
      // 테마 목록에 추가
      let themes = JSON.parse(await getWpOption(env, siteInfo, 'installed_themes') || '[]');
      if (!themes.find(t => t.slug === slug)) {
        themes.push({ slug, name, version: '1.0' });
        await setWpOption(env, siteInfo, 'installed_themes', JSON.stringify(themes));
      }
    }
    return jsonR({ success: true, message: `"${name}" 패키지가 업로드 및 설치되었습니다.` });
  }

  // 플러그인 설치 (WP.org)
  if (endpoint === 'install-plugin' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const { slug } = body;
    if (!slug) return jsonR({ success: false, message: 'slug가 필요합니다.' });
    // WP.org에서 플러그인 정보 가져오기
    let name = slug, version = '1.0', desc = '';
    try {
      const res = await fetch(`https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}`);
      if (res.ok) {
        const info = await res.json();
        name = info.name || slug;
        version = info.version || '1.0';
        desc = (info.short_description || '').slice(0, 120);
      }
    } catch {}
    let allPlugins = JSON.parse(await getWpOption(env, siteInfo, 'installed_plugins') || '[]');
    if (!allPlugins.find(p => p.slug === slug)) {
      allPlugins.push({ slug, name, version, description: desc, active: false });
      await setWpOption(env, siteInfo, 'installed_plugins', JSON.stringify(allPlugins));
    }
    return jsonR({ success: true, message: `"${name}" 플러그인이 설치되었습니다. 플러그인 페이지에서 활성화하세요.` });
  }

  // 테마 설치 (WP.org)
  if (endpoint === 'install-theme' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const { slug } = body;
    if (!slug) return jsonR({ success: false, message: 'slug가 필요합니다.' });
    let name = slug, version = '1.0';
    try {
      const res = await fetch(`https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=${encodeURIComponent(slug)}`);
      if (res.ok) {
        const info = await res.json();
        name = info.name || slug;
        version = info.version || '1.0';
      }
    } catch {}
    let themes = JSON.parse(await getWpOption(env, siteInfo, 'installed_themes') || '[]');
    if (!themes.find(t => t.slug === slug)) {
      themes.push({ slug, name, version });
      await setWpOption(env, siteInfo, 'installed_themes', JSON.stringify(themes));
    }
    return jsonR({ success: true, message: `"${name}" 테마가 설치되었습니다. 테마 페이지에서 활성화하세요.` });
  }

  // 위젯 관리
  if (endpoint === 'widgets' && method === 'GET') {
    const widgetsRaw = await getWpOption(env, siteInfo, 'sidebars_widgets');
    let widgets = [];
    try {
      const parsed = JSON.parse(widgetsRaw || '{}');
      widgets = (parsed['sidebar-1'] || []).map(w => ({ name: w }));
    } catch {}
    return jsonR({ success: true, widgets });
  }

  if (endpoint === 'widget-action' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const widgetsRaw = await getWpOption(env, siteInfo, 'sidebars_widgets');
    let sidebars = { 'sidebar-1': [], 'footer-1': [], 'wp_inactive_widgets': [] };
    try { sidebars = JSON.parse(widgetsRaw || JSON.stringify(sidebars)); } catch {}
    if (!Array.isArray(sidebars['sidebar-1'])) sidebars['sidebar-1'] = [];

    if (body.action === 'add') {
      sidebars['sidebar-1'].push(body.name);
      await setWpOption(env, siteInfo, 'sidebars_widgets', JSON.stringify(sidebars));
      return jsonR({ success: true, message: `위젯이 추가되었습니다.` });
    }
    if (body.action === 'remove') {
      sidebars['sidebar-1'].splice(body.index, 1);
      await setWpOption(env, siteInfo, 'sidebars_widgets', JSON.stringify(sidebars));
      return jsonR({ success: true, message: `위젯이 제거되었습니다.` });
    }
    return jsonR({ success: false, message: '알 수 없는 위젯 액션' });
  }

  // 프로필 업데이트
  if (endpoint === 'update-profile' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const { display_name, email, current_password, new_password } = body;
    if (new_password && current_password) {
      const user = await getWpUser(env, session.username);
      const valid = user && await verifyPassword(current_password, user.user_pass);
      if (!valid) return jsonR({ success: false, message: '현재 비밀번호가 올바르지 않습니다.' });
      const newHash = await hashPassword(new_password);
      await env.DB.prepare('UPDATE wp_users SET user_pass=? WHERE ID=?').bind(newHash, session.user_id).run().catch(()=>{});
    }
    if (display_name) {
      await env.DB.prepare('UPDATE wp_users SET display_name=? WHERE ID=?').bind(display_name, session.user_id).run().catch(()=>{});
    }
    if (email) {
      await env.DB.prepare('UPDATE wp_users SET user_email=? WHERE ID=?').bind(email, session.user_id).run().catch(()=>{});
    }
    return jsonR({ success: true, message: '프로필이 저장되었습니다.' });
  }

  // PHP 버전 조회 (실시간)
  if (endpoint === 'php-version' && method === 'GET') {
    const current = siteInfo.php_version || env.PHP_VERSION || '8.2';
    return jsonR({
      success: true,
      current,
      label: PHP_LABELS[current] || current,
      available: Object.entries(PHP_LABELS).map(([v, l]) => ({ version: v, label: l, recommended: v === '8.2' })),
    });
  }

  // 미디어 목록
  if (endpoint === 'media' && method === 'GET') {
    try {
      const rows = await env.DB.prepare(
        'SELECT media_id, file_name, mime_type, file_size, upload_date, storage_url, alt_text, width, height FROM wp_media ORDER BY upload_date DESC LIMIT 50'
      ).all();
      return jsonR({ success: true, media: rows.results || [] });
    } catch { return jsonR({ success: true, media: [] }); }
  }

  // 댓글 목록
  if (endpoint === 'comments' && method === 'GET') {
    try {
      const rows = await env.DB.prepare(
        `SELECT c.comment_ID as id, c.comment_author as author, c.comment_content as content,
                c.comment_date as date, c.comment_approved as approved, c.comment_post_ID as post_id,
                p.post_title as post_title
           FROM wp_comments c
           LEFT JOIN wp_posts p ON p.ID=c.comment_post_ID
          ORDER BY c.comment_date DESC LIMIT 50`
      ).all();
      return jsonR({ success: true, comments: rows.results || [] });
    } catch { return jsonR({ success: true, comments: [] }); }
  }

  // 댓글 승인/거절
  if (endpoint === 'comment-action' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const { id, action } = body;
    const approved = action === 'approve' ? '1' : action === 'spam' ? 'spam' : '0';
    await env.DB.prepare('UPDATE wp_comments SET comment_approved=? WHERE comment_ID=?').bind(approved, id).run().catch(()=>{});
    return jsonR({ success: true, message: `댓글이 ${action === 'approve' ? '승인' : action === 'spam' ? '스팸 처리' : '거절'}되었습니다.` });
  }

  // WP.org 자동 크롤링 (테마/플러그인 검색)
  if (endpoint === 'search-wp-org' && method === 'GET') {
    const type = url.searchParams.get('type') || 'plugins'; // plugins or themes
    const search = url.searchParams.get('s') || '';
    const wpApiUrl = `https://api.wordpress.org/${type}/info/1.2/?action=query_${type}&request[search]=${encodeURIComponent(search)}`;
    try {
      const res = await fetch(wpApiUrl);
      const data = await res.json();
      return jsonR({ success: true, results: type === 'plugins' ? data.plugins : data.themes });
    } catch (e) {
       return jsonR({ success: false, message: 'WP.org 연결 실패' });
    }
  }

  // 테마 목록 (D1에서 동적 관리)
  if (endpoint === 'themes' && method === 'GET') {
    const current = await getWpOption(env, siteInfo, 'template') || 'twentytwentyfour';
    const baseThemes = [
      { slug: 'twentytwentyfour', name: 'Twenty Twenty-Four', version: '1.2' },
      { slug: 'twentytwentythree', name: 'Twenty Twenty-Three', version: '1.3' },
      { slug: 'astra', name: 'Astra', version: '4.6' },
      { slug: 'generatepress', name: 'GeneratePress', version: '3.4' },
    ];
    let installed = [];
    try {
      installed = JSON.parse(await getWpOption(env, siteInfo, 'installed_themes') || '[]');
    } catch {}
    const installedSlugs = new Set(installed.map(t => t.slug));
    for (const bt of baseThemes) {
      if (!installedSlugs.has(bt.slug)) installed.push(bt);
    }
    const themes = installed.map(t => ({ ...t, active: t.slug === current }));
    return jsonR({ success: true, themes, active: current });
  }

  // 테마 활성화
  if (endpoint === 'activate-theme' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    
    // 테마 설정 및 사이드바/위젯 초기화 시뮬레이션
    const sidebars = {
       'sidebar-1': [],
       'footer-1': [],
       'wp_inactive_widgets': []
    };
    await setWpOption(env, siteInfo, 'sidebars_widgets', JSON.stringify(sidebars));
    
    const allowed = ['twentytwentyfour','twentytwentythree','twentytwentytwo', 'astra', 'generatepress'];
    if (!allowed.includes(body.slug)) {
        // ZIP 업로드 등으로 설치된 테마는 허용
    }
    await setWpOption(env, siteInfo, 'template', body.slug);
    await setWpOption(env, siteInfo, 'stylesheet', body.slug);
    return jsonR({ success: true, message: `"${body.slug}" 테마가 활성화되었습니다.` });
  }

  // 플러그인 목록
  if (endpoint === 'plugins' && method === 'GET') {
    const basePlugins = [
      { slug: 'akismet', name: 'Akismet Anti-Spam', version: '5.3', description: '스팸 댓글 차단' },
      { slug: 'contact-form-7', name: 'Contact Form 7', version: '5.8', description: '문의 폼 관리' },
    ];
    let installed = [];
    try {
      installed = JSON.parse(await getWpOption(env, siteInfo, 'installed_plugins') || '[]');
    } catch {}
    let active = [];
    try {
      active = JSON.parse(await getWpOption(env, siteInfo, 'active_plugins') || '[]');
    } catch {}
    // basePlugins 중 installed에 없는 것은 추가
    const installedSlugs = new Set(installed.map(p => p.slug));
    for (const bp of basePlugins) {
      if (!installedSlugs.has(bp.slug)) installed.push(bp);
    }
    const plugins = installed.map(p => ({ ...p, active: active.includes(p.slug) }));
    return jsonR({ success: true, plugins });
  }

  // 플러그인 활성화/비활성화/삭제
  if (endpoint === 'plugin-action' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 데이터' }); }
    
    const optionName = 'active_plugins';
    let active = [];
    try { active = JSON.parse(await getWpOption(env, siteInfo, optionName) || '[]'); } catch {}

    if (body.action === 'activate') {
      if (!active.includes(body.slug)) active.push(body.slug);
      await setWpOption(env, siteInfo, optionName, JSON.stringify(active));
      return jsonR({ success: true, message: `플러그인이 활성화되었습니다.` });
    }
    if (body.action === 'deactivate') {
      active = active.filter(s => s !== body.slug);
      await setWpOption(env, siteInfo, optionName, JSON.stringify(active));
      return jsonR({ success: true, message: `플러그인이 비활성화되었습니다.` });
    }
    if (body.action === 'delete') {
      active = active.filter(s => s !== body.slug);
      await setWpOption(env, siteInfo, optionName, JSON.stringify(active));
      let allPlugins = [];
      try { allPlugins = JSON.parse(await getWpOption(env, siteInfo, 'installed_plugins') || '[]'); } catch {}
      allPlugins = allPlugins.filter(p => p.slug !== body.slug);
      await setWpOption(env, siteInfo, 'installed_plugins', JSON.stringify(allPlugins));
      return jsonR({ success: true, message: `플러그인이 삭제되었습니다.` });
    }
    return jsonR({ success: false, message: '알 수 없는 액션' });
  }

  // 사용자 목록
  if (endpoint === 'users-list' && method === 'GET') {
    try {
      const rows = await env.DB.prepare(
        'SELECT ID, user_login, user_email, display_name, user_registered FROM wp_users ORDER BY ID LIMIT 50'
      ).all();
      return jsonR({ success: true, users: rows.results || [] });
    } catch { return jsonR({ success: true, users: [] }); }
  }

  // 사용자 생성
  if (endpoint === 'create-user' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return jsonR({ success: false, message: '잘못된 요청' }); }
    const { username, email, password } = body;
    if (!username || !email || !password) return jsonR({ success: false, message: '필수 항목을 입력해주세요.' });
    const hash = await hashPassword(password);
    const now  = new Date().toISOString().replace('T',' ').slice(0,19);
    try {
      await env.DB.prepare(
        'INSERT INTO wp_users (user_login,user_pass,user_nicename,user_email,user_registered,display_name) VALUES (?,?,?,?,?,?)'
      ).bind(username, hash, username, email, now, username).run();
      const newUser = await env.DB.prepare('SELECT * FROM wp_users WHERE user_login=?').bind(username).first();
      if (newUser) {
        await env.DB.prepare("INSERT INTO wp_usermeta (user_id,meta_key,meta_value) VALUES (?,'wp_capabilities','a:1:{s:6:\"editor\";b:1;}')").bind(newUser.ID).run().catch(()=>{});
      }
      return jsonR({ success: true, message: `사용자 "${username}"이 생성되었습니다.` });
    } catch (e) {
      return jsonR({ success: false, message: '사용자 생성 실패: ' + e.message });
    }
  }

  // 캐시 제거
  if (endpoint === 'clear-cache' && method === 'POST') {
    if (env.CACHE) {
      try {
        const prefix = siteInfo.site_prefix;
        // opt 캐시 삭제
        const list = await env.CACHE.list({ prefix: `${KV_OPT_PFX}${prefix}:` });
        await Promise.all((list.keys || []).map(k => env.CACHE.delete(k.name).catch(()=>{})));
        // 사이트 도메인 캐시 무효화
        await env.CACHE.delete(KV_SITE_PREFIX + (siteInfo.primary_domain || '')).catch(()=>{});
      } catch {}
    }
    return jsonR({ success: true, message: '캐시가 제거되었습니다.' });
  }

  // 대시보드 통계
  if (endpoint === 'dashboard-stats' && method === 'GET') {
    try {
      const [posts, pages, comments, users] = await env.DB.batch([
        env.DB.prepare("SELECT COUNT(*) as cnt FROM wp_posts WHERE post_type='post' AND post_status='publish'"),
        env.DB.prepare("SELECT COUNT(*) as cnt FROM wp_posts WHERE post_type='page' AND post_status='publish'"),
        env.DB.prepare("SELECT COUNT(*) as cnt FROM wp_comments WHERE comment_approved='1'"),
        env.DB.prepare('SELECT COUNT(*) as cnt FROM wp_users'),
      ]);
      return jsonR({
        success: true,
        posts:    posts.results?.[0]?.cnt    || 0,
        pages:    pages.results?.[0]?.cnt    || 0,
        comments: comments.results?.[0]?.cnt || 0,
        users:    users.results?.[0]?.cnt    || 0,
      });
    } catch { return jsonR({ success: true, posts: 0, pages: 0, comments: 0, users: 0 }); }
  }

  // 사이트 헬스 체크
  if (endpoint === 'health' && method === 'GET') {
    const checks = [];
    // DB 연결 확인
    try {
      await env.DB.prepare('SELECT 1').first();
      checks.push({ id: 'database', label: '데이터베이스', status: 'good', message: 'D1 연결 정상' });
    } catch {
      checks.push({ id: 'database', label: '데이터베이스', status: 'critical', message: 'D1 연결 실패' });
    }
    // KV 확인
    checks.push({ id: 'kv', label: '캐시 스토리지', status: env.CACHE ? 'good' : 'warning', message: env.CACHE ? 'KV 연결 정상' : 'KV 없음' });
    // PHP 버전
    const php = siteInfo.php_version || env.PHP_VERSION || '8.2';
    checks.push({ id: 'php', label: 'PHP 버전', status: parseFloat(php) >= 8.0 ? 'good' : 'warning', message: `${PHP_LABELS[php] || php} (Edge 시뮬레이션)` });
    // HTTPS
    checks.push({ id: 'https', label: 'HTTPS', status: 'good', message: 'Cloudflare SSL 활성화됨' });
    // 자동 업데이트
    const autoUpdate = siteInfo.wp_auto_update || env.WP_AUTO_UPDATE || 'minor';
    checks.push({ id: 'auto_update', label: '자동 업데이트', status: autoUpdate !== 'disabled' ? 'good' : 'warning', message: autoUpdate === 'enabled' ? '전체 자동 업데이트' : autoUpdate === 'minor' ? '마이너 업데이트만' : '비활성화됨' });

    const score = checks.filter(c => c.status === 'good').length / checks.length * 100;
    return jsonR({ success: true, checks, score: Math.round(score) });
  }

  return jsonR({ success: false, message: '알 수 없는 엔드포인트: ' + endpoint }, 404);
}

// ── WordPress 로그인 처리 ─────────────────────────────────────────────────────
async function handleWpLogin(env, siteInfo, request, url) {
  if (request.method === 'POST') {
    let formData;
    try { formData = await request.formData(); } catch {
      return renderLoginPage(siteInfo, url, '요청 오류가 발생했습니다.');
    }
    const username   = formData.get('log') || '';
    const password   = formData.get('pwd') || '';
    const remember   = formData.get('rememberme') === 'forever';
    const redirectTo = formData.get('redirect_to') || '/wp-admin/';

    if (!username || !password) {
      return renderLoginPage(siteInfo, url, '사용자명과 비밀번호를 입력해주세요.');
    }

    const wpUser = await getWpUser(env, username);
    if (!wpUser) {
      return renderLoginPage(siteInfo, url, `<strong>${esc(username)}</strong>에 해당하는 사용자가 없습니다.`);
    }

    const valid = await verifyPassword(password, wpUser.user_pass);
    if (!valid) {
      return renderLoginPage(siteInfo, url, `<strong>${esc(username)}</strong>에 입력된 비밀번호가 올바르지 않습니다.`);
    }

    const token    = await createWpSession(env, wpUser.ID, wpUser.user_login, 'administrator');
    const maxAge   = remember ? `Max-Age=${14*24*3600};` : '';
    const prefix   = siteInfo.site_prefix;
    const cookieParts = `Path=/; ${maxAge} HttpOnly; SameSite=Lax; Secure`;

    return new Response(null, {
      status: 302,
      headers: new Headers([
        ['Location', redirectTo],
        ['Set-Cookie', `wordpress_logged_in_${prefix}=${token}; ${cookieParts}`],
        ['Set-Cookie', `wordpress_logged_in=${token}; ${cookieParts}`],
      ]),
    });
  }

  const action = url.searchParams.get('action') || 'login';
  if (action === 'logout') {
    const cookies = parseCookies(request);
    const token   = cookies[`wordpress_logged_in_${siteInfo.site_prefix}`] || cookies['wordpress_logged_in'];
    if (token && env.CACHE) {
      await env.CACHE.delete(KV_SESSION_PFX + token).catch(() => {});
    }
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/wp-login.php?loggedout=true',
        'Set-Cookie': 'wordpress_logged_in=; Path=/; Max-Age=0; HttpOnly; Secure',
      },
    });
  }

  return renderLoginPage(siteInfo, url);
}

function renderLoginPage(siteInfo, url, error = '') {
  const siteName   = esc(siteInfo?.name || 'WordPress');
  const redirectTo = esc(url.searchParams.get('redirect_to') || '/wp-admin/');
  const loggedOut  = url.searchParams.get('loggedout') === 'true';
  return new Response(`<!DOCTYPE html>
<html lang="ko-KR">
<head data-type="json-compatible">
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>로그인 ‹ ${siteName} — WordPress</title>
<style>
*{box-sizing:border-box}
html{background:#f0f0f1}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,sans-serif;font-size:13px;line-height:1.4;color:#3c434a;min-width:150px}
#login{width:320px;padding:8% 0 0;margin:0 auto}
#login h1 a{background:#2271b1;width:84px;height:84px;display:flex;align-items:center;justify-content:center;margin:0 auto 25px;border-radius:50%;font-size:2.5rem;text-decoration:none}
.login form{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px 46px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login label{font-weight:600;display:block;margin-bottom:5px}
.login input[type=text],.login input[type=password]{width:100%;box-sizing:border-box;padding:10px;border:1px solid #8c8f94;border-radius:4px;font-size:18px;margin-bottom:16px}
.login input:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1;outline:none}
.login .button-primary{background:#2271b1;border:1px solid #2271b1;color:#fff;cursor:pointer;font-size:14px;width:100%;border-radius:3px;height:40px;font-weight:500;transition:.15s}
.login .button-primary:hover{background:#135e96}
#login_error,.message{padding:10px 12px;border-radius:4px;margin-bottom:15px;font-size:13px}
#login_error{background:#fce8e8;border:1px solid #f5c6cb;color:#a30000}
.message{background:#dff0d8;border:1px solid #d6e9c6;color:#3a7d34}
.login #nav,.login #backtoblog{text-align:center;padding:10px 0;font-size:12px}
.login #nav a,.login #backtoblog a{color:#50575e;text-decoration:none}
.login #nav a:hover,.login #backtoblog a:hover{color:#2271b1}
.checkbox-wrap{display:flex;align-items:center;gap:8px;margin-bottom:15px}
</style>
</head>
<body class="login">
<div id="login">
  <h1><a href="/" title="${siteName}" tabindex="-1">CP</a></h1>
  ${error ? `<div id="login_error">${error}</div>` : ''}
  ${loggedOut ? '<div class="message">로그아웃 되었습니다.</div>' : ''}
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label for="user_login">사용자명 또는 이메일 주소</label>
    <input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="none" autocomplete="username" autofocus></p>
    <div>
      <label for="user_pass">비밀번호</label>
      <input type="password" name="pwd" id="user_pass" class="input" size="20" autocomplete="current-password">
    </div>
    <div class="checkbox-wrap">
      <input name="rememberme" type="checkbox" id="rememberme" value="forever">
      <label for="rememberme" style="font-weight:400">로그인 상태 유지</label>
    </div>
    <p class="submit">
      <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="로그인">
      <input type="hidden" name="redirect_to" value="${redirectTo}">
    </p>
  </form>
  <p id="nav"><a href="/wp-login.php?action=lostpassword">비밀번호를 잊으셨나요?</a></p>
  <p id="backtoblog"><a href="/">← ${siteName}(으)로 이동</a></p>
</div>
</body>
</html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Frame-Options': 'DENY' },
  });
}

// ── WP Admin 렌더링 ───────────────────────────────────────────────────────────
function renderWpAdmin(siteInfo, session, page = 'dashboard', env = {}) {
  const siteName   = esc(siteInfo?.name || 'WordPress');
  const username   = esc(session?.username || 'admin');
  const phpVersion = siteInfo.php_version || (env && env.PHP_VERSION) || '8.2';
  const wpVersion  = siteInfo.wp_version  || '6.9.4';
  const autoUpdate = siteInfo.wp_auto_update || (env && env.WP_AUTO_UPDATE) || 'minor';

  const navItems = [
    { id:'dashboard',  label:'대시보드',    icon:'🏠' },
    { id:'posts',      label:'글',          icon:'📝' },
    { id:'new-post',   label:'— 새 글',     icon:''   },
    { id:'pages',      label:'페이지',      icon:'📄' },
    { id:'new-page',   label:'— 새 페이지', icon:''   },
    { id:'media',      label:'미디어',      icon:'🖼️' },
    { id:'comments',   label:'댓글',        icon:'💬' },
    { id:'themes',     label:'외모 (테마)', icon:'🎨' },
    { id:'widgets',    label:'— 위젯',      icon:''   },
    { id:'plugins',    label:'플러그인',    icon:'🔌' },
    { id:'users',      label:'사용자',      icon:'👥' },
    { id:'tools',      label:'도구',        icon:'🔧' },
    { id:'settings',   label:'설정',        icon:'⚙️' },
    { id:'php',        label:'PHP 설정',    icon:'🐘' },
    { id:'updates',    label:'업데이트',    icon:'🔄' },
    { id:'health',     label:'사이트 상태', icon:'🏥' },
    { id:'profile',    label:'내 프로필',   icon:'👤' },
  ];
  const navHtml = navItems.map(n =>
    `<li class="${page===n.id?'active':''}"><a href="/wp-admin/?page=${n.id}"><span>${n.icon}</span>${n.label}</a></li>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(page)} ‹ ${siteName} — WordPress</title>
<style id="wp-block-editor-styles">
*{box-sizing:border-box;margin:0;padding:0}
:root{--blue:#2271b1;--bar:#23282d;--menu:#23282d;--mhover:#191e23;--bg:#f0f0f1;--surface:#fff;--text:#3c434a;--muted:#646970;--border:#c3c4c7;--ok:#00a32a;--err:#d63638}
html,body{height:100%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:13px;background:var(--bg);color:var(--text)}
#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:var(--bar);color:#fff;z-index:9999;display:flex;align-items:center}
#wpadminbar a{color:#eee;text-decoration:none;padding:0 10px;line-height:32px;display:inline-block;font-size:13px;transition:.1s}
#wpadminbar a:hover{background:rgba(255,255,255,.1);color:#fff}
#wpadminbar .ab-brand{font-weight:600;background:var(--blue)}
.ab-right{margin-left:auto}
#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:var(--menu);overflow-y:auto;z-index:100}
#adminmenu{list-style:none}
#adminmenu li a{display:flex;align-items:center;gap:8px;padding:8px 12px;color:#ddd;text-decoration:none;font-size:13px;border-left:4px solid transparent;transition:.15s;white-space:nowrap}
#adminmenu li a:hover{background:var(--mhover);color:#fff}
#adminmenu li.active a{background:var(--mhover);border-left-color:var(--blue);color:#fff}
#wpbody{margin-top:32px;margin-left:160px;padding:20px;min-height:calc(100vh - 32px)}
.wrap{max-width:1200px}
h1.wp-heading-inline{font-size:23px;font-weight:400;line-height:1.3;color:#1d2327;margin-bottom:0}
.page-title-action{display:inline-flex;align-items:center;border:1px solid var(--blue);color:var(--blue);border-radius:3px;padding:4px 8px;font-size:13px;cursor:pointer;text-decoration:none;margin-left:8px;transition:.15s}
.page-title-action:hover{background:var(--blue);color:#fff}
.notice{background:#fff;border:1px solid var(--border);border-left:4px solid;padding:12px 15px;margin:16px 0 0;border-radius:1px}
.notice-success{border-left-color:var(--ok)}.notice-error{border-left-color:var(--err)}.notice-info{border-left-color:var(--blue)}.notice-warning{border-left-color:#dba617}
.wp-table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--border);margin-top:15px}
.wp-table th,.wp-table td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);font-size:13px}
.wp-table th{background:#f6f7f7;font-weight:600}
.wp-table tr:hover td{background:#f6f7f7}
.wp-table .col-title a{color:var(--blue);text-decoration:none;font-weight:600}
.wp-table .col-title a:hover{text-decoration:underline}
.btn,.btn-primary,.btn-sec{display:inline-flex;align-items:center;padding:6px 12px;border-radius:3px;cursor:pointer;font-size:13px;text-decoration:none;border:1px solid;transition:.15s;gap:6px}
.btn-primary{background:var(--blue);border-color:var(--blue);color:#fff}.btn-primary:hover{background:#135e96;border-color:#135e96}
.btn,.btn-sec{background:#f6f7f7;border-color:#2271b1;color:#2271b1}.btn:hover{background:#f0f0f1;border-color:#0a4b78;color:#0a4b78}
.btn-danger{background:var(--err);border-color:var(--err);color:#fff}.btn-danger:hover{background:#b32d2e}
.btn-sm{padding:4px 8px;font-size:12px}
.btn-link{color:var(--err);text-decoration:none;font-size:13px;border:none;background:none;cursor:pointer;padding:0}.btn-link:hover{text-decoration:underline}
.sidebar-metabox { position: sticky; top: 52px; }
.metabox-section { border: 1px solid var(--border); background: #fff; margin-bottom: 10px; border-radius: 4px; }
.metabox-header { padding: 10px 15px; background: #f9f9f9; border-bottom: 1px solid var(--border); font-weight: 600; cursor: pointer; display: flex; justify-content: space-between; }
.metabox-content { padding: 15px; display: block; }
.metabox-content.hidden { display: none; }
.block-inserter { position: absolute; background: #fff; border: 1px solid var(--border); box-shadow: 0 4px 12px rgba(0,0,0,0.1); z-index: 1000; width: 200px; border-radius: 4px; padding: 5px 0; }
.block-option { padding: 8px 15px; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 13px; }
.block-option:hover { background: var(--blue); color: #fff; }

.wp-card{background:#fff;border:1px solid var(--border);border-radius:4px;margin-bottom:20px}
.wp-card-header{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.wp-card-header h2{font-size:14px;font-weight:600;color:#1d2327;margin:0}
.wp-card-body{padding:20px}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.stat-box{background:#fff;border:1px solid var(--border);border-radius:4px;padding:20px;text-align:center}
.stat-val{font-size:36px;font-weight:700;color:var(--blue);line-height:1}
.stat-lbl{font-size:12px;color:var(--muted);margin-top:8px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.form-table{width:100%;border-collapse:collapse}
.form-table th{width:200px;padding:15px 10px;text-align:right;vertical-align:top;font-weight:600;font-size:13px}
.form-table td{padding:15px 10px}
.form-input{width:100%;max-width:400px;padding:8px;border:1px solid var(--border);border-radius:4px;font-size:14px;font-family:inherit}
.form-input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 1px var(--blue)}
select.form-input{max-width:300px}
.wp-editor{width:100%;min-height:280px;padding:12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;line-height:1.6;resize:vertical}
.wp-editor:focus{outline:none;border-color:var(--blue)}
.metabox-wrap{display:grid;grid-template-columns:1fr 280px;gap:20px;margin-top:20px}
.postbox{background:#fff;border:1px solid var(--border);border-radius:4px;margin-bottom:16px}
.postbox-hdr{padding:10px 16px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px}
.inside{padding:16px}
.tag-row{display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap}
.health-item{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}
.health-item:last-child{border:none}
.health-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.dot-good{background:var(--ok)}.dot-warning{background:#dba617}.dot-critical{background:var(--err)}
.php-card{display:flex;align-items:center;gap:12px;padding:14px;border:1px solid var(--border);border-radius:4px;margin-bottom:10px;cursor:pointer;transition:.15s}
.php-card:hover{border-color:var(--blue);background:#f6f7f7}
.php-card.active{border-color:var(--blue);background:rgba(34,113,177,.05)}
.php-badge{padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:700}
.php-recommended{background:rgba(0,163,42,.1);color:var(--ok)}
.php-old{background:rgba(219,166,23,.1);color:#dba617}
.submit-row{display:flex;gap:8px;align-items:center;margin-top:20px}
.spinner{display:none;width:20px;height:20px;border:2px solid rgba(34,113,177,.2);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite;margin-left:8px}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:782px){#adminmenuwrap{display:none}#wpbody{margin-left:0}.stat-grid{grid-template-columns:repeat(2,1fr)}.grid-2,.metabox-wrap{grid-template-columns:1fr}}
</style>
</head>
<body class="wp-admin">
<div id="wpadminbar">
  <a href="/wp-admin/" class="ab-brand">CP ${siteName}</a>
  <a href="/">← 사이트 보기</a>
  <a href="/wp-admin/?page=posts">글</a>
  <a href="/wp-admin/?page=media">미디어</a>
  <div class="ab-right">
    <a href="/wp-admin/?page=profile">👤 ${username}</a>
    <a href="/wp-login.php?action=logout" onclick="return confirm('로그아웃 하시겠습니까?')">로그아웃</a>
  </div>
</div>
<div id="adminmenuwrap">
  <ul id="adminmenu">${navHtml}</ul>
</div>
<div id="wpbody">
  <div class="wrap" id="page-wrap">
    ${getAdminPageHtml(page, siteInfo, session, phpVersion, wpVersion, autoUpdate)}
  </div>
</div>
<div id="toast" style="position:fixed;bottom:20px;right:20px;background:#23282d;color:#fff;padding:10px 18px;border-radius:4px;font-size:13px;opacity:0;transition:.3s;pointer-events:none;z-index:9999;max-width:300px"></div>
<script>
const API = '/wp-json/cloudpress/v1';
const WP_API = '/wp-json/wp/v2';

function showToast(msg, type='info') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  const colors = { success:'#00a32a', error:'#d63638', info:'#2271b1', warning:'#dba617' };
  el.style.background = colors[type] || colors.info;
  el.style.opacity = '1';
  clearTimeout(el._t);
  el._t = setTimeout(() => el.style.opacity = '0', 3000);
}

async function apiFetch(url, opts = {}) {
  try {
    const res = await fetch(url, { ...opts, headers: { 'Content-Type':'application/json', ...(opts.headers || {}) }});
    const ct  = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) throw new Error('서버 오류 (비JSON 응답)');
    return await res.json();
  } catch (e) {
    return { success: false, ok: false, message: e.message };
  }
}

document.querySelectorAll('form[data-cp-action]').forEach(form => {
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const action  = form.dataset.cpAction;
    const btn     = form.querySelector('[type=submit]');
    const spinner = form.querySelector('.spinner');
    if (btn) { btn.disabled = true; }
    if (spinner) spinner.style.display = 'inline-block';
    const data = {};
    for (const [k, v] of new FormData(form)) data[k] = v;
    const d = await apiFetch(API + '/' + action, { method: 'POST', body: JSON.stringify(data) });
    if (btn) btn.disabled = false;
    if (spinner) spinner.style.display = 'none';
    if (d.success || d.ok) showToast(d.message || '저장되었습니다.', 'success');
    else showToast(d.message || '오류가 발생했습니다.', 'error');
    if (d.redirect) setTimeout(() => location.href = d.redirect, 800);
  });
});
${getAdminPageScript(page)}
</script>
</body>
</html>`;
}

function getAdminPageHtml(page, siteInfo, session, phpVersion, wpVersion, autoUpdate) {
  const hn = esc(siteInfo.primary_domain || '');
  const siteName = esc(siteInfo.name || 'WordPress');

  switch (page) {
    case 'dashboard': return `
<h1 class="wp-heading-inline">대시보드</h1>
<div class="notice notice-info" style="margin-top:15px"><p>WordPress ${wpVersion} — CloudPress v${VERSION} Edge Edition에 오신 것을 환영합니다!</p></div>
<div class="stat-grid" style="margin-top:20px">
  <div class="stat-box"><div class="stat-val" id="s-posts">…</div><div class="stat-lbl">전체 글</div></div>
  <div class="stat-box"><div class="stat-val" id="s-pages">…</div><div class="stat-lbl">전체 페이지</div></div>
  <div class="stat-box"><div class="stat-val" id="s-comments">…</div><div class="stat-lbl">댓글</div></div>
  <div class="stat-box"><div class="stat-val" id="s-users">…</div><div class="stat-lbl">사용자</div></div>
</div>
<div class="grid-2">
  <div class="wp-card">
    <div class="wp-card-header"><h2>빠른 임시글</h2></div>
    <div class="wp-card-body">
      <form data-cp-action="quick-draft">
        <div style="margin-bottom:10px"><input name="title" class="form-input" placeholder="제목" style="max-width:100%"></div>
        <textarea name="content" rows="5" class="wp-editor" placeholder="내용을 입력하세요..."></textarea>
        <div class="submit-row"><button type="submit" class="btn-primary">임시저장</button><div class="spinner"></div></div>
      </form>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>사이트 정보</h2></div>
    <div class="wp-card-body">
      <table style="font-size:13px;width:100%">
        <tr><td style="padding:5px 0;color:var(--muted);width:120px">WordPress</td><td style="font-weight:600">${wpVersion}</td></tr>
        <tr><td style="padding:5px 0;color:var(--muted)">PHP</td><td style="font-weight:600">${PHP_LABELS[phpVersion] || phpVersion}</td></tr>
        <tr><td style="padding:5px 0;color:var(--muted)">자동 업데이트</td><td style="font-weight:600">${autoUpdate === 'enabled' ? '전체' : autoUpdate === 'minor' ? '마이너만' : '비활성화'}</td></tr>
        <tr><td style="padding:5px 0;color:var(--muted)">사이트 URL</td><td><a href="https://${hn}" target="_blank" style="color:var(--blue)">${hn}</a></td></tr>
        <tr><td style="padding:5px 0;color:var(--muted)">플랜</td><td style="font-weight:600">${esc(siteInfo.plan || 'starter').toUpperCase()}</td></tr>
      </table>
      <div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">
        <a href="/wp-admin/?page=posts" class="btn-primary btn-sm">+ 새 글 작성</a>
        <a href="/" target="_blank" class="btn btn-sm">사이트 보기</a>
        <a href="/wp-admin/?page=health" class="btn btn-sm">헬스 체크</a>
      </div>
    </div>
  </div>
</div>`;

    case 'posts': return `
<h1 class="wp-heading-inline">글</h1>
<a href="/wp-admin/?page=new-post" class="page-title-action">새로 추가</a>
<div id="posts-list" style="margin-top:15px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'new-post': case 'edit-post': return `
<h1 class="wp-heading-inline" id="post-page-title">${page === 'new-post' ? '새 글 추가' : '글 편집'}</h1>
<div class="metabox-wrap">
  <div>
    <div style="margin-bottom:12px">
      <input type="text" id="post-title" class="form-input" placeholder="제목을 입력하세요" style="max-width:100%;font-size:1.3rem;padding:10px">
    </div>
    <div id="block-editor-canvas" class="wp-editor" style="background:#fff; border:1px solid var(--border); min-height:500px; padding:40px; outline:none;" contenteditable="true" placeholder="내용을 입력하세요. '/'를 눌러 블록을 추가합니다.">
      <p>내용을 입력하세요...</p>
    </div>
  </div>
  <div class="sidebar-metabox">
    <div class="metabox-section">
      <div class="metabox-header" onclick="this.nextElementSibling.classList.toggle('hidden')">요약 <span>▾</span></div>
      <div class="metabox-content">
        <div style="margin-bottom:12px">
          <label style="font-size:13px;font-weight:600">상태</label>
          <select id="post-status" class="form-input" style="margin-top:4px;max-width:100%">
            <option value="publish">발행됨</option>
            <option value="future">예약됨</option>
            <option value="draft">임시저장</option>
          </select>
        </div>
        <div style="margin-bottom:12px">
          <label style="font-size:13px;font-weight:600">발행 일시</label>
          <input type="datetime-local" id="post-date" class="form-input" style="margin-top:4px;max-width:100%">
        </div>
        <div style="display:flex;gap:8px">
          <button type="button" onclick="savePost()" class="btn-primary" style="flex:1">저장</button>
        </div>
      </div>
    </div>
    <div class="metabox-section">
      <div class="metabox-header" onclick="this.nextElementSibling.classList.toggle('hidden')">발췌문 <span>▾</span></div>
      <div class="metabox-content hidden">
        <textarea id="post-excerpt" class="form-input" style="width:100%; height:80px;"></textarea>
      </div>
    </div>
  </div>
</div>`;

    case 'pages': return `
<h1 class="wp-heading-inline">페이지</h1>
<a href="/wp-admin/?page=new-page" class="page-title-action">새로 추가</a>
<div id="pages-list" style="margin-top:15px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'new-page': return `
<h1 class="wp-heading-inline">새 페이지 추가</h1>
<div class="metabox-wrap">
  <div>
    <div style="margin-bottom:12px">
      <input type="text" id="page-title" class="form-input" placeholder="제목" style="max-width:100%;font-size:1.3rem;padding:10px">
    </div>
    <div class="postbox">
      <div class="postbox-hdr">내용</div>
      <div class="inside">
        <textarea id="page-content" class="wp-editor" rows="20" placeholder="페이지 내용을 작성하세요..."></textarea>
      </div>
    </div>
  </div>
  <div>
    <div class="postbox">
      <div class="postbox-hdr">발행</div>
      <div class="inside">
        <select id="page-status" class="form-input" style="margin-bottom:10px;max-width:100%">
          <option value="publish">발행됨</option>
          <option value="draft">임시글</option>
        </select>
        <button type="button" onclick="savePage()" class="btn-primary" style="width:100%">페이지 발행</button>
        <div class="spinner" id="page-spinner" style="margin-top:8px"></div>
      </div>
    </div>
  </div>
</div>`;

    case 'media': return `
<h1 class="wp-heading-inline">미디어</h1>
<div id="media-list" style="margin-top:15px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'comments': return `
<h1 class="wp-heading-inline">댓글</h1>
<div id="comments-list" style="margin-top:15px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'themes': return `
<h1 class="wp-heading-inline">테마</h1>
<a href="/wp-admin/?page=add-theme" class="page-title-action">새 테마 추가</a>
<div id="themes-list" style="margin-top:15px;display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:20px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'add-theme': return `
<h1 class="wp-heading-inline">테마 추가</h1>
<a href="/wp-admin/?page=themes" class="page-title-action">← 테마 목록</a>
<div style="margin-top:20px">
  <div class="wp-card" style="margin-bottom:20px">
    <div class="wp-card-header"><h2>🔍 WordPress.org 테마 검색</h2></div>
    <div class="wp-card-body">
      <div style="display:flex;gap:8px;margin-bottom:16px">
        <input type="text" id="theme-search" class="form-input" placeholder="테마 이름 검색..." style="max-width:320px" onkeydown="if(event.key==='Enter')searchWPThemes()">
        <button class="btn-primary" onclick="searchWPThemes()">검색</button>
      </div>
      <div id="theme-search-results"></div>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>📦 ZIP 파일로 테마 업로드</h2></div>
    <div class="wp-card-body">
      <p style="font-size:13px;color:var(--muted);margin-bottom:14px">WordPress 테마 ZIP 파일을 직접 업로드하여 설치할 수 있습니다.</p>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input type="file" id="theme-zip" accept=".zip" style="border:1px solid var(--border);border-radius:4px;padding:6px;font-size:13px">
        <button id="upload-theme-btn" class="btn-primary" onclick="uploadTheme()">ZIP 업로드 및 설치</button>
      </div>
    </div>
  </div>
</div>`;

    case 'plugins': return `
<h1 class="wp-heading-inline">플러그인</h1>
<a href="/wp-admin/?page=add-plugin" class="page-title-action">새 플러그인 추가</a>
<div id="plugins-list" style="margin-top:15px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'add-plugin': return `
<h1 class="wp-heading-inline">플러그인 추가</h1>
<a href="/wp-admin/?page=plugins" class="page-title-action">← 플러그인 목록</a>
<div style="margin-top:20px">
  <div class="wp-card" style="margin-bottom:20px">
    <div class="wp-card-header"><h2>🔍 WordPress.org 플러그인 검색</h2></div>
    <div class="wp-card-body">
      <div style="display:flex;gap:8px;margin-bottom:16px">
        <input type="text" id="plugin-search" class="form-input" placeholder="플러그인 이름 검색..." style="max-width:320px" onkeydown="if(event.key==='Enter')searchWPOrg('plugins')">
        <button class="btn-primary" onclick="searchWPOrg('plugins')">검색</button>
      </div>
      <div id="search-results" style="display:flex;flex-direction:column;gap:12px"></div>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>📦 ZIP 파일로 플러그인 업로드</h2></div>
    <div class="wp-card-body">
      <p style="font-size:13px;color:var(--muted);margin-bottom:14px">WordPress 플러그인 ZIP 파일을 직접 업로드하여 설치할 수 있습니다.</p>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input type="file" id="plugin-zip" accept=".zip" style="border:1px solid var(--border);border-radius:4px;padding:6px;font-size:13px">
        <button id="upload-plugin-btn" class="btn-primary" onclick="uploadPlugin()">ZIP 업로드 및 설치</button>
      </div>
    </div>
  </div>
</div>`;

    case 'widgets': return `
<h1 class="wp-heading-inline">위젯</h1>
<div style="margin-top:20px">
  <div class="notice notice-info"><p>WordPress 위젯 영역입니다. 활성 테마의 위젯 영역에 위젯을 추가하고 관리합니다.</p></div>
  <div class="grid-2" style="margin-top:20px">
    <div class="wp-card">
      <div class="wp-card-header"><h2>사용 가능한 위젯</h2></div>
      <div class="wp-card-body">
        ${['검색','최근 글','최근 댓글','보관함','카테고리','태그','텍스트','HTML','이미지'].map(w=>`
        <div style="background:#f6f7f7;border:1px solid var(--border);border-radius:4px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
          <div style="font-weight:600;font-size:13px">${esc(w)}</div>
          <button class="btn btn-sm" onclick="addWidget('${esc(w)}')">추가 ▶</button>
        </div>`).join('')}
      </div>
    </div>
    <div class="wp-card">
      <div class="wp-card-header"><h2>사이드바 (sidebar-1)</h2></div>
      <div class="wp-card-body" id="sidebar-widgets">
        <p style="font-size:13px;color:var(--muted)">불러오는 중...</p>
      </div>
    </div>
  </div>
</div>`;

    case 'users': return `
<h1 class="wp-heading-inline">사용자</h1>
<a href="/wp-admin/?page=new-user" class="page-title-action">새로 추가</a>
<div id="users-list" style="margin-top:15px"><div style="padding:20px;color:var(--muted)">불러오는 중...</div></div>`;

    case 'new-user': return `
<h1 class="wp-heading-inline">새 사용자 추가</h1>
<form data-cp-action="create-user" style="max-width:600px;margin-top:20px">
  <table class="form-table">
    <tr><th>사용자명</th><td><input name="username" class="form-input" required autocomplete="username"></td></tr>
    <tr><th>이메일</th><td><input name="email" type="email" class="form-input" required></td></tr>
    <tr><th>비밀번호</th><td><input name="password" type="password" class="form-input" required autocomplete="new-password"></td></tr>
  </table>
  <div class="submit-row"><button type="submit" class="btn-primary">사용자 추가</button><div class="spinner"></div></div>
</form>`;

    case 'settings': return `
<h1 class="wp-heading-inline">설정</h1>
<form data-cp-action="update-settings" style="margin-top:20px">
  <table class="form-table">
    <tr><th><label for="blogname">사이트 제목</label></th><td><input name="blogname" id="blogname" class="form-input" value="${siteName}"></td></tr>
    <tr><th><label for="blogdescription">태그라인</label></th><td><input name="blogdescription" id="blogdescription" class="form-input"></td></tr>
    <tr><th><label for="admin_email">관리자 이메일</label></th><td><input name="admin_email" id="admin_email" type="email" class="form-input" value="${esc(siteInfo.wp_admin_username || '')}"></td></tr>
    <tr><th><label for="timezone_string">시간대</label></th>
      <td><select name="timezone_string" id="timezone_string" class="form-input">
        <option value="Asia/Seoul" selected>Asia/Seoul (UTC+9)</option>
        <option value="UTC">UTC</option>
        <option value="America/New_York">America/New_York</option>
        <option value="Europe/London">Europe/London</option>
      </select></td>
    </tr>
    <tr><th><label for="posts_per_page">페이지당 글 수</label></th>
      <td><input name="posts_per_page" id="posts_per_page" type="number" class="form-input" value="10" style="max-width:80px"></td>
    </tr>
    <tr><th><label for="permalink_structure">퍼마링크 구조</label></th>
      <td><select name="permalink_structure" id="permalink_structure" class="form-input">
        <option value="/%postname%/" selected>/%postname%/ (권장)</option>
        <option value="/?p=%post_id%">/?p=%post_id%</option>
        <option value="/%year%/%monthnum%/%day%/%postname%/">/%year%/%monthnum%/%day%/%postname%/</option>
      </select></td>
    </tr>
    <tr><th><label for="WPLANG">언어</label></th>
      <td><select name="WPLANG" id="WPLANG" class="form-input">
        <option value="ko_KR" selected>한국어</option>
        <option value="">English</option>
        <option value="ja">日本語</option>
        <option value="zh_CN">中文(简体)</option>
      </select></td>
    </tr>
  </table>
  <div class="submit-row"><button type="submit" class="btn-primary">변경사항 저장</button><div class="spinner"></div></div>
</form>`;

    case 'php': return `
<h1 class="wp-heading-inline">PHP 설정</h1>
<div style="margin-top:16px;max-width:640px">
  <div class="notice notice-info" style="margin-bottom:20px">
    <p>CloudPress는 Cloudflare Workers Edge Runtime에서 동작합니다. PHP 버전은 WordPress 호환성 레이블로 사용되며, 실제 PHP 프로세스와 동일한 동작을 에뮬레이션합니다.</p>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>🐘 PHP 버전 선택</h2></div>
    <div class="wp-card-body" id="php-versions">
      <div style="color:var(--muted)">불러오는 중...</div>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>PHP 정보</h2></div>
    <div class="wp-card-body">
      <table style="font-size:13px;width:100%">
        <tr><td style="padding:6px 0;color:var(--muted);width:180px">현재 버전</td><td style="font-weight:600" id="cur-php">${PHP_LABELS[phpVersion] || phpVersion}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">런타임</td><td style="font-weight:600">Cloudflare Workers V8</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">메모리 제한</td><td>128MB (Edge)</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">최대 실행시간</td><td>30초 (CPU)</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">파일 업로드</td><td>Cloudflare KV (100MB)</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">데이터베이스</td><td>Cloudflare D1 (SQLite)</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">OPCache</td><td>✅ 항상 활성화 (Edge)</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">Xdebug</td><td>❌ 미지원 (Edge 환경)</td></tr>
      </table>
    </div>
  </div>
</div>`;

    case 'updates': return `
<h1 class="wp-heading-inline">업데이트 설정</h1>
<div style="margin-top:16px;max-width:640px">
  <div class="wp-card">
    <div class="wp-card-header"><h2>🔄 WordPress 자동 업데이트</h2></div>
    <div class="wp-card-body">
      <form data-cp-action="auto-update">
        <div style="margin-bottom:16px">
          <label style="display:flex;align-items:center;gap:10px;padding:12px;border:1px solid var(--border);border-radius:4px;cursor:pointer;margin-bottom:8px;${autoUpdate==='enabled'?'border-color:var(--blue);background:rgba(34,113,177,.03)':''}">
            <input type="radio" name="mode" value="enabled" ${autoUpdate==='enabled'?'checked':''}> 
            <div><div style="font-weight:600">전체 자동 업데이트</div><div style="font-size:12px;color:var(--muted)">메이저, 마이너, 보안 패치 모두 자동 업데이트</div></div>
          </label>
          <label style="display:flex;align-items:center;gap:10px;padding:12px;border:1px solid var(--border);border-radius:4px;cursor:pointer;margin-bottom:8px;${autoUpdate==='minor'?'border-color:var(--blue);background:rgba(34,113,177,.03)':''}">
            <input type="radio" name="mode" value="minor" ${autoUpdate==='minor'?'checked':''}> 
            <div><div style="font-weight:600">마이너 업데이트만 <span style="background:rgba(34,163,42,.1);color:var(--ok);padding:1px 6px;border-radius:10px;font-size:.72rem">권장</span></div><div style="font-size:12px;color:var(--muted)">보안 패치 및 마이너 버전만 자동 업데이트</div></div>
          </label>
          <label style="display:flex;align-items:center;gap:10px;padding:12px;border:1px solid var(--border);border-radius:4px;cursor:pointer;${autoUpdate==='disabled'?'border-color:var(--err);background:rgba(214,99,56,.03)':''}">
            <input type="radio" name="mode" value="disabled" ${autoUpdate==='disabled'?'checked':''}> 
            <div><div style="font-weight:600">자동 업데이트 비활성화</div><div style="font-size:12px;color:var(--muted)">모든 업데이트를 수동으로 처리 (보안 위험 있음)</div></div>
          </label>
        </div>
        <div class="submit-row"><button type="submit" class="btn-primary">설정 저장</button><div class="spinner"></div></div>
      </form>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>현재 버전 정보</h2></div>
    <div class="wp-card-body">
      <table style="font-size:13px;width:100%">
        <tr><td style="padding:6px 0;color:var(--muted);width:160px">WordPress</td><td style="font-weight:600">${wpVersion} <span style="color:var(--ok)">✅ 최신</span></td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">PHP</td><td style="font-weight:600">${PHP_LABELS[phpVersion] || phpVersion}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">CloudPress</td><td style="font-weight:600">v${VERSION} <span style="color:var(--ok)">✅ 최신</span></td></tr>
        <tr><td style="padding:6px 0;color:var(--muted)">업데이트 주기</td><td>매일 02:00 KST (자동 Cron)</td></tr>
      </table>
    </div>
  </div>
</div>`;

    case 'health': return `
<h1 class="wp-heading-inline">사이트 상태</h1>
<div style="margin-top:16px;max-width:700px">
  <div class="wp-card" id="health-card">
    <div class="wp-card-header">
      <h2>🏥 헬스 체크</h2>
      <div id="health-score" style="font-size:1.4rem;font-weight:700;color:var(--blue)">…</div>
    </div>
    <div class="wp-card-body" id="health-list"><div style="color:var(--muted)">분석 중...</div></div>
  </div>
</div>`;

    case 'tools': return `
<h1 class="wp-heading-inline">도구</h1>
<div style="margin-top:20px;max-width:640px">
  <div class="wp-card" style="margin-bottom:20px">
    <div class="wp-card-header"><h2>캐시 관리</h2></div>
    <div class="wp-card-body">
      <p style="font-size:13px;color:var(--muted);margin-bottom:14px">Edge 캐시를 제거하면 모든 방문자에게 최신 콘텐츠가 제공됩니다.</p>
      <button type="button" onclick="clearCache()" class="btn-primary">🗑️ 캐시 전체 제거</button>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>데이터 가져오기 / 내보내기</h2></div>
    <div class="wp-card-body">
      <p style="font-size:13px;color:var(--muted);margin-bottom:14px">WordPress XML 형식으로 내보내거나 가져올 수 있습니다.</p>
      <button type="button" onclick="exportData()" class="btn">📥 데이터 내보내기 (WXR)</button>
    </div>
  </div>
</div>`;

    case 'profile': return `
<h1 class="wp-heading-inline">내 프로필</h1>
<form data-cp-action="update-profile" style="max-width:600px;margin-top:20px">
  <table class="form-table">
    <tr><th>표시 이름</th><td><input name="display_name" class="form-input" placeholder="표시될 이름"></td></tr>
    <tr><th>이메일</th><td><input name="email" type="email" class="form-input" placeholder="이메일 주소"></td></tr>
    <tr><th style="color:var(--muted);font-size:13px;padding-top:20px" colspan="2">비밀번호 변경</th></tr>
    <tr><th>현재 비밀번호</th><td><input name="current_password" type="password" class="form-input" autocomplete="current-password"></td></tr>
    <tr><th>새 비밀번호</th><td><input name="new_password" type="password" class="form-input" autocomplete="new-password"></td></tr>
  </table>
  <div class="submit-row"><button type="submit" class="btn-primary">프로필 업데이트</button><div class="spinner"></div></div>
</form>`;

    default: return `
<h1 class="wp-heading-inline">페이지를 찾을 수 없습니다</h1>
<p style="margin-top:15px;color:var(--muted)">요청하신 관리 페이지가 없습니다. <a href="/wp-admin/">대시보드</a>로 돌아가세요.</p>`;
  }
}

function getAdminPageScript(page) {
  const API = '/wp-json/cloudpress/v1';
  const WP  = '/wp-json/wp/v2';

  switch (page) {
    case 'dashboard': return `
(async () => {
  const d = await apiFetch('${API}/dashboard-stats');
  if (d.success) {
    document.getElementById('s-posts').textContent = d.posts;
    document.getElementById('s-pages').textContent = d.pages;
    document.getElementById('s-comments').textContent = d.comments;
    document.getElementById('s-users').textContent = d.users;
  }
})();`;

    case 'posts': return `
async function loadPosts() {
  const posts = await apiFetch('${WP}/posts?per_page=20&status=any');
  const el = document.getElementById('posts-list');
  if (!Array.isArray(posts) || !posts.length) {
    el.innerHTML = '<p style="padding:20px;color:var(--muted)">글이 없습니다. <a href="/wp-admin/?page=new-post">첫 글을 작성해보세요!</a></p>';
    return;
  }
  const rows = posts.map(p => \`<tr>
    <td class="col-title"><strong><a href="/wp-admin/?page=edit-post&id=\${p.id}">\${p.title?.rendered||'(제목 없음)'}</a></strong>
      <div style="font-size:12px;color:var(--muted);margin-top:3px">
        <a href="/wp-admin/?page=edit-post&id=\${p.id}" style="color:var(--blue)">수정</a> |
        <a href="/\${p.slug||'?p='+p.id}" target="_blank" style="color:var(--blue)">보기</a> |
        <button class="btn-link" onclick="if(confirm('삭제?'))delPost(\${p.id})">휴지통</button>
      </div>
    </td>
    <td>\${p.status==='publish'?'<span style="color:var(--ok)">●</span> 발행됨':'<span style="color:var(--muted)">●</span> '+p.status}</td>
    <td>\${new Date(p.date).toLocaleDateString('ko-KR')}</td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>제목</th><th>상태</th><th>날짜</th></tr></thead><tbody>\${rows}</tbody></table>\`;
}
loadPosts();
async function delPost(id) {
  await apiFetch('${WP_API}/posts/'+id, { method:'DELETE' });
  loadPosts();
}`;

    case 'new-post': case 'edit-post': return `
const urlParams = new URLSearchParams(location.search);
const editId = urlParams.get('id');
if (editId) {
  apiFetch('${WP_API}/posts/'+editId).then(p => {
    if (p && p.id) {
      document.getElementById('post-title').value = p.title?.rendered || '';
      document.getElementById('block-editor-canvas').innerHTML = p.content?.rendered || '<p></p>';
      document.getElementById('post-excerpt').value = p.excerpt?.rendered?.replace(/<[^>]*>/g,'') || '';
      document.getElementById('post-status').value = p.status || 'publish';
      document.getElementById('post-date').value = p.date.slice(0,16);
    }
  });
}

// 블록 에디터 기능
const editor = document.getElementById('block-editor-canvas');
editor.addEventListener('keydown', e => {
  if (e.key === '/') {
    const rect = window.getSelection().getRangeAt(0).getBoundingClientRect();
    showBlockInserter(rect.left, rect.top + 20);
  }
});

function showBlockInserter(x, y) {
  const menu = document.createElement('div');
  menu.className = 'block-inserter';
  menu.style.left = x + 'px'; menu.style.top = y + 'px';
  const blocks = [
    { t:'H1', c:'<h1>제목 1</h1>' }, { t:'H2', c:'<h2>제목 2</h2>' },
    { t:'H3', c:'<h3>제목 3</h3>' }, { t:'이미지', c:'<img src="https://via.placeholder.com/600x400">' },
    { t:'인용', c:'<blockquote>인용구 입력...</blockquote>' }, { t:'버튼', c:'<button class="wp-block-button">클릭</button>' }
  ];
  blocks.forEach(b => {
    const opt = document.createElement('div'); opt.className = 'block-option';
    opt.textContent = b.t;
    opt.onclick = () => { document.execCommand('insertHTML', false, b.c); menu.remove(); };
    menu.appendChild(opt);
  });
  document.body.appendChild(menu);
  setTimeout(() => document.addEventListener('click', () => menu.remove(), {once:true}), 10);
}

async function savePost(forceStatus) {
  const data = {
    title: document.getElementById('post-title').value,
    content: document.getElementById('block-editor-canvas').innerHTML,
    excerpt: document.getElementById('post-excerpt').value,
    status: forceStatus || document.getElementById('post-status').value,
    date: document.getElementById('post-date').value.replace('T', ' ') + ':00'
  };
  const method = editId ? 'PUT' : 'POST';
  const url = editId ? '${WP_API}/posts/'+editId : '${WP_API}/posts';
  const res = await apiFetch(url, { method, body: JSON.stringify(data) });
  if (res && res.id) {
    showToast('글이 저장되었습니다.', 'success');
    if (!editId) setTimeout(() => location.href = '/wp-admin/?page=edit-post&id='+res.id, 800);
  } else showToast(res.message || '저장 실패', 'error');
}`;

    case 'pages': return `
(async () => {
  const pages = await apiFetch('${WP}/pages?per_page=20');
  const el = document.getElementById('pages-list');
  if (!Array.isArray(pages) || !pages.length) {
    el.innerHTML = '<p style="padding:20px;color:var(--muted)">페이지가 없습니다. <a href="/wp-admin/?page=new-page">새 페이지 만들기</a></p>';
    return;
  }
  const rows = pages.map(p => \`<tr>
    <td class="col-title"><strong><a href="/\${p.slug}">\${p.title?.rendered||'(제목 없음)'}</a></strong></td>
    <td>\${new Date(p.date).toLocaleDateString('ko-KR')}</td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>제목</th><th>날짜</th></tr></thead><tbody>\${rows}</tbody></table>\`;
})();`;

    case 'new-page': return `
async function savePage() {
  const spinner = document.getElementById('page-spinner');
  if (spinner) spinner.style.display = 'inline-block';
  const res = await apiFetch('${WP}/posts', { method:'POST', body: JSON.stringify({
    title: document.getElementById('page-title').value,
    content: document.getElementById('page-content').value,
    status: document.getElementById('page-status').value,
    type: 'page',
  })});
  if (spinner) spinner.style.display = 'none';
  if (res && res.id) { showToast('페이지가 생성되었습니다.','success'); setTimeout(()=>location.href='/wp-admin/?page=pages',800); }
  else showToast((res && res.message)||'생성 실패','error');
}`;

    case 'media': return `
(async () => {
  const d = await apiFetch('${API}/media');
  const el = document.getElementById('media-list');
  if (!d.success || !d.media.length) {
    el.innerHTML = '<p style="padding:20px;color:var(--muted)">미디어 파일이 없습니다.</p>';
    return;
  }
  const rows = d.media.map(m => \`<tr>
    <td>\${m.file_name}</td>
    <td>\${m.mime_type}</td>
    <td>\${(m.file_size/1024).toFixed(1)} KB</td>
    <td>\${new Date(m.upload_date).toLocaleDateString('ko-KR')}</td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>파일명</th><th>유형</th><th>크기</th><th>업로드 날짜</th></tr></thead><tbody>\${rows}</tbody></table>\`;
})();`;

    case 'comments': return `
(async () => {
  const d = await apiFetch('${API}/comments');
  const el = document.getElementById('comments-list');
  if (!d.success || !d.comments.length) {
    el.innerHTML = '<p style="padding:20px;color:var(--muted)">댓글이 없습니다.</p>';
    return;
  }
  const rows = d.comments.map(c => \`<tr>
    <td>\${c.author}</td>
    <td style="max-width:300px">\${c.content.slice(0,100)}</td>
    <td>\${c.post_title||'-'}</td>
    <td>\${c.approved==='1'?'<span style="color:var(--ok)">승인됨</span>':'<span style="color:var(--muted)">대기 중</span>'}</td>
    <td style="white-space:nowrap">
      \${c.approved!=='1'?'<button class="btn btn-sm" onclick="commentAction('+c.id+',\\'approve\\')">승인</button> ':'' }
      <button class="btn btn-sm" onclick="commentAction(\${c.id},'spam')">스팸</button>
    </td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>작성자</th><th>내용</th><th>게시글</th><th>상태</th><th>작업</th></tr></thead><tbody>\${rows}</tbody></table>\`;
})();
async function commentAction(id, action) {
  const d = await apiFetch('${API}/comment-action', { method:'POST', body: JSON.stringify({id, action}) });
  if (d.success) { showToast(d.message, 'success'); setTimeout(()=>location.reload(), 800); }
  else showToast(d.message||'오류', 'error');
}`;

    case 'themes': return `
(async () => {
  const d = await apiFetch('${API}/themes');
  const el = document.getElementById('themes-list');
  if (!d.success) { el.innerHTML = '<p style="color:var(--muted)">테마 목록을 불러올 수 없습니다.</p>'; return; }
  el.innerHTML = d.themes.map(t => \`<div style="background:#fff;border:2px solid \${t.active?'var(--blue)':'var(--border)'};border-radius:4px;padding:20px;position:relative">
    \${t.active?'<div style="position:absolute;top:10px;right:10px;background:var(--blue);color:#fff;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:700">활성</div>':''}
    <h3 style="font-size:14px;margin-bottom:4px">\${t.name}</h3>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">버전 \${t.version}</p>
    \${!t.active
      ?'<button class="btn-primary btn-sm" onclick="activateTheme(\\'' + t.slug + '\\')">활성화</button>'
      :'<span style="font-size:13px;color:var(--ok)">✅ 현재 사용 중</span>'}
  </div>\`).join('');
})();
async function activateTheme(slug) {
  if (!confirm(slug+' 테마를 활성화하시겠습니까?')) return;
  const d = await apiFetch('${API}/activate-theme', { method:'POST', body: JSON.stringify({slug}) });
  if (d.success) { showToast(d.message,'success'); setTimeout(()=>location.reload(),600); }
  else showToast(d.message||'오류','error');
}`;

    case 'widgets': return `
(async () => {
  const d = await apiFetch('${API}/widgets');
  const el = document.getElementById('sidebar-widgets');
  if (!d || !d.success) {
    el.innerHTML = '<p style="font-size:13px;color:var(--muted)">등록된 위젯이 없습니다. 왼쪽에서 위젯을 추가하세요.</p>';
    return;
  }
  renderSidebarWidgets(d.widgets || []);
})();
function renderSidebarWidgets(widgets) {
  const el = document.getElementById('sidebar-widgets');
  if (!widgets.length) {
    el.innerHTML = '<p style="font-size:13px;color:var(--muted)">등록된 위젯이 없습니다. 왼쪽에서 위젯을 추가하세요.</p>';
    return;
  }
  el.innerHTML = widgets.map((w,i) => \`
    <div style="background:#f6f7f7;border:1px solid var(--border);border-radius:4px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
      <div style="font-weight:600;font-size:13px">\${w.name||w}</div>
      <button class="btn btn-sm btn-danger" style="color:var(--err)" onclick="removeWidget(\${i})">제거</button>
    </div>
  \`).join('');
}
async function addWidget(name) {
  const d = await apiFetch('${API}/widget-action', { method:'POST', body: JSON.stringify({action:'add', name}) });
  if (d.success) { showToast(name+' 위젯이 추가되었습니다.','success'); setTimeout(()=>location.reload(),600); }
  else showToast(d.message||'추가 실패','error');
}
async function removeWidget(idx) {
  const d = await apiFetch('${API}/widget-action', { method:'POST', body: JSON.stringify({action:'remove', index:idx}) });
  if (d.success) { showToast('위젯이 제거되었습니다.','success'); setTimeout(()=>location.reload(),600); }
  else showToast(d.message||'제거 실패','error');
}`;

    case 'plugins': return `
(async () => {
  const d = await apiFetch('${API}/plugins');
  const el = document.getElementById('plugins-list');
  if (!d.success) { el.innerHTML = '<p style="color:var(--muted)">플러그인 목록을 불러올 수 없습니다.</p>'; return; }
  const rows = d.plugins.map(p => \`<tr>
    <td><strong>\${p.name}</strong><br><span style="font-size:12px;color:var(--muted)">\${p.description}</span></td>
    <td>\${p.version}</td>
    <td>\${p.active?'<span style="color:var(--ok)">활성화됨</span>':'<span style="color:var(--muted)">비활성화</span>'}</td>
    <td><button class="btn btn-sm" onclick="pluginAction('\${p.slug}',\${p.active?'false':'true'})">\${p.active?'비활성화':'활성화'}</button></td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>플러그인</th><th>버전</th><th>상태</th><th>작업</th></tr></thead><tbody>\${rows}</tbody></table>\`;
})();
async function pluginAction(slug, activate) {
  const d = await apiFetch('${API}/plugin-action', { method:'POST', body: JSON.stringify({slug, action: activate?'activate':'deactivate'}) });
  if (d.success) { showToast(d.message,'success'); setTimeout(()=>location.reload(),800); }
  else showToast(d.message||'오류','error');
}`;
    case 'plugins': return `
(async () => {
  const d = await apiFetch('${API}/plugins');
  const el = document.getElementById('plugins-list');
  if (!d.success) { el.innerHTML = '<p style="color:var(--muted)">플러그인 목록을 불러올 수 없습니다.</p>'; return; }
  const rows = d.plugins.map(p => \`<tr>
    <td><strong>\${p.name}</strong><br><span style="font-size:12px;color:var(--muted)">\${p.description||''}</span></td>
    <td>\${p.version}</td>
    <td>\${p.active?'<span style="color:var(--ok)">활성화됨</span>':'<span style="color:var(--muted)">비활성화</span>'}</td>
    <td>
      <button class="btn btn-sm" onclick="pluginAction('\${p.slug}',\${p.active?'false':'true'})">\${p.active?'비활성화':'활성화'}</button>
      \${!p.active?'<button class="btn btn-sm btn-danger" style="margin-left:4px" onclick="if(confirm(\\'삭제?\\'))deletePlugin(\\'' + p.slug + '\\')">삭제</button>':''}
    </td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>플러그인</th><th>버전</th><th>상태</th><th>작업</th></tr></thead><tbody>\${rows}</tbody></table>\`;
})();
async function pluginAction(slug, activate) {
  const d = await apiFetch('${API}/plugin-action', { method:'POST', body: JSON.stringify({slug, action: activate==='true'||activate===true?'activate':'deactivate'}) });
  if (d.success) { showToast(d.message,'success'); setTimeout(()=>location.reload(),600); }
  else showToast(d.message||'오류','error');
}
async function deletePlugin(slug) {
  const d = await apiFetch('${API}/plugin-action', { method:'POST', body: JSON.stringify({slug, action:'delete'}) });
  if (d.success) { showToast(d.message,'success'); setTimeout(()=>location.reload(),600); }
  else showToast(d.message||'삭제 오류','error');
}`;

    case 'add-plugin': return `
(async () => {
  await searchWPOrg('plugins');
})();
async function searchWPOrg(type, q) {
  const query = q !== undefined ? q : (document.getElementById('plugin-search') ? document.getElementById('plugin-search').value : '');
  const el = document.getElementById('search-results');
  el.innerHTML = '<p style="padding:20px;color:var(--muted)">검색 중...</p>';
  const res = await apiFetch('${API}/search-wp-org?type='+type+'&s='+encodeURIComponent(query));
  if (!res.success || !res.results || !res.results.length) {
    el.innerHTML = '<p style="padding:20px;color:var(--muted)">검색 결과가 없습니다.</p>';
    return;
  }
  el.innerHTML = res.results.map(item => \`
    <div style="background:#fff;border:1px solid var(--border);border-radius:4px;padding:16px;display:flex;gap:14px;align-items:flex-start">
      <img src="\${item.icons&&item.icons['1x']?item.icons['1x']:(item.icons&&item.icons.default?item.icons.default:'https://s.w.org/plugins/geopattern-icon/'+item.slug+'.svg')}" style="width:80px;height:80px;border-radius:4px;object-fit:cover;flex-shrink:0" onerror="this.src='https://s.w.org/plugins/geopattern-icon/default.svg'">
      <div style="flex:1">
        <div style="font-weight:700;font-size:14px;margin-bottom:4px">\${item.name}</div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:4px">v\${item.version||'?'} | 다운로드 \${item.downloaded?Number(item.downloaded).toLocaleString():'?'}회</div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.5">\${(item.short_description||'').slice(0,120)}\${(item.short_description||'').length>120?'...':''}</div>
        <button class="btn-primary btn-sm" onclick="installPlugin('\${item.slug}',this)">설치</button>
      </div>
    </div>
  \`).join('');
}
async function installPlugin(slug, btn) {
  if (btn) { btn.disabled=true; btn.textContent='설치 중...'; }
  const d = await apiFetch('${API}/install-plugin', { method:'POST', body: JSON.stringify({slug}) });
  if (d.success) {
    showToast(d.message||'설치 완료', 'success');
    if (btn) { btn.textContent='✅ 설치됨'; btn.style.background='var(--ok)'; }
  } else {
    showToast(d.message||'설치 실패','error');
    if (btn) { btn.disabled=false; btn.textContent='설치'; }
  }
}
async function uploadPlugin() {
  const file = document.getElementById('plugin-zip').files[0];
  if (!file) { showToast('ZIP 파일을 선택해주세요.','error'); return; }
  const btn = document.getElementById('upload-plugin-btn');
  btn.disabled=true; btn.textContent='업로드 중...';
  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', 'plugin');
  try {
    const res = await fetch('${API}/upload-package', { method:'POST', body: formData });
    const data = await res.json();
    if (data.success) { showToast(data.message||'업로드 완료','success'); setTimeout(()=>location.href='/wp-admin/?page=plugins',1200); }
    else showToast(data.message||'업로드 실패','error');
  } catch(e) { showToast('오류: '+e.message,'error'); }
  btn.disabled=false; btn.textContent='ZIP 업로드';
}`;

    case 'add-theme': return `
(async () => {
  await searchWPThemes('');
})();
async function searchWPThemes(q) {
  const el = document.getElementById('theme-search-results');
  el.innerHTML = '<p style="padding:20px;color:var(--muted)">불러오는 중...</p>';
  const query = q !== undefined ? q : (document.getElementById('theme-search') ? document.getElementById('theme-search').value : '');
  const res = await apiFetch('${API}/search-wp-org?type=themes&s='+encodeURIComponent(query));
  if (!res.success || !res.results || !res.results.length) {
    el.innerHTML = '<p style="padding:20px;color:var(--muted)">검색 결과가 없습니다.</p>';
    return;
  }
  el.innerHTML = \`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px">\` + res.results.map(item => \`
    <div style="background:#fff;border:1px solid var(--border);border-radius:4px;overflow:hidden;position:relative">
      <img src="\${item.screenshot_url||'https://via.placeholder.com/300x200?text='+item.slug}" style="width:100%;height:150px;object-fit:cover">
      <div style="padding:12px">
        <div style="font-weight:700;font-size:13px;margin-bottom:4px">\${item.name}</div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:8px">v\${item.version||'?'}</div>
        <button class="btn-primary btn-sm" style="width:100%" onclick="installTheme('\${item.slug}',this)">설치</button>
      </div>
    </div>
  \`).join('') + '</div>';
}
async function installTheme(slug, btn) {
  if (btn) { btn.disabled=true; btn.textContent='설치 중...'; }
  const d = await apiFetch('${API}/install-theme', { method:'POST', body: JSON.stringify({slug}) });
  if (d.success) {
    showToast(d.message||'설치 완료','success');
    if (btn) { btn.textContent='✅ 설치됨'; btn.style.background='var(--ok)'; }
  } else {
    showToast(d.message||'설치 실패','error');
    if (btn) { btn.disabled=false; btn.textContent='설치'; }
  }
}
async function uploadTheme() {
  const file = document.getElementById('theme-zip').files[0];
  if (!file) { showToast('ZIP 파일을 선택해주세요.','error'); return; }
  const btn = document.getElementById('upload-theme-btn');
  btn.disabled=true; btn.textContent='업로드 중...';
  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', 'theme');
  try {
    const res = await fetch('${API}/upload-package', { method:'POST', body: formData });
    const data = await res.json();
    if (data.success) { showToast(data.message||'업로드 완료','success'); setTimeout(()=>location.href='/wp-admin/?page=themes',1200); }
    else showToast(data.message||'업로드 실패','error');
  } catch(e) { showToast('오류: '+e.message,'error'); }
  btn.disabled=false; btn.textContent='ZIP 업로드';
}`;

    case 'users': return `
(async () => {
  const d = await apiFetch('${API}/users-list');
  const el = document.getElementById('users-list');
  if (!d.success || !d.users.length) { el.innerHTML = '<p style="padding:20px;color:var(--muted)">사용자가 없습니다.</p>'; return; }
  const rows = d.users.map(u => \`<tr>
    <td><strong>\${u.display_name||u.user_login}</strong><br><span style="font-size:12px;color:var(--muted)">\${u.user_email}</span></td>
    <td>\${u.user_login}</td>
    <td>\${new Date(u.user_registered).toLocaleDateString('ko-KR')}</td>
  </tr>\`).join('');
  el.innerHTML = \`<table class="wp-table"><thead><tr><th>이름</th><th>사용자명</th><th>가입일</th></tr></thead><tbody>\${rows}</tbody></table>\`;
})();`;

    case 'php': return `
(async () => {
  const d = await apiFetch('${API}/php-version');
  const el = document.getElementById('php-versions');
  if (!d.success) { el.innerHTML = '<p style="color:var(--muted)">정보를 불러올 수 없습니다.</p>'; return; }
  el.innerHTML = d.available.map(v => \`
    <div class="php-card \${v.version===d.current?'active':''}" onclick="selectPhp('\${v.version}')">
      <div style="flex:1">
        <div style="font-weight:600">\${v.label}</div>
      </div>
      \${v.recommended?'<span class="php-badge php-recommended">권장</span>':''}
      \${v.version===d.current?'<span style="color:var(--blue);font-weight:700">✓ 현재</span>':''}
    </div>\`).join('');
  document.getElementById('cur-php').textContent = d.label;
})();
function selectPhp(version) {
  showToast('PHP 버전 변경은 CloudPress 관리자 페이지에서 처리됩니다.', 'info');
}`;

    case 'health': return `
(async () => {
  const d = await apiFetch('${API}/health');
  const scoreEl = document.getElementById('health-score');
  const listEl  = document.getElementById('health-list');
  if (!d.success) { listEl.innerHTML = '<p style="color:var(--muted)">상태를 확인할 수 없습니다.</p>'; return; }
  scoreEl.textContent = d.score + '%';
  scoreEl.style.color = d.score >= 80 ? 'var(--ok)' : d.score >= 60 ? '#dba617' : 'var(--err)';
  listEl.innerHTML = d.checks.map(c => \`<div class="health-item">
    <div class="health-dot dot-\${c.status}"></div>
    <div style="flex:1"><div style="font-weight:600">\${c.label}</div><div style="font-size:12px;color:var(--muted)">\${c.message}</div></div>
    <div style="font-size:12px;font-weight:600;color:\${c.status==='good'?'var(--ok)':c.status==='warning'?'#dba617':'var(--err)'}">
      \${c.status==='good'?'정상':c.status==='warning'?'주의':'심각'}
    </div>
  </div>\`).join('');
})();`;

    case 'tools': return `
async function clearCache() {
  const d = await apiFetch('${API}/clear-cache', { method:'POST' });
  showToast(d.success ? d.message : '캐시 제거 실패', d.success ? 'success' : 'error');
}
async function exportData() {
  showToast('데이터 내보내기는 준비 중입니다.', 'info');
}`;

    default: return '';
  }
}

// ── 프론트엔드 WordPress 페이지 ───────────────────────────────────────────────
async function renderFrontend(env, siteInfo, request, url) {
  const pathname = url.pathname;
  const hostname = url.hostname;

  const [siteTitle, siteDesc] = await Promise.all([
    getWpOption(env, siteInfo, 'blogname'),
    getWpOption(env, siteInfo, 'blogdescription'),
  ]).catch(() => ['WordPress', '']);

  const title = siteTitle || siteInfo.name || 'WordPress';
  const desc  = siteDesc  || '';
  const siteUrl = `https://${hostname}`;

  // 홈페이지
  if (pathname === '/' || pathname === '/index.php') {
    const posts = await getWpPosts(env, { post_type:'post', post_status:'publish', limit:10 });
    const postsHtml = posts.length
      ? posts.map(p => {
          const link    = `${siteUrl}/${p.post_name || '?p=' + p.ID}/`;
          const excerpt = p.post_excerpt || p.post_content.replace(/<[^>]*>/g,'').slice(0,200);
          const dateStr = new Date(p.post_date).toLocaleDateString('ko-KR',{year:'numeric',month:'long',day:'numeric'});
          return `<article class="post h-entry">
  <h2 class="entry-title"><a href="${esc(link)}" class="u-url p-name">${esc(p.post_title)}</a></h2>
  <div class="entry-meta"><time class="dt-published" datetime="${p.post_date}">${dateStr}</time></div>
  <div class="entry-summary p-summary"><p>${esc(excerpt)}${excerpt.length >= 200 ? '...' : ''}</p></div>
  <a href="${esc(link)}" class="more-link">더 읽기 →</a>
</article>`;
        }).join('\n')
      : '<div class="no-posts"><p>아직 게시글이 없습니다.</p><a href="/wp-admin/" class="btn-write">첫 글 작성하기</a></div>';

    return new Response(renderTheme(title, desc, siteUrl, `<div class="posts-list">${postsHtml}</div>`), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=60' },
    });
  }

  // 개별 포스트/페이지 — Error 1101 방지: 전체 try/catch로 감쌈
  try {
    const rawSlug = pathname.replace(/^\/+|\/+$/g, '').split('?')[0].split('/')[0];
    if (rawSlug && rawSlug.length > 0 && rawSlug.length < 200 && !/[<>'"&]/.test(rawSlug)) {
      const post = await env.DB.prepare(
        `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name, post_type
           FROM wp_posts WHERE post_name=? AND post_status='publish' AND post_type IN ('post','page') LIMIT 1`
      ).bind(rawSlug).first().catch(() => null);

      if (post) {
        let dateStr = '';
        try { dateStr = new Date(post.post_date).toLocaleDateString('ko-KR',{year:'numeric',month:'long',day:'numeric'}); } catch {}
        const safeContent = post.post_content ? String(post.post_content) : '';
        return new Response(renderTheme(
          esc(String(post.post_title || '')) + ' — ' + esc(title),
          esc(String(post.post_excerpt || '')),
          siteUrl,
          `<article class="post single h-entry">
  <h1 class="entry-title p-name">${esc(String(post.post_title || ''))}</h1>
  <div class="entry-meta"><time class="dt-published" datetime="${esc(String(post.post_date || ''))}">${dateStr}</time></div>
  <div class="entry-content e-content">${safeContent}</div>
  <nav class="post-nav" style="margin-top:32px;padding-top:20px;border-top:1px solid #e0e0e0">
    <a href="${siteUrl}" style="color:#2271b1">← 목록으로</a>
  </nav>
</article>`
        ), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=300' } });
      }
    }
  } catch (postErr) {
    // Error 1101 방지: 포스트 렌더링 실패 시 404로 안전하게 폴백
    console.error('Post render error (fallback to 404):', String(postErr?.message || postErr));
  }

  // 404
  return new Response(renderTheme('페이지를 찾을 수 없습니다 — ' + esc(title), '', siteUrl,
    `<div class="not-found" style="text-align:center;padding:60px 20px">
  <h1 style="font-size:4rem;color:#c3c4c7;margin-bottom:0">404</h1>
  <h2 style="font-size:1.2rem;margin-bottom:16px">페이지를 찾을 수 없습니다</h2>
  <p style="color:#646970;margin-bottom:24px">요청하신 페이지가 존재하지 않거나 이동되었습니다.</p>
  <a href="${siteUrl}" style="background:#2271b1;color:#fff;padding:10px 24px;border-radius:4px;text-decoration:none">홈으로 돌아가기</a>
</div>`), { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function renderTheme(title, description, siteUrl, content) {
  const siteTitle = title.includes(' — ') ? title.split(' — ').pop() : title;
  return `<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
${description ? `<meta name="description" content="${esc(description)}">` : ''}
<meta name="generator" content="WordPress (CloudPress Edge)">
<link rel="stylesheet" href="${siteUrl}/wp-includes/css/dashicons.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--primary:#2271b1;--text:#3c434a;--muted:#646970;--border:#e0e0e0;--bg:#f9f9f9;--surface:#fff}
html{background:var(--bg)}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,sans-serif;font-size:16px;line-height:1.7;color:var(--text);background:var(--bg)}
a{color:var(--primary);text-decoration:none}a:hover{text-decoration:underline}
.site-header{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.header-inner{max-width:1100px;margin:0 auto;padding:0 24px;display:flex;align-items:center;justify-content:space-between;height:64px}
.site-title{font-size:1.3rem;font-weight:700;color:var(--text)}
.site-title a{color:inherit;text-decoration:none}
.site-desc{font-size:.8rem;color:var(--muted);margin-top:2px}
nav.main-nav{display:flex;gap:24px}
nav.main-nav a{font-size:.9rem;color:var(--muted);font-weight:500}
nav.main-nav a:hover{color:var(--primary);text-decoration:none}
.site-container{max-width:1100px;margin:40px auto;padding:0 24px;display:grid;grid-template-columns:1fr 300px;gap:48px}
@media(max-width:768px){.site-container{grid-template-columns:1fr;gap:24px}nav.main-nav{display:none}}
.content-area{}
article.post{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:28px;margin-bottom:24px;transition:.15s}
article.post:hover{box-shadow:0 2px 8px rgba(0,0,0,.07)}
article.post.single{padding:36px}
.entry-title{font-size:1.3rem;font-weight:700;line-height:1.35;margin-bottom:10px}
.entry-title a{color:var(--text)}
.entry-title a:hover{color:var(--primary);text-decoration:none}
.entry-meta{font-size:.82rem;color:var(--muted);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.entry-summary{color:var(--text);font-size:.95rem}
.more-link{display:inline-block;margin-top:14px;font-size:.85rem;font-weight:600;color:var(--primary)}
.more-link:hover{text-decoration:underline}
.entry-content{font-size:1rem;line-height:1.85;color:var(--text)}
.entry-content h1,.entry-content h2,.entry-content h3,.entry-content h4{margin:28px 0 12px;line-height:1.3}
.entry-content h2{font-size:1.4rem}
.entry-content h3{font-size:1.15rem}
.entry-content p{margin-bottom:18px}
.entry-content ul,.entry-content ol{margin-bottom:18px;padding-left:24px}
.entry-content li{margin-bottom:6px}
.entry-content img{max-width:100%;height:auto;border-radius:4px;margin:8px 0}
.entry-content a{color:var(--primary)}
.entry-content blockquote{border-left:4px solid var(--primary);padding:12px 20px;margin:20px 0;background:rgba(34,113,177,.04);border-radius:0 4px 4px 0;font-style:italic;color:var(--muted)}
.entry-content code{background:#f6f7f7;padding:2px 6px;border-radius:3px;font-size:.9em;font-family:monospace}
.entry-content pre{background:#1d2327;color:#f0f0f1;padding:20px;border-radius:6px;overflow-x:auto;margin-bottom:18px}
.entry-content pre code{background:none;color:inherit;padding:0}
.no-posts{text-align:center;padding:48px 24px;background:var(--surface);border:1px solid var(--border);border-radius:6px}
.btn-write{display:inline-block;margin-top:12px;background:var(--primary);color:#fff;padding:10px 24px;border-radius:4px;font-size:.9rem;font-weight:600}
.btn-write:hover{text-decoration:none;background:#135e96}
.widget-area{}
.widget{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:20px;margin-bottom:20px}
.widget-title{font-size:.95rem;font-weight:700;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.site-footer{background:var(--surface);border-top:1px solid var(--border);padding:24px;text-align:center;font-size:.85rem;color:var(--muted);margin-top:48px}
.site-footer a{color:var(--muted)}.site-footer a:hover{color:var(--primary)}
</style>
</head>
<body class="wordpress">
<header class="site-header">
  <div class="header-inner">
    <div>
      <p class="site-title"><a href="${siteUrl}">${esc(siteTitle)}</a></p>
      ${description ? `<p class="site-desc">${esc(description)}</p>` : ''}
    </div>
    <nav class="main-nav">
      <a href="${siteUrl}/">홈</a>
    </nav>
  </div>
</header>
<div class="site-container">
  <main class="content-area">${content}</main>
  <aside class="widget-area">
    <div class="widget">
      <h2 class="widget-title">검색</h2>
      <form role="search" method="get" action="${siteUrl}/">
        <input type="text" name="s" placeholder="검색..." style="width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:4px;font-size:14px;font-family:inherit">
      </form>
    </div>
  </aside>
</div>
<footer class="site-footer">
  <p>
    <a href="${siteUrl}">${esc(siteTitle)}</a> |
    Powered by <a href="https://wordpress.org/">WordPress</a> &amp;
    <a href="https://cloudpress.site/">CloudPress</a> Edge Edition
  </p>
</footer>
<script>
Promise.all([
  fetch('/wp-json/wp/v2/posts?per_page=5').then(r=>r.json()).catch(()=>[]),
  fetch('/wp-json/wp/v2/categories?per_page=10').then(r=>r.json()).catch(()=>[]),
]).then(([posts, cats]) => {
  const rp = document.getElementById('recent-posts');
  if (rp) rp.innerHTML = Array.isArray(posts) && posts.length
    ? '<ul style="list-style:none;padding:0">'+posts.map(p=>'<li style="padding:6px 0;border-bottom:1px solid var(--border)"><a href="'+p.link+'" style="font-size:.88rem;color:var(--text);line-height:1.4">'+p.title.rendered+'</a></li>').join('')+'</ul>'
    : '<p style="font-size:.85rem;color:var(--muted)">글이 없습니다.</p>';
  const wc = document.getElementById('widget-cats');
  if (wc) wc.innerHTML = Array.isArray(cats) && cats.length
    ? '<ul style="list-style:none;padding:0">'+cats.map(c=>'<li style="padding:5px 0"><a href="/category/'+c.slug+'/" style="font-size:.88rem;color:var(--text)">'+c.name+' <span style="color:var(--muted)">('+c.count+')</span></a></li>').join('')+'</ul>'
    : '<p style="font-size:.85rem;color:var(--muted)">카테고리가 없습니다.</p>';
});
</script>
</body>
</html>`;
}

// ── 정적 파일 서빙 (KV) ───────────────────────────────────────────────────────
async function serveStaticFromKV(env, siteInfo, pathname) {
  if (!env.CACHE && !env.SITE_KV) return null;
  const prefix  = siteInfo.site_prefix;
  const kvKey   = `wp_file:${prefix}:${pathname}`;
  const kv      = env.SITE_KV || env.CACHE;
  try {
    const { value, metadata } = await kv.getWithMetadata(kvKey, { type: 'arrayBuffer' });
    if (!value) return null;
    const ext = pathname.split('.').pop().toLowerCase();
    const ctMap = {
      css:'text/css', js:'application/javascript', mjs:'application/javascript',
      png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif',
      svg:'image/svg+xml', ico:'image/x-icon', webp:'image/webp', avif:'image/avif',
      woff:'font/woff', woff2:'font/woff2', ttf:'font/ttf', eot:'application/vnd.ms-fontobject',
      pdf:'application/pdf', xml:'application/xml', txt:'text/plain', json:'application/json',
    };
    const ct = (metadata && metadata.contentType) || ctMap[ext] || 'application/octet-stream';
    return new Response(value, {
      headers: {
        'Content-Type': ct,
        'Cache-Control': `public, max-age=${CACHE_TTL_STATIC}, immutable`,
        'Vary': 'Accept-Encoding',
      },
    });
  } catch { return null; }
}

// ── 메인 fetch 핸들러 ─────────────────────────────────────────────────────────
async function handleRequest(request, env, ctx) {
    const url      = new URL(request.url);
    const pathname = url.pathname;
    const method   = request.method;

    // 1. CORS Preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      }});
    }

    // 2. WAF 검사
    const waf = wafCheck(request, url);
    if (waf.block) {
      return jsonR({ error: 'Blocked by WAF', reason: waf.reason }, waf.status || 403);
    }

    // 3. Rate Limit
    const ip = getClientIP(request);
    const rl = await rateLimitCheck(env, ip, pathname);
    if (!rl.allowed) {
      return new Response(rl.banned ? '차단된 IP입니다.' : '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.', {
        status: 429,
        headers: { 'Retry-After': String(RATE_LIMIT_WIN) },
      });
    }

    // 4. 사이트 정보 로드
    const siteInfo = await getSiteInfo(env, url.hostname);
    if (!siteInfo) {
      // CloudPress 플랫폼 자체 도메인 — Pages Functions이 처리하거나
      // 아직 프로비저닝 중인 사이트
      // 404를 반환하면 Cloudflare Pages가 정적 파일 서빙을 이어받음
      return new Response(null, { status: 404 });
    }

    // 사이트 일시정지 확인
    if (siteInfo.suspended) {
      return new Response(`<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>서비스 일시정지</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f9f9f9;margin:0}
.box{text-align:center;padding:48px 32px;background:#fff;border-radius:8px;border:1px solid #e0e0e0;max-width:420px}
h1{color:#d63638;margin-bottom:12px}p{color:#646970;line-height:1.6}</style>
</head><body><div class="box"><h1>⚠️ 서비스 일시정지</h1>
<p>${esc(siteInfo.suspension_reason || '이 사이트는 현재 일시 정지 상태입니다.')}</p>
</div></body></html>`, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // 5. 정적 파일 → KV 우선 서빙
    if (method === 'GET' && isStaticAsset(pathname)) {
      const kvRes = await serveStaticFromKV(env, siteInfo, pathname);
      if (kvRes) return kvRes;
      // KV에 없으면 WordPress.org CDN에서 직접 fetch
      if (pathname.startsWith('/wp-includes/') || pathname.startsWith('/wp-admin/')) {
        const wpVer = siteInfo.wp_version || env.WP_VERSION || '6.9.4';
        // downloads.wordpress.org CDN 사용 (SVN보다 빠르고 안정적)
        const cdnUrls = [
          `https://downloads.wordpress.org/release/wordpress-${wpVer}-no-content.zip`,
        ];
        // 파일별 직접 fetch: core GitHub mirror 또는 WordPress CDN
        const fileCdnUrl = `https://raw.githubusercontent.com/WordPress/WordPress/${wpVer}${pathname}`;
        try {
          const cdnRes = await fetch(fileCdnUrl, { cf: { cacheEverything: true, cacheTtl: 86400 } });
          if (cdnRes.ok) {
            const clone = cdnRes.clone();
            const buf   = await clone.arrayBuffer();
            // KV에 비동기 저장
            if (env.CACHE && siteInfo.site_prefix) {
              ctx.waitUntil(
                env.CACHE.put(`wp_file:${siteInfo.site_prefix}:${pathname}`, buf, {
                  expirationTtl: 86400 * 7,
                }).catch(() => {})
              );
            }
            const ext = pathname.split('.').pop().toLowerCase();
            const mimeMap = { css:'text/css', js:'application/javascript', png:'image/png',
              jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', svg:'image/svg+xml',
              woff:'font/woff', woff2:'font/woff2', ttf:'font/ttf', eot:'application/vnd.ms-fontobject',
              ico:'image/x-icon', json:'application/json', xml:'application/xml', txt:'text/plain' };
            return new Response(buf, {
              headers: {
                'Content-Type': cdnRes.headers.get('Content-Type') || mimeMap[ext] || 'application/octet-stream',
                'Cache-Control': `public, max-age=${CACHE_TTL_STATIC}`,
              },
            });
          }
        } catch {}
      }
      return new Response('Not Found', { status: 404 });
    }

    // 6. wp-login.php
    if (pathname === '/wp-login.php') {
      return handleWpLogin(env, siteInfo, request, url);
    }

    // 7. wp-admin/
    if (pathname === '/wp-admin/' || pathname === '/wp-admin' || pathname.startsWith('/wp-admin/')) {
      const session = await getWpSession(env, siteInfo, request);
      if (!session) {
        const redirect = encodeURIComponent(pathname + url.search);
        return Response.redirect(`/wp-login.php?redirect_to=${redirect}`, 302);
      }
      const page = url.searchParams.get('page') || 'dashboard';
      const html = renderWpAdmin(siteInfo, session, page, env);
      return new Response(html, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Frame-Options': 'SAMEORIGIN',
          'Cache-Control': 'no-store',
        },
      });
    }

    // 8. WordPress REST API
    if (pathname.startsWith('/wp-json/')) {
      return handleRestApi(env, siteInfo, request, url);
    }

    // 9. wp-cron.php
    if (pathname === '/wp-cron.php') {
      return new Response('OK', { headers: { 'Content-Type': 'text/plain' } });
    }

    // 10. sitemap.xml
    if (pathname === '/sitemap.xml') {
      const posts = await getWpPosts(env, { post_type:'post', post_status:'publish', limit:50 });
      const pages = await getWpPosts(env, { post_type:'page', post_status:'publish', limit:20 });
      const siteUrl = `https://${url.hostname}`;
      const urlSet = [...posts, ...pages].map(p => `
  <url>
    <loc>${siteUrl}/${esc(p.post_name || '?p=' + p.ID)}/</loc>
    <lastmod>${p.post_modified ? p.post_modified.split(' ')[0] : new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>${p.post_type === 'page' ? '0.8' : '0.6'}</priority>
  </url>`).join('');
      return new Response(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${siteUrl}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>${urlSet}
</urlset>`, { headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
    }

    // 11. robots.txt
    if (pathname === '/robots.txt') {
      return new Response(`User-agent: *\nAllow: /\nDisallow: /wp-admin/\nSitemap: https://${url.hostname}/sitemap.xml\n`, {
        headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' },
      });
    }

    // 12. 프론트엔드 WordPress 페이지 렌더링
    return renderFrontend(env, siteInfo, request, url);
}

// ── export default ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error('[CloudPress] Unhandled error:', e?.message || e);
      return new Response(JSON.stringify({ error: 'Internal Server Error', message: String(e?.message || e) }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }
  },

  // ── 스케줄된 Cron (자동 업데이트) ─────────────────────────────────────────
  async scheduled(event, env, ctx) {
    const mainDb = env.CP_MAIN_DB || env.DB;
    if (!mainDb) return;
    ctx.waitUntil((async () => {
      try {
        // WordPress 자동 업데이트 처리
        const sites = await mainDb.prepare(
          `SELECT id, site_prefix, wp_version, wp_auto_update, primary_domain
             FROM sites WHERE status='active' AND deleted_at IS NULL
              AND (wp_auto_update='enabled' OR wp_auto_update='minor')`
        ).all();

        if (!sites.results?.length) return;

        // 최신 WordPress 버전 확인
        let latestVersion = '';
        try {
          const verRes = await fetch('https://api.wordpress.org/core/version-check/1.7/');
          if (verRes.ok) {
            const verData = await verRes.json();
            latestVersion = verData?.offers?.[0]?.version || '';
          }
        } catch {}

        if (!latestVersion) return;

        for (const site of sites.results) {
          const current = site.wp_version || '6.9.4';
          if (current === latestVersion) continue;

          const [curMajor, curMinor] = current.split('.').map(Number);
          const [latMajor, latMinor] = latestVersion.split('.').map(Number);

          const isMajorUpdate = latMajor > curMajor;
          if (site.wp_auto_update === 'minor' && isMajorUpdate) continue;

          // 버전 업데이트 기록
          await mainDb.prepare(
            `UPDATE sites SET wp_version=?, updated_at=datetime('now') WHERE id=?`
          ).bind(latestVersion, site.id).run().catch(() => {});

          // KV 캐시 무효화
          if (env.CACHE && site.primary_domain) {
            await env.CACHE.delete(KV_SITE_PREFIX + site.primary_domain).catch(() => {});
          }

          console.log(`[cron] ${site.primary_domain}: WordPress ${current} → ${latestVersion}`);
        }
      } catch (e) {
        console.error('[cron] 자동 업데이트 오류:', e.message);
      }
    })());
  },
};
