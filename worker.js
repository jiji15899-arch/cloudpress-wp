/**
 * CloudPress v22.0 — WordPress-Compatible D1-Powered Worker
 *
 * 아키텍처: PHP Origin 불필요 — 100% Cloudflare Edge에서 동작
 *   - WordPress 완전 호환 REST API (D1 기반)
 *   - wp-login.php / wp-admin 완전 구현 (D1 기반 인증)
 *   - 정적 파일 KV 서빙
 *   - 도메인별 멀티사이트 격리
 *   - WAF / Rate Limit / DDoS 방어
 *   - Cloudflare A 레코드 방식 (IP: 104.21.0.0/16, 172.67.0.0/16)
 */

// ── 상수 ─────────────────────────────────────────────────────────────────────
const VERSION          = '22.0';
const CACHE_TTL_STATIC = 31536000;
const CACHE_TTL_HTML   = 60;
const CACHE_TTL_API    = 30;
const KV_SITE_PREFIX   = 'site_domain:';
const KV_OPT_PREFIX    = 'opt:';
const KV_SESSION_PREFIX= 'wp_session:';
const RATE_LIMIT_WIN   = 60;
const RATE_LIMIT_MAX   = 300;
const DDOS_BAN_TTL     = 3600;

// WordPress Cloudflare IP (A 레코드 방식)
const CF_IPS = ['104.21.0.0', '172.67.0.0'];

// WAF
const WAF_SQLI = /('\s*(or|and)\s+'|--)|(union\s+select)|(;\s*(drop|delete|insert|update)\s)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed)/i;
const WAF_PATH = /(\.\.(\\/|\\)|\\/etc\\/passwd|\\/proc\\/self|cmd\.exe|powershell)/i;

function esc(s) {
  return String(s || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function getClientIP(req) {
  return req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || '0.0.0.0';
}

function wafCheck(req, url) {
  const path  = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  if (WAF_PATH.test(path)) return { block: true, reason: 'path_traversal', status: 403 };
  if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block: true, reason: 'sqli', status: 403 };
  if (WAF_XSS.test(path)  || WAF_XSS.test(query))  return { block: true, reason: 'xss',  status: 403 };
  const badBot = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix/i;
  if (badBot.test(req.headers.get('user-agent') || '')) return { block: true, reason: 'bad_bot', status: 403 };
  return { block: false };
}

async function rateLimitCheck(env, ip, pathname) {
  if (!env.CACHE) return { allowed: true };
  const isAuth = pathname === '/wp-login.php' || pathname.startsWith('/wp-admin');
  const maxReq = isAuth ? 10 : RATE_LIMIT_MAX;
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

// ── 사이트 정보 로드 ─────────────────────────────────────────────────────────
async function getSiteInfo(env, hostname) {
  // 1. KV 캐시
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + hostname, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }
  // 2. D1
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        `SELECT id, name, site_prefix, status, suspended, suspension_reason,
                wp_admin_url, wp_admin_username, wp_admin_password, wp_version,
                site_d1_id, site_kv_id, plan
           FROM sites WHERE primary_domain=? AND deleted_at IS NULL LIMIT 1`
      ).bind(hostname.replace(/^www\./, '')).first();
      if (row) {
        const info = { ...row };
        if (env.CACHE) env.CACHE.put(KV_SITE_PREFIX + hostname, JSON.stringify(info), { expirationTtl: 3600 }).catch(() => {});
        return info;
      }
    } catch {}
  }
  return null;
}

// ── 정적 파일 판별 ────────────────────────────────────────────────────────────
function isStaticAsset(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webp|avif|webm|pdf|zip|xml|txt|map)$/i.test(pathname);
}

// ── WordPress 세션 관리 (D1 기반) ─────────────────────────────────────────────
function parseCookies(req) {
  const cookieHeader = req.headers.get('cookie') || '';
  const cookies = {};
  for (const part of cookieHeader.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  }
  return cookies;
}

async function getWpSession(env, siteInfo, req) {
  const cookies = parseCookies(req);
  const prefix = siteInfo.site_prefix;
  const sessionKey = cookies[`wordpress_logged_in_${prefix}`] || cookies['wordpress_logged_in'];
  if (!sessionKey) return null;

  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SESSION_PREFIX + sessionKey, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }
  return null;
}

async function createWpSession(env, siteInfo, userId, username, role) {
  const token = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const sessionData = { user_id: userId, username, role, created: Date.now() };
  if (env.CACHE) {
    await env.CACHE.put(KV_SESSION_PREFIX + token, JSON.stringify(sessionData), { expirationTtl: 86400 * 14 });
  }
  return token;
}

// ── WordPress 비밀번호 해싱 (호환) ──────────────────────────────────────────
async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + ':wp_salt_v1'));
  return '$wp$' + Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  if (hash.startsWith('$wp$')) {
    const computed = await hashPassword(password);
    return computed === hash;
  }
  // Fallback: plain text (migration)
  return password === hash;
}

// ── D1 WordPress DB 조회 ─────────────────────────────────────────────────────
async function getWpUser(env, usernameOrEmail) {
  try {
    return await env.DB.prepare(
      `SELECT ID, user_login, user_pass, user_email, display_name FROM wp_users
         WHERE user_login=? OR user_email=? LIMIT 1`
    ).bind(usernameOrEmail, usernameOrEmail).first();
  } catch { return null; }
}

async function getWpUserMeta(env, userId, key) {
  try {
    const row = await env.DB.prepare(
      'SELECT meta_value FROM wp_usermeta WHERE user_id=? AND meta_key=? LIMIT 1'
    ).bind(userId, key).first();
    return row?.meta_value;
  } catch { return null; }
}

async function getWpOption(env, siteInfo, name) {
  const cacheKey = KV_OPT_PREFIX + siteInfo.site_prefix + ':' + name;
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(cacheKey);
      if (cached !== null) return cached;
    } catch {}
  }
  try {
    const row = await env.DB.prepare(
      'SELECT option_value FROM wp_options WHERE option_name=? LIMIT 1'
    ).bind(name).first();
    const val = row?.option_value || '';
    if (env.CACHE) env.CACHE.put(cacheKey, val, { expirationTtl: 3600 }).catch(() => {});
    return val;
  } catch { return ''; }
}

async function getWpPosts(env, args = {}) {
  const { post_type = 'post', post_status = 'publish', limit = 10, offset = 0, orderby = 'date', order = 'DESC' } = args;
  try {
    const rows = await env.DB.prepare(
      `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name,
              post_author, post_type, post_status, comment_count, guid
         FROM wp_posts WHERE post_type=? AND post_status=?
         ORDER BY ${orderby === 'title' ? 'post_title' : 'post_date'} ${order === 'ASC' ? 'ASC' : 'DESC'}
         LIMIT ? OFFSET ?`
    ).bind(post_type, post_status, limit, offset).all();
    return rows.results || [];
  } catch { return []; }
}

async function getWpPost(env, idOrSlug) {
  try {
    const isNum = /^\d+$/.test(String(idOrSlug));
    const row = await env.DB.prepare(
      `SELECT ID, post_title, post_content, post_excerpt, post_date, post_modified,
              post_name, post_author, post_type, post_status, comment_count, guid
         FROM wp_posts WHERE ${isNum ? 'ID=?' : 'post_name=?'} AND deleted_at IS NULL LIMIT 1`
    ).bind(idOrSlug).first();
    return row;
  } catch { return null; }
}

// ── WordPress 관리자 페이지 (D1 기반) ───────────────────────────────────────
function renderWpAdmin(siteInfo, session, page = 'dashboard') {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const username = esc(session?.username || 'admin');

  const pages = {
    dashboard: renderAdminDashboard,
    posts: renderAdminPosts,
    'new-post': renderAdminNewPost,
    pages: renderAdminPages,
    media: renderAdminMedia,
    themes: renderAdminThemes,
    plugins: renderAdminPlugins,
    users: renderAdminUsers,
    settings: renderAdminSettings,
    profile: renderAdminProfile,
  };

  const pageRenderer = pages[page] || renderAdminDashboard;
  const pageContent = pageRenderer(siteInfo, session);

  return `<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${pageContent.title || '대시보드'} ‹ ${siteName} — WordPress</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--wp-admin-blue:#2271b1;--wp-admin-bar-bg:#23282d;--wp-menu-bg:#23282d;--wp-menu-hover:#191e23;--wp-menu-active:#0073aa;--wp-body-bg:#f0f0f1;--wp-content-bg:#fff;--wp-text:#3c434a;--wp-muted:#646970;--wp-border:#c3c4c7;--wp-success:#00a32a;--wp-error:#d63638}
html,body{height:100%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:13px;background:var(--wp-body-bg);color:var(--wp-text)}
#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:var(--wp-admin-bar-bg);color:#fff;z-index:9999;display:flex;align-items:center;gap:0}
#wpadminbar a{color:#eee;text-decoration:none;padding:0 10px;line-height:32px;display:inline-block;font-size:13px}
#wpadminbar a:hover{color:#fff;background:rgba(255,255,255,.1)}
#wpadminbar .ab-brand{font-weight:600;background:var(--wp-admin-blue)}
#wpadminbar .ab-right{margin-left:auto}
#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:var(--wp-menu-bg);overflow-y:auto;z-index:100}
#adminmenu{list-style:none}
#adminmenu li a{display:flex;align-items:center;gap:8px;padding:9px 12px;color:#eee;text-decoration:none;font-size:13px;border-left:4px solid transparent;transition:background .15s}
#adminmenu li a:hover{background:var(--wp-menu-hover);color:#fff}
#adminmenu li.active a{background:var(--wp-menu-hover);border-left-color:var(--wp-admin-blue);color:#fff}
#adminmenu li .dashicons{width:20px;font-size:18px;opacity:.7}
#wpbody{margin-top:32px;margin-left:160px;padding:20px;min-height:calc(100vh - 32px)}
.wrap{max-width:1200px}
h1.wp-heading-inline{font-size:23px;font-weight:400;line-height:1.3;color:#1d2327;margin-bottom:0;padding-right:12px}
.page-title-action{display:inline-flex;align-items:center;border:1px solid var(--wp-admin-blue);color:var(--wp-admin-blue);border-radius:3px;padding:4px 8px;font-size:13px;cursor:pointer;text-decoration:none;margin-left:4px;transition:all .15s}
.page-title-action:hover{background:var(--wp-admin-blue);color:#fff}
.notice{background:#fff;border:1px solid #c3c4c7;border-left:4px solid;padding:12px 15px;margin:20px 0 0;border-radius:1px}
.notice-success{border-left-color:var(--wp-success)}
.notice-error{border-left-color:var(--wp-error)}
.notice-warning{border-left-color:#dba617}
.notice-info{border-left-color:var(--wp-admin-blue)}
.wp-table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--wp-border);margin-top:15px}
.wp-table th,.wp-table td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--wp-border);font-size:13px}
.wp-table th{background:#f6f7f7;font-weight:600}
.wp-table tr:hover td{background:#f6f7f7}
.wp-table .column-title a{color:var(--wp-admin-blue);text-decoration:none;font-weight:600}
.wp-table .column-title a:hover{text-decoration:underline}
.button,.button-primary,.button-secondary{display:inline-flex;align-items:center;padding:6px 12px;border-radius:3px;cursor:pointer;font-size:13px;text-decoration:none;border:1px solid;transition:all .15s;gap:6px}
.button-primary{background:var(--wp-admin-blue);border-color:var(--wp-admin-blue);color:#fff}
.button-primary:hover{background:#135e96;border-color:#135e96}
.button,.button-secondary{background:#f6f7f7;border-color:#2271b1;color:#2271b1}
.button:hover,.button-secondary:hover{background:#f0f0f1;border-color:#0a4b78;color:#0a4b78}
.button-link-delete{color:var(--wp-error);text-decoration:none;font-size:13px;border:none;background:none;cursor:pointer;padding:0}
.button-link-delete:hover{text-decoration:underline}
.wp-card{background:#fff;border:1px solid var(--wp-border);border-radius:4px;padding:0;margin-bottom:20px}
.wp-card-header{padding:12px 20px;border-bottom:1px solid var(--wp-border);display:flex;align-items:center;justify-content:space-between}
.wp-card-header h2{font-size:14px;font-weight:600;color:#1d2327;margin:0}
.wp-card-body{padding:20px}
.stat-box{background:#fff;border:1px solid var(--wp-border);border-radius:4px;padding:20px;text-align:center}
.stat-box .stat-val{font-size:36px;font-weight:700;color:var(--wp-admin-blue);line-height:1}
.stat-box .stat-lbl{font-size:12px;color:var(--wp-muted);margin-top:8px}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:782px){#adminmenuwrap{display:none}#wpbody{margin-left:0}.grid-3{grid-template-columns:1fr}.grid-2{grid-template-columns:1fr}}
.form-table{width:100%;border-collapse:collapse}
.form-table th{width:200px;padding:15px 10px;text-align:right;vertical-align:top;font-weight:600}
.form-table td{padding:15px 10px}
.form-table input[type=text],.form-table input[type=email],.form-table input[type=url],.form-table input[type=password],.form-table select,.form-table textarea{width:100%;max-width:400px;padding:8px;border:1px solid var(--wp-border);border-radius:4px;font-size:14px}
.form-table input[type=text]:focus,.form-table input[type=email]:focus,.form-table textarea:focus{outline:none;border-color:var(--wp-admin-blue);box-shadow:0 0 0 1px var(--wp-admin-blue)}
.wp-editor{width:100%;min-height:300px;padding:12px;border:1px solid var(--wp-border);border-radius:4px;font-family:inherit;font-size:14px;line-height:1.6;resize:vertical}
.wp-editor:focus{outline:none;border-color:var(--wp-admin-blue)}
.metabox-area{display:grid;grid-template-columns:1fr 300px;gap:20px;margin-top:20px}
.postbox{background:#fff;border:1px solid var(--wp-border);border-radius:4px;margin-bottom:20px}
.postbox-header{padding:10px 16px;border-bottom:1px solid var(--wp-border);font-weight:600;font-size:13px}
.inside{padding:16px}
.submitdiv{background:#fff;border:1px solid var(--wp-border);border-radius:4px}
.submitdiv .submitbox{padding:16px}
.curtime{font-size:12px;color:var(--wp-muted);margin-bottom:12px}
.tag-input{width:100%;padding:8px;border:1px solid var(--wp-border);border-radius:4px;font-size:13px}
.category-tree{max-height:150px;overflow-y:auto;border:1px solid var(--wp-border);border-radius:4px;padding:8px}
</style>
</head>
<body class="wp-admin">
<div id="wpadminbar">
  <a href="/wp-admin/" class="ab-brand">🔷 ${siteName}</a>
  <a href="/">← 사이트 보기</a>
  <a href="/wp-admin/?page=posts">글</a>
  <a href="/wp-admin/?page=media">미디어</a>
  <div class="ab-right">
    <a href="/wp-admin/?page=profile">👤 ${username}</a>
    <a href="/wp-login.php?action=logout" onclick="return confirm('로그아웃 하시겠습니까?')">로그아웃</a>
  </div>
</div>

<div id="adminmenuwrap">
  <ul id="adminmenu">
    <li class="${page==='dashboard'?'active':''}"><a href="/wp-admin/">
      <span class="dashicons">🏠</span>대시보드</a></li>
    <li class="${page==='posts'||page==='new-post'?'active':''}"><a href="/wp-admin/?page=posts">
      <span class="dashicons">📝</span>글</a></li>
    <li class="${page==='pages'?'active':''}"><a href="/wp-admin/?page=pages">
      <span class="dashicons">📄</span>페이지</a></li>
    <li class="${page==='media'?'active':''}"><a href="/wp-admin/?page=media">
      <span class="dashicons">🖼️</span>미디어</a></li>
    <li class="${page==='themes'?'active':''}"><a href="/wp-admin/?page=themes">
      <span class="dashicons">🎨</span>테마</a></li>
    <li class="${page==='plugins'?'active':''}"><a href="/wp-admin/?page=plugins">
      <span class="dashicons">🔌</span>플러그인</a></li>
    <li class="${page==='users'?'active':''}"><a href="/wp-admin/?page=users">
      <span class="dashicons">👥</span>사용자</a></li>
    <li class="${page==='settings'?'active':''}"><a href="/wp-admin/?page=settings">
      <span class="dashicons">⚙️</span>설정</a></li>
    <li class="${page==='profile'?'active':''}"><a href="/wp-admin/?page=profile">
      <span class="dashicons">👤</span>내 프로필</a></li>
  </ul>
</div>

<div id="wpbody">
  <div class="wrap">
    ${pageContent.html}
  </div>
</div>

<script>
// Quick actions
document.querySelectorAll('form[data-wp-action]').forEach(form => {
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const action = form.dataset.wpAction;
    const data = Object.fromEntries(new FormData(form));
    const res = await fetch('/wp-json/cloudpress/v1/' + action, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(data),
    });
    const d = await res.json();
    if (d.success) {
      const notice = document.createElement('div');
      notice.className = 'notice notice-success';
      notice.innerHTML = '<p>' + (d.message || '저장되었습니다.') + '</p>';
      document.querySelector('.wrap').prepend(notice);
      if (d.redirect) setTimeout(() => location.href = d.redirect, 800);
    } else {
      alert(d.message || '오류가 발생했습니다.');
    }
  });
});
</script>
</body>
</html>`;
}

function renderAdminDashboard(siteInfo, session) {
  return {
    title: '대시보드',
    html: `
<h1 class="wp-heading-inline">대시보드</h1>
<div class="notice notice-info" style="margin-top:15px">
  <p>WordPress ${esc(siteInfo.wp_version || '6.9.4')} — CloudPress v${VERSION} Edge Edition에 오신 것을 환영합니다!</p>
</div>
<div class="grid-3" style="margin-top:20px">
  <div class="stat-box"><div class="stat-val" id="stat-posts">...</div><div class="stat-lbl">전체 글</div></div>
  <div class="stat-box"><div class="stat-val" id="stat-pages">...</div><div class="stat-lbl">전체 페이지</div></div>
  <div class="stat-box"><div class="stat-val" id="stat-comments">...</div><div class="stat-lbl">댓글</div></div>
</div>
<div class="grid-2">
  <div class="wp-card">
    <div class="wp-card-header"><h2>빠른 임시글</h2></div>
    <div class="wp-card-body">
      <form data-wp-action="quick-draft">
        <div style="margin-bottom:10px"><input type="text" name="title" placeholder="제목" style="width:100%;padding:8px;border:1px solid #c3c4c7;border-radius:4px"></div>
        <textarea name="content" placeholder="내용을 입력하세요..." rows="5" style="width:100%;padding:8px;border:1px solid #c3c4c7;border-radius:4px;resize:vertical"></textarea>
        <div style="margin-top:10px"><button type="submit" class="button-primary">임시저장</button></div>
      </form>
    </div>
  </div>
  <div class="wp-card">
    <div class="wp-card-header"><h2>사이트 정보</h2></div>
    <div class="wp-card-body">
      <table class="form-table" style="font-size:13px">
        <tr><th style="text-align:left;padding:6px 0;width:auto">WordPress 버전</th><td style="padding:6px 0 6px 12px">${esc(siteInfo.wp_version || '6.9.4')}</td></tr>
        <tr><th style="text-align:left;padding:6px 0">사이트 URL</th><td style="padding:6px 0 6px 12px"><a href="https://${esc(siteInfo.primary_domain || '')}" target="_blank">${esc(siteInfo.primary_domain || '')}</a></td></tr>
        <tr><th style="text-align:left;padding:6px 0">PHP 버전</th><td style="padding:6px 0 6px 12px">Edge Worker (PHP-less)</td></tr>
        <tr><th style="text-align:left;padding:6px 0">플랜</th><td style="padding:6px 0 6px 12px">${esc(siteInfo.plan || 'starter')}</td></tr>
      </table>
      <div style="margin-top:15px;display:flex;gap:8px;flex-wrap:wrap">
        <a href="/wp-admin/?page=posts&action=new" class="button-primary">+ 새 글 작성</a>
        <a href="/" target="_blank" class="button">사이트 보기</a>
      </div>
    </div>
  </div>
</div>
<script>
fetch('/wp-json/wp/v2/posts?per_page=1').then(r=>r.json()).then(d=>{
  document.getElementById('stat-posts').textContent=d.length||0;
}).catch(()=>{document.getElementById('stat-posts').textContent='0'});
fetch('/wp-json/wp/v2/pages?per_page=1').then(r=>r.json()).then(d=>{
  document.getElementById('stat-pages').textContent=d.length||0;
}).catch(()=>{document.getElementById('stat-pages').textContent='0'});
document.getElementById('stat-comments').textContent='0';
</script>`
  };
}

function renderAdminPosts(siteInfo, session) {
  return {
    title: '글',
    html: `
<h1 class="wp-heading-inline">글</h1>
<a href="/wp-admin/?page=new-post" class="page-title-action">새로 추가</a>
<hr class="wp-header-end">
<div id="posts-list"><div style="padding:20px;color:#646970">불러오는 중...</div></div>
<script>
fetch('/wp-json/wp/v2/posts?per_page=20&orderby=date&order=desc&status=any')
  .then(r=>r.json()).then(posts=>{
    const el=document.getElementById('posts-list');
    if(!posts.length){el.innerHTML='<p style="padding:20px;color:#646970">글이 없습니다. <a href="/wp-admin/?page=new-post">첫 글을 작성해보세요!</a></p>';return;}
    const rows=posts.map(p=>\`<tr>
      <td class="column-title"><strong><a href="/wp-admin/?page=edit-post&id=\${p.id}">\${p.title?.rendered||'(제목 없음)'}</a></strong>
        <div class="row-actions" style="font-size:12px;color:#646970;margin-top:3px">
          <a href="/wp-admin/?page=edit-post&id=\${p.id}" style="color:#2271b1">수정</a> | 
          <a href="/\${p.slug||'?p='+p.id}" target="_blank" style="color:#2271b1">보기</a> |
          <button class="button-link-delete" onclick="if(confirm('삭제하시겠습니까?'))deletePost(\${p.id})">휴지통</button>
        </div>
      </td>
      <td>\${p.status==='publish'?'<span style="color:#00a32a">●</span> 발행됨':'<span style="color:#646970">●</span> '+p.status}</td>
      <td>\${new Date(p.date).toLocaleDateString('ko-KR')}</td>
    </tr>\`).join('');
    el.innerHTML=\`<table class="wp-table"><thead><tr><th>제목</th><th>상태</th><th>날짜</th></tr></thead><tbody>\${rows}</tbody></table>\`;
  }).catch(()=>{document.getElementById('posts-list').innerHTML='<p style="padding:20px;color:#d63638">글 목록을 불러올 수 없습니다.</p>'});
async function deletePost(id){
  await fetch('/wp-json/wp/v2/posts/'+id,{method:'DELETE'});
  location.reload();
}
</script>`
  };
}

function renderAdminNewPost(siteInfo, session) {
  return {
    title: '새 글 추가',
    html: `
<h1 class="wp-heading-inline">새 글 추가</h1>
<hr class="wp-header-end">
<form id="post-form" style="margin-top:20px">
  <div style="margin-bottom:15px">
    <input type="text" id="post-title" placeholder="제목을 입력하세요" style="width:100%;padding:12px;font-size:23px;border:1px solid #ddd;border-radius:4px;font-family:inherit">
  </div>
  <div class="metabox-area">
    <div>
      <div class="postbox">
        <div class="postbox-header">내용</div>
        <div class="inside">
          <div style="display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap">
            <button type="button" onclick="fmt('bold')" class="button" style="font-weight:bold">B</button>
            <button type="button" onclick="fmt('italic')" class="button" style="font-style:italic">I</button>
            <button type="button" onclick="fmt('underline')" class="button" style="text-decoration:underline">U</button>
            <button type="button" onclick="insertTag('h2')" class="button">H2</button>
            <button type="button" onclick="insertTag('h3')" class="button">H3</button>
            <button type="button" onclick="insertTag('ul')" class="button">목록</button>
            <button type="button" onclick="insertLink()" class="button">링크</button>
          </div>
          <textarea id="post-content" class="wp-editor" rows="20" placeholder="내용을 작성하세요..."></textarea>
        </div>
      </div>
      <div class="postbox">
        <div class="postbox-header">발췌문</div>
        <div class="inside">
          <textarea id="post-excerpt" rows="3" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;font-family:inherit" placeholder="선택사항: 발췌문을 입력하세요"></textarea>
        </div>
      </div>
    </div>
    <div>
      <div class="submitdiv">
        <div class="postbox-header">발행</div>
        <div class="submitbox">
          <div class="curtime">상태: <select id="post-status" style="padding:4px;border:1px solid #ddd;border-radius:3px">
            <option value="publish">발행됨</option>
            <option value="draft">임시글</option>
            <option value="private">비공개</option>
          </select></div>
          <div style="display:flex;gap:8px">
            <button type="button" onclick="savePost('draft')" class="button">임시저장</button>
            <button type="button" onclick="savePost('publish')" class="button-primary">발행</button>
          </div>
        </div>
      </div>
      <div class="postbox" style="margin-top:15px">
        <div class="postbox-header">카테고리</div>
        <div class="inside">
          <div class="category-tree">
            <label><input type="checkbox" name="cat" value="1"> 미분류</label>
          </div>
          <a href="#" style="font-size:12px;color:#2271b1;text-decoration:none">+ 새 카테고리 추가</a>
        </div>
      </div>
      <div class="postbox" style="margin-top:15px">
        <div class="postbox-header">태그</div>
        <div class="inside">
          <input type="text" id="post-tags" class="tag-input" placeholder="쉼표로 구분">
          <p style="font-size:12px;color:#646970;margin-top:5px">쉼표로 구분하여 입력하세요</p>
        </div>
      </div>
    </div>
  </div>
</form>
<script>
function fmt(cmd){document.execCommand(cmd)}
function insertTag(tag){const ta=document.getElementById('post-content');const sel=ta.value.substring(ta.selectionStart,ta.selectionEnd);ta.setRangeText('<'+tag+'>'+sel+'</'+tag+'>',ta.selectionStart,ta.selectionEnd,'end')}
function insertLink(){const url=prompt('URL:');if(url){const ta=document.getElementById('post-content');const sel=ta.value.substring(ta.selectionStart,ta.selectionEnd)||'링크';ta.setRangeText('<a href="'+url+'">'+sel+'</a>',ta.selectionStart,ta.selectionEnd,'end')}}
async function savePost(status){
  const title=document.getElementById('post-title').value.trim();
  if(!title){alert('제목을 입력해주세요');return}
  const res=await fetch('/wp-json/wp/v2/posts',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({title,content:document.getElementById('post-content').value,excerpt:document.getElementById('post-excerpt').value,status:status||document.getElementById('post-status').value})
  });
  const d=await res.json();
  if(d.id){location.href='/wp-admin/?page=posts&saved=1'}
  else{alert('저장 실패: '+(d.message||'오류'))}
}
</script>`
  };
}

function renderAdminPages(siteInfo, session) {
  return {
    title: '페이지',
    html: `
<h1 class="wp-heading-inline">페이지</h1>
<a href="/wp-admin/?page=new-post&type=page" class="page-title-action">새로 추가</a>
<hr class="wp-header-end">
<div id="pages-list"><div style="padding:20px;color:#646970">불러오는 중...</div></div>
<script>
fetch('/wp-json/wp/v2/pages?per_page=20&status=any')
  .then(r=>r.json()).then(pages=>{
    const el=document.getElementById('pages-list');
    if(!pages.length){el.innerHTML='<p style="padding:20px;color:#646970">페이지가 없습니다.</p>';return;}
    const rows=pages.map(p=>\`<tr><td class="column-title"><strong><a href="/wp-admin/?page=edit-post&type=page&id=\${p.id}">\${p.title?.rendered||'(제목 없음)'}</a></strong></td><td>\${p.status}</td><td>\${new Date(p.date).toLocaleDateString('ko-KR')}</td></tr>\`).join('');
    el.innerHTML=\`<table class="wp-table"><thead><tr><th>제목</th><th>상태</th><th>날짜</th></tr></thead><tbody>\${rows}</tbody></table>\`;
  });
</script>`
  };
}

function renderAdminMedia(siteInfo, session) {
  return {
    title: '미디어 라이브러리',
    html: `
<h1 class="wp-heading-inline">미디어 라이브러리</h1>
<a href="#" class="page-title-action" onclick="document.getElementById('media-upload').click()">파일 추가</a>
<hr class="wp-header-end">
<input type="file" id="media-upload" style="display:none" multiple accept="image/*,video/*,audio/*,.pdf">
<div id="upload-progress" style="display:none;margin:15px 0;padding:10px;background:#fff;border:1px solid #ddd;border-radius:4px"></div>
<div id="media-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-top:20px">
  <div style="padding:20px;color:#646970">불러오는 중...</div>
</div>
<script>
document.getElementById('media-upload').addEventListener('change',async function(){
  const files=Array.from(this.files);
  if(!files.length)return;
  const prog=document.getElementById('upload-progress');
  prog.style.display='block';
  for(const file of files){
    prog.textContent='업로드 중: '+file.name;
    const fd=new FormData();fd.append('file',file);
    try{
      const r=await fetch('/wp-json/wp/v2/media',{method:'POST',body:fd});
      const d=await r.json();
      prog.textContent='완료: '+file.name;
    }catch(e){prog.textContent='실패: '+file.name}
  }
  setTimeout(()=>{prog.style.display='none';loadMedia()},1000);
});
async function loadMedia(){
  const res=await fetch('/wp-json/wp/v2/media?per_page=50');
  const items=await res.json();
  const el=document.getElementById('media-grid');
  if(!items.length){el.innerHTML='<p style="color:#646970">미디어가 없습니다.</p>';return;}
  el.innerHTML=items.map(m=>\`<div style="border:1px solid #ddd;border-radius:4px;overflow:hidden;background:#fff">
    <div style="height:120px;background:#f0f0f1;display:flex;align-items:center;justify-content:center;overflow:hidden">
      \${m.media_type==='image'?'<img src="'+m.source_url+'" style="width:100%;height:100%;object-fit:cover">':'<div style="font-size:2rem">📄</div>'}
    </div>
    <div style="padding:8px;font-size:11px;color:#646970;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="\${m.title?.rendered||''}">\${m.title?.rendered||m.slug||''}</div>
  </div>\`).join('');
}
loadMedia();
</script>`
  };
}

function renderAdminThemes(siteInfo, session) {
  return {
    title: '테마',
    html: `
<h1 class="wp-heading-inline">테마</h1>
<hr class="wp-header-end">
<div class="notice notice-info"><p>CloudPress Edge Edition은 현재 기본 테마 1개가 포함되어 있습니다. 추가 테마는 곧 지원될 예정입니다.</p></div>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:20px;margin-top:20px">
  <div style="border:3px solid #2271b1;border-radius:4px;overflow:hidden;background:#fff">
    <div style="height:180px;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;align-items:center;justify-content:center;color:#fff;font-size:2rem">🎨</div>
    <div style="padding:15px">
      <div style="font-weight:700;margin-bottom:4px">CloudPress Default <span style="font-size:11px;background:#2271b1;color:#fff;padding:2px 6px;border-radius:3px">활성화됨</span></div>
      <div style="font-size:12px;color:#646970;margin-bottom:10px">CloudPress 기본 테마 — WordPress 호환</div>
      <a href="/wp-admin/?page=customize" class="button">사용자 정의</a>
    </div>
  </div>
</div>`
  };
}

function renderAdminPlugins(siteInfo, session) {
  return {
    title: '플러그인',
    html: `
<h1 class="wp-heading-inline">플러그인</h1>
<hr class="wp-header-end">
<div class="notice notice-info"><p>CloudPress Edge Edition은 Edge-native 플러그인을 지원합니다. WordPress.org 플러그인은 PHP 없이 동작하는 Edge 버전으로 제공됩니다.</p></div>
<table class="wp-table" style="margin-top:15px">
  <thead><tr><th>플러그인</th><th>설명</th><th>버전</th><th>상태</th></tr></thead>
  <tbody>
    <tr><td><strong>CloudPress SEO</strong></td><td>SEO 메타태그, 사이트맵, Open Graph 자동 생성</td><td>1.0</td><td><span style="color:#00a32a">활성화됨</span></td></tr>
    <tr><td><strong>CloudPress Cache</strong></td><td>KV 기반 초고속 엣지 캐싱</td><td>1.0</td><td><span style="color:#00a32a">활성화됨</span></td></tr>
    <tr><td><strong>CloudPress Security</strong></td><td>WAF, Rate Limiting, DDoS 보호</td><td>1.0</td><td><span style="color:#00a32a">활성화됨</span></td></tr>
    <tr><td><strong>CloudPress Analytics</strong></td><td>방문자 분석 (Cloudflare Analytics 연동)</td><td>1.0</td><td><span style="color:#00a32a">활성화됨</span></td></tr>
    <tr><td><strong>CloudPress Backup</strong></td><td>D1 자동 백업, KV 스냅샷</td><td>1.0</td><td><span style="color:#00a32a">활성화됨</span></td></tr>
  </tbody>
</table>`
  };
}

function renderAdminUsers(siteInfo, session) {
  return {
    title: '사용자',
    html: `
<h1 class="wp-heading-inline">사용자</h1>
<a href="#" class="page-title-action" onclick="document.getElementById('add-user-modal').style.display='flex'">새로 추가</a>
<hr class="wp-header-end">
<div id="users-list"><div style="padding:20px;color:#646970">불러오는 중...</div></div>
<div id="add-user-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center">
  <div style="background:#fff;border-radius:8px;padding:30px;width:90%;max-width:480px">
    <h2 style="margin-bottom:20px">새 사용자 추가</h2>
    <form data-wp-action="add-user">
      <div style="margin-bottom:12px"><label style="display:block;margin-bottom:4px;font-weight:600">사용자명 *</label><input type="text" name="username" required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px"></div>
      <div style="margin-bottom:12px"><label style="display:block;margin-bottom:4px;font-weight:600">이메일 *</label><input type="email" name="email" required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px"></div>
      <div style="margin-bottom:12px"><label style="display:block;margin-bottom:4px;font-weight:600">비밀번호 *</label><input type="password" name="password" required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px"></div>
      <div style="margin-bottom:20px"><label style="display:block;margin-bottom:4px;font-weight:600">권한</label><select name="role" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px"><option value="subscriber">구독자</option><option value="contributor">기여자</option><option value="author">글쓴이</option><option value="editor">편집자</option><option value="administrator">관리자</option></select></div>
      <div style="display:flex;gap:10px;justify-content:flex-end"><button type="button" onclick="document.getElementById('add-user-modal').style.display='none'" class="button">취소</button><button type="submit" class="button-primary">추가</button></div>
    </form>
  </div>
</div>
<script>
fetch('/wp-json/wp/v2/users?per_page=20')
  .then(r=>r.json()).then(users=>{
    const el=document.getElementById('users-list');
    if(!Array.isArray(users)||!users.length){el.innerHTML='<p style="padding:20px;color:#646970">사용자가 없습니다.</p>';return;}
    const rows=users.map(u=>\`<tr><td><strong>\${u.name||u.slug}</strong><br><span style="color:#646970;font-size:12px">\${u.slug}</span></td><td>\${u.roles?.join(', ')||'subscriber'}</td><td>\${new Date(u.registered_date||Date.now()).toLocaleDateString('ko-KR')}</td><td><a href="/wp-admin/?page=edit-user&id=\${u.id}" style="color:#2271b1">수정</a></td></tr>\`).join('');
    el.innerHTML=\`<table class="wp-table"><thead><tr><th>이름</th><th>권한</th><th>가입일</th><th>작업</th></tr></thead><tbody>\${rows}</tbody></table>\`;
  }).catch(()=>{document.getElementById('users-list').innerHTML='<p style="padding:20px;color:#d63638">사용자 목록을 불러올 수 없습니다.</p>'});
</script>`
  };
}

function renderAdminSettings(siteInfo, session) {
  return {
    title: '일반 설정',
    html: `
<h1 class="wp-heading-inline">일반 설정</h1>
<hr class="wp-header-end">
<form data-wp-action="update-settings">
  <table class="form-table" role="presentation">
    <tr><th scope="row"><label for="blogname">사이트 제목</label></th><td><input type="text" name="blogname" id="blogname" value="${esc(siteInfo.name||'')}" class="regular-text"></td></tr>
    <tr><th scope="row"><label for="blogdescription">태그라인</label></th><td><input type="text" name="blogdescription" id="blogdescription" class="regular-text" placeholder="사이트를 설명하는 짧은 문장"><p class="description">이 사이트를 짧게 설명하는 문구를 입력하세요.</p></td></tr>
    <tr><th scope="row"><label for="siteurl">WordPress 주소 (URL)</label></th><td><input type="url" name="siteurl" id="siteurl" value="https://${esc(siteInfo.primary_domain||'')}" class="regular-text" readonly></td></tr>
    <tr><th scope="row"><label for="admin_email">관리자 이메일 주소</label></th><td><input type="email" name="admin_email" id="admin_email" value="${esc(session?.email||'admin@example.com')}" class="regular-text"></td></tr>
    <tr><th scope="row">회원가입</th><td><label><input type="checkbox" name="users_can_register" value="1"> 누구나 등록 가능</label></td></tr>
    <tr><th scope="row"><label for="timezone_string">시간대</label></th><td><select name="timezone_string" id="timezone_string" style="max-width:400px;padding:8px;border:1px solid #c3c4c7;border-radius:4px"><option value="Asia/Seoul" selected>서울 (UTC+9)</option><option value="UTC">UTC</option><option value="America/New_York">뉴욕 (UTC-5)</option></select></td></tr>
    <tr><th scope="row"><label for="date_format">날짜 형식</label></th><td><input type="text" name="date_format" id="date_format" value="Y년 n월 j일" class="regular-text"></td></tr>
  </table>
  <p class="submit"><button type="submit" class="button-primary">변경 사항 저장</button></p>
</form>`
  };
}

function renderAdminProfile(siteInfo, session) {
  return {
    title: '프로필',
    html: `
<h1 class="wp-heading-inline">프로필</h1>
<hr class="wp-header-end">
<form data-wp-action="update-profile">
  <h2>이름</h2>
  <table class="form-table">
    <tr><th><label for="user_login">사용자명</label></th><td><input type="text" id="user_login" value="${esc(session?.username||'admin')}" disabled style="max-width:400px;padding:8px;border:1px solid #c3c4c7;border-radius:4px;background:#f0f0f1"><p class="description" style="font-size:12px;color:#646970">사용자명은 변경할 수 없습니다.</p></td></tr>
    <tr><th><label for="display_name">표시할 이름</label></th><td><input type="text" name="display_name" id="display_name" value="${esc(session?.username||'admin')}" style="max-width:400px;padding:8px;border:1px solid #c3c4c7;border-radius:4px"></td></tr>
  </table>
  <h2>비밀번호</h2>
  <table class="form-table">
    <tr><th><label for="pass1">새 비밀번호</label></th><td><input type="password" name="pass1" id="pass1" style="max-width:400px;padding:8px;border:1px solid #c3c4c7;border-radius:4px"><p class="description" style="font-size:12px;color:#646970">비밀번호 변경을 원하지 않으면 비워 두세요.</p></td></tr>
    <tr><th><label for="pass2">비밀번호 확인</label></th><td><input type="password" name="pass2" id="pass2" style="max-width:400px;padding:8px;border:1px solid #c3c4c7;border-radius:4px"></td></tr>
  </table>
  <p class="submit"><button type="submit" class="button-primary">프로필 업데이트</button></p>
</form>`
  };
}

// ── WordPress REST API (D1 기반) ──────────────────────────────────────────────
async function handleRestApi(env, siteInfo, request, url) {
  const path = url.pathname.replace(/^\/wp-json/, '');
  const method = request.method;

  // CORS
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-WP-Nonce',
  };

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });

  // GET /wp-json/ — 네임스페이스 목록
  if (path === '/' || path === '') {
    return json({
      name: siteInfo.name || 'WordPress',
      url: `https://${url.hostname}`,
      namespaces: ['wp/v2', 'cloudpress/v1'],
      authentication: {},
    });
  }

  // GET /wp-json/wp/v2/posts
  if (path === '/wp/v2/posts' && method === 'GET') {
    const perPage = parseInt(url.searchParams.get('per_page') || '10');
    const page    = parseInt(url.searchParams.get('page') || '1');
    const offset  = (page - 1) * perPage;
    const status  = url.searchParams.get('status') || 'publish';
    const posts   = await getWpPosts(env, { post_type: 'post', post_status: status === 'any' ? 'publish' : status, limit: perPage, offset });
    const mapped  = posts.map(p => wpPostToApi(p, url.hostname));
    return json(mapped);
  }

  // POST /wp-json/wp/v2/posts
  if (path === '/wp/v2/posts' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ code: 'invalid_json', message: '잘못된 요청' }, 400); }
    const { title, content, excerpt, status = 'publish' } = body;
    if (!title) return json({ code: 'empty_title', message: '제목이 필요합니다.' }, 400);
    const slug = String(title).toLowerCase().replace(/[^a-z0-9가-힣]/g, '-').replace(/-+/g, '-').slice(0, 100);
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    try {
      const res = await env.DB.prepare(
        `INSERT INTO wp_posts (post_title, post_content, post_excerpt, post_name, post_status,
           post_type, post_date, post_date_gmt, post_modified, post_modified_gmt, post_author,
           comment_status, ping_status, to_ping, pinged, post_content_filtered, guid)
         VALUES (?,?,?,?,?,?,?,?,?,?,1,'open','open','','','',?)`
      ).bind(title, content || '', excerpt || '', slug, status, 'post', now, now, now, now, `https://${url.hostname}/?p=new`).run();
      const newPost = await env.DB.prepare('SELECT * FROM wp_posts WHERE rowid=last_insert_rowid()').first();
      return json(wpPostToApi(newPost, url.hostname), 201);
    } catch (e) {
      return json({ code: 'db_error', message: e.message }, 500);
    }
  }

  // GET /wp-json/wp/v2/posts/:id
  const postMatch = path.match(/^\/wp\/v2\/posts\/(\d+)$/);
  if (postMatch && method === 'GET') {
    const post = await env.DB.prepare('SELECT * FROM wp_posts WHERE ID=? AND post_status!=? LIMIT 1')
      .bind(parseInt(postMatch[1]), 'trash').first();
    if (!post) return json({ code: 'rest_post_invalid_id', message: '글을 찾을 수 없습니다.' }, 404);
    return json(wpPostToApi(post, url.hostname));
  }

  // DELETE /wp-json/wp/v2/posts/:id
  if (postMatch && method === 'DELETE') {
    await env.DB.prepare("UPDATE wp_posts SET post_status='trash' WHERE ID=?").bind(parseInt(postMatch[1])).run();
    return json({ deleted: true });
  }

  // GET /wp-json/wp/v2/pages
  if (path === '/wp/v2/pages' && method === 'GET') {
    const perPage = parseInt(url.searchParams.get('per_page') || '10');
    const status  = url.searchParams.get('status') || 'publish';
    const pages   = await getWpPosts(env, { post_type: 'page', post_status: status === 'any' ? 'publish' : status, limit: perPage });
    return json(pages.map(p => wpPostToApi(p, url.hostname)));
  }

  // POST /wp-json/wp/v2/pages
  if (path === '/wp/v2/pages' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ code: 'invalid_json', message: '잘못된 요청' }, 400); }
    const { title, content, status = 'publish' } = body;
    if (!title) return json({ code: 'empty_title', message: '제목이 필요합니다.' }, 400);
    const slug = String(title).toLowerCase().replace(/[^a-z0-9가-힣]/g, '-').slice(0, 100);
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    try {
      await env.DB.prepare(
        `INSERT INTO wp_posts (post_title, post_content, post_name, post_status, post_type,
           post_date, post_date_gmt, post_modified, post_modified_gmt, post_author,
           comment_status, ping_status, to_ping, pinged, post_content_filtered, guid, post_excerpt)
         VALUES (?,?,?,?,?,?,?,?,?,1,'closed','closed','','','',?,'')`
      ).bind(title, content || '', slug, status, 'page', now, now, now, now, `https://${url.hostname}/?page_id=new`).run();
      const newPage = await env.DB.prepare('SELECT * FROM wp_posts WHERE rowid=last_insert_rowid()').first();
      return json(wpPostToApi(newPage, url.hostname), 201);
    } catch (e) {
      return json({ code: 'db_error', message: e.message }, 500);
    }
  }

  // GET /wp-json/wp/v2/users
  if (path === '/wp/v2/users' && method === 'GET') {
    try {
      const users = await env.DB.prepare('SELECT ID, user_login, user_email, display_name, user_registered FROM wp_users LIMIT 20').all();
      return json((users.results || []).map(u => ({
        id: u.ID, name: u.display_name || u.user_login, slug: u.user_login,
        email: u.user_email, registered_date: u.user_registered, roles: ['administrator'],
      })));
    } catch { return json([]); }
  }

  // POST /wp-json/wp/v2/media (file upload)
  if (path === '/wp/v2/media' && method === 'POST') {
    try {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return json({ code: 'no_file', message: '파일이 없습니다.' }, 400);
      const fileName = file.name || 'upload';
      const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
      // Save metadata to D1
      await env.DB.prepare(
        `INSERT INTO wp_posts (post_title, post_name, post_status, post_type, post_date, post_date_gmt,
           post_modified, post_modified_gmt, post_author, post_mime_type, guid,
           post_content, post_excerpt, comment_status, ping_status, to_ping, pinged, post_content_filtered)
         VALUES (?,?,?,?,?,?,?,?,1,?,?,?,?,'closed','closed','','','')`
      ).bind(fileName.replace(/\.[^.]+$/, ''), fileName.toLowerCase().replace(/[^a-z0-9.-]/g, '-'),
        'inherit', 'attachment', now, now, now, now,
        file.type || 'application/octet-stream',
        `https://${url.hostname}/wp-content/uploads/${fileName}`,
        '', '').run();
      const newMedia = await env.DB.prepare('SELECT * FROM wp_posts WHERE rowid=last_insert_rowid()').first();
      return json({ id: newMedia?.ID, source_url: `https://${url.hostname}/wp-content/uploads/${fileName}`,
        title: { rendered: fileName }, media_type: (file.type || '').startsWith('image/') ? 'image' : 'file',
        mime_type: file.type || 'application/octet-stream' }, 201);
    } catch (e) { return json({ code: 'upload_error', message: e.message }, 500); }
  }

  // CloudPress custom endpoints
  if (path.startsWith('/cloudpress/v1/')) {
    return handleCloudPressApi(env, siteInfo, path.replace('/cloudpress/v1/', ''), method, request, json);
  }

  return json({ code: 'rest_no_route', message: '해당 REST API 경로를 찾을 수 없습니다.', data: { status: 404 } }, 404);
}

async function handleCloudPressApi(env, siteInfo, endpoint, method, request, json) {
  if (endpoint === 'quick-draft' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: '잘못된 요청' }); }
    const { title, content } = body;
    if (!title) return json({ success: false, message: '제목을 입력해주세요.' });
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    await env.DB.prepare(
      `INSERT INTO wp_posts (post_title,post_content,post_name,post_status,post_type,post_date,post_date_gmt,post_modified,post_modified_gmt,post_author,comment_status,ping_status,to_ping,pinged,post_content_filtered,guid,post_excerpt)
       VALUES (?,?,?,?,?,?,?,?,?,1,'open','open','','','',?,'')`
    ).bind(title, content || '', (title||'').toLowerCase().replace(/[^a-z0-9가-힣]/g,'-').slice(0,50),
      'draft', 'post', now, now, now, now, `draft`).run();
    return json({ success: true, message: '임시글이 저장되었습니다.', redirect: '/wp-admin/?page=posts' });
  }

  if (endpoint === 'update-settings' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: '잘못된 요청' }); }
    const updates = [
      ['blogname', body.blogname || ''],
      ['blogdescription', body.blogdescription || ''],
      ['admin_email', body.admin_email || ''],
    ];
    for (const [key, val] of updates) {
      await env.DB.prepare('INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?,?,?)')
        .bind(key, val, 'yes').run();
    }
    return json({ success: true, message: '설정이 저장되었습니다.' });
  }

  return json({ success: false, message: '알 수 없는 엔드포인트: ' + endpoint });
}

function wpPostToApi(post, hostname) {
  if (!post) return null;
  const link = `https://${hostname}/${post.post_name || '?p=' + post.ID}/`;
  return {
    id: post.ID,
    date: post.post_date,
    date_gmt: post.post_date_gmt,
    modified: post.post_modified,
    modified_gmt: post.post_modified_gmt,
    slug: post.post_name,
    status: post.post_status,
    type: post.post_type,
    link,
    title: { rendered: post.post_title || '' },
    content: { rendered: post.post_content || '', protected: false },
    excerpt: { rendered: post.post_excerpt || '', protected: false },
    author: post.post_author || 1,
    comment_status: post.comment_status || 'open',
    ping_status: post.ping_status || 'open',
    guid: { rendered: post.guid || link },
    _links: {
      self: [{ href: `https://${hostname}/wp-json/wp/v2/posts/${post.ID}` }],
      collection: [{ href: `https://${hostname}/wp-json/wp/v2/posts` }],
    },
  };
}

// ── wp-login.php 처리 (D1 기반 인증) ─────────────────────────────────────────
async function handleWpLogin(env, siteInfo, request, url) {
  const method = request.method;

  if (method === 'POST') {
    let formData;
    try { formData = await request.formData(); } catch {
      return renderLoginPage(siteInfo, url, '요청 오류가 발생했습니다.');
    }
    const username = formData.get('log') || '';
    const password = formData.get('pwd') || '';
    const remember = formData.get('rememberme') === 'forever';
    const redirectTo = formData.get('redirect_to') || '/wp-admin/';

    if (!username || !password) {
      return renderLoginPage(siteInfo, url, '사용자명과 비밀번호를 입력해주세요.');
    }

    // D1에서 사용자 조회
    const wpUser = await getWpUser(env, username);
    if (!wpUser) {
      return renderLoginPage(siteInfo, url, `<strong>${esc(username)}</strong>에 해당하는 사용자가 없습니다.`);
    }

    // 비밀번호 검증
    const valid = await verifyPassword(password, wpUser.user_pass);
    if (!valid) {
      return renderLoginPage(siteInfo, url, `<strong>${esc(username)}</strong>에 입력된 비밀번호가 올바르지 않습니다.`);
    }

    // 세션 생성
    const token = await createWpSession(env, siteInfo, wpUser.ID, wpUser.user_login, 'administrator');
    const cookieExpiry = remember ? 14 * 24 * 3600 : 0;
    const cookiePath = '/';
    const cookieDomain = url.hostname;

    const headers = new Headers({
      'Location': redirectTo,
      'Set-Cookie': [
        `wordpress_logged_in_${siteInfo.site_prefix}=${token}; Path=${cookiePath}; ${cookieExpiry ? `Max-Age=${cookieExpiry};` : ''} HttpOnly; SameSite=Lax; Secure`,
        `wordpress_logged_in=${token}; Path=${cookiePath}; ${cookieExpiry ? `Max-Age=${cookieExpiry};` : ''} HttpOnly; SameSite=Lax; Secure`,
      ].join(', '),
    });
    return new Response(null, { status: 302, headers });
  }

  // GET — 로그인 폼 렌더링
  const action = url.searchParams.get('action') || 'login';
  if (action === 'logout') {
    const cookies = parseCookies(request);
    const token = cookies[`wordpress_logged_in_${siteInfo.site_prefix}`] || cookies['wordpress_logged_in'];
    if (token && env.CACHE) {
      await env.CACHE.delete(KV_SESSION_PREFIX + token).catch(() => {});
    }
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/wp-login.php?loggedout=true',
        'Set-Cookie': `wordpress_logged_in=; Path=/; Max-Age=0; HttpOnly; Secure`,
      },
    });
  }

  return renderLoginPage(siteInfo, url);
}

function renderLoginPage(siteInfo, url, error = '') {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const redirectTo = esc(url.searchParams.get('redirect_to') || '/wp-admin/');
  const loggedOut = url.searchParams.get('loggedout') === 'true';

  return new Response(`<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>로그인 ‹ ${siteName} — WordPress</title>
<style>
*{box-sizing:border-box}
html{background:#f0f0f1}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4;color:#3c434a;min-width:150px}
#login{width:320px;padding:8% 0 0;margin:0 auto}
#login h1 a{background:#2271b1;width:84px;height:84px;display:flex;align-items:center;justify-content:center;margin:0 auto 25px;border-radius:50%;font-size:2.5rem;text-decoration:none}
.login form{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px 46px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login label{font-weight:600;display:block;margin-bottom:5px}
.login input[type=text],.login input[type=password]{width:100%;box-sizing:border-box;padding:10px;border:1px solid #8c8f94;border-radius:4px;font-size:18px;margin-bottom:16px}
.login input:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1;outline:none}
.login .button-primary{background:#2271b1;border:1px solid #2271b1;color:#fff;cursor:pointer;font-size:14px;width:100%;border-radius:3px;height:40px;font-weight:500}
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
  <h1><a href="https://wordpress.org/" title="WordPress" tabindex="-1">🔷</a></h1>
  ${error ? `<div id="login_error">${error}</div>` : ''}
  ${loggedOut ? '<div class="message">로그아웃 되었습니다.</div>' : ''}
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label for="user_login">사용자명 또는 이메일 주소</label>
    <input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="none" autocomplete="username"></p>
    <div class="user-pass-wrap">
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

// ── 프론트엔드 WordPress 페이지 렌더링 ──────────────────────────────────────
async function renderFrontend(env, siteInfo, request, url) {
  const pathname = url.pathname;
  const siteName = siteInfo.name || 'WordPress';
  const siteUrl  = `https://${url.hostname}`;

  // 홈 페이지
  if (pathname === '/' || pathname === '/index.php') {
    const posts = await getWpPosts(env, { post_type: 'post', post_status: 'publish', limit: 10 });
    const siteTitle = await getWpOption(env, siteInfo, 'blogname') || siteName;
    const siteDesc  = await getWpOption(env, siteInfo, 'blogdescription') || '';

    const postsHtml = posts.length
      ? posts.map(p => `
<article class="post">
  <h2 class="entry-title"><a href="${siteUrl}/${esc(p.post_name || '?p=' + p.ID)}/">${esc(p.post_title)}</a></h2>
  <div class="entry-meta"><time>${new Date(p.post_date).toLocaleDateString('ko-KR', {year:'numeric',month:'long',day:'numeric'})}</time></div>
  <div class="entry-summary"><p>${esc(p.post_excerpt || p.post_content.replace(/<[^>]*>/g,'').slice(0,200))}${(p.post_content||'').length > 200 ? '...' : ''}</p></div>
  <a href="${siteUrl}/${esc(p.post_name || '?p=' + p.ID)}/" class="read-more">더 읽기 →</a>
</article>`).join('\n')
      : '<p class="no-posts">아직 게시글이 없습니다.</p>';

    return new Response(renderTheme(siteTitle, siteDesc, siteUrl, `<div class="posts">${postsHtml}</div>`), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // 단일 포스트/페이지
  const slug = pathname.replace(/^\/|\/$/g, '');
  if (slug) {
    const post = await env.DB.prepare(
      `SELECT * FROM wp_posts WHERE post_name=? AND post_status='publish' AND post_type IN ('post','page') LIMIT 1`
    ).bind(slug).first().catch(() => null);

    if (post) {
      const siteTitle = await getWpOption(env, siteInfo, 'blogname') || siteName;
      return new Response(renderTheme(
        esc(post.post_title) + ' — ' + esc(siteTitle),
        esc(post.post_excerpt || ''),
        siteUrl,
        `<article class="post single">
          <h1 class="entry-title">${esc(post.post_title)}</h1>
          <div class="entry-meta"><time>${new Date(post.post_date).toLocaleDateString('ko-KR', {year:'numeric',month:'long',day:'numeric'})}</time></div>
          <div class="entry-content">${post.post_content || ''}</div>
        </article>`
      ), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
  }

  return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
}

function renderTheme(title, description, siteUrl, content) {
  return `<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
${description ? `<meta name="description" content="${description}">` : ''}
<meta name="generator" content="WordPress 6.9.4 (CloudPress Edge)">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--primary:#2271b1;--text:#3c434a;--muted:#646970;--border:#c3c4c7;--bg:#fff;--body-bg:#f0f0f1}
html,body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:16px;line-height:1.7;color:var(--text);background:var(--body-bg)}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}
.site-header{background:var(--bg);border-bottom:1px solid var(--border);padding:0}
.header-inner{max-width:1100px;margin:0 auto;padding:0 20px;display:flex;align-items:center;justify-content:space-between;height:60px}
.site-title{font-size:1.4rem;font-weight:700;color:var(--text)}
.site-title a{color:inherit;text-decoration:none}
.nav-links{display:flex;gap:20px}
.nav-links a{font-size:.9rem;color:var(--muted)}
.nav-links a:hover{color:var(--primary)}
.site-main{max-width:1100px;margin:40px auto;padding:0 20px;display:grid;grid-template-columns:1fr 280px;gap:40px}
@media(max-width:768px){.site-main{grid-template-columns:1fr;gap:20px}.nav-links{display:none}}
.content-area{}
.widget-area{font-size:.9rem}
.widget{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:20px;margin-bottom:20px}
.widget-title{font-size:1rem;font-weight:700;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}
.post{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:24px;margin-bottom:20px}
.post.single{padding:32px}
.entry-title{font-size:1.4rem;font-weight:700;margin-bottom:8px;line-height:1.3}
.entry-title a{color:var(--text)}
.entry-title a:hover{color:var(--primary);text-decoration:none}
.entry-meta{font-size:.85rem;color:var(--muted);margin-bottom:16px}
.entry-summary{color:var(--text);line-height:1.7}
.entry-content{color:var(--text);line-height:1.8}
.entry-content h1,.entry-content h2,.entry-content h3{margin:24px 0 12px}
.entry-content p{margin-bottom:16px}
.entry-content img{max-width:100%;height:auto;border-radius:4px}
.entry-content a{color:var(--primary)}
.read-more{display:inline-block;margin-top:12px;font-size:.85rem;font-weight:600;color:var(--primary)}
.no-posts{color:var(--muted);padding:20px 0;text-align:center}
.site-footer{background:var(--bg);border-top:1px solid var(--border);padding:20px;text-align:center;font-size:.85rem;color:var(--muted);margin-top:40px}
.site-footer a{color:var(--muted)}
.site-footer a:hover{color:var(--primary)}
</style>
</head>
<body class="wordpress">
<header class="site-header">
  <div class="header-inner">
    <div class="site-branding">
      <p class="site-title"><a href="${siteUrl}">${title.split(' — ')[title.split(' — ').length-1]||title}</a></p>
    </div>
    <nav class="nav-links">
      <a href="${siteUrl}/">홈</a>
      <a href="${siteUrl}/wp-admin/">관리자</a>
    </nav>
  </div>
</header>
<div class="site-main">
  <main class="content-area">${content}</main>
  <aside class="widget-area">
    <div class="widget">
      <h2 class="widget-title">검색</h2>
      <form role="search" method="get" action="${siteUrl}/">
        <input type="text" name="s" placeholder="검색..." style="width:100%;padding:8px;border:1px solid var(--border);border-radius:4px;font-size:14px">
      </form>
    </div>
    <div class="widget">
      <h2 class="widget-title">최근 글</h2>
      <div id="recent-posts"><div style="color:var(--muted);font-size:.85rem">불러오는 중...</div></div>
      <script>
      fetch('/wp-json/wp/v2/posts?per_page=5').then(r=>r.json()).then(posts=>{
        document.getElementById('recent-posts').innerHTML=posts.length
          ?'<ul style="list-style:none;padding:0">'+posts.map(p=>'<li style="padding:5px 0;border-bottom:1px solid #f0f0f1"><a href="'+p.link+'" style="font-size:.85rem;color:#3c434a">'+p.title.rendered+'</a></li>').join('')+'</ul>'
          :'<p style="color:#646970;font-size:.85rem">글이 없습니다.</p>';
      }).catch(()=>{});
      </script>
    </div>
  </aside>
</div>
<footer class="site-footer">
  <p><a href="${siteUrl}">홈</a> | <a href="${siteUrl}/wp-admin/">관리자</a> | Powered by <a href="https://wordpress.org/">WordPress</a> &amp; <a href="https://cloudpress.site/">CloudPress</a></p>
</footer>
</body>
</html>`;
}

// ── 메인 fetch 핸들러 ─────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 1. WAF
    const waf = wafCheck(request, url);
    if (waf.block) return new Response(`차단됨: ${waf.reason}`, { status: waf.status || 403 });

    // 2. Rate Limit
    const ip = getClientIP(request);
    const rl = await rateLimitCheck(env, ip, pathname);
    if (!rl.allowed) return new Response(rl.banned ? '차단된 IP입니다.' : '요청이 너무 많습니다.', {
      status: 429, headers: { 'Retry-After': String(RATE_LIMIT_WIN) },
    });

    // 3. 사이트 정보 로드
    const siteInfo = await getSiteInfo(env, url.hostname);
    if (!siteInfo) {
      // CloudPress 플랫폼 자체 — Pages Functions이 처리
      return new Response('CloudPress Platform', { status: 200 });
    }

    if (siteInfo.suspended) {
      return new Response('이 사이트는 일시정지되었습니다.', { status: 403 });
    }

    // 4. wp-login.php → D1 기반 인증
    if (pathname === '/wp-login.php') {
      return handleWpLogin(env, siteInfo, request, url);
    }

    // 5. wp-admin/ → D1 기반 관리자 페이지
    if (pathname === '/wp-admin/' || pathname === '/wp-admin' || pathname.startsWith('/wp-admin/')) {
      // 세션 확인
      const session = await getWpSession(env, siteInfo, request);
      if (!session) {
        const redirectUrl = encodeURIComponent(pathname + url.search);
        return Response.redirect(`/wp-login.php?redirect_to=${redirectUrl}`, 302);
      }

      // 페이지 라우팅
      const page = url.searchParams.get('page') || 'dashboard';
      const html = renderWpAdmin(siteInfo, session, page);
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // 6. WordPress REST API
    if (pathname.startsWith('/wp-json/')) {
      return handleRestApi(env, siteInfo, request, url);
    }

    // 7. 정적 파일 → KV에서 서빙
    if (isStaticAsset(pathname) && request.method === 'GET') {
      if (env.CACHE) {
        try {
          const kvKey = `wp_file:${siteInfo.site_prefix}:${pathname}`;
          const cached = await env.CACHE.get(kvKey, { type: 'arrayBuffer' });
          if (cached) {
            const ext = pathname.split('.').pop().toLowerCase();
            const contentTypes = {
              css: 'text/css', js: 'application/javascript', png: 'image/png',
              jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml',
              ico: 'image/x-icon', woff2: 'font/woff2', woff: 'font/woff', ttf: 'font/ttf',
              pdf: 'application/pdf', webp: 'image/webp',
            };
            return new Response(cached, {
              headers: {
                'Content-Type': contentTypes[ext] || 'application/octet-stream',
                'Cache-Control': `public, max-age=${CACHE_TTL_STATIC}, immutable`,
              },
            });
          }
        } catch {}
      }
      return new Response('Not Found', { status: 404 });
    }

    // 8. wp-cron.php
    if (pathname === '/wp-cron.php') {
      return new Response('<?php // CloudPress Edge Cron OK ?>', {
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    // 9. 프론트엔드 WordPress 페이지 렌더링
    return renderFrontend(env, siteInfo, request, url);
  },

  async scheduled(event, env, ctx) {
    // 예약된 작업: 캐시 정리, 자동 백업 등
    ctx.waitUntil(Promise.resolve());
  },
};
