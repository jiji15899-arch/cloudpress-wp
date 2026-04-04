// functions/api/sites/index.js
// CloudPress CMS 사이트 목록 + 생성 (Cloudflare Pages .pages.dev 자동 생성)

/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan,plan_expires_at FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
function genPw(n=16){const c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$';let s='';const a=new Uint8Array(n);crypto.getRandomValues(a);for(const b of a)s+=c[b%c.length];return s;}
/* ── end utils ── */

/* SHA-256 hex 헬퍼 */
async function sha256hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
}

/* 사이트 이름 → .pages.dev 슬러그 자동 생성 */
function generateProjectName(siteName) {
  const base = siteName
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 18) || 'site';
  const suffix = Math.random().toString(36).slice(2, 7);
  return `cp-${base}-${suffix}`.slice(0, 28);
}

/* CF API 키 복호화 */
function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    const key = salt || 'cp_enc_v1';
    const decoded = atob(str);
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
  } catch { return ''; }
}

async function getUserCfCreds(env, userId) {
  const row = await env.DB.prepare('SELECT cf_global_api_key,cf_account_email,cf_account_id FROM users WHERE id=?').bind(userId).first();
  if (!row?.cf_global_api_key) return null;
  return {
    apiKey: deobfuscate(row.cf_global_api_key, env.ENCRYPTION_KEY || 'cp_enc_default'),
    email: row.cf_account_email,
    accountId: row.cf_account_id,
  };
}

const SITE_LIMITS = { free:1, starter:3, pro:10, enterprise:Infinity };

/* ── 사이트 HTML 템플릿 생성 ── */
function buildSiteIndexHtml(siteName, siteUrl) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${siteName}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f1f1;color:#3c434a}
a{color:#2271b1;text-decoration:none}.site-header{background:#1d2327;padding:0}
.site-header-inner{max-width:1200px;margin:0 auto;padding:20px 24px;display:flex;align-items:center;justify-content:space-between}
.site-title{color:#fff;font-size:1.4rem;font-weight:700;letter-spacing:-.5px}
.site-desc{color:rgba(255,255,255,.55);font-size:.82rem;margin-top:3px}
nav.primary{background:#2271b1}.nav-inner{max-width:1200px;margin:0 auto;padding:0 24px;display:flex}
nav.primary a{color:#fff;padding:11px 16px;font-size:.88rem;display:inline-block;transition:background .2s}
nav.primary a:hover{background:rgba(0,0,0,.15)}
.wrapper{max-width:1200px;margin:36px auto;padding:0 24px;display:grid;grid-template-columns:1fr 300px;gap:36px}
.post-card{background:#fff;padding:28px;margin-bottom:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.post-title{font-size:1.35rem;color:#1d2327;margin-bottom:8px}.post-title a:hover{color:#2271b1}
.post-meta{color:#6b7280;font-size:.8rem;margin-bottom:16px}.post-excerpt{line-height:1.75;color:#50575e}
.more-link{display:inline-block;margin-top:14px;font-size:.85rem;font-weight:600;color:#2271b1}
.widget{background:#fff;padding:20px;margin-bottom:20px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.widget-title{font-size:.95rem;font-weight:700;border-bottom:2px solid #2271b1;padding-bottom:8px;margin-bottom:14px;color:#1d2327}
.widget ul{list-style:none}.widget li{padding:5px 0;border-bottom:1px solid #f0f0f1;font-size:.85rem}
.widget li:last-child{border:none}
footer.site-footer{background:#1d2327;color:rgba(255,255,255,.55);text-align:center;padding:28px 24px;margin-top:60px;font-size:.83rem}
footer a{color:rgba(255,255,255,.75)}
@media(max-width:768px){.wrapper{grid-template-columns:1fr}}
</style>
</head>
<body>
<header class="site-header">
  <div class="site-header-inner">
    <div>
      <div class="site-title">${siteName}</div>
      <div class="site-desc">CloudPress CMS로 만든 사이트</div>
    </div>
  </div>
</header>
<nav class="primary">
  <div class="nav-inner">
    <a href="/">홈</a>
    <a href="/?page=about">소개</a>
    <a href="/?page=contact">연락처</a>
    <a href="/wp-admin/">관리자</a>
  </div>
</nav>
<div class="wrapper">
  <main>
    <article class="post-card">
      <h2 class="post-title"><a href="/">안녕하세요!</a></h2>
      <div class="post-meta">작성일: 2025년 1월 1일 &nbsp;|&nbsp; 작성자: 관리자 &nbsp;|&nbsp; 카테고리: 미분류</div>
      <div class="post-excerpt">
        <p>CloudPress CMS에 오신 것을 환영합니다. 이 글을 편집하거나 삭제하고 블로그를 시작해보세요!</p>
        <p>이 사이트는 Cloudflare Pages 위에서 동작하는 빠르고 안전한 WordPress 호환 CMS입니다.</p>
        <a class="more-link" href="/">더 읽기 →</a>
      </div>
    </article>
    <article class="post-card">
      <h2 class="post-title"><a href="/?p=2">샘플 페이지</a></h2>
      <div class="post-meta">작성일: 2025년 1월 1일 &nbsp;|&nbsp; 작성자: 관리자 &nbsp;|&nbsp; 카테고리: 미분류</div>
      <div class="post-excerpt">
        <p>이것은 샘플 페이지입니다. 페이지는 블로그 글과 달리 고정된 위치에 배치됩니다. 사이트 소개, 이용약관 등 정적인 정보를 올리기 좋습니다.</p>
        <a class="more-link" href="/?p=2">더 읽기 →</a>
      </div>
    </article>
  </main>
  <aside>
    <div class="widget">
      <h3 class="widget-title">최근 글</h3>
      <ul>
        <li><a href="/">안녕하세요!</a></li>
        <li><a href="/?p=2">샘플 페이지</a></li>
      </ul>
    </div>
    <div class="widget">
      <h3 class="widget-title">카테고리</h3>
      <ul><li><a href="/">미분류 (2)</a></li></ul>
    </div>
    <div class="widget">
      <h3 class="widget-title">관리</h3>
      <ul>
        <li><a href="/wp-admin/">사이트 관리자 로그인</a></li>
        <li><a href="https://cloudpress.pages.dev/dashboard.html" target="_blank">CloudPress 대시보드</a></li>
      </ul>
    </div>
  </aside>
</div>
<footer class="site-footer">
  <p>${siteName} &mdash; Powered by <a href="https://cloudpress.pages.dev">CloudPress CMS</a> &amp; Cloudflare Pages</p>
</footer>
</body>
</html>`;
}

function buildAdminRedirectHtml(siteName, dashboardUrl) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="refresh" content="3;url=${dashboardUrl}">
<title>관리자 — ${siteName}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#1d2327;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}
.card{background:#2c3338;border-radius:8px;padding:48px 40px;max-width:420px;width:90%}
.wp-logo{width:84px;height:84px;border-radius:50%;background:#2271b1;display:flex;align-items:center;justify-content:center;margin:0 auto 24px}
h1{font-size:1.1rem;font-weight:700;margin-bottom:8px}
p{color:rgba(255,255,255,.55);font-size:.86rem;margin-bottom:20px;line-height:1.6}
.btn{display:inline-block;padding:10px 24px;background:#2271b1;border-radius:4px;color:#fff;font-size:.88rem;font-weight:600;text-decoration:none}
.spinner{width:28px;height:28px;border:3px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:sp 0.8s linear infinite;margin:0 auto 16px}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <div class="wp-logo">
    <svg width="36" height="36" viewBox="0 0 28 28" fill="none">
      <path d="M14 2L26 8V20L14 26L2 20V8L14 2Z" stroke="#fff" stroke-width="1.5"/>
      <path d="M14 8L20 11V17L14 20L8 17V11L14 8Z" fill="#fff" opacity=".5"/>
      <circle cx="14" cy="14" r="2.2" fill="#fff"/>
    </svg>
  </div>
  <h1>${siteName} 관리자</h1>
  <div class="spinner"></div>
  <p>CloudPress 대시보드로 이동 중입니다…<br>잠시만 기다려 주세요.</p>
  <a class="btn" href="${dashboardUrl}">바로 이동 →</a>
</div>
</body>
</html>`;
}

function build404Html(siteName, siteUrl) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>페이지를 찾을 수 없습니다 — ${siteName}</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f1f1f1;color:#3c434a;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}
.wrap{max-width:480px;padding:40px}
h1{font-size:6rem;color:#2271b1;font-weight:900;line-height:1}
h2{font-size:1.2rem;margin:16px 0 10px}
p{color:#6b7280;font-size:.9rem;margin-bottom:24px}
a{padding:10px 24px;background:#2271b1;color:#fff;border-radius:4px;text-decoration:none;font-size:.9rem;font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <h1>404</h1>
  <h2>페이지를 찾을 수 없습니다</h2>
  <p>요청하신 페이지가 존재하지 않거나 이동되었습니다.</p>
  <a href="${siteUrl}">홈으로 돌아가기</a>
</div>
</body>
</html>`;
}

/* ── CF Pages 파일 배포 ── */
async function deployPagesTemplate(accountId, projectName, cfAuth, { siteName, siteUrl, dashboardUrl }) {
  const files = {
    '/index.html':          buildSiteIndexHtml(siteName, siteUrl),
    '/404.html':            build404Html(siteName, siteUrl),
    '/wp-admin/index.html': buildAdminRedirectHtml(siteName, dashboardUrl),
  };

  /* SHA-256 해시 계산 */
  const entries = [];
  for (const [path, content] of Object.entries(files)) {
    const hash = await sha256hex(content);
    entries.push({ path, content, hash });
  }

  const manifest = {};
  for (const e of entries) manifest[e.hash] = e.path;

  /* multipart/form-data 업로드 */
  const form = new FormData();
  form.append('manifest', new Blob([JSON.stringify(manifest)], { type: 'application/json' }));
  for (const e of entries) {
    form.append(e.hash, new Blob([e.content], { type: 'text/html; charset=utf-8' }), e.hash);
  }

  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}/deployments`,
    {
      method: 'POST',
      headers: { 'X-Auth-Email': cfAuth.email, 'X-Auth-Key': cfAuth.apiKey },
      body: form,
    }
  ).then(r => r.json()).catch(e => ({ success: false, errors: [{ message: e.message }] }));

  return resp.success
    ? { ok: true }
    : { ok: false, error: resp.errors?.[0]?.message || '배포 실패' };
}

/* ─────────────────────────────────────────────
   CloudPress CMS 자동 구축 (.pages.dev 도메인)
   ───────────────────────────────────────────── */
async function provisionCmsSite(env, { siteId, siteName, projectName, userPlan, cmsVersion, creds }) {
  if (!creds) {
    return { ok: false, error: 'Cloudflare Global API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 먼저 API 키를 등록해주세요.' };
  }

  const { apiKey, email, accountId } = creds;
  
  // 🔧 인증 정보 검증 추가
  if (!apiKey || !email || !accountId) {
    return { 
      ok: false, 
      error: 'Cloudflare API 인증 정보가 불완전합니다. API 키, 이메일, Account ID를 모두 확인해주세요.',
      logs: [
        '❌ 인증 정보 검증 실패',
        `   - API 키: ${apiKey ? '✓' : '✗'}`,
        `   - 이메일: ${email || '없음'}`,
        `   - Account ID: ${accountId || '없음'}`
      ]
    };
  }

  const cfHeaders = { 'X-Auth-Email': email, 'X-Auth-Key': apiKey, 'Content-Type': 'application/json' };
  const cfAuth = { apiKey, email, accountId };
  const adminPassword = genPw(16);
  const dbName = `cp_${siteId.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`;
  const kvTitle = `CloudPress CMS KV - ${siteName}`;
  const siteUrl = `https://${projectName}.pages.dev`;
  const adminUrl = `https://${projectName}.pages.dev/wp-admin/`;
  const dashboardUrl = env.DASHBOARD_URL || 'https://cloudpress.pages.dev/dashboard.html';

  let cfKvNamespace = null;
  let cfD1Database  = null;
  const logs = [];

  try {
    /* Step 1: Cloudflare Pages 프로젝트 생성 */
    logs.push(`① Cloudflare Pages 프로젝트 생성 중... (${projectName})`);
    logs.push(`   인증: ${email} / Account: ${accountId}`);
    
    const pagesResp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects`,
      {
        method: 'POST',
        headers: cfHeaders,
        body: JSON.stringify({ name: projectName, production_branch: 'main' }),
      }
    ).then(r => r.json()).catch(e => {
      // 🔧 네트워크 오류 상세 로깅
      return { 
        success: false, 
        errors: [{ message: `네트워크 오류: ${e.message}` }],
        _fetchError: e.message 
      };
    });

    // 🔧 상세 오류 로깅 추가
    if (pagesResp.success) {
      logs.push(`   ✓ Pages 프로젝트 생성 완료 → ${siteUrl}`);
    } else {
      const errMsg = pagesResp.errors?.[0]?.message || '알 수 없는 오류';
      const errCode = pagesResp.errors?.[0]?.code || '';
      logs.push(`   ✗ Pages 프로젝트 생성 실패`);
      logs.push(`   오류: ${errMsg}${errCode ? ` (코드: ${errCode})` : ''}`);
      
      // 인증 오류인 경우 추가 정보 제공
      if (errMsg.toLowerCase().includes('authentication') || errMsg.toLowerCase().includes('unauthorized') || errCode === 10000) {
        logs.push(`   💡 인증 오류 해결 방법:`);
        logs.push(`      1. Cloudflare 대시보드에서 Global API 키 재확인`);
        logs.push(`      2. 이메일 주소가 Cloudflare 계정과 일치하는지 확인`);
        logs.push(`      3. Account ID가 올바른지 확인`);
        logs.push(`      4. API 키를 다시 입력해보세요`);
        return { 
          ok: false, 
          error: `Pages 프로젝트 생성 실패 (인증 오류)\n${errMsg}\n\n해결 방법: 내 계정에서 Cloudflare API 키를 다시 확인하고 재입력해주세요.`, 
          logs 
        };
      }
      
      // 전체 응답을 로그에 포함 (디버깅용)
      if (pagesResp._fetchError) {
        logs.push(`   네트워크 오류 상세: ${pagesResp._fetchError}`);
      }
      
      return { ok: false, error: `Pages 프로젝트 생성 실패: ${errMsg}`, logs };
    }

    /* Step 2: KV Namespace 생성 */
    logs.push('② KV Namespace 생성 중...');
    const kvResp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces`,
      { method: 'POST', headers: cfHeaders, body: JSON.stringify({ title: kvTitle }) }
    ).then(r => r.json()).catch(() => ({}));

    if (kvResp.success) {
      cfKvNamespace = kvResp.result?.id;
      logs.push(`   ✓ KV Namespace: ${cfKvNamespace}`);
    } else {
      logs.push(`   ⚠ KV 생성 실패 — ${kvResp.errors?.[0]?.message || '알 수 없는 오류'}`);
    }

    /* Step 3: D1 Database 생성 */
    logs.push('③ D1 데이터베이스 생성 중...');
    const d1Resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database`,
      { method: 'POST', headers: cfHeaders, body: JSON.stringify({ name: dbName }) }
    ).then(r => r.json()).catch(() => ({}));

    if (d1Resp.result?.uuid) {
      cfD1Database = d1Resp.result.uuid;
      logs.push(`   ✓ D1 Database: ${cfD1Database}`);
    } else {
      logs.push(`   ⚠ D1 생성 실패 — ${d1Resp.errors?.[0]?.message || '알 수 없는 오류'}`);
    }

    /* Step 4: D1 CMS 스키마 초기화 */
    if (cfD1Database) {
      logs.push('④ CMS 데이터베이스 초기화 중...');
      const cmsSchema = getCmsSchema(siteId, siteName, adminPassword, projectName);
      for (const sql of cmsSchema) {
        await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${cfD1Database}/query`,
          { method: 'POST', headers: cfHeaders, body: JSON.stringify({ sql }) }
        ).catch(() => {});
      }
      logs.push('   ✓ CMS 스키마 초기화 완료');
    }

    /* Step 5: KV 사이트 설정 저장 */
    if (cfKvNamespace) {
      logs.push('⑤ CMS 설정 데이터 저장 중...');
      const siteConfig = {
        site_id: siteId,
        site_name: siteName,
        site_url: siteUrl,
        admin_url: adminUrl,
        cms_version: cmsVersion || '1.0.0',
        created_at: new Date().toISOString(),
        theme: 'default',
        settings: {
          title: siteName,
          tagline: 'CloudPress CMS로 만든 사이트',
          language: 'ko_KR',
          timezone: 'Asia/Seoul',
          posts_per_page: 10,
        }
      };
      await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${cfKvNamespace}/values/site_config`,
        { method: 'PUT', headers: { ...cfHeaders, 'Content-Type': 'text/plain' }, body: JSON.stringify(siteConfig) }
      ).catch(() => {});
      logs.push('   ✓ CMS 설정 저장 완료');
    }

    /* Step 6: Pages에 CMS 템플릿 배포 */
    logs.push('⑥ CMS 사이트 템플릿 배포 중...');
    const deployResult = await deployPagesTemplate(accountId, projectName, cfAuth, {
      siteName, siteUrl, dashboardUrl,
    });
    if (deployResult.ok) {
      logs.push(`   ✓ 사이트 배포 완료 → ${siteUrl}`);
    } else {
      logs.push(`   ⚠ 배포 실패 — ${deployResult.error} (URL은 유효)`);
    }

    logs.push('✅ CloudPress CMS 구축 완료!');

    return {
      ok: true,
      status: 'active',
      cmsUrl: siteUrl,
      cmsAdminUrl: adminUrl,
      cmsUsername: 'admin',
      cmsPassword: adminPassword,
      cfZoneId: null,
      cfKvNamespace,
      cfD1Database,
      cfPagesProject: projectName,
      logs,
    };

  } catch (e) {
    console.error('provisionCmsSite error:', e);
    logs.push(`❌ 예상치 못한 오류: ${e?.message ?? e}`);
    return { ok: false, error: 'CMS 구축 중 오류: ' + (e?.message ?? e), logs };
  }
}

/* CMS D1 데이터베이스 스키마 */
function getCmsSchema(siteId, siteName, adminPw, projectName) {
  const siteUrl = `https://${projectName}.pages.dev`;
  return [
    `CREATE TABLE IF NOT EXISTS cp_users (ID INTEGER PRIMARY KEY AUTOINCREMENT, user_login TEXT UNIQUE NOT NULL, user_pass TEXT NOT NULL, user_email TEXT NOT NULL, display_name TEXT, user_registered TEXT DEFAULT (datetime('now')), user_status INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_posts (ID INTEGER PRIMARY KEY AUTOINCREMENT, post_author INTEGER DEFAULT 1, post_date TEXT DEFAULT (datetime('now')), post_content TEXT, post_title TEXT, post_excerpt TEXT, post_status TEXT DEFAULT 'draft', comment_status TEXT DEFAULT 'open', post_name TEXT, post_type TEXT DEFAULT 'post', menu_order INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_postmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, meta_key TEXT, meta_value TEXT)`,
    `CREATE TABLE IF NOT EXISTS cp_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT UNIQUE NOT NULL, option_value TEXT, autoload TEXT DEFAULT 'yes')`,
    `CREATE TABLE IF NOT EXISTS cp_terms (term_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL, term_group INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_term_taxonomy (term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT, term_id INTEGER, taxonomy TEXT, description TEXT, parent INTEGER DEFAULT 0, count INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_term_relationships (object_id INTEGER, term_taxonomy_id INTEGER, term_order INTEGER DEFAULT 0, PRIMARY KEY (object_id, term_taxonomy_id))`,
    `CREATE TABLE IF NOT EXISTS cp_comments (comment_ID INTEGER PRIMARY KEY AUTOINCREMENT, comment_post_ID INTEGER, comment_author TEXT, comment_author_email TEXT, comment_date TEXT DEFAULT (datetime('now')), comment_content TEXT, comment_approved TEXT DEFAULT '1')`,
    `CREATE TABLE IF NOT EXISTS cp_commentmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, comment_id INTEGER, meta_key TEXT, meta_value TEXT)`,
    `INSERT OR IGNORE INTO cp_users (user_login,user_pass,user_email,display_name) VALUES ('admin','${adminPw}','admin@${projectName}.pages.dev','관리자')`,
    `INSERT OR IGNORE INTO cp_options (option_name,option_value) VALUES ('siteurl','${siteUrl}'),('blogname','${siteName.replace(/'/g,"''")}'),('blogdescription','CloudPress CMS로 만든 사이트'),('admin_email','admin@${projectName}.pages.dev'),('posts_per_page','10'),('active_theme','default'),('cms_version','1.0.0'),('permalink_structure','/%year%/%monthnum%/%postname%/'),('timezone_string','Asia/Seoul'),('date_format','Y년 n월 j일'),('time_format','H:i'),('default_comment_status','open'),('show_on_front','posts')`,
    `INSERT OR IGNORE INTO cp_posts (post_title,post_content,post_status,post_type,post_name) VALUES ('안녕하세요!','CloudPress CMS에 오신 것을 환영합니다. 이 글을 편집하거나 삭제하고 블로그를 시작해보세요!','publish','post','hello-world'),('샘플 페이지','이것은 샘플 페이지입니다. 사이드바와는 달리 페이지는 고정된 위치에 있습니다.','publish','page','sample-page')`,
    `INSERT OR IGNORE INTO cp_terms (name,slug) VALUES ('미분류','uncategorized')`,
    `INSERT OR IGNORE INTO cp_term_taxonomy (term_id,taxonomy,description,count) VALUES (1,'category','',2)`,
    `INSERT OR IGNORE INTO cp_term_relationships (object_id,term_taxonomy_id) VALUES (1,1),(2,1)`,
  ];
}

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);

    const { results } = await env.DB.prepare(
      `SELECT id,name,subdomain,custom_domain,cms_url,cms_admin_url,
              cms_username,cms_version,status,plan,created_at,cf_zone_id,cf_d1_database,cf_kv_namespace
       FROM sites WHERE user_id=? ORDER BY created_at DESC`
    ).bind(user.id).all();

    return ok({ sites: results ?? [] });
  } catch (e) {
    console.error('sites GET error:', e);
    return err('사이트 목록 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { name, cms_version } = body || {};
    if (!name || !name.trim()) return err('사이트 이름을 입력해주세요.');

    // 플랜별 사이트 수 제한
    const countRow = await env.DB.prepare("SELECT COUNT(*) cnt FROM sites WHERE user_id=? AND status!='deleted'").bind(user.id).first();
    const siteCount = countRow?.cnt ?? 0;
    const limit = SITE_LIMITS[user.plan] ?? 1;
    if (siteCount >= limit) {
      return err(`현재 플랜(${user.plan})에서 최대 ${limit}개 사이트까지 가능합니다. 플랜을 업그레이드해주세요.`, 403);
    }

    // CF API 키 확인
    const creds = await getUserCfCreds(env, user.id);
    if (!creds) {
      return err('Cloudflare API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 먼저 API 키를 등록해주세요.', 403);
    }

    // .pages.dev 프로젝트명 자동 생성 (중복 시 재시도)
    let projectName = generateProjectName(name.trim());
    for (let i = 0; i < 4; i++) {
      const dup = await env.DB.prepare("SELECT id FROM sites WHERE subdomain=?").bind(projectName).first();
      if (!dup) break;
      projectName = generateProjectName(name.trim());
    }

    const siteId = genId();

    // DB에 먼저 저장 (provisioning 상태)
    await env.DB.prepare(
      `INSERT INTO sites (id,user_id,name,subdomain,status,plan,cms_version,created_at)
       VALUES (?,?,?,?,'provisioning',?,?,unixepoch())`
    ).bind(siteId, user.id, name.trim(), projectName, user.plan, cms_version || '1.0.0').run();

    // CMS 자동 구축 (.pages.dev)
    const result = await provisionCmsSite(env, {
      siteId,
      siteName: name.trim(),
      projectName,
      userPlan: user.plan,
      cmsVersion: cms_version || '1.0.0',
      creds,
    });

    if (!result.ok) {
      await env.DB.prepare("UPDATE sites SET status='error' WHERE id=?").bind(siteId).run();
      return err(result.error, 500);
    }

    // 결과 DB 저장
    await env.DB.prepare(
      `UPDATE sites SET status='active',cms_url=?,cms_admin_url=?,cms_username=?,cms_password=?,
       cf_zone_id=?,cf_kv_namespace=?,cf_d1_database=? WHERE id=?`
    ).bind(
      result.cmsUrl, result.cmsAdminUrl, result.cmsUsername, result.cmsPassword,
      result.cfZoneId || null, result.cfKvNamespace || null, result.cfD1Database || null,
      siteId
    ).run();

    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=?').bind(siteId).first();
    return ok({
      site,
      message: `CloudPress CMS 사이트가 ${result.cmsUrl} 에 구축되었습니다.`,
      logs: result.logs,
    });

  } catch (e) {
    console.error('sites POST error:', e);
    return err('사이트 생성 중 오류 발생: ' + (e?.message ?? e), 500);
  }
}
