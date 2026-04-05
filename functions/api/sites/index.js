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
async function sha256hexBytes(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes);
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
  const apiKey = deobfuscate(row.cf_global_api_key, env.ENCRYPTION_KEY || 'cp_enc_default');
  const email = row.cf_account_email;
  let accountId = row.cf_account_id;
  if (!accountId) {
    try {
      const headers = { 'X-Auth-Email': email, 'X-Auth-Key': apiKey, 'Content-Type': 'application/json' };
      const r = await fetch('https://api.cloudflare.com/client/v4/accounts?per_page=1', { headers });
      const d = await r.json();
      if (d.success && d.result?.length > 0) {
        accountId = d.result[0].id;
        await env.DB.prepare('UPDATE users SET cf_account_id=? WHERE id=?').bind(accountId, userId).run().catch(()=>{});
      }
    } catch (_) {}
  }
  if (!apiKey || !email || !accountId) return null;
  return { apiKey, email, accountId };
}

const SITE_LIMITS = { free:1, starter:3, pro:10, enterprise:Infinity };

/* ══════════════════════════════════════════════════════
   ZIP 파서 (Cloudflare Workers 환경 — 순수 JS)
   Local File Header(PK\x03\x04) 시그니처를 순회
   ══════════════════════════════════════════════════════ */
function parseZip(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  const files = [];
  let offset = 0;

  while (offset + 30 <= bytes.length) {
    const sig = view.getUint32(offset, true);
    if (sig !== 0x04034b50) break;                        // Local file header sig

    const compression    = view.getUint16(offset + 8,  true);
    const compressedSize = view.getUint32(offset + 18, true);
    const fileNameLen    = view.getUint16(offset + 26, true);
    const extraLen       = view.getUint16(offset + 28, true);

    const nameBytes = bytes.slice(offset + 30, offset + 30 + fileNameLen);
    const name      = new TextDecoder('utf-8').decode(nameBytes);
    const dataStart = offset + 30 + fileNameLen + extraLen;
    const data      = bytes.slice(dataStart, dataStart + compressedSize);

    files.push({ name, compression, data });
    offset = dataStart + compressedSize;
  }
  return files;
}

async function inflateDeflate(compressedBytes) {
  try {
    const ds     = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    writer.write(compressedBytes);
    writer.close();
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const total  = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(total);
    let pos = 0;
    for (const c of chunks) { result.set(c, pos); pos += c.length; }
    return result;
  } catch { return null; }
}

/* base64(또는 data:... prefix 포함) → ArrayBuffer */
function base64ToArrayBuffer(b64) {
  const raw    = b64.replace(/^data:[^;]+;base64,/, '');
  const binary = atob(raw);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/* Content-Type 추론 */
function getMimeType(path) {
  const ext = path.split('.').pop().toLowerCase();
  const map = {
    html:'text/html; charset=utf-8', js:'application/javascript; charset=utf-8',
    css:'text/css; charset=utf-8',   json:'application/json',
    txt:'text/plain; charset=utf-8', svg:'image/svg+xml',
    png:'image/png',  jpg:'image/jpeg', jpeg:'image/jpeg',
    gif:'image/gif',  ico:'image/x-icon',
    woff:'font/woff', woff2:'font/woff2',
  };
  return map[ext] || 'application/octet-stream';
}

/* 텍스트 파일의 플레이스홀더 치환 */
function applyPlaceholders(text, { siteUrl, projectName, kvNamespaceId, d1DatabaseId }) {
  return text
    .replace(/REPLACE_WITH_YOUR_SITE/g, projectName)
    .replace(/https:\/\/REPLACE_WITH_YOUR_SITE\.pages\.dev/g, siteUrl)
    .replace(/REPLACE_WITH_D1_DATABASE_ID/g, d1DatabaseId || '')
    .replace(/REPLACE_WITH_KV_NAMESPACE_ID/g, kvNamespaceId || '');
}

/* ══════════════════════════════════════════════════════
   KV에서 최신 CMS 패키지(ZIP base64) 로드
   우선순위: 지정 버전 → DB is_latest=1 → KV 키 스캔
   ══════════════════════════════════════════════════════ */
async function loadCmsPackageFromKV(env, preferredVersion) {
  // 1) 특정 버전 지정
  if (preferredVersion) {
    try {
      const val = await env.SESSIONS.get(`cms_package:${preferredVersion}`);
      if (val) return { data: val, version: preferredVersion };
    } catch (_) {}
  }

  // 2) DB에서 is_latest=1 버전 조회
  let latestVersion = null;
  try {
    const row = await env.DB.prepare(
      "SELECT version FROM cms_versions WHERE is_latest=1 ORDER BY created_at DESC LIMIT 1"
    ).first().catch(() => null);
    if (row?.version) {
      latestVersion = row.version;
    } else {
      const row2 = await env.DB.prepare(
        "SELECT version FROM cms_packages WHERE is_latest=1 ORDER BY uploaded_at DESC LIMIT 1"
      ).first().catch(() => null);
      if (row2?.version) latestVersion = row2.version;
    }
  } catch (_) {}

  if (latestVersion) {
    try {
      const val = await env.SESSIONS.get(`cms_package:${latestVersion}`);
      if (val) return { data: val, version: latestVersion };
    } catch (_) {}
  }

  // 3) KV 목록 스캔 (최후 수단)
  try {
    const list = await env.SESSIONS.list({ prefix: 'cms_package:' });
    if (list?.keys?.length > 0) {
      // 가장 최근 업로드 (list는 알파벳 순이므로 마지막이 최신은 아님 — 모두 시도)
      for (const kvKey of list.keys) {
        const version = kvKey.name.replace('cms_package:', '');
        const val = await env.SESSIONS.get(kvKey.name);
        if (val) return { data: val, version };
      }
    }
  } catch (_) {}

  return null;
}

/* ══════════════════════════════════════════════════════
   ZIP → Pages multipart 변환
   반환: { manifest, fileParts }
   ══════════════════════════════════════════════════════ */
async function extractZipForPages(zipBase64, { siteUrl, projectName, kvNamespaceId, d1DatabaseId }) {
  let zipBuffer;
  try {
    zipBuffer = base64ToArrayBuffer(zipBase64);
  } catch (e) {
    throw new Error('ZIP base64 디코딩 실패: ' + e.message);
  }

  const rawFiles = parseZip(zipBuffer);
  if (!rawFiles.length) throw new Error('ZIP 내 파일 파싱 실패 (파일 0개)');

  // 공통 루트 폴더 접두사 제거 (예: cloudpress-cms-v1.0.0/ → '')
  const firstFile = rawFiles.find(f => !f.name.endsWith('/'));
  const prefix    = firstFile?.name.match(/^([^/]+\/)/)?.[1] || '';

  const manifest  = {};
  const fileParts = [];

  for (const f of rawFiles) {
    if (f.name.endsWith('/')) continue;                          // 폴더 엔트리 스킵
    if (f.name.includes('__MACOSX') || f.name.includes('.DS_Store')) continue;
    if (f.name.endsWith('wrangler.toml')) continue;              // 배포에 불필요
    if (f.name.endsWith('cms-schema.sql')) continue;             // D1 초기화는 API로 수행

    let cleanPath = prefix && f.name.startsWith(prefix)
      ? f.name.slice(prefix.length) : f.name;
    if (!cleanPath) continue;

    // 파일 데이터 압축 해제
    let fileBytes;
    if (f.compression === 0) {
      fileBytes = f.data;
    } else if (f.compression === 8) {
      fileBytes = await inflateDeflate(f.data);
      if (!fileBytes) { continue; }  // 해제 실패 스킵
    } else {
      continue; // 지원하지 않는 압축 스킵
    }

    // 텍스트 파일에서 플레이스홀더 치환
    const mimeType = getMimeType(cleanPath);
    const isText   = mimeType.startsWith('text/') || mimeType.includes('javascript') || mimeType.includes('json');
    if (isText) {
      let text = new TextDecoder('utf-8').decode(fileBytes);
      text = applyPlaceholders(text, { siteUrl, projectName, kvNamespaceId, d1DatabaseId });
      fileBytes = new TextEncoder().encode(text);
    }

    const hash     = await sha256hexBytes(fileBytes);
    const pagePath = '/' + cleanPath;
    manifest[hash] = pagePath;
    fileParts.push({ hash, bytes: fileBytes, mimeType });
  }

  if (!fileParts.length) throw new Error('배포할 파일이 없습니다 (ZIP이 비어있거나 파싱 오류)');
  return { manifest, fileParts };
}

/* ══════════════════════════════════════════════════════
   Pages 프로젝트에 D1/KV 바인딩 + 환경변수 자동 설정
   ══════════════════════════════════════════════════════ */
async function setPagesBindings(accountId, projectName, cfAuth, { kvNamespaceId, d1DatabaseId, siteUrl, logs }) {
  const body = {
    deployment_configs: {
      production: {
        env_vars: {
          SITE_URL:    { type: 'plain_text', value: siteUrl },
          CMS_VERSION: { type: 'plain_text', value: '1.0.0' },
        },
      },
    },
  };
  if (kvNamespaceId) {
    body.deployment_configs.production.kv_namespaces = {
      CMS_KV: { namespace_id: kvNamespaceId },
    };
  }
  if (d1DatabaseId) {
    body.deployment_configs.production.d1_databases = {
      CMS_DB: { id: d1DatabaseId },
    };
  }

  try {
    const r = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}`,
      {
        method: 'PATCH',
        headers: { 'X-Auth-Email': cfAuth.email, 'X-Auth-Key': cfAuth.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    ).then(r => r.json());
    if (r.success) {
      logs.push('   ✓ Pages 바인딩(D1/KV/환경변수) 자동 설정 완료');
    } else {
      logs.push(`   ⚠ Pages 바인딩 설정 실패: ${r.errors?.[0]?.message || '알 수 없는 오류'} (Cloudflare 대시보드에서 수동 설정 필요)`);
    }
  } catch (e) {
    logs.push(`   ⚠ Pages 바인딩 설정 오류: ${e.message}`);
  }
}

/* ══════════════════════════════════════════════════════
   CF Pages 배포 메인
   1순위: KV에서 CMS ZIP 읽어 전체 파일 배포
   2순위: 기본 HTML 3개 fallback
   ══════════════════════════════════════════════════════ */
async function deployPagesFromPackage(env, {
  accountId, projectName, cfAuth,
  siteName, siteUrl, dashboardUrl,
  cmsVersion, kvNamespaceId, d1DatabaseId, adminPassword, logs,
}) {
  // ─ 1) KV에서 CMS 패키지 로드 ─
  const pkg = await loadCmsPackageFromKV(env, cmsVersion).catch(() => null);

  if (pkg?.data) {
    logs.push(`   ℹ 업로드된 CMS 패키지 v${pkg.version} 발견 → ZIP 배포 모드`);
    try {
      const { manifest, fileParts } = await extractZipForPages(pkg.data, {
        siteUrl, projectName, kvNamespaceId, d1DatabaseId,
      });
      logs.push(`   ℹ 배포 파일: ${fileParts.length}개`);

      const form = new FormData();
      form.append('manifest', new Blob([JSON.stringify(manifest)], { type: 'application/json' }));
      for (const f of fileParts) {
        form.append(f.hash, new Blob([f.bytes], { type: f.mimeType }), f.hash);
      }

      const resp = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}/deployments`,
        {
          method: 'POST',
          headers: { 'X-Auth-Email': cfAuth.email, 'X-Auth-Key': cfAuth.apiKey },
          body: form,
        }
      ).then(r => r.json()).catch(e => ({ success: false, errors: [{ message: e.message }] }));

      if (resp.success) {
        logs.push(`   ✓ CMS 패키지 배포 완료 (v${pkg.version}) → ${siteUrl}`);
        // Pages 프로젝트에 D1/KV 바인딩 자동 설정
        await setPagesBindings(accountId, projectName, cfAuth, { kvNamespaceId, d1DatabaseId, siteUrl, logs });
        return { ok: true, mode: 'package', version: pkg.version };
      }

      const errMsg = resp.errors?.[0]?.message || '알 수 없는 오류';
      logs.push(`   ⚠ ZIP 배포 실패: ${errMsg} → fallback 모드로 전환`);
    } catch (e) {
      logs.push(`   ⚠ ZIP 처리 오류: ${e.message} → fallback 모드로 전환`);
    }
  } else {
    logs.push('   ⚠ 업로드된 CMS 패키지 없음 → 기본 템플릿으로 배포');
  }

  // ─ 2) Fallback: 기본 HTML 3개 배포 ─
  const files = {
    '/index.html':          buildSiteIndexHtml(siteName, siteUrl),
    '/404.html':            build404Html(siteName, siteUrl),
    '/wp-admin/index.html': buildAdminRedirectHtml(siteName, dashboardUrl),
  };
  const entries = [];
  for (const [path, content] of Object.entries(files)) {
    entries.push({ path, content, hash: await sha256hex(content) });
  }
  const manifest = {};
  for (const e of entries) manifest[e.hash] = e.path;

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

  if (resp.success) {
    logs.push(`   ✓ 기본 템플릿 배포 완료 → ${siteUrl}`);
    return { ok: true, mode: 'fallback' };
  }
  const errMsg = resp.errors?.[0]?.message || '배포 실패';
  logs.push(`   ✗ 배포 실패: ${errMsg}`);
  return { ok: false, error: errMsg };
}

/* ── fallback 기본 HTML 생성 함수들 ── */
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
a{color:#2271b1;text-decoration:none}
.site-header{background:#1d2327}
.site-header-inner{max-width:1200px;margin:0 auto;padding:20px 24px;display:flex;align-items:center;justify-content:space-between}
.site-title{color:#fff;font-size:1.4rem;font-weight:700}
.site-desc{color:rgba(255,255,255,.55);font-size:.82rem;margin-top:3px}
nav.primary{background:#2271b1}
.nav-inner{max-width:1200px;margin:0 auto;padding:0 24px;display:flex}
nav.primary a{color:#fff;padding:11px 16px;font-size:.88rem;display:inline-block}
.wrapper{max-width:1200px;margin:36px auto;padding:0 24px;display:grid;grid-template-columns:1fr 300px;gap:36px}
.post-card{background:#fff;padding:28px;margin-bottom:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.post-title{font-size:1.35rem;color:#1d2327;margin-bottom:8px}
.post-meta{color:#6b7280;font-size:.8rem;margin-bottom:16px}
.post-excerpt{line-height:1.75;color:#50575e}
.more-link{display:inline-block;margin-top:14px;font-size:.85rem;font-weight:600;color:#2271b1}
.widget{background:#fff;padding:20px;margin-bottom:20px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.widget-title{font-size:.95rem;font-weight:700;border-bottom:2px solid #2271b1;padding-bottom:8px;margin-bottom:14px;color:#1d2327}
.widget ul{list-style:none}
.widget li{padding:5px 0;border-bottom:1px solid #f0f0f1;font-size:.85rem}
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
    <a href="/wp-admin/">관리자</a>
  </div>
</nav>
<div class="wrapper">
  <main>
    <article class="post-card">
      <h2 class="post-title"><a href="/">안녕하세요!</a></h2>
      <div class="post-meta">작성일: 2025년 1월 1일 &nbsp;|&nbsp; 작성자: 관리자</div>
      <div class="post-excerpt">
        <p>CloudPress CMS에 오신 것을 환영합니다. 관리자 페이지에서 글을 작성해보세요!</p>
        <a class="more-link" href="/wp-admin/">관리자 →</a>
      </div>
    </article>
  </main>
  <aside>
    <div class="widget">
      <h3 class="widget-title">관리</h3>
      <ul>
        <li><a href="/wp-admin/">사이트 관리자</a></li>
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
h1{font-size:1.1rem;font-weight:700;margin-bottom:8px}
p{color:rgba(255,255,255,.55);font-size:.86rem;margin-bottom:20px;line-height:1.6}
.btn{display:inline-block;padding:10px 24px;background:#2271b1;border-radius:4px;color:#fff;font-size:.88rem;font-weight:600;text-decoration:none}
.spinner{width:28px;height:28px;border:3px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:sp 0.8s linear infinite;margin:0 auto 16px}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <h1>${siteName} 관리자</h1>
  <div class="spinner"></div>
  <p>CloudPress 대시보드로 이동 중입니다…</p>
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

/* ─────────────────────────────────────────────
   CloudPress CMS 자동 구축 (.pages.dev 도메인)
   ───────────────────────────────────────────── */
async function provisionCmsSite(env, { siteId, siteName, projectName, userPlan, cmsVersion, creds }) {
  if (!creds) return { ok: false, error: 'Cloudflare Global API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 먼저 API 키를 등록해주세요.' };

  const { apiKey, email, accountId } = creds;
  const logs = [];

  // ── Step 0: 인증 검증 ──
  logs.push('① Cloudflare API 인증 확인 중...');
  if (!apiKey || !email || !accountId) {
    return { ok: false, error: 'Cloudflare API 인증 정보가 불완전합니다.', logs };
  }

  const cfHeaders = { 'X-Auth-Email': email, 'X-Auth-Key': apiKey, 'Content-Type': 'application/json' };

  try {
    const verifyData = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
      { headers: cfHeaders }
    ).then(r => r.json());

    if (!verifyData.success) {
      logs.push(`   ⚠ Account ID 검증 실패, 재조회 중...`);
      const acctListData = await fetch(
        'https://api.cloudflare.com/client/v4/accounts?per_page=1',
        { headers: cfHeaders }
      ).then(r => r.json());

      if (!acctListData.success || !acctListData.result?.length) {
        return {
          ok: false,
          error: `Cloudflare 인증 오류: ${verifyData.errors?.[0]?.message || '알 수 없는 오류'}\n\n해결 방법: 내 계정 → Cloudflare API 설정에서 API 키와 이메일을 다시 저장해주세요.`,
          logs
        };
      }
      creds.accountId = acctListData.result[0].id;
      logs.push(`   ✓ Account ID 재설정: ${creds.accountId}`);
      await env.DB.prepare('UPDATE users SET cf_account_id=? WHERE cf_account_email=?').bind(creds.accountId, email).run().catch(()=>{});
    } else {
      logs.push(`   ✓ 인증 확인 완료: ${verifyData.result?.name || accountId}`);
    }
  } catch (e) {
    return { ok: false, error: `Cloudflare API 연결 실패: ${e.message}`, logs };
  }

  const verifiedAccountId = creds.accountId || accountId;
  const verifiedHeaders   = { 'X-Auth-Email': email, 'X-Auth-Key': apiKey, 'Content-Type': 'application/json' };
  const cfAuth            = { apiKey, email, accountId: verifiedAccountId };

  const adminPassword = genPw(16);
  const dashboardUrl  = `https://cloudpress.pages.dev/dashboard.html`;
  const kvTitle       = `cp-kv-${projectName}`;
  const dbName        = `cp-db-${projectName}`;
  let cfKvNamespace   = null;
  let cfD1Database    = null;

  try {
    /* Step 1: Pages 프로젝트 생성 */
    logs.push(`② Cloudflare Pages 프로젝트 생성 중... (${projectName})`);
    let currentProjectName = projectName;

    for (let attempt = 1; attempt <= 3; attempt++) {
      const pagesResp = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${verifiedAccountId}/pages/projects`,
        {
          method: 'POST',
          headers: verifiedHeaders,
          body: JSON.stringify({ name: currentProjectName, production_branch: 'main' }),
        }
      ).then(r => r.json()).catch(e => ({ success: false, errors: [{ message: `네트워크 오류: ${e.message}` }] }));

      if (pagesResp.success) {
        logs.push(`   ✓ Pages 프로젝트 생성 완료 → https://${currentProjectName}.pages.dev`);
        break;
      }

      const errMsg  = pagesResp.errors?.[0]?.message || '';
      const errCode = pagesResp.errors?.[0]?.code;

      if (errMsg.toLowerCase().includes('already exist') || errMsg.toLowerCase().includes('duplicate') || errCode === 8000039) {
        currentProjectName = generateProjectName(siteName);
        logs.push(`   ⚠ 프로젝트명 중복, 재시도: ${currentProjectName} (${attempt}/3)`);
        continue;
      }
      if (errMsg.toLowerCase().includes('authentication') || errMsg.toLowerCase().includes('unauthorized') || errCode === 10000 || errCode === 9109) {
        return {
          ok: false,
          error: `Pages 프로젝트 생성 실패 (인증 오류)\n원인: ${errMsg}\n해결 방법: Global API 키를 다시 저장해주세요.`,
          logs
        };
      }
      if (attempt < 3) {
        logs.push(`   ⚠ 시도 ${attempt} 실패 (${errMsg}), 재시도 중...`);
        await new Promise(r => setTimeout(r, 2000 * attempt));
      } else {
        return { ok: false, error: `Pages 프로젝트 생성 실패: ${errMsg}`, logs };
      }
    }

    if (currentProjectName !== projectName) {
      projectName = currentProjectName;
      await env.DB.prepare('UPDATE sites SET subdomain=? WHERE id=?').bind(projectName, siteId).run().catch(()=>{});
    }
    const finalSiteUrl  = `https://${projectName}.pages.dev`;
    const finalAdminUrl = `https://${projectName}.pages.dev/wp-admin/`;

    /* Step 2: KV Namespace 생성 */
    logs.push('③ KV Namespace 생성 중...');
    const kvResp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${verifiedAccountId}/storage/kv/namespaces`,
      { method: 'POST', headers: verifiedHeaders, body: JSON.stringify({ title: kvTitle }) }
    ).then(r => r.json()).catch(() => ({}));

    if (kvResp.success) {
      cfKvNamespace = kvResp.result?.id;
      logs.push(`   ✓ KV Namespace: ${cfKvNamespace}`);
    } else {
      logs.push(`   ⚠ KV 생성 실패 — ${kvResp.errors?.[0]?.message || '알 수 없는 오류'} (계속 진행)`);
    }

    /* Step 3: D1 Database 생성 */
    logs.push('④ D1 데이터베이스 생성 중...');
    const d1Resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${verifiedAccountId}/d1/database`,
      { method: 'POST', headers: verifiedHeaders, body: JSON.stringify({ name: dbName }) }
    ).then(r => r.json()).catch(() => ({}));

    if (d1Resp.result?.uuid) {
      cfD1Database = d1Resp.result.uuid;
      logs.push(`   ✓ D1 Database: ${cfD1Database}`);
    } else {
      logs.push(`   ⚠ D1 생성 실패 — ${d1Resp.errors?.[0]?.message || '알 수 없는 오류'} (계속 진행)`);
    }

    /* Step 4: D1 CMS 스키마 초기화 */
    if (cfD1Database) {
      logs.push('⑤ CMS 데이터베이스 초기화 중...');
      const cmsSchema = getCmsSchema(siteId, siteName, adminPassword, projectName);
      let schemaOk = true;
      for (const sql of cmsSchema) {
        const r = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${verifiedAccountId}/d1/database/${cfD1Database}/query`,
          { method: 'POST', headers: verifiedHeaders, body: JSON.stringify({ sql }) }
        ).catch(() => null);
        if (!r?.ok) schemaOk = false;
      }
      logs.push(`   ${schemaOk ? '✓' : '⚠'} CMS 스키마 초기화 ${schemaOk ? '완료' : '일부 실패 (계속 진행)'}`);
    }

    /* Step 5: KV 사이트 설정 저장 */
    if (cfKvNamespace) {
      logs.push('⑥ CMS 설정 데이터 저장 중...');
      const siteConfig = {
        site_id: siteId, site_name: siteName, site_url: finalSiteUrl, admin_url: finalAdminUrl,
        cms_version: cmsVersion || '1.0.0', created_at: new Date().toISOString(), theme: 'default',
        settings: { title: siteName, tagline: 'CloudPress CMS로 만든 사이트', language: 'ko_KR', timezone: 'Asia/Seoul', posts_per_page: 10 }
      };
      await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${verifiedAccountId}/storage/kv/namespaces/${cfKvNamespace}/values/site_config`,
        { method: 'PUT', headers: { ...verifiedHeaders, 'Content-Type': 'text/plain' }, body: JSON.stringify(siteConfig) }
      ).catch(() => {});
      logs.push('   ✓ CMS 설정 저장 완료');
    }

    /* Step 6: Pages에 CMS 패키지(ZIP) 배포 ← 핵심 수정 */
    logs.push('⑦ CMS 사이트 파일 배포 중...');
    const deployResult = await deployPagesFromPackage(env, {
      accountId: verifiedAccountId,
      projectName,
      cfAuth,
      siteName,
      siteUrl: finalSiteUrl,
      dashboardUrl,
      cmsVersion,           // null이면 KV에서 최신 자동 선택
      kvNamespaceId: cfKvNamespace,
      d1DatabaseId: cfD1Database,
      adminPassword,
      logs,
    });

    if (!deployResult.ok) {
      logs.push(`   ⚠ 배포 경고: ${deployResult.error}`);
    }

    /* Step 7: 사이트 접속 확인 */
    logs.push('⑧ 사이트 구축 확인 중... (최대 2분 소요)');
    let crawlOk = false;
    let crawlStatus = '대기 중';
    const maxWait = 120000;
    const interval = 15000;
    const start = Date.now();

    while (Date.now() - start < maxWait) {
      await new Promise(r => setTimeout(r, interval));
      try {
        const crawlResp = await fetch(finalSiteUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'CloudPress-Crawler/1.0' },
          redirect: 'follow',
          signal: AbortSignal.timeout(10000),
        });
        if (crawlResp.status === 200) {
          const text = await crawlResp.text();
          if (text.includes(siteName) || text.includes('CloudPress') || text.includes('wp-admin')) {
            crawlOk = true; crawlStatus = 'HTTP 200 ✓'; break;
          } else {
            crawlStatus = '응답받음 (콘텐츠 확인 중...)';
          }
        } else if (crawlResp.status === 522 || crawlResp.status === 524) {
          crawlStatus = `배포 전파 중... (${Math.floor((Date.now()-start)/1000)}초)`;
        } else {
          crawlStatus = `HTTP ${crawlResp.status}`;
          if (crawlResp.status < 500) { crawlOk = true; break; }
        }
      } catch (_) {
        crawlStatus = `전파 중... (${Math.floor((Date.now()-start)/1000)}초)`;
      }
    }

    logs.push(`   ${crawlOk ? '✓' : '⚠'} 사이트 접속 확인: ${crawlStatus}`);
    if (!crawlOk) logs.push('   ℹ Cloudflare Pages 전파는 최대 5분이 걸릴 수 있습니다. 잠시 후 접속해주세요.');
    logs.push('✅ CloudPress CMS 구축 완료!');

    return {
      ok: true,
      status: 'active',
      cmsUrl: finalSiteUrl,
      cmsAdminUrl: finalAdminUrl,
      cmsUsername: 'admin',
      cmsPassword: adminPassword,
      cfZoneId: null,
      cfKvNamespace,
      cfD1Database,
      cfPagesProject: projectName,
      projectName,
      crawlVerified: crawlOk,
      deployMode: deployResult.mode || 'unknown',
      deployVersion: deployResult.version || null,
      logs,
    };

  } catch (e) {
    console.error('provisionCmsSite error:', e);
    logs.push(`❌ 예상치 못한 오류: ${e?.message ?? e}`);
    return { ok: false, error: 'CMS 구축 중 오류: ' + (e?.message ?? e), logs };
  }
}

/* CMS D1 스키마 (wp_ 접두사 — cms-schema.sql 동일 구조) */
function getCmsSchema(siteId, siteName, adminPw, projectName) {
  const siteUrl = `https://${projectName}.pages.dev`;
  return [
    `CREATE TABLE IF NOT EXISTS wp_users (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT NOT NULL UNIQUE, user_pass TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL UNIQUE, url TEXT DEFAULT '', user_registered TEXT NOT NULL DEFAULT (datetime('now')), role TEXT NOT NULL DEFAULT 'subscriber', user_status INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, post_author INTEGER NOT NULL DEFAULT 1, post_date TEXT NOT NULL DEFAULT (datetime('now')), post_date_gmt TEXT NOT NULL DEFAULT (datetime('now')), post_content TEXT NOT NULL DEFAULT '', post_title TEXT NOT NULL DEFAULT '', post_excerpt TEXT NOT NULL DEFAULT '', post_status TEXT NOT NULL DEFAULT 'draft', comment_status TEXT NOT NULL DEFAULT 'open', ping_status TEXT NOT NULL DEFAULT 'open', post_name TEXT NOT NULL DEFAULT '', post_modified TEXT NOT NULL DEFAULT (datetime('now')), post_modified_gmt TEXT NOT NULL DEFAULT (datetime('now')), post_parent INTEGER NOT NULL DEFAULT 0, guid TEXT NOT NULL DEFAULT '', menu_order INTEGER NOT NULL DEFAULT 0, post_type TEXT NOT NULL DEFAULT 'post', featured_media INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_postmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, meta_key TEXT NOT NULL DEFAULT '', meta_value TEXT DEFAULT NULL)`,
    `CREATE TABLE IF NOT EXISTS wp_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT NOT NULL UNIQUE, option_value TEXT NOT NULL DEFAULT '', autoload TEXT NOT NULL DEFAULT 'yes')`,
    `CREATE TABLE IF NOT EXISTS wp_terms (term_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', slug TEXT NOT NULL UNIQUE DEFAULT '', term_group INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_term_taxonomy (term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT, term_id INTEGER NOT NULL, taxonomy TEXT NOT NULL DEFAULT '', description TEXT DEFAULT '', parent INTEGER DEFAULT 0, count INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_term_relationships (object_id INTEGER NOT NULL, term_taxonomy_id INTEGER NOT NULL, PRIMARY KEY (object_id, term_taxonomy_id))`,
    `CREATE TABLE IF NOT EXISTS wp_comments (comment_id INTEGER PRIMARY KEY AUTOINCREMENT, comment_post_id INTEGER NOT NULL DEFAULT 0, comment_author TEXT NOT NULL DEFAULT '', comment_author_email TEXT NOT NULL DEFAULT '', comment_content TEXT NOT NULL DEFAULT '', comment_date TEXT NOT NULL DEFAULT (datetime('now')), comment_approved TEXT NOT NULL DEFAULT '1', user_id INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_media (id INTEGER PRIMARY KEY AUTOINCREMENT, file_name TEXT NOT NULL, mime_type TEXT NOT NULL DEFAULT 'image/jpeg', file_size INTEGER DEFAULT 0, width INTEGER DEFAULT 0, height INTEGER DEFAULT 0, post_id INTEGER DEFAULT 0, uploaded_at TEXT DEFAULT (datetime('now')))`,
    `INSERT OR IGNORE INTO wp_users (login,user_pass,display_name,email,role) VALUES ('admin','${adminPw}','관리자','admin@${projectName}.pages.dev','administrator')`,
    `INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('siteurl','${siteUrl}'),('blogname','${siteName.replace(/'/g,"''")}'),('blogdescription','CloudPress CMS로 만든 사이트'),('admin_email','admin@${projectName}.pages.dev'),('posts_per_page','10'),('active_theme','default'),('cms_version','1.0.0'),('permalink_structure','/%year%/%monthnum%/%postname%/'),('timezone_string','Asia/Seoul'),('date_format','Y년 n월 j일'),('time_format','H:i'),('default_comment_status','open'),('show_on_front','posts')`,
    `INSERT OR IGNORE INTO wp_posts (post_author,post_content,post_title,post_excerpt,post_status,post_name,post_type) VALUES (1,'CloudPress CMS에 오신 것을 환영합니다. 이 글을 편집하거나 삭제하고 블로그를 시작해보세요!','안녕하세요!','','publish','hello-world','post'),(1,'이것은 샘플 페이지입니다. 사이드바와는 달리 페이지는 고정된 위치에 있습니다.','샘플 페이지','','publish','sample-page','page')`,
    `INSERT OR IGNORE INTO wp_terms (name,slug) VALUES ('미분류','uncategorized')`,
    `INSERT OR IGNORE INTO wp_term_taxonomy (term_id,taxonomy,description,parent,count) VALUES (1,'category','',0,1)`,
    `INSERT OR IGNORE INTO wp_term_relationships (object_id,term_taxonomy_id) VALUES (1,1)`,
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

    const countRow  = await env.DB.prepare("SELECT COUNT(*) cnt FROM sites WHERE user_id=? AND status!='deleted'").bind(user.id).first();
    const siteCount = countRow?.cnt ?? 0;
    const limit     = SITE_LIMITS[user.plan] ?? 1;
    if (siteCount >= limit) {
      return err(`현재 플랜(${user.plan})에서 최대 ${limit}개 사이트까지 가능합니다. 플랜을 업그레이드해주세요.`, 403);
    }

    const creds = await getUserCfCreds(env, user.id);
    if (!creds) {
      return err('Cloudflare API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 먼저 API 키를 등록해주세요.', 403);
    }

    let projectName = generateProjectName(name.trim());
    for (let i = 0; i < 4; i++) {
      const dup = await env.DB.prepare("SELECT id FROM sites WHERE subdomain=?").bind(projectName).first();
      if (!dup) break;
      projectName = generateProjectName(name.trim());
    }

    const siteId = genId();
    await env.DB.prepare(
      `INSERT INTO sites (id,user_id,name,subdomain,status,plan,cms_version,created_at)
       VALUES (?,?,?,?,'provisioning',?,?,unixepoch())`
    ).bind(siteId, user.id, name.trim(), projectName, user.plan, cms_version || '1.0.0').run();

    const result = await provisionCmsSite(env, {
      siteId,
      siteName:   name.trim(),
      projectName,
      userPlan:   user.plan,
      cmsVersion: cms_version || null,  // null → KV에서 최신 버전 자동 선택
      creds,
    });

    if (!result.ok) {
      await env.DB.prepare("UPDATE sites SET status='error' WHERE id=?").bind(siteId).run();
      return err(result.error, 500);
    }

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
      message: `CloudPress CMS 사이트가 ${result.cmsUrl} 에 구축되었습니다.${result.deployVersion ? ` (CMS v${result.deployVersion})` : ''}`,
      logs:        result.logs,
      deploy_mode: result.deployMode,
    });

  } catch (e) {
    console.error('sites POST error:', e);
    return err('사이트 생성 중 오류 발생: ' + (e?.message ?? e), 500);
  }
}
