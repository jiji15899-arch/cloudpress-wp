// functions/api/sites/[id]/provision.js — CloudPress v15.0
//
// [v15.0 완전 재설계]
// ── 고정 WP Origin URL 완전 제거 ──────────────────────────────────
// ── VP 쿠키(PHPSESSID) 기반 완전 자동화 ──────────────────────────
//
// 흐름:
//   1. vp_accounts에서 사용 가능한 VP 계정 선택
//   2. VP 패널에 PHPSESSID 쿠키로 로그인 (실패 시 user/pass로 재로그인 후 쿠키 갱신)
//   3. VP 패널 API로 서브도메인 자동 생성 ({prefix}.{server_domain})
//   4. VP 패널 API로 DB 생성
//   5. WP 다운로드 → 설치 → wp-config 설정
//   6. WP REST API + cron job 강제 활성화
//   7. 해당 서브도메인을 origin으로 사이트 전용 Worker 빌드/업로드
//   8. CF DNS + Route 등록
//   9. 사용자 개인도메인이 Worker를 통해 서브도메인을 완전히 덮어씀
//      (origin URL = 0 권력 / 개인도메인 = 100 권력)
//
// 아키텍처:
//   [사용자 도메인] → [CF Worker] → [VP 서브도메인(origin)]
//                 ↑ 모든 URL/Cookie/Header에서 origin 흔적 제거

'use strict';

// ── CORS ────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function jsonRes(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
const ok  = (d)      => jsonRes({ ok: true,  ...(d || {}) });
const err = (msg, s) => jsonRes({ ok: false, error: msg }, s || 400);

// ── Auth ────────────────────────────────────────────────────────────
function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    if (!env?.SESSIONS || !env?.DB) return null;
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();
  } catch { return null; }
}

async function getSetting(env, key, fallback = '') {
  try {
    const r = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return (r?.value != null && r.value !== '') ? r.value : fallback;
  } catch { return fallback; }
}

async function updateSite(DB, siteId, fields) {
  const keys = Object.keys(fields);
  if (!keys.length) return;
  const sets = keys.map(k => k + '=?');
  const vals = [...keys.map(k => fields[k]), siteId];
  try {
    await DB.prepare(`UPDATE sites SET ${sets.join(', ')}, updated_at=datetime('now') WHERE id=?`).bind(...vals).run();
  } catch (e) { console.error('updateSite err:', e.message); }
}

async function failSite(DB, siteId, step, message) {
  console.error(`[FAIL] ${step}: ${message}`);
  try {
    await DB.prepare(
      "UPDATE sites SET status='failed', provision_step=?, error_message=?, updated_at=datetime('now') WHERE id=?"
    ).bind(step, String(message).slice(0, 500), siteId).run();
  } catch (e) { console.error('failSite err:', e.message); }
}

function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    const key = salt || 'cp_enc_v1';
    const dec = atob(str);
    let out = '';
    for (let i = 0; i < dec.length; i++) {
      out += String.fromCharCode(dec.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  } catch { return ''; }
}

function randSuffix(len = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

// ── Cloudflare API ───────────────────────────────────────────────────
const CF_API = 'https://api.cloudflare.com/client/v4';

function makeAuth(key, email) {
  if (email && email.includes('@')) return { type: 'global', key, email };
  return { type: 'bearer', value: key };
}

function cfHeaders(auth) {
  if (auth.type === 'global') {
    return { 'Content-Type': 'application/json', 'X-Auth-Email': auth.email, 'X-Auth-Key': auth.key };
  }
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (auth.value || auth.key) };
}

async function cfReq(auth, path, method = 'GET', body) {
  const opts = { method, headers: cfHeaders(auth) };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  try {
    const res  = await fetch(CF_API + path, opts);
    const json = await res.json();
    if (!json.success) console.error(`[cfReq] ${method} ${path} failed:`, JSON.stringify(json.errors || []));
    return json;
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

function cfErrMsg(json) {
  return (json?.errors || []).map(e => (e.code ? `[${e.code}] ` : '') + (e.message || '')).join('; ') || 'unknown';
}

// ── CF 리소스 생성 ───────────────────────────────────────────────────
async function createD1(auth, accountId, prefix) {
  const name = `cp-${prefix}-${Date.now().toString(36)}${randSuffix()}`;
  const res = await cfReq(auth, `/accounts/${accountId}/d1/database`, 'POST', { name });
  if (res.success && res.result) {
    const id = res.result.uuid || res.result.id || res.result.database_id;
    if (id) return { ok: true, id, name };
  }
  return { ok: false, error: 'D1 생성 실패: ' + cfErrMsg(res) };
}

async function createKV(auth, accountId, prefix) {
  const title = `CP_${prefix.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_${Date.now().toString(36).toUpperCase()}`;
  const res = await cfReq(auth, `/accounts/${accountId}/storage/kv/namespaces`, 'POST', { title });
  if (res.success && res.result?.id) return { ok: true, id: res.result.id, title };
  return { ok: false, error: 'KV 생성 실패: ' + cfErrMsg(res) };
}

async function initD1Schema(auth, accountId, d1Id) {
  const sqls = [
    "CREATE TABLE IF NOT EXISTS wp_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT NOT NULL UNIQUE, option_value TEXT NOT NULL DEFAULT '', autoload TEXT NOT NULL DEFAULT 'yes')",
    "CREATE TABLE IF NOT EXISTS wp_posts (ID INTEGER PRIMARY KEY AUTOINCREMENT, post_author INTEGER NOT NULL DEFAULT 0, post_date TEXT NOT NULL DEFAULT (datetime('now')), post_content TEXT NOT NULL DEFAULT '', post_title TEXT NOT NULL DEFAULT '', post_status TEXT NOT NULL DEFAULT 'publish', post_type TEXT NOT NULL DEFAULT 'post', post_name TEXT NOT NULL DEFAULT '', modified_at TEXT NOT NULL DEFAULT (datetime('now')))",
    "CREATE TABLE IF NOT EXISTS wp_users (ID INTEGER PRIMARY KEY AUTOINCREMENT, user_login TEXT NOT NULL UNIQUE, user_pass TEXT NOT NULL, user_email TEXT NOT NULL DEFAULT '', user_registered TEXT NOT NULL DEFAULT (datetime('now')), display_name TEXT NOT NULL DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS cp_site_meta (id INTEGER PRIMARY KEY AUTOINCREMENT, meta_key TEXT NOT NULL UNIQUE, meta_value TEXT, updated_at TEXT NOT NULL DEFAULT (datetime('now')))",
  ];
  for (const sql of sqls) {
    try {
      await cfReq(auth, `/accounts/${accountId}/d1/database/${d1Id}/query`, 'POST', { sql });
    } catch (_) {}
  }
}

async function initKVData(auth, accountId, kvId, data) {
  const hdrs = { ...cfHeaders(auth) };
  delete hdrs['Content-Type'];
  for (const [key, val] of Object.entries(data)) {
    try {
      await fetch(
        `${CF_API}/accounts/${accountId}/storage/kv/namespaces/${kvId}/values/${encodeURIComponent(key)}`,
        { method: 'PUT', headers: hdrs, body: typeof val === 'string' ? val : JSON.stringify(val) }
      );
    } catch (_) {}
  }
}

async function findPagesProjectName(auth, accountId) {
  try {
    const r = await cfReq(auth, `/accounts/${accountId}/pages/projects?per_page=50`);
    if (r.success && Array.isArray(r.result)) {
      for (const p of r.result) {
        if (p.name?.toLowerCase().includes('cloudpress')) return p.name;
      }
      if (r.result.length > 0) return r.result[0].name;
    }
  } catch (_) {}
  return null;
}

async function resolveMainBindingIds(auth, accountId, projectName, DB) {
  const result = { mainDbId: '', cacheKvId: '', sessionsKvId: '' };
  try {
    const r = await cfReq(auth, `/accounts/${accountId}/pages/projects/${projectName}`);
    if (!r.success || !r.result) return result;
    const prod  = r.result.deployment_configs?.production || {};
    const d1Cfg = prod.d1_databases  || {};
    const kvCfg = prod.kv_namespaces || {};
    if (d1Cfg['DB']?.id)       result.mainDbId     = d1Cfg['DB'].id;
    if (kvCfg['SESSIONS']?.id) result.sessionsKvId = kvCfg['SESSIONS'].id;
    if (kvCfg['CACHE']?.id)    result.cacheKvId    = kvCfg['CACHE'].id;
    const upsert = "INSERT INTO settings (key,value,updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at";
    if (result.mainDbId)     try { await DB.prepare(upsert).bind('main_db_id', result.mainDbId).run(); } catch(_){}
    if (result.sessionsKvId) try { await DB.prepare(upsert).bind('sessions_kv_id', result.sessionsKvId).run(); } catch(_){}
    if (result.cacheKvId)    try { await DB.prepare(upsert).bind('cache_kv_id', result.cacheKvId).run(); } catch(_){}
  } catch (_) {}
  return result;
}

async function cfGetZone(auth, domain) {
  const parts = domain.split('.');
  const root2 = parts.slice(-2).join('.');
  const root3 = parts.length >= 3 ? parts.slice(-3).join('.') : root2;
  let res = await cfReq(auth, `/zones?name=${encodeURIComponent(root2)}&status=active`);
  if (res.success && res.result?.length > 0) return { ok: true, zoneId: res.result[0].id };
  if (root3 !== root2) {
    res = await cfReq(auth, `/zones?name=${encodeURIComponent(root3)}&status=active`);
    if (res.success && res.result?.length > 0) return { ok: true, zoneId: res.result[0].id };
  }
  return { ok: false };
}

async function cfUpsertDns(auth, zoneId, type, name, content, proxied) {
  const list = await cfReq(auth, `/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`);
  const existing = list?.result?.[0] || null;
  const payload  = { type, name, content, proxied, ttl: 1 };
  if (existing) {
    const r = await cfReq(auth, `/zones/${zoneId}/dns_records/${existing.id}`, 'PUT', payload);
    return r.success ? { ok: true, recordId: existing.id } : { ok: false, error: cfErrMsg(r) };
  }
  const r = await cfReq(auth, `/zones/${zoneId}/dns_records`, 'POST', payload);
  return r.success ? { ok: true, recordId: r.result?.id } : { ok: false, error: cfErrMsg(r) };
}

async function cfUpsertRoute(auth, zoneId, pattern, script) {
  const list = await cfReq(auth, `/zones/${zoneId}/workers/routes`);
  const exist = list?.result?.find(r => r.pattern === pattern) || null;
  const payload = { pattern, script };
  if (exist) {
    const r = await cfReq(auth, `/zones/${zoneId}/workers/routes/${exist.id}`, 'PUT', payload);
    return r.success ? { ok: true, routeId: exist.id } : { ok: false, error: cfErrMsg(r) };
  }
  const r = await cfReq(auth, `/zones/${zoneId}/workers/routes`, 'POST', payload);
  return r.success ? { ok: true, routeId: r.result?.id } : { ok: false, error: cfErrMsg(r) };
}

async function getWorkerSubdomain(auth, accountId, workerName) {
  try {
    const r = await cfReq(auth, `/accounts/${accountId}/workers/subdomain`);
    if (r.success && r.result?.subdomain) return `${workerName}.${r.result.subdomain}.workers.dev`;
  } catch (_) {}
  return `${workerName}.workers.dev`;
}

// ══════════════════════════════════════════════════════════════════
// VP 패널 자동화 — 멀티 패널 자동 감지
//
// 지원 패널:
//   HestiaCP   — :8083  POST /login/      web: /add/web/   db: /add/db/
//   VestaCP    — :8083  POST /vpanel/login web: /vpanel/web/add
//   CyberPanel — :8090  REST JSON API     (Authorization: Basic)
//   aaPanel    — :7800  POST /login       cookie: session  web: /site  db: /database
//   DirectAdmin— :2222  GET  /CMD_LOGIN   web: /CMD_API    (session cookie)
//   Plesk      — :8443  POST /login_up.php web: /api/v2/domains
// ══════════════════════════════════════════════════════════════════

// ── 공통 헬퍼 ──────────────────────────────────────────────────────

function isAlreadyExists(text, status) {
  const t = String(text).toLowerCase();
  return status === 409 ||
    t.includes('exist') || t.includes('already') ||
    t.includes('duplicate') || t.includes('이미');
}

function isSessionExpired(status) {
  return status === 401 || status === 403;
}

// 응답 텍스트 파싱 (JSON 우선, 실패하면 text)
function parseRes(text) {
  try { return JSON.parse(text); } catch { return text; }
}

// 응답 요약 (에러 메시지용, 100자)
function resSummary(data) {
  return String(typeof data === 'object' ? JSON.stringify(data) : data).slice(0, 100);
}

// ── 패널 감지 ──────────────────────────────────────────────────────
//
// panelUrl의 포트·응답 헤더·응답 본문으로 패널 종류를 추론한다.
// 반환: 'hestia' | 'vesta' | 'cyberpanel' | 'aapanel' | 'directadmin' | 'plesk' | 'unknown'

async function detectPanelType(panelUrl) {
  // 1) 포트 기반 1차 추론
  try {
    const u = new URL(panelUrl);
    const port = u.port || (u.protocol === 'https:' ? '443' : '80');
    if (port === '8090') return 'cyberpanel';
    if (port === '7800' || port === '7788') return 'aapanel';
    if (port === '2222') return 'directadmin';
    if (port === '8443') return 'plesk';
    // 8083 = HestiaCP 또는 VestaCP → 응답으로 구분
  } catch (_) {}

  // 2) 루트(/) GET 응답 내용으로 구분
  try {
    const res = await fetch(panelUrl + '/', {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(6000),
    });
    const text = (await res.text().catch(() => '')).toLowerCase();
    const server = (res.headers.get('server') || '').toLowerCase();

    if (text.includes('hestia') || text.includes('hestiacp'))   return 'hestia';
    if (text.includes('vesta')  || text.includes('vestacp'))    return 'vesta';
    if (text.includes('cyberpanel'))                            return 'cyberpanel';
    if (text.includes('aapanel') || text.includes('宝塔'))      return 'aapanel';
    if (text.includes('directadmin'))                           return 'directadmin';
    if (text.includes('plesk'))                                 return 'plesk';
    if (server.includes('hestia'))                              return 'hestia';

    // /login/ 경로 존재 여부로 Hestia vs Vesta 구분
    const r2 = await fetch(panelUrl + '/login/', {
      method: 'GET', redirect: 'manual',
      signal: AbortSignal.timeout(4000),
    });
    if (r2.status !== 404) return 'hestia';

    const r3 = await fetch(panelUrl + '/vpanel/', {
      method: 'GET', redirect: 'manual',
      signal: AbortSignal.timeout(4000),
    });
    if (r3.status !== 404) return 'vesta';
  } catch (_) {}

  return 'unknown';
}

// ── HTTP 요청 헬퍼 ─────────────────────────────────────────────────

// 폼 POST (302/303도 성공으로 처리)
async function formPost(url, cookieHeader, params, extraHeaders = {}) {
  const body = Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
        ...(cookieHeader ? { 'Cookie': cookieHeader } : {}),
        ...extraHeaders,
      },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text().catch(() => '');
    const ok   = res.ok || res.status === 302 || res.status === 303;
    return { ok, status: res.status, data: parseRes(text), headers: res.headers };
  } catch (e) {
    return { ok: false, status: 0, data: e.message, headers: new Headers() };
  }
}

// JSON POST (CyberPanel, aaPanel REST)
async function jsonPost(url, authHeader, body) {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authHeader ? { 'Authorization': authHeader } : {}),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text().catch(() => '');
    return { ok: res.ok, status: res.status, data: parseRes(text) };
  } catch (e) {
    return { ok: false, status: 0, data: e.message };
  }
}

// GET (DirectAdmin CMD_API)
async function httpGet(url, cookieHeader, extraHeaders = {}) {
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        ...(cookieHeader ? { 'Cookie': cookieHeader } : {}),
        ...extraHeaders,
      },
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
    const text = await res.text().catch(() => '');
    return { ok: res.ok || res.status === 302, status: res.status, data: parseRes(text), headers: res.headers };
  } catch (e) {
    return { ok: false, status: 0, data: e.message, headers: new Headers() };
  }
}

// Set-Cookie에서 특정 쿠키 값 추출
function extractCookie(headers, name) {
  const setCookie = headers.get('set-cookie') || '';
  // 여러 Set-Cookie가 쉼표로 이어질 수 있음
  const re = new RegExp(`(?:^|,\\s*)${name}=([^;,\\s]+)`, 'i');
  const m  = setCookie.match(re);
  return m ? m[1] : null;
}

// ── 패널별 로그인 ──────────────────────────────────────────────────

async function loginHestia(panelUrl, username, password) {
  const res = await formPost(`${panelUrl}/login/`, null,
    { username, password });
  const sid = extractCookie(res.headers, 'PHPSESSID');
  if (sid) return { ok: true, cookie: `PHPSESSID=${sid}`, type: 'hestia' };
  if (res.status === 302 || res.status === 200) {
    // 일부 버전은 phpsessid 없이 다른 쿠키 사용
    const raw = res.headers.get('set-cookie') || '';
    if (raw) {
      // 첫 번째 쿠키값 그대로 사용
      const cookieVal = raw.split(';')[0].trim();
      if (cookieVal) return { ok: true, cookie: cookieVal, type: 'hestia' };
    }
  }
  return { ok: false, error: `HestiaCP 로그인 실패 (HTTP ${res.status})` };
}

async function loginVesta(panelUrl, username, password) {
  const res = await formPost(`${panelUrl}/vpanel/login`, null,
    { username, password });
  const sid = extractCookie(res.headers, 'PHPSESSID');
  if (sid) return { ok: true, cookie: `PHPSESSID=${sid}`, type: 'vesta' };
  return { ok: false, error: `VestaCP 로그인 실패 (HTTP ${res.status})` };
}

async function loginCyberPanel(panelUrl, username, password) {
  // CyberPanel: Basic Auth (세션 불필요, 매 요청마다 인증)
  const b64 = btoa(`${username}:${password}`);
  // 인증 확인
  const res = await jsonPost(`${panelUrl}/api/verifyConn`, `Basic ${b64}`, {});
  if (res.ok || res.status === 200) {
    return { ok: true, cookie: `__auth=Basic ${b64}`, type: 'cyberpanel', basicAuth: `Basic ${b64}` };
  }
  return { ok: false, error: `CyberPanel 로그인 실패 (HTTP ${res.status})` };
}

async function loginAaPanel(panelUrl, username, password) {
  // aaPanel: POST /login → session 쿠키
  const res = await formPost(`${panelUrl}/login`, null,
    { username, password, code: '', login_token: '', totp_code: '' });
  const sid = extractCookie(res.headers, 'session');
  if (sid) return { ok: true, cookie: `session=${sid}`, type: 'aapanel' };
  // 일부 버전
  const sid2 = extractCookie(res.headers, 'request_token');
  if (sid2) return { ok: true, cookie: `request_token=${sid2}`, type: 'aapanel' };
  return { ok: false, error: `aaPanel 로그인 실패 (HTTP ${res.status})` };
}

async function loginDirectAdmin(panelUrl, username, password) {
  // DirectAdmin: GET /CMD_LOGIN → session 쿠키
  const cred = `${encodeURIComponent(username)}:${encodeURIComponent(password)}`;
  const res  = await httpGet(`${panelUrl}/CMD_LOGIN?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`);
  const sid  = extractCookie(res.headers, 'session');
  if (sid) return { ok: true, cookie: `session=${sid}`, type: 'directadmin' };
  // Basic Auth 폴백
  const b64 = btoa(`${username}:${password}`);
  return { ok: true, cookie: '', type: 'directadmin', basicAuth: `Basic ${b64}` };
}

async function loginPlesk(panelUrl, username, password) {
  const res = await formPost(`${panelUrl}/login_up.php`, null,
    { login_name: username, passwd: password });
  const sid = extractCookie(res.headers, 'PLESKSESSID') ||
              extractCookie(res.headers, 'PHPSESSID');
  if (sid) return { ok: true, cookie: `PLESKSESSID=${sid}`, type: 'plesk' };
  return { ok: false, error: `Plesk 로그인 실패 (HTTP ${res.status})` };
}

// ── 통합 로그인 (패널 타입 자동 감지 + 로그인) ────────────────────

async function vpDetectAndLogin(panelUrl, username, password, cachedType) {
  const tryLogin = async (type) => {
    if (type === 'hestia')      return loginHestia(panelUrl, username, password);
    if (type === 'vesta')       return loginVesta(panelUrl, username, password);
    if (type === 'cyberpanel')  return loginCyberPanel(panelUrl, username, password);
    if (type === 'aapanel')     return loginAaPanel(panelUrl, username, password);
    if (type === 'directadmin') return loginDirectAdmin(panelUrl, username, password);
    if (type === 'plesk')       return loginPlesk(panelUrl, username, password);
    return { ok: false, error: 'unknown type' };
  };

  // 캐시된 타입 우선 시도
  if (cachedType && cachedType !== 'unknown') {
    const r = await tryLogin(cachedType);
    if (r.ok) return r;
    console.warn(`[vpLogin] 캐시 타입(${cachedType}) 로그인 실패, 재감지...`);
  }

  // 패널 감지 후 로그인
  const detected = await detectPanelType(panelUrl);
  console.log(`[vpLogin] 감지된 패널: ${detected}`);
  const r = await tryLogin(detected);
  if (r.ok) return r;

  // unknown이거나 감지 실패 → 모든 타입 순차 시도
  if (detected === 'unknown' || !r.ok) {
    for (const t of ['hestia', 'vesta', 'aapanel', 'cyberpanel', 'directadmin', 'plesk']) {
      if (t === detected) continue;
      const fallback = await tryLogin(t);
      if (fallback.ok) {
        console.log(`[vpLogin] 폴백 성공: ${t}`);
        return fallback;
      }
    }
  }

  return { ok: false, error: `패널 로그인 실패 (감지: ${detected}): ${r.error}` };
}

// ── 세션 확인 + 재로그인 ───────────────────────────────────────────

async function ensureVpSession(DB, vpAccount) {
  const { id, panel_url, vp_username, vp_password, phpsessid, panel_type } = vpAccount;

  // 기존 저장 쿠키/세션으로 유효성 확인
  if (phpsessid) {
    // 패널별 ping 경로
    const pingPaths = ['/list/web/', '/vpanel/api/status', '/api/verifyConn', '/'];
    for (const path of pingPaths) {
      try {
        const res = await fetch(`${panel_url}${path}`, {
          method: 'GET',
          headers: { 'Cookie': phpsessid },
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        });
        // 401/403/0 = 만료, 나머지 = 살아있음
        if (res.status !== 401 && res.status !== 403 && res.status !== 0) {
          return { ok: true, phpsessid, cookie: phpsessid };
        }
        break; // 첫 응답에서 만료 확인 → 재로그인
      } catch (_) {}
    }
  }

  // 재로그인
  console.log('[provision] VP 세션 만료 또는 없음 → 재로그인');
  const loginRes = await vpDetectAndLogin(panel_url, vp_username, vp_password, panel_type);
  if (!loginRes.ok) {
    if (phpsessid) {
      console.warn('[provision] 재로그인 실패, 기존 세션으로 계속 시도:', loginRes.error);
      return { ok: true, phpsessid, cookie: phpsessid, stale: true };
    }
    return { ok: false, error: loginRes.error };
  }

  const newCookie    = loginRes.cookie;
  const detectedType = loginRes.type;

  // DB에 세션 + 패널 타입 갱신
  try {
    await DB.prepare(
      "UPDATE vp_accounts SET phpsessid=?, phpsessid_updated_at=datetime('now'), updated_at=datetime('now') WHERE id=?"
    ).bind(newCookie, id).run();
  } catch (_) {}

  return { ok: true, phpsessid: newCookie, cookie: newCookie, panelType: detectedType, basicAuth: loginRes.basicAuth };
}

// ── 패널별 서브도메인 생성 ─────────────────────────────────────────

async function vpCreateSubdomain(panelUrl, sessionInfo, subdomain, serverDomain) {
  const fullDomain = `${subdomain}.${serverDomain}`;
  console.log(`[provision] VP 서브도메인 생성: ${fullDomain}`);

  const { cookie, basicAuth, panelType } = sessionInfo;
  const tried = [];

  // ── HestiaCP ──
  if (!panelType || panelType === 'hestia' || panelType === 'unknown') {
    tried.push('hestia');
    const res = await formPost(`${panelUrl}/add/web/`, cookie, {
      v_domain:  fullDomain,
      v_ip:      'default',
      v_aliases: '',
      v_stats:   'awstats',
      v_ssl:     '0',
    });
    if (res.ok) { console.log(`[provision] HestiaCP 서브도메인 성공 (${res.status})`); return { ok: true, domain: fullDomain }; }
    if (isAlreadyExists(res.data, res.status)) return { ok: true, domain: fullDomain, existed: true };
    if (isSessionExpired(res.status)) return { ok: false, error: `세션 만료 (${res.status})`, sessionExpired: true };
    if (res.status !== 404) {
      console.warn(`[provision] HestiaCP /add/web/ 실패: ${res.status} ${resSummary(res.data)}`);
    }
  }

  // ── VestaCP ──
  if (!panelType || panelType === 'vesta' || panelType === 'unknown') {
    tried.push('vesta');
    const res = await formPost(`${panelUrl}/vpanel/web/add`, cookie, {
      domain: fullDomain,
      ip:     'default',
    });
    if (res.ok) { console.log(`[provision] VestaCP 서브도메인 성공`); return { ok: true, domain: fullDomain }; }
    if (isAlreadyExists(res.data, res.status)) return { ok: true, domain: fullDomain, existed: true };
    if (res.status !== 404) {
      console.warn(`[provision] VestaCP /vpanel/web/add 실패: ${res.status} ${resSummary(res.data)}`);
    }
  }

  // ── CyberPanel ──
  if (!panelType || panelType === 'cyberpanel' || panelType === 'unknown') {
    tried.push('cyberpanel');
    const auth = basicAuth || cookie?.replace('__auth=', '');
    const res  = await jsonPost(`${panelUrl}/api/createWebsite`, auth, {
      domainName:    fullDomain,
      adminEmail:    `admin@${serverDomain}`,
      websiteOwner:  'admin',
      packageName:   'Default',
      websiteOwnerEmail: `admin@${serverDomain}`,
    });
    if (res.ok || (res.data?.status === 1)) { console.log(`[provision] CyberPanel 서브도메인 성공`); return { ok: true, domain: fullDomain }; }
    if (isAlreadyExists(JSON.stringify(res.data), res.status)) return { ok: true, domain: fullDomain, existed: true };
    if (res.status !== 404 && res.status !== 0) {
      console.warn(`[provision] CyberPanel 실패: ${res.status} ${resSummary(res.data)}`);
    }
  }

  // ── aaPanel ──
  if (!panelType || panelType === 'aapanel' || panelType === 'unknown') {
    tried.push('aapanel');
    const res = await formPost(`${panelUrl}/site`, cookie, {
      action:  'AddSite',
      webname: JSON.stringify({
        domain:   fullDomain,
        domainlist: [],
        count:    0,
      }),
      type:     '0',
      port:     '80',
      ps:       fullDomain,
      path:     `/www/wwwroot/${fullDomain}`,
      datauser: '',
      datapassword: '',
      codeing:  'utf8',
      mysql:    'mysql',
      version:  '80',
      rahter:   '0',
    });
    if (res.ok) { console.log(`[provision] aaPanel 서브도메인 성공`); return { ok: true, domain: fullDomain }; }
    if (isAlreadyExists(res.data, res.status)) return { ok: true, domain: fullDomain, existed: true };
    if (res.status !== 404 && res.status !== 0) {
      console.warn(`[provision] aaPanel 실패: ${res.status} ${resSummary(res.data)}`);
    }
  }

  // ── DirectAdmin ──
  if (!panelType || panelType === 'directadmin' || panelType === 'unknown') {
    tried.push('directadmin');
    const auth = basicAuth ? { 'Authorization': basicAuth } : {};
    const qs   = new URLSearchParams({
      action:  'create',
      domain:  fullDomain,
      ip:      'shared',
      php:     'ON',
      ssl:     'OFF',
    }).toString();
    const res  = await httpGet(`${panelUrl}/CMD_API_DOMAIN?${qs}`, cookie, auth);
    if (res.ok) { console.log(`[provision] DirectAdmin 서브도메인 성공`); return { ok: true, domain: fullDomain }; }
    if (isAlreadyExists(res.data, res.status)) return { ok: true, domain: fullDomain, existed: true };
    if (res.status !== 404 && res.status !== 0) {
      console.warn(`[provision] DirectAdmin 실패: ${res.status} ${resSummary(res.data)}`);
    }
  }

  // ── Plesk ──
  if (!panelType || panelType === 'plesk' || panelType === 'unknown') {
    tried.push('plesk');
    const res = await jsonPost(`${panelUrl}/api/v2/domains`, null, {
      name:        fullDomain,
      hosting_type: 'virtual',
      hosting_settings: { ftp_login: subdomain.replace(/[^a-z0-9]/g, ''), ftp_password: 'Cp' + subdomain },
    });
    if (res.ok) { console.log(`[provision] Plesk 서브도메인 성공`); return { ok: true, domain: fullDomain }; }
    if (isAlreadyExists(JSON.stringify(res.data), res.status)) return { ok: true, domain: fullDomain, existed: true };
    if (res.status !== 404 && res.status !== 0) {
      console.warn(`[provision] Plesk 실패: ${res.status} ${resSummary(res.data)}`);
    }
  }

  console.error(`[provision] 서브도메인 생성 전체 실패. 시도한 패널: ${tried.join(', ')}`);
  return {
    ok: false,
    error: `서브도메인 생성 실패 — 감지된 패널(${panelType || 'unknown'})의 API 경로가 모두 404입니다. ` +
           `panel_url(${panelUrl})과 패널 종류를 확인해주세요. 시도: ${tried.join(', ')}`,
  };
}

// ── 패널별 DB 생성 ─────────────────────────────────────────────────

async function vpCreateDatabase(panelUrl, sessionInfo, dbName, dbUser, dbPass) {
  console.log(`[provision] VP DB 생성: ${dbName}`);
  const { cookie, basicAuth, panelType } = sessionInfo;

  // HestiaCP
  if (!panelType || panelType === 'hestia' || panelType === 'unknown') {
    const res = await formPost(`${panelUrl}/add/db/`, cookie, {
      v_database: dbName, v_dbuser: dbUser, v_dbpass: dbPass,
      v_host: 'localhost', v_type: 'mysql', v_charset: 'utf8mb4',
    });
    if (res.ok) return { ok: true };
    if (isAlreadyExists(res.data, res.status)) return { ok: true, existed: true };
    if (res.status !== 404) console.warn(`[provision] HestiaCP /add/db/ 실패: ${res.status}`);
  }

  // VestaCP
  if (!panelType || panelType === 'vesta' || panelType === 'unknown') {
    const res = await formPost(`${panelUrl}/vpanel/db/add`, cookie, {
      database: dbName, dbuser: dbUser, password: dbPass, host: 'localhost',
    });
    if (res.ok) return { ok: true };
    if (isAlreadyExists(res.data, res.status)) return { ok: true, existed: true };
    if (res.status !== 404) console.warn(`[provision] VestaCP /vpanel/db/add 실패: ${res.status}`);
  }

  // CyberPanel
  if (!panelType || panelType === 'cyberpanel' || panelType === 'unknown') {
    const auth = basicAuth || cookie?.replace('__auth=', '');
    const res  = await jsonPost(`${panelUrl}/api/createDatabase`, auth, {
      databaseWebsite: dbName, dbName, dbUsername: dbUser, dbPassword: dbPass,
    });
    if (res.ok || res.data?.status === 1) return { ok: true };
    if (isAlreadyExists(JSON.stringify(res.data), res.status)) return { ok: true, existed: true };
  }

  // aaPanel
  if (!panelType || panelType === 'aapanel' || panelType === 'unknown') {
    const res = await formPost(`${panelUrl}/database`, cookie, {
      action: 'AddDatabase', name: dbName, username: dbUser,
      password: dbPass, codeing: 'utf8mb4', address: 'localhost',
      port: '3306', dtype: 'mysql', accept: dbUser,
    });
    if (res.ok) return { ok: true };
    if (isAlreadyExists(res.data, res.status)) return { ok: true, existed: true };
  }

  // DirectAdmin
  if (!panelType || panelType === 'directadmin' || panelType === 'unknown') {
    const auth = basicAuth ? { 'Authorization': basicAuth } : {};
    const qs   = new URLSearchParams({
      action: 'create', name: dbName, passwd: dbPass, passwd2: dbPass, user: dbUser,
    }).toString();
    const res  = await httpGet(`${panelUrl}/CMD_API_DATABASES?${qs}`, cookie, auth);
    if (res.ok) return { ok: true };
    if (isAlreadyExists(res.data, res.status)) return { ok: true, existed: true };
  }

  return { ok: false, error: `DB 생성 실패 (패널: ${panelType || 'unknown'})` };
}

// ── WP 설치 명령 실행 ──────────────────────────────────────────────

async function vpInstallWordPress(panelUrl, sessionInfo, params) {
  const {
    webRoot, subdomain, serverDomain, dbName, dbUser, dbPass,
    siteUrl, siteTitle, wpUser, wpPass, wpEmail, wpDownloadUrl, phpBin,
  } = params;

  const { cookie, basicAuth, panelType } = sessionInfo;
  const fullDomain = `${subdomain}.${serverDomain}`;
  const docRoot    = `${webRoot}/${fullDomain}/public_html`;
  const wpZip      = wpDownloadUrl || 'https://ko.wordpress.org/latest-ko_KR.zip';

  const cmds = [
    `cd /tmp && curl -fsSL "${wpZip}" -o wp.zip && unzip -q wp.zip -d wp_src`,
    `mkdir -p "${docRoot}" && cp -r /tmp/wp_src/wordpress/. "${docRoot}/" && rm -rf /tmp/wp.zip /tmp/wp_src`,
    `cp "${docRoot}/wp-config-sample.php" "${docRoot}/wp-config.php"`,
    `sed -i "s/database_name_here/${dbName}/g" "${docRoot}/wp-config.php"`,
    `sed -i "s/username_here/${dbUser}/g" "${docRoot}/wp-config.php"`,
    `sed -i "s/password_here/${dbPass}/g" "${docRoot}/wp-config.php"`,
    `echo "define('DISABLE_WP_CRON', true);" >> "${docRoot}/wp-config.php"`,
    `echo "remove_all_filters('rest_authentication_errors');" >> "${docRoot}/wp-config.php"`,
    `echo "define('WP_HOME','${siteUrl}'); define('WP_SITEURL','${siteUrl}');" >> "${docRoot}/wp-config.php"`,
    `cd "${docRoot}" && wp core install --url="${siteUrl}" --title="${siteTitle}" --admin_user="${wpUser}" --admin_password="${wpPass}" --admin_email="${wpEmail}" --skip-email --allow-root 2>/dev/null || true`,
    `cd "${docRoot}" && wp cron event schedule wp_version_check now --allow-root 2>/dev/null || true`,
    `cd "${docRoot}" && wp rewrite flush --allow-root 2>/dev/null || true`,
    `chown -R www-data:www-data "${docRoot}" 2>/dev/null || chown -R apache:apache "${docRoot}" 2>/dev/null || true`,
    `find "${docRoot}" -type d -exec chmod 755 {} \\; 2>/dev/null || true`,
    `find "${docRoot}" -type f -exec chmod 644 {} \\; 2>/dev/null || true`,
  ];
  const fullCmd = cmds.join(' && ');

  // HestiaCP / VestaCP exec
  const execPaths = [
    { path: '/exec/cmd/',       params: { v_cmd: fullCmd } },                        // HestiaCP
    { path: '/vpanel/cmd/exec', params: { cmd: fullCmd, php: phpBin || 'php8.3' } }, // VestaCP
  ];
  for (const ep of execPaths) {
    const res = await formPost(`${panelUrl}${ep.path}`, cookie, ep.params);
    if (res.ok) return { ok: true, output: String(res.data).slice(0, 500) };
  }

  // CyberPanel exec
  if (!panelType || panelType === 'cyberpanel' || panelType === 'unknown') {
    const auth = basicAuth || cookie?.replace('__auth=', '');
    const res  = await jsonPost(`${panelUrl}/api/runCommand`, auth, { command: fullCmd });
    if (res.ok) return { ok: true, output: String(res.data).slice(0, 500) };
  }

  // aaPanel exec
  if (!panelType || panelType === 'aapanel' || panelType === 'unknown') {
    const res = await formPost(`${panelUrl}/system`, cookie, {
      action: 'RunShell', shell: fullCmd,
    });
    if (res.ok) return { ok: true, output: String(res.data).slice(0, 500) };
  }

  console.warn('[provision] WP 설치 명령 직접 실행 불가 (수동 설치 필요)');
  return { ok: true, skipped: true, message: 'WP 설치 명령 직접 실행 불가 (수동 설치 필요)' };
}

// WP REST API 강제 활성화 확인
async function verifyAndActivateRestApi(originUrl) {
  try {
    const res = await fetch(`${originUrl}/wp-json/`, {
      method: 'GET',
      headers: { 'User-Agent': 'CloudPress/15.0' },
    });
    if (res.ok) return { ok: true };
    return { ok: false, status: res.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ══════════════════════════════════════════════════════════════════
// Worker 소스 생성 (v15.0 — origin 완전 흔적 제거 + cron 강제)
// ══════════════════════════════════════════════════════════════════
function buildWorkerSource() {
  const L = [];

  L.push("'use strict';");
  L.push("export default {");
  L.push("  async fetch(request, env) {");

  // null 가드
  L.push("    if (!env?.DB)    return errPage(503, '서버 설정 오류', 'DB 바인딩 없음');");
  L.push("    if (!env?.CACHE) return errPage(503, '서버 설정 오류', 'CACHE 바인딩 없음');");
  L.push("    const wpOriginUrl = (env.WP_ORIGIN_URL || '').trim().replace(/\\/+$/, '');");
  L.push("    if (!wpOriginUrl) return errPage(503, '서버 설정 오류', 'WP_ORIGIN_URL 미설정');");

  // URL 파싱
  L.push("    const url            = new URL(request.url);");
  L.push("    const rawHost        = url.hostname;");
  L.push("    const host           = rawHost.replace(/^www\\./, '');");
  L.push("    const personalOrigin = 'https://' + rawHost;");
  L.push("    let wpOriginHost;");
  L.push("    try { wpOriginHost = new URL(wpOriginUrl).hostname; } catch { wpOriginHost = ''; }");

  // 내부 경로 통과
  L.push("    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/__cloudpress/')) return fetch(request);");

  // ── CF Cron Trigger: /wp-cron.php 자동 실행
  L.push("    // ── CF Cron: /wp-cron (예약 이벤트 강제 실행) ───");
  L.push("    if (url.pathname === '/__cp_cron') {");
  L.push("      const site2 = await getSiteByHost(env, host);");
  L.push("      if (site2 && wpOriginUrl) {");
  L.push("        const cronUrl = wpOriginUrl + '/wp-cron.php?doing_wp_cron=1';");
  L.push("        fetch(cronUrl, { method: 'GET', headers: { 'X-CloudPress-Secret': env.WP_ORIGIN_SECRET || '' } }).catch(() => {});");
  L.push("      }");
  L.push("      return new Response('ok', { status: 200 });");
  L.push("    }");

  // 사이트 조회
  L.push("    const site = await getSiteByHost(env, host);");
  L.push("    if (!site) return errPage(404, '사이트 없음', host + ' 에 연결된 사이트가 없습니다.');");
  L.push("    if (site.suspended) return suspendedPage(site.name, site.suspension_reason);");

  // 페이지 캐시 (wp-admin 제외)
  L.push("    const isAdmin = url.pathname.startsWith('/wp-admin') || url.pathname === '/wp-login.php';");
  L.push("    const isCacheable = !isAdmin && request.method === 'GET'");
  L.push("      && !url.pathname.startsWith('/wp-')");
  L.push("      && !url.searchParams.has('preview')");
  L.push("      && !(request.headers.get('cookie') || '').includes('wordpress_logged_in');");
  L.push("    if (isCacheable && env.SITE_KV) {");
  L.push("      try {");
  L.push("        const ck = 'page:' + url.pathname + (url.search || '');");
  L.push("        const cached = await env.SITE_KV.get(ck, { type: 'json' });");
  L.push("        if (cached?.body) return new Response(cached.body, { headers: { 'Content-Type': cached.contentType || 'text/html;charset=utf-8', 'X-Cache': 'HIT' } });");
  L.push("      } catch (_) {}");
  L.push("    }");

  // 프록시 (모든 경로 통합, wp-admin 포함)
  L.push("    const target = new URL(wpOriginUrl + url.pathname + url.search);");
  L.push("    const ph = new Headers(request.headers);");
  L.push("    ph.set('X-CloudPress-Site',       site.site_prefix || '');");
  L.push("    ph.set('X-CloudPress-Secret',     env.WP_ORIGIN_SECRET || '');");
  L.push("    ph.set('X-CloudPress-Domain',     rawHost);");
  L.push("    ph.set('X-CloudPress-Public-URL', personalOrigin);");
  L.push("    ph.set('Host',                    wpOriginHost || target.hostname);");
  L.push("    ph.set('X-Forwarded-Host',        rawHost);");
  L.push("    ph.set('X-Forwarded-Proto',       'https');");
  L.push("    ph.set('X-Real-IP',               request.headers.get('CF-Connecting-IP') || '');");
  // REST API 강제 허용
  L.push("    ph.delete('X-WP-Nonce'); // nonce 문제 방지");

  L.push("    let oRes;");
  L.push("    try { oRes = await fetch(target.toString(), { method: request.method, headers: ph, body: ['GET','HEAD'].includes(request.method) ? null : request.body, redirect: 'manual' }); }");
  L.push("    catch (e) { return errPage(502, 'Origin 오류', e.message); }");

  // 리다이렉트 처리
  L.push("    if (oRes.status >= 300 && oRes.status < 400) {");
  L.push("      let loc = oRes.headers.get('Location') || '';");
  L.push("      loc = rewriteStr(loc, wpOriginUrl, personalOrigin, wpOriginHost, rawHost);");
  L.push("      const rh = new Headers();");
  L.push("      rh.set('Location', loc);");
  L.push("      for (const [k, v] of oRes.headers) {");
  L.push("        if (k.toLowerCase() === 'set-cookie') rh.append('Set-Cookie', rewriteCookie(v, wpOriginHost, rawHost));");
  L.push("      }");
  L.push("      return new Response(null, { status: oRes.status, headers: rh });");
  L.push("    }");

  // 응답 헤더
  L.push("    const skip = new Set(['transfer-encoding','content-encoding','content-length','connection','keep-alive']);");
  L.push("    const rh = new Headers();");
  L.push("    for (const [k, v] of oRes.headers) {");
  L.push("      if (skip.has(k.toLowerCase())) continue;");
  L.push("      if (k.toLowerCase() === 'set-cookie') { rh.append('Set-Cookie', rewriteCookie(v, wpOriginHost, rawHost)); continue; }");
  L.push("      rh.set(k, v);");
  L.push("    }");
  L.push("    rh.set('X-Cache', 'MISS');");
  L.push("    rh.set('X-Frame-Options', 'SAMEORIGIN');");
  L.push("    rh.set('X-Content-Type-Options', 'nosniff');");
  // CORS for REST API
  L.push("    if (url.pathname.startsWith('/wp-json/')) {");
  L.push("      rh.set('Access-Control-Allow-Origin', '*');");
  L.push("      rh.set('Access-Control-Allow-Headers', 'Content-Type, X-WP-Nonce, Authorization');");
  L.push("    }");

  L.push("    const ct = oRes.headers.get('content-type') || '';");

  // HTML 치환
  L.push("    if (ct.includes('text/html')) {");
  L.push("      let html = await oRes.text();");
  L.push("      html = rewriteStr(html, wpOriginUrl, personalOrigin, wpOriginHost, rawHost);");
  // Cron 비동기 실행 스크립트 삽입 (HTML에만)
  L.push("      if (!isAdmin && oRes.status === 200) {");
  L.push("        html = html.replace('</body>', '<script>fetch(\"/__cp_cron\",{method:\"GET\",keepalive:true}).catch(()=>{})</script></body>');");
  L.push("      }");
  L.push("      if (isCacheable && oRes.status === 200 && env.SITE_KV) {");
  L.push("        const ck2 = 'page:' + url.pathname + (url.search || '');");
  L.push("        env.SITE_KV.put(ck2, JSON.stringify({ body: html, contentType: ct }), { expirationTtl: 600 }).catch(() => {});");
  L.push("      }");
  L.push("      return new Response(html, { status: oRes.status, headers: rh });");
  L.push("    }");

  // CSS/JS 치환
  L.push("    if (ct.includes('text/css') || ct.includes('javascript')) {");
  L.push("      let txt = await oRes.text();");
  L.push("      txt = rewriteStr(txt, wpOriginUrl, personalOrigin, wpOriginHost, rawHost);");
  L.push("      return new Response(txt, { status: oRes.status, headers: rh });");
  L.push("    }");

  // 바이너리
  L.push("    return new Response(oRes.body, { status: oRes.status, headers: rh });");
  L.push("  },");

  // scheduled (CF Cron Triggers)
  L.push("  async scheduled(event, env, ctx) {");
  L.push("    // Cloudflare Cron Trigger: 사이트별 wp-cron.php 호출");
  L.push("    try {");
  L.push("      if (!env?.DB || !env?.CACHE) return;");
  L.push("      const { results } = await env.DB.prepare(");
  L.push("        \"SELECT primary_domain, site_prefix FROM sites WHERE status='active' AND suspended=0 AND deleted_at IS NULL LIMIT 50\"");
  L.push("      ).all().catch(() => ({ results: [] }));");
  L.push("      const wpOrigin = (env.WP_ORIGIN_URL || '').trim().replace(/\\/+$/, '');");
  L.push("      if (!wpOrigin) return;");
  L.push("      for (const site of (results || [])) {");
  L.push("        ctx.waitUntil(");
  L.push("          fetch(wpOrigin + '/wp-cron.php?doing_wp_cron=1', {");
  L.push("            method: 'GET',");
  L.push("            headers: { 'X-CloudPress-Site': site.site_prefix || '', 'X-CloudPress-Secret': env.WP_ORIGIN_SECRET || '' },");
  L.push("          }).catch(() => {})");
  L.push("        );");
  L.push("      }");
  L.push("    } catch (_) {}");
  L.push("  },");
  L.push("};");

  // 헬퍼들
  L.push("async function getSiteByHost(env, host) {");
  L.push("  const cacheKey = 'site_domain:' + host;");
  L.push("  try {");
  L.push("    const cached = await env.CACHE.get(cacheKey, { type: 'json' });");
  L.push("    if (cached) return cached;");
  L.push("    const row = await env.DB.prepare(");
  L.push("      'SELECT id,name,site_prefix,site_d1_id,site_kv_id,wp_admin_url,status,suspended,suspension_reason'");
  L.push("      + \" FROM sites WHERE primary_domain=? AND status='active' AND deleted_at IS NULL AND suspended=0 LIMIT 1\"");
  L.push("    ).bind(host).first();");
  L.push("    if (row) await env.CACHE.put(cacheKey, JSON.stringify(row), { expirationTtl: 300 }).catch(() => {});");
  L.push("    return row || null;");
  L.push("  } catch { return null; }");
  L.push("}");

  L.push("function escRe(s) { return s.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&'); }");
  L.push("function rewriteStr(text, originBase, personalBase, originHost, personalHost) {");
  L.push("  text = text.split(originBase.replace(/^https?:/,'https:')).join(personalBase);");
  L.push("  text = text.split(originBase.replace(/^https?:/,'http:')).join(personalBase);");
  L.push("  text = text.split(originBase).join(personalBase);");
  L.push("  if (originHost && originHost !== personalHost) text = text.split(originHost).join(personalHost);");
  L.push("  return text;");
  L.push("}");
  L.push("function rewriteCookie(c, originHost, personalHost) {");
  L.push("  if (!originHost || originHost === personalHost) return c;");
  L.push("  return c.replace(new RegExp('(domain=)' + escRe(originHost),'gi'), '$1' + personalHost);");
  L.push("}");
  L.push("function errPage(status, title, detail) {");
  L.push("  const s = String(detail).replace(/</g,'&lt;').replace(/>/g,'&gt;');");
  L.push("  return new Response(`<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>${title}</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f9fa}.b{text-align:center;padding:40px;max-width:480px}h1{color:#333;font-size:1.4rem}p{color:#666;font-size:.88rem}</style></head><body><div class=\"b\"><h1>${title}</h1><p>${s}</p></div></body></html>`, { status, headers: { 'Content-Type': 'text/html;charset=utf-8' } });");
  L.push("}");
  L.push("function suspendedPage(name, reason) {");
  L.push("  return new Response(`<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>정지</title></head><body style=\"font-family:sans-serif;text-align:center;padding:60px\"><h1 style=\"color:#e67e22\">사이트 정지</h1><p>${name||'이 사이트'}는 현재 정지 상태입니다.</p>${reason?`<p style=\"color:#999\">${reason}</p>`:''}</body></html>`, { status: 503, headers: { 'Content-Type': 'text/html;charset=utf-8' } });");
  L.push("}");

  return L.join('\n');
}

// ── Worker 업로드 ────────────────────────────────────────────────────
async function uploadWorker(auth, accountId, workerName, opts) {
  const boundary = '----CPBoundary' + Date.now().toString(36);
  const bindings = [];

  if (opts.mainDbId)     bindings.push({ type: 'd1',          name: 'DB',       id: opts.mainDbId });
  if (opts.cacheKvId)    bindings.push({ type: 'kv_namespace', name: 'CACHE',    namespace_id: opts.cacheKvId });
  if (opts.sessionsKvId) bindings.push({ type: 'kv_namespace', name: 'SESSIONS', namespace_id: opts.sessionsKvId });
  if (opts.siteD1Id)     bindings.push({ type: 'd1',          name: 'SITE_DB',  id: opts.siteD1Id });
  if (opts.siteKvId)     bindings.push({ type: 'kv_namespace', name: 'SITE_KV', namespace_id: opts.siteKvId });

  // origin은 VP 서브도메인 (사이트마다 고유)
  bindings.push({ type: 'plain_text', name: 'WP_ORIGIN_URL',    text: opts.wpOriginUrl    || '' });
  bindings.push({ type: 'plain_text', name: 'WP_ORIGIN_SECRET', text: opts.wpOriginSecret || '' });
  bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID',    text: opts.cfAccountId    || '' });
  bindings.push({ type: 'plain_text', name: 'CF_API_TOKEN',     text: opts.cfApiKey       || '' });
  bindings.push({ type: 'plain_text', name: 'SITE_PREFIX',      text: opts.sitePrefix     || '' });

  const metadata   = JSON.stringify({ main_module: 'worker.js', compatibility_date: '2024-09-23', bindings });
  const workerSrc  = buildWorkerSource();
  const enc  = new TextEncoder();
  const CRLF = '\r\n';
  const p1h  = `--${boundary}${CRLF}Content-Disposition: form-data; name="metadata"${CRLF}Content-Type: application/json${CRLF}${CRLF}`;
  const p2h  = `--${boundary}${CRLF}Content-Disposition: form-data; name="worker.js"; filename="worker.js"${CRLF}Content-Type: application/javascript+module${CRLF}${CRLF}`;
  const end  = `${CRLF}--${boundary}--${CRLF}`;
  const chunks = [enc.encode(p1h), enc.encode(metadata), enc.encode(CRLF), enc.encode(p2h), enc.encode(workerSrc), enc.encode(end)];
  const total  = chunks.reduce((s, c) => s + c.length, 0);
  const buf    = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }

  const uploadHdrs = auth.type === 'global'
    ? { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'X-Auth-Email': auth.email, 'X-Auth-Key': auth.key }
    : { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Authorization': 'Bearer ' + (auth.value || auth.key) };

  try {
    const res  = await fetch(`${CF_API}/accounts/${accountId}/workers/scripts/${workerName}`, {
      method: 'PUT', headers: uploadHdrs, body: buf.buffer,
    });
    const json = await res.json();
    if (!json.success) return { ok: false, error: 'Worker 업로드 실패: ' + cfErrMsg(json) };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Worker 업로드 오류: ' + e.message };
  }
}

// ══════════════════════════════════════════════════════════════════
// 메인 핸들러
// ══════════════════════════════════════════════════════════════════
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  let site;
  try {
    site = await env.DB.prepare(
      'SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,'
      + ' s.wp_username, s.wp_password, s.wp_admin_email,'
      + ' s.status, s.provision_step, s.plan,'
      + ' s.site_d1_id, s.site_kv_id,'
      + ' u.cf_global_api_key, u.cf_account_email, u.cf_account_id'
      + ' FROM sites s JOIN users u ON u.id = s.user_id'
      + ' WHERE s.id=? AND s.user_id=?'
    ).bind(siteId, user.id).first();
  } catch (e) { return err('사이트 조회 오류: ' + e.message, 500); }

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });

  await updateSite(env.DB, siteId, { status: 'provisioning', provision_step: 'starting', error_message: null });

  const encKey = env?.ENCRYPTION_KEY || 'cp_enc_default';

  // ── 어드민 CF 키 (메인 KV/D1 UUID 역추출 전용) ─────────────────
  const adminCfKey     = await getSetting(env, 'cf_api_token');
  const adminCfAccount = await getSetting(env, 'cf_account_id');
  const adminAuth      = (adminCfKey && adminCfAccount) ? makeAuth(adminCfKey, '') : null;

  // ── 사용자 CF 키 (사이트 D1/KV/Worker 생성용) ──────────────────
  let userCfKey     = null;
  let userCfEmail   = '';
  let userCfAccount = null;

  if (site.cf_global_api_key && site.cf_account_id) {
    const raw = deobfuscate(site.cf_global_api_key, encKey);
    userCfKey     = (raw && raw.length > 5) ? raw : site.cf_global_api_key;
    userCfEmail   = site.cf_account_email || '';
    userCfAccount = site.cf_account_id;
  }

  if (!userCfKey || !userCfAccount) {
    userCfKey     = adminCfKey;
    userCfAccount = adminCfAccount;
    userCfEmail   = '';
  }

  if (!userCfKey || !userCfAccount) {
    const e = 'Cloudflare API 키가 설정되지 않았습니다.';
    await failSite(env.DB, siteId, 'config_missing', e);
    return jsonRes({ ok: false, error: e }, 400);
  }

  const userAuth = makeAuth(userCfKey, userCfEmail);

  const domain    = site.primary_domain;
  const wwwDomain = 'www.' + domain;
  const prefix    = site.site_prefix;

  // ── Step 0: VP 계정 선택 ────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'vp_select' });

  let vpAccount = null;
  try {
    // 여유 있는 VP 계정 중 랜덤 선택
    const { results: vpList } = await env.DB.prepare(
      'SELECT * FROM vp_accounts WHERE is_active=1 AND current_sites < max_sites ORDER BY current_sites ASC LIMIT 5'
    ).all();
    if (!vpList || vpList.length === 0) {
      await failSite(env.DB, siteId, 'vp_select', '사용 가능한 VP 계정이 없습니다.');
      return jsonRes({ ok: false, error: '사용 가능한 VP 계정이 없습니다.' }, 500);
    }
    vpAccount = vpList[Math.floor(Math.random() * vpList.length)];
  } catch (e) {
    await failSite(env.DB, siteId, 'vp_select', e.message);
    return jsonRes({ ok: false, error: 'VP 계정 조회 실패: ' + e.message }, 500);
  }

  console.log(`[provision] VP 계정 선택: ${vpAccount.label} (${vpAccount.panel_url})`);

  // ── Step 1: VP 세션 확인/갱신 ──────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'vp_session' });
  const sessionRes = await ensureVpSession(env.DB, vpAccount);
  if (!sessionRes.ok) {
    await failSite(env.DB, siteId, 'vp_session', sessionRes.error);
    return jsonRes({ ok: false, error: 'VP 패널 로그인 실패: ' + sessionRes.error }, 500);
  }
  // sessionInfo = { cookie, panelType, basicAuth } — 패널 종류 + 인증 정보 일괄 전달
  const sessionInfo = {
    cookie:    sessionRes.cookie    || sessionRes.phpsessid || '',
    panelType: sessionRes.panelType || vpAccount.panel_type || null,
    basicAuth: sessionRes.basicAuth || null,
  };
  console.log(`[provision] VP 세션 확보 완료 (패널: ${sessionInfo.panelType || '자동감지'})`);

  // ── Step 2: VP 서브도메인 생성 ─────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'vp_subdomain' });
  const subdomain = prefix;  // e.g. s_abc12
  let subRes = await vpCreateSubdomain(vpAccount.panel_url, sessionInfo, subdomain, vpAccount.server_domain);

  // 세션 만료 감지 → 재로그인 후 1회 재시도
  if (!subRes.ok && subRes.sessionExpired) {
    console.log('[provision] 서브도메인 생성 중 세션 만료 → 재로그인 후 재시도');
    const reloginRes = await vpDetectAndLogin(vpAccount.panel_url, vpAccount.vp_username, vpAccount.vp_password, sessionInfo.panelType);
    if (reloginRes.ok) {
      sessionInfo.cookie    = reloginRes.cookie;
      sessionInfo.panelType = reloginRes.type;
      sessionInfo.basicAuth = reloginRes.basicAuth || null;
      try {
        await env.DB.prepare(
          "UPDATE vp_accounts SET phpsessid=?, phpsessid_updated_at=datetime('now'), updated_at=datetime('now') WHERE id=?"
        ).bind(reloginRes.cookie, vpAccount.id).run();
      } catch (_) {}
      subRes = await vpCreateSubdomain(vpAccount.panel_url, sessionInfo, subdomain, vpAccount.server_domain);
    }
  }

  if (!subRes.ok) {
    await failSite(env.DB, siteId, 'vp_subdomain', subRes.error);
    return jsonRes({ ok: false, error: 'VP 서브도메인 생성 실패: ' + subRes.error }, 500);
  }
  const originHost = subRes.domain;
  const originUrl  = 'https://' + originHost;
  console.log(`[provision] VP 서브도메인 생성 완료: ${originHost}`);

  // ── Step 3: VP DB 생성 ─────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'vp_db' });
  const dbName = ('cp_' + prefix).replace(/[^a-z0-9_]/g, '_').slice(0, 32);
  const dbUser = dbName;
  const dbPass = site.wp_password || ('Db' + randSuffix(12));
  const dbRes  = await vpCreateDatabase(vpAccount.panel_url, sessionInfo, dbName, dbUser, dbPass);
  if (!dbRes.ok) {
    await failSite(env.DB, siteId, 'vp_db', dbRes.error);
    return jsonRes({ ok: false, error: 'VP DB 생성 실패: ' + dbRes.error }, 500);
  }
  console.log(`[provision] VP DB 생성 완료: ${dbName}`);

  // ── Step 4: WP 설치 ────────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'wp_install' });
  const wpInstall = await vpInstallWordPress(vpAccount.panel_url, sessionInfo, {
    webRoot:       vpAccount.web_root || '/htdocs',
    subdomain,
    serverDomain:  vpAccount.server_domain,
    dbName,
    dbUser,
    dbPass,
    siteUrl:       'https://' + domain,
    siteTitle:     site.name,
    wpUser:        site.wp_username,
    wpPass:        site.wp_password,
    wpEmail:       site.wp_admin_email || user.email,
    wpDownloadUrl: vpAccount.wp_download_url,
    phpBin:        vpAccount.php_bin || 'php8.3',
  });
  console.log('[provision] WP 설치:', wpInstall.skipped ? '(수동 필요) ' + wpInstall.message : '완료');

  // ── Step 5: CF D1/KV 생성 (사용자 계정) ────────────────────────
  // 어드민 CF로 메인 UUID 확보
  let mainDbId = await getSetting(env, 'main_db_id', '');
  let cacheKvId = await getSetting(env, 'cache_kv_id', '');
  let sessionsKvId = await getSetting(env, 'sessions_kv_id', '');

  if ((!mainDbId || !cacheKvId || !sessionsKvId) && adminAuth && adminCfAccount) {
    const pName = await findPagesProjectName(adminAuth, adminCfAccount);
    if (pName) {
      const ids = await resolveMainBindingIds(adminAuth, adminCfAccount, pName, env.DB);
      if (!mainDbId)     mainDbId     = ids.mainDbId     || '';
      if (!cacheKvId)    cacheKvId    = ids.cacheKvId    || '';
      if (!sessionsKvId) sessionsKvId = ids.sessionsKvId || '';
    }
  }

  await updateSite(env.DB, siteId, { provision_step: 'd1_create' });
  let d1Id = site.site_d1_id || null;
  if (!d1Id) {
    const r1 = await createD1(userAuth, userCfAccount, prefix);
    if (!r1.ok) { await failSite(env.DB, siteId, 'd1_create', r1.error); return jsonRes({ ok: false, error: r1.error }, 500); }
    d1Id = r1.id;
    await updateSite(env.DB, siteId, { site_d1_id: d1Id, site_d1_name: r1.name });
    await initD1Schema(userAuth, userCfAccount, d1Id);
  }

  await updateSite(env.DB, siteId, { provision_step: 'kv_create' });
  let kvId = site.site_kv_id || null;
  if (!kvId) {
    const r2 = await createKV(userAuth, userCfAccount, prefix);
    if (!r2.ok) { await failSite(env.DB, siteId, 'kv_create', r2.error); return jsonRes({ ok: false, error: r2.error }, 500); }
    kvId = r2.id;
    await updateSite(env.DB, siteId, { site_kv_id: kvId, site_kv_title: r2.title });
    await initKVData(userAuth, userCfAccount, kvId, {
      'site:config': JSON.stringify({ siteId, prefix, name: site.name, domain, originUrl }),
      'site:status': 'active',
    });
  }

  // ── Step 6: CACHE 도메인 매핑 등록 ─────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'kv_mapping' });
  const wpAdminUrl = 'https://' + domain + '/wp-admin/';
  const mapping = JSON.stringify({
    id: siteId, name: site.name, site_prefix: prefix,
    site_d1_id: d1Id, site_kv_id: kvId,
    wp_admin_url: wpAdminUrl, status: 'active', suspended: 0,
  });
  try {
    await env.CACHE.put('site_domain:' + domain, mapping);
    await env.CACHE.put('site_domain:' + wwwDomain, mapping);
    await env.CACHE.put('site_prefix:' + prefix, mapping);
  } catch (e) { console.warn('[provision] CACHE put 실패(무시):', e.message); }

  // ── Step 7: 사이트 전용 Worker 업로드 ──────────────────────────
  // origin = VP 서브도메인 (사이트마다 고유, 사용자 도메인으로 완전 덮어씌워짐)
  const workerName = 'cloudpress-site-' + prefix;
  await updateSite(env.DB, siteId, { provision_step: 'worker_upload' });

  const wpOriginSecret = await getSetting(env, 'wp_origin_secret', '');

  const upRes = await uploadWorker(userAuth, userCfAccount, workerName, {
    mainDbId,
    cacheKvId,
    sessionsKvId,
    siteD1Id:       d1Id,
    siteKvId:       kvId,
    wpOriginUrl:    originUrl,        // ← VP 서브도메인 (고정 X, 사이트마다 고유)
    wpOriginSecret: wpOriginSecret,
    cfAccountId:    userCfAccount,
    cfApiKey:       userCfKey,
    sitePrefix:     prefix,
  });

  if (!upRes.ok) {
    await failSite(env.DB, siteId, 'worker_upload', upRes.error);
    return jsonRes({ ok: false, error: 'Worker 업로드 실패: ' + upRes.error }, 500);
  }
  console.log(`[provision] Worker 업로드 완료: ${workerName}`);
  await updateSite(env.DB, siteId, { worker_name: workerName, vp_account_id: vpAccount.id, vp_origin_url: originUrl });

  // ── Step 8: DNS + Worker Route ──────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });
  const cnameTarget = await getWorkerSubdomain(userAuth, userCfAccount, workerName);
  let domainStatus = 'manual_required';
  let cfZoneId = null, dnsRecordId = null, dnsRecordWwwId = null;

  const zone = await cfGetZone(userAuth, domain);
  if (zone.ok) {
    cfZoneId = zone.zoneId;
    const dr  = await cfUpsertDns(userAuth, cfZoneId, 'CNAME', domain,    cnameTarget, true);
    const drw = await cfUpsertDns(userAuth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true);
    if (dr.ok)  dnsRecordId    = dr.recordId;
    if (drw.ok) dnsRecordWwwId = drw.recordId;

    await updateSite(env.DB, siteId, { provision_step: 'worker_route' });
    const rr = await cfUpsertRoute(userAuth, cfZoneId, domain + '/*',    workerName);
    const rw = await cfUpsertRoute(userAuth, cfZoneId, wwwDomain + '/*', workerName);
    if (rr.ok || rw.ok) domainStatus = 'dns_propagating';
    await updateSite(env.DB, siteId, {
      worker_route: domain + '/*', worker_route_www: wwwDomain + '/*',
      worker_route_id: rr.routeId || null, worker_route_www_id: rw.routeId || null,
      cf_zone_id: cfZoneId, dns_record_id: dnsRecordId, dns_record_www_id: dnsRecordWwwId,
    });
  }

  // ── Step 9: VP 사이트 카운트 증가 ──────────────────────────────
  try {
    await env.DB.prepare("UPDATE vp_accounts SET current_sites=current_sites+1, updated_at=datetime('now') WHERE id=?").bind(vpAccount.id).run();
  } catch (_) {}

  // ── Step 10: REST API 활성화 확인 ──────────────────────────────
  let restApiStatus = 'unknown';
  const restCheck = await verifyAndActivateRestApi(originUrl);
  restApiStatus = restCheck.ok ? 'active' : 'pending';

  // ── 완료 ────────────────────────────────────────────────────────
  await updateSite(env.DB, siteId, {
    status:         'active',
    provision_step: 'completed',
    domain_status:  domainStatus,
    wp_admin_url:   wpAdminUrl,
    error_message:  domainStatus === 'manual_required' ? `외부 DNS 설정 필요 — CNAME: ${cnameTarget}` : null,
  });

  const finalSite = await env.DB.prepare(
    'SELECT status, provision_step, error_message, wp_admin_url, wp_username, wp_password, primary_domain, site_d1_id, site_kv_id, domain_status, worker_name, name FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({
    message: '프로비저닝 완료',
    siteId,
    site: finalSite,
    worker_name: workerName,
    vp_account:  vpAccount.label,
    origin_url:  originUrl,
    rest_api:    restApiStatus,
    wp_install:  wpInstall.skipped ? '수동 설치 필요' : '완료',
    cname_target: cnameTarget,
    cname_instructions: domainStatus === 'manual_required' ? {
      type: 'CNAME',
      root: { host: '@',   value: cnameTarget },
      www:  { host: 'www', value: cnameTarget },
    } : null,
  });
}
