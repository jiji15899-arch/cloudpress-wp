// functions/api/sites/[id]/provision.js — CloudPress v12.9
//
// [수정 사항]
// 1. Pages 바인딩 자동화: provision 완료 후 Cloudflare Pages API로 DB/SESSIONS/CACHE 바인딩 자동 저장
// 2. CNAME 값 반환: 외부 DNS 사용 시 실제 worker subdomain 값 포함하여 안내
// 3. 워커 이름 고정 방지: cloudpress-proxy-{6자리 랜덤} 으로 생성 (중복 방지)
// 4. D1 생성 후 site 전용 schema 자동 초기화 (wp_posts, wp_options 등)
// 5. D1/KV 이름에 타임스탬프+랜덤 접미사 추가로 완전한 중복 방지
// 6. [NEW] D1/KV 생성 직후 Worker 바인딩에 자동 연결 (updateWorkerBindings)
//    → 코드 자체에서 CF API로 Workers 바인딩을 직접 등록하여 env 주입 없이도 동작
// 7. [NEW] env.SESSIONS 누락 시 graceful 처리 (undefined 에러 방지)
'use strict';

var CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function jsonRes(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, CORS),
  });
}
function ok(data)    { return jsonRes(Object.assign({ ok: true  }, data || {})); }
function err(msg, s) { return jsonRes({ ok: false, error: msg }, s || 400); }

function getToken(req) {
  var a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  var c = req.headers.get('Cookie') || '';
  var m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    var t = getToken(req);
    if (!t) return null;
    // env.SESSIONS 바인딩 없으면 undefined 에러 방지
    if (!env || !env.SESSIONS) return null;
    var uid = await env.SESSIONS.get('session:' + t);
    if (!uid) return null;
    if (!env.DB) return null;
    return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();
  } catch (e) { return null; }
}

async function getSetting(env, key, fallback) {
  try {
    var row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return (row && row.value != null && row.value !== '') ? row.value : (fallback || '');
  } catch (e) { return fallback || ''; }
}

async function updateSite(DB, siteId, fields) {
  var keys = Object.keys(fields);
  if (!keys.length) return;
  var setParts = [];
  var vals = [];
  for (var i = 0; i < keys.length; i++) {
    setParts.push(keys[i] + '=?');
    vals.push(fields[keys[i]]);
  }
  vals.push(siteId);
  var sql = 'UPDATE sites SET ' + setParts.join(', ') + ", updated_at=datetime('now') WHERE id=?";
  try {
    await DB.prepare(sql).bind(...vals).run();
  } catch (e) { console.error('updateSite err:', e.message); }
}

async function failSite(DB, siteId, step, message) {
  console.error('[FAIL] ' + step + ': ' + message);
  try {
    await DB.prepare(
      "UPDATE sites SET status='failed', provision_step=?, error_message=?, updated_at=datetime('now') WHERE id=?"
    ).bind(step, String(message).substring(0, 500), siteId).run();
  } catch (e) { console.error('failSite err:', e.message); }
}

function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    var key = salt || 'cp_enc_v1';
    var dec = atob(str);
    var out = '';
    for (var i = 0; i < dec.length; i++) {
      out += String.fromCharCode(dec.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  } catch (e) { return ''; }
}

function randSuffix() {
  var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  var out = '';
  for (var i = 0; i < 6; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

var CF_API = 'https://api.cloudflare.com/client/v4';

function makeAuth(key, email) {
  if (email && email.includes('@')) {
    return { type: 'global', key: key, email: email };
  }
  return { type: 'bearer', value: key };
}

function getAuthHeaders(auth) {
  if (auth.type === 'global') {
    return {
      'Content-Type': 'application/json',
      'X-Auth-Email': auth.email,
      'X-Auth-Key':   auth.key,
    };
  }
  return {
    'Content-Type':  'application/json',
    'Authorization': 'Bearer ' + (auth.value || auth.key),
  };
}

async function cfReq(auth, path, method, body) {
  var opts = { method: method || 'GET', headers: getAuthHeaders(auth) };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  try {
    var res  = await fetch(CF_API + path, opts);
    var json = await res.json();
    if (!json.success) {
      console.error('[cfReq] ' + (method || 'GET') + ' ' + path + ' failed:', JSON.stringify(json.errors || []));
    }
    return json;
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

function cfErrMsg(json) {
  if (json && json.errors && json.errors.length > 0) {
    return json.errors.map(function(e) {
      return (e.code ? '[' + e.code + '] ' : '') + (e.message || '');
    }).join('; ');
  }
  return 'unknown error';
}

// ── D1 생성 (고유 이름 보장) ────────────────────────────────────────
async function createD1(auth, accountId, prefix) {
  var suffix = Date.now().toString(36) + randSuffix();
  var name = 'cp-' + prefix + '-' + suffix;

  var res = await cfReq(auth, '/accounts/' + accountId + '/d1/database', 'POST', { name: name });
  if (res.success && res.result) {
    var id = res.result.uuid || res.result.id || res.result.database_id;
    if (id) return { ok: true, id: id, name: name };
  }

  var errMsg = cfErrMsg(res);
  if (
    errMsg.toLowerCase().includes('already exist') ||
    errMsg.includes('10033') ||
    (res.errors && res.errors.some(function(e) { return e.code === 10033; }))
  ) {
    var page = 1;
    while (true) {
      var listRes = await cfReq(auth, '/accounts/' + accountId + '/d1/database?per_page=100&page=' + page);
      if (!listRes.success || !Array.isArray(listRes.result) || listRes.result.length === 0) break;
      for (var i = 0; i < listRes.result.length; i++) {
        var db = listRes.result[i];
        if (db.name === name) {
          var existId = db.uuid || db.id || db.database_id;
          if (existId) return { ok: true, id: existId, name: name };
        }
      }
      if (listRes.result.length < 100) break;
      page++;
    }
    return { ok: false, error: 'D1 이름 충돌 — 기존 DB 목록에서 찾지 못함: ' + name };
  }

  return { ok: false, error: 'D1 생성 실패: ' + errMsg };
}

// ── KV 생성 (고유 이름 보장) ────────────────────────────────────────
async function createKV(auth, accountId, prefix) {
  var suffix = Date.now().toString(36).toUpperCase() + randSuffix().toUpperCase();
  var title = 'CP_' + prefix.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_' + suffix;

  var res = await cfReq(auth, '/accounts/' + accountId + '/storage/kv/namespaces', 'POST', { title: title });
  if (res.success && res.result && res.result.id) {
    return { ok: true, id: res.result.id, title: title };
  }

  var errMsg = cfErrMsg(res);
  if (
    errMsg.toLowerCase().includes('already exist') ||
    errMsg.includes('10016') ||
    (res.errors && res.errors.some(function(e) { return e.code === 10016; }))
  ) {
    var page = 1;
    while (true) {
      var listRes = await cfReq(auth, '/accounts/' + accountId + '/storage/kv/namespaces?per_page=100&page=' + page);
      if (!listRes.success || !Array.isArray(listRes.result) || listRes.result.length === 0) break;
      for (var i = 0; i < listRes.result.length; i++) {
        var ns = listRes.result[i];
        if (ns.title === title) {
          return { ok: true, id: ns.id, title: title };
        }
      }
      if (listRes.result.length < 100) break;
      page++;
    }
    return { ok: false, error: 'KV 이름 충돌 — 기존 네임스페이스 목록에서 찾지 못함: ' + title };
  }

  return { ok: false, error: 'KV 생성 실패: ' + errMsg };
}

// ── D1 스키마 초기화 ────────────────────────────────────────────────
async function initD1Schema(auth, accountId, d1Id) {
  var sqls = [
    "CREATE TABLE IF NOT EXISTS wp_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT NOT NULL UNIQUE, option_value TEXT NOT NULL DEFAULT '', autoload TEXT NOT NULL DEFAULT 'yes')",
    "CREATE TABLE IF NOT EXISTS wp_posts (ID INTEGER PRIMARY KEY AUTOINCREMENT, post_author INTEGER NOT NULL DEFAULT 0, post_date TEXT NOT NULL DEFAULT (datetime('now')), post_content TEXT NOT NULL DEFAULT '', post_title TEXT NOT NULL DEFAULT '', post_status TEXT NOT NULL DEFAULT 'publish', post_type TEXT NOT NULL DEFAULT 'post', post_name TEXT NOT NULL DEFAULT '', modified_at TEXT NOT NULL DEFAULT (datetime('now')))",
    "CREATE TABLE IF NOT EXISTS wp_users (ID INTEGER PRIMARY KEY AUTOINCREMENT, user_login TEXT NOT NULL UNIQUE, user_pass TEXT NOT NULL, user_email TEXT NOT NULL DEFAULT '', user_registered TEXT NOT NULL DEFAULT (datetime('now')), display_name TEXT NOT NULL DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS wp_usermeta (umeta_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, meta_key TEXT NOT NULL, meta_value TEXT)",
    "CREATE TABLE IF NOT EXISTS wp_postmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL DEFAULT 0, meta_key TEXT, meta_value TEXT)",
    "CREATE TABLE IF NOT EXISTS wp_comments (comment_ID INTEGER PRIMARY KEY AUTOINCREMENT, comment_post_ID INTEGER NOT NULL DEFAULT 0, comment_content TEXT NOT NULL DEFAULT '', comment_date TEXT NOT NULL DEFAULT (datetime('now')), comment_approved TEXT NOT NULL DEFAULT '1')",
    "CREATE TABLE IF NOT EXISTS cp_site_meta (id INTEGER PRIMARY KEY AUTOINCREMENT, meta_key TEXT NOT NULL UNIQUE, meta_value TEXT, updated_at TEXT NOT NULL DEFAULT (datetime('now')))",
    "CREATE INDEX IF NOT EXISTS idx_wp_posts_status ON wp_posts(post_status)",
    "CREATE INDEX IF NOT EXISTS idx_wp_postmeta_post_id ON wp_postmeta(post_id)",
    "CREATE INDEX IF NOT EXISTS idx_wp_usermeta_user_id ON wp_usermeta(user_id)",
  ];

  for (var i = 0; i < sqls.length; i++) {
    try {
      var res = await cfReq(auth,
        '/accounts/' + accountId + '/d1/database/' + d1Id + '/query',
        'POST',
        { sql: sqls[i] }
      );
      if (!res.success) {
        console.warn('[provision] D1 schema stmt ' + i + ' 실패:', cfErrMsg(res));
      }
    } catch (e) {
      console.warn('[provision] D1 schema stmt ' + i + ' error:', e.message);
    }
  }
  console.log('[provision] D1 schema 초기화 완료');
}

// ── KV 초기 데이터 저장 ─────────────────────────────────────────────
async function initKVData(auth, accountId, kvId, siteData) {
  var entries = [
    { key: 'site:config',  value: JSON.stringify(siteData) },
    { key: 'site:status',  value: 'active' },
    { key: 'site:created', value: new Date().toISOString() },
  ];

  for (var i = 0; i < entries.length; i++) {
    try {
      var hdrs = getAuthHeaders(auth);
      delete hdrs['Content-Type'];
      await fetch(
        CF_API + '/accounts/' + accountId + '/storage/kv/namespaces/' + kvId + '/values/' + encodeURIComponent(entries[i].key),
        { method: 'PUT', headers: hdrs, body: entries[i].value }
      );
    } catch (e) {
      console.warn('[provision] KV put ' + entries[i].key + ' 실패:', e.message);
    }
  }
  console.log('[provision] KV 초기 데이터 저장 완료');
}

// ── Pages 바인딩 자동 업데이트 ──────────────────────────────────────
async function updatePagesBindings(auth, accountId, projectName, opts) {
  console.log('[provision] Pages 바인딩 업데이트: project=' + projectName);

  var projRes = await cfReq(auth, '/accounts/' + accountId + '/pages/projects/' + projectName);
  if (!projRes.success) {
    return { ok: false, error: 'Pages 프로젝트 조회 실패: ' + cfErrMsg(projRes) };
  }

  var proj = projRes.result;
  var prodCfg = (proj.deployment_configs && proj.deployment_configs.production) || {};
  var existingD1  = prodCfg.d1_databases  || {};
  var existingKV  = prodCfg.kv_namespaces || {};
  var existingVar = prodCfg.env_vars      || {};
  var existingSvc = prodCfg.services      || {};
  var compatDate  = prodCfg.compatibility_date || '2024-09-23';

  var newD1  = Object.assign({}, existingD1);
  var newKV  = Object.assign({}, existingKV);
  var newVar = Object.assign({}, existingVar);

  if (opts.mainDbId)     newD1['DB']       = { id: opts.mainDbId };
  if (opts.sessionsKvId) newKV['SESSIONS'] = { id: opts.sessionsKvId };
  if (opts.cacheKvId)    newKV['CACHE']    = { id: opts.cacheKvId };

  if (opts.wpOriginUrl)    newVar['WP_ORIGIN_URL']    = { type: 'plain_text', value: opts.wpOriginUrl };
  if (opts.wpOriginSecret) newVar['WP_ORIGIN_SECRET'] = { type: 'plain_text', value: opts.wpOriginSecret };
  if (opts.cfAccountId)    newVar['CF_ACCOUNT_ID']    = { type: 'plain_text', value: opts.cfAccountId };
  if (opts.cfApiKey)       newVar['CF_API_TOKEN']     = { type: 'plain_text', value: opts.cfApiKey };
  if (opts.encryptionKey)  newVar['ENCRYPTION_KEY']   = { type: 'plain_text', value: opts.encryptionKey };

  var envBlock = {
    d1_databases:       newD1,
    kv_namespaces:      newKV,
    env_vars:           newVar,
    services:           existingSvc,
    compatibility_date: compatDate,
  };

  var patchRes = await cfReq(
    auth,
    '/accounts/' + accountId + '/pages/projects/' + projectName,
    'PATCH',
    { deployment_configs: { production: envBlock, preview: envBlock } }
  );

  if (!patchRes.success) {
    return { ok: false, error: 'Pages 바인딩 PATCH 실패: ' + cfErrMsg(patchRes) };
  }

  console.log('[provision] Pages 바인딩 업데이트 완료');
  return { ok: true };
}

// ── Pages 프로젝트명 자동 탐색 ──────────────────────────────────────
async function findPagesProjectName(auth, accountId) {
  try {
    var listRes = await cfReq(auth, '/accounts/' + accountId + '/pages/projects?per_page=50');
    if (listRes.success && Array.isArray(listRes.result)) {
      for (var i = 0; i < listRes.result.length; i++) {
        var p = listRes.result[i];
        if (p.name && p.name.toLowerCase().includes('cloudpress')) return p.name;
      }
      if (listRes.result.length > 0) return listRes.result[0].name;
    }
  } catch (e) {
    console.warn('[provision] Pages 프로젝트 목록 조회 실패:', e.message);
  }
  return null;
}

async function cfGetZone(auth, domain) {
  var parts = domain.split('.');
  var root2 = parts.slice(-2).join('.');
  var root3 = parts.length >= 3 ? parts.slice(-3).join('.') : root2;

  var res = await cfReq(auth, '/zones?name=' + encodeURIComponent(root2) + '&status=active');
  if (res.success && res.result && res.result.length > 0) {
    return { ok: true, zoneId: res.result[0].id };
  }
  if (root3 !== root2) {
    res = await cfReq(auth, '/zones?name=' + encodeURIComponent(root3) + '&status=active');
    if (res.success && res.result && res.result.length > 0) {
      return { ok: true, zoneId: res.result[0].id };
    }
  }
  return { ok: false };
}

async function cfUpsertDns(auth, zoneId, type, name, content, proxied) {
  var list     = await cfReq(auth, '/zones/' + zoneId + '/dns_records?type=' + type + '&name=' + encodeURIComponent(name));
  var existing = list && list.result && list.result[0] ? list.result[0] : null;
  var payload  = { type: type, name: name, content: content, proxied: proxied, ttl: 1 };
  if (existing) {
    var upd = await cfReq(auth, '/zones/' + zoneId + '/dns_records/' + existing.id, 'PUT', payload);
    return upd.success ? { ok: true, recordId: existing.id } : { ok: false, error: cfErrMsg(upd) };
  }
  var cre = await cfReq(auth, '/zones/' + zoneId + '/dns_records', 'POST', payload);
  return cre.success ? { ok: true, recordId: cre.result && cre.result.id } : { ok: false, error: cfErrMsg(cre) };
}

async function cfUpsertRoute(auth, zoneId, pattern, script) {
  var list  = await cfReq(auth, '/zones/' + zoneId + '/workers/routes');
  var exist = null;
  if (list && list.result) {
    for (var i = 0; i < list.result.length; i++) {
      if (list.result[i].pattern === pattern) { exist = list.result[i]; break; }
    }
  }
  var payload = { pattern: pattern, script: script };
  if (exist) {
    var upd = await cfReq(auth, '/zones/' + zoneId + '/workers/routes/' + exist.id, 'PUT', payload);
    return upd.success ? { ok: true, routeId: exist.id } : { ok: false, error: cfErrMsg(upd) };
  }
  var cre = await cfReq(auth, '/zones/' + zoneId + '/workers/routes', 'POST', payload);
  return cre.success ? { ok: true, routeId: cre.result && cre.result.id } : { ok: false, error: cfErrMsg(cre) };
}

// ── Worker subdomain 조회 (CNAME 값 확보) ────────────────────────────
async function getWorkerSubdomain(auth, accountId, workerName) {
  try {
    var subRes = await cfReq(auth, '/accounts/' + accountId + '/workers/scripts/' + workerName + '/subdomain');
    if (subRes.success && subRes.result && subRes.result.subdomain) {
      return workerName + '.' + subRes.result.subdomain + '.workers.dev';
    }
    var accSubRes = await cfReq(auth, '/accounts/' + accountId + '/workers/subdomain');
    if (accSubRes.success && accSubRes.result && accSubRes.result.subdomain) {
      return workerName + '.' + accSubRes.result.subdomain + '.workers.dev';
    }
  } catch (e) {
    console.warn('[provision] Worker subdomain 조회 실패:', e.message);
  }
  return workerName + '.workers.dev';
}

async function initWpSite(wpOrigin, wpSecret, params) {
  if (!wpOrigin || !wpOrigin.startsWith('http')) {
    return { ok: true, skipped: true, message: 'WP Origin 미설정 — 건너뜀' };
  }
  var url = wpOrigin.replace(/\/$/, '') + '/wp-json/cloudpress/v1/init-site';
  var res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type':        'application/json',
        'X-CloudPress-Secret': wpSecret || '',
        'X-CloudPress-Site':   params.site_prefix,
      },
      body: JSON.stringify({
        site_prefix: params.site_prefix,
        site_name:   params.site_name || params.site_prefix,
        admin_user:  params.admin_user,
        admin_pass:  params.admin_pass,
        admin_email: params.admin_email,
        site_url:    params.site_url,
      }),
    });
  } catch (e) {
    console.warn('[provision] WP Origin 연결 실패 (계속):', e.message);
    return { ok: true, skipped: true, message: 'WP Origin 연결 실패 (무시): ' + e.message };
  }
  if (res.status === 200 || res.status === 201) {
    var json;
    try { json = await res.json(); } catch (e) { json = {}; }
    return { ok: true, message: json.message || '초기화 완료' };
  }
  var errJson;
  try { errJson = await res.json(); } catch (e) { errJson = {}; }
  var errMsg = errJson.message || errJson.error || ('HTTP ' + res.status);
  console.warn('[provision] WP init 실패 (계속):', errMsg);
  return { ok: true, skipped: true, message: 'WP 초기화 실패 (무시): ' + errMsg };
}

function buildWorkerSource() {
  var L = [];
  L.push("'use strict';");
  L.push("export default {");
  L.push("  async fetch(request, env) {");
  L.push("    var url     = new URL(request.url);");
  L.push("    var rawHost = url.hostname;");
  L.push("    var host    = rawHost.indexOf('www.') === 0 ? rawHost.slice(4) : rawHost;");
  L.push("    if (url.pathname.indexOf('/api/') === 0 || url.pathname.indexOf('/__cloudpress/') === 0) {");
  L.push("      return fetch(request);");
  L.push("    }");
  L.push("    var site = null;");
  L.push("    var cacheKey = 'site_domain:' + host;");
  L.push("    try {");
  L.push("      var cached = await env.CACHE.get(cacheKey, { type: 'json' });");
  L.push("      if (cached) {");
  L.push("        site = cached;");
  L.push("      } else {");
  L.push("        var row = await env.DB.prepare(");
  L.push("          'SELECT id,name,site_prefix,site_d1_id,site_kv_id,wp_admin_url,status,suspended,suspension_reason'");
  L.push("          + ' FROM sites WHERE primary_domain=? AND status=\\'active\\' AND deleted_at IS NULL AND suspended=0 LIMIT 1'");
  L.push("        ).bind(host).first();");
  L.push("        if (row) {");
  L.push("          site = row;");
  L.push("          await env.CACHE.put(cacheKey, JSON.stringify(row), { expirationTtl: 300 });");
  L.push("        }");
  L.push("      }");
  L.push("    } catch (e) { return errPage(500, '서버 오류', e.message); }");
  L.push("    if (!site) return errPage(404, '사이트 없음', host + ' 에 연결된 사이트가 없습니다.');");
  L.push("    if (site.suspended) return suspendedPage(site.name, site.suspension_reason);");
  L.push("    var originBase = (env.WP_ORIGIN_URL || '').replace(/\\/+$/, '');");
  L.push("    if (!originBase) return errPage(503, '서버 설정 오류', 'WP Origin URL이 설정되지 않았습니다.');");
  L.push("    if (url.pathname.indexOf('/wp-admin') === 0 || url.pathname === '/wp-login.php') {");
  L.push("      var adminTarget = new URL(originBase + url.pathname + url.search);");
  L.push("      var adminHdrs   = new Headers(request.headers);");
  L.push("      adminHdrs.set('X-CloudPress-Site',   site.site_prefix);");
  L.push("      adminHdrs.set('X-CloudPress-Secret', env.WP_ORIGIN_SECRET || '');");
  L.push("      adminHdrs.set('X-CloudPress-Domain', rawHost);");
  L.push("      adminHdrs.set('Host',                adminTarget.hostname);");
  L.push("      adminHdrs.set('X-Forwarded-Host',    rawHost);");
  L.push("      adminHdrs.set('X-Forwarded-Proto',   'https');");
  L.push("      try {");
  L.push("        var aRes = await fetch(adminTarget.toString(), {");
  L.push("          method:   request.method,");
  L.push("          headers:  adminHdrs,");
  L.push("          body:     request.method === 'GET' || request.method === 'HEAD' ? null : request.body,");
  L.push("          redirect: 'manual',");
  L.push("        });");
  L.push("        if (aRes.status >= 300 && aRes.status < 400) {");
  L.push("          var loc = aRes.headers.get('Location') || '';");
  L.push("          if (loc.indexOf(originBase) === 0) loc = 'https://' + rawHost + loc.slice(originBase.length);");
  L.push("          return new Response(null, { status: aRes.status, headers: { 'Location': loc } });");
  L.push("        }");
  L.push("        return aRes;");
  L.push("      } catch (e) { return errPage(502, 'WP Admin 오류', e.message); }");
  L.push("    }");
  L.push("    var originUrl = new URL(originBase + url.pathname + url.search);");
  L.push("    var ph = new Headers(request.headers);");
  L.push("    ph.set('X-CloudPress-Site',       site.site_prefix);");
  L.push("    ph.set('X-CloudPress-Secret',     env.WP_ORIGIN_SECRET || '');");
  L.push("    ph.set('X-CloudPress-Domain',     rawHost);");
  L.push("    ph.set('X-CloudPress-D1-ID',      site.site_d1_id || '');");
  L.push("    ph.set('X-CloudPress-KV-ID',      site.site_kv_id || '');");
  L.push("    ph.set('X-CloudPress-Public-URL', 'https://' + rawHost);");
  L.push("    ph.set('Host',                    originUrl.hostname);");
  L.push("    ph.set('X-Forwarded-Host',        rawHost);");
  L.push("    ph.set('X-Forwarded-Proto',       'https');");
  L.push("    ph.set('X-Real-IP',               request.headers.get('CF-Connecting-IP') || '');");
  L.push("    var oRes;");
  L.push("    try {");
  L.push("      oRes = await fetch(originUrl.toString(), {");
  L.push("        method:   request.method,");
  L.push("        headers:  ph,");
  L.push("        body:     request.method === 'GET' || request.method === 'HEAD' ? null : request.body,");
  L.push("        redirect: 'manual',");
  L.push("      });");
  L.push("    } catch (e) { return errPage(502, 'Origin 오류', e.message); }");
  L.push("    if (oRes.status >= 300 && oRes.status < 400) {");
  L.push("      var rLoc = oRes.headers.get('Location') || '';");
  L.push("      if (rLoc.indexOf(originBase) === 0) rLoc = 'https://' + rawHost + rLoc.slice(originBase.length);");
  L.push("      return new Response(null, { status: oRes.status, headers: { 'Location': rLoc } });");
  L.push("    }");
  L.push("    var rh   = new Headers();");
  L.push("    var skip = ['transfer-encoding','content-encoding','content-length','connection','keep-alive'];");
  L.push("    for (var pair of oRes.headers) {");
  L.push("      if (skip.indexOf(pair[0].toLowerCase()) === -1) rh.set(pair[0], pair[1]);");
  L.push("    }");
  L.push("    rh.set('X-Cache', 'MISS');");
  L.push("    rh.set('X-Frame-Options', 'SAMEORIGIN');");
  L.push("    rh.set('X-Content-Type-Options', 'nosniff');");
  L.push("    var ct         = oRes.headers.get('content-type') || '';");
  L.push("    var originHost = originUrl.hostname;");
  L.push("    if (ct.indexOf('text/html') >= 0) {");
  L.push("      var html = await oRes.text();");
  L.push("      var rw   = html.split(originBase).join('https://' + rawHost);");
  L.push("      if (originHost !== rawHost) rw = rw.split(originHost).join(rawHost);");
  L.push("      return new Response(rw, { status: oRes.status, headers: rh });");
  L.push("    }");
  L.push("    if (ct.indexOf('text/css') >= 0 || ct.indexOf('javascript') >= 0) {");
  L.push("      var txt = await oRes.text();");
  L.push("      var rw2 = txt.split(originBase).join('https://' + rawHost);");
  L.push("      if (originHost !== rawHost) rw2 = rw2.split(originHost).join(rawHost);");
  L.push("      return new Response(rw2, { status: oRes.status, headers: rh });");
  L.push("    }");
  L.push("    return new Response(oRes.body, { status: oRes.status, headers: rh });");
  L.push("  },");
  L.push("};");
  L.push("function errPage(status, title, detail) {");
  L.push("  return new Response('<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>' + title + '</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f9fa}.b{text-align:center;padding:40px}h1{color:#333;font-size:1.4rem}p{color:#666;font-size:.88rem}</style></head><body><div class=\"b\"><h1>' + title + '</h1><p>' + detail + '</p></div></body></html>', { status: status, headers: { 'Content-Type': 'text/html;charset=utf-8' } });");
  L.push("}");
  L.push("function suspendedPage(name, reason) {");
  L.push("  return new Response('<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>일시정지</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff8f0}.b{text-align:center;padding:40px}h1{color:#e67e22;font-size:1.4rem}</style></head><body><div class=\"b\"><h1>사이트 일시정지</h1><p>' + (name || '이 사이트') + '는 정지 상태입니다.</p>' + (reason ? '<p>' + reason + '</p>' : '') + '</div></body></html>', { status: 503, headers: { 'Content-Type': 'text/html;charset=utf-8' } });");
  L.push("}");
  return L.join('\n');
}

async function uploadWorker(auth, accountId, workerName, opts) {
  var boundary = '----CPBoundary' + Date.now().toString(36);

  var bindings = [];
  if (opts.mainDbId) {
    bindings.push({ type: 'd1', name: 'DB', id: opts.mainDbId });
  }
  if (opts.cacheKvId) {
    bindings.push({ type: 'kv_namespace', name: 'CACHE', namespace_id: opts.cacheKvId });
  }
  if (opts.sessionsKvId) {
    bindings.push({ type: 'kv_namespace', name: 'SESSIONS', namespace_id: opts.sessionsKvId });
  }
  bindings.push({ type: 'plain_text', name: 'WP_ORIGIN_URL',    text: opts.wpOriginUrl || '' });
  bindings.push({ type: 'plain_text', name: 'WP_ORIGIN_SECRET', text: opts.wpOriginSecret || '' });
  bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID',    text: opts.cfAccountId || '' });
  bindings.push({ type: 'plain_text', name: 'CF_API_TOKEN',     text: opts.cfApiKey || '' });

  var metadata  = JSON.stringify({
    main_module: 'worker.js',
    compatibility_date: '2024-09-23',
    bindings: bindings,
  });
  var workerSrc = buildWorkerSource();
  var enc  = new TextEncoder();
  var CRLF = '\r\n';
  var p1h  = '--' + boundary + CRLF + 'Content-Disposition: form-data; name="metadata"' + CRLF + 'Content-Type: application/json' + CRLF + CRLF;
  var p2h  = '--' + boundary + CRLF + 'Content-Disposition: form-data; name="worker.js"; filename="worker.js"' + CRLF + 'Content-Type: application/javascript+module' + CRLF + CRLF;
  var end  = CRLF + '--' + boundary + '--' + CRLF;
  var chunks  = [enc.encode(p1h), enc.encode(metadata), enc.encode(CRLF), enc.encode(p2h), enc.encode(workerSrc), enc.encode(end)];
  var total   = chunks.reduce(function(s, c) { return s + c.length; }, 0);
  var bodyBuf = new Uint8Array(total);
  var off = 0;
  for (var i = 0; i < chunks.length; i++) { bodyBuf.set(chunks[i], off); off += chunks[i].length; }

  var uploadHdrs;
  if (auth.type === 'global') {
    uploadHdrs = {
      'Content-Type': 'multipart/form-data; boundary=' + boundary,
      'X-Auth-Email': auth.email,
      'X-Auth-Key':   auth.key,
    };
  } else {
    uploadHdrs = {
      'Content-Type':  'multipart/form-data; boundary=' + boundary,
      'Authorization': 'Bearer ' + (auth.value || auth.key),
    };
  }
  try {
    var res  = await fetch(CF_API + '/accounts/' + accountId + '/workers/scripts/' + workerName, {
      method: 'PUT',
      headers: uploadHdrs,
      body: bodyBuf.buffer,
    });
    var json = await res.json();
    if (!json.success) return { ok: false, error: 'Worker 업로드 실패: ' + cfErrMsg(json) };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Worker 업로드 오류: ' + e.message };
  }
}

// ── Worker 바인딩 직접 업데이트 (D1 + KV 자동 연결) ────────────────
// CF Workers API PATCH /settings 엔드포인트로 바인딩을 직접 등록.
// wrangler.toml 재배포 없이 코드 자체에서 D1/KV를 Worker에 자동 연결.
async function updateWorkerBindings(auth, accountId, workerName, opts) {
  console.log('[provision] Worker 바인딩 업데이트 시작: ' + workerName);

  // 1. 현재 Worker settings 조회 (기존 바인딩 유지용)
  var settingsRes = await cfReq(
    auth,
    '/accounts/' + accountId + '/workers/scripts/' + workerName + '/settings',
    'GET'
  );

  var existingBindings = [];
  if (settingsRes.success && settingsRes.result && Array.isArray(settingsRes.result.bindings)) {
    existingBindings = settingsRes.result.bindings;
  }

  // 2. 새 바인딩 맵 구성 (이름 기준으로 기존 것 대체)
  var bindingMap = {};
  for (var i = 0; i < existingBindings.length; i++) {
    var b = existingBindings[i];
    if (b.name) bindingMap[b.name] = b;
  }

  // DB (메인 D1)
  if (opts.mainDbId) {
    bindingMap['DB'] = { type: 'd1', name: 'DB', id: opts.mainDbId };
  }
  // CACHE KV
  if (opts.cacheKvId) {
    bindingMap['CACHE'] = { type: 'kv_namespace', name: 'CACHE', namespace_id: opts.cacheKvId };
  }
  // SESSIONS KV
  if (opts.sessionsKvId) {
    bindingMap['SESSIONS'] = { type: 'kv_namespace', name: 'SESSIONS', namespace_id: opts.sessionsKvId };
  }
  // 환경 변수
  if (opts.wpOriginUrl) {
    bindingMap['WP_ORIGIN_URL'] = { type: 'plain_text', name: 'WP_ORIGIN_URL', text: opts.wpOriginUrl };
  }
  if (opts.wpOriginSecret) {
    bindingMap['WP_ORIGIN_SECRET'] = { type: 'plain_text', name: 'WP_ORIGIN_SECRET', text: opts.wpOriginSecret };
  }
  if (opts.cfAccountId) {
    bindingMap['CF_ACCOUNT_ID'] = { type: 'plain_text', name: 'CF_ACCOUNT_ID', text: opts.cfAccountId };
  }
  if (opts.cfApiKey) {
    bindingMap['CF_API_TOKEN'] = { type: 'plain_text', name: 'CF_API_TOKEN', text: opts.cfApiKey };
  }

  var newBindings = Object.values(bindingMap);

  // 3. multipart/form-data로 settings PATCH (바인딩 포함)
  var boundary = '----CPSettingsBound' + Date.now().toString(36);
  var CRLF = '\r\n';
  var metadata = JSON.stringify({ bindings: newBindings });
  var enc = new TextEncoder();
  var p1h = '--' + boundary + CRLF +
    'Content-Disposition: form-data; name="settings"' + CRLF +
    'Content-Type: application/json' + CRLF + CRLF;
  var end = CRLF + '--' + boundary + '--' + CRLF;
  var chunks = [enc.encode(p1h), enc.encode(metadata), enc.encode(end)];
  var total = chunks.reduce(function(s, c) { return s + c.length; }, 0);
  var bodyBuf = new Uint8Array(total);
  var off = 0;
  for (var j = 0; j < chunks.length; j++) { bodyBuf.set(chunks[j], off); off += chunks[j].length; }

  var hdrs;
  if (auth.type === 'global') {
    hdrs = {
      'Content-Type': 'multipart/form-data; boundary=' + boundary,
      'X-Auth-Email': auth.email,
      'X-Auth-Key':   auth.key,
    };
  } else {
    hdrs = {
      'Content-Type':  'multipart/form-data; boundary=' + boundary,
      'Authorization': 'Bearer ' + (auth.value || auth.key),
    };
  }

  try {
    var patchRes = await fetch(
      CF_API + '/accounts/' + accountId + '/workers/scripts/' + workerName + '/settings',
      { method: 'PATCH', headers: hdrs, body: bodyBuf.buffer }
    );
    var patchJson = await patchRes.json();
    if (!patchJson.success) {
      console.warn('[provision] Worker 바인딩 PATCH 실패:', cfErrMsg(patchJson));
      return { ok: false, error: 'Worker 바인딩 PATCH 실패: ' + cfErrMsg(patchJson) };
    }
    console.log('[provision] Worker 바인딩 자동 연결 완료 (' + newBindings.length + '개)');
    return { ok: true, count: newBindings.length };
  } catch (e) {
    console.warn('[provision] Worker 바인딩 업데이트 오류:', e.message);
    return { ok: false, error: 'Worker 바인딩 업데이트 오류: ' + e.message };
  }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  var user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  var siteId = params && params.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  var site;
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

  var encKey    = (env && env.ENCRYPTION_KEY) || 'cp_enc_default';
  var cfKey     = null;
  var cfEmail   = '';
  var cfAccount = null;

  if (site.cf_global_api_key && site.cf_account_id) {
    var raw = deobfuscate(site.cf_global_api_key, encKey);
    cfKey     = (raw && raw.length > 5) ? raw : site.cf_global_api_key;
    cfEmail   = site.cf_account_email || '';
    cfAccount = site.cf_account_id;
    console.log('[provision] 사용자 개인 CF 키 사용');
  }

  if (!cfKey || !cfAccount) {
    cfKey     = await getSetting(env, 'cf_api_token');
    cfAccount = await getSetting(env, 'cf_account_id');
    cfEmail   = '';
    if (cfKey && cfAccount) console.log('[provision] 관리자 전역 CF 키 사용');
  }

  if (!cfKey || !cfAccount) {
    var cfErrText = 'Cloudflare API 키 또는 Account ID가 설정되지 않았습니다. 관리자 설정 → Cloudflare CDN 설정을 먼저 완료해주세요.';
    await failSite(env.DB, siteId, 'config_missing', cfErrText);
    return jsonRes({ ok: false, error: cfErrText }, 400);
  }

  var auth         = makeAuth(cfKey, cfEmail);
  var wpOrigin     = await getSetting(env, 'wp_origin_url', '');
  var wpSecret     = await getSetting(env, 'wp_origin_secret', '');
  var domain       = site.primary_domain;
  var wwwDomain    = 'www.' + domain;
  var prefix       = site.site_prefix;
  var wpAdminUrl   = 'https://' + domain + '/wp-admin/';
  var mainDbId     = await getSetting(env, 'main_db_id', '');
  var cacheKvId    = await getSetting(env, 'cache_kv_id', '');
  var sessionsKvId = await getSetting(env, 'sessions_kv_id', '');

  // ── 워커 이름: cloudpress-proxy 고정 금지, 저장된 고유 이름 재사용 또는 신규 생성
  var workerName = await getSetting(env, 'cf_worker_name', '');
  if (!workerName || workerName === 'cloudpress-proxy') {
    workerName = 'cloudpress-proxy-' + randSuffix();
    try {
      await env.DB.prepare(
        "INSERT INTO settings (key,value,updated_at) VALUES ('cf_worker_name',?,datetime('now'))" +
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at"
      ).bind(workerName).run();
    } catch (e) { console.warn('[provision] worker name 저장 실패:', e.message); }
    console.log('[provision] 새 워커 이름 생성:', workerName);
  } else {
    console.log('[provision] 기존 워커 이름 재사용:', workerName);
  }

  console.log('[provision] start siteId=' + siteId + ' domain=' + domain + ' account=' + cfAccount + ' worker=' + workerName);

  // ── Step 1: D1 생성 ──────────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'd1_create' });
  var d1Id = site.site_d1_id || null;
  if (!d1Id) {
    var r1 = await createD1(auth, cfAccount, prefix);
    if (!r1.ok) {
      await failSite(env.DB, siteId, 'd1_create', r1.error);
      return jsonRes({ ok: false, error: r1.error }, 500);
    }
    d1Id = r1.id;
    await updateSite(env.DB, siteId, { site_d1_id: d1Id, site_d1_name: r1.name });
    console.log('[provision] D1 완료:', d1Id, r1.name);

    // D1 스키마 초기화 (신규 생성 시에만)
    await updateSite(env.DB, siteId, { provision_step: 'd1_schema' });
    await initD1Schema(auth, cfAccount, d1Id);
  } else {
    console.log('[provision] D1 기존 사용:', d1Id);
  }

  // ── Step 2: KV 생성 ──────────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'kv_create' });
  var kvId = site.site_kv_id || null;
  if (!kvId) {
    var r2 = await createKV(auth, cfAccount, prefix);
    if (!r2.ok) {
      await failSite(env.DB, siteId, 'kv_create', r2.error);
      return jsonRes({ ok: false, error: r2.error }, 500);
    }
    kvId = r2.id;
    await updateSite(env.DB, siteId, { site_kv_id: kvId, site_kv_title: r2.title });
    console.log('[provision] KV 완료:', kvId, r2.title);

    // KV 초기 데이터 저장 (신규 생성 시에만)
    await initKVData(auth, cfAccount, kvId, {
      site_id: siteId, site_prefix: prefix, site_name: site.name,
      domain: domain, d1_id: d1Id, status: 'active',
    });
  } else {
    console.log('[provision] KV 기존 사용:', kvId);
  }

  // ── Step 3: CACHE KV 도메인 매핑 ────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'kv_mapping' });
  var mapping = JSON.stringify({
    id: siteId, name: site.name, site_prefix: prefix,
    site_d1_id: d1Id, site_kv_id: kvId,
    wp_admin_url: wpAdminUrl, status: 'active', suspended: 0,
  });
  try {
    await env.CACHE.put('site_domain:' + domain,    mapping);
    await env.CACHE.put('site_domain:' + wwwDomain, mapping);
    await env.CACHE.put('site_prefix:' + prefix,    mapping);
    console.log('[provision] CACHE 매핑 완료');
  } catch (e) { console.warn('[provision] CACHE put 실패(무시):', e.message); }

  // ── Step 4: WP 초기화 ───────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'wp_init' });
  var wpRes = await initWpSite(wpOrigin, wpSecret, {
    site_prefix: prefix,
    site_name:   site.name,
    admin_user:  site.wp_username,
    admin_pass:  site.wp_password,
    admin_email: site.wp_admin_email || user.email,
    site_url:    'https://' + domain,
  });
  console.log('[provision] WP init:', wpRes.skipped ? ('건너뜀: ' + wpRes.message) : wpRes.message);

  // ── Step 5: CNAME 타겟 확보 + DNS 설정 ──────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });
  var cfZoneId = null, dnsRecordId = null, dnsRecordWwwId = null, domainStatus = 'manual_required';

  // CNAME 타겟 확보 (worker subdomain API 사용)
  var cnameTarget = await getSetting(env, 'worker_cname_target', '');
  if (!cnameTarget) {
    cnameTarget = await getWorkerSubdomain(auth, cfAccount, workerName);
    try {
      await env.DB.prepare(
        "INSERT INTO settings (key,value,updated_at) VALUES ('worker_cname_target',?,datetime('now'))" +
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at"
      ).bind(cnameTarget).run();
    } catch (e) { console.warn('[provision] cname target 저장 실패:', e.message); }
  }
  console.log('[provision] CNAME target:', cnameTarget);

  var zone = await cfGetZone(auth, domain);
  if (zone.ok) {
    cfZoneId = zone.zoneId;
    var dnsRoot = await cfUpsertDns(auth, cfZoneId, 'CNAME', domain,    cnameTarget, true);
    var dnsWww  = await cfUpsertDns(auth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true);
    if (dnsRoot.ok) dnsRecordId    = dnsRoot.recordId;
    if (dnsWww.ok)  dnsRecordWwwId = dnsWww.recordId;
  } else {
    console.log('[provision] CF Zone 없음 — DNS 수동 설정 필요');
  }

  // ── Step 6: Worker 업로드 ────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'worker_upload' });
  var upRes = await uploadWorker(auth, cfAccount, workerName, {
    mainDbId:       mainDbId,
    cacheKvId:      cacheKvId,
    sessionsKvId:   sessionsKvId,
    wpOriginUrl:    wpOrigin,
    wpOriginSecret: wpSecret,
    cfAccountId:    cfAccount,
    cfApiKey:       cfKey,
  });
  if (!upRes.ok) {
    console.warn('[provision] Worker 업로드 실패(계속):', upRes.error);
    await updateSite(env.DB, siteId, { error_message: upRes.error });
  } else {
    console.log('[provision] Worker 업로드 완료');
  }

  // ── Step 6-B: Worker 바인딩 자동 연결 (D1 + KV) ─────────────────
  // 코드 자체에서 CF API로 Worker 바인딩을 직접 등록
  // → Pages/wrangler.toml 재배포 없이 D1/KV 자동 연결
  await updateSite(env.DB, siteId, { provision_step: 'worker_binding' });
  var workerBindingRes = await updateWorkerBindings(auth, cfAccount, workerName, {
    mainDbId:       mainDbId,
    cacheKvId:      cacheKvId,
    sessionsKvId:   sessionsKvId,
    wpOriginUrl:    wpOrigin,
    wpOriginSecret: wpSecret,
    cfAccountId:    cfAccount,
    cfApiKey:       cfKey,
  });
  if (!workerBindingRes.ok) {
    console.warn('[provision] Worker 바인딩 자동 연결 실패(계속):', workerBindingRes.error);
  } else {
    console.log('[provision] Worker 바인딩 자동 연결 완료');
  }

  // ── Step 7: Worker Route 등록 ────────────────────────────────────
  if (zone.ok && cfZoneId) {
    await updateSite(env.DB, siteId, { provision_step: 'worker_route' });
    var rRoot = await cfUpsertRoute(auth, cfZoneId, domain + '/*',    workerName);
    var rWww  = await cfUpsertRoute(auth, cfZoneId, wwwDomain + '/*', workerName);
    if (rRoot.ok || rWww.ok) {
      domainStatus = 'dns_propagating';
      await updateSite(env.DB, siteId, {
        worker_route:         domain + '/*',
        worker_route_www:     wwwDomain + '/*',
        worker_route_id:      rRoot.routeId || null,
        worker_route_www_id:  rWww.routeId || null,
        cf_zone_id:           cfZoneId,
        dns_record_id:        dnsRecordId,
        dns_record_www_id:    dnsRecordWwwId,
      });
    }
  }

  // ── Step 8: Pages 바인딩 자동 업데이트 ──────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'pages_binding' });
  var pagesProjectName = await findPagesProjectName(auth, cfAccount);
  var bindingResult = { ok: false, error: 'Pages 프로젝트명 탐색 실패' };
  if (pagesProjectName) {
    bindingResult = await updatePagesBindings(auth, cfAccount, pagesProjectName, {
      mainDbId:       mainDbId,
      cacheKvId:      cacheKvId,
      sessionsKvId:   sessionsKvId,
      wpOriginUrl:    wpOrigin,
      wpOriginSecret: wpSecret,
      cfAccountId:    cfAccount,
      cfApiKey:       cfKey,
      encryptionKey:  encKey,
    });
  } else {
    console.warn('[provision] Pages 프로젝트명 탐색 실패 — 바인딩 수동 필요');
  }

  // ── Step 9: 완료 ─────────────────────────────────────────────────
  var dnsNote = null;
  var cnameInstructions = null;
  if (domainStatus === 'manual_required') {
    dnsNote = '외부 DNS 설정 필요 — CNAME 값: ' + cnameTarget;
    cnameInstructions = {
      type: 'CNAME',
      root: { host: '@',   value: cnameTarget, ttl: 3600 },
      www:  { host: 'www', value: cnameTarget, ttl: 3600 },
      note: '외부 DNS(가비아, 후이즈 등)에서 위 값으로 CNAME 레코드를 추가해주세요.',
    };
  }

  await updateSite(env.DB, siteId, {
    status:         'active',
    provision_step: 'completed',
    domain_status:  domainStatus,
    worker_name:    workerName,
    wp_admin_url:   wpAdminUrl,
    error_message:  dnsNote,
  });

  console.log('[provision] 완료 siteId=' + siteId + ' domainStatus=' + domainStatus);

  var finalSite = await env.DB.prepare(
    'SELECT status, provision_step, error_message, wp_admin_url, wp_username, wp_password,'
    + ' primary_domain, site_d1_id, site_kv_id, domain_status, worker_name, name FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({
    message:             '프로비저닝 완료',
    siteId:              siteId,
    site:                finalSite,
    wp_note:             wpRes.skipped ? wpRes.message : null,
    dns_note:            dnsNote,
    cname_instructions:  cnameInstructions,
    worker_binding:      workerBindingRes.ok
      ? ('자동 완료 (' + (workerBindingRes.count || 0) + '개 바인딩)')
      : ('실패: ' + (workerBindingRes.error || '오류')),
    pages_binding:       bindingResult.ok
      ? '자동 완료 (Pages 재배포 후 적용)'
      : ('수동 필요: ' + (bindingResult.error || '오류')),
  });
}
