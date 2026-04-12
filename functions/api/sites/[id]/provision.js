// functions/api/sites/[id]/provision.js — CloudPress v12.6
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
    var uid = await env.SESSIONS.get('session:' + t);
    if (!uid) return null;
    return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();
  } catch (e) { return null; }
}

async function getSetting(env, key, fallback) {
  try {
    var row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return (row && row.value != null) ? row.value : (fallback || '');
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
    ).bind(step, message, siteId).run();
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

var CF_API = 'https://api.cloudflare.com/client/v4';

function makeAuth(key, email) {
  if (email && email.indexOf('@') > 0) return { type: 'global', key: key, email: email };
  return { type: 'bearer', value: key };
}

function getAuthHeaders(auth) {
  if (auth.type === 'global') {
    return { 'Content-Type': 'application/json', 'X-Auth-Email': auth.email, 'X-Auth-Key': auth.key };
  }
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (auth.value || auth.key) };
}

async function cfReq(auth, path, method, body) {
  var opts = { method: method || 'GET', headers: getAuthHeaders(auth) };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  try {
    var res  = await fetch(CF_API + path, opts);
    var json = await res.json();
    if (!json.success) console.error('[cfReq] ' + (method || 'GET') + ' ' + path + ' failed:', JSON.stringify(json.errors || []));
    return json;
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

function cfErrMsg(json) {
  return (json.errors && json.errors[0]) ? json.errors[0].message : 'unknown';
}

async function createD1(auth, accountId, prefix) {
  var name = 'cp-site-' + prefix;
  var res  = await cfReq(auth, '/accounts/' + accountId + '/d1/database', 'POST', { name: name });
  if (!res.success || !res.result) return { ok: false, error: 'D1 생성 실패: ' + cfErrMsg(res) };
  var id = res.result.uuid || res.result.id;
  if (!id) return { ok: false, error: 'D1 생성 실패: ID 없음 result=' + JSON.stringify(res.result) };
  return { ok: true, id: id, name: name };
}

async function createKV(auth, accountId, prefix) {
  var title = 'CP_SITE_' + prefix.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  var res   = await cfReq(auth, '/accounts/' + accountId + '/storage/kv/namespaces', 'POST', { title: title });
  if (!res.success || !res.result) return { ok: false, error: 'KV 생성 실패: ' + cfErrMsg(res) };
  var id = res.result.id;
  if (!id) return { ok: false, error: 'KV 생성 실패: ID 없음 result=' + JSON.stringify(res.result) };
  return { ok: true, id: id, title: title };
}

async function cfGetZone(auth, domain) {
  var root = domain.split('.').slice(-2).join('.');
  var res  = await cfReq(auth, '/zones?name=' + encodeURIComponent(root) + '&status=active');
  if (!res.success || !res.result || !res.result.length) return { ok: false };
  return { ok: true, zoneId: res.result[0].id };
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

async function initWpSite(wpOrigin, wpSecret, params) {
  if (!wpOrigin) return { ok: false, error: 'WP Origin URL 미설정' };
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
    return { ok: false, error: 'WP Origin 연결 실패: ' + e.message };
  }
  if (res.status === 200 || res.status === 201) {
    var json;
    try { json = await res.json(); } catch (e) { json = {}; }
    return { ok: true, message: json.message || '초기화 완료' };
  }
  var errJson;
  try { errJson = await res.json(); } catch (e) { errJson = {}; }
  return { ok: false, error: errJson.message || errJson.error || ('HTTP ' + res.status) };
}

// Worker 소스 — template literal 완전 배제, 순수 문자열 연결
function buildWorkerSource() {
  var L = [];
  L.push("'use strict';");
  L.push("var CF_KV = 'https://api.cloudflare.com/client/v4';");
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
  L.push("    var cookie      = request.headers.get('cookie') || '';");
  L.push("    var isCacheable = request.method === 'GET'");
  L.push("      && url.pathname.indexOf('/wp-') !== 0");
  L.push("      && !url.searchParams.has('preview')");
  L.push("      && cookie.indexOf('wordpress_logged_in') === -1;");
  L.push("    if (isCacheable && site.site_kv_id && env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {");
  L.push("      var pcKey = 'page:' + host + url.pathname + (url.search || '');");
  L.push("      var pc    = await kvGet(env.CF_API_TOKEN, env.CF_ACCOUNT_ID, site.site_kv_id, pcKey);");
  L.push("      if (pc) {");
  L.push("        return new Response(pc.body, {");
  L.push("          headers: { 'Content-Type': pc.contentType || 'text/html;charset=utf-8', 'X-Cache': 'HIT' },");
  L.push("        });");
  L.push("      }");
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
  L.push("      if (isCacheable && oRes.status === 200 && site.site_kv_id && env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {");
  L.push("        var pcKey2 = 'page:' + host + url.pathname + (url.search || '');");
  L.push("        kvPut(env.CF_API_TOKEN, env.CF_ACCOUNT_ID, site.site_kv_id, pcKey2, { body: rw, contentType: ct }, 600);");
  L.push("      }");
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
  L.push("async function kvGet(token, accountId, nsId, key) {");
  L.push("  try {");
  L.push("    var r = await fetch(CF_KV + '/accounts/' + accountId + '/storage/kv/namespaces/' + nsId + '/values/' + encodeURIComponent(key), { headers: { 'Authorization': 'Bearer ' + token } });");
  L.push("    if (!r.ok) return null;");
  L.push("    return await r.json();");
  L.push("  } catch (e) { return null; }");
  L.push("}");
  L.push("async function kvPut(token, accountId, nsId, key, val, ttl) {");
  L.push("  try {");
  L.push("    await fetch(CF_KV + '/accounts/' + accountId + '/storage/kv/namespaces/' + nsId + '/values/' + encodeURIComponent(key) + '?expiration_ttl=' + (ttl || 600), { method: 'PUT', headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify(val) });");
  L.push("  } catch (e) {}");
  L.push("}");
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
  var bindings = [
    { type: 'd1',           name: 'DB',              id: opts.mainDbId || '' },
    { type: 'kv_namespace', name: 'CACHE',            namespace_id: opts.cacheKvId || '' },
    { type: 'kv_namespace', name: 'SESSIONS',         namespace_id: opts.sessionsKvId || '' },
    { type: 'plain_text',   name: 'WP_ORIGIN_URL',    text: opts.wpOriginUrl || '' },
    { type: 'plain_text',   name: 'WP_ORIGIN_SECRET', text: opts.wpOriginSecret || '' },
    { type: 'plain_text',   name: 'CF_ACCOUNT_ID',    text: opts.cfAccountId || '' },
    { type: 'plain_text',   name: 'CF_API_TOKEN',     text: opts.cfApiKey || '' },
  ];
  var metadata  = JSON.stringify({ main_module: 'worker.js', compatibility_date: '2024-09-23', bindings: bindings });
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
    uploadHdrs = { 'Content-Type': 'multipart/form-data; boundary=' + boundary, 'X-Auth-Email': auth.email, 'X-Auth-Key': auth.key };
  } else {
    uploadHdrs = { 'Content-Type': 'multipart/form-data; boundary=' + boundary, 'Authorization': 'Bearer ' + (auth.value || auth.key) };
  }
  try {
    var res  = await fetch(CF_API + '/accounts/' + accountId + '/workers/scripts/' + workerName, { method: 'PUT', headers: uploadHdrs, body: bodyBuf.buffer });
    var json = await res.json();
    if (!json.success) return { ok: false, error: 'Worker 업로드 실패: ' + cfErrMsg(json) };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Worker 업로드 오류: ' + e.message };
  }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  var user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  var siteId = params.id;
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

  var encKey    = env.ENCRYPTION_KEY || 'cp_enc_default';
  var cfKey     = null;
  var cfEmail   = '';
  var cfAccount = null;

  if (site.cf_global_api_key && site.cf_account_id) {
    var raw = deobfuscate(site.cf_global_api_key, encKey);
    cfKey     = raw || site.cf_global_api_key;
    cfEmail   = site.cf_account_email || '';
    cfAccount = site.cf_account_id;
  }
  if (!cfKey || !cfAccount) {
    cfKey     = await getSetting(env, 'cf_api_token');
    cfAccount = await getSetting(env, 'cf_account_id');
    cfEmail   = '';
  }
  if (!cfKey || !cfAccount) {
    await failSite(env.DB, siteId, 'config_missing', 'CF API 키 없음. 내 계정 → CF API 설정 먼저 해주세요.');
    var s0 = await env.DB.prepare('SELECT status,provision_step,error_message FROM sites WHERE id=?').bind(siteId).first();
    return jsonRes({ ok: false, error: s0 ? s0.error_message : 'CF API 키 없음', site: s0 }, 400);
  }

  var auth         = makeAuth(cfKey, cfEmail);
  var workerName   = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
  var wpOrigin     = await getSetting(env, 'wp_origin_url', '');
  var wpSecret     = await getSetting(env, 'wp_origin_secret', '');
  var domain       = site.primary_domain;
  var wwwDomain    = 'www.' + domain;
  var prefix       = site.site_prefix;
  var wpAdminUrl   = 'https://' + domain + '/wp-admin/';
  var mainDbId     = await getSetting(env, 'main_db_id', '');
  var cacheKvId    = await getSetting(env, 'cache_kv_id', '');
  var sessionsKvId = await getSetting(env, 'sessions_kv_id', '');

  console.log('[provision] start siteId=' + siteId + ' domain=' + domain + ' account=' + cfAccount);

  // Step 1: D1
  await updateSite(env.DB, siteId, { provision_step: 'd1_create' });
  var d1Id = site.site_d1_id || null;
  if (!d1Id) {
    var r1 = await createD1(auth, cfAccount, prefix);
    if (!r1.ok) { await failSite(env.DB, siteId, 'd1_create', r1.error); return jsonRes({ ok: false, error: r1.error }, 500); }
    d1Id = r1.id;
    await updateSite(env.DB, siteId, { site_d1_id: d1Id, site_d1_name: r1.name });
    console.log('[provision] D1 완료:', d1Id);
  }

  // Step 2: KV
  await updateSite(env.DB, siteId, { provision_step: 'kv_create' });
  var kvId = site.site_kv_id || null;
  if (!kvId) {
    var r2 = await createKV(auth, cfAccount, prefix);
    if (!r2.ok) { await failSite(env.DB, siteId, 'kv_create', r2.error); return jsonRes({ ok: false, error: r2.error }, 500); }
    kvId = r2.id;
    await updateSite(env.DB, siteId, { site_kv_id: kvId, site_kv_title: r2.title });
    console.log('[provision] KV 완료:', kvId);
  }

  // Step 3: CACHE KV 매핑
  await updateSite(env.DB, siteId, { provision_step: 'kv_mapping' });
  var mapping = JSON.stringify({ id: siteId, name: site.name, site_prefix: prefix, site_d1_id: d1Id, site_kv_id: kvId, wp_admin_url: wpAdminUrl, status: 'active', suspended: 0 });
  try {
    await env.CACHE.put('site_domain:' + domain,    mapping);
    await env.CACHE.put('site_domain:' + wwwDomain, mapping);
    await env.CACHE.put('site_prefix:' + prefix,    mapping);
  } catch (e) { console.error('[provision] CACHE put 실패(무시):', e.message); }

  // Step 4: WP 초기화
  await updateSite(env.DB, siteId, { provision_step: 'wp_init' });
  if (wpOrigin) {
    var wpRes = await initWpSite(wpOrigin, wpSecret, {
      site_prefix: prefix, site_name: site.name,
      admin_user: site.wp_username, admin_pass: site.wp_password,
      admin_email: site.wp_admin_email || user.email,
      site_url: 'https://' + domain,
    });
    if (!wpRes.ok) {
      await failSite(env.DB, siteId, 'wp_init', 'WP 초기화 실패: ' + wpRes.error);
      return jsonRes({ ok: false, error: wpRes.error }, 500);
    }
    console.log('[provision] WP init 완료:', wpRes.message);
  } else {
    console.log('[provision] WP Origin 없음 — wp_init 건너뜀');
  }

  // Step 5: DNS
  await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });
  var cfZoneId = null, dnsRecordId = null, dnsRecordWwwId = null, domainStatus = 'manual_required';
  var zone = await cfGetZone(auth, domain);
  if (zone.ok) {
    cfZoneId = zone.zoneId;
    var cnameTarget = workerName + '.workers.dev';
    var savedCname  = await getSetting(env, 'worker_cname_target', '');
    if (savedCname) {
      cnameTarget = savedCname;
    } else {
      try {
        var subRes = await cfReq(auth, '/accounts/' + cfAccount + '/workers/scripts/' + workerName + '/subdomain');
        if (subRes.success && subRes.result && subRes.result.subdomain) {
          cnameTarget = workerName + '.' + subRes.result.subdomain + '.workers.dev';
        }
      } catch (e) { console.log('[provision] subdomain 조회 실패, 폴백 사용'); }
    }
    console.log('[provision] CNAME target:', cnameTarget);
    var dnsRoot = await cfUpsertDns(auth, cfZoneId, 'CNAME', domain,    cnameTarget, true);
    var dnsWww  = await cfUpsertDns(auth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true);
    if (dnsRoot.ok) dnsRecordId    = dnsRoot.recordId;
    if (dnsWww.ok)  dnsRecordWwwId = dnsWww.recordId;
  }

  // Step 6: Worker Upload
  await updateSite(env.DB, siteId, { provision_step: 'worker_upload' });
  var upRes = await uploadWorker(auth, cfAccount, workerName, {
    mainDbId: mainDbId, cacheKvId: cacheKvId, sessionsKvId: sessionsKvId,
    wpOriginUrl: wpOrigin, wpOriginSecret: wpSecret,
    cfAccountId: cfAccount, cfApiKey: cfKey,
  });
  if (!upRes.ok) {
    console.error('[provision] Worker 업로드 실패(계속):', upRes.error);
    await updateSite(env.DB, siteId, { error_message: upRes.error });
  } else {
    console.log('[provision] Worker 업로드 완료');
  }

  // Step 7: Route
  if (zone.ok && cfZoneId) {
    await updateSite(env.DB, siteId, { provision_step: 'worker_route' });
    var rRoot = await cfUpsertRoute(auth, cfZoneId, domain + '/*',    workerName);
    var rWww  = await cfUpsertRoute(auth, cfZoneId, wwwDomain + '/*', workerName);
    if (rRoot.ok || rWww.ok) {
      domainStatus = 'dns_propagating';
      await updateSite(env.DB, siteId, {
        worker_route: domain + '/*', worker_route_www: wwwDomain + '/*',
        worker_route_id: rRoot.routeId || null, worker_route_www_id: rWww.routeId || null,
        cf_zone_id: cfZoneId, dns_record_id: dnsRecordId, dns_record_www_id: dnsRecordWwwId,
      });
    }
  }

  // Step 8: 완료
  var cnameHint = await getSetting(env, 'worker_cname_target', workerName + '.workers.dev');
  var finalMsg  = domainStatus === 'manual_required'
    ? 'DNS 수동 설정 필요: CNAME ' + domain + ' -> ' + cnameHint + ' (Cloudflare 프록시 켜기)'
    : null;

  await updateSite(env.DB, siteId, {
    status: 'active', provision_step: 'completed',
    domain_status: domainStatus, worker_name: workerName,
    wp_admin_url: wpAdminUrl, error_message: finalMsg,
  });

  console.log('[provision] 완료 siteId=' + siteId + ' domainStatus=' + domainStatus);

  var finalSite = await env.DB.prepare(
    'SELECT status,provision_step,error_message,wp_admin_url,wp_username,wp_password,'
    + 'primary_domain,site_d1_id,site_kv_id,domain_status,worker_name,name FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({ message: '프로비저닝 완료', siteId: siteId, site: finalSite });
}
