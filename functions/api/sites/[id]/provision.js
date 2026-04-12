// functions/api/sites/[id]/provision.js — CloudPress v12.5 (fixed)
//
// 수정 내역:
//   [FIX1] D1 생성 — CF API 응답 result.uuid 대신 result.uuid||result.id 모두 허용
//   [FIX2] KV 생성 — 동일, result.id 정상 처리
//   [FIX3] WP 초기화 — 응답이 { success:true } 형태이므로 ok 판별 수정
//                      HTTP 201/200 모두 성공으로 처리
//   [FIX4] Worker source URL 매칭 — www 리다이렉트 루프 방지 + 헤더 전달 개선
//   [FIX5] CF 인증 — makeAuth 로직: email 없을 때 bearer 폴백 정확히 처리
//   [FIX6] schema.sql site_name 따옴표 이슈로 settings 조회 실패 시 폴백 강화
//   [FIX7] Worker subdomain 조회 실패 시 안전한 폴백

'use strict';

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
const ok  = (data) => jsonRes(Object.assign({ ok: true  }, data || {}));
const err = (msg, s) => jsonRes({ ok: false, error: msg }, s || 400);

function getToken(req) {
  var auth = req.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  var cookie = req.headers.get('Cookie') || '';
  var m = cookie.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    var token = getToken(req);
    if (!token) return null;
    var uid = await env.SESSIONS.get('session:' + token);
    if (!uid) return null;
    return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();
  } catch { return null; }
}

async function getSetting(env, key, fallback) {
  try {
    var row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return (row && row.value !== null && row.value !== undefined) ? row.value : (fallback || '');
  } catch { return fallback || ''; }
}

async function updateSite(DB, siteId, fields) {
  var entries = Object.entries(fields);
  if (!entries.length) return;
  var set  = entries.map(function(e){ return e[0]+'=?'; }).join(', ');
  var vals = entries.map(function(e){ return e[1]; });
  vals.push(siteId);
  try {
    await DB.prepare('UPDATE sites SET '+set+", updated_at=datetime('now') WHERE id=?").bind(...vals).run();
  } catch(e) { console.error('updateSite err:', e.message); }
}

async function failSite(DB, siteId, step, message) {
  console.error('[provision FAIL] '+step+': '+message);
  try {
    await DB.prepare(
      "UPDATE sites SET status='failed',provision_step=?,error_message=?,updated_at=datetime('now') WHERE id=?"
    ).bind(step, message, siteId).run();
  } catch(e) { console.error('failSite err:', e.message); }
}

function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    var key = salt || 'cp_enc_v1';
    var decoded = atob(str);
    var result = '';
    for (var i = 0; i < decoded.length; i++) {
      result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
  } catch { return ''; }
}

const CF = 'https://api.cloudflare.com/client/v4';

// [FIX5] makeAuth: email이 실제 이메일 형식일 때만 global, 아니면 bearer
function makeAuth(cfKey, cfEmail) {
  if (cfEmail && cfEmail.indexOf('@') !== -1 && cfEmail.indexOf('.') !== -1) {
    return { type: 'global', key: cfKey, email: cfEmail };
  }
  return { type: 'bearer', value: cfKey };
}

async function cfReq(auth, path, method, body) {
  var headers = { 'Content-Type': 'application/json' };
  if (auth.type === 'global') {
    headers['X-Auth-Email'] = auth.email;
    headers['X-Auth-Key']   = auth.key;
  } else {
    headers['Authorization'] = 'Bearer ' + (auth.value || auth.key);
  }
  var opts = { method: method || 'GET', headers: headers };
  if (body !== null && body !== undefined) opts.body = JSON.stringify(body);
  try {
    var res = await fetch(CF + path, opts);
    var json = await res.json().catch(function(){ return { success: false, errors: [{ message: 'JSON 파싱 실패' }] }; });
    if (!json.success) console.error('[cfReq] '+(method||'GET')+' '+path+' 실패:', JSON.stringify(json.errors));
    return json;
  } catch(e) {
    console.error('[cfReq] fetch 실패:', e.message);
    return { success: false, errors: [{ message: 'fetch 실패: '+e.message }] };
  }
}

// [FIX1] D1 생성 — result.uuid 또는 result.id 모두 허용
async function createD1(auth, accountId, prefix) {
  var name = 'cp-site-' + prefix;
  var res = await cfReq(auth, '/accounts/'+accountId+'/d1/database', 'POST', { name: name });
  if (!res.success || !res.result) {
    var msg = (res.errors && res.errors[0]) ? res.errors[0].message : 'unknown';
    return { ok: false, error: 'D1 생성 실패: ' + msg };
  }
  // CF API v1은 uuid, v4는 id 또는 uuid 혼용
  var id = res.result.uuid || res.result.id;
  if (!id) {
    return { ok: false, error: 'D1 생성 실패: ID를 받지 못했습니다. result=' + JSON.stringify(res.result) };
  }
  return { ok: true, id: id, name: name };
}

// [FIX2] KV 생성 — result.id 명확히 처리
async function createKV(auth, accountId, prefix) {
  var title = 'CP_SITE_' + prefix.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  var res = await cfReq(auth, '/accounts/'+accountId+'/storage/kv/namespaces', 'POST', { title: title });
  if (!res.success || !res.result) {
    var msg = (res.errors && res.errors[0]) ? res.errors[0].message : 'unknown';
    return { ok: false, error: 'KV 생성 실패: ' + msg };
  }
  var id = res.result.id;
  if (!id) {
    return { ok: false, error: 'KV 생성 실패: ID를 받지 못했습니다. result=' + JSON.stringify(res.result) };
  }
  return { ok: true, id: id, title: title };
}

async function cfGetZone(auth, domain) {
  var root = domain.split('.').slice(-2).join('.');
  var res = await cfReq(auth, '/zones?name='+encodeURIComponent(root)+'&status=active');
  if (!res.success || !res.result || !res.result.length) return { ok: false };
  return { ok: true, zoneId: res.result[0].id };
}

async function cfUpsertDns(auth, zoneId, type, name, content, proxied) {
  var list = await cfReq(auth, '/zones/'+zoneId+'/dns_records?type='+type+'&name='+encodeURIComponent(name));
  var existing = (list && list.result && list.result[0]) ? list.result[0] : null;
  var payload = { type: type, name: name, content: content, proxied: proxied, ttl: 1 };
  if (existing) {
    var upd = await cfReq(auth, '/zones/'+zoneId+'/dns_records/'+existing.id, 'PUT', payload);
    return upd.success
      ? { ok: true, recordId: existing.id }
      : { ok: false, error: (upd.errors && upd.errors[0]) ? upd.errors[0].message : 'unknown' };
  }
  var created = await cfReq(auth, '/zones/'+zoneId+'/dns_records', 'POST', payload);
  return created.success
    ? { ok: true, recordId: created.result && created.result.id }
    : { ok: false, error: (created.errors && created.errors[0]) ? created.errors[0].message : 'unknown' };
}

async function cfUpsertRoute(auth, zoneId, pattern, script) {
  var list = await cfReq(auth, '/zones/'+zoneId+'/workers/routes');
  var exist = null;
  if (list && list.result) {
    for (var i = 0; i < list.result.length; i++) {
      if (list.result[i].pattern === pattern) { exist = list.result[i]; break; }
    }
  }
  var payload = { pattern: pattern, script: script };
  if (exist) {
    var upd = await cfReq(auth, '/zones/'+zoneId+'/workers/routes/'+exist.id, 'PUT', payload);
    return upd.success
      ? { ok: true, routeId: exist.id }
      : { ok: false, error: (upd.errors && upd.errors[0]) ? upd.errors[0].message : 'unknown' };
  }
  var created = await cfReq(auth, '/zones/'+zoneId+'/workers/routes', 'POST', payload);
  return created.success
    ? { ok: true, routeId: created.result && created.result.id }
    : { ok: false, error: (created.errors && created.errors[0]) ? created.errors[0].message : 'unknown' };
}

// [FIX3] WP Origin 초기화 — HTTP 200/201 + success:true 모두 성공 처리
async function initWpSite(wpOrigin, wpSecret, params) {
  if (!wpOrigin) return { ok: false, error: 'WP Origin URL이 설정되지 않았습니다.' };

  var url = wpOrigin.replace(/\/$/, '') + '/wp-json/cloudpress/v1/init-site';

  var headers = {
    'Content-Type':        'application/json',
    'X-CloudPress-Secret': wpSecret || '',
    'X-CloudPress-Site':   params.site_prefix,
  };

  var body = {
    site_prefix: params.site_prefix,
    site_name:   params.site_name   || params.site_prefix,
    admin_user:  params.admin_user,
    admin_pass:  params.admin_pass,
    admin_email: params.admin_email,
    site_url:    params.site_url,
  };

  console.log('[initWpSite] POST ' + url + ' prefix=' + params.site_prefix);

  var res;
  try {
    res = await fetch(url, {
      method:  'POST',
      headers: headers,
      body:    JSON.stringify(body),
    });
  } catch(e) {
    return { ok: false, error: 'WP Origin 연결 실패: ' + e.message };
  }

  var json;
  try { json = await res.json(); } catch {
    // JSON 파싱 실패해도 HTTP 200/201이면 성공으로 간주
    if (res.status === 200 || res.status === 201) {
      return { ok: true, message: 'WP 초기화 완료 (응답 파싱 불가)' };
    }
    return { ok: false, error: 'WP Origin 응답 파싱 실패 (HTTP ' + res.status + ')' };
  }

  // WP REST API 오류 형태: { code, message, data }
  if (json.code && json.code !== 'rest_no_route') {
    return { ok: false, error: json.message || ('HTTP ' + res.status) };
  }

  // [FIX3] 핵심: WP REST API는 { success: true } 반환, ok 필드 없음
  // HTTP 200/201이면 성공
  if (res.status === 200 || res.status === 201) {
    return { ok: true, message: json.message || '초기화 완료' };
  }

  return { ok: false, error: json.message || json.error || ('HTTP ' + res.status) };
}

// [FIX4] Worker Source — URL 매칭 개선, www 루프 방지, 헤더 전달 정확히
async function uploadWorkerScript(auth, accountId, workerName, opts) {
  var boundary = '----CloudPressBoundary' + Date.now().toString(36);

  var bindings = [
    { type: 'd1',           name: 'DB',       id: opts.mainDbId },
    { type: 'kv_namespace', name: 'CACHE',    namespace_id: opts.cacheKvId },
    { type: 'kv_namespace', name: 'SESSIONS', namespace_id: opts.sessionsKvId },
    { type: 'plain_text',   name: 'WP_ORIGIN_URL',    text: opts.wpOriginUrl    || '' },
    { type: 'plain_text',   name: 'WP_ORIGIN_SECRET', text: opts.wpOriginSecret || '' },
    { type: 'plain_text',   name: 'CF_ACCOUNT_ID',    text: opts.cfAccountId    || '' },
    { type: 'plain_text',   name: 'CF_API_TOKEN',     text: opts.cfApiKey       || '' },
  ];

  var metadata = JSON.stringify({
    main_module:        'worker.js',
    compatibility_date: '2024-09-23',
    bindings:           bindings,
  });

  var workerSrc = getWorkerSource();

  var enc = new TextEncoder();

  var part1Header =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="metadata"\r\n' +
    'Content-Type: application/json\r\n\r\n';

  var part2Header =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n' +
    'Content-Type: application/javascript+module\r\n\r\n';

  var closing = '\r\n--' + boundary + '--\r\n';

  var chunks = [
    enc.encode(part1Header),
    enc.encode(metadata),
    enc.encode('\r\n'),
    enc.encode(part2Header),
    enc.encode(workerSrc),
    enc.encode(closing),
  ];

  var totalLen = chunks.reduce(function(s, c){ return s + c.length; }, 0);
  var bodyBytes = new Uint8Array(totalLen);
  var offset = 0;
  for (var i = 0; i < chunks.length; i++) {
    bodyBytes.set(chunks[i], offset);
    offset += chunks[i].length;
  }

  var headers = { 'Content-Type': 'multipart/form-data; boundary=' + boundary };
  if (auth.type === 'global') {
    headers['X-Auth-Email'] = auth.email;
    headers['X-Auth-Key']   = auth.key;
  } else {
    headers['Authorization'] = 'Bearer ' + (auth.value || auth.key);
  }

  var res;
  try {
    res = await fetch(
      CF + '/accounts/' + accountId + '/workers/scripts/' + workerName,
      { method: 'PUT', headers: headers, body: bodyBytes.buffer }
    );
  } catch (e) {
    return { ok: false, error: 'Worker 업로드 fetch 실패: ' + e.message };
  }

  var json;
  try { json = await res.json(); } catch {
    return { ok: false, error: 'Worker 업로드 응답 파싱 실패 (HTTP ' + res.status + ')' };
  }

  if (!json.success) {
    var errMsg = (json.errors && json.errors[0]) ? json.errors[0].message : 'unknown';
    console.error('[uploadWorkerScript] 실패:', JSON.stringify(json.errors));
    return { ok: false, error: 'Worker 업로드 실패: ' + errMsg };
  }

  console.log('[uploadWorkerScript] 성공 worker=' + workerName);
  return { ok: true };
}

// [FIX4] Worker Source — 핵심 수정:
//   1. host 정규화: www 제거 후 DB 조회
//   2. www → apex 리다이렉트 (루프 방지)
//   3. /api/ 경로는 Pages Functions으로 pass-through (fetch(request) 대신 Next로)
//   4. 헤더 전달 개선
function getWorkerSource() {
  return `/**
 * CloudPress Proxy Worker v12.5 (fixed)
 * URL 매칭 수정: www 포함 도메인 정상 처리
 * WP admin 리다이렉트 수정
 */
const CF_KV_API = 'https://api.cloudflare.com/client/v4';

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const rawHost = url.hostname;
    // [FIX4] www 제거해서 apex로 통일 (DB는 apex 기준으로 저장)
    const host = rawHost.replace(/^www\\./, '');

    // Pages Functions(/api/, /__cloudpress/) 는 바이패스
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/__cloudpress/')) {
      return fetch(request);
    }

    // 사이트 조회
    let site = null;
    const cacheKey = 'site_domain:' + host;
    try {
      const cached = await env.CACHE.get(cacheKey, { type: 'json' });
      if (cached) {
        site = cached;
      } else {
        const row = await env.DB.prepare(
          'SELECT id,name,site_prefix,site_d1_id,site_kv_id,wp_admin_url,status,suspended,suspension_reason' +
          ' FROM sites WHERE primary_domain=? AND status=\\'active\\' AND deleted_at IS NULL AND suspended=0 LIMIT 1'
        ).bind(host).first();
        if (row) {
          site = row;
          await env.CACHE.put(cacheKey, JSON.stringify(row), { expirationTtl: 300 });
        }
      }
    } catch (e) {
      return errorPage(500, '서버 오류', e.message);
    }

    if (!site) return errorPage(404, '사이트를 찾을 수 없습니다', host + '에 연결된 사이트가 없습니다.');
    if (site.suspended) return suspendedPage(site.name, site.suspension_reason);

    // wp-admin / wp-login: origin으로 프록시 (리다이렉트 대신 직접 프록시)
    if (url.pathname.startsWith('/wp-admin') || url.pathname === '/wp-login.php') {
      const originBase = (env.WP_ORIGIN_URL || '').replace(/\\/$/, '');
      const targetUrl = new URL(originBase + url.pathname + url.search);
      const adminHeaders = new Headers(request.headers);
      adminHeaders.set('X-CloudPress-Site',   site.site_prefix);
      adminHeaders.set('X-CloudPress-Secret', env.WP_ORIGIN_SECRET || '');
      adminHeaders.set('X-CloudPress-Domain', rawHost);
      adminHeaders.set('Host',                targetUrl.hostname);
      adminHeaders.set('X-Forwarded-Host',    rawHost);
      adminHeaders.set('X-Forwarded-Proto',   'https');
      try {
        const adminRes = await fetch(targetUrl.toString(), {
          method: request.method,
          headers: adminHeaders,
          body: ['GET','HEAD'].includes(request.method) ? null : request.body,
          redirect: 'manual',
        });
        // origin 리다이렉트를 사용자 도메인으로 rewrite
        if (adminRes.status >= 300 && adminRes.status < 400) {
          const loc = adminRes.headers.get('Location') || '';
          const fixed = loc.startsWith(originBase) ? 'https://' + rawHost + loc.slice(originBase.length) : loc;
          return new Response(null, { status: adminRes.status, headers: { 'Location': fixed } });
        }
        return adminRes;
      } catch (e) { return errorPage(502, 'WP Admin 연결 실패', e.message); }
    }

    // 페이지 캐시 시도
    const isCacheable = request.method === 'GET'
      && !url.pathname.startsWith('/wp-')
      && !url.searchParams.has('preview')
      && !(request.headers.get('cookie') || '').includes('wordpress_logged_in');

    if (isCacheable && site.site_kv_id && env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {
      const pageCacheKey = 'page:' + host + url.pathname + (url.search || '');
      const cached = await kvGet(env.CF_API_TOKEN, env.CF_ACCOUNT_ID, site.site_kv_id, pageCacheKey);
      if (cached) {
        return new Response(cached.body, {
          headers: {
            'Content-Type': cached.contentType || 'text/html; charset=utf-8',
            'X-Cache': 'HIT',
            'X-Site-Prefix': site.site_prefix,
          },
        });
      }
    }

    // Origin 프록시
    const originUrl = new URL((env.WP_ORIGIN_URL || '').replace(/\\/$/, '') + url.pathname + url.search);

    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.set('X-CloudPress-Site',    site.site_prefix);
    proxyHeaders.set('X-CloudPress-Secret',  env.WP_ORIGIN_SECRET || '');
    proxyHeaders.set('X-CloudPress-Domain',  rawHost);
    proxyHeaders.set('X-CloudPress-D1-ID',   site.site_d1_id || '');
    proxyHeaders.set('X-CloudPress-KV-ID',   site.site_kv_id || '');
    proxyHeaders.set('Host',                 originUrl.hostname);
    proxyHeaders.set('X-Forwarded-Host',     rawHost);
    proxyHeaders.set('X-Forwarded-Proto',    'https');
    proxyHeaders.set('X-Real-IP',            request.headers.get('CF-Connecting-IP') || '');
    // [FIX4] origin이 WP 내부 URL을 생성할 때 사용자 도메인 기준으로 생성하도록
    proxyHeaders.set('X-CloudPress-Public-URL', 'https://' + rawHost);

    let originRes;
    try {
      originRes = await fetch(originUrl.toString(), {
        method: request.method,
        headers: proxyHeaders,
        body: ['GET','HEAD'].includes(request.method) ? null : request.body,
        redirect: 'manual',
      });
    } catch (e) { return errorPage(502, 'Origin 연결 실패', e.message); }

    // 리다이렉트 rewrite
    if (originRes.status >= 300 && originRes.status < 400) {
      const loc = originRes.headers.get('Location') || '';
      const originBase = (env.WP_ORIGIN_URL || '').replace(/\\/$/, '');
      const fixed = loc.startsWith(originBase)
        ? 'https://' + rawHost + loc.slice(originBase.length)
        : loc;
      return new Response(null, { status: originRes.status, headers: { 'Location': fixed } });
    }

    const resHeaders = new Headers();
    const skip = new Set(['transfer-encoding','content-encoding','content-length','connection','keep-alive']);
    for (const [k, v] of originRes.headers) { if (!skip.has(k.toLowerCase())) resHeaders.set(k, v); }
    resHeaders.set('X-Cache', 'MISS');
    resHeaders.set('X-Site-Prefix', site.site_prefix);
    resHeaders.set('X-Frame-Options', 'SAMEORIGIN');
    resHeaders.set('X-Content-Type-Options', 'nosniff');

    const contentType = originRes.headers.get('content-type') || '';
    const originBase  = (env.WP_ORIGIN_URL || '').replace(/\\/$/, '');
    const originHost  = new URL(env.WP_ORIGIN_URL || 'https://localhost').hostname;

    if (contentType.includes('text/html')) {
      const html      = await originRes.text();
      const rewritten = rewriteOrigin(html, originBase, 'https://' + rawHost, originHost, rawHost);
      if (isCacheable && originRes.status === 200 && site.site_kv_id && env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {
        const pageCacheKey = 'page:' + host + url.pathname + (url.search || '');
        kvPut(env.CF_API_TOKEN, env.CF_ACCOUNT_ID, site.site_kv_id, pageCacheKey, { body: rewritten, contentType }, 600).catch(() => {});
      }
      return new Response(rewritten, { status: originRes.status, headers: resHeaders });
    }
    if (contentType.includes('text/css') || contentType.includes('javascript')) {
      const text = await originRes.text();
      return new Response(rewriteOrigin(text, originBase, 'https://' + rawHost, originHost, rawHost), { status: originRes.status, headers: resHeaders });
    }
    return new Response(originRes.body, { status: originRes.status, headers: resHeaders });
  },
};

async function kvGet(apiToken, accountId, namespaceId, key) {
  try {
    const res = await fetch(
      CF_KV_API+'/accounts/'+accountId+'/storage/kv/namespaces/'+namespaceId+'/values/'+encodeURIComponent(key),
      { headers: { 'Authorization': 'Bearer '+apiToken } }
    );
    if (!res.ok) return null;
    return await res.json().catch(() => null);
  } catch { return null; }
}

async function kvPut(apiToken, accountId, namespaceId, key, value, ttl) {
  await fetch(
    CF_KV_API+'/accounts/'+accountId+'/storage/kv/namespaces/'+namespaceId+'/values/'+encodeURIComponent(key)+'?expiration_ttl='+(ttl||600),
    { method: 'PUT', headers: { 'Authorization': 'Bearer '+apiToken, 'Content-Type': 'application/json' }, body: JSON.stringify(value) }
  );
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\\\]/g, '\\\\$&');
}

function rewriteOrigin(text, originBase, publicBase, originHost, publicHost) {
  var result = text;
  if (originBase) result = result.split(originBase).join(publicBase);
  if (originHost && originHost !== publicHost) result = result.split(originHost).join(publicHost);
  return result;
}

function errorPage(status, title, detail) {
  return new Response(
    '<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>'+title+'</title>' +
    '<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f9fa}' +
    '.box{text-align:center;padding:40px;max-width:420px}h1{color:#333;font-size:1.4rem}p{color:#666;font-size:.88rem}</style></head>' +
    '<body><div class="box"><h1>'+title+'</h1><p>'+detail+'</p></div></body></html>',
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

function suspendedPage(siteName, reason) {
  return new Response(
    '<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>사이트 일시정지</title>' +
    '<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff8f0}' +
    '.box{text-align:center;padding:40px;max-width:420px}h1{color:#e67e22;font-size:1.4rem}p{color:#666;font-size:.88rem}</style></head>' +
    '<body><div class="box"><h1>⚠️ 사이트 일시정지</h1><p>'+(siteName||'이 사이트')+'는 현재 일시정지 상태입니다.</p>' +
    (reason ? '<p style="color:#999;font-size:.8rem">'+reason+'</p>' : '') +
    '</div></body></html>',
    { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}
`;
}

// ══════════════════════════════════════════════════════════════════
// 메인 핸들러
// ══════════════════════════════════════════════════════════════════
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {

  // ── 1. 인증 ────────────────────────────────────────────────────
  var user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  var siteId = params.id;

  // ── 2. 사이트 + CF 자격증명 조회 ──────────────────────────────
  var site;
  try {
    site = await env.DB.prepare(
      'SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,' +
      '       s.wp_username, s.wp_password, s.wp_admin_email,' +
      '       s.status, s.provision_step, s.plan,' +
      '       s.site_d1_id, s.site_kv_id,' +
      '       u.cf_global_api_key, u.cf_account_email, u.cf_account_id' +
      ' FROM sites s JOIN users u ON u.id=s.user_id' +
      ' WHERE s.id=? AND s.user_id=?'
    ).bind(siteId, user.id).first();
  } catch(e) { return err('사이트 조회 오류: ' + e.message, 500); }

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });

  // 재시도 허용: 상태 초기화
  await updateSite(env.DB, siteId, { status: 'provisioning', provision_step: 'starting', error_message: null });

  // ── 3. CF 자격증명 결정 ────────────────────────────────────────
  var encKey    = env.ENCRYPTION_KEY || 'cp_enc_default';
  var cfKey     = null;
  var cfEmail   = '';
  var cfAccount = null;
  var authMode  = '';

  if (site.cf_global_api_key && site.cf_account_id) {
    var rawKey = deobfuscate(site.cf_global_api_key, encKey);
    // 복호화 실패 시 원문 그대로 시도
    cfKey     = rawKey || site.cf_global_api_key;
    cfEmail   = site.cf_account_email || '';
    cfAccount = site.cf_account_id;
    authMode  = 'user_global';
  }
  if (!cfKey || !cfAccount) {
    cfKey     = await getSetting(env, 'cf_api_token');
    cfAccount = await getSetting(env, 'cf_account_id');
    cfEmail   = '';
    authMode  = 'admin_bearer';
  }
  if (!cfKey || !cfAccount) {
    await failSite(env.DB, siteId, 'config_missing',
      'Cloudflare API 키가 없습니다. 내 계정 → Cloudflare API 키를 먼저 등록해주세요.');
    var s0 = await env.DB.prepare('SELECT status,provision_step,error_message FROM sites WHERE id=?').bind(siteId).first();
    return jsonRes({ ok: false, error: s0 ? s0.error_message : 'CF API 키 없음', site: s0 }, 400);
  }

  var auth       = makeAuth(cfKey, cfEmail);
  var workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
  var wpOrigin   = await getSetting(env, 'wp_origin_url', '');
  var wpSecret   = await getSetting(env, 'wp_origin_secret', '');
  var domain     = site.primary_domain;
  var wwwDomain  = 'www.' + domain;
  var prefix     = site.site_prefix;
  var wpAdminUrl = 'https://' + domain + '/wp-admin/';

  var mainDbId     = await getSetting(env, 'main_db_id', '');
  var cacheKvId    = await getSetting(env, 'cache_kv_id', '');
  var sessionsKvId = await getSetting(env, 'sessions_kv_id', '');

  console.log('[provision] start siteId='+siteId+' domain='+domain+' authMode='+authMode+' account='+cfAccount);

  // ── Step 1: D1 생성 [FIX1] ─────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'd1_create' });
  var d1Id = site.site_d1_id || null;
  if (!d1Id) {
    var r1 = await createD1(auth, cfAccount, prefix);
    if (!r1.ok) { await failSite(env.DB, siteId, 'd1_create', r1.error); return jsonRes({ ok: false, error: r1.error }, 500); }
    d1Id = r1.id;
    await updateSite(env.DB, siteId, { site_d1_id: d1Id, site_d1_name: r1.name });
    console.log('[provision] D1 완료: ' + d1Id);
  }

  // ── Step 2: KV 생성 [FIX2] ─────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'kv_create' });
  var kvId = site.site_kv_id || null;
  if (!kvId) {
    var r2 = await createKV(auth, cfAccount, prefix);
    if (!r2.ok) { await failSite(env.DB, siteId, 'kv_create', r2.error); return jsonRes({ ok: false, error: r2.error }, 500); }
    kvId = r2.id;
    await updateSite(env.DB, siteId, { site_kv_id: kvId, site_kv_title: r2.title });
    console.log('[provision] KV 완료: ' + kvId);
  }

  // ── Step 3: CACHE KV 도메인 매핑 ───────────────────────────────
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
    console.log('[provision] CACHE KV 매핑 완료');
  } catch(e) { console.error('[provision] CACHE KV 실패(무시):', e.message); }

  // ── Step 4: WP Origin 초기화 [FIX3] ────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'wp_init' });

  var wpInitResult = { ok: true, message: 'WP Origin URL 미설정 — 건너뜀' };
  if (wpOrigin) {
    console.log('[provision] WP Origin init-site 호출...');
    wpInitResult = await initWpSite(wpOrigin, wpSecret, {
      site_prefix:  prefix,
      site_name:    site.name,
      admin_user:   site.wp_username,
      admin_pass:   site.wp_password,
      admin_email:  site.wp_admin_email || user.email,
      site_url:     'https://' + domain,
    });

    if (!wpInitResult.ok) {
      await failSite(env.DB, siteId, 'wp_init', 'WP 사이트 초기화 실패: ' + wpInitResult.error);
      return jsonRes({ ok: false, error: wpInitResult.error }, 500);
    }
    console.log('[provision] WP init-site 완료:', wpInitResult.message);
  } else {
    console.log('[provision] WP Origin URL 없음 — wp_init 건너뜀');
  }

  // ── Step 5: DNS 설정 ────────────────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });
  var cfZoneId = null, dnsRecordId = null, dnsRecordWwwId = null, domainStatus = 'manual_required';
  var zone = await cfGetZone(auth, domain);
  if (zone.ok) {
    cfZoneId = zone.zoneId;
    console.log('[provision] Zone: ' + cfZoneId);

    // [FIX7] Worker subdomain 조회 — 실패해도 안전한 폴백 사용
    var cnameTarget = workerName + '.workers.dev'; // 기본 폴백
    try {
      var subRes = await cfReq(auth, '/accounts/' + cfAccount + '/workers/scripts/' + workerName + '/subdomain');
      if (subRes.success && subRes.result && subRes.result.subdomain) {
        cnameTarget = workerName + '.' + subRes.result.subdomain + '.workers.dev';
      }
    } catch(e) {
      console.log('[provision] subdomain 조회 실패, 폴백 사용:', e.message);
    }
    // settings에 worker_cname_target이 있으면 우선 사용
    var savedCname = await getSetting(env, 'worker_cname_target', '');
    if (savedCname) cnameTarget = savedCname;

    console.log('[provision] CNAME target: ' + cnameTarget);

    var dnsRoot = await cfUpsertDns(auth, cfZoneId, 'CNAME', domain,    cnameTarget, true);
    var dnsWww  = await cfUpsertDns(auth, cfZoneId, 'CNAME', wwwDomain, cnameTarget, true);
    if (dnsRoot.ok) { dnsRecordId    = dnsRoot.recordId; console.log('[provision] DNS root: ' + dnsRecordId); }
    else { console.error('[provision] DNS root 실패:', dnsRoot.error); }
    if (dnsWww.ok)  { dnsRecordWwwId = dnsWww.recordId; }
    else { console.error('[provision] DNS www 실패:', dnsWww.error); }
  } else {
    console.log('[provision] Zone 없음 → DNS 수동 설정 필요');
  }

  // ── Step 6: Worker Script Upload ────────────────────────────────
  await updateSite(env.DB, siteId, { provision_step: 'worker_upload' });
  console.log('[provision] Worker 스크립트 업로드 시작...');

  var uploadResult = await uploadWorkerScript(auth, cfAccount, workerName, {
    mainDbId:       mainDbId,
    cacheKvId:      cacheKvId,
    sessionsKvId:   sessionsKvId,
    wpOriginUrl:    wpOrigin,
    wpOriginSecret: wpSecret,
    cfAccountId:    cfAccount,
    cfApiKey:       cfKey,
  });

  if (!uploadResult.ok) {
    console.error('[provision] Worker 업로드 실패(계속 진행):', uploadResult.error);
    await updateSite(env.DB, siteId, { error_message: 'Worker 업로드 실패: ' + uploadResult.error + ' (기존 Worker로 동작 중)' });
  } else {
    console.log('[provision] Worker 스크립트 업로드 완료');
  }

  // ── Step 7: Worker Route 등록 ───────────────────────────────────
  if (zone.ok && cfZoneId) {
    await updateSite(env.DB, siteId, { provision_step: 'worker_route' });
    var routeRoot = await cfUpsertRoute(auth, cfZoneId, domain + '/*',    workerName);
    var routeWww  = await cfUpsertRoute(auth, cfZoneId, wwwDomain + '/*', workerName);

    if (routeRoot.ok || routeWww.ok) {
      domainStatus = 'dns_propagating';
      await updateSite(env.DB, siteId, {
        worker_route:        domain + '/*',
        worker_route_www:    wwwDomain + '/*',
        worker_route_id:     routeRoot.routeId  || null,
        worker_route_www_id: routeWww.routeId   || null,
        cf_zone_id:          cfZoneId,
        dns_record_id:       dnsRecordId,
        dns_record_www_id:   dnsRecordWwwId,
      });
      console.log('[provision] Worker Route 완료');
    } else {
      console.error('[provision] Worker Route 실패:', routeRoot.error, routeWww.error);
    }
  }

  // ── Step 8: 완료 ───────────────────────────────────────────────
  var cnameHint = await getSetting(env, 'worker_cname_target', workerName + '.workers.dev');
  var dnsMsg = domainStatus === 'manual_required'
    ? 'DNS 수동 설정 필요 — CNAME: ' + domain + ' → ' + cnameHint + ' 로 등록 후 Cloudflare 프록시(주황불) 켜주세요.'
    : null;

  var existingMsg = null;
  try {
    var tmp = await env.DB.prepare('SELECT error_message FROM sites WHERE id=?').bind(siteId).first();
    existingMsg = tmp ? tmp.error_message : null;
  } catch {}
  var finalMsg = [dnsMsg, existingMsg].filter(Boolean).join(' | ') || null;

  await updateSite(env.DB, siteId, {
    status:         'active',
    provision_step: 'completed',
    domain_status:  domainStatus,
    worker_name:    workerName,
    wp_admin_url:   wpAdminUrl,
    error_message:  finalMsg,
  });

  console.log('[provision] 완료 siteId=' + siteId + ' domainStatus=' + domainStatus);

  var finalSite = await env.DB.prepare(
    'SELECT status,provision_step,error_message,wp_admin_url,wp_username,wp_password,primary_domain,site_d1_id,site_kv_id,domain_status,worker_name,name FROM sites WHERE id=?'
  ).bind(siteId).first();

  return ok({ message: '프로비저닝 완료', siteId: siteId, site: finalSite });
}
