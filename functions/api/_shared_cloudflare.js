// functions/api/_shared_cloudflare.js

const CF_API = 'https://api.cloudflare.com/client/v4';

export function cfHeaders(token, email) {
  if (email) {
    return {
      'Content-Type': 'application/json',
      'X-Auth-Key':   token,
      'X-Auth-Email': email,
    };
  }
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
}

export async function cfReq(auth, path, method = 'GET', body) {
  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;
  const opts  = { method, headers: cfHeaders(token, email) };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  try {
    const res  = await fetch(CF_API + path, opts);
    const json = await res.json();
    if (!json.success) {
      console.error(`[cfReq] ${method} ${path} 실패:`, JSON.stringify(json.errors || []));
    }
    return json;
  } catch (e) {
    return { success: false, errors: [{ message: e.message }] };
  }
}

export function cfErrMsg(json) {
  return (json?.errors || []).map(e => (e.code ? `[${e.code}] ` : '') + (e.message || '')).join('; ') || 'unknown';
}

export function randSuffix(len = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

export function deobfuscate(str, salt) {
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

export async function createD1(auth, accountId, prefix) {
  const name = `cloudpress-site-${prefix}-${Date.now().toString(36)}`;
  const res  = await cfReq(auth, `/accounts/${accountId}/d1/database`, 'POST', { name });
  if (res.success && res.result) {
    const id = res.result.uuid || res.result.id || res.result.database_id;
    if (id) return { ok: true, id, name };
  }
  return { ok: false, error: 'D1 생성 실패: ' + cfErrMsg(res) };
}

export async function createKV(auth, accountId, prefix) {
  const title = `cloudpress-site-${prefix}-kv`;
  const res   = await cfReq(auth, `/accounts/${accountId}/storage/kv/namespaces`, 'POST', { title });
  if (res.success && res.result?.id) {
    return { ok: true, id: res.result.id, title };
  }
  return { ok: false, error: 'KV 생성 실패: ' + cfErrMsg(res) };
}

export async function cfGetZone(auth, domain) {
  const root = domain.split('.').slice(-2).join('.');
  const res  = await cfReq(auth, `/zones?name=${encodeURIComponent(root)}&status=active`);
  if (res.success && res.result?.length > 0) return { ok: true, zoneId: res.result[0].id };
  return { ok: false, error: '존 없음: ' + root };
}

export async function cfUpsertDns(auth, zoneId, type, name, content, proxied = true) {
  const list     = await cfReq(auth, `/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`);
  const existing = list.result?.[0];
  if (existing) {
    const res = await cfReq(auth, `/zones/${zoneId}/dns_records/${existing.id}`, 'PATCH', { content, proxied });
    return { ok: res.success, recordId: existing.id };
  }
  const res = await cfReq(auth, `/zones/${zoneId}/dns_records`, 'POST', { type, name, content, proxied, ttl: 1 });
  if (res.success) return { ok: true, recordId: res.result?.id };
  return { ok: false, error: cfErrMsg(res) };
}

/**
 * 사이트별 WAF 커스텀 규칙 설정 (SQLi, XSS, Path Traversal 방어)
 */
export async function cfUpdateWafRules(auth, zoneId, sitePrefix, enabled = true) {
  // 1. 해당 Zone의 entry point ruleset ID 조회
  const rulesets = await cfReq(auth, `/zones/${zoneId}/rulesets`);
  const phaseRuleset = (rulesets.result || []).find(r => r.phase === 'http_request_firewall_custom');
  
  if (!phaseRuleset) return { ok: false, error: 'WAF Ruleset을 찾을 수 없습니다.' };

  const ruleName = `CP_WAF_${sitePrefix}`;
  const currentRules = phaseRuleset.rules || [];
  const existingRule = currentRules.find(r => r.description === ruleName);

  if (!enabled) {
    if (!existingRule) return { ok: true };
    // 규칙 삭제
    const res = await cfReq(auth, `/zones/${zoneId}/rulesets/${phaseRuleset.id}/rules/${existingRule.id}`, 'DELETE');
    return { ok: res.success };
  }

  // WAF 규칙 정의 (공격 패턴 탐지 시 차단)
  const ruleData = {
    action: "block",
    description: ruleName,
    expression: `(http.request.uri.path contains "${sitePrefix}") and (http.request.uri.query contains "union" or http.request.uri.query contains "select" or http.request.uri.query contains "<script>")`,
    enabled: true
  };

  if (existingRule) {
    // 기존 규칙 업데이트
    const res = await cfReq(auth, `/zones/${zoneId}/rulesets/${phaseRuleset.id}/rules/${existingRule.id}`, 'PATCH', ruleData);
    return { ok: res.success };
  } else {
    // 새 규칙 추가
    const res = await cfReq(auth, `/zones/${zoneId}/rulesets/${phaseRuleset.id}/rules`, 'POST', ruleData);
    return { ok: res.success };
  }
}

export async function cfUpsertRoute(auth, zoneId, pattern, workerName) {
  const list     = await cfReq(auth, `/zones/${zoneId}/workers/routes`);
  const existing = (list.result || []).find(r => r.pattern === pattern);
  if (existing) {
    const res = await cfReq(auth, `/zones/${zoneId}/workers/routes/${existing.id}`, 'PUT', { pattern, script: workerName });
    return { ok: res.success, routeId: existing.id };
  }
  const res = await cfReq(auth, `/zones/${zoneId}/workers/routes`, 'POST', { pattern, script: workerName });
  if (res.success) return { ok: true, routeId: res.result?.id };
  return { ok: false, error: cfErrMsg(res) };
}

export async function getWorkerSubdomain(auth, accountId, workerName) {
  const res = await cfReq(auth, `/accounts/${accountId}/workers/subdomain`);
  if (res.success && res.result?.subdomain) return `${workerName}.${res.result.subdomain}.workers.dev`;
  return `${workerName}.workers.dev`;
}

export async function enableWorkersDev(auth, accountId, workerName) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await cfReq(auth, `/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, 'POST', { enabled: true });
    if (res.success) return true;
    if (attempt < 2) await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}

export async function addWorkerCustomDomain(auth, accountId, workerName, hostname) {
  const res = await cfReq(auth, `/accounts/${accountId}/workers/domains`, 'PUT', {
    hostname, service: workerName, environment: 'production',
  });
  return res.success ? { ok: true, id: res.result?.id } : { ok: false, error: cfErrMsg(res) };
}

export async function uploadWordPressWorker(auth, accountId, workerName, opts) {
  const {
    mainDbId, cacheKvId, sessionsKvId, siteD1Id, siteKvId,
    cfAccountId, cfApiToken, sitePrefix, siteName, siteDomain, phpVersion,
    supabaseUrl, supabaseKey,
    adminUser, adminPass, adminEmail,
    wpVersion, workerSource,
  } = opts;

  const token = typeof auth === 'string' ? auth : auth.token;
  const email = typeof auth === 'string' ? null  : auth.email;

  const bindings = [];
  if (mainDbId)     bindings.push({ type: 'd1',           name: 'CP_MAIN_DB', id: mainDbId });
  if (cacheKvId)    bindings.push({ type: 'kv_namespace', name: 'CACHE',      namespace_id: cacheKvId });
  if (sessionsKvId) bindings.push({ type: 'kv_namespace', name: 'SESSIONS',   namespace_id: sessionsKvId });
  if (siteD1Id)     bindings.push({ type: 'd1',           name: 'DB',         id: siteD1Id });
  if (siteKvId)     bindings.push({ type: 'kv_namespace', name: 'SITE_KV',    namespace_id: siteKvId });

  bindings.push({ type: 'plain_text', name: 'CP_SITE_NAME',  text: siteName    || '' });
  bindings.push({ type: 'plain_text', name: 'CP_SITE_URL',   text: 'https://' + (siteDomain || '') });
  bindings.push({ type: 'plain_text', name: 'SITE_PREFIX',   text: sitePrefix  || '' });
  bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID', text: cfAccountId || '' });
  bindings.push({ type: 'plain_text', name: 'WP_VERSION',    text: wpVersion   || '6.7.1' });
  bindings.push({ type: 'plain_text', name: 'PHP_VERSION',   text: phpVersion  || '8.2' });
  bindings.push({ type: 'plain_text', name: 'WP_ADMIN_USER', text: adminUser   || 'admin' });

  if (adminPass)    bindings.push({ type: 'secret_text', name: 'WP_ADMIN_PASS', text: adminPass });
  if (adminEmail)   bindings.push({ type: 'plain_text',  name: 'ADMIN_EMAIL',   text: adminEmail });
  if (supabaseUrl)  bindings.push({ type: 'secret_text', name: 'SUPABASE_URL',  text: supabaseUrl });
  if (supabaseKey)  bindings.push({ type: 'secret_text', name: 'SUPABASE_KEY',  text: supabaseKey });
  if (cfApiToken)   bindings.push({ type: 'secret_text', name: 'CF_API_TOKEN',  text: cfApiToken });

  const metadata = {
    main_module:         'worker.js',
    compatibility_date:  '2025-04-01',
    compatibility_flags: ['nodejs_compat'],
    bindings,
    schedules: [{ cron: '0 17 * * *' }],
  };

  const boundary = '----CPWPUpload' + Date.now().toString(36) + randSuffix(4);
  const enc      = new TextEncoder();
  const CRLF     = '\r\n';

  const metaPart = enc.encode(
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="metadata"${CRLF}` +
    `Content-Type: application/json${CRLF}${CRLF}` +
    JSON.stringify(metadata) + CRLF
  );
  const scriptPart = enc.encode(
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="worker.js"; filename="worker.js"${CRLF}` +
    `Content-Type: application/javascript+module${CRLF}${CRLF}` +
    workerSource + CRLF
  );
  const closePart = enc.encode(`--${boundary}--${CRLF}`);

  const body = new Uint8Array(metaPart.length + scriptPart.length + closePart.length);
  body.set(metaPart, 0);
  body.set(scriptPart, metaPart.length);
  body.set(closePart, metaPart.length + scriptPart.length);

  try {
    const res = await fetch(
      `${CF_API}/accounts/${accountId}/workers/scripts/${workerName}`,
      {
        method:  'PUT',
        headers: {
          ...cfHeaders(token, email),
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
        },
        body,
      }
    );
    const json = await res.json();
    return json.success ? { ok: true } : { ok: false, error: cfErrMsg(json) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

export async function resolveMainBindingIds(auth, accountId) {
  const result = { mainDbId: '', cacheKvId: '', sessionsKvId: '' };
  try {
    const pagesRes = await cfReq(auth, `/accounts/${accountId}/pages/projects`);
    if (!pagesRes.success) return result;
    const project = (pagesRes.result || []).find(p =>
      p.name?.toLowerCase().includes('cloudpress') || p.name?.toLowerCase().includes('cp-')
    );
    if (!project) return result;
    const projRes    = await cfReq(auth, `/accounts/${accountId}/pages/projects/${project.name}`);
    if (!projRes.success) return result;
    const bindings   = projRes.result?.deployment_configs?.production?.d1_databases || {};
    const kvBindings = projRes.result?.deployment_configs?.production?.kv_namespaces || {};
    for (const [name, val] of Object.entries(bindings)) {
      const id = val?.id || val?.database_id || '';
      if (!id) continue;
      if (name === 'DB' || name === 'MAIN_DB') result.mainDbId = id;
    }
    for (const [name, val] of Object.entries(kvBindings)) {
      const id = val?.namespace_id || val?.id || '';
      if (!id) continue;
      if (name === 'CACHE')    result.cacheKvId    = id;
      if (name === 'SESSIONS') result.sessionsKvId = id;
    }
  } catch (e) { console.warn('[provision] 바인딩 ID 자동 탐색 실패:', e.message); }
  return result;
}
