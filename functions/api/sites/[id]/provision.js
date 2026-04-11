// functions/api/sites/[id]/provision.js — CloudPress v12.2
//
// 프로비저닝 파이프라인 (심플, 오리진 부하 제로):
//
//   Step 1 — 사이트 전용 D1 데이터베이스 생성 (사용자 CF API)
//   Step 2 — 사이트 전용 KV 네임스페이스 생성 (사용자 CF API)
//   Step 3 — 전역 CACHE KV 도메인→사이트 매핑 저장
//   Step 4 — CF DNS Zone 조회 + CNAME 레코드 등록
//   Step 5 — Worker Route 등록 (루트 + www)
//   Step 6 — 완료
//
// CF 인증: 사용자 개인 Global API Key 우선 (X-Auth-Key),
//          없으면 관리자 설정 Bearer Token 폴백
// WP 어드민 URL: 항상 사용자 개인 도메인 기준

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d = {}) => _j({ ok: true,  ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

/* XOR 복호화 (user/index.js 와 동일 알고리즘) */
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

function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
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
    return r?.value ?? fallback;
  } catch { return fallback; }
}

async function updateSite(DB, siteId, fields) {
  const entries = Object.entries(fields);
  if (!entries.length) return;
  const set  = entries.map(([k]) => `${k}=?`).join(',');
  const vals = entries.map(([, v]) => v);
  await DB.prepare(`UPDATE sites SET ${set}, updated_at=datetime('now') WHERE id=?`)
    .bind(...vals, siteId).run().catch(() => {});
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, ctx, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;
  const site = await env.DB.prepare(
    `SELECT s.id, s.user_id, s.name, s.primary_domain, s.site_prefix,
            s.wp_username, s.wp_password, s.wp_admin_email,
            s.status, s.provision_step, s.plan,
            s.site_d1_id, s.site_kv_id,
            u.cf_global_api_key, u.cf_account_email, u.cf_account_id
     FROM sites s
     JOIN users u ON u.id = s.user_id
     WHERE s.id=? AND s.user_id=?`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });
  if (site.status === 'provisioning') {
    return ok({ message: '프로비저닝 진행 중입니다.', provision_step: site.provision_step });
  }

  await updateSite(env.DB, siteId, { status: 'provisioning', provision_step: 'starting' });

  // 파이프라인을 직접 await — Pages Functions에서 waitUntil 없이도 안정적으로 실행
  try {
    await runPipeline(env, siteId, site);
  } catch (e) {
    await fail(env.DB, siteId, 'pipeline_error', '파이프라인 오류: ' + e.message);
  }

  // 완료 후 최신 상태 조회해서 반환
  const updated = await env.DB.prepare(
    `SELECT status, provision_step, error_message, wp_admin_url,
            wp_username, wp_password, primary_domain,
            site_d1_id, site_kv_id, domain_status
     FROM sites WHERE id=?`
  ).bind(siteId).first();

  return ok({ message: '프로비저닝 완료', siteId, site: updated });
}

// ══════════════════════════════════════════════════════════════════
// 파이프라인
// ══════════════════════════════════════════════════════════════════

async function runPipeline(env, siteId, site) {
  const domain    = site.primary_domain;
  const wwwDomain = 'www.' + domain;
  const prefix    = site.site_prefix;

  // ── CF 인증: 사용자 개인 CF Global API Key 우선, 없으면 관리자 설정 폴백
  let cfToken   = null;
  let cfAccount = null;

  const encKey = env.ENCRYPTION_KEY || 'cp_enc_default';

  if (site.cf_global_api_key) {
    // 사용자 Global API Key → X-Auth-Key 방식
    cfToken   = deobfuscate(site.cf_global_api_key, encKey);
    cfAccount = site.cf_account_id;
  }

  if (!cfToken || !cfAccount) {
    // 폴백: 관리자 설정 (Bearer Token 방식)
    cfToken   = await getSetting(env, 'cf_api_token');
    cfAccount = await getSetting(env, 'cf_account_id');
  }

  const workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
  const wpOrigin   = await getSetting(env, 'wp_origin_url');

  if (!cfToken || !cfAccount) {
    return fail(env.DB, siteId, 'config_missing',
      '사용자 Cloudflare API 키가 등록되지 않았습니다. 내 계정 → Cloudflare API 설정을 완료해주세요.');
  }

  // 사용자 CF API 방식 판별 (Global API Key: X-Auth-Key, 관리자 설정: Bearer)
  const cfEmail = site.cf_account_email || null;
  const auth    = makeAuth(cfToken, cfEmail);

  try {
    // ── Step 1: 사이트 전용 D1 생성 ────────────────────────────
    await updateSite(env.DB, siteId, { provision_step: 'd1_create' });
    let d1Id = site.site_d1_id;
    if (!d1Id) {
      const r = await createD1(auth, cfAccount, prefix);
      if (!r.ok) return fail(env.DB, siteId, 'd1_create', 'D1 생성 실패: ' + r.error);
      d1Id = r.id;
      await updateSite(env.DB, siteId, { site_d1_id: r.id, site_d1_name: r.name });
    }

    // ── Step 2: 사이트 전용 KV 생성 ────────────────────────────
    await updateSite(env.DB, siteId, { provision_step: 'kv_create' });

    let kvId = site.site_kv_id;
    if (!kvId) {
      const r = await createKV(auth, cfAccount, prefix);
      if (!r.ok) return fail(env.DB, siteId, 'kv_create', 'KV 생성 실패: ' + r.error);
      kvId = r.id;
      await updateSite(env.DB, siteId, { site_kv_id: r.id, site_kv_title: r.title });
    }

    // ── Step 3: 전역 CACHE KV 도메인 매핑 저장 ─────────────────
    await updateSite(env.DB, siteId, { provision_step: 'kv_mapping' });

    // 개인 도메인 기준 wp-admin URL
    const wpAdminUrl = `https://${domain}/wp-admin/`;

    const mapping = JSON.stringify({
      id:          siteId,
      name:        site.name,
      site_prefix: prefix,
      site_d1_id:  d1Id,
      site_kv_id:  kvId,
      wp_admin_url: wpAdminUrl,
      status:      'active',
      suspended:   0,
    });

    try {
      await env.CACHE.put(`site_domain:${domain}`,    mapping);
      await env.CACHE.put(`site_domain:${wwwDomain}`, mapping);
      await env.CACHE.put(`site_prefix:${prefix}`,    mapping);
    } catch (e) {
      // KV 실패는 치명적이지 않음 (Worker가 D1 fallback으로 조회)
      console.error('KV 매핑 저장 실패:', e.message);
    }

    // ── Step 4: CF DNS 레코드 등록 ──────────────────────────────
    await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });

    let cfZoneId       = null;
    let dnsRecordId    = null;
    let dnsRecordWwwId = null;
    let domainStatus   = 'manual_required';

    const zone = await cfGetZone(auth, domain);
    if (zone.ok) {
      cfZoneId = zone.zoneId;
      const cnameTarget = await cfGetWorkerDevUrl(auth, cfAccount, workerName)
        || `${workerName}.workers.dev`;

      const dnsRoot = await cfUpsertDns(auth, cfZoneId,
        { type: 'CNAME', name: domain,    content: cnameTarget, proxied: true });
      const dnsWww  = await cfUpsertDns(auth, cfZoneId,
        { type: 'CNAME', name: wwwDomain, content: domain,      proxied: true });

      if (dnsRoot.ok) dnsRecordId    = dnsRoot.recordId;
      if (dnsWww.ok)  dnsRecordWwwId = dnsWww.recordId;

      // ── Step 5: Worker Route 등록 ────────────────────────────
      await updateSite(env.DB, siteId, { provision_step: 'worker_route' });

      const routeRoot = await cfUpsertRoute(auth, cfZoneId, `${domain}/*`,    workerName);
      const routeWww  = await cfUpsertRoute(auth, cfZoneId, `${wwwDomain}/*`, workerName);

      if (routeRoot.ok || routeWww.ok) {
        domainStatus = 'dns_propagating';
        await updateSite(env.DB, siteId, {
          worker_route:         `${domain}/*`,
          worker_route_www:     `${wwwDomain}/*`,
          worker_route_id:      routeRoot.routeId || null,
          worker_route_www_id:  routeWww.routeId  || null,
          cf_zone_id:           cfZoneId,
          dns_record_id:        dnsRecordId,
          dns_record_www_id:    dnsRecordWwwId,
        });
      }
    }

    // ── Step 6: 완료 ────────────────────────────────────────────
    const cnameHint = await getSetting(env, 'worker_cname_target', `${workerName}.workers.dev`);

    await updateSite(env.DB, siteId, {
      status:         'active',
      provision_step: 'completed',
      domain_status:  domainStatus,
      worker_name:    workerName,
      wp_admin_url:   wpAdminUrl,
      error_message:  domainStatus === 'manual_required'
        ? `DNS 자동 설정 불가. 도메인 DNS에서 CNAME ${domain} → ${cnameHint} 설정 후 Cloudflare 프록시(주황불) 활성화 필요.`
        : null,
    });
}

async function fail(DB, siteId, step, msg) {
  await updateSite(DB, siteId, {
    status: 'failed', provision_step: step, error_message: msg,
  }).catch(() => {});
}

// ══════════════════════════════════════════════════════════════════
// CF API 헬퍼
// ══════════════════════════════════════════════════════════════════

const CF = 'https://api.cloudflare.com/client/v4';

// token: { type: 'bearer', value } | { type: 'global', key, email }
async function cfReq(auth, path, method = 'GET', body = null) {
  let headers = { 'Content-Type': 'application/json' };
  if (auth.type === 'global') {
    headers['X-Auth-Email'] = auth.email;
    headers['X-Auth-Key']   = auth.key;
  } else {
    headers['Authorization'] = 'Bearer ' + auth.value;
  }
  const res = await fetch(CF + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  return res.json().catch(() => ({ success: false, errors: [{ message: 'JSON 파싱 실패' }] }));
}

// auth 객체를 만들어주는 헬퍼
// cfToken: Global API Key 또는 Bearer Token
// cfEmail: Global API Key 사용 시 이메일 (없으면 Bearer 방식)
function makeAuth(cfToken, cfEmail) {
  if (cfEmail) return { type: 'global', key: cfToken, email: cfEmail };
  return { type: 'bearer', value: cfToken };
}

async function createD1(auth, account, prefix) {
  const name = `cp-site-${prefix}`;
  const d = await cfReq(auth, `/accounts/${account}/d1/database`, 'POST', { name });
  if (!d.result?.uuid) return { ok: false, error: d.errors?.[0]?.message || 'D1 생성 실패' };
  return { ok: true, id: d.result.uuid, name };
}

async function createKV(auth, account, prefix) {
  const title = `CP_SITE_${prefix.replace(/[^a-z0-9]/gi, '_').toUpperCase()}`;
  const d = await cfReq(auth, `/accounts/${account}/storage/kv/namespaces`, 'POST', { title });
  if (!d.result?.id) return { ok: false, error: d.errors?.[0]?.message || 'KV 생성 실패' };
  return { ok: true, id: d.result.id, title };
}

async function cfGetZone(auth, domain) {
  const root = domain.split('.').slice(-2).join('.');
  const d = await cfReq(auth, `/zones?name=${root}&status=active`);
  if (!d.success || !d.result?.length) return { ok: false };
  return { ok: true, zoneId: d.result[0].id };
}

async function cfGetWorkerDevUrl(auth, account, workerName) {
  try {
    const d = await cfReq(auth, `/accounts/${account}/workers/scripts/${workerName}/subdomain`);
    if (d.success && d.result?.subdomain)
      return `${workerName}.${d.result.subdomain}.workers.dev`;
  } catch (_) {}
  return null;
}

async function cfUpsertDns(auth, zoneId, { type, name, content, proxied }) {
  const ex = await cfReq(auth, `/zones/${zoneId}/dns_records?type=${type}&name=${name}`);
  const rec = ex?.result?.[0];
  if (rec) {
    const u = await cfReq(auth, `/zones/${zoneId}/dns_records/${rec.id}`, 'PUT',
      { type, name, content, proxied, ttl: 1 });
    return u.success ? { ok: true, recordId: rec.id } : { ok: false };
  }
  const c = await cfReq(auth, `/zones/${zoneId}/dns_records`, 'POST',
    { type, name, content, proxied, ttl: 1 });
  return c.success ? { ok: true, recordId: c.result?.id } : { ok: false };
}

async function cfUpsertRoute(auth, zoneId, pattern, script) {
  const ex = await cfReq(auth, `/zones/${zoneId}/workers/routes`);
  const route = ex?.result?.find(r => r.pattern === pattern);
  if (route) {
    const u = await cfReq(auth, `/zones/${zoneId}/workers/routes/${route.id}`, 'PUT', { pattern, script });
    return u.success ? { ok: true, routeId: route.id } : { ok: false };
  }
  const c = await cfReq(auth, `/zones/${zoneId}/workers/routes`, 'POST', { pattern, script });
  return c.success ? { ok: true, routeId: c.result?.id } : { ok: false };
}
