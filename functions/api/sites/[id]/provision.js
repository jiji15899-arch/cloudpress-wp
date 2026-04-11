// functions/api/sites/[id]/provision.js — CloudPress v12.0
//
// 프로비저닝 파이프라인 (오리진 부하 제로 설계):
//
//   Step 1 — 사이트 전용 D1 데이터베이스 생성 (CF API)
//   Step 2 — 사이트 전용 KV 네임스페이스 생성 (CF API)
//   Step 3 — 전역 CACHE KV에 도메인→사이트 매핑 저장
//   Step 4 — Cloudflare DNS: 도메인 Zone 조회 + A/CNAME 레코드 등록
//   Step 5 — Worker Route 등록 (루트 + www)
//   Step 6 — 완료
//
// WP origin은 이 파일 어디서도 호출하지 않음
// R2 사용 없음
// origin에 신호·요청·부하 전혀 없음

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
    `SELECT id, user_id, name, primary_domain, site_prefix,
            wp_username, wp_password, wp_admin_email,
            status, provision_step, plan,
            site_d1_id, site_kv_id
     FROM sites WHERE id=? AND user_id=?`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });
  if (site.status === 'provisioning') {
    return ok({ message: '프로비저닝 진행 중입니다.', provision_step: site.provision_step });
  }

  await updateSite(env.DB, siteId, { status: 'provisioning', provision_step: 'starting' });

  const pipeline = runPipeline(env, siteId, site);
  if (ctx?.waitUntil) ctx.waitUntil(pipeline.catch(() => {}));
  else pipeline.catch(() => {});

  return ok({ message: '프로비저닝을 시작합니다.', siteId });
}

// ══════════════════════════════════════════════════════════════════════
// 프로비저닝 파이프라인
// ══════════════════════════════════════════════════════════════════════

async function runPipeline(env, siteId, site) {
  const domain     = site.primary_domain;
  const wwwDomain  = 'www.' + domain;
  const sitePrefix = site.site_prefix;

  const cfToken    = await getSetting(env, 'cf_api_token');
  const cfAccount  = await getSetting(env, 'cf_account_id');
  const workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
  const wpOrigin   = await getSetting(env, 'wp_origin_url');

  if (!cfToken || !cfAccount) {
    await updateSite(env.DB, siteId, {
      status: 'failed', provision_step: 'config_missing',
      error_message: 'Cloudflare API Token 또는 Account ID가 설정되지 않았습니다.',
    });
    return;
  }

  try {
    // ── Step 1: 사이트 전용 D1 데이터베이스 생성 ──────────────────
    await updateSite(env.DB, siteId, { provision_step: 'd1_create' });

    // 이미 생성된 경우 스킵
    let d1Id   = site.site_d1_id;
    let d1Name = null;

    if (!d1Id) {
      const d1Result = await createSiteD1(cfToken, cfAccount, sitePrefix);
      if (!d1Result.ok) {
        await updateSite(env.DB, siteId, {
          status: 'failed', provision_step: 'd1_create',
          error_message: 'D1 생성 실패: ' + d1Result.error,
        });
        return;
      }
      d1Id   = d1Result.d1Id;
      d1Name = d1Result.d1Name;
      await updateSite(env.DB, siteId, { site_d1_id: d1Id, site_d1_name: d1Name });
    }

    // ── Step 2: 사이트 전용 KV 네임스페이스 생성 ─────────────────
    await updateSite(env.DB, siteId, { provision_step: 'kv_create' });

    let kvId    = site.site_kv_id;
    let kvTitle = null;

    if (!kvId) {
      const kvResult = await createSiteKV(cfToken, cfAccount, sitePrefix);
      if (!kvResult.ok) {
        await updateSite(env.DB, siteId, {
          status: 'failed', provision_step: 'kv_create',
          error_message: 'KV 생성 실패: ' + kvResult.error,
        });
        return;
      }
      kvId    = kvResult.kvId;
      kvTitle = kvResult.kvTitle;
      await updateSite(env.DB, siteId, { site_kv_id: kvId, site_kv_title: kvTitle });
    }

    // ── Step 3: 전역 CACHE KV에 도메인→사이트 매핑 저장 ─────────
    await updateSite(env.DB, siteId, { provision_step: 'kv_mapping' });

    const siteMapping = JSON.stringify({
      id:          siteId,
      name:        site.name,
      site_prefix: sitePrefix,
      site_d1_id:  d1Id,
      site_kv_id:  kvId,
      wp_admin_url: wpOrigin ? wpOrigin.replace(/\/$/, '') + '/wp-admin' : '',
      status:      'active',
      suspended:   0,
    });

    try {
      // TTL 없이 영구 저장 (삭제 시 명시적으로 제거)
      await env.CACHE.put(`site_domain:${domain}`,     siteMapping);
      await env.CACHE.put(`site_domain:${wwwDomain}`,  siteMapping);
      await env.CACHE.put(`site_prefix:${sitePrefix}`, siteMapping);
    } catch (e) {
      // KV 실패는 치명적이지 않음 — Worker가 D1 fallback으로 조회
      console.error('KV 매핑 저장 실패:', e.message);
    }

    // ── Step 4: Cloudflare DNS 레코드 등록 ───────────────────────
    await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });

    let cfZoneId       = null;
    let dnsRecordId    = null;
    let dnsRecordWwwId = null;
    let domainStatus   = 'manual_required';

    const zoneResult = await cfGetZone(cfToken, domain);
    if (zoneResult.ok) {
      cfZoneId = zoneResult.zoneId;

      // Worker workers.dev URL 조회 (CNAME 타겟)
      const workerDevUrl = await cfGetWorkerDevUrl(cfToken, cfAccount, workerName);
      const cnameTarget  = workerDevUrl || `${workerName}.${cfAccount}.workers.dev`;

      // 루트 도메인 DNS 레코드
      const dnsRoot = await cfUpsertDnsRecord(cfToken, cfZoneId, {
        type: 'CNAME', name: domain, content: cnameTarget, proxied: true,
      });
      if (dnsRoot.ok) dnsRecordId = dnsRoot.recordId;

      // www 서브도메인 DNS 레코드
      const dnsWww = await cfUpsertDnsRecord(cfToken, cfZoneId, {
        type: 'CNAME', name: wwwDomain, content: domain, proxied: true,
      });
      if (dnsWww.ok) dnsRecordWwwId = dnsWww.recordId;

      // ── Step 5: Worker Route 등록 ─────────────────────────────
      await updateSite(env.DB, siteId, { provision_step: 'worker_route' });

      const routeRoot = await cfUpsertWorkerRoute(cfToken, cfZoneId, {
        pattern: domain + '/*', script: workerName,
      });
      const routeWww = await cfUpsertWorkerRoute(cfToken, cfZoneId, {
        pattern: wwwDomain + '/*', script: workerName,
      });

      if (routeRoot.ok || routeWww.ok) {
        domainStatus = 'dns_propagating';
        await updateSite(env.DB, siteId, {
          worker_route:         domain + '/*',
          worker_route_www:     wwwDomain + '/*',
          worker_route_id:      routeRoot.routeId || null,
          worker_route_www_id:  routeWww.routeId  || null,
          cf_zone_id:           cfZoneId,
          dns_record_id:        dnsRecordId,
          dns_record_www_id:    dnsRecordWwwId,
        });
      }
    }
    // CF Zone 없으면 manual_required — 수동 CNAME 안내

    // ── Step 6: 완료 ─────────────────────────────────────────────
    const workerCnameTarget = await getSetting(env, 'worker_cname_target',
      workerName + '.workers.dev');

    const wpAdminUrl = wpOrigin
      ? wpOrigin.replace(/\/$/, '') + '/wp-admin'
      : '';

    await updateSite(env.DB, siteId, {
      status:         'active',
      provision_step: 'completed',
      domain_status:  domainStatus,
      worker_name:    workerName,
      wp_admin_url:   wpAdminUrl,
      error_message:  domainStatus === 'manual_required'
        ? `DNS 자동 설정 불가. 도메인 DNS에서 CNAME ${domain} → ${workerCnameTarget} 설정 후 Cloudflare 프록시(주황불) 활성화 필요.`
        : null,
    });

  } catch (e) {
    await updateSite(env.DB, siteId, {
      status: 'failed', provision_step: 'pipeline_error',
      error_message: '파이프라인 오류: ' + e.message,
    }).catch(() => {});
  }
}

// ══════════════════════════════════════════════════════════════════════
// Cloudflare API: D1 / KV 생성
// ══════════════════════════════════════════════════════════════════════

const CF_API = 'https://api.cloudflare.com/client/v4';

async function cfApi(token, path, method = 'GET', body = null) {
  const res = await fetch(CF_API + path, {
    method,
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : null,
  });
  return res.json().catch(() => ({ success: false, errors: [{ message: 'JSON 파싱 실패' }] }));
}

// 사이트 전용 D1 데이터베이스 생성
// 이름 예: cp-site-s_a3k9x2
async function createSiteD1(token, accountId, sitePrefix) {
  const dbName = `cp-site-${sitePrefix}`;
  const data = await cfApi(token, `/accounts/${accountId}/d1/database`, 'POST', { name: dbName });
  if (!data.result?.uuid) {
    return { ok: false, error: data.errors?.[0]?.message || 'D1 생성 실패' };
  }
  return { ok: true, d1Id: data.result.uuid, d1Name: dbName };
}

// 사이트 전용 KV 네임스페이스 생성
// 이름 예: CP_SITE_S_A3K9X2
async function createSiteKV(token, accountId, sitePrefix) {
  const kvTitle = `CP_SITE_${sitePrefix.replace(/[^a-z0-9]/gi, '_').toUpperCase()}`;
  const data = await cfApi(token, `/accounts/${accountId}/storage/kv/namespaces`, 'POST', { title: kvTitle });
  if (!data.result?.id) {
    return { ok: false, error: data.errors?.[0]?.message || 'KV 생성 실패' };
  }
  return { ok: true, kvId: data.result.id, kvTitle };
}

// ══════════════════════════════════════════════════════════════════════
// Cloudflare API: DNS / Worker Route
// ══════════════════════════════════════════════════════════════════════

// 도메인의 CF Zone ID 조회
async function cfGetZone(token, domain) {
  const parts = domain.split('.');
  const root  = parts.length >= 2 ? parts.slice(-2).join('.') : domain;
  const data  = await cfApi(token, `/zones?name=${root}&status=active`);
  if (!data.success || !data.result?.length) return { ok: false };
  return { ok: true, zoneId: data.result[0].id };
}

// Worker workers.dev 서브도메인 조회
async function cfGetWorkerDevUrl(token, accountId, workerName) {
  try {
    const data = await cfApi(token, `/accounts/${accountId}/workers/scripts/${workerName}/subdomain`);
    if (data.success && data.result?.subdomain) {
      return `${workerName}.${data.result.subdomain}.workers.dev`;
    }
  } catch (_) {}
  return null;
}

// DNS 레코드 upsert
async function cfUpsertDnsRecord(token, zoneId, { type, name, content, proxied }) {
  const existing = await cfApi(token, `/zones/${zoneId}/dns_records?type=${type}&name=${name}`);
  const record   = existing?.result?.[0];
  if (record) {
    const upd = await cfApi(token, `/zones/${zoneId}/dns_records/${record.id}`, 'PUT',
      { type, name, content, proxied, ttl: 1 });
    return upd.success ? { ok: true, recordId: record.id } : { ok: false, error: upd.errors?.[0]?.message };
  }
  const cre = await cfApi(token, `/zones/${zoneId}/dns_records`, 'POST',
    { type, name, content, proxied, ttl: 1 });
  return cre.success ? { ok: true, recordId: cre.result?.id } : { ok: false, error: cre.errors?.[0]?.message };
}

// Worker Route upsert
async function cfUpsertWorkerRoute(token, zoneId, { pattern, script }) {
  const existing = await cfApi(token, `/zones/${zoneId}/workers/routes`);
  const route    = existing?.result?.find(r => r.pattern === pattern);
  if (route) {
    const upd = await cfApi(token, `/zones/${zoneId}/workers/routes/${route.id}`, 'PUT', { pattern, script });
    return upd.success ? { ok: true, routeId: route.id } : { ok: false, error: upd.errors?.[0]?.message };
  }
  const cre = await cfApi(token, `/zones/${zoneId}/workers/routes`, 'POST', { pattern, script });
  return cre.success ? { ok: true, routeId: cre.result?.id } : { ok: false, error: cre.errors?.[0]?.message };
}
