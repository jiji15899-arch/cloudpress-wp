// functions/api/sites/[id]/provision.js — CloudPress v11.0
// 프로비저닝 파이프라인:
//   Step 1: WP origin에 사이트 초기화 (테이블 생성 + admin 계정)
//   Step 2: Cloudflare DNS API로 도메인 A/CNAME 레코드 추가
//   Step 3: Worker Route 등록 (루트 도메인 + www 완전 덮어씌우기)
//   Step 4: KV 도메인→사이트 매핑 등록
//   Step 5: 완료

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
  const set = entries.map(([k]) => `${k}=?`).join(',');
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
    `SELECT id, user_id, name, primary_domain, www_domain, site_prefix,
            wp_username, wp_password, wp_admin_email, status, provision_step, plan
     FROM sites WHERE id=? AND user_id=?`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });

  // 중복 실행 방지
  if (site.status === 'provisioning') {
    return ok({ message: '프로비저닝이 진행 중입니다.', provision_step: site.provision_step });
  }

  await updateSite(env.DB, siteId, { status: 'provisioning', provision_step: 'starting' });

  const pipelinePromise = runPipeline(env, siteId, site);
  if (ctx?.waitUntil) ctx.waitUntil(pipelinePromise.catch(() => {}));
  else pipelinePromise.catch(() => {});

  return ok({ message: '프로비저닝을 시작합니다.', siteId });
}

// ══════════════════════════════════════════════════════════════
// 프로비저닝 파이프라인
// ══════════════════════════════════════════════════════════════
async function runPipeline(env, siteId, site) {
  const domain     = site.primary_domain;
  const wwwDomain  = site.www_domain || ('www.' + domain);
  const sitePrefix = site.site_prefix;
  const siteUrl    = 'https://' + domain;

  const wpOrigin  = await getSetting(env, 'wp_origin_url');
  const wpSecret  = await getSetting(env, 'wp_origin_secret');
  const cfToken   = await getSetting(env, 'cf_api_token');
  const cfAccount = await getSetting(env, 'cf_account_id');
  const workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');

  try {
    // ── Step 1: WP origin 사이트 초기화 ──
    await updateSite(env.DB, siteId, { provision_step: 'wp_init' });

    const wpInit = await initWpSite({
      wpOrigin, wpSecret, sitePrefix,
      siteName:   site.name,
      adminUser:  site.wp_username,
      adminPw:    site.wp_password,
      adminEmail: site.wp_admin_email,
      domain,
    });

    if (!wpInit.ok) {
      await updateSite(env.DB, siteId, {
        status: 'failed', provision_step: 'wp_init',
        error_message: wpInit.error,
      });
      return;
    }

    // ── Step 2: Cloudflare Zone 조회 (도메인이 CF에 있는지) ──
    await updateSite(env.DB, siteId, { provision_step: 'dns_setup' });

    let cfZoneId = null;
    let dnsRecordId = null;
    let dnsRecordWwwId = null;
    let domainStatus = 'manual_required';

    if (cfToken && cfAccount) {
      const zoneResult = await cfGetZone(cfToken, domain);
      if (zoneResult.ok) {
        cfZoneId = zoneResult.zoneId;

        // Worker의 workers.dev URL을 CNAME 타겟으로 사용
        // 또는 Worker Route를 직접 설정
        const workerDev = await cfGetWorkerDevUrl(cfToken, cfAccount, workerName);

        // DNS 레코드 추가/업데이트 (루트 도메인)
        const dnsRoot = await cfUpsertDnsRecord(cfToken, cfZoneId, {
          type:    'CNAME',
          name:    domain,
          content: workerDev || (workerName + '.' + cfAccount + '.workers.dev'),
          proxied: true,   // CF 프록시 ON (Worker Route 작동 필수)
        });
        if (dnsRoot.ok) dnsRecordId = dnsRoot.recordId;

        // www 서브도메인
        const dnsWww = await cfUpsertDnsRecord(cfToken, cfZoneId, {
          type:    'CNAME',
          name:    'www.' + domain,
          content: domain,
          proxied: true,
        });
        if (dnsWww.ok) dnsRecordWwwId = dnsWww.recordId;

        // ── Step 3: Worker Route 등록 (루트 도메인 완전 덮어씌우기) ──
        await updateSite(env.DB, siteId, { provision_step: 'worker_route' });

        const routeRoot = await cfUpsertWorkerRoute(cfToken, cfZoneId, cfAccount, {
          pattern: domain + '/*',
          script:  workerName,
        });
        const routeWww = await cfUpsertWorkerRoute(cfToken, cfZoneId, cfAccount, {
          pattern: wwwDomain + '/*',
          script:  workerName,
        });

        if (routeRoot.ok || routeWww.ok) {
          domainStatus = 'dns_propagating';
          await updateSite(env.DB, siteId, {
            worker_route:       domain + '/*',
            worker_route_www:   wwwDomain + '/*',
            worker_route_id:    routeRoot.routeId || null,
            worker_route_www_id: routeWww.routeId || null,
            cf_zone_id:         cfZoneId,
            dns_record_id:      dnsRecordId,
            dns_record_www_id:  dnsRecordWwwId,
          });
        }
      }
      // CF Zone이 없으면 수동 CNAME 안내
    }

    // ── Step 4: KV 도메인→사이트 매핑 등록 ──
    await updateSite(env.DB, siteId, { provision_step: 'kv_mapping' });

    const siteMapping = JSON.stringify({
      id:          siteId,
      name:        site.name,
      site_prefix: sitePrefix,
      wp_admin_url: wpOrigin?.replace(/\/$/, '') + '/wp-admin/?cp_site=' + sitePrefix,
      status:      'active',
      suspended:   0,
    });

    // CACHE KV에 도메인→사이트 매핑 저장 (Workers가 읽음)
    try {
      await env.CACHE.put(`site_domain:${domain}`,     siteMapping, { expirationTtl: 86400 });
      await env.CACHE.put(`site_domain:${wwwDomain}`,  siteMapping, { expirationTtl: 86400 });
      await env.CACHE.put(`site_prefix:${sitePrefix}`, siteMapping, { expirationTtl: 86400 });
    } catch (e) {
      // KV 실패는 치명적이지 않음 (Worker가 D1에서 fallback으로 읽음)
      console.error('KV 매핑 저장 실패:', e.message);
    }

    // ── Step 5: 완료 ──
    const workerCnameTarget = await getSetting(env, 'worker_cname_target', workerName + '.workers.dev');

    await updateSite(env.DB, siteId, {
      status:         'active',
      provision_step: 'completed',
      domain_status:  domainStatus,
      worker_name:    workerName,
      wp_admin_url:   wpOrigin?.replace(/\/$/, '') + '/wp-admin/?cp_site=' + sitePrefix,
      error_message:  null,
    });

    // 수동 CNAME 필요 시 DB에 안내 저장
    if (domainStatus === 'manual_required') {
      await updateSite(env.DB, siteId, {
        error_message: `DNS 자동 설정 불가. 도메인 DNS에서 CNAME ${domain} → ${workerCnameTarget} 으로 설정 후 CF 프록시(주황불) 활성화 필요.`,
      });
    }

  } catch (e) {
    await updateSite(env.DB, siteId, {
      status: 'failed', provision_step: 'pipeline_error',
      error_message: '파이프라인 오류: ' + e.message,
    }).catch(() => {});
  }
}

// ══════════════════════════════════════════════════════════════
// WP origin 초기화
// ══════════════════════════════════════════════════════════════
async function initWpSite({ wpOrigin, wpSecret, sitePrefix, siteName, adminUser, adminPw, adminEmail, domain }) {
  if (!wpOrigin) return { ok: false, error: 'WP_ORIGIN_URL 미설정' };
  try {
    const res = await fetch(wpOrigin.replace(/\/$/, '') + '/wp-json/cloudpress/v1/init-site', {
      method: 'POST',
      headers: {
        'Content-Type':        'application/json',
        'X-CloudPress-Site':   sitePrefix,
        'X-CloudPress-Secret': wpSecret,
        'X-CloudPress-Domain': domain,
      },
      body: JSON.stringify({ site_prefix: sitePrefix, site_name: siteName, admin_user: adminUser, admin_pass: adminPw, admin_email: adminEmail, site_url: 'https://' + domain }),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => '');
      return { ok: false, error: `WP 응답 오류 (${res.status}): ${t.slice(0, 300)}` };
    }
    const data = await res.json().catch(() => ({}));
    return data?.success ? { ok: true } : { ok: false, error: data?.message || 'WP 초기화 실패' };
  } catch (e) {
    return { ok: false, error: 'WP 연결 실패: ' + e.message };
  }
}

// ══════════════════════════════════════════════════════════════
// Cloudflare API 헬퍼
// ══════════════════════════════════════════════════════════════
const CF_API = 'https://api.cloudflare.com/client/v4';

async function cfApi(token, path, method = 'GET', body = null) {
  const res = await fetch(CF_API + path, {
    method,
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : null,
  });
  return res.json().catch(() => ({ success: false, errors: [{ message: 'JSON 파싱 실패' }] }));
}

// 도메인의 CF Zone ID 조회
async function cfGetZone(token, domain) {
  // 루트 도메인으로 조회 (서브도메인 제거)
  const parts  = domain.split('.');
  const root   = parts.length >= 2 ? parts.slice(-2).join('.') : domain;

  const data = await cfApi(token, `/zones?name=${root}&status=active`);
  if (!data.success || !data.result?.length) return { ok: false };
  return { ok: true, zoneId: data.result[0].id };
}

// Worker의 workers.dev 도메인 조회
async function cfGetWorkerDevUrl(token, accountId, workerName) {
  try {
    const data = await cfApi(token, `/accounts/${accountId}/workers/scripts/${workerName}/subdomain`);
    if (data.success && data.result?.subdomain) {
      return `${workerName}.${data.result.subdomain}.workers.dev`;
    }
  } catch (_) {}
  return null;
}

// DNS 레코드 추가/업데이트
async function cfUpsertDnsRecord(token, zoneId, { type, name, content, proxied }) {
  // 기존 레코드 조회
  const existing = await cfApi(token, `/zones/${zoneId}/dns_records?type=${type}&name=${name}`);
  const record = existing?.result?.[0];

  if (record) {
    // 업데이트
    const upd = await cfApi(token, `/zones/${zoneId}/dns_records/${record.id}`, 'PUT', { type, name, content, proxied, ttl: 1 });
    return upd.success ? { ok: true, recordId: record.id } : { ok: false, error: upd.errors?.[0]?.message };
  } else {
    // 신규 생성
    const cre = await cfApi(token, `/zones/${zoneId}/dns_records`, 'POST', { type, name, content, proxied, ttl: 1 });
    return cre.success ? { ok: true, recordId: cre.result?.id } : { ok: false, error: cre.errors?.[0]?.message };
  }
}

// Worker Route 추가/업데이트 (루트 도메인 완전 덮어씌우기)
async function cfUpsertWorkerRoute(token, zoneId, accountId, { pattern, script }) {
  // 기존 라우트 조회
  const existing = await cfApi(token, `/zones/${zoneId}/workers/routes`);
  const route = existing?.result?.find(r => r.pattern === pattern);

  if (route) {
    const upd = await cfApi(token, `/zones/${zoneId}/workers/routes/${route.id}`, 'PUT', { pattern, script });
    return upd.success ? { ok: true, routeId: route.id } : { ok: false, error: upd.errors?.[0]?.message };
  } else {
    const cre = await cfApi(token, `/zones/${zoneId}/workers/routes`, 'POST', { pattern, script });
    return cre.success ? { ok: true, routeId: cre.result?.id } : { ok: false, error: cre.errors?.[0]?.message };
  }
}
