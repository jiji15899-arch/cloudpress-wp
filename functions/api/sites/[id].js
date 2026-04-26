// functions/api/sites/[id].js — CloudPress v11.1
//
// [v11.1 subrequest 최적화]
// ────────────────────────────────────────────────────────────────────────────
//  문제: getSetting()이 요청 핸들러 내에서 최대 3회 개별 호출
//        - GET: getSetting('wp_origin_url') + getSetting('worker_cname_target') = 2회
//        - DELETE: getSetting('cf_api_token') + getSetting('cf_account_id') = 2회
//        - PUT/check-domain: getSetting('cf_api_token') + getSetting('cf_worker_name') = 2회
//        각 getSetting = D1 쿼리 1회 → 불필요한 subrequest 낭비
//
//  해결:
//    1. 요청 시작 시 site 조회와 settings 전체를 DB.batch()로 1회 왕복 처리
//    2. 이후 모든 getSetting() → 메모리 objects에서 O(1) 조회
//
//  결과: GET/DELETE/PUT 모든 경로에서 D1 subrequest 최소 1회 절감

import { CORS, _j, ok, err, getToken, getUser, settingVal } from '../_shared.js';

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  // [수정] params가 없거나 id가 없는 경우 방어 처리
  const siteId = params?.id || new URL(request.url).pathname.split('/').filter(Boolean).pop();
  if (!siteId || siteId === 'sites') return err('사이트 ID가 없습니다.', 400);

  // ── [D1 #1] site + settings 동시 조회 (batch 1회) ──────────────────────────
  let site, settings;
  try {
    // batch: site + settings 동시 조회
    // settings 테이블이 없어도 site는 가져올 수 있도록 개별 fallback 처리
    let siteRows, settingsRows;
    try {
      [siteRows, settingsRows] = await env.DB.batch([
        env.DB.prepare(
          `SELECT id, user_id, name, primary_domain, domain_status,
                  site_prefix, worker_name, worker_route, worker_route_www,
                  worker_route_id, worker_route_www_id, cf_zone_id,
                  site_d1_id, site_kv_id,
                  supabase_url, supabase_key, storage_bucket,
                  supabase_url2, supabase_key2, storage_bucket2,
                  wp_admin_url, wp_username, wp_password,
                  wp_version, region,
                  status, provision_step, error_message,
                  suspended, suspension_reason, disk_used, bandwidth_used,
                  plan, created_at, updated_at
           FROM sites WHERE id=? AND (user_id=? OR 'admin'=?) AND deleted_at IS NULL`
        ).bind(siteId, user.id, (user.role === 'admin' || user.role === 'manager') ? 'admin' : '__never__'),
        env.DB.prepare('SELECT key, value FROM settings'),
      ]);
    } catch {
      // batch 실패 시 개별 조회 fallback
      siteRows = await env.DB.prepare(
        `SELECT id, user_id, name, primary_domain, domain_status,
                site_prefix, worker_name, worker_route, worker_route_www,
                worker_route_id, worker_route_www_id, cf_zone_id,
                site_d1_id, site_kv_id,
                supabase_url, supabase_key, storage_bucket,
                supabase_url2, supabase_key2, storage_bucket2,
                wp_admin_url, wp_username, wp_password,
                wp_version, region,
                status, provision_step, error_message,
                suspended, suspension_reason, disk_used, bandwidth_used,
                plan, created_at, updated_at
         FROM sites WHERE id=? AND (user_id=? OR 'admin'=?) AND deleted_at IS NULL`
      ).bind(siteId, user.id, (user.role === 'admin' || user.role === 'manager') ? 'admin' : '__never__').all();
      settingsRows = { results: [] };
    }

    site = siteRows.results?.[0] ?? null;

    settings = {};
    for (const r of settingsRows.results || []) settings[r.key] = r.value ?? '';
  } catch (e) {
    return err('데이터 조회 오류: ' + e.message, 500);
  }

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  // GET
  if (request.method === 'GET') {
    // settings는 이미 메모리에 있음 — 추가 D1 쿼리 없음
    const workerCname = settingVal(settings, 'worker_cname_target');
    return ok({
      site,
      wp_admin_direct_url: site.wp_admin_url,
      cname_instruction: site.domain_status === 'manual_required'
        ? `도메인 DNS에 CNAME ${site.primary_domain} → ${workerCname} 추가 후 CF 프록시(주황불) 활성화`
        : null,
    });
  }

  // DELETE
  if (request.method === 'DELETE') {
    // settings는 이미 메모리에 있음 — 추가 D1 쿼리 없음
    const cfToken   = settingVal(settings, 'cf_api_token');
    const cfAccount = settingVal(settings, 'cf_account_id');

    // 1. CF Worker Route 삭제 (병렬)
    if (cfToken && site.cf_zone_id) {
      const deleteRoute = (routeId) => {
        if (!routeId) return Promise.resolve();
        return fetch(`https://api.cloudflare.com/client/v4/zones/${site.cf_zone_id}/workers/routes/${routeId}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + cfToken },
        }).catch(() => {});
      };
      await Promise.all([
        deleteRoute(site.worker_route_id),
        deleteRoute(site.worker_route_www_id),
      ]);
    }

    // 1-b. CF Worker Script 삭제
    if (cfToken && cfAccount && site.worker_name) {
      fetch(`https://api.cloudflare.com/client/v4/accounts/${cfAccount}/workers/scripts/${site.worker_name}`, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + cfToken },
      }).catch(() => {});
    }

    // 1-c. CF Worker Custom Domain 삭제 (있는 경우)
    if (cfToken && cfAccount && site.primary_domain && site.worker_name) {
      // Worker Custom Domains 목록 조회 후 삭제
      fetch(`https://api.cloudflare.com/client/v4/accounts/${cfAccount}/workers/domains`, {
        headers: { 'Authorization': 'Bearer ' + cfToken },
      }).then(async r => {
        const j = await r.json().catch(() => ({}));
        for (const d of j.result || []) {
          if (d.service === site.worker_name) {
            fetch(`https://api.cloudflare.com/client/v4/accounts/${cfAccount}/workers/domains/${d.id}`, {
              method: 'DELETE',
              headers: { 'Authorization': 'Bearer ' + cfToken },
            }).catch(() => {});
          }
        }
      }).catch(() => {});
    }

    // 2. 전역 CACHE KV 도메인 매핑 삭제
    try {
      await env.CACHE.delete(`site_domain:${site.primary_domain}`);
      await env.CACHE.delete(`site_domain:www.${site.primary_domain}`);
      await env.CACHE.delete(`site_prefix:${site.site_prefix}`);
    } catch (_) {}

    // 3. 사이트 전용 D1 / KV 리소스 삭제 (CF API, 비동기 fire-and-forget)
    if (cfToken && cfAccount) {
      if (site.site_d1_id) {
        fetch(`https://api.cloudflare.com/client/v4/accounts/${cfAccount}/d1/database/${site.site_d1_id}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + cfToken },
        }).catch(() => {});
      }
      if (site.site_kv_id) {
        fetch(`https://api.cloudflare.com/client/v4/accounts/${cfAccount}/storage/kv/namespaces/${site.site_kv_id}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + cfToken },
        }).catch(() => {});
      }
    }

    // 3-b. Supabase 스토리지 버킷 삭제
    const supaDeleteBucket = async (url, key, bucket) => {
      if (!url || !key || !bucket) return;
      try {
        // 버킷 내 파일 전체 삭제
        await fetch(`${url}/storage/v1/object/list/${bucket}`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${key}`, 'apikey': key, 'Content-Type': 'application/json' },
          body: JSON.stringify({ prefix: '', limit: 1000 }),
        }).then(async r => {
          const j = await r.json().catch(() => ({}));
          const files = (j || []).map(f => f.name).filter(Boolean);
          if (files.length) {
            await fetch(`${url}/storage/v1/object/${bucket}`, {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${key}`, 'apikey': key, 'Content-Type': 'application/json' },
              body: JSON.stringify({ prefixes: files }),
            }).catch(() => {});
          }
        }).catch(() => {});
        // 버킷 자체 삭제
        await fetch(`${url}/storage/v1/bucket/${bucket}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${key}`, 'apikey': key },
        }).catch(() => {});
      } catch (_) {}
    };
    supaDeleteBucket(site.supabase_url,  site.supabase_key,  site.storage_bucket  || 'media');
    supaDeleteBucket(site.supabase_url2, site.supabase_key2, site.storage_bucket2 || 'media');

    // 4. DB soft delete
    await env.DB.prepare(
      `UPDATE sites SET deleted_at=datetime('now'), status='deleted' WHERE id=?`
    ).bind(siteId).run();

    return ok({ message: '사이트가 삭제되었습니다.' });
  }

  // PUT
  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    // 정지/해제 (admin만)
    if (body.action === 'suspend' && user.role === 'admin') {
      const suspended = body.suspended ? 1 : 0;
      await env.DB.prepare(
        `UPDATE sites SET suspended=?, suspension_reason=?, updated_at=datetime('now') WHERE id=?`
      ).bind(suspended, body.reason || '', siteId).run();

      // KV 캐시 무효화
      try {
        await env.CACHE.delete(`site_domain:${site.primary_domain}`);
        await env.CACHE.delete(`site_domain:www.${site.primary_domain}`);
      } catch (_) {}

      return ok({ message: suspended ? '사이트가 일시정지되었습니다.' : '일시정지가 해제되었습니다.' });
    }

    // 실패 사이트 재시도
    if (body.action === 'retry' && site.status === 'failed') {
      await env.DB.prepare(
        `UPDATE sites SET status='pending', provision_step='init', error_message=NULL, updated_at=datetime('now') WHERE id=?`
      ).bind(siteId).run();
      return ok({ message: '재시도 준비 완료. provision을 다시 호출해주세요.' });
    }

    // 이름 변경
    if (body.action === 'update-info' && body.name) {
      await env.DB.prepare(
        `UPDATE sites SET name=?, updated_at=datetime('now') WHERE id=?`
      ).bind(body.name.trim(), siteId).run();
      // KV 캐시 갱신
      try {
        const cached = await env.CACHE.get(`site_domain:${site.primary_domain}`, { type: 'json' });
        if (cached) {
          cached.name = body.name.trim();
          await env.CACHE.put(`site_domain:${site.primary_domain}`, JSON.stringify(cached), { expirationTtl: 86400 });
        }
      } catch (_) {}
      return ok({ message: '사이트 이름이 변경되었습니다.' });
    }

    // 도메인 상태 수동 확인 요청
    if (body.action === 'check-domain') {
      const domain    = site.primary_domain;
      // settings는 이미 메모리에 있음 — 추가 D1 쿼리 없음
      const cfToken   = settingVal(settings, 'cf_api_token');
      if (!cfToken) return err('CF API 토큰 미설정');

      const cfZoneId = site.cf_zone_id;
      if (!cfZoneId) return err('CF Zone ID 없음. 도메인이 Cloudflare에 연결되지 않은 경우 수동 CNAME 설정이 필요합니다.');

      // Worker Route 확인 (외부 fetch 1회)
      const routes = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/workers/routes`,
        { headers: { 'Authorization': 'Bearer ' + cfToken } }
      ).then(r => r.json()).catch(() => ({ result: [] }));

      const workerName = site.worker_name || settingVal(settings, 'cf_worker_name', '');
      const hasRoute = routes.result?.some(r => r.script === workerName && r.pattern.includes(domain));

      if (hasRoute) {
        await env.DB.prepare(
          `UPDATE sites SET domain_status='active', updated_at=datetime('now') WHERE id=?`
        ).bind(siteId).run();
        // KV 갱신
        try {
          const siteData = JSON.stringify({ id: siteId, name: site.name, site_prefix: site.site_prefix, status: 'active', suspended: 0 });
          await Promise.all([
            env.CACHE.put(`site_domain:${domain}`, siteData, { expirationTtl: 86400 }),
            env.CACHE.put(`site_domain:www.${site.primary_domain}`, siteData, { expirationTtl: 86400 }),
          ]);
        } catch (_) {}
        return ok({ message: '도메인 연결 확인 완료', domain_status: 'active' });
      }

      return ok({ message: 'Worker Route가 아직 없습니다. DNS 전파를 기다리거나 수동으로 CNAME을 설정해주세요.', domain_status: 'pending' });
    }

    return err('알 수 없는 요청');
  }

  return err('지원하지 않는 메서드', 405);
}
