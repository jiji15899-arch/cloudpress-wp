// functions/api/sites/[id].js — CloudPress v11.0

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
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

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;
  const site = await env.DB.prepare(
    `SELECT id, user_id, name, primary_domain, domain_status,
            site_prefix, worker_name, worker_route, worker_route_www,
            worker_route_id, worker_route_www_id, cf_zone_id,
            wp_username, wp_password, wp_admin_email, wp_admin_url,
            status, provision_step, error_message,
            suspended, suspension_reason, disk_used, bandwidth_used,
            plan, created_at, updated_at
     FROM sites WHERE id=? AND (user_id=? OR ?='admin') AND deleted_at IS NULL`
  ).bind(siteId, user.id, user.role).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  // GET
  if (request.method === 'GET') {
    const wpOrigin = await getSetting(env, 'wp_origin_url');
    const workerCname = await getSetting(env, 'worker_cname_target');
    return ok({
      site,
      // 프론트에 필요한 추가 정보
      wp_admin_direct_url: site.wp_admin_url,
      cname_instruction: site.domain_status === 'manual_required'
        ? `도메인 DNS에 CNAME ${site.primary_domain} → ${workerCname} 추가 후 CF 프록시(주황불) 활성화`
        : null,
    });
  }

  // DELETE
  if (request.method === 'DELETE') {
    // 1. CF Worker Route 삭제
    const cfToken = await getSetting(env, 'cf_api_token');
    if (cfToken && site.cf_zone_id) {
      const deleteRoute = async (routeId) => {
        if (!routeId) return;
        await fetch(`https://api.cloudflare.com/client/v4/zones/${site.cf_zone_id}/workers/routes/${routeId}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + cfToken },
        }).catch(() => {});
      };
      await deleteRoute(site.worker_route_id);
      await deleteRoute(site.worker_route_www_id);
    }

    // 2. KV 캐시 삭제
    try {
      await env.CACHE.delete(`site_domain:${site.primary_domain}`);
      await env.CACHE.delete(`site_domain:${`www.${site.primary_domain}`}`);
      await env.CACHE.delete(`site_prefix:${site.site_prefix}`);
    } catch (_) {}

    // 3. WP origin 테이블 삭제 요청
    const wpOrigin = await getSetting(env, 'wp_origin_url');
    const wpSecret = await getSetting(env, 'wp_origin_secret');
    if (wpOrigin) {
      fetch(wpOrigin.replace(/\/$/, '') + '/wp-json/cloudpress/v1/delete-site', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'X-CloudPress-Secret': wpSecret },
        body: JSON.stringify({ site_prefix: site.site_prefix }),
      }).catch(() => {});
    }

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
        await env.CACHE.delete(`site_domain:${`www.${site.primary_domain}`}`);
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
      const domain = site.primary_domain;
      const cfToken = await getSetting(env, 'cf_api_token');
      if (!cfToken) return err('CF API 토큰 미설정');

      const cfZoneId = site.cf_zone_id;
      if (!cfZoneId) return err('CF Zone ID 없음. 도메인이 Cloudflare에 연결되지 않은 경우 수동 CNAME 설정이 필요합니다.');

      // Worker Route 확인
      const routes = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/workers/routes`,
        { headers: { 'Authorization': 'Bearer ' + cfToken } }
      ).then(r => r.json()).catch(() => ({ result: [] }));

      const workerName = await getSetting(env, 'cf_worker_name', 'cloudpress-proxy');
      const hasRoute = routes.result?.some(r => r.script === workerName && r.pattern.includes(domain));

      if (hasRoute) {
        await env.DB.prepare(
          `UPDATE sites SET domain_status='active', updated_at=datetime('now') WHERE id=?`
        ).bind(siteId).run();
        // KV 갱신
        try {
          const siteData = JSON.stringify({ id: siteId, name: site.name, site_prefix: site.site_prefix, status: 'active', suspended: 0 });
          await env.CACHE.put(`site_domain:${domain}`, siteData, { expirationTtl: 86400 });
          await env.CACHE.put(`site_domain:${`www.${site.primary_domain}`}`, siteData, { expirationTtl: 86400 });
        } catch (_) {}
        return ok({ message: '도메인 연결 확인 완료', domain_status: 'active' });
      }

      return ok({ message: 'Worker Route가 아직 없습니다. DNS 전파를 기다리거나 수동으로 CNAME을 설정해주세요.', domain_status: 'pending' });
    }

    return err('알 수 없는 요청');
  }

  return err('지원하지 않는 메서드', 405);
}
