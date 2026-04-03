// functions/api/sites/[id].js
/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAuth(env,req){return await getUser(env,req);}
/* ── end utils ── */

const INSTAWP_API = 'https://app.instawp.io/api/v2';

/* InstaWP 상태 조회 */
async function iwpStatus(env, { taskId, iwpSiteId }) {
  const apiKey = env.INSTAWP_API_KEY;
  if (!apiKey) return null;

  try {
    // task_id로 폴링
    if (taskId && !iwpSiteId) {
      const r    = await fetch(`${INSTAWP_API}/tasks/${taskId}/status`, { headers: { 'Authorization': `Bearer ${apiKey}` } });
      const data = await r.json().catch(() => ({}));
      const s    = data.data?.status; // 'progress' | 'completed' | 'failed'
      if (s === 'failed')    return { status: 'error' };
      if (s !== 'completed') return { status: 'provisioning' };
      // 완료 → resource_id로 사이트 조회
      const rid = data.data?.resource_id;
      if (rid) return fetchIwpSite(env, String(rid));
      return { status: 'provisioning' };
    }

    // iwp_site_id로 직접 조회
    if (iwpSiteId) return fetchIwpSite(env, iwpSiteId);
  } catch (e) {
    console.warn('iwpStatus error:', e?.message);
  }
  return null;
}

async function fetchIwpSite(env, iwpSiteId) {
  const apiKey = env.INSTAWP_API_KEY;
  const r    = await fetch(`${INSTAWP_API}/sites/${iwpSiteId}`, { headers: { 'Authorization': `Bearer ${apiKey}` } });
  const data = await r.json().catch(() => ({}));
  if (!data.status || !data.data?.wp_url) return { status: 'provisioning' };
  const s = data.data;
  return {
    status:      'active',
    iwpSiteId:   String(s.id || iwpSiteId),
    wpUrl:       s.wp_url,
    wpAdminUrl:  s.wp_url.replace(/\/?$/, '/wp-admin'),
    wpUsername:  s.wp_username || 'admin',
    wpPassword:  s.wp_password || '',
  };
}

/* Cloudflare DNS 삭제 */
async function deleteDNS(env, name) {
  if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) return;
  try {
    const r = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?name=${encodeURIComponent(name)}`,
      { headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } }
    ).then(r => r.json());
    for (const rec of (r.result || [])) {
      await fetch(
        `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${rec.id}`,
        { method: 'DELETE', headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` } }
      );
    }
  } catch (_) {}
}

export const onRequestOptions = () => handleOptions();

export async function onRequest({ params, request, env }) {
  try {
    const url = new URL(request.url);

    /* ── GET /api/sites/:id/status ── */
    if (url.pathname.endsWith('/status')) {
      const user = await requireAuth(env, request);
      if (!user) return err('인증 필요', 401);

      const site = await env.DB.prepare(
        `SELECT id,status,wp_url,wp_admin_url,wp_username,wp_password,subdomain,custom_domain,iwp_site_id,iwp_task_id
         FROM sites WHERE id=? AND user_id=?`
      ).bind(params.id, user.id).first();
      if (!site) return err('사이트를 찾을 수 없습니다.', 404);

      // provisioning 중이면 InstaWP에서 실시간 확인
      if (site.status === 'provisioning') {
        const result = await iwpStatus(env, { taskId: site.iwp_task_id, iwpSiteId: site.iwp_site_id });
        if (result?.status === 'active') {
          const iwpHost = (() => { try { return new URL(result.wpUrl).hostname; } catch { return result.wpUrl; } })();
          await env.DB.prepare(
            `UPDATE sites SET status='active',iwp_site_id=?,subdomain=?,wp_url=?,wp_admin_url=?,wp_username=?,wp_password=? WHERE id=?`
          ).bind(result.iwpSiteId || site.iwp_site_id, iwpHost, result.wpUrl, result.wpAdminUrl, result.wpUsername || '', result.wpPassword || '', params.id).run();
          return ok({ site: { ...site, status:'active', wp_url:result.wpUrl, wp_admin_url:result.wpAdminUrl, wp_username:result.wpUsername, wp_password:result.wpPassword } });
        }
        if (result?.status === 'error') {
          await env.DB.prepare("UPDATE sites SET status='error' WHERE id=?").bind(params.id).run();
          return ok({ site: { ...site, status:'error' } });
        }
      }
      return ok({ site });
    }

    switch (request.method) {
      case 'GET':     return getSite(params, request, env);
      case 'DELETE':  return deleteSite(params, request, env);
      case 'PUT':     return updateSite(params, request, env);
      case 'OPTIONS': return handleOptions();
      default:        return err('허용되지 않는 메서드', 405);
    }
  } catch (e) {
    console.error('[id] onRequest error:', e);
    return err('요청 처리 중 오류: ' + (e?.message ?? e), 500);
  }
}

async function getSite(params, request, env) {
  try {
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);
    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=? AND user_id=?').bind(params.id, user.id).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);
    return ok({ site });
  } catch (e) {
    return err('사이트 조회 실패: ' + (e?.message ?? e), 500);
  }
}

async function deleteSite(params, request, env) {
  try {
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);
    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=? AND user_id=?').bind(params.id, user.id).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);

    // InstaWP 사이트 삭제 (백그라운드, 실패해도 DB는 삭제)
    if (site.iwp_site_id && env.INSTAWP_API_KEY) {
      fetch(`${INSTAWP_API}/sites/${site.iwp_site_id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${env.INSTAWP_API_KEY}` },
      }).catch(() => {});
    }

    // Cloudflare DNS 삭제
    if (site.custom_domain) deleteDNS(env, site.custom_domain).catch(() => {});

    await env.DB.prepare('DELETE FROM sites WHERE id=? AND user_id=?').bind(params.id, user.id).run();
    return ok({ message: '사이트가 삭제되었습니다.' });
  } catch (e) {
    return err('사이트 삭제 실패: ' + (e?.message ?? e), 500);
  }
}

async function updateSite(params, request, env) {
  try {
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);
    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=? AND user_id=?').bind(params.id, user.id).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { name, custom_domain } = body || {};

    if (name && name.trim()) {
      await env.DB.prepare('UPDATE sites SET name=? WHERE id=?').bind(name.trim(), params.id).run();
    }

    if (custom_domain) {
      if (!/^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(custom_domain)) return err('올바른 도메인 형식이 아닙니다.');
      const dup = await env.DB.prepare('SELECT id FROM sites WHERE custom_domain=? AND id!=?').bind(custom_domain, params.id).first();
      if (dup) return err('이미 다른 사이트에 연결된 도메인입니다.');

      // Cloudflare에 커스텀 도메인 → InstaWP URL CNAME 추가
      if (env.CF_API_TOKEN && env.CF_ZONE_ID && site.wp_url) {
        try {
          const origin = new URL(site.wp_url).hostname;
          await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ type:'CNAME', name:custom_domain, content:origin, proxied:true, ttl:1 }),
          });
        } catch (_) {}
      }
      await env.DB.prepare('UPDATE sites SET custom_domain=? WHERE id=?').bind(custom_domain, params.id).run();
    }

    const updated = await env.DB.prepare('SELECT * FROM sites WHERE id=?').bind(params.id).first();
    return ok({ site: updated });
  } catch (e) {
    return err('사이트 업데이트 실패: ' + (e?.message ?? e), 500);
  }
}
