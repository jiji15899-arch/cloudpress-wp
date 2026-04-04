// functions/api/sites/[id].js
// CloudPress CMS 개별 사이트 관리

/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
/* ── end utils ── */

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

async function getUserCfCreds(env, userId) {
  const row = await env.DB.prepare('SELECT cf_global_api_key,cf_account_email,cf_account_id FROM users WHERE id=?').bind(userId).first();
  if (!row?.cf_global_api_key) return null;
  return {
    apiKey: deobfuscate(row.cf_global_api_key, env.ENCRYPTION_KEY || 'cp_enc_default'),
    email: row.cf_account_email,
    accountId: row.cf_account_id,
  };
}

/* Cloudflare DNS 레코드 삭제 */
async function deleteCfDnsRecord(cfHeaders, zoneId, name) {
  if (!zoneId) return;
  try {
    const r = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${encodeURIComponent(name)}`,
      { headers: cfHeaders }
    ).then(r => r.json());
    for (const rec of (r.result || [])) {
      await fetch(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${rec.id}`,
        { method: 'DELETE', headers: cfHeaders }
      );
    }
  } catch (_) {}
}

/* KV Namespace 삭제 */
async function deleteCfKv(cfHeaders, accountId, namespaceId) {
  if (!namespaceId || !accountId) return;
  try {
    await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}`,
      { method: 'DELETE', headers: cfHeaders }
    );
  } catch (_) {}
}

/* D1 Database 삭제 */
async function deleteCfD1(cfHeaders, accountId, databaseId) {
  if (!databaseId || !accountId) return;
  try {
    await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${databaseId}`,
      { method: 'DELETE', headers: cfHeaders }
    );
  } catch (_) {}
}

export const onRequestOptions = () => handleOptions();

export async function onRequest({ params, request, env }) {
  try {
    const url = new URL(request.url);

    /* ── GET /api/sites/:id/status ── */
    if (url.pathname.endsWith('/status')) {
      const user = await getUser(env, request);
      if (!user) return err('인증 필요', 401);
      const site = await env.DB.prepare(
        `SELECT id,status,cms_url,cms_admin_url,cms_username,cms_password,subdomain,custom_domain,cf_zone_id,cf_d1_database,cf_kv_namespace,cms_version
         FROM sites WHERE id=? AND user_id=?`
      ).bind(params.id, user.id).first();
      if (!site) return err('사이트를 찾을 수 없습니다.', 404);
      return ok({ site });
    }

    /* ── GET /api/sites/:id/credentials ── */
    if (url.pathname.endsWith('/credentials')) {
      const user = await getUser(env, request);
      if (!user) return err('인증 필요', 401);
      const site = await env.DB.prepare(
        'SELECT id,cms_url,cms_admin_url,cms_username,cms_password FROM sites WHERE id=? AND user_id=?'
      ).bind(params.id, user.id).first();
      if (!site) return err('사이트를 찾을 수 없습니다.', 404);
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
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);
    const site = await env.DB.prepare(
      `SELECT id,name,subdomain,custom_domain,cms_url,cms_admin_url,cms_username,
              cms_version,status,plan,created_at,cf_zone_id,cf_d1_database,cf_kv_namespace
       FROM sites WHERE id=? AND user_id=?`
    ).bind(params.id, user.id).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);
    // 비밀번호는 별도 엔드포인트(/credentials)에서만 노출
    return ok({ site });
  } catch (e) {
    return err('사이트 조회 실패: ' + (e?.message ?? e), 500);
  }
}

async function deleteSite(params, request, env) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);
    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=? AND user_id=?').bind(params.id, user.id).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);

    // CF 리소스 정리 (백그라운드)
    const creds = await getUserCfCreds(env, user.id).catch(() => null);
    if (creds) {
      const cfHeaders = { 'X-Auth-Email': creds.email, 'X-Auth-Key': creds.apiKey, 'Content-Type': 'application/json' };
      const domain = env.SITE_DOMAIN || 'cloudpress.site';
      const fqdn = `${site.subdomain}.${domain}`;

      // 비동기 삭제 (결과 무관)
      if (site.cf_zone_id) deleteCfDnsRecord(cfHeaders, site.cf_zone_id, fqdn).catch(() => {});
      if (site.custom_domain) deleteCfDnsRecord(cfHeaders, site.cf_zone_id, site.custom_domain).catch(() => {});
      if (site.cf_kv_namespace) deleteCfKv(cfHeaders, creds.accountId, site.cf_kv_namespace).catch(() => {});
      if (site.cf_d1_database) deleteCfD1(cfHeaders, creds.accountId, site.cf_d1_database).catch(() => {});
    }

    await env.DB.prepare('DELETE FROM sites WHERE id=? AND user_id=?').bind(params.id, user.id).run();
    return ok({ message: '사이트가 삭제되었습니다.' });
  } catch (e) {
    return err('사이트 삭제 실패: ' + (e?.message ?? e), 500);
  }
}

async function updateSite(params, request, env) {
  try {
    const user = await getUser(env, request);
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

      // CF DNS에 커스텀 도메인 CNAME 추가
      const creds = await getUserCfCreds(env, user.id).catch(() => null);
      if (creds && site.cf_zone_id) {
        const cfHeaders = { 'X-Auth-Email': creds.email, 'X-Auth-Key': creds.apiKey, 'Content-Type': 'application/json' };
        const domain = env.SITE_DOMAIN || 'cloudpress.site';
        await fetch(`https://api.cloudflare.com/client/v4/zones/${site.cf_zone_id}/dns_records`, {
          method: 'POST',
          headers: cfHeaders,
          body: JSON.stringify({ type: 'CNAME', name: custom_domain, content: `${site.subdomain}.${domain}`, proxied: true, ttl: 1 }),
        }).catch(() => {});
      }
      await env.DB.prepare('UPDATE sites SET custom_domain=? WHERE id=?').bind(custom_domain, params.id).run();
    }

    const updated = await env.DB.prepare(
      `SELECT id,name,subdomain,custom_domain,cms_url,cms_admin_url,cms_username,cms_version,status,plan,created_at
       FROM sites WHERE id=?`
    ).bind(params.id).first();
    return ok({ site: updated });
  } catch (e) {
    return err('사이트 업데이트 실패: ' + (e?.message ?? e), 500);
  }
}
