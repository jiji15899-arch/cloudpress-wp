// functions/api/admin/settings.js
/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAdmin(env,req){const u=await getUser(env,req);return(u&&u.role==='admin')?u:null;}
/* ── end utils ── */

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('어드민 권한 필요', 403);

    const { results } = await env.DB.prepare('SELECT key,value FROM settings').all();
    const cfg = Object.fromEntries((results || []).map(r => [r.key, r.value]));

    // env 변수에서 InstaWP API 키 존재 여부도 표시 (실제 키는 wrangler.toml에)
    cfg.instawp_api_configured = env.INSTAWP_API_KEY ? '1' : '0';
    cfg.cf_api_configured      = env.CF_API_TOKEN    ? '1' : '0';

    return ok({ settings: cfg });
  } catch (e) {
    console.error('settings GET error:', e);
    return err('설정 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPut({ request, env }) {
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('어드민 권한 필요', 403);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { settings } = body || {};
    if (!settings || typeof settings !== 'object') return err('잘못된 요청');

    const now = Math.floor(Date.now() / 1000);
    // 허용된 설정 키만 저장 (보안)
    const ALLOWED_KEYS = [
      'plan_starter_price','plan_pro_price','plan_enterprise_price',
      'plan_starter_sites','plan_pro_sites','plan_enterprise_sites',
      'site_domain','toss_client_key','toss_secret_key',
      'instawp_api_key','contact_email',
    ];

    for (const [key, value] of Object.entries(settings)) {
      if (!ALLOWED_KEYS.includes(key)) continue;
      await env.DB.prepare(
        'INSERT INTO settings (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=?,updated_at=?'
      ).bind(key, String(value), now, String(value), now).run();
    }
    return ok({ message: '설정 저장 완료' });
  } catch (e) {
    console.error('settings PUT error:', e);
    return err('설정 저장 실패: ' + (e?.message ?? e), 500);
  }
}
