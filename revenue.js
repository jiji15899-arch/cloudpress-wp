// functions/api/admin/revenue.js
/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAdminOrMgr(env,req){const u=await getUser(env,req);return(u&&(u.role==='admin'||u.role==='manager'))?u:null;}
/* ── end utils ── */

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const user = await requireAdminOrMgr(env, request);
    if (!user) return err('권한 필요', 403);

    const url    = new URL(request.url);
    const page   = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
    const limit  = 25;
    const offset = (page - 1) * limit;

    const { results: payments } = await env.DB.prepare(
      `SELECT p.*,u.name user_name,u.email user_email
       FROM payments p JOIN users u ON p.user_id=u.id
       WHERE p.status='done'
       ORDER BY p.created_at DESC LIMIT ? OFFSET ?`
    ).bind(limit, offset).all();

    const countRow = await env.DB.prepare("SELECT COUNT(*) c FROM payments WHERE status='done'").first();
    const total = countRow?.c ?? 0;

    const { results: byPlan } = await env.DB.prepare(
      "SELECT plan,COUNT(*) cnt,SUM(amount) total FROM payments WHERE status='done' GROUP BY plan"
    ).all();

    const { results: byMonth } = await env.DB.prepare(
      `SELECT strftime('%Y-%m',created_at,'unixepoch') mo,COUNT(*) cnt,SUM(amount) total
       FROM payments WHERE status='done' GROUP BY mo ORDER BY mo DESC LIMIT 12`
    ).all();

    return ok({ payments: payments ?? [], total, page, pages: Math.ceil(total / limit) || 1, byPlan: byPlan ?? [], byMonth: byMonth ?? [] });
  } catch (e) {
    console.error('revenue GET error:', e);
    return err('매출 데이터 로딩 실패: ' + (e?.message ?? e), 500);
  }
}
