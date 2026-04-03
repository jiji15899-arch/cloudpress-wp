// functions/api/admin/stats.js
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
    if (!admin) return err('어드민 권한이 필요합니다.', 403);

    const now   = Math.floor(Date.now() / 1000);
    const day   = now - 86400;
    const week  = now - 7 * 86400;
    const month = now - 30 * 86400;
    const year  = now - 365 * 86400;

    const [
      totalUsers, totalSites, activeSites,
      sitesToday, sitesWeek, sitesMonth, sitesYear,
      totalRevenue, revenueMonth,
      recentPaymentsResult,
      countryStatsResult, deviceStatsResult,
    ] = await Promise.all([
      env.DB.prepare('SELECT COUNT(*) c FROM users').first(),
      env.DB.prepare('SELECT COUNT(*) c FROM sites').first(),
      env.DB.prepare("SELECT COUNT(*) c FROM sites WHERE status='active'").first(),
      env.DB.prepare('SELECT COUNT(*) c FROM sites WHERE created_at>?').bind(day).first(),
      env.DB.prepare('SELECT COUNT(*) c FROM sites WHERE created_at>?').bind(week).first(),
      env.DB.prepare('SELECT COUNT(*) c FROM sites WHERE created_at>?').bind(month).first(),
      env.DB.prepare('SELECT COUNT(*) c FROM sites WHERE created_at>?').bind(year).first(),
      env.DB.prepare("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='done'").first(),
      env.DB.prepare("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='done' AND created_at>?").bind(month).first(),
      env.DB.prepare("SELECT p.order_id,p.amount,p.plan,p.method,p.created_at,u.name,u.email FROM payments p JOIN users u ON p.user_id=u.id WHERE p.status='done' ORDER BY p.created_at DESC LIMIT 10").all(),
      env.DB.prepare('SELECT country,COUNT(*) cnt FROM traffic_logs GROUP BY country ORDER BY cnt DESC LIMIT 10').all(),
      env.DB.prepare('SELECT device,COUNT(*) cnt FROM traffic_logs GROUP BY device ORDER BY cnt DESC').all(),
    ]);

    const { results: dailySites } = await env.DB.prepare(
      `SELECT date(created_at,'unixepoch') d,COUNT(*) c FROM sites WHERE created_at>? GROUP BY d ORDER BY d`
    ).bind(month).all();

    return ok({
      users:          totalUsers?.c ?? 0,
      sites:          totalSites?.c ?? 0,
      activeSites:    activeSites?.c ?? 0,
      sitesToday:     sitesToday?.c ?? 0,
      sitesWeek:      sitesWeek?.c ?? 0,
      sitesMonth:     sitesMonth?.c ?? 0,
      sitesYear:      sitesYear?.c ?? 0,
      totalRevenue:   totalRevenue?.s ?? 0,
      revenueMonth:   revenueMonth?.s ?? 0,
      recentPayments: recentPaymentsResult?.results ?? [],
      countryStats:   countryStatsResult?.results ?? [],
      deviceStats:    deviceStatsResult?.results ?? [],
      dailySites:     dailySites ?? [],
    });
  } catch (e) {
    console.error('stats error:', e);
    return err('통계 로딩 실패: ' + (e?.message ?? e), 500);
  }
}
