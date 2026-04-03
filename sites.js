// functions/api/admin/sites.js
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

    const url    = new URL(request.url);
    const q      = url.searchParams.get('q') || '';
    const page   = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
    const status = url.searchParams.get('status') || '';
    const limit  = 20;
    const offset = (page - 1) * limit;

    const conds = [], binds = [];
    if (q)      { conds.push('(s.name LIKE ? OR s.subdomain LIKE ? OR s.wp_url LIKE ?)'); binds.push(`%${q}%`, `%${q}%`, `%${q}%`); }
    if (status) { conds.push('s.status=?'); binds.push(status); }

    const where = conds.length ? ' WHERE ' + conds.join(' AND ') : '';
    const query = `SELECT s.*,u.name user_name,u.email user_email
      FROM sites s JOIN users u ON s.user_id=u.id${where}
      ORDER BY s.created_at DESC LIMIT ? OFFSET ?`;

    const { results } = await env.DB.prepare(query).bind(...binds, limit, offset).all();
    const countRow    = await env.DB.prepare(`SELECT COUNT(*) c FROM sites s${where}`).bind(...binds).first();
    const total = countRow?.c ?? 0;

    return ok({ sites: results ?? [], total, page, pages: Math.ceil(total / limit) || 1 });
  } catch (e) {
    console.error('admin sites GET error:', e);
    return err('사이트 목록 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('어드민 권한 필요', 403);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { id } = body || {};
    if (!id) return err('id 필요');

    // InstaWP 사이트도 삭제
    const site = await env.DB.prepare('SELECT iwp_site_id FROM sites WHERE id=?').bind(id).first();
    if (site?.iwp_site_id && env.INSTAWP_API_KEY) {
      fetch(`https://app.instawp.io/api/v2/sites/${site.iwp_site_id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${env.INSTAWP_API_KEY}` },
      }).catch(() => {});
    }

    await env.DB.prepare('DELETE FROM sites WHERE id=?').bind(id).run();
    return ok({ message: '삭제 완료' });
  } catch (e) {
    console.error('admin sites DELETE error:', e);
    return err('삭제 실패: ' + (e?.message ?? e), 500);
  }
}
