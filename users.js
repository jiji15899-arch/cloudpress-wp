// functions/api/admin/users.js
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
    const limit  = 20;
    const offset = (page - 1) * limit;

    let query = 'SELECT u.id,u.name,u.email,u.role,u.plan,u.created_at,(SELECT COUNT(*) FROM sites s WHERE s.user_id=u.id) site_count FROM users u';
    const binds = [];
    if (q) { query += ' WHERE u.name LIKE ? OR u.email LIKE ?'; binds.push(`%${q}%`, `%${q}%`); }
    query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
    binds.push(limit, offset);

    const { results } = await env.DB.prepare(query).bind(...binds).all();
    const countRow = await env.DB.prepare(
      `SELECT COUNT(*) c FROM users${q ? ' WHERE name LIKE ? OR email LIKE ?' : ''}`
    ).bind(...(q ? [`%${q}%`, `%${q}%`] : [])).first();
    const total = countRow?.c ?? 0;

    return ok({ users: results ?? [], total, page, pages: Math.ceil(total / limit) || 1 });
  } catch (e) {
    console.error('admin users GET error:', e);
    return err('사용자 목록 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPut({ request, env }) {
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('어드민 권한 필요', 403);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { id, role, plan, name } = body || {};
    if (!id) return err('id 필요');

    const fields = [], binds = [];
    if (role !== undefined) { fields.push('role=?');  binds.push(role); }
    if (plan !== undefined) { fields.push('plan=?');  binds.push(plan); }
    if (name !== undefined) { fields.push('name=?');  binds.push(name.trim()); }
    if (!fields.length) return err('변경할 필드 없음');

    binds.push(id);
    await env.DB.prepare(`UPDATE users SET ${fields.join(',')} WHERE id=?`).bind(...binds).run();
    return ok({ message: '업데이트 완료' });
  } catch (e) {
    console.error('admin users PUT error:', e);
    return err('업데이트 실패: ' + (e?.message ?? e), 500);
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
    if (id === admin.id) return err('자기 자신은 삭제할 수 없습니다.');

    await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
    return ok({ message: '삭제 완료' });
  } catch (e) {
    console.error('admin users DELETE error:', e);
    return err('삭제 실패: ' + (e?.message ?? e), 500);
  }
}
