// functions/api/admin/notices.js
/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAdminOrMgr(env,req){const u=await getUser(env,req);return(u&&(u.role==='admin'||u.role==='manager'))?u:null;}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
/* ── end utils ── */

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const url    = new URL(request.url);
    const active = url.searchParams.get('active');
    let query = 'SELECT * FROM notices';
    if (active === '1') query += ' WHERE is_active=1';
    query += ' ORDER BY created_at DESC';
    const { results } = await env.DB.prepare(query).all();
    return ok({ notices: results ?? [] });
  } catch (e) {
    console.error('notices GET error:', e);
    return err('공지 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await requireAdminOrMgr(env, request);
    if (!user) return err('권한 필요', 403);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { title, content, type = 'info' } = body || {};
    if (!title || !content) return err('제목과 내용을 입력해주세요.');

    const id = genId();
    await env.DB.prepare(
      'INSERT INTO notices (id,title,content,type,is_active,created_by) VALUES (?,?,?,?,1,?)'
    ).bind(id, title.trim(), content.trim(), type, user.id).run();
    return ok({ id });
  } catch (e) {
    console.error('notices POST error:', e);
    return err('공지 작성 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPut({ request, env }) {
  try {
    const user = await requireAdminOrMgr(env, request);
    if (!user) return err('권한 필요', 403);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { id, title, content, type, is_active } = body || {};
    if (!id) return err('id 필요');

    const now = Math.floor(Date.now() / 1000);
    const fields = ['updated_at=?'];
    const binds  = [now];
    if (title     !== undefined) { fields.push('title=?');     binds.push(title.trim()); }
    if (content   !== undefined) { fields.push('content=?');   binds.push(content.trim()); }
    if (type      !== undefined) { fields.push('type=?');      binds.push(type); }
    if (is_active !== undefined) { fields.push('is_active=?'); binds.push(is_active ? 1 : 0); }

    binds.push(id);
    await env.DB.prepare(`UPDATE notices SET ${fields.join(',')} WHERE id=?`).bind(...binds).run();
    return ok({ message: '업데이트 완료' });
  } catch (e) {
    console.error('notices PUT error:', e);
    return err('공지 수정 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const user = await requireAdminOrMgr(env, request);
    if (!user) return err('권한 필요', 403);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { id } = body || {};
    if (!id) return err('id 필요');
    await env.DB.prepare('DELETE FROM notices WHERE id=?').bind(id).run();
    return ok({ message: '삭제 완료' });
  } catch (e) {
    console.error('notices DELETE error:', e);
    return err('공지 삭제 실패: ' + (e?.message ?? e), 500);
  }
}
