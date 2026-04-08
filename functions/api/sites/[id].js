// functions/api/sites/[id].js — 사이트 개별 관리 API

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok = (d = {}) => _j({ ok: true, ...d });
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

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;
  const site = await env.DB.prepare(
    `SELECT * FROM sites WHERE id=? AND user_id=?`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  // GET — 사이트 상세 정보
  if (request.method === 'GET') {
    // 일시정지 상태 확인
    if (site.suspended) {
      return ok({
        site: {
          ...site,
          suspended: true,
          suspension_reason: site.suspension_reason || '호스팅 제한',
        },
        suspended: true,
      });
    }
    return ok({ site });
  }

  // DELETE — 사이트 삭제
  if (request.method === 'DELETE') {
    await env.DB.prepare(
      "UPDATE sites SET status='deleted',deleted_at=unixepoch() WHERE id=?"
    ).bind(siteId).run();
    return ok({ message: '사이트가 삭제되었습니다.' });
  }

  // PUT — 사이트 상태 업데이트 (어드민 전용)
  if (request.method === 'PUT') {
    if (user.role !== 'admin') return err('관리자 권한이 필요합니다.', 403);
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    if (body.suspended !== undefined) {
      await env.DB.prepare(
        'UPDATE sites SET suspended=?,suspension_reason=? WHERE id=?'
      ).bind(body.suspended ? 1 : 0, body.reason || '', siteId).run();
      return ok({ message: body.suspended ? '사이트가 일시정지되었습니다.' : '사이트 일시정지가 해제되었습니다.' });
    }

    return err('알 수 없는 요청');
  }

  return err('지원하지 않는 메서드', 405);
}
