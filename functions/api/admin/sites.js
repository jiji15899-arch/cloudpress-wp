// functions/api/admin/sites.js — 관리자 WordPress 사이트 제어 API

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok = (d = {}) => _j({ ok: true, ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

async function requireAdmin(env, req) {
  try {
    const a = req.headers.get('Authorization') || '';
    const token = a.startsWith('Bearer ') ? a.slice(7) : null;
    if (!token) return null;
    const uid = await env.SESSIONS.get(`session:${token}`);
    if (!uid) return null;
    const user = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(uid).first();
    return user?.role === 'admin' ? user : null;
  } catch { return null; }
}

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  const url = new URL(request.url);

  // GET — 전체 사이트 목록
  if (request.method === 'GET') {
    try {
      const page = parseInt(url.searchParams.get('page') || '1');
      const perPage = 30;
      const offset = (page - 1) * perPage;
      const search = url.searchParams.get('search') || '';
      const status = url.searchParams.get('status') || '';
      const provider = url.searchParams.get('provider') || '';

      let where = "s.status != 'deleted'";
      const binds = [];

      if (search) {
        where += ' AND (s.name LIKE ? OR u.email LIKE ? OR s.hosting_domain LIKE ?)';
        binds.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }
      if (status) { where += ' AND s.status=?'; binds.push(status); }
      if (provider) { where += ' AND s.hosting_provider=?'; binds.push(provider); }

      const [totalRow, { results }] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as c FROM sites s JOIN users u ON s.user_id=u.id WHERE ${where}`).bind(...binds).first(),
        env.DB.prepare(
          `SELECT s.*,u.name as user_name,u.email as user_email
           FROM sites s JOIN users u ON s.user_id=u.id
           WHERE ${where} ORDER BY s.created_at DESC LIMIT ? OFFSET ?`
        ).bind(...binds, perPage, offset).all(),
      ]);

      return ok({
        sites: results || [],
        total: totalRow?.c || 0,
        page,
        totalPages: Math.ceil((totalRow?.c || 0) / perPage),
      });
    } catch (e) {
      return err('사이트 목록 조회 실패: ' + e.message);
    }
  }

  // POST — 사이트 일시정지 / 정지 해제
  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    const { siteId, action, reason } = body;
    if (!siteId) return err('사이트 ID가 필요합니다.');

    const site = await env.DB.prepare('SELECT id,status FROM sites WHERE id=?').bind(siteId).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);

    if (action === 'suspend') {
      await env.DB.prepare(
        'UPDATE sites SET suspended=1,suspension_reason=?,updated_at=datetime(\'now\') WHERE id=?'
      ).bind(reason || '관리자에 의해 일시 정지됨', siteId).run();
      return ok({ message: '사이트가 일시 정지되었습니다.' });
    }

    if (action === 'unsuspend') {
      await env.DB.prepare(
        'UPDATE sites SET suspended=0,suspension_reason=NULL,updated_at=datetime(\'now\') WHERE id=?'
      ).bind(siteId).run();
      return ok({ message: '사이트 정지가 해제되었습니다.' });
    }

    if (action === 'delete') {
      await env.DB.prepare(
        "UPDATE sites SET status='deleted',deleted_at=datetime('now') WHERE id=?"
      ).bind(siteId).run();
      return ok({ message: '사이트가 삭제되었습니다.' });
    }

    return err('알 수 없는 action');
  }

  return err('지원하지 않는 메서드', 405);
}
