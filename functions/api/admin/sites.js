// functions/api/admin/sites.js — CloudPress v17.1
// [수정사항]
// - 매니저(manager)도 사이트 목록 조회/정지/해제/삭제 허용

import { CORS, _j, ok, err, requireAdminOrMgr } from '../_shared.js';

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const user = await requireAdminOrMgr(env, request);
  if (!user) return err('관리자/매니저 권한이 필요합니다.', 403);

  const url = new URL(request.url);

  // GET — 전체 사이트 목록
  if (request.method === 'GET') {
    try {
      const page    = parseInt(url.searchParams.get('page') || '1');
      const perPage = 30;
      const offset  = (page - 1) * perPage;
      const search  = url.searchParams.get('search') || url.searchParams.get('q') || '';
      const status  = url.searchParams.get('status') || '';

      let where = "s.status != 'deleted'";
      const binds = [];

      if (search) {
        where += ' AND (s.name LIKE ? OR u.email LIKE ? OR s.primary_domain LIKE ?)';
        binds.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }
      if (status) { where += ' AND s.status=?'; binds.push(status); }

      const [totalRow, { results }] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as c FROM sites s JOIN users u ON s.user_id=u.id WHERE ${where}`).bind(...binds).first(),
        env.DB.prepare(
          `SELECT s.*,u.name as user_name,u.email as user_email
           FROM sites s JOIN users u ON s.user_id=u.id
           WHERE ${where} ORDER BY s.created_at DESC LIMIT ? OFFSET ?`
        ).bind(...binds, perPage, offset).all(),
      ]);

      return ok({
        sites:      results || [],
        total:      totalRow?.c || 0,
        page,
        totalPages: Math.ceil((totalRow?.c || 0) / perPage),
      });
    } catch (e) {
      return err('사이트 목록 조회 실패: ' + e.message);
    }
  }

  // POST — 사이트 일시정지 / 정지 해제 / 삭제
  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    const { siteId, action, reason } = body;
    if (!siteId) return err('사이트 ID가 필요합니다.');

    const site = await env.DB.prepare('SELECT id,status FROM sites WHERE id=?').bind(siteId).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);

    if (action === 'suspend') {
      await env.DB.prepare(
        "UPDATE sites SET suspended=1,suspension_reason=?,updated_at=datetime('now') WHERE id=?"
      ).bind(reason || '관리자에 의해 일시 정지됨', siteId).run();
      return ok({ message: '사이트가 일시 정지되었습니다.' });
    }
    if (action === 'unsuspend') {
      await env.DB.prepare(
        "UPDATE sites SET suspended=0,suspension_reason=NULL,updated_at=datetime('now') WHERE id=?"
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

  // DELETE
  if (request.method === 'DELETE') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }
    const { id: siteId } = body || {};
    if (!siteId) return err('사이트 ID가 필요합니다.');
    const site = await env.DB.prepare('SELECT id FROM sites WHERE id=?').bind(siteId).first();
    if (!site) return err('사이트를 찾을 수 없습니다.', 404);
    await env.DB.prepare(
      "UPDATE sites SET status='deleted',deleted_at=datetime('now') WHERE id=?"
    ).bind(siteId).run();
    return ok({ message: '사이트가 삭제되었습니다.' });
  }

  return err('지원하지 않는 메서드', 405);
}

import { ok, err, requireAdminOrMgr, CORS } from '../_shared.js';

export async function onRequestGet({ request, env }) {
  const admin = await requireAdminOrMgr(env, request);
  if (!admin) return err('Forbidden', 403);

  const { results } = await env.DB.prepare(
    "SELECT s.*, u.email as owner_email FROM sites s JOIN users u ON s.user_id = u.id WHERE s.deleted_at IS NULL ORDER BY s.created_at DESC"
  ).all();
  return ok({ sites: results });
}

export async function onRequestPut({ request, env }) {
  const admin = await requireAdminOrMgr(env, request);
  if (!admin) return err('Forbidden', 403);

  const body = await request.json();
  const { id, action, reason } = body;

  if (action === 'suspend') {
    await env.DB.prepare(
      "UPDATE sites SET suspended = 1, status = 'suspended', suspension_reason = ? WHERE id = ?"
    ).bind(reason || '관리자에 의해 정지됨', id).run();
    
    // Cache 무효화
    const site = await env.DB.prepare("SELECT primary_domain FROM sites WHERE id = ?").bind(id).first();
    if (site && env.CACHE) await env.CACHE.delete(`site_domain:${site.primary_domain}`);
    
    return ok({ message: '사이트가 정지되었습니다.' });
  }

  if (action === 'resume') {
    await env.DB.prepare(
      "UPDATE sites SET suspended = 0, status = 'active' WHERE id = ?"
    ).bind(id).run();
    return ok({ message: '사이트가 다시 활성화되었습니다.' });
  }

  return err('Invalid action');
}

export async function onRequestDelete({ request, env }) {
  const admin = await requireAdminOrMgr(env, request);
  if (!admin) return err('Forbidden', 403);
  const { id } = await request.json();
  await env.DB.prepare("UPDATE sites SET deleted_at = datetime('now'), status = 'deleted' WHERE id = ?").bind(id).run();
  return ok({ message: '사이트가 완전히 삭제되었습니다.' });
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });
