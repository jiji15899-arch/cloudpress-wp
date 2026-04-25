// functions/api/admin/sites.js — CloudPress v17.1
import { CORS, ok, err, requireAdminOrMgr } from '../_shared.js';

export async function onRequestGet({ request, env }) {
  const admin = await requireAdminOrMgr(env, request);
  if (!admin) return err('관리자/매니저 권한이 필요합니다.', 403);

  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page') || '1');
  const perPage = 30;
  const offset = (page - 1) * perPage;
  const search = url.searchParams.get('search') || url.searchParams.get('q') || '';

  let where = "s.status != 'deleted'";
  const binds = [];

  if (search) {
    where += ' AND (s.name LIKE ? OR u.email LIKE ? OR s.primary_domain LIKE ?)';
    binds.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  try {
    const [totalRow, { results }] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as c FROM sites s JOIN users u ON s.user_id=u.id WHERE ${where}`).bind(...binds).first(),
      env.DB.prepare(
        `SELECT s.*, u.name as user_name, u.email as user_email
         FROM sites s JOIN users u ON s.user_id = u.id 
         WHERE ${where} ORDER BY s.created_at DESC LIMIT ? OFFSET ?`
      ).bind(...binds, perPage, offset).all(),
    ]);

    return ok({ 
      sites: results || [], 
      total: totalRow?.c || 0,
      page,
      totalPages: Math.ceil((totalRow?.c || 0) / perPage)
    });
  } catch (e) {
    return err('사이트 목록 로딩 실패: ' + e.message, 500);
  }
}

/**
 * POST: 사이트 액션 처리 (정지, 복구 등)
 */
export async function onRequestPost({ request, env }) {
  const admin = await requireAdminOrMgr(env, request);
  if (!admin) return err('권한이 없습니다.', 403);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  const { siteId, action, reason } = body;
  if (!siteId) return err('사이트 ID가 필요합니다.');

  try {
    if (action === 'suspend') {
      await env.DB.prepare(
        "UPDATE sites SET suspended = 1, status = 'suspended', suspension_reason = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(reason || '관리자에 의해 정지됨', siteId).run();
      
      // KV 캐시가 있다면 사이트 정보 제거 (즉시 반영을 위함)
      const site = await env.DB.prepare("SELECT primary_domain FROM sites WHERE id = ?").bind(siteId).first();
      if (site?.primary_domain && env.CACHE) {
        await env.CACHE.delete(`site_domain:${site.primary_domain}`);
      }
      
      return ok({ message: '사이트가 일시 정지되었습니다.' });
    }

    if (action === 'resume' || action === 'unsuspend') {
      await env.DB.prepare(
        "UPDATE sites SET suspended = 0, status = 'active', suspension_reason = NULL, updated_at = datetime('now') WHERE id = ?"
      ).bind(siteId).run();
      return ok({ message: '사이트가 다시 활성화되었습니다.' });
    }

    if (action === 'delete') {
      await env.DB.prepare(
        "UPDATE sites SET status = 'deleted', deleted_at = datetime('now') WHERE id = ?"
      ).bind(siteId).run();
      return ok({ message: '사이트가 완전히 삭제되었습니다.' });
    }

    return err('지원하지 않는 액션입니다.');
  } catch (e) {
    return err('작업 중 오류 발생: ' + e.message, 500);
  }
}

export async function onRequestPut({ request, env }) {
