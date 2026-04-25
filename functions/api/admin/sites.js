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

  let body;
  try { body = await request.json(); } catch { return err('Invalid JSON'); }
  
  const { id, action, reason } = body || {};
  if (!id) return err('사이트 ID가 필요합니다.');

  try {
    if (action === 'suspend') {
      await env.DB.prepare(
        "UPDATE sites SET suspended = 1, status = 'suspended', suspension_reason = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(reason || '관리자에 의해 정지됨', id).run();
      
      // 캐시 무효화 (필요 시)
      const site = await env.DB.prepare("SELECT primary_domain FROM sites WHERE id = ?").bind(id).first();
      if (site?.primary_domain && env.CACHE) await env.CACHE.delete(`site_domain:${site.primary_domain}`);
      
      return ok({ message: '사이트가 일시 정지되었습니다.' });
    }

    if (action === 'resume') {
      await env.DB.prepare(
        "UPDATE sites SET suspended = 0, status = 'active', suspension_reason = NULL, updated_at = datetime('now') WHERE id = ?"
      ).bind(id).run();
      return ok({ message: '사이트가 다시 활성화되었습니다.' });
    }

    return err('지원하지 않는 액션입니다.');
  } catch (e) {
    return err('사이트 상태 업데이트 실패: ' + e.message);
  }
}

export async function onRequestDelete({ request, env }) {
  const admin = await requireAdminOrMgr(env, request);
  if (!admin) return err('권한이 없습니다.', 403);
  const { id: siteId } = await request.json();
  await env.DB.prepare("UPDATE sites SET deleted_at = datetime('now'), status = 'deleted' WHERE id = ?").bind(siteId).run();
  return ok({ message: '사이트가 완전히 삭제되었습니다.' });
}
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });
