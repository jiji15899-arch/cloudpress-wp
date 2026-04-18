// functions/api/admin/revenue.js
import { CORS, _j, ok, err, handleOptions, getToken, getUser, requireAdminOrMgr } from '../_shared.js';

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
