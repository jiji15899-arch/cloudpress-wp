import { ok, err, getUser } from '../_shared.js';

export async function onRequestGet({ request, env }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    const { results } = await env.DB.prepare(
      `SELECT * FROM sites WHERE user_id=? AND deleted_at IS NULL ORDER BY created_at DESC`
    ).bind(user.id).all();
    return ok({ sites: results ?? [] });
  } catch (e) {
    return err('사이트 목록 조회 실패: ' + e.message, 500);
  }
}

export async function onRequestPost({ request, env }) {
  if (!env || !env.DB || !env.SESSIONS) return err('서버 설정 오류: DB/SESSIONS 바인딩 없음 (Cloudflare Pages 설정 확인)', 503);
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  // 관리자/매니저가 아닌 경우 결제 수단(카드 정보) 등록 여부 확인
  if (user.role !== 'admin' && user.role !== 'manager') {
    if (!user.card_number || !user.card_expiry) {
      return err('호스팅 생성을 위해 먼저 "내 계정"에서 결제 수단을 등록해주세요. (7일 무료 체험 후 자동 결제)', 403);
    }
  }

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  const { name, plan, payment_method, promo_code } = body;

  // ── 푸시 구독 ──────────────────────────────────────────────────
  if (body.action === 'save-push-subscription') {
    const { subscription } = body;
    if (!subscription?.endpoint) return err('구독 정보 없음');
    try {
      const subId = 'sub_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
