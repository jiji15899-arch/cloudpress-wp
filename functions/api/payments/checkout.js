import { ok, err, getUser } from '../_shared.js';

export async function onRequestPost(ctx) {
  const { request, env, db } = ctx.data; // Assuming ctx.data is populated by middleware with db and user
  const user = await getUser(env, request);
  const { siteId, planId, cardNumber, cardExpiry, tossVirtualAccount } = await request.json();

  if (!siteId) return err('사이트 ID가 필요합니다.', 400);

  // 1. 어드민/매니저 체크 (결제 면제)
  if (user.role === 'admin' || user.role === 'manager') {
    await db.prepare("UPDATE sites SET billing_status = 'active', plan = ? WHERE id = ?")
      .bind(planId || 'pro', siteId).run();
    return ok({ message: '관리자 권한으로 즉시 활성화되었습니다.' });
  }

  // 2. 카드 정보 저장 (검증 서버 연동 전 임시 저장)
  if (cardNumber) {
    await db.prepare("UPDATE users SET card_number = ?, card_expiry = ? WHERE id = ?")
      .bind(cardNumber, cardExpiry, user.id).run();
  }

  // 3. 호스팅 단위 7일 무료 체험 및 유예 로직
  const trialEnd = new Date();
  trialEnd.setDate(trialEnd.getDate() + 7);

  await db.prepare(`
    UPDATE sites 
    SET billing_status = 'trial',
        plan = ?,
        trial_ends_at = ?,
        updated_at = datetime('now')
    WHERE id = ? AND user_id = ?
  `).bind(planId, trialEnd.toISOString(), siteId, user.id).run();

  return ok({ 
    message: '결제 수단 등록 완료. 7일 체험 기간 종료 후 자동 결제됩니다.',
    trialEndsAt: trialEnd.toISOString()
  });
}
