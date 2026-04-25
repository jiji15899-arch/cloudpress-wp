import { ok, err, getUser } from '../_shared.js';

export async function onRequestPost({ request, env }) {
  if (!env?.DB || !env?.SESSIONS) return err('서버 설정 오류', 503);

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  const { siteId, planId, cardNumber, cardExpiry } = body;
  if (!siteId) return err('사이트 ID가 필요합니다.', 400);

  // 1. 어드민/매니저 체크 (결제 면제)
  if (user.role === 'admin' || user.role === 'manager') {
    try {
      await env.DB.prepare("UPDATE sites SET plan = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(planId || 'pro', siteId).run();
    } catch (e) {
      return err('사이트 업데이트 실패: ' + e.message, 500);
    }
    return ok({ message: '관리자 권한으로 즉시 활성화되었습니다.' });
  }

  // 2. 카드 정보 저장
  if (cardNumber) {
    try {
      await env.DB.prepare("UPDATE users SET card_number = ?, card_expiry = ? WHERE id = ?")
        .bind(cardNumber, cardExpiry || '', user.id).run();
    } catch (e) {
      return err('카드 정보 저장 실패: ' + e.message, 500);
    }
  }

  // 3. 플랜 업데이트 (billing_status 컬럼은 migrate-v21.sql 실행 후 사용 가능)
  try {
    // billing_status 컬럼이 있으면 같이 업데이트, 없으면 plan만 업데이트
    try {
      const trialEnd = new Date();
      trialEnd.setDate(trialEnd.getDate() + 7);
      await env.DB.prepare(`
        UPDATE sites
        SET plan = ?,
            billing_status = 'trial',
            trial_ends_at = ?,
            updated_at = datetime('now')
        WHERE id = ? AND user_id = ?
      `).bind(planId || 'starter', trialEnd.toISOString(), siteId, user.id).run();

      return ok({
        message: '결제 수단 등록 완료. 7일 체험 기간 종료 후 자동 결제됩니다.',
        trialEndsAt: trialEnd.toISOString(),
      });
    } catch (e) {
      // billing_status 컬럼 없을 경우 fallback
      if (e.message && e.message.includes('billing_status')) {
        await env.DB.prepare(`
          UPDATE sites SET plan = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?
        `).bind(planId || 'starter', siteId, user.id).run();
        return ok({ message: '플랜이 업데이트되었습니다.' });
      }
      throw e;
    }
  } catch (e) {
    return err('결제 처리 실패: ' + e.message, 500);
  }
}
