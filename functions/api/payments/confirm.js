// functions/api/payments/confirm.js
import { CORS, _j, ok, err, handleOptions, getToken, getUser, requireAuth } from '../_shared.js';

export const onRequestOptions = () => handleOptions();

export async function onRequestPost({ request, env }) {
  try {
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { paymentKey, orderId, amount } = body || {};
    if (!paymentKey || !orderId || !amount) return err('결제 정보가 누락되었습니다.');

    const payment = await env.DB.prepare(
      "SELECT * FROM payments WHERE order_id=? AND user_id=? AND status='pending'"
    ).bind(orderId, user.id).first();
    if (!payment) return err('유효하지 않은 결제 요청입니다.');
    if (payment.amount !== parseInt(amount)) return err('결제 금액이 일치하지 않습니다.');

    const secretKey = env.TOSS_SECRET_KEY || (await env.DB.prepare("SELECT value FROM settings WHERE key='toss_secret_key'").first())?.value || '';
    if (!secretKey) return err('결제 키가 설정되지 않았습니다.', 500);

    let tossResp, tossData;
    try {
      tossResp = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
        method: 'POST',
        headers: { 'Authorization': `Basic ${btoa(secretKey + ':')}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ paymentKey, orderId, amount }),
      });
      tossData = await tossResp.json();
    } catch (fetchErr) {
      return err('결제 서버 연결 실패: ' + (fetchErr?.message ?? fetchErr), 500);
    }

    if (!tossResp.ok) {
      await env.DB.prepare("UPDATE payments SET status='failed' WHERE order_id=?").bind(orderId).run();
      return err(tossData?.message || '결제 승인에 실패했습니다.', 400);
    }

    const now        = Math.floor(Date.now() / 1000);
    const method     = tossData.method || '';
    const cardCo     = tossData.card?.company || tossData.easyPay?.provider || '';
    const receiptUrl = tossData.receipt?.url || '';

    await env.DB.prepare(
      `UPDATE payments SET status='done',payment_key=?,method=?,card_company=?,receipt_url=?,confirmed_at=? WHERE order_id=?`
    ).bind(paymentKey, method, cardCo, receiptUrl, now, orderId).run();

    const expiresAt = now + 30 * 86400;
    await env.DB.prepare(
      'UPDATE users SET plan=?,plan_expires_at=? WHERE id=?'
    ).bind(payment.plan, expiresAt, user.id).run();

    return ok({ message:'결제가 완료되었습니다.', plan:payment.plan, expiresAt, receiptUrl });
  } catch (e) {
    console.error('confirm error:', e);
    return err('결제 처리 중 오류: ' + (e?.message ?? e), 500);
  }
}
