import { ok, err, getUser, CORS } from './_shared.js';

export async function onRequestGet({ request, env }) {
  const user = await getUser(env, request);
  if (!user) return err('Unauthorized', 401);

  const data = await env.DB.prepare(
    "SELECT id, name, email, role, plan, card_number, card_expiry, cf_account_email, cf_account_id, (SELECT COUNT(*) FROM sites WHERE user_id = users.id AND deleted_at IS NULL) as site_count FROM users WHERE id = ?"
  ).bind(user.id).first();

  return ok({ user: data });
}

export async function onRequestPut({ request, env }) {
  const user = await getUser(env, request);
  if (!user) return err('Unauthorized', 401);

  const body = await request.json();

  // 카드 정보 업데이트 전용 로직
  if (body.action === 'update_payment') {
    const cardNumber = String(body.card_number || '').replace(/\s/g, '');
    const cardExpiry = String(body.card_expiry || '').trim();

    if (!cardNumber || !cardExpiry) return err('카드 정보를 모두 입력해주세요.');

    try {
      await env.DB.prepare(
        "UPDATE users SET card_number = ?, card_expiry = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(cardNumber, cardExpiry, user.id).run();
      
      return ok({ message: '결제 수단이 저장되었습니다.' });
    } catch (e) {
      return err('저장 실패: ' + e.message);
    }
  }

  // 일반 프로필(이름 등) 수정
  if (body.name) {
    try {
      await env.DB.prepare("UPDATE users SET name = ? WHERE id = ?").bind(body.name, user.id).run();
      const updated = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
      return ok({ user: updated });
    } catch (e) {
      return err(e.message);
    }
  }

  return err('잘못된 요청입니다.');
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });
