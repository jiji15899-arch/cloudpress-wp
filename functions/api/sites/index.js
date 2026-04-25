import { ok, err, getUser } from '../_shared.js';

/**
 * POST: 새 사이트 생성 또는 특정 액션 처리
 */
export async function onRequestPost({ request, env }) {
  if (!env?.DB || !env?.SESSIONS) return err('서버 설정 오류: 데이터베이스 연결 불가', 503);
  
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  // ── 사이트 생성 시 결제 수단 확인 ───────────────────────────
  if (!body.action || body.action === 'create') {
    if (user.role !== 'admin' && user.role !== 'manager') {
      // DB에서 최신 사용자 정보(카드 정보 포함) 다시 조회
      const fullUser = await env.DB.prepare("SELECT card_number FROM users WHERE id=?").bind(user.id).first();
      if (!fullUser?.card_number) {
        return err('사이트 생성을 위해 먼저 "내 계정" 탭에서 결제용 카드를 등록해주세요. (7일 무료 체험 후 자동 결제)', 403);
      }
    }

    const siteId = 'site_' + Math.random().toString(36).slice(2, 11);
    const prefix = 's' + Math.random().toString(36).slice(2, 7);
    if (!prefix) return err('접두사 생성 실패');

    try {
      await env.DB.prepare(
        "INSERT INTO sites (id, user_id, name, site_prefix, plan, status, created_at, billing_status) VALUES (?, ?, ?, ?, ?, 'pending', datetime('now'), 'trial')"
      ).bind(siteId, user.id, body.name || 'My Site', prefix, body.plan || 'starter').run();
      
      return ok({ siteId, prefix, message: '사이트 레코드가 생성되었습니다.' });
    } catch (e) {
      return err('데이터베이스 저장 실패: ' + e.message);
    }
  }

  return err('지원되지 않는 액션입니다.');
}
