import { ok, err, getUser } from '../_shared.js';

/**
 * GET: 사용자의 사이트 목록 조회
 */
export async function onRequestGet({ request, env }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    const { results } = await env.DB.prepare(
      "SELECT * FROM sites WHERE user_id=? AND deleted_at IS NULL ORDER BY created_at DESC"
    ).bind(user.id).all();
    return ok({ sites: results ?? [] });
  } catch (e) {
    return err('사이트 목록을 불러오는 중 오류가 발생했습니다: ' + e.message, 500);
  }
}

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
    
    // 사이트 생성 로직 호출 (provisioning 시작)
    // 실제 생성 로직은 /api/sites/[id]/provision.js에서 담당하므로 여기서는 레코드 초기 생성 후 ID 반환
    const siteId = 'site_' + Math.random().toString(36).slice(2, 11);
    try {
      await env.DB.prepare(
        "INSERT INTO sites (id, user_id, name, plan, status, created_at) VALUES (?, ?, ?, ?, 'pending', datetime('now'))"
      ).bind(siteId, user.id, body.name || 'My Site', body.plan || 'starter').run();
      
      return ok({ siteId, message: '사이트 생성이 시작되었습니다.' });
    } catch (e) {
      return err('데이터베이스 저장 실패: ' + e.message);
    }
  }

  const { name, plan, payment_method, promo_code } = body;

  // ── 푸시 구독 ──────────────────────────────────────────────────
  if (body.action === 'save-push-subscription') {
    const { subscription } = body;
    if (!subscription?.endpoint) return err('구독 정보 없음');
    try {
      const subId = 'sub_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      await env.DB.prepare("INSERT INTO push_subs (id, user_id, endpoint, data) VALUES (?,?,?,?)")
        .bind(subId, user.id, subscription.endpoint, JSON.stringify(subscription)).run();
      return ok({ message: '구독 저장됨' });
    } catch (e) { return err(e.message); }
  }

  return err('지원되지 않는 액션입니다.');
}

export const onRequestOptions = () => new Response(null, { 
  status: 204, 
  headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' } 
});
