import { ok, err, getUser } from '../_shared.js';

export const onRequestOptions = () => new Response(null, { status: 204, headers: {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
}});

export async function onRequestPost({ request, env }) {
  if (!env?.DB || !env?.SESSIONS) return err('서버 설정 오류: 데이터베이스 연결 불가', 503);

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  // ── 사이트 생성 ──────────────────────────────────────────────────
  if (!body.action || body.action === 'create') {
    const isPrivileged = user.role === 'admin' || user.role === 'manager';

    // 도메인 검증
    const domain = (body.domain || '').trim().toLowerCase()
      .replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    if (!domain || !domain.includes('.') || domain.length < 4) {
      return err('올바른 도메인을 입력해주세요. (예: myblog.com)', 400);
    }

    // 도메인 중복 확인
    const existingDomain = await env.DB.prepare(
      "SELECT id FROM sites WHERE primary_domain=? AND deleted_at IS NULL"
    ).bind(domain).first();
    if (existingDomain) return err('이미 사용 중인 도메인입니다.', 409);

    // DB에서 최신 사용자 정보(카드 및 Cloudflare API 정보) 조회
    const fullUser = await env.DB.prepare(
      'SELECT card_number, cf_global_api_key, cf_account_id, cf_account_email FROM users WHERE id=?'
    ).bind(user.id).first();

    // 어드민/매니저는 결제 수단 없이 사이트 생성 가능
    if (!isPrivileged && !fullUser?.card_number) {
      return err('사이트 생성을 위해 먼저 "내 계정" 탭에서 결제용 카드를 등록해주세요.', 403);
    }

    // Cloudflare API 정보 검증
    if (!fullUser?.cf_global_api_key || !fullUser?.cf_account_id) {
      return err('Cloudflare API 설정이 누락되었습니다. "내 계정"에서 Global API Key와 Account Email을 등록해주세요.', 400);
    }

    const siteId = 'site_' + Math.random().toString(36).slice(2, 11);
    const prefix = 's' + Math.random().toString(36).slice(2, 7);

    try {
      await env.DB.prepare(
        `INSERT INTO sites (id, user_id, name, primary_domain, site_prefix, plan, status, wp_username, wp_password, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', 'admin', '', datetime('now'))`
      ).bind(siteId, user.id, body.name || 'My Site', domain, prefix, body.plan || 'starter').run();

      return ok({ siteId, prefix, domain, message: '사이트 레코드가 생성되었습니다.' });
    } catch (e) {
      return err('데이터베이스 저장 실패: ' + e.message);
    }
  }

  return err('지원되지 않는 액션입니다.');
}

export async function onRequestGet({ request, env }) {
  if (!env?.DB || !env?.SESSIONS) return err('서버 설정 오류: 데이터베이스 연결 불가', 503);

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    // admin만 전체 사이트 목록 조회 가능, 나머지는 본인 사이트만
    const isAdmin = user.role === 'admin';
    const rows = isAdmin
      ? await env.DB.prepare(
          `SELECT id, user_id, name, primary_domain, site_prefix, status, plan, created_at, updated_at
           FROM sites WHERE deleted_at IS NULL ORDER BY created_at DESC`
        ).all()
      : await env.DB.prepare(
          `SELECT id, user_id, name, primary_domain, site_prefix, status, plan, created_at, updated_at
           FROM sites WHERE user_id=? AND deleted_at IS NULL ORDER BY created_at DESC`
        ).bind(user.id).all();

    return ok({ sites: rows.results || [] });
  } catch (e) {
    return err('사이트 목록 조회 실패: ' + e.message, 500);
  }
}
