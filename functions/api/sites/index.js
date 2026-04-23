// functions/api/sites/index.js — CloudPress v12.1
//
// [v12.1 subrequest 최적화]
// ────────────────────────────────────────────────────────────────────────────
//  문제: getSetting() 개별 호출 2회(plan_${plan}_sites, 내부 로직) → 각각 D1 쿼리 1회씩
//        사이트 생성 흐름에서 도메인 중복확인 + 플랜 한도확인이 별도 쿼리로 분리
//
//  해결:
//    1. loadAllSettings(): SELECT * FROM settings 1회로 모든 설정 메모리 로드
//    2. getMaxSites()에서 DB 쿼리 제거 → 메모리 settings 객체 사용
//    3. 도메인 중복 + 사이트 카운트를 DB.batch()로 1회 왕복 처리
//
//  결과: 사이트 생성 경로 D1 subrequest ~4회 → ~2회로 감소

import { CORS, _j, ok, err, getToken, getUser, loadAllSettings, settingVal, genId } from '../_shared.js';


// ── 설정 일괄 로드 (D1 1회 쿼리) ────────────────────────────────────────────
// 반환: { key → value } 순수 JS 객체
// s_ + 5자 영숫자 소문자 — CF 리소스 이름 / KV key에 안전
function genPrefix() {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let s = 's_';
  const arr = new Uint8Array(5);
  crypto.getRandomValues(arr);
  for (const b of arr) s += chars[b % chars.length];
  return s;
}

function genPw(len = 20) {
  // URL-safe chars only, no ambiguous 0/O/I/l, no special chars that break env vars/URLs
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const charsLen = chars.length; // 56 — 256/56=4 rem 32, reject b>=224 to eliminate modulo bias
  const limit = Math.floor(256 / charsLen) * charsLen; // 224
  let pw = '';
  while (pw.length < len) {
    const arr = crypto.getRandomValues(new Uint8Array(len * 2));
    for (const b of arr) {
      if (b < limit) pw += chars[b % charsLen];
      if (pw.length === len) break;
    }
  }
  return pw;
}

// settings 객체에서 플랜별 최대 사이트 수 반환 (D1 쿼리 없음)
function getMaxSitesFromSettings(settings, plan) {
  const FALLBACK = { free: 1, starter: 3, pro: 10, enterprise: -1 };
  const v = parseInt(settingVal(settings, `plan_${plan}_sites`, ''), 10);
  return isNaN(v) ? (FALLBACK[plan] ?? 1) : v;
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestGet({ request, env }) {
  if (!env || !env.DB || !env.SESSIONS) return err('서버 설정 오류: DB/SESSIONS 바인딩 없음 (Cloudflare Pages 설정 확인)', 503);
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, primary_domain, domain_status,
              site_prefix, worker_name, wp_admin_url,
              wp_admin_username, wp_admin_password,
              status, provision_step,
              error_message, suspended, suspension_reason,
              disk_used, bandwidth_used, plan,
              site_d1_id, site_d1_name, site_kv_id, site_kv_title,
              created_at, updated_at
       FROM sites
       WHERE user_id=? AND deleted_at IS NULL
       ORDER BY created_at DESC`
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

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  // ── 푸시 구독 ──────────────────────────────────────────────────
  if (body.action === 'save-push-subscription') {
    const { subscription } = body;
    if (!subscription?.endpoint) return err('구독 정보 없음');
    try {
      const subId = 'sub_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      await env.DB.prepare(
        `INSERT OR REPLACE INTO push_subscriptions (id,user_id,endpoint,p256dh,auth) VALUES (?,?,?,?,?)`
      ).bind(subId, user.id, subscription.endpoint, subscription.keys?.p256dh || '', subscription.keys?.auth || '').run();
      return ok({ message: '알림 구독 완료' });
    } catch (e) { return err('구독 저장 실패: ' + e.message, 500); }
  }

  // ── 사이트 생성 ────────────────────────────────────────────────
  const { siteName, adminLogin, personalDomain, sitePlan } = body;
  if (!siteName?.trim())        return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');
  if (!personalDomain?.trim())  return err('개인 도메인을 입력해주세요.');

  // 도메인 정규화 [FIX] www 제거 후 검증
  const domain = personalDomain.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9\-.]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain) || domain.includes('..')) {
    return err('올바른 도메인 형식이 아닙니다. (예: myblog.com 또는 myblog.co.kr)');
  }

  // ── [D1 #1] settings + 도메인 중복 + 사이트 카운트 한번에 조회 (batch 1회) ──
  let settings, existingDomain, siteCount;
  try {
    const [settingsRows, dupRow, countRow] = await env.DB.batch([
      env.DB.prepare('SELECT key, value FROM settings'),
      env.DB.prepare('SELECT id FROM sites WHERE primary_domain=? AND deleted_at IS NULL').bind(domain),
      env.DB.prepare('SELECT COUNT(*) as c FROM sites WHERE user_id=? AND deleted_at IS NULL').bind(user.id),
    ]);

    settings = {};
    for (const r of settingsRows.results || []) settings[r.key] = r.value ?? '';

    existingDomain = dupRow.results?.[0] ?? null;
    siteCount = countRow.results?.[0]?.c ?? 0;
  } catch (e) {
    return err('초기 데이터 조회 오류: ' + e.message, 500);
  }

  if (existingDomain) return err('이미 사용 중인 도메인입니다.');

  // 플랜 한도 확인 (메모리 settings에서, D1 쿼리 없음)
  const effectivePlan = sitePlan || user.plan || 'free';
  const maxSites = getMaxSitesFromSettings(settings, user.plan);
  if (maxSites !== -1 && siteCount >= maxSites) {
    return err(`플랜(${user.plan})의 최대 사이트 수(${maxSites}개)를 초과했습니다.`, 403);
  }

  const siteId     = genId();
  const sitePrefix = genPrefix();
  const wpAdminPw  = genPw(20);
  const wpAdminUrl = `https://${domain}/wp-admin/`;

  // ── [D1 #2] DB 레코드 생성 (1회) ──────────────────────────────
  try {
    await env.DB.prepare(
      `INSERT INTO sites (
        id, user_id, name,
        primary_domain, domain_status,
        site_prefix,
        wp_username, wp_password, wp_admin_email,
        wp_admin_url,
        status, provision_step, plan
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      siteId, user.id, siteName.trim(),
      domain, 'pending',
      sitePrefix,
      adminLogin, wpAdminPw, user.email,
      wpAdminUrl,
      'pending', 'init', effectivePlan
    ).run();
  } catch (e) {
    return err('사이트 레코드 생성 실패: ' + e.message, 500);
  }

  return ok({
    siteId,
    sitePrefix,
    plan: effectivePlan,
    domain,
    message: '사이트 레코드가 생성되었습니다. 인프라 구성을 시작합니다.',
  });
}
