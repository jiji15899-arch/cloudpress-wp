// functions/api/sites/index.js — CloudPress v11.0
// 단일 WP origin + prefix 격리 방식
// 사이트 생성 흐름:
//   1. site_prefix 생성 (7자 고유 ID)
//   2. WP origin에 사이트 초기화 요청 (테이블 생성 + 관리자 계정)
//   3. provision 엔드포인트에서 도메인 연결 (CF DNS + Worker Route)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d = {}) => _j({ ok: true,  ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();
  } catch { return null; }
}

async function getSetting(env, key, fallback = '') {
  try {
    const r = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    return r?.value ?? fallback;
  } catch { return fallback; }
}

function genId() {
  return 'site_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function genPrefix() {
  // s_ + 5자 영숫자 (소문자) — WP 테이블 prefix에 안전하게 쓸 수 있는 형태
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let s = 's_';
  const arr = new Uint8Array(5);
  crypto.getRandomValues(arr);
  for (const b of arr) s += chars[b % chars.length];
  return s;
}

function genPw(len = 20) {
  const chars = 'ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
  let pw = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (const b of arr) pw += chars[b % chars.length];
  return pw;
}

async function getMaxSites(env, plan) {
  const FALLBACK = { free: 1, starter: 3, pro: 10, enterprise: -1 };
  try {
    const r = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(`plan_${plan}_sites`).first();
    const v = parseInt(r?.value ?? '', 10);
    return isNaN(v) ? (FALLBACK[plan] ?? 1) : v;
  } catch { return FALLBACK[plan] ?? 1; }
}

// WP origin에 사이트 초기화 요청
// WP origin이 site_prefix 헤더를 보고 해당 prefix로 WP 테이블 생성 + admin 계정 생성
async function initWpSite(env, { sitePrefix, siteName, adminUser, adminPw, adminEmail, siteUrl }) {
  const wpOrigin  = await getSetting(env, 'wp_origin_url');
  const wpSecret  = await getSetting(env, 'wp_origin_secret');

  if (!wpOrigin) return { ok: false, error: 'WP origin URL이 설정되지 않았습니다. 관리자 설정을 확인해주세요.' };

  // WP origin의 특수 엔드포인트로 초기화 요청
  // (origin WP에 cloudpress-origin.php mu-plugin + REST 엔드포인트 필요)
  try {
    const res = await fetch(`${wpOrigin.replace(/\/$/, '')}/wp-json/cloudpress/v1/init-site`, {
      method: 'POST',
      headers: {
        'Content-Type':          'application/json',
        'X-CloudPress-Site':     sitePrefix,
        'X-CloudPress-Secret':   wpSecret,
        'X-CloudPress-Domain':   siteUrl.replace(/^https?:\/\//, ''),
      },
      body: JSON.stringify({
        site_prefix: sitePrefix,
        site_name:   siteName,
        admin_user:  adminUser,
        admin_pass:  adminPw,
        admin_email: adminEmail,
        site_url:    siteUrl,
      }),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, error: `WP origin 응답 오류 (${res.status}): ${text.slice(0, 200)}` };
    }

    const data = await res.json().catch(() => ({}));
    return data?.success ? { ok: true } : { ok: false, error: data?.message || 'WP 초기화 실패' };
  } catch (e) {
    return { ok: false, error: 'WP origin 연결 실패: ' + e.message };
  }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestGet({ request, env }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, primary_domain, domain_status,
              site_prefix, worker_name, wp_admin_url,
              wp_username, wp_password, status, provision_step,
              error_message, suspended, suspension_reason,
              disk_used, bandwidth_used, plan, created_at, updated_at
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
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  // 푸시 구독
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

  // 사이트 생성
  const { siteName, adminLogin, personalDomain, sitePlan } = body;
  if (!siteName?.trim())         return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');
  if (!personalDomain?.trim())   return err('개인 도메인을 입력해주세요.');

  // 도메인 형식 검증
  const domain = personalDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return err('올바른 도메인 형식이 아닙니다. (예: myblog.com)');
  }

  // WP origin 설정 확인
  const wpOrigin = await getSetting(env, 'wp_origin_url');
  if (!wpOrigin) return err('WP origin이 설정되지 않았습니다. 관리자 → 설정에서 WP Origin URL을 먼저 입력해주세요.', 503);

  // 도메인 중복 확인
  const existing = await env.DB.prepare(
    `SELECT id FROM sites WHERE primary_domain=? AND deleted_at IS NULL`
  ).bind(domain).first();
  if (existing) return err('이미 사용 중인 도메인입니다.');

  // 플랜 한도 확인
  const effectivePlan = sitePlan || user.plan || 'free';
  const maxSites = await getMaxSites(env, user.plan);
  if (maxSites !== -1) {
    const { c } = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM sites WHERE user_id=? AND deleted_at IS NULL"
    ).bind(user.id).first() ?? { c: 0 };
    if (c >= maxSites) return err(`플랜(${user.plan})의 최대 사이트 수(${maxSites}개)를 초과했습니다.`, 403);
  }

  const siteId     = genId();
  const sitePrefix = genPrefix();       // 예: s_a3k9x2
  const wpAdminPw  = genPw(20);
  const siteUrl    = 'https://' + domain;

  // DB 레코드 먼저 생성
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
      wpOrigin.replace(/\/$/, '') + '/wp-admin/?cp_site=' + sitePrefix,
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
    message: '사이트 생성을 시작합니다.',
  });
}
