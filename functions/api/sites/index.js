// functions/api/sites/index.js — CloudPress v12.0
//
// 사이트 생성 방식:
//   WP origin에 아무것도 요청하지 않음 (오리진 부하 제로)
//   1. site_prefix(고유 ID) 생성
//   2. DB 레코드 생성
//   3. provision.js 에서 사이트 전용 D1 + KV 생성 → DNS + Worker Route 등록
//
// 각 사이트는 완전히 독립된 D1 + KV를 가지므로 데이터 격리 보장
// WP origin은 오직 프록시 타겟으로만 사용 (이 파일에서 origin 호출 없음)

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

  // 도메인 정규화
  const domain = personalDomain.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return err('올바른 도메인 형식이 아닙니다. (예: myblog.com)');
  }

  // WP Origin 설정 확인 (프록시 타겟 — 이 시점에서 origin에 요청하지 않음)
  const wpOrigin = await getSetting(env, 'wp_origin_url');
  if (!wpOrigin) {
    return err('WP Origin URL이 설정되지 않았습니다. 관리자 → 설정에서 먼저 입력해주세요.', 503);
  }

  // CF 설정 확인 (provision 단계에서 D1/KV 생성에 필요)
  const cfToken   = await getSetting(env, 'cf_api_token');
  const cfAccount = await getSetting(env, 'cf_account_id');
  if (!cfToken || !cfAccount) {
    return err('Cloudflare API Token과 Account ID가 설정되지 않았습니다. 관리자 → 설정을 확인해주세요.', 503);
  }

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
      'SELECT COUNT(*) as c FROM sites WHERE user_id=? AND deleted_at IS NULL'
    ).bind(user.id).first() ?? { c: 0 };
    if (c >= maxSites) {
      return err(`플랜(${user.plan})의 최대 사이트 수(${maxSites}개)를 초과했습니다.`, 403);
    }
  }

  const siteId     = genId();
  const sitePrefix = genPrefix();
  const wpAdminPw  = genPw(20);

  // DB 레코드 생성
  // site_d1_id / site_kv_id 는 provision 단계에서 채워짐
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
      wpOrigin.replace(/\/$/, '') + '/wp-admin',
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
