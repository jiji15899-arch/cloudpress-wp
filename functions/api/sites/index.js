// functions/api/sites/index.js
// CloudPress v10.0 — POST는 DB 레코드 생성만 담당, 파이프라인은 provision.js에서 실행

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d = {}) => _j({ ok: true, ...d });
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
    return await env.DB.prepare(
      'SELECT id,name,email,role,plan FROM users WHERE id=?'
    ).bind(uid).first();
  } catch { return null; }
}

function genId() {
  return 'site_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}
function genPw(len = 16) {
  const chars = 'ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
  let pw = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (const b of arr) pw += chars[b % chars.length];
  return pw;
}

async function ensureSitesColumns(DB) {
  const migrations = [
    `ALTER TABLE sites ADD COLUMN hosting_provider TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN subdomain TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN account_username TEXT`,
    `ALTER TABLE sites ADD COLUMN vp_account_id TEXT`,
    `ALTER TABLE sites ADD COLUMN cpanel_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_admin_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_username TEXT DEFAULT 'admin'`,
    `ALTER TABLE sites ADD COLUMN wp_password TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_admin_email TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_version TEXT DEFAULT '6.x'`,
    `ALTER TABLE sites ADD COLUMN php_version TEXT`,
    `ALTER TABLE sites ADD COLUMN redis_enabled INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN cron_enabled INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN rest_api_enabled INTEGER DEFAULT 1`,
    `ALTER TABLE sites ADD COLUMN loopback_enabled INTEGER DEFAULT 1`,
    `ALTER TABLE sites ADD COLUMN ssl_active INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN cloudflare_zone_id TEXT`,
    `ALTER TABLE sites ADD COLUMN cloudflare_enabled INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN speed_optimized INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN suspend_protected INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN installation_mode TEXT DEFAULT 'installer'`,
    `ALTER TABLE sites ADD COLUMN error_message TEXT`,
    `ALTER TABLE sites ADD COLUMN provision_step TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN suspended INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN suspension_reason TEXT`,
    `ALTER TABLE sites ADD COLUMN disk_used INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN bandwidth_used INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN updated_at INTEGER DEFAULT (unixepoch())`,
    `ALTER TABLE sites ADD COLUMN deleted_at INTEGER`,
    `ALTER TABLE sites ADD COLUMN primary_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN custom_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN domain_status TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN cname_target TEXT`,
    `ALTER TABLE sites ADD COLUMN server_type TEXT DEFAULT 'shared'`,
    `ALTER TABLE sites ADD COLUMN login_url TEXT`,
    `ALTER TABLE sites ADD COLUMN install_method TEXT DEFAULT 'php_installer'`,
    `ALTER TABLE sites ADD COLUMN hosting_email TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_password TEXT`,
    `ALTER TABLE sites ADD COLUMN multisite_blog_id INTEGER DEFAULT NULL`,
  ];
  for (const sql of migrations) {
    try { await DB.prepare(sql).run(); } catch (_) {}
  }

  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS vp_accounts (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        vp_username TEXT NOT NULL,
        vp_password TEXT NOT NULL,
        panel_url TEXT NOT NULL,
        server_domain TEXT NOT NULL,
        web_root TEXT DEFAULT '/htdocs',
        php_bin TEXT DEFAULT 'php8.3',
        mysql_host TEXT DEFAULT 'localhost',
        clone_zip_url TEXT,
        wp_download_url TEXT,
        max_sites INTEGER DEFAULT 50,
        current_sites INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
  } catch (_) {}

  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS domains (
        id TEXT PRIMARY KEY, site_id TEXT NOT NULL, user_id TEXT NOT NULL,
        domain TEXT NOT NULL UNIQUE, cname_target TEXT NOT NULL,
        cname_verified INTEGER DEFAULT 0, is_primary INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending', verified_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
  } catch (_) {}

  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        endpoint TEXT NOT NULL UNIQUE, p256dh TEXT NOT NULL, auth TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
  } catch (_) {}
}

async function getMaxSites(env, plan) {
  const FALLBACK = { free: 1, starter: 3, pro: 10, enterprise: -1 };
  try {
    const row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(`plan_${plan}_sites`).first();
    const val = parseInt(row?.value ?? '', 10);
    if (isNaN(val)) return FALLBACK[plan] ?? 1;
    return val;
  } catch { return FALLBACK[plan] ?? 1; }
}

async function pickVpAccount(env) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT * FROM vp_accounts
       WHERE is_active=1 AND current_sites < max_sites
       ORDER BY current_sites ASC LIMIT 1`
    ).all();
    return results?.[0] || null;
  } catch { return null; }
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestGet({ request, env }) {
  await ensureSitesColumns(env.DB).catch(() => {});
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, hosting_provider, hosting_domain, subdomain, account_username,
        wp_url, wp_admin_url, wp_username, wp_password, wp_version, php_version,
        redis_enabled, cron_enabled, rest_api_enabled, loopback_enabled,
        ssl_active, cloudflare_enabled, speed_optimized, suspend_protected, status,
        provision_step, error_message, suspended, suspension_reason, disk_used,
        bandwidth_used, plan, primary_domain, custom_domain, domain_status,
        cname_target, server_type, installation_mode,
        login_url, install_method, created_at, updated_at
       FROM sites
       WHERE user_id=? AND (status IS NULL OR status != 'deleted')
       ORDER BY created_at DESC`
    ).bind(user.id).all();
    return ok({ sites: results ?? [] });
  } catch (e) {
    return err('사이트 목록 조회 실패: ' + e.message, 500);
  }
}

export async function onRequestPost({ request, env }) {
  await ensureSitesColumns(env.DB).catch(() => {});
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  if (body.action === 'save-push-subscription') {
    const { subscription } = body;
    if (!subscription?.endpoint) return err('구독 정보 없음');
    try {
      const subId = 'sub_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      await env.DB.prepare(
        `INSERT OR REPLACE INTO push_subscriptions (id, user_id, endpoint, p256dh, auth) VALUES (?,?,?,?,?)`
      ).bind(subId, user.id, subscription.endpoint, subscription.keys?.p256dh || '', subscription.keys?.auth || '').run();
      return ok({ message: '알림 구독 완료' });
    } catch (e) { return err('구독 저장 실패: ' + e.message, 500); }
  }

  if (body.action === 'get-vapid-key') {
    return ok({ vapidPublicKey: env.VAPID_PUBLIC_KEY || '' });
  }

  const { siteName, adminLogin, sitePlan } = body || {};
  if (!siteName || !siteName.trim())        return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');

  const vpAccount = await pickVpAccount(env);
  if (!vpAccount) {
    return err('사용 가능한 VP 계정이 없습니다. 관리자 → VP 계정 관리에서 계정을 추가해주세요.', 503);
  }

  const effectivePlan = sitePlan || user.plan || 'free';
  const maxSites = await getMaxSites(env, user.plan);
  if (maxSites !== -1) {
    const countRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM sites WHERE user_id=? AND (status IS NULL OR status != 'deleted')"
    ).bind(user.id).first();
    if ((countRow?.c ?? 0) >= maxSites) {
      return err(`현재 플랜(${user.plan})의 최대 사이트 수(${maxSites}개)에 도달했습니다. 플랜을 업그레이드해주세요.`, 403);
    }
  }

  const siteId    = genId();
  const wpAdminPw = genPw(16);

  try {
    await env.DB.prepare(
      `INSERT INTO sites (
        id, user_id, name, hosting_provider,
        wp_username, wp_password, wp_admin_email,
        status, provision_step, plan, server_type, installation_mode
      ) VALUES (?,?,?,'shared_hosting',?,?,?,'pending','init',?,'shared','php_installer')`
    ).bind(
      siteId, user.id, siteName.trim(),
      adminLogin, wpAdminPw, user.email,
      effectivePlan
    ).run();
  } catch (e) {
    return err('사이트 레코드 생성 실패: ' + e.message, 500);
  }

  // 파이프라인은 create.html → POST /api/sites/{id}/provision 에서 실행됨
  return ok({
    siteId,
    plan: effectivePlan,
    vpAccount: vpAccount.label,
    message: `WordPress 설치를 시작합니다.`,
  });
}
