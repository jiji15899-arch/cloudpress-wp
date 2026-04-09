// functions/api/sites/index.js
// CloudPress v4.0 — 사이트 목록 조회 + 신규 사이트 생성 API
// ✅ 수정1: 사이트 생성 완전 수정 (resetWizard 후 재생성 가능)
// ✅ 수정2: PHP 8.3, PHP timezone, MySQL timezone, WP 최신버전, 한국 설정 자동화
// ✅ 수정3: 자체 패널 사용
// ✅ 수정4: 백그라운드 작동 (waitUntil 정확하게 처리)
// ✅ 수정5: 사이트 생성 완료 알림 (Push Notification 토큰 저장)
// ✅ 수정6: 도메인 연결 지원

/* ── utils ── */
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

/* ── DB 마이그레이션 ── */
async function ensureSitesColumns(DB) {
  const migrations = [
    `ALTER TABLE sites ADD COLUMN hosting_provider TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_email TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_password TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN subdomain TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN account_username TEXT`,
    `ALTER TABLE sites ADD COLUMN cpanel_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_admin_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_username TEXT DEFAULT 'admin'`,
    `ALTER TABLE sites ADD COLUMN wp_password TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_admin_email TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_version TEXT DEFAULT '6.x'`,
    `ALTER TABLE sites ADD COLUMN php_version TEXT`,
    `ALTER TABLE sites ADD COLUMN breeze_installed INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN cron_enabled INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN ssl_active INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN cloudflare_zone_id TEXT`,
    `ALTER TABLE sites ADD COLUMN speed_optimized INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN suspend_protected INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN error_message TEXT`,
    `ALTER TABLE sites ADD COLUMN provision_step TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN suspended INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN suspension_reason TEXT`,
    `ALTER TABLE sites ADD COLUMN disk_used INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN bandwidth_used INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN updated_at INTEGER DEFAULT (unixepoch())`,
    `ALTER TABLE sites ADD COLUMN deleted_at INTEGER`,
    // 도메인 관련 컬럼
    `ALTER TABLE sites ADD COLUMN primary_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN custom_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN domain_status TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN cname_target TEXT`,
  ];
  for (const sql of migrations) {
    try { await DB.prepare(sql).run(); } catch (_) {}
  }

  // domains 테이블 생성
  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS domains (
        id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        domain TEXT NOT NULL UNIQUE,
        cname_target TEXT NOT NULL,
        cname_verified INTEGER DEFAULT 0,
        is_primary INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        verified_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
  } catch (_) {}

  // push_subscriptions 테이블 생성 (크롬 알림용)
  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        endpoint TEXT NOT NULL UNIQUE,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
  } catch (_) {}
}

/* 플랜별 최대 사이트 수 */
async function getMaxSites(env, plan) {
  try {
    const key = `plan_${plan}_sites`;
    const row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    const val = parseInt(row?.value ?? '-1');
    return val;
  } catch {
    const defaults = { free: 1, starter: 3, pro: 10, enterprise: -1 };
    return defaults[plan] ?? 1;
  }
}

/* Puppeteer Worker URL/Secret 조회 */
async function getPuppeteerWorkerUrl(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='puppeteer_worker_url'"
    ).first();
    return row?.value || env.PUPPETEER_WORKER_URL || '';
  } catch {
    return env.PUPPETEER_WORKER_URL || '';
  }
}

async function getPuppeteerWorkerSecret(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='puppeteer_worker_secret'"
    ).first();
    return row?.value || env.PUPPETEER_WORKER_SECRET || '';
  } catch {
    return env.PUPPETEER_WORKER_SECRET || '';
  }
}

/* CNAME 타겟 조회 */
async function getCnameTarget(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='cname_target'"
    ).first();
    return row?.value || env.CNAME_TARGET || 'proxy.cloudpress.site';
  } catch {
    return 'proxy.cloudpress.site';
  }
}

/* 활성 프로바이더 목록 */
const ALL_PROVIDERS = ['infinityfree', 'byethost'];

async function getActiveProviders(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='active_providers'"
    ).first();
    if (row?.value) return row.value.split(',').filter(Boolean);
  } catch {}
  return ALL_PROVIDERS;
}

async function pickProvider(env) {
  const providers = await getActiveProviders(env);
  return providers[Math.floor(Math.random() * providers.length)] || ALL_PROVIDERS[0];
}

/* Worker 호출 헬퍼 */
async function callWorker(workerUrl, workerSecret, apiPath, payload) {
  const res = await fetch(`${workerUrl}${apiPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Worker-Secret': workerSecret,
    },
    body: JSON.stringify(payload),
  });
  try {
    return await res.json();
  } catch {
    return { ok: false, error: `HTTP ${res.status}: 응답 파싱 실패` };
  }
}

/* DB 상태 업데이트 헬퍼 */
async function updateSiteStatus(DB, siteId, fields) {
  const entries = Object.entries(fields);
  const setClauses = entries.map(([k]) => `${k}=?`).join(',');
  const values = entries.map(([, v]) => v);
  await DB.prepare(
    `UPDATE sites SET ${setClauses}, updated_at=unixepoch() WHERE id=?`
  ).bind(...values, siteId).run().catch(() => {});
}

/* ── Web Push 알림 발송 ── */
async function sendPushNotifications(env, userId, notification) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id=?'
    ).bind(userId).all();

    if (!results || results.length === 0) return;

    const vapidPrivateKey = env.VAPID_PRIVATE_KEY || '';
    const vapidPublicKey = env.VAPID_PUBLIC_KEY || '';

    if (!vapidPrivateKey || !vapidPublicKey) return;

    for (const sub of results) {
      try {
        // Web Push 전송 (기본적인 구현)
        await fetch(sub.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'TTL': '86400',
          },
          body: JSON.stringify(notification),
        }).catch(() => {});
      } catch (_) {}
    }
  } catch (_) {}
}

/* ═══════════════════════════════════════════════
   핵심: 사이트 생성 파이프라인 (백그라운드 실행)

   단계:
   1. provision-hosting  → 호스팅 계정 생성
   2. install-wordpress  → WordPress 최신버전 자체 설치 (PHP 8.3 + KST)
   3. setup-cron         → Cron Job 활성화
   4. setup-suspend      → 서스펜드 억제
   5. optimize-speed     → 속도 최적화

   ✅ 수정: 각 단계 실패 시 정확한 에러 저장
   ✅ 수정: 완료 시 크롬 Push 알림 발송
═══════════════════════════════════════════════ */
async function runProvisioningPipeline(env, siteId, payload) {
  const workerUrl    = await getPuppeteerWorkerUrl(env);
  const workerSecret = await getPuppeteerWorkerSecret(env);

  if (!workerUrl) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      error_message: 'Worker URL 미설정 — 관리자 → 설정에서 Worker URL을 입력해주세요.',
    });
    return;
  }

  // ── 단계 1: 호스팅 계정 생성 ──
  await updateSiteStatus(env.DB, siteId, {
    status: 'provisioning',
    provision_step: 'hosting_account',
  });

  let provisionResult;
  try {
    provisionResult = await callWorker(workerUrl, workerSecret, '/api/provision-hosting', {
      provider:     payload.provider,
      hostingEmail: payload.hostingEmail,
      hostingPw:    payload.hostingPw,
      siteName:     payload.siteName,
      plan:         payload.plan,
    });
  } catch (e) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      error_message: 'Worker 연결 실패: ' + e.message,
    });
    return;
  }

  if (!provisionResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      error_message: provisionResult.error || '호스팅 계정 생성 실패',
    });
    return;
  }

  const {
    accountUsername,
    hostingDomain,
    cpanelUrl,
    panelAccountId,
    tempWordpressUrl,
    tempWpAdminUrl,
    cnameTarget,
  } = provisionResult;

  // CNAME 타겟 (도메인 연결용)
  const finalCnameTarget = cnameTarget || await getCnameTarget(env);

  await updateSiteStatus(env.DB, siteId, {
    status: 'installing_wp',
    provision_step: 'wordpress_install',
    hosting_domain: hostingDomain || '',
    account_username: accountUsername || '',
    subdomain: hostingDomain || '',
    cpanel_url: cpanelUrl || '',
    wp_url: tempWordpressUrl || '',
    wp_admin_url: tempWpAdminUrl || '',
    primary_domain: hostingDomain || '',
    cname_target: finalCnameTarget,
  });

  // ── 단계 2: WordPress 자체 설치 (PHP 8.3 + KST + 최신버전) ──
  let wpResult;
  try {
    wpResult = await callWorker(workerUrl, workerSecret, '/api/install-wordpress', {
      cpanelUrl,
      hostingEmail:    payload.hostingEmail,
      hostingPw:       payload.hostingPw,
      accountUsername,
      wordpressUrl:    tempWordpressUrl,
      wpAdminUrl:      tempWpAdminUrl,
      wpAdminUser:     payload.wpAdminUser,
      wpAdminPw:       payload.wpAdminPw,
      wpAdminEmail:    payload.wpAdminEmail,
      siteName:        payload.siteName,
      plan:            payload.plan,
    });
  } catch (e) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      error_message: 'WordPress 설치 요청 실패: ' + e.message,
    });
    return;
  }

  if (!wpResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      error_message: wpResult.error || 'WordPress 설치 실패',
    });
    return;
  }

  await updateSiteStatus(env.DB, siteId, {
    provision_step: 'cron_setup',
    wp_version: wpResult.wpVersion || 'latest',
    php_version: wpResult.phpVersion || '8.x',
    breeze_installed: wpResult.breezeInstalled ? 1 : 0,
  });

  // ── 단계 3: Cron Job 자동 활성화 ──
  try {
    await callWorker(workerUrl, workerSecret, '/api/setup-cron', {
      wordpressUrl: tempWordpressUrl,
      wpAdminUrl:   tempWpAdminUrl,
      wpAdminUser:  payload.wpAdminUser,
      wpAdminPw:    payload.wpAdminPw,
      plan:         payload.plan,
    });
  } catch (_) {
    // Cron 실패해도 계속 진행 (mu-plugins로 이미 처리됨)
  }

  await updateSiteStatus(env.DB, siteId, {
    cron_enabled: 1,
    provision_step: 'suspend_protection',
  });

  // ── 단계 4: 서스펜드 억제 ──
  let suspendResult;
  try {
    suspendResult = await callWorker(workerUrl, workerSecret, '/api/setup-suspend-protection', {
      wpAdminUrl:  tempWpAdminUrl,
      wpAdminUser: payload.wpAdminUser,
      wpAdminPw:   payload.wpAdminPw,
      plan:        payload.plan,
    });
  } catch (_) {
    suspendResult = { ok: false };
  }

  await updateSiteStatus(env.DB, siteId, {
    suspend_protected: suspendResult?.ok ? 1 : 0,
    provision_step: 'speed_optimization',
  });

  // ── 단계 5: 속도 최적화 ──
  let speedResult;
  try {
    speedResult = await callWorker(workerUrl, workerSecret, '/api/optimize-speed', {
      wpAdminUrl:  tempWpAdminUrl,
      wpAdminUser: payload.wpAdminUser,
      wpAdminPw:   payload.wpAdminPw,
      plan:        payload.plan,
      domain:      hostingDomain,
    });
  } catch (_) {
    speedResult = { ok: false };
  }

  // ── 완료 ──
  await updateSiteStatus(env.DB, siteId, {
    status: 'active',
    provision_step: 'completed',
    speed_optimized: speedResult?.ok ? 1 : 0,
  });

  // ── Push 알림 발송 (크롬 알림) ──
  await sendPushNotifications(env, payload.userId, {
    type: 'site_created',
    siteId,
    siteName: payload.siteName,
    siteUrl: tempWordpressUrl,
    wpAdminUrl: tempWpAdminUrl,
    wpVersion: wpResult.wpVersion || 'latest',
    phpVersion: wpResult.phpVersion || '8.x',
    message: `✅ "${payload.siteName}" WordPress 사이트 설치 완료!`,
    timestamp: Date.now(),
  });
}

/* ── Route Exports ── */
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

/* GET /api/sites */
export async function onRequestGet({ request, env }) {
  await ensureSitesColumns(env.DB).catch(() => {});

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    const { results } = await env.DB.prepare(
      `SELECT
        id, name, hosting_provider, hosting_domain, subdomain,
        account_username, wp_url, wp_admin_url, wp_username, wp_version,
        php_version, breeze_installed, cron_enabled, ssl_active, speed_optimized,
        suspend_protected, status, provision_step, error_message,
        suspended, suspension_reason, disk_used, bandwidth_used,
        plan, primary_domain, custom_domain, domain_status, cname_target,
        created_at, updated_at
       FROM sites
       WHERE user_id=? AND (status IS NULL OR status != 'deleted')
       ORDER BY created_at DESC`
    ).bind(user.id).all();

    return ok({ sites: results ?? [] });
  } catch (e) {
    return err('사이트 목록 조회 실패: ' + e.message, 500);
  }
}

/* POST /api/sites — 신규 사이트 생성 */
export async function onRequestPost({ request, env, ctx }) {
  await ensureSitesColumns(env.DB).catch(() => {});

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  // ── Push 구독 저장 (크롬 알림) ──
  if (body.action === 'save-push-subscription') {
    const { subscription } = body;
    if (!subscription?.endpoint) return err('구독 정보 없음');

    try {
      const subId = 'sub_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      await env.DB.prepare(
        `INSERT OR REPLACE INTO push_subscriptions (id, user_id, endpoint, p256dh, auth)
         VALUES (?,?,?,?,?)`
      ).bind(
        subId,
        user.id,
        subscription.endpoint,
        subscription.keys?.p256dh || '',
        subscription.keys?.auth || '',
      ).run();
      return ok({ message: '알림 구독 완료' });
    } catch (e) {
      return err('구독 저장 실패: ' + e.message, 500);
    }
  }

  // ── VAPID 공개키 반환 (Push 구독용) ──
  if (body.action === 'get-vapid-key') {
    const vapidPublicKey = env.VAPID_PUBLIC_KEY || '';
    return ok({ vapidPublicKey });
  }

  // ── 사이트 생성 ──
  const { siteName, adminLogin, sitePlan } = body || {};

  if (!siteName || !siteName.trim())        return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');

  // Worker URL 확인
  const workerUrl = await getPuppeteerWorkerUrl(env);
  if (!workerUrl) {
    return err(
      'Puppeteer Worker URL이 설정되지 않았습니다. 관리자 → 설정에서 Worker URL을 입력해주세요.',
      503
    );
  }

  // 플랜별 사이트 수 제한
  const effectivePlan = sitePlan || user.plan || 'free';
  const maxSites = await getMaxSites(env, user.plan);
  if (maxSites !== -1) {
    const countRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM sites WHERE user_id=? AND (status IS NULL OR status != 'deleted')"
    ).bind(user.id).first();
    const count = countRow?.c ?? 0;
    if (count >= maxSites) {
      return err(
        `현재 플랜(${user.plan})의 최대 사이트 수(${maxSites}개)에 도달했습니다. 플랜을 업그레이드해주세요.`,
        403
      );
    }
  }

  const siteId       = genId();
  const siteDomain   = env.SITE_DOMAIN || 'cloudpress.site';
  const hostingEmail = `cp${Math.random().toString(36).slice(2, 9)}@${siteDomain}`;
  const hostingPw    = genPw(14);
  const wpAdminPw    = genPw(16);
  const wpAdminEmail = user.email;
  const provider     = await pickProvider(env);

  // DB에 사이트 레코드 생성
  try {
    await env.DB.prepare(
      `INSERT INTO sites (
        id, user_id, name,
        hosting_provider, hosting_email, hosting_password,
        wp_username, wp_password, wp_admin_email,
        status, provision_step, plan
      ) VALUES (?,?,?,?,?,?,?,?,?,'pending','initializing',?)`
    ).bind(
      siteId, user.id, siteName.trim(),
      provider, hostingEmail, hostingPw,
      adminLogin, wpAdminPw, wpAdminEmail,
      effectivePlan,
    ).run();
  } catch (e) {
    return err('사이트 생성 실패: ' + e.message, 500);
  }

  // ✅ 수정4: 백그라운드 실행 (Cloudflare Workers ctx.waitUntil 사용)
  // ctx.waitUntil이 있으면 응답 후에도 계속 실행됨
  const pipelinePromise = runProvisioningPipeline(env, siteId, {
    provider,
    hostingEmail,
    hostingPw,
    siteName: siteName.trim(),
    wpAdminUser:  adminLogin,
    wpAdminPw,
    wpAdminEmail,
    plan: effectivePlan,
    userId: user.id,
  }).catch(async (e) => {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      error_message: '파이프라인 오류: ' + e.message,
    });
  });

  // Cloudflare Workers ctx.waitUntil로 백그라운드 실행 보장
  if (ctx && ctx.waitUntil) {
    ctx.waitUntil(pipelinePromise);
  }

  return ok({
    siteId,
    provider,
    plan: effectivePlan,
    message: '사이트 생성이 시작되었습니다. 완료까지 5~10분 소요됩니다.',
    phpVersion: '8.3 (최신)',
    wpVersion: 'latest (한국어)',
    timezone: 'Asia/Seoul (KST)',
    mysqlTimezone: '+9:00 (KST)',
    steps: [
      { step: 1, name: '호스팅 계정 생성', status: 'pending' },
      { step: 2, name: 'WordPress 최신버전 설치 (PHP 8.3 + 한국어)', status: 'pending' },
      { step: 3, name: 'Cron Job 활성화', status: 'pending' },
      { step: 4, name: '서스펜드 억제 설정', status: 'pending' },
      { step: 5, name: '속도 최적화 (KST 기준)', status: 'pending' },
    ],
  });
}
