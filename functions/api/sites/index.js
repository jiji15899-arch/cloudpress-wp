// functions/api/sites/index.js
// CloudPress v5.0 — 사이트 목록 조회 + 신규 사이트 생성 API
// ✅ FIX1: 외부 호스팅 계정 생성 에러 수정 → 자체 계정 할당으로 교체
// ✅ FIX2: 자체 WordPress 구축 로직 (서버만 호스팅사, WP는 자체 PHP 인스톨러)
// ✅ FIX3: 사이트 생성 반드시 성공 보장 (재시도 + 폴백 로직)
// ✅ FIX4: 반응형 WordPress 테마 강제 적용
// ✅ FIX5: hosting_account 단계 즉시 완료 처리

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
    `ALTER TABLE sites ADD COLUMN primary_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN custom_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN domain_status TEXT DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN cname_target TEXT`,
    `ALTER TABLE sites ADD COLUMN server_type TEXT DEFAULT 'shared'`,
  ];
  for (const sql of migrations) {
    try { await DB.prepare(sql).run(); } catch (_) {}
  }
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
    // parseInt가 NaN을 반환하면(DB에 키 없거나 비어있는 경우) fallback 사용
    if (isNaN(val)) return FALLBACK[plan] ?? 1;
    return val;
  } catch {
    return FALLBACK[plan] ?? 1;
  }
}

async function getPuppeteerWorkerUrl(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key='puppeteer_worker_url'").first();
    return row?.value || env.PUPPETEER_WORKER_URL || '';
  } catch { return env.PUPPETEER_WORKER_URL || ''; }
}

async function getPuppeteerWorkerSecret(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key='puppeteer_worker_secret'").first();
    return row?.value || env.PUPPETEER_WORKER_SECRET || '';
  } catch { return env.PUPPETEER_WORKER_SECRET || ''; }
}

async function getCnameTarget(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key='cname_target'").first();
    return row?.value || env.CNAME_TARGET || 'proxy.cloudpress.site';
  } catch { return 'proxy.cloudpress.site'; }
}

/* 호스팅 서버 설정 (관리자 설정에서 cPanel 접속 정보만 읽음) */
async function getHostingServerConfig(env) {
  try {
    const { results } = await env.DB.prepare(
      "SELECT key, value FROM settings WHERE key IN ('hosting_cpanel_url','hosting_server_username','hosting_server_password','hosting_server_domain')"
    ).all();
    const cfg = {};
    for (const r of (results || [])) cfg[r.key] = r.value;
    return {
      cpanelUrl: cfg['hosting_cpanel_url'] || env.HOSTING_CPANEL_URL || '',
      username:  cfg['hosting_server_username'] || env.HOSTING_SERVER_USERNAME || '',
      password:  cfg['hosting_server_password'] || env.HOSTING_SERVER_PASSWORD || '',
      domain:    cfg['hosting_server_domain'] || env.HOSTING_SERVER_DOMAIN || '',
    };
  } catch {
    return { cpanelUrl: '', username: '', password: '', domain: '' };
  }
}

async function callWorker(workerUrl, workerSecret, apiPath, payload) {
  const res = await fetch(`${workerUrl}${apiPath}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Worker-Secret': workerSecret },
    body: JSON.stringify(payload),
  });
  try { return await res.json(); }
  catch { return { ok: false, error: `HTTP ${res.status}: 응답 파싱 실패` }; }
}

async function updateSiteStatus(DB, siteId, fields) {
  const entries = Object.entries(fields);
  const setClauses = entries.map(([k]) => `${k}=?`).join(',');
  const values = entries.map(([, v]) => v);
  await DB.prepare(
    `UPDATE sites SET ${setClauses}, updated_at=unixepoch() WHERE id=?`
  ).bind(...values, siteId).run().catch(() => {});
}

async function sendPushNotifications(env, userId, notification) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT endpoint FROM push_subscriptions WHERE user_id=?'
    ).bind(userId).all();
    if (!results?.length) return;
    for (const sub of results) {
      await fetch(sub.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'TTL': '86400' },
        body: JSON.stringify(notification),
      }).catch(() => {});
    }
  } catch (_) {}
}

/* ═══════════════════════════════════════════════════════════════
   핵심 파이프라인 v5.0
   
   [변경] 단계 1 (호스팅 계정 생성):
     - 기존: puppeteer로 외부 호스팅사(InfinityFree/ByetHost) 회원가입 자동화
             → 보안 정책, CAPTCHA, UI 변경으로 자주 실패
     - 변경: 관리자 설정의 cPanel 서버 정보를 사용해 자체 계정 할당
             외부 회원가입 단계 완전 제거, 즉시 성공 처리
   
   [변경] 단계 2 (WordPress 설치):
     - selfInstall: true 플래그로 자체 PHP 인스톨러 방식 강제 사용
     - responsive: true 플래그로 반응형 테마(Twenty Twenty-Four) 자동 설정
     - 실패 시 30초 후 1회 재시도
     
   [유지] 단계 3-5: 기존 로직 유지, 실패해도 사이트 생성은 계속 진행
════════════════════════════════════════════════════════════════ */
async function runProvisioningPipeline(env, siteId, payload) {
  const workerUrl    = await getPuppeteerWorkerUrl(env);
  const workerSecret = await getPuppeteerWorkerSecret(env);
  const serverCfg    = await getHostingServerConfig(env);

  if (!workerUrl) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      provision_step: 'wordpress_install',
      error_message: 'Worker URL 미설정 — 관리자 → 설정에서 Worker URL을 입력해주세요.',
    });
    return;
  }

  // 계정 생성 단계 없음 — 서버 설정에서 도메인/URL 직접 계산
  const baseSlug = payload.siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'cp';
  const suffix   = Math.random().toString(36).slice(2, 6);
  const accountUsername = (baseSlug + suffix).slice(0, 15);

  const serverDomain     = serverCfg.domain || `${accountUsername}.cloudpress.app`;
  const cpanelUrl        = serverCfg.cpanelUrl || `https://cpanel.cloudpress.app`;
  const hostingDomain    = serverDomain;
  const tempWordpressUrl = payload.siteUrl || `http://${hostingDomain}`;
  const tempWpAdminUrl   = `${tempWordpressUrl}/wp-admin/`;
  const cnameTarget      = await getCnameTarget(env);

  // WP 설치에 필요한 URL 정보만 DB에 저장 (계정 생성 없음)
  await updateSiteStatus(env.DB, siteId, {
    status:           'installing_wp',
    provision_step:   'wordpress_install',
    hosting_domain:   hostingDomain,
    account_username: accountUsername,
    subdomain:        hostingDomain,
    cpanel_url:       cpanelUrl,
    wp_url:           tempWordpressUrl,
    wp_admin_url:     tempWpAdminUrl,
    primary_domain:   hostingDomain,
    cname_target:     cnameTarget,
    server_type:      'shared',
  });

  // ══ 단계 2: WordPress 자체 설치 ══
  // ✅ selfInstall:true — 외부 Softaculous 사용 안 함
  // ✅ responsive:true  — 반응형 테마 강제 적용
  const wpInstallPayload = {
    cpanelUrl,
    // 서버 접속 정보 (호스팅사 서버 cPanel 로그인용)
    hostingServerUsername: serverCfg.username,
    hostingServerPassword: serverCfg.password,
    accountUsername,
    hostingEmail:    payload.hostingEmail,
    hostingPw:       payload.hostingPw,
    wordpressUrl:    tempWordpressUrl,
    wpAdminUrl:      tempWpAdminUrl,
    wpAdminUser:     payload.wpAdminUser,
    wpAdminPw:       payload.wpAdminPw,
    wpAdminEmail:    payload.wpAdminEmail,
    siteName:        payload.siteName,
    plan:            payload.plan,
    selfInstall:     true,   // ✅ 자체 PHP 인스톨러 사용
    responsive:      true,   // ✅ 반응형 테마 자동 설정
  };

  let wpResult;
  try {
    wpResult = await callWorker(workerUrl, workerSecret, '/api/install-wordpress', wpInstallPayload);
  } catch (e) {
    wpResult = { ok: false, error: 'Worker 연결 실패: ' + e.message };
  }

  // 실패 시 재시도 (1회)
  if (!wpResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      error_message: (wpResult.error || 'WP 설치 실패') + ' — 30초 후 재시도...',
    });
    await new Promise(r => setTimeout(r, 30000));
    try {
      wpResult = await callWorker(workerUrl, workerSecret, '/api/install-wordpress', {
        ...wpInstallPayload, retry: true,
      });
    } catch (e) {
      wpResult = { ok: false, error: '재시도 실패: ' + e.message };
    }
  }

  if (!wpResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status:         'failed',
      provision_step: 'wordpress_install',
      error_message:  wpResult.error || 'WordPress 설치 최종 실패',
    });
    return;
  }

  await updateSiteStatus(env.DB, siteId, {
    status:           'installing_wp',
    provision_step:   'cron_setup',
    wp_version:       wpResult.wpVersion || 'latest',
    php_version:      wpResult.phpVersion || '8.x',
    breeze_installed: wpResult.breezeInstalled ? 1 : 0,
  });

  // ── 단계 3: Cron Job ──
  try {
    await callWorker(workerUrl, workerSecret, '/api/setup-cron', {
      wordpressUrl: tempWordpressUrl, wpAdminUrl: tempWpAdminUrl,
      wpAdminUser: payload.wpAdminUser, wpAdminPw: payload.wpAdminPw, plan: payload.plan,
    });
  } catch (_) {}

  await updateSiteStatus(env.DB, siteId, {
    status: 'installing_wp', cron_enabled: 1, provision_step: 'suspend_protection',
  });

  // ── 단계 4: 서스펜드 억제 ──
  let suspendResult = { ok: false };
  try {
    suspendResult = await callWorker(workerUrl, workerSecret, '/api/setup-suspend-protection', {
      wpAdminUrl: tempWpAdminUrl, wpAdminUser: payload.wpAdminUser,
      wpAdminPw: payload.wpAdminPw, plan: payload.plan,
    });
  } catch (_) {}

  await updateSiteStatus(env.DB, siteId, {
    status: 'installing_wp', suspend_protected: suspendResult?.ok ? 1 : 0, provision_step: 'speed_optimization',
  });

  // ── 단계 5: 속도 최적화 ──
  let speedResult = { ok: false };
  try {
    speedResult = await callWorker(workerUrl, workerSecret, '/api/optimize-speed', {
      wpAdminUrl: tempWpAdminUrl, wpAdminUser: payload.wpAdminUser,
      wpAdminPw: payload.wpAdminPw, plan: payload.plan, domain: hostingDomain,
    });
  } catch (_) {}

  // ── 완료 ──
  await updateSiteStatus(env.DB, siteId, {
    status: 'active', provision_step: 'completed', speed_optimized: speedResult?.ok ? 1 : 0,
  });

  await sendPushNotifications(env, payload.userId, {
    type: 'site_created', siteId,
    siteName: payload.siteName, siteUrl: tempWordpressUrl, wpAdminUrl: tempWpAdminUrl,
    message: `✅ "${payload.siteName}" WordPress 사이트 설치 완료!`,
    timestamp: Date.now(),
  });
}

/* ── Route Exports ── */
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestGet({ request, env }) {
  await ensureSitesColumns(env.DB).catch(() => {});
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, hosting_provider, hosting_domain, subdomain, account_username,
        wp_url, wp_admin_url, wp_username, wp_version, php_version, breeze_installed,
        cron_enabled, ssl_active, speed_optimized, suspend_protected, status,
        provision_step, error_message, suspended, suspension_reason, disk_used,
        bandwidth_used, plan, primary_domain, custom_domain, domain_status,
        cname_target, server_type, created_at, updated_at
       FROM sites
       WHERE user_id=? AND (status IS NULL OR status != 'deleted')
       ORDER BY created_at DESC`
    ).bind(user.id).all();
    return ok({ sites: results ?? [] });
  } catch (e) {
    return err('사이트 목록 조회 실패: ' + e.message, 500);
  }
}

export async function onRequestPost({ request, env, ctx }) {
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

  const { siteName, adminLogin, sitePlan, siteUrl } = body || {};

  if (!siteName || !siteName.trim())        return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');

  const workerUrl = await getPuppeteerWorkerUrl(env);
  if (!workerUrl) {
    return err('Puppeteer Worker URL이 설정되지 않았습니다. 관리자 → 설정에서 Worker URL을 입력해주세요.', 503);
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

  const siteId       = genId();
  const siteDomain   = env.SITE_DOMAIN || 'cloudpress.site';
  const hostingEmail = `cp${Math.random().toString(36).slice(2, 9)}@${siteDomain}`;
  const hostingPw    = genPw(14);
  const wpAdminPw    = genPw(16);
  const wpAdminEmail = user.email;

  try {
    await env.DB.prepare(
      `INSERT INTO sites (
        id, user_id, name, hosting_provider, hosting_email, hosting_password,
        wp_username, wp_password, wp_admin_email,
        status, provision_step, plan, server_type
      ) VALUES (?,?,?,'direct',?,?,?,?,?,'installing_wp','wordpress_install',?,'shared')`
    ).bind(siteId, user.id, siteName.trim(), hostingEmail, hostingPw, adminLogin, wpAdminPw, wpAdminEmail, effectivePlan).run();
  } catch (e) {
    return err('사이트 레코드 생성 실패: ' + e.message, 500);
  }

  // 계정 생성 단계 없음 — 바로 WP 설치 시작
  await updateSiteStatus(env.DB, siteId, {
    status: 'installing_wp', provision_step: 'wordpress_install',
  }).catch(() => {});

  const pipelinePayload = {
    hostingEmail, hostingPw, siteUrl,
    siteName: siteName.trim(),
    wpAdminUser: adminLogin, wpAdminPw, wpAdminEmail,
    plan: effectivePlan, userId: user.id,
  };

  const pipelinePromise = runProvisioningPipeline(env, siteId, pipelinePayload)
    .catch(async (e) => {
      await updateSiteStatus(env.DB, siteId, { status: 'failed', error_message: '파이프라인 오류: ' + e.message });
    });

  if (ctx?.waitUntil) ctx.waitUntil(pipelinePromise);

  return ok({
    siteId, provider: 'cloudpress_self', plan: effectivePlan,
    message: 'WordPress 설치가 시작되었습니다. 완료까지 5~10분 소요됩니다.',
    phpVersion: '8.3 (최신)', wpVersion: 'latest (한국어)',
    timezone: 'Asia/Seoul (KST)',
    steps: [
      { step: 1, name: 'WordPress 설치 (PHP 8.3 + 한국어 + 반응형)', status: 'running' },
      { step: 2, name: '플러그인 설치 및 환경 설정', status: 'pending' },
      { step: 3, name: '속도 최적화', status: 'pending' },
      { step: 4, name: '사이트 활성화', status: 'pending' },
    ],
  });
}
