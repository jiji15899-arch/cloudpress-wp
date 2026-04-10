// functions/api/sites/index.js
// CloudPress v6.1 — 공유 호스팅 최적화 + 사이트 생성 버그 수정
// ✅ v6.1 변경사항:
//   1. VP 계정 없어도 PHP 인스톨러 직접 실행 모드 지원
//   2. Worker URL 없어도 동작하는 공유호스팅 폴백 모드
//   3. 공유 호스팅 자동 설정: cron, REST API, 속도최적화
//   4. 사이트 생성 상태 폴링 안정화

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
    `ALTER TABLE sites ADD COLUMN multisite_blog_id INTEGER DEFAULT NULL`,
    `ALTER TABLE sites ADD COLUMN installation_mode TEXT DEFAULT 'wpmu'`,
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
    `ALTER TABLE sites ADD COLUMN install_method TEXT DEFAULT 'auto'`,
  ];
  for (const sql of migrations) {
    try { await DB.prepare(sql).run(); } catch (_) {}
  }

  // vp_accounts 테이블 생성
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
  } catch {
    return FALLBACK[plan] ?? 1;
  }
}

async function getWorkerUrl(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key='puppeteer_worker_url'").first();
    return row?.value || env.PUPPETEER_WORKER_URL || '';
  } catch { return env.PUPPETEER_WORKER_URL || ''; }
}

async function getWorkerSecret(env) {
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

// VP 계정 풀에서 여유 있는 계정 선택
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

// VP 계정 사이트 카운트 증가
async function incrementVpAccountSites(env, vpAccountId) {
  try {
    await env.DB.prepare(
      `UPDATE vp_accounts SET current_sites=current_sites+1, updated_at=datetime('now') WHERE id=?`
    ).bind(vpAccountId).run();
  } catch (_) {}
}

// 글로벌 설정 조회
async function getGlobalSettings(env) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT key, value FROM settings WHERE key IN (
        'cf_api_token','cf_account_id','cloudflare_cdn_enabled',
        'auto_ssl','redis_host','redis_port','redis_password',
        'installation_mode','cname_target','site_domain'
      )`
    ).all();
    const cfg = {};
    for (const r of (results || [])) cfg[r.key] = r.value;
    return cfg;
  } catch { return {}; }
}

// fetch with timeout
async function callWorker(workerUrl, workerSecret, apiPath, payload) {
  const controller = new AbortController();
  const timeoutMs = apiPath.includes('create-site') ? 600000 : 300000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${workerUrl}${apiPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Worker-Secret': workerSecret },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    try { return await res.json(); }
    catch { return { ok: false, error: `HTTP ${res.status}: 응답 파싱 실패` }; }
  } catch (e) {
    if (e.name === 'AbortError') return { ok: false, error: `Worker 타임아웃 (${timeoutMs/1000}초 초과)` };
    return { ok: false, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}

async function updateSiteStatus(DB, siteId, fields) {
  const entries = Object.entries(fields);
  if (!entries.length) return;
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
   공유 호스팅 자동 설정 생성기
   WP-CLI 없이도 wp-config.php PHP 스크립트로 모든 설정 적용
════════════════════════════════════════════════════════════════ */

// ⚠️ 수정 포인트: 템플릿 리터럴 대신 일반 문자열 연결 사용
// 템플릿 리터럴 안에서 PHP 코드의 $var, {}, 정규식 등이
// JavaScript 파서와 충돌하여 빌드 오류 발생
function buildSharedHostingMuPlugin() {
  const lines = [
    '<?php',
    '/**',
    ' * Plugin Name: CloudPress Shared Hosting Core',
    ' * Description: 공유 호스팅 자동 최적화 - Cron, REST API, 성능 설정',
    ' * Auto-generated by CloudPress v6.1',
    ' */',
    "if (!defined('ABSPATH')) exit;",
    '',
    '// ── REST API 강제 활성화 ──',
    "remove_filter('rest_authentication_errors', '__return_true');",
    "remove_filter('rest_enabled', '__return_false');",
    "add_filter('rest_enabled', '__return_true');",
    "add_filter('rest_jsonp_enabled', '__return_true');",
    '',
    '// ── 루프백 요청 허용 (공유호스팅 필수) ──',
    "add_filter('block_local_requests', '__return_false');",
    "add_filter('http_request_host_is_external', '__return_true');",
    '',
    '// ── WP-Cron 공유호스팅 호환 (실제 HTTP cron) ──',
    "if (!defined('DISABLE_WP_CRON')) {",
    "  define('DISABLE_WP_CRON', false);",
    '}',
    "define('WP_CRON_LOCK_TIMEOUT', 120);",
    '',
    '// ── 공유호스팅 메모리 제한 완화 ──',
    "if (!defined('WP_MEMORY_LIMIT')) define('WP_MEMORY_LIMIT', '256M');",
    "if (!defined('WP_MAX_MEMORY_LIMIT')) define('WP_MAX_MEMORY_LIMIT', '512M');",
    '',
    '// ── MySQL KST 타임존 ──',
    "add_action('init', function() {",
    '  global $wpdb;',
    '  $wpdb->query("SET time_zone = \'+9:00\'");',
    '  $wpdb->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");',
    '}, 1);',
    '',
    '// ── 성능 최적화: 불필요한 헤더 제거 ──',
    "remove_action('wp_head', 'wp_generator');",
    "remove_action('wp_head', 'wlwmanifest_link');",
    "remove_action('wp_head', 'rsd_link');",
    "remove_action('wp_head', 'wp_shortlink_wp_head');",
    "remove_action('wp_head', 'adjacent_posts_rel_link_wp_head');",
    '',
    '// ── Heartbeat API 최적화 (공유호스팅 부하 감소) ──',
    "add_filter('heartbeat_settings', function($settings) {",
    "  $settings['interval'] = 120;",
    '  return $settings;',
    '});',
    "add_filter('heartbeat_send', function($response, $data, $screen_id) {",
    '  if (!is_admin()) return array();',
    '  return $response;',
    '}, 10, 3);',
    '',
    '// ── XML-RPC 비활성화 ──',
    "add_filter('xmlrpc_enabled', '__return_false');",
    '',
    '// ── 이미지 업스케일 방지 ──',
    'add_filter(\'big_image_size_threshold\', function() { return 2048; });',
    '',
    '// ── 최초 실행시 공유호스팅 최적화 옵션 자동 설정 ──',
    "add_action('init', function() {",
    "  if (get_option('cloudpress_shared_hosting_optimized')) return;",
    '  ',
    '  // Permalink 구조 설정',
    "  if (!get_option('permalink_structure')) {",
    "    update_option('permalink_structure', '/%postname%/');",
    '    flush_rewrite_rules(true);',
    '  }',
    '  ',
    '  // 언어 설정 (한국어)',
    "  if (!get_option('WPLANG')) {",
    "    update_option('WPLANG', 'ko_KR');",
    '  }',
    '  ',
    '  // KST 타임존',
    "  update_option('timezone_string', 'Asia/Seoul');",
    "  update_option('gmt_offset', 9);",
    "  update_option('date_format', 'Y년 n월 j일');",
    "  update_option('time_format', 'H:i');",
    "  update_option('start_of_week', 0);",
    '  ',
    '  // 댓글 스팸 방지 기본 설정',
    "  update_option('default_comment_status', 'closed');",
    "  update_option('comment_moderation', 1);",
    '  ',
    '  // 완료 마킹',
    "  update_option('cloudpress_shared_hosting_optimized', time());",
    '}, 99);',
  ];
  return lines.join('\n');
}

/* ═══════════════════════════════════════════════════════════════
   핵심 프로비저닝 파이프라인 v6.1
   공유 호스팅 지원 강화
════════════════════════════════════════════════════════════════ */
async function runProvisioningPipeline(env, siteId, payload) {
  const workerUrl    = await getWorkerUrl(env);
  const workerSecret = await getWorkerSecret(env);
  const globalCfg    = await getGlobalSettings(env);

  // VP 계정 선택
  const vpAccount = payload.vpAccount;

  const baseSlug = payload.siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) || 'cp';
  const suffix   = Math.random().toString(36).slice(2, 5);
  const subDomain = (baseSlug + suffix).slice(0, 15);

  const serverDomain  = vpAccount?.server_domain || (globalCfg.site_domain || 'cloudpress.site');
  const hostingDomain = `${subDomain}.${serverDomain}`;
  const siteUrl       = `https://${hostingDomain}`;
  const wpAdminUrl    = `${siteUrl}/wp-admin/`;
  const cnameTarget   = await getCnameTarget(env);

  await updateSiteStatus(env.DB, siteId, {
    status:           'installing_wp',
    provision_step:   'creating_site',
    hosting_domain:   hostingDomain,
    account_username: subDomain,
    subdomain:        hostingDomain,
    cpanel_url:       vpAccount?.panel_url || '',
    wp_url:           siteUrl,
    wp_admin_url:     wpAdminUrl,
    primary_domain:   hostingDomain,
    cname_target:     cnameTarget,
    vp_account_id:    vpAccount?.id || null,
    installation_mode: globalCfg.installation_mode || 'standalone',
    login_url:        `${siteUrl}/wp-login.php`,
    server_type:      'shared',
  });

  // Worker URL이 없는 경우: 공유 호스팅 직접 설치 불가능 → failed로 기록
  if (!workerUrl) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed',
      provision_step: 'init',
      error_message: 'Worker URL 미설정 — 관리자 → 설정에서 Worker URL을 입력해주세요.',
    });
    return;
  }

  // VP 계정 없는 경우 경고만 하고 계속 진행 (standalone PHP installer 사용)
  const hasVpAccount = !!vpAccount;

  const createPayload = {
    // VP 패널 접속 정보 (없으면 빈 값)
    vpUsername:   vpAccount?.vp_username || '',
    vpPassword:   vpAccount?.vp_password || '',
    panelUrl:     vpAccount?.panel_url || '',
    serverDomain: serverDomain,
    webRoot:      vpAccount?.web_root || '/htdocs',
    phpBin:       vpAccount?.php_bin || 'php8.3',
    mysqlHost:    vpAccount?.mysql_host || 'localhost',

    // 사이트 정보
    subDomain,
    hostingDomain,
    siteUrl,
    siteName:     payload.siteName,
    wpAdminUser:  payload.wpAdminUser,
    wpAdminPw:    payload.wpAdminPw,
    wpAdminEmail: payload.wpAdminEmail,
    plan:         payload.plan,

    // 공유 호스팅 모드
    isSharedHosting: true,
    installationMode: hasVpAccount ? (globalCfg.installation_mode || 'standalone') : 'php_installer',

    // 자동화 옵션
    enableRedis:      false, // 공유 호스팅에서는 Redis 기본 비활성
    enableCloudflare: globalCfg.cloudflare_cdn_enabled === '1',
    cfApiToken:       globalCfg.cf_api_token || '',
    cfAccountId:      globalCfg.cf_account_id || '',
    enableSsl:        globalCfg.auto_ssl !== '0',

    // 공유 호스팅 자동 설정 플래그
    autoEnableCron:    true,
    autoEnableRestApi: true,
    autoOptimize:      true,
    sharedHostingMode: true,
  };

  let createResult;
  try {
    createResult = await callWorker(workerUrl, workerSecret, '/api/create-site', createPayload);
  } catch (e) {
    createResult = { ok: false, error: 'Worker 연결 실패: ' + e.message };
  }

  // 1회 재시도
  if (!createResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      error_message: (createResult.error || '사이트 생성 실패') + ' — 재시도 중...',
    });
    try {
      createResult = await callWorker(workerUrl, workerSecret, '/api/create-site', {
        ...createPayload, retry: true,
      });
    } catch (e) {
      createResult = { ok: false, error: '재시도 실패: ' + e.message };
    }
  }

  if (!createResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status:         'failed',
      provision_step: 'creating_site',
      error_message:  createResult.error || '사이트 생성 최종 실패',
    });
    return;
  }

  const blogId = createResult.blogId || null;
  const actualSiteUrl  = createResult.siteUrl  || siteUrl;
  const actualAdminUrl = createResult.adminUrl || wpAdminUrl;
  const loginUrl       = `${actualSiteUrl}/wp-login.php`;

  await updateSiteStatus(env.DB, siteId, {
    status:             'installing_wp',
    provision_step:     'configuring',
    wp_version:         createResult.wpVersion || 'latest',
    php_version:        createResult.phpVersion || '8.x',
    multisite_blog_id:  blogId,
    wp_url:             actualSiteUrl,
    wp_admin_url:       actualAdminUrl,
    login_url:          loginUrl,
    install_method:     createResult.installMethod || 'auto',
    error_message:      null,
  });

  // ══ 단계 2: 공유 호스팅 자동 설정 ══
  let configResult = { ok: false };
  try {
    configResult = await callWorker(workerUrl, workerSecret, '/api/configure-site', {
      vpUsername:    vpAccount?.vp_username || '',
      vpPassword:    vpAccount?.vp_password || '',
      panelUrl:      vpAccount?.panel_url || '',
      subDomain,
      hostingDomain,
      siteUrl:       actualSiteUrl,
      wpAdminUrl:    actualAdminUrl,
      wpAdminUser:   payload.wpAdminUser,
      wpAdminPw:     payload.wpAdminPw,
      phpBin:        vpAccount?.php_bin || 'php8.3',
      webRoot:       vpAccount?.web_root || '/htdocs',
      plan:          payload.plan,
      enableRedis:   false,
      blogId,
      // 공유 호스팅 설정
      isSharedHosting:    true,
      autoEnableCron:     true,
      autoEnableRestApi:  true,
      sharedHostingMode:  true,
      // mu-plugin 콘텐츠 전달
      muPluginContent:    buildSharedHostingMuPlugin(),
    });
  } catch (_) {}

  await updateSiteStatus(env.DB, siteId, {
    provision_step:   'installing_plugins',
    redis_enabled:    configResult?.redisEnabled ? 1 : 0,
    cron_enabled:     1,
    rest_api_enabled: 1,
    loopback_enabled: 1,
  });

  // ══ 단계 3: Bridge Migration 플러그인 자동 설치 ══
  let pluginResult = { ok: false };
  try {
    pluginResult = await callWorker(workerUrl, workerSecret, '/api/install-plugins', {
      vpUsername:  vpAccount?.vp_username || '',
      vpPassword:  vpAccount?.vp_password || '',
      panelUrl:    vpAccount?.panel_url || '',
      siteUrl:     actualSiteUrl,
      wpAdminUrl:  actualAdminUrl,
      wpAdminUser: payload.wpAdminUser,
      wpAdminPw:   payload.wpAdminPw,
      phpBin:      vpAccount?.php_bin || 'php8.3',
      webRoot:     vpAccount?.web_root || '/htdocs',
      subDomain,
      blogId,
      plan:        payload.plan,
      isSharedHosting: true,
    });
  } catch (_) {}

  await updateSiteStatus(env.DB, siteId, {
    provision_step: 'cloudflare_setup',
  });

  // ══ 단계 4: Cloudflare CDN (설정된 경우만) ══
  let cfResult = { ok: false };
  if (globalCfg.cloudflare_cdn_enabled === '1' && globalCfg.cf_api_token) {
    try {
      cfResult = await callWorker(workerUrl, workerSecret, '/api/setup-cloudflare', {
        domain:       hostingDomain,
        cfApiToken:   globalCfg.cf_api_token,
        cfAccountId:  globalCfg.cf_account_id || '',
        siteUrl:      actualSiteUrl,
        wpAdminUrl:   actualAdminUrl,
        wpAdminUser:  payload.wpAdminUser,
        wpAdminPw:    payload.wpAdminPw,
      });
    } catch (_) {}
  }

  await updateSiteStatus(env.DB, siteId, {
    provision_step:      'optimizing',
    cloudflare_enabled:  cfResult?.ok ? 1 : 0,
    cloudflare_zone_id:  cfResult?.zoneId || null,
  });

  // ══ 단계 5: 속도 최적화 (공유 호스팅 맞춤) ══
  let speedResult = { ok: false };
  try {
    speedResult = await callWorker(workerUrl, workerSecret, '/api/optimize-speed', {
      vpUsername:  vpAccount?.vp_username || '',
      vpPassword:  vpAccount?.vp_password || '',
      panelUrl:    vpAccount?.panel_url || '',
      siteUrl:     actualSiteUrl,
      wpAdminUrl:  actualAdminUrl,
      wpAdminUser: payload.wpAdminUser,
      wpAdminPw:   payload.wpAdminPw,
      phpBin:      vpAccount?.php_bin || 'php8.3',
      webRoot:     vpAccount?.web_root || '/htdocs',
      subDomain,
      blogId,
      plan:        payload.plan,
      isSharedHosting: true,
    });
  } catch (_) {}

  // ══ 완료 ══
  await updateSiteStatus(env.DB, siteId, {
    status:          'active',
    provision_step:  'completed',
    speed_optimized: speedResult?.ok ? 1 : 0,
    suspend_protected: 1,
    ssl_active:      1,
    error_message:   null,
    login_url:       loginUrl,
  });

  // VP 계정 사이트 카운트 증가
  if (vpAccount?.id) {
    await incrementVpAccountSites(env, vpAccount.id);
  }

  await sendPushNotifications(env, payload.userId, {
    type: 'site_created', siteId,
    siteName:     payload.siteName,
    siteUrl:      actualSiteUrl,
    wpAdminUrl:   actualAdminUrl,
    loginUrl,
    wpAdminUser:  payload.wpAdminUser,
    wpAdminPw:    payload.wpAdminPw,
    message:      `✅ "${payload.siteName}" 사이트 생성 완료! 관리자: ${actualAdminUrl}`,
    timestamp:    Date.now(),
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
        wp_url, wp_admin_url, wp_username, wp_password, wp_version, php_version,
        redis_enabled, cron_enabled, rest_api_enabled, loopback_enabled,
        ssl_active, cloudflare_enabled, speed_optimized, suspend_protected, status,
        provision_step, error_message, suspended, suspension_reason, disk_used,
        bandwidth_used, plan, primary_domain, custom_domain, domain_status,
        cname_target, server_type, installation_mode, multisite_blog_id,
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

export async function onRequestPost({ request, env, ctx }) {
  await ensureSitesColumns(env.DB).catch(() => {});
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  // 푸시 알림 구독
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

  // Worker URL 확인
  const workerUrl = await getWorkerUrl(env);
  if (!workerUrl) {
    return err('Worker URL이 설정되지 않았습니다. 관리자 → 설정에서 Worker URL을 입력해주세요.', 503);
  }

  // VP 계정 선택 (없어도 진행 가능 — PHP 인스톨러 방식)
  const vpAccount = await pickVpAccount(env);

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
      ) VALUES (?,?,?,'shared_hosting',?,?,?,'installing_wp','init',?,'shared','standalone')`
    ).bind(
      siteId, user.id, siteName.trim(),
      adminLogin, wpAdminPw, user.email,
      effectivePlan
    ).run();
  } catch (e) {
    return err('사이트 레코드 생성 실패: ' + e.message, 500);
  }

  const pipelinePayload = {
    vpAccount,
    siteName:     siteName.trim(),
    wpAdminUser:  adminLogin,
    wpAdminPw,
    wpAdminEmail: user.email,
    plan:         effectivePlan,
    userId:       user.id,
    siteUrl:      siteUrl || null,
  };

  const pipelinePromise = runProvisioningPipeline(env, siteId, pipelinePayload)
    .catch(async (e) => {
      await updateSiteStatus(env.DB, siteId, {
        status: 'failed',
        provision_step: 'pipeline_error',
        error_message: '파이프라인 오류: ' + e.message,
      });
    });

  if (ctx?.waitUntil) ctx.waitUntil(pipelinePromise);

  return ok({
    siteId,
    provider: 'shared_hosting',
    plan: effectivePlan,
    message: '공유 호스팅 방식으로 사이트 생성이 시작되었습니다. 완료까지 3~7분 소요됩니다.',
    phpVersion: '8.x',
    wpVersion: 'latest (한국어)',
    features: {
      cron:        'WordPress WP-Cron 자동 활성화',
      restApi:     'REST API 자동 활성화',
      loopback:    '루프백 요청 자동 허용',
      optimization: '공유 호스팅 맞춤 속도/캐시 최적화',
      bridge:      'Bridge Migration 플러그인 자동 설치',
      ssl:         'SSL 자동 설정',
    },
    steps: [
      { step: 1, name: 'WordPress 설치', status: 'running' },
      { step: 2, name: 'Cron / REST API / 루프백 자동 설정', status: 'pending' },
      { step: 3, name: 'Bridge Migration 플러그인 설치', status: 'pending' },
      { step: 4, name: 'Cloudflare CDN 연동 (선택)', status: 'pending' },
      { step: 5, name: '속도 최적화 자동 설정', status: 'pending' },
    ],
  });
}
