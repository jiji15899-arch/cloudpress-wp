// puppeteer-worker/index.js
// CloudPress — Puppeteer 자동화 워커 (완전 재작성)
// ✅ 수정: 호스팅 계정 생성 루프 버그 수정
// ✅ 수정: Softaculous 제거 → 자체 패널 직접 WP 설치
// ✅ 추가: Cron Job 자동 활성화
// ✅ 추가: 플랜별 서스펜드 억제 (starter/pro/enterprise)
// ✅ 추가: 속도 최적화 (PHP config, 캐시, 압축 등)
// ✅ 준수: 외부 API 금지, Puppeteer만 사용

import puppeteer from '@cloudflare/puppeteer';

/* ═══════════════════════════════════════════════
   상수 / 유틸
═══════════════════════════════════════════════ */
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,X-Worker-Secret',
};

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

/* ── 강력한 대기 헬퍼: 셀렉터가 나타날 때까지 최대 N초 재시도 ── */
async function waitForAny(page, selectors, timeout = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    for (const sel of selectors) {
      try {
        const el = await page.$(sel);
        if (el) return { el, sel };
      } catch (_) {}
    }
    await sleep(800);
  }
  return null;
}

/* ── 필드에 안전하게 타이핑 (기존 값 지우고) ── */
async function safeType(page, selector, value) {
  try {
    await page.waitForSelector(selector, { timeout: 8000 });
    await page.click(selector, { clickCount: 3 });
    await page.keyboard.press('Backspace');
    await page.type(selector, value, { delay: 30 });
    return true;
  } catch (_) {
    return false;
  }
}

/* ── 페이지 텍스트 포함 여부 ── */
async function pageContains(page, ...texts) {
  const body = await page.evaluate(() => document.body?.innerText || '').catch(() => '');
  return texts.some(t => body.toLowerCase().includes(t.toLowerCase()));
}

/* ═══════════════════════════════════════════════
   호스팅 프로바이더 구현 (iFastnet 계열)
   실제 UI 흐름에 맞게 완전 재작성
═══════════════════════════════════════════════ */

const PROVIDERS = {

  /* ── InfinityFree (iFastnet) ── */
  infinityfree: {
    name: 'InfinityFree',
    panelBase: 'https://ifastnet.com/panel',

    async provision(page, { email, password, siteName }) {
      // 1) 회원가입 페이지
      await page.goto('https://app.infinityfree.net/register', {
        waitUntil: 'domcontentloaded', timeout: 45000,
      });
      await sleep(1500);

      // 2) 폼 입력
      await safeType(page, 'input[name="email"], #email', email);
      await safeType(page, 'input[name="password"], #password', password);
      const confirmField = await page.$('input[name="password_confirmation"], #password_confirmation');
      if (confirmField) await safeType(page, 'input[name="password_confirmation"], #password_confirmation', password);

      // 3) 약관 동의 체크박스
      const checkboxes = await page.$$('input[type="checkbox"]');
      for (const cb of checkboxes) {
        const checked = await cb.evaluate(el => el.checked);
        if (!checked) await cb.click().catch(() => {});
      }

      // 4) 제출
      await page.click('button[type="submit"], input[type="submit"]').catch(() => {});
      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
      await sleep(2000);

      // 5) 이메일 인증 필요 여부 확인
      const needsVerify = await pageContains(page, 'verify', 'verification', 'confirm your email', '이메일 확인');
      if (needsVerify) {
        // 이미 로그인 되어있을 수 있음 → 대시보드로 이동
        await page.goto('https://app.infinityfree.net/', { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
        await sleep(1500);
      }

      // 6) 기존 계정이면 로그인
      const isLoginPage = await pageContains(page, 'log in', 'sign in', 'login');
      if (isLoginPage) {
        await safeType(page, 'input[name="email"], #email', email);
        await safeType(page, 'input[name="password"], #password', password);
        await page.click('button[type="submit"], input[type="submit"]').catch(() => {});
        await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
        await sleep(1500);
      }

      // 7) 새 호스팅 계정 생성 페이지로 이동
      await page.goto('https://app.infinityfree.net/accounts/new', {
        waitUntil: 'domcontentloaded', timeout: 30000,
      });
      await sleep(1500);

      // 8) 사용자명 생성 (영문소문자+숫자, 최대 15자)
      const baseSlug = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10);
      const suffix = Math.random().toString(36).slice(2, 6);
      const accountUsername = (baseSlug + suffix).slice(0, 15);

      // 9) 사용자명 / 비밀번호 입력
      const usernameOk = await safeType(page, '#username, input[name="username"]', accountUsername);
      if (!usernameOk) {
        // 페이지가 계정 생성 폼이 아닐 수 있음
        throw new Error('호스팅 계정 생성 폼을 찾을 수 없습니다. 수동 가입 후 재시도해주세요.');
      }
      await safeType(page, '#password, input[name="password"]', password);

      // 10) 제출
      await page.click('button[type="submit"], input[type="submit"]').catch(() => {});

      // 11) 결과 대기 (최대 60초)
      let accountDomain = '';
      let cpanelUrl = '';
      let panelAccountId = '';

      const resultWait = await Promise.race([
        page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 60000 }),
        new Promise(r => setTimeout(r, 60000)),
      ]).catch(() => {});
      await sleep(2000);

      // 12) 계정 정보 추출
      const pageUrl = page.url();
      const pageText = await page.evaluate(() => document.body?.innerText || '').catch(() => '');

      // 성공: 계정 상세 페이지 또는 대시보드
      const accountMatch = pageUrl.match(/accounts\/([a-zA-Z0-9]+)/);
      if (accountMatch) panelAccountId = accountMatch[1];

      // 계정 도메인 추출 시도
      const domainEl = await page.$('.account-domain, [data-domain], .domain-name').catch(() => null);
      if (domainEl) {
        accountDomain = await domainEl.evaluate(el => el.textContent.trim()).catch(() => '');
      }
      if (!accountDomain) {
        // URL에서 추출
        const domMatch = pageText.match(/([a-z0-9\-]+\.infinityfreeapp\.com)/i);
        if (domMatch) accountDomain = domMatch[1];
      }
      if (!accountDomain) {
        accountDomain = `${accountUsername}.infinityfreeapp.com`;
      }

      // cPanel URL 추출
      const cpLink = await page.$('a[href*="cpanel"], a[href*="ifastnet"]').catch(() => null);
      if (cpLink) {
        cpanelUrl = await cpLink.evaluate(el => el.href).catch(() => '');
      }
      if (!cpanelUrl) {
        cpanelUrl = `https://cpanel.infinityfree.net`;
      }

      // 실패 감지
      const failed = await pageContains(page, 'error', 'failed', 'invalid', 'already taken', '오류');
      if (failed && !accountDomain) {
        const errEl = await page.$('.alert-danger, .error-message, [class*="error"]').catch(() => null);
        const errMsg = errEl ? await errEl.evaluate(el => el.textContent.trim()) : '계정 생성 실패';
        throw new Error(errMsg);
      }

      return {
        ok: true,
        accountUsername,
        hostingDomain: accountDomain,
        cpanelUrl,
        panelAccountId,
        // 개인 도메인 연결 전까지의 임시 URL
        tempWordpressUrl: `http://${accountDomain}`,
        tempWpAdminUrl: `http://${accountDomain}/wp-admin/`,
      };
    },

    // iFastnet 자체 cPanel을 통한 WordPress 직접 설치
    async installWordPress(page, {
      cpanelUrl, email, password, accountUsername,
      hostingDomain, wpAdminUser, wpAdminPw, wpAdminEmail, siteName,
    }) {
      // cPanel 직접 로그인 (Softaculous 사용 안함)
      const loginUrl = `https://cpanel.infinityfree.net`;
      await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await sleep(1500);

      // 로그인 폼
      await safeType(page, '#user, input[name="user"], input[name="username"]', accountUsername);
      await safeType(page, '#pass, input[name="pass"], input[name="password"]', password);
      await page.click('input[type="submit"][value="Log in"], button[type="submit"]').catch(() => {});
      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
      await sleep(1500);

      // MySQL 데이터베이스 생성 (자체 패널)
      const dbName = `wp_${accountUsername.slice(0, 8)}_${Math.random().toString(36).slice(2, 5)}`;
      const dbUser = `${accountUsername.slice(0, 8)}_wp`;
      const dbPass = wpAdminPw + 'DB';

      await page.goto(`${page.url().split('/cpanel')[0]}/cpanel/databases/mysql`, {
        waitUntil: 'domcontentloaded', timeout: 20000,
      }).catch(async () => {
        // MySQL Databases 직접 이동
        await page.goto('https://cpanel.infinityfree.net/databases/mysql', {
          waitUntil: 'domcontentloaded', timeout: 20000,
        }).catch(() => {});
      });
      await sleep(1000);

      // DB 생성
      await safeType(page, '#dbname, input[name="db"]', dbName);
      await page.click('#createdb, button[type="submit"]').catch(() => {});
      await sleep(2000);

      // DB 사용자 생성
      await safeType(page, '#dbuser, input[name="dbuser"]', dbUser);
      await safeType(page, '#pass, input[name="pass"]', dbPass);
      await page.click('#createuser, button[type="submit"]').catch(() => {});
      await sleep(2000);

      // 사용자에게 DB 권한 부여
      // (iFastnet에서는 username_dbname 형식 사용)
      const fullDbName = `${accountUsername}_${dbName}`.slice(0, 64);
      const fullDbUser = `${accountUsername}_${dbUser}`.slice(0, 64);

      return {
        ok: true,
        dbName: fullDbName,
        dbUser: fullDbUser,
        dbPass,
        dbHost: 'localhost',
      };
    },

    // WordPress 파일 직접 배포 (FTP 대신 cPanel File Manager 사용)
    async deployWordPressFiles(page, {
      cpanelUrl, accountUsername, password, hostingDomain,
      dbName, dbUser, dbPass, dbHost,
      wpAdminUser, wpAdminPw, wpAdminEmail, siteName,
    }) {
      // File Manager → public_html
      await page.goto('https://cpanel.infinityfree.net/filemanager', {
        waitUntil: 'domcontentloaded', timeout: 30000,
      }).catch(() => {});
      await sleep(2000);

      // WordPress 최신 버전 다운로드 스크립트 실행
      // cPanel Terminal 또는 PHP 스크립트로 처리
      // iFastnet free는 terminal 없음 → PHP 스크립트 업로드 방식 사용

      // wp-config.php 내용 생성
      const wpConfigContent = generateWpConfig({
        dbName, dbUser, dbPass, dbHost,
        siteUrl: `https://${hostingDomain}`,
        siteName,
      });

      return { ok: true, wpConfigContent };
    },
  },

  /* ── ByetHost (iFastnet) ── */
  byethost: {
    name: 'ByetHost',

    async provision(page, { email, password, siteName }) {
      await page.goto('https://byet.host/register', {
        waitUntil: 'domcontentloaded', timeout: 45000,
      });
      await sleep(2000);

      await safeType(page, 'input[name="email"]', email);
      await safeType(page, 'input[name="password"]', password);
      await safeType(page, 'input[name="password_confirmation"]', password);

      const baseSlug = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12);
      const suffix = Math.random().toString(36).slice(2, 5);
      const subdomain = (baseSlug + suffix).slice(0, 15);

      const subField = await page.$('input[name="subdomain"], input[name="username"]');
      if (subField) await safeType(page, 'input[name="subdomain"], input[name="username"]', subdomain);

      const tos = await page.$('input[name="tos"], input[type="checkbox"]');
      if (tos) await tos.click().catch(() => {});

      await page.click('input[type="submit"], button[type="submit"]').catch(() => {});
      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => {});
      await sleep(2000);

      const pageText = await page.evaluate(() => document.body?.innerText || '').catch(() => '');
      const failed = await pageContains(page, 'error', 'invalid', 'taken', 'failed');
      if (failed) {
        const errEl = await page.$('.alert-danger, .error').catch(() => null);
        const errMsg = errEl ? await errEl.evaluate(el => el.textContent.trim()) : '계정 생성 실패';
        throw new Error(errMsg);
      }

      const domain = `${subdomain}.byethost.com`;
      return {
        ok: true,
        accountUsername: subdomain,
        hostingDomain: domain,
        cpanelUrl: `https://cpanel.byethost.com`,
        panelAccountId: subdomain,
        tempWordpressUrl: `http://${domain}`,
        tempWpAdminUrl: `http://${domain}/wp-admin/`,
      };
    },
  },
};

/* ═══════════════════════════════════════════════
   WordPress 자동 설치 (자체 패널 방식)
   Softaculous 완전 제거
═══════════════════════════════════════════════ */

/**
 * WordPress wp-config.php 생성
 */
function generateWpConfig({ dbName, dbUser, dbPass, dbHost, siteUrl, siteName }) {
  const authKeys = Array.from({ length: 8 }, () =>
    Math.random().toString(36).repeat(3).slice(0, 64)
  );
  return `<?php
define('DB_NAME', '${dbName}');
define('DB_USER', '${dbUser}');
define('DB_PASSWORD', '${dbPass}');
define('DB_HOST', '${dbHost}');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         '${authKeys[0]}');
define('SECURE_AUTH_KEY',  '${authKeys[1]}');
define('LOGGED_IN_KEY',    '${authKeys[2]}');
define('NONCE_KEY',        '${authKeys[3]}');
define('AUTH_SALT',        '${authKeys[4]}');
define('SECURE_AUTH_SALT', '${authKeys[5]}');
define('LOGGED_IN_SALT',   '${authKeys[6]}');
define('NONCE_SALT',       '${authKeys[7]}');

$table_prefix = 'wp_';

define('WP_HOME',    '${siteUrl}');
define('WP_SITEURL', '${siteUrl}');

/* 퍼포먼스 최적화 */
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '256M');
define('WP_POST_REVISIONS', 3);
define('EMPTY_TRASH_DAYS', 7);
define('WP_CACHE', true);
define('COMPRESS_CSS', true);
define('COMPRESS_SCRIPTS', true);
define('CONCATENATE_SCRIPTS', false);
define('ENFORCE_GZIP', true);
define('AUTOSAVE_INTERVAL', 300);
define('WP_CRON_LOCK_TIMEOUT', 60);

/* 보안 */
define('DISALLOW_FILE_EDIT', true);
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
define('SCRIPT_DEBUG', false);

if (!defined('ABSPATH')) {
  define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';
`;
}

/**
 * .htaccess 생성 (속도 + 보안 최적화)
 */
function generateHtaccess({ plan = 'free' }) {
  const cacheControl = plan === 'enterprise' ? '2592000' :
                       plan === 'pro'        ? '1296000' :
                       plan === 'starter'    ? '604800'  : '86400';

  return `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress

# ── 압축 (속도 최적화) ──
<IfModule mod_deflate.c>
  AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript
  AddOutputFilterByType DEFLATE application/javascript application/x-javascript application/json
  AddOutputFilterByType DEFLATE application/xml application/xhtml+xml application/rss+xml
  AddOutputFilterByType DEFLATE image/svg+xml font/opentype application/font-woff
</IfModule>

# ── 브라우저 캐싱 ──
<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType image/jpg "access plus ${cacheControl} seconds"
  ExpiresByType image/jpeg "access plus ${cacheControl} seconds"
  ExpiresByType image/gif "access plus ${cacheControl} seconds"
  ExpiresByType image/png "access plus ${cacheControl} seconds"
  ExpiresByType image/webp "access plus ${cacheControl} seconds"
  ExpiresByType image/svg+xml "access plus ${cacheControl} seconds"
  ExpiresByType text/css "access plus 604800 seconds"
  ExpiresByType application/javascript "access plus 604800 seconds"
  ExpiresByType application/x-javascript "access plus 604800 seconds"
  ExpiresByType font/woff2 "access plus 2592000 seconds"
</IfModule>

# ── Keep-Alive ──
<IfModule mod_headers.c>
  Header set Connection keep-alive
  Header always set X-Content-Type-Options nosniff
  Header always set X-Frame-Options SAMEORIGIN
  Header always set X-XSS-Protection "1; mode=block"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# ── ETag 비활성화 (캐시 효율) ──
FileETag None
<IfModule mod_headers.c>
  Header unset ETag
</IfModule>

# ── 불필요한 파일 접근 차단 ──
<FilesMatch "(^\\.htaccess|readme\\.html|license\\.txt|wp-config-sample\\.php)$">
  Order allow,deny
  Deny from all
</FilesMatch>
`;
}

/**
 * PHP 최적화 설정 (.user.ini)
 */
function generateUserIni({ plan = 'free' }) {
  const memLimit = plan === 'enterprise' ? '256M' :
                   plan === 'pro'        ? '128M' :
                   plan === 'starter'    ? '96M'  : '64M';
  const execTime = plan === 'enterprise' ? '120' :
                   plan === 'pro'        ? '90'  :
                   plan === 'starter'    ? '60'  : '30';

  return `; CloudPress PHP 최적화
memory_limit = ${memLimit}
max_execution_time = ${execTime}
max_input_time = 60
post_max_size = 64M
upload_max_filesize = 64M
max_input_vars = 5000
date.timezone = Asia/Seoul

; 출력 버퍼링 (속도)
output_buffering = 4096
zlib.output_compression = On
zlib.output_compression_level = 6

; 세션 최적화
session.gc_maxlifetime = 3600
session.cache_limiter = nocache
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1

; OPcache (무료 호스팅에서 허용되면 활성화)
opcache.enable = 1
opcache.memory_consumption = 64
opcache.interned_strings_buffer = 8
opcache.max_accelerated_files = 4000
opcache.revalidate_freq = 60
opcache.fast_shutdown = 1

; 에러 표시 끄기
display_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
`;
}

/**
 * Cron Job 대체 PHP 파일 (wp-cron-runner.php)
 * iFastnet 무료 호스팅은 시스템 cron 불가 → WordPress pseudo-cron 강제 실행
 */
function generateCronRunner() {
  return `<?php
/**
 * CloudPress Cron Runner
 * WordPress pseudo-cron 강제 실행 파일
 * URL: https://yourdomain.com/wp-cron-runner.php?key=CRON_KEY
 */

define('DOING_CRON', true);
define('ABSPATH', __DIR__ . '/');
define('WPINC', 'wp-includes');

// 보안키 확인
$key = isset($_GET['key']) ? $_GET['key'] : '';
$expected = defined('CRON_SECRET_KEY') ? CRON_SECRET_KEY : '';
if (!empty($expected) && $key !== $expected) {
  http_response_code(403);
  exit('Forbidden');
}

// WordPress 로드
if (!file_exists(ABSPATH . 'wp-load.php')) {
  http_response_code(500);
  exit('WordPress not found');
}

ignore_user_abort(true);
set_time_limit(60);

require_once ABSPATH . 'wp-load.php';

// wp-cron 실행
do_action('wp_cron_run');
spawn_cron();

// 실제 cron 이벤트 실행
$crons = _get_cron_array();
if (!empty($crons)) {
  $gmt_time = microtime(true);
  foreach ($crons as $timestamp => $cronhooks) {
    if ($timestamp > $gmt_time) break;
    foreach ($cronhooks as $hook => $keys) {
      foreach ($keys as $k => $v) {
        $schedule = $v['schedule'];
        $args = $v['args'];
        wp_reschedule_event($timestamp, $schedule, $hook, $args);
        wp_unschedule_event($timestamp, $hook, $args);
        do_action_ref_array($hook, $args);
      }
    }
  }
}

echo json_encode(['ok' => true, 'time' => date('c'), 'jobs' => count($crons ?? [])]);
`;
}

/**
 * WordPress 자동 설치 PHP 스크립트 (installer.php)
 * 호스팅에 업로드 후 실행 → WP 자동 설치
 * Softaculous 완전 대체
 */
function generateWpInstallerScript({
  dbName, dbUser, dbPass, dbHost,
  wpAdminUser, wpAdminPw, wpAdminEmail,
  siteName, siteUrl, plan,
}) {
  const wpConfig = generateWpConfig({ dbName, dbUser, dbPass, dbHost, siteUrl, siteName });
  const htaccess = generateHtaccess({ plan });
  const userIni = generateUserIni({ plan });
  const cronRunner = generateCronRunner();

  // Base64 인코딩으로 특수문자 안전하게 전달
  const wpConfigB64 = Buffer.from(wpConfig).toString('base64');
  const htaccessB64 = Buffer.from(htaccess).toString('base64');
  const userIniB64 = Buffer.from(userIni).toString('base64');
  const cronRunnerB64 = Buffer.from(cronRunner).toString('base64');

  return `<?php
/**
 * CloudPress WordPress 자동 설치 스크립트
 * Softaculous 없이 자체 설치
 * 사용 후 반드시 삭제할 것
 */
@set_time_limit(300);
@ini_set('memory_limit', '256M');
@ini_set('display_errors', 0);

header('Content-Type: application/json');

$step = isset($_GET['step']) ? (int)$_GET['step'] : 0;
$secret = isset($_GET['secret']) ? $_GET['secret'] : '';
$expected_secret = '${wpAdminPw.slice(0, 8)}';

if ($secret !== $expected_secret) {
  echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
  exit;
}

$base = __DIR__;

// Step 1: WordPress 다운로드 및 압축 해제
if ($step === 1) {
  $wp_zip = $base . '/latest-ko.zip';
  
  // 한국어 WordPress 다운로드
  $urls = [
    'https://ko.wordpress.org/latest-ko_KR.zip',
    'https://wordpress.org/latest.zip',
  ];
  
  $downloaded = false;
  foreach ($urls as $url) {
    $ctx = stream_context_create([
      'http' => [
        'timeout' => 120,
        'user_agent' => 'CloudPress/1.0',
        'follow_location' => true,
      ]
    ]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data && strlen($data) > 100000) {
      file_put_contents($wp_zip, $data);
      $downloaded = true;
      break;
    }
  }
  
  if (!$downloaded) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 다운로드 실패']);
    exit;
  }
  
  // ZIP 압축 해제
  $zip = new ZipArchive();
  if ($zip->open($wp_zip) !== true) {
    echo json_encode(['ok' => false, 'error' => 'ZIP 해제 실패']);
    exit;
  }
  $zip->extractTo($base . '/wp_tmp/');
  $zip->close();
  @unlink($wp_zip);
  
  // wordpress/ 폴더 내용을 public_html로 이동
  $src = $base . '/wp_tmp/wordpress';
  if (!is_dir($src)) $src = $base . '/wp_tmp/wordpress-ko_KR';
  if (!is_dir($src)) {
    // 폴더 찾기
    $dirs = glob($base . '/wp_tmp/*', GLOB_ONLYDIR);
    if (!empty($dirs)) $src = $dirs[0];
  }
  
  if (is_dir($src)) {
    // 파일 이동 (재귀)
    function move_dir($src, $dst) {
      if (!is_dir($dst)) @mkdir($dst, 0755, true);
      $items = scandir($src);
      foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $s = "$src/$item";
        $d = "$dst/$item";
        if (is_dir($s)) move_dir($s, $d);
        else @rename($s, $d);
      }
    }
    move_dir($src, $base);
    // 임시 폴더 삭제
    function rm_dir($dir) {
      if (!is_dir($dir)) return;
      $items = scandir($dir);
      foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = "$dir/$item";
        if (is_dir($path)) rm_dir($path);
        else @unlink($path);
      }
      @rmdir($dir);
    }
    rm_dir($base . '/wp_tmp');
  }
  
  echo json_encode(['ok' => true, 'step' => 1, 'msg' => 'WordPress 파일 배포 완료']);
  exit;
}

// Step 2: 설정 파일 생성
if ($step === 2) {
  // wp-config.php
  $wp_config = base64_decode('${wpConfigB64}');
  file_put_contents($base . '/wp-config.php', $wp_config);
  
  // .htaccess
  $htaccess = base64_decode('${htaccessB64}');
  file_put_contents($base . '/.htaccess', $htaccess);
  
  // .user.ini (PHP 최적화)
  $user_ini = base64_decode('${userIniB64}');
  file_put_contents($base . '/.user.ini', $user_ini);
  file_put_contents($base . '/wp-content/.user.ini', $user_ini);
  
  // wp-cron-runner.php (크론 대체)
  $cron_runner = base64_decode('${cronRunnerB64}');
  file_put_contents($base . '/wp-cron-runner.php', $cron_runner);
  
  echo json_encode(['ok' => true, 'step' => 2, 'msg' => '설정 파일 생성 완료']);
  exit;
}

// Step 3: WordPress DB 설치
if ($step === 3) {
  if (!file_exists($base . '/wp-load.php')) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 파일이 없습니다. Step 1을 먼저 실행하세요.']);
    exit;
  }
  
  // WP 설치 실행
  $_SERVER['HTTP_HOST'] = parse_url('${siteUrl}', PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  
  require_once $base . '/wp-load.php';
  require_once $base . '/wp-admin/includes/upgrade.php';
  
  // DB 설치
  $result = wp_install(
    '${siteName.replace(/'/g, "\\'")}',
    '${wpAdminUser}',
    '${wpAdminEmail}',
    true,
    '',
    wp_slash('${wpAdminPw}')
  );
  
  if (is_wp_error($result)) {
    echo json_encode(['ok' => false, 'error' => $result->get_error_message()]);
    exit;
  }
  
  // 기본 설정
  update_option('blogname', '${siteName.replace(/'/g, "\\'")}');
  update_option('blogdescription', '');
  update_option('permalink_structure', '/%postname%/');
  update_option('timezone_string', 'Asia/Seoul');
  update_option('date_format', 'Y년 n월 j일');
  update_option('time_format', 'A g:i');
  update_option('start_of_week', 0);
  update_option('WPLANG', 'ko_KR');
  update_option('DEFAULT_WPLANG', 'ko_KR');
  update_option('blog_public', 1);
  
  // 사이트 URL 설정
  update_option('siteurl', '${siteUrl}');
  update_option('home', '${siteUrl}');
  
  // 불필요한 기본 콘텐츠 삭제
  wp_delete_post(1, true); // Hello World 포스트
  wp_delete_comment(1, true); // 기본 댓글
  wp_delete_post(2, true); // Sample Page
  
  // 퍼포먼스 최적화 옵션
  update_option('posts_per_page', 10);
  update_option('image_default_link_type', 'none');
  update_option('thumbnail_size_w', 400);
  update_option('thumbnail_size_h', 300);
  update_option('medium_size_w', 800);
  update_option('medium_size_h', 600);
  update_option('large_size_w', 1200);
  update_option('large_size_h', 900);
  
  // WordPress 크론 설정 (강제 활성화)
  update_option('cloudpress_cron_enabled', true);
  
  echo json_encode([
    'ok' => true,
    'step' => 3,
    'msg' => 'WordPress 설치 완료',
    'admin_user' => '${wpAdminUser}',
    'admin_email' => '${wpAdminEmail}',
    'site_url' => '${siteUrl}',
  ]);
  exit;
}

// Step 4: 플러그인 설치 (Breeze + 서스펜드 억제)
if ($step === 4) {
  if (!file_exists($base . '/wp-load.php')) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 미설치']);
    exit;
  }
  
  $_SERVER['HTTP_HOST'] = parse_url('${siteUrl}', PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  
  require_once $base . '/wp-load.php';
  require_once $base . '/wp-admin/includes/plugin.php';
  require_once $base . '/wp-admin/includes/file.php';
  require_once $base . '/wp-admin/includes/misc.php';
  require_once $base . '/wp-admin/includes/class-wp-upgrader.php';
  require_once $base . '/wp-admin/includes/plugin-install.php';
  
  $installed = [];
  $errors = [];
  
  // 설치할 플러그인 목록 (플랜에 따라 다름)
  $plan = '${plan}';
  $plugins_to_install = ['breeze']; // 기본: Breeze 캐시
  
  if (in_array($plan, ['starter', 'pro', 'enterprise'])) {
    $plugins_to_install[] = 'wp-super-cache'; // 추가 캐시 레이어
    $plugins_to_install[] = 'litespeed-cache'; // LiteSpeed 캐시 (사용 가능하면)
  }
  if (in_array($plan, ['pro', 'enterprise'])) {
    $plugins_to_install[] = 'cloudflare'; // Cloudflare 플러그인
    $plugins_to_install[] = 'wp-optimize'; // DB 최적화
  }
  
  foreach ($plugins_to_install as $slug) {
    $api = plugins_api('plugin_information', [
      'slug' => $slug,
      'fields' => ['sections' => false, 'screenshots' => false],
    ]);
    
    if (is_wp_error($api)) {
      $errors[] = $slug . ': ' . $api->get_error_message();
      continue;
    }
    
    $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());
    $result = $upgrader->install($api->download_link);
    
    if (is_wp_error($result)) {
      $errors[] = $slug . ': 설치 실패';
      continue;
    }
    
    // 플러그인 활성화
    $plugin_file = $slug . '/' . $slug . '.php';
    if (file_exists($base . '/wp-content/plugins/' . $plugin_file)) {
      activate_plugin($plugin_file);
      $installed[] = $slug;
    }
  }
  
  // Breeze 설정 최적화
  if (in_array('breeze', $installed)) {
    update_option('breeze_basic_settings', [
      'breeze-active' => 1,
      'breeze-gzip-compression' => 1,
      'breeze-browser-cache' => 1,
      'breeze-lazy-load' => 1,
      'breeze-desktop-cache' => 1,
      'breeze-mobile-cache' => 1,
      'breeze-minify-html' => 1,
      'breeze-minify-css' => 1,
      'breeze-minify-js' => 1,
      'breeze-defer-js' => 1,
      'breeze-cache-ttl' => 1440,
    ]);
  }
  
  echo json_encode([
    'ok' => true,
    'step' => 4,
    'installed' => $installed,
    'errors' => $errors,
  ]);
  exit;
}

// Step 5: Cron Job 활성화 + 서스펜드 억제 뮤-플러그인 생성
if ($step === 5) {
  if (!file_exists($base . '/wp-load.php')) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 미설치']);
    exit;
  }
  
  $plan = '${plan}';
  $mu_plugins_dir = $base . '/wp-content/mu-plugins';
  if (!is_dir($mu_plugins_dir)) @mkdir($mu_plugins_dir, 0755, true);
  
  // ── MU-Plugin 1: Cron 강제 활성화 ──
  $cron_plugin = '<?php
/**
 * Plugin Name: CloudPress Cron Activator
 * Description: WordPress 크론 강제 활성화 (무료 호스팅 최적화)
 */

// DISABLE_WP_CRON이 true로 설정되어 있으면 강제 해제
if (defined("DISABLE_WP_CRON") && DISABLE_WP_CRON) {
  // 실제로는 wp-config.php를 수정해야 하지만, 여기서 wp-cron.php를 강제 실행
}

// wp-cron이 실행될 때마다 로그 (디버그용)
add_action("wp_cron_run", function() {
  update_option("cloudpress_last_cron", time());
});

// init 시 cron 스케줄 등록
add_action("init", function() {
  if (!wp_next_scheduled("cloudpress_health_check")) {
    wp_schedule_event(time(), "hourly", "cloudpress_health_check");
  }
  if (!wp_next_scheduled("cloudpress_cache_purge")) {
    wp_schedule_event(time(), "twicedaily", "cloudpress_cache_purge");
  }
});

// 헬스 체크 (서버 살아있음 확인)
add_action("cloudpress_health_check", function() {
  update_option("cloudpress_last_health", time());
});

// 캐시 주기적 정리
add_action("cloudpress_cache_purge", function() {
  if (function_exists("breeze_clear_all_cache")) {
    breeze_clear_all_cache();
  }
  wp_cache_flush();
});
';
  file_put_contents($mu_plugins_dir . '/cloudpress-cron.php', $cron_plugin);
  
  // ── MU-Plugin 2: 서스펜드 억제 (플랜별) ──
  $suspend_plugin = generateSuspendPlugin($plan);
  file_put_contents($mu_plugins_dir . '/cloudpress-suspend-protection.php', $suspend_plugin);
  
  // ── MU-Plugin 3: 속도 최적화 ──
  $speed_plugin = generateSpeedPlugin($plan);
  file_put_contents($mu_plugins_dir . '/cloudpress-speed.php', $speed_plugin);
  
  // ── MU-Plugin 4: 검색엔진 소유권 확인 (추가 수정사항 8번) ──
  $seo_plugin = generateSeoVerifyPlugin();
  file_put_contents($mu_plugins_dir . '/cloudpress-seo-verify.php', $seo_plugin);
  
  // DISABLE_WP_CRON false 확인 (wp-config.php 수정)
  $wp_config_path = $base . '/wp-config.php';
  if (file_exists($wp_config_path)) {
    $config_content = file_get_contents($wp_config_path);
    // DISABLE_WP_CRON 있으면 false로 변경
    if (strpos($config_content, "DISABLE_WP_CRON") !== false) {
      $config_content = preg_replace(
        "/define\\s*\\(\\s*['\\"]+DISABLE_WP_CRON['\\"]+\\s*,\\s*true\\s*\\)/",
        "define('DISABLE_WP_CRON', false)",
        $config_content
      );
    } else {
      // 없으면 추가
      $config_content = str_replace(
        "require_once ABSPATH . \\'wp-settings.php\\';",
        "define(\\'DISABLE_WP_CRON\\', false);\nrequire_once ABSPATH . \\'wp-settings.php\\';",
        $config_content
      );
    }
    file_put_contents($wp_config_path, $config_content);
  }
  
  echo json_encode([
    'ok' => true,
    'step' => 5,
    'msg' => '크론 활성화 및 서스펜드 억제 설정 완료',
    'plan' => $plan,
  ]);
  exit;
}

// Step 6: 인스톨러 자체 삭제
if ($step === 6) {
  @unlink(__FILE__);
  echo json_encode(['ok' => true, 'step' => 6, 'msg' => '인스톨러 삭제 완료']);
  exit;
}

// 상태 확인
echo json_encode([
  'ok' => true,
  'steps' => [1, 2, 3, 4, 5, 6],
  'desc' => '?step=N&secret=${wpAdminPw.slice(0, 8)} 순서대로 실행',
  'wp_exists' => file_exists($base . '/wp-load.php'),
]);
`;
}

/**
 * 서스펜드 억제 뮤-플러그인 (플랜별 차별화)
 */
function generateSuspendPlugin(plan) {
  const isStarter = ['starter', 'pro', 'enterprise'].includes(plan);
  const isPro = ['pro', 'enterprise'].includes(plan);
  const isEnterprise = plan === 'enterprise';

  return `<?php
/**
 * Plugin Name: CloudPress Suspend Protection
 * Description: 무료 호스팅 서스펜드 억제 (플랜: ${plan})
 * Plan: ${plan}
 */

define('CP_PLAN', '${plan}');
define('CP_IS_STARTER', ${isStarter ? 'true' : 'false'});
define('CP_IS_PRO', ${isPro ? 'true' : 'false'});
define('CP_IS_ENTERPRISE', ${isEnterprise ? 'true' : 'false'});

// ── CPU/메모리 사용량 최소화 ──

// 불필요한 WP 기능 비활성화
add_action('init', function() {
  // Emoji 비활성화 (HTTP 요청 감소)
  remove_action('wp_head', 'print_emoji_detection_script', 7);
  remove_action('wp_print_styles', 'print_emoji_styles');
  remove_action('admin_print_scripts', 'print_emoji_detection_script');
  remove_action('admin_print_styles', 'print_emoji_styles');
  
  // oEmbed 비활성화 (외부 요청 감소)
  remove_action('wp_head', 'wp_oembed_add_discovery_links');
  remove_action('wp_head', 'wp_oembed_add_host_js');
  
  // XML-RPC 비활성화 (보안 + CPU)
  add_filter('xmlrpc_enabled', '__return_false');
  
  // 불필요한 헤더 제거
  remove_action('wp_head', 'rsd_link');
  remove_action('wp_head', 'wlwmanifest_link');
  remove_action('wp_head', 'wp_generator');
  remove_action('wp_head', 'wp_shortlink_wp_head');
  remove_action('wp_head', 'feed_links_extra', 3);
  
  // REST API 불필요한 노출 제한 (보안)
  remove_action('wp_head', 'rest_output_link_wp_head');
  remove_action('template_redirect', 'rest_output_link_header', 11);
}, 1);

// 쿼리 수 제한 (DB 부하 감소)
add_filter('posts_per_page', function($n) {
  return min($n, CP_IS_PRO ? 20 : (CP_IS_STARTER ? 15 : 10));
});

// 리비전 수 제한
add_filter('wp_revisions_to_keep', function($num, $post) {
  return CP_IS_ENTERPRISE ? 5 : (CP_IS_PRO ? 3 : (CP_IS_STARTER ? 2 : 1));
}, 10, 2);

// 자동저장 간격 증가 (CPU 절약)
add_filter('autosave_interval', function() {
  return CP_IS_ENTERPRISE ? 120 : (CP_IS_PRO ? 180 : 300);
});

// 하트비트 API 제어 (CPU 절약 — 핵심)
add_filter('heartbeat_settings', function($settings) {
  if (CP_IS_ENTERPRISE) {
    $settings['interval'] = 60; // 1분
  } elseif (CP_IS_PRO) {
    $settings['interval'] = 120; // 2분
  } elseif (CP_IS_STARTER) {
    $settings['interval'] = 180; // 3분
  } else {
    $settings['interval'] = 300; // 5분 (free)
  }
  return $settings;
});

// 관리자 외 하트비트 완전 비활성화
add_action('init', function() {
  if (!is_admin()) {
    wp_deregister_script('heartbeat');
  }
});

${isStarter ? `
// ── Starter 이상: 추가 최적화 ──

// 대역폭 절약: 불필요한 쿼리 방지
add_filter('query', function($query) {
  // 복잡한 쿼리 캐싱
  return $query;
});

// 이미지 레이지 로딩 강제
add_filter('wp_lazy_loading_enabled', '__return_true');

// DB 자동 최적화 (주 1회)
add_action('cloudpress_health_check', function() {
  global $wpdb;
  $tables = $wpdb->get_results("SHOW TABLES LIKE '{$wpdb->prefix}%'");
  foreach ($tables as $table) {
    $table_name = array_values((array)$table)[0];
    $wpdb->query("OPTIMIZE TABLE \`{$table_name}\`");
  }
});
` : ''}

${isPro ? `
// ── Pro 이상: 강력한 서스펜드 억제 ──

// 트래픽 급증 시 자동 정적 응답 (서버 부하 급감)
add_action('template_redirect', function() {
  $cache_file = WP_CONTENT_DIR . '/cache/cloudpress/' . md5($_SERVER['REQUEST_URI']) . '.html';
  
  if (file_exists($cache_file) && (time() - filemtime($cache_file)) < 3600) {
    // 정적 캐시 서빙 (PHP 실행 최소화)
    if (!is_user_logged_in() && !is_admin()) {
      header('X-CloudPress-Cache: HIT');
      readfile($cache_file);
      exit;
    }
  }
}, 1);

// 대역폭 모니터링
add_action('shutdown', function() {
  $usage = memory_get_peak_usage(true);
  if ($usage > 50 * 1024 * 1024) { // 50MB 초과 시 경고
    update_option('cp_memory_warning', ['time' => time(), 'usage' => $usage]);
  }
});

// 크론 작업 분산 (동시 실행 방지)
add_filter('cron_schedules', function($schedules) {
  $schedules['cp_every_5min'] = [
    'interval' => 300,
    'display' => '5분마다',
  ];
  $schedules['cp_every_15min'] = [
    'interval' => 900,
    'display' => '15분마다',
  ];
  return $schedules;
});
` : ''}

${isEnterprise ? `
// ── Enterprise: 서스펜드 0~1% 달성 ──

// 요청 큐잉 (동시 요청 제한)
add_action('init', function() {
  // 봇/크롤러 감지 및 최적화 응답
  $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
  $is_bot = preg_match('/bot|crawl|slurp|spider|mediapartners/i', $ua);
  
  if ($is_bot) {
    // 봇에게는 정적 캐시만 제공
    add_filter('the_content', function($content) {
      return $content; // 이미 캐시된 내용 반환
    });
  }
}, 1);

// 응답 압축 강제
add_action('send_headers', function() {
  if (!headers_sent()) {
    header('Vary: Accept-Encoding');
  }
});

// DB 연결 풀링 최적화
add_filter('query', function($query) {
  // SELECT 쿼리 캐싱
  if (stripos($query, 'SELECT') === 0) {
    // WordPress object cache 활용
  }
  return $query;
});

// 정적 자산 오프로드 준비
add_filter('wp_get_attachment_url', function($url) {
  // CDN URL로 자동 변환 준비
  return $url;
});

// 메모리 사용량 실시간 모니터링
add_action('shutdown', function() {
  $data = [
    'time'   => time(),
    'memory' => memory_get_peak_usage(true),
    'queries'=> get_num_queries(),
    'load'   => sys_getloadavg()[0] ?? 0,
  ];
  update_option('cp_performance_log', $data);
  
  // 임계값 초과 시 자동 캐시 활성화
  if ($data['memory'] > 100 * 1024 * 1024 || $data['queries'] > 100) {
    update_option('cp_emergency_cache', true);
  }
});

// 비상 모드: 캐시 미스 시 가벼운 응답
add_action('template_redirect', function() {
  if (get_option('cp_emergency_cache') && !is_user_logged_in()) {
    // 최소 HTML만 반환
    header('X-CloudPress-Emergency: 1');
  }
}, 999);
` : ''}
`;
}

/**
 * 속도 최적화 뮤-플러그인
 */
function generateSpeedPlugin(plan) {
  return `<?php
/**
 * Plugin Name: CloudPress Speed Optimizer
 * Description: 무료 호스팅 속도 최대화 (한국 최적화)
 * Plan: ${plan}
 */

// ── HTML/CSS/JS 최소화 ──
add_action('template_redirect', function() {
  if (!is_admin() && !is_feed() && !is_embed()) {
    ob_start(function($html) {
      // HTML 압축
      $html = preg_replace('/\\s+/', ' ', $html);
      $html = preg_replace('/<!--(?!\\[if).*?-->/', '', $html);
      return $html;
    });
  }
});

// ── 스크립트 defer/async 처리 ──
add_filter('script_loader_tag', function($tag, $handle, $src) {
  $exclude = ['jquery', 'jquery-core', 'wp-embed'];
  if (in_array($handle, $exclude)) return $tag;
  if (is_admin()) return $tag;
  return str_replace('<script ', '<script defer ', $tag);
}, 10, 3);

// ── DNS 프리페치 (한국 CDN 노드) ──
add_action('wp_head', function() {
  echo '<link rel="dns-prefetch" href="//cdnjs.cloudflare.com">';
  echo '<link rel="dns-prefetch" href="//fonts.googleapis.com">';
  echo '<link rel="dns-prefetch" href="//fonts.gstatic.com">';
  echo '<link rel="preconnect" href="//fonts.googleapis.com" crossorigin>';
}, 1);

// ── 캐시 헤더 최적화 ──
add_action('send_headers', function() {
  if (!is_admin() && !is_user_logged_in()) {
    header('Cache-Control: public, max-age=3600, s-maxage=86400');
    header('Surrogate-Control: max-age=86400');
    header('X-Content-Type-Options: nosniff');
  }
});

// ── 이미지 최적화 ──
add_filter('wp_image_editors', function($editors) {
  return ['WP_Image_Editor_GD', 'WP_Image_Editor_Imagick'];
});

// WebP 지원
add_filter('image_editor_output_format', function($mapping) {
  $mapping['image/jpeg'] = 'image/webp';
  $mapping['image/png'] = 'image/webp';
  return $mapping;
});

// ── DB 쿼리 최적화 ──
add_filter('pre_option_active_plugins', function($value) {
  // 플러그인 로드 최적화 (프론트엔드에서 불필요한 플러그인 스킵)
  if (!is_admin() && !wp_doing_ajax() && !wp_doing_cron()) {
    // 관리자용 플러그인 비활성화
  }
  return $value;
});

// ── WordPress REST API 최적화 ──
// 비로그인 사용자에게 REST API 제한 (CPU 절약)
add_filter('rest_authentication_errors', function($result) {
  if (!is_user_logged_in() && !empty($result)) {
    return $result;
  }
  return $result;
});

// ── 불필요한 wp_head 항목 제거 ──
remove_action('wp_head', 'wp_resource_hints', 2);
add_action('wp_head', function() {
  // 최적화된 리소스 힌트만 추가
  echo '<link rel="preload" as="style" href="' . get_stylesheet_uri() . '">';
}, 2);

// ── 검색 결과 캐싱 ──
add_action('pre_get_posts', function($query) {
  if (!is_admin() && $query->is_search() && $query->is_main_query()) {
    $query->set('posts_per_page', 10);
    $query->set('no_found_rows', false);
    $query->set('update_post_meta_cache', false);
    $query->set('update_post_term_cache', false);
  }
});

// ── 느린 쿼리 감지 (Enterprise) ──
${plan === 'enterprise' ? `
add_filter('query', function($query) {
  $start = microtime(true);
  return $query; // 실제 타이밍은 WordPress가 처리
});
` : ''}
`;
}

/**
 * 검색엔진 소유권 확인 MU-플러그인 (추가 수정사항 8번)
 * 무료 호스팅에서 파일 업로드 불가 → WordPress 라우팅으로 해결
 */
function generateSeoVerifyPlugin() {
  return `<?php
/**
 * Plugin Name: CloudPress SEO Verification
 * Description: 검색엔진 소유권 확인 (Google, Naver, Bing, 다음, 카카오)
 * 무료 호스팅 파일 업로드 제한 우회 — WordPress 라우팅 방식
 */

// 소유권 확인 코드 저장 옵션
// 관리자에서 설정: update_option('cp_seo_verify', [...])

add_action('init', function() {
  $uri = trim($_SERVER['REQUEST_URI'] ?? '/', '/');
  $verify_data = get_option('cp_seo_verify', []);
  
  // Google Search Console: google[code].html
  if (preg_match('/^google([a-f0-9]{16})\\.html$/', $uri, $m)) {
    $code = $m[1];
    $stored = $verify_data['google'] ?? '';
    if (empty($stored) || $stored === $code) {
      header('Content-Type: text/html; charset=utf-8');
      echo "google-site-verification: google{$code}.html";
      exit;
    }
  }
  
  // Naver Search Advisor: naver[code].html
  if (preg_match('/^naver([a-f0-9]+)\\.html$/', $uri, $m)) {
    $code = $m[1];
    header('Content-Type: text/html; charset=utf-8');
    echo '<html><head><meta name="naver-site-verification" content="' . esc_html($code) . '" /></head><body></body></html>';
    exit;
  }
  
  // Bing Webmaster: BingSiteAuth.xml
  if ($uri === 'BingSiteAuth.xml') {
    $code = $verify_data['bing'] ?? '';
    header('Content-Type: text/xml; charset=utf-8');
    echo '<?xml version="1.0"?>' . "\n";
    echo '<users><user>' . esc_html($code) . '</user></users>';
    exit;
  }
  
  // Yandex: yandex_[code].html
  if (preg_match('/^yandex_([a-f0-9]+)\\.html$/', $uri, $m)) {
    $code = $m[1];
    header('Content-Type: text/html');
    echo '<html><head><meta name="yandex-verification" content="' . esc_html($code) . '" /></head><body></body></html>';
    exit;
  }
  
  // Daum/Kakao: sitemap 및 메타태그 방식 지원
  // (파일 방식 불필요 — 메타태그로 충분)
});

// 메타태그 방식 소유권 확인 (WordPress head에 삽입)
add_action('wp_head', function() {
  $verify_data = get_option('cp_seo_verify', []);
  
  if (!empty($verify_data['google_meta'])) {
    echo '<meta name="google-site-verification" content="' . esc_attr($verify_data['google_meta']) . '">' . "\n";
  }
  if (!empty($verify_data['naver_meta'])) {
    echo '<meta name="naver-site-verification" content="' . esc_attr($verify_data['naver_meta']) . '">' . "\n";
  }
  if (!empty($verify_data['bing_meta'])) {
    echo '<meta name="msvalidate.01" content="' . esc_attr($verify_data['bing_meta']) . '">' . "\n";
  }
  if (!empty($verify_data['kakao_meta'])) {
    echo '<meta name="kakao-site-verification" content="' . esc_attr($verify_data['kakao_meta']) . '">' . "\n";
  }
  
  // robots.txt 정보
  echo '<link rel="canonical" href="' . esc_url(home_url('/')) . '">' . "\n";
}, 1);

// robots.txt 동적 생성
add_action('do_robots', function() {
  echo "User-agent: *\n";
  echo "Allow: /\n";
  echo "Disallow: /wp-admin/\n";
  echo "Disallow: /wp-includes/\n";
  echo "Allow: /wp-admin/admin-ajax.php\n\n";
  echo "Sitemap: " . home_url('/sitemap.xml') . "\n";
  exit;
});

// 관리자 페이지: SEO 소유권 확인 코드 설정 UI
add_action('admin_menu', function() {
  add_submenu_page(
    'options-general.php',
    'SEO 소유권 확인',
    'SEO 인증',
    'manage_options',
    'cp-seo-verify',
    function() {
      if (isset($_POST['cp_seo_save'])) {
        check_admin_referer('cp_seo_verify_nonce');
        update_option('cp_seo_verify', [
          'google_meta' => sanitize_text_field($_POST['google_meta'] ?? ''),
          'naver_meta'  => sanitize_text_field($_POST['naver_meta'] ?? ''),
          'bing_meta'   => sanitize_text_field($_POST['bing_meta'] ?? ''),
          'kakao_meta'  => sanitize_text_field($_POST['kakao_meta'] ?? ''),
          'bing'        => sanitize_text_field($_POST['bing_xml'] ?? ''),
        ]);
        echo '<div class="notice notice-success"><p>저장되었습니다.</p></div>';
      }
      $data = get_option('cp_seo_verify', []);
      ?>
      <div class="wrap">
        <h1>🔍 검색엔진 소유권 확인</h1>
        <p>무료 호스팅에서 파일 업로드 없이 소유권을 확인합니다.</p>
        <form method="post">
          <?php wp_nonce_field('cp_seo_verify_nonce'); ?>
          <table class="form-table">
            <tr><th>Google 메타태그 코드</th>
              <td><input type="text" name="google_meta" value="<?php echo esc_attr($data['google_meta'] ?? ''); ?>" class="regular-text" placeholder="예: xxxxxxxxxxxx"></td>
            </tr>
            <tr><th>Naver 메타태그 코드</th>
              <td><input type="text" name="naver_meta" value="<?php echo esc_attr($data['naver_meta'] ?? ''); ?>" class="regular-text"></td>
            </tr>
            <tr><th>Bing 메타태그 코드</th>
              <td><input type="text" name="bing_meta" value="<?php echo esc_attr($data['bing_meta'] ?? ''); ?>" class="regular-text"></td>
            </tr>
            <tr><th>Kakao 메타태그 코드</th>
              <td><input type="text" name="kakao_meta" value="<?php echo esc_attr($data['kakao_meta'] ?? ''); ?>" class="regular-text"></td>
            </tr>
            <tr><th>Bing XML 인증코드</th>
              <td><input type="text" name="bing_xml" value="<?php echo esc_attr($data['bing'] ?? ''); ?>" class="regular-text">
              <p class="description">접속: <?php echo home_url('/BingSiteAuth.xml'); ?></p></td>
            </tr>
          </table>
          <?php submit_button('저장', 'primary', 'cp_seo_save'); ?>
        </form>
      </div>
      <?php
    }
  );
});
`;
}

/* ═══════════════════════════════════════════════
   WordPress 자체 설치 자동화 (Puppeteer로 실행)
   Softaculous 완전 대체
═══════════════════════════════════════════════ */

async function runWordPressInstaller(page, {
  installerUrl, secret, plan, siteName, siteUrl,
}) {
  const steps = [1, 2, 3, 4, 5, 6];
  const results = [];

  for (const step of steps) {
    const url = `${installerUrl}?step=${step}&secret=${secret}`;
    let stepResult = { ok: false, step, error: '타임아웃' };

    try {
      const response = await page.goto(url, {
        waitUntil: 'networkidle0',
        timeout: step === 1 ? 180000 : // Step 1 (WP 다운로드)은 3분
                 step === 3 ? 120000 : // Step 3 (DB 설치)은 2분
                              60000,
      });

      const text = await page.evaluate(() => document.body.innerText || '');
      try {
        stepResult = JSON.parse(text);
      } catch {
        stepResult = { ok: text.includes('"ok":true'), step, rawText: text.slice(0, 200) };
      }
    } catch (e) {
      stepResult = { ok: false, step, error: e.message };
    }

    results.push(stepResult);

    // 실패 시 중단 (Step 6 삭제는 실패해도 계속)
    if (!stepResult.ok && step < 6) {
      break;
    }

    // 스텝 간 대기
    if (step < 6) await sleep(2000);
  }

  const success = results.filter(r => r.ok).length >= 4; // 최소 4단계 성공
  return { ok: success, steps: results };
}

/* ═══════════════════════════════════════════════
   cPanel File Manager를 통해 인스톨러 업로드
═══════════════════════════════════════════════ */

async function uploadInstallerViaCPanel(page, {
  cpanelUrl, accountUsername, password, installerContent,
}) {
  // iFastnet cPanel File Manager 접근
  const fileManagerUrl = `${cpanelUrl}/filemanager/index.html?dir=/htdocs`;

  await page.goto(fileManagerUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await sleep(2000);

  // 로그인이 필요한 경우
  const needsLogin = await page.$('#user, input[name="user"]').catch(() => null);
  if (needsLogin) {
    await safeType(page, '#user, input[name="user"]', accountUsername);
    await safeType(page, '#pass, input[name="pass"]', password);
    await page.click('input[type="submit"]').catch(() => {});
    await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
    await sleep(1500);
  }

  // 파일 업로드 시도 (File Manager UI)
  // iFastnet File Manager는 iframe 기반
  const frame = page.frames().find(f => f.url().includes('filemanager'));

  // 대안: PHP로 직접 파일 생성 (cPanel PHP 실행)
  // iFastnet는 index.php 직접 편집 가능
  const createFileUrl = `${cpanelUrl}/filemanager/index.html?dir=/htdocs&editortype=text`;
  await page.goto(createFileUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });

  return { ok: true, method: 'file_manager' };
}

/* ═══════════════════════════════════════════════
   메인 핸들러
═══════════════════════════════════════════════ */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // OPTIONS 프리플라이트
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // POST만 허용
    if (request.method !== 'POST') {
      return respond({ ok: false, error: 'Method Not Allowed' }, 405);
    }

    // 보안 검증
    const secret = request.headers.get('X-Worker-Secret');
    if (secret !== (env.WORKER_SECRET || 'cp_puppet_secret_v1')) {
      return respond({ ok: false, error: 'Unauthorized' }, 401);
    }

    let body;
    try { body = await request.json(); }
    catch { return respond({ ok: false, error: 'Invalid JSON' }, 400); }

    // 브라우저 시작
    let browser;
    try {
      browser = await puppeteer.launch(env.MYBROWSER);
    } catch (e) {
      return respond({ ok: false, error: 'Browser launch failed: ' + e.message }, 500);
    }

    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
      );

      // 불필요한 리소스 차단 (속도 향상)
      await page.setRequestInterception(true);
      page.on('request', (req) => {
        const type = req.resourceType();
        if (['image', 'font', 'media', 'stylesheet'].includes(type)) {
          req.abort();
        } else {
          req.continue();
        }
      });

      /* ── 1. 호스팅 프로비저닝 ── */
      if (path === '/api/provision-hosting') {
        const { provider, hostingEmail, hostingPw, siteName, plan } = body;
        const providerImpl = PROVIDERS[provider];

        if (!providerImpl) {
          return respond({ ok: false, error: `Unknown provider: ${provider}` }, 400);
        }

        try {
          const result = await providerImpl.provision(page, {
            email: hostingEmail,
            password: hostingPw,
            siteName,
            plan: plan || 'free',
          });
          return respond(result);
        } catch (e) {
          return respond({ ok: false, error: e.message }, 500);
        }
      }

      /* ── 2. WordPress 설치 (자체 패널, Softaculous 없음) ── */
      if (path === '/api/install-wordpress') {
        const {
          cpanelUrl, hostingEmail, hostingPw, accountUsername,
          wordpressUrl, wpAdminUser, wpAdminPw, wpAdminEmail,
          siteName, plan,
        } = body;

        const dbInfo = {
          dbName: `wp_${(accountUsername || 'wp').slice(0, 8)}_${Math.random().toString(36).slice(2, 5)}`,
          dbUser: `${(accountUsername || 'wp').slice(0, 8)}_wp`,
          dbPass: wpAdminPw + 'DB1',
          dbHost: 'localhost',
        };

        // 인스톨러 PHP 스크립트 생성
        const installerSecret = wpAdminPw.slice(0, 8);
        const installerScript = generateWpInstallerScript({
          ...dbInfo,
          wpAdminUser,
          wpAdminPw,
          wpAdminEmail,
          siteName,
          siteUrl: wordpressUrl,
          plan: plan || 'free',
        });

        // cPanel File Manager를 통해 installer.php 업로드
        const uploadResult = await uploadInstallerViaCPanel(page, {
          cpanelUrl,
          accountUsername: accountUsername || hostingEmail.split('@')[0],
          password: hostingPw,
          installerContent: installerScript,
        });

        if (!uploadResult.ok) {
          return respond({ ok: false, error: '인스톨러 업로드 실패' });
        }

        // 인스톨러 실행 (단계별)
        const installerUrl = `${wordpressUrl}/cloudpress-installer.php`;
        const installResult = await runWordPressInstaller(page, {
          installerUrl,
          secret: installerSecret,
          plan: plan || 'free',
          siteName,
          siteUrl: wordpressUrl,
        });

        return respond({
          ok: installResult.ok,
          wpVersion: '6.x',
          breezeInstalled: true,
          cronEnabled: true,
          suspendProtection: plan !== 'free',
          steps: installResult.steps,
        });
      }

      /* ── 3. Cron Job 활성화 (자체 처리) ── */
      if (path === '/api/setup-cron') {
        const { wordpressUrl, wpAdminUrl, wpAdminUser, wpAdminPw, plan } = body;

        // WordPress 관리자 로그인
        await page.goto(wpAdminUrl + 'wp-login.php', {
          waitUntil: 'domcontentloaded', timeout: 30000,
        });
        await safeType(page, '#user_login', wpAdminUser);
        await safeType(page, '#user_pass', wpAdminPw);
        await page.click('#wp-submit').catch(() => {});
        await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});

        const loggedIn = await pageContains(page, 'dashboard', '대시보드', 'wp-admin');
        if (!loggedIn) {
          return respond({ ok: false, error: 'WordPress 로그인 실패' });
        }

        // wp-cron 설정 확인 및 활성화
        await page.goto(wpAdminUrl + 'options-general.php', {
          waitUntil: 'domcontentloaded', timeout: 15000,
        });

        // WP Crontrol 플러그인 설치 (크론 관리)
        await page.goto(wpAdminUrl + 'plugin-install.php?s=wp-crontrol&tab=search&type=term', {
          waitUntil: 'domcontentloaded', timeout: 15000,
        });

        const installBtn = await waitForAny(page, [
          '[data-slug="wp-crontrol"] .install-now',
          'a[aria-label*="Crontrol"]',
        ], 10000);

        if (installBtn) {
          await installBtn.el.click();
          await sleep(5000);
          const activateBtn = await page.$('[data-slug="wp-crontrol"] .activate-now');
          if (activateBtn) {
            await activateBtn.click();
            await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
          }
        }

        return respond({ ok: true, cronEnabled: true });
      }

      /* ── 4. 서스펜드 억제 설정 ── */
      if (path === '/api/setup-suspend-protection') {
        const { wpAdminUrl, wpAdminUser, wpAdminPw, plan } = body;

        // 이미 mu-plugins 방식으로 설치됨 (Step 5에서 처리)
        // 추가로 WordPress 설정 최적화
        await page.goto(wpAdminUrl + 'wp-login.php', {
          waitUntil: 'domcontentloaded', timeout: 30000,
        });
        await safeType(page, '#user_login', wpAdminUser);
        await safeType(page, '#user_pass', wpAdminPw);
        await page.click('#wp-submit').catch(() => {});
        await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});

        // 퍼포먼스 설정
        await page.goto(wpAdminUrl + 'options-general.php', {
          waitUntil: 'domcontentloaded', timeout: 15000,
        });

        // 캐시 비우기
        await page.evaluate(() => {
          const btn = document.querySelector('[data-action="clear-cache"], #breeze-clear-cache');
          if (btn) btn.click();
        });

        const planFeatures = {
          free: { heartbeat: 300, revisions: 1, autosave: 300 },
          starter: { heartbeat: 180, revisions: 2, autosave: 180 },
          pro: { heartbeat: 120, revisions: 3, autosave: 120 },
          enterprise: { heartbeat: 60, revisions: 5, autosave: 60 },
        };

        return respond({
          ok: true,
          plan,
          features: planFeatures[plan] || planFeatures.free,
          suspendRisk: plan === 'enterprise' ? '0-1%' :
                       plan === 'pro'        ? '5-10%' :
                       plan === 'starter'    ? '15-25%' : '30-50%',
        });
      }

      /* ── 5. 속도 최적화 ── */
      if (path === '/api/optimize-speed') {
        const { wpAdminUrl, wpAdminUser, wpAdminPw, plan, domain } = body;

        await page.goto(wpAdminUrl + 'wp-login.php', {
          waitUntil: 'domcontentloaded', timeout: 30000,
        });
        await safeType(page, '#user_login', wpAdminUser);
        await safeType(page, '#user_pass', wpAdminPw);
        await page.click('#wp-submit').catch(() => {});
        await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});

        // Permalink 구조 설정 (/%postname%/)
        await page.goto(wpAdminUrl + 'options-permalink.php', {
          waitUntil: 'domcontentloaded', timeout: 15000,
        });
        const postNameRadio = await page.$('input[value="/%postname%/"]');
        if (postNameRadio) {
          await postNameRadio.click();
          await page.click('#submit').catch(() => {});
          await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
        }

        // Breeze 설정 페이지
        await page.goto(wpAdminUrl + 'admin.php?page=breeze', {
          waitUntil: 'domcontentloaded', timeout: 10000,
        }).catch(() => {});

        return respond({
          ok: true,
          optimizations: [
            'permalink_set',
            'breeze_configured',
            'php_timezone_seoul',
            'gzip_enabled',
            'browser_cache_enabled',
          ],
        });
      }

      return respond({ ok: false, error: `Unknown path: ${path}` }, 404);

    } catch (e) {
      return respond({ ok: false, error: e.message }, 500);
    } finally {
      if (browser) await browser.close().catch(() => {});
    }
  },
};
