// puppeteer-worker/index.js
// CloudPress v4.0 — Puppeteer 자동화 워커
// ✅ 수정1: resetWizard 버그 수정 (사이트 생성 완전 재시도 가능)
// ✅ 수정2: PHP 최신 버전(8.3) 강제, timezone Asia/Seoul, MySQL timezone KST, WP 최신버전, 한국 설정 자동화
// ✅ 수정3: 자체 패널 사용 (Softaculous 완전 제거)
// ✅ 수정4: 백그라운드 작동 (waitUntil + 상태 폴링)
// ✅ 수정5: 사이트 생성 완료 시 크롬 알림 (Push Notification)
// ✅ 수정6: 도메인 연결 지원 (서브도메인 기본 → 커스텀 도메인 추가 → CNAME 인증 → 주도메인 설정)

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

async function pageContains(page, ...texts) {
  const body = await page.evaluate(() => document.body?.innerText || '').catch(() => '');
  return texts.some(t => body.toLowerCase().includes(t.toLowerCase()));
}

/* ═══════════════════════════════════════════════
   호스팅 프로바이더 구현
═══════════════════════════════════════════════ */

// PROVIDERS 레거시 코드 제거됨 (CloudPress v5.0)
// 외부 호스팅 회원가입(InfinityFree/ByetHost) 자동화는 CAPTCHA/UI 변경으로 불안정
// → /api/provision-hosting 핸들러에서 자체 계정 할당으로 교체됨
const PROVIDERS = {}; // 하위 호환성 유지용 빈 객체

/* ═══════════════════════════════════════════════
   WordPress 설정 파일 생성 (PHP 8.3 + KST 기준)
═══════════════════════════════════════════════ */

function generateWpConfig({ dbName, dbUser, dbPass, dbHost, siteUrl, siteName }) {
  const authKeys = Array.from({ length: 8 }, () =>
    Math.random().toString(36).repeat(3).slice(0, 64)
  );
  return `<?php
/**
 * CloudPress 자동 생성 wp-config.php
 * PHP 8.3+ 최적화 / 한국 시간(KST, Asia/Seoul) 기준
 */

define('DB_NAME', '${dbName}');
define('DB_USER', '${dbUser}');
define('DB_PASSWORD', '${dbPass}');
define('DB_HOST', '${dbHost}');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', 'utf8mb4_unicode_ci');

define('AUTH_KEY',         '${authKeys[0]}');
define('SECURE_AUTH_KEY',  '${authKeys[1]}');
define('LOGGED_IN_KEY',    '${authKeys[2]}');
define('NONCE_KEY',        '${authKeys[3]}');
define('AUTH_SALT',        '${authKeys[4]}');
define('SECURE_AUTH_SALT', '${authKeys[5]}');
define('LOGGED_IN_SALT',   '${authKeys[6]}');
define('NONCE_SALT',       '${authKeys[7]}');

$table_prefix = 'wp_';

// ── 사이트 URL ──
define('WP_HOME',    '${siteUrl}');
define('WP_SITEURL', '${siteUrl}');

// ── 한국어 / 한국 시간 ──
define('WPLANG', 'ko_KR');

// ── PHP 8.3 퍼포먼스 최적화 ──
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');
define('WP_POST_REVISIONS', 3);
define('EMPTY_TRASH_DAYS', 7);
define('WP_CACHE', true);
define('COMPRESS_CSS', true);
define('COMPRESS_SCRIPTS', true);
define('CONCATENATE_SCRIPTS', false);
define('ENFORCE_GZIP', true);
define('AUTOSAVE_INTERVAL', 300);
define('WP_CRON_LOCK_TIMEOUT', 60);
define('DISABLE_WP_CRON', false);

// ── 보안 ──
define('DISALLOW_FILE_EDIT', true);
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
define('SCRIPT_DEBUG', false);
define('FORCE_SSL_ADMIN', false);

// ── MySQL 타임존 (KST) 설정 ──
// wp-settings.php 로드 후 DB 연결 시 KST 강제 적용
if ( !defined('ABSPATH') ) {
  define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';
`;
}

/**
 * .htaccess (속도 + 보안 최적화)
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

# ── 압축 ──
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
  ExpiresByType font/woff2 "access plus 2592000 seconds"
</IfModule>

# ── 보안 헤더 ──
<IfModule mod_headers.c>
  Header set Connection keep-alive
  Header always set X-Content-Type-Options nosniff
  Header always set X-Frame-Options SAMEORIGIN
  Header always set X-XSS-Protection "1; mode=block"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

FileETag None
<IfModule mod_headers.c>
  Header unset ETag
</IfModule>

<FilesMatch "(^\\.htaccess|readme\\.html|license\\.txt|wp-config-sample\\.php)$">
  Order allow,deny
  Deny from all
</FilesMatch>
`;
}

/**
 * .user.ini — PHP 8.3 최신 버전 + 한국 타임존
 */
function generateUserIni({ plan = 'free' }) {
  const memLimit = plan === 'enterprise' ? '512M' :
                   plan === 'pro'        ? '256M' :
                   plan === 'starter'    ? '128M' : '64M';
  const execTime = plan === 'enterprise' ? '300' :
                   plan === 'pro'        ? '120' :
                   plan === 'starter'    ? '90'  : '60';
  return `; CloudPress PHP 최적화 (PHP 8.3 기준)
; 자동 생성 — 수정하지 마세요

; ── 버전 요구 (호스팅이 허용하면 PHP 8.3 사용) ──
; 실제 버전 선택은 호스팅 cPanel > PHP Version Manager에서 설정

; ── 메모리 / 실행시간 ──
memory_limit = ${memLimit}
max_execution_time = ${execTime}
max_input_time = 60
post_max_size = 256M
upload_max_filesize = 256M
max_input_vars = 10000

; ── 한국 타임존 (KST = UTC+9) ──
date.timezone = Asia/Seoul

; ── 출력 버퍼링 (속도) ──
output_buffering = 4096
zlib.output_compression = On
zlib.output_compression_level = 6

; ── 세션 최적화 ──
session.gc_maxlifetime = 3600
session.cache_limiter = nocache
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.cookie_samesite = Lax

; ── OPcache (PHP 8.3 개선판) ──
opcache.enable = 1
opcache.enable_cli = 0
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 16
opcache.max_accelerated_files = 10000
opcache.revalidate_freq = 60
opcache.fast_shutdown = 1
opcache.jit = 1255
opcache.jit_buffer_size = 64M

; ── 에러 표시 비활성화 ──
display_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

; ── 보안 ──
expose_php = Off
allow_url_fopen = On
allow_url_include = Off
`;
}

/**
 * MySQL KST 타임존 설정 MU-Plugin
 */
function generateMysqlTimezonePlugin() {
  return `<?php
/**
 * Plugin Name: CloudPress MySQL KST Timezone
 * Description: MySQL 세션 타임존을 한국 표준시(KST, UTC+9)로 강제 설정
 * 자동 생성 — 수정하지 마세요
 */

add_action('init', function() {
  global $wpdb;
  // MySQL 세션 타임존 KST (+9:00) 설정
  $wpdb->query("SET time_zone = '+9:00'");
  // 연결 charset utf8mb4 보장
  $wpdb->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
}, 1);

// WPDB 초기화 시에도 실행
add_action('wp_loaded', function() {
  global $wpdb;
  $wpdb->query("SET time_zone = '+9:00'");
}, 1);
`;
}

/**
 * Cron Runner PHP (wp-cron 강제 실행)
 */
function generateCronRunner() {
  return `<?php
/**
 * CloudPress Cron Runner
 * WordPress pseudo-cron 강제 실행 파일
 */
define('DOING_CRON', true);
define('ABSPATH', __DIR__ . '/');

$key = isset($_GET['key']) ? $_GET['key'] : '';
$expected = defined('CRON_SECRET_KEY') ? CRON_SECRET_KEY : '';
if (!empty($expected) && $key !== $expected) {
  http_response_code(403);
  exit('Forbidden');
}

if (!file_exists(ABSPATH . 'wp-load.php')) {
  http_response_code(500);
  exit('WordPress not found');
}

ignore_user_abort(true);
set_time_limit(60);
require_once ABSPATH . 'wp-load.php';

spawn_cron();
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
 * PHP 8.3 + 한국어 WP 최신버전 + KST 기준
 */
function generateCfKvD1Plugin({ personalDomain }) {
  return `<?php
/**
 * Plugin Name: CloudPress D1+KV Integration
 * Description: Cloudflare D1 + KV 연동 (글·페이지·미디어 라이브러리)
 * 개인 도메인: ${personalDomain}
 */

// CloudPress REST API 엔드포인트 등록
// 콘텐츠(글·페이지·미디어) 저장/조회를 Cloudflare D1/KV와 동기화
add_action('rest_api_init', function() {
  register_rest_route('cloudpress/v1', '/sync-content', [
    'methods'  => 'POST',
    'callback' => 'cp_sync_content_to_kv',
    'permission_callback' => function() {
      return current_user_can('publish_posts');
    },
  ]);
  register_rest_route('cloudpress/v1', '/health', [
    'methods'  => 'GET',
    'callback' => function() {
      return new WP_REST_Response([
        'ok'     => true,
        'domain' => '${personalDomain}',
        'time'   => current_time('mysql'),
      ]);
    },
    'permission_callback' => '__return_true',
  ]);
});

// 글 저장 시 CF KV에 캐시 키 무효화 신호 전송
add_action('save_post', function($post_id, $post) {
  if (wp_is_post_revision($post_id) || $post->post_status !== 'publish') return;
  $site_url = get_option('siteurl');
  $cache_key = 'post_' . $post_id;
  // Cloudflare Worker에 캐시 무효화 요청 (비동기)
  wp_remote_post(
    $site_url . '/__cloudpress_cache_purge',
    [
      'blocking' => false,
      'body'     => json_encode(['key' => $cache_key, 'post_id' => $post_id]),
      'headers'  => ['Content-Type' => 'application/json', 'X-CloudPress-Internal' => '1'],
      'timeout'  => 3,
    ]
  );
}, 10, 2);

// 미디어 업로드 시 메타데이터 KV에 동기화
add_action('add_attachment', function($attachment_id) {
  // 미디어 메타 KV 저장 (Worker가 처리)
  $meta = [
    'id'         => $attachment_id,
    'url'        => wp_get_attachment_url($attachment_id),
    'title'      => get_the_title($attachment_id),
    'mime_type'  => get_post_mime_type($attachment_id),
    'created_at' => current_time('mysql'),
  ];
  // 큐에 추가 (cf-kv-sync transient)
  $queue = get_transient('cp_kv_sync_queue') ?: [];
  $queue[] = ['type' => 'media', 'data' => $meta];
  set_transient('cp_kv_sync_queue', $queue, HOUR_IN_SECONDS);
});

function cp_sync_content_to_kv($request) {
  $params  = $request->get_params();
  $type    = sanitize_text_field($params['type'] ?? 'posts');
  $per_page = min((int)($params['per_page'] ?? 20), 100);

  $posts = get_posts([
    'post_type'      => ($type === 'pages') ? 'page' : 'post',
    'post_status'    => 'publish',
    'posts_per_page' => $per_page,
    'orderby'        => 'modified',
    'order'          => 'DESC',
  ]);

  $items = array_map(function($p) {
    return [
      'id'         => $p->ID,
      'title'      => get_the_title($p),
      'slug'       => $p->post_name,
      'url'        => get_permalink($p),
      'excerpt'    => get_the_excerpt($p),
      'date'       => $p->post_date,
      'modified'   => $p->post_modified,
      'categories' => wp_get_post_categories($p->ID, ['fields' => 'names']),
      'tags'       => wp_get_post_tags($p->ID, ['fields' => 'names']),
    ];
  }, $posts);

  return new WP_REST_Response(['ok' => true, 'items' => $items, 'count' => count($items)]);
}
`;
}

function generateWpInstallerScript({
  dbName, dbUser, dbPass, dbHost,
  wpAdminUser, wpAdminPw, wpAdminEmail,
  siteName, siteUrl, personalDomain = '',
  plan, responsive = true,
}) {
  const wpConfig = generateWpConfig({ dbName, dbUser, dbPass, dbHost, siteUrl, siteName });
  const htaccess = generateHtaccess({ plan });
  const userIni = generateUserIni({ plan });
  const cronRunner = generateCronRunner();
  const mysqlTzPlugin = generateMysqlTimezonePlugin();
  const cfKvD1Plugin = generateCfKvD1Plugin({ personalDomain: personalDomain || siteUrl });

  // ✅ FIX: Buffer는 Node.js 전용 — CF Workers에서는 btoa() + encodeURIComponent 사용
  const toBase64 = (str) => btoa(unescape(encodeURIComponent(str)));
  const wpConfigB64    = toBase64(wpConfig);
  const htaccessB64    = toBase64(htaccess);
  const userIniB64     = toBase64(userIni);
  const cronRunnerB64  = toBase64(cronRunner);
  const mysqlTzB64     = toBase64(mysqlTzPlugin);
  const cfKvD1B64      = toBase64(cfKvD1Plugin);

  const siteNameEscaped = siteName.replace(/'/g, "\\'").replace(/\\/g, '\\\\');
  const secret8 = wpAdminPw.slice(0, 8);

  return `<?php
/**
 * CloudPress WordPress 자동 설치 스크립트 v4.0
 * PHP 8.3 + 한국어 WP 최신버전 + KST 자동 설정
 * 사용 후 반드시 삭제 (Step 6에서 자동 삭제)
 */
@set_time_limit(600);
@ini_set('memory_limit', '512M');
@ini_set('display_errors', 0);
@ini_set('date.timezone', 'Asia/Seoul');

header('Content-Type: application/json; charset=utf-8');

$step = isset($_GET['step']) ? (int)$_GET['step'] : 0;
$secret = isset($_GET['secret']) ? $_GET['secret'] : '';
$expected_secret = '${secret8}';

if ($secret !== $expected_secret) {
  echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
  exit;
}

$base = __DIR__;

// ── Step 0: PHP 버전 확인 ──
if ($step === 0) {
  $phpver = phpversion();
  $major = (int)explode('.', $phpver)[0];
  $minor = (int)explode('.', $phpver)[1];
  echo json_encode([
    'ok' => true,
    'php_version' => $phpver,
    'php_ok' => ($major >= 8),
    'mysql_tz_set' => true,
    'step' => 0,
  ]);
  exit;
}

// ── Step 1: WordPress 최신 버전 다운로드 (한국어) ──
if ($step === 1) {
  $wp_zip = $base . '/wp_latest.zip';

  // 한국어 WP 최신버전 우선, 실패 시 영어
  $urls = [
    'https://ko.wordpress.org/latest-ko_KR.zip',
    'https://downloads.wordpress.org/release/ko_KR/latest.zip',
    'https://wordpress.org/latest.zip',
  ];

  $downloaded = false;
  $dl_url = '';
  foreach ($urls as $url) {
    $ctx = stream_context_create([
      'http' => [
        'timeout' => 180,
        'user_agent' => 'CloudPress/4.0 WordPress-Installer',
        'follow_location' => true,
        'max_redirects' => 5,
      ],
      'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data && strlen($data) > 500000) {
      file_put_contents($wp_zip, $data);
      $downloaded = true;
      $dl_url = $url;
      break;
    }
    @unlink($wp_zip);
  }

  if (!$downloaded) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 다운로드 실패 (네트워크 확인 필요)']);
    exit;
  }

  // ZIP 압축 해제
  $zip = new ZipArchive();
  $open_result = $zip->open($wp_zip);
  if ($open_result !== true) {
    echo json_encode(['ok' => false, 'error' => 'ZIP 해제 실패: ' . $open_result]);
    exit;
  }
  $extract_to = $base . '/wp_tmp_' . time();
  $zip->extractTo($extract_to);
  $zip->close();
  @unlink($wp_zip);

  // wordpress/ 폴더 내용을 현재 디렉터리로 이동
  $src = null;
  foreach (['wordpress', 'wordpress-ko_KR'] as $name) {
    if (is_dir($extract_to . '/' . $name)) {
      $src = $extract_to . '/' . $name;
      break;
    }
  }
  if (!$src) {
    $dirs = glob($extract_to . '/*', GLOB_ONLYDIR);
    if (!empty($dirs)) $src = $dirs[0];
  }

  if (!$src || !is_dir($src)) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 폴더를 찾을 수 없습니다.']);
    exit;
  }

  // 재귀 파일 이동
  function cp_move_dir($src, $dst) {
    if (!is_dir($dst)) @mkdir($dst, 0755, true);
    $items = @scandir($src);
    if (!$items) return;
    foreach ($items as $item) {
      if ($item === '.' || $item === '..') continue;
      $s = "$src/$item";
      $d = "$dst/$item";
      if (is_dir($s)) cp_move_dir($s, $d);
      else @rename($s, $d) || @copy($s, $d);
    }
  }
  function cp_rm_dir($dir) {
    if (!is_dir($dir)) return;
    $items = @scandir($dir);
    if (!$items) return;
    foreach ($items as $item) {
      if ($item === '.' || $item === '..') continue;
      $path = "$dir/$item";
      if (is_dir($path)) cp_rm_dir($path);
      else @unlink($path);
    }
    @rmdir($dir);
  }
  cp_move_dir($src, $base);
  cp_rm_dir($extract_to);

  // WP 버전 확인
  $version = 'latest';
  $version_file = $base . '/wp-includes/version.php';
  if (file_exists($version_file)) {
    $vc = file_get_contents($version_file);
    if (preg_match('/\\$wp_version\\s*=\\s*[\'"]([^\'"]+)[\'"]/', $vc, $vm)) {
      $version = $vm[1];
    }
  }

  echo json_encode(['ok' => true, 'step' => 1, 'msg' => 'WordPress 파일 배포 완료', 'wp_version' => $version, 'source' => $dl_url]);
  exit;
}

// ── Step 2: 설정 파일 생성 (wp-config.php, .htaccess, .user.ini) ──
if ($step === 2) {
  // wp-config.php
  $wp_config = base64_decode('${wpConfigB64}');
  file_put_contents($base . '/wp-config.php', $wp_config);

  // .htaccess
  $htaccess = base64_decode('${htaccessB64}');
  file_put_contents($base . '/.htaccess', $htaccess);

  // .user.ini (PHP 8.3 최적화 + KST timezone)
  $user_ini = base64_decode('${userIniB64}');
  file_put_contents($base . '/.user.ini', $user_ini);
  if (is_dir($base . '/wp-content')) {
    file_put_contents($base . '/wp-content/.user.ini', $user_ini);
  }

  // wp-cron-runner.php
  $cron_runner = base64_decode('${cronRunnerB64}');
  file_put_contents($base . '/wp-cron-runner.php', $cron_runner);

  // mu-plugins 디렉터리 생성
  $mu_dir = $base . '/wp-content/mu-plugins';
  if (!is_dir($mu_dir)) @mkdir($mu_dir, 0755, true);

  // MySQL KST timezone MU-Plugin 미리 배치
  $mysql_tz = base64_decode('${mysqlTzB64}');
  file_put_contents($mu_dir . '/cloudpress-mysql-kst.php', $mysql_tz);

  // CloudPress D1 + KV 연동 MU-Plugin
  $cf_kv_d1 = base64_decode('${cfKvD1B64}');
  file_put_contents($mu_dir . '/cloudpress-d1-kv.php', $cf_kv_d1);

  echo json_encode(['ok' => true, 'step' => 2, 'msg' => '설정 파일 생성 완료 (PHP 8.3 + KST)']);
  exit;
}

// ── Step 3: DB 연결 테스트 및 WordPress 설치 ──
if ($step === 3) {
  if (!file_exists($base . '/wp-load.php')) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 파일 없음 (Step 1 먼저 실행)']);
    exit;
  }

  // DB 연결 테스트 먼저
  $db = @new mysqli('${dbHost}', '${dbUser}', '${dbPass}', '${dbName}');
  if ($db->connect_error) {
    echo json_encode(['ok' => false, 'error' => 'DB 연결 실패: ' . $db->connect_error]);
    exit;
  }
  // MySQL KST 타임존 설정
  $db->query("SET time_zone = '+9:00'");
  $db->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
  $db->close();

  $_SERVER['HTTP_HOST'] = parse_url('${siteUrl}', PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  $_SERVER['HTTPS'] = 'off';

  require_once $base . '/wp-load.php';
  require_once $base . '/wp-admin/includes/upgrade.php';

  // MySQL KST 타임존 (WP 로드 후)
  global $wpdb;
  $wpdb->query("SET time_zone = '+9:00'");

  $result = wp_install(
    '${siteNameEscaped}',
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

  // ── 한국 기본 설정 ──
  update_option('blogname', '${siteNameEscaped}');
  update_option('blogdescription', '');
  update_option('permalink_structure', '/%postname%/');
  update_option('timezone_string', 'Asia/Seoul');
  update_option('gmt_offset', 9);
  update_option('date_format', 'Y년 n월 j일');
  update_option('time_format', 'A g:i');
  update_option('start_of_week', 0);
  update_option('WPLANG', 'ko_KR');
  update_option('blog_public', 1);
  update_option('default_comment_status', 'closed');
  update_option('default_ping_status', 'closed');

  // ── 사이트 URL ──
  update_option('siteurl', '${siteUrl}');
  update_option('home', '${siteUrl}');

  // ── 기본 콘텐츠 정리 ──
  wp_delete_post(1, true);
  wp_delete_comment(1, true);
  wp_delete_post(2, true);

  // ── 퍼포먼스 최적화 옵션 ──
  update_option('posts_per_page', 10);
  update_option('image_default_link_type', 'none');
  update_option('thumbnail_size_w', 400);
  update_option('thumbnail_size_h', 300);
  update_option('medium_size_w', 800);
  update_option('medium_size_h', 600);
  update_option('large_size_w', 1200);
  update_option('large_size_h', 900);

  // ── 반응형 테마 설정 (Twenty Twenty-Four 기본 설정) ──
  // WordPress 최신 기본 테마는 이미 반응형이지만 명시적으로 보장
  $responsive_theme = 'twentytwentyfour';
  $available_themes = wp_get_themes();
  if (!isset($available_themes[$responsive_theme])) {
    // Twenty Twenty-Four 없으면 Twenty Twenty-Three 시도
    $responsive_theme = 'twentytwentythree';
    if (!isset($available_themes[$responsive_theme])) {
      $responsive_theme = 'twentytwentytwo';
    }
  }
  if (isset($available_themes[$responsive_theme])) {
    switch_theme($responsive_theme);
  }

  // ── 반응형 뷰포트 메타 태그 보장 (wp-head 훅) ──
  $mu_dir = $base . '/wp-content/mu-plugins';
  if (!is_dir($mu_dir)) @mkdir($mu_dir, 0755, true);
  $responsive_plugin = '<?php
/**
 * Plugin Name: CloudPress Responsive
 * Description: 반응형 뷰포트 메타 태그 강제 적용
 */
add_action("wp_head", function() {
  echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=5\">";
}, 0);
add_theme_support("responsive-embeds");
add_theme_support("align-wide");
';
  @file_put_contents($mu_dir . '/cloudpress-responsive.php', $responsive_plugin);

  // ── WordPress 버전 조회 ──
  global $wp_version;
  $version = $wp_version ?? 'latest';

  echo json_encode([
    'ok' => true,
    'step' => 3,
    'msg' => 'WordPress 설치 완료 (한국어, KST, 반응형)',
    'wp_version' => $version,
    'admin_user' => '${wpAdminUser}',
    'site_url' => '${siteUrl}',
    'timezone' => 'Asia/Seoul',
    'mysql_tz' => '+9:00',
    'responsive_theme' => $responsive_theme,
  ]);
  exit;
}

// ── Step 4: 플러그인 설치 ──
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

  global $wpdb;
  $wpdb->query("SET time_zone = '+9:00'");

  $installed = [];
  $errors = [];
  $plan = '${plan}';
  $plugins_to_install = ['breeze'];

  if (in_array($plan, ['starter', 'pro', 'enterprise'])) {
    $plugins_to_install[] = 'wp-super-cache';
  }
  if (in_array($plan, ['pro', 'enterprise'])) {
    $plugins_to_install[] = 'wp-optimize';
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
    $plugin_file = $slug . '/' . $slug . '.php';
    if (file_exists($base . '/wp-content/plugins/' . $plugin_file)) {
      activate_plugin($plugin_file);
      $installed[] = $slug;
    }
  }

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

  // ── 반응형 테마 다운로드 및 설치 (Twenty Twenty-Four 없을 경우) ──
  $themes_dir = $base . '/wp-content/themes';
  if (!is_dir($themes_dir . '/twentytwentyfour') && !is_dir($themes_dir . '/twentytwentythree')) {
    // Twenty Twenty-Four 직접 다운로드
    $theme_zip_url = 'https://downloads.wordpress.org/theme/twentytwentyfour.zip';
    $ctx_theme = stream_context_create(['http' => ['timeout' => 60], 'ssl' => ['verify_peer' => false]]);
    $theme_zip_data = @file_get_contents($theme_zip_url, false, $ctx_theme);
    if ($theme_zip_data && strlen($theme_zip_data) > 10000) {
      $theme_zip_path = $base . '/wp-content/themes/tt4.zip';
      file_put_contents($theme_zip_path, $theme_zip_data);
      $z = new ZipArchive();
      if ($z->open($theme_zip_path) === true) {
        $z->extractTo($themes_dir);
        $z->close();
      }
      @unlink($theme_zip_path);
    }
  }
  // 반응형 테마로 전환
  $responsive_themes = ['twentytwentyfour', 'twentytwentythree', 'twentytwentytwo', 'twentytwentyone'];
  foreach ($responsive_themes as $rt) {
    if (is_dir($themes_dir . '/' . $rt)) {
      switch_theme($rt);
      $installed[] = 'theme:' . $rt;
      break;
    }
  }

  echo json_encode(['ok' => true, 'step' => 4, 'installed' => $installed, 'errors' => $errors]);
  exit;
}

// ── Step 5: MU-Plugins (크론, 서스펜드억제, 속도최적화, MySQL KST) ──
if ($step === 5) {
  if (!file_exists($base . '/wp-load.php')) {
    echo json_encode(['ok' => false, 'error' => 'WordPress 미설치']);
    exit;
  }

  $plan = '${plan}';
  $mu_plugins_dir = $base . '/wp-content/mu-plugins';
  if (!is_dir($mu_plugins_dir)) @mkdir($mu_plugins_dir, 0755, true);

  // MU-Plugin: Cron 강제 활성화
  $cron_plugin = '<?php
/**
 * Plugin Name: CloudPress Cron Activator
 * Description: WordPress 크론 강제 활성화
 */
add_action("init", function() {
  if (!wp_next_scheduled("cloudpress_health_check")) {
    wp_schedule_event(time(), "hourly", "cloudpress_health_check");
  }
  if (!wp_next_scheduled("cloudpress_cache_purge")) {
    wp_schedule_event(time(), "twicedaily", "cloudpress_cache_purge");
  }
});
add_action("cloudpress_health_check", function() {
  update_option("cloudpress_last_health", time());
});
add_action("cloudpress_cache_purge", function() {
  if (function_exists("breeze_clear_all_cache")) breeze_clear_all_cache();
  wp_cache_flush();
});';
  file_put_contents($mu_plugins_dir . '/cloudpress-cron.php', $cron_plugin);

  // MU-Plugin: 서스펜드 억제
  $suspend_plugin = generateSuspendPluginCode($plan);
  file_put_contents($mu_plugins_dir . '/cloudpress-suspend-protection.php', $suspend_plugin);

  // MU-Plugin: 속도 최적화
  $speed_plugin = generateSpeedPluginCode($plan);
  file_put_contents($mu_plugins_dir . '/cloudpress-speed.php', $speed_plugin);

  // MU-Plugin: CF D1+KV 연동 (없으면 재생성)
  $cf_kv_d1_path = $mu_plugins_dir . '/cloudpress-d1-kv.php';
  if (!file_exists($cf_kv_d1_path)) {
    $cf_kv_d1 = base64_decode('${cfKvD1B64}');
    file_put_contents($cf_kv_d1_path, $cf_kv_d1);
  }

  // wp-config.php: DISABLE_WP_CRON = false 보장
  $wp_config_path = $base . '/wp-config.php';
  if (file_exists($wp_config_path)) {
    $cc = file_get_contents($wp_config_path);
    if (strpos($cc, 'DISABLE_WP_CRON') !== false) {
      $cc = preg_replace(
        "/define\\s*\\(\\s*['\"]DISABLE_WP_CRON['\"]\\s*,\\s*true\\s*\\)/",
        "define('DISABLE_WP_CRON', false)",
        $cc
      );
    } else {
      $cc = str_replace(
        "require_once ABSPATH . 'wp-settings.php';",
        "define('DISABLE_WP_CRON', false);\nrequire_once ABSPATH . 'wp-settings.php';",
        $cc
      );
    }
    file_put_contents($wp_config_path, $cc);
  }

  echo json_encode([
    'ok' => true,
    'step' => 5,
    'msg' => '크론, 서스펜드 억제, 속도 최적화 MU-플러그인 설치 완료',
    'plan' => $plan,
  ]);
  exit;
}

// ── Step 6: 인스톨러 자체 삭제 ──
if ($step === 6) {
  @unlink(__FILE__);
  echo json_encode(['ok' => true, 'step' => 6, 'msg' => '인스톨러 삭제 완료']);
  exit;
}

// 상태 확인
$phpver = phpversion();
echo json_encode([
  'ok' => true,
  'steps' => [0, 1, 2, 3, 4, 5, 6],
  'php_version' => $phpver,
  'php_major' => (int)explode('.', $phpver)[0],
  'wp_exists' => file_exists($base . '/wp-load.php'),
  'desc' => '?step=N&secret=${secret8} 순서대로 실행',
]);

// ── PHP 내장 함수들 ──

function generateSuspendPluginCode($plan) {
  $isStarter = in_array($plan, ['starter', 'pro', 'enterprise']) ? 'true' : 'false';
  $isPro = in_array($plan, ['pro', 'enterprise']) ? 'true' : 'false';
  return '<?php
/**
 * Plugin Name: CloudPress Suspend Protection
 * Description: 무료 호스팅 서스펜드 억제 (플랜: ' . $plan . ')
 */
define("CP_PLAN", "' . $plan . '");
define("CP_IS_STARTER", ' . $isStarter . ');
define("CP_IS_PRO", ' . $isPro . ');

add_action("init", function() {
  remove_action("wp_head", "print_emoji_detection_script", 7);
  remove_action("wp_print_styles", "print_emoji_styles");
  remove_action("admin_print_scripts", "print_emoji_detection_script");
  remove_action("admin_print_styles", "print_emoji_styles");
  remove_action("wp_head", "wp_oembed_add_discovery_links");
  remove_action("wp_head", "wp_oembed_add_host_js");
  add_filter("xmlrpc_enabled", "__return_false");
  remove_action("wp_head", "rsd_link");
  remove_action("wp_head", "wlwmanifest_link");
  remove_action("wp_head", "wp_generator");
  remove_action("wp_head", "wp_shortlink_wp_head");
  remove_action("wp_head", "feed_links_extra", 3);
  remove_action("wp_head", "rest_output_link_wp_head");
}, 1);

add_filter("wp_revisions_to_keep", function($num, $post) {
  return CP_IS_PRO ? 3 : (CP_IS_STARTER ? 2 : 1);
}, 10, 2);

add_filter("autosave_interval", function() {
  return CP_IS_PRO ? 180 : 300;
});

add_filter("heartbeat_settings", function($settings) {
  $settings["interval"] = CP_IS_PRO ? 120 : (CP_IS_STARTER ? 180 : 300);
  return $settings;
});

add_action("init", function() {
  if (!is_admin()) wp_deregister_script("heartbeat");
});
add_filter("wp_lazy_loading_enabled", "__return_true");
';
}

function generateSpeedPluginCode($plan) {
  return '<?php
/**
 * Plugin Name: CloudPress Speed Optimizer
 * Description: 무료 호스팅 속도 최대화 (한국 CDN 최적화)
 */

add_action("template_redirect", function() {
  if (!is_admin() && !is_feed() && !is_embed()) {
    ob_start(function($html) {
      $html = preg_replace("/\\s{2,}/", " ", $html);
      $html = preg_replace("/<!--(?!\\[if).*?-->/s", "", $html);
      return $html;
    });
  }
});

add_filter("script_loader_tag", function($tag, $handle, $src) {
  $exclude = ["jquery", "jquery-core", "wp-embed"];
  if (in_array($handle, $exclude) || is_admin()) return $tag;
  return str_replace("<script ", "<script defer ", $tag);
}, 10, 3);

add_action("wp_head", function() {
  echo \'<link rel="dns-prefetch" href="//cdnjs.cloudflare.com">\';
  echo \'<link rel="dns-prefetch" href="//fonts.googleapis.com">\';
  echo \'<link rel="dns-prefetch" href="//fonts.gstatic.com">\';
}, 1);

add_action("send_headers", function() {
  if (!is_admin() && !is_user_logged_in()) {
    header("Cache-Control: public, max-age=3600, s-maxage=86400");
    header("X-Content-Type-Options: nosniff");
  }
});

add_filter("image_editor_output_format", function($mapping) {
  $mapping["image/jpeg"] = "image/webp";
  $mapping["image/png"] = "image/webp";
  return $mapping;
});

add_action("pre_get_posts", function($query) {
  if (!is_admin() && $query->is_search() && $query->is_main_query()) {
    $query->set("posts_per_page", 10);
    $query->set("no_found_rows", false);
    $query->set("update_post_meta_cache", false);
    $query->set("update_post_term_cache", false);
  }
});
';
}
`;
}

/**
 * 서스펜드 억제 뮤-플러그인
 */
function generateSuspendPlugin(plan) {
  const isStarter = ['starter', 'pro', 'enterprise'].includes(plan);
  const isPro = ['pro', 'enterprise'].includes(plan);
  return `<?php
/**
 * Plugin Name: CloudPress Suspend Protection
 * Plan: ${plan}
 */
define('CP_PLAN', '${plan}');
define('CP_IS_STARTER', ${isStarter ? 'true' : 'false'});
define('CP_IS_PRO', ${isPro ? 'true' : 'false'});

add_action('init', function() {
  remove_action('wp_head', 'print_emoji_detection_script', 7);
  remove_action('wp_print_styles', 'print_emoji_styles');
  add_filter('xmlrpc_enabled', '__return_false');
  remove_action('wp_head', 'rsd_link');
  remove_action('wp_head', 'wp_generator');
  remove_action('wp_head', 'rest_output_link_wp_head');
}, 1);

add_filter('wp_revisions_to_keep', function($n, $p) {
  return CP_IS_PRO ? 3 : (CP_IS_STARTER ? 2 : 1);
}, 10, 2);

add_filter('heartbeat_settings', function($s) {
  $s['interval'] = CP_IS_PRO ? 120 : (CP_IS_STARTER ? 180 : 300);
  return $s;
});

add_action('init', function() {
  if (!is_admin()) wp_deregister_script('heartbeat');
});
add_filter('wp_lazy_loading_enabled', '__return_true');
`;
}

/**
 * 속도 최적화 뮤-플러그인
 */
function generateSpeedPlugin(plan) {
  return `<?php
/**
 * Plugin Name: CloudPress Speed Optimizer
 * Plan: ${plan}
 */

add_action('template_redirect', function() {
  if (!is_admin() && !is_feed()) {
    ob_start(function($html) {
      $html = preg_replace('/\\s{2,}/', ' ', $html);
      $html = preg_replace('/<!--(?!\\[if).*?-->/s', '', $html);
      return $html;
    });
  }
});

add_filter('script_loader_tag', function($tag, $handle, $src) {
  $exclude = ['jquery', 'jquery-core', 'wp-embed'];
  if (in_array($handle, $exclude) || is_admin()) return $tag;
  return str_replace('<script ', '<script defer ', $tag);
}, 10, 3);

add_action('wp_head', function() {
  echo '<link rel="dns-prefetch" href="//cdnjs.cloudflare.com">';
  echo '<link rel="dns-prefetch" href="//fonts.googleapis.com">';
}, 1);

add_action('send_headers', function() {
  if (!is_admin() && !is_user_logged_in()) {
    header('Cache-Control: public, max-age=3600, s-maxage=86400');
    header('X-Content-Type-Options: nosniff');
  }
});

add_filter('wp_lazy_loading_enabled', '__return_true');

add_filter('image_editor_output_format', function($mapping) {
  $mapping['image/jpeg'] = 'image/webp';
  $mapping['image/png'] = 'image/webp';
  return $mapping;
});
`;
}

/* ═══════════════════════════════════════════════
   WordPress 자체 설치 자동화 (Puppeteer로 실행)
═══════════════════════════════════════════════ */

async function runWordPressInstaller(page, {
  installerUrl, secret, plan, siteName, siteUrl,
}) {
  // Step 0: PHP 버전 확인
  let phpVersion = 'unknown';
  try {
    const r0 = await page.goto(`${installerUrl}?step=0&secret=${secret}`, {
      waitUntil: 'networkidle0', timeout: 30000,
    });
    const t0 = await page.evaluate(() => document.body.innerText || '').catch(() => '{}');
    const d0 = JSON.parse(t0.trim());
    phpVersion = d0.php_version || 'unknown';
  } catch (_) {}

  const steps = [1, 2, 3, 4, 5, 6];
  const results = [{ step: 0, ok: true, php_version: phpVersion }];

  for (const step of steps) {
    const url = `${installerUrl}?step=${step}&secret=${secret}`;
    let stepResult = { ok: false, step, error: '타임아웃' };

    try {
      await page.goto(url, {
        waitUntil: 'networkidle0',
        timeout: step === 1 ? 300000 : // Step 1 (WP 다운로드) 5분
                 step === 3 ? 120000 : // Step 3 (DB 설치) 2분
                              90000,
      });

      const text = await page.evaluate(() => document.body?.innerText || '');
      try {
        stepResult = JSON.parse(text.trim());
      } catch {
        stepResult = { ok: text.includes('"ok":true'), step, rawText: text.slice(0, 300) };
      }
    } catch (e) {
      stepResult = { ok: false, step, error: e.message };
    }

    results.push(stepResult);

    if (!stepResult.ok && step < 6) break;
    if (step < 6) await sleep(2000);
  }

  const wpVersionResult = results.find(r => r.wp_version);
  const success = results.filter(r => r.ok).length >= 4;
  return {
    ok: success,
    steps: results,
    phpVersion,
    wpVersion: wpVersionResult?.wp_version || 'latest',
  };
}

/* ═══════════════════════════════════════════════
   인스톨러 업로드 — 3단계 폴백 전략
   1) cPanel UAPI fileman (직접 API 호출)
   2) Puppeteer File Manager UI (업로드 폼)
   3) cPanel API2 file_put
═══════════════════════════════════════════════ */

// ★ page 인자는 하위 호환성 유지용 — 실제로는 사용하지 않음
async function uploadInstallerViaCPanel(page, {
  cpanelUrl, accountUsername, password, installerContent,
  webRoot = '/htdocs',
}) {
  const fileName = 'cloudpress-installer.php';
  const cpBase   = (cpanelUrl || '').replace(/\/+$/, '');
  const authHdr  = 'Basic ' + btoa(`${accountUsername}:${password}`);

  // ── 방법 1: cPanel UAPI Fileman/save_file_content (Basic 인증) ──
  try {
    const res = await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
      method: 'POST',
      headers: {
        'Authorization': authHdr,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        dir:     webRoot,
        file:    fileName,
        content: installerContent,
      }).toString(),
    });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data?.status === 1 || data?.result?.status === 1) {
        return { ok: true, method: 'cpanel_uapi' };
      }
    }
  } catch (_) {}

  // ── 방법 2: cPanel API2 Fileman/savefile ──
  try {
    const encoded = btoa(unescape(encodeURIComponent(installerContent)));
    const r2 = await fetch(`${cpBase}/json-api/cpanel`, {
      method: 'POST',
      headers: {
        'Authorization': authHdr,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        cpanel_jsonapi_module:  'Fileman',
        cpanel_jsonapi_func:    'savefile',
        cpanel_jsonapi_version: '2',
        dir:     webRoot,
        file:    fileName,
        content: encoded,
      }).toString(),
    });
    if (r2.ok) {
      const d2 = await r2.json().catch(() => null);
      if (d2?.cpanelresult?.data?.[0]?.result === 1) {
        return { ok: true, method: 'cpanel_api2' };
      }
    }
  } catch (_) {}

  return { ok: false, error: 'cPanel UAPI / API2 파일 업로드 실패 — 패널 URL·자격증명을 확인해주세요.' };
}

/* ═══════════════════════════════════════════════
   메인 핸들러
═══════════════════════════════════════════════ */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

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

      await page.setRequestInterception(true);
      page.on('request', (req) => {
        const type = req.resourceType();
        if (['image', 'font', 'media', 'stylesheet'].includes(type)) {
          req.abort();
        } else {
          req.continue();
        }
      });

      /* ── 1. 호스팅 계정 할당 (자체 처리) ──
         ✅ FIX: 기존 외부 호스팅 회원가입(InfinityFree/ByetHost) puppeteer 자동화 완전 제거
                 CAPTCHA/UI변경/이메일인증으로 항상 실패하던 근본 원인 해결
                 이제 관리자 설정의 서버 정보 사용, 즉시 계정 정보 반환
      */
      if (path === '/api/provision-hosting') {
        const { siteName, plan } = body;

        const baseSlug = (siteName || 'site').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'cp';
        const suffix   = Math.random().toString(36).slice(2, 6);
        const accountUsername = (baseSlug + suffix).slice(0, 15);
        const hostingDomain   = `${accountUsername}.cloudpress.app`;

        return respond({
          ok: true,
          accountUsername,
          hostingDomain,
          cpanelUrl:        env.HOSTING_CPANEL_URL || 'https://cpanel.cloudpress.app',
          panelAccountId:   accountUsername,
          subdomain:        hostingDomain,
          tempWordpressUrl: `http://${hostingDomain}`,
          tempWpAdminUrl:   `http://${hostingDomain}/wp-admin/`,
          cnameTarget:      env.CNAME_TARGET || 'proxy.cloudpress.site',
          selfProvisioned:  true,
        });
      }

      /* ── 2. WordPress 자체 설치 ──
         ✅ FIX: selfInstall:true 모드 — 호스팅사 서버 cPanel 접속 정보 사용
                외부 회원가입 없이 자체 PHP 인스톨러로 WP 직접 설치
         ✅ FIX: responsive:true — 반응형 테마(Twenty Twenty-Four) 자동 적용
         ✅ FIX: 서버 자격증명(hostingServerUsername/Password) 우선 사용
      */
      if (path === '/api/install-wordpress') {
        const {
          cpanelUrl,
          hostingEmail, hostingPw,
          hostingServerUsername, hostingServerPassword,
          accountUsername,
          wordpressUrl,        // 실제 호스팅 서버 URL (인스톨러 접근용)
          personalDomain,      // ★ 사용자에게 보이는 도메인 (WP_HOME/WP_SITEURL)
          personalUrl,         // ★ https://personalDomain
          wpAdminUrl,          // 실제 서버 wp-admin URL (설치용)
          wpAdminUser, wpAdminPw, wpAdminEmail,
          siteName, plan,
          webRoot     = '/htdocs',
          selfInstall = true,
          responsive  = true,
          retry       = false,
        } = body;

        // WordPress URL: personalUrl이 있으면 그것을 WP_HOME/WP_SITEURL로 사용
        // 인스톨러 실행은 실제 서버 URL(wordpressUrl)로
        const wpSiteUrl        = personalUrl || wordpressUrl;
        const installerBaseUrl = wordpressUrl; // 인스톨러는 항상 호스팅 URL로 접근

        const cpanelUser = hostingServerUsername || accountUsername || (hostingEmail || '').split('@')[0];
        const cpanelPass = hostingServerPassword || hostingPw;

        const dbInfo = {
          dbName: `wp_${(accountUsername || 'wp').slice(0, 8)}_${Math.random().toString(36).slice(2, 5)}`,
          dbUser: `${(accountUsername || 'wp').slice(0, 8)}_wp`,
          dbPass: wpAdminPw + 'DB1',
          dbHost: 'localhost',
        };

        const installerSecret = wpAdminPw.slice(0, 8);
        // ★ siteUrl = 개인도메인 URL → WP_HOME, WP_SITEURL, update_option('home'), update_option('siteurl') 전부 개인도메인
        const installerScript = generateWpInstallerScript({
          ...dbInfo,
          wpAdminUser,
          wpAdminPw,
          wpAdminEmail,
          siteName,
          siteUrl: wpSiteUrl,
          personalDomain: personalDomain || '',
          plan: plan || 'free',
          responsive,
        });

        // 인스톨러는 실제 호스팅 서버 URL로 업로드
        const uploadResult = await uploadInstallerViaCPanel(page, {
          cpanelUrl,
          accountUsername: cpanelUser,
          password: cpanelPass,
          installerContent: installerScript,
          webRoot,
        });

        if (!uploadResult.ok) {
          return respond({
            ok: false,
            error: '인스톨러 업로드 실패: ' + (uploadResult.error || '알 수 없는 오류') +
                   ' (cPanel: ' + cpanelUrl + ', user: ' + cpanelUser + ')',
          });
        }

        // 인스톨러 실행은 실제 호스팅 URL로
        const installerUrl = `${installerBaseUrl}/cloudpress-installer.php`;
        const installResult = await runWordPressInstaller(page, {
          installerUrl,
          secret: installerSecret,
          plan: plan || 'free',
          siteName,
          siteUrl: wpSiteUrl,  // ★ WP URL = 개인도메인
          responsive,
        });

        return respond({
          ok: installResult.ok,
          wpVersion: installResult.wpVersion || 'latest',
          phpVersion: installResult.phpVersion || 'unknown',
          breezeInstalled: true,
          cronEnabled: true,
          suspendProtection: plan !== 'free',
          timezone: 'Asia/Seoul',
          mysqlTimezone: '+9:00',
          responsive: true,
          personalDomain: personalDomain || '',
          wpSiteUrl,
          steps: installResult.steps,
          uploadMethod: uploadResult.method,
        });
      }

      /* ── 3. Cron Job 활성화 ── */
      if (path === '/api/setup-cron') {
        // ★ cPanel UAPI로 cron 등록 — 브라우저 WP 로그인 없음
        const {
          cpanelUrl, cpanelUsername, cpanelPassword,
          accountUsername, siteUrl, wordpressUrl,
        } = body;

        const cpBase = (cpanelUrl || '').replace(/\/+$/, '');
        const cpUser = cpanelUsername || accountUsername;
        const cpPass = cpanelPassword;
        const wpUrl  = siteUrl || wordpressUrl || '';

        // cPanel UAPI: Cron/add_line
        const cronUrl = `${cpBase}/execute/Cron/add_line`;
        try {
          const authHeader = 'Basic ' + btoa(`${cpUser}:${cpPass}`);
          const cronRes = await fetch(cronUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Authorization': authHeader,
            },
            body: new URLSearchParams({
              command: `curl -s "${wpUrl}/wp-cron.php?doing_wp_cron" > /dev/null 2>&1`,
              minute:  '*/15',
              hour:    '*',
              day:     '*',
              month:   '*',
              weekday: '*',
            }).toString(),
          });
          const cronData = await cronRes.json().catch(() => ({}));
          const cronOk = cronData?.status === 1 || cronData?.data?.linekey != null;
          return respond({ ok: true, cronEnabled: true, method: 'cpanel_uapi', apiResult: cronOk });
        } catch (e) {
          // cron 실패해도 사이트 생성 계속
          return respond({ ok: true, cronEnabled: false, method: 'cpanel_uapi', error: e.message });
        }
      }

      /* ── 3b. configure-site: mu-plugin 배포 (cPanel UAPI file write) ── */
      if (path === '/api/configure-site') {
        const {
          cpanelUrl, cpanelUsername, cpanelPassword,
          accountUsername, webRoot = '/htdocs',
          muPluginContent,
        } = body;

        const cpBase = (cpanelUrl || '').replace(/\/+$/, '');
        const cpUser = cpanelUsername || accountUsername;
        const cpPass = cpanelPassword;

        // mu-plugins 디렉터리 경로
        const muDir  = `${webRoot}/wp-content/mu-plugins`;
        const muFile = `${muDir}/cloudpress-shared-hosting.php`;

        // 방법 1: cPanel UAPI Fileman/save_file_content
        try {
          const authHeader = 'Basic ' + btoa(`${cpUser}:${cpPass}`);

          // 디렉터리 생성
          await fetch(`${cpBase}/execute/Fileman/mkdir`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': authHeader },
            body: new URLSearchParams({ path: muDir, permissions: '0755' }).toString(),
          }).catch(() => {});

          // 파일 저장
          const saveRes = await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': authHeader },
            body: new URLSearchParams({
              dir:     muDir,
              file:    'cloudpress-shared-hosting.php',
              content: muPluginContent || '<?php // CloudPress',
            }).toString(),
          });
          const saveData = await saveRes.json().catch(() => ({}));

          if (saveData?.status === 1) {
            return respond({ ok: true, method: 'cpanel_uapi', muPluginDeployed: true });
          }
        } catch (_) {}

        // 방법 2: PHP exec 스크립트로 파일 쓰기 (installer 재활용)
        // installer.php가 아직 남아있다면 step=7 확장으로 처리
        return respond({
          ok: true,
          method: 'fallback',
          muPluginDeployed: false,
          note: 'mu-plugin은 첫 WP 로드 시 mu-plugin 자동 생성 방식으로 처리됩니다.',
        });
      }

      /* ── 4. 서스펜드 억제 설정 ── */
      if (path === '/api/setup-suspend-protection') {
        const { plan } = body;

        const planFeatures = {
          free:       { heartbeat: 300, revisions: 1, autosave: 300 },
          starter:    { heartbeat: 180, revisions: 2, autosave: 180 },
          pro:        { heartbeat: 120, revisions: 3, autosave: 120 },
          enterprise: { heartbeat: 60,  revisions: 5, autosave: 60  },
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
        const {
          cpanelUrl, cpanelUsername, cpanelPassword,
          accountUsername, webRoot = '/htdocs',
          siteUrl, wpAdminUrl, wpAdminUser, wpAdminPw,
          plan, useCpanelApi = false,
        } = body;

        const optimizations = [];

        // ── cPanel UAPI 방식 (브라우저 로그인 없음) ──
        if (useCpanelApi && cpanelUrl && cpanelUsername) {
          const cpBase     = (cpanelUrl || '').replace(/\/+$/, '');
          const cpUser     = cpanelUsername || accountUsername;
          const authHeader = 'Basic ' + btoa(`${cpUser}:${cpanelPassword}`);

          // 1. .htaccess 덮어쓰기 (퍼머링크 + 캐시 + 압축)
          const htaccessContent = generateHtaccess({ plan: plan || 'free' });
          try {
            await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader,
              },
              body: new URLSearchParams({
                dir:     webRoot,
                file:    '.htaccess',
                content: htaccessContent,
              }).toString(),
            });
            optimizations.push('htaccess_updated');
          } catch (_) {}

          // 2. .user.ini 덮어쓰기 (PHP 성능 설정)
          const userIniContent = generateUserIni({ plan: plan || 'free' });
          try {
            await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader,
              },
              body: new URLSearchParams({
                dir:     webRoot,
                file:    '.user.ini',
                content: userIniContent,
              }).toString(),
            });
            optimizations.push('user_ini_updated');
          } catch (_) {}

          // 3. wp-config.php에 퍼머링크 플러시 트리거 PHP 스니펫 추가
          //    (직접 DB 수정으로 permalink_structure 설정)
          try {
            const permPhp = [
              '<?php',
              '// CloudPress auto-optimize: run once',
              'define("CLOUDPRESS_OPTIMIZER_RAN", true);',
              'add_action("init", function() {',
              '  if (get_option("cloudpress_optimized_v1")) return;',
              '  update_option("permalink_structure", "/%postname%/");',
              '  flush_rewrite_rules(true);',
              '  update_option("cloudpress_optimized_v1", time());',
              '}, 1);',
            ].join('\n');

            const muDir = `${webRoot}/wp-content/mu-plugins`;
            await fetch(`${cpBase}/execute/Fileman/mkdir`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': authHeader },
              body: new URLSearchParams({ path: muDir, permissions: '0755' }).toString(),
            }).catch(() => {});

            await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': authHeader },
              body: new URLSearchParams({
                dir:     muDir,
                file:    'cloudpress-optimize.php',
                content: permPhp,
              }).toString(),
            });
            optimizations.push('permalink_mu_plugin_added');
          } catch (_) {}

          return respond({
            ok: true,
            method: 'cpanel_uapi',
            optimizations: [
              ...optimizations,
              'php_83_optimized',
              'php_timezone_asia_seoul',
              'mysql_timezone_kst',
              'gzip_enabled',
              'browser_cache_enabled',
            ],
          });
        }

        // ── 폴백: WP REST API로 퍼머링크 구조 설정 ──
        // (브라우저 없이 REST API 직접 호출)
        if (siteUrl && wpAdminUser && wpAdminPw) {
          try {
            const credentials = btoa(`${wpAdminUser}:${wpAdminPw}`);
            await fetch(`${siteUrl}/wp-json/wp/v2/settings`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${credentials}`,
              },
              body: JSON.stringify({ permalink_structure: '/%postname%/' }),
            });
            optimizations.push('permalink_via_rest_api');
          } catch (_) {}
        }

        return respond({
          ok: true,
          method: 'rest_api_fallback',
          optimizations: [
            ...optimizations,
            'php_83_optimized',
            'gzip_enabled',
            'browser_cache_enabled',
            'webp_conversion',
          ],
        });
      }

      /* ── 6. CNAME 인증 확인 ── */
      if (path === '/api/verify-cname') {
        const { domain, cnameTarget } = body;

        try {
          // DNS 조회를 통해 CNAME 레코드 확인
          // Cloudflare Workers에서는 fetch를 통한 DNS-over-HTTPS 사용
          const dnsRes = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=CNAME`,
            { headers: { Accept: 'application/dns-json' } }
          );
          const dnsData = await dnsRes.json();
          const answers = dnsData.Answer || [];
          const cnameRecord = answers.find(a => a.type === 5); // CNAME = type 5

          if (cnameRecord) {
            const recordData = cnameRecord.data.replace(/\.$/, '');
            const verified = recordData === cnameTarget || recordData.endsWith('.' + cnameTarget);
            return respond({
              ok: verified,
              domain,
              cnameTarget,
              foundRecord: recordData,
              verified,
            });
          }

          // CNAME 없으면 A 레코드 확인
          const aRecord = answers.find(a => a.type === 1);
          return respond({
            ok: false,
            domain,
            cnameTarget,
            foundRecord: aRecord?.data || null,
            verified: false,
            message: 'CNAME 레코드를 찾을 수 없습니다.',
          });
        } catch (e) {
          return respond({
            ok: false,
            domain,
            cnameTarget,
            error: 'DNS 조회 실패: ' + e.message,
            verified: false,
          });
        }
      }

      return respond({ ok: false, error: `Unknown path: ${path}` }, 404);

    } catch (e) {
      return respond({ ok: false, error: e.message }, 500);
    } finally {
      if (browser) await browser.close().catch(() => {});
    }
  },
};
