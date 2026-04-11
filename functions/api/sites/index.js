// functions/api/sites/index.js
// CloudPress v9.0 — Worker 완전 제거, Pages Functions에서 직접 cPanel UAPI 프로비저닝
// ✅ v9 변경사항:
//   1. Puppeteer Worker 의존성 완전 제거
//   2. cPanel UAPI로 PHP installer 업로드 → fetch()로 각 Step 실행
//   3. clone_zip_url 불필요 — WP 직접 다운로드 + WP-CLI phar 자동 설치
//   4. 플러그인: breeze(전 플랜) + wp-super-cache(starter+) + wp-optimize(pro+)
//   5. 백그라운드 waitUntil 처리 + 실시간 폴링

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

async function getCnameTarget(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key='cname_target'").first();
    return row?.value || env.CNAME_TARGET || 'proxy.cloudpress.site';
  } catch { return 'proxy.cloudpress.site'; }
}

async function getGlobalSettings(env) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT key, value FROM settings WHERE key IN (
        'cf_api_token','cf_account_id','cloudflare_cdn_enabled',
        'auto_ssl','site_domain','cname_target'
      )`
    ).all();
    const cfg = {};
    for (const r of (results || [])) cfg[r.key] = r.value;
    return cfg;
  } catch { return {}; }
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

async function incrementVpAccountSites(env, vpAccountId) {
  try {
    await env.DB.prepare(
      `UPDATE vp_accounts SET current_sites=current_sites+1, updated_at=datetime('now') WHERE id=?`
    ).bind(vpAccountId).run();
  } catch (_) {}
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

/* ══════════════════════════════════════════════════════════════
   cPanel UAPI 헬퍼
══════════════════════════════════════════════════════════════ */

// cPanel UAPI로 파일 저장
async function cpanelSaveFile(cpBase, authHdr, dir, filename, content) {
  // 방법 1: UAPI
  try {
    const res = await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
      method: 'POST',
      headers: { 'Authorization': authHdr, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ dir, file: filename, content }).toString(),
    });
    const data = await res.json().catch(() => ({}));
    if (data?.status === 1 || data?.result?.status === 1) return { ok: true, method: 'uapi' };
  } catch (_) {}

  // 방법 2: API2
  try {
    const encoded = btoa(unescape(encodeURIComponent(content)));
    const res2 = await fetch(`${cpBase}/json-api/cpanel`, {
      method: 'POST',
      headers: { 'Authorization': authHdr, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        cpanel_jsonapi_module: 'Fileman', cpanel_jsonapi_func: 'savefile',
        cpanel_jsonapi_version: '2', dir, file: filename, content: encoded,
      }).toString(),
    });
    const d2 = await res2.json().catch(() => ({}));
    if (d2?.cpanelresult?.data?.[0]?.result === 1) return { ok: true, method: 'api2' };
  } catch (_) {}

  return { ok: false, error: `파일 저장 실패: ${dir}/${filename}` };
}

// cPanel UAPI로 디렉터리 생성
async function cpanelMkdir(cpBase, authHdr, path) {
  try {
    await fetch(`${cpBase}/execute/Fileman/mkdir`, {
      method: 'POST',
      headers: { 'Authorization': authHdr, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ path, permissions: '0755' }).toString(),
    });
  } catch (_) {}
}

// installer.php를 fetch로 실행 (각 step)
async function runInstallerStep(installerUrl, secret, step, timeoutMs = 120000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${installerUrl}?step=${step}&secret=${encodeURIComponent(secret)}`, {
      signal: controller.signal,
    });
    const text = await res.text();
    try { return JSON.parse(text.trim()); }
    catch { return { ok: text.includes('"ok":true'), step, raw: text.slice(0, 200) }; }
  } catch (e) {
    if (e.name === 'AbortError') return { ok: false, step, error: `Step ${step} 타임아웃 (${timeoutMs/1000}초)` };
    return { ok: false, step, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}

/* ══════════════════════════════════════════════════════════════
   PHP 설치 스크립트 생성
   — WP 다운로드 → 설정 → DB 설치 → 플러그인(breeze 등) → mu-plugin → 자체 삭제
══════════════════════════════════════════════════════════════ */
function buildInstallerPHP({ dbName, dbUser, dbPass, dbHost, siteUrl, siteName,
  wpAdminUser, wpAdminPw, wpAdminEmail, plan, secret }) {

  // wp-config.php 내용
  const authKeys = Array.from({ length: 8 }, () =>
    Math.random().toString(36).repeat(4).slice(0, 64)
  );
  const wpConfigContent = `<?php
define('DB_NAME',     '${dbName}');
define('DB_USER',     '${dbUser}');
define('DB_PASSWORD', '${dbPass}');
define('DB_HOST',     '${dbHost}');
define('DB_CHARSET',  'utf8mb4');
define('DB_COLLATE',  'utf8mb4_unicode_ci');
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
define('WPLANG',     'ko_KR');
define('WP_MEMORY_LIMIT',     '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');
define('WP_POST_REVISIONS', 3);
define('EMPTY_TRASH_DAYS',  7);
define('WP_CACHE', true);
define('COMPRESS_CSS',         true);
define('COMPRESS_SCRIPTS',     true);
define('CONCATENATE_SCRIPTS',  false);
define('AUTOSAVE_INTERVAL',    300);
define('WP_CRON_LOCK_TIMEOUT', 60);
define('DISABLE_WP_CRON',      false);
define('DISALLOW_FILE_EDIT',   true);
define('WP_DEBUG',         false);
define('WP_DEBUG_LOG',     false);
define('WP_DEBUG_DISPLAY', false);
define('FORCE_SSL_ADMIN',  false);
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
`;

  const htaccessContent = `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
<IfModule mod_deflate.c>
  AddOutputFilterByType DEFLATE text/html text/plain text/css text/javascript application/javascript application/json
</IfModule>
<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType image/jpeg "access plus 30 days"
  ExpiresByType image/png  "access plus 30 days"
  ExpiresByType image/webp "access plus 30 days"
  ExpiresByType text/css   "access plus 7 days"
  ExpiresByType application/javascript "access plus 7 days"
</IfModule>
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options nosniff
  Header always set X-Frame-Options SAMEORIGIN
</IfModule>
FileETag None
`;

  const userIniContent = `date.timezone = Asia/Seoul
memory_limit = 256M
max_execution_time = 120
post_max_size = 256M
upload_max_filesize = 256M
max_input_vars = 10000
opcache.enable = 1
opcache.memory_consumption = 128
opcache.max_accelerated_files = 10000
display_errors = Off
`;

  const muPluginContent = `<?php
/**
 * Plugin Name: CloudPress Core
 * Description: REST API 활성화, MySQL KST, Cron 설정, 성능 최적화
 */
if (!defined('ABSPATH')) exit;

add_action('init', function() {
  global $wpdb;
  $wpdb->query("SET time_zone = '+9:00'");
  $wpdb->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
}, 1);

add_filter('rest_enabled',        '__return_true');
add_filter('rest_jsonp_enabled',  '__return_true');
add_filter('block_local_requests','__return_false');

if (!defined('DISABLE_WP_CRON')) define('DISABLE_WP_CRON', false);
define('WP_CRON_LOCK_TIMEOUT', 120);

add_action('init', function() {
  if (get_option('cloudpress_core_initialized')) return;
  update_option('permalink_structure', '/%postname%/');
  flush_rewrite_rules(true);
  update_option('timezone_string', 'Asia/Seoul');
  update_option('gmt_offset',      9);
  update_option('date_format',     'Y년 n월 j일');
  update_option('time_format',     'H:i');
  update_option('start_of_week',   0);
  update_option('default_comment_status', 'closed');
  update_option('comment_moderation', 1);
  update_option('cloudpress_core_initialized', time());
}, 99);

remove_action('wp_head', 'wp_generator');
remove_action('wp_head', 'wlwmanifest_link');
remove_action('wp_head', 'rsd_link');
add_filter('xmlrpc_enabled', '__return_false');
add_filter('heartbeat_settings', function($s){ $s['interval']=120; return $s; });
`;

  // base64 인코딩 (PHP의 base64_decode로 디코딩)
  const toB64 = (str) => btoa(unescape(encodeURIComponent(str)));
  const wpConfigB64  = toB64(wpConfigContent);
  const htaccessB64  = toB64(htaccessContent);
  const userIniB64   = toB64(userIniContent);
  const muPluginB64  = toB64(muPluginContent);

  const siteNameEsc  = siteName.replace(/'/g, "\\'").replace(/\\/g, '\\\\');
  const pluginList   = ['breeze'];
  if (['starter','pro','enterprise'].includes(plan)) pluginList.push('wp-super-cache');
  if (['pro','enterprise'].includes(plan))           pluginList.push('wp-optimize');
  const pluginListPHP = pluginList.map(p => `'${p}'`).join(', ');

  return `<?php
/**
 * CloudPress WordPress Installer v9.0
 * Worker-free: cPanel UAPI + direct HTTP fetch
 * 사용 후 자동 삭제 (Step 6)
 */
@set_time_limit(600);
@ini_set('memory_limit','512M');
@ini_set('display_errors',0);
@ini_set('date.timezone','Asia/Seoul');
header('Content-Type: application/json; charset=utf-8');

$step   = (int)($_GET['step']   ?? 0);
$secret = $_GET['secret'] ?? '';
if ($secret !== '${secret}') { echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
$base = __DIR__;

// ── Step 0: PHP 환경 확인 ──
if ($step === 0) {
  echo json_encode(['ok'=>true,'step'=>0,'php'=>phpversion(),'php_ok'=>(PHP_MAJOR_VERSION>=8)]);
  exit;
}

// ── Step 1: WordPress 다운로드 + 압축 해제 ──
if ($step === 1) {
  $zip_path = $base.'/wp_install.zip';
  $urls = [
    'https://ko.wordpress.org/latest-ko_KR.zip',
    'https://downloads.wordpress.org/release/ko_KR/latest.zip',
    'https://wordpress.org/latest.zip',
  ];
  $ok = false; $src_url = '';
  foreach ($urls as $url) {
    $ctx = stream_context_create(['http'=>['timeout'=>180,'follow_location'=>true,'max_redirects'=>5],
                                  'ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data && strlen($data) > 500000) {
      file_put_contents($zip_path, $data); $ok=true; $src_url=$url; break;
    }
  }
  if (!$ok) { echo json_encode(['ok'=>false,'error'=>'WP 다운로드 실패']); exit; }

  $zip = new ZipArchive();
  if ($zip->open($zip_path) !== true) { echo json_encode(['ok'=>false,'error'=>'ZIP 해제 실패']); exit; }
  $tmp = $base.'/wp_tmp_'.time();
  $zip->extractTo($tmp); $zip->close(); @unlink($zip_path);

  $src = null;
  foreach (['wordpress','wordpress-ko_KR'] as $n) {
    if (is_dir("$tmp/$n")) { $src = "$tmp/$n"; break; }
  }
  if (!$src) { $dirs=glob("$tmp/*",GLOB_ONLYDIR); $src=$dirs[0]??null; }
  if (!$src) { echo json_encode(['ok'=>false,'error'=>'WP 폴더 없음']); exit; }

  function cp_mv($s,$d){ if(!is_dir($d))@mkdir($d,0755,true); foreach(@scandir($s)?:[] as $i){ if($i==='.'||$i==='..') continue; $sf="$s/$i"; $df="$d/$i"; is_dir($sf)?cp_mv($sf,$df):(@rename($sf,$df)||@copy($sf,$df)); } }
  function cp_rm($d){ if(!is_dir($d))return; foreach(@scandir($d)?:[] as $i){ if($i==='.'||$i==='..') continue; $p="$d/$i"; is_dir($p)?cp_rm($p):@unlink($p); } @rmdir($d); }
  cp_mv($src, $base); cp_rm($tmp);

  $ver='latest';
  if(file_exists($vf=$base.'/wp-includes/version.php')){
    if(preg_match('/\\$wp_version\\s*=\\s*[\\x27"](\\S+)[\\x27"]/',file_get_contents($vf),$m)) $ver=$m[1];
  }
  echo json_encode(['ok'=>true,'step'=>1,'wp_version'=>$ver,'source'=>$src_url]);
  exit;
}

// ── Step 2: 설정 파일 생성 (wp-config.php, .htaccess, .user.ini) ──
if ($step === 2) {
  file_put_contents($base.'/wp-config.php', base64_decode('${wpConfigB64}'));
  file_put_contents($base.'/.htaccess',     base64_decode('${htaccessB64}'));
  file_put_contents($base.'/.user.ini',     base64_decode('${userIniB64}'));
  if(is_dir($base.'/wp-content')) file_put_contents($base.'/wp-content/.user.ini', base64_decode('${userIniB64}'));
  $mu = $base.'/wp-content/mu-plugins';
  if(!is_dir($mu)) @mkdir($mu,0755,true);
  file_put_contents($mu.'/cloudpress-core.php', base64_decode('${muPluginB64}'));
  echo json_encode(['ok'=>true,'step'=>2,'msg'=>'설정 완료']);
  exit;
}

// ── Step 3: DB 연결 + WordPress 설치 ──
if ($step === 3) {
  if (!file_exists($base.'/wp-load.php')) { echo json_encode(['ok'=>false,'error'=>'WP 파일 없음']); exit; }
  $db = @new mysqli('${dbHost}','${dbUser}','${dbPass}','${dbName}');
  if ($db->connect_error) { echo json_encode(['ok'=>false,'error'=>'DB 연결 실패: '.$db->connect_error]); exit; }
  $db->query("SET time_zone='+9:00'"); $db->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"); $db->close();
  $_SERVER['HTTP_HOST']   = parse_url('${siteUrl}',PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  $_SERVER['HTTPS']       = 'off';
  require_once $base.'/wp-load.php';
  require_once $base.'/wp-admin/includes/upgrade.php';
  global $wpdb; $wpdb->query("SET time_zone='+9:00'");
  $r = wp_install('${siteNameEsc}','${wpAdminUser}','${wpAdminEmail}',true,'',wp_slash('${wpAdminPw}'));
  if (is_wp_error($r)) { echo json_encode(['ok'=>false,'error'=>$r->get_error_message()]); exit; }
  update_option('blogname','${siteNameEsc}');
  update_option('siteurl','${siteUrl}');
  update_option('home','${siteUrl}');
  update_option('permalink_structure','/%postname%/');
  update_option('timezone_string','Asia/Seoul');
  update_option('gmt_offset',9);
  update_option('WPLANG','ko_KR');
  update_option('admin_email','${wpAdminEmail}');
  update_option('default_comment_status','closed');
  flush_rewrite_rules(true);
  echo json_encode(['ok'=>true,'step'=>3,'msg'=>'WordPress 설치 완료']);
  exit;
}

// ── Step 4: 플러그인 설치 (breeze + 플랜별 추가) ──
if ($step === 4) {
  if (!file_exists($base.'/wp-load.php')) { echo json_encode(['ok'=>false,'error'=>'WP 미설치']); exit; }
  $_SERVER['HTTP_HOST']   = parse_url('${siteUrl}',PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  require_once $base.'/wp-load.php';
  require_once $base.'/wp-admin/includes/plugin.php';
  require_once $base.'/wp-admin/includes/file.php';
  require_once $base.'/wp-admin/includes/misc.php';
  require_once $base.'/wp-admin/includes/class-wp-upgrader.php';
  require_once $base.'/wp-admin/includes/plugin-install.php';
  global $wpdb; $wpdb->query("SET time_zone='+9:00'");

  $to_install = [${pluginListPHP}];
  $installed = []; $errors = [];

  foreach ($to_install as $slug) {
    $api = plugins_api('plugin_information',['slug'=>$slug,'fields'=>['sections'=>false,'screenshots'=>false]]);
    if (is_wp_error($api)) { $errors[]=$slug.': API 오류'; continue; }
    $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());
    $result = $upgrader->install($api->download_link);
    if (is_wp_error($result)) { $errors[]=$slug.': 설치 실패'; continue; }
    $pf = $slug.'/'.$slug.'.php';
    if (file_exists($base.'/wp-content/plugins/'.$pf)) {
      activate_plugin($pf);
      $installed[] = $slug;
    }
  }

  // Breeze 기본 설정 적용
  if (in_array('breeze', $installed)) {
    update_option('breeze_basic_settings',[
      'breeze-active'=>1,'breeze-gzip-compression'=>1,'breeze-browser-cache'=>1,
      'breeze-lazy-load'=>1,'breeze-desktop-cache'=>1,'breeze-mobile-cache'=>1,
      'breeze-minify-html'=>1,'breeze-minify-css'=>1,'breeze-minify-js'=>1,
      'breeze-defer-js'=>1,'breeze-cache-ttl'=>1440,
    ]);
  }

  // Twenty Twenty-Four 테마 설치 (없으면)
  $themes_dir = $base.'/wp-content/themes';
  if (!is_dir($themes_dir.'/twentytwentyfour')) {
    $ctx = stream_context_create(['http'=>['timeout'=>60],'ssl'=>['verify_peer'=>false]]);
    $tz = @file_get_contents('https://downloads.wordpress.org/theme/twentytwentyfour.zip',false,$ctx);
    if ($tz && strlen($tz)>10000) {
      $tzp=$themes_dir.'/tt4.zip'; file_put_contents($tzp,$tz);
      $z=new ZipArchive(); if($z->open($tzp)===true){$z->extractTo($themes_dir);$z->close();}
      @unlink($tzp);
    }
  }
  foreach(['twentytwentyfour','twentytwentythree','twentytwentytwo'] as $t){
    if(is_dir($themes_dir.'/'.$t)){switch_theme($t); $installed[]='theme:'.$t; break;}
  }

  echo json_encode(['ok'=>true,'step'=>4,'installed'=>$installed,'errors'=>$errors]);
  exit;
}

// ── Step 5: cron job 예약 + 최종 설정 ──
if ($step === 5) {
  if (!file_exists($base.'/wp-load.php')) { echo json_encode(['ok'=>false,'error'=>'WP 미설치']); exit; }
  $_SERVER['HTTP_HOST']   = parse_url('${siteUrl}',PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  require_once $base.'/wp-load.php';
  global $wpdb; $wpdb->query("SET time_zone='+9:00'");

  // Cron 스케줄 등록
  if (!wp_next_scheduled('cloudpress_health_check'))
    wp_schedule_event(time(),'hourly','cloudpress_health_check');

  // 최종 permalink flush
  flush_rewrite_rules(true);

  echo json_encode(['ok'=>true,'step'=>5,'msg'=>'최종 설정 완료']);
  exit;
}

// ── Step 6: 인스톨러 자체 삭제 ──
if ($step === 6) {
  $f = __FILE__;
  echo json_encode(['ok'=>true,'step'=>6,'msg'=>'인스톨러 삭제 완료']);
  @unlink($f);
  exit;
}

echo json_encode(['ok'=>false,'error'=>'Unknown step: '.$step]);
`;
}

/* ══════════════════════════════════════════════════════════════
   핵심 프로비저닝 파이프라인 v9.0
   Worker 완전 제거 — Pages Function에서 직접 실행
   흐름: cPanel UAPI 파일 업로드 → fetch로 installer 각 Step 실행
══════════════════════════════════════════════════════════════ */
async function runProvisioningPipeline(env, siteId, payload) {
  const globalCfg = await getGlobalSettings(env);

  // ── VP 계정 선택 ──
  const vpAccount = await pickVpAccount(env);
  if (!vpAccount) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'init',
      error_message: 'VP 계정 없음 — 관리자 → VP 계정 관리에서 계정을 추가해주세요.',
    });
    return;
  }

  const cnameTarget   = await getCnameTarget(env);
  const serverDomain  = vpAccount.server_domain || globalCfg.site_domain || 'cloudpress.site';
  const webRoot       = vpAccount.web_root || '/htdocs';
  const mysqlHost     = vpAccount.mysql_host || 'localhost';
  const cpBase        = (vpAccount.panel_url || '').replace(/\/+$/, '');
  const authHdr       = 'Basic ' + btoa(`${vpAccount.vp_username}:${vpAccount.vp_password}`);

  // 서브도메인 계산
  const baseSlug    = payload.siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'cp';
  const suffix      = Math.random().toString(36).slice(2, 5);
  const subDomain   = (baseSlug + suffix).slice(0, 15);
  const hostingDomain = `${subDomain}.${serverDomain}`;
  const siteUrl       = `https://${hostingDomain}`;
  const wpAdminUrl    = `${siteUrl}/wp-admin/`;
  const loginUrl      = `${siteUrl}/wp-login.php`;

  // DB 자격증명 생성
  const dbName = `wp_${subDomain.slice(0, 8)}_${Math.random().toString(36).slice(2, 5)}`;
  const dbUser = `${subDomain.slice(0, 8)}_wp`;
  const dbPass = genPw(14);

  // 인스톨러 시크릿 (8자)
  const secret = payload.wpAdminPw.slice(0, 8);

  await incrementVpAccountSites(env, vpAccount.id);

  await updateSiteStatus(env.DB, siteId, {
    status:            'installing_wp',
    provision_step:    'uploading_installer',
    hosting_domain:    hostingDomain,
    account_username:  subDomain,
    subdomain:         hostingDomain,
    vp_account_id:     vpAccount.id,
    cpanel_url:        cpBase,
    wp_url:            siteUrl,
    wp_admin_url:      wpAdminUrl,
    primary_domain:    hostingDomain,
    cname_target:      cnameTarget,
    login_url:         loginUrl,
    server_type:       'shared',
    installation_mode: 'php_installer',
    wp_username:       payload.wpAdminUser,
    wp_password:       payload.wpAdminPw,
    wp_admin_email:    payload.wpAdminEmail,
  });

  // ══ 단계 1: installer.php 생성 및 업로드 ══
  const installerScript = buildInstallerPHP({
    dbName, dbUser, dbPass, dbHost: mysqlHost,
    siteUrl, siteName: payload.siteName,
    wpAdminUser:  payload.wpAdminUser,
    wpAdminPw:    payload.wpAdminPw,
    wpAdminEmail: payload.wpAdminEmail,
    plan:   payload.plan,
    secret,
  });

  const uploadResult = await cpanelSaveFile(cpBase, authHdr, webRoot, 'cloudpress-installer.php', installerScript);
  if (!uploadResult.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'uploading_installer',
      error_message: `installer.php 업로드 실패: ${uploadResult.error} — cPanel URL(${cpBase})과 자격증명을 확인해주세요.`,
    });
    return;
  }

  const installerUrl = `${siteUrl}/cloudpress-installer.php`;

  // ══ 단계 2: Step 0 — PHP 환경 확인 ══
  await updateSiteStatus(env.DB, siteId, { provision_step: 'checking_php' });
  const s0 = await runInstallerStep(installerUrl, secret, 0, 30000);
  if (!s0.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'checking_php',
      error_message: `PHP 확인 실패: ${s0.error || JSON.stringify(s0)} — 서버가 응답하지 않습니다.`,
    });
    return;
  }

  // ══ 단계 3: Step 1 — WordPress 다운로드 ══
  await updateSiteStatus(env.DB, siteId, { provision_step: 'installing_wp' });
  const s1 = await runInstallerStep(installerUrl, secret, 1, 360000); // 6분
  if (!s1.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'installing_wp',
      error_message: `WordPress 다운로드 실패: ${s1.error || s1.raw || JSON.stringify(s1)}`,
    });
    return;
  }

  // ══ 단계 4: Step 2 — 설정 파일 생성 ══
  const s2 = await runInstallerStep(installerUrl, secret, 2, 60000);
  if (!s2.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'installing_wp',
      error_message: `설정 파일 생성 실패: ${s2.error || JSON.stringify(s2)}`,
    });
    return;
  }

  // ══ 단계 5: Step 3 — DB 설치 ══
  await updateSiteStatus(env.DB, siteId, { provision_step: 'configuring' });
  const s3 = await runInstallerStep(installerUrl, secret, 3, 120000);
  if (!s3.ok) {
    await updateSiteStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'configuring',
      error_message: `DB 설치 실패: ${s3.error || JSON.stringify(s3)}`,
    });
    return;
  }

  // ══ 단계 6: Step 4 — 플러그인 설치 ══
  await updateSiteStatus(env.DB, siteId, { provision_step: 'installing_plugins' });
  const s4 = await runInstallerStep(installerUrl, secret, 4, 300000); // 5분
  // 플러그인 실패는 경고만 (사이트는 계속)

  // ══ 단계 7: Step 5 — 최종 설정 ══
  const s5 = await runInstallerStep(installerUrl, secret, 5, 60000);

  // ══ 단계 8: Step 6 — 인스톨러 삭제 ══
  await runInstallerStep(installerUrl, secret, 6, 15000).catch(() => {});

  // ══ 완료 ══
  await updateSiteStatus(env.DB, siteId, {
    status:            'active',
    provision_step:    'completed',
    wp_version:        s1.wp_version || 'latest',
    php_version:       s0.php || '8.x',
    cron_enabled:      1,
    rest_api_enabled:  1,
    loopback_enabled:  1,
    speed_optimized:   s4?.ok ? 1 : 0,
    suspend_protected: 1,
    ssl_active:        1,
    error_message:     null,
  });

  await sendPushNotifications(env, payload.userId, {
    type:       'site_created',
    siteId,
    siteName:   payload.siteName,
    siteUrl,
    wpAdminUrl,
    loginUrl,
    wpAdminUser:  payload.wpAdminUser,
    wpAdminPw:    payload.wpAdminPw,
    message:    `✅ "${payload.siteName}" 생성 완료! 관리자: ${wpAdminUrl}`,
    timestamp:  Date.now(),
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

  const { siteName, adminLogin, sitePlan } = body || {};
  if (!siteName || !siteName.trim())        return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');

  // VP 계정 확인
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
      ) VALUES (?,?,?,'shared_hosting',?,?,?,'installing_wp','init',?,'shared','php_installer')`
    ).bind(
      siteId, user.id, siteName.trim(),
      adminLogin, wpAdminPw, user.email,
      effectivePlan
    ).run();
  } catch (e) {
    return err('사이트 레코드 생성 실패: ' + e.message, 500);
  }

  const pipelinePayload = {
    siteName:     siteName.trim(),
    wpAdminUser:  adminLogin,
    wpAdminPw,
    wpAdminEmail: user.email,
    plan:         effectivePlan,
    userId:       user.id,
  };

  const pipelinePromise = runProvisioningPipeline(env, siteId, pipelinePayload)
    .catch(async (e) => {
      await updateSiteStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'pipeline_error',
        error_message: '파이프라인 오류: ' + e.message,
      });
    });

  if (ctx?.waitUntil) ctx.waitUntil(pipelinePromise);

  return ok({
    siteId,
    plan: effectivePlan,
    vpAccount: vpAccount.label,
    message: `WordPress 설치를 시작합니다. 완료까지 5~10분 소요됩니다.`,
    steps: [
      { step: 1, name: 'installer.php 업로드 (cPanel UAPI)',   status: 'running' },
      { step: 2, name: 'WordPress 다운로드 + 압축해제',          status: 'pending' },
      { step: 3, name: 'DB 설치 + wp-config 설정',              status: 'pending' },
      { step: 4, name: '플러그인 설치 (breeze, 반응형 테마)',    status: 'pending' },
      { step: 5, name: '최종 설정 (cron, permalink, KST)',      status: 'pending' },
    ],
  });
}
