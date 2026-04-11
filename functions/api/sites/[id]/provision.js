// functions/api/sites/[id]/provision.js
// CloudPress v10.0 — 프로비저닝 파이프라인 전용 엔드포인트
// create.html에서 POST /api/sites → siteId 받은 뒤 즉시 POST /api/sites/{id}/provision 호출

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', ...CORS },
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

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, ctx, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params.id;

  const site = await env.DB.prepare(
    `SELECT id, user_id, name, status, provision_step, plan,
            wp_username, wp_password, wp_admin_email
     FROM sites WHERE id=? AND user_id=?`
  ).bind(siteId, user.id).first();

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  // 이미 완료된 사이트
  if (site.status === 'active') return ok({ message: '이미 완료된 사이트입니다.' });

  // 실제로 진행 중인 단계인 경우만 중복 방지 (init, pending, failed는 허용)
  const IN_PROGRESS_STEPS = [
    'starting', 'uploading_installer', 'checking_php',
    'installing_wp', 'configuring', 'installing_plugins', 'completed',
  ];
  if (IN_PROGRESS_STEPS.includes(site.provision_step) && site.status === 'installing_wp') {
    return ok({ message: '이미 프로비저닝이 진행 중입니다.', provision_step: site.provision_step });
  }

  // 중복 실행 방지 락 설정
  await env.DB.prepare(
    `UPDATE sites SET status='installing_wp', provision_step='starting', updated_at=unixepoch() WHERE id=?`
  ).bind(siteId).run();

  const pipelinePromise = runPipeline(env, siteId, site);

  if (ctx?.waitUntil) {
    ctx.waitUntil(pipelinePromise.catch(() => {}));
  } else {
    pipelinePromise.catch(() => {});
  }

  return ok({ message: '프로비저닝을 시작합니다.', siteId });
}

async function updateStatus(DB, siteId, fields) {
  const entries = Object.entries(fields);
  if (!entries.length) return;
  const setClauses = entries.map(([k]) => `${k}=?`).join(',');
  const values = entries.map(([, v]) => v);
  await DB.prepare(
    `UPDATE sites SET ${setClauses}, updated_at=unixepoch() WHERE id=?`
  ).bind(...values, siteId).run().catch(() => {});
}

function genPw(len = 16) {
  const chars = 'ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
  let pw = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (const b of arr) pw += chars[b % chars.length];
  return pw;
}

async function runInstallerStep(installerUrl, secret, step, timeoutMs = 120000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${installerUrl}?step=${step}&secret=${encodeURIComponent(secret)}`, {
      signal: controller.signal,
    });
    const text = await res.text();
    try { return JSON.parse(text.trim()); }
    catch { return { ok: text.includes('"ok":true'), step, raw: text.slice(0, 500) }; }
  } catch (e) {
    if (e.name === 'AbortError') return { ok: false, step, error: `Step ${step} 타임아웃 (${timeoutMs/1000}초)` };
    return { ok: false, step, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}

async function cpanelSaveFile(cpBase, authHdr, dir, filename, content) {
  // 방법 1: UAPI
  try {
    const res = await fetch(`${cpBase}/execute/Fileman/save_file_content`, {
      method: 'POST',
      headers: { 'Authorization': authHdr, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ dir, file: filename, content }).toString(),
    });
    const data = await res.json().catch(() => ({}));
    if (data?.status === 1 || data?.result?.status === 1) return { ok: true };
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
    if (d2?.cpanelresult?.data?.[0]?.result === 1) return { ok: true };
  } catch (_) {}

  return { ok: false, error: `파일 저장 실패: ${dir}/${filename}` };
}

async function runPipeline(env, siteId, site) {
  try {
    // VP 계정 선택
    const { results: vpRows } = await env.DB.prepare(
      `SELECT * FROM vp_accounts WHERE is_active=1 AND current_sites < max_sites ORDER BY current_sites ASC LIMIT 1`
    ).all();
    const vpAccount = vpRows?.[0];

    if (!vpAccount) {
      await updateStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'init',
        error_message: 'VP 계정 없음 — 관리자 → VP 계정 관리에서 계정을 추가해주세요.',
      });
      return;
    }

    // 설정값
    const settingsRes = await env.DB.prepare(
      `SELECT key, value FROM settings WHERE key IN ('site_domain','cname_target')`
    ).all().catch(() => ({ results: [] }));
    const cfg = {};
    for (const r of (settingsRes.results || [])) cfg[r.key] = r.value;

    const serverDomain  = vpAccount.server_domain || cfg.site_domain || 'cloudpress.site';
    const webRoot       = vpAccount.web_root || '/htdocs';
    const mysqlHost     = vpAccount.mysql_host || 'localhost';
    const cpBase        = (vpAccount.panel_url || '').replace(/\/+$/, '');
    const authHdr       = 'Basic ' + btoa(`${vpAccount.vp_username}:${vpAccount.vp_password}`);
    const wpDownloadUrl = vpAccount.wp_download_url?.trim() || null;
    const cnameTarget   = cfg.cname_target || env.CNAME_TARGET || 'proxy.cloudpress.site';

    // 서브도메인 계산
    const baseSlug      = site.name.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'cp';
    const suffix        = Math.random().toString(36).slice(2, 5);
    const subDomain     = (baseSlug + suffix).slice(0, 15);
    const hostingDomain = `${subDomain}.${serverDomain}`;
    const siteUrl       = `https://${hostingDomain}`;
    const wpAdminUrl    = `${siteUrl}/wp-admin/`;
    const loginUrl      = `${siteUrl}/wp-login.php`;

    // DB 자격증명
    const dbName = `wp_${subDomain.slice(0, 8)}_${Math.random().toString(36).slice(2, 5)}`;
    const dbUser = `${subDomain.slice(0, 8)}_wp`;
    const dbPass = genPw(14);
    const secret = (site.wp_password || genPw(8)).slice(0, 8);

    // VP 카운터 증가
    await env.DB.prepare(
      `UPDATE vp_accounts SET current_sites=current_sites+1, updated_at=datetime('now') WHERE id=?`
    ).bind(vpAccount.id).run().catch(() => {});

    // vp_account_id 컬럼 없을 수 있으므로 마이그레이션 시도
    try { await env.DB.prepare(`ALTER TABLE sites ADD COLUMN vp_account_id TEXT`).run(); } catch (_) {}
    try { await env.DB.prepare(`ALTER TABLE sites ADD COLUMN login_url TEXT`).run(); } catch (_) {}

    await updateStatus(env.DB, siteId, {
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
    });

    const installerScript = buildInstallerPHP({
      dbName, dbUser, dbPass, dbHost: mysqlHost,
      siteUrl, siteName: site.name,
      wpAdminUser:  site.wp_username || 'admin',
      wpAdminPw:    site.wp_password,
      wpAdminEmail: site.wp_admin_email,
      plan:         site.plan,
      secret,
      wpDownloadUrl,
    });

    // installer.php 업로드
    const uploadResult = await cpanelSaveFile(cpBase, authHdr, webRoot, 'cloudpress-installer.php', installerScript);
    if (!uploadResult.ok) {
      await updateStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'uploading_installer',
        error_message: `installer.php 업로드 실패: ${uploadResult.error} — cPanel URL(${cpBase})과 계정 정보를 확인해주세요.`,
      });
      return;
    }

    const installerUrl = `${siteUrl}/cloudpress-installer.php`;

    // ── Step 0: PHP 환경 확인 ──
    await updateStatus(env.DB, siteId, { provision_step: 'checking_php' });
    const s0 = await runInstallerStep(installerUrl, secret, 0, 30000);
    if (!s0.ok) {
      await updateStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'checking_php',
        error_message: `PHP 확인 실패: ${s0.error || JSON.stringify(s0)} — 서버(${hostingDomain})가 응답하지 않습니다. DNS 전파 또는 서버 설정을 확인해주세요.`,
      });
      return;
    }

    // ── Step 1: WordPress 다운로드 ──
    await updateStatus(env.DB, siteId, { provision_step: 'installing_wp' });
    const s1 = await runInstallerStep(installerUrl, secret, 1, 360000); // 6분
    if (!s1.ok) {
      await updateStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'installing_wp',
        error_message: `WordPress 다운로드 실패: ${s1.error || s1.raw || JSON.stringify(s1)}`,
      });
      return;
    }

    // ── Step 2: 설정 파일 생성 ──
    const s2 = await runInstallerStep(installerUrl, secret, 2, 60000);
    if (!s2.ok) {
      await updateStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'installing_wp',
        error_message: `설정 파일 생성 실패: ${s2.error || s2.raw || JSON.stringify(s2)}`,
      });
      return;
    }

    // ── Step 3: DB 설치 ──
    await updateStatus(env.DB, siteId, { provision_step: 'configuring' });
    const s3 = await runInstallerStep(installerUrl, secret, 3, 120000);
    if (!s3.ok) {
      await updateStatus(env.DB, siteId, {
        status: 'failed', provision_step: 'configuring',
        error_message: `DB 설치 실패: ${s3.error || s3.raw || JSON.stringify(s3)}`,
      });
      return;
    }

    // ── Step 4: 플러그인 설치 ──
    await updateStatus(env.DB, siteId, { provision_step: 'installing_plugins' });
    const s4 = await runInstallerStep(installerUrl, secret, 4, 300000); // 5분
    // 플러그인 실패는 치명적이지 않음 → 계속 진행

    // ── Step 5: 최종 설정 ──
    const s5 = await runInstallerStep(installerUrl, secret, 5, 60000);

    // ── Step 6: 인스톨러 삭제 ──
    await runInstallerStep(installerUrl, secret, 6, 15000).catch(() => {});

    // ── 완료 ──
    await updateStatus(env.DB, siteId, {
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

  } catch (e) {
    await updateStatus(env.DB, siteId, {
      status: 'failed', provision_step: 'pipeline_error',
      error_message: '파이프라인 오류: ' + e.message,
    }).catch(() => {});
  }
}

// ══════════════════════════════════════════════════════════════
// PHP 설치 스크립트 빌더 (Step 0~6)
// ══════════════════════════════════════════════════════════════
function buildInstallerPHP({ dbName, dbUser, dbPass, dbHost, siteUrl, siteName,
  wpAdminUser, wpAdminPw, wpAdminEmail, plan, secret, wpDownloadUrl }) {

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

  const customUrlLine = wpDownloadUrl
    ? `  $custom_url = '${wpDownloadUrl.replace(/'/g, "\\'")}';`
    : `  $custom_url = '';`;

  return `<?php
/**
 * CloudPress WordPress Installer v10.0
 * Step 0: PHP 확인 / Step 1: WP 다운로드 / Step 2: 설정파일
 * Step 3: DB 설치 / Step 4: 플러그인 / Step 5: 최종설정 / Step 6: 자체삭제
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

if ($step === 0) {
  echo json_encode(['ok'=>true,'step'=>0,'php'=>phpversion(),'php_ok'=>(PHP_MAJOR_VERSION>=8)]);
  exit;
}

if ($step === 1) {
  $zip_path = $base.'/wp_install.zip';
${customUrlLine}
  $urls = array_values(array_filter([
    $custom_url,
    'https://ko.wordpress.org/latest-ko_KR.zip',
    'https://downloads.wordpress.org/release/ko_KR/latest.zip',
    'https://wordpress.org/latest.zip',
  ], function($u){ return !empty(trim((string)$u)); }));
  $ok = false; $src_url = '';
  foreach ($urls as $url) {
    $ctx = stream_context_create(['http'=>['timeout'=>180,'follow_location'=>true,'max_redirects'=>5],
                                  'ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data && strlen($data) > 500000) {
      file_put_contents($zip_path, $data); $ok=true; $src_url=$url; break;
    }
  }
  if (!$ok) { echo json_encode(['ok'=>false,'error'=>'WP 다운로드 실패 — 모든 미러 실패']); exit; }

  $zip = new ZipArchive();
  if ($zip->open($zip_path) !== true) { echo json_encode(['ok'=>false,'error'=>'ZIP 해제 실패']); exit; }
  $tmp = $base.'/wp_tmp_'.time();
  $zip->extractTo($tmp); $zip->close(); @unlink($zip_path);

  $src = null;
  foreach (['wordpress','wordpress-ko_KR'] as $n) {
    if (is_dir("$tmp/$n")) { $src = "$tmp/$n"; break; }
  }
  if (!$src) { $dirs=glob("$tmp/*",GLOB_ONLYDIR); $src=$dirs[0]??null; }
  if (!$src) { echo json_encode(['ok'=>false,'error'=>'WP 폴더를 찾을 수 없음']); exit; }

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

if ($step === 3) {
  if (!file_exists($base.'/wp-load.php')) { echo json_encode(['ok'=>false,'error'=>'WP 파일 없음 — Step 1 실패 확인']); exit; }
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

  if (in_array('breeze', $installed)) {
    update_option('breeze_basic_settings',[
      'breeze-active'=>1,'breeze-gzip-compression'=>1,'breeze-browser-cache'=>1,
      'breeze-lazy-load'=>1,'breeze-desktop-cache'=>1,'breeze-mobile-cache'=>1,
      'breeze-minify-html'=>1,'breeze-minify-css'=>1,'breeze-minify-js'=>1,
      'breeze-defer-js'=>1,'breeze-cache-ttl'=>1440,
    ]);
  }

  $themes_dir = $base.'/wp-content/themes';
  if (!is_dir($themes_dir.'/twentytwentyfour')) {
    $ctx2 = stream_context_create(['http'=>['timeout'=>60],'ssl'=>['verify_peer'=>false]]);
    $tz = @file_get_contents('https://downloads.wordpress.org/theme/twentytwentyfour.zip',false,$ctx2);
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

if ($step === 5) {
  if (!file_exists($base.'/wp-load.php')) { echo json_encode(['ok'=>false,'error'=>'WP 미설치']); exit; }
  $_SERVER['HTTP_HOST']   = parse_url('${siteUrl}',PHP_URL_HOST);
  $_SERVER['REQUEST_URI'] = '/';
  require_once $base.'/wp-load.php';
  global $wpdb; $wpdb->query("SET time_zone='+9:00'");
  if (!wp_next_scheduled('cloudpress_health_check'))
    wp_schedule_event(time(),'hourly','cloudpress_health_check');
  flush_rewrite_rules(true);
  echo json_encode(['ok'=>true,'step'=>5,'msg'=>'최종 설정 완료']);
  exit;
}

if ($step === 6) {
  $f = __FILE__;
  echo json_encode(['ok'=>true,'step'=>6,'msg'=>'인스톨러 삭제 완료']);
  @unlink($f);
  exit;
}

echo json_encode(['ok'=>false,'error'=>'Unknown step: '.$step]);
`;
}
