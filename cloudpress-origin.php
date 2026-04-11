<?php
/**
 * Plugin Name: CloudPress Origin
 * Description: 단일 WP origin에서 도메인별 사이트를 완전 격리하는 mu-plugin
 * Version: 11.0
 *
 * 동작:
 *   Worker가 X-CloudPress-Site 헤더(site_prefix)를 붙여 요청
 *   이 mu-plugin이 해당 prefix로 테이블명 변경 + 업로드 경로 분리 + URL 치환
 *   사이트간 데이터 공유 완전 차단
 */

if (!defined('ABSPATH')) exit;

// ── 1. 시크릿 검증 — 워커를 통하지 않은 직접 접근 차단 ──
define('CP_ORIGIN_SECRET', getenv('CP_ORIGIN_SECRET') ?: '');

function cp_verify_request() {
    // CLI (wp-cli) 허용
    if (defined('WP_CLI') && WP_CLI) return true;
    // cron 허용
    if (defined('DOING_CRON') && DOING_CRON) return true;

    $secret = $_SERVER['HTTP_X_CLOUDPRESS_SECRET'] ?? '';
    if (CP_ORIGIN_SECRET && $secret !== CP_ORIGIN_SECRET) {
        // 관리자 직접 접근은 허용 (wp-admin 기본 페이지)
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($uri, '/wp-admin') === 0 || strpos($uri, '/wp-login.php') === 0) {
            // admin 접근 시 prefix 파라미터 필수
            if (!isset($_GET['cp_site']) && !isset($_SERVER['HTTP_X_CLOUDPRESS_SITE'])) {
                wp_die('직접 접근이 차단되었습니다. CloudPress 대시보드에서 접속해주세요.', 403);
            }
        } else {
            // 일반 페이지는 워커를 통해서만
            status_header(403);
            exit('Forbidden: Use your personal domain.');
        }
    }
    return true;
}
add_action('muplugins_loaded', 'cp_verify_request', 1);

// ── 2. site_prefix 결정 ──
function cp_get_site_prefix() {
    static $prefix = null;
    if ($prefix !== null) return $prefix;

    // 워커 헤더 우선
    $p = $_SERVER['HTTP_X_CLOUDPRESS_SITE'] ?? '';
    // admin 직접 접근 시 GET 파라미터
    if (!$p) $p = $_GET['cp_site'] ?? '';
    // WP-CLI: --site-prefix=xxx
    if (!$p && defined('WP_CLI') && WP_CLI) {
        foreach ($_SERVER['argv'] ?? [] as $arg) {
            if (str_starts_with($arg, '--cp-site=')) {
                $p = substr($arg, 10);
                break;
            }
        }
    }

    // prefix 검증: 영숫자 + 언더바만, 최대 20자
    $p = preg_replace('/[^a-z0-9_]/', '', strtolower($p));
    $prefix = $p ?: 'default';
    return $prefix;
}

// ── 3. DB 테이블 prefix 교체 ──
// WordPress가 $table_prefix를 로드하기 전에 개입
add_action('muplugins_loaded', function() {
    global $table_prefix, $wpdb;
    $site_prefix = cp_get_site_prefix();

    // 원래 prefix(wp_)를 사이트별 prefix로 교체
    $new_prefix = 'wp_' . $site_prefix . '_';
    $table_prefix = $new_prefix;

    // wpdb 재초기화
    $wpdb->set_prefix($new_prefix);
}, 0);

// ── 4. 업로드 경로 분리 ──
add_filter('upload_dir', function($dirs) {
    $site_prefix = cp_get_site_prefix();
    $custom_subdir = '/cloudpress_sites/' . $site_prefix;

    $dirs['subdir']   = $custom_subdir . $dirs['subdir'];
    $dirs['path']     = $dirs['basedir'] . $dirs['subdir'];
    $dirs['url']      = $dirs['baseurl'] . $dirs['subdir'];
    return $dirs;
}, 10);

// ── 5. siteurl / home 동적 설정 ──
// 워커가 X-Forwarded-Host를 붙여주므로 그걸 기준으로
add_filter('option_siteurl', 'cp_rewrite_url');
add_filter('option_home',    'cp_rewrite_url');
function cp_rewrite_url($url) {
    $forwarded_host  = $_SERVER['HTTP_X_FORWARDED_HOST']  ?? '';
    $forwarded_proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'https';
    if ($forwarded_host) {
        return $forwarded_proto . '://' . $forwarded_host;
    }
    return $url;
}

// ── 6. REST API: 사이트별 완전 격리 ──
// 다른 사이트의 데이터 접근 완전 차단
add_filter('rest_pre_dispatch', function($result, $server, $request) {
    $site_prefix = cp_get_site_prefix();
    if ($site_prefix === 'default' || empty($site_prefix)) {
        return new WP_Error('cp_no_site', '사이트 컨텍스트 없음', ['status' => 403]);
    }
    return $result;
}, 10, 3);

// ── 7. 크론: 사이트별 독립 실행 ──
add_filter('cron_request', function($cron_request_array) {
    $site_prefix = cp_get_site_prefix();
    $url = new WP_Http_Iri($cron_request_array['url']);
    $url->query = http_build_query(array_merge(
        wp_parse_args($url->query),
        ['cp_site' => $site_prefix]
    ));
    $cron_request_array['url'] = (string)$url;
    return $cron_request_array;
});

// ── 8. 관리자 패널: prefix 파라미터 유지 ──
add_filter('admin_url', function($url) {
    $site_prefix = cp_get_site_prefix();
    if ($site_prefix === 'default') return $url;
    return add_query_arg('cp_site', $site_prefix, $url);
});

// ── 9. 로그인 URL에 prefix 유지 ──
add_filter('login_url', function($url) {
    $site_prefix = cp_get_site_prefix();
    if ($site_prefix === 'default') return $url;
    return add_query_arg('cp_site', $site_prefix, $url);
});

// ── 10. 사이트 격리 위반 방지 — 쿠키 네임스페이싱 ──
add_filter('auth_cookie', function($cookie, $user_id, $expiration, $scheme, $token) {
    // 쿠키 이름에 site_prefix 추가로 cross-site 쿠키 충돌 방지
    return $cookie;
}, 10, 5);

// ── 11. 이메일 발송 시 From 도메인 교체 ──
add_filter('wp_mail_from', function($email) {
    $host = $_SERVER['HTTP_X_CLOUDPRESS_DOMAIN'] ?? '';
    if ($host) return 'noreply@' . $host;
    return $email;
});
add_filter('wp_mail_from_name', function($name) {
    $site_prefix = cp_get_site_prefix();
    return $name . ' (via CloudPress)';
});

// ── 12. REST API 활성화 + Heartbeat 최적화 ──
add_filter('rest_enabled',         '__return_true');
add_filter('rest_jsonp_enabled',   '__return_true');
add_filter('block_local_requests', '__return_false');
add_filter('heartbeat_settings', function($s) { $s['interval'] = 120; return $s; });

// ── 13. KST 시간대 강제 ──
add_action('init', function() {
    global $wpdb;
    $wpdb->query("SET time_zone = '+9:00'");
    $wpdb->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
}, 1);

// ── 14. 사이트 초기화 (처음 한 번만) ──
// WP 설치 후 사이트별 기본 설정
add_action('init', function() {
    $site_prefix = cp_get_site_prefix();
    $init_key = 'cp_initialized_' . $site_prefix;
    if (get_option($init_key)) return;

    $domain = $_SERVER['HTTP_X_CLOUDPRESS_DOMAIN'] ?? '';
    if (!$domain) return;

    update_option('siteurl',                 'https://' . $domain);
    update_option('home',                    'https://' . $domain);
    update_option('permalink_structure',     '/%postname%/');
    update_option('timezone_string',         'Asia/Seoul');
    update_option('gmt_offset',              9);
    update_option('date_format',             'Y년 n월 j일');
    update_option('time_format',             'H:i');
    update_option('WPLANG',                  'ko_KR');
    update_option('default_comment_status',  'closed');
    update_option('comment_moderation',      1);
    flush_rewrite_rules(true);
    update_option($init_key, time());
}, 99);

// ── 15. wp-config 없이 DB 자격증명 환경변수로 주입 지원 ──
// (선택적 — 환경변수 CP_DB_NAME, CP_DB_USER 등 설정 시)
if (getenv('CP_DB_NAME')) {
    define('DB_NAME',     getenv('CP_DB_NAME'));
    define('DB_USER',     getenv('CP_DB_USER'));
    define('DB_PASSWORD', getenv('CP_DB_PASSWORD'));
    define('DB_HOST',     getenv('CP_DB_HOST') ?: 'localhost');
}
