<?php
/**
 * Plugin Name: CloudPress REST API
 * Description: WP origin에 사이트 초기화 REST 엔드포인트 제공
 * Version: 11.0
 * 
 * mu-plugins/에 cloudpress-origin.php와 함께 배치
 * 
 * 엔드포인트: POST /wp-json/cloudpress/v1/init-site
 *   - site_prefix 헤더로 격리된 WP 테이블 생성
 *   - 사이트별 admin 계정 생성
 *   - 사이트별 기본 설정 (permalink, timezone, etc.)
 */

if (!defined('ABSPATH')) exit;

add_action('rest_api_init', function() {
    register_rest_route('cloudpress/v1', '/init-site', [
        'methods'             => 'POST',
        'callback'            => 'cp_rest_init_site',
        'permission_callback' => 'cp_rest_verify_secret',
    ]);

    register_rest_route('cloudpress/v1', '/site-status', [
        'methods'             => 'GET',
        'callback'            => 'cp_rest_site_status',
        'permission_callback' => 'cp_rest_verify_secret',
    ]);

    register_rest_route('cloudpress/v1', '/delete-site', [
        'methods'             => 'DELETE',
        'callback'            => 'cp_rest_delete_site',
        'permission_callback' => 'cp_rest_verify_secret',
    ]);

    register_rest_route('cloudpress/v1', '/flush-cache', [
        'methods'             => 'POST',
        'callback'            => 'cp_rest_flush_cache',
        'permission_callback' => 'cp_rest_verify_secret',
    ]);
});

// 시크릿 검증
function cp_rest_verify_secret($request) {
    $secret = defined('CP_ORIGIN_SECRET') ? CP_ORIGIN_SECRET : '';
    if (!$secret) return true; // 설정 안 된 경우 허용 (개발환경)

    $header = $request->get_header('X-CloudPress-Secret');
    if ($header !== $secret) {
        return new WP_Error('forbidden', '인증 실패', ['status' => 403]);
    }
    return true;
}

// ── 사이트 초기화 ──
function cp_rest_init_site($request) {
    global $wpdb;

    $params       = $request->get_json_params();
    $site_prefix  = sanitize_key($params['site_prefix'] ?? '');
    $site_name    = sanitize_text_field($params['site_name'] ?? '');
    $admin_user   = sanitize_user($params['admin_user'] ?? '');
    $admin_pass   = $params['admin_pass'] ?? '';
    $admin_email  = sanitize_email($params['admin_email'] ?? '');
    $site_url     = esc_url_raw($params['site_url'] ?? '');

    if (!$site_prefix || !$admin_user || !$admin_pass || !$admin_email) {
        return new WP_Error('invalid_params', '필수 파라미터 누락', ['status' => 400]);
    }

    // 해당 prefix의 WP 테이블 존재 확인
    $table_prefix = 'wp_' . $site_prefix . '_';
    $users_table  = $table_prefix . 'users';

    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$users_table'");

    if (!$table_exists) {
        // ── WP 테이블 생성 ──
        // wp-admin/includes/upgrade.php의 dbDelta 활용
        // 단, prefix를 사이트별로 바꿔서 실행

        $original_prefix = $wpdb->prefix;
        $wpdb->set_prefix($table_prefix);

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        // WP 기본 테이블 생성 (wp_install과 동일한 테이블셋)
        $charset_collate = $wpdb->get_charset_collate();

        $tables_sql = "
CREATE TABLE {$table_prefix}posts (
  ID bigint(20) unsigned NOT NULL auto_increment,
  post_author bigint(20) unsigned NOT NULL default '0',
  post_date datetime NOT NULL default '0000-00-00 00:00:00',
  post_date_gmt datetime NOT NULL default '0000-00-00 00:00:00',
  post_content longtext NOT NULL,
  post_title text NOT NULL,
  post_excerpt text NOT NULL,
  post_status varchar(20) NOT NULL default 'publish',
  comment_status varchar(20) NOT NULL default 'open',
  ping_status varchar(20) NOT NULL default 'open',
  post_password varchar(255) NOT NULL default '',
  post_name varchar(200) NOT NULL default '',
  to_ping text NOT NULL,
  pinged text NOT NULL,
  post_modified datetime NOT NULL default '0000-00-00 00:00:00',
  post_modified_gmt datetime NOT NULL default '0000-00-00 00:00:00',
  post_content_filtered longtext NOT NULL,
  post_parent bigint(20) unsigned NOT NULL default '0',
  guid varchar(255) NOT NULL default '',
  menu_order int(11) NOT NULL default '0',
  post_type varchar(20) NOT NULL default 'post',
  post_mime_type varchar(100) NOT NULL default '',
  comment_count bigint(20) NOT NULL default '0',
  PRIMARY KEY  (ID),
  KEY post_name (post_name(191)),
  KEY type_status_date (post_type,post_status,post_date,ID),
  KEY post_parent (post_parent),
  KEY post_author (post_author)
) $charset_collate;

CREATE TABLE {$table_prefix}options (
  option_id bigint(20) unsigned NOT NULL auto_increment,
  option_name varchar(191) NOT NULL default '',
  option_value longtext NOT NULL,
  autoload varchar(20) NOT NULL default 'yes',
  PRIMARY KEY  (option_id),
  UNIQUE KEY option_name (option_name),
  KEY autoload (autoload)
) $charset_collate;

CREATE TABLE {$table_prefix}users (
  ID bigint(20) unsigned NOT NULL auto_increment,
  user_login varchar(60) NOT NULL default '',
  user_pass varchar(255) NOT NULL default '',
  user_nicename varchar(50) NOT NULL default '',
  user_email varchar(100) NOT NULL default '',
  user_url varchar(100) NOT NULL default '',
  user_registered datetime NOT NULL default '0000-00-00 00:00:00',
  user_activation_key varchar(255) NOT NULL default '',
  user_status int(11) NOT NULL default '0',
  display_name varchar(250) NOT NULL default '',
  PRIMARY KEY  (ID),
  KEY user_login_key (user_login),
  KEY user_nicename (user_nicename),
  KEY user_email (user_email)
) $charset_collate;

CREATE TABLE {$table_prefix}usermeta (
  umeta_id bigint(20) unsigned NOT NULL auto_increment,
  user_id bigint(20) unsigned NOT NULL default '0',
  meta_key varchar(255) default NULL,
  meta_value longtext,
  PRIMARY KEY  (umeta_id),
  KEY user_id (user_id),
  KEY meta_key (meta_key(191))
) $charset_collate;

CREATE TABLE {$table_prefix}postmeta (
  meta_id bigint(20) unsigned NOT NULL auto_increment,
  post_id bigint(20) unsigned NOT NULL default '0',
  meta_key varchar(255) default NULL,
  meta_value longtext,
  PRIMARY KEY  (meta_id),
  KEY post_id (post_id),
  KEY meta_key (meta_key(191))
) $charset_collate;

CREATE TABLE {$table_prefix}terms (
  term_id bigint(20) unsigned NOT NULL auto_increment,
  name varchar(200) NOT NULL default '',
  slug varchar(200) NOT NULL default '',
  term_group bigint(10) NOT NULL default 0,
  PRIMARY KEY  (term_id),
  KEY slug (slug(191)),
  KEY name (name(191))
) $charset_collate;

CREATE TABLE {$table_prefix}term_taxonomy (
  term_taxonomy_id bigint(20) unsigned NOT NULL auto_increment,
  term_id bigint(20) unsigned NOT NULL default 0,
  taxonomy varchar(32) NOT NULL default '',
  description longtext NOT NULL,
  parent bigint(20) unsigned NOT NULL default 0,
  count bigint(20) NOT NULL default 0,
  PRIMARY KEY  (term_taxonomy_id),
  UNIQUE KEY term_id_taxonomy (term_id,taxonomy),
  KEY taxonomy (taxonomy)
) $charset_collate;

CREATE TABLE {$table_prefix}term_relationships (
  object_id bigint(20) unsigned NOT NULL default 0,
  term_taxonomy_id bigint(20) unsigned NOT NULL default 0,
  term_order int(11) NOT NULL default 0,
  PRIMARY KEY  (object_id,term_taxonomy_id),
  KEY term_taxonomy_id (term_taxonomy_id)
) $charset_collate;

CREATE TABLE {$table_prefix}comments (
  comment_ID bigint(20) unsigned NOT NULL auto_increment,
  comment_post_ID bigint(20) unsigned NOT NULL default '0',
  comment_author tinytext NOT NULL,
  comment_author_email varchar(100) NOT NULL default '',
  comment_author_url varchar(200) NOT NULL default '',
  comment_author_IP varchar(100) NOT NULL default '',
  comment_date datetime NOT NULL default '0000-00-00 00:00:00',
  comment_date_gmt datetime NOT NULL default '0000-00-00 00:00:00',
  comment_content text NOT NULL,
  comment_karma int(11) NOT NULL default '0',
  comment_approved varchar(20) NOT NULL default '1',
  comment_agent varchar(255) NOT NULL default '',
  comment_type varchar(20) NOT NULL default 'comment',
  comment_parent bigint(20) unsigned NOT NULL default '0',
  user_id bigint(20) unsigned NOT NULL default '0',
  PRIMARY KEY  (comment_ID),
  KEY comment_post_ID (comment_post_ID),
  KEY comment_approved_date_gmt (comment_approved,comment_date_gmt),
  KEY comment_date_gmt (comment_date_gmt),
  KEY comment_parent (comment_parent),
  KEY comment_author_email (comment_author_email(10))
) $charset_collate;

CREATE TABLE {$table_prefix}commentmeta (
  meta_id bigint(20) unsigned NOT NULL auto_increment,
  comment_id bigint(20) unsigned NOT NULL default '0',
  meta_key varchar(255) default NULL,
  meta_value longtext,
  PRIMARY KEY  (meta_id),
  KEY comment_id (comment_id),
  KEY meta_key (meta_key(191))
) $charset_collate;

CREATE TABLE {$table_prefix}links (
  link_id bigint(20) unsigned NOT NULL auto_increment,
  link_url varchar(255) NOT NULL default '',
  link_name varchar(255) NOT NULL default '',
  link_image varchar(255) NOT NULL default '',
  link_target varchar(25) NOT NULL default '',
  link_description varchar(255) NOT NULL default '',
  link_visible varchar(20) NOT NULL default 'Y',
  link_owner bigint(20) unsigned NOT NULL default '1',
  link_rating int(11) NOT NULL default '0',
  link_updated datetime NOT NULL default '0000-00-00 00:00:00',
  link_rel varchar(255) NOT NULL default '',
  link_notes mediumtext NOT NULL,
  link_rss varchar(255) NOT NULL default '',
  PRIMARY KEY  (link_id),
  KEY link_visible (link_visible)
) $charset_collate;
";
        dbDelta($tables_sql);

        // 기본 옵션 삽입
        $options = [
            'siteurl'                => $site_url,
            'home'                   => $site_url,
            'blogname'               => $site_name,
            'blogdescription'        => '',
            'users_can_register'     => 0,
            'admin_email'            => $admin_email,
            'start_of_week'          => 0,
            'use_trackback'          => 0,
            'default_category'       => 1,
            'default_comment_status' => 'closed',
            'default_ping_status'    => 'open',
            'permalink_structure'    => '/%postname%/',
            'rewrite_rules'          => '',
            'timezone_string'        => 'Asia/Seoul',
            'date_format'            => 'Y년 n월 j일',
            'time_format'            => 'H:i',
            'WPLANG'                 => 'ko_KR',
            'template'               => 'twentytwentyfour',
            'stylesheet'             => 'twentytwentyfour',
            'comment_moderation'     => 1,
            'active_plugins'         => serialize([]),
            'cp_site_prefix'         => $site_prefix,
            'cp_initialized'         => time(),
        ];
        foreach ($options as $name => $value) {
            $wpdb->insert("{$table_prefix}options", [
                'option_name'  => $name,
                'option_value' => is_array($value) ? maybe_serialize($value) : $value,
                'autoload'     => 'yes',
            ]);
        }

        // 기본 카테고리
        $wpdb->insert("{$table_prefix}terms",        ['name' => '미분류', 'slug' => 'uncategorized', 'term_group' => 0]);
        $term_id = $wpdb->insert_id;
        $wpdb->insert("{$table_prefix}term_taxonomy", ['term_id' => $term_id, 'taxonomy' => 'category', 'description' => '', 'parent' => 0, 'count' => 0]);

        // 관리자 계정 생성
        $hashed_pass = wp_hash_password($admin_pass);
        $wpdb->insert("{$table_prefix}users", [
            'user_login'      => $admin_user,
            'user_pass'       => $hashed_pass,
            'user_nicename'   => $admin_user,
            'user_email'      => $admin_email,
            'user_registered' => current_time('mysql'),
            'display_name'    => $admin_user,
            'user_status'     => 0,
        ]);
        $user_id = $wpdb->insert_id;

        // admin 권한 부여
        $cap_key = $table_prefix . 'capabilities';
        $wpdb->insert("{$table_prefix}usermeta", ['user_id' => $user_id, 'meta_key' => $cap_key,           'meta_value' => serialize(['administrator' => true])]);
        $wpdb->insert("{$table_prefix}usermeta", ['user_id' => $user_id, 'meta_key' => $table_prefix . 'user_level', 'meta_value' => '10']);
        $wpdb->insert("{$table_prefix}options",  ['option_name' => 'user_roles', 'option_value' => serialize(cp_default_roles()), 'autoload' => 'yes']);

        // prefix 복원
        $wpdb->set_prefix($original_prefix);

        return new WP_REST_Response(['success' => true, 'message' => '사이트 초기화 완료', 'site_prefix' => $site_prefix], 201);
    }

    // 이미 존재하는 경우
    return new WP_REST_Response(['success' => true, 'message' => '이미 초기화된 사이트'], 200);
}

// ── 사이트 상태 확인 ──
function cp_rest_site_status($request) {
    global $wpdb;
    $site_prefix = sanitize_key($request->get_header('X-CloudPress-Site') ?: $request->get_param('site_prefix'));
    if (!$site_prefix) return new WP_Error('invalid', 'site_prefix 누락', ['status' => 400]);

    $table = 'wp_' . $site_prefix . '_options';
    $exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");

    return new WP_REST_Response([
        'success'     => true,
        'site_prefix' => $site_prefix,
        'initialized' => (bool)$exists,
    ]);
}

// ── 사이트 삭제 (테이블 DROP) ──
function cp_rest_delete_site($request) {
    global $wpdb;
    $params      = $request->get_json_params();
    $site_prefix = sanitize_key($params['site_prefix'] ?? '');
    if (!$site_prefix || $site_prefix === 'default') {
        return new WP_Error('invalid', '유효하지 않은 site_prefix', ['status' => 400]);
    }

    $prefix = 'wp_' . $site_prefix . '_';
    $tables = $wpdb->get_results("SHOW TABLES LIKE '{$prefix}%'", ARRAY_N);
    $dropped = [];
    foreach ($tables as $row) {
        $table = $row[0];
        // 보안: prefix가 정확히 일치하는 테이블만 DROP
        if (str_starts_with($table, $prefix)) {
            $wpdb->query("DROP TABLE IF EXISTS `$table`");
            $dropped[] = $table;
        }
    }

    // 업로드 파일 삭제 (선택적)
    $upload_dir = WP_CONTENT_DIR . '/uploads/cloudpress_sites/' . $site_prefix;
    if (is_dir($upload_dir)) {
        cp_rmdir_recursive($upload_dir);
    }

    return new WP_REST_Response(['success' => true, 'dropped_tables' => $dropped]);
}

// ── 캐시 플러시 ──
function cp_rest_flush_cache($request) {
    // WP 객체 캐시 클리어 (사이트 전체)
    wp_cache_flush();
    return new WP_REST_Response(['success' => true, 'message' => '캐시 플러시 완료']);
}

// 기본 역할 정의
function cp_default_roles() {
    return [
        'administrator' => ['name' => '관리자', 'capabilities' => ['switch_themes' => true, 'edit_themes' => true, 'activate_plugins' => true, 'edit_plugins' => true, 'edit_users' => true, 'edit_files' => true, 'manage_options' => true, 'moderate_comments' => true, 'manage_categories' => true, 'manage_links' => true, 'upload_files' => true, 'import' => true, 'unfiltered_html' => true, 'edit_posts' => true, 'edit_others_posts' => true, 'edit_published_posts' => true, 'publish_posts' => true, 'edit_pages' => true, 'read' => true, 'level_10' => true, 'level_9' => true, 'level_8' => true, 'level_7' => true, 'level_6' => true, 'level_5' => true, 'level_4' => true, 'level_3' => true, 'level_2' => true, 'level_1' => true, 'level_0' => true, 'edit_others_pages' => true, 'edit_published_pages' => true, 'publish_pages' => true, 'delete_pages' => true, 'delete_others_pages' => true, 'delete_published_pages' => true, 'delete_posts' => true, 'delete_others_posts' => true, 'delete_published_posts' => true, 'delete_private_posts' => true, 'edit_private_posts' => true, 'read_private_posts' => true, 'delete_private_pages' => true, 'edit_private_pages' => true, 'read_private_pages' => true, 'delete_users' => true, 'create_users' => true, 'unfiltered_upload' => true, 'edit_dashboard' => true, 'update_plugins' => true, 'delete_plugins' => true, 'install_plugins' => true, 'update_themes' => true, 'install_themes' => true, 'update_core' => true, 'list_users' => true, 'remove_users' => true, 'promote_users' => true, 'edit_theme_options' => true, 'delete_themes' => true, 'export' => true]],
        'editor'        => ['name' => '편집자', 'capabilities' => ['moderate_comments' => true, 'manage_categories' => true, 'manage_links' => true, 'upload_files' => true, 'unfiltered_html' => true, 'edit_posts' => true, 'edit_others_posts' => true, 'edit_published_posts' => true, 'publish_posts' => true, 'edit_pages' => true, 'read' => true, 'level_7' => true, 'level_6' => true, 'level_5' => true, 'level_4' => true, 'level_3' => true, 'level_2' => true, 'level_1' => true, 'level_0' => true, 'edit_others_pages' => true, 'edit_published_pages' => true, 'publish_pages' => true, 'delete_pages' => true, 'delete_others_pages' => true, 'delete_published_pages' => true, 'delete_posts' => true, 'delete_others_posts' => true, 'delete_published_posts' => true, 'delete_private_posts' => true, 'edit_private_posts' => true, 'read_private_posts' => true, 'delete_private_pages' => true, 'edit_private_pages' => true, 'read_private_pages' => true]],
        'author'        => ['name' => '글쓴이', 'capabilities' => ['upload_files' => true, 'edit_posts' => true, 'edit_published_posts' => true, 'publish_posts' => true, 'read' => true, 'level_2' => true, 'level_1' => true, 'level_0' => true, 'delete_posts' => true, 'delete_published_posts' => true]],
        'contributor'   => ['name' => '기여자', 'capabilities' => ['edit_posts' => true, 'read' => true, 'level_1' => true, 'level_0' => true, 'delete_posts' => true]],
        'subscriber'    => ['name' => '구독자', 'capabilities' => ['read' => true, 'level_0' => true]],
    ];
}

function cp_rmdir_recursive($dir) {
    if (!is_dir($dir)) return;
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . '/' . $item;
        is_dir($path) ? cp_rmdir_recursive($path) : unlink($path);
    }
    rmdir($dir);
}
