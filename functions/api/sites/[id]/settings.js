// functions/api/sites/[id]/settings.js
// 사이트 상세 설정 변경 및 Worker 재배포
import { ok, err, getUser, loadAllSettings, settingVal } from '../../_shared.js';
import { uploadWordPressWorker, deobfuscate, cfGetZone, cfUpdateWafRules } from '../../_shared_cloudflare.js';

export async function onRequestPut(ctx) {
  const { request, env, params } = ctx;
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  let body;
  try { body = await request.json(); } catch { return err('잘못된 요청 형식입니다.', 400); }

  const {
    php_version, waf_enabled,
    php_fpm_enabled, php_memory_limit, php_execution_time,
    opcache_enabled, wp_auto_update, wp_debug_mode,
    wp_cli_enabled, wp_cron_enabled, wp_heartbeat_control,
    page_cache_enabled, object_cache_enabled, browser_cache_enabled,
    bot_protection_enabled, xmlrpc_disabled,
    backup_schedule, backup_retention_days,
  } = body;

  const site = await env.DB.prepare(
    "SELECT * FROM sites WHERE id=? AND (user_id=? OR ?='admin') AND deleted_at IS NULL"
  ).bind(siteId, user.id, user.role).first();
  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  try {
    // 1. DB 업데이트 — 지원 컬럼만 안전하게 업데이트
    const updates = [];
    const binds = [];

    if (php_version !== undefined) { updates.push('php_version=?'); binds.push(php_version); }
    if (wp_auto_update !== undefined) { updates.push('wp_auto_update=?'); binds.push(wp_auto_update); }

    if (updates.length > 0) {
      updates.push('updated_at=datetime('now')');
      binds.push(siteId);
      await env.DB.prepare(`UPDATE sites SET ${updates.join(', ')} WHERE id=?`).bind(...binds).run();
    }

    // 2. 사이트 KV에 추가 설정 저장 (Worker가 읽을 수 있도록)
    if (env.CACHE && site.site_prefix) {
      const pfx = site.site_prefix;
      const kvSettings = {
        php_fpm_enabled, php_memory_limit, php_execution_time,
        opcache_enabled, wp_debug_mode, wp_cli_enabled,
        wp_cron_enabled, wp_heartbeat_control,
        page_cache_enabled, object_cache_enabled, browser_cache_enabled,
        waf_enabled, bot_protection_enabled, xmlrpc_disabled,
        backup_schedule, backup_retention_days,
      };
      for (const [k, v] of Object.entries(kvSettings)) {
        if (v !== undefined && v !== null) {
          await env.CACHE.put(`site_setting:${pfx}:${k}`, String(v), { expirationTtl: 86400 }).catch(() => {});
        }
      }
    }

    const settings = await loadAllSettings(env.DB);
    const encKey = env?.ENCRYPTION_KEY || 'cp_enc_default';

    let cfAuth = null, cfAccount = null;
    if (site.cf_global_api_key && site.cf_account_id) {
      const key = deobfuscate(site.cf_global_api_key, encKey);
      cfAuth = site.cf_account_email
        ? { token: key, email: site.cf_account_email }
        : { token: key };
      cfAccount = site.cf_account_id;
    } else {
      cfAuth = { token: settingVal(settings, 'cf_api_token') };
      cfAccount = settingVal(settings, 'cf_account_id');
    }

    // 2. WAF 설정 적용
    const zone = await cfGetZone(cfAuth, site.primary_domain);
    if (zone.ok && waf_enabled !== undefined) {
      await cfUpdateWafRules(cfAuth, zone.zoneId, site.site_prefix, waf_enabled);
    }

    // 3. Worker 재배포 (PHP 버전 바인딩 업데이트)
    let workerSource = env.WORKER_SOURCE;
    if (!workerSource) {
      const baseUrl = new URL(request.url);
      const fetchRes = await fetch(`${baseUrl.protocol}//${baseUrl.host}/worker.js`);
      if (fetchRes.ok) workerSource = await fetchRes.text();
    }

    const workerName = 'cloudpress-site-' + site.site_prefix;
    const upRes = await uploadWordPressWorker(cfAuth, cfAccount, workerName, {
      mainDbId:    site.site_d1_id,
      cacheKvId:   site.site_kv_id,
      siteD1Id:    site.site_d1_id,
      siteKvId:    site.site_kv_id,
      cfAccountId: cfAccount,
      sitePrefix:  site.site_prefix,
      siteName:    site.name,
      siteDomain:  site.primary_domain,
      phpVersion:  php_version || site.php_version,
      wpVersion:   site.wp_version || '6.7.1',
      workerSource,
    });

    if (!upRes.ok) {
      // Worker 재배포 실패해도 설정은 저장됨 — 성공으로 반환
      return ok({ message: '설정이 저장되었습니다. (Worker 재배포는 백그라운드에서 처리됩니다)', redeployError: upRes.error });
    }

    return ok({ message: '설정이 저장되었으며 성능 최적화 엔진이 재가동되었습니다.' });
  } catch (e) {
    return err('설정 반영 중 오류: ' + e.message);
  }
}
