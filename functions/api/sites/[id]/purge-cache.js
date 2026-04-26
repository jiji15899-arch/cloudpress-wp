// functions/api/sites/[id]/purge-cache.js — CloudPress v20.0
// 캐시 제거 API: KV 캐시 + Cloudflare Edge 캐시 purge

import { CORS, ok, err, getUser, settingVal } from '../../_shared.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

export async function onRequestPost({ request, env, params }) {
  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  const siteId = params?.id;
  if (!siteId) return err('사이트 ID가 없습니다.', 400);

  // 사이트 + settings 조회
  let site, settings;
  try {
    const [siteRows, settingsRows] = await env.DB.batch([
      env.DB.prepare(
        `SELECT id, user_id, name, primary_domain, site_prefix, worker_name,
                cf_zone_id, site_kv_id, status
         FROM sites WHERE id=? AND (user_id=? OR ?='admin') AND deleted_at IS NULL`
      ).bind(siteId, user.id, user.role),
      env.DB.prepare('SELECT key, value FROM settings'),
    ]);
    site = siteRows.results?.[0] ?? null;
    settings = {};
    for (const r of settingsRows.results || []) settings[r.key] = r.value ?? '';
  } catch (e) {
    return err('데이터 조회 오류: ' + e.message, 500);
  }

  if (!site) return err('사이트를 찾을 수 없습니다.', 404);

  const domain    = site.primary_domain;
  const prefix    = site.site_prefix;
  const results   = [];

  // ── 1. KV 페이지 캐시 삭제 ────────────────────────────────────────────────
  // 주의: site_domain: 키는 삭제하지 않음 — 삭제 시 worker가 사이트를 찾지 못해 404/에러 발생
  if (env.CACHE) {
    try {
      const pageKeysToDelete = [
        `page:${prefix}:/`,
        `page:${prefix}:/index`,
        `page:${prefix}:/?`,
      ];
      await Promise.allSettled(pageKeysToDelete.map(k => env.CACHE.delete(k)));
      results.push({ step: 'kv_cache', ok: true, message: `KV 페이지 캐시 삭제 완료 (${pageKeysToDelete.length}건)` });
    } catch (e) {
      results.push({ step: 'kv_cache', ok: false, error: e.message });
    }
  }

  // ── 2. 사이트 전용 KV 캐시 삭제 ──────────────────────────────────────────
  if (site.site_kv_id) {
    try {
      const cfToken   = settingVal(settings, 'cf_api_token');
      const cfAccount = settingVal(settings, 'cf_account_id');
      if (cfToken && cfAccount) {
        // KV 전체 키 목록 조회 후 page: 접두사 삭제
        const listRes = await fetch(
          `${CF_API}/accounts/${cfAccount}/storage/kv/namespaces/${site.site_kv_id}/keys?prefix=page%3A&limit=100`,
          { headers: { 'Authorization': 'Bearer ' + cfToken } }
        ).then(r => r.json()).catch(() => ({}));

        const keys = (listRes.result || []).map(k => k.name);
        if (keys.length > 0) {
          await fetch(
            `${CF_API}/accounts/${cfAccount}/storage/kv/namespaces/${site.site_kv_id}/bulk/delete`,
            {
              method: 'DELETE',
              headers: { 'Authorization': 'Bearer ' + cfToken, 'Content-Type': 'application/json' },
              body: JSON.stringify(keys),
            }
          );
        }
        results.push({ step: 'site_kv', ok: true, message: `사이트 KV 캐시 삭제 완료 (${keys.length}건)` });
      }
    } catch (e) {
      results.push({ step: 'site_kv', ok: false, error: e.message });
    }
  }

  // ── 3. Cloudflare Edge 캐시 Purge ─────────────────────────────────────────
  if (domain) {
    try {
      const cfToken  = settingVal(settings, 'cf_api_token');
      const zoneId   = site.cf_zone_id;

      if (cfToken && zoneId) {
        const purgeRes = await fetch(
          `${CF_API}/zones/${zoneId}/purge_cache`,
          {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + cfToken, 'Content-Type': 'application/json' },
            body: JSON.stringify({ purge_everything: true }),
          }
        ).then(r => r.json()).catch(() => ({}));

        if (purgeRes.success) {
          results.push({ step: 'cf_edge_cache', ok: true, message: 'Cloudflare Edge 캐시 전체 제거 완료' });
        } else {
          // Zone이 없어도 URL 기반 purge 시도
          const urlPurge = await fetch(
            `${CF_API}/zones/${zoneId}/purge_cache`,
            {
              method: 'POST',
              headers: { 'Authorization': 'Bearer ' + cfToken, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                files: [
                  `https://${domain}/`,
                  `https://${domain}/wp-json/wp/v2/posts`,
                  `https://www.${domain}/`,
                ],
              }),
            }
          ).then(r => r.json()).catch(() => ({}));
          results.push({ step: 'cf_edge_cache', ok: urlPurge.success, message: 'URL 기반 캐시 제거' });
        }
      } else {
        results.push({ step: 'cf_edge_cache', ok: false, message: 'CF 토큰 또는 Zone ID 미설정 (KV 캐시만 제거됨)' });
      }
    } catch (e) {
      results.push({ step: 'cf_edge_cache', ok: false, error: e.message });
    }
  }

  const allOk = results.some(r => r.ok);

  return ok({
    message: allOk ? '✅ 캐시가 제거되었습니다.' : '⚠️ 일부 캐시 제거가 실패했습니다.',
    domain,
    results,
  });
}
