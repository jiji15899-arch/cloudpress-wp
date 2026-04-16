/**
 * CloudPress Proxy Worker v14.0
 *
 * [v14.0 변경사항]
 * - 모든 경로(wp-admin, wp-login, 일반 페이지, CSS/JS)에서
 *   WP Origin URL을 사용자 개인 도메인으로 완전히 덮어씀
 * - Set-Cookie 헤더의 도메인도 치환
 * - 리다이렉트 Location 헤더 완전 치환
 * - HTML/CSS/JS 본문 내 origin host/URL 전부 치환
 */

const CF_KV_API = 'https://api.cloudflare.com/client/v4';

export default {
  async fetch(request, env) {
    // ── 0. 필수 바인딩 null 가드 ─────────────────────────────────
    if (!env || !env.DB) {
      return errorPage(503, '서버 설정 오류', 'DB 바인딩이 연결되지 않았습니다.');
    }
    if (!env.CACHE) {
      return errorPage(503, '서버 설정 오류', 'CACHE KV 바인딩이 연결되지 않았습니다.');
    }

    const url     = new URL(request.url);
    const rawHost = url.hostname;                          // www 포함 원본
    const host    = rawHost.replace(/^www\./, '');         // www 제거
    const personalOrigin = 'https://' + rawHost;           // 사용자 개인 도메인 origin

    // ── 1. 관리 API / 내부 경로는 프록시 안 함 ──────────────────
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/__cloudpress/')) {
      return fetch(request);
    }

    // ── 2. 사이트 조회 (CACHE KV 우선 → 메인 D1 fallback) ───────
    let site = null;
    const cacheKey = `site_domain:${host}`;

    try {
      const cached = await env.CACHE.get(cacheKey, { type: 'json' });
      if (cached) {
        site = cached;
      } else {
        const row = await env.DB.prepare(
          `SELECT id, name, site_prefix,
                  site_d1_id, site_kv_id,
                  wp_admin_url, status, suspended, suspension_reason
           FROM sites
           WHERE primary_domain=?
             AND status='active'
             AND deleted_at IS NULL
             AND suspended=0
           LIMIT 1`
        ).bind(host).first();

        if (row) {
          site = row;
          await env.CACHE.put(cacheKey, JSON.stringify(row), { expirationTtl: 300 });
        }
      }
    } catch (e) {
      return errorPage(500, '서버 오류', e.message);
    }

    if (!site) {
      return errorPage(404, '사이트를 찾을 수 없습니다', `${host}에 연결된 사이트가 없습니다.`);
    }
    if (site.suspended) {
      return suspendedPage(site.name, site.suspension_reason);
    }

    // ── 3. WP Origin URL 확보 ─────────────────────────────────────
    const wpOriginUrl = (env.WP_ORIGIN_URL || '').trim().replace(/\/$/, '');
    if (!wpOriginUrl) {
      return errorPage(503, '서버 설정 오류', 'WP_ORIGIN_URL이 설정되지 않았습니다.');
    }
    const wpOriginHost = new URL(wpOriginUrl).hostname;

    // ── 4. WP Admin / wp-login 포함 전체 경로 프록시 ─────────────
    //    (wp-admin도 개인 도메인 기준으로 완전 치환)
    const targetUrl = new URL(wpOriginUrl + url.pathname + url.search);
    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.set('X-CloudPress-Site',       site.site_prefix || '');
    proxyHeaders.set('X-CloudPress-Secret',     env.WP_ORIGIN_SECRET || '');
    proxyHeaders.set('X-CloudPress-Domain',     rawHost);
    proxyHeaders.set('X-CloudPress-D1-ID',      site.site_d1_id || '');
    proxyHeaders.set('X-CloudPress-KV-ID',      site.site_kv_id || '');
    proxyHeaders.set('X-CloudPress-Public-URL', personalOrigin);
    proxyHeaders.set('Host',                    wpOriginHost);
    proxyHeaders.set('X-Forwarded-Host',        rawHost);
    proxyHeaders.set('X-Forwarded-Proto',       'https');
    proxyHeaders.set('X-Real-IP',               request.headers.get('CF-Connecting-IP') || '');

    let originRes;
    try {
      originRes = await fetch(targetUrl.toString(), {
        method:   request.method,
        headers:  proxyHeaders,
        body:     ['GET', 'HEAD'].includes(request.method) ? null : request.body,
        redirect: 'manual',
      });
    } catch (e) {
      return errorPage(502, 'Origin 연결 실패', e.message);
    }

    // ── 5. 리다이렉트 — Location에서 origin 완전 치환 ────────────
    if (originRes.status >= 300 && originRes.status < 400) {
      let loc = originRes.headers.get('Location') || '';
      loc = rewriteStr(loc, wpOriginUrl, personalOrigin, wpOriginHost, rawHost);
      // 혹시 origin host만 남아있는 경우도 처리
      if (loc.startsWith('http://') || loc.startsWith('https://')) {
        try {
          const locUrl = new URL(loc);
          if (locUrl.hostname === wpOriginHost) {
            locUrl.hostname = rawHost;
            locUrl.protocol = 'https:';
            loc = locUrl.toString();
          }
        } catch (_) {}
      }
      const redirHeaders = new Headers();
      redirHeaders.set('Location', loc);
      // Set-Cookie도 그대로 전달
      for (const [k, v] of originRes.headers) {
        if (k.toLowerCase() === 'set-cookie') {
          redirHeaders.append('Set-Cookie', rewriteCookie(v, wpOriginHost, rawHost));
        }
      }
      return new Response(null, { status: originRes.status, headers: redirHeaders });
    }

    // ── 6. 응답 헤더 구성 ────────────────────────────────────────
    const resHeaders = new Headers();
    const skip = new Set(['transfer-encoding', 'content-encoding', 'content-length', 'connection', 'keep-alive']);
    for (const [k, v] of originRes.headers) {
      const kl = k.toLowerCase();
      if (skip.has(kl)) continue;
      if (kl === 'set-cookie') {
        // Set-Cookie domain을 개인 도메인으로 치환
        resHeaders.append('Set-Cookie', rewriteCookie(v, wpOriginHost, rawHost));
      } else {
        resHeaders.set(k, v);
      }
    }
    resHeaders.set('X-Cache',                'MISS');
    resHeaders.set('X-Site-Prefix',          site.site_prefix || '');
    resHeaders.set('X-Frame-Options',        'SAMEORIGIN');
    resHeaders.set('X-Content-Type-Options', 'nosniff');

    const contentType = originRes.headers.get('content-type') || '';

    // ── 7. 캐시 여부 판단 (wp-admin 제외) ────────────────────────
    const isCacheable = request.method === 'GET'
      && !url.pathname.startsWith('/wp-admin')
      && url.pathname !== '/wp-login.php'
      && !url.pathname.startsWith('/wp-')
      && !url.searchParams.has('preview')
      && !(request.headers.get('cookie') || '').includes('wordpress_logged_in');

    // ── 8. HTML — origin 완전 치환 + 페이지 캐시 저장 ────────────
    if (contentType.includes('text/html')) {
      let html = await originRes.text();
      html = rewriteStr(html, wpOriginUrl, personalOrigin, wpOriginHost, rawHost);

      if (isCacheable && originRes.status === 200 && site.site_kv_id && env.CF_ACCOUNT_ID && env.CF_API_TOKEN) {
        const pageCacheKey = `page:${url.pathname}${url.search || ''}`;
        kvPut(env.CF_API_TOKEN, env.CF_ACCOUNT_ID, site.site_kv_id, pageCacheKey, {
          body: html, contentType,
        }, 600).catch(() => {});
      }

      return new Response(html, { status: originRes.status, headers: resHeaders });
    }

    // ── 9. CSS/JS — origin 치환 ───────────────────────────────────
    if (contentType.includes('text/css') || contentType.includes('javascript')) {
      let text = await originRes.text();
      text = rewriteStr(text, wpOriginUrl, personalOrigin, wpOriginHost, rawHost);
      return new Response(text, { status: originRes.status, headers: resHeaders });
    }

    // ── 10. 바이너리 ─────────────────────────────────────────────
    return new Response(originRes.body, { status: originRes.status, headers: resHeaders });
  },
};

// ── 헬퍼: origin 문자열 치환 (URL 전체 + 호스트명) ────────────────
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function rewriteStr(text, originBase, personalBase, originHost, personalHost) {
  // 1) http/https origin 전체 치환 (URL 형태)
  text = text.replace(new RegExp(escapeRegex(originBase.replace(/^https?:/, 'https:')), 'g'), personalBase);
  text = text.replace(new RegExp(escapeRegex(originBase.replace(/^https?:/, 'http:')),  'g'), personalBase);
  // 2) origin base 그대로 치환
  text = text.replace(new RegExp(escapeRegex(originBase), 'g'), personalBase);
  // 3) 호스트명만 남은 경우 치환
  if (originHost !== personalHost) {
    text = text.replace(new RegExp(escapeRegex(originHost), 'g'), personalHost);
  }
  return text;
}

// ── 헬퍼: Set-Cookie의 Domain 속성 치환 ──────────────────────────
function rewriteCookie(cookieStr, originHost, personalHost) {
  return cookieStr.replace(
    new RegExp('(domain=)' + escapeRegex(originHost), 'gi'),
    '$1' + personalHost
  );
}

// ── KV REST API 헬퍼 ─────────────────────────────────────────────
async function kvGet(apiToken, accountId, namespaceId, key) {
  try {
    const res = await fetch(
      `${CF_KV_API}/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`,
      { headers: { 'Authorization': 'Bearer ' + apiToken } }
    );
    if (!res.ok) return null;
    return await res.json().catch(() => null);
  } catch { return null; }
}

async function kvPut(apiToken, accountId, namespaceId, key, value, ttl = 600) {
  await fetch(
    `${CF_KV_API}/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}?expiration_ttl=${ttl}`,
    {
      method:  'PUT',
      headers: { 'Authorization': 'Bearer ' + apiToken, 'Content-Type': 'application/json' },
      body:    JSON.stringify(value),
    }
  );
}

// ── 에러/정지 페이지 ─────────────────────────────────────────────
function errorPage(status, title, detail) {
  const safe = String(detail).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return new Response(
    `<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>${title}</title>
    <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f9fa}
    .box{text-align:center;padding:40px;max-width:480px}h1{color:#333;font-size:1.4rem}p{color:#666;font-size:.88rem;line-height:1.6}</style>
    </head><body><div class="box"><h1>${title}</h1><p>${safe}</p></div></body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

function suspendedPage(siteName, reason) {
  return new Response(
    `<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>사이트 일시정지</title>
    <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff8f0}
    .box{text-align:center;padding:40px;max-width:420px}h1{color:#e67e22;font-size:1.4rem}p{color:#666;font-size:.88rem}</style>
    </head><body><div class="box"><h1>⚠️ 사이트 일시정지</h1>
    <p>${siteName || '이 사이트'}는 현재 일시정지 상태입니다.</p>
    ${reason ? `<p style="color:#999;font-size:.8rem">${reason}</p>` : ''}
    </div></body></html>`,
    { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

/**
 * CloudPress CMS — Worker Entry Point
 *
 * Cloudflare Workers requires a default export with fetch (and optionally
 * scheduled) handlers. This file is the true entry point declared in
 * wrangler.toml (`main = "worker.js"`).
 *
 * @package CloudPress
 */

import { route }           from './cp-router.js';
import { handleScheduled } from './cp-cron.js';

export default {
  /**
   * Handle HTTP requests.
   */
  async fetch(request, env, ctx) {
    return route(request, env, ctx);
  },

  /**
   * Handle Cloudflare Cron Triggers.
   */
  async scheduled(event, env, ctx) {
    return handleScheduled(event, env, ctx);
  },
};
