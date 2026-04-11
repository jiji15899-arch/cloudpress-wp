/**
 * CloudPress Proxy Worker v11.0
 * 
 * 역할:
 *   1. 요청 도메인으로 D1에서 사이트 조회 (KV 캐시)
 *   2. site_prefix를 헤더에 붙여 단일 WP origin으로 프록시
 *   3. WP 응답의 URL을 origin → 개인 도메인으로 치환
 *   4. 각 사이트 완전 격리 (D1 prefix + KV prefix)
 * 
 * 환경 변수 (wrangler.toml에 설정):
 *   WP_ORIGIN_URL    — https://origin.cloudpress.site
 *   WP_ORIGIN_SECRET — mu-plugin 공유 시크릿
 *   DB               — D1 binding
 *   CACHE            — KV binding (도메인→사이트 캐시 + 페이지 캐시)
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const host = url.hostname.replace(/^www\./, ''); // www 제거해서 루트 도메인으로 통일

    // ── 1. 관리자 패널은 프록시 안 함 ──
    if (url.pathname.startsWith('/__cloudpress/') || url.pathname.startsWith('/api/')) {
      return fetch(request);
    }

    // ── 2. 사이트 조회 (KV 캐시 우선) ──
    let site = null;
    const cacheKey = `site_domain:${host}`;

    try {
      const cached = await env.CACHE.get(cacheKey, { type: 'json' });
      if (cached) {
        site = cached;
      } else {
        // D1에서 조회
        const row = await env.DB.prepare(
          `SELECT id, name, site_prefix, wp_admin_url, status, suspended, suspension_reason
           FROM sites
           WHERE (primary_domain=? OR www_domain=?)
             AND status='active'
             AND (deleted_at IS NULL)
             AND suspended=0
           LIMIT 1`
        ).bind(host, url.hostname).first();

        if (row) {
          site = row;
          // 5분 캐시
          await env.CACHE.put(cacheKey, JSON.stringify(row), { expirationTtl: 300 });
        }
      }
    } catch (e) {
      return errorPage(500, '서버 오류', e.message);
    }

    // ── 3. 사이트 없음 ──
    if (!site) {
      return errorPage(404, '사이트를 찾을 수 없습니다', `도메인 ${host}에 연결된 사이트가 없습니다.`);
    }

    // ── 4. 정지된 사이트 ──
    if (site.suspended) {
      return suspendedPage(site.name, site.suspension_reason);
    }

    // ── 5. WP admin 리다이렉트 처리 ──
    // /wp-admin/ 접근 시 origin WP admin으로 리다이렉트 (prefix 파라미터 포함)
    if (url.pathname.startsWith('/wp-admin') || url.pathname === '/wp-login.php') {
      const wpAdminUrl = env.WP_ORIGIN_URL.replace(/\/$/, '') + url.pathname + url.search;
      const adminWithPrefix = new URL(wpAdminUrl);
      adminWithPrefix.searchParams.set('cp_site', site.site_prefix);
      return Response.redirect(adminWithPrefix.toString(), 302);
    }

    // ── 6. 페이지 캐시 (GET만, wp-admin 제외) ──
    const isCacheable = request.method === 'GET'
      && !url.pathname.startsWith('/wp-')
      && !url.searchParams.has('preview')
      && !request.headers.get('cookie')?.includes('wordpress_logged_in');

    if (isCacheable) {
      const pageCacheKey = `page:${site.site_prefix}:${url.pathname}${url.search}`;
      try {
        const cachedPage = await env.CACHE.get(pageCacheKey, { type: 'arrayBuffer' });
        if (cachedPage) {
          const cachedMeta = await env.CACHE.get(pageCacheKey + ':meta', { type: 'json' });
          return new Response(cachedPage, {
            headers: {
              'Content-Type': cachedMeta?.contentType || 'text/html; charset=utf-8',
              'X-Cache': 'HIT',
              'X-Site-Prefix': site.site_prefix,
            },
          });
        }
      } catch (_) {}
    }

    // ── 7. WP Origin으로 프록시 ──
    const originUrl = new URL(env.WP_ORIGIN_URL);
    originUrl.pathname = url.pathname;
    originUrl.search   = url.search;

    // 요청 헤더 복사 + 사이트 격리 헤더 추가
    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.set('X-CloudPress-Site',   site.site_prefix);  // WP mu-plugin이 읽음
    proxyHeaders.set('X-CloudPress-Secret', env.WP_ORIGIN_SECRET);
    proxyHeaders.set('X-CloudPress-Domain', url.hostname);
    proxyHeaders.set('Host', originUrl.hostname);
    proxyHeaders.set('X-Forwarded-Host', url.hostname);
    proxyHeaders.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
    // 원래 클라이언트 IP
    proxyHeaders.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || '');
    // origin 시크릿 검증용
    proxyHeaders.set('Authorization', 'Bearer ' + env.WP_ORIGIN_SECRET);

    let originResponse;
    try {
      originResponse = await fetch(originUrl.toString(), {
        method:  request.method,
        headers: proxyHeaders,
        body:    ['GET', 'HEAD'].includes(request.method) ? null : request.body,
        redirect: 'manual', // 리다이렉트 직접 처리
      });
    } catch (e) {
      return errorPage(502, 'Origin 서버 연결 실패', e.message);
    }

    // ── 8. 리다이렉트 처리 — origin URL → 개인 도메인으로 교체 ──
    if (originResponse.status >= 300 && originResponse.status < 400) {
      const location = originResponse.headers.get('Location') || '';
      const fixedLocation = rewriteUrl(location, env.WP_ORIGIN_URL, url.origin);
      return new Response(null, {
        status: originResponse.status,
        headers: { 'Location': fixedLocation },
      });
    }

    // ── 9. 응답 헤더 구성 ──
    const responseHeaders = new Headers();
    const skipHeaders = new Set(['transfer-encoding', 'content-encoding', 'content-length', 'connection', 'keep-alive']);
    for (const [k, v] of originResponse.headers) {
      if (!skipHeaders.has(k.toLowerCase())) responseHeaders.set(k, v);
    }
    responseHeaders.set('X-Cache', 'MISS');
    responseHeaders.set('X-Site-Prefix', site.site_prefix);
    // 보안 헤더
    responseHeaders.set('X-Frame-Options', 'SAMEORIGIN');
    responseHeaders.set('X-Content-Type-Options', 'nosniff');

    const contentType = originResponse.headers.get('content-type') || '';

    // ── 10. HTML 응답 — URL 치환 ──
    if (contentType.includes('text/html')) {
      const html = await originResponse.text();
      const rewritten = html
        // origin URL → 개인 도메인
        .replace(new RegExp(escapeRegex(env.WP_ORIGIN_URL), 'g'), url.origin)
        // origin 호스트명 → 개인 도메인 호스트명
        .replace(new RegExp(escapeRegex(originUrl.hostname), 'g'), url.hostname);

      const body = new TextEncoder().encode(rewritten);

      // 페이지 캐시 저장 (10분)
      if (isCacheable && originResponse.status === 200) {
        const pageCacheKey = `page:${site.site_prefix}:${url.pathname}${url.search}`;
        env.CACHE.put(pageCacheKey, body, { expirationTtl: 600 }).catch(() => {});
        env.CACHE.put(pageCacheKey + ':meta', JSON.stringify({ contentType }), { expirationTtl: 600 }).catch(() => {});
      }

      return new Response(body, {
        status:  originResponse.status,
        headers: responseHeaders,
      });
    }

    // ── 11. CSS/JS — URL 치환 ──
    if (contentType.includes('text/css') || contentType.includes('javascript')) {
      const text = await originResponse.text();
      const rewritten = text.replace(new RegExp(escapeRegex(env.WP_ORIGIN_URL), 'g'), url.origin);
      return new Response(rewritten, { status: originResponse.status, headers: responseHeaders });
    }

    // ── 12. 바이너리 (이미지, 폰트 등) — 그대로 통과 ──
    return new Response(originResponse.body, { status: originResponse.status, headers: responseHeaders });
  },
};

// ── 헬퍼 ──

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function rewriteUrl(url, originBase, personalBase) {
  if (url.startsWith(originBase)) return personalBase + url.slice(originBase.length);
  return url;
}

function errorPage(status, title, detail) {
  return new Response(
    `<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>${title}</title>
    <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f9fa}
    .box{text-align:center;padding:40px;max-width:400px}h1{color:#333;font-size:1.5rem}p{color:#666;font-size:.9rem}</style>
    </head><body><div class="box"><h1>${title}</h1><p>${detail}</p></div></body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

function suspendedPage(siteName, reason) {
  return new Response(
    `<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>사이트 일시정지</title>
    <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff8f0}
    .box{text-align:center;padding:40px;max-width:400px}h1{color:#e67e22;font-size:1.5rem}p{color:#666;font-size:.9rem}</style>
    </head><body><div class="box"><h1>⚠️ 사이트 일시정지</h1><p>${siteName || '이 사이트'}는 현재 일시정지 상태입니다.</p>
    ${reason ? `<p style="color:#999;font-size:.8rem">${reason}</p>` : ''}
    </div></body></html>`,
    { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}
