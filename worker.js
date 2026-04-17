/**
 * CloudPress — Proxy Worker (cloudpress-proxy)
 * wrangler.worker.toml: main = "worker.js"
 *
 * 역할:
 *   사용자 커스텀 도메인으로 들어오는 요청을
 *   KV 캐시(CACHE) 또는 D1(DB)에서 사이트를 조회한 뒤
 *   WP_ORIGIN_URL 로 프록시합니다.
 *
 * 환경 바인딩:
 *   DB               — D1 (cloudpress-db)
 *   CACHE            — KV (도메인 → 사이트 매핑 캐시)
 *   WP_ORIGIN_URL    — 프록시 대상 WP origin URL
 *   WP_ORIGIN_SECRET — origin 인증 시크릿
 *
 * @package CloudPress
 */

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

/* ── 정적 HTML ────────────────────────────────────────────────────────────── */

const SUSPENDED_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>사이트 정지됨</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,sans-serif;display:flex;align-items:center;
         justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}
    .box{text-align:center;padding:2rem;max-width:480px}
    h1{font-size:2rem;margin-bottom:1rem;color:#f55}
    p{color:#aaa;line-height:1.6}
  </style>
</head>
<body>
  <div class="box">
    <h1>🚫 사이트가 정지되었습니다</h1>
    <p>이 사이트는 현재 이용 중지 상태입니다.<br>
       문의사항은 CloudPress 고객센터로 연락해 주세요.</p>
  </div>
</body>
</html>`;

const NOT_FOUND_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>사이트를 찾을 수 없음</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,sans-serif;display:flex;align-items:center;
         justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}
    .box{text-align:center;padding:2rem;max-width:480px}
    h1{font-size:2rem;margin-bottom:1rem;color:#fa0}
    p{color:#aaa;line-height:1.6}
    a{color:#7af;text-decoration:none}
  </style>
</head>
<body>
  <div class="box">
    <h1>🔍 사이트를 찾을 수 없습니다</h1>
    <p>요청한 도메인에 연결된 사이트가 없습니다.<br>
       <a href="https://cloudpress.pages.dev/">CloudPress 대시보드</a>에서 도메인을 확인해 주세요.</p>
  </div>
</body>
</html>`;

const PROVISIONING_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <title>사이트 준비 중</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,sans-serif;display:flex;align-items:center;
         justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff;text-align:center}
    .box{padding:2rem;max-width:480px}
    h1{font-size:1.8rem;margin-bottom:1rem;color:#7af}
    p{color:#aaa;line-height:1.6}
    .spin{font-size:2.5rem;display:inline-block;animation:spin 1.2s linear infinite;margin-bottom:1rem}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="box">
    <div class="spin">⚙️</div>
    <h1>사이트를 준비 중입니다</h1>
    <p>배포가 완료되면 자동으로 페이지가 갱신됩니다.<br>잠시만 기다려 주세요.</p>
  </div>
</body>
</html>`;

/* ── 메인 핸들러 ──────────────────────────────────────────────────────────── */

async function handleRequest(request, env) {
  const url      = new URL(request.url);
  const hostname = url.hostname.toLowerCase();

  /* 1. cloudpress 자체 도메인은 그대로 통과 */
  if (
    hostname.endsWith('.pages.dev') ||
    hostname.endsWith('.workers.dev') ||
    hostname === 'cloud-press.co.kr' ||
    hostname === 'www.cloud-press.co.kr'
  ) {
    return fetch(request);
  }

  /* 2. KV 캐시에서 도메인 → 사이트 조회 */
  let siteInfo = null;
  try {
    siteInfo = await env.CACHE.get(`site_domain:${hostname}`, { type: 'json' });
  } catch (_) {}

  /* 3. 캐시 미스 → D1 직접 조회 후 캐시 갱신 */
  if (!siteInfo) {
    try {
      const row = await env.DB
        .prepare(
          `SELECT id, name, site_prefix, status, suspended
             FROM sites
            WHERE primary_domain = ?
              AND domain_status  = 'active'
              AND deleted_at IS NULL
            LIMIT 1`
        )
        .bind(hostname)
        .first();

      if (row) {
        siteInfo = {
          id:          row.id,
          name:        row.name,
          site_prefix: row.site_prefix || row.id,
          status:      row.status,
          suspended:   row.suspended,
        };
        /* 캐시 저장 (24시간) — 실패해도 계속 진행 */
        env.CACHE.put(
          `site_domain:${hostname}`,
          JSON.stringify(siteInfo),
          { expirationTtl: 86400 }
        ).catch(() => {});
      }
    } catch (_) {}
  }

  /* 4. 사이트 없음 → 404 */
  if (!siteInfo) {
    return new Response(NOT_FOUND_HTML, {
      status: 404,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  /* 5. 정지된 사이트 → 403 */
  if (siteInfo.suspended || siteInfo.status === 'suspended') {
    return new Response(SUSPENDED_HTML, {
      status: 403,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  /* 6. 프로비저닝 중 → 503 (10초 후 새로고침) */
  if (siteInfo.status === 'pending' || siteInfo.status === 'provisioning') {
    return new Response(PROVISIONING_HTML, {
      status: 503,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After':  '10',
      },
    });
  }

  /* 7. WP_ORIGIN_URL 로 프록시 */
  const originBase   = (env.WP_ORIGIN_URL || '').replace(/\/$/, '');
  const originSecret = env.WP_ORIGIN_SECRET || '';
  const sitePrefix   = siteInfo.site_prefix || siteInfo.id;

  if (!originBase) {
    return new Response('Proxy origin not configured.', { status: 502 });
  }

  const targetUrl = originBase + url.pathname + url.search;

  /* 요청 헤더 복사 + CloudPress 식별 헤더 추가 */
  const reqHeaders = new Headers(request.headers);
  reqHeaders.set('X-CloudPress-Site',   sitePrefix);
  reqHeaders.set('X-CloudPress-Secret', originSecret);
  reqHeaders.set('X-Forwarded-Host',    hostname);
  reqHeaders.set('X-Forwarded-Proto',   url.protocol.replace(':', ''));
  reqHeaders.set('Host', new URL(originBase).hostname);

  const proxyReq = new Request(targetUrl, {
    method:   request.method,
    headers:  reqHeaders,
    body:     ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
    redirect: 'manual',
  });

  let originRes;
  try {
    originRes = await fetch(proxyReq);
  } catch (e) {
    return new Response('Origin unreachable: ' + String(e.message), { status: 502 });
  }

  /* 응답 헤더 정리 */
  const respHeaders = new Headers(originRes.headers);
  respHeaders.delete('x-powered-by');
  respHeaders.delete('server');

  /* Location 헤더의 origin 도메인 → 사용자 도메인으로 교체 */
  const location = respHeaders.get('location');
  if (location) {
    try {
      const loc        = new URL(location, originBase);
      const originHost = new URL(originBase).hostname;
      if (loc.hostname === originHost) {
        loc.hostname = hostname;
        loc.protocol = url.protocol;
        respHeaders.set('location', loc.toString());
      }
    } catch (_) {}
  }

  return new Response(originRes.body, {
    status:  originRes.status,
    headers: respHeaders,
  });
}
