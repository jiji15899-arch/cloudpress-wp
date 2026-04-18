/**
 * CloudPress — Proxy Worker (cloudpress-proxy) v18.0
 * wrangler.worker.toml: main = "worker.js"
 *
 * [수정 사항 — Error 1101 / 사이트 미표시 / DNS 인증 수정]
 *
 * 1) Error 1101 근본 원인 수정:
 *    - 최상위 await 제거 (Workers 런타임에서 금지)
 *    - 모든 env 바인딩 접근을 fetch() 핸들러 내부로 이동
 *    - try/catch 없이 env 접근 시 uncaught 예외 → 1101 발생하던 것 방지
 *
 * 2) CMS 사이트 렌더링:
 *    - JS/CSS만으로 이루어진 CMS Worker를 정상적인 HTML 페이지로 변환
 *    - Origin(WP/CMS)에서 받은 응답이 HTML이 아닌 경우 자동 래핑
 *    - CSS/JS 파일은 그대로 프록시, HTML은 Content-Type 보정
 *    - X-CloudPress-Render: cms 헤더로 CMS 렌더링 요청 명시
 *
 * 3) DNS 인증 URL 전용 라우트 추가:
 *    /.well-known/cloudpress-verify/<token>  →  TXT/HTML 인증 응답
 *
 * 환경 바인딩:
 *   DB               — D1 (cloudpress-db)
 *   CACHE            — KV (도메인 → 사이트 매핑 캐시)
 *   WP_ORIGIN_URL    — 프록시 대상 WP/CMS origin URL
 *   WP_ORIGIN_SECRET — origin 인증 시크릿
 *   CF_ACCOUNT_ID    — Cloudflare Account ID
 *   CF_API_TOKEN     — Cloudflare API Token
 *
 * @package CloudPress
 */

var __worker = {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      // Error 1101 방지: 최상위 예외를 절대 throw하지 않고 500으로 반환
      console.error('[worker] Unhandled error:', e?.message || e);
      return new Response(
        `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<title>일시적 오류</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;
min-height:100vh;margin:0;background:#0f0f0f;color:#fff}
.box{text-align:center;padding:2rem;max-width:480px}
h1{color:#f55;margin-bottom:1rem}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box">
<h1>⚠️ 일시적 서버 오류</h1>
<p>잠시 후 다시 시도해 주세요.<br>
문제가 지속되면 CloudPress 고객센터로 연락해 주세요.</p>
</div></body></html>`,
        { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      );
    }
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

/* ── CMS HTML 래퍼 (JS/CSS만 있는 CMS를 웹 페이지로 변환) ──────────────── */

/**
 * CMS Worker가 JS/CSS 응답만 반환할 때 완전한 HTML 페이지로 래핑
 * @param {string} sitePrefix - 사이트 식별자
 * @param {string} siteName   - 사이트 이름
 * @param {string} originBase - origin URL
 * @param {string} pathname   - 현재 경로
 * @param {string} hostname   - 사용자 도메인
 * @returns {string} 완성된 HTML
 */
function buildCMSShellHTML(sitePrefix, siteName, originBase, pathname, hostname) {
  const title = siteName || sitePrefix || 'CloudPress Site';
  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="CloudPress">
  <title>${escHtml(title)}</title>
  <!-- CloudPress CMS 스타일시트 -->
  <link rel="stylesheet" href="${originBase}/cp-includes/css/template-fallback.css">
  <link rel="stylesheet" href="${originBase}/cp-includes/css/comments.css">
  <style>
    /* CloudPress 기본 레이아웃 */
    *, *::before, *::after { box-sizing: border-box; }
    html { font-size: 16px; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                   'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #1d2327;
      background: #fff;
    }
    #cloudpress-app {
      min-height: 100vh;
    }
    /* 로딩 인디케이터 */
    #cp-loading {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 60vh;
      flex-direction: column;
      gap: 1rem;
      color: #646970;
    }
    #cp-loading .spinner {
      width: 36px;
      height: 36px;
      border: 3px solid #dcdcde;
      border-top-color: #2271b1;
      border-radius: 50%;
      animation: cp-spin 0.8s linear infinite;
    }
    @keyframes cp-spin { to { transform: rotate(360deg); } }
    /* 에러 표시 */
    #cp-error {
      display: none;
      padding: 2rem;
      max-width: 600px;
      margin: 4rem auto;
      text-align: center;
      color: #cc1818;
    }
  </style>
</head>
<body>
  <div id="cloudpress-app">
    <div id="cp-loading">
      <div class="spinner"></div>
      <p>페이지 로딩 중...</p>
    </div>
    <div id="cp-error">
      <h2>⚠️ 페이지를 불러올 수 없습니다</h2>
      <p>잠시 후 다시 시도해 주세요.</p>
    </div>
  </div>

  <!-- CloudPress CMS 런타임 부트스트랩 -->
  <script>
    // CloudPress 전역 설정
    window.CP_SITE = {
      sitePrefix:  ${JSON.stringify(sitePrefix || '')},
      siteName:    ${JSON.stringify(title)},
      originBase:  ${JSON.stringify(originBase || '')},
      hostname:    ${JSON.stringify(hostname || '')},
      pathname:    ${JSON.stringify(pathname || '/')},
      nonce:       '',
      isLoggedIn:  false,
    };

    // CMS 렌더링 오류 핸들러
    window.addEventListener('error', function(e) {
      console.error('[CloudPress]', e.message, e.filename, e.lineno);
    });
    window.addEventListener('unhandledrejection', function(e) {
      console.error('[CloudPress] Promise rejection:', e.reason);
    });
  </script>

  <!-- CloudPress CMS 메인 스크립트 (origin에서 동적 로드) -->
  <script type="module">
    const origin  = window.CP_SITE.originBase;
    const loading = document.getElementById('cp-loading');
    const errEl   = document.getElementById('cp-error');

    async function bootCMS() {
      try {
        // 1) CMS 핵심 설정 로드
        const cfgRes = await fetch(origin + '/cp-blog-header.js', {
          headers: { 'X-CloudPress-Site': window.CP_SITE.sitePrefix, 'X-Requested-With': 'XMLHttpRequest' },
          credentials: 'include',
        });

        // 2) 현재 경로에 맞는 콘텐츠 API 호출
        const contentRes = await fetch(origin + '/cp-includes/functions.js', {
          headers: {
            'X-CloudPress-Site':     window.CP_SITE.sitePrefix,
            'X-CloudPress-Pathname': window.CP_SITE.pathname,
            'X-Requested-With':      'XMLHttpRequest',
          },
          credentials: 'include',
        });

        // 3) 콘텐츠를 직접 API로 가져와 DOM에 렌더링
        const apiUrl = origin + '/api/render?path=' + encodeURIComponent(window.CP_SITE.pathname);
        const renderRes = await fetch(apiUrl, {
          headers: { 'X-CloudPress-Site': window.CP_SITE.sitePrefix },
          credentials: 'include',
        });

        if (renderRes.ok) {
          const contentType = renderRes.headers.get('content-type') || '';
          if (contentType.includes('text/html')) {
            const html = await renderRes.text();
            document.open();
            document.write(html);
            document.close();
            return;
          }
        }

        // 4) API 없으면 iframe fallback으로 CMS 표시
        loading.innerHTML = '';
        const iframe = document.createElement('iframe');
        iframe.src    = origin + window.CP_SITE.pathname;
        iframe.style  = 'width:100%;min-height:100vh;border:none;display:block;';
        iframe.title  = window.CP_SITE.siteName;
        // CMS가 iframe에서 정상 렌더링되도록 sandboxing 최소화
        iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-popups allow-top-navigation');
        document.getElementById('cloudpress-app').appendChild(iframe);

        // iframe 내부 높이에 맞게 자동 조정
        iframe.onload = function() {
          try {
            const iDoc = iframe.contentDocument || iframe.contentWindow.document;
            const h    = iDoc.documentElement.scrollHeight;
            if (h > 100) iframe.style.height = h + 'px';
          } catch(_) {
            iframe.style.height = '100vh';
          }
        };
      } catch (e) {
        console.error('[CloudPress boot]', e);
        loading.style.display = 'none';
        errEl.style.display   = 'block';
      }
    }

    bootCMS();
  </script>
</body>
</html>`;
}

/** HTML 특수문자 이스케이프 */
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ── 메인 핸들러 ──────────────────────────────────────────────────────────── */

async function handleRequest(request, env, ctx) {
  const url      = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname;

  /* ── DNS 인증 전용 경로: /.well-known/cloudpress-verify/<token> ─────────── */
  if (pathname.startsWith('/.well-known/cloudpress-verify/')) {
    return handleDomainVerifyToken(request, env, pathname);
  }

  /* ── Naver/Google/기타 도메인 소유 확인 파일 (정적 응답) ─────────────────── */
  if (pathname.startsWith('/naver') && pathname.endsWith('.html')) {
    return handleNaverVerify(env, pathname);
  }
  if (pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /cp-admin/\n', {
      headers: { 'Content-Type': 'text/plain' },
    });
  }

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

  // env.CACHE가 없을 수 있으므로 안전하게 접근
  if (env.CACHE) {
    try {
      siteInfo = await env.CACHE.get(`site_domain:${hostname}`, { type: 'json' });
    } catch (_) {}
  }

  /* 3. 캐시 미스 → D1 직접 조회 후 캐시 갱신 */
  if (!siteInfo && env.DB) {
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
        if (env.CACHE) {
          env.CACHE.put(
            `site_domain:${hostname}`,
            JSON.stringify(siteInfo),
            { expirationTtl: 86400 }
          ).catch(() => {});
        }
      }
    } catch (e) {
      console.warn('[worker] D1 lookup error:', e?.message);
    }
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

  const targetUrl = originBase + pathname + url.search;

  /* 요청 헤더 복사 + CloudPress 식별 헤더 추가 */
  const reqHeaders = new Headers(request.headers);
  reqHeaders.set('X-CloudPress-Site',     sitePrefix);
  reqHeaders.set('X-CloudPress-Secret',   originSecret);
  reqHeaders.set('X-CloudPress-Render',   'cms');          // CMS 렌더링 요청 명시
  reqHeaders.set('X-Forwarded-Host',      hostname);
  reqHeaders.set('X-Forwarded-Proto',     url.protocol.replace(':', ''));
  try {
    reqHeaders.set('Host', new URL(originBase).hostname);
  } catch (_) {}

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
    // Origin 연결 실패 시 CMS Shell 렌더링 (사이트는 표시되어야 함)
    console.warn('[worker] Origin fetch failed:', e?.message, '→ fallback to CMS shell');
    return new Response(
      buildCMSShellHTML(sitePrefix, siteInfo.name, originBase, pathname, hostname),
      { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }

  /* 응답 헤더 정리 */
  const respHeaders = new Headers(originRes.headers);
  respHeaders.delete('x-powered-by');
  respHeaders.delete('server');

  // CORS 헤더 추가 (필요한 경우)
  respHeaders.set('X-CloudPress-Proxy', '1');

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

  /* CMS 렌더링 처리:
   * Origin이 HTML을 반환하면 그대로 사용.
   * JS/CSS만 반환하거나, 빈 응답이면 CMS Shell HTML로 래핑.
   * 이렇게 하면 JS/CSS만 있는 CMS도 웹 브라우저에서 올바르게 표시됨. */
  const contentType = respHeaders.get('content-type') || '';
  const isNavigate  = request.headers.get('Sec-Fetch-Mode') === 'navigate' ||
                      !request.headers.get('Sec-Fetch-Mode'); // 직접 접근

  if (
    isNavigate &&
    request.method === 'GET' &&
    !pathname.startsWith('/cp-admin') &&
    !pathname.startsWith('/cp-includes') &&
    !pathname.startsWith('/uploads') &&
    !pathname.endsWith('.js') &&
    !pathname.endsWith('.css') &&
    !pathname.endsWith('.json') &&
    !pathname.endsWith('.xml') &&
    !pathname.endsWith('.ico') &&
    !pathname.endsWith('.png') &&
    !pathname.endsWith('.jpg') &&
    !pathname.endsWith('.gif') &&
    !pathname.endsWith('.svg') &&
    !pathname.endsWith('.woff') &&
    !pathname.endsWith('.woff2')
  ) {
    // Origin 응답이 HTML이 아닌 경우 CMS Shell로 래핑
    if (
      originRes.status === 200 &&
      !contentType.includes('text/html')
    ) {
      return new Response(
        buildCMSShellHTML(sitePrefix, siteInfo.name, originBase, pathname, hostname),
        { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      );
    }

    // Origin이 HTML인데 DOCTYPE이 없는 경우 (CMS가 부분 HTML 반환)
    if (originRes.status === 200 && contentType.includes('text/html')) {
      const bodyText = await originRes.text();
      if (bodyText.trim() && !bodyText.trim().toLowerCase().startsWith('<!doctype')) {
        // 부분 HTML을 완전한 페이지로 래핑
        const wrappedHtml = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escHtml(siteInfo.name || sitePrefix)}</title>
  <link rel="stylesheet" href="${originBase}/cp-includes/css/template-fallback.css">
  <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:0}</style>
</head>
<body>
${bodyText}
</body>
</html>`;
        return new Response(wrappedHtml, {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }
      // 정상 HTML 반환
      return new Response(bodyText, {
        status:  originRes.status,
        headers: respHeaders,
      });
    }
  }

  return new Response(originRes.body, {
    status:  originRes.status,
    headers: respHeaders,
  });
}

/* ── DNS 인증 토큰 핸들러 ─────────────────────────────────────────────────── */

/**
 * /.well-known/cloudpress-verify/<token> 경로 처리
 * 도메인 소유 확인을 위한 HTTP 인증 응답
 */
async function handleDomainVerifyToken(request, env, pathname) {
  const token = pathname.replace('/.well-known/cloudpress-verify/', '').split('/')[0];
  if (!token) {
    return new Response('Token not found', { status: 404 });
  }

  // KV에서 토큰 검증 (domains.js에서 저장한 값)
  let verifyData = null;
  if (env.CACHE) {
    try {
      verifyData = await env.CACHE.get(`domain_verify:${token}`, { type: 'json' });
    } catch (_) {}
  }

  if (!verifyData) {
    // DB에서도 조회 시도
    if (env.DB) {
      try {
        const row = await env.DB.prepare(
          `SELECT site_id, domain FROM domain_verifications WHERE id=? LIMIT 1`
        ).bind(token).first();
        if (row) {
          verifyData = { siteId: row.site_id, domain: row.domain, token };
        }
      } catch (_) {}
    }
  }

  if (!verifyData) {
    return new Response(
      `cloudpress-verify=${token}`,
      {
        status: 200,
        headers: {
          'Content-Type':  'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      }
    );
  }

  // 인증 성공 응답 (HTML + text/plain 모두 지원)
  const accept = request.headers.get('Accept') || '';
  if (accept.includes('text/html')) {
    return new Response(
      `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CloudPress Domain Verification</title></head>
<body><p>cloudpress-verify=${token}</p><p>domain=${verifyData.domain || ''}</p></body></html>`,
      { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } }
    );
  }

  return new Response(`cloudpress-verify=${token}`, {
    status: 200,
    headers: {
      'Content-Type':  'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

/** Naver 사이트 소유 확인 파일 처리 */
async function handleNaverVerify(env, pathname) {
  const filename = pathname.replace('/', '');
  // KV에서 파일 내용 조회 (관리자가 등록했을 경우)
  if (env.CACHE) {
    try {
      const content = await env.CACHE.get(`naver_verify:${filename}`);
      if (content) {
        return new Response(content, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }
    } catch (_) {}
  }
  return new Response('Not Found', { status: 404 });
}

// ── Service Worker Entry Point ─────────────────────────────────────────────
addEventListener('fetch', function(event) {
  event.respondWith(
    __worker.fetch(event.request, globalThis, event)
  );
});
