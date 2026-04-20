var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var worker_default = {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error("[worker] Unhandled error:", e?.message || e);
      return new Response(
        `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<title>\uC77C\uC2DC\uC801 \uC624\uB958</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;
min-height:100vh;margin:0;background:#0f0f0f;color:#fff}
.box{text-align:center;padding:2rem;max-width:480px}
h1{color:#f55;margin-bottom:1rem}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box">
<h1>\u26A0\uFE0F \uC77C\uC2DC\uC801 \uC11C\uBC84 \uC624\uB958</h1>
<p>\uC7A0\uC2DC \uD6C4 \uB2E4\uC2DC \uC2DC\uB3C4\uD574 \uC8FC\uC138\uC694.<br>
\uBB38\uC81C\uAC00 \uC9C0\uC18D\uB418\uBA74 CloudPress \uACE0\uAC1D\uC13C\uD130\uB85C \uC5F0\uB77D\uD574 \uC8FC\uC138\uC694.</p>
</div></body></html>`,
        { status: 500, headers: { "Content-Type": "text/html; charset=utf-8" } }
      );
    }
  }
};
var SUSPENDED_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>\uC0AC\uC774\uD2B8 \uC815\uC9C0\uB428</title>
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
    <h1>\u{1F6AB} \uC0AC\uC774\uD2B8\uAC00 \uC815\uC9C0\uB418\uC5C8\uC2B5\uB2C8\uB2E4</h1>
    <p>\uC774 \uC0AC\uC774\uD2B8\uB294 \uD604\uC7AC \uC774\uC6A9 \uC911\uC9C0 \uC0C1\uD0DC\uC785\uB2C8\uB2E4.<br>
       \uBB38\uC758\uC0AC\uD56D\uC740 CloudPress \uACE0\uAC1D\uC13C\uD130\uB85C \uC5F0\uB77D\uD574 \uC8FC\uC138\uC694.</p>
  </div>
</body>
</html>`;
var NOT_FOUND_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>\uC0AC\uC774\uD2B8\uB97C \uCC3E\uC744 \uC218 \uC5C6\uC74C</title>
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
    <h1>\u{1F50D} \uC0AC\uC774\uD2B8\uB97C \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4</h1>
    <p>\uC694\uCCAD\uD55C \uB3C4\uBA54\uC778\uC5D0 \uC5F0\uACB0\uB41C \uC0AC\uC774\uD2B8\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4.<br>
       <a href="https://cloudpress.pages.dev/">CloudPress \uB300\uC2DC\uBCF4\uB4DC</a>\uC5D0\uC11C \uB3C4\uBA54\uC778\uC744 \uD655\uC778\uD574 \uC8FC\uC138\uC694.</p>
  </div>
</body>
</html>`;
var PROVISIONING_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <title>\uC0AC\uC774\uD2B8 \uC900\uBE44 \uC911</title>
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
    <div class="spin">\u2699\uFE0F</div>
    <h1>\uC0AC\uC774\uD2B8\uB97C \uC900\uBE44 \uC911\uC785\uB2C8\uB2E4</h1>
    <p>\uBC30\uD3EC\uAC00 \uC644\uB8CC\uB418\uBA74 \uC790\uB3D9\uC73C\uB85C \uD398\uC774\uC9C0\uAC00 \uAC31\uC2E0\uB429\uB2C8\uB2E4.<br>\uC7A0\uC2DC\uB9CC \uAE30\uB2E4\uB824 \uC8FC\uC138\uC694.</p>
  </div>
</body>
</html>`;
function buildCMSShellHTML(sitePrefix, siteName, originBase, pathname, hostname) {
  const title = siteName || sitePrefix || "CloudPress Site";
  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="CloudPress">
  <title>${escHtml(title)}</title>
  <!-- CloudPress CMS \uC2A4\uD0C0\uC77C\uC2DC\uD2B8 -->
  <link rel="stylesheet" href="${originBase}/cp-includes/css/template-fallback.css">
  <link rel="stylesheet" href="${originBase}/cp-includes/css/comments.css">
  <style>
    /* CloudPress \uAE30\uBCF8 \uB808\uC774\uC544\uC6C3 */
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
    /* \uB85C\uB529 \uC778\uB514\uCF00\uC774\uD130 */
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
    /* \uC5D0\uB7EC \uD45C\uC2DC */
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
      <p>\uD398\uC774\uC9C0 \uB85C\uB529 \uC911...</p>
    </div>
    <div id="cp-error">
      <h2>\u26A0\uFE0F \uD398\uC774\uC9C0\uB97C \uBD88\uB7EC\uC62C \uC218 \uC5C6\uC2B5\uB2C8\uB2E4</h2>
      <p>\uC7A0\uC2DC \uD6C4 \uB2E4\uC2DC \uC2DC\uB3C4\uD574 \uC8FC\uC138\uC694.</p>
    </div>
  </div>

  <!-- CloudPress CMS \uB7F0\uD0C0\uC784 \uBD80\uD2B8\uC2A4\uD2B8\uB7A9 -->
  <script>
    // CloudPress \uC804\uC5ED \uC124\uC815
    window.CP_SITE = {
      sitePrefix:  ${JSON.stringify(sitePrefix || "")},
      siteName:    ${JSON.stringify(title)},
      originBase:  ${JSON.stringify(originBase || "")},
      hostname:    ${JSON.stringify(hostname || "")},
      pathname:    ${JSON.stringify(pathname || "/")},
      nonce:       '',
      isLoggedIn:  false,
    };

    // CMS \uB80C\uB354\uB9C1 \uC624\uB958 \uD578\uB4E4\uB7EC
    window.addEventListener('error', function(e) {
      console.error('[CloudPress]', e.message, e.filename, e.lineno);
    });
    window.addEventListener('unhandledrejection', function(e) {
      console.error('[CloudPress] Promise rejection:', e.reason);
    });
  <\/script>

  <!-- CloudPress CMS \uBA54\uC778 \uC2A4\uD06C\uB9BD\uD2B8 (origin\uC5D0\uC11C \uB3D9\uC801 \uB85C\uB4DC) -->
  <script type="module">
    const origin  = window.CP_SITE.originBase;
    const loading = document.getElementById('cp-loading');
    const errEl   = document.getElementById('cp-error');

    async function bootCMS() {
      try {
        // 1) CMS \uD575\uC2EC \uC124\uC815 \uB85C\uB4DC
        const cfgRes = await fetch(origin + '/cp-blog-header.js', {
          headers: { 'X-CloudPress-Site': window.CP_SITE.sitePrefix, 'X-Requested-With': 'XMLHttpRequest' },
          credentials: 'include',
        });

        // 2) \uD604\uC7AC \uACBD\uB85C\uC5D0 \uB9DE\uB294 \uCF58\uD150\uCE20 API \uD638\uCD9C
        const contentRes = await fetch(origin + '/cp-includes/functions.js', {
          headers: {
            'X-CloudPress-Site':     window.CP_SITE.sitePrefix,
            'X-CloudPress-Pathname': window.CP_SITE.pathname,
            'X-Requested-With':      'XMLHttpRequest',
          },
          credentials: 'include',
        });

        // 3) \uCF58\uD150\uCE20\uB97C \uC9C1\uC811 API\uB85C \uAC00\uC838\uC640 DOM\uC5D0 \uB80C\uB354\uB9C1
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

        // 4) API \uC5C6\uC73C\uBA74 iframe fallback\uC73C\uB85C CMS \uD45C\uC2DC
        loading.innerHTML = '';
        const iframe = document.createElement('iframe');
        iframe.src    = origin + window.CP_SITE.pathname;
        iframe.style  = 'width:100%;min-height:100vh;border:none;display:block;';
        iframe.title  = window.CP_SITE.siteName;
        // CMS\uAC00 iframe\uC5D0\uC11C \uC815\uC0C1 \uB80C\uB354\uB9C1\uB418\uB3C4\uB85D sandboxing \uCD5C\uC18C\uD654
        iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-popups allow-top-navigation');
        document.getElementById('cloudpress-app').appendChild(iframe);

        // iframe \uB0B4\uBD80 \uB192\uC774\uC5D0 \uB9DE\uAC8C \uC790\uB3D9 \uC870\uC815
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
  <\/script>
</body>
</html>`;
}
__name(buildCMSShellHTML, "buildCMSShellHTML");
function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
__name(escHtml, "escHtml");
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname;
  if (pathname.startsWith("/.well-known/cloudpress-verify/")) {
    return handleDomainVerifyToken(request, env, pathname);
  }
  if (pathname.startsWith("/naver") && pathname.endsWith(".html")) {
    return handleNaverVerify(env, pathname);
  }
  if (pathname === "/robots.txt") {
    return new Response("User-agent: *\nDisallow: /cp-admin/\n", {
      headers: { "Content-Type": "text/plain" }
    });
  }
  if (hostname.endsWith(".pages.dev") || hostname.endsWith(".workers.dev") || hostname === "cloudpress.site" || hostname === "www.cloudpress.site") {
    return fetch(request);
  }
  let siteInfo = null;
  if (env.CACHE) {
    try {
      siteInfo = await env.CACHE.get(`site_domain:${hostname}`, { type: "json" });
    } catch (_) {
    }
  }
  if (!siteInfo && env.DB) {
    try {
      const row = await env.DB.prepare(
        `SELECT id, name, site_prefix, status, suspended
             FROM sites
            WHERE primary_domain = ?
              AND domain_status  = 'active'
              AND deleted_at IS NULL
            LIMIT 1`
      ).bind(hostname).first();
      if (row) {
        siteInfo = {
          id: row.id,
          name: row.name,
          site_prefix: row.site_prefix || row.id,
          status: row.status,
          suspended: row.suspended
        };
        if (env.CACHE) {
          env.CACHE.put(
            `site_domain:${hostname}`,
            JSON.stringify(siteInfo),
            { expirationTtl: 86400 }
          ).catch(() => {
          });
        }
      }
    } catch (e) {
      console.warn("[worker] D1 lookup error:", e?.message);
    }
  }
  if (!siteInfo) {
    return new Response(NOT_FOUND_HTML, {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
  if (siteInfo.suspended || siteInfo.status === "suspended") {
    return new Response(SUSPENDED_HTML, {
      status: 403,
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
  if (siteInfo.status === "pending" || siteInfo.status === "provisioning") {
    return new Response(PROVISIONING_HTML, {
      status: 503,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Retry-After": "10"
      }
    });
  }
  const originBase = (env.WP_ORIGIN_URL || "").replace(/\/$/, "");
  const originSecret = env.WP_ORIGIN_SECRET || "";
  const sitePrefix = siteInfo.site_prefix || siteInfo.id;
  if (!originBase) {
    return new Response("Proxy origin not configured.", { status: 502 });
  }
  const targetUrl = originBase + pathname + url.search;
  const reqHeaders = new Headers(request.headers);
  reqHeaders.set("X-CloudPress-Site", sitePrefix);
  reqHeaders.set("X-CloudPress-Secret", originSecret);
  reqHeaders.set("X-CloudPress-Render", "cms");
  reqHeaders.set("X-Forwarded-Host", hostname);
  reqHeaders.set("X-Forwarded-Proto", url.protocol.replace(":", ""));
  try {
    reqHeaders.set("Host", new URL(originBase).hostname);
  } catch (_) {
  }
  const proxyReq = new Request(targetUrl, {
    method: request.method,
    headers: reqHeaders,
    body: ["GET", "HEAD"].includes(request.method) ? void 0 : request.body,
    redirect: "manual"
  });
  let originRes;
  try {
    originRes = await fetch(proxyReq);
  } catch (e) {
    console.warn("[worker] Origin fetch failed:", e?.message, "\u2192 fallback to CMS shell");
    return new Response(
      buildCMSShellHTML(sitePrefix, siteInfo.name, originBase, pathname, hostname),
      { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  }
  const respHeaders = new Headers(originRes.headers);
  respHeaders.delete("x-powered-by");
  respHeaders.delete("server");
  respHeaders.set("X-CloudPress-Proxy", "1");
  const location = respHeaders.get("location");
  if (location) {
    try {
      const loc = new URL(location, originBase);
      const originHost = new URL(originBase).hostname;
      if (loc.hostname === originHost) {
        loc.hostname = hostname;
        loc.protocol = url.protocol;
        respHeaders.set("location", loc.toString());
      }
    } catch (_) {
    }
  }
  const contentType = respHeaders.get("content-type") || "";
  const isNavigate = request.headers.get("Sec-Fetch-Mode") === "navigate" || !request.headers.get("Sec-Fetch-Mode");
  if (isNavigate && request.method === "GET" && !pathname.startsWith("/cp-admin") && !pathname.startsWith("/cp-includes") && !pathname.startsWith("/uploads") && !pathname.endsWith(".js") && !pathname.endsWith(".css") && !pathname.endsWith(".json") && !pathname.endsWith(".xml") && !pathname.endsWith(".ico") && !pathname.endsWith(".png") && !pathname.endsWith(".jpg") && !pathname.endsWith(".gif") && !pathname.endsWith(".svg") && !pathname.endsWith(".woff") && !pathname.endsWith(".woff2")) {
    if (originRes.status === 200 && !contentType.includes("text/html")) {
      return new Response(
        buildCMSShellHTML(sitePrefix, siteInfo.name, originBase, pathname, hostname),
        { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }
      );
    }
    if (originRes.status === 200 && contentType.includes("text/html")) {
      const bodyText = await originRes.text();
      if (bodyText.trim() && !bodyText.trim().toLowerCase().startsWith("<!doctype")) {
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
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      return new Response(bodyText, {
        status: originRes.status,
        headers: respHeaders
      });
    }
  }
  return new Response(originRes.body, {
    status: originRes.status,
    headers: respHeaders
  });
}
__name(handleRequest, "handleRequest");
async function handleDomainVerifyToken(request, env, pathname) {
  const token = pathname.replace("/.well-known/cloudpress-verify/", "").split("/")[0];
  if (!token) {
    return new Response("Token not found", { status: 404 });
  }
  let verifyData = null;
  if (env.CACHE) {
    try {
      verifyData = await env.CACHE.get(`domain_verify:${token}`, { type: "json" });
    } catch (_) {
    }
  }
  if (!verifyData) {
    if (env.DB) {
      try {
        const row = await env.DB.prepare(
          `SELECT site_id, domain FROM domain_verifications WHERE id=? LIMIT 1`
        ).bind(token).first();
        if (row) {
          verifyData = { siteId: row.site_id, domain: row.domain, token };
        }
      } catch (_) {
      }
    }
  }
  if (!verifyData) {
    return new Response(
      `cloudpress-verify=${token}`,
      {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store"
        }
      }
    );
  }
  const accept = request.headers.get("Accept") || "";
  if (accept.includes("text/html")) {
    return new Response(
      `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CloudPress Domain Verification</title></head>
<body><p>cloudpress-verify=${token}</p><p>domain=${verifyData.domain || ""}</p></body></html>`,
      { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
    );
  }
  return new Response(`cloudpress-verify=${token}`, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
__name(handleDomainVerifyToken, "handleDomainVerifyToken");
async function handleNaverVerify(env, pathname) {
  const filename = pathname.replace("/", "");
  if (env.CACHE) {
    try {
      const content = await env.CACHE.get(`naver_verify:${filename}`);
      if (content) {
        return new Response(content, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
    } catch (_) {
    }
  }
  return new Response("Not Found", { status: 404 });
}
__name(handleNaverVerify, "handleNaverVerify");
export {
  worker_default as default
};
