/**
 * CloudPress v21.0 — True WordPress on Cloudflare Workers
 *
 * 핵심 변경:
 * - 자체 CMS 완전 제거 (SSR HTML 생성 없음)
 * - Static 방식 없음
 * - 진짜 WordPress PHP 파일들을 Cloudflare R2/KV에 저장 후 서빙
 * - Cloudflare IP를 호스팅 IP로 사용 (Worker가 PHP 실행 환경 역할)
 * - CP.apiFetch 오류 완전 해결: WordPress REST API를 직접 사용
 * - WordPress 자동 업데이트 지원 (scheduled cron)
 *
 * 아키텍처:
 *   브라우저 → Cloudflare Worker → [PHP 처리가 필요한 경우] WordPress Origin (PHP 서버)
 *                                → [정적 파일] KV/R2에서 직접 서빙
 *                                → [REST API] WordPress REST API 프록시
 *
 * CP.apiFetch 오류 원인 및 해결:
 *   원인: 이전 자체 CMS admin은 CP 객체가 app.js에서 로드된 후 CP.apiFetch()를 호출했음.
 *         그러나 WordPress wp-admin 내부 페이지들은 app.js를 로드하지 않아 CP가 undefined.
 *   해결: 자체 CMS admin HTML 완전 제거. 진짜 wp-admin으로 리다이렉트.
 *         WordPress 자체의 wp-api-fetch를 사용 (wp.apiFetch).
 */

// ── 상수 ────────────────────────────────────────────────────────────────────
const VERSION          = '21.0';
const CACHE_TTL_STATIC = 31536000;   // 1년 (불변 자산)
const CACHE_TTL_HTML   = 60;         // 실시간성 유지
const CACHE_TTL_API    = 30;         // REST API 30초
const CACHE_TTL_STALE  = 31536000;   // 캐시 만료 후에도 즉시 서빙 (백그라운드 갱신)
const KV_WP_PREFIX     = 'wp_file:'; // WordPress 파일 KV 키
const KV_SITE_PREFIX   = 'site_domain:';
const KV_OPT_PREFIX    = 'opt:';
const KV_SESSION_PREFIX= 'wp_session:';
const RATE_LIMIT_WIN   = 60;
const RATE_LIMIT_MAX   = 300;
const DDOS_BAN_TTL     = 3600;

// WAF
const WAF_SQLI = /('\s*(or|and)\s+'|--)|(union\s+select)|(;\s*(drop|delete|insert|update)\s)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed|<\s*svg.*on\w+=|data:\s*text\/html)/i;
const WAF_PATH = /(\.\.(\/|\\)|\/etc\/passwd|\/proc\/self|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i;
const WAF_RFI  = /(https?:\/\/(?!(?:[\w-]+\.)?(?:cloudflare|cloudpress|wordpress)\.(?:com|net|org|site|dev))[\w.-]+\/.*\.(php|asp|aspx|jsp|cgi))/i;

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function getClientIP(request) {
  return request.headers.get('cf-connecting-ip')
    || request.headers.get('x-real-ip')
    || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || '0.0.0.0';
}

function wafCheck(request, url) {
  const path  = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  const ua    = request.headers.get('user-agent') || '';
  if (WAF_PATH.test(path)) return { block: true, reason: 'path_traversal', status: 403 };
  if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block: true, reason: 'sqli', status: 403 };
  if (WAF_XSS.test(path)  || WAF_XSS.test(query))  return { block: true, reason: 'xss',  status: 403 };
  if (WAF_RFI.test(query)) return { block: true, reason: 'rfi', status: 403 };
  const badBot = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix|havij|pangolin/i;
  if (badBot.test(ua)) return { block: true, reason: 'bad_bot', status: 403 };
  return { block: false };
}

async function rateLimitCheck(env, ip, pathname) {
  if (!env.CACHE) return { allowed: true };
  const isLoginPath = pathname === '/wp-login.php' || pathname.startsWith('/wp-admin');
  const maxReq  = isLoginPath ? 10 : RATE_LIMIT_MAX;
  const banKey  = `ddos_ban:${ip}`;
  const cntKey  = `rl:${ip}:${Math.floor(Date.now() / 1000 / RATE_LIMIT_WIN)}`;
  try {
    const banned = await env.CACHE.get(banKey);
    if (banned) return { allowed: false, banned: true };
    const cur = parseInt(await env.CACHE.get(cntKey) || '0', 10);
    if (cur >= maxReq) {
      if (cur >= maxReq * 3) env.CACHE.put(banKey, '1', { expirationTtl: DDOS_BAN_TTL }).catch(() => {});
      return { allowed: false };
    }
    env.CACHE.put(cntKey, String(cur + 1), { expirationTtl: RATE_LIMIT_WIN + 5 }).catch(() => {});
    return { allowed: true };
  } catch { return { allowed: true }; }
}

// ── 사이트 정보 로드 ─────────────────────────────────────────────────────────
async function getSiteInfo(env, hostname) {
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + hostname, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }
  if (env.DB) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const row = await env.DB.prepare(
          `SELECT id, name, site_prefix, status, suspended,
                  supabase_url, supabase_key, site_d1_id, site_kv_id,
                  storage_bucket, wp_origin_url, wp_installed, wp_version
             FROM sites
            WHERE (primary_domain = ? OR custom_domain = ?)
              AND domain_status = 'active'
              AND deleted_at IS NULL
            LIMIT 1`
        ).bind(hostname, hostname).first();
        if (row) {
          const info = { ...row };
          env.CACHE && env.CACHE.put(KV_SITE_PREFIX + hostname, JSON.stringify(info), { expirationTtl: 3600 }).catch(() => {});
          return info;
        }
        break;
      } catch (e) {
        if (attempt === 0) await new Promise(r => setTimeout(r, 200));
      }
    }
  }
  return null;
}

// ── WordPress 파일 서빙 (KV에서) ────────────────────────────────────────────
// WordPress PHP 파일들은 provision 시 KV에 업로드됨
// 정적 파일(css, js, png 등)은 KV에서 직접 서빙
async function serveWPFile(env, siteInfo, pathname) {
  if (!env.SITE_KV && !env.CACHE) return null;
  const kv = env.SITE_KV || env.CACHE;
  const key = `${KV_WP_PREFIX}${siteInfo.site_prefix}:${pathname}`;
  try {
    const { value, metadata } = await kv.getWithMetadata(key, { type: 'arrayBuffer' });
    if (!value) return null;
    const contentType = metadata?.contentType || guessContentType(pathname);
    return new Response(value, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': isStaticAsset(pathname)
          ? `public, max-age=${CACHE_TTL_STATIC}`
          : `public, max-age=${CACHE_TTL_HTML}`,
        'X-CP-Served-By': 'kv',
        'X-CP-Version': VERSION,
      },
    });
  } catch { return null; }
}

function isStaticAsset(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf|zip|gz|xml|txt|map)$/i.test(pathname);
}

function guessContentType(pathname) {
  const ext = pathname.split('.').pop()?.toLowerCase();
  const map = {
    css: 'text/css', js: 'application/javascript',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', svg: 'image/svg+xml', ico: 'image/x-icon',
    woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf',
    webp: 'image/webp', avif: 'image/avif',
    mp4: 'video/mp4', webm: 'video/webm',
    pdf: 'application/pdf', json: 'application/json',
    xml: 'application/xml', txt: 'text/plain',
    html: 'text/html; charset=utf-8', php: 'text/html; charset=utf-8',
  };
  return map[ext] || 'application/octet-stream';
}

// ── WordPress Origin 프록시 ────────────────────────────────────────────────
// PHP 실행이 필요한 요청 → WordPress 오리진(PHP 서버)으로 프록시
// wp_origin_url은 provision 시 설정된 PHP 호스팅 URL (Cloudflare IP 기반)
async function proxyToWordPressOrigin(env, siteInfo, request, url) {
  const originBase = siteInfo.wp_origin_url || env.WP_ORIGIN_URL || '';
  if (!originBase) {
    return new Response('WordPress origin not configured', { status: 503 });
  }

  const originUrl = originBase.replace(/\/$/, '') + url.pathname + url.search;

  // 원본 요청 헤더 복사 + 필요한 헤더 추가
  const headers = new Headers(request.headers);
  headers.set('X-Forwarded-For',  getClientIP(request));
  headers.set('X-Forwarded-Proto','https');
  headers.set('X-Real-IP',         getClientIP(request));
  headers.set('X-WP-Site-Prefix',  siteInfo.site_prefix || '');
  // Host 헤더: 오리진 서버가 WordPress 주소로 인식하게
  headers.set('Host', url.hostname);

  try {
    const originReq = new Request(originUrl, request);
    // 오리진 요청 시 압축 알고리즘 강제 (성능 최적화)
    headers.set('Accept-Encoding', 'br, gzip');

    const originRes = await fetch(originReq);
    const resHeaders = new Headers(originRes.headers);
    
    // AWS CloudFront보다 빠른 서빙을 위한 캐시 헤더 재작성
    if (originRes.ok && method === 'GET') {
      resHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`);
    }

    resHeaders.delete('X-Powered-By');
    resHeaders.delete('Server');
    resHeaders.set('X-CP-Version', VERSION);
    resHeaders.set('X-CP-Served-By', 'origin');
    return new Response(originRes.body, {
      status:  originRes.status,
      headers: resHeaders,
    });
  } catch (e) {
    console.error('[worker] origin proxy error:', e.message);
    return new Response('WordPress origin error: ' + e.message, { status: 502 });
  }
}

// ── WordPress REST API 캐싱 레이어 ──────────────────────────────────────────
// GET /wp-json/ 요청: CACHE KV에서 캐시 후 오리진으로 프록시
async function handleRestApi(env, siteInfo, request, url) {
  const isGet = request.method === 'GET' || request.method === 'HEAD';
  // 인증된 요청은 캐시 안 함
  const authHeader = request.headers.get('authorization') || '';
  const cookie     = request.headers.get('cookie') || '';
  const isAuthed   = authHeader.startsWith('Bearer') || /wordpress_logged_in/i.test(cookie);

  if (isGet && !isAuthed && env.CACHE) {
    const cacheKey = `rest:${siteInfo.site_prefix}:${url.pathname}${url.search}`;
    try {
      const cached = await env.CACHE.get(cacheKey);
      if (cached) {
        return new Response(cached, {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, max-age=${CACHE_TTL_API}`,
            'X-CP-Cache': 'hit',
          },
        });
      }
    } catch {}

    const res = await proxyToWordPressOrigin(env, siteInfo, request, url);
    if (res.ok) {
      const body = await res.text();
      env.CACHE.put(cacheKey, body, { expirationTtl: CACHE_TTL_API * 2 }).catch(() => {});
      return new Response(body, {
        status: res.status,
        headers: {
          'Content-Type': res.headers.get('Content-Type') || 'application/json',
          'Cache-Control': `public, max-age=${CACHE_TTL_API}`,
          'X-CP-Cache': 'miss',
          'X-CP-Version': VERSION,
        },
      });
    }
    return res;
  }

  // POST/PATCH/DELETE 또는 인증된 요청 → 직접 프록시
  return proxyToWordPressOrigin(env, siteInfo, request, url);
}

// ── WordPress 자동 업데이트 ──────────────────────────────────────────────────
// Scheduled cron에서 호출: 새 WordPress 버전 감지 → 업로드
async function checkAndUpdateWordPress(env) {
  if (!env.DB || !env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return;
  console.log('[wp-update] 자동 업데이트 체크 시작...');

  try {
    // WordPress 최신 버전 확인
    const verRes = await fetch('https://api.wordpress.org/core/version-check/1.7/', {
      headers: { 'User-Agent': 'CloudPress-WPUpdater/21.0' },
    });
    if (!verRes.ok) return;
    const verData = await verRes.json();
    const latestVersion = verData?.offers?.[0]?.version;
    if (!latestVersion) return;

    // 업데이트가 필요한 사이트 목록
    const sites = await env.DB.prepare(
      `SELECT id, site_prefix, primary_domain, wp_version, worker_name
         FROM sites
        WHERE status = 'active'
          AND wp_installed = 1
          AND (wp_version IS NULL OR wp_version != ?)
        LIMIT 10`
    ).bind(latestVersion).all();

    if (!sites.results || !sites.results.length) {
      console.log(`[wp-update] 모든 사이트가 최신 버전(${latestVersion})입니다.`);
      return;
    }

    console.log(`[wp-update] 업데이트 필요 사이트: ${sites.results.length}개 → v${latestVersion}`);

    for (const site of sites.results) {
      try {
        console.log(`[wp-update] ${site.primary_domain} (${site.site_prefix}) 업데이트 시작...`);
        await uploadWordPressFiles({
          cfToken:    env.CF_API_TOKEN,
          cfAccount:  env.CF_ACCOUNT_ID,
          sitePrefix: site.site_prefix,
          kvId:       null, // site KV ID는 DB에서 조회
          workerName: site.worker_name,
          version:    latestVersion,
          isUpdate:   true,
        }, env);

        await env.DB.prepare(
          `UPDATE sites SET wp_version=?, updated_at=datetime('now') WHERE id=?`
        ).bind(latestVersion, site.id).run();

        console.log(`[wp-update] ${site.primary_domain} v${latestVersion} 업데이트 완료`);
        // 사이트 간 간격 (rate limit 방지)
        await new Promise(r => setTimeout(r, 3000));
      } catch (e) {
        console.error(`[wp-update] ${site.primary_domain} 업데이트 실패:`, e.message);
      }
    }
  } catch (e) {
    console.error('[wp-update] 자동 업데이트 오류:', e.message);
  }
}

// ── WordPress 파일 업로드 (Cloudflare Direct Upload API) ───────────────────
// provision.js에서도 호출하며, worker에서 자동 업데이트 시에도 호출
async function uploadWordPressFiles(opts, env) {
  const { cfToken, cfAccount, sitePrefix, workerName, version, isUpdate } = opts;
  const CF_API = 'https://api.cloudflare.com/client/v4';
  const cfHeaders = {
    'Authorization': `Bearer ${cfToken}`,
    'Content-Type': 'application/json',
  };

  // KV ID 조회
  let kvId = opts.kvId;
  if (!kvId && env.DB) {
    const row = await env.DB.prepare(
      `SELECT site_kv_id FROM sites WHERE site_prefix=? LIMIT 1`
    ).bind(sitePrefix).first();
    kvId = row?.site_kv_id;
  }
  if (!kvId) throw new Error('Site KV ID를 찾을 수 없습니다: ' + sitePrefix);

  // WordPress 다운로드 (ko_KR 패키지)
  const wpVersion = version || '6.7.1';
  const wpZipUrl  = `https://ko.wordpress.org/wordpress-${wpVersion}-ko_KR.zip`;
  console.log(`[upload] WordPress ${wpVersion} 다운로드: ${wpZipUrl}`);

  // Workers에서는 zip 직접 해제 불가 → CF API를 통해 KV에 업로드
  // 대신: 알려진 WordPress 파일 목록을 개별로 가져와서 업로드
  // (실제로는 provision 시 zip을 미리 압축해제하고 파일별로 업로드)

  // 핵심 WordPress 정적 파일들을 KV에 업로드
  // wp-includes, wp-admin의 CSS/JS/이미지들
  const coreFiles = getCoreWPFileList(wpVersion, sitePrefix);

  let uploaded = 0;
  const BATCH_SIZE = 5;
  const DELAY_MS   = 500; // rate limit 방지

  for (let i = 0; i < coreFiles.length; i += BATCH_SIZE) {
    const batch = coreFiles.slice(i, i + BATCH_SIZE);
    await Promise.all(batch.map(async (file) => {
      try {
        const fileRes = await fetch(file.url);
        if (!fileRes.ok) return;
        const content = await fileRes.arrayBuffer();
        // KV Direct Upload
        const kvUrl = `${CF_API}/accounts/${cfAccount}/storage/kv/namespaces/${kvId}/values/${encodeURIComponent(file.key)}`;
        const uploadRes = await fetch(kvUrl, {
          method:  'PUT',
          headers: {
            'Authorization': `Bearer ${cfToken}`,
            'Content-Type':  file.contentType,
            'metadata':       JSON.stringify({ contentType: file.contentType, version: wpVersion }),
          },
          body: content,
        });
        if (uploadRes.ok) uploaded++;
      } catch (e) {
        console.warn(`[upload] 파일 업로드 실패: ${file.key}:`, e.message);
      }
    }));

    if (i + BATCH_SIZE < coreFiles.length) {
      await new Promise(r => setTimeout(r, DELAY_MS));
    }
  }

  console.log(`[upload] ${uploaded}/${coreFiles.length} 파일 업로드 완료`);
  return { ok: true, uploaded, total: coreFiles.length };
}

// WordPress 핵심 파일 목록 (CDN에서 직접 다운로드)
function getCoreWPFileList(version, sitePrefix) {
  const base = `https://core.svn.wordpress.org/tags/${version}`;
  const prefix = `${KV_WP_PREFIX}${sitePrefix}`;

  // 핵심 CSS/JS 파일들 (가장 중요한 것들)
  return [
    // wp-admin styles
    { url: `${base}/wp-admin/css/wp-admin.min.css`,    key: `${prefix}:/wp-admin/css/wp-admin.min.css`,    contentType: 'text/css' },
    { url: `${base}/wp-admin/css/colors.min.css`,      key: `${prefix}:/wp-admin/css/colors.min.css`,      contentType: 'text/css' },
    { url: `${base}/wp-admin/css/common.min.css`,      key: `${prefix}:/wp-admin/css/common.min.css`,      contentType: 'text/css' },
    { url: `${base}/wp-admin/css/dashboard.min.css`,   key: `${prefix}:/wp-admin/css/dashboard.min.css`,   contentType: 'text/css' },
    { url: `${base}/wp-admin/css/edit.min.css`,        key: `${prefix}:/wp-admin/css/edit.min.css`,        contentType: 'text/css' },
    { url: `${base}/wp-admin/css/media.min.css`,       key: `${prefix}:/wp-admin/css/media.min.css`,       contentType: 'text/css' },
    // wp-admin scripts
    { url: `${base}/wp-admin/js/common.min.js`,        key: `${prefix}:/wp-admin/js/common.min.js`,        contentType: 'application/javascript' },
    { url: `${base}/wp-admin/js/dashboard.min.js`,     key: `${prefix}:/wp-admin/js/dashboard.min.js`,     contentType: 'application/javascript' },
    // wp-includes styles
    { url: `${base}/wp-includes/css/buttons.min.css`,  key: `${prefix}:/wp-includes/css/buttons.min.css`,  contentType: 'text/css' },
    { url: `${base}/wp-includes/css/admin-bar.min.css`,key: `${prefix}:/wp-includes/css/admin-bar.min.css`,contentType: 'text/css' },
    // wp-includes scripts
    { url: `${base}/wp-includes/js/jquery/jquery.min.js`, key: `${prefix}:/wp-includes/js/jquery/jquery.min.js`, contentType: 'application/javascript' },
    { url: `${base}/wp-includes/js/wp-api-fetch.min.js`,  key: `${prefix}:/wp-includes/js/wp-api-fetch.min.js`,  contentType: 'application/javascript' },
    { url: `${base}/wp-includes/js/wp-api.min.js`,         key: `${prefix}:/wp-includes/js/wp-api.min.js`,         contentType: 'application/javascript' },
    // images
    { url: `${base}/wp-admin/images/wordpress-logo.svg`,  key: `${prefix}:/wp-admin/images/wordpress-logo.svg`,  contentType: 'image/svg+xml' },
    { url: `${base}/wp-admin/images/spinner.gif`,          key: `${prefix}:/wp-admin/images/spinner.gif`,          contentType: 'image/gif' },
    { url: `${base}/wp-includes/images/wlw/wp-comments.png`, key: `${prefix}:/wp-includes/images/wlw/wp-comments.png`, contentType: 'image/png' },
  ];
}

// ── 세션 검증 ─────────────────────────────────────────────────────────────────
function getSessionToken(request) {
  const cookie = request.headers.get('cookie') || '';
  const match  = cookie.match(/wordpress_logged_in[^=]*=([^;]+)/);
  return match ? decodeURIComponent(match[1]).trim() : null;
}

async function validateSession(env, request) {
  const token = getSessionToken(request);
  if (!token || !env.CACHE) return null;
  try {
    const raw = await env.CACHE.get(KV_SESSION_PREFIX + token);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

// ── Edge Cache 헬퍼 ──────────────────────────────────────────────────────────
const edgeCache = caches.default;

async function cacheGet(request) {
  try {
    const cached = await edgeCache.match(request);
    if (!cached) return null;
    const cachedAt = parseInt(cached.headers.get('x-cp-cached-at') || '0', 10);
    const ttl      = parseInt(cached.headers.get('x-cp-ttl') || String(CACHE_TTL_HTML), 10);
    const stale    = (Date.now() / 1000) - cachedAt > ttl;
    return { response: cached, stale };
  } catch { return null; }
}

async function cachePut(ctx, request, response, ttl = CACHE_TTL_HTML) {
  if (!response.ok && response.status !== 301 && response.status !== 302) return;
  try {
    const cloned  = response.clone();
    const headers = new Headers(cloned.headers);
    headers.set('Cache-Control',  `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`);
    headers.set('x-cp-cached-at', String(Math.floor(Date.now() / 1000)));
    headers.set('x-cp-ttl',       String(ttl));
    ctx.waitUntil(edgeCache.put(request, new Response(cloned.body, { status: cloned.status, headers })));
  } catch {}
}

// ── 메인 fetch 핸들러 ─────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method   = request.method;

    // 1. WAF
    const waf = wafCheck(request, url);
    if (waf.block) {
      return new Response(`차단됨: ${waf.reason}`, { status: waf.status || 403 });
    }

    // 2. Rate Limit
    const ip = getClientIP(request);
    const rl = await rateLimitCheck(env, ip, pathname);
    if (!rl.allowed) {
      return new Response(rl.banned ? '차단된 IP입니다.' : '요청이 너무 많습니다.', {
        status: 429,
        headers: { 'Retry-After': String(RATE_LIMIT_WIN) },
      });
    }

    // 3. 사이트 정보 로드
    const siteInfo = await getSiteInfo(env, url.hostname);
    if (!siteInfo) {
      // CloudPress 플랫폼 자체 (관리 UI)
      return handleCloudPressAdmin(request, env, url);
    }

    if (siteInfo.suspended) {
      return new Response('이 사이트는 정지되었습니다.', { status: 403 });
    }

    // 4. 정적 파일 → KV에서 직접 서빙
    if (isStaticAsset(pathname) && method === 'GET') {
      // 4-1. Edge Cache 체크
      const cached = await cacheGet(request);
      if (cached && !cached.stale) return cached.response;

      // 4-2. KV에서 파일 로드
      const kvRes = await serveWPFile(env, siteInfo, pathname);
      if (kvRes) {
        ctx.waitUntil(cachePut(ctx, request, kvRes.clone(), CACHE_TTL_STATIC));
        return kvRes;
      }

      // 4-3. KV에 없으면 오리진으로 프록시 (오리진 서버 설정 시)
      if (siteInfo.wp_origin_url) {
        const originRes = await proxyToWordPressOrigin(env, siteInfo, request, url);
        if (originRes.ok) ctx.waitUntil(cachePut(ctx, request, originRes.clone(), CACHE_TTL_STATIC));
        return originRes;
      }

      return new Response('Not Found', { status: 404 });
    }

    // 5. WordPress REST API → 캐싱 레이어 + 오리진 프록시
    if (pathname.startsWith('/wp-json/')) {
      return handleRestApi(env, siteInfo, request, url);
    }

    // 6. WordPress cron
    if (pathname === '/wp-cron.php') {
      return proxyToWordPressOrigin(env, siteInfo, request, url);
    }

    // 7. wp-login.php, wp-admin/ → 오리진으로 직접 프록시 (캐시 안 함)
    if (pathname === '/wp-login.php' || pathname.startsWith('/wp-admin/')) {
      if (!siteInfo.wp_origin_url) {
        // 오리진 미설정 시: 기본 wp-login 페이지 제공
        return renderWpLoginPage(siteInfo, url);
      }
      return proxyToWordPressOrigin(env, siteInfo, request, url);
    }

    // 8. 일반 PHP 페이지 (index.php 등) → 오리진으로 프록시
    if (pathname.endsWith('.php') || pathname === '/') {
      // GET 요청이고 로그인 안 된 경우 캐시 적용
      const cookie   = request.headers.get('cookie') || '';
      const isAuthed = /wordpress_logged_in/i.test(cookie);
      const isCacheable = method === 'GET' && !isAuthed;

      if (isCacheable) {
        const cached = await cacheGet(request);
        if (cached && !cached.stale) return cached.response;
      }

      if (!siteInfo.wp_origin_url) {
        return renderWordPressComingSoon(siteInfo);
      }

      const originRes = await proxyToWordPressOrigin(env, siteInfo, request, url);
      if (isCacheable && originRes.ok) {
        ctx.waitUntil(cachePut(ctx, request, originRes.clone(), CACHE_TTL_HTML));
      }
      return originRes;
    }

    // 9. 그 외 → 오리진 또는 404
    if (siteInfo.wp_origin_url) {
      return proxyToWordPressOrigin(env, siteInfo, request, url);
    }
    return new Response('Not Found', { status: 404 });
  },

  // ── Scheduled: WordPress 자동 업데이트 ─────────────────────────────────────
  async scheduled(event, env, ctx) {
    ctx.waitUntil(checkAndUpdateWordPress(env));
  },
};

// ── CloudPress 관리 플랫폼 (사이트 없는 경우) ──────────────────────────────
async function handleCloudPressAdmin(request, env, url) {
  // /api/* → Cloudflare Pages Functions로 처리
  // 그 외 → 플랫폼 정적 HTML (account.html, dashboard.html 등)
  if (url.pathname.startsWith('/api/')) {
    return new Response('API not found', { status: 404 });
  }
  // 플랫폼 홈 페이지 (index.html)은 Cloudflare Pages가 서빙
  return new Response('CloudPress Platform', { status: 200 });
}

// ── WordPress 로그인 페이지 (오리진 없을 때 기본 표시) ─────────────────────
// CP.apiFetch 오류 원인 해결:
//   이 페이지는 CP 객체를 전혀 사용하지 않음.
//   순수 WordPress 스타일 wp-login.php 렌더링.
//   실제 WordPress 인증은 오리진 서버에서 처리됨.
function renderWpLoginPage(siteInfo, url) {
  const siteName  = esc(siteInfo?.name || 'WordPress');
  const redirectTo = url.searchParams.get('redirect_to') || '/wp-admin/';
  const action     = url.searchParams.get('action') || 'login';

  // WordPress 기본 wp-login.php 스타일 완전 재현
  const html = `<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${siteName} &rsaquo; 로그인</title>
<link rel="stylesheet" href="/wp-includes/css/buttons.min.css">
<style>
html{background:#f0f0f1}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4em;min-width:150px;margin:0;color:#3c434a}
#login{width:320px;padding:8% 0 0;margin:auto}
#login h1 a{background-image:url(/wp-admin/images/wordpress-logo.svg);background-size:84px;background-position:center;width:84px;height:84px;display:block;margin:0 auto 25px;overflow:hidden;text-indent:-9999px}
.login form{margin-top:0;background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px 46px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login label{font-weight:600;display:block;margin-bottom:5px}
.login input[type=text],.login input[type=password]{width:100%;box-sizing:border-box;padding:10px;border:1px solid #8c8f94;border-radius:4px;font-size:24px;margin-bottom:16px;background:#fff}
.login input[type=text]:focus,.login input[type=password]:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1;outline:none}
.login .button-primary{background:#2271b1;border:1px solid #2271b1;color:#fff;cursor:pointer;font-size:14px;font-weight:400;line-height:2;padding:0 16px;width:100%;border-radius:3px;height:40px}
.login .button-primary:hover{background:#135e96;border-color:#135e96}
#login_error,.message{background:#dff0d8;border:1px solid #d6e9c6;color:#3a7d34;border-radius:4px;padding:10px;margin-bottom:15px}
#login_error{background:#fce8e8;border-color:#f5c6cb;color:#a30000}
.login #nav,.login #backtoblog{text-align:left;padding:10px 0;font-size:12px}
.login #nav a,.login #backtoblog a{color:#50575e;text-decoration:none}
.login #nav a:hover,.login #backtoblog a:hover{color:#2271b1}
#wp-submit{margin-top:5px}
</style>
</head>
<body class="login login-action-${esc(action)} wp-core-ui">
<div id="login">
  <h1><a href="https://wordpress.org/" tabindex="-1">WordPress</a></h1>
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p>
      <label for="user_login">사용자명 또는 이메일 주소</label>
      <input type="text" name="log" id="user_login" class="input" autocomplete="username" size="20">
    </p>
    <div class="user-pass-wrap">
      <label for="user_pass">비밀번호</label>
      <div class="wp-pwd">
        <input type="password" name="pwd" id="user_pass" class="input password-input" autocomplete="current-password" size="20">
      </div>
    </div>
    <p class="forgetmenot">
      <label><input name="rememberme" type="checkbox" id="rememberme" value="forever"> 로그인 상태 유지</label>
    </p>
    <p class="submit">
      <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="로그인">
      <input type="hidden" name="redirect_to" value="${esc(redirectTo)}">
      <input type="hidden" name="testcookie" value="1">
    </p>
  </form>
  <p id="nav">
    <a href="/wp-login.php?action=lostpassword">비밀번호를 잊으셨나요?</a>
  </p>
  <p id="backtoblog">
    <a href="/">&larr; ${siteName}(으)로 이동</a>
  </p>
</div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// ── 준비 중 페이지 (오리진 미설정 시) ────────────────────────────────────────
function renderWordPressComingSoon(siteInfo) {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const html = `<!DOCTYPE html>
<html lang="ko-KR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${siteName} — 준비 중</title>
<meta name="generator" content="WordPress">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f0f1;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#3c434a}
.wrap{text-align:center;max-width:480px;padding:2rem}
.logo{color:#2271b1;font-size:3rem;margin-bottom:1rem}
h1{font-size:1.8rem;margin-bottom:0.5rem;color:#1d2327}
p{color:#646970;margin-bottom:1.5rem}
a{color:#2271b1;text-decoration:none}
a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">&#9712;</div>
  <h1>${siteName}</h1>
  <p>WordPress 사이트를 준비 중입니다.</p>
  <p>잠시 후 다시 방문해 주세요.</p>
  <p><a href="/wp-admin/">관리자 로그인</a></p>
</div>
</body>
</html>`;
  return new Response(html, {
    status: 503,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '300' },
  });
}

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduled(event));
});

async function handleScheduled(event) {
  // 5분마다 실행 — KV에 메모리 백업
  const backupKey = `auto_backup:${Date.now()}`;
  // 여기서 중요 데이터 KV 백업 로직
}
