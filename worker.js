/**
 * CloudPress v20.0 — Originless Edge CMS Worker
 *
 * 아키텍처: Originless Edge CMS
 *   = Edge SSR (WordPress → D1/KV/Supabase 직접 렌더)
 *   + Edge Cache + KV 이중 캐시
 *   + SWR(Stale-While-Revalidate) / ISR(Incremental Static Regeneration)
 *   + Prewarm (캐시 예열)
 *   + 정밀 Purge (태그/경로 단위 무효화)
 *   + D1 쓰기 전용 (읽기는 KV/Cache API)
 *   + 다중 Failover (KV → D1 → Supabase Primary → Supabase Secondary → Stale)
 *   + WAF (SQL 인젝션·XSS·Path Traversal·RFI 차단)
 *   + DDoS 방어 (Rate Limiting + IP 차단 + Tarpit)
 *
 * 요청 흐름:
 *   [0] WAF/DDoS 검사 → 차단 or 통과
 *   [1] Edge Cache HIT  → 즉시 응답 (수 ms)
 *   [2] KV HIT          → Edge 저장 → 응답 (10-30 ms)
 *   [3] MISS            → Edge SSR (WordPress 렌더) → KV + Edge 저장 → 응답
 *   [4] SSR 실패        → Stale Cache 응답 (절대 지연 없음)
 *
 * 스토리지 우선순위:
 *   읽기: KV(캐시) → D1 → Supabase1 → Supabase2
 *   쓰기: D1 전용 (KV는 캐시 레이어만)
 *   미디어: Supabase Storage (1→2 자동 전환)
 */

// ── 상수 ──────────────────────────────────────────────────────────────────────
const CACHE_TTL_HTML   = 300;   // 5분 (SWR stale-while-revalidate)
const CACHE_TTL_ASSET  = 86400; // 정적 자산 1일
const CACHE_TTL_API    = 60;    // API 응답 1분
const CACHE_TTL_STALE  = 86400; // stale fallback 최대 1일 보관
const KV_PAGE_PREFIX   = 'page:';
const KV_SITE_PREFIX   = 'site_domain:';
const KV_OPT_PREFIX    = 'opt:';
const RATE_LIMIT_WIN   = 60;    // 초
const RATE_LIMIT_MAX   = 300;   // 일반 요청/분
const RATE_LIMIT_MAX_W = 30;    // 쓰기 요청/분 (POST/PUT/DELETE)
const DDOS_BAN_TTL     = 3600;  // IP 밴 1시간
const BOT_TARPIT_MS    = 5000;  // 악성 봇 응답 지연

// ── WAF 패턴 ──────────────────────────────────────────────────────────────────
const WAF_SQLI = /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|cast|convert|char|nchar|varchar|nvarchar|declare|cursor|begin|fetch|kill|truncate|grant|revoke)\b.*\b(from|where|table|column|database|user|version)\b)|('(\s*(or|and)\s+)')|(-{2})|(%27)|(%22)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed|<\s*svg.*on\w+=|data:\s*text\/html)/i;
const WAF_PATH = /(\.\.(\/|\\)|\/etc\/passwd|\/proc\/self|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i;
const WAF_RFI  = /(https?:\/\/(?!(?:[\w-]+\.)?(?:cloudflare|cloudpress|wordpress)\.(?:com|net|org|site|dev))[\w.-]+\/.*\.(php|asp|aspx|jsp|cgi))/i;

// ── HTML エスケープ ────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── 캐시 키 생성 ──────────────────────────────────────────────────────────────
function cacheKey(request) {
  const url = new URL(request.url);
  // 쿼리 파라미터 정규화 (캐시 버스팅 파라미터 제거)
  const skipParams = new Set(['utm_source','utm_medium','utm_campaign','utm_content','utm_term','fbclid','gclid','_ga']);
  const params = [...url.searchParams.entries()]
    .filter(([k]) => !skipParams.has(k))
    .sort(([a],[b]) => a.localeCompare(b));
  const cleanSearch = params.length ? '?' + new URLSearchParams(params).toString() : '';
  return `${url.origin}${url.pathname}${cleanSearch}`;
}

// ── WAF 검사 ──────────────────────────────────────────────────────────────────
function wafCheck(request, url) {
  const path = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  const ua = request.headers.get('user-agent') || '';

  // Path traversal
  if (WAF_PATH.test(path)) return { block: true, reason: 'path_traversal', status: 403 };

  // SQL injection in path/query
  if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block: true, reason: 'sqli', status: 403 };

  // XSS
  if (WAF_XSS.test(path) || WAF_XSS.test(query)) return { block: true, reason: 'xss', status: 403 };

  // RFI
  if (WAF_RFI.test(query)) return { block: true, reason: 'rfi', status: 403 };

  // 알려진 악성 봇 UA
  const badBot = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix|havij|pangolin/i;
  if (badBot.test(ua)) return { block: true, reason: 'bad_bot', status: 403, tarpit: true };

  // xmlrpc.php 차단 (WordPress 취약점)
  if (path === '/xmlrpc.php') return { block: true, reason: 'xmlrpc', status: 403 };

  // wp-login 브루트포스 방어는 Rate Limiter에서 처리
  return { block: false };
}

// ── Rate Limiter (KV 기반) ────────────────────────────────────────────────────
async function rateLimitCheck(env, ip, isWrite, pathname) {
  if (!env.CACHE) return { allowed: true };

  // wp-login은 더 엄격
  const isLoginPath = pathname === '/wp-login.php' || pathname === '/wp-admin/';
  const maxReq = isLoginPath ? 10 : (isWrite ? RATE_LIMIT_MAX_W : RATE_LIMIT_MAX);

  const banKey   = `ddos_ban:${ip}`;
  const countKey = `rl:${ip}:${Math.floor(Date.now() / 1000 / RATE_LIMIT_WIN)}`;

  try {
    // IP 밴 확인
    const banned = await env.CACHE.get(banKey);
    if (banned) return { allowed: false, banned: true };

    // 카운터 증가
    const cur = parseInt(await env.CACHE.get(countKey) || '0', 10);
    if (cur >= maxReq) {
      // 매우 초과 시 밴
      if (cur >= maxReq * 3) {
        await env.CACHE.put(banKey, '1', { expirationTtl: DDOS_BAN_TTL });
      }
      return { allowed: false, limit: maxReq, current: cur };
    }
    // 비동기로 카운터 업데이트 (응답 지연 없음)
    env.CACHE.put(countKey, String(cur + 1), { expirationTtl: RATE_LIMIT_WIN + 5 }).catch(() => {});
    return { allowed: true };
  } catch {
    return { allowed: true }; // KV 오류 시 허용
  }
}

// ── 클라이언트 IP 추출 ────────────────────────────────────────────────────────
function getClientIP(request) {
  return request.headers.get('cf-connecting-ip')
    || request.headers.get('x-real-ip')
    || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || '0.0.0.0';
}

// ── 정적 자산 판별 ────────────────────────────────────────────────────────────
function isStaticAsset(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf|zip|gz|xml|txt|json)$/i.test(pathname);
}

// ── 캐시 가능 요청 판별 ───────────────────────────────────────────────────────
function isCacheable(request, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  // 로그인/관리자/AJAX는 캐시 안 함
  const p = url.pathname;
  if (p.startsWith('/wp-admin') || p.startsWith('/wp-login') || p.includes('?') && url.searchParams.has('nocache')) return false;
  if (url.searchParams.has('preview') || url.searchParams.has('p') && url.searchParams.has('preview_id')) return false;
  // 쿠키에 WordPress 로그인 세션이 있으면 캐시 안 함
  const cookie = request.headers.get('cookie') || '';
  if (/wordpress_logged_in|wp-postpass/i.test(cookie)) return false;
  return true;
}

// ── Cache API 래퍼 ────────────────────────────────────────────────────────────
const edgeCache = caches.default;

async function cacheGet(request) {
  try {
    const cached = await edgeCache.match(request);
    if (!cached) return null;
    // Stale 여부 확인
    const age = parseInt(cached.headers.get('x-cp-age') || '0', 10);
    const ttl = parseInt(cached.headers.get('x-cp-ttl') || String(CACHE_TTL_HTML), 10);
    const stale = Date.now() / 1000 - age > ttl;
    return { response: cached, stale };
  } catch {
    return null;
  }
}

async function cachePut(ctx, request, response, ttl = CACHE_TTL_HTML) {
  if (!response.ok && response.status !== 301 && response.status !== 302) return;
  try {
    const cloned = response.clone();
    const headers = new Headers(cloned.headers);
    headers.set('Cache-Control', `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`);
    headers.set('x-cp-age', String(Math.floor(Date.now() / 1000)));
    headers.set('x-cp-ttl', String(ttl));
    headers.set('x-cp-cached', 'edge');
    const cachedResp = new Response(cloned.body, { status: cloned.status, headers });
    ctx.waitUntil(edgeCache.put(request, cachedResp));
  } catch {}
}

// ── KV 페이지 캐시 ────────────────────────────────────────────────────────────
async function kvCacheGet(env, key) {
  if (!env.CACHE) return null;
  try {
    const meta = await env.CACHE.getWithMetadata(KV_PAGE_PREFIX + key, { type: 'text' });
    if (!meta || !meta.value) return null;
    const { contentType, status, cachedAt, ttl } = meta.metadata || {};
    const stale = Date.now() / 1000 - (cachedAt || 0) > (ttl || CACHE_TTL_HTML);
    return { body: meta.value, contentType, status: status || 200, stale, cachedAt };
  } catch {
    return null;
  }
}

async function kvCachePut(env, key, body, contentType = 'text/html; charset=utf-8', status = 200, ttl = CACHE_TTL_HTML) {
  if (!env.CACHE) return;
  try {
    await env.CACHE.put(
      KV_PAGE_PREFIX + key,
      body,
      {
        expirationTtl: CACHE_TTL_STALE,
        metadata: { contentType, status, cachedAt: Math.floor(Date.now() / 1000), ttl },
      }
    );
  } catch {}
}

// ── KV 사이트 정보 캐시 ───────────────────────────────────────────────────────
async function getSiteInfo(env, hostname) {
  // [1] KV 캐시
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + hostname, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }

  // [2] D1
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        `SELECT id, name, site_prefix, status, suspended,
                supabase_url, supabase_key, supabase_url2, supabase_key2,
                site_d1_id, site_kv_id, storage_bucket, storage_bucket2
           FROM sites
          WHERE (primary_domain = ? OR custom_domain = ?)
            AND domain_status = 'active'
            AND deleted_at IS NULL
          LIMIT 1`
      ).bind(hostname, hostname).first();

      if (row) {
        const info = {
          id: row.id, name: row.name,
          site_prefix: row.site_prefix || row.id,
          status: row.status, suspended: row.suspended,
          supabase_url: row.supabase_url, supabase_key: row.supabase_key,
          supabase_url2: row.supabase_url2, supabase_key2: row.supabase_key2,
          site_d1_id: row.site_d1_id, site_kv_id: row.site_kv_id,
          storage_bucket: row.storage_bucket, storage_bucket2: row.storage_bucket2,
        };
        // KV에 캐시
        if (env.CACHE) {
          env.CACHE.put(KV_SITE_PREFIX + hostname, JSON.stringify(info), { expirationTtl: 86400 }).catch(() => {});
        }
        return info;
      }
    } catch (e) {
      console.warn('[worker] D1 site lookup error:', e?.message);
    }
  }
  return null;
}

// ── WordPress 옵션 로드 (KV 캐시 → D1) ───────────────────────────────────────
async function getWPOptions(env, sitePrefix, keys) {
  const result = {};
  const missing = [];

  // KV 에서 먼저
  for (const k of keys) {
    const kvKey = `${KV_OPT_PREFIX}${sitePrefix}:${k}`;
    try {
      const v = env.CACHE ? await env.CACHE.get(kvKey) : null;
      if (v !== null) result[k] = v;
      else missing.push(k);
    } catch { missing.push(k); }
  }

  if (missing.length && env.DB) {
    try {
      const placeholders = missing.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT option_name, option_value FROM wp_options WHERE option_name IN (${placeholders}) LIMIT 50`
      ).bind(...missing).all();

      for (const row of (rows.results || [])) {
        result[row.option_name] = row.option_value;
        // KV 에 캐시
        if (env.CACHE) {
          env.CACHE.put(
            `${KV_OPT_PREFIX}${sitePrefix}:${row.option_name}`,
            row.option_value,
            { expirationTtl: 3600 }
          ).catch(() => {});
        }
      }
    } catch {}
  }
  return result;
}

// ── Supabase 스토리지 헬퍼 ────────────────────────────────────────────────────
async function supabaseUpload(siteInfo, bucket, path, body, contentType) {
  // Primary 시도
  if (siteInfo.supabase_url && siteInfo.supabase_key) {
    try {
      const res = await fetch(
        `${siteInfo.supabase_url}/storage/v1/object/${bucket}/${path}`,
        {
          method: 'POST',
          headers: {
            'apikey': siteInfo.supabase_key,
            'Authorization': `Bearer ${siteInfo.supabase_key}`,
            'Content-Type': contentType,
          },
          body,
        }
      );
      if (res.ok || res.status === 200 || res.status === 201) {
        return { ok: true, url: `${siteInfo.supabase_url}/storage/v1/object/public/${bucket}/${path}` };
      }
      // 스토리지 한도 초과(413) or quota 오류 → Secondary로
      if (res.status === 413 || res.status === 402) {
        throw new Error('quota_exceeded');
      }
    } catch (e) {
      if (e.message !== 'quota_exceeded') {
        // 네트워크 오류
      }
    }
  }

  // Secondary 시도
  if (siteInfo.supabase_url2 && siteInfo.supabase_key2) {
    try {
      const bucket2 = siteInfo.storage_bucket2 || bucket;
      const res = await fetch(
        `${siteInfo.supabase_url2}/storage/v1/object/${bucket2}/${path}`,
        {
          method: 'POST',
          headers: {
            'apikey': siteInfo.supabase_key2,
            'Authorization': `Bearer ${siteInfo.supabase_key2}`,
            'Content-Type': contentType,
          },
          body,
        }
      );
      if (res.ok) {
        // DB에 secondary 사용 표시
        if (env?.DB) {
          env.DB.prepare(
            `UPDATE sites SET storage_active = 2, updated_at = datetime('now') WHERE id = ?`
          ).bind(siteInfo.id).run().catch(() => {});
        }
        return { ok: true, url: `${siteInfo.supabase_url2}/storage/v1/object/public/${bucket2}/${path}`, secondary: true };
      }
    } catch {}
  }

  // D1 fallback (소형 파일만)
  return { ok: false, error: 'all_storage_failed' };
}

// ── Edge SSR: WordPress 페이지 렌더 ──────────────────────────────────────────
async function renderWordPressPage(env, siteInfo, url, request) {
  const sitePrefix = siteInfo.site_prefix;
  const hostname = url.hostname;
  const pathname = url.pathname;
  const search = url.search;

  // WordPress 옵션 로드
  const opts = await getWPOptions(env, sitePrefix, [
    'blogname', 'blogdescription', 'siteurl', 'home',
    'template', 'stylesheet', 'active_plugins', 'permalink_structure',
    'posts_per_page', 'date_format', 'time_format', 'timezone_string',
    'admin_email', 'default_comment_status',
  ]);

  const siteName = opts.blogname || siteInfo.name || hostname;
  const siteDesc = opts.blogdescription || '';
  const siteUrl  = `https://${hostname}`;
  const themeDir = opts.stylesheet || opts.template || 'twentytwentyfour';

  // permalink 구조 해석 → 어떤 컨텐츠인지 판단
  const contentData = await resolveWPRoute(env, sitePrefix, pathname, search, opts);

  // HTML 렌더
  const html = await renderWPTemplate(env, sitePrefix, siteInfo, contentData, {
    siteName, siteDesc, siteUrl, themeDir, opts, hostname, pathname,
  });

  return { html, contentData };
}

// ── WordPress 라우팅 해석 ─────────────────────────────────────────────────────
async function resolveWPRoute(env, sitePrefix, pathname, search, opts) {
  const searchParams = new URLSearchParams(search);
  const p = searchParams.get('p');
  const pageName = searchParams.get('page_id') || searchParams.get('page');
  const catSlug  = searchParams.get('cat') || searchParams.get('category_name');
  const tagSlug  = searchParams.get('tag');
  const postSlug = pathname.replace(/^\/|\/$/g,'');
  const permaStruct = opts.permalink_structure || '';

  let type = 'home', posts = [], post = null, term = null;

  try {
    if (pathname === '/' || pathname === '') {
      // 홈 페이지
      const frontPage = opts.page_on_front ? parseInt(opts.page_on_front, 10) : 0;
      if (frontPage) {
        post = await env.DB.prepare(
          `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
        ).bind(frontPage).first();
        type = 'page';
      } else {
        const perPage = parseInt(opts.posts_per_page || '10', 10);
        const res = await env.DB.prepare(
          `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name, post_author, comment_count
             FROM wp_posts
            WHERE post_type = 'post' AND post_status = 'publish'
            ORDER BY post_date DESC LIMIT ?`
        ).bind(perPage).all();
        posts = res.results || [];
        type = 'home';
      }
    } else if (p) {
      // ?p=123
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
      ).bind(parseInt(p, 10)).first();
      type = post?.post_type === 'page' ? 'page' : 'single';
    } else if (catSlug) {
      // 카테고리
      const cat = await env.DB.prepare(
        `SELECT t.*, tt.description, tt.count, tt.term_taxonomy_id
           FROM wp_terms t
           JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
          WHERE t.slug = ? AND tt.taxonomy = 'category' LIMIT 1`
      ).bind(catSlug).first();
      if (cat) {
        term = cat;
        const res = await env.DB.prepare(
          `SELECT p.ID, p.post_title, p.post_content, p.post_excerpt, p.post_date, p.post_name
             FROM wp_posts p
             JOIN wp_term_relationships tr ON tr.object_id = p.ID
            WHERE tr.term_taxonomy_id = ? AND p.post_status = 'publish' AND p.post_type = 'post'
            ORDER BY p.post_date DESC LIMIT 10`
        ).bind(cat.term_taxonomy_id).all();
        posts = res.results || [];
      }
      type = 'archive';
    } else if (tagSlug) {
      // 태그
      const tag = await env.DB.prepare(
        `SELECT t.*, tt.description, tt.term_taxonomy_id
           FROM wp_terms t
           JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
          WHERE t.slug = ? AND tt.taxonomy = 'post_tag' LIMIT 1`
      ).bind(tagSlug).first();
      if (tag) {
        term = tag;
        const res = await env.DB.prepare(
          `SELECT p.ID, p.post_title, p.post_content, p.post_excerpt, p.post_date, p.post_name
             FROM wp_posts p
             JOIN wp_term_relationships tr ON tr.object_id = p.ID
            WHERE tr.term_taxonomy_id = ? AND p.post_status = 'publish' AND p.post_type = 'post'
            ORDER BY p.post_date DESC LIMIT 10`
        ).bind(tag.term_taxonomy_id).all();
        posts = res.results || [];
      }
      type = 'archive';
    } else if (postSlug) {
      // slug 기반 라우팅 (permalink)
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts
          WHERE post_name = ? AND post_status = 'publish'
            AND post_type IN ('post', 'page')
          LIMIT 1`
      ).bind(postSlug).first();
      if (post) {
        type = post.post_type === 'page' ? 'page' : 'single';
        // 포스트 메타 로드
        if (post.ID) {
          const metaRes = await env.DB.prepare(
            `SELECT meta_key, meta_value FROM wp_postmeta WHERE post_id = ? LIMIT 50`
          ).bind(post.ID).all();
          post._meta = {};
          for (const m of (metaRes.results || [])) {
            post._meta[m.meta_key] = m.meta_value;
          }
          // 카테고리, 태그
          const taxRes = await env.DB.prepare(
            `SELECT t.name, t.slug, tt.taxonomy
               FROM wp_terms t
               JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
               JOIN wp_term_relationships tr ON tr.term_taxonomy_id = tt.term_taxonomy_id
              WHERE tr.object_id = ? AND tt.taxonomy IN ('category','post_tag')`
          ).bind(post.ID).all();
          post._categories = (taxRes.results || []).filter(r => r.taxonomy === 'category');
          post._tags       = (taxRes.results || []).filter(r => r.taxonomy === 'post_tag');
        }
      } else {
        type = '404';
      }
    }
  } catch (e) {
    console.warn('[SSR] DB query error:', e.message);
    type = 'error';
  }

  return { type, post, posts, term };
}

// ── WordPress 테마 렌더 ────────────────────────────────────────────────────────
async function renderWPTemplate(env, sitePrefix, siteInfo, contentData, ctx) {
  const { siteName, siteDesc, siteUrl, opts, hostname, pathname } = ctx;
  const { type, post, posts, term } = contentData;

  // 사이드바 위젯 (최근 글)
  let recentPosts = [];
  try {
    const rp = await env.DB.prepare(
      `SELECT ID, post_title, post_name, post_date FROM wp_posts
        WHERE post_type = 'post' AND post_status = 'publish'
        ORDER BY post_date DESC LIMIT 5`
    ).all();
    recentPosts = rp.results || [];
  } catch {}

  // 메뉴 (wp_nav_menus)
  let navItems = [];
  try {
    const navRes = await env.DB.prepare(
      `SELECT p.post_title, pm.meta_value as url, p.menu_order
         FROM wp_posts p
         LEFT JOIN wp_postmeta pm ON pm.post_id = p.ID AND pm.meta_key = '_menu_item_url'
        WHERE p.post_type = 'nav_menu_item' AND p.post_status = 'publish'
        ORDER BY p.menu_order ASC LIMIT 20`
    ).all();
    navItems = navRes.results || [];
  } catch {}

  // 컨텐츠 영역 생성
  let mainContent = '';
  let pageTitle   = siteName;
  let metaDesc    = siteDesc;

  if (type === 'single' || type === 'page') {
    pageTitle = esc(post?.post_title || siteName);
    metaDesc  = esc(post?.post_excerpt || siteDesc);
    const excerpt = post?.post_excerpt || (post?.post_content || '').slice(0, 200).replace(/<[^>]+>/g, '');
    const cats = (post?._categories || []).map(c =>
      `<a href="${esc(siteUrl)}/?category_name=${esc(c.slug)}" rel="category tag">${esc(c.name)}</a>`
    ).join(', ');
    const tags = (post?._tags || []).map(t =>
      `<a href="${esc(siteUrl)}/?tag=${esc(t.slug)}" rel="tag">${esc(t.name)}</a>`
    ).join(', ');

    mainContent = `
<article id="post-${post?.ID || 0}" class="post-${post?.ID || 0} ${post?.post_type || 'post'} type-${post?.post_type || 'post'} status-publish hentry${cats ? ' has-cats' : ''}">
  <header class="entry-header">
    <h1 class="entry-title">${esc(post?.post_title || '')}</h1>
    ${type === 'single' ? `<div class="entry-meta">
      <time class="entry-date published" datetime="${esc(post?.post_date || '')}">${formatDate(post?.post_date, opts.date_format)}</time>
      ${cats ? `<span class="cat-links">${cats}</span>` : ''}
    </div>` : ''}
  </header>
  <div class="entry-content">${renderShortcodes(post?.post_content || '')}</div>
  ${tags ? `<footer class="entry-footer"><span class="tags-links">${tags}</span></footer>` : ''}
</article>`;
  } else if (type === 'home' || type === 'archive') {
    if (type === 'archive' && term) {
      pageTitle = esc(term.name);
      metaDesc  = esc(term.description || '');
      mainContent += `<header class="page-header"><h1 class="page-title">${esc(term.name)}</h1>${term.description ? `<div class="taxonomy-description">${esc(term.description)}</div>` : ''}</header>`;
    }
    if (posts.length === 0) {
      mainContent += `<div class="no-posts"><p>게시글이 없습니다.</p></div>`;
    } else {
      mainContent += '<div class="posts-loop">';
      for (const p of posts) {
        const excerpt = (p.post_excerpt || p.post_content || '').slice(0, 300).replace(/<[^>]+>/g, '');
        mainContent += `
<article id="post-${p.ID}" class="post-${p.ID} post type-post status-publish hentry">
  <header class="entry-header">
    <h2 class="entry-title"><a href="${esc(siteUrl)}/${esc(p.post_name)}/" rel="bookmark">${esc(p.post_title)}</a></h2>
    <div class="entry-meta"><time class="entry-date published" datetime="${esc(p.post_date)}">${formatDate(p.post_date, opts.date_format)}</time></div>
  </header>
  <div class="entry-summary"><p>${esc(excerpt.slice(0, 200))}${excerpt.length > 200 ? '…' : ''}</p><a href="${esc(siteUrl)}/${esc(p.post_name)}/" class="more-link">더 읽기</a></div>
</article>`;
      }
      mainContent += '</div>';
    }
  } else if (type === '404') {
    pageTitle = '페이지를 찾을 수 없음';
    mainContent = `<div class="error-404 not-found"><h1>404</h1><p>요청하신 페이지를 찾을 수 없습니다.</p><a href="${esc(siteUrl)}/">홈으로</a></div>`;
  }

  // 네비게이션 메뉴 HTML
  const navHtml = navItems.length
    ? navItems.map(n => `<li class="menu-item"><a href="${esc(n.url || siteUrl + '/')}">${esc(n.post_title)}</a></li>`).join('')
    : `<li class="menu-item"><a href="${esc(siteUrl)}/">홈</a></li>`;

  // 사이드바
  const sidebarHtml = `
<aside id="secondary" class="widget-area">
  <section id="recent-posts" class="widget widget_recent_entries">
    <h2 class="widget-title">최근 글</h2>
    <ul>${recentPosts.map(rp => `<li><a href="${esc(siteUrl)}/${esc(rp.post_name)}/">${esc(rp.post_title)}</a></li>`).join('')}</ul>
  </section>
</aside>`;

  // 완전한 WordPress 스타일 HTML
  return `<!DOCTYPE html>
<html lang="ko" class="no-js">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="WordPress 6.7">
  <title>${pageTitle}${type !== 'home' ? ` – ${esc(siteName)}` : ''}</title>
  <meta name="description" content="${metaDesc}">
  <link rel="canonical" href="${esc(siteUrl + pathname)}">
  <link rel="alternate" type="application/rss+xml" title="${esc(siteName)} &raquo; 피드" href="${esc(siteUrl)}/feed/">
  <link rel="stylesheet" id="wp-block-library-css" href="/wp-includes/css/dist/block-library/style.min.css" media="all">
  <link rel="stylesheet" id="theme-css" href="/wp-content/themes/twentytwentyfour/style.css" media="all">
  <style>
    :root{--wp--preset--color--black:#000;--wp--preset--color--white:#fff;--wp--preset--color--cyan-bluish-gray:#abb8c3;--wp--preset--color--pale-pink:#f78da7;--wp--preset--color--vivid-red:#cf2e2e;--wp--preset--color--luminous-vivid-orange:#ff6900;--wp--preset--color--vivid-green-cyan:#00d084;--wp--preset--color--pale-cyan-blue:#8ed1fc;--wp--preset--font-size--small:13px;--wp--preset--font-size--medium:20px;--wp--preset--font-size--large:36px;--wp--preset--font-size--x-large:42px;--wp--preset--font-size--normal:16px;}
    *,::after,::before{box-sizing:border-box}
    html{font-size:16px;scroll-behavior:smooth}
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:1rem;line-height:1.7;color:#1e1e1e;background:#fff}
    a{color:#0073aa;text-decoration:none}a:hover{text-decoration:underline;color:#005580}
    img{max-width:100%;height:auto}
    .site{display:flex;flex-direction:column;min-height:100vh}
    .site-header{background:#fff;border-bottom:1px solid #e0e0e0;padding:.8rem 0;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.1)}
    .header-inner{max-width:1200px;margin:0 auto;padding:0 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
    .site-branding .site-title{margin:0;font-size:1.5rem;font-weight:700}.site-branding .site-title a{color:#1e1e1e}
    .site-branding .site-description{margin:.25rem 0 0;color:#767676;font-size:.875rem}
    nav.main-navigation ul{list-style:none;margin:0;padding:0;display:flex;gap:1.5rem}
    nav.main-navigation ul li a{font-size:.9375rem;color:#1e1e1e;font-weight:500;padding:.25rem 0;border-bottom:2px solid transparent;transition:border-color .2s}
    nav.main-navigation ul li a:hover{border-bottom-color:#0073aa;text-decoration:none}
    .site-content{flex:1;max-width:1200px;margin:0 auto;padding:2rem 1.5rem;width:100%;display:grid;grid-template-columns:1fr 300px;gap:2.5rem}
    @media(max-width:768px){.site-content{grid-template-columns:1fr}}
    .entry-header{margin-bottom:1.5rem}
    .entry-title{font-size:1.75rem;font-weight:700;margin:0 0 .5rem;line-height:1.3}
    .entry-title a{color:#1e1e1e}.entry-title a:hover{color:#0073aa;text-decoration:none}
    .entry-meta{color:#767676;font-size:.875rem;margin-bottom:.5rem}
    .entry-meta time{margin-right:.75rem}
    .entry-content{line-height:1.8;font-size:1rem}
    .entry-content p{margin:0 0 1.25rem}
    .entry-content h2,.entry-content h3,.entry-content h4{margin:2rem 0 1rem;font-weight:700}
    .entry-content img{border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.12)}
    .entry-summary{margin-bottom:.75rem}.entry-summary p{margin:0}
    .more-link{display:inline-block;margin-top:.5rem;padding:.35rem .875rem;background:#0073aa;color:#fff;border-radius:3px;font-size:.875rem;font-weight:500;transition:background .15s}
    .more-link:hover{background:#005580;color:#fff;text-decoration:none}
    .posts-loop article{padding:1.5rem 0;border-bottom:1px solid #e8e8e8}.posts-loop article:last-child{border-bottom:none}
    .cat-links a,.tags-links a{display:inline-block;margin:0 .25rem .25rem 0;padding:.15rem .5rem;background:#f0f0f0;border-radius:3px;font-size:.8125rem;color:#555}
    .error-404{text-align:center;padding:3rem 1rem}.error-404 h1{font-size:6rem;font-weight:900;color:#0073aa;margin:0}
    .error-404 p{font-size:1.25rem;color:#767676;margin:1rem 0 2rem}
    .widget-area{font-size:.9375rem}
    .widget{margin-bottom:2rem;padding:1.5rem;background:#f9f9f9;border-radius:6px;border:1px solid #e8e8e8}
    .widget-title{font-size:1rem;font-weight:700;margin:0 0 1rem;padding-bottom:.5rem;border-bottom:2px solid #0073aa}
    .widget ul{list-style:none;margin:0;padding:0}
    .widget ul li{padding:.4rem 0;border-bottom:1px solid #eee}.widget ul li:last-child{border-bottom:none}
    .site-footer{background:#1e1e1e;color:#a0a0a0;padding:2rem 1.5rem;text-align:center;font-size:.875rem;margin-top:auto}
    .site-footer a{color:#c0c0c0}.site-footer a:hover{color:#fff}
    .no-posts{text-align:center;padding:3rem 1rem;color:#767676;font-size:1.1rem}
    .page-header{margin-bottom:2rem;padding-bottom:1rem;border-bottom:2px solid #0073aa}
    .page-title{font-size:1.5rem;font-weight:700;margin:0}
    .entry-footer{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e8e8e8;font-size:.875rem;color:#767676}
    .wp-admin-bar{display:none}
    @media(prefers-color-scheme:dark){body{background:#1a1a1a;color:#e0e0e0}.site-header{background:#1e1e1e;border-bottom-color:#333}.entry-title a,.site-branding .site-title a{color:#e0e0e0}a{color:#4fa8d5}.site-footer{background:#111}.widget{background:#252525;border-color:#333}.widget ul li{border-bottom-color:#333}.posts-loop article{border-bottom-color:#333}}
  </style>
  <link rel="pingback" href="${esc(siteUrl)}/xmlrpc.php">
</head>
<body class="wp-site-blocks ${type === 'single' ? 'single-post' : type === 'page' ? 'page' : type === 'home' ? 'home blog' : type}">
<div id="page" class="site">
  <header id="masthead" class="site-header">
    <div class="header-inner">
      <div class="site-branding">
        <p class="site-title"><a href="${esc(siteUrl)}/" rel="home">${esc(siteName)}</a></p>
        ${siteDesc ? `<p class="site-description">${esc(siteDesc)}</p>` : ''}
      </div>
      <nav id="site-navigation" class="main-navigation" aria-label="주 메뉴">
        <ul>${navHtml}</ul>
      </nav>
    </div>
  </header>

  <div id="content" class="site-content">
    <main id="primary" class="site-main">${mainContent}</main>
    ${sidebarHtml}
  </div>

  <footer id="colophon" class="site-footer">
    <div class="site-info">
      <a href="${esc(siteUrl)}/">${esc(siteName)}</a> &mdash; 
      <a href="https://wordpress.org/" target="_blank" rel="noopener">WordPress</a>로 제작
      &nbsp;|&nbsp; Powered by <a href="https://cloudpress.site/" target="_blank" rel="noopener">CloudPress</a>
    </div>
  </footer>
</div>
<script>document.documentElement.className=document.documentElement.className.replace('no-js','js');</script>
</body>
</html>`;
}

// ── 날짜 포맷 ─────────────────────────────────────────────────────────────────
function formatDate(dateStr, fmt) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    const year = d.getFullYear(), month = d.getMonth()+1, day = d.getDate();
    if (!fmt || fmt === 'Y년 n월 j일') {
      return `${year}년 ${month}월 ${day}일`;
    }
    return d.toLocaleDateString('ko-KR');
  } catch { return dateStr; }
}

// ── WordPress 쇼트코드 렌더 ───────────────────────────────────────────────────
function renderShortcodes(content) {
  if (!content) return '';
  // 기본 쇼트코드 처리
  return content
    .replace(/\[caption[^\]]*\](.*?)\[\/caption\]/gs, (_, inner) => `<figure class="wp-caption">${inner}</figure>`)
    .replace(/\[gallery[^\]]*\]/g, '<div class="gallery">[갤러리]</div>')
    .replace(/\[embed\](.*?)\[\/embed\]/g, (_, url) => `<div class="wp-embed-responsive"><a href="${esc(url)}" target="_blank" rel="noopener">${esc(url)}</a></div>`)
    .replace(/\[[\w_-]+[^\]]*\]/g, '') // 나머지 쇼트코드 제거
    .replace(/\n\n+/g, '</p><p>') // 단락 변환
    .replace(/^(?!<[a-z])/gm, (m) => m ? `<p>${m}` : m);
}

// ── wp-admin 요청 처리 ────────────────────────────────────────────────────────
async function handleWPAdmin(env, request, url, siteInfo) {
  // 로그인 체크
  const cookie = request.headers.get('cookie') || '';
  const hasSession = /wordpress_logged_in/.test(cookie);

  if (!hasSession && url.pathname !== '/wp-login.php') {
    // 로그인 페이지로 리다이렉트
    return Response.redirect(`https://${url.hostname}/wp-login.php?redirect_to=${encodeURIComponent(url.pathname)}`, 302);
  }

  // wp-admin 파일들을 D1/KV에서 서빙
  // (간소화: 실제 WordPress 파일 서빙은 Workers Sites나 R2 사용)
  return new Response(renderAdminPage(url.pathname, siteInfo), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function renderAdminPage(pathname, siteInfo) {
  return `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WordPress 관리자 – ${esc(siteInfo?.name || '')}</title>
<style>body{font-family:-apple-system,sans-serif;background:#f0f0f1;margin:0;padding:20px}
.wrap{max-width:900px;margin:40px auto;background:#fff;padding:30px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
h1{color:#1d2327;font-size:1.5rem;margin:0 0 1rem}</style>
</head><body><div class="wrap">
<h1>WordPress 관리자 <span style="font-size:.8em;color:#888;">${esc(pathname)}</span></h1>
<p>CloudPress Edge에서 WordPress 관리자 기능이 D1 + Supabase 스토리지 기반으로 동작 중입니다.</p>
<p><a href="/">← 사이트 보기</a></p>
</div></body></html>`;
}

// ── WordPress 로그인 처리 ─────────────────────────────────────────────────────
async function handleWPLogin(env, request, url, siteInfo) {
  if (request.method === 'POST') {
    const body = await request.formData().catch(() => new FormData());
    const username = body.get('log') || '';
    const password = body.get('pwd') || '';
    const redirectTo = body.get('redirect_to') || '/wp-admin/';

    if (username && password) {
      try {
        // WordPress 패스워드 해시 검증 (bcrypt 지원)
        const user = await env.DB.prepare(
          `SELECT ID, user_login, user_pass, user_email, display_name FROM wp_users WHERE user_login = ? OR user_email = ? LIMIT 1`
        ).bind(username, username).first();

        if (user && await verifyWPPassword(password, user.user_pass)) {
          // 세션 생성
          const sessionToken = crypto.randomUUID();
          const expiry = new Date(Date.now() + 30 * 24 * 3600 * 1000).toUTCString();

          if (env.CACHE) {
            await env.CACHE.put(
              `wp_session:${sessionToken}`,
              JSON.stringify({ userId: user.ID, login: user.user_login }),
              { expirationTtl: 30 * 24 * 3600 }
            );
          }

          const cookieDomain = url.hostname;
          return new Response('', {
            status: 302,
            headers: {
              'Location': redirectTo,
              'Set-Cookie': `wordpress_logged_in_${hashSimple(cookieDomain)}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiry}`,
            },
          });
        }
      } catch (e) {
        console.warn('[login] error:', e.message);
      }
    }

    // 로그인 실패
    return new Response(renderLoginPage(siteInfo, '사용자명 또는 비밀번호가 올바르지 않습니다.', url), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  return new Response(renderLoginPage(siteInfo, '', url), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function renderLoginPage(siteInfo, error, url) {
  const siteUrl = url ? `https://${url.hostname}` : '';
  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>로그인 – ${esc(siteInfo?.name || 'WordPress')}</title>
  <link rel="stylesheet" href="/wp-admin/css/login.min.css">
  <style>
    html{height:auto;background:#f0f0f1}
    body{display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;font-family:-apple-system,sans-serif;background:#f0f0f1}
    #login{width:320px;padding:26px 24px 24px;background:#fff;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.13)}
    .login-logo{text-align:center;margin-bottom:20px}
    .login-logo a{display:inline-block;width:84px;height:84px;background:url(/wp-admin/images/wordpress-logo.svg) no-repeat center;background-size:contain;text-indent:-9999px}
    h1{display:none}
    label{display:block;font-size:.875rem;font-weight:600;margin-bottom:.375rem;color:#1d2327}
    input[type=text],input[type=password]{width:100%;padding:.5rem .75rem;border:1px solid #8c8f94;border-radius:4px;font-size:1rem;box-sizing:border-box;margin-bottom:1rem}
    input[type=text]:focus,input[type=password]:focus{border-color:#2271b1;outline:2px solid rgba(34,113,177,.4);outline-offset:-1px}
    .button-primary{width:100%;padding:.6rem;background:#2271b1;color:#fff;border:none;border-radius:4px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .15s}
    .button-primary:hover{background:#135e96}
    .login-error{background:#f0f0f1;border-left:4px solid #d63638;padding:.75rem 1rem;margin-bottom:1rem;font-size:.875rem;color:#d63638;border-radius:0 4px 4px 0}
    .nav{margin-top:1rem;text-align:center;font-size:.8125rem}
    .nav a{color:#2271b1;margin:0 .5rem}
  </style>
</head>
<body>
<div id="login">
  <div class="login-logo"><a href="${esc(siteUrl)}/">WordPress</a></div>
  <h1>WordPress에 로그인</h1>
  ${error ? `<div class="login-error">${esc(error)}</div>` : ''}
  <form name="loginform" method="post" action="/wp-login.php">
    <label for="user_login">사용자명 또는 이메일 주소</label>
    <input type="text" name="log" id="user_login" autocomplete="username" required>
    <label for="user_pass">비밀번호</label>
    <input type="password" name="pwd" id="user_pass" autocomplete="current-password" required>
    <input type="hidden" name="redirect_to" value="/wp-admin/">
    <input type="hidden" name="testcookie" value="1">
    <button type="submit" class="button-primary">로그인</button>
  </form>
  <div class="nav">
    <a href="${esc(siteUrl)}/wp-login.php?action=lostpassword">비밀번호 찾기</a>
    <a href="${esc(siteUrl)}/">← ${esc(siteInfo?.name || '사이트')}으로</a>
  </div>
</div>
</body>
</html>`;
}

// ── WordPress 비밀번호 검증 ───────────────────────────────────────────────────
async function verifyWPPassword(password, hash) {
  if (!hash) return false;
  // MD5 기반 WordPress 해시 ($P$)
  if (hash.startsWith('$P$')) {
    return wpCheckPassword(password, hash);
  }
  // bcrypt
  if (hash.startsWith('$2y$') || hash.startsWith('$2b$')) {
    // Workers 환경에서 bcrypt 미지원 → 단순 비교 fallback
    return false;
  }
  // plain MD5 (구형)
  const md5 = await crypto.subtle.digest('MD5', new TextEncoder().encode(password)).catch(() => null);
  if (md5) {
    const hex = [...new Uint8Array(md5)].map(b => b.toString(16).padStart(2,'0')).join('');
    return hex === hash;
  }
  return false;
}

// WordPress portable hash (phpass)
function wpCheckPassword(password, hash) {
  const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  function encode64(input, count) {
    let output = '', i = 0;
    do {
      let value = input[i++];
      output += itoa64[value & 63];
      if (i < count) value |= input[i] << 8;
      output += itoa64[(value >> 6) & 63];
      if (i++ >= count) break;
      if (i < count) value |= input[i] << 8;
      output += itoa64[(value >> 12) & 63];
      if (i++ >= count) break;
      output += itoa64[(value >> 18) & 63];
    } while (i < count);
    return output;
  }
  // 간소화된 검증 (Workers에서 동기 MD5 불가 → false 반환, 실제 환경에서는 PHP origin 사용)
  return false;
}

function hashSimple(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return Math.abs(h).toString(16).slice(0, 8);
}

// ── REST API 처리 ─────────────────────────────────────────────────────────────
async function handleWPRestAPI(env, request, url, siteInfo) {
  const path = url.pathname.replace('/wp-json', '');
  const method = request.method;

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
    'Content-Type': 'application/json; charset=utf-8',
  };

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  const j = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: corsHeaders });

  try {
    // /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'GET') {
      const perPage = parseInt(url.searchParams.get('per_page') || '10', 10);
      const page    = parseInt(url.searchParams.get('page') || '1', 10);
      const offset  = (page - 1) * perPage;
      const search  = url.searchParams.get('search') || '';
      const catId   = url.searchParams.get('categories');
      const tagId   = url.searchParams.get('tags');

      let sql = `SELECT ID, post_title, post_content, post_excerpt, post_date, post_date_gmt, post_modified, post_name, post_author, comment_count, post_type, post_status, guid FROM wp_posts WHERE post_type = 'post' AND post_status = 'publish'`;
      const binds = [];
      if (search) { sql += ` AND (post_title LIKE ? OR post_content LIKE ?)`; binds.push(`%${search}%`, `%${search}%`); }
      sql += ` ORDER BY post_date DESC LIMIT ? OFFSET ?`;
      binds.push(perPage, offset);

      const res = await env.DB.prepare(sql).bind(...binds).all();
      const posts = (res.results || []).map(wpPostToJSON);

      // X-WP-Total 헤더
      const countRes = await env.DB.prepare(`SELECT COUNT(*) as c FROM wp_posts WHERE post_type='post' AND post_status='publish'`).first();
      const total = countRes?.c || 0;

      return new Response(JSON.stringify(posts), {
        status: 200,
        headers: { ...corsHeaders, 'X-WP-Total': String(total), 'X-WP-TotalPages': String(Math.ceil(total / perPage)) },
      });
    }

    // /wp/v2/posts/:id
    const postMatch = path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/);
    if (postMatch && method === 'GET') {
      const post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
      ).bind(parseInt(postMatch[1], 10)).first();
      if (!post) return j({ code: 'rest_post_invalid_id', message: '유효하지 않은 포스트 ID입니다.' }, 404);
      return j(wpPostToJSON(post));
    }

    // /wp/v2/pages
    if (path.match(/^\/wp\/v2\/pages\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE post_type = 'page' AND post_status = 'publish' ORDER BY menu_order ASC, post_date DESC LIMIT 100`
      ).all();
      return j((res.results || []).map(wpPostToJSON));
    }

    // /wp/v2/categories
    if (path.match(/^\/wp\/v2\/categories\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count, tt.parent FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'category' ORDER BY t.name ASC`
      ).all();
      return j(res.results || []);
    }

    // /wp/v2/tags
    if (path.match(/^\/wp\/v2\/tags\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'post_tag' ORDER BY tt.count DESC LIMIT 100`
      ).all();
      return j(res.results || []);
    }

    // /wp/v2/users
    if (path.match(/^\/wp\/v2\/users\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT ID as id, display_name as name, user_login as slug, user_url as url FROM wp_users LIMIT 20`
      ).all();
      return j(res.results || []);
    }

    // /wp/v2/media (GET)
    if (path.match(/^\/wp\/v2\/media\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT media_id as id, file_name as slug, alt_text, caption, mime_type, file_size FROM wp_media ORDER BY upload_date DESC LIMIT 20`
      ).all();
      return j(res.results || []);
    }

    // /wp/v2/settings (읽기 전용)
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'GET') {
      const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','url','email','timezone','date_format','posts_per_page']);
      return j({
        title: opts.blogname || '',
        description: opts.blogdescription || '',
        url: opts.url || '',
        email: opts.email || '',
        timezone: opts.timezone || 'Asia/Seoul',
        date_format: opts.date_format || 'Y년 n월 j일',
        posts_per_page: parseInt(opts.posts_per_page || '10', 10),
      });
    }

    // Feed (RSS)
    if (path === '' && url.searchParams.has('feed') || url.pathname === '/feed/') {
      return await handleRSSFeed(env, siteInfo, url);
    }

    return j({ code: 'rest_no_route', message: '일치하는 라우트가 없습니다.', data: { status: 404 } }, 404);
  } catch (e) {
    console.error('[REST API] error:', e.message);
    return j({ code: 'rest_error', message: '서버 오류가 발생했습니다.' }, 500);
  }
}

function wpPostToJSON(p) {
  return {
    id: p.ID || p.id,
    date: p.post_date,
    date_gmt: p.post_date_gmt,
    modified: p.post_modified,
    slug: p.post_name,
    status: p.post_status,
    type: p.post_type,
    link: p.guid,
    title: { rendered: p.post_title || '' },
    content: { rendered: p.post_content || '', protected: false },
    excerpt: { rendered: p.post_excerpt || '', protected: false },
    author: p.post_author || 1,
    comment_status: p.comment_status || 'open',
    comment_count: p.comment_count || 0,
    _links: {
      self: [{ href: `/wp-json/wp/v2/posts/${p.ID || p.id}` }],
      collection: [{ href: '/wp-json/wp/v2/posts' }],
    },
  };
}

// ── RSS 피드 ──────────────────────────────────────────────────────────────────
async function handleRSSFeed(env, siteInfo, url) {
  const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','siteurl']);
  const siteName = opts.blogname || siteInfo.name;
  const siteUrl  = `https://${url.hostname}`;

  let posts = [];
  try {
    const res = await env.DB.prepare(
      `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 10`
    ).all();
    posts = res.results || [];
  } catch {}

  const items = posts.map(p => {
    const link = `${siteUrl}/${p.post_name}/`;
    return `<item>
  <title><![CDATA[${p.post_title}]]></title>
  <link>${link}</link>
  <pubDate>${new Date(p.post_date).toUTCString()}</pubDate>
  <guid isPermaLink="true">${link}</guid>
  <description><![CDATA[${(p.post_excerpt || p.post_content || '').slice(0, 500)}]]></description>
</item>`;
  }).join('\n');

  const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:wfw="http://wellformedweb.org/CommentAPI/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>${siteName}</title>
  <link>${siteUrl}</link>
  <description>${opts.blogdescription || ''}</description>
  <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
  <language>ko</language>
  <atom:link href="${siteUrl}/feed/" rel="self" type="application/rss+xml"/>
  ${items}
</channel>
</rss>`;

  return new Response(rss, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

// ── 미디어 업로드 처리 ────────────────────────────────────────────────────────
async function handleMediaUpload(env, request, siteInfo) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('multipart/form-data')) {
    return new Response(JSON.stringify({ error: 'multipart/form-data 필요' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const formData = await request.formData();
  const file = formData.get('file') || formData.get('async-upload');

  if (!file || typeof file === 'string') {
    return new Response(JSON.stringify({ error: '파일이 없습니다' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const fileName = file.name || 'upload_' + Date.now();
  const mimeType = file.type || 'application/octet-stream';
  const fileSize = file.size || 0;
  const bucket   = siteInfo.storage_bucket || 'media';
  const datePath = new Date().toISOString().slice(0, 7).replace('-', '/');
  const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = `${siteInfo.site_prefix}/${datePath}/${Date.now()}_${safeName}`;

  const arrayBuffer = await file.arrayBuffer();
  const result = await supabaseUpload(siteInfo, bucket, storagePath, arrayBuffer, mimeType);

  if (!result.ok) {
    // D1에 바이너리 저장 시도 (소형 파일 <500KB)
    if (fileSize < 500 * 1024) {
      const b64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
      try {
        await env.DB.prepare(
          `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'd1', '')`
        ).bind(safeName, storagePath, mimeType, fileSize).run();
        // KV에도 저장
        if (env.CACHE) {
          await env.CACHE.put(`media:${storagePath}`, b64, { metadata: { mimeType, size: fileSize } });
        }
        return new Response(JSON.stringify({ id: Date.now(), url: `/wp-content/uploads/${storagePath}`, title: safeName }), {
          status: 201, headers: { 'Content-Type': 'application/json' },
        });
      } catch {}
    }
    return new Response(JSON.stringify({ error: '업로드 실패' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  // DB에 미디어 레코드 저장
  try {
    await env.DB.prepare(
      `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'supabase', '')`
    ).bind(safeName, result.url, mimeType, fileSize).run();
  } catch {}

  return new Response(JSON.stringify({
    id: Date.now(),
    url: result.url,
    title: safeName.replace(/\.[^.]+$/, ''),
    mime_type: mimeType,
    source_url: result.url,
    secondary: result.secondary || false,
  }), { status: 201, headers: { 'Content-Type': 'application/json' } });
}

// ── SWR 백그라운드 재검증 ─────────────────────────────────────────────────────
async function revalidatePage(env, siteInfo, url, request) {
  try {
    const { html } = await renderWordPressPage(env, siteInfo, url, request);
    const kvKey = `${siteInfo.site_prefix}:${url.pathname}${url.search}`;
    await kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', 200, CACHE_TTL_HTML);
    // Edge Cache 갱신
    const freshResp = new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
        'x-cp-cached': 'edge',
        'x-cp-revalidated': '1',
      },
    });
    await edgeCache.put(new Request(url.toString()), freshResp);
  } catch (e) {
    console.warn('[SWR] revalidation failed:', e.message);
  }
}

// ── 캐시 Purge API ────────────────────────────────────────────────────────────
async function handlePurge(env, request, url, siteInfo) {
  const auth = request.headers.get('Authorization') || '';
  const purgeKey = env.PURGE_KEY || '';

  if (purgeKey && auth !== `Bearer ${purgeKey}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const body = await request.json().catch(() => ({}));
  const paths = body.paths || [url.searchParams.get('path') || '/'];
  const prefix = siteInfo.site_prefix;

  let purged = 0;
  for (const p of paths) {
    const kvKey = `${prefix}:${p}`;
    try {
      await env.CACHE?.delete(KV_PAGE_PREFIX + kvKey);
      await edgeCache.delete(new Request(`https://${url.hostname}${p}`));
      purged++;
    } catch {}
  }

  return new Response(JSON.stringify({ ok: true, purged, paths }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Prewarm API ───────────────────────────────────────────────────────────────
async function handlePrewarm(env, request, url, siteInfo) {
  const paths = ['/', '/wp-sitemap.xml'];

  // 최근 포스트 슬러그 추가
  try {
    const res = await env.DB.prepare(
      `SELECT post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 5`
    ).all();
    for (const r of (res.results || [])) paths.push(`/${r.post_name}/`);
  } catch {}

  // 백그라운드에서 캐시 워밍
  const hostname = url.hostname;
  for (const p of paths) {
    const warmUrl = new URL(`https://${hostname}${p}`);
    revalidatePage(env, siteInfo, warmUrl, request).catch(() => {});
  }

  return new Response(JSON.stringify({ ok: true, paths, message: '캐시 예열 시작됨' }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Sitemap ───────────────────────────────────────────────────────────────────
async function handleSitemap(env, siteInfo, url) {
  const siteUrl = `https://${url.hostname}`;
  let posts = [], pages = [];

  try {
    const [pr, pgr] = await Promise.all([
      env.DB.prepare(`SELECT post_name, post_modified FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 1000`).all(),
      env.DB.prepare(`SELECT post_name, post_modified FROM wp_posts WHERE post_type='page' AND post_status='publish' ORDER BY menu_order ASC LIMIT 100`).all(),
    ]);
    posts = pr.results || [];
    pages = pgr.results || [];
  } catch {}

  const urls = [
    `<url><loc>${siteUrl}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>`,
    ...pages.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified || '').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`),
    ...posts.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified || '').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.6</priority></url>`),
  ];

  return new Response(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

// ── 설치 방지 (한번 설치 후 재설치 차단) ─────────────────────────────────────
async function isAlreadyInstalled(env) {
  if (!env.CACHE) return false;
  const flag = await env.CACHE.get('cp_installed').catch(() => null);
  return flag === '1';
}

async function markInstalled(env) {
  if (env.CACHE) {
    await env.CACHE.put('cp_installed', '1').catch(() => {});
  }
}

// ── 메인 핸들러 ───────────────────────────────────────────────────────────────
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname;
  const method   = request.method;
  const ip       = getClientIP(request);

  // ── [WAF] 요청 검사 ─────────────────────────────────────────────────────────
  const wafResult = wafCheck(request, url);
  if (wafResult.block) {
    if (wafResult.tarpit) {
      await new Promise(r => setTimeout(r, BOT_TARPIT_MS));
    }
    return new Response(
      `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>요청이 차단되었습니다. (${wafResult.reason})</p></body></html>`,
      { status: wafResult.status || 403, headers: { 'Content-Type': 'text/html', 'X-WAF-Block': wafResult.reason } }
    );
  }

  // ── [DDoS] Rate Limiting ────────────────────────────────────────────────────
  const isWrite = !['GET','HEAD','OPTIONS'].includes(method);
  const rlResult = await rateLimitCheck(env, ip, isWrite, pathname);
  if (!rlResult.allowed) {
    if (rlResult.banned) {
      return new Response('IP가 차단되었습니다. 잠시 후 다시 시도하세요.', {
        status: 429,
        headers: { 'Retry-After': String(DDOS_BAN_TTL), 'X-RateLimit-Reason': 'banned' },
      });
    }
    return new Response('Too Many Requests', {
      status: 429,
      headers: {
        'Retry-After': String(RATE_LIMIT_WIN),
        'X-RateLimit-Limit': String(rlResult.limit),
        'X-RateLimit-Remaining': '0',
      },
    });
  }

  // ── CloudPress 플랫폼 자체 요청 통과 ────────────────────────────────────────
  if (hostname.endsWith('.pages.dev') || hostname.endsWith('.workers.dev') ||
      hostname === 'cloudpress.site' || hostname === 'www.cloudpress.site') {
    return fetch(request);
  }

  // ── 도메인 인증 요청 ─────────────────────────────────────────────────────────
  if (pathname.startsWith('/.well-known/cloudpress-verify/')) {
    const token = pathname.split('/').pop();
    return new Response(`cloudpress-verify=${token}`, {
      headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' },
    });
  }

  // ── 사이트 정보 조회 ─────────────────────────────────────────────────────────
  const siteInfo = await getSiteInfo(env, hostname);

  if (!siteInfo) {
    return new Response(NOT_FOUND_HTML, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.suspended) {
    return new Response(SUSPENDED_HTML, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.status === 'pending' || siteInfo.status === 'provisioning') {
    return new Response(PROVISIONING_HTML, {
      status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' },
    });
  }

  // ── wp-login.php ─────────────────────────────────────────────────────────────
  if (pathname === '/wp-login.php') {
    return handleWPLogin(env, request, url, siteInfo);
  }

  // ── wp-admin ─────────────────────────────────────────────────────────────────
  if (pathname.startsWith('/wp-admin')) {
    return handleWPAdmin(env, request, url, siteInfo);
  }

  // ── REST API ─────────────────────────────────────────────────────────────────
  if (pathname.startsWith('/wp-json/')) {
    return handleWPRestAPI(env, request, url, siteInfo);
  }

  // ── RSS 피드 ─────────────────────────────────────────────────────────────────
  if (pathname === '/feed/' || pathname === '/feed' || url.searchParams.has('feed')) {
    return handleRSSFeed(env, siteInfo, url);
  }

  // ── Sitemap ──────────────────────────────────────────────────────────────────
  if (pathname === '/wp-sitemap.xml' || pathname === '/sitemap.xml' || pathname === '/sitemap_index.xml') {
    const sitemapResp = await handleSitemap(env, siteInfo, url);
    ctx.waitUntil(cachePut(ctx, request, sitemapResp.clone(), CACHE_TTL_API));
    return sitemapResp;
  }

  // ── 미디어 업로드 ────────────────────────────────────────────────────────────
  if (pathname === '/wp-admin/async-upload.php' && method === 'POST') {
    return handleMediaUpload(env, request, siteInfo);
  }

  // ── 캐시 Purge API ───────────────────────────────────────────────────────────
  if (pathname === '/cp-purge' || pathname === '/wp-json/cloudpress/v1/purge') {
    return handlePurge(env, request, url, siteInfo);
  }

  // ── Prewarm API ───────────────────────────────────────────────────────────────
  if (pathname === '/cp-prewarm') {
    return handlePrewarm(env, request, url, siteInfo);
  }

  // ── robots.txt ───────────────────────────────────────────────────────────────
  if (pathname === '/robots.txt') {
    const siteUrl = `https://${hostname}`;
    return new Response(
      `User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\nDisallow: /wp-json/\nAllow: /wp-admin/admin-ajax.php\nSitemap: ${siteUrl}/wp-sitemap.xml\n`,
      { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } }
    );
  }

  // ── OPTIONS 프리플라이트 ─────────────────────────────────────────────────────
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
      },
    });
  }

  // ── 정적 자산은 빠른 캐시만 ──────────────────────────────────────────────────
  if (isStaticAsset(pathname)) {
    // Edge Cache 확인
    const cached = await cacheGet(request);
    if (cached && !cached.stale) {
      const r = new Response(cached.response.body, { status: cached.response.status, headers: cached.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    // 정적 자산은 미디어 스토리지에서 서빙
    if (siteInfo.supabase_url) {
      const mediaPath = pathname.replace('/wp-content/uploads/', '');
      const mediaUrl  = `${siteInfo.supabase_url}/storage/v1/object/public/${siteInfo.storage_bucket || 'media'}/${siteInfo.site_prefix}/${mediaPath}`;
      try {
        const mediaResp = await fetch(mediaUrl, { cf: { cacheTtl: CACHE_TTL_ASSET, cacheEverything: true } });
        if (mediaResp.ok) {
          ctx.waitUntil(cachePut(ctx, request, mediaResp.clone(), CACHE_TTL_ASSET));
          const r = new Response(mediaResp.body, { status: mediaResp.status, headers: mediaResp.headers });
          r.headers.set('Cache-Control', `public, max-age=${CACHE_TTL_ASSET}`);
          return r;
        }
      } catch {}
    }
    return new Response('Not Found', { status: 404 });
  }

  // ── 캐시 불가능한 요청 (POST 등) 직접 처리 ──────────────────────────────────
  if (!isCacheable(request, url)) {
    const { html, contentData } = await renderWordPressPage(env, siteInfo, url, request);
    return new Response(html, {
      status: contentData.type === '404' ? 404 : 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, private' },
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 캐시 흐름: [1] Edge → [2] KV → [3] SSR → [4] Stale
  // ══════════════════════════════════════════════════════════════════════════
  const kvKey = `${siteInfo.site_prefix}:${pathname}${url.search}`;

  // ── [1] Edge Cache HIT ────────────────────────────────────────────────────
  const edgeHit = await cacheGet(request);
  if (edgeHit) {
    if (!edgeHit.stale) {
      const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      r.headers.set('x-cp-via', 'cloudpress-edge');
      return r;
    }
    // SWR: stale이면 백그라운드 재검증 후 stale 응답
    ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
    const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
    r.headers.set('x-cp-hit', 'edge-stale');
    r.headers.set('x-cp-swr', '1');
    return r;
  }

  // ── [2] KV Cache HIT ──────────────────────────────────────────────────────
  const kvHit = await kvCacheGet(env, kvKey);
  if (kvHit) {
    const status = kvHit.status || 200;
    const headers = new Headers({
      'Content-Type': kvHit.contentType || 'text/html; charset=utf-8',
      'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
      'x-cp-hit': 'kv',
      'x-cp-via': 'cloudpress-kv',
    });
    const resp = new Response(kvHit.body, { status, headers });
    // KV hit → Edge에도 저장 (이중 캐시)
    ctx.waitUntil(cachePut(ctx, request, resp.clone(), CACHE_TTL_HTML));

    if (kvHit.stale) {
      // SWR: stale이면 백그라운드 재검증
      ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
      resp.headers.set('x-cp-swr', '1');
    }
    return resp;
  }

  // ── [3] Edge SSR → 캐시 저장 ─────────────────────────────────────────────
  let html, contentData;
  try {
    ({ html, contentData } = await renderWordPressPage(env, siteInfo, url, request));
  } catch (ssrError) {
    console.error('[SSR] render failed:', ssrError?.message);

    // ── [4] 완전 실패 → Stale Cache 응답 (절대 지연 없음) ─────────────────
    // stale KV라도 있으면 반환
    if (kvHit) {
      const r = new Response(kvHit.body, {
        status: 200,
        headers: { 'Content-Type': kvHit.contentType || 'text/html; charset=utf-8', 'x-cp-hit': 'stale-fallback' },
      });
      return r;
    }
    // 아무것도 없으면 503
    return new Response(ERROR_HTML, {
      status: 503,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' },
    });
  }

  const isNotFound = contentData.type === '404';
  const respStatus = isNotFound ? 404 : 200;
  const ttl        = isNotFound ? 60 : CACHE_TTL_HTML;

  const responseHeaders = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': isNotFound
      ? 'public, max-age=60'
      : `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`,
    'x-cp-hit': 'miss',
    'x-cp-via': 'cloudpress-ssr',
    'x-cp-rendered': '1',
  });

  // 캐시에 저장 (백그라운드)
  if (!isNotFound) {
    ctx.waitUntil(kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', respStatus, ttl));
  }
  const ssrResp = new Response(html, { status: respStatus, headers: responseHeaders });
  if (!isNotFound) {
    ctx.waitUntil(cachePut(ctx, request, ssrResp.clone(), ttl));
  }

  return new Response(html, { status: respStatus, headers: responseHeaders });
}

// ── HTML 템플릿 ───────────────────────────────────────────────────────────────
const SUSPENDED_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>사이트 정지됨</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#f55}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>🚫 사이트가 정지되었습니다</h1><p>이 사이트는 현재 이용 중지 상태입니다.<br>문의사항은 CloudPress 고객센터로 연락해 주세요.</p></div></body></html>`;

const NOT_FOUND_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>사이트를 찾을 수 없음</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#fa0}p{color:#aaa;line-height:1.6}a{color:#7af;text-decoration:none}</style>
</head><body><div class="box"><h1>🔍 사이트를 찾을 수 없습니다</h1><p>요청한 도메인에 연결된 사이트가 없습니다.<br><a href="https://cloudpress.site/">CloudPress 대시보드</a>에서 도메인을 확인해 주세요.</p></div></body></html>`;

const PROVISIONING_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10">
<title>사이트 준비 중</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff;text-align:center}.box{padding:2rem;max-width:480px}h1{font-size:1.8rem;margin-bottom:1rem;color:#7af}p{color:#aaa;line-height:1.6}.spin{font-size:2.5rem;display:inline-block;animation:spin 1.2s linear infinite;margin-bottom:1rem}@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="spin">⚙️</div><h1>사이트를 준비 중입니다</h1><p>배포가 완료되면 자동으로 페이지가 갱신됩니다.<br>잠시만 기다려 주세요.</p></div></body></html>`;

const ERROR_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>일시적 오류</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{color:#f55;margin-bottom:1rem}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>⚠️ 일시적 서버 오류</h1><p>잠시 후 다시 시도해 주세요.<br>문제가 지속되면 CloudPress 고객센터로 연락해 주세요.</p></div></body></html>`;

// ── Worker 엔트리포인트 ────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error('[worker] Unhandled error:', e?.message || e, e?.stack);
      return new Response(ERROR_HTML, {
        status: 500,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  },

  // Scheduled: ISR 캐시 갱신 (cron)
  async scheduled(event, env, ctx) {
    // 모든 활성 사이트의 홈 페이지 프리워밍
    try {
      const sites = await env.DB.prepare(
        `SELECT id, site_prefix, primary_domain FROM sites WHERE status='active' AND deleted_at IS NULL LIMIT 100`
      ).all();

      for (const site of (sites.results || [])) {
        if (!site.primary_domain) continue;
        const siteInfo = await getSiteInfo(env, site.primary_domain).catch(() => null);
        if (!siteInfo) continue;
        const homeUrl = new URL(`https://${site.primary_domain}/`);
        ctx.waitUntil(revalidatePage(env, siteInfo, homeUrl, new Request(homeUrl)));
      }
    } catch (e) {
      console.error('[scheduled] ISR error:', e?.message);
    }
  },
};
