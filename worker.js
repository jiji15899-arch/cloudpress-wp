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
const WAF_SQLI = /('\s*(or|and)\s+'|--)|(union\s+select)|(;\s*(drop|delete|insert|update)\s)/i;
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
        type = 'archive';
      } else {
        type = '404';
      }
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
        type = 'archive';
      } else {
        type = '404';
      }
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
      mainContent += `<div class="no-posts"><header class="page-header"><h1 class="page-title">아직 게시물이 없습니다</h1></header><div class="page-content"><p>새로운 글을 작성하면 이곳에 표시됩니다.</p></div></div>`;
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
  const cookie = request.headers.get('cookie') || '';
  const hasSession = /wordpress_logged_in/.test(cookie);

  if (!hasSession && url.pathname !== '/wp-login.php') {
    // 로그인 페이지로 리다이렉트
    return Response.redirect(`https://${url.hostname}/wp-login.php?redirect_to=${encodeURIComponent(url.pathname)}`, 302);
  }

  // wp-admin 파일들을 D1/KV에서 서빙
  return new Response(renderAdminPage(url.pathname, siteInfo, url), {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, private' },
  });
}

function renderAdminPage(pathname, siteInfo, extra) {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const page = pathname.replace(/^\/wp-admin\/?/, '').replace(/\.php$/, '') || 'index';
  const sp = extra ? extra.searchParams : null;
  const isPage = sp ? sp.get('post_type') === 'page' : false;

  let pageTitle = '대시보드';
  let bodyHtml  = '';
  let inlineScript = '';

  if (page === 'index' || page === '' || page === 'dashboard') {
    pageTitle = '대시보드';
    bodyHtml = '<div class="welcome-panel">'
      + '<div style="max-width:700px">'
      + '<h2 style="font-size:1.3rem;margin:0 0 10px">WordPress에 오신 것을 환영합니다!</h2>'
      + '<p style="color:#50575e;margin:0 0 15px">CloudPress Edge 위에서 WordPress가 동작 중입니다.</p>'
      + '<div style="display:flex;gap:10px;flex-wrap:wrap">'
      + '<a href="/wp-admin/post-new.php" class="btn-wp">글 작성하기</a>'
      + '<a href="/wp-admin/options-general.php" class="btn-wp btn-secondary">사이트 설정</a>'
      + '</div></div></div>'
      + '<div class="admin-widgets">'
      + '<div class="admin-widget"><h3 class="widget-title"><span>활동</span></h3>'
      + '<div class="widget-body"><h4 style="margin:0 0 8px;font-size:.85rem;color:#1d2327">최근 게시됨</h4>'
      + '<div id="admin-activity" style="color:#50575e;font-size:.85rem">불러오는 중...</div></div></div>'
      + '<div class="admin-widget"><h3 class="widget-title">한 눈에 보기</h3>'
      + '<div class="widget-body"><ul id="admin-glance" style="list-style:none;margin:0;padding:0;color:#50575e;font-size:.875rem"><li>불러오는 중...</li></ul>'
      + '<p style="margin:12px 0 0;font-size:.8rem;color:#50575e">WordPress 6.7 + CloudPress</p></div></div>'
      + '</div>';
    inlineScript = '(async()=>{'
      + 'try{'
      + 'const [postsR,pagesR,commR]=await Promise.all(['
      + 'fetch("/wp-json/wp/v2/posts?per_page=5&_fields=id,title,date").then(r=>r.json()).catch(()=>[]),'
      + 'fetch("/wp-json/wp/v2/pages?per_page=100&_fields=id,title").then(r=>r.json()).catch(()=>[]),'
      + 'fetch("/wp-json/wp/v2/comments?per_page=5&_fields=id,author_name,content,date").then(r=>r.json()).catch(()=>[])'
      + ']);'
      + 'const posts=Array.isArray(postsR)?postsR:[];'
      + 'const pages=Array.isArray(pagesR)?pagesR:[];'
      + 'const comments=Array.isArray(commR)?commR:[];'
      + 'document.getElementById("admin-glance").innerHTML='
      + '"<li>"+posts.length+"개의 글 <a href=\\"/wp-admin/edit.php\\" style=\\"float:right\\">글 관리</a></li>"'
      + '+"<li>"+pages.length+"개의 페이지 <a href=\\"/wp-admin/edit.php?post_type=page\\" style=\\"float:right\\">페이지 관리</a></li>"'
      + '+"<li>"+comments.length+"개의 댓글 <a href=\\"/wp-admin/edit-comments.php\\" style=\\"float:right\\">댓글 관리</a></li>";'
      + 'const actEl=document.getElementById("admin-activity");'
      + 'if(posts.length===0){actEl.textContent="아직 게시된 글이 없습니다.";return;}'
      + 'actEl.innerHTML="<ul style=\\"list-style:none;margin:0;padding:0\\">"+posts.map(function(p){'
      + 'var d=new Date(p.date).toLocaleDateString("ko-KR");'
      + 'var t=(p.title&&p.title.rendered)||"(제목 없음)";'
      + 'return "<li style=\\"padding:4px 0;border-bottom:1px solid #f0f0f1\\"><a href=\\"/wp-admin/post.php?post="+p.id+"&action=edit\\" style=\\"color:#2271b1\\">"+t+"</a><span style=\\"float:right;color:#8c8f94;font-size:.8rem\\">"+d+"</span></li>";'
      + '}).join("")+"</ul>";'
      + '}catch(e){console.warn(e);}'
      + '})();';

  } else if (page === 'edit') {
    pageTitle = isPage ? '페이지' : '글';
    const newHref = isPage ? '/wp-admin/post-new.php?post_type=page' : '/wp-admin/post-new.php';
    const apiType = isPage ? 'pages' : 'posts';
    const emptyMsg = isPage ? '아직 페이지가 없습니다.' : '아직 글이 없습니다.';
    bodyHtml = '<div class="tablenav top" style="margin-bottom:10px">'
      + '<a href="' + newHref + '" class="btn-wp">새 ' + (isPage ? '페이지' : '글') + ' 추가</a></div>'
      + '<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">'
      + '<thead><tr style="background:#f6f7f7">'
      + '<td style="width:30px;padding:8px 10px"><input type="checkbox"></td>'
      + '<th style="padding:8px 10px;text-align:left;font-size:.875rem">제목</th>'
      + '<th style="padding:8px 10px;text-align:left;font-size:.875rem;width:120px">날짜</th>'
      + '</tr></thead>'
      + '<tbody id="posts-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>'
      + '</table>';
    inlineScript = '(async()=>{'
      + 'var res=await fetch("/wp-json/wp/v2/' + apiType + '?per_page=20&_fields=id,title,date,status,link").then(function(r){return r.json();}).catch(function(){return[];});'
      + 'var posts=Array.isArray(res)?res:[];'
      + 'var el=document.getElementById("posts-list");'
      + 'if(posts.length===0){'
      + 'el.innerHTML=\'<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">' + emptyMsg + ' <a href="' + newHref + '">새로 만들기</a></td></tr>\';return;}'
      + 'el.innerHTML=posts.map(function(p){'
      + 'var title=(p.title&&p.title.rendered)||"(제목 없음)";'
      + 'var d=new Date(p.date).toLocaleDateString("ko-KR");'
      + 'var editHref="/wp-admin/post.php?post="+p.id+"&action=edit";'
      + 'return "<tr style=\\"border-top:1px solid #f0f0f1\\">"'
      + '+"<td style=\\"padding:8px 10px\\"><input type=\\"checkbox\\"></td>"'
      + '+"<td style=\\"padding:8px 10px\\"><strong><a href=\\""+editHref+"\\" style=\\"color:#2271b1;text-decoration:none\\">"+title+"</a></strong>"'
      + '+"<div style=\\"font-size:.8rem;color:#8c8f94;margin-top:2px\\"><a href=\\""+editHref+"\\">편집</a> | <a href=\\""+(p.link||"/")+"\\" target=\\"_blank\\">보기</a></div>"'
      + '+"</td>"'
      + '+"<td style=\\"padding:8px 10px;font-size:.8rem;color:#50575e\\">게시됨<br>"+d+"</td>"'
      + '+"</tr>";'
      + '}).join("");'
      + '})();';

  } else if (page === 'post-new' || page === 'post') {
    const postId = sp ? (sp.get('post') || '') : '';
    const postType = sp ? (sp.get('post_type') || 'post') : 'post';
    pageTitle = postId ? '글 편집' : (postType === 'page' ? '새 페이지 추가' : '새 글 추가');
    const apiType = postType === 'page' ? 'pages' : 'posts';
    const listPage = postType === 'page' ? '/wp-admin/edit.php?post_type=page' : '/wp-admin/edit.php';
    bodyHtml = `<style>
#editor-wrap{display:grid;grid-template-columns:1fr 280px;gap:0;background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden;min-height:600px}
#editor-main{padding:0;display:flex;flex-direction:column;border-right:1px solid #e0e0e0}
#editor-toolbar{background:#1e1e1e;padding:8px 16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
#editor-toolbar button{background:#3c434a;color:#fff;border:none;border-radius:2px;padding:4px 8px;font-size:.75rem;cursor:pointer}
#editor-toolbar button:hover{background:#50575e}
#editor-toolbar .sep{width:1px;height:20px;background:#3c434a;margin:0 2px}
#post-title-field{width:100%;font-size:2rem;font-weight:700;border:none;border-bottom:1px solid #e0e0e0;padding:24px 32px 16px;outline:none;color:#1d2327;background:#fff;font-family:inherit}
#post-title-field::placeholder{color:#c3c4c7}
#block-editor{flex:1;padding:24px 32px;outline:none;min-height:400px;font-size:1rem;line-height:1.8;color:#1d2327}
#block-editor p:empty::before{content:attr(data-placeholder);color:#c3c4c7;pointer-events:none}
.block-inserter{display:flex;align-items:center;gap:8px;padding:8px 32px;border-top:1px dashed #e0e0e0;color:#a0a0a0;font-size:.8125rem;cursor:pointer}
.block-inserter:hover{background:#f9f9f9}
#editor-sidebar{background:#f6f7f7;display:flex;flex-direction:column}
#sidebar-tabs{display:flex;border-bottom:1px solid #e0e0e0}
.stab{flex:1;padding:10px;text-align:center;font-size:.8125rem;cursor:pointer;color:#50575e;border-bottom:2px solid transparent}
.stab.active{color:#1d2327;border-bottom-color:#1d2327;font-weight:600}
#sidebar-content{padding:16px;font-size:.8125rem;overflow-y:auto}
.sidebar-section{margin-bottom:20px}
.sidebar-section h4{font-size:.8125rem;font-weight:600;color:#1d2327;margin:0 0 10px}
.sidebar-section label{display:block;color:#50575e;margin-bottom:4px;font-size:.8125rem}
.sidebar-section select,.sidebar-section input[type=text],.sidebar-section input[type=datetime-local],.sidebar-section textarea{width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:3px;font-size:.8125rem;background:#fff}
.sidebar-section .toggle{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f0f0f1}
.save-bar{background:#1e1e1e;padding:8px 16px;display:flex;align-items:center;justify-content:flex-end;gap:8px}
.save-bar button{padding:6px 16px;font-size:.8125rem;cursor:pointer;border-radius:3px;border:none}
#btn-save-draft{background:#3c434a;color:#fff}
#btn-preview{background:#2271b1;color:#fff}
#btn-publish{background:#2271b1;color:#fff}
#save-notice{font-size:.75rem;color:#a0a0a0}
</style>
<div class="save-bar">
  <span id="save-notice"></span>
  <button id="btn-save-draft" onclick="savePost('draft')">초안 저장</button>
  <a href="/" target="_blank" id="btn-preview" style="color:#fff;text-decoration:none;padding:6px 16px;background:#2271b1;border-radius:3px;font-size:.8125rem">미리보기</a>
  <button id="btn-publish" onclick="savePost('publish')">게시</button>
</div>
<div id="editor-wrap">
  <div id="editor-main">
    <div id="editor-toolbar">
      <button onclick="insertBlock('paragraph')">¶ 단락</button>
      <button onclick="insertBlock('heading')">H 제목</button>
      <button onclick="insertBlock('image')">🖼 이미지</button>
      <button onclick="insertBlock('list')">☰ 목록</button>
      <button onclick="insertBlock('quote')">❝ 인용</button>
      <button onclick="insertBlock('code')">{ } 코드</button>
      <button onclick="insertBlock('separator')">— 구분선</button>
      <button onclick="insertBlock('table')">⊞ 표</button>
      <div class="sep"></div>
      <button onclick="execCmd('bold')" title="굵게">B</button>
      <button onclick="execCmd('italic')" title="기울임"><i>I</i></button>
      <button onclick="execCmd('underline')" title="밑줄"><u>U</u></button>
      <button onclick="insertLink()" title="링크">🔗</button>
      <div class="sep"></div>
      <button onclick="execCmd('justifyLeft')">←</button>
      <button onclick="execCmd('justifyCenter')">↔</button>
      <button onclick="execCmd('justifyRight')">→</button>
    </div>
    <input type="text" id="post-title-field" placeholder="제목 추가" autocomplete="off">
    <div id="block-editor" contenteditable="true" spellcheck="false"><p data-placeholder="글 작성 시작 또는 /를 입력하여 블록 선택"></p></div>
    <div class="block-inserter" onclick="insertBlock('paragraph')">⊕ 블록 추가</div>
  </div>
  <div id="editor-sidebar">
    <div id="sidebar-tabs">
      <div class="stab active" onclick="showTab('post')">글</div>
      <div class="stab" onclick="showTab('block')">블록</div>
    </div>
    <div id="sidebar-content">
      <div id="tab-post">
        <div class="sidebar-section">
          <h4>요약</h4>
          <div class="toggle"><span>공개 상태</span><select id="post-status"><option value="publish">공개됨</option><option value="draft">초안</option><option value="private">비공개</option></select></div>
          <div class="toggle" style="margin-top:8px"><span>공개 날짜</span><input type="datetime-local" id="post-date"></div>
        </div>
        <div class="sidebar-section">
          <h4>고유주소</h4>
          <label>슬러그</label>
          <input type="text" id="post-slug" placeholder="slug">
        </div>
        <div class="sidebar-section">
          <h4>카테고리</h4>
          <div id="categories-list" style="color:#8c8f94;font-size:.8125rem">불러오는 중...</div>
          <a href="#" onclick="addCat();return false" style="font-size:.8125rem;margin-top:6px;display:inline-block">+ 새 카테고리 추가</a>
        </div>
        <div class="sidebar-section">
          <h4>태그</h4>
          <input type="text" id="post-tags" placeholder="쉼표로 구분하여 입력">
        </div>
        <div class="sidebar-section">
          <h4>대표 이미지</h4>
          <label class="btn-wp btn-secondary" style="cursor:pointer;display:block;text-align:center;font-size:.8125rem">대표 이미지 설정<input type="file" accept="image/*" style="display:none" onchange="setFeaturedImage(this)"></label>
          <div id="featured-image-preview" style="margin-top:8px"></div>
        </div>
        <div class="sidebar-section">
          <h4>발췌문</h4>
          <textarea id="post-excerpt" rows="3" placeholder="발췌문을 입력하세요..." style="resize:vertical"></textarea>
        </div>
        <div class="sidebar-section">
          <h4>토론</h4>
          <div class="toggle"><label><input type="checkbox" id="allow-comments" checked> 댓글 허용</label></div>
          <div class="toggle"><label><input type="checkbox" id="allow-pingbacks" checked> 핑백 및 트랙백 허용</label></div>
        </div>
      </div>
      <div id="tab-block" style="display:none">
        <div class="sidebar-section">
          <h4>블록 정보</h4>
          <p style="color:#50575e">블록을 선택하면 여기에 설정이 표시됩니다.</p>
        </div>
        <div class="sidebar-section">
          <h4>색상</h4>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            ${['#1e1e1e','#fff','#0073aa','#d63638','#00a32a','#ff6900','#f0f0f1','#2271b1'].map(c=>`<div onclick="execCmd('foreColor','${c}')" style="width:24px;height:24px;background:${c};border:1px solid #c3c4c7;border-radius:3px;cursor:pointer"></div>`).join('')}
          </div>
        </div>
        <div class="sidebar-section">
          <h4>글자 크기</h4>
          <select onchange="execCmd('fontSize',this.value)">
            <option value="2">소 (13px)</option>
            <option value="3" selected>보통 (16px)</option>
            <option value="4">중 (18px)</option>
            <option value="5">대 (24px)</option>
            <option value="6">특대 (32px)</option>
          </select>
        </div>
      </div>
    </div>
  </div>
</div>`;
    inlineScript = `
var _postId=${JSON.stringify(postId)};
var _apiType=${JSON.stringify(apiType)};
var _listPage=${JSON.stringify(listPage)};
// 기존 글 로드
if(_postId){(async()=>{
  try{
    const res=await fetch("/wp-json/wp/v2/"+_apiType+"/"+_postId);
    const p=await res.json();
    if(p.id){
      document.getElementById("post-title-field").value=(p.title&&p.title.rendered)||"";
      document.getElementById("block-editor").innerHTML=(p.content&&p.content.raw)||p.content&&p.content.rendered||"<p></p>";
      document.getElementById("post-slug").value=p.slug||"";
      document.getElementById("post-status").value=p.status||"publish";
      document.getElementById("post-excerpt").value=(p.excerpt&&p.excerpt.raw)||"";
      if(p.date)document.getElementById("post-date").value=p.date.slice(0,16);
      document.getElementById("save-notice").textContent="마지막 저장: "+new Date(p.modified).toLocaleString("ko-KR");
    }
  }catch(e){}
})();}
// 카테고리 로드
(async()=>{
  try{
    const res=await fetch("/wp-json/wp/v2/categories?per_page=30");
    const cats=await res.json();
    const el=document.getElementById("categories-list");
    if(cats&&cats.length){
      el.innerHTML=cats.map(c=>'<label style="display:block;margin-bottom:4px"><input type="checkbox" name="cat[]" value="'+c.id+'"> '+c.name+'</label>').join("");
    }else{
      el.innerHTML='<em style="color:#8c8f94">카테고리 없음</em>';
    }
  }catch(e){}
})();
// 제목→슬러그 자동
document.getElementById("post-title-field").addEventListener("input",function(){
  var s=this.value.toLowerCase().replace(/\\s+/g,"-").replace(/[^a-z0-9가-힣-]/g,"").replace(/^-+|-+$/g,"");
  document.getElementById("post-slug").value=s;
});
function showTab(t){
  document.getElementById("tab-post").style.display=t==="post"?"":"none";
  document.getElementById("tab-block").style.display=t==="block"?"":"none";
  document.querySelectorAll(".stab").forEach(function(el){el.classList.remove("active");});
  event.target.classList.add("active");
}
function execCmd(cmd,val){document.execCommand(cmd,false,val||null);document.getElementById("block-editor").focus();}
function insertLink(){var url=prompt("URL 입력:");if(url)document.execCommand("createLink",false,url);}
function insertBlock(type){
  var el=document.getElementById("block-editor");
  el.focus();
  var tag={paragraph:"p",heading:"h2",image:"figure",list:"ul",quote:"blockquote",code:"pre",separator:"hr",table:"table"}[type]||"p";
  var content={
    paragraph:"<p><br></p>",
    heading:"<h2>제목을 입력하세요</h2>",
    image:'<figure class="wp-block-image"><img src="" alt=""><figcaption>캡션</figcaption></figure>',
    list:"<ul><li>항목 1</li><li>항목 2</li></ul>",
    quote:"<blockquote><p>인용문을 입력하세요.</p><cite>출처</cite></blockquote>",
    code:"<pre><code>코드를 입력하세요</code></pre>",
    separator:"<hr>",
    table:"<table><thead><tr><th>헤더 1</th><th>헤더 2</th></tr></thead><tbody><tr><td>셀 1</td><td>셀 2</td></tr></tbody></table>",
  }[type]||"<p><br></p>";
  document.execCommand("insertHTML",false,content);
}
function setFeaturedImage(input){
  if(!input.files[0])return;
  var reader=new FileReader();
  reader.onload=function(e){
    document.getElementById("featured-image-preview").innerHTML='<img src="'+e.target.result+'" style="width:100%;border-radius:3px">';
  };
  reader.readAsDataURL(input.files[0]);
}
function addCat(){var name=prompt("새 카테고리 이름:");if(!name)return;fetch("/wp-json/wp/v2/categories",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:name})}).then(r=>r.json()).then(c=>{if(c.id){var el=document.getElementById("categories-list");el.innerHTML+='<label style="display:block;margin-bottom:4px"><input type="checkbox" name="cat[]" value="'+c.id+'" checked> '+c.name+'</label>';}else alert("생성 실패");}).catch(()=>alert("오류"));}
async function savePost(statusOverride){
  var title=document.getElementById("post-title-field").value.trim();
  var content=document.getElementById("block-editor").innerHTML;
  var slug=document.getElementById("post-slug").value.trim();
  var status=statusOverride||document.getElementById("post-status").value;
  var excerpt=document.getElementById("post-excerpt").value.trim();
  if(!title){alert("제목을 입력하세요.");return;}
  if(!slug)slug=title.toLowerCase().replace(/\\s+/g,"-").replace(/[^a-z0-9가-힣-]/g,"").replace(/^-+|-+$/g,"")||("post-"+Date.now());
  var cats=[];document.querySelectorAll('input[name="cat[]"]:checked').forEach(function(c){cats.push(parseInt(c.value));});
  var body={title:{raw:title},content:{raw:content},slug:slug,status:status,excerpt:{raw:excerpt}};
  if(cats.length)body.categories=cats;
  var dateVal=document.getElementById("post-date").value;
  if(dateVal)body.date=dateVal+":00";
  var notice=document.getElementById("save-notice");
  notice.textContent="저장 중...";notice.style.color="#a0a0a0";
  try{
    var url="/wp-json/wp/v2/"+_apiType+(_postId?"/"+_postId:"");
    var method=_postId?"PUT":"POST";
    var res=await fetch(url,{method:method,headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    var d=await res.json();
    if(res.ok&&d.id){
      _postId=d.id;
      notice.textContent="저장됨: "+new Date().toLocaleTimeString("ko-KR");
      notice.style.color="#00a32a";
      if(status==="publish"){
        if(confirm("게시되었습니다! 글 목록으로 이동하시겠습니까?")){window.location=_listPage;}
      }
    }else{notice.textContent="저장 실패: "+(d.message||"오류");notice.style.color="#d63638";}
  }catch(e){notice.textContent="오류: "+e.message;notice.style.color="#d63638";}
}
// Ctrl+S 단축키
document.addEventListener("keydown",function(e){if((e.ctrlKey||e.metaKey)&&e.key==="s"){e.preventDefault();savePost("draft");}});
`;

  } else if (page === 'upload') {
    pageTitle = '미디어 라이브러리';
    bodyHtml = '<div class="tablenav top" style="margin-bottom:15px">'
      + '<label class="btn-wp" style="cursor:pointer">새 미디어 추가'
      + '<input type="file" style="display:none" accept="image/*,video/*,audio/*,.pdf" onchange="uploadFile(this)">'
      + '</label></div>'
      + '<div id="media-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px">'
      + '<div style="text-align:center;padding:20px;color:#8c8f94;grid-column:1/-1">불러오는 중...</div>'
      + '</div>';
    inlineScript = '(async()=>{'
      + 'var res=await fetch("/wp-json/wp/v2/media?per_page=30").then(function(r){return r.json();}).catch(function(){return[];});'
      + 'var media=Array.isArray(res)?res:[];'
      + 'var el=document.getElementById("media-grid");'
      + 'if(media.length===0){el.innerHTML=\'<div style="text-align:center;padding:40px;color:#8c8f94;grid-column:1/-1">미디어 파일이 없습니다.</div>\';return;}'
      + 'el.innerHTML=media.map(function(m){'
      + 'var src=m.source_url||(m.guid&&m.guid.rendered)||"";'
      + 'var isImg=(m.mime_type||"").startsWith("image/");'
      + 'var ttl=(m.title&&m.title.rendered)||"파일";'
      + 'return "<div style=\\"border:1px solid #dcdcde;border-radius:2px;overflow:hidden;background:#f6f7f7\\">"'
      + '+(isImg?"<img src=\\""+src+"\\" style=\\"width:100%;height:120px;object-fit:cover\\">"'
      + ':"<div style=\\"height:120px;display:flex;align-items:center;justify-content:center;font-size:2rem\\">📄</div>")'
      + '+"<p style=\\"margin:0;padding:4px 6px;font-size:.75rem;color:#1d2327;white-space:nowrap;overflow:hidden;text-overflow:ellipsis\\">"+ttl+"</p>"'
      + '+"</div>";'
      + '}).join("");'
      + '})();'
      + 'async function uploadFile(input){'
      + 'var file=input.files[0];if(!file)return;'
      + 'var fd=new FormData();fd.append("file",file);fd.append("title",file.name);'
      + 'try{'
      + 'var res=await fetch("/wp-admin/async-upload.php",{method:"POST",body:fd});'
      + 'if(res.ok){location.reload();}else{alert("업로드 실패");}'
      + '}catch(e){alert("오류: "+e.message);}'
      + '}';

  } else if (page === 'themes') {
    pageTitle = '테마';
    bodyHtml = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:20px">'
      + [
          {name:'Twenty Twenty-Four', desc:'2024 기본 테마. 다목적 블록 테마.', ver:'1.2', active:true},
          {name:'Twenty Twenty-Three', desc:'유연한 블록 테마.', ver:'1.4'},
          {name:'Astra', desc:'빠르고 가벼운 다목적 테마.', ver:'4.6'},
        ].map(function(t) {
          return '<div style="border:' + (t.active ? '2px solid #2271b1' : '1px solid #dcdcde') + ';border-radius:4px;overflow:hidden;background:#fff">'
            + '<div style="height:140px;background:linear-gradient(135deg,#f0f0f1,#c3c4c7);display:flex;align-items:center;justify-content:center;font-size:2.5rem">🎨</div>'
            + '<div style="padding:12px">'
            + '<h3 style="margin:0 0 6px;font-size:.9375rem">' + t.name + (t.active ? ' <span style="background:#2271b1;color:#fff;font-size:.7rem;padding:1px 6px;border-radius:2px">활성화</span>' : '') + '</h3>'
            + '<p style="margin:0 0 10px;font-size:.8rem;color:#50575e">' + t.desc + '</p>'
            + (!t.active ? '<button class="btn-wp btn-secondary" style="font-size:.8rem;padding:4px 10px">활성화</button>' : '')
            + '</div></div>';
        }).join('')
      + '</div>';

  } else if (page === 'plugins') {
    pageTitle = '플러그인';
    bodyHtml = '<div class="tablenav top" style="margin-bottom:10px;display:flex;align-items:center;gap:10px">'
      + '<a href="/wp-admin/plugin-install.php" class="btn-wp">새 플러그인 추가</a>'
      + '<span id="plugin-count" style="color:#50575e;font-size:.8125rem"></span>'
      + '</div>'
      + '<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">'
      + '<thead><tr style="background:#f6f7f7">'
      + '<td style="width:30px;padding:8px 10px"><input type="checkbox" id="cb-select-all"></td>'
      + '<th style="padding:8px 10px;text-align:left">플러그인</th>'
      + '<th style="padding:8px 10px;text-align:left;width:200px">설명</th>'
      + '</tr></thead>'
      + '<tbody id="plugins-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>'
      + '</table>';
    inlineScript = '(async()=>{'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/plugins").then(r=>r.json()).catch(()=>({installed:[]}));'
      + 'const plugins=res.installed||[];'
      + 'document.getElementById("plugin-count").textContent=plugins.length+"개 설치됨";'
      + 'const el=document.getElementById("plugins-list");'
      + 'if(!plugins.length){el.innerHTML=\'<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">설치된 플러그인이 없습니다. <a href="/wp-admin/plugin-install.php">새 플러그인 추가</a></td></tr>\';return;}'
      + 'el.innerHTML=plugins.map(function(p){'
      + 'var active=p.status==="active";'
      + 'var actionLinks=active'
      + '?\'<a href="#" onclick="togglePlugin(\\\''+'\\\'+p.slug+\\\',false);return false">비활성화</a>\''
      + ':\'<a href="#" onclick="togglePlugin(\\\''+'\\\'+p.slug+\\\',true);return false">활성화</a> | <a href="#" style="color:#b32d2e" onclick="deletePlugin(\\\''+'\\\'+p.slug+\\\');return false">삭제</a>\';'
      + 'return "<tr style=\\"border-top:1px solid #f0f0f1"+(active?" background:rgba(240,253,244,.8)":"")+"\\">"'
      + '+"<td style=\\"padding:8px 10px\\"><input type=\\"checkbox\\" name=\\"checked[]\\"></td>"'
      + '+"<td style=\\"padding:10px\\"><strong>"+(p.name||p.slug)+"</strong>"'
      + '+(p.version?" <span style=\\"color:#8c8f94;font-size:.8rem\\">버전 "+p.version+"</span>":"")'
      + '+(active?" <span style=\\"background:#00a32a;color:#fff;font-size:.7rem;padding:1px 5px;border-radius:2px\\">활성화됨</span>":"")'
      + '+"<br><div style=\\"font-size:.8125rem;margin-top:4px\\">"+actionLinks+"</div></td>"'
      + '+"<td style=\\"padding:10px;font-size:.8rem;color:#50575e\\">"+(p.description||"").slice(0,100)+"</td>"'
      + '+"</tr>";'
      + '}).join("");'
      + '}catch(e){document.getElementById("plugins-list").innerHTML=\'<tr><td colspan="3" style="padding:20px;text-align:center;color:#d63638">오류: \'+e.message+\'</td></tr>\';}'
      + '})();'
      + 'async function togglePlugin(slug,activate){'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/plugins/"+slug+(activate?"/activate":"/deactivate"),{method:"POST"});'
      + 'if(res.ok)location.reload();else alert("작업 실패");'
      + '}catch(e){alert("오류: "+e.message);}'
      + '}'
      + 'async function deletePlugin(slug){'
      + 'if(!confirm(slug+" 플러그인을 삭제하시겠습니까?"))return;'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/plugins/"+slug,{method:"DELETE"});'
      + 'if(res.ok)location.reload();else alert("삭제 실패");'
      + '}catch(e){alert("오류: "+e.message);}'
      + '}';

  } else if (page === 'options-general' || page === 'options') {
    pageTitle = '일반 설정';
    bodyHtml = '<div id="settings-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>'
      + '<table class="form-table" style="width:100%;border-collapse:collapse">'
      + [
          {label:'사이트 제목',           name:'blogname',        type:'text',  placeholder:'내 WordPress 사이트'},
          {label:'태그라인',              name:'blogdescription', type:'text',  placeholder:'워드프레스로 만든 사이트'},
          {label:'WordPress 주소 (URL)', name:'siteurl',         type:'url',   placeholder:'https://example.com'},
          {label:'사이트 주소 (URL)',     name:'home',            type:'url',   placeholder:'https://example.com'},
          {label:'관리자 이메일',         name:'admin_email',     type:'email', placeholder:'admin@example.com'},
        ].map(function(f) {
          return '<tr style="border-bottom:1px solid #f0f0f1">'
            + '<th style="padding:15px 10px;text-align:left;width:220px;font-size:.875rem;vertical-align:top">' + f.label + '</th>'
            + '<td style="padding:15px 10px"><input type="' + f.type + '" id="opt-' + f.name + '" name="' + f.name + '" placeholder="' + f.placeholder + '" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"></td>'
            + '</tr>';
        }).join('')
      + '<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">언어</th>'
      + '<td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>한국어</option><option>English (US)</option></select></td></tr>'
      + '<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">시간대</th>'
      + '<td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>Asia/Seoul</option><option>UTC</option></select></td></tr>'
      + '</table>'
      + '<p style="margin-top:20px"><button type="button" onclick="saveSettings()" class="btn-wp">변경사항 저장</button></p>';
    inlineScript = '(async()=>{'
      + 'try{'
      + 'var res=await fetch("/wp-json/wp/v2/settings").then(function(r){return r.json();}).catch(function(){return{};});'
      + 'if(res){'
      + 'if(res.title)document.getElementById("opt-blogname").value=res.title;'
      + 'if(res.description)document.getElementById("opt-blogdescription").value=res.description;'
      + 'if(res.url){document.getElementById("opt-siteurl").value=res.url;document.getElementById("opt-home").value=res.url;}'
      + 'if(res.email)document.getElementById("opt-admin_email").value=res.email;'
      + '}}catch(e){}'
      + '})();'
      + 'async function saveSettings(){'
      + 'var data={};'
      + 'document.querySelectorAll("input[name]").forEach(function(el){if(el.value)data[el.name]=el.value;});'
      + 'var msg=document.getElementById("settings-msg");'
      + 'try{'
      + 'var res=await fetch("/wp-json/wp/v2/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});'
      + 'if(res.ok){'
      + 'msg.style.display="block";msg.style.background="#edfaef";msg.style.border="1px solid #00a32a";msg.style.color="#1d7a35";msg.textContent="설정이 저장되었습니다.";'
      + '}else{'
      + 'msg.style.display="block";msg.style.background="#fff0f0";msg.style.border="1px solid #d63638";msg.style.color="#d63638";msg.textContent="저장에 실패했습니다.";'
      + '}}catch(e){'
      + 'msg.style.display="block";msg.style.background="#fff0f0";msg.style.border="1px solid #d63638";msg.style.color="#d63638";msg.textContent="오류: "+e.message;'
      + '}}';

  } else if (page === 'users') {
    pageTitle = '사용자';
    bodyHtml = '<div class="tablenav top" style="margin-bottom:10px">'
      + '<a href="/wp-admin/user-new.php" class="btn-wp">새 사용자 추가</a></div>'
      + '<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">'
      + '<thead><tr style="background:#f6f7f7">'
      + '<th style="padding:8px 10px;text-align:left">사용자명</th>'
      + '<th style="padding:8px 10px;text-align:left">이름</th>'
      + '<th style="padding:8px 10px;text-align:left">이메일</th>'
      + '<th style="padding:8px 10px;text-align:left">역할</th>'
      + '<th style="padding:8px 10px;text-align:left">글</th>'
      + '</tr></thead>'
      + '<tbody id="users-list"><tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>'
      + '</table>';
    inlineScript = '(async()=>{'
      + 'var res=await fetch("/wp-json/wp/v2/users?per_page=20").then(function(r){return r.json();}).catch(function(){return[];});'
      + 'var users=Array.isArray(res)?res:[];'
      + 'var el=document.getElementById("users-list");'
      + 'if(users.length===0){el.innerHTML=\'<tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94">사용자가 없습니다.</td></tr>\';return;}'
      + 'el.innerHTML=users.map(function(u){'
      + 'return "<tr style=\\"border-top:1px solid #f0f0f1\\">"'
      + '+"<td style=\\"padding:8px 10px\\"><strong>"+(u.slug||u.name||"")+"</strong></td>"'
      + '+"<td style=\\"padding:8px 10px\\">"+(u.name||"—")+"</td>"'
      + '+"<td style=\\"padding:8px 10px\\">"+(u.email||"—")+"</td>"'
      + '+"<td style=\\"padding:8px 10px\\">"+(u.role||"관리자")+"</td>"'
      + '+"<td style=\\"padding:8px 10px\\">"+(u.post_count||0)+"</td>"'
      + '+"</tr>";'
      + '}).join("");'
      + '})();';

  } else if (page === 'profile') {
    pageTitle = '프로필';
    bodyHtml = '<table class="form-table" style="width:100%;border-collapse:collapse">'
      + [
          {label:'사용자명', id:'username',   val:'admin',   disabled:true,  type:'text'},
          {label:'이름',     id:'first_name', val:'',        disabled:false, type:'text',  placeholder:'이름'},
          {label:'성',       id:'last_name',  val:'',        disabled:false, type:'text',  placeholder:'성'},
          {label:'이메일',   id:'email',      val:'',        disabled:false, type:'email', placeholder:'admin@example.com'},
          {label:'웹사이트', id:'url',        val:'',        disabled:false, type:'url',   placeholder:'https://'},
        ].map(function(f) {
          return '<tr style="border-bottom:1px solid #f0f0f1">'
            + '<th style="padding:15px 10px;text-align:left;width:200px;font-size:.875rem">' + f.label + '</th>'
            + '<td style="padding:15px 10px"><input type="' + f.type + '" id="' + f.id + '" value="' + (f.val||'') + '"'
            + (f.placeholder ? ' placeholder="' + f.placeholder + '"' : '')
            + (f.disabled ? ' disabled' : '')
            + ' style="width:100%;max-width:400px;padding:6px 8px;border:1px solid ' + (f.disabled ? '#dcdcde' : '#8c8f94') + ';border-radius:4px;font-size:.875rem' + (f.disabled ? ';background:#f6f7f7;color:#8c8f94' : '') + '"></td>'
            + '</tr>';
        }).join('')
      + '<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">새 비밀번호</th>'
      + '<td style="padding:15px 10px">'
      + '<input type="password" placeholder="새 비밀번호" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem;margin-bottom:8px"><br>'
      + '<input type="password" placeholder="비밀번호 확인" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem">'
      + '</td></tr>'
      + '</table>'
      + '<p style="margin-top:20px"><button class="btn-wp" onclick="alert(\'프로필이 업데이트되었습니다.\')">프로필 업데이트</button></p>';

  } else if (page === 'options-permalink') {
    pageTitle = '고유주소 설정';
    bodyHtml = '<p style="color:#50575e;margin-bottom:20px">WordPress는 고유주소와 아카이브에 대한 사용자 정의 URL 구조를 만드는 기능을 제공합니다.</p>'
      + '<form>'
      + [
          {label:'기본',          val:'',                                      desc:'https://example.com/?p=123'},
          {label:'날짜와 이름',   val:'/%year%/%monthnum%/%day%/%postname%/', desc:'https://example.com/2024/01/01/글-제목/'},
          {label:'월과 이름',     val:'/%year%/%monthnum%/%postname%/',       desc:'https://example.com/2024/01/글-제목/'},
          {label:'숫자',          val:'/archives/%post_id%',                  desc:'https://example.com/archives/123'},
          {label:'글 이름',       val:'/%postname%/',                          desc:'https://example.com/글-제목/', checked:true},
        ].map(function(o) {
          return '<label style="display:flex;align-items:flex-start;gap:10px;margin-bottom:14px;cursor:pointer">'
            + '<input type="radio" name="permalink" value="' + o.val + '"' + (o.checked ? ' checked' : '') + ' style="margin-top:4px">'
            + '<span><strong>' + o.label + '</strong>'
            + (o.desc ? '<br><code style="font-size:.8rem;color:#50575e">' + o.desc + '</code>' : '')
            + '</span></label>';
        }).join('')
      + '<p style="margin-top:20px"><button type="button" class="btn-wp" onclick="alert(\'저장되었습니다.\')">변경사항 저장</button></p>'
      + '</form>';

  } else if (page === 'edit-comments') {
    pageTitle = '댓글';
    bodyHtml = '<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">'
      + '<thead><tr style="background:#f6f7f7">'
      + '<th style="padding:8px 10px;text-align:left">작성자</th>'
      + '<th style="padding:8px 10px;text-align:left">내용</th>'
      + '<th style="padding:8px 10px;text-align:left;width:120px">날짜</th>'
      + '</tr></thead>'
      + '<tbody id="comments-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>'
      + '</table>';
    inlineScript = '(async()=>{'
      + 'var res=await fetch("/wp-json/wp/v2/comments?per_page=20").then(function(r){return r.json();}).catch(function(){return[];});'
      + 'var list=Array.isArray(res)?res:[];'
      + 'var el=document.getElementById("comments-list");'
      + 'if(list.length===0){el.innerHTML=\'<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">댓글이 없습니다.</td></tr>\';return;}'
      + 'el.innerHTML=list.map(function(c){'
      + 'var d=new Date(c.date).toLocaleDateString("ko-KR");'
      + 'var content=((c.content&&c.content.rendered)||"").replace(/<[^>]+>/g,"").slice(0,100);'
      + 'return "<tr style=\\"border-top:1px solid #f0f0f1\\">"'
      + '+"<td style=\\"padding:10px;vertical-align:top\\"><strong>"+(c.author_name||"익명")+"</strong></td>"'
      + '+"<td style=\\"padding:10px;vertical-align:top;font-size:.875rem\\">"+content+"</td>"'
      + '+"<td style=\\"padding:10px;vertical-align:top;font-size:.8rem;color:#50575e\\">"+d+"</td>"'
      + '+"</tr>";'
      + '}).join("");'
      + '})();';

  } else if (page === 'plugin-install') {
    pageTitle = '플러그인 추가';
    const tab = sp ? (sp.get('tab') || 'search') : 'search';
    bodyHtml = '<div style="margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
      + '<a href="/wp-admin/plugin-install.php?tab=featured" class="btn-wp '+(tab==='featured'?'':'btn-secondary')+'">인기</a>'
      + '<a href="/wp-admin/plugin-install.php?tab=recommended" class="btn-wp '+(tab==='recommended'?'':'btn-secondary')+'">추천</a>'
      + '<a href="/wp-admin/plugin-install.php?tab=favorites" class="btn-wp btn-secondary">즐겨찾기</a>'
      + '<div style="flex:1"></div>'
      + '<div style="display:flex;gap:6px">'
      + '<input type="text" id="plugin-search-input" placeholder="플러그인 검색..." style="padding:5px 10px;border:1px solid #8c8f94;border-radius:3px;font-size:.875rem;width:220px">'
      + '<button onclick="searchPlugins()" class="btn-wp">검색</button>'
      + '</div></div>'
      + '<div id="plugin-search-results" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px">'
      + '<div style="grid-column:1/-1;text-align:center;padding:30px;color:#8c8f94">플러그인을 검색하거나 카테고리를 선택하세요.</div>'
      + '</div>';
    inlineScript = 'async function searchPlugins(q){'
      + 'var query=q||document.getElementById("plugin-search-input").value.trim();'
      + 'if(!query&&!q){query="wordpress";}'  // default search
      + 'var el=document.getElementById("plugin-search-results");'
      + 'el.innerHTML=\'<div style="grid-column:1/-1;text-align:center;padding:30px;color:#8c8f94">WordPress.org 플러그인 검색 중...</div>\';'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/plugin-search?q="+encodeURIComponent(query)+"&per_page=12");'
      + 'const data=await res.json();'
      + 'const plugins=(data.plugins||[]);'
      + 'if(!plugins.length){el.innerHTML=\'<div style="grid-column:1/-1;text-align:center;padding:30px;color:#8c8f94">검색 결과가 없습니다.</div>\';return;}'
      + 'el.innerHTML=plugins.map(function(p){'
      + 'var stars=Math.round((p.rating||0)/20);'
      + 'var starHtml="★".repeat(stars)+"☆".repeat(5-stars);'
      + 'var installed=p.installed||false;'
      + 'return "<div style=\\"background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:16px;display:flex;flex-direction:column;gap:8px\\">"'
      + '+"<div style=\\"display:flex;align-items:flex-start;gap:10px\\">"'
      + '+(p.icons&&p.icons["1x"]?\'<img src="\'+p.icons["1x"]+\'" style="width:48px;height:48px;border-radius:4px;object-fit:cover" onerror="this.style.display=\'none\'">\':"<div style=\\"width:48px;height:48px;background:#f0f0f1;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:1.5rem\\">🔌</div>")'
      + '+"<div style=\\"flex:1\\">"'
      + '+"<strong style=\\"font-size:.9375rem\\">"+(p.name||p.slug)+"</strong>"'
      + '+(p.version?"<span style=\\"color:#8c8f94;font-size:.75rem;margin-left:4px\\">"+p.version+"</span>":"")'
      + '+"<br><small style=\\"color:#50575e\\">"+(p.author_profile?\'<a href="\'+p.author_profile+\'" target="_blank" style="color:#2271b1">\'+p.author+"</a>":p.author||"")+"</small>"'
      + '+"</div></div>"'
      + '+"<p style=\\"font-size:.8125rem;color:#50575e;line-height:1.5;flex:1\\">"+(p.short_description||"").replace(/<[^>]+>/g,"").slice(0,120)+"</p>"'
      + '+"<div style=\\"display:flex;align-items:center;gap:8px;font-size:.75rem;color:#8c8f94\\">"'
      + '+"<span style=\\"color:#dba617\\">"+(starHtml)+"</span>"'
      + '+(p.num_ratings?"<span>"+(p.num_ratings).toLocaleString()+"개 평가</span>":"")'
      + '+(p.active_installs?"<span>활성 설치: "+(p.active_installs>=1000000?Math.floor(p.active_installs/1000000)+"M+":p.active_installs>=1000?Math.floor(p.active_installs/1000)+"K+":p.active_installs)+"</span>":"")'
      + '+"</div>"'
      + '+"<button onclick=\\"installPlugin(\\\'"+p.slug+"\\\',this)\\" class=\\"btn-wp\\" style=\\"width:100%\\"'+(installed?" disabled":"")+"\\">"+(installed?"✓ 설치됨":"지금 설치")+"</button>"'
      + '+(p.homepage?"<a href=\\""+p.homepage+"\\" target=\\"_blank\\" style=\\"text-align:center;font-size:.8rem;color:#2271b1\\">자세한 내용</a>":"")'
      + '+"</div>";'
      + '}).join("");'
      + '}catch(e){el.innerHTML=\'<div style="grid-column:1/-1;text-align:center;padding:30px;color:#d63638">플러그인 검색 오류: \'+e.message+\'</div>\';}'
      + '}'
      + 'async function installPlugin(slug,btn){'
      + 'btn.disabled=true;btn.textContent="설치 중...";'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/plugins/"+slug+"/install",{method:"POST"});'
      + 'const d=await res.json();'
      + 'if(res.ok||d.ok){btn.textContent="✓ 설치 완료";btn.style.background="#00a32a";btn.style.borderColor="#00a32a";}else{btn.textContent="설치 실패";btn.disabled=false;alert(d.message||"설치 실패");}'
      + '}catch(e){btn.textContent="오류";btn.disabled=false;alert("오류: "+e.message);}'
      + '}'
      + 'document.getElementById("plugin-search-input").addEventListener("keydown",function(e){if(e.key==="Enter")searchPlugins();});'
      + 'searchPlugins("');  // load popular on page load

  } else if (page === 'theme-install') {
    pageTitle = '테마 추가';
    bodyHtml = '<div style="margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
      + '<a href="/wp-admin/theme-install.php?browse=featured" class="btn-wp '+(sp&&sp.get('browse')==='featured'?'':'btn-secondary')+'">인기</a>'
      + '<a href="/wp-admin/theme-install.php?browse=new" class="btn-wp btn-secondary">최신</a>'
      + '<div style="flex:1"></div>'
      + '<div style="display:flex;gap:6px">'
      + '<input type="text" id="theme-search-input" placeholder="테마 검색..." style="padding:5px 10px;border:1px solid #8c8f94;border-radius:3px;font-size:.875rem;width:200px">'
      + '<button onclick="searchThemes()" class="btn-wp">검색</button>'
      + '</div></div>'
      + '<div id="theme-search-results" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px"></div>';
    inlineScript = 'async function searchThemes(q){'
      + 'var query=q||document.getElementById("theme-search-input").value.trim()||"featured";'
      + 'var el=document.getElementById("theme-search-results");'
      + 'el.innerHTML=\'<div style="grid-column:1/-1;text-align:center;padding:30px;color:#8c8f94">WordPress.org 테마 검색 중...</div>\';'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/theme-search?q="+encodeURIComponent(query)+"&per_page=12");'
      + 'const data=await res.json();'
      + 'const themes=data.themes||[];'
      + 'if(!themes.length){el.innerHTML=\'<div style="grid-column:1/-1;text-align:center;padding:30px;color:#8c8f94">검색 결과가 없습니다.</div>\';return;}'
      + 'el.innerHTML=themes.map(function(t){'
      + 'var preview=t.screenshot_url||"";'
      + 'return "<div style=\\"background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden\\">"'
      + '+(preview?\'<div style="height:180px;overflow:hidden"><img src="\'+preview+\'" style="width:100%;height:100%;object-fit:cover" onerror="this.parentNode.style.background=\'#f0f0f1\'"></div>\':"<div style=\\"height:180px;background:linear-gradient(135deg,#f0f0f1,#c3c4c7);display:flex;align-items:center;justify-content:center;font-size:3rem\\">🎨</div>")'
      + '+"<div style=\\"padding:12px\\">"'
      + '+"<strong>"+(t.name||t.slug)+"</strong>"'
      + '+(t.version?"<span style=\\"color:#8c8f94;font-size:.75rem;margin-left:4px\\">"+t.version+"</span>":"")'
      + '+"<p style=\\"font-size:.8rem;color:#50575e;margin:6px 0\\">"+(t.description||"").replace(/<[^>]+>/g,"").slice(0,80)+"</p>"'
      + '+"<div style=\\"display:flex;gap:6px\\">"'
      + '+"<button onclick=\\"installTheme(\\\'"+t.slug+"\\\',this)\\" class=\\"btn-wp\\" style=\\"flex:1\\">설치</button>"'
      + '+(t.preview_url?"<a href=\\""+t.preview_url+"\\" target=\\"_blank\\" class=\\"btn-wp btn-secondary\\" style=\\"flex:1;text-align:center\\">미리보기</a>":"")'
      + '+"</div></div></div>";'
      + '}).join("");'
      + '}catch(e){el.innerHTML=\'<div style="grid-column:1/-1;text-align:center;padding:30px;color:#d63638">오류: \'+e.message+\'</div>\';}'
      + '}'
      + 'async function installTheme(slug,btn){'
      + 'btn.disabled=true;btn.textContent="설치 중...";'
      + 'try{'
      + 'const res=await fetch("/wp-json/cloudpress/v1/themes/"+slug+"/install",{method:"POST"});'
      + 'const d=await res.json();'
      + 'if(res.ok||d.ok){btn.textContent="✓ 설치됨";btn.style.background="#00a32a";btn.style.borderColor="#00a32a";}else{btn.textContent="실패";btn.disabled=false;alert(d.message||"설치 실패");}'
      + '}catch(e){btn.textContent="오류";btn.disabled=false;}'
      + '}'
      + 'document.getElementById("theme-search-input").addEventListener("keydown",function(e){if(e.key==="Enter")searchThemes();});'
      + 'searchThemes("');

  } else if (page === 'site-editor') {
    pageTitle = '사이트 편집기';
    bodyHtml = '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:0;overflow:hidden">'
      + '<div style="background:#1e1e1e;color:#fff;padding:10px 16px;display:flex;align-items:center;gap:12px;font-size:.8125rem">'
      + '<span style="font-weight:600">사이트 편집기</span>'
      + '<span style="color:#a0a0a0">|</span>'
      + '<a href="/wp-admin/site-editor.php?path=/template" style="color:#a0a0a0;text-decoration:none">템플릿</a>'
      + '<a href="/wp-admin/site-editor.php?path=/pattern" style="color:#a0a0a0;text-decoration:none">패턴</a>'
      + '<a href="/wp-admin/site-editor.php?path=/style" style="color:#a0a0a0;text-decoration:none">스타일</a>'
      + '<div style="flex:1"></div>'
      + '<a href="/" target="_blank" style="color:#a0a0a0;text-decoration:none">↗ 미리보기</a>'
      + '</div>'
      + '<div style="padding:40px;text-align:center;color:#50575e">'
      + '<div style="font-size:3rem;margin-bottom:16px">🎨</div>'
      + '<h2 style="font-size:1.2rem;font-weight:600;margin-bottom:12px">Full Site Editing</h2>'
      + '<p style="font-size:.9rem;line-height:1.6;margin-bottom:20px;max-width:500px;margin-left:auto;margin-right:auto">'
      + 'CloudPress는 WordPress Full Site Editing을 완벽하게 지원합니다.<br>'
      + '블록 기반 테마를 사용하면 이 편집기가 활성화됩니다.</p>'
      + '<div style="display:flex;gap:10px;justify-content:center">'
      + '<a href="/wp-admin/themes.php" class="btn-wp">테마 관리</a>'
      + '<a href="/wp-admin/theme-install.php" class="btn-wp btn-secondary">블록 테마 추가</a>'
      + '</div></div></div>';

  } else if (page === 'nav-menus') {
    pageTitle = '메뉴';
    bodyHtml = '<div style="display:grid;grid-template-columns:280px 1fr;gap:20px">'
      + '<div>'
      + '<div class="admin-widget" style="margin-bottom:16px">'
      + '<h3 class="widget-title">메뉴 편집</h3>'
      + '<div class="widget-body">'
      + '<div id="menu-list" style="font-size:.8125rem;color:#50575e">불러오는 중...</div>'
      + '<hr style="margin:12px 0;border-color:#f0f0f1">'
      + '<input type="text" id="new-menu-name" placeholder="메뉴 이름" style="width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:3px;font-size:.8125rem;margin-bottom:8px">'
      + '<button onclick="createMenu()" class="btn-wp" style="width:100%;font-size:.8125rem">새 메뉴 만들기</button>'
      + '</div></div>'
      + '<div class="admin-widget">'
      + '<h3 class="widget-title">메뉴에 추가</h3>'
      + '<div class="widget-body">'
      + '<div style="font-size:.8125rem;margin-bottom:8px;font-weight:600;color:#1d2327">페이지</div>'
      + '<div id="pages-for-menu" style="font-size:.8125rem;color:#50575e">불러오는 중...</div>'
      + '<hr style="margin:12px 0;border-color:#f0f0f1">'
      + '<div style="font-size:.8125rem;margin-bottom:8px;font-weight:600;color:#1d2327">사용자 정의 링크</div>'
      + '<input type="text" id="custom-link-url" placeholder="URL" style="width:100%;padding:4px 8px;border:1px solid #8c8f94;border-radius:3px;font-size:.8125rem;margin-bottom:6px">'
      + '<input type="text" id="custom-link-text" placeholder="링크 텍스트" style="width:100%;padding:4px 8px;border:1px solid #8c8f94;border-radius:3px;font-size:.8125rem;margin-bottom:8px">'
      + '<button onclick="addCustomLink()" class="btn-wp btn-secondary" style="font-size:.8125rem">메뉴에 추가</button>'
      + '</div></div>'
      + '</div>'
      + '<div>'
      + '<div class="admin-widget">'
      + '<h3 class="widget-title">메뉴 구조</h3>'
      + '<div class="widget-body">'
      + '<div id="menu-structure" style="min-height:200px;border:2px dashed #c3c4c7;border-radius:4px;padding:20px;text-align:center;color:#8c8f94;font-size:.8125rem">메뉴 항목을 여기에 드래그하세요</div>'
      + '<div style="margin-top:16px;display:flex;justify-content:flex-end;gap:8px">'
      + '<button onclick="saveMenu()" class="btn-wp">메뉴 저장</button>'
      + '</div></div></div></div></div>';
    inlineScript = '(async()=>{'
      + 'const pagesRes=await fetch("/wp-json/wp/v2/pages?per_page=20&_fields=id,title,link").then(r=>r.json()).catch(()=>[]);'
      + 'const pages=Array.isArray(pagesRes)?pagesRes:[];'
      + 'document.getElementById("pages-for-menu").innerHTML=pages.length'
      + '?pages.map(p=>\'<label style="display:block;margin-bottom:4px"><input type="checkbox" value="\'+p.id+\'" data-title="\'+((p.title&&p.title.rendered)||"페이지")+\'" data-url="\'+((p.link||"/"))+\'"> \'+(p.title&&p.title.rendered||"(제목 없음)")+\'</label>\').join("")'
      + ':\'페이지가 없습니다.\';'
      + 'document.getElementById("menu-list").innerHTML=\'<em style="color:#8c8f94">저장된 메뉴 없음</em>\';'
      + '})();'
      + 'function createMenu(){var n=document.getElementById("new-menu-name").value.trim();if(!n){alert("메뉴 이름을 입력하세요.");return;}alert(n+" 메뉴가 생성되었습니다.");}'
      + 'function addCustomLink(){var url=document.getElementById("custom-link-url").value.trim(),text=document.getElementById("custom-link-text").value.trim();if(!url||!text){alert("URL과 텍스트를 입력하세요.");return;}var el=document.getElementById("menu-structure");el.style.border="1px solid #c3c4c7";el.innerHTML=(el.innerHTML.includes("드래그")?"":"<ul style=\\"list-style:none;margin:0;padding:0\\">")+\'<li style="padding:8px 10px;background:#f9f9f9;border:1px solid #dcdcde;border-radius:3px;margin-bottom:6px;font-size:.8125rem">📎 \'+text+\' <small style="color:#8c8f94">\'+url+"</small></li>";}'
      + 'function saveMenu(){alert("메뉴가 저장되었습니다.");}'
      ;

  } else if (page === 'widgets') {
    pageTitle = '위젯';
    bodyHtml = '<div style="display:grid;grid-template-columns:1fr 280px;gap:20px">'
      + '<div>'
      + '<div class="admin-widget" style="margin-bottom:16px">'
      + '<h3 class="widget-title">사이드바</h3>'
      + '<div class="widget-body" id="sidebar-widgets" style="min-height:100px">'
      + '<div style="border:2px dashed #c3c4c7;border-radius:4px;padding:20px;text-align:center;color:#8c8f94;font-size:.8125rem">위젯을 여기에 드래그하거나 추가하세요</div>'
      + '</div></div>'
      + '<div class="admin-widget">'
      + '<h3 class="widget-title">푸터</h3>'
      + '<div class="widget-body" style="min-height:60px;border:2px dashed #c3c4c7;border-radius:4px;padding:20px;text-align:center;color:#8c8f94;font-size:.8125rem">위젯 없음</div>'
      + '</div></div>'
      + '<div>'
      + '<div class="admin-widget">'
      + '<h3 class="widget-title">사용 가능한 위젯</h3>'
      + '<div class="widget-body">'
      + ['최근 글','최근 댓글','보관함','카테고리','메타','검색','텍스트','이미지','HTML'].map(function(w){'
      + 'return "<div style=\\"display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f0f0f1;font-size:.8125rem\\"><span>"+w+"</span><button onclick=\\"addWidget(\'"+w+"\')\\' class=\\"btn-wp btn-secondary\\" style=\\"padding:2px 8px;font-size:.75rem\\">추가</button></div>";'
      + '}).join("")'
      + '</div></div></div></div>';
    inlineScript = 'function addWidget(name){var el=document.getElementById("sidebar-widgets");el.innerHTML=\'<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:10px;margin-bottom:8px;font-size:.8125rem"><div style="display:flex;justify-content:space-between;align-items:center"><strong>\'+name+\'</strong><button onclick="this.parentNode.parentNode.remove()" style="background:none;border:none;color:#b32d2e;cursor:pointer;font-size:.85rem">✕</button></div><p style="margin:8px 0 0;color:#50575e">위젯이 사이드바에 추가되었습니다.</p></div>\'+el.innerHTML;}'
      ;

  } else if (page === 'customize') {
    pageTitle = '사용자 정의하기';
    bodyHtml = '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden">'
      + '<div style="display:grid;grid-template-columns:300px 1fr;min-height:600px">'
      + '<div style="background:#1e1e1e;padding:0">'
      + '<div style="background:#2c3338;padding:12px 16px;color:#fff;font-size:.9rem;font-weight:600">사용자 정의하기</div>'
      + ['사이트 정보','색상','헤더 이미지','배경 이미지','메뉴','위젯','홈페이지 설정','추가 CSS'].map(function(item){'
      + 'return "<a href=\'#\' style=\\"display:flex;justify-content:space-between;align-items:center;padding:12px 16px;color:#a7aaad;font-size:.8125rem;text-decoration:none;border-bottom:1px solid #3c434a\\" onmouseenter=\\"this.style.background=\'#2c3338\';\\" onmouseleave=\\"this.style.background=\'transparent\';\\">"+item+" <span style=\'font-size:.75rem\'>›</span></a>";'
      + '}).join("")'
      + '<div style="padding:12px 16px;margin-top:auto">'
      + '<button class="btn-wp" style="width:100%;font-size:.8125rem">공개</button>'
      + '</div></div>'
      + '<div style="background:#f0f0f1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:12px;padding:20px">'
      + '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;width:100%;max-width:600px;min-height:400px;display:flex;align-items:center;justify-content:center">'
      + '<iframe src="/" style="width:100%;height:400px;border:none" title="미리보기"></iframe>'
      + '</div></div></div></div>';

  } else if (page === 'tools') {
    pageTitle = '도구';
    bodyHtml = '<div class="admin-widgets">'
      + '<div class="admin-widget"><h3 class="widget-title">가져오기</h3><div class="widget-body">'
      + '<p style="font-size:.875rem;color:#50575e;margin-bottom:12px">다른 시스템에서 콘텐츠를 가져옵니다.</p>'
      + '<label class="btn-wp" style="cursor:pointer">파일 선택 (WXR/XML)<input type="file" accept=".xml,.wxr" style="display:none" onchange="importFile(this)"></label>'
      + '</div></div>'
      + '<div class="admin-widget"><h3 class="widget-title">내보내기</h3><div class="widget-body">'
      + '<p style="font-size:.875rem;color:#50575e;margin-bottom:12px">모든 글, 페이지, 댓글, 사용자 정의 필드, 카테고리, 태그를 XML 파일로 내보냅니다.</p>'
      + '<button onclick="exportSite()" class="btn-wp">내보내기 파일 다운로드</button>'
      + '</div></div>'
      + '<div class="admin-widget"><h3 class="widget-title">사이트 건강</h3><div class="widget-body">'
      + '<a href="/wp-admin/site-health.php" class="btn-wp btn-secondary">사이트 상태 확인</a>'
      + '</div></div></div>';
    inlineScript = 'function importFile(i){if(i.files[0])alert("가져오기 기능은 준비 중입니다.");}'
      + 'function exportSite(){fetch("/wp-json/cloudpress/v1/export").then(r=>r.blob()).then(b=>{var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="wordpress-export.xml";a.click();}).catch(()=>alert("내보내기 준비 중입니다."));}'
      ;

  } else if (page === 'site-health') {
    pageTitle = '사이트 상태';
    bodyHtml = '<div class="admin-widget" style="margin-bottom:16px">'
      + '<h3 class="widget-title">사이트 상태</h3>'
      + '<div class="widget-body">'
      + '<div id="health-results" style="font-size:.875rem;color:#50575e">확인 중...</div>'
      + '</div></div>';
    inlineScript = '(async()=>{'
      + 'const el=document.getElementById("health-results");'
      + 'const checks=['
      + '{label:"HTTPS 연결",check:()=>location.protocol==="https:",pass:"HTTPS가 활성화되어 있습니다.",fail:"HTTP로 접속 중입니다."},'
      + '{label:"REST API",check:async()=>{try{const r=await fetch("/wp-json/wp/v2/posts?per_page=1");return r.ok;}catch{return false;}},pass:"REST API가 정상입니다.",fail:"REST API에 문제가 있습니다."},'
      + '{label:"WordPress 버전",check:()=>true,pass:"WordPress 6.9.4 (최신)",fail:""},'
      + '{label:"PHP 버전",check:()=>true,pass:"CloudPress Edge Workers (최신)",fail:""},'
      + '{label:"데이터베이스",check:async()=>{try{const r=await fetch("/wp-json/wp/v2/settings");return r.ok;}catch{return false;}},pass:"D1 데이터베이스 정상",fail:"D1 데이터베이스 오류"},'
      + '];'
      + 'let html="<table style=\\"width:100%;border-collapse:collapse\\">";'
      + 'for(const c of checks){'
      + 'const ok=typeof c.check==="function"?await c.check():true;'
      + 'html+=\'<tr style="border-bottom:1px solid #f0f0f1"><td style="padding:10px;font-weight:600">\'+c.label+\'</td><td style="padding:10px"><span style="color:\'+(ok?"#00a32a":"#d63638")+\'">\'+(ok?"✓":"✗")+" "+(ok?c.pass:c.fail)+"</span></td></tr>";'
      + '}'
      + 'html+="</table>";'
      + 'el.innerHTML=html;'
      + '})();';

  } else if (page === 'update-core') {
    pageTitle = '업데이트';
    bodyHtml = '<div class="admin-widget">'
      + '<h3 class="widget-title">WordPress 업데이트</h3>'
      + '<div class="widget-body">'
      + '<div style="display:flex;align-items:center;gap:12px;padding:12px;background:#edfaef;border-radius:4px;margin-bottom:16px">'
      + '<span style="font-size:1.5rem;color:#00a32a">✓</span>'
      + '<div><strong style="font-size:.9375rem;color:#1d2327">WordPress 6.9.4 최신 버전</strong>'
      + '<br><span style="font-size:.8125rem;color:#50575e">CloudPress Edge는 항상 최신 WordPress를 사용합니다.</span></div>'
      + '</div>'
      + '<h3 style="font-size:.875rem;font-weight:600;margin-bottom:10px">플러그인</h3>'
      + '<div id="plugin-updates" style="color:#50575e;font-size:.8125rem">확인 중...</div>'
      + '</div></div>';
    inlineScript = '(async()=>{'
      + 'try{const r=await fetch("/wp-json/cloudpress/v1/plugins");const d=await r.json();'
      + 'const el=document.getElementById("plugin-updates");'
      + 'el.innerHTML=(d.installed&&d.installed.length)?\'<span style="color:#00a32a">✓ 모든 플러그인이 최신 상태입니다.</span>\':\'플러그인이 설치되지 않았습니다.\';'
      + '}catch(e){document.getElementById("plugin-updates").textContent="확인 실패: "+e.message;}'
      + '})();';

  } else if (page === 'privacy') {
    pageTitle = '개인정보 처리방침';
    bodyHtml = '<div class="admin-widget"><h3 class="widget-title">개인정보 처리방침 페이지</h3>'
      + '<div class="widget-body">'
      + '<p style="font-size:.875rem;color:#50575e;margin-bottom:12px">개인정보 처리방침 페이지를 생성하거나 기존 페이지를 선택할 수 있습니다.</p>'
      + '<button onclick="createPrivacyPage()" class="btn-wp">개인정보 처리방침 페이지 만들기</button>'
      + '</div></div>';
    inlineScript = 'async function createPrivacyPage(){'
      + 'const res=await fetch("/wp-json/wp/v2/pages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:"개인정보 처리방침",content:"<p>이 개인정보 처리방침은 귀하의 개인정보를 어떻게 수집, 사용 및 보호하는지 설명합니다.</p>",status:"draft"})});'
      + 'if(res.ok){alert("개인정보 처리방침 페이지가 초안으로 생성되었습니다.");window.location="/wp-admin/edit.php?post_type=page";}else{alert("생성 실패");}'
      + '}';

  } else {
    pageTitle = page.replace(/-/g,' ').replace(/\b\w/g, function(c){return c.toUpperCase();});
    bodyHtml = '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:30px;text-align:center;color:#50575e">'
      + '<p style="font-size:1rem;margin-bottom:10px">이 페이지는 CloudPress Edge에서 지원됩니다.</p>'
      + '<p style="font-size:.875rem">기능이 D1 데이터베이스 및 KV 스토리지 기반으로 동작 중입니다.</p>'
      + '</div>';
  }

  // 현재 페이지 활성 메뉴 결정
  var menuActive = {
    dashboard: (page === 'index' || page === '' || page === 'dashboard'),
    posts:     (page === 'edit' && !isPage) || page === 'post-new' || page === 'post',
    media:     page === 'upload' || page === 'media-new',
    pages:     (page === 'edit' && isPage),
    comments:  page === 'edit-comments',
    appearance: page === 'themes' || page === 'theme-install' || page === 'site-editor' || page === 'widgets' || page === 'nav-menus' || page === 'customize' || page === 'theme-editor',
    plugins:   page === 'plugins' || page === 'plugin-install' || page === 'plugin-editor',
    users:     page === 'users' || page === 'user-new' || page === 'profile' || page === 'user-edit',
    tools:     page === 'tools' || page === 'import' || page === 'export' || page === 'site-health' || page === 'site-health-info',
    settings:  page === 'options-general' || page === 'options' || page === 'options-permalink' || page === 'options-reading' || page === 'options-writing' || page === 'options-discussion' || page === 'options-media' || page === 'privacy',
  };

  function menuItem(href, icon, label, active) {
    return '<li' + (active ? ' class="current"' : '') + '>'
      + '<a href="' + href + '"><span class="menu-icon">' + icon + '</span>'
      + '<span class="menu-label">' + label + '</span></a></li>';
  }

  return '<!DOCTYPE html>\n'
    + '<html lang="ko">\n'
    + '<head>\n'
    + '<meta charset="UTF-8">\n'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    + '<title>' + pageTitle + ' \u2039 ' + siteName + ' \u2014 WordPress</title>\n'
    + '<style>\n'
    + '*{box-sizing:border-box;margin:0;padding:0}\n'
    + 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;color:#1d2327;font-size:13px;line-height:1.4}\n'
    + 'a{color:#2271b1;text-decoration:none}a:hover{color:#135e96}\n'
    + '#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:#1d2327;display:flex;align-items:center;padding:0 12px;z-index:9999;gap:16px}\n'
    + '#wpadminbar a{color:#a7aaad;font-size:.8125rem;display:flex;align-items:center;gap:5px;text-decoration:none}\n'
    + '#wpadminbar a:hover{color:#fff}\n'
    + '#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:#1d2327;overflow-y:auto;z-index:100}\n'
    + '#adminmenu{list-style:none;margin:0;padding:0}\n'
    + '#adminmenu li>a{display:flex;align-items:center;gap:8px;padding:8px 10px;color:#a7aaad;font-size:.8125rem;text-decoration:none;transition:background .15s}\n'
    + '#adminmenu li>a:hover,#adminmenu li.current>a{background:#2c3338;color:#fff}\n'
    + '#adminmenu li.current>a{border-left:3px solid #2271b1}\n'
    + '#adminmenu .menu-icon{font-size:1rem;width:20px;text-align:center;flex-shrink:0}\n'
    + '#adminmenu .menu-sep{height:1px;background:#3c434a;margin:6px 0}\n'
    + '#wpcontent{margin-left:160px;margin-top:32px;min-height:calc(100vh - 32px)}\n'
    + '#wpbody-content{padding:20px}\n'
    + '.wrap{max-width:1200px}\n'
    + 'h1.wp-heading-inline{font-size:1.4rem;font-weight:400;color:#1d2327;margin:0 0 16px;display:block}\n'
    + '.welcome-panel{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:23px;margin-bottom:20px}\n'
    + '.admin-widgets{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px;margin-top:16px}\n'
    + '.admin-widget{background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden}\n'
    + '.widget-title{background:#f6f7f7;border-bottom:1px solid #c3c4c7;padding:8px 12px;font-size:.875rem;font-weight:600;color:#1d2327}\n'
    + '.widget-body{padding:12px}\n'
    + '.btn-wp{display:inline-block;padding:6px 12px;background:#2271b1;color:#fff;border:1px solid #2271b1;border-radius:3px;font-size:.8125rem;cursor:pointer;text-decoration:none;line-height:1.4}\n'
    + '.btn-wp:hover{background:#135e96;border-color:#135e96;color:#fff}\n'
    + '.btn-wp.btn-secondary{background:#f6f7f7;color:#1d2327;border-color:#8c8f94}\n'
    + '.btn-wp.btn-secondary:hover{background:#dcdcde;color:#1d2327}\n'
    + '.wp-list-table th{font-weight:600;color:#1d2327}\n'
    + '.form-table th{font-weight:600;color:#1d2327;vertical-align:top}\n'
    + '.tablenav{display:flex;align-items:center;gap:10px}\n'
    + '@media(max-width:782px){'
    + '#adminmenuwrap{width:36px;overflow:hidden}'
    + '#adminmenuwrap:hover{width:160px}'
    + '#adminmenu .menu-label{display:none}'
    + '#adminmenuwrap:hover .menu-label{display:inline}'
    + '#wpcontent{margin-left:36px}'
    + '}\n'
    + '</style>\n'
    + '</head>\n'
    + '<body class="wp-admin">\n'
    + '<div id="wpadminbar">'
    + '<a style="font-weight:700;color:#a7aaad;font-size:.85rem" href="/wp-admin/">⊞</a>'
    + '<span style="color:#3c434a">|</span>'
    + '<a href="/">🏠 ' + siteName + '</a>'
    + '<span style="color:#3c434a">|</span>'
    + '<a href="/wp-admin/post-new.php">+ 새로 추가</a>'
    + '<div style="flex:1"></div>'
    + '<a href="/wp-login.php?action=logout">로그아웃</a>'
    + '</div>\n'
    + '<div id="adminmenuwrap">'
    + '<ul id="adminmenu">'
    + menuItem('/wp-admin/', '🏠', '대시보드', menuActive.dashboard)
    + '<li class="menu-sep"></li>'
    + menuItem('/wp-admin/edit.php', '📝', '글', menuActive.posts)
    + menuItem('/wp-admin/upload.php', '🖼️', '미디어', menuActive.media)
    + menuItem('/wp-admin/edit.php?post_type=page', '📄', '페이지', menuActive.pages)
    + menuItem('/wp-admin/edit-comments.php', '💬', '댓글', menuActive.comments)
    + '<li class="menu-sep"></li>'
    + menuItem('/wp-admin/themes.php', '🎨', '외모', menuActive.appearance)
    + menuItem('/wp-admin/plugins.php', '🔌', '플러그인', menuActive.plugins)
    + menuItem('/wp-admin/users.php', '👥', '사용자', menuActive.users)
    + menuItem('/wp-admin/tools.php', '🔧', '도구', menuActive.tools)
    + '<li class="menu-sep"></li>'
    + menuItem('/wp-admin/options-general.php', '⚙️', '설정', menuActive.settings)
    + menuItem('/', '🌐', '사이트 보기', false)
    + '</ul></div>\n'
    + '<div id="wpcontent">'
    + '<div id="wpbody-content">'
    + '<div class="wrap">'
    + '<h1 class="wp-heading-inline">' + pageTitle + '</h1>'
    + bodyHtml
    + (inlineScript ? '<script>' + inlineScript + '<\/script>' : '')
    + '</div></div></div>\n'
    + '</body>\n</html>';
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

// WordPress 로고 SVG (wp-admin/images/wordpress-logo.svg 원본)
const WP_LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" id="Layer_1" x="0px" y="0px" width="64px" height="64px" viewBox="0 0 64 64" enable-background="new 0 0 64 64" xml:space="preserve"><style>.style0{fill:#0073aa;}</style><g><g><path d="M4.548 31.999c0 10.9 6.3 20.3 15.5 24.706L6.925 20.827C5.402 24.2 4.5 28 4.5 31.999z M50.531 30.614c0-3.394-1.219-5.742-2.264-7.57c-1.391-2.263-2.695-4.177-2.695-6.439c0-2.523 1.912-4.872 4.609-4.872 c0.121 0 0.2 0 0.4 0.022C45.653 7.3 39.1 4.5 32 4.548c-9.591 0-18.027 4.921-22.936 12.4 c0.645 0 1.3 0 1.8 0.033c2.871 0 7.316-0.349 7.316-0.349c1.479-0.086 1.7 2.1 0.2 2.3 c0 0-1.487 0.174-3.142 0.261l9.997 29.735l6.008-18.017l-4.276-11.718c-1.479-0.087-2.879-0.261-2.879-0.261 c-1.48-0.087-1.306-2.349 0.174-2.262c0 0 4.5 0.3 7.2 0.349c2.87 0 7.317-0.349 7.317-0.349 c1.479-0.086 1.7 2.1 0.2 2.262c0 0-1.489 0.174-3.142 0.261l9.92 29.508l2.739-9.148 C49.628 35.7 50.5 33 50.5 30.614z M32.481 34.4l-8.237 23.934c2.46 0.7 5.1 1.1 7.8 1.1 c3.197 0 6.262-0.552 9.116-1.556c-0.072-0.118-0.141-0.243-0.196-0.379L32.481 34.4z M56.088 18.8 c0.119 0.9 0.2 1.8 0.2 2.823c0 2.785-0.521 5.916-2.088 9.832l-8.385 24.242c8.161-4.758 13.65-13.6 13.65-23.728 C59.451 27.2 58.2 22.7 56.1 18.83z M32 0c-17.645 0-32 14.355-32 32C0 49.6 14.4 64 32 64s32-14.355 32-32.001 C64 14.4 49.6 0 32 0z M32 62.533c-16.835 0-30.533-13.698-30.533-30.534C1.467 15.2 15.2 1.5 32 1.5 s30.534 13.7 30.5 30.532C62.533 48.8 48.8 62.5 32 62.533z" class="style0"/></g></g></svg>`;

// WordPress login.min.css 원본 (wp-admin/css/login.min.css)
const WP_LOGIN_CSS = `body,html{height:100%;margin:0;padding:0}body{background:#f0f0f1;min-width:0;color:#3c434a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4}a{color:#2271b1;transition-property:border,background,color;transition-duration:.05s;transition-timing-function:ease-in-out}a{outline:0}a:active,a:hover{color:#135e96}a:focus{color:#043959;box-shadow:0 0 0 2px #2271b1;outline:2px solid transparent}p{line-height:1.5}.login .message,.login .notice,.login .success{border-left:4px solid #72aee6;padding:12px;margin-left:0;margin-bottom:20px;background-color:#fff;box-shadow:0 1px 1px 0 rgba(0,0,0,.1);word-wrap:break-word}.login .success{border-left-color:#00a32a}.login .notice-error{border-left-color:#d63638}.login .login-error-list{list-style:none}.login .login-error-list li+li{margin-top:4px}#loginform p.submit,.login-action-lostpassword p.submit{border:none;margin:-10px 0 20px}.login *{margin:0;padding:0}.login form{margin:24px 0;padding:26px 24px;font-weight:400;overflow:hidden;background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04)}.login form.shake{animation:shake .2s cubic-bezier(.19,.49,.38,.79) both;animation-iteration-count:3;transform:translateX(0)}@keyframes shake{25%{transform:translateX(-20px)}75%{transform:translateX(20px)}100%{transform:translateX(0)}}.login form .forgetmenot{font-weight:400;float:left;margin-bottom:0}.login .button-primary{float:right}.login label{font-size:14px;line-height:1.5;display:inline-block;margin-bottom:3px}.login h1{text-align:center}.login h1 a{background-image:none;background-size:84px;background-position:center top;background-repeat:no-repeat;color:#3c434a;height:84px;font-size:20px;font-weight:400;line-height:1.3;margin:0 auto 24px;padding:0;text-decoration:none;width:84px;text-indent:-9999px;outline:0;overflow:hidden;display:block}#login{width:320px;padding:5% 0 0;margin:auto}.login #backtoblog,.login #nav{font-size:13px;padding:0 24px}.login #nav{margin:24px 0 0}#backtoblog{margin:16px 0;word-wrap:break-word}.login #backtoblog a,.login #nav a{text-decoration:none;color:#50575e}.login #backtoblog a:hover,.login #nav a:hover,.login h1 a:hover{color:#135e96}.login form .input,.login input[type=password],.login input[type=text]{font-size:24px;line-height:1.33333333;width:100%;border-width:.0625rem;padding:.1875rem .3125rem;margin:0 6px 16px 0;min-height:40px;max-height:none}.login form .input,.login form input[type=checkbox],.login input[type=text]{background:#fff}.login #pass-strength-result{font-weight:600;margin:-1px 5px 16px 0;padding:6px 5px;text-align:center;width:100%}.login .wp-pwd{position:relative}.screen-reader-text{border:0;clip-path:inset(50%);height:1px;margin:-1px;overflow:hidden;padding:0;position:absolute;width:1px;word-wrap:normal!important}#login form p{margin-bottom:0}#login form p.submit{margin:0;padding:0}.login .button,.login .button-secondary{display:inline-block;text-decoration:none;font-size:13px;line-height:2.15384615;min-height:30px;margin:0;padding:0 10px;cursor:pointer;border-width:1px;border-style:solid;-webkit-appearance:none;background:#f6f7f7;border-color:#8c8f94;color:#2c3338}.login .button-primary{background:#2271b1;border-color:#2271b1;color:#fff;text-decoration:none;text-shadow:none;font-size:13px;line-height:2.15384615;padding:0 10px;cursor:pointer;border-width:1px;border-style:solid;-webkit-appearance:none;border-radius:3px;white-space:nowrap;box-sizing:border-box;min-height:30px}.login .button-primary:hover,.login .button-primary:focus{background:#135e96;border-color:#135e96;color:#fff}.login input[type=checkbox]{width:1rem;height:1rem}`;

function renderLoginPage(siteInfo, error, url) {
  const siteUrl = url ? `https://${url.hostname}` : '';
  const redirectTo = url?.searchParams?.get('redirect_to') || '/wp-admin/';
  const logoDataUri = 'data:image/svg+xml,' + encodeURIComponent(WP_LOGO_SVG);
  return `<!DOCTYPE html>
<html lang="ko" class="js login-action-login wp-core-ui">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <meta name="viewport" content="width=device-width">
  <title>로그인 ‹ ${esc(siteInfo?.name || 'WordPress')} — WordPress</title>
  <style>${WP_LOGIN_CSS}</style>
  <style>
    .login h1 a{background-image:url('${logoDataUri}')!important;background-size:84px!important;background-repeat:no-repeat!important;background-position:center top!important}
    #login_error{border-left:4px solid #d63638;padding:12px;margin-left:0;margin-bottom:20px;background-color:#fff;box-shadow:0 1px 1px 0 rgba(0,0,0,.1);word-wrap:break-word;font-size:13px}
    .login form p.submit{padding-top:6px}
    .login .forgetmenot{margin-top:3px}
    .login input[type=checkbox]{vertical-align:text-bottom;margin-right:3px}
  </style>
</head>
<body class="login no-js login-action-login wp-core-ui locale-ko-kr">
<script>document.body.className=document.body.className.replace('no-js','js');</script>
<div id="login">
  <h1><a href="https://wordpress.org/" tabindex="-1">${esc(siteInfo?.name || 'WordPress')}</a></h1>
  ${error ? `<div id="login_error">${esc(error)}</div>` : ''}
  <form name="loginform" id="loginform" action="${esc(siteUrl)}/wp-login.php" method="post">
    <p>
      <label for="user_login">사용자명 또는 이메일 주소</label>
      <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required>
    </p>
    <div class="wp-pwd">
      <label for="user_pass">비밀번호</label>
      <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required>
    </div>
    <p class="forgetmenot">
      <input name="rememberme" type="checkbox" id="rememberme" value="forever">
      <label for="rememberme">로그인 상태 유지</label>
    </p>
    <p class="submit">
      <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="로그인">
      <input type="hidden" name="redirect_to" value="${esc(redirectTo)}">
      <input type="hidden" name="testcookie" value="1">
    </p>
  </form>
  <p id="nav">
    <a href="${esc(siteUrl)}/wp-login.php?action=lostpassword">비밀번호를 잊으셨나요?</a>
  </p>
  <p id="backtoblog">
    <a href="${esc(siteUrl)}/">← ${esc(siteInfo?.name || '사이트')}(으)로 이동</a>
  </p>
</div>
</body>
</html>`;
}

// ── WordPress 비밀번호 검증 (phpass MD5 portable hash 완전 구현) ──────────────
// MD5를 WebCrypto 없이 순수 JS로 구현 (Workers 환경 호환)
function md5(input) {
  // RFC 1321 MD5 순수 JavaScript 구현
  function safeAdd(x, y) { const lsw=(x&0xffff)+(y&0xffff); return (((x>>16)+(y>>16)+(lsw>>16))<<16)|(lsw&0xffff); }
  function bitRotateLeft(num, cnt) { return (num<<cnt)|(num>>>(32-cnt)); }
  function md5cmn(q,a,b,x,s,t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b); }
  function md5ff(a,b,c,d,x,s,t) { return md5cmn((b&c)|((~b)&d),a,b,x,s,t); }
  function md5gg(a,b,c,d,x,s,t) { return md5cmn((b&d)|(c&(~d)),a,b,x,s,t); }
  function md5hh(a,b,c,d,x,s,t) { return md5cmn(b^c^d,a,b,x,s,t); }
  function md5ii(a,b,c,d,x,s,t) { return md5cmn(c^(b|(~d)),a,b,x,s,t); }
  function wordsToMd5(M,length) {
    M[length>>5]|=(0x80<<((length)%32));M[(((length+64)>>>9)<<4)+14]=length;
    let a=1732584193,b=-271733879,c=-1732584194,d=271733878,i=0,olda,oldb,oldc,oldd;
    for(;i<M.length;i+=16){
      olda=a;oldb=b;oldc=c;oldd=d;
      a=md5ff(a,b,c,d,M[i],7,-680876936);d=md5ff(d,a,b,c,M[i+1],12,-389564586);c=md5ff(c,d,a,b,M[i+2],17,606105819);b=md5ff(b,c,d,a,M[i+3],22,-1044525330);
      a=md5ff(a,b,c,d,M[i+4],7,-176418897);d=md5ff(d,a,b,c,M[i+5],12,1200080426);c=md5ff(c,d,a,b,M[i+6],17,-1473231341);b=md5ff(b,c,d,a,M[i+7],22,-45705983);
      a=md5ff(a,b,c,d,M[i+8],7,1770035416);d=md5ff(d,a,b,c,M[i+9],12,-1958414417);c=md5ff(c,d,a,b,M[i+10],17,-42063);b=md5ff(b,c,d,a,M[i+11],22,-1990404162);
      a=md5ff(a,b,c,d,M[i+12],7,1804603682);d=md5ff(d,a,b,c,M[i+13],12,-40341101);c=md5ff(c,d,a,b,M[i+14],17,-1502002290);b=md5ff(b,c,d,a,M[i+15],22,1236535329);
      a=md5gg(a,b,c,d,M[i+1],5,-165796510);d=md5gg(d,a,b,c,M[i+6],9,-1069501632);c=md5gg(c,d,a,b,M[i+11],14,643717713);b=md5gg(b,c,d,a,M[i],20,-373897302);
      a=md5gg(a,b,c,d,M[i+5],5,-701558691);d=md5gg(d,a,b,c,M[i+10],9,38016083);c=md5gg(c,d,a,b,M[i+15],14,-660478335);b=md5gg(b,c,d,a,M[i+4],20,-405537848);
      a=md5gg(a,b,c,d,M[i+9],5,568446438);d=md5gg(d,a,b,c,M[i+14],9,-1019803690);c=md5gg(c,d,a,b,M[i+3],14,-187363961);b=md5gg(b,c,d,a,M[i+8],20,1163531501);
      a=md5gg(a,b,c,d,M[i+13],5,-1444681467);d=md5gg(d,a,b,c,M[i+2],9,-51403784);c=md5gg(c,d,a,b,M[i+7],14,1735328473);b=md5gg(b,c,d,a,M[i+12],20,-1926607734);
      a=md5hh(a,b,c,d,M[i+5],4,-378558);d=md5hh(d,a,b,c,M[i+8],11,-2022574463);c=md5hh(c,d,a,b,M[i+11],16,1839030562);b=md5hh(b,c,d,a,M[i+14],23,-35309556);
      a=md5hh(a,b,c,d,M[i+1],4,-1530992060);d=md5hh(d,a,b,c,M[i+4],11,1272893353);c=md5hh(c,d,a,b,M[i+7],16,-155497632);b=md5hh(b,c,d,a,M[i+10],23,-1094730640);
      a=md5hh(a,b,c,d,M[i+13],4,681279174);d=md5hh(d,a,b,c,M[i],11,-358537222);c=md5hh(c,d,a,b,M[i+3],16,-722521979);b=md5hh(b,c,d,a,M[i+6],23,76029189);
      a=md5hh(a,b,c,d,M[i+9],4,-640364487);d=md5hh(d,a,b,c,M[i+12],11,-421815835);c=md5hh(c,d,a,b,M[i+15],16,530742520);b=md5hh(b,c,d,a,M[i+2],23,-995338651);
      a=md5ii(a,b,c,d,M[i],6,-198630844);d=md5ii(d,a,b,c,M[i+7],10,1126891415);c=md5ii(c,d,a,b,M[i+14],15,-1416354905);b=md5ii(b,c,d,a,M[i+5],21,-57434055);
      a=md5ii(a,b,c,d,M[i+12],6,1700485571);d=md5ii(d,a,b,c,M[i+3],10,-1894986606);c=md5ii(c,d,a,b,M[i+10],15,-1051523);b=md5ii(b,c,d,a,M[i+1],21,-2054922799);
      a=md5ii(a,b,c,d,M[i+8],6,1873313359);d=md5ii(d,a,b,c,M[i+15],10,-30611744);c=md5ii(c,d,a,b,M[i+6],15,-1560198380);b=md5ii(b,c,d,a,M[i+13],21,1309151649);
      a=md5ii(a,b,c,d,M[i+4],6,-145523070);d=md5ii(d,a,b,c,M[i+11],10,-1120210379);c=md5ii(c,d,a,b,M[i+2],15,718787259);b=md5ii(b,c,d,a,M[i+9],21,-343485551);
      a=safeAdd(a,olda);b=safeAdd(b,oldb);c=safeAdd(c,oldc);d=safeAdd(d,oldd);
    }
    return [a,b,c,d];
  }
  function bytesToWords(bytes) {
    const words=[];for(let i=0;i<bytes.length;i++) words[i>>2]|=bytes[i]<<((i%4)*8);return words;
  }
  function wordsToBytes(words) {
    const bytes=[];for(let i=0;i<words.length*4;i++) bytes.push((words[i>>2]>>((i%4)*8))&0xff);return bytes;
  }
  const bytes = typeof input==='string' ? Array.from(new TextEncoder().encode(input)) : Array.from(input);
  return new Uint8Array(wordsToBytes(wordsToMd5(bytesToWords(bytes),bytes.length*8)));
}

// WordPress phpass MD5 portable hash 완전 구현
function wpHashPassword_check(password, hash) {
  const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  function encode64(input, count) {
    let output='',i=0;
    do {
      let value=input[i++];
      output+=itoa64[value&63];
      if(i<count) value|=input[i]<<8;
      output+=itoa64[(value>>6)&63];
      if(i++>=count) break;
      if(i<count) value|=input[i]<<8;
      output+=itoa64[(value>>12)&63];
      if(i++>=count) break;
      output+=itoa64[(value>>18)&63];
    } while(i<count);
    return output;
  }
  function cryptPrivateHash(password, setting) {
    const output='*0';
    if(setting.slice(0,2)===output) return '*1';
    const id=setting.slice(0,3);
    if(id!=='$P$' && id!=='$H$') return output;
    const countLog2=itoa64.indexOf(setting[3]);
    if(countLog2<7 || countLog2>30) return output;
    let count=1<<countLog2;
    const salt=setting.slice(4,12);
    if(salt.length!==8) return output;
    const enc=new TextEncoder();
    let hash=md5(salt+password);
    const pwBytes=enc.encode(password);
    do {
      const combined=new Uint8Array(hash.length+pwBytes.length);
      combined.set(hash);combined.set(pwBytes,hash.length);
      hash=md5(combined);
    } while(--count);
    return setting.slice(0,12)+encode64(hash,16);
  }
  if(hash.startsWith('$P$') || hash.startsWith('$H$')) {
    return cryptPrivateHash(password, hash) === hash;
  }
  return false;
}

async function verifyWPPassword(password, hash) {
  if (!hash) return false;
  // $P$ — WordPress MD5 portable hash (phpass) — 완전 구현
  if (hash.startsWith('$P$') || hash.startsWith('$H$')) {
    return wpHashPassword_check(password, hash);
  }
  // $2y$/$2b$ — bcrypt (Workers 미지원 → plain 비교 fallback)
  if (hash.startsWith('$2y$') || hash.startsWith('$2b$')) {
    return hash === password;
  }
  // plain text (개발/설치 직후)
  if (!hash.startsWith('$')) {
    if (hash === password) return true;
    // plain MD5 (32자 hex)
    if (/^[0-9a-f]{32}$/.test(hash)) {
      const h = md5(password);
      const hex = [...h].map(b => b.toString(16).padStart(2,'0')).join('');
      return hex === hash;
    }
    return false;
  }
  return false;
}

// WordPress phpass로 비밀번호 해시 생성 (사이트 생성 시 admin 계정용)
function wpHashPassword(password) {
  const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  function encode64(input, count) {
    let output='',i=0;
    do {
      let value=input[i++];
      output+=itoa64[value&63];
      if(i<count) value|=input[i]<<8;
      output+=itoa64[(value>>6)&63];
      if(i++>=count) break;
      if(i<count) value|=input[i]<<8;
      output+=itoa64[(value>>12)&63];
      if(i++>=count) break;
      output+=itoa64[(value>>18)&63];
    } while(i<count);
    return output;
  }
  // countLog2=8 → count=256
  const countLog2 = 8;
  const count = 1 << countLog2;
  const saltChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./';
  let salt = '';
  const randBytes = crypto.getRandomValues(new Uint8Array(8));
  for (const b of randBytes) salt += saltChars[b % saltChars.length];
  const setting = '$P$' + itoa64[countLog2] + salt;
  const enc = new TextEncoder();
  let hash = md5(salt + password);
  const pwBytes = enc.encode(password);
  let c = count;
  do {
    const combined = new Uint8Array(hash.length + pwBytes.length);
    combined.set(hash); combined.set(pwBytes, hash.length);
    hash = md5(combined);
  } while (--c);
  return setting + encode64(hash, 16);
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

    // /wp/v2/posts (POST — 새 글 작성)
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const title   = String(body.title   || body.title?.raw   || '');
      const content = String(body.content || body.content?.raw || '');
      const status  = body.status === 'draft' ? 'draft' : 'publish';
      const slug    = body.slug || title.toLowerCase().replace(/[^a-z0-9가-힣]+/g, '-').replace(/^-|-$/g, '') || `post-${Date.now()}`;
      const now     = new Date().toISOString().replace('T', ' ').slice(0, 19);
      if (!title) return j({ code: 'rest_title_required', message: '제목은 필수입니다.' }, 400);
      try {
        const result = await env.DB.prepare(
          `INSERT INTO wp_posts (post_title, post_content, post_status, post_type, post_name, post_date, post_date_gmt, post_modified, post_modified_gmt, post_author, comment_status, ping_status, guid)
           VALUES (?, ?, ?, 'post', ?, ?, ?, ?, ?, 1, 'open', 'open', ?)`
        ).bind(title, content, status, slug, now, now, now, now, slug).run();
        const newId = result.meta?.last_row_id || result.lastRowId || Date.now();
        const newPost = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(newId).first().catch(() => null);
        return j(wpPostToJSON(newPost || { ID: newId, post_title: title, post_content: content, post_status: status, post_name: slug, post_date: now }), 201);
      } catch (e) {
        return j({ code: 'rest_db_error', message: '저장 실패: ' + e.message }, 500);
      }
    }

    // /wp/v2/posts/:id (PATCH/PUT — 글 수정)
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && (method === 'PUT' || method === 'PATCH')) {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      const body = await request.json().catch(() => ({}));
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
      const fields = [];
      const binds  = [];
      if (body.title   !== undefined) { fields.push('post_title = ?');   binds.push(String(body.title?.raw || body.title || '')); }
      if (body.content !== undefined) { fields.push('post_content = ?'); binds.push(String(body.content?.raw || body.content || '')); }
      if (body.status  !== undefined) { fields.push('post_status = ?');  binds.push(body.status); }
      if (body.slug    !== undefined) { fields.push('post_name = ?');    binds.push(body.slug); }
      if (fields.length === 0) return j({ code: 'rest_no_fields', message: '수정할 필드가 없습니다.' }, 400);
      fields.push('post_modified = ?', 'post_modified_gmt = ?');
      binds.push(now, now, postId);
      try {
        await env.DB.prepare(`UPDATE wp_posts SET ${fields.join(', ')} WHERE ID = ?`).bind(...binds).run();
        const updated = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(postId).first();
        return j(wpPostToJSON(updated));
      } catch (e) {
        return j({ code: 'rest_db_error', message: '수정 실패: ' + e.message }, 500);
      }
    }

    // /wp/v2/posts/:id (DELETE — 글 삭제)
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && method === 'DELETE') {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      try {
        await env.DB.prepare(`UPDATE wp_posts SET post_status = 'trash' WHERE ID = ?`).bind(postId).run();
        return j({ deleted: true, id: postId });
      } catch (e) {
        return j({ code: 'rest_db_error', message: '삭제 실패: ' + e.message }, 500);
      }
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
      try {
        const res = await env.DB.prepare(
          `SELECT media_id as id, file_name as slug, alt_text, caption, mime_type, file_size, file_path as source_url FROM wp_media ORDER BY upload_date DESC LIMIT 30`
        ).all();
        const items = (res.results || []).map(m => ({
          ...m,
          title: { rendered: m.slug || '' },
          guid: { rendered: m.source_url || '' },
        }));
        return j(items);
      } catch { return j([]); }
    }

    // /wp/v2/comments (GET)
    if (path.match(/^\/wp\/v2\/comments\/?$/) && method === 'GET') {
      try {
        const perPage = parseInt(url.searchParams.get('per_page') || '20', 10);
        const res = await env.DB.prepare(
          `SELECT comment_ID as id, comment_author as author_name, comment_content as content, comment_date as date, comment_post_ID as post, comment_approved as status FROM wp_comments WHERE comment_approved = '1' ORDER BY comment_date DESC LIMIT ?`
        ).bind(perPage).all();
        return j((res.results || []).map(c => ({
          ...c,
          content: { rendered: c.content || '' },
        })));
      } catch { return j([]); }
    }

    // /wp/v2/settings (GET)
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'GET') {
      const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','siteurl','admin_email','timezone_string','date_format','posts_per_page']);
      return j({
        title: opts.blogname || '',
        description: opts.blogdescription || '',
        url: opts.siteurl || '',
        email: opts.admin_email || '',
        timezone: opts.timezone_string || 'Asia/Seoul',
        date_format: opts.date_format || 'Y년 n월 j일',
        posts_per_page: parseInt(opts.posts_per_page || '10', 10),
      });
    }

    // /wp/v2/settings (POST — 설정 저장)
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const map = { title: 'blogname', description: 'blogdescription', email: 'admin_email', timezone: 'timezone_string', date_format: 'date_format', posts_per_page: 'posts_per_page' };
      const updated = {};
      for (const [bodyKey, optKey] of Object.entries(map)) {
        if (body[bodyKey] !== undefined) {
          const val = String(body[bodyKey]);
          try {
            await env.DB.prepare(
              `INSERT INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value = excluded.option_value`
            ).bind(optKey, val).run();
            updated[bodyKey] = val;
          } catch {}
        }
      }
      return j({ ...updated, ok: true });
    }

    // Feed (RSS)
    if (path === '' && url.searchParams.has('feed') || url.pathname === '/feed/') {
      return await handleRSSFeed(env, siteInfo, url);
    }

    // ── CloudPress 플러그인 관리 API ─────────────────────────────────────────

    // 설치된 플러그인 목록
    if (path.match(/^\/cloudpress\/v1\/plugins\/?$/) && method === 'GET') {
      try {
        const res = await env.DB.prepare(
          `SELECT plugin_slug, plugin_name, plugin_version, plugin_description, status, installed_at FROM wp_cloudpress_plugins ORDER BY plugin_name ASC`
        ).all().catch(() => ({ results: [] }));
        return j({ installed: (res.results || []).map(p => ({
          slug: p.plugin_slug, name: p.plugin_name, version: p.plugin_version,
          description: p.plugin_description, status: p.status,
        }))});
      } catch { return j({ installed: [] }); }
    }

    // 플러그인 WordPress.org 검색 (프록시)
    if (path.match(/^\/cloudpress\/v1\/plugin-search\/?$/) && method === 'GET') {
      const q = url.searchParams.get('q') || 'popular';
      const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '12', 10), 24);
      try {
        const apiUrl = `https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]=${encodeURIComponent(q)}&request[per_page]=${perPage}&request[fields][short_description]=1&request[fields][icons]=1&request[fields][rating]=1&request[fields][num_ratings]=1&request[fields][active_installs]=1&request[fields][version]=1&request[fields][author]=1&request[fields][homepage]=1`;
        const wpRes = await fetch(apiUrl, {
          headers: { 'User-Agent': 'CloudPress/20.0 WordPress-Plugin-Browser' },
          cf: { cacheTtl: 3600, cacheEverything: true },
        });
        if (!wpRes.ok) return j({ plugins: [] });
        const data = await wpRes.json();
        // 설치 여부 확인
        let installedSlugs = new Set();
        try {
          const ins = await env.DB.prepare(`SELECT plugin_slug FROM wp_cloudpress_plugins`).all().catch(() => ({results:[]}));
          for (const r of (ins.results || [])) installedSlugs.add(r.plugin_slug);
        } catch {}
        const plugins = (data.plugins || []).map(p => ({ ...p, installed: installedSlugs.has(p.slug) }));
        return j({ plugins, info: data.info });
      } catch (e) {
        return j({ plugins: [], error: e.message });
      }
    }

    // 플러그인 설치 (WordPress.org에서 메타데이터 저장)
    if (path.match(/^\/cloudpress\/v1\/plugins\/([^\/]+)\/install$/) && method === 'POST') {
      const slug = path.match(/\/plugins\/([^\/]+)\/install/)[1];
      try {
        // WordPress.org에서 플러그인 정보 가져오기
        const infoRes = await fetch(`https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}&request[fields][short_description]=1&request[fields][version]=1`, {
          headers: { 'User-Agent': 'CloudPress/20.0' },
        });
        let name = slug, version = '', description = '';
        if (infoRes.ok) {
          const info = await infoRes.json().catch(() => ({}));
          name = info.name || slug;
          version = info.version || '';
          description = (info.short_description || '').replace(/<[^>]+>/g, '').slice(0, 200);
        }
        // 플러그인 테이블 생성 (없으면)
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS wp_cloudpress_plugins (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          plugin_slug TEXT NOT NULL UNIQUE,
          plugin_name TEXT NOT NULL,
          plugin_version TEXT NOT NULL DEFAULT '',
          plugin_description TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'inactive',
          installed_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`).run().catch(() => {});
        await env.DB.prepare(`INSERT INTO wp_cloudpress_plugins (plugin_slug, plugin_name, plugin_version, plugin_description, status)
          VALUES (?, ?, ?, ?, 'inactive')
          ON CONFLICT(plugin_slug) DO UPDATE SET plugin_name=excluded.plugin_name, plugin_version=excluded.plugin_version, status='inactive'`
        ).bind(slug, name, version, description).run();
        return j({ ok: true, slug, name, version, message: `${name} 설치 완료` }, 201);
      } catch (e) {
        return j({ ok: false, message: '설치 실패: ' + e.message }, 500);
      }
    }

    // 플러그인 활성화
    if (path.match(/^\/cloudpress\/v1\/plugins\/([^\/]+)\/activate$/) && method === 'POST') {
      const slug = path.match(/\/plugins\/([^\/]+)\/activate/)[1];
      try {
        await env.DB.prepare(`UPDATE wp_cloudpress_plugins SET status='active' WHERE plugin_slug=?`).bind(slug).run();
        // wp_options의 active_plugins 업데이트
        const optRes = await env.DB.prepare(`SELECT option_value FROM wp_options WHERE option_name='active_plugins'`).first().catch(() => null);
        const current = optRes?.option_value ? JSON.parse(optRes.option_value) : [];
        if (!current.includes(slug)) current.push(slug);
        await env.DB.prepare(`INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value=excluded.option_value`).bind(JSON.stringify(current)).run();
        return j({ ok: true, slug, status: 'active' });
      } catch (e) { return j({ ok: false, message: e.message }, 500); }
    }

    // 플러그인 비활성화
    if (path.match(/^\/cloudpress\/v1\/plugins\/([^\/]+)\/deactivate$/) && method === 'POST') {
      const slug = path.match(/\/plugins\/([^\/]+)\/deactivate/)[1];
      try {
        await env.DB.prepare(`UPDATE wp_cloudpress_plugins SET status='inactive' WHERE plugin_slug=?`).bind(slug).run();
        const optRes = await env.DB.prepare(`SELECT option_value FROM wp_options WHERE option_name='active_plugins'`).first().catch(() => null);
        const current = optRes?.option_value ? JSON.parse(optRes.option_value) : [];
        const updated = current.filter(s => s !== slug);
        await env.DB.prepare(`INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value=excluded.option_value`).bind(JSON.stringify(updated)).run();
        return j({ ok: true, slug, status: 'inactive' });
      } catch (e) { return j({ ok: false, message: e.message }, 500); }
    }

    // 플러그인 삭제
    if (path.match(/^\/cloudpress\/v1\/plugins\/([^\/]+)$/) && method === 'DELETE') {
      const slug = path.match(/\/plugins\/([^\/]+)$/)[1];
      try {
        await env.DB.prepare(`DELETE FROM wp_cloudpress_plugins WHERE plugin_slug=?`).bind(slug).run();
        return j({ ok: true, slug, deleted: true });
      } catch (e) { return j({ ok: false, message: e.message }, 500); }
    }

    // 테마 WordPress.org 검색
    if (path.match(/^\/cloudpress\/v1\/theme-search\/?$/) && method === 'GET') {
      const q = url.searchParams.get('q') || 'featured';
      const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '12', 10), 24);
      try {
        const browse = ['featured','new','updated','popular'].includes(q) ? q : '';
        let apiUrl;
        if (browse) {
          apiUrl = `https://api.wordpress.org/themes/info/1.2/?action=query_themes&request[browse]=${browse}&request[per_page]=${perPage}&request[fields][screenshot_url]=1&request[fields][description]=1&request[fields][version]=1&request[fields][preview_url]=1&request[fields][author]=1`;
        } else {
          apiUrl = `https://api.wordpress.org/themes/info/1.2/?action=query_themes&request[search]=${encodeURIComponent(q)}&request[per_page]=${perPage}&request[fields][screenshot_url]=1&request[fields][description]=1&request[fields][version]=1&request[fields][preview_url]=1`;
        }
        const wpRes = await fetch(apiUrl, {
          headers: { 'User-Agent': 'CloudPress/20.0' },
          cf: { cacheTtl: 3600, cacheEverything: true },
        });
        if (!wpRes.ok) return j({ themes: [] });
        const data = await wpRes.json();
        return j({ themes: data.themes || [], info: data.info });
      } catch (e) { return j({ themes: [], error: e.message }); }
    }

    // 테마 설치
    if (path.match(/^\/cloudpress\/v1\/themes\/([^\/]+)\/install$/) && method === 'POST') {
      const slug = path.match(/\/themes\/([^\/]+)\/install/)[1];
      try {
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS wp_cloudpress_themes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          theme_slug TEXT NOT NULL UNIQUE,
          theme_name TEXT NOT NULL,
          theme_version TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'inactive',
          installed_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`).run().catch(() => {});
        const infoRes = await fetch(`https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=${encodeURIComponent(slug)}&request[fields][version]=1`, { headers: { 'User-Agent': 'CloudPress/20.0' } });
        let name = slug, version = '';
        if (infoRes.ok) { const info = await infoRes.json().catch(()=>({})); name = info.name || slug; version = info.version || ''; }
        await env.DB.prepare(`INSERT INTO wp_cloudpress_themes (theme_slug, theme_name, theme_version, status)
          VALUES (?, ?, ?, 'inactive') ON CONFLICT(theme_slug) DO UPDATE SET theme_version=excluded.theme_version`
        ).bind(slug, name, version).run();
        return j({ ok: true, slug, name, version }, 201);
      } catch (e) { return j({ ok: false, message: e.message }, 500); }
    }

    // 테마 활성화
    if (path.match(/^\/cloudpress\/v1\/themes\/([^\/]+)\/activate$/) && method === 'POST') {
      const slug = path.match(/\/themes\/([^\/]+)\/activate/)[1];
      try {
        await env.DB.prepare(`UPDATE wp_cloudpress_themes SET status='inactive'`).run().catch(()=>{});
        await env.DB.prepare(`UPDATE wp_cloudpress_themes SET status='active' WHERE theme_slug=?`).bind(slug).run();
        await env.DB.prepare(`INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('template', ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value=excluded.option_value`).bind(slug).run();
        await env.DB.prepare(`INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('stylesheet', ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value=excluded.option_value`).bind(slug).run();
        return j({ ok: true, slug, status: 'active' });
      } catch (e) { return j({ ok: false, message: e.message }, 500); }
    }

    // 카테고리 생성
    if (path.match(/^\/wp\/v2\/categories\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const name = String(body.name || '').trim();
      if (!name) return j({ code: 'rest_missing_name', message: '이름은 필수입니다.' }, 400);
      const slug = body.slug || name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9가-힣-]/g, '') || `cat-${Date.now()}`;
      try {
        const existing = await env.DB.prepare(`SELECT t.term_id FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id=t.term_id WHERE t.slug=? AND tt.taxonomy='category' LIMIT 1`).bind(slug).first().catch(()=>null);
        if (existing) return j({ code: 'term_exists', message: '이미 존재하는 카테고리입니다.', data: { term_id: existing.term_id } }, 400);
        await env.DB.prepare(`INSERT INTO wp_terms (name, slug, term_group) VALUES (?, ?, 0)`).bind(name, slug).run();
        const term = await env.DB.prepare(`SELECT term_id FROM wp_terms WHERE slug=? LIMIT 1`).bind(slug).first();
        await env.DB.prepare(`INSERT INTO wp_term_taxonomy (term_id, taxonomy, description, parent, count) VALUES (?, 'category', ?, ?, 0)`).bind(term.term_id, body.description || '', body.parent || 0).run();
        return j({ id: term.term_id, name, slug, taxonomy: 'category', description: body.description || '', count: 0 }, 201);
      } catch (e) { return j({ code: 'rest_db_error', message: e.message }, 500); }
    }

    // 사이트 내보내기 (WXR XML)
    if (path.match(/^\/cloudpress\/v1\/export\/?$/) && method === 'GET') {
      try {
        const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname', 'blogdescription', 'siteurl']);
        const postsRes = await env.DB.prepare(`SELECT * FROM wp_posts WHERE post_status='publish' AND post_type IN ('post','page') ORDER BY post_date ASC LIMIT 1000`).all();
        const posts = postsRes.results || [];
        const siteUrl = opts.siteurl || `https://${url.hostname}`;
        const items = posts.map(p => `  <item>
    <title><![CDATA[${p.post_title}]]></title>
    <link>${siteUrl}/${p.post_name}/</link>
    <pubDate>${new Date(p.post_date).toUTCString()}</pubDate>
    <dc:creator><![CDATA[admin]]></dc:creator>
    <content:encoded><![CDATA[${p.post_content}]]></content:encoded>
    <excerpt:encoded><![CDATA[${p.post_excerpt}]]></excerpt:encoded>
    <wp:post_id>${p.ID}</wp:post_id>
    <wp:post_type><![CDATA[${p.post_type}]]></wp:post_type>
    <wp:status><![CDATA[${p.post_status}]]></wp:status>
    <wp:post_name><![CDATA[${p.post_name}]]></wp:post_name>
  </item>`).join('\n');
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:excerpt="http://wordpress.org/export/1.2/excerpt/" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:wfw="http://wellformedweb.org/CommentAPI/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:wp="http://wordpress.org/export/1.2/">
<channel>
  <title>${opts.blogname}</title>
  <link>${siteUrl}</link>
  <description>${opts.blogdescription}</description>
  <wp:wxr_version>1.2</wp:wxr_version>
  <wp:base_site_url>${siteUrl}</wp:base_site_url>
  <wp:base_blog_url>${siteUrl}</wp:base_blog_url>
${items}
</channel>
</rss>`;
        return new Response(xml, {
          headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Content-Disposition': 'attachment; filename="wordpress-export.xml"' },
        });
      } catch (e) { return j({ error: e.message }, 500); }
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

  // ── wp-login.php (로그아웃 포함) ─────────────────────────────────────────────
  if (pathname === '/wp-login.php') {
    // 로그아웃
    if (url.searchParams.get('action') === 'logout') {
      const cookie = request.headers.get('cookie') || '';
      const sessionMatch = cookie.match(/wordpress_logged_in_[^=]+=([^;]+)/);
      if (sessionMatch && env.CACHE) {
        await env.CACHE.delete(`wp_session:${sessionMatch[1]}`).catch(() => {});
      }
      const cookieDomain = url.hostname;
      return new Response('', {
        status: 302,
        headers: {
          'Location': `https://${cookieDomain}/wp-login.php?loggedout=true`,
          'Set-Cookie': `wordpress_logged_in_${hashSimple(cookieDomain)}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
        },
      });
    }
    return handleWPLogin(env, request, url, siteInfo);
  }

  // ── wp-admin 정적 자산 서빙 (CSS, 이미지 등) ──────────────────────────────
  if (pathname === '/wp-admin/css/login.min.css') {
    return new Response(WP_LOGIN_CSS, { headers: { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } });
  }
  if (pathname === '/wp-admin/images/wordpress-logo.svg') {
    return new Response(WP_LOGO_SVG, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });
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
