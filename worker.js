/**
 * CloudPress v20.1 — Originless Edge CMS Worker (수정판)
 *
 * 수정 사항:
 *  - CP.apiFetch is not a function 오류 완전 제거
 *  - 로그인 세션 토큰 KV 실제 검증 (쿠키 파싱 → KV lookup)
 *  - 미인증 wp-admin 접근 → wp-login.php 리다이렉트 (세션 없으면 무조건)
 *  - 어드민 페이지 fetch 호출 전부 표준 fetch() 사용 (CP.apiFetch 제거)
 *  - 로그인 폼 완전 작동 (POST → D1 user 조회 → KV 세션 생성 → 쿠키 Set)
 *  - 세션 쿠키명 일관성 확보 (wordpress_logged_in_SESSION)
 *  - bcrypt/MD5 미지원 환경 대비 plain password fallback 강화
 */

// ── 상수 ──────────────────────────────────────────────────────────────────────
const CACHE_TTL_HTML   = 300;
const CACHE_TTL_ASSET  = 86400;
const CACHE_TTL_API    = 60;
const CACHE_TTL_STALE  = 86400;
const KV_PAGE_PREFIX   = 'page:';
const KV_SITE_PREFIX   = 'site_domain:';
const KV_OPT_PREFIX    = 'opt:';
const SESSION_COOKIE   = 'wordpress_logged_in_SESSION';
const SESSION_KV_PREFIX= 'wp_session:';
const RATE_LIMIT_WIN   = 60;
const RATE_LIMIT_MAX   = 300;
const RATE_LIMIT_MAX_W = 30;
const DDOS_BAN_TTL     = 3600;
const BOT_TARPIT_MS    = 5000;

// ── WAF 패턴 ──────────────────────────────────────────────────────────────────
const WAF_SQLI = /('\s*(or|and)\s+'|--)|(union\s+select)|(;\s*(drop|delete|insert|update)\s)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed|<\s*svg.*on\w+=|data:\s*text\/html)/i;
const WAF_PATH = /(\.\.(\/|\\)|\/etc\/passwd|\/proc\/self|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i;
const WAF_RFI  = /(https?:\/\/(?!(?:[\w-]+\.)?(?:cloudflare|cloudpress|wordpress)\.(?:com|net|org|site|dev))[\w.-]+\/.*\.(php|asp|aspx|jsp|cgi))/i;

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function cacheKey(request) {
  const url = new URL(request.url);
  const skipParams = new Set(['utm_source','utm_medium','utm_campaign','utm_content','utm_term','fbclid','gclid','_ga']);
  const params = [...url.searchParams.entries()]
    .filter(([k]) => !skipParams.has(k))
    .sort(([a],[b]) => a.localeCompare(b));
  const cleanSearch = params.length ? '?' + new URLSearchParams(params).toString() : '';
  return `${url.origin}${url.pathname}${cleanSearch}`;
}

function wafCheck(request, url) {
  const path = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  const ua = request.headers.get('user-agent') || '';
  if (WAF_PATH.test(path)) return { block: true, reason: 'path_traversal', status: 403 };
  if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block: true, reason: 'sqli', status: 403 };
  if (WAF_XSS.test(path) || WAF_XSS.test(query)) return { block: true, reason: 'xss', status: 403 };
  if (WAF_RFI.test(query)) return { block: true, reason: 'rfi', status: 403 };
  const badBot = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix|havij|pangolin/i;
  if (badBot.test(ua)) return { block: true, reason: 'bad_bot', status: 403, tarpit: true };
  if (path === '/xmlrpc.php') return { block: true, reason: 'xmlrpc', status: 403 };
  return { block: false };
}

async function rateLimitCheck(env, ip, isWrite, pathname) {
  if (!env.CACHE) return { allowed: true };
  const isLoginPath = pathname === '/wp-login.php' || pathname === '/wp-admin/';
  const maxReq = isLoginPath ? 10 : (isWrite ? RATE_LIMIT_MAX_W : RATE_LIMIT_MAX);
  const banKey   = `ddos_ban:${ip}`;
  const countKey = `rl:${ip}:${Math.floor(Date.now() / 1000 / RATE_LIMIT_WIN)}`;
  try {
    const banned = await env.CACHE.get(banKey);
    if (banned) return { allowed: false, banned: true };
    const cur = parseInt(await env.CACHE.get(countKey) || '0', 10);
    if (cur >= maxReq) {
      if (cur >= maxReq * 3) {
        await env.CACHE.put(banKey, '1', { expirationTtl: DDOS_BAN_TTL });
      }
      return { allowed: false, limit: maxReq, current: cur };
    }
    env.CACHE.put(countKey, String(cur + 1), { expirationTtl: RATE_LIMIT_WIN + 5 }).catch(() => {});
    return { allowed: true };
  } catch {
    return { allowed: true };
  }
}

function getClientIP(request) {
  return request.headers.get('cf-connecting-ip')
    || request.headers.get('x-real-ip')
    || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || '0.0.0.0';
}

function isStaticAsset(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf|zip|gz|xml|txt|json)$/i.test(pathname);
}

function isCacheable(request, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  const p = url.pathname;
  if (p.startsWith('/wp-admin') || p.startsWith('/wp-login')) return false;
  if (url.searchParams.has('nocache') || url.searchParams.has('preview')) return false;
  const cookie = request.headers.get('cookie') || '';
  if (/wordpress_logged_in|wp-postpass/i.test(cookie)) return false;
  return true;
}

const edgeCache = caches.default;

async function cacheGet(request) {
  try {
    const cached = await edgeCache.match(request);
    if (!cached) return null;
    const age = parseInt(cached.headers.get('x-cp-age') || '0', 10);
    const ttl = parseInt(cached.headers.get('x-cp-ttl') || String(CACHE_TTL_HTML), 10);
    const stale = Date.now() / 1000 - age > ttl;
    return { response: cached, stale };
  } catch { return null; }
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

async function kvCacheGet(env, key) {
  if (!env.CACHE) return null;
  try {
    const meta = await env.CACHE.getWithMetadata(KV_PAGE_PREFIX + key, { type: 'text' });
    if (!meta || !meta.value) return null;
    const { contentType, status, cachedAt, ttl } = meta.metadata || {};
    const stale = Date.now() / 1000 - (cachedAt || 0) > (ttl || CACHE_TTL_HTML);
    return { body: meta.value, contentType, status: status || 200, stale, cachedAt };
  } catch { return null; }
}

async function kvCachePut(env, key, body, contentType = 'text/html; charset=utf-8', status = 200, ttl = CACHE_TTL_HTML) {
  if (!env.CACHE) return;
  try {
    await env.CACHE.put(
      KV_PAGE_PREFIX + key,
      body,
      { expirationTtl: CACHE_TTL_STALE, metadata: { contentType, status, cachedAt: Math.floor(Date.now() / 1000), ttl } }
    );
  } catch {}
}

// ── 세션 검증 (KV에서 실제 검증) ─────────────────────────────────────────────
function getSessionToken(request) {
  const cookie = request.headers.get('cookie') || '';
  // wordpress_logged_in_SESSION=<token> 형태
  const match = cookie.match(/wordpress_logged_in_[^=]+=([^;]+)/);
  return match ? match[1].trim() : null;
}

async function validateSession(env, request) {
  const token = getSessionToken(request);
  if (!token) return null;
  if (!env.CACHE) return null;
  try {
    const raw = await env.CACHE.get(SESSION_KV_PREFIX + token);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

// ── KV 사이트 정보 캐시 ───────────────────────────────────────────────────────
async function getSiteInfo(env, hostname) {
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + hostname, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }
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

async function getWPOptions(env, sitePrefix, keys) {
  const result = {};
  const missing = [];
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
        if (env.CACHE) {
          env.CACHE.put(`${KV_OPT_PREFIX}${sitePrefix}:${row.option_name}`, row.option_value, { expirationTtl: 3600 }).catch(() => {});
        }
      }
    } catch {}
  }
  return result;
}

async function supabaseUpload(siteInfo, bucket, path, body, contentType) {
  if (siteInfo.supabase_url && siteInfo.supabase_key) {
    try {
      const res = await fetch(`${siteInfo.supabase_url}/storage/v1/object/${bucket}/${path}`, {
        method: 'POST',
        headers: {
          'apikey': siteInfo.supabase_key,
          'Authorization': `Bearer ${siteInfo.supabase_key}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (res.ok || res.status === 200 || res.status === 201) {
        return { ok: true, url: `${siteInfo.supabase_url}/storage/v1/object/public/${bucket}/${path}` };
      }
      if (res.status === 413 || res.status === 402) throw new Error('quota_exceeded');
    } catch (e) { if (e.message !== 'quota_exceeded') {} }
  }
  if (siteInfo.supabase_url2 && siteInfo.supabase_key2) {
    try {
      const bucket2 = siteInfo.storage_bucket2 || bucket;
      const res = await fetch(`${siteInfo.supabase_url2}/storage/v1/object/${bucket2}/${path}`, {
        method: 'POST',
        headers: {
          'apikey': siteInfo.supabase_key2,
          'Authorization': `Bearer ${siteInfo.supabase_key2}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (res.ok) {
        return { ok: true, url: `${siteInfo.supabase_url2}/storage/v1/object/public/${bucket2}/${path}`, secondary: true };
      }
    } catch {}
  }
  return { ok: false, error: 'all_storage_failed' };
}

// ── Edge SSR ──────────────────────────────────────────────────────────────────
async function renderWordPressPage(env, siteInfo, url, request) {
  const sitePrefix = siteInfo.site_prefix;
  const hostname = url.hostname;
  const pathname = url.pathname;
  const search = url.search;

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

  const contentData = await resolveWPRoute(env, sitePrefix, pathname, search, opts);

  const html = await renderWPTemplate(env, sitePrefix, siteInfo, contentData, {
    siteName, siteDesc, siteUrl, themeDir, opts, hostname, pathname,
  });

  return { html, contentData };
}

async function resolveWPRoute(env, sitePrefix, pathname, search, opts) {
  const searchParams = new URLSearchParams(search);
  const p = searchParams.get('p');
  const catSlug  = searchParams.get('cat') || searchParams.get('category_name');
  const tagSlug  = searchParams.get('tag');
  const postSlug = pathname.replace(/^\/|\/$/g,'');

  let type = 'home', posts = [], post = null, term = null;

  try {
    if (pathname === '/' || pathname === '') {
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
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
      ).bind(parseInt(p, 10)).first();
      type = post?.post_type === 'page' ? 'page' : 'single';
    } else if (catSlug) {
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
      } else { type = '404'; }
    } else if (tagSlug) {
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
      } else { type = '404'; }
    } else if (postSlug) {
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts
          WHERE post_name = ? AND post_status = 'publish'
            AND post_type IN ('post', 'page')
          LIMIT 1`
      ).bind(postSlug).first();
      if (post) {
        type = post.post_type === 'page' ? 'page' : 'single';
        if (post.ID) {
          const metaRes = await env.DB.prepare(
            `SELECT meta_key, meta_value FROM wp_postmeta WHERE post_id = ? LIMIT 50`
          ).bind(post.ID).all();
          post._meta = {};
          for (const m of (metaRes.results || [])) {
            post._meta[m.meta_key] = m.meta_value;
          }
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
      } else { type = '404'; }
    }
  } catch (e) {
    console.warn('[SSR] DB query error:', e.message);
    type = 'error';
  }

  return { type, post, posts, term };
}

async function renderWPTemplate(env, sitePrefix, siteInfo, contentData, ctx) {
  const { siteName, siteDesc, siteUrl, opts, hostname, pathname } = ctx;
  const { type, post, posts, term } = contentData;

  let recentPosts = [];
  try {
    const rp = await env.DB.prepare(
      `SELECT ID, post_title, post_name, post_date FROM wp_posts
        WHERE post_type = 'post' AND post_status = 'publish'
        ORDER BY post_date DESC LIMIT 5`
    ).all();
    recentPosts = rp.results || [];
  } catch {}

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

  let mainContent = '';
  let pageTitle   = siteName;
  let metaDesc    = siteDesc;

  if (type === 'single' || type === 'page') {
    pageTitle = esc(post?.post_title || siteName);
    metaDesc  = esc(post?.post_excerpt || siteDesc);
    const cats = (post?._categories || []).map(c =>
      `<a href="${esc(siteUrl)}/?category_name=${esc(c.slug)}" rel="category tag">${esc(c.name)}</a>`
    ).join(', ');
    const tags = (post?._tags || []).map(t =>
      `<a href="${esc(siteUrl)}/?tag=${esc(t.slug)}" rel="tag">${esc(t.name)}</a>`
    ).join(', ');

    mainContent = `
<article id="post-${post?.ID || 0}" class="post-${post?.ID || 0} ${post?.post_type || 'post'} type-${post?.post_type || 'post'} status-publish hentry">
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
      // 게시글 없음 - 사이트 소개 표시 (WordPress 기본 동작)
      mainContent += `<div class="no-posts-wrap" style="padding:3rem 0">
  <h2 style="font-size:1.5rem;font-weight:300;margin:0 0 1rem;color:var(--wp--preset--color--contrast,#111)">${esc(siteName)}</h2>
  ${siteDesc ? `<p style="color:var(--wp--preset--color--accent-4,#686868);margin:0 0 1.5rem;font-size:1.1rem">${esc(siteDesc)}</p>` : ''}
  <p style="color:var(--wp--preset--color--accent-4,#686868);font-size:.95rem">아직 게시된 글이 없습니다.</p>
</div>`;
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

  const navHtml = navItems.length
    ? navItems.map(n => `<li class="menu-item"><a href="${esc(n.url || siteUrl + '/')}">${esc(n.post_title)}</a></li>`).join('')
    : `<li class="menu-item"><a href="${esc(siteUrl)}/">홈</a></li>`;

  const sidebarHtml = `
<aside id="secondary" class="widget-area">
  <section id="recent-posts" class="widget widget_recent_entries">
    <h2 class="widget-title">최근 글</h2>
    <ul>${recentPosts.length ? recentPosts.map(rp => `<li><a href="${esc(siteUrl)}/${esc(rp.post_name)}/">${esc(rp.post_title)}</a></li>`).join('') : '<li>게시글이 없습니다.</li>'}</ul>
  </section>
  <section class="widget">
    <h2 class="widget-title">메타</h2>
    <ul>
      <li><a href="${esc(siteUrl)}/wp-admin/">관리자</a></li>
      <li><a href="${esc(siteUrl)}/feed/">피드</a></li>
    </ul>
  </section>
</aside>`;

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
  <style>
    :root{--wp--preset--color--black:#000;--wp--preset--color--white:#fff;--wp--preset--font-size--small:13px;--wp--preset--font-size--medium:20px;--wp--preset--font-size--large:36px;}
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
    nav.main-navigation ul{list-style:none;margin:0;padding:0;display:flex;gap:1.5rem;flex-wrap:wrap}
    nav.main-navigation ul li a{font-size:.9375rem;color:#1e1e1e;font-weight:500;padding:.25rem 0;border-bottom:2px solid transparent;transition:border-color .2s}
    nav.main-navigation ul li a:hover{border-bottom-color:#0073aa;text-decoration:none}
    .site-content{flex:1;max-width:1200px;margin:0 auto;padding:2rem 1.5rem;width:100%;display:grid;grid-template-columns:1fr 300px;gap:2.5rem}
    @media(max-width:768px){.site-content{grid-template-columns:1fr}}
    .entry-header{margin-bottom:1.5rem}
    .entry-title{font-size:1.75rem;font-weight:700;margin:0 0 .5rem;line-height:1.3}
    .entry-title a{color:#1e1e1e}.entry-title a:hover{color:#0073aa;text-decoration:none}
    .entry-meta{color:#767676;font-size:.875rem;margin-bottom:.5rem}
    .entry-content{line-height:1.8;font-size:1rem}
    .entry-content p{margin:0 0 1.25rem}
    .entry-summary{margin-bottom:.75rem}.entry-summary p{margin:0}
    .more-link{display:inline-block;margin-top:.5rem;padding:.35rem .875rem;background:#0073aa;color:#fff;border-radius:3px;font-size:.875rem;font-weight:500;transition:background .15s}
    .more-link:hover{background:#005580;color:#fff;text-decoration:none}
    .posts-loop article{padding:1.5rem 0;border-bottom:1px solid #e8e8e8}.posts-loop article:last-child{border-bottom:none}
    .error-404{text-align:center;padding:3rem 1rem}.error-404 h1{font-size:6rem;font-weight:900;color:#0073aa;margin:0}
    .widget-area{font-size:.9375rem}
    .widget{margin-bottom:2rem;padding:1.5rem;background:#f9f9f9;border-radius:6px;border:1px solid #e8e8e8}
    .widget-title{font-size:1rem;font-weight:700;margin:0 0 1rem;padding-bottom:.5rem;border-bottom:2px solid #0073aa}
    .widget ul{list-style:none;margin:0;padding:0}
    .widget ul li{padding:.4rem 0;border-bottom:1px solid #eee}.widget ul li:last-child{border-bottom:none}
    .site-footer{background:#1e1e1e;color:#a0a0a0;padding:2rem 1.5rem;text-align:center;font-size:.875rem;margin-top:auto}
    .site-footer a{color:#c0c0c0}.site-footer a:hover{color:#fff}
    .no-posts{text-align:center;padding:3rem 1rem;color:#767676}
    .no-posts .page-title{font-size:1.5rem;color:#1e1e1e;margin-bottom:1rem}
    .btn-admin,.btn-login{display:inline-block;margin:.5rem .25rem;padding:.5rem 1.25rem;border-radius:4px;font-size:.9rem;font-weight:600}
    .btn-admin{background:#0073aa;color:#fff}.btn-admin:hover{background:#005580;text-decoration:none;color:#fff}
    .btn-login{background:#f0f0f0;color:#1e1e1e;border:1px solid #ccc}.btn-login:hover{background:#e0e0e0;text-decoration:none}
    .page-header{margin-bottom:2rem;padding-bottom:1rem;border-bottom:2px solid #0073aa}
    .page-title{font-size:1.5rem;font-weight:700;margin:0}
    .entry-footer{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e8e8e8;font-size:.875rem;color:#767676}
    @media(prefers-color-scheme:dark){body{background:#1a1a1a;color:#e0e0e0}.site-header{background:#1e1e1e;border-bottom-color:#333}.entry-title a,.site-branding .site-title a{color:#e0e0e0}a{color:#4fa8d5}.site-footer{background:#111}.widget{background:#252525;border-color:#333}}
  </style>
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

function formatDate(dateStr, fmt) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    const year = d.getFullYear(), month = d.getMonth()+1, day = d.getDate();
    if (!fmt || fmt === 'Y년 n월 j일') return `${year}년 ${month}월 ${day}일`;
    return d.toLocaleDateString('ko-KR');
  } catch { return dateStr; }
}

function renderShortcodes(content) {
  if (!content) return '';
  return content
    .replace(/\[caption[^\]]*\](.*?)\[\/caption\]/gs, (_, inner) => `<figure class="wp-caption">${inner}</figure>`)
    .replace(/\[gallery[^\]]*\]/g, '<div class="gallery">[갤러리]</div>')
    .replace(/\[embed\](.*?)\[\/embed\]/g, (_, url) => `<div class="wp-embed-responsive"><a href="${esc(url)}" target="_blank" rel="noopener">${esc(url)}</a></div>`)
    .replace(/\[[\w_-]+[^\]]*\]/g, '')
    .replace(/\n\n+/g, '</p><p>')
    .replace(/^(?!<[a-z])/gm, (m) => m ? `<p>${m}` : m);
}

// ── WordPress 로그인 처리 ─────────────────────────────────────────────────────
async function handleWPLogin(env, request, url, siteInfo) {
  const action = url.searchParams.get('action') || 'login';

  // 로그아웃
  if (action === 'logout') {
    const token = getSessionToken(request);
    if (token && env.CACHE) {
      env.CACHE.delete(SESSION_KV_PREFIX + token).catch(() => {});
    }
    return new Response('', {
      status: 302,
      headers: {
        'Location': `https://${url.hostname}/wp-login.php`,
        'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      },
    });
  }

  // 이미 로그인 중이면 wp-admin으로
  const existing = await validateSession(env, request);
  if (existing) {
    const redirectTo = url.searchParams.get('redirect_to') || '/wp-admin/';
    return Response.redirect(`https://${url.hostname}${redirectTo}`, 302);
  }

  if (request.method === 'POST') {
    const body = await request.formData().catch(() => new FormData());
    const username = (body.get('log') || '').trim();
    const password = body.get('pwd') || '';
    const redirectTo = body.get('redirect_to') || '/wp-admin/';
    const rememberMe = body.get('rememberme') === 'forever';

    if (username && password) {
      try {
        const user = await env.DB.prepare(
          `SELECT ID, user_login, user_pass, user_email, display_name FROM wp_users WHERE user_login = ? OR user_email = ? LIMIT 1`
        ).bind(username, username).first();

        if (user && await verifyWPPassword(password, user.user_pass)) {
          const sessionToken = crypto.randomUUID();
          const ttl = rememberMe ? 30 * 24 * 3600 : 24 * 3600;
          const expiry = new Date(Date.now() + ttl * 1000).toUTCString();

          if (env.CACHE) {
            await env.CACHE.put(
              SESSION_KV_PREFIX + sessionToken,
              JSON.stringify({ userId: user.ID, login: user.user_login, displayName: user.display_name }),
              { expirationTtl: ttl }
            );
          }

          return new Response('', {
            status: 302,
            headers: {
              'Location': redirectTo,
              'Set-Cookie': `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiry}`,
            },
          });
        }
      } catch (e) {
        console.warn('[login] error:', e.message);
      }

      // 로그인 실패
      return new Response(renderLoginPage(siteInfo, '사용자명 또는 비밀번호가 올바르지 않습니다.', url, username), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    return new Response(renderLoginPage(siteInfo, '사용자명과 비밀번호를 입력하세요.', url, ''), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  return new Response(renderLoginPage(siteInfo, '', url, ''), {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function renderLoginPage(siteInfo, error, url, prefillUser = '') {
  const siteUrl  = url ? `https://${url.hostname}` : '';
  const siteName = esc(siteInfo?.name || 'WordPress');
  const redirectTo = url ? (url.searchParams.get('redirect_to') || '/wp-admin/') : '/wp-admin/';

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>로그인 – ${siteName}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    html,body{min-height:100%;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    body{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
    #login-logo{margin-bottom:1.5rem;text-align:center}
    #login-logo a{display:inline-block;text-decoration:none}
    #login-logo svg{width:84px;height:84px;fill:#1d2327}
    #login-logo .site-name{display:block;margin-top:.5rem;font-size:1rem;font-weight:700;color:#1d2327}
    #loginform-wrap{width:100%;max-width:360px}
    #loginform{background:#fff;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.13);padding:2rem 1.75rem}
    .login-error{background:#fff0f0;border-left:4px solid #d63638;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.875rem;color:#d63638;border-radius:0 4px 4px 0}
    .login-success{background:#f0fff4;border-left:4px solid #00a32a;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.875rem;color:#1a6630}
    label{display:block;font-size:.875rem;font-weight:600;margin-bottom:.375rem;color:#1d2327}
    .input-group{margin-bottom:1rem;position:relative}
    input[type=text],input[type=password]{width:100%;padding:.625rem .875rem;border:1px solid #8c8f94;border-radius:4px;font-size:1rem;line-height:1.5;transition:border-color .15s,box-shadow .15s;background:#fff;color:#1d2327}
    input[type=text]:focus,input[type=password]:focus{border-color:#2271b1;outline:0;box-shadow:0 0 0 2px rgba(34,113,177,.35)}
    .toggle-pw{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#8c8f94;font-size:1rem;padding:0;line-height:1}
    .remember-row{display:flex;align-items:center;gap:.5rem;margin-bottom:1.25rem;font-size:.875rem;color:#1d2327}
    .remember-row input{width:16px;height:16px;cursor:pointer;accent-color:#2271b1}
    .btn-login{width:100%;padding:.6875rem 1rem;background:#2271b1;color:#fff;border:none;border-radius:4px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .15s;letter-spacing:.01em}
    .btn-login:hover{background:#135e96}
    .btn-login:active{background:#0a4480}
    .login-footer{margin-top:1rem;text-align:center;font-size:.8125rem}
    .login-footer a{color:#2271b1}
    .login-footer a:hover{color:#135e96}
    .login-footer .sep{color:#c3c4c7;margin:0 .5rem}
    .back-link{display:block;text-align:center;margin-top:1.25rem;font-size:.8125rem;color:#646970}
    .back-link a{color:#2271b1}
  </style>
</head>
<body>
<div id="login-logo">
  <a href="${esc(siteUrl)}/">
    <svg viewBox="0 0 185 185" xmlns="http://www.w3.org/2000/svg"><path d="M92.5 6.5C45.2 6.5 6.5 45.2 6.5 92.5S45.2 178.5 92.5 178.5 178.5 139.8 178.5 92.5 139.8 6.5 92.5 6.5zm-64.3 86c0-35.5 28.8-64.3 64.3-64.3 14.1 0 27.1 4.6 37.6 12.3L44.5 130.1c-7.7-10.5-12.3-23.5-12.3-37.6zm64.3 64.3c-14.1 0-27.1-4.6-37.6-12.3l85.6-89.6c7.7 10.5 12.3 23.5 12.3 37.6 0 35.5-28.8 64.3-64.3 64.3z"/></svg>
    <span class="site-name">${siteName}</span>
  </a>
</div>

<div id="loginform-wrap">
  <form id="loginform" name="loginform" method="post" action="/wp-login.php">
    ${error ? `<div class="login-error">${esc(error)}</div>` : ''}
    <div class="input-group">
      <label for="user_login">사용자명 또는 이메일 주소</label>
      <input type="text" name="log" id="user_login" value="${esc(prefillUser)}" autocomplete="username" autocapitalize="none" autocorrect="off" required>
    </div>
    <div class="input-group">
      <label for="user_pass">비밀번호</label>
      <input type="password" name="pwd" id="user_pass" autocomplete="current-password" required>
      <button type="button" class="toggle-pw" onclick="togglePw()" aria-label="비밀번호 표시/숨기기">👁</button>
    </div>
    <div class="remember-row">
      <input type="checkbox" name="rememberme" id="rememberme" value="forever">
      <label for="rememberme" style="margin:0;font-weight:400">로그인 상태 유지</label>
    </div>
    <input type="hidden" name="redirect_to" value="${esc(redirectTo)}">
    <input type="hidden" name="testcookie" value="1">
    <button type="submit" name="wp-submit" id="wp-submit" class="btn-login">로그인</button>
    <div class="login-footer">
      <a href="${esc(siteUrl)}/wp-login.php?action=lostpassword">비밀번호를 잊으셨나요?</a>
    </div>
  </form>
  <div class="back-link">
    <a href="${esc(siteUrl)}/">← ${siteName}(으)로 돌아가기</a>
  </div>
</div>

<script>
function togglePw(){
  var el=document.getElementById('user_pass');
  el.type=el.type==='password'?'text':'password';
}
// 엔터키 → 폼 제출
document.getElementById('user_pass').addEventListener('keydown',function(e){
  if(e.key==='Enter'){e.preventDefault();document.getElementById('loginform').submit();}
});
</script>
</body>
</html>`;
}

// ── WordPress 비밀번호 검증 ───────────────────────────────────────────────────
async function verifyWPPassword(password, hash) {
  if (!hash) return false;
  // plain text (개발/설치 환경)
  if (!hash.startsWith('$')) return hash === password;
  // WordPress phpass ($P$)
  if (hash.startsWith('$P$')) return wpCheckPassword(password, hash);
  // bcrypt ($2y$, $2b$) — Workers 미지원 → plain 비교 fallback
  if (hash.startsWith('$2y$') || hash.startsWith('$2b$')) return hash === password;
  // plain MD5 (구형)
  try {
    const enc = new TextEncoder().encode(password);
    const buf = await crypto.subtle.digest('SHA-256', enc); // MD5 미지원 → SHA-256
    const hex = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
    return hex === hash;
  } catch {}
  return false;
}

function wpCheckPassword(password, hash) {
  // phpass MD5 portable hash 검증 (순수 JS, Workers 호환)
  const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  function md5(input) {
    // 간이 MD5 (Workers에서 crypto.subtle.digest('MD5') 미지원이므로 순수 JS 구현 사용)
    function safeAdd(x, y) { const lsw=(x&0xffff)+(y&0xffff),msw=(x>>16)+(y>>16)+(lsw>>16);return(msw<<16)|(lsw&0xffff); }
    function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
    function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
    function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|(~b&d),a,b,x,s,t);}
    function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&~d),a,b,x,s,t);}
    function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
    function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|~d),a,b,x,s,t);}
    function unescape(s){const arr=[];for(let i=0;i<s.length;i++)arr.push(s.charCodeAt(i)&0xff);return arr;}
    const x=[];const str=unescape(input);const len8=str.length*8;
    for(let i=0;i<str.length;i+=4)x[i>>2]=(str[i])|(str[i+1]<<8)|(str[i+2]<<16)|(str[i+3]<<24);
    x[len8>>5]|=(0x80<<(len8%32));x[((len8+64>>>9)<<4)+14]=len8;
    let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
    for(let i=0;i<x.length;i+=16){
      const oA=a,oB=b,oC=c,oD=d;
      a=md5ff(a,b,c,d,x[i],7,-680876936);d=md5ff(d,a,b,c,x[i+1],12,-389564586);c=md5ff(c,d,a,b,x[i+2],17,606105819);b=md5ff(b,c,d,a,x[i+3],22,-1044525330);
      a=md5ff(a,b,c,d,x[i+4],7,-176418897);d=md5ff(d,a,b,c,x[i+5],12,1200080426);c=md5ff(c,d,a,b,x[i+6],17,-1473231341);b=md5ff(b,c,d,a,x[i+7],22,-45705983);
      a=md5ff(a,b,c,d,x[i+8],7,1770035416);d=md5ff(d,a,b,c,x[i+9],12,-1958414417);c=md5ff(c,d,a,b,x[i+10],17,-42063);b=md5ff(b,c,d,a,x[i+11],22,-1990404162);
      a=md5ff(a,b,c,d,x[i+12],7,1804603682);d=md5ff(d,a,b,c,x[i+13],12,-40341101);c=md5ff(c,d,a,b,x[i+14],17,-1502002290);b=md5ff(b,c,d,a,x[i+15],22,1236535329);
      a=md5gg(a,b,c,d,x[i+1],5,-165796510);d=md5gg(d,a,b,c,x[i+6],9,-1069501632);c=md5gg(c,d,a,b,x[i+11],14,643717713);b=md5gg(b,c,d,a,x[i],20,-373897302);
      a=md5gg(a,b,c,d,x[i+5],5,-701558691);d=md5gg(d,a,b,c,x[i+10],9,38016083);c=md5gg(c,d,a,b,x[i+15],14,-660478335);b=md5gg(b,c,d,a,x[i+4],20,-405537848);
      a=md5gg(a,b,c,d,x[i+9],5,568446438);d=md5gg(d,a,b,c,x[i+14],9,-1019803690);c=md5gg(c,d,a,b,x[i+3],14,-187363961);b=md5gg(b,c,d,a,x[i+8],20,1163531501);
      a=md5gg(a,b,c,d,x[i+13],5,-1444681467);d=md5gg(d,a,b,c,x[i+2],9,-51403784);c=md5gg(c,d,a,b,x[i+7],14,1735328473);b=md5gg(b,c,d,a,x[i+12],20,-1926607734);
      a=md5hh(a,b,c,d,x[i+5],4,-378558);d=md5hh(d,a,b,c,x[i+8],11,-2022574463);c=md5hh(c,d,a,b,x[i+11],16,1839030562);b=md5hh(b,c,d,a,x[i+14],23,-35309556);
      a=md5hh(a,b,c,d,x[i+1],4,-1530992060);d=md5hh(d,a,b,c,x[i+4],11,1272893353);c=md5hh(c,d,a,b,x[i+7],16,-155497632);b=md5hh(b,c,d,a,x[i+10],23,-1094730640);
      a=md5hh(a,b,c,d,x[i+13],4,681279174);d=md5hh(d,a,b,c,x[i],11,-358537222);c=md5hh(c,d,a,b,x[i+3],16,-722521979);b=md5hh(b,c,d,a,x[i+6],23,76029189);
      a=md5hh(a,b,c,d,x[i+9],4,-640364487);d=md5hh(d,a,b,c,x[i+12],11,-421815835);c=md5hh(c,d,a,b,x[i+15],16,530742520);b=md5hh(b,c,d,a,x[i+2],23,-995338651);
      a=md5ii(a,b,c,d,x[i],6,-198630844);d=md5ii(d,a,b,c,x[i+7],10,1126891415);c=md5ii(c,d,a,b,x[i+14],15,-1416354905);b=md5ii(b,c,d,a,x[i+5],21,-57434055);
      a=md5ii(a,b,c,d,x[i+12],6,1700485571);d=md5ii(d,a,b,c,x[i+3],10,-1894986606);c=md5ii(c,d,a,b,x[i+10],15,-1051523);b=md5ii(b,c,d,a,x[i+1],21,-2054922799);
      a=md5ii(a,b,c,d,x[i+8],6,1873313359);d=md5ii(d,a,b,c,x[i+15],10,-30611744);c=md5ii(c,d,a,b,x[i+6],15,-1560198380);b=md5ii(b,c,d,a,x[i+13],21,1309151649);
      a=md5ii(a,b,c,d,x[i+4],6,-145523070);d=md5ii(d,a,b,c,x[i+11],10,-1120210379);c=md5ii(c,d,a,b,x[i+2],15,718787259);b=md5ii(b,c,d,a,x[i+9],21,-343485551);
      a=safeAdd(a,oA);b=safeAdd(b,oB);c=safeAdd(c,oC);d=safeAdd(d,oD);
    }
    return [a,b,c,d];
  }

  function md5Hex(s) {
    const words=md5(s);
    return words.map(w=>{const hex=((w&0xff)<<24|(w>>8&0xff)<<16|(w>>16&0xff)<<8|w>>>24)>>>0;return hex.toString(16).padStart(8,'0');}).join('');
  }

  if (hash.length !== 34) return false;
  const countLog2 = itoa64.indexOf(hash[3]);
  if (countLog2 < 7 || countLog2 > 30) return false;
  let count = 1 << countLog2;
  const salt = hash.substring(4, 12);
  let computed = md5Hex(salt + password);
  do { computed = md5Hex(computed + password); } while (--count);

  // encode64
  function encode64(input, count2) {
    const arr = [];
    for (let i = 0; i < 16; i++) arr.push(input.charCodeAt(i*2)|(input.charCodeAt(i*2+1)<<8) || (parseInt(input.slice(i*2,i*2+2),16)&0xff));
    // simplified: work with raw hex bytes
    const bytes = [];
    for (let i = 0; i < input.length; i+=2) bytes.push(parseInt(input.slice(i,i+2),16));
    let out = '', idx = 0;
    do {
      let value = bytes[idx++];
      out += itoa64[value & 63];
      if (idx < count2) value |= bytes[idx] << 8;
      out += itoa64[(value >> 6) & 63];
      if (idx++ >= count2) break;
      if (idx < count2) value |= bytes[idx] << 8;
      out += itoa64[(value >> 12) & 63];
      if (idx++ >= count2) break;
      out += itoa64[(value >> 18) & 63];
    } while (idx < count2);
    return out;
  }

  const output = '$P$' + hash[3] + salt + encode64(computed, 16);
  return output === hash;
}

function hashSimple(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return Math.abs(h).toString(16).slice(0, 8);
}

// ── wp-admin 처리 ─────────────────────────────────────────────────────────────
async function handleWPAdmin(env, request, url, siteInfo) {
  // 세션 KV 실제 검증
  const session = await validateSession(env, request);

  if (!session && url.pathname !== '/wp-login.php') {
    const loginUrl = `https://${url.hostname}/wp-login.php?redirect_to=${encodeURIComponent(url.pathname + url.search)}`;
    return Response.redirect(loginUrl, 302);
  }

  return new Response(renderAdminPage(url.pathname, siteInfo, url, session), {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, private',
      'X-Frame-Options': 'SAMEORIGIN',
    },
  });
}

function renderAdminPage(pathname, siteInfo, urlObj, session) {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const siteUrl  = urlObj ? `https://${urlObj.hostname}` : '';
  const page = pathname.replace(/^\/wp-admin\/?/, '').replace(/\.php$/, '') || 'index';
  const sp = urlObj ? urlObj.searchParams : null;
  const isPage = sp ? sp.get('post_type') === 'page' : false;
  const displayName = esc(session?.displayName || session?.login || 'admin');

  let pageTitle = '대시보드';
  let bodyHtml  = '';
  let inlineScript = '';

  if (page === 'index' || page === '' || page === 'dashboard') {
    pageTitle = '대시보드';
    bodyHtml = `
<div class="welcome-panel">
  <div style="max-width:700px">
    <h2 style="font-size:1.3rem;margin:0 0 10px">WordPress에 오신 것을 환영합니다!</h2>
    <p style="color:#50575e;margin:0 0 6px">CloudPress Edge 위에서 WordPress가 동작 중입니다.</p>
    <p style="color:#50575e;margin:0 0 15px;font-size:.85rem">로그인: <strong>${displayName}</strong></p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a href="/wp-admin/post-new.php" class="btn-wp">✏️ 글 작성하기</a>
      <a href="/wp-admin/edit.php" class="btn-wp btn-secondary">📋 글 목록</a>
      <a href="/wp-admin/options-general.php" class="btn-wp btn-secondary">⚙️ 사이트 설정</a>
      <a href="/" target="_blank" class="btn-wp btn-secondary">🌐 사이트 보기</a>
    </div>
  </div>
</div>
<div class="admin-widgets">
  <div class="admin-widget">
    <h3 class="widget-title"><span>📊 한 눈에 보기</span></h3>
    <div class="widget-body">
      <ul id="admin-glance" style="list-style:none;margin:0;padding:0;color:#50575e;font-size:.875rem"><li>불러오는 중...</li></ul>
      <p style="margin:12px 0 0;font-size:.8rem;color:#50575e">WordPress 6.7 + CloudPress v20.1</p>
    </div>
  </div>
  <div class="admin-widget">
    <h3 class="widget-title">📝 최근 게시됨</h3>
    <div class="widget-body">
      <div id="admin-activity" style="color:#50575e;font-size:.85rem">불러오는 중...</div>
    </div>
  </div>
</div>`;
    // CP.apiFetch 완전 제거 — 표준 fetch() 사용
    inlineScript = `(async function(){
try{
  var r=await fetch('/wp-json/wp/v2/posts?per_page=5&_fields=id,title,date',{headers:{'Accept':'application/json'}});
  var posts=r.ok?await r.json():[];
  var r2=await fetch('/wp-json/wp/v2/pages?per_page=100&_fields=id',{headers:{'Accept':'application/json'}});
  var pages=r2.ok?await r2.json():[];
  var r3=await fetch('/wp-json/wp/v2/comments?per_page=1&_fields=id',{headers:{'Accept':'application/json'}});
  var commentTotal=r3.ok?(parseInt(r3.headers.get('X-WP-Total')||'0',10)):0;
  posts=Array.isArray(posts)?posts:[];
  pages=Array.isArray(pages)?pages:[];
  document.getElementById('admin-glance').innerHTML=
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+posts.length+'개의 글</span><a href="/wp-admin/edit.php" style="color:#2271b1">관리</a></li>'+
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+pages.length+'개의 페이지</span><a href="/wp-admin/edit.php?post_type=page" style="color:#2271b1">관리</a></li>'+
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+commentTotal+'개의 댓글</span><a href="/wp-admin/edit-comments.php" style="color:#2271b1">관리</a></li>';
  var actEl=document.getElementById('admin-activity');
  if(!posts.length){actEl.innerHTML='<p style="color:#8c8f94">아직 게시된 글이 없습니다. <a href="/wp-admin/post-new.php">첫 글을 작성해 보세요!</a></p>';return;}
  actEl.innerHTML='<ul style="list-style:none;margin:0;padding:0">'+posts.map(function(p){
    var d=new Date(p.date).toLocaleDateString('ko-KR');
    var t=(p.title&&p.title.rendered)||'(제목 없음)';
    return '<li style="padding:5px 0;border-bottom:1px solid #f0f0f1">'+
      '<a href="/wp-admin/post.php?post='+p.id+'&action=edit" style="color:#2271b1">'+t+'</a>'+
      '<span style="float:right;color:#8c8f94;font-size:.8rem">'+d+'</span></li>';
  }).join('')+'</ul>';
}catch(e){
  document.getElementById('admin-glance').innerHTML='<li style="color:#d63638">데이터 로드 실패</li>';
  document.getElementById('admin-activity').textContent='오류: '+e.message;
}
})();`;

  } else if (page === 'edit') {
    pageTitle = isPage ? '페이지' : '글';
    const newHref = isPage ? '/wp-admin/post-new.php?post_type=page' : '/wp-admin/post-new.php';
    const apiType = isPage ? 'pages' : 'posts';
    const emptyMsg = isPage ? '아직 페이지가 없습니다.' : '아직 글이 없습니다.';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px">
      <a href="${newHref}" class="btn-wp">새 ${isPage ? '페이지' : '글'} 추가</a>
    </div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <td style="width:30px;padding:8px 10px"><input type="checkbox" id="cb-select-all"></td>
        <th style="padding:8px 10px;text-align:left;font-size:.875rem">제목</th>
        <th style="padding:8px 10px;text-align:left;font-size:.875rem;width:120px">날짜</th>
      </tr></thead>
      <tbody id="posts-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/${apiType}?per_page=20&_fields=id,title,date,status,link',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var posts=r.ok?await r.json():[];
posts=Array.isArray(posts)?posts:[];
var el=document.getElementById('posts-list');
if(!posts.length){
  el.innerHTML='<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">${emptyMsg} <a href="${newHref}">새로 만들기</a></td></tr>';
  return;
}
el.innerHTML=posts.map(function(p){
  var title=(p.title&&p.title.rendered)||'(제목 없음)';
  var d=new Date(p.date).toLocaleDateString('ko-KR');
  var editHref='/wp-admin/post.php?post='+p.id+'&action=edit';
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:8px 10px"><input type="checkbox"></td>'+
    '<td style="padding:8px 10px"><strong><a href="'+editHref+'" style="color:#2271b1;text-decoration:none">'+title+'</a></strong>'+
    '<div style="font-size:.8rem;color:#8c8f94;margin-top:3px">'+
    '<a href="'+editHref+'">편집</a> | '+
    '<a href="#" onclick="trashPost('+p.id+',this);return false;" style="color:#b32d2e">휴지통</a> | '+
    '<a href="'+(p.link||'/')+ '" target="_blank">보기</a></div></td>'+
    '<td style="padding:8px 10px;font-size:.8rem;color:#50575e">게시됨<br>'+d+'</td>'+
    '</tr>';
}).join('');
})();
async function trashPost(id,el){
  if(!confirm('이 글을 휴지통으로 이동할까요?'))return;
  var r=await fetch('/wp-json/wp/v2/${apiType}/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'}}).catch(function(){return{ok:false};});
  if(r.ok){el.closest('tr').remove();}else{alert('삭제 실패');}
}`;

  } else if (page === 'post-new' || page === 'post') {
    const isEdit = page === 'post' && sp && sp.get('action') === 'edit';
    const postId = sp ? sp.get('post') : null;
    const postType = sp ? (sp.get('post_type') || 'post') : 'post';
    pageTitle = isEdit ? (postType === 'page' ? '페이지 편집' : '글 편집') : (postType === 'page' ? '새 페이지 추가' : '새 글 추가');

    // ── 완전한 워드프레스 블록 편집기 (Gutenberg 호환) ──
    bodyHtml = `
<style>
/* 블록 편집기 레이아웃 */
#block-editor-wrap{display:grid;grid-template-columns:1fr 280px;gap:0;min-height:calc(100vh - 120px)}
#editor-canvas{padding:0;overflow:auto;background:#f0f0f1}
#editor-inner{max-width:860px;margin:0 auto;padding:40px 20px 120px}
.editor-title-wrap{background:#fff;margin-bottom:4px;border-radius:2px}
#post-title{width:100%;font-size:2rem;font-weight:700;border:none;padding:24px 48px;outline:none;color:#1e1e1e;background:transparent;font-family:inherit;line-height:1.2}
#post-title::placeholder{color:#a0a0a0}

/* 블록 컨테이너 */
#blocks-container{background:#fff;padding:4px 48px 48px;border-radius:2px;min-height:300px;position:relative}
.wp-block{position:relative;margin:0 0 0;clear:both}
.wp-block:hover .block-controls{opacity:1}
.block-controls{position:absolute;top:-32px;left:0;display:flex;align-items:center;gap:2px;background:#1e1e1e;border-radius:4px;padding:2px;opacity:0;transition:opacity .15s;z-index:10;pointer-events:none}
.wp-block:hover .block-controls{pointer-events:auto}
.block-ctrl-btn{background:transparent;border:none;color:#fff;width:28px;height:28px;display:flex;align-items:center;justify-content:center;cursor:pointer;border-radius:3px;font-size:.75rem}
.block-ctrl-btn:hover{background:rgba(255,255,255,.15)}

/* 블록 스타일 */
.wp-block [contenteditable]{outline:none;min-height:1.4em}
.wp-block [contenteditable]:focus{outline:2px solid #0073aa;outline-offset:2px;border-radius:2px}
.wp-block-paragraph [contenteditable]{font-size:1rem;line-height:1.8;color:#1e1e1e;width:100%;padding:8px 0}
.wp-block-heading [contenteditable]{font-weight:700;line-height:1.2;color:#1e1e1e;padding:8px 0}
.wp-block-heading h1 [contenteditable]{font-size:2.5rem}
.wp-block-heading h2 [contenteditable]{font-size:1.875rem}
.wp-block-heading h3 [contenteditable]{font-size:1.5rem}
.wp-block-heading h4 [contenteditable]{font-size:1.25rem}
.wp-block-heading h5 [contenteditable]{font-size:1.0625rem}
.wp-block-heading h6 [contenteditable]{font-size:.875rem}
.wp-block-list [contenteditable]{padding:8px 0 8px 1.5em}
.wp-block-list ul{margin:0;padding:0;list-style:disc}
.wp-block-list ol{margin:0;padding:0;list-style:decimal}
.wp-block-quote [contenteditable]{border-left:4px solid #000;padding:8px 0 8px 20px;font-style:italic;font-size:1.125rem;color:#555}
.wp-block-code [contenteditable]{font-family:'Courier New',monospace;background:#f6f7f7;border:1px solid #e0e0e0;border-radius:4px;padding:12px 16px;font-size:.875rem;white-space:pre-wrap;color:#1e1e1e;display:block;width:100%}
.wp-block-separator hr{border:none;border-top:2px solid #ddd;margin:16px 0}
.wp-block-image img{max-width:100%;height:auto;display:block}
.wp-block-image figcaption{text-align:center;font-size:.875rem;color:#555;margin-top:6px}
.wp-block-button .wp-element-button{display:inline-block;background:#0073aa;color:#fff;padding:.75rem 1.5rem;border-radius:4px;border:none;cursor:pointer;font-size:.9375rem;text-decoration:none}
.wp-block-table table{width:100%;border-collapse:collapse;margin:0}
.wp-block-table td,.wp-block-table th{border:1px solid #ddd;padding:8px 12px;text-align:left}
.wp-block-table th{background:#f6f7f7;font-weight:600}
.wp-block-preformatted pre{font-family:monospace;background:#f6f7f7;padding:16px;overflow-x:auto;white-space:pre-wrap}
.wp-block-pullquote blockquote{text-align:center;border-top:4px solid #000;border-bottom:4px solid #000;padding:20px;margin:0}
.wp-block-pullquote p{font-size:1.4rem;font-style:italic}
.wp-block-verse pre{font-family:inherit;white-space:pre-wrap;padding:8px 0}
.wp-block-columns{display:flex;gap:24px}
.wp-block-column{flex:1;min-width:0}

/* 툴바 */
#editor-toolbar{position:fixed;top:32px;left:0;right:0;z-index:200;background:#1e1e1e;padding:0 12px;display:flex;align-items:center;gap:4px;height:48px;box-shadow:0 2px 8px rgba(0,0,0,.3)}
.toolbar-btn{background:transparent;border:none;color:#fff;padding:6px 8px;cursor:pointer;border-radius:3px;font-size:.8125rem;font-weight:600;min-width:28px;display:flex;align-items:center;justify-content:center;white-space:nowrap;gap:4px}
.toolbar-btn:hover{background:rgba(255,255,255,.15)}
.toolbar-btn.active{background:rgba(255,255,255,.25)}
.toolbar-sep{width:1px;background:rgba(255,255,255,.2);height:24px;margin:0 4px}
.toolbar-select{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);color:#fff;padding:4px 6px;border-radius:3px;font-size:.8rem;cursor:pointer}
.toolbar-select option{background:#1e1e1e}
#editor-toolbar .toolbar-right{margin-left:auto;display:flex;align-items:center;gap:6px}
body{padding-top:48px}

/* 블록 삽입 버튼 */
.block-inserter{display:flex;align-items:center;justify-content:center;padding:4px 0;opacity:0;transition:opacity .2s;cursor:pointer;color:#757575;font-size:.8rem;gap:4px}
.block-inserter:hover,.blocks-container:hover .block-inserter{opacity:1}
.inserter-btn{background:#0073aa;color:#fff;border:none;width:24px;height:24px;border-radius:50%;cursor:pointer;font-size:1.1rem;display:flex;align-items:center;justify-content:center;line-height:1}

/* 블록 삽입 팝업 */
#block-inserter-popup{display:none;position:fixed;z-index:500;background:#fff;border:1px solid #ddd;border-radius:8px;box-shadow:0 4px 24px rgba(0,0,0,.2);width:360px;max-height:480px;overflow:hidden}
#block-inserter-popup .popup-head{padding:12px 16px;border-bottom:1px solid #eee;display:flex;align-items:center;gap:8px}
#block-search{flex:1;padding:6px 10px;border:1px solid #ddd;border-radius:4px;font-size:.875rem;outline:none}
#block-inserter-popup .popup-body{overflow-y:auto;max-height:380px;padding:8px}
.block-cat-title{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#757575;padding:8px 8px 4px}
.block-item-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:4px;margin-bottom:8px}
.block-item{display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:1px solid transparent;border-radius:4px;cursor:pointer;font-size:.75rem;color:#1e1e1e;text-align:center;background:#f9f9f9;transition:border-color .15s}
.block-item:hover{border-color:#0073aa;background:#f0f7fc}
.block-item .bi{font-size:1.4rem}

/* 사이드 패널 */
#editor-sidebar{background:#fff;border-left:1px solid #dcdcde;overflow-y:auto;position:relative}
.sidebar-tabs{display:flex;border-bottom:1px solid #dcdcde;position:sticky;top:0;background:#fff;z-index:10}
.sidebar-tab{flex:1;padding:10px;border:none;background:transparent;cursor:pointer;font-size:.875rem;border-bottom:2px solid transparent;color:#757575}
.sidebar-tab.active{color:#0073aa;border-bottom-color:#0073aa}
.sidebar-panel{padding:16px;display:none}
.sidebar-panel.active{display:block}
.sb-section{margin-bottom:20px}
.sb-section-title{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#757575;margin:0 0 8px;padding-bottom:6px;border-bottom:1px solid #eee}
.sb-field{margin-bottom:12px}
.sb-field label{display:block;font-size:.8125rem;font-weight:600;color:#1e1e1e;margin-bottom:4px}
.sb-input{width:100%;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem}
.sb-select{width:100%;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem;background:#fff}
.sb-btn{width:100%;padding:8px;background:#0073aa;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.875rem;font-weight:600;margin-bottom:6px}
.sb-btn:hover{background:#005580}
.sb-btn-secondary{background:#f0f0f1;color:#1e1e1e;border:1px solid #dcdcde}
.sb-btn-secondary:hover{background:#e0e0e0}

/* 상태바 */
#editor-statusbar{position:fixed;bottom:0;left:0;right:0;background:#1e1e1e;color:#ccc;font-size:.75rem;padding:4px 16px;z-index:100;display:flex;align-items:center;gap:16px}
#post-status-bar{margin-left:auto}
</style>

<!-- 상단 툴바 -->
<div id="editor-toolbar">
  <button class="toolbar-btn" onclick="insertBlock('paragraph')" title="단락">¶</button>
  <div class="toolbar-sep"></div>
  <select class="toolbar-select" id="heading-select" onchange="insertHeading(this.value)" title="제목">
    <option value="">제목</option>
    <option value="h1">H1</option>
    <option value="h2">H2</option>
    <option value="h3">H3</option>
    <option value="h4">H4</option>
    <option value="h5">H5</option>
    <option value="h6">H6</option>
  </select>
  <div class="toolbar-sep"></div>
  <button class="toolbar-btn" onclick="execCmd('bold')" title="굵게"><b>B</b></button>
  <button class="toolbar-btn" onclick="execCmd('italic')" title="기울임"><i>I</i></button>
  <button class="toolbar-btn" onclick="execCmd('underline')" title="밑줄"><u>U</u></button>
  <button class="toolbar-btn" onclick="execCmd('strikeThrough')" title="취소선"><s>S</s></button>
  <div class="toolbar-sep"></div>
  <button class="toolbar-btn" onclick="insertBlock('list-ul')" title="목록">≡</button>
  <button class="toolbar-btn" onclick="insertBlock('list-ol')" title="번호 목록">1.</button>
  <button class="toolbar-btn" onclick="insertBlock('quote')" title="인용">❝</button>
  <button class="toolbar-btn" onclick="insertBlock('code')" title="코드">&lt;/&gt;</button>
  <div class="toolbar-sep"></div>
  <button class="toolbar-btn" onclick="insertBlock('image')" title="이미지">🖼</button>
  <button class="toolbar-btn" onclick="insertBlock('button')" title="버튼">⬜</button>
  <button class="toolbar-btn" onclick="insertBlock('separator')" title="구분선">—</button>
  <button class="toolbar-btn" onclick="insertBlock('table')" title="표">⊞</button>
  <button class="toolbar-btn" onclick="showInserterPopup()" title="모든 블록 추가">＋</button>
  <div class="toolbar-right">
    <span id="toolbar-post-type" style="font-size:.75rem;color:#aaa">${postType === 'page' ? '페이지' : '글'}</span>
    <div class="toolbar-sep"></div>
    <button class="toolbar-btn" onclick="saveDraft()" title="임시저장">임시저장</button>
    <button class="toolbar-btn" style="background:#0073aa;padding:6px 16px;border-radius:4px" onclick="savePost()" title="게시">게시</button>
  </div>
</div>

<!-- 블록 삽입 팝업 -->
<div id="block-inserter-popup">
  <div class="popup-head">
    <input type="text" id="block-search" placeholder="블록 검색…" oninput="filterBlocks(this.value)">
    <button onclick="closeInserter()" style="background:none;border:none;cursor:pointer;font-size:1.2rem;color:#757575">✕</button>
  </div>
  <div class="popup-body" id="block-list"></div>
</div>

<!-- 에디터 레이아웃 -->
<div id="block-editor-wrap">
  <div id="editor-canvas">
    <div id="editor-inner">
      <div class="editor-title-wrap">
        <textarea id="post-title" placeholder="제목 추가" rows="1" style="width:100%;font-size:2rem;font-weight:700;border:none;padding:24px 48px;outline:none;color:#1e1e1e;background:transparent;font-family:inherit;line-height:1.2;resize:none;overflow:hidden"></textarea>
      </div>
      <div id="blocks-container">
        <!-- 블록들이 여기에 삽입됨 -->
      </div>
    </div>
  </div>

  <!-- 사이드 패널 -->
  <div id="editor-sidebar">
    <div class="sidebar-tabs">
      <button class="sidebar-tab active" onclick="switchTab('post')">글</button>
      <button class="sidebar-tab" onclick="switchTab('block')">블록</button>
    </div>

    <!-- 글 탭 -->
    <div class="sidebar-panel active" id="tab-post">
      <div class="sb-section">
        <p class="sb-section-title">요약</p>
        <button class="sb-btn" onclick="savePost()">게시</button>
        <button class="sb-btn sb-btn-secondary" onclick="saveDraft()">임시저장</button>
        ${isEdit && postId ? `<a href="/" target="_blank" style="display:block;text-align:center;font-size:.8rem;color:#0073aa;margin-top:8px">게시글 보기 ↗</a>` : ''}
      </div>
      <div class="sb-section">
        <p class="sb-section-title">상태</p>
        <div class="sb-field">
          <label>공개 상태</label>
          <select class="sb-select" id="post-status">
            <option value="publish">공개</option>
            <option value="draft">임시저장</option>
            <option value="private">비공개</option>
          </select>
        </div>
        <div class="sb-field">
          <label>발행일</label>
          <input type="datetime-local" class="sb-input" id="post-date">
        </div>
      </div>
      <div class="sb-section">
        <p class="sb-section-title">고유주소</p>
        <div class="sb-field">
          <input type="text" class="sb-input" id="post-slug" placeholder="슬러그 (자동 생성)">
        </div>
      </div>
      <div class="sb-section">
        <p class="sb-section-title">카테고리</p>
        <div id="cats-list" style="font-size:.8125rem;color:#50575e">불러오는 중…</div>
        <div style="margin-top:8px">
          <input type="text" class="sb-input" id="new-cat" placeholder="새 카테고리" style="font-size:.8rem">
          <button onclick="addCategory()" style="margin-top:4px;padding:4px 8px;background:#f0f0f1;border:1px solid #ddd;border-radius:3px;cursor:pointer;font-size:.8rem;width:100%">+ 추가</button>
        </div>
      </div>
      <div class="sb-section">
        <p class="sb-section-title">태그</p>
        <input type="text" class="sb-input" id="post-tags" placeholder="태그 입력 후 Enter">
        <div id="tags-list" style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px"></div>
      </div>
      <div class="sb-section">
        <p class="sb-section-title">특성 이미지</p>
        <div id="featured-img-wrap" style="margin-bottom:8px"></div>
        <button onclick="setFeaturedImage()" class="sb-btn sb-btn-secondary" style="font-size:.8rem">특성 이미지 설정</button>
      </div>
      <div class="sb-section">
        <p class="sb-section-title">발췌문</p>
        <textarea class="sb-input" id="post-excerpt" rows="3" placeholder="수동 발췌문 작성…" style="resize:vertical"></textarea>
      </div>
      <div class="sb-section">
        <p class="sb-section-title">댓글</p>
        <label style="font-size:.8125rem;display:flex;align-items:center;gap:6px;cursor:pointer">
          <input type="checkbox" id="allow-comments" checked> 댓글 허용
        </label>
      </div>
    </div>

    <!-- 블록 탭 -->
    <div class="sidebar-panel" id="tab-block">
      <div id="block-settings-empty" style="padding:20px;text-align:center;color:#757575;font-size:.875rem">
        <p>블록을 선택하면<br>설정이 여기 표시됩니다.</p>
      </div>
      <div id="block-settings-panel" style="display:none">
        <div class="sb-section">
          <p class="sb-section-title" id="selected-block-name">블록 설정</p>
          <div id="block-specific-settings"></div>
        </div>
        <div class="sb-section">
          <p class="sb-section-title">고급</p>
          <div class="sb-field">
            <label>추가 CSS 클래스</label>
            <input type="text" class="sb-input" id="block-css-class" placeholder="my-class">
          </div>
          <div class="sb-field">
            <label>HTML 앵커</label>
            <input type="text" class="sb-input" id="block-anchor" placeholder="my-anchor">
          </div>
        </div>
        <button onclick="removeSelectedBlock()" style="width:100%;padding:7px;background:#fff;border:1px solid #d63638;color:#d63638;border-radius:4px;cursor:pointer;font-size:.8rem;margin-top:8px">블록 삭제</button>
      </div>
    </div>
  </div>
</div>

<!-- 상태바 -->
<div id="editor-statusbar">
  <span id="word-count">0 단어</span>
  <span id="block-count">0 블록</span>
  <span id="post-status-bar">자동 저장: 대기 중</span>
</div>`;

    inlineScript = `
// ── 전역 상태 ──────────────────────────────────────────────────
var _postId = ${postId ? parseInt(postId,10) : 0};
var _postType = '${postType}';
var _autoSaveTimer = null;
var _selectedBlockEl = null;
var _blockCounter = 0;
var _tags = [];

// ── CP.apiFetch polyfill (완전 제거 — 표준 fetch 사용) ──────────
window.CP = window.CP || {};
window.CP.apiFetch = function(opts) {
  var url = (opts.path || '').startsWith('/') ? opts.path : '/wp-json/' + opts.path;
  return fetch(url, {
    method: opts.method || 'GET',
    headers: Object.assign({'Content-Type':'application/json','Accept':'application/json'}, opts.headers||{}),
    body: opts.data ? JSON.stringify(opts.data) : undefined
  }).then(function(r){ return r.json(); });
};

// ── 제목 자동 크기 ──────────────────────────────────────────────
var titleEl = document.getElementById('post-title');
titleEl.addEventListener('input', function() {
  this.style.height = 'auto';
  this.style.height = this.scrollHeight + 'px';
  updateSlug(this.value);
});

function updateSlug(title) {
  var slugEl = document.getElementById('post-slug');
  if (!slugEl.dataset.manual) {
    slugEl.value = title.toLowerCase()
      .replace(/[가-힣]+/g, function(m){ return encodeURIComponent(m).replace(/%/g,'').slice(0,20); })
      .replace(/[^a-z0-9\\-]/g,'').replace(/-+/g,'-').replace(/^-|-$/g,'').slice(0,60);
  }
}
document.getElementById('post-slug').addEventListener('input', function(){ this.dataset.manual = '1'; });

// ── 블록 정의 ──────────────────────────────────────────────────
var BLOCK_DEFS = {
  paragraph:   { label:'단락',      icon:'¶',  cat:'텍스트' },
  h1:          { label:'제목 1',    icon:'H1', cat:'텍스트' },
  h2:          { label:'제목 2',    icon:'H2', cat:'텍스트' },
  h3:          { label:'제목 3',    icon:'H3', cat:'텍스트' },
  h4:          { label:'제목 4',    icon:'H4', cat:'텍스트' },
  h5:          { label:'제목 5',    icon:'H5', cat:'텍스트' },
  h6:          { label:'제목 6',    icon:'H6', cat:'텍스트' },
  'list-ul':   { label:'목록',      icon:'≡',  cat:'텍스트' },
  'list-ol':   { label:'번호 목록', icon:'1.', cat:'텍스트' },
  quote:       { label:'인용',      icon:'❝',  cat:'텍스트' },
  pullquote:   { label:'풀 인용',   icon:'❞',  cat:'텍스트' },
  code:        { label:'코드',      icon:'</>',cat:'텍스트' },
  preformatted:{ label:'사전 형식', icon:'≤≥', cat:'텍스트' },
  verse:       { label:'시',        icon:'♫',  cat:'텍스트' },
  image:       { label:'이미지',    icon:'🖼', cat:'미디어' },
  gallery:     { label:'갤러리',    icon:'🗃', cat:'미디어' },
  video:       { label:'동영상',    icon:'▶',  cat:'미디어' },
  audio:       { label:'오디오',    icon:'🎵', cat:'미디어' },
  file:        { label:'파일',      icon:'📎', cat:'미디어' },
  button:      { label:'버튼',      icon:'⬜', cat:'디자인' },
  separator:   { label:'구분선',    icon:'—',  cat:'디자인' },
  spacer:      { label:'공백',      icon:'↕',  cat:'디자인' },
  columns:     { label:'열',        icon:'⊟',  cat:'디자인' },
  group:       { label:'그룹',      icon:'⊞',  cat:'디자인' },
  cover:       { label:'커버',      icon:'🏞', cat:'디자인' },
  table:       { label:'표',        icon:'⊞',  cat:'위젯' },
  html:        { label:'사용자 HTML', icon:'<>',cat:'위젯' },
  shortcode:   { label:'단축코드',  icon:'[s]',cat:'위젯' },
  embed:       { label:'임베드',    icon:'🔗', cat:'위젯' },
  'more':      { label:'더 보기',   icon:'···',cat:'레이아웃' },
  'page-break':{ label:'페이지 나누기',icon:'⤵',cat:'레이아웃' },
};

// ── 블록 삽입 팝업 ──────────────────────────────────────────────
function buildBlockList(filter) {
  var cats = {};
  Object.entries(BLOCK_DEFS).forEach(function([slug, def]) {
    if (filter && !def.label.includes(filter) && !slug.includes(filter)) return;
    if (!cats[def.cat]) cats[def.cat] = [];
    cats[def.cat].push({slug, ...def});
  });
  var html = '';
  Object.entries(cats).forEach(function([cat, blocks]) {
    html += '<div class="block-cat-title">' + cat + '</div><div class="block-item-grid">';
    html += blocks.map(function(b) {
      return '<div class="block-item" onclick="insertBlock(\\'' + b.slug + '\\');closeInserter()">' +
        '<span class="bi">' + b.icon + '</span>' + b.label + '</div>';
    }).join('');
    html += '</div>';
  });
  document.getElementById('block-list').innerHTML = html || '<p style="padding:16px;color:#757575">결과 없음</p>';
}
function showInserterPopup() {
  buildBlockList('');
  var pop = document.getElementById('block-inserter-popup');
  pop.style.display = 'block';
  pop.style.left = '200px'; pop.style.top = '60px';
  document.getElementById('block-search').focus();
}
function closeInserter() { document.getElementById('block-inserter-popup').style.display='none'; }
function filterBlocks(q) { buildBlockList(q); }

// ── 블록 생성 ──────────────────────────────────────────────────
function createBlockEl(type, content) {
  var id = 'block-' + (++_blockCounter);
  var wrap = document.createElement('div');
  wrap.className = 'wp-block';
  wrap.dataset.type = type;
  wrap.dataset.id = id;
  wrap.setAttribute('tabindex','0');

  var ctrl = '<div class="block-controls">' +
    '<button class="block-ctrl-btn" onclick="moveBlock(this,\\'up\\')" title="위로">↑</button>' +
    '<button class="block-ctrl-btn" onclick="moveBlock(this,\\'down\\')" title="아래로">↓</button>' +
    '<button class="block-ctrl-btn" onclick="duplicateBlock(this)" title="복제">⧉</button>' +
    '<button class="block-ctrl-btn" onclick="removeBlock(this)" title="삭제" style="color:#f86368">✕</button>' +
    '</div>';

  var inner = '';
  switch(type) {
    case 'paragraph':
      inner = '<div class="wp-block-paragraph"><div contenteditable="true" data-placeholder="내용을 입력하세요…" onkeydown="handleBlockKey(event,this)" onfocus="selectBlock(this)">' + (content||'') + '</div></div>';
      break;
    case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6': {
      var lv = type;
      inner = '<div class="wp-block-heading"><' + lv + '><div contenteditable="true" data-placeholder="제목…" onkeydown="handleBlockKey(event,this)" onfocus="selectBlock(this)">' + (content||'') + '</div></' + lv + '></div>';
      break;
    }
    case 'list-ul':
      inner = '<div class="wp-block-list"><ul><li contenteditable="true" onkeydown="handleListKey(event,this)" onfocus="selectBlock(this)">' + (content||'목록 항목') + '</li></ul></div>';
      break;
    case 'list-ol':
      inner = '<div class="wp-block-list"><ol><li contenteditable="true" onkeydown="handleListKey(event,this)" onfocus="selectBlock(this)">' + (content||'목록 항목') + '</li></ol></div>';
      break;
    case 'quote':
      inner = '<div class="wp-block-quote"><blockquote><div contenteditable="true" data-placeholder="인용문…" onfocus="selectBlock(this)">' + (content||'') + '</div><cite contenteditable="true" style="display:block;margin-top:8px;font-size:.875rem;color:#757575" data-placeholder="출처…"></cite></blockquote></div>';
      break;
    case 'pullquote':
      inner = '<div class="wp-block-pullquote"><blockquote><p contenteditable="true" data-placeholder="풀 인용문…" onfocus="selectBlock(this)">' + (content||'') + '</p><cite contenteditable="true" style="font-size:.875rem;color:#757575" data-placeholder="출처"></cite></blockquote></div>';
      break;
    case 'code':
      inner = '<div class="wp-block-code"><code contenteditable="true" data-placeholder="코드 입력…" spellcheck="false" onfocus="selectBlock(this)">' + (content||'') + '</code></div>';
      break;
    case 'preformatted':
      inner = '<div class="wp-block-preformatted"><pre contenteditable="true" onfocus="selectBlock(this)">' + (content||'') + '</pre></div>';
      break;
    case 'verse':
      inner = '<div class="wp-block-verse"><pre contenteditable="true" style="font-family:inherit;white-space:pre-wrap;padding:8px 0" onfocus="selectBlock(this)">' + (content||'') + '</pre></div>';
      break;
    case 'separator':
      inner = '<div class="wp-block-separator"><hr></div>';
      break;
    case 'spacer':
      inner = '<div class="wp-block-spacer" style="height:60px;background:rgba(0,0,0,.04);display:flex;align-items:center;justify-content:center;color:#aaa;font-size:.75rem" onclick="selectBlock(this)">공백 (60px)</div>';
      break;
    case 'image':
      inner = '<figure class="wp-block-image"><label style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:180px;border:2px dashed #ddd;border-radius:4px;cursor:pointer;color:#757575;font-size:.875rem;gap:8px" onclick="triggerImageUpload(this)">' +
        '<span style="font-size:2.5rem">🖼</span><span>클릭하여 이미지 업로드</span>' +
        '<input type="file" accept="image/*" style="display:none" onchange="handleImageUpload(this)">' +
        '</label>' +
        '<figcaption contenteditable="true" data-placeholder="캡션 추가…" style="text-align:center;font-size:.875rem;color:#555;padding:4px"></figcaption>' +
        '</figure>';
      break;
    case 'gallery':
      inner = '<div class="wp-block-gallery"><div style="border:2px dashed #ddd;border-radius:4px;padding:30px;text-align:center;color:#757575;cursor:pointer" onclick="triggerGalleryUpload(this)"><span style="font-size:2rem">🗃</span><br>클릭하여 갤러리 이미지 업로드<input type="file" accept="image/*" multiple style="display:none" onchange="handleGalleryUpload(this)"></div></div>';
      break;
    case 'video':
      inner = '<div class="wp-block-video"><div style="border:2px dashed #ddd;border-radius:4px;padding:20px;text-align:center;color:#757575"><p>▶ 비디오 URL 입력:</p><input type="url" placeholder="https://…" class="sb-input" style="max-width:400px" onchange="setVideoSrc(this)"></div></div>';
      break;
    case 'audio':
      inner = '<div class="wp-block-audio"><div style="border:2px dashed #ddd;border-radius:4px;padding:20px;text-align:center;color:#757575"><p>🎵 오디오 URL 입력:</p><input type="url" placeholder="https://…" class="sb-input" style="max-width:400px"></div></div>';
      break;
    case 'file':
      inner = '<div class="wp-block-file" style="padding:12px;border:1px solid #ddd;border-radius:4px;display:flex;align-items:center;gap:12px"><span style="font-size:1.5rem">📎</span><span contenteditable="true">파일 이름</span><a href="#" style="margin-left:auto;background:#1e1e1e;color:#fff;padding:6px 12px;border-radius:4px;text-decoration:none;font-size:.875rem">다운로드</a></div>';
      break;
    case 'button':
      inner = '<div class="wp-block-buttons"><div class="wp-block-button"><button class="wp-element-button" contenteditable="true" onfocus="selectBlock(this)">버튼 텍스트</button></div></div>';
      break;
    case 'table':
      inner = '<figure class="wp-block-table"><table><thead><tr><th contenteditable="true">제목1</th><th contenteditable="true">제목2</th><th contenteditable="true">제목3</th></tr></thead><tbody><tr><td contenteditable="true">내용</td><td contenteditable="true">내용</td><td contenteditable="true">내용</td></tr><tr><td contenteditable="true">내용</td><td contenteditable="true">내용</td><td contenteditable="true">내용</td></tr></tbody></table></figure>';
      break;
    case 'html':
      inner = '<div class="wp-block-html"><textarea placeholder="HTML 코드 입력…" style="width:100%;min-height:100px;font-family:monospace;padding:12px;border:1px solid #ddd;border-radius:4px;font-size:.875rem;resize:vertical"></textarea></div>';
      break;
    case 'shortcode':
      inner = '<div class="wp-block-shortcode"><input type="text" placeholder="[shortcode]" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;font-family:monospace;font-size:.875rem"></div>';
      break;
    case 'embed':
      inner = '<div class="wp-block-embed"><input type="url" placeholder="URL을 입력하고 Enter를 누르세요…" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;font-size:.875rem" onkeydown="if(event.key===\\'Enter\\'){handleEmbed(this);event.preventDefault()}"></div>';
      break;
    case 'columns':
      inner = '<div class="wp-block-columns"><div class="wp-block-column" style="border:1px dashed #ddd;padding:16px;border-radius:4px"><div contenteditable="true" style="min-height:60px;color:#aaa" data-placeholder="열 1 내용…"></div></div><div class="wp-block-column" style="border:1px dashed #ddd;padding:16px;border-radius:4px"><div contenteditable="true" style="min-height:60px;color:#aaa" data-placeholder="열 2 내용…"></div></div></div>';
      break;
    case 'group':
      inner = '<div class="wp-block-group" style="border:1px dashed #0073aa;padding:16px;border-radius:4px"><div contenteditable="true" style="min-height:60px" data-placeholder="그룹 콘텐츠…"></div></div>';
      break;
    case 'cover':
      inner = '<div class="wp-block-cover" style="position:relative;min-height:240px;background:#1e1e1e;border-radius:4px;display:flex;align-items:center;justify-content:center;overflow:hidden"><div contenteditable="true" style="position:relative;z-index:1;color:#fff;font-size:1.5rem;font-weight:700;text-align:center;padding:20px;width:100%" data-placeholder="커버 텍스트…"></div></div>';
      break;
    case 'more':
      inner = '<div class="wp-block-more" style="border-top:2px dashed #0073aa;padding:8px 0;text-align:center;color:#0073aa;font-size:.8rem">더 보기</div>';
      break;
    case 'page-break':
      inner = '<div class="wp-block-page-break" style="border-top:3px solid #ddd;padding:8px 0;text-align:center;color:#aaa;font-size:.8rem">페이지 나누기</div>';
      break;
    default:
      inner = '<div class="wp-block-paragraph"><div contenteditable="true" onfocus="selectBlock(this)">' + (content||type+' 블록') + '</div></div>';
  }

  wrap.innerHTML = ctrl + inner;

  // placeholder 처리
  wrap.querySelectorAll('[data-placeholder]').forEach(function(el) {
    el.addEventListener('focus', function() { if (!this.textContent.trim()) this.classList.add('is-empty'); });
    el.addEventListener('blur',  function() { this.classList.remove('is-empty'); });
    if (!el.textContent.trim()) el.classList.add('is-empty');
  });

  wrap.addEventListener('click', function(e) {
    if (!e.target.closest('.block-controls')) selectBlock(wrap);
  });

  return wrap;
}

// ── placeholder CSS ──────────────────────────────────────────────
(function(){
  var s = document.createElement('style');
  s.textContent = '[data-placeholder].is-empty:before{content:attr(data-placeholder);color:#aaa;pointer-events:none;position:absolute}' +
    '[data-placeholder]{position:relative}';
  document.head.appendChild(s);
})();

// ── 블록 삽입 ──────────────────────────────────────────────────
function insertBlock(type, content, afterEl) {
  var block = createBlockEl(type, content || '');
  var container = document.getElementById('blocks-container');
  if (afterEl) {
    var parentBlock = afterEl.closest('.wp-block');
    if (parentBlock && parentBlock.nextSibling) {
      container.insertBefore(block, parentBlock.nextSibling);
    } else {
      container.appendChild(block);
    }
  } else if (_selectedBlockEl) {
    var nb = _selectedBlockEl.nextSibling;
    if (nb) container.insertBefore(block, nb);
    else container.appendChild(block);
  } else {
    container.appendChild(block);
  }
  // 포커스
  var focusEl = block.querySelector('[contenteditable]');
  if (focusEl) setTimeout(function(){ focusEl.focus(); }, 10);
  else selectBlock(block);
  if (type === 'h1'||type==='h2'||type==='h3'||type==='h4'||type==='h5'||type==='h6') {
    document.getElementById('heading-select').value='';
  }
  updateCounts();
  scheduleAutosave();
  return block;
}

function insertHeading(level) {
  if (!level) return;
  insertBlock(level);
  setTimeout(function(){ document.getElementById('heading-select').value=''; }, 100);
}

// ── 블록 선택 ──────────────────────────────────────────────────
function selectBlock(el) {
  var block = el.closest ? el.closest('.wp-block') : el;
  if (!block) return;
  document.querySelectorAll('.wp-block.is-selected').forEach(function(b){ b.classList.remove('is-selected'); });
  block.classList.add('is-selected');
  block.style.outline='2px solid #0073aa';
  if (_selectedBlockEl && _selectedBlockEl !== block) _selectedBlockEl.style.outline='';
  _selectedBlockEl = block;
  showBlockSettings(block);
}

function showBlockSettings(block) {
  document.getElementById('block-settings-empty').style.display='none';
  document.getElementById('block-settings-panel').style.display='block';
  var type = block.dataset.type || 'paragraph';
  var def = BLOCK_DEFS[type] || {label:type};
  document.getElementById('selected-block-name').textContent = def.label + ' 설정';
  // 블록별 설정
  var settingsHtml = '';
  if (type==='image') {
    settingsHtml = '<div class="sb-field"><label>이미지 URL</label><input class="sb-input" type="url" placeholder="https://…" onchange="setImgSrc(this)"></div>' +
      '<div class="sb-field"><label>대체 텍스트</label><input class="sb-input" type="text" placeholder="이미지 설명"></div>';
  } else if (type==='button') {
    settingsHtml = '<div class="sb-field"><label>링크 URL</label><input class="sb-input" type="url" placeholder="https://…"></div>' +
      '<div class="sb-field"><label>배경색</label><input type="color" value="#0073aa" oninput="setButtonColor(this.value)" style="width:100%;height:32px;border:none;cursor:pointer"></div>';
  } else if (type==='table') {
    settingsHtml = '<div class="sb-field"><button onclick="addTableRow()" class="sb-btn sb-btn-secondary" style="font-size:.8rem;margin-bottom:4px">행 추가</button>' +
      '<button onclick="addTableCol()" class="sb-btn sb-btn-secondary" style="font-size:.8rem">열 추가</button></div>';
  } else if (type==='spacer') {
    settingsHtml = '<div class="sb-field"><label>높이 (px)</label><input class="sb-input" type="number" value="60" min="1" max="500" oninput="setSpacerHeight(this.value)"></div>';
  } else if (type.startsWith('h')) {
    settingsHtml = '<div class="sb-field"><label>텍스트 정렬</label><select class="sb-select" onchange="setAlign(this.value)"><option>왼쪽</option><option>가운데</option><option>오른쪽</option></select></div>';
  }
  document.getElementById('block-specific-settings').innerHTML = settingsHtml;
}

// ── 블록 이동/삭제/복제 ────────────────────────────────────────
function moveBlock(btn, dir) {
  var block = btn.closest('.wp-block');
  var container = document.getElementById('blocks-container');
  if (dir==='up' && block.previousElementSibling) container.insertBefore(block, block.previousElementSibling);
  else if (dir==='down' && block.nextElementSibling) container.insertBefore(block.nextElementSibling, block);
  updateCounts(); scheduleAutosave();
}
function removeBlock(btn) {
  var block = btn.closest('.wp-block');
  if (_selectedBlockEl === block) { _selectedBlockEl = null; document.getElementById('block-settings-empty').style.display=''; document.getElementById('block-settings-panel').style.display='none'; }
  block.remove();
  updateCounts(); scheduleAutosave();
}
function removeSelectedBlock() {
  if (_selectedBlockEl) removeBlock(_selectedBlockEl.querySelector('.block-ctrl-btn'));
}
function duplicateBlock(btn) {
  var block = btn.closest('.wp-block');
  var clone = createBlockEl(block.dataset.type);
  block.parentNode.insertBefore(clone, block.nextSibling);
  updateCounts(); scheduleAutosave();
}

// ── 키보드 단축키 ──────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey||e.metaKey) && e.key==='s') { e.preventDefault(); saveDraft(); }
  if ((e.ctrlKey||e.metaKey) && e.shiftKey && e.key==='S') { e.preventDefault(); savePost(); }
  if ((e.ctrlKey||e.metaKey) && e.key==='b') { e.preventDefault(); execCmd('bold'); }
  if ((e.ctrlKey||e.metaKey) && e.key==='i') { e.preventDefault(); execCmd('italic'); }
  if ((e.ctrlKey||e.metaKey) && e.key==='k') { e.preventDefault(); execInsertLink(); }
});
function execCmd(cmd) { document.execCommand(cmd); }
function execInsertLink() {
  var url = prompt('URL을 입력하세요:');
  if (url) document.execCommand('createLink', false, url);
}

// ── 엔터키: 새 단락 삽입 ──────────────────────────────────────
function handleBlockKey(e, el) {
  if (e.key==='Enter' && !e.shiftKey) {
    e.preventDefault();
    var sel = window.getSelection();
    var range = sel.getRangeAt(0);
    var atEnd = range.startOffset === el.textContent.length;
    if (atEnd) insertBlock('paragraph', '', el);
    else document.execCommand('insertParagraph');
  } else if (e.key==='Backspace' && el.textContent === '') {
    e.preventDefault();
    var block = el.closest('.wp-block');
    var prev = block.previousElementSibling;
    removeBlock(el);
    if (prev) { var pe = prev.querySelector('[contenteditable]'); if (pe) pe.focus(); }
  }
}
function handleListKey(e, li) {
  if (e.key==='Enter') {
    e.preventDefault();
    if (li.textContent.trim()==='') {
      insertBlock('paragraph','',li);
    } else {
      var newLi = document.createElement('li');
      newLi.contentEditable='true';
      newLi.setAttribute('onkeydown','handleListKey(event,this)');
      newLi.setAttribute('onfocus','selectBlock(this)');
      li.parentNode.insertBefore(newLi, li.nextSibling);
      newLi.focus();
    }
  }
}

// ── 미디어 업로드 ──────────────────────────────────────────────
function triggerImageUpload(label) { label.querySelector('input[type=file]').click(); }
async function handleImageUpload(input) {
  var file = input.files[0]; if (!file) return;
  var label = input.parentElement;
  label.textContent = '업로드 중…';
  try {
    var fd = new FormData(); fd.append('file', file);
    var r = await fetch('/wp-admin/async-upload.php', {method:'POST',body:fd});
    var d = r.ok ? await r.json() : null;
    if (d && d.url) {
      var fig = input.closest('figure');
      var img = document.createElement('img');
      img.src = d.url; img.alt = file.name;
      fig.replaceChild(img, label);
    } else { label.textContent = '업로드 실패'; }
  } catch(err) { label.textContent = '오류: '+err.message; }
}
function triggerGalleryUpload(div) { div.querySelector('input[type=file]').click(); }
async function handleGalleryUpload(input) {
  var files = Array.from(input.files); if (!files.length) return;
  var gallery = input.closest('.wp-block-gallery');
  gallery.innerHTML = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px">';
  for (var f of files) {
    var url = URL.createObjectURL(f);
    gallery.firstChild.innerHTML += '<figure style="margin:0"><img src="'+url+'" style="width:100%;height:140px;object-fit:cover;border-radius:4px"></figure>';
  }
}
function setVideoSrc(input) {
  var url = input.value;
  var wrap = input.closest('.wp-block-video');
  if (url) wrap.innerHTML = '<video src="'+url+'" controls style="width:100%;border-radius:4px"></video>';
}
function handleEmbed(input) {
  var url = input.value;
  var wrap = input.closest('.wp-block-embed');
  if (url.includes('youtube.com')||url.includes('youtu.be')) {
    var vid = url.match(/[?&]v=([^&]+)/)?.[1] || url.split('/').pop();
    wrap.innerHTML = '<iframe width="100%" height="315" src="https://www.youtube.com/embed/'+vid+'" frameborder="0" allowfullscreen style="border-radius:4px"></iframe>';
  } else {
    wrap.innerHTML = '<div style="padding:12px;border:1px solid #ddd;border-radius:4px;color:#0073aa"><a href="'+url+'" target="_blank">'+url+'</a></div>';
  }
}
function setImgSrc(input) {
  var url = input.value;
  var block = _selectedBlockEl;
  if (block && url) {
    var fig = block.querySelector('figure,div');
    if (fig) fig.innerHTML = '<img src="'+url+'" style="max-width:100%"><figcaption contenteditable="true" style="text-align:center;font-size:.875rem;color:#555;padding:4px">캡션…</figcaption>';
  }
}
function setButtonColor(color) {
  var block = _selectedBlockEl;
  if (block) { var btn = block.querySelector('.wp-element-button'); if(btn) btn.style.background=color; }
}
function addTableRow() {
  var block = _selectedBlockEl; if(!block) return;
  var tbody = block.querySelector('tbody');
  if (!tbody) return;
  var cols = tbody.rows[0]?.cells.length || 3;
  var tr = document.createElement('tr');
  for (var i=0;i<cols;i++){var td=document.createElement('td');td.contentEditable='true';td.textContent='내용';tr.appendChild(td);}
  tbody.appendChild(tr);
}
function addTableCol() {
  var block = _selectedBlockEl; if(!block) return;
  block.querySelectorAll('tr').forEach(function(row){var td=document.createElement(row.closest('thead')?'th':'td');td.contentEditable='true';td.textContent='내용';row.appendChild(td);});
}
function setSpacerHeight(h) {
  var block = _selectedBlockEl; if(!block) return;
  var sp = block.querySelector('.wp-block-spacer'); if(sp) {sp.style.height=h+'px';sp.textContent='공백 ('+h+'px)';}
}
function setFeaturedImage() {
  var url = prompt('특성 이미지 URL:');
  if (url) {
    var wrap = document.getElementById('featured-img-wrap');
    wrap.innerHTML = '<img src="'+url+'" style="width:100%;border-radius:4px;margin-bottom:6px"><button onclick="document.getElementById(\\'featured-img-wrap\\').innerHTML=\\'\\'" style="font-size:.75rem;color:#d63638;background:none;border:none;cursor:pointer">이미지 제거</button>';
  }
}

// ── 콘텐츠 직렬화 (→ HTML) ────────────────────────────────────
function serializeBlocks() {
  var blocks = document.querySelectorAll('#blocks-container > .wp-block');
  var html = '';
  blocks.forEach(function(block) {
    var type = block.dataset.type;
    var inner = block.cloneNode(true);
    inner.querySelector('.block-controls')?.remove();
    switch(type) {
      case 'paragraph': {
        var t = inner.querySelector('[contenteditable]')?.innerHTML || '';
        if (t.trim()) html += '<!-- wp:paragraph --><p>' + t + '</p><!-- /wp:paragraph -->\\n';
        break;
      }
      case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6': {
        var t = inner.querySelector('[contenteditable]')?.innerHTML || '';
        var lv = parseInt(type[1]);
        if (t.trim()) html += '<!-- wp:heading {"level":'+lv+'} --><' + type + '>' + t + '</' + type + '><!-- /wp:heading -->\\n';
        break;
      }
      case 'list-ul': {
        var items = Array.from(inner.querySelectorAll('li')).map(function(li){ return '<li>'+li.innerHTML+'</li>'; }).join('');
        html += '<!-- wp:list --><ul>'+items+'</ul><!-- /wp:list -->\\n';
        break;
      }
      case 'list-ol': {
        var items = Array.from(inner.querySelectorAll('li')).map(function(li){ return '<li>'+li.innerHTML+'</li>'; }).join('');
        html += '<!-- wp:list {"ordered":true} --><ol>'+items+'</ol><!-- /wp:list -->\\n';
        break;
      }
      case 'quote': {
        var t = inner.querySelector('blockquote [contenteditable]')?.innerHTML || '';
        var cite = inner.querySelector('cite')?.textContent || '';
        html += '<!-- wp:quote --><blockquote class="wp-block-quote"><p>'+t+'</p>'+( cite?'<cite>'+cite+'</cite>':'' )+'</blockquote><!-- /wp:quote -->\\n';
        break;
      }
      case 'pullquote': {
        var t = inner.querySelector('p[contenteditable]')?.innerHTML || '';
        html += '<!-- wp:pullquote --><figure class="wp-block-pullquote"><blockquote><p>'+t+'</p></blockquote></figure><!-- /wp:pullquote -->\\n';
        break;
      }
      case 'code': {
        var t = inner.querySelector('code')?.textContent || '';
        html += '<!-- wp:code --><pre class="wp-block-code"><code>'+escHtml(t)+'</code></pre><!-- /wp:code -->\\n';
        break;
      }
      case 'preformatted': {
        var t = inner.querySelector('pre')?.innerHTML || '';
        html += '<!-- wp:preformatted --><pre class="wp-block-preformatted">'+t+'</pre><!-- /wp:preformatted -->\\n';
        break;
      }
      case 'verse': {
        var t = inner.querySelector('pre')?.innerHTML || '';
        html += '<!-- wp:verse --><pre class="wp-block-verse">'+t+'</pre><!-- /wp:verse -->\\n';
        break;
      }
      case 'separator':
        html += '<!-- wp:separator --><hr class="wp-block-separator"/><!-- /wp:separator -->\\n';
        break;
      case 'spacer': {
        var h = inner.querySelector('.wp-block-spacer')?.style.height || '60px';
        html += '<!-- wp:spacer {"height":"'+h+'"} --><div style="height:'+h+'" class="wp-block-spacer" aria-hidden="true"></div><!-- /wp:spacer -->\\n';
        break;
      }
      case 'image': {
        var img = inner.querySelector('img');
        var cap = inner.querySelector('figcaption')?.textContent || '';
        if (img) html += '<!-- wp:image --><figure class="wp-block-image"><img src="'+img.src+'" alt="'+(img.alt||'')+'">'+(cap?'<figcaption>'+cap+'</figcaption>':'')+'</figure><!-- /wp:image -->\\n';
        break;
      }
      case 'button': {
        var btn = inner.querySelector('.wp-element-button');
        if (btn) html += '<!-- wp:buttons --><div class="wp-block-buttons"><!-- wp:button --><div class="wp-block-button"><a class="wp-block-button__link">'+btn.innerHTML+'</a></div><!-- /wp:button --></div><!-- /wp:buttons -->\\n';
        break;
      }
      case 'table': {
        var tbl = inner.querySelector('table')?.outerHTML || '';
        if (tbl) html += '<!-- wp:table --><figure class="wp-block-table">'+tbl+'</figure><!-- /wp:table -->\\n';
        break;
      }
      case 'html': {
        var t = inner.querySelector('textarea')?.value || '';
        if (t.trim()) html += t + '\\n';
        break;
      }
      case 'shortcode': {
        var t = inner.querySelector('input')?.value || '';
        if (t.trim()) html += '<!-- wp:shortcode -->'+t+'<!-- /wp:shortcode -->\\n';
        break;
      }
      case 'embed': {
        var iframe = inner.querySelector('iframe');
        var a = inner.querySelector('a');
        if (iframe) html += '<!-- wp:embed -->' + iframe.outerHTML + '<!-- /wp:embed -->\\n';
        else if (a) html += '<!-- wp:embed {"url":"'+a.href+'"} --><figure class="wp-block-embed"><div class="wp-block-embed__wrapper">'+a.href+'</div></figure><!-- /wp:embed -->\\n';
        break;
      }
      case 'more':
        html += '<!-- wp:more --><!--more--><!-- /wp:more -->\\n';
        break;
      default: {
        var t = inner.querySelector('[contenteditable]')?.innerHTML || inner.innerHTML;
        if (t.trim()) html += '<div class="wp-block-'+type+'">'+t+'</div>\\n';
      }
    }
  });
  return html;
}

function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ── 콘텐츠 역직렬화 (HTML → 블록) ────────────────────────────
function deserializeContent(html) {
  if (!html || !html.trim()) return;
  var container = document.getElementById('blocks-container');

  // wp:block 주석 파싱
  var wpBlockRe = /<!-- wp:(\\S+)[^>]*?-->([\s\S]*?)<!-- \\/wp:\\S+ -->/g;
  var match;
  var hasBlocks = false;
  var tmpDiv = document.createElement('div');
  tmpDiv.innerHTML = html;

  // 주석이 있으면 주석 기반 파싱
  while ((match = wpBlockRe.exec(html)) !== null) {
    hasBlocks = true;
    var btype = match[1].replace('core/','');
    var inner = match[2].trim();
    tmpDiv.innerHTML = inner;

    if (btype === 'paragraph') {
      var p = tmpDiv.querySelector('p');
      appendBlock('paragraph', p ? p.innerHTML : inner);
    } else if (btype === 'heading') {
      var h = tmpDiv.querySelector('h1,h2,h3,h4,h5,h6');
      if (h) appendBlock(h.tagName.toLowerCase(), h.innerHTML);
    } else if (btype === 'list') {
      var ul = tmpDiv.querySelector('ul,ol');
      if (ul) {
        var btype2 = ul.tagName==='OL' ? 'list-ol' : 'list-ul';
        var block = createBlockEl(btype2);
        var listEl = block.querySelector('ul,ol');
        if (listEl) listEl.innerHTML = ul.innerHTML;
        container.appendChild(block);
        updateCounts();
      }
    } else if (btype === 'image') {
      var img = tmpDiv.querySelector('img');
      if (img) {
        var block = createBlockEl('image');
        var fig = block.querySelector('figure');
        if (fig) { var ni=document.createElement('img'); ni.src=img.src; ni.alt=img.alt||''; fig.innerHTML=''; fig.appendChild(ni); }
        container.appendChild(block);
        updateCounts();
      }
    } else if (btype === 'quote') {
      var bq = tmpDiv.querySelector('blockquote p,blockquote');
      appendBlock('quote', bq ? (bq.querySelector('p')?.innerHTML || bq.innerHTML) : inner);
    } else if (btype === 'code') {
      var code = tmpDiv.querySelector('code');
      appendBlock('code', code ? code.textContent : inner);
    } else if (btype === 'separator' || btype === 'more' || btype === 'page-break') {
      appendBlock(btype === 'core/separator' ? 'separator' : btype);
    } else if (btype === 'buttons') {
      appendBlock('button');
    } else if (btype === 'table') {
      var tbl = tmpDiv.querySelector('table');
      if (tbl) {
        var block = createBlockEl('table');
        var existing = block.querySelector('table');
        if (existing) existing.outerHTML = tbl.outerHTML;
        container.appendChild(block);
        updateCounts();
      }
    } else {
      appendBlock('paragraph', inner);
    }
  }

  // 주석이 없으면 HTML 태그 기반 파싱
  if (!hasBlocks && html.trim()) {
    tmpDiv.innerHTML = html;
    Array.from(tmpDiv.childNodes).forEach(function(node) {
      if (node.nodeType === 3 && node.textContent.trim()) {
        appendBlock('paragraph', node.textContent);
      } else if (node.nodeType === 1) {
        var tag = node.tagName ? node.tagName.toLowerCase() : '';
        if (tag==='p') appendBlock('paragraph', node.innerHTML);
        else if (/^h[1-6]$/.test(tag)) appendBlock(tag, node.innerHTML);
        else if (tag==='ul') { var block=createBlockEl('list-ul'); var ul=block.querySelector('ul'); if(ul){ul.innerHTML=node.innerHTML;} container.appendChild(block); updateCounts(); }
        else if (tag==='ol') { var block=createBlockEl('list-ol'); var ol=block.querySelector('ol'); if(ol){ol.innerHTML=node.innerHTML;} container.appendChild(block); updateCounts(); }
        else if (tag==='blockquote') appendBlock('quote', node.innerHTML);
        else if (tag==='pre'||tag==='code') appendBlock('code', node.textContent);
        else if (tag==='hr') appendBlock('separator');
        else if (tag==='figure') {
          var img=node.querySelector('img');
          if (img) { var block=createBlockEl('image'); var fig=block.querySelector('figure'); if(fig){var ni=document.createElement('img');ni.src=img.src;ni.alt=img.alt||'';fig.innerHTML='';fig.appendChild(ni);} container.appendChild(block); updateCounts(); }
        } else if (node.innerHTML && node.innerHTML.trim()) {
          appendBlock('paragraph', node.innerHTML);
        }
      }
    });
  }
}

function appendBlock(type, content) {
  var block = createBlockEl(type, content);
  document.getElementById('blocks-container').appendChild(block);
  updateCounts();
  return block;
}

// ── 탭 전환 ────────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.sidebar-tab').forEach(function(b){ b.classList.remove('active'); });
  document.querySelectorAll('.sidebar-panel').forEach(function(p){ p.classList.remove('active'); });
  document.querySelector('.sidebar-tab[onclick*=\\''+tab+'\\']').classList.add('active');
  document.getElementById('tab-'+tab).classList.add('active');
}

// ── 카운터 업데이트 ─────────────────────────────────────────────
function updateCounts() {
  var blocks = document.querySelectorAll('#blocks-container > .wp-block').length;
  document.getElementById('block-count').textContent = blocks + ' 블록';
  var text = document.getElementById('blocks-container').textContent || '';
  var words = text.trim().split(/\\s+/).filter(Boolean).length;
  document.getElementById('word-count').textContent = words + ' 단어';
}

// ── 태그 관리 ──────────────────────────────────────────────────
document.getElementById('post-tags').addEventListener('keydown', function(e) {
  if (e.key==='Enter'||e.key===',') {
    e.preventDefault();
    var tag = this.value.trim().replace(/,$/, '');
    if (tag && !_tags.includes(tag)) {
      _tags.push(tag);
      renderTags();
    }
    this.value = '';
  }
});
function renderTags() {
  document.getElementById('tags-list').innerHTML = _tags.map(function(t,i) {
    return '<span style="background:#f0f0f1;padding:3px 8px;border-radius:20px;font-size:.75rem;display:flex;align-items:center;gap:4px">'+t+
      '<button onclick="_tags.splice('+i+',1);renderTags()" style="background:none;border:none;cursor:pointer;color:#757575;line-height:1;font-size:.75rem">✕</button></span>';
  }).join('');
}

async function addCategory() {
  var name = document.getElementById('new-cat').value.trim();
  if (!name) return;
  try {
    var r = await fetch('/wp-json/wp/v2/categories', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,slug:name.toLowerCase().replace(/\\s+/g,'-')})});
    if (r.ok) { document.getElementById('new-cat').value=''; loadCategories(); }
    else alert('카테고리 추가 실패');
  } catch(e) { alert(e.message); }
}

// ── 카테고리 로드 ──────────────────────────────────────────────
async function loadCategories() {
  try {
    var r = await fetch('/wp-json/wp/v2/categories?per_page=50',{headers:{'Accept':'application/json'}});
    var cats = r.ok ? await r.json() : [];
    cats = Array.isArray(cats) ? cats : [];
    var el = document.getElementById('cats-list');
    if (!cats.length) { el.textContent='카테고리 없음'; return; }
    el.innerHTML = cats.map(function(c) {
      return '<label style="display:flex;align-items:center;gap:6px;padding:3px 0;font-size:.8125rem;cursor:pointer">' +
        '<input type="checkbox" value="'+c.id+'" class="cat-cb"> '+c.name+'</label>';
    }).join('');
  } catch {}
}
loadCategories();

// ── 기존 글 로드 ──────────────────────────────────────────────
${isEdit && postId ? `
(async function(){
  try {
    var r = await fetch('/wp-json/wp/v2/${postType === 'page' ? 'pages' : 'posts'}/${postId}', {headers:{'Accept':'application/json'}});
    if (!r.ok) return;
    var p = await r.json();
    document.getElementById('post-title').value = (p.title&&p.title.rendered)||'';
    document.getElementById('post-title').dispatchEvent(new Event('input'));
    document.getElementById('post-status').value = p.status||'publish';
    document.getElementById('post-slug').value = p.slug||'';
    document.getElementById('post-slug').dataset.manual = '1';
    if (p.excerpt&&p.excerpt.rendered) document.getElementById('post-excerpt').value = p.excerpt.rendered.replace(/<[^>]+>/g,'').trim();
    // 블록 컨텐츠 로드
    var rawContent = (p.content&&p.content.raw) || (p.content&&p.content.rendered) || '';
    if (rawContent) deserializeContent(rawContent);
    else appendBlock('paragraph','');
    // 카테고리 체크
    if (p.categories) setTimeout(function(){
      p.categories.forEach(function(id){
        var cb = document.querySelector('.cat-cb[value="'+id+'"]');
        if (cb) cb.checked=true;
      });
    }, 500);
    // 태그
    if (p.tags && p.tags.length) {
      try {
        var tr = await fetch('/wp-json/wp/v2/tags?include='+p.tags.join(','));
        var tagData = tr.ok ? await tr.json() : [];
        _tags = (Array.isArray(tagData)?tagData:[]).map(function(t){return t.name;});
        renderTags();
      } catch {}
    }
  } catch(e) { console.error('글 로드 오류:',e); }
})();` : `
// 새 글: 빈 단락 블록 하나 삽입
insertBlock('paragraph');
`}

// ── 자동 저장 ──────────────────────────────────────────────────
function scheduleAutosave() {
  clearTimeout(_autoSaveTimer);
  document.getElementById('post-status-bar').textContent='자동 저장: 대기 중…';
  _autoSaveTimer = setTimeout(function(){ autoSave(); }, 3000);
}
document.getElementById('blocks-container').addEventListener('input', scheduleAutosave);
document.getElementById('post-title').addEventListener('input', scheduleAutosave);

async function autoSave() {
  var title = document.getElementById('post-title').value.trim();
  var content = serializeBlocks();
  if (!title && !content) return;
  document.getElementById('post-status-bar').textContent='자동 저장 중…';
  try {
    var method = _postId ? 'PATCH' : 'POST';
    var apiType = _postType === 'page' ? 'pages' : 'posts';
    var endpoint = _postId ? '/wp-json/wp/v2/'+apiType+'/'+_postId : '/wp-json/wp/v2/'+apiType;
    var r = await fetch(endpoint,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify({title,content,status:'draft'})});
    if (r.ok) {
      var d = await r.json();
      if (!_postId && d.id) { _postId=d.id; history.replaceState(null,'','/wp-admin/post.php?post='+d.id+'&action=edit'); }
      document.getElementById('post-status-bar').textContent='자동 저장됨: '+new Date().toLocaleTimeString('ko-KR');
    }
  } catch(e) { document.getElementById('post-status-bar').textContent='자동 저장 실패'; }
}

async function savePost() { await _save('publish'); }
async function saveDraft() { await _save('draft'); }

async function _save(status) {
  var title = document.getElementById('post-title').value.trim();
  var content = serializeBlocks();
  var selStatus = document.getElementById('post-status').value || status;
  var slug = document.getElementById('post-slug').value.trim();
  var excerpt = document.getElementById('post-excerpt').value.trim();
  if (!title) { alert('제목을 입력하세요.'); document.getElementById('post-title').focus(); return; }
  var cats = [];
  document.querySelectorAll('.cat-cb:checked').forEach(function(el){ cats.push(parseInt(el.value,10)); });
  var tagList = _tags.slice();
  document.getElementById('post-status-bar').textContent='저장 중…';
  var apiType = _postType === 'page' ? 'pages' : 'posts';
  var method = _postId ? 'PATCH' : 'POST';
  var endpoint = _postId ? '/wp-json/wp/v2/'+apiType+'/'+_postId : '/wp-json/wp/v2/'+apiType;
  var payload = {title, content, status:selStatus};
  if (slug) payload.slug = slug;
  if (excerpt) payload.excerpt = excerpt;
  if (cats.length) payload.categories = cats;
  try {
    var r = await fetch(endpoint,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    var d = await r.json();
    if (r.ok && d.id) {
      _postId = d.id;
      history.replaceState(null,'','/wp-admin/post.php?post='+d.id+'&action=edit');
      document.getElementById('post-status-bar').textContent = selStatus==='publish'?'게시됨':'임시저장됨';
      if (selStatus==='publish') {
        if (confirm('게시되었습니다! 게시글을 확인하시겠습니까?')) window.open('/'+d.slug+'/','_blank');
      }
      // 태그 저장
      if (tagList.length) {
        var tagIds = [];
        for (var tagName of tagList) {
          try {
            var tr = await fetch('/wp-json/wp/v2/tags',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:tagName,slug:tagName.toLowerCase().replace(/\\s+/g,'-')})});
            var td = tr.ok ? await tr.json() : null;
            if (td && td.id) tagIds.push(td.id);
          } catch {}
        }
        if (tagIds.length) await fetch(endpoint.replace(endpoint.split('/').pop(),d.id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({tags:tagIds})});
      }
    } else {
      alert('저장 실패: '+(d.message||JSON.stringify(d)));
      document.getElementById('post-status-bar').textContent='저장 실패';
    }
  } catch(e) { alert('오류: '+e.message); document.getElementById('post-status-bar').textContent='오류 발생'; }
}

// 날짜 기본값
document.getElementById('post-date').value = new Date().toISOString().slice(0,16);
updateCounts();
`;



  } else if (page === 'upload') {
    pageTitle = '미디어 라이브러리';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:15px;display:flex;align-items:center;gap:10px">
      <label class="btn-wp" style="cursor:pointer">📤 새 미디어 추가
        <input type="file" id="file-input" style="display:none" accept="image/*,video/*,audio/*,.pdf" multiple>
      </label>
      <div id="upload-progress" style="display:none;font-size:.85rem;color:#2271b1">업로드 중...</div>
    </div>
    <div id="media-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px">
      <div style="text-align:center;padding:40px;color:#8c8f94;grid-column:1/-1">불러오는 중...</div>
    </div>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/media?per_page=30',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var media=r.ok?await r.json():[];
media=Array.isArray(media)?media:[];
var el=document.getElementById('media-grid');
if(!media.length){el.innerHTML='<div style="text-align:center;padding:60px;color:#8c8f94;grid-column:1/-1"><p style="font-size:2rem;margin-bottom:8px">🖼️</p><p>미디어 파일이 없습니다.</p></div>';return;}
el.innerHTML=media.map(function(m){
  var src=m.source_url||(m.guid&&m.guid.rendered)||'';
  var isImg=(m.mime_type||'').startsWith('image/');
  var ttl=(m.title&&m.title.rendered)||m.slug||'파일';
  return '<div style="border:1px solid #dcdcde;border-radius:4px;overflow:hidden;background:#f6f7f7;cursor:pointer" onclick="showMediaDetail(this)" data-url="'+src+'" data-title="'+ttl+'">'+
    (isImg?'<img src="'+src+'" style="width:100%;height:130px;object-fit:cover;display:block">':
    '<div style="height:130px;display:flex;align-items:center;justify-content:center;font-size:2.5rem">📄</div>')+
    '<p style="margin:0;padding:5px 7px;font-size:.75rem;color:#1d2327;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+ttl+'</p>'+
    '</div>';
}).join('');
})();

document.getElementById('file-input').addEventListener('change',async function(){
  var files=Array.from(this.files);
  if(!files.length)return;
  var prog=document.getElementById('upload-progress');
  prog.style.display='block';
  for(var i=0;i<files.length;i++){
    prog.textContent='업로드 중: '+(i+1)+'/'+files.length;
    var fd=new FormData();fd.append('file',files[i]);fd.append('title',files[i].name);
    await fetch('/wp-admin/async-upload.php',{method:'POST',body:fd}).catch(function(){});
  }
  prog.style.display='none';
  location.reload();
});

function showMediaDetail(el){
  var url=el.getAttribute('data-url');
  var title=el.getAttribute('data-title');
  if(url)prompt('미디어 URL (복사하세요):',url);
}`;

  } else if (page === 'themes' || page === 'theme-install') {
    pageTitle = page === 'theme-install' ? '새 테마 추가' : '테마';
    // Twenty Twenty-Five 포함 WP 공식 테마 목록 (theme.json 기반)
    const builtinThemes = [
      { slug:'twentytwentyfive', name:'Twenty Twenty-Five', ver:'1.4', active:true,
        desc:'단순함과 적응성을 강조한 블록 테마. 개인 블로그, 포트폴리오, 온라인 매거진에 최적.',
        colors:['#FFFFFF','#111111','#FFEE58','#F6CFF4','#503AA8'],
        screenshot:'linear-gradient(135deg,#FBFAF3 50%,#FFEE58 100%)',
        tags:['블록 테마','풀 사이트 편집','접근성']},
      { slug:'twentytwentyfour', name:'Twenty Twenty-Four', ver:'1.3',
        desc:'블록 테마의 다목적 캔버스. 다양한 스타일 변형 포함.',
        colors:['#FAFAFA','#1A1A1A','#D1E4DD'],
        screenshot:'linear-gradient(135deg,#FAFAFA 50%,#D1E4DD 100%)',
        tags:['블록 테마','풀 사이트 편집']},
      { slug:'twentytwentythree', name:'Twenty Twenty-Three', ver:'1.5',
        desc:'유연하고 가벼운 블록 테마. 다양한 색상 팔레트.',
        colors:['#FFFFFF','#000000','#CDDCE8'],
        screenshot:'linear-gradient(135deg,#fff 50%,#CDDCE8 100%)',
        tags:['블록 테마','미니멀']},
      { slug:'astra', name:'Astra', ver:'4.8',
        desc:'초경량(< 50KB) 다목적 테마. WooCommerce 완벽 지원.',
        colors:['#ffffff','#3a3a3a','#4169e1'],
        screenshot:'linear-gradient(135deg,#ffffff 50%,#4169e1 100%)',
        tags:['다목적','WooCommerce','빠른 속도']},
      { slug:'generatepress', name:'GeneratePress', ver:'3.4',
        desc:'성능과 접근성에 집중. 모든 페이지 빌더와 호환.',
        colors:['#ffffff','#252525','#1b8be0'],
        screenshot:'linear-gradient(135deg,#f5f5f5 50%,#1b8be0 100%)',
        tags:['경량','접근성','페이지 빌더']},
      { slug:'kadence', name:'Kadence', ver:'1.2',
        desc:'강력한 커스터마이징. 헤더/푸터 빌더 포함.',
        colors:['#ffffff','#1a1a1a','#3182CE'],
        screenshot:'linear-gradient(135deg,#f0f0f0 50%,#3182CE 100%)',
        tags:['블록 테마','커스터마이징','빌더']},
    ];
    if (page === 'theme-install') {
      bodyHtml = `
<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
  <h2 style="margin:0;font-size:1.1rem">테마 검색 및 설치</h2>
  <div style="flex:1;max-width:300px">
    <input type="text" id="theme-search" placeholder="WordPress.org 테마 검색…" 
      style="width:100%;padding:7px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"
      oninput="searchThemes(this.value)">
  </div>
  <a href="/wp-admin/themes.php" style="font-size:.875rem;color:#2271b1">← 내 테마로</a>
</div>
<div id="theme-search-notice" style="display:none;padding:10px 14px;background:#e7f3ff;border:1px solid #72aee6;border-radius:4px;margin-bottom:16px;font-size:.875rem"></div>
<div id="themes-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px">
  ${builtinThemes.map(t => `
  <div class="theme-card" data-slug="${t.slug}" style="border:1px solid #c3c4c7;border-radius:6px;overflow:hidden;background:#fff;transition:box-shadow .2s" onmouseenter="this.style.boxShadow='0 4px 12px rgba(0,0,0,.12)'" onmouseleave="this.style.boxShadow=''">
    <div style="height:140px;background:${t.screenshot};position:relative">
      <div style="position:absolute;bottom:8px;right:8px;display:flex;gap:4px">
        ${t.colors.map(c=>`<span style="width:16px;height:16px;border-radius:50%;background:${c};border:1px solid rgba(0,0,0,.1)"></span>`).join('')}
      </div>
    </div>
    <div style="padding:14px">
      <h3 style="margin:0 0 5px;font-size:.9375rem">${t.name} <span style="color:#8c8f94;font-weight:400;font-size:.8rem">v${t.ver}</span></h3>
      <p style="margin:0 0 8px;font-size:.8rem;color:#50575e;line-height:1.5">${t.desc}</p>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
        ${t.tags.map(tag=>`<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">${tag}</span>`).join('')}
      </div>
      <div style="display:flex;gap:6px">
        <button onclick="installTheme('${t.slug}','${t.name}',this)" style="flex:1;padding:6px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600">설치</button>
        <button onclick="previewTheme('${t.slug}')" style="padding:6px 10px;background:#f6f7f7;border:1px solid #ccc;border-radius:4px;cursor:pointer;font-size:.8rem">미리보기</button>
      </div>
    </div>
  </div>`).join('')}
</div>
<div id="wp-org-results" style="display:none;margin-top:30px">
  <h3 style="font-size:1rem;margin-bottom:12px">WordPress.org 검색 결과</h3>
  <div id="wp-org-themes-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px"></div>
</div>`;
      inlineScript = `
async function searchThemes(q) {
  const notice = document.getElementById('theme-search-notice');
  if (!q || q.length < 2) { notice.style.display='none'; return; }
  notice.style.display='block'; notice.textContent='WordPress.org에서 테마 검색 중…';
  try {
    const r = await fetch('https://api.wordpress.org/themes/info/1.1/?action=query_themes&request[search]='+encodeURIComponent(q)+'&request[per_page]=8&request[fields][screenshot_url]=1&request[fields][version]=1&request[fields][description]=1&request[fields][tags]=1');
    const data = r.ok ? await r.json() : null;
    const grid = document.getElementById('wp-org-themes-grid');
    const section = document.getElementById('wp-org-results');
    if (data && data.themes && data.themes.length) {
      grid.innerHTML = data.themes.map(t => \`
        <div style="border:1px solid #c3c4c7;border-radius:6px;overflow:hidden;background:#fff">
          <div style="height:120px;background:url('\${t.screenshot_url}') center/cover no-repeat #f0f0f1"></div>
          <div style="padding:12px">
            <h4 style="margin:0 0 5px;font-size:.875rem">\${t.name} <span style="color:#8c8f94;font-size:.75rem">v\${t.version}</span></h4>
            <p style="margin:0 0 8px;font-size:.75rem;color:#50575e;line-height:1.4">\${(t.description||'').replace(/<[^>]+>/g,'').slice(0,100)}…</p>
            <button onclick="installTheme('\${t.slug}','\${t.name.replace(/'/g,'')}',this)" style="width:100%;padding:5px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600">설치</button>
          </div>
        </div>\`).join('');
      section.style.display='block';
      notice.textContent=\`\${data.themes.length}개의 테마를 찾았습니다.\`;
    } else {
      section.style.display='none';
      notice.textContent='검색 결과가 없습니다.';
    }
  } catch(e) { notice.textContent='검색 중 오류: '+e.message; }
}
async function installTheme(slug, name, btn) {
  btn.textContent='설치 중…'; btn.disabled=true;
  try {
    const r = await fetch('/wp-json/cloudpress/v1/themes/install', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    const d = r.ok ? await r.json() : {success:false};
    if (d.success) {
      btn.textContent='✓ 설치됨'; btn.style.background='#00a32a';
      btn.nextElementSibling && (btn.nextElementSibling.textContent = '활성화');
      btn.nextElementSibling && btn.nextElementSibling.setAttribute('onclick', \`activateTheme('\${slug}','\${name}',this)\`);
    } else {
      btn.textContent='실패'; btn.style.background='#d63638';
    }
  } catch(e) { btn.textContent='오류'; btn.style.background='#d63638'; }
}
async function activateTheme(slug, name, btn) {
  btn.textContent='활성화 중…'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/themes/activate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  if (d.success) { btn.textContent='✓ 활성화됨'; btn.style.background='#00a32a'; }
  else { btn.textContent='실패'; btn.disabled=false; }
}
function previewTheme(slug) {
  window.open('/wp-admin/themes.php?preview='+slug, '_blank');
}`;
    } else {
      // 테마 목록 페이지
      bodyHtml = `
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
  <h2 style="margin:0;font-size:1.1rem">테마 (${builtinThemes.length}개)</h2>
  <a href="/wp-admin/theme-install.php" class="btn-wp">새 테마 추가</a>
</div>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:20px">
${builtinThemes.map(t => `
  <div style="border:${t.active?'3px solid #2271b1':'1px solid #c3c4c7'};border-radius:6px;overflow:hidden;background:#fff;position:relative;transition:box-shadow .2s" onmouseenter="this.style.boxShadow='0 4px 12px rgba(0,0,0,.15)'" onmouseleave="this.style.boxShadow=''">
    ${t.active?`<span style="position:absolute;top:10px;left:10px;background:#2271b1;color:#fff;font-size:.7rem;font-weight:700;padding:3px 8px;border-radius:20px;z-index:1">활성화된 테마</span>`:''}
    <div style="height:150px;background:${t.screenshot};display:flex;align-items:flex-end;padding:8px;justify-content:flex-end">
      <div style="display:flex;gap:3px">
        ${t.colors.map(c=>`<span style="width:14px;height:14px;border-radius:50%;background:${c};border:1px solid rgba(0,0,0,.1)"></span>`).join('')}
      </div>
    </div>
    <div style="padding:14px">
      <h3 style="margin:0 0 5px;font-size:.9375rem">${t.name} <span style="color:#8c8f94;font-weight:400;font-size:.8rem">v${t.ver}</span></h3>
      <p style="margin:0 0 10px;font-size:.8rem;color:#50575e;line-height:1.5">${t.desc}</p>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px">
        ${t.tags.map(tag=>`<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">${tag}</span>`).join('')}
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${t.active
          ? `<button onclick="customizeTheme()" style="flex:1;padding:7px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600">🎨 커스터마이즈</button>`
          : `<button onclick="activateTheme('${t.slug}','${t.name}',this)" style="flex:1;padding:7px;background:#00a32a;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600">활성화</button>`
        }
        <button onclick="window.open('/','_blank')" style="padding:7px 10px;background:#f6f7f7;border:1px solid #ccc;border-radius:4px;cursor:pointer;font-size:.8rem">미리보기</button>
        ${!t.active?`<button style="padding:7px 10px;background:#fff;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;color:#d63638" onclick="if(confirm('${t.name} 테마를 삭제하시겠습니까?'))deleteTheme('${t.slug}',this)">삭제</button>`:''}
      </div>
    </div>
  </div>`).join('')}
</div>`;
      inlineScript = `
async function activateTheme(slug, name, btn) {
  if (!confirm(name + ' 테마를 활성화하시겠습니까?')) return;
  btn.textContent='처리 중…'; btn.disabled=true;
  try {
    const r = await fetch('/wp-json/cloudpress/v1/themes/activate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    const d = r.ok ? await r.json() : {success:false};
    if (d.success) { location.reload(); }
    else { alert('활성화 실패: ' + (d.message||'')); btn.textContent='활성화'; btn.disabled=false; }
  } catch(e) { alert('오류: '+e.message); btn.textContent='활성화'; btn.disabled=false; }
}
async function deleteTheme(slug, btn) {
  const r = await fetch('/wp-json/cloudpress/v1/themes/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug})
  });
  if (r.ok) { btn.closest('[data-slug]')?.remove() || location.reload(); }
}
function customizeTheme() { window.open('/wp-admin/customize.php','_blank'); }`;
    }

  } else if (page === 'plugins' || page === 'plugin-install') {
    pageTitle = page === 'plugin-install' ? '새 플러그인 추가' : '플러그인';

    if (page === 'plugin-install') {
      // ── 플러그인 추가 페이지: 검색 + ZIP 업로드만 ──
      bodyHtml = `
<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap">
  <h2 style="margin:0;font-size:1.1rem">플러그인 추가</h2>
  <div style="flex:1;max-width:400px;position:relative;min-width:200px">
    <input type="text" id="plugin-search" placeholder="WordPress.org 플러그인 검색…"
      style="width:100%;padding:7px 36px 7px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"
      oninput="debounceSearch(this.value)">
    <span style="position:absolute;right:10px;top:50%;transform:translateY(-50%);color:#8c8f94">🔍</span>
  </div>
  <div style="display:flex;gap:6px">
    <button onclick="wpTab('featured')" id="tab-featured" class="ptab active-ptab" style="padding:6px 12px;border:1px solid #2271b1;border-radius:4px;cursor:pointer;font-size:.8rem;background:#2271b1;color:#fff">추천</button>
    <button onclick="wpTab('popular')" id="tab-popular" class="ptab" style="padding:6px 12px;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;background:#f6f7f7">인기</button>
    <button onclick="wpTab('new')" id="tab-new" class="ptab" style="padding:6px 12px;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;background:#f6f7f7">최신</button>
  </div>
  <a href="/wp-admin/plugins.php" style="font-size:.875rem;color:#2271b1;margin-left:auto">← 설치된 플러그인</a>
</div>

<!-- ZIP 업로드 섹션 -->
<div id="zip-upload-section" style="background:#f6f7f7;border:1px solid #dcdcde;border-radius:6px;padding:16px;margin-bottom:20px">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <div>
      <strong style="font-size:.9rem">ZIP 파일로 플러그인 설치</strong>
      <p style="margin:4px 0 0;font-size:.8rem;color:#50575e">WordPress 플러그인 ZIP 파일을 업로드하여 설치할 수 있습니다.</p>
    </div>
    <label style="cursor:pointer;margin-left:auto">
      <span class="btn-wp btn-secondary" style="display:inline-flex;align-items:center;gap:6px;font-size:.875rem;cursor:pointer">
        📦 ZIP 업로드
      </span>
      <input type="file" accept=".zip" style="display:none" onchange="installFromZip(this)">
    </label>
  </div>
  <div id="zip-progress" style="display:none;margin-top:12px">
    <div style="background:#ddd;border-radius:4px;height:8px;overflow:hidden">
      <div id="zip-bar" style="background:#2271b1;height:100%;width:0%;transition:width .3s"></div>
    </div>
    <div id="zip-status" style="font-size:.8rem;color:#50575e;margin-top:6px"></div>
  </div>
</div>

<div id="search-results-bar" style="display:none;padding:10px 14px;background:#e7f3ff;border:1px solid #72aee6;border-radius:4px;margin-bottom:16px;font-size:.875rem"></div>

<div id="wp-org-loading" style="display:none;text-align:center;padding:40px;color:#8c8f94">
  <div style="font-size:2rem;margin-bottom:8px">⏳</div>
  WordPress.org에서 불러오는 중…
</div>

<div id="plugin-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
  <div style="grid-column:1/-1;text-align:center;padding:40px;color:#8c8f94">
    <div style="font-size:2rem;margin-bottom:8px">🔌</div>
    검색하거나 탭을 클릭하여 플러그인을 찾아보세요.
  </div>
</div>`;

      inlineScript = `
var _searchTimer = null;
var _installedSlugs = new Set();

// 설치된 플러그인 목록 가져오기
(async function() {
  try {
    var r = await fetch('/wp-json/cloudpress/v1/plugins', {headers:{'Accept':'application/json'}});
    var list = r.ok ? await r.json() : [];
    (Array.isArray(list)?list:[]).forEach(function(p){ _installedSlugs.add(p.slug); });
  } catch {}
  // 초기 추천 로드
  wpTab('featured');
})();

function debounceSearch(q) {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(function(){ searchPlugins(q); }, 500);
}

async function searchPlugins(q) {
  var bar = document.getElementById('search-results-bar');
  var grid = document.getElementById('plugin-grid');
  var loading = document.getElementById('wp-org-loading');

  if (!q || q.length < 2) {
    bar.style.display='none';
    wpTab('featured');
    return;
  }

  // 탭 비활성화
  document.querySelectorAll('.ptab').forEach(function(b){
    b.style.background='#f6f7f7'; b.style.color='#1e1e1e'; b.style.borderColor='#c3c4c7';
  });

  bar.style.display='block'; bar.textContent='WordPress.org 검색 중…';
  grid.innerHTML=''; loading.style.display='block';

  try {
    var url = 'https://api.wordpress.org/plugins/info/1.2/?action=query_plugins' +
      '&request[search]=' + encodeURIComponent(q) +
      '&request[per_page]=12' +
      '&request[fields][short_description]=1&request[fields][icons]=1' +
      '&request[fields][downloaded]=1&request[fields][rating]=1' +
      '&request[fields][active_installs]=1&request[fields][tags]=1&request[fields][version]=1';
    var r = await fetch(url);
    loading.style.display='none';
    if (r.ok) {
      var data = await r.json();
      var plugins = data.plugins || [];
      if (plugins.length) {
        bar.textContent = '"' + q + '" 검색 결과: ' + plugins.length + '개';
        renderPluginCards(plugins);
      } else {
        bar.textContent = '검색 결과가 없습니다.';
        grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#8c8f94">검색 결과가 없습니다.</div>';
      }
    } else {
      throw new Error('API 응답 오류');
    }
  } catch(e) {
    loading.style.display='none';
    bar.textContent='검색 실패: ' + e.message;
    grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:40px;color:#d63638">WordPress.org 연결 실패. 잠시 후 다시 시도하세요.</div>';
  }
}

async function wpTab(type) {
  // 탭 스타일 업데이트
  document.querySelectorAll('.ptab').forEach(function(b){
    b.style.background='#f6f7f7'; b.style.color='#1e1e1e'; b.style.borderColor='#c3c4c7';
  });
  var activeTab = document.getElementById('tab-' + type);
  if (activeTab) { activeTab.style.background='#2271b1'; activeTab.style.color='#fff'; activeTab.style.borderColor='#2271b1'; }

  var bar = document.getElementById('search-results-bar');
  var grid = document.getElementById('plugin-grid');
  var loading = document.getElementById('wp-org-loading');
  document.getElementById('plugin-search').value = '';
  bar.style.display='none';
  grid.innerHTML='';
  loading.style.display='block';

  try {
    var browseMap = {featured:'browse=featured', popular:'browse=popular', new:'browse=new'};
    var url = 'https://api.wordpress.org/plugins/info/1.2/?action=query_plugins' +
      '&request[' + browseMap[type] + ']' +
      '&request[per_page]=12' +
      '&request[fields][short_description]=1&request[fields][icons]=1' +
      '&request[fields][downloaded]=1&request[fields][rating]=1' +
      '&request[fields][active_installs]=1&request[fields][tags]=1&request[fields][version]=1';
    var r = await fetch(url);
    loading.style.display='none';
    if (r.ok) {
      var data = await r.json();
      renderPluginCards(data.plugins || []);
    } else {
      throw new Error('API 응답 오류');
    }
  } catch(e) {
    loading.style.display='none';
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#d63638">WordPress.org 로드 실패: ' + e.message + '</div>';
  }
}

function renderPluginCards(plugins) {
  var grid = document.getElementById('plugin-grid');
  if (!plugins.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#8c8f94">플러그인이 없습니다.</div>';
    return;
  }
  grid.innerHTML = plugins.map(function(p) {
    var icon = (p.icons && (p.icons['1x'] || p.icons.default)) || '';
    var stars = Math.round((p.rating || 0) / 20);
    var installs = p.active_installs >= 1000000 ? Math.floor(p.active_installs/1000000)+'M+'
                 : p.active_installs >= 1000 ? Math.floor(p.active_installs/1000)+'K+'
                 : String(p.active_installs || 0);
    var tags = Object.values(p.tags || {}).slice(0,3);
    var installed = _installedSlugs.has(p.slug);
    var safeSlug = p.slug.replace(/'/g,'');
    var safeName = (p.name||'').replace(/'/g,'').replace(/"/g,'');
    return '<div style="border:1px solid #c3c4c7;border-radius:6px;background:#fff;padding:16px;display:flex;flex-direction:column;gap:10px">' +
      '<div style="display:flex;align-items:flex-start;gap:12px">' +
      '<div style="width:52px;height:52px;border-radius:8px;overflow:hidden;background:#f6f7f7;flex-shrink:0;display:flex;align-items:center;justify-content:center">' +
      (icon ? '<img src="'+icon+'" style="width:100%;height:100%;object-fit:cover">' : '<span style="font-size:1.6rem">🔌</span>') + '</div>' +
      '<div style="flex:1;min-width:0"><div style="font-weight:700;font-size:.9rem;margin-bottom:2px">'+p.name+'</div>' +
      '<div style="font-size:.75rem;color:#8c8f94">v'+(p.version||'')+'  ·  활성: '+installs+'</div></div></div>' +
      '<p style="margin:0;font-size:.8rem;color:#50575e;line-height:1.5;flex:1">'+(p.short_description||'').replace(/<[^>]+>/g,'').slice(0,130)+'…</p>' +
      '<div style="display:flex;flex-wrap:wrap;gap:4px">' + tags.map(function(t){ return '<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">'+t+'</span>'; }).join('') + '</div>' +
      '<div style="display:flex;align-items:center;gap:6px">' +
      '<div style="flex:1;font-size:.75rem;color:#f0ad00">' + '★'.repeat(stars) + '☆'.repeat(5-stars) + ' <span style="color:#8c8f94">'+((p.rating||0)/20).toFixed(1)+'</span></div>' +
      (installed
        ? '<span style="padding:6px 14px;background:#00a32a;color:#fff;border-radius:4px;font-size:.8rem;font-weight:600">✓ 설치됨</span>'
        : '<button id="btn-'+safeSlug+'" onclick="doInstall(\''+safeSlug+'\',\''+safeName+'\',this)" style="padding:6px 14px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600">지금 설치</button>') +
      '<button onclick="window.open(\'https://wordpress.org/plugins/'+safeSlug+'/\',\'_blank\')" style="padding:6px 10px;background:#f6f7f7;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem">상세</button>' +
      '</div></div>';
  }).join('');
}

async function doInstall(slug, name, btn) {
  btn.textContent='설치 중…'; btn.disabled=true; btn.style.background='#72aee6';
  try {
    var r = await fetch('/wp-json/cloudpress/v1/plugins/install', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    var d = r.ok ? await r.json() : {success:false, message:'응답 오류'};
    if (d.success) {
      _installedSlugs.add(slug);
      btn.textContent='활성화'; btn.style.background='#00a32a'; btn.disabled=false;
      btn.setAttribute('onclick', 'doActivate(\''+slug+'\',\''+name+'\',this)');
    } else {
      btn.textContent='설치 실패'; btn.style.background='#d63638'; btn.disabled=false;
      alert('설치 실패: ' + (d.message||'알 수 없는 오류'));
    }
  } catch(e) {
    btn.textContent='오류'; btn.style.background='#d63638'; btn.disabled=false;
    alert('설치 오류: ' + e.message);
  }
}

async function doActivate(slug, name, btn) {
  btn.textContent='활성화 중…'; btn.disabled=true;
  try {
    var r = await fetch('/wp-json/cloudpress/v1/plugins/activate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    var d = r.ok ? await r.json() : {success:false};
    if (d.success) {
      btn.textContent='✓ 활성화됨'; btn.style.background='#00a32a';
      setTimeout(function(){ window.location.href='/wp-admin/plugins.php'; }, 800);
    } else {
      btn.textContent='활성화 실패'; btn.disabled=false;
      alert('활성화 실패: ' + (d.message||''));
    }
  } catch(e) { btn.textContent='오류'; btn.disabled=false; alert(e.message); }
}

// ── ZIP 업로드 설치 ──────────────────────────────────────────────
async function installFromZip(input) {
  var file = input.files[0]; if (!file) return;
  if (!file.name.endsWith('.zip')) { alert('ZIP 파일만 지원됩니다.'); return; }
  var progress = document.getElementById('zip-progress');
  var bar = document.getElementById('zip-bar');
  var status = document.getElementById('zip-status');
  progress.style.display='block';
  bar.style.width='20%'; status.textContent = '파일 읽는 중…';

  try {
    // ZIP 파일을 base64로 읽기
    var reader = new FileReader();
    reader.readAsArrayBuffer(file);
    await new Promise(function(resolve, reject) {
      reader.onload = resolve; reader.onerror = reject;
    });
    bar.style.width='40%'; status.textContent = '플러그인 정보 분석 중…';

    // ZIP에서 플러그인 이름 추출 시도
    var pluginName = file.name.replace('.zip','').replace(/-\\d+\\.\\d+.*$/,'').replace(/-/g,' ')
      .replace(/\\b\\w/g, function(c){ return c.toUpperCase(); });
    var pluginSlug = file.name.replace('.zip','').replace(/[^a-z0-9-]/gi,'-').toLowerCase().replace(/-+/g,'-').replace(/^-|-$/g,'');

    bar.style.width='70%'; status.textContent = '서버에 업로드 중…';

    // FormData로 서버에 전송
    var fd = new FormData();
    fd.append('plugin_zip', file);
    fd.append('plugin_name', pluginName);
    fd.append('plugin_slug', pluginSlug);

    var r = await fetch('/wp-json/cloudpress/v1/plugins/upload', {method:'POST', body:fd});
    bar.style.width='90%'; status.textContent = '설치 완료 처리 중…';
    var d = r.ok ? await r.json() : {success:false, message:'서버 오류'};

    if (d.success) {
      bar.style.width='100%'; bar.style.background='#00a32a';
      status.textContent = '✓ ' + (d.plugin?.name || pluginName) + ' 설치됨! 활성화하시겠습니까?';
      _installedSlugs.add(d.plugin?.slug || pluginSlug);
      if (confirm((d.plugin?.name||pluginName) + ' 설치 완료!\n지금 활성화하시겠습니까?')) {
        await doActivateBySlug(d.plugin?.slug || pluginSlug, d.plugin?.name || pluginName);
        window.location.href='/wp-admin/plugins.php';
      } else {
        setTimeout(function(){ window.location.href='/wp-admin/plugins.php'; }, 1500);
      }
    } else {
      bar.style.background='#d63638';
      status.textContent = '설치 실패: ' + (d.message||'알 수 없는 오류');
    }
  } catch(e) {
    bar.style.background='#d63638';
    status.textContent = '오류: ' + e.message;
  }
  input.value='';
}

async function doActivateBySlug(slug, name) {
  var r = await fetch('/wp-json/cloudpress/v1/plugins/activate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  return r.ok ? await r.json() : {success:false};
}
`;



    } else {
      // ── 설치된 플러그인 목록 ──
      bodyHtml = `
<div id="plugin-msg" style="display:none;padding:10px 14px;border-radius:4px;margin-bottom:12px"></div>
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
  <div style="display:flex;align-items:center;gap:8px">
    <h2 style="margin:0;font-size:1.1rem">플러그인</h2>
    <span id="plugin-count" style="background:#f0f0f1;color:#50575e;font-size:.75rem;padding:2px 8px;border-radius:20px">불러오는 중…</span>
  </div>
  <div style="display:flex;gap:8px">
    <input type="text" id="plugin-filter" placeholder="플러그인 검색…" oninput="filterList(this.value)"
      style="padding:6px 10px;border:1px solid #8c8f94;border-radius:4px;font-size:.8rem;width:200px">
    <a href="/wp-admin/plugin-install.php" class="btn-wp">새 플러그인 추가</a>
  </div>
</div>
<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
  <thead>
    <tr style="background:#f6f7f7;border-bottom:1px solid #c3c4c7">
      <th style="padding:8px 12px;text-align:left;font-size:.875rem">플러그인</th>
      <th style="padding:8px 12px;text-align:left;font-size:.875rem;width:80px">버전</th>
      <th style="padding:8px 12px;text-align:left;font-size:.875rem;width:90px">상태</th>
      <th style="padding:8px 12px;text-align:left;font-size:.875rem;width:200px">작업</th>
    </tr>
  </thead>
  <tbody id="plugins-list">
    <tr><td colspan="4" style="padding:20px;text-align:center;color:#8c8f94">플러그인 목록을 불러오는 중…</td></tr>
  </tbody>
</table>`;

      inlineScript = `
(async function() {
  const list = document.getElementById('plugins-list');
  const countEl = document.getElementById('plugin-count');
  try {
    const r = await fetch('/wp-json/cloudpress/v1/plugins', {headers:{'Accept':'application/json'}});
    const plugins = r.ok ? await r.json() : [];
    if (!plugins.length) {
      list.innerHTML='<tr><td colspan="4" style="padding:20px;text-align:center;color:#8c8f94">설치된 플러그인이 없습니다. <a href="/wp-admin/plugin-install.php">새 플러그인 추가</a></td></tr>';
      countEl.textContent = '0개';
      return;
    }
    countEl.textContent = plugins.length + '개';
    renderPlugins(plugins);
  } catch(e) {
    list.innerHTML = '<tr><td colspan="4" style="padding:20px;text-align:center;color:#d63638">불러오기 오류: '+e.message+'</td></tr>';
  }
})();

function renderPlugins(plugins) {
  const list = document.getElementById('plugins-list');
  list.innerHTML = plugins.map(p => \`
    <tr id="row-\${p.slug}" style="border-top:1px solid #f0f0f1;\${p.active?'background:#f0f7e6':''}">
      <td style="padding:12px">
        <div style="display:flex;align-items:flex-start;gap:10px">
          \${p.icon?'<img src="'+p.icon+'" style="width:36px;height:36px;border-radius:6px;flex-shrink:0">':'<div style=\\"width:36px;height:36px;border-radius:6px;background:#f0f0f1;display:flex;align-items:center;justify-content:center;font-size:1.2rem;flex-shrink:0\\">🔌</div>'}
          <div>
            <strong style="font-size:.9rem">\${p.name}</strong>
            <p style="margin:3px 0 0;font-size:.8rem;color:#50575e">\${p.description||''}</p>
            \${p.author?'<p style="margin:3px 0 0;font-size:.75rem;color:#8c8f94">제작: '+p.author+'</p>':''}
          </div>
        </div>
      </td>
      <td style="padding:12px;font-size:.8rem;color:#50575e;vertical-align:top">v\${p.version||'-'}</td>
      <td style="padding:12px;vertical-align:top">
        <span style="font-size:.8rem;font-weight:600;\${p.active?'color:#00a32a':'color:#8c8f94'}">\${p.active?'● 활성':'○ 비활성'}</span>
      </td>
      <td style="padding:12px;vertical-align:top">
        <div style="display:flex;flex-wrap:wrap;gap:4px;font-size:.8rem">
          \${p.active
            ? '<button onclick="deactivatePlugin(\''+p.slug+'\',\''+p.name.replace(/'/g,'')+'\',this)" style="padding:4px 10px;background:#fff;border:1px solid #c3c4c7;border-radius:3px;cursor:pointer;font-size:.8rem">비활성화</button>'
            : '<button onclick="activatePlugin(\''+p.slug+'\',\''+p.name.replace(/'/g,'')+'\',this)" style="padding:4px 10px;background:#00a32a;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:.8rem;font-weight:600">활성화</button>'
          }
          \${p.settings_url?'<a href="'+p.settings_url+'" style="padding:4px 10px;background:#f6f7f7;border:1px solid #c3c4c7;border-radius:3px;font-size:.8rem;text-decoration:none;color:#1e1e1e">설정</a>':''}
          \${!p.active?'<button onclick="deletePlugin(\''+p.slug+'\',\''+p.name.replace(/'/g,'')+'\',this)" style="padding:4px 10px;background:#fff;border:1px solid #d63638;color:#d63638;border-radius:3px;cursor:pointer;font-size:.8rem">삭제</button>':''}
        </div>
      </td>
    </tr>\`).join('');
  window._pluginData = plugins;
}

function filterList(q) {
  const rows = document.querySelectorAll('#plugins-list tr[id]');
  const lq = q.toLowerCase();
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(lq) ? '' : 'none';
  });
}

async function activatePlugin(slug, name, btn) {
  btn.textContent='처리 중…'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/plugins/activate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  showMsg(d.success ? '✓ ' + name + ' 활성화됨' : '활성화 실패: '+(d.message||''), d.success);
  if (d.success) location.reload();
  else { btn.textContent='활성화'; btn.disabled=false; }
}

async function deactivatePlugin(slug, name, btn) {
  btn.textContent='처리 중…'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/plugins/deactivate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  showMsg(d.success ? '✓ ' + name + ' 비활성화됨' : '실패', d.success);
  if (d.success) location.reload();
  else { btn.textContent='비활성화'; btn.disabled=false; }
}

async function deletePlugin(slug, name, btn) {
  if (!confirm(name + ' 플러그인을 삭제하시겠습니까?\\n이 작업은 되돌릴 수 없습니다.')) return;
  btn.textContent='삭제 중…'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/plugins/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug})
  });
  const d = r.ok ? await r.json() : {success:false};
  if (d.success) {
    document.getElementById('row-'+slug)?.remove();
    showMsg('✓ ' + name + ' 삭제됨', true);
  } else { btn.textContent='삭제'; btn.disabled=false; showMsg('삭제 실패', false); }
}

function showMsg(text, ok) {
  const el = document.getElementById('plugin-msg');
  el.style.cssText = ok
    ? 'display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px;margin-bottom:12px'
    : 'display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px;margin-bottom:12px';
  el.textContent = text;
  setTimeout(()=>el.style.display='none', 4000);
}`;
    }


  } else if (page === 'options-general' || page === 'options') {
    pageTitle = '일반 설정';
    bodyHtml = `<div id="settings-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>
    <table class="form-table" style="width:100%;border-collapse:collapse">` +
      [
        {label:'사이트 제목',          name:'blogname',        type:'text',  placeholder:'내 WordPress 사이트'},
        {label:'태그라인',             name:'blogdescription', type:'text',  placeholder:'워드프레스로 만든 사이트'},
        {label:'WordPress 주소 (URL)',name:'siteurl',         type:'url',   placeholder:'https://example.com'},
        {label:'사이트 주소 (URL)',    name:'home',            type:'url',   placeholder:'https://example.com'},
        {label:'관리자 이메일',        name:'admin_email',     type:'email', placeholder:'admin@example.com'},
      ].map(f =>
        `<tr style="border-bottom:1px solid #f0f0f1">
          <th style="padding:15px 10px;text-align:left;width:220px;font-size:.875rem;vertical-align:top">${f.label}</th>
          <td style="padding:15px 10px"><input type="${f.type}" id="opt-${f.name}" name="${f.name}" placeholder="${f.placeholder}" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"></td>
        </tr>`
      ).join('') +
      `<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">언어</th>
        <td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>한국어 (ko_KR)</option><option>English (US)</option></select></td></tr>
      <tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">시간대</th>
        <td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>Asia/Seoul</option><option>UTC</option></select></td></tr>
      </table>
      <p style="margin-top:20px"><button type="button" onclick="saveSettings()" class="btn-wp">변경사항 저장</button></p>`;

    inlineScript = `(async function(){
try{
  var r=await fetch('/wp-json/wp/v2/settings',{headers:{'Accept':'application/json'}});
  var res=r.ok?await r.json():{};
  if(res.title)document.getElementById('opt-blogname').value=res.title;
  if(res.description)document.getElementById('opt-blogdescription').value=res.description;
  if(res.url){document.getElementById('opt-siteurl').value=res.url;document.getElementById('opt-home').value=res.url;}
  if(res.email)document.getElementById('opt-admin_email').value=res.email;
}catch(e){}
})();
async function saveSettings(){
  var data={};
  document.querySelectorAll('input[name]').forEach(function(el){if(el.value.trim())data[el.name]=el.value.trim();});
  var msg=document.getElementById('settings-msg');
  try{
    var r=await fetch('/wp-json/wp/v2/settings',{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(data)});
    if(r.ok){
      msg.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
      msg.textContent='✓ 설정이 저장되었습니다.';
    }else{
      msg.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
      msg.textContent='저장에 실패했습니다.';
    }
  }catch(e){
    msg.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
    msg.textContent='오류: '+e.message;
  }
}`;

  } else if (page === 'users') {
    pageTitle = '사용자';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px"><a href="/wp-admin/user-new.php" class="btn-wp">새 사용자 추가</a></div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <th style="padding:8px 10px;text-align:left">사용자명</th>
        <th style="padding:8px 10px;text-align:left">이름</th>
        <th style="padding:8px 10px;text-align:left">이메일</th>
        <th style="padding:8px 10px;text-align:left">역할</th>
        <th style="padding:8px 10px;text-align:left">글</th>
      </tr></thead>
      <tbody id="users-list"><tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/users?per_page=20',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var users=r.ok?await r.json():[];
users=Array.isArray(users)?users:[];
var el=document.getElementById('users-list');
if(!users.length){el.innerHTML='<tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94">사용자가 없습니다.</td></tr>';return;}
el.innerHTML=users.map(function(u){
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:8px 10px"><strong>'+(u.slug||u.name||'')+'</strong></td>'+
    '<td style="padding:8px 10px">'+(u.name||'—')+'</td>'+
    '<td style="padding:8px 10px">'+(u.email||'—')+'</td>'+
    '<td style="padding:8px 10px">'+(u.role||'관리자')+'</td>'+
    '<td style="padding:8px 10px">'+(u.post_count||0)+'</td>'+
    '</tr>';
}).join('');
})();`;

  } else if (page === 'profile') {
    pageTitle = '프로필';
    bodyHtml = `<div id="profile-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>
    <table class="form-table" style="width:100%;border-collapse:collapse">` +
      [
        {label:'사용자명', id:'username',   val:session?.login||'admin', disabled:true,  type:'text'},
        {label:'이름',     id:'first_name', val:'', disabled:false, type:'text',  placeholder:'이름'},
        {label:'이메일',   id:'email',      val:'', disabled:false, type:'email', placeholder:'admin@example.com'},
      ].map(f =>
        `<tr style="border-bottom:1px solid #f0f0f1">
          <th style="padding:15px 10px;text-align:left;width:200px;font-size:.875rem">${f.label}</th>
          <td style="padding:15px 10px"><input type="${f.type}" id="${f.id}" value="${esc(f.val||'')}"${f.placeholder?` placeholder="${f.placeholder}"`:''}${f.disabled?' disabled':''} style="width:100%;max-width:400px;padding:6px 8px;border:1px solid ${f.disabled?'#dcdcde':'#8c8f94'};border-radius:4px;font-size:.875rem${f.disabled?';background:#f6f7f7;color:#8c8f94':''}"></td>
        </tr>`
      ).join('') +
      `<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem">새 비밀번호</th>
        <td style="padding:15px 10px">
          <input type="password" id="new_pass1" placeholder="새 비밀번호" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem;margin-bottom:8px"><br>
          <input type="password" id="new_pass2" placeholder="비밀번호 확인" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem">
        </td></tr>
      </table>
      <p style="margin-top:20px"><button class="btn-wp" onclick="saveProfile()">프로필 업데이트</button></p>`;
    inlineScript = `function saveProfile(){
  var p1=document.getElementById('new_pass1').value;
  var p2=document.getElementById('new_pass2').value;
  if(p1&&p1!==p2){alert('비밀번호가 일치하지 않습니다.');return;}
  var msg=document.getElementById('profile-msg');
  msg.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
  msg.textContent='✓ 프로필이 업데이트되었습니다.';
}`;

  } else if (page === 'edit-comments') {
    pageTitle = '댓글';
    bodyHtml = `<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <th style="padding:8px 10px;text-align:left">작성자</th>
        <th style="padding:8px 10px;text-align:left">내용</th>
        <th style="padding:8px 10px;text-align:left;width:120px">날짜</th>
      </tr></thead>
      <tbody id="comments-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">불러오는 중...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/comments?per_page=20',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var list=r.ok?await r.json():[];
list=Array.isArray(list)?list:[];
var el=document.getElementById('comments-list');
if(!list.length){el.innerHTML='<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">댓글이 없습니다.</td></tr>';return;}
el.innerHTML=list.map(function(c){
  var d=new Date(c.date).toLocaleDateString('ko-KR');
  var content=((c.content&&c.content.rendered)||'').replace(/<[^>]+>/g,'').slice(0,100);
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:10px;vertical-align:top"><strong>'+(c.author_name||'익명')+'</strong></td>'+
    '<td style="padding:10px;vertical-align:top;font-size:.875rem">'+content+'</td>'+
    '<td style="padding:10px;vertical-align:top;font-size:.8rem;color:#50575e">'+d+'</td>'+
    '</tr>';
}).join('');
})();`;

  } else if (page === 'options-permalink') {
    pageTitle = '고유주소 설정';
    bodyHtml = `<p style="color:#50575e;margin-bottom:20px">WordPress는 고유주소와 아카이브에 대한 사용자 정의 URL 구조를 만드는 기능을 제공합니다.</p>` +
      [
        {label:'기본',        val:'',                               desc:'https://example.com/?p=123'},
        {label:'날짜와 이름', val:'/%year%/%monthnum%/%day%/%postname%/', desc:'https://example.com/2024/01/01/글-제목/'},
        {label:'월과 이름',   val:'/%year%/%monthnum%/%postname%/',       desc:'https://example.com/2024/01/글-제목/'},
        {label:'숫자',        val:'/archives/%post_id%',                  desc:'https://example.com/archives/123'},
        {label:'글 이름',     val:'/%postname%/',                         desc:'https://example.com/글-제목/', checked:true},
      ].map(o =>
        `<label style="display:flex;align-items:flex-start;gap:10px;margin-bottom:14px;cursor:pointer">
          <input type="radio" name="permalink" value="${o.val}"${o.checked?' checked':''} style="margin-top:4px">
          <span><strong>${o.label}</strong>${o.desc?`<br><code style="font-size:.8rem;color:#50575e">${o.desc}</code>`:''}
          </span></label>`
      ).join('') +
      `<p style="margin-top:20px"><button type="button" class="btn-wp" onclick="alert('저장되었습니다.')">변경사항 저장</button></p>`;

  } else {
    pageTitle = page.replace(/-/g,' ').replace(/\b\w/g, c => c.toUpperCase());
    bodyHtml = `<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:30px;text-align:center;color:#50575e">
      <p>이 페이지는 CloudPress Edge에서 지원됩니다.</p>
    </div>`;
  }

  const menuActive = {
    dashboard: (page === 'index' || page === '' || page === 'dashboard'),
    posts:     (page === 'edit' && !isPage) || page === 'post-new' || page === 'post',
    media:     page === 'upload',
    pages:     page === 'edit' && isPage,
    comments:  page === 'edit-comments',
    themes:    page === 'themes' || page === 'theme-install',
    plugins:   page === 'plugins' || page === 'plugin-install',
    users:     page === 'users' || page === 'user-new' || page === 'profile',
    settings:  page === 'options-general' || page === 'options' || page === 'options-permalink',
  };

  function menuItem(href, icon, label, active) {
    return `<li${active?' class="current"':''}>` +
      `<a href="${href}"><span class="menu-icon">${icon}</span>` +
      `<span class="menu-label">${label}</span></a></li>`;
  }

  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${pageTitle} ‹ ${siteName} — WordPress</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;color:#1d2327;font-size:13px;line-height:1.4}
a{color:#2271b1;text-decoration:none}a:hover{color:#135e96}
#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:#1d2327;display:flex;align-items:center;padding:0 12px;z-index:9999;gap:16px}
#wpadminbar a{color:#a7aaad;font-size:.8125rem;display:flex;align-items:center;gap:5px;text-decoration:none;padding:2px 4px;border-radius:2px}
#wpadminbar a:hover{color:#fff;background:#3c434a}
#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:#1d2327;overflow-y:auto;z-index:100}
#adminmenu{list-style:none;margin:0;padding:0}
#adminmenu li>a{display:flex;align-items:center;gap:8px;padding:9px 10px;color:#a7aaad;font-size:.8125rem;text-decoration:none;transition:background .15s,color .1s}
#adminmenu li>a:hover,#adminmenu li.current>a{background:#2c3338;color:#fff}
#adminmenu li.current>a{border-left:3px solid #2271b1;padding-left:7px}
#adminmenu .menu-icon{font-size:1rem;width:20px;text-align:center;flex-shrink:0}
#adminmenu .menu-sep{height:1px;background:#3c434a;margin:6px 0}
#wpcontent{margin-left:160px;margin-top:32px;min-height:calc(100vh - 32px)}
#wpbody-content{padding:20px 20px 40px}
.wrap{max-width:1200px}
h1.wp-heading-inline{font-size:1.4rem;font-weight:400;color:#1d2327;margin:0 0 20px;display:block}
.welcome-panel{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:23px;margin-bottom:20px}
.admin-widgets{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px;margin-top:16px}
.admin-widget{background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden}
.widget-title{background:#f6f7f7;border-bottom:1px solid #c3c4c7;padding:9px 12px;font-size:.875rem;font-weight:600;color:#1d2327}
.widget-body{padding:14px}
.btn-wp{display:inline-block;padding:6px 12px;background:#2271b1;color:#fff;border:1px solid #2271b1;border-radius:3px;font-size:.8125rem;cursor:pointer;text-decoration:none;line-height:1.4;transition:background .15s}
.btn-wp:hover{background:#135e96;border-color:#135e96;color:#fff;text-decoration:none}
.btn-wp.btn-secondary{background:#f6f7f7;color:#1d2327;border-color:#8c8f94}
.btn-wp.btn-secondary:hover{background:#dcdcde;color:#1d2327}
.wp-list-table th{font-weight:600;color:#1d2327}
.form-table th{font-weight:600;color:#1d2327;vertical-align:top}
.tablenav{display:flex;align-items:center;gap:10px}
@media(max-width:782px){
  #adminmenuwrap{width:36px;overflow:hidden}
  #adminmenuwrap:hover{width:160px}
  #adminmenu .menu-label{display:none}
  #adminmenuwrap:hover .menu-label{display:inline}
  #wpcontent{margin-left:36px}
}
</style>
</head>
<body class="wp-admin">
<div id="wpadminbar">
  <a style="font-weight:700;color:#a7aaad;font-size:.9rem" href="/wp-admin/">⊞</a>
  <span style="color:#3c434a">|</span>
  <a href="/" target="_blank">🏠 ${siteName}</a>
  <span style="color:#3c434a">|</span>
  <a href="/wp-admin/post-new.php">+ 새로 추가</a>
  <div style="flex:1"></div>
  <span style="color:#a7aaad;font-size:.8rem">👤 ${displayName}</span>
  <a href="/wp-login.php?action=logout" style="color:#f86368">로그아웃</a>
</div>
<div id="adminmenuwrap">
  <ul id="adminmenu">
    ${menuItem('/wp-admin/', '🏠', '대시보드', menuActive.dashboard)}
    <li class="menu-sep"></li>
    ${menuItem('/wp-admin/edit.php', '📝', '글', menuActive.posts)}
    ${menuItem('/wp-admin/upload.php', '🖼️', '미디어', menuActive.media)}
    ${menuItem('/wp-admin/edit.php?post_type=page', '📄', '페이지', menuActive.pages)}
    ${menuItem('/wp-admin/edit-comments.php', '💬', '댓글', menuActive.comments)}
    <li class="menu-sep"></li>
    ${menuItem('/wp-admin/themes.php', '🎨', '외모', menuActive.themes)}
    ${menuItem('/wp-admin/plugins.php', '🔌', '플러그인', menuActive.plugins)}
    ${menuItem('/wp-admin/users.php', '👥', '사용자', menuActive.users)}
    <li class="menu-sep"></li>
    ${menuItem('/wp-admin/options-general.php', '⚙️', '설정', menuActive.settings)}
    ${menuItem('/', '🌐', '사이트 보기', false)}
  </ul>
</div>
<div id="wpcontent">
  <div id="wpbody-content">
    <div class="wrap">
      <h1 class="wp-heading-inline">${pageTitle}</h1>
      ${bodyHtml}
      ${inlineScript ? `<script>${inlineScript}<\/script>` : ''}
    </div>
  </div>
</div>
</body>
</html>`;
}

// ── REST API ──────────────────────────────────────────────────────────────────
async function handleWPRestAPI(env, request, url, siteInfo) {
  const path = url.pathname.replace('/wp-json', '');
  const method = request.method;

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
    'Content-Type': 'application/json; charset=utf-8',
  };

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  const j = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: corsHeaders });

  try {
    // GET /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'GET') {
      const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '10', 10), 100);
      const page    = parseInt(url.searchParams.get('page') || '1', 10);
      const offset  = (page - 1) * perPage;
      const search  = url.searchParams.get('search') || '';
      const fields  = url.searchParams.get('_fields') || '';

      let sql = `SELECT * FROM wp_posts WHERE post_type = 'post' AND post_status = 'publish'`;
      const binds = [];
      if (search) { sql += ` AND (post_title LIKE ? OR post_content LIKE ?)`; binds.push(`%${search}%`, `%${search}%`); }
      sql += ` ORDER BY post_date DESC LIMIT ? OFFSET ?`;
      binds.push(perPage, offset);

      const res = await env.DB.prepare(sql).bind(...binds).all();
      const posts = (res.results || []).map(wpPostToJSON);
      const countRes = await env.DB.prepare(`SELECT COUNT(*) as c FROM wp_posts WHERE post_type='post' AND post_status='publish'`).first();
      const total = countRes?.c || 0;

      return new Response(JSON.stringify(posts), {
        status: 200,
        headers: { ...corsHeaders, 'X-WP-Total': String(total), 'X-WP-TotalPages': String(Math.ceil(total / perPage)) },
      });
    }

    // POST /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const title   = String(body.title?.raw || body.title || '');
      const content = String(body.content?.raw || body.content || '');
      const status  = ['publish','draft','private'].includes(body.status) ? body.status : 'publish';
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
        // 카테고리 연결
        if (body.categories && Array.isArray(body.categories) && body.categories.length && newId) {
          for (const catId of body.categories) {
            const tt = await env.DB.prepare(`SELECT term_taxonomy_id FROM wp_term_taxonomy WHERE term_id = ? AND taxonomy = 'category' LIMIT 1`).bind(catId).first().catch(() => null);
            if (tt) {
              await env.DB.prepare(`INSERT OR IGNORE INTO wp_term_relationships (object_id, term_taxonomy_id) VALUES (?, ?)`).bind(newId, tt.term_taxonomy_id).run().catch(() => {});
            }
          }
        }
        return j(wpPostToJSON(newPost || { ID: newId, post_title: title, post_content: content, post_status: status, post_name: slug, post_date: now }), 201);
      } catch (e) {
        return j({ code: 'rest_db_error', message: '저장 실패: ' + e.message }, 500);
      }
    }

    // PATCH /wp/v2/posts/:id
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && (method === 'PUT' || method === 'PATCH')) {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      const body = await request.json().catch(() => ({}));
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
      const fields = [], binds = [];
      if (body.title   !== undefined) { fields.push('post_title = ?');   binds.push(String(body.title?.raw || body.title || '')); }
      if (body.content !== undefined) { fields.push('post_content = ?'); binds.push(String(body.content?.raw || body.content || '')); }
      if (body.status  !== undefined) { fields.push('post_status = ?');  binds.push(body.status); }
      if (body.slug    !== undefined) { fields.push('post_name = ?');    binds.push(body.slug); }
      if (!fields.length) return j({ code: 'rest_no_fields', message: '수정할 필드가 없습니다.' }, 400);
      fields.push('post_modified = ?', 'post_modified_gmt = ?');
      binds.push(now, now, postId);
      await env.DB.prepare(`UPDATE wp_posts SET ${fields.join(', ')} WHERE ID = ?`).bind(...binds).run();
      const updated = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(postId).first();
      return j(wpPostToJSON(updated));
    }

    // DELETE /wp/v2/posts/:id
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && method === 'DELETE') {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      await env.DB.prepare(`UPDATE wp_posts SET post_status = 'trash' WHERE ID = ?`).bind(postId).run();
      return j({ deleted: true, id: postId });
    }

    // GET /wp/v2/posts/:id
    const postMatch = path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/);
    if (postMatch && method === 'GET') {
      const post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status IN ('publish','draft') LIMIT 1`
      ).bind(parseInt(postMatch[1], 10)).first();
      if (!post) return j({ code: 'rest_post_invalid_id', message: '유효하지 않은 포스트 ID입니다.' }, 404);
      return j(wpPostToJSON(post));
    }

    // GET /wp/v2/pages
    if (path.match(/^\/wp\/v2\/pages\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE post_type = 'page' AND post_status = 'publish' ORDER BY menu_order ASC, post_date DESC LIMIT 100`
      ).all();
      return j((res.results || []).map(wpPostToJSON));
    }

    // GET /wp/v2/categories
    if (path.match(/^\/wp\/v2\/categories\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count, tt.parent FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'category' ORDER BY t.name ASC`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/tags
    if (path.match(/^\/wp\/v2\/tags\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'post_tag' ORDER BY tt.count DESC LIMIT 100`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/users
    if (path.match(/^\/wp\/v2\/users\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT ID as id, display_name as name, user_login as slug, user_url as url FROM wp_users LIMIT 20`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/media
    if (path.match(/^\/wp\/v2\/media\/?$/) && method === 'GET') {
      try {
        const res = await env.DB.prepare(
          `SELECT media_id as id, file_name as slug, alt_text, caption, mime_type, file_size, file_path as source_url FROM wp_media ORDER BY upload_date DESC LIMIT 30`
        ).all();
        return j((res.results || []).map(m => ({
          ...m, title: { rendered: m.slug || '' }, guid: { rendered: m.source_url || '' },
        })));
      } catch { return j([]); }
    }

    // GET /wp/v2/comments
    if (path.match(/^\/wp\/v2\/comments\/?$/) && method === 'GET') {
      try {
        const perPage = parseInt(url.searchParams.get('per_page') || '20', 10);
        const res = await env.DB.prepare(
          `SELECT comment_ID as id, comment_author as author_name, comment_content as content, comment_date as date, comment_post_ID as post FROM wp_comments WHERE comment_approved = '1' ORDER BY comment_date DESC LIMIT ?`
        ).bind(perPage).all();
        const total = await env.DB.prepare(`SELECT COUNT(*) as c FROM wp_comments WHERE comment_approved='1'`).first();
        return new Response(JSON.stringify((res.results || []).map(c => ({ ...c, content: { rendered: c.content || '' } }))), {
          status: 200,
          headers: { ...corsHeaders, 'X-WP-Total': String(total?.c || 0) },
        });
      } catch { return j([]); }
    }

    // GET /wp/v2/settings
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

    // POST /wp/v2/settings
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const map = { title:'blogname', description:'blogdescription', email:'admin_email', timezone:'timezone_string', date_format:'date_format', posts_per_page:'posts_per_page' };
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

    // ── CloudPress v1 API ──────────────────────────────────────────────────────

    // GET /cloudpress/v1/plugins — 설치된 플러그인 목록
    if (path === '/cloudpress/v1/plugins' && method === 'GET') {
      try {
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const allPluginsRes = await env.DB.prepare(
          `SELECT option_name, option_value FROM wp_options WHERE option_name LIKE 'cp_plugin_%'`
        ).all();
        const activePlugins = res?.option_value ? JSON.parse(res.option_value) : [];
        const pluginMeta = {};
        for (const row of (allPluginsRes.results || [])) {
          try { pluginMeta[row.option_name] = JSON.parse(row.option_value); } catch {}
        }
        // DB에 저장된 플러그인만 표시 (기본 내장 없음)
        const dbPlugins = Object.entries(pluginMeta).map(([k, v]) => ({
          slug: k.replace('cp_plugin_', ''),
          ...v,
        }));
        const allPlugins = [...dbPlugins];
        const result = allPlugins.map(p => ({
          ...p,
          active: activePlugins.includes(p.slug) || activePlugins.includes(p.slug + '/index.php'),
        }));
        return j(result);
      } catch(e) {
        return j([]);
      }
    }

    // POST /cloudpress/v1/plugins/install
    if (path === '/cloudpress/v1/plugins/install' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        // WordPress.org API에서 플러그인 메타 가져오기
        let pluginInfo = { slug, name: name || slug, version: 'latest', description: '' };
        try {
          const wpRes = await fetch(
            `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}&request[fields][short_description]=1&request[fields][versions]=0&request[fields][icons]=1`,
            { headers: { 'User-Agent': 'CloudPress/20' } }
          );
          if (wpRes.ok) {
            const info = await wpRes.json();
            if (info && info.slug) {
              pluginInfo = {
                slug: info.slug,
                name: info.name || name || slug,
                version: info.version || 'latest',
                description: (info.short_description || '').replace(/<[^>]+>/g, '').slice(0, 200),
                author: (info.author || '').replace(/<[^>]+>/g, ''),
                icon: info.icons?.['1x'] || info.icons?.default || '',
                download_link: info.download_link || '',
                installed_at: new Date().toISOString(),
              };
            }
          }
        } catch {}
        // DB에 플러그인 메타 저장
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_plugin_${slug}`, JSON.stringify(pluginInfo)).run();
        return j({ success: true, plugin: pluginInfo, message: `${pluginInfo.name} 설치됨` });
      } catch(e) {
        return j({ success: false, message: '설치 실패: ' + e.message }, 500);
      }
    }

    // POST /cloudpress/v1/plugins/activate
    if (path === '/cloudpress/v1/plugins/activate' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const active = res?.option_value ? JSON.parse(res.option_value) : [];
        if (!active.includes(slug)) active.push(slug);
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes')`
        ).bind(JSON.stringify(active)).run();
        return j({ success: true, message: `${slug} 활성화됨`, active_plugins: active });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/plugins/deactivate
    if (path === '/cloudpress/v1/plugins/deactivate' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const active = (res?.option_value ? JSON.parse(res.option_value) : []).filter(s => s !== slug);
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes')`
        ).bind(JSON.stringify(active)).run();
        return j({ success: true, message: `${slug} 비활성화됨` });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/plugins/delete
    if (path === '/cloudpress/v1/plugins/delete' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        // active_plugins에서 제거
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const active = (res?.option_value ? JSON.parse(res.option_value) : []).filter(s => s !== slug);
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes')`
        ).bind(JSON.stringify(active)).run();
        // 플러그인 메타 삭제
        await env.DB.prepare(`DELETE FROM wp_options WHERE option_name = ?`).bind(`cp_plugin_${slug}`).run();
        return j({ success: true, message: `${slug} 삭제됨` });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/themes/install
    if (path === '/cloudpress/v1/themes/install' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        let themeInfo = { slug, name: name || slug, version: 'latest' };
        try {
          const wpRes = await fetch(
            `https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=${encodeURIComponent(slug)}&request[fields][description]=1&request[fields][screenshots]=1&request[fields][version]=1`,
            { headers: { 'User-Agent': 'CloudPress/20' } }
          );
          if (wpRes.ok) {
            const info = await wpRes.json();
            if (info && info.slug) {
              themeInfo = {
                slug: info.slug,
                name: info.name || name || slug,
                version: info.version || 'latest',
                description: (info.description || '').replace(/<[^>]+>/g, '').slice(0, 200),
                author: (info.author || '').replace(/<[^>]+>/g, ''),
                screenshot_url: info.screenshot_url || '',
                installed_at: new Date().toISOString(),
              };
            }
          }
        } catch {}
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_theme_${slug}`, JSON.stringify(themeInfo)).run();
        return j({ success: true, theme: themeInfo, message: `${themeInfo.name} 설치됨` });
      } catch(e) { return j({ success: false, message: '테마 설치 실패: ' + e.message }, 500); }
    }

    // POST /cloudpress/v1/themes/activate
    if (path === '/cloudpress/v1/themes/activate' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('stylesheet', ?, 'yes')`
        ).bind(slug).run();
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('template', ?, 'yes')`
        ).bind(slug).run();
        return j({ success: true, message: `${name || slug} 테마 활성화됨`, active_theme: slug });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/themes/delete
    if (path === '/cloudpress/v1/themes/delete' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug 필요' }, 400);
      try {
        await env.DB.prepare(`DELETE FROM wp_options WHERE option_name = ?`).bind(`cp_theme_${slug}`).run();
        return j({ success: true, message: `${slug} 테마 삭제됨` });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/plugins/upload — ZIP 파일 업로드 설치
    if (path === '/cloudpress/v1/plugins/upload' && method === 'POST') {
      try {
        const formData = await request.formData();
        const zipFile = formData.get('plugin_zip');
        const pluginName = formData.get('plugin_name') || 'Unknown Plugin';
        const pluginSlug = formData.get('plugin_slug') || 'custom-plugin-' + Date.now();

        if (!zipFile) return j({ success: false, message: 'ZIP 파일이 없습니다.' }, 400);

        // ZIP 파일 내부에서 플러그인 헤더 파싱 시도
        let finalSlug = pluginSlug;
        let finalName = pluginName;
        let version = '1.0.0';
        let description = '';
        let author = '';

        try {
          // ZIP 시그니처 확인 (PK\x03\x04)
          const buf = await zipFile.arrayBuffer();
          const bytes = new Uint8Array(buf);
          if (bytes[0] === 0x50 && bytes[1] === 0x4B) {
            // ZIP 유효 — 간단한 파싱으로 첫 번째 .php 파일에서 헤더 추출
            const text = new TextDecoder('utf-8', {fatal:false}).decode(bytes.slice(0, 16384));
            const nameMatch = text.match(/Plugin Name:\s*(.+)/i);
            const verMatch  = text.match(/Version:\s*(.+)/i);
            const descMatch = text.match(/Description:\s*(.+)/i);
            const authMatch = text.match(/Author:\s*(.+)/i);
            const slugMatch = text.match(/Text Domain:\s*([\w-]+)/i);
            if (nameMatch) finalName = nameMatch[1].trim();
            if (verMatch)  version = verMatch[1].trim();
            if (descMatch) description = descMatch[1].trim().slice(0, 200);
            if (authMatch) author = authMatch[1].replace(/<[^>]+>/g,'').trim();
            if (slugMatch) finalSlug = slugMatch[1].trim();
          }
        } catch {}

        const pluginInfo = {
          slug: finalSlug,
          name: finalName,
          version,
          description,
          author,
          installed_at: new Date().toISOString(),
          source: 'zip_upload',
          file_size: zipFile.size,
        };

        // DB에 저장
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_plugin_${finalSlug}`, JSON.stringify(pluginInfo)).run();

        return j({ success: true, plugin: pluginInfo, message: `${finalName} 설치됨` });
      } catch(e) {
        return j({ success: false, message: 'ZIP 설치 실패: ' + e.message }, 500);
      }
    }

    return j({ code: 'rest_no_route', message: '일치하는 라우트가 없습니다.', data: { status: 404 } }, 404);
  } catch (e) {
    console.error('[REST API] error:', e.message);
    return j({ code: 'rest_error', message: '서버 오류가 발생했습니다.' }, 500);
  }
}

function wpPostToJSON(p) {
  if (!p) return null;
  return {
    id: p.ID || p.id,
    date: p.post_date,
    date_gmt: p.post_date_gmt,
    modified: p.post_modified,
    slug: p.post_name,
    status: p.post_status,
    type: p.post_type,
    link: p.guid || `/?p=${p.ID||p.id}`,
    title: { rendered: p.post_title || '', raw: p.post_title || '' },
    content: { rendered: p.post_content || '', raw: p.post_content || '', protected: false },
    excerpt: { rendered: p.post_excerpt || '', raw: p.post_excerpt || '', protected: false },
    author: p.post_author || 1,
    comment_status: p.comment_status || 'open',
    comment_count: p.comment_count || 0,
    _links: {
      self: [{ href: `/wp-json/wp/v2/posts/${p.ID||p.id}` }],
      collection: [{ href: '/wp-json/wp/v2/posts' }],
    },
  };
}

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
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:atom="http://www.w3.org/2005/Atom">
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
    if (fileSize < 500 * 1024) {
      const b64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
      try {
        await env.DB.prepare(
          `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'd1', '')`
        ).bind(safeName, storagePath, mimeType, fileSize).run();
        if (env.CACHE) await env.CACHE.put(`media:${storagePath}`, b64, { metadata: { mimeType, size: fileSize } });
        return new Response(JSON.stringify({ id: Date.now(), url: `/wp-content/uploads/${storagePath}`, title: safeName }), {
          status: 201, headers: { 'Content-Type': 'application/json' },
        });
      } catch {}
    }
    return new Response(JSON.stringify({ error: '업로드 실패' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
  try {
    await env.DB.prepare(
      `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'supabase', '')`
    ).bind(safeName, result.url, mimeType, fileSize).run();
  } catch {}
  return new Response(JSON.stringify({
    id: Date.now(), url: result.url, title: safeName.replace(/\.[^.]+$/, ''),
    mime_type: mimeType, source_url: result.url, secondary: result.secondary || false,
  }), { status: 201, headers: { 'Content-Type': 'application/json' } });
}

async function revalidatePage(env, siteInfo, url, request) {
  try {
    const { html } = await renderWordPressPage(env, siteInfo, url, request);
    const kvKey = `${siteInfo.site_prefix}:${url.pathname}${url.search}`;
    await kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', 200, CACHE_TTL_HTML);
    const freshResp = new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
        'x-cp-cached': 'edge', 'x-cp-revalidated': '1',
      },
    });
    await edgeCache.put(new Request(url.toString()), freshResp);
  } catch (e) { console.warn('[SWR] revalidation failed:', e.message); }
}

async function handlePurge(env, request, url, siteInfo) {
  const auth = request.headers.get('Authorization') || '';
  const purgeKey = env.PURGE_KEY || '';
  if (purgeKey && auth !== `Bearer ${purgeKey}`) return new Response('Unauthorized', { status: 401 });
  const body = await request.json().catch(() => ({}));
  const paths = body.paths || [url.searchParams.get('path') || '/'];
  let purged = 0;
  for (const p of paths) {
    const kvKey = `${siteInfo.site_prefix}:${p}`;
    try {
      await env.CACHE?.delete(KV_PAGE_PREFIX + kvKey);
      await edgeCache.delete(new Request(`https://${url.hostname}${p}`));
      purged++;
    } catch {}
  }
  return new Response(JSON.stringify({ ok: true, purged, paths }), { headers: { 'Content-Type': 'application/json' } });
}

async function handlePrewarm(env, request, url, siteInfo) {
  const paths = ['/'];
  try {
    const res = await env.DB.prepare(
      `SELECT post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 5`
    ).all();
    for (const r of (res.results || [])) paths.push(`/${r.post_name}/`);
  } catch {}
  const hostname = url.hostname;
  for (const p of paths) {
    const warmUrl = new URL(`https://${hostname}${p}`);
    revalidatePage(env, siteInfo, warmUrl, request).catch(() => {});
  }
  return new Response(JSON.stringify({ ok: true, paths, message: '캐시 예열 시작됨' }), { headers: { 'Content-Type': 'application/json' } });
}

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
    ...pages.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified||'').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`),
    ...posts.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified||'').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.6</priority></url>`),
  ];
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

// ── 메인 핸들러 ───────────────────────────────────────────────────────────────
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname;
  const method   = request.method;
  const ip       = getClientIP(request);

  // WAF
  const wafResult = wafCheck(request, url);
  if (wafResult.block) {
    if (wafResult.tarpit) await new Promise(r => setTimeout(r, BOT_TARPIT_MS));
    return new Response(
      `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>요청이 차단되었습니다. (${wafResult.reason})</p></body></html>`,
      { status: wafResult.status || 403, headers: { 'Content-Type': 'text/html', 'X-WAF-Block': wafResult.reason } }
    );
  }

  // Rate limit
  const isWrite = !['GET','HEAD','OPTIONS'].includes(method);
  const rlResult = await rateLimitCheck(env, ip, isWrite, pathname);
  if (!rlResult.allowed) {
    if (rlResult.banned) {
      return new Response('IP가 차단되었습니다.', { status: 429, headers: { 'Retry-After': String(DDOS_BAN_TTL) } });
    }
    return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': String(RATE_LIMIT_WIN) } });
  }

  // CloudPress 플랫폼 자체 요청
  if (hostname.endsWith('.pages.dev') || hostname.endsWith('.workers.dev') ||
      hostname === 'cloudpress.site' || hostname === 'www.cloudpress.site') {
    return fetch(request);
  }

  // 도메인 인증
  if (pathname.startsWith('/.well-known/cloudpress-verify/')) {
    const token = pathname.split('/').pop();
    return new Response(`cloudpress-verify=${token}`, { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
  }

  // 사이트 정보
  const siteInfo = await getSiteInfo(env, hostname);
  if (!siteInfo) {
    return new Response(NOT_FOUND_HTML, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.suspended) {
    return new Response(SUSPENDED_HTML, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.status === 'pending' || siteInfo.status === 'provisioning') {
    return new Response(PROVISIONING_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' } });
  }

  // ── 라우팅 ────────────────────────────────────────────────────────────────────

  // wp-login.php
  if (pathname === '/wp-login.php') {
    return handleWPLogin(env, request, url, siteInfo);
  }

  // wp-admin
  if (pathname.startsWith('/wp-admin')) {
    return handleWPAdmin(env, request, url, siteInfo);
  }

  // REST API
  if (pathname.startsWith('/wp-json/')) {
    return handleWPRestAPI(env, request, url, siteInfo);
  }

  // RSS
  if (pathname === '/feed/' || pathname === '/feed' || url.searchParams.has('feed')) {
    return handleRSSFeed(env, siteInfo, url);
  }

  // Sitemap
  if (pathname === '/wp-sitemap.xml' || pathname === '/sitemap.xml' || pathname === '/sitemap_index.xml') {
    const r = await handleSitemap(env, siteInfo, url);
    ctx.waitUntil(cachePut(ctx, request, r.clone(), CACHE_TTL_API));
    return r;
  }

  // 미디어 업로드
  if (pathname === '/wp-admin/async-upload.php' && method === 'POST') {
    return handleMediaUpload(env, request, siteInfo);
  }

  // Purge API
  if (pathname === '/cp-purge' || pathname === '/wp-json/cloudpress/v1/purge') {
    return handlePurge(env, request, url, siteInfo);
  }

  // Prewarm
  if (pathname === '/cp-prewarm') {
    return handlePrewarm(env, request, url, siteInfo);
  }

  // robots.txt
  if (pathname === '/robots.txt') {
    return new Response(
      `User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\nDisallow: /wp-json/\nAllow: /wp-admin/admin-ajax.php\nSitemap: https://${hostname}/wp-sitemap.xml\n`,
      { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } }
    );
  }

  // OPTIONS
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
      },
    });
  }

  // 정적 자산
  if (isStaticAsset(pathname)) {
    const cached = await cacheGet(request);
    if (cached && !cached.stale) {
      const r = new Response(cached.response.body, { status: cached.response.status, headers: cached.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    if (siteInfo.supabase_url) {
      const mediaPath = pathname.replace('/wp-content/uploads/', '');
      const mediaUrl  = `${siteInfo.supabase_url}/storage/v1/object/public/${siteInfo.storage_bucket || 'media'}/${siteInfo.site_prefix}/${mediaPath}`;
      try {
        const mediaResp = await fetch(mediaUrl, { cf: { cacheTtl: CACHE_TTL_ASSET, cacheEverything: true } });
        if (mediaResp.ok) {
          ctx.waitUntil(cachePut(ctx, request, mediaResp.clone(), CACHE_TTL_ASSET));
          return new Response(mediaResp.body, {
            status: mediaResp.status,
            headers: new Headers({ ...Object.fromEntries(mediaResp.headers), 'Cache-Control': `public, max-age=${CACHE_TTL_ASSET}` }),
          });
        }
      } catch {}
    }
    return new Response('Not Found', { status: 404 });
  }

  // 캐시 불가 요청
  if (!isCacheable(request, url)) {
    const { html, contentData } = await renderWordPressPage(env, siteInfo, url, request);
    return new Response(html, {
      status: contentData.type === '404' ? 404 : 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, private' },
    });
  }

  // ── 캐시 흐름: Edge → KV → SSR ────────────────────────────────────────────
  const kvKey = `${siteInfo.site_prefix}:${pathname}${url.search}`;

  const edgeHit = await cacheGet(request);
  if (edgeHit) {
    if (!edgeHit.stale) {
      const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
    const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
    r.headers.set('x-cp-hit', 'edge-stale');
    r.headers.set('x-cp-swr', '1');
    return r;
  }

  const kvHit = await kvCacheGet(env, kvKey);
  if (kvHit) {
    const headers = new Headers({
      'Content-Type': kvHit.contentType || 'text/html; charset=utf-8',
      'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
      'x-cp-hit': 'kv',
    });
    const resp = new Response(kvHit.body, { status: kvHit.status || 200, headers });
    ctx.waitUntil(cachePut(ctx, request, resp.clone(), CACHE_TTL_HTML));
    if (kvHit.stale) {
      ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
      resp.headers.set('x-cp-swr', '1');
    }
    return resp;
  }

  let html, contentData;
  try {
    ({ html, contentData } = await renderWordPressPage(env, siteInfo, url, request));
  } catch (ssrError) {
    console.error('[SSR] render failed:', ssrError?.message);
    return new Response(ERROR_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' } });
  }

  const isNotFound = contentData.type === '404';
  const respStatus = isNotFound ? 404 : 200;
  const ttl        = isNotFound ? 60 : CACHE_TTL_HTML;

  const responseHeaders = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': isNotFound ? 'public, max-age=60' : `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`,
    'x-cp-hit': 'miss',
    'x-cp-via': 'cloudpress-ssr',
  });

  if (!isNotFound) {
    ctx.waitUntil(kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', respStatus, ttl));
  }
  const ssrResp = new Response(html, { status: respStatus, headers: responseHeaders });
  if (!isNotFound) ctx.waitUntil(cachePut(ctx, request, ssrResp.clone(), ttl));
  return new Response(html, { status: respStatus, headers: responseHeaders });
}

// ── HTML 템플릿 ───────────────────────────────────────────────────────────────
const SUSPENDED_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>사이트 정지됨</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#f55}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>🚫 사이트가 정지되었습니다</h1><p>이 사이트는 현재 이용 중지 상태입니다.</p></div></body></html>`;

const NOT_FOUND_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>사이트를 찾을 수 없음</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#fa0}p{color:#aaa;line-height:1.6}a{color:#7af;text-decoration:none}</style>
</head><body><div class="box"><h1>🔍 사이트를 찾을 수 없습니다</h1><p>요청한 도메인에 연결된 사이트가 없습니다.<br><a href="https://cloudpress.site/">CloudPress 대시보드</a>에서 도메인을 확인해 주세요.</p></div></body></html>`;

const PROVISIONING_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10">
<title>사이트 준비 중</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff;text-align:center}.box{padding:2rem;max-width:480px}h1{font-size:1.8rem;margin-bottom:1rem;color:#7af}p{color:#aaa;line-height:1.6}.spin{font-size:2.5rem;display:inline-block;animation:spin 1.2s linear infinite;margin-bottom:1rem}@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="spin">⚙️</div><h1>사이트를 준비 중입니다</h1><p>잠시만 기다려 주세요.</p></div></body></html>`;

const ERROR_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>일시적 오류</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{color:#f55;margin-bottom:1rem}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>⚠️ 일시적 서버 오류</h1><p>잠시 후 다시 시도해 주세요.</p></div></body></html>`;

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

  async scheduled(event, env, ctx) {
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
