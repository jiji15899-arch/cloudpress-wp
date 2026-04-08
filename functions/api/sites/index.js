// functions/api/sites/index.js — CloudPress WordPress Hosting v3.0
// Cloudflare CMS 완전 제거 → 무료 WordPress 호스팅 자동화 (Puppeteer)

/* ── 공통 유틸 ── */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok = (d = {}) => _j({ ok: true, ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);
const handleOptions = () => new Response(null, { status: 204, headers: CORS });

function getToken(req) {
  const a = req.headers.get('Authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7);
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/cp_session=([^;]+)/);
  return m ? m[1] : null;
}

async function getUser(env, req) {
  try {
    const t = getToken(req);
    if (!t) return null;
    const uid = await env.SESSIONS.get(`session:${t}`);
    if (!uid) return null;
    return await env.DB.prepare(
      'SELECT id,name,email,role,plan,plan_expires_at FROM users WHERE id=?'
    ).bind(uid).first();
  } catch { return null; }
}

function genId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 9); }
function genPw(n = 16) {
  const c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%';
  let s = '';
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  for (const b of a) s += c[b % c.length];
  return s;
}

/* ── 호스팅 제공업체 목록 ── */
const HOSTING_PROVIDERS = [
  {
    id: 'infinityfree',
    name: 'InfinityFree',
    domain: 'infinityfree.net',
    signupUrl: 'https://app.infinityfree.net/register',
    softaculousPath: '/softaculous',
    sslAuto: true,
    plan: 'free',
  },
  {
    id: 'byethost',
    name: 'ByetHost',
    domain: 'byethost.com',
    signupUrl: 'https://byet.host/register',
    softaculousPath: '/softaculous',
    sslAuto: true,
    plan: 'free',
  },
  {
    id: 'hyperphp',
    name: 'HyperPHP',
    domain: 'hyperphp.com',
    signupUrl: 'https://www.hyperphp.com/free-hosting.php',
    softaculousPath: '/softaculous',
    sslAuto: false,
    plan: 'free',
  },
  {
    id: 'freehosting',
    name: 'FreeHosting',
    domain: 'freehosting.com',
    signupUrl: 'https://www.freehosting.com/free-hosting.html',
    softaculousPath: '/softaculous',
    sslAuto: true,
    plan: 'free',
  },
  {
    id: 'profreehost',
    name: 'ProFreeHost',
    domain: 'profreehost.com',
    signupUrl: 'https://profreehost.com/register/',
    softaculousPath: '/softaculous',
    sslAuto: false,
    plan: 'free',
  },
  {
    id: 'aeonfree',
    name: 'AeonFree',
    domain: 'aeonscope.net',
    signupUrl: 'https://www.aeonscope.net/free-web-hosting/',
    softaculousPath: '/softaculous',
    sslAuto: true,
    plan: 'free',
  },
];

/* ── 임의 호스팅 제공업체 선택 ── */
function pickRandomProvider() {
  const idx = Math.floor(Math.random() * HOSTING_PROVIDERS.length);
  return HOSTING_PROVIDERS[idx];
}

/* ── 사이트 한도 확인 ── */
async function getSiteLimit(env, plan) {
  try {
    const row = await env.DB.prepare(
      'SELECT value FROM settings WHERE key=?'
    ).bind(`plan_${plan}_sites`).first();
    if (row) {
      const v = parseInt(row.value);
      return v === -1 ? Infinity : v;
    }
  } catch (_) {}
  const def = { free: 1, starter: 3, pro: 10, enterprise: Infinity };
  return def[plan] ?? 1;
}

/* ── Puppeteer Worker 호출 (호스팅 자동화) ── */
async function callPuppeteerWorker(env, action, payload) {
  const workerUrl = env.PUPPETEER_WORKER_URL || 'https://cloudpress-puppet.workers.dev';
  const secret = env.PUPPETEER_WORKER_SECRET || 'cp_puppet_secret_v1';
  try {
    const res = await fetch(`${workerUrl}/api/${action}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Worker-Secret': secret,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => 'Unknown error');
      return { ok: false, error: `Worker responded ${res.status}: ${txt}` };
    }
    return await res.json();
  } catch (e) {
    return { ok: false, error: `Worker connection failed: ${e.message}` };
  }
}

/* ── 메인 핸들러 ── */
export async function onRequest({ request, env, ctx }) {
  if (request.method === 'OPTIONS') return handleOptions();

  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  // 가격 조회
  if (method === 'GET' && path.endsWith('/prices')) {
    return _j({
      free: { price: 0, sites: 1, label: '무료 플랜' },
      starter: { price: 4900, sites: 3, label: '스타터 플랜' },
      pro: { price: 14900, sites: 10, label: '프로 플랜' },
      enterprise: { price: 49900, sites: -1, label: '엔터프라이즈 플랜' },
    });
  }

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  // GET /api/sites — 사이트 목록
  if (method === 'GET') {
    try {
      const sites = await env.DB.prepare(
        `SELECT id,name,subdomain,hosting_provider,hosting_domain,wp_url,wp_admin_url,
         wp_username,wp_password,status,plan,cloudflare_zone_id,breeze_installed,
         ssl_active,created_at,bandwidth_used,disk_used,suspended,suspension_reason
         FROM sites WHERE user_id=? ORDER BY created_at DESC`
      ).bind(user.id).all();
      return ok({ sites: sites.results || [] });
    } catch (e) {
      return err('사이트 목록 조회 실패: ' + e.message);
    }
  }

  // POST /api/sites — 새 WordPress 사이트 생성
  if (method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('요청 형식 오류'); }

    const { siteName } = body;
    if (!siteName?.trim()) return err('사이트 이름을 입력해주세요.');

    // 플랜 한도 확인
    const limit = await getSiteLimit(env, user.plan || 'free');
    const countRow = await env.DB.prepare(
      'SELECT COUNT(*) as c FROM sites WHERE user_id=? AND status != ?'
    ).bind(user.id, 'deleted').first();
    const count = countRow?.c ?? 0;
    if (count >= limit) {
      return err(`현재 플랜에서 최대 ${limit}개의 사이트만 생성 가능합니다. 플랜을 업그레이드하세요.`, 403);
    }

    // 임의 호스팅 제공업체 선택
    const provider = pickRandomProvider();

    // 호스팅 계정 정보 생성
    const hostingEmail = `cp${genId()}@tempmail.cloudpress.dev`;
    const hostingPw = genPw(14);
    const wpAdminUser = body.adminLogin?.trim() || 'admin';
    const wpAdminPw = genPw(16);
    const wpAdminEmail = user.email;
    const siteId = genId();

    // DB에 pending 상태로 먼저 저장
    await env.DB.prepare(
      `INSERT INTO sites
       (id,user_id,name,hosting_provider,hosting_email,hosting_password,
        wp_username,wp_password,wp_admin_email,status,plan,created_at)
       VALUES (?,?,?,?,?,?,?,?,?,'pending',?,datetime('now'))`
    ).bind(
      siteId, user.id, siteName.trim(),
      provider.id, hostingEmail, hostingPw,
      wpAdminUser, wpAdminPw, wpAdminEmail,
      user.plan || 'free'
    ).run();

    // Puppeteer Worker에 백그라운드 작업 위임
    ctx.waitUntil((async () => {
      try {
        await env.DB.prepare(
          "UPDATE sites SET status='provisioning' WHERE id=?"
        ).bind(siteId).run();

        // 1단계: 호스팅 계정 자동 생성
        const provisionResult = await callPuppeteerWorker(env, 'provision-hosting', {
          siteId,
          provider: provider.id,
          providerSignupUrl: provider.signupUrl,
          hostingEmail,
          hostingPw,
          siteName: siteName.trim(),
          wpAdminUser,
          wpAdminPw,
          wpAdminEmail,
        });

        if (!provisionResult.ok) {
          await env.DB.prepare(
            "UPDATE sites SET status='failed',error_message=? WHERE id=?"
          ).bind(provisionResult.error || '호스팅 생성 실패', siteId).run();
          return;
        }

        const { subdomain, cpanelUrl, hostingDomain, wordpressUrl, wordpressAdminUrl } = provisionResult;

        await env.DB.prepare(
          `UPDATE sites SET
           subdomain=?,hosting_domain=?,cpanel_url=?,
           wp_url=?,wp_admin_url=?,status='installing_wp'
           WHERE id=?`
        ).bind(subdomain, hostingDomain, cpanelUrl, wordpressUrl, wordpressAdminUrl, siteId).run();

        // 2단계: Softaculous로 WordPress 자동 설치 + Breeze 설치
        const wpResult = await callPuppeteerWorker(env, 'install-wordpress', {
          siteId,
          cpanelUrl,
          hostingEmail,
          hostingPw,
          wordpressUrl,
          wpAdminUser,
          wpAdminPw,
          wpAdminEmail,
          siteName: siteName.trim(),
          installBreeze: true,
        });

        if (!wpResult.ok) {
          await env.DB.prepare(
            "UPDATE sites SET status='failed',error_message=? WHERE id=?"
          ).bind(wpResult.error || 'WordPress 설치 실패', siteId).run();
          return;
        }

        // 3단계: SSL 인증서 발급 (자동 지원 호스팅의 경우)
        let sslActive = false;
        if (provider.sslAuto) {
          const sslResult = await callPuppeteerWorker(env, 'setup-ssl', {
            siteId,
            cpanelUrl,
            hostingEmail,
            hostingPw,
            domain: hostingDomain,
          });
          sslActive = sslResult.ok;
        }

        // 4단계: Cloudflare CDN 자동 연동
        let cfZoneId = null;
        if (env.CF_API_TOKEN && env.CF_ACCOUNT_ID && hostingDomain) {
          const cfResult = await setupCloudflare(env, {
            domain: hostingDomain,
            siteId,
          });
          if (cfResult.ok) cfZoneId = cfResult.zoneId;
        }

        // 완료
        await env.DB.prepare(
          `UPDATE sites SET
           status='active',ssl_active=?,cloudflare_zone_id=?,
           breeze_installed=1,wp_version=?,
           updated_at=datetime('now')
           WHERE id=?`
        ).bind(sslActive ? 1 : 0, cfZoneId, wpResult.wpVersion || '6.x', siteId).run();

      } catch (e) {
        await env.DB.prepare(
          "UPDATE sites SET status='failed',error_message=? WHERE id=?"
        ).bind(e.message, siteId).run();
      }
    })());

    return ok({
      siteId,
      status: 'pending',
      provider: provider.name,
      message: `${provider.name}에 WordPress 사이트를 생성하고 있습니다. 약 3~5분 소요됩니다.`,
    }, 202);
  }

  return err('지원하지 않는 메서드', 405);
}

/* ── Cloudflare CDN 자동 연동 ── */
async function setupCloudflare(env, { domain, siteId }) {
  const token = env.CF_API_TOKEN;
  const accountId = env.CF_ACCOUNT_ID;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  try {
    // 존 추가
    const zoneRes = await fetch('https://api.cloudflare.com/client/v4/zones', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: domain, account: { id: accountId }, jump_start: true }),
    }).then(r => r.json());

    if (!zoneRes.success) return { ok: false };
    const zoneId = zoneRes.result.id;

    // 자동 캐싱 규칙 설정
    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/cache_level`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ value: 'aggressive' }),
    });

    // Browser Cache TTL
    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/browser_cache_ttl`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ value: 14400 }),
    });

    // 항상 HTTPS
    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/always_use_https`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ value: 'on' }),
    });

    // HSTS
    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/security_header`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({
        value: {
          strict_transport_security: {
            enabled: true,
            max_age: 31536000,
            include_subdomains: true,
          },
        },
      }),
    });

    return { ok: true, zoneId };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
