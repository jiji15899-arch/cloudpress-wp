// functions/api/sites/index.js — 사이트 목록 조회 + 신규 사이트 생성 API

/* ── utils ── */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const _j = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', ...CORS },
});
const ok  = (d = {}) => _j({ ok: true,  ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

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
      'SELECT id,name,email,role,plan FROM users WHERE id=?'
    ).bind(uid).first();
  } catch { return null; }
}

function genId() {
  return 'site_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function genPw(len = 16) {
  const chars = 'ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
  let pw = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (const b of arr) pw += chars[b % chars.length];
  return pw;
}

/* ── DB 마이그레이션: sites 테이블에 필요한 컬럼 보장 ── */
async function ensureSitesColumns(DB) {
  const migrations = [
    `ALTER TABLE sites ADD COLUMN hosting_provider TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_email TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_password TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_domain TEXT`,
    `ALTER TABLE sites ADD COLUMN subdomain TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE sites ADD COLUMN cpanel_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_admin_url TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_username TEXT DEFAULT 'admin'`,
    `ALTER TABLE sites ADD COLUMN wp_password TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_admin_email TEXT`,
    `ALTER TABLE sites ADD COLUMN wp_version TEXT DEFAULT '6.x'`,
    `ALTER TABLE sites ADD COLUMN breeze_installed INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN ssl_active INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN cloudflare_zone_id TEXT`,
    `ALTER TABLE sites ADD COLUMN error_message TEXT`,
    `ALTER TABLE sites ADD COLUMN suspended INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN suspension_reason TEXT`,
    `ALTER TABLE sites ADD COLUMN disk_used INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN bandwidth_used INTEGER DEFAULT 0`,
    `ALTER TABLE sites ADD COLUMN updated_at INTEGER DEFAULT (unixepoch())`,
    `ALTER TABLE sites ADD COLUMN deleted_at INTEGER`,
  ];
  for (const sql of migrations) {
    try { await DB.prepare(sql).run(); } catch (_) { /* 이미 존재하면 무시 */ }
  }
}

/* 플랜별 최대 사이트 수 조회 */
async function getMaxSites(env, plan) {
  try {
    const key = `plan_${plan}_sites`;
    const row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    const val = parseInt(row?.value ?? '-1');
    return val; // -1 = unlimited
  } catch {
    const defaults = { free: 1, starter: 3, pro: 10, enterprise: -1 };
    return defaults[plan] ?? 1;
  }
}

/* Puppeteer Worker URL/Secret 조회 (DB 우선, env 폴백) */
async function getPuppeteerWorkerUrl(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='puppeteer_worker_url'"
    ).first();
    return row?.value || env.PUPPETEER_WORKER_URL || '';
  } catch {
    return env.PUPPETEER_WORKER_URL || '';
  }
}

async function getPuppeteerWorkerSecret(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='puppeteer_worker_secret'"
    ).first();
    return row?.value || env.PUPPETEER_WORKER_SECRET || '';
  } catch {
    return env.PUPPETEER_WORKER_SECRET || '';
  }
}

/* 활성 호스팅 프로바이더 목록 */
const ALL_PROVIDERS = [
  'infinityfree', 'byethost', 'hyperphp',
  'freehosting', 'profreehost', 'aeonfree',
];

async function getActiveProviders(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='active_providers'"
    ).first();
    if (row?.value) return row.value.split(',').filter(Boolean);
  } catch {}
  return ALL_PROVIDERS;
}

async function pickProvider(env) {
  const providers = await getActiveProviders(env);
  return providers[Math.floor(Math.random() * providers.length)] || ALL_PROVIDERS[0];
}

/* Puppeteer Worker에 비동기 작업 위임 (fire-and-forget) */
async function dispatchToWorker(env, siteId, payload) {
  const workerUrl    = await getPuppeteerWorkerUrl(env);
  const workerSecret = await getPuppeteerWorkerSecret(env);

  if (!workerUrl) {
    await env.DB.prepare(
      "UPDATE sites SET status='failed',error_message='Worker URL 미설정',updated_at=unixepoch() WHERE id=?"
    ).bind(siteId).run().catch(() => {});
    return;
  }

  // 1단계: 호스팅 프로비저닝
  fetch(`${workerUrl}/api/provision-hosting`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Worker-Secret': workerSecret,
    },
    body: JSON.stringify(payload),
  })
    .then(async (res) => {
      let result;
      try { result = await res.json(); } catch { result = { ok: false, error: '응답 파싱 실패' }; }

      if (!result.ok) {
        await env.DB.prepare(
          "UPDATE sites SET status='failed',error_message=?,updated_at=unixepoch() WHERE id=?"
        ).bind(result.error || '호스팅 프로비저닝 실패', siteId).run().catch(() => {});
        return;
      }

      // 프로비저닝 완료 → DB 업데이트
      await env.DB.prepare(
        `UPDATE sites SET
          status='installing_wp',
          hosting_domain=?,
          subdomain=?,
          cpanel_url=?,
          wp_url=?,
          wp_admin_url=?,
          updated_at=unixepoch()
        WHERE id=?`
      ).bind(
        result.hostingDomain || '',
        result.subdomain     || '',
        result.cpanelUrl     || '',
        result.wordpressUrl  || '',
        result.wordpressAdminUrl || '',
        siteId,
      ).run().catch(() => {});

      // 2단계: WordPress 설치
      fetch(`${workerUrl}/api/install-wordpress`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Worker-Secret': workerSecret,
        },
        body: JSON.stringify({
          ...payload,
          cpanelUrl:    result.cpanelUrl,
          wordpressUrl: result.wordpressUrl,
        }),
      })
        .then(async (r2) => {
          let r2data;
          try { r2data = await r2.json(); } catch { r2data = { ok: false, error: 'WP 설치 응답 오류' }; }

          const finalStatus = r2data.ok ? 'active' : 'failed';
          await env.DB.prepare(
            `UPDATE sites SET
              status=?,
              wp_version=?,
              breeze_installed=?,
              error_message=?,
              updated_at=unixepoch()
            WHERE id=?`
          ).bind(
            finalStatus,
            r2data.wpVersion || '6.x',
            r2data.breezeInstalled ? 1 : 0,
            r2data.ok ? null : (r2data.error || 'WordPress 설치 실패'),
            siteId,
          ).run().catch(() => {});

          // 3단계: SSL 자동 설정
          if (r2data.ok) {
            const autoSslRow = await env.DB.prepare(
              "SELECT value FROM settings WHERE key='auto_ssl'"
            ).first().catch(() => null);

            if (autoSslRow?.value === '1') {
              fetch(`${workerUrl}/api/setup-ssl`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Worker-Secret': workerSecret,
                },
                body: JSON.stringify({
                  cpanelUrl:    result.cpanelUrl,
                  hostingEmail: payload.hostingEmail,
                  hostingPw:    payload.hostingPw,
                  domain:       result.hostingDomain,
                }),
              })
                .then(async (r3) => {
                  let r3data;
                  try { r3data = await r3.json(); } catch { r3data = { ok: false }; }
                  if (r3data.ok) {
                    await env.DB.prepare(
                      "UPDATE sites SET ssl_active=1,updated_at=unixepoch() WHERE id=?"
                    ).bind(siteId).run().catch(() => {});
                  }
                })
                .catch(() => {});
            }
          }
        })
        .catch(async (e) => {
          await env.DB.prepare(
            "UPDATE sites SET status='failed',error_message=?,updated_at=unixepoch() WHERE id=?"
          ).bind('WordPress 설치 요청 실패: ' + e.message, siteId).run().catch(() => {});
        });
    })
    .catch(async (e) => {
      await env.DB.prepare(
        "UPDATE sites SET status='failed',error_message=?,updated_at=unixepoch() WHERE id=?"
      ).bind('Worker 연결 실패: ' + e.message, siteId).run().catch(() => {});
    });
}

/* ── Route Exports ── */

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

/* GET /api/sites — 내 사이트 목록 조회 */
export async function onRequestGet({ request, env }) {
  // 컬럼 존재 보장 (기존 DB 호환)
  await ensureSitesColumns(env.DB).catch(() => {});

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  try {
    const { results } = await env.DB.prepare(
      `SELECT
        id, name, hosting_provider, hosting_domain, subdomain,
        wp_url, wp_admin_url, wp_username, wp_version,
        breeze_installed, ssl_active, status, error_message,
        suspended, suspension_reason, disk_used, bandwidth_used,
        plan, created_at, updated_at
       FROM sites
       WHERE user_id=? AND (status IS NULL OR status != 'deleted')
       ORDER BY created_at DESC`
    ).bind(user.id).all();

    return ok({ sites: results ?? [] });
  } catch (e) {
    return err('사이트 목록 조회 실패: ' + e.message, 500);
  }
}

/* POST /api/sites — 신규 사이트 생성 */
export async function onRequestPost({ request, env }) {
  // 컬럼 존재 보장 (기존 DB 호환) — INSERT 전에 반드시 실행
  await ensureSitesColumns(env.DB).catch(() => {});

  const user = await getUser(env, request);
  if (!user) return err('로그인이 필요합니다.', 401);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  const { siteName, adminLogin } = body || {};

  if (!siteName || !siteName.trim())        return err('사이트 이름을 입력해주세요.');
  if (!adminLogin || adminLogin.length < 3) return err('관리자 아이디는 3자 이상 입력해주세요.');
  if (!/^[a-zA-Z0-9_]+$/.test(adminLogin)) return err('관리자 아이디는 영문/숫자/언더바만 사용 가능합니다.');

  // Puppeteer Worker URL 설정 여부 확인
  const workerUrl = await getPuppeteerWorkerUrl(env);
  if (!workerUrl) {
    return err(
      'Puppeteer Worker URL이 설정되지 않았습니다. 관리자 → 설정에서 Worker URL을 입력해주세요.',
      503
    );
  }

  // 플랜별 사이트 수 제한 확인
  const maxSites = await getMaxSites(env, user.plan);
  if (maxSites !== -1) {
    const countRow = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM sites WHERE user_id=? AND (status IS NULL OR status != 'deleted')"
    ).bind(user.id).first();
    const count = countRow?.c ?? 0;
    if (count >= maxSites) {
      return err(
        `현재 플랜(${user.plan})의 최대 사이트 수(${maxSites}개)에 도달했습니다. 플랜을 업그레이드해주세요.`,
        403
      );
    }
  }

  // 자동 생성 값
  const siteId       = genId();
  const siteDomain   = env.SITE_DOMAIN || 'cloudpress.site';
  const hostingEmail = `cp${Math.random().toString(36).slice(2, 9)}@${siteDomain}`;
  const hostingPw    = genPw(14);
  const wpAdminPw    = genPw(16);
  const wpAdminEmail = user.email;
  const provider     = await pickProvider(env);

  const autoBreezeRow = await env.DB.prepare(
    "SELECT value FROM settings WHERE key='auto_breeze'"
  ).first().catch(() => null);
  const installBreeze = autoBreezeRow?.value === '1';

  // DB에 사이트 레코드 생성
  // hosting_* / wp_* 컬럼이 없는 구버전 DB는 ensureSitesColumns로 이미 추가됨
  try {
    await env.DB.prepare(
      `INSERT INTO sites (
        id, user_id, name,
        hosting_provider, hosting_email, hosting_password,
        subdomain,
        wp_username, wp_password, wp_admin_email,
        status, plan
      ) VALUES (?,?,?,?,?,?,?,?,?,?,'provisioning',?)`
    ).bind(
      siteId, user.id, siteName.trim(),
      provider, hostingEmail, hostingPw,
      '',
      adminLogin, wpAdminPw, wpAdminEmail,
      user.plan,
    ).run();
  } catch (e) {
    return err('사이트 생성 실패: ' + e.message, 500);
  }

  // Puppeteer Worker에 비동기 위임
  dispatchToWorker(env, siteId, {
    provider,
    hostingEmail,
    hostingPw,
    siteName: siteName.trim(),
    wpAdminUser:  adminLogin,
    wpAdminPw,
    wpAdminEmail,
    installBreeze,
  });

  return ok({
    siteId,
    provider,
    message: '사이트 생성이 시작되었습니다. 완료까지 3~5분 소요됩니다.',
  });
}
