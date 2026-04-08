// functions/api/auth/[[action]].js
// login / register / logout / me + 2FA 지원 + DB 자동 초기화

/* ── inline utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function hashPw(p){const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p+':cloudpress_salt_v3'));return[...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');}
function genToken(){const a=new Uint8Array(32);crypto.getRandomValues(a);return[...a].map(b=>b.toString(16).padStart(2,'0')).join('');}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
function gen6(){return String(Math.floor(100000+Math.random()*900000));}
/* ── end utils ── */

/* 개인정보 패턴 탐지 (생년월일, 전화번호, 주민번호 등) */
function detectPersonalInfo(str) {
  if (!str) return false;
  // 생년월일 패턴: 19xx, 20xx, 19xx-xx-xx, 20xx/xx/xx 등
  if (/19\d{6}|20\d{6}/.test(str.replace(/[-\/\.]/g,''))) return true;
  // 6자리 숫자 연속 (생년월일 가능)
  if (/^\d{6}$/.test(str.trim())) return true;
  // 전화번호 패턴
  if (/01[0-9][-\s]?\d{3,4}[-\s]?\d{4}/.test(str)) return true;
  // 주민등록번호 패턴
  if (/\d{6}-[1-4]\d{6}/.test(str)) return true;
  return false;
}

/* ── DB 자동 초기화 ── */
async function ensureSchema(DB, env) {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',plan TEXT NOT NULL DEFAULT 'free',plan_expires_at INTEGER,cf_global_api_key TEXT,cf_account_email TEXT,cf_account_id TEXT,twofa_type TEXT DEFAULT NULL,twofa_secret TEXT DEFAULT NULL,twofa_enabled INTEGER DEFAULT 0,twofa_pending_code TEXT DEFAULT NULL,twofa_code_expires INTEGER DEFAULT NULL,created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,hosting_provider TEXT,hosting_email TEXT,hosting_password TEXT,hosting_domain TEXT,subdomain TEXT,cpanel_url TEXT,wp_url TEXT,wp_admin_url TEXT,wp_username TEXT DEFAULT 'admin',wp_password TEXT,wp_admin_email TEXT,wp_version TEXT DEFAULT '6.x',breeze_installed INTEGER DEFAULT 0,ssl_active INTEGER DEFAULT 0,cloudflare_zone_id TEXT,status TEXT NOT NULL DEFAULT 'provisioning',error_message TEXT,suspended INTEGER DEFAULT 0,suspension_reason TEXT,disk_used INTEGER DEFAULT 0,bandwidth_used INTEGER DEFAULT 0,plan TEXT NOT NULL DEFAULT 'free',created_at INTEGER NOT NULL DEFAULT (unixepoch()),updated_at INTEGER NOT NULL DEFAULT (unixepoch()),deleted_at INTEGER)`,
    `CREATE TABLE IF NOT EXISTS cms_versions (id TEXT PRIMARY KEY,version TEXT NOT NULL UNIQUE,label TEXT NOT NULL,description TEXT,is_stable INTEGER DEFAULT 1,is_latest INTEGER DEFAULT 0,release_notes TEXT,created_by TEXT REFERENCES users(id),created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),order_id TEXT UNIQUE NOT NULL,payment_key TEXT,amount INTEGER NOT NULL,plan TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',method TEXT,card_company TEXT,receipt_url TEXT,created_at INTEGER NOT NULL DEFAULT (unixepoch()),confirmed_at INTEGER)`,
    `CREATE TABLE IF NOT EXISTS notices (id TEXT PRIMARY KEY,title TEXT NOT NULL,content TEXT NOT NULL,type TEXT NOT NULL DEFAULT 'info',is_active INTEGER NOT NULL DEFAULT 1,created_by TEXT REFERENCES users(id),created_at INTEGER NOT NULL DEFAULT (unixepoch()),updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS traffic_logs (id TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),path TEXT NOT NULL,referrer TEXT,country TEXT,device TEXT,ua TEXT,created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sites_subdomain ON sites(subdomain)`,
    `CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id)`,
    `CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(created_at)`,
    `INSERT OR IGNORE INTO settings (key,value) VALUES ('plan_free_sites','1'),('plan_starter_price','9900'),('plan_pro_price','29900'),('plan_enterprise_price','99000'),('plan_starter_sites','3'),('plan_pro_sites','10'),('plan_enterprise_sites','-1'),('site_domain','cloudpress.site'),('toss_client_key',''),('toss_secret_key',''),('contact_email','choichoi3227@gmail.com'),('cms_latest_version','1.0.0'),('puppeteer_worker_url',''),('puppeteer_worker_secret',''),('auto_ssl','1'),('auto_breeze','1'),('maintenance_mode','0'),('active_providers','infinityfree,byethost,hyperphp,freehosting,profreehost,aeonfree'),('cloudflare_cdn_enabled','0')`,
    `INSERT OR IGNORE INTO cms_versions (id,version,label,description,is_stable,is_latest) VALUES ('cv1','1.0.0','CloudPress CMS v1.0.0','초기 안정 버전',1,1),('cv2','1.1.0-beta','CloudPress CMS v1.1.0 Beta','베타: 멀티사이트 지원',0,0)`,
    /* 기존 sites 테이블에 새 컬럼 추가 (마이그레이션) */
    `ALTER TABLE sites ADD COLUMN cms_url TEXT`,
    `ALTER TABLE sites ADD COLUMN cms_admin_url TEXT`,
    `ALTER TABLE sites ADD COLUMN cms_username TEXT DEFAULT 'admin'`,
    `ALTER TABLE sites ADD COLUMN cms_password TEXT`,
    `ALTER TABLE sites ADD COLUMN cms_email TEXT`,
    `ALTER TABLE sites ADD COLUMN cms_version TEXT DEFAULT 'latest'`,
    `ALTER TABLE sites ADD COLUMN cf_zone_id TEXT`,
    `ALTER TABLE sites ADD COLUMN cf_pages_project TEXT`,
    `ALTER TABLE sites ADD COLUMN cf_kv_namespace TEXT`,
    `ALTER TABLE sites ADD COLUMN cf_d1_database TEXT`,
    /* WordPress 호스팅 컬럼 마이그레이션 (기존 DB 호환) */
    `ALTER TABLE sites ADD COLUMN hosting_provider TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_email TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_password TEXT`,
    `ALTER TABLE sites ADD COLUMN hosting_domain TEXT`,
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
    /* 기존 users 테이블에 새 컬럼 추가 (마이그레이션) */
    `ALTER TABLE users ADD COLUMN cf_global_api_key TEXT`,
    `ALTER TABLE users ADD COLUMN cf_account_email TEXT`,
    `ALTER TABLE users ADD COLUMN cf_account_id TEXT`,
    `ALTER TABLE users ADD COLUMN twofa_type TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN twofa_secret TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN twofa_enabled INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN twofa_pending_code TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN twofa_code_expires INTEGER DEFAULT NULL`,
  ];
  for (const sql of stmts) {
    try { await DB.prepare(sql).run(); } catch (_) { /* 이미 존재하면 무시 */ }
  }

  /* ── 어드민 계정 자동 시드 (최초 1회) ── */
  try {
    const adminEmail = ((env && env.ADMIN_EMAIL) || 'choichoi3227@gmail.com').toLowerCase().trim();
    const adminPw    = (env && env.ADMIN_PASSWORD) || 'Swsh120327!';
    const exists = await DB.prepare('SELECT id FROM users WHERE email=?').bind(adminEmail).first();
    if (!exists) {
      const hash    = await hashPw(adminPw);
      const adminId = 'adm_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7);
      await DB.prepare(
        'INSERT OR IGNORE INTO users (id,name,email,password_hash,role,plan) VALUES (?,?,?,?,?,?)'
      ).bind(adminId, '관리자', adminEmail, hash, 'admin', 'enterprise').run();
    } else {
      /* 비밀번호가 변경됐을 수 있으므로 env.ADMIN_PASSWORD가 있으면 항상 동기화 */
      if (env && env.ADMIN_PASSWORD) {
        const hash = await hashPw(env.ADMIN_PASSWORD);
        await DB.prepare('UPDATE users SET password_hash=?,role=?,plan=? WHERE email=?')
          .bind(hash, 'admin', 'enterprise', adminEmail).run();
      }
    }
  } catch (_) { /* 어드민 시드 실패는 무시 */ }
}
/* ── end schema ── */

export const onRequestOptions = () => handleOptions();

export async function onRequest({ request, env, params }) {
  const action = (params.action || []).join('/');

  if (!env.DB)       return err('서버 설정 오류: DB 바인딩 없음 (wrangler.toml 확인)', 503);
  if (!env.SESSIONS) return err('서버 설정 오류: SESSIONS KV 바인딩 없음 (wrangler.toml 확인)', 503);

  try { await ensureSchema(env.DB, env); } catch (_) {}

  const method = request.method.toUpperCase();

  try {
    /* ── POST /api/auth/login ── */
    if (action === 'login' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('잘못된 요청 형식'); }
      const { email, password, twofa_code } = body || {};
      if (!email || !password) return err('이메일과 비밀번호를 입력해주세요.');

      const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email.toLowerCase().trim()).first();
      if (!user) return err('이메일 또는 비밀번호가 올바르지 않습니다.');
      if (await hashPw(password) !== user.password_hash) return err('이메일 또는 비밀번호가 올바르지 않습니다.');

      // 2FA 활성화된 경우
      if (user.twofa_enabled && user.twofa_type) {
        if (!twofa_code) {
          // 이메일 2FA: 코드 발송
          if (user.twofa_type === 'email') {
            const code = gen6();
            const expires = Math.floor(Date.now()/1000) + 600; // 10분
            await env.DB.prepare('UPDATE users SET twofa_pending_code=?,twofa_code_expires=? WHERE id=?')
              .bind(code, expires, user.id).run();
            // 실제 이메일 발송은 외부 서비스 필요 - 여기서는 KV에 임시 저장
            await env.SESSIONS.put(`2fa_code:${user.id}`, code, { expirationTtl: 600 });
            return _j({ ok: false, requires_2fa: true, twofa_type: 'email', message: '이메일로 인증 코드를 발송했습니다.' }, 200);
          }
          // 2차 비밀번호: 코드 입력 요청
          if (user.twofa_type === 'second_password') {
            return _j({ ok: false, requires_2fa: true, twofa_type: 'second_password', message: '2차 비밀번호를 입력해주세요.' }, 200);
          }
        }

        // 코드 검증
        if (user.twofa_type === 'email') {
          const storedCode = await env.SESSIONS.get(`2fa_code:${user.id}`);
          if (!storedCode || storedCode !== twofa_code) return err('인증 코드가 올바르지 않거나 만료되었습니다.');
          await env.SESSIONS.delete(`2fa_code:${user.id}`);
          await env.DB.prepare('UPDATE users SET twofa_pending_code=NULL,twofa_code_expires=NULL WHERE id=?').bind(user.id).run();
        } else if (user.twofa_type === 'second_password') {
          if (!twofa_code || await hashPw(twofa_code) !== user.twofa_secret) return err('2차 비밀번호가 올바르지 않습니다.');
        }
      }

      const token = genToken();
      await env.SESSIONS.put(`session:${token}`, user.id, { expirationTtl: 7 * 86400 });
      return ok({ token, user: { id:user.id, name:user.name, email:user.email, role:user.role, plan:user.plan } });
    }

    /* ── POST /api/auth/register ── */
    if (action === 'register' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('잘못된 요청 형식'); }
      const { name, email, password } = body || {};
      if (!name || !email || !password) return err('이름, 이메일, 비밀번호를 모두 입력해주세요.');
      if (password.length < 8) return err('비밀번호는 8자 이상이어야 합니다.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('올바른 이메일 형식이 아닙니다.');
      if (detectPersonalInfo(password)) return err('비밀번호에 생년월일이나 개인정보를 사용하지 마세요.');

      const lc  = email.toLowerCase().trim();
      const dup = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(lc).first();
      if (dup) return err('이미 사용 중인 이메일입니다.');

      const id   = genId();
      const hash = await hashPw(password);
      const role = lc === (env.ADMIN_EMAIL || 'choichoi3227@gmail.com').toLowerCase() ? 'admin' : 'user';

      await env.DB.prepare('INSERT INTO users (id,name,email,password_hash,role,plan) VALUES (?,?,?,?,?,?)').bind(id, name.trim(), lc, hash, role, 'free').run();

      const token = genToken();
      await env.SESSIONS.put(`session:${token}`, id, { expirationTtl: 7 * 86400 });
      return ok({ token, user: { id, name:name.trim(), email:lc, role, plan:'free' } });
    }

    /* ── POST /api/auth/logout ── */
    if (action === 'logout' && method === 'POST') {
      const t = getToken(request);
      if (t) { try { await env.SESSIONS.delete(`session:${t}`); } catch (_) {} }
      return ok({ message: '로그아웃 완료' });
    }

    /* ── GET /api/auth/me ── */
    if (action === 'me' && method === 'GET') {
      const t = getToken(request);
      if (!t) return err('인증 필요', 401);
      const uid = await env.SESSIONS.get(`session:${t}`);
      if (!uid) return err('세션 만료', 401);
      const user = await env.DB.prepare(
        'SELECT id,name,email,role,plan,plan_expires_at,twofa_enabled,twofa_type,cf_account_email FROM users WHERE id=?'
      ).bind(uid).first();
      if (!user) return err('사용자를 찾을 수 없습니다.', 404);
      // CF API 키 설정 여부 (실제 키는 노출 안 함)
      const cfRow = await env.DB.prepare('SELECT cf_global_api_key FROM users WHERE id=?').bind(uid).first();
      return ok({ user: { ...user, has_cf_api: !!(cfRow?.cf_global_api_key) } });
    }

    /* ── POST /api/auth/send-2fa-code ── */
    if (action === 'send-2fa-code' && method === 'POST') {
      const t = getToken(request);
      if (!t) return err('인증 필요', 401);
      const uid = await env.SESSIONS.get(`session:${t}`);
      if (!uid) return err('세션 만료', 401);
      const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(uid).first();
      if (!user) return err('사용자를 찾을 수 없습니다.', 404);

      const code = gen6();
      await env.SESSIONS.put(`2fa_setup:${uid}`, code, { expirationTtl: 600 });
      // 실제 환경에서는 이메일 발송 로직 추가
      // 개발/데모 환경: 코드를 응답에 포함 (프로덕션에서는 제거)
      return ok({ message: '인증 코드가 이메일로 발송되었습니다. (데모: ' + code + ')', _demo_code: code });
    }

    return err('잘못된 요청', 404);
  } catch (e) {
    console.error('auth error:', e);
    return err('서버 오류: ' + (e?.message ?? e), 500);
  }
}
