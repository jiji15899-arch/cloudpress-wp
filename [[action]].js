// functions/api/auth/[[action]].js
// login / register / logout / me + DB 자동 초기화

/* ── inline utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function hashPw(p){const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p+':cloudpress_salt_v2'));return[...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');}
function genToken(){const a=new Uint8Array(32);crypto.getRandomValues(a);return[...a].map(b=>b.toString(16).padStart(2,'0')).join('');}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
/* ── end utils ── */

/* ── DB 자동 초기화 (첫 요청 시 테이블 없으면 생성) ── */
async function ensureSchema(DB) {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',plan TEXT NOT NULL DEFAULT 'free',plan_expires_at INTEGER,created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,subdomain TEXT UNIQUE NOT NULL,custom_domain TEXT,wp_url TEXT,wp_admin_url TEXT,wp_username TEXT,wp_password TEXT,iwp_site_id TEXT,iwp_task_id TEXT,vps_container_id TEXT,status TEXT NOT NULL DEFAULT 'provisioning',php_version TEXT DEFAULT 'latest',region TEXT DEFAULT 'ap-southeast-1',plan TEXT NOT NULL DEFAULT 'free',disk_usage_mb INTEGER DEFAULT 0,created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),order_id TEXT UNIQUE NOT NULL,payment_key TEXT,amount INTEGER NOT NULL,plan TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',method TEXT,card_company TEXT,receipt_url TEXT,created_at INTEGER NOT NULL DEFAULT (unixepoch()),confirmed_at INTEGER)`,
    `CREATE TABLE IF NOT EXISTS notices (id TEXT PRIMARY KEY,title TEXT NOT NULL,content TEXT NOT NULL,type TEXT NOT NULL DEFAULT 'info',is_active INTEGER NOT NULL DEFAULT 1,created_by TEXT REFERENCES users(id),created_at INTEGER NOT NULL DEFAULT (unixepoch()),updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE TABLE IF NOT EXISTS traffic_logs (id TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),path TEXT NOT NULL,referrer TEXT,country TEXT,device TEXT,ua TEXT,created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
    `CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sites_subdomain ON sites(subdomain)`,
    `CREATE INDEX IF NOT EXISTS idx_sites_iwp ON sites(iwp_site_id)`,
    `CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id)`,
    `CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(created_at)`,
    `INSERT OR IGNORE INTO settings (key,value) VALUES ('plan_starter_price','9900'),('plan_pro_price','29900'),('plan_enterprise_price','99000'),('plan_starter_sites','3'),('plan_pro_sites','10'),('plan_enterprise_sites','-1'),('site_domain','cloudpress.cloud-in.co.kr'),('toss_client_key',''),('toss_secret_key',''),('instawp_api_key',''),('contact_email','choichoi3227@gmail.com')`,
  ];
  for (const sql of stmts) {
    try { await DB.prepare(sql).run(); } catch (_) {}
  }
}
/* ── end schema ── */

export const onRequestOptions = () => handleOptions();

export async function onRequest({ request, env, params }) {
  const action = (params.action || []).join('/');

  if (!env.DB)       return err('서버 설정 오류: DB 바인딩 없음 (wrangler.toml 확인)', 503);
  if (!env.SESSIONS) return err('서버 설정 오류: SESSIONS KV 바인딩 없음 (wrangler.toml 확인)', 503);

  try { await ensureSchema(env.DB); } catch (_) {}

  const method = request.method.toUpperCase();

  try {
    /* ── POST /api/auth/login ── */
    if (action === 'login' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('잘못된 요청 형식'); }
      const { email, password } = body || {};
      if (!email || !password) return err('이메일과 비밀번호를 입력해주세요.');

      const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email.toLowerCase().trim()).first();
      if (!user) return err('이메일 또는 비밀번호가 올바르지 않습니다.');
      if (await hashPw(password) !== user.password_hash) return err('이메일 또는 비밀번호가 올바르지 않습니다.');

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
      if (password.length < 6)          return err('비밀번호는 6자 이상이어야 합니다.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('올바른 이메일 형식이 아닙니다.');

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
      if (!t) return err('인증이 필요합니다.', 401);
      const userId = await env.SESSIONS.get(`session:${t}`);
      if (!userId) return err('세션이 만료되었습니다. 다시 로그인해주세요.', 401);
      const user = await env.DB.prepare('SELECT id,name,email,role,plan,plan_expires_at,created_at FROM users WHERE id=?').bind(userId).first();
      if (!user) return err('사용자를 찾을 수 없습니다.', 401);
      return ok({ user });
    }

    return err('잘못된 요청 경로', 404);

  } catch (e) {
    console.error(`auth [${action}] error:`, e?.message ?? e);
    return err('처리 중 오류가 발생했습니다: ' + (e?.message ?? '알 수 없는 오류'), 500);
  }
}
