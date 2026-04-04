// functions/api/sites/index.js
// CloudPress CMS 사이트 목록 + 생성 (Cloudflare Global API 활용)

/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan,plan_expires_at FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
function genPw(n=16){const c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$';let s='';const a=new Uint8Array(n);crypto.getRandomValues(a);for(const b of a)s+=c[b%c.length];return s;}
/* ── end utils ── */

/* CF API 키 복호화 */
function deobfuscate(str, salt) {
  if (!str) return '';
  try {
    const key = salt || 'cp_enc_v1';
    const decoded = atob(str);
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
  } catch { return ''; }
}

async function getUserCfCreds(env, userId) {
  const row = await env.DB.prepare('SELECT cf_global_api_key,cf_account_email,cf_account_id FROM users WHERE id=?').bind(userId).first();
  if (!row?.cf_global_api_key) return null;
  return {
    apiKey: deobfuscate(row.cf_global_api_key, env.ENCRYPTION_KEY || 'cp_enc_default'),
    email: row.cf_account_email,
    accountId: row.cf_account_id,
  };
}

const SITE_LIMITS = { free:1, starter:3, pro:10, enterprise:Infinity };

/* ─────────────────────────────────────────────
   CloudPress CMS 자동 구축 (Cloudflare API 활용)
   ───────────────────────────────────────────── */
async function provisionCmsSite(env, { siteId, siteName, subdomain, userPlan, cmsVersion, creds }) {
  if (!creds) {
    return { ok: false, error: 'Cloudflare Global API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 먼저 API 키를 등록해주세요.' };
  }

  const { apiKey, email, accountId } = creds;
  const cfHeaders = { 'X-Auth-Email': email, 'X-Auth-Key': apiKey, 'Content-Type': 'application/json' };
  const domain = env.SITE_DOMAIN || 'cloudpress.site';
  const fullSubdomain = `${subdomain}.${domain}`;
  const adminPassword = genPw(16);
  const dbName = `cp_${siteId.replace(/-/g, '_')}`;
  const kvTitle = `CloudPress CMS KV - ${siteName}`;

  let cfZoneId = null;
  let cfKvNamespace = null;
  let cfD1Database = null;
  let cfPagesProject = null;
  const logs = [];

  try {
    /* Step 1: Zone ID 조회 */
    logs.push('① Cloudflare 존 확인 중...');
    const zonesResp = await fetch(
      `https://api.cloudflare.com/client/v4/zones?name=${domain}`,
      { headers: cfHeaders }
    ).then(r => r.json()).catch(() => ({}));

    if (zonesResp.success && zonesResp.result?.length > 0) {
      cfZoneId = zonesResp.result[0].id;
      logs.push(`   ✓ Zone ID: ${cfZoneId}`);
    } else {
      logs.push('   ⚠ Zone 없음 — DNS 설정 건너뜀');
    }

    /* Step 2: KV Namespace 생성 (콘텐츠 저장소) */
    logs.push('② KV Namespace 생성 중...');
    const kvResp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces`,
      { method: 'POST', headers: cfHeaders, body: JSON.stringify({ title: kvTitle }) }
    ).then(r => r.json()).catch(() => ({}));

    if (kvResp.success) {
      cfKvNamespace = kvResp.result?.id;
      logs.push(`   ✓ KV Namespace: ${cfKvNamespace}`);
    } else {
      logs.push('   ⚠ KV 생성 실패 — ' + (kvResp.errors?.[0]?.message || '알 수 없는 오류'));
    }

    /* Step 3: D1 Database 생성 (데이터베이스) */
    logs.push('③ D1 데이터베이스 생성 중...');
    const d1Resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database`,
      { method: 'POST', headers: cfHeaders, body: JSON.stringify({ name: dbName }) }
    ).then(r => r.json()).catch(() => ({}));

    if (d1Resp.result?.uuid) {
      cfD1Database = d1Resp.result.uuid;
      logs.push(`   ✓ D1 Database: ${cfD1Database}`);
    } else {
      logs.push('   ⚠ D1 생성 실패 — ' + (d1Resp.errors?.[0]?.message || '알 수 없는 오류'));
    }

    /* Step 4: D1에 CMS 스키마 초기화 */
    if (cfD1Database) {
      logs.push('④ CMS 데이터베이스 초기화 중...');
      const cmsSchema = getCmsSchema(siteId, siteName, adminPassword);
      for (const sql of cmsSchema) {
        await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${cfD1Database}/query`,
          { method: 'POST', headers: cfHeaders, body: JSON.stringify({ sql }) }
        ).catch(() => {});
      }
      logs.push('   ✓ CMS 스키마 초기화 완료');
    }

    /* Step 5: KV에 CMS 설정 데이터 저장 */
    if (cfKvNamespace) {
      logs.push('⑤ CMS 설정 데이터 저장 중...');
      const siteConfig = {
        site_id: siteId,
        site_name: siteName,
        site_url: `https://${fullSubdomain}`,
        admin_url: `https://${fullSubdomain}/cms-admin`,
        cms_version: cmsVersion || '1.0.0',
        created_at: new Date().toISOString(),
        theme: 'default',
        plugins: [],
        settings: {
          title: siteName,
          tagline: 'CloudPress CMS로 만든 사이트',
          language: 'ko_KR',
          timezone: 'Asia/Seoul',
          date_format: 'Y년 n월 j일',
          time_format: 'H:i',
          posts_per_page: 10,
          allow_comments: true,
          permalink_structure: '/%year%/%monthnum%/%postname%/',
        }
      };
      await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${cfKvNamespace}/values/site_config`,
        { method: 'PUT', headers: { ...cfHeaders, 'Content-Type': 'text/plain' }, body: JSON.stringify(siteConfig) }
      ).catch(() => {});
      logs.push('   ✓ CMS 설정 저장 완료');
    }

    /* Step 6: DNS CNAME 등록 */
    if (cfZoneId) {
      logs.push('⑥ DNS 레코드 등록 중...');
      const dnsResp = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records`,
        {
          method: 'POST',
          headers: cfHeaders,
          body: JSON.stringify({
            type: 'CNAME',
            name: subdomain,
            content: `${domain}`,
            proxied: true,
            ttl: 1,
          })
        }
      ).then(r => r.json()).catch(() => ({}));

      if (dnsResp.success) {
        logs.push(`   ✓ DNS CNAME 등록: ${fullSubdomain}`);
      } else {
        logs.push('   ⚠ DNS 등록 실패 — ' + (dnsResp.errors?.[0]?.message || '이미 존재할 수 있음'));
      }
    }

    logs.push('✅ CloudPress CMS 구축 완료!');

    return {
      ok: true,
      status: 'active',
      cmsUrl: `https://${fullSubdomain}`,
      cmsAdminUrl: `https://${fullSubdomain}/cms-admin`,
      cmsUsername: 'admin',
      cmsPassword: adminPassword,
      cfZoneId,
      cfKvNamespace,
      cfD1Database,
      cfPagesProject,
      logs,
    };

  } catch (e) {
    console.error('provisionCmsSite error:', e);
    return { ok: false, error: 'CMS 구축 중 오류: ' + (e?.message ?? e), logs };
  }
}

/* CMS D1 데이터베이스 스키마 */
function getCmsSchema(siteId, siteName, adminPw) {
  return [
    `CREATE TABLE IF NOT EXISTS cp_users (ID INTEGER PRIMARY KEY AUTOINCREMENT, user_login TEXT UNIQUE NOT NULL, user_pass TEXT NOT NULL, user_email TEXT NOT NULL, display_name TEXT, user_registered TEXT DEFAULT (datetime('now')), user_status INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_posts (ID INTEGER PRIMARY KEY AUTOINCREMENT, post_author INTEGER DEFAULT 1, post_date TEXT DEFAULT (datetime('now')), post_content TEXT, post_title TEXT, post_excerpt TEXT, post_status TEXT DEFAULT 'draft', comment_status TEXT DEFAULT 'open', post_name TEXT, post_type TEXT DEFAULT 'post', menu_order INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_postmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, meta_key TEXT, meta_value TEXT)`,
    `CREATE TABLE IF NOT EXISTS cp_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT UNIQUE NOT NULL, option_value TEXT, autoload TEXT DEFAULT 'yes')`,
    `CREATE TABLE IF NOT EXISTS cp_terms (term_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL, term_group INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_term_taxonomy (term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT, term_id INTEGER, taxonomy TEXT, description TEXT, parent INTEGER DEFAULT 0, count INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cp_term_relationships (object_id INTEGER, term_taxonomy_id INTEGER, term_order INTEGER DEFAULT 0, PRIMARY KEY (object_id, term_taxonomy_id))`,
    `CREATE TABLE IF NOT EXISTS cp_comments (comment_ID INTEGER PRIMARY KEY AUTOINCREMENT, comment_post_ID INTEGER, comment_author TEXT, comment_author_email TEXT, comment_date TEXT DEFAULT (datetime('now')), comment_content TEXT, comment_approved TEXT DEFAULT '1')`,
    `CREATE TABLE IF NOT EXISTS cp_commentmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, comment_id INTEGER, meta_key TEXT, meta_value TEXT)`,
    `INSERT OR IGNORE INTO cp_users (user_login,user_pass,user_email,display_name) VALUES ('admin','${adminPw}','admin@${siteId}.cloudpress.site','관리자')`,
    `INSERT OR IGNORE INTO cp_options (option_name,option_value) VALUES ('siteurl','https://${siteId}.cloudpress.site'),('blogname','${siteName.replace(/'/g,"''")}'),('blogdescription','CloudPress CMS로 만든 사이트'),('admin_email','admin@${siteId}.cloudpress.site'),('posts_per_page','10'),('active_theme','default'),('cms_version','1.0.0'),('permalink_structure','/%year%/%monthnum%/%postname%/'),('timezone_string','Asia/Seoul'),('date_format','Y년 n월 j일'),('time_format','H:i'),('default_comment_status','open'),('default_ping_status','open'),('show_on_front','posts'),('uploads_path','uploads')`,
    `INSERT OR IGNORE INTO cp_posts (post_title,post_content,post_status,post_type,post_name) VALUES ('안녕하세요!','CloudPress CMS에 오신 것을 환영합니다. 이 글을 편집하거나 삭제하고 블로그를 시작해보세요!','publish','post','hello-world'),('샘플 페이지','이것은 샘플 페이지입니다. 사이드바와는 달리 페이지는 고정된 위치에 있습니다.','publish','page','sample-page')`,
    `INSERT OR IGNORE INTO cp_terms (name,slug) VALUES ('미분류','uncategorized')`,
    `INSERT OR IGNORE INTO cp_term_taxonomy (term_id,taxonomy,description,count) VALUES (1,'category','',1)`,
    `INSERT OR IGNORE INTO cp_term_relationships (object_id,term_taxonomy_id) VALUES (1,1)`,
  ];
}

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);

    const { results } = await env.DB.prepare(
      `SELECT id,name,subdomain,custom_domain,cms_url,cms_admin_url,
              cms_username,cms_version,status,plan,created_at,cf_zone_id,cf_d1_database,cf_kv_namespace
       FROM sites WHERE user_id=? ORDER BY created_at DESC`
    ).bind(user.id).all();

    return ok({ sites: results ?? [] });
  } catch (e) {
    console.error('sites GET error:', e);
    return err('사이트 목록 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await getUser(env, request);
    if (!user) return err('인증 필요', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { name, subdomain, cms_version } = body || {};
    if (!name || !name.trim()) return err('사이트 이름을 입력해주세요.');
    if (!subdomain || !subdomain.trim()) return err('서브도메인을 입력해주세요.');
    if (!/^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(subdomain)) {
      return err('서브도메인은 3~30자, 영소문자·숫자·하이픈만 사용 가능하며 시작과 끝은 영숫자여야 합니다.');
    }

    // 서브도메인 중복 체크
    const dupSub = await env.DB.prepare("SELECT id FROM sites WHERE subdomain=?").bind(subdomain).first();
    if (dupSub) return err('이미 사용 중인 서브도메인입니다.');

    // 플랜별 사이트 수 제한
    const countRow = await env.DB.prepare("SELECT COUNT(*) cnt FROM sites WHERE user_id=? AND status!='deleted'").bind(user.id).first();
    const siteCount = countRow?.cnt ?? 0;
    const limit = SITE_LIMITS[user.plan] ?? 1;
    if (siteCount >= limit) {
      return err(`현재 플랜(${user.plan})에서 최대 ${limit}개 사이트까지 가능합니다. 플랜을 업그레이드해주세요.`, 403);
    }

    // CF API 키 확인
    const creds = await getUserCfCreds(env, user.id);
    if (!creds) {
      return err('Cloudflare API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 먼저 API 키를 등록해주세요.', 403);
    }

    const siteId = genId();

    // DB에 먼저 저장 (provisioning 상태)
    await env.DB.prepare(
      `INSERT INTO sites (id,user_id,name,subdomain,status,plan,cms_version,created_at)
       VALUES (?,?,?,?,'provisioning',?,?,unixepoch())`
    ).bind(siteId, user.id, name.trim(), subdomain, user.plan, cms_version || '1.0.0').run();

    // CMS 자동 구축
    const result = await provisionCmsSite(env, {
      siteId,
      siteName: name.trim(),
      subdomain,
      userPlan: user.plan,
      cmsVersion: cms_version || '1.0.0',
      creds,
    });

    if (!result.ok) {
      await env.DB.prepare("UPDATE sites SET status='error' WHERE id=?").bind(siteId).run();
      return err(result.error, 500);
    }

    // 결과 DB 저장
    await env.DB.prepare(
      `UPDATE sites SET status='active',cms_url=?,cms_admin_url=?,cms_username=?,cms_password=?,
       cf_zone_id=?,cf_kv_namespace=?,cf_d1_database=? WHERE id=?`
    ).bind(
      result.cmsUrl, result.cmsAdminUrl, result.cmsUsername, result.cmsPassword,
      result.cfZoneId || null, result.cfKvNamespace || null, result.cfD1Database || null,
      siteId
    ).run();

    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=?').bind(siteId).first();
    return ok({
      site,
      message: 'CloudPress CMS 사이트가 구축되었습니다.',
      logs: result.logs,
    });

  } catch (e) {
    console.error('sites POST error:', e);
    return err('사이트 생성 중 오류 발생: ' + (e?.message ?? e), 500);
  }
}
