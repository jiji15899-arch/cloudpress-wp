// functions/api/sites/index.js
// 사이트 목록 + 생성 (InstaWP API 인라인)
/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan,plan_expires_at FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAuth(env,req){return await getUser(env,req);}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
/* ── end utils ── */

/* ── InstaWP 설정 ── */
const INSTAWP_API  = 'https://app.instawp.io/api/v2';
const IWP_PLAN_MAP = { free:'starter', starter:'starter', pro:'pro', enterprise:'turbo' };
const AUTO_PLUGINS = ['rank-math-seo', 'litespeed-cache', 'instawp-connect'];
const SITE_LIMITS  = { free:1, starter:3, pro:10, enterprise:Infinity };

async function provisionSite(env, { siteName, userPlan }) {
  const apiKey = env.INSTAWP_API_KEY;
  if (!apiKey) {
    return { ok:false, error:'InstaWP API 키가 설정되지 않았습니다. Cloudflare Pages → Settings → Environment Variables에 INSTAWP_API_KEY를 추가해주세요.' };
  }

  // InstaWP site_name: 영문 소문자+숫자+하이픈만 허용, 최대 32자
  const cleanName = siteName.toLowerCase().replace(/[^a-z0-9]/g,'-').replace(/-+/g,'-').replace(/^-|-$/g,'').slice(0,32);

  const payload = {
    site_name:         cleanName || `cp-${Date.now().toString(36)}`,
    wordpress_version: 'latest',
    php_version:       'latest',
    region:            'ap-southeast-1',  // Singapore
    is_reserved:       true,              // 영구 사이트 (임시 아님)
    plan:              IWP_PLAN_MAP[userPlan] || 'starter',
    plugins:           AUTO_PLUGINS,
  };

  let resp, data;
  try {
    resp = await fetch(`${INSTAWP_API}/sites`, {
      method:  'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    data = await resp.json();
  } catch (fetchErr) {
    return { ok:false, error:'InstaWP API 연결 실패: ' + (fetchErr?.message ?? fetchErr) };
  }

  if (!resp.ok || !data.status) {
    return { ok:false, error: 'InstaWP 오류: ' + (data.message || `HTTP ${resp.status}`) };
  }

  // 즉시 완료 (풀 사이트)
  if (data.data?.wp_url) {
    const s = data.data;
    return {
      ok:         true,
      status:     'active',
      iwpSiteId:  String(s.id),
      wpUrl:      s.wp_url,                                           // e.g. https://name.instawp.xyz
      wpAdminUrl: s.wp_url.replace(/\/?$/, '/wp-admin'),
      wpUsername: s.wp_username || 'admin',
      wpPassword: s.wp_password || '',
      taskId:     null,
    };
  }

  // 비동기 생성 중 (task_id)
  if (data.data?.task_id) {
    return { ok:true, status:'provisioning', iwpSiteId:null, wpUrl:null, taskId:String(data.data.task_id) };
  }

  return { ok:false, error:'InstaWP: 예상치 못한 응답 형식' };
}
/* ── end InstaWP ── */

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);

    const { results } = await env.DB.prepare(
      `SELECT id,name,subdomain,custom_domain,wp_url,wp_admin_url,
              wp_username,wp_password,status,plan,created_at,iwp_site_id,iwp_task_id
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
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { name } = body || {};
    if (!name || !name.trim()) return err('사이트 이름을 입력해주세요.');

    // 플랜별 사이트 수 제한 체크
    const countRow = await env.DB.prepare(
      "SELECT COUNT(*) cnt FROM sites WHERE user_id=? AND status != 'deleted'"
    ).bind(user.id).first();
    const siteCount = countRow?.cnt ?? 0;
    const limit = SITE_LIMITS[user.plan] ?? 1;
    if (siteCount >= limit) {
      return err(`현재 플랜(${user.plan})에서 최대 ${limit}개 사이트까지 가능합니다. 플랜을 업그레이드해주세요.`, 403);
    }

    const siteId = genId();

    // DB에 먼저 저장 (provisioning 상태)
    await env.DB.prepare(
      `INSERT INTO sites (id,user_id,name,subdomain,status,plan,region,php_version,created_at)
       VALUES (?,?,?,?,'provisioning',?,'ap-southeast-1','latest',unixepoch())`
    ).bind(siteId, user.id, name.trim(), siteId, user.plan).run();
    // 서브도메인은 InstaWP가 만든 URL로 대체되므로 임시로 siteId 사용

    // InstaWP 사이트 생성
    const result = await provisionSite(env, { siteName: name.trim(), userPlan: user.plan });

    if (!result.ok) {
      // 생성 실패 → DB 상태 error로 업데이트
      await env.DB.prepare("UPDATE sites SET status='error' WHERE id=?").bind(siteId).run();
      return err(result.error, 500);
    }

    // 결과 DB 저장
    if (result.status === 'active') {
      // InstaWP URL을 서브도메인으로 사용 (예: name.instawp.xyz)
      const iwpHost = new URL(result.wpUrl).hostname;
      await env.DB.prepare(
        `UPDATE sites SET status='active',iwp_site_id=?,subdomain=?,wp_url=?,wp_admin_url=?,wp_username=?,wp_password=? WHERE id=?`
      ).bind(result.iwpSiteId, iwpHost, result.wpUrl, result.wpAdminUrl, result.wpUsername, result.wpPassword, siteId).run();
    } else {
      // 비동기 생성 중
      await env.DB.prepare(
        `UPDATE sites SET status='provisioning',iwp_task_id=? WHERE id=?`
      ).bind(result.taskId, siteId).run();
    }

    const site = await env.DB.prepare('SELECT * FROM sites WHERE id=?').bind(siteId).first();
    return ok({ site, message: result.status === 'active' ? '사이트가 생성되었습니다.' : '사이트 생성 중입니다. 잠시 후 확인해주세요.' });

  } catch (e) {
    console.error('sites POST error:', e);
    return err('사이트 생성 중 오류 발생: ' + (e?.message ?? e), 500);
  }
}
