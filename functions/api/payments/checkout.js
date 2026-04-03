// functions/api/payments/checkout.js
/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAuth(env,req){return await getUser(env,req);}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
/* ── end utils ── */

export const onRequestOptions = () => handleOptions();

export async function onRequestPost({ request, env }) {
  try {
    const user = await requireAuth(env, request);
    if (!user) return err('인증 필요', 401);

    let body;
    try { body = await request.json(); } catch { return err('잘못된 요청'); }

    const { plan } = body || {};
    if (!plan || plan === 'free') return err('유효한 플랜을 선택해주세요.');
    if (!['starter','pro','enterprise'].includes(plan)) return err('알 수 없는 플랜입니다.');

    const [starterRow, proRow, enterpriseRow] = await Promise.all([
      env.DB.prepare("SELECT value FROM settings WHERE key='plan_starter_price'").first(),
      env.DB.prepare("SELECT value FROM settings WHERE key='plan_pro_price'").first(),
      env.DB.prepare("SELECT value FROM settings WHERE key='plan_enterprise_price'").first(),
    ]);

    const prices = {
      starter:    parseInt(starterRow?.value    || '9900'),
      pro:        parseInt(proRow?.value        || '29900'),
      enterprise: parseInt(enterpriseRow?.value || '99000'),
    };

    const amount = prices[plan];
    if (!amount || isNaN(amount)) return err('가격 정보를 불러올 수 없습니다.');

    const orderId   = `order_${genId()}`;
    const planNames = { starter:'스타터', pro:'프로', enterprise:'엔터프라이즈' };

    await env.DB.prepare(
      'INSERT INTO payments (id,user_id,order_id,amount,plan,status) VALUES (?,?,?,?,?,?)'
    ).bind(genId(), user.id, orderId, amount, plan, 'pending').run();

    const tossClientKey = env.TOSS_CLIENT_KEY || (await env.DB.prepare("SELECT value FROM settings WHERE key='toss_client_key'").first())?.value || '';

    return ok({ orderId, orderName:`CloudPress ${planNames[plan]} 플랜`, amount, customerName:user.name, customerEmail:user.email, tossClientKey, plan });
  } catch (e) {
    console.error('checkout error:', e);
    return err('결제 준비 실패: ' + (e?.message ?? e), 500);
  }
}
