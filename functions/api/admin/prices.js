// functions/api/sites/prices.js — 공개 플랜 가격 조회 API
import { CORS, _j, ok, err } from '../_shared.js';

export const onRequestOptions=()=>new Response(null,{status:204,headers:CORS});
export async function onRequestGet({env}){
  try{
    const keys=['plan_starter_price','plan_pro_price','plan_enterprise_price','plan_starter_sites','plan_pro_sites','plan_enterprise_sites'];
    const{results}=await env.DB.prepare(`SELECT key,value FROM settings WHERE key IN (${keys.map(()=>'?').join(',')})`).bind(...keys).all();
    const data={ok:true};
    for(const r of(results||[]))data[r.key]=r.value;
    return _j(data);
  }catch(e){return _j({ok:false,error:e.message},500);}
}
