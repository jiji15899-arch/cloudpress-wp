// functions/api/sites/index.js — CloudPress CMS v2.1 (백그라운드 + 완전 수정)

/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan,plan_expires_at FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
function genPw(n=16){const c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';let s='';const a=new Uint8Array(n);crypto.getRandomValues(a);for(const b of a)s+=c[b%c.length];return s;}
/* ── end utils ── */

async function sha256hex(text){const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));return[...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');}
async function sha256hexBytes(bytes){const buf=await crypto.subtle.digest('SHA-256',bytes);return[...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');}

function generateProjectName(siteName){
  const base=siteName.toLowerCase().replace(/[^a-z0-9]/g,'-').replace(/-+/g,'-').replace(/^-+|-+$/g,'').slice(0,18)||'site';
  const suffix=Math.random().toString(36).slice(2,7);
  return`cp-${base}-${suffix}`.slice(0,28);
}

function deobfuscate(str,salt){
  if(!str)return'';
  try{const key=salt||'cp_enc_v1';const decoded=atob(str);let r='';for(let i=0;i<decoded.length;i++){r+=String.fromCharCode(decoded.charCodeAt(i)^key.charCodeAt(i%key.length));}return r;}catch{return'';}
}

async function getUserCfCreds(env,userId){
  const row=await env.DB.prepare('SELECT cf_global_api_key,cf_account_email,cf_account_id FROM users WHERE id=?').bind(userId).first();
  if(!row?.cf_global_api_key)return null;
  const apiKey=deobfuscate(row.cf_global_api_key,env.ENCRYPTION_KEY||'cp_enc_default');
  const email=row.cf_account_email;
  let accountId=row.cf_account_id;
  if(!accountId){
    try{
      const h={'X-Auth-Email':email,'X-Auth-Key':apiKey,'Content-Type':'application/json'};
      const r=await fetch('https://api.cloudflare.com/client/v4/accounts?per_page=1',{headers:h});
      const d=await r.json();
      if(d.success&&d.result?.length>0){
        accountId=d.result[0].id;
        await env.DB.prepare('UPDATE users SET cf_account_id=? WHERE id=?').bind(accountId,userId).run().catch(()=>{});
      }
    }catch(_){}
  }
  if(!apiKey||!email||!accountId)return null;
  return{apiKey,email,accountId};
}

async function getSiteLimit(env,plan){
  try{
    const row=await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(`plan_${plan}_sites`).first();
    if(row){const v=parseInt(row.value);return v===-1?Infinity:v;}
  }catch(_){}
  const def={free:0,starter:3,pro:10,enterprise:Infinity};
  return def[plan]??0;
}

/* ══ ZIP 파서 ══ */
function parseZip(buffer){
  const view=new DataView(buffer),bytes=new Uint8Array(buffer),files=[];let offset=0;
  while(offset+30<=bytes.length){
    const sig=view.getUint32(offset,true);if(sig!==0x04034b50)break;
    const compression=view.getUint16(offset+8,true);
    const compressedSize=view.getUint32(offset+18,true);
    const fileNameLen=view.getUint16(offset+26,true);
    const extraLen=view.getUint16(offset+28,true);
    const name=new TextDecoder('utf-8').decode(bytes.slice(offset+30,offset+30+fileNameLen));
    const dataStart=offset+30+fileNameLen+extraLen;
    files.push({name,compression,data:bytes.slice(dataStart,dataStart+compressedSize)});
    offset=dataStart+compressedSize;
  }
  return files;
}

async function inflateDeflate(data){
  try{
    const ds=new DecompressionStream('deflate-raw');
    const w=ds.writable.getWriter(),r=ds.readable.getReader();
    w.write(data);w.close();
    const chunks=[];
    while(true){const{done,value}=await r.read();if(done)break;chunks.push(value);}
    const total=chunks.reduce((s,c)=>s+c.length,0),result=new Uint8Array(total);
    let pos=0;for(const c of chunks){result.set(c,pos);pos+=c.length;}
    return result;
  }catch{return null;}
}

function base64ToBuffer(b64){
  const raw=b64.replace(/^data:[^;]+;base64,/,''),binary=atob(raw);
  const bytes=new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
  return bytes.buffer;
}

function getMimeType(path){
  const ext=path.split('.').pop().toLowerCase();
  const map={html:'text/html; charset=utf-8',js:'application/javascript; charset=utf-8',css:'text/css; charset=utf-8',json:'application/json',txt:'text/plain; charset=utf-8',svg:'image/svg+xml',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',ico:'image/x-icon',woff:'font/woff',woff2:'font/woff2',webp:'image/webp'};
  return map[ext]||'application/octet-stream';
}

function applyPlaceholders(text,vars){
  return text
    .replace(/REPLACE_WITH_YOUR_SITE/g,vars.projectName)
    .replace(/https:\/\/REPLACE_WITH_YOUR_SITE\.pages\.dev/g,vars.siteUrl)
    .replace(/REPLACE_WITH_D1_DATABASE_ID/g,vars.d1DatabaseId||'')
    .replace(/REPLACE_WITH_KV_NAMESPACE_ID/g,vars.kvNamespaceId||'')
    .replace(/SITE_URL_PLACEHOLDER/g,vars.siteUrl.replace('https://',''))
    .replace(/SITE_NAME_PLACEHOLDER/g,(vars.siteName||'').replace(/'/g,"''"))
    .replace(/ADMIN_EMAIL_PLACEHOLDER/g,vars.adminEmail||`admin@${vars.projectName}.pages.dev`)
    .replace(/ADMIN_LOGIN_PLACEHOLDER/g,vars.adminLogin||'admin');
}

/* ══ GitHub CMS 파일 목록 ══
   jiji15899-arch/cloudflare-cms-file-assets 레포에서
   실제 파일을 직접 fetch해서 Pages에 배포한다.
   배포 순서: GitHub raw → KV 캐시 → DB 패키지 → 기본 템플릿 */

const GITHUB_REPO='jiji15899-arch/cloudflare-cms-file-assets';
const GITHUB_BRANCH='main';
const GITHUB_RAW=`https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}`;
const GITHUB_API=`https://api.github.com/repos/${GITHUB_REPO}/git/trees/${GITHUB_BRANCH}?recursive=1`;

/* GitHub 레포에서 전체 파일 트리를 가져온다 */
async function fetchGithubTree(logs){
  try{
    const r=await fetch(GITHUB_API,{headers:{'User-Agent':'CloudPress-Provisioner','Accept':'application/vnd.github.v3+json'}});
    if(!r.ok){logs.push(`   ⚠ GitHub API 오류: ${r.status}`);return null;}
    const d=await r.json();
    /* blob(파일)만 필터 — 디렉토리/트리 제외 */
    return(d.tree||[]).filter(t=>t.type==='blob'&&t.path&&!t.path.includes('__MACOSX')&&!t.path.includes('.DS_Store')&&t.path!=='README.md'&&!t.path.endsWith('wrangler.toml')&&!t.path.endsWith('cms-schema.sql'));
  }catch(e){logs.push(`   ⚠ GitHub 트리 fetch 실패: ${e.message}`);return null;}
}

/* GitHub raw에서 단일 파일을 ArrayBuffer로 fetch */
async function fetchGithubFile(path){
  const r=await fetch(`${GITHUB_RAW}/${path}`,{headers:{'User-Agent':'CloudPress-Provisioner'}});
  if(!r.ok)throw new Error(`HTTP ${r.status}: ${path}`);
  return r.arrayBuffer();
}

async function loadCmsPackage(env,preferredVersion){
  // 1) 지정 버전 KV
  if(preferredVersion){
    const val=await env.SESSIONS.get(`cms_package:${preferredVersion}`).catch(()=>null);
    if(val)return{data:val,version:preferredVersion,source:'kv'};
  }
  // 2) DB 최신 버전
  let ver=null;
  try{
    const r=await env.DB.prepare("SELECT version FROM cms_versions WHERE is_latest=1 ORDER BY created_at DESC LIMIT 1").first().catch(()=>null);
    ver=r?.version||null;
    if(!ver){const r2=await env.DB.prepare("SELECT version FROM cms_packages WHERE is_latest=1 ORDER BY uploaded_at DESC LIMIT 1").first().catch(()=>null);ver=r2?.version||null;}
  }catch(_){}
  if(ver){const val=await env.SESSIONS.get(`cms_package:${ver}`).catch(()=>null);if(val)return{data:val,version:ver,source:'kv'};}
  // 3) KV 스캔
  try{
    const list=await env.SESSIONS.list({prefix:'cms_package:'});
    for(const k of list?.keys||[]){
      const val=await env.SESSIONS.get(k.name).catch(()=>null);
      if(val)return{data:val,version:k.name.replace('cms_package:',''),source:'kv'};
    }
  }catch(_){}
  return null;
}

/* GitHub에서 파일들을 직접 fetch해서 Pages 배포용 {manifest, fileParts} 생성 */
async function buildDeployFromGithub(vars,logs){
  logs.push('   ℹ GitHub에서 CMS 파일 목록 가져오는 중...');
  const tree=await fetchGithubTree(logs);
  if(!tree||tree.length===0){logs.push('   ⚠ GitHub 파일 목록 없음');return null;}
  logs.push(`   ℹ GitHub 파일 ${tree.length}개 발견 → 다운로드 중...`);

  const manifest={},fileParts=[];
  let failed=0;

  /* 동시 다운로드 (최대 6개씩) */
  const chunks=[];
  for(let i=0;i<tree.length;i+=6)chunks.push(tree.slice(i,i+6));

  for(const chunk of chunks){
    await Promise.all(chunk.map(async file=>{
      try{
        const buf=await fetchGithubFile(file.path);
        const mimeType=getMimeType(file.path);
        const isText=mimeType.startsWith('text/')||mimeType.includes('javascript')||mimeType.includes('json');
        let fileBytes=new Uint8Array(buf);
        if(isText){
          let text=new TextDecoder('utf-8').decode(fileBytes);
          text=applyPlaceholders(text,vars);
          fileBytes=new TextEncoder().encode(text);
        }
        const hash=await sha256hexBytes(fileBytes);
        const cleanPath='/'+file.path;
        manifest[hash]=cleanPath;
        fileParts.push({hash,bytes:fileBytes,mimeType});
      }catch(e){failed++;console.error(`GitHub fetch fail: ${file.path}`,e.message);}
    }));
  }

  if(!fileParts.length){logs.push('   ⚠ GitHub에서 다운로드된 파일 없음');return null;}
  if(failed>0)logs.push(`   ⚠ ${failed}개 파일 다운로드 실패 (나머지 ${fileParts.length}개로 배포)`);
  else logs.push(`   ✓ GitHub 파일 ${fileParts.length}개 다운로드 완료`);
  return{manifest,fileParts};
}

async function extractZipForPages(zipBase64,vars){
  const zipBuffer=base64ToBuffer(zipBase64);
  const rawFiles=parseZip(zipBuffer);
  if(!rawFiles.length)throw new Error('ZIP 파일 파싱 실패 (파일 0개)');
  const first=rawFiles.find(f=>!f.name.endsWith('/'));
  const prefix=first?.name.match(/^([^/]+\/)/)?.[1]||'';
  const manifest={},fileParts=[];
  for(const f of rawFiles){
    if(f.name.endsWith('/')||f.name.includes('__MACOSX')||f.name.includes('.DS_Store'))continue;
    if(f.name.endsWith('wrangler.toml')||f.name.endsWith('cms-schema.sql'))continue;
    let cleanPath=prefix&&f.name.startsWith(prefix)?f.name.slice(prefix.length):f.name;
    if(!cleanPath)continue;
    let fileBytes;
    if(f.compression===0)fileBytes=f.data;
    else if(f.compression===8){fileBytes=await inflateDeflate(f.data);if(!fileBytes)continue;}
    else continue;
    const mimeType=getMimeType(cleanPath);
    const isText=mimeType.startsWith('text/')||mimeType.includes('javascript')||mimeType.includes('json');
    if(isText){
      let text=new TextDecoder('utf-8').decode(fileBytes);
      text=applyPlaceholders(text,vars);
      fileBytes=new TextEncoder().encode(text);
    }
    const hash=await sha256hexBytes(fileBytes);
    manifest[hash]='/'+cleanPath;
    fileParts.push({hash,bytes:fileBytes,mimeType});
  }
  if(!fileParts.length)throw new Error('배포할 파일이 없습니다');
  return{manifest,fileParts};
}

/* ══ Pages 바인딩 자동 설정 ══ */
async function setPagesBindings(accountId,projectName,cfAuth,{kvNamespaceId,d1DatabaseId,siteUrl,adminLogin,logs}){
  const body={deployment_configs:{production:{
    env_vars:{
      SITE_URL:{type:'plain_text',value:siteUrl},
      CMS_VERSION:{type:'plain_text',value:'1.0.0'},
      ADMIN_LOGIN:{type:'plain_text',value:adminLogin||'admin'},
    }
  }}};
  if(kvNamespaceId)body.deployment_configs.production.kv_namespaces={CMS_KV:{namespace_id:kvNamespaceId}};
  if(d1DatabaseId)body.deployment_configs.production.d1_databases={CMS_DB:{id:d1DatabaseId}};
  try{
    const r=await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}`,
      {method:'PATCH',headers:{'X-Auth-Email':cfAuth.email,'X-Auth-Key':cfAuth.apiKey,'Content-Type':'application/json'},body:JSON.stringify(body)}
    ).then(r=>r.json());
    if(r.success)logs.push('   ✓ Pages 바인딩(D1/KV/환경변수) 자동 설정 완료');
    else logs.push(`   ⚠ Pages 바인딩 설정 실패: ${r.errors?.[0]?.message||'unknown'}`);
  }catch(e){logs.push(`   ⚠ Pages 바인딩 오류: ${e.message}`);}
}

/* ══ Pages에 파일셋 업로드 공통 함수 ══ */
async function uploadToPages(accountId,projectName,cfAuth,{manifest,fileParts}){
  const form=new FormData();
  form.append('manifest',new Blob([JSON.stringify(manifest)],{type:'application/json'}));
  for(const f of fileParts)form.append(f.hash,new Blob([f.bytes],{type:f.mimeType}),f.hash);
  return fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}/deployments`,
    {method:'POST',headers:{'X-Auth-Email':cfAuth.email,'X-Auth-Key':cfAuth.apiKey},body:form}
  ).then(r=>r.json()).catch(e=>({success:false,errors:[{message:e.message}]}));
}

/* ══ CMS 배포: GitHub → KV 패키지 → 기본 템플릿 ══ */
async function deployCmsSite(env,{accountId,projectName,cfAuth,siteName,siteUrl,cmsVersion,kvNamespaceId,d1DatabaseId,adminLogin,adminEmail,logs}){
  const vars={siteUrl,projectName,kvNamespaceId:kvNamespaceId||'',d1DatabaseId:d1DatabaseId||'',siteName,adminLogin,adminEmail};

  /* ── 1순위: GitHub 직접 배포 ── */
  logs.push('   ℹ GitHub CMS 파일 배포 시도 중...');
  try{
    const ghResult=await buildDeployFromGithub(vars,logs);
    if(ghResult){
      const resp=await uploadToPages(accountId,projectName,cfAuth,ghResult);
      if(resp.success){
        logs.push(`   ✓ GitHub CMS 파일 배포 완료 → ${siteUrl}`);
        await setPagesBindings(accountId,projectName,cfAuth,{kvNamespaceId,d1DatabaseId,siteUrl,adminLogin,logs});
        return{ok:true,mode:'github',version:'latest'};
      }
      logs.push(`   ⚠ GitHub 배포 실패: ${resp.errors?.[0]?.message||'unknown'} → KV 패키지 시도`);
    }
  }catch(e){logs.push(`   ⚠ GitHub 배포 오류: ${e.message} → KV 패키지 시도`);}

  /* ── 2순위: KV에 저장된 ZIP 패키지 ── */
  const pkg=await loadCmsPackage(env,cmsVersion).catch(()=>null);
  if(pkg?.data){
    logs.push(`   ℹ KV CMS 패키지 v${pkg.version} 발견 → ZIP 배포`);
    try{
      const{manifest,fileParts}=await extractZipForPages(pkg.data,vars);
      logs.push(`   ℹ 배포 파일: ${fileParts.length}개`);
      const resp=await uploadToPages(accountId,projectName,cfAuth,{manifest,fileParts});
      if(resp.success){
        logs.push(`   ✓ KV CMS 패키지 v${pkg.version} 배포 완료 → ${siteUrl}`);
        await setPagesBindings(accountId,projectName,cfAuth,{kvNamespaceId,d1DatabaseId,siteUrl,adminLogin,logs});
        return{ok:true,mode:'package',version:pkg.version};
      }
      logs.push(`   ⚠ ZIP 배포 실패: ${resp.errors?.[0]?.message||'unknown'} → 기본 템플릿`);
    }catch(e){logs.push(`   ⚠ ZIP 처리 오류: ${e.message} → 기본 템플릿`);}
  }else{
    logs.push('   ⚠ KV에 CMS 패키지 없음 → 기본 템플릿 배포');
  }

  /* ── 3순위 (최후 fallback): 기본 HTML 3개 인라인 생성 ── */
  logs.push('   ℹ 기본 템플릿으로 최소 배포 진행...');
  const dashboardUrl='https://cloudpress.pages.dev/dashboard.html';
  const fbFiles={
    '/index.html':buildIndexHtml(siteName,siteUrl),
    '/404.html':build404Html(siteName,siteUrl),
    '/wp-admin/index.html':buildAdminHtml(siteName,dashboardUrl),
  };
  const fbEntries=[];
  for(const[path,content]of Object.entries(fbFiles))
    fbEntries.push({path,content,hash:await sha256hex(content)});
  const fbManifest={};for(const e of fbEntries)fbManifest[e.hash]=e.path;
  const fbParts=fbEntries.map(e=>({hash:e.hash,bytes:new TextEncoder().encode(e.content),mimeType:'text/html; charset=utf-8'}));
  const resp=await uploadToPages(accountId,projectName,cfAuth,{manifest:fbManifest,fileParts:fbParts});
  if(resp.success){
    logs.push(`   ✓ 기본 템플릿 배포 완료 → ${siteUrl}`);
    await setPagesBindings(accountId,projectName,cfAuth,{kvNamespaceId,d1DatabaseId,siteUrl,adminLogin,logs});
    return{ok:true,mode:'fallback'};
  }
  const errMsg=resp.errors?.[0]?.message||'배포 실패';
  logs.push(`   ✗ 배포 실패: ${errMsg}`);
  return{ok:false,error:errMsg};
}

/* fallback HTML 생성 */
function buildIndexHtml(siteName,siteUrl){
  const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return`<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${esc(siteName)}</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f1f1;color:#3c434a}.site-header{background:#1d2327;padding:20px 24px}.site-title{color:#fff;font-size:1.4rem;font-weight:700}nav{background:#2271b1}nav a{color:#fff;padding:11px 16px;font-size:.88rem;display:inline-block;text-decoration:none}.wrapper{max-width:1200px;margin:36px auto;padding:0 24px}.post-card{background:#fff;padding:28px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}.post-title{font-size:1.35rem;color:#1d2327;margin-bottom:8px}.post-excerpt{line-height:1.75;color:#50575e}</style></head><body><header class="site-header"><div class="site-title">${esc(siteName)}</div></header><nav><a href="/">홈</a><a href="/wp-admin/">관리자</a></nav><div class="wrapper"><div class="post-card"><h2 class="post-title">안녕하세요!</h2><div class="post-excerpt"><p>${esc(siteName)}에 오신 것을 환영합니다. 관리자 페이지에서 글을 작성해보세요!</p></div></div></div></body></html>`;
}
function buildAdminHtml(siteName,dashboardUrl){
  const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;');
  return`<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta http-equiv="refresh" content="3;url=${dashboardUrl}"><title>관리자 — ${esc(siteName)}</title><style>body{font-family:-apple-system,sans-serif;background:#1d2327;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}.card{background:#2c3338;border-radius:8px;padding:48px 40px;max-width:420px;width:90%}.spinner{width:28px;height:28px;border:3px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:sp .8s linear infinite;margin:0 auto 16px}@keyframes sp{to{transform:rotate(360deg)}}a{color:#fff;display:inline-block;margin-top:16px;padding:10px 24px;background:#2271b1;border-radius:4px;text-decoration:none}</style></head><body><div class="card"><h1 style="margin-bottom:16px">${esc(siteName)}</h1><div class="spinner"></div><p>CloudPress 대시보드로 이동 중...</p><a href="${dashboardUrl}">바로 이동 →</a></div></body></html>`;
}
function build404Html(siteName,siteUrl){
  const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;');
  return`<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>404 — ${esc(siteName)}</title><style>body{font-family:-apple-system,sans-serif;background:#f1f1f1;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}.wrap{max-width:480px;padding:40px}h1{font-size:6rem;color:#2271b1;font-weight:900;line-height:1}a{display:inline-block;margin-top:20px;padding:10px 24px;background:#2271b1;color:#fff;border-radius:4px;text-decoration:none}</style></head><body><div class="wrap"><h1>404</h1><h2 style="margin:16px 0 10px">페이지를 찾을 수 없습니다</h2><p style="color:#6b7280;margin-bottom:24px">요청하신 페이지가 존재하지 않거나 이동되었습니다.</p><a href="${siteUrl}">홈으로 돌아가기</a></div></body></html>`;
}

/* ══ CMS D1 스키마 ══ */
function getCmsSchema(siteName,adminPw,projectName,adminLogin,adminEmail){
  const siteUrl=`https://${projectName}.pages.dev`;
  const q=s=>s.replace(/'/g,"''");
  const login=q(adminLogin||'admin');
  const email=q(adminEmail||`admin@${projectName}.pages.dev`);
  const pw=q(adminPw);
  const name=q(siteName);
  return[
    `CREATE TABLE IF NOT EXISTS wp_users (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT NOT NULL UNIQUE, user_pass TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL UNIQUE, url TEXT DEFAULT '', user_registered TEXT NOT NULL DEFAULT (datetime('now')), role TEXT NOT NULL DEFAULT 'subscriber', user_status INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, post_author INTEGER NOT NULL DEFAULT 1, post_date TEXT NOT NULL DEFAULT (datetime('now')), post_date_gmt TEXT NOT NULL DEFAULT (datetime('now')), post_content TEXT NOT NULL DEFAULT '', post_title TEXT NOT NULL DEFAULT '', post_excerpt TEXT NOT NULL DEFAULT '', post_status TEXT NOT NULL DEFAULT 'draft', comment_status TEXT NOT NULL DEFAULT 'open', ping_status TEXT NOT NULL DEFAULT 'open', post_name TEXT NOT NULL DEFAULT '', post_modified TEXT NOT NULL DEFAULT (datetime('now')), post_modified_gmt TEXT NOT NULL DEFAULT (datetime('now')), post_parent INTEGER NOT NULL DEFAULT 0, guid TEXT NOT NULL DEFAULT '', menu_order INTEGER NOT NULL DEFAULT 0, post_type TEXT NOT NULL DEFAULT 'post', featured_media INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_postmeta (meta_id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, meta_key TEXT NOT NULL DEFAULT '', meta_value TEXT DEFAULT NULL)`,
    `CREATE TABLE IF NOT EXISTS wp_options (option_id INTEGER PRIMARY KEY AUTOINCREMENT, option_name TEXT NOT NULL UNIQUE, option_value TEXT NOT NULL DEFAULT '', autoload TEXT NOT NULL DEFAULT 'yes')`,
    `CREATE TABLE IF NOT EXISTS wp_terms (term_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', slug TEXT NOT NULL UNIQUE DEFAULT '', term_group INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_term_taxonomy (term_taxonomy_id INTEGER PRIMARY KEY AUTOINCREMENT, term_id INTEGER NOT NULL, taxonomy TEXT NOT NULL DEFAULT '', description TEXT DEFAULT '', parent INTEGER DEFAULT 0, count INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_term_relationships (object_id INTEGER NOT NULL, term_taxonomy_id INTEGER NOT NULL, PRIMARY KEY (object_id, term_taxonomy_id))`,
    `CREATE TABLE IF NOT EXISTS wp_comments (comment_id INTEGER PRIMARY KEY AUTOINCREMENT, comment_post_id INTEGER NOT NULL DEFAULT 0, comment_author TEXT NOT NULL DEFAULT '', comment_author_email TEXT NOT NULL DEFAULT '', comment_content TEXT NOT NULL DEFAULT '', comment_date TEXT NOT NULL DEFAULT (datetime('now')), comment_approved TEXT NOT NULL DEFAULT '1', user_id INTEGER DEFAULT 0, comment_parent INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS wp_media (id INTEGER PRIMARY KEY AUTOINCREMENT, file_name TEXT NOT NULL, mime_type TEXT NOT NULL DEFAULT 'image/jpeg', file_size INTEGER DEFAULT 0, width INTEGER DEFAULT 0, height INTEGER DEFAULT 0, alt_text TEXT DEFAULT '', title TEXT DEFAULT '', url TEXT NOT NULL DEFAULT '', uploaded_by INTEGER DEFAULT 1, uploaded_at TEXT DEFAULT (datetime('now')))`,
    `INSERT OR IGNORE INTO wp_users (login,user_pass,display_name,email,role) VALUES ('${login}','${pw}','관리자','${email}','administrator')`,
    `INSERT OR IGNORE INTO wp_options (option_name,option_value) VALUES ('siteurl','${siteUrl}'),('blogname','${name}'),('blogdescription','${name} - CloudPress CMS'),('admin_email','${email}'),('posts_per_page','10'),('active_theme','default'),('template','default'),('stylesheet','default'),('cms_version','1.0.0'),('permalink_structure','/%year%/%monthnum%/%postname%/'),('timezone_string','Asia/Seoul'),('date_format','Y년 n월 j일'),('time_format','H:i'),('default_comment_status','open'),('show_on_front','posts'),('db_version','60621'),('initial_db_version','60621'),('blogcharset','UTF-8'),('blog_public','1'),('default_category','1'),('comment_moderation','0')`,
    `INSERT OR IGNORE INTO wp_posts (id,post_author,post_content,post_title,post_excerpt,post_status,post_name,post_type,guid) VALUES (1,1,'<p>${name}에 오신 것을 환영합니다! 이 글은 샘플 글입니다. CloudPress CMS는 워드프레스와 동일한 방식으로 글을 작성하고, 카테고리와 태그를 지정하며, 미디어를 업로드할 수 있습니다.</p>','안녕하세요! ${name}에 오신 것을 환영합니다','${name} - CloudPress CMS','publish','hello-world','post','${siteUrl}/?p=1'),(2,1,'<p>이것은 샘플 페이지입니다. 사이드바와는 달리 페이지는 고정된 위치에 있습니다.</p>','샘플 페이지','','publish','sample-page','page','${siteUrl}/?p=2')`,
    `INSERT OR IGNORE INTO wp_terms (term_id,name,slug) VALUES (1,'미분류','uncategorized')`,
    `INSERT OR IGNORE INTO wp_term_taxonomy (term_taxonomy_id,term_id,taxonomy,description,parent,count) VALUES (1,1,'category','',0,1)`,
    `INSERT OR IGNORE INTO wp_term_relationships (object_id,term_taxonomy_id) VALUES (1,1)`,
  ];
}

/* ══ 핵심: 사이트 프로비저닝 ══ */
async function provisionCmsSite(env,{siteId,siteName,projectName,cmsVersion,creds,adminLogin,adminEmail,adminPassword}){
  if(!creds)return{ok:false,error:'Cloudflare Global API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 등록해주세요.'};
  const{apiKey,email,accountId:rawAccountId}=creds;
  const logs=[];

  // ① 인증 확인
  logs.push('① Cloudflare API 인증 확인 중...');
  if(!apiKey||!email||!rawAccountId)return{ok:false,error:'Cloudflare API 인증 정보(키/이메일/AccountID)가 불완전합니다.',logs};
  const cfH={'X-Auth-Email':email,'X-Auth-Key':apiKey,'Content-Type':'application/json'};

  let accountId=rawAccountId;
  try{
    const verify=await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}`,{headers:cfH}).then(r=>r.json());
    if(!verify.success){
      const list=await fetch('https://api.cloudflare.com/client/v4/accounts?per_page=1',{headers:cfH}).then(r=>r.json());
      if(!list.success||!list.result?.length)
        return{ok:false,error:`Cloudflare 인증 오류: ${verify.errors?.[0]?.message||'알 수 없는 오류'}\n내 계정 → Cloudflare API 설정에서 API 키와 이메일을 다시 저장해주세요.`,logs};
      accountId=list.result[0].id;
      await env.DB.prepare('UPDATE users SET cf_account_id=? WHERE cf_account_email=?').bind(accountId,email).run().catch(()=>{});
      logs.push(`   ✓ Account ID 재설정: ${accountId}`);
    }else{
      logs.push(`   ✓ 인증 완료: ${verify.result?.name||accountId}`);
    }
  }catch(e){return{ok:false,error:`Cloudflare API 연결 실패: ${e.message}`,logs};}

  const cfAuth={apiKey,email,accountId};
  const vH={'X-Auth-Email':email,'X-Auth-Key':apiKey,'Content-Type':'application/json'};
  let kvNamespaceId=null,d1DatabaseId=null;

  try{
    // ② Pages 프로젝트 생성
    logs.push(`② Cloudflare Pages 프로젝트 생성 중... (${projectName})`);
    let currentProject=projectName;
    let pagesOk=false;
    for(let attempt=1;attempt<=3;attempt++){
      const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects`,{
        method:'POST',headers:vH,body:JSON.stringify({name:currentProject,production_branch:'main'})
      }).then(r=>r.json()).catch(e=>({success:false,errors:[{message:e.message}]}));

      if(r.success){logs.push(`   ✓ Pages 프로젝트 생성 완료 → https://${currentProject}.pages.dev`);pagesOk=true;break;}
      const msg=r.errors?.[0]?.message||'';
      const code=r.errors?.[0]?.code;
      if(msg.toLowerCase().includes('already exist')||msg.toLowerCase().includes('duplicate')||code===8000039){
        currentProject=generateProjectName(siteName);
        logs.push(`   ⚠ 프로젝트명 중복 → 재시도: ${currentProject}`);
        continue;
      }
      if(msg.toLowerCase().includes('auth')||code===10000||code===9109)
        return{ok:false,error:`Pages 인증 오류: ${msg}\nGlobal API 키를 다시 확인해주세요.`,logs};
      if(attempt<3){logs.push(`   ⚠ 시도 ${attempt} 실패(${msg}), 재시도...`);await new Promise(r=>setTimeout(r,2000*attempt));}
      else return{ok:false,error:`Pages 프로젝트 생성 실패: ${msg}`,logs};
    }
    if(!pagesOk)return{ok:false,error:'Pages 프로젝트 생성 실패',logs};

    if(currentProject!==projectName){
      projectName=currentProject;
      await env.DB.prepare('UPDATE sites SET subdomain=? WHERE id=?').bind(projectName,siteId).run().catch(()=>{});
    }
    const siteUrl=`https://${projectName}.pages.dev`;
    const adminUrl=`https://${projectName}.pages.dev/wp-admin/`;

    // ③ KV Namespace 생성
    logs.push('③ KV Namespace 생성 중...');
    const kvR=await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces`,{
      method:'POST',headers:vH,body:JSON.stringify({title:`cp-kv-${projectName}`})
    }).then(r=>r.json()).catch(()=>({}));
    if(kvR.success){kvNamespaceId=kvR.result?.id;logs.push(`   ✓ KV Namespace: ${kvNamespaceId}`);}
    else logs.push(`   ⚠ KV 생성 실패: ${kvR.errors?.[0]?.message||'unknown'} (계속 진행)`);

    // ④ D1 Database 생성
    logs.push('④ D1 데이터베이스 생성 중...');
    const d1R=await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database`,{
      method:'POST',headers:vH,body:JSON.stringify({name:`cp-db-${projectName}`})
    }).then(r=>r.json()).catch(()=>({}));
    if(d1R.result?.uuid){d1DatabaseId=d1R.result.uuid;logs.push(`   ✓ D1 Database: ${d1DatabaseId}`);}
    else logs.push(`   ⚠ D1 생성 실패: ${d1R.errors?.[0]?.message||'unknown'} (계속 진행)`);

    // ⑤ D1 스키마 초기화
    if(d1DatabaseId){
      logs.push('⑤ CMS 데이터베이스 스키마 초기화 중...');
      const schema=getCmsSchema(siteName,adminPassword,projectName,adminLogin,adminEmail);
      let schemaOk=true;
      for(const sql of schema){
        const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${d1DatabaseId}/query`,{
          method:'POST',headers:vH,body:JSON.stringify({sql})
        }).catch(()=>null);
        if(!r?.ok){schemaOk=false;const t=await r?.text().catch(()=>'');if(t)console.error('D1 SQL err:',t);}
      }
      logs.push(`   ${schemaOk?'✓':'⚠'} CMS 스키마 초기화 ${schemaOk?'완료':'일부 실패(계속 진행)'}`);
    }

    // ⑥ KV 설정 저장
    if(kvNamespaceId){
      logs.push('⑥ CMS 설정 KV 저장 중...');
      const config={site_id:siteId,site_name:siteName,site_url:siteUrl,admin_url:adminUrl,cms_version:cmsVersion||'1.0.0',created_at:new Date().toISOString(),theme:'default',settings:{title:siteName,tagline:`${siteName} - CloudPress CMS`,language:'ko_KR',timezone:'Asia/Seoul',posts_per_page:10}};
      await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${kvNamespaceId}/values/site_config`,{method:'PUT',headers:{...vH,'Content-Type':'text/plain'},body:JSON.stringify(config)}).catch(()=>{});
      await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${kvNamespaceId}/values/admin_info`,{method:'PUT',headers:{...vH,'Content-Type':'text/plain'},body:JSON.stringify({login:adminLogin,email:adminEmail,display_name:'관리자'})}).catch(()=>{});
      logs.push('   ✓ CMS 설정 저장 완료');
    }

    // ⑦ CMS 파일 배포 (ZIP or fallback)
    logs.push('⑦ CMS 사이트 파일 배포 중...');
    const deployResult=await deployCmsSite(env,{
      accountId,projectName,cfAuth,siteName,siteUrl,cmsVersion,
      kvNamespaceId,d1DatabaseId,adminLogin,adminEmail,logs,
    });
    if(!deployResult.ok)logs.push(`   ⚠ 배포 경고: ${deployResult.error}`);

    // ⑧ DB에 결과 저장 (단일 UPDATE — 중복 없음)
    await env.DB.prepare(
      `UPDATE sites SET status='active',cms_url=?,cms_admin_url=?,cms_username=?,cms_password=?,cf_kv_namespace=?,cf_d1_database=?,cf_pages_project=? WHERE id=?`
    ).bind(siteUrl,adminUrl,adminLogin,adminPassword,kvNamespaceId||null,d1DatabaseId||null,projectName,siteId).run();
    logs.push('✅ CloudPress CMS 구축 완료!');

    return{
      ok:true,
      cmsUrl:siteUrl,cmsAdminUrl:adminUrl,
      cmsUsername:adminLogin,cmsPassword:adminPassword,
      cfKvNamespace:kvNamespaceId,cfD1Database:d1DatabaseId,cfPagesProject:projectName,projectName,
      deployMode:deployResult.mode||'unknown',deployVersion:deployResult.version||null,
      logs,
    };
  }catch(e){
    console.error('provisionCmsSite error:',e);
    logs.push(`❌ 예상치 못한 오류: ${e?.message??e}`);
    await env.DB.prepare("UPDATE sites SET status='error' WHERE id=?").bind(siteId).run().catch(()=>{});
    return{ok:false,error:`CMS 구축 중 오류: ${e?.message??e}`,logs};
  }
}

export const onRequestOptions=()=>handleOptions();

export async function onRequestGet({request,env}){
  try{
    const user=await getUser(env,request);
    if(!user)return err('인증 필요',401);
    const{results}=await env.DB.prepare(
      'SELECT id,name,subdomain,custom_domain,cms_url,cms_admin_url,cms_username,cms_version,status,plan,created_at,cf_zone_id,cf_d1_database,cf_kv_namespace FROM sites WHERE user_id=? ORDER BY created_at DESC'
    ).bind(user.id).all();
    return ok({sites:results??[]});
  }catch(e){return err('사이트 목록 로딩 실패: '+(e?.message??e),500);}
}

/* ══ POST: 사이트 생성 — ctx.waitUntil로 진정한 백그라운드 처리 ══ */
export async function onRequestPost({request,env,ctx}){
  try{
    const user=await getUser(env,request);
    if(!user)return err('인증 필요',401);

    let body;
    try{body=await request.json();}catch{return err('잘못된 요청 형식');}

    const{name,cms_version,admin_login,admin_email,admin_password}=body||{};
    if(!name?.trim())return err('사이트 이름을 입력해주세요.');

    /* 어드민 정보 검증 */
    const adminLogin=(admin_login||'admin').trim().toLowerCase().replace(/[^a-z0-9_-]/g,'');
    if(adminLogin.length<3)return err('관리자 아이디는 영문/숫자/언더바/하이픈 3자 이상이어야 합니다.');
    if(admin_email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(admin_email))return err('올바른 이메일 형식이 아닙니다.');
    if(admin_password&&admin_password.length<8)return err('비밀번호는 8자 이상이어야 합니다.');
    const adminEmail=admin_email||`${adminLogin}@example.com`;
    const adminPassword=admin_password||genPw(16);

    /* 플랜 한도 확인 */
    const countRow=await env.DB.prepare("SELECT COUNT(*) cnt FROM sites WHERE user_id=? AND status NOT IN ('deleted','error')").bind(user.id).first();
    const siteCount=countRow?.cnt??0;
    const limit=await getSiteLimit(env,user.plan);
    if(siteCount>=limit)
      return err(`현재 플랜(${user.plan})에서 최대 ${limit===Infinity?'무제한':limit}개 사이트까지 가능합니다. 플랜을 업그레이드해주세요.`,403);

    /* CF 크레덴셜 확인 */
    const creds=await getUserCfCreds(env,user.id);
    if(!creds)return err('Cloudflare API 키가 설정되지 않았습니다. 내 계정 → Cloudflare API 설정에서 등록해주세요.',403);

    /* 중복 subdomain 방지 */
    let projectName=generateProjectName(name.trim());
    for(let i=0;i<5;i++){
      const dup=await env.DB.prepare('SELECT id FROM sites WHERE subdomain=?').bind(projectName).first();
      if(!dup)break;
      projectName=generateProjectName(name.trim());
    }

    const siteId=genId();
    await env.DB.prepare(
      `INSERT INTO sites (id,user_id,name,subdomain,status,plan,cms_version,cms_username,cms_password,created_at)
       VALUES (?,?,?,?,'provisioning',?,?,?,?,unixepoch())`
    ).bind(siteId,user.id,name.trim(),projectName,user.plan,cms_version||'1.0.0',adminLogin,adminPassword).run();

    /* ── 백그라운드 프로비저닝 ──
       ctx.waitUntil: Cloudflare Pages Functions에서 응답 반환 후에도 Promise 계속 실행
       ctx가 없는 환경(테스트 등)에서는 동기 실행으로 폴백 */
    const provisionJob=provisionCmsSite(env,{
      siteId,siteName:name.trim(),projectName,cmsVersion:cms_version||null,
      creds,adminLogin,adminEmail,adminPassword,
    });

    if(ctx?.waitUntil){
      /* 진정한 백그라운드: 응답 즉시 반환 */
      ctx.waitUntil(provisionJob.catch(e=>console.error('background provision failed:',e)));
      return ok({
        site:{id:siteId,name:name.trim(),subdomain:projectName,status:'provisioning',cms_username:adminLogin,cms_password:adminPassword,cms_version:cms_version||'1.0.0'},
        message:`${name.trim()} 사이트 구축을 시작했습니다. 완료까지 3~8분 소요됩니다.`,
        background:true,
        cms_password:adminPassword,
        site_url:`https://${projectName}.pages.dev`,
        admin_url:`https://${projectName}.pages.dev/wp-admin/`,
      });
    }else{
      /* 동기 실행 (ctx 없는 환경) */
      const result=await provisionJob;
      if(!result.ok)return err(result.error,500);
      const site=await env.DB.prepare('SELECT * FROM sites WHERE id=?').bind(siteId).first();
      return ok({
        site,
        message:`${name.trim()} 사이트가 ${result.cmsUrl}에 구축되었습니다.${result.deployVersion?` (CMS v${result.deployVersion})`:''}`,
        logs:result.logs,
        deploy_mode:result.deployMode,
        cms_password:adminPassword,
        background:false,
      });
    }
  }catch(e){
    console.error('sites POST error:',e);
    return err('사이트 생성 중 오류: '+(e?.message??e),500);
  }
}
