// functions/api/admin/cms-packages.js
// CMS 패키지 목록 조회 (관리자 전용)

const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAdmin(env,req){const u=await getUser(env,req);return(u&&u.role==='admin')?u:null;}

export const onRequestOptions=()=>handleOptions();

export async function onRequestGet({request,env}){
  try{
    const admin=await requireAdmin(env,request);
    if(!admin)return err('어드민 권한 필요',403);

    // cms_packages 테이블 우선 조회 (없으면 cms_versions로 폴백)
    let packages=[];
    try{
      const {results}=await env.DB.prepare(
        `SELECT p.id, p.version, p.filename, p.filesize, p.description,
                p.is_latest, p.is_stable, p.uploaded_at as created_at,
                v.label, v.release_notes
         FROM cms_packages p
         LEFT JOIN cms_versions v ON v.version=p.version
         ORDER BY p.uploaded_at DESC`
      ).all();
      packages=results||[];
    }catch(e){
      // cms_packages 테이블 없으면 cms_versions 사용
      const {results}=await env.DB.prepare(
        'SELECT id,version,label,description,is_stable,is_latest,release_notes,created_at FROM cms_versions ORDER BY created_at DESC'
      ).all().catch(()=>({results:[]}));
      packages=(results||[]).map(v=>({
        id:v.id, version:v.version,
        filename:`cloudpress-cms-v${v.version}.zip`,
        filesize:0, description:v.description,
        is_latest:v.is_latest, is_stable:v.is_stable,
        created_at:v.created_at, label:v.label,
      }));
    }

    // KV 메타데이터로 filesize 보강 (cms_packages에 저장 안 된 경우)
    for(const p of packages){
      if(!p.filesize && env.SESSIONS){
        try{
          const kv=await env.SESSIONS.getWithMetadata(`cms_package:${p.version}`);
          if(kv?.metadata?.filesize) p.filesize=kv.metadata.filesize;
          if(kv?.metadata?.filename && !p.filename) p.filename=kv.metadata.filename;
        }catch(e){}
      }
    }

    // 최신 패키지 기준 배포 구조 문자열
    const latest=packages.find(p=>p.is_latest)||packages[0];
    const ver=latest?latest.version:'1.0.0';
    const deploy_structure=`cloudpress-cms-v${ver}/
├── index.html              ← 메인 홈 (워드프레스 홈과 동일)
├── wp-admin/
│   ├── index.html          ← CMS 관리자 대시보드
│   ├── post-new.html       ← 글 작성 (블록 에디터)
│   ├── edit.html           ← 글/페이지 목록
│   ├── themes.html         ← 테마 관리
│   └── plugins.html        ← 플러그인 관리
├── wp-content/
│   ├── themes/default/     ← 기본 테마 (Twenty-style)
│   └── plugins/            ← 플러그인
├── functions/
│   └── api/
│       ├── wp-json/wp/v2/  ← REST API (WP 완전 호환)
│       │   ├── posts.js
│       │   ├── pages.js
│       │   ├── users.js
│       │   ├── categories.js
│       │   └── settings.js
│       └── wp-login/       ← 인증
├── 404.html
├── _headers
└── _redirects`;

    return ok({packages,deploy_structure});
  }catch(e){
    console.error('cms-packages GET error:',e);
    return err('패키지 목록 로딩 실패: '+(e?.message??e),500);
  }
}
