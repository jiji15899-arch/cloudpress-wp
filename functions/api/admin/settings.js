// functions/api/admin/settings.js
// 관리자 설정 + CMS 버전 관리

/* ── utils ── */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};
const _j=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const ok=(d={})=>_j({ok:true,...d});
const err=(msg,s=400)=>_j({ok:false,error:msg},s);
const handleOptions=()=>new Response(null,{status:204,headers:CORS});
function getToken(req){const a=req.headers.get('Authorization')||'';if(a.startsWith('Bearer '))return a.slice(7);const c=req.headers.get('Cookie')||'';const m=c.match(/cp_session=([^;]+)/);return m?m[1]:null;}
async function getUser(env,req){try{const t=getToken(req);if(!t)return null;const uid=await env.SESSIONS.get(`session:${t}`);if(!uid)return null;return await env.DB.prepare('SELECT id,name,email,role,plan FROM users WHERE id=?').bind(uid).first();}catch{return null;}}
async function requireAdmin(env,req){const u=await getUser(env,req);return(u&&u.role==='admin')?u:null;}
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2,9);}
/* ── end utils ── */

export const onRequestOptions = () => handleOptions();

export async function onRequestGet({ request, env }) {
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('어드민 권한 필요', 403);

    const { results } = await env.DB.prepare('SELECT key,value FROM settings').all();
    const cfg = Object.fromEntries((results || []).map(r => [r.key, r.value]));

    // CF API 설정 여부 (키 값은 노출 안 함)
    cfg.cf_api_configured = env.CF_API_TOKEN ? '1' : '0';

    // CMS 버전 목록
    const versionsResult = await env.DB.prepare(
      'SELECT id,version,label,description,is_stable,is_latest,release_notes,created_at FROM cms_versions ORDER BY created_at DESC'
    ).all().catch(() => ({ results: [] }));
    const versions = versionsResult.results || [];

    return ok({ settings: cfg, cms_versions: versions });
  } catch (e) {
    console.error('settings GET error:', e);
    return err('설정 로딩 실패: ' + (e?.message ?? e), 500);
  }
}

export async function onRequestPut({ request, env }) {
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return err('어드민 권한 필요', 403);

    let body;
    try { body = await request.json(); } catch(e) { return err('요청 파싱 실패: 파일이 너무 크거나 잘못된 형식입니다. (' + (e?.message||'JSON parse error') + ')'); }

    const { settings, action } = body || {};

    /* ── CMS 버전 추가 ── */
    if (action === 'add_cms_version') {
      const { version, label, description, is_stable, is_latest, release_notes } = body;
      if (!version || !label) return err('버전과 라벨을 입력해주세요.');
      if (!/^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/.test(version)) return err('버전 형식: 1.0.0 또는 1.0.0-beta');

      const dup = await env.DB.prepare('SELECT id FROM cms_versions WHERE version=?').bind(version).first();
      if (dup) return err('이미 존재하는 버전입니다.');

      const id = genId();
      // is_latest 설정 시 기존 latest 해제
      if (is_latest) {
        await env.DB.prepare('UPDATE cms_versions SET is_latest=0').run();
        await env.DB.prepare("UPDATE settings SET value=?,updated_at=unixepoch() WHERE key='cms_latest_version'")
          .bind(version).run();
      }

      await env.DB.prepare(
        'INSERT INTO cms_versions (id,version,label,description,is_stable,is_latest,release_notes,created_by) VALUES (?,?,?,?,?,?,?,?)'
      ).bind(id, version, label, description || '', is_stable ? 1 : 0, is_latest ? 1 : 0, release_notes || '', admin.id).run();

      return ok({ message: `CMS ${version} 버전이 추가되었습니다.` });
    }

    /* ── CMS 버전 삭제 ── */
    if (action === 'delete_cms_version') {
      const { version_id } = body;
      if (!version_id) return err('버전 ID를 입력해주세요.');
      const v = await env.DB.prepare('SELECT * FROM cms_versions WHERE id=?').bind(version_id).first();
      if (!v) return err('버전을 찾을 수 없습니다.');
      if (v.is_latest) return err('현재 최신 버전은 삭제할 수 없습니다. 다른 버전을 최신으로 설정 후 삭제하세요.');
      await env.DB.prepare('DELETE FROM cms_versions WHERE id=?').bind(version_id).run();
      return ok({ message: '버전이 삭제되었습니다.' });
    }

    /* ── CMS 버전 최신으로 설정 ── */
    if (action === 'set_latest_version') {
      const { version_id } = body;
      if (!version_id) return err('버전 ID를 입력해주세요.');
      const v = await env.DB.prepare('SELECT * FROM cms_versions WHERE id=?').bind(version_id).first();
      if (!v) return err('버전을 찾을 수 없습니다.');
      await env.DB.prepare('UPDATE cms_versions SET is_latest=0').run();
      await env.DB.prepare('UPDATE cms_versions SET is_latest=1 WHERE id=?').bind(version_id).run();
      await env.DB.prepare("UPDATE settings SET value=?,updated_at=unixepoch() WHERE key='cms_latest_version'")
        .bind(v.version).run();
      return ok({ message: `${v.version}이(가) 최신 버전으로 설정되었습니다.` });
    }

    /* ── CMS 패키지 ZIP 업로드 ── */
    if (action === 'upload_cms_package') {
      const { version, description, is_latest, is_stable, filename, filesize, data } = body;
      if (!version) return err('버전을 입력해주세요.');
      if (!data)    return err('파일 데이터가 없습니다. 파일을 다시 선택해주세요.');
      if (!/^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/.test(version)) return err('버전 형식: 1.0.0 또는 1.0.0-beta');
      if (filesize && filesize > 50 * 1024 * 1024) return err('파일 크기는 50MB 이하여야 합니다.');

      // 기존 버전 중복 체크
      const dup = await env.DB.prepare('SELECT id FROM cms_versions WHERE version=?').bind(version).first();

      if (is_latest) {
        await env.DB.prepare('UPDATE cms_versions SET is_latest=0').run();
        await env.DB.prepare("UPDATE settings SET value=?,updated_at=unixepoch() WHERE key='cms_latest_version'")
          .bind(version).run().catch(() => {});
      }

      if (dup) {
        await env.DB.prepare(
          'UPDATE cms_versions SET label=?,description=?,is_stable=?,is_latest=?,release_notes=? WHERE version=?'
        ).bind(
          `CloudPress CMS v${version}`,
          description || filename || `CMS 패키지 v${version}`,
          is_stable ? 1 : 0,
          is_latest ? 1 : 0,
          `파일: ${filename||''}, 크기: ${filesize ? Math.round(filesize/1024)+'KB' : ''}`,
          version
        ).run();
      } else {
        const id = genId();
        await env.DB.prepare(
          'INSERT INTO cms_versions (id,version,label,description,is_stable,is_latest,release_notes,created_by) VALUES (?,?,?,?,?,?,?,?)'
        ).bind(
          id, version,
          `CloudPress CMS v${version}`,
          description || filename || `CMS 패키지 v${version}`,
          is_stable ? 1 : 0,
          is_latest ? 1 : 0,
          `파일: ${filename||''}, 크기: ${filesize ? Math.round(filesize/1024)+'KB' : ''}`,
          admin.id
        ).run();
      }

      // KV에 ZIP base64 저장 (사이트 구축 시 사용)
      if (env.SESSIONS && data) {
        try {
          await env.SESSIONS.put(`cms_package:${version}`, data, {
            metadata: {
              filename: filename || '',
              filesize: filesize || 0,
              version,
              description: description || '',
              uploaded_at: Date.now()
            }
          });
        } catch(e) {
          console.error('KV cms_package 저장 실패:', e);
          // KV 저장 실패해도 DB 등록은 성공 처리
        }
      }

      // cms_packages 테이블에 메타 기록 (없으면 무시 — schema 미적용 환경 대비)
      try {
        const pkgId = genId();
        await env.DB.prepare(
          `INSERT INTO cms_packages (id,version,filename,filesize,description,is_latest,is_stable,uploaded_by,uploaded_at)
           VALUES (?,?,?,?,?,?,?,?,unixepoch())
           ON CONFLICT(version) DO UPDATE SET
             filename=excluded.filename, filesize=excluded.filesize,
             description=excluded.description, is_latest=excluded.is_latest,
             is_stable=excluded.is_stable, uploaded_by=excluded.uploaded_by,
             uploaded_at=unixepoch()`
        ).bind(
          pkgId, version,
          filename || `cloudpress-cms-v${version}.zip`,
          filesize || 0,
          description || '',
          is_latest ? 1 : 0,
          is_stable ? 1 : 0,
          admin.id
        ).run();
        if (is_latest) {
          await env.DB.prepare('UPDATE cms_packages SET is_latest=0 WHERE version!=?').bind(version).run();
        }
      } catch(e) {
        // cms_packages 테이블 없으면 무시 (cms_versions에 이미 저장됨)
        console.warn('cms_packages 테이블 저장 실패 (무시):', e?.message);
      }

      return ok({ message: `CMS v${version} 패키지가 ${dup ? '업데이트' : '등록'}되었습니다.` });
    }

    /* ── 일반 설정 저장 ── */
    if (!settings || typeof settings !== 'object') return err('잘못된 요청');

    const now = Math.floor(Date.now() / 1000);
    const ALLOWED_KEYS = [
      'plan_starter_price', 'plan_pro_price', 'plan_enterprise_price',
      'plan_starter_sites', 'plan_pro_sites', 'plan_enterprise_sites',
      'site_domain', 'toss_client_key', 'toss_secret_key',
      'contact_email', 'cms_latest_version',
    ];

    for (const [key, value] of Object.entries(settings)) {
      if (!ALLOWED_KEYS.includes(key)) continue;
      await env.DB.prepare(
        'INSERT INTO settings (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=?,updated_at=?'
      ).bind(key, String(value), now, String(value), now).run();
    }
    return ok({ message: '설정 저장 완료' });
  } catch (e) {
    console.error('settings PUT error:', e);
    return err('설정 저장 실패: ' + (e?.message ?? e), 500);
  }
}
