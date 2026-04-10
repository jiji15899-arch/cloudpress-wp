// functions/api/admin/vp-accounts.js
// VP 계정 관리 API + ZIP 파일 업로드 (R2 저장)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

const _j  = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', ...CORS }
});
const ok  = (d = {}) => _j({ ok: true,  ...d });
const err = (msg, s = 400) => _j({ ok: false, error: msg }, s);

async function requireAdmin(env, req) {
  try {
    const a = req.headers.get('Authorization') || '';
    const token = a.startsWith('Bearer ') ? a.slice(7) : null;
    if (!token) return null;
    const uid = await env.SESSIONS.get(`session:${token}`);
    if (!uid) return null;
    const user = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(uid).first();
    return user?.role === 'admin' ? user : null;
  } catch { return null; }
}

function genId() {
  return 'vp_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

// ─────────────────────────────────────────────
// POST /api/admin/vp-accounts/upload-zip
// multipart/form-data 로 ZIP 파일 수신 → R2 저장 → URL 반환
//
// ✅ Cloudflare Pages Functions 라우팅 규칙:
//   이 파일은 /api/admin/vp-accounts 를 처리합니다.
//   /upload-zip 서브 경로는 onRequestPost 에서 URL path로 분기합니다.
// ─────────────────────────────────────────────

// GET - VP 계정 목록 조회
export async function onRequestGet({ request, env }) {
  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  try {
    const { results } = await env.DB.prepare(
      `SELECT id, label, vp_username, panel_url, server_domain, web_root,
              php_bin, mysql_host, clone_zip_url, max_sites, current_sites,
              is_active, created_at, updated_at
       FROM vp_accounts
       ORDER BY created_at DESC`
    ).all();
    return ok({ accounts: results || [] });
  } catch (e) {
    return err('VP 계정 조회 실패: ' + e.message, 500);
  }
}

// POST - VP 계정 생성 OR ZIP 파일 업로드 (path로 분기)
export async function onRequestPost({ request, env }) {
  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  // ✅ /upload-zip 경로 분기
  const url = new URL(request.url);
  if (url.pathname.endsWith('/upload-zip')) {
    return handleZipUpload(request, env);
  }

  // ── 계정 생성 ──
  let body;
  try {
    body = await request.json();
  } catch {
    return err('요청 형식 오류');
  }

  const {
    label, vp_username, vp_password, panel_url, server_domain,
    web_root, php_bin, mysql_host, clone_zip_url, max_sites,
  } = body;

  if (!label?.trim())         return err('계정 레이블을 입력해주세요.');
  if (!vp_username?.trim())   return err('VP 사용자명을 입력해주세요.');
  if (!vp_password?.trim())   return err('VP 비밀번호를 입력해주세요.');
  if (!panel_url?.trim())     return err('패널 URL을 입력해주세요.');
  if (!server_domain?.trim()) return err('서버 도메인을 입력해주세요.');

  const vpId = genId();

  try {
    await env.DB.prepare(
      `INSERT INTO vp_accounts (
        id, label, vp_username, vp_password, panel_url, server_domain,
        web_root, php_bin, mysql_host, clone_zip_url, max_sites,
        current_sites, is_active, created_at, updated_at
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,1,datetime('now'),datetime('now'))`
    ).bind(
      vpId,
      label.trim(),
      vp_username.trim(),
      vp_password.trim(),
      panel_url.trim(),
      server_domain.trim(),
      web_root || '/htdocs',
      php_bin || 'php8.3',
      mysql_host || 'localhost',
      clone_zip_url || null,
      parseInt(max_sites, 10) || 50
    ).run();

    return ok({ message: 'VP 계정이 생성되었습니다.', accountId: vpId });
  } catch (e) {
    return err('VP 계정 생성 실패: ' + e.message, 500);
  }
}

// ✅ ZIP 업로드 핸들러
// R2 버킷 바인딩명: ZIP_BUCKET (wrangler.toml에 추가 필요)
// R2가 없는 경우 KV fallback (25MB 이하 파일만)
async function handleZipUpload(request, env) {
  let formData;
  try {
    formData = await request.formData();
  } catch (e) {
    return err('multipart 파싱 실패: ' + e.message);
  }

  const file = formData.get('file');
  if (!file || typeof file === 'string') return err('파일이 없습니다.');
  if (!file.name.toLowerCase().endsWith('.zip')) return err('ZIP 파일만 업로드할 수 있습니다.');

  const maxBytes = 500 * 1024 * 1024; // 500MB
  if (file.size > maxBytes) return err('파일 크기는 500MB를 초과할 수 없습니다.');

  // 파일명 정규화: 타임스탬프 + 원본명 (경로 순회 방지)
  const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
  const key = 'zip-templates/' + Date.now() + '_' + safeName;

  // ── R2 저장 시도 ──
  if (env.ZIP_BUCKET) {
    try {
      const arrayBuffer = await file.arrayBuffer();
      await env.ZIP_BUCKET.put(key, arrayBuffer, {
        httpMetadata: { contentType: 'application/zip' },
        customMetadata: { originalName: file.name, uploadedAt: new Date().toISOString() },
      });

      // R2 public URL — wrangler.toml에서 custom domain 설정 필요
      // 없으면 worker 경유 URL 반환
      const r2PublicBase = env.R2_PUBLIC_URL || '';
      const zipUrl = r2PublicBase
        ? r2PublicBase.replace(/\/$/, '') + '/' + key
        : '/api/admin/vp-accounts/zip-file?key=' + encodeURIComponent(key);

      return ok({ url: zipUrl, key, name: file.name, size: file.size });
    } catch (e) {
      return err('R2 업로드 실패: ' + e.message, 500);
    }
  }

  // ── R2 없음: KV fallback (25MB 이하) ──
  if (env.SESSIONS) {
    const kvLimit = 25 * 1024 * 1024;
    if (file.size > kvLimit) {
      return err(
        'R2 버킷이 설정되지 않았습니다. 25MB를 초과하는 파일은 wrangler.toml에 ZIP_BUCKET(R2)을 추가해야 합니다.' +
        ' 현재 파일 크기: ' + (file.size / 1024 / 1024).toFixed(1) + 'MB'
      );
    }
    try {
      const ab = await file.arrayBuffer();
      const b64 = btoa(String.fromCharCode(...new Uint8Array(ab)));
      const kvKey = 'zip:' + key;
      // KV TTL 없이 저장 (영구)
      await env.SESSIONS.put(kvKey, b64);
      const zipUrl = '/api/admin/vp-accounts/zip-file?key=' + encodeURIComponent(kvKey);
      return ok({ url: zipUrl, key: kvKey, name: file.name, size: file.size });
    } catch (e) {
      return err('KV 저장 실패: ' + e.message, 500);
    }
  }

  return err('스토리지가 설정되지 않았습니다. wrangler.toml에 ZIP_BUCKET(R2) 바인딩을 추가해주세요.');
}

// PUT - VP 계정 수정
export async function onRequestPut({ request, env }) {
  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return err('요청 형식 오류');
  }

  const {
    id, label, vp_username, vp_password, panel_url, server_domain,
    web_root, php_bin, mysql_host, clone_zip_url, max_sites, is_active,
  } = body;

  if (!id) return err('계정 ID가 필요합니다.');

  const existing = await env.DB.prepare(
    'SELECT id FROM vp_accounts WHERE id=?'
  ).bind(id).first();
  if (!existing) return err('존재하지 않는 VP 계정입니다.', 404);

  try {
    const updates = [];
    const values = [];

    if (label !== undefined)        { updates.push('label=?');         values.push(label.trim()); }
    if (vp_username !== undefined)  { updates.push('vp_username=?');   values.push(vp_username.trim()); }
    if (vp_password !== undefined)  { updates.push('vp_password=?');   values.push(vp_password.trim()); }
    if (panel_url !== undefined)    { updates.push('panel_url=?');     values.push(panel_url.trim()); }
    if (server_domain !== undefined){ updates.push('server_domain=?'); values.push(server_domain.trim()); }
    if (web_root !== undefined)     { updates.push('web_root=?');      values.push(web_root || '/htdocs'); }
    if (php_bin !== undefined)      { updates.push('php_bin=?');       values.push(php_bin || 'php8.3'); }
    if (mysql_host !== undefined)   { updates.push('mysql_host=?');    values.push(mysql_host || 'localhost'); }
    // ✅ clone_zip_url: null 허용 (제거 요청 처리)
    if (clone_zip_url !== undefined){ updates.push('clone_zip_url=?'); values.push(clone_zip_url || null); }
    if (max_sites !== undefined)    { updates.push('max_sites=?');     values.push(parseInt(max_sites, 10) || 50); }
    if (is_active !== undefined)    { updates.push('is_active=?');     values.push(is_active ? 1 : 0); }

    if (updates.length === 0) return ok({ message: '변경사항 없음' });

    updates.push("updated_at=datetime('now')");
    values.push(id);

    await env.DB.prepare(
      `UPDATE vp_accounts SET ${updates.join(', ')} WHERE id=?`
    ).bind(...values).run();

    return ok({ message: 'VP 계정이 수정되었습니다.' });
  } catch (e) {
    return err('VP 계정 수정 실패: ' + e.message, 500);
  }
}

// DELETE - VP 계정 삭제
export async function onRequestDelete({ request, env }) {
  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return err('계정 ID가 필요합니다.');

  try {
    const { results } = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM sites WHERE vp_account_id=? AND (status IS NULL OR status != 'deleted')"
    ).bind(id).all();

    const siteCount = results?.[0]?.count || 0;
    if (siteCount > 0) {
      return err(`이 VP 계정을 사용 중인 사이트가 ${siteCount}개 있습니다. 먼저 사이트를 삭제해주세요.`, 400);
    }

    await env.DB.prepare('DELETE FROM vp_accounts WHERE id=?').bind(id).run();
    return ok({ message: 'VP 계정이 삭제되었습니다.' });
  } catch (e) {
    return err('VP 계정 삭제 실패: ' + e.message, 500);
  }
}
