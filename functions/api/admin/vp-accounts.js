// functions/api/admin/vp-accounts.js
// VP 계정 관리 API — clone_zip_url 은 GitHub Raw URL 직접 입력

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

// GET — VP 계정 목록
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

// POST — VP 계정 생성
export async function onRequestPost({ request, env }) {
  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  const { label, vp_username, vp_password, panel_url, server_domain,
          web_root, php_bin, mysql_host, clone_zip_url, max_sites } = body;

  if (!label?.trim())         return err('계정 레이블을 입력해주세요.');
  if (!vp_username?.trim())   return err('VP 사용자명을 입력해주세요.');
  if (!vp_password?.trim())   return err('VP 비밀번호를 입력해주세요.');
  if (!panel_url?.trim())     return err('패널 URL을 입력해주세요.');
  if (!server_domain?.trim()) return err('서버 도메인을 입력해주세요.');
  if (!clone_zip_url?.trim()) return err('복제 압축 파일 URL을 입력해주세요.');

  // GitHub Raw URL 형식 검증 (.zip / .7z 지원)
  const zipUrl = clone_zip_url.trim();
  if (!zipUrl.startsWith('http://') && !zipUrl.startsWith('https://')) {
    return err('올바른 URL 형식이 아닙니다. (https://... 로 시작해야 합니다)');
  }
  if (!/\.(zip|7z)(\?.*)?$/i.test(zipUrl)) {
    return err('지원하지 않는 파일 형식입니다. (.zip 또는 .7z 파일 URL을 입력해주세요)');
  }

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
      web_root?.trim() || '/htdocs',
      php_bin?.trim() || 'php8.3',
      mysql_host?.trim() || 'localhost',
      zipUrl,
      parseInt(max_sites, 10) || 50
    ).run();

    return ok({ message: 'VP 계정이 생성되었습니다.', accountId: vpId });
  } catch (e) {
    return err('VP 계정 생성 실패: ' + e.message, 500);
  }
}

// PUT — VP 계정 수정
export async function onRequestPut({ request, env }) {
  const admin = await requireAdmin(env, request);
  if (!admin) return err('관리자 권한이 필요합니다.', 403);

  let body;
  try { body = await request.json(); } catch { return err('요청 형식 오류'); }

  const { id, label, vp_username, vp_password, panel_url, server_domain,
          web_root, php_bin, mysql_host, clone_zip_url, max_sites, is_active } = body;

  if (!id) return err('계정 ID가 필요합니다.');

  const existing = await env.DB.prepare('SELECT id FROM vp_accounts WHERE id=?').bind(id).first();
  if (!existing) return err('존재하지 않는 VP 계정입니다.', 404);

  // clone_zip_url URL 형식 검증 (.zip / .7z 지원)
  if (clone_zip_url !== undefined && clone_zip_url !== null && clone_zip_url.trim()) {
    const zipUrl = clone_zip_url.trim();
    if (!zipUrl.startsWith('http://') && !zipUrl.startsWith('https://')) {
      return err('올바른 URL 형식이 아닙니다. (https://... 로 시작해야 합니다)');
    }
    if (!/\.(zip|7z)(\?.*)?$/i.test(zipUrl)) {
      return err('지원하지 않는 파일 형식입니다. (.zip 또는 .7z 파일 URL을 입력해주세요)');
    }
  }

  try {
    const updates = [];
    const values = [];

    if (label !== undefined)        { updates.push('label=?');         values.push(label.trim()); }
    if (vp_username !== undefined)  { updates.push('vp_username=?');   values.push(vp_username.trim()); }
    if (vp_password !== undefined && vp_password.trim()) {
                                      updates.push('vp_password=?');   values.push(vp_password.trim()); }
    if (panel_url !== undefined)    { updates.push('panel_url=?');     values.push(panel_url.trim()); }
    if (server_domain !== undefined){ updates.push('server_domain=?'); values.push(server_domain.trim()); }
    if (web_root !== undefined)     { updates.push('web_root=?');      values.push(web_root?.trim() || '/htdocs'); }
    if (php_bin !== undefined)      { updates.push('php_bin=?');       values.push(php_bin?.trim() || 'php8.3'); }
    if (mysql_host !== undefined)   { updates.push('mysql_host=?');    values.push(mysql_host?.trim() || 'localhost'); }
    if (clone_zip_url !== undefined){ updates.push('clone_zip_url=?'); values.push(clone_zip_url?.trim() || null); }
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

// DELETE — VP 계정 삭제
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
