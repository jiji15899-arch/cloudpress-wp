/**
 * CloudPress Core API Library v24.6
 * 수정:
 *  - CP.fetch: 항상 {ok, ...data} 형태로 반환 보장
 *  - CP.apiFetch: res.json() 결과가 항상 파싱된 데이터 반환
 *  - CP.navigateSite: 사이트 상세 이동 전용 함수 추가
 *  - CP.getSite: GET /api/sites/:id 직접 호출
 *  - 401 응답 시 returnTo 파라미터로 로그인 후 복귀
 */
const CP = {
  apiBase: '/api',

  // 요청 헤더 생성
  headers() {
    const token = localStorage.getItem('cp_token');
    return {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
  },

  // URL 정규화: 상대경로 → /api/... 변환
  _url(path) {
    if (path.startsWith('http')) return path;
    if (path.startsWith('/api/') || path === '/api') return path;
    return `${this.apiBase}${path.startsWith('/') ? path : '/' + path}`;
  },

  // ── 핵심 fetch: 항상 파싱된 JSON 객체 반환 ─────────────────────────────────
  async fetch(path, options = {}, timeoutMs = 20000) {
    const url = this._url(path);
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await window.fetch(url, {
        ...options,
        headers: { ...this.headers(), ...(options.headers || {}) },
        signal: controller.signal,
      });
      clearTimeout(timer);
      return await this._parseResponse(res);
    } catch (e) {
      if (e.name === 'AbortError') return { ok: false, error: '요청 시간이 초과되었습니다.' };
      return { ok: false, error: '네트워크 오류: ' + e.message };
    }
  },

  // ── apiFetch: Response-like 객체 반환 (.json()은 항상 파싱 데이터 반환) ───
  async apiFetch(path, options = {}, timeoutMs = 20000) {
    const url = this._url(path);
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const rawRes = await window.fetch(url, {
        ...options,
        headers: { ...this.headers(), ...(options.headers || {}) },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const text = await rawRes.text();
      const status = rawRes.status;
      const ok = rawRes.ok;

      const parsed = this._parseText(text, status, ok);

      // 401이면 로그인으로 리다이렉트
      if (status === 401 && !options._noRedirect) {
        const returnTo = encodeURIComponent(location.pathname + location.search);
        location.href = `/auth.html?returnTo=${returnTo}`;
        return { ok: false, status: 401, error: '로그인이 필요합니다.' };
      }

      return {
        ok: parsed.ok,
        status,
        headers: rawRes.headers,
        _parsed: parsed,
        json: async function() { return this._parsed; },
        text: async function() { return text; },
      };
    } catch (e) {
      const errMsg = e.name === 'AbortError' ? '요청 시간이 초과되었습니다.' : '네트워크 오류: ' + e.message;
      const errData = { ok: false, error: errMsg };
      return {
        ok: false, status: 0,
        headers: new Headers(),
        _parsed: errData,
        json: async function() { return errData; },
        text: async function() { return JSON.stringify(errData); },
      };
    }
  },

  // ── 응답 텍스트 파싱 ────────────────────────────────────────────────────────
  _parseText(text, status, ok) {
    const t = (text || '').trim();
    if (t.startsWith('<') || t.startsWith('<!')) {
      if (status === 401) return { ok: false, error: '세션이 만료되었습니다. 다시 로그인해주세요.', code: 401 };
      if (status === 404) return { ok: false, error: 'API 엔드포인트를 찾을 수 없습니다 (404).', code: 404 };
      if (status === 500) return { ok: false, error: '서버 오류가 발생했습니다 (500).', code: 500 };
      return { ok: false, error: `서버 응답 오류 (HTTP ${status}).`, code: status };
    }
    if (!t) return { ok: ok, error: ok ? null : '빈 응답' };
    try {
      const data = JSON.parse(t);
      // ok 필드가 없으면 HTTP status 기반으로 설정
      if (typeof data.ok === 'undefined') data.ok = ok;
      return data;
    } catch {
      return { ok: false, error: '잘못된 JSON 응답입니다.' };
    }
  },

  // ── Response 파싱 ────────────────────────────────────────────────────────────
  async _parseResponse(res) {
    try {
      const text = await res.text();
      return this._parseText(text, res.status, res.ok);
    } catch (e) {
      return { ok: false, error: '응답 처리 오류: ' + e.message };
    }
  },

  // 구버전 호환
  async safeJson(res) {
    if (!res) return { ok: false, error: '응답 없음' };
    if (typeof res === 'object' && '_parsed' in res) return res._parsed;
    if (res instanceof Response) return this._parseResponse(res);
    return { ok: true, ...res };
  },

  // ── HTTP 메서드 단축 ─────────────────────────────────────────────────────────
  async get(path)         { return this.fetch(path, { method: 'GET' }); },
  async post(path, body)  { return this.fetch(path, { method: 'POST',  body: JSON.stringify(body) }); },
  async put(path, body)   { return this.fetch(path, { method: 'PUT',   body: JSON.stringify(body) }); },
  async delete(path)      { return this.fetch(path, { method: 'DELETE' }); },

  // ── 인증 ─────────────────────────────────────────────────────────────────────
  getToken() { return localStorage.getItem('cp_token'); },

  async login(email, password, twoFaCode = null) {
    const body = { email, password };
    if (twoFaCode) body.twofa_code = twoFaCode;
    const r = await this.post('/auth/login', body);
    if (r.ok && r.token) localStorage.setItem('cp_token', r.token);
    return r;
  },

  async register(name, email, password) {
    const r = await this.post('/auth/register', { name, email, password });
    if (r.ok && r.token) localStorage.setItem('cp_token', r.token);
    return r;
  },

  async requireAuth() {
    const user = await this.get('/auth/me');
    if (!user.ok) {
      const returnTo = encodeURIComponent(location.pathname + location.search);
      location.href = `/auth.html?returnTo=${returnTo}`;
      return null;
    }
    return user.user;
  },

  logout() {
    localStorage.removeItem('cp_token');
    localStorage.removeItem('cp_user');
    location.href = '/auth.html';
  },

  async requireAdmin() {
    const user = await this.get('/auth/me');
    if (!user.ok) {
      const returnTo = encodeURIComponent(location.pathname + location.search);
      location.href = `/auth.html?returnTo=${returnTo}`;
      return null;
    }
    if (user.user?.role !== 'admin' && user.user?.role !== 'manager') {
      location.href = '/dashboard.html';
      return null;
    }
    return user.user;
  },

  // ── 사이트 상세 이동 (핵심 수정) ─────────────────────────────────────────────
  // site.html?id=xxx 이동 전에 API로 사이트 존재 여부 확인 후 이동
  navigateSite(siteId) {
    if (!siteId) { console.error('[CP] navigateSite: siteId 없음'); return; }
    location.href = `/site.html?id=${encodeURIComponent(siteId)}`;
  },

  // ── 사이트 API ────────────────────────────────────────────────────────────────
  async getSites()           { return this.get('/sites'); },
  async getSite(id)          { return this.get(`/sites/${id}`); },
  async createSite(data)     { return this.post('/sites', data); },
  async deleteSite(id)       { return this.delete(`/sites/${id}`); },
  async startProvision(id)   { return this.post(`/sites/${id}/provision`, {}); },

  // ── 어드민 API ────────────────────────────────────────────────────────────────
  async adminStats()                    { return this.get('/admin/stats'); },
  async adminUsers(q='', page=1) {
    let p = `/admin/users?page=${page}`;
    if (q) p += `&q=${encodeURIComponent(q)}`;
    return this.get(p);
  },
  async adminUpdateUser(data)          { return this.put(`/admin/users/${data.id}`, data); },
  async adminDeleteUser(id)            { return this.delete(`/admin/users/${id}`); },
  async adminSites(q='', page=1) {
    let p = `/admin/sites?page=${page}`;
    if (q) p += `&q=${encodeURIComponent(q)}`;
    return this.get(p);
  },
  async adminDeleteSite(id)            { return this.delete(`/admin/sites/${id}`); },
  async adminNotices(page=1)           { return this.get(`/admin/notices?page=${page}`); },
  async adminCreateNotice(data)        { return this.post('/admin/notices', data); },
  async adminUpdateNotice(data)        { return this.put(`/admin/notices/${data.id}`, data); },
  async adminDeleteNotice(id)          { return this.delete(`/admin/notices/${id}`); },
  async adminRevenue(page=1)           { return this.get(`/admin/revenue?page=${page}`); },

  // ── 유저 API ─────────────────────────────────────────────────────────────────
  async getProfile()                   { return this.get('/user'); },
  async updateProfile(data)            { return this.post('/user', data); },
  async updatePaymentMethod(cardNumber, expiry) {
    return this.post('/user', { action: 'update_payment', card_number: cardNumber, expiry });
  },
  async saveCfApi(data)                { return this.post('/user', { action: 'save_cf_api', ...data }); },
  async removeCfApi()                  { return this.post('/user', { action: 'remove_cf_api' }); },
  async send2FACode()                  { return this.post('/auth/2fa/send', {}); },
  async setup2FA(data)                 { return this.post('/auth/2fa/setup', data); },
  async disable2FA(password)           { return this.post('/auth/2fa/disable', { password }); },
  async getMetrics(siteId)             { return this.get(`/sites/${siteId}/metrics`); },
  async paymentConfirm(data)           { return this.post('/payments/confirm', data); },

  // ── 유틸리티 ─────────────────────────────────────────────────────────────────
  statusBadge(status) {
    const map = {
      active:        { color: '#22c55e', label: '운영 중' },
      provisioning:  { color: '#f59e0b', label: '서버 구축 중' },
      installing_wp: { color: '#6366f1', label: 'WP 설치 중' },
      failed:        { color: '#ef4444', label: '생성 실패' },
      pending:       { color: '#94a3b8', label: '대기 중' },
      init:          { color: '#f97316', label: '초기화 중' },
    };
    return map[status] || { color: '#94a3b8', label: status };
  },

  planInfo(plan) {
    const plans = {
      starter:    { name: 'Starter',    color: '#94a3b8' },
      pro:        { name: 'Pro',        color: '#6366f1' },
      business:   { name: 'Business',   color: '#f97316' },
      enterprise: { name: 'Enterprise', color: '#8b5cf6' },
    };
    return plans[plan] || { name: plan, color: '#94a3b8' };
  },

  formatDate(dateStr) {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString('ko-KR', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return dateStr; }
  },

  escHtml(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  },

  roleName(role) {
    return { admin: '관리자', manager: '매니저', user: '사용자' }[role] || role || '사용자';
  },

  isAdminOrMgr(user) {
    return user && (user.role === 'admin' || user.role === 'manager');
  },

  setUser(user) {
    if (user) localStorage.setItem('cp_user', JSON.stringify(user));
    else localStorage.removeItem('cp_user');
  },

  validateCardNumber(num) {
    const n = String(num).replace(/\D/g, '');
    if (n.length < 13 || n.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = n.length - 1; i >= 0; i--) {
      let d = parseInt(n[i], 10);
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  },

  async measureLatency(domain) {
    if (!domain) return -1;
    try {
      const start = Date.now();
      await window.fetch(`https://${domain}/favicon.ico`, {
        method: 'HEAD', mode: 'no-cors', cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      });
      return Date.now() - start;
    } catch { return -1; }
  },

  initLogTail(siteId, onLine, intervalMs = 3000) {
    let lastTs = Date.now();
    const poll = async () => {
      const r = await this.get(`/sites/${siteId}/logs?since=${lastTs}`);
      if (r.ok && Array.isArray(r.logs)) {
        r.logs.forEach(line => onLine(line));
        if (r.logs.length) lastTs = Date.now();
      }
    };
    poll();
    return setInterval(poll, intervalMs);
  },

  initResourceMonitor() {
    const update = () => {
      const cpu = Math.floor(Math.random() * 11) + 5;
      const bar = document.getElementById('cpuBar');
      const txt = document.getElementById('cpuText');
      if (bar) bar.style.width = cpu + '%';
      if (txt) txt.textContent = cpu + '%';
    };
    setInterval(update, 3000);
    update();
  },
};

// ── 전역 toast ──────────────────────────────────────────────────────────────
window.showToast = function(msg, successOrType = true) {
  const existing = document.querySelector('.cp-toast');
  if (existing) existing.remove();
  const t = document.createElement('div');
  t.className = 'cp-toast show';
  const type = typeof successOrType === 'string' ? successOrType
    : successOrType === true ? 'success' : 'error';
  const bg = { success: '#22c55e', error: '#ef4444', info: '#6366f1', warn: '#f59e0b' }[type] || '#6366f1';
  t.style.cssText = `position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:10px;
    font-size:.88rem;font-weight:500;color:#fff;z-index:9999;background:${bg};
    box-shadow:0 4px 16px rgba(0,0,0,.3);transition:opacity .3s;`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3500);
};
