/* CloudPress CMS app.js v20.1 — 캐시 버스팅 적용 */
'use strict';

window.CP = window.CP || {};
const CP = window.CP;

Object.assign(CP, {
  TOKEN_KEY: 'cp_token',
  USER_KEY:  'cp_user',

  setToken(token) { if (token) localStorage.setItem(this.TOKEN_KEY, token); },
  getToken() { return localStorage.getItem(this.TOKEN_KEY); },
  clearAuth() { localStorage.removeItem(this.TOKEN_KEY); localStorage.removeItem(this.USER_KEY); },
  setUser(user) { localStorage.setItem(this.USER_KEY, JSON.stringify(user)); },
  getUser() { try { return JSON.parse(localStorage.getItem(this.USER_KEY) || 'null'); } catch { return null; } },

  async apiFetch(path, opts = {}) {
    const token = this.getToken();
    let url = path;
    if (!url.startsWith('http')) {
      url = url.startsWith('/api/') ? url : '/api' + (url.startsWith('/') ? '' : '/') + url;
    }
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(opts.headers || {}),
    };
    const res = await fetch(url, { ...opts, headers });
    if (res.status === 401 && !this._isAuthPage()) {
      this.clearAuth();
      this._redirectToLogin();
    }
    return res;
  },

  async api(path, opts = {}) {
    let res;
    try { res = await this.apiFetch(path, opts); } catch (e) {
      return { ok: false, error: '네트워크 오류: ' + e.message };
    }
    let data;
    try { data = await res.json(); } catch {
      return { ok: false, error: '서버 응답 오류 (status=' + res.status + ')' };
    }
    if (!res.ok && data.ok !== false) data.ok = false;
    return data;
  },

  get:  (p)    => CP.api(p, { method: 'GET' }),
  post: (p, b) => CP.api(p, { method: 'POST',   body: JSON.stringify(b ?? {}) }),
  put:  (p, b) => CP.api(p, { method: 'PUT',    body: JSON.stringify(b ?? {}) }),
  del:  (p, b) => CP.api(p, { method: 'DELETE', body: JSON.stringify(b ?? {}) }),

  async login(email, password, twofaCode) {
    const r = await this.post('/auth/login', { email, password, twofa_code: twofaCode });
    if (r.ok && r.token) { this.setToken(r.token); if (r.user) this.setUser(r.user); }
    return r;
  },
  async register(name, email, password) {
    const r = await this.post('/auth/register', { name, email, password });
    if (r.ok && r.token) { this.setToken(r.token); if (r.user) this.setUser(r.user); }
    return r;
  },
  async logout() {
    await this.post('/auth/logout', {});
    this.clearAuth();
    window.location.href = '/';
  },

  async requireAuth() {
    const d = await this.get('/auth/me');
    if (!d.ok) { this._redirectToLogin(); return null; }
    if (d.user) this.setUser(d.user);
    return d.user;
  },

  async requireAdmin() {
    const user = await this.requireAuth();
    if (!user) return null;
    if (user.role !== 'admin' && user.role !== 'manager') {
      window.location.href = '/dashboard.html';
      return null;
    }
    return user;
  },

  isAdminOrMgr(user) {
    return user && (user.role === 'admin' || user.role === 'manager');
  },

  async getSites()         { return this.get('/api/sites'); },
  async getSite(id)        { return this.get('/api/sites/' + id); },
  async createSite(b)      { return this.post('/api/sites', b); },
  async deleteSite(id)     { return this.del('/api/sites/' + id); },
  async startProvision(id) { return this.post('/api/sites/' + id + '/provision', {}); },
  async getMetrics(id)     { return this.get('/api/sites/' + id + '/metrics'); },

  async getProfile()           { return this.get('/api/user'); },
  async updateProfile(b)       { return this.put('/api/user', b); },
  async saveCfApi(b)           { return this.put('/api/user', { action: 'save_cf_api', ...b }); },
  async removeCfApi()          { return this.put('/api/user', { action: 'remove_cf_api' }); },
  async updatePaymentMethod(b) { return this.post('/api/payments/checkout', b); },
  async paymentConfirm(b)      { return this.post('/api/payments/confirm', b); },

  async adminStats()             { return this.get('/api/admin/stats'); },
  async adminSites(q, page)      { return this.get('/api/admin/sites' + _qs({ q, page })); },
  async adminUsers(q, page)      { return this.get('/api/admin/users' + _qs({ q, page })); },
  async adminRevenue(page)       { return this.get('/api/admin/revenue' + _qs({ page })); },
  async adminNotices()           { return this.get('/api/admin/notices'); },
  async adminCreateNotice(b)     { return this.post('/api/admin/notices', b); },
  async adminUpdateNotice(id, b) { return this.put('/api/admin/notices', { id, ...b }); },
  async adminDeleteNotice(id)    { return this.del('/api/admin/notices', { id }); },
  async adminUpdateUser(b)       { return this.put('/api/admin/users', b); },
  async adminDeleteUser(id)      { return this.del('/api/admin/users', { id }); },
  async adminDeleteSite(id)      { return this.del('/api/admin/sites', { id }); },

  escHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  },

  formatDate(str) {
    if (!str) return '—';
    try {
      const d = new Date(str);
      return d.toLocaleDateString('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit' });
    } catch { return str; }
  },

  statusBadge(status) {
    const map = {
      active:        { label: '운영중',   color: '#22c55e' },
      pending:       { label: '대기중',   color: '#eab308' },
      provisioning:  { label: '생성중',   color: '#6366f1' },
      installing_wp: { label: 'WP설치중', color: '#6366f1' },
      init:          { label: '초기화중', color: '#6366f1' },
      starting:      { label: '시작중',   color: '#6366f1' },
      failed:        { label: '실패',     color: '#ef4444' },
      error:         { label: '오류',     color: '#ef4444' },
      suspended:     { label: '정지됨',   color: '#f97316' },
      deleted:       { label: '삭제됨',   color: '#6b7280' },
    };
    return map[status] || { label: status || '알 수 없음', color: '#6b7280' };
  },

  planInfo(plan) {
    const map = {
      free:       { name: '무료',          color: '#6b7280' },
      starter:    { name: '스타터',        color: '#6366f1' },
      pro:        { name: '프로',          color: '#f97316' },
      enterprise: { name: '엔터프라이즈',  color: '#ec4899' },
    };
    return map[plan] || { name: plan || '알 수 없음', color: '#6b7280' };
  },

  roleName(role) {
    const map = { admin: '관리자', manager: '매니저', user: '일반 사용자' };
    return map[role] || role || '알 수 없음';
  },

  validateCardNumber(num) {
    const n = String(num).replace(/\D/g, '');
    if (n.length < 13 || n.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = n.length - 1; i >= 0; i--) {
      let d = parseInt(n[i]);
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d; alt = !alt;
    }
    return sum % 10 === 0;
  },

  disable(btnId, loading = true) {
    const b = document.getElementById(btnId);
    if (!b) return;
    b.disabled = loading;
    if (loading) { b.dataset._orig = b.textContent; b.textContent = '처리 중...'; }
    else b.textContent = b.dataset._orig || b.textContent;
  },

  initLogTail(siteId, onUpdate) {
    const iv = setInterval(async () => {
      const d = await CP.getSite(siteId);
      if (!d.ok) { clearInterval(iv); return; }
      if (onUpdate) onUpdate(d.site);
      if (!['provisioning','installing_wp','pending','init','starting'].includes(d.site?.status)) {
        clearInterval(iv);
      }
    }, 3000);
    return { stop: () => clearInterval(iv) };
  },

  setup() {},
  send(b) { return this.post('/api/support', b); },

  _isAuthPage() {
    const p = window.location.pathname;
    return ['/auth', '/auth.html', '/login', '/signup', '/register'].some(x => p.startsWith(x));
  },
  _redirectToLogin() {
    if (this._isAuthPage()) return;
    const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = '/auth.html?returnTo=' + returnTo;
  },
});

function _qs(obj) {
  const p = Object.entries(obj).filter(([, v]) => v != null && v !== '').map(([k, v]) => k + '=' + encodeURIComponent(v));
  return p.length ? '?' + p.join('&') : '';
}
