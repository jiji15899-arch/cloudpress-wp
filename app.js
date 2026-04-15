/* CloudPress CMS app.js v4.0 */
'use strict';

const CP = {
  TOKEN_KEY: 'cp_token',
  USER_KEY:  'cp_user',

  getToken() {
    try { return localStorage.getItem(this.TOKEN_KEY); } catch { return null; }
  },
  setToken(t) {
    try { localStorage.setItem(this.TOKEN_KEY, t); } catch {}
  },
  getUser() {
    try { return JSON.parse(localStorage.getItem(this.USER_KEY) || 'null'); } catch { return null; }
  },
  setUser(u) {
    try { localStorage.setItem(this.USER_KEY, JSON.stringify(u)); } catch {}
  },
  clearAuth() {
    try {
      localStorage.removeItem(this.TOKEN_KEY);
      localStorage.removeItem(this.USER_KEY);
    } catch {}
  },

  async api(path, opts = {}) {
    const token = this.getToken();
    const res = await fetch('/api' + path, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...(opts.headers || {}),
      },
    });
    let data;
    try { data = await res.json(); } catch { data = { ok: false, error: '서버 오류' }; }
    if (res.status === 401) { this.clearAuth(); this._redirectToLogin(); }
    return data;
  },

  get:  (p)    => CP.api(p, { method: 'GET' }),
  post: (p, b) => CP.api(p, { method: 'POST',   body: JSON.stringify(b) }),
  put:  (p, b) => CP.api(p, { method: 'PUT',    body: JSON.stringify(b) }),
  del:  (p, b) => CP.api(p, { method: 'DELETE', body: JSON.stringify(b || {}) }),

  async login(email, password, twofaCode) {
    const body = { email, password };
    if (twofaCode) body.twofa_code = twofaCode;
    const d = await this.post('/auth/login', body);
    if (d.ok) { this.setToken(d.token); this.setUser(d.user); }
    return d;
  },
  async register(name, email, password) {
    const d = await this.post('/auth/register', { name, email, password });
    if (d.ok) { this.setToken(d.token); this.setUser(d.user); }
    return d;
  },
  async logout() {
    await this.post('/auth/logout', {});
    this.clearAuth();
    window.location.href = '/';
  },
  _isAuthPage() {
    const p = window.location.pathname;
    return ['/auth', '/auth.html', '/login', '/signup', '/register'].some(x => p.startsWith(x));
  },
  _redirectToLogin() {
    if (this._isAuthPage()) return;
    // 현재 URL을 returnTo 파라미터로 전달해 로그인 후 복귀 가능하게
    const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = '/auth.html?returnTo=' + returnTo;
  },
  async requireAuth() {
    if (!this.getToken()) { this._redirectToLogin(); return null; }
    const cached = this.getUser();
    if (cached) return cached;
    const d = await this.get('/auth/me');
    if (!d.ok) { this.clearAuth(); this._redirectToLogin(); return null; }
    this.setUser(d.user);
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
  isAdmin(user) {
    return user?.role === 'admin';
  },
  isAdminOrMgr(user) {
    return user?.role === 'admin' || user?.role === 'manager';
  },

  // Sites
  getSites:    ()      => CP.get('/sites'),
  getSite:     (id)    => CP.get(`/sites/${id}`),
  createSite:  (b)     => CP.post('/sites', b),
  deleteSite:  (id)    => CP.del(`/sites/${id}`),
  updateSite:  (id, b) => CP.put(`/sites/${id}`, b),
  pollSite:    (id)    => CP.get(`/sites/${id}`),
  getSiteCreds:(id)    => CP.get(`/sites/${id}/credentials`),

  // User
  getProfile:    ()    => CP.get('/user'),
  updateProfile: (b)   => CP.put('/user', b),
  saveCfApi:     (b)   => CP.put('/user', { action: 'save_cf_api', ...b }),
  removeCfApi:   ()    => CP.put('/user', { action: 'remove_cf_api' }),
  setup2FA:      (b)   => CP.put('/user', { action: 'setup_2fa', ...b }),
  disable2FA:    (pw)  => CP.put('/user', { action: 'disable_2fa', password: pw }),
  send2FACode:   ()    => CP.post('/auth/send-2fa-code', {}),

  // Admin
  adminStats:        ()      => CP.get('/admin/stats'),
  adminUsers:        (q, p)  => CP.get(`/admin/users?q=${q||''}&page=${p||1}`),
  adminUpdateUser:   (b)     => CP.put('/admin/users', b),
  adminDeleteUser:   (id)    => CP.del('/admin/users', { id }),
  adminSites:        (q, p)  => CP.get(`/admin/sites?q=${q||''}&page=${p||1}`),
  adminDeleteSite:   (id)    => CP.del('/admin/sites', { id }),
  adminNotices:      ()      => CP.get('/admin/notices'),
  adminCreateNotice: (b)     => CP.post('/admin/notices', b),
  adminUpdateNotice: (b)     => CP.put('/admin/notices', b),
  adminDeleteNotice: (id)    => CP.del('/admin/notices', { id }),
  adminRevenue:      (p)     => CP.get(`/admin/revenue?page=${p||1}`),
  adminSettings:     ()      => CP.get('/admin/settings'),
  adminSaveSettings: (b)     => CP.put('/admin/settings', { settings: b }),
  adminAddCmsVersion:(b)     => CP.put('/admin/settings', { action: 'add_cms_version', ...b }),
  adminDeleteCmsVersion:(id) => CP.put('/admin/settings', { action: 'delete_cms_version', version_id: id }),
  adminSetLatestVersion:(id) => CP.put('/admin/settings', { action: 'set_latest_version', version_id: id }),
  getCmsVersions:    ()      => CP.get('/admin/settings'),

  // Payments
  paymentCheckout: (plan) => CP.post('/payments/checkout', { plan }),
  paymentConfirm:  (b)    => CP.post('/payments/confirm', b),

  // Util
  formatDate(ts) {
    if (!ts) return '—';
    return new Date(ts > 1e10 ? ts : ts * 1000)
      .toLocaleDateString('ko-KR', { year: 'numeric', month: 'short', day: 'numeric' });
  },
  formatMoney(n) {
    return Number(n || 0).toLocaleString('ko-KR') + '원';
  },
  planInfo(plan) {
    // 모든 요금제 무료 — 플랜은 어드민이 사용자별로 설정
    const p = {
      free:       { name: '무료', price: 0, color: '#6b7280', sites: 1  },
      starter:    { name: '무료', price: 0, color: '#6366f1', sites: 3  },
      pro:        { name: '무료', price: 0, color: '#f97316', sites: 10 },
      enterprise: { name: '무료', price: 0, color: '#ec4899', sites: -1 },
    };
    return p[plan] || p.free;
  },
  statusBadge(s) {
    const m = {
      active:        { label: '활성',    color: '#22c55e' },
      provisioning:  { label: '구축 중', color: '#f97316' },
      installing_wp: { label: '설치 중', color: '#f97316' },
      pending:       { label: '대기 중', color: '#f97316' },
      init:          { label: '설치 중', color: '#f97316' },
      starting:      { label: '설치 중', color: '#f97316' },
      failed:        { label: '실패',    color: '#ef4444' },
      error:         { label: '오류',    color: '#ef4444' },
      stopped:       { label: '중지',    color: '#6b7280' },
      suspended:     { label: '정지됨',  color: '#6b7280' },
      deleted:       { label: '삭제됨',  color: '#6b7280' },
    };
    return m[s] || { label: s || '알 수 없음', color: '#6b7280' };
  },
  roleName(r) {
    return { admin: '어드민', manager: '매니저', user: '일반' }[r] || r;
  },
  escHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c =>
      ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  },
};

/* Toast */
function showToast(msg, type = 'info') {
  let el = document.getElementById('cp-toast');
  if (!el) { el = document.createElement('div'); el.id = 'cp-toast'; document.body.appendChild(el); }
  el.className = `cp-toast ${type}`;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3500);
}

/* Sidebar */
function openSidebar()  { document.getElementById('sidebar')?.classList.add('open');  document.getElementById('overlay')?.classList.add('show'); }
function closeSidebar() { document.getElementById('sidebar')?.classList.remove('open'); document.getElementById('overlay')?.classList.remove('show'); }

/* Copy */
async function copyText(text, btn) {
  await navigator.clipboard.writeText(text);
  const orig = btn.textContent;
  btn.textContent = '완료!';
  setTimeout(() => btn.textContent = orig, 1500);
}
