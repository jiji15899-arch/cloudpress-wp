/* CloudPress app.js v3.0 — 실제 API 연동 */
'use strict';

const CP = {
  TOKEN_KEY: 'cp_token',
  USER_KEY:  'cp_user',

  getToken() { return localStorage.getItem(this.TOKEN_KEY); },
  setToken(t) { localStorage.setItem(this.TOKEN_KEY, t); },
  getUser() {
    try { return JSON.parse(localStorage.getItem(this.USER_KEY) || 'null'); } catch { return null; }
  },
  setUser(u) { localStorage.setItem(this.USER_KEY, JSON.stringify(u)); },
  clearAuth() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
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
    if (res.status === 401) { this.clearAuth(); window.location.href = '/auth.html'; }
    return data;
  },

  get:  (p)    => CP.api(p, { method: 'GET' }),
  post: (p, b) => CP.api(p, { method: 'POST',   body: JSON.stringify(b) }),
  put:  (p, b) => CP.api(p, { method: 'PUT',    body: JSON.stringify(b) }),
  del:  (p, b) => CP.api(p, { method: 'DELETE', body: JSON.stringify(b || {}) }),

  async login(email, password) {
    const d = await this.post('/auth/login', { email, password });
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
  async requireAuth() {
    if (!this.getToken()) { window.location.href = '/auth.html'; return null; }
    const cached = this.getUser();
    if (cached) return cached;
    const d = await this.get('/auth/me');
    if (!d.ok) { this.clearAuth(); window.location.href = '/auth.html'; return null; }
    this.setUser(d.user);
    return d.user;
  },
  async requireAdmin() {
    const user = await this.requireAuth();
    if (!user) return null;
    if (user.role !== 'admin') { window.location.href = '/dashboard.html'; return null; }
    return user;
  },

  // Sites
  getSites:              ()       => CP.get('/sites'),
  getSite:               (id)     => CP.get(`/sites/${id}`),
  createSite:            (b)      => CP.post('/sites', b),
  deleteSite:            (id)     => CP.del(`/sites/${id}`),
  updateSite:            (id, b)  => CP.put(`/sites/${id}`, b),
  pollSite:              (id)     => CP.get(`/sites/${id}/status`),

  // User
  getProfile:            ()       => CP.get('/user'),
  updateProfile:         (b)      => CP.put('/user', b),

  // Admin
  adminStats:            ()       => CP.get('/admin/stats'),
  adminUsers:            (q, p)   => CP.get(`/admin/users?q=${q||''}&page=${p||1}`),
  adminUpdateUser:       (b)      => CP.put('/admin/users', b),
  adminDeleteUser:       (id)     => CP.del('/admin/users', { id }),
  adminSites:            (q, p)   => CP.get(`/admin/sites?q=${q||''}&page=${p||1}`),
  adminDeleteSite:       (id)     => CP.del('/admin/sites', { id }),
  adminNotices:          ()       => CP.get('/admin/notices'),
  adminCreateNotice:     (b)      => CP.post('/admin/notices', b),
  adminUpdateNotice:     (b)      => CP.put('/admin/notices', b),
  adminDeleteNotice:     (id)     => CP.del('/admin/notices', { id }),
  adminRevenue:          (p)      => CP.get(`/admin/revenue?page=${p||1}`),
  adminSettings:         ()       => CP.get('/admin/settings'),
  adminSaveSettings:     (b)      => CP.put('/admin/settings', { settings: b }),

  // Payments
  paymentCheckout:       (plan)   => CP.post('/payments/checkout', { plan }),
  paymentConfirm:        (b)      => CP.post('/payments/confirm', b),

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
    const p = {
      free:       { name: '무료',        price: 0,      color: '#6b7280', sites: 1 },
      starter:    { name: '스타터',      price: 9900,   color: '#6366f1', sites: 3 },
      pro:        { name: '프로',        price: 29900,  color: '#f97316', sites: 10 },
      enterprise: { name: '엔터프라이즈', price: 99000,  color: '#ec4899', sites: -1 },
    };
    return p[plan] || p.free;
  },
  statusBadge(s) {
    const m = {
      active:       { label: '활성',    color: '#22c55e' },
      provisioning: { label: '설치 중', color: '#f97316' },
      error:        { label: '오류',    color: '#ef4444' },
      stopped:      { label: '중지',    color: '#6b7280' },
    };
    return m[s] || m.stopped;
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
