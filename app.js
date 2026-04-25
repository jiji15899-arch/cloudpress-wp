/* CloudPress CMS app.js v4.0 */
'use strict';

// 전역 CP 객체 즉시 선언 (CP is not defined 방지)
const CP = {};
window.CP = CP;

Object.assign(CP, {
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

  async apiFetch(path, opts = {}) {
    if (typeof fetch === 'undefined') return;
    const token = this.getToken();
    // 경로가 /api 로 시작하지 않으면 자동으로 붙여줌
    const url = (path.startsWith('http') || path.startsWith('/')) ? path : '/api' + (path.startsWith('/') ? '' : '/') + path;
    
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    };
    const res = await fetch(url, { ...opts, headers });
    if (res.status === 401) { this.clearAuth(); this._redirectToLogin(); }
    return res;
  },

  // [기능 추가] 자체 결제 로직: 카드 정보 업데이트
  async updatePaymentMethod(cardNumber, expiry) {
    return this.put('/user', { action: 'update_payment', card_number: cardNumber, card_expiry: expiry });
  },

  // [기능 추가] 포럼 및 문의하기
  async submitForum(title, content) {
    return this.post('/forum/posts', { title, content });
  },
  async submitInquiry(subject, message) {
    return this.post('/support/tickets', { subject, message });
  },

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
  updateSiteSettings: (id, b) => CP.put(`/sites/${id}/settings`, b),
  pollSite:    (id)    => CP.get(`/sites/${id}`),
  // 사이트 생성 시 결제/할인 코드 포함
  createSite: (b) => CP.post('/sites', b),
  
  // [사이트 상세 20+ 기능 핵심 API]
  siteAction: (id, action, params = {}) => CP.post(`/sites/${id}/action`, { action, ...params }),
  // 아래 기능들은 siteAction('restart_php'), siteAction('clear_cache') 등으로 호출됨
  // 1. PHP 버전 변경 2. 서버 재시작 3. 캐시 삭제 4. SSL 강제화 5. WAF 설정 6. IP 차단 7. 백업 생성 
  // 8. DB 최적화 9. SFTP 계정 관리 10. SSH 키 등록 11. Cron 작업 설정 12. 스테이징 생성 
  // 13. Git 배포 설정 14. 실시간 모니터링 15. 에러 로그 보기 16. 접속 로그 분석 17. 디스크 정리 
  // 18. New Relic 연동 19. Redis 캐시 관리 20. Varnish 설정 21. CDN 퍼지

  // DNS 관리
  addDnsRecord: (domain, data) => CP.post(`/dns/${domain}/records`, data),
  deleteDnsRecord: (domain, recordId) => CP.del(`/dns/${domain}/records/${recordId}`),
  
  // [DNS 정책] 
  // 1. DNS 페이지: Cloudflare Nameserver 연동 (Global API 사용)
  async setupNameservers(domain) {
    return this.post('/dns/setup', { domain, method: 'nameserver' });
  },
  // 2. 사이트 상세: A 레코드 방식
  async setupARecord(id, domain) {
    return this.post(`/sites/${id}/dns`, { domain, method: 'a_record' });
  },

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

  // Luhn 알고리즘을 사용한 카드 번호 검증
  validateCardNumber(number) {
    const digits = String(number).replace(/\D/g, '');
    if (!digits || digits.length < 13) return false;
    
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits.charAt(i));
      if (shouldDouble) {
        if ((digit *= 2) > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return (sum % 10) === 0;
  },
});

/* Toast */
window.showToast = function(msg, type = 'info') { // Make showToast global
  let el = document.getElementById('cp-toast');
  if (!el) { el = document.createElement('div'); el.id = 'cp-toast'; document.body.appendChild(el); }
  el.className = `cp-toast ${type}`;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3000);
}

/* Sidebar */
window.openSidebar = function()  { document.getElementById('sidebar')?.classList.add('open');  document.getElementById('overlay')?.classList.add('show'); }
window.closeSidebar = function() { document.getElementById('sidebar')?.classList.remove('open'); document.getElementById('overlay')?.classList.remove('show'); }

/* Copy */
window.copyText = async function(text, btn) {
  await navigator.clipboard.writeText(text);
  const orig = btn.textContent;
  btn.textContent = '완료!';
  setTimeout(() => btn.textContent = orig, 1500);
}
