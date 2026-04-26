/**
 * CloudPress Core API Library v25.0
 * ─────────────────────────────────────────────────────────────────────────────
 * v25.0 변경:
 *  · navigateSite(): 단순 location.href 이동 (onclick 이스케이프 문제 해결)
 *  · getSite(): 타임아웃 15s 명시
 *  · safeJson(): apiFetch Response-like + 진짜 Response + 일반 객체 모두 처리
 *  · requireAuth(): auth.html 루프 방지
 *  · showToast(): 중복 제거 개선
 *  · openSidebar/closeSidebar 전역 등록
 *  · escHtml(): null/undefined 안전
 *  · CP.VERSION 추가
 */
const CP = {
  VERSION: '25.0',
  apiBase: '/api',

  headers() {
    const token = localStorage.getItem('cp_token');
    return {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': 'Bearer ' + token } : {}),
    };
  },

  _url(path) {
    if (path.startsWith('http')) return path;
    if (path.startsWith('/api/') || path === '/api') return path;
    return this.apiBase + (path.startsWith('/') ? path : '/' + path);
  },

  _parseText(text, status, httpOk) {
    const t = (text || '').trim();
    if (t.startsWith('<') || t.startsWith('<!')) {
      if (status === 401) return { ok: false, error: '세션이 만료되었습니다. 다시 로그인해주세요.', code: 401 };
      if (status === 404) return { ok: false, error: 'API 엔드포인트를 찾을 수 없습니다 (404).', code: 404 };
      if (status === 500) return { ok: false, error: '서버 오류가 발생했습니다 (500).', code: 500 };
      return { ok: false, error: '서버 응답 오류 (HTTP ' + status + ').', code: status };
    }
    if (!t) return { ok: httpOk, error: httpOk ? null : '빈 응답' };
    try {
      const data = JSON.parse(t);
      if (typeof data.ok === 'undefined') data.ok = httpOk;
      return data;
    } catch {
      return { ok: false, error: '잘못된 JSON 응답입니다.' };
    }
  },

  async _parseResponse(res) {
    try {
      const text = await res.text();
      return this._parseText(text, res.status, res.ok);
    } catch (e) {
      return { ok: false, error: '응답 처리 오류: ' + e.message };
    }
  },

  async fetch(path, options, timeoutMs) {
    options = options || {};
    timeoutMs = timeoutMs || 20000;
    const url = this._url(path);
    try {
      const controller = new AbortController();
      const timer = setTimeout(function() { controller.abort(); }, timeoutMs);
      const res = await window.fetch(url, Object.assign({}, options, {
        headers: Object.assign({}, this.headers(), options.headers || {}),
        signal: controller.signal,
      }));
      clearTimeout(timer);
      return await this._parseResponse(res);
    } catch (e) {
      if (e.name === 'AbortError') return { ok: false, error: '요청 시간이 초과되었습니다.' };
      return { ok: false, error: '네트워크 오류: ' + e.message };
    }
  },

  async apiFetch(path, options, timeoutMs) {
    options = options || {};
    timeoutMs = timeoutMs || 20000;
    const url = this._url(path);
    const self = this;
    try {
      const controller = new AbortController();
      const timer = setTimeout(function() { controller.abort(); }, timeoutMs);
      const rawRes = await window.fetch(url, Object.assign({}, options, {
        headers: Object.assign({}, self.headers(), options.headers || {}),
        signal: controller.signal,
      }));
      clearTimeout(timer);
      const text = await rawRes.text();
      const status = rawRes.status;
      const httpOk = rawRes.ok;
      const parsed = self._parseText(text, status, httpOk);
      if (status === 401 && !options._noRedirect && location.pathname.indexOf('auth.html') === -1) {
        const returnTo = encodeURIComponent(location.pathname + location.search);
        location.href = '/auth.html?returnTo=' + returnTo;
        return { ok: false, status: 401, error: '로그인이 필요합니다.' };
      }
      return {
        ok: parsed.ok,
        status: status,
        headers: rawRes.headers,
        _parsed: parsed,
        json: async function() { return this._parsed; },
        text: async function() { return text; },
      };
    } catch (e) {
      const errMsg = e.name === 'AbortError' ? '요청 시간이 초과되었습니다.' : '네트워크 오류: ' + e.message;
      const errData = { ok: false, error: errMsg };
      return {
        ok: false, status: 0, headers: new Headers(), _parsed: errData,
        json: async function() { return errData; },
        text: async function() { return JSON.stringify(errData); },
      };
    }
  },

  async safeJson(res) {
    if (!res) return { ok: false, error: '응답 없음' };
    if (typeof res === 'object' && '_parsed' in res) return res._parsed;
    if (res && typeof res.json === 'function') {
      try { return await res.json(); } catch { return { ok: false, error: '응답 파싱 오류' }; }
    }
    return Object.assign({ ok: true }, res);
  },

  async get(path, timeoutMs)         { return this.fetch(path, { method: 'GET' }, timeoutMs); },
  async post(path, body, timeoutMs)  { return this.fetch(path, { method: 'POST', body: JSON.stringify(body) }, timeoutMs); },
  async put(path, body)              { return this.fetch(path, { method: 'PUT',  body: JSON.stringify(body) }); },
  async delete(path)                 { return this.fetch(path, { method: 'DELETE' }); },

  getToken() { return localStorage.getItem('cp_token'); },

  async login(email, password, twoFaCode) {
    const body = { email: email, password: password };
    if (twoFaCode) body.twofa_code = twoFaCode;
    const r = await this.post('/auth/login', body);
    if (r.ok && r.token) localStorage.setItem('cp_token', r.token);
    return r;
  },

  async register(name, email, password) {
    const r = await this.post('/auth/register', { name: name, email: email, password: password });
    if (r.ok && r.token) localStorage.setItem('cp_token', r.token);
    return r;
  },

  async requireAuth() {
    if (location.pathname.indexOf('auth.html') !== -1) return null;
    const user = await this.get('/auth/me', 10000);
    if (!user.ok) {
      const returnTo = encodeURIComponent(location.pathname + location.search);
      location.href = '/auth.html?returnTo=' + returnTo;
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
    const user = await this.get('/auth/me', 10000);
    if (!user.ok) {
      const returnTo = encodeURIComponent(location.pathname + location.search);
      location.href = '/auth.html?returnTo=' + returnTo;
      return null;
    }
    if (user.user && user.user.role !== 'admin' && user.user.role !== 'manager') {
      location.href = '/dashboard.html';
      return null;
    }
    return user.user;
  },

  // 사이트 상세 페이지 이동 — onclick에서 직접 호출 가능
  navigateSite(siteId) {
    if (!siteId) { console.error('[CP] navigateSite: siteId 없음'); return; }
    window.location.href = '/site.html?id=' + encodeURIComponent(String(siteId));
  },

  async getSites()         { return this.get('/sites'); },
  async getSite(id)        { return this.get('/sites/' + id, 15000); },
  async createSite(data)   { return this.post('/sites', data); },
  async deleteSite(id)     { return this.delete('/sites/' + id); },
  async startProvision(id) { return this.post('/sites/' + id + '/provision', {}); },

  async adminStats()                 { return this.get('/admin/stats'); },
  async adminUsers(q, page)          {
    q = q || ''; page = page || 1;
    var p = '/admin/users?page=' + page;
    if (q) p += '&q=' + encodeURIComponent(q);
    return this.get(p);
  },
  async adminUpdateUser(data)        { return this.put('/admin/users/' + data.id, data); },
  async adminDeleteUser(id)          { return this.delete('/admin/users/' + id); },
  async adminSites(q, page)          {
    q = q || ''; page = page || 1;
    var p = '/admin/sites?page=' + page;
    if (q) p += '&q=' + encodeURIComponent(q);
    return this.get(p);
  },
  async adminDeleteSite(id)          { return this.delete('/admin/sites/' + id); },
  async adminNotices(page)           { return this.get('/admin/notices?page=' + (page || 1)); },
  async adminCreateNotice(data)      { return this.post('/admin/notices', data); },
  async adminUpdateNotice(data)      { return this.put('/admin/notices/' + data.id, data); },
  async adminDeleteNotice(id)        { return this.delete('/admin/notices/' + id); },
  async adminRevenue(page)           { return this.get('/admin/revenue?page=' + (page || 1)); },

  async getProfile()                 { return this.get('/user'); },
  async updateProfile(data)          { return this.post('/user', data); },
  async updatePaymentMethod(cardNumber, expiry) {
    return this.post('/user', { action: 'update_payment', card_number: cardNumber, expiry: expiry });
  },
  async saveCfApi(data)    { return this.post('/user', Object.assign({ action: 'save_cf_api' }, data)); },
  async removeCfApi()      { return this.post('/user', { action: 'remove_cf_api' }); },
  async send2FACode()      { return this.post('/auth/2fa/send', {}); },
  async setup2FA(data)     { return this.post('/auth/2fa/setup', data); },
  async disable2FA(pw)     { return this.post('/auth/2fa/disable', { password: pw }); },
  async getMetrics(siteId) { return this.get('/sites/' + siteId + '/metrics'); },
  async paymentConfirm(data) { return this.post('/payments/confirm', data); },

  statusBadge(status) {
    var map = {
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
    var plans = {
      starter:    { name: 'Starter',    color: '#94a3b8' },
      pro:        { name: 'Pro',        color: '#6366f1' },
      business:   { name: 'Business',   color: '#f97316' },
      enterprise: { name: 'Enterprise', color: '#8b5cf6' },
    };
    return plans[plan] || { name: plan || '—', color: '#94a3b8' };
  },

  formatDate(dateStr) {
    if (!dateStr) return '—';
    try {
      return new Date(dateStr).toLocaleDateString('ko-KR', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch (e) { return dateStr; }
  },

  escHtml(str) {
    if (str == null) return '';
    var div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  },

  roleName(role) {
    return ({ admin: '관리자', manager: '매니저', user: '사용자' })[role] || role || '사용자';
  },

  isAdminOrMgr(user) {
    return user && (user.role === 'admin' || user.role === 'manager');
  },

  setUser(user) {
    if (user) localStorage.setItem('cp_user', JSON.stringify(user));
    else localStorage.removeItem('cp_user');
  },

  validateCardNumber(num) {
    var n = String(num).replace(/\D/g, '');
    if (n.length < 13 || n.length > 19) return false;
    var sum = 0, alt = false;
    for (var i = n.length - 1; i >= 0; i--) {
      var d = parseInt(n[i], 10);
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d; alt = !alt;
    }
    return sum % 10 === 0;
  },

  async measureLatency(domain) {
    if (!domain) return -1;
    try {
      var start = Date.now();
      await window.fetch('https://' + domain + '/favicon.ico', {
        method: 'HEAD', mode: 'no-cors', cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      });
      return Date.now() - start;
    } catch (e) { return -1; }
  },

  initLogTail(siteId, onLine, intervalMs) {
    intervalMs = intervalMs || 3000;
    var lastTs = Date.now();
    var self = this;
    var poll = async function() {
      var r = await self.get('/sites/' + siteId + '/logs?since=' + lastTs);
      if (r.ok && Array.isArray(r.logs)) {
        r.logs.forEach(function(line) { onLine(line); });
        if (r.logs.length) lastTs = Date.now();
      }
    };
    poll();
    return setInterval(poll, intervalMs);
  },

  initResourceMonitor() {
    var update = function() {
      var cpu = Math.floor(Math.random() * 11) + 5;
      var bar = document.getElementById('cpuBar');
      var txt = document.getElementById('cpuText');
      if (bar) bar.style.width = cpu + '%';
      if (txt) txt.textContent = cpu + '%';
    };
    setInterval(update, 3000);
    update();
  },
};

// ── 전역 showToast ──────────────────────────────────────────────────────────
window.showToast = function(msg, successOrType) {
  document.querySelectorAll('.cp-toast').forEach(function(el) { el.remove(); });
  var t = document.createElement('div');
  t.className = 'cp-toast';
  var type = typeof successOrType === 'string' ? successOrType
    : (successOrType === false ? 'error' : 'success');
  var colors = { success: '#22c55e', error: '#ef4444', info: '#6366f1', warn: '#f59e0b', warning: '#f59e0b' };
  var bg = colors[type] || '#6366f1';
  t.style.cssText = 'position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:10px;' +
    'font-size:.88rem;font-weight:500;color:#fff;z-index:9999;background:' + bg + ';' +
    'box-shadow:0 4px 16px rgba(0,0,0,.3);transition:opacity .3s;max-width:320px;';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(function() { t.style.opacity = '0'; setTimeout(function() { t.remove(); }, 300); }, 3500);
};

// ── 사이드바 토글 전역 등록 ─────────────────────────────────────────────────
window.openSidebar = function() {
  var sb = document.getElementById('sidebar');
  var ov = document.getElementById('overlay');
  if (sb) sb.classList.add('open');
  if (ov) ov.classList.add('open');
};
window.closeSidebar = function() {
  var sb = document.getElementById('sidebar');
  var ov = document.getElementById('overlay');
  if (sb) sb.classList.remove('open');
  if (ov) ov.classList.remove('open');
};
