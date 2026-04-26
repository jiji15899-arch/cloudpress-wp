/**
 * CloudPress Core API Library v24.1
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

  // API 통신 기본 메소드
  async fetch(path, options = {}) {
    try {
      const res = await fetch(`${this.apiBase}${path.startsWith('/') ? path : '/' + path}`, {
        ...options,
        headers: { ...this.headers(), ...options.headers }
      });
      return await this.safeJson(res);
    } catch (e) {
      return { ok: false, error: '네트워크 오류가 발생했습니다.' };
    }
  },

  async get(path) { return this.fetch(path, { method: 'GET' }); },
  async post(path, body) { return this.fetch(path, { method: 'POST', body: JSON.stringify(body) }); },
  async put(path, body) { return this.fetch(path, { method: 'PUT', body: JSON.stringify(body) }); },
  async delete(path) { return this.fetch(path, { method: 'DELETE' }); },

  // 안전한 JSON 파싱 (HTML 응답 에러 방지)
  safeJson: async function(res) {
    try {
      if (!res) return { ok: false, error: '응답 객체가 없습니다.' };
      if (typeof res === 'object' && !(res instanceof Response)) {
        return { ok: res.ok ?? true, ...res };
      }

      const ct = res.headers?.get?.('content-type') || '';
      const text = await res.text();
      
      // HTML 응답 감지 (Unexpected token '<' 방지)
      if (text.trim().startsWith('<') || text.trim().startsWith('<!')) {
        if (res.status === 401) return { ok: false, error: '세션이 만료되었습니다. 다시 로그인해주세요.', code: 401 };
        if (res.status === 404) return { ok: false, error: '요청하신 API 엔드포인트를 찾을 수 없습니다 (404).', code: 404 };
        return { ok: false, error: `서버 오류가 발생했습니다 (HTTP ${res.status}).`, code: res.status };
      }

      let data = {};
      try {
        data = JSON.parse(text);
      } catch (e) {
        return { ok: false, error: '올바르지 않은 JSON 응답입니다.' };
      }

      return { ok: res.ok, ...data };
    } catch (e) {
      return { ok: false, error: '응답 처리 중 오류가 발생했습니다.' };
    }
  },

  // 인증 관련
  getToken() {
    return localStorage.getItem('cp_token');
  },

  async login(email, password, twoFaCode = null) {
    const body = { email, password };
    if (twoFaCode) body.twofa_code = twoFaCode;
    const r = await this.post('/auth/login', body);
    if (r.ok && r.token) {
      localStorage.setItem('cp_token', r.token);
    }
    return r;
  },

  async register(name, email, password) {
    const r = await this.post('/auth/register', { name, email, password });
    if (r.ok && r.token) {
      localStorage.setItem('cp_token', r.token);
    }
    return r;
  },

  async requireAuth() {
    const user = await this.get('/auth/me');
    if (!user.ok) {
      location.href = '/auth.html?returnTo=' + encodeURIComponent(location.pathname + location.search);
      return null;
    }
    return user.user;
  },

  logout() {
    localStorage.removeItem('cp_token');
    location.href = '/auth.html';
  },

  // 사이트 관리 API
  async getSites() { return await this.get('/sites'); },
  async getSite(id) { return await this.get(`/sites/${id}`); },
  async createSite(data) { return await this.post('/sites', data); },
  async deleteSite(id) { return await this.delete(`/sites/${id}`); },
  async startProvision(id) { return await this.post(`/sites/${id}/provision`, {}); },

  // 유틸리티: 상태 배지
  statusBadge(status) {
    const map = {
      active: { color: '#22c55e', label: '운영 중' },
      provisioning: { color: '#f59e0b', label: '서버 구축 중' },
      installing_wp: { color: '#6366f1', label: 'WP 설치 중' },
      failed: { color: '#ef4444', label: '생성 실패' },
      pending: { color: '#94a3b8', label: '대기 중' },
      init: { color: '#f97316', label: '초기화 중' }
    };
    return map[status] || { color: '#94a3b8', label: status };
  },

  // 유틸리티: 플랜 정보
  planInfo(plan) {
    const plans = {
      starter: { name: 'Starter', color: '#94a3b8' },
      pro: { name: 'Pro', color: '#6366f1' },
      business: { name: 'Business', color: '#f97316' },
      enterprise: { name: 'Enterprise', color: '#8b5cf6' }
    };
    return plans[plan] || { name: plan, color: '#94a3b8' };
  },

  // 유틸리티: 날짜 포맷
  formatDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('ko-KR', { year: 'numeric', month: 'short', day: 'numeric' });
  },

  // 유틸리티: HTML 이스케이프 (XSS 방지)
  escHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  // 리소스 모니터링 시뮬레이션 (실제 데이터 연동 전용)
  initResourceMonitor() {
    const update = () => {
      const cpu = Math.floor(Math.random() * (15 - 5 + 1)) + 5; // 5~15% 사이 시뮬레이션
      const bar = document.getElementById('cpuBar');
      const txt = document.getElementById('cpuText');
      if (bar && txt) {
        bar.style.width = cpu + '%';
        txt.textContent = cpu + '%';
      }
    };
    setInterval(update, 3000);
    update();
  }
};

// 전역 초기화
window.showToast = function(msg, type = 'info') {
  const existing = document.querySelector('.cp-toast');
  if (existing) existing.remove();
  const t = document.createElement('div');
  t.className = `cp-toast ${type} show`;
  t.style.cssText = "position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:10px;font-size:.88rem;font-weight:500;color:#fff;z-index:9999;transition:all .3s;";
  if(type==='success') t.style.background='#22c55e';
  else if(type==='error') t.style.background='#ef4444';
  else t.style.background='#6366f1';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3000);
};
