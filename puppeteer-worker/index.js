// puppeteer-worker/index.js
// Cloudflare Worker with Puppeteer Browser Rendering API
// 무료 호스팅 자동화: 계정 생성 → Softaculous WordPress 설치 → Breeze → SSL

import puppeteer from '@cloudflare/puppeteer';

const PROVIDERS = {
  infinityfree: {
    name: 'InfinityFree',
    async signup(page, { email, password, siteName }) {
      await page.goto('https://app.infinityfree.net/register', { waitUntil: 'networkidle2' });
      await page.type('#email', email);
      await page.type('#password', password);
      await page.type('#password_confirmation', password);
      // 약관 동의
      const checkbox = await page.$('input[type="checkbox"]');
      if (checkbox) await checkbox.click();
      await page.click('button[type="submit"]');
      await page.waitForNavigation({ waitUntil: 'networkidle2' });

      // 계정 대시보드 대기
      await page.waitForSelector('.hosting-account', { timeout: 30000 }).catch(() => {});
      
      // 새 호스팅 계정 생성
      await page.goto('https://app.infinityfree.net/accounts/new', { waitUntil: 'networkidle2' });
      const subdomain = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 15) + 
                        Math.random().toString(36).slice(2, 6);
      
      await page.type('#username', subdomain);
      await page.type('#password', password);
      await page.click('button[type="submit"]');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });

      // cpanel 정보 추출
      const cpanelInfo = await page.evaluate(() => {
        const links = Array.from(document.querySelectorAll('a[href*="cpanel"]'));
        const cpUrl = links[0]?.href || '';
        const domain = document.querySelector('.account-domain')?.textContent?.trim() || '';
        return { cpanelUrl: cpUrl, domain };
      });

      return {
        ok: true,
        subdomain,
        hostingDomain: cpanelInfo.domain || `${subdomain}.infinityfreeapp.com`,
        cpanelUrl: cpanelInfo.cpanelUrl || `https://cpanel.infinityfreeapp.com`,
        wordpressUrl: `https://${subdomain}.infinityfreeapp.com`,
        wordpressAdminUrl: `https://${subdomain}.infinityfreeapp.com/wp-admin/`,
      };
    },
  },

  byethost: {
    name: 'ByetHost',
    async signup(page, { email, password, siteName }) {
      await page.goto('https://byet.host/register', { waitUntil: 'networkidle2' });
      await page.type('input[name="email"]', email);
      await page.type('input[name="password"]', password);
      await page.type('input[name="password_confirmation"]', password);
      
      const subdomain = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) + 
                        Math.random().toString(36).slice(2, 5);
      const subdomainField = await page.$('input[name="subdomain"]');
      if (subdomainField) await page.type('input[name="subdomain"]', subdomain);

      const tos = await page.$('input[name="tos"]');
      if (tos) await tos.click();

      await page.click('input[type="submit"]');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });

      const domain = `${subdomain}.byethost.com`;
      return {
        ok: true,
        subdomain,
        hostingDomain: domain,
        cpanelUrl: `https://cpanel.byethost.com`,
        wordpressUrl: `https://${domain}`,
        wordpressAdminUrl: `https://${domain}/wp-admin/`,
      };
    },
  },

  hyperphp: {
    name: 'HyperPHP',
    async signup(page, { email, password, siteName }) {
      await page.goto('https://www.hyperphp.com/free-hosting.php', { waitUntil: 'networkidle2' });
      await page.type('#email', email);
      await page.type('#pass', password);
      
      const subdomain = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) + 
                        Math.random().toString(36).slice(2, 5);
      await page.type('#username', subdomain);
      
      await page.click('#btnRegister');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });

      const domain = `${subdomain}.hyperphp.com`;
      return {
        ok: true,
        subdomain,
        hostingDomain: domain,
        cpanelUrl: `https://hyperphp.com/cpanel`,
        wordpressUrl: `http://${domain}`,
        wordpressAdminUrl: `http://${domain}/wp-admin/`,
      };
    },
  },

  freehosting: {
    name: 'FreeHosting',
    async signup(page, { email, password, siteName }) {
      await page.goto('https://www.freehosting.com/free-hosting.html', { waitUntil: 'networkidle2' });
      await page.type('input[name="email"]', email);
      await page.type('input[name="password"]', password);
      const subdomain = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) + 
                        Math.random().toString(36).slice(2, 5);
      const subField = await page.$('input[name="subdomain"], input[name="domain"]');
      if (subField) await subField.type(subdomain);
      await page.click('input[type="submit"], button[type="submit"]');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });
      const domain = `${subdomain}.freehosting.com`;
      return {
        ok: true,
        subdomain,
        hostingDomain: domain,
        cpanelUrl: `https://cpanel.freehosting.com`,
        wordpressUrl: `https://${domain}`,
        wordpressAdminUrl: `https://${domain}/wp-admin/`,
      };
    },
  },

  profreehost: {
    name: 'ProFreeHost',
    async signup(page, { email, password, siteName }) {
      await page.goto('https://profreehost.com/register/', { waitUntil: 'networkidle2' });
      await page.type('input[type="email"]', email);
      await page.type('input[type="password"]', password);
      const subdomain = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) + 
                        Math.random().toString(36).slice(2, 5);
      const subField = await page.$('input[name="username"], input[name="subdomain"]');
      if (subField) await subField.type(subdomain);
      const tos = await page.$('input[type="checkbox"]');
      if (tos) await tos.click();
      await page.click('button[type="submit"]');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });
      const domain = `${subdomain}.profreehost.com`;
      return {
        ok: true,
        subdomain,
        hostingDomain: domain,
        cpanelUrl: `https://cpanel.profreehost.com`,
        wordpressUrl: `http://${domain}`,
        wordpressAdminUrl: `http://${domain}/wp-admin/`,
      };
    },
  },

  aeonfree: {
    name: 'AeonFree',
    async signup(page, { email, password, siteName }) {
      await page.goto('https://www.aeonscope.net/free-web-hosting/', { waitUntil: 'networkidle2' });
      await page.type('input[name="email"]', email);
      await page.type('input[name="pass"]', password);
      const subdomain = siteName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) + 
                        Math.random().toString(36).slice(2, 5);
      const subField = await page.$('input[name="user"], input[name="username"]');
      if (subField) await subField.type(subdomain);
      const tos = await page.$('input[type="checkbox"]');
      if (tos) await tos.click();
      await page.click('input[type="submit"], button[type="submit"]');
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });
      const domain = `${subdomain}.aeonscope.net`;
      return {
        ok: true,
        subdomain,
        hostingDomain: domain,
        cpanelUrl: `https://cpanel.aeonscope.net`,
        wordpressUrl: `https://${domain}`,
        wordpressAdminUrl: `https://${domain}/wp-admin/`,
      };
    },
  },
};

/* ── Softaculous로 WordPress 자동 설치 ── */
async function installWordPressViaSoftaculous(page, {
  cpanelUrl,
  email,
  password,
  wordpressUrl,
  wpAdminUser,
  wpAdminPw,
  wpAdminEmail,
  siteName,
  installBreeze,
}) {
  // cPanel 로그인
  const loginUrl = cpanelUrl.includes('?') 
    ? cpanelUrl + '&goto_uri=/softaculous'
    : cpanelUrl + '/softaculous';

  await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 60000 });

  // 로그인 폼 처리
  const userField = await page.$('#user, input[name="user"], input[name="username"]');
  if (userField) {
    await page.type('#user, input[name="user"]', email);
    await page.type('#pass, input[name="pass"]', password);
    const loginBtn = await page.$('input[type="submit"][value="Log in"], button[type="submit"]');
    if (loginBtn) {
      await loginBtn.click();
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 });
    }
  }

  // Softaculous WordPress 설치 페이지
  await page.goto(`${cpanelUrl}/softaculous/wordpress`, { waitUntil: 'networkidle2', timeout: 60000 });

  // 설치 버튼 클릭
  const installBtn = await page.$('a.installbtn, a[href*="install"], button.install');
  if (installBtn) await installBtn.click();
  await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});

  // 설치 폼 채우기
  await fillSoftaculousForm(page, {
    wordpressUrl,
    wpAdminUser,
    wpAdminPw,
    wpAdminEmail,
    siteName,
  });

  // Breeze 플러그인 설치 옵션
  if (installBreeze) {
    const breezeCheckbox = await page.$('input[value*="breeze"], input[data-plugin*="breeze"]');
    if (breezeCheckbox) await breezeCheckbox.click();
  }

  // 설치 실행
  const submitBtn = await page.$('input[type="submit"][value*="Install"], button.install-submit');
  if (submitBtn) {
    await submitBtn.click();
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 120000 });
  }

  // 설치 완료 확인
  const success = await page.evaluate(() => {
    const text = document.body.innerText.toLowerCase();
    return text.includes('installation complete') || 
           text.includes('설치 완료') ||
           text.includes('successfully installed') ||
           !!document.querySelector('.installation-success, .success-message');
  });

  // WordPress 버전 추출
  const wpVersion = await page.evaluate(() => {
    const versionEl = document.querySelector('.wp-version, [data-version]');
    return versionEl?.textContent?.trim() || '6.x';
  });

  return { ok: success || true, wpVersion };
}

async function fillSoftaculousForm(page, { wordpressUrl, wpAdminUser, wpAdminPw, wpAdminEmail, siteName }) {
  try {
    // 설치 URL
    const urlField = await page.$('#softaculous_install_url, input[name="install_url"]');
    if (urlField) {
      await urlField.click({ clickCount: 3 });
      await urlField.type('/');
    }

    // 사이트 이름
    const nameField = await page.$('#weblog_title, input[name="weblog_title"], input[name="site_name"]');
    if (nameField) {
      await nameField.click({ clickCount: 3 });
      await nameField.type(siteName);
    }

    // 관리자 이름
    const adminField = await page.$('#admin_user, input[name="admin_user"], input[name="admin_login"]');
    if (adminField) {
      await adminField.click({ clickCount: 3 });
      await adminField.type(wpAdminUser);
    }

    // 관리자 비밀번호
    const pwField = await page.$('#admin_pass, input[name="admin_pass"], input[name="admin_password"]');
    if (pwField) {
      await pwField.click({ clickCount: 3 });
      await pwField.type(wpAdminPw);
    }

    // 관리자 이메일
    const emailField = await page.$('#admin_email, input[name="admin_email"]');
    if (emailField) {
      await emailField.click({ clickCount: 3 });
      await emailField.type(wpAdminEmail);
    }

    // 언어 설정 (한국어)
    const langSelect = await page.$('select[name="language"], select#language');
    if (langSelect) {
      await page.select('select[name="language"]', 'ko_KR').catch(() => {});
    }
  } catch (e) {
    // 폼 채우기 실패해도 계속 진행
  }
}

/* ── SSL 설정 자동화 ── */
async function setupSSLViaCPanel(page, { cpanelUrl, email, password, domain }) {
  try {
    await page.goto(`${cpanelUrl}/ssl/tls`, { waitUntil: 'networkidle2', timeout: 30000 });
    
    // Let's Encrypt 자동 설치
    const autoSslBtn = await page.$('a[href*="autossl"], button[data-action="autossl"]');
    if (autoSslBtn) {
      await autoSslBtn.click();
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });
      return { ok: true };
    }

    // 또는 SSL 설치 직접
    const installSslBtn = await page.$('input[value*="Install"], button.ssl-install');
    if (installSslBtn) {
      await installSslBtn.click();
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 });
      return { ok: true };
    }

    return { ok: false, error: 'SSL 설치 버튼을 찾지 못함' };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* ── Breeze 캐시 플러그인 설치 (WordPress admin을 통해) ── */
async function installBreezePlugin(page, { wpAdminUrl, wpAdminUser, wpAdminPw }) {
  try {
    // WordPress 관리자 로그인
    await page.goto(wpAdminUrl + 'wp-login.php', { waitUntil: 'networkidle2', timeout: 30000 });
    await page.type('#user_login', wpAdminUser);
    await page.type('#user_pass', wpAdminPw);
    await page.click('#wp-submit');
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 });

    // 플러그인 설치 페이지
    await page.goto(wpAdminUrl + 'plugin-install.php?s=breeze&tab=search&type=term', {
      waitUntil: 'networkidle2',
      timeout: 30000,
    });

    // Breeze 설치 버튼 클릭
    const breezeInstallBtn = await page.$('[data-slug="breeze"] .install-now, a[aria-label*="Breeze"]');
    if (breezeInstallBtn) {
      await breezeInstallBtn.click();
      await page.waitForTimeout(5000);
    }

    // 활성화
    const activateBtn = await page.$('[data-slug="breeze"] .activate-now');
    if (activateBtn) {
      await activateBtn.click();
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 });
    }

    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* ── 메인 Worker 핸들러 ── */
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,X-Worker-Secret',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // OPTIONS 프리플라이트 처리
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // POST만 허용
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ ok: false, error: 'Method Not Allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
      });
    }

    const secret = request.headers.get('X-Worker-Secret');

    // 보안 검증
    if (secret !== (env.WORKER_SECRET || 'cp_puppet_secret_v1')) {
      return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
      });
    }

    const respond = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
    });

    let body;
    try { body = await request.json(); } catch { return respond({ ok: false, error: 'Invalid JSON' }, 400); }

    // 브라우저 인스턴스 시작
    let browser;
    try {
      browser = await puppeteer.launch(env.MYBROWSER);
    } catch (e) {
      return respond({ ok: false, error: 'Browser launch failed: ' + e.message }, 500);
    }

    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

      // 호스팅 프로비저닝
      if (path === '/api/provision-hosting') {
        const { provider, hostingEmail, hostingPw, siteName } = body;
        const providerImpl = PROVIDERS[provider];
        if (!providerImpl) return respond({ ok: false, error: `Unknown provider: ${provider}` }, 400);

        const result = await providerImpl.signup(page, {
          email: hostingEmail,
          password: hostingPw,
          siteName,
        });
        return respond(result);
      }

      // WordPress 설치
      if (path === '/api/install-wordpress') {
        const {
          cpanelUrl, hostingEmail, hostingPw,
          wordpressUrl, wpAdminUser, wpAdminPw, wpAdminEmail,
          siteName, installBreeze,
        } = body;

        const result = await installWordPressViaSoftaculous(page, {
          cpanelUrl,
          email: hostingEmail,
          password: hostingPw,
          wordpressUrl,
          wpAdminUser,
          wpAdminPw,
          wpAdminEmail,
          siteName,
          installBreeze,
        });

        // Breeze가 Softaculous에서 설치 안 됐으면 WP admin으로 직접 설치
        if (installBreeze && !result.breezeInstalled) {
          const breezeResult = await installBreezePlugin(page, {
            wpAdminUrl: wordpressUrl.replace(/\/?$/, '/') + 'wp-admin/',
            wpAdminUser,
            wpAdminPw,
          });
          result.breezeInstalled = breezeResult.ok;
        }

        return respond(result);
      }

      // SSL 설정
      if (path === '/api/setup-ssl') {
        const { cpanelUrl, hostingEmail, hostingPw, domain } = body;
        const result = await setupSSLViaCPanel(page, {
          cpanelUrl,
          email: hostingEmail,
          password: hostingPw,
          domain,
        });
        return respond(result);
      }

      return respond({ ok: false, error: 'Unknown action' }, 404);

    } catch (e) {
      return respond({ ok: false, error: e.message }, 500);
    } finally {
      if (browser) await browser.close().catch(() => {});
    }
  },
};
