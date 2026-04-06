/* CloudPress CMS — wp-admin/plugins.js */
'use strict';

const PLUGINS=[
  {name:'CloudPress SEO',slug:'cloudpress-seo',desc:'검색엔진 최적화(SEO) 메타 태그, 사이트맵, 오픈그래프 자동 생성. Yoast SEO 완전 호환.',version:'1.0.0',author:'CloudPress',active:true},
  {name:'CloudPress Cache',slug:'cloudpress-cache',desc:'Cloudflare Edge 캐시를 활용한 초고속 페이지 캐싱 플러그인.',version:'1.0.0',author:'CloudPress',active:true},
  {name:'CloudPress Forms',slug:'cloudpress-forms',desc:'드래그앤드롭 폼 빌더. 이메일 알림, 파일 업로드, 조건부 로직 지원.',version:'1.0.0',author:'CloudPress',active:false},
  {name:'CloudPress WooCommerce',slug:'cloudpress-woo',desc:'Cloudflare Pages에서 동작하는 완전한 전자상거래 솔루션.',version:'0.9.0-beta',author:'CloudPress',active:false},
];
const API=`${location.origin}/wp-json/wp/v2`;
async function init(){
  const r=await fetch(`${API}/users/me`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
  if(!r.ok){location.href='/wp-login/';return;}
  const u=await r.json();document.getElementById('abUser').textContent=u.name;
  renderPlugins();
}
function renderPlugins(){
  document.getElementById('pluginsTbody').innerHTML=PLUGINS.map(p=>`
    <tr class="${p.active?'active-row':''}">
      <td><div class="status-dot ${p.active?'dot-active':'dot-inactive'}"></div></td>
      <td>
        <div class="plugin-name">${p.name}</div>
        <div class="plugin-desc">${p.desc}</div>
        <div class="plugin-meta">by ${p.author}</div>
        <div class="plugin-actions">
          ${p.active
            ?`<a class="deactivate" onclick="togglePlugin('${p.slug}',false)">비활성화</a>`
            :`<a onclick="togglePlugin('${p.slug}',true)">활성화</a>`}
          <a>설정</a>
        </div>
      </td>
      <td><span style="font-size:.8rem">${p.version}</span></td>
      <td><span style="font-size:.8rem;font-weight:600;color:${p.active?'var(--ok)':'var(--muted)'}">${p.active?'활성화됨':'비활성화됨'}</span></td>
    </tr>`).join('');
}
function togglePlugin(slug,activate){
  const p=PLUGINS.find(x=>x.slug===slug);if(p)p.active=activate;renderPlugins();
}
init();
