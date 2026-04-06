/* CloudPress CMS — wp-admin/themes.js */
'use strict';

const THEMES=[
  {slug:'default',name:'CloudPress Default',author:'CloudPress',desc:'기본 제공 테마. 워드프레스 Twenty-style 디자인.', active:true},
  {slug:'minimal',name:'CloudPress Minimal',author:'CloudPress',desc:'미니멀하고 빠른 단일 컬럼 블로그 테마.',active:false},
  {slug:'magazine',name:'CloudPress Magazine',author:'CloudPress',desc:'뉴스, 매거진 스타일의 다단 레이아웃 테마.',active:false},
];
const API=`${location.origin}/wp-json/wp/v2`;
async function init(){
  const r=await fetch(`${API}/users/me`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
  if(!r.ok){location.href='/wp-login/';return;}
  const u=await r.json();document.getElementById('abUser').textContent=u.name;
  renderThemes();
}
function renderThemes(){
  const el=document.getElementById('themeBrowser');
  el.innerHTML=THEMES.map(t=>`
    <div class="theme-item${t.active?' active':''}">
      <div class="theme-screenshot">
        ${t.active?'<div class="active-badge">활성화됨</div>':''}
        <svg width="60" height="60" viewBox="0 0 24 24" fill="none" opacity=".3"><path d="M12 2L2 7l10 5 10-5-10-5z" stroke="currentColor" stroke-width="1.5"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.5"/></svg>
      </div>
      <div class="theme-info">
        <div class="theme-name">${t.name}</div>
        <div class="theme-author">by ${t.author}</div>
        <div style="font-size:.78rem;color:var(--muted);margin-top:6px">${t.desc}</div>
        <div class="theme-actions">
          ${t.active?'<span class="btn-sm" style="background:#edfaef;color:#00a32a;border:1px solid #8ddf8e">활성 테마</span>':'<button class="btn-sm btn-primary" onclick="activateTheme(\''+t.slug+'\')">활성화</button>'}
          <button class="btn-sm btn-ghost" onclick="previewTheme('${t.slug}')">미리보기</button>
        </div>
      </div>
    </div>`).join('');
}
async function activateTheme(slug){
  const r=await fetch(`${API}/settings`,{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json','X-WP-Nonce':'cloudpress-nonce'},body:JSON.stringify({active_theme:slug})});
  if(r.ok){THEMES.forEach(t=>t.active=t.slug===slug);renderThemes();alert(`${slug} 테마가 활성화되었습니다.`);}
}
function previewTheme(slug){window.open('/','_blank');}
init();
