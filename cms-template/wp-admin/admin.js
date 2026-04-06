/* CloudPress CMS — wp-admin 공통 JS */
'use strict';

/* ── 인증 헬퍼 ── */
function getCmsToken(){
  const m=document.cookie.match(/cp_cms_session=([^;]+)/);
  return m?m[1]:'';
}
function cmsHeaders(){
  return{'Content-Type':'application/json','Authorization':'Bearer '+getCmsToken(),'X-WP-Nonce':'cloudpress-nonce'};
}

/* ── API 헬퍼 ── */
const BASE=()=>location.origin;
async function apiGet(path){
  const r=await fetch(BASE()+path,{credentials:'include',headers:cmsHeaders()});
  return r.json();
}
async function apiPost(path,data,method='POST'){
  const r=await fetch(BASE()+path,{method,credentials:'include',headers:cmsHeaders(),body:JSON.stringify(data)});
  return r.json();
}
async function apiPut(path,data){return apiPost(path,data,'PUT');}
async function apiDelete(path){
  const r=await fetch(BASE()+path,{method:'DELETE',credentials:'include',headers:cmsHeaders()});
  return r.json();
}

/* ── 로그인 체크 & 유저 정보 ── */
let _currentUser=null;
async function requireAuth(){
  if(_currentUser)return _currentUser;
  try{
    const d=await apiGet('/wp-json/wp/v2/users/me');
    if(d.id){_currentUser=d;return d;}
  }catch(_){}
  location.href='/wp-login/?redirect_to='+encodeURIComponent(location.pathname+location.search);
  return null;
}

/* ── 사이트 설정 로드 ── */
let _settings=null;
async function loadSettings(){
  if(_settings)return _settings;
  try{const d=await apiGet('/wp-json/wp/v2/settings');_settings=d;return d;}catch{return{};}
}

/* ── 사이드바 렌더링 ── */
function renderAdminBar(user,settings){
  const siteName=settings?.title||settings?.blogname||'내 사이트';
  const siteUrl=settings?.url||location.origin;
  const el=document.getElementById('wpadminbar');
  if(!el)return;
  el.innerHTML=`
    <a class="ab-logo" href="/wp-admin/"><svg width="18" height="18" viewBox="0 0 28 28" fill="none"><path d="M14 2L26 8V20L14 26L2 20V8L14 2Z" stroke="#fff" stroke-width="1.5"/><path d="M14 8L20 11V17L14 20L8 17V11L14 8Z" fill="#fff" opacity=".4"/><circle cx="14" cy="14" r="2.2" fill="#fff"/></svg>CP</a>
    <span class="ab-site-name"><a class="ab-item" href="${siteUrl}" target="_blank">${esc(siteName)}</a></span>
    <a class="ab-item" href="/wp-admin/">대시보드</a>
    <a class="ab-item" href="/wp-admin/post-new.html">+ 새 글</a>
    <span class="ab-spacer"></span>
    <span class="ab-user">안녕하세요, ${esc(user.name||user.login||'관리자')}님</span>
    <a class="ab-item" href="/wp-login/?action=logout" onclick="doLogout();return false;">로그아웃</a>`;
}

function renderSidebar(activePage){
  const el=document.getElementById('adminmenu');
  if(!el)return;
  const nav=[
    {href:'/wp-admin/',icon:'dashboard',label:'대시보드',page:'dashboard'},
    {href:'/wp-admin/post-new.html',icon:'edit',label:'새 글 쓰기',page:'post-new'},
    {href:'/wp-admin/edit.html',icon:'list',label:'글 목록',page:'edit'},
    {sep:true},
    {href:'/wp-admin/media.html',icon:'image',label:'미디어',page:'media'},
    {href:'/wp-admin/post-new.html?post_type=page',icon:'page',label:'페이지',page:'pages'},
    {sep:true},
    {href:'/wp-admin/themes.html',icon:'palette',label:'테마',page:'themes'},
    {href:'/wp-admin/plugins.html',icon:'plugin',label:'플러그인',page:'plugins'},
    {sep:true},
    {href:'/wp-admin/users.html',icon:'users',label:'사용자',page:'users'},
    {href:'/wp-admin/options-general.html',icon:'settings',label:'설정',page:'settings'},
  ];
  const icons={
    dashboard:'<rect x="3" y="3" width="7" height="7" rx="1" stroke="currentColor" stroke-width="1.5"/><rect x="14" y="3" width="7" height="7" rx="1" stroke="currentColor" stroke-width="1.5"/><rect x="3" y="14" width="7" height="7" rx="1" stroke="currentColor" stroke-width="1.5"/><rect x="14" y="14" width="7" height="7" rx="1" stroke="currentColor" stroke-width="1.5"/>',
    edit:'<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
    list:'<line x1="8" y1="6" x2="21" y2="6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><line x1="8" y1="12" x2="21" y2="12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><line x1="8" y1="18" x2="21" y2="18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><line x1="3" y1="6" x2="3.01" y2="6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="3" y1="12" x2="3.01" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="3" y1="18" x2="3.01" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    image:'<rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" stroke-width="1.5"/><circle cx="8.5" cy="8.5" r="1.5" stroke="currentColor" stroke-width="1.5"/><polyline points="21 15 16 10 5 21" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
    page:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" stroke-width="1.5"/><polyline points="14 2 14 8 20 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
    palette:'<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5"/>',
    plugin:'<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" stroke="currentColor" stroke-width="1.5"/><line x1="7" y1="7" x2="7.01" y2="7" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    users:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke="currentColor" stroke-width="1.5"/><circle cx="9" cy="7" r="4" stroke="currentColor" stroke-width="1.5"/><path d="M23 21v-2a4 4 0 0 0-3-3.87" stroke="currentColor" stroke-width="1.5"/><path d="M16 3.13a4 4 0 0 1 0 7.75" stroke="currentColor" stroke-width="1.5"/>',
    settings:'<circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" stroke="currentColor" stroke-width="1.5"/>',
  };
  el.innerHTML=`<ul>${nav.map(item=>{
    if(item.sep)return'<li class="separator"></li>';
    const isCur=item.page===activePage?'current':'';
    const ico=icons[item.icon]||'';
    return`<li class="${isCur}"><a href="${item.href}"><span class="menu-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none">${ico}</svg></span>${esc(item.label)}</a></li>`;
  }).join('')}</ul>
  <div class="collapse-wrap"><button class="collapse-btn" onclick="document.getElementById('adminmenu').classList.toggle('collapsed')">◀ 축소</button></div>`;
}

/* ── 토스트 알림 ── */
function showToast(msg,type='info',duration=3000){
  let wrap=document.getElementById('cp-toast');
  if(!wrap){wrap=document.createElement('div');wrap.id='cp-toast';document.body.appendChild(wrap);}
  const el=document.createElement('div');
  el.className=`cp-toast-item cp-toast-${type}`;
  el.textContent=msg;
  wrap.appendChild(el);
  setTimeout(()=>{el.style.opacity='0';el.style.transform='translateY(8px)';el.style.transition='all .3s';setTimeout(()=>el.remove(),300);},duration);
}

/* ── 로그아웃 ── */
async function doLogout(){
  document.cookie='cp_cms_session=; Path=/; Max-Age=0';
  location.href='/wp-login/';
}

/* ── 유틸 ── */
function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function formatDate(s){if(!s)return'—';try{const d=new Date(s);if(isNaN(d))return s;return d.toLocaleDateString('ko-KR',{year:'numeric',month:'long',day:'numeric',hour:'2-digit',minute:'2-digit'});}catch{return s;}}
function truncate(s,n=60){if(!s)return'';return s.length>n?s.slice(0,n)+'…':s;}

/* ── 공통 초기화 ── */
async function initAdminPage(activePage){
  const user=await requireAuth();if(!user)return null;
  const settings=await loadSettings();
  renderAdminBar(user,settings);
  renderSidebar(activePage);
  return{user,settings};
}

/* 전역 노출 */
window.CMS={apiGet,apiPost,apiPut,apiDelete,requireAuth,loadSettings,initAdminPage,showToast,doLogout,esc,formatDate,truncate,getCmsToken};
