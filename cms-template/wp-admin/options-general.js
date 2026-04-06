/* CloudPress CMS — wp-admin/options-general.js */
'use strict';

let activeTab='general';

(async()=>{
  const ctx=await CMS.initAdminPage('settings');if(!ctx)return;
  const s=ctx.settings;
  if(!s)return;
  document.getElementById('blogname').value=s.title||s.blogname||'';
  document.getElementById('blogdescription').value=s.description||s.blogdescription||'';
  document.getElementById('siteurl').value=s.url||location.origin;
  document.getElementById('admin_email').value=s.email||'';
  document.getElementById('timezone_string').value=s.timezone||'Asia/Seoul';
  document.getElementById('date_format').value=s.date_format||'Y년 n월 j일';
  document.getElementById('time_format').value=s.time_format||'H:i';
  document.getElementById('posts_per_page').value=s.posts_per_page||10;
  document.getElementById('show_on_front').value=s.show_on_front||'posts';
  document.getElementById('blog_public').checked=s.blog_public!==false;
})();

function showTab(t){
  document.querySelectorAll('[id^="tab-"]').forEach(el=>el.style.display='none');
  document.getElementById('tab-'+t).style.display='';
  document.querySelectorAll('.nav-tab').forEach(el=>el.classList.remove('nav-tab-active'));
  event.target.classList.add('nav-tab-active');
  activeTab=t;
}

async function saveGeneral(){
  const data={
    title:document.getElementById('blogname').value.trim(),
    blogname:document.getElementById('blogname').value.trim(),
    description:document.getElementById('blogdescription').value.trim(),
    email:document.getElementById('admin_email').value.trim(),
    timezone:document.getElementById('timezone_string').value,
    date_format:document.getElementById('date_format').value,
    time_format:document.getElementById('time_format').value,
    posts_per_page:parseInt(document.getElementById('posts_per_page').value)||10,
  };
  const r=await CMS.apiPost('/wp-json/wp/v2/settings',data,'POST');
  if(r.url||r.title){CMS.showToast('설정이 저장되었습니다','success');}
  else CMS.showToast('저장 실패: '+(r.message||'알 수 없는 오류'),'error');
}

async function saveReading(){
  const data={
    show_on_front:document.getElementById('show_on_front').value,
    blog_public:document.getElementById('blog_public').checked,
  };
  const r=await CMS.apiPost('/wp-json/wp/v2/settings',data,'POST');
  if(r.url||r.title)CMS.showToast('읽기 설정이 저장되었습니다','success');
  else CMS.showToast('저장 실패','error');
}

async function changePassword(){
  const cur=document.getElementById('currentPassword').value;
  const np=document.getElementById('newPassword').value;
  const np2=document.getElementById('newPassword2').value;
  if(!cur||!np){CMS.showToast('현재 비밀번호와 새 비밀번호를 입력해주세요','warning');return;}
  if(np!==np2){CMS.showToast('새 비밀번호가 일치하지 않습니다','error');return;}
  if(np.length<8){CMS.showToast('비밀번호는 8자 이상이어야 합니다','error');return;}
  const r=await CMS.apiPut('/wp-json/wp/v2/users/me',{password:np});
  if(r.id){CMS.showToast('비밀번호가 변경되었습니다. 다시 로그인해주세요','success');setTimeout(()=>CMS.doLogout(),2000);}
  else CMS.showToast('변경 실패: '+(r.message||'현재 비밀번호를 확인해주세요'),'error');
}

/* ── 비밀번호 표시/숨기기 ── */
function togglePwVis(inputId,btn){
  const inp=document.getElementById(inputId);
  const shown=inp.type==='text';
  inp.type=shown?'password':'text';
  btn.querySelector('svg').innerHTML=shown
    ?'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5"/>'
    :'<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><line x1="1" y1="1" x2="23" y2="23" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>';
}
