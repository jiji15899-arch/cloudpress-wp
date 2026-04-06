/* CloudPress CMS — wp-admin/media.js */
'use strict';

const API=`${location.origin}/wp-json/wp/v2`;
let mediaItems=JSON.parse(localStorage.getItem('cp_media')||'[]');
async function init(){
  const r=await fetch(`${API}/users/me`,{credentials:'include',headers:{'X-WP-Nonce':'cloudpress-nonce'}});
  if(!r.ok){location.href='/wp-login/';return;}
  const u=await r.json();document.getElementById('abUser').textContent=u.name;
  renderMedia();
  const drop=document.getElementById('uploadArea');
  drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('drag');});
  drop.addEventListener('dragleave',()=>drop.classList.remove('drag'));
  drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('drag');handleFiles(e.dataTransfer.files);});
}
function handleFiles(files){
  const msg=document.getElementById('uploadMsg');
  msg.style.display='';msg.style.background='#edfaef';msg.style.border='1px solid #8ddf8e';msg.style.color='#00a32a';
  msg.textContent=`${files.length}개 파일 업로드 중...`;
  Array.from(files).forEach(f=>{
    const reader=new FileReader();
    reader.onload=e=>{
      const item={id:Date.now()+Math.random(),name:f.name,type:f.type,size:f.size,url:e.target.result,date:new Date().toISOString()};
      mediaItems.unshift(item);
      localStorage.setItem('cp_media',JSON.stringify(mediaItems.slice(0,100)));
      renderMedia();
    };
    if(f.type.startsWith('image/'))reader.readAsDataURL(f);
    else{const item={id:Date.now()+Math.random(),name:f.name,type:f.type,size:f.size,url:'',date:new Date().toISOString()};mediaItems.unshift(item);localStorage.setItem('cp_media',JSON.stringify(mediaItems.slice(0,100)));renderMedia();}
  });
  setTimeout(()=>{msg.textContent=`${files.length}개 파일 업로드 완료 ✓`;setTimeout(()=>msg.style.display='none',2000);},500);
}
function renderMedia(){
  const grid=document.getElementById('mediaGrid');
  if(!mediaItems.length){grid.innerHTML='<div style="color:var(--muted);font-size:.88rem;padding:20px 0">미디어 라이브러리가 비어 있습니다.</div>';return;}
  grid.innerHTML=mediaItems.map(m=>`
    <div class="media-item" onclick="mediaDetail('${m.id}')">
      <div class="media-thumb">${m.url&&m.type?.startsWith('image/')?`<img src="${m.url}" alt="${m.name}">`:`<svg width="32" height="32" viewBox="0 0 24 24" fill="none" opacity=".3"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" stroke-width="1.5"/><polyline points="14 2 14 8 20 8" stroke="currentColor" stroke-width="1.5"/></svg>`}</div>
      <div class="media-name" title="${m.name}">${m.name}</div>
    </div>`).join('');
}
function mediaDetail(id){const m=mediaItems.find(x=>String(x.id)===String(id));if(m)alert(`파일명: ${m.name}\n크기: ${Math.round(m.size/1024)}KB\n종류: ${m.type}`);}
init();
