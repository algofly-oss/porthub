const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const base=process.env.PORTHUB_TEST_UI_URL;assert(base);
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome'});
 try{for(const width of [1440,402]){
  let rooms=[],images=[],serial=0,nativeDialogs=0;const errors=[];
  const roomId='a'.repeat(32);let png;
  const contexts=[];
  async function client(){
   const context=await browser.newContext({serviceWorkers:'block',viewport:{width,height:950}});contexts.push(context);
   const page=await context.newPage();const demo=makeDemoData();
   page.on('pageerror',e=>errors.push(e.message));page.on('dialog',async d=>{nativeDialogs++;await d.dismiss();});
   await page.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;window.copiedLinks=[];Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>window.copiedLinks.push(text)}});});
   await page.route('**/socket.io/**',r=>r.abort());
   await page.route('**/r/*.png',r=>r.fulfill({contentType:'image/png',body:png}));
   await page.route('**/api/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname,method=request.method().toLowerCase();let body;
    const visitor=request.headers()['x-image-visitor'];
    const reply=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
    if(path==='/api/images')return reply({images:[]});
    if(path==='/api/image-rooms'){
     if(method==='get')return reply({rooms:rooms.map(room=>({...room,image_count:images.filter(i=>i.room_id===room.id).length,used:images.filter(i=>i.room_id===room.id).reduce((n,i)=>n+i.size,0)}))});
     const input=request.postDataJSON();const room={id:roomId,name:input.name||'Image room',image_ttl_seconds:input.image_ttl_seconds||3600,enabled:true,max_storage:512*1024*1024,path:`/drop?room=${roomId}`,url:`${base}/drop?room=${roomId}`};rooms.push(room);return reply(room);
    }
    if(path.startsWith('/api/image-rooms/')){
     const room=rooms[0];if(!room)return reply({detail:'Room or image not found'},404);
     if(path===`/api/image-rooms/${roomId}`){
      if(method==='patch'){Object.assign(room,request.postDataJSON());return reply(room);}
      if(method==='delete'){rooms=[];images=[];return route.fulfill({status:204});}
     }
     const isPublic=path.includes('/public/');
     const endpoint=isPublic?`/api/image-rooms/public/${roomId}/images`:`/api/image-rooms/${roomId}/images`;
     if(method==='get')return reply({room,images:images.filter(i=>Date.parse(i.expires_at)>Date.now()).map(({visitor:author,...i})=>({...i,can_delete:!isPublic||author===visitor})),max_storage:room.max_storage});
     if(method==='post'){
      if(!room.enabled)return reply({detail:'Uploads to this room are paused'},403);
      assert.match(visitor,/^[a-f0-9]{64}$/);
      const input=request.postDataJSON(),id=String(++serial).padStart(32,'0'),code=['AbC23','Def45','Ghj67','JKm89'][serial-1];
      const row={id,room_id:roomId,name:input.name,width:640,height:200,size:png.length,created_at:new Date().toISOString().replace('Z',''),expires_at:new Date(Date.now()+room.image_ttl_seconds*1000).toISOString(),path:`/r/${code}.png`,url:`${base}/r/${code}.png`,visitor};images.unshift(row);const {visitor:_,...response}=row;return reply({...response,can_delete:true});
     }
     if(method==='delete'){
      const id=path.split('/').at(-1),image=images.find(i=>i.id===id);
      if(!image||(isPublic&&image.visitor!==visitor))return reply({detail:'Image not found'},404);
      images=images.filter(i=>i.id!==id);return route.fulfill({status:204});
     }
    }
    try{body=handleDemoRequest(demo,method,request.url(),request.postDataJSON()||{});}catch{body={};}
    return reply(body);
   });
   return page;
  }
  const owner=await client();png=Buffer.from(await owner.evaluate(()=>{const c=document.createElement('canvas');c.width=640;c.height=200;const x=c.getContext('2d');x.fillStyle='#0f172a';x.fillRect(0,0,640,200);x.fillStyle='#fff';x.font='28px sans-serif';x.fillText('Public image room',32,80);return c.toDataURL('image/png').split(',')[1];}),'base64');await owner.goto(`${base}/home?view=images`);await owner.getByRole('button',{name:'Public rooms',exact:true}).click();
  await owner.getByText('Create your first public room',{exact:true}).waitFor();await owner.getByRole('button',{name:'New room',exact:true}).click();
  const form=owner.getByRole('dialog',{name:'New public room',exact:true});await form.getByLabel('Name',{exact:true}).fill('Quick room');assert.equal(await form.getByLabel('Image lifetime (minutes)',{exact:true}).inputValue(),'60');
  await form.getByRole('button',{name:'Create room',exact:true}).click();await form.waitFor({state:'hidden'});
  const row=owner.getByRole('table',{name:'Public image rooms'}).getByRole('row').filter({hasText:'Quick room'});await row.waitFor();
  assert.equal(await owner.getByLabel('Latest room URL').inputValue(),`${base}/drop?room=${roomId}`);
  async function roomAction(name){try {await row.getByRole('button',{name:'Room actions for Quick room'}).click({timeout:8000});await owner.getByRole('menuitem',{name,exact:true}).click();}catch(error){require('node:fs').writeFileSync('/tmp/porthub-room-production-failure.html',await owner.content());await owner.screenshot({path:'/tmp/porthub-room-production-failure.png'});console.error('Room action failed:',name,'width:',width,'rooms:',rooms.length,'url:',owner.url(),await owner.locator('body').innerText());throw error;}}
  await roomAction('Disable room');await row.getByText('Disabled',{exact:true}).waitFor();await roomAction('Enable room');await row.getByText('Enabled',{exact:true}).waitFor();
  const a=await client();await a.goto(`${base}/drop?room=${roomId}`);await a.getByRole('heading',{name:'Quick room',exact:true}).waitFor();
  await a.getByLabel('Choose images').setInputFiles({name:'alice.png',mimeType:'image/png',buffer:png});await a.getByRole('row').filter({hasText:'alice.png'}).waitFor();
  await a.waitForFunction(()=>window.copiedLinks.length===1);await a.getByRole('button',{name:'Copy link for alice.png',exact:true}).click();await a.waitForFunction(()=>window.copiedLinks.length===2);
  const aid=await a.evaluate(()=>localStorage.getItem('porthub:image-room-visitor:v1'));assert.match(aid,/^[a-f0-9]{64}$/);
  const b=await client();await b.goto(`${base}/drop?room=${roomId}`);await b.getByRole('row').filter({hasText:'alice.png'}).waitFor();assert.equal(await b.getByRole('button',{name:'Delete alice.png',exact:true}).count(),0);
  assert.notEqual(await b.evaluate(()=>localStorage.getItem('porthub:image-room-visitor:v1')),aid);
  await b.getByLabel('Choose images').setInputFiles({name:'bob.png',mimeType:'image/png',buffer:png});await b.getByRole('button',{name:'Delete bob.png',exact:true}).waitFor();
  const bid=await b.evaluate(()=>localStorage.getItem('porthub:image-room-visitor:v1'));await b.reload();await b.getByRole('button',{name:'Delete bob.png',exact:true}).waitFor();assert.equal(await b.evaluate(()=>localStorage.getItem('porthub:image-room-visitor:v1')),bid);
  await a.getByRole('button',{name:'Refresh images',exact:true}).click();await a.getByRole('row').filter({hasText:'bob.png'}).waitFor();assert.equal(await a.getByRole('button',{name:'Delete bob.png',exact:true}).count(),0);
  await roomAction('Inspect images');const inspection=owner.getByRole('region',{name:'Room inspection',exact:true});await inspection.getByRole('button',{name:'Delete bob.png',exact:true}).click();
  const confirm=owner.getByRole('dialog',{name:'Delete image',exact:true});await confirm.getByRole('button',{name:'Delete image',exact:true}).click();await confirm.waitFor({state:'hidden'});await inspection.getByRole('row').filter({hasText:'bob.png'}).waitFor({state:'detached'});
  assert(await inspection.isVisible(),'Room inspection stays open after deleting an image');
  await inspection.getByRole('button',{name:'← Back to rooms',exact:true}).click();
  await roomAction('Room settings');const settings=owner.getByRole('dialog',{name:'Room settings',exact:true});await settings.getByLabel('Image lifetime (minutes)',{exact:true}).fill('2');await settings.getByRole('button',{name:'Save settings',exact:true}).click();await settings.waitFor({state:'hidden'});
  assert.equal(rooms[0].image_ttl_seconds,120);
  if(process.env.PORTHUB_TEST_SCREENSHOT_DIR){require('node:fs').mkdirSync(process.env.PORTHUB_TEST_SCREENSHOT_DIR,{recursive:true});await a.screenshot({path:`${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/room-${width}.png`});}
  await a.getByRole('button',{name:'Delete alice.png',exact:true}).click();const ownDelete=a.getByRole('dialog',{name:'Delete image',exact:true});await ownDelete.waitFor();for(let key=0;key<5;key++){await a.keyboard.press('Tab');assert(await ownDelete.evaluate(node=>node.contains(document.activeElement)),'Keyboard focus stays in the dialog');}await ownDelete.getByRole('button',{name:'Delete image',exact:true}).click();await ownDelete.waitFor({state:'hidden'});await a.waitForFunction(()=>document.getElementById('__next').getAttribute('aria-hidden')!=='true');assert.equal(images.length,0);

  await roomAction('Delete room');const deletion=owner.getByRole('dialog',{name:'Delete room',exact:true});await deletion.getByRole('button',{name:'Delete room',exact:true}).click();await deletion.waitFor({state:'hidden'});await owner.getByText('Create your first public room',{exact:true}).waitFor();
  assert.equal(nativeDialogs,0);assert.deepEqual(errors,[]);for(const context of contexts)await context.close();
 }
 console.log('Public image rooms: owner creation/settings/toggle/inspection/deletion, anonymous upload and manual copy, separate visitor ownership, persistent browser identity, desktop and mobile passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
