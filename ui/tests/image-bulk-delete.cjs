const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const base=process.env.PORTHUB_TEST_UI_URL;assert(base);
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome'});
 try{for(const width of [1440,402]){for(const guest of [false,true]){
  const context=await browser.newContext({serviceWorkers:'block',viewport:{width,height:950}}),page=await context.newPage();const state=makeDemoData();let dialogs=0,bulkCalls=[];
  let images=Array.from({length:guest?3:24},(_,i)=>({id:String(i+1).padStart(32,'0'),name:`Shot ${i+1}.png`,width:640,height:200,size:1024,created_at:'2026-11-11T01:00:00',expires_at:new Date(Date.now()+3600000).toISOString(),path:'/i/AbC23.png',url:`${base}/i/AbC23.png`,can_delete:!guest||i===0}));
  const roomId='a'.repeat(32),endpoint=guest?`/api/image-rooms/public/${roomId}/images`:'/api/images';
  page.on('dialog',async dialog=>{dialogs++;await dialog.dismiss();});
  await page.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
  await page.route('**/socket.io/**',r=>r.abort());await page.route('**/i/*.png',r=>r.fulfill({contentType:'image/png',body:Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a6i0AAAAASUVORK5CYII=','base64')}));
  await page.route('**/api/**',async route=>{
   const request=route.request(),path=new URL(request.url()).pathname,method=request.method().toLowerCase();let body;
   if(path===endpoint){
    if(method==='get')body={images,...(guest?{room:{name:'Bulk room',enabled:true,image_ttl_seconds:3600}}:{})};
    else if(method==='delete'){const input=request.postDataJSON();bulkCalls.push(input);const before=images.length;images=images.filter(image=>!(image.can_delete&&(input.all||input.ids.includes(image.id))));body={deleted_count:before-images.length};}
   }else{try{body=handleDemoRequest(state,method,request.url(),request.postDataJSON()||{});}catch{body={};}}
   await route.fulfill({contentType:'application/json',body:JSON.stringify(body)});
  });
  await page.goto(guest?`${base}/drop?room=${roomId}`:`${base}/home?view=images`);
  await page.getByRole('row').filter({hasText:'Shot 1.png'}).waitFor();
  const allLabel=guest?'Select all my images':'Select all images',deleteLabel=guest?'Delete all my images':'Delete all';
  if(guest){
   assert(await page.getByRole('checkbox',{name:'Select Shot 2.png',exact:true}).isDisabled());
   await page.getByRole('checkbox',{name:allLabel,exact:true}).check();await page.getByText('1 selected',{exact:true}).waitFor();
  }else{
   await page.getByRole('checkbox',{name:'Select Shot 1.png',exact:true}).check();await page.getByRole('button',{name:'Delete selected',exact:true}).click();
   const selected=page.getByRole('dialog',{name:'Delete selected images',exact:true});await selected.getByRole('button',{name:'Delete selected',exact:true}).click();await selected.waitFor({state:'hidden'});await page.getByRole('row').filter({hasText:'Shot 1.png'}).waitFor({state:'detached'});
   assert.deepEqual(bulkCalls[0],{ids:['1'.padStart(32,'0')]});assert.equal(images.length,23);
   await page.getByRole('checkbox',{name:allLabel,exact:true}).check();await page.getByText('23 selected',{exact:true}).waitFor();
   const pager=page.locator('footer[aria-label="Images pagination"]');if(width<768)await pager.getByRole('button',{name:'Next page',exact:true}).click();else await pager.getByRole('button',{name:'2',exact:true}).click();
   assert(await page.getByRole('checkbox',{name:'Select Shot 12.png',exact:true}).isChecked());
  }
  await page.getByRole('button',{name:deleteLabel,exact:true}).click();const confirm=page.getByRole('dialog',{name:'Delete all images',exact:true});await confirm.getByRole('button',{name:'Cancel',exact:true}).click();await confirm.waitFor({state:'hidden'});assert.equal(images.length,guest?3:23);
  await page.getByRole('button',{name:deleteLabel,exact:true}).click();await confirm.getByRole('button',{name:'Delete all',exact:true}).click();await confirm.waitFor({state:'hidden'});await page.waitForFunction(()=>document.getElementById('__next').getAttribute('aria-hidden')!=='true');
  assert.deepEqual(bulkCalls.at(-1),{all:true});assert.equal(images.length,guest?2:0);
  if(guest){await page.getByRole('row').filter({hasText:'Shot 2.png'}).waitFor();assert.equal(await page.getByRole('button',{name:'Delete all my images',exact:true}).count(),0);}else await page.getByText('Your images will appear here',{exact:true}).waitFor();
  assert.equal(dialogs,0);await context.close();
 }}
 console.log('Bulk deletion: individual selection, all-page selection, selected deletion, cancel/confirm delete-all, anonymous ownership restrictions, desktop and mobile passed.');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1});
