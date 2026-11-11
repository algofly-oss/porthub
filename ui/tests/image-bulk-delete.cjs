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
  const size=page.getByLabel('Images per page',{exact:true});
  const waitForAuto=()=>page.waitForFunction(()=>{
   const table=document.querySelector('table[aria-label="Hosted images"]'),viewport=table?.parentElement,row=table?.querySelector('tbody tr');
   if(!row)return false;
   const fitted=Math.max(1,Math.min(1000,Math.floor((viewport.clientHeight-table.querySelector('thead').getBoundingClientRect().height)/row.getBoundingClientRect().height)));
   return document.querySelector('[aria-label="Images per page"]').value===`Auto (${fitted})`;
  });
  await waitForAuto();
  if(!guest&&width>=768){
   const fitted=Number((await size.inputValue()).match(/\d+/)[0]);
   await page.setViewportSize({width,height:1300});
   await page.waitForFunction(previous=>Number(document.querySelector('[aria-label="Images per page"]').value.match(/\d+/)[0])>previous,fitted);
   const filled=await page.getByRole('table',{name:'Hosted images'}).evaluate(table=>{const viewport=table.parentElement,row=table.querySelector('tbody tr');return viewport.clientHeight-table.getBoundingClientRect().height<row.getBoundingClientRect().height+2;});
   assert(filled,'Auto pagination uses the available table height');
   const expanded=Number((await size.inputValue()).match(/\d+/)[0]);
   await page.setViewportSize({width,height:950});
   await waitForAuto();
   assert(Number((await size.inputValue()).match(/\d+/)[0])<expanded,'Auto pagination adapts when the available height shrinks');
  }
  await size.click();await page.getByRole('option',{name:'10 / page',exact:true}).click();
  const allLabel=guest?'Select all my images':'Select all images';
  const heading=page.locator('header.page-heading').filter({has:page.getByRole('button',{name:'Refresh images',exact:true})});
  const selection=heading.getByRole('group',{name:'Image selection',exact:true});
  assert.equal(await selection.count(),0,'Bulk actions are hidden before selection');
  assert.equal(await heading.getByRole('button',{name:'Delete all',exact:true}).count(),0);
  const first=page.getByRole('checkbox',{name:'Select Shot 1.png',exact:true});
  await first.check();await selection.waitFor();await page.getByText('1 selected',{exact:true}).waitFor();
  assert(await heading.evaluate(node=>node.scrollWidth<=node.clientWidth+1),'Contextual actions fit the available width');
  if(width>=768){const deletion=await selection.getByRole('button',{name:'Delete selected',exact:true}).boundingBox(),refresh=await heading.getByRole('button',{name:'Refresh images',exact:true}).boundingBox();assert(deletion.x+deletion.width<=refresh.x,'Selection actions are left of Refresh');assert(Math.abs(deletion.y+deletion.height/2-refresh.y-refresh.height/2)<2,'Selection actions share the top row');}
  await selection.getByRole('button',{name:'Clear selection',exact:true}).click();await selection.waitFor({state:'detached'});assert.equal(await first.isChecked(),false);
  await first.check();
  if(guest){
   assert(await page.getByRole('checkbox',{name:'Select Shot 2.png',exact:true}).isDisabled());
  }else{
   await selection.getByRole('button',{name:'Delete selected',exact:true}).click();
   const dialog=page.getByRole('dialog',{name:'Delete selected images',exact:true});await dialog.getByRole('button',{name:'Delete selected',exact:true}).click();await dialog.waitFor({state:'hidden'});await page.getByRole('row').filter({hasText:'Shot 1.png'}).waitFor({state:'detached'});
   assert.deepEqual(bulkCalls[0],{ids:['1'.padStart(32,'0')]});assert.equal(images.length,23);await selection.waitFor({state:'detached'});
   await page.getByRole('checkbox',{name:'Select Shot 2.png',exact:true}).check();
  }
  await selection.getByRole('checkbox',{name:allLabel,exact:true}).check();await page.getByText(guest?'1 selected':'23 selected',{exact:true}).waitFor();
  if(!guest){const pager=page.locator('footer[aria-label="Images pagination"]');if(width<768)await pager.getByRole('button',{name:'Next page',exact:true}).click();else await pager.getByRole('button',{name:'2',exact:true}).click();assert(await page.getByRole('checkbox',{name:'Select Shot 12.png',exact:true}).isChecked());}
  await selection.getByRole('button',{name:'Delete selected',exact:true}).click();const confirm=page.getByRole('dialog',{name:'Delete selected images',exact:true});await confirm.getByRole('button',{name:'Cancel',exact:true}).click();await confirm.waitFor({state:'hidden'});assert.equal(images.length,guest?3:23);
  await selection.getByRole('button',{name:'Delete selected',exact:true}).click();await confirm.getByRole('button',{name:'Delete selected',exact:true}).click();await confirm.waitFor({state:'hidden'});await selection.waitFor({state:'detached'});
  assert.equal(bulkCalls.at(-1).ids.length,guest?1:23);assert.equal(bulkCalls.at(-1).all,undefined);assert.equal(images.length,guest?2:0);
  if(guest)await page.getByRole('row').filter({hasText:'Shot 2.png'}).waitFor();else await page.getByText('Your images will appear here',{exact:true}).waitFor();
  assert.equal(dialogs,0);await context.close();
 }}
 console.log('Contextual selection: hidden default actions, clear selection, all-page selection, confirmed deletion, anonymous ownership restrictions, desktop and mobile passed.');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1});
