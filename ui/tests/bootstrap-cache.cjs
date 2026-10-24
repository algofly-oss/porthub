const {launchBrowser}=require('./browser.cjs');
const assert=require('node:assert/strict');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const state=makeDemoData();
 const browser=await launchBrowser();
 const page=await browser.newPage({viewport:{width:1512,height:982},serviceWorkers:'block'});
 // These fixtures mock API traffic; disable PWA registration as well as its network interception.
 await page.addInitScript(()=>{delete Navigator.prototype.serviceWorker;});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 let commandRequests=0,releasePreview,notifyPreviewStart;
 const previewStarted=new Promise(resolve=>notifyPreviewStart=resolve);
 await page.route('**/api/**',async route=>{
  const req=route.request();let body={};try{body=req.postDataJSON()||{}}catch{}
  const response=handleDemoRequest(state,req.method().toLowerCase(),req.url(),body);
  if(new URL(req.url()).pathname.includes('/command/')) {
   commandRequests++;
   if(new URL(req.url()).search) {
    await new Promise(resolve=>{releasePreview=resolve;notifyPreviewStart();});
    response.data.command='porthub setup preview-command';
   } else response.data.command='porthub setup saved-command';
  }
  await route.fulfill({json:response}).catch(()=>{});
 });
 try {
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:47130'}/home?view=machines`);
  await page.getByRole('button',{name:`Configure ${state.machines[0].name}`,exact:true}).click();
  const dialog=page.getByRole('dialog',{name:/^Configure /});
  await dialog.getByRole('button',{name:'Client',exact:true}).click();
  await dialog.getByText('porthub setup saved-command',{exact:true}).waitFor();
  assert.equal(commandRequests,1);
  const advanced=dialog.getByRole('button',{name:/^Advanced settings/});
  for(let i=0;i<2;i++) {
   await advanced.click();await page.waitForTimeout(450);
   assert.equal(commandRequests,1,'expanding unchanged settings must not refetch');
   assert.equal(await dialog.getByText('Loading bootstrap command...',{exact:true}).count(),0);
   await advanced.click();
  }
  await advanced.click();
  await dialog.getByLabel('PortHub access URL',{exact:true}).fill('https://changed.invalid');
  await page.waitForFunction(()=>document.querySelector('button[aria-label="Copy bootstrap command"]')?.disabled);
  await dialog.getByText('porthub setup saved-command',{exact:true}).waitFor();
  assert.equal(await dialog.getByText('Loading bootstrap command...',{exact:true}).count(),0,'keep command visible during refresh');
  await previewStarted;
  assert.equal(commandRequests,2);
  assert(releasePreview);
  releasePreview();
  await dialog.getByText('porthub setup preview-command',{exact:true}).waitFor();
  await advanced.click();await advanced.click();await page.waitForTimeout(450);
  assert.equal(commandRequests,2,'reopening an unchanged draft must reuse its preview');
  await dialog.getByLabel('PortHub access URL',{exact:true}).fill('https://preview.invalid');
  await dialog.getByText('porthub setup saved-command',{exact:true}).waitFor();
  assert.equal(commandRequests,2,'reverting must reuse the saved command');
  assert.deepEqual(errors,[]);
  console.log('PASS unchanged advanced settings do not refetch; cached commands remain visible; changed drafts refresh; reverting reuses saved command');
 } finally {releasePreview?.();await browser.close()}
})().catch(error=>{console.error(error);process.exit(1)});
