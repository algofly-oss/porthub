const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const {bootstrapCommand,windowsShells}=await import('../src/shared/utils/bootstrap-command.mjs');
 const bootstrap='https://hub.example/install/test-ticket';
 const browser=await launchBrowser();
 try {for(const width of [1440,402]) {
  const state=makeDemoData();
  const context=await browser.newContext({viewport:{width,height:1000},serviceWorkers:'block',permissions:['clipboard-read','clipboard-write']});
  await context.addInitScript(()=>{delete Navigator.prototype.serviceWorker;});
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/**',async route=>{
   const request=route.request();let body={};try{body=request.postDataJSON()||{}}catch{}
   let response;
   try {response=handleDemoRequest(state,request.method().toLowerCase(),request.url(),body);}
   catch {await route.fulfill({status:404,json:{detail:"Unavailable in installer fixture"}});return;}

   if(new URL(request.url()).pathname.includes('/command/')) response.data={...response.data,bootstrap_url:bootstrap,command:bootstrapCommand(bootstrap,'linux')};
   await route.fulfill({json:response});
  });
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3108'}/home?view=machines`);
  await page.getByRole('button',{name:`Configure ${state.machines[0].name}`,exact:true}).click();
  const dialog=page.getByRole('dialog',{name:/^Configure /});
  await dialog.getByRole('button',{name:'Client',exact:true}).click();
  const operatingSystem=dialog.getByRole('group',{name:'Install operating system',exact:true});
  await operatingSystem.getByRole('button',{name:'Windows',exact:true}).click();
  await dialog.getByText(bootstrapCommand(bootstrap,'windows'),{exact:true}).waitFor();
  await dialog.getByRole('button',{name:'Copy bootstrap command',exact:true}).click();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),bootstrapCommand(bootstrap,'windows'));
  for(const shell of windowsShells) {
   await dialog.getByRole('combobox',{name:'Windows shell',exact:true}).selectOption(shell.id);
   await dialog.getByText(bootstrapCommand(bootstrap,'windows',shell.id),{exact:true}).waitFor();
   await dialog.getByRole('button',{name:'Copy bootstrap command',exact:true}).click();
   assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),bootstrapCommand(bootstrap,'windows',shell.id));
  }
  assert.equal(await dialog.getByRole('link',{name:'Download .bat',exact:true}).getAttribute('href'),`${bootstrap}/windows.bat`);
  assert.equal(await dialog.getByRole('link',{name:'Download .ps1',exact:true}).getAttribute('href'),`${bootstrap}/windows.ps1`);
  assert(await dialog.getByText(/Paste into the selected shell/).isVisible());
  await dialog.screenshot({path:`/tmp/porthub-windows-install-${width}.png`});
  await operatingSystem.getByRole('button',{name:'Linux',exact:true}).click();
  await dialog.getByText(bootstrapCommand(bootstrap,'linux'),{exact:true}).waitFor();
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  assert.deepEqual(errors,[]);await context.close();console.log(`PASS ${width}: Windows launcher rendered/copied; PowerShell and cmd guidance; Linux/WSL preserved`);
 }}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
