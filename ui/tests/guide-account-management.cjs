const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const data=makeDemoData();
 const longPort="continuous-service-name-".repeat(8);
 const fixtureMachines=data.machines.slice(0,2).map((machine,index)=>({...machine,ports:[{...data.connections[index*2],service_name:longPort}]}));
 let signedIn=false,created=0,deleted=0;
 let accounts=[{user:{id:'000000000000000000000001',name:'Administrator',email:data.user.username,role:'admin'},machines:[]},{user:{id:'000000000000000000000002',name:'Example member',email:'member@example.invalid',role:'user'},machines:fixtureMachines}];
 process.env.NODE_ENV='production';process.env.NEXT_BUILD_DIR=process.env.REVIEW_BUILD_DIR||'.next-guide-review';
 const app=require('next')({dev:false,dir:path.resolve(__dirname,'..')});await app.prepare();
 const handler=app.getRequestHandler();
 const server=require('node:http').createServer(async(req,res)=>{
  if(!req.url.startsWith('/api/'))return handler(req,res);
  let body='';for await(const chunk of req)body+=chunk;
  let payload={};try{payload=JSON.parse(body||'{}');}catch{}
  let result,status=200;const pathname=new URL(req.url,'http://fixture').pathname;
  if(pathname==='/api/auth/me'){if(signedIn)result=data.user;else{status=400;result={detail:'User not logged in'};}}
  else if(pathname==='/api/admin/overview')result={data:accounts};
  else if(pathname==='/api/admin/users'&&req.method==='POST'){
   assert.equal(payload.email,'new@example.invalid');assert.equal(payload.password,'Fixture-Password1!');
   created++;const user={id:'000000000000000000000003',name:payload.name,email:payload.email,role:'user'};accounts.push({user,machines:[]});status=201;result={data:user};
  }else if(pathname==='/api/admin/users/000000000000000000000003'&&req.method==='DELETE'){
   assert.equal(payload.confirm_email,'new@example.invalid');deleted++;accounts=accounts.filter(a=>a.user.id!=='000000000000000000000003');result={msg:'Account and related resources deleted'};
  }else{try{result=handleDemoRequest(data,req.method.toLowerCase(),req.url,payload);}catch{result={data:[]};}}
  res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(result));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 const browser=await launchBrowser(),screens=process.env.REVIEW_SCREENSHOTS||'/tmp/porthub-guide-review';await fs.mkdir(screens,{recursive:true});
 try{
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  await context.addInitScript(scheme=>localStorage.setItem('mantine-color-scheme',JSON.stringify(scheme)),process.env.REVIEW_SCHEME||'light');
  const page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto(origin+'/account/signin');await page.getByRole('heading',{name:'Welcome back',exact:true}).waitFor();
  await page.getByLabel('Email',{exact:true}).fill('person@example.invalid');await page.getByLabel('Password',{exact:true}).fill('fixture');
  assert(await page.getByRole('region',{name:'About PortHub'}).isVisible());
  await page.screenshot({path:path.join(screens,'login-desktop.png'),fullPage:true});
  for(const width of [320,402]){
   await page.setViewportSize({width,height:874});await page.waitForTimeout(100);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'Login must fit mobile width');
   assert((await page.getByRole('main').boundingBox()).height>=873,'Login fills the viewport without a blank strip');
  }
  await page.screenshot({path:path.join(screens,'login-iphone.png'),fullPage:true});
  await page.getByRole('link',{name:'User guide',exact:true}).click();await page.getByRole('heading',{name:'Meet PortHub',exact:true}).waitFor();
  await page.getByRole('button',{name:'Open guide navigation'}).click();
  const drawer=page.getByRole('dialog');await drawer.getByRole('textbox',{name:'Search user guide'}).fill('filename');
  await drawer.getByRole('link',{name:/Download with get/}).click();await page.getByRole('heading',{name:'Download with get',exact:true}).waitFor();
  await page.getByRole('cell',{name:'download.bin',exact:true}).waitFor();
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'Guide must fit mobile width');
  await page.screenshot({path:path.join(screens,'guide-iphone.png'),fullPage:true});
  await page.setViewportSize({width:1440,height:1000});
  await page.keyboard.press('Control+k');await page.getByRole('textbox',{name:'Search user guide'}).fill('nothing-matches-this');
  await page.getByText('No matching pages.',{exact:false}).waitFor();await page.getByRole('button',{name:'Clear guide search'}).click();
  await page.getByRole('button',{name:'Copy command',exact:true}).first().click();await page.getByRole('button',{name:'Copied command'}).waitFor();
  await page.screenshot({path:path.join(screens,'guide-desktop.png'),fullPage:true});
  await page.waitForLoadState('networkidle');signedIn=true;
  await page.goto(origin+'/home?view=platform');await page.getByRole('heading',{name:'Platform Overview',exact:true}).waitFor();
  const disclosure=page.getByRole('button',{name:'View machines for Example member',exact:true});
  const chevron=await disclosure.boundingBox();const account=await disclosure.evaluate(element=>{const r=element.closest('tr').getBoundingClientRect();return {right:r.right};});
  assert(chevron.x+chevron.width>account.right-30,'Account chevron belongs at the far right');
  await disclosure.click();
  const fleet=page.getByRole('region',{name:'Platform results'}).locator('details:visible');await fleet.first().locator('summary').click();
  const portName=fleet.first().getByText(longPort,{exact:true});assert(await portName.evaluate(element=>element.scrollWidth<=element.clientWidth+1),'Long service names wrap');
  await fleet.first().locator('summary').hover();
  assert.notEqual(await fleet.first().locator('summary').evaluate(element=>getComputedStyle(element).backgroundColor),'rgba(0, 0, 0, 0)','The hovered machine gets its own highlight');
  assert.equal(await fleet.nth(1).locator('summary').evaluate(element=>getComputedStyle(element).backgroundColor),'rgba(0, 0, 0, 0)','Other machines do not highlight');
  assert.equal(await fleet.first().evaluate(element=>getComputedStyle(element.closest('tr')).backgroundColor),'rgba(0, 0, 0, 0)','Expanded account row must not highlight the entire fleet');
  await page.screenshot({path:path.join(screens,'platform-expanded.png'),fullPage:true});
  await page.getByRole('button',{name:'Create user',exact:true}).click();let modal=page.getByRole('dialog');
  await modal.getByLabel('Display name',{exact:true}).fill('New member');await modal.getByLabel('Email',{exact:true}).fill('new@example.invalid');await modal.getByLabel('Initial password',{exact:true}).fill('Fixture-Password1!');
  await page.waitForTimeout(250);await page.screenshot({path:path.join(screens,'admin-create.png'),fullPage:true});
  await modal.getByRole('button',{name:'Create account',exact:true}).click();await page.getByRole('dialog',{name:'Account created',exact:true}).waitFor();assert.equal(created,1);
  await page.getByRole('button',{name:'Done',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});
  await page.getByRole('button',{name:'Delete account new@example.invalid',exact:true}).click();modal=page.getByRole('dialog');
  const remove=modal.getByRole('button',{name:'Delete account',exact:true});assert(await remove.isDisabled());
  await modal.getByRole('textbox').fill('wrong@example.invalid');assert(await remove.isDisabled());assert.equal(deleted,0);
  await modal.getByRole('textbox').fill('new@example.invalid');assert(await remove.isEnabled());
  await page.waitForTimeout(250);await page.screenshot({path:path.join(screens,'admin-delete.png'),fullPage:true});
  await remove.click();await page.getByRole('dialog').waitFor({state:'hidden'});assert.equal(deleted,1);
  await page.getByRole('button',{name:'Delete account new@example.invalid',exact:true}).waitFor({state:'detached'});
  assert(await page.getByRole('button',{name:`Delete account ${data.user.username}`,exact:true}).isDisabled());
  for(const width of [320,402]) {
   await page.setViewportSize({width,height:874});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'Platform fits mobile width');
  }
  const mobileDisclosure=page.getByRole('button',{name:'View machines for Example member',exact:true});
  if(await mobileDisclosure.getAttribute('aria-expanded')!=='true')await mobileDisclosure.click();
  const mobileFleet=page.getByRole('region',{name:'Platform results'}).locator('details:visible').first();
  if(!await mobileFleet.getAttribute('open')) {if(await mobileFleet.getAttribute('open')===null)await mobileFleet.locator('summary').click();}
  assert(await mobileFleet.getByText(longPort,{exact:true}).evaluate(element=>element.scrollWidth<=element.clientWidth+1),'Mobile port names wrap');
  await page.screenshot({path:path.join(screens,'platform-iphone.png'),fullPage:true});
  await page.waitForLoadState('networkidle');
  await page.getByRole('button',{name:'More navigation',exact:true}).click();
  await page.getByRole('link',{name:'User guide',exact:true}).click();
  await page.getByRole('heading',{name:'Meet PortHub',exact:true}).waitFor();
  await page.evaluate(()=>window.scrollTo(0,document.body.scrollHeight));await page.waitForTimeout(100);
  assert(await page.evaluate(()=>window.scrollY>0),'Guide stays scrollable when opened from the workspace');
  assert.deepEqual(errors,[]);console.log('PASS responsive sign-in, guide navigation/search/copy, admin account creation and confirmed deletion');
  await context.close();
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));await app.close();}
})().catch(error=>{console.error(error);process.exitCode=1});
