const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
let origin=process.env.REVIEW_ORIGIN||'http://127.0.0.1:5300';
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const state=makeDemoData();const browser=await launchBrowser();
 let mode='unavailable',releasePending,hold=false,phase='startup';
 let server,app;const timeline=[];
 async function responseFor(method,url,body){
  const path=new URL(url,origin).pathname;if(path.startsWith('/api/auth/'))timeline.push({path,mode,hold,phase});
  if(path==='/api/auth/signout'){mode='anonymous';return {json:{msg:'success'},headers:{'Set-Cookie':'porthub_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'}};}
  if(path==='/api/auth/me'){
   if(hold){hold=false;await new Promise(resolve=>releasePending=resolve);return {json:state.user};}
   if(mode==='unavailable')return {status:503,json:{detail:'Temporary network failure'}};
   if(mode==='anonymous')return {status:401,json:{detail:'Not signed in'}};
  }
  let data;try{data=handleDemoRequest(state,method.toLowerCase(),url,body);}catch{data={data:[]};}
  return {json:data};
 }
 async function prepare(context){
  if(server)return;
  await context.route('**/api/**',async route=>{
   const req=route.request();let body={};try{body=req.postDataJSON()||{};}catch{}
   return route.fulfill(await responseFor(req.method(),req.url(),body));
  });
 }
 try{
  if(process.env.SESSION_TEST_BUILD_DIR){
   process.env.NODE_ENV='production';process.env.NEXT_BUILD_DIR=process.env.SESSION_TEST_BUILD_DIR;
   app=require('next')({dev:false,dir:require('node:path').resolve(__dirname,'..')});await app.prepare();
   const handler=app.getRequestHandler();
   server=require('node:http').createServer(async(req,res)=>{
    if(!req.url.startsWith('/api/'))return handler(req,res);
    try{
     let raw='';for await(const chunk of req)raw+=chunk;
     const result=await responseFor(req.method,req.url,raw?JSON.parse(raw):{});
     if(res.destroyed)return;
     res.writeHead(result.status||200,{'Content-Type':'application/json','Cache-Control':'no-store',...result.headers});res.end(JSON.stringify(result.json));
    }catch{if(!res.destroyed){res.statusCode=500;res.end();}}
   });
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
  }
  let context=await browser.newContext({viewport:{width:402,height:874},isMobile:true,hasTouch:true});await prepare(context);
  await context.addCookies([{name:'porthub_session',value:'isolated-session-fixture',url:origin,httpOnly:true,sameSite:'Lax',expires:Math.floor(Date.now()/1000)+86400}]);
  let page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push({phase,message:e.message,stack:e.stack}));
  await page.goto(origin+'/home');await page.getByRole('alert').filter({hasText:'saved session has not been cleared'}).waitFor();
  assert.equal(new URL(page.url()).pathname,'/home');assert((await context.cookies()).some(c=>c.name==='porthub_session'));
  mode='ready';await page.getByRole('button',{name:'Try again',exact:true}).click();await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
  mode='unavailable';await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await page.waitForTimeout(300);
  assert.equal(new URL(page.url()).pathname,'/home');assert(await page.getByRole('heading',{name:'Dashboard',exact:true}).isVisible());
  await page.reload();await page.getByRole('alert').filter({hasText:'saved session has not been cleared'}).waitFor();assert.equal(new URL(page.url()).pathname,'/home');
  phase='closing first context';const storage=await context.storageState();await context.close();phase='reopening';
  mode='ready';context=await browser.newContext({viewport:{width:402,height:874},isMobile:true,hasTouch:true,storageState:storage});await prepare(context);page=await context.newPage();page.on('pageerror',e=>errors.push({phase,message:e.message,stack:e.stack}));
  await page.goto(origin+'/home');await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
  phase='revocation';mode='anonymous';await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await page.waitForURL('**/account/signin');
  await page.getByRole('button',{name:'Sign in',exact:true}).waitFor();await page.waitForLoadState('networkidle');
  phase='restore';mode='ready';await page.goto(origin+'/home');await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
  await page.waitForLoadState('networkidle');phase='logout race';await page.setViewportSize({width:1512,height:982});hold=true;await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
  for(let n=0;n<100&&!releasePending;n++)await new Promise(resolve=>setTimeout(resolve,50));
  assert.equal(typeof releasePending,'function','The pre-logout account request must be pending before signing out');
  await page.getByRole('button',{name:'Log out',exact:true}).click();
  const dialog=page.getByRole('dialog');await dialog.getByRole('button',{name:/log out|sign out/i}).click();
  try{await page.waitForURL('**/account/signin',{timeout:10000});}catch(error){console.log(JSON.stringify(timeline));console.log(await page.locator('body').innerText());throw error;}releasePending();await page.waitForTimeout(250);
  assert.equal(new URL(page.url()).pathname,'/account/signin','An old account response cannot restore a signed-out session');
  assert(!(await context.cookies()).some(c=>c.name==='porthub_session'),'Explicit logout clears the cookie');assert.deepEqual(errors,[]);
  console.log('PASS persistent session across 503, resume, reload and browser-context restart; 401 redirects; logout fences late responses');
  await context.close();
 }finally{if(releasePending)releasePending();await browser.close();if(server)await new Promise(resolve=>server.close(resolve));if(app)await app.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
