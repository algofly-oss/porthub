const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const { launchBrowser } = require("./browser.cjs");

// Production-only app on a temporary loopback port. All API data is fabricated;
// this test never connects to the deployed API, database, or firewall.
process.env.NODE_ENV = "production";
process.env.NEXT_BUILD_DIR ||= ".next-verify-goal";
process.env.NEXT_TELEMETRY_DISABLED = "1";

(async () => {
  const {makeDemoData,handleDemoRequest} = await import("../src/shared/demo/data.mjs");
  const state = makeDemoData();
  const app = require("next")({dev:false,dir:path.resolve(__dirname,"..")});
  let server, browser, privateReads=0;
  try {
    await app.prepare();
    const handler=app.getRequestHandler();
    server=http.createServer(async (request,response)=>{
      if(request.url==="/audit-bootstrap") {response.setHeader("Content-Type","text/html");response.end("<!doctype html><title>Isolated PWA Audit</title>");return;}
      if(request.url==="/audit-old-worker.js") {
        response.setHeader("Content-Type","application/javascript");
        response.end(`self.addEventListener("install",event=>event.waitUntil((async()=>{
          const cache=await caches.open("legacy-api-audit");
          if(!(await cache.match("/audit-public-static"))) {
            await cache.put("/api/audit-private",new Response(JSON.stringify({privateFixture:"old"})));
            await cache.put("/audit-public-static",new Response("Public fixture"));
          }
          await self.skipWaiting();
        })()));self.addEventListener("activate",event=>event.waitUntil(self.clients.claim()));`);
        return;
      }
      if(request.url==="/audit-public-static") {response.end("Public fixture");return;}
      if(request.url.startsWith("/api/")) {
        let payload=""; for await(const chunk of request)payload+=chunk;
        let data;
        try {data=request.url==="/api/audit-private"?{privateFixture:true,read:++privateReads}:handleDemoRequest(state,request.method.toLowerCase(),request.url,payload?JSON.parse(payload):{});}
        catch(error){response.statusCode=400;data={detail:error.message};}
        response.setHeader("Content-Type","application/json");response.end(JSON.stringify(data));return;
      }
      return handler(request,response);
    });
    await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
    const origin=`http://127.0.0.1:${server.address().port}`;
    browser=await launchBrowser();
    const context=await browser.newContext({viewport:{width:402,height:874}});
    const page=await context.newPage();
    async function cacheDiagnostic(label) {
      if(!process.env.PWA_DEBUG)return;
      const diagnostic=await page.evaluate(async()=>({controller:navigator.serviceWorker.controller?.scriptURL,caches:await Promise.all((await caches.keys()).map(async name=>({name,entries:await Promise.all((await(await caches.open(name)).keys()).filter(request=>request.url.includes("audit-")).map(async request=>({url:request.url,body:await(await(await caches.open(name)).match(request))?.text()})))})))}));
      console.log(label,JSON.stringify(diagnostic));
    }
    const errors=[];page.on("pageerror",error=>errors.push(error.message));
    await page.goto(`${origin}/audit-bootstrap`);
    await page.evaluate(()=>navigator.serviceWorker.register("/audit-old-worker.js"));
    await page.waitForFunction(()=>navigator.serviceWorker.controller?.scriptURL.endsWith("/audit-old-worker.js"));
    assert(await page.evaluate(async()=>!!await caches.match("/audit-public-static")),"Legacy worker seeded the public fixture");
    assert(await page.evaluate(async()=>!!await caches.match("/api/audit-private")),"Legacy worker seeded the private fixture");
    await cacheDiagnostic("Seeded");
    await page.goto(`${origin}/offline`);
    await page.getByRole("heading",{name:"You’re Offline",exact:true}).waitFor();
    await page.waitForFunction(()=>navigator.serviceWorker.controller?.scriptURL.endsWith("/sw.js")&&navigator.serviceWorker.controller.state==="activated");
    // clients.claim() can attach the new worker before its other activation
    // tasks finish. Inspect actual cache keys, not a relative match shortcut.
    assert(await page.evaluate(async()=>{
      const entries=(await Promise.all((await caches.keys()).map(async name=>(await(await caches.open(name)).keys()).map(request=>request.url)))).flat();
      return !entries.some(url=>new URL(url).pathname.startsWith("/api/"));
    }),"Activated worker finished removing legacy API cache entries");
    assert(await page.evaluate(async()=>!!await caches.match("/audit-public-static")),"Cache upgrade preserves public assets");
    await cacheDiagnostic("Purged");
    const manifest=await (await context.request.get(`${origin}/manifest.json`)).json();
    assert.equal(manifest.display,"standalone");assert.equal(manifest.start_url,"/home");
    for(const icon of manifest.icons) {
      const response=await context.request.get(new URL(icon.src,origin).href);assert(response.ok(),icon.src);
      if(icon.type==="image/png") {
        const bytes=await response.body();assert.equal(bytes.toString("hex",0,8),"89504e470d0a1a0a");
        const [width,height]=icon.sizes.split("x").map(Number);assert.equal(bytes.readUInt32BE(16),width);assert.equal(bytes.readUInt32BE(20),height);
      }
    }
    const privateData=await page.evaluate(async()=>await(await fetch("/api/audit-private")).json());
    await cacheDiagnostic("Fetched");
    assert.equal(privateData.privateFixture,true);assert.equal(privateReads,1);
    const cachedPrivate=await page.evaluate(async()=>{const names=await caches.keys();return(await Promise.all(names.map(async name=>(await(await caches.open(name)).keys()).filter(request=>new URL(request.url).pathname==="/api/audit-private").map(request=>({cache:name,url:request.url}))))).flat();});
    assert.deepEqual(cachedPrivate,[],"Private API responses are not cached");
    const cacheEntries=await page.evaluate(async()=>{const names=await caches.keys();return(await Promise.all(names.map(async name=>(await(await caches.open(name)).keys()).map(request=>request.url)))).flat();});
    assert(!cacheEntries.some(url=>new URL(url).pathname.startsWith("/api/")),"No cached account, machine, proxy, or traffic APIs");
    console.log("PASS production manifest/icons, active service worker, legacy API cache purge, public asset preservation, network-only API policy");
    await context.setOffline(true);
    const unavailable=await page.evaluate(async()=>{const response=await fetch("/api/audit-private");return{status:response.status,body:await response.json()};});
    assert.equal(unavailable.status,503,"Offline private API returns an honest unavailable state, never stale data");
    assert.match(unavailable.body.detail,/unreachable/i);
    assert.equal(privateReads,1,"Offline fetch does not reach the server or replay a previous API response");
    await page.goto(`${origin}/uncached-offline-audit`);
    await page.getByRole("heading",{name:"You’re Offline",exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth && scrollY===0),true);
    await page.screenshot({path:`/tmp/porthub-pwa-offline-${process.env.REVIEW_BROWSER||"chromium"}.png`});
    await context.setOffline(false);
    await page.getByRole("button",{name:"Try Again",exact:true}).click();
    await page.getByRole("heading",{name:"Dashboard",exact:true}).waitFor();
    assert.deepEqual(errors,[]);
    console.log("PASS offline fallback, honest unavailable API state, phone layout, reconnect to workspace, no browser errors");
  } finally {
    await browser?.close();
    if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections?.();});
    await app.close();
  }
// Next 13 retains internal cache timers after app.close(). All owned browser
// and HTTP resources are closed above before the standalone test process exits.
})().then(()=>process.exit(0),error=>{console.error(error);process.exit(1);});
