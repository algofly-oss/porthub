const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");

(async()=>{
  const {makeDemoData}=await import("../src/shared/demo/data.mjs");
  const connection=makeDemoData().connections.find(port=>port.machine_is_active&&port.internal_port===8080);
  const browser=await launchBrowser();
  try{
    for(const theme of ["light","dark"])for(const [width,height]of [[402,874],[1512,982],[3840,2160]]){
      const context=await browser.newContext({viewport:{width,height},isMobile:width===402,hasTouch:width===402});
      await context.addInitScript(theme=>{if(location.protocol.startsWith("http"))localStorage.setItem("mantine-color-scheme",JSON.stringify(theme));},theme);
      const page=await context.newPage();const errors=[],requests=[];
      page.on("pageerror",error=>errors.push(error.message));
      page.on("request",request=>{if(new URL(request.url()).pathname.startsWith("/api/"))requests.push(request.url());});
      await page.goto(`http://luna.local:8345/traffic-monitor?demo=1&data_id=${connection._id}`);
      await page.getByRole("heading",{name:connection.machine_name,exact:true}).waitFor();
      const chart=page.getByRole("img",{name:/Traffic monitor chart/i});await chart.waitFor();
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),"Dedicated monitor fits without horizontal scrolling");
      if(width>=1512)assert(await page.evaluate(()=>document.documentElement.scrollHeight<=innerHeight+1),"Desktop dedicated monitor fits the viewport");
      await page.screenshot({path:`/tmp/porthub-monitor-${process.env.REVIEW_BROWSER||"chromium"}-${theme}-${width}.png`});
      assert.deepEqual(errors,[]);assert.deepEqual(requests,[]);
      await context.close();
    }
    console.log(`PASS ${process.env.REVIEW_BROWSER||"chromium"}: standalone monitor in both themes at iPhone/MacBook/4K sizes, semantic heading, no horizontal overflow, no real API requests`);
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
