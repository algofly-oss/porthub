const assert = require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
  const {makeDemoData}=await import('../src/shared/demo/data.mjs');
  const browser=await launchBrowser();
  try {
    for(const width of [320,1512]) {
      const state=makeDemoData();
      state.trafficHover={contributors:[{connection_id:'test-port',machine_name:'Luna',service_name:'Web app',public_port:8888,configured_target:{host:'127.0.0.1',port:3000},incoming_bytes_per_second:2048,outgoing_bytes_per_second:1024,source_status:'observed',accepted_incoming_ips:['192.0.2.25','2001:db8::1'],accepted_incoming_ips_window_seconds:60}],total_contributors:1,truncated:false};
      const context=await browser.newContext({viewport:{width,height:900}});
      await context.addInitScript(state=>sessionStorage.setItem('porthub-demo-v1',JSON.stringify(state)),state);
      const page=await context.newPage();
      await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3017'}/home?demo=1&view=dashboard`);
      const chart=page.getByRole('img',{name:'Public port traffic chart'});
      await chart.scrollIntoViewIfNeeded();
      const details=page.getByLabel('Public traffic destinations');
      await chart.hover({position:{x:20,y:80}});
      await details.getByText('Luna · Web app',{exact:true}).waitFor();
      await page.keyboard.press('Escape');
      await chart.focus();
      await details.getByText('Luna · Web app',{exact:true}).waitFor();
      assert.match(await details.innerText(),/Public :8888 → 127.0.0.1:3000/);
      assert.match(await details.innerText(),/192.0.2.25, 2001:db8::1/);
      const rect=await details.boundingBox();
      assert(rect.x>=0 && rect.x+rect.width<=width,`Tooltip fits ${width}px viewport`);
      await page.getByRole("button",{name:"Close traffic details"}).click();
      await chart.focus();
      await page.keyboard.press("ArrowLeft");
      await details.getByText("Luna · Web app",{exact:true}).waitFor();
      await page.keyboard.press('Escape');
      assert.equal(await details.count(),0);
      await context.close();
      console.log(`PASS traffic machine/ports/IPv4/IPv6 and viewport ${width}`);
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
