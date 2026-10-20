const { chromium } = require("playwright");
const assert = require("node:assert/strict");

(async () => {
  const browser = await chromium.launch({executablePath:"/usr/bin/google-chrome"});
  try {
    for (const [width,height] of [[1512,982],[402,874],[1280,600]]) {
      const context = await browser.newContext({viewport:{width,height}});
      const page = await context.newPage();
      const errors = [], requests = [];
      page.on("pageerror",error=>errors.push(error.message));
      page.on("request",request=>{if(new URL(request.url()).pathname.startsWith("/api/"))requests.push(request.url());});
      await page.goto("http://luna.local/home?demo=1");
      await page.getByRole("button",{name:"Enroll a Machine",exact:true}).click();
      const machine = page.getByRole("dialog",{name:"Create Machine",exact:true});
      await machine.waitFor();
      await page.waitForFunction(()=>!new URL(location.href).searchParams.has("create"));
      await machine.getByRole("button",{name:"Cancel",exact:true}).click();
      for(const tab of ["Proxies","Settings","Machines"]) {
        await page.getByRole("button",{name:tab,exact:true}).click();
        await page.waitForTimeout(200);
        assert.equal(await page.getByRole("dialog").count(),0,`${tab} must not replay create`);
        assert(!new URL(page.url()).searchParams.has("create"));
      }
      await page.reload(); await page.getByRole("heading",{name:"Machines",exact:true}).waitFor();
      assert.equal(await page.getByRole("dialog").count(),0,"Refresh cannot replay machine enrollment");
      await page.goto("http://luna.local/home?demo=1&view=proxies&create=1");
      const proxy = page.getByRole("dialog",{name:"Create Proxy Route",exact:true});
      await proxy.waitFor(); await page.waitForFunction(()=>!new URL(location.href).searchParams.has("create"));
      await proxy.getByRole("button",{name:"Cancel",exact:true}).click();
      await page.getByRole("button",{name:"Refresh proxies",exact:true}).click();
      await page.getByRole("button",{name:"Create proxy",exact:true}).waitFor({state:"visible"});
      assert.equal(await page.getByRole("dialog").count(),0,"Proxy refresh must not replay create");
      for(const tab of ["Machines","Proxies"]) { await page.getByRole("button",{name:tab,exact:true}).click(); await page.waitForTimeout(200); assert.equal(await page.getByRole("dialog").count(),0); }
      // A long group list reproduces the original clipped dropdown reliably.
      await page.evaluate(()=>{const state=JSON.parse(sessionStorage.getItem("porthub-demo-v1"));state.groups=Array.from({length:500},(_,i)=>({_id:`review-group-${i}`,name:`Review Group ${String(i).padStart(3,"0")}`}));sessionStorage.setItem("porthub-demo-v1",JSON.stringify(state));});
      await page.goto("http://luna.local/home?demo=1&view=machines");
      await page.getByRole("button",{name:"Create machine",exact:true}).click();
      const select = machine.getByLabel("Machine group",{exact:true});
      await select.click();
      const list = page.getByRole("listbox"); await list.waitFor();
      await page.waitForTimeout(200);
      const bounds = await list.boundingBox();
      assert(bounds.x>=0 && bounds.y>=0 && bounds.x+bounds.width<=width+1 && bounds.y+bounds.height<=height+1,`Dropdown fits viewport: ${JSON.stringify(bounds)}`);
      assert(await list.evaluate(element=>!element.closest('[role="dialog"]')),"Dropdown must escape the popup's clipping/scroll container");
      await page.screenshot({path:`/tmp/porthub-dropdown-open-${width}.png`});
      await select.fill("Review Group 499");
      const option=page.getByRole("option",{name:"Review Group 499",exact:true});
      await option.click(); assert.equal(await select.inputValue(),"Review Group 499");
      await select.click(); await page.keyboard.press("Escape"); assert.equal(await machine.count(),1,"Escape closes the list before the popup");
      await page.screenshot({path:`/tmp/porthub-dropdown-verified-${width}.png`});
      await machine.getByRole("button",{name:"Cancel",exact:true}).click();
      await page.goto("http://luna.local/home?demo=1&view=dashboard");
      await page.getByRole("heading",{name:"Dashboard",exact:true}).waitFor();
      const scroller=page.getByLabel("Dashboard content",{exact:true});
      if(await scroller.evaluate(element=>element.scrollHeight>element.clientHeight+100)) {
        const heading=page.getByRole("heading",{name:"Dashboard",exact:true}); const before=await heading.boundingBox();
        await scroller.evaluate(element=>element.scrollTop=160); const after=await heading.boundingBox();
        assert(after.y<before.y-100,"Heading scrolls with dashboard cards, not over them");
        assert.equal(await page.evaluate(()=>scrollY),0,"Dashboard scrolling stays inside the app");
        await page.screenshot({path:`/tmp/porthub-dashboard-scroll-${width}.png`});
      }
      assert.deepEqual(errors,[]); assert.deepEqual(requests,[]);
      await context.close(); console.log(`PASS ${width}×${height}: one-shot enrollment/proxy routes, clean tab navigation/refresh, searchable 500-group portal dropdown, dashboard heading scroll`);
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
