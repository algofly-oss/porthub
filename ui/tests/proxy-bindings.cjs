const assert=require("node:assert/strict");
const fs=require("node:fs");
const {launchBrowser}=require("./browser.cjs");
(async()=>{
  const browser=await launchBrowser();const root=process.env.REVIEW_ORIGIN || "http://127.0.0.1:3105";
  const dir="/tmp/porthub-proxy-bindings-review";fs.mkdirSync(dir,{recursive:true});
  try{
    for(const theme of (process.env.REVIEW_THEMES || "dark,light").split(","))for(const width of (process.env.REVIEW_WIDTHS || "1440,768,402,320").split(",").map(Number)){
      const context=await browser.newContext({viewport:{width,height:1000}});
      await context.addInitScript(theme=>localStorage.setItem("mantine-color-scheme",JSON.stringify(theme)),theme);
      const page=await context.newPage();const errors=[];page.on("pageerror",e=>errors.push(e.message));
      await page.goto(`${root}/home?demo=1&view=proxies`);
      const row=page.locator('[aria-label^="Edit proxy "]:visible').first();await row.waitFor();await row.focus();await page.keyboard.press("Enter");
      const dialog=page.getByRole("dialog");await dialog.waitFor();
      await dialog.getByRole("button",{name:"Options",exact:true}).click();
      const description=dialog.getByLabel("Description",{exact:true});
      for(const focused of [false,true]){
        if(focused)await description.focus();
        const style=await description.evaluate(el=>{const s=getComputedStyle(el);return {border:s.borderTopWidth,outline:s.outlineStyle,shadow:s.boxShadow};});
        if(theme==="dark")assert.equal(style.border,"0px",`description border while focused=${focused}`);
        assert.equal(style.outline,"none",`description outline while focused=${focused}`);
        assert(!style.shadow || style.shadow==="none" || !style.shadow.includes("rgb(37, 99, 235)"),`description must not gain a blue focus ring: ${style.shadow}`);
      }
      await dialog.getByRole("button",{name:"Bindings",exact:true}).click();
      if(theme==="dark") {
        const active=dialog.getByRole("list",{name:"Proxy bindings",exact:true}).getByRole("listitem").first();
        const border=await active.evaluate(el=>getComputedStyle(el).borderTopColor);
        const channels=border.match(/[\d.]+/g).map(Number);
        assert(channels[0]<150 && channels[2]>channels[0]+50,`expanded dark binding must have its accent border, not a white fallback: ${border}`);
      }

      assert(await dialog.getByRole("radio",{name:/My priority order/}).isChecked());
      await dialog.getByRole("button",{name:"Add binding",exact:true}).click();
      await dialog.getByLabel("Binding 2 URL",{exact:true}).fill("https://backup.example.invalid/app");
      await dialog.getByLabel("Binding 2 label",{exact:true}).fill("Backup standalone route");
      await dialog.getByLabel("Binding 2 priority",{exact:true}).fill("2");
      await dialog.getByRole("button",{name:"Move binding 2 up",exact:true}).click();
      const titles=await dialog.getByRole("list",{name:"Proxy bindings",exact:true}).getByRole("listitem").getByRole("button",{name:/^Edit binding /}).allTextContents();
      assert(titles[0].includes("Backup standalone route"),"keyboard/touch reorder moves the target");
      await dialog.getByText("Load balance",{exact:true}).click();
      assert(await dialog.getByRole("radio",{name:/Load balance/}).isChecked());
      assert.equal(await dialog.getByLabel(/Binding \d+ priority/).count(),0,"priority fields disappear in balancing mode");
      await dialog.getByLabel("Balancing method",{exact:true}).click();await page.getByRole("option",{name:"Weighted round robin",exact:true}).click();
      await dialog.getByLabel("Binding 1 weight",{exact:true}).fill("3");
      await dialog.getByLabel("Sticky sessions",{exact:true}).check({force:true});
      await dialog.screenshot({path:`${dir}/${theme}-${width}-bindings.png`});
      await dialog.locator("[data-proxy-scroll]").evaluate(el=>el.scrollTop=0);
      await dialog.screenshot({path:`${dir}/${theme}-${width}-overview.png`});
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),"no page overflow");
      assert(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1),"no dialog overflow");
      await dialog.getByRole("button",{name:"Save Proxy",exact:true}).click();await dialog.waitFor({state:"hidden"});
      const saved=await page.evaluate(()=>JSON.parse(sessionStorage.getItem("porthub-demo-v1")).proxies.find(p=>p.bindings?.some(b=>b.label==="Backup standalone route")));
      assert(saved);assert.equal(saved.bindings.length,2);assert.equal(saved.routing.mode,"balance");assert.equal(saved.routing.strategy,"weighted_round_robin");assert.equal(saved.bindings[0].weight,3);assert.equal(saved.routing.sticky_sessions,true);
      const edited=page.locator('[aria-label^="Edit proxy "]:visible').filter({hasText:saved.hosts[0]}).first();await edited.click();
      await dialog.getByRole("button",{name:"Bindings",exact:true}).click();await dialog.getByText("Priority",{exact:true}).click();
      await dialog.getByRole("radio",{name:/Best health & response/}).check();
      assert.equal(await dialog.getByLabel(/Binding \d+ priority/).count(),0,"automatic health selection does not show manual order");
      await dialog.getByRole("button",{name:"Health",exact:true}).click();
      assert(await dialog.getByLabel("Active health checks",{exact:true}).isChecked());assert(await dialog.getByLabel("Active health checks",{exact:true}).isDisabled());
      await dialog.getByLabel("Default health path",{exact:true}).fill("/healthz");
      await dialog.getByText("Recovery & request limits",{exact:true}).click();
      await dialog.getByLabel("Failed checks before unhealthy",{exact:true}).fill("3");
      await dialog.screenshot({path:`${dir}/${theme}-${width}-health.png`});
      await dialog.getByRole("button",{name:"Save Proxy",exact:true}).click();await dialog.waitFor({state:"hidden"});
      const healthSaved=await page.evaluate(id=>JSON.parse(sessionStorage.getItem("porthub-demo-v1")).proxies.find(p=>p._id===id),saved._id);
      assert.equal(healthSaved.routing.mode,"priority");assert.equal(healthSaved.routing.priority_policy,"health");assert.equal(healthSaved.routing.health.path,"/healthz");assert.equal(healthSaved.routing.health.unhealthy_after,3);
      await page.getByRole("button",{name:"Create proxy",exact:true}).click();await dialog.waitFor();
      await dialog.getByLabel("Domain suffix",{exact:true}).fill("");
      await dialog.getByRole("button",{name:"Options",exact:true}).click();await dialog.getByRole("button",{name:"Create Proxy",exact:true}).click();
      await dialog.getByRole("alert").first().waitFor();
      assert(await dialog.getByLabel("Primary subdomain",{exact:true}).isVisible(),"invalid submit returns to the address field");
      await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
      assert.deepEqual(errors,[]);await context.close();
      console.log(`PASS ${theme} ${width}: mixed bindings, reorder, modes, weights, affinity, save/reopen, health settings, validation, overflow`);
    }
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
