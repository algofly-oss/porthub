const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");

(async()=>{
  const browser=await launchBrowser();
  try{
    for(const theme of ["dark","light"])for(const width of [1512,402]){
      const context=await browser.newContext({viewport:{width,height:982}});
      await context.addInitScript(theme=>localStorage.setItem("mantine-color-scheme",JSON.stringify(theme)),theme);
      const page=await context.newPage();const errors=[];page.on("pageerror",error=>errors.push(error.message));
      await page.goto(`${process.env.REVIEW_ORIGIN || "http://luna.local:8345"}/home?demo=1&view=proxies`);
      const rows=page.locator('[aria-label^="Edit proxy "]:visible');const row=rows.first();await row.waitFor();
      assert.equal(await page.getByRole("columnheader",{name:"Status",exact:true}).count(),0);
      assert.equal(await page.getByRole("button",{name:/^Edit proxy /}).count(),0);
      await row.locator('span[role="img"]').waitFor();
      await row.getByRole("link").evaluate(link=>link.addEventListener("click",event=>event.preventDefault()));
      await row.getByRole("link").click();
      assert.equal(await page.getByRole("dialog").count(),0,"URL clicks do not open settings");
      await row.locator('span[role="img"]').click();
      const dialog=page.getByRole("dialog");await dialog.waitFor();
      await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
      await row.focus();await page.keyboard.press("Enter");await dialog.waitFor();
      await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
      await page.screenshot({path:`/tmp/porthub-proxy-row-${theme}-${width}.png`});
      assert.deepEqual(errors,[]);await context.close();
      console.log(`PASS proxy row ${theme} ${width}: inline status, URL isolation, row edit, keyboard edit, no extra buttons/columns`);
    }
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
