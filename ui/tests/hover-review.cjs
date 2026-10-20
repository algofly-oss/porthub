const { chromium } = require("playwright");
const assert = require("node:assert/strict");

const origin = process.env.REVIEW_URL || "http://luna.local:8345";

async function colours(locator) {
  return locator.evaluate(element => {
    const rgba = value => (value.match(/[\d.]+/g) || []).map(Number);
    let background = [255,255,255];
    const ancestors = [];
    for (let node = element; node; node = node.parentElement) ancestors.unshift(node);
    for (const node of ancestors) {
      const [r,g,b,a=1] = rgba(getComputedStyle(node).backgroundColor);
      background = [r,g,b].map((value,index) => value * a + background[index] * (1-a));
    }
    const foreground = rgba(getComputedStyle(element).color).slice(0,3);
    const luminance = colour => colour.map(value => { const v=value/255; return v<=.04045?v/12.92:((v+.055)/1.055)**2.4; }).reduce((sum,value,index)=>sum+value*[.2126,.7152,.0722][index],0);
    const [light,dark] = [luminance(background),luminance(foreground)].sort((a,b)=>b-a);
    return { foreground, background:background.map(Math.round), contrast:(light+.05)/(dark+.05) };
  });
}

(async () => {
  const {makeDemoData} = await import("../src/shared/demo/data.mjs");
  const browser = await chromium.launch({executablePath:"/usr/bin/google-chrome"});
  try {
    for (const theme of ["light","dark"]) {
      const state = makeDemoData();
      state.proxies = Array.from({length:200},(_,index)=>({...state.proxies[index%state.proxies.length],_id:`scale-proxy-${index}`,hosts:[`service-${String(index).padStart(3,"0")}.preview.invalid`],name:`Service ${index}`,updated_at:new Date(Date.now()-index*1000).toISOString()}));
      state.platformAccounts = Array.from({length:52},(_,index)=>({user:{id:`scale-account-${index}`,name:`Account ${String(index).padStart(2,"0")}`,email:`account-${index}@preview.invalid`,role:index%10===0?"admin":"user"},machines:index===0?state.machines.map(machine=>({...machine,ports:state.connections.filter(port=>port.machine_id===machine._id)})):[]}));
      const context = await browser.newContext({viewport:{width:1512,height:982}});
      await context.addInitScript(({theme,state})=>{localStorage.setItem("mantine-color-scheme",JSON.stringify(theme));if(!sessionStorage.getItem("porthub-demo-v1"))sessionStorage.setItem("porthub-demo-v1",JSON.stringify(state));},{theme,state});
      const page = await context.newPage();
      const errors=[],requests=[];
      page.on("pageerror",error=>errors.push(error.message));
      page.on("request",request=>{if(new URL(request.url()).pathname.startsWith("/api/"))requests.push(request.url());});
      async function hover(locator,label,{changes=true,blue=false}={}) {
        await page.mouse.move(1,1); await page.waitForTimeout(180);
        const before=await colours(locator);
        await locator.hover(); await page.waitForTimeout(180);
        const after=await colours(locator);
        assert(after.contrast>=4.5,`${theme} ${label}: hover contrast ${after.contrast.toFixed(2)}`);
        if(changes)assert.notDeepEqual(after.background,before.background,`${theme} ${label}: visible hover surface`);
        if(blue)assert(after.background[2]>after.background[0]+60 && after.foreground.every(value=>value===255),`${label}: active control stays blue with white text`);
        return after;
      }
      async function go(view,title) {
        await page.goto(`${origin}/home?demo=1&view=${view}`);
        await page.getByRole("heading",{name:title,exact:true}).waitFor();
        await page.waitForTimeout(220);
      }
      await go("machines","Machines");
      const navigation=page.getByRole("navigation",{name:"Workspace pages"});
      assert.equal(await navigation.getByRole("separator").filter({visible:true}).count(),1);
      await page.getByRole("button",{name:"Collapse navigation",exact:true}).click();
      await page.getByRole("button",{name:"Expand navigation",exact:true}).waitFor();
      assert.equal(await navigation.getByRole("separator").filter({visible:true}).count(),1);
      await page.getByRole("button",{name:"Expand navigation",exact:true}).click();
      await hover(page.getByRole("button",{name:"Create machine",exact:true}),"primary button",{blue:true});
      await hover(page.getByRole("button",{name:"Groups",exact:true}),"secondary button");
      const status=page.getByRole("group",{name:"Machine status",exact:true});
      await hover(status.getByRole("button",{name:"All",exact:true}),"active status tab",{blue:true});
      await hover(status.getByRole("button",{name:"Online",exact:true}),"inactive status tab");
      await hover(navigation.getByRole("button",{name:"Proxies",exact:true}),"navigation item");
      const row=page.getByRole("table",{name:"Machines",exact:true}).locator("tbody > tr").first();
      await hover(row,"machine row");
      await hover(row.locator('[title="Outgoing"]'),"machine outgoing rate",{changes:false});
      await page.getByLabel("Filter machine group",{exact:true}).click();
      await hover(page.getByRole("option",{name:"All groups",exact:true}),"selected group option",{changes:false});
      const option=page.getByRole("option",{name:"Development",exact:true});
      await hover(option,"group option");
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-dropdown.png`});
      await page.keyboard.press("Escape");
      await page.getByRole("button",{name:"Configure orion-dev-02",exact:true}).click();
      const machine=page.getByRole("dialog",{name:/^Configure orion-dev-02/});
      const table=machine.getByRole("table",{name:"Forwarded ports",exact:true});
      assert.notDeepEqual((await colours(table)).background,(await colours(machine)).background,"Popup table is separate from the dialog in both themes");
      await hover(table.locator("tbody > tr").first(),"popup port row");
      await hover(table.getByRole("link",{name:"service-001.preview.invalid",exact:true}),"popup web address",{changes:false});
      await page.mouse.move(1,1); await page.waitForTimeout(180);
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-ports.png`});
      await machine.getByRole("button",{name:"Edit forwarding rule API",exact:true}).click();
      const portTabs=machine.getByRole("group",{name:"Port configuration sections",exact:true});
      const badges=machine.getByText(/^LAN:/).first();
      for(const section of ["Connection","Access","Traffic","Web Addresses"]) {
        await portTabs.getByRole("button",{name:section,exact:true}).click();
        const tabs=await portTabs.boundingBox(),badge=await badges.boundingBox();
        assert(tabs.y+tabs.height<=badge.y,"Every port tab stays above status bubbles");
      }
      await portTabs.getByRole("button",{name:"Connection",exact:true}).click();
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-port-editor.png`});
      await machine.getByRole("button",{name:"All Ports",exact:true}).click();
      await machine.getByRole("button",{name:"History",exact:true}).click();
      const uptime=machine.getByRole("region",{name:"Uptime History",exact:true});
      assert((await colours(uptime.getByText("Online now",{exact:true}))).contrast>=4.5,"Uptime status text remains readable");
      const unknown=uptime.locator('[data-uptime-status="no-data"]').first();
      assert.notDeepEqual((await colours(unknown)).background,(await colours(uptime)).background,"No-data uptime bars have their own visible layer");
      await hover(uptime.getByRole("button",{name:"Older",exact:true}),"uptime history pager");
      await hover(uptime.getByRole("button",{name:"1H",exact:true}),"uptime timeframe");
      await uptime.locator('[data-uptime-status="online"]').last().hover();
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-uptime.png`});
      await machine.getByRole("button",{name:"Machine actions",exact:true}).click();
      await hover(page.getByRole("menuitem",{name:"Disable machine",exact:true}),"normal menu item");
      await hover(page.getByRole("menuitem",{name:"Delete machine",exact:true}),"destructive menu item");
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-menu.png`});
      await page.keyboard.press("Escape");
      await page.getByRole("menu").waitFor({state:"hidden"});
      assert.equal(await machine.count(),1,"Escape dismisses a menu, not its parent machine popup");
      await machine.getByRole("button",{name:"Close",exact:true}).click();
      await go("dashboard","Dashboard");
      const recent=page.getByRole("region",{name:"Recent Web Addresses",exact:true});
      await recent.getByText("5 most recent of 200 proxies",{exact:true}).waitFor();
      assert.equal(await recent.locator("button").count(),7,"Dashboard renders five proxies, not the full list");
      assert.equal(await recent.getByText("service-005.preview.invalid",{exact:true}).count(),0);
      await recent.scrollIntoViewIfNeeded();
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-dashboard-scale.png`});
      await recent.getByRole("button",{name:"View All Proxies",exact:true}).click();
      await page.getByRole("heading",{name:"Web Proxies",exact:true}).waitFor();
      await page.getByText("200 proxies · 1/8",{exact:true}).waitFor();
      assert.equal(await page.getByRole("table",{name:"Web proxies",exact:true}).locator("tbody > tr").count(),25);
      await hover(page.getByRole("button",{name:"Create proxy",exact:true}),"proxy primary",{blue:true});
      await hover(page.getByRole("table",{name:"Web proxies",exact:true}).locator("tbody > tr").first(),"proxy row");
      await hover(page.getByRole("link",{name:"service-000.preview.invalid",exact:true}),"proxy hostname",{changes:false});
      await go("platform","Platform Overview");
      const results=page.getByRole("region",{name:"Platform results",exact:true});
      await results.getByText("Showing 1 to 25 of 52 accounts",{exact:true}).waitFor();
      assert.equal(await results.getByRole("table").locator("tbody > tr").count(),25);
      await hover(results.getByRole("table").locator("tbody > tr").first().locator("td").nth(3).locator("span"),"platform online count",{changes:false});
      const active=results.locator('.mantine-Pagination-control[data-active="true"]');
      await hover(active,"active pagination",{changes:false,blue:true});
      const pageTwo=results.getByRole("button",{name:"2",exact:true});
      await hover(pageTwo,"inactive pagination"); await pageTwo.click();
      await results.getByText("Showing 26 to 50 of 52 accounts",{exact:true}).waitFor();
      await page.getByLabel("Search platform",{exact:true}).fill("account-51@preview.invalid");
      await results.getByText("Showing 1 to 1 of 1 accounts",{exact:true}).waitFor();
      await page.getByLabel("Search platform",{exact:true}).fill("");
      await results.getByText("Showing 1 to 25 of 52 accounts",{exact:true}).waitFor();
      await results.getByLabel("Accounts per page",{exact:true}).click();
      await page.getByRole("option",{name:"10 per page",exact:true}).click();
      await results.getByText("Showing 1 to 10 of 52 accounts",{exact:true}).waitFor();
      await page.waitForFunction(()=>document.querySelector('input[aria-label="Accounts per page"]')?.value==="10 per page");
      await page.screenshot({path:`/tmp/porthub-hover-${theme}-platform.png`});
      const footer=await results.locator("footer").boundingBox(),card=await results.boundingBox();
      assert(Math.abs(footer.y+footer.height-card.y-card.height)<2,"Platform pagination stays attached to table");
      for(const [width,height] of [[820,1180],[402,874],[320,700]]) {
        await page.setViewportSize({width,height});
        await go("proxies","Web Proxies");
        await page.getByText("200 proxies · 1/8",{exact:true}).waitFor();
        const pagerBounds=await page.locator('.proxy-results footer .mantine-Pagination-control').evaluateAll(elements=>elements.map(element=>({left:element.getBoundingClientRect().left,right:element.getBoundingClientRect().right})));
        assert(pagerBounds.every(bounds=>bounds.left>=0 && bounds.right<=width),`Large proxy list pagination fits at ${width}px`);
        await page.getByRole("button",{name:"2",exact:true}).click();
        await page.getByText("200 proxies · 2/8",{exact:true}).waitFor();
        await page.screenshot({path:`/tmp/porthub-hover-${theme}-proxies-${width}.png`});
        await go("platform","Platform Overview");
        await results.getByRole("button",{name:"View machines for Account 00",exact:true}).click();
        await page.waitForTimeout(200);
        assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1 && scrollY===0),"No phone page overflow");
        const navBounds=await navigation.getByRole("button").evaluateAll(elements=>elements.map(element=>({left:element.getBoundingClientRect().left,right:element.getBoundingClientRect().right})));
        assert(navBounds.every(bounds=>bounds.left>=0 && bounds.right<=width),`All admin navigation buttons fit at ${width}px`);
        const divider=navigation.getByRole("separator").filter({visible:true});
        assert.equal(await divider.getAttribute("aria-orientation"),width>=768?"horizontal":"vertical");
        await page.screenshot({path:`/tmp/porthub-hover-${theme}-platform-${width}.png`});
        await go("machines","Machines");
        await page.getByRole("button",{name:"Configure orion-dev-02",exact:true}).click();
        await machine.getByRole("button",{name:"Edit forwarding rule API",exact:true}).click();
        const tabs=await portTabs.boundingBox(),badge=await badges.boundingBox();
        assert(tabs.y+tabs.height<=badge.y,"Phone port tabs are above bubbles too");
        await page.screenshot({path:`/tmp/porthub-hover-${theme}-port-editor-${width}.png`});
        await machine.getByRole("button",{name:"All Ports",exact:true}).click();
        await machine.getByRole("button",{name:"History",exact:true}).click();
        await uptime.getByRole("button",{name:"1H",exact:true}).click();
        await uptime.locator('[data-uptime-status="online"]').last().hover();
        await page.screenshot({path:`/tmp/porthub-hover-${theme}-uptime-${width}.png`});
        await go("platform","Platform Overview");
      }
      // Non-admins see neither the admin item nor its divider.
      await page.evaluate(()=>{const state=JSON.parse(sessionStorage.getItem("porthub-demo-v1"));state.user.role="user";sessionStorage.setItem("porthub-demo-v1",JSON.stringify(state));});
      await go("machines","Machines");
      assert.equal(await navigation.getByRole("button",{name:"Platform",exact:true}).count(),0);
      assert.equal(await navigation.getByRole("separator").count(),0);
      assert.deepEqual(errors,[]); assert.deepEqual(requests,[]);
      await context.close();
      console.log(`PASS ${theme}: hover contrast, table layers, port navigation, uptime colours, 200-proxy dashboard, 52-account paging, admin divider, desktop/820px/402px/320px layouts, no real API requests`);
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
