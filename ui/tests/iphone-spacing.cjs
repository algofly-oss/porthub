const assert=require('node:assert/strict');
const {launchBrowser,navigateWorkspace}=require('./browser.cjs');
const origin=process.env.REVIEW_ORIGIN||'http://127.0.0.1:5300';
const theme=process.env.REVIEW_THEME||'light';
(async()=>{
 const browser=await launchBrowser();
 try{
  for(const width of [320,402,430]){
   const height=width===402?874:932;
   const context=await browser.newContext({viewport:{width,height},screen:{width,height},isMobile:true,hasTouch:true,userAgent:'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1'});
   await context.addInitScript(theme=>{
    localStorage.setItem('mantine-color-scheme',JSON.stringify(theme));
    Object.defineProperty(navigator,'standalone',{value:true});
    Object.defineProperty(window,'innerHeight',{value:760,configurable:true});
    const v=new EventTarget();Object.assign(v,{height:760,width:screen.width,offsetTop:0,scale:1});Object.defineProperty(window,'visualViewport',{value:v});
   },theme);
   const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto(origin+'/home?demo=1');await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
   // Reproduce a shortened fixed containing block independently of the full
   // screen: JS heights and an inset-only shell are insufficient in this case.
   await page.addStyleTag({content:`#__next {position:fixed;top:0;left:0;width:100%;height:760px;transform:translateZ(0);}`});
   const nav=page.getByRole('complementary',{name:'Main navigation'});let machineSearchWidth;
   for(const view of ['Dashboard','Machines','Rules','Proxies','Traffic','Settings','Platform']){
    await navigateWorkspace(page,view);
    const title={Rules:'Access Rules',Proxies:'Public Web Proxies',Traffic:'Traffic Explorer',Platform:'Platform Overview'}[view]||view;
    await page.getByRole('heading',{name:title,exact:true}).waitFor();
    const panel=page.locator('.workspace-page:visible');await panel.waitFor();
    const box=await nav.boundingBox();assert(Math.abs(box.y+box.height-height)<1,`${width} ${view}: bottom navigation fills the full iPhone screen`);
    const heading=await panel.locator('.page-heading').boundingBox();assert(Math.abs(heading.x-12)<1,`${view}: shared 12px page inset`);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false,`${view}: no horizontal overflow`);
    if(view==='Machines'||view==='Proxies'){
     const toolbar=page.locator(`[aria-label="${view==='Machines'?'Machine':'Proxy'} tools"]`);
     const status=await toolbar.getByRole('group').boundingBox();const filter=await toolbar.getByRole('button',{name:'Filters',exact:true}).boundingBox();
     assert(Math.abs(filter.x-status.x-status.width-8)<1,`${view}: status and Filters have exactly the shared 8px gap`);
     const search=await toolbar.locator('.search-field').boundingBox();const actions=await toolbar.getByRole('button',{name:view==='Machines'?'Create machine':'Create proxy',exact:true}).boundingBox();
     assert(Math.abs(actions.x-search.x-search.width-8)<1,`${view}: search and actions also have an 8px gap`);
     assert(Math.abs(search.width-status.width)<1&&Math.abs(search.x-status.x)<1,`${view}: search and status share the same column width`);
     assert(Math.abs(actions.width-filter.width)<1&&Math.abs(actions.x-filter.x)<1,`${view}: Create and Filters share the same column width`);
     const surfaces=await toolbar.evaluate(el=>[el.querySelector('.search-field'),el.querySelector('[role="group"]'),el.querySelector('[aria-label="Filters"]')].map(node=>getComputedStyle(node).backgroundColor));
     if(theme==='light')assert(surfaces.every(color=>color==='rgb(255, 255, 255)'),`${view}: light-mode search, status, and filter surfaces are white`);
     if(view==='Machines')machineSearchWidth=search.width;else assert(Math.abs(search.width-machineSearchWidth)<1,'Machines and Proxies search rows use identical widths');
     assert(Math.abs(search.y-actions.y)<1&&Math.abs(status.y-filter.y)<1,`${view}: controls align within their independent rows`);
    }
    if((view==='Machines'||view==='Proxies')&&theme==='light'){
     const toolbar=page.locator(`[aria-label="${view==='Machines'?'Machine':'Proxy'} tools"]`);
     await toolbar.getByRole('button',{name:'Filters',exact:true}).click();
     for(const label of view==='Machines'?['Filter machine group','Sort machines']:['Filter proxy group','Sort proxies']){
      const field=page.getByLabel(label,{exact:true});await field.waitFor();
      assert.equal(await field.evaluate(el=>getComputedStyle(el).backgroundColor),'rgb(255, 255, 255)',`${label}: shared white control surface`);
     }
     if(view==='Machines')assert.equal(await page.getByRole('button',{name:'Groups',exact:true}).evaluate(el=>getComputedStyle(el).backgroundColor),'rgb(255, 255, 255)','Groups button: shared white control surface');
     await page.getByRole('heading',{name:title,exact:true}).click();
    }
    if(view==='Traffic'&&theme==='light'){
     for(const label of ['Traffic machine','Sort traffic','Traffic window']){
      const field=page.getByLabel(label,{exact:true});await field.waitFor();
      assert.equal(await field.evaluate(el=>getComputedStyle(el).backgroundColor),'rgb(255, 255, 255)',`${label}: shared white control surface`);
     }
    }
    if(view==='Rules'){
     await page.getByLabel('Filter rule group',{exact:true}).waitFor({state:'visible'});const select=await page.getByLabel('Filter rule group',{exact:true}).boundingBox();assert(Math.abs(select.width-(width-24))<2,'Policy group dropdown fills its mobile row');
    }
    if(view==='Settings'&&theme==='light'){
     const categories=page.getByRole('navigation',{name:'Settings categories',exact:true});
     for(const category of ['Profile','Security','Notifications','Appearance']){
      await categories.getByRole('button',{name:category,exact:true}).click();
      await panel.getByRole('heading',{name:category,exact:true}).waitFor();
      if(category==='Notifications')await page.getByLabel('Bot token',{exact:true}).waitFor();
      const fields=panel.locator('input:visible:not([type="file"]):not([type="checkbox"]):not([type="radio"]),textarea:visible,select:visible');
      const styles=await fields.evaluateAll(elements=>elements.map(el=>({label:el.getAttribute('aria-label')||el.type,border:getComputedStyle(el).borderTopWidth,color:getComputedStyle(el).borderTopColor,fill:getComputedStyle(el).backgroundColor})));
      for(const field of styles){assert.equal(field.border,'1px',`${category} ${field.label}: visible field boundary`);assert(!['transparent','rgba(0, 0, 0, 0)','rgb(255, 255, 255)'].includes(field.color),`${category} ${field.label}: outline contrasts with white card`);}
     }
     await categories.getByRole('button',{name:'Profile',exact:true}).click();
    }
    if(view==='Platform'){
     assert.equal(await panel.locator('.data-scroll').evaluate(el=>getComputedStyle(el).backgroundImage),'none','Hidden desktop table headers do not paint a stripe across mobile account rows');
     const role=await page.getByLabel('Filter account role',{exact:true}).boundingBox();const sort=await page.getByLabel('Sort accounts',{exact:true}).boundingBox();
     assert(Math.abs(role.y-sort.y)<1);assert(Math.abs(role.width-sort.width)<1);assert(role.width>=(width-32)/2-1,'Platform dropdown labels have a full half-width row');
     assert(Math.abs(role.height-44)<1&&Math.abs(sort.height-44)<1,'Shared 44px phone control height');
     const settings=await page.getByRole('button',{name:'Platform settings',exact:true}).boundingBox();const refresh=await page.getByRole('button',{name:'Refresh platform',exact:true}).boundingBox();assert(Math.abs(settings.y-refresh.y)<1);assert(Math.abs(refresh.x-(settings.x+settings.width)-8)<1,'Settings and refresh keep an 8px gap');
    }
    if(width===402)await page.screenshot({path:`/tmp/porthub-iphone16pro-${view.toLowerCase()}.png`});
   }
   assert.deepEqual(errors,[]);await context.close();console.log(`PASS ${theme} iPhone ${width}: all pages, consistent insets/control spacing, full-screen bottom navigation, no overflow`);
  }
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
