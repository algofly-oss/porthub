const assert = require('node:assert/strict');
const fs = require('node:fs');
const {launchBrowser, waitForWorkspaceLayout} = require('./browser.cjs');
(async () => {
  const {makeDemoData,handleDemoRequest} = await import('../src/shared/demo/data.mjs');
  const {demoPrivateTraffic} = await import('../src/shared/demo/private-traffic.mjs');
  const {formatBytes} = await import('../src/shared/utils/traffic.mjs');
  const scrollSection=async locator=>{await locator.evaluate(element=>{element.scrollIntoView({block:'start'});let parent=element.parentElement;while(parent){if(/auto|scroll/.test(getComputedStyle(parent).overflowY)&&parent.scrollHeight>parent.clientHeight){parent.scrollTop-=40;return;}parent=parent.parentElement;}window.scrollBy(0,-40);});};
  const browser = await launchBrowser(), engine = process.env.REVIEW_BROWSER || 'chromium';
  const directory = process.env.REVIEW_SCREENSHOT_DIR || '/tmp/porthub-private-traffic-browser';
  fs.mkdirSync(directory, {recursive:true});
  try {
    for (const viewport of [{width:1512,height:982},{width:402,height:874},{width:874,height:402},{width:402,height:760},{width:320,height:760},{width:402,height:760,historical:true},{width:402,height:874,paged:true}].filter(viewport=>!process.env.REVIEW_VIEWPORT||`${viewport.width}x${viewport.height}`===process.env.REVIEW_VIEWPORT)) {
      const context = await browser.newContext({viewport:{width:viewport.width,height:viewport.height},serviceWorkers:'block',...(viewport.width<=874?{isMobile:true,hasTouch:true,deviceScaleFactor:3}:{})});
      await context.addInitScript(()=>{
        // API/demo fixtures own their responses; PWA registration is outside this test.
        // Blocking registration alone yields undefined in Workbox. Model SW unavailable.
        for(const owner of [navigator,Object.getPrototypeOf(navigator)])if(Object.prototype.hasOwnProperty.call(owner,'serviceWorker')&&!Reflect.deleteProperty(owner,'serviceWorker'))throw Error('Fixture cannot isolate service workers');
        if('serviceWorker' in navigator)throw Error('Fixture service worker isolation failed');
      });
      const state=makeDemoData(), errors=[];
      if(viewport.historical){state.privateTrafficCoverage={reporting_peers:0,eligible_peers:4,unreported_peers:4,dropped_rows:2,history_incomplete:true};state.privateTrafficStale=true;}
      if(viewport.paged)state.privateTrafficDirections=85;
      const label=`${engine}-${viewport.width}x${viewport.height}${viewport.historical?'-historical':''}${viewport.paged?'-paged':''}`;
      await context.addInitScript(state=>sessionStorage.setItem('porthub-demo-v1',JSON.stringify(state)),state);
      await context.addInitScript(()=>document.addEventListener('mousemove',event=>{window.__privateTrafficReviewPointer={x:event.clientX,y:event.clientY};},true));
      const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
      try {
      await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:8321'}/home?demo=1&view=dashboard`);
      const panel=page.getByRole('region',{name:'Private network traffic',exact:true});
      await panel.getByText(viewport.historical?'0 of 4 peers reporting · 4 unreported':'3 of 4 peers reporting · 1 unreported',{exact:true}).waitFor();
      await panel.scrollIntoViewIfNeeded();await waitForWorkspaceLayout(page);
      await scrollSection(panel.getByRole('heading',{name:'Private network traffic',exact:true}));await waitForWorkspaceLayout(page);
      await page.screenshot({path:`${directory}/${label}-initial.png`,scale:'css'});
      assert.equal(await panel.locator('select').count(),0,'controls must use searchable custom selectors');
      const demo=demoPrivateTraffic(state.machines,'1h','all',Date.now(),{demoDirections:viewport.paged?85:4});
      const total=demo.totals.total_bytes;
      assert.ok((await panel.innerText()).includes(formatBytes(total)),'canonical directional volume shown without RX double-count');
      if(!viewport.paged){assert.match(await panel.innerText(),/Sender report missing/);assert.match(await panel.innerText(),/No recent sender report/);}
      const flows=panel.locator('button[aria-pressed]');assert.equal(await flows.count(),viewport.paged?40:4);
      if(viewport.paged){
        await panel.getByRole('button',{name:'Next',exact:true}).click();await panel.getByText(/Page 2 · 85 matching of 85/).waitFor();assert.equal(await flows.count(),40);
        await panel.getByRole('button',{name:'Next',exact:true}).click();await panel.getByText(/Page 3 · 85 matching of 85/).waitFor();assert.equal(await flows.count(),5);
        assert.ok((await panel.innerText()).includes(formatBytes(total)),'last page must retain FULL aggregate');
        await panel.getByRole('searchbox',{name:'Find a private traffic pair'}).fill('pair 84');await panel.getByText(/Page 1 · 1 matching of 85/).waitFor();assert.equal(await flows.count(),1);assert.ok((await panel.innerText()).includes(formatBytes(total)),'server search must not replace FULL aggregate');
      }
      await flows.first().click();
      const chart=panel.getByRole('group',{name:/Selected machine pair traffic history/});await chart.waitFor();await chart.getByRole('status').filter({hasText:/Direct|Relayed|No report for this interval/}).waitFor();
      const selected=demo.flows.sort((a,b)=>b.total_bytes-a.total_bytes)[0];
      assert.match(await chart.innerText(),new RegExp(`${selected.source_name} → ${selected.destination_name}`));
      await scrollSection(chart);await waitForWorkspaceLayout(page);await page.screenshot({path:`${directory}/${label}-chart.png`,scale:'css'});
      await chart.evaluate(element=>{element.__reviewEvents=[];for(const type of ['keydown','mousemove','focus','blur'])element.addEventListener(type,event=>{if(element.__reviewEvents.length<80)element.__reviewEvents.push({type,key:event.key||null,x:event.clientX??null,y:event.clientY??null,dx:event.movementX??null,dy:event.movementY??null,at:performance.now(),focused:document.activeElement===element});});});
      const keySteps=[];await chart.focus();await page.keyboard.press('Home');
      const homeStatus=await chart.getByRole('status').innerText();keySteps.push({key:'Home',status:homeStatus,focused:await chart.evaluate(element=>document.activeElement===element)});
      // Retained real WebKit failure: focus/scroll emitted a zero-motion event
      // after Home, replacing keyboard index0 with the stationary pointer index.
      const chartBox=await chart.boundingBox();
      const stationary=await page.evaluate(()=>window.__privateTrafficReviewPointer);assert.ok(stationary,'real pointer baseline recorded');
      await chart.dispatchEvent('mousemove',{clientX:stationary.x,clientY:stationary.y,movementX:0,movementY:0});
      assert.equal(await chart.getByRole('status').innerText(),homeStatus,'stationary mouse event must not replace keyboard selection');
      for(const key of Array(14).fill('ArrowRight')){await page.keyboard.press(key);keySteps.push({key,status:await chart.getByRole('status').innerText(),focused:await chart.evaluate(element=>document.activeElement===element)});}
      fs.writeFileSync(`${directory}/${label}-keyboard.json`,JSON.stringify({steps:keySteps,events:await chart.evaluate(element=>element.__reviewEvents)},null,2));
      assert.match(await chart.getByRole('status').innerText(),/No report for this interval/,'missing buckets stay gaps');
      const gapStatus=await chart.getByRole('status').innerText();
      await page.mouse.move(0,0);await chart.hover({position:{x:chartBox.width*.8,y:20}});
      fs.writeFileSync(`${directory}/${label}-pointer.json`,JSON.stringify({events:await chart.evaluate(element=>element.__reviewEvents),box:await chart.boundingBox(),status:await chart.getByRole('status').innerText()},null,2));
      assert.notEqual(await chart.getByRole('status').innerText(),gapStatus,'real pointer motion must still inspect another interval');
      await panel.getByRole('button',{name:'Show all machine pairs',exact:true}).click();
      if(!viewport.paged){
        const missing=panel.locator('button[aria-pressed]').filter({hasText:'Sender report missing'});await missing.click();
        const unknown=panel.getByRole('group',{name:/Selected machine pair traffic history/});await unknown.getByText('No sender-reported history',{exact:true}).waitFor();
        assert.equal(await unknown.locator('rect').count(),0,'receiver-only observations must not invent sender bars');assert.match(await unknown.getByRole('status').innerText(),/No report for this interval/);assert.match(await missing.innerText(),/Receiver observed/);assert.match(await missing.innerText(),/—/);
        await panel.getByRole('button',{name:'Show all machine pairs',exact:true}).click();
      }
      await panel.getByRole('button',{name:'Pause private traffic updates',exact:true}).click();
      await panel.getByText('Updates paused',{exact:true}).waitFor();
      await panel.getByRole('button',{name:'Resume private traffic updates',exact:true}).click();
      if(!viewport.historical){await panel.getByLabel('Private traffic history range',{exact:true}).click();
      await page.getByRole('option',{name:'Last 30 days',exact:true}).click();
      await panel.getByLabel('Private traffic history range',{exact:true}).waitFor();
      await panel.getByText(/86400s interval/).waitFor();}
      const measurement = panel.getByRole('button',{name:'How traffic is measured',exact:true});
      await measurement.click();
      assert.equal(await measurement.getAttribute('aria-expanded'),'true');
      await panel.getByText(/^Agents count private transport bytes locally/).waitFor();
      await waitForWorkspaceLayout(page);
      const geometry=await panel.evaluate(element=>{
        const rect=element.getBoundingClientRect();
        const controls=[...element.querySelectorAll('button,input,summary')].filter(node=>{const r=node.getBoundingClientRect();return r.width>0&&r.height>0;}).map(node=>{const r=node.getBoundingClientRect();return {label:node.getAttribute('aria-label')||node.textContent.trim().slice(0,60),width:r.width,height:r.height,font:parseFloat(getComputedStyle(node).fontSize),left:r.left,right:r.right,tag:node.tagName};});
        return {width:innerWidth,scrollWidth:document.documentElement.scrollWidth,left:rect.left,right:rect.right,controls};
      });
      fs.writeFileSync(`${directory}/${label}.json`,JSON.stringify({geometry,errors},null,2));
      await scrollSection(measurement);await waitForWorkspaceLayout(page);
      await page.screenshot({path:`${directory}/${label}.png`,scale:'css'});
      assert.ok(geometry.scrollWidth<=geometry.width+1,JSON.stringify(geometry));
      assert.ok(geometry.left>=-1&&geometry.right<=geometry.width+1,JSON.stringify(geometry));
      for(const control of geometry.controls){
        assert.ok(control.left>=geometry.left-1&&control.right<=geometry.right+1,JSON.stringify(control));
        if(viewport.width<=402){assert.ok(control.height>=43.5,`phone touch target ${JSON.stringify(control)}`);if(control.tag==='INPUT')assert.ok(control.font>=16,`phone input zoom ${JSON.stringify(control)}`);}
      }
      assert.deepEqual(errors,[]);console.log(`PASS ${engine} private traffic canonical pair/partial coverage/gaps/range/pause/layout ${viewport.width}x${viewport.height}`);
      } catch(error) {
        await page.screenshot({path:`${directory}/${label}-failure.png`,scale:"css"}).catch(()=>{});
        const detail=await page.getByRole('region',{name:'Private network traffic',exact:true}).innerText().catch(()=>'(panel unavailable)');
        fs.writeFileSync(`${directory}/${label}-failure.json`,JSON.stringify({error:String(error),errors,panel:detail.slice(0,10000)},null,2));
        throw error;
      } finally {await context.close();}
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
