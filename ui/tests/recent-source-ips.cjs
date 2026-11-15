const assert = require('node:assert/strict');
const { launchBrowser } = require('./browser.cjs');
(async () => {
  const { makeDemoData } = await import('../src/shared/demo/data.mjs');
  const browser = await launchBrowser();
  try {
    for (const width of [320, 1512]) {
      const state = makeDemoData();
      state.connections.find(c => c.machine_name === 'orion-dev-02' && c.service_name === 'API').firewall.allowed_ips = ['192.0.2.25'];
      state.recentIpHitsByConnection = Object.fromEntries(state.connections.filter(c=>c.machine_name==='luna-home-03').map(c=>[c._id,[{ip:'203.0.113.82',last_seen:1700000000}]]));
      state.recentIpHits = [{ip:'192.0.2.25',last_seen:1700000000},{ip:'198.51.100.91',last_seen:null}];
      const context = await browser.newContext({viewport:{width,height:982}});
      await context.addInitScript(state => sessionStorage.setItem('porthub-demo-v1',JSON.stringify(state)),state);
      const page = await context.newPage();
      const errors=[];page.on('pageerror',error=>errors.push(error.message));
      await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3019'}/home?demo=1&view=machines`);
      await page.getByRole('button',{name:'Configure orion-dev-02',exact:true}).click();
      const dialog=page.getByRole('dialog',{name:/^Configure orion-dev-02/});
      await dialog.getByRole('button',{name:'Ports',exact:true}).click();
      await dialog.getByRole('button',{name:'Edit forwarding rule API',exact:true}).click();
      await dialog.getByRole('button',{name:'Traffic',exact:true}).click();
      const list=dialog.getByRole('region',{name:'Recent source IPs'});
      await list.getByText('198.51.100.91',{exact:true}).waitFor();
      assert.equal(await list.getByText('192.0.2.25',{exact:true}).count(),1,'Allowed address remains visible');
      assert.equal(await list.getByText('127.0.0.1',{exact:true}).count(),0,'No invented loopback suggestion');
      assert.equal(await list.locator('time').getAttribute('datetime'),'2023-11-14T22:13:20.000Z');
      assert.match(await list.innerText(),/Time unavailable/);
      assert.equal(await list.getByRole('button').count(),0,'Observation rows cannot change access');
      const rect=await list.boundingBox();assert(rect.x>=0&&rect.x+rect.width<=width,'List fits viewport');
      await list.scrollIntoViewIfNeeded();
      await page.screenshot({path:`/tmp/porthub-recent-source-ips-${width}.png`,fullPage:true});
      const count=()=>page.evaluate(()=>JSON.parse(sessionStorage.getItem('porthub-demo-v1')).recentIpHitsRequests||0);
      await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));});
      const before=await count();await page.waitForTimeout(5200);assert.equal(await count(),before,'Hidden page does not poll');
      await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));});
      await page.waitForTimeout(200);assert((await count())>before,'Visible page refreshes');
      await dialog.getByRole('button',{name:'Connection',exact:true}).click();
      const stopped=await count();await page.waitForTimeout(5200);assert.equal(await count(),stopped,'Other tabs do not poll');
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      await dialog.waitFor({state:'hidden'});
      await page.getByRole('button',{name:'Configure luna-home-03',exact:true}).click();
      const nextHost=page.getByRole('dialog',{name:/^Configure luna-home-03/});
      await nextHost.getByRole('button',{name:'Ports',exact:true}).click();
      await nextHost.getByRole('button',{name:'Edit forwarding rule Dashboard',exact:true}).click();
      await nextHost.getByRole('button',{name:'Traffic',exact:true}).click();
      const nextList=nextHost.getByRole('region',{name:'Recent source IPs'});
      await nextList.getByText('203.0.113.82',{exact:true}).waitFor();
      assert.equal(await nextList.getByText('192.0.2.25',{exact:true}).count(),0,'Changing hosts does not retain the previous host observations');
      assert.deepEqual(errors,[]);await context.close();console.log(`PASS recent source IPs ${width}`);
    }
    for (const failed of [false, true]) {
      const state=makeDemoData();state.recentIpHits=[];state.recentIpHitsError=failed;
      const context=await browser.newContext({viewport:{width:320,height:982}});
      await context.addInitScript(state=>sessionStorage.setItem('porthub-demo-v1',JSON.stringify(state)),state);
      const page=await context.newPage();
      await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3019'}/home?demo=1&view=machines`);
      await page.getByRole('button',{name:'Configure orion-dev-02',exact:true}).click();
      const dialog=page.getByRole('dialog',{name:/^Configure orion-dev-02/});
      await dialog.getByRole('button',{name:'Ports',exact:true}).click();
      await dialog.getByRole('button',{name:'Edit forwarding rule API',exact:true}).click();
      await dialog.getByRole('button',{name:'Traffic',exact:true}).click();
      const list=dialog.getByRole('region',{name:'Recent source IPs'});
      await list.getByText(failed ? 'Couldn’t load recent observations.' : 'No recent connection attempts observed.',{exact:true}).waitFor();
      assert.equal(await list.getByRole('button',{name:'Retry',exact:true}).count(),failed?1:0);
      assert.equal(await list.getByRole('table').count(),0);
      await context.close();console.log(`PASS recent source IPs ${failed?'unavailable':'known empty'}`);
    }
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1);});
