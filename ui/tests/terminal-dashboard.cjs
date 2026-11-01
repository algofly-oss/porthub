const assert = require('node:assert/strict');
const {launchBrowser} = require('./browser.cjs');
(async () => {
  const {makeDemoData} = await import('../src/shared/demo/data.mjs');
  const {demoTerminalTraffic} = await import('../src/shared/utils/terminal-traffic.mjs');
  const browser = await launchBrowser();
  const origin = process.env.REVIEW_ORIGIN || 'http://127.0.0.1:32923';
  try {
    for (const theme of ['dark','light']) for (const width of [1512,402,320]) {
      const context = await browser.newContext({viewport:{width,height:1100}});
      await context.addInitScript(theme => localStorage.setItem('mantine-color-scheme',JSON.stringify(theme)),theme);
      const page = await context.newPage(), errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      await page.goto(`${origin}/home?demo=1&view=dashboard`);
      const card = page.getByRole('region',{name:'Terminal traffic',exact:true});
      const chart = card.getByRole('group',{name:/Terminal traffic chart/});
      await chart.waitFor();
      await card.getByRole('tab',{name:'Direct UDP',exact:true}).click();
      await page.waitForURL(/terminal_scope=direct/);
      await card.locator('#terminal-scope-direct[aria-selected="true"]').waitFor();
      await chart.focus(); await page.keyboard.press('Home');
      await card.getByRole('status').filter({hasText:'No report for this interval'}).waitFor();
      await page.keyboard.press('End');
      await card.getByRole('status').filter({hasText:/Received .*Sent /}).waitFor();
      await card.getByRole('tab',{name:'Direct UDP',exact:true}).focus();
      await page.keyboard.press('ArrowRight');
      await page.waitForURL(/terminal_scope=pty/);
      await card.locator('#terminal-scope-pty[aria-selected="true"]').waitFor();
      await card.getByLabel('Terminal traffic range',{exact:true}).selectOption('24h');
      await page.waitForURL(/terminal_range=24h/);
      const machine = card.getByLabel('Terminal traffic machine',{exact:true});
      await machine.click(); await machine.fill('atlas');
      await page.getByRole('option',{name:'atlas-prod-01',exact:true}).click();
      await page.waitForURL(/terminal_machine=[a-f0-9]{24}/);
      await page.reload(); await chart.waitFor();
      assert.equal(await card.getByLabel('Terminal traffic range',{exact:true}).inputValue(),'24h');
      await card.locator('#terminal-scope-pty[aria-selected="true"]').waitFor();
      await card.getByRole('button',{name:'Pause terminal measurements',exact:true}).click();
      await card.getByText('Paused',{exact:true}).waitFor();
      await card.getByText('About these measurements',{exact:true}).click();
      await card.getByText(/These views overlap; do not add them together/).waitFor();
      await card.getByText('About these measurements',{exact:true}).click();
      await card.scrollIntoViewIfNeeded();
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'dashboard must not overflow');
      await card.screenshot({path:`/tmp/porthub-terminal-dashboard-${process.env.REVIEW_BROWSER || "chromium"}-${theme}-${width}.png`});
      assert.deepEqual(errors,[]); await context.close();
      console.log('PASS terminal dashboard controls, URL, keyboard and layout',theme,width);
    }
    for (const mode of ['empty','error','invalid','legacy','zero']) {
      const state=makeDemoData();
      if(mode==='zero'){state.terminalTraffic=demoTerminalTraffic();for(const point of state.terminalTraffic.points)for(const key of ['relay_sent','relay_received','udp_sent','udp_received','pty_input','pty_output'])point[key]=0;}
      if(mode==='legacy'){state.terminalTraffic=demoTerminalTraffic();for(const point of state.terminalTraffic.points){point.host_reports=0;point.unreported_hosts=1;point.udp_sent=0;point.pty_output=0;}}
      if(mode==='empty')state.terminalTraffic=demoTerminalTraffic('1h','all',false);
      if(mode==='error')state.terminalTrafficError='fixture outage';
      if(mode==='invalid'){state.terminalTraffic=demoTerminalTraffic();state.terminalTraffic.points[0].udp_sent=-1;}
      const context=await browser.newContext({viewport:{width:402,height:1000}});
      await context.addInitScript(state=>sessionStorage.setItem('porthub-demo-v1',JSON.stringify(state)),state);
      const page=await context.newPage();await page.goto(`${origin}/home?demo=1&view=dashboard`);
      const card=page.getByRole('region',{name:'Terminal traffic',exact:true});
      if(mode==='zero'){state.terminalTraffic=demoTerminalTraffic();for(const point of state.terminalTraffic.points)for(const key of ['relay_sent','relay_received','udp_sent','udp_received','pty_input','pty_output'])point[key]=0;}
      if(mode==='zero'){await card.getByRole('group',{name:/Terminal traffic chart/}).waitFor();await card.getByText('0 B peak',{exact:true}).waitFor();console.log('PASS terminal dashboard measured zero');await context.close();continue;}
      if(mode==='legacy'){
        await card.getByRole('group',{name:/Terminal traffic chart/}).waitFor();
        await card.getByRole('tab',{name:'Direct UDP',exact:true}).click();
        await card.getByText('No terminal measurements in this window',{exact:true}).waitFor();
        await card.getByText('Some terminal hosts have incomplete measurements. Totals include only reporting hosts.',{exact:true}).waitFor();
        assert.equal(await card.getByRole('group',{name:/Terminal traffic chart/}).count(),0);
        console.log('PASS terminal dashboard legacy coverage');await context.close();continue;
      }
      await card.getByText(mode==='empty'?'No terminal measurements in this window':'No snapshot available',{exact:true}).waitFor();
      assert.equal(await card.getByRole('group',{name:/Terminal traffic chart/}).count(),0);
      if(mode!=='empty')await card.getByRole('alert').waitFor();
      console.log('PASS terminal dashboard state',mode);await context.close();
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
