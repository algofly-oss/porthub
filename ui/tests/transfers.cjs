const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs/promises');
const base = process.env.PORTHUB_TEST_UI_URL;
assert(base, 'An isolated local UI URL is required');
(async () => {
  const { makeDemoData, handleDemoRequest } = await import('../src/shared/demo/data.mjs');
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome' });
  try {
    const screens=[[3840,2160],[2560,1440],[1920,1080],[1728,1117],[1512,982],[1440,900],[1280,800],[1024,1366],[768,1024],[932,430],[844,390],[430,932],[393,852],[390,844],[375,667],[320,568]];
    for (const [width,height] of screens) {
      const phone=width<=430||height<=430;
      const context = await browser.newContext({ viewport: { width, height },isMobile:phone,hasTouch:phone,deviceScaleFactor:phone?3:1 });
      await context.addInitScript(() => {
        delete Object.getPrototypeOf(navigator).serviceWorker;
        window.copiedCommands = [];
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async text => window.copiedCommands.push(text) } });
      });
      const page = await context.newPage(), state = makeDemoData(), errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/socket.io/**', route => route.abort());
      await page.route('**/api/**', async route => {
        const pathname=new URL(route.request().url()).pathname;
        if(pathname.startsWith('/api/transfers'))return route.continue();
        if(pathname==='/api/boards')return route.fulfill({contentType:'application/json',body:JSON.stringify({boards:[]})});
        let body;
        try { body = handleDemoRequest(state, route.request().method().toLowerCase(), route.request().url(), route.request().postDataJSON() || {}); } catch { body = {}; }
        await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
      });
      await page.goto(base + '/home?view=transfers');
      await page.getByRole('heading', { name: 'Transfers', exact: true }).waitFor();
      const panel = page.getByRole('tabpanel');
      assert.equal(await page.getByRole('tab',{name:'From browser',exact:true}).getAttribute('aria-selected'),'true','Browser sharing is the default');
      const assertWidth=async()=>{const shell=await page.getByLabel('Transfers content',{exact:true}).boundingBox(),bounds=await panel.boundingBox();assert(bounds.width>=Math.min(shell.width,1600)-44,'Transfers uses the available workspace width at '+width+'px');};
      if(width>=1280)await assertWidth();
      if(width>=1280){await page.getByRole('button',{name:'Collapse navigation',exact:true}).click();await page.waitForTimeout(250);await assertWidth();await page.getByRole('button',{name:'Expand navigation',exact:true}).click();await page.waitForTimeout(250);}
      const checkPanel=async()=>{
        assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'No page overflow at '+width+'x'+height);
        const fits=await panel.evaluate(root=>[...root.querySelectorAll('button,a,input,select,iframe')].filter(el=>el.getClientRects().length).every(el=>{const r=el.getBoundingClientRect(),p=root.getBoundingClientRect();return r.left>=p.left-1&&r.right<=p.right+1}));assert(fits,'Controls stay inside the transfer panel at '+width+'x'+height);
      };
      await checkPanel();
      if(process.env.PORTHUB_TEST_SCREENSHOT_DIR){await fs.mkdir(process.env.PORTHUB_TEST_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:`${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/transfers-browser-${width}x${height}.png`});}
      const sharedName='Responsive file with a long name.xlsx';
      await page.getByLabel('Choose files to share',{exact:true}).setInputFiles({name:sharedName,mimeType:'application/octet-stream',buffer:Buffer.from('PortHub responsive test fixture')});
      const sharedUrl=page.getByLabel(`Public URL for ${sharedName}`,{exact:true});
      await page.waitForFunction(name=>[...document.querySelectorAll('input')].some(input=>input.getAttribute('aria-label')==='Public URL for '+name&&input.value.includes('/api/transfers/')),sharedName);
      await checkPanel();
      const clipped=await panel.locator('button,a,input,select').evaluateAll(controls=>controls.filter(el=>el.getClientRects().length).some(el=>{const rect=el.getBoundingClientRect();let parent=el.parentElement;while(parent&&parent.getAttribute('role')!=='tabpanel'){if(['hidden','clip'].includes(getComputedStyle(parent).overflowX)){const bounds=parent.getBoundingClientRect();if(rect.left<bounds.left-1||rect.right>bounds.right+1)return true;}parent=parent.parentElement;}return false;}));assert(!clipped,'Active file controls are not clipped at '+width+'x'+height);
      await page.getByRole('button',{name:`Copy URL for ${sharedName}`,exact:true}).click();assert.equal(await page.evaluate(()=>window.copiedCommands.at(-1)),await sharedUrl.inputValue());
      if(process.env.PORTHUB_TEST_SCREENSHOT_DIR)await page.screenshot({path:`${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/transfers-browser-active-${width}x${height}.png`});
      await page.getByRole('button',{name:`Stop sharing ${sharedName}`,exact:true}).click();
      await page.getByRole('tab',{name:'From terminal',exact:true}).click();

      const copy = () => panel.getByRole('button', { name: /^Copy .* command$/ });
      assert.equal(await page.locator('pre').count(), 1, 'Only one command is visible');
      assert.equal(await panel.getByRole('button', { name: 'aria2', exact: true }).count(), 0, 'aria2 is offered for downloads only');
      await page.getByLabel('File path', { exact: true }).fill("./archive's backup.zip");
      for (const tool of ['cURL', 'Wget']) {
        await panel.getByRole('button', { name: tool, exact: true }).click();
        await copy().click();
        const command = await page.evaluate(() => window.copiedCommands.at(-1));
        assert(!command.includes('\n'), 'Copied commands are single-line');
        execFileSync('bash', ['-n', '-c', command]);
        assert(command.includes(tool === 'Wget' ? 'wget -qO-' : 'curl -fsS'));
        assert(command.includes("archive'\\''s backup.zip"), 'Shell quotes survive apostrophes');
      }
      if (process.env.PORTHUB_TEST_SCREENSHOT_DIR) {
        await fs.mkdir(process.env.PORTHUB_TEST_SCREENSHOT_DIR, { recursive: true });
        await page.screenshot({ path: `${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/transfers-send-${width}.png` });
      }
      await checkPanel();
      await page.getByRole('tab', { name: 'Download', exact: true }).click();
      assert(await copy().isDisabled(), 'No placeholder download links can be copied');
      await page.getByLabel('Download URL', { exact: true }).fill('javascript:alert(1)');
      assert(await copy().isDisabled());
      await page.getByLabel('Download URL', { exact: true }).fill(base + '/api/transfers/test-download');
      assert.equal(await page.getByLabel('Save as', { exact: true }).inputValue(), '', 'Original filename is the default');
      for (const tool of ['cURL', 'Wget', 'aria2']) {
        await panel.getByRole('button', { name: tool, exact: true }).click(); await copy().click();
        const command = await page.evaluate(() => window.copiedCommands.at(-1));
        assert(!command.includes('\n'));
        assert(!command.includes('download.zip'), 'No hard-coded ZIP filename');
        if (tool === 'cURL') assert(command.startsWith('curl -fLOJ '));
        if (tool === 'Wget') assert(command.includes('--content-disposition'));
        if (tool === 'aria2') assert(!/\s-o\s/.test(command));
      }
      assert.equal(await page.getByText('How it works', {exact:true}).count(), 0);
      await page.getByLabel('Save as', { exact: true }).fill("./folder's/download.zip");
      for (const tool of ['cURL', 'Wget', 'aria2']) {
        await panel.getByRole('button', { name: tool, exact: true }).click();
        await copy().click();
        const command = await page.evaluate(() => window.copiedCommands.at(-1));
        assert(!command.includes('\n'), 'Copied commands are single-line');
        execFileSync('bash', ['-n', '-c', command]);
        assert(command.startsWith({ cURL: 'curl ', Wget: 'wget ', aria2: 'aria2c ' }[tool]));
        assert(command.includes('/api/transfers/test-download'));
        if (tool === 'aria2') assert(command.includes("-d './folder'\\''s'"), 'aria2 receives an explicit output directory');
      }
      await panel.getByRole('button', { name: 'cURL', exact: true }).click();
      await page.getByLabel('Connections', { exact: true }).selectOption('4');
      await copy().click();
      execFileSync('bash', ['-n', '-c', await page.evaluate(() => window.copiedCommands.at(-1))]);
      assert.equal(await page.locator('pre').count(), 1, 'Parallel mode replaces the command');
      if (process.env.PORTHUB_TEST_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/transfers-download-${width}.png` });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No horizontal page overflow');
      await page.getByRole('tab', { name: 'From terminal', exact: true }).click();
      await page.keyboard.press('ArrowRight');
      assert.equal(await page.getByRole('tab', { name: 'Download' }).getAttribute('aria-selected'), 'true');
      await checkPanel();
      if(width===1512){await page.getByRole('button',{name:'Boards',exact:true}).click();await page.getByRole('heading',{name:'Boards',exact:true}).waitFor();await page.getByRole('button',{name:'Transfers',exact:true}).click();assert.equal(await page.getByRole('tab',{name:'From browser',exact:true}).getAttribute('aria-selected'),'true','Returning to Transfers starts with browser sharing');}
      await page.getByRole('tab',{name:'PairDrop',exact:true}).click();await page.getByTitle('PairDrop file sharing',{exact:true}).waitFor();await checkPanel();
      if(process.env.PORTHUB_TEST_PAIRDROP_UPSTREAM){const embedded=page.frameLocator('iframe[title="PairDrop file sharing"]');await embedded.locator('x-peers').waitFor({state:'attached'});assert(await embedded.locator('html').evaluate(root=>root.scrollWidth<=innerWidth),'Embedded PairDrop fits '+width+'x'+height);}
      await page.waitForTimeout(200);
      if(process.env.PORTHUB_TEST_SCREENSHOT_DIR)await page.screenshot({path:`${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/transfers-pairdrop-${width}x${height}.png`});
      assert.deepEqual(errors, []);
      await context.close();
    }
    console.log('PASS: compact Send/Download tabs, cURL/Wget/aria2 commands, safe quoting, copy state, validation, parallel mode, keyboard and 16 responsive viewports from iPhone to 4K, all four views, both desktop sidebar layouts and browser default.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
