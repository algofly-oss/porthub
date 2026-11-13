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
    for (const width of [1440, 1024, 768, 390, 320]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      await context.addInitScript(() => {
        delete Object.getPrototypeOf(navigator).serviceWorker;
        window.copiedCommands = [];
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async text => window.copiedCommands.push(text) } });
      });
      const page = await context.newPage(), state = makeDemoData(), errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/socket.io/**', route => route.abort());
      await page.route('**/api/**', async route => {
        let body;
        try { body = handleDemoRequest(state, route.request().method().toLowerCase(), route.request().url(), route.request().postDataJSON() || {}); } catch { body = {}; }
        await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
      });
      await page.goto(base + '/home?view=transfers');
      await page.getByRole('heading', { name: 'Transfers', exact: true }).waitFor();
      const panel = page.getByRole('tabpanel');
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
      await page.getByRole('tab', { name: 'Download a file', exact: true }).click();
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
      await page.getByRole('tab', { name: 'Send a file', exact: true }).click();
      await page.keyboard.press('ArrowRight');
      assert.equal(await page.getByRole('tab', { name: 'Download a file' }).getAttribute('aria-selected'), 'true');
      assert.deepEqual(errors, []);
      await context.close();
    }
    console.log('PASS: compact Send/Download tabs, cURL/Wget/aria2 commands, safe quoting, copy state, validation, parallel mode, keyboard and five responsive widths.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
