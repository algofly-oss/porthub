const assert = require('node:assert/strict');
const { launchBrowser } = require('./browser.cjs');

(async () => {
  const { makeDemoData, handleDemoRequest } = await import('../src/shared/demo/data.mjs');
  const browser = await launchBrowser();
  try {
    // iPhone 16 Pro logical viewport, including a sideways phone.
    for (const viewport of [{ width: 402, height: 874 }, { width: 874, height: 402 }]) {
      const context = await browser.newContext({ viewport, isMobile: true, hasTouch: true, deviceScaleFactor: 3, serviceWorkers: 'block' });
      const page = await context.newPage();
      const state = makeDemoData();
      await context.route('**/api/**', async route => {
        const request = route.request(), path = new URL(request.url()).pathname;
        let data;
        if (path === '/api/keyboard/targets') data = { targets: [] };
        else if (path === '/api/keyboard/speech') data = { settings: { enabled: false, model: '', device: 'cpu' }, models: [] };
        else if (path === '/api/machines/metrics') data = { machines: [{ id: state.machines[1]._id, name: state.machines[1].name, live: true, reading: { at: Date.now(), sample: { cpu: 24, cores: 8, ram: { used: 4 * 1024 ** 3, total: 16 * 1024 ** 3 }, disk: { used: 50 * 1024 ** 3, total: 1024 ** 4 }, gpus: [] } } }] };
        else if (path.startsWith('/api/machines/metrics/')) data = { latest: null, history: [], drives: [] };
        else { try { data = handleDemoRequest(state, request.method(), request.url()); } catch { data = {}; } }
        await route.fulfill({ json: data });
      });
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      for (const view of ['dashboard', 'machines', 'keyboard', 'settings', 'traffic', 'access']) {
        await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3019'}/home?view=${view}`);
        await page.getByRole('complementary', { name: 'Main navigation' }).waitFor();
        if (view === 'keyboard') await page.getByRole('button', { name: 'VKeyboard settings', exact: true }).waitFor();
        await page.waitForTimeout(200);
        const geometry = await page.evaluate(() => ({
          overflow: document.documentElement.scrollWidth > innerWidth + 1,
          viewport: document.querySelector('meta[name=viewport]').content,
          smallFields: [...document.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=range]):not([type=color]):not([type=hidden]),textarea')]
            .filter(field => field.getBoundingClientRect().width && parseFloat(getComputedStyle(field).fontSize) < 16)
            .map(field => field.getAttribute('aria-label') || field.placeholder),
        }));
        assert.equal(geometry.overflow, false, `${view} fits ${viewport.width}px`);
        assert.deepEqual(geometry.smallFields, [], `${view}: readable fields prevent iOS focus zoom`);
        assert(!/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(?:\D|$)/i.test(geometry.viewport), 'Pinch zoom remains available');
        await page.screenshot({ path: `/tmp/porthub-iphone16-${process.env.REVIEW_BROWSER || 'chromium'}-${viewport.width}-${view}.png` });
        if (view === 'dashboard') {
          await page.getByRole('region', { name: 'Machine resource utilization' }).getByRole('button').filter({ hasText: state.machines[1].name }).click();
          const dialog = page.getByRole('dialog');
          await dialog.waitFor();
          await page.waitForTimeout(250);
          const bounds = await dialog.boundingBox();
          assert(bounds.x >= -1 && bounds.x + bounds.width <= viewport.width + 1, 'Host configuration fits the phone');
          await page.screenshot({ path: `/tmp/porthub-iphone16-host-${process.env.REVIEW_BROWSER || 'chromium'}-${viewport.width}.png` });
          await page.keyboard.press('Escape');
          await dialog.waitFor({ state: 'hidden' });
        }
        if (view === 'keyboard') {
          await page.getByRole('button', { name: 'VKeyboard settings', exact: true }).click();
          const dialog = page.getByRole('dialog');
          await dialog.waitFor();
          await page.waitForTimeout(250);
          const bounds = await dialog.boundingBox();
          assert(bounds.x >= -1 && bounds.x + bounds.width <= viewport.width + 1, 'Keyboard settings fit the phone');
          const close = page.getByRole('button', { name: 'Close VKeyboard settings', exact: true });
          await close.scrollIntoViewIfNeeded();
          const target = await close.boundingBox();
          assert(target.y >= 0 && target.y + target.height <= viewport.height, 'Settings close remains reachable');
          await page.screenshot({ path: `/tmp/porthub-iphone16-settings-${process.env.REVIEW_BROWSER || 'chromium'}-${viewport.width}.png` });
          await close.click();
          await dialog.waitFor({ state: 'hidden' });
        }
      }
      assert.deepEqual(errors, []);
      await context.close();
      console.log(`PASS iPhone 16 Pro ${viewport.width}×${viewport.height}: six views fit, fields ≥16px, pinch zoom enabled`);
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
