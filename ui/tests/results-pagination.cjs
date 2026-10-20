const assert = require("node:assert/strict");
const { launchBrowser } = require("./browser.cjs");

(async () => {
  const { makeDemoData } = await import("../src/shared/demo/data.mjs");
  const browser = await launchBrowser();
  try {
    for (const theme of ["light", "dark"]) for (const width of [320, 402, 1512]) {
      const state = makeDemoData();
      state.platformAccounts = Array.from({ length: 31 }, (_, i) => ({ user: { ...state.user, id: `account-${i}`, name: `Account ${String(i).padStart(2,"0")}` }, machines: [] }));
      const context = await browser.newContext({ viewport: { width, height: 874 } });
      await context.addInitScript(({state, theme}) => {
        sessionStorage.setItem("porthub-demo-v1", JSON.stringify(state));
        localStorage.setItem("mantine-color-scheme", JSON.stringify(theme));
      }, {state, theme});
      const page = await context.newPage(), errors = [];
      page.on("pageerror", error => errors.push(error.message));
      for (const [view, noun] of [["machines", "Machines"], ["proxies", "Proxies"], ["traffic", "Ports"], ["platform", "Accounts"]]) {
        await page.goto(`${process.env.REVIEW_ORIGIN || "http://luna.local:8345"}/home?demo=1&view=${view}`);
        const footer = page.locator(`footer[aria-label="${noun} pagination"]`);
        await footer.waitFor();
        if (width < 640) {
          const rect = await footer.boundingBox();
          assert(rect.height <= 56, `${view}: single compact row (${rect.height}px)`);
          const previous = footer.getByRole("button", {name: "Previous page"});
          const next = footer.getByRole("button", {name: "Next page"});
          assert(await previous.isDisabled());
          await next.click();
          await page.waitForTimeout(150);
          assert(!(await previous.isDisabled()), `${view}: moved to page two`);
          assert((await next.boundingBox()).height >= 44, "Touch target at least 44px");
          await previous.click();
          if (view !== "traffic") {
            await footer.getByLabel(`${noun} per page`, {exact: true}).click();
            await page.getByRole("option", {name: "50 / page", exact: true}).click();
            await page.waitForTimeout(150);
            assert.equal(await footer.getByRole("button", {name: "Next page"}).count(), 0, "Single-page results don't waste space on disabled navigation");
          }
        }
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        await page.screenshot({path: `/tmp/porthub-pagination-${theme}-${width}-${view}.png`});
      }
      await page.goto(`${process.env.REVIEW_ORIGIN || "http://luna.local:8345"}/home?demo=1&view=dashboard`);
      await page.getByText("Last 5 minutes · all forwarded ports · bytes per second", {exact:true}).waitFor();
      assert.equal(await page.getByRole("group", {name: "Dashboard traffic window"}).count(), 0);
      const chart = page.getByRole("img", {name: /Network Activity chart/i});
      await chart.waitFor();
      await page.getByText("5m ago", {exact:true}).waitFor();
      assert.deepEqual(errors, []);
      await context.close();
      console.log(`PASS compact pagination, page-size controls, no overflow and five-minute dashboard: ${theme} ${width}`);
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
