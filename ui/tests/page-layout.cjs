const assert = require("node:assert/strict");
const { launchBrowser, navigateWorkspace, seedEmptyPolicies } = require("./browser.cjs");

(async () => {
  const browser = await launchBrowser();
  try {
    for (const theme of ["dark", "light"]) for (const width of [1440, 402, 320]) {
      const context = await browser.newContext({ viewport: { width, height: 850 } });
      await seedEmptyPolicies(context);
      await context.addInitScript(value => localStorage.setItem("mantine-color-scheme", JSON.stringify(value)), theme);
      const page = await context.newPage();
      await page.goto(`${process.env.REVIEW_ORIGIN || "http://luna.local:8345"}/home?demo=1&view=access`);
      await page.getByText("Choose who can connect", { exact: true }).waitFor();
      assert.equal(await page.getByLabel("Private workspace", { exact: true }).count(), 0, "Workspace switcher lives outside the page");
      await page.getByLabel("Search policies", { exact: true }).fill("no-result-xyz");
      assert.equal(await page.locator('[aria-label="Private policies"]').evaluate(el => [...el.querySelectorAll("*")].some(node => getComputedStyle(node).borderTopStyle === "dashed")), false);
      await page.waitForTimeout(250);
      await page.screenshot({ path: `/tmp/porthub-rules-refined-${theme}-${width}.png` });
      const workspaceButton = page.locator('button[aria-label="Workspaces"]:visible');
      if (!(await workspaceButton.count())) await page.getByRole("button", {name: "More navigation", exact: true}).click();
      await workspaceButton.click();
      await page.getByLabel("Search workspaces", {exact: true}).fill("Demo");
      const workspaceOption = page.getByRole("button", {name: "Demo Workspace owner", exact: true});
      const optionBox = await workspaceOption.boundingBox();
      assert(optionBox && optionBox.y >= 0 && optionBox.y + optionBox.height <= 850, "Workspace menu option stays accessible");
      await workspaceOption.click();
      await page.getByLabel("Search workspaces", {exact: true}).waitFor({state: "hidden"});
      await page.getByRole("heading", {name: "Access Rules", exact: true}).waitFor();
      await navigateWorkspace(page, "Traffic");
      const combined = page.locator("details").filter({ has: page.locator("summary", { hasText: "Combined traffic" }) });
      await combined.waitFor();
      assert.equal(await combined.evaluate(el => el.open), false, "Combined chart starts collapsed");
      assert(await page.locator('[aria-label="Traffic results"] button[aria-expanded="false"] svg path').count() > 0, "Collapsed port rows include traffic graphs");
      await combined.locator("summary").click();
      assert.equal(await combined.evaluate(el => el.open), true);
      await navigateWorkspace(page, "Dashboard");
      const dashboard = page.locator('[aria-label="Dashboard content"]');
      await page.getByRole("heading", { name: "Public port traffic", exact: true }).waitFor();
      await page.locator('[aria-label="Recent Web Addresses"] [aria-label^="Linked port traffic"]').first().waitFor();
      await page.waitForTimeout(250);
      const geometry = await dashboard.evaluate(el => {
        const main = document.getElementById("workspace-content").getBoundingClientRect(), box = el.getBoundingClientRect();
        el.scrollTop = el.scrollHeight;
        return { top: box.top - main.top, bottom: main.bottom - box.bottom, nested: [...el.querySelectorAll("*")].filter(child => child.scrollHeight > child.clientHeight + 2 && ["auto", "scroll"].includes(getComputedStyle(child).overflowY)).length };
      });
      assert(Math.abs(geometry.top) < 2 && Math.abs(geometry.bottom) < 2, "Dashboard scroller fills main area edge to edge");
      assert.equal(geometry.nested, 0, "No inset dashboard scroll container");
      await page.screenshot({ path: `/tmp/porthub-dashboard-scroll-${theme}-${width}.png` });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await context.close();
      console.log(`PASS page layout ${theme} ${width}`);
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
