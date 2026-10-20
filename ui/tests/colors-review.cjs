const { launchBrowser } = require("./browser.cjs");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const origin = process.env.REVIEW_URL || "http://luna.local";
const output = process.env.REVIEW_OUTPUT || "/tmp/porthub-colors-review";
const views = [["dashboard", "Dashboard"], ["machines", "Machines"], ["proxies", "Web Proxies"], ["traffic", "Traffic Explorer"], ["settings", "Settings"], ["platform", "Platform Overview"]];

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await launchBrowser();
  const errors = [], apiRequests = [];
  try {
    for (const theme of ["dark", "light"]) {
      const context = await browser.newContext({ viewport: { width: 1512, height: 982 } });
      await context.addInitScript(value => localStorage.setItem("mantine-color-scheme", JSON.stringify(value)), theme);
      const page = await context.newPage();
      page.on("pageerror", error => errors.push(error.message));
      page.on("request", request => { if (new URL(request.url()).pathname.startsWith("/api/")) apiRequests.push(request.url()); });
      async function capture(name) {
        // Wait for the short entry animation, not arbitrary network-idle: traffic polls continuously.
        await page.waitForTimeout(250);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.documentElement.scrollHeight <= innerHeight + 1), `${theme} ${name}: full-page overflow`);
        const inconsistentControls = await page.locator('[role="dialog"] input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]), [role="dialog"] textarea').evaluateAll(elements => elements.flatMap(element => {
          if (!element.getClientRects().length) return [];
          let parent = element, background = "rgba(0, 0, 0, 0)";
          while (parent && background === "rgba(0, 0, 0, 0)") { background = getComputedStyle(parent).backgroundColor; parent = parent.parentElement; }
          const tokens = ["control", "accent"].map(name => { const probe = document.createElement("span"); probe.style.color = `hsl(var(--${name}))`; element.parentElement.append(probe); const color = getComputedStyle(probe).color; probe.remove(); return color; });
          return tokens.includes(background) ? [] : [{ name: element.getAttribute("aria-label") || element.id, background, expected: tokens }];
        }));
        assert.deepEqual(inconsistentControls, [], `${theme} ${name}: inconsistent fields`);
        await page.screenshot({ path: `${output}/${theme}-${name}.png` });
      }
      async function go(view) {
        await page.goto(`${origin}/home?demo=1&view=${view}`);
        try { await page.getByRole("heading", { name: views.find(entry => entry[0] === view)[1], exact: true }).waitFor(); }
        catch (error) { await page.screenshot({path:`${output}/${theme}-failed-${view}.png`}); console.error({url:page.url(),errors,body:(await page.locator("body").innerText()).slice(0,3000)}); throw error; }
      }
      async function checkDialog(name) {
        const dialog = page.getByRole("dialog", { name, exact: typeof name === "string" });
        await dialog.waitFor();
        await page.waitForTimeout(200);
        const colours = await dialog.evaluate(element => {
          function token(name) { const probe = document.createElement("span"); probe.style.color = `hsl(var(--${name}))`; element.append(probe); const result = getComputedStyle(probe).color; probe.remove(); return result; }
          const header = element.querySelector(".mantine-Modal-header, .mantine-Drawer-header");
          const body = element.querySelector(".mantine-Modal-body, .mantine-Drawer-body");
          return { expected: token("dialog"), surface: getComputedStyle(element).backgroundColor, header: getComputedStyle(header).backgroundColor, body: getComputedStyle(body).backgroundColor };
        });
        assert.equal(colours.surface, colours.expected, `${name} surface`);
        assert.equal(colours.header, colours.expected, `${name} header`);
        assert.equal(colours.body, colours.expected, `${name} body`);
        return dialog;
      }
      async function checkTables() {
        for (const table of await page.getByRole("table").all()) {
          if (!(await table.isVisible())) continue;
          const colours = await table.evaluate(element => {
            const probe = document.createElement("span"); probe.style.color = "hsl(var(--surface))"; element.append(probe); const expected = getComputedStyle(probe).color; probe.remove();
            return { expected, body: getComputedStyle(element).backgroundColor, header: getComputedStyle(element.querySelector("thead")).backgroundColor };
          });
          assert.equal(colours.body, colours.expected, "Table uses the shared surface");
          assert.notEqual(colours.header, colours.body, "Table header remains visibly separate");
        }
      }
      for (const [view] of views) { await go(view); await capture(view); await checkTables(); }
      await go("settings");
      for (const name of ["Profile", "Security", "Notifications", "Appearance"]) { await page.getByRole("button", { name, exact: true }).click(); await capture(`settings-${name}`); }
      await page.getByRole("button", { name: "Security", exact: true }).click();
      await page.getByRole("button", { name: "Sign Out", exact: true }).first().click();
      await checkDialog(/^Sign Out.*Device\?$/); await capture("session-confirm"); await page.getByRole("dialog").last().getByRole("button", { name: "Cancel", exact: true }).click();
      await go("machines");
      await page.getByRole("button", { name: "Create machine", exact: true }).click();
      const create = await checkDialog("Create Machine"); await capture("create-machine");
      await create.getByLabel("Machine group", { exact: true }).click(); await capture("create-machine-select"); await page.keyboard.press("Escape");
      await create.getByRole("button", { name: "Cancel", exact: true }).click();
      await page.getByRole("button", { name: "Groups", exact: true }).click();
      const groups = await checkDialog("Machine Groups"); await capture("groups");
      await groups.getByLabel("New group name", { exact: true }).click();
      assert.equal(await groups.getByLabel("New group name", { exact: true }).evaluate(element => getComputedStyle(element).outlineStyle), "none");
      await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "Configure orion-dev-02", exact: true }).click();
      const machine = await checkDialog(/^Configure orion-dev-02/);
      const initialBounds = await machine.boundingBox();
      const footer = machine.locator("[data-dialog-footer]");
      for (const name of ["Ports", "Details", "Client", "Logs", "History"]) {
        await machine.getByRole("button", { name, exact: true }).click(); await capture(`machine-${name}`); await checkTables();
        assert.equal(Math.round((await machine.boundingBox()).height), Math.round(initialBounds.height));
        const footerBounds = await footer.boundingBox();
        assert(initialBounds.y + initialBounds.height - footerBounds.y - footerBounds.height < 25, "Machine footer stays at the bottom");
      }
      await machine.getByRole("button", { name: "Client", exact: true }).click();
      await machine.getByRole("button", { name: "Refresh machine token", exact: true }).click();
      const token = await checkDialog("Refresh machine token"); await capture("token-confirm"); await token.getByRole("button", { name: "Cancel", exact: true }).click();
      await machine.getByRole("button", { name: "Machine actions", exact: true }).click(); await capture("machine-menu");
      await page.getByRole("menuitem", { name: "Delete machine", exact: true }).click();
      const remove = await checkDialog("Delete machine"); await capture("machine-confirm"); await remove.getByRole("button", { name: "Cancel", exact: true }).click();
      await machine.getByRole("button", { name: "Ports", exact: true }).click();
      await machine.getByRole("button", { name: "Edit forwarding rule API", exact: true }).click();
      for (const name of ["Connection", "Access", "Traffic", "Web Addresses"]) { await machine.getByRole("button", { name, exact: true }).click(); await capture(`port-${name}`); await checkTables(); }
      await go("proxies");
      await page.getByRole("button", { name: "Filters", exact: true }).click(); await capture("proxy-filters"); await page.keyboard.press("Escape");
      await page.getByRole("button", { name: /^Edit proxy/ }).first().click();
      const proxy = await checkDialog(/^Edit Proxy Route/); const proxyBounds = await proxy.boundingBox();
      for (const name of ["Address", "Destination", "Options"]) {
        await proxy.getByRole("button", { name, exact: true }).click(); await capture(`proxy-${name}`);
        assert.equal(Math.round((await proxy.boundingBox()).height), Math.round(proxyBounds.height));
      }
      await proxy.getByRole("button", { name: "Proxy actions", exact: true }).click(); await capture("proxy-menu");
      await page.getByRole("menuitem", { name: "Delete proxy", exact: true }).click();
      await checkDialog("Delete proxy"); await capture("proxy-confirm");
      await go("machines"); await page.getByRole("button", { name: "Log out", exact: true }).click();
      await checkDialog("Log out?"); await capture("logout-confirm");
      // Responsive check of every page, plus every editor on a phone.
      for (const [device, width, height] of [["phone",402,874], ["small",320,700], ["4k",3840,2160]]) {
        await page.setViewportSize({ width, height });
        for (const [view] of views) { await go(view); await capture(`${device}-${view}`); await checkTables(); }
        if (device !== "phone") continue;
        await go("machines"); await page.getByRole("button", { name: "Create machine", exact: true }).click(); await checkDialog("Create Machine"); await capture("phone-create-machine"); await page.keyboard.press("Escape");
        await page.getByRole("button", { name: "Groups", exact: true }).click(); await checkDialog("Machine Groups"); await capture("phone-groups"); await page.keyboard.press("Escape");
        await page.getByRole("button", { name: "Configure orion-dev-02", exact: true }).click(); await checkDialog(/^Configure orion-dev-02/);
        for (const name of ["Ports", "Details", "Client", "Logs", "History"]) { await page.getByRole("dialog").last().getByRole("button", { name, exact: true }).click(); await capture(`phone-machine-${name}`); }
        await go("proxies"); await page.getByRole("button", { name: /^Edit proxy/ }).first().click(); await checkDialog(/^Edit Proxy Route/);
        for (const name of ["Address", "Destination", "Options"]) { await page.getByRole("dialog").last().getByRole("button", { name, exact: true }).click(); await capture(`phone-proxy-${name}`); }
      }
      await context.close();
      console.log(`PASS ${theme}: all page/table surfaces, editors and sections, confirmation dialogs, menus, fixed footers, phone/320px/4K layouts`);
    }
    assert.deepEqual(errors, [], "No browser errors"); assert.deepEqual(apiRequests, [], "Demo audit does not contact real infrastructure");
    console.log(`Screenshots: ${output}`);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
