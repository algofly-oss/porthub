const { launchBrowser } = require("./browser.cjs");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const origin = process.env.REVIEW_URL || "http://luna.local:8345";
const output = process.env.REVIEW_OUTPUT || "/tmp/porthub-input-focus";
const fields = 'input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]), textarea, select';

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await launchBrowser();
  try {
    for (const theme of (process.env.REVIEW_THEME ? [process.env.REVIEW_THEME] : ["dark", "light"])) for (const width of (process.env.REVIEW_WIDTH ? [Number(process.env.REVIEW_WIDTH)] : [1512, 402])) {
      const context = await browser.newContext({ viewport: { width, height: 982 }, hasTouch: width === 402 });
      await context.addInitScript(value => localStorage.setItem("mantine-color-scheme", JSON.stringify(value)), theme);
      const page = await context.newPage();
      const errors = [], resizeNotifications = [], unexpectedRequests = [];
      let stage = "initial load";
      page.on("pageerror", error => {
        // WebKit reports Floating UI's deferred popup-size observation as a
        // browser notification, not a thrown application exception. Retain it
        // in the audit output; all actual exceptions still fail the test.
        if (error.message === "ResizeObserver loop completed with undelivered notifications.") resizeNotifications.push(stage);
        else { errors.push(error.message); console.error(`${theme} ${width} ${stage}: ${error.stack || error.message}`); }
      });
      // Demo views must never contact the deployment's actual API. Auth pages
      // below have their own explicitly mocked read-only account responses.
      await page.route("**/api/**", route => {
        unexpectedRequests.push(route.request().url());
        return route.fulfill({ json: {} });
      });
      let checked = 0;
      async function snapshot(field) {
        return field.evaluate(element => {
          const read = node => {
            const style = getComputedStyle(node);
            const result = Object.fromEntries(["backgroundColor", "color", "borderTopColor", "borderRightColor", "borderBottomColor", "borderLeftColor", "borderTopWidth", "borderRadius", "boxShadow"].map(key => [key, style[key]]));
            // A border with zero width cannot produce a visible colour change.
            for (const side of ["Top", "Right", "Bottom", "Left"]) if (style[`border${side}Width`] === "0px") result[`border${side}Color`] = "not painted";
            return result;
          };
          return { field: read(element), container: read(element.closest(".search-field") || element.parentElement) };
        });
      }
      async function audit(name, scope = page) {
        stage = name;
        const inputs = scope.locator(fields);
        for (const field of await inputs.all()) {
          if (!await field.isVisible() || !await field.isEnabled()) continue;
          await field.evaluate(element => element.blur());
          await page.mouse.move(0, 0);
          await page.waitForTimeout(180);
          const label = await field.getAttribute("aria-label") || await field.getAttribute("id") || await field.getAttribute("placeholder") || "unlabelled field";
          const before = await snapshot(field);
          if (width === 402) await field.tap(); else await field.click();
          assert.deepEqual(await snapshot(field), before, `${theme} ${width} ${name}: ${label} changed immediately on click/tap`);
          await page.waitForTimeout(180);
          assert.deepEqual(await snapshot(field), before, `${theme} ${width} ${name}: ${label} changed after focus transition`);
          assert.equal(await field.evaluate(element => getComputedStyle(element).outlineStyle), "none", `${label}: pointer focus must not add an outline`);
          if (await field.getAttribute("aria-autocomplete") === "list" || await field.getAttribute("role") === "combobox") {
            await page.keyboard.press("Escape");
            await page.getByRole("listbox").waitFor({ state: "hidden" });
          }
          checked++;
        }
      }
      async function keyboardAudit(field) {
        stage = "keyboard navigation";
        await field.click();
        const before = await snapshot(field);
        await page.keyboard.press("Shift+Tab");
        await page.keyboard.press("Tab");
        assert(await field.evaluate(element => document.activeElement === element), "Tab returns to the audited input");
        assert.equal(await field.evaluate(element => getComputedStyle(element).outlineStyle), "solid", "Keyboard navigation retains an external focus marker");
        assert.deepEqual(await snapshot(field), before, "Keyboard focus must not change field fill, border or text colour");
        await field.click();
        assert.equal(await field.evaluate(element => getComputedStyle(element).outlineStyle), "none", "Switching back to pointer removes the keyboard-only marker");
      }
      async function go(view) {
        await page.goto(`${origin}/home?demo=1&view=${view}`);
        const titles = { dashboard: "Dashboard", machines: "Machines", proxies: "Public Web Proxies", traffic: "Traffic Explorer", platform: "Platform Overview", settings: "Settings" };
        await page.getByRole("heading", { name: titles[view], exact: true }).waitFor();
        await page.waitForFunction(view => window.next?.router?.isReady && window.next.router.query.view === view, view);
      }
      try {
        for (const view of ["dashboard", "machines", "proxies", "traffic", "platform"]) {
          await go(view); await audit(view);
          if (view === "proxies") {
            await page.getByRole("button", { name: "Filters", exact: true }).click();
            await audit("proxy filters"); await page.keyboard.press("Escape");
          }
        }
        await go("settings");
        for (const category of ["Profile", "Security", "Notifications", "Appearance"]) {
          await page.getByRole("button", { name: category, exact: true }).click();
          await audit(`settings ${category}`);
        }
        await go("machines");
        await page.getByRole("button", { name: "Create machine", exact: true }).click();
        let dialog = page.getByRole("dialog", { name: "Create Machine", exact: true });
        await audit("enrollment", dialog);
        await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
        await page.getByRole("button", { name: "Groups", exact: true }).click();
        dialog = page.getByRole("dialog", { name: "Machine Groups", exact: true });
        await audit("groups", dialog);
        const groupName = dialog.getByLabel("New group name", { exact: true });
        await keyboardAudit(groupName);
        await groupName.fill("Focus audit draft");
        await audit("group typed draft", dialog);
        await page.screenshot({ path: `${output}/${theme}-${width}-groups.png` });
        await page.keyboard.press("Escape");
        await page.getByRole("button", { name: "Configure orion-dev-02", exact: true }).click();
        dialog = page.getByRole("dialog", { name: /^Configure orion-dev-02/ });
        for (const section of ["Details", "Client", "Logs", "History", "Ports"]) {
          await dialog.getByRole("button", { name: section, exact: true }).click();
          if (section === "Client") await dialog.getByRole("button", { name: /^Advanced settings/ }).click();
          await audit(`machine ${section}`, dialog);
        }
        await dialog.getByRole("button", { name: "Edit forwarding rule API", exact: true }).click();
        for (const section of ["Connection", "Access", "Traffic", "Web Addresses"]) {
          await dialog.getByRole("button", { name: section, exact: true }).click();
          await audit(`port ${section}`, dialog);
          if (section === "Connection") {
            const toggle = dialog.getByRole("checkbox", { name: "Enable service auto refresh", exact: true });
            if (await toggle.count()) {
              const track = dialog.locator(`label[for="${await toggle.getAttribute("id")}"]`);
              await track.click(); await audit("scheduled refresh interval", dialog);
              await track.click();
            }
          }
        }
        await go("proxies");
        await page.getByRole("button", { name: /^Edit proxy/ }).first().click();
        dialog = page.getByRole("dialog", { name: /^Edit Proxy Route/ });
        await dialog.getByRole("button", { name: "Add Alias", exact: true }).click();
        await audit("proxy address and aliases", dialog);
        await dialog.getByRole("button", { name: "Destination", exact: true }).click();
        await dialog.getByRole("button", { name: "Machine Port", exact: true }).click();
        await audit("proxy machine destination", dialog);
        await dialog.getByRole("button", { name: "Standalone URL", exact: true }).click();
        await audit("proxy standalone destination", dialog);
        await dialog.getByRole("button", { name: "Options", exact: true }).click();
        await audit("proxy options and textarea", dialog);
        await keyboardAudit(dialog.getByLabel("Description", { exact: true }));
        await page.screenshot({ path: `${output}/${theme}-${width}-proxy.png` });
        assert.deepEqual(unexpectedRequests, [], "Demo audit must not call the actual API");
        await page.unroute("**/api/**");
        await page.route("**/api/**", route => route.fulfill({ json: {} }));
        for (const route of ["signin", "signup"]) {
          await page.goto(`${origin}/account/${route}`);
          await page.getByPlaceholder("Enter your email").waitFor();
          await audit(`account ${route}`);
        }
        assert.deepEqual(errors, [], "No runtime or hydration errors");
        console.log(`PASS ${theme} ${width}: ${checked} input states, pointer/touch stability, keyboard focus, all pages/settings/editors/auth; no real API calls`);
        if (resizeNotifications.length) console.log(`WebKit popup-size notifications (non-fatal): ${resizeNotifications.join(", ")}`);
      } catch (error) {
        await page.screenshot({ path: `${output}/${theme}-${width}-failure.png` });
        throw error;
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
