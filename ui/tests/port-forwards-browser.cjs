// Run against a local PortHub UI. Fixtures are limited to browser state and
// owner API responses; real SSH and API authorization have separate tests.
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const fs = require("node:fs/promises");
const base = new URL(process.env.PORTHUB_TEST_UI_URL);
assert(["localhost", "127.0.0.1"].includes(base.hostname));
const machine = "202020202020202020202020",
  id = "123456781234567812345678";
async function audit(element) {
  if (!process.env.PORTHUB_TEST_AXE_PATH) return;
  const violations = await element.evaluate(async (root) =>
    (
      await window.axe.run(root, {
        runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
      })
    ).violations.map(({ id, nodes }) => ({
      id,
      nodes: nodes.map(({ target }) => target),
    })),
  );
  assert.deepEqual(violations, []);
}
(async () => {
  const { makeDemoData, handleDemoRequest } = await import(
    "../src/shared/demo/data.mjs"
  );
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH || "/usr/bin/google-chrome",
    headless: true,
  });
  try {
    for (const width of [1440, 1024, 768, 390]) {
      const context = await browser.newContext({
        viewport: { width, height: 900 },
      });
      const theme = process.env.PORTHUB_TEST_THEME || "dark";
      await context.addInitScript((theme) => {
        localStorage.setItem("mantine-color-scheme", JSON.stringify(theme));
        delete Object.getPrototypeOf(navigator).serviceWorker;
        Object.defineProperty(navigator, "clipboard", {
          value: {
            writeText: async (s) => {
              window.testClipboard = s;
            },
          },
        });
      }, theme);
      const page = await context.newPage(),
        state = makeDemoData();
      let entry,
        reveals = 0;
      const errors = [];
      page.on("pageerror", (e) => errors.push(e.message));
      await page.route("**/socket.io/**", (r) => r.abort());
      await page.route("**/api/**", async (route) => {
        const req = route.request(),
          path = new URL(req.url()).pathname,
          method = req.method();
        let body = {};
        if (path === "/api/port-forwards" && method === "GET")
          body = {
            entries: entry ? [entry] : [],
            machines: [{ id: machine, name: "Condor" }],
            groups: [],
          };
        else if (path === "/api/port-forwards" && method === "POST") {
          const input = req.postDataJSON();
          assert.equal(input.public, false);
          assert.deepEqual(input.machineIds, [machine]);
          assert.equal(input.mappings.length, 3);
          entry = {
            id,
            ...input,
            mappings: input.mappings.map((m, i) => ({
              ...m,
              ...(m.direction === "remote"
                ? { gatewayPort: 24000 + i }
                : { target: "host-" + machine }),
            })),
            status: {
              ready: false,
              privateHost: "test.phub",
              reason: "Waiting for SSH connection",
            },
          };
          body = { id };
        } else if (path.endsWith("/credentials")) {
          reveals++;
          body = {
            gateway: "gateway.example",
            sshPort: 8347,
            username: "pf-" + id,
            hostKey: "ssh-ed25519 AAAA",
            fingerprint: "SHA256:test",
            privateKey:
              "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            mappings: entry.mappings,
          };
        } else if (path === "/api/port-forwards/" + id && method === "DELETE") {
          entry = null;
          return route.fulfill({ status: 204 });
        } else {
          try {
            body = handleDemoRequest(
              state,
              method.toLowerCase(),
              req.url(),
              req.postDataJSON() || {},
            );
          } catch {}
        }
        return route.fulfill({
          contentType: "application/json",
          body: JSON.stringify(body ?? {}),
        });
      });
      await page.goto(base + "home?view=transfers");
      const pair = page.getByRole("tab", { name: "PairDrop", exact: true }),
        tab = page.getByRole("tab", { name: "Port forwards", exact: true });
      await pair.focus();
      await pair.press("ArrowRight");
      assert.equal(await tab.getAttribute("aria-selected"), "true");
      await page
        .getByRole("button", { name: "New forward", exact: true })
        .click();
      await page.getByLabel("Forward name").fill("Support laptop");
      const privateAccess = page.getByRole("radio", {
        name: "Private network",
      });
      const publicAccess = page.getByRole("radio", { name: "Public internet" });
      assert(await privateAccess.isChecked());
      await privateAccess.focus();
      await privateAccess.press("ArrowDown");
      assert(await publicAccess.isChecked());
      assert.equal(
        await page.getByRole("checkbox", { name: "Condor" }).count(),
        0,
      );
      await publicAccess.press("ArrowUp");
      assert(await privateAccess.isChecked());
      await page.getByRole("button", { name: "Generate command" }).click();
      await page
        .getByRole("alert")
        .filter({ hasText: "Select at least one machine or group" })
        .waitFor();
      const condor = page.getByRole("checkbox", { name: "Condor" });
      assert(
        await condor.evaluate((element) => element === document.activeElement),
      );
      await condor.press("Space");
      await page.getByText("1 selected", { exact: true }).waitFor();
      assert.equal(
        await page
          .getByText("Select at least one machine or group for private access.")
          .count(),
        0,
      );
      await page.getByLabel("Port on this computer").fill("8000-8001");
      await page.getByRole("button", { name: "Add mapping" }).click();
      await page
        .getByLabel("Direction", { exact: true })
        .nth(1)
        .selectOption("local");
      await page.getByLabel("Destination machine").selectOption(machine);
      if (process.env.PORTHUB_TEST_AXE_PATH) {
        await page.addScriptTag({ path: process.env.PORTHUB_TEST_AXE_PATH });
        await audit(
          page.locator("form").filter({ has: page.getByLabel("Forward name") }),
        );
      }
      if (process.env.PORTHUB_TEST_SCREENSHOT_DIR) {
        await fs.mkdir(process.env.PORTHUB_TEST_SCREENSHOT_DIR, {
          recursive: true,
        });
        await page.screenshot({
          path:
            process.env.PORTHUB_TEST_SCREENSHOT_DIR +
            "/builder-" +
            width +
            ".png",
        });
      }
      await page.getByRole("button", { name: "Generate command" }).click();
      const command = page.getByRole("textbox", { name: "SSH command" });
      await command.waitFor();
      await audit(page.getByRole("region", { name: "SSH command" }));
      await page.getByText("Private network", { exact: true }).waitFor();
      assert.equal(
        await page
          .getByRole("button", { name: "Hide credentials" })
          .getAttribute("aria-expanded"),
        "true",
      );
      const value = await command.inputValue();
      assert(value.includes("-R 127.0.0.1:24000"));
      assert(value.includes("-L 127.0.0.1:2222:"));
      assert(value.includes("StrictHostKeyChecking=yes"));
      assert(value.includes("BatchMode=yes"));
      assert(!value.includes("\n"));
      await command.fill(value + " ");
      await page.getByRole("button", { name: "Copy command" }).click();
      assert.equal(
        await page.evaluate(() => window.testClipboard),
        value + " ",
      );
      await page.getByRole("button", { name: "Reset edits" }).click();
      assert.equal(await command.inputValue(), value);
      assert(
        await command.evaluate((element) => element === document.activeElement),
      );
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        true,
      );
      if (process.env.PORTHUB_TEST_SCREENSHOT_DIR)
        await page.screenshot({
          path:
            process.env.PORTHUB_TEST_SCREENSHOT_DIR +
            "/command-" +
            width +
            ".png",
        });
      await page.getByRole("button", { name: "Hide credentials" }).click();
      await pair.click();
      await tab.click();
      await page.getByRole("heading", { name: "Support laptop" }).waitFor();
      assert.equal(reveals, 1);
      assert.equal(await command.count(), 0);
      await page.getByRole("button", { name: "Delete Support laptop" }).click();
      await page
        .getByRole("button", { name: "Delete forward", exact: true })
        .click();
      await page.getByText("No saved forwards yet.").waitFor();
      assert.deepEqual(errors, []);
      await context.close();
      console.log(
        `PASS Transfers forwarding lifecycle at ${width}px (${theme})`,
      );
    }
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
