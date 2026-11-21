// Run against a local PortHub UI. Fixtures are limited to browser state and
// owner API responses; real SSH and API authorization have separate tests.
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const fs = require("node:fs/promises");
const base = new URL(process.env.PORTHUB_TEST_UI_URL);
assert(["localhost", "127.0.0.1"].includes(base.hostname));
const machine = "202020202020202020202020",
  id = "123456781234567812345678";
(async () => {
  const { makeDemoData, handleDemoRequest } = await import(
    "../src/shared/demo/data.mjs"
  );
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH || "/usr/bin/google-chrome",
    headless: true,
  });
  try {
    for (const width of [1440, 390]) {
      const context = await browser.newContext({
        viewport: { width, height: 900 },
      });
      await context.addInitScript(() => {
        delete Object.getPrototypeOf(navigator).serviceWorker;
        Object.defineProperty(navigator, "clipboard", {
          value: {
            writeText: async (s) => {
              window.testClipboard = s;
            },
          },
        });
      });
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
      await page.getByLabel("Port on this computer").fill("8000-8001");
      await page.getByRole("checkbox", { name: "Condor" }).check();
      await page.getByRole("button", { name: "Add mapping" }).click();
      await page
        .getByLabel("Direction", { exact: true })
        .nth(1)
        .selectOption("local");
      await page.getByLabel("Destination machine").selectOption(machine);
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
      console.log("PASS Transfers forwarding lifecycle at " + width + "px");
    }
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
