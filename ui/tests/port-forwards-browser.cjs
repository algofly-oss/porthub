// Local mocked owner API; real SSH and API authorization have separate gates.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const { launchBrowser } = require("./browser.cjs");
const base = new URL(
  process.env.PORTHUB_TEST_UI_URL || process.env.REVIEW_ORIGIN,
);
assert(["localhost", "127.0.0.1"].includes(base.hostname));
const machine = "202020202020202020202020";
const secondMachine = "303030303030303030303030";
const id = "123456781234567812345678";
const cleanCommand = "ssh -N -F ./porthub.conf forward";
async function choose(page, label, option) {
  await page.getByLabel(label, { exact: true }).click();
  await page.getByRole("option", { name: option, exact: true }).click();
}
(async () => {
  const { makeDemoData, handleDemoRequest } = await import(
    "../src/shared/demo/data.mjs"
  );
  const browser = await launchBrowser();
  try {
    for (const width of [1440, 402]) {
      const context = await browser.newContext({
        viewport: { width, height: 900 },
        serviceWorkers: "block",
        acceptDownloads: true,
      });
      await context.addInitScript(() => {
        delete Object.getPrototypeOf(navigator).serviceWorker;
        Object.defineProperty(navigator, "clipboard", {
          value: {
            writeText: async (text) => {
              window.testClipboard = text;
            },
          },
        });
      });
      const page = await context.newPage(),
        state = makeDemoData();
      let extraEntries = [], publicPorts = [];
      let entry,
        reveals = 0,
        creates = 0,
        updates = 0,
        failSave = false;
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.route("**/socket.io/**", (route) => route.abort());
      await page.route("**/api/**", async (route) => {
        const req = route.request(),
          path = new URL(req.url()).pathname,
          method = req.method();
        let body = {};
        if (path === "/api/port-forwards" && method === "GET") {
          body = {
            entries: entry ? [entry, ...extraEntries] : [],
            machines: [
              { id: machine, name: "Condor" },
              { id: secondMachine, name: "Miro" },
            ],
            groups: [],
          };
        } else if (path === "/api/port-forwards" && method === "POST") {
          const input = req.postDataJSON();
          creates++;
          assert.equal(
            input.public,
            undefined,
            "Default creation does not ask for exposure",
          );
          assert.equal(input.machineIds, undefined);
          assert.equal(input.groupIds, undefined);
          if (creates === 1)
            assert.deepEqual(input.mappings, [
              { direction: "host" },
            ]);
          else {
            assert.equal(input.mappings.length, 3);
            assert.equal(input.mappings[2].direction, "local");
            assert.equal(input.mappings[2].machineId, machine);
          }
          entry = {
            id,
            ...input,
            public: false,
            published: false,
            machineIds: [],
            groupIds: [],
            mappings: input.mappings.map((mapping, index) => ({
              ...mapping,
              ...(mapping.direction !== "local"
                ? { gatewayPort: 24000 + index }
                : { target: "host-" + machine }),
            })),
            status: {
              connected: false,
              ready: false,
              privateHost: "condor-notebook.forwards.phub",
              publicHost: "gateway.example",
              reason: "Waiting for SSH connection",
            },
          };
          body = { id };
        } else if (
          path === `/api/port-forwards/${id}/audience` &&
          method === "PUT"
        ) {
          updates++;
          if (failSave) {
            failSave = false;
            return route.fulfill({
              status: 409,
              contentType: "application/json",
              body: JSON.stringify({
                detail: "Selected machine is no longer available.",
              }),
            });
          }
          const input = req.postDataJSON();
          assert.deepEqual(Object.keys(input).sort(), [
            "groupIds",
            "machineIds",
            "public",
          ]);
          entry = {
            ...entry,
            ...input,
            published:
              input.public ||
              !!input.machineIds.length ||
              !!input.groupIds.length,
          };
          body = { id };
        } else if (path === `/api/port-forwards/${id}` && method === "PATCH") {
          entry.name = req.postDataJSON().name;
          assert.equal(req.postDataJSON().hostname, "new-notebook");
          entry.status.privateHost = "new-notebook.forwards.phub";
          body = { id };
        } else if (path.startsWith(`/api/port-forwards/${id}/public-ports`)) {
          if (method === "POST") {
            const { clientPort } = req.postDataJSON();
            assert.equal(clientPort, 8888);
            publicPorts = [{ clientPort, gatewayPort: 35000, host: "gateway.example" }];
          }
          if (method === "DELETE") {
            assert(path.endsWith("/8888"));
            publicPorts = [];
          }
          body = { ports: publicPorts };
        } else if (path.endsWith("/credentials")) {
          reveals++;
          body = {
            launcherToken: "test-launch-token",
            gateway: "gateway.example",
            sshPort: 8347,
            username: "pf-" + id,
            hostKey: "ssh-ed25519 AAAA",
            fingerprint: "SHA256:test",
            privateKey:
              "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            mappings: entry.mappings,
          };
        } else if (path === `/api/port-forwards/${id}` && method === "DELETE") {
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
      const shot = async (name) => {
        if (!process.env.PORTHUB_TEST_SCREENSHOT_DIR) return;
        await fs.mkdir(process.env.PORTHUB_TEST_SCREENSHOT_DIR, {
          recursive: true,
        });
        await page.screenshot({
          path: `${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/${process.env.REVIEW_BROWSER || "chromium"}-${name}-${width}.png`,
          fullPage: true,
        });
      };
      await page.goto(base + "home?view=transfers");
      const pair = page.getByRole("tab", { name: "PairDrop", exact: true });
      const tab = page.getByRole("tab", { name: "Port forwards", exact: true });
      await pair.focus();
      await pair.press("ArrowRight");
      assert.equal(await tab.getAttribute("aria-selected"), "true");
      const newForward = page.getByRole("button", { name: "New forward", exact: true });
      const createDialog = page.getByRole("dialog", { name: "New port forward" });
      await page.getByText("No saved forwards", { exact: true }).waitFor();
      assert.equal(await page.getByRole("button", { name: "Generate command" }).count(), 0);
      for (const dismissal of ["Cancel", "Escape"]) {
        await newForward.click();
        await createDialog.waitFor();
        if (dismissal === "Cancel") await createDialog.getByRole("button", { name: "Cancel" }).click();
        else await page.keyboard.press("Escape");
        await createDialog.waitFor({ state: "hidden" });
        await page.waitForFunction(() => document.activeElement?.textContent.trim() === "New forward");
      }
      await newForward.click();
      await createDialog.getByRole("button", { name: "Generate command" }).waitFor();
      assert.equal(await page.getByLabel("Port on this computer", { exact: true }).count(), 0);
      assert.equal(
        await page.locator("select").count(),
        0,
        "No native dropdowns",
      );
      assert.equal(
        await page.getByLabel("Access mode", { exact: true }).count(),
        0,
      );
      assert.equal(await page.getByRole("checkbox").count(), 0);
      await page.getByLabel("Profile name", { exact: false }).fill("Condor notebook");
      await shot("default");
      // A single click generates the default isolated command.
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .click();
      const launcher = page.getByLabel("Reusable SSH command", { exact: true });
      await launcher.waitFor();
      const launcherUrl = new URL(`/api/port-forwards/${id}/launcher`, base);
      launcherUrl.protocol = "https:";
      const expectedLauncher = `curl -fsS -H 'Authorization: Bearer test-launch-token' '${launcherUrl.href}' | sh`;
      assert.equal(await launcher.textContent(), expectedLauncher);
      await page.getByRole("button", { name: "Copy connection command" }).click();
      assert.equal(await page.evaluate(() => window.testClipboard), expectedLauncher);
      await choose(page, "Command for", "Windows · PowerShell / OpenSSH");
      await page.getByRole("button", { name: "Copy connection command" }).click();
      const windowsLauncher = await page.evaluate(() => window.testClipboard);
      assert(windowsLauncher.includes("curl.exe -fsS -H 'Authorization: Bearer test-launch-token'"));
      assert(windowsLauncher.includes(launcherUrl.href + "?shell=powershell"));
      assert(windowsLauncher.includes("if ($LASTEXITCODE -eq 0)"));
      await choose(page, "Command for", "Linux / macOS · OpenSSH");
      await page.getByText("Download an SSH profile", { exact: true }).click();
      const command = page.getByLabel("SSH command", { exact: true });
      await command.waitFor();
      assert.equal(await command.textContent(), cleanCommand);
      assert.equal(
        await command.evaluate(
          (element) =>
            element.scrollWidth <= element.clientWidth &&
            element.scrollHeight <= element.clientHeight,
        ),
        true,
        "Complete clean command fits without clipping",
      );

      assert.equal(
        await page.getByText("condor-notebook.forwards.phub:24000", { exact: true }).count(),
        0,
      );
      assert.equal(
        await page.getByText("gateway.example:24000", { exact: true }).count(),
        0,
      );
      assert.equal(
        await page
          .getByRole("textbox", {
            name: "Self-contained SSH command",
            exact: true,
          })
          .isVisible(),
        false,
      );
      const downloaded = page.waitForEvent("download");
      await page
        .getByRole("button", { name: "Download SSH profile", exact: true })
        .click();
      const download = await downloaded;
      assert.equal(download.suggestedFilename(), `porthub-condor-notebook-pf-${id}.zip`);
      const zip = await fs.readFile(await download.path());
      assert.equal(zip.readUInt32LE(0), 0x04034b50);
      // Inspect the actual downloaded file, not only the click event.
      const { unzipSync, strFromU8 } = require("fflate");
      const files = unzipSync(zip);
      assert.deepEqual(Object.keys(files).sort(), [
        "porthub.conf",
        "porthub.key",
        "porthub.known_hosts",
      ]);
      assert.match(
        strFromU8(files["porthub.conf"]),
        /RemoteForward 127\.0\.0\.1:24000$/m,
      );
      assert.match(
        strFromU8(files["porthub.key"]),
        /BEGIN OPENSSH PRIVATE KEY/,
      );
      assert.match(strFromU8(files["porthub.known_hosts"]), /ssh-ed25519 AAAA/);
      await page
        .getByRole("button", { name: "Copy command", exact: true })
        .click();
      assert.equal(
        await page.evaluate(() => window.testClipboard),
        cleanCommand,
      );
      const closeSettings = () => page.getByRole("button", { name: "Close forward settings", exact: true }).click();
      const settingsSection = name => page.getByRole("dialog").getByRole("button", { name, exact: true }).click();
      await closeSettings();
      const layout = await page.evaluate(() => {
        const panel = document.getElementById("transfer-panel").getBoundingClientRect();
        const footer = document.querySelector('footer[aria-label="Forwards pagination"]').getBoundingClientRect();
        const table = document.querySelector('table[aria-label="Saved port forwards"]').getBoundingClientRect();
        return {
          fullWidth: Math.abs(table.width - panel.width) < 3,
          footerAtBottom: Math.abs(footer.bottom - panel.bottom) < 3,
          footerWidth: Math.abs(footer.width - panel.width) < 3,
        };
      });
      assert.deepEqual(layout, { fullWidth: true, footerAtBottom: true, footerWidth: true });
      await shot("inventory");
      const row = page.getByRole("row", { name: "Configure Condor notebook" });
      assert.equal(await row.getByRole("button").count(), 0);
      if (width === 402) await row.click();
      else { await row.focus(); await row.press("Enter"); }
      await settingsSection("Public ports");
      await page.getByLabel("Port on this computer").fill("8888");
      await page.getByRole("button", { name: "Publish port", exact: true }).click();
      await page.getByText("gateway.example:35000", { exact: true }).waitFor();
      await shot("public");
      await settingsSection("Access");
      await choose(page, "Access mode", "Selected PortHub machines and groups");
      const picker = page.getByRole("searchbox", {
        name: "Allowed machines and groups",
        exact: true,
      });
      await picker.fill("Con");
      await page.getByRole("option", { name: "Condor", exact: true }).click();
      await picker.fill("Mir");
      assert.equal(
        await page.getByRole("option", { name: "Condor", exact: true }).count(),
        0,
      );
      await page.getByRole("option", { name: "Miro", exact: true }).click();
      await picker.press("Escape");
      const pill = page
        .locator(".mantine-MultiSelect-value")
        .filter({ hasText: "Condor" });
      await pill.locator("button").click();
      assert.equal(
        await page
          .locator(".mantine-MultiSelect-value")
          .filter({ hasText: "Condor" })
          .count(),
        0,
      );
      await picker.focus();
      await picker.press("Backspace");
      assert.equal(
        await page.locator(".mantine-MultiSelect-value").count(),
        0,
        "Keyboard can remove the remaining pill",
      );
      await picker.fill("Mir");
      await page.getByRole("option", { name: "Miro", exact: true }).click();
      await picker.press("Escape");
      failSave = true;
      await page
        .getByRole("button", { name: "Save access", exact: true })
        .click();
      await page
        .getByRole("alert")
        .filter({ hasText: "Selected machine is no longer available." })
        .waitFor();
      assert.equal(
        entry.public,
        false,
        "Failed edit leaves saved access intact",
      );
      assert.equal(creates, 1);
      assert.equal(reveals, 1);
      await shot("private-editor");
      await page
        .getByRole("button", { name: "Save access", exact: true })
        .click();
      await page
        .getByRole("form", { name: "Edit access for Condor notebook", exact: true })
        .waitFor({ state: "hidden" });
      await page.getByRole("dialog").getByText("condor-notebook.forwards.phub", { exact: true }).waitFor();
      await settingsSection("Public ports");
      await page.getByText("gateway.example:35000", { exact: true }).waitFor();
      await page.getByRole("button", { name: "Unpublish", exact: true }).click();
      await page.getByText("No public ports.").waitFor();

      assert.deepEqual(entry.machineIds, [secondMachine]);
      assert.equal(entry.id, id);
      assert.equal(reveals, 1);
      await settingsSection("Access");
      await choose(page, "Access mode", "Not published");
      await page
        .getByRole("button", { name: "Save access", exact: true })
        .click();
      await page.getByRole("dialog").getByText("Choose machines or groups in Access to use this hostname.", { exact: true }).waitFor();
      assert.equal(
        await page.getByText("condor-notebook.forwards.phub:24000", { exact: true }).count(),
        0,
      );
      await page
        .getByRole("form", { name: "Edit access for Condor notebook", exact: true })
        .waitFor({ state: "hidden" });
      assert.equal(creates, 1);
      assert.equal(reveals, 1);
      assert.equal(updates, 3);
      await page.getByRole("dialog").getByLabel("Profile name").fill("Renamed notebook");
      await page.getByLabel("Private hostname").fill("new-notebook");
      await page.getByRole("button", { name: "Save changes", exact: true }).click();
      await page.getByRole("dialog", { name: "Renamed notebook" }).waitFor();
      await page.getByRole("button", { name: "Delete profile", exact: true }).click();
      await page
        .getByRole("button", { name: "Delete forward", exact: true })
        .click();
      await newForward.click();
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .waitFor();
      await choose(page, "Forwarding mode", "Specific ports");
      await page
        .getByLabel("Profile name", { exact: false })
        .fill("Support laptop");
      await page
        .getByRole("textbox", { name: "Port on this computer", exact: true })
        .fill("8000-8001");
      await page
        .getByRole("button", { name: "Add mapping", exact: true })
        .click();
      const direction = page.getByLabel("Direction", { exact: true }).nth(1);
      await direction.click();
      await page
        .getByRole("option", { name: "Access a PortHub machine", exact: true })
        .click();
      await choose(page, "Destination machine", "Condor");
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .click();
      await page.getByLabel("Reusable SSH command", { exact: true }).waitFor();
      await page
        .getByText("Self-contained SSH command options", { exact: true })
        .click();
      const advanced = page.getByRole("textbox", {
        name: "Self-contained SSH command",
        exact: true,
      });
      const value = await advanced.inputValue();
      assert(value.includes("-R 127.0.0.1:24000"));
      assert(value.includes("-L 127.0.0.1:2222:"));
      assert(value.includes("StrictHostKeyChecking=yes"));
      assert(value.includes("BatchMode=yes"));
      assert(!value.includes("\n"));
      await advanced.fill(value + " ");
      await page
        .getByRole("button", {
          name: "Copy self-contained command",
          exact: true,
        })
        .click();
      assert.equal(
        await page.evaluate(() => window.testClipboard),
        value + " ",
      );
      assert.equal(await page.locator("select").count(), 0);
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        true,
      );
      await shot("advanced");
      await settingsSection("Access");
      await choose(page, "Access mode", "Public address and port");
      await page.getByRole("button", { name: "Save access", exact: true }).click();
      await page.getByRole("dialog").getByText("gateway.example:24000", { exact: true }).waitFor();
      await closeSettings();
      await pair.click();
      await tab.click();
      await page
        .getByRole("heading", { name: "Support laptop", exact: true })
        .waitFor();
      assert.equal(reveals, 2);
      assert.equal(await command.count(), 0);
      await newForward.click();
      await createDialog.getByRole("button", { name: "Cancel" }).click();
      await createDialog.waitFor({ state: "hidden" });
      await page.waitForFunction(() => document.activeElement?.textContent.trim() === "New forward");
      extraEntries = Array.from({ length: 10 }, (_, index) => ({
        ...entry, id: String(index), name: `Lab device ${index + 1}`,
      }));
      entry.status = { ...entry.status, connected: true, ready: false };
      const refreshStatus = () => page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      await refreshStatus();
      const table = page.getByRole("table", { name: "Saved port forwards" });
      await table.getByText("Connected", { exact: true }).waitFor();
      const search = page.getByRole("searchbox", { name: "Search forwards" });
      await search.fill("Lab device 10");
      await table.getByRole("heading", { name: "Lab device 10", exact: true }).waitFor();
      assert.equal(await table.getByRole("heading").count(), 1);
      await search.fill("");
      if (width === 402) await page.getByRole("button", { name: "Next page" }).click();
      else await page.getByRole("button", { name: "2", exact: true }).click();
      await table.getByRole("heading", { name: "Lab device 10", exact: true }).waitFor();
      await search.fill("Support laptop");
      await table.getByRole("row", { name: "Configure Support laptop" }).click();
      const session = page.getByRole("dialog");
      await session.getByRole("status", { name: "SSH session: Connected", exact: true }).waitFor();
      entry.status.connected = false;
      await session.getByRole("status", { name: "SSH session: Disconnected", exact: true }).waitFor({ timeout: 10000 });
      entry.status.connected = true;
      await session.getByRole("status", { name: "SSH session: Connected", exact: true }).waitFor({ timeout: 10000 });
      await closeSettings();
      entry.status.connected = false;
      await refreshStatus();
      await table.getByText("Disconnected", { exact: true }).waitFor();
      assert.deepEqual(errors, []);
      await context.close();
      console.log(
        `PASS host profile, private audience and independent public ports, rename, legacy mappings, search and pagination at ${width}px`,
      );
    }
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
