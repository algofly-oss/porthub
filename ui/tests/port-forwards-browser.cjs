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
            entries: entry ? [entry] : [],
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
              { direction: "remote", clientPort: 22 },
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
              ...(mapping.direction === "remote"
                ? { gatewayPort: 24000 + index }
                : { target: "host-" + machine }),
            })),
            status: {
              ready: false,
              privateHost: "test.phub",
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
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .waitFor();
      assert.equal(
        await page
          .getByRole("textbox", { name: "Port on this computer", exact: true })
          .inputValue(),
        "22",
      );
      assert.equal(
        await page
          .getByRole("button", { name: "New forward", exact: true })
          .count(),
        0,
      );
      assert.equal(
        await page.getByRole("button", { name: "Cancel", exact: true }).count(),
        0,
      );
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
      await shot("default");
      // A single click generates the default isolated command.
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .click();
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
      await page.getByText("Not published", { exact: true }).waitFor();
      assert.equal(
        await page.getByText("test.phub:24000", { exact: true }).count(),
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
      assert.equal(download.suggestedFilename(), `porthub-pf-${id}.zip`);
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
        /RemoteForward 127\.0\.0\.1:24000 127\.0\.0\.1:22/,
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
      await shot("isolated-command");
      await page
        .getByRole("button", { name: "Edit access", exact: true })
        .click();
      await choose(page, "Access mode", "Public address and port");
      await page
        .getByRole("button", { name: "Save access", exact: true })
        .click();
      await page
        .getByRole("form", { name: "Edit access for Port 22", exact: true })
        .waitFor({ state: "hidden" });
      await page.getByText("gateway.example:24000", { exact: true }).waitFor();
      assert.equal(await command.textContent(), cleanCommand);
      assert.equal(creates, 1);
      assert.equal(reveals, 1);
      await shot("public");
      await page
        .getByRole("button", { name: "Edit access", exact: true })
        .click();
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
        true,
        "Failed edit leaves saved access intact",
      );
      assert.equal(creates, 1);
      assert.equal(reveals, 1);
      await shot("private-editor");
      await page
        .getByRole("button", { name: "Save access", exact: true })
        .click();
      await page
        .getByRole("form", { name: "Edit access for Port 22", exact: true })
        .waitFor({ state: "hidden" });
      await page.getByText("test.phub:24000", { exact: true }).waitFor();
      assert.deepEqual(entry.machineIds, [secondMachine]);
      assert.equal(entry.id, id);
      assert.equal(reveals, 1);
      await page
        .getByRole("button", { name: "Edit access", exact: true })
        .click();
      await choose(page, "Access mode", "Not published");
      await page
        .getByRole("button", { name: "Save access", exact: true })
        .click();
      await page.getByText("Not published", { exact: true }).waitFor();
      assert.equal(
        await page.getByText("test.phub:24000", { exact: true }).count(),
        0,
      );
      await page
        .getByRole("form", { name: "Edit access for Port 22", exact: true })
        .waitFor({ state: "hidden" });
      assert.equal(creates, 1);
      assert.equal(reveals, 1);
      assert.equal(updates, 4);
      assert.equal(await command.textContent(), cleanCommand);
      await page
        .getByRole("button", { name: "Delete Port 22", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Delete forward", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .waitFor();
      // Retain existing advanced mixed remote/local direction behavior.
      await page
        .getByText("Advanced ports and direction", { exact: true })
        .click();
      await page
        .getByLabel("Forward name", { exact: false })
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
        .getByRole("button", {
          name: "Advanced ports and direction",
          exact: true,
        })
        .click();
      await page
        .getByText(
          "2 configured port mappings. Open advanced settings to review them.",
          { exact: true },
        )
        .waitFor();
      assert.equal(
        await page.getByLabel("Direction", { exact: true }).count(),
        0,
        "Collapsed advanced fields are unmounted",
      );
      await page
        .getByRole("button", { name: "Generate command", exact: true })
        .click();
      await page.getByLabel("SSH command", { exact: true }).waitFor();
      await page
        .getByText("Advanced: self-contained command", { exact: true })
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
      await page
        .getByRole("button", { name: "Hide credentials", exact: true })
        .click();
      await pair.click();
      await tab.click();
      await page
        .getByRole("heading", { name: "Support laptop", exact: true })
        .waitFor();
      assert.equal(reveals, 2);
      assert.equal(await command.count(), 0);
      assert.deepEqual(errors, []);
      await context.close();
      console.log(
        `PASS clean isolated generation/download, same-ID audience edits/pills/error, advanced directions at ${width}px`,
      );
    }
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
