const assert = require("node:assert/strict");
const { launchBrowser } = require("./browser.cjs");

async function pick(page, editor, label, search, option) {
  const input = editor.getByLabel(label, { exact: true });
  await input.click();
  await input.fill(search);
  await page.getByRole("option", { name: option, exact: true }).click();
  if (await page.getByRole("listbox").isVisible()) await page.keyboard.press("Escape");
}

(async () => {
  const { makeDemoData } = await import("../src/shared/demo/data.mjs");
  const seed = makeDemoData();
  const [source, provider, target] = seed.machines;
  source.name = "condor";
  provider.name = "luna";
  provider.connection_status = "offline";
  provider.supports_virtual_hosts = false;
  target.name = "miro";
  seed.access = { books: [], invitations: [], network: { cidr: "10.203.0.0/24", dns_suffix: "ph.io" } };
  const origin = process.env.REVIEW_ORIGIN || "http://127.0.0.1:3788";
  const browser = await launchBrowser();
  try {
    for (const width of [1280, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 820 } });
      await context.addInitScript(data => {
        if (!sessionStorage.getItem("porthub-demo-v1")) sessionStorage.setItem("porthub-demo-v1", JSON.stringify(data));
      }, seed);
      const page = await context.newPage();
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      const machines = `${origin}/home?demo=1&view=machines`;
      const configure = `${machines}&machine=${provider._id}&machineTab=virtual-hosts`;
      await page.goto(configure);
      const panel = page.getByRole("region", { name: "Virtual hosts" });
      await panel.getByText(/luna’s private connection is offline/).waitFor();
      await panel.getByLabel("Name", { exact: true }).fill("miro-via-luna");
      await panel.getByLabel("LAN IPv4 address").fill("192.168.1.57");
      await panel.getByLabel("LAN IPv4 address").press("Enter");
      await panel.getByText("miro-via-luna.ph.io", { exact: true }).waitFor();
      for (const [from, to] of [["miro-via-luna", "miro-private"], ["miro-private", "miro-via-luna"]]) {
        await panel.getByRole("button", { name: `Edit private DNS for ${from}` }).click();
        await panel.getByLabel("Private DNS name", { exact: true }).fill(to);
        await panel.getByRole("button", { name: "Save", exact: true }).click();
        await panel.getByText(`${to}.ph.io`, { exact: true }).waitFor();
      }
      await panel.getByLabel("Name", { exact: true }).fill("miro-via-luna");
      await panel.getByLabel("LAN IPv4 address").fill("192.168.1.58");
      await panel.getByRole("button", { name: "Add virtual host" }).click();
      await panel.getByRole("alert").getByText("Private name already in use").waitFor();
      await page.evaluate(id => {
        const seed = JSON.parse(sessionStorage.getItem("porthub-demo-v1"));
        seed.machines.find(machine => machine._id === id).connection_status = "online";
        sessionStorage.setItem("porthub-demo-v1", JSON.stringify(seed));
      }, provider._id);
      await page.reload();
      await panel.getByText(/Update the agent on luna/).waitFor();
      await panel.getByRole("heading", { name: "miro-via-luna" }).waitFor();
      const configTabs = page.getByRole("group", { name: "Machine configuration sections" });
      const virtualTab = configTabs.getByRole("button", { name: "Virtual Host", exact: true });
      assert.equal(await virtualTab.getAttribute("aria-pressed"), "true");
      await configTabs.getByRole("button", { name: "Shells", exact: true }).click();
      await page.getByRole("region", { name: "Shell sessions" }).waitFor();
      await virtualTab.click();
      await panel.getByRole("heading", { name: "miro-via-luna" }).waitFor();
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({ path: `/tmp/porthub-vh-${width}.png` });

      await page.goto(machines);
      await page.getByLabel("Search machines", { exact: true }).fill("miro-via-luna");
      const row = page.getByRole("row").filter({ hasText: "miro-via-luna" });
      await row.getByText(`Virtual host via ${provider.name}`, { exact: true }).waitFor();
      await row.click();
      const details = page.getByRole("dialog", { name: "miro-via-luna" });
      await details.getByText("192.168.1.57").waitFor();
      assert.equal(await details.getByRole("button", { name: /shells|open shell|update client/i }).count(), 0);
      await page.goto(`${machines}&machine=${encodeURIComponent(new URL(page.url()).searchParams.get("machine"))}&machineTab=shells`);
      await details.getByText("192.168.1.57").waitFor();
      assert.equal(await page.getByRole("region", { name: "Shell sessions" }).count(), 0);
      await details.getByRole("button", { name: `Manage on ${provider.name}` }).click();
      await panel.waitFor();

      await page.goto(`${origin}/home?demo=1&view=access`);
      await page.getByRole("button", { name: "Policy", exact: true }).click();
      const editor = page.getByRole("dialog", { name: "New Policy" });
      await editor.getByLabel("Policy name", { exact: true }).fill("Condor to virtual Miro");
      await editor.getByLabel("Rule name", { exact: true }).fill("HTTPS");
      await pick(page, editor, "Policy group", "Development", "Development");
      const sources = editor.getByLabel("Source entities", { exact: true });
      await sources.click();
      await sources.fill("miro-via-luna");
      await page.getByText("No matching options", { exact: true }).waitFor();
      await sources.fill("miro");
      await page.getByRole("option", { name: "Machine · miro", exact: true }).waitFor();
      await page.keyboard.press("Escape");
      await pick(page, editor, "Source entities", "condor", "Machine · condor");
      await pick(page, editor, "Destination entities", "miro-via-luna", `Machine · miro-via-luna (via ${provider.name})`);
      await editor.getByLabel("Allow both directions").press("Space");
      await editor.getByText(/Virtual hosts can only reply/).waitFor();
      await editor.getByLabel("Allow both directions").press("Space");
      await editor.getByLabel("Rule ports", { exact: true }).fill("443");
      await editor.getByRole("button", { name: "Save Policy", exact: true }).click();
      await editor.waitFor({ state: "hidden" });
      const saved = await page.evaluate(() => JSON.parse(sessionStorage.getItem("porthub-demo-v1")));
      assert.deepEqual(saved.access.books[0].rules[0].sources, [{ kind: "machine", id: source._id }]);
      assert.notEqual(target._id, saved.virtualHosts[0].id);
      assert.deepEqual(saved.access.books[0].rules[0].destinations, [{ kind: "machine", id: saved.virtualHosts[0].id }]);
      await page.goto(configure);
      await panel.getByRole("button", { name: "Remove miro-via-luna" }).click();
      await panel.getByRole("button", { name: "Cancel", exact: true }).click();
      await panel.getByRole("button", { name: "Remove miro-via-luna" }).click();
      await panel.getByRole("button", { name: "Remove virtual host", exact: true }).click();
      await panel.getByRole("heading", { name: "miro-via-luna" }).waitFor({ state: "detached" });
      await page.reload();
      await panel.getByLabel("Name", { exact: true }).waitFor();
      assert.equal(await panel.getByRole("heading", { name: "miro-via-luna" }).count(), 0);
      assert.deepEqual(errors, []);
      await context.close();
      console.log(`PASS virtual host management and access rule picker at ${width}px`);
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
