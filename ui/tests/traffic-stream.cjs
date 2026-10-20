const { chromium } = require("playwright");
const assert = require("node:assert/strict");

(async () => {
  const { makeDemoData, handleDemoRequest } = await import("../src/shared/demo/data.mjs");
  const { buildTrafficWindow, trafficLinePath } = await import("../src/shared/utils/traffic.mjs");
  const state = makeDemoData();
  const connection = state.connections.find(port => port.machine_is_active);
  let latestRaw = [], snapshots = 0;
  const browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome" });
  try {
    const page = await browser.newPage({ viewport: {width:1512,height:982} });
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/api/**", async route => {
      const request = route.request();
      let body = {}; try { body = request.postDataJSON() || {}; } catch {}
      let data;
      if (request.url().includes("/traffic/snapshot")) {
        const now = Math.floor(Date.now()/1000);
        latestRaw = Array.from({length:180}, (_,index) => {
          const timestamp = now - 179 + index, incoming = 800 + timestamp % 17 * 80;
          return [{timestamp,in_bytes:incoming}, {timestamp,out_bytes:incoming/2}, {timestamp,drop_bytes:10}];
        }).flat();
        data = {data:[{connection,traffic:latestRaw}]}; snapshots++;
      } else data = handleDemoRequest(state, request.method().toLowerCase(), request.url(), body);
      await route.fulfill({json:data});
    });
    await page.goto("http://luna.local/home?view=traffic");
    const chart = page.getByRole("img", {name:"Combined traffic chart",exact:true});
    await chart.waitFor();
    const start = Date.now();
    for (const elapsed of [5000,35000,70000]) {
      const remaining = start + elapsed - Date.now();
      if (remaining > 0) await page.waitForTimeout(remaining);
      const rendered = await chart.evaluate(svg => ({
        end: Number(svg.dataset.windowEnd),
        incoming: svg.querySelector('path[stroke="rgb(52, 211, 153)"]')?.getAttribute("d"),
      }));
      const window = buildTrafficWindow(latestRaw,60,rendered.end).samples;
      const peak = Math.max(...window.flatMap(sample=>[sample.in_rate,sample.out_rate,sample.drop_rate])) * 1.15;
      assert.equal(rendered.incoming,trafficLinePath(window,"in_rate",560,132,peak));
      assert.equal(window.filter(sample=>sample.observed).length,60);
      console.log(`PASS ${Math.round(elapsed/1000)}s: complete 60-second chart matches directional source records; ${snapshots} refreshes`);
    }
    assert(snapshots >= 30);
    assert.deepEqual(errors,[]);
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
