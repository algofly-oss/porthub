// Run against a local UI: PORTHUB_TEST_UI_URL=http://127.0.0.1:4317 node tests/hosted-images.cjs
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const base = process.env.PORTHUB_TEST_UI_URL;
assert(base, "An isolated local UI URL is required");

(async () => {
  const { makeDemoData, handleDemoRequest } = await import("../src/shared/demo/data.mjs");
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || "/usr/bin/google-chrome" });
  try {
    for (const width of [1440, 402]) {
      const context = await browser.newContext({ serviceWorkers: "block", viewport: { width, height: 950 } });
      const page = await context.newPage();
      const png=Buffer.from(await page.evaluate(()=>{const c=document.createElement("canvas");c.width=640;c.height=200;const x=c.getContext("2d");x.fillStyle="#0f172a";x.fillRect(0,0,640,200);x.fillStyle="#ffffff";x.font="28px sans-serif";x.fillText("PortHub image sharing",32,80);x.fillStyle="#93c5fd";x.font="18px sans-serif";x.fillText("Original image preview",32,128);return c.toDataURL("image/png").split(",")[1];}),"base64");
      await page.route("**/i/*.png",route=>route.fulfill({contentType:"image/png",body:png}));

      let images = [], serial = 0, failNext = false;
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      await page.addInitScript(() => {
        // Keep API mocks authoritative on HTTPS production previews too.
        delete Object.getPrototypeOf(navigator).serviceWorker;
        window.copiedLinks = [];
        Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async text => { window.copiedLinks.push(text); } } });
      });
      const state = makeDemoData();
      await page.route("**/socket.io/**", route => route.abort());
      await page.route("**/api/**", async route => {
        const request = route.request(), path = new URL(request.url()).pathname;
        const method = request.method().toLowerCase();
        if (path.startsWith("/api/images/public/")) return route.fulfill({contentType:"image/png",body:png});
        let body;
        if (path === "/api/images") {
          if (method === "get") body = { images };
          else {
            if (failNext) { failNext=false; return route.fulfill({status:400,contentType:"application/json",body:JSON.stringify({detail:"Storage full test"})}); }
            const input = request.postDataJSON(); assert(input.image.length > 0);
            const id = String(++serial).padStart(32,"0");
            const code=["AbC23","Def45","Ghj67"][serial-1];
            body = {id,name:input.name,width:640,height:200,size:png.length,created_at:"2026-11-10T10:00:00",path:`/i/${code}.png`,url:`${base}/i/${code}.png`};
            images.unshift(body);
          }
        } else if (path.startsWith("/api/images/") && method === "delete") {
          images = images.filter(image => !path.endsWith(image.id));
          return route.fulfill({status:204});
        } else {
          try { body = handleDemoRequest(state,method,request.url(),request.postDataJSON() || {}); }
          catch { body = {}; }
        }
        return route.fulfill({contentType:"application/json",body:JSON.stringify(body)});
      });
      await page.goto(`${base}/home?view=images`);
      await page.getByRole("heading",{name:"Hosted images",exact:true}).waitFor();
      await page.getByText("Your images will appear here",{exact:true}).waitFor();
      await page.getByLabel("Choose images").setInputFiles({name:"chosen.png",mimeType:"image/png",buffer:png});
      await page.getByRole("row").filter({hasText:"chosen.png"}).waitFor();
      await page.waitForFunction(() => window.copiedLinks.length === 1);
      await page.getByLabel("Latest public image URL").focus();
      await page.evaluate(data => {
        const transfer = new DataTransfer(); transfer.items.add(new File([new Uint8Array(data)],"pasted.png",{type:"image/png"}));
        document.activeElement.dispatchEvent(new ClipboardEvent("paste",{clipboardData:transfer,bubbles:true}));
      }, [...png]);
      await page.getByRole("row").filter({hasText:"pasted.png"}).waitFor();
      await page.waitForFunction(() => window.copiedLinks.length === 2);
      await page.evaluate(data => {
        const transfer = new DataTransfer(); transfer.items.add(new File([new Uint8Array(data)],"dropped.png",{type:"image/png"}));
        const target = [...document.querySelectorAll(".workspace-page")].find(el => el.textContent.includes("Paste a screenshot"));
        target.dispatchEvent(new DragEvent("drop",{dataTransfer:transfer,bubbles:true,cancelable:true}));
      }, [...png]);
      await page.getByRole("row").filter({hasText:"dropped.png"}).waitFor();
      await page.waitForFunction(() => window.copiedLinks.length === 3);
      await page.getByRole("button",{name:"Preview chosen.png",exact:true}).click();
      const preview=page.getByRole("dialog",{name:"chosen.png",exact:true});
      await preview.waitFor();
      await preview.getByRole("img",{name:"chosen.png",exact:true}).waitFor();
      await preview.getByRole("link",{name:"Open original",exact:true}).waitFor();
      await page.keyboard.press("Escape");
      await preview.waitFor({state:"hidden"});
      await page.waitForTimeout(300);
      if(process.env.PORTHUB_TEST_SCREENSHOT_DIR) await page.screenshot({path:`${process.env.PORTHUB_TEST_SCREENSHOT_DIR}/images-${width}.png`,fullPage:true});
      const last = page.getByLabel("Latest public image URL");
      assert((await last.inputValue()).endsWith("Ghj67.png"));
      const card = page.getByRole("row").filter({hasText:"chosen.png"});
      await card.getByRole("button",{name:"Copy link for chosen.png",exact:true}).click();
      assert((await page.evaluate(() => window.copiedLinks.at(-1))).endsWith("AbC23.png"));
      let nativeDialogs=0;
      page.on("dialog",dialog=>{nativeDialogs++;dialog.dismiss();});
      await card.getByRole("button",{name:"Delete chosen.png",exact:true}).click();
      const confirmation=page.getByRole("dialog",{name:"Delete image",exact:true});
      await confirmation.waitFor();
      await confirmation.getByRole("button",{name:"Cancel",exact:true}).click();
      await confirmation.waitFor({state:"hidden"});
      assert.equal(images.length,3,"Cancel preserves the image");
      await card.getByRole("button",{name:"Delete chosen.png",exact:true}).click();
      await confirmation.getByRole("button",{name:"Delete image",exact:true}).click();
      await card.waitFor({state:"detached"});
      assert.equal(images.length,2);
      failNext = true;
      await page.getByLabel("Choose images").setInputFiles({name:"failed.png",mimeType:"image/png",buffer:png});
      await page.getByText("Storage full test",{exact:true}).waitFor();
      assert.equal(images.length,2);
      await page.getByRole("button",{name:"Desktop shortcut setup",exact:true}).click();
      await page.getByText("porthub image shortcut enable",{exact:true}).waitFor();
      await page.getByText("Off by default. Run in your desktop terminal:",{exact:true}).waitFor();
      await page.keyboard.press("Escape");
      assert.equal(nativeDialogs,0,"Deletion never opens a native browser confirmation");
      // Exercise pagination with more than one page of image metadata.
      const sample=images[0];
      images=Array.from({length:24},(_,index)=>({...sample,id:String(100+index).padStart(32,"0"),name:`page-image-${index+1}.png`}));
      await page.getByRole("button",{name:"Refresh images",exact:true}).click();
      await page.getByRole("row").filter({hasText:"page-image-1.png"}).waitFor();
      assert.equal(await page.getByRole("table",{name:"Hosted images"}).getByRole("row").count(),11);
      const pager=page.locator('footer[aria-label="Images pagination"]');
      const next=pager.getByRole("button",{name:"Next page",exact:true});
      if(width<768) await next.click();
      else await pager.getByRole("button",{name:"2",exact:true}).click();
      await page.getByRole("row").filter({hasText:"page-image-11.png"}).waitFor();
      assert.equal(await page.getByRole("table",{name:"Hosted images"}).getByRole("row").count(),11);
      if (width < 768) {
        await page.getByRole("button",{name:"More navigation"}).click();
        await page.getByRole("button",{name:"Hosted images",exact:true}).waitFor();
      } else await page.getByRole("button",{name:"Hosted images",exact:true}).waitFor();
      assert.deepEqual(errors,[]);
      await context.close();
    }
    console.log("Hosted images: compact table, full-size preview, file upload, paste, drop, automatic copy, deletion, failure and mobile navigation passed.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
