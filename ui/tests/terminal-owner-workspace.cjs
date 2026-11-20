const assert = require("node:assert/strict");
const { launchBrowser } = require("./browser.cjs");

async function exercise() {
  const origin = process.env.REVIEW_ORIGIN;
  const machine = process.env.PORTHUB_TEST_TERMINAL_MACHINE;
  const session = process.env.PORTHUB_TEST_TERMINAL_SESSION;
  const browser = await launchBrowser();
  try {
    async function login(cookie) {
      const context = await browser.newContext({viewport:{width:1440,height:900}});
      const [name, value] = cookie.split("=");
      await context.addCookies([{name, value, url:origin, httpOnly:true, sameSite:"Lax"}]);
      return context;
    }
    const first = await login(process.env.PORTHUB_TEST_TERMINAL_COOKIE);
    const second = await login(process.env.SECOND_COOKIE);
    const foreign = await login(process.env.FOREIGN_COOKIE);
    const path = `/api/machines/${machine}/terminal-sessions`;
    const dashboard = `${origin}/home?view=machines&machine=${machine}&machineTab=shells`;
    const denied = await foreign.request.post(origin+path,{headers:{Origin:origin},data:{request_id:"3".repeat(32)}});
    assert.equal(denied.status(),404);
    const wrongOrigin = await first.request.post(origin+path,{headers:{Origin:"https://foreign.example"},data:{request_id:"4".repeat(32)}});
    assert.equal(wrongOrigin.status(),403);
    const page = await first.newPage();
    const initial = await (await first.request.get(origin+path)).json();
    assert.equal(initial.can_open,true,"A fresh locally authorized workspace must be available");
    page.on("pageerror", error => console.error("dashboard page error",error.message));
    await page.goto(dashboard);
    const open = page.getByRole("button",{name:"New shell",exact:true});
    try { await open.click({timeout:18000}); }
    catch (error) {
      const section=page.getByRole("region",{name:"Shell sessions"});
      console.error("Dashboard shell section",await section.count() ? await section.innerText() : "absent");
      throw error;
    }
    const shell = p => p.locator(".xterm-helper-textarea");
    async function output(p,text) {
      await p.waitForFunction(text=>document.querySelector(".xterm-rows")?.textContent.includes(text),text,{timeout:15000});
    }
    await output(page,"porthub-test$");
    const concurrent = await second.newPage();
    await concurrent.goto(dashboard);
    await concurrent.getByRole("button",{name:"amberotter",exact:true}).click();
    await output(concurrent,"porthub-test$");
    await shell(page).focus();
    await page.keyboard.type("VALUE=shared");
    await output(concurrent,"VALUE=shared");
    await page.keyboard.press("Enter");
    // A second account can only participate after the owner issues an invitation.
    const issuePath = origin+path+"/"+session+"/guest-links";
    assert.equal((await foreign.request.post(issuePath,{headers:{Origin:origin},data:{}})).status(),404);
    await page.getByText("Invite guests",{exact:true}).click();
    await page.getByRole("button",{name:"Create guest links"}).click();
    const readLink = await page.getByLabel("Read-only link").inputValue();
    const writeLink = await page.getByLabel("Interactive link").inputValue();
    const readGuest = await foreign.newPage();
    await readGuest.goto(readLink);
    await readGuest.getByRole("button",{name:"Connect",exact:true}).click();
    await output(readGuest,"porthub-test$");
    assert.ok(await readGuest.getByRole("status").filter({hasText:"Read-only"}).count());
    await shell(readGuest).focus();
    await readGuest.keyboard.type("unauthorized_text");
    await readGuest.keyboard.press("Enter");
    const writeGuest = await foreign.newPage();
    await writeGuest.goto(writeLink);
    await writeGuest.getByRole("button",{name:"Connect",exact:true}).click();
    await output(writeGuest,"porthub-test$");
    await shell(writeGuest).focus();
    await writeGuest.keyboard.type("GUEST=explicit");
    await output(page,"GUEST=explicit");
    assert.equal((await page.locator(".xterm-rows").innerText()).includes("unauthorized_text"), false);
    await writeGuest.keyboard.press("Enter");
    await writeGuest.close();
    await readGuest.close();
    const tabPromise=first.waitForEvent("page");
    await page.getByRole("link",{name:"Open in new tab"}).click();
    const tab=await tabPromise;
    assert.equal(new URL(tab.url()).hash,"");
    await output(tab,"porthub-test$");
    await shell(tab).focus();
    await tab.keyboard.type('echo DASHBOARD-"$VALUE"');
    await tab.keyboard.press("Enter");
    await output(concurrent,"DASHBOARD-shared");
    await tab.reload();
    await output(tab,"DASHBOARD-shared");
    const extra = await first.request.post(origin+path,{headers:{Origin:origin},data:{request_id:"5".repeat(32)}});
    assert.equal(extra.status(),409);
    const response = await first.request.post(origin+"/api/terminal/info",{data:{token:process.env.PORTHUB_TEST_TERMINAL_WRITE}});
    assert.equal(response.ok(),false);
    const sessions = await (await second.request.get(origin+path)).json();
    assert.ok(sessions.sessions.some(row=>row.id===session && row.dashboard));
    await tab.getByRole("button",{name:"Block new joins",exact:true}).click();
    await tab.getByRole("button",{name:"Block invitation URLs",exact:true}).click();
    await tab.getByText("New invitation joins blocked",{exact:true}).waitFor();
    const stale = await foreign.request.post(origin+"/api/terminal/info",{data:{token:new URL(writeLink).hash.slice(1)}});
    assert.equal(stale.ok(),false);
    await shell(tab).focus();
    await tab.keyboard.press("Control+d");
    try { await tab.getByRole("button",{name:"Reconnect",exact:true}).waitFor({timeout:15000}); }
    catch (error) {
      console.error("After shell exit",await tab.getByRole("status").allTextContents(),
        (await first.request.get(origin+path+"/"+session)).status());
      throw error;
    }
    console.log("PASS dashboard workspace claim, two authorized browser logins, foreign-account and Origin denial, shared pre-Enter keystrokes, dedicated-tab reattach and shell exit");
  } finally { await browser.close(); }
}
exercise().catch(error=>{console.error(error);process.exitCode=1;});
