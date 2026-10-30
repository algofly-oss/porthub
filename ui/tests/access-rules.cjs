const assert = require("node:assert/strict");
const {launchBrowser, navigateWorkspace, seedEmptyPolicies} = require("./browser.cjs");

(async () => {
  const browser = await launchBrowser();
  try {
    for (const theme of (process.env.REVIEW_THEMES || "dark,light").split(",")) for (const width of (process.env.REVIEW_WIDTHS || "1512,402,320").split(",").map(Number)) {
      const context = await browser.newContext({viewport:{width,height:982}});
      await seedEmptyPolicies(context);
      await context.addInitScript(theme=>localStorage.setItem("mantine-color-scheme",JSON.stringify(theme)),theme);
      const page=await context.newPage(),errors=[];
      page.on("pageerror",error=>errors.push(error.message));
      await page.goto(`${process.env.REVIEW_ORIGIN||"http://luna.local:8345"}/home?demo=1&view=access`);
      await page.getByRole("heading",{name:"Access Rules",exact:true}).waitFor();
      await page.getByText("Choose who can connect",{exact:true}).waitFor();
      const initial=await page.evaluate(()=>JSON.parse(sessionStorage.getItem("porthub-demo-v1")));
      assert.deepEqual(initial.access.books,[],"No implicit allow-all policy");
      await page.getByRole("button",{name:"Policy",exact:true}).click();
      let editor=page.getByRole("dialog",{name:"New Policy",exact:true});
      await editor.getByLabel("Policy name",{exact:true}).fill("Developer Access");
      await editor.getByLabel("Rule name",{exact:true}).fill("SSH to production");
      async function pick(label,option,within=editor){
        const input=within.getByLabel(label,{exact:true});await input.click();await input.fill(option);
        await page.getByRole("option",{name:option,exact:true}).click();
        if(await page.getByRole("listbox").isVisible().catch(()=>false))await page.keyboard.press("Escape");
      }
      await pick("Policy group","Development");
      await pick("Source entities","Group · Development");
      await pick("Destination entities","Group · Production");
      await editor.getByLabel("Rule ports",{exact:true}).fill("22");
      await page.screenshot({path:`/tmp/porthub-access-editor-${theme}-${width}.png`});
      await editor.getByRole("button",{name:"Save Policy",exact:true}).click();
      await editor.waitFor({state:"hidden"});
      await page.locator('[aria-label="Edit policy Developer Access"]:visible').waitFor();
      assert.equal(await page.getByRole("button",{name:"Test Access",exact:true}).count(),0);
      assert.equal(await page.getByRole("button",{name:"Flow",exact:true}).count(),0,"single policy view only");
      // Click the policy name: the row centre can be the pause switch on phones.
      await page.locator('[aria-label="Edit policy Developer Access"]:visible').getByText("Developer Access",{exact:true}).click();
      editor=page.getByRole("dialog",{name:"Edit Policy",exact:true});
      await editor.getByLabel("Allow both directions",{exact:true}).check({force:true});
      await editor.getByRole("button",{name:"Save Policy",exact:true}).click();
      await editor.waitFor({state:"hidden"});
      await page.locator('[aria-label="Edit policy Developer Access"]:visible').getByLabel("both directions").waitFor();
      const toggle=page.getByRole("switch",{name:"Pause policy Developer Access",exact:true}).locator("visible=true");
      await toggle.click();
      await page.getByRole("switch",{name:"Resume policy Developer Access",exact:true}).locator("visible=true").waitFor();
      await page.getByRole("switch",{name:"Resume policy Developer Access",exact:true}).locator("visible=true").click();
      await page.getByRole("switch",{name:"Pause policy Developer Access",exact:true}).locator("visible=true").waitFor();
      const policyRow=page.locator('[aria-label="Edit policy Developer Access"]:visible');
      const before=await policyRow.evaluate(e=>getComputedStyle(e).backgroundColor);
      await policyRow.hover();await page.waitForTimeout(250);
      assert.notEqual(await policyRow.evaluate(e=>getComputedStyle(e).backgroundColor),before,"policy row hover");
      await page.screenshot({path:`/tmp/porthub-access-list-${theme}-${width}.png`});
      await policyRow.getByText("Developer Access",{exact:true}).click();
      await editor.getByLabel("Policy name",{exact:true}).fill("Unsaved change");
      await editor.getByRole("button",{name:"Cancel",exact:true}).click();
      const guard=page.getByRole("dialog",{name:"Discard unsaved changes?",exact:true});
      await guard.waitFor();await guard.getByRole("button",{name:"Discard Changes",exact:true}).click();
      await editor.waitFor({state:"hidden"});
      await page.getByRole("button",{name:"Groups",exact:true}).click();
      await page.getByLabel("New access group",{exact:true}).fill("Engineering");
      await page.getByRole("button",{name:"Group",exact:true}).click();
      await page.getByRole("button",{name:"Manage members of Engineering",exact:true}).click();
      const members=page.getByRole("dialog",{name:"Engineering · Members",exact:true});
      await members.getByRole("button",{name:"People",exact:true}).click();
      await members.getByLabel("Include Demo Workspace",{exact:true}).click();
      await members.getByRole("button",{name:"Save Members",exact:true}).click();
      await members.waitFor({state:"hidden"});
      await page.getByText(/0 machines · 1 person · 0 policies/).waitFor();
      await page.getByRole("button",{name:"People",exact:true}).click();
      await page.getByRole("button",{name:"Invite Person",exact:true}).click();
      const invitation=page.getByRole("dialog",{name:"Invite to Workspace",exact:true});
      await invitation.getByLabel("Invite email",{exact:true}).fill("alice@example.test");
      await invitation.getByRole("button",{name:"Create Invitation",exact:true}).click();
      assert((await invitation.getByLabel("Invitation link",{exact:true}).inputValue()).includes("/join#"),"Token stays in URL fragment, not HTTP logs");
      await invitation.getByRole("button",{name:"Done",exact:true}).click();
      await page.getByText("alice@example.test",{exact:true}).waitFor();
      await page.getByRole("button",{name:"Network",exact:true}).click();
      await page.getByLabel("Private IPv4 range",{exact:true}).fill("10.204.0.0/24");
      await page.getByRole("button",{name:"Save Preferences",exact:true}).click();
      await page.reload();await page.getByRole("button",{name:"Network",exact:true}).click();
      assert.equal(await page.getByLabel("Private IPv4 range",{exact:true}).inputValue(),"10.204.0.0/24");
      await page.screenshot({path:`/tmp/porthub-access-network-${theme}-${width}.png`});
      await navigateWorkspace(page,"Public Web Proxies");
      await page.getByRole("heading",{name:"Public Web Proxies",exact:true}).waitFor();
      await navigateWorkspace(page,"Settings");
      await page.getByRole("heading",{name:"Settings",exact:true}).waitFor();
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
      assert.deepEqual(errors,[]);
      await context.close();console.log(`PASS access controls ${theme} ${width}: empty policies, policy editing, single list with hover and pause, group tags, invites, persistence, safe navigation`);
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
