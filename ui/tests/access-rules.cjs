const assert = require("node:assert/strict");
const {launchBrowser, navigateWorkspace, seedEmptyPolicies} = require("./browser.cjs");

(async () => {
  const browser = await launchBrowser();
  try {
    for (const theme of ["dark", "light"]) for (const width of [1512, 402, 320]) {
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
      await pick("Source entities","Group · Development");
      await pick("Destination entities","Group · Production");
      await editor.getByLabel("Rule ports",{exact:true}).fill("22");
      await page.screenshot({path:`/tmp/porthub-access-editor-${theme}-${width}.png`});
      await editor.getByRole("button",{name:"Save Policy",exact:true}).click();
      await editor.waitFor({state:"hidden"});
      await page.getByRole("button",{name:"Edit policy Developer Access",exact:true}).waitFor();
      assert.equal(await page.getByRole("button",{name:"Test Access",exact:true}).count(),0);
      await page.getByRole("button",{name:"Edit rule SSH to production",exact:true}).click();
      editor=page.getByRole("dialog",{name:"Edit Policy",exact:true});
      await editor.getByLabel("Allow both directions",{exact:true}).check({force:true});
      await editor.getByRole("button",{name:"Save Policy",exact:true}).click();
      await editor.waitFor({state:"hidden"});
      await page.getByRole("button",{name:"Flow",exact:true}).click();
      await page.getByText("Both sides can initiate · click to inspect",{exact:true}).waitFor();
      await page.waitForTimeout(200);
      await page.screenshot({path:`/tmp/porthub-access-map-${theme}-${width}.png`});
      await page.getByRole("button",{name:"Edit policy Developer Access",exact:true}).click();
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
      await members.getByLabel("Tag Demo Workspace",{exact:true}).click();
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
      await context.close();console.log(`PASS access controls ${theme} ${width}: empty policies, policy editing, flow view, group tags, invites, persistence, safe navigation`);
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
