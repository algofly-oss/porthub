const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");
(async()=>{
 const {makeDemoData}=await import("../src/shared/demo/data.mjs");
 const browser=await launchBrowser();
 try { for(const width of [1440,402]) {
  const state=makeDemoData();
  const disabled=state.machines.find(machine=>machine.enabled===false);
  disabled.name="Disabled inventory regression";
  const context=await browser.newContext({viewport:{width,height:1000}});
  await context.addInitScript(state=>sessionStorage.setItem("porthub-demo-v1",JSON.stringify(state)),state);
  const page=await context.newPage(),errors=[];
  page.on("pageerror",error=>errors.push(error.message));
  await page.goto(`${process.env.REVIEW_ORIGIN||"http://127.0.0.1:3108"}/home?demo=1&view=machines`);
  await page.getByLabel("Search machines",{exact:true}).fill(disabled.name);
  const target=page.getByRole("button",{name:`Configure ${disabled.name}`,exact:true});
  await target.waitFor();
  const statuses=page.getByLabel("Machine status",{exact:true});
  const selectStatus=async label=>{await statuses.click();await page.getByRole("option",{name:label,exact:true}).click();};
  if(width>=768)assert((await statuses.boundingBox()).width<=140,"Machine status dropdown must stay compact");
  await selectStatus("Disabled");
  await target.waitFor();
  for(const status of ["Online","Offline"]) {
   await selectStatus(status);
   await target.waitFor({state:"hidden"});
  }
  await selectStatus("All");
  await target.waitFor();
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),"Machine filters must fit the viewport");
  await target.click();
  await page.getByRole("dialog").waitFor();
  assert.deepEqual(errors,[]);
  await context.close();
  console.log(`PASS ${width}: disabled machine discoverable in All and Disabled; excluded from Online and Offline; configuration accessible`);
 }} finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
