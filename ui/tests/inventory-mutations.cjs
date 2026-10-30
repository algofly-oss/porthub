// Mutation safety against a disposable real API/Mongo fixture only.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {launchBrowser,navigateWorkspace}=require('./browser.cjs');
(async()=>{
 const f=JSON.parse(fs.readFileSync(process.env.INVENTORY_FIXTURE || '/tmp/porthub-inventory-fixture/fixture.json','utf8'));
 assert(f.db.startsWith('porthub_inventory_browser_'),'This test requires a disposable inventory fixture');
 const origin=process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3114',browser=await launchBrowser();
 try{for(const width of (process.env.REVIEW_WIDTHS || '1440,402').split(',').map(Number)){
  const context=await browser.newContext({viewport:{width,height:1000}});
  await context.addCookies([{name:'porthub_session',value:f.cookie,url:origin}]);
  async function get(path){const r=await context.request.get(origin+path);assert.equal(r.status(),200);return r.json();}
  const before=await get('/api/connections/list');
  const all=Array.isArray(before.data) ? before.data : before;
  const ports=all.filter(c=>c.machine_id===f.machine),target=ports.find(c=>c.internal_port===8010);
  assert.equal(ports.length,152);
  const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto(`${origin}/home?view=machines`);
  await page.getByRole('button',{name:'Configure A large inventory target',exact:true}).click();
  const dialog=page.getByRole('dialog');await dialog.getByRole('button',{name:'Ports',exact:true}).click();
  const table=dialog.getByRole('table',{name:'Forwarded ports',exact:true});
  await table.locator('tbody tr').first().waitFor();assert.equal(await table.locator('tbody tr').count(),5);
  await dialog.getByRole('button',{name:'3',exact:true}).click();
  await table.getByRole('button',{name:`Edit forwarding rule ${target.service_name}`,exact:true}).click();
  const renamed=`service-010 checked ${width}`;
  await dialog.getByLabel('Service name',{exact:true}).fill(renamed);
  await dialog.getByRole('button',{name:'Save Changes',exact:true}).click();
  await dialog.getByText('All changes saved',{exact:true}).waitFor();
  const after=await get('/api/connections/list');const saved=Array.isArray(after.data) ? after.data : after;
  assert.equal(saved.length,all.length,'Partial editor must preserve unloaded inventory');
  const changed=saved.find(c=>c._id===target._id);assert.equal(changed.service_name,renamed);
  const comparable=row=>{const copy={...row};delete copy.updated_at;return copy;};
  const byId=new Map(saved.map(row=>[row._id,row]));
  for(const original of all){const expected={...original};if(original._id===target._id)expected.service_name=renamed;assert.deepEqual(comparable(byId.get(original._id)),comparable(expected),'Saving one visible port must preserve every other field and unloaded port');}
  await dialog.getByRole('button',{name:'Close',exact:true}).click();
  await navigateWorkspace(page,'Public Web Proxies');
  await page.locator('[aria-label="Edit proxy proxy-000.example.invalid"]:visible').click();
  await dialog.getByRole('button',{name:'Bindings',exact:true}).click();
  const bindings=dialog.getByRole('list',{name:'Proxy bindings',exact:true});
  assert.equal(await bindings.getByRole('listitem').count(),128,'Editor must load all bindings beyond list preview');
  await dialog.getByLabel('Binding 1 label',{exact:true}).fill(`Verified target ${width}`);
  await dialog.getByRole('button',{name:'Save Proxy',exact:true}).click();await dialog.waitFor({state:'hidden'});
  const proxy=(await get(`/api/inventory/proxies?ids=${f.proxy}&detail=true&page_size=1`)).data[0];
  assert.equal(proxy.bindings.length,128);assert.equal(proxy.bindings[0].label,`Verified target ${width}`);assert.equal(proxy.bindings[127].target_url,'https://target-127.example.invalid/service/0');
  assert.deepEqual(errors,[]);await context.close();
  console.log(`PASS real mutations ${width}: all 152 ports preserved from page-three edit; all 128 proxy bindings retained`);
 }}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
