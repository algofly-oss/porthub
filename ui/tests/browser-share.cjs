const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {execFile}=require('node:child_process'),{promisify}=require('node:util');
const execute=promisify(execFile);
const base=process.env.PORTHUB_TEST_UI_URL,cookie=process.env.PORTHUB_TEST_BOARD_COOKIE?.split('=')[1];
assert(base&&cookie,'Isolated portal and test session required');
async function until(predicate,message){for(let i=0;i<100;i++){if(await predicate())return;await new Promise(resolve=>setTimeout(resolve,100));}throw Error(message);}
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome'});
 const folder=await fs.mkdtemp(path.join(os.tmpdir(),'porthub-browser-source-'));
 try{
  const context=await browser.newContext({viewport:{width:1440,height:950}});
  await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.lastCopied=text;}}});});
  await context.addCookies([{name:'porthub_session',value:cookie,url:base}]);
  const page=await context.newPage(),errors=[],leaks=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',async request=>{if(new URL(request.url()).pathname.startsWith('/api/transfers')&&['POST','PUT'].includes(request.method())){try{const headers=await request.allHeaders();if(headers.cookie||headers.authorization)leaks.push(request.url());}catch{ /* a page-close cleanup can cancel header inspection */ }}});
  await page.goto(base+'/home?view=transfers');
  await page.getByRole('tab',{name:'From browser',exact:true}).click();
  await page.getByRole('complementary',{name:'Browser sharing guide'}).waitFor();
  const filename="Résumé's ENV.xlsx",source=crypto.randomBytes(17*1024*1024+37),file=path.join(folder,filename);await fs.writeFile(file,source);
  await page.getByLabel('Choose files to share',{exact:true}).setInputFiles(file);
  const urlInput=page.getByLabel(`Public URL for ${filename}`,{exact:true});
  await until(async()=> (await urlInput.inputValue()).startsWith(base+'/api/transfers/'),'Browser file URL was not generated');
  const url=await urlInput.inputValue();
  assert.equal(await page.getByRole('complementary',{name:'Browser sharing guide'}).count(),0,'Active file links replace the getting-started guide');
  await page.getByRole('button',{name:`Copy URL for ${filename}`,exact:true}).click();assert.equal(await page.evaluate(()=>window.lastCopied),url);
  const article=page.getByRole('article',{name:`Share ${filename}`,exact:true});
  const commands={};
  for(const tool of ['cURL','Wget']){
   await article.getByRole('group').getByRole('button',{name:tool,exact:true}).click();
   await article.getByRole('button',{name:/^Copy browser download with .* command$/}).click();commands[tool]=await page.evaluate(()=>window.lastCopied);assert(!commands[tool].includes('\n'));
  }
  await Promise.all(Object.entries(commands).map(async([tool,command])=>{const out=path.join(folder,tool);await fs.mkdir(out);await execute('bash',['-c',command],{cwd:out,timeout:60000});assert.deepEqual(await fs.readFile(path.join(out,filename)),source,tool+' downloads the exact selected file with its original Unicode name');}));
  const chunk=Math.ceil(source.length/4);
  const parts=await Promise.all(Array.from({length:4},async(_,i)=>{const start=i*chunk,end=Math.min(source.length-1,start+chunk-1);return (await execute('curl',['-fsS','--range',`${start}-${end}`,url],{encoding:'buffer',maxBuffer:8*1024*1024,timeout:60000})).stdout;}));
  assert.deepEqual(Buffer.concat(parts),source,'Four parallel recipients request browser file slices correctly');
  // A full page reload ends the source; ordinary SPA navigation is checked below.
  await page.goto(base+'/home?view=boards');
  // Full navigation unloads the page; this intentionally ends the source.
  await until(async()=>{const r=await context.request.head(url);return r.status()===404;},'Leaving the source page must revoke its URL');
  await page.goto(base+'/home?view=transfers');
  // Drop on the terminal panel directly: no preliminary browser-tab click.
  await page.getByRole('tabpanel').evaluate(node=>{const transfer=new DataTransfer();transfer.items.add(new File(['PortHub drag and drop'],'dropped.txt',{type:'text/plain'}));node.dispatchEvent(new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:transfer}));});
  const dropped=page.getByLabel('Public URL for dropped.txt',{exact:true});await until(async()=> (await dropped.inputValue()).startsWith(base),'Drop did not switch to browser sharing');
  const dropUrl=await dropped.inputValue();
  // Next.js client navigation keeps the same window and its publisher alive.
  await page.getByRole('button',{name:'Boards',exact:true}).click();
  assert.equal((await execute('curl',['-fsS',dropUrl],{timeout:30000})).stdout,'PortHub drag and drop');
  await page.getByRole('button',{name:'Transfers',exact:true}).click();
  await page.getByRole('tab',{name:'From browser',exact:true}).click();
  await page.getByRole('button',{name:'Stop sharing dropped.txt',exact:true}).click();
  await until(async()=> (await context.request.head(dropUrl)).status()===404,'Stop must invalidate the browser URL');
  assert.deepEqual(leaks,[],'No portal account credentials go to the anonymous relay');assert.deepEqual(errors,[]);
  console.log('PASS: browser File streaming, original Unicode names, copied cURL/Wget commands, parallel connections, drop from terminal view, SPA navigation and stop/page-close cleanup.');
 }finally{await browser.close();await fs.rm(folder,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exit(1);});
