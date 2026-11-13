const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{spawn,execFile}=require('node:child_process'),{promisify}=require('node:util');
const execute=promisify(execFile);
const base=process.env.PORTHUB_TEST_UI_URL;
const cookie=process.env.PORTHUB_TEST_BOARD_COOKIE?.split('=')[1];
assert(base&&cookie,'Isolated server and test session are required');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome',args:['--no-sandbox']});
 const errors=[],external=[];
 let transferProcess=null,transferFolder=null;
 const context=async(owner=false,width=1440)=>{
  const c=await browser.newContext({viewport:{width,height:950},serviceWorkers:'block'});
  await c.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
  if(owner)await c.addCookies([{name:'porthub_session',value:cookie,url:base}]);
  c.on('page',page=>{page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(base))external.push(r.url());});});
  return c;
 };
 try{
  const owner=await context(true),guest=await context(),viewer=await context(false,390);
  const page=await owner.newPage();
  await page.goto(base+'/home?view=boards');
  await page.getByRole('button',{name:'New board',exact:true}).click();
  await page.getByLabel('Board name',{exact:true}).fill('Sprint planning');
  await page.getByRole('button',{name:'Create board',exact:true}).click();
  await page.waitForURL('**/board?id=*');
  await page.locator('.excalidraw canvas').first().waitFor();
  assert((await page.locator('main > header').boundingBox()).height>=56,'Board header retains room for touch controls');
  await page.getByRole('button',{name:'Board menu',exact:true}).waitFor();
  const id=new URL(page.url()).searchParams.get('id');
  const scene=async()=>{const r=await owner.request.get(base+'/api/boards/'+id);assert(r.ok());return r.json();};
  const draw=async(p,key,x,y)=>{
   await p.locator('.excalidraw').click({position:{x:500,y:400}});
   await p.keyboard.press(key);await p.mouse.move(x,y);await p.mouse.down();await p.mouse.move(x+140,y+90,{steps:8});await p.mouse.up();
  };
  await draw(page,'r',420,300);
  await page.keyboard.press('t');await page.mouse.click(450,540);await page.keyboard.type('PortHub design notes');await page.keyboard.press('Escape');
  await page.waitForFunction(()=>document.querySelector('[role=status]')?.textContent.includes('All changes saved'));
  await new Promise(r=>setTimeout(r,300));
  assert((await scene()).elements.filter(e=>!e.isDeleted).length>=1,'Drawn rectangle is persisted');
  await page.getByRole('button',{name:'Share',exact:true}).click();
  await page.getByLabel('Enable sharing links').check();
  const edit=await page.locator('#board-edit-link').inputValue(),view=await page.locator('#board-view-link').inputValue();
  await page.evaluate(()=>{Object.defineProperty(navigator,'clipboard',{configurable:true,value:undefined});const original=document.execCommand.bind(document);document.execCommand=(command,...args)=>{if(command==='copy'){window.boardCopied={value:document.activeElement.value,inDialog:!!document.activeElement.closest('[role=dialog]')};return true;}return original(command,...args);};});
  await page.getByRole('button',{name:'Copy link',exact:true}).first().click();assert.deepEqual(await page.evaluate(()=>window.boardCopied),{value:edit,inDialog:true},'Clipboard fallback works inside the sharing dialog on local HTTP gateways');
  await page.getByRole('button',{name:'Close dialog'}).click();
  const g=await guest.newPage(),v=await viewer.newPage();
  g.on('response',async r=>{if(r.url().includes('/api/boards/')&&r.status()>=400)console.error('Guest API',r.status(),await r.text());});
  await Promise.all([g.goto(edit),v.goto(view)]);
  await Promise.all([g.locator('.excalidraw canvas').first().waitFor(),v.locator('.excalidraw canvas').first().waitFor()]);
  assert(new URL(g.url()).pathname==='/board','Guest does not get redirected to sign-in');
  await v.getByRole('status').filter({hasText:'View only'}).waitFor();
  const countBeforeGuest=(await scene()).elements.filter(e=>!e.isDeleted).length;
  const canvasBefore=await page.locator('.excalidraw canvas').first().evaluate(c=>c.toDataURL());
  await draw(g,'o',720,400);
  let guestSaved=false;for(let i=0;i<100;i++){if((await scene()).elements.filter(e=>!e.isDeleted).length>countBeforeGuest){guestSaved=true;break;}await page.waitForTimeout(100);}
  assert(guestSaved,'Guest drawing is saved: '+await g.getByRole('status').allTextContents()+' scene='+JSON.stringify(await scene()));
  await page.waitForFunction(before=>document.querySelector('.excalidraw canvas').toDataURL()!==before,canvasBefore);
  const revision=(await scene()).revision;
  await page.reload();await page.locator('.excalidraw canvas').first().waitFor();
  assert((await scene()).revision===revision,'Reload does not replace the stored document');
  // Native image drag/drop must upload private board assets before saving its element.
  await page.evaluate(()=>Object.defineProperty(window.crypto,'subtle',{configurable:true,value:undefined}));
  await page.locator('.excalidraw').evaluate(root=>{
   const canvas=document.createElement('canvas');canvas.width=48;canvas.height=32;const x=canvas.getContext('2d');x.fillStyle='#ef4444';x.fillRect(0,0,48,32);
   const bytes=Uint8Array.from(atob(canvas.toDataURL().split(',')[1]),c=>c.charCodeAt(0));
   const dt=new DataTransfer();dt.items.add(new File([bytes],'board-image.png',{type:'image/png'}));
   root.dispatchEvent(new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:dt,clientX:600,clientY:550}));
  });
  await page.waitForTimeout(1200);
  const withImage=await scene();const image=withImage.elements.find(e=>e.type==='image'&&!e.isDeleted);
  assert(image,'Dropped image is saved');
  const share=new URL(edit).hash.slice('#share='.length);
  const asset=await guest.request.get(`${base}/api/boards/${id}/assets/${image.fileId}`,{headers:{'x-board-share':share}});
  assert(asset.ok()&&(await asset.json()).dataURL.startsWith('data:image/png;base64,'));
  const anonymous=await viewer.request.get(`${base}/api/boards/${id}/assets/${image.fileId}`);assert(!anonymous.ok(),'Image does not have a public screenshot URL');
  await page.locator('.excalidraw').evaluate(root=>{const dt=new DataTransfer();dt.items.add(new File(['<svg xmlns="http://www.w3.org/2000/svg" width="48" height="32"><rect width="48" height="32" fill="blue"/></svg>'],'diagram.svg',{type:'image/svg+xml'}));root.dispatchEvent(new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:dt,clientX:850,clientY:550}));});
  let svgSaved=false;for(let i=0;i<50;i++){if((await scene()).elements.filter(e=>e.type==='image'&&!e.isDeleted).length>=2){svgSaved=true;break;}await page.waitForTimeout(100);}assert(svgSaved,'SVG images are rasterized and saved as safe private PNG assets');
  await page.getByRole('button',{name:'Share',exact:true}).click();
  await page.getByRole('button',{name:'Regenerate both links',exact:true}).click();
  await g.locator('main [role=alert]').waitFor();await v.locator('main [role=alert]').waitFor();
  await page.getByRole('button',{name:'Close dialog'}).click();
  await page.getByRole('button',{name:'Back to boards',exact:true}).click();
  await page.getByRole('link',{name:'Sprint planning',exact:true}).waitFor();
  await page.getByRole('button',{name:'Rename Sprint planning'}).click();await page.getByLabel('Board name',{exact:true}).fill('Design notes');await page.getByRole('button',{name:'Save name',exact:true}).click();
  await page.getByRole('link',{name:'Design notes',exact:true}).waitFor();
  await page.getByRole('button',{name:'Delete Design notes'}).click();await page.getByRole('button',{name:'Delete board',exact:true}).click();
  await page.getByText('Create a board, then share a link to draw together.',{exact:true}).waitFor();
  await page.goto(base+'/home?view=transfers');await page.getByRole('heading',{name:'Transfers',exact:true}).waitFor();
  await page.getByRole('button',{name:'Copy send with curl command'}).waitFor();
  transferFolder=await fs.mkdtemp(path.join(os.tmpdir(),'porthub-recipe-'));
  const source=Buffer.alloc(9*1024*1024+17);for(let i=0;i<source.length;i++)source[i]=(i*37)%251;
  const sourceFolder=path.join(transferFolder,"sender's files");await fs.mkdir(sourceFolder);
  const file=path.join(sourceFolder,"ENV-1.03.xlsx"),output=path.join(transferFolder,"download file's.bin");await fs.writeFile(file,source);
  await page.getByLabel('File path',{exact:true}).fill(file);
  await page.evaluate(()=>{window.copiedCommands=[];Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>window.copiedCommands.push(text)}});});
  await page.getByRole('button',{name:'Copy send with curl command'}).click();
  const senderCommand=await page.evaluate(()=>window.copiedCommands.at(-1));
  transferProcess=spawn('bash',['-c',senderCommand],{detached:true,stdio:['ignore','pipe','pipe']});
  const transferUrl=await new Promise((resolve,reject)=>{
    let text='';const timeout=setTimeout(()=>reject(new Error('Sender did not print a download URL')),10000);
    transferProcess.stdout.on('data',chunk=>{text+=chunk;const match=text.match(/Download: (https?:\/\/[^\s]+)/);if(match){clearTimeout(timeout);resolve(match[1]);}});
    transferProcess.on('error',reject);
  });
  await page.getByRole('tab',{name:'Download a file',exact:true}).click();
  await page.getByLabel('Download URL',{exact:true}).fill(transferUrl);
  for(const tool of ['cURL','Wget','aria2']){
    const folder=path.join(transferFolder,tool);await fs.mkdir(folder);
    await page.getByRole('group',{name:'Download tool',exact:true}).getByRole('button',{name:tool,exact:true}).click();
    await page.getByRole('tabpanel').getByRole('button',{name:/^Copy .* command$/}).click();
    const command=await page.evaluate(()=>window.copiedCommands.at(-1));assert(!command.includes('\n'));
    await execute('bash',['-c',command],{cwd:folder,timeout:30000});
    assert.deepEqual(await fs.readFile(path.join(folder,'ENV-1.03.xlsx')),source,'Original XLSX filename and bytes survive '+tool);
  }
  await page.getByRole('group',{name:'Download tool',exact:true}).getByRole('button',{name:'cURL',exact:true}).click();
  await page.getByLabel('Connections',{exact:true}).selectOption('4');
  await page.getByRole('button',{name:'Copy parallel download with curl command'}).click();
  const autoParallelFolder=path.join(transferFolder,'parallel-auto');await fs.mkdir(autoParallelFolder);
  await execute('bash',['-c',await page.evaluate(()=>window.copiedCommands.at(-1))],{cwd:autoParallelFolder,timeout:30000});
  assert.deepEqual(await fs.readFile(path.join(autoParallelFolder,'ENV-1.03.xlsx')),source,'Parallel helper preserves the original filename');
  await page.getByLabel('Save as',{exact:true}).fill(output);
  await page.getByRole('group',{name:'Download tool',exact:true}).getByRole('button',{name:'aria2',exact:true}).click();
  await page.getByRole('button',{name:'Copy download with aria2 command'}).click();
  await execute('bash',['-c',await page.evaluate(()=>window.copiedCommands.at(-1))],{timeout:30000});
  assert.deepEqual(await fs.readFile(output),source,'Copied aria2 command downloads the exact original file');
  await fs.rm(output);
  await page.getByRole('group',{name:'Download tool',exact:true}).getByRole('button',{name:'cURL',exact:true}).click();
  await page.getByLabel('Connections',{exact:true}).selectOption('4');
  await page.getByRole('button',{name:'Copy parallel download with curl command'}).click();
  const parallel=await page.evaluate(()=>window.copiedCommands.at(-1));
  await execute('bash',['-c',parallel],{timeout:30000});
  assert.deepEqual(await fs.readFile(output),source,'Copied parallel command downloads the exact original file');
  try{process.kill(-transferProcess.pid,'SIGTERM');}catch{}
  await new Promise(resolve=>transferProcess.once('exit',resolve));transferProcess=null;
  let closed=false;for(let i=0;i<30;i++){if((await owner.request.head(transferUrl)).status()===404){closed=true;break;}await new Promise(r=>setTimeout(r,100));}assert(closed,'Stopping copied sender command revokes the link');

  await page.setViewportSize({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Transfer instructions fit mobile width');
  const preview=await viewer.newPage();await preview.goto(base+'/home?demo=1&view=transfers');await preview.getByText('to view transfer commands.',{exact:false}).waitFor();assert((await preview.getByRole('button',{name:/Copy .* command/}).count())===0,'Public demo does not expose the signed-in transfer recipes');
  assert.deepEqual(errors,[],'No browser errors');
  assert.deepEqual(external,[],'Editor assets and fonts come only from PortHub');
  for(const script of ['hosted-images.cjs','image-rooms.cjs','image-bulk-delete.cjs','transfers.cjs']){const result=await execute(process.execPath,[path.join(__dirname,script)],{env:process.env,timeout:90000});console.log(result.stdout);}
  console.log('PASS: real saved boards, anonymous editing/view-only access, live drawing, private images, reload durability, share rotation, rename/delete and mobile transfer instructions.');
 }catch(error){console.error(error);throw error;}finally{if(transferProcess)try{process.kill(-transferProcess.pid,'SIGTERM');}catch{}if(transferFolder)await fs.rm(transferFolder,{recursive:true,force:true});await browser.close();}
})().catch(()=>process.exit(1));
