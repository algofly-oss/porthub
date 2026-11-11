// Linux X11 integration: Xvfb, xdotool, xclip, GNOME Terminal, Python 3, Playwright,
// a built agent and an installed registration are required. The real desktop is untouched.
const {chromium}=require('playwright');
const {spawn,execFileSync,spawnSync}=require('node:child_process');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const config=fs.mkdtempSync(path.join(os.tmpdir(),'porthub-repeat-'));
 const env={...process.env,XDG_CONFIG_HOME:config,XDG_CACHE_HOME:path.join(config,'cache'),XDG_DATA_HOME:path.join(config,'data'),DBUS_SESSION_BUS_ADDRESS:'unix:path=/tmp/porthub-isolated-test-no-bus'};delete env.WAYLAND_DISPLAY;delete env.XAUTHORITY;
 const log=fs.openSync(path.join(config,'display.log'),'a');const xvfb=spawn('Xvfb',['-displayfd','1','-screen','0','1280x800x24','-nolisten','tcp'],{stdio:['ignore','pipe',log]});let browser,terminal,grab;
 const binary=process.env.PORTHUB_TEST_AGENT_BIN||path.resolve(__dirname,'../../target/agent-dev/porthub');
 const activeHelper=path.join(config,'active.py'),grabHelper=path.join(config,'grab.py');
 fs.writeFileSync(activeHelper,"import ctypes,sys\nx=ctypes.CDLL('libX11.so.6')\nx.XOpenDisplay.restype=ctypes.c_void_p\nx.XDefaultRootWindow.argtypes=[ctypes.c_void_p];x.XDefaultRootWindow.restype=ctypes.c_ulong\nx.XInternAtom.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int];x.XInternAtom.restype=ctypes.c_ulong\nx.XChangeProperty.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_int]\nx.XCloseDisplay.argtypes=[ctypes.c_void_p]\nd=x.XOpenDisplay(None);assert d\nwindow=ctypes.c_ulong(int(sys.argv[1]))\nsupported=ctypes.c_ulong(x.XInternAtom(d,b'_NET_ACTIVE_WINDOW',0))\nx.XChangeProperty(d,x.XDefaultRootWindow(d),x.XInternAtom(d,b'_NET_SUPPORTED',0),4,32,0,ctypes.byref(supported),1)\nx.XChangeProperty(d,x.XDefaultRootWindow(d),x.XInternAtom(d,b'_NET_ACTIVE_WINDOW',0),33,32,0,ctypes.byref(window),1)\nx.XCloseDisplay(d)\n");
 fs.writeFileSync(grabHelper,"import ctypes,sys,pathlib,time\nx=ctypes.CDLL('libX11.so.6');x.XOpenDisplay.restype=ctypes.c_void_p\nx.XDefaultRootWindow.argtypes=[ctypes.c_void_p];x.XDefaultRootWindow.restype=ctypes.c_ulong\nx.XKeysymToKeycode.argtypes=[ctypes.c_void_p,ctypes.c_ulong];x.XKeysymToKeycode.restype=ctypes.c_ubyte\nx.XSelectInput.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_long]\nx.XGrabKey.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_uint,ctypes.c_ulong,ctypes.c_int,ctypes.c_int,ctypes.c_int]\nx.XSync.argtypes=[ctypes.c_void_p,ctypes.c_int]\nd=x.XOpenDisplay(None);assert d;root=x.XDefaultRootWindow(d)\nx.XSelectInput(d,root,3);x.XGrabKey(d,x.XKeysymToKeycode(d,0x75),5,root,0,1,1);x.XSync(d,0)\npathlib.Path(sys.argv[1]).write_text('ready');time.sleep(120)\n");
 try{
  env.DISPLAY=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Xvfb did not start')),5000);xvfb.once('error',reject);xvfb.stdout.once('data',data=>{clearTimeout(timer);const number=data.toString().trim();assert.match(number,/^\d+$/);resolve(':'+number);});});browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:false,env});const page=await browser.newPage();await page.setContent('<title>PortHub repeat test</title><textarea autofocus></textarea>');await page.locator('textarea').focus();await page.waitForTimeout(1000);
  const id=execFileSync('xdotool',['search','--onlyvisible','--name','PortHub repeat test'],{env,encoding:'utf8'}).trim().split('\n').at(-1);
  execFileSync('python3',[activeHelper,id],{env});execFileSync('xdotool',['windowfocus','--sync',id],{env});
  const registration=JSON.parse(execFileSync(binary,['ls','--json'],{encoding:'utf8'})).find(r=>!r.private&&r.gateway.includes('porthub.algofly.in'));
  assert(registration);
  const origin=new URL(registration.gateway).origin,url=origin+'/i/AbC23.png';
  const copy=text=>execFileSync('xclip',['-selection','clipboard','-in','-target','UTF8_STRING'],{env,input:text,stdio:['pipe','ignore','ignore']});
  const paste=()=>execFileSync(binary,['image','--mode','paste'],{env,encoding:'utf8'}).trim();
  const start=()=>{const child=spawn(binary,['image','--mode','paste'],{env,stdio:['ignore','pipe','pipe']});let out='',err='',ready;const started=new Promise(resolve=>ready=resolve);child.stdout.on('data',data=>{out+=data;ready();});child.stderr.on('data',data=>err+=data);const done=new Promise(resolve=>child.on('close',code=>{ready();resolve({code,out:out.trim(),err});}));done.ready=started;return done;};
  const hold=()=>execFileSync('xdotool',['keydown','Control_L','keydown','Shift_L','keydown','u'],{env});
  const release=()=>execFileSync('xdotool',['keyup','u','keyup','Shift_L','keyup','Control_L'],{env});
  const heldPaste=async()=>{hold();const result=start();await page.waitForTimeout(180);release();const done=await result;assert.equal(done.code,0,done.err);return done.out;};

  const ready=path.join(config,'grab-ready');grab=spawn('python3',[grabHelper,ready],{env,stdio:['ignore',log,log]});for(let i=0;i<30&&!fs.existsSync(ready);i++)await page.waitForTimeout(100);assert(fs.existsSync(ready));
  copy(url);assert.equal(paste(),url);assert.equal(paste(),url);await page.waitForFunction(expected=>document.querySelector('textarea').value===expected,url+url);
  await page.locator('textarea').fill('');assert.equal(await heldPaste(),url);assert.equal(await heldPaste(),url);await page.waitForFunction(expected=>document.querySelector('textarea').value===expected,url+url);
  const parent=path.join(config,'porthub','images');fs.mkdirSync(parent,{recursive:true,mode:0o700});const alternate='https://images.example.invalid/i/Def45.png';
  fs.writeFileSync(path.join(parent,'last-upload.json'),JSON.stringify({registration:registration.id,user:false,url:alternate}),{mode:0o600});
  copy(alternate);assert.equal(paste(),alternate);assert.equal(paste(),alternate);await page.waitForFunction(expected=>document.querySelector('textarea').value===expected,url+url+alternate+alternate);
  copy('unrelated text');const rejected=spawnSync(binary,['image','--mode','paste'],{env,encoding:'utf8'});assert.notEqual(rejected.status,0);assert.equal(await page.locator('textarea').inputValue(),url+url+alternate+alternate);
  const capture=path.join(config,'terminal-input.bin'),script=path.join(config,'capture-input.py');
  fs.writeFileSync(script,`import os,sys,tty
tty.setraw(0)
while True:
 data=os.read(0,4096)
 with open(sys.argv[1],"ab") as stream:stream.write(data)
`);
  terminal=spawn('dbus-run-session',['--','gnome-terminal','--wait','--title=PortHub isolated terminal paste','--','python3',script,capture],{env,stdio:['ignore',log,log]});
  await page.waitForTimeout(1800);
  const terminalId=execFileSync('xdotool',['search','--onlyvisible','--name','^PortHub isolated terminal paste$'],{env,encoding:'utf8'}).trim().split('\n').at(-1);
  execFileSync('python3',[activeHelper,terminalId],{env});execFileSync('xdotool',['windowfocus','--sync',terminalId],{env});
  console.log('Terminal class:',execFileSync('xprop',['-id',terminalId,'WM_CLASS'],{env,encoding:'utf8'}));
  console.log('CLI version:',execFileSync(binary,['version'],{encoding:'utf8'}));
  copy(url);assert.equal(await heldPaste(),url);assert.equal(await heldPaste(),url);
  for(let i=0;i<50 && (!fs.existsSync(capture)||fs.readFileSync(capture,'utf8')!==url+url);i++)await page.waitForTimeout(100);
  assert.equal(fs.readFileSync(capture,'utf8'),url+url,'Real terminal receives two clipboard pastes without any Enter key');
  execFileSync('python3',[activeHelper,id],{env});execFileSync('xdotool',['windowfocus','--sync',id],{env});
  hold();const changed=start();await page.waitForTimeout(100);
  execFileSync('python3',[activeHelper,terminalId],{env});execFileSync('xdotool',['windowfocus','--sync',terminalId],{env});release();
  const result=await changed;assert.notEqual(result.code,0);assert(result.err.includes('Focus changed'));assert.equal(fs.readFileSync(capture,'utf8'),url+url,'Focus change must not paste into the new window');
  execFileSync('python3',[activeHelper,id],{env});execFileSync('xdotool',['windowfocus','--sync',id],{env});
  hold();const clipboardChanged=start();await clipboardChanged.ready;await page.waitForTimeout(100);copy('do not paste me');release();
  const preserved=await clipboardChanged;assert.notEqual(preserved.code,0);assert(preserved.err.includes('Clipboard changed'));
  assert.equal(await page.locator('textarea').inputValue(),url+url+alternate+alternate,'A clipboard change during key release must not be pasted');
  console.log('PASS: Chrome and GNOME Terminal receive repeated pastes with a real Ctrl+Shift+U X11 keyboard grab held and then released. Focus and clipboard changes block delivery, unrelated text is preserved, no upload or Enter occurs, and the real desktop clipboard is untouched.');
 }finally{if(grab)grab.kill();if(terminal)terminal.kill();if(browser)await browser.close();xvfb.kill();fs.closeSync(log);fs.rmSync(config,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1});
