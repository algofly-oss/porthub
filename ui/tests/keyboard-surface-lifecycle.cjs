const assert=require('node:assert/strict'),fs=require('node:fs/promises');
const{launchBrowser}=require('./browser.cjs');
(async()=>{const browser=await launchBrowser();try{
 const page=await browser.newPage({viewport:{width:402,height:874},hasTouch:true});
 await page.setContent('<style>#pad{position:relative;width:300px;height:240px;touch-action:none}#keyboard{display:none}.tp-btn{height:44px}</style><div id="root"><div id="keyboard"></div><div id="pad"><button class="tp-btn" data-button="left">Left</button></div></div>');
 const source=await fs.readFile(process.env.PORTHUB_TEST_SURFACE_SOURCE||require('node:path').join(__dirname,'../src/lib/keyboardSurface.mjs'),'utf8');await page.addScriptTag({content:source.replace('export function mountKeyboardSurface','window.mountKeyboardSurface=function')});
 await page.evaluate(()=>{window.commands=[];window.mount=()=>mountKeyboardSurface({root:document.querySelector('#root'),keyboard:document.querySelector('#keyboard'),pad:document.querySelector('#pad'),read:()=>({connected:true,platform:'macos'}),command:c=>commands.push(c),mic:()=>{}});const first=mount();first.destroy();window.surface=mount();commands=[];});
 assert.equal(await page.locator('[data-mod=alt]').first().textContent(),'⌥','native macOS platform label matches original Option key');
 await page.touchscreen.tap(120,100);await page.waitForTimeout(100);
 assert.equal((await page.evaluate(()=>commands)).filter(c=>c.action==='click').length,1,'remounting the same pad must not duplicate touch listeners');
 await page.evaluate(()=>{commands=[];surface.destroy();surface.destroy();});
 assert.equal((await page.evaluate(()=>commands)).filter(c=>c.type==='release_all').length,1,'destroy is idempotent');
 await page.evaluate(()=>{commands=[];});await page.touchscreen.tap(120,100);await page.waitForTimeout(100);
 assert.deepEqual(await page.evaluate(()=>commands),[],'destroyed pad cannot emit stale commands');
 console.log('PASS actual browser touch after same-DOM destroy/remount, single emission, idempotent destroy and no stale ingress');
 }finally{await browser.close();}})().catch(error=>{console.error(error);process.exit(1)});
