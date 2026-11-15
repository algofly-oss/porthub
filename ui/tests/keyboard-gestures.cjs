const {chromium}=require('playwright');const fs=require('node:fs/promises');const assert=require('node:assert/strict');
(async()=>{const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});try{
 const page=await browser.newPage({hasTouch:true,viewport:{width:390,height:844}});await page.setContent('<div id="root" tabindex="0"><div id="keyboard"></div><div id="pad"><button class="tp-btn" data-button="left">Left</button><button class="tp-btn" data-button="right">Right</button></div></div>');
 const source=(await fs.readFile(require('node:path').join(__dirname,'../src/lib/keyboardSurface.mjs'),'utf8')).replace('export function mountKeyboardSurface','window.mountKeyboardSurface = function');await page.addScriptTag({content:source});
 await page.evaluate(()=>{window.commands=[];window.preferences={connected:true,functionKeys:true,reverseScroll:false};window.surface=mountKeyboardSurface({root:document.querySelector('#root'),keyboard:document.querySelector('#keyboard'),pad:document.querySelector('#pad'),read:()=>preferences,command:c=>commands.push(c),mic:()=>{}});
 window.pointer=(selector,type,id=1)=>document.querySelector(selector).dispatchEvent(new PointerEvent(type,{bubbles:true,cancelable:true,pointerId:id,pointerType:'touch'}));
 window.tap=selector=>{pointer(selector,'pointerdown');pointer(selector,'pointerup')};
 window.touch=(type,fingers,time)=>{const pad=document.querySelector('#pad');const touches=fingers.map(([id,x,y])=>new Touch({identifier:id,target:pad,clientX:x,clientY:y}));const e=new TouchEvent(type,{bubbles:true,cancelable:true,changedTouches:touches});Object.defineProperty(e,'timeStamp',{value:time});pad.dispatchEvent(e);};
 });
 await page.evaluate(()=>{pointer('[data-base=q]','pointerdown',1);pointer('[data-base=w]','pointerdown',2)});assert.deepEqual(await page.evaluate(()=>commands.slice(-2)),[{type:'text',text:'q'},{type:'text',text:'w'}],'two-thumb rollover emits on down');
 await page.evaluate(()=>{tap('[data-mod=ctrl]');tap('[data-base=a]');tap('[data-base=b]')});assert.deepEqual(await page.evaluate(()=>commands.slice(-2)),[{type:'key',key:'ctrl+a',state:'press'},{type:'text',text:'b'}]);
 await page.evaluate(()=>{tap('[data-mod=shift]');tap('[data-mod=shift]');tap('[data-base=c]');tap('[data-base=d]')});assert.deepEqual(await page.evaluate(()=>commands.slice(-2)),[{type:'text',text:'C'},{type:'text',text:'D'}]);
 await page.evaluate(()=>{tap('[data-mod=shift]');pointer('[data-mod=ctrl]','pointerdown',3);tap('[data-base=e]');tap('[data-base=f]');pointer('[data-mod=ctrl]','pointerup',3)});assert.deepEqual(await page.evaluate(()=>commands.slice(-2).map(c=>c.key)),['ctrl+e','ctrl+f']);
 await page.evaluate(()=>{commands=[];pointer('[data-key=backspace]','pointerdown')});await page.waitForTimeout(360);await page.evaluate(()=>pointer('[data-key=backspace]','pointerup'));const count=await page.evaluate(()=>commands.length);assert(count>=4);await page.waitForTimeout(180);assert.equal(await page.evaluate(()=>commands.length),count,'repeat stops on release');
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50],[2,80,50]],1000);touch('touchend',[[1,50,50],[2,80,50]],1100)});assert.deepEqual(await page.evaluate(()=>commands),[{type:'pointer',action:'click',button:'right'}]);
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50],[2,80,50]],2000);touch('touchmove',[[1,50,86],[2,80,86]],2030);touch('touchend',[[1,50,86],[2,80,86]],2100)});await page.waitForTimeout(30);assert((await page.evaluate(()=>commands)).some(c=>c.action==='scroll'&&c.dy<0));
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50]],3000);touch('touchend',[[1,50,50]],3050);touch('touchstart',[[1,50,50]],3150);touch('touchmove',[[1,80,50]],3170);touch('touchend',[[1,80,50]],3250)});const drag=await page.evaluate(()=>commands);assert(drag.some(c=>c.action==='press'&&c.button==='left'));assert(drag.some(c=>c.action==='release'&&c.button==='left'));
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50]],4000);touch('touchcancel',[[1,50,50]],4010)});assert(!(await page.evaluate(()=>commands)).some(c=>c.action==='click'),'cancellation never clicks');
 await page.evaluate(()=>{commands=[];pointer('.tp-btn','pointerdown',8);window.dispatchEvent(new Event('blur'))});assert((await page.evaluate(()=>commands)).some(c=>c.action==='release'&&c.button==='left'),'blur releases held mouse buttons');
 // A stationary second tap must hold before any movement and renew the native
 // five-second deadman. A quick second tap still produces a normal double click.
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50]],5000);touch('touchend',[[1,50,50]],5050);touch('touchstart',[[1,50,50]],5350)});
 await page.waitForTimeout(120);
 assert.equal((await page.evaluate(()=>commands)).filter(c=>c.action==='press').length,1,'stationary second tap presses once');
 await page.waitForTimeout(6100);
 const held=await page.evaluate(()=>commands);assert(!held.some(c=>c.action==='release'),'holding never releases early');assert(held.filter(c=>c.action==='move'&&c.dx===0&&c.dy===0).length>=5,'stationary hold renews native deadman');
 await page.evaluate(()=>touch('touchend',[[1,50,50]],11700));
 assert.equal((await page.evaluate(()=>commands)).filter(c=>c.action==='release').length,1);
 const released=await page.evaluate(()=>commands.length);await page.waitForTimeout(1100);assert.equal(await page.evaluate(()=>commands.length),released,'renewal stops after lift');
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50]],13000);touch('touchend',[[1,50,50]],13050);touch('touchstart',[[1,50,50]],13100);touch('touchend',[[1,50,50]],13150)});
 await page.waitForTimeout(120);assert.equal((await page.evaluate(()=>commands)).filter(c=>c.action==='click').length,2,'quick double tap stays a double click');
 await page.evaluate(()=>{commands=[];touch('touchstart',[[1,50,50]],14000);touch('touchend',[[1,50,50]],14050);touch('touchstart',[[1,50,50]],14100);touch('touchcancel',[[1,50,50]],14120)});
 await page.waitForTimeout(120);assert(!(await page.evaluate(()=>commands)).some(c=>c.action==='press'),'cancelled hold timer cannot press later');
 await page.evaluate(()=>surface.destroy());console.log('PASS: touch-down typing, sticky/held modifiers, Caps Lock, repeat, two-finger right-click/scroll, tap-and-drag, cancellation and held-button cleanup');
 }finally{await browser.close();}})().catch(error=>{console.error(error);process.exitCode=1});
