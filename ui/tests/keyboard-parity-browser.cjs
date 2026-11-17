const assert=require('node:assert/strict'),fs=require('node:fs');
const{launchBrowser,waitForWorkspaceLayout}=require('./browser.cjs');
const{createKeyboardFixture,verifyNativeBrowserTouch}=require('./keyboard-local-fixture.cjs');
(async()=>{
 const browser=await launchBrowser(),engine=process.env.REVIEW_BROWSER||'chromium',out=process.env.REVIEW_SCREENSHOT_DIR||'/tmp/porthub-vkeyboard-parity';fs.mkdirSync(out,{recursive:true});
 try{for(const viewport of[{width:1512,height:982},{width:402,height:874},{width:402,height:760},{width:874,height:402},{width:320,height:760}]){
  const fixture=await createKeyboardFixture(browser,viewport),{page}=fixture,label=`${engine}-${viewport.width}x${viewport.height}`;
  try{
   await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:8322'}/home?view=keyboard`);
   const toolbar=page.getByRole('toolbar',{name:'Keyboard controls',exact:true});await toolbar.waitFor();
   assert.equal(await toolbar.locator('input,select').count(),0,'client selector belongs inside settings');
   await page.getByRole('button',{name:'Keyboard clients',exact:true}).click();
   const picker=page.getByLabel('Keyboard client',{exact:true});await picker.waitFor();
   assert.ok(await picker.isVisible(),'device selector reachable inside Clients settings');
   await page.screenshot({path:`${out}/${label}-clients.png`,scale:'css'});
   await page.getByRole('button',{name:'Connect client',exact:true}).click();
   await page.getByRole('button',{name:'Disconnect client',exact:true}).waitFor();
   await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();
   await page.getByRole('dialog').waitFor({state:'hidden'});await waitForWorkspaceLayout(page);
   const geometry=await toolbar.evaluate(element=>{const r=element.getBoundingClientRect();return{height:r.height,left:r.left,right:r.right,width:innerWidth,scrollWidth:document.documentElement.scrollWidth,buttons:[...element.querySelectorAll('button')].filter(b=>b.getBoundingClientRect().width).map(b=>({label:b.getAttribute('aria-label'),height:b.getBoundingClientRect().height,width:b.getBoundingClientRect().width,borderRadius:getComputedStyle(b).borderRadius}))};});
   assert.ok(geometry.height<=45&&geometry.scrollWidth<=geometry.width+1,JSON.stringify(geometry));for(const b of geometry.buttons)assert.ok(b.width>=44&&b.height>=44,JSON.stringify(b));
   const accent=await page.getByRole('textbox',{name:'Capture physical keyboard',exact:true}).evaluate(element=>({primary:getComputedStyle(element).getPropertyValue('--primary').trim(),enter:getComputedStyle(element.querySelector('.vk.enter')).backgroundColor}));
   assert.ok(accent.primary&&accent.enter!=='rgba(0, 0, 0, 0)','scoped accent is defined; enter/microphone never fall back to transparent');
   await page.screenshot({path:`${out}/${label}-idle.png`,scale:'css'});
   const touchProof=engine==='chromium'&&viewport.width===402&&viewport.height===874?await verifyNativeBrowserTouch(fixture):null;
   const start=page.getByRole('button',{name:'Start dictation',exact:true});if(await start.isVisible())await start.click();else await page.getByRole('button',{name:'Dictate',exact:true}).click();
   const stop=page.getByRole('button',{name:'Stop recording',exact:true});await stop.waitFor();
   await fixture.feed(.08);await page.waitForTimeout(200);
   const wave=page.getByRole('meter',{name:'Microphone level',exact:true});await wave.waitFor();
   if(await wave.isVisible()){const b=await wave.boundingBox();assert.ok(b.width>=150,'original recording waveform takes the status area');}
   await page.screenshot({path:`${out}/${label}-recording.png`,scale:'css'});
   await fixture.feed(0);fixture.releaseFirst();
   const caption=page.getByLabel('Recognized text',{exact:true});await caption.waitFor();
   assert.match(await caption.innerText(),/THE NEWEST SPOKEN WORDS ARE VISIBLE/);
   assert.ok(await stop.isVisible(),'returned live transcript is visible before recording stops');
   assert.ok(await wave.isVisible(),'waveform stays visible alongside returned live text');
   await page.waitForFunction(()=>{const e=document.querySelector('[aria-label="Recognized text"]');return e&&e.getAnimations({subtree:true}).every(a=>a.playState!=='running');});
   const tail=await caption.evaluate(element=>{const node=element.firstElementChild?.lastElementChild?.firstChild;if(!node||node.nodeType!==Node.TEXT_NODE)throw Error('caption text node absent');const range=document.createRange();range.setStart(node,Math.max(0,node.textContent.length-7));range.setEnd(node,node.textContent.length);const r=range.getBoundingClientRect(),clip=element.getBoundingClientRect();return{top:r.top,bottom:r.bottom,clipTop:clip.top,clipBottom:clip.bottom,viewport:innerHeight};});
   assert.ok(tail.bottom<=tail.clipBottom+2&&tail.bottom>tail.clipTop&&tail.bottom<=tail.viewport,'newest words are actually visible, pinned to bottom');
   await page.screenshot({path:`${out}/${label}-live-recognized.png`,scale:'css'});
   await fixture.feed(.08);await fixture.feed(0);await stop.click();
   await page.screenshot({path:`${out}/${label}-processing.png`,scale:'css'});
   fixture.releaseSecond();await page.getByLabel('Recognized text',{exact:true}).getByText('FINAL WORDS AFTER STOP',{exact:false}).waitFor();
   await page.waitForFunction(()=>{const e=document.querySelector('[aria-label="Recognized text"]');return e&&e.getAnimations({subtree:true}).every(a=>a.playState!=='running');});
   await page.screenshot({path:`${out}/${label}-recognized.png`,scale:'css'});
   assert.equal(fixture.records.filter(row=>row.command.type==='text'&&row.command.text.includes('THE NEWEST SPOKEN')).length,1,'actual current target session receives live transcription once');
   await page.getByRole('button',{name:'Read recognized text',exact:true}).click();
   await page.getByLabel('Text to send to the selected client').waitFor();assert.equal(await page.getByLabel('Text to send to the selected client').inputValue(),fixture.firstText+' '+fixture.finalText+' ');
   await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});
   const restart=page.getByRole('button',{name:'Start dictation',exact:true});if(await restart.isVisible())await restart.click();else await page.getByRole('button',{name:'Dictate',exact:true}).click();
   await page.getByRole('button',{name:'Stop recording',exact:true}).waitFor();
   await fixture.feed(.08);await fixture.feed(0);
   const nextCaption=page.getByLabel('Recognized text',{exact:true});await nextCaption.getByText('SECOND RECORDING LATEST WORDS',{exact:false}).waitFor();
   assert.doesNotMatch(await nextCaption.innerText(),/THE NEWEST SPOKEN|FINAL WORDS AFTER STOP/,'new recording resets only live caption context');
   await page.getByRole('button',{name:'Stop recording',exact:true}).click();
   assert.deepEqual(fixture.errors,[]);fs.writeFileSync(`${out}/${label}.json`,JSON.stringify({geometry,tail,touchProof,errors:fixture.errors,commands:fixture.records.map(r=>r.command.type)},null,2));
   console.log(`PASS ${engine} original toolbar/Clients/recording/processing/recognized tail/full text/session ${viewport.width}x${viewport.height}`);
  }catch(error){await page.screenshot({path:`${out}/${label}-failure.png`,scale:'css'}).catch(()=>{});fs.writeFileSync(`${out}/${label}-failure.json`,JSON.stringify({error:String(error),errors:fixture.errors},null,2));throw error;}finally{await fixture.close();}
 }}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exit(1)});
