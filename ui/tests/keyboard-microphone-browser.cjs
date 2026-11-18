const assert=require('node:assert/strict'),fs=require('node:fs');
const{launchBrowser,waitForWorkspaceLayout}=require('./browser.cjs');
const{createKeyboardFixture}=require('./keyboard-local-fixture.cjs');
(async()=>{
 const browser=await launchBrowser(),engine=process.env.REVIEW_BROWSER||'chromium',out=process.env.REVIEW_SCREENSHOT_DIR||'/tmp/porthub-vkeyboard-microphone';fs.mkdirSync(out,{recursive:true});
 try{await verifySlowInitialSettings(browser,engine);for(const layout of ['portrait','auto'])await verifyMicrophoneLandscape(browser,engine,out,layout);for(const viewport of[{width:402,height:874},{width:320,height:760}]){
  const fixture=await createKeyboardFixture(browser,viewport,{reducedMotion:viewport.width===320?'reduce':'no-preference'}),{page}=fixture,label=`${engine}-${viewport.width}x${viewport.height}-microphone`;
  await fixture.context.addInitScript(()=>{localStorage.setItem('porthub.keyboard.layout','portrait');localStorage.setItem('porthub.keyboard.preferences',JSON.stringify({touchpad:false,mouseButtons:true,functionKeys:false,reverseScroll:false}));});
  try{
   await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:8323'}/home?view=keyboard`);
   const start=page.getByRole('button',{name:'Start dictation',exact:true});await start.waitFor();await waitForWorkspaceLayout(page);
   const timer=page.getByRole('timer',{name:'Recording duration'});
   assert.equal(await timer.innerText(),'0:00');assert.equal(await timer.evaluate(e=>getComputedStyle(e).opacity),'0');
   const mic=await start.boundingBox();assert.equal(mic.width,128);assert.equal(mic.height,128);
   await page.screenshot({path:`${out}/${label}-idle.png`,scale:'css'});
   await start.click();const stop=page.getByRole('button',{name:'Stop recording',exact:true});await stop.waitFor();
   await page.waitForFunction(()=>document.querySelector('[role="timer"]')?.textContent==='0:01',{},{timeout:4000});
   assert.equal(await timer.evaluate(e=>getComputedStyle(e).opacity),'1');
   const pulses=await stop.evaluate(e=>[...e.parentElement.querySelectorAll('[aria-hidden]')].map(n=>getComputedStyle(n).animationName));
   assert.equal(pulses.filter(name=>name.includes('dictationPulse')).length,viewport.width===320?0:2,'original two staggered pulses respect reduced motion');
   await fixture.feed(.08);await fixture.feed(0);fixture.releaseFirst();
   const caption=page.getByLabel('Recognized text',{exact:true});await caption.getByText('THE NEWEST SPOKEN WORDS ARE VISIBLE',{exact:false}).waitFor();
   await waitForWorkspaceLayout(page);
   const geometry=await stop.evaluate(e=>{const r=e.getBoundingClientRect(),timer=document.querySelector('[role="timer"]').getBoundingClientRect(),caption=document.querySelector('[aria-label="Recognized text"]').getBoundingClientRect();return{mic:{top:r.top,bottom:r.bottom},timer:{top:timer.top,bottom:timer.bottom},caption:{top:caption.top,bottom:caption.bottom},width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth};});
   assert.ok(geometry.timer.bottom<=geometry.mic.top&&geometry.caption.top>=geometry.mic.bottom,JSON.stringify(geometry));assert.ok(geometry.caption.bottom<=geometry.height&&geometry.scrollWidth<=geometry.width+1,JSON.stringify(geometry));
   await page.screenshot({path:`${out}/${label}-recording.png`,scale:'css'});
   await fixture.feed(.08);await fixture.feed(0);await stop.click();
   await page.waitForFunction(()=>document.querySelector('[aria-label="Start dictation"]')?.disabled===true);
   const frozen=await timer.innerText();await page.waitForTimeout(1100);assert.equal(await timer.innerText(),frozen,'processing freezes original elapsed duration');
   await page.screenshot({path:`${out}/${label}-processing.png`,scale:'css'});
   fixture.releaseSecond();await caption.getByText('FINAL WORDS AFTER STOP',{exact:false}).waitFor();
   await page.waitForFunction(()=>document.querySelector('[role="timer"]')?.textContent==='0:00');
   await page.waitForFunction(()=>getComputedStyle(document.querySelector('[role="timer"]')).opacity==='0');
   assert.equal(await timer.evaluate(e=>getComputedStyle(e).opacity),'0');
   await start.click();await stop.waitFor();assert.equal(await timer.innerText(),'0:00','new recording resets elapsed duration');await stop.click();
   assert.deepEqual(fixture.errors,[]);fs.writeFileSync(`${out}/${label}.json`,JSON.stringify({geometry,frozen,errors:fixture.errors},null,2));console.log(`PASS ${engine} microphone-only elapsed/recording/processing/reset ${viewport.width}x${viewport.height}`);
  }catch(error){await page.screenshot({path:`${out}/${label}-failure.png`,scale:'css'}).catch(()=>{});fs.writeFileSync(`${out}/${label}-failure.json`,JSON.stringify({error:String(error),errors:fixture.errors},null,2));throw error;}finally{await fixture.close();}
 }}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exit(1)});

async function verifySlowInitialSettings(browser,engine){
 const fixture=await createKeyboardFixture(browser,{width:402,height:874}),{page}=fixture;
 let releaseInitial,finishedInitial;const held=new Promise(resolve=>releaseInitial=resolve),finished=new Promise(resolve=>finishedInitial=resolve);let requests=0;
 await fixture.context.route('**/api/keyboard/speech',async route=>{const first=++requests===1;if(first)await held;await route.fulfill({json:{settings:{enabled:first,model:'fixture'},models:[{id:'fixture',installed:true,languages:['en'],translate:false}]},headers:{'x-fixture-settings':first?'stale':'new'}}).catch(()=>{});if(first)finishedInitial();});
 try{
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:8323'}/home?view=keyboard`);
  await page.getByRole('button',{name:'Keyboard clients',exact:true}).waitFor();
  const newer=page.waitForResponse(response=>response.headers()['x-fixture-settings']==='new');
  await page.getByRole('button',{name:'Keyboard clients',exact:true}).click();await newer;
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await waitForWorkspaceLayout(page);
  const status=page.getByRole('button',{name:'Dictation status',exact:true});await status.getByText('Dictation off',{exact:true}).waitFor();
  releaseInitial();await finished;await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  assert.equal(await status.innerText(),'Dictation off','late initial settings cannot overwrite newer drawer state');
  assert.equal(await page.getByRole('button',{name:'Start dictation',exact:true}).isEnabled(),false);
  assert.equal(await page.evaluate(()=>window.fixtureMicrophoneRequests||0),0);assert.deepEqual(fixture.errors,[]);
  console.log(`PASS ${engine} delayed initial speech settings preserve newer disabled state`);
 }finally{releaseInitial();await fixture.close();}
}

async function verifyMicrophoneLandscape(browser,engine,out,layout){
 const fixture=await createKeyboardFixture(browser,{width:874,height:402}),{page}=fixture,label=`${engine}-874x402-microphone-${layout}`;
 await fixture.context.addInitScript(layout=>{localStorage.setItem('porthub.keyboard.layout',layout);localStorage.setItem('porthub.keyboard.preferences',JSON.stringify({touchpad:false}));},layout);
 const geometry=async()=>page.evaluate(()=>({height:innerHeight,width:innerWidth,scrollWidth:document.documentElement.scrollWidth,keys:[...document.querySelectorAll('.vk')].filter(e=>e.getBoundingClientRect().width).map(e=>({top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom}))}));
 const fits=async phase=>{const g=await geometry();assert.ok(g.keys.length>20&&g.keys.every(k=>k.top>=0&&k.bottom<=g.height+1)&&g.scrollWidth<=g.width+1,phase+': '+JSON.stringify(g));return g;};
 try{
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:8323'}/home?view=keyboard`);await page.getByRole('toolbar',{name:'Keyboard controls'}).waitFor();await waitForWorkspaceLayout(page);
  assert.equal(await page.locator('[role="timer"]').isVisible(),false,'compact landscape has no large microphone timer stage');
  const idle=await fits('idle');await page.screenshot({path:`${out}/${label}-idle.png`,scale:'css'});
  await page.getByRole('button',{name:'Dictate',exact:true}).click();const stop=page.getByRole('button',{name:'Stop recording',exact:true});await stop.waitFor();await fixture.feed(.08);await fixture.feed(0);fixture.releaseFirst();
  await page.getByLabel('Recognized text',{exact:true}).getByText('THE NEWEST SPOKEN WORDS ARE VISIBLE',{exact:false}).waitFor();await waitForWorkspaceLayout(page);
  const recording=await fits('recording recognized text');assert.ok(await stop.isVisible());await page.screenshot({path:`${out}/${label}-recording.png`,scale:'css'});
  await fixture.feed(.08);await fixture.feed(0);await stop.click();const busy=page.getByRole('button',{name:'Transcribing…',exact:true});await busy.waitFor();
  const processing=await fits('processing');const icon=await busy.evaluate(e=>({height:e.getBoundingClientRect().height,spinner:parseFloat(getComputedStyle(e,'::after').height)}));assert.ok(icon.spinner>0&&icon.spinner<=icon.height,'processing spinner fits compact microphone key');
  assert.equal(await page.getByRole('button',{name:'Start dictation',exact:true,includeHidden:true}).evaluate(e=>getComputedStyle(e).width),'44px','standalone microphone resets to compact size');
  await page.screenshot({path:`${out}/${label}-processing.png`,scale:'css'});fixture.releaseSecond();await page.getByLabel('Recognized text',{exact:true}).getByText('FINAL WORDS AFTER STOP',{exact:false}).waitFor();
  assert.deepEqual(fixture.errors,[]);fs.writeFileSync(`${out}/${label}.json`,JSON.stringify({idle,recording,processing,icon,errors:fixture.errors},null,2));console.log(`PASS ${engine} microphone-only compact landscape ${layout} 874x402`);
 }catch(error){await page.screenshot({path:`${out}/${label}-failure.png`,scale:'css'}).catch(()=>{});throw error;}finally{await fixture.close();}
}
