// Local browser-only transport/audio fixture. No native input or microphone APIs.
exports.createKeyboardFixture=async(browser,viewport,{reducedMotion='no-preference'}={})=>{
 const{makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');const state=makeDemoData(),id=state.machines[1]._id;
 const context=await browser.newContext({viewport,isMobile:viewport.width<=874,hasTouch:true,serviceWorkers:'block',reducedMotion});
 const records=[],errors=[];let held=false,transcription=0,releaseFirst,releaseSecond;
 const firstResponse=new Promise(resolve=>releaseFirst=resolve),secondResponse=new Promise(resolve=>releaseSecond=resolve);
 const firstText=`${'Earlier recognized context needs to scroll away. '.repeat(20)}THE NEWEST SPOKEN WORDS ARE VISIBLE`;
 await context.addInitScript(()=>{
  const track={stop(){},onended:null};const stream={getTracks:()=>[track],getAudioTracks:()=>[track]};
  Object.defineProperty(navigator,'mediaDevices',{configurable:true,value:{getUserMedia:async()=>{window.fixtureMicrophoneRequests=(window.fixtureMicrophoneRequests||0)+1;return stream;}}});
  class Node{connect(next){return next;}disconnect(){}}
  window.AudioContext=class{constructor(){this.state='running';this.audioWorklet={addModule:async()=>{}};this.destination=new Node();}async resume(){}createMediaStreamSource(){return new Node();}createGain(){const n=new Node();n.gain={value:1};return n;}async close(){this.state='closed';}};
  window.AudioWorkletNode=class extends Node{constructor(){super();this.port={onmessage:null};window.fixtureAudioNode=this;}};
 });
 await context.route('**/api/**',async route=>{const req=route.request(),path=new URL(req.url()).pathname;let data;
  if(path==='/api/keyboard/targets')data={targets:[{id,name:'Fixture desktop',kind:'agent',platform:'macos',online:true}]};
  else if(path==='/api/keyboard/speech')data={settings:{enabled:true,model:'fixture'},models:[{id:'fixture',name:'Local fixture model',installed:true,languages:['en'],translate:false,auto_language:false}]};
  else if(path==='/api/keyboard/speech/transcribe'){const n=++transcription;if(n===1)await firstResponse;if(n===2)await secondResponse;data={text:n===1?firstText:n===2?'FINAL WORDS AFTER STOP':'SECOND RECORDING LATEST WORDS'};}
  else{try{data=handleDemoRequest(state,req.method(),req.url(),req.postData()||{});}catch{data={};}}
  await route.fulfill({json:data}).catch(()=>{});
 });
 await context.routeWebSocket('**/api/keyboard/control/**',socket=>{socket.send(JSON.stringify({type:'ready',session:'local-keyboard-review-session',clipboard:true,direct:false}));socket.onMessage(raw=>{const event=JSON.parse(raw);if(event.type!=='input')return;const command=event.input.command;if(command.type==='release_all')held=false;if(command.type==='pointer'&&command.action==='press'&&command.button==='left')held=true;if(command.type==='pointer'&&command.action==='release'&&command.button==='left')held=false;records.push({command,held,id:event.input.id,at:Date.now()});socket.send(JSON.stringify({type:'ack',ack:{id:event.input.id,ok:true}}));});});
 const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
 return {page,context,records,errors,firstText,releaseFirst,releaseSecond,finalText:'FINAL WORDS AFTER STOP',feed:async amplitude=>page.evaluate(amplitude=>{const pcm=new Float32Array(amplitude?8000:16000).fill(amplitude);window.fixtureAudioNode.port.onmessage({data:{pcm,rate:16000}});},amplitude),close:async()=>{releaseFirst();releaseSecond();await context.close();}};
};

// Chromium's browser input pipeline creates real touch/pointer events. Observe
// their actual KeyboardTransport envelopes at the independent WS target model.
exports.verifyNativeBrowserTouch=async fixture=>{
 const assert=require('node:assert/strict'),{page,context,records}=fixture;
 const pad=page.getByRole('application',{name:/Touchpad:/}),box=await pad.boundingBox(),x=box.x+box.width/2,y=box.y+Math.min(box.height/2,box.height-60);
 const cdp=await context.newCDPSession(page);
 const touch=(type,dx=0,dy=0)=>cdp.send('Input.dispatchTouchEvent',{type,touchPoints:type==='touchEnd'||type==='touchCancel'?[]:[{x:x+dx,y:y+dy,id:41,radiusX:3,radiusY:3,force:1}]});
 const idle=await pad.evaluate(el=>getComputedStyle(el).borderColor);records.length=0;
 await touch('touchStart');await touch('touchMove',20);await page.waitForTimeout(180);
 assert.equal(await pad.evaluate(el=>getComputedStyle(el).borderColor),idle,'ordinary actual finger movement never highlights border');await touch('touchEnd');await page.waitForTimeout(500);
 records.length=0;await touch('touchStart');await touch('touchEnd');await page.waitForTimeout(100);await touch('touchStart');await page.waitForTimeout(180);
 assert.equal(records.filter(r=>r.command.action==='click').length,1,'first tap clicks once after StrictMode remount');
 assert.equal(records.filter(r=>r.command.action==='press').length,1,'stationary second tap presses once');
 assert.notEqual(await pad.evaluate(el=>getComputedStyle(el).borderColor),idle,'hold alone highlights border');
 await page.waitForTimeout(1100);assert.ok(records.some(r=>r.command.action==='move'&&r.command.dx===0&&r.command.dy===0&&r.held),'stationary hold renews target button');
 await touch('touchMove',30,10);await page.waitForTimeout(100);await touch('touchEnd');await page.waitForTimeout(120);
 const press=records.findIndex(r=>r.command.action==='press'),release=records.findIndex(r=>r.command.action==='release');
 assert.ok(press>=0&&release>press);assert.equal(records.filter(r=>r.command.action==='release').length,1);
 assert.ok(records.slice(press+1,release).some(r=>r.command.action==='move'&&(r.command.dx||r.command.dy)&&r.held),'target sees held move between press and release');
 assert.equal(new Set(records.map(r=>r.id)).size,records.length,'commands have distinct transport identities');
 const proof=records.map(r=>({command:r.command,held:r.held}));await cdp.detach();return proof;
};
