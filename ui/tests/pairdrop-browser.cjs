const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const base=process.env.PORTHUB_TEST_UI_URL;
assert(base&&process.env.PORTHUB_TEST_PAIRDROP_UPSTREAM,'Isolated portal with PairDrop required');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome'});
 const folder=await fs.mkdtemp(path.join(os.tmpdir(),'porthub-pairdrop-browser-'));
 try{
  for(const blocked of [false,true]){
   const contexts=[];
   for(let i=0;i<2;i++){
    const context=await browser.newContext({acceptDownloads:true,viewport:{width:1280,height:900}});contexts.push(context);
    await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
    if(blocked)await context.addInitScript(()=>{
     class BlockedRTC {
      constructor(){this.connectionState='new';this.iceConnectionState='new';this.signalingState='stable';}
      createDataChannel(){return {readyState:'connecting',close(){this.readyState='closed';}};}
      createOffer(){return new Promise(()=>{});}
      close(){this.connectionState='closed';this.signalingState='closed';}
     }
     window.RTCPeerConnection=BlockedRTC;
    });
   }
   const [sender,receiver]=await Promise.all(contexts.map(context=>context.newPage()));
   const errors=[];for(const page of [sender,receiver])page.on('pageerror',error=>errors.push(error.message));
   await sender.goto(base+'/pairdrop/');
   await sender.waitForFunction(()=>typeof pairDrop!=='undefined'&&!!pairDrop.peers);
   let receiverUrl=base+'/pairdrop/';
   if(blocked){
    await sender.locator('#join-public-room').click();
    await sender.waitForFunction(()=>document.querySelector('#public-room-dialog .key').textContent.trim().length===5);
    const room=await sender.locator('#public-room-dialog .key').innerText();
    receiverUrl+='?room_id='+room.trim();
    await sender.locator('#public-room-dialog button[close]').click();
   }
   await receiver.goto(receiverUrl);
   await Promise.all([sender.locator('x-peer input[type=file]').first().waitFor({state:'attached'}),receiver.locator('x-peer').first().waitFor()]);
   if(blocked){await sender.waitForFunction(()=>Object.values(pairDrop.peers.peers).some(peer=>!peer.rtcSupported));assert(await sender.locator('x-peer').first().evaluate(node=>node.classList.contains('ws-peer')),'Failed RTC negotiates the room-authorized relay automatically');}
   const payload=crypto.randomBytes(256*1024+37);
   const downloadPromise=receiver.waitForEvent('download',{timeout:30000});
   await sender.locator('x-peer input[type=file]').first().setInputFiles({name:'PairDrop original.xlsx',mimeType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',buffer:payload});
   await receiver.locator('#accept-request').click();
   const download=await downloadPromise;assert.equal(download.suggestedFilename(),'PairDrop original.xlsx');
   const out=path.join(folder,blocked?'relayed.xlsx':'normal.xlsx');await download.saveAs(out);assert.deepEqual(await fs.readFile(out),payload);
   if(!blocked){
    await sender.evaluate(async()=>{await PersistentStorage.addRoomSecret('a'.repeat(64),'<img src=x onerror="window.porthubXss=true">','<svg onload="window.porthubXss=true">');});
    await sender.reload();await sender.locator('#edit-paired-devices').click();
    await sender.locator('.paired-device .display-name').first().waitFor();
    assert.equal(await sender.locator('.paired-device img,.paired-device svg').count(),0,'Peer names remain text in the paired-device dialog');
    assert.equal(await sender.evaluate(()=>!!window.porthubXss),false);
   }
   assert.deepEqual(errors,[]);
   await Promise.all(contexts.map(context=>context.close()));
  }
  console.log('PASS: anonymous PairDrop browser discovery, accepted original-file downloads, public-room links, automatic relay after failed RTC, and escaped stored peer names.');
 }finally{await browser.close();await fs.rm(folder,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exit(1);});
