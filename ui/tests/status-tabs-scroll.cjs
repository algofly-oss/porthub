const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {revealSelectedTab}=await import('../src/components/ui/status-tabs-scroll.mjs');
 const browser=await launchBrowser();
 try {
  for(const width of [320,402,874,1440]) {
   const page=await browser.newPage({viewport:{width,height:874}});
   await page.setContent(`<style>body{margin:0;height:2500px}.outer{margin-top:900px;max-width:650px;overflow-x:auto}.group{display:inline-flex;white-space:nowrap}button{flex-shrink:0;width:90px;height:40px}</style><div class="outer"><div class="group">${['Details','Ports','DNS','Client','Logs','History','Resources','USB'].map(n=>`<button aria-pressed="${n==='Resources'}">${n}</button>`).join('')}</div></div>`);
   await page.evaluate(()=>window.scrollTo(0,700));
   const reveal=()=>page.evaluate(`(${revealSelectedTab.toString()})(document.querySelector('.group'))`);
   const check=async()=>{
    const result=await page.evaluate(()=>{const p=document.querySelector('.outer'),b=document.querySelector('[aria-pressed=true]'),r=p.getBoundingClientRect(),t=b.getBoundingClientRect();return {visible:t.left>=r.left-1&&t.right<=r.left+p.clientWidth+1,y:window.scrollY,x:window.scrollX,scroll:p.scrollLeft};});
    assert(result.visible,`selected tab clipped at ${width}`);assert.equal(result.y,700);assert.equal(result.x,0);return result;
   };
   await reveal();await check();
   await page.evaluate(()=>{document.querySelector('[aria-pressed=true]').setAttribute('aria-pressed','false');document.querySelector('button').setAttribute('aria-pressed','true');});
   await reveal();assert.equal((await check()).scroll,0);
   await page.close();
  }
  console.log('PASS selected deep-linked tab and changed selection visible at 320/402/874/1440; page scroll unchanged');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
