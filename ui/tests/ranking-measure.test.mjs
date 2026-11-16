import test from 'node:test';
import assert from 'node:assert/strict';
import { observeRankingRows } from '../src/shared/utils/ranking-measure.mjs';
function fixture(run) {
  const original = [globalThis.ResizeObserver, globalThis.requestAnimationFrame, globalThis.cancelAnimationFrame];
  let callback, disconnected = false, next = 0;
  const frames = new Map(), writes = [];
  const style = name => { const values = new Map(); return { getPropertyValue:key=>values.get(key)||'', setProperty:(key,value)=>{values.set(key,value);writes.push([name,key,value]);} }; };
  const parent = { style:style('parent') }, rows = [{getBoundingClientRect:()=>({height:19})},{getBoundingClientRect:()=>({height:19})}];
  const element = { clientHeight:39,offsetWidth:116,clientWidth:100,parentElement:parent,style:style('viewport'),querySelectorAll:()=>rows };
  globalThis.ResizeObserver = class { constructor(fn){callback=fn;} observe(){} disconnect(){disconnected=true;} };
  globalThis.requestAnimationFrame = fn => {frames.set(++next,fn);return next;};
  globalThis.cancelAnimationFrame = id => frames.delete(id);
  try {run({element,writes,frames,notify:()=>callback(),flush:()=>{const pending=[...frames.values()];frames.clear();pending.forEach(fn=>fn());},disconnected:()=>disconnected});}
  finally {[globalThis.ResizeObserver,globalThis.requestAnimationFrame,globalThis.cancelAnimationFrame]=original;}
}
test('observer delivery coalesces without synchronous layout writes',()=>fixture(f=>{
 const stop=observeRankingRows(f.element);f.writes.length=0;f.element.clientHeight=50;
 f.notify();f.notify();f.notify();assert.equal(f.frames.size,1);assert.deepEqual(f.writes,[]);
 f.flush();assert.equal(f.element.style.getPropertyValue('--ranking-row-height'),'20px');assert.equal(f.frames.size,0);stop();
}));
test('unchanged geometry causes no repeated style writes',()=>fixture(f=>{
 const stop=observeRankingRows(f.element);f.writes.length=0;f.notify();f.flush();assert.deepEqual(f.writes,[]);stop();
}));
test('cleanup cancels scheduled measurement and rejects late callbacks',()=>fixture(f=>{
 const stop=observeRankingRows(f.element);f.writes.length=0;f.notify();const late=[...f.frames.values()][0];stop();assert.equal(f.frames.size,0);assert(f.disconnected());
 f.element.clientHeight=80;late();f.notify();assert.equal(f.frames.size,0);assert.deepEqual(f.writes,[]);
}));
test('hidden viewport resumes measuring after a later visible frame',()=>fixture(f=>{
 f.element.clientHeight=0;const stop=observeRankingRows(f.element);assert.equal(f.element.style.getPropertyValue('--ranking-row-height'),'');
 f.element.clientHeight=39;f.notify();f.flush();assert.equal(f.element.style.getPropertyValue('--ranking-row-height'),'39px');stop();
}));
