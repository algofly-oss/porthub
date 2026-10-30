import test from "node:test";
import assert from "node:assert/strict";
import {createInventoryResource,inventoryUrl} from "../src/shared/utils/inventory-resource.mjs";
test("inventory requests are bounded, deduplicated and conditionally revalidated",async()=>{
 const resource=createInventoryResource({capacity:2});let requests=0;
 const loader=async({etag})=>{requests++;return etag ? {status:304,etag} : {status:200,data:{data:[{_id:"one"}]},etag:'"v1"'};};
 const a=resource.acquire("one",loader),b=resource.acquire("one",loader);assert.equal((await a.promise).data.data[0]._id,"one");await b.promise;assert.equal(requests,1);a.release();b.release();
 await resource.acquire("one",loader).promise;assert.equal(requests,2);assert.equal(resource.get("one").data.data.length,1);
 await resource.acquire("two",loader).promise;await resource.acquire("three",loader).promise;assert.equal(resource.size,2);assert.equal(resource.get("one"),undefined);
});
test("abandoned searches abort without dropping a shared reader",async()=>{
 const resource=createInventoryResource();let finish,signal;
 const loader=options=>{signal=options.signal;return new Promise(resolve=>{finish=resolve;});};
 const a=resource.acquire("query",loader),b=resource.acquire("query",loader);await Promise.resolve();a.release();assert.equal(signal.aborted,false);b.release();assert.equal(signal.aborted,true);
 finish({status:200,data:{data:["stale"]}});await assert.rejects(a.promise,{name:"AbortError"});assert.equal(resource.get("query"),undefined);
});
test("query keys include every filter and are stable across property order",()=>{
 assert.equal(inventoryUrl("machines",{page:1,q:"Reid"}),inventoryUrl("machines",{q:"Reid",page:1}));
 assert.notEqual(inventoryUrl("machines",{page:1}),inventoryUrl("machines",{page:2}));
});
test("a mutation invalidates pending reads before they can cache old data",async()=>{
 const resource=createInventoryResource();let finish;
 const key=inventoryUrl("machines",{page:1});const stale=resource.acquire(key,()=>new Promise(resolve=>finish=resolve));await Promise.resolve();
 resource.invalidate("machines");const fresh=resource.acquire(key,async()=>({status:200,data:{data:["new"]}}));await fresh.promise;
 finish({status:200,data:{data:["old"]}});await assert.rejects(stale.promise,{name:"AbortError"});assert.deepEqual(resource.get(key).data.data,["new"]);
});
