import test from "node:test";
import assert from "node:assert/strict";
import {proxyBindings,proxyRouting,validateBindings,bindingPayload,defaultRouting,newBinding,newProxyDraft} from "../src/shared/utils/proxy-bindings.mjs";
import {selectProxies} from "../src/shared/utils/search.mjs";
test("legacy proxy remains one binding with passive health",()=>{
 const old={_id:"old",target_mode:"connection",connection:{data_id:"port",machine_id:"reid"},target_url:"http://gateway:8000"};
 assert.equal(proxyBindings(old)[0].connection_data_id,"port");assert.equal(proxyRouting(old).health.enabled,false);
 assert.equal(defaultRouting().health.enabled,true);
});
test("mixed binding payload drops copied connection metadata and resolves numbers",()=>{
 const bindings=[{...newBinding(),target_mode:"connection",connection_data_id:"port",connection:{machine_id:"reid"},priority:"2",weight:"3"},{...newBinding(),target_url:"https://standalone.example"}];
 const payload=bindingPayload(bindings);assert.equal(payload[0].priority,2);assert.equal(payload[0].weight,3);assert.equal(payload[0].target_url,null);assert.equal(payload[0].connection,undefined);
 assert.deepEqual(validateBindings(bindings,defaultRouting()),{});
 bindings[1].target_url="file:///etc/passwd";assert(Object.keys(validateBindings(bindings,defaultRouting())).length>0);
});
test("search and machine filters include every binding",()=>{
 const proxies=[{_id:"one",name:"one",enabled:true,bindings:[{label:"remote backup",target_url:"https://backup.example",connection:{machine_id:"thor"}},{connection:{machine_id:"reid"}}]}];
 assert.equal(selectProxies(proxies,{machine:"reid"}).length,1);assert.equal(selectProxies(proxies,{query:"remote backup"}).length,1);assert.equal(selectProxies(proxies,{machine:"unrelated"}).length,0);
});

test("new host-port proxy retains exact IDs through URL-driven creation",()=>{
 const draft=newProxyDraft("machine-b","port-b2");
 const binding=proxyBindings(draft)[0];
 assert.equal(binding.target_mode,"connection");assert.equal(binding.connection_data_id,"port-b2");assert.equal(binding.connection.machine_id,"machine-b");
 assert.notEqual(binding.connection_data_id,"port-b1");
 assert.equal(proxyBindings(newProxyDraft("machine-b"))[0].connection_data_id,"");
});
test("global proxy creation remains standalone without guessing a machine",()=>{
 assert.equal(newProxyDraft(),null);assert.equal(newProxyDraft("","port-b2"),null);
 assert.equal(newBinding().target_mode,"manual");
});
