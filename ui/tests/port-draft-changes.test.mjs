import test from 'node:test';import assert from 'node:assert/strict';
import {portDraftChanges} from '../src/shared/utils/port-draft-changes.mjs';
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
test('unloaded ports cannot be deleted or overwritten by a paged editor',()=>{
 const original={dataId:'loaded',serviceName:'safe',firewall:{allowedIps:['192.0.2.1']}};
 const edits=[{...original,serviceName:'changed'},{dataId:'not-in-originals',serviceName:'unloaded'}];
 const changes=portDraftChanges([original],edits,equal);assert.deepEqual(changes.deleted,[]);assert.deepEqual(changes.updated,[edits[0]]);
});
test('only loaded removals and explicit new rows are applied; temporary mappings are preserved',()=>{
 const keep={dataId:'keep'},removed={dataId:'remove'},temp={dataId:'temporary',temporary:true};const fresh={serviceName:'new'};
 const changes=portDraftChanges([keep,removed,temp],[keep,fresh],equal);assert.deepEqual(changes.deleted,[removed]);assert.deepEqual(changes.created,[fresh]);assert.deepEqual(changes.updated,[]);
});
