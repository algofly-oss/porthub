import test from 'node:test';
import assert from 'node:assert/strict';
import {makeDemoData,handleDemoRequest} from '../src/shared/demo/data.mjs';
import {normalizePrivateTraffic,privateTrafficWindow} from '../src/shared/utils/private-traffic.mjs';
for(const range of ['1h','24h','7d','30d'])test(`paged demo directional contract ${range}`,()=>{
 const state=makeDemoData(),reply=normalizePrivateTraffic(handleDemoRequest(state,'GET',`/api/private/traffic?range=${range}`));
 assert.equal(reply.flows.length,3);assert.equal(reply.coverage.reporting_peers,3);assert.equal(reply.coverage.unreported_peers,1);assert.equal(reply.selected_flow,null);assert.ok(reply.flows.every(flow=>!Object.hasOwn(flow,'points')));
 assert.equal(reply.totals.total_bytes,reply.points.reduce((sum,p)=>sum+p.direct_sent+p.relay_sent,0));assert.ok(privateTrafficWindow(reply).some(point=>point.direct===null));
 const flow=reply.flows[0],pair=normalizePrivateTraffic(handleDemoRequest(state,'GET',`/api/private/traffic?range=${range}&source_peer_id=${flow.source_peer_id}&destination_peer_id=${flow.destination_peer_id}`));assert.equal(pair.selected_flow.source_peer_id,flow.source_peer_id);assert.ok(pair.selected_flow.points.length);assert.deepEqual(pair.totals,reply.totals);
 const machine=state.machines[1]._id,filtered=normalizePrivateTraffic(handleDemoRequest(state,'GET',`/api/private/traffic?range=${range}&machine_id=${machine}`));assert.equal(filtered.flows.length,2);assert.ok(filtered.flows.every(flow=>flow.source_machine_id===machine||flow.destination_machine_id===machine));
});
test('large demo pagination and search retain full aggregate without all pair histories',()=>{
 const state=makeDemoData();state.privateTrafficDirections=85;
 const first=normalizePrivateTraffic(handleDemoRequest(state,'GET','/api/private/traffic?page=1')),second=normalizePrivateTraffic(handleDemoRequest(state,'GET','/api/private/traffic?page=2')),third=normalizePrivateTraffic(handleDemoRequest(state,'GET','/api/private/traffic?page=3'));
 assert.equal(first.flows.length,40);assert.equal(second.flows.length,40);assert.equal(third.flows.length,5);assert.deepEqual(second.totals,first.totals);assert.deepEqual(third.points,first.points);assert.equal(first.pagination.total_pairs,85);
 const search=normalizePrivateTraffic(handleDemoRequest(state,'GET','/api/private/traffic?search=pair%2084'));assert.equal(search.flows.length,1);assert.equal(search.pagination.filtered_pairs,1);assert.deepEqual(search.totals,first.totals);
 const missing=normalizePrivateTraffic(handleDemoRequest(state,'GET','/api/private/traffic?source_peer_id=foreign&destination_peer_id=absent'));assert.equal(missing.selected_flow,null);assert.deepEqual(missing.totals,first.totals);
});
test('historic demo volume survives zero current reporters and errors stay explicit',()=>{
 const state=makeDemoData();state.privateTrafficCoverage={reporting_peers:0,eligible_peers:4,unreported_peers:4,dropped_rows:2,history_incomplete:true};state.privateTrafficStale=true;
 const reply=normalizePrivateTraffic(handleDemoRequest(state,'GET','/api/private/traffic'));assert.ok(reply.totals.total_bytes>0);assert.equal(reply.coverage.reporting_peers,0);assert.ok(reply.flows.every(flow=>flow.rate_stale));
 state.privateTrafficError='demo temporary report failure';assert.throws(()=>handleDemoRequest(state,'GET','/api/private/traffic'),/temporary report failure/);
});
