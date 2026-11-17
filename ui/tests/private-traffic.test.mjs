import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizePrivateTraffic, privateTrafficTotals, privateTrafficWindow, privateFlowKey, privateRanges, privateTrafficRequest, privateTrafficForRequest } from '../src/shared/utils/private-traffic.mjs';
function fixture(range='1h') {
 const step=privateRanges[range]*1000,seconds={'1h':3600,'24h':86400,'7d':604800,'30d':2592000}[range],end=Math.floor(1800000000000/step)*step,start=end-seconds*1000+step;
 const flow={source_peer_id:'workspace:source',destination_peer_id:'workspace:destination',source_machine_id:'a'.repeat(24),destination_machine_id:'b'.repeat(24),source_name:'Luna',destination_name:'Miro',direct_bytes:100,relay_bytes:20,total_bytes:120,bytes_per_second:120/seconds,recent_bytes_per_second:null,recent_interval_seconds:60,rate_at:null,rate_stale:true,latest_report_at:end,coverage:'receiver_only'};
 return {scope:'private_peer_carrier_payload',range,start,end,interval_seconds:step/1000,coverage:{reporting_peers:1,eligible_peers:2,unreported_peers:1,dropped_rows:0,history_incomplete:false},points:[{at:start,direct_sent:100,relay_sent:20,direct_received:100,relay_received:20}],flows:[flow],totals:{direct_bytes:100,relay_bytes:20,total_bytes:120,bytes_per_second:120/seconds},pagination:{page:1,page_size:40,total_pairs:1,filtered_pairs:1},selected_flow:null};
}
function select(input) {input.selected_flow={...input.flows[0],points:[{at:input.start,direct_bytes:100,relay_bytes:20}]};return input;}
test('all ranges preserve aligned inclusive bucket windows',()=>{for(const range of Object.keys(privateRanges)){const data=normalizePrivateTraffic(fixture(range));assert.equal(privateTrafficWindow(data).length,{'1h':60,'24h':96,'7d':84,'30d':30}[range]);}});
test('full aggregate totals do not depend on page or filtered summaries',()=>{
 const input=fixture();input.flows=[];input.pagination={page:2,page_size:40,total_pairs:1000,filtered_pairs:0};const data=normalizePrivateTraffic(input);assert.equal(data.totals.total_bytes,120);assert.equal(data.flows.length,0);assert.equal(privateTrafficWindow(data)[0].direct,100);
});
test('summary polling rejects embedded per-pair histories',()=>{const input=fixture();input.flows[0].points=[];assert.throws(()=>normalizePrivateTraffic(input));});
test('canonical sent volume excludes informational overlapping RX',()=>{const data=normalizePrivateTraffic(fixture());assert.equal(data.totals.total_bytes,120);assert.deepEqual(privateTrafficWindow(data)[0],{at:data.start,direct:100,relay:20});});
test('sparse gaps stay null and explicit zero remains observed',()=>{const input=select(fixture());input.points.push({at:input.start+120000,direct_sent:0,relay_sent:0,direct_received:0,relay_received:0});const data=normalizePrivateTraffic(input);assert.equal(privateTrafficWindow(data)[1].direct,null);assert.equal(privateTrafficWindow(data)[2].direct,0);const rows=privateTrafficWindow(data,data.selected_flow);assert.equal(rows[0].coverage,'receiver_only');assert.equal(rows[1].direct,null);});
test('selected history sums and aggregate totals are validated independently of page',()=>{
 const data=normalizePrivateTraffic(select(fixture()));assert.equal(data.selected_flow.total_bytes,120);
 for(const change of [x=>x.selected_flow.points[0].direct_bytes=99,x=>x.totals.total_bytes=121,x=>x.points[0].direct_sent=99,x=>x.selected_flow.points.push({...x.selected_flow.points[0]})]){const bad=select(fixture());change(bad);assert.throws(()=>normalizePrivateTraffic(bad));}
});
test('historical volume and explicit overflow survive zero current coverage',()=>{const input=fixture();input.coverage={reporting_peers:0,eligible_peers:2,unreported_peers:2,dropped_rows:136,history_incomplete:true};const data=normalizePrivateTraffic(input);assert.equal(data.totals.total_bytes,120);assert.equal(data.coverage.dropped_rows,136);input.coverage.history_incomplete=false;assert.throws(()=>normalizePrivateTraffic(input));});
test('recent rate uses actual observed duration and stale flags, not upload time',()=>{
 const input=fixture('24h');Object.assign(input.flows[0],{recent_bytes_per_second:4,recent_interval_seconds:30,rate_at:input.end,rate_stale:false,latest_report_at:input.end+1000});assert.equal(normalizePrivateTraffic(input).flows[0].recent_interval_seconds,30);
 input.flows[0].recent_interval_seconds=120;assert.equal(normalizePrivateTraffic(input).flows[0].recent_interval_seconds,120);
 for(const change of [x=>x.rate_at=null,x=>x.rate_stale=true,x=>x.recent_interval_seconds=121,x=>x.recent_bytes_per_second=Infinity]){const bad=structuredClone(input);change(bad.flows[0]);assert.throws(()=>normalizePrivateTraffic(bad));}
});
test('malformed counters, identities, bounds and duplicate summaries are rejected',()=>{
 for(const change of [x=>x.flows[0].source_machine_id='wrong',x=>x.flows[0].source_name='',x=>x.flows[0].total_bytes=-1,x=>{x.flows.push({...x.flows[0]});x.pagination.total_pairs=2;x.pagination.filtered_pairs=2;},x=>x.points[0].at++,x=>x.coverage.unreported_peers=0,x=>x.pagination.page_size=50,x=>x.pagination.filtered_pairs=2,x=>x.end+=60000]){const bad=fixture();change(bad);assert.throws(()=>normalizePrivateTraffic(bad));}
});
test('request keys encode server paging/search and demand-bound selected history',()=>{
 const plain=privateTrafficRequest({range:'1h',page:2,search:'Luna & Miro'}),url=new URL(plain.key,'https://fixture.invalid');assert.equal(url.searchParams.get('page'),'2');assert.equal(url.searchParams.get('search'),'Luna & Miro');assert.equal(url.searchParams.has('source_peer_id'),false);
 const selected=fixture().flows[0],pair=privateTrafficRequest({range:'1h',page:2,search:'Luna & Miro',selected});assert.equal(pair.listKey,plain.listKey);assert.equal(new URL(pair.key,'https://fixture.invalid').searchParams.get('source_peer_id'),selected.source_peer_id);assert.notEqual(privateFlowKey(selected),privateFlowKey({...selected,source_peer_id:selected.destination_peer_id,destination_peer_id:selected.source_peer_id}));
 for(const request of [{range:'1h',page:0},{range:'1h',search:'x'.repeat(129)}])assert.throws(()=>privateTrafficRequest(request));
});
test('response fences reject wrong range/page/machine/selected pair',()=>{
 const input=normalizePrivateTraffic(select(fixture())),request={range:'1h',page:1,machine:'all',selected:input.flows[0]};assert.equal(privateTrafficForRequest(input,request),input);
 for(const change of [r=>r.page=2,r=>r.range='24h',r=>r.machine='c'.repeat(24),r=>r.selected=null,r=>r.selected={...r.selected,source_peer_id:'foreign'}]){const bad={...request};change(bad);assert.throws(()=>privateTrafficForRequest(input,bad));}
});
test('account and pair rows sort without mutating response',()=>{const input=fixture();input.points.push({...input.points[0],at:input.start+60000,direct_sent:0,relay_sent:0});input.points.reverse();const before=JSON.stringify(input);assert.equal(normalizePrivateTraffic(input).points[0].at,input.start);assert.equal(JSON.stringify(input),before);});
