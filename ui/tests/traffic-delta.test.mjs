import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeTrafficDelta } from '../src/shared/utils/traffic-delta.mjs';
test('overlapping traffic deltas replace counters and accept delayed seconds without duplication', () => {
  const merged = mergeTrafficDelta([{timestamp:100,in_bytes:10},{timestamp:102,in_bytes:20}], [{timestamp:101,in_bytes:15},{timestamp:102,in_bytes:25}]);
  assert.deepEqual(merged, [{timestamp:100,in_bytes:10},{timestamp:101,in_bytes:15},{timestamp:102,in_bytes:25}]);
  assert.equal(merged.reduce((sum,row) => sum + row.in_bytes,0),50);
});
test('retained history stays bounded while a new page starts without another page’s samples', () => {
  assert.deepEqual(mergeTrafficDelta([], [{timestamp:50,in_bytes:7}]), [{timestamp:50,in_bytes:7}]);
  assert.deepEqual(mergeTrafficDelta([{timestamp:1},{timestamp:2}], [{timestamp:3}], 2).map(row=>row.timestamp), [2,3]);
});

import { mergeTrafficPage, trafficRowCursors } from '../src/shared/utils/traffic-delta.mjs';
test('aggregate corrections can replace earlier partial seconds and remove expired buckets', () => {
  const current={rows:[],aggregate:[{timestamp:100,in_bytes:10},{timestamp:101,in_bytes:20}],scopeRevision:'a'};
  const next=mergeTrafficPage(current,{data:[],aggregate:[{timestamp:100,in_bytes:30},{timestamp:102,in_bytes:40}],aggregate_removed:[101],aggregate_token:'base',scope_revision:'a'},'test',1);
  assert.deepEqual(next.aggregate,[{timestamp:100,in_bytes:30},{timestamp:102,in_bytes:40}]);
  assert.equal(next.aggregateToken,'base');
});
test('scope changes and evicted delta bases cannot retain traffic from removed ports', () => {
  const current={rows:[{connection:{_id:'one'},traffic:[{timestamp:100,in_bytes:99}]}],aggregate:[{timestamp:100,in_bytes:99}]};
  const next=mergeTrafficPage(current,{reset:true,data:[{connection:{_id:'two'},traffic:[{timestamp:101,in_bytes:5}],replace:true,token:'new'}],aggregate:[{timestamp:101,in_bytes:5}],aggregate_replace:true},'test',1);
  assert.deepEqual(next.rows[0].traffic,[{timestamp:101,in_bytes:5}]);assert.deepEqual(next.aggregate,[{timestamp:101,in_bytes:5}]);
  assert.equal(trafficRowCursors(next.rows,true),'two:new');assert.equal(trafficRowCursors(next.rows),'two:101');
});
