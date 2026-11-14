import test from 'node:test';
import assert from 'node:assert/strict';
import { utilization, rankedMachines, metricSegments } from '../src/lib/machineMetrics.mjs';
const sample = (cpu, gpu = null) => ({ cpu, ram: { used: 4, total: 8 }, disk: { used: 25, total: 100 }, gpus: gpu === null ? [] : [{ utilization: gpu }] });
test('resource percentages normalize capacity and preserve unsupported GPU', () => {
  assert.equal(utilization(sample(10), 'ram'), 50);
  assert.equal(utilization(sample(10), 'disk'), 25);
  assert.equal(utilization(sample(10), 'gpu'), null);
  assert.equal(utilization({ ...sample(10), gpus: [{utilization: 10}, {utilization: 50}] }, 'gpu'), 30);
  assert.equal(utilization(sample(NaN), 'cpu'), null);
});
test('ranking combines resources, excludes stale hosts, and puts missing readings last', () => {
  const machines = [
    {id:'a',name:'A',live:true,reading:{sample:sample(80, 0)}},
    {id:'b',name:'B',live:true,reading:{sample:sample(40, 90)}},
    {id:'c',name:'C',live:true,reading:{sample:sample(90)}},
    {id:'d',name:'D',live:false,reading:{sample:sample(100, 100)}},
  ];
  assert.deepEqual(rankedMachines(machines, ['cpu']).map(m => m.id), ['c','a','b']);
  assert.deepEqual(rankedMachines(machines, ['cpu','gpu']).map(m => m.id), ['b','a','c']);
  assert.deepEqual(rankedMachines(machines, ['cpu','gpu'], true).map(m => m.id), ['a','b','c']);
  assert.equal(rankedMachines(machines, ['cpu','gpu'])[0].score, 65);
});
test('history gaps are never interpolated as idle usage', () => {
  const points = [0,60000,240000,300000].map(at => ({at, sample:sample(20)}));
  assert.deepEqual(metricSegments(points, 'cpu').map(s => s.length), [2,2]);
  assert.equal(metricSegments(points, 'gpu').length, 0);
  assert.equal(metricSegments(points, 'cpu', 240000).length, 1);
});
