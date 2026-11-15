import test from 'node:test';
import assert from 'node:assert/strict';
import { utilization, rankedMachines, metricSegments, diskDevices, diskReading, capacityPercent } from '../src/lib/machineMetrics.mjs';
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

test('drive histories combine mounted partitions by capacity and retain disconnect gaps',()=>{
 const sample={disks:[{id:'/dev/nvme0n1p1',name:'boot',used:1,total:100},{id:'/dev/nvme0n1p2',name:'root',used:200,total:900},{id:'/dev/sda1',name:'SSD',used:20,total:100}]};
 assert.deepEqual(diskDevices([{at:0,sample}],sample).map(d=>d.id),['/dev/nvme0n1','/dev/sda']);
 assert.deepEqual(diskReading(sample,'/dev/nvme0n1'),{used:201,total:1000});
 assert.equal(capacityPercent(diskReading(sample,'/dev/nvme0n1')),20.1);
 assert.equal(diskReading({disks:[]},'/dev/sda'),null);
 assert.deepEqual(diskDevices([],{disks:[{id:'Macintosh HD',name:'Macintosh HD',used:1,total:10}]}),[{id:'Macintosh HD',name:'Macintosh HD'}]);
});
