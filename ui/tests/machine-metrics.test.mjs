import test from 'node:test';
import assert from 'node:assert/strict';
import { utilization, rankedMachines, metricSegments, diskDevices, diskReading, capacityPercent, memoryText, gpuDevices, gpuReading } from '../src/lib/machineMetrics.mjs';
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

test('GPU history prefers current identities and joins only unambiguous older readings',()=>{
 const older={gpus:[{name:'GPU',utilization:30}]},latest={gpus:[{id:'gpu-a',name:'GPU',utilization:80,temperature:60}]};
 const devices=gpuDevices([{at:0,sample:older}],latest);assert.equal(devices.length,1);assert.equal(devices[0].id,'gpu-a');
 assert.equal(gpuReading(older,'gpu-a','GPU',devices[0].allowLegacy).utilization,30);
 const multiple={gpus:[...latest.gpus,{id:'gpu-b',name:'GPU',utilization:20}]};
 const ambiguous=gpuDevices([{at:0,sample:older}],multiple);assert.equal(ambiguous[0].id,'gpu-a');assert.equal(ambiguous[0].allowLegacy,false);
 assert.equal(gpuReading(older,'gpu-a','GPU',false),null);
});

test('physical-drive assessment uses the worst finding and never hides incomplete SMART coverage',async()=>{
 const {driveAssessment}=await import('../src/lib/machineMetrics.mjs');const at=Date.now();
 const good={id:'good',present:true,status:'healthy',checked_at:at};
 assert.equal(driveAssessment({drive_health:[good]},at).score,100);
 const partial=driveAssessment({drive_health:[good,{id:'unknown',present:true,status:'unavailable'}]},at);
 assert.equal(partial.risk,null);assert.equal(partial.incomplete,true);assert.equal(partial.checked,1);
 const bad=driveAssessment({drive_health:[good,{...good,id:'failing',status:'critical'}]},at);
 assert.equal(bad.score,0);assert.equal(bad.risk,100);assert.equal(bad.critical,1);
 assert.equal(driveAssessment({drive_health:[{...good,present:false,status:'removed'}]},at).score,null);
 assert.equal(driveAssessment({drive_health:[{...good,checked_at:at-76*60*1000}]},at).risk,null);
});
test('drive-health ranking prioritizes a critical drive and puts unknown coverage after known assessments',async()=>{
 const at=Date.now(),snapshot=status=>({drive_health:[{present:true,status,checked_at:at}]});
 const machines=['healthy','critical','unavailable','warning'].map((status,i)=>({id:String(i),name:status,live:true,reading:{sample:snapshot(status)}}));
 assert.deepEqual(rankedMachines(machines,['health']).map(m=>m.name),['critical','warning','healthy','unavailable']);
 assert.deepEqual(rankedMachines(machines,['health'],true).map(m=>m.name),['healthy','warning','critical','unavailable']);
 assert.equal(utilization({cpu:0,cpu_available:false},'cpu'),null);
});

test('unmounted physical drive keeps identity but shows unavailable capacity and chart gap', () => {
 const unavailable={disks:[{id:'mac-physical:a',name:'External drive',used:0,total:0}],disk:{used:0,total:0}};
 assert.equal(memoryText(diskReading(unavailable,'mac-physical:a')),'Unavailable');
 assert.equal(capacityPercent(diskReading(unavailable,'mac-physical:a')),null);
 assert.equal(utilization(unavailable,'disk'),null);
 assert.deepEqual(metricSegments([{at:1,sample:unavailable}],s=>capacityPercent(diskReading(s,'mac-physical:a'))),[]);
 assert.equal(memoryText({used:1024,total:2048}),'1.0 KB / 2.0 KB');
 assert.equal(diskDevices([],unavailable)[0].name,'External drive');
});
