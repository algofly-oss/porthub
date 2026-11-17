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

test('shared GPU limits remain separate from dedicated memory and missing usage', async () => {
  const {sharedGpuMemoryText,gpuMemorySummary}=await import('../src/lib/machineMetrics.mjs');
  const gpu={name:'Integrated test GPU',integrated:true,memory:{used:0,total:128*1024**2},shared_memory_capacity:8*1024**3};
  assert.equal(capacityPercent(gpu.shared_memory),null);
  assert.equal(sharedGpuMemoryText(gpu),'Up to 8.0 GB · usage unavailable');
  assert.match(gpuMemorySummary(gpu),/Integrated graphics/);
  assert.match(gpuMemorySummary(gpu),/0 B \/ 128.0 MB dedicated/);
  assert.match(gpuMemorySummary(gpu),/8.0 GB · usage unavailable shared/);
  gpu.shared_memory={used:256*1024**2,total:8*1024**3};
  assert.equal(capacityPercent(gpu.shared_memory),3.125);
  assert.equal(sharedGpuMemoryText(gpu),'256.0 MB / 8.0 GB max');
  assert.equal(gpuMemorySummary({name:'Legacy',memory:{used:1,total:2}}),'Legacy · 1 B / 2 B dedicated');
});

test('fresh explicit empty inventory keeps historical drives without current presence or risk',async()=>{
 const {driveInventoryView}=await import('../src/lib/machineMetrics.mjs');
 const now=1700000000000,old={id:'old',name:'Virtual Disk',present:true,status:'critical',observed_at:now-60000,checked_at:now-60000};
 const history=[{at:now-60000,snapshot:old}],before=JSON.stringify(history);
 const view=driveInventoryView({history,drives:[old],latest:[],reportedAt:now,enabled:true,now});
 assert.equal(view.authoritative,true);assert.equal(view.entries.length,1);assert.equal(view.entries[0].reportMembership,'historical');
 assert.equal(view.assessment.total,0);assert.equal(view.assessment.critical,0);assert.equal(view.assessment.risk,null);
 assert.equal(JSON.stringify(history),before);assert.equal(old.present,true);assert.equal(view.entries[0].observed_at,old.observed_at);
});
test('disabled missing and stale inventory leave presence unknown instead of inventing removal',async()=>{
 const {driveInventoryView}=await import('../src/lib/machineMetrics.mjs');const now=1700000000000;
 const old={id:'old',name:'Recorded SSD',present:true,status:'healthy',checked_at:now-1000};
 for(const context of [{latest:[],reportedAt:now,enabled:false},{reportedAt:now,enabled:true},{latest:[],enabled:true},{latest:[],reportedAt:now-45001,enabled:true},{latest:[],reportedAt:now,enabled:undefined}]){
  const view=driveInventoryView({history:[{at:now-1000,snapshot:old}],now,...context});
  assert.equal(view.authoritative,false);assert.equal(view.entries[0].reportMembership,'unknown');assert.equal(view.entries[0].status,'healthy');
  assert.equal(view.assessment.total,0);assert.equal(view.assessment.risk,null);assert(!view.entries.some(drive=>drive.status==='removed'));
  const pastRemoval=driveInventoryView({history:[{at:now-1000,snapshot:{...old,present:false,status:'removed'}}],now,...context});assert.equal(pastRemoval.entries[0].reportMembership,'unknown');assert.equal(pastRemoval.entries[0].status,'removed');
 }
});
test('current rejoin overrides past removal while real removed observations remain intact',async()=>{
 const {driveInventoryView}=await import('../src/lib/machineMetrics.mjs');const now=1700000000000;
 const removed={id:'same',name:'External SSD',present:false,status:'removed',observed_at:now-10000};
 const history=[{at:now-10000,snapshot:removed}];
 const absent=driveInventoryView({history,latest:[],reportedAt:now,enabled:true,now});assert.equal(absent.entries[0].reportMembership,'removed');assert.equal(absent.entries[0].observed_at,removed.observed_at);
 const rejoined={...removed,present:true,status:'healthy',checked_at:now,observed_at:now};
 const joined=driveInventoryView({history,latest:[rejoined],reportedAt:now,enabled:true,now});assert.equal(joined.entries[0].reportMembership,'current');assert.equal(joined.assessment.total,1);assert.equal(joined.assessment.risk,0);assert.equal(history[0].snapshot.present,false);
});
test('current assessment and ordering exclude historical warnings',async()=>{
 const {driveInventoryView}=await import('../src/lib/machineMetrics.mjs');const now=1700000000000;
 const old={id:'a',name:'A past drive',present:true,status:'critical',checked_at:now};const current={id:'z',name:'Z current drive',present:true,status:'healthy',checked_at:now};
 const view=driveInventoryView({history:[{at:now,snapshot:old}],latest:[current],reportedAt:now,enabled:true,now});
 assert.equal(view.entries[0].id,'z');assert.equal(view.assessment.total,1);assert.equal(view.assessment.critical,0);assert.equal(view.assessment.risk,0);
});

test('historical drive catalog survives narrowed queries and remains bounded',async()=>{
 const {driveCatalog}=await import('../src/lib/machineMetrics.mjs');
 const a={id:'a',name:'A',observed_at:1},b={id:'b',name:'B',observed_at:2};
 let catalog=driveCatalog([],[{snapshot:a},{snapshot:b}]);
 catalog=driveCatalog(catalog,[{snapshot:{...a,observed_at:3}}],[a]);
 assert.deepEqual(new Set(catalog.map(d=>d.id)),new Set(['a','b']));
 assert.equal(driveCatalog([],[],[{id:'new-host'}]).some(d=>d.id==='a'),false);
 assert.equal(driveCatalog([],[],Array.from({length:600},(_,i)=>({id:String(i),observed_at:i}))).length,512);
});

import {driveConditionSeries} from '../src/lib/machineMetrics.mjs';
test('all-drive condition series preserves identity, categorical transitions and unknown/removed gaps',()=>{
 const a={id:'a',name:'SSD'},b={id:'b',name:'HDD'},c={id:'c',name:'USB'};
 const point=(id,at,status,present=true)=>({at,snapshot:{id,status,present}});
 const rows=driveConditionSeries([point('a',1,'healthy'),point('b',1,'warning'),point('a',2,'warning'),point('a',3,'unavailable'),point('a',4,'critical'),point('b',2,'removed',false),point('b',3,'healthy'),point('c',1,'unavailable')],[a,b,c]);
 assert.deepEqual(rows[0].segments.map(s=>s.map(p=>p.value)),[[2,1],[0]]);
 assert.deepEqual(rows[1].segments.map(s=>s.map(p=>p.value)),[[1],[2]]);
 assert.deepEqual(rows[2].segments,[]);
 assert.deepEqual(rows.map(s=>s.drive.name),['SSD','HDD','USB']);
});
test('condition series never invents readings for absent drives or connects long reporting gaps',()=>{
 const day=86400000;
 assert.deepEqual(driveConditionSeries([],[{id:'a'}])[0].segments,[]);
 const history=[{at:1,snapshot:{id:'a',present:true,status:'healthy'}},{at:12*day,snapshot:{id:'a',present:true,status:'critical'}}];
 assert.equal(driveConditionSeries(history,[{id:'a'}])[0].segments.length,2);
});
