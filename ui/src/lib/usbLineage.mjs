// Presentation only: use the owner's current inventory and explicit import link.
// Never infer a physical origin from a device name, serial or VID/PID alone.
export function usbLineage(machines, forwards, machineId, device) {
 const byId=new Map(machines.map(m=>[m.id,m]));
 const path=[machineId], seen=new Set(path), rules=new Set();
 let current=machineId, selected=device, imported=false;
 const unknown=()=>({imported:true,known:false,path:[...path].reverse(),origin:null});
 if(!device||!byId.has(current))return {imported:false,known:false,path,origin:null};
 for(let hop=0;hop<=4;hop++){
  const report=byId.get(current)?.report;
  if(!report)return imported||selected.busid?.startsWith('0-')?unknown():{imported:false,known:false,path:[...path].reverse(),origin:null};
  const links=(report?.imports||[]).filter(i=>i.busid===selected.busid);
  if(!links.length){
   if(selected.busid?.startsWith('0-')||/\(forwarded\)/i.test(selected.name||''))return unknown();
   return {imported,known:true,path:[...path].reverse(),origin:current};
  }
  imported=true;
  if(links.length!==1||hop===4)return unknown();
  const matches=forwards.filter(f=>f.id===links[0].upstream_id);
  if(matches.length!==1)return unknown();
  const parent=matches[0],d=parent.device;
  if(parent.destination!==current||!byId.has(parent.source)||seen.has(parent.source)||rules.has(parent.id)||!d||
     !['vendor','product','serial'].every(k=>typeof selected[k]==='string'&&selected[k]===d[k]))return unknown();
  rules.add(parent.id);seen.add(parent.source);path.push(parent.source);
  current=parent.source;selected=d;
 }
 return unknown();
}
export function usbOriginLabel(lineage,machines){
 if(!lineage.imported)return '';
 return lineage.known?`Forwarded from ${machines.find(m=>m.id===lineage.origin)?.name||'unknown source'}`:'Forwarded · original source unknown';
}
