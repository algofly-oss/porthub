// Deterministic demo transport observations; never presented as live account data.
const windows = { '1h': [3600, 60], '24h': [86400, 900], '7d': [604800, 7200], '30d': [2592000, 86400] };
export function demoPrivateTraffic(machines, range = '1h', machine = 'all', now = Date.now(), options = {}) {
  const [duration, interval] = windows[range] || windows['1h'];
  if (!Object.hasOwn(windows, range)) range = '1h';
  const step = interval * 1000, end = Math.floor(now / step) * step, start = end - duration * 1000 + step;
  const peers = machines.slice(0, 4), base = [[0,1,'direct'],[1,0,'direct'],[0,2,'relay'],[2,0,'relay']];
  const definitions = peers.length >= 3 ? Array.from({length:options.demoDirections || 4},(_,i)=>base[i%base.length]) : [];
  const flows = definitions.map(([source,destination,carrier],direction)=>{
    const from=peers[source],to=peers[destination],missing=direction===3;
    const observed=Array.from({length:duration/interval},(_,index)=>{
      if(index%19>=14&&index%19<=16)return null;
      const bytes=(direction+1)*(index%7+1)*4096;
      return {at:start+index*step,direct_bytes:carrier==='direct'?bytes:0,relay_bytes:carrier==='relay'?bytes:0,sender_coverage_complete:direction!==2};
    }).filter(Boolean);
    // A receiver samples one bucket later. Its observations never enter sent
    // volume/history, even when no sender report exists for that bucket.
    const receiver_points=observed.filter(point=>point.at+step<=end).map(point=>({at:point.at+step,direct_received:point.direct_bytes,relay_received:point.relay_bytes}));
    const points=missing?[]:observed.filter((_,index)=>direction!==2||index!==1);
    const direct_bytes=points.reduce((sum,p)=>sum+p.direct_bytes,0),relay_bytes=points.reduce((sum,p)=>sum+p.relay_bytes,0);
    const received_direct_bytes=receiver_points.reduce((sum,p)=>sum+p.direct_received,0),received_relay_bytes=receiver_points.reduce((sum,p)=>sum+p.relay_received,0);
    return {source_peer_id:`demo-private-${from._id}${direction>3?`-${direction}`:''}`,destination_peer_id:`demo-private-${to._id}`,
      source_machine_id:from._id,destination_machine_id:to._id,source_name:`${from.name}${direction>3?` pair ${direction}`:''}`,destination_name:to.name,
      direct_bytes,relay_bytes,total_bytes:direct_bytes+relay_bytes,bytes_per_second:(direct_bytes+relay_bytes)/duration,
      received_direct_bytes,received_relay_bytes,received_total_bytes:received_direct_bytes+received_relay_bytes,
      recent_bytes_per_second:missing||options.stale?null:(direction+1)*1024,recent_interval_seconds:60,
      rate_at:missing||options.stale?null:now,rate_stale:missing||!!options.stale,latest_report_at:now,
      coverage:missing?'missing_sender':'sender_reported',sender_coverage_complete:direction!==2&&!missing,points,receiver_points};
  }).filter(flow=>machine==='all'||flow.source_machine_id===machine||flow.destination_machine_id===machine);
  const buckets=new Map();
  for(const flow of flows)for(const point of flow.points){const row=buckets.get(point.at)||{at:point.at,direct_sent:0,relay_sent:0,direct_received:0,relay_received:0};row.direct_sent+=point.direct_bytes;row.relay_sent+=point.relay_bytes;buckets.set(point.at,row);}
  for(const flow of flows)for(const point of flow.receiver_points){const row=buckets.get(point.at);if(row){row.direct_received+=point.direct_received;row.relay_received+=point.relay_received;}}
  const eligible=machine==='all'?peers.length:Number(peers.some(peer=>peer._id===machine));
  const reporting=machine==='all'?Math.min(3,peers.length):Number(peers.slice(0,3).some(peer=>peer._id===machine));
  const missing_sender_pairs=flows.filter(flow=>!flow.sender_coverage_complete).length;
  flows.sort((a,b)=>b.total_bytes-a.total_bytes||a.source_peer_id.localeCompare(b.source_peer_id));
  const totals=flows.reduce((sum,flow)=>({direct_bytes:sum.direct_bytes+flow.direct_bytes,relay_bytes:sum.relay_bytes+flow.relay_bytes,total_bytes:sum.total_bytes+flow.total_bytes,bytes_per_second:sum.bytes_per_second+flow.bytes_per_second}),{direct_bytes:0,relay_bytes:0,total_bytes:0,bytes_per_second:0});
  const search=(options.search||'').trim().toLocaleLowerCase(),matched=flows.filter(flow=>!search||[flow.source_name,flow.destination_name].some(name=>name.toLocaleLowerCase().includes(search))),page=options.page||1;
  const selected_flow=options.source_peer_id&&options.destination_peer_id?flows.find(flow=>flow.source_peer_id===options.source_peer_id&&flow.destination_peer_id===options.destination_peer_id)||null:null;
  return {range,start,end,interval_seconds:interval,scope:'private_peer_carrier_payload',totals,
    flows:matched.slice((page-1)*40,page*40).map(({points,receiver_points,...summary})=>summary),selected_flow,
    pagination:{page,page_size:40,total_pairs:flows.length,filtered_pairs:matched.length},points:[...buckets.values()].sort((a,b)=>a.at-b.at),
    coverage:{...(options.coverage||{reporting_peers:reporting,eligible_peers:eligible,unreported_peers:eligible-reporting,dropped_rows:2,history_incomplete:true}),missing_sender_pairs}};
}
