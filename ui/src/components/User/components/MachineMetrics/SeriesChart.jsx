import {useState} from 'react';
import {metricSegments} from '@/lib/machineMetrics.mjs';
const colors=['#60a5fa','#2dd4bf','#fbbf24','#fb7185','#c084fc','#fb923c'];
export default function SeriesChart({label,history,series,intervalMs}){
 const [index,setIndex]=useState(null);
 const first=history[0]?.at||0,last=history.at(-1)?.at||first+1;
 const point=index===null?history.at(-1):history[index];
 const x=at=>36+(at-first)/Math.max(1,last-first)*448;
 const y=value=>132-value*1.1;
 const available=series.some(s=>history.some(p=>s.read(p.sample)!==null));
 return <div className="min-w-0 rounded-lg bg-control/40 p-3"><h3 className="text-sm font-medium">{label}</h3><p className="mt-1 text-xs text-muted-foreground">{point?new Date(point.at).toLocaleString():'No reports yet'}</p>{available?<svg role="img" aria-label={`${label} history`} tabIndex={0} viewBox="0 0 520 160" className="mt-2 w-full touch-pan-y" onKeyDown={e=>{if(['ArrowLeft','ArrowRight'].includes(e.key)){e.preventDefault();setIndex(i=>Math.max(0,Math.min(history.length-1,(i??history.length-1)+(e.key==='ArrowLeft'?-1:1))));}}} onPointerMove={e=>{const box=e.currentTarget.getBoundingClientRect();const at=first+Math.max(0,Math.min(1,(e.clientX-box.left)/box.width))*(last-first);setIndex(history.reduce((best,p,i)=>Math.abs(p.at-at)<Math.abs(history[best].at-at)?i:best,0));}} onPointerLeave={()=>setIndex(null)}>
 {[0,50,100].map(n=><g key={n}><line x1="36" x2="484" y1={y(n)} y2={y(n)} stroke="currentColor" opacity=".1"/><text x="30" y={y(n)+3} textAnchor="end" fontSize="9" fill="currentColor">{n}%</text></g>)}
 {series.map((s,i)=>metricSegments(history,s.read,intervalMs).map((segment,j)=>segment.length===1?<circle key={`${i}:${j}`} cx={x(segment[0].at)} cy={y(s.scale?s.scale(segment[0].value):segment[0].value)} r="3" fill={colors[i%colors.length]}/>:<polyline key={`${i}:${j}`} points={segment.map(p=>`${x(p.at)},${y(s.scale?s.scale(p.value):p.value)}`).join(' ')} fill="none" stroke={colors[i%colors.length]} strokeWidth="2"/>))}
 {series.some(s=>s.scale)&&<text x="490" y="16" fill={colors[2]} fontSize="9">150°C</text>}
 </svg>:<p className="py-5 text-xs text-muted-foreground">No sensor readings in this period.</p>}
 <ul className="mt-2 space-y-2">{series.map((s,i)=><li key={s.id} className="flex items-start gap-2 text-xs"><span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{background:colors[i%colors.length]}}/><span className="min-w-0 flex-1 break-words text-muted-foreground">{s.label}</span><span className="text-right tabular-nums">{point?s.format(point.sample):'Unavailable'}</span></li>)}</ul><p className="mt-3 text-[11px] text-muted-foreground">Hover, tap or use arrow keys to inspect · Gaps indicate missing readings{series.some(s=>s.scale)?' · Temperature uses the right scale (0–150°C)':''}</p></div>;
}
