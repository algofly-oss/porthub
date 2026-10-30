import { demoAccess } from "./access.mjs";
import { searchScore } from "../utils/search.mjs";
export function demoAccessInventory(state,kind,p,id) {
 const snapshot=demoAccess(state,"get","/access/snapshot",{},id);
 const size=Math.min(100,Math.max(1,Number(p.page_size)||25)),page=Math.max(1,Number(p.page)||1),q=p.q || "";
 const entities=[...snapshot.machines.map(m=>({_id:`machine:${m._id}`,kind:"machine",name:m.name})),...snapshot.groups.map(g=>({_id:`group:${g._id}`,kind:"group",name:g.name})),...snapshot.users.map(u=>({_id:`user:${u._id}`,kind:"user",name:u.name || u.email}))];
 const names=new Map(entities.map(e=>[e._id,e.name]));
 if(kind==="summary")return {data:{workspace_id:snapshot.workspace_id,workspace_name:"Demo Workspace",role:snapshot.role,network:snapshot.network,counts:{machines:snapshot.machines.length,groups:snapshot.groups.length,books:snapshot.books.length,people:snapshot.users.length,peers:snapshot.private_peers.length}}};
 let rows;
 if(kind==="books")rows=snapshot.books.filter(b=>(!p.group || p.group==="all" || b.group_id===p.group) && Number.isFinite(searchScore(q,[b.name,...b.rules.flatMap(r=>[r.name,...[...r.sources,...r.destinations].map(e=>names.get(`${e.kind}:${e.id}`))])]))).map(b=>({...b,group_name:snapshot.groups.find(g=>g._id===b.group_id)?.name,rules_count:b.rules.length,rules:p.detail==="true" ? b.rules : b.rules.slice(0,2)}));
 else if(kind==="entities")rows=entities.filter(e=>(!p.entity_types || p.entity_types.split(",").includes(e.kind)) && Number.isFinite(searchScore(q,[e.name,`${{machine:"Machine",group:"Group",user:"Person"}[e.kind]} · ${e.name}`])));
 else if(kind==="groups")rows=snapshot.groups.map(g=>({_id:g._id,name:g.name,machine_count:snapshot.machines.filter(m=>m.group_ids.includes(g._id)).length,user_count:g.user_ids.length,book_count:snapshot.books.filter(b=>b.group_id===g._id).length}));
 else if(kind==="machines")rows=snapshot.machines.map(m=>({_id:m._id,name:m.name,group_ids:m.group_ids,enabled:m.enabled,connection_status:m.connection_status,private_owner_id:m.private_owner_id,private_owner_revoked:m.private_owner_revoked,member:m.group_ids.includes(p.membership)}));
 else if(kind==="people")rows=snapshot.users.map(u=>({...u,member:snapshot.groups.find(g=>g._id===p.membership)?.user_ids.includes(u._id) || false}));
 else if(kind==="invitations")rows=snapshot.invitations;
 else if(kind==="peers")rows=snapshot.private_peers;
 else if(kind==="exits")rows=snapshot.exit_nodes || state.exitNodes || [];
 else if(kind==="proxy-grants")rows=snapshot.proxy_grants || [];
 else if(kind==="workspaces")rows=[{_id:snapshot.workspace_id,id:snapshot.workspace_id,name:"Demo Workspace",role:snapshot.role}];
 else rows=[];
 if(p.ids){const selected=new Set(p.ids.split(","));rows=rows.filter(row=>selected.has(row._id));}
 if(!["books","entities"].includes(kind))rows=rows.filter(row=>Number.isFinite(searchScore(q,[row.name,row.email,row.ip])));
 rows.sort((a,b)=>(a.name || a.email || "").localeCompare(b.name || b.email || "",undefined,{numeric:true}));
 const total=rows.length;rows=rows.slice((page-1)*size,page*size);
 const labels={};if(["books","exits"].includes(kind))for(const row of rows){const selectors=kind==="books" ? row.rules.flatMap(r=>[...r.sources,...r.destinations]) : [...(row.routing_selectors || []),...(row.distribution_selectors || [])];for(const e of selectors){const key=`${e.kind}:${e.id}`;if(names.has(key))labels[key]=names.get(key);}}
 return {data:rows,labels,role:snapshot.role,workspace_id:snapshot.workspace_id,can_allow_gateway_lan:state.user.role==="admin",pagination:{page,page_size:size,total,pages:Math.max(1,Math.ceil(total/size))}};
}
