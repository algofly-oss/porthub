export function portDraftChanges(originals,drafts,equal) {
 const before=new Map(originals.filter(p=>p.dataId).map(p=>[p.dataId,p]));
 const after=new Set(drafts.filter(p=>p.dataId).map(p=>p.dataId));
 return {
  deleted: originals.filter(p=>p.dataId && !p.temporary && !after.has(p.dataId)),
  created: drafts.filter(p=>!p.dataId && !p.temporary),
  updated: drafts.filter(p=>p.dataId && !p.temporary && before.has(p.dataId) && !equal(before.get(p.dataId),p)),
 };
}
