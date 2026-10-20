import { useEffect, useState } from "react";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import SearchSelect from "@/components/ui/search-select";

const initialForm = {name:"",hostname:"",groupId:""};
export default function MachineCreateModal({opened,onClose,onCreate,isCreating,groups=[]}) {
  const [form,setForm] = useState(initialForm);
  const [error,setError] = useState("");
  useEffect(()=>{if(!opened){setForm(initialForm);setError("");}},[opened]);
  async function submit(event) {
    event.preventDefault();
    if(!form.name.trim()){setError("Machine name is required");return;}
    const created = await onCreate({name:form.name.trim(),hostname:form.hostname.trim(),group_ids:form.groupId ? [form.groupId] : []});
    if(created){setForm(initialForm);setError("");}
  }
  return <WorkspaceDrawer opened={opened} onClose={onClose} title="Create Machine" size="lg" fixedHeight="min(560px, calc(100dvh - 64px))" closeOnClickOutside={!isCreating} closeOnEscape={!isCreating}>
    <form onSubmit={submit} className="flex h-full min-h-0 flex-1 flex-col">
      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto pb-5">
        <p className="text-sm leading-6 text-muted-foreground">Name your machine, then install its client. IP addresses and connection details appear automatically when it connects.</p>
        <label htmlFor="machine-name" className="block text-sm font-medium">Machine name<Input id="machine-name" className="mt-2" placeholder="e.g. edge-node-1" value={form.name} onChange={event=>setForm(current=>({...current,name:event.target.value}))} required aria-invalid={!!error} />{error && <span className="mt-1 block text-xs text-red-500">{error}</span>}</label>
        <label htmlFor="machine-hostname" className="block text-sm font-medium">Hostname <span className="font-normal text-muted-foreground">(optional)</span><Input id="machine-hostname" className="mt-2" placeholder="Reported by the client when left empty" value={form.hostname} onChange={event=>setForm(current=>({...current,hostname:event.target.value}))} /></label>
        <div><label htmlFor="machine-group" className="mb-2 block text-sm font-medium">Group <span className="font-normal text-muted-foreground">(optional)</span></label><SearchSelect id="machine-group" label="Machine group" value={form.groupId} onChange={value=>setForm(current=>({...current,groupId:value}))} options={[{value:"",label:"Ungrouped"},...groups.map(group=>({value:group._id,label:group.name}))]} /></div>
      </div>
      <div className="flex shrink-0 justify-end gap-2 border-t border-border pt-4"><Button type="button" variant="secondary" onClick={onClose} disabled={isCreating}>Cancel</Button><Button type="submit" disabled={isCreating}>{isCreating ? "Creating…" : "Create Machine"}</Button></div>
    </form>
  </WorkspaceDrawer>;
}
