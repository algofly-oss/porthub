import { useState } from "react";
import axios from "axios";
import { IconCheck, IconCopy, IconEye, IconEyeOff, IconKey, IconTrash, IconUserPlus } from "@tabler/icons-react";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import apiRoutes from "@/shared/routes/apiRoutes";
import { copyText } from "@/shared/utils/clipboard";

const inputClass="mt-1.5 h-11 w-full rounded-lg border border-input bg-control px-3 text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-blue-500 focus:ring-2 focus:ring-blue-500/[0.15]";
function message(error,fallback) {
  const detail=error?.response?.data?.detail;
  return typeof detail==="string"?detail:Array.isArray(detail)?detail.map(item=>item.msg||item.message||"Invalid input").join(". "):fallback;
}
export function CreateUser({onChanged}) {
  const [opened,setOpened]=useState(false), [values,setValues]=useState({name:"",email:"",password:""});
  const [visible,setVisible]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(""),[created,setCreated]=useState(false),[copied,setCopied]=useState(false);
  function close(){if(busy)return;setOpened(false);setValues({name:"",email:"",password:""});setCreated(false);setError("");setVisible(false);setCopied(false);}
  function generate(){
    const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%+-";
    const bytes=new Uint8Array(24);crypto.getRandomValues(bytes);
    setValues(v=>({...v,password:Array.from(bytes,b=>alphabet[b%alphabet.length]).join("")}));
    setVisible(true);
  }
  async function submit(event){
    event.preventDefault();if(busy||created)return;
    setBusy(true);setError("");
    try{await axios.post(apiRoutes.adminUsers,values);setCreated(true);onChanged();}
    catch(err){setError(message(err,"Could not create account."));}
    finally{setBusy(false);}
  }
  async function copy(){try{await copyText(`Email: ${values.email.trim().toLowerCase()}\nPassword: ${values.password}`);setCopied(true);}catch{setError("Copy is unavailable. Select and copy the credentials manually.");}}
  return <>
    <Button onClick={()=>setOpened(true)}><IconUserPlus size={16}/><span>Create user</span></Button>
    <Dialog opened={opened} onClose={close} closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy} title={created?"Account created":"Create user"} size="md">
      {created?<div><div className="mb-5 flex gap-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4"><IconCheck size={20} className="shrink-0 text-emerald-600"/><p className="text-sm leading-6">The account is ready. Share these credentials through a trusted channel. They are cleared from this dialog when you close it.</p></div><dl className="rounded-lg border border-border bg-surface p-4 text-sm"><dt className="text-xs text-muted-foreground">Email</dt><dd className="mt-1 break-all font-medium">{values.email.trim().toLowerCase()}</dd><dt className="mt-4 text-xs text-muted-foreground">Initial password</dt><dd className="mt-1 flex items-center justify-between gap-2"><code className="break-all">{visible?values.password:"•".repeat(16)}</code><button type="button" aria-label={visible?"Hide password":"Show password"} onClick={()=>setVisible(v=>!v)} className="rounded p-2 hover:bg-accent">{visible?<IconEyeOff size={17}/>:<IconEye size={17}/>}</button></dd></dl>{error&&<p role="alert" className="mt-3 text-sm text-red-600">{error}</p>}<div className="mt-5 flex flex-wrap justify-end gap-2"><Button variant="outline" onClick={copy}>{copied?<IconCheck size={16}/>:<IconCopy size={16}/>} {copied?"Copied":"Copy credentials"}</Button><Button onClick={close}>Done</Button></div></div>:<form onSubmit={submit} className="space-y-4">
        <p className="text-sm leading-6 text-muted-foreground">Create a member account directly. Public signups can remain disabled. Creating an account does not sign you out.</p>
        <label className="block text-xs font-medium">Display name<input required maxLength={100} autoComplete="off" autoFocus className={inputClass} value={values.name} onChange={e=>setValues(v=>({...v,name:e.target.value}))} placeholder="e.g. Alex Morgan"/></label>
        <label className="block text-xs font-medium">Email<input required type="email" maxLength={254} autoComplete="off" className={inputClass} value={values.email} onChange={e=>setValues(v=>({...v,email:e.target.value}))} placeholder="alex@example.com"/></label>
        <div><div className="flex items-center justify-between gap-2"><label htmlFor="new-account-password" className="text-xs font-medium">Initial password</label><button type="button" onClick={generate} className="inline-flex items-center gap-1 text-xs font-medium text-primary"><IconKey size={13}/>Generate password</button></div><div className="relative"><input id="new-account-password" required minLength={8} maxLength={72} type={visible?"text":"password"} autoComplete="new-password" className={`${inputClass} pr-11`} value={values.password} onChange={e=>setValues(v=>({...v,password:e.target.value}))} placeholder="At least 8 characters"/><button type="button" onClick={()=>setVisible(v=>!v)} aria-label={visible?"Hide password":"Show password"} className="absolute right-1 top-2 rounded p-2 text-muted-foreground hover:bg-accent">{visible?<IconEyeOff size={17}/>:<IconEye size={17}/>}</button></div><p className="mt-1.5 text-[11px] text-muted-foreground">Stored as a password hash. Existing passwords cannot be retrieved later.</p></div>
        {error&&<p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <div className="flex justify-end gap-2 border-t border-border pt-4"><Button type="button" variant="outline" disabled={busy} onClick={close}>Cancel</Button><Button type="submit" disabled={busy}>{busy?"Creating…":"Create account"}</Button></div>
      </form>}
    </Dialog>
  </>;
}
export function DeleteUser({entry,onChanged,currentEmail}) {
  const [opened,setOpened]=useState(false),[confirmation,setConfirmation]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const email=entry.user.email||"",own=email.toLowerCase()===String(currentEmail||"").toLowerCase();
  const ports=entry.port_count ?? (entry.machines || []).reduce((total,machine)=>total+(machine.ports?.length||0),0);
  function close(){if(!busy){setOpened(false);setConfirmation("");setError("");}}
  async function remove(){
    if(busy||confirmation.trim().toLowerCase()!==email.toLowerCase())return;
    setBusy(true);setError("");
    try{await axios.delete(`${apiRoutes.adminUsers}/${encodeURIComponent(entry.user.id)}`,{data:{confirm_email:confirmation}});setOpened(false);setConfirmation("");onChanged();}
    catch(err){setError(message(err,"Could not delete account. Please try again."));onChanged();}
    finally{setBusy(false);}
  }
  return <><Button type="button" variant="ghost" size="icon" disabled={own} title={own?"Manage your own account in Settings":entry.user.deleting?"Retry account cleanup":"Delete account"} aria-label={`Delete account ${email}`} onClick={event=>{event.stopPropagation();setOpened(true);}} className="text-muted-foreground hover:bg-red-500/10 hover:text-red-600"><IconTrash size={16}/></Button>
    <Dialog opened={opened} onClose={close} closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy} title={entry.user.deleting?"Complete account deletion":"Delete account?"} size="md">
      <p className="text-sm leading-6">Permanently delete <strong className="break-all">{email}</strong> and its PortHub resources? This cannot be undone.</p>
      <div className="my-5 grid grid-cols-2 gap-3 rounded-lg border border-red-500/20 bg-red-500/5 p-4"><div><p className="text-xl font-semibold">{entry.machine_count ?? entry.machines?.length ?? 0}</p><p className="text-xs text-muted-foreground">Machine registrations</p></div><div><p className="text-xl font-semibold">{ports}</p><p className="text-xs text-muted-foreground">Public mappings</p></div></div>
      <p className="text-xs leading-6 text-muted-foreground">This also removes the account’s proxies, groups, private peers, access rules, invitations, membership records, sessions and saved settings. Connected clients lose access. Files stored on their computers are not deleted.</p>
      <label className="mt-5 block text-xs font-medium">Type {email} to confirm<input className={inputClass} autoComplete="off" value={confirmation} onChange={event=>setConfirmation(event.target.value)} placeholder="Account email"/></label>
      {error&&<p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="mt-5 flex justify-end gap-2 border-t border-border pt-4"><Button variant="outline" disabled={busy} onClick={close}>Cancel</Button><Button variant="destructive" disabled={busy||confirmation.trim().toLowerCase()!==email.toLowerCase()} onClick={remove}>{busy?"Deleting…":"Delete account"}</Button></div>
    </Dialog>
  </>;
}
