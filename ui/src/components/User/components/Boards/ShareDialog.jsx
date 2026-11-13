import { useEffect, useState } from "react";
import axios from "axios";
import toast from "react-hot-toast";
import { Button } from "@/components/ui/button";
import ImageDialog from "../HostedImages/ImageDialog";
import { copyText } from "@/shared/utils/clipboard";
export function boardError(error) { return typeof error?.response?.data?.detail === "string" ? error.response.data.detail : "Could not reach PortHub. Please try again."; }
export default function ShareDialog({ board, onClose, onChange }) {
  const [current,setCurrent]=useState(board),[busy,setBusy]=useState(false);
  useEffect(()=>{if(!busy)setCurrent(board);},[board,busy]);
  const change=async(enabled,rotate=false)=>{
    const previous=current;
    setBusy(true);setCurrent(value=>({...value,sharing:{...value.sharing,enabled}}));
    try { const {data}=await axios.patch(`/api/boards/${board.id}/sharing`,{enabled,rotate});setCurrent(data);onChange?.(data); }
    catch(error){setCurrent(previous);toast.error(boardError(error));} finally{setBusy(false);}
  };
  const link=mode=>typeof window!=="undefined"&&current?.sharing?.[`${mode}_token`] ? `${window.location.origin}/board?id=${current.id}#share=${current.sharing[`${mode}_token`]}` : "";
  const copy=async mode=>{try{await copyText(link(mode));toast.success("Board link copied");}catch{toast.error("Select and copy the link below.");}};
  return <ImageDialog opened={!!board} onClose={onClose} title="Share board" size="lg">
    <p className="mb-4 text-sm text-muted-foreground">Enable sharing to create editing and view-only links. Guests need no account.</p>
    <label className="mb-4 flex min-h-11 items-center gap-3 text-sm"><input type="checkbox" checked={current?.sharing?.enabled||false} disabled={busy} onChange={event=>change(event.target.checked)} />Enable sharing links</label>
    {current?.sharing?.enabled&&current.sharing.edit_token&&<div className="space-y-4">{[["edit","Can edit"],["view","View only"]].map(([mode,label])=><div key={mode}><label htmlFor={`board-${mode}-link`} className="mb-1 block text-sm font-medium">{label}</label><div className="flex gap-2"><input id={`board-${mode}-link`} readOnly value={link(mode)} onFocus={event=>event.target.select()} className="min-w-0 flex-1 rounded-lg border border-input bg-control px-3 text-xs" /><Button variant="secondary" disabled={busy} onClick={()=>copy(mode)}>Copy link</Button></div></div>)}
    <Button variant="secondary" disabled={busy} onClick={()=>change(true,true)}>Regenerate both links</Button><p className="text-xs text-muted-foreground">Regenerating links immediately revokes both previous links.</p></div>}
  </ImageDialog>;
}
