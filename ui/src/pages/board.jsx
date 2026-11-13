import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import dynamic from "next/dynamic";
const Editor=dynamic(()=>{window.EXCALIDRAW_ASSET_PATH="/excalidraw/";return import("@/components/User/components/Boards/Editor");},{ssr:false,loading:()=> <main className="flex h-[100dvh] items-center justify-center bg-background text-sm text-muted-foreground">Loading whiteboard…</main>});
export default function BoardPage(){
  const router=useRouter();const [share,setShare]=useState(null);
  useEffect(()=>{setShare(new URLSearchParams(window.location.hash.slice(1)).get("share")||"");},[router.asPath]);
  if(!router.isReady||share===null)return null;
  const id=router.query.id;
  if(typeof id!=="string"||!/^[a-f0-9]{32}$/.test(id))return <main className="flex h-[100dvh] items-center justify-center bg-background p-6 text-sm text-foreground"><p role="alert">This board link is invalid.</p></main>;
  return <Editor key={`${id}:${share}`} id={id} share={share}/>;
}
