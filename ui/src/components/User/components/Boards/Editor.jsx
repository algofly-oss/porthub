import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import Head from "next/head";
import axios from "axios";
import { io } from "socket.io-client";
import { Excalidraw, exportToBlob, CaptureUpdateAction, reconcileElements, MainMenu, WelcomeScreen } from "@excalidraw/excalidraw";
import { useMantineColorScheme } from "@mantine/core";
import { IconArrowLeft, IconShare, IconMoon, IconSun } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import ShareDialog, { boardError } from "./ShareDialog";

const key = element => `${element.version}:${element.versionNonce}`;
const newer = (a,b) => !b || a.version>b.version || a.version===b.version && a.versionNonce<b.versionNonce;
async function fileId(file) {
  if (crypto.subtle) {
    const digest=await crypto.subtle.digest("SHA-256",await file.arrayBuffer());
    return Array.from(new Uint8Array(digest),byte=>byte.toString(16).padStart(2,"0")).join("");
  }
  return Array.from(crypto.getRandomValues(new Uint8Array(20)),byte=>byte.toString(16).padStart(2,"0")).join("");
}

async function imagePayload(file) {
  const match=/^data:image\/(png|jpeg|webp|gif);base64,(.+)$/s.exec(file.dataURL);
  if(match)return match[2];
  if(!file.dataURL.startsWith("data:image/svg+xml"))throw new Error("This image format cannot be saved to the board.");
  const image=new Image();image.src=file.dataURL;await image.decode();
  if(!image.naturalWidth||!image.naturalHeight||image.naturalWidth*image.naturalHeight>32*1024*1024)throw new Error("Board images must be within 32 megapixels.");
  const canvas=document.createElement("canvas");canvas.width=image.naturalWidth;canvas.height=image.naturalHeight;
  canvas.getContext("2d").drawImage(image,0,0);
  return canvas.toDataURL("image/png").split(",")[1];
}
export default function Editor({ id, share }) {
  const router=useRouter(); const {colorScheme,toggleColorScheme}=useMantineColorScheme();
  const [meta,setMeta]=useState(null),[error,setError]=useState(""),[saveState,setSaveState]=useState("Opening board…"),[connected,setConnected]=useState(false),[sharing,setSharing]=useState(false),[api,setApi]=useState(null),[people,setPeople]=useState(1);
  const apiRef=useRef(null),metaRef=useRef(null),initial=useRef(null),server=useRef(new Map()),pending=useRef(new Map()),shown=useRef(new Map()),files=useRef({}),uploaded=useRef(new Set()),fetchingFiles=useRef(new Set());
  const alive=useRef(true),inFlight=useRef(false),timer=useRef(null),flushRef=useRef(null),bg=useRef("#ffffff"),pendingBg=useRef(null),revision=useRef(-1),socket=useRef(null),pointerAt=useRef(0);
  const previewBusy=useRef(false),previewRevision=useRef(-1);
  const headers=useRef(share?{"x-board-share":share}:{});
  const endpoint=`/api/boards/${id}`;
  useEffect(()=>{
    if(!api)return;
    const root=document.getElementById("board-canvas");if(!root)return;
    // Excalidraw 0.18's built-in menu trigger has no accessible name.
    const labelMenu=()=>{const menu=root.querySelector(".main-menu-trigger");if(menu&&!menu.hasAttribute("aria-label"))menu.setAttribute("aria-label","Board menu");};
    labelMenu();const observer=new MutationObserver(labelMenu);observer.observe(root,{childList:true,subtree:true});
    return()=>observer.disconnect();
  },[api]);
  useEffect(()=>{if(error)socket.current?.disconnect();},[error]);
  metaRef.current=meta;
  const loadAssets=useCallback(async elements=>{
    const required=[...new Set(elements.filter(e=>e.type==="image"&&!e.isDeleted&&e.fileId).map(e=>e.fileId))];
    for(let i=0;i<required.length;i+=4) await Promise.all(required.slice(i,i+4).map(async file=>{
      if(apiRef.current?.getFiles()?.[file]||fetchingFiles.current.has(file))return;
      fetchingFiles.current.add(file);
      try{const {data}=await axios.get(`${endpoint}/assets/${encodeURIComponent(file)}`,{headers:headers.current});if(alive.current){uploaded.current.add(file);apiRef.current?.addFiles([data]);}}
      catch(error){if(alive.current)setSaveState(`Image unavailable: ${boardError(error)}`);}finally{fetchingFiles.current.delete(file);}
    }));
  },[endpoint]);
  const ingest=useCallback(data=>{
    if(!alive.current)return;
    for(const element of data.elements||[])if(newer(element,server.current.get(element.id)))server.current.set(element.id,element);
    const fresh=data.revision>=revision.current;
    if(fresh){revision.current=data.revision; if(data.appState?.viewBackgroundColor)bg.current=data.appState.viewBackgroundColor;}
    const editor=apiRef.current;
    if(editor){
      const merged=reconcileElements(editor.getSceneElementsIncludingDeleted(),[...server.current.values()],editor.getAppState());
      shown.current=new Map(merged.map(e=>[e.id,e]));
      editor.updateScene({elements:merged,...(fresh&&!pendingBg.current?{appState:{viewBackgroundColor:bg.current}}:{}),captureUpdate:CaptureUpdateAction.NEVER});
      void loadAssets(merged);
    }
    if(data.name)setMeta(previous=>({...previous,...data}));
  },[loadAssets]);
  const refresh=useCallback(async()=>{
    const {data}=await axios.get(endpoint,{headers:headers.current});
    if(alive.current){ingest(data);return data;}
  },[endpoint,ingest]);
  const schedule=useCallback((delay=220)=>{window.clearTimeout(timer.current);timer.current=window.setTimeout(()=>flushRef.current?.(),delay);},[]);
  flushRef.current=async()=>{
    if(inFlight.current||!metaRef.current?.editable||!alive.current||error)return;
    if(!pending.current.size&&!pendingBg.current)return;
    inFlight.current=true;setSaveState("Saving…");
    const batch=[...pending.current.values()],background=pendingBg.current;let retry=true;
    try{
      for(const element of batch){
        if(element.type!=="image"||element.isDeleted||!element.fileId||uploaded.current.has(element.fileId))continue;
        const file=files.current[element.fileId];if(!file)throw new Error("Wait for the image to finish loading before saving.");
        const image=await imagePayload(file);
        await axios.put(`${endpoint}/assets/${encodeURIComponent(element.fileId)}`,{image},{headers:headers.current,timeout:300000});
        uploaded.current.add(element.fileId);
      }
      const {data}=await axios.patch(`${endpoint}/scene`,{elements:batch,...(background?{app_state:{viewBackgroundColor:background}}:{})},{headers:headers.current,timeout:60000});
      if(!alive.current)return;
      for(const element of batch)if(key(pending.current.get(element.id)||{})===key(element))pending.current.delete(element.id);
      if(pendingBg.current===background)pendingBg.current=null;
      ingest(data);
      setSaveState(pending.current.size||pendingBg.current?"Saving…":"All changes saved");
    }catch(error){
      retry=!!error.isAxiosError&&(!error.response||error.response.status>=500||[409,429].includes(error.response.status));
      if(alive.current){setSaveState(`Not saved · ${error.response?boardError(error):error.message||"Reconnect to save"}`);
        if([400,403,404].includes(error.response?.status)){try{await refresh();}catch{setError("This board is unavailable or its sharing link has been disabled.");}}
      }
    }finally{inFlight.current=false;if(retry&&alive.current&&(pending.current.size||pendingBg.current))schedule(2500);}
  };
  useEffect(()=>{
    alive.current=true;
    const open=async()=>{
      try{const {data}=await axios.get(endpoint,{headers:headers.current});if(!alive.current)return;
        revision.current=data.revision;bg.current=data.appState?.viewBackgroundColor||"#ffffff";
        server.current=new Map(data.elements.map(e=>[e.id,e]));shown.current=new Map(server.current);
        initial.current={elements:data.elements,appState:{viewBackgroundColor:bg.current},scrollToContent:true};
        setMeta(data);setSaveState(data.editable?"All changes saved":"View only");
      }catch(error){if(alive.current)setError(boardError(error));}
    };void open();
    const unload=event=>{if(pending.current.size||pendingBg.current||inFlight.current){event.preventDefault();event.returnValue="";}};
    window.addEventListener("beforeunload",unload);
    return()=>{alive.current=false;window.clearTimeout(timer.current);window.removeEventListener("beforeunload",unload);};
  },[endpoint]);
  useEffect(()=>{
    if(!api)return;
    apiRef.current=api;void loadAssets([...server.current.values()]);
    const name=(()=>{try{let name=sessionStorage.getItem("porthub.boardGuest");if(!name){name=`Guest ${crypto.getRandomValues(new Uint32Array(1))[0].toString(36).slice(0,4)}`;sessionStorage.setItem("porthub.boardGuest",name);}return name;}catch{return "Guest";}})();
    const wire=io("/boards",{path:"/socket.io",transports:["websocket"],forceNew:true,auth:{board:id,share:share||"",name}});socket.current=wire;
    const synchronize=async()=>{try{await refresh();if(pending.current.size||pendingBg.current)schedule(0);}catch(error){if([400,403,404].includes(error.response?.status))setError("This board is unavailable or its sharing link has been disabled.");}};
    wire.on("ready",()=>{setConnected(true);void synchronize();});
    wire.on("scene",ingest);wire.on("changed",()=>void synchronize());
    wire.on("presence",peers=>{
      setPeople(peers.length);
      const collaborators=new Map(peers.filter(p=>p.id!==wire.id).map(p=>[p.id,{username:p.name||"Guest",pointer:p.pointer||undefined,color:{background:"#dbeafe",stroke:"#2563eb"}}]));
      api.updateScene({collaborators,captureUpdate:CaptureUpdateAction.NEVER});
    });
    wire.on("disconnect",reason=>{setConnected(false);if(reason==="io server disconnect")void synchronize();});
    wire.on("connect_error",()=>{setConnected(false);void synchronize();});
    const poll=window.setInterval(()=>{void synchronize();},30000);
    return()=>{window.clearInterval(poll);wire.disconnect();socket.current=null;};
  },[api,id,share,ingest,loadAssets,refresh,schedule]);
  useEffect(()=>{
    if(!api||!meta?.editable)return;
    const update=async()=>{
      const current=revision.current;
      if(!alive.current||previewBusy.current||inFlight.current||pending.current.size||pendingBg.current||fetchingFiles.current.size||previewRevision.current===current)return;
      const elements=api.getSceneElements();
      if(!elements.length)return;
      if(elements.some(e=>e.type==="image"&&e.fileId&&!api.getFiles()[e.fileId]))return;
      previewBusy.current=true;
      try{
        const blob=await exportToBlob({elements,files:api.getFiles(),appState:{...api.getAppState(),exportBackground:true,exportWithDarkMode:false,exportEmbedScene:false},maxWidthOrHeight:320,mimeType:"image/png"});
        if(!alive.current||current!==revision.current||pending.current.size)return;
        const image=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(",")[1]);reader.onerror=reject;reader.readAsDataURL(blob);});
        await axios.put(`${endpoint}/preview`,{revision:current,image},{headers:headers.current});
        previewRevision.current=current;
      }catch{/* A thumbnail must never interrupt saving the board. */}finally{previewBusy.current=false;}
    };
    const interval=setInterval(update,1600);return()=>clearInterval(interval);
  },[api,meta?.editable,endpoint]);
  const change=(elements,state,currentFiles)=>{
    files.current=currentFiles;
    if(!metaRef.current?.editable||error)return;
    const ids=new Set(elements.map(e=>e.id)),all=[...elements];
    for(const [id,previous]of shown.current)if(!ids.has(id)&&!previous.isDeleted){const element={...previous,isDeleted:true,version:previous.version+1,versionNonce:crypto.getRandomValues(new Uint32Array(1))[0]};all.push(element);}
    shown.current=new Map(all.map(e=>[e.id,e]));
    for(const element of all)if(key(element)!==key(server.current.get(element.id)||{}))pending.current.set(element.id,element);
    if(state.viewBackgroundColor&&state.viewBackgroundColor!==bg.current)pendingBg.current=state.viewBackgroundColor;
    if(pending.current.size||pendingBg.current){setSaveState("Saving…");schedule();}
  };
  const pointer=data=>{if(Date.now()-pointerAt.current<100||!socket.current?.connected)return;pointerAt.current=Date.now();socket.current.emit("pointer",data.pointer||data);};
  const back=async()=>{await flushRef.current?.();if(pending.current.size||pendingBg.current||inFlight.current){setSaveState("Changes are not saved yet. Reconnect before leaving this board.");return;}router.push("/home?view=boards");};
  return <main className="porthub-board flex h-[100dvh] min-h-0 flex-col overflow-hidden bg-background text-foreground">
    <Head><title>{meta?.name||"Board"} · PortHub</title><meta name="robots" content="noindex,nofollow"/><meta name="referrer" content="no-referrer"/></Head>
    <a href="#board-canvas" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-3">Skip to whiteboard</a>
    <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border px-2 sm:px-4">
      {meta?.owner&&<Button variant="ghost" size="icon" aria-label="Back to boards" disabled={inFlight.current} onClick={back}><IconArrowLeft size={19}/></Button>}
      <div className="min-w-0 flex-1"><h1 className="truncate text-sm font-semibold">{meta?.name||"PortHub board"}</h1><p className="truncate text-xs text-muted-foreground" role="status">{saveState}{meta&&!error?` · ${connected?`${people} online`:"Reconnecting…"}`:""}</p></div>
      <Button variant="ghost" size="icon" aria-label="Toggle color theme" onClick={()=>toggleColorScheme()}>{colorScheme==="dark"?<IconSun size={18}/>:<IconMoon size={18}/>}</Button>
      {meta?.owner&&<Button size="sm" onClick={()=>setSharing(true)}><IconShare size={16}/>Share</Button>}
    </header>
    {error?<div className="flex flex-1 items-center justify-center p-6"><p role="alert" className="max-w-lg text-center text-sm text-muted-foreground">{error}</p></div>:!meta?<div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">Opening board…</div>:<div id="board-canvas" className="min-h-0 flex-1" aria-label="Collaborative whiteboard"><Excalidraw excalidrawAPI={setApi} initialData={initial.current} onChange={change} onPointerUpdate={pointer} viewModeEnabled={!meta.editable} isCollaborating={connected} theme={colorScheme} name={meta.name} validateEmbeddable={false} generateIdForFile={fileId} UIOptions={{canvasActions:{saveToActiveFile:false,toggleTheme:false}}}>
        <MainMenu>{meta.editable&&<MainMenu.DefaultItems.LoadScene/>}<MainMenu.DefaultItems.Export/><MainMenu.DefaultItems.SaveAsImage/><MainMenu.Separator/><MainMenu.DefaultItems.SearchMenu/><MainMenu.DefaultItems.Help/>{meta.editable&&<><MainMenu.Separator/><MainMenu.DefaultItems.ClearCanvas/><MainMenu.DefaultItems.ChangeCanvasBackground/></>}</MainMenu>
        <WelcomeScreen><WelcomeScreen.Hints.ToolbarHint/><WelcomeScreen.Hints.HelpHint/><WelcomeScreen.Center><WelcomeScreen.Center.Logo><span className="text-2xl font-semibold text-foreground">PortHub</span></WelcomeScreen.Center.Logo><WelcomeScreen.Center.Heading>{meta.editable?"Draw together. Your board saves automatically.":"Nothing drawn on this board yet."}</WelcomeScreen.Center.Heading>{meta.editable&&<WelcomeScreen.Center.Menu><WelcomeScreen.Center.MenuItemLoadScene/><WelcomeScreen.Center.MenuItemHelp/></WelcomeScreen.Center.Menu>}</WelcomeScreen.Center></WelcomeScreen>
      </Excalidraw></div>}
    {sharing&&meta?.owner&&<ShareDialog board={meta} onClose={()=>setSharing(false)} onChange={data=>setMeta(previous=>({...previous,...data}))}/>}
  </main>;
}
