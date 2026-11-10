import { useEffect, useMemo, useState } from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import Gallery from "@/components/User/components/HostedImages/Gallery";
import { imageRoomVisitor } from "@/shared/utils/image-room-visitor";

export default function ImageDropRoom() {
  const router = useRouter();
  const [visitor, setVisitor] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    try { setVisitor(imageRoomVisitor()); }
    catch { setError("This browser cannot create a secure upload identity. Try another browser."); }
  }, []);
  const headers = useMemo(() => visitor ? { "x-image-visitor": visitor.id } : {}, [visitor]);
  const room = typeof router.query.room === "string" && /^[a-f0-9]{32}$/.test(router.query.room) ? router.query.room : null;
  return <main className="flex h-[100dvh] min-h-0 flex-col bg-background text-foreground">
    <Head><title>Image drop · PortHub</title><meta name="robots" content="noindex,nofollow" /><meta name="referrer" content="no-referrer" /></Head>
    <div className="mx-auto w-full max-w-[1600px] shrink-0 border-b border-border px-3 py-3 text-sm font-semibold sm:px-5">PortHub <span className="ml-2 text-xs font-normal text-muted-foreground">Public image drop · No account needed</span></div>
    {error ? <p role="alert" className="p-6 text-sm text-red-500">{error}</p> : !router.isReady || !visitor ? <p className="p-6 text-sm text-muted-foreground">Opening room…</p> : !room ? <p role="alert" className="p-6 text-sm text-muted-foreground">This room link is invalid.</p> : <div className="min-h-0 flex-1"><Gallery key={room} endpoint={`/api/image-rooms/public/${room}/images`} requestHeaders={headers} roomMode /></div>}
    {visitor && <p className="mx-auto w-full max-w-[1600px] shrink-0 px-3 pb-3 text-xs text-muted-foreground sm:px-5">{visitor.durable ? "Keep this browser’s storage to retain deletion access to your uploads." : "Browser storage is unavailable. You can delete your uploads only during this session."}</p>}
  </main>;
}
