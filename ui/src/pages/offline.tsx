import Head from "next/head";
import { IconWifiOff, IconRefresh } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";

export default function OfflinePage() {
  return <main className="flex min-h-[100dvh] items-center justify-center bg-background px-5 py-8 text-foreground">
    <Head><title>Offline | PortHub</title></Head>
    <section className="w-full max-w-md rounded-xl bg-surface p-6 sm:p-8">
      <span className="mb-5 inline-flex h-12 w-12 items-center justify-center rounded-xl bg-control text-muted-foreground"><IconWifiOff size={25} /></span>
      <h1 className="text-2xl font-semibold tracking-tight">You’re Offline</h1>
      <p className="mt-3 text-sm leading-6 text-muted-foreground">PortHub needs a connection to load live machines, proxies, and traffic. Your server settings have not changed.</p>
      <p className="mt-3 text-sm leading-6 text-muted-foreground">Reconnect to your network, then return to your workspace.</p>
      <Button type="button" className="mt-6" onClick={() => location.assign("/home")}><IconRefresh size={16} />Try Again</Button>
    </section>
  </main>;
}
