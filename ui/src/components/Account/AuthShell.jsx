import Link from "next/link";
import { IconArrowUpRight, IconBook2, IconBrandGithub, IconRoute, IconServer, IconWorld } from "@tabler/icons-react";
import DarkThemeToggle from "../User/components/NavBar/components/DarkThemeToggle";

export function PortHubBrand({ light = false, compact = false }) {
  return <span className={`inline-flex items-center gap-2.5 text-lg font-semibold tracking-tight ${light ? "text-white" : "text-foreground"}`}><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-600"><img src="/favicon.svg" alt="" width="25" height="25" /></span><span className={compact ? "sr-only sm:not-sr-only" : ""}>PortHub</span></span>;
}

export default function AuthShell({ children }) {
  return <main className="grid min-h-screen min-h-[100dvh] bg-background text-foreground lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
    <section aria-label="About PortHub" className="relative hidden min-h-screen min-h-[100dvh] flex-col overflow-hidden bg-[#101c36] p-10 text-white lg:flex xl:p-14">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 opacity-30" style={{ backgroundImage: "radial-gradient(ellipse at 75% 45%, #2563eb 0%, transparent 60%), radial-gradient(circle, #8fa8da 1px, transparent 1px)", backgroundSize: "100% 100%, 28px 28px" }} />
      <div className="relative"><PortHubBrand light /></div>
      <div className="relative mx-auto flex w-full max-w-xl flex-1 flex-col justify-center py-14">
        <p className="mb-5 text-xs font-medium uppercase tracking-[0.2em] text-blue-200">Your infrastructure, connected</p>
        <h1 className="max-w-lg text-[clamp(2.4rem,3.5vw,3.8rem)] font-semibold leading-[1.1] tracking-[-0.045em]">Every machine.<br />One place to connect.</h1>
        <p className="mt-6 max-w-md text-base leading-7 text-slate-300">Bring your machines, services and files together. Publish a port, connect privately, or move a dataset—all from one workspace.</p>
        <div className="relative my-10 rounded-2xl border border-white/[0.15] bg-[#142340]/90 p-6 shadow-2xl shadow-black/[0.15]">
          <div className="mb-8 flex items-center justify-between text-[11px] text-slate-300"><span className="flex items-center gap-2"><IconRoute size={15} />A connected workspace</span><span className="rounded-full border border-blue-300/20 px-2 py-1 text-blue-200">Private + public</span></div>
          <div className="relative grid grid-cols-3 gap-3 pb-4">
            <svg aria-hidden="true" className="absolute left-0 top-5 h-20 w-full text-blue-400/70" preserveAspectRatio="none" viewBox="0 0 300 80"><path d="M50 0 V35 Q50 45 65 45 H235 Q250 45 250 35 V0 M150 0 V75" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 5" /></svg>
            {[[IconServer,"Your workstation"],[IconServer,"Remote machine"],[IconWorld,"Your services"]].map(([Icon,label])=><div key={label} className="relative flex flex-col items-center gap-3 text-center"><span className="flex h-11 w-11 items-center justify-center rounded-xl border border-blue-300/25 bg-[#1c3359] text-blue-200"><Icon size={21} stroke={1.5} /></span><span className="text-[11px] text-slate-300">{label}</span></div>)}
          </div>
          <div className="relative mx-auto mt-2 flex w-fit items-center gap-2 rounded-lg border border-blue-300/30 bg-blue-500/[0.15] px-5 py-3 text-sm font-medium"><img src="/favicon.svg" alt="" width="20" height="20" />PortHub</div>
          <div className="mt-6 rounded-lg border border-white/10 bg-[#0c172b] px-4 py-3 font-mono text-xs text-blue-100"><span className="mr-2 select-none text-blue-400">$</span>porthub push ./data http://node.phub:8001/</div>
        </div>
        <div className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-slate-300"><span>Private networking</span><span>Public port mapping</span><span>Built-in transfers</span></div>
      </div>
      <div className="relative flex items-center justify-between gap-4 border-t border-white/10 pt-5 text-xs text-slate-400"><span>Self-hosted. Built around your machines.</span><a href="https://github.com/algofly-oss/porthub" target="_blank" rel="noreferrer" aria-label="PortHub on GitHub" className="flex items-center gap-1.5 text-slate-300 hover:text-white"><IconBrandGithub size={16} />GitHub<IconArrowUpRight size={13} /></a></div>
    </section>
    <section className="flex min-w-0 flex-col px-6 pb-[max(1.5rem,env(safe-area-inset-bottom))] pt-[max(1.5rem,env(safe-area-inset-top))] sm:px-10 lg:px-14">
      <header className="flex min-h-10 items-center justify-between gap-4"><Link href="/" className="lg:hidden"><PortHubBrand /></Link><div className="ml-auto flex items-center gap-3"><Link href="/guide" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><IconBook2 size={16} />User guide</Link><DarkThemeToggle compact /></div></header>
      <div className="mx-auto flex w-full max-w-[400px] flex-1 flex-col justify-center py-12 sm:py-16">{children}</div>
      <footer className="mx-auto flex w-full max-w-[400px] items-center justify-between gap-3 border-t border-border pt-5 text-[11px] text-muted-foreground"><span>Your gateway. Your workspace.</span><Link href="/guide/getting-started" className="hover:text-foreground">New to PortHub? Start here →</Link></footer>
    </section>
  </main>;
}
