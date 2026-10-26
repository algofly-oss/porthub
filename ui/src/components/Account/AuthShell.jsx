import Link from "next/link";
import { IconBook2 } from "@tabler/icons-react";
import DarkThemeToggle from "../User/components/NavBar/components/DarkThemeToggle";

export function PortHubBrand({ light = false, compact = false }) {
  return <span className={`inline-flex items-center gap-2.5 text-lg font-semibold tracking-tight ${light ? "text-white" : "text-foreground"}`}><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-600"><img src="/favicon.svg" alt="" width="25" height="25" /></span><span className={compact ? "sr-only sm:not-sr-only" : ""}>PortHub</span></span>;
}

export default function AuthShell({ children }) {
  return <main className="flex h-screen h-[100dvh] flex-col overflow-hidden bg-background text-foreground">
    <header className="box-border flex shrink-0 items-center justify-end gap-4 px-5 pt-[env(safe-area-inset-top)] sm:px-8" style={{minHeight:"calc(4rem + env(safe-area-inset-top))"}}>
      <Link href="/guide" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><IconBook2 size={16} />User guide</Link>
      <DarkThemeToggle compact />
    </header>
    <section className="flex min-h-0 flex-1 items-center justify-center overflow-hidden px-6 py-4">
      <div className="w-full max-w-[400px]">{children}</div>
    </section>
  </main>;
}
