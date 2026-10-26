import Head from "next/head";
import { copyText } from "@/shared/utils/clipboard";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/router";
import { Drawer } from "@mantine/core";
import { IconArrowLeft, IconArrowRight, IconBook2, IconCheck, IconChevronRight, IconCopy, IconInfoCircle, IconMenu2, IconSearch, IconX } from "@tabler/icons-react";
import { guideArticles, guideGroups } from "@/content/guide";
import { PortHubBrand } from "../Account/AuthShell";
import DarkThemeToggle from "../User/components/NavBar/components/DarkThemeToggle";

const hrefFor = slug => slug === "overview" ? "/guide" : `/guide/${slug}`;
const searchText = article => JSON.stringify([article.title, article.description, article.sections]).toLowerCase();
const searchIndex = guideArticles.map(article=>({article,text:searchText(article)}));
function Inline({ text }) { return String(text).split(/(`[^`]+`)/g).map((part,i)=>part.startsWith("`") ? <code key={i} className="rounded bg-muted px-1 py-0.5 text-[0.9em]">{part.slice(1,-1)}</code> : part); }
function CodeBlock({ text, label }) {
  const lines = String(text).split("\n").filter(line => line.trim());
  const commandCount = lines.filter(line => !line.trimStart().startsWith("#")).length;
  let commandIndex = 0;
  return <div className="my-5 overflow-hidden rounded-xl border border-border bg-muted/40 text-foreground">
    <div className="flex items-center justify-between border-b border-border px-4 py-2.5 text-[11px] text-muted-foreground"><span>{label || "Command"}</span><span>{commandCount > 1 ? `${commandCount} commands` : "Command"}</span></div>
    <div className="divide-y divide-border">
      {lines.map((line, i) => line.trimStart().startsWith("#")
        ? <div key={`comment-${i}`} className="flex items-start px-4 py-2 font-mono text-xs text-muted-foreground sm:text-[13px]"><pre className="m-0 whitespace-pre-wrap break-words">{line}</pre></div>
        : <CommandLine key={`${i}-${line}`} command={line} index={commandIndex++} multiple={commandCount > 1} />)}
    </div>
  </div>;
}
function CommandLine({ command, index, multiple }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef(null);
  useEffect(() => () => clearTimeout(timer.current), []);
  async function copy() {
    try {
      await copyText(command);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1800);
    } catch { setCopied(false); }
  }
  return <div className="flex min-w-0 items-start gap-3 px-4 py-2.5">
    <pre className="m-0 min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all py-1 font-mono text-xs leading-6 sm:text-[13px]"><code>{command}</code></pre>
    <button type="button" onClick={copy} aria-label={copied ? "Copied command" : `Copy command${multiple ? ` ${index + 1}` : ""}`} className="flex shrink-0 items-center gap-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground">{copied ? <IconCheck size={14}/> : <IconCopy size={14}/>}{copied ? "Copied" : "Copy"}</button>
  </div>;
}
function Block({block}) {
  if(block.type==="code")return <CodeBlock {...block}/>;
  if(block.type==="steps")return <ol className="my-5 space-y-4">{block.items.map((item,i)=><li key={i} className="flex gap-3 text-sm leading-7"><span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border bg-muted/50 text-[11px] font-medium">{i+1}</span><span><Inline text={item}/></span></li>)}</ol>;
  if(block.type==="note")return <aside className="my-6 flex items-start gap-3 rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 text-sm leading-7"><IconInfoCircle className="mt-1 shrink-0 text-primary" size={18}/><p><Inline text={block.text}/></p></aside>;
  if(block.type==="table")return <div className="my-6 overflow-x-auto rounded-xl border border-border"><table className="w-full text-left text-sm"><thead className="bg-muted/60 text-xs">{<tr>{block.columns.map(c=><th key={c} className="px-4 py-3 font-medium">{c}</th>)}</tr>}</thead><tbody>{block.rows.map((row,i)=><tr key={i} className="border-t border-border">{row.map((cell,j)=><td key={j} className={`px-4 py-3 align-top leading-6 ${j===0?"font-medium":"text-muted-foreground"}`}><Inline text={cell}/></td>)}</tr>)}</tbody></table></div>;
  return <p className="my-4 text-sm leading-7 text-muted-foreground"><Inline text={block.text}/></p>;
}
export default function Guide({slug="overview"}) {
  const router=useRouter(), [menu,setMenu]=useState(false), [query,setQuery]=useState("");
  const searchRef=useRef(null);
  const article=guideArticles.find(a=>a.slug===slug)||guideArticles[0];
  const index=guideArticles.indexOf(article), previous=guideArticles[index-1], next=guideArticles[index+1];
  const results=useMemo(()=>{
    const words=query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return words.length ? searchIndex.filter(({text})=>words.every(word=>text.includes(word))).map(({article})=>article).sort((a,b)=>Number(b.title.toLowerCase().includes(query.toLowerCase()))-Number(a.title.toLowerCase().includes(query.toLowerCase()))) : [];
  },[query]);
  useEffect(()=>{setMenu(false);setQuery("");},[router.asPath]);
  useEffect(()=>{
    const keydown=e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();if(window.innerWidth<1024)setMenu(true);else searchRef.current?.focus();}};
    window.addEventListener("keydown",keydown);return()=>window.removeEventListener("keydown",keydown);
  },[]);
  const navigation=(mobile=false)=><div className="flex h-full flex-col"><div className="compound-field mb-6 flex items-center gap-2 rounded-lg border border-border bg-background px-3"><IconSearch size={16} className="shrink-0 text-muted-foreground"/><input ref={mobile?undefined:searchRef} autoFocus={mobile} aria-label="Search user guide" placeholder="Search the guide…" value={query} onChange={e=>setQuery(e.target.value)} className="h-10 w-full min-w-0 border-0 bg-transparent p-0 text-sm outline-none placeholder:text-muted-foreground focus:ring-0"/>{query?<button aria-label="Clear guide search" onClick={()=>setQuery("")}><IconX size={14}/></button>:<kbd className="hidden shrink-0 text-[10px] text-muted-foreground lg:inline">⌘ K</kbd>}</div>
    <nav aria-label="Guide pages" className="flex-1 space-y-6 overflow-y-auto pb-8">{query.trim()?<div><p className="mb-3 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{results.length} matching pages</p>{results.length?results.map(a=><Link key={a.slug} href={hrefFor(a.slug)} className="mb-1 block rounded-lg px-3 py-2.5 hover:bg-accent"><span className="block text-sm font-medium">{a.title}</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">{a.description}</span></Link>):<p role="status" className="px-2 text-sm leading-6 text-muted-foreground">No matching pages. Try “private”, “resume” or a command name.</p>}</div>:guideGroups.map(group=><div key={group}><p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{group}</p><div className="space-y-0.5">{guideArticles.filter(a=>a.group===group).map(a=><Link key={a.slug} href={hrefFor(a.slug)} aria-current={slug===a.slug?"page":undefined} className={`flex min-h-[38px] items-center justify-between gap-2 rounded-lg px-3 py-2 text-[13px] transition-colors ${slug===a.slug?"bg-blue-500/10 font-medium text-primary":"text-muted-foreground hover:bg-accent/60 hover:text-foreground"}`}>{a.title}{slug===a.slug&&<IconChevronRight size={13}/>}</Link>)}</div></div>)}</nav>
    <div className="border-t border-border pt-4 text-[11px] leading-5 text-muted-foreground">Built into your gateway.<br />No external documentation service required.</div></div>;
  return <div className="min-h-screen min-h-[100dvh] bg-background text-foreground" style={{"--guide-header-height":"calc(4rem + env(safe-area-inset-top))"}}>
    <Head><title>{article.title} · PortHub Guide</title><meta name="description" content={article.description}/></Head>
    <a href="#guide-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded focus:bg-primary focus:p-3 focus:text-white">Skip to guide content</a>
    <header className="sticky top-0 z-30 flex h-[var(--guide-header-height)] items-center justify-between gap-3 border-b border-border bg-background/95 px-5 backdrop-blur-sm sm:px-8" style={{paddingTop:"env(safe-area-inset-top)"}}><div className="flex items-center gap-4"><Link href="/guide"><PortHubBrand compact/></Link><span className="hidden h-5 w-px bg-border sm:block"/><span className="hidden text-xs text-muted-foreground sm:block">User guide</span></div><div className="flex items-center gap-2 sm:gap-4"><DarkThemeToggle compact/><Link href="/home" className="rounded-lg border border-border px-3 py-2 text-xs font-medium hover:bg-accent">Open workspace<span className="ml-1 hidden sm:inline">↗</span></Link><button aria-label="Open guide navigation" aria-expanded={menu} onClick={()=>setMenu(true)} className="flex h-9 w-9 items-center justify-center rounded-lg hover:bg-accent lg:hidden"><IconMenu2 size={21}/></button></div></header>
    <div className="mx-auto flex max-w-[1480px]">
      <aside className="sticky top-[var(--guide-header-height)] hidden h-[calc(100dvh-var(--guide-header-height))] w-64 shrink-0 border-r border-border px-5 py-7 lg:block xl:w-72 xl:px-7">{navigation()}</aside>
      <Drawer opened={menu} onClose={()=>setMenu(false)} title="PortHub user guide" size={320} padding="lg" classNames={{content:"!bg-background !text-foreground",header:"!bg-background",body:"h-[calc(100dvh-80px)]"}}>{navigation(true)}</Drawer>
      <main id="guide-content" className="min-w-0 flex-1 px-5 py-8 sm:px-10 sm:py-12 xl:px-14"><article className="mx-auto max-w-[720px]">
        <nav aria-label="Breadcrumb" className="mb-7 flex items-center gap-2 text-[11px] text-muted-foreground"><Link href="/guide" className="hover:text-primary">Guide</Link><IconChevronRight size={12}/><span>{article.group}</span></nav>
        <h1 className="text-3xl font-semibold leading-tight tracking-[-0.035em] sm:text-[40px]">{article.title}</h1><p className="mt-4 text-base leading-7 text-muted-foreground">{article.description}</p>
        {slug==="overview"&&<div className="my-8 grid gap-3 sm:grid-cols-2">{[["getting-started","Connect your first machine","From install command to online."],["file-transfer","Move your first file","Built-in serving and transfers."]].map(([id,title,detail])=><Link key={id} href={hrefFor(id)} className="group rounded-xl border border-border bg-surface p-5 hover:border-blue-500/40"><IconBook2 size={21} className="mb-4 text-primary"/><p className="flex items-center justify-between text-sm font-medium">{title}<IconArrowRight size={15} className="text-muted-foreground group-hover:text-primary"/></p><p className="mt-2 text-xs text-muted-foreground">{detail}</p></Link>)}</div>}
        <div className="mt-9 border-t border-border pt-3">{article.sections.map(section=><section id={section.id} key={section.id} className="pb-4 pt-7" style={{scrollMarginTop:"calc(var(--guide-header-height) + 2rem)"}}><h2 className="text-xl font-semibold tracking-tight"><a href={`#${section.id}`} className="hover:text-primary">{section.title}</a></h2>{section.blocks.map((block,i)=><Block key={i} block={block}/>)}</section>)}</div>
        <footer className="mt-10 border-t border-border pt-7"><div className="grid gap-3 sm:grid-cols-2">{previous?<Link href={hrefFor(previous.slug)} className="rounded-xl border border-border p-4 hover:bg-accent/40"><span className="flex items-center gap-1.5 text-[11px] text-muted-foreground"><IconArrowLeft size={13}/>Previous</span><p className="mt-2 text-sm font-medium">{previous.title}</p></Link>:<span/>}{next&&<Link href={hrefFor(next.slug)} className="rounded-xl border border-border p-4 text-right hover:bg-accent/40"><span className="flex items-center justify-end gap-1.5 text-[11px] text-muted-foreground">Next<IconArrowRight size={13}/></span><p className="mt-2 text-sm font-medium">{next.title}</p></Link>}</div><p className="mt-7 text-[11px] leading-6 text-muted-foreground">Examples use the current native CLI. Run <code>porthub COMMAND --help</code> to see the flags supported by your installed version.</p></footer>
      </article></main>
      <aside aria-label="On this page" className="sticky top-[var(--guide-header-height)] hidden h-fit w-48 shrink-0 py-12 pr-6 xl:block"><p className="mb-4 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">On this page</p><nav className="space-y-3 border-l border-border pl-4">{article.sections.map(s=><a key={s.id} href={`#${s.id}`} className="block text-xs leading-5 text-muted-foreground hover:text-primary">{s.title}</a>)}</nav></aside>
    </div>
  </div>;
}
