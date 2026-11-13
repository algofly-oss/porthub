import { useEffect, useRef, useState } from 'react';
import { IconCopy, IconExternalLink } from '@tabler/icons-react';
import { Button } from '@/components/ui/button';
import { copyText } from '@/shared/utils/clipboard';
import toast from 'react-hot-toast';
import { useMantineColorScheme } from '@mantine/core';
export default function PairDrop(){
  const {colorScheme}=useMantineColorScheme();const frame=useRef(null);const initialTheme=useRef(colorScheme);
  useEffect(()=>{frame.current?.contentWindow?.postMessage({type:'porthub-theme',theme:colorScheme},window.location.origin);},[colorScheme]);
  const [url,setUrl]=useState('');useEffect(()=>setUrl(`${window.location.origin}/pairdrop/`),[]);
  return <div>
    <div className="mb-3 flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-muted-foreground">Send files between browsers. No account needed.</p><div className="flex max-w-full flex-wrap gap-2"><Button variant="secondary" size="sm" onClick={async()=>{try{await copyText(url);toast.success('PairDrop link copied');}catch{toast.error('Open PairDrop and copy its address.');}}}><IconCopy size={15}/>Copy public link</Button><Button asChild size="sm"><a href="/pairdrop/" target="_blank" rel="noopener noreferrer"><IconExternalLink size={15}/>Open PairDrop</a></Button></div></div>
    <iframe title="PairDrop file sharing" ref={frame} src={`/pairdrop/?theme=${initialTheme.current}`} className="h-[640px] max-h-[72dvh] w-full rounded-lg border border-border" allow="clipboard-write; fullscreen; screen-wake-lock"/>
  </div>;
}
