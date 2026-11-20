import Head from "next/head";
import { useRouter } from "next/router";
import SharedTerminal from "@/components/Terminal/SharedTerminal";

export default function TerminalPage() {
  const router = useRouter();
  const { machine, workspace } = router.query;
  const dashboard = /^[a-f0-9]{24}$/.test(machine) && /^[a-f0-9]{32}$/.test(workspace);
  return <><Head><title>Shared Terminal · PortHub</title><meta name="referrer" content="no-referrer" /><meta name="robots" content="noindex,nofollow" /></Head>{router.isReady && <SharedTerminal machineId={dashboard ? machine : null} workspaceId={dashboard ? workspace : null} />}</>;
}
