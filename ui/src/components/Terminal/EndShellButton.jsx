import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";

export default function EndShellButton({ machineId, workspaceId, name, onEnded }) {
  const [confirmEnd, setConfirmEnd] = useState(false);
  const [ending, setEnding] = useState(false);
  const [endError, setEndError] = useState("");
  async function terminateSession() {
    if (ending || !machineId || !workspaceId) return;
    setEnding(true);
    setEndError("");
    try {
      const response = await fetch(`/api/machines/${machineId}/terminal-sessions/${workspaceId}`, {
        method: "DELETE", credentials: "same-origin", signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) {
        const result = await response.json().catch(() => ({}));
        throw new Error(typeof result.detail === "string" ? result.detail : "Could not confirm that the shell ended.");
      }
      setConfirmEnd(false);
      onEnded?.();
    } catch (failure) {
      setEndError(failure.name === "TimeoutError" ? "Termination could not be confirmed. Check the session before retrying." : failure.message || "Could not reach the shell host.");
    } finally { setEnding(false); }
  }
  return <>
    <Button type="button" size="sm" variant="ghost" className="text-destructive"
      aria-label={name ? `End session ${name}` : "End session"}
      onClick={() => { setEndError(""); setConfirmEnd(true); }}>End session</Button>
    <Dialog opened={confirmEnd} onClose={() => { if (!ending) setConfirmEnd(false); }}
      title={`End ${name || "this shell session"}?`} size="sm" zIndex={450}
      closeOnEscape={!ending} closeOnClickOutside={!ending} withCloseButton={!ending}>
      <p className="text-sm">This stops the shell and its running tasks for everyone connected.</p>
      {endError && <p role="alert" className="mt-3 text-sm text-destructive">{endError}</p>}
      <div className="mt-5 flex justify-end gap-2">
        <Button data-autofocus type="button" size="sm" variant="secondary" disabled={ending} onClick={() => setConfirmEnd(false)}>Cancel</Button>
        <Button type="button" size="sm" variant="destructive" disabled={ending} onClick={terminateSession}>{ending ? "Ending…" : "End session"}</Button>
      </div>
    </Dialog>
  </>;
}
