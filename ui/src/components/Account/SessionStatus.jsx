import { Button } from "@/components/ui/button";

export default function SessionStatus({ error, onRetry }) {
  return <main className="flex min-h-[100dvh] items-center justify-center bg-background px-6 text-foreground">
    <div className="max-w-sm space-y-4 text-center">
      <p role={error ? "alert" : "status"} className="text-sm text-muted-foreground">{error || "Restoring your session…"}</p>
      {error && <Button onClick={onRetry}>Try again</Button>}
    </div>
  </main>;
}
