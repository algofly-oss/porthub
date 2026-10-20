import { useEffect, useRef } from "react";
import { useRouter } from "next/router";

// A dashboard/deep-link command, not a persistent page filter. Consume it with
// replace so refresh, back/forward and later tab visits cannot replay it.
export default function useCreateFromUrl(view, onCreate, enabled = true) {
  const router = useRouter();
  const handled = useRef(false);
  const callback = useRef(onCreate);
  callback.current = onCreate;
  const requested = router.isReady && router.query.view === view && router.query.create === "1";
  useEffect(() => {
    if (!requested) { handled.current = false; return; }
    if (!enabled || handled.current) return;
    handled.current = true;
    callback.current();
    const query = { ...router.query };
    delete query.create;
    router.replace({ pathname: router.pathname, query }, undefined, { shallow: true, scroll: false }).catch(error => {
      // A deliberate navigation can cancel this cleanup; tab navigation also
      // discards page-specific parameters, so the command cannot leak there.
      if (!error.cancelled) console.error("Could not clear the create command", error);
    });
  }, [requested, enabled, router]);
}
