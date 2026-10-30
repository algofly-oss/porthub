import useInventoryPage from "@/shared/hooks/useInventoryPage";
import useTrafficPage from "@/shared/hooks/useTrafficPage";
import TrafficMonitorPanel from "@/components/User/components/Home/components/Host/TrafficMonitorPanel";
import useAuth from "@/shared/hooks/useAuth";
import apiRoutes from "@/shared/routes/apiRoutes";
import uiRoutes from "@/shared/routes/uiRoutes";
import { Alert, Loader, useMantineColorScheme } from "@mantine/core";
import axios from "axios";
import Head from "next/head";
import { useRouter } from "next/router";
import { useEffect, useMemo, useRef, useState } from "react";

type TrafficSample = {
  timestamp?: number;
  in_bytes?: number;
  out_bytes?: number;
  drop_bytes?: number;
  blocked_ips?: string[];
  incoming_ips?: string[];
  outgoing_ips?: string[];
};

type ConnectionDetails = {
  _id?: string;
  machine_id?: string;
  machine_name?: string;
  machine_hostname?: string;
  machine_local_ip?: string;
  service_name?: string;
  service_description?: string;
  internal_ip?: string;
  internal_port?: number;
  external_port?: number;
};

export default function TrafficMonitorPage() {
  const auth = useAuth();
  const router = useRouter();
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const dataId = typeof router.query.data_id === "string" ? router.query.data_id : "";
  const hostName = typeof router.query.host === "string" ? router.query.host : "";
  const hostDescription =
    typeof router.query.description === "string" ? router.query.description : "";
  const localIp =
    typeof router.query.local_ip === "string" ? router.query.local_ip : "";
  const serviceName = typeof router.query.service === "string" ? router.query.service : "";
  const externalPort =
    typeof router.query.external_port === "string" ? router.query.external_port : "";
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const details=useInventoryPage("connections",{ids:dataId,page_size:1},{enabled:!isCheckingAuth && !!dataId});
  const traffic=useTrafficPage({ids:dataId,page_size:1,seconds:300,expanded:dataId},{enabled:!isCheckingAuth && !!dataId});
  const connectionDetails:ConnectionDetails | null=details.rows[0] || null;
  const samples:TrafficSample[]=useMemo(()=>traffic.rows[0]?.traffic || [],[traffic.rows]);
  const isLoading=!!dataId && traffic.loading;
  const loadError=traffic.error || details.error;

  const checkAccount=useRef(auth.getAccountInfo);
  const navigation=useRef(router);
  navigation.current=router;
  useEffect(() => {
    let isActive = true;

    const checkAuth = async () => {
      const account = await checkAccount.current();
      if (!isActive) {
        return;
      }

      if (!account?.role) {
        navigation.current.replace(uiRoutes.signIn);
        return;
      }

      setIsCheckingAuth(false);
    };

    checkAuth();

    return () => {
      isActive = false;
    };
  }, []);

  const resolvedMachineName = useMemo(
    () =>
      connectionDetails?.machine_name ||
      hostName ||
      connectionDetails?.machine_hostname ||
      "Unknown machine",
    [connectionDetails, hostName]
  );

  const resolvedMachineDescription = useMemo(
    () => hostDescription || connectionDetails?.machine_hostname || "",
    [connectionDetails, hostDescription]
  );

  const resolvedLocalIp = useMemo(
    () => connectionDetails?.machine_local_ip || localIp || "",
    [connectionDetails, localIp]
  );

  const activeConnection = connectionDetails;

  const resolvedServiceName = useMemo(
    () => activeConnection?.service_name || serviceName || "",
    [activeConnection, serviceName]
  );

  const resolvedServiceDescription = useMemo(
    () => activeConnection?.service_description || "",
    [activeConnection]
  );

  const resolvedExternalPort = useMemo(
    () =>
      activeConnection?.external_port !== undefined && activeConnection?.external_port !== null
        ? String(activeConnection.external_port)
        : externalPort,
    [activeConnection, externalPort]
  );

  const resolvedInternalIp = useMemo(
    () => activeConnection?.internal_ip || "",
    [activeConnection]
  );

  const resolvedInternalPort = useMemo(
    () =>
      activeConnection?.internal_port !== undefined &&
      activeConnection?.internal_port !== null
        ? String(activeConnection.internal_port)
        : "",
    [activeConnection]
  );
  const pageTitleActivityPrefix = useMemo(() => {
    const now = Math.floor(Date.now() / 1000);
    const recentSamples = (Array.isArray(samples) ? samples : []).filter(
      (sample) => Number(sample?.timestamp) >= now - 3
    );

    const hasRecentBlocked = recentSamples.some(
      (sample) => Math.max(0, Number(sample?.drop_bytes) || 0) > 0
    );
    if (hasRecentBlocked) {
      return "[BLOCKED]";
    }

    const hasRecentIncoming = recentSamples.some(
      (sample) => Math.max(0, Number(sample?.in_bytes) || 0) > 0
    );
    const hasRecentOutgoing = recentSamples.some(
      (sample) => Math.max(0, Number(sample?.out_bytes) || 0) > 0
    );

    if (hasRecentIncoming && hasRecentOutgoing) {
      return "[LIVE]";
    }

    if (hasRecentIncoming) {
      return "[IN]";
    }

    if (hasRecentOutgoing) {
      return "[OUT]";
    }

    return "";
  }, [samples]);
  const pageTitle = useMemo(() => {
    const titleParts = [resolvedServiceName, resolvedMachineName].filter(Boolean);
    const baseTitle =
      titleParts.length > 0
        ? `${titleParts.join(" - ")} | Traffic Monitor | PortHub`
        : "Traffic Monitor | PortHub";
    if (pageTitleActivityPrefix) {
      return `${pageTitleActivityPrefix} ${baseTitle}`;
    }
    return baseTitle;
  }, [pageTitleActivityPrefix, resolvedMachineName, resolvedServiceName]);

  if (isCheckingAuth) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-foreground ">
        <Loader size="sm" color="blue" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground px-4 py-6  md:px-8">
      <Head>
        <title>{pageTitle}</title>
      </Head>
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <div className="space-y-3">
          <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
            Traffic Monitor
          </div>
          <h1
            className={`break-words text-2xl font-semibold tracking-tight sm:text-3xl ${
              isDark ? "text-zinc-100" : "text-zinc-900"
            }`}
          >
            {resolvedMachineName}
          </h1>
          {resolvedMachineDescription ? (
            <div
              className={`max-w-3xl text-sm leading-6 ${
                isDark ? "text-zinc-400" : "text-zinc-600"
              }`}
            >
              {resolvedMachineDescription}
            </div>
          ) : null}
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <div className="min-w-0">
              <span className="mr-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                Local IP
              </span>
              <span
                className={`text-sm font-medium ${
                  isDark ? "text-zinc-100" : "text-zinc-900"
                }`}
              >
                {resolvedLocalIp || "Unavailable"}
              </span>
            </div>
            <div className="min-w-0">
              <span className="mr-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                Service
              </span>
              <span
                className={`text-sm font-medium ${
                  isDark ? "text-zinc-100" : "text-zinc-900"
                }`}
              >
                {resolvedServiceName || "Unknown service"}
              </span>
            </div>
            <div className="min-w-0">
              <span className="mr-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                Mapping
              </span>
              <span
                className={`text-sm font-medium ${
                  isDark ? "text-zinc-100" : "text-zinc-900"
                }`}
              >
                {resolvedInternalIp && resolvedInternalPort
                  ? `${resolvedInternalIp}:${resolvedInternalPort}`
                  : "Unavailable"}
                {resolvedExternalPort ? ` -> ${resolvedExternalPort}` : ""}
              </span>
            </div>
          </div>
          {resolvedServiceDescription ? (
            <div
              className={`text-sm ${
                isDark ? "text-muted-foreground" : "text-zinc-600"
              }`}
            >
              {resolvedServiceDescription}
            </div>
          ) : null}
        </div>

        {!dataId ? (
          <Alert color="red" variant="light">
            Missing traffic monitor target. Open this page from a service row in the host popup.
          </Alert>
        ) : null}

        {loadError ? (
          <Alert color="red" variant="light">
            {loadError}
          </Alert>
        ) : null}

        <TrafficMonitorPanel
          isDark={isDark}
          samples={samples}
          isLoading={isLoading}
          title="Traffic monitor"
          subtitle="Dedicated live monitor for this forwarded port. Hover points to inspect recent incoming, outgoing, and blocked IP activity."
          onOpenExternal={undefined}
          hostName={resolvedMachineName}
          serviceName={resolvedServiceName}
          externalPort={resolvedExternalPort}
          mode="standalone"
          windowSeconds={90}
          showStandaloneMeta={false}
        />
      </div>
    </div>
  );
}
