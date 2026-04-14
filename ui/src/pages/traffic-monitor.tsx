import TrafficMonitorPanel from "@/components/User/components/Home/components/Host/TrafficMonitorPanel";
import useAuth from "@/shared/hooks/useAuth";
import apiRoutes from "@/shared/routes/apiRoutes";
import uiRoutes from "@/shared/routes/uiRoutes";
import { Alert, Loader, useMantineColorScheme } from "@mantine/core";
import axios from "axios";
import { useRouter } from "next/router";
import { useEffect, useMemo, useState } from "react";

type TrafficSample = {
  timestamp?: number;
  in_bytes?: number;
  out_bytes?: number;
  drop_bytes?: number;
  blocked_ips?: string[];
  incoming_ips?: string[];
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
  const [isLoading, setIsLoading] = useState(false);
  const [samples, setSamples] = useState<TrafficSample[]>([]);
  const [loadError, setLoadError] = useState("");
  const [connectionDetails, setConnectionDetails] = useState<ConnectionDetails | null>(null);

  useEffect(() => {
    let isActive = true;

    const checkAuth = async () => {
      const account = await auth.getAccountInfo();
      if (!isActive) {
        return;
      }

      if (!account?.role) {
        router.replace(uiRoutes.signIn);
        return;
      }

      setIsCheckingAuth(false);
    };

    checkAuth();

    return () => {
      isActive = false;
    };
  }, []);

  useEffect(() => {
    if (isCheckingAuth || !dataId) {
      return;
    }

    let isActive = true;

    const loadConnectionDetails = async () => {
      try {
        const response = await axios.get(apiRoutes.listConnections);
        if (!isActive) {
          return;
        }

        const connections = Array.isArray(response.data?.data) ? response.data.data : [];
        const matchedConnection = connections
          ? connections.find((item: any) => item?._id === dataId)
          : null;

        setConnectionDetails(matchedConnection || null);
      } catch {
        if (isActive) {
          setConnectionDetails(null);
        }
      }
    };

    loadConnectionDetails();

    return () => {
      isActive = false;
    };
  }, [dataId, isCheckingAuth]);

  useEffect(() => {
    if (isCheckingAuth || !dataId) {
      return;
    }

    let isActive = true;

    const loadTrafficSamples = async ({ showLoading = false } = {}) => {
      if (showLoading) {
        setIsLoading(true);
      }

      try {
        const response = await axios.post(apiRoutes.trafficSnapshot, {
          data_ids: [dataId],
        });
        if (!isActive) {
          return;
        }

        const traffic =
          Array.isArray(response.data?.data) && response.data.data.length > 0
            ? response.data.data[0]?.traffic
            : [];

        setSamples(Array.isArray(traffic) ? traffic : []);
        setLoadError("");
      } catch (loadTrafficError: any) {
        if (!isActive) {
          return;
        }
        setLoadError(
          loadTrafficError?.response?.data?.detail ||
            "Could not load the live traffic stream."
        );
      } finally {
        if (isActive) {
          setIsLoading(false);
        }
      }
    };

    loadTrafficSamples({ showLoading: true });
    const intervalId = window.setInterval(() => {
      loadTrafficSamples();
    }, 1000);

    return () => {
      isActive = false;
      window.clearInterval(intervalId);
    };
  }, [dataId, isCheckingAuth]);

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

  if (isCheckingAuth) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-100 dark:bg-zinc-900">
        <Loader size="sm" color="blue" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-neutral-100 px-4 py-6 dark:bg-zinc-900 md:px-8">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <div className="space-y-3">
          <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">
            Traffic Monitor
          </div>
          <div
            className={`text-3xl font-semibold tracking-tight ${
              isDark ? "text-zinc-100" : "text-zinc-900"
            }`}
          >
            {resolvedMachineName}
          </div>
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
              <span className="mr-2 text-[11px] uppercase tracking-[0.16em] text-zinc-500">
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
              <span className="mr-2 text-[11px] uppercase tracking-[0.16em] text-zinc-500">
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
              <span className="mr-2 text-[11px] uppercase tracking-[0.16em] text-zinc-500">
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
                isDark ? "text-zinc-500" : "text-zinc-600"
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
          subtitle="Dedicated live monitor for this forwarded port. Hover points to inspect recent accepted and blocked source IPs."
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
