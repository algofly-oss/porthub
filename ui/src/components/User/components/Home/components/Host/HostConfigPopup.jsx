import { externalEndpoint, internalEndpoint } from "@/shared/utils/endpoints.mjs";
import Pagination from "@/components/ui/pagination";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { Dialog as Modal } from "@/components/ui/dialog";
import { Menu } from "@/components/ui/menu";
import { Tooltip } from "@/components/ui/tooltip";
import useTrafficSnapshot from "@/shared/hooks/useTrafficSnapshot";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import { Button as WorkspaceButton } from "@/components/ui/button";
import { StatusTabs } from "@/components/ui/status-tabs";
import { Input as WorkspaceInput } from "@/components/ui/input";
import { Table, TableHeader, TableHead, TableBody, TableRow, TableCell } from "@/components/ui/table";

function PortField({ id, label, value, onChange, error, ...props }) {
  return <div className="min-w-0"><label htmlFor={id} className="mb-2 block text-sm font-medium">{label}</label><WorkspaceInput {...props} id={id} className="bg-control" value={value} onChange={event=>onChange(event.target.value)} aria-invalid={!!error} aria-describedby={error ? `${id}-error` : undefined} />{error && <p id={`${id}-error`} className="mt-1 text-xs text-red-600 dark:text-red-400">{error}</p>}</div>;
}
import { useContext, useEffect, useRef, useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Popover,
  Stack,
  Switch,
  Text,
  useMantineColorScheme,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import {
  IconArrowLeft,
  IconChevronDown,
  IconChevronUp,
  IconCopy,
  IconDotsVertical,
  IconFolder,
  IconInfoCircle,
  IconPlus,
  IconRefresh,
  IconShieldLock,
  IconTrash,
  IconUsers,
  IconX,
} from "@tabler/icons-react";
import axios from "axios";
import Proxy from "../../../Proxy";
import apiRoutes from "@/shared/routes/apiRoutes";
import uiRoutes from "@/shared/routes/uiRoutes";
import useToast from "@/shared/hooks/useToast";
import { SocketContext } from "@/shared/contexts/socket";
import socketRoutes from "@/shared/routes/socketRoutes";
import TrafficMonitorPanel, {
  normalizeTrafficSamples,
} from "./TrafficMonitorPanel";
import UptimeHistoryPanel from "./UptimeHistoryPanel";
import { useDemo } from "@/shared/demo/DemoProvider";

const getInputClassName = () => "w-full rounded-lg !border !border-transparent !bg-control px-3 py-2 text-sm !text-foreground !outline-none !shadow-none placeholder:!text-muted-foreground";
const getLabelClassName = () => "mb-2 block text-sm font-medium text-foreground";
const errorClassName = "mt-1 text-xs text-red-600 dark:text-red-400";
const getDetailInputClassName = getInputClassName;

const getInfoBadgeClassName = () => "!bg-control !text-muted-foreground";

const getStatusBadgeClassName = (_isDark, tone) => ({
  success: "!bg-emerald-500/10 !text-emerald-700 dark:!text-emerald-400",
  warning: "!bg-amber-500/10 !text-amber-700 dark:!text-amber-400",
  danger: "!bg-red-500/10 !text-red-700 dark:!text-red-400",
}[tone] || "!bg-control !text-muted-foreground");

const parseServerDate = (value) => {
  if (!value) {
    return null;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === "string") {
    const normalized = /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : `${value}Z`;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const formatCompactLastSeen = (value) => {
  const parsed = parseServerDate(value);
  if (!parsed) {
    return "Never seen";
  }

  const secondsAgo = Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 1000));
  if (secondsAgo <= 30) {
    return "Just now";
  }
  if (secondsAgo < 60) {
    return `${secondsAgo}s ago`;
  }

  const minutesAgo = Math.floor(secondsAgo / 60);
  if (minutesAgo < 60) {
    return `${minutesAgo}m ago`;
  }

  const hoursAgo = Math.floor(minutesAgo / 60);
  if (hoursAgo < 24) {
    return `${hoursAgo}h ago`;
  }

  const daysAgo = Math.floor(hoursAgo / 24);
  return `${daysAgo}d ago`;
};

const formatRelativeUnixTimestamp = (value) => {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "Unknown";
  }

  const secondsAgo = Math.max(0, Math.floor(Date.now() / 1000 - seconds));
  if (secondsAgo <= 1) {
    return "1s ago";
  }
  if (secondsAgo < 60) {
    return `${secondsAgo}s ago`;
  }

  const minutesAgo = Math.floor(secondsAgo / 60);
  if (minutesAgo === 1) {
    return "1m ago";
  }
  if (minutesAgo < 60) {
    return `${minutesAgo}m ago`;
  }

  const hoursAgo = Math.floor(minutesAgo / 60);
  if (hoursAgo === 1) {
    return "1h ago";
  }
  if (hoursAgo < 24) {
    return `${hoursAgo}h ago`;
  }

  const daysAgo = Math.floor(hoursAgo / 24);
  return daysAgo === 1 ? "1d ago" : `${daysAgo}d ago`;
};

const createRuleId = () =>
  `rule-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

const createEmptyRule = (externalPort = "") => ({
  localId: createRuleId(),
  dataId: null,
  serviceName: "",
  serviceDescription: "",
  internalIp: "0.0.0.0",
  internalPort: "",
  externalPort: externalPort ? String(externalPort) : "",
  enabled: true,
  autoRefreshEnabled: false,
  autoRefreshIntervalMinutes: "60",
  firewall: {
    isPublic: true,
    allowedIps: [],
  },
});

const mapRuleFromConfig = (config) => ({
  localId: config.dataId || createRuleId(),
  dataId: config.dataId || null,
  serviceName: config.serviceName || "",
  serviceDescription: config.serviceDescription || "",
  internalIp: config.internalIp || config.internal_ip || "0.0.0.0",
  externalBindIp: config.externalBindIp || config.external_bind_ip || "0.0.0.0",
  internalPort:
    config.internalPort === undefined ||
    config.internalPort === null ||
    config.internalPort === ""
      ? ""
      : String(config.internalPort),
  externalPort:
    config.externalPort === undefined ||
    config.externalPort === null ||
    config.externalPort === ""
      ? ""
      : String(config.externalPort),
  enabled: config.enabled ?? true,
  autoRefreshEnabled: config.autoRefreshEnabled ?? config.auto_refresh_enabled ?? false,
  autoRefreshIntervalMinutes:
    config.autoRefreshIntervalMinutes === undefined ||
    config.autoRefreshIntervalMinutes === null ||
    config.autoRefreshIntervalMinutes === ""
      ? String(config.auto_refresh_interval_minutes || 60)
      : String(config.autoRefreshIntervalMinutes),
  autoRefreshedAt: config.autoRefreshedAt || config.auto_refreshed_at || null,
  autoRefreshNextAt: config.autoRefreshNextAt || config.auto_refresh_next_at || null,
  firewall: {
    isPublic:
      typeof config.firewall?.isPublic === "boolean"
        ? config.firewall.isPublic
        : typeof config.firewall?.is_public === "boolean"
          ? config.firewall.is_public
          : true,
    allowedIps: Array.isArray(config.firewall?.allowedIps)
      ? config.firewall.allowedIps
      : Array.isArray(config.firewall?.allowed_ips)
        ? config.firewall.allowed_ips
        : [],
  },
});

const normalizeAllowedIps = (values) =>
  [...new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || "").trim())
      .filter(Boolean)
  )].sort((left, right) => left.localeCompare(right));

const isValidIpv4Address = (value) => {
  const normalized = (value || "").trim();
  if (!normalized) {
    return false;
  }

  const parts = normalized.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }
    const segment = Number(part);
    return segment >= 0 && segment <= 255;
  });
};

const isValidHostname = (value) => {
  const normalized = (value || "").trim();
  if (!normalized || normalized.length > 253) {
    return false;
  }

  if (normalized.toLowerCase() === "localhost") {
    return true;
  }

  return normalized.split(".").every((label) => {
    if (!label || label.length > 63) {
      return false;
    }

    if (!/^[A-Za-z0-9-]+$/.test(label)) {
      return false;
    }

    return !label.startsWith("-") && !label.endsWith("-");
  });
};

const isValidInternalHost = (value) =>
  isValidIpv4Address(value) || isValidHostname(value);

const normalizeInternalHost = (value) => {
  const normalized = (value || "").trim();
  return normalized || "0.0.0.0";
};

const buildExternalPortUrl = (serviceDomain, externalPort) => {
  const normalizedPort = Number(externalPort);
  if (!Number.isInteger(normalizedPort) || normalizedPort < 1 || normalizedPort > 65535) {
    return "";
  }

  const normalizedServiceDomain = String(serviceDomain || "").trim();
  if (!normalizedServiceDomain) {
    return "";
  }

  try {
    const rootUrl = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(normalizedServiceDomain)
      ? normalizedServiceDomain
      : `${typeof window !== "undefined" ? window.location.protocol : "http:"}//${normalizedServiceDomain}`;
    const url = new URL(rootUrl);
    url.port = String(normalizedPort);
    return url.toString();
  } catch {
    return "";
  }
};

const getApiErrorMessage = (requestError, fallbackMessage) =>
  requestError?.response?.data?.detail || fallbackMessage;

const createEmptyClientSetupValues = () => ({
  publicBaseUrl: "",
  ratholeServerAddress: "",
  serviceDomain: "",
});

const mapClientSetupValues = (values = {}) => ({
  publicBaseUrl: String(values.public_base_url || values.publicBaseUrl || "").trim(),
  ratholeServerAddress: String(
    values.rathole_server_address || values.ratholeServerAddress || ""
  ).trim(),
  serviceDomain: String(values.service_domain || values.serviceDomain || "").trim(),
});

const valuesDiffer = (left, right) =>
  left.publicBaseUrl !== right.publicBaseUrl ||
  left.ratholeServerAddress !== right.ratholeServerAddress ||
  left.serviceDomain !== right.serviceDomain;

const getChangedClientSetupValues = (fields, defaults) => ({
  publicBaseUrl:
    fields.publicBaseUrl.trim() && fields.publicBaseUrl.trim() !== defaults.publicBaseUrl
      ? fields.publicBaseUrl.trim()
      : "",
  ratholeServerAddress:
    fields.ratholeServerAddress.trim() &&
    fields.ratholeServerAddress.trim() !== defaults.ratholeServerAddress
      ? fields.ratholeServerAddress.trim()
      : "",
  serviceDomain:
    fields.serviceDomain.trim() && fields.serviceDomain.trim() !== defaults.serviceDomain
      ? fields.serviceDomain.trim()
      : "",
});

const getRuleErrors = (rule) => {
  const errors = {};

  if (!rule.serviceName.trim()) {
    errors.serviceName = "Service name is required";
  }

  if (rule.internalIp.trim() && !isValidInternalHost(rule.internalIp)) {
    errors.internalIp = "Use a valid IPv4 address or hostname";
  }

  const internalPort = Number(rule.internalPort);
  if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) {
    errors.internalPort = "Use a valid internal port";
  }

  const externalPort = Number(rule.externalPort);
  if (!Number.isInteger(externalPort) || externalPort < 1 || externalPort > 65535) {
    errors.externalPort = "Use a valid external port";
  }

  if (rule.autoRefreshEnabled) {
    const intervalMinutes = Number(rule.autoRefreshIntervalMinutes);
    if (
      !Number.isInteger(intervalMinutes) ||
      intervalMinutes < 1 ||
      intervalMinutes > 10080
    ) {
      errors.autoRefreshIntervalMinutes = "Use 1 to 10080 minutes";
    }
  }

  return errors;
};

/** Normalize rule for comparison (exclude localId/dataId, consistent types) */
const normalizeRuleForCompare = (rule) => ({
  serviceName: (rule.serviceName || "").trim(),
  serviceDescription: (rule.serviceDescription || "").trim(),
  internalIp: normalizeInternalHost(rule.internalIp),
  internalPort: Number(rule.internalPort) || 0,
  externalPort: Number(rule.externalPort) || 0,
  enabled: Boolean(rule.enabled),
  autoRefreshEnabled: Boolean(rule.autoRefreshEnabled),
  autoRefreshIntervalMinutes: Number(rule.autoRefreshIntervalMinutes) || 60,
  firewall: {
    isPublic:
      rule.firewall?.isPublic !== false ||
      normalizeAllowedIps(rule.firewall?.allowedIps).length === 0,
    allowedIps: normalizeAllowedIps(rule.firewall?.allowedIps),
  },
});

const rulesSnapshotKey = (rules) =>
  JSON.stringify(rules.map(normalizeRuleForCompare));

const RULES_PER_PAGE = 5;
const MAX_CLIENT_LOG_LINES = 2000;
const CLIENT_LOG_AUTO_SCROLL_THRESHOLD = 24;

export default function HostConfigPopup({
  host,
  privateDomain = "",
  opened,
  onClose,
  onSave,
  onUpdateMachineDetails,
  onUpdateClientSetup,
  onDeleteMachine,
  onToggleMachine,
  onToggleTelegramAlerts,
  onRefreshMachineToken,
  onRequestClientUpdate,
  onRefreshConnection,
  onCreateGroup,
  onAddMachineToGroup,
  onRemoveMachineFromGroup,
  groups = [],
  isSaving,
  initialSection = "ports",
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const demo = useDemo();
  const { success, error } = useToast();
  const socket = useContext(SocketContext);

  const [rules, setRules] = useState([]);
  const [machineSection, setMachineSection] = useState("ports");
  const [portSection, setPortSection] = useState("connection");
  const [linkedProxies, setLinkedProxies] = useState([]);
  const [proxiesOpen, setProxiesOpen] = useState(false);
  const [proxyEditorOpen, setProxyEditorOpen] = useState(false);
  const [discardConfirmOpen, setDiscardConfirmOpen] = useState(false);
  useEffect(() => { if (opened) setMachineSection(initialSection); }, [opened, host?.id, initialSection]);
  const allPortTraffic = useTrafficSnapshot({ ids: rules.map(rule=>rule.dataId), enabled: opened });
  const samplesByConnection = new Map(allPortTraffic.rows.map(row=>[row.connection?._id,row.traffic]));
  useEffect(() => {
    if (!opened || !host?.id) return;
    const controller = new AbortController();
    axios.get(apiRoutes.listTrafficRoutes, {signal:controller.signal}).then(response=>setLinkedProxies((response.data?.data || []).filter(proxy=>proxy.connection?.machine_id === host.id))).catch(()=>{});
    return () => controller.abort();
  }, [opened, host?.id, proxyEditorOpen]);
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [errorsByRuleId, setErrorsByRuleId] = useState({});
  const [availabilityByRuleId, setAvailabilityByRuleId] = useState({});
  const [isCheckingAvailability, setIsCheckingAvailability] = useState(false);
  const [randomizingRuleId, setRandomizingRuleId] = useState(null);
  const [machineCommand, setMachineCommand] = useState("");
  const machineCommandPreviewsRef = useRef({ identity: "", commands: new Map() });
  const [isLoadingMachineCommand, setIsLoadingMachineCommand] = useState(false);
  const [showClientSetupAdvanced, setShowClientSetupAdvanced] = useState(false);
  const [clientSetupDefaults, setClientSetupDefaults] = useState(
    createEmptyClientSetupValues
  );
  const [clientSetupFields, setClientSetupFields] = useState(
    createEmptyClientSetupValues
  );
  const [isSavingClientSetup, setIsSavingClientSetup] = useState(false);
  const [isRefreshingMachineToken, setIsRefreshingMachineToken] = useState(false);
  const [isRequestingClientUpdate, setIsRequestingClientUpdate] = useState(false);
  const [refreshingRuleId, setRefreshingRuleId] = useState(null);
  const [isTogglingMachine, setIsTogglingMachine] = useState(false);
  const [isTogglingTelegramAlerts, setIsTogglingTelegramAlerts] = useState(false);
  const [showUptimeHistory, setShowUptimeHistory] = useState(false);
  const [uptimeEvents, setUptimeEvents] = useState([]);
  const [uptimeCurrentStatus, setUptimeCurrentStatus] = useState(null);
  const [isLoadingUptimeHistory, setIsLoadingUptimeHistory] = useState(false);
  const [isRefreshMachineTokenConfirmOpen, setIsRefreshMachineTokenConfirmOpen] =
    useState(false);
  const [isDeleteMachineConfirmOpen, setIsDeleteMachineConfirmOpen] =
    useState(false);
  const [isDeletingMachine, setIsDeletingMachine] = useState(false);
  const [showGroups, setShowGroups] = useState(false);
  const [showMachineCredentials, setShowMachineCredentials] = useState(false);
  const [showClientLogs, setShowClientLogs] = useState(false);
  const [showVerboseClientLogs, setShowVerboseClientLogs] = useState(false);
  const [showClientLogLineNumbers, setShowClientLogLineNumbers] = useState(false);
  const [clientLogs, setClientLogs] = useState([]);
  const [clientLogStartLineNumber, setClientLogStartLineNumber] = useState(1);
  const [clientLogStreamStatus, setClientLogStreamStatus] = useState("idle");
  const [shouldAutoScrollClientLogs, setShouldAutoScrollClientLogs] = useState(true);
  const [editingRuleSnapshot, setEditingRuleSnapshot] = useState(null);
  const [rulesPage, setRulesPage] = useState(1);
  const [groupSaving, setGroupSaving] = useState(false);
  const [isGroupPickerOpen, setIsGroupPickerOpen] = useState(false);
  const [groupQuery, setGroupQuery] = useState("");
  const [privateAddresses, setPrivateAddresses] = useState(null);
  const [privateAddressError, setPrivateAddressError] = useState(false);
  useEffect(() => {
    setPrivateAddresses(null);
    setPrivateAddressError(false);
    if (!opened || !host?.id) return;
    let active = true;
    axios.get(`/api/machines/private-addresses/${host.id}`)
      .then(({ data }) => { if (active) setPrivateAddresses(data.data || []); })
      .catch(() => { if (active) setPrivateAddressError(true); });
    return () => { active = false; };
  }, [opened, host?.id]);
  const [machineDetails, setMachineDetails] = useState({ name: "", hostname: "" });
  const [machineDetailsErrors, setMachineDetailsErrors] = useState({});
  const [isSavingMachineDetails, setIsSavingMachineDetails] = useState(false);
  const [showRuleAdvanced, setShowRuleAdvanced] = useState(true);
  const [allowIpDraft, setAllowIpDraft] = useState("");
  const [allowIpRecentHitsByRuleId, setAllowIpRecentHitsByRuleId] = useState({});
  const [isLoadingAllowIpSuggestions, setIsLoadingAllowIpSuggestions] = useState(false);
  const [isAllowIpPickerOpen, setIsAllowIpPickerOpen] = useState(false);
  const [trafficSamplesByRuleId, setTrafficSamplesByRuleId] = useState({});
  const [isLoadingTrafficSamples, setIsLoadingTrafficSamples] = useState(false);
  const [serviceDomain, setServiceDomain] = useState("");
  const [debouncedRules] = useDebouncedValue(rules, 300);
  const [debouncedClientSetupFields] = useDebouncedValue(clientSetupFields, 300);
  const initialRulesSnapshotRef = useRef("");
  const clientLogsContainerRef = useRef(null);
  const groupInputRef = useRef(null);
  const allowIpInputRef = useRef(null);
  const previousHostIdRef = useRef(null);
  const loadRecentHitsRef = useRef(null);
  const editorFormRef = useRef(null);
  const portHeadingRef = useRef(null);
  const portsHeadingRef = useRef(null);

  const selectedRule = rules.find((rule) => rule.localId === selectedRuleId) || null;
  useEffect(() => {
    if (!opened) return;
    const form = editorFormRef.current;
    if (form && !form.contains(document.activeElement)) {
      (selectedRuleId ? portHeadingRef.current : portsHeadingRef.current || form)?.focus({ preventScroll: true });
    }
  }, [opened, selectedRuleId, machineSection, portSection]);
  const hasUnsavedChanges =
    host && rulesSnapshotKey(rules) !== initialRulesSnapshotRef.current;
  const savedRuleCount = host?.forwardingConfigs?.length || 0;
  const hostConnectionStatus =
    host?.connectionStatus || (host?.isActive ? "online" : "offline");
  const showClientUpdateAction = Boolean(host?.id);
  const clientVersionLabel = host?.clientVersion
    ? `v${host.clientVersion}`
    : "Awaiting heartbeat";
  const latestClientVersionLabel = host?.latestClientVersion
    ? `v${host.latestClientVersion}`
    : "Unknown";
  const savedRulesById = new Map(
    (host?.forwardingConfigs || [])
      .filter((rule) => rule.dataId)
      .map((rule) => [rule.dataId, rule])
  );
  const visibleClientLogs = clientLogs.reduce((result, line, index) => {
    if (!showVerboseClientLogs && line.includes("[DEBUG]")) {
      return result;
    }

    result.push({
      number: clientLogStartLineNumber + index,
      text: line,
    });
    return result;
  }, []);
  const totalRulePages = Math.max(1, Math.ceil(rules.length / RULES_PER_PAGE));
  const paginatedRules = rules.slice(
    (rulesPage - 1) * RULES_PER_PAGE,
    rulesPage * RULES_PER_PAGE
  );
  const assignedGroupIds = Array.isArray(host?.groupIds) ? host.groupIds : [];
  const assignedGroups = assignedGroupIds
    .map((groupId) => groups.find((group) => group._id === groupId))
    .filter(Boolean);
  const availableGroups = groups.filter(
    (group) => !assignedGroupIds.includes(group._id)
  );
  const normalizedGroupQuery = groupQuery.trim().toLowerCase();
  const filteredAvailableGroups = availableGroups.filter((group) =>
    group.name.toLowerCase().includes(normalizedGroupQuery)
  );
  const hasExactGroupName = groups.some(
    (group) => group.name.trim().toLowerCase() === normalizedGroupQuery
  );
  const canCreateGroupFromQuery = Boolean(
    onCreateGroup && normalizedGroupQuery && !hasExactGroupName
  );
  const machineNameValue = machineDetails.name.trim();
  const machineHostnameValue = machineDetails.hostname.trim();
  // The name field holds "name, alias, alias"; the server splits and cleans it.
  const hostAliasesKey = (host?.aliases || []).join(",");
  const hostNameValue = [host?.name || "", ...(host?.aliases || [])].join(", ").trim();
  const hostHostnameValue = (host?.hostname || "").trim();
  const clientHostnameValue = (host?.clientHostname || "").trim();
  const machineDetailsChanged =
    machineNameValue !== hostNameValue || machineHostnameValue !== hostHostnameValue;
  const savedClientSetupFields = {
    publicBaseUrl:
      (host?.clientSetupPublicBaseUrl || "").trim() ||
      clientSetupDefaults.publicBaseUrl,
    ratholeServerAddress:
      (host?.clientSetupRatholeServerAddress || "").trim() ||
      clientSetupDefaults.ratholeServerAddress,
    serviceDomain:
      (host?.clientSetupServiceDomain || "").trim() ||
      clientSetupDefaults.serviceDomain,
  };
  const clientSetupChanged = valuesDiffer(clientSetupFields, savedClientSetupFields);
  const anyUnsavedChanges = Boolean(host) && (hasUnsavedChanges || machineDetailsChanged || clientSetupChanged);
  const savingSection = isSaving || isSavingMachineDetails || isSavingClientSetup;
  const hasSavedClientSetupOverrides = Boolean(
    (host?.clientSetupPublicBaseUrl || "").trim() ||
      (host?.clientSetupRatholeServerAddress || "").trim() ||
      (host?.clientSetupServiceDomain || "").trim()
  );
  const effectiveServiceDomain =
    (host?.clientSetupServiceDomain || "").trim() || serviceDomain;

  // Keep the gateway address visible for saved mappings even when disabled.
  // A custom web proxy is an additional address, not a prerequisite.
  const gatewayLink = (rule) => {
    const url = rule.dataId ? buildExternalPortUrl(effectiveServiceDomain, rule.externalPort) : "";
    return url ? (
      <a href={url} target="_blank" rel="noreferrer" onClick={(event) => event.stopPropagation()} className="block truncate text-xs text-blue-700 hover:underline dark:text-blue-300" title={rule.enabled ? "Open directly on the gateway" : "Gateway address (mapping disabled)"}>
        {url.replace(/^https?:\/\//, "").replace(/\/$/, "")}
      </a>
    ) : null;
  };

  const openTrafficMonitorWindow = (rule) => {
    if (!rule?.dataId || typeof window === "undefined") {
      return;
    }

    const nextUrl = uiRoutes.getTrafficMonitor({
      demo,
      dataId: rule.dataId,
      hostName: host?.name || host?.hostname || host?.clientHostname || "",
      hostDescription: host?.hostname || "",
      localIp: host?.localIp || "",
      serviceName: rule.serviceName || "",
      externalPort: rule.externalPort || "",
    });
    window.open(nextUrl, "_blank", "noopener,noreferrer");
  };

  useEffect(() => {
    if (rulesPage > totalRulePages) {
      setRulesPage(totalRulePages);
    }
  }, [rulesPage, totalRulePages]);

  const selectedRuleHasErrors = selectedRule
    ? (() => {
        const ruleErrors = getRuleErrors(selectedRule);
        const availability = availabilityByRuleId[selectedRule.localId];
        const hasValidationErrors = Object.keys(ruleErrors).length > 0;
        const hasAvailabilityError =
          availability && !availability.available;
        return hasValidationErrors || hasAvailabilityError;
      })()
    : false;

  useEffect(() => {
    if (!host) {
      previousHostIdRef.current = null;
      setRules([]);
      setSelectedRuleId(null);
      setErrorsByRuleId({});
      setAvailabilityByRuleId({});
      setMachineCommand("");
      setShowClientSetupAdvanced(false);
      setClientSetupDefaults(createEmptyClientSetupValues());
      setClientSetupFields(createEmptyClientSetupValues());
      setIsSavingClientSetup(false);
      setShowGroups(false);
      setShowMachineCredentials(false);
      setShowClientLogs(false);
      setShowVerboseClientLogs(false);
      setShowClientLogLineNumbers(false);
      setClientLogs([]);
      setClientLogStartLineNumber(1);
      setClientLogStreamStatus("idle");
      setShouldAutoScrollClientLogs(true);
      setIsRefreshMachineTokenConfirmOpen(false);
      setRefreshingRuleId(null);
      setIsDeleteMachineConfirmOpen(false);
      setGroupQuery("");
      setEditingRuleSnapshot(null);
      setRulesPage(1);
      setMachineDetails({ name: "", hostname: "" });
      setMachineDetailsErrors({});
      setIsSavingMachineDetails(false);
      setShowRuleAdvanced(true);
      setAllowIpDraft("");
      setAllowIpRecentHitsByRuleId({});
      setTrafficSamplesByRuleId({});
      setIsAllowIpPickerOpen(false);
      initialRulesSnapshotRef.current = "";
      return;
    }

    const nextRules =
      host.forwardingConfigs?.length > 0
        ? host.forwardingConfigs.map(mapRuleFromConfig)
        : [];

    const isHostSwitch = previousHostIdRef.current !== host.id;
    previousHostIdRef.current = host.id;

    setRules(nextRules);
    setErrorsByRuleId({});
    setAvailabilityByRuleId({});
    initialRulesSnapshotRef.current = rulesSnapshotKey(nextRules);

    if (isHostSwitch) {
      setSelectedRuleId(null);
      setShowGroups(false);
      setShowMachineCredentials(false);
      setShowClientSetupAdvanced(false);
      setShowClientLogs(false);
      setShowVerboseClientLogs(false);
      setShowClientLogLineNumbers(false);
      setClientLogs([]);
      setClientLogStartLineNumber(1);
      setClientLogStreamStatus("idle");
      setShouldAutoScrollClientLogs(true);
      setIsRefreshMachineTokenConfirmOpen(false);
      setIsDeleteMachineConfirmOpen(false);
      setRefreshingRuleId(null);
      setGroupQuery("");
      setEditingRuleSnapshot(null);
      setRulesPage(1);
      setShowRuleAdvanced(true);
      setAllowIpDraft("");
      setTrafficSamplesByRuleId({});
      setIsAllowIpPickerOpen(false);
      return;
    }

    setSelectedRuleId((currentSelectedRuleId) =>
      currentSelectedRuleId &&
      nextRules.some((rule) => rule.localId === currentSelectedRuleId)
        ? currentSelectedRuleId
        : null
    );
    setEditingRuleSnapshot((currentSnapshot) =>
      currentSnapshot &&
      nextRules.some((rule) => rule.localId === currentSnapshot.localId)
        ? currentSnapshot
        : null
    );
  }, [
    host?.id,
    host?.forwardingConfigs,
  ]);

  // Metadata saves must not reset draft port edits, or vice versa.
  useEffect(() => {
    setMachineDetails({ name: [host?.name || "", ...(host?.aliases || [])].join(", "), hostname: host?.hostname || "" });
    setMachineDetailsErrors({});
  }, [host?.id, host?.name, hostAliasesKey, host?.hostname]);

  useEffect(() => {
    setShowGroups(machineSection === "groups");
    setShowMachineCredentials(machineSection === "credentials");
    setShowClientLogs(machineSection === "logs");
    setShowUptimeHistory(machineSection === "uptime");
  }, [machineSection, opened, host?.id]);

  useEffect(() => {
    if (!selectedRule) {
      setShowRuleAdvanced(true);
      setAllowIpDraft("");
      setIsAllowIpPickerOpen(false);
      return;
    }

    setAllowIpDraft("");
    setShowRuleAdvanced(true);
  }, [selectedRule?.localId]);

  useEffect(() => {
    if (!opened || !selectedRule?.dataId || (!showRuleAdvanced && !isAllowIpPickerOpen)) {
      return;
    }

    let isActive = true;

    const loadRecentHits = async ({ showLoading = false } = {}) => {
      if (showLoading) {
        setIsLoadingAllowIpSuggestions(true);
      }

      try {
        const response = await axios.get(
          apiRoutes.getConnectionRecentIpHits(selectedRule.dataId, 10)
        );
        if (!isActive) {
          return;
        }

        setAllowIpRecentHitsByRuleId((current) => ({
          ...current,
          [selectedRule.localId]: response.data?.data || [],
        }));
      } catch {
        if (!isActive) {
          return;
        }
        setAllowIpRecentHitsByRuleId((current) => ({
          ...current,
          [selectedRule.localId]: current[selectedRule.localId] || [],
        }));
      } finally {
        if (isActive) {
          setIsLoadingAllowIpSuggestions(false);
        }
      }
    };
    loadRecentHitsRef.current = loadRecentHits;

    loadRecentHits({ showLoading: true });
    const intervalId = window.setInterval(() => {
      loadRecentHits();
    }, 5000);

    return () => {
      isActive = false;
      window.clearInterval(intervalId);
      loadRecentHitsRef.current = null;
    };
  }, [
    opened,
    selectedRule?.dataId,
    selectedRule?.localId,
    showRuleAdvanced,
    isAllowIpPickerOpen,
  ]);

  useEffect(() => {
    if (!opened || !selectedRule?.dataId || !showRuleAdvanced) {
      return;
    }

    let isActive = true;
    const controller = new AbortController();
    let timeout;

    const loadTrafficSamples = async ({ showLoading = false } = {}) => {
      if (showLoading) {
        setIsLoadingTrafficSamples(true);
      }

      try {
        const response = await axios.post(apiRoutes.trafficSnapshot, {
          data_ids: [selectedRule.dataId],
        }, { signal: controller.signal });
        if (!isActive) {
          return;
        }

        const traffic =
          Array.isArray(response.data?.data) && response.data.data.length > 0
            ? response.data.data[0]?.traffic
            : [];

        setTrafficSamplesByRuleId((current) => ({
          ...current,
          [selectedRule.localId]: normalizeTrafficSamples(traffic),
        }));
      } catch {
        if (!isActive) {
          return;
        }

        setTrafficSamplesByRuleId((current) => ({
          ...current,
          [selectedRule.localId]: current[selectedRule.localId] || [],
        }));
      } finally {
        if (isActive) {
          setIsLoadingTrafficSamples(false);
          timeout = setTimeout(loadTrafficSamples, 1000);
        }
      }
    };

    loadTrafficSamples({ showLoading: true });

    return () => {
      isActive = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [opened, selectedRule?.dataId, selectedRule?.localId, showRuleAdvanced]);

  useEffect(() => {
    if (!opened || !host?.id) {
      setMachineCommand("");
      setIsLoadingMachineCommand(false);
      setIsGroupPickerOpen(false);
      setGroupQuery("");
      return;
    }

    let isActive = true;
    const controller = new AbortController();
    const identity = `${host.id}:${host.token || ""}`;
    if (machineCommandPreviewsRef.current.identity !== identity) {
      machineCommandPreviewsRef.current = { identity, commands: new Map() };
      setMachineCommand("");
    }

    const loadMachineCommand = async () => {
      setIsLoadingMachineCommand(true);

      try {
        const response = await axios.get(apiRoutes.getMachineCommand(host.id), { signal: controller.signal });
        if (isActive) {
          const setup = response.data?.data?.client_setup || {};
          const defaults = mapClientSetupValues(setup.defaults);
          const overrides = mapClientSetupValues(setup.overrides);
          const fields = {
            publicBaseUrl: overrides.publicBaseUrl || defaults.publicBaseUrl,
            ratholeServerAddress:
              overrides.ratholeServerAddress || defaults.ratholeServerAddress,
            serviceDomain: overrides.serviceDomain || defaults.serviceDomain,
          };
          const command = response.data?.data?.command || "";
          machineCommandPreviewsRef.current.commands.set(
            JSON.stringify(getChangedClientSetupValues(fields, defaults)), command
          );
          setMachineCommand(command);
          setClientSetupDefaults(defaults);
          setClientSetupFields(fields);
        }
      } catch (machineCommandError) {
        // Keep the last known command instead of flashing "Unavailable" on transient failures.
      } finally {
        if (isActive) {
          setIsLoadingMachineCommand(false);
        }
      }
    };

    loadMachineCommand();

    return () => {
      isActive = false;
      controller.abort();
    };
  }, [opened, host?.id, host?.token]);

  useEffect(() => {
    if (!opened || !host?.id || !showClientSetupAdvanced) {
      return undefined;
    }

    let isActive = true;
    const commandOverrides = getChangedClientSetupValues(
      debouncedClientSetupFields,
      clientSetupDefaults
    );

    const cache = machineCommandPreviewsRef.current;
    const key = JSON.stringify(commandOverrides);
    // Expanding advanced settings is not an input change. Reuse commands for
    // saved or previously previewed values, scoped to this machine and token.
    if (cache.identity !== `${host.id}:${host.token || ""}` || !cache.commands.size ||
        valuesDiffer(debouncedClientSetupFields, clientSetupFields)) {
      return undefined;
    }
    if (cache.commands.has(key)) {
      setMachineCommand(cache.commands.get(key));
      setIsLoadingMachineCommand(false);
      return undefined;
    }
    const controller = new AbortController();
    const loadPreviewCommand = async () => {
      setIsLoadingMachineCommand(true);
      try {
        const response = await axios.get(
          apiRoutes.getMachineCommand(host.id, commandOverrides),
          { signal: controller.signal }
        );
        if (isActive) {
          const command = response.data?.data?.command || "";
          if (cache.commands.size >= 16) cache.commands.delete(cache.commands.keys().next().value);
          cache.commands.set(key, command);
          setMachineCommand(command);
        }
      } catch {
        // Keep the last known command while the user is editing advanced values.
      } finally {
        if (isActive) {
          setIsLoadingMachineCommand(false);
        }
      }
    };

    loadPreviewCommand();

    return () => {
      isActive = false;
      controller.abort();
      setIsLoadingMachineCommand(false);
    };
  }, [
    opened,
    host?.id,
    host?.token,
    clientSetupFields,
    showClientSetupAdvanced,
    debouncedClientSetupFields,
    clientSetupDefaults,
  ]);

  useEffect(() => {
    if (!opened) {
      setServiceDomain("");
      return;
    }

    let isActive = true;

    const loadAuthSettings = async () => {
      try {
        const response = await axios.get(apiRoutes.authSettings);
        if (isActive) {
          setServiceDomain(
            String(response.data?.port_hub_service_domain || "").trim()
          );
        }
      } catch {
        if (isActive) {
          setServiceDomain("");
        }
      }
    };

    loadAuthSettings();

    return () => {
      isActive = false;
    };
  }, [opened]);

  useEffect(() => {
    if (!socket || !opened || !host?.id || !showClientLogs) {
      return undefined;
    }

    const subscribeToLogs = () => {
      socket.emit(socketRoutes.ctsMachineLogStreamSubscribe, {
        machine_id: host.id,
      });
    };

    setClientLogs([]);
    setClientLogStartLineNumber(1);
    setClientLogStreamStatus(host.isActive ? "connecting" : "offline");
    setShouldAutoScrollClientLogs(true);
    subscribeToLogs();
    socket.on("connect", subscribeToLogs);

    return () => {
      socket.off("connect", subscribeToLogs);
      socket.emit(socketRoutes.ctsMachineLogStreamUnsubscribe, {
        machine_id: host.id,
      });
    };
  }, [socket, opened, host?.id, host?.isActive, showClientLogs]);

  useEffect(() => {
    if (!opened || !host?.id || !showUptimeHistory) {
      return;
    }

    let isActive = true;
    const loadUptimeHistory = (showLoading) => {
      if (showLoading) {
        setIsLoadingUptimeHistory(true);
      }
      axios
        .get(apiRoutes.getMachineStatusHistory(host.id, 365))
        .then((response) => {
          if (isActive) {
            setUptimeEvents(response.data?.data || []);
            setUptimeCurrentStatus(response.data?.current_status || null);
          }
        })
        .catch(() => {
          if (isActive && showLoading) {
            setUptimeEvents([]);
            setUptimeCurrentStatus(null);
          }
        })
        .finally(() => {
          if (isActive && showLoading) {
            setIsLoadingUptimeHistory(false);
          }
        });
    };

    loadUptimeHistory(true);
    // Refresh while open so newly recorded status changes show up live.
    const refreshTimer = setInterval(() => loadUptimeHistory(false), 30 * 1000);

    return () => {
      isActive = false;
      clearInterval(refreshTimer);
    };
  }, [opened, host?.id, showUptimeHistory, host?.isActive]);

  useEffect(() => {
    if (!socket || !host?.id) {
      return undefined;
    }

    const handleLogStreamStatus = (payload) => {
      if (payload?.machine_id !== host.id) {
        return;
      }

      if (payload?.subscribed || payload?.stream_requested) {
        setClientLogStreamStatus("streaming");
      } else if (payload?.machine_online === false) {
        setClientLogStreamStatus("offline");
      } else {
        setClientLogStreamStatus("idle");
      }
    };

    const handleLogStreamLine = (payload) => {
      if (payload?.machine_id !== host.id || !payload?.line) {
        return;
      }

      setClientLogStreamStatus("streaming");
      setClientLogs((current) => {
        const next = [...current, payload.line];
        const overflow = Math.max(0, next.length - MAX_CLIENT_LOG_LINES);
        if (overflow > 0) {
          setClientLogStartLineNumber((lineNumber) => lineNumber + overflow);
        }
        return overflow > 0 ? next.slice(-MAX_CLIENT_LOG_LINES) : next;
      });
    };

    socket.on(socketRoutes.stcMachineLogStreamStatus, handleLogStreamStatus);
    socket.on(socketRoutes.stcMachineLogStreamLine, handleLogStreamLine);

    return () => {
      socket.off(socketRoutes.stcMachineLogStreamStatus, handleLogStreamStatus);
      socket.off(socketRoutes.stcMachineLogStreamLine, handleLogStreamLine);
    };
  }, [socket, host?.id]);

  useEffect(() => {
    if (
      !showClientLogs ||
      !clientLogsContainerRef.current ||
      !shouldAutoScrollClientLogs
    ) {
      return;
    }

    clientLogsContainerRef.current.scrollTop =
      clientLogsContainerRef.current.scrollHeight;
  }, [showClientLogs, visibleClientLogs, shouldAutoScrollClientLogs]);

  const handleClientLogsScroll = () => {
    const element = clientLogsContainerRef.current;
    if (!element) {
      return;
    }

    const distanceFromBottom =
      element.scrollHeight - element.scrollTop - element.clientHeight;
    setShouldAutoScrollClientLogs(
      distanceFromBottom <= CLIENT_LOG_AUTO_SCROLL_THRESHOLD
    );
  };

  const handleRuleRowClick = (event, rule) => {
    if (event.target instanceof Element && event.target.closest("[data-rule-toggle='true']")) {
      return;
    }
    openRuleEditor(rule);
  };

  useEffect(() => {
    if (!opened) {
      return;
    }

    let isActive = true;

    const checkAvailability = async () => {
      const nextAvailability = {};
      const duplicatePortCount = {};

      debouncedRules.forEach((rule) => {
        const externalPort = Number(rule.externalPort);
        if (Number.isInteger(externalPort) && externalPort >= 1 && externalPort <= 65535) {
          duplicatePortCount[externalPort] = (duplicatePortCount[externalPort] || 0) + 1;
        }
      });

      const rulesToCheck = debouncedRules.filter((rule) => {
        const externalPort = Number(rule.externalPort);

        if (!Number.isInteger(externalPort) || externalPort < 1 || externalPort > 65535) {
          return false;
        }

        if (duplicatePortCount[externalPort] > 1) {
          nextAvailability[rule.localId] = {
            available: false,
            message: "External port is duplicated in this host configuration",
          };
          return false;
        }

        return true;
      });

      setAvailabilityByRuleId(nextAvailability);

      if (rulesToCheck.length === 0) {
        setIsCheckingAvailability(false);
        return;
      }

      setIsCheckingAvailability(true);

      const results = await Promise.all(
        rulesToCheck.map(async (rule) => {
          try {
            const response = await axios.get(
              apiRoutes.checkExternalPortAvailability(Number(rule.externalPort)),
              {
                params: rule.dataId ? { data_id: rule.dataId } : {},
              }
            );

            return {
              localId: rule.localId,
              available: response.data.available,
              message: response.data.message || "",
            };
          } catch (error) {
            return {
              localId: rule.localId,
              available: false,
              message: "Could not verify external port availability",
            };
          }
        })
      );

      if (!isActive) {
        return;
      }

      setAvailabilityByRuleId((current) => {
        const merged = { ...current };

        results.forEach((result) => {
          merged[result.localId] = {
            available: result.available,
            message: result.message,
          };
        });

        return merged;
      });
      setIsCheckingAvailability(false);
    };

    checkAvailability();

    return () => {
      isActive = false;
    };
  }, [opened, debouncedRules]);

  const handleClose = () => {
    if (anyUnsavedChanges) { setDiscardConfirmOpen(true); return; }
    setErrorsByRuleId({});
    setAvailabilityByRuleId({});
    setMachineDetailsErrors({});
    onClose();
  };

  const handleMachineDetailsChange = (field, value) => {
    setMachineDetails((current) => ({ ...current, [field]: value }));
    setMachineDetailsErrors((current) => {
      if (!current[field]) {
        return current;
      }

      const next = { ...current };
      delete next[field];
      return next;
    });
  };

  const handleResetHostnameToClient = () => {
    setMachineDetails((current) => ({
      ...current,
      hostname: clientHostnameValue,
    }));
    setMachineDetailsErrors((current) => {
      if (!current.hostname) {
        return current;
      }

      const next = { ...current };
      delete next.hostname;
      return next;
    });
  };

  const handleSaveMachineDetails = async () => {
    if (!host || !onUpdateMachineDetails || isSavingMachineDetails) {
      return;
    }

    const nextErrors = {};

    if (!machineNameValue) {
      nextErrors.name = "Machine name is required";
    }

    setMachineDetailsErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0 || !machineDetailsChanged) {
      return;
    }

    setIsSavingMachineDetails(true);
    try {
      const saved = await onUpdateMachineDetails(host.id, {
        name: machineNameValue,
        hostname: machineHostnameValue,
      });

      if (saved) {
        setMachineDetailsErrors({});
      }
    } finally {
      setIsSavingMachineDetails(false);
    }
  };

  const updateRule = (localId, field, value) => {
    setRules((currentRules) =>
      currentRules.map((rule) =>
        rule.localId === localId ? { ...rule, [field]: value } : rule
      )
    );

    setErrorsByRuleId((currentErrors) => {
      if (!currentErrors[localId]?.[field]) {
        return currentErrors;
      }

      return {
        ...currentErrors,
        [localId]: {
          ...currentErrors[localId],
          [field]: null,
        },
      };
    });
  };

  const updateRuleFirewall = (localId, updater) => {
    setRules((currentRules) =>
      currentRules.map((rule) => {
        if (rule.localId !== localId) {
          return rule;
        }

        const currentFirewall = {
          isPublic: rule.firewall?.isPublic ?? true,
          allowedIps: normalizeAllowedIps(rule.firewall?.allowedIps),
        };
        const nextFirewall = updater(currentFirewall);
        const normalizedAllowedIps = normalizeAllowedIps(nextFirewall.allowedIps);

        return {
          ...rule,
          firewall: {
            isPublic:
              typeof nextFirewall.isPublic === "boolean"
                ? nextFirewall.isPublic
                : normalizedAllowedIps.length === 0,
            allowedIps:
              (typeof nextFirewall.isPublic === "boolean"
                ? nextFirewall.isPublic
                : normalizedAllowedIps.length === 0)
                ? []
                : normalizedAllowedIps,
          },
        };
      })
    );
  };

  const addAllowedIpToRule = (localId, value) => {
    const normalized = String(value || "").trim();
    if (!isValidIpv4Address(normalized)) {
      error("Use a valid IPv4 address");
      return false;
    }

    updateRuleFirewall(localId, (currentFirewall) => ({
      isPublic: false,
      allowedIps: [...currentFirewall.allowedIps, normalized],
    }));
    setAllowIpDraft("");
    setIsAllowIpPickerOpen(false);
    return true;
  };

  const removeAllowedIpFromRule = (localId, value) => {
    updateRuleFirewall(localId, (currentFirewall) => {
      const nextAllowedIps = normalizeAllowedIps(currentFirewall.allowedIps).filter(
        (item) => item !== value
      );
      return {
        isPublic: nextAllowedIps.length === 0,
        allowedIps: nextAllowedIps,
      };
    });
  };

  const getUniqueRandomPort = async (localIdToExclude = null) => {
    const reservedPorts = new Set(
      rules
        .filter((rule) => rule.localId !== localIdToExclude)
        .map((rule) => Number(rule.externalPort))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
    );

    for (let attempt = 0; attempt < 10; attempt += 1) {
      const response = await axios.get(apiRoutes.getRandomPort);
      const port = Number(response.data?.port);

      if (
        Number.isInteger(port) &&
        port >= 1 &&
        port <= 65535 &&
        !reservedPorts.has(port)
      ) {
        return String(port);
      }
    }

    throw new Error("Could not generate a unique external port");
  };

  const openRuleEditor = (rule) => {
    setPortSection("connection");
    setEditingRuleSnapshot(rule?.dataId ? { ...rule } : null);
    setSelectedRuleId(rule.localId);
  };

  const handleAddRule = async () => {
    setPortSection("connection");
    const nextRule = createEmptyRule();
    setRules((currentRules) => [...currentRules, nextRule]);
    setEditingRuleSnapshot(null);
    setSelectedRuleId(nextRule.localId);
    setRulesPage(Math.ceil((rules.length + 1) / RULES_PER_PAGE));
    setRandomizingRuleId(nextRule.localId);

    try {
      const externalPort = await getUniqueRandomPort(nextRule.localId);
      updateRule(nextRule.localId, "externalPort", externalPort);
    } catch (randomPortError) {
      error(getApiErrorMessage(randomPortError, "Could not generate a random external port"));
    } finally {
      setRandomizingRuleId(null);
    }
  };

  const handleDoneEditing = (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    setEditingRuleSnapshot(null);
    setSelectedRuleId(null);
  };

  const handleCancelEditing = () => {
    if (!selectedRule) {
      return;
    }

    if (editingRuleSnapshot?.localId === selectedRule.localId) {
      setRules((currentRules) =>
        currentRules.map((rule) =>
          rule.localId === selectedRule.localId ? editingRuleSnapshot : rule
        )
      );
      setEditingRuleSnapshot(null);
      setSelectedRuleId(null);
      return;
    }

    setRules((currentRules) =>
      currentRules.filter((rule) => rule.localId !== selectedRule.localId)
    );
    setEditingRuleSnapshot(null);
    setSelectedRuleId(null);

    setErrorsByRuleId((currentErrors) => {
      const nextErrors = { ...currentErrors };
      delete nextErrors[selectedRule.localId];
      return nextErrors;
    });

    setAvailabilityByRuleId((currentAvailability) => {
      const nextAvailability = { ...currentAvailability };
      delete nextAvailability[selectedRule.localId];
      return nextAvailability;
    });
  };

  const handleRemoveRule = (localId) => {
    setRules((currentRules) =>
      currentRules.filter((r) => r.localId !== localId)
    );
    setSelectedRuleId(null);

    setErrorsByRuleId((currentErrors) => {
      const nextErrors = { ...currentErrors };
      delete nextErrors[localId];
      return nextErrors;
    });

    setAvailabilityByRuleId((currentAvailability) => {
      const nextAvailability = { ...currentAvailability };
      delete nextAvailability[localId];
      return nextAvailability;
    });
  };

  const handleGeneratePort = async (localId) => {
    setRandomizingRuleId(localId);

    try {
      const response = await axios.get(apiRoutes.getRandomPort);
      updateRule(localId, "externalPort", String(response.data.port));
    } catch (requestError) {
      error(getApiErrorMessage(requestError, "Could not generate a random external port"));
    } finally {
      setRandomizingRuleId(null);
    }
  };

  const handleCopy = async (label, value) => {
    if (!value) {
      error(`No ${label.toLowerCase()} available`);
      return;
    }

    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const textArea = document.createElement("textarea");
        textArea.value = value;
        textArea.setAttribute("readonly", "");
        textArea.style.position = "fixed";
        textArea.style.top = "-9999px";
        textArea.style.left = "-9999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        const copied = document.execCommand("copy");
        document.body.removeChild(textArea);

        if (!copied) {
          throw new Error("Copy command failed");
        }
      }

      success(`${label} copied`);
    } catch (copyError) {
      error(`Could not copy ${label.toLowerCase()}`);
    }
  };

  const handleOpenDeleteMachineConfirm = () => {
    setIsDeleteMachineConfirmOpen(true);
  };

  const toggleAccordionSection = (section) => {
    setShowGroups((current) => (section === "groups" ? !current : false));
    setShowMachineCredentials((current) =>
      section === "credentials" ? !current : false
    );
    setShowClientLogs((current) => (section === "logs" ? !current : false));
    setShowUptimeHistory((current) => (section === "uptime" ? !current : false));
  };

  const handleToggleMachine = async () => {
    if (!host || !onToggleMachine || isTogglingMachine) {
      return;
    }

    setIsTogglingMachine(true);

    try {
      await onToggleMachine(host.id, !(host.enabled ?? true));
    } finally {
      setIsTogglingMachine(false);
    }
  };

  const handleToggleTelegramAlerts = async () => {
    if (!host || !onToggleTelegramAlerts || isTogglingTelegramAlerts) {
      return;
    }

    setIsTogglingTelegramAlerts(true);

    try {
      await onToggleTelegramAlerts(host.id, !(host.telegramAlertsExcluded ?? false));
    } finally {
      setIsTogglingTelegramAlerts(false);
    }
  };

  const handleAddGroupFromSelect = async (value) => {
    if (!host || !onAddMachineToGroup || !value || groupSaving) {
      return;
    }
    if ((host.groupIds || []).includes(value)) {
      return;
    }
    setGroupSaving(true);
    try {
      await onAddMachineToGroup(host.id, value);
      setGroupQuery("");
      setIsGroupPickerOpen(true);
    } catch (assignError) {
      error(getApiErrorMessage(assignError, "Could not add machine to group"));
    } finally {
      setGroupSaving(false);
    }
  };

  const handleRemoveGroupChip = async (groupId) => {
    if (!host || !onRemoveMachineFromGroup || groupSaving) {
      return;
    }
    setGroupSaving(true);
    try {
      await onRemoveMachineFromGroup(host.id, groupId);
    } catch (assignError) {
      error(getApiErrorMessage(assignError, "Could not remove machine from group"));
    } finally {
      setGroupSaving(false);
    }
  };

  const handleCreateGroupFromQuery = async () => {
    const trimmedQuery = groupQuery.trim();
    if (
      !host ||
      !onCreateGroup ||
      !onAddMachineToGroup ||
      !trimmedQuery ||
      groupSaving
    ) {
      return;
    }

    setGroupSaving(true);
    try {
      const createdGroup = await onCreateGroup(trimmedQuery);
      const createdGroupId = createdGroup?._id;
      if (createdGroupId) {
        await onAddMachineToGroup(host.id, createdGroupId);
      }
      setGroupQuery("");
      setIsGroupPickerOpen(true);
    } catch (createGroupError) {
      error(getApiErrorMessage(createGroupError, "Could not create group"));
    } finally {
      setGroupSaving(false);
    }
  };

  const handleCloseDeleteMachineConfirm = () => {
    if (isDeletingMachine) {
      return;
    }
    setIsDeleteMachineConfirmOpen(false);
  };

  const handleDeleteMachine = async () => {
    if (!host) {
      return;
    }

    setIsDeletingMachine(true);
    try {
      const deleted = await onDeleteMachine(host.id);
      if (deleted) {
        setIsDeleteMachineConfirmOpen(false);
      }
    } finally {
      setIsDeletingMachine(false);
    }
  };

  const handleOpenRefreshMachineTokenConfirm = () => {
    setIsRefreshMachineTokenConfirmOpen(true);
  };

  const handleCloseRefreshMachineTokenConfirm = () => {
    if (isRefreshingMachineToken) {
      return;
    }
    setIsRefreshMachineTokenConfirmOpen(false);
  };

  const handleRefreshMachineToken = async () => {
    if (!host) {
      return;
    }

    setIsRefreshingMachineToken(true);

    try {
      const refreshedHost = await onRefreshMachineToken(host.id);
      if (!refreshedHost) {
        return;
      }

      const response = await axios.get(apiRoutes.getMachineCommand(host.id));
      setMachineCommand(response.data?.data?.command || "");
      setIsRefreshMachineTokenConfirmOpen(false);
    } catch (refreshError) {
      error("Could not refresh machine setup details");
    } finally {
      setIsRefreshingMachineToken(false);
    }
  };

  const handleClientSetupFieldChange = (field, value) => {
    setClientSetupFields((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const reloadMachineCommand = async () => {
    if (!host?.id) {
      return;
    }

    setIsLoadingMachineCommand(true);
    try {
      const response = await axios.get(apiRoutes.getMachineCommand(host.id));
      const setup = response.data?.data?.client_setup || {};
      const defaults = mapClientSetupValues(setup.defaults);
      const overrides = mapClientSetupValues(setup.overrides);
      const fields = {
        publicBaseUrl: overrides.publicBaseUrl || defaults.publicBaseUrl,
        ratholeServerAddress:
          overrides.ratholeServerAddress || defaults.ratholeServerAddress,
        serviceDomain: overrides.serviceDomain || defaults.serviceDomain,
      };
      const command = response.data?.data?.command || "";
      machineCommandPreviewsRef.current = {
        identity: `${host.id}:${host.token || ""}`,
        commands: new Map([[JSON.stringify(getChangedClientSetupValues(fields, defaults)), command]]),
      };
      setMachineCommand(command);
      setClientSetupDefaults(defaults);
      setClientSetupFields(fields);
    } finally {
      setIsLoadingMachineCommand(false);
    }
  };

  const handleSaveClientSetup = async () => {
    if (!host || !onUpdateClientSetup || isSavingClientSetup) {
      return;
    }

    const payload = getChangedClientSetupValues(
      clientSetupFields,
      clientSetupDefaults
    );

    setIsSavingClientSetup(true);
    try {
      const updatedHost = await onUpdateClientSetup(host.id, payload);
      if (updatedHost) {
        await reloadMachineCommand();
      }
    } finally {
      setIsSavingClientSetup(false);
    }
  };

  const handleResetClientSetup = async () => {
    setClientSetupFields(clientSetupDefaults);
  };

  const handleRequestClientUpdate = async () => {
    if (!host || !onRequestClientUpdate || isRequestingClientUpdate) {
      return;
    }

    setIsRequestingClientUpdate(true);

    try {
      await onRequestClientUpdate(host.id);
    } finally {
      setIsRequestingClientUpdate(false);
    }
  };

  const handleRefreshRuleNow = async (rule) => {
    if (!host || !rule?.dataId || !onRefreshConnection || refreshingRuleId) {
      return;
    }

    setRefreshingRuleId(rule.localId);
    try {
      const refreshedConfig = await onRefreshConnection(host.id, rule.dataId);
      if (refreshedConfig) {
        setRules((currentRules) =>
          currentRules.map((currentRule) =>
            currentRule.localId === rule.localId
              ? mapRuleFromConfig(refreshedConfig)
              : currentRule
          )
        );
      }
    } finally {
      setRefreshingRuleId(null);
    }
  };

  const handleSubmit = async (event) => {
    event?.preventDefault();

    if (!host) {
      return;
    }

    const nextErrors = {};

    rules.forEach((rule) => {
      const ruleErrors = getRuleErrors(rule);
      const availability = availabilityByRuleId[rule.localId];

      if (availability && !availability.available) {
        ruleErrors.externalPort = availability.message;
      }

      if (Object.keys(ruleErrors).length > 0) {
        nextErrors[rule.localId] = ruleErrors;
      }
    });

    setErrorsByRuleId(nextErrors);

    if (Object.keys(nextErrors).length > 0 || isCheckingAvailability) {
      if (Object.keys(nextErrors).length) { setSelectedRuleId(Object.keys(nextErrors)[0]); setPortSection("connection"); }
      return false;
    }

    const normalizedRules = rules.map((rule) => ({
      ...rule,
      internalIp: normalizeInternalHost(rule.internalIp),
    }));

    const payload = normalizedRules.map((rule) => ({
      dataId: rule.dataId,
      serviceName: rule.serviceName.trim(),
      serviceDescription: rule.serviceDescription.trim(),
      internalIp: rule.internalIp,
      internalPort: Number(rule.internalPort),
      externalPort: Number(rule.externalPort),
      enabled: rule.enabled,
      autoRefreshEnabled: rule.autoRefreshEnabled ?? false,
      autoRefreshIntervalMinutes: Number(rule.autoRefreshIntervalMinutes) || 60,
      firewall: {
        isPublic:
          normalizeAllowedIps(rule.firewall?.allowedIps).length === 0,
        allowedIps: normalizeAllowedIps(rule.firewall?.allowedIps),
      },
    }));

    const saved = await onSave(host.id, payload);

    if (saved) {
      setRules(normalizedRules);
      initialRulesSnapshotRef.current = rulesSnapshotKey(normalizedRules);
    }
    return Boolean(saved);
  };

  const modalClassNames = { title: "flex-1", body: "!pt-0" };
  const btnSecondary = "!rounded-lg !border-transparent !bg-control !text-foreground hover:!bg-accent";
  const renderAdvancedLabel = (htmlFor, label, tooltip) => (
    <div className="mb-1.5 flex items-center gap-1.5">
      <label
        className={getLabelClassName(isDark).replace("mb-1.5 ", "")}
        htmlFor={htmlFor}
      >
        {label}
      </label>
      <Tooltip
        label={tooltip}
        withArrow
        multiline
        width={260}
        position="top"
        classNames={{
          tooltip: isDark
            ? "!border !border-border !bg-dialog !text-zinc-100"
            : "!border !border-border !bg-dialog !text-zinc-900",
          arrow: isDark
            ? "!border-border !bg-dialog"
            : "!border-border !bg-dialog",
        }}
      >
        <span
          className={
            isDark
              ? "inline-flex text-muted-foreground hover:text-zinc-300"
              : "inline-flex text-zinc-400 hover:text-zinc-600"
          }
        >
          <IconInfoCircle size={14} />
        </span>
      </Tooltip>
    </div>
  );

  return (
    <>
      <WorkspaceDrawer
        animate={false}
        opened={opened}
        trapFocus={!proxyEditorOpen && !discardConfirmOpen}
        onClose={handleClose}
        title={
          host ? (
            <div className="flex w-full items-center justify-between gap-2 pr-2">
              <span className="flex min-w-0 items-center gap-2">
                <span className="truncate">Configure {host.name}</span>
                {anyUnsavedChanges && (
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${
                      isDark
                        ? "bg-amber-500/20 text-amber-300"
                        : "bg-amber-100 text-amber-800"
                    }`}
                  >
                    Unsaved changes
                  </span>
                )}
              </span>

              {!selectedRule ? (
                <Menu position="bottom-end" withinPortal>
                  <Menu.Target>
                    <ActionIcon
                      type="button"
                      variant="subtle"
                      aria-label="Machine actions"
                      className={
                        isDark
                          ? "!h-7 !w-7 !text-muted-foreground hover:!bg-accent"
                          : "!h-7 !w-7 !text-muted-foreground hover:!bg-accent"
                      }
                    >
                      <IconDotsVertical size={16} />
                    </ActionIcon>
                  </Menu.Target>

                  <Menu.Dropdown
                    className={
                      isDark
                        ? "!border-border !bg-dialog"
                        : "!border-border !bg-dialog"
                    }
                  >
                    <Menu.Item
                      onClick={handleToggleMachine}
                      disabled={isTogglingMachine}
                    >
                      {host.enabled === false ? "Enable machine" : "Disable machine"}
                    </Menu.Item>
                    <Menu.Item
                      onClick={handleToggleTelegramAlerts}
                      disabled={isTogglingTelegramAlerts}
                    >
                      {host.telegramAlertsExcluded
                        ? "Include in Telegram alerts"
                        : "Exclude from Telegram alerts"}
                    </Menu.Item>
                    <Menu.Item
                      color="red"
                      onClick={handleOpenDeleteMachineConfirm}
                    >
                      Delete machine
                    </Menu.Item>
                  </Menu.Dropdown>
                </Menu>
              ) : null}
            </div>
          ) : (
            "Configure host"
          )
        }
        centered
        radius="md"
        size="min(960px, calc(100vw - 48px))"
        fixedHeight="min(680px, calc(100dvh - 64px))"
        classNames={modalClassNames}
        closeOnClickOutside={
          !proxyEditorOpen &&
          !isSaving &&
          !isSavingMachineDetails &&
          !isSavingClientSetup
        }
        closeOnEscape={
          !proxyEditorOpen &&
          !isSaving &&
          !isSavingMachineDetails &&
          !isSavingClientSetup
        }
      >
        {host ? (
          <form
            ref={editorFormRef}
            tabIndex={-1}
            onSubmit={async event => {
              event.preventDefault();
              event.stopPropagation();
              if (!selectedRule && machineSection === "groups") handleSaveMachineDetails();
              else if (!selectedRule && machineSection === "credentials") handleSaveClientSetup();
              else if (await handleSubmit(event) && selectedRule) handleDoneEditing();
            }}
            className={`text-foreground !outline-none flex h-full min-h-0 flex-1 flex-col overflow-hidden ${
              isRefreshMachineTokenConfirmOpen || isDeleteMachineConfirmOpen
                ? "pointer-events-none blur-[1px]"
                : ""
            }`}
          >
            <Stack spacing="md" className="min-h-0 flex-1 overflow-hidden">
            <div
              className={`min-h-0 flex-1 overflow-y-auto pr-1 ${
                isDark ? "dark-scrollbar" : "light-scrollbar"
              }`}
            >
            <div className="flex flex-col gap-3">
            {!selectedRule ? <div className="overflow-x-auto pb-1"><StatusTabs label="Machine configuration sections" value={machineSection} onChange={setMachineSection} options={[{value:"ports",label:"Ports"},{value:"groups",label:"Details"},{value:"credentials",label:"Client"},{value:"logs",label:"Logs"},{value:"uptime",label:"History"}]} /></div> : <div className="flex min-w-0 items-center gap-3"><WorkspaceButton type="button" variant="ghost" size="sm" onClick={handleDoneEditing}><IconArrowLeft size={16} />All Ports</WorkspaceButton><span className="text-muted-foreground" aria-hidden="true">/</span><h2 ref={portHeadingRef} tabIndex={-1} className="min-w-0 flex-1 truncate text-base font-semibold !outline-none">{selectedRule.serviceName || "New Port"}</h2><WorkspaceButton type="button" variant="ghost" size="icon" onClick={()=>handleRemoveRule(selectedRule.localId)} className="text-red-600 dark:text-red-400" aria-label="Remove Port"><IconTrash size={16} /></WorkspaceButton></div>}
            {selectedRule && <div className="overflow-x-auto pb-1"><StatusTabs label="Port configuration sections" value={portSection} onChange={setPortSection} options={[{value:"connection",label:"Connection"},{value:"access",label:"Access"},{value:"traffic",label:"Traffic"},{value:"web",label:"Web Addresses"}]} /></div>}
            <div className="flex items-start justify-between gap-3">
              <Group spacing="xs">
                <Badge
                  color={
                    hostConnectionStatus === "online"
                      ? "green"
                      : hostConnectionStatus === "disabled"
                        ? "gray"
                      : hostConnectionStatus === "auth_required"
                        ? "yellow"
                        : "red"
                  }
                  variant="light"
                  className={getStatusBadgeClassName(
                    isDark,
                    hostConnectionStatus === "online"
                      ? "success"
                      : hostConnectionStatus === "disabled"
                        ? "neutral"
                        : hostConnectionStatus === "auth_required"
                          ? "warning"
                          : "danger"
                  )}
                >
                  {hostConnectionStatus === "online"
                    ? "Online"
                    : hostConnectionStatus === "disabled"
                      ? "Disabled"
                    : hostConnectionStatus === "auth_required"
                      ? "Auth required"
                      : "Offline"}
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  {host.name || "Untitled machine"}
                </Badge>
                {privateDomain && <ActionIcon
                  type="button"
                  variant="subtle"
                  size="sm"
                  onClick={() => handleCopy("PortHub domain", privateDomain)}
                  aria-label={`Copy PortHub domain ${privateDomain}`}
                  title={`Copy ${privateDomain}`}
                  className="text-muted-foreground hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
                >
                  <IconCopy size={14} />
                </ActionIcon>}
                <Badge component="button" type="button" color="blue" variant="light"
                  disabled={!host.localIp}
                  onClick={() => handleCopy("LAN IP", host.localIp)}
                  aria-label={host.localIp ? `Copy LAN IP ${host.localIp}` : "LAN IP not reported"}
                  title={host.localIp ? "Copy LAN IP" : "LAN IP not reported"}
                  rightSection={host.localIp ? <IconCopy size={12} /> : null}
                  className={`${getInfoBadgeClassName(isDark)} ${host.localIp ? "cursor-pointer" : "cursor-default"} focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2`}>
                  LAN: {host.localIp || "Not reported"}
                </Badge>
                <Badge component="button" type="button" color="blue" variant="light"
                  disabled={!host.publicIp}
                  onClick={() => handleCopy("WAN IP", host.publicIp)}
                  aria-label={host.publicIp ? `Copy WAN IP ${host.publicIp}` : "WAN IP not reported"}
                  title={host.publicIp ? "Copy WAN IP" : "WAN IP not reported"}
                  rightSection={host.publicIp ? <IconCopy size={12} /> : null}
                  className={`${getInfoBadgeClassName(isDark)} ${host.publicIp ? "cursor-pointer" : "cursor-default"} focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2`}>
                  WAN: {host.publicIp || "Pending"}
                </Badge>
                {privateAddresses?.length ? privateAddresses.map((ip) => (
                  <Badge key={ip} component="button" type="button" color="blue" variant="light"
                    onClick={() => handleCopy("Private IP", ip)}
                    aria-label={`Copy private IP ${ip}`} title="Copy private IP"
                    rightSection={<IconCopy size={12} />}
                    className={`${getInfoBadgeClassName(isDark)} cursor-pointer focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2`}>
                    PAN: {ip}
                  </Badge>
                )) : (
                  <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                    PAN: {privateAddressError ? "Unavailable" : privateAddresses ? "Not enrolled" : "Loading…"}
                  </Badge>
                )}
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  Last seen: {formatCompactLastSeen(host.lastSeenAt)}
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  {host.numPorts} active ports
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  {savedRuleCount} configured rules
                </Badge>
              </Group>

            </div>

            {!selectedRule && machineSection !== "ports" ? (
              <div
                className="rounded-lg bg-control/40"
              >
                <div className="divide-y divide-border/60">
                  <div hidden={machineSection !== "groups"}>
                    <h2 className="px-4 py-3 text-base font-semibold">Machine Details</h2>

                    <div>
                      <div className="space-y-4 px-4 pb-4 pt-1.5">
                        <p className="text-xs text-muted-foreground">
                          Rename the machine and add a description. The reset icon fills this
                          field with the latest hostname reported by the client.
                        </p>

                        <div className="grid gap-3 md:grid-cols-2">
                          <div>
                            <input
                              type="text"
                              aria-label="Machine name"
                              placeholder="Machine name, then optional aliases separated by commas"
                              className={getDetailInputClassName(isDark)}
                              value={machineDetails.name}
                              onChange={(event) =>
                                handleMachineDetailsChange("name", event.currentTarget.value)
                              }
                            />
                            {machineDetailsErrors.name ? (
                              <p className={errorClassName}>{machineDetailsErrors.name}</p>
                            ) : null}
                          </div>

                          <div>
                            <div className="relative">
                              <input
                                type="text"
                                aria-label="Machine description"
                                placeholder="Description"
                                className={`${getDetailInputClassName(isDark)} pr-11`}
                                value={machineDetails.hostname}
                                onChange={(event) =>
                                  handleMachineDetailsChange("hostname", event.currentTarget.value)
                                }
                              />
                              <Tooltip
                                label="Reset to client hostname"
                                withArrow
                                position="top"
                                classNames={{
                                  tooltip: isDark
                                    ? "!border !border-border !bg-dialog !text-zinc-100"
                                    : "!border !border-border !bg-dialog !text-zinc-900",
                                  arrow: isDark
                                    ? "!border-border !bg-dialog"
                                    : "!border-border !bg-dialog",
                                }}
                              >
                                <ActionIcon
                                  type="button"
                                  variant="subtle"
                                  radius="md"
                                  aria-label="Reset description to client hostname"
                                  onClick={handleResetHostnameToClient}
                                  disabled={!clientHostnameValue || isSavingMachineDetails}
                                  className={`!absolute right-1.5 top-1/2 -translate-y-1/2 ${
                                    isDark
                                      ? "!text-zinc-400 hover:!bg-accent hover:!text-zinc-200 disabled:!opacity-35"
                                      : "!text-muted-foreground hover:!bg-accent hover:!text-zinc-700 disabled:!opacity-35"
                                  }`}
                                >
                                  <IconRefresh size={15} />
                                </ActionIcon>
                              </Tooltip>
                            </div>
                            {machineDetailsErrors.hostname ? (
                              <p className={errorClassName}>{machineDetailsErrors.hostname}</p>
                            ) : null}
                          </div>

                        </div>

                        {groups.length > 0 && onAddMachineToGroup && onRemoveMachineFromGroup ? (
                          <div>
                            <p className="mb-2 text-xs text-muted-foreground">
                              Search existing groups, add new ones, or remove assignments for this machine.
                            </p>
                            <Popover
                            opened={isGroupPickerOpen}
                            onChange={setIsGroupPickerOpen}
                            position="bottom-start"
                            offset={2}
                            width="target"
                            withinPortal
                            shadow="md"
                            >
                              <Popover.Target>
                                <div
                                  onClick={() => {
                                    if (groupSaving) {
                                      return;
                                    }
                                    setIsGroupPickerOpen(true);
                                    groupInputRef.current?.focus();
                                  }}
                                  className={`flex min-h-[2.7rem] w-full items-center justify-between gap-3 rounded-md border px-3 py-2 text-left transition ${
                                    isDark
                                      ? "border-transparent bg-control text-foreground"
                                      : "border-transparent bg-control text-foreground"
                                  } ${groupSaving ? "cursor-not-allowed opacity-70" : ""}`}
                                >
                                  <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
                                    {assignedGroups.length > 0 ? (
                                      assignedGroups.map((group) => (
                                        <span
                                          key={group._id}
                                          className={`inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium ${
                                            isDark
                                              ? "border-blue-500/25 bg-blue-500/10 text-blue-100"
                                              : "border-blue-200 bg-blue-50 text-blue-900"
                                          }`}
                                        >
                                          <span className="truncate">{group.name}</span>
                                          <ActionIcon
                                            type="button"
                                            size="xs"
                                            radius="xl"
                                            variant="subtle"
                                            aria-label={`Remove ${group.name}`}
                                            disabled={groupSaving}
                                            onClick={(event) => {
                                              event.preventDefault();
                                              event.stopPropagation();
                                              handleRemoveGroupChip(group._id);
                                            }}
                                            className={
                                              isDark
                                                ? "!h-4 !w-4 !text-blue-200 hover:!bg-blue-400/15"
                                                : "!h-4 !w-4 !text-blue-700 hover:!bg-blue-100"
                                            }
                                          >
                                            <IconX size={11} stroke={2} />
                                          </ActionIcon>
                                        </span>
                                      ))
                                    ) : null}
                              <input
                                ref={groupInputRef}
                                type="text"
                                value={groupQuery}
                                disabled={groupSaving}
                                onFocus={() => setIsGroupPickerOpen(true)}
                                onChange={(event) => {
                                  setGroupQuery(event.currentTarget.value);
                                  setIsGroupPickerOpen(true);
                                }}
                                onKeyDown={(event) => {
                                  if (event.key === "Enter") {
                                    event.preventDefault();
                                    if (filteredAvailableGroups.length > 0) {
                                      handleAddGroupFromSelect(filteredAvailableGroups[0]._id);
                                    } else if (canCreateGroupFromQuery) {
                                      handleCreateGroupFromQuery();
                                    }
                                  }

                                  if (event.key === "Escape") {
                                    setIsGroupPickerOpen(false);
                                  }
                                }}
                                placeholder="Search groups or add new group by pressing Enter"
                                className={`min-w-[7rem] flex-1 appearance-none border-0 bg-transparent p-0 text-sm shadow-none outline-none ring-0 placeholder:text-xs focus:border-0 focus:outline-none focus:ring-0 ${
                                  isDark
                                    ? "text-zinc-100 placeholder:text-muted-foreground"
                                    : "text-zinc-900 placeholder:text-zinc-400"
                                }`}
                              />
                                  </div>
                                  <IconChevronDown
                                    size={16}
                                    className={`shrink-0 ${isDark ? "text-muted-foreground" : "text-zinc-400"}`}
                                  />
                                </div>
                              </Popover.Target>

                              <Popover.Dropdown
                                className={
                                  isDark
                                    ? "!border-border !bg-dialog !p-1.5"
                                    : "!border-border !bg-dialog !p-1.5"
                                }
                              >
                                {canCreateGroupFromQuery ? (
                                  <button
                                    type="button"
                                    disabled={groupSaving}
                                    onClick={handleCreateGroupFromQuery}
                                    className={`mb-1 flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-sm transition ${
                                      isDark
                                        ? "border-transparent bg-control text-foreground hover:bg-accent"
                                        : "border-transparent bg-control text-foreground hover:bg-accent"
                                    }`}
                                  >
                                    <span className="flex min-w-0 items-center gap-2 truncate">
                                      <span
                                        className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${
                                          isDark ? "bg-control text-muted-foreground" : "bg-control text-muted-foreground"
                                        }`}
                                      >
                                        <IconFolder size={14} />
                                      </span>
                                      <span className="truncate font-medium">{groupQuery.trim()}</span>
                                    </span>
                                    <span className="shrink-0 text-xs text-muted-foreground">
                                      Add this group by pressing{" "}
                                      <span
                                        className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-semibold ${
                                          isDark
                                            ? "border-border bg-control text-foreground"
                                            : "border-border bg-control text-foreground"
                                        }`}
                                      >
                                        Enter
                                      </span>
                                    </span>
                                  </button>
                                ) : null}

                                {filteredAvailableGroups.length === 0 ? (
                                  canCreateGroupFromQuery ? null : (
                                    <div
                                      className={`px-2 py-2 text-sm ${
                                        isDark ? "text-muted-foreground" : "text-muted-foreground"
                                      }`}
                                    >
                                      {availableGroups.length === 0
                                        ? "All groups already assigned."
                                        : "No matching groups."}
                                    </div>
                                  )
                                ) : (
                                  <div className="flex max-h-52 flex-col gap-1 overflow-y-auto">
                                    {filteredAvailableGroups.map((group) => (
                                      <button
                                        key={group._id}
                                        type="button"
                                        disabled={groupSaving}
                                        onClick={() => handleAddGroupFromSelect(group._id)}
                                        className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-sm transition ${
                                          isDark
                                            ? "border-transparent bg-control text-foreground hover:bg-accent"
                                            : "border-transparent bg-control text-foreground hover:bg-accent"
                                        }`}
                                      >
                                        <span className="flex min-w-0 items-center gap-2 truncate">
                                          <span
                                            className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${
                                              isDark ? "bg-control text-muted-foreground" : "bg-control text-muted-foreground"
                                            }`}
                                          >
                                            <IconFolder size={14} />
                                          </span>
                                          <span className="truncate">{group.name}</span>
                                        </span>
                                        <span className="flex shrink-0 items-center gap-1.5 text-xs text-muted-foreground">
                                          <IconUsers size={13} />
                                          <span>{group.machineCount || 0} Peer(s)</span>
                                        </span>
                                      </button>
                                    ))}
                                  </div>
                                )}
                              </Popover.Dropdown>
                            </Popover>
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </div>

                  <div hidden={machineSection !== "credentials"}>
                    <h2 className="px-4 py-3 text-base font-semibold">Client Setup</h2>

                    <div>
                      <div className="space-y-1 px-4 pb-2 pt-1.5">
                        <div>
                          <div className="flex items-center gap-1.5">
                            <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                              Bootstrap command
                            </p>
                            <Tooltip
                              label="Refresh machine token"
                              withArrow
                              position="top"
                              classNames={{
                                tooltip: isDark
                                  ? "!border !border-border !bg-dialog !text-zinc-100"
                                  : "!border !border-border !bg-dialog !text-zinc-900",
                                arrow: isDark
                                  ? "!border-border !bg-dialog"
                                  : "!border-border !bg-dialog",
                              }}
                            >
                              <ActionIcon
                                type="button"
                                variant="subtle"
                                onClick={handleOpenRefreshMachineTokenConfirm}
                                aria-label="Refresh machine token"
                                className={
                                  isDark
                                    ? "!h-6 !w-6 !text-zinc-400 hover:!bg-accent hover:!text-zinc-200"
                                    : "!h-6 !w-6 !text-muted-foreground hover:!bg-accent hover:!text-zinc-700"
                                }
                              >
                                <IconRefresh size={14} />
                              </ActionIcon>
                            </Tooltip>
                            <Tooltip
                              label="Copy machine token"
                              withArrow
                              position="top"
                              classNames={{
                                tooltip: isDark
                                  ? "!border !border-border !bg-dialog !text-zinc-100"
                                  : "!border !border-border !bg-dialog !text-zinc-900",
                                arrow: isDark
                                  ? "!border-border !bg-dialog"
                                  : "!border-border !bg-dialog",
                              }}
                            >
                              <ActionIcon
                                type="button"
                                variant="subtle"
                                onClick={() => handleCopy("Machine token", host?.token || "")}
                                aria-label="Copy machine token"
                                disabled={!host?.token}
                                className={
                                  isDark
                                    ? "!h-6 !w-6 !text-zinc-400 hover:!bg-accent hover:!text-zinc-200 disabled:!opacity-40"
                                    : "!h-6 !w-6 !text-muted-foreground hover:!bg-accent hover:!text-zinc-700 disabled:!opacity-40"
                                }
                              >
                                <IconCopy size={14} />
                              </ActionIcon>
                            </Tooltip>
                          </div>
                          <div className="mt-2">
                            <div
                              className={`relative rounded-lg ${
                                isDark ? "bg-control" : "bg-control"
                              }`}
                            >
                              <ActionIcon
                                type="button"
                                variant="subtle"
                                onClick={() => handleCopy("Bootstrap command", machineCommand)}
                                aria-label="Copy bootstrap command"
                                disabled={!machineCommand || isLoadingMachineCommand}
                                className={`!absolute right-2 top-2 ${
                                  isDark
                                    ? "!text-zinc-300 hover:!bg-accent disabled:!bg-transparent"
                                    : "!text-zinc-600 hover:!bg-accent disabled:!bg-transparent"
                                }`}
                              >
                                <IconCopy size={16} />
                              </ActionIcon>
                              <code
                                className={`block break-all rounded-lg px-3 py-3 pr-12 text-xs ${
                                  isDark ? "text-zinc-100" : "text-zinc-800"
                                }`}
                              >
                                {isLoadingMachineCommand && !machineCommand
                                  ? "Loading bootstrap command..."
                                  : machineCommand || "Unavailable"}
                              </code>
                            </div>
                            <p className="mt-2 text-xs text-muted-foreground">
                              Paste once to install and connect. Then use
                              {" "}
                              <code>porthub ls</code>,{" "}
                              <code>porthub status</code>, or{" "}
                              <code>porthub stop</code>
                              {" "}
                              on the client. If multiple accounts are connected, pass the
                              registration ID from
                              {" "}
                              <code>porthub ls</code>
                              {" "}
                              to
                              {" "}
                              <code>status</code>
                              {" "}
                              or
                              {" "}
                              <code>stop</code>.
                            </p>
                            <div
                              className={`mt-3 rounded-md border px-3 py-2.5 ${
                                isDark
                                  ? "border-border bg-control/40"
                                  : "border-border bg-control/40"
                              }`}
                            >
                              <button
                                type="button"
                                className="flex w-full items-center justify-between gap-3 text-left"
                                onClick={() =>
                                  setShowClientSetupAdvanced((current) => !current)
                                }
                                aria-expanded={showClientSetupAdvanced}
                              >
                                <div className="min-w-0">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <p
                                      className={`text-sm font-medium ${
                                        isDark ? "text-zinc-100" : "text-zinc-900"
                                      }`}
                                    >
                                      Advanced settings
                                    </p>
                                    {hasSavedClientSetupOverrides ? (
                                      <Badge
                                        size="xs"
                                        className={getInfoBadgeClassName(isDark)}
                                      >
                                        Enabled
                                      </Badge>
                                    ) : null}
                                  </div>
                                  <p className="mt-0.5 text-xs text-muted-foreground">
                                    Use a different PortHub address for this machine.
                                  </p>
                                </div>
                                {showClientSetupAdvanced ? (
                                  <IconChevronUp
                                    size={18}
                                    className={
                                      isDark ? "text-zinc-400" : "text-zinc-600"
                                    }
                                  />
                                ) : (
                                  <IconChevronDown
                                    size={18}
                                    className={
                                      isDark ? "text-zinc-400" : "text-zinc-600"
                                    }
                                  />
                                )}
                              </button>

                              <div hidden={!showClientSetupAdvanced}>
                                <div className="mt-3 space-y-3">
                                  <div>
                                    {renderAdvancedLabel(
                                      "client-setup-public-base-url",
                                      "PortHub access URL",
                                      "The address this machine uses to reach PortHub. Tunnel and other endpoints are provided by the server automatically."
                                    )}
                                    <input
                                      id="client-setup-public-base-url"
                                      type="url"
                                      value={clientSetupFields.publicBaseUrl}
                                      onChange={(event) =>
                                        handleClientSetupFieldChange(
                                          "publicBaseUrl",
                                          event.target.value
                                        )
                                      }
                                      placeholder={clientSetupDefaults.publicBaseUrl}
                                      className={getDetailInputClassName(isDark)}
                                    />
                                  </div>

                                  <div className="flex flex-wrap justify-end gap-2">
                                    <Button
                                      type="button"
                                      variant="default"
                                      size="xs"
                                      onClick={handleResetClientSetup}
                                      disabled={isSavingClientSetup}
                                      classNames={{ root: btnSecondary }}
                                    >
                                      Reset
                                    </Button>
                                  </div>
                                </div>
                              </div>
                            </div>
                            <div className="mt-1.5 flex items-center gap-1.5">
                              <p
                                className={`text-xs ${
                                  isDark ? "text-zinc-400" : "text-muted-foreground"
                                }`}
                              >
                                Installed client version: {clientVersionLabel}
                                {host?.latestClientVersion ? (
                                  <>
                                    {" · "}
                                    {host.clientUpdateRequested ? (
                                      <span className="text-amber-700 dark:text-amber-400">
                                        Update requested: {latestClientVersionLabel}
                                      </span>
                                    ) : host.clientVersion === host.latestClientVersion ? (
                                      <span className="text-emerald-700 dark:text-emerald-400">
                                        Up to date
                                      </span>
                                    ) : (
                                      <span className="text-amber-700 dark:text-amber-400">
                                        Latest is {latestClientVersionLabel}
                                      </span>
                                    )}
                                  </>
                                ) : null}
                              </p>
                              {showClientUpdateAction ? (
                                <Tooltip
                                  label={
                                    host.clientUpdateRequested
                                      ? "Update client"
                                      : host.clientUpdateAvailable
                                        ? "Update client"
                                        : "Update client"
                                  }
                                  withArrow
                                  position="top"
                                  classNames={{
                                    tooltip: isDark
                                      ? "!border !border-border !bg-dialog !text-zinc-100"
                                      : "!border !border-border !bg-dialog !text-zinc-900",
                                    arrow: isDark
                                      ? "!border-border !bg-dialog"
                                      : "!border-border !bg-dialog",
                                  }}
                                >
                                  <ActionIcon
                                    type="button"
                                    variant="subtle"
                                    onClick={handleRequestClientUpdate}
                                    aria-label="Update client"
                                    disabled={isRequestingClientUpdate}
                                    className={
                                      host.clientUpdateRequested
                                        ? isDark
                                          ? "!h-5 !w-5 !text-amber-300/90 hover:!bg-accent"
                                          : "!h-5 !w-5 !text-amber-700/90 hover:!bg-accent"
                                        : isDark
                                          ? "!h-5 !w-5 !text-muted-foreground hover:!bg-accent hover:!text-zinc-300"
                                          : "!h-5 !w-5 !text-zinc-400 hover:!bg-accent hover:!text-zinc-600"
                                    }
                                  >
                                    <IconRefresh size={12} />
                                  </ActionIcon>
                                </Tooltip>
                              ) : null}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div hidden={machineSection !== "logs"}>
                    <h2 className="px-4 py-3 text-base font-semibold">Client Logs</h2>

                    <div>
                      <div className="space-y-3 px-4 py-4">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                            Live stream
                          </p>
                          <div className="flex items-center gap-3">
                            <Switch
                              size="xs"
                              checked={showClientLogLineNumbers}
                              onChange={(event) =>
                                setShowClientLogLineNumbers(event.currentTarget.checked)
                              }
                              labelPosition="left"
                              label="Line numbers"
                            />
                            <Switch
                              size="xs"
                              checked={showVerboseClientLogs}
                              onChange={(event) =>
                                setShowVerboseClientLogs(event.currentTarget.checked)
                              }
                              labelPosition="left"
                              label="Verbose"
                            />
                          </div>
                        </div>

                        <div
                          ref={clientLogsContainerRef}
                          onScroll={handleClientLogsScroll}
                          className="max-h-72 overflow-y-auto rounded-lg bg-control px-3 py-3 font-mono text-xs text-foreground"
                        >
                          {visibleClientLogs.length > 0 ? (
                            <div className="space-y-0.5">
                              {visibleClientLogs.map((entry) => (
                                <div
                                  key={entry.number}
                                  className={
                                    showClientLogLineNumbers
                                      ? "grid grid-cols-[42px_minmax(0,1fr)] gap-2"
                                      : "block"
                                  }
                                >
                                  {showClientLogLineNumbers ? (
                                    <span
                                      className={`select-none text-right ${
                                        isDark ? "text-muted-foreground" : "text-zinc-400"
                                      }`}
                                    >
                                      {entry.number}
                                    </span>
                                  ) : null}
                                  <span className="whitespace-pre-wrap break-words">
                                    {entry.text}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className={isDark ? "text-zinc-400" : "text-muted-foreground"}>
                              {clientLogs.length > 0
                                ? "Verbose logs are currently hidden. Enable the verbose toggle to view them."
                                : clientLogStreamStatus === "offline"
                                  ? "The client must be online before logs can be streamed."
                                : showClientLogs
                                  ? "Fetching logs from the client..."
                                  : "Fetching logs from the client..."}
                            </p>
                          )}
                        </div>

                        <p className="text-xs text-muted-foreground">
                          Shows the same combined PortHub client and Rathole log stream
                          available on the client via <code>porthub logs</code>. Turn on
                          verbose to include debug noise.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div hidden={machineSection !== "uptime"}>
                    <div>
                      <div className="pt-1">
                        <UptimeHistoryPanel
                          isDark={isDark}
                          events={uptimeEvents}
                          currentStatus={
                            host?.isActive === undefined
                              ? uptimeCurrentStatus
                              : host.isActive
                                ? "online"
                                : "offline"
                          }
                          isLoading={isLoadingUptimeHistory}
                          days={365}
                        />
                      </div>
                    </div>
                  </div>

                </div>
              </div>
            ) : null}

            {selectedRule ? (
              /* Edit view: only the form for the selected rule */
              (() => {
                const rule = selectedRule;
                const ruleErrors = errorsByRuleId[rule.localId] || {};
                const availability = availabilityByRuleId[rule.localId];
                const persistedRule = rule.dataId ? savedRulesById.get(rule.dataId) : null;
                const ruleHasUnsavedChanges = !persistedRule ||
                  JSON.stringify(normalizeRuleForCompare(persistedRule)) !==
                    JSON.stringify(normalizeRuleForCompare(rule));
                const allowedIps = normalizeAllowedIps(rule.firewall?.allowedIps);
                const recentIpHits = allowIpRecentHitsByRuleId[rule.localId] || [];
                const filteredRecentIpHits = [
                  ...(!allowedIps.includes("127.0.0.1")
                    ? [{ ip: "127.0.0.1", last_seen: null }]
                    : []),
                  ...recentIpHits.filter(
                    (item) =>
                      item.ip !== "127.0.0.1" &&
                      !allowedIps.includes(item.ip) &&
                      (!allowIpDraft.trim() || item.ip.includes(allowIpDraft.trim()))
                  ),
                ];

                return (
                  <div className="space-y-5">
                    {portSection === "connection" && <div className="space-y-5">
                      <PortField id={`service-name-${rule.localId}`} label="Service name" value={rule.serviceName} onChange={value=>updateRule(rule.localId,"serviceName",value)} error={ruleErrors.serviceName} placeholder="e.g. SSH or Web app" />
                      <label className="block text-sm font-medium" htmlFor={`service-description-${rule.localId}`}>Description<textarea aria-label="Description" id={`service-description-${rule.localId}`} rows={2} className="mt-2 w-full resize-y rounded-lg border-0 bg-control p-3 text-sm !outline-none" value={rule.serviceDescription} onChange={event=>updateRule(rule.localId,"serviceDescription",event.target.value)} placeholder="What does this service do?" /></label>
                      <div className="grid gap-4 sm:grid-cols-3"><PortField id={`internal-ip-${rule.localId}`} label="Internal host / IP" value={rule.internalIp} onChange={value=>updateRule(rule.localId,"internalIp",value)} error={ruleErrors.internalIp} placeholder="127.0.0.1" /><PortField id={`internal-port-${rule.localId}`} label="Internal port" value={rule.internalPort} onChange={value=>updateRule(rule.localId,"internalPort",value)} error={ruleErrors.internalPort} inputMode="numeric" /><div><PortField id={`external-port-${rule.localId}`} label="External port" value={rule.externalPort} onChange={value=>updateRule(rule.localId,"externalPort",value)} error={ruleErrors.externalPort || (availability?.available === false ? availability.message : "")} inputMode="numeric" /><WorkspaceButton type="button" variant="ghost" size="sm" disabled={randomizingRuleId === rule.localId} aria-label="Generate random external port" onClick={()=>handleGeneratePort(rule.localId)}><IconRefresh size={14} />Choose available port</WorkspaceButton></div></div>
                      <div className="rounded-lg bg-surface p-4"><div className="flex items-center justify-between gap-4"><div><h3 className="text-sm font-medium">Scheduled Refresh</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Reconnect this service periodically.</p></div><Switch size="sm" checked={rule.autoRefreshEnabled || false} onChange={event=>updateRule(rule.localId,"autoRefreshEnabled",event.currentTarget.checked)} aria-label={rule.autoRefreshEnabled ? "Disable service auto refresh" : "Enable service auto refresh"} /></div><div className="mt-4 flex flex-wrap items-end gap-3">{rule.autoRefreshEnabled && <PortField id={`auto-refresh-interval-${rule.localId}`} label="Refresh interval (minutes)" value={rule.autoRefreshIntervalMinutes} onChange={value=>updateRule(rule.localId,"autoRefreshIntervalMinutes",value)} error={ruleErrors.autoRefreshIntervalMinutes} inputMode="numeric" />}<WorkspaceButton type="button" variant="secondary" disabled={!rule.dataId || rule.enabled === false || ruleHasUnsavedChanges || !!refreshingRuleId} onClick={()=>handleRefreshRuleNow(rule)}><IconRefresh size={15} />{refreshingRuleId === rule.localId ? "Refreshing…" : "Refresh Now"}</WorkspaceButton></div></div>
                    </div>}
                    {portSection === "access" && <div className="space-y-4"><div><h3 className="text-base font-semibold">Source IP Access</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">Leave the list empty for public access. Add IP addresses to restrict who can reach this port.</p></div><div className="flex flex-wrap gap-2">{allowedIps.map(ip=><span key={ip} className="inline-flex items-center gap-2 rounded-md bg-surface px-3 py-2 text-sm">{ip}<button type="button" aria-label={`Remove ${ip}`} onClick={()=>removeAllowedIpFromRule(rule.localId,ip)} className="rounded text-muted-foreground hover:text-foreground"><IconX size={14} /></button></span>)}</div><div className="flex gap-2"><WorkspaceInput aria-label="Allowed source IP" className="bg-control" value={allowIpDraft} onChange={event=>setAllowIpDraft(event.target.value)} placeholder="e.g. 192.0.2.10" onKeyDown={event=>{if(event.key==="Enter"){event.preventDefault();addAllowedIpToRule(rule.localId,allowIpDraft);}}} /><WorkspaceButton type="button" disabled={!allowIpDraft.trim()} onClick={()=>addAllowedIpToRule(rule.localId,allowIpDraft)}>Add IP</WorkspaceButton></div><div><h4 className="mb-2 text-xs font-medium text-muted-foreground">Recent source addresses</h4><div className="flex flex-wrap gap-2">{filteredRecentIpHits.slice(0,10).map(item=><WorkspaceButton type="button" key={item.ip} size="sm" variant="secondary" onClick={()=>addAllowedIpToRule(rule.localId,item.ip)}>{item.ip}<IconPlus size={13} /></WorkspaceButton>)}{!filteredRecentIpHits.length && <p className="text-xs text-muted-foreground">No additional addresses observed.</p>}</div></div></div>}
                    {portSection === "traffic" && <TrafficMonitorPanel isDark={isDark} samples={samplesByConnection.get(rule.dataId) || []} isLoading={allPortTraffic.loading} onOpenExternal={()=>openTrafficMonitorWindow(rule)} title={`${rule.serviceName || "Port"} Traffic`} />}
                    {portSection === "web" && <div><p className="mb-4 text-sm text-muted-foreground">Web addresses that route to this port. Changes here also appear on the Proxies page.</p>{rule.dataId ? <Proxy key={`${host.id}-${rule.dataId}`} machineId={host.id} connectionId={rule.dataId} onEditorOpenChange={setProxyEditorOpen} compact /> : <p className="rounded-lg bg-surface p-4 text-sm">Save this port first, then connect a web address to it.</p>}</div>}
                  </div>
                );
              })()
            ) : (
              <div className={machineSection === "ports" ? "flex min-h-0 flex-1 flex-col gap-3" : "hidden"}>
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0"><h2 ref={portsHeadingRef} tabIndex={-1} className="text-base font-semibold !outline-none">Forwarded Ports</h2><p className="mt-1 hidden text-xs text-muted-foreground sm:block">Live traffic and linked web addresses for every port.</p></div>
                  <WorkspaceButton type="button" onClick={handleAddRule}><IconPlus size={16} />Add Port</WorkspaceButton>
                </div>
                {allPortTraffic.error && <p role="status" className="text-xs text-amber-700 dark:text-amber-300">{allPortTraffic.error}</p>}
                <div className="min-h-0 overflow-auto rounded-lg bg-surface">
                  <Table aria-label="Forwarded ports"><TableHeader><TableRow><TableHead>Service</TableHead><TableHead className="hidden w-[19%] md:table-cell">Forwarding</TableHead><TableHead className="w-36 md:w-44">Live Traffic</TableHead><TableHead className="hidden w-[25%] md:table-cell">Web Addresses</TableHead><TableHead className="w-20"><span className="sr-only">Enabled</span></TableHead></TableRow></TableHeader><TableBody>
                    {paginatedRules.map(rule => {
                      const addresses = linkedProxies.filter(proxy => (proxy.connection?.data_id || proxy.connection?._id) === rule.dataId);
                      const openAddresses = event => { event.stopPropagation(); openRuleEditor(rule); setPortSection("web"); };
                      return <TableRow key={rule.localId} className="cursor-pointer" onClick={()=>openRuleEditor(rule)}>
                        <TableCell className="!py-2"><button type="button" aria-label={`Edit forwarding rule ${rule.serviceName.trim() || "untitled rule"}`} className="block max-w-full text-left"><span className="block truncate text-sm font-medium">{rule.serviceName || "Untitled service"}</span><span className="mt-1 hidden truncate text-xs text-muted-foreground md:block">{rule.serviceDescription || `Port ${rule.externalPort}`}</span></button><p className="mt-1 text-xs text-muted-foreground md:hidden">{externalEndpoint(rule)} → {internalEndpoint(rule)}</p><div className="md:hidden">{gatewayLink(rule)}</div><button type="button" onClick={openAddresses} className="mt-1 max-w-full truncate text-left text-xs text-blue-700 dark:text-blue-300 md:hidden">{addresses[0]?.hosts?.[0] || "Add web address"}</button></TableCell>
                        <TableCell className="hidden md:table-cell !py-2"><p className="font-mono text-xs">{externalEndpoint(rule)} → {internalEndpoint(rule)}</p></TableCell>
                        <TableCell className="!py-2"><TrafficSparkline dense samples={samplesByConnection.get(rule.dataId) || []} label={`${rule.serviceName} port traffic`} /></TableCell>
                        <TableCell className="hidden md:table-cell"><div className="space-y-1">{addresses.slice(0,2).map(proxy=><a key={proxy._id} href={`${proxy.entry_points?.includes("websecure") ? "https" : "http"}://${proxy.hosts?.[0]}`} target="_blank" rel="noreferrer" onClick={event=>event.stopPropagation()} className="block truncate text-xs text-blue-700 hover:underline dark:text-blue-300" title={proxy.hosts?.join(", ")}>{proxy.hosts?.[0] || proxy.name}</a>)}{gatewayLink(rule)}<button type="button" onClick={openAddresses} className="text-xs text-muted-foreground hover:text-foreground">{addresses.length ? addresses.length > 2 ? `Manage ${addresses.length} addresses` : "Manage addresses" : "+ Add web address"}</button></div></TableCell>
                        <TableCell><div onClick={event=>event.stopPropagation()}><Switch size="sm" checked={rule.enabled} onChange={event=>updateRule(rule.localId,"enabled",event.currentTarget.checked)} aria-label={rule.enabled ? "Disable forwarding rule" : "Enable forwarding rule"} /></div></TableCell>
                      </TableRow>;
                    })}
                  </TableBody></Table>
                  {!rules.length && <p className="px-4 py-8 text-center text-sm text-muted-foreground">Add a port to expose a service on this machine.</p>}
                  {rules.length > RULES_PER_PAGE && <div className="flex justify-end border-t border-border p-3"><Pagination value={rulesPage} onChange={setRulesPage} total={totalRulePages} size="sm" siblings={0} /></div>}
                </div>
              </div>
            )}
            </div>
            </div>

            <Group position="right" data-dialog-footer>
              <span className={`mr-auto text-xs ${anyUnsavedChanges ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground"}`} role="status">{savingSection ? "Saving…" : anyUnsavedChanges ? "Unsaved changes" : "All changes saved"}</span>
              {selectedRule ? (
                /* Saving applies the edit immediately; no second save step. */
                <>
                  <WorkspaceButton
                    type="button"
                    variant="secondary"
                    onClick={handleCancelEditing}
                    disabled={isSaving}
                  >
                    Cancel
                  </WorkspaceButton>
                  <WorkspaceButton
                    type="button"
                    onClick={async event => { if (await handleSubmit(event)) handleDoneEditing(); }}
                    disabled={selectedRuleHasErrors || isSaving || isCheckingAvailability || !hasUnsavedChanges}
                  >
                    {isSaving ? "Saving…" : "Save Changes"}
                  </WorkspaceButton>
                </>
              ) : (
                <>
                  <WorkspaceButton
                    type="button"
                    variant="secondary"
                    onClick={handleClose}
                    disabled={savingSection}
                  >
                    Close
                  </WorkspaceButton>
                  {machineSection === "ports" && hasUnsavedChanges && <WorkspaceButton type="submit" disabled={isSaving || isCheckingAvailability}>{isSaving ? "Saving…" : "Save Changes"}</WorkspaceButton>}
                  {machineSection === "groups" && <WorkspaceButton type="button" onClick={handleSaveMachineDetails} disabled={isSavingMachineDetails || !machineDetailsChanged || !machineNameValue}>{isSavingMachineDetails ? "Saving…" : "Save Details"}</WorkspaceButton>}
                  {machineSection === "credentials" && clientSetupChanged && <WorkspaceButton type="button" onClick={handleSaveClientSetup} disabled={isSavingClientSetup}>{isSavingClientSetup ? "Saving…" : "Save Client Settings"}</WorkspaceButton>}
                </>
              )}
            </Group>
            </Stack>
          </form>
        ) : (
          <Text
            size="sm"
            className={isDark ? "!text-zinc-400" : "!text-zinc-600"}
          >
            Select a host to configure port forwarding.
          </Text>
        )}
      </WorkspaceDrawer>

      <Modal opened={discardConfirmOpen} onClose={() => setDiscardConfirmOpen(false)} title="Discard Unsaved Changes?" size="sm">
        <p className="text-sm leading-6 text-muted-foreground">Your changes have not been applied to this machine. Keep editing or discard them before closing.</p>
        <div className="mt-5 flex justify-end gap-2"><WorkspaceButton variant="secondary" onClick={() => setDiscardConfirmOpen(false)}>Keep Editing</WorkspaceButton><WorkspaceButton variant="destructive" onClick={() => { setDiscardConfirmOpen(false); onClose(); }}>Discard Changes</WorkspaceButton></div>
      </Modal>

      <Modal
        opened={isRefreshMachineTokenConfirmOpen}
        onClose={handleCloseRefreshMachineTokenConfirm}
        title="Refresh machine token"
        centered
        radius="md"
        size="sm"
        classNames={modalClassNames}
        closeOnClickOutside={!isRefreshingMachineToken}
      >
        <div className={isDark ? "text-zinc-100" : "text-zinc-900"}>
          <Text
            size="sm"
            className={isDark ? "!text-zinc-300" : "!text-zinc-700"}
          >
            Refreshing the machine token will remove authentication for the
            already configured client.
          </Text>
          <Text
            size="sm"
            className={isDark ? "!mt-2 !text-zinc-400" : "!mt-2 !text-zinc-600"}
          >
            The client will need the new token before it can sync again.
          </Text>

          <div className="mt-5 flex justify-end gap-3">
            <WorkspaceButton
              type="button"
              variant="secondary"
              onClick={handleCloseRefreshMachineTokenConfirm}
              disabled={isRefreshingMachineToken}
            >
              Cancel
            </WorkspaceButton>
            <WorkspaceButton
              type="button"
              variant="destructive"
              onClick={handleRefreshMachineToken}
              disabled={isRefreshingMachineToken}
            >
              Refresh machine token
            </WorkspaceButton>
          </div>
        </div>
      </Modal>

      <Modal
        opened={isDeleteMachineConfirmOpen}
        onClose={handleCloseDeleteMachineConfirm}
        title="Delete machine"
        centered
        radius="md"
        size="sm"
        classNames={modalClassNames}
        closeOnClickOutside={!isDeletingMachine}
      >
        <div className={isDark ? "text-zinc-100" : "text-zinc-900"}>
          <Text
            size="sm"
            className={isDark ? "!text-zinc-300" : "!text-zinc-700"}
          >
            Delete this machine and all configured port pairs attached to it.
          </Text>
          <Text
            size="sm"
            className={isDark ? "!mt-2 !text-zinc-400" : "!mt-2 !text-zinc-600"}
          >
            This action cannot be undone.
          </Text>

          <div className="mt-5 flex justify-end gap-3">
            <WorkspaceButton
              type="button"
              variant="secondary"
              onClick={handleCloseDeleteMachineConfirm}
              disabled={isDeletingMachine}
            >
              Cancel
            </WorkspaceButton>
            <WorkspaceButton
              type="button"
              variant="destructive"
              onClick={handleDeleteMachine}
              disabled={isDeletingMachine}
            >
              Delete machine
            </WorkspaceButton>
          </div>
        </div>
      </Modal>
    </>
  );
}
