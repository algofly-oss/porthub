import { useContext, useEffect, useRef, useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Collapse,
  Group,
  Menu,
  Modal,
  Pagination,
  Select,
  Stack,
  Switch,
  Text,
  Tooltip,
  useMantineColorScheme,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import {
  IconArrowLeft,
  IconChevronDown,
  IconChevronUp,
  IconCopy,
  IconDotsVertical,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconX,
} from "@tabler/icons-react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";
import useToast from "@/shared/hooks/useToast";
import { SocketContext } from "@/shared/contexts/socket";
import socketRoutes from "@/shared/routes/socketRoutes";

const getInputClassName = (isDark) =>
  `w-full rounded-md border px-3 py-2 text-sm outline-none transition-colors focus:!border-blue-500 focus:ring-0 ${
    isDark
      ? "!border-zinc-600 !bg-zinc-800 !text-zinc-100 placeholder:!text-zinc-500"
      : "!border-zinc-300 !bg-zinc-50 !text-zinc-900 placeholder:!text-zinc-400"
  }`;

const getLabelClassName = (isDark) =>
  `mb-1.5 block text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`;

const errorClassName = "mt-1 text-xs text-red-600 dark:text-red-400";

const getInfoBadgeClassName = (isDark) =>
  isDark
    ? "!bg-blue-500/10 !text-blue-200/75"
    : "!bg-blue-100/45 !text-blue-900/65";

const getStatusBadgeClassName = (isDark, tone) => {
  if (tone === "success") {
    return isDark
      ? "!bg-emerald-500/14 !text-emerald-200/80"
      : "!bg-emerald-100/55 !text-emerald-900/70";
  }

  if (tone === "warning") {
    return isDark
      ? "!bg-amber-500/14 !text-amber-200/82"
      : "!bg-amber-100/60 !text-amber-900/72";
  }

  if (tone === "danger") {
    return isDark
      ? "!bg-red-500/12 !text-red-200/78"
      : "!bg-red-100/55 !text-red-900/68";
  }

  return isDark
    ? "!bg-zinc-500/14 !text-zinc-200/78"
    : "!bg-zinc-100/80 !text-zinc-900/62";
};

const createRuleId = () =>
  `rule-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

const createEmptyRule = (externalPort = "") => ({
  localId: createRuleId(),
  dataId: null,
  serviceName: "",
  serviceDescription: "",
  internalIp: "0.0.0.0",
  internalPort: "3000",
  externalPort: externalPort ? String(externalPort) : "",
  enabled: true,
});

const mapRuleFromConfig = (config) => ({
  localId: config.dataId || createRuleId(),
  dataId: config.dataId || null,
  serviceName: config.serviceName || "",
  serviceDescription: config.serviceDescription || "",
  internalIp: config.internalIp || config.internal_ip || "0.0.0.0",
  internalPort: String(config.internalPort || 3000),
  externalPort: String(config.externalPort || 3000),
  enabled: config.enabled ?? true,
});

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

const getApiErrorMessage = (requestError, fallbackMessage) =>
  requestError?.response?.data?.detail || fallbackMessage;

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
});

const rulesSnapshotKey = (rules) =>
  JSON.stringify(rules.map(normalizeRuleForCompare));

const RULES_PER_PAGE = 5;
const MAX_CLIENT_LOG_LINES = 2000;
const CLIENT_LOG_AUTO_SCROLL_THRESHOLD = 24;

export default function HostConfigPopup({
  host,
  opened,
  onClose,
  onSave,
  onDeleteMachine,
  onToggleMachine,
  onRefreshMachineToken,
  onRequestClientUpdate,
  onAddMachineToGroup,
  onRemoveMachineFromGroup,
  groups = [],
  isSaving,
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const { success, error } = useToast();
  const socket = useContext(SocketContext);

  const [rules, setRules] = useState([]);
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [errorsByRuleId, setErrorsByRuleId] = useState({});
  const [availabilityByRuleId, setAvailabilityByRuleId] = useState({});
  const [isCheckingAvailability, setIsCheckingAvailability] = useState(false);
  const [randomizingRuleId, setRandomizingRuleId] = useState(null);
  const [machineCommand, setMachineCommand] = useState("");
  const [isLoadingMachineCommand, setIsLoadingMachineCommand] = useState(false);
  const [isRefreshingMachineToken, setIsRefreshingMachineToken] = useState(false);
  const [isRequestingClientUpdate, setIsRequestingClientUpdate] = useState(false);
  const [isTogglingMachine, setIsTogglingMachine] = useState(false);
  const [isRefreshMachineTokenConfirmOpen, setIsRefreshMachineTokenConfirmOpen] =
    useState(false);
  const [isDeleteMachineConfirmOpen, setIsDeleteMachineConfirmOpen] =
    useState(false);
  const [isDeletingMachine, setIsDeletingMachine] = useState(false);
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
  const [debouncedRules] = useDebouncedValue(rules, 300);
  const initialRulesSnapshotRef = useRef("");
  const clientLogsContainerRef = useRef(null);
  const previousHostIdRef = useRef(null);

  const selectedRule = rules.find((rule) => rule.localId === selectedRuleId) || null;
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
      setShowMachineCredentials(false);
      setShowClientLogs(false);
      setShowVerboseClientLogs(false);
      setShowClientLogLineNumbers(false);
      setClientLogs([]);
      setClientLogStartLineNumber(1);
      setClientLogStreamStatus("idle");
      setShouldAutoScrollClientLogs(true);
      setIsRefreshMachineTokenConfirmOpen(false);
      setIsDeleteMachineConfirmOpen(false);
      setEditingRuleSnapshot(null);
      setRulesPage(1);
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
      setShowMachineCredentials(false);
      setShowClientLogs(false);
      setShowVerboseClientLogs(false);
      setShowClientLogLineNumbers(false);
      setClientLogs([]);
      setClientLogStartLineNumber(1);
      setClientLogStreamStatus("idle");
      setShouldAutoScrollClientLogs(true);
      setIsRefreshMachineTokenConfirmOpen(false);
      setIsDeleteMachineConfirmOpen(false);
      setEditingRuleSnapshot(null);
      setRulesPage(1);
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
  }, [host?.id, host?.forwardingConfigs]);

  useEffect(() => {
    if (!opened || !host?.id) {
      setMachineCommand("");
      setIsLoadingMachineCommand(false);
      return;
    }

    let isActive = true;

    const loadMachineCommand = async () => {
      setIsLoadingMachineCommand(true);

      try {
        const response = await axios.get(apiRoutes.getMachineCommand(host.id));
        if (isActive) {
          setMachineCommand(response.data?.data?.command || "");
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
    };
  }, [opened, host?.id]);

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
    setErrorsByRuleId({});
    setAvailabilityByRuleId({});
    onClose();
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
    setEditingRuleSnapshot(rule?.dataId ? { ...rule } : null);
    setSelectedRuleId(rule.localId);
  };

  const handleAddRule = async () => {
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

  const handleSubmit = async (event) => {
    event.preventDefault();

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
      return;
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
    }));

    const saved = await onSave(host.id, payload);

    if (saved) {
      setRules(normalizedRules);
      initialRulesSnapshotRef.current = rulesSnapshotKey(normalizedRules);
    }
  };

  const modalClassNames = isDark
    ? {
        content: "!border !border-zinc-700 !bg-zinc-900",
        header: "!border-b !border-zinc-800 !bg-zinc-900",
        title: "font-bold !text-zinc-100",
        close: "!text-zinc-400 hover:!bg-zinc-800",
        body: "!bg-zinc-900 !pt-3",
      }
    : {
        content: "!border !border-zinc-200 !bg-white",
        header: "!border-b !border-zinc-200 !bg-white",
        title: "font-bold !text-zinc-900",
        close: "!text-zinc-500 hover:!bg-zinc-100",
        body: "!bg-white !pt-3",
      };

  const btnSecondary = isDark
    ? "!border-zinc-700 !bg-zinc-800 !text-zinc-100 hover:!bg-zinc-700"
    : "!border-zinc-300 !bg-white !text-zinc-900 hover:!bg-zinc-50";

  return (
    <>
      <Modal
        opened={opened}
        onClose={handleClose}
        title={
          host ? (
            <span className="flex items-center gap-2">
              Configure {host.name}
              {hasUnsavedChanges && (
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
          ) : (
            "Configure host"
          )
        }
        centered
        radius="md"
        size="lg"
        overlayProps={{ blur: 3 }}
        classNames={modalClassNames}
        closeOnClickOutside={false}
      >
        {host ? (
          <form
            onSubmit={handleSubmit}
            className={`${isDark ? "text-zinc-100" : "text-zinc-900"} flex max-h-[calc(100vh-12rem)] flex-col overflow-hidden transition ${
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
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  LAN: {host.localIp || "Pending"}
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  WAN: {host.publicIp || "Pending"}
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  Last seen: {host.lastSeen || "Never seen"}
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  {host.numPorts} active ports
                </Badge>
                <Badge color="blue" variant="light" className={getInfoBadgeClassName(isDark)}>
                  {savedRuleCount} configured rules
                </Badge>
              </Group>

              <div className="flex items-center gap-1">
                {!selectedRule ? (
                  <Menu position="bottom-end" withinPortal>
                    <Menu.Target>
                      <ActionIcon
                        type="button"
                        variant="subtle"
                        aria-label="Machine actions"
                        className={
                          isDark
                            ? "!text-zinc-300 hover:!bg-zinc-800"
                            : "!text-zinc-600 hover:!bg-zinc-100"
                        }
                      >
                        <IconDotsVertical size={16} />
                      </ActionIcon>
                    </Menu.Target>

                    <Menu.Dropdown
                      className={
                        isDark
                          ? "!border-zinc-700 !bg-zinc-900"
                          : "!border-zinc-200 !bg-white"
                      }
                    >
                      <Menu.Item
                        onClick={handleToggleMachine}
                        disabled={isTogglingMachine}
                      >
                        {host.enabled === false ? "Enable machine" : "Disable machine"}
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
            </div>

            {groups.length > 0 && onAddMachineToGroup && onRemoveMachineFromGroup ? (
              <div
                className={`rounded-lg border px-4 py-3 ${
                  isDark ? "border-zinc-700 bg-zinc-950/50" : "border-zinc-200 bg-zinc-50/80"
                }`}
              >
                <Text size="sm" weight={600} className={isDark ? "text-zinc-200" : "text-zinc-800"}>
                  Groups
                </Text>
                <Text size="xs" className={`mt-1 ${isDark ? "text-zinc-500" : "text-zinc-500"}`}>
                  Use the list to add a folder. Remove opens that membership only.
                </Text>

                <div className="mt-3 flex flex-wrap gap-2">
                  {(host.groupIds || []).length === 0 ? (
                    <Text size="sm" className={isDark ? "text-zinc-500" : "text-zinc-500"}>
                      Not in any group yet.
                    </Text>
                  ) : (
                    (host.groupIds || []).map((gid) => {
                      const g = groups.find((x) => x._id === gid);
                      const label = g?.name || gid;
                      return (
                        <div
                          key={gid}
                          className={`inline-flex max-w-full items-center gap-1 rounded-md border px-2.5 py-1 text-sm font-medium ${
                            isDark
                              ? "border-blue-500/35 bg-blue-950/55 text-blue-100"
                              : "border-blue-200/90 bg-blue-50 text-blue-900"
                          }`}
                        >
                          <span className="min-w-0 truncate">{label}</span>
                          <ActionIcon
                            type="button"
                            size="xs"
                            radius="xl"
                            variant="subtle"
                            color="gray"
                            aria-label={`Remove ${label}`}
                            disabled={groupSaving}
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              handleRemoveGroupChip(gid);
                            }}
                            className={
                              isDark
                                ? "!h-6 !w-6 shrink-0 !text-blue-200 hover:!bg-blue-900/80"
                                : "!h-6 !w-6 shrink-0 !text-blue-800 hover:!bg-blue-100/90"
                            }
                          >
                            <IconX size={14} stroke={2} />
                          </ActionIcon>
                        </div>
                      );
                    })
                  )}
                </div>

                {(() => {
                  const assigned = host.groupIds || [];
                  const addOptions = groups
                    .filter((g) => !assigned.includes(g._id))
                    .map((g) => ({ value: g._id, label: g.name }));
                  if (addOptions.length === 0) {
                    return null;
                  }
                  return (
                    <div className="mt-4">
                      <Text
                        size="xs"
                        weight={600}
                        className={`mb-1.5 uppercase tracking-wide ${isDark ? "text-zinc-500" : "text-zinc-500"}`}
                      >
                        Add to group
                      </Text>
                      <Select
                        key={`add-group-${host.id}-${(host.groupIds || []).join(",")}`}
                        placeholder="Choose a group to add…"
                        clearable
                        searchable
                        disabled={groupSaving}
                        data={addOptions}
                        onChange={(value) => {
                          if (value) {
                            handleAddGroupFromSelect(value);
                          }
                        }}
                        classNames={{
                          input: getInputClassName(isDark),
                          dropdown: isDark
                            ? "!border-zinc-700 !bg-zinc-900"
                            : "!border-zinc-200 !bg-white",
                          item: isDark
                            ? "!text-zinc-100 hover:!bg-zinc-800"
                            : "!text-zinc-900 hover:!bg-zinc-100",
                        }}
                      />
                    </div>
                  );
                })()}
              </div>
            ) : null}

            <div
              className={`rounded-md border ${
                isDark
                  ? "border-zinc-700 bg-zinc-950/70"
                  : "border-zinc-200 bg-zinc-50/70"
              }`}
            >
              <div className={isDark ? "divide-y divide-zinc-800" : "divide-y divide-zinc-200"}>
                <div>
                  <button
                    type="button"
                    onClick={() => setShowMachineCredentials((current) => !current)}
                    className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
                  >
                    <span className={isDark ? "text-sm text-zinc-200" : "text-sm text-zinc-800"}>
                      Client setup
                    </span>
                    {showMachineCredentials ? (
                      <IconChevronUp size={18} className={isDark ? "text-zinc-400" : "text-zinc-600"} />
                    ) : (
                      <IconChevronDown size={18} className={isDark ? "text-zinc-400" : "text-zinc-600"} />
                    )}
                  </button>

                  <Collapse in={showMachineCredentials}>
                    <div className="space-y-1 px-4 pb-2 pt-1.5">
                      <div>
                        <div className="flex items-center gap-1.5">
                          <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">
                            Bootstrap command
                          </p>
                          <Tooltip
                            label="Refresh machine token"
                            withArrow
                            position="top"
                            classNames={{
                              tooltip: isDark
                                ? "!border !border-zinc-700 !bg-zinc-900 !text-zinc-100"
                                : "!border !border-zinc-200 !bg-white !text-zinc-900",
                              arrow: isDark
                                ? "!border-zinc-700 !bg-zinc-900"
                                : "!border-zinc-200 !bg-white",
                            }}
                          >
                            <ActionIcon
                              type="button"
                              variant="subtle"
                              onClick={handleOpenRefreshMachineTokenConfirm}
                              aria-label="Refresh machine token"
                              className={
                                isDark
                                  ? "!h-6 !w-6 !text-zinc-400 hover:!bg-zinc-800 hover:!text-zinc-200"
                                  : "!h-6 !w-6 !text-zinc-500 hover:!bg-zinc-200 hover:!text-zinc-700"
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
                                ? "!border !border-zinc-700 !bg-zinc-900 !text-zinc-100"
                                : "!border !border-zinc-200 !bg-white !text-zinc-900",
                              arrow: isDark
                                ? "!border-zinc-700 !bg-zinc-900"
                                : "!border-zinc-200 !bg-white",
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
                                  ? "!h-6 !w-6 !text-zinc-400 hover:!bg-zinc-800 hover:!text-zinc-200 disabled:!opacity-40"
                                  : "!h-6 !w-6 !text-zinc-500 hover:!bg-zinc-200 hover:!text-zinc-700 disabled:!opacity-40"
                              }
                            >
                              <IconCopy size={14} />
                            </ActionIcon>
                          </Tooltip>
                        </div>
                        <div className="mt-2">
                          <div
                            className={`relative rounded-lg ${
                              isDark ? "bg-zinc-800/80" : "bg-zinc-100"
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
                                  ? "!text-zinc-300 hover:!bg-zinc-700 disabled:!bg-transparent"
                                  : "!text-zinc-600 hover:!bg-zinc-200 disabled:!bg-transparent"
                              }`}
                            >
                              <IconCopy size={16} />
                            </ActionIcon>
                            <code
                              className={`block break-all rounded-lg px-3 py-3 pr-12 text-xs ${
                                isDark ? "text-zinc-100" : "text-zinc-800"
                              }`}
                            >
                              {isLoadingMachineCommand
                                ? "Loading bootstrap command..."
                                : machineCommand || "Unavailable"}
                            </code>
                          </div>
                          <p className="mt-2 text-xs text-zinc-500">
                            Paste once to install and connect. After that use
                            {" "}
                            <code>porthub ls</code>
                            {", "}
                            <code>porthub status &lt;tenant&gt;</code>
                            {" "}
                            and
                            {" "}
                            <code>porthub stop &lt;tenant&gt;</code>
                            {" "}
                            on the client machine.
                          </p>
                          <div className="mt-1.5 flex items-center gap-1.5">
                            <p
                              className={`text-xs ${
                                isDark ? "text-zinc-400" : "text-zinc-500"
                              }`}
                            >
                              Installed client version: {clientVersionLabel}
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
                                    ? "!border !border-zinc-700 !bg-zinc-900 !text-zinc-100"
                                    : "!border !border-zinc-200 !bg-white !text-zinc-900",
                                  arrow: isDark
                                    ? "!border-zinc-700 !bg-zinc-900"
                                    : "!border-zinc-200 !bg-white",
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
                                        ? "!h-5 !w-5 !text-amber-300/90 hover:!bg-zinc-800"
                                        : "!h-5 !w-5 !text-amber-700/90 hover:!bg-zinc-200"
                                      : isDark
                                        ? "!h-5 !w-5 !text-zinc-500 hover:!bg-zinc-800 hover:!text-zinc-300"
                                        : "!h-5 !w-5 !text-zinc-400 hover:!bg-zinc-200 hover:!text-zinc-600"
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
                  </Collapse>
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => setShowClientLogs((current) => !current)}
                    className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
                  >
                    <span className={isDark ? "text-sm text-zinc-200" : "text-sm text-zinc-800"}>
                      Client logs
                    </span>
                    {showClientLogs ? (
                      <IconChevronUp size={18} className={isDark ? "text-zinc-400" : "text-zinc-600"} />
                    ) : (
                      <IconChevronDown size={18} className={isDark ? "text-zinc-400" : "text-zinc-600"} />
                    )}
                  </button>

                  <Collapse in={showClientLogs}>
                    <div className="space-y-3 px-4 py-4">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">
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
                        className={`max-h-72 overflow-y-auto rounded-lg border px-3 py-3 font-mono text-xs ${
                          isDark
                            ? "border-zinc-700 bg-zinc-900 text-zinc-100 dark-scrollbar"
                            : "border-zinc-200 bg-zinc-100 text-zinc-800 light-scrollbar"
                        }`}
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
                                      isDark ? "text-zinc-500" : "text-zinc-400"
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
                          <p className={isDark ? "text-zinc-400" : "text-zinc-500"}>
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

                      <p className="text-xs text-zinc-500">
                        Shows the same combined PortHub client and Rathole log stream
                        available on the client via <code>porthub logs</code>. Turn on
                        verbose to include debug noise.
                      </p>
                    </div>
                  </Collapse>
                </div>
              </div>
            </div>

            {selectedRule ? (
              /* Edit view: only the form for the selected rule */
              (() => {
                const rule = selectedRule;
                const ruleErrors = errorsByRuleId[rule.localId] || {};
                const availability = availabilityByRuleId[rule.localId];

                return (
                  <>
                    <div
                      className={`rounded-xl border p-4 ${
                        isDark
                          ? "border-zinc-700 bg-zinc-950/70"
                          : "border-zinc-200 bg-zinc-50/70"
                      }`}
                    >
                      <div className="mb-4 flex items-center justify-between gap-3">
                        <button
                          type="button"
                          onClick={handleDoneEditing}
                          className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1.5 text-sm font-medium transition-colors ${
                            isDark
                              ? "text-zinc-300 hover:bg-zinc-800"
                              : "text-zinc-600 hover:bg-zinc-100"
                          }`}
                        >
                          <IconArrowLeft size={18} />
                          Back to list
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRemoveRule(rule.localId)}
                          className={`inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
                            isDark
                              ? "text-red-400 hover:bg-red-950/60"
                              : "text-red-600 hover:bg-red-50"
                          }`}
                        >
                          <IconTrash size={14} />
                          Remove
                        </button>
                      </div>

                      <div className="space-y-4">
                        <div>
                          <label
                            htmlFor={`service-name-${rule.localId}`}
                            className={getLabelClassName(isDark)}
                          >
                            Service name
                          </label>
                          <input
                            id={`service-name-${rule.localId}`}
                            type="text"
                            placeholder="SSH"
                            className={getInputClassName(isDark)}
                            value={rule.serviceName}
                            onChange={(event) =>
                              updateRule(
                                rule.localId,
                                "serviceName",
                                event.currentTarget.value
                              )
                            }
                          />
                          {ruleErrors.serviceName && (
                            <p className={errorClassName}>
                              {ruleErrors.serviceName}
                            </p>
                          )}
                        </div>

                        <div>
                          <label
                            htmlFor={`service-description-${rule.localId}`}
                            className={getLabelClassName(isDark)}
                          >
                            Service description
                          </label>
                          <textarea
                            id={`service-description-${rule.localId}`}
                            placeholder="Secure access to this host over SSH"
                            rows={3}
                            className={`${getInputClassName(isDark)} resize-y`}
                            value={rule.serviceDescription}
                            onChange={(event) =>
                              updateRule(
                                rule.localId,
                                "serviceDescription",
                                event.currentTarget.value
                              )
                            }
                          />
                        </div>

                        <div className="grid gap-4 md:grid-cols-3">
                          <div>
                            <label
                              htmlFor={`internal-ip-${rule.localId}`}
                              className={getLabelClassName(isDark)}
                            >
                              Internal host / IP
                            </label>
                            <input
                              id={`internal-ip-${rule.localId}`}
                              type="text"
                              spellCheck={false}
                              placeholder="0.0.0.0 or app.local"
                              className={getInputClassName(isDark)}
                              value={rule.internalIp}
                              onChange={(event) =>
                                updateRule(
                                  rule.localId,
                                  "internalIp",
                                  event.currentTarget.value
                                )
                              }
                            />
                            {ruleErrors.internalIp && (
                              <p className={errorClassName}>
                                {ruleErrors.internalIp}
                              </p>
                            )}
                          </div>

                          <div>
                            <label
                              htmlFor={`internal-port-${rule.localId}`}
                              className={getLabelClassName(isDark)}
                            >
                              Internal port
                            </label>
                            <input
                              id={`internal-port-${rule.localId}`}
                              type="text"
                              inputMode="numeric"
                              placeholder="22"
                              className={getInputClassName(isDark)}
                              value={rule.internalPort}
                              onChange={(event) =>
                                updateRule(
                                  rule.localId,
                                  "internalPort",
                                  event.currentTarget.value
                                )
                              }
                            />
                            {ruleErrors.internalPort && (
                              <p className={errorClassName}>
                                {ruleErrors.internalPort}
                              </p>
                            )}
                          </div>

                          <div>
                            <label
                              htmlFor={`external-port-${rule.localId}`}
                              className={getLabelClassName(isDark)}
                            >
                              External port
                            </label>
                            <div className="flex items-end gap-2">
                              <div className="flex-1">
                                <input
                                  id={`external-port-${rule.localId}`}
                                  type="text"
                                  inputMode="numeric"
                                  placeholder="50022"
                                  className={getInputClassName(isDark)}
                                  value={rule.externalPort}
                                  onChange={(event) =>
                                    updateRule(
                                      rule.localId,
                                      "externalPort",
                                      event.currentTarget.value
                                    )
                                  }
                                />
                              </div>
                              <ActionIcon
                                type="button"
                                variant="light"
                                size={36}
                                onClick={() => handleGeneratePort(rule.localId)}
                                loading={randomizingRuleId === rule.localId}
                                aria-label="Generate random external port"
                                className={
                                  isDark
                                    ? "mb-0.5 !border-zinc-700 !bg-zinc-800 !text-blue-200 hover:!bg-zinc-700"
                                    : "mb-0.5 !border-blue-300 !bg-blue-100 !text-blue-700 hover:!bg-blue-200"
                                }
                              >
                                <IconRefresh size={18} />
                              </ActionIcon>
                            </div>
                            {ruleErrors.externalPort && (
                              <p className={errorClassName}>
                                {ruleErrors.externalPort}
                              </p>
                            )}
                            {!ruleErrors.externalPort &&
                              availability &&
                              !availability.available && (
                                <p className={errorClassName}>
                                  {availability.message}
                                </p>
                              )}
                          </div>
                        </div>

                        <Text
                          size="xs"
                          className={isDark ? "!text-zinc-400" : "!text-zinc-500"}
                        >
                          External ports must be unique across all configured
                          services.
                        </Text>

                        <Switch
                          label="Enable forwarding rule"
                          checked={rule.enabled}
                          onChange={(event) =>
                            updateRule(
                              rule.localId,
                              "enabled",
                              event.currentTarget.checked
                            )
                          }
                          classNames={{
                            label: isDark
                              ? "!text-zinc-100"
                              : "!text-zinc-900",
                            track: isDark
                              ? "!border-zinc-700"
                              : "!border-zinc-300",
                          }}
                        />
                      </div>
                    </div>
                  </>
                );
              })()
            ) : (
              /* List view: table + Add port pair (no edit form) */
              <div className="flex min-h-0 flex-1 flex-col gap-3">
                <div className="flex items-center justify-between gap-3">
                  <Text
                    size="sm"
                    className={isDark ? "!text-zinc-400" : "!text-zinc-600"}
                  >
                    {rules.length === 0
                      ? "No port pairs yet. Add one now to get started."
                      : "Click Edit on a row to change it, or add a new port pair."}
                  </Text>

                  <Button
                    type="button"
                    variant="default"
                    leftIcon={<IconPlus size={16} />}
                    onClick={handleAddRule}
                    classNames={{ root: btnSecondary }}
                  >
                    Add port pair
                  </Button>
                </div>

                {rules.length > 0 ? (
                  <div className="flex min-h-0 flex-1 flex-col gap-1">
                    <div
                      className={`flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border ${
                        isDark
                          ? "border-zinc-700"
                          : "border-zinc-200"
                      }`}
                    >
                      <div
                        className={`grid grid-cols-[52px_minmax(0,1.3fr)_minmax(0,1fr)_90px_110px_96px] border-b px-4 py-3 text-xs font-semibold uppercase tracking-wide ${
                          isDark
                            ? "border-zinc-700 bg-zinc-800 text-zinc-400"
                            : "border-zinc-200 bg-zinc-100/80 text-zinc-600"
                        }`}
                      >
                        <span className="text-center">#</span>
                        <span>Service</span>
                        <span>Internal</span>
                        <span>External</span>
                        <span>Status</span>
                        <span>Toggle</span>
                      </div>

                      <div className="min-h-0 flex-1 overflow-y-auto">
                      {paginatedRules.map((rule, index) => {
                          const availability =
                            availabilityByRuleId[rule.localId];
                          const isAvailabilityKnown = Boolean(availability);
                          const isInvalid =
                            isAvailabilityKnown && availability.available === false;
                          const savedRule = rule.dataId
                            ? savedRulesById.get(rule.dataId)
                            : null;
                          const persistedEnabled =
                            savedRule?.enabled ?? rule.enabled;
                          const rowNumber =
                            (rulesPage - 1) * RULES_PER_PAGE + index + 1;

                          return (
                            <div
                              key={rule.localId}
                              role="button"
                              tabIndex={0}
                              onClick={(event) => handleRuleRowClick(event, rule)}
                              onKeyDown={(event) => {
                                if (event.key === "Enter" || event.key === " ") {
                                  event.preventDefault();
                                  handleRuleRowClick(event, rule);
                                }
                              }}
                              className={`grid w-full grid-cols-[52px_minmax(0,1.3fr)_minmax(0,1fr)_90px_110px_96px] items-center border-b px-4 py-3 text-left text-sm last:border-b-0 ${
                                isDark
                                  ? "border-zinc-700 bg-zinc-900 hover:bg-zinc-800/80"
                                  : "border-zinc-200 bg-white hover:bg-zinc-50"
                              }`}
                              aria-label={`Edit forwarding rule ${rule.serviceName.trim() || rowNumber}`}
                            >
                              <span
                                className={
                                  isDark
                                    ? "text-center font-mono text-zinc-400"
                                    : "text-center font-mono text-zinc-500"
                                }
                              >
                                {rowNumber}
                              </span>

                              <div className="min-w-0">
                                <p
                                  className={
                                    isDark
                                      ? "truncate font-medium text-zinc-100"
                                      : "truncate font-medium text-zinc-900"
                                  }
                                >
                                  {rule.serviceName.trim() || "Untitled rule"}
                                </p>
                                <p
                                  className={
                                    isDark
                                      ? "truncate text-xs text-zinc-400"
                                      : "truncate text-xs text-zinc-500"
                                  }
                                >
                                  {rule.serviceDescription.trim() ||
                                    "No description"}
                                </p>
                              </div>

                              <span
                                className={
                                  isDark
                                    ? "font-mono text-zinc-300"
                                    : "font-mono text-zinc-700"
                                }
                              >
                                {rule.internalPort || "-"}
                              </span>

                              <span
                                className={
                                  isDark
                                    ? "font-mono text-zinc-300"
                                    : "font-mono text-zinc-700"
                                }
                              >
                                {rule.externalPort || "-"}
                              </span>

                              <div>
                                {isInvalid ? (
                                  <span
                                    className={
                                      isDark
                                        ? "text-xs font-medium text-red-300"
                                        : "text-xs font-medium text-red-700"
                                    }
                                  >
                                    Invalid
                                  </span>
                                ) : !isAvailabilityKnown && isCheckingAvailability ? (
                                  <span
                                    className={
                                      isDark
                                        ? "text-xs font-medium text-blue-200"
                                        : "text-xs font-medium text-blue-700"
                                    }
                                  >
                                    Checking
                                  </span>
                                ) : persistedEnabled ? (
                                  <span
                                    className={
                                      isDark
                                        ? "text-xs font-medium text-emerald-300"
                                        : "text-xs font-medium text-emerald-700"
                                    }
                                  >
                                    Active
                                  </span>
                                ) : (
                                  <span
                                    className={
                                      isDark
                                        ? "text-xs font-medium text-zinc-300"
                                        : "text-xs font-medium text-zinc-700"
                                    }
                                  >
                                    Inactive
                                  </span>
                                )}
                              </div>

                              <div
                                className="flex items-center"
                                data-rule-toggle="true"
                                onClick={(event) => event.stopPropagation()}
                                onMouseDown={(event) => event.stopPropagation()}
                                onPointerDown={(event) => event.stopPropagation()}
                              >
                                <Switch
                                  size="sm"
                                  checked={rule.enabled}
                                  onMouseDown={(event) => event.stopPropagation()}
                                  onClick={(event) => event.stopPropagation()}
                                  onPointerDown={(event) => event.stopPropagation()}
                                  onKeyDown={(event) => event.stopPropagation()}
                                  onChangeCapture={(event) => event.stopPropagation()}
                                  onChange={(event) =>
                                    updateRule(
                                      rule.localId,
                                      "enabled",
                                      event.currentTarget.checked
                                    )
                                  }
                                  aria-label={
                                    rule.enabled
                                      ? "Disable forwarding rule"
                                      : "Enable forwarding rule"
                                  }
                                  classNames={{
                                    track: isDark
                                      ? "!border-zinc-700"
                                      : "!border-zinc-300",
                                  }}
                                />
                              </div>
                            </div>
                        );
                      })}
                      </div>
                    </div>

                    {rules.length > RULES_PER_PAGE ? (
                      <div className="flex justify-end pt-1">
                        <Pagination
                          value={rulesPage}
                          onChange={setRulesPage}
                          total={totalRulePages}
                          size="sm"
                          radius="md"
                          withEdges
                          siblings={1}
                          classNames={{
                            control: isDark
                              ? "!border-zinc-700 !bg-zinc-900 !text-zinc-200 hover:!bg-zinc-800 data-[active=true]:!border-blue-500 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50"
                              : "!border-zinc-300 !bg-white !text-zinc-700 hover:!bg-zinc-50 data-[active=true]:!border-blue-600 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50",
                          }}
                        />
                      </div>
                    ) : null}
                  </div>
                ) : null}

              </div>
            )}
            </div>
            </div>

            <Group position="right">
              {selectedRule ? (
                /* Edit mode: Cancel = discard current edit session, Done = go to list (keep edits) */
                <>
                  <Button
                    type="button"
                    variant="default"
                    onClick={handleCancelEditing}
                    classNames={{ root: btnSecondary }}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="button"
                    variant="filled"
                    onClick={handleDoneEditing}
                    disabled={selectedRuleHasErrors}
                    classNames={{
                      root:
                        "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400 disabled:!opacity-50",
                    }}
                  >
                    Done
                  </Button>
                </>
              ) : (
                /* List mode: Cancel / Save config */
                <>
                  <Button
                    type="button"
                    variant="default"
                    onClick={handleClose}
                    disabled={isSaving}
                    classNames={{ root: btnSecondary }}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    loading={isSaving}
                    disabled={isCheckingAvailability}
                    classNames={{
                      root:
                        "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400",
                    }}
                  >
                    Save config
                  </Button>
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
      </Modal>

      <Modal
        opened={isRefreshMachineTokenConfirmOpen}
        onClose={handleCloseRefreshMachineTokenConfirm}
        title="Refresh machine token"
        centered
        radius="md"
        size="sm"
        overlayProps={{ backgroundOpacity: 0, blur: 0 }}
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
            <Button
              type="button"
              variant="default"
              onClick={handleCloseRefreshMachineTokenConfirm}
              disabled={isRefreshingMachineToken}
              classNames={{ root: btnSecondary }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="filled"
              onClick={handleRefreshMachineToken}
              loading={isRefreshingMachineToken}
              classNames={{
                root:
                  "!bg-red-600 !text-red-50 hover:!bg-red-700 disabled:!bg-red-400",
              }}
            >
              Refresh machine token
            </Button>
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
        overlayProps={{ backgroundOpacity: 0, blur: 0 }}
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
            <Button
              type="button"
              variant="default"
              onClick={handleCloseDeleteMachineConfirm}
              disabled={isDeletingMachine}
              classNames={{ root: btnSecondary }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="filled"
              onClick={handleDeleteMachine}
              loading={isDeletingMachine}
              classNames={{
                root:
                  "!bg-red-600 !text-red-50 hover:!bg-red-700 disabled:!bg-red-400",
              }}
            >
              Delete machine
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
