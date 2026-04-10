import { useEffect, useRef, useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Modal,
  Stack,
  Switch,
  Text,
  useMantineColorScheme,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconArrowLeft, IconPencil, IconPlus, IconRefresh, IconTrash } from "@tabler/icons-react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";
import useToast from "@/shared/hooks/useToast";

const getInputClassName = (isDark) =>
  `w-full rounded-md border px-3 py-2 text-sm outline-none transition-colors focus:!border-blue-500 focus:ring-0 ${
    isDark
      ? "!border-zinc-600 !bg-zinc-800 !text-zinc-100 placeholder:!text-zinc-500"
      : "!border-zinc-300 !bg-zinc-50 !text-zinc-900 placeholder:!text-zinc-400"
  }`;

const getLabelClassName = (isDark) =>
  `mb-1.5 block text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`;

const errorClassName = "mt-1 text-xs text-red-600 dark:text-red-400";

const createRuleId = () =>
  `rule-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

const createEmptyRule = () => ({
  localId: createRuleId(),
  dataId: null,
  serviceName: "",
  serviceDescription: "",
  internalPort: "3000",
  externalPort: "3000",
  enabled: true,
});

const mapRuleFromConfig = (config) => ({
  localId: config.dataId || createRuleId(),
  dataId: config.dataId || null,
  serviceName: config.serviceName || "",
  serviceDescription: config.serviceDescription || "",
  internalPort: String(config.internalPort || 3000),
  externalPort: String(config.externalPort || 3000),
  enabled: config.enabled ?? true,
});

const getRuleErrors = (rule) => {
  const errors = {};

  if (!rule.serviceName.trim()) {
    errors.serviceName = "Service name is required";
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
  internalPort: Number(rule.internalPort) || 0,
  externalPort: Number(rule.externalPort) || 0,
  enabled: Boolean(rule.enabled),
});

const rulesSnapshotKey = (rules) =>
  JSON.stringify(rules.map(normalizeRuleForCompare));

export default function HostConfigPopup({
  host,
  opened,
  onClose,
  onSave,
  isSaving,
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const { success } = useToast();

  const [rules, setRules] = useState([]);
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [errorsByRuleId, setErrorsByRuleId] = useState({});
  const [availabilityByRuleId, setAvailabilityByRuleId] = useState({});
  const [isCheckingAvailability, setIsCheckingAvailability] = useState(false);
  const [randomizingRuleId, setRandomizingRuleId] = useState(null);
  const [debouncedRules] = useDebouncedValue(rules, 300);
  const initialRulesSnapshotRef = useRef("");

  const selectedRule = rules.find((rule) => rule.localId === selectedRuleId) || null;
  const hasUnsavedChanges =
    host && rulesSnapshotKey(rules) !== initialRulesSnapshotRef.current;

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
      setRules([]);
      setSelectedRuleId(null);
      setErrorsByRuleId({});
      setAvailabilityByRuleId({});
      initialRulesSnapshotRef.current = "";
      return;
    }

    const nextRules =
      host.forwardingConfigs?.length > 0
        ? host.forwardingConfigs.map(mapRuleFromConfig)
        : [];

    setRules(nextRules);
    setSelectedRuleId(null);
    setErrorsByRuleId({});
    setAvailabilityByRuleId({});
    initialRulesSnapshotRef.current = rulesSnapshotKey(nextRules);
  }, [host]);

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

  const handleAddRule = () => {
    const nextRule = createEmptyRule();
    setRules((currentRules) => [...currentRules, nextRule]);
    setSelectedRuleId(nextRule.localId); // open new rule in edit view
  };

  const handleDoneEditing = (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    setSelectedRuleId(null);
  };

  const handleRemoveRule = (localId) => {
    const rule = rules.find((r) => r.localId === localId);
    const serviceName = rule?.serviceName?.trim() || "Port pair";

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

    success(`${serviceName} removed successfully`);
  };

  const handleGeneratePort = async (localId) => {
    setRandomizingRuleId(localId);

    try {
      const response = await axios.get(apiRoutes.getRandomPort);
      updateRule(localId, "externalPort", String(response.data.port));
    } finally {
      setRandomizingRuleId(null);
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

    const payload = rules.map((rule) => ({
      dataId: rule.dataId,
      serviceName: rule.serviceName.trim(),
      serviceDescription: rule.serviceDescription.trim(),
      internalPort: Number(rule.internalPort),
      externalPort: Number(rule.externalPort),
      enabled: rule.enabled,
    }));

    const saved = await onSave(host.id, payload);

    if (saved) {
      initialRulesSnapshotRef.current = rulesSnapshotKey(rules);
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
          className={isDark ? "text-zinc-100" : "text-zinc-900"}
        >
          <Stack spacing="md">
            <Group spacing="xs">
              <Badge color={host.isActive ? "green" : "red"} variant="light">
                {host.isActive ? "Online" : "Offline"}
              </Badge>
              <Badge variant="outline">{host.ip}</Badge>
              <Badge variant="outline">{host.numPorts} active ports</Badge>
              <Badge variant="outline">{rules.length} configured rules</Badge>
            </Group>

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

                        <div className="grid gap-4 md:grid-cols-2">
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
              <>
                <Text
                  size="sm"
                  className={isDark ? "!text-zinc-400" : "!text-zinc-600"}
                >
                  {rules.length === 0
                    ? "No port pairs yet. Add one below to get started."
                    : "Click Edit on a row to change it, or add a new port pair."}
                </Text>

                {rules.length > 0 ? (
                  <div
                    className={`overflow-hidden rounded-xl border ${
                      isDark
                        ? "border-zinc-700"
                        : "border-zinc-200"
                    }`}
                  >
                    <div
                      className={`grid grid-cols-[minmax(0,1.4fr)_90px_90px_110px_72px] border-b px-4 py-3 text-xs font-semibold uppercase tracking-wide ${
                        isDark
                          ? "border-zinc-700 bg-zinc-800 text-zinc-400"
                          : "border-zinc-200 bg-zinc-100/80 text-zinc-600"
                      }`}
                    >
                      <span>Service</span>
                      <span>Internal</span>
                      <span>External</span>
                      <span>Status</span>
                      <span className="text-right">Edit</span>
                    </div>

                    <div className="max-h-[14rem] overflow-y-auto">
                      {rules.map((rule) => {
                        const availability =
                          availabilityByRuleId[rule.localId];

                        return (
                          <div
                            key={rule.localId}
                            className={`grid grid-cols-[minmax(0,1.4fr)_90px_90px_110px_72px] items-center border-b px-4 py-3 text-sm last:border-b-0 ${
                              isDark
                                ? "border-zinc-700 bg-zinc-900"
                                : "border-zinc-200 bg-white"
                            }`}
                          >
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
                              {!availability?.available ? (
                                <span
                                  className={
                                    isDark
                                      ? "inline-flex rounded-full bg-red-950/60 px-2 py-1 text-xs font-medium text-red-300"
                                      : "inline-flex rounded-full bg-red-100 px-2 py-1 text-xs font-medium text-red-700"
                                  }
                                >
                                  Invalid
                                </span>
                              ) : rule.enabled ? (
                                <span
                                  className={
                                    isDark
                                      ? "inline-flex rounded-full bg-emerald-950/60 px-2 py-1 text-xs font-medium text-emerald-300"
                                      : "inline-flex rounded-full bg-emerald-100 px-2 py-1 text-xs font-medium text-emerald-700"
                                  }
                                >
                                  Active
                                </span>
                              ) : (
                                <span
                                  className={
                                    isDark
                                      ? "inline-flex rounded-full bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-300"
                                      : "inline-flex rounded-full bg-zinc-200 px-2 py-1 text-xs font-medium text-zinc-700"
                                  }
                                >
                                  Inactive
                                </span>
                              )}
                            </div>

                            <div className="flex justify-end">
                              <ActionIcon
                                type="button"
                                variant="subtle"
                                onClick={() =>
                                  setSelectedRuleId(rule.localId)
                                }
                                className={
                                  isDark
                                    ? "!text-zinc-300 hover:!bg-zinc-800"
                                    : "!text-zinc-600 hover:!bg-zinc-100"
                                }
                                aria-label="Edit forwarding rule"
                              >
                                <IconPencil size={16} />
                              </ActionIcon>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ) : null}

                <div className="flex items-center justify-between gap-3">
                  <Text
                    size="xs"
                    className={isDark ? "!text-zinc-400" : "!text-zinc-500"}
                  >
                    External ports must be unique across all configured
                    services.
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
              </>
            )}

            <Group position="right">
              {selectedRule ? (
                /* Edit mode: Cancel = remove this rule & go to list, Done = go to list (keep edits) */
                <>
                  <Button
                    type="button"
                    variant="default"
                    onClick={() => handleRemoveRule(selectedRule.localId)}
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
                /* List mode: Cancel = close modal, Save config = persist to DB */
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
  );
}
