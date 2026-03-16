import { useEffect, useState } from "react";
import { ActionIcon, Badge, Button, Group, Modal, Stack, Switch, Text } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconPencil, IconPlus, IconRefresh, IconTrash } from "@tabler/icons-react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";

const inputClassName =
  "w-full rounded-md border border-zinc-300 bg-zinc-50 px-3 py-2 text-sm text-zinc-900 outline-none transition-colors placeholder:text-zinc-400 focus:border-blue-500 focus:ring-0 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100 dark:placeholder:text-zinc-500";

const labelClassName =
  "mb-1.5 block text-sm font-semibold text-zinc-900 dark:text-zinc-100";

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

export default function HostConfigPopup({
  host,
  opened,
  onClose,
  onSave,
  isSaving,
}) {
  const [rules, setRules] = useState([createEmptyRule()]);
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [errorsByRuleId, setErrorsByRuleId] = useState({});
  const [availabilityByRuleId, setAvailabilityByRuleId] = useState({});
  const [isCheckingAvailability, setIsCheckingAvailability] = useState(false);
  const [randomizingRuleId, setRandomizingRuleId] = useState(null);
  const [debouncedRules] = useDebouncedValue(rules, 300);

  const selectedRule =
    rules.find((rule) => rule.localId === selectedRuleId) || rules[0] || null;

  useEffect(() => {
    if (!host) {
      const emptyRule = createEmptyRule();
      setRules([emptyRule]);
      setSelectedRuleId(emptyRule.localId);
      setErrorsByRuleId({});
      setAvailabilityByRuleId({});
      return;
    }

    const nextRules =
      host.forwardingConfigs?.length > 0
        ? host.forwardingConfigs.map(mapRuleFromConfig)
        : [createEmptyRule()];

    setRules(nextRules);
    setSelectedRuleId(nextRules[0]?.localId || null);
    setErrorsByRuleId({});
    setAvailabilityByRuleId({});
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
    setSelectedRuleId(nextRule.localId);
  };

  const handleRemoveRule = (localId) => {
    setRules((currentRules) => {
      const nextRules = currentRules.filter((rule) => rule.localId !== localId);
      const fallbackRule = createEmptyRule();
      const resolvedRules = nextRules.length > 0 ? nextRules : [fallbackRule];

      if (selectedRuleId === localId) {
        setSelectedRuleId(resolvedRules[0]?.localId || null);
      }

      return resolvedRules;
    });

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
      handleClose();
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={handleClose}
      title={host ? `Configure ${host.name}` : "Configure host"}
      centered
      radius="md"
      size="lg"
      overlayProps={{ blur: 3 }}
      classNames={{
        content:
          "!border !border-zinc-200 !bg-white dark:!border-zinc-700 dark:!bg-zinc-900",
        header:
          "!border-b !border-zinc-200 !bg-white dark:!border-zinc-800 dark:!bg-zinc-900",
        title: "font-bold !text-zinc-900 dark:!text-zinc-100",
        close:
          "!text-zinc-500 hover:!bg-zinc-100 dark:!text-zinc-400 dark:hover:!bg-zinc-800",
        body: "!bg-white !pt-3 dark:!bg-zinc-900",
      }}
    >
      {host ? (
        <form onSubmit={handleSubmit} className="!text-zinc-900 dark:!text-zinc-100">
          <Stack spacing="md">
            <Group spacing="xs">
              <Badge color={host.isActive ? "green" : "red"} variant="light">
                {host.isActive ? "Online" : "Offline"}
              </Badge>
              <Badge variant="outline">{host.ip}</Badge>
              <Badge variant="outline">{host.numPorts} active ports</Badge>
              <Badge variant="outline">{rules.length} configured rules</Badge>
            </Group>

            <Text size="sm" className="!text-zinc-600 dark:!text-zinc-400">
              Review all configured port pairs first, then edit only the selected row below.
            </Text>

            <div className="overflow-hidden rounded-xl border border-zinc-200 dark:border-zinc-800">
              <div className="grid grid-cols-[minmax(0,1.4fr)_90px_90px_110px_72px] border-b border-zinc-200 bg-zinc-100/80 px-4 py-3 text-xs font-semibold uppercase tracking-wide text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400">
                <span>Service</span>
                <span>Internal</span>
                <span>External</span>
                <span>Status</span>
                <span className="text-right">Edit</span>
              </div>

              <div className="max-h-[14rem] overflow-y-auto">
                {rules.map((rule) => {
                  const availability = availabilityByRuleId[rule.localId];
                  const isSelected = rule.localId === selectedRule?.localId;

                  return (
                    <div
                      key={rule.localId}
                      className={`grid grid-cols-[minmax(0,1.4fr)_90px_90px_110px_72px] items-center border-b border-zinc-200 px-4 py-3 text-sm last:border-b-0 dark:border-zinc-800 ${
                        isSelected
                          ? "bg-blue-50 dark:bg-blue-950/30"
                          : "bg-white dark:bg-zinc-900"
                      }`}
                    >
                      <div className="min-w-0">
                        <p className="truncate font-medium text-zinc-900 dark:text-zinc-100">
                          {rule.serviceName.trim() || "Untitled rule"}
                        </p>
                        <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                          {rule.serviceDescription.trim() || "No description"}
                        </p>
                      </div>

                      <span className="font-mono text-zinc-700 dark:text-zinc-300">
                        {rule.internalPort || "-"}
                      </span>

                      <span className="font-mono text-zinc-700 dark:text-zinc-300">
                        {rule.externalPort || "-"}
                      </span>

                      <div>
                        {!availability?.available ? (
                          <span className="inline-flex rounded-full bg-red-100 px-2 py-1 text-xs font-medium text-red-700 dark:bg-red-950/60 dark:text-red-300">
                            Invalid
                          </span>
                        ) : rule.enabled ? (
                          <span className="inline-flex rounded-full bg-emerald-100 px-2 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300">
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex rounded-full bg-zinc-200 px-2 py-1 text-xs font-medium text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                            Inactive
                          </span>
                        )}
                      </div>

                      <div className="flex justify-end">
                        <ActionIcon
                          type="button"
                          variant="subtle"
                          onClick={() => setSelectedRuleId(rule.localId)}
                          className={
                            isSelected
                              ? "!bg-blue-100 !text-blue-700 dark:!bg-blue-900/60 dark:!text-blue-200"
                              : "!text-zinc-600 hover:!bg-zinc-100 dark:!text-zinc-300 dark:hover:!bg-zinc-800"
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

            {selectedRule && (() => {
              const rule = selectedRule;
              const ruleErrors = errorsByRuleId[rule.localId] || {};
              const availability = availabilityByRuleId[rule.localId];

              return (
                <div className="rounded-xl border border-zinc-200 bg-zinc-50/70 p-4 dark:border-zinc-800 dark:bg-zinc-950/70">
                  <div className="mb-4 flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                        Edit selected port pair
                      </p>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400">
                        Change the details for the highlighted row only.
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleRemoveRule(rule.localId)}
                      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-red-600 transition-colors hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/60"
                    >
                      <IconTrash size={14} />
                      Remove
                    </button>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <label
                        htmlFor={`service-name-${rule.localId}`}
                        className={labelClassName}
                      >
                        Service name
                      </label>
                      <input
                        id={`service-name-${rule.localId}`}
                        type="text"
                        placeholder="SSH"
                        className={inputClassName}
                        value={rule.serviceName}
                        onChange={(event) =>
                          updateRule(rule.localId, "serviceName", event.currentTarget.value)
                        }
                      />
                      {ruleErrors.serviceName && (
                        <p className={errorClassName}>{ruleErrors.serviceName}</p>
                      )}
                    </div>

                    <div>
                      <label
                        htmlFor={`service-description-${rule.localId}`}
                        className={labelClassName}
                      >
                        Service description
                      </label>
                      <textarea
                        id={`service-description-${rule.localId}`}
                        placeholder="Secure access to this host over SSH"
                        rows={3}
                        className={`${inputClassName} resize-y`}
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
                          className={labelClassName}
                        >
                          Internal port
                        </label>
                        <input
                          id={`internal-port-${rule.localId}`}
                          type="text"
                          inputMode="numeric"
                          placeholder="22"
                          className={inputClassName}
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
                          <p className={errorClassName}>{ruleErrors.internalPort}</p>
                        )}
                      </div>

                      <div>
                        <label
                          htmlFor={`external-port-${rule.localId}`}
                          className={labelClassName}
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
                              className={inputClassName}
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
                            className="mb-0.5 border border-blue-300 bg-blue-100 text-blue-700 hover:bg-blue-200 dark:border-blue-700 dark:bg-blue-950 dark:text-blue-200 dark:hover:bg-blue-800"
                          >
                            <IconRefresh size={18} />
                          </ActionIcon>
                        </div>
                        {ruleErrors.externalPort && (
                          <p className={errorClassName}>{ruleErrors.externalPort}</p>
                        )}
                        {!ruleErrors.externalPort &&
                          availability &&
                          !availability.available && (
                            <p className={errorClassName}>{availability.message}</p>
                          )}
                      </div>
                    </div>

                    <Switch
                      label="Enable forwarding rule"
                      checked={rule.enabled}
                      onChange={(event) =>
                        updateRule(rule.localId, "enabled", event.currentTarget.checked)
                      }
                      classNames={{
                        label: "!text-zinc-900 dark:!text-zinc-100",
                        track: "!border-zinc-300 dark:!border-zinc-700",
                      }}
                    />
                  </div>
                </div>
              );
            })()}

            <div className="flex items-center justify-between gap-3">
              <Text size="xs" className="!text-zinc-500 dark:!text-zinc-400">
                External ports must be unique across all configured services.
              </Text>

              <Button
                type="button"
                variant="default"
                leftIcon={<IconPlus size={16} />}
                onClick={handleAddRule}
                classNames={{
                  root:
                    "!border-zinc-300 !bg-white !text-zinc-900 hover:!bg-zinc-50 dark:!border-zinc-700 dark:!bg-zinc-800 dark:!text-zinc-100 dark:hover:!bg-zinc-700",
                }}
              >
                Add port pair
              </Button>
            </div>

            <Group position="right">
              <Button
                variant="default"
                onClick={handleClose}
                disabled={isSaving}
                classNames={{
                  root:
                    "!border-zinc-300 !bg-white !text-zinc-900 hover:!bg-zinc-50 dark:!border-zinc-700 dark:!bg-zinc-800 dark:!text-zinc-100 dark:hover:!bg-zinc-700",
                }}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                loading={isSaving}
                disabled={isCheckingAvailability}
                classNames={{
                  root:
                    "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400 dark:!bg-blue-600 dark:!text-blue-50 dark:hover:!bg-blue-500",
                }}
              >
                Save config
              </Button>
            </Group>
          </Stack>
        </form>
      ) : (
        <Text size="sm" className="!text-zinc-600 dark:!text-zinc-400">
          Select a host to configure port forwarding.
        </Text>
      )}
    </Modal>
  );
}
