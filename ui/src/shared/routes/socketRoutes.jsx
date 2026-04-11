let socketRoutes = {
  ctsMachineStatusSnapshot: "/cts/machines/status-snapshot",
  stcMachineStatusSnapshot: "/stc/machines/status-snapshot",
  stcMachineStatusChanged: "/stc/machines/status-changed",
  ctsMachineLogStreamSubscribe: "/cts/machines/log-stream-subscribe",
  ctsMachineLogStreamUnsubscribe: "/cts/machines/log-stream-unsubscribe",
  stcMachineLogStreamStatus: "/stc/machines/log-stream-status",
  stcMachineLogStreamLine: "/stc/machines/log-stream-line",
};

export default socketRoutes;
