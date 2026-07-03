const API_PREFIX = process.env.API_PREFIX || "/api";

let apiRoutes = {
  // auth
  signUp: "/auth/signup",
  signIn: "/auth/signin",
  signOut: "/auth/signout",
  accountInfo: "/auth/me",
  authSettings: "/auth/settings",

  // Connections
  getRandomPort: "/connections/random",
  addConnection: "/connections/add",
  updateConnection: "/connections/update",
  refreshConnection: "/connections/refresh",
  listConnections: "/connections/list",
  deleteConnection: "/connections/delete",
  updateConnectionFirewallPolicy: "/connections/firewall/policy",
  trafficSnapshot: "/connections/firewall/traffic/snapshot",
  // Traffic routes / proxies
  listTrafficRoutes: "/traffic-routes/list",
  addTrafficRoute: "/traffic-routes/add",
  updateTrafficRoute: "/traffic-routes/update",
  deleteTrafficRoute: "/traffic-routes/delete",
  // Machine groups
  listGroups: "/groups/list",
  addGroup: "/groups/add",
  updateGroup: "/groups/update",
  deleteGroup: "/groups/delete",

  // Machines
  addMachine: "/machines/add",
  updateMachine: "/machines/update",
  listMachines: "/machines/list",
  deleteMachine: "/machines/delete",
  refreshMachineToken: "/machines/refresh-token",
  requestClientUpdate: "/machines/request-client-update",
  syncMachine: "/machines/sync",
  addMachineToGroup: "/machines/groups/add",
  removeMachineFromGroup: "/machines/groups/remove",
};

Object.entries(apiRoutes).forEach(([key, value]) => {
  apiRoutes[key] = API_PREFIX + value;
});

apiRoutes.checkExternalPortAvailability = (port) =>
  `${API_PREFIX}/connections/external-port/${port}/availability`;
apiRoutes.getConnectionFirewallPolicy = (dataId) =>
  `${API_PREFIX}/connections/firewall/policy/${dataId}`;
apiRoutes.deleteConnectionFirewallPolicy = (dataId) =>
  `${API_PREFIX}/connections/firewall/policy/${dataId}`;
apiRoutes.getConnectionRecentIpHits = (dataId, limit = 10) =>
  `${API_PREFIX}/connections/firewall/recent-ip-hits/${dataId}?limit=${limit}`;

apiRoutes.getMachineCommand = (machineId, clientSetup = {}) => {
  const params = new URLSearchParams();
  if (clientSetup.publicBaseUrl) {
    params.set("public_base_url", clientSetup.publicBaseUrl);
  }
  if (clientSetup.ratholeServerAddress) {
    params.set("rathole_server_address", clientSetup.ratholeServerAddress);
  }
  if (clientSetup.serviceDomain) {
    params.set("service_domain", clientSetup.serviceDomain);
  }
  const query = params.toString();
  return `${API_PREFIX}/machines/command/${machineId}${query ? `?${query}` : ""}`;
};

export default apiRoutes;
