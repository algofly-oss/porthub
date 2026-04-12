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
  listConnections: "/connections/list",
  deleteConnection: "/connections/delete",
  // Machines
  addMachine: "/machines/add",
  updateMachine: "/machines/update",
  listMachines: "/machines/list",
  deleteMachine: "/machines/delete",
  refreshMachineToken: "/machines/refresh-token",
  requestClientUpdate: "/machines/request-client-update",
  syncMachine: "/machines/sync",
};

Object.entries(apiRoutes).forEach(([key, value]) => {
  apiRoutes[key] = API_PREFIX + value;
});

apiRoutes.checkExternalPortAvailability = (port) =>
  `${API_PREFIX}/connections/external-port/${port}/availability`;

apiRoutes.getMachineCommand = (machineId) =>
  `${API_PREFIX}/machines/command/${machineId}`;

export default apiRoutes;
