const API_PREFIX = process.env.API_PREFIX || "/api";

let apiRoutes = {
  // auth
  signUp: "/auth/signup",
  signIn: "/auth/signin",
  signOut: "/auth/signout",
  accountInfo: "/auth/me",

  // Connections
  getRandomPort: "/connections/random",
  addConnection: "/connections/add",
  updateConnection: "/connections/update",
  listConnections: "/connections/list",
  deleteConnection: "/connections/delete",
  getConnectionCommand: "/connections/command",
};

Object.entries(apiRoutes).forEach(([key, value]) => {
  apiRoutes[key] = API_PREFIX + value;
});

apiRoutes.checkExternalPortAvailability = (port) =>
  `${API_PREFIX}/connections/external-port/${port}/availability`;

export default apiRoutes;
