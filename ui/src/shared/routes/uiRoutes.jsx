const UI_PREFIX = process.env.UI_PREFIX || "";

const uiRoutes = {
  root: "/",
  home: "/home",
  trafficMonitor: "/traffic-monitor",
  accountRedirect: "/account",
  signIn: "/account/signin",
  signUp: "/account/signup",
  forgotPassword: "/account/forgot",
};

Object.entries(uiRoutes).forEach(([key, value]) => {
  uiRoutes[key] = UI_PREFIX + value;
});

uiRoutes.getTrafficMonitor = ({
  dataId,
  hostName,
  hostDescription,
  localIp,
  serviceName,
  externalPort,
}) => {
  const params = new URLSearchParams();
  if (dataId) {
    params.set("data_id", dataId);
  }
  if (hostName) {
    params.set("host", hostName);
  }
  if (hostDescription) {
    params.set("description", hostDescription);
  }
  if (localIp) {
    params.set("local_ip", localIp);
  }
  if (serviceName) {
    params.set("service", serviceName);
  }
  if (externalPort) {
    params.set("external_port", String(externalPort));
  }

  const queryString = params.toString();
  return `${uiRoutes.trafficMonitor}${queryString ? `?${queryString}` : ""}`;
};

export default uiRoutes;
