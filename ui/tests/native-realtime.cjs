// Official frontend client against an isolated native API (test credentials only).
const assert = require("node:assert/strict");
const http = require("node:http");
const https = require("node:https");
const { io } = require("socket.io-client");
const base = process.env.PORTHUB_TEST_SOCKET_URL;
const machine = process.env.PORTHUB_TEST_MACHINE_ID;
const token = process.env.PORTHUB_TEST_MACHINE_TOKEN;
const cookie = process.env.PORTHUB_TEST_SESSION_COOKIE;
const insecure = process.env.PORTHUB_TEST_SELF_SIGNED === "1";
const agentLogs = process.env.PORTHUB_TEST_EXPECT_AGENT_LOG === "1";
assert(base && machine && token && cookie, "isolated test fixture required");
const socket = io(base, { path: "/socket.io", transports: ["websocket"],
  autoConnect: false, reconnection: false, forceNew: true, timeout: 5000,
  rejectUnauthorized: !insecure, extraHeaders: { Cookie: cookie } });
function wait(event, predicate = () => true, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.off(event, receive); reject(new Error(`Missing ${event}`)); }, timeout);
    function receive(data) {
      if (!predicate(data)) return;
      clearTimeout(timer); socket.off(event, receive); resolve(data);
    }
    socket.on(event, receive);
  });
}
function upload() {
  const body = JSON.stringify({ machine_id: machine, token, source: "native-sdk-test", lines: ["native realtime check"] });
  const url = new URL("/api/machines/client/logs", base);
  return new Promise((resolve, reject) => {
    const request = (url.protocol === "https:" ? https : http).request(url, {
      method: "POST", rejectUnauthorized: !insecure,
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    }, response => {
      let result = ""; response.setEncoding("utf8"); response.on("data", chunk => { result += chunk; });
      response.on("end", () => { try { assert.equal(response.statusCode, 200); assert.equal(JSON.parse(result).data.count, 1); resolve(); } catch (error) { reject(error); } });
    });
    request.setTimeout(5000, () => request.destroy(new Error("Log upload timeout")));
    request.on("error", reject); request.end(body);
  });
}
(async () => {
  try {
    const connected = wait("connect");
    const failure = new Promise((_, reject) => socket.once("connect_error", () => reject(new Error("Native socket authentication failed"))));
    socket.connect(); await Promise.race([connected, failure]);
    const snapshot = wait("/stc/machines/status-snapshot");
    socket.emit("/cts/machines/status-snapshot");
    assert((await snapshot).machines.some(item => item._id === machine));
    const subscribed = wait("/stc/machines/log-stream-status", data => data.machine_id === machine && data.subscribed === true);
    const line = agentLogs
      ? wait("/stc/machines/log-stream-line", data => data.machine_id === machine && data.source === "agent" && typeof data.line === "string" && data.line.trim().length > 0, 15000)
      : wait("/stc/machines/log-stream-line", data => data.machine_id === machine && data.line === "native realtime check");
    socket.emit("/cts/machines/log-stream-subscribe", { machine_id: machine });
    assert.equal((await subscribed).stream_requested, true);
    if (agentLogs) {
      const received = await line;
      assert(!received.line.includes(token), "agent diagnostics exposed credentials");
      assert(!/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(received.line), "agent diagnostics exposed an endpoint address");
    } else {
      await upload(); assert.equal((await line).source, "native-sdk-test");
    }
    const unsubscribed = wait("/stc/machines/log-stream-status", data => data.machine_id === machine && data.subscribed === false);
    socket.emit("/cts/machines/log-stream-unsubscribe", { machine_id: machine });
    assert.equal((await unsubscribed).stream_requested, false);
    console.log(agentLogs ? "Native agent diagnostics reached the UI Socket.IO client." : "Native Socket.IO status and log streaming passed.");
  } finally { socket.disconnect(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
