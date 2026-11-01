import assert from "node:assert/strict";
import test from "node:test";
import { demoTerminalTraffic, normalizeTerminalTraffic, terminalWindow, terminalRanges } from "../src/shared/utils/terminal-traffic.mjs";
test("all bounded API ranges retain gaps, exact scopes and valid measured zeroes", () => {
  for (const range of Object.keys(terminalRanges)) {
    const data = normalizeTerminalTraffic(demoTerminalTraffic(range));
    data.points[0].relay_received = 0;
    const rows = terminalWindow(data, "relay");
    assert(rows.length <= 120);
    assert.equal(rows[0].incoming, null, "missing reports must not become measured zeroes");
    assert.equal(rows.find(row => row.at === data.points[0].at).incoming, 0);
    assert.equal(rows.at(-1).outgoing, data.points.at(-1).relay_sent);
    assert.equal(terminalWindow(data, "direct").at(-1).outgoing, data.points.at(-1).udp_sent);
    assert.equal(terminalWindow(data, "pty").at(-1).incoming, data.points.at(-1).pty_input);
  }
});
test("unknown or malformed telemetry cannot masquerade as an empty healthy graph", () => {
  for (const mutate of [value => value.points.push(value.points[0]), value => value.points[0].udp_sent = -1,
    value => value.points[0].at += 1, value => value.end += 1, value => value.interval_seconds = 1,
    value => value.scope = "public_ports", value => value.points[0].relay_sent = Number.MAX_SAFE_INTEGER + 1]) {
    const value = demoTerminalTraffic(); mutate(value);
    assert.throws(() => normalizeTerminalTraffic(value));
  }
  const empty = normalizeTerminalTraffic(demoTerminalTraffic("1h", "all", false));
  assert(terminalWindow(empty, "relay").every(row => row.incoming === null));
});
test("relay observations never invent PTY or UDP coverage for legacy hosts", () => {
  const value=demoTerminalTraffic();
  for(const point of value.points){delete point.host_reports;point.unreported_hosts=1;point.udp_sent=0;point.pty_input=0;}
  const data=normalizeTerminalTraffic(value);
  assert(terminalWindow(data,"relay").some(row=>row.incoming>0));
  assert(terminalWindow(data,"direct").every(row=>row.incoming===null));
  assert(terminalWindow(data,"pty").every(row=>row.incoming===null));
  value.points[0].host_reports=1;
  assert.equal(terminalWindow(normalizeTerminalTraffic(value),"direct").find(row=>row.at===value.points[0].at).outgoing,0);
});
