import test from "node:test";
import assert from "node:assert/strict";
import { searchScore, selectProxies } from "../src/shared/utils/search.mjs";
import { aggregateTraffic, trafficSummary, formatBytes, normalizeTrafficSamples, buildTrafficWindow, trafficLinePath } from "../src/shared/utils/traffic.mjs";
import { compareInventoryEntries } from "../src/shared/utils/inventory-sort.mjs";

test("inventory ordering supports names, registration and directional traffic with stable ties", () => {
  const entries = [
    {id:"a",name:"Machine 2",createdAt:"2026-01-01",traffic:{volume:90,incomingVolume:80,outgoingVolume:10}},
    {id:"b",name:"Machine 10",createdAt:"2026-02-01",traffic:{volume:120,incomingVolume:20,outgoingVolume:100}},
  ];
  for (const [sort,first] of [["name","a"],["name-desc","b"],["oldest","a"],["newest","b"],["traffic","b"],["incoming","a"],["outgoing","b"]]) {
    assert.equal([...entries].sort((a,b)=>compareInventoryEntries(a,b,sort))[0].id,first);
  }
  assert(compareInventoryEntries({id:"a",name:"Same"},{id:"b",name:"Same"},"traffic")<0);
});

const proxies = [
  { _id: "1", hosts: ["docs.example.com", "wiki.example.com"], name: "Docs", enabled: true, group: "Work", updated_at: "2026-10-19T10:00:00Z", connection: { machine_id: "a", machine_name: "Atlas", external_port: 8080 } },
  { _id: "2", hosts: ["media.example.com"], name: "Media", enabled: false, group: "Home", updated_at: "2026-10-18T10:00:00Z", target_url: "http://192.168.1.2:8096" },
];
test("fuzzy search handles substitution, omission, insertion and transposition", () => {
  for (const typo of ["medai", "meda", "meedia", "medix"]) assert.equal(selectProxies(proxies, { query: typo })[0]?._id, "2");
  assert.equal(selectProxies(proxies, { query: "unrelated" }).length, 0);
  assert.equal(searchScore("", []), 0);
});
test("search covers aliases, machine, ports, target, and multiple terms", () => {
  for (const query of ["wiki", "atlas 8080", "work docs"]) assert.equal(selectProxies(proxies, { query })[0]?._id, "1");
  assert.equal(selectProxies(proxies, { query: "8096" })[0]?._id, "2");
  assert.equal(selectProxies(proxies, { query: "docs media" }).length, 0);
});
test("filters combine and sorting is deterministic", () => {
  assert.deepEqual(selectProxies(proxies, { status: "enabled", group: "Work", machine: "a" }).map(p => p._id), ["1"]);
  assert.equal(selectProxies(proxies, { machine: "manual" })[0]._id, "2");
  assert.equal(selectProxies(proxies, { group: "missing" }).length, 0);
  assert.equal(selectProxies([...proxies].reverse(), { sort: "updated" })[0]._id, "1");
  assert.equal(selectProxies([...proxies].reverse(), { sort: "status" })[0]._id, "1");
});
test("numeric ports and addresses never use typo matching", () => {
  assert.equal(searchScore("8081", [8080]), Infinity);
  assert.equal(searchScore("20003", [20063]), Infinity);
  assert.equal(searchScore("8080", [8080]), 0);
  assert.equal(searchScore("808", [8080]), 1);
  assert.equal(searchScore("192.0.2.10", ["192.0.2.11"]), Infinity);
  assert.equal(selectProxies(proxies, {query:"atlas 8081"}).length, 0);
});
test("traffic aggregation aligns timestamps and deduplicates IPs", () => {
  const result = aggregateTraffic([
    { traffic: [{ timestamp: 100, in_bytes: 10, out_bytes: 5, incoming_ips: ["1.2.3.4"] }] },
    { traffic: [{ timestamp: 100, in_bytes: 20, out_bytes: 2, incoming_ips: ["1.2.3.4"], drop_bytes: 3 }, { timestamp: 101, in_bytes: 2 }] },
  ]);
  assert.equal(result.length, 2); assert.equal(result[0].in_bytes, 30); assert.equal(result[0].out_bytes, 7);
  assert.deepEqual(result[0].incoming_ips, ["1.2.3.4"]);
  assert.equal(trafficSummary(result, 60, 102).volume, 39);
});
test("stale samples never appear as live rates and window excludes old data", () => {
  const samples = [{ timestamp: 100, in_bytes: 1024, drop_bytes: 12, blocked_ips: ["5.6.7.8"] }];
  assert.equal(trafficSummary(samples, 60, 102).incoming, 1024);
  assert.equal(trafficSummary(samples, 60, 110).incoming, 0);
  assert.equal(trafficSummary(samples, 60, 200).volume, 0);
  assert.equal(trafficSummary(samples, 60, 102).blockedVolume, 12);
  assert.equal(formatBytes(1024), "1.0 KB");
});

test("directional records are combined before trimming; an advancing 120-second window never develops a false plateau", () => {
  for (let now = 200; now <= 500; now++) {
    const raw = Array.from({length: 180}, (_, index) => {
      const timestamp = now - 179 + index;
      return [{timestamp, in_bytes: timestamp}, {timestamp, out_bytes: timestamp * 2}, {timestamp, drop_bytes: 3}];
    }).flat();
    const normalized = normalizeTrafficSamples(raw, 120);
    assert.equal(normalized.length, 120);
    assert.equal(normalized[0].timestamp, now - 119);
    const window = buildTrafficWindow(raw, 120, now).samples;
    assert(window.every(sample => sample.observed));
    window.forEach(sample => { assert.equal(sample.in_rate, sample.timestamp); assert.equal(sample.out_rate, sample.timestamp * 2); });
    const summary = trafficSummary(raw, 120, now);
    assert.equal(summary.incoming, now);
    assert.equal(summary.outgoing, now * 2);
  }
});

test("missing history is unknown and chart paths break at gaps instead of fabricating traffic", () => {
  const samples = [{timestamp: 100, in_bytes: 100}, {timestamp: 102, in_bytes: 20}];
  const window = buildTrafficWindow(samples, 10, 104).samples;
  assert.equal(window.filter(sample => sample.observed).length, 2);
  assert.equal(window[0].in_rate, 0);
  const path = trafficLinePath(window, "in_rate", 100, 20, 120);
  assert.equal((path.match(/M /g) || []).length, 2);
  assert.equal(trafficLinePath(window, "out_rate", 100, 20, 120), "");
});

test("rate accounts for a slow sampling interval while transferred volume remains exact", () => {
  const raw = [{timestamp: 100, interval_seconds: 2.5, in_bytes: 500, out_bytes: 250}];
  const summary = trafficSummary(raw, 60, 101);
  assert.equal(summary.incoming, 200);
  assert.equal(summary.outgoing, 100);
  assert.equal(summary.volume, 750);
  assert.equal(trafficSummary(normalizeTrafficSamples(raw), 60, 101).incoming, 200);
});

test("measured sampling intervals cover integer-second jitter without inventing bytes", () => {
  const raw = [{timestamp: 100, interval_seconds: 1, in_bytes: 100}, {timestamp: 102, interval_seconds: 1.2, in_bytes: 240}, {timestamp: 104, interval_seconds: 1.8, in_bytes: 540}];
  const normalized = normalizeTrafficSamples(normalizeTrafficSamples(raw));
  assert.equal(normalized[1].interval_seconds, 1.2);
  const window = buildTrafficWindow(normalized, 5, 104).samples;
  assert(window.every(sample => sample.observed));
  assert.equal(window[1].in_rate, 200);
  assert.equal(window[1].intervalAverage, true);
  assert.equal(window[1].in_bytes, 0);
  assert.equal((trafficLinePath(window, "in_rate", 100, 20, 600).match(/M /g) || []).length, 1);
  assert.equal(trafficSummary(raw, 60, 104).volume, 880);
  assert.equal(window.reduce((sum, sample) => sum + sample.in_bytes, 0), 880);
});

test("aggregation preserves overlapping coverage rather than adding interval durations", () => {
  const aggregate = aggregateTraffic([{traffic:[{timestamp:102,interval_seconds:1.2,in_bytes:120}]}, {traffic:[{timestamp:102,interval_seconds:1.2,in_bytes:240}]}]);
  assert.equal(aggregate[0].interval_seconds, 1.2);
  assert.equal(aggregate[0].in_rate, 300);
  const window = buildTrafficWindow(aggregate, 5, 102).samples;
  assert.equal(window.filter(sample => sample.observed).length, 2);
});

test("full 90-second history follows the latest measurement and leaves genuine outages visible", () => {
  const raw = Array.from({length: 61}, (_, index) => ({timestamp: 100 + index * 2, interval_seconds: 1.8, in_bytes: 180}));
  const {samples, windowEndTimestamp} = buildTrafficWindow(raw, 90);
  assert.equal(windowEndTimestamp, 220);
  assert.equal(samples.length, 90);
  assert.equal(samples[0].timestamp, 131);
  assert(samples.every(sample => sample.observed));
  const outage = buildTrafficWindow([{timestamp:100,in_bytes:100,interval_seconds:1}, {timestamp:105,in_bytes:100,interval_seconds:1.2}], 6, 105).samples;
  assert.equal(outage.filter(sample => !sample.observed).length, 3);
  assert.equal((trafficLinePath(outage, "in_rate", 100, 20, 200).match(/M /g) || []).length, 2);
});
