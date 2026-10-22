import assert from "node:assert/strict";
import { makeDemoData, handleDemoRequest } from "../src/shared/demo/data.mjs";

const state = makeDemoData();
const snapshot = handleDemoRequest(state, "get", "/api/access/snapshot");
assert.equal(snapshot.books.length, 3);
assert.equal(snapshot.users.length, 3);
assert.equal(snapshot.transport_ready, false);
assert.equal(snapshot.invitations.length, 1);
const source = state.machines.find(m => m.name === "orion-dev-02");
const destination = state.machines.find(m => m.name === "atlas-prod-19");
const check = (a, b, port) => handleDemoRequest(state, "post", "/api/access/test", {
  source_id: a._id, destination_id: b._id, protocol: "tcp", port,
}).data.allowed;
assert.equal(check(source, destination, 22), true);
assert.equal(check(source, destination, 23), false);
assert.equal(check(destination, source, 22), false);
const personal = state.machines.find(m => m.name === "luna-home-03");
assert.equal(check(personal, destination, 22), false, "Paused maintenance policy grants no access");
assert.equal(check(source, source, 443), true);
console.log("PASS sample policies: directional SSH, restricted ports, paused maintenance, people, invitation and inactive transport");
