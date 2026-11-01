import test from "node:test";
import assert from "node:assert/strict";
import { terminalStunServers } from "../src/lib/terminalConnectivity.mjs";
test("terminal discovery endpoints are explicit, canonical and bounded",()=>{
  assert.deepEqual(terminalStunServers(""),[]);
  assert.deepEqual(terminalStunServers("stun:example.com\nstun:example.com:3478?transport=udp"),["stun:example.com:3478"]);
  assert.deepEqual(terminalStunServers("stun:[2001:db8::1]:19302"),["stun:[2001:db8::1]:19302"]);
  for(const invalid of ["turn:example.com","https://example.com","stun:user:secret@example.com","stun:example.com/path","stun:example.com?transport=tcp","stun:example.com:0","stun:example.com:65536","stun:0.0.0.0","stun:224.0.0.1","stun:[ff02::1]","stun:[fe80::1]","stun:example.com#fragment","stun:a,stun:b,stun:c"])
    assert.throws(()=>terminalStunServers(invalid),invalid);
});
