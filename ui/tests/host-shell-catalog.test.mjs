import test from "node:test";
import assert from "node:assert/strict";
import { sessionRows } from "../src/shared/utils/host-shell-catalog.mjs";
import { handleDemoRequest, makeDemoData } from "../src/shared/demo/data.mjs";

test("a fallback response cannot become shell state", () => {
  for (const body of [undefined, {}, "<html>", {sessions:[null]}, {sessions:[{id:"a",name:[]}] }]) {
    assert.throws(() => sessionRows(body));
  }
  const rows = [{id:"a".repeat(32), name:"work", read_only:false}];
  assert.deepEqual(sessionRows({sessions:rows}), rows);
});

test("demo hosts have an empty immutable shell catalog", () => {
  const data = makeDemoData();
  const path = "/api/machines/example/terminal-sessions";
  assert.deepEqual(sessionRows(handleDemoRequest(data,"GET",path)), []);
  assert.throws(() => handleDemoRequest(data,"POST",path));
  assert.deepEqual(sessionRows(handleDemoRequest(data,"GET",path)), []);
});
