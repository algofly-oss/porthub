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

test("retired shell requests fail without changing the demo machine inventory", () => {
  const data = makeDemoData();
  const before = structuredClone(data);
  const path = `/api/machines/${data.machines[0]._id}/terminal-sessions`;
  for (const endpoint of [path, `${path}/example`, `${path}/example/join`, "/api/terminal/host"]) {
    for (const method of ["GET", "POST", "DELETE"]) {
      assert.throws(() => handleDemoRequest(data, method, endpoint), { status: 410 });
    }
  }
  assert.deepEqual(data, before);
});
