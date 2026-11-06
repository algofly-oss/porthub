import test from "node:test";
import assert from "node:assert/strict";
import { bootstrapCommand } from "../src/shared/utils/bootstrap-command.mjs";
test("Windows launches an explicit shell and does not require command aliases", () => {
  const command = bootstrapCommand("https://hub.example/install/ticket", "windows");
  assert(command.startsWith('powershell.exe -NoProfile -Command "'));
  assert(command.includes("Invoke-RestMethod -Uri 'https://hub.example/install/ticket/windows.ps1'"));
  assert(command.includes("Invoke-Expression"));
  assert(!command.includes("ExecutionPolicy"));
});
test("URL content cannot expand in either parent PowerShell or cmd.exe", () => {
  const command = bootstrapCommand("https://hub.example/prefix/$value/%25/!value!/'quoted'/`value`/install/ticket", "windows");
  assert(!/[\$%`!^]/.test(command));
  assert(command.includes("[char]36"));
  assert(command.includes("[char]37"));
  assert(command.includes("[char]39"));
});
test("Linux and WSL retain the bash installer with literal URL quoting", () => {
  assert.equal(bootstrapCommand("https://hub.example/install/ticket", "linux"), "curl -fsSL 'https://hub.example/install/ticket' | bash");
  assert(bootstrapCommand("https://hub.example/a'b/install/ticket", "linux").includes("'\\''"));
});
test("invalid bootstrap URLs never become executable commands", () => {
  for (const url of ["", "not a URL", "file:///tmp/code", "https://user:secret@hub.example/install/ticket", "https://hub.example/install/ticket#fragment"]) assert.equal(bootstrapCommand(url, "windows"), "");
});
test("PowerShell 5.1 and 7 get native commands without a nested shell", () => {
  for (const shell of ["powershell", "pwsh"]) {
    const command = bootstrapCommand("https://hub.example/install/ticket", "windows", shell);
    assert(command.startsWith("[Net.ServicePointManager]::SecurityProtocol"));
    assert(command.includes("Invoke-RestMethod -Uri 'https://hub.example/install/ticket/windows.ps1'"));
    assert(!command.includes("powershell.exe"));
  }
});
test("download options use the same installer capability and reject invalid URLs", async () => {
  const { windowsInstallerDownloads } = await import("../src/shared/utils/bootstrap-command.mjs");
  assert.deepEqual(windowsInstallerDownloads("https://hub.example/install/ticket/"), [
    { label: "Download .bat", url: "https://hub.example/install/ticket/windows.bat" },
    { label: "Download .ps1", url: "https://hub.example/install/ticket/windows.ps1" },
  ]);
  assert.deepEqual(windowsInstallerDownloads("file:///tmp/file"), []);
});
