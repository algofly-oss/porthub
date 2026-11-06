import {bootstrapCommand} from "../src/shared/utils/bootstrap-command.mjs";
const base=process.argv[2];
const shells={"cmd.exe":"cmd","powershell.exe":"powershell","pwsh.exe":"pwsh"};
console.log(JSON.stringify(Object.fromEntries(Object.entries(shells).map(([executable,shell])=>[executable,[
  bootstrapCommand(`${base}/install/test-ticket`,"windows",shell),
  bootstrapCommand(`${base}/prefix/$value/%25/!value!/'quoted'/install/test-ticket`,"windows",shell),
]]))));
