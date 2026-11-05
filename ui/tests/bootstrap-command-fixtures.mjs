import {bootstrapCommand} from "../src/shared/utils/bootstrap-command.mjs";
const base=process.argv[2];
console.log(JSON.stringify([
  bootstrapCommand(`${base}/install/test-ticket`,"windows"),
  bootstrapCommand(`${base}/prefix/$value/%25/!value!/'quoted'/install/test-ticket`,"windows"),
]));
