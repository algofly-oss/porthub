// Next 13's standalone launcher reads HOSTNAME for NextServer but omits it
// from http.Server.listen. Bind that listener to the configured loopback host.
const fs = require("fs");
const file = process.argv[2];
if (!file) throw new Error("Expected the standalone server.js path");
const source = fs.readFileSync(file, "utf8");
const before = "server.listen(currentPort, (err) => {";
const after = "server.listen(currentPort, hostname, (err) => {";
if (source.includes(after)) process.exit(0);
if (!source.includes(before)) {
  throw new Error("Standalone launcher changed; verify its bind address before deploying");
}
fs.writeFileSync(file, source.replace(before, after));
