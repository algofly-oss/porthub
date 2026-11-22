import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import {
  expandPortRange,
  forwardCommand,
  forwardProfileCommand,
  forwardProfileFiles,
} from "../src/shared/transfers/port-forwards.mjs";

const sample = {
  username: "pf-" + "a".repeat(24),
  gateway: "example.test",
  sshPort: 8443,
  hostKey: "ssh-ed25519 AAAA",
  privateKey:
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
  mappings: [{ direction: "remote", gatewayPort: 51000, clientPort: 22 }],
};
test("one-line commands use independent keys and fail closed on first contact", () => {
  for (const client of ["openssh", "powershell"]) {
    const command = forwardCommand(sample, client);
    assert(!command.includes("\n"));
    for (const flag of [
      "BatchMode=yes",
      "NumberOfPasswordPrompts=0",
      "IdentitiesOnly=yes",
      "ExitOnForwardFailure=yes",
      "StrictHostKeyChecking=yes",
      "HostKeyAlias=porthub-forward-gateway",
      "-R 127.0.0.1:51000:127.0.0.1:22",
    ])
      assert(command.includes(flag), flag);
    assert(!command.includes("accept-new"));
  }
  const profile = forwardProfileFiles(sample);
  assert.equal(forwardProfileCommand, "ssh -N -F ./porthub.conf forward");
  assert.match(profile["porthub.conf"], /StrictHostKeyChecking yes/);
  assert.match(
    profile["porthub.conf"],
    /RemoteForward 127.0.0.1:51000 127.0.0.1:22/,
  );
  assert.equal(
    profile["porthub.known_hosts"],
    "porthub-forward-gateway ssh-ed25519 AAAA\n",
  );
  assert(!forwardProfileCommand.includes(sample.privateKey));
  assert.deepEqual(expandPortRange("65534-65535"), [65534, 65535]);
  for (const invalid of ["0", "-1", "8000-7999", "0-40", "65536", "23;id"])
    assert.throws(() => expandPortRange(invalid));
  for (const gateway of ["-oProxyCommand=bad", "host;id", "x\ny"])
    assert.throws(() => forwardCommand({ ...sample, gateway }, "openssh"));
  assert.doesNotThrow(() =>
    forwardCommand({ ...sample, gateway: "2001:db8::8" }, "openssh"),
  );
});

test("host profiles restrict reverse dynamic forwarding to TCP on the exporter loopback", () => {
  const host = { ...sample, mappings: [{ direction: "host", gatewayPort: 51000 }] };
  for (const client of ["openssh", "powershell"]) {
    const command = forwardCommand(host, client);
    assert.match(command, /-o PermitRemoteOpen=127\.0\.0\.1:\* -R 127\.0\.0\.1:51000 /);
  }
  const config = forwardProfileFiles(host)["porthub.conf"];
  assert.match(config, /^  PermitRemoteOpen 127\.0\.0\.1:\*$/m);
  assert.match(config, /^  RemoteForward 127\.0\.0\.1:51000$/m);
  assert.throws(() => forwardProfileFiles({ ...host, mappings: [...host.mappings, ...sample.mappings] }));
});

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}
async function roundtrip(port) {
  return new Promise((resolve, reject) => {
    const bytes = Buffer.from("PortHub verification " + port);
    const socket = net.connect({ host: "127.0.0.1", port }, () =>
      socket.write(bytes),
    );
    const chunks = [];
    socket.setTimeout(1200, () =>
      socket.destroy(new Error("stream timed out")),
    );
    socket.on("data", (data) => {
      chunks.push(data);
      const got = Buffer.concat(chunks);
      if (got.length >= bytes.length) {
        socket.destroy();
        if (got.equals(bytes)) resolve();
        else reject(new Error("data mismatch"));
      }
    });
    socket.on("error", reject);
    socket.on("close", () => reject(new Error("stream closed")));
  });
}
async function retry(action) {
  let err;
  for (let n = 0; n < 65; n++) {
    try {
      return await action();
    } catch (e) {
      err = e;
      await delay(80);
    }
  }
  throw err;
}
test(
  "pasted command and extracted profile both forward with a fresh OpenSSH client",
  { skip: !process.env.PORTHUB_FORWARD_BROKER_TEST, timeout: 30000 },
  async () => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), "porthub paste test "),
    );
    const home = path.join(root, "fresh home"),
      brokerDir = path.join(root, "broker"),
      temps = path.join(root, "private temp");
    await Promise.all(
      [home, brokerDir, temps].map((dir) => fs.mkdir(dir, { mode: 0o700 })),
    );
    const broker = spawn(
      process.env.PORTHUB_FORWARD_BROKER_TEST,
      ["--ignored", "--exact", "saved_entry_loopback_fixture"],
      {
        env: { ...process.env, PORTHUB_SSH_FIXTURE_DIR: brokerDir },
        stdio: "ignore",
      },
    );
    const echo = net.createServer((s) => s.pipe(s));
    const clients = [];
    try {
      const f = await retry(async () =>
        JSON.parse(
          await fs.readFile(path.join(brokerDir, "ready.json"), "utf8"),
        ),
      );
      const tempPort = net.createServer(),
        localPort = await listen(tempPort);
      await new Promise((r) => tempPort.close(r));
      const clientPort = await listen(echo);
      const entry = {
        gateway: f.host,
        sshPort: f.port,
        hostKey: f.host_public_key,
        privateKey: await fs.readFile(f.identity, "utf8"),
        username: f.username,
        mappings: [
          { direction: "remote", clientPort, gatewayPort: f.remote_port },
          {
            direction: "local",
            clientPort: localPort,
            target: f.import_host,
            servicePort: f.import_port,
          },
        ],
      };
      const askpass = path.join(root, "askpass");
      await fs.writeFile(
        askpass,
        '#!/bin/sh\ntouch "$HOME/prompt-called"\nexit 99\n',
        { mode: 0o700 },
      );
      function start(opts) {
        const proc = spawn("sh", ["-c", forwardCommand(opts, "openssh")], {
          cwd: "/",
          env: {
            PATH: process.env.PATH,
            HOME: home,
            TMPDIR: temps,
            SSH_ASKPASS: askpass,
            SSH_ASKPASS_REQUIRE: "force",
            DISPLAY: ":99",
          },
          stdio: ["ignore", "ignore", "pipe"],
          detached: true,
        });
        clients.push(proc);
        return proc;
      }
      const changed = start({ ...entry, hostKey: f.client_public_key });
      let error = "";
      changed.stderr.on("data", (c) => {
        error += c;
      });
      assert.notEqual((await once(changed, "exit"))[0], 0);
      assert.match(error, /Host key verification failed/i);
      const proc = start(entry);
      await retry(() => roundtrip(localPort));
      await retry(() => roundtrip(f.ingress_port));
      const stopped = once(proc, "exit");
      process.kill(-proc.pid, "SIGTERM");
      await stopped;
      for (const [filename, text] of Object.entries(
        forwardProfileFiles(entry),
      )) {
        await fs.writeFile(path.join(root, filename), text, { mode: 0o600 });
      }
      const [ssh, ...args] = forwardProfileCommand.split(" ");
      const profile = spawn(ssh, args, {
        cwd: root,
        stdio: "ignore",
        detached: true,
      });
      clients.push(profile);
      await retry(() => roundtrip(localPort));
      await retry(() => roundtrip(f.ingress_port));
      const revoked = once(profile, "exit");
      await fs.writeFile(path.join(brokerDir, "revoke"), "");
      await revoked;
      assert.deepEqual(
        await fs.readdir(home),
        [],
        "no user key prompts or configuration changes",
      );
      assert.deepEqual(
        await fs.readdir(temps),
        [],
        "temporary identity and pinned host file removed",
      );
    } finally {
      for (const c of clients)
        if (c.exitCode === null && c.signalCode === null) {
          try {
            process.kill(-c.pid, "SIGTERM");
          } catch {}
        }
      echo.close();
      await fs.writeFile(path.join(brokerDir, "stop"), "");
      if (broker.exitCode === null)
        await Promise.race([once(broker, "exit"), delay(500)]);
      broker.kill();
      await fs.rm(root, { recursive: true, force: true });
    }
  },
);
