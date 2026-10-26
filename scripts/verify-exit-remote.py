#!/usr/bin/env python3
"""Explicit live test: Miro consumer; Luna and Condor exits, isolated namespaces."""
import ipaddress
import json
import os
import pathlib
import secrets
import shlex
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV = {**os.environ, "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
assert ENV.get("PORTHUB_TEST_MONGO_URI", "").startswith("mongodb://127.0.0.1:")
HOSTS = ["miro", None, "condor"]

def run(host, args, **kwargs):
    command = args if host is None else ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, shlex.join(args)]
    result = subprocess.run(command, check=True, text=True, capture_output=True, **kwargs)
    return (result.stdout + (result.stderr if args[:2] == ["docker", "logs"] else "")).strip()

def start(host, args, log):
    command = args if host is None else ["ssh", "-o", "BatchMode=yes", host, shlex.join(args)]
    return subprocess.Popen(command, stdout=log, stderr=log)

def build(package, test, features=()):
    with tempfile.TemporaryFile(mode="w+") as output:
        result = subprocess.run(["cargo", "test", "-p", package, "--test", test, *features, "--no-run", "--message-format=json"], cwd=ROOT, env=ENV, stdout=output)
        output.seek(0)
        messages = [json.loads(line) for line in output]
        if result.returncode:
            for message in messages:
                if message.get("reason") == "compiler-message": print(message["message"].get("rendered", ""))
            result.check_returncode()
        return next(m["executable"] for m in messages if m.get("executable") and m.get("target", {}).get("name") == test)

PROXY = '''import asyncio,sys
async def handle(reader, writer):
 try:
  upstream, output = await asyncio.open_connection('127.0.0.1', int(sys.argv[2]))
  async def copy(source, destination):
   try:
    while data := await source.read(65536):
     destination.write(data); await destination.drain()
   finally:
    destination.close()
  await asyncio.gather(copy(reader, output), copy(upstream, writer))
 except Exception:
  writer.close()
async def main():
 server = await asyncio.start_server(handle, sys.argv[1], 17601)
 async with server: await server.serve_forever()
asyncio.run(main())
'''
worker = build("porthub-agent", "exit_worker", ["--features", "netns-tests"])
fixture = build("porthub-api", "exit_remote")
prefix = "porthub-exit-remote-" + secrets.token_hex(5)
with tempfile.TemporaryDirectory(prefix=prefix + "-") as directory:
    directory = pathlib.Path(directory)
    ready = directory / "ready.json"
    log = open(directory / "fixture.log", "w+")
    api = subprocess.Popen([fixture, "--ignored", "--exact", "remote_exit_control_fixture", "--nocapture"], cwd=ROOT, env={**ENV, "PORTHUB_TEST_REMOTE_READY": str(ready)}, stdout=log, stderr=log)
    resources, processes, logs = [], [], [log]
    try:
        deadline = time.monotonic() + 25
        while not ready.exists():
            assert api.poll() is None and time.monotonic() < deadline, "fixture failed to become ready"
            time.sleep(.1)
        config = json.loads(ready.read_text())
        port = config["address"].rsplit(":", 1)[1]
        # Only compare these in memory; no public origin addresses in logs.
        probe = "import urllib.request; print(urllib.request.urlopen('https://api4.ipify.org', timeout=15).read().decode().strip())"
        expected = [run(host, ["python3", "-c", probe]) for host in [None, "condor"]]
        assert expected[0] != expected[1], "exit hosts need distinct public addresses"
        for i in [1, 2, 0]:
            host = HOSTS[i]
            name = prefix + "-" + str(i)
            remote_dir = run(host, ["mktemp", "-d", "/tmp/" + name + ".XXXXXXXX"])
            resources.append((host, name, remote_dir))
            routes = json.loads(run(host, ["ip", "-j", "-4", "route", "show", "table", "all"]))
            subnet = next(ipaddress.ip_network(f"198.19.{n}.0/24") for n in range(100+i, 250) if not any(r.get("dst") not in (None,"default") and ipaddress.ip_network(f"198.19.{n}.0/24").overlaps(ipaddress.ip_network(r["dst"], strict=False)) for r in routes))
            gateway = str(subnet.network_address + 1)
            run(host, ["docker", "network", "create", "--subnet", str(subnet), name])
            if host:
                forward_port = run(host, ["python3", "-c", "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"])
                forward_log = open(directory / f"forward-{i}.log", "w+"); logs.append(forward_log)
                processes.append(subprocess.Popen(["ssh", "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-R", f"127.0.0.1:{forward_port}:127.0.0.1:{port}", host], stdout=forward_log, stderr=forward_log))
            else: forward_port = port
            proxy = directory / f"proxy-{i}.py"; proxy.write_text(PROXY)
            profile = {**config["profiles"][i], "server": f"http://{gateway}:17601"}
            envfile = directory / f"env-{i}"
            envfile.write_text("\n".join([
                "PORTHUB_TEST_OWNED_NETNS=1", "PORTHUB_TEST_PROFILE=" + json.dumps(profile),
                "PORTHUB_TEST_ROLE=" + ("http-consumer" if i == 0 else "exit"),
                "PORTHUB_TEST_EXIT_IPS=" + json.dumps(expected),
                f"PORTHUB_TEST_CONTROL_URL=http://{gateway}:17601", "PORTHUB_TEST_CONTROL_KEY=" + config["control_key"],
            ]) + "\n")
            envfile.chmod(0o600)
            for source, dest in [(worker,"worker"),(str(proxy),"proxy.py"),(str(envfile),"env")]:
                if host: subprocess.run(["scp", "-q", source, f"{host}:{remote_dir}/{dest}"], check=True)
                else: run(None, ["cp", source, f"{remote_dir}/{dest}"])
            proxy_log = open(directory / f"proxy-{i}.log", "w+"); logs.append(proxy_log)
            processes.append(start(host, ["timeout", "420", "python3", remote_dir+"/proxy.py", gateway, forward_port], proxy_log))
            run(host, ["docker", "image", "inspect", "ubuntu:24.04"] ) if run(host, ["docker", "images", "-q", "ubuntu:24.04"]) else run(host, ["docker", "pull", "ubuntu:24.04"])
            time.sleep(.5)
            run(host, ["docker", "run", "-d", "--name", name, "--network", name, "--read-only", "--tmpfs", "/state:rw,mode=700", "--tmpfs", "/run/porthub-exits:rw,mode=700", "--tmpfs", "/tmp:rw,mode=1777", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges:true", "--security-opt", "systempaths=unconfined", "--security-opt", "apparmor=unconfined", "--sysctl", "net.ipv4.ip_forward=0", "--device", "/dev/net/tun", "--env-file", remote_dir+"/env", "--mount", f"type=bind,src={remote_dir}/worker,dst=/worker,readonly", "--entrypoint", "/worker", "ubuntu:24.04", "--ignored", "--exact", "isolated_exit_worker", "--nocapture"])
        status = run("miro", ["docker", "wait", prefix+"-0"], timeout=360)
        print(run("miro", ["docker", "logs", prefix+"-0"]))
        assert status == "0", "remote consumer test failed"
        print("Real-host exit selection passed; restoring test resources.")
    finally:
        for host, name, remote_dir in reversed(resources):
            # SSH termination does not reliably terminate its remote children.
            # Match the exact temporary script path before stopping that proxy.
            stop_proxy = "import os,signal; target=" + repr(remote_dir + "/proxy.py") + "\nfor entry in os.scandir('/proc'):\n if not entry.name.isdigit(): continue\n try: args=open(entry.path+'/cmdline','rb').read().split(b'\\0')\n except OSError: continue\n if len(args)>1 and args[0] in (b'python3',b'/usr/bin/python3') and args[1].decode()==target: os.kill(int(entry.name),signal.SIGTERM)"
            try: run(host, ["python3", "-c", stop_proxy], timeout=10)
            except Exception: print("Proxy cleanup requires review:", name)
            for command in [["docker","rm","-f",name],["docker","network","rm",name],["find",remote_dir,"-depth","-delete"]]:
                try: run(host, command, timeout=20)
                except Exception: print("Cleanup requires review:", name, command[0:2])
        for process in processes:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill()
        (directory / "stop").touch()
        try: api.wait(timeout=10)
        except subprocess.TimeoutExpired: api.terminate(); api.wait(timeout=5)
        for stream in logs: stream.close()
