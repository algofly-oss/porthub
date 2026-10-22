#!/usr/bin/env python3
"""Run the private overlay end to end in disposable Docker containers.

Host-side runner; never deployed. It creates exactly porthub-test-api,
porthub-test-a, porthub-test-b and the internal network porthub-test, refuses
to start if any of those names already exist, and removes only the objects it
created. The controller uses its own per-run Mongo database (dropped on
shutdown) and a read-only source mount. Existing PortHub containers, public
ports, proxies and Rathole are not touched.

Usage: python3 api/tests/overlay_lab_run.py [--binary /tmp/porthub-native-dev]
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
API_CONTAINER = "porthub_api_prod"
NETWORK = "porthub-test"
CONTROLLER, NODE_A, NODE_B = "porthub-test-api", "porthub-test-a", "porthub-test-b"
IMAGE = "porthub-test:latest"
# Only configuration the controller needs; never printed.
ENV_PREFIXES = ("MONGO_", "REDIS_", "API_")

created_containers, created_networks = [], []
results = []


def docker(*args, check=True, stdin=None, timeout=120):
    run = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and run.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {run.stderr.strip()[:400]}")
    return run


def node_sh(node, script, timeout=60, check=False):
    return docker("exec", node, "sh", "-c", script, check=check, timeout=timeout)


def record(name, ok, detail=""):
    results.append({"test": name, "ok": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}", flush=True)


class Lab:
    def __init__(self, port, key):
        self.base, self.key = f"http://127.0.0.1:{port}", key

    def call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers={"x-lab-key": self.key, "content-type": "application/json"})
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read() or b"null")

    def policy(self, **body):
        return self.call("PUT", "/lab/policy", body)

    def state(self):
        return self.call("GET", "/lab/state")


def wait(what, ok, timeout=30, interval=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = ok()
            if value:
                return value
        except Exception:
            pass
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what}")


def refuse_existing():
    names = docker("ps", "-a", "--format", "{{.Names}}").stdout.split()
    taken = {CONTROLLER, NODE_A, NODE_B} & set(names)
    if taken:
        raise SystemExit(f"Refusing to run: containers already exist and are not owned by this run: {sorted(taken)}")
    if docker("network", "inspect", NETWORK, check=False).returncode == 0:
        raise SystemExit(f"Refusing to run: network {NETWORK} already exists")


def controller_env(path):
    config = json.loads(docker("inspect", API_CONTAINER).stdout)[0]["Config"]
    lines = [item for item in config["Env"] if item.split("=", 1)[0].startswith(ENV_PREFIXES)]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return config["Image"]


def setup(binary, scratch):
    refuse_existing()
    docker("network", "create", "--internal", NETWORK)
    created_networks.append(NETWORK)
    env_file = os.path.join(scratch, "controller.env")
    image = controller_env(env_file)
    database = "porthub_overlay_lab_" + secrets.token_hex(8)
    key = secrets.token_urlsafe(32)
    cid = docker("run", "-d", "--name", CONTROLLER, "--network", "porthub", "--env-file", env_file,
                 "-e", f"PORTHUB_OVERLAY_LAB_DATABASE={database}", "-e", f"PORTHUB_OVERLAY_LAB_SECRET={key}",
                 "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{ROOT}/api:/app:ro", "-w", "/app",
                 "-p", "127.0.0.1::8089", "--entrypoint", "python", image,
                 "-m", "uvicorn", "tests.overlay_lab_server:app", "--host", "0.0.0.0", "--port", "8089").stdout.strip()
    created_containers.append(cid)
    os.unlink(env_file)
    docker("network", "connect", NETWORK, cid)
    port = docker("port", cid, "8089/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1]
    lab = Lab(port, key)
    wait("controller", lambda: lab.state(), timeout=40)
    for node in (NODE_A, NODE_B):
        cid = docker("run", "-d", "--name", node, "--hostname", node, "--network", NETWORK,
                     "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                     "-v", f"{binary}:/usr/local/bin/porthub:ro",
                     "-v", f"{ROOT}/api/tests/overlay_lab_service.py:/lab/service.py:ro", IMAGE).stdout.strip()
        created_containers.append(cid)
        docker("exec", "-d", node, "python3", "/lab/service.py")
    return lab


def enroll_and_start(lab, which, node):
    ticket = lab.call("POST", f"/lab/enroll/{which}")["ticket"]
    run = docker("exec", "-i", node, "porthub", "enroll", "--server", f"http://{CONTROLLER}:8089",
                 "--profile", "/root/private.json", "--allow-insecure-http-for-tests", stdin=ticket, check=False)
    if run.returncode:
        raise RuntimeError(f"enroll {which} failed: {run.stderr.strip()[-400:]}")
    start_agent(node)


def start_agent(node):
    docker("exec", "-d", node, "sh", "-c", "exec porthub run --profile /root/private.json >>/tmp/agent.log 2>&1")


def agent_running(node):
    return node_sh(node, "pgrep -f 'porthub run' >/dev/null").returncode == 0


def curl(node, url, seconds=4):
    run = node_sh(node, f"curl -s -o /dev/null -w '%{{http_code}} %{{size_download}} %{{time_total}}' --max-time {seconds} {url}", timeout=seconds + 10)
    parts = run.stdout.split()
    return (parts[0] == "200", parts) if parts else (False, [])


def controller_bytes():
    stats = node_sh(CONTROLLER, "cat /proc/net/dev", check=True).stdout
    total = 0
    for line in stats.splitlines()[2:]:
        name, values = line.split(":", 1)
        if name.strip() != "lo":
            fields = values.split()
            total += int(fields[0]) + int(fields[8])
    return total


def peers_by_machine(lab):
    state = lab.state()
    ids = {v: k for k, v in state["machines"].items()}
    return {ids[p["_id"].split(":")[1]]: p for p in state["peers"]}


def paths_direct(lab):
    peers = peers_by_machine(lab)
    a, b = peers.get("a", {}), peers.get("b", {})
    return a.get("paths", {}).get(b.get("_id")) == "direct" and b.get("paths", {}).get(a.get("_id")) == "direct"


def tests(lab):
    state = lab.state()
    public_before = (state["public_ports"], state["public_proxies"])
    enroll_and_start(lab, "a", NODE_A)
    enroll_and_start(lab, "b", NODE_B)
    peers = wait("both agents syncing", lambda: (lambda p: p if len(p) == 2 and all(x.get("last_seen_at") for x in p.values()) else None)(peers_by_machine(lab)))
    ip_a, ip_b = peers["a"]["ip"], peers["b"]["ip"]
    record("enrollment allocates private addresses", ip_a != ip_b, f"a={ip_a} b={ip_b}")
    ok, _ = curl(NODE_B, f"http://127.0.0.1:18081/")
    record("denial-test service on 18081 is alive locally", ok)

    ok, parts = curl(NODE_A, f"http://{ip_b}:18080/", 3)
    record("default deny with no policy", not ok, " ".join(parts))

    lab.policy(enabled=True, protocol="tcp", ports="18080")
    began = time.time()
    wait("direct private path", lambda: paths_direct(lab), timeout=40)
    record("peers connect over a direct path", True, f"{time.time() - began:.1f}s after policy")
    ok, parts = wait("permitted HTTP", lambda: (lambda r: r if r[0] else None)(curl(NODE_A, f"http://{ip_b}:18080/")), timeout=15)
    record("permitted a->b tcp/18080", ok, " ".join(parts))
    ok, parts = curl(NODE_A, f"http://{ip_b}:18081/", 3)
    record("other port a->b tcp/18081 denied", not ok, " ".join(parts))
    ok, parts = curl(NODE_B, f"http://{ip_a}:18080/", 3)
    record("reverse direction b->a denied", not ok, " ".join(parts))
    udp = f"python3 -c \"import socket;s=socket.socket(2,2);s.settimeout(2);s.sendto(b'ping',('{ip_b}',19090));print(s.recv(64))\""
    record("udp not granted by tcp policy", node_sh(NODE_A, udp).returncode != 0)
    record("icmp not granted by tcp policy", node_sh(NODE_A, f"ping -c1 -W2 {ip_b}").returncode != 0)

    before = controller_bytes()
    ok, parts = curl(NODE_A, f"http://{ip_b}:18080/bulk", 120)
    moved = int(parts[1]) if ok else 0
    controller_delta = controller_bytes() - before
    seconds = float(parts[2]) if ok else 0
    record("bulk transfer over private path", ok and moved >= 32 * 1024 * 1024,
           f"{moved / 1048576:.1f} MiB in {seconds:.2f}s = {moved * 8 / max(seconds, 1e-6) / 1e6:.0f} Mbit/s")
    record("bulk payload bypasses the controller", ok and controller_delta < moved / 20,
           f"controller moved {controller_delta / 1024:.0f} KiB during transfer")

    node_sh(NODE_A, f"rm -f /tmp/stream; (curl -s --max-time 60 http://{ip_b}:18080/stream > /tmp/stream &)")
    wait("stream started", lambda: int(node_sh(NODE_A, "stat -c %s /tmp/stream").stdout or 0) > 4096, timeout=10)
    lab.policy(enabled=False)
    revoked_at = time.time()

    def stalled():
        first = int(node_sh(NODE_A, "stat -c %s /tmp/stream").stdout)
        time.sleep(1.0)
        return int(node_sh(NODE_A, "stat -c %s /tmp/stream").stdout) == first
    wait("existing stream cut off", stalled, timeout=30, interval=0)
    record("policy removal stops an established stream", True, f"stalled within {time.time() - revoked_at:.1f}s")
    ok, parts = curl(NODE_A, f"http://{ip_b}:18080/", 3)
    record("new connections denied after removal", not ok, " ".join(parts))

    lab.policy(enabled=True, protocol="udp", ports="19090")
    wait("udp policy", lambda: node_sh(NODE_A, udp).returncode == 0, timeout=40)
    record("udp a->b/19090 permitted by udp policy", True)
    ok, _ = curl(NODE_A, f"http://{ip_b}:18080/", 3)
    record("tcp denied under udp-only policy", not ok)

    lab.policy(enabled=True, protocol="icmp", ports="")
    wait("icmp policy", lambda: node_sh(NODE_A, f"ping -c1 -W2 {ip_b}").returncode == 0, timeout=40)
    record("icmp echo a->b permitted by icmp policy", True)
    record("icmp b->a denied (directional)", node_sh(NODE_B, f"ping -c1 -W2 {ip_a}").returncode != 0)

    lab.policy(enabled=True, protocol="tcp", ports="18080", bidirectional=True)
    wait("bidirectional", lambda: curl(NODE_B, f"http://{ip_a}:18080/", 3)[0], timeout=40)
    record("bidirectional policy permits b->a", True)

    node_sh(NODE_B, "pkill -f 'porthub run'")
    wait("agent b stopped", lambda: not agent_running(NODE_B), timeout=15)
    record("private interface removed on exit", "ph" not in node_sh(NODE_B, "ip -o link | awk -F': ' '{print $2}' | grep '^ph' || true").stdout)
    start_agent(NODE_B)
    began = time.time()
    wait("reconnect after restart", lambda: curl(NODE_A, f"http://{ip_b}:18080/", 3)[0], timeout=60)
    record("restarted peer reconnects", True, f"{time.time() - began:.1f}s")

    lab.call("DELETE", f"/api/access/private/peers/{peers['b']['_id']}")
    wait("revoked agent exits", lambda: not agent_running(NODE_B), timeout=20)
    record("revoked credential stops the agent", True)
    ok, _ = curl(NODE_A, f"http://{ip_b}:18080/", 3)
    record("revoked peer unreachable", not ok)

    state = lab.state()
    record("no public ports or proxies written", (state["public_ports"], state["public_proxies"]) == public_before == (0, 0))


def cleanup():
    for cid in reversed(created_containers):
        # SIGTERM lets the controller drop its per-run database before exit.
        docker("stop", "-t", "15", cid, check=False)
        docker("rm", "-f", cid, check=False)
    for name in created_networks:
        docker("network", "rm", name, check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="/tmp/porthub-native-dev")
    parser.add_argument("--keep-logs", default="")
    args = parser.parse_args()
    if not os.path.isfile(args.binary):
        raise SystemExit("Build the native client first")
    with tempfile.TemporaryDirectory(prefix="porthub-lab-") as scratch:
        try:
            lab = setup(os.path.abspath(args.binary), scratch)
            tests(lab)
        except Exception as error:
            record("lab run", False, str(error))
        finally:
            if created_containers:
                for node in (NODE_A, NODE_B):
                    log = node_sh(node, "tail -n 40 /tmp/agent.log").stdout
                    if args.keep_logs:
                        with open(os.path.join(args.keep_logs, f"{node}.log"), "w") as f:
                            f.write(log)
                    if any(not r["ok"] for r in results):
                        print(f"--- {node} agent log ---\n{log}")
            cleanup()
    failed = [r for r in results if not r["ok"]]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
