#!/usr/bin/env python3
"""Interoperability lab: Go `porthub tunnel` against the real rathole server.

Host-side runner; never deployed. Creates exactly porthub-test-rathole,
porthub-test-a, porthub-test-b and the internal network porthub-test, refuses
to run if they already exist, and removes only what it created. The real
rathole client from the same image runs beside the Go client as a reference.

Usage: python3 api/tests/tunnel_lab_run.py [--binary /tmp/porthub-native-dev]
"""
import argparse
import os
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NETWORK, SERVER, NODE_A, NODE_B = "porthub-test", "porthub-test-rathole", "porthub-test-a", "porthub-test-b"
RATHOLE_IMAGE, NODE_IMAGE = "archef2000/rathole:latest", "porthub-test:latest"
created_containers, created_networks, results = [], [], []


def docker(*args, check=True, timeout=180):
    run = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and run.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {run.stderr.strip()[:400]}")
    return run


def sh(node, script, timeout=120):
    return docker("exec", node, "sh", "-c", script, check=False, timeout=timeout)


def record(name, ok, detail=""):
    results.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}", flush=True)


def wait(what, ok, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ok():
            return True
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {what}")


def curl(port, path="/", seconds=5):
    run = sh(NODE_B, f"curl -s -o /dev/null -w '%{{http_code}} %{{size_download}} %{{time_total}}' --max-time {seconds} http://{SERVER}:{port}{path}", seconds + 10)
    parts = run.stdout.split()
    return (bool(parts) and parts[0] == "200"), parts


def client_toml(services):
    lines = ["# Managed by PortHub. Manual changes will be overwritten.", "[client]", f'remote_addr = "{SERVER}:2334"', ""]
    for name, token in services:
        lines += [f"[client.services.{name}]", f'token = "{token}"', 'local_addr = "127.0.0.1:18080"', ""]
    return "\n".join(lines)


def write_in(node, path, content):
    run = subprocess.run(["docker", "exec", "-i", node, "sh", "-c", f"cat > {path}.tmp && mv {path}.tmp {path}"], input=content, text=True, capture_output=True)
    if run.returncode:
        raise RuntimeError(run.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="/tmp/porthub-native-dev")
    args = parser.parse_args()
    names = docker("ps", "-a", "--format", "{{.Names}}").stdout.split()
    if {SERVER, NODE_A, NODE_B} & set(names) or docker("network", "inspect", NETWORK, check=False).returncode == 0:
        raise SystemExit("Refusing to run: lab containers or network already exist")
    token, ref_token = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="porthub-tunnel-lab-") as scratch:
        try:
            docker("network", "create", "--internal", NETWORK)
            created_networks.append(NETWORK)
            with open(os.path.join(scratch, "server.toml"), "w") as f:
                f.write(f"""[server]
bind_addr = "0.0.0.0:2334"
[server.services.porthub_go]
token = "{token}"
bind_addr = "0.0.0.0:9000"
[server.services.porthub_go2]
token = "{token}"
bind_addr = "0.0.0.0:9002"
[server.services.porthub_ref]
token = "{ref_token}"
bind_addr = "0.0.0.0:9001"
""")
            os.chmod(scratch, 0o755)
            os.chmod(os.path.join(scratch, "server.toml"), 0o644)
            created_containers.append(docker("run", "-d", "--name", SERVER, "--network", NETWORK, "-v", f"{scratch}:/cfg:ro",
                                             "--entrypoint", "/rathole", RATHOLE_IMAGE, "-s", "/cfg/server.toml").stdout.strip())
            version = docker("run", "--rm", "--entrypoint", "/rathole", RATHOLE_IMAGE, "--version").stdout.strip()
            docker("cp", f"{SERVER}:/rathole", os.path.join(scratch, "rathole"))
            for node in (NODE_A, NODE_B):
                created_containers.append(docker("run", "-d", "--name", node, "--network", NETWORK,
                                                 "-v", f"{os.path.abspath(args.binary)}:/usr/local/bin/porthub:ro",
                                                 "-v", f"{scratch}/rathole:/usr/local/bin/rathole:ro",
                                                 "-v", f"{ROOT}/api/tests/overlay_lab_service.py:/lab/service.py:ro", NODE_IMAGE).stdout.strip())
            docker("exec", "-d", NODE_A, "python3", "/lab/service.py")
            print(f"server: {version}")

            write_in(NODE_A, "/root/client.toml", client_toml([("porthub_go", token)]))
            write_in(NODE_A, "/root/ref.toml", client_toml([("porthub_ref", ref_token)]))
            docker("exec", "-d", NODE_A, "sh", "-c", "exec porthub tunnel --config /root/client.toml >>/tmp/go.log 2>&1")
            docker("exec", "-d", NODE_A, "sh", "-c", "exec rathole /root/ref.toml >>/tmp/ref.log 2>&1")
            wait("go tunnel", lambda: curl(9000)[0])
            record("Go client forwards through real rathole server", True, curl(9000)[1][0])
            wait("reference tunnel", lambda: curl(9001)[0])

            for label, port in (("Go client", 9000), ("rathole client", 9001)):
                times = []
                for _ in range(3):
                    ok, parts = curl(port, "/bulk", 120)
                    if ok:
                        times.append(float(parts[2]))
                ok = len(times) == 3 and True
                best = min(times) if times else 0
                record(f"{label}: 32 MiB bulk x3", ok, f"best {32 * 8 / max(best, 1e-6):.0f} Mbit/s ({best:.2f}s)")

            for label, port in (("Go client", 9000), ("rathole client", 9001)):
                run = sh(NODE_B, f"start=$(date +%s%N); for i in $(seq 1 200); do curl -s -o /dev/null -w '%{{http_code}}\\n' http://{SERVER}:{port}/ & done | sort | uniq -c; echo $(( ($(date +%s%N)-start)/1000000 ))ms", 120)
                record(f"{label}: 200 concurrent requests", "200 200" in " ".join(run.stdout.split()), " ".join(run.stdout.split()))

            write_in(NODE_A, "/root/client.toml", client_toml([("porthub_go2", token)]))
            wait("hot-reloaded service", lambda: curl(9002)[0], 15)
            record("hot reload adds a service", True)
            wait("removed service closed", lambda: not curl(9000, "/", 3)[0], 15)
            record("hot reload removes a service", True)

            docker("restart", SERVER)
            began = time.time()
            wait("reconnect after server restart", lambda: curl(9002, "/", 3)[0], 60)
            record("reconnects after server restart", True, f"{time.time() - began:.1f}s")

            write_in(NODE_A, "/root/client.toml", client_toml([("porthub_go2", "wrong-token")]))
            wait("auth failure logged", lambda: "incorrect token" in sh(NODE_A, "cat /tmp/go.log").stdout, 15)
            record("wrong token is rejected and reported", not curl(9002, "/", 3)[0])

            pid = sh(NODE_A, "pgrep -f 'porthub tunnel'").stdout.strip()
            sh(NODE_A, f"kill -TERM {pid}")
            wait("graceful exit", lambda: sh(NODE_A, "pgrep -f 'porthub tunnel'").returncode != 0, 10)
            record("SIGTERM exits cleanly", True)
        except Exception as error:
            record("lab run", False, str(error))
            print("--- go client log ---\n" + sh(NODE_A, "tail -n 30 /tmp/go.log").stdout)
            print("--- server log ---\n" + docker("logs", "--tail", "30", SERVER, check=False).stderr)
        finally:
            for cid in reversed(created_containers):
                docker("rm", "-f", cid, check=False)
            for name in created_networks:
                docker("network", "rm", name, check=False)
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
