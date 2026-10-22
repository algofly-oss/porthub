#!/usr/bin/env python3
"""Private overlay test across real machines. Host-side runner; never deployed.

  a = this host (Luna)  native agent as root, host network namespace
  b = Miro              native agent as root over SSH, host network namespace
  c = urm2 (optional)   agent in a disposable container with its OWN network
                        namespace; urm2's host network and production
                        containers are never touched

The lab controller (see overlay_lab_run.py) runs locally; remote agents reach
it through SSH reverse tunnels. The sudo password is read from
PORTHUB_TEST_SUDO_PASSWORD and only ever passed to `sudo -S` on stdin.
Everything created is removed afterwards, and host routes/links are compared
before and after.

Usage: PORTHUB_TEST_SUDO_PASSWORD=... python3 api/tests/overlay_hosts_run.py [--with-urm2]
"""
import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import overlay_lab_run as lab_run  # noqa: E402
from overlay_lab_run import Lab, docker, record, wait  # noqa: E402

ROOT = lab_run.ROOT
CONTROLLER = lab_run.CONTROLLER
MIRO, URM2 = "miro", "urm2"
REMOTE_DIR = "porthub-overlay-test"  # under the remote user's home
TUNNEL_PORT = 18089
STUN = [{"urls": ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"]}]
PASSWORD = os.environ.get("PORTHUB_TEST_SUDO_PASSWORD", "")
background, cleanups = [], []


def run(cmd, input=None, timeout=120, check=False):
    r = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(f"{cmd[0]} failed: {(r.stderr or r.stdout).strip()[-400:]}")
    return r


def ssh(host, script, input=None, timeout=120, check=False):
    return run(["ssh", "-o", "BatchMode=yes", host, script], input=input, timeout=timeout, check=check)


def local(script, input=None, timeout=120, check=False):
    return run(["sh", "-c", script], input=input, timeout=timeout, check=check)


def sudo_bg(where, command):
    """Start command as root in the background; the password goes to stdin."""
    # Output is detached: a backgrounded child holding our pipes would hang us.
    script = f"sudo -S -p '' -b sh -c {shlex.quote(command)} >/dev/null 2>&1"
    r = (local(script, input=PASSWORD + "\n") if where == "luna" else ssh(where, script, input=PASSWORD + "\n"))
    if r.returncode:
        raise RuntimeError(f"start on {where} failed: {r.stderr.strip()[-300:]}")


def sudo(where, command):
    script = f"sudo -S -p '' sh -c {shlex.quote(command)}"
    return local(script, input=PASSWORD + "\n") if where == "luna" else ssh(where, script, input=PASSWORD + "\n")


def pattern(text):
    """A pkill -f pattern that cannot match the shell command carrying it."""
    return "'[" + text[0] + "]" + text[1:] + "'"


def host_network(where):
    script = "ip -4 route show table all | grep -v ' ph[0-9a-f]\\{8\\} ' | sort; ip -o link | awk -F': ' '{print $2}' | grep -v '^veth' | sort"
    return (local(script) if where == "luna" else ssh(where, script)).stdout


def start_controller(scratch):
    lab_run.refuse_existing()
    env_file = os.path.join(scratch, "controller.env")
    image = lab_run.controller_env(env_file)
    key = secrets.token_urlsafe(32)
    cid = docker("run", "-d", "--name", CONTROLLER, "--network", "porthub", "--env-file", env_file,
                 "-e", f"PORTHUB_OVERLAY_LAB_DATABASE=porthub_overlay_lab_{secrets.token_hex(8)}",
                 "-e", f"PORTHUB_OVERLAY_LAB_SECRET={key}", "-e", f"PORTHUB_PRIVATE_ICE_SERVERS={json.dumps(STUN)}",
                 "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{ROOT}/api:/app:ro", "-w", "/app",
                 "-p", "127.0.0.1::8089", "--entrypoint", "python", image,
                 "-m", "uvicorn", "tests.overlay_lab_server:app", "--host", "0.0.0.0", "--port", "8089").stdout.strip()
    lab_run.created_containers.append(cid)
    os.unlink(env_file)
    port = docker("port", cid, "8089/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1]
    lab = Lab(port, key)
    wait("controller", lambda: lab.state(), timeout=40)
    return lab, port


def reverse_tunnel(host, port, bind="127.0.0.1"):
    p = subprocess.Popen(["ssh", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-N",
                          "-R", f"{bind}:{TUNNEL_PORT}:127.0.0.1:{port}", host],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    background.append(p)
    time.sleep(2)
    if p.poll() is not None:
        raise RuntimeError(f"reverse tunnel to {host} failed")


def enroll(lab, which, enroll_cmd):
    ticket = lab.call("POST", f"/lab/enroll/{which}")["ticket"]
    r = enroll_cmd(ticket)
    if r.returncode:
        raise RuntimeError(f"enroll {which}: {r.stderr.strip()[-300:]}")


def curl(where, url, seconds=4):
    cmd = f"curl -s -o /dev/null -w '%{{http_code}} %{{size_download}} %{{time_total}}' --max-time {seconds} {url}"
    r = local(cmd, timeout=seconds + 15) if where == "luna" else ssh(where, cmd, timeout=seconds + 15)
    parts = r.stdout.split()
    return (bool(parts) and parts[0] == "200"), parts


def peers(lab):
    state = lab.state()
    ids = {v: k for k, v in state["machines"].items()}
    return {ids[p["_id"].split(":")[1]]: p for p in state["peers"]}


def path(lab, x, y):
    p = peers(lab)
    return p.get(x, {}).get("paths", {}).get(p.get(y, {}).get("_id"))


def mbit(parts):
    return f"{int(parts[1]) * 8 / max(float(parts[2]), 1e-6) / 1e6:.0f} Mbit/s"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-urm2", action="store_true")
    args = parser.parse_args()
    if not PASSWORD:
        raise SystemExit("PORTHUB_TEST_SUDO_PASSWORD is required")
    scratch = tempfile.mkdtemp(prefix="porthub-hosts-")
    os.chmod(scratch, 0o700)
    binary = "/tmp/porthub-native-dev"
    hosts = ["luna", MIRO]
    before = {h: host_network(h) for h in hosts}
    try:
        lab, port = start_controller(scratch)
        state = lab.state()
        public_before = (state["public_ports"], state["public_proxies"])

        # --- a: Luna, native agent as root
        profile_a = os.path.join(scratch, "a.json")
        enroll(lab, "a", lambda t: local(f"{binary} enroll --server http://127.0.0.1:{port} --profile {profile_a} --allow-insecure-http-for-tests", input=t))
        cleanups.append(lambda: sudo("luna", f"pkill -TERM -f {pattern(binary + ' run --profile ' + profile_a)}"))
        sudo_bg("luna", f"exec {binary} run --profile {profile_a} >>{scratch}/a.log 2>&1")

        # --- b: Miro, native agent as root; services run as the normal user
        ssh(MIRO, f"rm -rf ~/{REMOTE_DIR} && mkdir -m 700 ~/{REMOTE_DIR}", check=True)
        cleanups.append(lambda: ssh(MIRO, f"pkill -f {pattern(REMOTE_DIR + '/service.py')}; rm -rf ~/{REMOTE_DIR}"))
        run(["scp", "-q", binary, f"{MIRO}:{REMOTE_DIR}/porthub"], check=True)
        run(["scp", "-q", f"{ROOT}/api/tests/overlay_lab_service.py", f"{MIRO}:{REMOTE_DIR}/service.py"], check=True)
        ssh(MIRO, f"nohup python3 $HOME/{REMOTE_DIR}/service.py </dev/null >$HOME/{REMOTE_DIR}/service.log 2>&1 &", check=True)
        reverse_tunnel(MIRO, port)
        enroll(lab, "b", lambda t: ssh(MIRO, f"~/{REMOTE_DIR}/porthub enroll --server http://127.0.0.1:{TUNNEL_PORT} --profile ~/{REMOTE_DIR}/b.json --allow-insecure-http-for-tests", input=t))
        home = ssh(MIRO, "echo $HOME").stdout.strip()
        cleanups.insert(0, lambda: sudo(MIRO, f"pkill -TERM -f {pattern(REMOTE_DIR + '/porthub run')}"))
        sudo_bg(MIRO, f"exec {home}/{REMOTE_DIR}/porthub run --profile {home}/{REMOTE_DIR}/b.json >>{home}/{REMOTE_DIR}/b.log 2>&1")

        # --- c: urm2 container with its own network namespace
        if args.with_urm2:
            existing = ssh(URM2, "docker ps -a --format '{{.Names}}' | grep -x porthub-test-c; docker network ls --format '{{.Name}}' | grep -x porthub-test").stdout.strip()
            if existing:
                raise RuntimeError(f"urm2 already has {existing}; refusing")
            ssh(URM2, f"rm -rf ~/{REMOTE_DIR} && mkdir -m 755 ~/{REMOTE_DIR} ~/{REMOTE_DIR}/www", check=True)
            cleanups.append(lambda: ssh(URM2, f"docker rm -f porthub-test-c; docker network rm porthub-test; pkill -f {pattern(REMOTE_DIR + '/forward.py')}; rm -rf ~/{REMOTE_DIR}"))
            run(["scp", "-q", "/tmp/porthub-native-arm64", f"{URM2}:{REMOTE_DIR}/porthub"], check=True)
            ssh(URM2, f"head -c 33554432 /dev/urandom > ~/{REMOTE_DIR}/www/bulk; echo urm2-private-service > ~/{REMOTE_DIR}/www/index.html", check=True)
            ssh(URM2, "docker network create porthub-test >/dev/null", check=True)
            gateway = ssh(URM2, "docker network inspect porthub-test --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'").stdout.strip()
            reverse_tunnel(URM2, port)
            # The container cannot reach urm2's loopback; a user-level relay on
            # the test network's gateway address forwards only the controller port.
            forward = ("import socket,threading,sys\n"
                       "s=socket.socket();s.setsockopt(1,2,1);s.bind((sys.argv[1],%d));s.listen(64)\n"
                       "def pump(a,b):\n  try:\n    while (d:=a.recv(65536)): b.sendall(d)\n  except OSError: pass\n  finally:\n    a.close();b.close()\n"
                       "while True:\n  c,_=s.accept();u=socket.create_connection(('127.0.0.1',%d))\n"
                       "  threading.Thread(target=pump,args=(c,u),daemon=True).start();threading.Thread(target=pump,args=(u,c),daemon=True).start()\n") % (TUNNEL_PORT, TUNNEL_PORT)
            ssh(URM2, f"cat > ~/{REMOTE_DIR}/forward.py", input=forward, check=True)
            ssh(URM2, f"nohup python3 $HOME/{REMOTE_DIR}/forward.py {gateway} </dev/null >$HOME/{REMOTE_DIR}/forward.log 2>&1 &", check=True)
            home2 = ssh(URM2, "echo $HOME").stdout.strip()
            ssh(URM2, f"docker run -d --name porthub-test-c --network porthub-test --cap-add NET_ADMIN --device /dev/net/tun "
                      f"-v {home2}/{REMOTE_DIR}/porthub:/usr/local/bin/porthub:ro -v {home2}/{REMOTE_DIR}/www:/www:ro "
                      f"--entrypoint sleep redis:6.2-alpine infinity >/dev/null", check=True)
            enroll(lab, "c", lambda t: ssh(URM2, f"docker exec -i porthub-test-c porthub enroll --server http://{gateway}:{TUNNEL_PORT} --profile /root/c.json --allow-insecure-http-for-tests", input=t))
            ssh(URM2, "docker exec -d porthub-test-c sh -c 'exec porthub run --profile /root/c.json >>/tmp/c.log 2>&1'", check=True)
            ssh(URM2, "docker exec -d porthub-test-c porthub http.server 18080 /www", check=True)

        names = ["a", "b"] + (["c"] if args.with_urm2 else [])
        p = wait("agents syncing", lambda: (lambda x: x if len(x) == len(names) and all(v.get("last_seen_at") for v in x.values()) else None)(peers(lab)), timeout=40)
        ip = {k: v["ip"] for k, v in p.items()}
        record("real hosts enrolled", True, " ".join(f"{k}={v}" for k, v in sorted(ip.items())))

        ok, parts = curl("luna", f"http://{ip['b']}:18080/", 3)
        record("default deny Luna->Miro", not ok, " ".join(parts))

        lab.policy(enabled=True, protocol="tcp", ports="18080")
        began = time.time()
        wait("Luna-Miro path", lambda: path(lab, "a", "b") in {"direct", "relay"}, timeout=45)
        record("Luna<->Miro connected", True, f"{path(lab, 'a', 'b')} after {time.time() - began:.1f}s")
        ok, parts = wait("Luna->Miro HTTP", lambda: (lambda r: r if r[0] else None)(curl("luna", f"http://{ip['b']}:18080/")), timeout=20)
        record("Luna host curl -> Miro private service", ok, " ".join(parts))
        ok, parts = curl("luna", f"http://{ip['b']}:18081/", 3)
        record("Miro tcp/18081 denied (service alive on LAN)", not ok and curl("luna", "http://192.168.0.166:18081/", 3)[0])
        ok, _ = curl(MIRO, f"http://{ip['a']}:18080/", 3)
        record("reverse Miro->Luna denied", not ok)
        ok, overlay = curl("luna", f"http://{ip['b']}:18080/bulk", 120)
        ok2, lan = curl("luna", "http://192.168.0.166:18080/bulk", 120)
        record("32 MiB Luna<-Miro over overlay", ok, f"overlay {mbit(overlay) if ok else '-'} vs plain LAN {mbit(lan) if ok2 else '-'}")
        record("icmp blocked by tcp-only policy", "100% packet loss" in local(f"ping -c 2 -W 1 {ip['b']}").stdout)

        if args.with_urm2:
            began = time.time()
            try:
                wait("Luna-urm2 path", lambda: path(lab, "a", "c") in {"direct", "relay"}, timeout=60)
                record("Luna<->urm2 container connected across NAT", True, f"{path(lab, 'a', 'c')} after {time.time() - began:.1f}s")
                ok, parts = wait("Luna->urm2", lambda: (lambda r: r if r[0] else None)(curl("luna", f"http://{ip['c']}:18080/")), timeout=20)
                record("Luna host curl -> urm2 private service", ok, " ".join(parts))
                ok, parts = curl("luna", f"http://{ip['c']}:18080/bulk", 180)
                record("32 MiB Luna<-urm2 over overlay", ok, mbit(parts) if ok else " ".join(parts))
            except TimeoutError:
                record("Luna<->urm2 container connected across NAT", False, f"path={path(lab, 'a', 'c')} (no relay implemented yet)")
            ok, _ = curl(MIRO, f"http://{ip['c']}:18080/", 3)
            record("Miro->urm2 denied (no rule between destinations)", not ok)

        lab.policy(enabled=True, protocol="icmp", ports="")
        wait("icmp", lambda: " 0% packet loss" in local(f"ping -c 2 -W 1 {ip['b']}").stdout, timeout=30)
        rtt = local(f"ping -c 20 -i 0.2 -q {ip['b']} | tail -1").stdout.strip()
        lan_rtt = local("ping -c 20 -i 0.2 -q 192.168.0.166 | tail -1").stdout.strip()
        record("icmp allowed by icmp policy", True, f"overlay {rtt} | LAN {lan_rtt}")
        lab.policy(enabled=False)
        wait("revocation", lambda: "100% packet loss" in local(f"ping -c 2 -W 1 {ip['b']}").stdout, timeout=30)
        record("policy removal revokes on real hosts", True)

        lab.policy(enabled=True, protocol="tcp", ports="18080")
        sudo(MIRO, f"pkill -TERM -f {pattern(REMOTE_DIR + '/porthub run')}")
        time.sleep(2)
        record("Miro interface removed on stop", "ph" not in ssh(MIRO, "ip -o link | awk -F': ' '{print $2}' | grep '^ph' || true").stdout)
        sudo_bg(MIRO, f"exec {home}/{REMOTE_DIR}/porthub run --profile {home}/{REMOTE_DIR}/b.json >>{home}/{REMOTE_DIR}/b.log 2>&1")
        began = time.time()
        wait("reconnect", lambda: curl("luna", f"http://{ip['b']}:18080/", 3)[0], timeout=60)
        record("Miro agent restart reconnects", True, f"{time.time() - began:.1f}s")
        state = lab.state()
        record("no public ports or proxies written", (state["public_ports"], state["public_proxies"]) == public_before)
    except Exception as error:
        record("hosts run", False, str(error)[:500])
    finally:
        for log, where in ((f"{scratch}/a.log", "luna"), (f"~/{REMOTE_DIR}/b.log", MIRO)):
            out = local(f"tail -n 15 {log}") if where == "luna" else ssh(where, f"tail -n 15 {log}")
            if any(not r["ok"] for r in lab_run.results):
                print(f"--- {where} agent log ---\n{out.stdout}")
        if args.with_urm2:
            print("--- urm2 agent log ---\n" + ssh(URM2, "docker exec porthub-test-c tail -n 15 /tmp/c.log").stdout)
        for fn in cleanups:
            try:
                fn()
            except Exception as e:
                print("cleanup:", e)
        for p in background:
            p.terminate()
        lab_run.cleanup()
        time.sleep(2)
        for h in hosts:
            record(f"{h} routes/links unchanged after test", host_network(h) == before[h])
        local(f"sudo -S -p '' rm -rf {scratch}", input=PASSWORD + "\n")
    failed = [r for r in lab_run.results if not r["ok"]]
    print(f"{len(lab_run.results) - len(failed)}/{len(lab_run.results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
