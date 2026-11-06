#!/usr/bin/env python3
"""Real installer/SCM gate. Only disposable GitHub Windows runners may run this.

Serves the actual installer and tested executable over loopback. The existing
test-only plaintext opt-in is inserted into the rendered action, never shipped.
No external credentials, DNS edits, or certificate verification overrides.
"""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def ps(script, **kwargs):
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return run(["powershell.exe", "-NoProfile", "-EncodedCommand", encoded], **kwargs)


def wait_for(predicate, description):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.25)
    raise AssertionError("Timed out: " + description)


def main():
    if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("This gate requires a disposable GitHub-hosted Windows runner")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Administrator token required for the real SCM gate")
    import winreg

    source = Path(sys.argv[1]).resolve(strict=True)
    repo = Path(__file__).resolve().parent.parent
    state = Path(os.environ["ProgramData"]) / "PortHub"
    display = state.with_name("PortHubStatus")
    published = Path(os.environ["ProgramFiles"]) / "PortHub"
    # Never erase an earlier installation, even on an unexpectedly reused runner.
    if any(p.exists() for p in (state, display, published)):
        raise SystemExit("Refusing to modify an existing PortHub installation")
    ps("if (Get-Service -Name 'porthub-*' -ErrorAction SilentlyContinue) { exit 1 }")
    registry = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry) as key:
        old_path, path_type = winreg.QueryValueEx(key, "Path")
    machine = os.urandom(12).hex()
    token = "disposable-fixture-only"
    syncs = []
    errors = []
    downloads = []
    server = None
    service = None
    cli = published / "bin" / "porthub.exe"
    try:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass  # Request URLs can carry installer capabilities.

            def reply(self, body=b"", status=200, headers=None):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == "/install/test-ticket/windows.ps1":
                    template = (repo / "crates/porthub-api/assets/client/install.ps1").read_text()
                    body = template.replace("{{URL}}", "'" + origin + "/install/test-ticket'")
                    body = body.replace("{{ACTION}}", "setup --allow-insecure-http-for-tests")
                    return self.reply(body.encode(), headers={"Content-Type": "text/plain; charset=utf-8"})
                if path.startswith("/install/test-ticket/agent/windows_"):
                    downloads.append(path)
                    # Stream instead of buffering a large debug executable twice.
                    self.send_response(200)
                    self.send_header("Content-Length", str(source.stat().st_size))
                    self.end_headers()
                    with source.open("rb") as reader:
                        shutil.copyfileobj(reader, self.wfile)
                    return
                if path == "/install/test-ticket":
                    profile = dict(format_version=1, server=origin, machine_id=machine,
                                   token=token, fallback_servers=[], setup_overrides={"public_base_url": origin})
                    return self.reply(json.dumps(dict(format_version=1, profile=profile)).encode(),
                                      headers={"Content-Type": "application/json", "x-porthub-machine-id": machine})
                if path == "/api/machines/client/changes.toml":
                    return self.reply(status=204, headers={"x-porthub-machine-id": machine,
                                                          "x-porthub-config-version": "windows-install-fixture"})
                return self.reply(status=404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length > 65536:
                    return self.reply(status=413)
                body = self.rfile.read(length)
                if urlsplit(self.path).path == "/api/machines/client/sync":
                    value = json.loads(body)
                    if value.get("machine_id") != machine or value.get("token") != token:
                        errors.append("Invalid control identity")
                        return self.reply(status=403)
                    syncs.append(value.get("client_version"))
                    config = dict(machine_id=machine, version="windows-install-fixture",
                                  files={"client.toml": "[client]\nremote_addr='ws://127.0.0.1:9'\n"})
                    return self.reply(json.dumps({"data": {"config": config}}).encode(),
                                      headers={"Content-Type": "application/json"})
                return self.reply(status=404)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        origin = "http://127.0.0.1:" + str(server.server_port)
        identity = hashlib.sha256((origin + "\n" + machine).encode()).hexdigest()
        service = "porthub-" + identity[:24]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        commands = json.loads(subprocess.check_output(
            ["node", str(repo / "ui/tests/bootstrap-command-fixtures.mjs"), origin], text=True))
        with tempfile.TemporaryDirectory(prefix="porthub full installer ") as temporary:
            for shell in ("cmd.exe", "powershell.exe", "pwsh.exe", "batch"):
                before = len(syncs)
                line = commands["powershell.exe" if shell == "batch" else shell][0]
                env = os.environ.copy()
                # Every install starts with the original PATH, like a fresh terminal.
                env["Path"] = os.environ["Path"]
                if shell == "cmd.exe":
                    run([shell, "/d", "/s", "/c", line], env=env)
                elif shell == "batch":
                    batch = Path(temporary) / "porthub install.bat"
                    template = (repo / "crates/porthub-api/assets/client/install.bat").read_bytes()
                    payload = base64.b64encode(line.encode("utf-16le"))
                    batch.write_bytes(template.replace(b"{{PAYLOAD}}", payload))
                    run(["cmd.exe", "/d", "/s", "/c", '"' + str(batch) + '"'], env=env)
                else:
                    # Inspect the same PowerShell session after the copied command.
                    check = "; if ((Get-Command porthub -ErrorAction Stop).Source -ne '" + str(cli) + "') { throw 'Session PATH missing' }; porthub --version; if ($LASTEXITCODE) { exit 1 }"
                    encoded = base64.b64encode((line + check).encode("utf-16le")).decode()
                    run([shell, "-NoProfile", "-EncodedCommand", encoded], env=env)
                wait_for(lambda: len(syncs) > before, shell + " installed service control sync")
                ps("$s = Get-CimInstance Win32_Service -Filter \"Name='" + service + "'\"; "
                   "if ($s.State -ne 'Running' -or $s.StartMode -ne 'Auto' -or $s.StartName -ne 'LocalSystem') { exit 1 }")
                assert len(list((state / "native").glob("*.service.json"))) == 1, "Reinstall duplicated enrollment"
                print("PASS actual installer, SCM and authenticated control:", shell, flush=True)
        expected = subprocess.check_output([str(source), "--version"], text=True).strip()
        assert subprocess.check_output([str(cli), "--version"], text=True).strip() == expected
        assert all(v == expected.removeprefix("porthub ") for v in syncs), "Wrong installed version"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry) as key:
            machine_path, _ = winreg.QueryValueEx(key, "Path")
        assert sum(p.rstrip("\\").lower() == str(cli.parent).lower() for p in machine_path.split(";")) == 1
        env = os.environ.copy()
        env["Path"] = os.path.expandvars(machine_path) + ";" + env["Path"]
        run(["cmd.exe", "/d", "/c", "porthub --version"], env=env)
        run([str(cli), "stop", identity[:12]])
        ps("if ((Get-Service '" + service + "').Status -ne 'Stopped') { exit 1 }")
        before = len(syncs)
        run([str(cli), "start", identity[:12]])
        wait_for(lambda: len(syncs) > before, "service start control sync")
        before = len(syncs)
        run([str(cli), "restart", identity[:12]])
        wait_for(lambda: len(syncs) > before, "service restart control sync")
        run([str(cli), "remove", identity[:12]])
        ps("if (Get-Service '" + service + "' -ErrorAction SilentlyContinue) { exit 1 }")
        assert not errors and len(downloads) == 4
        print("PASS published CLI version, persistent PATH, stop/start/restart/remove", flush=True)
    finally:
        # Only the exact fixture service is eligible for emergency cleanup.
        if service:
            subprocess.run(["sc.exe", "stop", service], capture_output=True, timeout=30)
            subprocess.run(["sc.exe", "delete", service], capture_output=True, timeout=30)
        if server:
            server.shutdown()
            server.server_close()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Path", 0, path_type, old_path)
        for path in (state, display, published):
            for attempt in range(20):
                try:
                    if path.exists():
                        shutil.rmtree(path)
                    break
                except PermissionError:
                    if attempt == 19:
                        raise
                    time.sleep(.5)


if __name__ == "__main__":
    main()
