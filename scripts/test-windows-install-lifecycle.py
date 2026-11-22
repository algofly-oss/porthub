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
import socket
import uuid
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def run(args, **kwargs):
    # Encoded PowerShell progress becomes large CLIXML records when CI redirects
    # its output. Keep useful installer output and bound failure diagnostics.
    result = subprocess.run(args, timeout=90, capture_output=True, **kwargs)
    sys.stdout.write(result.stdout.decode(errors='replace')[-4000:])
    if result.returncode:
        sys.stderr.write(result.stderr.decode(errors='replace')[-4000:])
    result.check_returncode()
    return result


def ps(script, **kwargs):
    script = "$ProgressPreference='SilentlyContinue';\n" + script
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return run(["powershell.exe", "-NoProfile", "-EncodedCommand", encoded], **kwargs)


def wait_for(predicate, description):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.25)
    raise AssertionError("Timed out: " + description)



def assert_console_state(pid, attached=False):
    # The short-lived probe detaches its own console before inspection.
    # Attaching and detaching it sends no input and leaves other attachments intact.
    probe = r"""
import ctypes,sys,time
from ctypes import wintypes
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.AttachConsole.argtypes=[wintypes.DWORD];kernel.AttachConsole.restype=wintypes.BOOL
kernel.FreeConsole.restype=wintypes.BOOL
kernel.GetConsoleProcessList.argtypes=[ctypes.POINTER(wintypes.DWORD),wintypes.DWORD]
buffer=(wintypes.DWORD*2)()
# Console attachment differs across runner hosts even with CREATE_NO_WINDOW.
# Detach only this disposable probe; the parent and helper are unaffected.
kernel.FreeConsole()
assert kernel.GetConsoleProcessList(buffer,2)==0,'Probe could not detach its own console'
expected=sys.argv[2]=='attached'
for attempt in range(50):
    if kernel.AttachConsole(int(sys.argv[1])):
        kernel.FreeConsole()
        if expected:break
        time.sleep(.1)
        continue
    error=ctypes.get_last_error()
    assert error==6,'Cannot verify target console state: '+str(error)
    if not expected:break
    time.sleep(.1)
else:
    raise AssertionError('Native console attachment did not match '+sys.argv[2])
"""
    run([sys.executable, "-c", probe, str(pid), "attached" if attached else "detached"], creationflags=subprocess.CREATE_NO_WINDOW)


def assert_helper_has_no_console(pid):
    assert_console_state(pid)


def verify_mapping_console_scope(executable):
    # Isolated local state only: no recovery task, enrollment, USB, or network
    # destination connection. A fresh console makes a missing detach observable.
    with tempfile.TemporaryDirectory(prefix="porthub console scope ") as fixture:
        for hidden in (True, False):
            root = Path(fixture) / ("hidden" if hidden else "foreground")
            mappings = root / "mappings"
            mappings.mkdir(parents=True)
            env = os.environ.copy()
            env["PORTHUB_STATE_DIR"] = str(root)
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                port = reserved.getsockname()[1]
            if hidden:
                identity = uuid.uuid4().hex
                (mappings / (identity + ".json")).write_text(json.dumps({
                    "id": identity, "recover": False,
                    "spec": {"kind": "forward", "target": "127.0.0.1:9", "bind": "127.0.0.1", "port": port},
                }))
                args = [str(executable), "mapping-worker", identity]
            else:
                args = [str(executable), "forward", "127.0.0.1:9", "--bind", "localhost", "--local-port", str(port)]
            process = subprocess.Popen(args, env=env, creationflags=subprocess.CREATE_NEW_CONSOLE,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                def ready():
                    if process.poll() is not None:
                        raise AssertionError("Isolated mapping exited before binding")
                    for path in mappings.glob("*.status"):
                        try:
                            if json.loads(path.read_text())["state"] == "running":
                                return True
                        except (OSError, ValueError, KeyError):
                            pass  # Atomic status publication can race a reader.
                    return False
                wait_for(ready, "isolated mapping listener")
                assert_console_state(process.pid, attached=not hidden)
            finally:
                # Remove only this fixture's desired state and let its worker
                # close normally; terminate only its own PID if it fails to exit.
                for path in mappings.glob("*.json"):
                    path.unlink()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
    print("PASS hidden mapping worker detaches and foreground forward retains its console", flush=True)


def wait_keyboard_image(executable):
    expected = str(executable).replace("'", "''")
    result = ps(r"""$ErrorActionPreference='Stop'
$expected='""" + expected + r"""'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name='PortHubKeyboard-'+$sid
for($attempt=0;$attempt -lt 100;$attempt++){
    $task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    $process=@(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'" | Where-Object {
        $_.ExecutablePath -eq $expected -and $_.SessionId -ne 0 -and $_.CommandLine -match '(?i)\skeyboard\s+startup\s*$'
    })
    if($task -and $task.Actions[0].Execute -eq $expected -and $task.Actions[0].Arguments -eq 'keyboard startup' -and $task.State -eq 'Running' -and $process.Count){$process[0].ProcessId;exit 0}
    Start-Sleep -Milliseconds 250
}
$task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if($task){
    $info=Get-ScheduledTaskInfo -InputObject $task
    [pscustomobject]@{Task=$name;State=$task.State.ToString();LastResult=('0x{0:X8}' -f $info.LastTaskResult);LastRun=$info.LastRunTime;Principal=$task.Principal.UserId;LogonType=$task.Principal.LogonType.ToString();RunLevel=$task.Principal.RunLevel.ToString();Execute=$task.Actions.Execute;Arguments=$task.Actions.Arguments;Expected=$expected}|ConvertTo-Json -Compress
}
Get-CimInstance Win32_Process -Filter "Name='porthub.exe'" | Select-Object ProcessId,ParentProcessId,ExecutablePath,SessionId | Format-List
throw 'Persistent desktop helper did not advance to its published immutable image'
""")
    pid = int(result.stdout.decode().strip())
    assert_helper_has_no_console(pid)
    return pid


def cleanup_desktop(state):
    # The disposable fixture proved that these roots did not exist at entry.
    # Never stop a task or process solely because its executable is named PortHub.
    root = str(state / "releases").replace("'", "''")
    ps(r"""$ErrorActionPreference='Stop'
$root='""" + root + r"""'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name='PortHubKeyboard-'+$sid
function OwnedRelease($path) {
    if(-not $path){return $false}
    $item=Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if(-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){return $false}
    if($item.Name -ne 'porthub.exe' -or $item.Directory.Name -notmatch '^[a-fA-F0-9]{64}$'){return $false}
    if($item.Directory.Parent.FullName -ne $root){return $false}
    return (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -eq $item.Directory.Name
}
$task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if($task){
    if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Arguments -notin @('keyboard run','keyboard startup') -or -not (OwnedRelease $task.Actions[0].Execute)){
        throw 'Refusing to remove a desktop task outside the fixture immutable releases'
    }
    Stop-ScheduledTask -TaskName $name
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
}
# A previously replaced task may still have its earlier immutable helper alive.
foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'")){
    if((OwnedRelease $p.ExecutablePath) -and $p.CommandLine -match '(?i)\skeyboard\s+(?:run|startup)(?:\s|$)'){
        $live=Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        if($live -and $live.Path -eq $p.ExecutablePath){Stop-Process -InputObject $live -Force -ErrorAction SilentlyContinue}
    }
}
if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Fixture keyboard task survived cleanup'}
$remaining=@(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'" | Where-Object {
    (OwnedRelease $_.ExecutablePath) -and $_.CommandLine -match '(?i)\skeyboard\s+(?:run|startup)(?:\s|$)'
})
if($remaining.Count){$remaining | Select-Object ProcessId,ExecutablePath,SessionId | Format-List;throw 'Fixture desktop helper survived cleanup'}
""")


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
    ps("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
       "if(Get-ScheduledTask -TaskName ('PortHubKeyboard-'+$sid) -ErrorAction SilentlyContinue){throw 'Existing desktop task'}")
    firewall_fixture = str(repo / "scripts/test-windows-usb-firewall.ps1").replace("'", "''")
    firewall_rule = str(repo / "crates/porthub-agent/src/usb/windows_usb_direct_rule.ps1").replace("'", "''")
    firewall_executable = str(source).replace("'", "''")
    ps("& ([ScriptBlock]::Create([IO.File]::ReadAllText('" + firewall_fixture + "'))) "
       "-RuleScript ([IO.File]::ReadAllText('" + firewall_rule + "')) -Executable '" + firewall_executable + "'")
    registry = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry) as key:
        old_path, path_type = winreg.QueryValueEx(key, "Path")
    machine = os.urandom(12).hex()
    token = "disposable-fixture-only"
    syncs = []
    sync_times = []
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
                    sync_times.append(time.time())
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
                env["PATH"] = os.environ["PATH"]
                if shell == "cmd.exe":
                    # Pass the clipboard text verbatim: Python's list2cmdline
                    # uses C argv escaping, which is not cmd.exe quote syntax.
                    run("cmd.exe /d /s /c " + line, env=env)
                elif shell == "batch":
                    batch = Path(temporary) / "porthub install.bat"
                    template = (repo / "crates/porthub-api/assets/client/install.bat").read_bytes()
                    payload = base64.b64encode(line.encode("utf-16le"))
                    batch.write_bytes(template.replace(b"{{PAYLOAD}}", payload))
                    run('cmd.exe /d /s /c ""' + str(batch) + '""', env=env)
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
        verify_mapping_console_scope(cli)
        assert all(v == expected.removeprefix("porthub ") for v in syncs), "Wrong installed version"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry) as key:
            machine_path, _ = winreg.QueryValueEx(key, "Path")
        assert sum(p.rstrip("\\").lower() == str(cli.parent).lower() for p in machine_path.split(";")) == 1
        env = os.environ.copy()
        # os.environ is case-insensitive on Windows, but its copied dict is not;
        # Python normalizes its keys to uppercase (PATH rather than Path).
        env["PATH"] = os.path.expandvars(machine_path) + ";" + env["PATH"]
        run(["cmd.exe", "/d", "/c", "porthub --version"], env=env)
        run([str(cli), "stop", identity[:12]])
        # The first SCM recovery action is delayed five seconds. A clean stop
        # must remain stopped past that deadline, even with recovery enabled.
        ps("$until=[DateTime]::UtcNow.AddSeconds(7); do { "
           "if ((Get-Service '" + service + "').Status -ne 'Stopped') { exit 1 }; "
           "Start-Sleep -Milliseconds 250 } while ([DateTime]::UtcNow -lt $until)")
        before = len(syncs)
        run([str(cli), "start", identity[:12]])
        wait_for(lambda: len(syncs) > before, "service start control sync")
        before = len(syncs)
        run([str(cli), "restart", identity[:12]])
        wait_for(lambda: len(syncs) > before, "service restart control sync")
        # A different immutable image must replace a verified owned SCM entry.
        # A PE overlay changes the content hash without changing executable behavior.
        manifest_path = state / "native" / (identity + ".service.json")
        previous_spec = json.loads(manifest_path.read_text())
        wait_keyboard_image(previous_spec["executable"])
        with tempfile.TemporaryDirectory(prefix="porthub update candidate ") as update:
            replacement = Path(update) / "porthub.exe"
            replacement.write_bytes(source.read_bytes() + b"porthub-owned-update-fixture-v1")
            before = len(syncs)
            run([str(replacement), "service", "install", "--profile", previous_spec["profile"], "--publish-cli"])
            wait_for(lambda: len(syncs) > before, "replacement image authenticated control")
            next_spec = json.loads(manifest_path.read_text())
            assert next_spec["executable"] != previous_spec["executable"], "SCM update retained old image"
            assert hashlib.sha256(Path(next_spec["executable"]).read_bytes()).digest() == hashlib.sha256(replacement.read_bytes()).digest()
            assert next_spec["cli"] == previous_spec["cli"], "SCM update lost shared CLI publication"
            assert hashlib.sha256(cli.read_bytes()).digest() == hashlib.sha256(replacement.read_bytes()).digest(), "Published CLI retained old release"
            updated_helper = wait_keyboard_image(next_spec["executable"])
            ps("$s = Get-CimInstance Win32_Service -Filter \"Name='" + service + "'\"; "
               "if ($s.State -ne 'Running' -or -not $s.PathName.Contains('" + next_spec["executable"] + "')) { exit 1 }")
            # Idempotent reinstallation must retain this registration and credentials.
            run([str(replacement), "service", "install", "--profile", previous_spec["profile"], "--publish-cli"])
            assert json.loads(manifest_path.read_text())["identity"] == previous_spec["identity"]
            assert wait_keyboard_image(next_spec["executable"]) == updated_helper, "Idempotent setup restarted a healthy desktop helper"
        # Confirm that the installed policy actually relaunches the enrolled
        # service and reconnects it to this fixture's authenticated controller.
        # Hold the exact process handle to avoid a PID reuse race with teardown.
        recovery = ps(r"""$ErrorActionPreference='Stop'
$name='""" + service + """'
$expected='""" + next_spec["executable"].replace("'", "''") + r"""'
$svc=Get-CimInstance Win32_Service -Filter "Name='$name'"
if ($svc.State -ne 'Running' -or $svc.ProcessId -le 0) {throw 'Fixture service is not running'}
$child=Get-Process -Id $svc.ProcessId
$handle=$child.Handle
if ($child.SessionId -ne 0 -or $child.Path -ne $expected) {throw 'Unexpected fixture service image'}
$child.Kill()
if (-not $child.WaitForExit(5000)) {throw 'Fixture process did not exit'}
$deadline=[DateTime]::UtcNow.AddSeconds(45)
do {
    $svc=Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($svc.State -eq 'Running' -and $svc.ProcessId -gt 0 -and $svc.ProcessId -ne $child.Id) {
        $replacement=Get-Process -Id $svc.ProcessId
        if ($replacement.Path -ne $expected) {throw 'Recovered service image changed'}
        ([DateTimeOffset]$replacement.StartTime).ToUnixTimeMilliseconds()
        exit 0
    }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
throw 'SCM did not recover the fixture service'
""")
        started_at = int(recovery.stdout.decode().strip()) / 1000
        wait_for(lambda: any(at >= started_at for at in sync_times),
                 "authenticated control sync after SCM crash recovery")
        print("PASS verified owned SCM image replacement and idempotency", flush=True)
        run([str(cli), "remove", identity[:12]])
        ps("if (Get-Service '" + service + "' -ErrorAction SilentlyContinue) { exit 1 }")
        assert not errors and len(downloads) == 4
        print("PASS published CLI version, persistent PATH, stop/start/restart/remove", flush=True)
    finally:
        # Only the exact fixture service is eligible for emergency cleanup.
        if service:
            subprocess.run(["sc.exe", "stop", service], capture_output=True, timeout=30)
            subprocess.run(["sc.exe", "delete", service], capture_output=True, timeout=30)
        cleanup_desktop(state)
        print("PASS fixture-owned desktop task and helper cleanup", flush=True)
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
                        ps("Get-CimInstance Win32_Process -Filter \"Name='porthub.exe'\" | Select-Object ProcessId,ExecutablePath,SessionId | Format-List")
                        raise
                    time.sleep(.5)


if __name__ == "__main__":
    main()
