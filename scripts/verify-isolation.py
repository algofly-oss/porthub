#!/usr/bin/env python3
"""Exercise built production images without touching host ports or firewall.

Renders the root Compose file, gives every resource a fresh test-only name,
and places edge/firewall in one disposable bridge namespace. Always removes
only that project's resources. Requires Docker Compose and built porthub:core/edge/firewall images.
"""
import gzip
import hashlib
import json
import os
import pathlib
import platform
import secrets
import shutil
import socket
import ssl
import sys
import subprocess
import time
import tempfile
import urllib.request
import urllib.parse
import urllib.error


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    prefix = "porthub-verify-" + secrets.token_hex(5)
    password, key = secrets.token_hex(24), secrets.token_hex(32)
    bind_root = pathlib.Path(tempfile.mkdtemp(prefix=prefix + "-binds-"))
    environment = {**os.environ, "PORTHUB_MODE": "prod", "PORTHUB_CORE_READ_ONLY": "true"}
    config = json.loads(subprocess.check_output(
        ["docker", "compose", "config", "--format", "json"], cwd=ROOT, env=environment))
    config["name"] = prefix
    for name, volume in config.get("volumes", {}).items():
        volume["name"] = prefix + "-" + name
        assert not volume.get("external")
    for name, network in config.get("networks", {}).items():
        network["name"] = prefix + "-" + name
        assert not network.get("external")
    bind_sources = {}
    for role, service in config["services"].items():
        service["container_name"] = prefix + "-" + role
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind":
                source = mount["source"]
                isolated_source = bind_root / hashlib.sha256(source.encode()).hexdigest()
                isolated_source.mkdir(parents=True, exist_ok=True)
                mount["source"] = str(isolated_source)
                bind_sources[mount["target"]] = isolated_source
        for field in ("env_file", "restart", "develop", "build"):
            service.pop(field, None)
        service["healthcheck"].update(interval="1s", start_period="20s", retries=30)
        service["read_only"] = True
        if role == "core":
            service["environment"] = {
                "PORTHUB_MODE": "prod", "MONGO_INITDB_ROOT_USERNAME": "isolation-check",
                "MONGO_INITDB_ROOT_PASSWORD": password,
                "MONGO_DATABASE_URI": f"mongodb://isolation-check:{password}@127.0.0.1:47017/isolation?authSource=admin",
                "MONGO_DATABASE_NAME": "isolation", "PORTHUB_DB_INITIALIZE": "true",
                "PORTHUB_API_SOCKET": "/run/porthub-api/api.sock",
                "PORTHUB_EDGE_SOCKET": "/run/porthub-edge/control.sock",
                "PORTHUB_GATEWAY_CONFIG_PATH": "/run/porthub-config/gateway.toml",
                "PORTHUB_WEB_ROUTES_CONFIG_PATH": "/run/porthub-config/web-routes.json",
                "PORTHUB_WEB_ACTIVITY_LOG_PATH": "/run/porthub-activity/web-activity.log",
                "FIREWALL_SOCKET": "/run/porthub-firewall/api.sock",
                "FW_API_KEY": key, "PORTHUB_GATEWAY_PUBLIC_IP": "93.184.216.34",
                "MACHINE_ONLINE_TTL_SECONDS": "8",
                "MACHINE_OFFLINE_ALERT_GRACE_SECONDS": "2",
            }
        elif role == "edge":
            # This fixture places the firewall in edge's disposable namespace.
            # Start its empty edge before firewall/core; production firewall
            # uses the host namespace and has no such dependency.
            service.pop("depends_on", None)
            service.pop("network_mode", None)
            service["networks"] = {"default": None}
            service["environment"] = {
                "PORTHUB_API_SOCKET": "/run/porthub-api/api.sock",
                "PORTHUB_EDGE_SOCKET": "/run/porthub-edge/control.sock",
                "PORTHUB_WEB_ROUTES_CONFIG_PATH": "/run/porthub-config/web-routes.json",
                "PORTHUB_WEB_ACTIVITY_LOG_PATH": "/run/porthub-activity/web-activity.log",
                "PORTHUB_EDGE_HTTP_LISTEN": "0.0.0.0:8345",
                "PORTHUB_EDGE_TLS_LISTEN": "0.0.0.0:8346",
                "PORTHUB_TLS_CERT": "/data/certificates/origin.crt",
                "PORTHUB_TLS_KEY": "/data/certificates/origin.key",
                "PORTHUB_ALLOW_SELF_SIGNED": "true",
                "PORT_HUB_PUBLIC_BASE_URL": "https://localhost",
            }
            service["ports"] = [dict(target=port, published="0", host_ip="127.0.0.1", protocol="tcp")
                                for port in (8345, 8346, 49123)]
        elif role == "firewall":
            service["network_mode"] = "service:edge"
            service["environment"] = {"FW_API_KEY": key}
        else:
            raise AssertionError("unexpected Compose role")
    assert set(config["services"]) == {"core", "edge", "firewall"}
    rendered = json.dumps(config)
    base = ["docker", "compose", "--project-name", prefix, "--file", "-"]

    def compose(*args):
        result = subprocess.run([*base, *args], input=rendered, capture_output=True, text=True, cwd=ROOT)
        if result.returncode:
            raise RuntimeError(result.stderr.replace(password, "[redacted]").replace(key, "[redacted]"))
        return result.stdout

    def docker(*args, check=True):
        return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)

    def prepare_bind_roots():
        # Match deploy.sh's owner/group permissions. Named volumes used to
        # receive these permissions from image initialization.
        bind_permissions = {
            "/data": ("10001:10001", "0750"),
            "/run/porthub-api": ("10001:10001", "0770"),
            "/run/porthub-edge": ("0:10001", "0770"),
            "/run/porthub-firewall": ("0:10001", "0770"),
            "/run/porthub-config": ("10001:10001", "0750"),
            "/run/porthub-activity": ("0:10001", "0770"),
            "/data/certificates": ("0:10001", "0770"),
            "/data/firewall": ("0:10001", "0770"),
        }
        commands = []
        for target, source in bind_sources.items():
            owner, mode = bind_permissions[target]
            path = "/porthub-test-binds/" + str(source.relative_to(bind_root))
            commands.extend((f"chown {owner} {path}", f"chmod {mode} {path}"))
        data_path = "/porthub-test-binds/" + str(bind_sources["/data"].relative_to(bind_root))
        config_path = "/porthub-test-binds/" + str(bind_sources["/run/porthub-config"].relative_to(bind_root))
        commands.extend((f"mkdir -p {data_path}/mongo", f"chown 10001:10001 {data_path}/mongo",
                         f"chmod 0750 {data_path}/mongo", f"printf '[server.services]\\n' > {config_path}/gateway.toml",
                         f"chown 10001:10001 {config_path}/gateway.toml"))
        subprocess.run(
            ["docker", "run", "--rm", "--user", "0:0", "--mount",
             f"type=bind,src={bind_root},dst=/porthub-test-binds", "--entrypoint", "/bin/sh",
             "porthub:core", "-c", " && ".join(commands)],
            check=True, capture_output=True, text=True)

    def inspect(role):
        return json.loads(docker("inspect", prefix + "-" + role).stdout)[0]

    def address(tls=False):
        ports = inspect("edge")["NetworkSettings"]["Ports"]
        port = ports[f'{8346 if tls else 8345}/tcp'][0]["HostPort"]
        return f'{"https" if tls else "http"}://127.0.0.1:{port}'

    def request(path, tls=False, data=None, headers=None, method=None):
        req = urllib.request.Request(address(tls) + path, data=data, headers=headers or {}, method=method)
        # Only the generated test certificate is accepted here; no production TLS config changes.
        with urllib.request.urlopen(req, context=ssl._create_unverified_context() if tls else None,
                                    timeout=20) as response:
            return response.status, response.headers, response.read()

    checks = []
    children = []
    client_image = prefix + "-ui-check"
    client_image_id = None
    client_container = prefix + "-realtime"
    try:
        prepare_bind_roots()
        # Reuse the locked UI builder dependencies without installing Node or
        # node_modules on the deployment host or in any production image.
        built = subprocess.run(["docker", "build", "--target", "ui-build", "--tag", client_image, "."],
                               cwd=ROOT, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError("could not prepare the isolated UI verification image: " + built.stderr)
        client_image_id = docker("image", "inspect", client_image, "--format", "{{.Id}}").stdout.strip()
        # Compose creates every container before startup, exercising shared-volume ownership.
        compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "150")
        for tls in (False, True):
            assert request("/api/auth/settings", tls)[0] == 200
        checks.append("HTTP/HTTPS ingress reaches Unix API after simultaneous Compose creation")
        status, headers, content = request("/home", headers={"Accept-Encoding": "gzip"})
        assert status == 200 and headers["Content-Encoding"] == "gzip"
        assert b"__NEXT_DATA__" in gzip.decompress(content)
        assert docker("exec", prefix + "-core", "node", "--version", check=False).returncode != 0
        checks.append("production UI is exported/precompressed and served without Node")
        result = docker("exec", prefix + "-core", "porthub-runtime", "check", "--socket",
                        "/run/porthub-firewall/api.sock", "--path", "/api/ping", "--api-key-env", "FW_API_KEY")
        assert result.returncode == 0
        assert docker("exec", prefix + "-core", "porthub-runtime", "check", "--socket",
                      "/run/porthub-firewall/api.sock", "--path", "/api/ping", check=False).returncode != 0
        assert docker("exec", prefix + "-edge", "test", "-S", "/run/porthub-firewall/api.sock",
                      check=False).returncode != 0
        checks.append("firewall IPC requires credentials and is unavailable to edge")
        def mount(role, target):
            return next(item for item in inspect(role)["Mounts"] if item["Destination"] == target)
        assert not mount("core", "/run/porthub-edge")["RW"]
        assert mount("edge", "/run/porthub-edge")["RW"]
        assert all(item["Destination"] != "/run/porthub-edge" for item in inspect("firewall")["Mounts"])
        checks.append("edge apply socket is writable only by edge, core connects through a read-only mount, and firewall has no mount")
        core = inspect("core")
        core_ip = next(iter(core["NetworkSettings"]["Networks"].values()))["IPAddress"]
        edge_ip = next(iter(inspect("edge")["NetworkSettings"]["Networks"].values()))["IPAddress"]
        for ip, ports in ((core_ip, (47017, 47030, 47080)), (edge_ip, (47001, 2334))):
            for port in ports:
                with socket.socket() as client:
                    client.settimeout(.3)
                    assert client.connect_ex((ip, port)) != 0, f"unexpected internal listener {port}"
        checks.append("database/API/UI/firewall TCP ports and standalone tunnel control port are inaccessible")
        for role, caps in (("core", []), ("edge", ["NET_BIND_SERVICE"]), ("firewall", ["NET_ADMIN"])):
            host = inspect(role)["HostConfig"]
            assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
            actual_caps = [cap.removeprefix("CAP_") for cap in (host["CapAdd"] or [])]
            assert actual_caps == caps, (role, actual_caps)
            assert "no-new-privileges:true" in host["SecurityOpt"]
        checks.append("all production roots read-only with separate minimum capabilities")
        signup = json.dumps(dict(name="Isolation Check", username="check@example.invalid",
                                 password="Isolated-Password1!Sample")).encode()
        status, headers, _ = request("/api/auth/signup", tls=True, data=signup,
                                      headers={"Content-Type": "application/json"})
        assert status in (200, 201)
        cookie = headers["Set-Cookie"]
        assert cookie and "Secure" in cookie
        cookie = cookie.split(";", 1)[0]
        identity = request("/api/auth/me", headers={"Cookie": cookie})[2]
        created = json.loads(request("/api/machines/add", data=json.dumps({"name": "Isolated fixture"}).encode(),
                                     headers={"Cookie": cookie, "Content-Type": "application/json"})[2])
        machine_id = created["data"]["_id"]
        origin_request = json.dumps({"machine_id": machine_id, "token": created["data"]["token"]}).encode()
        origin = json.loads(request("/api/gateway/origin", data=origin_request,
            headers={"Content-Type": "application/json"})[2])["data"]
        assert origin["tls_port"] == 8346 and len(origin["spki_sha256"]) == 64
        assert all(character in "0123456789abcdef" for character in origin["spki_sha256"])
        checks.append("authenticated origin discovery receives the gateway TLS key pin through the read-only role mount")
        private_before = request("/api/machines/private-addresses/" + machine_id, headers={"Cookie": cookie})[2]
        assert len(json.loads(private_before)["data"]) == 1
        checks.append("native machine creation assigns a private address and publishes gateway config")
        def ui_client(agent_logs=False):
            with tempfile.TemporaryDirectory(prefix=prefix + "-client-") as directory:
                environment_file = pathlib.Path(directory) / "environment"
                values = {"PORTHUB_TEST_SOCKET_URL": address(tls=True),
                          "PORTHUB_TEST_MACHINE_ID": machine_id,
                          "PORTHUB_TEST_MACHINE_TOKEN": created["data"]["token"],
                          "PORTHUB_TEST_SESSION_COOKIE": cookie,
                          "PORTHUB_TEST_SELF_SIGNED": "1",
                          "PORTHUB_TEST_EXPECT_AGENT_LOG": "1" if agent_logs else "0"}
                with environment_file.open("x") as output:
                    os.chmod(environment_file, 0o600)
                    output.write("".join(name + "=" + value + "\n" for name, value in values.items()))
                result = subprocess.run(
                    ["docker", "run", "--rm", "--name", client_container,
                     "--label", "porthub.verification=" + prefix, "--network", "host",
                     "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges:true",
                     "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--env", "HOME=/tmp",
                     "--env-file", str(environment_file), "--mount",
                     f"type=bind,src={ROOT / 'ui/tests/native-realtime.cjs'},dst=/src/ui/tests/native-realtime.cjs,readonly",
                     client_image, "node", "/src/ui/tests/native-realtime.cjs"],
                    capture_output=True, text=True, timeout=25 if agent_logs else 20)
            if result.returncode:
                detail = result.stderr.replace(cookie, "[redacted]").replace(created["data"]["token"], "[redacted]")
                raise AssertionError("official Socket.IO client failed through TLS edge ingress: " + detail)
            return result.stdout
        assert "Native Socket.IO status and log streaming passed." in ui_client()
        checks.append("official UI Socket.IO client authenticates and streams scoped status/log events through HTTPS edge and Unix API")
        request("/api/machines/sync", data=json.dumps({
            "machine_id": machine_id, "token": created["data"]["token"]}).encode(),
            headers={"Content-Type": "application/json"})
        def machine_history():
            return json.loads(request(f"/api/machines/{machine_id}/status-history",
                                     headers={"Cookie": cookie})[2])["data"]
        for _ in range(100):
            history = machine_history()
            if history and history[-1]["status"] == "online":
                break
            time.sleep(.1)
        assert history and history[-1]["status"] == "online", "worker did not persist online presence"
        for _ in range(150):
            history = machine_history()
            if history[-1]["status"] == "offline":
                break
            time.sleep(.1)
        assert history[-1]["status"] == "offline", "idle machine did not expire without a heartbeat"
        checks.append("native status worker persists online history and detects idle expiry without a client request")
        route = json.loads(request("/api/traffic-routes/add", data=json.dumps({
            "name": "Activity check", "hosts": ["activity-check.invalid"],
            "targetUrl": "http://localhost:8345"}).encode(),
            headers={"Cookie": cookie, "Content-Type": "application/json"})[2])
        route_id = route["data"]["_id"]
        def activity_count():
            body = json.loads(request("/api/traffic-routes/activity", headers={"Cookie": cookie})[2])
            rows = [item for item in body["data"] if item["route_id"] == route_id]
            return rows[0]["requests"] if rows else 0
        # Wait for atomic routing-file notification before issuing counted requests.
        for _ in range(100):
            if docker("exec", prefix + "-edge", "cat", "/run/porthub-config/web-routes.json").stdout.find(route_id) >= 0:
                break
            time.sleep(.1)
        time.sleep(.2)
        for _ in range(3):
            assert request("/healthz", headers={"Host": "activity-check.invalid"})[0] == 200
        for _ in range(150):
            if activity_count() == 3:
                break
            time.sleep(.1)
        assert activity_count() == 3
        core_mounts = {item["Destination"]: item["RW"] for item in inspect("core")["Mounts"]}
        edge_mounts = {item["Destination"]: item["RW"] for item in inspect("edge")["Mounts"]}
        assert core_mounts["/run/porthub-activity"] is False
        assert edge_mounts["/run/porthub-activity"] is True
        journal = docker("exec", prefix + "-edge", "cat", "/run/porthub-activity/web-activity.log").stdout
        assert "activity-check.invalid" in journal and "/healthz" not in journal
        checks.append("native edge counts reach activity API through a read-only core journal mount")
        # Exercise the native API -> generated config -> embedded Rathole path,
        # native file server/download, and actual private policy in this namespace.
        def api(method, path, body):
            return json.loads(request(path, data=json.dumps(body).encode(), method=method,
                headers={"Cookie": cookie, "Content-Type": "application/json"})[2])
        private_snapshot = json.loads(request("/api/access/snapshot", headers={"Cookie": cookie})[2])
        assert private_snapshot["transport_ready"] is False
        migration_body = None
        for suffix in ("downloads/porthub", "client.sh"):
            status, headers, content = request(f"/api/machines/{machine_id}/{created['data']['token']}/{suffix}")
            assert status == 200 and headers["Cache-Control"] == "no-store"
            assert content.startswith(b"#!/usr/bin/env bash\n")
            assert b"porthub_native_migration_cmd()" in content and b"__PORT_HUB_" not in content
            assert created["data"]["token"].encode() not in content and machine_id.encode() not in content
            assert migration_body is None or migration_body == content
            migration_body = content
        checks.append("packaged native API serves credential-free authenticated legacy migration bridges on both old update URLs")
        assert any(peer["machine_id"] == machine_id for peer in private_snapshot["private_peers"])
        assert created["data"]["token"] not in json.dumps(private_snapshot)
        public_peer = next(peer for peer in private_snapshot["private_peers"] if peer["machine_id"] == machine_id)
        try:
            api("POST", "/api/access/private/sync", {"peer_id": public_peer["_id"],
                "token": created["data"]["token"], "fingerprint": ":".join(["AB"] * 32),
                "instance": "isolation-sync-instance"})
        except urllib.error.HTTPError as error:
            assert error.code == 403
        else:
            raise AssertionError("public machine credential authenticated private signaling")
        checks.append("native private signaling ingress rejects public machine credentials")
        network_settings = private_snapshot["network"]
        assert api("PUT", "/api/access/network", network_settings)["data"] == network_settings
        managed_private = api("POST", "/api/machines/add", {"name": "Private controls fixture"})["data"]
        private_snapshot = json.loads(request("/api/access/snapshot", headers={"Cookie": cookie})[2])
        managed_peer = next(peer for peer in private_snapshot["private_peers"] if peer["machine_id"] == managed_private["_id"])
        managed_path = "/api/access/private/peers/" + urllib.parse.quote(managed_peer["_id"], safe="")
        assert api("PUT", managed_path, {"enabled": False})["msg"] == "Private access disabled"
        assert api("PUT", managed_path, {"enabled": True})["msg"] == "Private access enabled"
        assert api("DELETE", managed_path, None)["msg"] == "Private credential revoked; public access is unchanged"
        private_snapshot = json.loads(request("/api/access/snapshot", headers={"Cookie": cookie})[2])
        revoked_peer = next(peer for peer in private_snapshot["private_peers"] if peer["_id"] == managed_peer["_id"])
        assert revoked_peer["enabled"] is False and revoked_peer["installed"] is False
        assert revoked_peer["ip"] == managed_peer["ip"]
        checks.append("native private-access inventory, network settings and scoped peer controls preserve assigned addresses without exposing machine credentials")
        policy_group = api("POST", "/api/groups/add", {"name": "Native policy fixture"})["data"]["_id"]
        policy_preview = {"source_id": machine_id, "destination_id": managed_private["_id"], "port": 22}
        assert api("POST", "/api/access/test", policy_preview)["data"]["allowed"] is False
        policy_book = {"name": "Native SSH", "group_id": policy_group, "rules": [{
            "id": "ssh", "name": "Allow fixture SSH", "sources": [{"kind": "machine", "id": machine_id}],
            "destinations": [{"kind": "machine", "id": managed_private["_id"]}], "ports": "22,22"}]}
        created_book = api("POST", "/api/access/books", policy_book)["data"]
        assert created_book["revision"] == 1 and created_book["rules"][0]["ports"] == "22"
        book_snapshot = json.loads(request("/api/access/snapshot", headers={"Cookie": cookie})[2])
        assert next(book for book in book_snapshot["books"] if book["_id"] == created_book["_id"])["created_by"] == created_book["created_by"]
        assert api("POST", "/api/access/test", policy_preview)["data"]["allowed"] is True
        book_path = "/api/access/books/" + created_book["_id"]
        policy_book["revision"] = 1
        policy_book["rules"][0]["bidirectional"] = True
        assert api("PUT", book_path, policy_book)["data"]["revision"] == 2
        try:
            api("PUT", book_path, policy_book)
        except urllib.error.HTTPError as error:
            assert error.code == 409
        else:
            raise AssertionError("stale rule-book revision was accepted")
        assert api("DELETE", book_path, {"revision": 2})["msg"] == "Rule book deleted"
        assert api("POST", "/api/access/test", policy_preview)["data"]["allowed"] is False
        checks.append("native rule-book validation, revision conflict detection and deletion drive allow-only policy previews through production ingress")
        agent_name = "porthub-" + {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x86_64", "AMD64": "x86_64"}[platform.machine()]
        def run_agent(*args):
            return docker("exec", "-e", "PORTHUB_STATE_DIR=/tmp/porthub-state", prefix + "-core", agent, *args)
        def start_core(*args):
            child = subprocess.Popen(["docker", "exec", "-e", "PORTHUB_STATE_DIR=/tmp/porthub-state", prefix + "-core", *args],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(child)
            return child
        releases = json.loads(request(f"/api/machines/{machine_id}/{created['data']['token']}/downloads/releases")[2])
        release = next(item for item in releases["releases"] if item["asset"] == agent_name)
        agent = "/data/agent-releases/" + release["version"] + "/" + agent_name
        assert releases["format_version"] == 1 and release["size"] > 0
        release_path = f"/api/machines/{machine_id}/{created['data']['token']}/downloads/agent/{release['target']}"
        status, headers, content = request(release_path, headers={"Range": "bytes=0-4095"})
        assert status == 206 and len(content) == 4096 and headers["X-PortHub-Agent-Sha256"] == release["sha256"]
        # The API fetched this target lazily into the test-only writable data
        # mount. Mark that cached fixture executable for the lifecycle checks.
        docker("exec", prefix + "-core", "chmod", "0700", agent)
        docker("exec", prefix + "-core", "sh", "-c", "test ! -e /app/client-bin")
        legacy_path = f"/api/machines/{machine_id}/{created['data']['token']}/downloads/rathole/{release['target']}"
        assert request(legacy_path, method="HEAD")[1]["X-PortHub-Rathole-Asset"] == agent_name
        run_agent("get", f"http://{edge_ip}:8345{release_path}", "--dir", "/tmp/agent-release-get",
                  "--connections", "4", "--segment-size", "65536", "--sha256", release["sha256"])
        downloaded = docker("exec", prefix + "-core", "sha256sum", "/tmp/agent-release-get/" + agent_name).stdout.split()[0]
        assert downloaded == release["sha256"]
        checks.append("lazy GitHub cache, authenticated release catalog, legacy alias, HTTP ranges and cached agent self-download preserve SHA256 integrity without an image bundle")
        with tempfile.TemporaryDirectory(prefix="porthub-transfer-check-") as directory:
            source = pathlib.Path(directory) / "payload.bin"
            chunk = bytes(range(256)) * 4096
            with source.open("wb") as output:
                for _ in range(32):
                    output.write(chunk)
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            docker("exec", prefix + "-core", "mkdir", "/tmp/transfer-source", "/tmp/transfer-get")
            with source.open("rb") as content:
                subprocess.run(["docker", "exec", "-i", prefix + "-core", "tee", "/tmp/transfer-source/payload.bin"],
                               stdin=content, stdout=subprocess.DEVNULL, check=True)
            source_server = start_core(agent, "http.server", "47180", "/tmp/transfer-source", "--bind", "127.0.0.1")
            for _ in range(100):
                if "47180" in run_agent("http.server", "list").stdout:
                    break
                assert source_server.poll() is None
                time.sleep(.1)
            mapped = api("POST", "/api/connections/add", {"machine_id": machine_id,
                "service_name": "Native transfer check", "internal_ip": "127.0.0.1",
                "internal_port": 47180, "external_port": 49123})
            mapped_id = mapped["data"]["_id"]
            docker("exec", prefix + "-core", "mkdir", "-m", "700", "/tmp/agent-profile")
            profile_path = "/tmp/agent-profile/machine.json"
            setup = json.loads(request(f"/api/machines/command/{machine_id}?" + urllib.parse.urlencode({
                "public_base_url": f"http://{edge_ip}:8345"}), headers={"Cookie": cookie})[2])
            assert created["data"]["token"] not in setup["data"]["command"]
            run_agent("setup", "--ticket", setup["data"]["bootstrap_url"], "--profile", profile_path,
                      "--no-service", "--allow-insecure-http-for-tests")
            enrolled = json.loads(docker("exec", prefix + "-core", "cat", profile_path).stdout)
            assert enrolled["machine_id"] == machine_id and enrolled["token"] == created["data"]["token"]
            checks.append("owner setup ticket enrolls the packaged native CLI into a private profile without passing machine credentials in arguments")
            private_profiles = []
            for index, selected in enumerate((machine_id, managed_private["_id"])):
                enrollment = api("POST", "/api/access/private/peers", {"machine_id": selected})
                short_path = urllib.parse.urlparse(enrollment["native_command"].split()[-1]).path
                private_path = f"/tmp/agent-profile/private-{index}.json"
                enrolled = run_agent("enroll", "--ticket", f"http://{edge_ip}:8345{short_path}",
                    "--profile", private_path, "--allow-insecure-http-for-tests")
                assert "not activated" in enrolled.stdout
                private_profiles.append(json.loads(docker("exec", prefix + "-core", "cat", private_path).stdout))
            policy_book = {"name": "Private signaling fixture", "group_id": policy_group, "rules": [{
                "id": "private", "name": "Private fixture", "sources": [{"kind": "machine", "id": machine_id}],
                "destinations": [{"kind": "machine", "id": managed_private["_id"]}], "ports": "22", "bidirectional": True}]}
            signal_book = api("POST", "/api/access/books", policy_book)["data"]
            private_requests = {}
            for index, profile in enumerate(private_profiles):
                body = {"peer_id": profile["peer_id"], "token": profile["token"],
                    "fingerprint": ":".join(["AB" if index == 0 else "CD"] * 32),
                    "instance": f"isolation-private-instance-{index}"}
                private_requests[profile["peer_id"]] = body
                assert api("POST", "/api/access/private/sync", body)["snapshot"]["self"] == profile["peer_id"]
            sender, recipient = sorted(private_requests)
            outgoing = dict(private_requests[sender])
            outgoing["signals"] = [{"to": recipient, "session": "isolation-private-session",
                "description": {"type": "offer", "sdp": f"v=0\r\na=fingerprint:sha-256 {outgoing['fingerprint']}\r\n"}}]
            api("POST", "/api/access/private/sync", outgoing)
            received = api("POST", "/api/access/private/sync", private_requests[recipient])
            assert len(received["signals"]) == 1 and received["signals"][0]["from"] == sender
            assert len(received["snapshot"]["peers"]) == 2 and received["snapshot"]["expires_at"].endswith("Z")
            acknowledged = dict(private_requests[recipient])
            acknowledged["acks"] = [received["signals"][0]["id"]]
            assert api("POST", "/api/access/private/sync", acknowledged)["signals"] == []
            api("DELETE", "/api/access/books/" + signal_book["_id"], {"revision": 1})
            checks.append("packaged native CLI stages two private enrollments and exchanges authenticated scoped signaling through production ingress without activating packet transport")
            tunnel = start_core(agent, "run", "--profile", profile_path)
            mapped_port = inspect("edge")["NetworkSettings"]["Ports"]["49123/tcp"][0]["HostPort"]
            for _ in range(150):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{mapped_port}/payload.bin", timeout=2) as response:
                        assert response.read(256) == bytes(range(256))
                    break
                except (OSError, urllib.error.URLError):
                    assert tunnel.poll() is None
                    time.sleep(.1)
            else:
                raise AssertionError("native public forwarding did not become ready")
            source_url = f"http://{edge_ip}:49123/payload.bin"
            run_agent("get", source_url,
                   "--dir", "/tmp/transfer-get", "--connections", "4", "--sha256", expected)
            actual = docker("exec", prefix + "-core", "sha256sum", "/tmp/transfer-get/payload.bin").stdout.split()[0]
            assert actual == expected
            checks.append("saved-profile native agent syncs real API configuration and transfers 32 MiB via embedded tunnel, http.server and parallel get with matching SHA256")
            assert "Native agent diagnostics reached the UI Socket.IO client." in ui_client(agent_logs=True)
            checks.append("native agent captures diagnostics in memory and streams them on demand to the official UI client over HTTPS without shell helpers")
            api("PUT", "/api/connections/firewall/policy", {"data_id": mapped_id,
                "is_public": False, "allowed_ips": ["203.0.113.254"]})
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{mapped_port}/payload.bin", timeout=1)
            except (OSError, urllib.error.URLError):
                pass
            else:
                raise AssertionError("private mapped-port policy allowed an unauthorized source")
            api("PUT", "/api/connections/firewall/policy", {"data_id": mapped_id,
                "is_public": False, "allowed_ips": [core_ip]})
            docker("exec", prefix + "-core", "rm", "/tmp/transfer-get/payload.bin")
            run_agent("get", source_url,
                   "--dir", "/tmp/transfer-get", "--connections", "4", "--sha256", expected)
            actual = docker("exec", prefix + "-core", "sha256sum", "/tmp/transfer-get/payload.bin").stdout.split()[0]
            assert actual == expected
            traffic = api("POST", "/api/connections/firewall/traffic/snapshot", {"data_ids": [mapped_id]})
            assert len(traffic["data"]) == 1 and traffic["data"][0]["connection"]["_id"] == mapped_id
            api("POST", "/api/connections/delete", {"data_id": mapped_id})
            with socket.socket() as client:
                client.settimeout(.5)
                # Docker's published-port proxy can accept a TCP handshake even
                # after the target closes; inspect the container listener itself.
                assert client.connect_ex((edge_ip, 49123)) != 0
            for _ in range(200):
                result = docker("exec", prefix + "-core", "cat", profile_path + ".status.json", check=False)
                if result.returncode == 0 and json.loads(result.stdout)["service_count"] == 0:
                    break
                time.sleep(.1)
            else:
                raise AssertionError("native saved-profile agent did not apply mapped-port deletion")
            assert "token" not in run_agent("status", "--profile", profile_path).stdout
            checks.append("saved-profile native agent applies live mapped-port deletion without a shell client")
            retiring = api("POST", "/api/machines/add", {"name": "Native retirement check"})
            retiring_id = retiring["data"]["_id"]
            retiring_profile = "/tmp/agent-profile/retiring.json"
            subprocess.run(["docker", "exec", "-i", prefix + "-core", agent, "configure",
                            "--profile", retiring_profile, "--server", f"http://{edge_ip}:8345",
                            "--machine-id", retiring_id, "--allow-insecure-http-for-tests"],
                           input=retiring["data"]["token"], text=True, stdout=subprocess.DEVNULL, check=True)
            retiring_agent = start_core(agent, "run", "--profile", retiring_profile)
            api("POST", "/api/connections/add", {"machine_id": retiring_id,
                "service_name": "Retirement forwarding", "internal_ip": "127.0.0.1",
                "internal_port": 47180, "external_port": 49123})
            for _ in range(150):
                try:
                    probe = urllib.request.Request(f"http://127.0.0.1:{mapped_port}/payload.bin",
                                                   headers={"Range": "bytes=0-255"})
                    with urllib.request.urlopen(probe, timeout=2) as response:
                        assert response.read() == bytes(range(256))
                    break
                except (OSError, urllib.error.URLError):
                    assert retiring_agent.poll() is None
                    time.sleep(.1)
            else:
                raise AssertionError("retirement fixture did not forward")
            api("POST", "/api/machines/delete", {"data_id": retiring_id})
            for _ in range(150):
                if retiring_agent.poll() is not None:
                    break
                time.sleep(.1)
            assert retiring_agent.poll() == 0, "deleted native agent did not exit normally"
            retired = json.loads(docker("exec", prefix + "-core", "cat", retiring_profile + ".status.json").stdout)
            assert "token" not in run_agent("status", "--profile", retiring_profile).stdout
            assert retired["state"] == "deleted" and retired["service_count"] == 0
            history = json.loads(request(f"/api/machines/{retiring_id}/status-history",
                                         headers={"Cookie": cookie})[2])
            assert history["msg"] == "Machine not found", "agent ACK did not finish tombstone removal"
            assert tunnel.poll() is None and source_server.poll() is None
            checks.append("whole-machine deletion closes forwarding, native agent exits and acknowledges removal, and the other profile/server stays running")
            run_agent("http.server", "stop", "47180")
            checks.append("native API enforces deny/allow mapped-port policy via authenticated firewall IPC and filters traffic by ownership")
        cert = docker("exec", prefix + "-edge", "cat", "/data/certificates/origin.key").stdout
        fingerprint = hashlib.sha256(cert.encode()).hexdigest()
        compose("restart", "core", "edge", "firewall")
        compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "120")
        assert request("/api/auth/me", headers={"Cookie": cookie})[2] == identity
        assert request("/api/machines/private-addresses/" + machine_id, headers={"Cookie": cookie})[2] == private_before
        assert hashlib.sha256(docker("exec", prefix + "-edge", "cat",
                                    "/data/certificates/origin.key").stdout.encode()).hexdigest() == fingerprint
        assert activity_count() == 3
        checks.append("MongoDB account/session, private address, activity counters and TLS identity survive restart")
        removal=json.dumps({"username":"check@example.invalid","password":"Isolated-Password1!Sample"}).encode()
        status,_,body=request("/api/auth/delete",method="DELETE",data=removal,
            headers={"Cookie":cookie,"Content-Type":"application/json"})
        assert status==200, (status,body)
        for endpoint,expected,payload,request_headers in [
            ("/api/auth/me",400,None,{"Cookie":cookie}),
            ("/api/machines/client/config?"+urllib.parse.urlencode(json.loads(origin_request)),410,None,{}),
        ]:
            try:
                request(endpoint,data=payload,headers=request_headers)
            except urllib.error.HTTPError as error:
                assert error.code==expected, (endpoint,error.code)
            else:
                raise AssertionError("Retired account credentials were accepted: "+endpoint)
        checks.append("account retirement revokes sessions and machine credentials and cascades service cleanup through production ingress and firewall IPC")

        report = {"checks": checks, "images": {role: inspect(role)["Image"] for role in config["services"]}}
        output = os.environ.get("PORTHUB_VERIFICATION_REPORT")
        if output:
            pathlib.Path(output).write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    except Exception:
        for role in config["services"]:
            log = docker("logs", "--tail", "20", prefix + "-" + role, check=False)
            text = (log.stdout + log.stderr).replace(password, "[redacted]").replace(key, "[redacted]")
            print(f"Disposable {role} logs:\n{text}", file=sys.stderr)
        raise
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        # A timed-out docker run CLI can leave its container alive. Remove only
        # this run's labelled client, then its private Compose resources and tag.
        client = docker("inspect", client_container, check=False)
        if client.returncode == 0:
            record = json.loads(client.stdout)[0]
            if (record["Config"].get("Labels") or {}).get("porthub.verification") == prefix:
                docker("rm", "--force", record["Id"], check=False)
        try:
            compose("down", "--volumes")
        finally:
            image = docker("image", "inspect", client_image, "--format", "{{.Id}}", check=False)
            if client_image_id and image.returncode == 0 and image.stdout.strip() == client_image_id:
                docker("image", "rm", client_image, check=False)
            shutil.rmtree(bind_root, ignore_errors=True)


if __name__ == "__main__":
    main()
