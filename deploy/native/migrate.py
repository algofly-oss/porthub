#!/usr/bin/env python3
"""Offline migration of the owned PortHub monolith to the root Compose roles.

Operator maintenance utility only; no Python process is installed in a runtime
image or client. Default mode performs read-only preflight. --apply stops only
the identified PortHub container, takes a cold backup, and rolls back on failure.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import uuid

ASSETS = {
    "porthub-" + target + (".exe" if target.startswith("windows_") else "")
    for target in ("x86_64", "x86", "arm64", "armhf", "armv7", "darwin_x86_64",
                   "darwin_arm64", "windows_x86_64", "windows_x86", "windows_arm64")
}


def image_version(image):
    version = (image["Config"].get("Labels") or {}).get("org.opencontainers.image.version", "")
    if version == "dev" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version):
        raise RuntimeError("native image requires an explicit release version")
    return version


def artifact_files(name, payload, version, checksum, expected_version):
    """Validate and normalize one immutable, fully captured agent release."""
    if name not in ASSETS or not 0 < len(payload) <= 128 * 1024 * 1024:
        raise RuntimeError("invalid native artifact")
    if len(version) > 256 or len(checksum) > 512:
        raise RuntimeError("invalid native artifact metadata")
    try:
        version = version.decode("ascii").strip()
        fields = checksum.decode("ascii").split()
    except UnicodeError as error:
        raise RuntimeError("invalid native artifact metadata") from error
    digest = hashlib.sha256(payload).hexdigest()
    if version != expected_version:
        raise RuntimeError("native images and agent artifacts must have the same release version")
    if fields != [digest, name]:
        raise RuntimeError("native artifact hash or filename mismatch")
    return {name: payload, name + ".version": (version + "\n").encode(),
            name + ".sha256": (digest + "  " + name + "\n").encode()}


def artifact_bundle(directory, expected_version, initial):
    """Resolve bundles before stopping production; identical host assets coalesce."""
    result = dict(initial)
    if directory is None:
        return result
    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise RuntimeError("native artifact bundle must be a directory")
    names = set()
    for path in directory.iterdir():
        name = path.name
        if name.startswith("porthub-"):
            if name.endswith(".sha256"):
                name = name.removesuffix(".sha256")
            elif name.endswith(".version"):
                name = name.removesuffix(".version")
            if name not in ASSETS:
                raise RuntimeError("unsupported native artifact filename")
            names.add(name)
    for name in sorted(names):
        parts = []
        for suffix, maximum in (("", 128 * 1024 * 1024), (".version", 256), (".sha256", 512)):
            path = directory / (name + suffix)
            if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
                raise RuntimeError("missing or unsafe native artifact bundle entry")
            parts.append(path.read_bytes())
        files = artifact_files(name, *parts, expected_version)
        for filename, content in files.items():
            if filename in result and result[filename] != content:
                raise RuntimeError("native artifact bundle conflicts with the packaged host agent")
            result[filename] = content
    return result


def image_release_preflight(version):
    image = inspect("image", "porthub:core")
    if (image["Config"].get("Labels") or {}).get("io.porthub.image-client-bundle") != "complete-v1":
        raise RuntimeError("production core must embed its complete client release")
    report = json.loads(run(["docker", "run", "--rm", "--network", "none", "--read-only",
                            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                            "--entrypoint", "porthub-api", "porthub:core", "--check-artifacts",
                            "/app/client-bin", version]))
    releases = report.get("releases", [])
    if (report.get("version") != version or len(releases) != len(ASSETS)
            or {entry.get("asset") for entry in releases} != ASSETS
            or any(entry.get("version") != version or not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
                   for entry in releases)):
        raise RuntimeError("invalid embedded client release receipt")
    return {entry["asset"]: entry for entry in releases}


def run(arguments, *, binary=False):
    result = subprocess.run(arguments, capture_output=True, text=not binary)
    if result.returncode:
        # Docker/Compose errors can include environment-derived credentials.
        raise RuntimeError("maintenance command failed: " + arguments[0])
    return result.stdout


def inspect(kind, name):
    return json.loads(run(["docker", kind, "inspect", name]))[0]


def database_preflight(configured, root):
    """Use the native renderer against the live database, with no startup writes."""
    environment = configured["services"]["core"]["environment"]
    if not environment.get("MONGO_DATABASE_URI") or not environment.get("MONGO_DATABASE_NAME"):
        raise RuntimeError("database configuration is required for native preflight")
    nonce = uuid.uuid4().hex
    name = "porthub-data-preflight-" + nonce
    arguments = ["docker", "run", "--rm", "--name", name,
                 "--label", "porthub.data-preflight=" + nonce, "--network", "host",
                 "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
    forwarded = {key: str(value) for key, value in environment.items()
                 if value is not None and key.startswith(("MONGO_", "PORTHUB_", "PORT_HUB_", "RATHOLE_", "FW_", "FIREWALL_", "SESSION_", "SIGNUP_", "MACHINE_", "WEB_PROXY_"))}
    for key in forwarded:
        arguments.extend(["--env", key])
    arguments.extend(["--entrypoint", "porthub-api", "porthub:core", "--check-config"])
    try:
        result = subprocess.run(arguments, env={**os.environ, **forwarded}, capture_output=True, text=True, timeout=45)
        private_file(root / (name + ".log"), (result.stdout + result.stderr).encode())
        if result.returncode:
            raise RuntimeError("live database configuration preflight failed; private diagnostics retained")
        report = json.loads(result.stdout)
        expected = {"active_machines", "public_services", "web_routes", "proxy_routes", "gateway_alias_routes"}
        if set(report) != expected or any(type(value) is not int or value < 0 for value in report.values()):
            raise RuntimeError("invalid native database preflight receipt")
        return report
    finally:
        inspected = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
        if inspected.returncode == 0:
            record = json.loads(inspected.stdout)[0]
            if (record["Config"].get("Labels") or {}).get("porthub.data-preflight") == nonce:
                subprocess.run(["docker", "rm", "--force", record["Id"]], capture_output=True)


def legacy_tls(container, enabled, allow_self_signed=False):
    if not enabled:
        return None
    certificate = run(["docker", "exec", container, "cat", "/app/deploy/certificates/server.crt"], binary=True)
    key = run(["docker", "exec", container, "cat", "/app/deploy/certificates/server.key"], binary=True)
    if not certificate or not key:
        if allow_self_signed:
            return None
        raise RuntimeError("legacy TLS certificate/key is empty; configure HTTP ingress or supply valid TLS material before migration")
    with tempfile.TemporaryDirectory(prefix="porthub-tls-preflight-") as directory:
        cert_path, key_path = pathlib.Path(directory) / "certificate", pathlib.Path(directory) / "key"
        private_file(cert_path, certificate)
        private_file(key_path, key)
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert_path, key_path, password=lambda: b"")
        except ssl.SSLError as error:
            if allow_self_signed:
                return None
            raise RuntimeError("legacy TLS certificate/key is invalid; configure HTTP ingress or supply valid TLS material before migration") from error
    return certificate, key


def private_file(path, data):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def snapshot(source, destination):
    if not source.is_dir() or source.is_symlink():
        raise RuntimeError("PortHub state directory is unavailable")
    paths = [source, *source.rglob("*")]
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths):
        raise RuntimeError("PortHub state contains unsupported filesystem entries")
    ownership = {str(path.relative_to(source)): (path.stat().st_uid, path.stat().st_gid) for path in paths}
    shutil.copytree(source, destination)
    for path in paths:
        if path.is_file():
            copied = destination / path.relative_to(source)
            if file_hash(path) != file_hash(copied):
                raise RuntimeError("PortHub cold backup integrity check failed")
    return ownership


def owner_tree(path, uid, gid):
    for item in [path, *path.rglob("*")]:
        if item.is_symlink():
            raise RuntimeError("unsafe state symlink")
        os.chown(item, uid, gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=pathlib.Path, required=True)
    parser.add_argument("--container", default="porthub")
    parser.add_argument("--project", default="porthub")
    parser.add_argument("--extra-artifacts", type=pathlib.Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.project_dir.resolve(strict=True)
    if args.project != "porthub" or args.container != "porthub":
        raise RuntimeError("migration is restricted to the existing PortHub project")
    old = inspect("container", args.container)
    labels = old["Config"].get("Labels", {})
    if labels.get("com.docker.compose.project") != args.project or labels.get("com.docker.compose.service") != "porthub":
        raise RuntimeError("existing container is not the PortHub monolith")
    mount = next(item for item in old["Mounts"] if item["Destination"] == "/data")
    if mount["Type"] != "volume" or mount["Name"] != "porthub_porthub_data":
        raise RuntimeError("unexpected PortHub data volume")
    data = pathlib.Path(inspect("volume", mount["Name"])["Mountpoint"])
    versions = set()
    for role in ("core", "edge", "firewall"):
        image = inspect("image", "porthub:" + role)
        versions.add(image_version(image))
        if role == "core" and (image["Config"].get("Labels") or {}).get("io.porthub.api-preflight") != "v1":
            raise RuntimeError("core image must support read-only database configuration preflight")
        wanted = "arm64" if platform.machine() == "aarch64" else "amd64"
        if image["Architecture"] != wanted:
            raise RuntimeError("native image architecture does not match host")
    if len(versions) != 1:
        raise RuntimeError("native core, edge and firewall images must have the same release version")
    version = versions.pop()
    compose = ["docker", "compose", "--project-name", args.project, "--project-directory", str(root), "--file", str(root / "docker-compose.yml")]
    configured=json.loads(run([*compose,"config","--format","json"]))
    if configured["services"]["core"]["environment"].get("PORTHUB_VERSION", version) != version:
        raise RuntimeError("configured runtime version must match the native image release")
    old_environment=dict(item.split("=",1) for item in old["Config"]["Env"] if "=" in item)
    old_table=old_environment.get("FW_NFT_TABLE","inet rathole").removeprefix("inet ").strip()
    new_table=configured["services"]["firewall"]["environment"].get("FW_NFT_TABLE","inet porthub").removeprefix("inet ").strip()
    if old_table!=new_table:
        raise RuntimeError("native firewall must retain the existing PortHub table name")
    native_target = "arm64" if platform.machine() == "aarch64" else "x86_64"
    artifact = "porthub-" + native_target
    parts = [run(["docker", "run", "--rm", "--network", "none", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--entrypoint", "/bin/cat", "porthub:core", "/app/client-bin/" + artifact + suffix], binary=True)
             for suffix in ("", ".version", ".sha256")]
    artifacts = artifact_bundle(args.extra_artifacts, version, artifact_files(artifact, *parts, version))
    embedded = image_release_preflight(version)
    for name in ASSETS & artifacts.keys():
        if hashlib.sha256(artifacts[name]).hexdigest() != embedded[name]["sha256"]:
            raise RuntimeError("external client bundle differs from the embedded production release")
    edge_environment = configured["services"].get("edge", {}).get("environment", {})
    tls_enabled = bool(edge_environment.get("PORTHUB_EDGE_TLS_LISTEN", ""))
    allow_self_signed = str(edge_environment.get("PORTHUB_ALLOW_SELF_SIGNED", "false")).lower() in ("1", "true", "yes", "on")
    tls_material = legacy_tls(args.container, tls_enabled, allow_self_signed)
    data_report = database_preflight(configured, root)
    print("Preflight: owned PortHub container, data volume, native images and Compose configuration verified", flush=True)
    print("Preflight: matching release versions and complete agent artifacts verified before downtime", flush=True)
    print("Preflight: live configuration verified: " + json.dumps(data_report, sort_keys=True), flush=True)
    print("Preflight: TLS " + ("identity validated" if tls_material else "optional listener uses native automatic identity" if tls_enabled else "disabled; HTTP ingress configured"), flush=True)
    if not args.apply:
        return
    if os.geteuid() != 0:
        raise RuntimeError("administrator access is required for state ownership migration")
    lock = os.open(root / ".migration.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = root / ("backup-before-native-" + stamp)
    backup.mkdir(mode=0o700)
    private_file(backup / "container.json", json.dumps(old).encode())
    private_file(backup / "environment", (root / ".env").read_bytes())
    if tls_material:
        for name, content in zip(("origin.crt", "origin.key"), tls_material):
            private_file(backup / name, content)
    running = set(run(["docker", "ps", "--quiet"]).split())
    others = running - {old["Id"][:12]}
    stopped = False
    owners = None
    watched_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_handlers = {number: signal.getsignal(number) for number in watched_signals}

    def interrupted(_number, _frame):
        raise RuntimeError("PortHub migration interrupted; restoring the previous deployment")

    try:
        for number in watched_signals:
            signal.signal(number, interrupted)
        # A Docker stop can take effect before its CLI is interrupted. Rollback
        # must also run if that command never returns a successful result.
        stopped = True
        run(["docker", "stop", "--time", "30", args.container])
        owners = snapshot(data / "mongo", backup / "mongo")
        snapshot(data / "firewall", backup / "firewall")
        private_file(backup / "mongo-ownership.json", json.dumps(owners).encode())
        print("PortHub stopped; cold MongoDB/firewall backups verified", flush=True)
        volumes = {}
        for name in ("firewall_data", "certificates"):
            volume = args.project + "_" + name
            run(["docker", "volume", "create", volume])
            path = pathlib.Path(inspect("volume", volume)["Mountpoint"])
            if any(path.iterdir()):
                raise RuntimeError("native destination volume must be empty for initial migration")
            volumes[name] = path
        shutil.copytree(backup / "firewall", volumes["firewall_data"], dirs_exist_ok=True)
        if tls_material:
            for name in ("origin.crt", "origin.key"):
                shutil.copy2(backup / name, volumes["certificates"] / name)
                os.chmod(volumes["certificates"] / name, 0o640)
        owner_tree(volumes["certificates"], 0, 10001)
        os.chmod(volumes["certificates"], 0o770)
        owner_tree(data / "mongo", 10001, 10001)
        run([*compose, "up", "--detach", "--no-build", "--wait", "--wait-timeout", "180", "firewall", "core", "edge"])
        after = set(run(["docker", "ps", "--quiet"]).split())
        if not others.issubset(after):
            raise RuntimeError("an unrelated previously running container is no longer running")
        print("Native PortHub roles healthy; unrelated containers retained; backup: " + str(backup), flush=True)
    except BaseException:
        if stopped:
            # A lost SSH session must not interrupt the short restoration path.
            for number in watched_signals:
                signal.signal(number, signal.SIG_IGN)
            # Preserve the failed native state before restoring the verified
            # snapshot; no database directory is deleted during rollback.
            subprocess.run([*compose, "stop", "--timeout", "20", "edge", "core", "firewall"], capture_output=True)
            if owners is not None:
                failed = data / ("mongo-native-failed-" + stamp)
                (data / "mongo").rename(failed)
                shutil.copytree(backup / "mongo", data / "mongo")
                for relative, (uid, gid) in owners.items():
                    os.chown(data / "mongo" / relative, uid, gid)
            subprocess.run(["docker", "start", args.container], capture_output=True, check=True)
            print("Native activation failed; previous PortHub container restored; diagnostic state retained", file=sys.stderr, flush=True)
        raise
    finally:
        for number, previous in previous_handlers.items():
            signal.signal(number, previous)
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
