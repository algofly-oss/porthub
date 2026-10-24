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
import shutil
import subprocess
import sys


def run(arguments, *, binary=False):
    result = subprocess.run(arguments, capture_output=True, text=not binary)
    if result.returncode:
        # Docker/Compose errors can include environment-derived credentials.
        raise RuntimeError("maintenance command failed: " + arguments[0])
    return result.stdout


def inspect(kind, name):
    return json.loads(run(["docker", kind, "inspect", name]))[0]


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
    for role in ("core", "edge", "firewall"):
        image = inspect("image", "porthub:" + role)
        wanted = "arm64" if platform.machine() == "aarch64" else "amd64"
        if image["Architecture"] != wanted:
            raise RuntimeError("native image architecture does not match host")
    compose = ["docker", "compose", "--project-name", args.project, "--project-directory", str(root), "--file", str(root / "docker-compose.yml")]
    configured=json.loads(run([*compose,"config","--format","json"]))
    old_environment=dict(item.split("=",1) for item in old["Config"]["Env"] if "=" in item)
    old_table=old_environment.get("FW_NFT_TABLE","inet rathole").removeprefix("inet ").strip()
    new_table=configured["services"]["firewall"]["environment"].get("FW_NFT_TABLE","inet porthub").removeprefix("inet ").strip()
    if old_table!=new_table:
        raise RuntimeError("native firewall must retain the existing PortHub table name")
    print("Preflight: owned PortHub container, data volume, native images and Compose configuration verified", flush=True)
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
    for source, destination in [("/app/deploy/certificates/server.crt", "origin.crt"), ("/app/deploy/certificates/server.key", "origin.key")]:
        private_file(backup / destination, run(["docker", "exec", args.container, "cat", source], binary=True))
    running = set(run(["docker", "ps", "--quiet"]).split())
    others = running - {old["Id"][:12]}
    stopped = False
    owners = None
    try:
        run(["docker", "stop", "--time", "30", args.container])
        stopped = True
        owners = snapshot(data / "mongo", backup / "mongo")
        snapshot(data / "firewall", backup / "firewall")
        private_file(backup / "mongo-ownership.json", json.dumps(owners).encode())
        print("PortHub stopped; cold MongoDB/firewall backups verified; TLS identity retained", flush=True)
        volumes = {}
        for name in ("firewall_data", "certificates", "client_artifacts"):
            volume = args.project + "_" + name
            run(["docker", "volume", "create", volume])
            path = pathlib.Path(inspect("volume", volume)["Mountpoint"])
            if any(path.iterdir()):
                raise RuntimeError("native destination volume must be empty for initial migration")
            volumes[name] = path
        shutil.copytree(backup / "firewall", volumes["firewall_data"], dirs_exist_ok=True)
        for name in ("origin.crt", "origin.key"):
            shutil.copy2(backup / name, volumes["certificates"] / name)
            os.chmod(volumes["certificates"] / name, 0o640)
        owner_tree(volumes["certificates"], 0, 10001)
        os.chmod(volumes["certificates"], 0o770)
        owner_tree(data / "mongo", 10001, 10001)
        native_target = "arm64" if platform.machine() == "aarch64" else "x86_64"
        artifact_dir = volumes["client_artifacts"]
        artifact = "porthub-" + native_target
        payload = run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/cat", "porthub:core", "/app/client-bin/" + artifact], binary=True)
        private_file(artifact_dir / artifact, payload)
        version = run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/cat", "porthub:core", "/app/client-bin/" + artifact + ".version"], binary=True)
        private_file(artifact_dir / (artifact + ".version"), version)
        private_file(artifact_dir / (artifact + ".sha256"), (hashlib.sha256(payload).hexdigest() + "  " + artifact + "\n").encode())
        if args.extra_artifacts:
            source_dir = args.extra_artifacts.resolve(strict=True)
            for checksum in source_dir.glob("porthub-*.sha256"):
                name = checksum.name.removesuffix(".sha256")
                source = source_dir / name
                if not source.is_file() or source.is_symlink() or source.stat().st_size > 128 * 1024 * 1024:
                    raise RuntimeError("invalid additional native artifact")
                payload = source.read_bytes()
                if hashlib.sha256(payload).hexdigest() != checksum.read_text().split()[0]:
                    raise RuntimeError("additional native artifact hash mismatch")
                for suffix in ("", ".version", ".sha256"):
                    item = source_dir / (name + suffix)
                    if item.is_symlink() or not item.is_file():
                        raise RuntimeError("invalid artifact metadata")
                    private_file(artifact_dir / item.name, item.read_bytes())
        for path in artifact_dir.iterdir():
            os.chmod(path, 0o555 if path.suffix not in (".version", ".sha256") else 0o444)
        os.chmod(artifact_dir, 0o755)
        run([*compose, "up", "--detach", "--no-build", "--wait", "--wait-timeout", "180", "firewall", "core", "edge"])
        after = set(run(["docker", "ps", "--quiet"]).split())
        if not others.issubset(after):
            raise RuntimeError("an unrelated previously running container is no longer running")
        print("Native PortHub roles healthy; unrelated containers retained; backup: " + str(backup), flush=True)
    except BaseException:
        if stopped:
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


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
