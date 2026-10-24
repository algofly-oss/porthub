"""Migration release checks must fail before any production stop or state write."""
import hashlib
import importlib.util
import io
import json
import pathlib
import signal
import sys
import tempfile
import tarfile
import unittest
from unittest import mock

MODULE = importlib.util.spec_from_file_location("porthub_migrate", pathlib.Path(__file__).with_name("migrate.py"))
migrate = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(migrate)


class ReleasePreflight(unittest.TestCase):
    version = "release-fixture-123"

    def bundle(self, name, payload=b"native-agent", version=None):
        version = self.version if version is None else version
        digest = hashlib.sha256(payload).hexdigest()
        return migrate.artifact_files(name, payload, (version + "\n").encode(),
                                      (digest + "  " + name + "\n").encode(), version)

    def write_bundle(self, directory, files):
        for name, content in files.items():
            (directory / name).write_bytes(content)

    def tar_file(self, name, content):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
        return output.getvalue()

    def test_identical_host_asset_coalesces_with_complete_cross_platform_bundle(self):
        host = self.bundle("porthub-arm64")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            extra = {**host, **self.bundle("porthub-x86_64"),
                     **self.bundle("porthub-darwin_arm64"), **self.bundle("porthub-windows_arm64.exe")}
            self.write_bundle(root, extra)
            self.assertEqual(migrate.artifact_bundle(root, self.version, host), extra)

    def test_conflicting_host_payload_and_mixed_release_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_bundle(root, self.bundle("porthub-arm64", b"another-native-build"))
            with self.assertRaisesRegex(RuntimeError, "conflicts"):
                migrate.artifact_bundle(root, self.version, self.bundle("porthub-arm64"))
            self.write_bundle(root, self.bundle("porthub-arm64", version="another-release"))
            with self.assertRaisesRegex(RuntimeError, "same release version"):
                migrate.artifact_bundle(root, self.version, {})

    def test_incomplete_symlink_and_hash_mismatches_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            files = self.bundle("porthub-x86_64")
            self.write_bundle(root, files)
            (root / "porthub-x86_64.version").unlink()
            with self.assertRaisesRegex(RuntimeError, "missing or unsafe"):
                migrate.artifact_bundle(root, self.version, {})
            (root / "porthub-x86_64.version").symlink_to(root / "porthub-x86_64.sha256")
            with self.assertRaisesRegex(RuntimeError, "missing or unsafe"):
                migrate.artifact_bundle(root, self.version, {})
            (root / "porthub-x86_64.version").unlink()
            self.write_bundle(root, files)
            (root / "porthub-x86_64").write_bytes(b"damaged")
            with self.assertRaisesRegex(RuntimeError, "hash or filename mismatch"):
                migrate.artifact_bundle(root, self.version, {})

    def test_unknown_names_and_metadata_filename_substitution_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "porthub-unknown").write_bytes(b"unexpected")
            with self.assertRaisesRegex(RuntimeError, "unsupported"):
                migrate.artifact_bundle(root, self.version, {})
        files = self.bundle("porthub-x86_64")
        with self.assertRaisesRegex(RuntimeError, "hash or filename mismatch"):
            migrate.artifact_files("porthub-x86_64", files["porthub-x86_64"],
                                   files["porthub-x86_64.version"],
                                   files["porthub-x86_64.sha256"].replace(b"porthub-x86_64", b"porthub-arm64"),
                                   self.version)

    def test_apply_rejects_invalid_bundle_before_stopping_or_creating_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            extra = root / "artifacts"
            extra.mkdir()
            self.write_bundle(extra, self.bundle("porthub-darwin_arm64", version="stale"))
            old = {"Config": {"Labels": {"com.docker.compose.project": "porthub",
                                          "com.docker.compose.service": "porthub"}, "Env": []},
                   "Mounts": [{"Destination": "/data", "Type": "volume", "Name": "porthub_porthub_data"}]}
            image = {"Architecture": "amd64", "Config": {"Labels": {"org.opencontainers.image.version": self.version, "io.porthub.api-preflight": "v1"}}}
            files = self.bundle("porthub-x86_64")
            calls = []

            def inspect(kind, name):
                return old if kind == "container" else image if kind == "image" else {"Mountpoint": str(root / "data")}

            def run(arguments, *, binary=False):
                calls.append(arguments)
                if arguments[:2] == ["docker", "compose"]:
                    return json.dumps({"services": {
                        "core": {"environment": {"PORTHUB_VERSION": self.version}},
                        "firewall": {"environment": {"FW_NFT_TABLE": "inet rathole"}}}})
                if arguments[:2] == ["docker", "run"]:
                    self.assertTrue(binary)
                    self.assertIn("none", arguments)
                    return files[pathlib.PurePosixPath(arguments[-1]).name]
                self.fail("unexpected maintenance action")

            argv = ["migrate.py", "--apply", "--project-dir", str(root), "--extra-artifacts", str(extra)]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(migrate, "inspect", inspect), \
                 mock.patch.object(migrate, "run", run), mock.patch.object(migrate.platform, "machine", return_value="x86_64"):
                with self.assertRaisesRegex(RuntimeError, "same release version"):
                    migrate.main()
            self.assertFalse(any(command[:2] == ["docker", "stop"] for command in calls))
            self.assertFalse(list(root.glob("backup-before-native-*")))
            self.assertFalse((root / ".migration.lock").exists())

    def test_missing_or_development_image_version_is_rejected(self):
        for labels in (None, {}, {"org.opencontainers.image.version": "dev"},
                       {"org.opencontainers.image.version": "bad\nversion"}):
            with self.assertRaisesRegex(RuntimeError, "explicit release version"):
                migrate.image_version({"Config": {"Labels": labels}})

    def test_mixed_image_or_configured_runtime_versions_fail_before_downtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for mismatch in ("image", "runtime"):
                with self.subTest(mismatch=mismatch):
                    calls = []

                    def inspect(kind, name):
                        if kind == "container":
                            return {"Config": {"Labels": {"com.docker.compose.project": "porthub",
                                                           "com.docker.compose.service": "porthub"}},
                                    "Mounts": [{"Destination": "/data", "Type": "volume", "Name": "porthub_porthub_data"}]}
                        if kind == "volume":
                            return {"Mountpoint": str(root / "data")}
                        version = "stale" if mismatch == "image" and name == "porthub:edge" else self.version
                        return {"Architecture": "amd64", "Config": {"Labels": {"org.opencontainers.image.version": version, "io.porthub.api-preflight": "v1"}}}

                    def run(arguments, **_):
                        calls.append(arguments)
                        self.assertEqual(arguments[:2], ["docker", "compose"])
                        return json.dumps({"services": {"core": {"environment": {"PORTHUB_VERSION": "stale"}}}})

                    with mock.patch.object(sys, "argv", ["migrate.py", "--apply", "--project-dir", str(root)]), \
                         mock.patch.object(migrate, "inspect", inspect), mock.patch.object(migrate, "run", run), \
                         mock.patch.object(migrate.platform, "machine", return_value="x86_64"):
                        with self.assertRaisesRegex(RuntimeError, "same release version|runtime version must match"):
                            migrate.main()
                    self.assertFalse(any(command[:2] == ["docker", "stop"] for command in calls))
                    self.assertFalse((root / ".migration.lock").exists())

    def test_interrupted_stop_and_lost_ssh_restore_only_the_owned_container(self):
        for interruption in ("command", signal.SIGTERM, signal.SIGHUP):
            with self.subTest(interruption=interruption), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / ".env").write_text("PORTHUB_VERSION=" + self.version + "\n")
                old_id = "a" * 64
                old = {"Id": old_id, "Config": {"Env": [], "Labels": {
                    "com.docker.compose.project": "porthub", "com.docker.compose.service": "porthub"}},
                    "Mounts": [{"Destination": "/data", "Type": "volume", "Name": "porthub_porthub_data"}]}
                image = {"Architecture": "amd64", "Config": {"Labels": {"org.opencontainers.image.version": self.version, "io.porthub.api-preflight": "v1"}}}
                files = self.bundle("porthub-x86_64")
                calls = []
                handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

                def inspect(kind, _name):
                    return old if kind == "container" else image if kind == "image" else {"Mountpoint": str(root / "data")}

                def run(arguments, *, binary=False):
                    calls.append(arguments)
                    if arguments[:2] == ["docker", "compose"]:
                        return json.dumps({"services": {
                            "core": {"environment": {"PORTHUB_VERSION": self.version}},
                            "firewall": {"environment": {"FW_NFT_TABLE": "inet rathole"}}}})
                    if arguments[:2] == ["docker", "run"]:
                        return files[pathlib.PurePosixPath(arguments[-1]).name]
                    if arguments[:2] == ["docker", "exec"]:
                        self.assertTrue(binary)
                        return b"retained-certificate-fixture"
                    if arguments[:2] == ["docker", "ps"]:
                        return old_id[:12] + "\nunrelated123\n"
                    self.assertEqual(arguments[:2], ["docker", "stop"])
                    if interruption == "command":
                        raise RuntimeError("interrupted Docker stop")
                    signal.raise_signal(interruption)
                    self.fail("migration signal did not interrupt the stop")

                argv = ["migrate.py", "--apply", "--project-dir", str(root)]
                with mock.patch.object(sys, "argv", argv), mock.patch.object(migrate, "inspect", inspect), \
                     mock.patch.object(migrate, "run", run), mock.patch.object(migrate.os, "geteuid", return_value=0), \
                     mock.patch.object(migrate, "database_preflight", return_value={"web_routes": 0}), \
                     mock.patch.object(migrate, "image_release_preflight", return_value={name:{"sha256":hashlib.sha256(b"native-agent").hexdigest()} for name in migrate.ASSETS}), \
                     mock.patch.object(migrate.platform, "machine", return_value="x86_64"), \
                     mock.patch.object(migrate.subprocess, "run") as rollback:
                    with self.assertRaisesRegex(RuntimeError, "interrupted"):
                        migrate.main()
                self.assertEqual(rollback.call_count, 2)
                self.assertEqual(rollback.call_args_list[0].args[0][-5:], ["--timeout", "20", "edge", "core", "firewall"])
                self.assertEqual(rollback.call_args_list[1].args[0], ["docker", "start", "porthub"])
                self.assertEqual(handlers, {number: signal.getsignal(number) for number in handlers})
                self.assertFalse((root / "data").exists(), "interrupted stop reached data migration")

    def test_http_ingress_never_reads_or_requires_a_legacy_private_key(self):
        with mock.patch.object(migrate, "run") as run:
            self.assertIsNone(migrate.legacy_tls("porthub", False))
            run.assert_not_called()

    def test_empty_tls_key_fails_before_any_stop_when_tls_is_requested(self):
        with mock.patch.object(migrate, "run", side_effect=[
            self.tar_file("server.crt", b"existing-certificate"),
            self.tar_file("server.key", b""),
        ]):
            with self.assertRaisesRegex(RuntimeError, "certificate/key is empty"):
                migrate.legacy_tls("porthub", True)

    def test_invalid_legacy_key_does_not_block_an_explicit_automatic_identity(self):
        with mock.patch.object(migrate, "run", side_effect=[
            self.tar_file("server.crt", b"existing-certificate"),
            self.tar_file("server.key", b""),
        ]):
            self.assertIsNone(migrate.legacy_tls("porthub", True, allow_self_signed=True))

    def test_tls_material_reads_stopped_container_files_without_starting_container(self):
        certificate, key = b"certificate", b"private-key"
        with mock.patch.object(migrate, "run", side_effect=[
            self.tar_file("server.crt", certificate), self.tar_file("server.key", key),
        ]) as run, mock.patch.object(migrate.ssl, "SSLContext") as context:
            self.assertEqual(migrate.legacy_tls("porthub", True), (certificate, key))
        context.return_value.load_cert_chain.assert_called_once()
        self.assertEqual(run.call_args_list[0].args[0], [
            "docker", "cp", "porthub:/app/deploy/certificates/server.crt", "-",
        ])
        self.assertTrue(run.call_args_list[0].kwargs["binary"])

    def test_native_data_preflight_forwards_secrets_only_in_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            report = {"active_machines": 1, "public_services": 2, "web_routes": 3,
                      "proxy_routes": 1, "gateway_alias_routes": 2}
            environment = {"MONGO_DATABASE_URI": "mongodb://preflight:fixture-secret@127.0.0.1:47017/database",
                           "MONGO_DATABASE_NAME": "database", "PATH": "/not-a-command-search-path"}
            configured = {"services": {"core": {"environment": environment}}}
            completed = migrate.subprocess.CompletedProcess([], 0, json.dumps(report), "")
            absent = migrate.subprocess.CompletedProcess([], 1, "", "")
            with mock.patch.object(migrate.subprocess, "run", side_effect=[completed, absent]) as run:
                self.assertEqual(migrate.database_preflight(configured, pathlib.Path(directory)), report)
            arguments = run.call_args_list[0].args[0]
            self.assertEqual(arguments[-1], "--check-config")
            self.assertNotIn(environment["MONGO_DATABASE_URI"], arguments)
            self.assertEqual(run.call_args_list[0].kwargs["env"]["MONGO_DATABASE_URI"], environment["MONGO_DATABASE_URI"])
            self.assertNotEqual(run.call_args_list[0].kwargs["env"].get("PATH"), environment["PATH"])
            logs = list(pathlib.Path(directory).glob("*.log"))
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
