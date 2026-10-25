#!/usr/bin/env python3
"""Build a development-only legacy wire reference; never ships in images.

The current Go peer waits for gathering completion while requesting continual
gathering, which does not emit completion. Use one-shot gathering only in this
temporary fixture so its unchanged ICE/DTLS packet protocol can be exercised.
"""
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
legacy_client = root / "legacy/go-client"
output = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/porthub-go-mesh-compat").resolve()
source = (legacy_client / "internal/mesh/peer.go").read_text()
old = "ice.WithContinualGatheringPolicy(ice.GatherContinually)"
assert source.count(old) == 1
with tempfile.TemporaryDirectory(prefix="porthub-go-wire-fixture-") as temporary:
    directory = pathlib.Path(temporary)
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(legacy_client / name, directory / name)
    (directory / "internal/mesh").mkdir(parents=True)
    (directory / "internal/mesh/peer.go").write_text(source.replace(old, "ice.WithContinualGatheringPolicy(ice.GatherOnce)"))
    (directory / "cmd/porthub-mesh-compat").mkdir(parents=True)
    shutil.copyfile(legacy_client / "cmd/porthub-mesh-compat/main.go", directory / "cmd/porthub-mesh-compat/main.go")
    (directory / "internal/relay").mkdir(parents=True)
    for item in (legacy_client / "internal/relay").glob("*.go"):
        if not item.name.endswith("_test.go"):
            shutil.copyfile(item,directory / "internal/relay" / item.name)
    subprocess.run(["go", "build", "-mod=readonly", "-o", str(output), "./cmd/porthub-mesh-compat"], cwd=directory, check=True)
    (directory / "cmd/porthub-turn-compat").mkdir(parents=True)
    shutil.copyfile(legacy_client / "cmd/porthub-turn-compat/main.go",directory / "cmd/porthub-turn-compat/main.go")
    turn_output=output.with_name("porthub-go-turn-compat")
    subprocess.run(["go","build","-mod=readonly","-o",str(turn_output),"./cmd/porthub-turn-compat"],cwd=directory,check=True)

print("Legacy source SHA256:", hashlib.sha256(source.encode()).hexdigest())
print("Fixture executable SHA256:", hashlib.sha256(output.read_bytes()).hexdigest())

print("TURN fixture executable SHA256:", hashlib.sha256(turn_output.read_bytes()).hexdigest())
