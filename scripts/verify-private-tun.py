#!/usr/bin/env python3
"""Verify TUN packets and kernel interface discovery in disposable namespaces."""
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
environment = {**os.environ, "CARGO_BUILD_JOBS": "8", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
tests = {
    "private_packets": "owned_linux_tun_routes_kernel_udp_packets_and_cleans_up",
    "porthub_agent": "private_network::interfaces::tests::kernel_events_refresh_underlay_addresses_and_ignore_owned_overlay_links",
}
with tempfile.TemporaryFile(mode="w+") as output:
    build = subprocess.run([str(pathlib.Path.home()/".cargo/bin/cargo"), "test", "-p", "porthub-agent", "--features", "netns-tests", "--lib", "--test", "private_packets", "--no-run", "--message-format=json"], cwd=ROOT, env=environment, stdout=output)
    output.seek(0)
    messages = [json.loads(line) for line in output]
    if build.returncode:
        for item in messages:
            if item.get("reason") == "compiler-message":
                print(item["message"].get("rendered", ""), file=sys.stderr, end="")
        build.check_returncode()
    artifacts = {item["target"]["name"]: item["executable"] for item in messages if item.get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] in tests}
assert artifacts.keys() == tests.keys()
for target, test in tests.items():
    executable = pathlib.Path(artifacts[target]).resolve()
    assert executable.is_file() and executable.parent == (ROOT/"target/debug/deps").resolve()
    subprocess.run(["docker", "run", "--rm", "--name", "porthub-tun-verify-"+secrets.token_hex(5), "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges:true", "--device", "/dev/net/tun", "--env", "PORTHUB_TEST_OWNED_NETNS=1", "--mount", f"type=bind,src={executable},dst=/native-test,readonly", "--entrypoint", "/native-test", "porthub:edge", "--ignored", "--exact", test], check=True, cwd=ROOT)
