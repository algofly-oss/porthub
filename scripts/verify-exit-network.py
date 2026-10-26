#!/usr/bin/env python3
"""Run real agents and native API on two isolated, disposable Docker networks."""
import ipaddress
import json
import os
import pathlib
import secrets
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV = {**os.environ, "CARGO_BUILD_JOBS": "8", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
assert ENV.get("PORTHUB_TEST_MONGO_URI", "").startswith("mongodb://127.0.0.1:"), "isolated loopback Mongo URI required"
artifacts = {}
for package, target, features in [("porthub-agent", "exit_worker", ["--features", "netns-tests"]), ("porthub-api", "exit_network", [])]:
    with tempfile.TemporaryFile(mode="w+") as output:
        build = subprocess.run([str(pathlib.Path.home()/".cargo/bin/cargo"), "test", "-p", package, *features, "--test", target, "--no-run", "--message-format=json"], cwd=ROOT, env=ENV, stdout=output)
        output.seek(0)
        messages = [json.loads(line) for line in output]
        if build.returncode:
            for item in messages:
                if item.get("reason") == "compiler-message": print(item["message"].get("rendered", ""))
            build.check_returncode()
        artifacts[target] = next(item["executable"] for item in messages if item.get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == target)
# Reject overlap with existing non-default host routes before creating bridges.
routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "table", "all"]))
subnets = ["198.18.10.0/24", "203.0.113.0/24"]
for subnet in subnets:
    candidate = ipaddress.ip_network(subnet)
    assert not any(route.get("dst") not in (None, "default") and candidate.overlaps(ipaddress.ip_network(route["dst"], strict=False)) for route in routes), f"test subnet {subnet} overlaps a host route"
prefix = "porthub-exit-test-" + secrets.token_hex(5)
networks = []
try:
    for suffix, subnet in zip(["control", "external"], subnets):
        name = prefix + "-" + suffix
        subprocess.run(["docker", "network", "create", "--internal", "--subnet", subnet, name], check=True, stdout=subprocess.DEVNULL)
        networks.append(name)
    environment = {**ENV, "PORTHUB_TEST_CONTROL_NETWORK": networks[0], "PORTHUB_TEST_EXTERNAL_NETWORK": networks[1], "PORTHUB_TEST_WORKER_BINARY": artifacts["exit_worker"]}
    subprocess.run([artifacts["exit_network"], "--ignored", "--exact", "native_agents_use_two_exits_and_preserve_established_tcp", "--nocapture"], cwd=ROOT, env=environment, check=True)
finally:
    for name in networks:
        # Only containers carrying this unique test network's generated name.
        names = subprocess.check_output(["docker", "ps", "-a", "--filter", f"name={name}-node-", "--format", "{{.Names}}"], text=True).splitlines()
        for container in names:
            if container.startswith(name + "-node-"): subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL)
    for name in reversed(networks): subprocess.run(["docker", "network", "rm", name], stdout=subprocess.DEVNULL)
