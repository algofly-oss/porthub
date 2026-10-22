#!/usr/bin/env python3
"""Compare the Go API with the Python API, request by request.

Usage: parity.py PYTHON_BASE GO_BASE SESSION_TOKEN [COOKIE_NAME]
Each case is sent to both; status and JSON body must match (volatile fields
such as access times are ignored). Add cases as route groups are ported.
"""
import json
import sys
import urllib.request

py_base, go_base, token = sys.argv[1:4]
cookie = sys.argv[4] if len(sys.argv) > 4 else "porthub_session"
VOLATILE = {"last_accessed_at", "latency"}

CASES = [
    ("GET", "/api/auth/settings", None, True),
    ("GET", "/api/auth/me", None, True),
    ("GET", "/api/auth/me", None, False),
    ("GET", "/api/auth/sessions", None, True),
    ("POST", "/api/auth/signin", {"username": "nobody@example.com", "password": "x"}, False),
    ("POST", "/api/auth/signin", {"username": "x"}, False),
    # Intended difference: pydantic v1 coerced 5 -> "5"; Go rejects the wrong type (422).
    ("POST", "/api/auth/signout", None, False),
    ("DELETE", "/api/auth/sessions/does-not-exist", None, True),
    ("PUT", "/api/auth/settings/password", {"current_password": "wrong", "new_password": "Xx1!xxxxx"}, True),
    ("DELETE", "/api/auth/delete", {"username": "nobody@example.com", "password": "x"}, False),
    ("GET", "/api/machines/list", None, True),
]


def call(base, method, path, body, auth):
    headers = {"Content-Type": "application/json", "User-Agent": "parity"}
    if auth:
        headers["Cookie"] = f"{cookie}={token}"
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        return status, raw[:200]


def strip(value):
    if isinstance(value, dict):
        return {k: strip(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [strip(v) for v in value]
    return value


failed = 0
for method, path, body, auth in CASES:
    py, go = call(py_base, method, path, body, auth), call(go_base, method, path, body, auth)
    same = py[0] == go[0] and strip(py[1]) == strip(go[1])
    failed += not same
    print(("SAME" if same else "DIFF"), method, path, f"auth={auth}", f"python={py[0]} go={go[0]}")
    if not same:
        print("   python:", json.dumps(py[1])[:400])
        print("   go:    ", json.dumps(go[1])[:400])
print(f"{len(CASES) - failed}/{len(CASES)} identical")
sys.exit(1 if failed else 0)
