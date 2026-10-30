#!/usr/bin/env python3
"""Retain the latest verified version release/tag; keep Git history intact."""
import argparse
import json
import os
import re
import subprocess
from urllib.parse import quote

VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")


def version(tag):
    match = VERSION.fullmatch(tag)
    return tuple(map(int, match.groups())) if match else None


def plan(releases, tags, keep):
    current = version(keep)
    if current is None:
        raise ValueError("The kept release must have a version tag")
    old = lambda tag: tag != keep and version(tag) is not None and version(tag) <= current
    releases = sorted((r for r in releases if old(r["tag_name"])), key=lambda r: version(r["tag_name"]))
    return releases, sorted((t for t in tags if old(t)), key=version)


def validate_latest(latest, keep):
    if latest.get("tag_name") != keep or latest.get("draft") or latest.get("prerelease"):
        raise ValueError("Refusing cleanup: the kept release is not the latest published stable release")


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
            raise ValueError("Invalid GitHub repository")
        self.prefix = "repos/" + repository

    def api(self, suffix, method="GET"):
        result = subprocess.run(["gh", "api", "--method", method, self.prefix + suffix], check=True, capture_output=True, text=True)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def pages(self, suffix):
        result = subprocess.run(["gh", "api", "--paginate", self.prefix + suffix], check=True, capture_output=True, text=True)
        # Older gh versions emit concatenated JSON arrays without --slurp.
        remaining = result.stdout.strip()
        items = []
        decoder = json.JSONDecoder()
        while remaining:
            page, end = decoder.raw_decode(remaining)
            if not isinstance(page, list):
                raise ValueError("Expected a GitHub list response")
            items.extend(page)
            remaining = remaining[end:].lstrip()
        return items

    def contains_commit(self, older, current):
        return self.api("/compare/" + older + "..." + current)["status"] in ("ahead", "identical")

    def commit(self, tag):
        obj = self.api("/git/ref/tags/" + quote(tag, safe=""))["object"]
        for _ in range(4):
            if obj["type"] == "commit":
                return obj["sha"]
            if obj["type"] != "tag":
                break
            obj = self.api("/git/tags/" + obj["sha"])["object"]
        raise ValueError("Release tag does not resolve to a commit")


def prune(github, keep, expected_commit, execute=False):
    validate_latest(github.api("/releases/latest"), keep)
    if github.commit(keep) != expected_commit:
        raise ValueError("Kept tag does not match the verified release commit")
    releases, tags = plan(github.pages("/releases?per_page=100"), [t["name"] for t in github.pages("/tags?per_page=100")], keep)
    # Deleting a tag must not make an old release's source unreachable. Every
    # retired release commit must remain in the kept release's Git history.
    for tag in sorted(set(tags) | {r["tag_name"] for r in releases}):
        commit = github.commit(tag)
        if not github.contains_commit(commit, expected_commit):
            raise ValueError("Older release source is not retained in the kept history: " + tag)
        print("Retained source:", tag, commit)
    print("Keep:", keep)
    print("Older releases:", ", ".join(r["tag_name"] for r in releases) or "none")
    print("Older version tags:", ", ".join(tags) or "none")
    if not execute:
        print("Dry run; no release or tag deleted")
        return
    for release in releases:
        validate_latest(github.api("/releases/latest"), keep)
        github.api("/releases/" + str(int(release["id"])), "DELETE")
        print("Deleted release:", release["tag_name"])
    for tag in tags:
        validate_latest(github.api("/releases/latest"), keep)
        github.api("/git/refs/tags/" + quote(tag, safe=""), "DELETE")
        print("Deleted version tag:", tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--keep", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[a-f0-9]{40}", args.expected_commit):
        parser.error("An explicit repository and full verified commit SHA are required")
    prune(GitHub(args.repository), args.keep, args.expected_commit, args.execute)


if __name__ == "__main__":
    main()
