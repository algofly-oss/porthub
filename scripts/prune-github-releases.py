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


def plan(releases, tags, keep, protected=(), remove_previews=False):
    current = version(keep)
    if current is None:
        raise ValueError("The kept release must have a version tag")
    protected = set(protected) | {keep}
    old = lambda tag: tag not in protected and version(tag) is not None and version(tag) <= current
    preview = lambda release: remove_previews and release["tag_name"] not in protected and (release.get("draft") or release.get("prerelease"))
    selected = [release for release in releases if old(release["tag_name"]) or preview(release)]
    preview_tags = {release["tag_name"] for release in selected if preview(release)}
    order = lambda tag: (version(tag) or (-1, -1, -1), tag)
    return sorted(selected, key=lambda release: order(release["tag_name"])), sorted(
        (tag for tag in tags if tag not in protected and (old(tag) or tag in preview_tags)), key=order)


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


def prune(github, keep, expected_commit, execute=False, protected=(), remove_previews=False):
    validate_latest(github.api("/releases/latest"), keep)
    if github.commit(keep) != expected_commit:
        raise ValueError("Kept tag does not match the verified release commit")
    all_tags = [tag["name"] for tag in github.pages("/tags?per_page=100")]
    releases, tags = plan(github.pages("/releases?per_page=100"), all_tags, keep, protected, remove_previews)
    tagless_drafts = {release["tag_name"] for release in releases if release.get("draft") and release["tag_name"] not in all_tags}
    previews = {release["tag_name"] for release in releases if release.get("draft") or release.get("prerelease")}
    branches = None
    # Deleting a tag must not make an old release's source unreachable. Every
    # retired release commit must remain in the kept release's Git history.
    for tag in sorted(set(tags) | {r["tag_name"] for r in releases}):
        if tag in tagless_drafts:
            # Removing draft metadata does not delete a Git ref or source tag.
            continue
        commit = github.commit(tag)
        if not github.contains_commit(commit, expected_commit):
            if tag in previews:
                if branches is None:
                    branches = github.pages("/branches?per_page=100")
                reachable = any(github.contains_commit(commit, branch["commit"]["sha"]) for branch in branches)
            else:
                reachable = False
            if not reachable:
                raise ValueError("Older release source is not retained in the kept history or a source branch: " + tag)
        print("Retained source:", tag, commit)
    print("Keep:", keep)
    print("Explicitly protected tags:", ", ".join(sorted(set(protected))) or "none")
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
    parser.add_argument("--protect", action="append", default=[], help="Preserve an explicitly requested tag and its release")
    parser.add_argument("--remove-previews", action="store_true", help="Remove unprotected draft/prerelease metadata and tags while retaining their source")
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[a-f0-9]{40}", args.expected_commit):
        parser.error("An explicit repository and full verified commit SHA are required")
    protected = set(args.protect) | set(filter(None, re.split(r"[,\s]+", os.environ.get("PORTHUB_RETAIN_TAGS", ""))))
    prune(GitHub(args.repository), args.keep, args.expected_commit, args.execute, protected, args.remove_previews)


if __name__ == "__main__":
    main()
