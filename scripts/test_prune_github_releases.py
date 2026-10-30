import contextlib
import io
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("retention", pathlib.Path(__file__).with_name("prune-github-releases.py"))
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


class Fake:
    def __init__(self):
        self.latest = {"tag_name": "v1.8.5", "draft": False, "prerelease": False}
        self.deleted = []
        self.change_after_delete = False
        self.reachable = True

    def api(self, path, method="GET"):
        if method == "DELETE":
            self.deleted.append(path)
            if self.change_after_delete:
                self.latest = dict(self.latest, tag_name="v1.8.6")
            return
        assert path == "/releases/latest"
        return self.latest

    def pages(self, path):
        if path.startswith("/releases"):
            return [{"id": 1, "tag_name": "v1.8.3"}, {"id": 2, "tag_name": "v1.8.4"}, {"id": 3, "tag_name": "v1.8.5"}]
        return [{"name": t} for t in ["v1.8.3", "v1.8.4", "v1.8.5", "v1.8.6", "experiment"]]

    def contains_commit(self, older, current):
        return self.reachable

    def commit(self, tag):
        return "a" * 40


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def test_paginated_arrays_work_with_older_gh(self):
        with patch.object(retention.subprocess, "run") as run:
            run.return_value.stdout = '[{"name":"v1.8.5"}]\n[{"name":"v1.8.4"}]\n'
            self.assertEqual(retention.GitHub("owner/repo").pages("/tags"),
                             [{"name": "v1.8.5"}, {"name": "v1.8.4"}])

    def test_only_older_versions_are_selected(self):
        releases, tags = retention.plan([{"tag_name": t} for t in ["v1.8.4", "v1.8.5", "v1.8.10", "notes"]], ["v1.8.4", "v1.8.5", "v1.8.10", "experiment"], "v1.8.5")
        self.assertEqual([r["tag_name"] for r in releases], ["v1.8.4"])
        self.assertEqual(tags, ["v1.8.4"])

    def test_dry_run_does_not_delete(self):
        github = Fake()
        retention.prune(github, "v1.8.5", "a" * 40)
        self.assertEqual(github.deleted, [])

    def test_verified_cleanup_deletes_old_releases_and_version_tags(self):
        github = Fake()
        retention.prune(github, "v1.8.5", "a" * 40, True)
        self.assertEqual(github.deleted, ["/releases/1", "/releases/2", "/git/refs/tags/v1.8.3", "/git/refs/tags/v1.8.4"])

    def test_changed_latest_aborts_before_further_deletions(self):
        github = Fake()
        github.change_after_delete = True
        with self.assertRaises(ValueError):
            retention.prune(github, "v1.8.5", "a" * 40, True)
        self.assertEqual(github.deleted, ["/releases/1"])

    def test_unmerged_old_source_is_preserved_before_any_deletion(self):
        github = Fake()
        github.reachable = False
        with self.assertRaises(ValueError):
            retention.prune(github, "v1.8.5", "a" * 40, True)
        self.assertEqual(github.deleted, [])

    def test_wrong_commit_or_unpublished_keep_cannot_delete_anything(self):
        for changed in ("commit", "draft", "prerelease", "tag_name"):
            github = Fake()
            expected = "b" * 40 if changed == "commit" else "a" * 40
            if changed in ("draft", "prerelease"):
                github.latest[changed] = True
            elif changed == "tag_name":
                github.latest[changed] = "v1.8.6"
            with self.assertRaises(ValueError):
                retention.prune(github, "v1.8.5", expected, True)
            self.assertEqual(github.deleted, [])


if __name__ == "__main__":
    unittest.main()
