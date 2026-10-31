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

    def test_explicit_protection_applies_to_stable_and_preview_tags(self):
        releases = [{"id": 1, "tag_name": "v1.8.4"},
                    {"id": 2, "tag_name": "v1.9.0-rc.1", "prerelease": True},
                    {"id": 3, "tag_name": "preview-unused", "draft": True}]
        selected, tags = retention.plan(releases, [r["tag_name"] for r in releases], "v1.8.5",
                                        {"v1.8.4", "v1.9.0-rc.1"}, True)
        self.assertEqual([r["tag_name"] for r in selected], ["preview-unused"])
        self.assertEqual(tags, ["preview-unused"])

    def test_protected_old_release_and_tag_are_not_deleted(self):
        github = Fake()
        retention.prune(github, "v1.8.5", "a" * 40, True, {"v1.8.4"})
        self.assertEqual(github.deleted, ["/releases/1", "/git/refs/tags/v1.8.3"])

    def test_unused_tagless_draft_deletes_metadata_without_resolving_a_nonexistent_tag(self):
        class Draft(Fake):
            def pages(self, path):
                if path.startswith("/releases"):
                    return super().pages(path) + [{"id": 4, "tag_name": "preview-unused", "draft": True}]
                return super().pages(path)
            def commit(self, tag):
                if tag == "preview-unused":
                    raise AssertionError("tagless draft has no source ref to delete")
                return super().commit(tag)
        github = Draft()
        retention.prune(github, "v1.8.5", "a" * 40, True, remove_previews=True)
        self.assertIn("/releases/4", github.deleted)
        self.assertNotIn("/git/refs/tags/preview-unused", github.deleted)

    def test_unmerged_preview_source_must_remain_on_a_branch(self):
        class Preview(Fake):
            def pages(self, path):
                if path.startswith("/branches"):
                    return [{"name": "feature", "commit": {"sha": "c" * 40}}]
                if path.startswith("/releases"):
                    return super().pages(path) + [{"id": 4, "tag_name": "v1.9.0-rc.1", "prerelease": True}]
                return super().pages(path) + [{"name": "v1.9.0-rc.1"}]
            def commit(self, tag):
                return "b" * 40 if tag == "v1.9.0-rc.1" else super().commit(tag)
            def contains_commit(self, older, current):
                return older != "b" * 40 or current == "c" * 40 and self.reachable
        github = Preview()
        retention.prune(github, "v1.8.5", "a" * 40, True, remove_previews=True)
        self.assertIn("/releases/4", github.deleted)
        self.assertIn("/git/refs/tags/v1.9.0-rc.1", github.deleted)
        self.assertFalse(any("/heads/" in path for path in github.deleted))
        github = Preview()
        github.reachable = False
        with self.assertRaisesRegex(ValueError, "source"):
            retention.prune(github, "v1.8.5", "a" * 40, True, remove_previews=True)
        self.assertEqual(github.deleted, [])
        retention.prune(github, "v1.8.5", "a" * 40, True, {"v1.9.0-rc.1"}, True)
        self.assertNotIn("/releases/4", github.deleted)

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
