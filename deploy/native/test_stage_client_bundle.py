import hashlib
import pathlib
import tempfile
import unittest
from stage_client_bundle import stage
from migrate import ASSETS


class ImageBundleStaging(unittest.TestCase):
    def release(self, source, version):
        source.mkdir()
        for name in ASSETS:
            data = (name + version).encode()
            (source / name).write_bytes(data)
            (source / (name + ".version")).write_text(version + "\n")
            (source / (name + ".sha256")).write_text(hashlib.sha256(data).hexdigest() + "  " + name + "\n")

    def test_staging_replaces_the_old_release_without_retaining_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            old, new, destination = root / "old", root / "new", root / "client-bin"
            self.release(old, "1.1.1")
            self.release(new, "1.2.0")
            stage(old, destination, "1.1.1")
            stage(new, destination, "1.2.0")
            self.assertEqual(len(list(destination.iterdir())), 31)
            self.assertTrue(all(path.is_file() for path in destination.iterdir()))
            self.assertEqual({path.read_text().strip() for path in destination.glob("*.version")}, {"1.2.0"})
            self.assertFalse(list(root.glob(".previous-client-bundle-*")))
            self.assertFalse(list(root.glob(".client-bundle-*")))

    def test_invalid_or_incomplete_input_leaves_current_bundle_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, destination = root / "source", root / "client-bin"
            self.release(source, "1.2.0")
            stage(source, destination, "1.2.0")
            before = {path.name: path.read_bytes() for path in destination.iterdir()}
            with self.assertRaises(RuntimeError):
                stage(source, destination, "1.1.1")
            (source / "porthub-arm64.sha256").unlink()
            with self.assertRaises(RuntimeError):
                stage(source, destination, "1.2.0")
            self.assertEqual(before, {path.name: path.read_bytes() for path in destination.iterdir()})

    def test_unexpected_context_files_are_never_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, destination = root / "source", root / "client-bin"
            self.release(source, "1.2.0")
            destination.mkdir()
            (destination / "operator-file").write_text("keep")
            with self.assertRaises(RuntimeError):
                stage(source, destination, "1.2.0")
            self.assertEqual((destination / "operator-file").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
