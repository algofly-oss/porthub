import hashlib
from pathlib import Path
import tempfile
import unittest
from collect_client_bundle import collect
from migrate import ASSETS


class ClientCollection(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.source = Path(self.temp)/'artifacts'; self.source.mkdir()
        self.destination = Path(self.temp)/'clients'
        for name in ASSETS:
            directory = self.source/name.removesuffix('.exe'); directory.mkdir()
            payload = ('fixture '+name).encode()
            (directory/name).write_bytes(payload)
            (directory/(name+'.version')).write_text('1.9.0\n')
            (directory/(name+'.sha256')).write_text(hashlib.sha256(payload).hexdigest()+'  '+name+'\n')
    def test_server_artifacts_and_records_cannot_pollute_client_bundle(self):
        server = self.source/'porthub-server-arm64'; server.mkdir()
        (server/'porthub-api').write_text('server binary')
        record = self.source/'porthub-release-bundle'; record.mkdir()
        names = collect(self.source,self.destination,'1.9.0')
        self.assertEqual(len(names),30)
        self.assertEqual(set(names),{name+suffix for name in ASSETS for suffix in ('','.version','.sha256')})
    def test_mixed_version_or_bad_checksum_fails_before_writing(self):
        directory = self.source/'porthub-x86_64'
        version = directory/'porthub-x86_64.version'; version.write_text('1.8.9\n')
        with self.assertRaises(RuntimeError):collect(self.source,self.destination,'1.9.0')
        self.assertFalse(self.destination.exists())
        version.write_text('1.9.0\n')
        (directory/'porthub-x86_64').write_text('corrupt')
        with self.assertRaises(RuntimeError):collect(self.source,self.destination,'1.9.0')
        self.assertFalse(self.destination.exists())
    def test_extra_platform_file_or_missing_platform_is_rejected(self):
        extra = self.source/'porthub-x86_64'/'unexpected'; extra.touch()
        with self.assertRaises(RuntimeError):collect(self.source,self.destination,'1.9.0')
        extra.unlink()
        directory = self.source/'porthub-x86_64'; directory.rename(self.source/'unrelated')
        with self.assertRaises(RuntimeError):collect(self.source,self.destination,'1.9.0')
    def test_existing_destination_is_not_overwritten(self):
        self.destination.mkdir(); sentinel=self.destination/'keep';sentinel.write_text('unchanged')
        with self.assertRaises(RuntimeError):collect(self.source,self.destination,'1.9.0')
        self.assertEqual(sentinel.read_text(),'unchanged')


if __name__=='__main__':unittest.main()
