import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from shared.proxy_activity import read_batch, apply_records, collect_proxy_activity
from shared import proxy_activity as collector
from router.traffic_routes import activity


class ProxyActivityTest(unittest.IsolatedAsyncioTestCase):
    def line(self, host="docs.example.com", stamp="2026-10-20T10:00:00Z"):
        return json.dumps({"RequestHost": host, "StartUTC": stamp, "RouterName": "route@file", "ClientHost": "private", "RequestPath": "/secret"}) + "\n"

    def test_first_run_skips_history_then_reads_only_complete_new_records(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "access.log"
            path.write_text(self.line())
            identity, offset, rows = read_batch(path, None)
            self.assertEqual(rows, [])
            state = {"identity": identity, "offset": offset}
            with path.open("a") as target:
                target.write(self.line() + self.line()[:-1])
            _, next_offset, rows = read_batch(path, state)
            self.assertEqual(len(rows), 1)
            with path.open("a") as target:
                target.write("\n")
            self.assertEqual(len(read_batch(path, {"identity": identity, "offset": next_offset})[2]), 1)

    def test_rotation_missing_files_and_malformed_lines(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "access.log"
            self.assertIsNone(read_batch(path, None))
            path.write_text(self.line())
            identity, offset, _ = read_batch(path, None)
            path.rename(Path(root) / "old.log")
            path.write_text("bad json\n" + self.line())
            self.assertEqual(len(read_batch(path, {"identity": identity, "offset": offset})[2]), 1)

    def test_traefik_fractional_timestamps_work_on_python_310(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"access.log"
            path.write_text("".join(self.line(stamp=f"2026-10-20T10:00:00.{fraction}Z") for fraction in ["1","1234","123456789"]))
            stat=path.stat()
            rows=read_batch(path,{"identity":f"{stat.st_dev}:{stat.st_ino}","offset":0})[2]
            self.assertEqual(len(rows),3)
            self.assertEqual(rows[-1][1],"2026-10-20T10:00:00.123456+00:00")

    def test_unread_rotated_segment_is_drained_before_new_log(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "access.log"
            path.write_text(self.line())
            identity, offset, _ = read_batch(path, None)
            with path.open("a") as target:
                target.write(self.line("wiki.example.com"))
            path.rename(Path(str(path)+".1"))
            path.write_text(self.line("new.example.com"))
            old_identity, old_end, old_rows=read_batch(path,{"identity":identity,"offset":offset})
            self.assertEqual(old_rows[0][0],"wiki.example.com")
            new_identity, _, new_rows=read_batch(path,{"identity":old_identity,"offset":old_end})
            self.assertNotEqual(new_identity,old_identity)
            self.assertEqual(new_rows[0][0],"new.example.com")

    def test_aliases_aggregate_only_registered_hosts_without_private_log_data(self):
        routes = [{"_id": "a", "hosts": ["docs.example.com", "wiki.example.com"]}]
        result = apply_records({}, [("docs.example.com", "2026-10-20T10:00:00+00:00"), ("wiki.example.com", "2026-10-20T11:00:00+00:00"), ("other.example.com", "later")], routes)
        self.assertEqual(result["a"]["requests"], 2)
        self.assertEqual(result["a"]["last_host"], "wiki.example.com")
        self.assertEqual(set(result["a"]), {"requests", "last_requested_at", "last_host"})
        self.assertEqual(apply_records(result, [], []), {})

    async def test_checkpoint_and_counts_use_one_compare_and_swap_update(self):
        state = {"_id": collector.STATE_ID, "identity": "old", "offset": 0, "revision": 9, "metrics": {}}
        storage = SimpleNamespace(find_one=AsyncMock(return_value=state), update_one=AsyncMock())
        routes = SimpleNamespace(find=lambda *args: SimpleNamespace(to_list=AsyncMock(return_value=[{"_id":"a","hosts":["docs.example.com"]}])))
        with patch.object(collector, "db", SimpleNamespace(proxy_activity=storage, traffic_routes=routes)), patch.object(collector, "read_batch", return_value=("new", 120, [("docs.example.com", "2026-10-20T10:00:00+00:00")])):
            await collect_proxy_activity()
        query, update = storage.update_one.call_args.args
        self.assertEqual(query["revision"], 9)
        self.assertEqual(update["$set"]["offset"], 120)
        self.assertEqual(update["$set"]["metrics"]["a"]["requests"], 1)
        self.assertEqual(update["$inc"], {"revision":1})

    async def test_endpoint_returns_only_authenticated_accounts_proxy_ids(self):
        find = AsyncMock(return_value={"metrics":{"owned":{"requests":2},"other":{"requests":999}},"tracking_since":"now"})
        routes = SimpleNamespace(find=lambda query, fields: SimpleNamespace(to_list=AsyncMock(return_value=[{"_id":"owned"}])) if query=={"user_id":"user"} else self.fail("Missing owner filter"))
        with patch.object(activity,"db",SimpleNamespace(proxy_activity=SimpleNamespace(find_one=find),traffic_routes=routes)), patch.object(activity,"get_authenticated_user",AsyncMock(return_value={"_id":"user"})):
            result=await activity.proxy_activity(None)
        self.assertEqual(result["data"],[{"route_id":"owned","requests":2}])
