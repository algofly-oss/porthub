import os
import unittest
from unittest.mock import patch

os.environ.setdefault("FW_API_KEY", "test-only")
from shared.sampler import record_snapshot, cleanup_ports, pending
from shared.state import PORT_STATS, ACTIVE_PORTS
from shared.env import BUFFER_SECONDS, ACTIVE_TTL
from router.ports.traffic import snapshot
from router.ports.models.traffic import TrafficSnapshotRequest


def counters(incoming, outgoing=0, blocked=0):
    return {"nftables": [{"counter": {"name": f"cnt_{key}_24000", "bytes": value}}
                         for key, value in (("in", incoming), ("out", outgoing), ("drop", blocked))]}


class TrafficSamplingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        PORT_STATS.clear()
        ACTIVE_PORTS.clear()
        pending.clear()

    def test_initial_cumulative_counters_are_a_baseline(self):
        record_snapshot(counters(10_000_000, 4_000_000), 1000, 10)
        self.assertEqual(list(PORT_STATS[24000]["history"]), [])
        record_snapshot(counters(10_000_100, 4_000_200, 20), 1001, 11)
        sample = PORT_STATS[24000]["history"][-1]
        self.assertEqual((sample["in_bytes"], sample["out_bytes"], sample["drop_bytes"]), (100, 200, 20))
        self.assertEqual(len(pending), 1)

    def test_idle_cleanup_keeps_counter_baselines(self):
        record_snapshot(counters(1000), 1000, 10)
        record_snapshot(counters(1100), 1001, 11)
        cleanup_ports(1002 + ACTIVE_TTL)
        self.assertNotIn(24000, ACTIVE_PORTS)
        self.assertIn(24000, PORT_STATS)
        record_snapshot(counters(1150), 1003 + ACTIVE_TTL, 13 + ACTIVE_TTL)
        self.assertEqual(PORT_STATS[24000]["history"][-1]["in_bytes"], 50)

    def test_counter_resets_do_not_generate_spikes(self):
        record_snapshot(counters(1_000_000), 1000, 10)
        record_snapshot(counters(0), 1001, 11)
        self.assertEqual(PORT_STATS[24000]["history"][-1]["in_bytes"], 0)
        record_snapshot(counters(100), 1002, 12)
        self.assertEqual(PORT_STATS[24000]["history"][-1]["in_bytes"], 100)

    async def test_full_window_and_snapshot_keep_all_directions(self):
        for second in range(BUFFER_SECONDS + 31):
            record_snapshot(counters(second * 100, second * 200, second * 5), 1000 + second, 10 + second)
        history = list(PORT_STATS[24000]["history"])
        self.assertEqual(len({sample["timestamp"] for sample in history}), len(history))
        self.assertGreaterEqual(history[-1]["timestamp"] - history[0]["timestamp"], BUFFER_SECONDS - 1)
        self.assertEqual((history[-1]["in_bytes"], history[-1]["out_bytes"]), (100, 200))
        with patch("router.ports.traffic.time.time", return_value=1000 + BUFFER_SECONDS + 30):
            result = await snapshot(TrafficSnapshotRequest(ports=[24000]))
        self.assertEqual(result["data"][24000][-1], history[-1])

    def test_slow_poll_preserves_volume_and_duration(self):
        record_snapshot(counters(100), 1000, 10)
        record_snapshot(counters(600), 1002, 12.5)
        sample = PORT_STATS[24000]["history"][-1]
        self.assertEqual(sample["in_bytes"], 500)
        self.assertEqual(sample["interval_seconds"], 2.5)

    def test_removed_ports_release_state(self):
        record_snapshot(counters(100), 1000, 10)
        record_snapshot({"nftables": []}, 1001, 11)
        self.assertNotIn(24000, PORT_STATS)

    def test_scheduler_jitter_in_the_same_wall_second_combines_duration(self):
        record_snapshot(counters(1000), 1000, 10)
        record_snapshot(counters(1100), 1001, 11)
        record_snapshot(counters(1200), 1001, 12)
        history = list(PORT_STATS[24000]["history"])
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["in_bytes"], 200)
        self.assertEqual(history[0]["interval_seconds"], 2)

    def test_ips_are_read_from_the_matching_set_in_the_same_snapshot(self):
        record_snapshot(counters(100), 1000, 10)
        payload = counters(200, 100)
        payload["nftables"] += [{"set": {"name": name, "elem": [ip]}} for name, ip in
                                (("recent_24000", "192.0.2.1"), ("recent_out_24000", "192.0.2.2"), ("recent_25000", "192.0.2.3"))]
        record_snapshot(payload, 1001, 11)
        sample = PORT_STATS[24000]["history"][-1]
        self.assertEqual(sample["incoming_ips"], ["192.0.2.1"])
        self.assertEqual(sample["outgoing_ips"], ["192.0.2.2"])
