import unittest

import yaml

from shared.traffic_config import render_traffic_config


class TrafficConfigTest(unittest.TestCase):
    def routes(self, entry_points):
        return [{"_id": "abc", "hosts": ["algofly.in"], "target_mode": "manual", "target_url": "http://10.0.0.1:8071", "entry_points": entry_points}]

    def test_http_routes_also_answer_https(self):
        config = yaml.safe_load(render_traffic_config(self.routes(["web"]), "test"))
        routers = config["http"]["routers"]
        self.assertEqual(routers["porthub_traffic_abc"]["entryPoints"], ["web"])
        self.assertNotIn("tls", routers["porthub_traffic_abc"])
        secure = routers["porthub_traffic_abc_tls"]
        self.assertEqual(secure["entryPoints"], ["websecure"])
        self.assertEqual(secure["rule"], "Host(`algofly.in`)")
        self.assertEqual(secure["service"], "porthub_traffic_abc")
        self.assertEqual(secure["tls"], {})

    def test_explicit_websecure_route_gets_tls_once(self):
        routers = yaml.safe_load(render_traffic_config(self.routes(["web", "websecure"]), "test"))["http"]["routers"]
        self.assertEqual(set(routers), {"porthub_traffic_abc"})
        self.assertEqual(routers["porthub_traffic_abc"]["tls"], {})
