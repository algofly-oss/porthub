import unittest
from unittest.mock import AsyncMock, patch
from types import SimpleNamespace
from bson import ObjectId
from pydantic import ValidationError
from router.traffic_routes.models.traffic_route import TrafficRoute
from router.traffic_routes import add, update
from shared.traffic_config import serialize_traffic_route_document


class ProxyGroupsTest(unittest.IsolatedAsyncioTestCase):
    def payload(self, **changes):
        return TrafficRoute(name="Docs", hosts=["docs.example.com"], targetUrl="http://localhost:8080", group=" Work ", **changes)

    async def test_group_saved_on_create(self):
        user_id, route_id = ObjectId(), ObjectId()
        routes = SimpleNamespace(insert_one=AsyncMock(return_value=SimpleNamespace(inserted_id=route_id)), find_one=AsyncMock(return_value={"_id": route_id, "user_id": user_id, "group": "Work"}))
        with patch.object(add, "db", SimpleNamespace(traffic_routes=routes)), patch.object(add, "get_authenticated_user", AsyncMock(return_value={"_id": user_id})), patch.object(add, "_find_conflicting_hosts", AsyncMock(return_value=[])), patch.object(add, "rebuild_traffic_config", AsyncMock()):
            result = await add.add_traffic_route(self.payload(), None)
        document = routes.insert_one.call_args.args[0]
        self.assertEqual(document["group"], "Work")
        self.assertEqual(document["user_id"], user_id)
        self.assertEqual(result["data"]["group"], "Work")

    async def test_update_preserves_user_ownership(self):
        user_id, route_id = ObjectId(), ObjectId()
        document = {"_id": route_id, "user_id": user_id, "group": "Work"}
        routes = SimpleNamespace(find_one=AsyncMock(return_value=document), update_one=AsyncMock())
        with patch.object(update, "db", SimpleNamespace(traffic_routes=routes)), patch.object(update, "get_authenticated_user", AsyncMock(return_value={"_id": user_id})), patch.object(update, "_find_conflicting_hosts", AsyncMock(return_value=[])), patch.object(update, "rebuild_traffic_config", AsyncMock()):
            await update.update_traffic_route(self.payload(data_id=str(route_id)), None)
        self.assertEqual(routes.find_one.call_args_list[0].args[0], {"_id": route_id, "user_id": user_id})
        self.assertEqual(routes.update_one.call_args.args[1]["$set"]["group"], "Work")

    def test_old_routes_and_group_validation(self):
        self.assertEqual(serialize_traffic_route_document({"_id": ObjectId(), "user_id": ObjectId()})["group"], "")
        with self.assertRaises(ValidationError):
            TrafficRoute(name="Docs", hosts=["docs.example.com"], targetUrl="http://localhost:8080", group="x" * 81)


if __name__ == "__main__":
    unittest.main()
