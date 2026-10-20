import datetime
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bson import ObjectId
from fastapi import HTTPException
from pydantic import ValidationError
from router.auth import account_update


class NavigationPreferencesTest(unittest.IsolatedAsyncioTestCase):
    async def test_update_is_scoped_to_authenticated_account_and_nested_field(self):
        user_id = ObjectId()
        users = SimpleNamespace(update_one=AsyncMock(return_value=SimpleNamespace(matched_count=1)))
        with patch.object(account_update, "db", SimpleNamespace(users=users)), patch.object(account_update, "authenticate_user", return_value=str(user_id)):
            result = await account_update.update_preferences(account_update.NavigationPreferences(nav_collapsed=True), None)
        users.update_one.assert_awaited_once_with({"_id": user_id}, {"$set": {"preferences.nav_collapsed": True}})
        self.assertEqual(result, {"nav_collapsed": True})

    async def test_missing_account_is_reported(self):
        users = SimpleNamespace(update_one=AsyncMock(return_value=SimpleNamespace(matched_count=0)))
        with patch.object(account_update, "db", SimpleNamespace(users=users)), patch.object(account_update, "authenticate_user", return_value=str(ObjectId())):
            with self.assertRaises(HTTPException) as caught:
                await account_update.update_preferences(account_update.NavigationPreferences(nav_collapsed=False), None)
        self.assertEqual(caught.exception.status_code, 404)

    def test_legacy_default_and_saved_preferences_are_returned(self):
        user = {"name": "Test User", "username": "test@example.invalid", "role": "user", "created_at": datetime.datetime.now(datetime.timezone.utc)}
        self.assertFalse(account_update.serialize_user(user)["preferences"]["nav_collapsed"])
        user["preferences"] = {"nav_collapsed": True, "other_setting": "preserved"}
        self.assertTrue(account_update.serialize_user(user)["preferences"]["nav_collapsed"])

    def test_boolean_preference_rejects_ambiguous_strings(self):
        for value in ("false", "true", 0, 1, None):
            with self.assertRaises(ValidationError):
                account_update.NavigationPreferences(nav_collapsed=value)
