def serialize_machine_group(group: dict) -> dict:
    return {
        "_id": str(group["_id"]),
        "user_id": str(group["user_id"]),
        "name": group.get("name", ""),
        "sort_order": group.get("sort_order", 0),
        "created_at": group.get("created_at"),
        "updated_at": group.get("updated_at"),
    }
