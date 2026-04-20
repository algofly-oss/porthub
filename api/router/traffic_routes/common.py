from shared.traffic_config import serialize_traffic_route_document


def serialize_traffic_route(route: dict) -> dict:
    return serialize_traffic_route_document(route)
