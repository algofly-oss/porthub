from collections import defaultdict, deque


def init_port():
    return {"last_in": 0, "last_out": 0, "history": deque(maxlen=300)}


PORT_STATS = defaultdict(init_port)
ACTIVE_PORTS = {}
STATE = {}
