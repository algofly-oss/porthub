from collections import defaultdict, deque
from .env import BUFFER_SECONDS


def init_port():
    return {"last_in": None, "last_out": None, "last_drop": None,
            "sampled_at": None, "history": deque(maxlen=BUFFER_SECONDS + 2)}


PORT_STATS = defaultdict(init_port)
ACTIVE_PORTS = {}
STATE = {}
