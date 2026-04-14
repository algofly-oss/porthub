from pydantic import BaseModel, IPvAnyAddress
from typing import List


class AllowRequest(BaseModel):
    ips: List[IPvAnyAddress]
