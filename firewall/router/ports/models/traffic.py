from typing import List

from pydantic import BaseModel, Field


class TrafficSnapshotRequest(BaseModel):
    ports: List[int] = Field(default_factory=list, example=[2334, 8080])
