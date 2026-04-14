from ipaddress import IPv4Address
from typing import List

from pydantic import BaseModel, Field

try:
    from pydantic import model_validator
except ImportError:  # pragma: no cover - pydantic v1 fallback
    model_validator = None

if model_validator is None:  # pragma: no cover - pydantic v1 fallback
    from pydantic import root_validator
else:  # pragma: no cover - pydantic v2 path
    root_validator = None


class ConnectionFirewallPolicy(BaseModel):
    data_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    is_public: bool = Field(True, example=True)
    allowed_ips: List[IPv4Address] = Field(default_factory=list, example=["203.0.113.10"])

    if model_validator is not None:
        @model_validator(mode="after")
        def validate_policy(self):
            if self.is_public and self.allowed_ips:
                raise ValueError("allowed_ips must be empty when is_public is true")
            return self
    else:
        @root_validator(skip_on_failure=True)
        def validate_policy(cls, values):
            is_public = bool(values.get("is_public", True))
            allowed_ips = values.get("allowed_ips") or []
            if is_public and allowed_ips:
                raise ValueError("allowed_ips must be empty when is_public is true")
            return values


class ConnectionTrafficSnapshotRequest(BaseModel):
    data_ids: List[str] = Field(default_factory=list)
