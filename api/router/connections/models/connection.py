import typing
import ipaddress
import re

from pydantic import BaseModel, Field, validator

try:
    from pydantic import ConfigDict
except ImportError:  # pragma: no cover - pydantic v1 fallback
    ConfigDict = None


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:localhost|(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))(?:\.(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)))*)$",
    re.IGNORECASE,
)

class Connection(BaseModel):
    if ConfigDict is not None:
        model_config = ConfigDict(populate_by_name=True)

    user_id: typing.Optional[str] = Field(None)
    data_id: typing.Optional[str] = Field(None)
    machine_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    service_name: str = Field(..., min_length=1, example="SSH")
    service_description: typing.Optional[str] = Field(
        "", example="Secure shell access for my homelab node"
    )
    internal_ip: str = Field("0.0.0.0", alias="internalIp", example="0.0.0.0")
    internal_port: int = Field(..., ge=1, le=65535, example=22)
    external_port: int = Field(..., ge=1, le=65535, example=54312)
    enabled: typing.Optional[bool] = Field(True, example=True)

    if ConfigDict is None:
        class Config:
            allow_population_by_field_name = True

    @validator("internal_ip", pre=True, always=True)
    def validate_internal_ip(cls, value):
        normalized = str(value or "0.0.0.0").strip()
        try:
            return str(ipaddress.IPv4Address(normalized))
        except ipaddress.AddressValueError as exc:
            if HOSTNAME_RE.fullmatch(normalized):
                return normalized.lower()
            raise ValueError("Use a valid internal IPv4 address or hostname") from exc
