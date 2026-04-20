import typing

from pydantic import BaseModel, Field, validator
import re

try:
    from pydantic import ConfigDict
except ImportError:  # pragma: no cover - pydantic v1 fallback
    ConfigDict = None

try:
    from pydantic import model_validator
except ImportError:  # pragma: no cover - pydantic v1 fallback
    model_validator = None

if model_validator is None:  # pragma: no cover - pydantic v1 fallback
    from pydantic import root_validator
else:  # pragma: no cover - pydantic v2 path
    root_validator = None

from router.connections.models.connection import HOSTNAME_RE

TARGET_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
HTTP_TARGET_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


class TrafficRoute(BaseModel):
    if ConfigDict is not None:
        model_config = ConfigDict(populate_by_name=True)

    user_id: typing.Optional[str] = Field(None)
    data_id: typing.Optional[str] = Field(None)
    name: str = Field(..., min_length=1, example="Primary Docs Route")
    description: typing.Optional[str] = Field(
        "", example="Routes docs.example.com traffic to the internal docs server"
    )
    hosts: list[str] = Field(
        default_factory=list,
        example=["example.com", "docs.example.com"],
    )
    target_mode: str = Field("manual", alias="targetMode", example="connection")
    target_url: typing.Optional[str] = Field(
        None,
        alias="targetUrl",
        example="http://127.0.0.1:18080",
    )
    entry_points: list[str] = Field(
        default_factory=lambda: ["web"],
        alias="entryPoints",
        example=["web"],
    )
    enabled: typing.Optional[bool] = Field(True, example=True)
    connection_data_id: typing.Optional[str] = Field(
        None,
        alias="connectionDataId",
        example="67f7d26b760bd71f4d3f3c34",
    )

    if ConfigDict is None:
        class Config:
            allow_population_by_field_name = True

    @validator("hosts", pre=True, always=True)
    def validate_hosts(cls, value):
        items = value or []
        normalized: list[str] = []
        seen: set[str] = set()
        for item in items:
            host = str(item or "").strip().lower()
            if not host:
                continue
            if not HOSTNAME_RE.fullmatch(host):
                raise ValueError(f"Invalid host: {host}")
            if host not in seen:
                seen.add(host)
                normalized.append(host)

        if not normalized:
            raise ValueError("At least one host is required")

        return normalized

    @validator("entry_points", pre=True, always=True)
    def validate_entry_points(cls, value):
        items = value or ["web"]
        normalized: list[str] = []
        seen: set[str] = set()
        for item in items:
            entry_point = str(item or "").strip()
            if not entry_point:
                continue
            if entry_point not in seen:
                seen.add(entry_point)
                normalized.append(entry_point)

        if not normalized:
            return ["web"]
        return normalized

    @validator("target_mode", pre=True, always=True)
    def validate_target_mode(cls, value):
        normalized = str(value or "manual").strip().lower()
        if normalized not in {"manual", "connection"}:
            raise ValueError("target_mode must be either manual or connection")
        return normalized

    @validator("target_url", pre=True, always=True)
    def validate_target_url(cls, value):
        if value in (None, ""):
            return None

        normalized = str(value).strip()
        if not TARGET_SCHEME_RE.match(normalized):
            raise ValueError("target_url must include a scheme like http:// or tcp://")
        return normalized

    if model_validator is not None:
        @model_validator(mode="after")
        def validate_mode_requirements(self):
            if self.target_mode == "connection" and not (self.connection_data_id or "").strip():
                raise ValueError("connectionDataId is required when targetMode is connection")
            if self.target_mode == "manual" and not (self.target_url or "").strip():
                raise ValueError("targetUrl is required when targetMode is manual")
            if self.target_mode == "manual" and not HTTP_TARGET_SCHEME_RE.match(str(self.target_url or "").strip()):
                raise ValueError("targetUrl must use http:// or https:// when targetMode is manual")
            if self.target_mode == "connection" and not (self.target_url or "").strip():
                raise ValueError("targetUrl is required when targetMode is connection")
            return self
    else:
        @root_validator(skip_on_failure=True)
        def validate_mode_requirements(cls, values):
            target_mode = str(values.get("target_mode") or "manual").strip().lower()
            target_url = str(values.get("target_url") or "").strip()
            connection_data_id = str(values.get("connection_data_id") or "").strip()

            if target_mode == "connection" and not connection_data_id:
                raise ValueError("connectionDataId is required when targetMode is connection")
            if target_mode == "manual" and not target_url:
                raise ValueError("targetUrl is required when targetMode is manual")
            if target_mode == "manual" and not HTTP_TARGET_SCHEME_RE.match(target_url):
                raise ValueError("targetUrl must use http:// or https:// when targetMode is manual")
            if target_mode == "connection" and not target_url:
                raise ValueError("targetUrl is required when targetMode is connection")

            return values

    def normalized_hosts(self) -> list[str]:
        return [str(host).strip().lower() for host in (self.hosts or []) if str(host).strip()]

    def normalized_target_url(self) -> str:
        return str(self.target_url or "").strip()

    def normalized_entry_points(self) -> list[str]:
        return [str(entry_point).strip() for entry_point in (self.entry_points or []) if str(entry_point).strip()] or ["web"]


class TrafficRouteDelete(BaseModel):
    data_id: str = Field(..., alias="data_id", example="67f7d26b760bd71f4d3f3c34")
