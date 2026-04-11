from pydantic import BaseModel, Field
import typing

class Connection(BaseModel):
    user_id: typing.Optional[str] = Field(None)
    data_id: typing.Optional[str] = Field(None)
    machine_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    service_name: str = Field(..., min_length=1, example="SSH")
    service_description: typing.Optional[str] = Field(
        "", example="Secure shell access for my homelab node"
    )
    internal_port: int = Field(..., ge=1, le=65535, example=22)
    external_port: int = Field(..., ge=1, le=65535, example=54312)
    enabled: typing.Optional[bool] = Field(True, example=True)
