import typing

from pydantic import BaseModel, Field


class Machine(BaseModel):
    data_id: typing.Optional[str] = Field(None)
    name: str = Field(..., min_length=1, example="luna")
    hostname: typing.Optional[str] = Field("", example="luna.local")
    is_active: typing.Optional[bool] = Field(False, example=False)


class MachineSync(BaseModel):
    machine_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    token: str = Field(..., min_length=1)
    hostname: typing.Optional[str] = Field("", example="luna.local")
    local_ip: typing.Optional[str] = Field("", example="192.168.0.3")
    public_ip: typing.Optional[str] = Field("", example="203.0.113.25")
    is_active: typing.Optional[bool] = Field(True, example=True)
