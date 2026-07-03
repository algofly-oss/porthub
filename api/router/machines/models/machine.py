import typing

from pydantic import BaseModel, Field


class Machine(BaseModel):
    data_id: typing.Optional[str] = Field(None)
    name: str = Field(..., min_length=1, example="luna")
    hostname: typing.Optional[str] = Field("", example="luna.local")
    enabled: typing.Optional[bool] = Field(None, example=True)
    is_active: typing.Optional[bool] = Field(None, example=False)
    client_setup_public_base_url: typing.Optional[str] = Field(
        None,
        example="https://porthub.example.com",
    )
    client_setup_rathole_server_address: typing.Optional[str] = Field(
        None,
        example="rathole.example.com:2334",
    )
    client_setup_service_domain: typing.Optional[str] = Field(
        None,
        example="services.example.com",
    )
    group_ids: typing.Optional[typing.List[str]] = Field(
        None,
        example=["67f7d26b760bd71f4d3f3c34"],
    )


class MachineSync(BaseModel):
    machine_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    token: str = Field(..., min_length=1)
    hostname: typing.Optional[str] = Field("", example="luna.local")
    local_ip: typing.Optional[str] = Field("", example="192.168.0.3")
    public_ip: typing.Optional[str] = Field("", example="203.0.113.25")
    is_active: typing.Optional[bool] = Field(True, example=True)
