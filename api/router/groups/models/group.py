from pydantic import BaseModel, Field


class MachineGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, example="Production")


class MachineGroupUpdate(BaseModel):
    data_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, example="Production")


class MachineGroupDelete(BaseModel):
    data_id: str = Field(..., min_length=1)
