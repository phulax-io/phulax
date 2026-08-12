import uuid

from fastapi import APIRouter, Depends, HTTPException
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from sqlalchemy import select
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import Organization, Tool
from phulax_api.schemas import ToolCreate, ToolOut

router = APIRouter(prefix="/v1", tags=["tools"])


@router.post("/tools", response_model=ToolOut, status_code=201)
def register_tool(body: ToolCreate, db: Session = Depends(get_db)) -> Tool:
    if db.get(Organization, body.org_id) is None:
        raise HTTPException(status_code=404, detail="organization not found")
    try:
        Draft202012Validator.check_schema(body.args_schema)
    except SchemaError as exc:
        raise HTTPException(
            status_code=422, detail=f"args_schema is not a valid JSON Schema: {exc.message}"
        ) from exc
    duplicate = db.scalar(select(Tool).where(Tool.org_id == body.org_id, Tool.name == body.name))
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="tool already registered")
    tool = Tool(
        org_id=body.org_id,
        name=body.name,
        description=body.description,
        args_schema=body.args_schema,
        sensitivity=body.sensitivity,
        side_effect=body.side_effect,
        sensitive_fields=body.sensitive_fields,
    )
    db.add(tool)
    db.flush()
    return tool


@router.get("/tools", response_model=list[ToolOut])
def list_tools(
    org_id: uuid.UUID | None = None,
    name: str | None = None,
    db: Session = Depends(get_db),
):
    query = select(Tool)
    if org_id is not None:
        query = query.where(Tool.org_id == org_id)
    if name is not None:
        query = query.where(Tool.name == name)
    return db.scalars(query).all()
