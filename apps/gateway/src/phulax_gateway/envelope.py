"""The request envelope (plan §7.1) — everything downstream consumes it."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ActionEnvelope(BaseModel):
    request_id: uuid.UUID
    # The whole-story correlator (plan §11.3): reuse one trace_id across a
    # request → approval → retry cycle and the timeline reconstructs it.
    trace_id: uuid.UUID | None = None
    idempotency_key: str | None = None
    agent_id: uuid.UUID
    agent_version: str
    session_id: uuid.UUID
    acting_user_id: uuid.UUID | None = None
    environment: str = Field(min_length=1, max_length=50)
    tool_name: str = Field(min_length=1, max_length=200)
    arguments: dict = Field(default_factory=dict)
    requested_at: datetime
    context: dict = Field(default_factory=dict)
