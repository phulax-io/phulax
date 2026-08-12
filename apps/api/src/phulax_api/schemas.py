import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

Sensitivity = Literal["low", "medium", "high"]
SideEffect = Literal["read", "write", "irreversible"]
Verdict = Literal["allow", "deny", "require_approval", "freeze"]
ExecutionState = Literal["AUTHORIZED", "EXECUTING", "SUCCEEDED", "FAILED"]
ApprovalState = Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED", "VOIDED"]


class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class OrgOut(BaseModel):
    id: uuid.UUID
    name: str


class UserCreate(BaseModel):
    org_id: uuid.UUID
    email: EmailStr
    name: str = Field(min_length=1, max_length=200)
    role: str | None = Field(default=None, max_length=50)


class UserOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    name: str
    role: str | None = None


class AgentRegister(BaseModel):
    """Registration always creates the agent together with its first
    immutable version — an agent without a version is unattributable."""

    org_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    owner_user_id: uuid.UUID
    version: str = Field(min_length=1, max_length=100)
    manifest: dict = Field(description="Code/config/model/tool manifest; hashed for attribution")


class AgentVersionOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    version: str
    manifest_hash: str


class AgentOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    owner_user_id: uuid.UUID
    revoked_at: datetime | None
    latest_version: AgentVersionOut | None = None


class VersionCreate(BaseModel):
    version: str = Field(min_length=1, max_length=100)
    manifest: dict


class ToolCreate(BaseModel):
    org_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    args_schema: dict = Field(description="JSON Schema (draft 2020-12) for arguments")
    sensitivity: Sensitivity
    side_effect: SideEffect
    sensitive_fields: list[str] = Field(
        default_factory=list,
        description="Dotted argument paths redacted before leaving the gateway",
    )


class ToolOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: str
    args_schema: dict
    sensitivity: Sensitivity
    side_effect: SideEffect
    sensitive_fields: list[str]


class SessionCreate(BaseModel):
    agent_version_id: uuid.UUID
    environment: str = Field(min_length=1, max_length=50)


class SessionOut(BaseModel):
    id: uuid.UUID
    agent_version_id: uuid.UUID
    environment: str
    started_at: datetime


class TokenRequest(BaseModel):
    session_id: uuid.UUID


class TokenOut(BaseModel):
    token: str
    expires_at: datetime
    claims: dict


class ActionRequestIn(BaseModel):
    """Metadata only (ADR-0002): the gateway never sends raw arguments."""

    request_id: uuid.UUID
    trace_id: uuid.UUID | None = None
    idempotency_key: str | None = None
    session_id: uuid.UUID
    tool_name: str
    environment: str
    acting_user_id: uuid.UUID | None = None
    canonical_hash: str = Field(min_length=64, max_length=64)
    args_meta: dict = Field(default_factory=dict)
    content_mode: Literal["metadata_only"] = "metadata_only"
    redacted_fields: list[str] = Field(default_factory=list)
    requested_at: datetime


class DecisionIn(BaseModel):
    verdict: Verdict
    rule: str
    reason_codes: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    policy_version: str | None = None
    latency_ms: int | None = None


class EventIngest(BaseModel):
    action_request: ActionRequestIn
    event: DecisionIn


class EventOut(BaseModel):
    id: uuid.UUID
    request_id: uuid.UUID
    trace_id: uuid.UUID | None
    session_id: uuid.UUID
    tool_name: str
    environment: str
    canonical_hash: str
    args_meta: dict
    content_mode: str
    redacted_fields: list[str]
    type: str
    verdict: Verdict | None
    rule: str
    detail: dict | None
    reason_codes: list[str]
    matched_rules: list[str]
    risk_score: int | None
    policy_version: str | None
    latency_ms: int | None
    created_at: datetime


class BundlePublish(BaseModel):
    """Rules arrive as the authored YAML document — reviewable as-is."""

    org_id: uuid.UUID
    document: str = Field(min_length=1)


class BundleOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    version: int
    rules: list[dict]
    signature: str
    created_at: datetime


class ExecutionClaim(BaseModel):
    org_id: uuid.UUID
    idempotency_key: str = Field(min_length=1, max_length=200)
    request_id: uuid.UUID
    canonical_hash: str = Field(min_length=64, max_length=64)


class ExecutionClaimOut(BaseModel):
    execution_id: uuid.UUID
    claimed: bool
    state: ExecutionState
    result_meta: dict | None


class ExecutionComplete(BaseModel):
    state: Literal["SUCCEEDED", "FAILED"]
    result_meta: dict = Field(default_factory=dict)


class ExecutionOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    idempotency_key: str
    request_id: uuid.UUID
    canonical_hash: str
    state: ExecutionState
    result_meta: dict | None
    created_at: datetime


class ApprovalResolve(BaseModel):
    """The gateway's one round trip per require_approval decision: consume
    an approval that authorizes exactly this request, or surface/create the
    pending one. args_preview arrives already redacted (plan §7.3 Day 20)."""

    org_id: uuid.UUID
    request_id: uuid.UUID
    trace_id: uuid.UUID | None = None
    session_id: uuid.UUID
    canonical_hash: str = Field(min_length=64, max_length=64)
    tool_name: str
    environment: str
    agent_version: str
    policy_version: str
    approver_role: str = Field(min_length=1, max_length=50)
    requester_user_id: uuid.UUID | None = None
    args_preview: dict = Field(default_factory=dict)
    redacted_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    risk_score: int | None = None


class ApprovalOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    request_id: uuid.UUID
    trace_id: uuid.UUID | None
    session_id: uuid.UUID
    canonical_hash: str
    tool_name: str
    environment: str
    agent_version: str
    policy_version: str
    approver_role: str
    requester_user_id: uuid.UUID | None
    args_preview: dict
    redacted_fields: list[str]
    reason_codes: list[str]
    matched_rules: list[str]
    risk_score: int | None
    state: ApprovalState
    expires_at: datetime
    decided_by: uuid.UUID | None
    decided_at: datetime | None
    consumed_at: datetime | None
    created_at: datetime


class ApprovalResolveOut(BaseModel):
    mode: Literal["consumed", "pending", "rejected"]
    created: bool = False
    approval: ApprovalOut


class ApprovalDecision(BaseModel):
    user_id: uuid.UUID


class TimelineEventOut(BaseModel):
    """One step of the reconstructed story (plan §11.3, Day 19)."""

    id: uuid.UUID
    trace_id: uuid.UUID | None
    request_id: uuid.UUID
    session_id: uuid.UUID
    tool_name: str
    type: str
    verdict: Verdict | None
    rule: str
    detail: dict | None
    reason_codes: list[str]
    matched_rules: list[str]
    policy_version: str | None
    created_at: datetime
