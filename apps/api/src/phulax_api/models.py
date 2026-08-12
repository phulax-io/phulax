"""The eight entities everything else hangs on (plan §11.1, §11.6).

Two rules carry most of the security weight:

- ``AgentVersion`` is immutable: it references a hash of code/config/model/
  tool manifest. A changed manifest means a *new* version — never an UPDATE.
  No update path is exposed anywhere in the API.
- Every ``Session`` links to exactly one ``AgentVersion`` (attribution is a
  foreign key, not a log-grep).

Metadata-first (ADR-0002): ``ActionRequest`` stores the canonical hash and
argument *shape* — never raw argument values.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SENSITIVITIES = ("low", "medium", "high")
SIDE_EFFECTS = ("read", "write", "irreversible")
# The decision model (plan §4.4): every verdict is one of the four effects.
VERDICTS = ("allow", "deny", "require_approval", "freeze")
# The execution state machine (plan §5.5): only one atomic transition may
# enter EXECUTING for an idempotency key.
EXECUTION_STATES = ("AUTHORIZED", "EXECUTING", "SUCCEEDED", "FAILED")
# The approval state machine (plan §7.3): PENDING is the only state a
# human decides from; CONSUMED is terminal and single-use by construction.
APPROVAL_STATES = ("PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED", "VOIDED")

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("org_id", "email"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # The approver role separation of duties checks against (plan §7.3),
    # e.g. "finance_approver". One role per user is enough for v1.
    role: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("org_id", "name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class AgentVersion(Base):
    """Immutable. A changed manifest is a new row, never an update."""

    __tablename__ = "agent_versions"
    __table_args__ = (UniqueConstraint("agent_id", "version"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    manifest: Mapped[dict] = mapped_column(JSONB, nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class Tool(Base):
    __tablename__ = "tools"
    __table_args__ = (
        UniqueConstraint("org_id", "name"),
        CheckConstraint(f"sensitivity IN {SENSITIVITIES}", name="sensitivity"),
        CheckConstraint(f"side_effect IN {SIDE_EFFECTS}", name="side_effect"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    args_schema: Mapped[dict] = mapped_column(JSONB, nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(20), nullable=False)
    side_effect: Mapped[str] = mapped_column(String(20), nullable=False)
    # Dotted argument paths the gateway redacts before anything leaves its
    # process (plan §7.3 Day 20), e.g. ["card_token", "customer.ssn"].
    sensitive_fields: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = _created_at()


class AgentSession(Base):
    """One session, exactly one agent_version — attribution by foreign key."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    agent_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agent_versions.id"), nullable=False
    )
    environment: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime] = _created_at()


class ActionRequest(Base):
    """Metadata-first (ADR-0002): hash + argument shape, never raw values."""

    __tablename__ = "action_requests"

    id: Mapped[uuid.UUID] = _uuid_pk()
    request_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    # The three correlators (plan §11.3): trace (the whole story),
    # request (this action), session (this conversation).
    trace_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    tool_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tools.id"), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)
    environment: Mapped[str] = mapped_column(String(50), nullable=False)
    acting_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    canonical_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    args_meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    content_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="metadata_only")
    redacted_fields: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (CheckConstraint(f"verdict IN {VERDICTS}", name="verdict"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    action_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("action_requests.id"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False, default="decision")
    # Only decision events carry a verdict; lifecycle events (approval,
    # execution) tell their story via type + rule + detail.
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    rule: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Explainability (plan §4.4): why, by which rules, under which policy.
    reason_codes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    matched_rules: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = _created_at()


class Approval(Base):
    """A decision about one request — never a permission (plan §7.3).

    The binding is (org, canonical_hash, session): consuming additionally
    requires the policy version to match what the approver saw. Session
    binding subsumes agent-version voiding — a session references exactly
    one immutable AgentVersion, so the version cannot change under an
    approval without the session changing too (agent_version is stored for
    the audit trail). Single-use is the same compare-and-set discipline as
    ``Execution``: exactly one atomic transition APPROVED → CONSUMED.
    """

    __tablename__ = "approvals"
    __table_args__ = (CheckConstraint(f"state IN {APPROVAL_STATES}", name="state"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    action_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("action_requests.id"), nullable=False
    )
    request_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    trace_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    canonical_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)
    environment: Mapped[str] = mapped_column(String(50), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(100), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    approver_role: Mapped[str] = mapped_column(String(50), nullable=False)
    requester_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    # What the reviewer sees: sensitive paths removed by the gateway BEFORE
    # transmission, and the removal is marked, never silent.
    args_preview: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    redacted_fields: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reason_codes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    matched_rules: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class PolicyBundle(Base):
    """A versioned, signed set of rules (plan §7.2, T08).

    Immutable once published: a rule change is a *new* version, never an
    UPDATE — same discipline as ``AgentVersion``. The signature covers
    (version, rules), so replaying old rules under a new version fails
    verification at the gateway.
    """

    __tablename__ = "policy_bundles"
    __table_args__ = (UniqueConstraint("org_id", "version"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    rules: Mapped[list] = mapped_column(JSONB, nullable=False)
    signature: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class Execution(Base):
    """At-most-once side effect per idempotency key (plan §5.5, T07).

    The unique key plus the compare-and-set claim (``UPDATE … WHERE
    state='AUTHORIZED'``) guarantee exactly one winner enters EXECUTING;
    concurrent duplicates read the recorded outcome instead of re-executing.
    ``result_meta`` is metadata-first: a result hash, never the result.
    """

    __tablename__ = "executions"
    __table_args__ = (
        UniqueConstraint("org_id", "idempotency_key"),
        CheckConstraint(f"state IN {EXECUTION_STATES}", name="state"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    canonical_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="AUTHORIZED")
    result_meta: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
