"""Approvals: a decision about one request, once (plan §7.3).

The §7.3 safety rules live here as *mechanics*, not policy prose:

- hash binding      → resolve matches on (org, canonical_hash, session)
- single use        → APPROVED → CONSUMED is an atomic compare-and-set
- expiry            → every transition checks ``expires_at > now()`` in SQL
- context voiding   → consuming requires the policy version the approver
                      saw; session binding already pins the agent version
- separation of duties → approver must hold the rule's role AND differ
                      from the requester
- marked redaction  → the preview stores *which* fields the gateway removed

Every state change emits a lifecycle event onto the request's timeline.
"""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import ActionRequest, Approval, Event, User
from phulax_api.notify import notify_pending_approval
from phulax_api.schemas import (
    ApprovalDecision,
    ApprovalOut,
    ApprovalResolve,
    ApprovalResolveOut,
    ApprovalState,
)
from phulax_api.settings import get_settings

router = APIRouter(prefix="/v1", tags=["approvals"])


@router.post("/approvals/resolve", response_model=ApprovalResolveOut)
def resolve_approval(body: ApprovalResolve, db: Session = Depends(get_db)) -> ApprovalResolveOut:
    """The gateway's single round trip for a require_approval decision."""
    binding = (
        Approval.org_id == body.org_id,
        Approval.canonical_hash == body.canonical_hash,
        Approval.session_id == body.session_id,
    )

    # Single use, single winner: the atomic APPROVED → CONSUMED transition.
    consumed = db.execute(
        update(Approval)
        .where(
            *binding,
            Approval.state == "APPROVED",
            Approval.expires_at > func.now(),
            Approval.policy_version == body.policy_version,
        )
        .values(state="CONSUMED", consumed_at=func.now())
        .returning(Approval.id)
    ).first()
    if consumed is not None:
        approval = db.get(Approval, consumed.id)
        assert approval is not None
        _record(db, approval, "approval.consumed")
        return ApprovalResolveOut(mode="consumed", approval=_out(approval))

    # An approval granted under a different policy version is void — the
    # approver's context no longer exists (TOCTOU, plan §7.3).
    voided = db.execute(
        update(Approval)
        .where(
            *binding,
            Approval.state == "APPROVED",
            Approval.expires_at > func.now(),
            Approval.policy_version != body.policy_version,
        )
        .values(state="VOIDED")
        .returning(Approval.id)
    ).first()
    if voided is not None:
        _record(db, db.get(Approval, voided.id), "approval.voided")

    # Housekeeping: anything past its window is EXPIRED, visibly.
    for expired in db.execute(
        update(Approval)
        .where(
            *binding,
            Approval.state.in_(("PENDING", "APPROVED")),
            Approval.expires_at <= func.now(),
        )
        .values(state="EXPIRED")
        .returning(Approval.id)
    ):
        _record(db, db.get(Approval, expired.id), "approval.expired")

    # A live rejection is a human's "no" — it holds until it expires.
    rejected = db.scalar(
        select(Approval).where(
            *binding, Approval.state == "REJECTED", Approval.expires_at > func.now()
        )
    )
    if rejected is not None:
        return ApprovalResolveOut(mode="rejected", approval=_out(rejected))

    pending = db.scalar(select(Approval).where(*binding, Approval.state == "PENDING"))
    if pending is not None:
        return ApprovalResolveOut(mode="pending", approval=_out(pending))

    approval = _create_pending(db, body)
    return ApprovalResolveOut(mode="pending", created=True, approval=_out(approval))


def _create_pending(db: Session, body: ApprovalResolve) -> Approval:
    action_request = db.scalar(
        select(ActionRequest)
        .where(ActionRequest.request_id == body.request_id)
        .order_by(ActionRequest.created_at.desc())
        .limit(1)
    )
    if action_request is None:
        # Record-first discipline: no decision event, no approval.
        raise HTTPException(status_code=404, detail="no recorded request to approve")

    approval = Approval(
        org_id=body.org_id,
        action_request_id=action_request.id,
        request_id=body.request_id,
        trace_id=body.trace_id,
        session_id=body.session_id,
        canonical_hash=body.canonical_hash,
        tool_name=body.tool_name,
        environment=body.environment,
        agent_version=body.agent_version,
        policy_version=body.policy_version,
        approver_role=body.approver_role,
        requester_user_id=body.requester_user_id,
        args_preview=body.args_preview,
        redacted_fields=body.redacted_fields,
        reason_codes=body.reason_codes,
        matched_rules=body.matched_rules,
        risk_score=body.risk_score,
        state="PENDING",
        expires_at=datetime.now(UTC) + timedelta(seconds=get_settings().approval_ttl_seconds),
    )
    db.add(approval)
    try:
        db.flush()
    except IntegrityError:
        # Concurrent resolve created the pending first; serve that one.
        db.rollback()
        existing = db.scalar(
            select(Approval).where(
                Approval.org_id == body.org_id,
                Approval.canonical_hash == body.canonical_hash,
                Approval.session_id == body.session_id,
                Approval.state == "PENDING",
            )
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="approval state changed; retry") from None
        return existing
    _record(db, approval, "approval.requested")
    notify_pending_approval(approval)
    return approval


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalOut)
def approve(
    approval_id: uuid.UUID, body: ApprovalDecision, db: Session = Depends(get_db)
) -> ApprovalOut:
    return _out(decide_approval(db, approval_id, body.user_id, approve=True))


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalOut)
def reject(
    approval_id: uuid.UUID, body: ApprovalDecision, db: Session = Depends(get_db)
) -> ApprovalOut:
    return _out(decide_approval(db, approval_id, body.user_id, approve=False))


def decide_approval(
    db: Session, approval_id: uuid.UUID, user_id: uuid.UUID, *, approve: bool
) -> Approval:
    """Shared by the JSON API and the review UI — one set of safety rules."""
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")

    user = db.get(User, user_id)
    if user is None or user.org_id != approval.org_id:
        raise HTTPException(status_code=404, detail="approver not found in this org")
    if user.role != approval.approver_role:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "approval.role-mismatch",
                "detail": f"decision requires role {approval.approver_role!r}",
            },
        )
    # Separation of duties is mechanical, not HR policy (plan §7.3).
    if approval.requester_user_id is not None and user.id == approval.requester_user_id:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "approval.self-approval",
                "detail": "the requester cannot decide their own request",
            },
        )

    new_state = "APPROVED" if approve else "REJECTED"
    decided = db.execute(
        update(Approval)
        .where(
            Approval.id == approval_id,
            Approval.state == "PENDING",
            Approval.expires_at > func.now(),
        )
        .values(state=new_state, decided_by=user.id, decided_at=func.now())
    )
    if decided.rowcount != 1:
        db.refresh(approval)
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval.not-pending",
                "detail": f"approval is {approval.state} (or past its expiry)",
            },
        )
    db.refresh(approval)
    _record(db, approval, f"approval.{new_state.lower()}", {"decided_by": str(user.id)})
    return approval


@router.get("/approvals", response_model=list[ApprovalOut])
def list_approvals(
    org_id: uuid.UUID | None = None,
    state: ApprovalState | None = None,
    db: Session = Depends(get_db),
):
    query = select(Approval).order_by(Approval.created_at.desc()).limit(100)
    if org_id is not None:
        query = query.where(Approval.org_id == org_id)
    if state is not None:
        query = query.where(Approval.state == state)
    return [_out(approval) for approval in db.scalars(query)]


@router.get("/approvals/{approval_id}", response_model=ApprovalOut)
def get_approval(approval_id: uuid.UUID, db: Session = Depends(get_db)) -> ApprovalOut:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    return _out(approval)


def _record(db: Session, approval: Approval | None, rule: str, extra: dict | None = None) -> None:
    """Every approval state change is timeline evidence (plan §11.3)."""
    if approval is None:
        return
    db.add(
        Event(
            action_request_id=approval.action_request_id,
            type="approval",
            verdict=None,
            rule=rule,
            detail={"approval_id": str(approval.id), "state": approval.state} | (extra or {}),
        )
    )
    db.flush()


def _out(approval: Approval) -> ApprovalOut:
    return ApprovalOut.model_validate(approval, from_attributes=True)
