"""At-most-once execution claims (plan §5.5, Day 13, T07).

"Exactly once" over a network is impossible in general; what exists here is
at-most-once side effect per idempotency key plus safe retries. The claim is
a compare-and-set: ``UPDATE … WHERE state='AUTHORIZED'`` admits exactly one
winner into EXECUTING — Postgres row locking serializes concurrent
duplicates, and the loser reads the recorded outcome instead of re-executing
(scenario #10).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import ActionRequest, Event, Execution
from phulax_api.schemas import ExecutionClaim, ExecutionClaimOut, ExecutionComplete, ExecutionOut

router = APIRouter(prefix="/v1", tags=["executions"])


@router.post("/executions/claim", response_model=ExecutionClaimOut)
def claim_execution(body: ExecutionClaim, db: Session = Depends(get_db)) -> ExecutionClaimOut:
    db.execute(
        insert(Execution)
        .values(
            org_id=body.org_id,
            idempotency_key=body.idempotency_key,
            request_id=body.request_id,
            canonical_hash=body.canonical_hash,
            state="AUTHORIZED",
        )
        .on_conflict_do_nothing(index_elements=["org_id", "idempotency_key"])
    )
    execution = db.scalar(
        select(Execution).where(
            Execution.org_id == body.org_id,
            Execution.idempotency_key == body.idempotency_key,
        )
    )
    assert execution is not None  # just inserted or already present

    # A reused key with different arguments is not a retry — it's a bug or
    # an attack. Refuse loudly rather than dedupe silently.
    if execution.canonical_hash != body.canonical_hash:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "execution.key-reused",
                "detail": "idempotency key already used for a different canonical request",
            },
        )

    # The atomic transition: exactly one caller moves AUTHORIZED → EXECUTING.
    claimed = db.execute(
        update(Execution)
        .where(Execution.id == execution.id, Execution.state == "AUTHORIZED")
        .values(state="EXECUTING")
    )
    db.flush()
    db.refresh(execution)
    return ExecutionClaimOut(
        execution_id=execution.id,
        claimed=claimed.rowcount == 1,
        state=execution.state,  # type: ignore[arg-type]
        result_meta=execution.result_meta,
    )


@router.post("/executions/{execution_id}/complete", response_model=ExecutionOut)
def complete_execution(
    execution_id: uuid.UUID, body: ExecutionComplete, db: Session = Depends(get_db)
) -> ExecutionOut:
    finished = db.execute(
        update(Execution)
        .where(Execution.id == execution_id, Execution.state == "EXECUTING")
        .values(state=body.state, result_meta=body.result_meta)
    )
    if finished.rowcount != 1:
        execution = db.get(Execution, execution_id)
        if execution is None:
            raise HTTPException(status_code=404, detail="execution not found")
        raise HTTPException(
            status_code=409,
            detail={
                "code": "execution.not-executing",
                "detail": f"cannot complete from state {execution.state!r}",
            },
        )
    execution = db.get(Execution, execution_id)
    assert execution is not None
    db.refresh(execution)
    _record_execution_event(db, execution)
    return ExecutionOut(
        id=execution.id,
        org_id=execution.org_id,
        idempotency_key=execution.idempotency_key,
        request_id=execution.request_id,
        canonical_hash=execution.canonical_hash,
        state=execution.state,  # type: ignore[arg-type]
        result_meta=execution.result_meta,
        created_at=execution.created_at,
    )


def _record_execution_event(db: Session, execution: Execution) -> None:
    """The result lands on the timeline too (plan §11.3): received →
    decision → … → executing → result, all one trace query away."""
    action_request = db.scalar(
        select(ActionRequest)
        .where(ActionRequest.request_id == execution.request_id)
        .order_by(ActionRequest.created_at.desc())
        .limit(1)
    )
    if action_request is None:
        return
    db.add(
        Event(
            action_request_id=action_request.id,
            type="execution",
            verdict=None,
            rule=f"execution.{execution.state.lower()}",
            detail={
                "execution_id": str(execution.id),
                "state": execution.state,
                "result_meta": execution.result_meta,
            },
        )
    )
    db.flush()
