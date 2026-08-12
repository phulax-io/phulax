import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import ActionRequest, Agent, AgentSession, AgentVersion, Event, Tool
from phulax_api.schemas import EventIngest, EventOut, TimelineEventOut

router = APIRouter(prefix="/v1", tags=["events"])

# NOTE: ingestion is not yet authenticated — security backlog item #4
# ("Authenticated event ingestion", control plane v1). The walking skeleton
# proves the evidence path; the lock arrives with signed gateway identity.


@router.post("/events", response_model=EventOut, status_code=201)
def ingest_event(body: EventIngest, db: Session = Depends(get_db)) -> EventOut:
    session = db.get(AgentSession, body.action_request.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    version = db.get(AgentVersion, session.agent_version_id)
    agent = db.get(Agent, version.agent_id) if version else None
    tool = (
        db.scalar(
            select(Tool).where(
                Tool.org_id == agent.org_id, Tool.name == body.action_request.tool_name
            )
        )
        if agent
        else None
    )

    request = ActionRequest(
        request_id=body.action_request.request_id,
        trace_id=body.action_request.trace_id,
        idempotency_key=body.action_request.idempotency_key,
        session_id=body.action_request.session_id,
        tool_id=tool.id if tool else None,
        tool_name=body.action_request.tool_name,
        environment=body.action_request.environment,
        acting_user_id=body.action_request.acting_user_id,
        canonical_hash=body.action_request.canonical_hash,
        args_meta=body.action_request.args_meta,
        content_mode=body.action_request.content_mode,
        redacted_fields=body.action_request.redacted_fields,
        requested_at=body.action_request.requested_at,
    )
    db.add(request)
    db.flush()
    event = Event(
        action_request_id=request.id,
        verdict=body.event.verdict,
        rule=body.event.rule,
        reason_codes=body.event.reason_codes,
        matched_rules=body.event.matched_rules,
        risk_score=body.event.risk_score,
        policy_version=body.event.policy_version,
        latency_ms=body.event.latency_ms,
    )
    db.add(event)
    db.flush()
    return _event_out(request, event)


@router.get("/events", response_model=list[EventOut])
def list_events(
    request_id: uuid.UUID | None = None,
    db: Session = Depends(get_db),
):
    query = (
        select(ActionRequest, Event)
        .join(Event, Event.action_request_id == ActionRequest.id)
        .order_by(Event.created_at.desc())
        .limit(100)
    )
    if request_id is not None:
        query = query.where(ActionRequest.request_id == request_id)
    return [_event_out(request, event) for request, event in db.execute(query).all()]


def _event_out(request: ActionRequest, event: Event) -> EventOut:
    return EventOut(
        id=event.id,
        request_id=request.request_id,
        trace_id=request.trace_id,
        session_id=request.session_id,
        tool_name=request.tool_name,
        environment=request.environment,
        canonical_hash=request.canonical_hash,
        args_meta=request.args_meta,
        content_mode=request.content_mode,
        redacted_fields=request.redacted_fields,
        type=event.type,
        verdict=event.verdict,  # type: ignore[arg-type]
        rule=event.rule,
        detail=event.detail,
        reason_codes=event.reason_codes,
        matched_rules=event.matched_rules,
        risk_score=event.risk_score,
        policy_version=event.policy_version,
        latency_ms=event.latency_ms,
        created_at=event.created_at,
    )


@router.get("/timeline", response_model=list[TimelineEventOut])
def timeline(trace_id: uuid.UUID, db: Session = Depends(get_db)):
    """One query, the whole story (plan §11.3 Day 19): every event of every
    request that shares this trace, in the order it happened."""
    rows = db.execute(
        select(ActionRequest, Event)
        .join(Event, Event.action_request_id == ActionRequest.id)
        .where(ActionRequest.trace_id == trace_id)
        .order_by(Event.created_at.asc(), Event.id.asc())
    ).all()
    return [
        TimelineEventOut(
            id=event.id,
            trace_id=request.trace_id,
            request_id=request.request_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            type=event.type,
            verdict=event.verdict,  # type: ignore[arg-type]
            rule=event.rule,
            detail=event.detail,
            reason_codes=event.reason_codes,
            matched_rules=event.matched_rules,
            policy_version=event.policy_version,
            created_at=event.created_at,
        )
        for request, event in rows
    ]
