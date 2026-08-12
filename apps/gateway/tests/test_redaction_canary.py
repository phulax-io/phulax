"""Day 20: redaction proven by canary, not by code review.

A known fake secret rides through the full approval lifecycle; then every
surface the control plane exposes — events, approvals, the timeline, the
review UI — plus everything the processes logged is scanned for it. R3
("we accidentally became a vault of secrets") is handled by architecture,
and this test is the alarm on the door.
"""

import json
import uuid
from datetime import UTC, datetime

from phulax_gateway.redaction import redact

# The canary must look like a real secret to be a fair test; it is fake.
CANARY_TOKEN = "tok_CANARY_4eC39HqLyjWDarjtT1zdp7dc"  # gitleaks:allow
CANARY_SSN = "CANARY-078-05-1120"


def test_redact_removes_marked_paths_and_lists_them():
    arguments = {
        "order_id": "ORD-1001",
        "amount": 748.0,
        "card_token": CANARY_TOKEN,
        "customer": {"name": "Jo", "ssn": CANARY_SSN},
    }
    preview, redacted = redact(arguments, ["card_token", "$.customer.ssn"])
    assert preview == {"order_id": "ORD-1001", "amount": 748.0, "customer": {"name": "Jo"}}
    assert redacted == ["card_token", "customer.ssn"]
    # The original is untouched — redaction copies, never mutates.
    assert arguments["card_token"] == CANARY_TOKEN
    assert arguments["customer"]["ssn"] == CANARY_SSN


def test_redact_skips_paths_that_are_not_present():
    preview, redacted = redact({"amount": 5}, ["card_token", "customer.ssn"])
    assert preview == {"amount": 5}
    assert redacted == []  # nothing was there to redact — and none claimed


def test_redacted_field_never_in_events_or_logs(gateway_client, api_client, seeded, caplog):
    caplog.set_level("DEBUG")
    trace_id = uuid.uuid4()
    envelope = {
        "request_id": str(uuid.uuid4()),
        "trace_id": str(trace_id),
        "idempotency_key": f"refund-{uuid.uuid4()}",
        "agent_id": seeded["agent"]["id"],
        "agent_version": "1.0.0",
        "session_id": seeded["session"]["id"],
        "environment": "staging",
        "tool_name": "issue_refund",
        "arguments": {
            "order_id": "ORD-1001",
            "amount": 748.0,
            "card_token": CANARY_TOKEN,
            "customer_note": CANARY_SSN,
        },
        "requested_at": datetime.now(UTC).isoformat(),
    }
    headers = {"Authorization": f"Bearer {seeded['token']}"}

    # Full lifecycle: pending → approved → consumed → executed.
    pending = gateway_client.post("/v1/actions", json=envelope, headers=headers)
    assert pending.status_code == 202
    approval_id = pending.json()["approval"]["id"]
    api_client.post(
        f"/v1/approvals/{approval_id}/approve", json={"user_id": seeded["finance"]["id"]}
    ).raise_for_status()
    executed = gateway_client.post(
        "/v1/actions", json=envelope | {"request_id": str(uuid.uuid4())}, headers=headers
    )
    assert executed.status_code == 200

    # Scan every control-plane surface for the canaries.
    surfaces = {
        "events": api_client.get("/v1/events").json(),
        "approvals": api_client.get("/v1/approvals", params={"org_id": seeded["org"]["id"]}).json(),
        "timeline": api_client.get("/v1/timeline", params={"trace_id": str(trace_id)}).json(),
        "ui_detail": api_client.get(f"/ui/approvals/{approval_id}").text,
    }
    for name, dump in surfaces.items():
        blob = dump if isinstance(dump, str) else json.dumps(dump)
        assert CANARY_TOKEN not in blob, f"canary token leaked into {name}"
        assert CANARY_SSN not in blob, f"canary note leaked into {name}"

    # ...and everything either process logged during the whole flow.
    assert CANARY_TOKEN not in caplog.text
    assert CANARY_SSN not in caplog.text

    # The reviewer still saw the safe fields — redaction, not blackout.
    approval = api_client.get(f"/v1/approvals/{approval_id}").json()
    assert approval["args_preview"] == {"order_id": "ORD-1001", "amount": 748.0}
    assert set(approval["redacted_fields"]) == {"card_token", "customer_note"}
