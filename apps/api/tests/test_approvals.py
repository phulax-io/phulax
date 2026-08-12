"""Days 15 & 17: the §7.3 approval safety rules, at the API that owns them.

Hash binding, atomic single-use consume, expiry, policy-version voiding,
role checks, and mechanical separation of duties — each rule is a test,
not a promise.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from sqlalchemy import text

HASH_A = "a" * 64


def _ingest_request(api_client, seeded, request_id, canonical_hash=HASH_A, trace_id=None):
    """Approvals require a recorded request (record-first discipline)."""
    api_client.post(
        "/v1/events",
        json={
            "action_request": {
                "request_id": str(request_id),
                "trace_id": str(trace_id) if trace_id else None,
                "session_id": seeded["session"]["id"],
                "tool_name": "issue_refund",
                "environment": "staging",
                "canonical_hash": canonical_hash,
                "args_meta": {"order_id": "string", "amount": "number"},
                "requested_at": datetime.now(UTC).isoformat(),
            },
            "event": {
                "verdict": "require_approval",
                "rule": "approve-large-refund",
                "reason_codes": ["RULE_APPROVAL"],
                "matched_rules": ["approve-large-refund"],
                "policy_version": "1",
            },
        },
    ).raise_for_status()


def _resolve(api_client, seeded, canonical_hash=HASH_A, policy_version="1", requester=None):
    request_id = uuid.uuid4()
    _ingest_request(api_client, seeded, request_id, canonical_hash)
    response = api_client.post(
        "/v1/approvals/resolve",
        json={
            "org_id": seeded["org"]["id"],
            "request_id": str(request_id),
            "session_id": seeded["session"]["id"],
            "canonical_hash": canonical_hash,
            "tool_name": "issue_refund",
            "environment": "staging",
            "agent_version": "1.0.0",
            "policy_version": policy_version,
            "approver_role": "finance_approver",
            "requester_user_id": requester,
            "args_preview": {"order_id": "ORD-1001", "amount": 748.0},
            "redacted_fields": ["card_token", "customer_note"],
            "reason_codes": ["RULE_APPROVAL"],
            "matched_rules": ["approve-large-refund"],
            "risk_score": 60,
        },
    )
    response.raise_for_status()
    return response.json()


def _approve(api_client, approval_id, user_id):
    return api_client.post(f"/v1/approvals/{approval_id}/approve", json={"user_id": user_id})


def test_resolve_creates_one_pending_and_reuses_it(api_client, seeded):
    first = _resolve(api_client, seeded)
    assert first["mode"] == "pending" and first["created"] is True
    again = _resolve(api_client, seeded)
    assert again["mode"] == "pending" and again["created"] is False
    assert again["approval"]["id"] == first["approval"]["id"]


def test_approver_role_is_required(api_client, seeded):
    pending = _resolve(api_client, seeded)
    response = _approve(api_client, pending["approval"]["id"], seeded["owner"]["id"])
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "approval.role-mismatch"


def test_requester_cannot_approve_own_request(api_client, seeded):
    # Separation of duties is mechanical: even the right ROLE is refused
    # when the approver IS the requester.
    pending = _resolve(api_client, seeded, requester=seeded["finance"]["id"])
    response = _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"])
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "approval.self-approval"


def test_approved_consumed_exactly_once(api_client, seeded):
    pending = _resolve(api_client, seeded)
    _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"]).raise_for_status()

    first = _resolve(api_client, seeded)
    assert first["mode"] == "consumed"
    assert first["approval"]["state"] == "CONSUMED"

    # The token is spent: the same binding now yields a fresh PENDING.
    second = _resolve(api_client, seeded)
    assert second["mode"] == "pending" and second["created"] is True
    assert second["approval"]["id"] != first["approval"]["id"]


def test_concurrent_resolves_consume_a_single_approval_once(api_client, seeded):
    pending = _resolve(api_client, seeded)
    _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"]).raise_for_status()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _resolve(api_client, seeded), range(2)))
    assert sorted(result["mode"] for result in results) == ["consumed", "pending"]


def test_rejection_holds_until_expiry(api_client, seeded):
    pending = _resolve(api_client, seeded)
    api_client.post(
        f"/v1/approvals/{pending['approval']['id']}/reject",
        json={"user_id": seeded["finance"]["id"]},
    ).raise_for_status()

    result = _resolve(api_client, seeded)
    assert result["mode"] == "rejected"
    assert result["approval"]["state"] == "REJECTED"


def test_expired_approval_never_consumed(api_client, seeded, clean_db):
    pending = _resolve(api_client, seeded)
    _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"]).raise_for_status()
    with clean_db.begin() as conn:
        conn.execute(text("UPDATE approvals SET expires_at = now() - interval '1 minute'"))

    result = _resolve(api_client, seeded)
    assert result["mode"] == "pending" and result["created"] is True
    old = api_client.get(f"/v1/approvals/{pending['approval']['id']}").json()
    assert old["state"] == "EXPIRED"


def test_policy_version_change_voids_approval(api_client, seeded):
    # Approve under policy v1, attempt to use under v2: the context the
    # approver saw no longer exists (TOCTOU, plan §7.3).
    pending = _resolve(api_client, seeded, policy_version="1")
    _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"]).raise_for_status()

    result = _resolve(api_client, seeded, policy_version="2")
    assert result["mode"] == "pending" and result["created"] is True
    old = api_client.get(f"/v1/approvals/{pending['approval']['id']}").json()
    assert old["state"] == "VOIDED"


def test_decide_requires_pending_state(api_client, seeded):
    pending = _resolve(api_client, seeded)
    _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"]).raise_for_status()
    again = _approve(api_client, pending["approval"]["id"], seeded["finance"]["id"])
    assert again.status_code == 409
    assert again.json()["detail"]["code"] == "approval.not-pending"


def test_pending_notification_fires_webhook(api_client, seeded, monkeypatch):
    from phulax_api import notify
    from phulax_api.settings import get_settings

    calls = []
    monkeypatch.setattr(notify.httpx, "post", lambda url, **kw: calls.append((url, kw)))
    monkeypatch.setattr(get_settings(), "slack_webhook_url", "https://hooks.example/T00/B00")

    _resolve(api_client, seeded)
    assert len(calls) == 1
    assert "issue_refund" in calls[0][1]["json"]["text"]
    assert "2 field(s) redacted" in calls[0][1]["json"]["text"]


def test_review_ui_lists_and_details_pending(api_client, seeded):
    pending = _resolve(api_client, seeded)
    listing = api_client.get("/ui/approvals")
    assert listing.status_code == 200
    assert "issue_refund" in listing.text

    detail = api_client.get(f"/ui/approvals/{pending['approval']['id']}")
    assert detail.status_code == 200
    assert "refund-agent" in detail.text  # the reviewer sees the agent
    assert "card_token" in detail.text  # ...and WHICH fields were redacted
    assert "748" in detail.text  # ...and the safe fields' values


def test_review_ui_decides_through_the_same_rules(api_client, seeded):
    pending = _resolve(api_client, seeded)
    approval_id = pending["approval"]["id"]

    # Wrong role bounces back with the mechanical error, not a decision.
    denied = api_client.post(
        f"/ui/approvals/{approval_id}/decide",
        data={"user_id": seeded["owner"]["id"], "action": "approve"},
        follow_redirects=False,
    )
    assert denied.status_code == 303 and "error=" in denied.headers["location"]

    approved = api_client.post(
        f"/ui/approvals/{approval_id}/decide",
        data={"user_id": seeded["finance"]["id"], "action": "approve"},
        follow_redirects=False,
    )
    assert approved.status_code == 303 and "error" not in approved.headers["location"]
    assert api_client.get(f"/v1/approvals/{approval_id}").json()["state"] == "APPROVED"
