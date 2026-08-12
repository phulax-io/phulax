"""Reviewer notification (plan §7 Day 18) — best-effort, never blocking.

A pending approval must *reach* a reviewer; it must never make the decision
path fragile. The webhook is fire-and-forget: failures are logged and the
approval flow proceeds — the polling UI remains the guaranteed channel.
"""

import logging

import httpx

from phulax_api.models import Approval
from phulax_api.settings import get_settings

logger = logging.getLogger("phulax.api.notify")

_WEBHOOK_TIMEOUT_SECONDS = 2.0


def notify_pending_approval(approval: Approval) -> None:
    webhook_url = get_settings().slack_webhook_url
    if not webhook_url:
        return
    redacted = len(approval.redacted_fields)
    text = (
        f"Phulax approval needed: `{approval.tool_name}` in {approval.environment} "
        f"(risk {approval.risk_score}, {redacted} field(s) redacted) — "
        f"role `{approval.approver_role}`, expires {approval.expires_at:%H:%M:%S %Z}"
    )
    try:
        httpx.post(webhook_url, json={"text": text}, timeout=_WEBHOOK_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        logger.warning("approval notification not delivered: %s", exc)
