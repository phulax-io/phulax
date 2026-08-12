"""The minimal approval review UI (plan §7 Day 16) — a dev-grade console.

Server-rendered HTML, no build step: a pending list that refreshes itself
every five seconds (the Day 18 polling channel) and a detail view showing
what a reviewer must see before deciding — agent, action, resource, the
*redacted* argument preview, and **which** fields were redacted. Redaction
is marked, never silent: a reviewer seeing "2 fields redacted" is informed;
one seeing a partial record without knowing it is deceived.

Decisions go through the same ``decide_approval`` mechanics as the JSON
API — the UI cannot bypass a safety rule it doesn't implement.
"""

import html
import json
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import Agent, AgentSession, AgentVersion, Approval, User
from phulax_api.routers.approvals import decide_approval

router = APIRouter(prefix="/ui", tags=["ui"], include_in_schema=False)

_STYLE = """
body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem;
       background: #0f1115; color: #d7dae0; }
a { color: #7aa2f7; text-decoration: none; }
h1 { font-size: 1.2rem; } h2 { font-size: 1rem; margin-top: 1.5rem; }
table { border-collapse: collapse; width: 100%; }
td, th { border-bottom: 1px solid #2a2e37; padding: .5rem .75rem; text-align: left;
         font-size: .85rem; }
.badge { padding: .1rem .5rem; border-radius: .25rem; font-size: .75rem; }
.PENDING { background: #3b3417; color: #e0c060; }
.APPROVED, .CONSUMED { background: #1d3324; color: #7fd88f; }
.REJECTED, .EXPIRED, .VOIDED { background: #381d1d; color: #e07f7f; }
.redacted { background: #38284a; color: #c39ae0; padding: .1rem .5rem;
            border-radius: .25rem; font-size: .75rem; }
pre { background: #16181e; padding: 1rem; border-radius: .5rem; overflow-x: auto; }
form { margin-top: 1rem; } select, button { font: inherit; padding: .4rem .8rem; }
button { border: 0; border-radius: .3rem; cursor: pointer; margin-left: .5rem; }
.approve { background: #1d3324; color: #7fd88f; } .reject { background: #381d1d; color: #e07f7f; }
.error { color: #e07f7f; } .muted { color: #6b7280; font-size: .8rem; }
"""


def _page(title: str, body: str, refresh: bool = False) -> HTMLResponse:
    meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'>{meta}"
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><h1>Phulax · {html.escape(title)}</h1>{body}</body></html>"
    )


def _esc(value: object) -> str:
    return html.escape(str(value))


@router.get("/approvals", response_class=HTMLResponse)
def approvals_list(db: Session = Depends(get_db)) -> HTMLResponse:
    approvals = db.scalars(select(Approval).order_by(Approval.created_at.desc()).limit(50)).all()
    pending = [a for a in approvals if a.state == "PENDING"]
    decided = [a for a in approvals if a.state != "PENDING"]

    def rows(items: list[Approval]) -> str:
        if not items:
            return "<tr><td colspan='6' class='muted'>none</td></tr>"
        out = []
        for a in items:
            out.append(
                f"<tr><td><a href='/ui/approvals/{a.id}'>{_esc(str(a.id)[:8])}…</a></td>"
                f"<td>{_esc(a.tool_name)}</td><td>{_esc(a.environment)}</td>"
                f"<td><span class='badge {_esc(a.state)}'>{_esc(a.state)}</span></td>"
                f"<td><span class='redacted'>{len(a.redacted_fields)} redacted</span></td>"
                f"<td class='muted'>expires {a.expires_at:%H:%M:%S}</td></tr>"
            )
        return "".join(out)

    body = (
        "<h2>Pending (auto-refreshes)</h2><table>"
        "<tr><th>id</th><th>tool</th><th>env</th><th>state</th><th>fields</th><th></th></tr>"
        f"{rows(pending)}</table>"
        f"<h2>Recent decisions</h2><table>{rows(decided)}</table>"
    )
    return _page("approvals", body, refresh=True)


@router.get("/approvals/{approval_id}", response_class=HTMLResponse)
def approval_detail(
    approval_id: uuid.UUID, error: str = "", db: Session = Depends(get_db)
) -> HTMLResponse:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")

    session = db.get(AgentSession, approval.session_id)
    version = db.get(AgentVersion, session.agent_version_id) if session else None
    agent = db.get(Agent, version.agent_id) if version else None
    users = db.scalars(select(User).where(User.org_id == approval.org_id)).all()

    redacted = (
        " ".join(f"<span class='redacted'>{_esc(name)}</span>" for name in approval.redacted_fields)
        or "<span class='muted'>none</span>"
    )
    options = "".join(
        f"<option value='{user.id}'>{_esc(user.name)} ({_esc(user.role or 'no role')})</option>"
        for user in users
    )
    decide_form = (
        f"<form method='post' action='/ui/approvals/{approval.id}/decide'>"
        f"<label>decide as <select name='user_id'>{options}</select></label>"
        "<button class='approve' name='action' value='approve'>Approve once</button>"
        "<button class='reject' name='action' value='reject'>Reject</button>"
        f"<div class='muted'>requires role “{_esc(approval.approver_role)}”; "
        "the requester cannot decide their own request</div></form>"
        if approval.state == "PENDING"
        else "<p class='muted'>This approval is no longer pending.</p>"
    )
    error_html = f"<p class='error'>{_esc(error)}</p>" if error else ""

    body = f"""
{error_html}
<p><a href="/ui/approvals">← pending list</a></p>
<table>
<tr><th>state</th><td>
  <span class="badge {_esc(approval.state)}">{_esc(approval.state)}</span></td></tr>
<tr><th>agent</th><td>{_esc(agent.name if agent else "?")} v{_esc(approval.agent_version)}</td></tr>
<tr><th>action</th><td>{_esc(approval.tool_name)} ({_esc(approval.environment)})</td></tr>
<tr><th>request hash</th><td>{_esc(approval.canonical_hash[:16])}…
  <span class="muted">approval binds to exactly this</span></td></tr>
<tr><th>policy</th><td>v{_esc(approval.policy_version)}
  · rules {_esc(", ".join(approval.matched_rules))}</td></tr>
<tr><th>reasons</th><td>{_esc(", ".join(approval.reason_codes))}</td></tr>
<tr><th>risk</th><td>{_esc(approval.risk_score)}</td></tr>
<tr><th>redacted fields</th><td>{redacted}</td></tr>
<tr><th>expires</th><td>{approval.expires_at:%Y-%m-%d %H:%M:%S %Z}</td></tr>
</table>
<h2>Arguments (sensitive fields removed before they reached this server)</h2>
<pre>{_esc(json.dumps(approval.args_preview, indent=2))}</pre>
{decide_form}
"""
    return _page(f"approval {str(approval.id)[:8]}", body)


@router.post("/approvals/{approval_id}/decide")
def approval_decide(
    approval_id: uuid.UUID,
    user_id: uuid.UUID = Form(),
    action: str = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    try:
        decide_approval(db, approval_id, user_id, approve=(action == "approve"))
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else exc.detail.get("detail", "refused")
        return RedirectResponse(
            f"/ui/approvals/{approval_id}?error={urllib.parse.quote(str(detail))}",
            status_code=303,
        )
    return RedirectResponse(f"/ui/approvals/{approval_id}", status_code=303)
