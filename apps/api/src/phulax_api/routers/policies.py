"""Publish signed, versioned policy bundles (plan §7.2, Day 10).

The control plane validates the authored YAML with the same constrained
parser the gateway uses, assigns the next monotonic version, and signs
(version, rules) with its Ed25519 key. Distribution can now run over an
untrusted channel: a compromised path can corrupt a bundle, never forge
one (T08).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from phulax_policy import PolicyError, sign_bundle
from phulax_policy.schema import load_rules_document
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import Organization, PolicyBundle
from phulax_api.schemas import BundleOut, BundlePublish
from phulax_api.settings import get_settings

router = APIRouter(prefix="/v1", tags=["policies"])


@router.post("/policy-bundles", response_model=BundleOut, status_code=201)
def publish_bundle(body: BundlePublish, db: Session = Depends(get_db)) -> BundleOut:
    if not get_settings().policy_signing_key:
        raise HTTPException(
            status_code=503,
            detail="POLICY_SIGNING_KEY is not configured — bundles cannot be signed",
        )
    if db.get(Organization, body.org_id) is None:
        raise HTTPException(status_code=404, detail="organization not found")
    try:
        rules_data, _ = load_rules_document(body.document)
    except PolicyError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "policy.invalid-rules", "errors": list(exc.errors)},
        ) from exc

    latest = db.scalar(
        select(func.max(PolicyBundle.version)).where(PolicyBundle.org_id == body.org_id)
    )
    version = (latest or 0) + 1
    bundle = PolicyBundle(
        org_id=body.org_id,
        version=version,
        rules=rules_data,
        signature=sign_bundle(
            get_settings().policy_signing_key, version=version, rules_data=rules_data
        ),
    )
    db.add(bundle)
    db.flush()
    return _bundle_out(bundle)


@router.get("/policy-bundles/latest", response_model=BundleOut)
def latest_bundle(org_id: uuid.UUID, db: Session = Depends(get_db)) -> BundleOut:
    bundle = db.scalar(
        select(PolicyBundle)
        .where(PolicyBundle.org_id == org_id)
        .order_by(PolicyBundle.version.desc())
        .limit(1)
    )
    if bundle is None:
        raise HTTPException(status_code=404, detail="no policy bundle published for org")
    return _bundle_out(bundle)


def _bundle_out(bundle: PolicyBundle) -> BundleOut:
    return BundleOut(
        id=bundle.id,
        org_id=bundle.org_id,
        version=bundle.version,
        rules=bundle.rules,
        signature=bundle.signature,
        created_at=bundle.created_at,
    )
