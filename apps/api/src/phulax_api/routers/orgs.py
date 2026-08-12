import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from phulax_api.db import get_db
from phulax_api.models import Organization, User
from phulax_api.schemas import OrgCreate, OrgOut, UserCreate, UserOut

router = APIRouter(prefix="/v1", tags=["organizations"])


@router.post("/organizations", response_model=OrgOut, status_code=201)
def create_organization(body: OrgCreate, db: Session = Depends(get_db)) -> Organization:
    existing = db.scalar(select(Organization).where(Organization.name == body.name))
    if existing is not None:
        raise HTTPException(status_code=409, detail="organization already exists")
    org = Organization(name=body.name)
    db.add(org)
    db.flush()
    return org


@router.get("/organizations", response_model=list[OrgOut])
def list_organizations(name: str | None = None, db: Session = Depends(get_db)):
    query = select(Organization)
    if name is not None:
        query = query.where(Organization.name == name)
    return db.scalars(query).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db)) -> User:
    if db.get(Organization, body.org_id) is None:
        raise HTTPException(status_code=404, detail="organization not found")
    existing = db.scalar(select(User).where(User.org_id == body.org_id, User.email == body.email))
    if existing is not None:
        raise HTTPException(status_code=409, detail="user already exists")
    user = User(org_id=body.org_id, email=body.email, name=body.name, role=body.role)
    db.add(user)
    db.flush()
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    org_id: uuid.UUID | None = None,
    email: str | None = None,
    db: Session = Depends(get_db),
):
    query = select(User)
    if org_id is not None:
        query = query.where(User.org_id == org_id)
    if email is not None:
        query = query.where(User.email == email)
    return db.scalars(query).all()
