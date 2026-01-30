from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.engine import SessionLocal
from app.db.models import Admin, AdminStatus
from app.db.models import Plan, PlanType
from app.routers import admin, health, payments, portal, sms, vendo
from app.security.passwords import hash_password


def _ensure_bootstrap_admin(db: Session) -> None:
    existing = db.query(Admin).filter(Admin.username == settings.admin_username).one_or_none()
    if existing:
        return
    db.add(
        Admin(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            status=AdminStatus.ACTIVE,
        )
    )
    db.commit()

def _ensure_default_plans(db: Session) -> None:
    # Seed minimal starter plans so the portal can be used immediately after install.
    # Operators can edit/delete these in Admin → Plans & Pricing.
    any_plan = db.query(Plan).limit(1).one_or_none()
    if any_plan:
        return
    db.add_all(
        [
            Plan(type=PlanType.TIME, duration_seconds=3600, price=10.00, metadata_json='{"name":"1 hour"}'),
            Plan(type=PlanType.TIME, duration_seconds=86400, price=50.00, metadata_json='{"name":"1 day"}'),
            Plan(type=PlanType.UNLIMITED, duration_seconds=None, price=0.00, metadata_json='{"name":"Unlimited"}'),
        ]
    )
    db.commit()


app = FastAPI(title="Centralized WiFi Roaming Platform", version="1.0.0")

app.include_router(health.router)
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(payments.router, prefix="/api/v1/payments", tags=["payments"])
app.include_router(portal.router, prefix="/api/v1/portal", tags=["portal"])
app.include_router(sms.router, prefix="/api/v1/sms", tags=["sms"])
app.include_router(vendo.router, prefix="/api/v1/vendo", tags=["vendo"])


@app.on_event("startup")
def on_startup() -> None:
    db = SessionLocal()
    try:
        _ensure_bootstrap_admin(db)
        _ensure_default_plans(db)
    finally:
        db.close()
