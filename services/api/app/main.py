from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.engine import SessionLocal
from app.db.models import Admin, AdminStatus
from app.routers import admin, health, payments, sms, vendo
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


app = FastAPI(title="Centralized WiFi Roaming Platform", version="1.0.0")

app.include_router(health.router)
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(payments.router, prefix="/api/v1/payments", tags=["payments"])
app.include_router(sms.router, prefix="/api/v1/sms", tags=["sms"])
app.include_router(vendo.router, prefix="/api/v1/vendo", tags=["vendo"])


@app.on_event("startup")
def on_startup() -> None:
    db = SessionLocal()
    try:
        _ensure_bootstrap_admin(db)
    finally:
        db.close()

