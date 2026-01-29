from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.deps import get_db, require_admin
from app.db.models import SMSLog
from app.providers.sms import get_sms_provider

router = APIRouter()


class SMSTestIn(BaseModel):
    to_phone: str
    message: str


@router.post("/test")
def sms_test(payload: SMSTestIn, _: dict = Depends(require_admin), db: Session = Depends(get_db)):
    provider = get_sms_provider()
    provider.send(db, payload.to_phone, payload.message)
    return {"ok": True, "provider": getattr(provider, "provider_name", "mock")}


@router.get("/logs")
def sms_logs(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(SMSLog).order_by(SMSLog.id.desc()).limit(200).all()
    return [
        {
            "id": r.id,
            "to_phone": r.to_phone,
            "message": r.message,
            "provider": r.provider,
            "status": r.status,
            "created_at": r.created_at,
        }
        for r in rows
    ]

