from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.engine import SessionLocal
from app.db.models import Transaction, TransactionSource, User, Wallet, WebhookLog

router = APIRouter()


class CheckoutIn(BaseModel):
    phone: str = Field(..., description="E.164 phone (must already exist as a user)")
    amount_seconds: int = Field(..., gt=0)
    amount_money: float = Field(0, ge=0)
    ref: str = Field("", description="Payment reference / order id")


@router.post("/checkout")
def checkout(payload: CheckoutIn):
    # Mock gateway: returns a deterministic "payment_ref" that can be used to trigger a webhook.
    payment_ref = payload.ref or f"mock-{int(datetime.now(timezone.utc).timestamp())}"
    return {
        "provider": "mock",
        "payment_ref": payment_ref,
        "webhook_url": "/api/v1/payments/webhook/mock",
        "next": {
            "how_to_complete": "POST the same payload to /api/v1/payments/webhook/mock with Idempotency-Key header",
        },
    }


class MockWebhookIn(BaseModel):
    phone: str
    amount_seconds: int = Field(..., gt=0)
    amount_money: float = Field(0, ge=0)
    ref: str = ""
    status: str = Field("paid", description="paid|failed")


@router.post("/webhook/mock")
def webhook_mock(
    payload: MockWebhookIn,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    if payload.status != "paid":
        return {"ok": True, "ignored": True}
    key = idempotency_key or payload.ref or f"mock-{request.headers.get('x-request-id','')}"
    if not key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key (or ref)")

    db: Session = SessionLocal()
    try:
        # 1) Ensure idempotency (unique constraint).
        db.add(
            WebhookLog(
                kind="PAYMENT",
                idempotency_key=key,
                payload=json.dumps(payload.model_dump(), separators=(",", ":")),
            )
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {"ok": True, "idempotent": True}

        # 2) Credit wallet after webhook is "verified".
        u = db.query(User).filter(User.phone == payload.phone).one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        w = db.query(Wallet).filter(Wallet.user_id == u.id).with_for_update().one()
        w.time_remaining_seconds = max(0, w.time_remaining_seconds + int(payload.amount_seconds))
        db.add(
            Transaction(
                user_id=u.id,
                source=TransactionSource.PAYMENT,
                amount_seconds=int(payload.amount_seconds),
                amount_money=float(payload.amount_money),
                ref=payload.ref or key,
            )
        )
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@router.post("/webhook/maya")
def webhook_maya_skeleton():
    # Adapter stub: implement signature verification and payload parsing via env-based credentials.
    raise HTTPException(status_code=501, detail="Maya adapter not configured (use mock)")

