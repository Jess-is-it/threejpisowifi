from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Device, DeviceEvent, Transaction, TransactionSource, User, Wallet
from app.deps import get_db
from app.providers.crypto import constant_time_equal, hmac_sha256_hex
from app.providers.tokenbox import TokenBox

router = APIRouter()


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _canonical_message(device_id: str, coin_amount: int, timestamp: int, nonce: str) -> bytes:
    return f"{device_id}:{coin_amount}:{timestamp}:{nonce}".encode()


class VendoCreditIn(BaseModel):
    device_id: str
    coin_amount: int = Field(..., gt=0)
    timestamp: int = Field(..., description="Unix epoch seconds")
    nonce: str
    hmac_signature: str = Field(..., description="hex(HMAC-SHA256(device_token, canonical_message))")

    # Optional: if present, credits a specific user wallet; otherwise credits the device's configured wallet_user_id.
    target_phone: str | None = None


@router.post("/credit")
def vendo_credit(payload: VendoCreditIn, db: Session = Depends(get_db)):
    # 1) Basic checks
    if abs(_now_epoch() - int(payload.timestamp)) > int(settings.vendo_event_tolerance_seconds):
        raise HTTPException(status_code=400, detail="Event timestamp outside tolerance window")

    d = db.query(Device).filter(Device.device_id == payload.device_id).one_or_none()
    if not d or d.status.value != "ACTIVE":
        raise HTTPException(status_code=401, detail="Unknown or inactive device")
    if not d.token_enc:
        raise HTTPException(status_code=500, detail="Device missing token_enc")

    # 2) Signature validation
    tb = TokenBox(settings.device_token_enc_key)
    token_plain = tb.decrypt(d.token_enc)
    expected = hmac_sha256_hex(token_plain.encode(), _canonical_message(payload.device_id, payload.coin_amount, payload.timestamp, payload.nonce))
    if not constant_time_equal(expected, payload.hmac_signature.lower()):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 3) Idempotency (nonce per device)
    ev = DeviceEvent(
        device_id=payload.device_id,
        timestamp=datetime.fromtimestamp(int(payload.timestamp), tz=timezone.utc),
        nonce=payload.nonce,
        raw=json.dumps(payload.model_dump(), separators=(",", ":")),
    )
    db.add(ev)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"ok": True, "idempotent": True}

    # 4) Credit wallet
    seconds = int(payload.coin_amount) * int(settings.vendo_seconds_per_coin)
    user: User | None = None
    if payload.target_phone:
        user = db.query(User).filter(User.phone == payload.target_phone).one_or_none()
    elif d.wallet_user_id:
        user = db.query(User).filter(User.id == d.wallet_user_id).one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="No target wallet (provide target_phone or configure device.wallet_user_id)")

    w = db.query(Wallet).filter(Wallet.user_id == user.id).with_for_update().one()
    w.time_remaining_seconds = max(0, w.time_remaining_seconds + seconds)
    db.add(
        Transaction(
            user_id=user.id,
            source=TransactionSource.COIN,
            amount_seconds=seconds,
            amount_money=0,
            ref=f"vendo:{payload.device_id}:{payload.nonce}",
        )
    )
    db.commit()
    return {"ok": True, "credited_seconds": seconds, "user_id": user.id, "time_remaining_seconds": w.time_remaining_seconds}


class VendoBatchIn(BaseModel):
    events: list[VendoCreditIn]


@router.post("/batch-credit")
def vendo_batch_credit(payload: VendoBatchIn, db: Session = Depends(get_db)):
    results = []
    for ev in payload.events:
        try:
            results.append(vendo_credit(ev, db))
        except HTTPException as e:
            results.append({"ok": False, "error": e.detail, "status_code": e.status_code, "nonce": ev.nonce})
    return {"ok": True, "results": results}

