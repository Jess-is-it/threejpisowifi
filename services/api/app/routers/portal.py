from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

import redis
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.deps import get_client_ip, get_db, require_user
from app.db.models import Plan, PlanType, Transaction, TransactionSource, User, UserStatus, Wallet, WebhookLog
from app.providers.crypto import random_token_urlsafe
from app.providers.sms import get_sms_provider
from app.security.jwt import create_user_token
from app.security.passwords import hash_password, verify_password

router = APIRouter()


def _validate_e164(phone: str) -> None:
    if not phone.startswith("+"):
        raise HTTPException(status_code=400, detail="phone must be E.164 (e.g. +639171234567)")
    digits = phone[1:]
    if not digits.isdigit() or not (7 <= len(digits) <= 17):
        raise HTTPException(status_code=400, detail="phone must be E.164 (e.g. +639171234567)")


def _redis() -> redis.Redis | None:
    try:
        return redis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        return None


def _rate_limit(key: str, limit: int, window_seconds: int) -> None:
    r = _redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds, nx=True)
        count, _ = pipe.execute()
        if int(count) > int(limit):
            raise HTTPException(status_code=429, detail="Too many requests; try again later")
    except HTTPException:
        raise
    except Exception:
        # Fail open if Redis is down.
        return


class CredentialRequestIn(BaseModel):
    phone: str


@router.post("/credentials/request")
def request_credentials(payload: CredentialRequestIn, request: Request, db: Session = Depends(get_db)):
    """
    End-user helper:
    - Creates the user if missing.
    - Resets password if user exists.
    - Sends credentials via SMS provider (mock by default).
    """
    phone = payload.phone.strip()
    _validate_e164(phone)

    ip = get_client_ip(request)
    _rate_limit(f"portal:credreq:phone:{phone}", limit=3, window_seconds=3600)
    _rate_limit(f"portal:credreq:ip:{ip}", limit=20, window_seconds=3600)

    u = db.query(User).filter(User.phone == phone).one_or_none()
    if u and u.status != UserStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="User is disabled")

    new_pw = random_token_urlsafe(9)
    created = False
    if not u:
        created = True
        u = User(
            phone=phone,
            username=phone,
            password_hash=hash_password(new_pw),
            radius_password=new_pw,
            status=UserStatus.ACTIVE,
        )
        w = Wallet(user=u, time_remaining_seconds=0, valid_until_ts=None, is_unlimited=False)
        db.add(u)
        db.add(w)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            # Race: user created between query and insert.
            u = db.query(User).filter(User.phone == phone).one()
            u.password_hash = hash_password(new_pw)
            u.radius_password = new_pw
            db.commit()
    else:
        u.password_hash = hash_password(new_pw)
        u.radius_password = new_pw
        db.commit()

    msg = (
        "Central WiFi credentials:\n"
        f"Username: {phone}\n"
        f"Password: {new_pw}\n\n"
        f"Top-up portal: {settings.cw_public_base_url.rstrip('/')}/portal"
    )
    provider = get_sms_provider()
    provider.send(db, phone, msg)
    db.commit()
    return {"ok": True, "created": created, "provider": getattr(provider, "provider_name", "mock")}


class PortalLoginIn(BaseModel):
    phone: str
    password: str


@router.post("/auth/login")
def portal_login(payload: PortalLoginIn, db: Session = Depends(get_db)):
    phone = payload.phone.strip()
    _validate_e164(phone)
    u = db.query(User).filter(User.phone == phone).one_or_none()
    if not u or u.status != UserStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_user_token(u.id, u.username)}


@router.get("/me")
def me(auth: dict = Depends(require_user), db: Session = Depends(get_db)):
    uid = int(auth.get("user_id", 0))
    w = db.query(Wallet).filter(Wallet.user_id == uid).one_or_none()
    if not w:
        raise HTTPException(status_code=404, detail="Wallet not found")
    now = datetime.now(timezone.utc)
    has_credit = bool(w.is_unlimited) or (w.valid_until_ts and w.valid_until_ts > now) or (w.time_remaining_seconds > 0)
    return {
        "user_id": uid,
        "username": auth.get("username", ""),
        "wallet": {
            "time_remaining_seconds": int(w.time_remaining_seconds),
            "valid_until_ts": w.valid_until_ts,
            "is_unlimited": bool(w.is_unlimited),
            "has_credit": has_credit,
        },
    }


@router.get("/plans")
def list_plans(db: Session = Depends(get_db)):
    rows = db.query(Plan).order_by(Plan.id.asc()).limit(200).all()
    out = []
    for p in rows:
        try:
            meta = json.loads(p.metadata_json or "{}")
        except Exception:
            meta = {}
        out.append(
            {
                "id": p.id,
                "type": p.type.value,
                "duration_seconds": p.duration_seconds,
                "price": float(p.price),
                "metadata": meta,
            }
        )
    return out


class TopupIn(BaseModel):
    plan_id: int
    idempotency_key: str = Field("", description="Client-generated idempotency key")


def _apply_plan_to_wallet(db: Session, w: Wallet, p: Plan) -> int:
    now = datetime.now(timezone.utc)
    seconds = int(p.duration_seconds or 0)
    if p.type == PlanType.TIME:
        if seconds <= 0:
            raise HTTPException(status_code=400, detail="Invalid TIME plan duration")
        w.time_remaining_seconds = max(0, int(w.time_remaining_seconds) + seconds)
        return seconds
    if p.type == PlanType.DATE:
        # Treat duration_seconds as a validity extension window.
        if seconds <= 0:
            # Allow metadata override for DATE plans.
            try:
                meta = json.loads(p.metadata_json or "{}")
                seconds = int(meta.get("validity_seconds") or 0)
            except Exception:
                seconds = 0
        if seconds <= 0:
            raise HTTPException(status_code=400, detail="Invalid DATE plan validity window")
        base = w.valid_until_ts if (w.valid_until_ts and w.valid_until_ts > now) else now
        w.valid_until_ts = base + timedelta(seconds=seconds)
        return seconds
    if p.type == PlanType.UNLIMITED:
        w.is_unlimited = True
        return 0
    raise HTTPException(status_code=400, detail="Unknown plan type")


@router.post("/topup")
def topup(payload: TopupIn, auth: dict = Depends(require_user), db: Session = Depends(get_db)):
    """
    Production behavior:
    - For real gateways, this should create a checkout session and wait for a verified webhook.

    Default behavior (mock):
    - Immediately applies the plan as if a verified webhook was received.
    - Uses WebhookLog to enforce idempotency.
    """
    if settings.payment_provider != "mock":
        raise HTTPException(status_code=501, detail="Payment provider not configured (use mock)")

    uid = int(auth.get("user_id", 0))
    plan = db.query(Plan).filter(Plan.id == int(payload.plan_id)).one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    key = (payload.idempotency_key or "").strip() or f"portal-{uid}-{secrets.token_hex(8)}"

    # 1) Ensure idempotency.
    db.add(
        WebhookLog(
            kind="PAYMENT",
            idempotency_key=key,
            payload=json.dumps({"plan_id": int(plan.id), "user_id": uid, "mode": "portal-mock"}, separators=(",", ":")),
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"ok": True, "idempotent": True}

    # 2) Apply plan to wallet atomically.
    w = db.query(Wallet).filter(Wallet.user_id == uid).with_for_update().one()
    delta_seconds = _apply_plan_to_wallet(db, w, plan)
    db.add(
        Transaction(
            user_id=uid,
            source=TransactionSource.PAYMENT,
            amount_seconds=int(delta_seconds),
            amount_money=float(plan.price),
            ref=key,
        )
    )
    db.commit()
    return {"ok": True, "ref": key}

