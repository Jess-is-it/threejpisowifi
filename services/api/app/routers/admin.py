from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.deps import get_db, require_admin
from app.db.models import (
    Admin,
    AdminStatus,
    AuditLog,
    Device,
    DeviceStatus,
    NAS,
    Session as DbSession,
    Transaction,
    TransactionSource,
    User,
    UserStatus,
    Wallet,
    WebhookLog,
)
from app.providers.crypto import random_token_urlsafe
from app.providers.tokenbox import TokenBox
from app.security.jwt import create_admin_token
from app.security.passwords import hash_password, verify_password
from app.core.config import settings

router = APIRouter()


def _audit(db: Session, actor: str, action: str, object_type: str, object_id: str, details: dict[str, Any]) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            details=json.dumps(details, separators=(",", ":")),
        )
    )


def _validate_e164(phone: str) -> None:
    # Minimal validation: starts with + and digits, length 8..18.
    if not phone.startswith("+"):
        raise HTTPException(status_code=400, detail="phone must be E.164 (e.g. +15551234567)")
    digits = phone[1:]
    if not digits.isdigit() or not (7 <= len(digits) <= 17):
        raise HTTPException(status_code=400, detail="phone must be E.164 (e.g. +15551234567)")


class LoginIn(BaseModel):
    username: str
    password: str


class LoginOut(BaseModel):
    token: str


@router.post("/auth/login", response_model=LoginOut)
def admin_login(body: LoginIn, db: Session = Depends(get_db)) -> LoginOut:
    admin = db.query(Admin).filter(Admin.username == body.username).one_or_none()
    if not admin or admin.status != AdminStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    admin.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return LoginOut(token=create_admin_token(admin.username))


class UserCreateIn(BaseModel):
    phone: str = Field(..., description="E.164 phone; used as WiFi username")
    password: str | None = Field(None, description="WiFi password (random if omitted)")


class UserOut(BaseModel):
    id: int
    phone: str
    username: str
    status: str
    created_at: datetime


@router.get("/users", response_model=list[UserOut])
def list_users(_: dict = Depends(require_admin), db: Session = Depends(get_db)) -> list[UserOut]:
    rows = db.query(User).order_by(User.id.desc()).limit(500).all()
    return [
        UserOut(id=u.id, phone=u.phone, username=u.username, status=u.status.value, created_at=u.created_at) for u in rows
    ]


@router.post("/users", response_model=UserOut)
def create_user(payload: UserCreateIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)) -> UserOut:
    _validate_e164(payload.phone)
    password = payload.password or random_token_urlsafe(9)
    u = User(
        phone=payload.phone,
        username=payload.phone,
        password_hash=hash_password(password),
        radius_password=password,
        status=UserStatus.ACTIVE,
    )
    w = Wallet(user=u, time_remaining_seconds=0, valid_until_ts=None, is_unlimited=False)
    db.add(u)
    db.add(w)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="User already exists")
    _audit(db, auth["username"], "CREATE", "user", str(u.id), {"phone": payload.phone})
    db.commit()
    return UserOut(id=u.id, phone=u.phone, username=u.username, status=u.status.value, created_at=u.created_at)


class ResetPasswordOut(BaseModel):
    username: str
    new_password: str


@router.post("/users/{user_id}/reset-password", response_model=ResetPasswordOut)
def reset_password(user_id: int, auth: dict = Depends(require_admin), db: Session = Depends(get_db)) -> ResetPasswordOut:
    u = db.query(User).filter(User.id == user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    new_pw = random_token_urlsafe(9)
    u.radius_password = new_pw
    u.password_hash = hash_password(new_pw)
    _audit(db, auth["username"], "RESET_PASSWORD", "user", str(u.id), {})
    db.commit()
    return ResetPasswordOut(username=u.username, new_password=new_pw)


class UserStatusIn(BaseModel):
    status: UserStatus


@router.post("/users/{user_id}/status")
def set_user_status(user_id: int, payload: UserStatusIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.status = payload.status
    _audit(db, auth["username"], "SET_STATUS", "user", str(u.id), {"status": payload.status.value})
    db.commit()
    return {"ok": True}


class WalletOut(BaseModel):
    user_id: int
    time_remaining_seconds: int
    valid_until_ts: datetime | None
    is_unlimited: bool


@router.get("/users/{user_id}/wallet", response_model=WalletOut)
def get_wallet(user_id: int, _: dict = Depends(require_admin), db: Session = Depends(get_db)) -> WalletOut:
    w = db.query(Wallet).filter(Wallet.user_id == user_id).one_or_none()
    if not w:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return WalletOut(
        user_id=w.user_id,
        time_remaining_seconds=w.time_remaining_seconds,
        valid_until_ts=w.valid_until_ts,
        is_unlimited=w.is_unlimited,
    )


class WalletCreditIn(BaseModel):
    user_id: int
    source: TransactionSource = TransactionSource.ADMIN
    amount_seconds: int = 0
    amount_money: float = 0
    ref: str = ""
    set_unlimited: bool = False
    extend_valid_until_seconds: int = 0


@router.post("/wallet/credit")
def credit_wallet(payload: WalletCreditIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == payload.user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    w = db.query(Wallet).filter(Wallet.user_id == payload.user_id).with_for_update().one()

    now = datetime.now(timezone.utc)
    if payload.set_unlimited:
        w.is_unlimited = True
    if payload.extend_valid_until_seconds > 0:
        base = w.valid_until_ts if w.valid_until_ts and w.valid_until_ts > now else now
        w.valid_until_ts = base + timedelta(seconds=int(payload.extend_valid_until_seconds))
    if payload.amount_seconds:
        w.time_remaining_seconds = max(0, w.time_remaining_seconds + int(payload.amount_seconds))

    db.add(
        Transaction(
            user_id=u.id,
            source=payload.source,
            amount_seconds=int(payload.amount_seconds),
            amount_money=float(payload.amount_money),
            ref=payload.ref or "",
        )
    )
    _audit(db, auth["username"], "CREDIT_WALLET", "wallet", str(u.id), payload.model_dump())
    db.commit()
    return {"ok": True}


class NASIn(BaseModel):
    name: str
    ip: str
    secret: str


@router.get("/nas")
def list_nas(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(NAS).order_by(NAS.id.asc()).all()
    return [{"id": n.id, "name": n.name, "ip": n.ip, "secret": n.secret} for n in rows]


@router.post("/nas")
def create_nas(payload: NASIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    n = NAS(
        name=payload.name,
        ip=payload.ip,
        secret=payload.secret,
        nasname=payload.ip,
        shortname=payload.name[:32],
        type="other",
    )
    db.add(n)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="NAS already exists")
    _audit(db, auth["username"], "CREATE", "nas", str(n.id), {"ip": n.ip})
    db.commit()
    return {"ok": True, "id": n.id}


class DeviceCreateIn(BaseModel):
    device_id: str
    wallet_user_id: int | None = None


@router.get("/devices")
def list_devices(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(Device).order_by(Device.id.desc()).limit(500).all()
    return [
        {
            "id": d.id,
            "device_id": d.device_id,
            "status": d.status.value,
            "wallet_user_id": d.wallet_user_id,
            "created_at": d.created_at,
        }
        for d in rows
    ]


@router.post("/devices")
def create_device(payload: DeviceCreateIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    token_plain = random_token_urlsafe(24)
    tb = TokenBox(settings.device_token_enc_key)
    token_enc = tb.encrypt(token_plain)
    d = Device(
        device_id=payload.device_id,
        token_hash=hash_password(token_plain),
        token_enc=token_enc,
        status=DeviceStatus.ACTIVE,
        wallet_user_id=payload.wallet_user_id,
    )
    db.add(d)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Device already exists")
    _audit(db, auth["username"], "CREATE", "device", str(d.id), {"device_id": d.device_id})
    db.commit()
    return {
        "ok": True,
        "id": d.id,
        "device_id": d.device_id,
        "device_token": token_plain,  # shown once
    }


@router.get("/sessions")
def list_sessions(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = (
        db.query(DbSession)
        .filter(DbSession.stop.is_(None))
        .order_by(DbSession.last_update.desc())
        .limit(500)
        .all()
    )
    return [
        {
            "id": s.id,
            "user_id": s.user_id,
            "nas_id": s.nas_id,
            "calling_station_id": s.calling_station_id,
            "acct_session_id": s.acct_session_id,
            "start": s.start,
            "last_update": s.last_update,
            "stop": s.stop,
        }
        for s in rows
    ]


@router.get("/webhooks")
def list_webhooks(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(WebhookLog).order_by(WebhookLog.id.desc()).limit(200).all()
    return [
        {
            "id": w.id,
            "kind": w.kind,
            "idempotency_key": w.idempotency_key,
            "created_at": w.created_at,
            "payload": w.payload,
        }
        for w in rows
    ]


@router.get("/audit-logs")
def list_audit_logs(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    return [
        {
            "id": a.id,
            "actor": a.actor,
            "action": a.action,
            "object_type": a.object_type,
            "object_id": a.object_id,
            "created_at": a.created_at,
            "details": a.details,
        }
        for a in rows
    ]
