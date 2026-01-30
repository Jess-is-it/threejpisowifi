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
    DeviceEvent,
    NAS,
    Plan,
    PlanType,
    Session as DbSession,
    Transaction,
    TransactionSource,
    User,
    UserStatus,
    Wallet,
    WebhookLog,
    SystemSetting,
)
from app.providers.crypto import random_token_urlsafe
from app.providers.tokenbox import TokenBox
from app.security.jwt import create_admin_token
from app.security.passwords import hash_password, verify_password
from app.core.config import settings

router = APIRouter()

def _setting_get(db: Session, key: str, default: str = "") -> str:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).one_or_none()
    return row.value if row else default


def _setting_set(db: Session, key: str, value: str) -> None:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).one_or_none()
    if row:
        row.value = value
        db.add(row)
        db.commit()
        return
    db.add(SystemSetting(key=key, value=value))
    db.commit()


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

@router.get("/transactions")
def list_transactions(
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
    user_id: int | None = None,
    limit: int = 200,
):
    limit = max(1, min(int(limit), 500))
    q = db.query(Transaction).order_by(Transaction.id.desc())
    if user_id is not None:
        q = q.filter(Transaction.user_id == int(user_id))
    rows = q.limit(limit).all()
    return [
        {
            "id": t.id,
            "user_id": t.user_id,
            "source": t.source.value,
            "amount_seconds": t.amount_seconds,
            "amount_money": float(t.amount_money),
            "ref": t.ref,
            "created_at": t.created_at,
        }
        for t in rows
    ]


class PlanIn(BaseModel):
    type: PlanType
    duration_seconds: int | None = None
    price: float = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.get("/plans")
def list_plans(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(Plan).order_by(Plan.id.asc()).limit(500).all()
    return [
        {
            "id": p.id,
            "type": p.type.value,
            "duration_seconds": p.duration_seconds,
            "price": float(p.price),
            "metadata": json.loads(p.metadata_json or "{}"),
        }
        for p in rows
    ]


@router.post("/plans")
def create_plan(payload: PlanIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    if payload.type == PlanType.TIME and (not payload.duration_seconds or payload.duration_seconds <= 0):
        raise HTTPException(status_code=400, detail="TIME plans require duration_seconds > 0")
    if payload.type == PlanType.DATE and payload.duration_seconds:
        raise HTTPException(status_code=400, detail="DATE plans should not set duration_seconds")
    if payload.type == PlanType.UNLIMITED and payload.duration_seconds:
        raise HTTPException(status_code=400, detail="UNLIMITED plans should not set duration_seconds")

    p = Plan(
        type=payload.type,
        duration_seconds=payload.duration_seconds,
        price=float(payload.price),
        metadata_json=json.dumps(payload.metadata, separators=(",", ":")),
    )
    db.add(p)
    db.commit()
    _audit(db, auth["username"], "CREATE", "plan", str(p.id), {"type": payload.type.value})
    db.commit()
    return {"ok": True, "id": p.id}


@router.put("/plans/{plan_id}")
def update_plan(plan_id: int, payload: PlanIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    p = db.query(Plan).filter(Plan.id == plan_id).one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Plan not found")
    p.type = payload.type
    p.duration_seconds = payload.duration_seconds
    p.price = float(payload.price)
    p.metadata_json = json.dumps(payload.metadata, separators=(",", ":"))
    db.commit()
    _audit(db, auth["username"], "UPDATE", "plan", str(p.id), {"type": payload.type.value})
    db.commit()
    return {"ok": True}


@router.delete("/plans/{plan_id}")
def delete_plan(plan_id: int, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    p = db.query(Plan).filter(Plan.id == plan_id).one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Plan not found")
    db.delete(p)
    db.commit()
    _audit(db, auth["username"], "DELETE", "plan", str(plan_id), {})
    db.commit()
    return {"ok": True}


@router.get("/device-events")
def list_device_events(_: dict = Depends(require_admin), db: Session = Depends(get_db), limit: int = 200):
    limit = max(1, min(int(limit), 500))
    rows = db.query(DeviceEvent).order_by(DeviceEvent.id.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "device_id": e.device_id,
            "timestamp": e.timestamp,
            "nonce": e.nonce,
            "raw": e.raw,
            "created_at": e.created_at,
        }
        for e in rows
    ]


@router.post("/sessions/{session_id}/terminate")
def terminate_session(session_id: int, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    s = db.query(DbSession).filter(DbSession.id == session_id).one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    if s.stop is not None:
        return {"ok": True, "already_stopped": True}
    s.stop = datetime.now(timezone.utc)
    _audit(db, auth["username"], "TERMINATE", "session", str(s.id), {"user_id": s.user_id, "calling_station_id": s.calling_station_id})
    db.commit()
    return {"ok": True}


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


@router.get("/system/info")
def system_info(_: dict = Depends(require_admin)):
    # Admin-only helper for the setup wizard and operator visibility.
    return {
        "cw_public_base_url": settings.cw_public_base_url,
        "jwt_issuer": settings.jwt_issuer,
        "active_session_grace_seconds": int(settings.active_session_grace_seconds),
        "radius": {
            "auth_port_udp": 1812,
            "acct_port_udp": 1813,
            "shared_secret": settings.radius_shared_secret,
        },
        "sms_provider": settings.sms_provider,
        "payment_provider": settings.payment_provider,
        "vendo": {
            "seconds_per_coin": int(settings.vendo_seconds_per_coin),
            "event_tolerance_seconds": int(settings.vendo_event_tolerance_seconds),
        },
    }


@router.get("/system/setup")
def get_setup_state(_: dict = Depends(require_admin), db: Session = Depends(get_db)):
    completed = _setting_get(db, "setup_completed", "false").lower() == "true"
    completed_at = _setting_get(db, "setup_completed_at", "")
    state_raw = _setting_get(db, "setup_state", "{}")
    try:
        state = json.loads(state_raw or "{}")
    except Exception:
        state = {}
    return {"completed": completed, "completed_at": completed_at or None, "state": state}


class SetupStateIn(BaseModel):
    state: dict[str, Any] = Field(default_factory=dict)


@router.put("/system/setup")
def put_setup_state(payload: SetupStateIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    _setting_set(db, "setup_state", json.dumps(payload.state or {}, separators=(",", ":")))
    _audit(db, auth["username"], "UPDATE", "system_setup", "setup_state", {"keys": list((payload.state or {}).keys())})
    db.commit()
    return {"ok": True}


@router.post("/system/setup/complete")
def complete_setup(auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc).isoformat()
    _setting_set(db, "setup_completed", "true")
    _setting_set(db, "setup_completed_at", now)
    _audit(db, auth["username"], "COMPLETE", "system_setup", "setup", {"at": now})
    db.commit()
    return {"ok": True, "completed_at": now}


@router.post("/system/setup/reset")
def reset_setup(auth: dict = Depends(require_admin), db: Session = Depends(get_db)):
    _setting_set(db, "setup_completed", "false")
    _setting_set(db, "setup_completed_at", "")
    _audit(db, auth["username"], "RESET", "system_setup", "setup", {})
    db.commit()
    return {"ok": True}


class FeaturesOut(BaseModel):
    walled_garden_on_no_credit: bool
    walled_garden_vlan_id: int
    portal_url: str


@router.get("/system/features", response_model=FeaturesOut)
def get_features(_: dict = Depends(require_admin), db: Session = Depends(get_db)) -> FeaturesOut:
    wg = _setting_get(db, "walled_garden_on_no_credit", "0").strip()
    vlan = _setting_get(db, "walled_garden_vlan_id", "0").strip()
    try:
        vlan_i = int(vlan or "0")
    except Exception:
        vlan_i = 0
    portal_url = settings.cw_public_base_url.rstrip("/") + "/portal"
    return FeaturesOut(walled_garden_on_no_credit=(wg == "1" or wg.lower() == "true"), walled_garden_vlan_id=vlan_i, portal_url=portal_url)


class FeaturesIn(BaseModel):
    walled_garden_on_no_credit: bool = False
    walled_garden_vlan_id: int = 0


@router.put("/system/features", response_model=FeaturesOut)
def put_features(payload: FeaturesIn, auth: dict = Depends(require_admin), db: Session = Depends(get_db)) -> FeaturesOut:
    on = "1" if bool(payload.walled_garden_on_no_credit) else "0"
    vlan = str(max(0, int(payload.walled_garden_vlan_id or 0)))
    _setting_set(db, "walled_garden_on_no_credit", on)
    _setting_set(db, "walled_garden_vlan_id", vlan)
    _audit(db, auth["username"], "UPDATE", "system_features", "walled_garden", {"on": on, "vlan": vlan})
    db.commit()
    portal_url = settings.cw_public_base_url.rstrip("/") + "/portal"
    return FeaturesOut(walled_garden_on_no_credit=(on == "1"), walled_garden_vlan_id=int(vlan), portal_url=portal_url)
