import os
import secrets
from datetime import datetime, timezone
from typing import Optional

import redis
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from .db import fetch_all, fetch_one, get_conn
from .security import create_token, current_admin, hash_password, verify_password

app = FastAPI(title="3JCentralPisowifi API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)
    confirm_password: str = Field(min_length=8)


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=8)
    phone_number: Optional[str] = None


class UserUpdate(BaseModel):
    phone_number: Optional[str] = None
    status: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=8)


class TopUpRequest(BaseModel):
    amount_seconds: int = Field(ge=0)
    valid_until: Optional[datetime] = None
    is_unlimited: bool = False
    note: Optional[str] = None


class NasCreate(BaseModel):
    name: str
    nas_ip: str
    shortname: str
    secret: Optional[str] = None
    type: str = "other"
    notes: Optional[str] = None


class SystemSettingsUpdate(BaseModel):
    branding: Optional[dict] = None
    access: Optional[dict] = None
    backup: Optional[dict] = None


class AdminCreate(BaseModel):
    username: str
    password: str = Field(min_length=8)
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: str = "admin"


class AdminUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=8)


class DangerAction(BaseModel):
    action: str
    confirmation: str
    current_password: str


def audit(actor_id: str, action: str, target_type: str = None, target_id: str = None, details: dict = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_logs(actor_admin_id, action, target_type, target_id, details) VALUES (%s, %s, %s, %s, %s)",
                (actor_id, action, target_type, target_id, Json(details or {})),
            )


@app.get("/health")
def health():
    db_ok = bool(fetch_one("SELECT 1 AS ok"))
    redis_ok = False
    try:
        r = redis.Redis.from_url(os.environ["REDIS_URL"], socket_connect_timeout=1)
        redis_ok = r.ping()
    except Exception:
        redis_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "environment": os.getenv("APP_ENV", "unknown"),
        "database": db_ok,
        "redis": bool(redis_ok),
        "radius_ports": {
            "auth": int(os.getenv("RADIUS_AUTH_PORT", "1812")),
            "accounting": int(os.getenv("RADIUS_ACCT_PORT", "1813")),
        },
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    admin = fetch_one("SELECT id, username, password_hash, role, status, full_name, email FROM admins WHERE username = %s", (payload.username,))
    if not admin or admin["status"] != "active" or not verify_password(payload.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return {"token": create_token(admin), "admin": {"username": admin["username"], "role": admin["role"], "full_name": admin["full_name"], "email": admin["email"]}}


@app.get("/api/public/branding")
def public_branding():
    row = fetch_one("SELECT value FROM app_settings WHERE key = 'system'")
    value = row["value"] if row else {}
    branding = value.get("branding", {})
    return {
        "display_name": branding.get("display_name", "3JCentralPisowifi"),
        "portal_subtitle": branding.get("portal_subtitle", "Source of Truth + Manual RADIUS Test MVP"),
        "accent_color": branding.get("accent_color", "#206bc4"),
    }


@app.get("/api/me")
def me(admin=Depends(current_admin)):
    profile = fetch_one("SELECT id, username, role, status, full_name, email, created_at, updated_at FROM admins WHERE id = %s", (admin["id"],))
    return profile


@app.patch("/api/me")
def update_me(payload: ProfileUpdate, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE admins SET full_name = COALESCE(%s, full_name), email = COALESCE(%s, email), updated_at = now() WHERE id = %s",
                (payload.full_name, payload.email, admin["id"]),
            )
    audit(admin["id"], "update_profile", "admin", str(admin["id"]), payload.model_dump(exclude_none=True))
    return {"status": "ok"}


@app.post("/api/me/change-password")
def change_password(payload: ChangePasswordRequest, admin=Depends(current_admin)):
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")
    row = fetch_one("SELECT password_hash FROM admins WHERE id = %s", (admin["id"],))
    if not row or not verify_password(payload.current_password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE admins SET password_hash = %s, updated_at = now() WHERE id = %s", (hash_password(payload.new_password), admin["id"]))
    audit(admin["id"], "change_password", "admin", str(admin["id"]))
    return {"status": "ok"}


@app.get("/api/dashboard")
def dashboard(admin=Depends(current_admin)):
    health_data = health()
    stats = fetch_one(
        """
        SELECT
          (SELECT count(*) FROM users) AS total_users,
          (SELECT count(*) FROM nas_clients WHERE status = 'active') AS nas_clients,
          (SELECT count(*) FROM sessions WHERE stop_time IS NULL) AS active_sessions
        """
    )
    recent_auth = fetch_all(
        "SELECT username, nas_ip::text, calling_station_id, result, reply_message, created_at FROM radius_auth_logs ORDER BY created_at DESC LIMIT 10"
    )
    return {"environment": os.getenv("APP_ENV", "unknown"), "health": health_data, "stats": stats, "recent_auth": recent_auth}


@app.get("/api/users")
def list_users(admin=Depends(current_admin)):
    return fetch_all(
        """
        SELECT u.id, u.username, u.phone_number, u.status, u.created_at, w.time_remaining_seconds,
               w.valid_until, w.is_unlimited
        FROM users u
        LEFT JOIN wallets w ON w.user_id = u.id
        ORDER BY u.created_at DESC
        """
    )


@app.post("/api/users")
def create_user(payload: UserCreate, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users(username, phone_number, password_hash) VALUES (%s, %s, %s) RETURNING id",
                (payload.username, payload.phone_number, hash_password(payload.password)),
            )
            user_id = cur.fetchone()["id"]
            cur.execute("INSERT INTO wallets(user_id) VALUES (%s)", (user_id,))
            cur.execute(
                "INSERT INTO radcheck(username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s) ON CONFLICT (username, attribute) DO UPDATE SET value = EXCLUDED.value",
                (payload.username, payload.password),
            )
    audit(admin["id"], "create_user", "user", str(user_id), {"username": payload.username})
    return {"id": user_id}


@app.get("/api/users/{user_id}")
def get_user(user_id: str, admin=Depends(current_admin)):
    user = fetch_one(
        """
        SELECT u.id, u.username, u.phone_number, u.status, u.created_at, u.updated_at,
               w.time_remaining_seconds, w.valid_until, w.is_unlimited, w.updated_at AS wallet_updated_at
        FROM users u LEFT JOIN wallets w ON w.user_id = u.id WHERE u.id = %s
        """,
        (user_id,),
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    sessions = fetch_all("SELECT * FROM sessions WHERE user_id = %s ORDER BY start_time DESC LIMIT 25", (user_id,))
    transactions = fetch_all("SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC LIMIT 25", (user_id,))
    return {"user": user, "sessions": sessions, "transactions": transactions}


@app.patch("/api/users/{user_id}")
def update_user(user_id: str, payload: UserUpdate, admin=Depends(current_admin)):
    user = fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    with get_conn() as conn:
        with conn.cursor() as cur:
            if payload.phone_number is not None:
                cur.execute("UPDATE users SET phone_number = %s, updated_at = now() WHERE id = %s", (payload.phone_number, user_id))
            if payload.status is not None:
                cur.execute("UPDATE users SET status = %s, updated_at = now() WHERE id = %s", (payload.status, user_id))
            if payload.password:
                cur.execute("UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s", (hash_password(payload.password), user_id))
                cur.execute(
                    "INSERT INTO radcheck(username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s) ON CONFLICT (username, attribute) DO UPDATE SET value = EXCLUDED.value",
                    (user["username"], payload.password),
                )
    audit(admin["id"], "update_user", "user", user_id, payload.model_dump(exclude_none=True))
    return {"status": "ok"}


@app.post("/api/users/{user_id}/top-up")
def top_up(user_id: str, payload: TopUpRequest, admin=Depends(current_admin)):
    user = fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE wallets
                SET time_remaining_seconds = time_remaining_seconds + %s,
                    valid_until = COALESCE(%s, valid_until),
                    is_unlimited = %s,
                    updated_at = now()
                WHERE user_id = %s
                """,
                (payload.amount_seconds, payload.valid_until, payload.is_unlimited, user_id),
            )
            cur.execute(
                """
                INSERT INTO transactions(user_id, source, type, amount_seconds, note, created_by)
                VALUES (%s, 'ADMIN', 'MANUAL_TIME_TOPUP', %s, %s, %s)
                """,
                (user_id, payload.amount_seconds, payload.note, admin["id"]),
            )
    audit(admin["id"], "manual_top_up", "user", user_id, payload.model_dump(mode="json"))
    return {"status": "ok"}


@app.get("/api/sessions")
def list_sessions(admin=Depends(current_admin)):
    return fetch_all("SELECT * FROM sessions ORDER BY last_update_time DESC LIMIT 200")


@app.get("/api/nas-clients")
def list_nas(admin=Depends(current_admin)):
    return fetch_all("SELECT id, name, nas_ip::text, shortname, type, status, notes, created_at, updated_at FROM nas_clients ORDER BY created_at DESC")


@app.post("/api/nas-clients")
def create_nas(payload: NasCreate, admin=Depends(current_admin)):
    secret = payload.secret or os.getenv("RADIUS_DEFAULT_SECRET") or secrets.token_urlsafe(24)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO nas_clients(name, nas_ip, shortname, secret, type, notes)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
                """,
                (payload.name, payload.nas_ip, payload.shortname, secret, payload.type, payload.notes),
            )
            nas_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO nas(nasname, shortname, type, secret, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (shortname) DO UPDATE SET nasname = EXCLUDED.nasname, secret = EXCLUDED.secret, type = EXCLUDED.type
                """,
                (payload.nas_ip, payload.shortname, payload.type, secret, payload.name),
            )
    audit(admin["id"], "create_nas_client", "nas_client", str(nas_id), {"shortname": payload.shortname})
    return {"id": nas_id, "secret": secret}


@app.post("/api/nas-clients/{nas_id}/rotate-secret")
def rotate_secret(nas_id: str, admin=Depends(current_admin)):
    new_secret = secrets.token_urlsafe(24)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE nas_clients SET secret = %s, updated_at = now() WHERE id = %s RETURNING shortname", (new_secret, nas_id))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="NAS client not found")
            cur.execute("UPDATE nas SET secret = %s WHERE shortname = %s", (new_secret, row["shortname"]))
    audit(admin["id"], "rotate_nas_secret", "nas_client", nas_id)
    return {"secret": new_secret}


@app.get("/api/auth-logs")
def auth_logs(admin=Depends(current_admin)):
    return fetch_all("SELECT username, nas_ip::text, nas_identifier, calling_station_id, result, reply_message, created_at FROM radius_auth_logs ORDER BY created_at DESC LIMIT 200")


@app.get("/api/audit-logs")
def audit_logs(admin=Depends(current_admin)):
    return fetch_all("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200")


@app.get("/api/settings")
def settings(admin=Depends(current_admin)):
    return {
        "environment": os.getenv("APP_ENV", "unknown").title(),
        "active_session_grace_seconds": int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180")),
        "radius_auth_port": int(os.getenv("RADIUS_AUTH_PORT", "1812")),
        "radius_accounting_port": int(os.getenv("RADIUS_ACCT_PORT", "1813")),
    }


def system_settings_payload():
    row = fetch_one("SELECT value FROM app_settings WHERE key = 'system'")
    value = row["value"] if row else {}
    return {
        "branding": value.get("branding", {}),
        "access": value.get("access", {}),
        "backup": value.get("backup", {}),
        "environment": os.getenv("APP_ENV", "unknown"),
        "install_dir": os.getenv("INSTALL_DIR", ""),
        "compose_project_name": os.getenv("COMPOSE_PROJECT_NAME", ""),
        "database_name": os.getenv("POSTGRES_DB", ""),
    }


@app.get("/api/system/settings")
def get_system_settings(admin=Depends(current_admin)):
    return system_settings_payload()


@app.patch("/api/system/settings")
def update_system_settings(payload: SystemSettingsUpdate, admin=Depends(current_admin)):
    current = system_settings_payload()
    merged = {
        "branding": {**current.get("branding", {}), **(payload.branding or {})},
        "access": {**current.get("access", {}), **(payload.access or {})},
        "backup": {**current.get("backup", {}), **(payload.backup or {})},
    }
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_settings(key, value, updated_at)
                VALUES ('system', %s, now())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """,
                (Json(merged),),
            )
    audit(admin["id"], "update_system_settings", "system", "system", merged)
    return system_settings_payload()


@app.get("/api/system/access/admins")
def list_admins(admin=Depends(current_admin)):
    return fetch_all("SELECT id, username, full_name, email, role, status, created_at, updated_at FROM admins ORDER BY created_at DESC")


@app.post("/api/system/access/admins")
def create_admin(payload: AdminCreate, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO admins(username, password_hash, role, status, full_name, email)
                VALUES (%s, %s, %s, 'active', %s, %s)
                RETURNING id
                """,
                (payload.username, hash_password(payload.password), payload.role, payload.full_name, payload.email),
            )
            admin_id = cur.fetchone()["id"]
    audit(admin["id"], "create_admin", "admin", str(admin_id), {"username": payload.username, "role": payload.role})
    return {"id": admin_id}


@app.patch("/api/system/access/admins/{admin_id}")
def update_admin(admin_id: str, payload: AdminUpdate, admin=Depends(current_admin)):
    if admin_id == str(admin["id"]) and payload.status and payload.status != "active":
        raise HTTPException(status_code=400, detail="You cannot disable your own active admin account")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM admins WHERE id = %s", (admin_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Admin not found")
            if payload.full_name is not None:
                cur.execute("UPDATE admins SET full_name = %s, updated_at = now() WHERE id = %s", (payload.full_name, admin_id))
            if payload.email is not None:
                cur.execute("UPDATE admins SET email = %s, updated_at = now() WHERE id = %s", (payload.email, admin_id))
            if payload.role is not None:
                cur.execute("UPDATE admins SET role = %s, updated_at = now() WHERE id = %s", (payload.role, admin_id))
            if payload.status is not None:
                cur.execute("UPDATE admins SET status = %s, updated_at = now() WHERE id = %s", (payload.status, admin_id))
            if payload.password:
                cur.execute("UPDATE admins SET password_hash = %s, updated_at = now() WHERE id = %s", (hash_password(payload.password), admin_id))
    audit(admin["id"], "update_admin", "admin", admin_id, payload.model_dump(exclude_none=True))
    return {"status": "ok"}


@app.get("/api/system/backup")
def backup_status(admin=Depends(current_admin)):
    env = os.getenv("APP_ENV", "staging")
    install_dir = os.getenv("INSTALL_DIR", "")
    return {
        "environment": env,
        "install_dir": install_dir,
        "backup_command": f"sudo {install_dir}/deploy/backup.sh {env}" if install_dir else "",
        "restore_command": f"sudo {install_dir}/deploy/restore.sh {env} <backup-dir>" if install_dir else "",
        "note": "Backups run from the Ubuntu host so database dumps and .env files are stored outside containers.",
    }


@app.post("/api/system/backup/request")
def request_backup(admin=Depends(current_admin)):
    payload = backup_status(admin)
    audit(admin["id"], "request_backup", "system", os.getenv("APP_ENV", "unknown"), payload)
    return payload


@app.get("/api/system/update")
def update_status(admin=Depends(current_admin)):
    env = os.getenv("APP_ENV", "staging")
    branch = "master" if env == "production" else "staging"
    install_dir = os.getenv("INSTALL_DIR", "")
    return {
        "environment": env,
        "branch": branch,
        "install_dir": install_dir,
        "update_command": f"sudo {install_dir}/deploy/install.sh update {env}" if install_dir else "",
        "one_line_update": f"curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejpisowifi/{branch}/deploy/install.sh | sudo bash -s -- update {env}",
    }


@app.post("/api/system/update/request")
def request_update(admin=Depends(current_admin)):
    payload = update_status(admin)
    audit(admin["id"], "request_update", "system", os.getenv("APP_ENV", "unknown"), payload)
    return payload


@app.post("/api/system/danger")
def danger_action(payload: DangerAction, admin=Depends(current_admin)):
    row = fetch_one("SELECT password_hash FROM admins WHERE id = %s", (admin["id"],))
    if not row or not verify_password(payload.current_password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    actions = {
        "clear_auth_logs": ("CLEAR AUTH LOGS", "DELETE FROM radius_auth_logs"),
        "clear_sessions": ("CLEAR SESSIONS", "DELETE FROM sessions"),
    }
    if payload.action not in actions:
        raise HTTPException(status_code=400, detail="Unsupported danger action")
    expected, query = actions[payload.action]
    if payload.confirmation != expected:
        raise HTTPException(status_code=400, detail=f"Type {expected} to confirm")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
    audit(admin["id"], payload.action, "system", "danger")
    return {"status": "ok", "action": payload.action}
