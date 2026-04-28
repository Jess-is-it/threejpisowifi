import os
import secrets
import shutil
import socket
import struct
import time
import hmac
from hashlib import md5
from ipaddress import ip_interface
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/app/uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/api/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")


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


class RadiusSimulationRequest(BaseModel):
    username: str
    password: str
    nas_ip: str = "127.0.0.1"
    nas_identifier: Optional[str] = "portal-simulator"
    calling_station_id: Optional[str] = "SIMULATED-DEVICE"


class RealRadiusTestRequest(BaseModel):
    username: str
    password: str
    nas_ip: str = "127.0.0.1"
    nas_identifier: Optional[str] = "portal-real-test"
    calling_station_id: Optional[str] = "REAL-TEST-DEVICE"
    shared_secret: Optional[str] = None
    radius_host: str = "radius"
    radius_port: int = Field(default=1812, ge=1, le=65535)


class RealAccountingTestRequest(BaseModel):
    username: str
    nas_ip: str = "172.18.0.1"
    nas_identifier: Optional[str] = "Docker API Test NAS"
    calling_station_id: Optional[str] = "REAL-ACCT-TEST"
    framed_ip_address: Optional[str] = "10.10.10.10"
    acct_session_id: str
    acct_unique_session_id: Optional[str] = None
    shared_secret: Optional[str] = None
    radius_host: str = "radius"
    accounting_port: int = Field(default=1813, ge=1, le=65535)
    acct_session_time: int = Field(default=0, ge=0)
    input_octets: int = Field(default=0, ge=0)
    output_octets: int = Field(default=0, ge=0)


class NasCreate(BaseModel):
    name: str
    nas_ip: str
    shortname: str
    secret: Optional[str] = None
    type: str = "other"
    notes: Optional[str] = None


class NasUpdate(BaseModel):
    name: Optional[str] = None
    nas_ip: Optional[str] = None
    shortname: Optional[str] = None
    secret: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
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


def record_radius_auth(cur, username, nas_ip, nas_identifier, calling_station_id, result, message):
    cur.execute(
        """
        INSERT INTO radius_auth_logs(username, nas_ip, nas_identifier, calling_station_id, result, reply_message, diagnostic_reason)
        VALUES (%s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s)
        """,
        (username, nas_ip or "", nas_identifier, calling_station_id, result, message, message),
    )


def evaluate_radius_auth(cur, username, password, nas_ip, nas_identifier, calling_station_id):
    grace = int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180"))
    cur.execute(
        """
        SELECT u.id, u.password_hash, u.status, w.time_remaining_seconds, w.valid_until, w.is_unlimited
        FROM users u
        LEFT JOIN wallets w ON w.user_id = u.id
        WHERE u.username = %s
        """,
        (username,),
    )
    user = cur.fetchone()
    result = "reject"
    message = "Unknown user"
    session_timeout = None
    checks = {
        "user_exists": False,
        "password_valid": False,
        "user_active": False,
        "has_balance": False,
        "single_device_clear": False,
    }
    if not user:
        record_radius_auth(cur, username, nas_ip, nas_identifier, calling_station_id, result, message)
        return result, message, session_timeout, checks

    checks["user_exists"] = True
    checks["user_active"] = user["status"] == "active"
    checks["password_valid"] = bool(password and verify_password(password, user["password_hash"]))
    remaining = user["time_remaining_seconds"] or 0
    valid_until = user["valid_until"]
    unlimited = bool(user["is_unlimited"])
    checks["has_balance"] = bool(unlimited or remaining > 0 or (valid_until and valid_until > datetime.now(timezone.utc)))

    if not checks["user_active"]:
        message = "User is disabled"
    elif not checks["password_valid"]:
        message = "Invalid password"
    elif not checks["has_balance"]:
        message = "No active balance"
    else:
        cur.execute(
            """
            SELECT 1 FROM sessions
            WHERE user_id = %s
              AND status = 'ACTIVE'
              AND stop_time IS NULL
              AND last_update_time > now() - (%s || ' seconds')::interval
            LIMIT 1
            """,
            (user["id"], grace),
        )
        checks["single_device_clear"] = cur.fetchone() is None
        if not checks["single_device_clear"]:
            message = "Account is already in use"
        else:
            result = "accept"
            message = "Access accepted"
            if not unlimited and remaining > 0:
                session_timeout = remaining

    record_radius_auth(cur, username, nas_ip, nas_identifier, calling_station_id, result, message)
    return result, message, session_timeout, checks


def radius_attr(attr_type: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("RADIUS attribute value is too long")
    return bytes([attr_type, len(value) + 2]) + value


def encode_user_password(password: str, secret: bytes, request_authenticator: bytes) -> bytes:
    password_bytes = password.encode()
    padded_len = ((len(password_bytes) + 15) // 16) * 16
    padded = password_bytes.ljust(padded_len or 16, b"\x00")
    result = b""
    previous = request_authenticator
    for index in range(0, len(padded), 16):
        digest = md5(secret + previous).digest()
        block = bytes(a ^ b for a, b in zip(padded[index:index + 16], digest))
        result += block
        previous = block
    return result


def normalize_ip(value: str) -> str:
    return str(ip_interface(value).ip)


def parse_radius_reply(attributes: bytes) -> dict:
    reply = {"reply_message": "", "raw_attributes": []}
    index = 0
    messages = []
    while index + 2 <= len(attributes):
        attr_type = attributes[index]
        attr_len = attributes[index + 1]
        if attr_len < 2 or index + attr_len > len(attributes):
            break
        value = attributes[index + 2:index + attr_len]
        reply["raw_attributes"].append({"type": attr_type, "length": attr_len, "value_hex": value.hex()})
        if attr_type == 18:
            messages.append(value.decode(errors="replace"))
        index += attr_len
    reply["reply_message"] = " ".join(messages)
    return reply


def send_radius_access_request(payload: RealRadiusTestRequest) -> dict:
    secret_value = payload.shared_secret or os.getenv("RADIUS_DEFAULT_SECRET") or "testing123"
    secret = secret_value.encode()
    identifier = secrets.randbelow(256)
    request_authenticator = secrets.token_bytes(16)
    nas_ip = normalize_ip(payload.nas_ip)
    attributes = b"".join(
        [
            radius_attr(1, payload.username.encode()),
            radius_attr(2, encode_user_password(payload.password, secret, request_authenticator)),
            radius_attr(4, socket.inet_aton(nas_ip)),
            radius_attr(5, struct.pack("!I", 0)),
            radius_attr(6, struct.pack("!I", 2)),
            radius_attr(31, (payload.calling_station_id or "REAL-TEST-DEVICE").encode()),
            radius_attr(32, (payload.nas_identifier or "portal-real-test").encode()),
        ]
    )
    attributes_with_message_authenticator = attributes + radius_attr(80, b"\x00" * 16)
    packet_length = 20 + len(attributes_with_message_authenticator)
    unsigned_packet = struct.pack("!BBH", 1, identifier, packet_length) + request_authenticator + attributes_with_message_authenticator
    message_authenticator = hmac.new(secret, unsigned_packet, md5).digest()
    attributes = attributes + radius_attr(80, message_authenticator)
    packet_length = 20 + len(attributes)
    packet = struct.pack("!BBH", 1, identifier, packet_length) + request_authenticator + attributes

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        try:
            sock.sendto(packet, (payload.radius_host, payload.radius_port))
            response, remote = sock.recvfrom(4096)
        except socket.timeout:
            return {
                "result": "No Reply",
                "detail": "No UDP response was received. This can mean wrong host/port, firewall block, unknown RADIUS client, or a dropped packet.",
                "reply_message": "",
                "diagnostic_reason": "No Reply",
                "raw_attributes": [],
            }
        except OSError as exc:
            return {"result": "No Reply", "detail": str(exc), "reply_message": "", "diagnostic_reason": "No Reply", "raw_attributes": []}

    if len(response) < 20:
        return {"result": "No Reply", "detail": "Received an invalid short RADIUS response.", "reply_message": "", "diagnostic_reason": "No Reply", "raw_attributes": []}
    code, response_identifier, response_length = struct.unpack("!BBH", response[:4])
    if response_identifier != identifier or response_length > len(response):
        return {"result": "No Reply", "detail": "Received an invalid RADIUS response identifier or length.", "reply_message": "", "diagnostic_reason": "No Reply", "raw_attributes": []}

    response_packet = response[:response_length]
    response_authenticator = response_packet[4:20]
    response_attributes = response_packet[20:]
    expected_authenticator = md5(response_packet[:4] + request_authenticator + response_attributes + secret).digest()
    if response_authenticator != expected_authenticator:
        return {
            "result": "Wrong Secret",
            "detail": "RADIUS replied, but the response authenticator did not match the shared secret.",
            "reply_message": "",
            "diagnostic_reason": "Wrong Secret",
            "raw_attributes": [],
            "remote": f"{remote[0]}:{remote[1]}",
        }

    parsed = parse_radius_reply(response_attributes)
    reply_message = parsed["reply_message"]
    if code == 2:
        result = "Access-Accept"
    elif code == 3:
        result = "Database Error" if "database" in reply_message.lower() else "Access-Reject"
    else:
        result = "No Reply"
    diagnostic_reason = reply_message or ("Unknown authorization failure" if result == "Access-Reject" else result)
    return {
        "result": result,
        "detail": diagnostic_reason if result == "Access-Reject" else (reply_message or f"Received RADIUS response code {code}."),
        "reply_message": reply_message,
        "diagnostic_reason": diagnostic_reason,
        "raw_attributes": parsed["raw_attributes"],
        "remote": f"{remote[0]}:{remote[1]}",
    }


def encode_int(value: int) -> bytes:
    return struct.pack("!I", int(value or 0))


def build_accounting_attributes(payload: RealAccountingTestRequest, status_type: str) -> bytes:
    status_map = {"Start": 1, "Stop": 2, "Interim-Update": 3}
    nas_ip = normalize_ip(payload.nas_ip)
    attrs = [
        radius_attr(1, payload.username.encode()),
        radius_attr(4, socket.inet_aton(nas_ip)),
        radius_attr(5, encode_int(0)),
        radius_attr(32, (payload.nas_identifier or "Docker API Test NAS").encode()),
        radius_attr(31, (payload.calling_station_id or "REAL-ACCT-TEST").encode()),
        radius_attr(40, encode_int(status_map[status_type])),
        radius_attr(41, encode_int(0)),
        radius_attr(42, encode_int(payload.input_octets)),
        radius_attr(43, encode_int(payload.output_octets)),
        radius_attr(44, payload.acct_session_id.encode()),
        radius_attr(46, encode_int(payload.acct_session_time)),
    ]
    if payload.framed_ip_address:
        attrs.append(radius_attr(8, socket.inet_aton(normalize_ip(payload.framed_ip_address))))
    if payload.acct_unique_session_id:
        attrs.append(radius_attr(50, payload.acct_unique_session_id.encode()))
    return b"".join(attrs)


def send_radius_accounting_request(payload: RealAccountingTestRequest, status_type: str) -> dict:
    secret_value = payload.shared_secret or os.getenv("RADIUS_DEFAULT_SECRET") or "testing123"
    secret = secret_value.encode()
    identifier = secrets.randbelow(256)
    attributes = build_accounting_attributes(payload, status_type)
    packet_length = 20 + len(attributes)
    header = struct.pack("!BBH", 4, identifier, packet_length)
    request_authenticator = md5(header + (b"\x00" * 16) + attributes + secret).digest()
    packet = header + request_authenticator + attributes
    raw_request = parse_radius_reply(attributes)["raw_attributes"]

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        try:
            sock.sendto(packet, (payload.radius_host, payload.accounting_port))
            response, remote = sock.recvfrom(4096)
        except socket.timeout:
            return {
                "result": "No Reply",
                "diagnostic_reason": "No reply from FreeRADIUS",
                "detail": "No UDP Accounting-Response was received.",
                "raw_request_attributes": raw_request,
                "raw_response_attributes": [],
            }
        except OSError as exc:
            return {
                "result": "No Reply",
                "diagnostic_reason": str(exc),
                "detail": str(exc),
                "raw_request_attributes": raw_request,
                "raw_response_attributes": [],
            }

    if len(response) < 20:
        return {
            "result": "No Reply",
            "diagnostic_reason": "Invalid short accounting response",
            "detail": "Received an invalid short Accounting-Response.",
            "raw_request_attributes": raw_request,
            "raw_response_attributes": [],
        }
    code, response_identifier, response_length = struct.unpack("!BBH", response[:4])
    if response_identifier != identifier or response_length > len(response):
        return {
            "result": "No Reply",
            "diagnostic_reason": "Invalid accounting response identifier or length",
            "detail": "Received an invalid Accounting-Response identifier or length.",
            "raw_request_attributes": raw_request,
            "raw_response_attributes": [],
        }
    response_packet = response[:response_length]
    response_attrs = response_packet[20:]
    expected = md5(response_packet[:4] + request_authenticator + response_attrs + secret).digest()
    if response_packet[4:20] != expected:
        return {
            "result": "Wrong Secret",
            "diagnostic_reason": "Wrong shared secret",
            "detail": "FreeRADIUS replied, but the accounting response authenticator did not match the shared secret.",
            "raw_request_attributes": raw_request,
            "raw_response_attributes": [],
            "remote": f"{remote[0]}:{remote[1]}",
        }
    parsed = parse_radius_reply(response_attrs)
    diagnostic = parsed["reply_message"] or ("Accounting-Response" if code == 5 else f"Unexpected RADIUS code {code}")
    return {
        "result": "Accounting-Response" if code == 5 else "No Reply",
        "diagnostic_reason": diagnostic,
        "detail": diagnostic,
        "reply_message": parsed["reply_message"],
        "raw_request_attributes": raw_request,
        "raw_response_attributes": parsed["raw_attributes"],
        "remote": f"{remote[0]}:{remote[1]}",
    }


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
        "company_logo_url": branding.get("company_logo_url"),
        "browser_logo_url": branding.get("browser_logo_url"),
    }


def read_cpu_ticks():
    parts = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    values = [int(part) for part in parts]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def format_pct(value):
    return round(float(value), 1)


@app.get("/api/system/resources")
def system_resources(admin=Depends(current_admin)):
    total_a, idle_a = read_cpu_ticks()
    time.sleep(0.1)
    total_b, idle_b = read_cpu_ticks()
    total_delta = max(total_b - total_a, 1)
    idle_delta = max(idle_b - idle_a, 0)
    cpu_pct = format_pct((1 - (idle_delta / total_delta)) * 100)

    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        mem[key] = int(value.strip().split()[0])
    total_kb = mem.get("MemTotal", 0)
    available_kb = mem.get("MemAvailable", 0)
    free_kb = mem.get("MemFree", 0)
    cached_kb = mem.get("Cached", 0) + mem.get("SReclaimable", 0)
    ram_pressure_pct = format_pct(((total_kb - available_kb) / total_kb) * 100) if total_kb else 0
    ram_used_incl_cache_pct = format_pct(((total_kb - free_kb) / total_kb) * 100) if total_kb else 0

    disk = shutil.disk_usage("/")
    uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
    return {
        "cpu_pct": cpu_pct,
        "ram_pct": ram_pressure_pct,
        "ram_pressure_pct": ram_pressure_pct,
        "ram_used_incl_cache_pct": ram_used_incl_cache_pct,
        "ram_total_kb": total_kb,
        "ram_available_kb": available_kb,
        "ram_cached_kb": cached_kb,
        "ram_free_kb": free_kb,
        "disk_pct": format_pct((disk.used / disk.total) * 100),
        "uptime_seconds": int(uptime_seconds),
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
        "SELECT username, nas_ip::text, calling_station_id, result, reply_message, diagnostic_reason, created_at FROM radius_auth_logs ORDER BY created_at DESC LIMIT 10"
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
    grace = int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180"))
    return fetch_all(
        """
        SELECT s.*,
               CASE
                 WHEN s.status = 'ACTIVE' AND s.stop_time IS NULL AND s.last_update_time > now() - (%s || ' seconds')::interval THEN 'ACTIVE'
                 WHEN s.status = 'ACTIVE' AND s.stop_time IS NULL THEN 'STALE'
                 ELSE s.status
               END AS display_status
        FROM sessions s
        ORDER BY s.last_update_time DESC
        LIMIT 300
        """,
        (grace,),
    )


@app.get("/api/sessions/active")
def active_sessions(admin=Depends(current_admin)):
    grace = int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180"))
    return fetch_all(
        """
        SELECT * FROM sessions
        WHERE status = 'ACTIVE'
          AND stop_time IS NULL
          AND last_update_time > now() - (%s || ' seconds')::interval
        ORDER BY last_update_time DESC
        """,
        (grace,),
    )


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str, admin=Depends(current_admin)):
    session = fetch_one("SELECT * FROM sessions WHERE id = %s", (session_id,))
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    logs = fetch_all(
        "SELECT * FROM radius_accounting_logs WHERE username = %s AND acct_session_id = %s ORDER BY created_at DESC LIMIT 50",
        (session["username"], session["acct_session_id"]),
    )
    return {"session": session, "accounting_logs": logs}


@app.post("/api/sessions/{session_id}/mark-stale")
def mark_session_stale(session_id: str, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE sessions SET status = 'STALE', updated_at = now() WHERE id = %s RETURNING id", (session_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Session not found")
    audit(admin["id"], "mark_session_stale", "session", session_id)
    return {"status": "ok"}


@app.post("/api/sessions/{session_id}/force-stop-local")
def force_stop_local(session_id: str, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sessions
                SET status = 'STOPPED',
                    stop_time = COALESCE(stop_time, now()),
                    last_update_time = now(),
                    updated_at = now()
                WHERE id = %s
                RETURNING id
                """,
                (session_id,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Session not found")
    audit(admin["id"], "force_stop_session_local", "session", session_id, {"note": "Local stop only; no CoA disconnect sent"})
    return {"status": "ok", "warning": "This does not disconnect the user from the AP/router yet. It only clears the local active-session record."}


@app.get("/api/users/{user_id}/wallet-accounting-summary")
def wallet_accounting_summary(user_id: str, admin=Depends(current_admin)):
    grace = int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180"))
    user = fetch_one(
        """
        SELECT u.id, u.username, u.status, w.time_remaining_seconds, w.valid_until, w.is_unlimited, w.updated_at AS wallet_updated_at
        FROM users u
        LEFT JOIN wallets w ON w.user_id = u.id
        WHERE u.id = %s
        """,
        (user_id,),
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    active = fetch_one(
        """
        SELECT id, calling_station_id, nas_identifier, framed_ip_address::text, start_time, last_update_time, acct_session_time, status
        FROM sessions
        WHERE user_id = %s
          AND status = 'ACTIVE'
          AND stop_time IS NULL
          AND last_update_time > now() - (%s || ' seconds')::interval
        ORDER BY last_update_time DESC
        LIMIT 1
        """,
        (user_id, grace),
    )
    last_debit = fetch_one(
        """
        SELECT amount_seconds, reference, note, created_at
        FROM transactions
        WHERE user_id = %s AND source = 'ACCOUNTING' AND type = 'DEBIT'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (user_id,),
    )
    debits = fetch_all(
        """
        SELECT amount_seconds, reference, note, created_at
        FROM transactions
        WHERE user_id = %s AND source = 'ACCOUNTING' AND type = 'DEBIT'
        ORDER BY created_at DESC
        LIMIT 10
        """,
        (user_id,),
    )
    return {"user": user, "active_session": active, "last_accounting_deduction": last_debit, "recent_accounting_debits": debits}


@app.post("/api/radius/simulate-auth")
def simulate_radius_auth(payload: RadiusSimulationRequest, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            result, message, session_timeout, checks = evaluate_radius_auth(
                cur,
                payload.username,
                payload.password,
                payload.nas_ip,
                payload.nas_identifier,
                payload.calling_station_id,
            )
    audit(
        admin["id"],
        "simulate_radius_auth",
        "radius",
        payload.username,
        {"result": result, "reply_message": message, "nas_ip": payload.nas_ip, "calling_station_id": payload.calling_station_id},
    )
    return {
        "result": result,
        "access": "Access-Accept" if result == "accept" else "Access-Reject",
        "reply_message": message,
        "session_timeout": session_timeout,
        "checks": checks,
        "simulated": True,
    }


@app.get("/api/radius/real-packet-defaults")
def real_radius_packet_defaults(admin=Depends(current_admin)):
    docker_subnet = os.getenv("RADIUS_DOCKER_CLIENT_SUBNET", "172.18.0.0/16")
    packet_nas_ip = os.getenv("RADIUS_INTERNAL_TEST_NAS_IP", "172.18.0.1")
    return {
        "nas_client_source": "Internal Docker RADIUS Test Client",
        "client_name": "Docker API Test NAS",
        "client_subnet": docker_subnet,
        "packet_nas_ip": packet_nas_ip,
        "shared_secret": os.getenv("RADIUS_DEFAULT_SECRET") or "testing123",
        "radius_host": "radius",
        "radius_port": 1812,
        "accounting_port": 1813,
        "note": "This test is sent from the API container to the FreeRADIUS container. It uses the internal Docker test client secret, not the router/AP NAS shared secret.",
    }


@app.post("/api/radius/real-packet-test")
def real_radius_packet_test(payload: RealRadiusTestRequest, admin=Depends(current_admin)):
    try:
        result = send_radius_access_request(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    recent = fetch_one(
        """
        SELECT id, reply_message, diagnostic_reason
        FROM radius_auth_logs
        WHERE username = %s
          AND created_at > now() - interval '15 seconds'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (payload.username,),
    )
    if result["result"] in ("Access-Reject", "Database Error") and not result.get("reply_message"):
        if recent and (recent.get("diagnostic_reason") or recent.get("reply_message")):
            reason = recent.get("diagnostic_reason") or recent.get("reply_message")
            result["diagnostic_reason"] = reason
            result["reply_message"] = recent.get("reply_message") or reason
            result["detail"] = reason
    audit(
        admin["id"],
        "real_radius_packet_test",
        "radius",
        payload.username,
        {
            "result": result["result"],
            "radius_host": payload.radius_host,
            "radius_port": payload.radius_port,
            "nas_ip": payload.nas_ip,
            "nas_identifier": payload.nas_identifier,
        },
    )
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if recent and result["result"] in ("Access-Accept", "Access-Reject", "Database Error"):
                    cur.execute(
                        "UPDATE radius_auth_logs SET result = %s, diagnostic_reason = COALESCE(diagnostic_reason, %s), reply_message = COALESCE(reply_message, %s) WHERE id = %s",
                        (result["result"], result.get("diagnostic_reason") or result.get("detail"), result.get("reply_message") or result.get("detail"), recent["id"]),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO radius_auth_logs(username, nas_ip, nas_identifier, calling_station_id, result, reply_message, diagnostic_reason)
                        VALUES (%s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s)
                        """,
                        (
                            payload.username,
                            payload.nas_ip or "",
                            payload.nas_identifier,
                            payload.calling_station_id,
                            result["result"],
                            result.get("reply_message") or result.get("detail"),
                            result.get("diagnostic_reason") or result.get("detail"),
                        ),
                    )
    except Exception:
        pass
    return result


def run_accounting_packet(payload: RealAccountingTestRequest, status_type: str, admin):
    result = send_radius_accounting_request(payload, status_type)
    recent = fetch_one(
        """
        SELECT id, result, diagnostic_reason, raw_payload
        FROM radius_accounting_logs
        WHERE username = %s
          AND acct_session_id = %s
          AND acct_status_type = %s
          AND created_at > now() - interval '15 seconds'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (payload.username, payload.acct_session_id, status_type),
    )
    if recent:
        result["accounting_result"] = recent["result"]
        result["diagnostic_reason"] = recent["diagnostic_reason"] or result.get("diagnostic_reason")
        result["detail"] = result["diagnostic_reason"]
        result["raw_payload"] = recent["raw_payload"]
    elif result["result"] != "Accounting-Response":
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO radius_accounting_logs(username, acct_status_type, acct_session_id, nas_ip, nas_identifier, calling_station_id,
                                                       framed_ip_address, acct_session_time, input_octets, output_octets, raw_payload, result, diagnostic_reason)
                    VALUES (%s, %s, %s, NULLIF(%s, '')::inet, %s, %s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        payload.username,
                        status_type,
                        payload.acct_session_id,
                        payload.nas_ip or "",
                        payload.nas_identifier,
                        payload.calling_station_id,
                        payload.framed_ip_address or "",
                        payload.acct_session_time,
                        payload.input_octets,
                        payload.output_octets,
                        Json(payload.model_dump(mode="json")),
                        result["result"],
                        result.get("diagnostic_reason") or result.get("detail"),
                    ),
                )
    audit(admin["id"], f"radius_accounting_{status_type.lower().replace('-', '_')}", "radius", payload.username, {
        "result": result["result"],
        "diagnostic_reason": result.get("diagnostic_reason"),
        "acct_session_id": payload.acct_session_id,
    })
    return result


@app.post("/api/radius-test/accounting/start")
def accounting_start(payload: RealAccountingTestRequest, admin=Depends(current_admin)):
    return run_accounting_packet(payload, "Start", admin)


@app.post("/api/radius-test/accounting/interim")
def accounting_interim(payload: RealAccountingTestRequest, admin=Depends(current_admin)):
    return run_accounting_packet(payload, "Interim-Update", admin)


@app.post("/api/radius-test/accounting/stop")
def accounting_stop(payload: RealAccountingTestRequest, admin=Depends(current_admin)):
    return run_accounting_packet(payload, "Stop", admin)


@app.get("/api/nas-clients")
def list_nas(admin=Depends(current_admin)):
    return fetch_all("SELECT id, name, nas_ip::text, shortname, secret, type, status, notes, created_at, updated_at FROM nas_clients ORDER BY created_at DESC")


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


@app.patch("/api/nas-clients/{nas_id}")
def update_nas(nas_id: str, payload: NasUpdate, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT shortname FROM nas_clients WHERE id = %s", (nas_id,))
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="NAS client not found")
            cur.execute(
                """
                UPDATE nas_clients
                SET name = COALESCE(%s, name),
                    nas_ip = COALESCE(%s, nas_ip),
                    shortname = COALESCE(%s, shortname),
                    secret = COALESCE(%s, secret),
                    type = COALESCE(%s, type),
                    status = COALESCE(%s, status),
                    notes = %s,
                    updated_at = now()
                WHERE id = %s
                RETURNING name, nas_ip::text, shortname, secret, type, status, notes
                """,
                (payload.name, payload.nas_ip, payload.shortname, payload.secret, payload.type, payload.status, payload.notes, nas_id),
            )
            updated = cur.fetchone()
            cur.execute("DELETE FROM nas WHERE shortname = %s AND shortname <> %s", (existing["shortname"], updated["shortname"]))
            if updated["status"] == "active":
                cur.execute(
                    """
                    INSERT INTO nas(nasname, shortname, type, secret, description)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (shortname) DO UPDATE
                    SET nasname = EXCLUDED.nasname,
                        secret = EXCLUDED.secret,
                        type = EXCLUDED.type,
                        description = EXCLUDED.description
                    """,
                    (updated["nas_ip"], updated["shortname"], updated["type"], updated["secret"], updated["name"]),
                )
            else:
                cur.execute("DELETE FROM nas WHERE shortname = %s", (updated["shortname"],))
    audit(admin["id"], "update_nas_client", "nas_client", nas_id, payload.model_dump(exclude_none=True))
    return {"status": "ok"}


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
    return fetch_all("SELECT username, nas_ip::text, nas_identifier, calling_station_id, result, reply_message, diagnostic_reason, created_at FROM radius_auth_logs ORDER BY created_at DESC LIMIT 200")


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


def save_branding_file(file: UploadFile, key: str):
    allowed_types = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/webp": ".webp",
        "image/gif": ".gif",
        "image/x-icon": ".ico",
        "image/vnd.microsoft.icon": ".ico",
    }
    suffix = allowed_types.get(file.content_type or "")
    if not suffix:
        filename_suffix = Path(file.filename or "").suffix.lower()
        if filename_suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico"}:
            suffix = ".jpg" if filename_suffix == ".jpeg" else filename_suffix
    if not suffix:
        raise HTTPException(status_code=400, detail="Upload an image file: PNG, JPG, WebP, GIF, or ICO")

    path = UPLOAD_DIR / f"{key}{suffix}"
    with path.open("wb") as out:
        shutil.copyfileobj(file.file, out)
    return f"/api/uploads/{path.name}"


@app.post("/api/system/branding/company-logo")
def upload_company_logo(company_logo: UploadFile = File(...), admin=Depends(current_admin)):
    logo_url = save_branding_file(company_logo, "company-logo")
    current = system_settings_payload()
    branding = {**current.get("branding", {}), "company_logo_url": logo_url}
    update_system_settings(SystemSettingsUpdate(branding=branding), admin)
    audit(admin["id"], "upload_company_logo", "system", "branding", {"company_logo_url": logo_url})
    return public_branding()


@app.post("/api/system/branding/browser-logo")
def upload_browser_logo(browser_logo: UploadFile = File(...), admin=Depends(current_admin)):
    logo_url = save_branding_file(browser_logo, "browser-logo")
    current = system_settings_payload()
    branding = {**current.get("branding", {}), "browser_logo_url": logo_url}
    update_system_settings(SystemSettingsUpdate(branding=branding), admin)
    audit(admin["id"], "upload_browser_logo", "system", "branding", {"browser_logo_url": logo_url})
    return public_branding()


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
