from __future__ import annotations

import re
from datetime import datetime, timezone

import docker
import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

JWT_ISSUER = "centralwifi"
JWT_SECRET = None


def _env(name: str, default: str | None = None) -> str | None:
    import os

    return os.environ.get(name, default)


def _require_admin(authorization: str | None) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization")
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = jwt.decode(
            token,
            _env("JWT_SECRET") or "",
            algorithms=["HS256"],
            issuer=_env("JWT_ISSUER", JWT_ISSUER),
            options={"require": ["exp", "iat", "iss"]},
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return claims


def _docker() -> docker.DockerClient:
    return docker.DockerClient(base_url="unix://var/run/docker.sock")


def _find_one_container(service: str) -> docker.models.containers.Container:
    """
    Locate the compose container for a given service name.
    Works regardless of compose project name as long as labels exist.
    """
    client = _docker()
    containers = client.containers.list(
        all=True,
        filters={"label": [f"com.docker.compose.service={service}"]},
    )
    if not containers:
        raise HTTPException(status_code=503, detail=f"Service container not found: {service}")
    # Prefer running container.
    running = [c for c in containers if c.status == "running"]
    return (running[0] if running else containers[0])


def _exec(container: docker.models.containers.Container, cmd: list[str], timeout_s: int = 30) -> str:
    res = container.exec_run(cmd, stdout=True, stderr=True, demux=False)
    out = res.output.decode(errors="replace") if isinstance(res.output, (bytes, bytearray)) else str(res.output)
    if res.exit_code != 0:
        raise HTTPException(status_code=500, detail=f"Command failed: {' '.join(cmd)}\n{out}")
    return out


def _render_caddyfile(site: str) -> str:
    # Keep this in sync with services/reverse-proxy/Caddyfile intent.
    return f"""\
{{
  # Managed by Central WiFi Admin Setup Wizard.
}}

{site} {{
  encode zstd gzip

  @health path /healthz
  respond @health 200

  @ops path /api/v1/ops/*
  reverse_proxy @ops ops:9000

  handle_path /portal* {{
    reverse_proxy portal:80
  }}

  @api path /api/* /openapi.json /docs /docs/*
  reverse_proxy @api api:8000

  reverse_proxy admin:80

  header {{
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer"
    Permissions-Policy "geolocation=(), microphone=(), camera=()"
  }}
}}
"""


def _extract_site_from_caddyfile(text: str) -> str:
    # Extract the first site block label (the first "<site> {" outside global options).
    #
    # Note: Caddyfile site labels can start with "{$VAR}" which also starts with "{",
    # so we must only treat a line that is exactly "{" as the start of global options.
    in_global = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "{":
            in_global = True
            continue
        if in_global:
            if s == "}":
                in_global = False
            continue
        # Match: "<site> {"
        m = re.match(r"^(.+?)\s*\{\s*$", s)
        if not m:
            continue
        label = m.group(1).strip()
        # Ignore nested directive blocks if we ever reach them.
        if label.startswith("@") or label in {"header", "handle", "route", "tls", "log"}:
            continue
        return label
    return ""


def _validate_domain(domain: str) -> str:
    d = domain.strip()
    if d == "":
        return ""
    # allow ":80" / ":443" / ":port" for IP-based testing
    if d.startswith(":") and d[1:].isdigit():
        return d
    # allow host:port
    if ":" in d:
        host, port = d.rsplit(":", 1)
        if port.isdigit() and host:
            d = host  # for TLS, we strongly prefer no explicit port
    # very small sanity check; DNS validation is external.
    if not re.match(r"^[a-zA-Z0-9.-]+$", d) or "." not in d:
        raise HTTPException(status_code=400, detail="Invalid domain (expected something like example.com)")
    return d.lower()


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _envfile_set(path: str, updates: dict[str, str]) -> bool:
    """
    Best-effort update of a dotenv file on a bind-mounted path.
    Preserves unknown lines and comments.
    """
    import os

    try:
        if not os.path.exists(path):
            return False
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception:
        return False

    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            out.append(line)
            continue
        k = m.group(1)
        if k in updates:
            out.append(f"{k}={updates[k]}")
            seen.add(k)
        else:
            out.append(line)

    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}")

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        return True
    except Exception:
        return False


def _restart_services(services: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for svc in services:
        try:
            c = _find_one_container(svc)
            c.restart()
            out[svc] = "restarted"
        except Exception as e:
            out[svc] = f"failed: {type(e).__name__}"
    return out


class DomainIn(BaseModel):
    domain: str = Field("", description="Caddy site address. Use example.com for HTTPS, or :80 for HTTP-only.")
    public_base_url: str = Field("", description="Informational base URL shown in the UI (does not change DNS).")
    mode: str = Field("https", description="https|http")


class RadiusTestIn(BaseModel):
    username: str = Field(..., description="WiFi username (typically E.164 phone).")
    password: str = Field(..., description="WiFi password.")
    calling_station_id: str = Field("AA-BB-CC-DD-EE-FF", description="Client MAC (Calling-Station-Id).")
    nas_ip: str = Field("127.0.0.1", description="NAS IP attribute for the packet.")


class EnvUpdateIn(BaseModel):
    updates: dict[str, str] = Field(default_factory=dict)


app = FastAPI(title="Central WiFi Ops", version="1.0.0")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/v1/ops/domain")
def get_domain(authorization: str | None = Header(default=None, alias="Authorization")):
    _require_admin(authorization)
    c = _find_one_container("reverse-proxy")
    text = _exec(c, ["sh", "-lc", "cat /etc/caddy/Caddyfile 2>/dev/null || true"])
    site = _extract_site_from_caddyfile(text) or ""
    return {"site": site, "updated_at": datetime.now(timezone.utc).isoformat()}


@app.put("/api/v1/ops/domain")
def set_domain(payload: DomainIn, authorization: str | None = Header(default=None, alias="Authorization")):
    _require_admin(authorization)
    mode = (payload.mode or "https").lower()
    if mode not in ("https", "http"):
        raise HTTPException(status_code=400, detail="mode must be https or http")

    domain = _validate_domain(payload.domain)
    if mode == "http":
        site = domain or ":80"
        # If user entered example.com with http mode, pin to :80 to avoid ACME attempts.
        if site and not site.startswith(":") and ":" not in site:
            site = f"{site}:80"
    else:
        # HTTPS mode: require a real domain (no ports) so Caddy can do ACME.
        if not domain or domain.startswith(":"):
            raise HTTPException(status_code=400, detail="HTTPS mode requires a real domain like example.com")
        if _is_ipv4(domain):
            raise HTTPException(status_code=400, detail="HTTPS mode requires a DNS hostname (not an IP address)")
        site = domain

    new_cfg = _render_caddyfile(site)
    c = _find_one_container("reverse-proxy")

    # Write config and reload.
    _exec(
        c,
        [
            "sh",
            "-lc",
            "cat > /etc/caddy/Caddyfile <<'EOF'\n" + new_cfg + "EOF\ncaddy reload --config /etc/caddy/Caddyfile",
        ],
        timeout_s=60,
    )
    # Best-effort: keep runtime config in sync for API/UI link generation.
    env_written = _envfile_set(
        "/host/.env",
        {
            "CW_DOMAIN": site,
            "CW_PUBLIC_BASE_URL": (payload.public_base_url or "").strip(),
        },
    )
    restarts = _restart_services(["api", "admin"])

    return {"ok": True, "site": site, "env_written": env_written, "restarts": restarts}


@app.get("/api/v1/ops/env")
def get_env(authorization: str | None = Header(default=None, alias="Authorization")):
    _require_admin(authorization)
    # Only expose a small allowlist of operator-tunable keys.
    allow = {
        "CW_PUBLIC_BASE_URL",
        "CW_DOMAIN",
        "WALLED_GARDEN_ON_NO_CREDIT",
        "WALLED_GARDEN_VLAN_ID",
        "SMS_PROVIDER",
        "PAYMENT_PROVIDER",
    }
    try:
        with open("/host/.env", "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception:
        raise HTTPException(status_code=500, detail="Cannot read /host/.env")

    out: dict[str, str] = {}
    for line in lines:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line.strip())
        if not m:
            continue
        k = m.group(1)
        if k in allow:
            out[k] = m.group(2)
    return {"values": out}


@app.put("/api/v1/ops/env")
def put_env(payload: EnvUpdateIn, authorization: str | None = Header(default=None, alias="Authorization")):
    _require_admin(authorization)
    allow = {
        "CW_PUBLIC_BASE_URL",
        "CW_DOMAIN",
        "WALLED_GARDEN_ON_NO_CREDIT",
        "WALLED_GARDEN_VLAN_ID",
        "SMS_PROVIDER",
        "PAYMENT_PROVIDER",
    }
    updates: dict[str, str] = {}
    for k, v in (payload.updates or {}).items():
        if k not in allow:
            continue
        updates[k] = str(v)

    if not updates:
        return {"ok": True, "env_written": False, "restarts": {}}

    env_written = _envfile_set("/host/.env", updates)
    # Restart only what needs it.
    restart = []
    if any(k.startswith("WALLED_GARDEN_") or k in {"CW_DOMAIN", "CW_PUBLIC_BASE_URL"} for k in updates.keys()):
        restart += ["radius", "api", "admin"]
    restarts = _restart_services(sorted(set(restart)))
    return {"ok": True, "env_written": env_written, "restarts": restarts}


@app.post("/api/v1/ops/radius/test")
def radius_test(payload: RadiusTestIn, authorization: str | None = Header(default=None, alias="Authorization")):
    _require_admin(authorization)
    secret = _env("RADIUS_SHARED_SECRET") or ""
    if not secret:
        raise HTTPException(status_code=500, detail="Missing RADIUS_SHARED_SECRET in env")

    # radclient input is line-based "Attribute = value". Keep it simple and restrict surprises.
    username = payload.username.strip()
    password = payload.password
    calling = payload.calling_station_id.strip() or "AA-BB-CC-DD-EE-FF"
    nas_ip = payload.nas_ip.strip() or "127.0.0.1"
    if not username:
        raise HTTPException(status_code=400, detail="username is required")
    if any("\n" in x or "\r" in x for x in (username, password, calling, nas_ip)):
        raise HTTPException(status_code=400, detail="invalid input")

    # Avoid shell injection by constraining allowed characters (this is a diagnostic tool).
    if not re.match(r"^[+0-9A-Za-z@._:-]{1,128}$", username):
        raise HTTPException(status_code=400, detail="username contains unsupported characters")
    if not re.match(r"^[0-9A-Za-z._~+=/-]{1,128}$", password):
        raise HTTPException(status_code=400, detail="password contains unsupported characters")
    if not re.match(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$", calling):
        raise HTTPException(status_code=400, detail="calling_station_id must look like a MAC (AA-BB-CC-DD-EE-FF)")
    if not _is_ipv4(nas_ip):
        raise HTTPException(status_code=400, detail="nas_ip must be IPv4")

    c = _find_one_container("radius")
    # Use printf with %s to keep quoting predictable.
    out = _exec(
        c,
        [
            "sh",
            "-lc",
            "printf 'User-Name = %s\\nUser-Password = %s\\nCalling-Station-Id = %s\\nNAS-IP-Address = %s\\n' "
            + f"'{username}' '{password}' '{calling}' '{nas_ip}' "
            + f"| radclient -x 127.0.0.1:1812 auth '{secret}'",
        ],
        timeout_s=30,
    )
    verdict = "unknown"
    if "Access-Accept" in out:
        verdict = "ACCEPT"
    elif "Access-Reject" in out:
        verdict = "REJECT"
    return {"verdict": verdict, "output": out}
