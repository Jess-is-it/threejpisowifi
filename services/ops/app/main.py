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
    # First non-empty non-brace line is the site label.
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("{"):
            # global options block, skip until closed
            continue
        if s.startswith("#"):
            continue
        # Match: "<site> {"
        m = re.match(r"^(.+?)\s*\{\s*$", s)
        if m:
            return m.group(1).strip()
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


class DomainIn(BaseModel):
    domain: str = Field("", description="Caddy site address. Use example.com for HTTPS, or :80 for HTTP-only.")
    public_base_url: str = Field("", description="Informational base URL shown in the UI (does not change DNS).")
    mode: str = Field("https", description="https|http")


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
    return {"ok": True, "site": site}

