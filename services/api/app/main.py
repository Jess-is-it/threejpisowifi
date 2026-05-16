import os
import base64
import concurrent.futures
import csv
import ftplib
import html
import io
import json
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import hmac
import uuid
from hashlib import md5, sha256
from ipaddress import ip_address, ip_interface, ip_network
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import paramiko
import redis
import requests
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from .db import fetch_all, fetch_one, get_conn
from .omada_client import OmadaApiClient, OmadaApiError
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


class SiteDeploymentCreate(BaseModel):
    site_name: str
    application_scenario: str = "Office"
    country_region: Optional[str] = None
    time_zone: Optional[str] = None
    device_account_username: Optional[str] = None
    device_account_password: Optional[str] = None
    location_id: Optional[str] = None
    location: Optional[str] = None
    address: Optional[str] = None
    municipality: Optional[str] = None
    barangay: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    contact_name: Optional[str] = None
    contact_phone: Optional[str] = None
    deployment_status: str = "ACTIVE"
    notes: Optional[str] = None


class SiteDeploymentUpdate(BaseModel):
    location_id: Optional[str] = None
    contact_name: Optional[str] = None
    contact_phone: Optional[str] = None
    notes: Optional[str] = None


class ApAdoptRequest(BaseModel):
    site_id: str
    ap_macs: list[str] = Field(default_factory=list)
    ap_names: dict[str, str] = Field(default_factory=dict)
    username: Optional[str] = None
    password: Optional[str] = None


class ApDeploymentUpdate(BaseModel):
    display_name: str


class ApMapUpdate(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)


class ApDeploymentConfigurationUpdate(BaseModel):
    auto_apply_enabled: bool = True
    device_account_username: Optional[str] = None
    device_account_password: Optional[str] = None
    use_same_ssid: bool = True
    same_ssid_name: str = "3J-FreeWiFi"
    ssid_2g: str = "3J-FreeWiFi-2G"
    ssid_5g: str = "3J-FreeWiFi-5G"
    band_steering_enabled: bool = True
    security_mode: str = "OPEN"
    security_password: Optional[str] = None
    site_vlans: dict[str, Optional[int]] = Field(default_factory=dict)


class ApDeploymentConfigurationApplyRequest(BaseModel):
    site_id: Optional[str] = None
    ap_id: Optional[str] = None


class LocationCreate(BaseModel):
    location_name: Optional[str] = None
    address: str
    municipality: Optional[str] = None
    barangay: Optional[str] = None
    province: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    geocode_source: Optional[str] = None
    raw_geocode: Optional[dict] = None
    notes: Optional[str] = None


class SystemSettingsUpdate(BaseModel):
    general: Optional[dict] = None
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


class OmadaSettingsUpdate(BaseModel):
    controller_name: Optional[str] = None
    host: Optional[str] = None
    http_port: Optional[int] = Field(default=None, ge=1, le=65535)
    https_port: Optional[int] = Field(default=None, ge=1, le=65535)
    api_base_url: Optional[str] = None
    api_username: Optional[str] = None
    api_password: Optional[str] = None
    api_token: Optional[str] = None
    ssh_host: Optional[str] = None
    ssh_port: Optional[int] = Field(default=None, ge=1, le=65535)
    ssh_username: Optional[str] = None
    ssh_auth_type: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_private_key_passphrase: Optional[str] = None
    sudo_mode: Optional[str] = None
    install_method: Optional[str] = None
    network_mode: Optional[str] = None
    docker_image: Optional[str] = None
    checklist_progress: Optional[dict] = None


class OmadaWebTestRequest(BaseModel):
    host: Optional[str] = None
    http_port: Optional[int] = Field(default=None, ge=1, le=65535)
    https_port: Optional[int] = Field(default=None, ge=1, le=65535)


class OmadaNasCreate(BaseModel):
    name: str = "Omada Controller Staging"
    ip_address: str = "192.168.50.71"
    shortname: str = "omada-staging"
    secret: Optional[str] = None
    type: str = "Omada Controller"


class OmadaApiSettingsUpdate(BaseModel):
    controller_host: Optional[str] = None
    https_port: Optional[int] = Field(default=None, ge=1, le=65535)
    api_base_url: Optional[str] = None
    verify_tls: Optional[bool] = None
    username: Optional[str] = None
    password: Optional[str] = None
    controller_id: Optional[str] = None
    remember_credentials: Optional[bool] = True


class OmadaSiteSelect(BaseModel):
    site_id: str
    site_name: Optional[str] = None


class OmadaRadiusProfileRequest(BaseModel):
    environment: str = "STAGING"
    profile_name: Optional[str] = None
    radius_server_ip: str = "192.168.50.70"
    auth_port: Optional[int] = Field(default=None, ge=1, le=65535)
    accounting_port: Optional[int] = Field(default=None, ge=1, le=65535)
    shared_secret: Optional[str] = None
    accounting_enabled: bool = True
    interim_update_seconds: int = Field(default=300, ge=0, le=86400)


class OmadaMatchingNasRequest(BaseModel):
    environment: str = "STAGING"
    name: Optional[str] = None
    ip_address: str = "192.168.50.71"
    shortname: Optional[str] = None
    type: str = "Omada Controller"
    shared_secret: Optional[str] = None


class OmadaTestSsidRequest(BaseModel):
    environment: str = "STAGING"
    ssid_name: str = "3J-Test-WiFi"
    radius_profile_id: Optional[str] = None


class VoucherCreate(BaseModel):
    voucher_type: str = "TIME_BASED"
    code: Optional[str] = None
    time_value_seconds: Optional[int] = Field(default=None, ge=0)
    valid_until: Optional[datetime] = None
    unlimited_expires_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    note: Optional[str] = None
    status: str = "UNUSED"
    max_redemptions: int = Field(default=1, ge=1)
    code_prefix: Optional[str] = None
    code_length: int = Field(default=8, ge=4, le=32)


class VoucherUpdate(BaseModel):
    voucher_type: Optional[str] = None
    time_value_seconds: Optional[int] = Field(default=None, ge=0)
    valid_until: Optional[datetime] = None
    unlimited_expires_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    note: Optional[str] = None
    status: Optional[str] = None
    max_redemptions: Optional[int] = Field(default=None, ge=1)


class VoucherBatchCreate(BaseModel):
    batch_name: str
    description: Optional[str] = None
    voucher_type: str = "TIME_BASED"
    quantity: int = Field(default=10, ge=1, le=5000)
    time_value_seconds: Optional[int] = Field(default=None, ge=0)
    valid_until: Optional[datetime] = None
    unlimited_expires_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    price: Optional[float] = None
    code_prefix: Optional[str] = None
    code_length: int = Field(default=8, ge=4, le=32)
    note: Optional[str] = None
    max_redemptions: int = Field(default=1, ge=1)


class VoucherRedeemTest(BaseModel):
    voucher_code: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    device_identifier: Optional[str] = None


class PortalSessionRequest(BaseModel):
    portal_session_id: Optional[str] = None
    mac: Optional[str] = None
    ip: Optional[str] = None
    client_mac: Optional[str] = None
    clientMac: Optional[str] = None
    client_ip: Optional[str] = None
    ap_mac: Optional[str] = None
    apMac: Optional[str] = None
    gateway_mac: Optional[str] = None
    gatewayMac: Optional[str] = None
    vlan_id: Optional[str] = None
    vid: Optional[str] = None
    ssid: Optional[str] = None
    site: Optional[str] = None
    gateway: Optional[str] = None
    redirect_url: Optional[str] = None
    redirectUrl: Optional[str] = None
    nas_id: Optional[str] = None
    server_name: Optional[str] = None
    link_login: Optional[str] = None
    link_login_only: Optional[str] = None
    link_orig: Optional[str] = None
    chap_id: Optional[str] = None
    chap_challenge: Optional[str] = None
    token: Optional[str] = None
    authToken: Optional[str] = None
    raw_query_params: Optional[dict] = None


class PortalRedeemRequest(PortalSessionRequest):
    voucher_code: str


class CaptivePortalSettingsUpdate(BaseModel):
    portal_mode: Optional[str] = None
    open_ssid_name: Optional[str] = None
    portal_url_staging: Optional[str] = None
    portal_url_production: Optional[str] = None
    default_access_duration_seconds: Optional[int] = Field(default=None, ge=1)
    post_login_redirect_url: Optional[str] = None
    selected_omada_site_id: Optional[str] = None
    selected_omada_site_name: Optional[str] = None
    test_checklist_progress: Optional[dict] = None
    status: Optional[str] = None


class OmadaPortalConfigureRequest(BaseModel):
    portal_url: Optional[str] = None
    ssid_name: Optional[str] = None


class MikrotikRouterCreate(BaseModel):
    router_name: str
    host: str
    api_port: int = Field(default=8728, ge=1, le=65535)
    use_tls: bool = False
    username: Optional[str] = None
    password: Optional[str] = None
    account_privilege: str = "FULL"
    notes: Optional[str] = None
    hotspot_vlan_id: Optional[int] = Field(default=None, ge=1, le=4094)
    hotspot_vlan_parent_interface: Optional[str] = None
    hotspot_vlan_interface_name: Optional[str] = None
    hotspot_interface: Optional[str] = None
    hotspot_profile_name: Optional[str] = None
    hotspot_server_name: Optional[str] = None
    hotspot_dns_name: Optional[str] = None
    hotspot_html_directory: Optional[str] = None
    hotspot_client_network_cidr: Optional[str] = None
    hotspot_gateway_ip: Optional[str] = None
    hotspot_pool_start_ip: Optional[str] = None
    hotspot_pool_end_ip: Optional[str] = None
    hotspot_pool_name: Optional[str] = None
    hotspot_dhcp_server_name: Optional[str] = None
    hotspot_dhcp_lease_time: Optional[str] = None
    hotspot_dns_servers: Optional[str] = None
    hotspot_wan_interface: Optional[str] = None
    hotspot_enable_nat: bool = False


class MikrotikRouterUpdate(BaseModel):
    router_name: Optional[str] = None
    host: Optional[str] = None
    api_port: Optional[int] = Field(default=None, ge=1, le=65535)
    use_tls: Optional[bool] = None
    username: Optional[str] = None
    password: Optional[str] = None
    account_privilege: Optional[str] = None
    notes: Optional[str] = None
    hotspot_vlan_id: Optional[int] = Field(default=None, ge=1, le=4094)
    hotspot_vlan_parent_interface: Optional[str] = None
    hotspot_vlan_interface_name: Optional[str] = None
    hotspot_interface: Optional[str] = None
    hotspot_profile_name: Optional[str] = None
    hotspot_server_name: Optional[str] = None
    hotspot_dns_name: Optional[str] = None
    hotspot_html_directory: Optional[str] = None
    hotspot_client_network_cidr: Optional[str] = None
    hotspot_gateway_ip: Optional[str] = None
    hotspot_pool_start_ip: Optional[str] = None
    hotspot_pool_end_ip: Optional[str] = None
    hotspot_pool_name: Optional[str] = None
    hotspot_dhcp_server_name: Optional[str] = None
    hotspot_dhcp_lease_time: Optional[str] = None
    hotspot_dns_servers: Optional[str] = None
    hotspot_wan_interface: Optional[str] = None
    hotspot_enable_nat: Optional[bool] = None


class MikrotikStationRouterPayload(BaseModel):
    router_id: str
    bridge_name: Optional[str] = Field(default=None, max_length=200)
    tagged_ports: Optional[str] = Field(default=None, max_length=1200)
    notes: Optional[str] = Field(default=None, max_length=1200)


class MikrotikStationCreate(BaseModel):
    station_name: str = Field(min_length=1, max_length=160)
    station_code: Optional[str] = Field(default=None, max_length=80)
    description: Optional[str] = Field(default=None, max_length=2000)
    vlan_id: int = Field(ge=1, le=4094)
    vlan_interface_name: Optional[str] = Field(default=None, max_length=200)
    client_network_cidr: str = Field(min_length=4, max_length=64)
    gateway_ip: str = Field(min_length=3, max_length=64)
    pool_start_ip: str = Field(min_length=3, max_length=64)
    pool_end_ip: str = Field(min_length=3, max_length=64)
    pool_name: Optional[str] = Field(default=None, max_length=200)
    dhcp_server_name: Optional[str] = Field(default=None, max_length=200)
    dhcp_lease_time: Optional[str] = Field(default="1h", max_length=80)
    create_dhcp_server: bool = True
    dns_servers: Optional[str] = Field(default=None, max_length=400)
    local_interface_list: Optional[str] = Field(default="LOCAL", max_length=120)
    create_hotspot_profile: bool = True
    create_hotspot_server: bool = True
    create_walled_garden: bool = True
    hotspot_profile_name: Optional[str] = Field(default=None, max_length=200)
    hotspot_html_directory: Optional[str] = Field(default="hotspot", max_length=160)
    hotspot_dns_name: Optional[str] = Field(default=None, max_length=200)
    hotspot_server_name: Optional[str] = Field(default=None, max_length=200)
    portal_url: Optional[str] = Field(default=None, max_length=500)
    ap_management_enabled: bool = False
    ap_management_vlan_id: Optional[int] = Field(default=111, ge=1, le=4094)
    ap_management_vlan_interface_name: Optional[str] = Field(default=None, max_length=200)
    ap_management_network_cidr: Optional[str] = Field(default="10.111.0.0/24", max_length=64)
    ap_management_gateway_ip: Optional[str] = Field(default="10.111.0.1", max_length=64)
    ap_management_pool_start_ip: Optional[str] = Field(default="10.111.0.10", max_length=64)
    ap_management_pool_end_ip: Optional[str] = Field(default="10.111.0.254", max_length=64)
    ap_management_pool_name: Optional[str] = Field(default=None, max_length=200)
    ap_management_dhcp_server_name: Optional[str] = Field(default=None, max_length=200)
    ap_management_dhcp_lease_time: Optional[str] = Field(default="1h", max_length=80)
    ap_management_dns_servers: Optional[str] = Field(default=None, max_length=400)
    routers: list[MikrotikStationRouterPayload] = Field(default_factory=list)


class MikrotikApManagementRouterPayload(BaseModel):
    router_id: str
    bridge_name: Optional[str] = Field(default=None, max_length=200)
    tagged_ports: Optional[str] = Field(default=None, max_length=1200)
    notes: Optional[str] = Field(default=None, max_length=1200)


class MikrotikApManagementConfigPayload(BaseModel):
    config_name: str = Field(default="Central AP Management", min_length=1, max_length=160)
    vlan_id: int = Field(default=111, ge=1, le=4094)
    vlan_interface_name: Optional[str] = Field(default=None, max_length=200)
    network_cidr: str = Field(default="10.111.0.0/24", min_length=4, max_length=64)
    gateway_ip: Optional[str] = Field(default="10.111.0.1", max_length=64)
    pool_start_ip: Optional[str] = Field(default="10.111.0.10", max_length=64)
    pool_end_ip: Optional[str] = Field(default="10.111.0.254", max_length=64)
    pool_name: Optional[str] = Field(default=None, max_length=200)
    dhcp_server_name: Optional[str] = Field(default=None, max_length=200)
    dhcp_lease_time: Optional[str] = Field(default="1h", max_length=80)
    dns_servers: Optional[str] = Field(default=None, max_length=400)
    local_interface_list: Optional[str] = Field(default="LOCAL", max_length=120)
    routers: list[MikrotikApManagementRouterPayload] = Field(default_factory=list)


class MikrotikConfigurationStepApply(BaseModel):
    step_key: str


class MikrotikStationCommandApply(BaseModel):
    router_id: str
    command_index: int = Field(ge=0)


class MikrotikHotspotLoginSyncPayload(BaseModel):
    station_ids: Optional[list[str]] = None


class MikrotikDeploymentModePayload(BaseModel):
    confirmed_router_role: str
    confirmed_deployment_mode: str
    sensitive_confirmation: bool = False


class MikrotikExpertOverridePayload(BaseModel):
    confirmation_phrase: str
    reason: str = Field(min_length=4, max_length=1000)


class PortalDesignUpdate(BaseModel):
    html_template: str
    css_template: Optional[str] = ""


class OpenAISettingsPayload(BaseModel):
    api_key: Optional[str] = Field(default=None, max_length=400)
    clear_api_key: bool = False
    selected_model: Optional[str] = Field(default=None, max_length=80)
    reasoning_effort: Optional[str] = Field(default=None, max_length=20)
    organization_id: Optional[str] = Field(default=None, max_length=200)
    project_id: Optional[str] = Field(default=None, max_length=200)


class OpenAITestPayload(BaseModel):
    prompt: str = Field(default="Reply with one short sentence confirming this API key works.", max_length=4000)
    model_id: Optional[str] = Field(default=None, max_length=80)
    reasoning_effort: Optional[str] = Field(default=None, max_length=20)
    max_output_tokens: int = Field(default=120, ge=16, le=512)


class MikrotikAiConversationCreate(BaseModel):
    router_id: Optional[str] = None
    title: Optional[str] = Field(default=None, max_length=160)


class MikrotikAiMessageCreate(BaseModel):
    message_text: str = Field(min_length=1, max_length=4000)
    router_id: Optional[str] = None


class MikrotikDeploymentQuestionUpdate(BaseModel):
    answer_value: Optional[str] = Field(default=None, max_length=2000)


class MikrotikDeploymentQuestionsSaveAll(BaseModel):
    answers: dict[str, Optional[str]] = Field(default_factory=dict)


class MikrotikDeploymentQuestionAction(BaseModel):
    question_key: str = Field(min_length=1, max_length=120)
    value: Optional[str] = Field(default=None, max_length=2000)
    locked: Optional[bool] = None


class MikrotikDraftPlanGenerateRequest(BaseModel):
    note: Optional[str] = Field(default=None, max_length=1200)


class MikrotikPilotSelectionPayload(BaseModel):
    router_id: str
    reason: Optional[str] = Field(default=None, max_length=1200)
    physical_recovery_confidence: str = "MODERATE"
    operator_note: Optional[str] = Field(default=None, max_length=2000)


class MikrotikVlanPathPlanPayload(BaseModel):
    hotspot_gateway_router_id: Optional[str] = None
    gateway_parent_interface: Optional[str] = Field(default=None, max_length=200)
    next_hop_type: str = "UNKNOWN"
    crs_involved: bool = False
    crs_router_id: Optional[str] = None
    crs_port_to_gateway: Optional[str] = Field(default=None, max_length=400)
    crs_ports_to_olt_ap: Optional[str] = Field(default=None, max_length=800)
    olts_involved: bool = False
    olt_notes: Optional[str] = Field(default=None, max_length=2000)
    olt_vlan_behavior: str = "UNKNOWN"
    ap_vlan_mode: str = "UNKNOWN"
    ssid_vlan_id: Optional[int] = Field(default=None, ge=1, le=4094)
    confirmation_status: str = "DRAFT"


def audit(actor_id: str, action: str, target_type: str = None, target_id: str = None, details: dict = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_logs(actor_admin_id, action, target_type, target_id, details) VALUES (%s, %s, %s, %s, %s)",
                (actor_id, action, target_type, target_id, Json(details or {})),
            )


def secret_box():
    seed = os.getenv("SECRET_KEY") or os.getenv("JWT_SECRET") or os.getenv("POSTGRES_PASSWORD") or "change-me"
    return Fernet(base64.urlsafe_b64encode(sha256(seed.encode()).digest()))


def encrypt_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return secret_box().encrypt(value.encode()).decode()


def decrypt_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return secret_box().decrypt(value.encode()).decode()
    except InvalidToken:
        return None


def redact(text: str) -> str:
    if not text:
        return ""
    redacted = text
    for row in fetch_all("SELECT api_password_encrypted, api_token_encrypted, ssh_password_encrypted, ssh_private_key_encrypted, ssh_private_key_passphrase_encrypted FROM omada_controller_settings"):
        for key in row:
            secret_value = decrypt_secret(row.get(key))
            if secret_value:
                redacted = redacted.replace(secret_value, "[REDACTED]")
    return redacted


def omada_default_settings():
    return {
        "controller_name": "Omada Controller",
        "host": "192.168.50.71",
        "http_port": 8088,
        "https_port": 8043,
        "api_base_url": "https://192.168.50.71:8043",
        "api_username": None,
        "ssh_host": "192.168.50.71",
        "ssh_port": 22,
        "ssh_username": None,
        "ssh_auth_type": "PASSWORD",
        "sudo_mode": "PASSWORDLESS",
        "install_method": "DOCKER",
        "network_mode": "bridge",
        "docker_image": "mbentley/omada-controller:latest",
        "install_status": "NOT_INSTALLED",
        "last_detected_version": None,
        "last_status_check_at": None,
        "last_error": None,
        "checklist_progress": {},
    }


def ensure_omada_settings():
    row = fetch_one("SELECT * FROM omada_controller_settings ORDER BY created_at ASC LIMIT 1")
    if row:
        return row
    defaults = omada_default_settings()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO omada_controller_settings(controller_name, host, http_port, https_port, api_base_url, ssh_host, ssh_port, ssh_auth_type, sudo_mode, install_method, network_mode, docker_image)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    defaults["controller_name"], defaults["host"], defaults["http_port"], defaults["https_port"], defaults["api_base_url"],
                    defaults["ssh_host"], defaults["ssh_port"], defaults["ssh_auth_type"], defaults["sudo_mode"], defaults["install_method"],
                    defaults["network_mode"], defaults["docker_image"],
                ),
            )
            return cur.fetchone()


def public_omada_settings(row=None):
    row = row or ensure_omada_settings()
    return {
        "id": row["id"],
        "controller_name": row["controller_name"],
        "host": row["host"],
        "http_port": row["http_port"],
        "https_port": row["https_port"],
        "api_base_url": row["api_base_url"],
        "api_username": row["api_username"],
        "has_api_password": bool(row.get("api_password_encrypted")),
        "has_api_token": bool(row.get("api_token_encrypted")),
        "ssh_host": row["ssh_host"],
        "ssh_port": row["ssh_port"],
        "ssh_username": row["ssh_username"],
        "ssh_auth_type": row["ssh_auth_type"],
        "has_ssh_password": bool(row.get("ssh_password_encrypted")),
        "has_ssh_private_key": bool(row.get("ssh_private_key_encrypted")),
        "has_ssh_private_key_passphrase": bool(row.get("ssh_private_key_passphrase_encrypted")),
        "sudo_mode": row["sudo_mode"],
        "install_method": row["install_method"],
        "network_mode": row["network_mode"],
        "docker_image": row["docker_image"],
        "install_status": row["install_status"],
        "last_detected_version": row["last_detected_version"],
        "last_status_check_at": row["last_status_check_at"],
        "last_error": row["last_error"],
        "checklist_progress": row["checklist_progress"] or {},
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def normalize_environment(environment: str) -> str:
    value = (environment or "STAGING").upper()
    if value not in {"STAGING", "PRODUCTION"}:
        raise HTTPException(status_code=400, detail="Environment must be STAGING or PRODUCTION")
    return value


def radius_defaults(environment: str, shared_secret: Optional[str] = None):
    env = normalize_environment(environment)
    return {
        "environment": env,
        "profile_name": f"3JCentralPisowifi {'Staging' if env == 'STAGING' else 'Production'} RADIUS",
        "radius_server_ip": "192.168.50.70",
        "auth_port": 11812 if env == "STAGING" else 1812,
        "accounting_port": 11813 if env == "STAGING" else 1813,
        "shared_secret": shared_secret or secrets.token_urlsafe(24),
        "accounting_enabled": True,
        "interim_update_seconds": 300,
        "ssid_name": "3J-Test-WiFi",
    }


OPENAI_PRICING_SOURCE = {
    "label": "OpenAI API pricing",
    "url": "https://platform.openai.com/docs/pricing/",
    "checked_at": "2026-05-11",
    "unit": "USD per 1M tokens, Standard short-context pricing",
    "note": "Long-context, Batch, Flex, Priority, regional processing, tool, image, audio, and video pricing can differ.",
}
OPENAI_REASONING_EFFORTS = [
    {"id": "none", "label": "None", "description": "Fastest responses for models that support no explicit reasoning."},
    {"id": "minimal", "label": "Minimal", "description": "Very light reasoning for simple checks and short responses."},
    {"id": "low", "label": "Low", "description": "Lower latency and lower reasoning token use."},
    {"id": "medium", "label": "Medium", "description": "Default balance between speed, cost, and reasoning quality."},
    {"id": "high", "label": "High", "description": "More complete reasoning for complex tasks."},
    {"id": "xhigh", "label": "Extra high", "description": "Maximum supported reasoning effort for the hardest tasks."},
]
OPENAI_MODEL_OPTIONS = [
    {
        "id": "gpt-5.5",
        "label": "GPT-5.5",
        "category": "Flagship",
        "recommended_for": "Highest-quality customer workflows, complex automation, tool-heavy assistants, and long-context analysis.",
        "context_window": "1M",
        "max_output": "128K",
        "reasoning": "none, minimal, low, medium, high, xhigh",
        "reasoning_efforts": ["none", "minimal", "low", "medium", "high", "xhigh"],
        "prices": {"input": 5.00, "cached_input": 0.50, "output": 30.00},
    },
    {
        "id": "gpt-5.4",
        "label": "GPT-5.4",
        "category": "Balanced flagship",
        "recommended_for": "Balanced quality and cost for production ISP back-office assistance.",
        "context_window": "1M",
        "max_output": "128K",
        "reasoning": "none, minimal, low, medium, high, xhigh",
        "reasoning_efforts": ["none", "minimal", "low", "medium", "high", "xhigh"],
        "prices": {"input": 2.50, "cached_input": 0.25, "output": 15.00},
    },
    {
        "id": "gpt-5.4-mini",
        "label": "GPT-5.4 mini",
        "category": "Default ISP operations pick",
        "recommended_for": "Cost-conscious support drafting, summaries, classification, and routine customer/account tasks.",
        "context_window": "400K",
        "max_output": "128K",
        "reasoning": "none, minimal, low, medium, high, xhigh",
        "reasoning_efforts": ["none", "minimal", "low", "medium", "high", "xhigh"],
        "prices": {"input": 0.75, "cached_input": 0.075, "output": 4.50},
    },
    {
        "id": "gpt-5.4-nano",
        "label": "GPT-5.4 nano",
        "category": "Lowest cost",
        "recommended_for": "Simple labels, fast checks, short rewrites, and low-cost helper tasks.",
        "context_window": "400K",
        "max_output": "128K",
        "reasoning": "none, minimal, low, medium, high, xhigh",
        "reasoning_efforts": ["none", "minimal", "low", "medium", "high", "xhigh"],
        "prices": {"input": 0.20, "cached_input": 0.02, "output": 1.25},
    },
    {
        "id": "gpt-5.5-pro",
        "label": "GPT-5.5 pro",
        "category": "Premium reasoning",
        "recommended_for": "Rare high-stakes analysis where output quality matters more than speed or cost.",
        "context_window": "1M",
        "max_output": "128K",
        "reasoning": "high, xhigh",
        "reasoning_efforts": ["high", "xhigh"],
        "prices": {"input": 30.00, "cached_input": None, "output": 180.00},
    },
    {
        "id": "gpt-5.4-pro",
        "label": "GPT-5.4 pro",
        "category": "Premium balanced",
        "recommended_for": "High-effort analysis with lower cost than GPT-5.5 pro.",
        "context_window": "1M",
        "max_output": "128K",
        "reasoning": "high, xhigh",
        "reasoning_efforts": ["high", "xhigh"],
        "prices": {"input": 30.00, "cached_input": None, "output": 180.00},
    },
]
DEFAULT_OPENAI_MODEL = "gpt-5.4-mini"
DEFAULT_OPENAI_REASONING_EFFORT = "medium"


def mask_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    return "[REDACTED]" if len(value) <= 4 else f"[REDACTED]...{value[-4:]}"


def sanitize_summary(value):
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if any(word in key.lower() for word in ["password", "secret", "token", "authorization", "csrf", "api_key", "apikey"]):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = sanitize_summary(item)
        return clean
    if isinstance(value, list):
        return [sanitize_summary(item) for item in value[:20]]
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if hasattr(value, "hex") and value.__class__.__name__ == "UUID":
        return str(value)
    if isinstance(value, bytes):
        return sanitize_routeros_text(value) if "sanitize_routeros_text" in globals() else value.decode("utf-8", errors="replace").replace("\x00", "")
    if isinstance(value, str) and len(value) > 1200:
        text = sanitize_routeros_text(value) if "sanitize_routeros_text" in globals() else value.replace("\x00", "")
        return text[:1200] + "...[truncated]"
    if isinstance(value, str):
        return sanitize_routeros_text(value) if "sanitize_routeros_text" in globals() else value.replace("\x00", "")
    return value


def json_safe(value):
    return sanitize_summary(value)


def normalize_openai_text(value) -> str:
    return str(value or "").strip()


def openai_model_by_id(model_id: Optional[str]) -> Optional[dict]:
    normalized = normalize_openai_text(model_id)
    return next((model for model in OPENAI_MODEL_OPTIONS if model["id"] == normalized), None)


def normalize_openai_model(model_id: Optional[str]) -> str:
    model = openai_model_by_id(model_id or DEFAULT_OPENAI_MODEL)
    if model is None:
        allowed = ", ".join(model["id"] for model in OPENAI_MODEL_OPTIONS)
        raise HTTPException(status_code=400, detail=f"Unknown OpenAI model. Choose one of: {allowed}")
    return model["id"]


def openai_reasoning_effort_ids_for_model(model_id: Optional[str]) -> list[str]:
    model = openai_model_by_id(model_id)
    if not model:
        return [DEFAULT_OPENAI_REASONING_EFFORT]
    efforts = model.get("reasoning_efforts")
    if isinstance(efforts, list) and efforts:
        return [normalize_openai_text(effort).lower() for effort in efforts if normalize_openai_text(effort)]
    reasoning = normalize_openai_text(model.get("reasoning"))
    return [effort.strip().lower() for effort in reasoning.split(",") if effort.strip()] or [DEFAULT_OPENAI_REASONING_EFFORT]


def default_openai_reasoning_effort(model_id: Optional[str]) -> str:
    efforts = openai_reasoning_effort_ids_for_model(model_id)
    if DEFAULT_OPENAI_REASONING_EFFORT in efforts:
        return DEFAULT_OPENAI_REASONING_EFFORT
    return efforts[0]


def normalize_openai_reasoning_effort(model_id: Optional[str], effort_id: Optional[str], strict: bool = False) -> str:
    model = normalize_openai_model(model_id)
    efforts = openai_reasoning_effort_ids_for_model(model)
    effort = normalize_openai_text(effort_id).lower().replace("_", "-")
    if not effort:
        return default_openai_reasoning_effort(model)
    if effort not in efforts:
        if strict:
            allowed = ", ".join(efforts)
            raise HTTPException(status_code=400, detail=f"Unsupported reasoning effort for {model}. Choose one of: {allowed}")
        return default_openai_reasoning_effort(model)
    return effort


def public_openai_reasoning_efforts(model_id: Optional[str]) -> list[dict]:
    effort_ids = set(openai_reasoning_effort_ids_for_model(model_id))
    return [effort for effort in OPENAI_REASONING_EFFORTS if effort["id"] in effort_ids]


def mask_openai_api_key(api_key: Optional[str]) -> Optional[str]:
    value = normalize_openai_text(api_key)
    if not value:
        return None
    if len(value) <= 10:
        return f"{value[:3]}..."
    return f"{value[:7]}...{value[-4:]}"


def openai_store() -> dict:
    row = fetch_one("SELECT value FROM app_settings WHERE key = 'openai'")
    store = row["value"] if row and isinstance(row["value"], dict) else {}
    selected_model = normalize_openai_text(store.get("selected_model"))
    if not openai_model_by_id(selected_model):
        selected_model = DEFAULT_OPENAI_MODEL
    store["selected_model"] = selected_model
    store["reasoning_effort"] = normalize_openai_reasoning_effort(selected_model, store.get("reasoning_effort"))
    store.setdefault("organization_id", "")
    store.setdefault("project_id", "")
    return store


def save_openai_store(store: dict):
    clean = {
        "api_key_encrypted": store.get("api_key_encrypted"),
        "selected_model": normalize_openai_model(store.get("selected_model")),
        "reasoning_effort": normalize_openai_reasoning_effort(store.get("selected_model"), store.get("reasoning_effort")),
        "organization_id": normalize_openai_text(store.get("organization_id")),
        "project_id": normalize_openai_text(store.get("project_id")),
    }
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_settings(key, value, updated_at)
                VALUES ('openai', %s, now())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """,
                (Json(clean),),
            )


def public_openai_settings() -> dict:
    store = openai_store()
    selected_model = normalize_openai_model(store.get("selected_model"))
    selected_reasoning_effort = normalize_openai_reasoning_effort(selected_model, store.get("reasoning_effort"))
    api_key = decrypt_secret(store.get("api_key_encrypted"))
    return {
        "api_key_configured": bool(normalize_openai_text(api_key)),
        "api_key_hint": mask_openai_api_key(api_key),
        "selected_model": selected_model,
        "selected_reasoning_effort": selected_reasoning_effort,
        "selected_model_config": openai_model_by_id(selected_model),
        "organization_id": normalize_openai_text(store.get("organization_id")),
        "project_id": normalize_openai_text(store.get("project_id")),
        "models": OPENAI_MODEL_OPTIONS,
        "reasoning_efforts": OPENAI_REASONING_EFFORTS,
        "selected_model_reasoning_efforts": public_openai_reasoning_efforts(selected_model),
        "pricing_source": OPENAI_PRICING_SOURCE,
    }


def extract_openai_response_text(response_data: dict) -> str:
    output_text = response_data.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()
    output = response_data.get("output")
    texts = []
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    text = part.get("text")
                    if isinstance(text, str) and text.strip():
                        texts.append(text.strip())
    return "\n".join(texts).strip()


def openai_api_status() -> dict:
    store = openai_store()
    api_key = decrypt_secret(store.get("api_key_encrypted"))
    model_id = normalize_openai_model(store.get("selected_model"))
    return {
        "configured": bool(normalize_openai_text(api_key)),
        "model": model_id,
        "reasoning_effort": normalize_openai_reasoning_effort(model_id, store.get("reasoning_effort")),
    }


def call_openai_responses(system_prompt: str, user_payload, max_output_tokens: int = 900, user_agent: str = "3JCentralPisowifi/0.1 ai-network-assistant", text_format: Optional[dict] = None, reasoning_effort_override: Optional[str] = None) -> str:
    store = openai_store()
    api_key = decrypt_secret(store.get("api_key_encrypted"))
    if not normalize_openai_text(api_key):
        raise HTTPException(status_code=400, detail="OpenAI API key is not configured. AI features are optional; preflight and planning still work without AI.")
    model_id = normalize_openai_model(store.get("selected_model"))
    reasoning_effort = normalize_openai_reasoning_effort(model_id, reasoning_effort_override or store.get("reasoning_effort"))
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    organization_id = normalize_openai_text(store.get("organization_id"))
    project_id = normalize_openai_text(store.get("project_id"))
    if organization_id:
        headers["OpenAI-Organization"] = organization_id
    if project_id:
        headers["OpenAI-Project"] = project_id
    payload_text = user_payload if isinstance(user_payload, str) else json.dumps(json_safe(user_payload), default=str)
    body = {
        "model": model_id,
        "input": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": payload_text[:24000]},
        ],
        "max_output_tokens": max_output_tokens,
    }
    if reasoning_effort:
        body["reasoning"] = {"effort": reasoning_effort}
    if text_format:
        body["text"] = {"format": text_format}
    try:
        response = requests.post("https://api.openai.com/v1/responses", headers=headers, json=body, timeout=60)
        response_data = response.json() if response.content else {}
        if response.status_code >= 400:
            message = response_data.get("error", {}).get("message") if isinstance(response_data, dict) else None
            raise RuntimeError(message or f"OpenAI API returned HTTP {response.status_code}")
        output_text = extract_openai_response_text(response_data if isinstance(response_data, dict) else {})
        if not output_text:
            raise RuntimeError("OpenAI returned an empty response.")
        return sanitize_routeros_text(output_text, max_length=12000)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"OpenAI request failed: {exc}") from exc


def clear_site_deployment_tombstone(cur, omada_site_id: Optional[str] = None, site_name: Optional[str] = None):
    clean_site_id = str(omada_site_id or "").strip() or None
    clean_site_name = str(site_name or "").strip() or None
    if not clean_site_id and not clean_site_name:
        return
    conditions = []
    params = []
    if clean_site_id:
        conditions.append("omada_site_id = %s")
        params.append(clean_site_id)
    if clean_site_name:
        conditions.append("lower(site_name) = lower(%s)")
        params.append(clean_site_name)
    cur.execute(f"DELETE FROM site_deployment_tombstones WHERE {' OR '.join(conditions)}", tuple(params))


def record_site_deployment_tombstone(
    cur,
    omada_site_id: Optional[str],
    site_name: Optional[str],
    admin_id: Optional[str],
    omada_delete_attempted: bool,
    omada_deleted: bool,
    omada_delete_error: Optional[str],
    omada_response_summary: Optional[dict],
):
    clean_site_id = str(omada_site_id or "").strip() or None
    clean_site_name = str(site_name or "").strip() or None
    if not clean_site_id and not clean_site_name:
        return
    clear_site_deployment_tombstone(cur, clean_site_id, clean_site_name)
    cur.execute(
        """
        INSERT INTO site_deployment_tombstones(
            omada_site_id, site_name, deleted_by_admin_id, omada_delete_attempted,
            omada_deleted, omada_delete_error, omada_response_summary
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            clean_site_id,
            clean_site_name,
            admin_id,
            omada_delete_attempted,
            omada_deleted,
            omada_delete_error,
            Json(sanitize_summary(omada_response_summary or {})),
        ),
    )


def ensure_omada_api_settings():
    row = fetch_one("SELECT * FROM omada_api_settings ORDER BY created_at ASC LIMIT 1")
    if row:
        return row
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO omada_api_settings(controller_host, https_port, api_base_url, verify_tls)
                VALUES ('192.168.50.71', 8043, 'https://192.168.50.71:8043', false)
                RETURNING *
                """
            )
            return cur.fetchone()


def public_omada_api_settings(row=None):
    row = row or ensure_omada_api_settings()
    return {
        "id": row["id"],
        "controller_host": row["controller_host"],
        "https_port": row["https_port"],
        "api_base_url": row["api_base_url"],
        "verify_tls": row["verify_tls"],
        "username": row["username"],
        "has_password": bool(row.get("password_encrypted")),
        "controller_id": row["controller_id"],
        "selected_site_id": row["selected_site_id"],
        "selected_site_name": row["selected_site_name"],
        "last_login_success_at": row["last_login_success_at"],
        "last_login_error": row["last_login_error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def omada_api_client_from_settings():
    row = ensure_omada_api_settings()
    password = decrypt_secret(row.get("password_encrypted"))
    if not row.get("username") or not password:
        raise HTTPException(status_code=400, detail="Omada API username and password are required")
    return row, OmadaApiClient(
        row["api_base_url"],
        row["username"],
        password,
        verify_tls=bool(row["verify_tls"]),
        controller_id=row.get("controller_id"),
    )


def log_omada_automation(admin_id, action: str, status: str, request_summary: dict = None, response_summary: dict = None, error_message: str = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO omada_automation_logs(admin_id, action, status, request_summary, response_summary, error_message)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    admin_id,
                    action,
                    status,
                    Json(sanitize_summary(request_summary or {})),
                    Json(sanitize_summary(response_summary or {})),
                    error_message,
                ),
            )


def tcp_check(host: str, port: int, timeout: float = 3.0):
    started = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"port": int(port), "status": "Reachable", "latency_ms": int((time.time() - started) * 1000)}
    except socket.timeout:
        return {"port": int(port), "status": "Timeout", "latency_ms": None}
    except ConnectionRefusedError:
        return {"port": int(port), "status": "Connection refused", "latency_ms": None}
    except OSError as exc:
        return {"port": int(port), "status": "Not reachable", "error": str(exc), "latency_ms": None}


def routeros_write_word(sock, word: str):
    data = word.encode()
    length = len(data)
    if length < 0x80:
        prefix = bytes([length])
    elif length < 0x4000:
        prefix = struct.pack("!H", length | 0x8000)
    elif length < 0x200000:
        prefix = struct.pack("!I", length | 0xC00000)[1:]
    elif length < 0x10000000:
        prefix = struct.pack("!I", length | 0xE0000000)
    else:
        prefix = b"\xF0" + struct.pack("!I", length)
    sock.sendall(prefix + data)


def routeros_read_length(sock):
    first = sock.recv(1)
    if not first:
        raise OSError("RouterOS API closed the connection")
    c = first[0]
    if (c & 0x80) == 0:
        return c
    if (c & 0xC0) == 0x80:
        return ((c & ~0xC0) << 8) + sock.recv(1)[0]
    if (c & 0xE0) == 0xC0:
        rest = sock.recv(2)
        return ((c & ~0xE0) << 16) + (rest[0] << 8) + rest[1]
    if (c & 0xF0) == 0xE0:
        rest = sock.recv(3)
        return ((c & ~0xF0) << 24) + (rest[0] << 16) + (rest[1] << 8) + rest[2]
    rest = sock.recv(4)
    return struct.unpack("!I", rest)[0]


def routeros_read_sentence(sock):
    words = []
    while True:
        length = routeros_read_length(sock)
        if length == 0:
            return words
        words.append(sock.recv(length).decode(errors="replace"))


def routeros_send_sentence(sock, words):
    for word in words:
        routeros_write_word(sock, word)
    routeros_write_word(sock, "")


def routeros_sentence_dict(sentence):
    data = {}
    for word in sentence[1:]:
        if word.startswith("="):
            key_value = word[1:].split("=", 1)
            if len(key_value) == 2:
                key = sanitize_routeros_text(key_value[0], max_length=200) or "field"
                data[key] = sanitize_routeros_text(key_value[1])
    return data


def routeros_read_result(sock):
    replies = []
    while True:
        sentence = routeros_read_sentence(sock)
        if not sentence:
            continue
        marker = sentence[0]
        if marker == "!re":
            replies.append(routeros_sentence_dict(sentence))
            continue
        if marker == "!empty":
            continue
        if marker == "!done":
            return replies
        if marker == "!trap":
            message = next((word.split("=", 2)[2] for word in sentence if word.startswith("=message=")), "RouterOS API command failed")
            raise RuntimeError(sanitize_routeros_text(message))
        raise RuntimeError(f"Unexpected RouterOS API response: {sanitize_routeros_text(marker)}")


def routeros_login_socket(sock, username: Optional[str], password: Optional[str]):
    routeros_send_sentence(sock, ["/login", f"=name={username or ''}", f"=password={password or ''}"])
    routeros_read_result(sock)


def routeros_cli_preview(path: str, params: dict):
    command = path.strip("/").replace("/", " ")
    parts = [f"/{command}"]
    for key, value in (params or {}).items():
        if value is None or value == "":
            continue
        text_value = str(value)
        if any(char.isspace() for char in text_value):
            text_value = '"' + text_value.replace('"', '\\"') + '"'
        parts.append(f"{key}={text_value}")
    return " ".join(parts)


def routeros_remove_preview(print_path: str, query_field: str, query_value: str):
    base = print_path[:-6] if print_path.endswith("/print") else print_path
    command = base.strip("/").replace("/", " ")
    text_value = str(query_value)
    if any(char.isspace() for char in text_value):
        text_value = '"' + text_value.replace('"', '\\"') + '"'
    return f"/{command} remove [find {query_field}={text_value}]"


def routeros_safe_identifier(value: Optional[str], fallback: str = "3jcentralpisowifi") -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", (value or fallback).strip().lower()).strip("-")
    return text or fallback


def mikrotik_hotspot_managed_names(display_name: Optional[str]) -> dict:
    identifier = routeros_safe_identifier(display_name)
    base = identifier if identifier.endswith("-hotspot") else f"{identifier}-hotspot"
    return {
        "identifier": identifier,
        "hotspot_base": base,
        "vlan": f"{base}-vlan",
        "profile": f"{base}-profile",
        "server": base,
        "pool": f"{base}-pool",
        "dhcp": f"{base}-dhcp",
    }


def routeros_command_words(path: str, params: dict):
    return [path] + [f"={key}={value}" for key, value in (params or {}).items() if value is not None and value != ""]


def routeros_print_path_for_add(path: str):
    if path.endswith("/add"):
        return f"{path[:-4]}/print"
    return None


def routeros_remove_path_for_print(print_path: str):
    if print_path.endswith("/print"):
        return f"{print_path[:-6]}/remove"
    return None


def routeros_truthy(value) -> bool:
    return str(value or "").strip().lower() in {"true", "yes", "1"}


def routeros_execute_commands(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, commands: list, timeout: float = 8.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        results = []
        for command in commands:
            path = command.get("path")
            params = command.get("params") or {}
            label = command.get("label") or path
            verify = command.get("verify")
            if verify and verify.get("words"):
                existing = routeros_read_result_after_send(sock, verify["words"])
                if routeros_verify_matches(existing, verify):
                    results.append({
                        "label": label,
                        "status": "SKIPPED",
                        "message": routeros_verify_message(verify),
                        "existing_count": len(existing),
                    })
                    continue
            if command.get("set_existing_query"):
                query = command["set_existing_query"]
                print_path = query.get("print_path")
                query_fields = query.get("query") or {}
                set_path = query.get("set_path") or path
                existing = routeros_read_result_after_send(
                    sock,
                    [print_path] + [f"?{key}={value}" for key, value in query_fields.items() if value not in (None, "")],
                )
                if not existing:
                    query_label = ", ".join(f"{key}={value}" for key, value in query_fields.items())
                    raise RuntimeError(f"{label}: existing RouterOS item was not found for {query_label}.")
                item_id = existing[0].get(".id")
                if not item_id:
                    raise RuntimeError(f"{label}: existing RouterOS item has no ID.")
                replies = routeros_read_result_after_send(sock, routeros_command_words(set_path, {".id": item_id, **params}))
                results.append({"label": label, "status": "SUCCESS", "message": "Existing RouterOS item was updated.", "reply_count": len(replies)})
                continue
            if command.get("place_before_query"):
                place_query = command["place_before_query"]
                place_print_path = place_query.get("print_path")
                place_fields = place_query.get("query") or {}
                if place_print_path and place_fields:
                    place_rows = routeros_read_result_after_send(
                        sock,
                        [place_print_path] + [f"?{key}={value}" for key, value in place_fields.items() if value not in (None, "")],
                    )
                    if place_rows and place_rows[0].get(".id"):
                        params = {**params, "place-before": place_rows[0][".id"]}
            if command.get("merge_bridge_vlan_tagged"):
                print_path = routeros_print_path_for_add(path)
                bridge = params.get("bridge")
                vlan_ids = params.get("vlan-ids")
                desired_tagged = params.get("tagged")
                if print_path and bridge and vlan_ids and desired_tagged:
                    existing = routeros_read_result_after_send(sock, [print_path, f"?bridge={bridge}", f"?vlan-ids={vlan_ids}"])
                    if existing:
                        editable_existing = [item for item in existing if not routeros_truthy(item.get("dynamic"))]
                        if not editable_existing:
                            words = routeros_command_words(path, params)
                            replies = routeros_read_result_after_send(sock, words)
                            results.append({
                                "label": label,
                                "status": "SUCCESS",
                                "message": "Created a static bridge VLAN row. Existing dynamic RouterOS VLAN rows are read-only and were left unchanged.",
                                "reply_count": len(replies),
                                "dynamic_existing_count": len(existing),
                            })
                            continue
                        existing_item = editable_existing[0]
                        existing_tagged = existing_item.get("tagged") or ""
                        merged_tagged = station_dedupe_csv(existing_tagged, desired_tagged)
                        existing_set = {item.strip() for item in existing_tagged.split(",") if item.strip()}
                        merged_set = {item.strip() for item in merged_tagged.split(",") if item.strip()}
                        if merged_set == existing_set:
                            results.append({"label": label, "status": "SKIPPED", "message": "Existing static bridge VLAN already has the required tagged members.", "existing_count": len(editable_existing), "dynamic_existing_count": len(existing) - len(editable_existing)})
                            continue
                        item_id = existing_item.get(".id")
                        if not item_id:
                            raise RuntimeError("Existing bridge VLAN item has no RouterOS ID.")
                        routeros_read_result_after_send(sock, ["/interface/bridge/vlan/set", f"=.id={item_id}", f"=tagged={merged_tagged}"])
                        results.append({"label": label, "status": "SUCCESS", "message": f"Updated existing static bridge VLAN tagged members to {merged_tagged}.", "existing_count": len(editable_existing), "dynamic_existing_count": len(existing) - len(editable_existing)})
                        continue
            unique_query = None
            if command.get("existing_query"):
                unique_query = command.get("existing_query")
            elif command.get("unique_comment"):
                unique_query = ("comment", command.get("unique_comment"))
            elif command.get("unique_field") and command.get("unique_value"):
                unique_query = (command.get("unique_field"), command.get("unique_value"))
            if unique_query:
                print_path = routeros_print_path_for_add(path)
                if print_path:
                    if isinstance(unique_query, dict):
                        query_words = [print_path] + [f"?{key}={value}" for key, value in unique_query.items() if value not in (None, "")]
                    else:
                        query_words = [print_path, f"?{unique_query[0]}={unique_query[1]}"]
                    existing = routeros_read_result_after_send(sock, query_words)
                    if existing:
                        if isinstance(unique_query, dict):
                            query_label = ", ".join(f"{key}={value}" for key, value in unique_query.items())
                        else:
                            query_label = f"{unique_query[0]}={unique_query[1]}"
                        results.append({"label": label, "status": "SKIPPED", "message": f"Existing MikroTik item was found for {query_label}.", "existing_count": len(existing)})
                        continue
            words = routeros_command_words(path, params)
            replies = routeros_read_result_after_send(sock, words)
            results.append({"label": label, "status": "SUCCESS", "message": "Command accepted by RouterOS.", "reply_count": len(replies)})
        return {"status": "SUCCESS", "message": "RouterOS commands completed.", "results": results}
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_duration_to_seconds(value: Optional[str]) -> int:
    text = str(value or "").strip().lower()
    if not text:
        return 0
    if ":" in text and re.fullmatch(r"\d+:\d{1,2}:\d{1,2}", text):
        hours, minutes, seconds = [int(part) for part in text.split(":")]
        return hours * 3600 + minutes * 60 + seconds
    total = 0
    for amount, unit in re.findall(r"(\d+)([wdhms])", text):
        number = int(amount)
        if unit == "w":
            total += number * 7 * 24 * 3600
        elif unit == "d":
            total += number * 24 * 3600
        elif unit == "h":
            total += number * 3600
        elif unit == "m":
            total += number * 60
        elif unit == "s":
            total += number
    if total:
        return total
    try:
        return int(float(text))
    except ValueError:
        return 0


def routeros_authorize_hotspot_client(
    host: str,
    port: int,
    username: Optional[str],
    password: Optional[str],
    use_tls: bool,
    hotspot_username: str,
    hotspot_password: str,
    duration_seconds: int,
    comment: str,
    login_ip: str,
    client_mac: Optional[str],
    timeout: float = 8.0,
):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        requested_seconds = max(int(duration_seconds or 0), 60)
        existing_users = routeros_read_result_after_send(
            sock,
            [
                "/ip/hotspot/user/print",
                f"?name={hotspot_username}",
                "=.proplist=.id,name,uptime,limit-uptime,disabled,comment",
            ],
        )
        results = []
        if existing_users:
            existing = existing_users[0]
            existing_id = existing.get(".id")
            if not existing_id:
                raise RuntimeError("Existing HotSpot user has no RouterOS ID.")
            used_seconds = routeros_duration_to_seconds(existing.get("uptime"))
            new_limit_seconds = max(used_seconds + requested_seconds, requested_seconds)
            routeros_read_result_after_send(
                sock,
                [
                    "/ip/hotspot/user/set",
                    f"=.id={existing_id}",
                    f"=password={hotspot_password}",
                    f"=limit-uptime={new_limit_seconds}s",
                    f"=comment={comment}",
                    "=disabled=no",
                ],
            )
            results.append({
                "label": "Extend existing portal HotSpot user",
                "status": "SUCCESS",
                "message": f"Existing HotSpot user limit updated to preserve {requested_seconds}s of new voucher time.",
                "previous_uptime": existing.get("uptime"),
                "new_limit_uptime": f"{new_limit_seconds}s",
            })
        else:
            routeros_read_result_after_send(
                sock,
                [
                    "/ip/hotspot/user/add",
                    f"=name={hotspot_username}",
                    f"=password={hotspot_password}",
                    f"=limit-uptime={requested_seconds}s",
                    f"=comment={comment}",
                ],
            )
            results.append({
                "label": "Create portal HotSpot user",
                "status": "SUCCESS",
                "message": "HotSpot user created for this portal account.",
                "limit_uptime": f"{requested_seconds}s",
            })
        login_words = [
            "/ip/hotspot/active/login",
            f"=user={hotspot_username}",
            f"=password={hotspot_password}",
            f"=ip={login_ip}",
        ]
        if client_mac:
            login_words.append(f"=mac-address={client_mac}")
        replies = routeros_read_result_after_send(sock, login_words)
        results.append({
            "label": "Authorize active MikroTik HotSpot client",
            "status": "SUCCESS",
            "message": "Command accepted by RouterOS.",
            "reply_count": len(replies),
        })
        return {"status": "SUCCESS", "message": "RouterOS HotSpot authorization completed.", "results": results}
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_remove_hotspot_client_state(
    host: str,
    port: int,
    username: Optional[str],
    password: Optional[str],
    use_tls: bool,
    client_mac: Optional[str] = None,
    timeout: float = 8.0,
) -> dict:
    if not client_mac:
        return {"status": "SKIPPED", "message": "No client MAC was available for HotSpot state cleanup.", "removed": []}
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    removed = []
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        for print_path, remove_path in [
            ("/ip/hotspot/active/print", "/ip/hotspot/active/remove"),
            ("/ip/hotspot/host/print", "/ip/hotspot/host/remove"),
        ]:
            rows = routeros_read_result_after_send(
                sock,
                [print_path, f"?mac-address={client_mac}", "=.proplist=.id,address,to-address,mac-address,user,server,authorized"],
            )
            for row in rows:
                item_id = row.get(".id")
                if not item_id:
                    continue
                routeros_read_result_after_send(sock, [remove_path, f"=.id={item_id}"])
                removed.append({"path": remove_path, "id": item_id, "address": row.get("address"), "to_address": row.get("to-address")})
        return {"status": "SUCCESS", "message": "HotSpot active/host state removed for this client.", "removed": removed}
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_execute_remove_commands(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, commands: list, timeout: float = 8.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        results = []
        for command in commands:
            label = command.get("label") or command.get("print_path") or "Remove managed item"
            print_path = command.get("print_path")
            remove_path = command.get("remove_path") or routeros_remove_path_for_print(print_path or "")
            query_field = command.get("query_field")
            query_value = command.get("query_value")
            if not print_path or not remove_path or not query_field or query_value in (None, ""):
                results.append({"label": label, "status": "SKIPPED", "message": "Removal command is incomplete."})
                continue
            existing = routeros_read_result_after_send(sock, [print_path, f"?{query_field}={query_value}"])
            if not existing:
                results.append({"label": label, "status": "SKIPPED", "message": "No matching 3JCentralPisowifi-managed item found."})
                continue
            removed_ids = []
            for item in existing:
                item_id = item.get(".id")
                if not item_id:
                    continue
                routeros_read_result_after_send(sock, [remove_path, f"=.id={item_id}"])
                removed_ids.append(item_id)
            results.append({"label": label, "status": "SUCCESS", "message": f"Removed {len(removed_ids)} managed item(s).", "removed_count": len(removed_ids)})
        return {"status": "SUCCESS", "message": "Managed MikroTik configuration removed.", "results": results}
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_detect_remove_targets(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, commands: list, timeout: float = 8.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        items = []
        found_count = 0
        for command in commands:
            label = command.get("label") or command.get("print_path") or "Managed item"
            print_path = command.get("print_path")
            query_field = command.get("query_field")
            query_value = command.get("query_value")
            if not print_path or not query_field or query_value in (None, ""):
                items.append({"label": label, "status": "SKIPPED", "found_count": 0, "message": "Detection command is incomplete."})
                continue
            existing = routeros_read_result_after_send(sock, [print_path, f"?{query_field}={query_value}"])
            count = len(existing)
            found_count += count
            items.append({
                "label": label,
                "status": "FOUND" if count else "NOT_FOUND",
                "found_count": count,
                "query_field": query_field,
                "query_value": query_value,
            })
        return {
            "status": "SUCCESS",
            "message": f"Found {found_count} 3JCentralPisowifi-managed MikroTik object(s).",
            "has_managed_config": found_count > 0,
            "found_count": found_count,
            "items": items,
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_detect_station_apply_targets(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, commands: list, timeout: float = 8.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        items = []
        found_count = 0
        for index, command in enumerate(commands):
            label = command.get("label") or command.get("path") or f"Command {index + 1}"
            path = command.get("path")
            params = command.get("params") or {}
            print_path = routeros_print_path_for_add(path or "")
            query_words = None
            query_label = ""
            verify = command.get("verify")
            if verify and verify.get("words"):
                existing = routeros_read_result_after_send(sock, verify["words"])
                matched = routeros_verify_matches(existing, verify)
                found_count += 1 if matched else 0
                items.append({
                    "label": label,
                    "command_index": index,
                    "status": "FOUND" if matched else "NOT_FOUND",
                    "found_count": 1 if matched else 0,
                    "query_label": verify.get("label") or ", ".join(verify.get("words") or []),
                    "existing_count": len(existing),
                    "message": routeros_verify_message(verify) if matched else verify.get("not_found_message") or "Required RouterOS state was not detected.",
                })
                continue
            if command.get("set_existing_query"):
                query = command["set_existing_query"]
                print_path = query.get("print_path")
                query_fields = query.get("query") or {}
                existing = routeros_read_result_after_send(
                    sock,
                    [print_path] + [f"?{key}={value}" for key, value in query_fields.items() if value not in (None, "")],
                )
                items.append({
                    "label": label,
                    "command_index": index,
                    "status": "UNKNOWN",
                    "found_count": 0,
                    "query_label": ", ".join(f"{key}={value}" for key, value in query_fields.items()),
                    "existing_count": len(existing),
                    "message": "This step updates an existing RouterOS item. Detection requires a verification rule.",
                })
                continue
            if command.get("merge_bridge_vlan_tagged") and print_path:
                bridge = params.get("bridge")
                vlan_ids = params.get("vlan-ids")
                tagged = {item.strip() for item in str(params.get("tagged") or "").split(",") if item.strip()}
                if bridge and vlan_ids:
                    query_words = [print_path, f"?bridge={bridge}", f"?vlan-ids={vlan_ids}"]
                    query_label = f"bridge={bridge}, vlan-ids={vlan_ids}"
                    existing = routeros_read_result_after_send(sock, query_words)
                    static_rows = [row for row in existing if not routeros_truthy(row.get("dynamic"))]
                    matched = any(tagged.issubset({item.strip() for item in str(row.get("tagged") or "").split(",") if item.strip()}) for row in static_rows)
                    found_count += 1 if matched else 0
                    items.append({
                        "label": label,
                        "command_index": index,
                        "status": "FOUND" if matched else "NOT_FOUND",
                        "found_count": 1 if matched else 0,
                        "query_label": query_label,
                        "dynamic_existing_count": len(existing) - len(static_rows),
                        "message": "Static bridge VLAN row has the required tagged members." if matched else "No static bridge VLAN row has all required tagged members yet.",
                    })
                    continue
            if command.get("existing_query") and print_path:
                unique_query = command.get("existing_query")
                if isinstance(unique_query, dict):
                    query_words = [print_path] + [f"?{key}={value}" for key, value in unique_query.items() if value not in (None, "")]
                    query_label = ", ".join(f"{key}={value}" for key, value in unique_query.items())
            elif command.get("unique_comment") and print_path:
                query_words = [print_path, f"?comment={command.get('unique_comment')}"]
                query_label = f"comment={command.get('unique_comment')}"
            elif command.get("unique_field") and command.get("unique_value") and print_path:
                query_words = [print_path, f"?{command.get('unique_field')}={command.get('unique_value')}"]
                query_label = f"{command.get('unique_field')}={command.get('unique_value')}"
            if not query_words:
                items.append({"label": label, "command_index": index, "status": "UNKNOWN", "found_count": 0, "message": "No safe detection query is available for this command."})
                continue
            existing = routeros_read_result_after_send(sock, query_words)
            count = len(existing)
            found_count += 1 if count else 0
            items.append({
                "label": label,
                "command_index": index,
                "status": "FOUND" if count else "NOT_FOUND",
                "found_count": 1 if count else 0,
                "query_label": query_label,
                "existing_count": count,
            })
        return {
            "status": "SUCCESS",
            "message": f"Found {found_count} pushed station step(s).",
            "has_managed_config": found_count > 0,
            "found_count": found_count,
            "items": items,
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_readonly_query(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, words: list, timeout: float = 8.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        return routeros_read_result_after_send(sock, words)
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_file_words(file_path: str) -> list[str]:
    return [
        "/file/print",
        f"?name={file_path}",
        "=.proplist=.id,name,type,size,contents,creation-time,modified-time",
    ]


def routeros_file_query(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, file_path: str, timeout: float = 8.0):
    return routeros_readonly_query(host, port, username, password, use_tls, routeros_file_words(file_path), timeout=timeout)


def routeros_write_text_file(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, file_path: str, content: str, timeout: float = 10.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        existing = routeros_read_result_after_send(sock, routeros_file_words(file_path))
        action = "add"
        if existing:
            item_id = existing[0].get(".id")
            if not item_id:
                raise RuntimeError("Existing RouterOS file has no ID and cannot be updated safely.")
            try:
                routeros_read_result_after_send(sock, ["/file/set", f"=.id={item_id}", f"=contents={content}"])
                action = "set"
            except Exception:
                routeros_read_result_after_send(sock, ["/file/remove", f"=.id={item_id}"])
                routeros_read_result_after_send(sock, ["/file/add", f"=name={file_path}", f"=contents={content}"])
                action = "replace"
        else:
            routeros_read_result_after_send(sock, ["/file/add", f"=name={file_path}", f"=contents={content}"])
        verified = routeros_read_result_after_send(sock, routeros_file_words(file_path))
        if not verified:
            raise RuntimeError("RouterOS accepted the file operation but the file was not detected after upload.")
        returned_content = verified[0].get("contents")
        expected_hash = sha256(content.encode()).hexdigest()
        try:
            remote_size = int(verified[0].get("size") or 0)
        except (TypeError, ValueError):
            remote_size = 0
        returned_truncated = bool(returned_content and ("[TRUNCATED]" in returned_content or (remote_size and len(returned_content) < remote_size)))
        returned_hash = sha256(returned_content.encode()).hexdigest() if returned_content is not None and not returned_truncated else None
        return {
            "status": "SUCCESS",
            "message": f"Uploaded managed HotSpot login.html using RouterOS /file {action}.",
            "file_path": file_path,
            "action": action,
            "content_hash": expected_hash,
            "returned_content_hash": returned_hash,
            "content_verified": returned_hash == expected_hash if returned_hash else None,
            "content_readback_truncated": returned_truncated,
            "file": sanitize_summary(verified[0]),
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def routeros_hotspot_file_candidates(file_path: str) -> list[str]:
    normalized = re.sub(r"/+", "/", str(file_path or "").strip().replace("\\", "/")).strip("/")
    if not normalized:
        normalized = "hotspot/login.html"
    candidates = [normalized]
    if not normalized.startswith("flash/"):
        candidates.append(f"flash/{normalized}")
    if normalized.startswith("flash/"):
        candidates.append(normalized.removeprefix("flash/"))
    deduped = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


def routeros_write_text_file_via_ftp(host: str, username: Optional[str], password: Optional[str], file_path: str, content: str, timeout: float = 12.0):
    last_error = None
    content_bytes = content.encode()
    for candidate in routeros_hotspot_file_candidates(file_path):
        directory, _, filename = candidate.rpartition("/")
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, 21, timeout=timeout)
            ftp.login(username or "", password or "")
            if directory:
                ftp.cwd(directory)
            ftp.storbinary(f"STOR {filename or 'login.html'}", io.BytesIO(content_bytes))
            try:
                ftp.quit()
            except Exception:
                pass
            return {
                "status": "SUCCESS",
                "message": f"Uploaded managed HotSpot login.html using RouterOS FTP fallback to {candidate}.",
                "file_path": candidate,
                "action": "ftp_stor",
                "content_hash": sha256(content_bytes).hexdigest(),
                "content_verified": None,
            }
        except Exception as exc:
            last_error = exc
            try:
                ftp.close()
            except Exception:
                pass
    raise RuntimeError(f"RouterOS API file upload failed and FTP fallback could not upload login.html: {last_error}")


def routeros_read_result_after_send(sock, words):
    routeros_send_sentence(sock, words)
    return routeros_read_result(sock)


MIKROTIK_PREFLIGHT_PATHS = [
    {"key": "identity", "path": "/system/identity/print", "category": "IDENTITY"},
    {"key": "resource", "path": "/system/resource/print", "category": "SYSTEM"},
    {"key": "interfaces", "path": "/interface/print", "category": "INTERFACE"},
    {"key": "bridges", "path": "/interface/bridge/print", "category": "BRIDGE"},
    {"key": "bridge_ports", "path": "/interface/bridge/port/print", "category": "BRIDGE"},
    {"key": "bridge_vlans", "path": "/interface/bridge/vlan/print", "category": "VLAN"},
    {"key": "interface_vlans", "path": "/interface/vlan/print", "category": "VLAN"},
    {"key": "ip_addresses", "path": "/ip/address/print", "category": "SUBNET"},
    {"key": "ip_pools", "path": "/ip/pool/print", "category": "POOL"},
    {"key": "dhcp_servers", "path": "/ip/dhcp-server/print", "category": "DHCP"},
    {"key": "dhcp_networks", "path": "/ip/dhcp-server/network/print", "category": "DHCP"},
    {"key": "hotspots", "path": "/ip/hotspot/print", "category": "HOTSPOT"},
    {"key": "hotspot_profiles", "path": "/ip/hotspot/profile/print", "category": "HOTSPOT"},
    {"key": "firewall_nat", "path": "/ip/firewall/nat/print", "category": "NAT"},
    {"key": "firewall_filter", "path": "/ip/firewall/filter/print", "category": "FIREWALL"},
    {"key": "routes", "path": "/ip/route/print", "category": "ROUTING"},
    {"key": "ospf_interface_templates", "path": "/routing/ospf/interface-template/print", "category": "OSPF"},
    {"key": "ospf_instances", "path": "/routing/ospf/instance/print", "category": "OSPF"},
    {"key": "radius", "path": "/radius/print", "category": "RADIUS"},
    {"key": "wireguard", "path": "/interface/wireguard/print", "category": "WIREGUARD"},
    {"key": "pppoe_servers", "path": "/interface/pppoe-server/server/print", "category": "PPPoE"},
]

MIKROTIK_SECRET_FIELD_RE = re.compile(r"(password|secret|private|passphrase|certificate|token|api[_-]?key|auth|shared)", re.I)
MIKROTIK_PRESCAN_MAX_CONCURRENCY = int(os.getenv("MIKROTIK_PRESCAN_MAX_CONCURRENCY", "3"))
MIKROTIK_DEPLOYMENT_MODES = {
    "HOTSPOT_GATEWAY",
    "VLAN_TRUNK_HELPER",
    "READ_ONLY_CORE",
    "ISP_BACKUP_TRANSPORT",
    "UNKNOWN_NEEDS_REVIEW",
}
MIKROTIK_ROUTER_ROLES = {
    "PPPoE_ACCESS_CONCENTRATOR",
    "HOTSPOT_GATEWAY_CANDIDATE",
    "CORE_ROUTER_READ_ONLY",
    "SWITCH_TRUNK_HELPER",
    "ISP_BACKUP_TRANSPORT",
    "UNKNOWN_NEEDS_REVIEW",
}
MIKROTIK_DEPLOYMENT_MODE_ALIASES = {
    "HotSpot Gateway": "HOTSPOT_GATEWAY",
    "VLAN Trunk Helper": "VLAN_TRUNK_HELPER",
    "Read-only / Core Router": "READ_ONLY_CORE",
    "Read-only/Core": "READ_ONLY_CORE",
    "ISP Backup / Transport Router": "ISP_BACKUP_TRANSPORT",
    "Unknown/Needs Review": "UNKNOWN_NEEDS_REVIEW",
}
MIKROTIK_ROLE_TO_RECOMMENDED_MODE = {
    "HOTSPOT_GATEWAY_CANDIDATE": "HOTSPOT_GATEWAY",
    "SWITCH_TRUNK_HELPER": "VLAN_TRUNK_HELPER",
    "CORE_ROUTER_READ_ONLY": "READ_ONLY_CORE",
    "PPPoE_ACCESS_CONCENTRATOR": "HOTSPOT_GATEWAY",
    "ISP_BACKUP_TRANSPORT": "ISP_BACKUP_TRANSPORT",
    "UNKNOWN_NEEDS_REVIEW": "UNKNOWN_NEEDS_REVIEW",
}


def sanitize_routeros_text(value, max_length: int = 2000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    # PostgreSQL json/jsonb cannot store \u0000. Other control characters make
    # RouterOS diagnostics hard to read, so strip them except normal whitespace.
    safe_chars = []
    for char in text:
        code = ord(char)
        if char in ("\n", "\r", "\t"):
            safe_chars.append(char)
        elif code == 0:
            continue
        elif code < 32 or code == 127:
            continue
        elif 0xD800 <= code <= 0xDFFF:
            safe_chars.append("\uFFFD")
        else:
            safe_chars.append(char)
    clean = "".join(safe_chars)
    clean = clean.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if len(clean) > max_length:
        return clean[:max_length] + "...[TRUNCATED]"
    return clean


def sanitize_routeros_value(value, parent_key: str = ""):
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            key_text = sanitize_routeros_text(key, max_length=200)
            if not key_text:
                key_text = "field"
            if MIKROTIK_SECRET_FIELD_RE.search(key_text):
                clean[key_text] = "[REDACTED]" if item not in (None, "") else item
            else:
                clean[key_text] = sanitize_routeros_value(item, key_text)
        return clean
    if isinstance(value, (list, tuple, set)):
        return [sanitize_routeros_value(item, parent_key) for item in value]
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, str):
        if MIKROTIK_SECRET_FIELD_RE.search(parent_key):
            return "[REDACTED]" if value else value
        return sanitize_routeros_text(value)
    if isinstance(value, bytes):
        return sanitize_routeros_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_routeros_text(value)


def sanitize_routeros_object(value):
    return sanitize_routeros_value(value)


def sanitize_routeros_snapshot(value):
    return sanitize_routeros_value(value)


def sanitize_mikrotik_snapshot(value, parent_key: str = ""):
    return sanitize_routeros_value(value, parent_key)


def sanitize_mikrotik_snapshot_old(value, parent_key: str = ""):
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            key_text = str(key)
            if MIKROTIK_SECRET_FIELD_RE.search(key_text):
                clean[key] = "[REDACTED]" if item not in (None, "") else item
            else:
                clean[key] = sanitize_mikrotik_snapshot(item, key_text)
        return clean
    if isinstance(value, list):
        return [sanitize_mikrotik_snapshot(item, parent_key) for item in value]
    if isinstance(value, str):
        if MIKROTIK_SECRET_FIELD_RE.search(parent_key):
            return "[REDACTED]" if value else value
        return value[:2000] + "...[TRUNCATED]" if len(value) > 2000 else value
    return value


def routeros_readonly_snapshot(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool, timeout: float = 8.0):
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        routeros_login_socket(sock, username, password)
        paths = {}
        unsupported = []
        for item in MIKROTIK_PREFLIGHT_PATHS:
            try:
                rows = routeros_read_result_after_send(sock, [item["path"]])
                clean_rows = sanitize_routeros_snapshot(rows)
                paths[item["key"]] = {
                    "path": item["path"],
                    "category": item["category"],
                    "items": clean_rows,
                    "count": len(rows),
                    "supported": True,
                }
            except Exception as exc:
                message = sanitize_routeros_text(str(exc))
                unsupported.append({"key": item["key"], "path": item["path"], "category": item["category"], "error": message})
                paths[item["key"]] = {
                    "path": item["path"],
                    "category": item["category"],
                    "items": [],
                    "count": 0,
                    "supported": False,
                    "error": message,
                }
        return {"paths": paths, "unsupported_paths": unsupported}
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def mikrotik_snapshot_items(snapshot: dict, key: str) -> list:
    section = ((snapshot or {}).get("paths") or {}).get(key) or {}
    items = section.get("items")
    return items if isinstance(items, list) else []


def parse_routeros_vlan_ids(value) -> set[int]:
    ids = set()
    text = str(value or "").strip()
    if not text:
        return ids
    for part in text.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            try:
                start, end = [int(piece.strip()) for piece in token.split("-", 1)]
                ids.update(range(max(1, start), min(4094, end) + 1))
            except (TypeError, ValueError):
                continue
        else:
            try:
                ids.add(int(token))
            except (TypeError, ValueError):
                continue
    return ids


def parse_routeros_ip_network(value):
    try:
        return ip_interface(str(value)).network
    except Exception:
        return None


def parse_routeros_pool_ranges(value) -> list[tuple[int, int]]:
    ranges = []
    for part in str(value or "").split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
        else:
            start_text = end_text = token
        try:
            start = int(ip_address(start_text.strip()))
            end = int(ip_address(end_text.strip()))
            ranges.append((min(start, end), max(start, end)))
        except Exception:
            continue
    return ranges


def mikrotik_ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] <= right[1] and right[0] <= left[1]


def mikrotik_public_ip_indicators(snapshot: dict) -> list[str]:
    indicators = []
    for item in mikrotik_snapshot_items(snapshot, "ip_addresses"):
        address_text = item.get("address")
        try:
            interface = ip_interface(str(address_text))
        except Exception:
            continue
        ip_value = interface.ip
        if not (ip_value.is_private or ip_value.is_loopback or ip_value.is_link_local or ip_value.is_multicast or ip_value.is_reserved):
            indicators.append(f"{address_text} on {item.get('interface') or 'unknown interface'}")
    return indicators


def mikrotik_default_routes(snapshot: dict) -> list[dict]:
    defaults = []
    for item in mikrotik_snapshot_items(snapshot, "routes"):
        destination = item.get("dst-address") or item.get("dst-addresses") or item.get("dst")
        if destination in ("0.0.0.0/0", "::/0"):
            defaults.append(item)
    return defaults


def mikrotik_finding(category: str, severity: str, title: str, message: str, related_object: Optional[str] = None, recommendation: Optional[str] = None) -> dict:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "message": message,
        "related_object": related_object,
        "recommendation": recommendation,
    }


def analyze_mikrotik_preflight(router: dict, snapshot: dict) -> dict:
    findings = []
    conflicts = []
    recommendations = []
    identity = (mikrotik_snapshot_items(snapshot, "identity") or [{}])[0]
    resource = (mikrotik_snapshot_items(snapshot, "resource") or [{}])[0]
    router_identity = identity.get("name") or router.get("router_name")
    router_model = resource.get("board-name") or resource.get("platform") or resource.get("architecture-name")
    router_version = resource.get("version")
    existing_vlan_ids = set()
    for item in mikrotik_snapshot_items(snapshot, "interface_vlans"):
        existing_vlan_ids.update(parse_routeros_vlan_ids(item.get("vlan-id")))
    for item in mikrotik_snapshot_items(snapshot, "bridge_vlans"):
        existing_vlan_ids.update(parse_routeros_vlan_ids(item.get("vlan-ids")))

    proposed_vlan_id = router.get("hotspot_vlan_id")
    try:
        proposed_vlan_id = int(proposed_vlan_id) if proposed_vlan_id not in (None, "") else None
    except (TypeError, ValueError):
        proposed_vlan_id = None
    if proposed_vlan_id:
        if proposed_vlan_id in existing_vlan_ids:
            finding = mikrotik_finding(
                "VLAN",
                "BLOCKER",
                f"VLAN {proposed_vlan_id} already exists",
                "The customer VLAN entered for captive portal setup already exists on this MikroTik.",
                f"VLAN {proposed_vlan_id}",
                "Choose a different unused VLAN ID or confirm the existing VLAN is intended for captive portal clients before any future apply step.",
            )
            conflicts.append(finding)
            findings.append(finding)
        else:
            findings.append(mikrotik_finding("VLAN", "INFO", f"VLAN {proposed_vlan_id} appears unused", "The proposed customer VLAN was not found in the scanned RouterOS VLAN lists.", f"VLAN {proposed_vlan_id}", "Confirm this VLAN is also configured on the AP SSID before deployment."))
    else:
        findings.append(mikrotik_finding("VLAN", "WARNING", "No proposed customer VLAN configured", "The router record does not yet have a customer VLAN ID.", None, "Add the VLAN ID in Add Router before preparing HotSpot setup."))

    existing_networks = []
    for item in mikrotik_snapshot_items(snapshot, "ip_addresses"):
        network = parse_routeros_ip_network(item.get("address"))
        if network:
            existing_networks.append({"network": network, "interface": item.get("interface"), "address": item.get("address")})
    proposed_cidr = (router.get("hotspot_client_network_cidr") or "").strip()
    proposed_network = None
    if proposed_cidr:
        try:
            proposed_network = ip_network(proposed_cidr, strict=False)
        except Exception:
            finding = mikrotik_finding("SUBNET", "BLOCKER", "Proposed client subnet is invalid", f"{proposed_cidr} is not a valid CIDR network.", proposed_cidr, "Correct the client network CIDR before continuing.")
            conflicts.append(finding)
            findings.append(finding)
    if proposed_network:
        for existing in existing_networks:
            if proposed_network.overlaps(existing["network"]):
                finding = mikrotik_finding(
                    "SUBNET",
                    "BLOCKER",
                    "Client subnet overlaps existing router subnet",
                    f"Proposed {proposed_network} overlaps {existing['network']} on {existing.get('interface') or 'unknown interface'}.",
                    str(existing["network"]),
                    "Use a unique client subnet that is not already configured on this router.",
                )
                conflicts.append(finding)
                findings.append(finding)
    elif not proposed_cidr:
        findings.append(mikrotik_finding("SUBNET", "WARNING", "No proposed client subnet configured", "Client Network CIDR is empty in this router record.", None, "Enter a dedicated captive portal client subnet before future apply steps."))

    existing_pool_ranges = []
    for item in mikrotik_snapshot_items(snapshot, "ip_pools"):
        for pool_range in parse_routeros_pool_ranges(item.get("ranges")):
            existing_pool_ranges.append({"range": pool_range, "name": item.get("name"), "ranges": item.get("ranges")})
    proposed_pool = None
    start_ip = (router.get("hotspot_pool_start_ip") or "").strip()
    end_ip = (router.get("hotspot_pool_end_ip") or "").strip()
    if start_ip and end_ip:
        try:
            start_value = int(ip_address(start_ip))
            end_value = int(ip_address(end_ip))
            proposed_pool = (min(start_value, end_value), max(start_value, end_value))
            for existing in existing_pool_ranges:
                if mikrotik_ranges_overlap(proposed_pool, existing["range"]):
                    finding = mikrotik_finding(
                        "POOL",
                        "BLOCKER",
                        "Proposed DHCP pool overlaps existing pool",
                        f"Proposed pool {start_ip}-{end_ip} overlaps existing pool {existing.get('name')}: {existing.get('ranges')}.",
                        existing.get("name"),
                        "Choose a non-overlapping pool range for captive portal clients.",
                    )
                    conflicts.append(finding)
                    findings.append(finding)
        except Exception:
            finding = mikrotik_finding("POOL", "BLOCKER", "Proposed pool range is invalid", f"Pool start/end values are invalid: {start_ip} - {end_ip}.", None, "Correct the DHCP pool start and end IP addresses.")
            conflicts.append(finding)
            findings.append(finding)
    elif start_ip or end_ip:
        findings.append(mikrotik_finding("POOL", "WARNING", "Incomplete proposed DHCP pool", "Only one pool boundary was provided.", None, "Enter both Pool Start IP and Pool End IP."))

    target_interface = (router.get("hotspot_vlan_interface_name") or router.get("hotspot_interface") or "").strip()
    for item in mikrotik_snapshot_items(snapshot, "dhcp_servers"):
        if target_interface and item.get("interface") == target_interface:
            finding = mikrotik_finding("DHCP", "BLOCKER", "DHCP server already exists on target interface", f"DHCP server {item.get('name')} already uses {target_interface}.", item.get("name"), "Confirm whether this DHCP server should be reused manually or choose another interface/network.")
            conflicts.append(finding)
            findings.append(finding)
    if mikrotik_snapshot_items(snapshot, "hotspots"):
        findings.append(mikrotik_finding("HOTSPOT", "WARNING", "Existing HotSpot server found", "This MikroTik already has at least one HotSpot server.", None, "Do not overwrite existing HotSpot setup. Use a dedicated system-owned HotSpot only after review."))
    if mikrotik_snapshot_items(snapshot, "hotspot_profiles"):
        findings.append(mikrotik_finding("HOTSPOT", "INFO", "Existing HotSpot profiles found", "HotSpot profiles are present and may belong to another service.", None, "Keep profiles unchanged unless the future command preview explicitly targets 3JCentralPisowifi-managed objects."))

    pppoe_servers = mikrotik_snapshot_items(snapshot, "pppoe_servers")
    if pppoe_servers:
        findings.append(mikrotik_finding("PPPoE", "DANGER", "PPPoE server detected", "This router appears to serve PPPoE users.", None, "Avoid automatic changes to PPPoE bridges, pools, profiles, or access networks."))
    ospf_entries = mikrotik_snapshot_items(snapshot, "ospf_interface_templates") + mikrotik_snapshot_items(snapshot, "ospf_instances")
    if ospf_entries:
        findings.append(mikrotik_finding("OSPF", "DANGER", "OSPF routing detected", "Dynamic routing is present on this router.", None, "Treat this as routing-sensitive. Do not change routing or bridge behavior without expert review."))
    wireguard_entries = mikrotik_snapshot_items(snapshot, "wireguard")
    if wireguard_entries:
        findings.append(mikrotik_finding("WIREGUARD", "WARNING", "WireGuard interface detected", "WireGuard is present on this router.", None, "Do not modify tunnel interfaces or peer routing in this phase."))
    public_ips = mikrotik_public_ip_indicators(snapshot)
    if public_ips:
        findings.append(mikrotik_finding("ROUTING", "DANGER", "Public IP address detected", "This router has public IP addressing and may be an edge/core router.", ", ".join(public_ips[:3]), "Use read-only/core mode unless the operator confirms this is the intended gateway for captive portal clients."))
    default_routes = mikrotik_default_routes(snapshot)
    if default_routes:
        findings.append(mikrotik_finding("ROUTING", "INFO", "Default route present", "The router has at least one default route.", None, "Confirm WAN/Internet interface before any future NAT or HotSpot gateway setup."))

    bridge_vlan_count = len(mikrotik_snapshot_items(snapshot, "bridge_vlans"))
    firewall_filter_count = len(mikrotik_snapshot_items(snapshot, "firewall_filter"))
    nat_count = len(mikrotik_snapshot_items(snapshot, "firewall_nat"))
    route_count = len(mikrotik_snapshot_items(snapshot, "routes"))
    unsupported_paths = (snapshot or {}).get("unsupported_paths") or []
    if unsupported_paths:
        findings.append(mikrotik_finding("SYSTEM", "WARNING", "Some RouterOS paths are unsupported", f"{len(unsupported_paths)} read-only scan path(s) were not available on this RouterOS version.", None, "Unsupported paths are expected across RouterOS versions; review the listed warnings."))
    findings.append(mikrotik_finding("FIREWALL", "INFO", "Firewall/NAT scanned", f"Detected {firewall_filter_count} filter rule(s), {nat_count} NAT rule(s), and {route_count} route(s).", None, "Detailed firewall changes are not part of MT-1."))

    model_text = str(router_model or "").lower()
    identity_text = f"{router_identity or ''} {router.get('router_name') or ''}".lower()
    has_crs = "crs" in model_text
    core_name = any(token in identity_text for token in ["core", "border", "backbone", "upstream", "edge-core", "main-core"])
    strong_core_indicators = [
        bool(public_ips),
        len(default_routes) > 1,
        bool(core_name),
        route_count > 80,
        bool(ospf_entries and route_count > 30),
    ]
    strong_core_score = sum(1 for item in strong_core_indicators if item)
    has_vlan_switching = bridge_vlan_count >= 2 or has_crs
    role_reasoning = []
    deployment_reasoning = []
    if pppoe_servers:
        role_guess = "PPPoE_ACCESS_CONCENTRATOR"
        recommended_mode = "HOTSPOT_GATEWAY"
        role_reasoning.append(f"Detected {len(pppoe_servers)} PPPoE server entry/entries, so this looks like an access concentrator.")
        deployment_reasoning.append("HotSpot Gateway is possible with caution only on a new dedicated VLAN/subnet after confirmation. PPPoE bridges, pools, profiles, OSPF, WireGuard, and access networks must remain untouched.")
    elif has_vlan_switching and not mikrotik_snapshot_items(snapshot, "hotspots"):
        role_guess = "SWITCH_TRUNK_HELPER"
        recommended_mode = "VLAN_TRUNK_HELPER"
        role_reasoning.append("Bridge VLAN or CRS/switch indicators are present without a HotSpot/PPPoE gateway role.")
        deployment_reasoning.append("This device should carry VLANs only; it should not host HotSpot/DHCP/NAT.")
    elif strong_core_score >= 2:
        role_guess = "CORE_ROUTER_READ_ONLY"
        recommended_mode = "READ_ONLY_CORE"
        role_reasoning.append("Multiple core/routing indicators were detected, such as public IPs, OSPF, many routes, core naming, or multiple default routes.")
        deployment_reasoning.append("HotSpot setup is blocked by default on core/routing infrastructure.")
    elif proposed_vlan_id and proposed_network:
        role_guess = "HOTSPOT_GATEWAY_CANDIDATE"
        recommended_mode = "HOTSPOT_GATEWAY"
        role_reasoning.append("A proposed dedicated VLAN and client subnet are present and no stronger core/switch role was detected.")
        deployment_reasoning.append("This router may be a pilot candidate if conflicts are resolved and deployment mode is confirmed.")
    else:
        role_guess = "UNKNOWN_NEEDS_REVIEW"
        recommended_mode = "UNKNOWN_NEEDS_REVIEW"
        role_reasoning.append("The scan does not provide enough evidence to safely classify this router.")
        deployment_reasoning.append("Confirm whether this is a gateway, trunk helper, core router, or transport router before setup.")

    blocker_count = sum(1 for item in findings if item["severity"] == "BLOCKER")
    danger_count = sum(1 for item in findings if item["severity"] == "DANGER")
    warning_count = sum(1 for item in findings if item["severity"] == "WARNING")
    if blocker_count:
        risk_level = "BLOCKED"
    elif danger_count:
        risk_level = "HIGH"
    elif warning_count:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    pilot_suitability = "UNKNOWN"
    pilot_reason = "Insufficient data. Run a successful scan and confirm deployment mode."
    if role_guess == "CORE_ROUTER_READ_ONLY":
        pilot_suitability = "NOT_RECOMMENDED"
        pilot_reason = "Core/routing infrastructure should stay read-only for captive portal setup."
    elif role_guess == "SWITCH_TRUNK_HELPER":
        pilot_suitability = "NOT_RECOMMENDED"
        pilot_reason = "This device may carry VLANs but should not host the HotSpot gateway."
    elif risk_level == "BLOCKED":
        pilot_suitability = "NOT_RECOMMENDED"
        pilot_reason = "Hard conflicts must be resolved before this router can be considered."
    elif role_guess == "PPPoE_ACCESS_CONCENTRATOR":
        pilot_suitability = "POSSIBLE_WITH_CAUTION"
        pilot_reason = "PPPoE AC routers are high risk, but a separate captive portal VLAN/subnet can be evaluated after confirmation."
    elif role_guess == "HOTSPOT_GATEWAY_CANDIDATE" and risk_level in ("LOW", "MEDIUM"):
        pilot_suitability = "GOOD_PILOT"
        pilot_reason = "The router has a dedicated VLAN/subnet plan and no hard blocker in the scan."
    elif risk_level == "HIGH":
        pilot_suitability = "POSSIBLE_WITH_CAUTION"
        pilot_reason = "High-risk indicators require expert confirmation and dedicated isolation."
    recommendations.extend(
        [
            {"title": "Confirm router role", "message": "Role guess is advisory. The operator must confirm deployment mode before any future apply step."},
            {"title": "Confirm AP/customer VLAN", "message": "Identify the VLAN that will carry open SSID captive portal clients from Omada APs to this MikroTik."},
            {"title": "Confirm client IP range", "message": "Use a dedicated client subnet and pool that do not overlap existing router networks."},
            {"title": "Scan before setup", "message": "Run this preflight scan again after editing VLAN, subnet, or pool fields."},
        ]
    )
    if pppoe_servers:
        recommendations.append({"title": "Protect PPPoE services", "message": "Do not change PPPoE bridges, profiles, or pools during captive portal setup."})
    if ospf_entries:
        recommendations.append({"title": "Protect routing", "message": "Do not modify OSPF or core routing in captive portal setup."})

    return {
        "router_identity": router_identity,
        "router_model": router_model,
        "router_version": router_version,
        "router_role_guess": role_guess,
        "recommended_deployment_mode": recommended_mode,
        "risk_level": risk_level,
        "role_reasoning": role_reasoning,
        "deployment_reasoning": deployment_reasoning,
        "pilot_suitability": pilot_suitability,
        "pilot_reason": pilot_reason,
        "findings": findings,
        "conflicts": conflicts,
        "recommendations": recommendations,
        "summary": {
            "existing_vlan_ids": sorted(existing_vlan_ids),
            "existing_subnets": [
                {"address": item["address"], "network": str(item["network"]), "interface": item.get("interface")}
                for item in existing_networks
            ],
            "existing_pools": [
                {"name": item.get("name"), "ranges": item.get("ranges")}
                for item in existing_pool_ranges
            ],
            "counts": {
                "interfaces": len(mikrotik_snapshot_items(snapshot, "interfaces")),
                "bridges": len(mikrotik_snapshot_items(snapshot, "bridges")),
                "bridge_vlans": bridge_vlan_count,
                "dhcp_servers": len(mikrotik_snapshot_items(snapshot, "dhcp_servers")),
                "hotspots": len(mikrotik_snapshot_items(snapshot, "hotspots")),
                "pppoe_servers": len(pppoe_servers),
                "ospf_entries": len(ospf_entries),
                "wireguard": len(wireguard_entries),
                "firewall_filter": firewall_filter_count,
                "firewall_nat": nat_count,
                "routes": route_count,
                "unsupported_paths": len(unsupported_paths),
            },
        },
    }


def public_mikrotik_preflight_scan(row, include_snapshot: bool = True) -> Optional[dict]:
    if not row:
        return None
    stored_snapshot = row.get("sanitized_snapshot_json") or {}
    stored_analysis = stored_snapshot.get("analysis") if isinstance(stored_snapshot, dict) else {}
    stored_analysis = stored_analysis or {}
    data = {
        "id": row["id"],
        "router_id": row["router_id"],
        "scan_status": row["scan_status"],
        "router_identity": row["router_identity"],
        "router_model": row["router_model"],
        "router_version": row["router_version"],
        "router_role_guess": row["router_role_guess"],
        "recommended_deployment_mode": row["recommended_deployment_mode"],
        "risk_level": row["risk_level"],
        "role_reasoning": stored_analysis.get("role_reasoning") or [],
        "deployment_reasoning": stored_analysis.get("deployment_reasoning") or [],
        "pilot_suitability": stored_analysis.get("pilot_suitability") or "UNKNOWN",
        "pilot_reason": stored_analysis.get("pilot_reason"),
        "findings": row.get("findings_json") or [],
        "conflicts": row.get("conflicts_json") or [],
        "recommendations": row.get("recommendations_json") or [],
        "policy_result": row.get("policy_result_json"),
        "confirmed_router_role": row.get("confirmed_router_role"),
        "confirmed_deployment_mode": row.get("confirmed_deployment_mode"),
        "deployment_mode_confirmed_by_admin_id": row.get("deployment_mode_confirmed_by_admin_id"),
        "deployment_mode_confirmed_at": row.get("deployment_mode_confirmed_at"),
        "setup_blocked": bool(row.get("setup_blocked")),
        "setup_block_reason": row.get("setup_block_reason"),
        "ai_summary": row["ai_summary"],
        "last_error": row["last_error"],
        "scanned_by_admin_id": row["scanned_by_admin_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if include_snapshot:
        data["sanitized_snapshot"] = public_mikrotik_preflight_snapshot(stored_snapshot)
        data["raw_snapshot"] = public_mikrotik_preflight_snapshot(row.get("raw_snapshot_json") or {})
    return data


def mikrotik_preflight_ai_payload(scan: dict) -> dict:
    snapshot = scan.get("sanitized_snapshot") or {}
    analysis = scan.get("sanitized_snapshot", {}).get("analysis") or {}
    return {
        "router_identity": scan.get("router_identity"),
        "router_model": scan.get("router_model"),
        "router_version": scan.get("router_version"),
        "router_role_guess": scan.get("router_role_guess"),
        "recommended_deployment_mode": scan.get("recommended_deployment_mode"),
        "risk_level": scan.get("risk_level"),
        "role_reasoning": scan.get("role_reasoning") or [],
        "deployment_reasoning": scan.get("deployment_reasoning") or [],
        "pilot_suitability": scan.get("pilot_suitability"),
        "pilot_reason": scan.get("pilot_reason"),
        "policy_result": scan.get("policy_result"),
        "findings": scan.get("findings") or [],
        "conflicts": scan.get("conflicts") or [],
        "recommendations": scan.get("recommendations") or [],
        "snapshot_summary": analysis.get("summary") or {},
        "unsupported_paths": (snapshot.get("unsupported_paths") or [])[:12],
    }


def public_mikrotik_preflight_snapshot(snapshot: dict) -> dict:
    clean = sanitize_mikrotik_snapshot(snapshot or {})
    limits = {
        "routes": 25,
        "firewall_filter": 75,
        "firewall_nat": 75,
        "interfaces": 150,
    }
    for key, limit in limits.items():
        section = ((clean.get("paths") or {}).get(key) or {})
        items = section.get("items")
        if isinstance(items, list) and len(items) > limit:
            section["items"] = items[:limit]
            section["truncated"] = True
            section["truncated_count"] = len(items) - limit
    return clean


def normalize_mikrotik_deployment_mode(value: Optional[str]) -> str:
    text = (value or "").strip()
    if not text:
        return "UNKNOWN_NEEDS_REVIEW"
    if text in MIKROTIK_DEPLOYMENT_MODE_ALIASES:
        return MIKROTIK_DEPLOYMENT_MODE_ALIASES[text]
    normalized = re.sub(r"[^A-Z0-9]+", "_", text.upper()).strip("_")
    if "HOTSPOT" in normalized and "GATEWAY" in normalized:
        return "HOTSPOT_GATEWAY"
    if "VLAN" in normalized and "TRUNK" in normalized:
        return "VLAN_TRUNK_HELPER"
    if "READ" in normalized and "CORE" in normalized:
        return "READ_ONLY_CORE"
    if normalized in MIKROTIK_DEPLOYMENT_MODES:
        return normalized
    return "UNKNOWN_NEEDS_REVIEW"


def normalize_mikrotik_router_role(value: Optional[str]) -> str:
    text = (value or "").strip()
    if not text:
        return "UNKNOWN_NEEDS_REVIEW"
    normalized = re.sub(r"[^A-Z0-9]+", "_", text.upper()).strip("_")
    if normalized in MIKROTIK_ROUTER_ROLES:
        return normalized
    if "PPPOE" in normalized or "PPPOE" in normalized.replace("_", ""):
        return "PPPoE_ACCESS_CONCENTRATOR"
    if "HOTSPOT" in normalized and "GATEWAY" in normalized:
        return "HOTSPOT_GATEWAY_CANDIDATE"
    role_aliases = {
        "PPPOE_ACCESS_CONCENTRATOR": "PPPoE_ACCESS_CONCENTRATOR",
        "CORE_ROUTER": "CORE_ROUTER_READ_ONLY",
        "CORE": "CORE_ROUTER_READ_ONLY",
        "SWITCH": "SWITCH_TRUNK_HELPER",
        "CRS": "SWITCH_TRUNK_HELPER",
        "TRUNK": "SWITCH_TRUNK_HELPER",
        "HOTSPOT_GATEWAY": "HOTSPOT_GATEWAY_CANDIDATE",
        "UNKNOWN": "UNKNOWN_NEEDS_REVIEW",
    }
    return role_aliases.get(normalized, "UNKNOWN_NEEDS_REVIEW")


def latest_mikrotik_scan_row(router_id: str):
    return fetch_one(
        """
        SELECT *
        FROM mikrotik_preflight_scans
        WHERE router_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (router_id,),
    )


def latest_mikrotik_policy_row(router_id: str, scan_id: Optional[str] = None):
    if scan_id:
        return fetch_one(
            """
            SELECT *
            FROM mikrotik_deployment_policy_results
            WHERE router_id = %s AND scan_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (router_id, scan_id),
        )
    return fetch_one(
        """
        SELECT *
        FROM mikrotik_deployment_policy_results
        WHERE router_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (router_id,),
    )


def public_mikrotik_policy_result(row) -> Optional[dict]:
    if not row:
        return None
    return {
        "id": row["id"],
        "router_id": row["router_id"],
        "scan_id": row["scan_id"],
        "risk_level": row["risk_level"],
        "role_guess": row["role_guess"],
        "recommended_deployment_mode": row["recommended_deployment_mode"],
        "confirmed_router_role": row.get("confirmed_router_role"),
        "confirmed_deployment_mode": row.get("confirmed_deployment_mode"),
        "setup_allowed": row["setup_allowed"],
        "hotspot_setup_allowed": bool((row.get("confirmed_deployment_mode") == "HOTSPOT_GATEWAY") and row["setup_allowed"]),
        "requires_expert_override": row["requires_expert_override"],
        "expert_override_enabled": row["expert_override_enabled"],
        "expert_override_reason": row.get("expert_override_reason"),
        "expert_override_by_admin_id": row.get("expert_override_by_admin_id"),
        "expert_override_at": row.get("expert_override_at"),
        "blocking_reasons": row.get("blocking_reasons_json") or [],
        "warnings": row.get("warnings_json") or [],
        "next_questions": row.get("next_questions_json") or [],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def evaluate_mikrotik_deployment_policy(router: dict, scan_row=None, existing_policy=None) -> dict:
    scan = public_mikrotik_preflight_scan(scan_row) if scan_row else None
    findings = scan.get("findings") if scan else []
    conflicts = scan.get("conflicts") if scan else []
    snapshot = (scan or {}).get("sanitized_snapshot") or {}
    analysis = snapshot.get("analysis") or {}
    summary = analysis.get("summary") or {}
    counts = summary.get("counts") or {}
    blocking_reasons = []
    warnings = []
    next_questions = [
        "Confirm this router's real role in the network.",
        "Confirm which VLAN carries customer AP traffic.",
        "Confirm the dedicated captive portal client subnet and DHCP pool.",
        "Confirm whether this router should ever host HotSpot or only carry VLANs.",
    ]
    if not scan:
        return {
            "risk_level": "BLOCKED",
            "role_guess": "UNKNOWN_NEEDS_REVIEW",
            "recommended_deployment_mode": "UNKNOWN_NEEDS_REVIEW",
            "role_reasoning": ["No successful preflight scan is available."],
            "deployment_reasoning": ["Run Preflight Scanner before choosing a deployment mode."],
            "pilot_suitability": "UNKNOWN",
            "pilot_reason": "No scan exists.",
            "confirmed_router_role": None,
            "confirmed_deployment_mode": None,
            "setup_allowed": False,
            "requires_expert_override": False,
            "expert_override_enabled": False,
            "blocking_reasons": ["Run a successful read-only preflight scan before MikroTik setup."],
            "warnings": [],
            "next_questions": next_questions,
        }
    if scan.get("scan_status") != "SUCCESS":
        failure_reason = scan.get("last_error") or "Latest preflight scan failed."
        if "unicode" in failure_reason.lower() or "\\u0000" in failure_reason or "null byte" in failure_reason.lower():
            failure_reason = "Failed due to invalid RouterOS text. Try re-scan after sanitizer update."
        return {
            "risk_level": "BLOCKED",
            "role_guess": scan.get("router_role_guess") or "UNKNOWN_NEEDS_REVIEW",
            "recommended_deployment_mode": "UNKNOWN_NEEDS_REVIEW",
            "role_reasoning": scan.get("role_reasoning") or ["Scan failed before role could be safely classified."],
            "deployment_reasoning": scan.get("deployment_reasoning") or ["Fix scan failure and retry."],
            "pilot_suitability": "NOT_RECOMMENDED",
            "pilot_reason": failure_reason,
            "confirmed_router_role": scan.get("confirmed_router_role"),
            "confirmed_deployment_mode": scan.get("confirmed_deployment_mode"),
            "setup_allowed": False,
            "requires_expert_override": False,
            "expert_override_enabled": False,
            "blocking_reasons": [failure_reason],
            "warnings": [],
            "next_questions": next_questions,
        }

    role_guess = normalize_mikrotik_router_role(scan.get("router_role_guess"))
    recommended_mode = normalize_mikrotik_deployment_mode(scan.get("recommended_deployment_mode"))
    if recommended_mode == "UNKNOWN_NEEDS_REVIEW":
        recommended_mode = MIKROTIK_ROLE_TO_RECOMMENDED_MODE.get(role_guess, "UNKNOWN_NEEDS_REVIEW")
    confirmed_role = normalize_mikrotik_router_role(scan.get("confirmed_router_role") or (existing_policy or {}).get("confirmed_router_role"))
    confirmed_mode = normalize_mikrotik_deployment_mode(scan.get("confirmed_deployment_mode") or (existing_policy or {}).get("confirmed_deployment_mode"))
    if not scan.get("confirmed_deployment_mode") and not (existing_policy or {}).get("confirmed_deployment_mode"):
        confirmed_mode = None
    if not scan.get("confirmed_router_role") and not (existing_policy or {}).get("confirmed_router_role"):
        confirmed_role = None
    role_reasoning = scan.get("role_reasoning") or []
    deployment_reasoning = scan.get("deployment_reasoning") or []
    pilot_suitability = scan.get("pilot_suitability") or "UNKNOWN"
    pilot_reason = scan.get("pilot_reason")
    expert_override_enabled = bool((existing_policy or {}).get("expert_override_enabled"))
    risk_level = scan.get("risk_level") or "MEDIUM"

    danger_titles = []
    for finding in findings:
        severity = finding.get("severity")
        title = finding.get("title") or "Finding"
        message = finding.get("message") or title
        category = finding.get("category")
        if severity == "BLOCKER":
            blocking_reasons.append(message)
        elif severity == "DANGER":
            danger_titles.append(title)
            warnings.append(message)
        elif severity == "WARNING":
            warnings.append(message)
        if category == "PPPoE" and severity in ("DANGER", "WARNING"):
            warnings.append("Do not modify PPPoE bridges, pools, profiles, or access networks.")
        if category == "OSPF":
            warnings.append("Do not modify OSPF interfaces/routes in captive portal setup.")
        if category == "WIREGUARD":
            warnings.append("Do not modify WireGuard tunnels in this phase.")

    for conflict in conflicts:
        message = conflict.get("message") or conflict.get("title") or "Preflight conflict detected."
        if message not in blocking_reasons:
            blocking_reasons.append(message)

    if counts.get("pppoe_servers"):
        warnings.append("PPPoE server exists. HotSpot Gateway is possible only on a new dedicated non-conflicting VLAN/network.")
    if counts.get("ospf_entries") or counts.get("routes", 0) > 30:
        warnings.append("Router has routing-sensitive indicators. Core routing must remain unchanged.")
    if counts.get("wireguard"):
        warnings.append("WireGuard exists. Tunnel interfaces and tunnel routes are out of scope.")

    requires_expert_override = risk_level in ("HIGH", "BLOCKED") or bool(danger_titles)
    setup_allowed = False
    if not confirmed_mode:
        blocking_reasons.append("Deployment mode is not confirmed.")
    elif confirmed_mode in ("READ_ONLY_CORE", "ISP_BACKUP_TRANSPORT"):
        blocking_reasons.append("Router is confirmed as read-only/transport. HotSpot setup is disabled.")
    elif confirmed_mode == "VLAN_TRUNK_HELPER":
        warnings.append("This router is confirmed as VLAN Trunk Helper. HotSpot/DHCP/NAT setup is disabled; only future VLAN helper actions may be allowed.")
        setup_allowed = False
    elif confirmed_mode == "UNKNOWN_NEEDS_REVIEW":
        blocking_reasons.append("Deployment mode is Unknown/Needs Review.")
    elif confirmed_mode == "HOTSPOT_GATEWAY":
        if role_guess == "CORE_ROUTER_READ_ONLY":
            blocking_reasons.append("Router appears to be core/routing infrastructure. HotSpot Gateway is blocked by default.")
        if role_guess == "SWITCH_TRUNK_HELPER":
            blocking_reasons.append("Router appears to be a VLAN trunk/switch helper. HotSpot Gateway is not allowed on this device.")
        required_fields = {
            "hotspot_vlan_id": "Customer VLAN ID is required.",
            "hotspot_vlan_parent_interface": "VLAN Parent Interface is required.",
            "hotspot_vlan_interface_name": "VLAN Interface Name is required.",
            "hotspot_client_network_cidr": "Client Network CIDR is required.",
            "hotspot_gateway_ip": "Gateway IP is required.",
            "hotspot_pool_start_ip": "Pool Start IP is required.",
            "hotspot_pool_end_ip": "Pool End IP is required.",
            "hotspot_dhcp_server_name": "DHCP Server Name is required.",
            "hotspot_dns_name": "HotSpot DNS Name is required.",
            "hotspot_dns_servers": "DNS Servers are required.",
        }
        for field, message in required_fields.items():
            if not str(router.get(field) or "").strip():
                blocking_reasons.append(message)
        portal_settings = ensure_captive_portal_settings()
        if not (portal_settings.get("portal_url_staging") or portal_settings.get("portal_url_production")):
            blocking_reasons.append("Portal URL is required.")
        if router.get("hotspot_enable_nat") and not str(router.get("hotspot_wan_interface") or "").strip():
            blocking_reasons.append("WAN/Internet Interface is required when NAT masquerade is enabled.")
        if requires_expert_override and not expert_override_enabled:
            blocking_reasons.append("Expert override is required because this router has sensitive/high-risk indicators.")
        setup_allowed = not blocking_reasons

    unique_blocking = []
    for reason in blocking_reasons:
        if reason and reason not in unique_blocking:
            unique_blocking.append(reason)
    unique_warnings = []
    for warning in warnings:
        if warning and warning not in unique_warnings:
            unique_warnings.append(warning)
    if unique_blocking:
        risk_level = "BLOCKED" if any("overlap" in item.lower() or "already exists" in item.lower() for item in unique_blocking) else risk_level
        if risk_level == "LOW":
            risk_level = "MEDIUM"
    return {
        "risk_level": risk_level,
        "role_guess": role_guess,
        "recommended_deployment_mode": recommended_mode,
        "role_reasoning": role_reasoning,
        "deployment_reasoning": deployment_reasoning,
        "pilot_suitability": pilot_suitability,
        "pilot_reason": pilot_reason,
        "confirmed_router_role": confirmed_role,
        "confirmed_deployment_mode": confirmed_mode,
        "setup_allowed": bool(setup_allowed),
        "requires_expert_override": bool(requires_expert_override),
        "expert_override_enabled": bool(expert_override_enabled),
        "blocking_reasons": unique_blocking,
        "warnings": unique_warnings,
        "next_questions": next_questions + [
            "Which router should be the first one-router pilot?",
            "Which routers must remain read-only/core?",
            "Is this MikroTik a gateway, a trunk/switch, or a PPPoE/core router?",
        ],
    }


def save_mikrotik_policy_result(router_id: str, scan_row, policy: dict, existing_policy=None):
    existing_policy = existing_policy or {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_deployment_policy_results(
                    router_id, scan_id, risk_level, role_guess, recommended_deployment_mode,
                    confirmed_router_role, confirmed_deployment_mode, setup_allowed,
                    requires_expert_override, expert_override_enabled, expert_override_reason,
                    expert_override_by_admin_id, expert_override_at, blocking_reasons_json,
                    warnings_json, next_questions_json
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    router_id,
                    scan_row["id"] if scan_row else None,
                    policy["risk_level"],
                    policy["role_guess"],
                    policy["recommended_deployment_mode"],
                    policy.get("confirmed_router_role"),
                    policy.get("confirmed_deployment_mode"),
                    policy["setup_allowed"],
                    policy["requires_expert_override"],
                    policy.get("expert_override_enabled", False),
                    existing_policy.get("expert_override_reason"),
                    existing_policy.get("expert_override_by_admin_id"),
                    existing_policy.get("expert_override_at"),
                    Json(policy.get("blocking_reasons") or []),
                    Json(policy.get("warnings") or []),
                    Json(policy.get("next_questions") or []),
                ),
            )
            row = cur.fetchone()
            if scan_row:
                public_policy = public_mikrotik_policy_result(row)
                public_policy.update({
                    "role_reasoning": policy.get("role_reasoning") or [],
                    "deployment_reasoning": policy.get("deployment_reasoning") or [],
                    "pilot_suitability": policy.get("pilot_suitability") or "UNKNOWN",
                    "pilot_reason": policy.get("pilot_reason"),
                })
                cur.execute(
                    """
                    UPDATE mikrotik_preflight_scans
                    SET policy_result_json = %s,
                        setup_blocked = %s,
                        setup_block_reason = %s,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (
                        Json(json_safe(public_policy)),
                        not policy["setup_allowed"],
                        "; ".join(policy.get("blocking_reasons") or []) or None,
                        scan_row["id"],
                    ),
                )
    return row


def evaluate_and_store_mikrotik_policy(router: dict, scan_row=None):
    scan_row = scan_row or latest_mikrotik_scan_row(str(router["id"]))
    existing_policy = latest_mikrotik_policy_row(str(router["id"]), scan_row["id"] if scan_row else None)
    policy = evaluate_mikrotik_deployment_policy(router, scan_row, existing_policy)
    return save_mikrotik_policy_result(str(router["id"]), scan_row, policy, existing_policy)


def test_mikrotik_api_login(host: str, port: int, username: Optional[str], password: Optional[str], use_tls: bool = False, timeout: float = 5.0):
    started = time.time()
    raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        sock = raw_sock
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        if not username:
            return {"status": "REACHABLE", "message": "MikroTik API port is reachable.", "latency_ms": int((time.time() - started) * 1000)}
        routeros_send_sentence(sock, ["/login", f"=name={username}", f"=password={password or ''}"])
        sentences = []
        while True:
            sentence = routeros_read_sentence(sock)
            sentences.append(sentence)
            if not sentence:
                continue
            marker = sentence[0]
            if marker == "!done":
                return {"status": "REACHABLE", "message": "MikroTik API login succeeded.", "latency_ms": int((time.time() - started) * 1000)}
            if marker == "!trap":
                message = next((word.split("=", 2)[2] for word in sentence if word.startswith("=message=")), "Authentication failed")
                return {"status": "AUTH_FAILED", "message": message, "latency_ms": int((time.time() - started) * 1000)}
            if len(sentences) > 10:
                return {"status": "ERROR", "message": "Unexpected RouterOS API response.", "latency_ms": int((time.time() - started) * 1000)}
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass


def create_omada_log(admin_id, action: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO omada_install_logs(started_by_admin_id, action, status, progress_percent, current_step)
                VALUES (%s, %s, 'RUNNING', 0, 'Queued') RETURNING id
                """,
                (admin_id, action),
            )
            return cur.fetchone()["id"]


def update_omada_log(log_id, output: str, progress_percent: int = None, current_step: str = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT output_text FROM omada_install_logs WHERE id = %s", (log_id,))
            row = cur.fetchone()
            current_output = row["output_text"] if row else ""
            next_output = redact((current_output + "\n\n" + output).strip())[-60000:] if output else current_output
            cur.execute(
                """
                UPDATE omada_install_logs
                SET output_text = %s,
                    progress_percent = COALESCE(%s, progress_percent),
                    current_step = COALESCE(%s, current_step)
                WHERE id = %s
                """,
                (next_output, progress_percent, current_step, log_id),
            )


def finish_omada_log(log_id, status: str, output: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE omada_install_logs
                SET status = %s,
                    output_text = %s,
                    progress_percent = CASE WHEN %s = 'SUCCESS' THEN 100 ELSE progress_percent END,
                    current_step = CASE WHEN %s = 'SUCCESS' THEN 'Complete' ELSE 'Failed' END,
                    completed_at = now()
                WHERE id = %s
                """,
                (status, redact(output)[-60000:], status, status, log_id),
            )


def update_omada_status(status: str, error: str = None, version: str = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE omada_controller_settings
                SET install_status = %s,
                    last_error = %s,
                    last_detected_version = COALESCE(%s, last_detected_version),
                    last_status_check_at = now(),
                    updated_at = now()
                WHERE id = (SELECT id FROM omada_controller_settings ORDER BY created_at ASC LIMIT 1)
                """,
                (status, error, version),
            )


def omada_ssh_client(settings):
    username = settings.get("ssh_username")
    if not username:
        raise HTTPException(status_code=400, detail="SSH username is required")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": settings["ssh_host"],
        "port": int(settings["ssh_port"] or 22),
        "username": username,
        "timeout": 10,
        "banner_timeout": 10,
        "auth_timeout": 10,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if settings["ssh_auth_type"] == "PRIVATE_KEY":
        key_text = decrypt_secret(settings.get("ssh_private_key_encrypted"))
        if not key_text:
            raise HTTPException(status_code=400, detail="SSH private key is not configured")
        passphrase = decrypt_secret(settings.get("ssh_private_key_passphrase_encrypted"))
        key_file = io.StringIO(key_text)
        try:
            kwargs["pkey"] = paramiko.RSAKey.from_private_key(key_file, password=passphrase)
        except paramiko.SSHException:
            key_file.seek(0)
            kwargs["pkey"] = paramiko.Ed25519Key.from_private_key(key_file, password=passphrase)
    else:
        password = decrypt_secret(settings.get("ssh_password_encrypted"))
        if not password:
            raise HTTPException(status_code=400, detail="SSH password is not configured")
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_ssh(client, command: str, sudo_mode: str = "PASSWORDLESS", sudo_password: Optional[str] = None, timeout: int = 120):
    if sudo_mode == "SUDO_PASSWORD" and sudo_password:
        command = f"printf '%s\\n' {json.dumps(sudo_password)} | sudo -S bash -lc {json.dumps(command)}"
    elif sudo_mode == "PASSWORDLESS":
        command = f"sudo -n bash -lc {json.dumps(command)}"
    else:
        command = f"bash -lc {json.dumps(command)}"
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    output = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
    return exit_code, redact(output)


def omada_compose_content(settings):
    image = settings.get("docker_image") or "mbentley/omada-controller:latest"
    network_mode = settings.get("network_mode") or "bridge"
    if network_mode == "host":
        return f"""services:
  omada-controller:
    image: {image}
    restart: unless-stopped
    network_mode: host
    environment:
      - TZ=Asia/Manila
    volumes:
      - data:/opt/tplink/EAPController/data
      - logs:/opt/tplink/EAPController/logs
      - work:/opt/tplink/EAPController/work

volumes:
  data:
  logs:
  work:
"""
    return f"""services:
  omada-controller:
    image: {image}
    restart: unless-stopped
    ports:
      - "8088:8088"
      - "8043:8043"
      - "8843:8843"
      - "29810:29810/udp"
      - "29811:29811"
      - "29812:29812"
      - "29813:29813"
      - "29814:29814"
    environment:
      - TZ=Asia/Manila
    volumes:
      - data:/opt/tplink/EAPController/data
      - logs:/opt/tplink/EAPController/logs
      - work:/opt/tplink/EAPController/work

volumes:
  data:
  logs:
  work:
"""


def detect_omada(settings):
    lines = []
    status = "NOT_INSTALLED"
    version = None
    with omada_ssh_client(settings) as client:
        checks = [
            ("ubuntu", "test -f /etc/os-release && . /etc/os-release && echo \"$PRETTY_NAME\" || uname -a"),
            ("docker", "command -v docker >/dev/null && docker --version || true"),
            ("compose", "docker compose version 2>/dev/null || true"),
            ("compose_file", "test -f /opt/omada-controller/docker-compose.yml && echo yes || echo no"),
            ("containers", "docker ps -a --filter label=com.docker.compose.project=omada_controller --format '{{.Names}} {{.Status}}' 2>/dev/null || true"),
            ("version", "docker ps --filter label=com.docker.compose.project=omada_controller --format '{{.Image}}' 2>/dev/null | head -1 || true"),
            ("ports", "ss -lntup 2>/dev/null | egrep '(:8088|:8043|:8843|:29810|:29811|:29812|:29813|:29814)' || true"),
        ]
        for label, command in checks:
            code, out = run_ssh(client, command, sudo_mode="NONE", timeout=30)
            lines.append(f"$ {label}\n{out.strip() or '(no output)'}")
            if label == "compose_file" and "yes" in out:
                status = "INSTALLED"
            if label == "containers" and "Up " in out:
                status = "RUNNING"
            if label == "version" and out.strip():
                version = out.strip().splitlines()[0]
    web = {
        "http": tcp_check(settings["host"], settings["http_port"]),
        "https": tcp_check(settings["host"], settings["https_port"]),
    }
    if web["http"]["status"] == "Reachable" or web["https"]["status"] == "Reachable":
        status = "RUNNING"
    lines.append(f"web_checks\nHTTP {web['http']['status']} HTTPS {web['https']['status']}")
    return {"status": status, "version": version, "web": web, "output": "\n\n".join(lines)}


def run_omada_action(action: str, admin_id, log_id=None):
    settings = ensure_omada_settings()
    log_id = log_id or create_omada_log(admin_id, action)
    output = []
    success = False
    try:
        if action in {"DETECT", "STATUS", "CHECK_PORTS"}:
            detected = detect_omada(settings)
            update_omada_status(detected["status"], None, detected.get("version"))
            output.append(detected["output"])
            success = True
        else:
            sudo_password = decrypt_secret(settings.get("ssh_password_encrypted")) if settings.get("sudo_mode") == "SUDO_PASSWORD" else None
            with omada_ssh_client(settings) as client:
                if action == "INSTALL":
                    update_omada_status("INSTALLING")
                    compose = omada_compose_content(settings)
                    compose_b64 = base64.b64encode(compose.encode()).decode()
                    commands = [
                        ("Checking Ubuntu compatibility", 10, "test -f /etc/os-release && . /etc/os-release && echo \"OS=$PRETTY_NAME\""),
                        ("Checking and installing Docker if missing", 25, "command -v docker >/dev/null || (apt-get update && apt-get install -y ca-certificates curl gnupg lsb-release docker.io)"),
                        ("Checking Docker Compose plugin", 38, "docker compose version >/dev/null 2>&1 || apt-get install -y docker-compose-plugin || apt-get install -y docker-compose-v2 || apt-get install -y docker-compose"),
                        ("Creating /opt/omada-controller", 48, "mkdir -p /opt/omada-controller"),
                        ("Writing Omada Compose file", 58, f"printf '%s' {json.dumps(compose_b64)} | base64 -d > /opt/omada-controller/docker-compose.yml"),
                        ("Pulling Omada Docker image", 72, "cd /opt/omada-controller && docker compose -p omada_controller pull"),
                        ("Starting Omada Controller", 86, "cd /opt/omada-controller && docker compose -p omada_controller up -d"),
                        ("Checking Omada container status", 92, "cd /opt/omada-controller && docker compose -p omada_controller ps"),
                    ]
                elif action == "START":
                    commands = [("Starting Omada Controller", 50, "cd /opt/omada-controller && docker compose -p omada_controller up -d")]
                elif action == "STOP":
                    commands = [("Stopping Omada Controller", 50, "cd /opt/omada-controller && docker compose -p omada_controller stop")]
                elif action == "RESTART":
                    commands = [("Restarting Omada Controller", 50, "cd /opt/omada-controller && docker compose -p omada_controller restart")]
                elif action == "BACKUP":
                    commands = [("Backing up Omada config", 50, "mkdir -p /opt/omada-controller/backups && tar -czf /opt/omada-controller/backups/omada-backup-$(date +%Y%m%d-%H%M%S).tgz -C /opt/omada-controller .")]
                elif action == "APPLY_HOST_NETWORK":
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE omada_controller_settings SET network_mode = 'host', updated_at = now() WHERE id = %s",
                                (settings["id"],),
                            )
                    settings = ensure_omada_settings()
                    compose = omada_compose_content({**settings, "network_mode": "host"})
                    compose_b64 = base64.b64encode(compose.encode()).decode()
                    commands = [
                        ("Backing up existing Omada Compose file", 10, "mkdir -p /opt/omada-controller/backups && test ! -f /opt/omada-controller/docker-compose.yml || cp /opt/omada-controller/docker-compose.yml /opt/omada-controller/backups/docker-compose.$(date +%Y%m%d-%H%M%S).yml"),
                        ("Writing host-network Omada Compose file", 25, f"mkdir -p /opt/omada-controller && printf '%s' {json.dumps(compose_b64)} | base64 -d > /opt/omada-controller/docker-compose.yml"),
                        ("Recreating Omada Controller in host network mode", 55, "cd /opt/omada-controller && docker compose -p omada_controller down --remove-orphans && docker compose -p omada_controller up -d"),
                        ("Verifying Docker network mode", 82, "docker inspect omada_controller-omada-controller-1 --format 'NetworkMode={{.HostConfig.NetworkMode}}'"),
                        ("Checking Omada container status", 92, "cd /opt/omada-controller && docker compose -p omada_controller ps"),
                    ]
                else:
                    raise HTTPException(status_code=400, detail="Unsupported Omada action")
                for step, progress, command in commands:
                    update_omada_log(log_id, f"STEP: {step}", progress, step)
                    code, out = run_ssh(client, command, settings.get("sudo_mode") or "PASSWORDLESS", sudo_password, timeout=600)
                    chunk = f"$ {command}\n{out.strip()}"
                    output.append(chunk)
                    update_omada_log(log_id, chunk, progress, step)
                    if code != 0:
                        raise RuntimeError(f"Command failed with exit code {code}")
            update_omada_log(log_id, "STEP: Verifying Omada UI and container status", 96, "Verifying Omada status")
            detected = detect_omada(ensure_omada_settings())
            output.append(detected["output"])
            update_omada_log(log_id, detected["output"], 98, "Verifying Omada status")
            update_omada_status(detected["status"], None, detected.get("version"))
            success = True
    except Exception as exc:
        update_omada_status("ERROR", str(exc))
        output.append(f"ERROR: {exc}")
    finish_omada_log(log_id, "SUCCESS" if success else "FAILED", "\n\n".join(output))
    if not success:
        raise HTTPException(status_code=400, detail="Omada action failed. Check logs for details.")
    audit(admin_id, f"omada_{action.lower()}", "omada_controller", str(settings["id"]))
    return {"status": "ok", "log_id": log_id, "settings": public_omada_settings(ensure_omada_settings())}


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
        "portal_title": branding.get("portal_title", "3J WiFi"),
        "portal_welcome_message": branding.get("portal_welcome_message", "Welcome to 3J WiFi. Please enter your voucher code to start using the internet."),
        "portal_support_text": branding.get("portal_support_text", "Need a voucher? Ask the nearest vendo/operator."),
        "portal_terms_note": branding.get("portal_terms_note", "Use of this WiFi service is subject to local operator rules."),
        "portal_show_powered_by": branding.get("portal_show_powered_by", True),
    }


def system_display_name() -> str:
    row = fetch_one("SELECT value FROM app_settings WHERE key = 'system'")
    value = row["value"] if row else {}
    branding = value.get("branding", {})
    return (branding.get("display_name") or "3JCentralPisowifi").strip() or "3JCentralPisowifi"


def public_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def mask_voucher_code(code: str) -> str:
    normalized = normalize_voucher_code(code)
    if len(normalized) <= 4:
        return "****"
    return f"{normalized[:2]}***{normalized[-2:]}"


def mask_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return mac
    clean = re.sub(r"[^A-Fa-f0-9]", "", mac)
    if len(clean) < 6:
        return "***"
    return f"{clean[:2]}:**:**:**:{clean[-4:-2]}:{clean[-2:]}".upper()


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    clean = re.sub(r"[^A-Fa-f0-9]", "", mac)
    if len(clean) != 12:
        return mac.upper()
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2)).upper()


def portal_context(payload: PortalSessionRequest) -> dict:
    raw = payload.raw_query_params or {}
    raw_server_name = raw.get("server-name") or raw.get("server_name") or raw.get("server")
    link_login = payload.link_login or raw.get("link-login") or raw.get("link_login")
    link_login_only = payload.link_login_only or raw.get("link-login-only") or raw.get("link_login_only")
    link_orig = payload.link_orig or raw.get("link-orig") or raw.get("link_orig")
    return {
        "client_mac": payload.client_mac or payload.clientMac or payload.mac or raw.get("client_mac") or raw.get("clientMac") or raw.get("mac"),
        "client_ip": payload.client_ip or payload.ip or raw.get("client_ip") or raw.get("clientIp") or raw.get("ip"),
        "ap_mac": payload.ap_mac or payload.apMac or raw.get("ap_mac") or raw.get("apMac"),
        "gateway_mac": payload.gateway_mac or payload.gatewayMac or raw.get("gateway_mac") or raw.get("gatewayMac"),
        "vlan_id": payload.vlan_id or payload.vid or raw.get("vlan_id") or raw.get("vid"),
        "ssid": payload.ssid or raw.get("ssid"),
        "site": payload.site or raw.get("site"),
        "gateway": payload.gateway or raw.get("gateway"),
        "redirect_url": payload.redirect_url or payload.redirectUrl or raw.get("redirect_url") or raw.get("redirectUrl"),
        "nas_id": payload.nas_id or raw.get("nas_id") or raw.get("nasId") or raw_server_name,
        "mikrotik_server_name": payload.server_name or raw_server_name,
        "mikrotik_link_login": link_login,
        "mikrotik_link_login_only": link_login_only,
        "mikrotik_link_orig": link_orig,
        "mikrotik_chap_id": payload.chap_id or raw.get("chap-id") or raw.get("chap_id"),
        "mikrotik_chap_challenge": payload.chap_challenge or raw.get("chap-challenge") or raw.get("chap_challenge"),
        "auth_token": payload.authToken or payload.token or raw.get("authToken") or raw.get("token") or raw.get("t"),
        "raw_query_params": raw,
    }


def portal_source(payload: PortalSessionRequest) -> str:
    ctx = portal_context(payload)
    gateway = (ctx["gateway"] or "").lower()
    nas_id = (ctx["nas_id"] or "").lower()
    if ctx.get("mikrotik_link_login") or ctx.get("mikrotik_link_login_only") or ctx.get("mikrotik_server_name") or ("mikrotik" in gateway or "mikrotik" in nas_id):
        return "MIKROTIK"
    if ctx["site"] or ctx["ap_mac"] or ctx["client_mac"] or ctx["auth_token"]:
        return "OMADA"
    if any([ctx["client_ip"], ctx["ssid"], ctx["gateway"], ctx["redirect_url"], ctx["nas_id"]]):
        return "UNKNOWN"
    return "MANUAL_TEST"


def station_hotspot_server_name(station: Optional[dict]) -> Optional[str]:
    if not station:
        return None
    return (station.get("hotspot_server_name") or f"HS-3J-HOTSPOT-V{station['vlan_id']}").strip()


def station_portal_url(station: Optional[dict] = None) -> str:
    settings = ensure_captive_portal_settings()
    return (
        (station or {}).get("portal_url")
        or settings.get("portal_url_staging")
        or settings.get("portal_url_production")
        or "http://192.168.50.70:8080/portal"
    )


def station_capport_url(station: Optional[dict] = None) -> str:
    portal_url = station_portal_url(station)
    parsed_url = portal_url if "://" in portal_url else f"http://{portal_url}"
    parsed = urlparse(parsed_url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path.split("/")[0]
    if not netloc:
        netloc = "192.168.50.70:8080"
    return f"{scheme}://{netloc}/api/portal/capport"


def station_gateway_login_url(station: Optional[dict] = None) -> str:
    if not station:
        return station_portal_url(station)
    dns_name = (station.get("hotspot_dns_name") or default_hotspot_dns_name(station.get("station_code"))).strip()
    return f"http://{dns_name}/login" if dns_name else station_portal_url(station)


def default_hotspot_dns_name(station_code: Optional[str] = None) -> str:
    code = re.sub(r"[^a-z0-9-]+", "-", str(station_code or "3j").strip().lower()).strip("-") or "3j"
    # Avoid .local because phones often reserve it for mDNS and skip normal DNS.
    return f"wifi.{code}.3jportal.test"


def station_captive_dns_probe_hosts() -> list[str]:
    return [
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "captive.apple.com",
        "www.msftconnecttest.com",
        "ipv6.msftconnecttest.com",
        "www.msftncsi.com",
        "dns.msftncsi.com",
        "connectivitycheck.platform.hicloud.com",
        "connectivitycheck.platform.hihonorcloud.com",
        "connectivitycheck.unisoc.com",
        "connect.rom.miui.com",
    ]


def station_for_client_ip(client_ip: Optional[str]):
    if not client_ip:
        return None
    try:
        target_ip = ip_address(str(client_ip))
    except ValueError:
        return None
    for station in fetch_all("SELECT * FROM mikrotik_stations WHERE status <> 'ARCHIVED' ORDER BY updated_at DESC"):
        try:
            if target_ip in ip_network(station["client_network_cidr"], strict=False):
                return station
        except Exception:
            continue
    return None


def station_for_root_gateway_ip(gateway_ip: Optional[str]):
    if not gateway_ip:
        return None
    return fetch_one(
        """
        SELECT s.*
        FROM mikrotik_stations s
        JOIN mikrotik_station_routers sr ON sr.station_id = s.id
        JOIN mikrotik_routers mr ON mr.id = sr.router_id
        WHERE s.status <> 'ARCHIVED'
          AND mr.host = %s
          AND (sr.station_role = 'ROOT_GATEWAY' OR sr.sequence_order = 0)
        ORDER BY
          CASE WHEN sr.station_role = 'ROOT_GATEWAY' THEN 0 ELSE 1 END,
          sr.sequence_order ASC,
          s.updated_at DESC
        LIMIT 1
        """,
        (str(gateway_ip).strip(),),
    )


def ensure_portal_session(cur, payload: PortalSessionRequest, request: Request):
    public_session_id = payload.portal_session_id or secrets.token_urlsafe(18)
    source = portal_source(payload)
    ctx = portal_context(payload)
    request_ip = public_ip(request)
    request_ip_station = station_for_client_ip(request_ip)
    payload_ip_station = station_for_client_ip(ctx.get("client_ip"))
    request_station = request_ip_station or payload_ip_station
    if request_station:
        if request_ip_station:
            ctx["client_ip"] = request_ip
        if not ctx.get("vlan_id"):
            ctx["vlan_id"] = str(request_station["vlan_id"])
        if not ctx.get("mikrotik_server_name"):
            ctx["mikrotik_server_name"] = station_hotspot_server_name(request_station)
        if source == "MANUAL_TEST":
            source = "MIKROTIK"
    cur.execute(
        """
        INSERT INTO portal_sessions(public_session_id, client_mac, client_ip, ap_mac, ssid, site, gateway, nas_id, redirect_url, user_agent, source,
                                    gateway_mac, vlan_id, raw_query_params, omada_site_name, omada_client_mac, omada_ap_mac,
                                    omada_gateway_mac, omada_token_encrypted, omada_redirect_url, omada_authorization_status,
                                    mikrotik_client_mac, mikrotik_client_ip, mikrotik_server_name, mikrotik_link_login,
                                    mikrotik_link_login_only, mikrotik_link_orig, mikrotik_chap_id, mikrotik_chap_challenge,
                                    mikrotik_authorization_status)
        VALUES (%s, %s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                CASE WHEN %s = 'OMADA' THEN 'PENDING' WHEN %s = 'MANUAL_TEST' THEN 'MANUAL_TEST' ELSE 'NOT_REQUIRED' END,
                %s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s, %s,
                CASE WHEN %s = 'MIKROTIK' THEN 'PENDING' WHEN %s = 'MANUAL_TEST' THEN 'MANUAL_TEST' ELSE 'NOT_REQUIRED' END)
        ON CONFLICT (public_session_id) DO UPDATE
        SET client_mac = COALESCE(EXCLUDED.client_mac, portal_sessions.client_mac),
            client_ip = COALESCE(EXCLUDED.client_ip, portal_sessions.client_ip),
            ap_mac = COALESCE(EXCLUDED.ap_mac, portal_sessions.ap_mac),
            gateway_mac = COALESCE(EXCLUDED.gateway_mac, portal_sessions.gateway_mac),
            vlan_id = COALESCE(EXCLUDED.vlan_id, portal_sessions.vlan_id),
            ssid = COALESCE(EXCLUDED.ssid, portal_sessions.ssid),
            site = COALESCE(EXCLUDED.site, portal_sessions.site),
            gateway = COALESCE(EXCLUDED.gateway, portal_sessions.gateway),
            nas_id = COALESCE(EXCLUDED.nas_id, portal_sessions.nas_id),
            redirect_url = COALESCE(EXCLUDED.redirect_url, portal_sessions.redirect_url),
            raw_query_params = COALESCE(EXCLUDED.raw_query_params, portal_sessions.raw_query_params),
            omada_site_name = COALESCE(EXCLUDED.omada_site_name, portal_sessions.omada_site_name),
            omada_client_mac = COALESCE(EXCLUDED.omada_client_mac, portal_sessions.omada_client_mac),
            omada_ap_mac = COALESCE(EXCLUDED.omada_ap_mac, portal_sessions.omada_ap_mac),
            omada_gateway_mac = COALESCE(EXCLUDED.omada_gateway_mac, portal_sessions.omada_gateway_mac),
            omada_token_encrypted = COALESCE(EXCLUDED.omada_token_encrypted, portal_sessions.omada_token_encrypted),
            omada_redirect_url = COALESCE(EXCLUDED.omada_redirect_url, portal_sessions.omada_redirect_url),
            mikrotik_client_mac = COALESCE(EXCLUDED.mikrotik_client_mac, portal_sessions.mikrotik_client_mac),
            mikrotik_client_ip = COALESCE(EXCLUDED.mikrotik_client_ip, portal_sessions.mikrotik_client_ip),
            mikrotik_server_name = COALESCE(EXCLUDED.mikrotik_server_name, portal_sessions.mikrotik_server_name),
            mikrotik_link_login = COALESCE(EXCLUDED.mikrotik_link_login, portal_sessions.mikrotik_link_login),
            mikrotik_link_login_only = COALESCE(EXCLUDED.mikrotik_link_login_only, portal_sessions.mikrotik_link_login_only),
            mikrotik_link_orig = COALESCE(EXCLUDED.mikrotik_link_orig, portal_sessions.mikrotik_link_orig),
            mikrotik_chap_id = COALESCE(EXCLUDED.mikrotik_chap_id, portal_sessions.mikrotik_chap_id),
            mikrotik_chap_challenge = COALESCE(EXCLUDED.mikrotik_chap_challenge, portal_sessions.mikrotik_chap_challenge),
            user_agent = EXCLUDED.user_agent,
            source = CASE WHEN portal_sessions.source = 'MANUAL_TEST' THEN EXCLUDED.source ELSE portal_sessions.source END,
            omada_authorization_status = CASE
                WHEN EXCLUDED.source = 'OMADA' AND portal_sessions.omada_authorization_status IN ('NOT_REQUIRED', 'MANUAL_TEST') THEN 'PENDING'
                ELSE portal_sessions.omada_authorization_status
            END,
            mikrotik_authorization_status = CASE
                WHEN EXCLUDED.source = 'MIKROTIK' AND portal_sessions.mikrotik_authorization_status IN ('NOT_REQUIRED', 'MANUAL_TEST') THEN 'PENDING'
                ELSE portal_sessions.mikrotik_authorization_status
            END,
            updated_at = now()
        RETURNING *
        """,
        (
            public_session_id,
            ctx["client_mac"],
            ctx["client_ip"] or "",
            ctx["ap_mac"],
            ctx["ssid"],
            ctx["site"],
            ctx["gateway"],
            ctx["nas_id"],
            ctx["redirect_url"],
            request.headers.get("user-agent"),
            source,
            ctx["gateway_mac"],
            ctx["vlan_id"],
            Json(ctx["raw_query_params"] or {}),
            ctx["site"],
            ctx["client_mac"],
            ctx["ap_mac"],
            ctx["gateway_mac"],
            encrypt_secret(ctx["auth_token"]) if ctx["auth_token"] else None,
            ctx["redirect_url"],
            source,
            source,
            ctx["client_mac"],
            ctx["client_ip"] or "",
            ctx["mikrotik_server_name"],
            ctx["mikrotik_link_login"],
            ctx["mikrotik_link_login_only"],
            ctx["mikrotik_link_orig"],
            ctx["mikrotik_chap_id"],
            ctx["mikrotik_chap_challenge"],
            source,
            source,
        ),
    )
    return cur.fetchone()


def create_portal_event(cur, session_id, event_type: str, request: Request, message: str = None, voucher_code: str = None, raw_context: dict = None):
    cur.execute(
        """
        INSERT INTO portal_events(portal_session_id, event_type, voucher_code_masked, message, ip_address, user_agent, raw_context)
        VALUES (%s, %s, %s, %s, NULLIF(%s, '')::inet, %s, %s)
        """,
        (
            session_id,
            event_type,
            mask_voucher_code(voucher_code) if voucher_code else None,
            message,
            public_ip(request),
            request.headers.get("user-agent"),
            Json(raw_context or {}),
        ),
    )


def ensure_portal_user(cur, session):
    if session.get("user_id"):
        cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
        existing = cur.fetchone()
        if existing:
            return existing
    suffix = normalize_voucher_code(session["public_session_id"])[:8].lower()
    username = f"portal_{suffix}"
    password = secrets.token_urlsafe(18)
    cur.execute(
        """
        INSERT INTO users(username, password_hash, status, source)
        VALUES (%s, %s, 'active', 'PORTAL')
        ON CONFLICT (username) DO UPDATE SET updated_at = now()
        RETURNING *
        """,
        (username, hash_password(password)),
    )
    user = cur.fetchone()
    cur.execute("INSERT INTO wallets(user_id) VALUES (%s) ON CONFLICT (user_id) DO NOTHING", (user["id"],))
    cur.execute(
        "INSERT INTO radcheck(username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s) ON CONFLICT (username, attribute) DO UPDATE SET value = EXCLUDED.value",
        (username, password),
    )
    cur.execute("UPDATE portal_sessions SET user_id = %s, updated_at = now() WHERE id = %s", (user["id"], session["id"]))
    return user


def portal_wallet_status(cur, session):
    if not session.get("user_id"):
        return None
    cur.execute(
        """
        SELECT u.id, u.username, w.time_remaining_seconds, w.valid_until, w.is_unlimited
        FROM users u
        LEFT JOIN wallets w ON w.user_id = u.id
        WHERE u.id = %s
        """,
        (session["user_id"],),
    )
    return cur.fetchone()


def aware_utc(value):
    if not value:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def portal_access_view(session, wallet, redemption=None):
    now = datetime.now(timezone.utc)
    wallet_remaining = int((wallet or {}).get("time_remaining_seconds") or 0)
    unlimited = bool((wallet or {}).get("is_unlimited"))
    valid_until = aware_utc((wallet or {}).get("valid_until"))
    access_expires_at = aware_utc(session.get("access_expires_at"))
    if not access_expires_at and session.get("source") in {"OMADA", "MIKROTIK"} and redemption:
        redeemed_seconds = int(redemption.get("redeemed_time_seconds") or 0)
        granted_at = aware_utc(session.get("access_granted_at")) or aware_utc(redemption.get("created_at"))
        if redeemed_seconds > 0 and granted_at:
            access_expires_at = granted_at + timedelta(seconds=redeemed_seconds)

    gateway_authorization_status = session.get("mikrotik_authorization_status") if session.get("source") == "MIKROTIK" else session.get("omada_authorization_status")
    gateway_authorized = gateway_authorization_status == "AUTHORIZED"
    uses_gateway_window = session.get("source") in {"OMADA", "MIKROTIK"} and access_expires_at and not unlimited

    if uses_gateway_window:
        remaining = max(int((access_expires_at - now).total_seconds()), 0)
        expired = remaining <= 0
        return {
            "remaining_time_seconds": remaining,
            "valid_until": access_expires_at,
            "unlimited": False,
            "access_expires_at": access_expires_at,
            "access_expired": expired,
            "connected": gateway_authorized and not expired,
            "message": "Access time fully consumed. Enter a new voucher to continue." if expired else "Access loaded.",
        }

    valid_until_expired = valid_until is not None and valid_until <= now
    access_expired = not unlimited and wallet_remaining <= 0 and valid_until_expired
    return {
        "remaining_time_seconds": max(wallet_remaining, 0),
        "valid_until": valid_until,
        "unlimited": unlimited,
        "access_expires_at": access_expires_at,
        "access_expired": access_expired,
        "connected": bool(unlimited or wallet_remaining > 0 or (valid_until and valid_until > now)),
        "message": "Access time fully consumed. Enter a new voucher to continue." if access_expired else ("Access loaded." if wallet else "Enter a voucher to start."),
    }


def ensure_captive_portal_settings():
    row = fetch_one("SELECT * FROM captive_portal_settings ORDER BY created_at ASC LIMIT 1")
    if row:
        return row
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO captive_portal_settings(portal_mode, open_ssid_name, portal_url_staging, portal_url_production, status)
                VALUES ('MIKROTIK', '3J-FreeWiFi', 'http://192.168.50.70:8080/portal', 'http://192.168.50.70/portal', 'READY_FOR_TEST')
                RETURNING *
                """
            )
            return cur.fetchone()


def captive_portal_ssid_from_ap_configuration(config: Optional[dict] = None) -> dict:
    config = config or ensure_ap_deployment_configuration()
    use_same = bool(config.get("use_same_ssid"))
    same_ssid = (config.get("same_ssid_name") or "3J-FreeWiFi").strip()
    ssid_2g = (config.get("ssid_2g") or same_ssid or "3J-FreeWiFi-2G").strip()
    ssid_5g = (config.get("ssid_5g") or same_ssid or "3J-FreeWiFi-5G").strip()
    primary = same_ssid if use_same else ssid_2g
    display = same_ssid if use_same else f"{ssid_2g} / {ssid_5g}"
    return {
        "source": "AP_DEPLOYMENT_CONFIGURATION",
        "use_same_ssid": use_same,
        "primary_ssid": primary,
        "display_ssid": display,
        "same_ssid_name": same_ssid,
        "ssid_2g": ssid_2g,
        "ssid_5g": ssid_5g,
        "band_steering_enabled": bool(config.get("band_steering_enabled")),
        "security_mode": (config.get("security_mode") or "OPEN").upper(),
    }


def public_captive_portal_settings(row=None):
    row = row or ensure_captive_portal_settings()
    design = fetch_one("SELECT * FROM portal_design_templates ORDER BY updated_at DESC LIMIT 1")
    portal_ssid = captive_portal_ssid_from_ap_configuration()
    return {
        "id": row["id"],
        "portal_mode": row["portal_mode"],
        "open_ssid_name": portal_ssid["primary_ssid"],
        "portal_ssid": portal_ssid,
        "ssid_source": portal_ssid["source"],
        "portal_url_staging": row["portal_url_staging"],
        "portal_url_production": row["portal_url_production"],
        "default_access_duration_seconds": row["default_access_duration_seconds"],
        "post_login_redirect_url": row["post_login_redirect_url"],
        "selected_omada_site_id": row["selected_omada_site_id"],
        "selected_omada_site_name": row["selected_omada_site_name"],
        "test_checklist_progress": row["test_checklist_progress"] or {},
        "status": row["status"],
        "custom_html": design["html_template"] if design else "",
        "custom_css": design["css_template"] if design else "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def log_captive_portal_test(action: str, status: str, message: str, details: dict = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO captive_portal_test_logs(action, status, message, details) VALUES (%s, %s, %s, %s)",
                (action, status, message, Json(sanitize_summary(details or {}))),
            )


def validate_voucher_for_portal(cur, voucher_code: str):
    normalized = normalize_voucher_code(voucher_code)
    cur.execute("SELECT * FROM vouchers WHERE normalized_code = %s FOR UPDATE", (normalized,))
    voucher = cur.fetchone()
    if not voucher:
        return None, "Voucher not found"
    failure = None
    if voucher["status"] == "USED":
        failure = "Voucher already used"
    elif voucher["status"] == "EXPIRED" or (voucher["expires_at"] and voucher["expires_at"] <= datetime.now(timezone.utc)):
        failure = "Voucher expired"
    elif voucher["status"] == "DISABLED":
        failure = "Voucher disabled"
    elif voucher["status"] == "VOIDED":
        failure = "Voucher voided"
    elif voucher["redemption_count"] >= voucher["max_redemptions"]:
        failure = "Voucher redemption limit reached"
    elif voucher["voucher_type"] not in VOUCHER_TYPES:
        failure = "Invalid voucher type"
    if failure == "Voucher expired" and voucher["status"] == "UNUSED":
        cur.execute("UPDATE vouchers SET status = 'EXPIRED', updated_at = now() WHERE id = %s", (voucher["id"],))
    return voucher, failure


def voucher_authorization_duration(voucher, settings):
    now = datetime.now(timezone.utc)
    if voucher["voucher_type"] == "TIME_BASED":
        duration = max(int(voucher["time_value_seconds"] or 0), 0)
        return duration, now + timedelta(seconds=duration) if duration > 0 else now
    if voucher["voucher_type"] == "DATE_BASED":
        valid_until = voucher["valid_until"]
        if valid_until and valid_until.tzinfo is None:
            valid_until = valid_until.replace(tzinfo=timezone.utc)
        duration = max(int((valid_until - now).total_seconds()), 0) if valid_until else 0
        return duration, valid_until
    if voucher["voucher_type"] == "UNLIMITED":
        unlimited_until = voucher["unlimited_expires_at"]
        if unlimited_until and unlimited_until.tzinfo is None:
            unlimited_until = unlimited_until.replace(tzinfo=timezone.utc)
        if unlimited_until:
            return max(int((unlimited_until - now).total_seconds()), 0), unlimited_until
        duration = int(settings.get("default_access_duration_seconds") or 86400)
        return duration, now + timedelta(seconds=duration)
    return 0, None


def omada_selected_site(settings):
    api_settings = ensure_omada_api_settings()
    site_id = settings.get("selected_omada_site_id") or api_settings.get("selected_site_id")
    site_name = settings.get("selected_omada_site_name") or api_settings.get("selected_site_name")
    return api_settings, site_id, site_name


def attempt_omada_authorization(cur, session, voucher, user, duration_seconds: int, access_expires_at, payload: PortalRedeemRequest):
    settings = ensure_captive_portal_settings()
    api_settings, site_id, site_name = omada_selected_site(settings)
    ctx = portal_context(payload)
    client_mac = ctx["client_mac"] or session.get("omada_client_mac") or session.get("client_mac")
    ap_mac = ctx["ap_mac"] or session.get("omada_ap_mac") or session.get("ap_mac")
    gateway_mac = ctx["gateway_mac"] or session.get("omada_gateway_mac") or session.get("gateway_mac")
    request_summary = {
        "site_id": site_id,
        "site_name": site_name or ctx["site"],
        "client_mac": mask_mac(client_mac),
        "ap_mac": mask_mac(ap_mac),
        "gateway_mac": mask_mac(gateway_mac),
        "ssid": ctx["ssid"] or session.get("ssid"),
        "duration_seconds": duration_seconds,
        "has_token": bool(ctx["auth_token"]),
    }
    cur.execute(
        """
        INSERT INTO omada_portal_authorizations(portal_session_id, voucher_id, user_id, client_mac, ap_mac, gateway_mac,
                                                site_name, site_id, ssid, authorization_duration_seconds, access_expires_at,
                                                omada_request_summary, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING')
        RETURNING *
        """,
        (
            session["id"],
            voucher["id"],
            user["id"],
            client_mac,
            ap_mac,
            gateway_mac,
            site_name or ctx["site"],
            site_id,
            ctx["ssid"] or session.get("ssid"),
            duration_seconds,
            access_expires_at,
            Json(sanitize_summary(request_summary)),
        ),
    )
    authorization = cur.fetchone()
    if not site_id:
        error = "Omada site not selected"
    elif not client_mac:
        error = "Missing client MAC/token from Omada redirect"
    else:
        error = None
    if error:
        cur.execute(
            """
            UPDATE omada_portal_authorizations SET status = 'FAILED', error_message = %s, updated_at = now() WHERE id = %s
            """,
            (error, authorization["id"]),
        )
        cur.execute(
            "UPDATE portal_sessions SET omada_authorization_status = 'FAILED', omada_authorization_error = %s, updated_at = now() WHERE id = %s",
            (error, session["id"]),
        )
        return {"status": "FAILED", "error": error, "authorization_id": authorization["id"], "request_summary": request_summary}

    omada_payload = {
        "clientMac": client_mac,
        "apMac": ap_mac,
        "gatewayMac": gateway_mac,
        "ssid": ctx["ssid"] or session.get("ssid"),
        "site": site_name or ctx["site"],
        "authToken": ctx["auth_token"],
        "token": ctx["auth_token"],
        "duration": duration_seconds,
        "time": duration_seconds,
        "expire": int(access_expires_at.timestamp()) if access_expires_at else None,
    }
    try:
        _, client = omada_api_client_from_settings()
        result = client.authorize_portal_client(site_id, {k: v for k, v in omada_payload.items() if v is not None})
        response_summary = result.get("response_summary")
        cur.execute(
            """
            UPDATE omada_portal_authorizations
            SET status = 'SUCCESS', omada_response_summary = %s, updated_at = now()
            WHERE id = %s
            """,
            (Json(sanitize_summary(response_summary or {})), authorization["id"]),
        )
        cur.execute(
            """
            UPDATE portal_sessions
            SET omada_authorization_status = 'AUTHORIZED',
                omada_authorization_error = NULL,
                access_granted_at = now(),
                access_expires_at = %s,
                updated_at = now()
            WHERE id = %s
            """,
            (access_expires_at, session["id"]),
        )
        log_captive_portal_test("AUTHORIZE_CLIENT", "SUCCESS", "Omada client authorization succeeded.", {"request": request_summary, "response": response_summary})
        return {"status": "SUCCESS", "authorization_id": authorization["id"], "response_summary": response_summary}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        cur.execute(
            """
            UPDATE omada_portal_authorizations
            SET status = 'FAILED', omada_response_summary = %s, error_message = %s, updated_at = now()
            WHERE id = %s
            """,
            (Json(sanitize_summary(response_summary)), str(exc), authorization["id"]),
        )
        cur.execute(
            "UPDATE portal_sessions SET omada_authorization_status = 'FAILED', omada_authorization_error = %s, updated_at = now() WHERE id = %s",
            (str(exc), session["id"]),
        )
        log_captive_portal_test("AUTHORIZE_CLIENT", "FAILED", "Omada client authorization failed.", {"request": request_summary, "response": response_summary, "error": str(exc)})
        return {"status": "FAILED", "error": str(exc), "authorization_id": authorization["id"], "response_summary": response_summary}


def portal_user_cleartext_password(cur, user) -> str:
    cur.execute(
        "SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password' ORDER BY id DESC LIMIT 1",
        (user["username"],),
    )
    row = cur.fetchone()
    if row and row.get("value"):
        return row["value"]
    password = secrets.token_urlsafe(18)
    cur.execute(
        """
        INSERT INTO radcheck(username, attribute, op, value)
        VALUES (%s, 'Cleartext-Password', ':=', %s)
        ON CONFLICT (username, attribute) DO UPDATE SET value = EXCLUDED.value
        """,
        (user["username"], password),
    )
    return password


def station_for_mikrotik_portal_session(session, ctx: dict):
    server_name = (ctx.get("mikrotik_server_name") or session.get("mikrotik_server_name") or "").strip()
    vlan_id = (ctx.get("vlan_id") or session.get("vlan_id") or "").strip()
    if server_name:
        for row in fetch_all("SELECT * FROM mikrotik_stations WHERE status <> 'ARCHIVED' ORDER BY updated_at DESC"):
            if (station_hotspot_server_name(row) or "").lower() == server_name.lower():
                return row
    if vlan_id:
        try:
            return fetch_one(
                """
                SELECT *
                FROM mikrotik_stations
                WHERE status <> 'ARCHIVED' AND vlan_id = %s
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (int(vlan_id),),
            )
        except (TypeError, ValueError):
            return None
    client_ip = session.get("mikrotik_client_ip") or session.get("client_ip") or ctx.get("client_ip")
    station = station_for_client_ip(str(client_ip) if client_ip else None)
    if station:
        return station
    return None


def attempt_mikrotik_authorization(cur, session, voucher, user, duration_seconds: int, access_expires_at, payload: PortalRedeemRequest):
    ctx = portal_context(payload)
    station = station_for_mikrotik_portal_session(session, ctx)
    client_mac = ctx["client_mac"] or session.get("mikrotik_client_mac") or session.get("client_mac")
    client_ip = str(session.get("mikrotik_client_ip") or session.get("client_ip") or ctx["client_ip"] or "")
    server_name = ctx.get("mikrotik_server_name") or session.get("mikrotik_server_name") or station_hotspot_server_name(station)
    request_summary = {
        "station_id": str(station["id"]) if station else None,
        "station_name": station.get("station_name") if station else None,
        "client_mac": mask_mac(client_mac),
        "client_ip": client_ip,
        "hotspot_server_name": server_name,
        "duration_seconds": duration_seconds,
    }
    router = None
    if station:
        routers = station_router_rows(str(station["id"]))
        if routers:
            router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (routers[0]["router_id"],))
    cur.execute(
        """
        INSERT INTO mikrotik_portal_authorizations(portal_session_id, station_id, router_id, voucher_id, user_id,
                                                   client_mac, client_ip, hotspot_server_name, authorization_duration_seconds,
                                                   access_expires_at, mikrotik_request_summary, status)
        VALUES (%s, %s, %s, %s, %s, %s, NULLIF(%s, '')::inet, %s, %s, %s, %s, 'PENDING')
        RETURNING *
        """,
        (
            session["id"],
            station["id"] if station else None,
            router["id"] if router else None,
            voucher["id"],
            user["id"],
            client_mac,
            client_ip or "",
            server_name,
            duration_seconds,
            access_expires_at,
            Json(sanitize_summary(request_summary)),
        ),
    )
    authorization = cur.fetchone()

    def fail_authorization(message: str, response_summary: Optional[dict] = None):
        safe_message = sanitize_routeros_text(str(message))
        cur.execute(
            """
            UPDATE mikrotik_portal_authorizations
            SET status = 'FAILED', error_message = %s, mikrotik_response_summary = %s, updated_at = now()
            WHERE id = %s
            """,
            (safe_message, Json(response_summary or {"error": safe_message}), authorization["id"]),
        )
        cur.execute(
            "UPDATE portal_sessions SET mikrotik_authorization_status = 'FAILED', mikrotik_authorization_error = %s, updated_at = now() WHERE id = %s",
            (safe_message, session["id"]),
        )
        return {"status": "FAILED", "error": safe_message, "authorization_id": authorization["id"], "request_summary": request_summary, "response_summary": response_summary or {"error": safe_message}}

    error = None
    if not station:
        error = "MikroTik station not found for this HotSpot server or VLAN."
    elif not router:
        error = "Root gateway router not found for this station."
    elif not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        error = "Root gateway RouterOS API credentials are incomplete."
    elif not server_name:
        error = "MikroTik HotSpot server name was not provided by the portal redirect."
    elif not client_ip and not client_mac:
        error = "MikroTik client IP or MAC was not provided by the portal redirect."
    if error:
        return fail_authorization(error)

    password = decrypt_secret(router.get("password_encrypted"))
    hotspot_host_rows = []
    hotspot_active_rows = []
    hotspot_login_ip = client_ip
    if client_ip:
        try:
            hotspot_host_rows = routeros_readonly_query(
                router["host"],
                router["api_port"],
                router.get("username"),
                password,
                router.get("use_tls"),
                ["/ip/hotspot/host/print", f"?address={client_ip}", "=.proplist=.id,address,to-address,mac-address,authorized,bypassed,server,comment"],
                timeout=8,
            )
            if not hotspot_host_rows:
                hotspot_host_rows = routeros_readonly_query(
                    router["host"],
                    router["api_port"],
                    router.get("username"),
                    password,
                    router.get("use_tls"),
                    ["/ip/hotspot/host/print", f"?to-address={client_ip}", "=.proplist=.id,address,to-address,mac-address,authorized,bypassed,server,comment"],
                    timeout=8,
                )
        except Exception as exc:
            return fail_authorization(f"Could not verify MikroTik HotSpot host before authorization: {exc}")
        if hotspot_host_rows:
            host_row = hotspot_host_rows[0]
            if not client_mac:
                client_mac = host_row.get("mac-address")
            client_ip = host_row.get("address") or client_ip
            hotspot_login_ip = host_row.get("to-address") or host_row.get("address") or client_ip
            host_to_address = host_row.get("to-address")
            if host_to_address and host_to_address != host_row.get("address"):
                try:
                    server_rows = routeros_readonly_query(
                        router["host"],
                        router["api_port"],
                        router.get("username"),
                        password,
                        router.get("use_tls"),
                        ["/ip/hotspot/print", f"?name={server_name}", "=.proplist=.id,name,address-pool"],
                        timeout=8,
                    )
                except Exception:
                    server_rows = []
                server_pool = (server_rows[0].get("address-pool") if server_rows else "") or ""
                if server_pool in {"", "none"}:
                    cleanup = routeros_remove_hotspot_client_state(
                        router["host"],
                        router["api_port"],
                        router.get("username"),
                        password,
                        router.get("use_tls"),
                        client_mac,
                    )
                    return fail_authorization(
                        "MikroTik cleared an old translated HotSpot session for this phone. Reconnect to WiFi, open the portal again, then redeem the voucher.",
                        {
                            "request": sanitize_summary(request_summary),
                            "stale_host": sanitize_summary(host_row),
                            "cleanup": sanitize_summary(cleanup),
                        },
                    )
            request_summary["client_mac"] = mask_mac(client_mac)
            request_summary["hotspot_host_detected"] = True
            request_summary["hotspot_host_server"] = host_row.get("server")
            request_summary["hotspot_host_address"] = host_row.get("address")
            request_summary["hotspot_login_ip"] = hotspot_login_ip
            cur.execute(
                """
                UPDATE mikrotik_portal_authorizations
                SET client_mac = %s, client_ip = NULLIF(%s, '')::inet, mikrotik_request_summary = %s, updated_at = now()
                WHERE id = %s
                """,
                (client_mac, client_ip or "", Json(sanitize_summary(request_summary)), authorization["id"]),
            )
            cur.execute(
                """
                UPDATE portal_sessions
                SET client_ip = NULLIF(%s, '')::inet,
                    mikrotik_client_ip = NULLIF(%s, '')::inet,
                    mikrotik_client_mac = COALESCE(%s, mikrotik_client_mac),
                    updated_at = now()
                WHERE id = %s
                """,
                (client_ip or "", client_ip or "", client_mac, session["id"]),
            )
            try:
                hotspot_active_rows = routeros_readonly_query(
                    router["host"],
                    router["api_port"],
                    router.get("username"),
                    password,
                    router.get("use_tls"),
                    ["/ip/hotspot/active/print", f"?address={hotspot_login_ip}", "=.proplist=.id,address,mac-address,user,server,uptime,session-time-left"],
                    timeout=8,
                )
            except Exception:
                hotspot_active_rows = []
            if routeros_truthy(host_row.get("authorized")) or hotspot_active_rows:
                response_summary = sanitize_summary({
                    "status": "SUCCESS",
                    "message": "Client is already authorized in MikroTik HotSpot.",
                    "hotspot_login_ip": hotspot_login_ip,
                    "active_rows": hotspot_active_rows,
                })
                cur.execute(
                    """
                    UPDATE mikrotik_portal_authorizations
                    SET status = 'SUCCESS', mikrotik_response_summary = %s, updated_at = now()
                    WHERE id = %s
                    """,
                    (Json(response_summary), authorization["id"]),
                )
                cur.execute(
                    """
                    UPDATE portal_sessions
                    SET mikrotik_authorization_status = 'AUTHORIZED',
                        mikrotik_authorization_error = NULL,
                        access_granted_at = now(),
                        access_expires_at = %s,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (access_expires_at, session["id"]),
                )
                log_captive_portal_test("AUTHORIZE_MIKROTIK_CLIENT", "SUCCESS", "MikroTik HotSpot client was already authorized.", {"request": request_summary, "response": response_summary})
                return {"status": "SUCCESS", "authorization_id": authorization["id"], "response_summary": response_summary}
        else:
            request_summary["hotspot_host_detected"] = False
            return fail_authorization(
                f"Client {client_ip} is not visible in MikroTik HotSpot hosts. Reconnect to the HotSpot SSID, open the portal again, then retry the voucher.",
                {"request": sanitize_summary(request_summary), "host_rows": []},
            )

    hotspot_password = portal_user_cleartext_password(cur, user)
    hotspot_user_comment = f"3J Hotspot - portal user {user['username']}"
    try:
        result = routeros_authorize_hotspot_client(
            router["host"],
            router["api_port"],
            router.get("username"),
            password,
            router.get("use_tls"),
            user["username"],
            hotspot_password,
            duration_seconds,
            hotspot_user_comment,
            hotspot_login_ip,
            client_mac,
        )
        response_summary = sanitize_summary({**result, "commands": [{"label": item.get("label"), "status": item.get("status"), "message": item.get("message")} for item in result.get("results", [])]})
        cur.execute(
            """
            UPDATE mikrotik_portal_authorizations
            SET status = 'SUCCESS', mikrotik_response_summary = %s, updated_at = now()
            WHERE id = %s
            """,
            (Json(response_summary), authorization["id"]),
        )
        cur.execute(
            """
            UPDATE portal_sessions
            SET mikrotik_authorization_status = 'AUTHORIZED',
                mikrotik_authorization_error = NULL,
                access_granted_at = now(),
                access_expires_at = %s,
                updated_at = now()
            WHERE id = %s
            """,
            (access_expires_at, session["id"]),
        )
        log_captive_portal_test("AUTHORIZE_MIKROTIK_CLIENT", "SUCCESS", "MikroTik HotSpot client authorization succeeded.", {"request": request_summary, "response": response_summary})
        return {"status": "SUCCESS", "authorization_id": authorization["id"], "response_summary": response_summary}
    except Exception as exc:
        message = sanitize_routeros_text(str(exc))
        log_captive_portal_test("AUTHORIZE_MIKROTIK_CLIENT", "FAILED", "MikroTik HotSpot client authorization failed.", {"request": request_summary, "error": message})
        return fail_authorization(message)


def mikrotik_station_client_is_authorized(station: Optional[dict], client_ip: Optional[str]) -> bool:
    if not station or not client_ip:
        return False
    root = station_root_router(str(station["id"]))
    if not root:
        return False
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (root["router_id"],))
    if not router or not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        return False
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        rows = routeros_readonly_query(
            router["host"],
            router["api_port"],
            router.get("username"),
            password,
            router.get("use_tls"),
            ["/ip/hotspot/active/print", f"?address={client_ip}", "=.proplist=.id,address,mac-address,user,server,session-time-left"],
            timeout=5,
        )
        return bool(rows)
    except Exception:
        return False


@app.get("/api/portal/capport")
def portal_capport(request: Request):
    client_ip = public_ip(request)
    station = station_for_client_ip(client_ip) or station_for_root_gateway_ip(client_ip)
    portal_url = station_gateway_login_url(station) if station else station_portal_url(station)
    payload = {
        "captive": True if station and station_for_root_gateway_ip(client_ip) else not mikrotik_station_client_is_authorized(station, client_ip),
        "user-portal-url": portal_url,
        "venue-info-url": portal_url,
        "can-extend-session": True,
        "seconds-remaining": 0,
    }
    return Response(content=json.dumps(payload), media_type="application/captive+json")


@app.get("/api/portal/settings")
def portal_settings():
    branding = public_branding()
    design = fetch_one("SELECT * FROM portal_design_templates ORDER BY updated_at DESC LIMIT 1")
    return {
        "portal_title": branding["portal_title"],
        "portal_subtitle": branding["portal_subtitle"] or "Enter your voucher to connect",
        "welcome_message": branding["portal_welcome_message"],
        "support_text": branding["portal_support_text"],
        "terms_note": branding["portal_terms_note"],
        "show_powered_by": branding["portal_show_powered_by"],
        "accent_color": branding["accent_color"],
        "company_logo_url": branding["company_logo_url"],
        "custom_html": design["html_template"] if design else "",
        "custom_css": design["css_template"] if design else "",
    }


@app.post("/api/portal/session")
def create_or_update_portal_session(payload: PortalSessionRequest, request: Request):
    with get_conn() as conn:
        with conn.cursor() as cur:
            session = ensure_portal_session(cur, payload, request)
            create_portal_event(cur, session["id"], "PORTAL_VIEW", request, "Portal viewed", raw_context=payload.model_dump())
    return {
        "portal_session_id": session["public_session_id"],
        "status": session["status"],
        "source": session["source"],
        "omada_authorization_status": session.get("omada_authorization_status"),
        "mikrotik_authorization_status": session.get("mikrotik_authorization_status"),
        "device_detected": session["source"] in {"OMADA", "MIKROTIK", "UNKNOWN"},
    }


@app.post("/api/portal/redeem")
def portal_redeem(payload: PortalRedeemRequest, request: Request):
    with get_conn() as conn:
        with conn.cursor() as cur:
            session = ensure_portal_session(cur, payload, request)
            failed_count = fetch_one(
                """
                SELECT count(*) AS count
                FROM portal_events
                WHERE event_type = 'VOUCHER_REDEEM_FAILED'
                  AND created_at > now() - interval '10 minutes'
                  AND (ip_address = NULLIF(%s, '')::inet OR portal_session_id = %s)
                """,
                (public_ip(request), session["id"]),
            )["count"]
            if failed_count >= 10:
                create_portal_event(cur, session["id"], "VOUCHER_REDEEM_FAILED", request, "Too many attempts. Please wait a few minutes.", payload.voucher_code, payload.model_dump())
                return {"status": "FAILED", "message": "Too many attempts. Please wait a few minutes before trying again.", "portal_session_id": session["public_session_id"]}
            create_portal_event(cur, session["id"], "VOUCHER_SUBMITTED", request, "Voucher submitted", payload.voucher_code, payload.model_dump())
            user = ensure_portal_user(cur, session)
            if session["source"] == "OMADA":
                voucher, failure = validate_voucher_for_portal(cur, payload.voucher_code)
                if failure:
                    if voucher:
                        log_failed_redemption(
                            cur,
                            voucher,
                            VoucherRedeemTest(voucher_code=payload.voucher_code, user_id=str(user["id"]), device_identifier=payload.client_mac or payload.clientMac or payload.client_ip or session["public_session_id"]),
                            failure,
                            "CLIENT_PORTAL",
                            request,
                        )
                    cur.execute(
                        """
                        UPDATE portal_sessions
                        SET status = 'ACCESS_DENIED',
                            last_error = %s,
                            updated_at = now()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (failure, session["id"]),
                    )
                    session = cur.fetchone()
                    create_portal_event(cur, session["id"], "VOUCHER_REDEEM_FAILED", request, failure, payload.voucher_code, {"result": "FAILED", "phase": "validation"})
                    return {"status": "FAILED", "message": failure or "Something went wrong. Please try again or contact the operator.", "portal_session_id": session["public_session_id"], "authorization_status": session.get("omada_authorization_status")}

                portal_settings_row = ensure_captive_portal_settings()
                duration_seconds, access_expires_at = voucher_authorization_duration(voucher, portal_settings_row)
                authorization = attempt_omada_authorization(cur, session, voucher, user, duration_seconds, access_expires_at, payload)
                if authorization["status"] != "SUCCESS":
                    message = "Voucher is valid but we could not authorize your device. Please ask the operator."
                    cur.execute(
                        """
                        UPDATE portal_sessions
                        SET status = 'ACCESS_DENIED',
                            last_error = %s,
                            updated_at = now()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (authorization.get("error") or message, session["id"]),
                    )
                    session = cur.fetchone()
                    create_portal_event(cur, session["id"], "VOUCHER_REDEEM_FAILED", request, message, payload.voucher_code, {"result": "FAILED", "authorization": sanitize_summary(authorization)})
                    return {
                        "status": "FAILED",
                        "message": message,
                        "portal_session_id": session["public_session_id"],
                        "authorization_status": "FAILED",
                        "authorization_error": authorization.get("error"),
                }

            if session["source"] == "MIKROTIK":
                voucher, failure = validate_voucher_for_portal(cur, payload.voucher_code)
                if failure:
                    if voucher:
                        log_failed_redemption(
                            cur,
                            voucher,
                            VoucherRedeemTest(voucher_code=payload.voucher_code, user_id=str(user["id"]), device_identifier=payload.mac or payload.client_mac or payload.clientMac or payload.ip or payload.client_ip or session["public_session_id"]),
                            failure,
                            "CLIENT_PORTAL",
                            request,
                        )
                    cur.execute(
                        """
                        UPDATE portal_sessions
                        SET status = 'ACCESS_DENIED',
                            last_error = %s,
                            mikrotik_authorization_status = 'FAILED',
                            mikrotik_authorization_error = %s,
                            updated_at = now()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (failure, failure, session["id"]),
                    )
                    session = cur.fetchone()
                    create_portal_event(cur, session["id"], "VOUCHER_REDEEM_FAILED", request, failure, payload.voucher_code, {"result": "FAILED", "phase": "mikrotik_validation"})
                    return {"status": "FAILED", "message": failure or "Something went wrong. Please try again or contact the operator.", "portal_session_id": session["public_session_id"], "authorization_status": session.get("mikrotik_authorization_status")}

                portal_settings_row = ensure_captive_portal_settings()
                duration_seconds, access_expires_at = voucher_authorization_duration(voucher, portal_settings_row)
                authorization = attempt_mikrotik_authorization(cur, session, voucher, user, duration_seconds, access_expires_at, payload)
                if authorization["status"] != "SUCCESS":
                    message = "Voucher is valid but we could not authorize your device. Please ask the operator."
                    cur.execute(
                        """
                        UPDATE portal_sessions
                        SET status = 'ACCESS_DENIED',
                            last_error = %s,
                            updated_at = now()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (authorization.get("error") or message, session["id"]),
                    )
                    session = cur.fetchone()
                    create_portal_event(cur, session["id"], "VOUCHER_REDEEM_FAILED", request, message, payload.voucher_code, {"result": "FAILED", "authorization": sanitize_summary(authorization), "source": "MIKROTIK"})
                    return {
                        "status": "FAILED",
                        "message": message,
                        "portal_session_id": session["public_session_id"],
                        "authorization_status": "FAILED",
                        "authorization_error": authorization.get("error"),
                    }

            result = redeem_voucher(cur, VoucherRedeemTest(voucher_code=payload.voucher_code, user_id=str(user["id"]), device_identifier=payload.client_mac or payload.clientMac or payload.mac or payload.client_ip or payload.ip or session["public_session_id"]), None, request, "CLIENT_PORTAL")
            if result["status"] == "SUCCESS":
                next_status = "ACCESS_GRANTED" if session["source"] in {"OMADA", "MIKROTIK"} else "VOUCHER_REDEEMED"
                omada_status = "AUTHORIZED" if session["source"] == "OMADA" else ("MANUAL_TEST" if session["source"] == "MANUAL_TEST" else "NOT_REQUIRED")
                mikrotik_status = "AUTHORIZED" if session["source"] == "MIKROTIK" else ("MANUAL_TEST" if session["source"] == "MANUAL_TEST" else "NOT_REQUIRED")
                cur.execute(
                    """
                    UPDATE portal_sessions
                    SET voucher_id = %s,
                        user_id = %s,
                        status = %s,
                        last_error = NULL,
                        omada_authorization_status = %s,
                        mikrotik_authorization_status = %s,
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (result["voucher_id"], user["id"], next_status, omada_status, mikrotik_status, session["id"]),
                )
                session = cur.fetchone()
                success_message = "Voucher accepted. You may now use the internet." if session["source"] in {"OMADA", "MIKROTIK"} else "Voucher accepted. Your access has been loaded."
                create_portal_event(cur, session["id"], "VOUCHER_REDEEM_SUCCESS", request, success_message, payload.voucher_code, {"result": result["status"], "authorization_status": session.get("omada_authorization_status") or session.get("mikrotik_authorization_status")})
                wallet = portal_wallet_status(cur, session)
                access_view = portal_access_view(session, wallet)
                return {
                    "status": "SUCCESS",
                    "message": success_message,
                    "portal_session_id": session["public_session_id"],
                    "username": user["username"],
                    "remaining_time_seconds": access_view["remaining_time_seconds"],
                    "valid_until": access_view["valid_until"],
                    "unlimited": access_view["unlimited"],
                    "time_added_seconds": result.get("time_added_seconds", 0),
                    "authorization_status": session.get("mikrotik_authorization_status") if session["source"] == "MIKROTIK" else session.get("omada_authorization_status"),
                    "access_expires_at": access_view["access_expires_at"],
                    "access_expired": access_view["access_expired"],
                    "connected": access_view["connected"],
                    "redirect_url": session.get("mikrotik_link_orig") or session.get("redirect_url"),
                }
            cur.execute(
                """
                UPDATE portal_sessions
                SET status = CASE
                        WHEN status IN ('VOUCHER_REDEEMED', 'ACCESS_GRANTED') THEN status
                        ELSE 'ACCESS_DENIED'
                    END,
                    last_error = %s,
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (result.get("reason") or "Voucher redemption failed", session["id"]),
            )
            session = cur.fetchone()
            create_portal_event(cur, session["id"], "VOUCHER_REDEEM_FAILED", request, result.get("reason"), payload.voucher_code, {"result": result["status"]})
            return {"status": "FAILED", "message": result.get("reason") or "Something went wrong. Please try again or contact the operator.", "portal_session_id": session["public_session_id"]}


@app.get("/api/portal/status")
def portal_status(portal_session_id: str, request: Request):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM portal_sessions WHERE public_session_id = %s", (portal_session_id,))
            session = cur.fetchone()
            if not session:
                return {"status": "NEW", "message": "No portal session yet."}
            create_portal_event(cur, session["id"], "STATUS_VIEW", request, "Status viewed")
            wallet = portal_wallet_status(cur, session)
            cur.execute(
                """
                SELECT r.*, v.code AS voucher_code
                FROM voucher_redemptions r
                LEFT JOIN vouchers v ON v.id = r.voucher_id
                WHERE r.user_id = %s
                ORDER BY r.created_at DESC
                LIMIT 1
                """,
                (session["user_id"],),
            )
            redemption = cur.fetchone() if session.get("user_id") else None
            access_view = portal_access_view(session, wallet, redemption)
            if access_view["access_expired"] and session["status"] == "ACCESS_GRANTED":
                cur.execute(
                    """
                    UPDATE portal_sessions
                    SET status = 'EXPIRED',
                        last_error = 'Access time fully consumed. Enter a new voucher to continue.',
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (session["id"],),
                )
                session = cur.fetchone()
    return {
        "status": session["status"],
        "portal_session_id": session["public_session_id"],
        "username": wallet["username"] if wallet else None,
        "remaining_time_seconds": access_view["remaining_time_seconds"],
        "valid_until": access_view["valid_until"],
        "unlimited": access_view["unlimited"],
        "source": session["source"],
        "omada_authorization_status": session.get("omada_authorization_status"),
        "mikrotik_authorization_status": session.get("mikrotik_authorization_status"),
        "authorization_error": session.get("omada_authorization_error"),
        "mikrotik_authorization_error": session.get("mikrotik_authorization_error"),
        "access_expires_at": access_view["access_expires_at"],
        "access_expired": access_view["access_expired"],
        "connected": access_view["connected"],
        "redirect_url": session.get("mikrotik_link_orig") or session.get("redirect_url"),
        "last_voucher_redemption": redemption,
        "message": session["last_error"] or access_view["message"],
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


VOUCHER_TYPES = {"TIME_BASED", "DATE_BASED", "UNLIMITED"}
VOUCHER_STATUSES = {"UNUSED", "USED", "EXPIRED", "DISABLED", "VOIDED"}
VOUCHER_BATCH_STATUSES = {"ACTIVE", "COMPLETED", "VOIDED"}
VOUCHER_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def normalize_voucher_code(code: str) -> str:
    return re.sub(r"[\s-]+", "", (code or "").upper())


def format_voucher_code(normalized: str, prefix: Optional[str] = None) -> str:
    clean_prefix = normalize_voucher_code(prefix or "")
    body = normalized
    if clean_prefix and body.startswith(clean_prefix):
        body = body[len(clean_prefix):]
    chunks = [body[i:i + 4] for i in range(0, len(body), 4) if body[i:i + 4]]
    return "-".join([clean_prefix, *chunks] if clean_prefix else chunks)


def generate_voucher_code(prefix: Optional[str] = None, code_length: int = 8) -> tuple[str, str]:
    clean_prefix = normalize_voucher_code(prefix or "")
    body = "".join(secrets.choice(VOUCHER_ALPHABET) for _ in range(code_length))
    normalized = f"{clean_prefix}{body}"
    return format_voucher_code(normalized, clean_prefix), normalized


def validate_voucher_payload(voucher_type: str, time_value_seconds=None, valid_until=None):
    voucher_type = (voucher_type or "").upper()
    if voucher_type not in VOUCHER_TYPES:
        raise HTTPException(status_code=400, detail="Invalid voucher type")
    if voucher_type == "TIME_BASED" and not time_value_seconds:
        raise HTTPException(status_code=400, detail="Time-based vouchers require time value")
    if voucher_type == "DATE_BASED" and not valid_until:
        raise HTTPException(status_code=400, detail="Date-based vouchers require valid_until")
    return voucher_type


def expire_vouchers(cur):
    cur.execute(
        """
        UPDATE vouchers
        SET status = 'EXPIRED', updated_at = now()
        WHERE status = 'UNUSED'
          AND expires_at IS NOT NULL
          AND expires_at <= now()
        """
    )


def create_single_voucher(cur, payload: VoucherCreate, admin_id: str, batch_id=None):
    voucher_type = validate_voucher_payload(payload.voucher_type, payload.time_value_seconds, payload.valid_until)
    status = (payload.status or "UNUSED").upper()
    if status not in VOUCHER_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid voucher status")
    code = payload.code
    normalized = normalize_voucher_code(code) if code else ""
    for _ in range(50):
        if not normalized:
            code, normalized = generate_voucher_code(payload.code_prefix, payload.code_length)
        cur.execute("SELECT 1 FROM vouchers WHERE normalized_code = %s", (normalized,))
        if not cur.fetchone():
            break
        code = None
        normalized = ""
    if not normalized:
        raise HTTPException(status_code=409, detail="Could not generate unique voucher code")
    is_unlimited = voucher_type == "UNLIMITED"
    cur.execute(
        """
        INSERT INTO vouchers(batch_id, code, normalized_code, voucher_type, time_value_seconds, valid_until, is_unlimited,
                             unlimited_expires_at, status, max_redemptions, expires_at, note, created_by_admin_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        (
            batch_id,
            code,
            normalized,
            voucher_type,
            payload.time_value_seconds,
            payload.valid_until,
            is_unlimited,
            payload.unlimited_expires_at,
            status,
            payload.max_redemptions,
            payload.expires_at,
            payload.note,
            admin_id,
        ),
    )
    return cur.fetchone()


def voucher_rows(where_sql="", params=()):
    with get_conn() as conn:
        with conn.cursor() as cur:
            expire_vouchers(cur)
            cur.execute(
                f"""
                SELECT v.*,
                       u.username AS redeemed_by_username,
                       b.batch_name
                FROM vouchers v
                LEFT JOIN users u ON u.id = v.redeemed_by_user_id
                LEFT JOIN voucher_batches b ON b.id = v.batch_id
                {where_sql}
                ORDER BY v.created_at DESC
                LIMIT 1000
                """,
                params,
            )
            return cur.fetchall()


def voucher_summary():
    with get_conn() as conn:
        with conn.cursor() as cur:
            expire_vouchers(cur)
            cur.execute(
                """
                SELECT
                    count(*) AS total_vouchers,
                    count(*) FILTER (WHERE status = 'UNUSED') AS unused,
                    count(*) FILTER (WHERE status = 'USED') AS used,
                    count(*) FILTER (WHERE status = 'EXPIRED') AS expired,
                    count(*) FILTER (WHERE status = 'DISABLED') AS disabled,
                    COALESCE(sum(time_value_seconds) FILTER (WHERE voucher_type = 'TIME_BASED'), 0) AS total_time_issued,
                    COALESCE((SELECT sum(redeemed_time_seconds) FROM voucher_redemptions WHERE result = 'SUCCESS'), 0) AS total_time_redeemed
                FROM vouchers
                """
            )
            return cur.fetchone()


def log_failed_redemption(cur, voucher, payload: VoucherRedeemTest, reason: str, source="ADMIN_TEST", request: Request = None):
    cur.execute(
        """
        INSERT INTO voucher_redemptions(voucher_id, user_id, username, device_identifier, source, result, failure_reason, ip_address, user_agent)
        VALUES (%s, NULL, %s, %s, %s, 'FAILED', %s, NULLIF(%s, '')::inet, %s)
        """,
        (
            voucher["id"] if voucher else None,
            payload.username,
            payload.device_identifier,
            source,
            reason,
            request.client.host if request and request.client else "",
            request.headers.get("user-agent") if request else None,
        ),
    )


def redeem_voucher(cur, payload: VoucherRedeemTest, admin_id: str, request: Request = None, source="ADMIN_TEST"):
    normalized = normalize_voucher_code(payload.voucher_code)
    cur.execute("SELECT * FROM vouchers WHERE normalized_code = %s FOR UPDATE", (normalized,))
    voucher = cur.fetchone()
    if not voucher:
        return {"status": "FAILED", "reason": "Voucher not found"}

    user = None
    if payload.user_id:
        cur.execute("SELECT u.*, w.time_remaining_seconds, w.valid_until, w.is_unlimited FROM users u LEFT JOIN wallets w ON w.user_id = u.id WHERE u.id = %s", (payload.user_id,))
        user = cur.fetchone()
    elif payload.username:
        cur.execute("SELECT u.*, w.time_remaining_seconds, w.valid_until, w.is_unlimited FROM users u LEFT JOIN wallets w ON w.user_id = u.id WHERE lower(u.username) = lower(%s)", (payload.username,))
        user = cur.fetchone()
    if not user:
        log_failed_redemption(cur, voucher, payload, "User not found", source, request)
        return {"status": "FAILED", "reason": "User not found", "voucher_id": voucher["id"]}

    failure = None
    if voucher["status"] == "USED":
        failure = "Voucher already used"
    elif voucher["status"] == "EXPIRED" or (voucher["expires_at"] and voucher["expires_at"] <= datetime.now(timezone.utc)):
        failure = "Voucher expired"
    elif voucher["status"] == "DISABLED":
        failure = "Voucher disabled"
    elif voucher["status"] == "VOIDED":
        failure = "Voucher voided"
    elif voucher["redemption_count"] >= voucher["max_redemptions"]:
        failure = "Voucher redemption limit reached"
    elif voucher["voucher_type"] not in VOUCHER_TYPES:
        failure = "Invalid voucher type"
    if failure:
        if failure == "Voucher expired" and voucher["status"] == "UNUSED":
            cur.execute("UPDATE vouchers SET status = 'EXPIRED', updated_at = now() WHERE id = %s", (voucher["id"],))
        log_failed_redemption(cur, voucher, payload, failure, source, request)
        return {"status": "FAILED", "reason": failure, "voucher_id": voucher["id"]}

    before = {
        "time_remaining_seconds": user["time_remaining_seconds"] or 0,
        "valid_until": user["valid_until"],
        "is_unlimited": bool(user["is_unlimited"]),
    }
    redeemed_time = voucher["time_value_seconds"] if voucher["voucher_type"] == "TIME_BASED" else 0
    redeemed_valid_until = voucher["valid_until"] if voucher["voucher_type"] == "DATE_BASED" else (voucher["unlimited_expires_at"] if voucher["voucher_type"] == "UNLIMITED" else None)
    redeemed_unlimited = voucher["voucher_type"] == "UNLIMITED"
    cur.execute("INSERT INTO wallets(user_id) VALUES (%s) ON CONFLICT (user_id) DO NOTHING", (user["id"],))
    if voucher["voucher_type"] == "TIME_BASED":
        cur.execute(
            "UPDATE wallets SET time_remaining_seconds = time_remaining_seconds + %s, updated_at = now() WHERE user_id = %s",
            (redeemed_time, user["id"]),
        )
    elif voucher["voucher_type"] == "DATE_BASED":
        cur.execute(
            """
            UPDATE wallets
            SET valid_until = CASE WHEN valid_until IS NULL OR valid_until < %s THEN %s ELSE valid_until END,
                updated_at = now()
            WHERE user_id = %s
            """,
            (voucher["valid_until"], voucher["valid_until"], user["id"]),
        )
    elif voucher["voucher_type"] == "UNLIMITED":
        cur.execute(
            """
            UPDATE wallets
            SET is_unlimited = true,
                valid_until = CASE
                    WHEN %s::timestamptz IS NULL THEN valid_until
                    WHEN valid_until IS NULL OR valid_until < %s THEN %s
                    ELSE valid_until
                END,
                updated_at = now()
            WHERE user_id = %s
            """,
            (voucher["unlimited_expires_at"], voucher["unlimited_expires_at"], voucher["unlimited_expires_at"], user["id"]),
        )

    cur.execute(
        """
        INSERT INTO transactions(user_id, source, type, amount_seconds, reference, note, created_by)
        VALUES (%s, 'VOUCHER', 'CREDIT', %s, %s, %s, %s)
        RETURNING id
        """,
        (user["id"], redeemed_time or 0, voucher["code"], "Voucher redemption", admin_id),
    )
    transaction_id = cur.fetchone()["id"]
    cur.execute(
        """
        INSERT INTO voucher_redemptions(voucher_id, user_id, username, device_identifier, source, wallet_transaction_id,
                                        result, redeemed_time_seconds, redeemed_valid_until, redeemed_unlimited, ip_address, user_agent)
        VALUES (%s, %s, %s, %s, %s, %s, 'SUCCESS', %s, %s, %s, NULLIF(%s, '')::inet, %s)
        RETURNING id
        """,
        (
            voucher["id"],
            user["id"],
            user["username"],
            payload.device_identifier,
            source,
            transaction_id,
            redeemed_time,
            redeemed_valid_until,
            redeemed_unlimited,
            request.client.host if request and request.client else "",
            request.headers.get("user-agent") if request else None,
        ),
    )
    redemption_id = cur.fetchone()["id"]
    next_count = voucher["redemption_count"] + 1
    next_status = "USED" if next_count >= voucher["max_redemptions"] else voucher["status"]
    cur.execute(
        """
        UPDATE vouchers
        SET redemption_count = %s,
            redeemed_by_user_id = %s,
            redeemed_at = now(),
            status = %s,
            updated_at = now()
        WHERE id = %s
        """,
        (next_count, user["id"], next_status, voucher["id"]),
    )
    cur.execute("SELECT time_remaining_seconds, valid_until, is_unlimited FROM wallets WHERE user_id = %s", (user["id"],))
    after = cur.fetchone()
    return {
        "status": "SUCCESS",
        "message": "Voucher accepted",
        "voucher_id": voucher["id"],
        "voucher_code": voucher["code"],
        "user_id": user["id"],
        "username": user["username"],
        "wallet_before": before,
        "wallet_after": after,
        "transaction_id": transaction_id,
        "redemption_id": redemption_id,
        "time_added_seconds": redeemed_time,
        "valid_until": redeemed_valid_until,
        "unlimited": redeemed_unlimited,
    }


@app.get("/api/vouchers")
def get_vouchers(status: Optional[str] = None, voucher_type: Optional[str] = None, search: Optional[str] = None, batch_id: Optional[str] = None, admin=Depends(current_admin)):
    clauses = []
    params = []
    if status:
        clauses.append("v.status = %s")
        params.append(status.upper())
    if voucher_type:
        clauses.append("v.voucher_type = %s")
        params.append(voucher_type.upper())
    if search:
        clauses.append("(v.normalized_code LIKE %s OR v.code ILIKE %s)")
        params.extend([f"%{normalize_voucher_code(search)}%", f"%{search}%"])
    if batch_id:
        clauses.append("v.batch_id = %s")
        params.append(batch_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return {"summary": voucher_summary(), "vouchers": voucher_rows(where, tuple(params))}


@app.post("/api/vouchers")
def create_voucher(payload: VoucherCreate, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            row = create_single_voucher(cur, payload, admin["id"])
    audit(admin["id"], "create_voucher", "voucher", str(row["id"]), {"voucher_type": row["voucher_type"], "status": row["status"]})
    return row


@app.get("/api/vouchers/export.csv")
def export_vouchers_csv(status: Optional[str] = None, batch_id: Optional[str] = None, admin=Depends(current_admin)):
    clauses = []
    params = []
    if status:
        clauses.append("v.status = %s")
        params.append(status.upper())
    if batch_id:
        clauses.append("v.batch_id = %s")
        params.append(batch_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = voucher_rows(where, tuple(params))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["code", "type", "time_value_seconds", "valid_until", "is_unlimited", "status", "expires_at", "batch_name", "created_at"])
    for row in rows:
        writer.writerow([row["code"], row["voucher_type"], row["time_value_seconds"], row["valid_until"], row["is_unlimited"], row["status"], row["expires_at"], row["batch_name"], row["created_at"]])
    audit(admin["id"], "export_vouchers", "voucher", None, {"status": status, "batch_id": batch_id, "count": len(rows)})
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=vouchers.csv"})


@app.post("/api/vouchers/redeem-test")
def redeem_test_voucher(payload: VoucherRedeemTest, request: Request, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            result = redeem_voucher(cur, payload, admin["id"], request, "ADMIN_TEST")
    audit(admin["id"], "test_redeem_voucher", "voucher", str(result.get("voucher_id") or ""), {"result": result["status"], "reason": result.get("reason")})
    return result


@app.get("/api/voucher-redemptions")
def get_voucher_redemptions(result: Optional[str] = None, source: Optional[str] = None, search: Optional[str] = None, admin=Depends(current_admin)):
    clauses = []
    params = []
    if result:
        clauses.append("r.result = %s")
        params.append(result.upper())
    if source:
        clauses.append("r.source = %s")
        params.append(source.upper())
    if search:
        clauses.append("(v.code ILIKE %s OR r.username ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return fetch_all(
        f"""
        SELECT r.*, v.code AS voucher_code
        FROM voucher_redemptions r
        LEFT JOIN vouchers v ON v.id = r.voucher_id
        {where}
        ORDER BY r.created_at DESC
        LIMIT 500
        """,
        tuple(params),
    )


@app.get("/api/portal/events")
def get_portal_events(admin=Depends(current_admin)):
    return fetch_all(
        """
        SELECT e.*, s.public_session_id, s.status AS portal_status, s.ssid, s.site
        FROM portal_events e
        LEFT JOIN portal_sessions s ON s.id = e.portal_session_id
        ORDER BY e.created_at DESC
        LIMIT 100
        """
    )


@app.get("/api/portal/sessions")
def get_portal_sessions(admin=Depends(current_admin)):
    return fetch_all(
        """
        SELECT s.*, u.username, v.code AS voucher_code
        FROM portal_sessions s
        LEFT JOIN users u ON u.id = s.user_id
        LEFT JOIN vouchers v ON v.id = s.voucher_id
        ORDER BY s.updated_at DESC
        LIMIT 100
        """
    )


@app.get("/api/connected-devices")
def connected_devices(include_test: bool = False, admin=Depends(current_admin)):
    grace = int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180"))
    devices = {}
    omada_error = None

    def is_lab_device(device):
        text = " ".join(str(device.get(key) or "") for key in ["hostname", "username", "session_id", "raw_status", "id"]).lower()
        if device.get("source") == "PORTAL_SESSION":
            return True
        if str(device.get("hostname") or "").lower().startswith("portal_") and device.get("source") in {"OMADA", "UNKNOWN", "MANUAL_TEST"}:
            return True
        return any(marker in text for marker in ["phase1", "phase2", "pivot_smoke", "diag_", "stale-session", "smoke"])

    def upsert_device(device):
        if not include_test and not device.get("active") and is_lab_device(device):
            return
        mac = normalize_mac(device.get("client_mac"))
        key = mac or device.get("id") or f"{device.get('source')}:{len(devices)}"
        existing = devices.get(key, {})
        merged = {**existing, **{k: v for k, v in device.items() if v not in (None, "")}}
        merged["client_mac"] = mac or device.get("client_mac")
        merged["active"] = bool(existing.get("active") or device.get("active"))
        merged["status"] = "ACTIVE" if merged["active"] else "INACTIVE"
        merged["client_mac_masked"] = mask_mac(merged.get("client_mac"))
        devices[key] = merged

    settings = ensure_captive_portal_settings()
    _, site_id, site_name = omada_selected_site(settings)
    if site_id:
        try:
            _, client = omada_api_client_from_settings()
            result = client.get_clients_if_supported(site_id)
            for item in result.get("clients", []):
                upsert_device({
                    "source": "OMADA",
                    "client_mac": item.get("client_mac"),
                    "client_ip": item.get("client_ip"),
                    "hostname": item.get("hostname"),
                    "ap_mac": item.get("ap_mac"),
                    "ap_name": item.get("ap_name"),
                    "ssid": item.get("ssid"),
                    "site": site_name,
                    "active": item.get("active"),
                    "last_seen": item.get("last_seen"),
                    "uptime_seconds": item.get("uptime_seconds"),
                    "raw_status": item.get("raw_status"),
                })
        except Exception as exc:
            omada_error = str(exc)

    for row in fetch_all(
        """
        SELECT s.*,
               CASE
                 WHEN s.status = 'ACTIVE' AND s.stop_time IS NULL AND s.last_update_time > now() - (%s || ' seconds')::interval THEN true
                 ELSE false
               END AS is_active,
               u.username AS account_username
        FROM sessions s
        LEFT JOIN users u ON u.id = s.user_id
        ORDER BY s.last_update_time DESC
        LIMIT 500
        """,
        (grace,),
    ):
        upsert_device({
            "id": str(row["id"]),
            "source": "RADIUS_ACCOUNTING",
            "client_mac": row.get("calling_station_id"),
            "client_ip": row.get("framed_ip_address"),
            "hostname": row.get("account_username") or row.get("username"),
            "username": row.get("username"),
            "ap_name": row.get("nas_identifier"),
            "ap_ip": row.get("nas_ip"),
            "active": row.get("is_active"),
            "last_seen": row.get("last_update_time"),
            "connected_since": row.get("start_time"),
            "session_id": row.get("acct_session_id"),
            "raw_status": row.get("status"),
        })

    for row in fetch_all(
        """
        SELECT s.*, u.username, v.code AS voucher_code
        FROM portal_sessions s
        LEFT JOIN users u ON u.id = s.user_id
        LEFT JOIN vouchers v ON v.id = s.voucher_id
        WHERE COALESCE(s.omada_client_mac, s.client_mac) IS NOT NULL
        ORDER BY s.updated_at DESC
        LIMIT 500
        """
    ):
        active = row.get("status") in {"VOUCHER_REDEEMED", "ACCESS_GRANTED"} and row.get("updated_at") and row["updated_at"] > datetime.now(timezone.utc) - timedelta(seconds=grace)
        upsert_device({
            "id": str(row["id"]),
            "source": "PORTAL_SESSION",
            "portal_source": row.get("source"),
            "client_mac": row.get("omada_client_mac") or row.get("client_mac"),
            "client_ip": row.get("client_ip"),
            "hostname": row.get("username"),
            "ap_mac": row.get("omada_ap_mac") or row.get("ap_mac"),
            "ssid": row.get("ssid"),
            "site": row.get("omada_site_name") or row.get("site"),
            "active": active,
            "last_seen": row.get("updated_at"),
            "connected_since": row.get("created_at"),
            "voucher_code": row.get("voucher_code"),
            "raw_status": row.get("status"),
            "authorization_status": row.get("omada_authorization_status"),
        })

    rows = sorted(devices.values(), key=lambda item: (not item.get("active"), str(item.get("last_seen") or "")), reverse=False)
    active_rows = [row for row in rows if row.get("active")]
    inactive_rows = [row for row in rows if not row.get("active")]
    return {
        "summary": {
            "total": len(rows),
            "active": len(active_rows),
            "inactive": len(inactive_rows),
            "omada_site_id": site_id,
            "omada_site_name": site_name,
            "omada_error": omada_error,
        },
        "active": active_rows,
        "inactive": inactive_rows,
    }


@app.get("/api/site-deployments")
def list_site_deployments(admin=Depends(current_admin)):
    rows = fetch_all(
        """
        SELECT s.*, a.username AS created_by_username
        FROM site_deployments s
        LEFT JOIN admins a ON a.id = s.created_by_admin_id
        ORDER BY s.created_at DESC
        """
    )
    tombstones = fetch_all("SELECT omada_site_id, site_name FROM site_deployment_tombstones")
    tombstone_ids = {str(row.get("omada_site_id") or "") for row in tombstones if row.get("omada_site_id")}
    tombstone_names = {str(row.get("site_name") or "").strip().lower() for row in tombstones if row.get("site_name")}
    rows = [
        row for row in rows
        if str(row.get("omada_site_id") or "") not in tombstone_ids
        and str(row.get("site_name") or "").strip().lower() not in tombstone_names
    ]
    known_ids = {str(row.get("omada_site_id") or "") for row in rows if row.get("omada_site_id")}
    known_names = {str(row.get("site_name") or "").strip().lower() for row in rows}
    omada_sites = []
    api_settings = ensure_omada_api_settings()
    try:
        _, client = omada_api_client_from_settings()
        result = client.get_sites()
        omada_sites = result.get("sites", [])
    except Exception:
        omada_sites = []
        client = None
    ap_counts = {}
    if omada_sites and client:
        for site in omada_sites:
            site_id = site.get("site_id")
            if not site_id:
                continue
            try:
                ap_counts[str(site_id)] = client.get_site_ap_summary(site_id)
            except Exception as exc:
                ap_counts[str(site_id)] = {
                    "ap_total_count": None,
                    "ap_connected_count": None,
                    "ap_error": str(exc),
                }
    for row in rows:
        site_id = row.get("omada_site_id")
        summary = ap_counts.get(str(site_id)) if site_id else None
        row["ap_total_count"] = summary.get("ap_total_count") if summary else 0
        row["ap_connected_count"] = summary.get("ap_connected_count") if summary else 0
        row["ap_error"] = summary.get("ap_error") if summary else None
    if api_settings.get("selected_site_id") or api_settings.get("selected_site_name"):
        selected = {
            "site_id": api_settings.get("selected_site_id"),
            "site_name": api_settings.get("selected_site_name") or "Selected Omada Site",
            "is_default": True,
        }
        if not any(site.get("site_id") == selected["site_id"] or str(site.get("site_name", "")).lower() == str(selected["site_name"]).lower() for site in omada_sites):
            omada_sites.append(selected)
    for site in omada_sites:
        site_id = site.get("site_id")
        site_name = site.get("site_name") or "Unnamed Omada Site"
        if (site_id and str(site_id) in tombstone_ids) or site_name.strip().lower() in tombstone_names:
            continue
        if (site_id and str(site_id) in known_ids) or site_name.strip().lower() in known_names:
            continue
        rows.append({
            "id": f"omada-{site_id or normalize_voucher_code(site_name).lower()}",
            "site_name": site_name,
            "location": None,
            "address": None,
            "municipality": None,
            "barangay": None,
            "latitude": None,
            "longitude": None,
            "application_scenario": site.get("application_scenario"),
            "country_region": None,
            "time_zone": None,
            "contact_name": None,
            "contact_phone": None,
            "omada_site_id": site_id,
            "deployment_status": "ACTIVE",
            "notes": "Detected from Omada Controller. Add or link a local deployment record later for planning details.",
            "created_by_admin_id": None,
            "created_by_username": "Omada Controller",
            "created_at": None,
            "updated_at": None,
            "source": "OMADA_CONTROLLER",
            "is_omada_detected": True,
            "ap_total_count": (ap_counts.get(str(site_id)) or {}).get("ap_total_count") or 0,
            "ap_connected_count": (ap_counts.get(str(site_id)) or {}).get("ap_connected_count") or 0,
            "ap_error": (ap_counts.get(str(site_id)) or {}).get("ap_error"),
        })
    return rows


def normalize_ap_mac(mac: Optional[str]) -> str:
    return re.sub(r"[^A-Fa-f0-9]", "", mac or "").upper()


def ap_name_from_mac(mac: Optional[str]) -> str:
    normalized = normalize_ap_mac(mac)
    return f"AP-{normalized[-6:]}" if len(normalized) >= 6 else "AP-UNKNOWN"


def ap_status_from_omada(ap: dict) -> str:
    status = str(ap.get("status") or "").lower()
    code = ap.get("status_code")
    category = ap.get("status_category")
    if status in {"connected", "online", "normal"} or code in (14, 15, 16, 17) or category == 1:
        return "CONNECTED"
    if "adopt failed" in status or "failed" in status or code in (24, 25) or category == 4:
        return "ADOPT_FAILED"
    if "adopting" in status or code in (22, 23):
        return "ADOPTING"
    if "disconnected" in status or code in (0, 1, 30, 31, 32, 33) or category == 5:
        return "DISCONNECTED"
    return "ADOPTING"


def ap_is_pending_candidate(ap: dict) -> bool:
    status = str(ap.get("status") or "").lower()
    site_id = str(ap.get("site_id") or "").upper()
    return (
        "pending" in status
        or ap.get("status_code") in (20, 21)
        or ap.get("status_category") == 0
        or site_id == "PENDING-SITE"
        or bool(ap.get("adoptable"))
    )


def public_ap_deployment(row: dict, ap: dict = None) -> dict:
    ap = ap or {}
    raw_omada = row.get("raw_omada") if isinstance(row.get("raw_omada"), dict) else {}
    status = row.get("deployment_status") or ap.get("local_status") or "ADOPTING"
    return {
        "id": str(row["id"]) if row.get("id") else ap.get("id"),
        "mac": row.get("mac") or ap.get("mac"),
        "normalized_mac": row.get("normalized_mac") or normalize_ap_mac(ap.get("mac")),
        "name": row.get("display_name") or ap.get("name") or ap_name_from_mac(ap.get("mac")),
        "display_name": row.get("display_name") or ap.get("name") or ap_name_from_mac(ap.get("mac")),
        "mac_bound_name": ap_name_from_mac(row.get("mac") or ap.get("mac")),
        "model": ap.get("model") or row.get("model"),
        "ip": ap.get("ip") or row.get("ip_address"),
        "firmware_version": ap.get("firmware_version") or row.get("firmware_version"),
        "serial_number": ap.get("serial_number") or row.get("serial_number"),
        "site_id": row.get("omada_site_id") or ap.get("site_id"),
        "site_name": row.get("site_name") or ap.get("site_name"),
        "status": "Adopt Failed" if status == "ADOPT_FAILED" else status.replace("_", " ").title(),
        "local_status": status,
        "status_code": ap.get("status_code"),
        "status_category": ap.get("status_category"),
        "client_count": ap.get("client_count") or 0,
        "client_count_2g": ap.get("client_count_2g") if ap.get("client_count_2g") is not None else raw_omada.get("clientNum2g"),
        "client_count_5g": ap.get("client_count_5g") if ap.get("client_count_5g") is not None else raw_omada.get("clientNum5g"),
        "client_count_5g2": ap.get("client_count_5g2") if ap.get("client_count_5g2") is not None else raw_omada.get("clientNum5g2"),
        "client_count_6g": ap.get("client_count_6g") if ap.get("client_count_6g") is not None else raw_omada.get("clientNum6g"),
        "cpu_util": ap.get("cpu_util") if ap.get("cpu_util") is not None else raw_omada.get("cpuUtil"),
        "mem_util": ap.get("mem_util") if ap.get("mem_util") is not None else raw_omada.get("memUtil"),
        "download": ap.get("download") if ap.get("download") is not None else raw_omada.get("download"),
        "upload": ap.get("upload") if ap.get("upload") is not None else raw_omada.get("upload"),
        "tx_rate": ap.get("tx_rate") if ap.get("tx_rate") is not None else raw_omada.get("txRate"),
        "rx_rate": ap.get("rx_rate") if ap.get("rx_rate") is not None else raw_omada.get("rxRate"),
        "radio_2g": ap.get("radio_2g") or raw_omada.get("wp2g") or raw_omada.get("radio2g"),
        "radio_5g": ap.get("radio_5g") or raw_omada.get("wp5g") or raw_omada.get("radio5g"),
        "radio_5g2": ap.get("radio_5g2") or raw_omada.get("wp5g2") or raw_omada.get("radio5g2"),
        "radio_6g": ap.get("radio_6g") or raw_omada.get("wp6g") or raw_omada.get("radio6g"),
        "uptime": ap.get("uptime"),
        "uptime_seconds": ap.get("uptime_seconds") if ap.get("uptime_seconds") is not None else raw_omada.get("uptimeLong"),
        "last_seen": ap.get("last_seen") or row.get("last_seen"),
        "last_error": row.get("last_error"),
        "configuration_status": row.get("configuration_status") or "PENDING",
        "configuration_error": row.get("configuration_error"),
        "configured_at": row.get("configured_at"),
        "map_latitude": row.get("map_latitude"),
        "map_longitude": row.get("map_longitude"),
        "map_source": row.get("map_source"),
        "mapped_at": row.get("mapped_at"),
        "mapped": row.get("map_latitude") is not None and row.get("map_longitude") is not None,
        "is_local": True,
    }


def upsert_ap_deployment(cur, site_id: str, site_name: Optional[str], mac: str, display_name: Optional[str], admin_id=None, status: str = "ADOPTING", last_error: Optional[str] = None, ap: dict = None):
    normalized = normalize_ap_mac(mac)
    if not normalized:
        return None
    display_name = (display_name or ap_name_from_mac(mac)).strip() or ap_name_from_mac(mac)
    ap = ap or {}
    cur.execute(
        """
        INSERT INTO ap_deployments(omada_site_id, site_name, mac, normalized_mac, display_name, model, ip_address,
                                   firmware_version, serial_number, deployment_status, configuration_status, last_error, last_omada_status,
                                   raw_omada, created_by_admin_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING', %s, %s, %s, %s)
        ON CONFLICT (omada_site_id, normalized_mac) DO UPDATE SET
            site_name = COALESCE(EXCLUDED.site_name, ap_deployments.site_name),
            mac = EXCLUDED.mac,
            display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), ap_deployments.display_name),
            model = COALESCE(EXCLUDED.model, ap_deployments.model),
            ip_address = COALESCE(EXCLUDED.ip_address, ap_deployments.ip_address),
            firmware_version = COALESCE(EXCLUDED.firmware_version, ap_deployments.firmware_version),
            serial_number = COALESCE(EXCLUDED.serial_number, ap_deployments.serial_number),
            deployment_status = EXCLUDED.deployment_status,
            configuration_status = CASE
                WHEN ap_deployments.deployment_status = 'DELETED' THEN 'PENDING'
                WHEN EXCLUDED.deployment_status IN ('ADOPTING', 'CONNECTED') AND ap_deployments.configuration_status = 'NOT_CONFIGURED' THEN 'PENDING'
                ELSE ap_deployments.configuration_status
            END,
            last_error = EXCLUDED.last_error,
            last_omada_status = EXCLUDED.last_omada_status,
            raw_omada = EXCLUDED.raw_omada,
            updated_at = now()
        RETURNING *
        """,
        (
            site_id,
            site_name,
            mac,
            normalized,
            display_name,
            ap.get("model"),
            ap.get("ip"),
            ap.get("firmware_version"),
            ap.get("serial_number"),
            status,
            last_error,
            ap.get("status"),
            Json(sanitize_summary(ap)) if ap else Json({}),
            admin_id,
        ),
    )
    return cur.fetchone()


def get_known_ap_identities(normalized_macs: list[str]) -> dict:
    normalized = [mac for mac in {normalize_ap_mac(mac) for mac in normalized_macs} if mac]
    if not normalized:
        return {}
    rows = fetch_all(
        """
        SELECT DISTINCT ON (normalized_mac)
            normalized_mac,
            mac,
            display_name,
            model,
            firmware_version,
            serial_number,
            omada_site_id,
            site_name,
            deployment_status,
            updated_at
        FROM ap_deployments
        WHERE normalized_mac = ANY(%s)
        ORDER BY normalized_mac, updated_at DESC
        """,
        (normalized,),
    )
    return {row["normalized_mac"]: row for row in rows}


def ensure_ap_deployment_configuration() -> dict:
    row = fetch_one("SELECT * FROM ap_deployment_configuration WHERE id = 1")
    if row:
        return row
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ap_deployment_configuration(id) VALUES (1) ON CONFLICT (id) DO NOTHING RETURNING *")
            row = cur.fetchone()
            if not row:
                cur.execute("SELECT * FROM ap_deployment_configuration WHERE id = 1")
                row = cur.fetchone()
    return row


def public_ap_deployment_configuration(row: dict) -> dict:
    return {
        "id": row["id"],
        "auto_apply_enabled": row["auto_apply_enabled"],
        "device_account_username": row.get("device_account_username") or "",
        "has_device_account_password": bool(row.get("device_account_password_encrypted")),
        "use_same_ssid": row["use_same_ssid"],
        "same_ssid_name": row["same_ssid_name"],
        "ssid_2g": row["ssid_2g"],
        "ssid_5g": row["ssid_5g"],
        "band_steering_enabled": row["band_steering_enabled"],
        "security_mode": row["security_mode"],
        "has_security_password": bool(row.get("security_password_encrypted")),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def validate_ssid_name(value: str, label: str) -> str:
    value = (value or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail=f"{label} is required.")
    if len(value) > 32:
        raise HTTPException(status_code=400, detail=f"{label} must be 32 characters or less.")
    return value


def log_ap_configuration(ap_row: Optional[dict], action: str, status: str, message: str, request_summary: dict = None, response_summary: dict = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ap_configuration_logs(ap_deployment_id, omada_site_id, site_name, ap_mac, action, status, message,
                                                  request_summary, response_summary)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    ap_row.get("id") if ap_row else None,
                    ap_row.get("omada_site_id") if ap_row else None,
                    ap_row.get("site_name") if ap_row else None,
                    ap_row.get("mac") if ap_row else None,
                    action,
                    status,
                    message,
                    Json(sanitize_summary(request_summary or {})),
                    Json(sanitize_summary(response_summary or {})),
                ),
            )


def build_deployment_config_payload(config: dict, vlan_tag: Optional[int]) -> dict:
    security_mode = (config.get("security_mode") or "OPEN").upper()
    return {
        "use_same_ssid": bool(config.get("use_same_ssid")),
        "same_ssid_name": config.get("same_ssid_name"),
        "ssid_2g": config.get("ssid_2g"),
        "ssid_5g": config.get("ssid_5g"),
        "band_steering_enabled": bool(config.get("band_steering_enabled")),
        "security_mode": security_mode,
        "security_password": decrypt_secret(config.get("security_password_encrypted")),
        "vlan_tag": int(vlan_tag) if vlan_tag is not None else None,
    }


def apply_configuration_to_ap(ap_row: dict, admin_id: Optional[str] = None, force: bool = False) -> dict:
    config = ensure_ap_deployment_configuration()
    if not config.get("auto_apply_enabled") and not force:
        return {"status": "SKIPPED", "message": "Automatic AP configuration is disabled."}
    if not ap_row.get("omada_site_id") or not ap_row.get("mac"):
        return {"status": "SKIPPED", "message": "AP is missing Omada site or MAC."}
    if ap_row.get("deployment_status") != "CONNECTED" and not force:
        return {"status": "SKIPPED", "message": "AP is not connected yet."}
    if ap_row.get("configuration_status") == "APPLIED" and not force:
        return {"status": "SKIPPED", "message": "AP configuration is already applied."}

    site = fetch_one("SELECT * FROM site_deployments WHERE omada_site_id = %s LIMIT 1", (ap_row["omada_site_id"],))
    vlan_tag = site.get("vlan_tag") if site else None
    request_summary = {
        "site_id": ap_row["omada_site_id"],
        "ap_mac": mask_mac(ap_row["mac"]),
        "vlan_tag": vlan_tag,
        "vlan_mode": "tagged" if vlan_tag is not None else "disabled",
        "ssid_mode": "same" if config["use_same_ssid"] else "separate",
        "security_mode": config["security_mode"],
        "device_account": bool(config.get("device_account_username") and config.get("device_account_password_encrypted")),
    }
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE ap_deployments SET configuration_status = 'APPLYING', configuration_error = NULL, updated_at = now() WHERE id = %s", (ap_row["id"],))
    try:
        _, client = omada_api_client_from_settings()
        results = {}
        device_username = (config.get("device_account_username") or "").strip()
        device_password = decrypt_secret(config.get("device_account_password_encrypted"))
        if device_username and device_password:
            results["device_account"] = client.configure_ap_device_account_if_supported(
                str(ap_row["omada_site_id"]),
                ap_row["mac"],
                device_username,
                device_password,
            )
        results["wlan"] = client.configure_site_wlan_defaults_if_supported(
            str(ap_row["omada_site_id"]),
            build_deployment_config_payload(config, vlan_tag),
        )
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ap_deployments SET configuration_status = 'APPLIED', configuration_error = NULL, configured_at = now(), updated_at = now() WHERE id = %s RETURNING *",
                    (ap_row["id"],),
                )
                updated = cur.fetchone()
        log_ap_configuration(updated or ap_row, "APPLY_DEPLOYMENT_CONFIGURATION", "SUCCESS", "AP deployment configuration applied.", request_summary, results)
        if admin_id:
            audit(admin_id, "apply_ap_deployment_configuration", "ap_deployment", str(ap_row["id"]), request_summary)
        return {"status": "SUCCESS", "message": "AP deployment configuration applied.", "ap": public_ap_deployment(updated or ap_row), "result": sanitize_summary(results)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ap_deployments SET configuration_status = 'FAILED', configuration_error = %s, updated_at = now() WHERE id = %s RETURNING *",
                    (str(exc), ap_row["id"]),
                )
                updated = cur.fetchone()
        log_ap_configuration(updated or ap_row, "APPLY_DEPLOYMENT_CONFIGURATION", "FAILED", str(exc), request_summary, response_summary)
        if admin_id:
            audit(admin_id, "apply_ap_deployment_configuration_failed", "ap_deployment", str(ap_row["id"]), {"error": str(exc), **request_summary})
        return {"status": "FAILED", "message": str(exc), "ap": public_ap_deployment(updated or ap_row), "details": sanitize_summary(response_summary)}


@app.get("/api/ap-deployments/sites")
def list_ap_deployment_sites(admin=Depends(current_admin)):
    sites = list_site_deployments(admin)
    omada_error = None
    client = None
    local_rows = fetch_all("SELECT * FROM ap_deployments WHERE deployment_status <> 'DELETED'")
    local_by_site = {}
    for row in local_rows:
        local_by_site.setdefault(str(row["omada_site_id"]), {})[row["normalized_mac"]] = row
    try:
        _, client = omada_api_client_from_settings()
    except Exception as exc:
        omada_error = str(exc)
    for site in sites:
        site["aps"] = []
        site["ap_error"] = site.get("ap_error")
        site["pending_ap_count"] = 0
        site["pending_ap_error"] = None
        omada_site_id = site.get("omada_site_id")
        site_id = str(omada_site_id) if omada_site_id else ""
        local_for_site = local_by_site.get(site_id, {})
        if not client or not omada_site_id:
            site["aps"] = [public_ap_deployment(row) for row in local_for_site.values()]
            continue
        merged = {}
        try:
            result = client.get_site_aps(site_id, site.get("site_name"))
            omada_aps = result.get("aps", [])
            with get_conn() as conn:
                with conn.cursor() as cur:
                    for ap in omada_aps:
                        normalized = normalize_ap_mac(ap.get("mac"))
                        if not normalized:
                            continue
                        local = local_for_site.get(normalized)
                        if not local and ap_is_pending_candidate(ap):
                            continue
                        status = ap_status_from_omada(ap)
                        display_name = local.get("display_name") if local else (ap.get("name") or ap_name_from_mac(ap.get("mac")))
                        error = "Omada reported adoption failed." if status == "ADOPT_FAILED" else None
                        row = upsert_ap_deployment(cur, site_id, site.get("site_name"), ap.get("mac"), display_name, admin["id"], status, error, ap)
                        local_for_site[normalized] = row
                        merged[normalized] = public_ap_deployment(row, ap)
        except Exception as exc:
            site["ap_error"] = str(exc)
        for normalized, row in local_for_site.items():
            if normalized not in merged:
                merged[normalized] = public_ap_deployment(row)
        site["aps"] = list(merged.values())
        for index, ap_public in enumerate(site["aps"]):
            if ap_public.get("local_status") == "CONNECTED" and ap_public.get("configuration_status") == "PENDING":
                row = fetch_one("SELECT * FROM ap_deployments WHERE id = %s", (ap_public["id"],))
                if row:
                    applied = apply_configuration_to_ap(row)
                    if applied.get("ap"):
                        site["aps"][index] = applied["ap"]
        site["ap_total_count"] = len(site["aps"])
        site["ap_connected_count"] = len([ap for ap in site["aps"] if ap.get("local_status") == "CONNECTED"])
        try:
            pending = client.detect_adoptable_aps(site_id)
            site["pending_ap_count"] = len([
                ap for ap in pending.get("aps", [])
                if normalize_ap_mac(ap.get("mac")) not in local_for_site
            ])
        except Exception as exc:
            site["pending_ap_error"] = str(exc)
    return {"sites": sites, "omada_error": omada_error}


def ap_map_error(ap: dict) -> Optional[str]:
    status = str(ap.get("local_status") or ap.get("status") or "").lower()
    if ap.get("last_error"):
        return ap.get("last_error")
    if ap.get("configuration_error"):
        return ap.get("configuration_error")
    if "failed" in status:
        return "AP reported a failed state."
    if "disconnect" in status:
        return "AP is disconnected."
    return None


def ping_ap_ip(ip_address: Optional[str]) -> Optional[bool]:
    ip_address = str(ip_address or "").strip()
    if not ip_address or not shutil.which("ping"):
        return None
    try:
        socket.inet_aton(ip_address)
    except OSError:
        return None
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return None


@app.get("/api/ap-deployments/map")
def ap_deployment_map(admin=Depends(current_admin)):
    data = list_ap_deployment_sites(admin)
    aps = []
    site_centers = []
    for site in data.get("sites", []):
        if site.get("latitude") is not None and site.get("longitude") is not None:
            site_centers.append({
                "site_id": site.get("omada_site_id"),
                "site_name": site.get("site_name"),
                "latitude": site.get("latitude"),
                "longitude": site.get("longitude"),
            })
        for ap in site.get("aps", []):
            if ap.get("local_status") == "DELETED":
                continue
            error = ap_map_error(ap)
            ping_status = ping_ap_ip(ap.get("ip"))
            if error is None and ping_status is False:
                error = "AP cannot be pinged from 3JCentralPisowifi."
            aps.append({
                **ap,
                "site_id": site.get("omada_site_id") or ap.get("site_id"),
                "site_name": site.get("site_name") or ap.get("site_name"),
                "site_latitude": site.get("latitude"),
                "site_longitude": site.get("longitude"),
                "vlan_tag": site.get("vlan_tag"),
                "map_health": "ERROR" if error else ("HAS_CLIENTS" if int(ap.get("client_count") or 0) > 0 else "NO_CLIENTS"),
                "map_error": error,
                "map_ping_status": "REACHABLE" if ping_status is True else ("FAILED" if ping_status is False else "UNKNOWN"),
            })
    for ap in aps:
        if ap.get("map_error"):
            ap["map_health"] = "ERROR"
        else:
            ap["map_health"] = "HAS_CLIENTS" if int(ap.get("client_count") or 0) > 0 else "NO_CLIENTS"
    mapped = [ap for ap in aps if ap.get("mapped")]
    unmapped = [ap for ap in aps if not ap.get("mapped")]
    return {
        "aps": aps,
        "mapped": mapped,
        "unmapped": unmapped,
        "site_centers": site_centers,
        "summary": {
            "total": len(aps),
            "mapped": len(mapped),
            "unmapped": len(unmapped),
            "with_clients": len([ap for ap in aps if int(ap.get("client_count") or 0) > 0]),
            "errors": len([ap for ap in aps if ap.get("map_error")]),
        },
        "omada_error": data.get("omada_error"),
    }


def ap_client_map_ssids() -> dict:
    config = ensure_ap_deployment_configuration()
    if config.get("use_same_ssid"):
        ssid = config.get("same_ssid_name") or "3J-FreeWiFi"
        return {
            "use_same_ssid": True,
            "ssid_2g": ssid,
            "ssid_5g": ssid,
        }
    return {
        "use_same_ssid": False,
        "ssid_2g": config.get("ssid_2g") or "3J-FreeWiFi-2G",
        "ssid_5g": config.get("ssid_5g") or "3J-FreeWiFi-5G",
    }


def public_ap_map_client(client: dict, source: str) -> dict:
    client_mac = client.get("client_mac")
    return {
        "source": source,
        "client_mac": normalize_mac(client_mac),
        "client_mac_masked": mask_mac(client_mac),
        "client_ip": client.get("client_ip"),
        "hostname": client.get("hostname") or client.get("username") or "Unknown device",
        "device_type": client.get("device_type"),
        "ssid": client.get("ssid"),
        "active": bool(client.get("active")),
        "status": "ACTIVE" if client.get("active") else "INACTIVE",
        "last_seen": client.get("last_seen"),
        "connected_since": client.get("connected_since"),
        "uptime_seconds": client.get("uptime_seconds"),
        "radio_id": client.get("radio_id"),
        "band": client.get("band"),
        "channel": client.get("channel"),
        "rssi": client.get("rssi"),
        "snr": client.get("snr"),
        "rx_rate": client.get("rx_rate"),
        "tx_rate": client.get("tx_rate"),
        "activity": client.get("activity"),
        "traffic_down": client.get("traffic_down"),
        "traffic_up": client.get("traffic_up"),
        "vid": client.get("vid"),
        "raw_status": client.get("raw_status"),
    }


def attach_client_to_ap(clients_by_ap: dict, ap_key: Optional[str], client: dict, source: str):
    if not ap_key:
        return
    row = public_ap_map_client(client, source)
    key = normalize_mac(row.get("client_mac")) or row.get("client_ip") or f"{source}:{len(clients_by_ap.get(ap_key, []))}"
    bucket = clients_by_ap.setdefault(ap_key, {})
    existing = bucket.get(key, {})
    bucket[key] = {**existing, **{k: v for k, v in row.items() if v not in (None, "")}}


@app.get("/api/ap-client-map")
def ap_client_map(admin=Depends(current_admin)):
    data = ap_deployment_map(admin)
    ssids = ap_client_map_ssids()
    aps = data.get("aps", [])
    clients_by_ap: dict[str, dict] = {}
    ap_lookup = {}
    ap_name_lookup = {}
    for ap in aps:
        ap_key = normalize_ap_mac(ap.get("mac"))
        if not ap_key:
            continue
        ap_lookup[ap_key] = ap
        for value in [ap.get("display_name"), ap.get("name"), ap.get("mac_bound_name"), ap.get("mac"), ap.get("ip")]:
            if value:
                ap_name_lookup[str(value).strip().lower()] = ap_key

    omada_client_errors = []
    unique_sites = {}
    for ap in aps:
        site_id = ap.get("site_id")
        if site_id:
            unique_sites[str(site_id)] = ap.get("site_name")

    try:
        _, client = omada_api_client_from_settings()
        for site_id, site_name in unique_sites.items():
            try:
                result = client.get_clients_if_supported(site_id, site_name)
                for row in result.get("clients", []):
                    ap_key = normalize_ap_mac(row.get("ap_mac"))
                    if not ap_key and row.get("ap_name"):
                        ap_key = ap_name_lookup.get(str(row["ap_name"]).strip().lower())
                    attach_client_to_ap(clients_by_ap, ap_key, row, "OMADA")
            except Exception as exc:
                omada_client_errors.append({"site_id": site_id, "site_name": site_name, "error": str(exc)})
    except Exception as exc:
        omada_client_errors.append({"error": str(exc)})

    try:
        local_devices = connected_devices(include_test=True, admin=admin)
        for row in local_devices.get("active", []) + local_devices.get("inactive", []):
            ap_key = normalize_ap_mac(row.get("ap_mac"))
            if not ap_key and row.get("ap_name"):
                ap_key = ap_name_lookup.get(str(row["ap_name"]).strip().lower())
            if not ap_key and row.get("ap_ip"):
                ap_key = ap_name_lookup.get(str(row["ap_ip"]).strip().lower())
            attach_client_to_ap(clients_by_ap, ap_key, row, row.get("source") or "LOCAL")
    except Exception as exc:
        omada_client_errors.append({"source": "LOCAL_FALLBACK", "error": str(exc)})

    enriched_aps = []
    for ap in aps:
        ap_key = normalize_ap_mac(ap.get("mac"))
        client_rows = list((clients_by_ap.get(ap_key) or {}).values())
        active_clients = [row for row in client_rows if row.get("active")]
        ap_client_count = int(ap.get("client_count") or 0)
        enriched_aps.append({
            **ap,
            **ssids,
            "clients": sorted(client_rows, key=lambda row: (not row.get("active"), str(row.get("hostname") or row.get("client_mac") or ""))),
            "client_count": max(ap_client_count, len(active_clients)),
            "active_client_count": len(active_clients),
            "inactive_client_count": len(client_rows) - len(active_clients),
            "traffic": {
                "download": ap.get("download") or 0,
                "upload": ap.get("upload") or 0,
                "tx_rate": ap.get("tx_rate") or 0,
                "rx_rate": ap.get("rx_rate") or 0,
            },
            "radio_stats": {
                "2g": ap.get("radio_2g") or {},
                "5g": ap.get("radio_5g") or {},
                "5g2": ap.get("radio_5g2") or {},
                "6g": ap.get("radio_6g") or {},
            },
        })

    mapped = [ap for ap in enriched_aps if ap.get("mapped")]
    unmapped = [ap for ap in enriched_aps if not ap.get("mapped")]
    total_clients = sum(int(ap.get("active_client_count") or 0) for ap in enriched_aps)
    return {
        **data,
        "aps": enriched_aps,
        "mapped": mapped,
        "unmapped": unmapped,
        "ssid_configuration": ssids,
        "summary": {
            **(data.get("summary") or {}),
            "total_clients": total_clients,
            "with_clients": len([ap for ap in enriched_aps if int(ap.get("active_client_count") or ap.get("client_count") or 0) > 0]),
            "omada_client_error_count": len(omada_client_errors),
        },
        "omada_client_errors": omada_client_errors,
    }


@app.patch("/api/ap-deployments/{ap_id}/map")
def update_ap_deployment_map(ap_id: str, payload: ApMapUpdate, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ap_deployments
                SET map_latitude = %s,
                    map_longitude = %s,
                    map_source = 'MANUAL_MAP',
                    mapped_at = now(),
                    map_updated_by_admin_id = %s,
                    updated_at = now()
                WHERE id::text = %s AND deployment_status <> 'DELETED'
                RETURNING *
                """,
                (payload.latitude, payload.longitude, admin["id"], ap_id),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="AP deployment not found")
    audit(admin["id"], "map_ap_deployment", "ap_deployment", ap_id, {"mac": mask_mac(row["mac"]), "latitude": payload.latitude, "longitude": payload.longitude})
    return public_ap_deployment(row)


@app.get("/api/ap-deployments/detected")
def detect_ap_deployments(site_id: Optional[str] = None, admin=Depends(current_admin)):
    try:
        _, client = omada_api_client_from_settings()
        result = client.detect_adoptable_aps(site_id)
        detected_aps = result.get("aps", [])
        known_identities = get_known_ap_identities([normalize_ap_mac(ap.get("mac")) for ap in detected_aps])
        existing = set()
        if site_id:
            existing = {
                row["normalized_mac"]
                for row in fetch_all(
                    "SELECT normalized_mac FROM ap_deployments WHERE omada_site_id = %s AND deployment_status <> 'DELETED'",
                    (site_id,),
                )
            }
        aps = []
        for ap in detected_aps:
            normalized = normalize_ap_mac(ap.get("mac"))
            if normalized in existing:
                continue
            identity = known_identities.get(normalized) or {}
            display_name = identity.get("display_name") or ap.get("name") or ap_name_from_mac(ap.get("mac"))
            aps.append({
                **ap,
                "name": display_name,
                "display_name": display_name,
                "known_ap": normalized in known_identities,
                "last_known_site_name": identity.get("site_name"),
                "last_known_status": identity.get("deployment_status"),
            })
        return {
            "status": "SUCCESS",
            "aps": aps,
            "message": "Omada AP auto-detection completed.",
            "details": sanitize_summary(result.get("response_summary")),
        }
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        return {
            "status": "FAILED",
            "aps": [],
            "message": "Omada AP auto-detection failed. You can still adopt APs directly in Omada Controller.",
            "error": str(exc),
            "details": sanitize_summary(response_summary),
        }


@app.post("/api/ap-deployments/adopt")
def adopt_ap_deployments(payload: ApAdoptRequest, admin=Depends(current_admin)):
    site_id = payload.site_id.strip()
    ap_macs = [mac.strip() for mac in payload.ap_macs if mac and mac.strip()]
    if not site_id:
        raise HTTPException(status_code=400, detail="Site ID is required")
    if not ap_macs:
        raise HTTPException(status_code=400, detail="Select at least one AP to add")
    site_name = None
    local_site = fetch_one("SELECT site_name FROM site_deployments WHERE omada_site_id = %s LIMIT 1", (site_id,))
    if local_site:
        site_name = local_site["site_name"]
    failed_error = None
    try:
        _, client = omada_api_client_from_settings()
        result = client.adopt_aps_if_supported(site_id, ap_macs, payload.username, payload.password)
        status = "SUCCESS"
        message = "AP adoption was submitted to Omada."
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        result = {"response_summary": response_summary}
        status = "FAILED"
        message = f"Omada AP adoption failed: {exc}"
        failed_error = str(exc)
        audit(admin["id"], "adopt_omada_aps_failed", "omada_site", site_id, {"ap_count": len(ap_macs), "ap_macs": [mask_mac(mac) for mac in ap_macs], "error": str(exc), "response": sanitize_summary(response_summary)})
    known_identities = get_known_ap_identities([normalize_ap_mac(mac) for mac in ap_macs])
    with get_conn() as conn:
        with conn.cursor() as cur:
            for mac in ap_macs:
                normalized = normalize_ap_mac(mac)
                identity = known_identities.get(normalized) or {}
                name = payload.ap_names.get(mac) or payload.ap_names.get(normalized) or identity.get("display_name") or ap_name_from_mac(mac)
                upsert_ap_deployment(cur, site_id, site_name, mac, name, admin["id"], "ADOPT_FAILED" if failed_error else "ADOPTING", failed_error)
    if status == "SUCCESS":
        audit(admin["id"], "adopt_omada_aps", "omada_site", site_id, {"ap_count": len(ap_macs), "ap_macs": [mask_mac(mac) for mac in ap_macs]})
    return {"status": status, "message": message, "result": sanitize_summary(result)}


@app.patch("/api/ap-deployments/{ap_id}")
def update_ap_deployment(ap_id: str, payload: ApDeploymentUpdate, admin=Depends(current_admin)):
    display_name = payload.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="AP name is required")
    if len(display_name) > 80:
        raise HTTPException(status_code=400, detail="AP name must be 80 characters or less")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ap_deployments
                SET display_name = %s, updated_at = now()
                WHERE id::text = %s AND deployment_status <> 'DELETED'
                RETURNING *
                """,
                (display_name, ap_id),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="AP deployment not found")
    audit(admin["id"], "update_ap_deployment_name", "ap_deployment", ap_id, {"mac": mask_mac(row["mac"]), "display_name": display_name})
    return public_ap_deployment(row)


@app.post("/api/ap-deployments/{ap_id}/retry")
def retry_ap_deployment(ap_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM ap_deployments WHERE id::text = %s AND deployment_status <> 'DELETED'", (ap_id,))
    if not row:
        raise HTTPException(status_code=404, detail="AP deployment not found")
    try:
        _, client = omada_api_client_from_settings()
        result = client.adopt_aps_if_supported(row["omada_site_id"], [row["mac"]])
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ap_deployments SET deployment_status = 'ADOPTING', last_error = NULL, updated_at = now() WHERE id = %s RETURNING *",
                    (row["id"],),
                )
                updated = cur.fetchone()
        audit(admin["id"], "retry_omada_ap_adoption", "ap_deployment", ap_id, {"mac": mask_mac(row["mac"])})
        return {"status": "SUCCESS", "message": "AP adoption retry submitted.", "ap": public_ap_deployment(updated), "result": sanitize_summary(result)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ap_deployments SET deployment_status = 'ADOPT_FAILED', last_error = %s, updated_at = now() WHERE id = %s RETURNING *",
                    (str(exc), row["id"]),
                )
                updated = cur.fetchone()
        audit(admin["id"], "retry_omada_ap_adoption_failed", "ap_deployment", ap_id, {"mac": mask_mac(row["mac"]), "error": str(exc), "response": sanitize_summary(response_summary)})
        return {"status": "FAILED", "message": f"AP adoption retry failed: {exc}", "ap": public_ap_deployment(updated), "details": sanitize_summary(response_summary)}


@app.delete("/api/ap-deployments/{ap_id}")
def delete_ap_deployment(ap_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM ap_deployments WHERE id::text = %s AND deployment_status <> 'DELETED'", (ap_id,))
    if not row:
        raise HTTPException(status_code=404, detail="AP deployment not found")
    omada_result = None
    omada_error = None
    try:
        _, client = omada_api_client_from_settings()
        omada_result = client.delete_ap_if_supported(row["omada_site_id"], row["mac"])
    except Exception as exc:
        omada_error = str(exc)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE ap_deployments SET deployment_status = 'DELETED', last_error = %s, updated_at = now() WHERE id = %s", (omada_error, row["id"]))
    audit(admin["id"], "delete_ap_deployment", "ap_deployment", ap_id, {"mac": mask_mac(row["mac"]), "omada_deleted": bool(omada_result), "omada_error": omada_error})
    return {"status": "ok", "omada_deleted": bool(omada_result), "omada_error": omada_error, "result": sanitize_summary(omada_result or {})}


@app.get("/api/site-deployments/options")
def site_deployment_options(admin=Depends(current_admin)):
    settings = system_settings_payload()
    fallback = ["Airport", "Campus", "Dormitory", "Factory", "Home", "Hospital", "Hotel", "Office", "Restaurant", "Shopping Mall"]
    scenarios = fallback
    error = None
    try:
        _, client = omada_api_client_from_settings()
        data = client.get_application_scenarios()
        if data.get("scenarios"):
            scenarios = data["scenarios"]
    except Exception as exc:
        error = str(exc)
    return {
        "general": settings.get("general", {}),
        "application_scenarios": scenarios,
        "omada_error": error,
    }


@app.get("/api/site-deployments/configuration")
def get_site_deployment_configuration(admin=Depends(current_admin)):
    config = ensure_ap_deployment_configuration()
    sites = [
        {
            "id": str(site["id"]),
            "site_name": site.get("site_name"),
            "omada_site_id": site.get("omada_site_id"),
            "vlan_tag": site.get("vlan_tag"),
            "is_omada_detected": site.get("is_omada_detected", False),
        }
        for site in list_site_deployments(admin)
    ]
    logs = fetch_all(
        """
        SELECT id, ap_deployment_id, omada_site_id, site_name, ap_mac, action, status, message, created_at
        FROM ap_configuration_logs
        ORDER BY created_at DESC
        LIMIT 20
        """
    )
    mikrotik_vlans = fetch_all(
        """
        SELECT id, router_name, host, hotspot_vlan_id, hotspot_vlan_parent_interface, hotspot_vlan_interface_name
        FROM mikrotik_routers
        WHERE hotspot_vlan_id IS NOT NULL
        ORDER BY router_name, host
        """
    )
    return {
        "configuration": public_ap_deployment_configuration(config),
        "sites": sites,
        "mikrotik_vlans": [
            {
                "router_id": str(row["id"]),
                "router_name": row.get("router_name"),
                "host": row.get("host"),
                "vlan_id": row.get("hotspot_vlan_id"),
                "parent_interface": row.get("hotspot_vlan_parent_interface"),
                "vlan_interface_name": row.get("hotspot_vlan_interface_name"),
            }
            for row in mikrotik_vlans
        ],
        "logs": [{**row, "ap_mac_masked": mask_mac(row.get("ap_mac"))} for row in logs],
    }


@app.put("/api/site-deployments/configuration")
def update_site_deployment_configuration(payload: ApDeploymentConfigurationUpdate, admin=Depends(current_admin)):
    config = ensure_ap_deployment_configuration()
    security_mode = (payload.security_mode or "OPEN").upper()
    if security_mode not in {"OPEN", "WPA2_PSK", "WPA_WPA2_PSK"}:
        raise HTTPException(status_code=400, detail="Unsupported security mode.")
    same_ssid_name = validate_ssid_name(payload.same_ssid_name, "Same SSID name")
    ssid_2g = validate_ssid_name(payload.ssid_2g, "2.4GHz SSID name")
    ssid_5g = validate_ssid_name(payload.ssid_5g, "5GHz SSID name")
    device_username = (payload.device_account_username or "").strip() or None
    if device_username and not re.match(r"^[!-~]{4,64}$", device_username):
        raise HTTPException(status_code=400, detail="Device account username must be 4-64 visible ASCII characters.")
    existing_device_password = decrypt_secret(config.get("device_account_password_encrypted"))
    existing_security_password = decrypt_secret(config.get("security_password_encrypted"))
    device_password = payload.device_account_password if payload.device_account_password is not None and payload.device_account_password != "" else existing_device_password
    security_password = payload.security_password if payload.security_password is not None and payload.security_password != "" else existing_security_password
    if device_username and not device_password:
        raise HTTPException(status_code=400, detail="Device account password is required when a username is set.")
    if device_password and not device_username:
        raise HTTPException(status_code=400, detail="Device account username is required when a password is set.")
    if device_password and (
        len(device_password) < 8
        or len(device_password) > 64
        or not re.search(r"[a-z]", device_password)
        or not re.search(r"[A-Z]", device_password)
        or not re.search(r"\d", device_password)
        or not re.search(r"[^A-Za-z0-9]", device_password)
    ):
        raise HTTPException(status_code=400, detail="Device account password must be 8-64 characters and include uppercase, lowercase, number, and symbol.")
    if security_mode != "OPEN" and not security_password:
        raise HTTPException(status_code=400, detail="WiFi password is required unless security mode is Open.")
    if security_password and (len(security_password) < 8 or len(security_password) > 64):
        raise HTTPException(status_code=400, detail="WiFi password must be 8-64 characters.")

    sites = list_site_deployments(admin)
    site_ids = {str(site["id"]) for site in sites}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ap_deployment_configuration
                SET auto_apply_enabled = %s,
                    device_account_username = %s,
                    device_account_password_encrypted = %s,
                    use_same_ssid = %s,
                    same_ssid_name = %s,
                    ssid_2g = %s,
                    ssid_5g = %s,
                    band_steering_enabled = %s,
                    security_mode = %s,
                    security_password_encrypted = %s,
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE id = 1
                RETURNING *
                """,
                (
                    payload.auto_apply_enabled,
                    device_username,
                    encrypt_secret(device_password),
                    payload.use_same_ssid,
                    same_ssid_name,
                    ssid_2g,
                    ssid_5g,
                    payload.band_steering_enabled,
                    security_mode,
                    encrypt_secret(security_password) if security_mode != "OPEN" else None,
                    admin["id"],
                ),
            )
            updated_config = cur.fetchone()
            for site in sites:
                key = str(site["id"])
                vlan_value = payload.site_vlans.get(key)
                normalized_vlan = None
                if vlan_value not in (None, ""):
                    normalized_vlan = int(vlan_value)
                    if normalized_vlan < 1 or normalized_vlan > 4094:
                        raise HTTPException(status_code=400, detail=f"VLAN tag for {site['site_name']} must be between 1 and 4094.")
                if key.startswith("omada-") or site.get("is_omada_detected"):
                    cur.execute(
                        "SELECT * FROM site_deployments WHERE omada_site_id = %s OR lower(site_name) = lower(%s) LIMIT 1",
                        (site.get("omada_site_id"), site.get("site_name")),
                    )
                    existing_site = cur.fetchone()
                    if existing_site:
                        cur.execute("UPDATE site_deployments SET vlan_tag = %s, updated_at = now() WHERE id = %s", (normalized_vlan, existing_site["id"]))
                    else:
                        cur.execute(
                            """
                            INSERT INTO site_deployments(site_name, omada_site_id, deployment_status, notes, created_by_admin_id, application_scenario,
                                                         vlan_tag)
                            VALUES (%s, %s, 'ACTIVE', %s, %s, %s, %s)
                            """,
                            (
                                site.get("site_name") or "Unnamed Omada Site",
                                site.get("omada_site_id"),
                                "Linked automatically when AP deployment VLAN was configured.",
                                admin["id"],
                                site.get("application_scenario"),
                                normalized_vlan,
                            ),
                        )
                else:
                    cur.execute("UPDATE site_deployments SET vlan_tag = %s, updated_at = now() WHERE id = %s", (normalized_vlan, site["id"]))
            unknown = set(payload.site_vlans.keys()) - site_ids
            if unknown:
                raise HTTPException(status_code=400, detail="One or more VLAN entries refer to an unknown site.")
            cur.execute(
                """
                UPDATE ap_deployments
                SET configuration_status = 'PENDING',
                    configuration_error = NULL,
                    configured_at = NULL,
                    updated_at = now()
                WHERE deployment_status = 'CONNECTED'
                """
            )
    audit(admin["id"], "save_ap_site_configuration", "ap_deployment_configuration", "1", {
        "auto_apply_enabled": payload.auto_apply_enabled,
        "ssid_mode": "same" if payload.use_same_ssid else "separate",
        "security_mode": security_mode,
        "vlan_tagged_site_count": len([site_id for site_id, value in payload.site_vlans.items() if value not in (None, "")]),
    })
    return {
        "status": "SUCCESS",
        "message": "Sites configuration saved. Connected APs were marked pending for configuration.",
        "configuration": public_ap_deployment_configuration(updated_config),
        "missing_vlan_sites": [],
    }


@app.post("/api/site-deployments/configuration/apply")
def apply_site_deployment_configuration(payload: ApDeploymentConfigurationApplyRequest = ApDeploymentConfigurationApplyRequest(), admin=Depends(current_admin)):
    params = []
    where = ["deployment_status = 'CONNECTED'"]
    if payload.ap_id:
        where.append("id::text = %s")
        params.append(payload.ap_id)
    if payload.site_id:
        where.append("omada_site_id = %s")
        params.append(payload.site_id)
    rows = fetch_all(f"SELECT * FROM ap_deployments WHERE {' AND '.join(where)} ORDER BY updated_at DESC", tuple(params))
    results = [apply_configuration_to_ap(row, admin["id"], force=True) for row in rows]
    success_count = len([item for item in results if item.get("status") == "SUCCESS"])
    failed_count = len([item for item in results if item.get("status") == "FAILED"])
    skipped_count = len([item for item in results if item.get("status") == "SKIPPED"])
    return {
        "status": "SUCCESS" if failed_count == 0 else "FAILED",
        "message": f"Configuration apply completed: {success_count} succeeded, {failed_count} failed, {skipped_count} skipped.",
        "summary": {"success": success_count, "failed": failed_count, "skipped": skipped_count},
        "results": sanitize_summary(results),
    }


@app.get("/api/locations")
def list_locations(admin=Depends(current_admin)):
    return fetch_all(
        """
        SELECT l.*, a.username AS created_by_username
        FROM locations l
        LEFT JOIN admins a ON a.id = l.created_by_admin_id
        ORDER BY l.created_at DESC
        """
    )


@app.get("/api/locations/search")
def search_locations(q: str, admin=Depends(current_admin)):
    query = (q or "").strip()
    if len(query) < 3:
        raise HTTPException(status_code=400, detail="Search text must be at least 3 characters")
    try:
        response = requests.get(
            os.getenv("GEOCODER_SEARCH_URL", "https://nominatim.openstreetmap.org/search"),
            params={"q": f"{query}, Philippines", "format": "json", "addressdetails": 1, "limit": 5},
            headers={"User-Agent": "3JCentralPisowifi/0.1 location-management"},
            timeout=10,
        )
        response.raise_for_status()
        results = response.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Address search failed: {exc}") from exc
    suggestions = []
    for item in results:
        address = item.get("address") or {}
        municipality = (
            address.get("city")
            or address.get("town")
            or address.get("municipality")
            or address.get("county")
        )
        barangay = (
            address.get("village")
            or address.get("suburb")
            or address.get("neighbourhood")
            or address.get("quarter")
            or address.get("hamlet")
        )
        suggestions.append({
            "display_name": item.get("display_name"),
            "address": item.get("display_name"),
            "municipality": municipality,
            "barangay": barangay,
            "province": address.get("state") or address.get("province"),
            "region": address.get("region"),
            "latitude": float(item["lat"]) if item.get("lat") else None,
            "longitude": float(item["lon"]) if item.get("lon") else None,
            "geocode_source": "NOMINATIM",
            "raw_geocode": sanitize_summary(item),
        })
    return {"results": suggestions}


@app.post("/api/locations")
def create_location(payload: LocationCreate, admin=Depends(current_admin)):
    address = payload.address.strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO locations(location_name, address, municipality, barangay, province, region, latitude, longitude,
                                      geocode_source, raw_geocode, notes, created_by_admin_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    payload.location_name,
                    address,
                    payload.municipality,
                    payload.barangay,
                    payload.province,
                    payload.region,
                    payload.latitude,
                    payload.longitude,
                    payload.geocode_source,
                    Json(sanitize_summary(payload.raw_geocode or {})),
                    payload.notes,
                    admin["id"],
                ),
            )
            row = cur.fetchone()
    audit(admin["id"], "create_location", "location", str(row["id"]), {"address": row["address"], "municipality": row["municipality"], "barangay": row["barangay"]})
    return row


@app.delete("/api/locations/{location_id}")
def delete_location(location_id: str, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, address FROM locations WHERE id = %s", (location_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Location not found")
            cur.execute("DELETE FROM locations WHERE id = %s", (location_id,))
    audit(admin["id"], "delete_location", "location", location_id, {"address": row["address"]})
    return {"status": "ok"}


@app.post("/api/site-deployments")
def create_site_deployment(payload: SiteDeploymentCreate, admin=Depends(current_admin)):
    status = "ACTIVE"
    site_name = payload.site_name.strip()
    if not site_name:
        raise HTTPException(status_code=400, detail="Site name is required")
    general = system_settings_payload().get("general", {})
    application_scenario = (payload.application_scenario or "Office").strip() or "Office"
    country_region = (payload.country_region or general.get("country_region") or "Philippines").strip() or "Philippines"
    time_zone = (payload.time_zone or general.get("time_zone") or "Asia/Manila").strip() or "Asia/Manila"
    device_account_username = (payload.device_account_username or "").strip()
    device_account_password = payload.device_account_password or ""
    if not device_account_username or not device_account_password:
        raise HTTPException(status_code=400, detail="Omada Device Account username and password are required to create a site.")
    if not re.match(r"^[!-~]{4,64}$", device_account_username):
        raise HTTPException(status_code=400, detail="Omada Device Account username must be 4-64 visible ASCII characters.")
    if (
        len(device_account_password) < 8
        or len(device_account_password) > 64
        or not re.search(r"[a-z]", device_account_password)
        or not re.search(r"[A-Z]", device_account_password)
        or not re.search(r"\d", device_account_password)
        or not re.search(r"[^A-Za-z0-9]", device_account_password)
    ):
        raise HTTPException(status_code=400, detail="Omada Device Account password must be 8-64 characters and include uppercase, lowercase, number, and symbol.")
    if not re.match(r"^[A-Za-z0-9!@#$%*]+$", device_account_password):
        raise HTTPException(status_code=400, detail="Omada Device Account password can use letters, numbers, and these symbols: ! @ # $ % *")
    omada_site_id = None
    omada_result = None
    location = None
    if payload.location_id:
        location = fetch_one("SELECT * FROM locations WHERE id = %s", (payload.location_id,))
        if not location:
            raise HTTPException(status_code=404, detail="Location not found")
    try:
        _, client = omada_api_client_from_settings()
        omada_result = client.create_site_if_supported(
            site_name,
            application_scenario,
            country_region,
            time_zone,
            device_account_username,
            device_account_password,
        )
        omada_site_id = omada_result.get("site_id")
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        audit(admin["id"], "create_site_deployment_omada_failed", "site_deployment", site_name, {"error": str(exc), "response": sanitize_summary(response_summary)})
        raise HTTPException(status_code=400, detail=f"Omada site creation failed: {exc}") from exc
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO site_deployments(site_name, location, address, contact_name, contact_phone, omada_site_id,
                                                 deployment_status, notes, created_by_admin_id, application_scenario,
                                                 country_region, time_zone)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        payload.site_name.strip(),
                        payload.location or (location["location_name"] if location else None),
                        payload.address or (location["address"] if location else None),
                        payload.contact_name,
                        payload.contact_phone,
                        omada_site_id,
                        status,
                        payload.notes,
                        admin["id"],
                        application_scenario,
                        country_region,
                        time_zone,
                    ),
                )
                row = cur.fetchone()
                cur.execute(
                    """
                    UPDATE site_deployments
                    SET location_id = %s,
                        municipality = %s,
                        barangay = %s,
                        latitude = %s,
                        longitude = %s,
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        payload.location_id,
                        payload.municipality or (location["municipality"] if location else None),
                        payload.barangay or (location["barangay"] if location else None),
                        payload.latitude if payload.latitude is not None else (location["latitude"] if location else None),
                        payload.longitude if payload.longitude is not None else (location["longitude"] if location else None),
                        row["id"],
                    ),
                )
                row = cur.fetchone()
                clear_site_deployment_tombstone(cur, omada_site_id, row["site_name"])
            except Exception as exc:
                if "idx_site_deployments_site_name_lower" in str(exc):
                    raise HTTPException(status_code=409, detail="Site name already exists") from exc
                raise
    audit(admin["id"], "create_site_deployment", "site_deployment", str(row["id"]), {"site_name": row["site_name"], "omada_site_id": omada_site_id, "omada_created": bool(omada_result and omada_result.get("created"))})
    return {**row, "omada_created": bool(omada_result and omada_result.get("created")), "omada_result": sanitize_summary(omada_result or {})}


@app.patch("/api/site-deployments/{deployment_id}")
def update_site_deployment(deployment_id: str, payload: SiteDeploymentUpdate, admin=Depends(current_admin)):
    location = None
    if payload.location_id:
        location = fetch_one("SELECT * FROM locations WHERE id = %s", (payload.location_id,))
        if not location:
            raise HTTPException(status_code=404, detail="Location not found")
    omada_site = None
    local_row = fetch_one("SELECT * FROM site_deployments WHERE id::text = %s", (deployment_id,))
    if not local_row and deployment_id.startswith("omada-"):
        omada_site_id = deployment_id.removeprefix("omada-")
        local_row = fetch_one("SELECT * FROM site_deployments WHERE omada_site_id = %s", (omada_site_id,))
        if not local_row:
            try:
                _, client = omada_api_client_from_settings()
                sites = client.get_sites().get("sites", [])
                omada_site = next((site for site in sites if str(site.get("site_id")) == omada_site_id), None)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Could not load Omada site details: {exc}") from exc
            if not omada_site:
                raise HTTPException(status_code=404, detail="Site deployment not found")
    elif not local_row:
        raise HTTPException(status_code=404, detail="Site deployment not found")

    with get_conn() as conn:
        with conn.cursor() as cur:
            if local_row:
                cur.execute(
                    """
                    UPDATE site_deployments
                    SET location_id = %s,
                        location = %s,
                        address = %s,
                        municipality = %s,
                        barangay = %s,
                        latitude = %s,
                        longitude = %s,
                        contact_name = %s,
                        contact_phone = %s,
                        notes = %s,
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        payload.location_id,
                        location["location_name"] if location else None,
                        location["address"] if location else None,
                        location["municipality"] if location else None,
                        location["barangay"] if location else None,
                        location["latitude"] if location else None,
                        location["longitude"] if location else None,
                        payload.contact_name,
                        payload.contact_phone,
                        payload.notes,
                        local_row["id"],
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO site_deployments(site_name, location, address, contact_name, contact_phone, omada_site_id,
                                                 deployment_status, notes, created_by_admin_id, application_scenario,
                                                 location_id, municipality, barangay, latitude, longitude)
                    VALUES (%s, %s, %s, %s, %s, %s, 'ACTIVE', %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        omada_site.get("site_name") or "Unnamed Omada Site",
                        location["location_name"] if location else None,
                        location["address"] if location else None,
                        payload.contact_name,
                        payload.contact_phone,
                        omada_site.get("site_id"),
                        payload.notes,
                        admin["id"],
                        omada_site.get("application_scenario"),
                        payload.location_id,
                        location["municipality"] if location else None,
                        location["barangay"] if location else None,
                        location["latitude"] if location else None,
                        location["longitude"] if location else None,
                    ),
                )
            row = cur.fetchone()
            clear_site_deployment_tombstone(cur, row.get("omada_site_id"), row.get("site_name"))
    audit(admin["id"], "update_site_deployment", "site_deployment", str(row["id"]), {"site_name": row["site_name"], "omada_site_id": row.get("omada_site_id")})
    return row


@app.delete("/api/site-deployments/{deployment_id}")
def delete_site_deployment(deployment_id: str, delete_omada: bool = True, site_name: Optional[str] = None, admin=Depends(current_admin)):
    local_row = fetch_one("SELECT * FROM site_deployments WHERE id::text = %s", (deployment_id,))
    omada_site_id = local_row.get("omada_site_id") if local_row else None
    if not local_row and deployment_id.startswith("omada-"):
        omada_site_id = deployment_id.removeprefix("omada-")
        local_row = fetch_one("SELECT * FROM site_deployments WHERE omada_site_id = %s", (omada_site_id,))
    if not local_row and not omada_site_id:
        raise HTTPException(status_code=404, detail="Site deployment not found")

    site_name = (site_name or (local_row.get("site_name") if local_row else None) or "").strip() or None
    omada_deleted = False
    omada_result = None
    omada_error = None
    omada_delete_attempted = False
    if delete_omada and omada_site_id:
        try:
            _, client = omada_api_client_from_settings()
            if not site_name:
                try:
                    sites = client.get_sites().get("sites", [])
                    matched_site = next((site for site in sites if str(site.get("site_id")) == str(omada_site_id)), None)
                    site_name = (matched_site or {}).get("site_name") or site_name
                except Exception:
                    pass
            omada_delete_attempted = True
            omada_result = client.delete_site_if_supported(omada_site_id)
            omada_deleted = bool(omada_result.get("deleted"))
        except Exception as exc:
            response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
            omada_result = response_summary
            omada_error = str(exc)
            audit(admin["id"], "delete_site_deployment_omada_failed", "site_deployment", deployment_id, {"error": str(exc), "response": sanitize_summary(response_summary)})
            raise HTTPException(
                status_code=409,
                detail=f"Omada site deletion failed, so the site was not hidden locally: {omada_error}",
            )

    affected_ap_count = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            record_site_deployment_tombstone(
                cur,
                omada_site_id,
                site_name,
                admin["id"],
                omada_delete_attempted,
                omada_deleted,
                omada_error,
                omada_result,
            )
            if local_row:
                cur.execute("DELETE FROM site_deployments WHERE id = %s", (local_row["id"],))
            if omada_site_id:
                cur.execute(
                    """
                    UPDATE ap_deployments
                    SET deployment_status = 'DISCONNECTED',
                        last_error = %s,
                        updated_at = now()
                    WHERE omada_site_id = %s
                      AND deployment_status <> 'DELETED'
                    """,
                    (
                        "Parent site was deleted from Sites Deployments. AP history remains saved.",
                        omada_site_id,
                    ),
                )
                affected_ap_count = cur.rowcount
            if omada_site_id:
                cur.execute(
                    """
                    UPDATE omada_api_settings
                    SET selected_site_id = NULL,
                        selected_site_name = NULL,
                        updated_at = now()
                    WHERE selected_site_id = %s
                    """,
                    (omada_site_id,),
                )
    warning = None
    if omada_error:
        warning = "Site was removed from the Sites list locally, but Omada Controller did not confirm the remote delete. Delete it manually in Omada if it still appears there."
    audit(
        admin["id"],
        "delete_site_deployment",
        "site_deployment",
        deployment_id,
        {
            "site_name": site_name,
            "omada_site_id": omada_site_id,
            "omada_deleted": omada_deleted,
            "local_deleted": bool(local_row),
            "local_hidden": True,
            "affected_ap_count": affected_ap_count,
            "omada_error": omada_error,
        },
    )
    return {
        "status": "ok",
        "omada_deleted": omada_deleted,
        "local_deleted": bool(local_row),
        "local_hidden": True,
        "affected_ap_count": affected_ap_count,
        "omada_error": omada_error,
        "warning": warning,
        "omada_result": sanitize_summary(omada_result or {}),
    }


@app.get("/api/captive-portal/settings")
def get_captive_portal_settings(admin=Depends(current_admin)):
    return public_captive_portal_settings()


@app.put("/api/captive-portal/settings")
def save_captive_portal_settings(payload: CaptivePortalSettingsUpdate, admin=Depends(current_admin)):
    current = ensure_captive_portal_settings()
    allowed = {
        "portal_mode",
        "portal_url_staging",
        "portal_url_production",
        "default_access_duration_seconds",
        "post_login_redirect_url",
        "selected_omada_site_id",
        "selected_omada_site_name",
        "test_checklist_progress",
        "status",
    }
    updates = {key: value for key, value in payload.model_dump(exclude_none=True).items() if key in allowed}
    if not updates:
        return public_captive_portal_settings(current)
    assignments = ", ".join([f"{key} = %s" for key in updates] + ["updated_at = now()"])
    params = [Json(value) if key == "test_checklist_progress" else value for key, value in updates.items()] + [current["id"]]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE captive_portal_settings SET {assignments} WHERE id = %s", tuple(params))
    audit(admin["id"], "save_captive_portal_settings", "captive_portal_settings", str(current["id"]), sanitize_summary(updates))
    return public_captive_portal_settings()


MIKROTIK_SETUP_STEP_KEYS = [
    "validate_api_login",
    "prepare_hotspot_profile",
    "allow_pre_auth_portal",
    "use_voucher_portal_url",
    "set_post_login_behavior",
]


def mikrotik_step_status_map(row) -> dict:
    status = row.get("configuration_step_status") if row else {}
    return status if isinstance(status, dict) else {}


def mikrotik_configuration_progress(row, actions: Optional[list] = None) -> dict:
    step_status = mikrotik_step_status_map(row)
    step_keys = [action.get("key") for action in (actions or []) if action.get("key")] or MIKROTIK_SETUP_STEP_KEYS
    completed = sum(1 for key in step_keys if (step_status.get(key) or {}).get("status") == "SUCCESS")
    total = len(step_keys)
    return {
        "completed": completed,
        "total": total,
        "label": f"{completed}/{total}",
        "complete": total > 0 and completed >= total,
    }


def update_mikrotik_step_status(router_id: str, row, step_key: str, status: str, message: str = None):
    step_status = mikrotik_step_status_map(row).copy()
    now_text = datetime.now(timezone.utc).isoformat()
    current = dict(step_status.get(step_key) or {})
    current.update(
        {
            "status": status,
            "message": message,
            "updated_at": now_text,
        }
    )
    if status == "SUCCESS":
        current["applied_at"] = now_text
        current.pop("failed_at", None)
    elif status == "FAILED":
        current["failed_at"] = now_text
    step_status[step_key] = current
    completed = sum(1 for key in MIKROTIK_SETUP_STEP_KEYS if (step_status.get(key) or {}).get("status") == "SUCCESS")
    configuration_status = "APPLIED" if completed >= len(MIKROTIK_SETUP_STEP_KEYS) else "NOT_REVIEWED"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_routers
                SET configuration_step_status = %s,
                    configuration_status = %s,
                    updated_at = now()
                WHERE id = %s
                """,
                (Json(step_status), configuration_status, router_id),
            )
    return step_status


def public_mikrotik_router(row):
    progress = mikrotik_configuration_progress(row)
    display_name = system_display_name()
    managed_names = mikrotik_hotspot_managed_names(display_name)
    latest_preflight = fetch_one(
        """
        SELECT id, scan_status, risk_level, router_role_guess, recommended_deployment_mode, created_at, last_error
        FROM mikrotik_preflight_scans
        WHERE router_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (row["id"],),
    )
    latest_policy = latest_mikrotik_policy_row(str(row["id"]))
    legacy_profile_name = "3jcentralpisowifi-hotspot-profile"
    legacy_server_name = "3jcentralpisowifi-hotspot"
    hotspot_profile_name = row.get("hotspot_profile_name")
    hotspot_server_name = row.get("hotspot_server_name")
    hotspot_pool_name = row.get("hotspot_pool_name")
    hotspot_dhcp_server_name = row.get("hotspot_dhcp_server_name")
    hotspot_vlan_id = row.get("hotspot_vlan_id")
    hotspot_vlan_interface_name = row.get("hotspot_vlan_interface_name") or (f"{managed_names['vlan']}-{hotspot_vlan_id}" if hotspot_vlan_id else managed_names["vlan"])
    return {
        "id": row["id"],
        "router_name": row["router_name"],
        "host": row["host"],
        "api_port": row["api_port"],
        "use_tls": row["use_tls"],
        "username": row["username"],
        "has_password": bool(row.get("password_encrypted")),
        "account_privilege": row["account_privilege"],
        "notes": row["notes"],
        "status": row["status"],
        "last_test_at": row["last_test_at"],
        "last_error": row["last_error"],
        "configuration_status": row.get("configuration_status", "NOT_REVIEWED"),
        "last_configuration_review_at": row.get("last_configuration_review_at"),
        "last_configuration_apply_at": row.get("last_configuration_apply_at"),
        "last_configuration_error": row.get("last_configuration_error"),
        "configuration_step_status": mikrotik_step_status_map(row),
        "configuration_progress": progress,
        "latest_preflight_scan": {
            "id": latest_preflight["id"],
            "scan_status": latest_preflight["scan_status"],
            "risk_level": latest_preflight["risk_level"],
            "router_role_guess": latest_preflight["router_role_guess"],
            "recommended_deployment_mode": latest_preflight["recommended_deployment_mode"],
            "created_at": latest_preflight["created_at"],
            "last_error": latest_preflight["last_error"],
        } if latest_preflight else None,
        "latest_policy_result": public_mikrotik_policy_result(latest_policy),
        "hotspot_vlan_id": hotspot_vlan_id,
        "hotspot_vlan_parent_interface": row.get("hotspot_vlan_parent_interface"),
        "hotspot_vlan_interface_name": hotspot_vlan_interface_name,
        "hotspot_interface": row.get("hotspot_interface"),
        "hotspot_profile_name": managed_names["profile"] if not hotspot_profile_name or hotspot_profile_name == legacy_profile_name else hotspot_profile_name,
        "hotspot_server_name": managed_names["server"] if not hotspot_server_name or hotspot_server_name == legacy_server_name else hotspot_server_name,
        "hotspot_dns_name": row.get("hotspot_dns_name"),
        "hotspot_html_directory": row.get("hotspot_html_directory") or "hotspot",
        "hotspot_client_network_cidr": row.get("hotspot_client_network_cidr"),
        "hotspot_gateway_ip": row.get("hotspot_gateway_ip"),
        "hotspot_pool_start_ip": row.get("hotspot_pool_start_ip"),
        "hotspot_pool_end_ip": row.get("hotspot_pool_end_ip"),
        "hotspot_pool_name": hotspot_pool_name or managed_names["pool"],
        "hotspot_dhcp_server_name": hotspot_dhcp_server_name or managed_names["dhcp"],
        "hotspot_dhcp_lease_time": row.get("hotspot_dhcp_lease_time") or "1h",
        "hotspot_dns_servers": row.get("hotspot_dns_servers"),
        "hotspot_wan_interface": row.get("hotspot_wan_interface"),
        "hotspot_enable_nat": bool(row.get("hotspot_enable_nat")),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def routeros_cli_value(value: Optional[str]) -> str:
    text = str(value or "").strip()
    if not text:
        return '""'
    if re.match(r"^[A-Za-z0-9_./:@+-]+$", text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def routeros_cli_list(value: Optional[str]) -> str:
    items = [item.strip() for item in str(value or "").split(",") if item.strip()]
    return ",".join(routeros_cli_value(item) for item in items)


def normalize_dns_servers(value: Optional[str], gateway_ip: str) -> str:
    tokens = [token.strip() for token in str(value or "").split(",") if token.strip()]
    if not tokens:
        tokens = [gateway_ip, "8.8.8.8", "1.1.1.1"]
    for token in tokens:
        try:
            parsed = ip_address(token)
            if parsed.version != 4:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=400, detail=f"DNS server is not a valid IPv4 address: {token}")
    return ",".join(tokens)


def normalize_upstream_dns_servers(value: Optional[str], gateway_ip: str) -> str:
    tokens = [token.strip() for token in str(value or "").split(",") if token.strip()]
    if not tokens:
        tokens = ["8.8.8.8", "1.1.1.1"]
    filtered = []
    seen = set()
    for token in tokens:
        try:
            parsed = ip_address(token)
            if parsed.version != 4:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=400, detail=f"DNS server is not a valid IPv4 address: {token}")
        normalized = str(parsed)
        if normalized == str(gateway_ip):
            continue
        if normalized not in seen:
            seen.add(normalized)
            filtered.append(normalized)
    if not filtered:
        filtered = ["8.8.8.8", "1.1.1.1"]
    return ",".join(filtered)


def validate_station_network(payload: MikrotikStationCreate) -> tuple[object, object, object, object, str]:
    try:
        network = ip_network(payload.client_network_cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Client network CIDR is invalid.")
    if network.version != 4:
        raise HTTPException(status_code=400, detail="Client network must be IPv4.")
    try:
        gateway_ip = ip_address(payload.gateway_ip)
        pool_start = ip_address(payload.pool_start_ip)
        pool_end = ip_address(payload.pool_end_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Gateway and pool values must be valid IPv4 addresses.")
    if any(value.version != 4 for value in (gateway_ip, pool_start, pool_end)):
        raise HTTPException(status_code=400, detail="Gateway and pool values must be IPv4 addresses.")
    if gateway_ip not in network:
        raise HTTPException(status_code=400, detail="Gateway IP must be inside the client network CIDR.")
    if gateway_ip in (network.network_address, network.broadcast_address):
        raise HTTPException(status_code=400, detail="Gateway IP cannot be the network or broadcast address.")
    if pool_start not in network or pool_end not in network:
        raise HTTPException(status_code=400, detail="DHCP pool start and end must be inside the client network CIDR.")
    if int(pool_start) > int(pool_end):
        raise HTTPException(status_code=400, detail="DHCP pool start must be lower than or equal to pool end.")
    if int(pool_start) <= int(gateway_ip) <= int(pool_end):
        raise HTTPException(status_code=400, detail="DHCP pool cannot include the gateway IP.")
    dns_servers = normalize_upstream_dns_servers(payload.dns_servers, str(gateway_ip))
    return network, gateway_ip, pool_start, pool_end, dns_servers


def station_default_ipv4_values(cidr: Optional[str]) -> dict:
    try:
        network = ip_network(str(cidr or "").strip(), strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="AP management network CIDR is invalid.")
    if network.version != 4:
        raise HTTPException(status_code=400, detail="AP management network must be IPv4.")
    if network.num_addresses < 16:
        raise HTTPException(status_code=400, detail="AP management network is too small for DHCP.")
    gateway_ip = ip_address(int(network.network_address) + 1)
    pool_start = ip_address(min(int(network.network_address) + 10, int(network.broadcast_address) - 1))
    pool_end = ip_address(int(network.broadcast_address) - 1)
    return {
        "network": network,
        "gateway_ip": gateway_ip,
        "pool_start": pool_start,
        "pool_end": pool_end,
    }


def validate_station_ap_management_network(payload: MikrotikStationCreate, client_network) -> Optional[dict]:
    if not payload.ap_management_enabled:
        return None
    if not payload.ap_management_vlan_id:
        raise HTTPException(status_code=400, detail="AP management VLAN ID is required when AP management is enabled.")
    if int(payload.ap_management_vlan_id) == int(payload.vlan_id):
        raise HTTPException(status_code=400, detail="AP management VLAN must be different from the customer HotSpot VLAN.")
    defaults = station_default_ipv4_values(payload.ap_management_network_cidr or "10.111.0.0/24")
    network = defaults["network"]
    try:
        gateway_ip = ip_address(payload.ap_management_gateway_ip or str(defaults["gateway_ip"]))
        pool_start = ip_address(payload.ap_management_pool_start_ip or str(defaults["pool_start"]))
        pool_end = ip_address(payload.ap_management_pool_end_ip or str(defaults["pool_end"]))
    except ValueError:
        raise HTTPException(status_code=400, detail="AP management gateway and pool values must be valid IPv4 addresses.")
    if any(value.version != 4 for value in (gateway_ip, pool_start, pool_end)):
        raise HTTPException(status_code=400, detail="AP management gateway and pool values must be IPv4 addresses.")
    if network.overlaps(client_network):
        raise HTTPException(status_code=400, detail="AP management subnet must be different from the customer HotSpot client subnet.")
    if gateway_ip not in network:
        raise HTTPException(status_code=400, detail="AP management gateway IP must be inside the AP management CIDR.")
    if gateway_ip in (network.network_address, network.broadcast_address):
        raise HTTPException(status_code=400, detail="AP management gateway IP cannot be the network or broadcast address.")
    if pool_start not in network or pool_end not in network:
        raise HTTPException(status_code=400, detail="AP management DHCP pool start and end must be inside the AP management CIDR.")
    if int(pool_start) > int(pool_end):
        raise HTTPException(status_code=400, detail="AP management DHCP pool start must be lower than or equal to pool end.")
    if int(pool_start) <= int(gateway_ip) <= int(pool_end):
        raise HTTPException(status_code=400, detail="AP management DHCP pool cannot include the gateway IP.")
    dns_servers = normalize_upstream_dns_servers(payload.ap_management_dns_servers, str(gateway_ip))
    vlan_id = int(payload.ap_management_vlan_id)
    return {
        "vlan_id": vlan_id,
        "vlan_interface_name": (payload.ap_management_vlan_interface_name or "").strip() or f"VLAN{vlan_id}-AP-MGMT",
        "network": network,
        "gateway_ip": gateway_ip,
        "pool_start": pool_start,
        "pool_end": pool_end,
        "pool_name": (payload.ap_management_pool_name or "").strip() or f"POOL-AP-MGMT-V{vlan_id}",
        "dhcp_server_name": (payload.ap_management_dhcp_server_name or "").strip() or f"DHCP-AP-MGMT-V{vlan_id}",
        "dhcp_lease_time": (payload.ap_management_dhcp_lease_time or "1h").strip() or "1h",
        "dns_servers": dns_servers,
    }


def station_dedupe_csv(*values: Optional[str]) -> str:
    items = []
    seen = set()
    for value in values:
        for raw_item in str(value or "").split(","):
            item = raw_item.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            items.append(item)
    return ",".join(items)


def routeros_cli_add_preview(path: str, params: dict) -> str:
    section = path[:-4] if path.endswith("/add") else path
    command = section.strip("/").replace("/", " ")
    parts = ["add"]
    for key, value in (params or {}).items():
        if value is None or value == "":
            continue
        text_value = str(value)
        if any(char.isspace() for char in text_value):
            text_value = '"' + text_value.replace('"', '\\"') + '"'
        parts.append(f"{key}={text_value}")
    return f"/{command}\n{' '.join(parts)}"


def routeros_cli_set_preview(path: str, params: dict) -> str:
    section = path[:-4] if path.endswith("/set") else path
    command = section.strip("/").replace("/", " ")
    parts = ["set"]
    for key, value in (params or {}).items():
        if value is None or value == "":
            continue
        text_value = str(value)
        if any(char.isspace() for char in text_value):
            text_value = '"' + text_value.replace('"', '\\"') + '"'
        parts.append(f"{key}={text_value}")
    return f"/{command}\n{' '.join(parts)}"


def routeros_verify_matches(rows: list[dict], verify: Optional[dict]) -> bool:
    if not verify:
        return False
    checks = verify.get("checks")
    if checks:
        return all(routeros_verify_matches(rows, check) for check in checks)
    field = verify.get("field")
    expected = verify.get("value")
    if not field or not rows:
        return False
    if verify.get("truthy"):
        expected_truthy = routeros_truthy(expected)
        return any(routeros_truthy(row.get(field)) == expected_truthy for row in rows)
    if verify.get("contains"):
        return any(str(expected or "") in str(row.get(field) or "") for row in rows)
    return any(str(row.get(field) or "").strip() == str(expected or "").strip() for row in rows)


def routeros_verify_message(verify: Optional[dict]) -> str:
    if not verify:
        return "No verification rule was provided."
    return verify.get("message") or f"{verify.get('field')} is already {verify.get('value')}."


def station_routeros_add_command(label: str, path: str, params: dict, **metadata) -> dict:
    command = {
        "label": label,
        "path": path,
        "params": params,
        "preview": routeros_cli_add_preview(path, params),
    }
    command.update(metadata)
    return command


def station_routeros_set_command(label: str, path: str, params: dict, **metadata) -> dict:
    command = {
        "label": label,
        "path": path,
        "params": params,
        "preview": routeros_cli_set_preview(path, params),
    }
    command.update(metadata)
    return command


def station_routeros_set_existing_command(label: str, print_path: str, query: dict, set_path: str, params: dict, **metadata) -> dict:
    command = {
        "label": label,
        "path": set_path,
        "params": params,
        "set_existing_query": {
            "print_path": print_path,
            "query": query,
            "set_path": set_path,
        },
        "preview": f"{routeros_remove_preview(print_path, next(iter(query.keys())), next(iter(query.values()))).replace(' remove ', ' set ')} {' '.join(f'{key}={value}' for key, value in params.items() if value not in (None, ''))}",
    }
    command.update(metadata)
    return command


def station_routeros_remove_command(label: str, print_path: str, query_field: str, query_value: str) -> dict:
    return {
        "label": label,
        "print_path": print_path,
        "query_field": query_field,
        "query_value": query_value,
        "preview": routeros_remove_preview(print_path, query_field, query_value),
    }


def station_code_from_text(value: Optional[str]) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return text or f"station-{uuid.uuid4().hex[:8]}"


def station_snapshot_for_router(router_id: str) -> tuple[Optional[dict], dict]:
    scan = latest_mikrotik_scan_row(router_id)
    if not scan or scan.get("scan_status") != "SUCCESS":
        return scan, {}
    return scan, scan.get("sanitized_snapshot_json") or {}


def station_interface_map(snapshot: dict) -> dict[str, dict]:
    return {
        str(item.get("name") or ""): item
        for item in mikrotik_snapshot_items(snapshot, "interfaces")
        if item.get("name")
    }


def mikrotik_live_interface_map(router_id: str) -> tuple[dict[str, dict], Optional[str]]:
    """Read current RouterOS interfaces without changing the router.

    Preflight scan remains required for conflict detection, but station/AP
    management forms can use fresher Detect Ports data. This fallback prevents
    saves from failing when the selected bridge/port exists live but the latest
    preflight snapshot is stale.
    """
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        return {}, "MikroTik router not found."
    if not row.get("username") or not row.get("password_encrypted"):
        return {}, "RouterOS API username and password are required."
    try:
        password = decrypt_secret(row.get("password_encrypted"))
        interfaces = sanitize_routeros_snapshot(routeros_readonly_query(
            row["host"],
            row["api_port"],
            row.get("username"),
            password,
            row.get("use_tls"),
            ["/interface/print"],
        ))
        try:
            bridge_ports = sanitize_routeros_snapshot(routeros_readonly_query(
                row["host"],
                row["api_port"],
                row.get("username"),
                password,
                row.get("use_tls"),
                ["/interface/bridge/port/print"],
            ))
        except Exception:
            bridge_ports = []
        bridge_membership = {
            sanitize_routeros_text(item.get("interface"), max_length=200): sanitize_routeros_text(item.get("bridge"), max_length=200)
            for item in bridge_ports
            if item.get("interface") and item.get("bridge")
        }
        mapped = {}
        for item in interfaces:
            name = sanitize_routeros_text(item.get("name"), max_length=200)
            if not name:
                continue
            mapped[name] = {
                **item,
                "name": name,
                "type": sanitize_routeros_text(item.get("type"), max_length=120),
                "default-name": sanitize_routeros_text(item.get("default-name"), max_length=200),
                "comment": sanitize_routeros_text(item.get("comment"), max_length=500),
                "bridge": bridge_membership.get(name),
            }
        return mapped, None
    except Exception as exc:
        return {}, sanitize_routeros_text(str(exc), max_length=1000)


def station_interface_map_with_live_fallback(router_id: str, snapshot: dict, selected_names: list[str]) -> tuple[dict[str, dict], Optional[str], bool]:
    interfaces = station_interface_map(snapshot)
    required_names = [name for name in [str(value or "").strip() for value in selected_names] if name]
    if required_names and any(name not in interfaces for name in required_names):
        live_interfaces, live_error = mikrotik_live_interface_map(router_id)
        if live_interfaces:
            return {**interfaces, **live_interfaces}, live_error, True
        return interfaces, live_error, False
    return interfaces, None, False


def station_interface_is_pppoe(interface: dict) -> bool:
    text = " ".join(str(interface.get(key) or "").lower() for key in ("name", "type", "comment", "default-name"))
    return "pppoe" in text


def station_existing_vlan_is_managed(snapshot: dict, vlan_id: int, vlan_interface_name: str, marker: Optional[str] = None) -> bool:
    marker = (marker or f"3j hotspot - vlan {vlan_id}").lower()
    for item in mikrotik_snapshot_items(snapshot, "interface_vlans"):
        if vlan_id not in parse_routeros_vlan_ids(item.get("vlan-id")):
            continue
        if str(item.get("name") or "") == vlan_interface_name:
            return True
        if marker in str(item.get("comment") or "").lower():
            return True
    for item in mikrotik_snapshot_items(snapshot, "bridge_vlans"):
        if routeros_truthy(item.get("dynamic")):
            continue
        if vlan_id not in parse_routeros_vlan_ids(item.get("vlan-ids")):
            continue
        if marker in str(item.get("comment") or "").lower():
            return True
    return False


def station_validate_router_path(payload: MikrotikStationCreate, station_id: Optional[str], network, pool_start, pool_end, ap_management: Optional[dict] = None):
    errors = []
    vlan_id = int(payload.vlan_id)
    vlan_interface_name = (payload.vlan_interface_name or "").strip() or f"VLAN{vlan_id}-3J-HOTSPOT"
    pool_name = (payload.pool_name or "").strip() or f"POOL-3J-HOTSPOT-V{vlan_id}"
    dhcp_server_name = (payload.dhcp_server_name or "").strip() or f"DHCP-3J-HOTSPOT-V{vlan_id}"
    hotspot_profile_name = (payload.hotspot_profile_name or "").strip() or f"PROFILE-3J-HOTSPOT-V{vlan_id}"
    hotspot_server_name = (payload.hotspot_server_name or "").strip() or f"HS-3J-HOTSPOT-V{vlan_id}"
    ap_vlan_id = int(ap_management["vlan_id"]) if ap_management else None
    ap_vlan_interface_name = ap_management["vlan_interface_name"] if ap_management else None
    ap_pool_name = ap_management["pool_name"] if ap_management else None
    ap_dhcp_server_name = ap_management["dhcp_server_name"] if ap_management else None
    for index, item in enumerate(payload.routers):
        router = fetch_one("SELECT id, router_name FROM mikrotik_routers WHERE id = %s", (item.router_id,))
        router_label = router["router_name"] if router else f"router #{index + 1}"
        scan, snapshot = station_snapshot_for_router(item.router_id)
        if not scan:
            errors.append(f"{router_label}: run a successful Preflight Scan before saving this station.")
            continue
        if scan.get("scan_status") != "SUCCESS":
            errors.append(f"{router_label}: latest Preflight Scan failed. Re-scan before saving this station.")
            continue
        bridge_name = (item.bridge_name or "").strip()
        port_names = [port.strip() for port in str(item.tagged_ports or "").split(",") if port.strip()]
        interfaces, live_interface_error, used_live_interfaces = station_interface_map_with_live_fallback(item.router_id, snapshot, [bridge_name, *port_names])
        if bridge_name not in interfaces:
            suffix = f" Live Detect Ports also failed: {live_interface_error}" if live_interface_error else ""
            errors.append(f"{router_label}: selected bridge/interface '{bridge_name}' was not found in the latest scan or live RouterOS interface detection.{suffix}")
        elif station_interface_is_pppoe(interfaces[bridge_name]):
            errors.append(f"{router_label}: '{bridge_name}' is PPPoE-related and cannot carry the station captive portal VLAN.")
        for port_name in port_names:
            if port_name not in interfaces:
                suffix = f" Live Detect Ports also failed: {live_interface_error}" if live_interface_error else ""
                errors.append(f"{router_label}: tagged port '{port_name}' was not found in the latest scan or live RouterOS interface detection.{suffix}")
            elif station_interface_is_pppoe(interfaces[port_name]):
                errors.append(f"{router_label}: tagged port '{port_name}' is PPPoE-related and cannot carry the station captive portal VLAN.")
        existing_vlan_ids = set()
        for row in mikrotik_snapshot_items(snapshot, "interface_vlans"):
            existing_vlan_ids.update(parse_routeros_vlan_ids(row.get("vlan-id")))
        for row in mikrotik_snapshot_items(snapshot, "bridge_vlans"):
            if routeros_truthy(row.get("dynamic")):
                continue
            existing_vlan_ids.update(parse_routeros_vlan_ids(row.get("vlan-ids")))
        if vlan_id in existing_vlan_ids and not station_existing_vlan_is_managed(snapshot, vlan_id, vlan_interface_name):
            errors.append(f"{router_label}: VLAN {vlan_id} already exists in the latest scan and is not marked as this station's managed VLAN.")
        if ap_management and ap_vlan_id in existing_vlan_ids and not station_existing_vlan_is_managed(snapshot, ap_vlan_id, ap_vlan_interface_name, f"3j ap management - vlan {ap_vlan_id}"):
            errors.append(f"{router_label}: AP management VLAN {ap_vlan_id} already exists in the latest scan and is not marked as this station's managed AP management VLAN.")
        if index == 0:
            for row in mikrotik_snapshot_items(snapshot, "ip_addresses"):
                existing_network = parse_routeros_ip_network(row.get("address"))
                existing_interface = str(row.get("interface") or "")
                existing_comment = str(row.get("comment") or "").lower()
                if existing_network and network.overlaps(existing_network) and existing_interface != vlan_interface_name and f"3j hotspot - vlan {vlan_id}" not in existing_comment:
                    errors.append(f"{router_label}: client subnet {network.with_prefixlen} overlaps existing router network {existing_network} on {existing_interface or 'unknown interface'}.")
                if ap_management and existing_network and ap_management["network"].overlaps(existing_network) and existing_interface != ap_vlan_interface_name and f"3j ap management - vlan {ap_vlan_id}" not in existing_comment:
                    errors.append(f"{router_label}: AP management subnet {ap_management['network'].with_prefixlen} overlaps existing router network {existing_network} on {existing_interface or 'unknown interface'}.")
            proposed_pool = (int(pool_start), int(pool_end))
            proposed_ap_pool = (int(ap_management["pool_start"]), int(ap_management["pool_end"])) if ap_management else None
            for row in mikrotik_snapshot_items(snapshot, "ip_pools"):
                if str(row.get("name") or "") == pool_name:
                    continue
                for existing_range in parse_routeros_pool_ranges(row.get("ranges")):
                    if mikrotik_ranges_overlap(proposed_pool, existing_range):
                        errors.append(f"{router_label}: DHCP pool {pool_start}-{pool_end} overlaps existing pool {row.get('name')}: {row.get('ranges')}.")
                    if proposed_ap_pool and str(row.get("name") or "") != ap_pool_name and mikrotik_ranges_overlap(proposed_ap_pool, existing_range):
                        errors.append(f"{router_label}: AP management DHCP pool {ap_management['pool_start']}-{ap_management['pool_end']} overlaps existing pool {row.get('name')}: {row.get('ranges')}.")
            if payload.create_dhcp_server:
                for row in mikrotik_snapshot_items(snapshot, "dhcp_servers"):
                    existing_name = str(row.get("name") or "")
                    existing_interface = str(row.get("interface") or "")
                    existing_comment = str(row.get("comment") or "").lower()
                    if existing_name == dhcp_server_name:
                        continue
                    if existing_interface == vlan_interface_name and f"3j hotspot - dhcp server for vlan {vlan_id}" not in existing_comment:
                        errors.append(f"{router_label}: DHCP server already exists on {vlan_interface_name}. Disable station DHCP creation or choose a different VLAN interface.")
            if ap_management:
                for row in mikrotik_snapshot_items(snapshot, "dhcp_servers"):
                    existing_name = str(row.get("name") or "")
                    existing_interface = str(row.get("interface") or "")
                    existing_comment = str(row.get("comment") or "").lower()
                    if existing_name == ap_dhcp_server_name:
                        continue
                    if existing_interface == ap_vlan_interface_name and f"3j ap management - dhcp server for vlan {ap_vlan_id}" not in existing_comment:
                        errors.append(f"{router_label}: DHCP server already exists on AP management interface {ap_vlan_interface_name}. Choose a different AP management VLAN or disable the conflicting DHCP server first.")
            if payload.create_hotspot_profile:
                for row in mikrotik_snapshot_items(snapshot, "hotspot_profiles"):
                    existing_name = str(row.get("name") or "")
                    if existing_name == hotspot_profile_name:
                        continue
            if payload.create_hotspot_server:
                for row in mikrotik_snapshot_items(snapshot, "hotspots"):
                    existing_name = str(row.get("name") or "")
                    existing_interface = str(row.get("interface") or "")
                    existing_comment = str(row.get("comment") or "").lower()
                    if existing_name == hotspot_server_name:
                        continue
                    if existing_interface == vlan_interface_name and existing_name != hotspot_server_name and f"3j hotspot - hotspot server for vlan {vlan_id}" not in existing_comment:
                        errors.append(f"{router_label}: another HotSpot server already exists on {vlan_interface_name}. Choose a different VLAN/interface or remove the existing HotSpot server first.")
    if errors:
        raise HTTPException(status_code=400, detail=" ".join(errors))


def build_mikrotik_station_plan(station: dict, routers: list[dict]) -> dict:
    vlan_id = int(station["vlan_id"])
    network = ip_network(station["client_network_cidr"], strict=False)
    vlan_interface_name = station.get("vlan_interface_name") or f"VLAN{vlan_id}-3J-HOTSPOT"
    pool_name = station.get("pool_name") or f"POOL-3J-HOTSPOT-V{vlan_id}"
    dhcp_server_name = station.get("dhcp_server_name") or f"DHCP-3J-HOTSPOT-V{vlan_id}"
    dhcp_lease_time = station.get("dhcp_lease_time") or "1h"
    create_dhcp_server = bool(station.get("create_dhcp_server", True))
    hotspot_profile_name = station.get("hotspot_profile_name") or f"PROFILE-3J-HOTSPOT-V{vlan_id}"
    hotspot_html_directory = station.get("hotspot_html_directory") or "hotspot"
    hotspot_dns_name = station.get("hotspot_dns_name") or default_hotspot_dns_name(station.get("station_code"))
    hotspot_server_name = station.get("hotspot_server_name") or f"HS-3J-HOTSPOT-V{vlan_id}"
    create_hotspot_profile = bool(station.get("create_hotspot_profile", True))
    create_hotspot_server = bool(station.get("create_hotspot_server", True))
    create_walled_garden = bool(station.get("create_walled_garden", True))
    portal_url = station.get("portal_url") or "http://192.168.50.70:8080/portal"
    ap_management_enabled = bool(station.get("ap_management_enabled"))
    ap_management_vlan_id = int(station.get("ap_management_vlan_id") or 111)
    ap_management_network = ip_network(station.get("ap_management_network_cidr") or "10.111.0.0/24", strict=False)
    ap_management_vlan_interface_name = station.get("ap_management_vlan_interface_name") or f"VLAN{ap_management_vlan_id}-AP-MGMT"
    ap_management_gateway_ip = station.get("ap_management_gateway_ip") or str(ip_address(int(ap_management_network.network_address) + 1))
    ap_management_pool_start_ip = station.get("ap_management_pool_start_ip") or str(ip_address(min(int(ap_management_network.network_address) + 10, int(ap_management_network.broadcast_address) - 1)))
    ap_management_pool_end_ip = station.get("ap_management_pool_end_ip") or str(ip_address(int(ap_management_network.broadcast_address) - 1))
    ap_management_pool_name = station.get("ap_management_pool_name") or f"POOL-AP-MGMT-V{ap_management_vlan_id}"
    ap_management_dhcp_server_name = station.get("ap_management_dhcp_server_name") or f"DHCP-AP-MGMT-V{ap_management_vlan_id}"
    ap_management_dhcp_lease_time = station.get("ap_management_dhcp_lease_time") or "1h"
    ap_management_dns_servers = normalize_upstream_dns_servers(station.get("ap_management_dns_servers"), ap_management_gateway_ip)
    parsed_portal_url = portal_url if "://" in portal_url else f"http://{portal_url}"
    parsed_portal = urlparse(parsed_portal_url)
    portal_host = parsed_portal.hostname or "192.168.50.70"
    portal_port = parsed_portal.port or (443 if parsed_portal.scheme == "https" else 80)
    capport_url = station_capport_url(station)
    capport_option_name = f"3J-CAPPORT-V{vlan_id}"
    client_dns_servers = str(station["gateway_ip"])
    upstream_dns_servers = normalize_upstream_dns_servers(station.get("dns_servers"), str(station["gateway_ip"]))
    local_interface_list = station.get("local_interface_list") or "LOCAL"
    nat_comment = f"3J Hotspot - NAT for VLAN {vlan_id} clients"
    dns_udp_redirect_comment = f"3J Hotspot - force DNS UDP to router for VLAN {vlan_id}"
    dns_tcp_redirect_comment = f"3J Hotspot - force DNS TCP to router for VLAN {vlan_id}"
    raw_client_tracking_comment = f"3J Hotspot - keep VLAN {vlan_id} client traffic tracked"
    raw_return_tracking_comment = f"3J Hotspot - keep VLAN {vlan_id} return traffic tracked"
    private_dns_reject_comment = f"3J Hotspot - reject Private DNS TLS for VLAN {vlan_id}"
    legacy_http_probe_redirect_comment = f"3J Hotspot - send unauth HTTP to portal for VLAN {vlan_id}"
    ipv6_ra_suppress_comment = f"3J Hotspot - suppress IPv6 RA on VLAN {vlan_id}"
    router_plans = []
    for index, router in enumerate(routers):
        bridge_name = (router.get("bridge_name") or "").strip()
        tagged_ports = (router.get("tagged_ports") or "").strip()
        effective_tagged_ports = station_dedupe_csv(bridge_name, tagged_ports)
        is_root = index == 0
        role = "ROOT_GATEWAY" if is_root else "TRUNK_HELPER"
        commands = []
        if is_root:
            if ap_management_enabled:
                commands.extend([
                    station_routeros_add_command(
                        f"Create AP management VLAN {ap_management_vlan_id} interface",
                        "/interface/vlan/add",
                        {
                            "comment": f"3J AP Management - VLAN {ap_management_vlan_id} interface on {bridge_name}",
                            "interface": bridge_name,
                            "name": ap_management_vlan_interface_name,
                            "vlan-id": str(ap_management_vlan_id),
                        },
                        unique_field="name",
                        unique_value=ap_management_vlan_interface_name,
                    ),
                    station_routeros_add_command(
                        f"Tag AP management VLAN {ap_management_vlan_id} toward AP path",
                        "/interface/bridge/vlan/add",
                        {
                            "bridge": bridge_name,
                            "comment": f"3J AP Management - VLAN {ap_management_vlan_id} trunk to next station router",
                            "tagged": effective_tagged_ports,
                            "vlan-ids": str(ap_management_vlan_id),
                        },
                        existing_query={"bridge": bridge_name, "vlan-ids": str(ap_management_vlan_id)},
                        merge_bridge_vlan_tagged=True,
                    ),
                    station_routeros_add_command(
                        f"Add AP management VLAN {ap_management_vlan_id} gateway IP",
                        "/ip/address/add",
                        {
                            "address": f"{ap_management_gateway_ip}/{ap_management_network.prefixlen}",
                            "comment": f"3J AP Management - VLAN {ap_management_vlan_id} gateway",
                            "interface": ap_management_vlan_interface_name,
                            "network": str(ap_management_network.network_address),
                        },
                        unique_comment=f"3J AP Management - VLAN {ap_management_vlan_id} gateway",
                    ),
                    station_routeros_add_command(
                        "Create AP management DHCP pool",
                        "/ip/pool/add",
                        {
                            "name": ap_management_pool_name,
                            "ranges": f"{ap_management_pool_start_ip}-{ap_management_pool_end_ip}",
                        },
                        unique_field="name",
                        unique_value=ap_management_pool_name,
                    ),
                    station_routeros_add_command(
                        "Create AP management DHCP server",
                        "/ip/dhcp-server/add",
                        {
                            "name": ap_management_dhcp_server_name,
                            "interface": ap_management_vlan_interface_name,
                            "address-pool": ap_management_pool_name,
                            "lease-time": ap_management_dhcp_lease_time,
                            "disabled": "no",
                        },
                        unique_field="name",
                        unique_value=ap_management_dhcp_server_name,
                    ),
                    station_routeros_add_command(
                        "Add AP management DHCP network options",
                        "/ip/dhcp-server/network/add",
                        {
                            "address": ap_management_network.with_prefixlen,
                            "comment": f"3J AP Management - DHCP options for VLAN {ap_management_vlan_id}",
                            "dns-server": ap_management_dns_servers,
                            "gateway": ap_management_gateway_ip,
                        },
                        existing_query={"address": ap_management_network.with_prefixlen},
                    ),
                    station_routeros_add_command(
                        "Allow AP management VLAN as local/LAN interface",
                        "/interface/list/member/add",
                        {
                            "comment": f"3J AP Management - allow VLAN {ap_management_vlan_id} as local/LAN interface",
                            "interface": ap_management_vlan_interface_name,
                            "list": local_interface_list,
                        },
                        existing_query={"interface": ap_management_vlan_interface_name, "list": local_interface_list},
                    ),
                ])
            commands.extend([
                station_routeros_add_command(
                    f"Create VLAN {vlan_id} interface",
                    "/interface/vlan/add",
                    {
                        "comment": f"3J Hotspot - VLAN {vlan_id} interface on {bridge_name}",
                        "interface": bridge_name,
                        "name": vlan_interface_name,
                        "vlan-id": str(vlan_id),
                    },
                    unique_field="name",
                    unique_value=vlan_interface_name,
                ),
                station_routeros_add_command(
                    f"Tag VLAN {vlan_id} toward the next hop",
                    "/interface/bridge/vlan/add",
                    {
                        "bridge": bridge_name,
                        "comment": f"3J Hotspot - VLAN {vlan_id} trunk to next station router",
                        "tagged": effective_tagged_ports,
                        "vlan-ids": str(vlan_id),
                    },
                    existing_query={"bridge": bridge_name, "vlan-ids": str(vlan_id)},
                    merge_bridge_vlan_tagged=True,
                ),
                station_routeros_add_command(
                    f"Add VLAN {vlan_id} gateway IP",
                    "/ip/address/add",
                    {
                        "address": f"{station['gateway_ip']}/{network.prefixlen}",
                        "comment": f"3J Hotspot - VLAN {vlan_id} gateway",
                        "interface": vlan_interface_name,
                        "network": str(network.network_address),
                    },
                    unique_comment=f"3J Hotspot - VLAN {vlan_id} gateway",
                ),
                station_routeros_add_command(
                    "Create DHCP pool",
                    "/ip/pool/add",
                    {
                        "name": pool_name,
                        "ranges": f"{station['pool_start_ip']}-{station['pool_end_ip']}",
                    },
                    unique_field="name",
                    unique_value=pool_name,
                ),
                *([
                    station_routeros_add_command(
                        "Create DHCP server on root gateway",
                        "/ip/dhcp-server/add",
                        {
                            "name": dhcp_server_name,
                            "interface": vlan_interface_name,
                            "address-pool": pool_name,
                            "lease-time": dhcp_lease_time,
                            "disabled": "no",
                        },
                        unique_field="name",
                        unique_value=dhcp_server_name,
                    )
                ] if create_dhcp_server else []),
                station_routeros_add_command(
                    "Add DHCP network options",
                    "/ip/dhcp-server/network/add",
                    {
                        "address": network.with_prefixlen,
                        "comment": f"3J Hotspot - DHCP options for VLAN {vlan_id}",
                        "dns-server": client_dns_servers,
                        "gateway": str(station["gateway_ip"]),
                    },
                    existing_query={"address": network.with_prefixlen},
                ),
                station_routeros_set_command(
                    "Enable router DNS for captive portal popup detection",
                    "/ip/dns/set",
                    {
                        "allow-remote-requests": "yes",
                        "servers": upstream_dns_servers,
                    },
                    verify={
                        "words": ["/ip/dns/print", "=.proplist=allow-remote-requests,servers"],
                        "checks": [
                            {"field": "allow-remote-requests", "value": "yes", "truthy": True},
                            {"field": "servers", "value": upstream_dns_servers},
                        ],
                        "label": "/ip dns allow-remote-requests",
                        "message": "RouterOS DNS is already enabled with the configured upstream DNS servers.",
                        "not_found_message": "RouterOS DNS remote requests or upstream DNS servers need to be updated.",
                    },
                ),
                station_routeros_set_existing_command(
                    "Set DHCP DNS to HotSpot gateway only",
                    "/ip/dhcp-server/network/print",
                    {"address": network.with_prefixlen},
                    "/ip/dhcp-server/network/set",
                    {
                        "dns-server": client_dns_servers,
                    },
                    verify={
                        "words": ["/ip/dhcp-server/network/print", f"?address={network.with_prefixlen}", "=.proplist=.id,address,dns-server"],
                        "field": "dns-server",
                        "value": client_dns_servers,
                        "label": "DHCP client DNS",
                        "message": "DHCP clients already receive only the HotSpot gateway as DNS.",
                        "not_found_message": "DHCP clients do not yet receive only the HotSpot gateway as DNS.",
                    },
                ),
                station_routeros_add_command(
                    "Create DHCP captive portal option",
                    "/ip/dhcp-server/option/add",
                    {
                        "name": capport_option_name,
                        "code": "114",
                        "value": f"'{capport_url}'",
                    },
                    unique_field="name",
                    unique_value=capport_option_name,
                ),
                station_routeros_set_existing_command(
                    "Attach captive portal option to DHCP network",
                    "/ip/dhcp-server/network/print",
                    {"address": network.with_prefixlen},
                    "/ip/dhcp-server/network/set",
                    {
                        "dhcp-option": capport_option_name,
                    },
                    verify={
                        "words": ["/ip/dhcp-server/network/print", f"?address={network.with_prefixlen}", "=.proplist=.id,address,dhcp-option"],
                        "field": "dhcp-option",
                        "value": capport_option_name,
                        "contains": True,
                        "label": "DHCP network captive portal option",
                        "message": "DHCP network already advertises the captive portal option.",
                        "not_found_message": "DHCP network does not advertise the captive portal option yet.",
                    },
                ),
                station_routeros_add_command(
                    "Allow VLAN as local/LAN interface",
                    "/interface/list/member/add",
                    {
                        "comment": f"3J Hotspot - allow VLAN {vlan_id} as local/LAN interface",
                        "interface": vlan_interface_name,
                        "list": local_interface_list,
                    },
                    existing_query={"interface": vlan_interface_name, "list": local_interface_list},
                ),
                station_routeros_add_command(
                    "Create internet NAT for HotSpot clients",
                    "/ip/firewall/nat/add",
                    {
                        "chain": "srcnat",
                        "src-address": network.with_prefixlen,
                        "action": "masquerade",
                        "comment": nat_comment,
                    },
                    unique_comment=nat_comment,
                ),
                station_routeros_add_command(
                    "Keep client traffic tracked before global raw notrack",
                    "/ip/firewall/raw/add",
                    {
                        "chain": "prerouting",
                        "src-address": network.with_prefixlen,
                        "action": "accept",
                        "comment": raw_client_tracking_comment,
                    },
                    unique_comment=raw_client_tracking_comment,
                    place_before_query={
                        "print_path": "/ip/firewall/raw/print",
                        "query": {"chain": "prerouting", "action": "notrack"},
                    },
                ),
                station_routeros_add_command(
                    "Keep return traffic tracked before global raw notrack",
                    "/ip/firewall/raw/add",
                    {
                        "chain": "prerouting",
                        "dst-address": network.with_prefixlen,
                        "action": "accept",
                        "comment": raw_return_tracking_comment,
                    },
                    unique_comment=raw_return_tracking_comment,
                    place_before_query={
                        "print_path": "/ip/firewall/raw/print",
                        "query": {"chain": "prerouting", "action": "notrack"},
                    },
                ),
                station_routeros_add_command(
                    "Force client DNS UDP to HotSpot gateway",
                    "/ip/firewall/nat/add",
                    {
                        "chain": "dstnat",
                        "src-address": network.with_prefixlen,
                        "protocol": "udp",
                        "dst-port": "53",
                        "action": "redirect",
                        "to-ports": "53",
                        "comment": dns_udp_redirect_comment,
                    },
                    unique_comment=dns_udp_redirect_comment,
                ),
                station_routeros_add_command(
                    "Force client DNS TCP to HotSpot gateway",
                    "/ip/firewall/nat/add",
                    {
                        "chain": "dstnat",
                        "src-address": network.with_prefixlen,
                        "protocol": "tcp",
                        "dst-port": "53",
                        "action": "redirect",
                        "to-ports": "53",
                        "comment": dns_tcp_redirect_comment,
                    },
                    unique_comment=dns_tcp_redirect_comment,
                ),
                station_routeros_add_command(
                    "Reject Android Private DNS TLS during captive check",
                    "/ip/firewall/filter/add",
                    {
                        "chain": "input",
                        "src-address": network.with_prefixlen,
                        "protocol": "tcp",
                        "dst-port": "853",
                        "action": "reject",
                        "reject-with": "tcp-reset",
                        "comment": private_dns_reject_comment,
                    },
                    unique_comment=private_dns_reject_comment,
                    place_before_query={
                        "print_path": "/ip/firewall/filter/print",
                        "query": {"chain": "input", "action": "jump"},
                    },
                ),
                station_routeros_add_command(
                    "Suppress IPv6 router advertisements on HotSpot VLAN",
                    "/ipv6/nd/add",
                    {
                        "interface": vlan_interface_name,
                        "ra-lifetime": "0s",
                        "advertise-dns": "no",
                        "disabled": "no",
                        "comment": ipv6_ra_suppress_comment,
                    },
                    existing_query={"interface": vlan_interface_name},
                ),
                *([
                    station_routeros_add_command(
                        "Create HotSpot profile",
                        "/ip/hotspot/profile/add",
                        {
                            "name": hotspot_profile_name,
                            "hotspot-address": str(station["gateway_ip"]),
                            "dns-name": hotspot_dns_name,
                            "html-directory": hotspot_html_directory,
                            "login-by": "cookie,http-chap",
                        },
                        unique_field="name",
                        unique_value=hotspot_profile_name,
                    )
                ] if create_hotspot_profile else []),
                *([
                    station_routeros_add_command(
                        "Create HotSpot server on root gateway",
                        "/ip/hotspot/add",
                        {
                            "name": hotspot_server_name,
                            "interface": vlan_interface_name,
                            "profile": hotspot_profile_name,
                            "address-pool": "none",
                            "disabled": "no",
                        },
                        unique_field="name",
                        unique_value=hotspot_server_name,
                    )
                ] if create_hotspot_server else []),
                *([
                    station_routeros_add_command(
                        "Allow portal server before login",
                        "/ip/hotspot/walled-garden/ip/add",
                        {
                            "action": "accept",
                            "dst-address": portal_host,
                            "comment": f"3J Hotspot - portal server for VLAN {vlan_id}",
                        },
                        unique_comment=f"3J Hotspot - portal server for VLAN {vlan_id}",
                    ),
                    station_routeros_add_command(
                        f"Allow portal URL TCP port {portal_port}",
                        "/ip/hotspot/walled-garden/ip/add",
                        {
                            "action": "accept",
                            "protocol": "tcp",
                            "dst-address": portal_host,
                            "dst-port": str(portal_port),
                            "comment": f"3J Hotspot - portal URL for VLAN {vlan_id}",
                        },
                        unique_comment=f"3J Hotspot - portal URL for VLAN {vlan_id}",
                    ),
                    station_routeros_add_command(
                        "Allow DNS UDP before login",
                        "/ip/hotspot/walled-garden/ip/add",
                        {
                            "action": "accept",
                            "protocol": "udp",
                            "dst-port": "53",
                            "comment": f"3J Hotspot - DNS UDP for VLAN {vlan_id}",
                        },
                        unique_comment=f"3J Hotspot - DNS UDP for VLAN {vlan_id}",
                    ),
                    station_routeros_add_command(
                        "Allow DNS TCP before login",
                        "/ip/hotspot/walled-garden/ip/add",
                        {
                            "action": "accept",
                            "protocol": "tcp",
                            "dst-port": "53",
                            "comment": f"3J Hotspot - DNS TCP for VLAN {vlan_id}",
                        },
                        unique_comment=f"3J Hotspot - DNS TCP for VLAN {vlan_id}",
                    ),
                ] if create_walled_garden else []),
            ])
        else:
            previous_name = routers[index - 1].get("router_name") or "previous router"
            if ap_management_enabled:
                commands.extend([
                    station_routeros_add_command(
                        f"Create AP management VLAN {ap_management_vlan_id} monitoring interface",
                        "/interface/vlan/add",
                        {
                            "comment": f"3J AP Management - VLAN {ap_management_vlan_id} monitor interface on {bridge_name}",
                            "interface": bridge_name,
                            "name": ap_management_vlan_interface_name,
                            "vlan-id": str(ap_management_vlan_id),
                        },
                        unique_field="name",
                        unique_value=ap_management_vlan_interface_name,
                    ),
                    station_routeros_add_command(
                        f"Carry AP management VLAN {ap_management_vlan_id} through this router",
                        "/interface/bridge/vlan/add",
                        {
                            "bridge": bridge_name,
                            "comment": f"3J AP Management - VLAN {ap_management_vlan_id} trunk from {previous_name} to OLT/APs",
                            "tagged": effective_tagged_ports,
                            "vlan-ids": str(ap_management_vlan_id),
                        },
                        existing_query={"bridge": bridge_name, "vlan-ids": str(ap_management_vlan_id)},
                        merge_bridge_vlan_tagged=True,
                    ),
                ])
            commands.extend([
                station_routeros_add_command(
                    f"Create VLAN {vlan_id} monitoring interface",
                    "/interface/vlan/add",
                    {
                        "comment": f"3J Hotspot - VLAN {vlan_id} monitor interface on {bridge_name}",
                        "interface": bridge_name,
                        "name": vlan_interface_name,
                        "vlan-id": str(vlan_id),
                    },
                    unique_field="name",
                    unique_value=vlan_interface_name,
                ),
                station_routeros_add_command(
                    f"Carry VLAN {vlan_id} through this router",
                    "/interface/bridge/vlan/add",
                    {
                        "bridge": bridge_name,
                        "comment": f"3J Hotspot - VLAN {vlan_id} trunk from {previous_name} to OLT/APs",
                        "tagged": effective_tagged_ports,
                        "vlan-ids": str(vlan_id),
                    },
                    existing_query={"bridge": bridge_name, "vlan-ids": str(vlan_id)},
                    merge_bridge_vlan_tagged=True,
                ),
            ])
        router_plans.append({
            "router_id": str(router["router_id"]),
            "router_name": router.get("router_name"),
            "host": router.get("host"),
            "sequence_order": router.get("sequence_order", index),
            "role": role,
            "bridge_name": bridge_name,
            "tagged_ports": tagged_ports,
            "effective_tagged_ports": effective_tagged_ports,
            "commands": commands,
        })
    return {
        "summary": "Root router creates the AP management VLAN and customer HotSpot VLAN. Downstream routers carry both VLANs as tagged trunks toward OLT/AP paths.",
        "station_code": station.get("station_code"),
        "vlan_id": vlan_id,
        "client_network_cidr": network.with_prefixlen,
        "gateway_ip": str(station["gateway_ip"]),
        "pool_range": f"{station['pool_start_ip']}-{station['pool_end_ip']}",
        "dhcp_server_name": dhcp_server_name,
        "dhcp_lease_time": dhcp_lease_time,
        "create_dhcp_server": create_dhcp_server,
        "dns_servers": client_dns_servers,
        "router_upstream_dns_servers": upstream_dns_servers,
        "hotspot_profile_name": hotspot_profile_name,
        "hotspot_html_directory": hotspot_html_directory,
        "hotspot_dns_name": hotspot_dns_name,
        "hotspot_server_name": hotspot_server_name,
        "create_hotspot_profile": create_hotspot_profile,
        "create_hotspot_server": create_hotspot_server,
        "create_walled_garden": create_walled_garden,
        "portal_url": portal_url,
        "portal_host": portal_host,
        "portal_port": portal_port,
        "capport_url": capport_url,
        "capport_option_name": capport_option_name,
        "ap_management_enabled": ap_management_enabled,
        "ap_management_vlan_id": ap_management_vlan_id,
        "ap_management_vlan_interface_name": ap_management_vlan_interface_name,
        "ap_management_network_cidr": ap_management_network.with_prefixlen,
        "ap_management_gateway_ip": ap_management_gateway_ip,
        "ap_management_pool_range": f"{ap_management_pool_start_ip}-{ap_management_pool_end_ip}",
        "ap_management_pool_name": ap_management_pool_name,
        "ap_management_dhcp_server_name": ap_management_dhcp_server_name,
        "ap_management_dhcp_lease_time": ap_management_dhcp_lease_time,
        "ap_management_dns_servers": ap_management_dns_servers,
        "nat_comment": nat_comment,
        "dns_udp_redirect_comment": dns_udp_redirect_comment,
        "dns_tcp_redirect_comment": dns_tcp_redirect_comment,
        "raw_client_tracking_comment": raw_client_tracking_comment,
        "raw_return_tracking_comment": raw_return_tracking_comment,
        "private_dns_reject_comment": private_dns_reject_comment,
        "ipv6_ra_suppress_comment": ipv6_ra_suppress_comment,
        "router_plans": router_plans,
    }


def build_mikrotik_station_remove_plan(station: dict, routers: list[dict]) -> dict:
    vlan_id = int(station["vlan_id"])
    vlan_interface_name = station.get("vlan_interface_name") or f"VLAN{vlan_id}-3J-HOTSPOT"
    pool_name = station.get("pool_name") or f"POOL-3J-HOTSPOT-V{vlan_id}"
    dhcp_server_name = station.get("dhcp_server_name") or f"DHCP-3J-HOTSPOT-V{vlan_id}"
    hotspot_profile_name = station.get("hotspot_profile_name") or f"PROFILE-3J-HOTSPOT-V{vlan_id}"
    hotspot_server_name = station.get("hotspot_server_name") or f"HS-3J-HOTSPOT-V{vlan_id}"
    local_interface_list = station.get("local_interface_list") or "LOCAL"
    network = ip_network(station["client_network_cidr"], strict=False)
    nat_comment = f"3J Hotspot - NAT for VLAN {vlan_id} clients"
    dns_udp_redirect_comment = f"3J Hotspot - force DNS UDP to router for VLAN {vlan_id}"
    dns_tcp_redirect_comment = f"3J Hotspot - force DNS TCP to router for VLAN {vlan_id}"
    raw_client_tracking_comment = f"3J Hotspot - keep VLAN {vlan_id} client traffic tracked"
    raw_return_tracking_comment = f"3J Hotspot - keep VLAN {vlan_id} return traffic tracked"
    private_dns_reject_comment = f"3J Hotspot - reject Private DNS TLS for VLAN {vlan_id}"
    legacy_http_probe_redirect_comment = f"3J Hotspot - send unauth HTTP to portal for VLAN {vlan_id}"
    ipv6_ra_suppress_comment = f"3J Hotspot - suppress IPv6 RA on VLAN {vlan_id}"
    ap_management_enabled = bool(station.get("ap_management_enabled"))
    ap_management_vlan_id = int(station.get("ap_management_vlan_id") or 111)
    ap_management_vlan_interface_name = station.get("ap_management_vlan_interface_name") or f"VLAN{ap_management_vlan_id}-AP-MGMT"
    ap_management_pool_name = station.get("ap_management_pool_name") or f"POOL-AP-MGMT-V{ap_management_vlan_id}"
    ap_management_dhcp_server_name = station.get("ap_management_dhcp_server_name") or f"DHCP-AP-MGMT-V{ap_management_vlan_id}"
    router_plans = []
    for index, router in reversed(list(enumerate(routers))):
        bridge_name = (router.get("bridge_name") or "").strip()
        is_root = index == 0
        role = "ROOT_GATEWAY" if is_root else "TRUNK_HELPER"
        previous_name = routers[index - 1].get("router_name") if index > 0 else None
        commands = []
        if is_root:
            commands.extend([
                station_routeros_remove_command(
                    "Remove HotSpot server",
                    "/ip/hotspot/print",
                    "name",
                    hotspot_server_name,
                ),
                station_routeros_remove_command(
                    "Remove HotSpot profile",
                    "/ip/hotspot/profile/print",
                    "name",
                    hotspot_profile_name,
                ),
                station_routeros_remove_command(
                    "Remove walled garden DNS TCP",
                    "/ip/hotspot/walled-garden/ip/print",
                    "comment",
                    f"3J Hotspot - DNS TCP for VLAN {vlan_id}",
                ),
                station_routeros_remove_command(
                    "Remove walled garden DNS UDP",
                    "/ip/hotspot/walled-garden/ip/print",
                    "comment",
                    f"3J Hotspot - DNS UDP for VLAN {vlan_id}",
                ),
                station_routeros_remove_command(
                    "Remove walled garden portal URL",
                    "/ip/hotspot/walled-garden/ip/print",
                    "comment",
                    f"3J Hotspot - portal URL for VLAN {vlan_id}",
                ),
                station_routeros_remove_command(
                    "Remove walled garden portal server",
                    "/ip/hotspot/walled-garden/ip/print",
                    "comment",
                    f"3J Hotspot - portal server for VLAN {vlan_id}",
                ),
                station_routeros_remove_command(
                    "Remove VLAN from local/LAN interface list",
                    "/interface/list/member/print",
                    "comment",
                    f"3J Hotspot - allow VLAN {vlan_id} as local/LAN interface",
                ),
                station_routeros_remove_command(
                    "Remove internet NAT for HotSpot clients",
                    "/ip/firewall/nat/print",
                    "comment",
                    nat_comment,
                ),
                station_routeros_remove_command(
                    "Remove raw client tracking exception",
                    "/ip/firewall/raw/print",
                    "comment",
                    raw_client_tracking_comment,
                ),
                station_routeros_remove_command(
                    "Remove raw return tracking exception",
                    "/ip/firewall/raw/print",
                    "comment",
                    raw_return_tracking_comment,
                ),
                station_routeros_remove_command(
                    "Remove forced client DNS UDP redirect",
                    "/ip/firewall/nat/print",
                    "comment",
                    dns_udp_redirect_comment,
                ),
                station_routeros_remove_command(
                    "Remove forced client DNS TCP redirect",
                    "/ip/firewall/nat/print",
                    "comment",
                    dns_tcp_redirect_comment,
                ),
                station_routeros_remove_command(
                    "Remove Private DNS TLS reject rule",
                    "/ip/firewall/filter/print",
                    "comment",
                    private_dns_reject_comment,
                ),
                station_routeros_remove_command(
                    "Remove IPv6 RA suppression",
                    "/ipv6/nd/print",
                    "interface",
                    vlan_interface_name,
                ),
                station_routeros_remove_command(
                    "Remove legacy unauthenticated HTTP portal redirect",
                    "/ip/firewall/nat/print",
                    "comment",
                    legacy_http_probe_redirect_comment,
                ),
                station_routeros_remove_command(
                    "Remove DHCP network options",
                    "/ip/dhcp-server/network/print",
                    "comment",
                    f"3J Hotspot - DHCP options for VLAN {vlan_id}",
                ),
                station_routeros_remove_command(
                    "Remove DHCP captive portal option",
                    "/ip/dhcp-server/option/print",
                    "name",
                    f"3J-CAPPORT-V{vlan_id}",
                ),
                *[
                    station_routeros_remove_command(
                        f"Remove captive-check DNS {host}",
                        "/ip/dns/static/print",
                        "comment",
                        f"3J Hotspot - captive check DNS {host} for VLAN {vlan_id}",
                    )
                    for host in station_captive_dns_probe_hosts()
                ],
                station_routeros_remove_command(
                    "Remove DHCP server",
                    "/ip/dhcp-server/print",
                    "name",
                    dhcp_server_name,
                ),
                station_routeros_remove_command(
                    "Remove DHCP pool",
                    "/ip/pool/print",
                    "name",
                    pool_name,
                ),
                station_routeros_remove_command(
                    f"Remove VLAN {vlan_id} gateway IP",
                    "/ip/address/print",
                    "comment",
                    f"3J Hotspot - VLAN {vlan_id} gateway",
                ),
                station_routeros_remove_command(
                    f"Remove station-created bridge VLAN {vlan_id}",
                    "/interface/bridge/vlan/print",
                    "comment",
                    f"3J Hotspot - VLAN {vlan_id} trunk to next station router",
                ),
                station_routeros_remove_command(
                    f"Remove VLAN {vlan_id} interface",
                    "/interface/vlan/print",
                    "name",
                    vlan_interface_name,
                ),
            ])
            if ap_management_enabled:
                commands.extend([
                    station_routeros_remove_command(
                        "Remove AP management VLAN from local/LAN interface list",
                        "/interface/list/member/print",
                        "comment",
                        f"3J AP Management - allow VLAN {ap_management_vlan_id} as local/LAN interface",
                    ),
                    station_routeros_remove_command(
                        "Remove AP management DHCP server",
                        "/ip/dhcp-server/print",
                        "name",
                        ap_management_dhcp_server_name,
                    ),
                    station_routeros_remove_command(
                        "Remove AP management DHCP network options",
                        "/ip/dhcp-server/network/print",
                        "comment",
                        f"3J AP Management - DHCP options for VLAN {ap_management_vlan_id}",
                    ),
                    station_routeros_remove_command(
                        "Remove AP management DHCP pool",
                        "/ip/pool/print",
                        "name",
                        ap_management_pool_name,
                    ),
                    station_routeros_remove_command(
                        f"Remove AP management VLAN {ap_management_vlan_id} gateway IP",
                        "/ip/address/print",
                        "comment",
                        f"3J AP Management - VLAN {ap_management_vlan_id} gateway",
                    ),
                    station_routeros_remove_command(
                        f"Remove AP management bridge VLAN {ap_management_vlan_id}",
                        "/interface/bridge/vlan/print",
                        "comment",
                        f"3J AP Management - VLAN {ap_management_vlan_id} trunk to next station router",
                    ),
                    station_routeros_remove_command(
                        f"Remove AP management VLAN {ap_management_vlan_id} interface",
                        "/interface/vlan/print",
                        "name",
                        ap_management_vlan_interface_name,
                    ),
                ])
        else:
            commands.extend([
                station_routeros_remove_command(
                    f"Remove station-created bridge VLAN {vlan_id}",
                    "/interface/bridge/vlan/print",
                    "comment",
                    f"3J Hotspot - VLAN {vlan_id} trunk from {previous_name or 'previous router'} to OLT/APs",
                ),
                station_routeros_remove_command(
                    f"Remove VLAN {vlan_id} monitoring interface",
                    "/interface/vlan/print",
                    "name",
                    vlan_interface_name,
                ),
            ])
            if ap_management_enabled:
                commands.extend([
                    station_routeros_remove_command(
                        f"Remove AP management bridge VLAN {ap_management_vlan_id}",
                        "/interface/bridge/vlan/print",
                        "comment",
                        f"3J AP Management - VLAN {ap_management_vlan_id} trunk from {previous_name or 'previous router'} to OLT/APs",
                    ),
                    station_routeros_remove_command(
                        f"Remove AP management VLAN {ap_management_vlan_id} monitoring interface",
                        "/interface/vlan/print",
                        "name",
                        ap_management_vlan_interface_name,
                    ),
                ])
        router_plans.append({
            "router_id": str(router["router_id"]),
            "router_name": router.get("router_name"),
            "host": router.get("host"),
            "sequence_order": router.get("sequence_order", index),
            "role": role,
            "bridge_name": bridge_name,
            "commands": commands,
        })
    return {
        "summary": "Remove only station-created objects by exact station names/comments. Existing shared bridge VLAN rows are not deleted unless they carry the station-created comment.",
        "station_code": station.get("station_code"),
        "vlan_id": vlan_id,
        "client_network_cidr": network.with_prefixlen,
        "ap_management_enabled": ap_management_enabled,
        "ap_management_vlan_id": ap_management_vlan_id,
        "router_plans": router_plans,
    }


def mikrotik_hotspot_login_portal_url(station: Optional[dict] = None) -> str:
    return station_portal_url(station)


def mikrotik_hotspot_login_file_path(station: dict) -> str:
    directory = re.sub(r"/+", "/", str(station.get("hotspot_html_directory") or "hotspot").strip().replace("\\", "/")).strip("/")
    return f"{directory}/login.html" if directory else "login.html"


def build_mikrotik_hotspot_login_html(station: Optional[dict] = None) -> str:
    portal_url = mikrotik_hotspot_login_portal_url(station)
    parsed_portal = urlparse(portal_url if "://" in portal_url else f"http://{portal_url}")
    api_origin = f"{parsed_portal.scheme or 'http'}://{parsed_portal.netloc or '192.168.50.70'}"
    external_portal_url = f"{api_origin}/portal"
    escaped_portal_url = html.escape(external_portal_url, quote=True)
    js_api_origin = json.dumps(api_origin)
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>3J WiFi Voucher Login</title>
  <style>
    :root {{ color-scheme: light; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Arial, sans-serif; background: #eef4fb; color: #1f2937; }}
    main {{ width: min(430px, calc(100% - 28px)); background: #fff; border: 1px solid #dbe3ed; border-radius: 14px; padding: 24px; box-shadow: 0 18px 48px rgba(15,23,42,.12); }}
    .brand {{ text-align: center; margin-bottom: 18px; }}
    .logo {{ width: 58px; height: 58px; margin: 0 auto 12px; border-radius: 16px; display: grid; place-items: center; background: #206bc4; color: #fff; font-weight: 800; font-size: 22px; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ color: #64748b; line-height: 1.45; }}
    label {{ display: block; margin: 12px 0 7px; font-size: 14px; font-weight: 700; }}
    input {{ width: 100%; border: 1px solid #cbd5e1; border-radius: 10px; padding: 14px 12px; font-size: 20px; text-align: center; letter-spacing: 2px; text-transform: uppercase; }}
    button, a.button {{ width: 100%; display: inline-flex; align-items: center; justify-content: center; border: 0; margin-top: 14px; padding: 13px 16px; border-radius: 10px; background: #206bc4; color: #fff; text-decoration: none; font-weight: 800; font-size: 16px; }}
    button[disabled] {{ opacity: .72; }}
    .secondary {{ background: #edf2f7 !important; color: #334155 !important; }}
    .message {{ display: none; margin-top: 14px; padding: 12px; border-radius: 10px; font-weight: 700; line-height: 1.4; }}
    .message.ok {{ display: block; background: #dcfce7; color: #166534; }}
    .message.err {{ display: block; background: #fee2e2; color: #991b1b; }}
    .help {{ margin-top: 16px; font-size: 13px; text-align: center; color: #64748b; }}
  </style>
</head>
<body>
  <main>
    <div class="brand">
      <div class="logo">3J</div>
      <h1>3J WiFi</h1>
      <p>Enter your voucher to connect</p>
    </div>
    <form id="voucher-form">
      <label for="voucher-code">Voucher Code</label>
      <input id="voucher-code" name="voucher_code" autocomplete="one-time-code" required>
      <button id="submit-button" type="submit">Redeem / Connect</button>
    </form>
    <div id="message" class="message"></div>
    <a class="button secondary" href="{escaped_portal_url}">Open full portal</a>
    <div class="help">Need a voucher? Ask the nearest vendo/operator. If internet does not start after success, disconnect and reconnect to WiFi.</div>
    <noscript><p><a href="{escaped_portal_url}">Open voucher portal</a></p></noscript>
  </main>
  <script>
    (function () {{
      var apiOrigin = {js_api_origin};
      var values = {{
        gateway: "mikrotik",
        mac: "$(mac)",
        ip: "$(ip)",
        "server-name": "$(server-name)",
        "link-login": "$(link-login)",
        "link-login-only": "$(link-login-only)",
        "link-orig": "$(link-orig)",
        "chap-id": "$(chap-id)",
        "chap-challenge": "$(chap-challenge)",
        error: "$(error)"
      }};
      var context = {{
        gateway: "mikrotik",
        raw_query_params: {{}}
      }};
      Object.keys(values).forEach(function (key) {{
        var value = values[key] || "";
        if (value && value.indexOf("$(") !== 0) {{
          context.raw_query_params[key] = value;
          var normalized = key.replace(/-/g, "_");
          context[normalized] = value;
          if (key === "mac") context.client_mac = value;
          if (key === "ip") context.client_ip = value;
          if (key === "server-name") context.server_name = value;
        }}
      }});
      var form = document.getElementById("voucher-form");
      var input = document.getElementById("voucher-code");
      var button = document.getElementById("submit-button");
      var message = document.getElementById("message");
      input.addEventListener("input", function () {{
        input.value = input.value.toUpperCase();
      }});
      function show(type, text) {{
        message.className = "message " + type;
        message.textContent = text;
      }}
      form.addEventListener("submit", function (event) {{
        event.preventDefault();
        var code = (input.value || "").trim();
        if (!code) return;
        button.disabled = true;
        button.textContent = "Checking...";
        show("", "");
        fetch(apiOrigin + "/api/portal/redeem", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(Object.assign({{}}, context, {{ voucher_code: code }}))
        }})
          .then(function (response) {{ return response.json(); }})
          .then(function (data) {{
            if (data && data.status === "SUCCESS") {{
              show("ok", data.message || "Voucher accepted. You may now use the internet.");
              button.textContent = "Connected";
            }} else {{
              show("err", (data && (data.message || data.reason)) || "Voucher was not accepted.");
              button.disabled = false;
              button.textContent = "Redeem / Connect";
            }}
          }})
          .catch(function () {{
            show("err", "Could not contact the voucher server. Please ask the operator.");
            button.disabled = false;
            button.textContent = "Redeem / Connect";
          }});
      }});
    }})();
  </script>
</body>
</html>
"""


def mikrotik_hotspot_login_hash(station: Optional[dict] = None) -> str:
    return sha256(build_mikrotik_hotspot_login_html(station).encode()).hexdigest()


def latest_hotspot_login_sync_log(station_id: str) -> Optional[dict]:
    return fetch_one(
        """
        SELECT *
        FROM mikrotik_hotspot_login_sync_logs
        WHERE station_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (station_id,),
    )


def record_hotspot_login_sync_log(
    station_id: str,
    router_id: Optional[str],
    file_path: str,
    content_hash: str,
    status: str,
    message: str,
    result: Optional[dict],
    admin_id: Optional[str],
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_hotspot_login_sync_logs(
                    station_id, router_id, file_path, content_hash, sync_status,
                    message, result_json, synced_by_admin_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (station_id, router_id, file_path, content_hash, status, message, Json(sanitize_summary(result or {})), admin_id),
            )


def station_router_rows(station_id: str) -> list[dict]:
    return fetch_all(
        """
        SELECT sr.*, mr.router_name, mr.host, mr.api_port, mr.status AS api_status
        FROM mikrotik_station_routers sr
        JOIN mikrotik_routers mr ON mr.id = sr.router_id
        WHERE sr.station_id = %s
        ORDER BY sr.sequence_order ASC
        """,
        (station_id,),
    )


def public_mikrotik_station(row: dict) -> dict:
    routers = station_router_rows(str(row["id"]))
    login_file_path = mikrotik_hotspot_login_file_path(row)
    login_hash = mikrotik_hotspot_login_hash(row)
    latest_login_sync = latest_hotspot_login_sync_log(str(row["id"]))
    return {
        "id": row["id"],
        "station_name": row["station_name"],
        "station_code": row.get("station_code"),
        "description": row.get("description"),
        "vlan_id": row["vlan_id"],
        "vlan_interface_name": row.get("vlan_interface_name") or f"VLAN{row['vlan_id']}-3J-HOTSPOT",
        "client_network_cidr": row["client_network_cidr"],
        "gateway_ip": row["gateway_ip"],
        "pool_start_ip": row["pool_start_ip"],
        "pool_end_ip": row["pool_end_ip"],
        "pool_name": row.get("pool_name") or f"POOL-3J-HOTSPOT-V{row['vlan_id']}",
        "dhcp_server_name": row.get("dhcp_server_name") or f"DHCP-3J-HOTSPOT-V{row['vlan_id']}",
        "dhcp_lease_time": row.get("dhcp_lease_time") or "1h",
        "create_dhcp_server": bool(row.get("create_dhcp_server", True)),
        "dns_servers": row.get("dns_servers"),
        "local_interface_list": row.get("local_interface_list") or "LOCAL",
        "create_hotspot_profile": bool(row.get("create_hotspot_profile", True)),
        "create_hotspot_server": bool(row.get("create_hotspot_server", True)),
        "create_walled_garden": bool(row.get("create_walled_garden", True)),
        "hotspot_profile_name": row.get("hotspot_profile_name") or f"PROFILE-3J-HOTSPOT-V{row['vlan_id']}",
        "hotspot_html_directory": row.get("hotspot_html_directory") or "hotspot",
        "hotspot_dns_name": row.get("hotspot_dns_name"),
        "hotspot_server_name": row.get("hotspot_server_name") or f"HS-3J-HOTSPOT-V{row['vlan_id']}",
        "portal_url": station_portal_url(row),
        "ap_management_enabled": bool(row.get("ap_management_enabled")),
        "ap_management_vlan_id": row.get("ap_management_vlan_id"),
        "ap_management_vlan_interface_name": row.get("ap_management_vlan_interface_name") or (f"VLAN{row.get('ap_management_vlan_id')}-AP-MGMT" if row.get("ap_management_vlan_id") else None),
        "ap_management_network_cidr": row.get("ap_management_network_cidr"),
        "ap_management_gateway_ip": row.get("ap_management_gateway_ip"),
        "ap_management_pool_start_ip": row.get("ap_management_pool_start_ip"),
        "ap_management_pool_end_ip": row.get("ap_management_pool_end_ip"),
        "ap_management_pool_name": row.get("ap_management_pool_name") or (f"POOL-AP-MGMT-V{row.get('ap_management_vlan_id')}" if row.get("ap_management_vlan_id") else None),
        "ap_management_dhcp_server_name": row.get("ap_management_dhcp_server_name") or (f"DHCP-AP-MGMT-V{row.get('ap_management_vlan_id')}" if row.get("ap_management_vlan_id") else None),
        "ap_management_dhcp_lease_time": row.get("ap_management_dhcp_lease_time") or "1h",
        "ap_management_dns_servers": row.get("ap_management_dns_servers"),
        "hotspot_login_file_path": login_file_path,
        "hotspot_login_expected_hash": login_hash,
        "hotspot_login_sync": {
            "status": latest_login_sync.get("sync_status") if latest_login_sync else "NEVER_SYNCED",
            "message": latest_login_sync.get("message") if latest_login_sync else "Managed login.html has not been uploaded yet.",
            "file_path": latest_login_sync.get("file_path") if latest_login_sync else login_file_path,
            "content_hash": latest_login_sync.get("content_hash") if latest_login_sync else None,
            "expected_hash": login_hash,
            "is_current": bool(latest_login_sync and latest_login_sync.get("sync_status") == "SUCCESS" and latest_login_sync.get("content_hash") == login_hash),
            "created_at": latest_login_sync.get("created_at") if latest_login_sync else None,
        },
        "status": row["status"],
        "routers": [
            {
                "id": item["id"],
                "router_id": item["router_id"],
                "router_name": item["router_name"],
                "host": item["host"],
                "api_port": item["api_port"],
                "api_status": item["api_status"],
                "sequence_order": item["sequence_order"],
                "station_role": item["station_role"],
                "bridge_name": item.get("bridge_name"),
                "tagged_ports": item.get("tagged_ports"),
                "notes": item.get("notes"),
            }
            for item in routers
        ],
        "plan": build_mikrotik_station_plan(row, routers),
        "remove_plan": build_mikrotik_station_remove_plan(row, routers),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def ap_management_router_rows(config_id: str) -> list[dict]:
    return fetch_all(
        """
        SELECT ar.*, mr.router_name, mr.host, mr.api_port, mr.status AS api_status
        FROM mikrotik_ap_management_routers ar
        JOIN mikrotik_routers mr ON mr.id = ar.router_id
        WHERE ar.config_id = %s
        ORDER BY ar.sequence_order ASC
        """,
        (config_id,),
    )


def ap_management_default_config() -> dict:
    return {
        "id": None,
        "config_name": "Central AP Management",
        "vlan_id": 111,
        "vlan_interface_name": "VLAN111-AP-MGMT",
        "network_cidr": "10.111.0.0/24",
        "gateway_ip": "10.111.0.1",
        "pool_start_ip": "10.111.0.10",
        "pool_end_ip": "10.111.0.254",
        "pool_name": "POOL-AP-MGMT-V111",
        "dhcp_server_name": "DHCP-AP-MGMT-V111",
        "dhcp_lease_time": "1h",
        "dns_servers": "8.8.8.8,1.1.1.1",
        "local_interface_list": "LOCAL",
        "status": "DRAFT",
        "routers": [],
        "plan": {"router_plans": [], "summary": "Save AP management details before reviewing RouterOS steps."},
        "created_at": None,
        "updated_at": None,
    }


def normalize_ap_management_config_payload(payload: MikrotikApManagementConfigPayload) -> dict:
    defaults = station_default_ipv4_values(payload.network_cidr)
    network = defaults["network"]
    try:
        gateway_ip = ip_address(payload.gateway_ip or str(defaults["gateway_ip"]))
        pool_start = ip_address(payload.pool_start_ip or str(defaults["pool_start"]))
        pool_end = ip_address(payload.pool_end_ip or str(defaults["pool_end"]))
    except ValueError:
        raise HTTPException(status_code=400, detail="AP management gateway and pool values must be valid IPv4 addresses.")
    if any(value.version != 4 for value in (gateway_ip, pool_start, pool_end)):
        raise HTTPException(status_code=400, detail="AP management gateway and pool values must be IPv4 addresses.")
    if gateway_ip not in network:
        raise HTTPException(status_code=400, detail="AP management gateway IP must be inside the AP management subnet.")
    if gateway_ip in (network.network_address, network.broadcast_address):
        raise HTTPException(status_code=400, detail="AP management gateway IP cannot be the network or broadcast address.")
    if pool_start not in network or pool_end not in network:
        raise HTTPException(status_code=400, detail="AP management DHCP pool start and end must be inside the AP management subnet.")
    if int(pool_start) > int(pool_end):
        raise HTTPException(status_code=400, detail="AP management DHCP pool start must be lower than or equal to pool end.")
    if int(pool_start) <= int(gateway_ip) <= int(pool_end):
        raise HTTPException(status_code=400, detail="AP management DHCP pool cannot include the gateway IP.")
    for station in fetch_all("SELECT station_name, vlan_id, client_network_cidr FROM mikrotik_stations WHERE status <> 'ARCHIVED'"):
        if int(station["vlan_id"]) == int(payload.vlan_id):
            raise HTTPException(status_code=400, detail=f"AP management VLAN {payload.vlan_id} is already used as customer VLAN by station {station['station_name']}.")
        try:
            station_network = ip_network(station["client_network_cidr"], strict=False)
        except ValueError:
            station_network = None
        if station_network and network.overlaps(station_network):
            raise HTTPException(status_code=400, detail=f"AP management subnet {network.with_prefixlen} overlaps customer subnet {station_network.with_prefixlen} from station {station['station_name']}.")
    dns_servers = normalize_upstream_dns_servers(payload.dns_servers, str(gateway_ip))
    vlan_id = int(payload.vlan_id)
    return {
        "config_name": payload.config_name.strip(),
        "vlan_id": vlan_id,
        "vlan_interface_name": (payload.vlan_interface_name or "").strip() or f"VLAN{vlan_id}-AP-MGMT",
        "network": network,
        "gateway_ip": gateway_ip,
        "pool_start": pool_start,
        "pool_end": pool_end,
        "pool_name": (payload.pool_name or "").strip() or f"POOL-AP-MGMT-V{vlan_id}",
        "dhcp_server_name": (payload.dhcp_server_name or "").strip() or f"DHCP-AP-MGMT-V{vlan_id}",
        "dhcp_lease_time": (payload.dhcp_lease_time or "1h").strip() or "1h",
        "dns_servers": dns_servers,
        "local_interface_list": (payload.local_interface_list or "LOCAL").strip() or "LOCAL",
    }


def validate_ap_management_router_path(payload: MikrotikApManagementConfigPayload, normalized: dict, config_id: Optional[str] = None):
    if not payload.routers:
        raise HTTPException(status_code=400, detail="Add at least one MikroTik router to the AP management chain.")
    router_ids = [item.router_id for item in payload.routers]
    if len(router_ids) != len(set(router_ids)):
        raise HTTPException(status_code=400, detail="A MikroTik router can appear only once in the AP management chain.")
    existing_routers = fetch_all("SELECT id, router_name FROM mikrotik_routers WHERE id = ANY(%s::uuid[])", (router_ids,))
    existing_ids = {str(row["id"]) for row in existing_routers}
    missing_ids = [router_id for router_id in router_ids if router_id not in existing_ids]
    if missing_ids:
        raise HTTPException(status_code=400, detail="One or more selected MikroTik routers no longer exist.")
    errors = []
    vlan_id = normalized["vlan_id"]
    vlan_interface_name = normalized["vlan_interface_name"]
    for index, item in enumerate(payload.routers):
        router = fetch_one("SELECT id, router_name FROM mikrotik_routers WHERE id = %s", (item.router_id,))
        router_label = router["router_name"] if router else f"router #{index + 1}"
        if not (item.bridge_name or "").strip():
            errors.append(f"{router_label}: bridge/interface is required.")
        if not (item.tagged_ports or "").strip():
            errors.append(f"{router_label}: tagged ports are required.")
        scan, snapshot = station_snapshot_for_router(item.router_id)
        if not scan:
            errors.append(f"{router_label}: run a successful Preflight Scan before saving AP management.")
            continue
        if scan.get("scan_status") != "SUCCESS":
            errors.append(f"{router_label}: latest Preflight Scan failed. Re-scan before saving AP management.")
            continue
        bridge_name = (item.bridge_name or "").strip()
        port_names = [port.strip() for port in str(item.tagged_ports or "").split(",") if port.strip()]
        interfaces, live_interface_error, used_live_interfaces = station_interface_map_with_live_fallback(item.router_id, snapshot, [bridge_name, *port_names])
        if bridge_name and bridge_name not in interfaces:
            suffix = f" Live Detect Ports also failed: {live_interface_error}" if live_interface_error else ""
            errors.append(f"{router_label}: selected bridge/interface '{bridge_name}' was not found in the latest scan or live RouterOS interface detection.{suffix}")
        elif bridge_name and station_interface_is_pppoe(interfaces[bridge_name]):
            errors.append(f"{router_label}: '{bridge_name}' is PPPoE-related and cannot carry AP management VLAN.")
        for port_name in port_names:
            if port_name not in interfaces:
                suffix = f" Live Detect Ports also failed: {live_interface_error}" if live_interface_error else ""
                errors.append(f"{router_label}: tagged port '{port_name}' was not found in the latest scan or live RouterOS interface detection.{suffix}")
            elif station_interface_is_pppoe(interfaces[port_name]):
                errors.append(f"{router_label}: tagged port '{port_name}' is PPPoE-related and cannot carry AP management VLAN.")
        existing_vlan_ids = set()
        for row in mikrotik_snapshot_items(snapshot, "interface_vlans"):
            existing_vlan_ids.update(parse_routeros_vlan_ids(row.get("vlan-id")))
        for row in mikrotik_snapshot_items(snapshot, "bridge_vlans"):
            if routeros_truthy(row.get("dynamic")):
                continue
            existing_vlan_ids.update(parse_routeros_vlan_ids(row.get("vlan-ids")))
        if vlan_id in existing_vlan_ids and not station_existing_vlan_is_managed(snapshot, vlan_id, vlan_interface_name, f"3j ap management - vlan {vlan_id}"):
            errors.append(f"{router_label}: AP management VLAN {vlan_id} already exists in the latest scan and is not marked as system-managed.")
        if index == 0:
            for row in mikrotik_snapshot_items(snapshot, "ip_addresses"):
                existing_network = parse_routeros_ip_network(row.get("address"))
                existing_interface = str(row.get("interface") or "")
                existing_comment = str(row.get("comment") or "").lower()
                if existing_network and normalized["network"].overlaps(existing_network) and existing_interface != vlan_interface_name and f"3j ap management - vlan {vlan_id}" not in existing_comment:
                    errors.append(f"{router_label}: AP management subnet {normalized['network'].with_prefixlen} overlaps existing router network {existing_network} on {existing_interface or 'unknown interface'}.")
            proposed_pool = (int(normalized["pool_start"]), int(normalized["pool_end"]))
            for row in mikrotik_snapshot_items(snapshot, "ip_pools"):
                if str(row.get("name") or "") == normalized["pool_name"]:
                    continue
                for existing_range in parse_routeros_pool_ranges(row.get("ranges")):
                    if mikrotik_ranges_overlap(proposed_pool, existing_range):
                        errors.append(f"{router_label}: AP management DHCP pool {normalized['pool_start']}-{normalized['pool_end']} overlaps existing pool {row.get('name')}: {row.get('ranges')}.")
            for row in mikrotik_snapshot_items(snapshot, "dhcp_servers"):
                existing_name = str(row.get("name") or "")
                existing_interface = str(row.get("interface") or "")
                existing_comment = str(row.get("comment") or "").lower()
                if existing_name == normalized["dhcp_server_name"]:
                    continue
                if existing_interface == vlan_interface_name and f"3j ap management - dhcp server for vlan {vlan_id}" not in existing_comment:
                    errors.append(f"{router_label}: DHCP server already exists on {vlan_interface_name}.")
    if errors:
        raise HTTPException(status_code=400, detail=" ".join(errors))


def build_mikrotik_ap_management_plan(config: dict, routers: list[dict]) -> dict:
    vlan_id = int(config["vlan_id"])
    network = ip_network(config["network_cidr"], strict=False)
    vlan_interface_name = config.get("vlan_interface_name") or f"VLAN{vlan_id}-AP-MGMT"
    pool_name = config.get("pool_name") or f"POOL-AP-MGMT-V{vlan_id}"
    dhcp_server_name = config.get("dhcp_server_name") or f"DHCP-AP-MGMT-V{vlan_id}"
    dhcp_lease_time = config.get("dhcp_lease_time") or "1h"
    dns_servers = normalize_upstream_dns_servers(config.get("dns_servers"), str(config["gateway_ip"]))
    local_interface_list = config.get("local_interface_list") or "LOCAL"
    router_plans = []
    for index, router in enumerate(routers):
        bridge_name = (router.get("bridge_name") or "").strip()
        tagged_ports = (router.get("tagged_ports") or "").strip()
        effective_tagged_ports = station_dedupe_csv(bridge_name, tagged_ports)
        is_root = index == 0
        role = "ROOT_GATEWAY" if is_root else "TRUNK_HELPER"
        commands = []
        if is_root:
            commands.extend([
                station_routeros_add_command(
                    f"Create AP management VLAN {vlan_id} interface",
                    "/interface/vlan/add",
                    {
                        "comment": f"3J AP Management - VLAN {vlan_id} interface on {bridge_name}",
                        "interface": bridge_name,
                        "name": vlan_interface_name,
                        "vlan-id": str(vlan_id),
                    },
                    unique_field="name",
                    unique_value=vlan_interface_name,
                ),
                station_routeros_add_command(
                    f"Tag AP management VLAN {vlan_id} toward AP path",
                    "/interface/bridge/vlan/add",
                    {
                        "bridge": bridge_name,
                        "comment": f"3J AP Management - VLAN {vlan_id} trunk to AP path",
                        "tagged": effective_tagged_ports,
                        "vlan-ids": str(vlan_id),
                    },
                    existing_query={"bridge": bridge_name, "vlan-ids": str(vlan_id)},
                    merge_bridge_vlan_tagged=True,
                ),
                station_routeros_add_command(
                    f"Add AP management VLAN {vlan_id} gateway IP",
                    "/ip/address/add",
                    {
                        "address": f"{config['gateway_ip']}/{network.prefixlen}",
                        "comment": f"3J AP Management - VLAN {vlan_id} gateway",
                        "interface": vlan_interface_name,
                        "network": str(network.network_address),
                    },
                    unique_comment=f"3J AP Management - VLAN {vlan_id} gateway",
                ),
                station_routeros_add_command(
                    "Create AP management DHCP pool",
                    "/ip/pool/add",
                    {
                        "name": pool_name,
                        "ranges": f"{config['pool_start_ip']}-{config['pool_end_ip']}",
                    },
                    unique_field="name",
                    unique_value=pool_name,
                ),
                station_routeros_add_command(
                    "Create AP management DHCP server",
                    "/ip/dhcp-server/add",
                    {
                        "name": dhcp_server_name,
                        "interface": vlan_interface_name,
                        "address-pool": pool_name,
                        "lease-time": dhcp_lease_time,
                        "disabled": "no",
                    },
                    unique_field="name",
                    unique_value=dhcp_server_name,
                ),
                station_routeros_add_command(
                    "Add AP management DHCP network options",
                    "/ip/dhcp-server/network/add",
                    {
                        "address": network.with_prefixlen,
                        "comment": f"3J AP Management - DHCP options for VLAN {vlan_id}",
                        "dns-server": dns_servers,
                        "gateway": str(config["gateway_ip"]),
                    },
                    existing_query={"address": network.with_prefixlen},
                ),
                station_routeros_add_command(
                    "Allow AP management VLAN as local/LAN interface",
                    "/interface/list/member/add",
                    {
                        "comment": f"3J AP Management - allow VLAN {vlan_id} as local/LAN interface",
                        "interface": vlan_interface_name,
                        "list": local_interface_list,
                    },
                    existing_query={"interface": vlan_interface_name, "list": local_interface_list},
                ),
            ])
        else:
            previous_name = routers[index - 1].get("router_name") or "previous router"
            commands.extend([
                station_routeros_add_command(
                    f"Create AP management VLAN {vlan_id} monitoring interface",
                    "/interface/vlan/add",
                    {
                        "comment": f"3J AP Management - VLAN {vlan_id} monitor interface on {bridge_name}",
                        "interface": bridge_name,
                        "name": vlan_interface_name,
                        "vlan-id": str(vlan_id),
                    },
                    unique_field="name",
                    unique_value=vlan_interface_name,
                ),
                station_routeros_add_command(
                    f"Carry AP management VLAN {vlan_id} through this router",
                    "/interface/bridge/vlan/add",
                    {
                        "bridge": bridge_name,
                        "comment": f"3J AP Management - VLAN {vlan_id} trunk from {previous_name} to OLT/APs",
                        "tagged": effective_tagged_ports,
                        "vlan-ids": str(vlan_id),
                    },
                    existing_query={"bridge": bridge_name, "vlan-ids": str(vlan_id)},
                    merge_bridge_vlan_tagged=True,
                ),
            ])
        router_plans.append({
            "router_id": str(router["router_id"]),
            "router_name": router.get("router_name"),
            "host": router.get("host"),
            "sequence_order": router.get("sequence_order", index),
            "role": role,
            "bridge_name": bridge_name,
            "tagged_ports": tagged_ports,
            "effective_tagged_ports": effective_tagged_ports,
            "commands": commands,
        })
    return {
        "summary": "Central AP management creates one AP management VLAN/subnet on the root gateway and carries that VLAN through selected downstream routers toward OLT/AP paths.",
        "vlan_id": vlan_id,
        "vlan_interface_name": vlan_interface_name,
        "network_cidr": network.with_prefixlen,
        "gateway_ip": str(config["gateway_ip"]),
        "pool_range": f"{config['pool_start_ip']}-{config['pool_end_ip']}",
        "pool_name": pool_name,
        "dhcp_server_name": dhcp_server_name,
        "dhcp_lease_time": dhcp_lease_time,
        "dns_servers": dns_servers,
        "router_plans": router_plans,
    }


def public_mikrotik_ap_management_config(row: Optional[dict]) -> dict:
    if not row:
        return ap_management_default_config()
    routers = ap_management_router_rows(str(row["id"]))
    return {
        "id": row["id"],
        "config_name": row["config_name"],
        "vlan_id": row["vlan_id"],
        "vlan_interface_name": row.get("vlan_interface_name") or f"VLAN{row['vlan_id']}-AP-MGMT",
        "network_cidr": row["network_cidr"],
        "gateway_ip": row["gateway_ip"],
        "pool_start_ip": row["pool_start_ip"],
        "pool_end_ip": row["pool_end_ip"],
        "pool_name": row.get("pool_name") or f"POOL-AP-MGMT-V{row['vlan_id']}",
        "dhcp_server_name": row.get("dhcp_server_name") or f"DHCP-AP-MGMT-V{row['vlan_id']}",
        "dhcp_lease_time": row.get("dhcp_lease_time") or "1h",
        "dns_servers": row.get("dns_servers"),
        "local_interface_list": row.get("local_interface_list") or "LOCAL",
        "status": row["status"],
        "routers": [
            {
                "id": item["id"],
                "router_id": item["router_id"],
                "router_name": item["router_name"],
                "host": item["host"],
                "api_port": item["api_port"],
                "api_status": item["api_status"],
                "sequence_order": item["sequence_order"],
                "router_role": item["router_role"],
                "bridge_name": item.get("bridge_name"),
                "tagged_ports": item.get("tagged_ports"),
                "notes": item.get("notes"),
            }
            for item in routers
        ],
        "plan": build_mikrotik_ap_management_plan(row, routers),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def record_ap_management_command_log(config_id: str, router_id: Optional[str], action: str, command_index: Optional[int], command: Optional[dict], status: str, message: str, result: Optional[dict], admin_id: Optional[str]):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_ap_management_command_logs(
                    config_id, router_id, action, command_index, command_label, command_preview,
                    status, message, result_json, created_by_admin_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    config_id,
                    router_id,
                    action,
                    command_index,
                    (command or {}).get("label"),
                    (command or {}).get("preview"),
                    status,
                    message,
                    Json(sanitize_summary(result or {})),
                    admin_id,
                ),
            )


def public_ap_management_command_log(row: dict) -> dict:
    return {
        "id": row["id"],
        "config_id": row["config_id"],
        "router_id": row["router_id"],
        "action": row["action"],
        "command_index": row["command_index"],
        "command_label": row["command_label"],
        "command_preview": row["command_preview"],
        "command_status": row["status"],
        "message": row["message"],
        "result": row.get("result_json") or {},
        "router_name": row.get("router_name"),
        "host": row.get("host"),
        "created_at": row["created_at"],
    }


def record_station_command_log(
    station_id: str,
    router_id: Optional[str],
    operation: str,
    command_index: Optional[int],
    command: Optional[dict],
    status: str,
    message: Optional[str],
    result: Optional[dict],
    admin_id: Optional[str],
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_station_command_logs(
                    station_id, router_id, operation, command_index, command_label,
                    command_preview, command_status, message, result_json, created_by_admin_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    station_id,
                    router_id,
                    operation,
                    command_index,
                    (command or {}).get("label"),
                    (command or {}).get("preview"),
                    status,
                    message,
                    Json(sanitize_summary(result or {})),
                    admin_id,
                ),
            )


def public_station_command_log(row: dict) -> dict:
    return {
        "id": row["id"],
        "station_id": row["station_id"],
        "router_id": row["router_id"],
        "operation": row["operation"],
        "command_index": row["command_index"],
        "command_label": row["command_label"],
        "command_preview": row["command_preview"],
        "command_status": row["command_status"],
        "message": row["message"],
        "result": row.get("result_json") or {},
        "router_name": row.get("router_name"),
        "host": row.get("host"),
        "created_at": row["created_at"],
    }


def station_root_router(station_id: str) -> Optional[dict]:
    routers = station_router_rows(station_id)
    return routers[0] if routers else None


def mikrotik_hotspot_login_sync_status_for_station(station: dict, remote_check: bool = True) -> dict:
    station_id = str(station["id"])
    root = station_root_router(station_id)
    file_path = mikrotik_hotspot_login_file_path(station)
    expected_hash = mikrotik_hotspot_login_hash(station)
    latest_sync = latest_hotspot_login_sync_log(station_id)
    base = {
        "station_id": station_id,
        "station_name": station.get("station_name"),
        "router_id": root.get("router_id") if root else None,
        "router_name": root.get("router_name") if root else None,
        "host": root.get("host") if root else None,
        "file_path": file_path,
        "expected_hash": expected_hash,
        "latest_sync": {
            "status": latest_sync.get("sync_status") if latest_sync else "NEVER_SYNCED",
            "message": latest_sync.get("message") if latest_sync else None,
            "content_hash": latest_sync.get("content_hash") if latest_sync else None,
            "created_at": latest_sync.get("created_at") if latest_sync else None,
        },
    }
    if not root:
        return {**base, "status": "NOT_READY", "message": "Station has no root gateway router."}
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (root["router_id"],))
    if not router or not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        return {**base, "status": "NOT_READY", "message": "Root gateway host, username, and password are required before checking login.html."}
    if not remote_check:
        if latest_sync and latest_sync.get("sync_status") == "SUCCESS" and latest_sync.get("content_hash") == expected_hash:
            return {**base, "status": "SYNCED", "message": "Latest recorded sync matches the current managed login.html."}
        return {**base, "status": "UNKNOWN", "message": "Run Check Sync to verify the file on MikroTik."}
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        rows = []
        detected_file_path = file_path
        for candidate in routeros_hotspot_file_candidates(file_path):
            rows = routeros_file_query(router["host"], router["api_port"], router.get("username"), password, router.get("use_tls"), candidate)
            if rows:
                detected_file_path = candidate
                break
        if not rows:
            return {**base, "status": "MISSING", "message": f"{file_path} was not detected on the root gateway.", "checked_paths": routeros_hotspot_file_candidates(file_path)}
        contents = rows[0].get("contents")
        if contents is not None:
            size_text = rows[0].get("size")
            try:
                remote_size = int(size_text) if size_text not in (None, "") else 0
            except (TypeError, ValueError):
                remote_size = 0
            content_truncated = "[TRUNCATED]" in contents or (remote_size and len(contents) < remote_size)
            if content_truncated and latest_sync and latest_sync.get("sync_status") == "SUCCESS" and latest_sync.get("content_hash") == expected_hash:
                return {**base, "file_path": detected_file_path, "status": "SYNCED", "message": f"{detected_file_path} exists. RouterOS returned truncated file contents, but the last recorded sync matches the current managed login.html."}
            remote_hash = sha256(contents.encode()).hexdigest()
            if remote_hash == expected_hash:
                return {**base, "file_path": detected_file_path, "status": "SYNCED", "message": f"{detected_file_path} exists and matches the current managed login.html.", "remote_hash": remote_hash}
            return {**base, "file_path": detected_file_path, "status": "OUTDATED", "message": f"{detected_file_path} exists but does not match the current managed login.html.", "remote_hash": remote_hash}
        if latest_sync and latest_sync.get("sync_status") == "SUCCESS" and latest_sync.get("content_hash") == expected_hash:
            return {**base, "file_path": detected_file_path, "status": "SYNCED", "message": f"{detected_file_path} exists. RouterOS did not return file contents, but the last recorded sync matches the current template."}
        return {**base, "file_path": detected_file_path, "status": "DETECTED", "message": f"{detected_file_path} exists, but RouterOS did not return file contents for hash verification."}
    except Exception as exc:
        return {**base, "status": "ERROR", "message": sanitize_routeros_text(str(exc))}


def mikrotik_station_hotspot_diagnostics(station: dict, client_ip: Optional[str] = None) -> dict:
    station_id = str(station["id"])
    root = station_root_router(station_id)
    checks = []

    def add_check(key: str, title: str, status: str, message: str, details: Optional[dict] = None):
        checks.append({
            "key": key,
            "title": title,
            "status": status,
            "message": message,
            "details": sanitize_summary(details or {}),
        })

    station_summary = {
        "station_id": station_id,
        "station_name": station.get("station_name"),
        "vlan_id": station.get("vlan_id"),
        "client_network_cidr": station.get("client_network_cidr"),
        "gateway_ip": station.get("gateway_ip"),
        "hotspot_server_name": station_hotspot_server_name(station),
        "hotspot_profile_name": station.get("hotspot_profile_name") or f"PROFILE-3J-HOTSPOT-V{station['vlan_id']}",
        "hotspot_interface": station.get("vlan_interface_name") or f"VLAN{station['vlan_id']}-3J-HOTSPOT",
        "portal_url": station_portal_url(station),
        "client_ip": client_ip,
    }
    if not root:
        add_check("root_gateway", "Root gateway", "FAILED", "Station has no root gateway router.")
        return {"status": "FAILED", "station": station_summary, "root_router": None, "checks": checks}

    station_summary["root_router_id"] = str(root["router_id"])
    station_summary["root_router_name"] = root.get("router_name")
    station_summary["root_router_host"] = root.get("host")
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (root["router_id"],))
    if not router or not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        add_check("root_gateway", "Root gateway API", "FAILED", "Root gateway API credentials are incomplete.")
        return {"status": "FAILED", "station": station_summary, "root_router": sanitize_summary(root), "checks": checks}

    try:
        password = decrypt_secret(router.get("password_encrypted"))
        if not password:
            raise RuntimeError("Saved MikroTik password could not be decrypted.")
    except Exception as exc:
        add_check("root_gateway", "Root gateway API", "FAILED", sanitize_routeros_text(str(exc)))
        return {"status": "FAILED", "station": station_summary, "root_router": sanitize_summary(root), "checks": checks}

    def query(path: str, *extra_words: str):
        return routeros_readonly_query(
            router["host"],
            router["api_port"],
            router.get("username"),
            password,
            router.get("use_tls"),
            [path, *extra_words],
        )

    try:
        identity = query("/system/identity/print")
        add_check("api_login", "RouterOS API login", "OK", "Root gateway API login works.", {"identity": identity[:1]})
    except Exception as exc:
        add_check("api_login", "RouterOS API login", "FAILED", sanitize_routeros_text(str(exc)))
        return {"status": "FAILED", "station": station_summary, "root_router": sanitize_summary(root), "checks": checks}

    profile_name = station_summary["hotspot_profile_name"]
    server_name = station_summary["hotspot_server_name"]
    hotspot_interface = station_summary["hotspot_interface"]
    portal_host = urlparse(station_summary["portal_url"] if "://" in station_summary["portal_url"] else f"http://{station_summary['portal_url']}").hostname
    portal_port = urlparse(station_summary["portal_url"] if "://" in station_summary["portal_url"] else f"http://{station_summary['portal_url']}").port or 80

    try:
        rows = query("/ip/hotspot/profile/print", f"?name={profile_name}", "=.proplist=.id,name,dns-name,html-directory,login-by,hotspot-address")
        add_check("hotspot_profile", "HotSpot profile", "OK" if rows else "FAILED", f"HotSpot profile {profile_name} {'exists' if rows else 'was not found'}.", {"rows": rows})
    except Exception as exc:
        add_check("hotspot_profile", "HotSpot profile", "FAILED", sanitize_routeros_text(str(exc)))

    try:
        rows = query("/ip/hotspot/print", f"?name={server_name}", "=.proplist=.id,name,interface,profile,address-pool,disabled")
        if rows:
            server = rows[0]
            disabled = routeros_truthy(server.get("disabled"))
            interface_matches = server.get("interface") == hotspot_interface
            status = "OK" if not disabled and interface_matches else "WARNING"
            message = f"HotSpot server {server_name} is {'disabled' if disabled else 'enabled'} on {server.get('interface') or 'unknown interface'}."
            if not interface_matches:
                message += f" Expected interface {hotspot_interface}."
            add_check("hotspot_server", "HotSpot server", status, message, {"rows": rows})
        else:
            add_check("hotspot_server", "HotSpot server", "FAILED", f"HotSpot server {server_name} was not found.")
    except Exception as exc:
        add_check("hotspot_server", "HotSpot server", "FAILED", sanitize_routeros_text(str(exc)))

    login_status = mikrotik_hotspot_login_sync_status_for_station(station, remote_check=True)
    add_check(
        "login_html",
        "Managed login.html",
        "OK" if login_status.get("status") == "SYNCED" else "WARNING",
        login_status.get("message") or "Managed login.html status checked.",
        login_status,
    )

    try:
        dhcp_name = station.get("dhcp_server_name") or f"DHCP-3J-HOTSPOT-V{station['vlan_id']}"
        rows = query("/ip/dhcp-server/print", f"?name={dhcp_name}", "=.proplist=.id,name,interface,address-pool,disabled")
        add_check("dhcp_server", "DHCP server", "OK" if rows else "WARNING", "DHCP server exists on the root gateway." if rows else "DHCP server was not found by expected station name.", {"rows": rows})
    except Exception as exc:
        add_check("dhcp_server", "DHCP server", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        dhcp_name = station.get("dhcp_server_name") or f"DHCP-3J-HOTSPOT-V{station['vlan_id']}"
        lease_rows = query(
            "/ip/dhcp-server/lease/print",
            "=.proplist=.id,address,mac-address,host-name,status,last-seen,server,dynamic",
        )
        station_leases_by_mac = {}
        non_station_leases_by_mac = {}
        ap_like_station_leases = []
        for row in lease_rows:
            mac = str(row.get("mac-address") or "").upper()
            if not mac:
                continue
            host_name = str(row.get("host-name") or "")
            if row.get("server") == dhcp_name:
                station_leases_by_mac.setdefault(mac, []).append(row)
                if re.search(r"(EAP\d*|^AP[-_]|OMADA|ACCESS[-_ ]?POINT)", host_name, re.IGNORECASE):
                    ap_like_station_leases.append(row)
            else:
                non_station_leases_by_mac.setdefault(mac, []).append(row)
        leaked_macs = []
        for mac, station_rows in station_leases_by_mac.items():
            other_rows = [
                row for row in non_station_leases_by_mac.get(mac, [])
                if str(row.get("status") or "").lower() == "bound"
            ]
            if other_rows:
                leaked_macs.append({"mac": mask_mac(mac), "station_leases": station_rows, "other_leases": other_rows})
        if leaked_macs:
            add_check(
                "client_vlan_isolation",
                "Captive VLAN isolation",
                "FAILED",
                "At least one client MAC has both a HotSpot VLAN lease and a normal/non-station DHCP lease. The captive SSID is not isolated to the station VLAN, so phones can bypass the HotSpot popup path.",
                {"dhcp_server": dhcp_name, "overlaps": leaked_macs[:10]},
            )
        elif ap_like_station_leases:
            add_check(
                "client_vlan_isolation",
                "Captive VLAN isolation",
                "WARNING",
                "AP-looking devices are receiving leases from the captive client DHCP server. AP management should normally stay on the management/native network while only SSID client traffic uses the HotSpot VLAN.",
                {"dhcp_server": dhcp_name, "ap_like_station_leases": ap_like_station_leases[:10]},
            )
        else:
            add_check(
                "client_vlan_isolation",
                "Captive VLAN isolation",
                "OK",
                "No duplicate MAC was found between the station HotSpot DHCP server and other DHCP servers on the root gateway.",
                {"dhcp_server": dhcp_name},
            )
    except Exception as exc:
        add_check("client_vlan_isolation", "Captive VLAN isolation", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        rows = query("/ip/dns/print", "=.proplist=allow-remote-requests,servers")
        dns_enabled = any(routeros_truthy(row.get("allow-remote-requests")) for row in rows)
        add_check(
            "dns_resolver",
            "Router DNS for phone popup detection",
            "OK" if dns_enabled else "FAILED",
            "RouterOS DNS remote requests are enabled for captive-check lookups." if dns_enabled else "RouterOS DNS remote requests are disabled. Phones may not resolve captive-check domains, so the WiFi sign-in popup may not appear.",
            {"rows": rows},
        )
    except Exception as exc:
        add_check("dns_resolver", "Router DNS for phone popup detection", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        rows = query("/ip/dhcp-server/network/print", f"?address={station['client_network_cidr']}", "=.proplist=.id,address,gateway,dns-server,comment")
        dns_text = ",".join(str(row.get("dns-server") or "") for row in rows)
        expected_dns = str(station["gateway_ip"])
        dns_values = [item.strip() for item in dns_text.split(",") if item.strip()]
        dns_gateway_only = rows and dns_values == [expected_dns]
        add_check(
            "dhcp_dns_options",
            "DHCP DNS options",
            "OK" if dns_gateway_only else "WARNING",
            "DHCP gives captive clients only the HotSpot gateway as DNS." if dns_gateway_only else "DHCP DNS should be only the station gateway IP. Public DNS should stay on the MikroTik resolver, not be handed directly to captive clients.",
            {"expected_client_dns": expected_dns, "actual_client_dns": dns_values, "rows": rows},
        )
    except Exception as exc:
        add_check("dhcp_dns_options", "DHCP DNS options", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        udp_comment = f"3J Hotspot - force DNS UDP to router for VLAN {station['vlan_id']}"
        tcp_comment = f"3J Hotspot - force DNS TCP to router for VLAN {station['vlan_id']}"
        udp_rows = query("/ip/firewall/nat/print", f"?comment={udp_comment}", "=.proplist=.id,chain,action,src-address,protocol,dst-port,to-ports,disabled,comment")
        tcp_rows = query("/ip/firewall/nat/print", f"?comment={tcp_comment}", "=.proplist=.id,chain,action,src-address,protocol,dst-port,to-ports,disabled,comment")
        udp_ok = any(row.get("chain") == "dstnat" and row.get("action") == "redirect" and row.get("src-address") == station["client_network_cidr"] and row.get("protocol") == "udp" and str(row.get("dst-port") or "") == "53" and not routeros_truthy(row.get("disabled")) for row in udp_rows)
        tcp_ok = any(row.get("chain") == "dstnat" and row.get("action") == "redirect" and row.get("src-address") == station["client_network_cidr"] and row.get("protocol") == "tcp" and str(row.get("dst-port") or "") == "53" and not routeros_truthy(row.get("disabled")) for row in tcp_rows)
        add_check(
            "dns_redirect",
            "Client DNS redirect",
            "OK" if udp_ok and tcp_ok else "WARNING",
            "Client DNS attempts are redirected to the HotSpot gateway." if udp_ok and tcp_ok else "DNS redirect rules are incomplete. Phones may bypass captive detection with public/private DNS.",
            {"udp_rows": udp_rows, "tcp_rows": tcp_rows},
        )
    except Exception as exc:
        add_check("dns_redirect", "Client DNS redirect", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        private_dns_comment = f"3J Hotspot - reject Private DNS TLS for VLAN {station['vlan_id']}"
        rows = query(
            "/ip/firewall/filter/print",
            f"?comment={private_dns_comment}",
            "=.proplist=.id,chain,action,src-address,protocol,dst-port,reject-with,disabled,comment",
        )
        has_reject = any(
            row.get("chain") == "input"
            and row.get("action") == "reject"
            and row.get("src-address") == station["client_network_cidr"]
            and row.get("protocol") == "tcp"
            and str(row.get("dst-port") or "") == "853"
            and str(row.get("reject-with") or "") == "tcp-reset"
            and not routeros_truthy(row.get("disabled"))
            for row in rows
        )
        add_check(
            "private_dns_tls_reject",
            "Private DNS captive fallback",
            "OK" if has_reject else "WARNING",
            "TCP 853 Private DNS is rejected with TCP reset for station clients, so Android can fall back to normal captive DNS checks." if has_reject else "No station rule rejects TCP 853 Private DNS. Some Android phones may keep trying DNS-over-TLS and never reach the normal captive portal HTTP check.",
            {"rows": rows},
        )
    except Exception as exc:
        add_check("private_dns_tls_reject", "Private DNS captive fallback", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        rows = query(
            "/ip/firewall/nat/print",
            "=.proplist=.id,chain,action,src-address,protocol,dst-port,to-ports,disabled,comment",
        )
        conflicting_rows = [
            row for row in rows
            if row.get("chain") == "dstnat"
            and row.get("action") == "redirect"
            and str(row.get("dst-port") or "") in {"80,443", "443,80"}
            and str(row.get("to-ports") or "") == "8081"
            and not row.get("src-address")
            and not routeros_truthy(row.get("disabled"))
        ]
        add_check(
            "legacy_web_proxy_redirect",
            "Legacy web-proxy redirect",
            "WARNING" if conflicting_rows else "OK",
            "A global TCP 80/443 redirect to MikroTik web proxy port 8081 is enabled and can interfere with HotSpot captive portal redirects." if conflicting_rows else "No enabled global TCP 80/443 web-proxy redirect was detected.",
            {"rows": conflicting_rows},
        )
    except Exception as exc:
        add_check("legacy_web_proxy_redirect", "Legacy web-proxy redirect", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        rows = query(
            "/ipv6/nd/print",
            "=.proplist=.id,interface,disabled,advertise-dns,ra-lifetime,comment",
        )
        expected_interface = station.get("vlan_interface_name") or f"VLAN{station['vlan_id']}-3J-HOTSPOT"
        suppress_ok = any(
            row.get("interface") == expected_interface
            and not routeros_truthy(row.get("disabled"))
            and not routeros_truthy(row.get("advertise-dns"))
            and str(row.get("ra-lifetime") or "").lower() in {"0s", "none"}
            for row in rows
        )
        add_check(
            "ipv6_ra_suppression",
            "IPv6 RA suppression",
            "OK" if suppress_ok else "WARNING",
            "IPv6 router advertisements are suppressed on the station HotSpot VLAN. Captive portal enforcement remains IPv4-only." if suppress_ok else "IPv6 router advertisements may still be active on the station VLAN. Phones may try IPv6 and bypass the IPv4 HotSpot redirect path.",
            {"expected_interface": expected_interface, "rows": rows},
        )
    except Exception as exc:
        add_check("ipv6_ra_suppression", "IPv6 RA suppression", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        capport_option_name = f"3J-CAPPORT-V{station['vlan_id']}"
        capport_url = station_capport_url(station)
        option_rows = query("/ip/dhcp-server/option/print", f"?name={capport_option_name}", "=.proplist=.id,name,code,value")
        network_rows = query("/ip/dhcp-server/network/print", f"?address={station['client_network_cidr']}", "=.proplist=.id,address,dhcp-option")
        option_exists = bool(option_rows)
        network_has_option = any(capport_option_name in str(row.get("dhcp-option") or "") for row in network_rows)
        add_check(
            "capport_dhcp_option",
            "DHCP captive portal option",
            "OK" if option_exists and network_has_option else "WARNING",
            "DHCP option 114 advertises the captive portal API to supported phones." if option_exists and network_has_option else "DHCP option 114 is not fully attached. Some phones may not auto-open the captive portal popup.",
            {"option_name": capport_option_name, "capport_url": capport_url, "option_rows": option_rows, "network_rows": network_rows},
        )
    except Exception as exc:
        add_check("capport_dhcp_option", "DHCP captive portal option", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        nat_comment = f"3J Hotspot - NAT for VLAN {station['vlan_id']} clients"
        rows = query(
            "/ip/firewall/nat/print",
            f"?comment={nat_comment}",
            "=.proplist=.id,chain,action,src-address,out-interface,out-interface-list,comment,disabled",
        )
        enabled_rows = [row for row in rows if not routeros_truthy(row.get("disabled"))]
        has_station_nat = any(
            row.get("chain") == "srcnat"
            and row.get("action") == "masquerade"
            and row.get("src-address") == station["client_network_cidr"]
            for row in enabled_rows
        )
        add_check(
            "internet_nat",
            "Internet NAT",
            "OK" if has_station_nat else "FAILED",
            "NAT masquerade exists for the station client subnet." if has_station_nat else "No enabled station NAT masquerade was found. Authorized clients may not have internet.",
            {"expected_comment": nat_comment, "expected_src_address": station["client_network_cidr"], "rows": rows},
        )
    except Exception as exc:
        add_check("internet_nat", "Internet NAT", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        client_tracking_comment = f"3J Hotspot - keep VLAN {station['vlan_id']} client traffic tracked"
        return_tracking_comment = f"3J Hotspot - keep VLAN {station['vlan_id']} return traffic tracked"
        client_rows = query("/ip/firewall/raw/print", f"?comment={client_tracking_comment}", "=.proplist=.id,chain,action,src-address,dst-address,disabled,comment")
        return_rows = query("/ip/firewall/raw/print", f"?comment={return_tracking_comment}", "=.proplist=.id,chain,action,src-address,dst-address,disabled,comment")
        broad_notrack_rows = [
            row for row in query("/ip/firewall/raw/print", "=.proplist=.id,chain,action,src-address,dst-address,disabled,comment")
            if row.get("chain") == "prerouting"
            and row.get("action") == "notrack"
            and not row.get("src-address")
            and not row.get("dst-address")
            and not routeros_truthy(row.get("disabled"))
        ]
        client_ok = any(row.get("chain") == "prerouting" and row.get("action") == "accept" and row.get("src-address") == station["client_network_cidr"] and not routeros_truthy(row.get("disabled")) for row in client_rows)
        return_ok = any(row.get("chain") == "prerouting" and row.get("action") == "accept" and row.get("dst-address") == station["client_network_cidr"] and not routeros_truthy(row.get("disabled")) for row in return_rows)
        if broad_notrack_rows and not (client_ok and return_ok):
            status = "WARNING"
            message = "A broad raw notrack rule exists. Station traffic should have raw accept exceptions before it so HotSpot redirect/NAT remains trackable."
        else:
            status = "OK"
            message = "Station traffic has raw tracking exceptions, or no broad raw notrack rule was detected."
        add_check(
            "raw_tracking",
            "Raw tracking for HotSpot redirect",
            status,
            message,
            {"broad_notrack_rows": broad_notrack_rows, "client_rows": client_rows, "return_rows": return_rows},
        )
    except Exception as exc:
        add_check("raw_tracking", "Raw tracking for HotSpot redirect", "WARNING", sanitize_routeros_text(str(exc)))

    try:
        rows = query("/ip/hotspot/walled-garden/ip/print", "=.proplist=.id,action,dst-address,dst-port,protocol,disabled,comment")
        relevant = [
            row for row in rows
            if (portal_host and row.get("dst-address") == portal_host)
            or f"VLAN {station['vlan_id']}" in str(row.get("comment") or "")
        ]
        has_portal_host = any(row.get("dst-address") == portal_host for row in relevant)
        has_portal_port = any(str(row.get("dst-port") or "") == str(portal_port) for row in relevant)
        add_check(
            "walled_garden",
            "Pre-login portal access",
            "OK" if has_portal_host and has_portal_port else "WARNING",
            "Walled garden contains portal host and port allow rules." if has_portal_host and has_portal_port else "Portal walled garden rules may be incomplete.",
            {"portal_host": portal_host, "portal_port": portal_port, "rows": relevant},
        )
    except Exception as exc:
        add_check("walled_garden", "Pre-login portal access", "WARNING", sanitize_routeros_text(str(exc)))

    if client_ip:
        try:
            host_rows = query("/ip/hotspot/host/print", f"?address={client_ip}", "=.proplist=.id,address,mac-address,authorized,bypassed,server")
            active_rows = query("/ip/hotspot/active/print", f"?address={client_ip}", "=.proplist=.id,address,mac-address,user,server,uptime")
            if active_rows:
                add_check("client_status", "Client HotSpot status", "OK", f"Client {client_ip} is already active/authorized.", {"host_rows": host_rows, "active_rows": active_rows})
            elif host_rows:
                add_check("client_status", "Client HotSpot status", "WARNING", f"Client {client_ip} is visible in HotSpot hosts but is not authorized yet.", {"host_rows": host_rows, "active_rows": active_rows})
            else:
                add_check("client_status", "Client HotSpot status", "FAILED", f"Client {client_ip} is not visible in MikroTik HotSpot host table. Redirect will not work until HotSpot catches this client.", {"host_rows": [], "active_rows": []})
        except Exception as exc:
            add_check("client_status", "Client HotSpot status", "WARNING", sanitize_routeros_text(str(exc)))
    else:
        add_check("client_status", "Client HotSpot status", "WARNING", "Enter the phone/client IP to verify whether MikroTik sees it in the HotSpot host table.")

    failed = sum(1 for item in checks if item["status"] == "FAILED")
    warnings = sum(1 for item in checks if item["status"] == "WARNING")
    status = "FAILED" if failed else "WARNING" if warnings else "READY"
    return {
        "status": status,
        "station": station_summary,
        "root_router": sanitize_summary(root),
        "checks": checks,
        "summary": {
            "ready": sum(1 for item in checks if item["status"] == "OK"),
            "warnings": warnings,
            "failed": failed,
            "total": len(checks),
        },
    }


def sync_mikrotik_hotspot_login_for_station(station: dict, admin_id: Optional[str]) -> dict:
    station_id = str(station["id"])
    root = station_root_router(station_id)
    file_path = mikrotik_hotspot_login_file_path(station)
    content = build_mikrotik_hotspot_login_html(station)
    content_hash = sha256(content.encode()).hexdigest()
    if not root:
        message = "Station has no root gateway router."
        record_hotspot_login_sync_log(station_id, None, file_path, content_hash, "NOT_READY", message, {"error": message}, admin_id)
        return {"station_id": station_id, "station_name": station.get("station_name"), "status": "NOT_READY", "message": message, "file_path": file_path}
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (root["router_id"],))
    if not router or not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        message = "Root gateway host, username, and password are required before uploading login.html."
        record_hotspot_login_sync_log(station_id, root.get("router_id"), file_path, content_hash, "NOT_READY", message, {"error": message}, admin_id)
        return {"station_id": station_id, "station_name": station.get("station_name"), "router_id": root.get("router_id"), "router_name": root.get("router_name"), "status": "NOT_READY", "message": message, "file_path": file_path}
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        if not password:
            raise RuntimeError("Saved MikroTik password could not be decrypted.")
        try:
            result = routeros_write_text_file(
                router["host"],
                router["api_port"],
                router.get("username"),
                password,
                router.get("use_tls"),
                file_path,
                content,
            )
        except Exception as api_exc:
            result = routeros_write_text_file_via_ftp(
                router["host"],
                router.get("username"),
                password,
                file_path,
                content,
            )
            result["api_upload_error"] = sanitize_routeros_text(str(api_exc))
        actual_file_path = result.get("file_path") or file_path
        status = "SUCCESS"
        message = result.get("message") or f"Uploaded managed HotSpot login.html to {actual_file_path}."
        record_hotspot_login_sync_log(station_id, root["router_id"], actual_file_path, content_hash, status, message, result, admin_id)
        record_station_command_log(
            station_id,
            root["router_id"],
            "APPLY",
            None,
            {"label": "Upload managed HotSpot login.html", "preview": f"/file set-or-add name={actual_file_path} contents=<3J managed redirect template>"},
            status,
            message,
            result,
            admin_id,
        )
        return {
            "station_id": station_id,
            "station_name": station.get("station_name"),
            "router_id": root["router_id"],
            "router_name": root.get("router_name"),
            "host": root.get("host"),
            "status": status,
            "message": message,
            "file_path": actual_file_path,
            "content_hash": content_hash,
            "result": sanitize_summary(result),
        }
    except Exception as exc:
        message = sanitize_routeros_text(str(exc))
        result = {"error": message}
        record_hotspot_login_sync_log(station_id, root.get("router_id"), file_path, content_hash, "FAILED", message, result, admin_id)
        record_station_command_log(
            station_id,
            root.get("router_id"),
            "APPLY",
            None,
            {"label": "Upload managed HotSpot login.html", "preview": f"/file set-or-add name={file_path} contents=<3J managed redirect template>"},
            "FAILED",
            message,
            result,
            admin_id,
        )
        return {
            "station_id": station_id,
            "station_name": station.get("station_name"),
            "router_id": root.get("router_id"),
            "router_name": root.get("router_name"),
            "host": root.get("host"),
            "status": "FAILED",
            "message": message,
            "file_path": file_path,
            "content_hash": content_hash,
        }


def latest_mikrotik_ap_management_config_row() -> Optional[dict]:
    return fetch_one(
        """
        SELECT *
        FROM mikrotik_ap_management_configs
        WHERE status <> 'ARCHIVED'
        ORDER BY updated_at DESC, created_at DESC
        LIMIT 1
        """
    )


def save_mikrotik_ap_management_payload(payload: MikrotikApManagementConfigPayload, admin: dict) -> dict:
    normalized = normalize_ap_management_config_payload(payload)
    validate_ap_management_router_path(payload, normalized)
    existing = latest_mikrotik_ap_management_config_row()
    with get_conn() as conn:
        with conn.cursor() as cur:
            if existing:
                cur.execute(
                    """
                    UPDATE mikrotik_ap_management_configs
                    SET config_name = %s,
                        vlan_id = %s,
                        vlan_interface_name = %s,
                        network_cidr = %s,
                        gateway_ip = %s,
                        pool_start_ip = %s,
                        pool_end_ip = %s,
                        pool_name = %s,
                        dhcp_server_name = %s,
                        dhcp_lease_time = %s,
                        dns_servers = %s,
                        local_interface_list = %s,
                        status = 'READY_FOR_REVIEW',
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        normalized["config_name"],
                        normalized["vlan_id"],
                        normalized["vlan_interface_name"],
                        normalized["network"].with_prefixlen,
                        str(normalized["gateway_ip"]),
                        str(normalized["pool_start"]),
                        str(normalized["pool_end"]),
                        normalized["pool_name"],
                        normalized["dhcp_server_name"],
                        normalized["dhcp_lease_time"],
                        normalized["dns_servers"],
                        normalized["local_interface_list"],
                        existing["id"],
                    ),
                )
                config = cur.fetchone()
                cur.execute("DELETE FROM mikrotik_ap_management_routers WHERE config_id = %s", (config["id"],))
            else:
                cur.execute(
                    """
                    INSERT INTO mikrotik_ap_management_configs(
                        config_name, vlan_id, vlan_interface_name, network_cidr, gateway_ip,
                        pool_start_ip, pool_end_ip, pool_name, dhcp_server_name, dhcp_lease_time,
                        dns_servers, local_interface_list, status, created_by_admin_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'READY_FOR_REVIEW', %s)
                    RETURNING *
                    """,
                    (
                        normalized["config_name"],
                        normalized["vlan_id"],
                        normalized["vlan_interface_name"],
                        normalized["network"].with_prefixlen,
                        str(normalized["gateway_ip"]),
                        str(normalized["pool_start"]),
                        str(normalized["pool_end"]),
                        normalized["pool_name"],
                        normalized["dhcp_server_name"],
                        normalized["dhcp_lease_time"],
                        normalized["dns_servers"],
                        normalized["local_interface_list"],
                        admin["id"],
                    ),
                )
                config = cur.fetchone()
            for index, item in enumerate(payload.routers):
                cur.execute(
                    """
                    INSERT INTO mikrotik_ap_management_routers(
                        config_id, router_id, sequence_order, router_role, bridge_name, tagged_ports, notes
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        config["id"],
                        item.router_id,
                        index,
                        "ROOT_GATEWAY" if index == 0 else "TRUNK_HELPER",
                        (item.bridge_name or "").strip(),
                        (item.tagged_ports or "").strip(),
                        (item.notes or "").strip() or None,
                    ),
                )
    audit(admin["id"], "save_mikrotik_ap_management_config", "mikrotik_ap_management_configs", str(config["id"]), {"vlan_id": normalized["vlan_id"], "network_cidr": normalized["network"].with_prefixlen, "router_count": len(payload.routers)})
    saved = fetch_one("SELECT * FROM mikrotik_ap_management_configs WHERE id = %s", (config["id"],))
    return public_mikrotik_ap_management_config(saved)


def save_mikrotik_station_payload(payload: MikrotikStationCreate, admin: dict, station_id: Optional[str] = None) -> dict:
    if not payload.routers:
        raise HTTPException(status_code=400, detail="Add at least one MikroTik router to the station chain.")
    router_ids = [item.router_id for item in payload.routers]
    if len(router_ids) != len(set(router_ids)):
        raise HTTPException(status_code=400, detail="A MikroTik router can appear only once in a station chain.")
    existing_routers = fetch_all("SELECT id, router_name FROM mikrotik_routers WHERE id = ANY(%s::uuid[])", (router_ids,))
    existing_ids = {str(row["id"]) for row in existing_routers}
    missing_ids = [router_id for router_id in router_ids if router_id not in existing_ids]
    if missing_ids:
        raise HTTPException(status_code=400, detail="One or more selected MikroTik routers no longer exist.")
    for index, item in enumerate(payload.routers):
        if not (item.bridge_name or "").strip():
            label = "root/primary router" if index == 0 else f"router #{index + 1}"
            raise HTTPException(status_code=400, detail=f"Bridge/interface is required for the {label}.")
        if not (item.tagged_ports or "").strip():
            label = "root/primary router" if index == 0 else f"router #{index + 1}"
            raise HTTPException(status_code=400, detail=f"Tagged ports are required for the {label}.")
    network, gateway_ip, pool_start, pool_end, dns_servers = validate_station_network(payload)
    ap_management = validate_station_ap_management_network(payload, network)
    station_code = station_code_from_text(payload.station_code or payload.station_name)
    vlan_interface_name = (payload.vlan_interface_name or "").strip() or f"VLAN{payload.vlan_id}-3J-HOTSPOT"
    pool_name = (payload.pool_name or "").strip() or f"POOL-3J-HOTSPOT-V{payload.vlan_id}"
    dhcp_server_name = (payload.dhcp_server_name or "").strip() or f"DHCP-3J-HOTSPOT-V{payload.vlan_id}"
    dhcp_lease_time = (payload.dhcp_lease_time or "1h").strip() or "1h"
    hotspot_profile_name = (payload.hotspot_profile_name or "").strip() or f"PROFILE-3J-HOTSPOT-V{payload.vlan_id}"
    hotspot_html_directory = (payload.hotspot_html_directory or "hotspot").strip() or "hotspot"
    hotspot_dns_name = (payload.hotspot_dns_name or "").strip() or default_hotspot_dns_name(station_code)
    hotspot_server_name = (payload.hotspot_server_name or "").strip() or f"HS-3J-HOTSPOT-V{payload.vlan_id}"
    portal_url = (payload.portal_url or "").strip() or "http://192.168.50.70:8080/portal"
    station_validate_router_path(payload, station_id, network, pool_start, pool_end, ap_management)
    duplicate_conditions = [
        ("station_code", "lower(btrim(station_code)) = lower(btrim(%s))", station_code, "Station code is already used by another active station."),
        ("vlan_id", "vlan_id = %s", payload.vlan_id, f"Customer VLAN {payload.vlan_id} is already used by another active station."),
        ("client_network_cidr", "lower(btrim(client_network_cidr)) = lower(btrim(%s))", network.with_prefixlen, f"Client network {network.with_prefixlen} is already used by another active station."),
    ]
    if ap_management:
        duplicate_conditions.extend([
            ("ap_management_vlan_id", "ap_management_enabled = TRUE AND ap_management_vlan_id = %s", ap_management["vlan_id"], f"AP management VLAN {ap_management['vlan_id']} is already used by another active station."),
            ("ap_management_network_cidr", "ap_management_enabled = TRUE AND lower(btrim(ap_management_network_cidr)) = lower(btrim(%s))", ap_management["network"].with_prefixlen, f"AP management network {ap_management['network'].with_prefixlen} is already used by another active station."),
        ])
    for _, condition, value, message in duplicate_conditions:
        existing = fetch_one(
            f"""
            SELECT id, station_name
            FROM mikrotik_stations
            WHERE status <> 'ARCHIVED'
              AND {condition}
              AND (%s IS NULL OR id <> %s)
            LIMIT 1
            """,
            (value, station_id, station_id),
        )
        if existing:
            raise HTTPException(status_code=400, detail=f"{message} Existing station: {existing['station_name']}.")
    action = "create_mikrotik_station"
    with get_conn() as conn:
        with conn.cursor() as cur:
            station = None
            if station_id:
                cur.execute(
                    "SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED' FOR UPDATE",
                    (station_id,),
                )
                station = cur.fetchone()
                if not station:
                    raise HTTPException(status_code=404, detail="MikroTik station not found")
            else:
                cur.execute(
                    """
                    SELECT *
                    FROM mikrotik_stations
                    WHERE lower(btrim(station_name)) = lower(btrim(%s))
                      AND status <> 'ARCHIVED'
                    ORDER BY updated_at DESC, created_at DESC
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (payload.station_name.strip(),),
                )
                station = cur.fetchone()
            if station:
                action = "update_mikrotik_station"
                cur.execute(
                    """
                    UPDATE mikrotik_stations
                    SET station_name = %s,
                        station_code = %s,
                        description = %s,
                        vlan_id = %s,
                        vlan_interface_name = %s,
                        client_network_cidr = %s,
                        gateway_ip = %s,
                        pool_start_ip = %s,
                        pool_end_ip = %s,
                        pool_name = %s,
                        dhcp_server_name = %s,
                        dhcp_lease_time = %s,
                        create_dhcp_server = %s,
                        dns_servers = %s,
                        local_interface_list = %s,
                        create_hotspot_profile = %s,
                        create_hotspot_server = %s,
                        create_walled_garden = %s,
                        hotspot_profile_name = %s,
                        hotspot_html_directory = %s,
                        hotspot_dns_name = %s,
                        hotspot_server_name = %s,
                        portal_url = %s,
                        ap_management_enabled = %s,
                        ap_management_vlan_id = %s,
                        ap_management_vlan_interface_name = %s,
                        ap_management_network_cidr = %s,
                        ap_management_gateway_ip = %s,
                        ap_management_pool_start_ip = %s,
                        ap_management_pool_end_ip = %s,
                        ap_management_pool_name = %s,
                        ap_management_dhcp_server_name = %s,
                        ap_management_dhcp_lease_time = %s,
                        ap_management_dns_servers = %s,
                        status = 'READY_FOR_REVIEW',
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        payload.station_name.strip(),
                        station_code,
                        payload.description,
                        payload.vlan_id,
                        vlan_interface_name,
                        network.with_prefixlen,
                        str(gateway_ip),
                        str(pool_start),
                        str(pool_end),
                        pool_name,
                        dhcp_server_name,
                        dhcp_lease_time,
                        payload.create_dhcp_server,
                        dns_servers,
                        (payload.local_interface_list or "LOCAL").strip() or "LOCAL",
                        payload.create_hotspot_profile,
                        payload.create_hotspot_server,
                        payload.create_walled_garden,
                        hotspot_profile_name,
                        hotspot_html_directory,
                        hotspot_dns_name,
                        hotspot_server_name,
                        portal_url,
                        bool(ap_management),
                        ap_management["vlan_id"] if ap_management else None,
                        ap_management["vlan_interface_name"] if ap_management else None,
                        ap_management["network"].with_prefixlen if ap_management else None,
                        str(ap_management["gateway_ip"]) if ap_management else None,
                        str(ap_management["pool_start"]) if ap_management else None,
                        str(ap_management["pool_end"]) if ap_management else None,
                        ap_management["pool_name"] if ap_management else None,
                        ap_management["dhcp_server_name"] if ap_management else None,
                        ap_management["dhcp_lease_time"] if ap_management else None,
                        ap_management["dns_servers"] if ap_management else None,
                        station["id"],
                    ),
                )
                station = cur.fetchone()
                cur.execute("DELETE FROM mikrotik_station_routers WHERE station_id = %s", (station["id"],))
            else:
                cur.execute(
                    """
                    INSERT INTO mikrotik_stations(
                        station_name, station_code, description, vlan_id, vlan_interface_name, client_network_cidr,
                        gateway_ip, pool_start_ip, pool_end_ip, pool_name, dhcp_server_name, dhcp_lease_time,
                        create_dhcp_server, dns_servers,
                        local_interface_list, create_hotspot_profile, create_hotspot_server, create_walled_garden,
                        hotspot_profile_name, hotspot_html_directory, hotspot_dns_name, hotspot_server_name, portal_url,
                        ap_management_enabled, ap_management_vlan_id, ap_management_vlan_interface_name,
                        ap_management_network_cidr, ap_management_gateway_ip, ap_management_pool_start_ip,
                        ap_management_pool_end_ip, ap_management_pool_name, ap_management_dhcp_server_name,
                        ap_management_dhcp_lease_time, ap_management_dns_servers,
                        status, created_by_admin_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'READY_FOR_REVIEW', %s)
                    RETURNING *
                    """,
                    (
                        payload.station_name.strip(),
                        station_code,
                        payload.description,
                        payload.vlan_id,
                        vlan_interface_name,
                        network.with_prefixlen,
                        str(gateway_ip),
                        str(pool_start),
                        str(pool_end),
                        pool_name,
                        dhcp_server_name,
                        dhcp_lease_time,
                        payload.create_dhcp_server,
                        dns_servers,
                        (payload.local_interface_list or "LOCAL").strip() or "LOCAL",
                        payload.create_hotspot_profile,
                        payload.create_hotspot_server,
                        payload.create_walled_garden,
                        hotspot_profile_name,
                        hotspot_html_directory,
                        hotspot_dns_name,
                        hotspot_server_name,
                        portal_url,
                        bool(ap_management),
                        ap_management["vlan_id"] if ap_management else None,
                        ap_management["vlan_interface_name"] if ap_management else None,
                        ap_management["network"].with_prefixlen if ap_management else None,
                        str(ap_management["gateway_ip"]) if ap_management else None,
                        str(ap_management["pool_start"]) if ap_management else None,
                        str(ap_management["pool_end"]) if ap_management else None,
                        ap_management["pool_name"] if ap_management else None,
                        ap_management["dhcp_server_name"] if ap_management else None,
                        ap_management["dhcp_lease_time"] if ap_management else None,
                        ap_management["dns_servers"] if ap_management else None,
                        admin["id"],
                    ),
                )
                station = cur.fetchone()
            for index, item in enumerate(payload.routers):
                cur.execute(
                    """
                    INSERT INTO mikrotik_station_routers(
                        station_id, router_id, sequence_order, station_role, bridge_name, tagged_ports, notes
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        station["id"],
                        item.router_id,
                        index,
                        "ROOT_GATEWAY" if index == 0 else "TRUNK_HELPER",
                        (item.bridge_name or "").strip(),
                        (item.tagged_ports or "").strip(),
                        item.notes,
                    ),
                )
    audit(
        admin["id"],
        action,
        "mikrotik_stations",
        str(station["id"]),
        {
            "station_name": payload.station_name,
            "station_code": station_code,
            "vlan_id": payload.vlan_id,
            "client_network_cidr": network.with_prefixlen,
            "ap_management_enabled": bool(ap_management),
            "ap_management_vlan_id": ap_management["vlan_id"] if ap_management else None,
            "ap_management_network_cidr": ap_management["network"].with_prefixlen if ap_management else None,
            "router_count": len(payload.routers),
        },
    )
    saved = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s", (station["id"],))
    return public_mikrotik_station(saved)


def mikrotik_hotspot_network_config(router: dict, managed_names: dict) -> tuple[Optional[dict], list[str]]:
    errors = []
    vlan_id_value = router.get("hotspot_vlan_id")
    vlan_parent_interface = (router.get("hotspot_vlan_parent_interface") or "").strip()
    vlan_interface_name = (router.get("hotspot_vlan_interface_name") or "").strip()
    network_cidr = (router.get("hotspot_client_network_cidr") or "").strip()
    gateway_ip_text = (router.get("hotspot_gateway_ip") or "").strip()
    pool_start_text = (router.get("hotspot_pool_start_ip") or "").strip()
    pool_end_text = (router.get("hotspot_pool_end_ip") or "").strip()
    pool_name = (router.get("hotspot_pool_name") or managed_names["pool"]).strip()
    dhcp_name = (router.get("hotspot_dhcp_server_name") or managed_names["dhcp"]).strip()
    lease_time = (router.get("hotspot_dhcp_lease_time") or "1h").strip()
    dns_servers = (router.get("hotspot_dns_servers") or "").strip()
    wan_interface = (router.get("hotspot_wan_interface") or "").strip()
    enable_nat = bool(router.get("hotspot_enable_nat"))

    vlan_id = None
    if vlan_id_value in (None, ""):
        errors.append("Customer VLAN ID is required. This VLAN is tagged on the AP SSID and created on MikroTik for captive portal clients.")
    else:
        try:
            vlan_id = int(vlan_id_value)
            if vlan_id < 1 or vlan_id > 4094:
                errors.append("Customer VLAN ID must be between 1 and 4094.")
        except (TypeError, ValueError):
            errors.append("Customer VLAN ID must be a number between 1 and 4094.")
    if vlan_id and not vlan_interface_name:
        vlan_interface_name = f"{managed_names['vlan']}-{vlan_id}"
    if not vlan_parent_interface:
        errors.append("VLAN Parent Interface is required. Choose the MikroTik interface, bridge, or trunk port that carries AP customer VLAN traffic.")
    if not vlan_interface_name:
        errors.append("VLAN Interface Name is required. Leave it blank only when Customer VLAN ID is set so the system can generate it.")
    if not network_cidr:
        errors.append("Client Network CIDR is required, for example 10.30.0.0/24.")
    if not gateway_ip_text:
        errors.append("Gateway IP is required, for example 10.30.0.1.")
    if not pool_start_text:
        errors.append("Pool Start IP is required, for example 10.30.0.10.")
    if not pool_end_text:
        errors.append("Pool End IP is required, for example 10.30.0.254.")
    if enable_nat and not wan_interface:
        errors.append("WAN/Internet Interface is required when NAT masquerade is enabled.")

    network = gateway_ip = pool_start = pool_end = None
    if network_cidr:
        try:
            network = ip_network(network_cidr, strict=False)
        except ValueError:
            errors.append("Client Network CIDR is invalid.")
    if gateway_ip_text:
        try:
            gateway_ip = ip_address(gateway_ip_text)
        except ValueError:
            errors.append("Gateway IP is invalid.")
    if pool_start_text:
        try:
            pool_start = ip_address(pool_start_text)
        except ValueError:
            errors.append("Pool Start IP is invalid.")
    if pool_end_text:
        try:
            pool_end = ip_address(pool_end_text)
        except ValueError:
            errors.append("Pool End IP is invalid.")
    if network and gateway_ip and gateway_ip not in network:
        errors.append("Gateway IP must be inside Client Network CIDR.")
    if network and pool_start and pool_start not in network:
        errors.append("Pool Start IP must be inside Client Network CIDR.")
    if network and pool_end and pool_end not in network:
        errors.append("Pool End IP must be inside Client Network CIDR.")
    if pool_start and pool_end and int(pool_start) > int(pool_end):
        errors.append("Pool Start IP must be lower than or equal to Pool End IP.")
    if gateway_ip and pool_start and pool_end and int(pool_start) <= int(gateway_ip) <= int(pool_end):
        errors.append("Gateway IP should not be inside the DHCP pool range.")

    if errors:
        return None, errors

    return {
        "interface": vlan_interface_name,
        "vlan_id": vlan_id,
        "vlan_parent_interface": vlan_parent_interface,
        "vlan_interface_name": vlan_interface_name,
        "network": network,
        "network_cidr": str(network),
        "prefixlen": network.prefixlen,
        "gateway_ip": str(gateway_ip),
        "pool_start": str(pool_start),
        "pool_end": str(pool_end),
        "pool_name": pool_name,
        "dhcp_name": dhcp_name,
        "lease_time": lease_time,
        "dns_servers": dns_servers,
        "wan_interface": wan_interface,
        "enable_nat": enable_nat,
    }, []


def mikrotik_configuration_plan(router, settings):
    display_name = system_display_name()
    managed_names = mikrotik_hotspot_managed_names(display_name)
    managed_comment_prefix = f"{display_name} managed"
    staging_url = settings.get("portal_url_staging") or "http://192.168.50.70:8080/portal"
    production_url = settings.get("portal_url_production") or "http://192.168.50.70/portal"
    parsed = urlparse(staging_url)
    portal_host = parsed.hostname or "192.168.50.70"
    portal_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    portal_ssid = captive_portal_ssid_from_ap_configuration()
    open_ssid = portal_ssid["primary_ssid"]
    post_login_url = settings.get("post_login_redirect_url") or "Use MikroTik default redirect or customer requested URL"
    duration = settings.get("default_access_duration_seconds") or 86400
    step_status = mikrotik_step_status_map(router)
    latest_scan = latest_mikrotik_scan_row(str(router["id"]))
    latest_policy = latest_mikrotik_policy_row(str(router["id"]), latest_scan["id"] if latest_scan else None)
    if latest_scan and not latest_policy:
        latest_policy = evaluate_and_store_mikrotik_policy(router, latest_scan)
    public_policy = public_mikrotik_policy_result(latest_policy)
    policy_block_reasons = []
    if not latest_scan:
        policy_block_reasons.append("Run a successful Preflight Scan before MikroTik setup.")
    elif latest_scan["scan_status"] != "SUCCESS":
        policy_block_reasons.append(latest_scan.get("last_error") or "Latest Preflight Scan failed.")
    elif public_policy:
        policy_block_reasons.extend(public_policy.get("blocking_reasons") or [])
    else:
        policy_block_reasons.append("Evaluate Safe Deployment Mode policy before setup.")
    hotspot_interface = (router.get("hotspot_interface") or "").strip()
    legacy_profile_name = "3jcentralpisowifi-hotspot-profile"
    legacy_server_name = "3jcentralpisowifi-hotspot"
    raw_profile_name = (router.get("hotspot_profile_name") or "").strip()
    raw_server_name = (router.get("hotspot_server_name") or "").strip()
    hotspot_profile_name = managed_names["profile"] if not raw_profile_name or raw_profile_name == legacy_profile_name else raw_profile_name
    hotspot_server_name = managed_names["server"] if not raw_server_name or raw_server_name == legacy_server_name else raw_server_name
    hotspot_dns_name = (router.get("hotspot_dns_name") or "").strip()
    hotspot_html_directory = (router.get("hotspot_html_directory") or "hotspot").strip()
    hotspot_config, hotspot_config_errors = mikrotik_hotspot_network_config(router, managed_names)
    hotspot_ready = not hotspot_config_errors and hotspot_config is not None
    hotspot_interface_for_commands = hotspot_config["interface"] if hotspot_config else hotspot_interface
    hotspot_pool_name = hotspot_config["pool_name"] if hotspot_config else managed_names["pool"]
    hotspot_profile_params = {
        "name": hotspot_profile_name,
        "login-by": "http-chap,http-pap",
        "html-directory": hotspot_html_directory,
    }
    if hotspot_dns_name:
        hotspot_profile_params["dns-name"] = hotspot_dns_name
    hotspot_server_params = {
        "name": hotspot_server_name,
        "interface": hotspot_interface_for_commands,
        "profile": hotspot_profile_name,
        "disabled": "no",
        "address-pool": hotspot_pool_name,
    }
    dedicated_network_commands = []
    if hotspot_config:
        dedicated_network_commands = [
            {
                "label": "Create customer WiFi VLAN interface",
                "path": "/interface/vlan/add",
                "params": {
                    "name": hotspot_config["vlan_interface_name"],
                    "vlan-id": str(hotspot_config["vlan_id"]),
                    "interface": hotspot_config["vlan_parent_interface"],
                    "comment": f"{managed_comment_prefix} customer VLAN {hotspot_config['vlan_id']} for AP SSID tagging",
                },
                "unique_field": "name",
                "unique_value": hotspot_config["vlan_interface_name"],
            },
            {
                "label": "Assign captive portal gateway IP",
                "path": "/ip/address/add",
                "params": {
                    "address": f"{hotspot_config['gateway_ip']}/{hotspot_config['prefixlen']}",
                    "interface": hotspot_config["interface"],
                    "comment": f"{managed_comment_prefix} HotSpot gateway IP",
                },
                "unique_comment": f"{managed_comment_prefix} HotSpot gateway IP",
            },
            {
                "label": "Create captive portal DHCP pool",
                "path": "/ip/pool/add",
                "params": {
                    "name": hotspot_config["pool_name"],
                    "ranges": f"{hotspot_config['pool_start']}-{hotspot_config['pool_end']}",
                    "comment": f"{managed_comment_prefix} HotSpot client pool",
                },
                "unique_field": "name",
                "unique_value": hotspot_config["pool_name"],
            },
            {
                "label": "Create captive portal DHCP server",
                "path": "/ip/dhcp-server/add",
                "params": {
                    "name": hotspot_config["dhcp_name"],
                    "interface": hotspot_config["interface"],
                    "address-pool": hotspot_config["pool_name"],
                    "lease-time": hotspot_config["lease_time"],
                    "disabled": "no",
                    "comment": f"{managed_comment_prefix} HotSpot DHCP server",
                },
                "unique_field": "name",
                "unique_value": hotspot_config["dhcp_name"],
            },
            {
                "label": "Create captive portal DHCP network",
                "path": "/ip/dhcp-server/network/add",
                "params": {
                    "address": hotspot_config["network_cidr"],
                    "gateway": hotspot_config["gateway_ip"],
                    "dns-server": hotspot_config["dns_servers"],
                    "comment": f"{managed_comment_prefix} HotSpot DHCP network",
                },
                "unique_comment": f"{managed_comment_prefix} HotSpot DHCP network",
            },
        ]
        if hotspot_config["enable_nat"]:
            dedicated_network_commands.append(
                {
                    "label": "Create captive portal NAT masquerade",
                    "path": "/ip/firewall/nat/add",
                    "params": {
                        "chain": "srcnat",
                        "src-address": hotspot_config["network_cidr"],
                        "out-interface": hotspot_config["wan_interface"],
                        "action": "masquerade",
                        "comment": f"{managed_comment_prefix} HotSpot NAT",
                    },
                    "unique_comment": f"{managed_comment_prefix} HotSpot NAT",
                }
            )
    hotspot_commands = dedicated_network_commands + [
        {
            "label": "Create HotSpot profile",
            "path": "/ip/hotspot/profile/add",
            "params": hotspot_profile_params,
            "unique_field": "name",
            "unique_value": hotspot_profile_name,
        },
        {
            "label": "Create HotSpot server",
            "path": "/ip/hotspot/add",
            "params": hotspot_server_params,
            "unique_field": "name",
            "unique_value": hotspot_server_name,
        },
    ]
    for command in hotspot_commands:
        command["preview"] = routeros_cli_preview(command["path"], command["params"])
    walled_garden_commands = [
        {
            "label": "Allow portal server IP before login",
            "path": "/ip/hotspot/walled-garden/ip/add",
            "params": {
                "action": "accept",
                "dst-address": portal_host,
                "comment": f"{managed_comment_prefix} portal server",
            },
            "unique_comment": f"{managed_comment_prefix} portal server",
        },
        {
            "label": f"Allow portal URL TCP port {portal_port}",
            "path": "/ip/hotspot/walled-garden/ip/add",
            "params": {
                "action": "accept",
                "protocol": "tcp",
                "dst-address": portal_host,
                "dst-port": str(portal_port),
                "comment": f"{managed_comment_prefix} portal URL",
            },
            "unique_comment": f"{managed_comment_prefix} portal URL",
        },
        {
            "label": "Allow DNS UDP before login",
            "path": "/ip/hotspot/walled-garden/ip/add",
            "params": {
                "action": "accept",
                "protocol": "udp",
                "dst-port": "53",
                "comment": f"{managed_comment_prefix} DNS UDP",
            },
            "unique_comment": f"{managed_comment_prefix} DNS UDP",
        },
        {
            "label": "Allow DNS TCP before login",
            "path": "/ip/hotspot/walled-garden/ip/add",
            "params": {
                "action": "accept",
                "protocol": "tcp",
                "dst-port": "53",
                "comment": f"{managed_comment_prefix} DNS TCP",
            },
            "unique_comment": f"{managed_comment_prefix} DNS TCP",
        },
    ]
    for command in walled_garden_commands:
        command["preview"] = routeros_cli_preview(command["path"], command["params"])
    actions = [
        {
            "key": "validate_api_login",
            "step": "Validate RouterOS API login",
            "status": "ready",
            "details": f"Connect to {router['host']}:{router['api_port']} using the saved dedicated full/write API account.",
            "apply_supported": True,
            "apply_mode": "api_login",
            "apply_label": "Test API Login",
            "commands": [
                {
                    "label": "RouterOS API login",
                    "preview": f"Connect to RouterOS API {router['host']}:{router['api_port']} as {router.get('username') or '[username]'}",
                }
            ],
        },
        {
            "key": "prepare_hotspot_profile",
            "step": "Create dedicated HotSpot network, profile, and server",
            "status": "ready" if hotspot_ready else "needs_required_fields",
            "details": f"Creates only {display_name}-managed RouterOS objects on VLAN {hotspot_config['vlan_id']} ({hotspot_config['interface']}) using client network {hotspot_config['network_cidr']}. AP customer SSIDs must use the same VLAN tag." if hotspot_ready else "Complete the required customer VLAN and captive portal network fields in Add Router. The system will not auto-detect or reuse existing MikroTik pools, subnets, or profiles.",
            "apply_supported": hotspot_ready,
            "apply_mode": "routeros_commands",
            "apply_label": "Create Dedicated HotSpot" if hotspot_ready else "Complete Required Fields",
            "commands": hotspot_commands if hotspot_ready else [
                {"label": f"Required field {index + 1}", "preview": error}
                for index, error in enumerate(hotspot_config_errors)
            ],
        },
        {
            "key": "allow_pre_auth_portal",
            "step": "Allow pre-auth access to portal",
            "status": "planned",
            "details": f"Walled garden must allow portal server {portal_host} and staging URL {staging_url}. DNS pre-auth access may also be required.",
            "apply_supported": True,
            "apply_mode": "routeros_commands",
            "apply_label": "Apply Walled Garden",
            "commands": walled_garden_commands,
        },
        {
            "key": "use_voucher_portal_url",
            "step": "Use voucher portal URL",
            "status": "placeholder",
            "details": f"Staging portal URL: {staging_url}. Production portal URL: {production_url}.",
            "apply_supported": False,
            "apply_label": "Coming after HotSpot profile selection",
            "commands": [
                {
                    "label": "Portal URL reference",
                    "preview": f"Portal URL to place in the MikroTik login page or HotSpot profile workflow: {staging_url}",
                }
            ],
        },
        {
            "key": "set_post_login_behavior",
            "step": "Set post-login behavior",
            "status": "placeholder",
            "details": f"Post-login redirect: {post_login_url}. Default unlimited authorization duration: {duration} seconds.",
            "apply_supported": False,
            "apply_label": "Coming after authorization workflow",
            "commands": [
                {
                    "label": "Future authorization duration",
                    "preview": f"Authorize client for voucher duration or default unlimited duration of {duration} seconds.",
                },
                {
                    "label": "Future post-login redirect",
                    "preview": f"Redirect connected client to: {post_login_url}",
                },
            ],
        },
    ]
    for index, action in enumerate(actions, start=1):
        if action.get("apply_mode") == "routeros_commands":
            action["policy_blocked"] = True
            if policy_block_reasons:
                action["status"] = "blocked"
                action["apply_supported"] = False
                action["apply_label"] = "Blocked by Preflight Policy"
                action["policy_block_reasons"] = policy_block_reasons
            elif not public_policy or not public_policy.get("hotspot_setup_allowed"):
                action["status"] = "blocked"
                action["apply_supported"] = False
                action["apply_label"] = "Confirm Deployment Mode"
                action["policy_block_reasons"] = ["HotSpot setup is not allowed by the current deployment policy."]
            else:
                action["status"] = "preview_only"
                action["apply_supported"] = False
                action["apply_label"] = "Command preview in future phase"
                action["policy_block_reasons"] = ["RouterOS write apply is disabled in MT-2. Future MT-4/MT-5 will add command preview and step-by-step apply after policy validation."]
        applied_status = step_status.get(action["key"]) or {}
        action["step_number"] = index
        action["applied_status"] = applied_status
        action["is_applied"] = applied_status.get("status") == "SUCCESS"
        if action["is_applied"]:
            action["status"] = "applied"
        elif applied_status.get("status") == "FAILED":
            action["status"] = "failed"
            action["last_error"] = applied_status.get("message")
    progress = mikrotik_configuration_progress(router, actions)
    managed_configuration_status = mikrotik_managed_configuration_status(router)
    return {
        "router": public_mikrotik_router(router),
        "summary": {
            "open_ssid_name": open_ssid,
            "ssid_display": portal_ssid["display_ssid"],
            "ssid_source": portal_ssid["source"],
            "ssid_2g": portal_ssid["ssid_2g"],
            "ssid_5g": portal_ssid["ssid_5g"],
            "use_same_ssid": portal_ssid["use_same_ssid"],
            "portal_url_staging": staging_url,
            "portal_url_production": production_url,
            "portal_host": portal_host,
            "default_access_duration_seconds": duration,
        },
        "actions": actions,
        "progress": progress,
        "revert": mikrotik_revert_configuration_plan(router),
        "managed_configuration_status": managed_configuration_status,
        "policy_gate": {
            "latest_scan": public_mikrotik_preflight_scan(latest_scan, include_snapshot=False) if latest_scan else None,
            "policy": public_policy,
            "blocked": bool(policy_block_reasons or not public_policy or not public_policy.get("hotspot_setup_allowed")),
            "blocking_reasons": policy_block_reasons,
            "phase_note": "MT-2 is read-only for RouterOS configuration. Write steps remain disabled until command preview/apply phases.",
        },
        "can_apply": bool(router.get("host") and router.get("username") and router.get("password_encrypted")),
        "apply_note": "Start Setup now uses Preflight Policy. RouterOS write apply remains disabled in MT-2; command preview/apply comes in future phases.",
    }


def mikrotik_revert_configuration_plan(router) -> dict:
    display_name = system_display_name()
    managed_names = mikrotik_hotspot_managed_names(display_name)
    managed_comment_prefix = f"{display_name} managed"
    legacy_profile_name = "3jcentralpisowifi-hotspot-profile"
    legacy_server_name = "3jcentralpisowifi-hotspot"
    raw_profile_name = (router.get("hotspot_profile_name") or "").strip()
    raw_server_name = (router.get("hotspot_server_name") or "").strip()
    hotspot_profile_name = managed_names["profile"] if not raw_profile_name or raw_profile_name == legacy_profile_name else raw_profile_name
    hotspot_server_name = managed_names["server"] if not raw_server_name or raw_server_name == legacy_server_name else raw_server_name
    hotspot_pool_name = (router.get("hotspot_pool_name") or managed_names["pool"]).strip()
    hotspot_dhcp_name = (router.get("hotspot_dhcp_server_name") or managed_names["dhcp"]).strip()
    vlan_id = router.get("hotspot_vlan_id")
    hotspot_vlan_name = (router.get("hotspot_vlan_interface_name") or (f"{managed_names['vlan']}-{vlan_id}" if vlan_id else managed_names["vlan"])).strip()
    commands = [
        {
            "label": "Remove HotSpot server",
            "print_path": "/ip/hotspot/print",
            "query_field": "name",
            "query_value": hotspot_server_name,
        },
        {
            "label": "Remove HotSpot profile",
            "print_path": "/ip/hotspot/profile/print",
            "query_field": "name",
            "query_value": hotspot_profile_name,
        },
        {
            "label": "Remove walled garden DNS TCP",
            "print_path": "/ip/hotspot/walled-garden/ip/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} DNS TCP",
        },
        {
            "label": "Remove walled garden DNS UDP",
            "print_path": "/ip/hotspot/walled-garden/ip/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} DNS UDP",
        },
        {
            "label": "Remove walled garden portal URL",
            "print_path": "/ip/hotspot/walled-garden/ip/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} portal URL",
        },
        {
            "label": "Remove walled garden portal server",
            "print_path": "/ip/hotspot/walled-garden/ip/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} portal server",
        },
        {
            "label": "Remove captive portal NAT",
            "print_path": "/ip/firewall/nat/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} HotSpot NAT",
        },
        {
            "label": "Remove captive portal DHCP network",
            "print_path": "/ip/dhcp-server/network/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} HotSpot DHCP network",
        },
        {
            "label": "Remove captive portal DHCP server",
            "print_path": "/ip/dhcp-server/print",
            "query_field": "name",
            "query_value": hotspot_dhcp_name,
        },
        {
            "label": "Remove captive portal DHCP pool",
            "print_path": "/ip/pool/print",
            "query_field": "name",
            "query_value": hotspot_pool_name,
        },
        {
            "label": "Remove captive portal gateway IP",
            "print_path": "/ip/address/print",
            "query_field": "comment",
            "query_value": f"{managed_comment_prefix} HotSpot gateway IP",
        },
        {
            "label": "Remove customer WiFi VLAN interface",
            "print_path": "/interface/vlan/print",
            "query_field": "name",
            "query_value": hotspot_vlan_name,
        },
    ]
    for command in commands:
        command["preview"] = routeros_remove_preview(command["print_path"], command["query_field"], command["query_value"])
    return {
        "commands": commands,
        "summary": {
            "managed_comment_prefix": managed_comment_prefix,
            "hotspot_server_name": hotspot_server_name,
            "hotspot_profile_name": hotspot_profile_name,
            "hotspot_pool_name": hotspot_pool_name,
            "hotspot_dhcp_server_name": hotspot_dhcp_name,
            "hotspot_vlan_interface_name": hotspot_vlan_name,
        },
    }


def mikrotik_managed_configuration_status(row) -> dict:
    if not row.get("host") or not row.get("username") or not row.get("password_encrypted"):
        return {
            "status": "NOT_READY",
            "message": "Router host, username, and password are required before checking managed configuration.",
            "has_managed_config": False,
            "found_count": 0,
            "items": [],
        }
    revert_plan = mikrotik_revert_configuration_plan(row)
    try:
        password = decrypt_secret(row.get("password_encrypted"))
        return routeros_detect_remove_targets(
            row["host"],
            row["api_port"],
            row.get("username"),
            password,
            row.get("use_tls"),
            revert_plan["commands"],
        )
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": str(exc),
            "has_managed_config": False,
            "found_count": 0,
            "items": [],
        }


@app.get("/api/captive-portal/mikrotik")
def list_mikrotik_routers(admin=Depends(current_admin)):
    return [
        public_mikrotik_router(row)
        for row in fetch_all("SELECT * FROM mikrotik_routers ORDER BY created_at DESC")
    ]


@app.get("/api/network/mikrotik/stations")
def list_mikrotik_stations(admin=Depends(current_admin)):
    return [
        public_mikrotik_station(row)
        for row in fetch_all("SELECT * FROM mikrotik_stations WHERE status <> 'ARCHIVED' ORDER BY updated_at DESC, created_at DESC")
    ]


@app.get("/api/network/mikrotik/ap-management")
def get_mikrotik_ap_management_config(admin=Depends(current_admin)):
    return public_mikrotik_ap_management_config(latest_mikrotik_ap_management_config_row())


@app.put("/api/network/mikrotik/ap-management")
def save_mikrotik_ap_management_config(payload: MikrotikApManagementConfigPayload, admin=Depends(current_admin)):
    return save_mikrotik_ap_management_payload(payload, admin)


@app.get("/api/network/mikrotik/ap-management/{config_id}/command-logs")
def list_mikrotik_ap_management_command_logs(config_id: str, admin=Depends(current_admin)):
    config = fetch_one("SELECT id FROM mikrotik_ap_management_configs WHERE id = %s AND status <> 'ARCHIVED'", (config_id,))
    if not config:
        raise HTTPException(status_code=404, detail="AP management configuration not found")
    return [
        public_ap_management_command_log(row)
        for row in fetch_all(
            """
            SELECT l.*, mr.router_name, mr.host
            FROM mikrotik_ap_management_command_logs l
            LEFT JOIN mikrotik_routers mr ON mr.id = l.router_id
            WHERE l.config_id = %s
            ORDER BY l.created_at DESC
            LIMIT 100
            """,
            (config_id,),
        )
    ]


def mikrotik_ap_management_config_for_id(config_id: str) -> tuple[dict, list[dict], dict]:
    config = fetch_one("SELECT * FROM mikrotik_ap_management_configs WHERE id = %s AND status <> 'ARCHIVED'", (config_id,))
    if not config:
        raise HTTPException(status_code=404, detail="AP management configuration not found")
    routers = ap_management_router_rows(config_id)
    return config, routers, build_mikrotik_ap_management_plan(config, routers)


@app.get("/api/network/mikrotik/ap-management/{config_id}/managed-configuration-status")
def mikrotik_ap_management_managed_configuration_status(config_id: str, quiet: bool = False, admin=Depends(current_admin)):
    config, routers, plan = mikrotik_ap_management_config_for_id(config_id)
    total_steps = 0
    pushed_steps = 0
    router_statuses = []
    for router_plan in plan.get("router_plans") or []:
        commands = router_plan.get("commands") or []
        total_steps += len(commands)
        router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_plan["router_id"],))
        if not router:
            status = {"status": "ERROR", "message": "Router not found", "has_managed_config": False, "found_count": 0, "items": []}
        elif not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
            status = {"status": "NOT_READY", "message": "Router host, username, and password are required before checking AP management config.", "has_managed_config": False, "found_count": 0, "items": []}
        else:
            try:
                password = decrypt_secret(router.get("password_encrypted"))
                status = routeros_detect_station_apply_targets(
                    router["host"],
                    router["api_port"],
                    router.get("username"),
                    password,
                    router.get("use_tls"),
                    commands,
                )
            except Exception as exc:
                status = {"status": "ERROR", "message": sanitize_routeros_text(str(exc)), "has_managed_config": False, "found_count": 0, "items": []}
        pushed_steps += int(status.get("found_count") or 0)
        router_statuses.append({
            "router_id": router_plan["router_id"],
            "router_name": router_plan.get("router_name"),
            "host": router_plan.get("host"),
            **status,
        })
    summary_status = "SUCCESS" if router_statuses and all(item.get("status") in ("SUCCESS", "NOT_READY") for item in router_statuses) else "ERROR" if any(item.get("status") == "ERROR" for item in router_statuses) else "SUCCESS"
    result = {
        "status": summary_status,
        "config_id": config_id,
        "config_name": config["config_name"],
        "vlan_id": config["vlan_id"],
        "has_managed_config": pushed_steps > 0,
        "found_count": pushed_steps,
        "push_progress": {
            "pushed_steps": pushed_steps,
            "total_steps": total_steps,
            "routers": router_statuses,
        },
        "routers": router_statuses,
    }
    if not quiet:
        record_ap_management_command_log(config_id, None, "CHECK", None, {"label": "Check existing AP management config", "preview": "Detect 3J AP management RouterOS objects"}, summary_status, f"Found {pushed_steps} AP management step(s).", result, admin["id"])
        audit(admin["id"], "check_mikrotik_ap_management_config", "mikrotik_ap_management_configs", config_id, {"found_count": pushed_steps, "status": summary_status})
    return result


@app.post("/api/network/mikrotik/ap-management/{config_id}/implement-command")
def implement_mikrotik_ap_management_command(config_id: str, payload: MikrotikStationCommandApply, admin=Depends(current_admin)):
    config, routers, plan = mikrotik_ap_management_config_for_id(config_id)
    router_plan = next((item for item in plan.get("router_plans") or [] if item.get("router_id") == payload.router_id), None)
    if not router_plan:
        raise HTTPException(status_code=404, detail="Router is not part of this AP management plan")
    commands = router_plan.get("commands") or []
    if payload.command_index >= len(commands):
        raise HTTPException(status_code=404, detail="AP management command was not found")
    command = commands[payload.command_index]
    if not command.get("path") or not command.get("params"):
        raise HTTPException(status_code=400, detail="This AP management command is preview-only and cannot be applied.")
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (payload.router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    if not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        raise HTTPException(status_code=400, detail="Router host, username, and password are required before applying AP management configuration.")
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        if not password:
            raise RuntimeError("Saved MikroTik password could not be decrypted.")
        result = routeros_execute_commands(
            router["host"],
            router["api_port"],
            router.get("username"),
            password,
            router.get("use_tls"),
            [command],
        )
        command_result = (result.get("results") or [{}])[0]
        command_status = command_result.get("status") or result.get("status") or "SUCCESS"
        all_commands = [
            (item.get("router_id"), command_index)
            for item in plan.get("router_plans") or []
            for command_index, _ in enumerate(item.get("commands") or [])
        ]
        if all_commands and all_commands[-1] == (payload.router_id, payload.command_index) and command_status in ("SUCCESS", "SKIPPED"):
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE mikrotik_ap_management_configs SET status = 'ACTIVE', updated_at = now() WHERE id = %s", (config_id,))
        log_captive_portal_test(
            "IMPLEMENT_MIKROTIK_AP_MANAGEMENT_COMMAND",
            command_status,
            command_result.get("message") or result.get("message") or "AP management command completed.",
            {"config_id": config_id, "router_id": payload.router_id, "command_index": payload.command_index, "command": sanitize_summary(command), "result": sanitize_summary(command_result)},
        )
        record_ap_management_command_log(
            config_id,
            payload.router_id,
            "APPLY",
            payload.command_index,
            command,
            command_status,
            command_result.get("message") or result.get("message") or "AP management command completed.",
            command_result,
            admin["id"],
        )
        audit(
            admin["id"],
            "implement_mikrotik_ap_management_command",
            "mikrotik_ap_management_configs",
            config_id,
            {
                "router_id": payload.router_id,
                "router_name": router_plan.get("router_name"),
                "command_index": payload.command_index,
                "label": command.get("label"),
                "status": command_status,
            },
        )
        return {
            "status": command_status,
            "message": command_result.get("message") or result.get("message") or "AP management command completed.",
            "config_id": config_id,
            "router_id": payload.router_id,
            "command_index": payload.command_index,
            "command": sanitize_summary(command),
            "result": sanitize_summary(command_result),
        }
    except Exception as exc:
        message = sanitize_routeros_text(str(exc))
        record_ap_management_command_log(config_id, payload.router_id, "APPLY", payload.command_index, command, "FAILED", message, {"error": message}, admin["id"])
        log_captive_portal_test(
            "IMPLEMENT_MIKROTIK_AP_MANAGEMENT_COMMAND",
            "FAILED",
            message,
            {"config_id": config_id, "router_id": payload.router_id, "command_index": payload.command_index, "command": sanitize_summary(command)},
        )
        audit(
            admin["id"],
            "implement_mikrotik_ap_management_command",
            "mikrotik_ap_management_configs",
            config_id,
            {
                "router_id": payload.router_id,
                "router_name": router_plan.get("router_name"),
                "command_index": payload.command_index,
                "label": command.get("label"),
                "status": "FAILED",
                "error": message,
            },
        )
        raise HTTPException(status_code=400, detail=message)


@app.get("/api/network/mikrotik/stations/hotspot-login-sync-status")
def mikrotik_hotspot_login_sync_status(remote: bool = False, admin=Depends(current_admin)):
    stations = fetch_all("SELECT * FROM mikrotik_stations WHERE status <> 'ARCHIVED' ORDER BY updated_at DESC, created_at DESC")
    statuses = [mikrotik_hotspot_login_sync_status_for_station(station, remote_check=remote) for station in stations]
    synced = sum(1 for item in statuses if item.get("status") == "SYNCED")
    needs_sync = sum(1 for item in statuses if item.get("status") in {"MISSING", "OUTDATED", "DETECTED", "UNKNOWN"})
    failed = sum(1 for item in statuses if item.get("status") in {"ERROR", "FAILED", "NOT_READY"})
    return {
        "summary": {
            "total": len(statuses),
            "synced": synced,
            "needs_sync": needs_sync,
            "failed": failed,
        },
        "stations": statuses,
    }


@app.post("/api/network/mikrotik/stations/sync-hotspot-login")
def sync_all_mikrotik_hotspot_login(payload: Optional[MikrotikHotspotLoginSyncPayload] = None, admin=Depends(current_admin)):
    payload = payload or MikrotikHotspotLoginSyncPayload()
    params = []
    where = "status <> 'ARCHIVED'"
    if payload.station_ids:
        where += " AND id = ANY(%s::uuid[])"
        params.append(payload.station_ids)
    stations = fetch_all(f"SELECT * FROM mikrotik_stations WHERE {where} ORDER BY updated_at DESC, created_at DESC", tuple(params))
    results = [sync_mikrotik_hotspot_login_for_station(station, admin["id"]) for station in stations]
    success = sum(1 for item in results if item.get("status") == "SUCCESS")
    failed = len(results) - success
    status = "SUCCESS" if results and failed == 0 else "PARTIAL_SUCCESS" if success else "FAILED" if results else "NO_STATIONS"
    message = "No MikroTik stations are available for login.html sync." if not results else f"Synced {success}/{len(results)} station HotSpot login.html file(s)."
    log_captive_portal_test("SYNC_MIKROTIK_HOTSPOT_LOGIN_HTML", status, message, {"results": sanitize_summary(results)})
    audit(admin["id"], "sync_mikrotik_hotspot_login_html", "mikrotik_stations", None, {"status": status, "success": success, "failed": failed})
    return {"status": status, "message": message, "results": results}


@app.post("/api/network/mikrotik/stations/{station_id}/sync-hotspot-login")
def sync_one_mikrotik_hotspot_login(station_id: str, admin=Depends(current_admin)):
    station = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not station:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    result = sync_mikrotik_hotspot_login_for_station(station, admin["id"])
    log_captive_portal_test("SYNC_MIKROTIK_HOTSPOT_LOGIN_HTML", result.get("status") or "FAILED", result.get("message"), {"station_id": station_id, "result": sanitize_summary(result)})
    audit(admin["id"], "sync_mikrotik_hotspot_login_html", "mikrotik_stations", station_id, {"status": result.get("status"), "file_path": result.get("file_path")})
    if result.get("status") not in {"SUCCESS"}:
        raise HTTPException(status_code=400, detail=result.get("message") or "HotSpot login.html sync failed.")
    return result


@app.get("/api/network/mikrotik/stations/{station_id}")
def get_mikrotik_station(station_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    return public_mikrotik_station(row)


@app.get("/api/network/mikrotik/stations/{station_id}/hotspot-login.html")
def download_mikrotik_station_hotspot_login(station_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    return Response(
        content=build_mikrotik_hotspot_login_html(row),
        media_type="text/html",
        headers={"Content-Disposition": 'attachment; filename="login.html"'},
    )


@app.get("/api/network/mikrotik/stations/{station_id}/hotspot-diagnostics")
def get_mikrotik_station_hotspot_diagnostics(station_id: str, client_ip: Optional[str] = None, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    result = mikrotik_station_hotspot_diagnostics(row, client_ip)
    audit(admin["id"], "run_mikrotik_station_hotspot_diagnostics", "mikrotik_stations", station_id, {"status": result.get("status"), "client_ip": client_ip})
    return result


@app.post("/api/network/mikrotik/stations")
def create_mikrotik_station(payload: MikrotikStationCreate, admin=Depends(current_admin)):
    return save_mikrotik_station_payload(payload, admin)


@app.put("/api/network/mikrotik/stations/{station_id}")
def update_mikrotik_station(station_id: str, payload: MikrotikStationCreate, admin=Depends(current_admin)):
    return save_mikrotik_station_payload(payload, admin, station_id=station_id)


@app.delete("/api/network/mikrotik/stations/{station_id}")
def delete_mikrotik_station(station_id: str, admin=Depends(current_admin)):
    station = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not station:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_stations
                SET status = 'ARCHIVED', updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (station_id,),
            )
            archived = cur.fetchone()
    audit(
        admin["id"],
        "delete_mikrotik_station",
        "mikrotik_stations",
        station_id,
        {
            "station_name": station.get("station_name"),
            "station_code": station.get("station_code"),
            "note": "Station plan was archived only. RouterOS objects are not removed by station delete.",
        },
    )
    return {
        "status": "SUCCESS",
        "message": "Station plan deleted from the system. RouterOS configuration was not removed; use Remove Config before delete when router cleanup is needed.",
        "station": public_mikrotik_station(archived),
    }


@app.get("/api/network/mikrotik/stations/{station_id}/command-logs")
def list_mikrotik_station_command_logs(station_id: str, admin=Depends(current_admin)):
    station = fetch_one("SELECT id FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not station:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    return [
        public_station_command_log(row)
        for row in fetch_all(
            """
            SELECT l.*, mr.router_name, mr.host
            FROM mikrotik_station_command_logs l
            LEFT JOIN mikrotik_routers mr ON mr.id = l.router_id
            WHERE l.station_id = %s
            ORDER BY l.created_at DESC
            LIMIT 100
            """,
            (station_id,),
        )
    ]


def station_remove_plan_for_id(station_id: str) -> tuple[dict, list[dict], dict]:
    station = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not station:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    routers = station_router_rows(station_id)
    return station, routers, build_mikrotik_station_remove_plan(station, routers)


@app.get("/api/network/mikrotik/stations/{station_id}/managed-configuration-status")
def mikrotik_station_managed_configuration_status(station_id: str, quiet: bool = False, admin=Depends(current_admin)):
    station, routers, remove_plan = station_remove_plan_for_id(station_id)
    apply_plan = build_mikrotik_station_plan(station, routers)
    router_statuses = []
    total_found = 0
    total_steps = 1
    pushed_steps = 0
    apply_router_statuses = []
    for router_plan in apply_plan.get("router_plans") or []:
        commands = router_plan.get("commands") or []
        total_steps += len(commands)
        router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_plan["router_id"],))
        if not router:
            status = {"status": "ERROR", "message": "Router not found", "has_managed_config": False, "found_count": 0, "items": []}
        elif not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
            status = {"status": "NOT_READY", "message": "Router host, username, and password are required before checking station config.", "has_managed_config": False, "found_count": 0, "items": []}
        else:
            try:
                password = decrypt_secret(router.get("password_encrypted"))
                status = routeros_detect_station_apply_targets(
                    router["host"],
                    router["api_port"],
                    router.get("username"),
                    password,
                    router.get("use_tls"),
                    commands,
                )
            except Exception as exc:
                status = {"status": "ERROR", "message": sanitize_routeros_text(str(exc)), "has_managed_config": False, "found_count": 0, "items": []}
        pushed_steps += int(status.get("found_count") or 0)
        apply_router_statuses.append({
            "router_id": router_plan["router_id"],
            "router_name": router_plan.get("router_name"),
            "host": router_plan.get("host"),
            **status,
        })
    login_status = mikrotik_hotspot_login_sync_status_for_station(station, remote_check=True)
    if login_status.get("status") == "SYNCED":
        pushed_steps += 1
    for router_plan in remove_plan.get("router_plans") or []:
        router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_plan["router_id"],))
        if not router:
            status = {"status": "ERROR", "message": "Router not found", "has_managed_config": False, "found_count": 0, "items": []}
        elif not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
            status = {"status": "NOT_READY", "message": "Router host, username, and password are required before checking station config.", "has_managed_config": False, "found_count": 0, "items": []}
        else:
            try:
                password = decrypt_secret(router.get("password_encrypted"))
                status = routeros_detect_remove_targets(
                    router["host"],
                    router["api_port"],
                    router.get("username"),
                    password,
                    router.get("use_tls"),
                    router_plan.get("commands") or [],
                )
            except Exception as exc:
                status = {"status": "ERROR", "message": sanitize_routeros_text(str(exc)), "has_managed_config": False, "found_count": 0, "items": []}
        total_found += int(status.get("found_count") or 0)
        router_statuses.append({
            "router_id": router_plan["router_id"],
            "router_name": router_plan.get("router_name"),
            "host": router_plan.get("host"),
            **status,
        })
    combined_statuses = router_statuses + apply_router_statuses
    summary_status = "SUCCESS" if combined_statuses and all(item.get("status") in ("SUCCESS", "NOT_READY") for item in combined_statuses) else "ERROR" if any(item.get("status") == "ERROR" for item in combined_statuses) else "SUCCESS"
    result = {
        "status": summary_status,
        "station_id": station_id,
        "station_name": station["station_name"],
        "has_managed_config": total_found > 0,
        "found_count": total_found,
        "routers": router_statuses,
        "push_progress": {
            "pushed_steps": pushed_steps,
            "total_steps": total_steps,
            "login_html_status": login_status,
            "routers": apply_router_statuses,
        },
    }
    if not quiet:
        record_station_command_log(station_id, None, "CHECK", None, {"label": "Check existing station config", "preview": "Detect station-created RouterOS objects"}, summary_status, f"Found {total_found} station-managed object(s).", result, admin["id"])
        audit(admin["id"], "check_mikrotik_station_managed_configuration", "mikrotik_stations", station_id, {"found_count": total_found, "status": summary_status})
    return result


@app.post("/api/network/mikrotik/stations/{station_id}/implement-command")
def implement_mikrotik_station_command(station_id: str, payload: MikrotikStationCommandApply, admin=Depends(current_admin)):
    station = fetch_one("SELECT * FROM mikrotik_stations WHERE id = %s AND status <> 'ARCHIVED'", (station_id,))
    if not station:
        raise HTTPException(status_code=404, detail="MikroTik station not found")
    routers = station_router_rows(station_id)
    plan = build_mikrotik_station_plan(station, routers)
    router_plan = next((item for item in plan.get("router_plans") or [] if item.get("router_id") == payload.router_id), None)
    if not router_plan:
        raise HTTPException(status_code=404, detail="Router is not part of this station plan")
    commands = router_plan.get("commands") or []
    if payload.command_index >= len(commands):
        raise HTTPException(status_code=404, detail="Station command was not found")
    command = commands[payload.command_index]
    if not command.get("path") or not command.get("params"):
        raise HTTPException(status_code=400, detail="This station command is preview-only and cannot be applied.")
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (payload.router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    if not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        raise HTTPException(status_code=400, detail="Router host, username, and password are required before applying station configuration.")
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        if not password:
            raise RuntimeError("Saved MikroTik password could not be decrypted.")
        result = routeros_execute_commands(
            router["host"],
            router["api_port"],
            router.get("username"),
            password,
            router.get("use_tls"),
            [command],
        )
        command_result = (result.get("results") or [{}])[0]
        command_status = command_result.get("status") or result.get("status") or "SUCCESS"
        all_commands = [
            (item.get("router_id"), command_index)
            for item in plan.get("router_plans") or []
            for command_index, _ in enumerate(item.get("commands") or [])
        ]
        if all_commands and all_commands[-1] == (payload.router_id, payload.command_index) and command_status in ("SUCCESS", "SKIPPED"):
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE mikrotik_stations SET status = 'ACTIVE', updated_at = now() WHERE id = %s", (station_id,))
        log_captive_portal_test(
            "IMPLEMENT_MIKROTIK_STATION_COMMAND",
            command_status,
            command_result.get("message") or result.get("message") or "Station command completed.",
            {"station_id": station_id, "router_id": payload.router_id, "command_index": payload.command_index, "command": sanitize_summary(command), "result": sanitize_summary(command_result)},
        )
        record_station_command_log(
            station_id,
            payload.router_id,
            "APPLY",
            payload.command_index,
            command,
            command_status,
            command_result.get("message") or result.get("message") or "Station command completed.",
            command_result,
            admin["id"],
        )
        audit(
            admin["id"],
            "implement_mikrotik_station_command",
            "mikrotik_stations",
            station_id,
            {
                "router_id": payload.router_id,
                "router_name": router_plan.get("router_name"),
                "command_index": payload.command_index,
                "label": command.get("label"),
                "status": command_status,
            },
        )
        return {
            "status": command_status,
            "message": command_result.get("message") or result.get("message") or "Station command completed.",
            "station_id": station_id,
            "router_id": payload.router_id,
            "command_index": payload.command_index,
            "command": sanitize_summary(command),
            "result": sanitize_summary(command_result),
        }
    except Exception as exc:
        message = sanitize_routeros_text(str(exc))
        record_station_command_log(station_id, payload.router_id, "APPLY", payload.command_index, command, "FAILED", message, {"error": message}, admin["id"])
        log_captive_portal_test(
            "IMPLEMENT_MIKROTIK_STATION_COMMAND",
            "FAILED",
            message,
            {"station_id": station_id, "router_id": payload.router_id, "command_index": payload.command_index, "command": sanitize_summary(command)},
        )
        audit(
            admin["id"],
            "implement_mikrotik_station_command",
            "mikrotik_stations",
            station_id,
            {
                "router_id": payload.router_id,
                "router_name": router_plan.get("router_name"),
                "command_index": payload.command_index,
                "label": command.get("label"),
                "status": "FAILED",
                "error": message,
            },
        )
        raise HTTPException(status_code=400, detail=message)


@app.post("/api/network/mikrotik/stations/{station_id}/remove-command")
def remove_mikrotik_station_command(station_id: str, payload: MikrotikStationCommandApply, admin=Depends(current_admin)):
    station, _, remove_plan = station_remove_plan_for_id(station_id)
    router_plan = next((item for item in remove_plan.get("router_plans") or [] if item.get("router_id") == payload.router_id), None)
    if not router_plan:
        raise HTTPException(status_code=404, detail="Router is not part of this station remove plan")
    commands = router_plan.get("commands") or []
    if payload.command_index >= len(commands):
        raise HTTPException(status_code=404, detail="Station remove command was not found")
    command = commands[payload.command_index]
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (payload.router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    if not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        raise HTTPException(status_code=400, detail="Router host, username, and password are required before removing station configuration.")
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        if not password:
            raise RuntimeError("Saved MikroTik password could not be decrypted.")
        result = routeros_execute_remove_commands(
            router["host"],
            router["api_port"],
            router.get("username"),
            password,
            router.get("use_tls"),
            [command],
        )
        command_result = (result.get("results") or [{}])[0]
        command_status = command_result.get("status") or result.get("status") or "SUCCESS"
        all_commands = [
            (item.get("router_id"), command_index)
            for item in remove_plan.get("router_plans") or []
            for command_index, _ in enumerate(item.get("commands") or [])
        ]
        if all_commands and all_commands[-1] == (payload.router_id, payload.command_index) and command_status in ("SUCCESS", "SKIPPED"):
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE mikrotik_stations SET status = 'READY_FOR_REVIEW', updated_at = now() WHERE id = %s", (station_id,))
        record_station_command_log(
            station_id,
            payload.router_id,
            "REMOVE",
            payload.command_index,
            command,
            command_status,
            command_result.get("message") or result.get("message") or "Station remove command completed.",
            command_result,
            admin["id"],
        )
        log_captive_portal_test(
            "REMOVE_MIKROTIK_STATION_COMMAND",
            command_status,
            command_result.get("message") or result.get("message") or "Station remove command completed.",
            {"station_id": station_id, "router_id": payload.router_id, "command_index": payload.command_index, "command": sanitize_summary(command), "result": sanitize_summary(command_result)},
        )
        audit(
            admin["id"],
            "remove_mikrotik_station_command",
            "mikrotik_stations",
            station_id,
            {
                "router_id": payload.router_id,
                "router_name": router_plan.get("router_name"),
                "command_index": payload.command_index,
                "label": command.get("label"),
                "status": command_status,
            },
        )
        return {
            "status": command_status,
            "message": command_result.get("message") or result.get("message") or "Station remove command completed.",
            "station_id": station_id,
            "router_id": payload.router_id,
            "command_index": payload.command_index,
            "command": sanitize_summary(command),
            "result": sanitize_summary(command_result),
        }
    except Exception as exc:
        message = sanitize_routeros_text(str(exc))
        record_station_command_log(station_id, payload.router_id, "REMOVE", payload.command_index, command, "FAILED", message, {"error": message}, admin["id"])
        log_captive_portal_test(
            "REMOVE_MIKROTIK_STATION_COMMAND",
            "FAILED",
            message,
            {"station_id": station_id, "router_id": payload.router_id, "command_index": payload.command_index, "command": sanitize_summary(command)},
        )
        audit(
            admin["id"],
            "remove_mikrotik_station_command",
            "mikrotik_stations",
            station_id,
            {
                "router_id": payload.router_id,
                "router_name": router_plan.get("router_name"),
                "command_index": payload.command_index,
                "label": command.get("label"),
                "status": "FAILED",
                "error": message,
            },
        )
        raise HTTPException(status_code=400, detail=message)


@app.post("/api/captive-portal/mikrotik")
def create_mikrotik_router(payload: MikrotikRouterCreate, admin=Depends(current_admin)):
    privilege = (payload.account_privilege or "FULL").upper()
    if privilege not in ("FULL", "READ_ONLY"):
        raise HTTPException(status_code=400, detail="Invalid MikroTik account privilege")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_routers(router_name, host, api_port, use_tls, username, password_encrypted, account_privilege, notes, created_by_admin_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    payload.router_name,
                    payload.host,
                    payload.api_port,
                    payload.use_tls,
                    payload.username,
                    encrypt_secret(payload.password),
                    privilege,
                    payload.notes,
                    admin["id"],
                ),
            )
            row = cur.fetchone()
    audit(admin["id"], "create_mikrotik_router", "mikrotik_routers", str(row["id"]), {"host": payload.host, "api_port": payload.api_port, "use_tls": payload.use_tls, "account_privilege": privilege})
    hotspot_updates = {
        "hotspot_vlan_id": payload.hotspot_vlan_id,
        "hotspot_vlan_parent_interface": payload.hotspot_vlan_parent_interface,
        "hotspot_vlan_interface_name": payload.hotspot_vlan_interface_name,
        "hotspot_interface": payload.hotspot_interface,
        "hotspot_profile_name": payload.hotspot_profile_name,
        "hotspot_server_name": payload.hotspot_server_name,
        "hotspot_dns_name": payload.hotspot_dns_name,
        "hotspot_html_directory": payload.hotspot_html_directory,
        "hotspot_client_network_cidr": payload.hotspot_client_network_cidr,
        "hotspot_gateway_ip": payload.hotspot_gateway_ip,
        "hotspot_pool_start_ip": payload.hotspot_pool_start_ip,
        "hotspot_pool_end_ip": payload.hotspot_pool_end_ip,
        "hotspot_pool_name": payload.hotspot_pool_name,
        "hotspot_dhcp_server_name": payload.hotspot_dhcp_server_name,
        "hotspot_dhcp_lease_time": payload.hotspot_dhcp_lease_time,
        "hotspot_dns_servers": payload.hotspot_dns_servers,
        "hotspot_wan_interface": payload.hotspot_wan_interface,
        "hotspot_enable_nat": payload.hotspot_enable_nat,
    }
    hotspot_updates = {key: value for key, value in hotspot_updates.items() if value not in (None, "")}
    if hotspot_updates:
        assignments = ", ".join([f"{key} = %s" for key in hotspot_updates] + ["updated_at = now()"])
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE mikrotik_routers SET {assignments} WHERE id = %s RETURNING *", tuple(hotspot_updates.values()) + (row["id"],))
                row = cur.fetchone()
    return public_mikrotik_router(row)


@app.patch("/api/captive-portal/mikrotik/{router_id}")
def update_mikrotik_router(router_id: str, payload: MikrotikRouterUpdate, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    updates = payload.model_dump(exclude_unset=True)
    if "account_privilege" in updates and updates["account_privilege"]:
        updates["account_privilege"] = updates["account_privilege"].upper()
        if updates["account_privilege"] not in ("FULL", "READ_ONLY"):
            raise HTTPException(status_code=400, detail="Invalid MikroTik account privilege")
    if "password" in updates:
        updates["password_encrypted"] = encrypt_secret(updates.pop("password"))
    updates = {
        key: value
        for key, value in updates.items()
        if key in {
            "router_name",
            "host",
            "api_port",
            "use_tls",
            "username",
            "password_encrypted",
            "account_privilege",
            "notes",
            "hotspot_vlan_id",
            "hotspot_vlan_parent_interface",
            "hotspot_vlan_interface_name",
            "hotspot_interface",
            "hotspot_profile_name",
            "hotspot_server_name",
            "hotspot_dns_name",
            "hotspot_html_directory",
            "hotspot_client_network_cidr",
            "hotspot_gateway_ip",
            "hotspot_pool_start_ip",
            "hotspot_pool_end_ip",
            "hotspot_pool_name",
            "hotspot_dhcp_server_name",
            "hotspot_dhcp_lease_time",
            "hotspot_dns_servers",
            "hotspot_wan_interface",
            "hotspot_enable_nat",
        }
    }
    if updates:
        assignments = ", ".join([f"{key} = %s" for key in updates] + ["updated_at = now()"])
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE mikrotik_routers SET {assignments} WHERE id = %s RETURNING *", tuple(updates.values()) + (router_id,))
                row = cur.fetchone()
    audit(admin["id"], "update_mikrotik_router", "mikrotik_routers", router_id, sanitize_summary({k: v for k, v in updates.items() if k != "password_encrypted"}))
    return public_mikrotik_router(row)


@app.delete("/api/captive-portal/mikrotik/{router_id}")
def delete_mikrotik_router(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM mikrotik_routers WHERE id = %s", (router_id,))
    audit(admin["id"], "delete_mikrotik_router", "mikrotik_routers", router_id, {"host": row["host"], "router_name": row["router_name"]})
    return {"status": "deleted"}


@app.post("/api/captive-portal/mikrotik/{router_id}/test")
def test_mikrotik_router(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    try:
        password = decrypt_secret(row.get("password_encrypted"))
        result = test_mikrotik_api_login(row["host"], row["api_port"], row.get("username"), password, row.get("use_tls"))
        status = result["status"]
        message = result["message"]
    except (socket.timeout, TimeoutError):
        status = "UNREACHABLE"
        message = "Connection timed out. Check MikroTik API service, firewall, and route."
        result = {"status": status, "message": message}
    except ConnectionRefusedError:
        status = "UNREACHABLE"
        message = "Connection refused. Enable MikroTik API service on the selected port."
        result = {"status": status, "message": message}
    except Exception as exc:
        status = "ERROR"
        message = str(exc)
        result = {"status": status, "message": message}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE mikrotik_routers SET status = %s, last_test_at = now(), last_error = %s, updated_at = now() WHERE id = %s",
                (status, None if status == "REACHABLE" else message, router_id),
            )
    log_captive_portal_test("TEST_MIKROTIK_API", "SUCCESS" if status == "REACHABLE" else "FAILED", message, {"router_id": router_id, "host": row["host"], "api_port": row["api_port"], "status": status})
    audit(admin["id"], "test_mikrotik_router", "mikrotik_routers", router_id, {"status": status})
    return result


@app.get("/api/captive-portal/mikrotik/{router_id}/routeros-options")
def mikrotik_routeros_options(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    if not row.get("username") or not row.get("password_encrypted"):
        raise HTTPException(status_code=400, detail="RouterOS API username and password are required before loading dropdown options.")
    try:
        password = decrypt_secret(row.get("password_encrypted"))
        option_warnings = []

        def read_options(path: str, required: bool = False):
            try:
                return sanitize_routeros_snapshot(routeros_readonly_query(
                    row["host"],
                    row["api_port"],
                    row.get("username"),
                    password,
                    row.get("use_tls"),
                    [path],
                ))
            except Exception as exc:
                message = sanitize_routeros_text(str(exc), max_length=1000)
                option_warnings.append({"path": path, "message": message})
                if required:
                    raise
                return []

        interfaces = read_options("/interface/print", required=True)
        bridge_ports = read_options("/interface/bridge/port/print")
        interface_lists = read_options("/interface/list/print")
        bridge_membership = {
            sanitize_routeros_text(item.get("interface"), max_length=200): sanitize_routeros_text(item.get("bridge"), max_length=200)
            for item in bridge_ports
            if item.get("interface") and item.get("bridge")
        }
        public_interfaces = [
            {
                "name": sanitize_routeros_text(item.get("name"), max_length=200),
                "type": sanitize_routeros_text(item.get("type"), max_length=120),
                "running": item.get("running") == "true",
                "disabled": item.get("disabled") == "true",
                "bridge": bridge_membership.get(sanitize_routeros_text(item.get("name"), max_length=200)),
                "comment": sanitize_routeros_text(item.get("comment"), max_length=500),
            }
            for item in interfaces
            if item.get("name")
        ]
        public_interface_lists = sorted([
            {
                "name": sanitize_routeros_text(item.get("name"), max_length=200),
                "include": sanitize_routeros_text(item.get("include"), max_length=500),
                "exclude": sanitize_routeros_text(item.get("exclude"), max_length=500),
                "comment": sanitize_routeros_text(item.get("comment"), max_length=500),
            }
            for item in interface_lists
            if item.get("name")
        ], key=lambda item: item["name"].lower())
        public_interfaces.sort(key=lambda item: (item["disabled"], item["name"].lower()))
        audit(admin["id"], "load_mikrotik_routeros_options", "mikrotik_routers", router_id, {"interface_count": len(public_interfaces), "interface_list_count": len(public_interface_lists), "warning_count": len(option_warnings)})
        return {"status": "SUCCESS", "interfaces": public_interfaces, "interface_lists": public_interface_lists, "warnings": option_warnings}
    except Exception as exc:
        message = str(exc)
        audit(admin["id"], "load_mikrotik_routeros_options", "mikrotik_routers", router_id, {"status": "FAILED", "error": message})
        raise HTTPException(status_code=400, detail=f"Could not load MikroTik dropdown options: {message}")


def perform_mikrotik_preflight_scan(router: dict, admin_id: Optional[str] = None, batch_id: Optional[str] = None):
    router_id = str(router["id"])
    if not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
        raise RuntimeError("Router host, username, and saved password are required before running the preflight scan.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_preflight_scans(router_id, batch_id, scan_status, risk_level, scanned_by_admin_id)
                VALUES (%s, %s, 'PENDING', 'MEDIUM', %s)
                RETURNING *
                """,
                (router_id, batch_id, admin_id),
            )
            scan_row = cur.fetchone()
    scan_id = scan_row["id"]
    try:
        password = decrypt_secret(router.get("password_encrypted"))
        snapshot = routeros_readonly_snapshot(router["host"], router["api_port"], router.get("username"), password, router.get("use_tls"))
        snapshot["router_record"] = {
            "id": router_id,
            "router_name": router["router_name"],
            "host": router["host"],
            "api_port": router["api_port"],
            "use_tls": bool(router.get("use_tls")),
            "hotspot_vlan_id": router.get("hotspot_vlan_id"),
            "hotspot_vlan_parent_interface": router.get("hotspot_vlan_parent_interface"),
            "hotspot_vlan_interface_name": router.get("hotspot_vlan_interface_name"),
            "hotspot_client_network_cidr": router.get("hotspot_client_network_cidr"),
            "hotspot_pool_start_ip": router.get("hotspot_pool_start_ip"),
            "hotspot_pool_end_ip": router.get("hotspot_pool_end_ip"),
        }
        sanitized_snapshot = sanitize_routeros_snapshot(snapshot)
        analysis = analyze_mikrotik_preflight(router, sanitized_snapshot)
        sanitized_snapshot["analysis"] = sanitize_routeros_object(analysis)
        findings = analysis["findings"]
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE mikrotik_preflight_scans
                    SET scan_status = 'SUCCESS',
                        router_identity = %s,
                        router_model = %s,
                        router_version = %s,
                        router_role_guess = %s,
                        recommended_deployment_mode = %s,
                        risk_level = %s,
                        raw_snapshot_json = %s,
                        sanitized_snapshot_json = %s,
                        findings_json = %s,
                        conflicts_json = %s,
                        recommendations_json = %s,
                        last_error = NULL,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (
                        sanitize_routeros_text(analysis["router_identity"]),
                        sanitize_routeros_text(analysis["router_model"]),
                        sanitize_routeros_text(analysis["router_version"]),
                        analysis["router_role_guess"],
                        analysis["recommended_deployment_mode"],
                        analysis["risk_level"],
                        Json(json_safe(sanitized_snapshot)),
                        Json(json_safe(sanitized_snapshot)),
                        Json(json_safe(findings)),
                        Json(json_safe(analysis["conflicts"])),
                        Json(json_safe(analysis["recommendations"])),
                        scan_id,
                    ),
                )
                cur.execute("DELETE FROM mikrotik_preflight_findings WHERE scan_id = %s", (scan_id,))
                for finding in findings:
                    cur.execute(
                        """
                        INSERT INTO mikrotik_preflight_findings(scan_id, category, severity, title, message, related_object, recommendation)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            scan_id,
                            finding.get("category"),
                            finding.get("severity"),
                            sanitize_routeros_text(finding.get("title")),
                            sanitize_routeros_text(finding.get("message")),
                            sanitize_routeros_text(finding.get("related_object")),
                            sanitize_routeros_text(finding.get("recommendation")),
                        ),
                    )
                cur.execute(
                    "UPDATE mikrotik_routers SET status = 'REACHABLE', last_test_at = now(), last_error = NULL, updated_at = now() WHERE id = %s",
                    (router_id,),
                )
        latest = fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_id,))
        evaluate_and_store_mikrotik_policy(router, latest)
        log_captive_portal_test("MIKROTIK_PREFLIGHT_SCAN", "SUCCESS", "MikroTik preflight scan completed.", {"router_id": router_id, "scan_id": str(scan_id), "risk_level": analysis["risk_level"], "role_guess": analysis["router_role_guess"]})
        return fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_id,))
    except Exception as exc:
        message = sanitize_routeros_text(str(exc))
        if "unicode" in message.lower() or "\\u0000" in message or "null byte" in message.lower():
            message = "Failed due to invalid RouterOS text. Try re-scan after sanitizer update."
        failed_finding = mikrotik_finding("SYSTEM", "BLOCKER", "Preflight scan failed", message, None, "Check MikroTik reachability, API service, firewall, and credentials.")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE mikrotik_preflight_scans
                    SET scan_status = 'FAILED',
                        risk_level = 'BLOCKED',
                        last_error = %s,
                        findings_json = %s,
                        conflicts_json = %s,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (
                        message,
                        Json(json_safe([failed_finding])),
                        Json(json_safe([failed_finding])),
                        scan_id,
                    ),
                )
                cur.execute(
                    "UPDATE mikrotik_routers SET status = 'ERROR', last_error = %s, updated_at = now() WHERE id = %s",
                    (message, router_id),
                )
        latest = fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_id,))
        evaluate_and_store_mikrotik_policy(router, latest)
        log_captive_portal_test("MIKROTIK_PREFLIGHT_SCAN", "FAILED", message, {"router_id": router_id, "scan_id": str(scan_id)})
        return fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_id,))


def mikrotik_router_next_action(scan, policy) -> str:
    if not scan:
        return "Run preflight scan"
    if scan.get("scan_status") != "SUCCESS":
        error_text = str(scan.get("last_error") or "")
        if "unicode" in error_text.lower() or "\\u0000" in error_text or "null byte" in error_text.lower():
            return "Fix invalid RouterOS text and re-scan"
        return "Fix API reachability and run scan again"
    if not policy:
        return "Evaluate policy"
    if policy.get("blocking_reasons"):
        if any("Deployment mode is not confirmed" in item for item in policy.get("blocking_reasons") or []):
            if policy.get("role_guess") == "PPPoE_ACCESS_CONCENTRATOR":
                return "Confirm mode and dedicated VLAN/subnet"
            return "Confirm deployment mode"
        if any("overlap" in item.lower() or "already exists" in item.lower() for item in policy.get("blocking_reasons") or []):
            return "Review VLAN/subnet conflicts"
        return "Resolve blocking conflicts"
    if policy.get("requires_expert_override") and not policy.get("expert_override_enabled"):
        return "Review expert override"
    if policy.get("confirmed_deployment_mode") in ("READ_ONLY_CORE", "ISP_BACKUP_TRANSPORT"):
        return "Keep read-only"
    if policy.get("confirmed_deployment_mode") == "VLAN_TRUNK_HELPER":
        return "Use future VLAN trunk helper mode"
    if policy.get("setup_allowed"):
        if policy.get("pilot_suitability") == "GOOD_PILOT":
            return "Candidate for pilot after command preview"
        return "Ready for future command preview"
    return "Review preflight"


def build_mikrotik_preflight_summary() -> dict:
    routers = fetch_all("SELECT * FROM mikrotik_routers ORDER BY created_at DESC")
    latest_batch = fetch_one("SELECT * FROM mikrotik_preflight_scan_batches ORDER BY created_at DESC LIMIT 1")
    readiness = []
    role_counts = {}
    mode_counts = {}
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "BLOCKED": 0}
    vlan_usage = {}
    network_conflicts = []
    high_risk = []
    hotspot_candidates = []
    read_only = []
    trunk_helpers = []
    missing_scan = []
    unreachable = []
    failed_scans = []
    requires_confirmation = []
    blocked_by_conflicts = []
    scanned = 0
    for router in routers:
        scan_row = latest_mikrotik_scan_row(str(router["id"]))
        policy_row = latest_mikrotik_policy_row(str(router["id"]), scan_row["id"] if scan_row else None)
        if scan_row and not policy_row:
            policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
        scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=True) if scan_row else None
        policy = public_mikrotik_policy_result(policy_row)
        if policy and scan:
            policy.update({
                "role_reasoning": scan.get("role_reasoning") or [],
                "deployment_reasoning": scan.get("deployment_reasoning") or [],
                "pilot_suitability": scan.get("pilot_suitability") or "UNKNOWN",
                "pilot_reason": scan.get("pilot_reason"),
            })
        if scan:
            scanned += 1
            risk_counts[scan.get("risk_level") or "MEDIUM"] = risk_counts.get(scan.get("risk_level") or "MEDIUM", 0) + 1
            role = normalize_mikrotik_router_role(scan.get("router_role_guess"))
            role_counts[role] = role_counts.get(role, 0) + 1
            mode = (policy or {}).get("recommended_deployment_mode") or normalize_mikrotik_deployment_mode(scan.get("recommended_deployment_mode"))
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
            analysis = ((scan.get("sanitized_snapshot") or {}).get("analysis") or {})
            for vlan_id in ((analysis.get("summary") or {}).get("existing_vlan_ids") or []):
                vlan_usage.setdefault(str(vlan_id), []).append(router["router_name"])
            for item in scan.get("findings") or []:
                if item.get("severity") == "BLOCKER":
                    network_conflicts.append({"router": router["router_name"], "category": item.get("category"), "title": item.get("title"), "message": item.get("message")})
            if scan.get("risk_level") in ("HIGH", "BLOCKED"):
                high_risk.append(router["router_name"])
            if scan.get("scan_status") != "SUCCESS":
                failed_scans.append(router["router_name"])
            if role in ("HOTSPOT_GATEWAY_CANDIDATE", "PPPoE_ACCESS_CONCENTRATOR") and (scan.get("pilot_suitability") in ("GOOD_PILOT", "POSSIBLE_WITH_CAUTION")):
                hotspot_candidates.append(router["router_name"])
            if role == "CORE_ROUTER_READ_ONLY" or (policy or {}).get("confirmed_deployment_mode") == "READ_ONLY_CORE":
                read_only.append(router["router_name"])
            if role == "SWITCH_TRUNK_HELPER":
                trunk_helpers.append(router["router_name"])
            if not (policy or {}).get("confirmed_deployment_mode") or ((policy or {}).get("requires_expert_override") and not (policy or {}).get("expert_override_enabled")):
                requires_confirmation.append(router["router_name"])
        else:
            missing_scan.append(router["router_name"])
        if router.get("status") in ("UNREACHABLE", "ERROR", "AUTH_FAILED"):
            unreachable.append(router["router_name"])
        blocking_count = len((policy or {}).get("blocking_reasons") or [])
        hard_blockers = [
            reason for reason in ((policy or {}).get("blocking_reasons") or [])
            if any(token in reason.lower() for token in ["overlap", "already exists", "invalid", "core/routing", "not allowed"])
        ]
        if hard_blockers:
            blocked_by_conflicts.append(router["router_name"])
        readiness.append({
            "router_id": router["id"],
            "router": router["router_name"],
            "host": f"{router['host']}:{router['api_port']}",
            "api_status": router.get("status") or "NOT_TESTED",
            "scan_id": scan.get("id") if scan else None,
            "last_scan": scan.get("created_at") if scan else None,
            "risk_level": (policy or {}).get("risk_level") or (scan or {}).get("risk_level") or "NOT_SCANNED",
            "role_guess": (policy or {}).get("role_guess") or (scan or {}).get("router_role_guess") or "UNKNOWN_NEEDS_REVIEW",
            "recommended_deployment_mode": (policy or {}).get("recommended_deployment_mode") or normalize_mikrotik_deployment_mode((scan or {}).get("recommended_deployment_mode")),
            "confirmed_deployment_mode": (policy or {}).get("confirmed_deployment_mode"),
            "blocking_conflicts": blocking_count,
            "hard_blocking_conflicts": len(hard_blockers),
            "setup_allowed": bool((policy or {}).get("setup_allowed")),
            "next_action": mikrotik_router_next_action(scan, policy),
            "scan_status": scan.get("scan_status") if scan else "NOT_SCANNED",
            "confirmation_status": "CONFIRMED" if (policy or {}).get("confirmed_deployment_mode") else "NEEDS_CONFIRMATION",
            "pilot_suitability": scan.get("pilot_suitability") if scan else "UNKNOWN",
            "pilot_reason": scan.get("pilot_reason") if scan else None,
            "policy": policy,
        })
    duplicate_vlans = [
        {"vlan_id": vlan_id, "routers": names, "message": f"VLAN {vlan_id} appears on {len(names)} router scan(s). Confirm this is expected trunking before reuse."}
        for vlan_id, names in vlan_usage.items()
        if len(names) > 1
    ][:50]
    summary = {
        "last_full_prescan": latest_batch["completed_at"] or latest_batch["started_at"] if latest_batch else None,
        "latest_batch": public_mikrotik_preflight_batch(latest_batch) if latest_batch else None,
        "cards": {
            "total_routers": len(routers),
            "scanned": scanned,
            "reachable": sum(1 for router in routers if router.get("status") == "REACHABLE"),
            "failed_unreachable": len(unreachable),
            "failed_scans": len(failed_scans),
            "high_risk": risk_counts.get("HIGH", 0),
            "blocked": risk_counts.get("BLOCKED", 0),
            "hotspot_gateway_candidates": len(hotspot_candidates),
            "requires_confirmation": len(set(requires_confirmation)),
            "read_only_core": len(read_only),
            "vlan_trunk_helpers": len(trunk_helpers),
            "blocked_by_conflicts": len(set(blocked_by_conflicts)),
        },
        "risk_counts": risk_counts,
        "role_counts": role_counts,
        "deployment_mode_counts": mode_counts,
        "readiness": readiness,
        "network_conflicts": network_conflicts[:100],
        "duplicate_vlan_usage": duplicate_vlans,
        "high_risk_routers": high_risk,
        "hotspot_gateway_candidates": hotspot_candidates,
        "read_only_core_routers": read_only,
        "vlan_trunk_helper_candidates": trunk_helpers,
        "routers_missing_scan": missing_scan,
        "routers_unreachable": unreachable,
        "routers_failed_scan": failed_scans,
        "requires_confirmation_routers": sorted(set(requires_confirmation)),
        "blocked_by_conflict_routers": sorted(set(blocked_by_conflicts)),
        "recommended_rollout_order": [
            "Start with one lab, office, or pilot router.",
            "Do not start with core routers or routers carrying public/OSPF/PPPoE-sensitive traffic.",
            "Do not configure CRS/switch devices as HotSpot gateways.",
            "Confirm AP/customer VLAN path end to end.",
            "Run one-router/site validation before any command preview or apply phase.",
        ],
    }
    return summary


def public_mikrotik_preflight_batch(row) -> Optional[dict]:
    if not row:
        return None
    items = fetch_all(
        """
        SELECT bi.*, mr.router_name, mr.host, mr.api_port
        FROM mikrotik_preflight_scan_batch_items bi
        LEFT JOIN mikrotik_routers mr ON mr.id = bi.router_id
        WHERE bi.batch_id = %s
        ORDER BY bi.created_at ASC
        """,
        (row["id"],),
    )
    return {
        "id": row["id"],
        "status": row["status"],
        "total_routers": row["total_routers"],
        "scanned_count": row["scanned_count"],
        "success_count": row["success_count"],
        "failed_count": row["failed_count"],
        "skipped_count": row["skipped_count"],
        "max_concurrency": row["max_concurrency"],
        "summary": row.get("summary_json"),
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "last_error": row["last_error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "items": [
            {
                "id": item["id"],
                "batch_id": item["batch_id"],
                "router_id": item["router_id"],
                "router_name": item.get("router_name"),
                "host": f"{item.get('host')}:{item.get('api_port')}" if item.get("host") else None,
                "scan_id": item["scan_id"],
                "status": item["status"],
                "started_at": item["started_at"],
                "completed_at": item["completed_at"],
                "error_message": item["error_message"],
            }
            for item in items
        ],
    }


def mikrotik_ai_system_prompt(mode: str = "chat") -> str:
    base = (
        "You are an advisory network assistant for 3JCentralPisowifi. "
        "Help non-technical ISP operators understand sanitized MikroTik preflight scan data and plan a safe pilot. "
        "You must not generate executable RouterOS commands, CLI snippets, scripts, or terminal instructions. "
        "You must not tell the user to apply changes directly. "
        "You must not bypass the deterministic safety policy engine. "
        "Treat PPPoE, OSPF, WireGuard, core routing, existing production bridges, and non-system-managed objects as protected. "
        "A PPPoE access concentrator is high risk, but it is not automatically read-only/core; HotSpot Gateway planning may be possible with a new dedicated VLAN/subnet and explicit confirmation. "
        "Do not recommend Read-only/Core for PPPoE access concentrators unless strong core-only indicators are present. "
        "Do not guess the AP/customer VLAN parent interface. If the VLAN path through CRS, OLT, ONU, switch, or AP is not confirmed, ask the operator to confirm the bridge/trunk path and return null for that field. "
        "Warn when a client subnet is larger than /22 and prefer /24 or /22 for first pilot tests. "
        "Prefer one office/lab/pilot router first. Do not recommend core routers or CRS/switches as HotSpot gateways. "
        "Ask clarifying questions when required details are missing. State uncertainty when scan data is incomplete. "
        "Never expose or ask for passwords, API keys, RADIUS secrets, WireGuard keys, tokens, or private keys."
    )
    if mode == "draft_plan":
        return (
            base
            + " Return only one JSON object. Do not use markdown. Do not include executable RouterOS commands. "
            "The object must use the requested draft deployment plan fields and may use null for unknown values."
        )
    if mode == "planning_suggestions":
        return (
            base
            + " Return only one JSON object. Do not use markdown. Suggest planning answers only. "
            "Do not invent interface names not present in the sanitized scan data. "
            "For vlan_parent_interface, return null unless the operator already confirmed the AP/customer VLAN path or scan/topology data proves the bridge/trunk path. "
            "Ask the operator to confirm CRS/OLT/AP VLAN path when uncertain."
        )
    return base + " Keep explanations plain and concise. Label your advice as guidance only, not approval to apply RouterOS changes."


def mikrotik_ai_safe_context(router_id: Optional[str] = None) -> dict:
    summary = build_mikrotik_preflight_summary()
    context = {
        "project_direction": "Captive Portal + Voucher. MikroTik is gateway/enforcement; Omada manages AP/SSID; 3JCentralPisowifi remains source of truth.",
        "safety_boundary": "MT-3 is advisory only. RouterOS writes and command generation are disabled.",
        "openai_data_policy": "This payload is sanitized. Secrets are redacted before AI use.",
        "preflight_summary": {
            "last_full_prescan": summary.get("last_full_prescan"),
            "cards": summary.get("cards") or {},
            "role_counts": summary.get("role_counts") or {},
            "deployment_mode_counts": summary.get("deployment_mode_counts") or {},
            "recommended_rollout_order": summary.get("recommended_rollout_order") or [],
        },
        "router_readiness": [
            {
                "router_id": row.get("router_id"),
                "router": row.get("router"),
                "host": row.get("host"),
                "api_status": row.get("api_status"),
                "risk_level": row.get("risk_level"),
                "role_guess": row.get("role_guess"),
                "recommended_deployment_mode": row.get("recommended_deployment_mode"),
                "confirmed_deployment_mode": row.get("confirmed_deployment_mode"),
                "blocking_conflicts": row.get("blocking_conflicts"),
                "next_action": row.get("next_action"),
                "pilot_suitability": row.get("pilot_suitability"),
                "pilot_reason": row.get("pilot_reason"),
            }
            for row in (summary.get("readiness") or [])
        ],
    }
    if router_id:
        router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
        scan_row = latest_mikrotik_scan_row(router_id) if router else None
        policy_row = latest_mikrotik_policy_row(router_id, scan_row["id"] if scan_row else None) if router else None
        if router and scan_row and not policy_row:
            policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
        scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=True) if scan_row else None
        context["selected_router"] = {
            "router": public_mikrotik_router(router) if router else None,
            "scan": mikrotik_preflight_ai_payload(scan) if scan else None,
            "policy": public_mikrotik_policy_result(policy_row),
            "deployment_questions": [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)] if router else [],
        }
    return sanitize_summary(context)


def rank_mikrotik_pilot_candidates(summary: dict) -> list[dict]:
    ranked = []
    for row in summary.get("readiness") or []:
        role = row.get("role_guess")
        suitability = row.get("pilot_suitability")
        risk = row.get("risk_level")
        router_name = str(row.get("router") or "").lower()
        score = 0
        reasons = []
        if suitability == "GOOD_PILOT":
            score += 60
            reasons.append("Good pilot suitability from preflight policy.")
        elif suitability == "POSSIBLE_WITH_CAUTION":
            score += 35
            reasons.append("Possible with caution after confirmation.")
        elif suitability == "NOT_RECOMMENDED":
            score -= 80
            reasons.append("Not recommended as the first pilot.")
        if role in ("HOTSPOT_GATEWAY_CANDIDATE", "PPPoE_ACCESS_CONCENTRATOR"):
            score += 20
        if role == "CORE_ROUTER_READ_ONLY":
            score -= 120
            reasons.append("Core/read-only routers must not be first pilot gateways.")
        if role == "SWITCH_TRUNK_HELPER":
            score -= 90
            reasons.append("CRS/switch devices are VLAN helpers only, not HotSpot gateways.")
        if row.get("api_status") == "REACHABLE":
            score += 10
        if risk == "LOW":
            score += 15
        elif risk == "MEDIUM":
            score += 8
        elif risk == "HIGH":
            score -= 10
        elif risk == "BLOCKED":
            score -= 100
            reasons.append("Blocked by policy/conflict.")
        if row.get("blocking_conflicts"):
            score -= int(row.get("blocking_conflicts") or 0) * 12
        if any(token in router_name for token in ["office", "lab", "pilot", "test", "local"]):
            score += 15
            reasons.append("Name suggests office/lab/pilot router.")
        if not row.get("confirmed_deployment_mode"):
            reasons.append("Deployment mode still needs confirmation.")
        action = "Confirm deployment mode first"
        if score >= 70:
            action = "Good pilot candidate after MT-4 preview"
        elif score >= 35:
            action = "Possible with caution"
        elif role == "CORE_ROUTER_READ_ONLY":
            action = "Read-only/core, do not configure"
        elif role == "SWITCH_TRUNK_HELPER":
            action = "VLAN trunk helper only"
        elif risk == "BLOCKED":
            action = "Resolve blockers first"
        ranked.append({
            "router_id": row.get("router_id"),
            "router": row.get("router"),
            "role_guess": role,
            "risk_level": risk,
            "pilot_suitability": suitability,
            "score": score,
            "reason": " ".join(reasons) or row.get("pilot_reason") or row.get("next_action"),
            "recommended_action": action,
        })
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked


MIKROTIK_DEPLOYMENT_QUESTION_DEFS = [
    ("pilot_router_confirmed", "Is this MikroTik the first pilot router/site?"),
    ("router_role_confirmed", "Confirm the router role: gateway, PPPoE access concentrator, core/read-only, switch/trunk, or transport."),
    ("deployment_mode_confirmed", "Confirm deployment mode: HotSpot Gateway, VLAN Trunk Helper, Read-only/Core, Transport, or Unknown."),
    ("vlan_parent_interface", "Which MikroTik interface, bridge, or trunk carries the AP/customer VLAN?"),
    ("customer_vlan_id", "What customer VLAN ID should be used for the open captive portal SSID?"),
    ("vlan_interface_name", "What MikroTik VLAN interface name should the system use for this customer VLAN?"),
    ("client_network_cidr", "What dedicated client subnet should voucher WiFi users receive?"),
    ("gateway_ip", "What gateway IP should MikroTik use for that client subnet?"),
    ("dhcp_pool", "What DHCP pool start and end IP should clients receive?"),
    ("nat_enabled", "Should MikroTik create NAT masquerade for captive portal clients?"),
    ("wan_interface", "If NAT is enabled, which WAN/Internet interface should be used?"),
    ("dns_servers", "Which DNS servers should captive portal clients use?"),
    ("hotspot_dns_name", "What HotSpot DNS name should be used for browser redirects?"),
    ("portal_url", "What portal URL should clients access before login?"),
    ("read_only_routers", "Which routers must remain read-only/core or transport-only?"),
]


MIKROTIK_DEPLOYMENT_QUESTION_META = {
    "pilot_router_confirmed": {"category": "Pilot / Router Role", "helper_text": "Confirm this is the one router you can safely test first. Prefer a lab or easy-to-recover router.", "required_for_preview": False},
    "router_role_confirmed": {"category": "Pilot / Router Role", "helper_text": "Describe whether this router is a gateway, PPPoE access concentrator, core router, switch/trunk helper, or transport router.", "required_for_preview": True},
    "deployment_mode_confirmed": {"category": "Pilot / Router Role", "helper_text": "This must match the confirmed mode in Preflight Scanner before command preview.", "required_for_preview": True},
    "vlan_parent_interface": {"category": "AP / Customer VLAN", "helper_text": "The MikroTik bridge, trunk, or port where tagged AP customer traffic arrives. This is usually the path from APs to the router, not the WAN.", "required_for_preview": True},
    "customer_vlan_id": {"category": "AP / Customer VLAN", "helper_text": "VLAN number used by the open SSID for voucher customers. It must match APs Deployment -> Sites -> Configurations.", "required_for_preview": True},
    "vlan_interface_name": {"category": "AP / Customer VLAN", "helper_text": "System-owned MikroTik VLAN interface name. It is normally auto-derived from System Display Name and VLAN ID.", "required_for_preview": True},
    "client_network_cidr": {"category": "Client IP Network", "helper_text": "Private subnet for voucher users, for example 10.30.0.0/24. Do not reuse office LAN or AP management networks.", "required_for_preview": True},
    "gateway_ip": {"category": "Client IP Network", "helper_text": "MikroTik IP inside the client subnet, for example 10.30.0.1. It should not be inside the DHCP pool.", "required_for_preview": True},
    "dhcp_pool": {"category": "Client IP Network", "helper_text": "Client IP range, for example 10.30.0.10-10.30.0.254. Both ends must be inside the client subnet.", "required_for_preview": True},
    "dns_servers": {"category": "HotSpot / Portal", "helper_text": "Comma-separated DNS IP addresses, for example 1.1.1.1,8.8.8.8.", "required_for_preview": True},
    "hotspot_dns_name": {"category": "HotSpot / Portal", "helper_text": "Local HotSpot redirect name shown to clients. Avoid .local because phones may treat it as mDNS. Example: wifi.3j.3jportal.test.", "required_for_preview": True},
    "portal_url": {"category": "HotSpot / Portal", "helper_text": "Customer voucher portal URL. Staging is usually http://192.168.50.70:8080/portal.", "required_for_preview": True},
    "nat_enabled": {"category": "NAT / Internet", "helper_text": "Answer yes if this MikroTik should NAT voucher users to the internet directly. Answer no if upstream routing will handle it.", "required_for_preview": True},
    "wan_interface": {"category": "NAT / Internet", "helper_text": "Required only when NAT is yes. This is the internet/uplink interface, not the AP/customer VLAN interface.", "required_for_preview": False},
    "read_only_routers": {"category": "Protected Routers", "helper_text": "List routers that must remain scan-only, such as core, transport, OSPF, or backup routers.", "required_for_preview": False},
}


def ensure_mikrotik_deployment_questions(router_id: str) -> list:
    router = fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    with get_conn() as conn:
        with conn.cursor() as cur:
            for key, text in MIKROTIK_DEPLOYMENT_QUESTION_DEFS:
                meta = MIKROTIK_DEPLOYMENT_QUESTION_META.get(key, {})
                cur.execute(
                    """
                    INSERT INTO mikrotik_deployment_questions(router_id, question_key, question_text, required_for_preview)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (router_id, question_key) DO UPDATE
                    SET question_text = EXCLUDED.question_text,
                        required_for_preview = EXCLUDED.required_for_preview,
                        updated_at = mikrotik_deployment_questions.updated_at
                    """,
                    (router_id, key, text, bool(meta.get("required_for_preview", True))),
                )
    return fetch_all("SELECT * FROM mikrotik_deployment_questions WHERE router_id = %s ORDER BY created_at ASC, question_key ASC", (router_id,))


def public_mikrotik_deployment_question(row) -> dict:
    meta = MIKROTIK_DEPLOYMENT_QUESTION_META.get(row["question_key"], {})
    return {
        "id": row["id"],
        "router_id": row["router_id"],
        "question_key": row["question_key"],
        "question_text": row["question_text"],
        "category": meta.get("category", "Planning"),
        "helper_text": meta.get("helper_text"),
        "answer_value": row.get("answer_value"),
        "suggested_value": row.get("suggested_value"),
        "approved_value": row.get("approved_value"),
        "answer_status": row.get("answer_status") or ("EMPTY" if not row.get("answer_value") else "USER_EDITED"),
        "suggestion_reason": row.get("suggestion_reason"),
        "suggestion_confidence": row.get("suggestion_confidence"),
        "suggestion_requires_review": bool(row.get("suggestion_requires_review", True)),
        "derived_from": row.get("derived_from"),
        "is_derived": bool(row.get("is_derived", False)),
        "locked": bool(row.get("locked", False)),
        "validation_status": row.get("validation_status"),
        "validation_errors": row.get("validation_errors_json") or [],
        "answered_by_admin_id": row.get("answered_by_admin_id"),
        "answered_at": row.get("answered_at"),
        "updated_by_admin_id": row.get("updated_by_admin_id"),
        "required_for_preview": bool(meta.get("required_for_preview", row["required_for_preview"])),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def mikrotik_effective_question_value(item: dict) -> str:
    if item.get("answer_status") in ("APPROVED", "LOCKED") and item.get("approved_value") not in (None, ""):
        return str(item.get("approved_value") or "").strip()
    return str(item.get("answer_value") or "").strip()


def mikrotik_question_answer_map(questions: list[dict]) -> dict:
    return {item["question_key"]: mikrotik_effective_question_value(item) for item in questions}


def latest_mikrotik_snapshot_summary(router_id: str) -> dict:
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row or scan_row.get("scan_status") != "SUCCESS":
        return {}
    scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=True)
    return ((((scan or {}).get("sanitized_snapshot") or {}).get("analysis") or {}).get("summary") or {})


def derive_mikrotik_network_fields(cidr: Optional[str]) -> dict:
    result = {
        "status": "EMPTY",
        "cidr": cidr,
        "errors": [],
        "derived": {},
    }
    text = str(cidr or "").strip()
    if not text:
        return result
    try:
        network = ip_network(text, strict=False)
    except Exception:
        result["status"] = "ERROR"
        result["errors"].append("CIDR is not valid. Use a value like 10.15.0.0/20.")
        return result
    if network.version != 4:
        result["status"] = "ERROR"
        result["errors"].append("Only IPv4 CIDR is supported for MikroTik HotSpot planning.")
        return result
    if network.num_addresses < 16:
        result["status"] = "ERROR"
        result["errors"].append("CIDR is too small for a practical captive portal DHCP pool. Use at least a /28 or larger.")
        return result
    first = ip_address(int(network.network_address) + 1)
    last = ip_address(int(network.broadcast_address) - 1)
    pool_start_int = int(network.network_address) + 10
    if pool_start_int > int(last):
        pool_start_int = int(first) + 1
    pool_start = ip_address(pool_start_int)
    pool_end = last
    usable_hosts = max(network.num_addresses - 2, 0)
    result.update({
        "status": "SUCCESS",
        "cidr": str(network),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "first_usable_ip": str(first),
        "last_usable_ip": str(last),
        "gateway_ip": str(first),
        "pool_start_ip": str(pool_start),
        "pool_end_ip": str(pool_end),
        "usable_hosts": usable_hosts,
        "range": f"{network.network_address} - {network.broadcast_address}",
        "dhcp_pool": f"{pool_start}-{pool_end}",
        "derived": {
            "client_network_cidr": str(network),
            "gateway_ip": str(first),
            "dhcp_pool": f"{pool_start}-{pool_end}",
        },
    })
    return result


def mikrotik_safe_name_slug(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return text or "3jcentralpisowifi"


def mikrotik_vlan_interface_name(vlan_id: Optional[str]) -> Optional[str]:
    text = str(vlan_id or "").strip()
    if not text:
        return None
    try:
        value = int(text)
    except Exception:
        return None
    if value < 1 or value > 4094:
        return None
    return f"{mikrotik_safe_name_slug(system_display_name())}-vlan{value}"


def mikrotik_question_rows_by_key(router_id: str) -> dict:
    return {row["question_key"]: row for row in ensure_mikrotik_deployment_questions(router_id)}


def mikrotik_apply_derivation(router_id: str, source_key: str, target_key: str, new_value: Optional[str], reason: str, admin_id: Optional[str] = None):
    rows = mikrotik_question_rows_by_key(router_id)
    row = rows.get(target_key)
    if not row or row.get("locked"):
        return None
    old_value = row.get("answer_value")
    if (old_value or "") == (new_value or ""):
        return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_questions
                SET answer_value = %s,
                    approved_value = NULL,
                    answer_status = CASE WHEN %s = '' THEN 'EMPTY' ELSE 'USER_EDITED' END,
                    derived_from = %s,
                    is_derived = true,
                    answered_by_admin_id = %s,
                    answered_at = CASE WHEN %s = '' THEN NULL ELSE now() END,
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE router_id = %s AND question_key = %s
                """,
                (new_value or None, new_value or "", source_key, admin_id, new_value or "", admin_id, router_id, target_key),
            )
            cur.execute(
                """
                INSERT INTO mikrotik_planning_derivations(router_id, source_question_key, target_question_key, old_value, new_value, reason, applied)
                VALUES (%s, %s, %s, %s, %s, %s, true)
                """,
                (router_id, source_key, target_key, old_value, new_value, reason),
            )
    return {"target_question_key": target_key, "old_value": old_value, "new_value": new_value, "reason": reason}


def mikrotik_auto_derive_from_answers(router_id: str, answers: dict, admin_id: Optional[str] = None) -> list[dict]:
    derivations = []
    cidr = answers.get("client_network_cidr")
    if cidr:
        preview = derive_mikrotik_network_fields(cidr)
        if preview.get("status") == "SUCCESS":
            for target_key, value in (preview.get("derived") or {}).items():
                if target_key == "client_network_cidr":
                    continue
                item = mikrotik_apply_derivation(router_id, "client_network_cidr", target_key, value, "Auto-derived from client network CIDR.", admin_id)
                if item:
                    derivations.append(item)
    vlan_name = mikrotik_vlan_interface_name(answers.get("customer_vlan_id"))
    if vlan_name:
        item = mikrotik_apply_derivation(router_id, "customer_vlan_id", "vlan_interface_name", vlan_name, "Auto-derived from customer VLAN ID.", admin_id)
        if item:
            derivations.append(item)
    return derivations


def mikrotik_interface_candidates(router_id: str) -> dict:
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row or scan_row.get("scan_status") != "SUCCESS":
        return {"groups": [], "items": []}
    scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=True)
    paths = (((scan.get("sanitized_snapshot") or {}).get("paths") or {}))
    interface_rows = ((paths.get("interfaces") or {}).get("items") or [])
    bridge_rows = ((paths.get("bridges") or {}).get("items") or [])
    vlan_rows = ((paths.get("interface_vlans") or {}).get("items") or [])
    pppoe_rows = ((paths.get("pppoe_servers") or {}).get("items") or [])
    wireguard_rows = ((paths.get("wireguard") or {}).get("items") or [])
    routes = ((paths.get("routes") or {}).get("items") or [])
    bridge_names = {str(item.get("name") or "") for item in bridge_rows if item.get("name")}
    bridge_by_name = {str(item.get("name") or ""): item for item in bridge_rows if item.get("name")}
    bridge_ports = ((paths.get("bridge_ports") or {}).get("items") or [])
    bridge_port_by_interface = {str(item.get("interface") or ""): item for item in bridge_ports if item.get("interface")}
    bridge_vlan_rows = ((paths.get("bridge_vlans") or {}).get("items") or [])
    vlan_usage_by_interface: dict[str, list[str]] = {}
    for vlan_row in bridge_vlan_rows:
        vlan_ids = str(vlan_row.get("vlan-ids") or vlan_row.get("vlan_ids") or "").strip()
        for field in ["tagged", "untagged", "current-tagged", "current-untagged", "current_tagged", "current_untagged"]:
            for name in re.split(r"[,;\s]+", str(vlan_row.get(field) or "")):
                clean = name.strip()
                if clean and vlan_ids:
                    vlan_usage_by_interface.setdefault(clean, []).append(vlan_ids)
    vlan_interfaces = {str(item.get("interface") or "") for item in vlan_rows if item.get("interface")}
    pppoe_interfaces = {str(item.get("interface") or "") for item in pppoe_rows if item.get("interface")}
    wireguard_names = {str(item.get("name") or "") for item in wireguard_rows if item.get("name")}
    routed_interfaces = {str(item.get("gateway") or "") for item in routes if item.get("gateway")}
    items = []
    for row in interface_rows:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        type_text = str(row.get("type") or "").lower()
        labels = []
        group = "unknown"
        avoid = False
        if name in bridge_names or type_text == "bridge":
            group = "bridge interfaces"
            labels.append("Bridge interface")
            bridge_row = bridge_by_name.get(name) or {}
            if str(bridge_row.get("vlan-filtering") or bridge_row.get("vlan_filtering") or "").lower() == "true":
                labels.append("Bridge VLAN filtering enabled")
                group = "vlan-filtered bridges"
        elif type_text in {"ether", "sfp", "sfp-sfpplus", "bonding"}:
            group = "physical interfaces"
            labels.append("Physical interface")
        elif "vlan" in type_text:
            group = "existing VLAN interfaces"
            labels.append("Existing VLAN interface")
        if name in vlan_interfaces:
            labels.append("Likely trunk or VLAN parent")
            if group == "physical interfaces":
                group = "likely trunks"
        bridge_port = bridge_port_by_interface.get(name)
        bridge_membership = bridge_port.get("bridge") if bridge_port else None
        if bridge_membership:
            labels.append(f"Bridge port of {bridge_membership}")
            if group == "unknown":
                group = "bridge ports"
        existing_vlans = sorted(set(vlan_usage_by_interface.get(name) or []))
        if existing_vlans:
            labels.append(f"Existing VLANs: {', '.join(existing_vlans[:6])}")
        if str(row.get("disabled") or "").lower() == "true":
            labels.append("Disabled")
            avoid = True
        if name in pppoe_interfaces or "pppoe" in name.lower():
            labels.append("PPPoE-related, avoid")
            avoid = True
        if name in wireguard_names or "wireguard" in name.lower() or "wg" == name.lower():
            labels.append("WireGuard-related, avoid")
            avoid = True
        if name in routed_interfaces:
            labels.append("Has routing sensitivity")
        if any(token in name.lower() for token in ["wan", "internet", "uplink"]):
            labels.append("Core/WAN candidate, avoid unless NAT")
        items.append({
            "name": name,
            "type": row.get("type"),
            "group": group,
            "labels": labels,
            "avoid": avoid,
            "running": row.get("running"),
            "comment": row.get("comment"),
            "bridge_membership": bridge_membership,
            "vlan_filtering": "Bridge VLAN filtering enabled" in labels,
            "existing_vlans": existing_vlans,
        })
    groups = []
    avoid_items = [item for item in items if item["avoid"]]
    for group_name in ["bridge interfaces", "vlan-filtered bridges", "likely trunks", "bridge ports", "physical interfaces", "existing VLAN interfaces", "unknown"]:
        grouped = [item for item in items if item["group"] == group_name and not item["avoid"]]
        if grouped:
            groups.append({"group": group_name, "items": grouped})
    if avoid_items:
        groups.append({"group": "sensitive / avoid", "items": avoid_items})
    return {"groups": groups, "items": items}


def public_mikrotik_vlan_path_plan(row, router_id: Optional[str] = None) -> dict:
    if not row:
        return {
            "id": None,
            "router_id": router_id,
            "hotspot_gateway_router_id": router_id,
            "gateway_parent_interface": None,
            "next_hop_type": "UNKNOWN",
            "crs_involved": False,
            "crs_router_id": None,
            "crs_port_to_gateway": None,
            "crs_ports_to_olt_ap": None,
            "olts_involved": False,
            "olt_notes": None,
            "olt_vlan_behavior": "UNKNOWN",
            "ap_vlan_mode": "UNKNOWN",
            "ssid_vlan_id": None,
            "confirmation_status": "DRAFT",
            "confirmed_by_admin_id": None,
            "confirmed_at": None,
            "created_at": None,
            "updated_at": None,
        }
    return {
        "id": row["id"],
        "router_id": row["router_id"],
        "hotspot_gateway_router_id": row.get("hotspot_gateway_router_id"),
        "gateway_parent_interface": row.get("gateway_parent_interface"),
        "next_hop_type": row.get("next_hop_type") or "UNKNOWN",
        "crs_involved": bool(row.get("crs_involved")),
        "crs_router_id": row.get("crs_router_id"),
        "crs_port_to_gateway": row.get("crs_port_to_gateway"),
        "crs_ports_to_olt_ap": row.get("crs_ports_to_olt_ap"),
        "olts_involved": bool(row.get("olts_involved")),
        "olt_notes": row.get("olt_notes"),
        "olt_vlan_behavior": row.get("olt_vlan_behavior") or "UNKNOWN",
        "ap_vlan_mode": row.get("ap_vlan_mode") or "UNKNOWN",
        "ssid_vlan_id": row.get("ssid_vlan_id"),
        "confirmation_status": row.get("confirmation_status") or "DRAFT",
        "confirmed_by_admin_id": row.get("confirmed_by_admin_id"),
        "confirmed_at": row.get("confirmed_at"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def get_mikrotik_vlan_path_plan_row(router_id: str):
    return fetch_one("SELECT * FROM mikrotik_vlan_path_plans WHERE router_id = %s", (router_id,))


def validate_mikrotik_vlan_path_plan(plan: dict, answers: Optional[dict] = None) -> dict:
    answers = answers or {}
    errors = []
    warnings = []
    if not str(plan.get("gateway_parent_interface") or "").strip():
        errors.append("Gateway VLAN parent interface/bridge is required before MT-4.")
    if plan.get("crs_involved"):
        if not plan.get("crs_router_id") and not str(plan.get("crs_port_to_gateway") or plan.get("crs_ports_to_olt_ap") or "").strip():
            warnings.append("CRS is involved. Identify the CRS device or explain the CRS ports before command preview.")
        warnings.append("CRS may need VLAN trunk helper configuration in a later phase.")
    if plan.get("olts_involved"):
        if (plan.get("olt_vlan_behavior") or "UNKNOWN") == "UNKNOWN":
            warnings.append("OLT VLAN behavior must be confirmed before applying MikroTik commands.")
        if not str(plan.get("olt_notes") or "").strip():
            warnings.append("OLTs are involved. Add OLT names or notes so the VLAN path is reviewable.")
    customer_vlan = None
    try:
        customer_vlan = int(str(answers.get("customer_vlan_id") or "").strip()) if answers.get("customer_vlan_id") else None
    except Exception:
        customer_vlan = None
    if (plan.get("ap_vlan_mode") or "UNKNOWN") == "TAGGED":
        if not customer_vlan:
            errors.append("Customer VLAN ID is required when AP receives tagged VLAN.")
        else:
            warnings.append(f"AP tagged VLAN should use customer VLAN {customer_vlan}; no separate SSID VLAN value is required.")
    if (plan.get("ap_vlan_mode") or "UNKNOWN") == "UNTAGGED":
        warnings.append("AP receives untagged/access VLAN. Confirm downstream CRS/OLT/ONU conversion before MT-4.")
    if (plan.get("confirmation_status") or "DRAFT") != "CONFIRMED":
        errors.append("VLAN path plan must be confirmed before MT-4 command preview.")
    return {
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
        "complete": not errors,
    }


def save_mikrotik_ai_planning_suggestions(admin_id: Optional[str], router_id: str, status: str, prompt_summary: str, suggestions: Optional[dict] = None, warnings: Optional[list] = None, error_message: Optional[str] = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_ai_planning_suggestions(router_id, admin_id, prompt_summary, suggestions_json, warnings_json, status, error_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    router_id,
                    admin_id,
                    sanitize_routeros_text(prompt_summary or "", max_length=1200),
                    Json(json_safe(suggestions or {})),
                    Json(json_safe(warnings or [])),
                    status,
                    sanitize_routeros_text(error_message or "", max_length=2000) if error_message else None,
                ),
            )
            return cur.fetchone()


def apply_mikrotik_ai_suggestions_to_questions(router_id: str, suggestions: list[dict], admin_id: Optional[str]):
    allowed_keys = {key for key, _ in MIKROTIK_DEPLOYMENT_QUESTION_DEFS}
    updated = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            for item in suggestions:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("question_key") or "").strip()
                if key not in allowed_keys:
                    continue
                suggested = item.get("suggested_value")
                suggested_text = sanitize_routeros_text(str(suggested), max_length=2000) if suggested not in (None, "") else None
                reason = sanitize_routeros_text(item.get("reason") or "", max_length=2000)
                confidence = str(item.get("confidence") or "low").strip().lower()
                requires_review = bool(item.get("requires_user_review", True))
                cur.execute(
                    """
                    UPDATE mikrotik_deployment_questions
                    SET suggested_value = %s,
                        answer_value = CASE
                            WHEN %s = '' THEN answer_value
                            WHEN COALESCE(answer_status, 'EMPTY') IN ('EMPTY', 'AI_SUGGESTED', 'REJECTED') OR COALESCE(answer_value, '') = '' THEN %s
                            ELSE answer_value
                        END,
                        approved_value = CASE
                            WHEN COALESCE(answer_status, 'EMPTY') IN ('APPROVED', 'LOCKED') THEN approved_value
                            ELSE NULL
                        END,
                        suggestion_reason = %s,
                        suggestion_confidence = %s,
                        suggestion_requires_review = %s,
                        answer_status = CASE
                            WHEN locked THEN 'LOCKED'
                            WHEN %s = '' THEN answer_status
                            WHEN COALESCE(answer_status, 'EMPTY') IN ('EMPTY', 'AI_SUGGESTED', 'REJECTED') OR COALESCE(answer_value, '') = '' THEN 'AI_SUGGESTED'
                            ELSE answer_status
                        END,
                        answered_by_admin_id = CASE
                            WHEN %s = '' THEN answered_by_admin_id
                            WHEN COALESCE(answer_status, 'EMPTY') IN ('EMPTY', 'AI_SUGGESTED', 'REJECTED') OR COALESCE(answer_value, '') = '' THEN %s
                            ELSE answered_by_admin_id
                        END,
                        answered_at = CASE
                            WHEN %s = '' THEN answered_at
                            WHEN COALESCE(answer_status, 'EMPTY') IN ('EMPTY', 'AI_SUGGESTED', 'REJECTED') OR COALESCE(answer_value, '') = '' THEN now()
                            ELSE answered_at
                        END,
                        updated_by_admin_id = %s,
                        updated_at = now()
                    WHERE router_id = %s AND question_key = %s AND locked = false
                    RETURNING *
                    """,
                    (
                        suggested_text,
                        suggested_text or "",
                        suggested_text,
                        reason or None,
                        confidence or None,
                        requires_review,
                        suggested_text or "",
                        suggested_text or "",
                        admin_id,
                        suggested_text or "",
                        admin_id,
                        router_id,
                        key,
                    ),
                )
                row = cur.fetchone()
                if row:
                    updated.append(public_mikrotik_deployment_question(row))
    return updated


def mikrotik_ai_planning_suggestion_context(router: dict, router_id: str, questions: list[dict], interface_candidates: dict) -> dict:
    scan_row = latest_mikrotik_scan_row(router_id)
    policy_row = latest_mikrotik_policy_row(router_id, scan_row["id"] if scan_row else None)
    if scan_row and not policy_row:
        policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
    snapshot_summary = latest_mikrotik_snapshot_summary(router_id)
    compact_interfaces = []
    for item in (interface_candidates.get("items") or [])[:40]:
        compact_interfaces.append({
            "name": item.get("name"),
            "type": item.get("type"),
            "group": item.get("group"),
            "labels": item.get("labels") or [],
            "avoid": bool(item.get("avoid")),
        })
    return sanitize_summary({
        "router": {
            "id": router_id,
            "name": router.get("router_name"),
            "host": router.get("host"),
        },
        "latest_scan": {
            "id": scan_row.get("id") if scan_row else None,
            "status": scan_row.get("scan_status") if scan_row else None,
            "identity": scan_row.get("router_identity") if scan_row else None,
            "model": scan_row.get("router_model") if scan_row else None,
            "version": scan_row.get("router_version") if scan_row else None,
            "risk_level": scan_row.get("risk_level") if scan_row else None,
            "role_guess": scan_row.get("router_role_guess") if scan_row else None,
            "recommended_deployment_mode": scan_row.get("recommended_deployment_mode") if scan_row else None,
        },
        "policy": public_mikrotik_policy_result(policy_row),
        "existing_network_summary": {
            "existing_vlan_ids": snapshot_summary.get("existing_vlan_ids") or [],
            "existing_subnets": (snapshot_summary.get("existing_subnets") or [])[:40],
            "existing_pools": (snapshot_summary.get("existing_pools") or [])[:40],
            "counts": snapshot_summary.get("counts") or {},
        },
        "current_questions": [
            {
                "question_key": item.get("question_key"),
                "question_text": item.get("question_text"),
                "category": item.get("category"),
                "required_for_preview": item.get("required_for_preview"),
                "answer_value": item.get("answer_value"),
                "approved_value": item.get("approved_value"),
                "answer_status": item.get("answer_status"),
                "locked": item.get("locked"),
            }
            for item in questions
        ],
        "interface_candidates": compact_interfaces,
    })


def choose_unused_mikrotik_vlan(existing_vlan_ids: list) -> str:
    used = set()
    for item in existing_vlan_ids or []:
        try:
            used.add(int(item))
        except Exception:
            continue
    for vlan_id in [777, 778, 779, 880, 881, 990, 991]:
        if vlan_id not in used:
            return str(vlan_id)
    for vlan_id in range(700, 900):
        if vlan_id not in used:
            return str(vlan_id)
    return "777"


def choose_unused_mikrotik_client_cidr(existing_subnets: list) -> str:
    existing_networks = []
    for item in existing_subnets or []:
        try:
            existing_networks.append(ip_network(str(item.get("network")), strict=False))
        except Exception:
            continue
    candidates = ["10.77.0.0/24", "10.78.0.0/24", "10.79.0.0/24", "10.250.0.0/24", "172.31.240.0/24", "10.77.0.0/22"]
    for cidr in candidates:
        network = ip_network(cidr, strict=False)
        if not any(network.overlaps(existing) for existing in existing_networks):
            return cidr
    return "10.77.0.0/24"


def build_mikrotik_deterministic_planning_suggestions(router_id: str, questions: list[dict], interface_candidates: dict) -> list[dict]:
    rows = {item["question_key"]: item for item in questions}
    summary = latest_mikrotik_snapshot_summary(router_id)
    policy_row = latest_mikrotik_policy_row(router_id, latest_mikrotik_scan_row(router_id)["id"] if latest_mikrotik_scan_row(router_id) else None)
    policy = public_mikrotik_policy_result(policy_row)
    interface_items = interface_candidates.get("items") or []
    suggestions = []

    def add(key: str, value: Optional[str], reason: str, confidence: str = "medium", requires_review: bool = True):
        if key not in rows:
            return
        suggestions.append({
            "question_key": key,
            "suggested_value": value,
            "reason": reason,
            "confidence": confidence,
            "requires_user_review": requires_review,
        })

    role_value = policy.get("confirmed_router_role") or policy.get("role_guess")
    mode_value = policy.get("confirmed_deployment_mode") or policy.get("recommended_deployment_mode")
    if role_value == "PPPoE_ACCESS_CONCENTRATOR" and mode_value in (None, "", "UNKNOWN_NEEDS_REVIEW", "READ_ONLY_CORE"):
        mode_value = "HOTSPOT_GATEWAY"
    add("pilot_router_confirmed", "yes" if active_mikrotik_pilot_selection() and str(active_mikrotik_pilot_selection().get("router_id")) == str(router_id) else "no", "Derived from the active pilot router selection.", "high", True)
    add("router_role_confirmed", role_value, "Derived from the latest preflight policy role guess/confirmation.", "medium", True)
    add("deployment_mode_confirmed", mode_value, "Derived from the latest preflight policy deployment recommendation/confirmation.", "medium", True)

    add("vlan_parent_interface", None, "The AP/customer VLAN path is not confirmed. Choose the bridge or trunk on the HotSpot gateway that carries VLAN traffic toward CRS/OLT/APs.", "low", True)

    vlan_id = choose_unused_mikrotik_vlan(summary.get("existing_vlan_ids") or [])
    add("customer_vlan_id", vlan_id, f"VLAN {vlan_id} was not found in the selected router's latest preflight VLAN list.", "medium", True)
    add("vlan_interface_name", mikrotik_vlan_interface_name(vlan_id), "Derived from the system display name and suggested customer VLAN ID.", "high", False)

    client_cidr = choose_unused_mikrotik_client_cidr(summary.get("existing_subnets") or [])
    network_preview = derive_mikrotik_network_fields(client_cidr)
    add("client_network_cidr", client_cidr, "Selected from private CIDR candidates that do not overlap the selected router's scanned subnets.", "medium", True)
    if network_preview.get("status") == "SUCCESS":
        add("gateway_ip", network_preview.get("gateway_ip"), "Auto-derived as the first usable IP in the suggested client subnet.", "high", False)
        add("dhcp_pool", network_preview.get("dhcp_pool"), "Auto-derived from the suggested client subnet, starting at network + 10.", "high", False)

    add("dns_servers", "1.1.1.1,8.8.8.8", "Safe public DNS defaults for captive portal clients. Change if the ISP requires local DNS.", "medium", True)
    add("hotspot_dns_name", default_hotspot_dns_name("3j"), "Default HotSpot DNS name for client browser redirects. Avoids .local so phones use normal DNS.", "medium", True)
    settings = public_captive_portal_settings()
    add("portal_url", settings.get("portal_url_staging") or "http://192.168.50.70:8080/portal", "Derived from Captive Portal staging settings.", "high", False)

    wan_candidate = None
    for item in interface_items:
        name = str(item.get("name") or "")
        labels = " ".join(item.get("labels") or []).lower()
        if any(token in name.lower() for token in ["wan", "internet", "uplink"]) or "wan" in labels:
            wan_candidate = name
            break
    if wan_candidate:
        add("nat_enabled", "yes", "A likely WAN/uplink interface was found. Confirm NAT design before MT-4.", "low", True)
        add("wan_interface", wan_candidate, "Chosen from scanned interface names that look like WAN/uplink candidates. Confirm before MT-4.", "low", True)
    else:
        add("nat_enabled", "no", "No clear WAN/uplink interface was detected. Use no by default until the operator confirms NAT is needed.", "low", True)
        add("wan_interface", None, "WAN interface is required only if NAT is enabled.", "low", True)

    add("read_only_routers", "", "Optional note. List protected routers only if this pilot plan depends on them.", "low", True)
    return suggestions


def complete_mikrotik_planning_suggestions(router_id: str, questions: list[dict], ai_suggestions: list[dict], interface_candidates: dict) -> list[dict]:
    by_key = {}
    for item in ai_suggestions or []:
        if isinstance(item, dict) and item.get("question_key"):
            by_key[str(item["question_key"])] = item
    question_by_key = {item.get("question_key"): item for item in questions}
    policy_row = latest_mikrotik_policy_row(router_id, latest_mikrotik_scan_row(router_id)["id"] if latest_mikrotik_scan_row(router_id) else None)
    policy = public_mikrotik_policy_result(policy_row)
    if (policy or {}).get("role_guess") == "PPPoE_ACCESS_CONCENTRATOR":
        mode_item = by_key.get("deployment_mode_confirmed")
        if mode_item and str(mode_item.get("suggested_value") or "").strip().upper() in {"READ_ONLY_CORE", "CORE_ROUTER_READ_ONLY", "READ-ONLY/CORE", "READ ONLY CORE"}:
            by_key["deployment_mode_confirmed"] = {
                **mode_item,
                "suggested_value": "HOTSPOT_GATEWAY",
                "reason": "This router is a PPPoE access concentrator. It is high risk, but HotSpot Gateway planning is possible with a new dedicated VLAN/subnet while PPPoE, OSPF, WireGuard, and routing stay protected.",
                "confidence": "medium",
                "requires_user_review": True,
            }
    vlan_parent_question = question_by_key.get("vlan_parent_interface") or {}
    if vlan_parent_question.get("answer_status") not in ("APPROVED", "LOCKED"):
        by_key["vlan_parent_interface"] = {
            "question_key": "vlan_parent_interface",
            "suggested_value": None,
            "reason": "The AP/customer VLAN path is not confirmed. Choose the bridge or trunk on the HotSpot gateway that carries VLAN traffic toward CRS/OLT/APs.",
            "confidence": "low",
            "requires_user_review": True,
        }
    for item in build_mikrotik_deterministic_planning_suggestions(router_id, questions, interface_candidates):
        key = item.get("question_key")
        if not key:
            continue
        existing = by_key.get(key)
        if not existing or existing.get("suggested_value") in (None, ""):
            by_key[key] = item
    if by_key.get("router_role_confirmed", {}).get("suggested_value"):
        by_key["router_role_confirmed"]["suggested_value"] = normalize_mikrotik_router_role(by_key["router_role_confirmed"].get("suggested_value"))
    if by_key.get("deployment_mode_confirmed", {}).get("suggested_value"):
        by_key["deployment_mode_confirmed"]["suggested_value"] = normalize_mikrotik_deployment_mode(by_key["deployment_mode_confirmed"].get("suggested_value"))
    allowed_order = [key for key, _ in MIKROTIK_DEPLOYMENT_QUESTION_DEFS]
    return [by_key[key] for key in allowed_order if key in by_key]


def update_question_validation_metadata(router_id: str, validation: dict):
    error_text = " ".join(validation.get("errors") or [])
    warning_text = " ".join(validation.get("warnings") or [])
    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in ensure_mikrotik_deployment_questions(router_id):
                public = public_mikrotik_deployment_question(row)
                key = public["question_key"]
                related = []
                for item in validation.get("errors") or []:
                    lower = item.lower()
                    if key.replace("_", " ") in lower or key.split("_")[0] in lower:
                        related.append(item)
                status = "ERROR" if related else ("WARNING" if warning_text and public.get("answer_value") else "OK")
                cur.execute(
                    """
                    UPDATE mikrotik_deployment_questions
                    SET validation_status = %s,
                        validation_errors_json = %s,
                        updated_at = now()
                    WHERE router_id = %s AND question_key = %s
                    """,
                    (status, Json(json_safe(related)), router_id, key),
                )


def active_mikrotik_pilot_selection():
    return fetch_one(
        """
        SELECT ps.*, mr.router_name, mr.host, mr.api_port
        FROM mikrotik_pilot_selection ps
        JOIN mikrotik_routers mr ON mr.id = ps.router_id
        WHERE ps.status = 'ACTIVE'
        ORDER BY ps.updated_at DESC
        LIMIT 1
        """
    )


def public_mikrotik_pilot_selection(row) -> Optional[dict]:
    if not row:
        return None
    return {
        "id": row["id"],
        "router_id": row["router_id"],
        "router_name": row.get("router_name"),
        "host": f"{row.get('host')}:{row.get('api_port')}" if row.get("host") else None,
        "selected_by_admin_id": row.get("selected_by_admin_id"),
        "reason": row.get("reason"),
        "physical_recovery_confidence": row.get("physical_recovery_confidence"),
        "operator_note": row.get("operator_note"),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def public_mikrotik_smoke_test(row) -> Optional[dict]:
    if not row:
        return None
    return {
        "id": row["id"],
        "admin_id": row.get("admin_id"),
        "status": row["status"],
        "prompt_summary": row.get("prompt_summary"),
        "response_summary": row.get("response_summary"),
        "error_message": row.get("error_message"),
        "created_at": row["created_at"],
    }


def parse_yes_no(value) -> Optional[bool]:
    text = str(value or "").strip().lower()
    if text in {"yes", "y", "true", "1", "enabled", "enable", "nat", "on"}:
        return True
    if text in {"no", "n", "false", "0", "disabled", "disable", "off", "none"}:
        return False
    return None


def parse_dhcp_pool_answer(value) -> tuple[Optional[str], Optional[str]]:
    text = str(value or "").strip()
    if not text:
        return None, None
    normalized = re.sub(r"\s+(to|until|through)\s+", "-", text, flags=re.IGNORECASE)
    normalized = normalized.replace(" ", "")
    if "-" in normalized:
        start, end = normalized.split("-", 1)
        return start.strip(), end.strip()
    parts = [part.strip() for part in re.split(r"[,/]", normalized) if part.strip()]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None, None


def validate_mikrotik_question_answers(questions: list[dict], router_id: Optional[str] = None) -> dict:
    answers = mikrotik_question_answer_map(questions)
    errors = []
    warnings = []
    required_keys = [
        key for key, meta in MIKROTIK_DEPLOYMENT_QUESTION_META.items()
        if meta.get("required_for_preview")
    ]
    for key in required_keys:
        if not answers.get(key):
            errors.append(f"{MIKROTIK_DEPLOYMENT_QUESTION_META[key]['category']}: {key.replace('_', ' ')} is required.")
    question_by_key = {item["question_key"]: item for item in questions}
    for key in required_keys:
        item = question_by_key.get(key) or {}
        status = item.get("answer_status")
        if answers.get(key) and status not in ("APPROVED", "LOCKED"):
            errors.append(f"{MIKROTIK_DEPLOYMENT_QUESTION_META[key]['category']}: {key.replace('_', ' ')} must be approved before MT-4 readiness.")
    vlan_text = answers.get("customer_vlan_id")
    vlan_id = None
    if vlan_text:
        try:
            vlan_id = int(vlan_text)
            if vlan_id < 1 or vlan_id > 4094:
                errors.append("Customer VLAN ID must be between 1 and 4094.")
        except Exception:
            errors.append("Customer VLAN ID must be numeric.")
    network = None
    cidr = answers.get("client_network_cidr")
    if cidr:
        try:
            network = ip_network(cidr, strict=False)
            if network.version != 4:
                errors.append("Client IP range must be an IPv4 CIDR.")
            if network.num_addresses < 16:
                errors.append("Client IP range is too small for a practical DHCP pool. Use at least a /28 or larger.")
            if network.prefixlen < 22:
                warnings.append("This is a large WiFi/HotSpot client network. For pilot testing, use /24 or /22 unless you are sure the network needs more clients.")
        except Exception:
            errors.append("Client IP range must be a valid CIDR, for example 10.30.0.0/24.")
    gateway_text = answers.get("gateway_ip")
    gateway_ip_value = None
    if gateway_text:
        try:
            gateway_ip_value = ip_address(gateway_text)
            if network and gateway_ip_value not in network:
                errors.append("Gateway IP must be inside the client IP range.")
            if network and gateway_ip_value in (network.network_address, network.broadcast_address):
                errors.append("Gateway IP cannot be the network or broadcast address.")
        except Exception:
            errors.append("Gateway IP must be a valid IP address.")
    pool_start_text, pool_end_text = parse_dhcp_pool_answer(answers.get("dhcp_pool"))
    pool_start = pool_end = None
    if answers.get("dhcp_pool"):
        if not pool_start_text or not pool_end_text:
            errors.append("DHCP pool must include start and end IPs, for example 10.30.0.10-10.30.0.254.")
        else:
            try:
                pool_start = ip_address(pool_start_text)
                pool_end = ip_address(pool_end_text)
                if int(pool_start) > int(pool_end):
                    errors.append("DHCP pool start must be lower than or equal to pool end.")
                if network and pool_start not in network:
                    errors.append("DHCP pool start must be inside the client IP range.")
                if network and pool_end not in network:
                    errors.append("DHCP pool end must be inside the client IP range.")
                if gateway_ip_value and int(pool_start) <= int(gateway_ip_value) <= int(pool_end):
                    errors.append("DHCP pool must not include the gateway IP.")
            except Exception:
                errors.append("DHCP pool start/end must be valid IP addresses.")
    dns_text = answers.get("dns_servers")
    if dns_text:
        for token in re.split(r"[,\s]+", dns_text):
            if not token:
                continue
            try:
                ip_address(token)
            except Exception:
                errors.append(f"DNS server is not a valid IP address: {token}")
    nat_value = parse_yes_no(answers.get("nat_enabled"))
    if answers.get("nat_enabled") and nat_value is None:
        errors.append("NAT decision must be yes or no.")
    if nat_value and not answers.get("wan_interface"):
        errors.append("WAN/interface is required when NAT is enabled.")
    summary = latest_mikrotik_snapshot_summary(router_id) if router_id else {}
    if vlan_id and vlan_id in set(summary.get("existing_vlan_ids") or []):
        errors.append(f"Customer VLAN {vlan_id} already exists on this router.")
    if network:
        for existing in summary.get("existing_subnets") or []:
            try:
                existing_network = ip_network(str(existing.get("network")), strict=False)
                if network.overlaps(existing_network):
                    errors.append(f"Client IP range {network} overlaps existing router network {existing_network} on {existing.get('interface') or 'unknown interface'}.")
            except Exception:
                continue
    pool_range = mikrotik_ip_pool_range(str(pool_start) if pool_start else None, str(pool_end) if pool_end else None)
    if pool_range:
        for existing_pool in summary.get("existing_pools") or []:
            for existing_range in parse_routeros_pool_ranges(existing_pool.get("ranges")):
                if mikrotik_ranges_overlap(pool_range, existing_range):
                    errors.append(f"DHCP pool overlaps existing pool {existing_pool.get('name')}: {existing_pool.get('ranges')}.")
    return {
        "answers": answers,
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
        "answered_required": sum(1 for key in required_keys if answers.get(key)),
        "total_required": len(required_keys),
        "complete": not errors and all(answers.get(key) for key in required_keys),
        "parsed": {
            "customer_vlan_id": vlan_id,
            "client_network_cidr": str(network) if network else None,
            "gateway_ip": str(gateway_ip_value) if gateway_ip_value else None,
            "pool_start": str(pool_start) if pool_start else None,
            "pool_end": str(pool_end) if pool_end else None,
            "nat_enabled": nat_value,
        },
    }


def mikrotik_policy_hard_blockers(policy: Optional[dict]) -> list[str]:
    hard_tokens = [
        "overlap",
        "already exists",
        "core/routing infrastructure",
        "core/read-only",
        "not allowed",
        "read-only/transport",
        "vlan trunk/switch",
        "unknown/needs review",
    ]
    hard = []
    for reason in (policy or {}).get("blocking_reasons") or []:
        lower = str(reason).lower()
        if any(token in lower for token in hard_tokens):
            hard.append(reason)
    return hard


def build_mikrotik_mt4_readiness(router_id: str) -> dict:
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    pilot = active_mikrotik_pilot_selection()
    scan_row = latest_mikrotik_scan_row(router_id)
    policy_row = latest_mikrotik_policy_row(router_id, scan_row["id"] if scan_row else None)
    if scan_row and not policy_row:
        policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
    scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=False) if scan_row else None
    policy = public_mikrotik_policy_result(policy_row)
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    answer_validation = validate_mikrotik_question_answers(questions, router_id)
    vlan_path_plan = public_mikrotik_vlan_path_plan(get_mikrotik_vlan_path_plan_row(router_id), router_id)
    vlan_path_validation = validate_mikrotik_vlan_path_plan(vlan_path_plan, answer_validation.get("answers") or {})
    pilot_selected = bool(pilot and str(pilot["router_id"]) == str(router_id))
    mode_confirmed = bool((policy or {}).get("confirmed_deployment_mode"))
    hard_blockers = mikrotik_policy_hard_blockers(policy)
    checks = [
        {"key": "pilot_router_selected", "label": "Pilot router selected", "passed": pilot_selected, "message": "Select exactly one pilot router." if not pilot_selected else "This router is the active pilot."},
        {"key": "latest_successful_preflight", "label": "Latest successful preflight scan exists", "passed": bool(scan and scan.get("scan_status") == "SUCCESS"), "message": "Run a successful read-only preflight scan."},
        {"key": "deployment_mode_confirmed", "label": "Deployment mode confirmed", "passed": mode_confirmed, "message": "Confirm deployment mode in Preflight Scanner."},
        {"key": "vlan_answered", "label": "VLAN answered", "passed": bool(answer_validation["answers"].get("customer_vlan_id")) and not any("VLAN" in err for err in answer_validation["errors"]), "message": "Enter a numeric customer VLAN ID."},
        {"key": "client_subnet_answered", "label": "Client subnet answered", "passed": bool(answer_validation["answers"].get("client_network_cidr")) and not any("CIDR" in err or "IP range" in err for err in answer_validation["errors"]), "message": "Enter a valid client subnet CIDR."},
        {"key": "gateway_pool_answered", "label": "Gateway and pool answered", "passed": bool(answer_validation["answers"].get("gateway_ip") and answer_validation["answers"].get("dhcp_pool")) and not any("Gateway" in err or "DHCP pool" in err for err in answer_validation["errors"]), "message": "Enter gateway IP and DHCP pool range."},
        {"key": "portal_url_answered", "label": "Portal URL answered", "passed": bool(answer_validation["answers"].get("portal_url")), "message": "Enter the customer portal URL."},
        {"key": "nat_decision_answered", "label": "NAT decision answered", "passed": bool(answer_validation["answers"].get("nat_enabled")) and not any("NAT" in err or "WAN" in err for err in answer_validation["errors"]), "message": "Answer whether NAT is needed, and WAN interface if NAT is yes."},
        {"key": "vlan_path_confirmed", "label": "VLAN path confirmed", "passed": vlan_path_validation["complete"], "message": "; ".join(vlan_path_validation["errors"] + vlan_path_validation["warnings"]) if not vlan_path_validation["complete"] else "VLAN path is confirmed."},
        {"key": "safety_policy_checked", "label": "Safety policy checked", "passed": not hard_blockers, "message": "; ".join(hard_blockers) if hard_blockers else "No hard policy blockers detected."},
    ]
    missing = [item["message"] for item in checks if not item["passed"]]
    missing.extend(answer_validation["errors"])
    missing.extend(vlan_path_validation["errors"])
    ready = all(item["passed"] for item in checks) and not answer_validation["errors"]
    latest_plan = fetch_one("SELECT * FROM mikrotik_draft_deployment_plans WHERE router_id = %s ORDER BY created_at DESC LIMIT 1", (router_id,))
    latest_plan_public = public_mikrotik_draft_plan(latest_plan) if latest_plan else None
    plan_validation = (latest_plan_public or {}).get("validation_result") or {}
    openai = openai_api_status()
    ready_for_draft_plan = bool(ready and openai.get("configured"))
    ready_for_mt4 = bool(ready and latest_plan_public and latest_plan_public.get("validation_status") in ("PASS", "WARNING") and plan_validation.get("eligible_for_mt4"))
    return {
        "router": public_mikrotik_router(router),
        "pilot_selection": public_mikrotik_pilot_selection(pilot),
        "scan": scan,
        "policy": policy,
        "questions": questions,
        "answer_validation": answer_validation,
        "vlan_path_plan": vlan_path_plan,
        "vlan_path_validation": vlan_path_validation,
        "checks": checks,
        "ready": bool(ready),
        "openai": openai,
        "ready_for_draft_plan": ready_for_draft_plan,
        "ready_for_mt4": ready_for_mt4,
        "missing_requirements": sorted(set(item for item in missing if item)),
        "latest_draft_plan": latest_plan_public,
        "message": "Ready for MT-4 Command Preview. No RouterOS commands are generated or applied yet." if ready_for_mt4 else ("Ready to generate a draft plan. No RouterOS commands are generated or applied yet." if ready_for_draft_plan else "Not ready for MT-4. Complete the missing requirements first."),
    }


def public_mikrotik_ai_conversation(row, include_messages: bool = True) -> dict:
    data = {
        "id": row["id"],
        "admin_id": row.get("admin_id"),
        "router_id": row.get("router_id"),
        "scan_batch_id": row.get("scan_batch_id"),
        "title": row.get("title"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if include_messages:
        rows = fetch_all("SELECT * FROM mikrotik_ai_messages WHERE conversation_id = %s ORDER BY created_at ASC", (row["id"],))
        data["messages"] = [
            {
                "id": item["id"],
                "conversation_id": item["conversation_id"],
                "role": item["role"],
                "message_text": item["message_text"],
                "created_at": item["created_at"],
            }
            for item in rows
        ]
    return data


def strip_json_markdown(text: str) -> str:
    clean = (text or "").strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"\s*```$", "", clean)
    start = clean.find("{")
    end = clean.rfind("}")
    if start >= 0 and end > start:
        clean = clean[start:end + 1]
    return clean


def parse_ai_draft_plan(text: str) -> dict:
    try:
        plan = json.loads(strip_json_markdown(text))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"AI returned invalid draft plan JSON: {exc}") from exc
    if not isinstance(plan, dict):
        raise HTTPException(status_code=400, detail="AI draft plan must be a JSON object.")
    return sanitize_routeros_object(plan)


def mikrotik_plan_has_routeros_commands(value) -> bool:
    command_keys = {"commands", "routeros_commands", "terminal", "script", "cli", "command_preview"}
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key or "").lower()
            if key_text in command_keys:
                return True
            if mikrotik_plan_has_routeros_commands(item):
                return True
    elif isinstance(value, list):
        return any(mikrotik_plan_has_routeros_commands(item) for item in value)
    elif isinstance(value, str):
        return bool(re.search(r"(^|\n)\s*/(?:ip|interface|routing|system|tool|radius|queue|ppp|certificate)\b", value, flags=re.IGNORECASE))
    return False


def mikrotik_ip_pool_range(start_ip: Optional[str], end_ip: Optional[str]) -> Optional[tuple[int, int]]:
    if not start_ip or not end_ip:
        return None
    try:
        start = int(ip_address(str(start_ip).strip()))
        end = int(ip_address(str(end_ip).strip()))
        return (min(start, end), max(start, end))
    except Exception:
        return None


def validate_mikrotik_draft_plan(router: dict, plan: dict, scan_row=None, policy_row=None) -> dict:
    scan_row = scan_row or latest_mikrotik_scan_row(str(router["id"]))
    policy_row = policy_row or latest_mikrotik_policy_row(str(router["id"]), scan_row["id"] if scan_row else None)
    scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=True) if scan_row else None
    policy = public_mikrotik_policy_result(policy_row)
    blockers = []
    warnings = []
    required_next_questions = []
    if mikrotik_plan_has_routeros_commands(plan):
        blockers.append("Draft plan contains executable RouterOS command content. MT-3 allows planning only, not commands.")
    if not scan or scan.get("scan_status") != "SUCCESS":
        blockers.append("A successful preflight scan is required before draft plan validation can pass.")
    mode = normalize_mikrotik_deployment_mode(plan.get("proposed_deployment_mode"))
    if mode == "UNKNOWN_NEEDS_REVIEW":
        blockers.append("Draft plan must choose a deployment mode before MT-4 command preview.")
    role_guess = normalize_mikrotik_router_role((policy or {}).get("role_guess") or (scan or {}).get("router_role_guess"))
    confirmed_mode = normalize_mikrotik_deployment_mode((policy or {}).get("confirmed_deployment_mode"))
    if confirmed_mode in ("READ_ONLY_CORE", "ISP_BACKUP_TRANSPORT"):
        blockers.append("Router is confirmed as read-only/transport. HotSpot command preview is blocked.")
    if mode == "HOTSPOT_GATEWAY" and role_guess == "CORE_ROUTER_READ_ONLY":
        blockers.append("Core/read-only routers cannot be used as HotSpot gateways.")
    if mode == "HOTSPOT_GATEWAY" and role_guess == "SWITCH_TRUNK_HELPER":
        blockers.append("CRS/switch trunk helpers cannot host HotSpot Gateway mode.")
    if not (policy or {}).get("confirmed_deployment_mode"):
        blockers.append("Deployment mode has not been confirmed in Preflight Scanner.")

    analysis = (((scan or {}).get("sanitized_snapshot") or {}).get("analysis") or {})
    summary = analysis.get("summary") or {}
    proposed_vlan = plan.get("proposed_customer_vlan_id")
    try:
        proposed_vlan_int = int(proposed_vlan) if proposed_vlan not in (None, "") else None
    except Exception:
        proposed_vlan_int = None
        blockers.append("Proposed customer VLAN ID is invalid.")
    if mode == "HOTSPOT_GATEWAY":
        required_fields = {
            "proposed_customer_vlan_id": "Customer VLAN ID",
            "proposed_vlan_parent_interface": "VLAN parent interface",
            "proposed_vlan_interface_name": "VLAN interface name",
            "proposed_client_network_cidr": "Client network CIDR",
            "proposed_gateway_ip": "Gateway IP",
            "proposed_pool_start": "DHCP pool start",
            "proposed_pool_end": "DHCP pool end",
            "proposed_dhcp_server_name": "DHCP server name",
            "proposed_dns_servers": "DNS servers",
            "proposed_hotspot_dns_name": "HotSpot DNS name",
            "proposed_portal_url": "Portal URL",
        }
        for key, label in required_fields.items():
            value = plan.get(key)
            if value in (None, "", []):
                blockers.append(f"{label} is required for HotSpot Gateway preview.")
                required_next_questions.append(label)
    if proposed_vlan_int and proposed_vlan_int in set(summary.get("existing_vlan_ids") or []):
        blockers.append(f"Customer VLAN {proposed_vlan_int} already exists on this router.")
    cidr = plan.get("proposed_client_network_cidr")
    proposed_network = None
    if cidr:
        try:
            proposed_network = ip_network(str(cidr), strict=False)
        except Exception:
            blockers.append("Proposed client network CIDR is invalid.")
    if proposed_network:
        for existing in summary.get("existing_subnets") or []:
            try:
                existing_network = ip_network(str(existing.get("network")), strict=False)
                if proposed_network.overlaps(existing_network):
                    blockers.append(f"Proposed client subnet {proposed_network} overlaps existing {existing_network} on {existing.get('interface') or 'unknown interface'}.")
            except Exception:
                continue
    pool_range = mikrotik_ip_pool_range(plan.get("proposed_pool_start"), plan.get("proposed_pool_end"))
    if plan.get("proposed_pool_start") or plan.get("proposed_pool_end"):
        if not pool_range:
            blockers.append("Proposed DHCP pool start/end is invalid.")
    if pool_range:
        for existing_pool in summary.get("existing_pools") or []:
            for existing_range in parse_routeros_pool_ranges(existing_pool.get("ranges")):
                if mikrotik_ranges_overlap(pool_range, existing_range):
                    blockers.append(f"Proposed DHCP pool overlaps existing pool {existing_pool.get('name')}: {existing_pool.get('ranges')}.")
    if plan.get("proposed_nat_enabled") and not str(plan.get("proposed_wan_interface") or "").strip():
        blockers.append("WAN/interface is required when NAT is enabled.")
    protected_text = json.dumps(json_safe(plan), default=str).lower()
    for protected in ["pppoe", "ospf", "wireguard"]:
        if f"modify {protected}" in protected_text or f"delete {protected}" in protected_text or f"change {protected}" in protected_text:
            blockers.append(f"Draft plan appears to modify protected {protected.upper()} configuration.")
    if (policy or {}).get("warnings"):
        warnings.extend((policy or {}).get("warnings") or [])
    if role_guess == "PPPoE_ACCESS_CONCENTRATOR":
        warnings.append("PPPoE access concentrator: pilot is possible only on a new isolated VLAN/subnet and must not touch PPPoE objects.")
    status = "BLOCKED" if blockers else ("WARNING" if warnings else "PASS")
    ai_questions = plan.get("questions_still_needed") or []
    if isinstance(ai_questions, str):
        ai_questions = [ai_questions]
    elif not isinstance(ai_questions, list):
        ai_questions = []
    return {
        "validation_status": status,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "questions_still_needed": sorted(set(required_next_questions + [str(item) for item in ai_questions if item])),
        "eligible_for_mt4": status in ("PASS", "WARNING"),
        "policy_result": policy,
        "scan_id": scan.get("id") if scan else None,
    }


def public_mikrotik_draft_plan(row) -> dict:
    return {
        "id": row["id"],
        "router_id": row["router_id"],
        "scan_id": row.get("scan_id"),
        "created_by_admin_id": row.get("created_by_admin_id"),
        "ai_generated": row["ai_generated"],
        "plan_json": row["plan_json"],
        "validation_status": row["validation_status"],
        "validation_result": row.get("validation_result_json"),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def save_mikrotik_ai_smoke_test(admin_id: Optional[str], status: str, prompt_summary: str, response_summary: Optional[str] = None, error_message: Optional[str] = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_ai_smoke_tests(admin_id, status, prompt_summary, response_summary, error_message)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    admin_id,
                    status,
                    sanitize_routeros_text(prompt_summary or "", max_length=800),
                    sanitize_routeros_text(response_summary or "", max_length=1600) if response_summary else None,
                    sanitize_routeros_text(error_message or "", max_length=1600) if error_message else None,
                ),
            )
            return cur.fetchone()


def latest_mikrotik_ai_smoke_test():
    return fetch_one("SELECT * FROM mikrotik_ai_smoke_tests ORDER BY created_at DESC LIMIT 1")


def mikrotik_question_progress_by_router() -> dict:
    active_pilot = active_mikrotik_pilot_selection()
    active_pilot_router_id = str(active_pilot["router_id"]) if active_pilot else None
    required_keys = {
        key
        for key, _ in MIKROTIK_DEPLOYMENT_QUESTION_DEFS
        if MIKROTIK_DEPLOYMENT_QUESTION_META.get(key, {}).get("required_for_preview", True)
    }
    total_required = len(required_keys)
    progress = {}
    for router in fetch_all("SELECT id FROM mikrotik_routers"):
        if active_pilot_router_id and str(router["id"]) != active_pilot_router_id:
            progress[str(router["id"])] = {
                "answered_required": 0,
                "total_required": total_required,
                "label": "Pilot only",
                "complete": False,
                "pilot_only": True,
            }
            continue
        progress[str(router["id"])] = {
            "answered_required": 0,
            "total_required": total_required,
            "label": f"0/{total_required}",
            "complete": False,
            "pilot_only": False,
        }
    rows = fetch_all(
        """
        SELECT router_id, question_key, answer_value, approved_value, answer_status
        FROM mikrotik_deployment_questions
        WHERE question_key = ANY(%s)
        """,
        (list(required_keys),),
    )
    for row in rows:
        router_id = str(row["router_id"])
        if active_pilot_router_id and router_id != active_pilot_router_id:
            continue
        if router_id not in progress:
            progress[router_id] = {
                "answered_required": 0,
                "total_required": total_required,
                "label": f"0/{total_required}",
                "complete": False,
                "pilot_only": False,
            }
        status = row.get("answer_status")
        value = row.get("approved_value") if status in ("APPROVED", "LOCKED") and row.get("approved_value") not in (None, "") else row.get("answer_value")
        if str(value or "").strip():
            progress[router_id]["answered_required"] += 1
    for item in progress.values():
        item["label"] = f"{item['answered_required']}/{item['total_required']}"
        item["complete"] = bool(item["total_required"] and item["answered_required"] >= item["total_required"])
    return progress


def clear_non_pilot_mikrotik_planning_answers(admin_id: Optional[str] = None) -> int:
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot:
        return 0
    active_router_id = str(active_pilot["router_id"])
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_questions
                SET answer_value = NULL,
                    suggested_value = NULL,
                    approved_value = NULL,
                    answer_status = 'EMPTY',
                    suggestion_reason = NULL,
                    suggestion_confidence = NULL,
                    suggestion_requires_review = true,
                    derived_from = NULL,
                    is_derived = false,
                    locked = false,
                    validation_status = NULL,
                    validation_errors_json = NULL,
                    answered_by_admin_id = NULL,
                    answered_at = NULL,
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE router_id::text <> %s
                  AND (
                    answer_value IS NOT NULL
                    OR suggested_value IS NOT NULL
                    OR approved_value IS NOT NULL
                    OR COALESCE(answer_status, 'EMPTY') <> 'EMPTY'
                    OR locked = true
                  )
                """,
                (admin_id, active_router_id),
            )
            return cur.rowcount or 0


def mikrotik_pilot_selection_eligibility(router_id: str) -> dict:
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    scan_row = latest_mikrotik_scan_row(router_id)
    policy_row = latest_mikrotik_policy_row(router_id, scan_row["id"] if scan_row else None)
    if scan_row and not policy_row:
        policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
    scan = public_mikrotik_preflight_scan(scan_row, include_snapshot=False) if scan_row else None
    policy = public_mikrotik_policy_result(policy_row)
    blockers = []
    warnings = []
    role = normalize_mikrotik_router_role((policy or {}).get("confirmed_router_role") or (policy or {}).get("role_guess") or (scan or {}).get("router_role_guess"))
    mode = normalize_mikrotik_deployment_mode((policy or {}).get("confirmed_deployment_mode") or (policy or {}).get("recommended_deployment_mode") or (scan or {}).get("recommended_deployment_mode"))
    expert_override = bool((policy or {}).get("expert_override_enabled"))
    if not scan or scan.get("scan_status") != "SUCCESS":
        blockers.append("A successful read-only preflight scan is required before pilot selection.")
    if role == "CORE_ROUTER_READ_ONLY" or mode in {"READ_ONLY_CORE", "ISP_BACKUP_TRANSPORT"}:
        if not expert_override:
            blockers.append("Core/read-only or transport routers cannot be selected as a pilot without an expert override record.")
    if role == "SWITCH_TRUNK_HELPER" or mode == "VLAN_TRUNK_HELPER":
        blockers.append("CRS/switch trunk helper routers cannot be selected as a HotSpot Gateway pilot.")
    if role == "PPPoE_ACCESS_CONCENTRATOR":
        warnings.append("PPPoE access concentrator: possible with caution only on a new dedicated VLAN/subnet.")
        if not (policy or {}).get("confirmed_deployment_mode"):
            blockers.append("PPPoE access concentrators require deployment mode confirmation before pilot selection.")
    hard_blockers = mikrotik_policy_hard_blockers(policy)
    for reason in hard_blockers:
        if reason not in blockers:
            blockers.append(reason)
    return {
        "router": public_mikrotik_router(router),
        "scan": scan,
        "policy": policy,
        "allowed": not blockers,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
    }


@app.get("/api/captive-portal/mikrotik/ai/smoke-test-status")
def get_mikrotik_ai_smoke_test_status(admin=Depends(current_admin)):
    raise_ai_feature_removed()
    return {
        "openai": openai_api_status(),
        "last_smoke_test": public_mikrotik_smoke_test(latest_mikrotik_ai_smoke_test()),
        "safety_note": "AI smoke test uses sanitized summary only and must not generate RouterOS commands.",
    }


@app.post("/api/captive-portal/mikrotik/ai/smoke-test")
def run_mikrotik_ai_smoke_test(admin=Depends(current_admin)):
    raise_ai_feature_removed()
    openai = openai_api_status()
    prompt = "Summarize the current MikroTik preflight planning status in one short paragraph. Do not generate RouterOS commands."
    if not openai.get("configured"):
        row = save_mikrotik_ai_smoke_test(admin["id"], "DISABLED", prompt, error_message="OpenAI API key is not configured.")
        return {
            "openai": openai,
            "last_smoke_test": public_mikrotik_smoke_test(row),
            "message": "AI is not configured. Preflight and readiness checks still work without AI.",
        }
    context = mikrotik_ai_safe_context()
    cards = ((context.get("preflight_summary") or {}).get("cards") or {})
    summary_text = (
        f"Latest sanitized preflight summary: total routers {cards.get('total_routers', 0)}, "
        f"scanned {cards.get('scanned', 0)}, failed scans {cards.get('failed_scans', 0)}, "
        f"potential HotSpot candidates {cards.get('hotspot_gateway_candidates', 0)}, "
        f"read-only/core {cards.get('read_only_core', 0)}, VLAN trunk helpers {cards.get('vlan_trunk_helpers', 0)}, "
        f"routers requiring confirmation {cards.get('requires_confirmation', 0)}."
    )
    payload = {
        "prompt": prompt,
        "summary_text": summary_text,
        "sanitized_preflight_summary": context.get("preflight_summary"),
        "router_readiness": context.get("router_readiness"),
        "instruction": "Return one short paragraph only. Do not include RouterOS commands, CLI snippets, or apply steps.",
    }
    try:
        response_text = call_openai_responses(mikrotik_ai_system_prompt("chat"), payload, max_output_tokens=600, user_agent="3JCentralPisowifi/0.1 mikrotik-ai-smoke-test")
        if mikrotik_plan_has_routeros_commands(response_text):
            error_message = "RouterOS commands are not allowed in MT-3.1. Command preview will be generated in MT-4 only."
            row = save_mikrotik_ai_smoke_test(admin["id"], "FAILED", prompt, response_summary=response_text, error_message=error_message)
            return {"openai": openai, "last_smoke_test": public_mikrotik_smoke_test(row), "message": error_message}
        row = save_mikrotik_ai_smoke_test(admin["id"], "SUCCESS", prompt, response_summary=response_text)
        audit(admin["id"], "run_mikrotik_ai_smoke_test", "mikrotik_ai_smoke_tests", str(row["id"]), {"status": "SUCCESS"})
        return {"openai": openai, "last_smoke_test": public_mikrotik_smoke_test(row), "message": "AI smoke test succeeded."}
    except HTTPException as exc:
        row = save_mikrotik_ai_smoke_test(admin["id"], "FAILED", prompt, error_message=str(exc.detail))
        return {"openai": openai, "last_smoke_test": public_mikrotik_smoke_test(row), "message": str(exc.detail)}


@app.get("/api/captive-portal/mikrotik/pilot-selection")
def get_mikrotik_pilot_selection(admin=Depends(current_admin)):
    return {
        "pilot_selection": public_mikrotik_pilot_selection(active_mikrotik_pilot_selection()),
        "rules": [
            "Only one active pilot router can be selected.",
            "Pilot selection does not apply MikroTik configuration.",
            "Core/read-only routers require expert override before pilot selection.",
            "CRS/switch trunk helpers cannot be selected as HotSpot Gateway pilots.",
        ],
    }


@app.put("/api/captive-portal/mikrotik/pilot-selection")
def set_mikrotik_pilot_selection(payload: MikrotikPilotSelectionPayload, admin=Depends(current_admin)):
    confidence = (payload.physical_recovery_confidence or "MODERATE").strip().upper()
    if confidence not in {"EASY_TO_RECOVER", "MODERATE", "HARD_REMOTE_SITE"}:
        raise HTTPException(status_code=400, detail="Physical recovery confidence must be EASY_TO_RECOVER, MODERATE, or HARD_REMOTE_SITE.")
    eligibility = mikrotik_pilot_selection_eligibility(payload.router_id)
    if not eligibility["allowed"]:
        raise HTTPException(status_code=400, detail={"message": "Pilot router selection is blocked by safety policy.", "blockers": eligibility["blockers"], "warnings": eligibility["warnings"]})
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_pilot_selection
                SET status = 'CLEARED',
                    updated_at = now()
                WHERE status = 'ACTIVE'
                """
            )
            cur.execute(
                """
                INSERT INTO mikrotik_pilot_selection(router_id, selected_by_admin_id, reason, physical_recovery_confidence, operator_note, status)
                VALUES (%s, %s, %s, %s, %s, 'ACTIVE')
                RETURNING *
                """,
                (
                    payload.router_id,
                    admin["id"],
                    sanitize_routeros_text(payload.reason or "", max_length=1200) or None,
                    confidence,
                    sanitize_routeros_text(payload.operator_note or "", max_length=2000) or None,
                ),
            )
            row = cur.fetchone()
    audit(admin["id"], "set_mikrotik_pilot_selection", "mikrotik_pilot_selection", str(row["id"]), {"router_id": payload.router_id, "warnings": eligibility["warnings"]})
    cleared_count = clear_non_pilot_mikrotik_planning_answers(admin["id"])
    return {"pilot_selection": public_mikrotik_pilot_selection(active_mikrotik_pilot_selection()), "eligibility": eligibility, "cleared_non_pilot_questions": cleared_count}


@app.delete("/api/captive-portal/mikrotik/pilot-selection")
def clear_mikrotik_pilot_selection(admin=Depends(current_admin)):
    current = active_mikrotik_pilot_selection()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_pilot_selection
                SET status = 'CLEARED',
                    updated_at = now()
                WHERE status = 'ACTIVE'
                """
            )
    if current:
        audit(admin["id"], "clear_mikrotik_pilot_selection", "mikrotik_pilot_selection", str(current["id"]), {"router_id": current["router_id"]})
    return {"pilot_selection": None, "message": "Pilot selection cleared. No MikroTik configuration was changed."}


@app.get("/api/captive-portal/mikrotik/ai/summary")
def mikrotik_ai_network_summary(admin=Depends(current_admin)):
    raise_ai_feature_removed()
    summary = build_mikrotik_preflight_summary()
    return {
        "openai": openai_api_status(),
        "summary": summary,
        "pilot_candidates": rank_mikrotik_pilot_candidates(summary),
        "question_progress": mikrotik_question_progress_by_router(),
        "smoke_test": public_mikrotik_smoke_test(latest_mikrotik_ai_smoke_test()),
        "pilot_selection": public_mikrotik_pilot_selection(active_mikrotik_pilot_selection()),
        "note": "AI uses sanitized scan data only. It cannot see passwords, secrets, or private keys.",
    }


@app.post("/api/captive-portal/mikrotik/ai/conversations")
def create_mikrotik_ai_conversation(payload: MikrotikAiConversationCreate, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    router_id = payload.router_id
    if router_id and not fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,)):
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    latest_batch = fetch_one("SELECT id FROM mikrotik_preflight_scan_batches ORDER BY created_at DESC LIMIT 1")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_ai_conversations(admin_id, router_id, scan_batch_id, title)
                VALUES (%s, %s, %s, %s)
                RETURNING *
                """,
                (admin["id"], router_id, latest_batch["id"] if latest_batch else None, payload.title or "AI Network Assistant"),
            )
            row = cur.fetchone()
    audit(admin["id"], "create_mikrotik_ai_conversation", "mikrotik_ai_conversations", str(row["id"]), {"router_id": router_id})
    return public_mikrotik_ai_conversation(row)


@app.get("/api/captive-portal/mikrotik/ai/conversations/{conversation_id}")
def get_mikrotik_ai_conversation(conversation_id: str, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    row = fetch_one("SELECT * FROM mikrotik_ai_conversations WHERE id = %s", (conversation_id,))
    if not row:
        raise HTTPException(status_code=404, detail="AI conversation not found")
    return public_mikrotik_ai_conversation(row)


@app.post("/api/captive-portal/mikrotik/ai/conversations/{conversation_id}/messages")
def send_mikrotik_ai_message(conversation_id: str, payload: MikrotikAiMessageCreate, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    conversation = fetch_one("SELECT * FROM mikrotik_ai_conversations WHERE id = %s", (conversation_id,))
    if not conversation:
        raise HTTPException(status_code=404, detail="AI conversation not found")
    router_id = payload.router_id or conversation.get("router_id")
    context = mikrotik_ai_safe_context(router_id)
    user_text = sanitize_routeros_text(payload.message_text, max_length=4000)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_ai_messages(conversation_id, role, message_text, sanitized_context_json)
                VALUES (%s, 'USER', %s, %s)
                """,
                (conversation_id, user_text, Json(json_safe(context))),
            )
    history_rows = fetch_all(
        """
        SELECT role, message_text, created_at
        FROM mikrotik_ai_messages
        WHERE conversation_id = %s
        ORDER BY created_at DESC
        LIMIT 8
        """,
        (conversation_id,),
    )
    history = [
        {"role": row["role"], "message_text": row["message_text"], "created_at": row["created_at"]}
        for row in reversed(history_rows)
    ]
    ai_payload = {
        "user_question": user_text,
        "recent_conversation": history,
        "sanitized_context": context,
        "instruction": "Answer as guidance only. Do not output RouterOS commands.",
    }
    answer = call_openai_responses(mikrotik_ai_system_prompt("chat"), ai_payload, max_output_tokens=1000)
    if mikrotik_plan_has_routeros_commands(answer):
        answer = "I cannot provide RouterOS commands in MT-3. I can explain the scan, risks, and missing planning questions, but command previews are reserved for a later safety-gated phase."
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_ai_messages(conversation_id, role, message_text, sanitized_context_json)
                VALUES (%s, 'ASSISTANT', %s, %s)
                """,
                (conversation_id, answer, Json(json_safe({"context_used": "sanitized_preflight_summary", "router_id": router_id}))),
            )
            cur.execute("UPDATE mikrotik_ai_conversations SET updated_at = now() WHERE id = %s RETURNING *", (conversation_id,))
            row = cur.fetchone()
    audit(admin["id"], "send_mikrotik_ai_message", "mikrotik_ai_conversations", conversation_id, {"router_id": router_id})
    return public_mikrotik_ai_conversation(row)


@app.get("/api/captive-portal/mikrotik/{router_id}/deployment-questions")
def get_mikrotik_deployment_questions(router_id: str, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        return []
    return [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]


@app.put("/api/captive-portal/mikrotik/{router_id}/deployment-questions/{question_key}")
def update_mikrotik_deployment_question(router_id: str, question_key: str, payload: MikrotikDeploymentQuestionUpdate, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    answer = sanitize_routeros_text(payload.answer_value or "", max_length=2000)
    row_before = fetch_one("SELECT locked FROM mikrotik_deployment_questions WHERE router_id = %s AND question_key = %s", (router_id, question_key))
    if row_before and row_before.get("locked"):
        raise HTTPException(status_code=400, detail="This planning answer is locked. Unlock it before editing.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_questions
                SET answer_value = %s,
                    approved_value = NULL,
                    answer_status = CASE WHEN %s = '' THEN 'EMPTY' ELSE 'USER_EDITED' END,
                    answered_by_admin_id = %s,
                    answered_at = CASE WHEN %s = '' THEN NULL ELSE now() END,
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE router_id = %s AND question_key = %s
                RETURNING *
                """,
                (answer or None, answer, admin["id"] if answer else None, answer, admin["id"], router_id, question_key),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Deployment question not found")
    audit(admin["id"], "update_mikrotik_deployment_question", "mikrotik_deployment_questions", str(row["id"]), {"router_id": router_id, "question_key": question_key, "answered": bool(answer)})
    return public_mikrotik_deployment_question(row)


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/save-all")
def save_all_mikrotik_deployment_questions(router_id: str, payload: MikrotikDeploymentQuestionsSaveAll, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    allowed_keys = {key for key, _ in MIKROTIK_DEPLOYMENT_QUESTION_DEFS}
    answers = payload.answers or {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            for key, value in answers.items():
                if key not in allowed_keys:
                    continue
                answer = sanitize_routeros_text(value or "", max_length=2000)
                cur.execute(
                    """
                    UPDATE mikrotik_deployment_questions
                    SET answer_value = %s,
                        approved_value = CASE
                            WHEN locked THEN approved_value
                            WHEN %s = '' THEN NULL
                            ELSE %s
                        END,
                        answer_status = CASE
                            WHEN locked THEN 'LOCKED'
                            WHEN %s = '' THEN 'EMPTY'
                            ELSE 'APPROVED'
                        END,
                        answered_by_admin_id = %s,
                        answered_at = CASE WHEN %s = '' THEN NULL ELSE now() END,
                        updated_by_admin_id = %s,
                        updated_at = now()
                    WHERE router_id = %s AND question_key = %s AND locked = false
                    """,
                    (answer or None, answer, answer, answer, admin["id"] if answer else None, answer, admin["id"], router_id, key),
                )
    latest_rows = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    latest_answers = {item["question_key"]: item.get("answer_value") or "" for item in latest_rows}
    derivations = mikrotik_auto_derive_from_answers(router_id, latest_answers, admin["id"])
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    validation = validate_mikrotik_question_answers(questions, router_id)
    update_question_validation_metadata(router_id, validation)
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    audit(admin["id"], "save_all_mikrotik_deployment_questions", "mikrotik_deployment_questions", router_id, {"answered_required": validation["answered_required"], "total_required": validation["total_required"], "valid": validation["complete"]})
    return {"questions": questions, "validation": validation, "derivations": derivations}


@app.get("/api/captive-portal/mikrotik/{router_id}/mt4-readiness")
def get_mikrotik_mt4_readiness(router_id: str, admin=Depends(current_admin)):
    return build_mikrotik_mt4_readiness(router_id)


@app.get("/api/captive-portal/mikrotik/{router_id}/planning-network-preview")
def get_mikrotik_planning_network_preview(router_id: str, admin=Depends(current_admin)):
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    answers = mikrotik_question_answer_map(questions)
    preview = derive_mikrotik_network_fields(answers.get("client_network_cidr"))
    validation = validate_mikrotik_question_answers(questions, router_id)
    return {
        "preview": preview,
        "validation": validation,
        "interface_candidates": mikrotik_interface_candidates(router_id),
    }


@app.get("/api/captive-portal/mikrotik/{router_id}/interface-candidates")
def get_mikrotik_interface_candidates_endpoint(router_id: str, admin=Depends(current_admin)):
    router = fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    return mikrotik_interface_candidates(router_id)


@app.get("/api/captive-portal/mikrotik/{router_id}/vlan-path-plan")
def get_mikrotik_vlan_path_plan(router_id: str, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        return {"plan": public_mikrotik_vlan_path_plan(None, router_id), "validation": {"errors": ["VLAN path planning is currently enabled only for the selected pilot router."], "warnings": [], "complete": False}}
    router = fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    answers = mikrotik_question_answer_map(questions)
    plan = public_mikrotik_vlan_path_plan(get_mikrotik_vlan_path_plan_row(router_id), router_id)
    return {"plan": plan, "validation": validate_mikrotik_vlan_path_plan(plan, answers)}


@app.put("/api/captive-portal/mikrotik/{router_id}/vlan-path-plan")
def save_mikrotik_vlan_path_plan(router_id: str, payload: MikrotikVlanPathPlanPayload, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="VLAN path planning is currently enabled only for the selected pilot router.")
    router = fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    next_hop_type = str(payload.next_hop_type or "UNKNOWN").strip().upper()
    if next_hop_type not in {"CRS", "OLT", "SWITCH", "DIRECT_AP", "UNKNOWN"}:
        raise HTTPException(status_code=400, detail="Invalid next hop type.")
    olt_vlan_behavior = str(payload.olt_vlan_behavior or "UNKNOWN").strip().upper()
    if olt_vlan_behavior not in {"TRANSPARENT", "TRANSLATED", "UNKNOWN"}:
        raise HTTPException(status_code=400, detail="Invalid OLT VLAN behavior.")
    ap_vlan_mode = str(payload.ap_vlan_mode or "UNKNOWN").strip().upper()
    if ap_vlan_mode not in {"TAGGED", "UNTAGGED", "UNKNOWN"}:
        raise HTTPException(status_code=400, detail="Invalid AP VLAN mode.")
    confirmation_status = str(payload.confirmation_status or "DRAFT").strip().upper()
    if confirmation_status not in {"DRAFT", "NEEDS_REVIEW", "CONFIRMED"}:
        raise HTTPException(status_code=400, detail="Invalid confirmation status.")
    crs_router_id = payload.crs_router_id or None
    if crs_router_id:
        crs = fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (crs_router_id,))
        if not crs:
            raise HTTPException(status_code=400, detail="Selected CRS router was not found.")
    gateway_router_id = payload.hotspot_gateway_router_id or router_id
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_vlan_path_plans(
                    router_id, hotspot_gateway_router_id, gateway_parent_interface, next_hop_type,
                    crs_involved, crs_router_id, crs_port_to_gateway, crs_ports_to_olt_ap,
                    olts_involved, olt_notes, olt_vlan_behavior, ap_vlan_mode, ssid_vlan_id,
                    confirmation_status, confirmed_by_admin_id, confirmed_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        CASE WHEN %s = 'CONFIRMED' THEN %s ELSE NULL END,
                        CASE WHEN %s = 'CONFIRMED' THEN now() ELSE NULL END)
                ON CONFLICT (router_id) DO UPDATE
                SET hotspot_gateway_router_id = EXCLUDED.hotspot_gateway_router_id,
                    gateway_parent_interface = EXCLUDED.gateway_parent_interface,
                    next_hop_type = EXCLUDED.next_hop_type,
                    crs_involved = EXCLUDED.crs_involved,
                    crs_router_id = EXCLUDED.crs_router_id,
                    crs_port_to_gateway = EXCLUDED.crs_port_to_gateway,
                    crs_ports_to_olt_ap = EXCLUDED.crs_ports_to_olt_ap,
                    olts_involved = EXCLUDED.olts_involved,
                    olt_notes = EXCLUDED.olt_notes,
                    olt_vlan_behavior = EXCLUDED.olt_vlan_behavior,
                    ap_vlan_mode = EXCLUDED.ap_vlan_mode,
                    ssid_vlan_id = EXCLUDED.ssid_vlan_id,
                    confirmation_status = EXCLUDED.confirmation_status,
                    confirmed_by_admin_id = CASE WHEN EXCLUDED.confirmation_status = 'CONFIRMED' THEN %s ELSE NULL END,
                    confirmed_at = CASE WHEN EXCLUDED.confirmation_status = 'CONFIRMED' THEN now() ELSE NULL END,
                    updated_at = now()
                RETURNING *
                """,
                (
                    router_id,
                    gateway_router_id,
                    sanitize_routeros_text(payload.gateway_parent_interface or "", max_length=200) or None,
                    next_hop_type,
                    bool(payload.crs_involved),
                    crs_router_id,
                    sanitize_routeros_text(payload.crs_port_to_gateway or "", max_length=400) or None,
                    sanitize_routeros_text(payload.crs_ports_to_olt_ap or "", max_length=800) or None,
                    bool(payload.olts_involved),
                    sanitize_routeros_text(payload.olt_notes or "", max_length=2000) or None,
                    olt_vlan_behavior,
                    ap_vlan_mode,
                    payload.ssid_vlan_id,
                    confirmation_status,
                    confirmation_status,
                    admin["id"],
                    confirmation_status,
                    admin["id"],
                ),
            )
            row = cur.fetchone()
    plan = public_mikrotik_vlan_path_plan(row, router_id)
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    answers = mikrotik_question_answer_map(questions)
    validation = validate_mikrotik_vlan_path_plan(plan, answers)
    audit(admin["id"], "save_mikrotik_vlan_path_plan", "mikrotik_vlan_path_plans", str(row["id"]), {"router_id": router_id, "confirmation_status": confirmation_status})
    return {"plan": plan, "validation": validation, "mt4_readiness": build_mikrotik_mt4_readiness(router_id)}


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/derive")
def derive_mikrotik_deployment_questions(router_id: str, payload: MikrotikDeploymentQuestionsSaveAll, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    answers = payload.answers or {}
    preview = derive_mikrotik_network_fields(answers.get("client_network_cidr"))
    derived = {}
    if preview.get("status") == "SUCCESS":
        derived.update(preview.get("derived") or {})
    vlan_name = mikrotik_vlan_interface_name(answers.get("customer_vlan_id"))
    if vlan_name:
        derived["vlan_interface_name"] = vlan_name
    if not answers.get("hotspot_dns_name"):
        derived["hotspot_dns_name"] = default_hotspot_dns_name("3j")
    if not answers.get("portal_url"):
        settings = public_captive_portal_settings()
        derived["portal_url"] = settings.get("portal_url_staging") or "http://192.168.50.70:8080/portal"
    return {"network_preview": preview, "derived_answers": derived, "interface_candidates": mikrotik_interface_candidates(router_id)}


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/validate")
def validate_mikrotik_deployment_questions_endpoint(router_id: str, payload: Optional[MikrotikDeploymentQuestionsSaveAll] = None, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    if payload and payload.answers:
        public_questions = []
        row_map = {row["question_key"]: public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)}
        for key, value in payload.answers.items():
            if key in row_map:
                row_map[key]["answer_value"] = sanitize_routeros_text(value or "", max_length=2000)
                row_map[key]["answer_status"] = row_map[key].get("answer_status") or "USER_EDITED"
        public_questions = list(row_map.values())
    else:
        public_questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    validation = validate_mikrotik_question_answers(public_questions, router_id)
    update_question_validation_metadata(router_id, validation)
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    return {"questions": questions, "validation": validation, "network_preview": derive_mikrotik_network_fields(validation.get("answers", {}).get("client_network_cidr"))}


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/approve")
def approve_mikrotik_deployment_question(router_id: str, payload: MikrotikDeploymentQuestionAction, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    row = fetch_one("SELECT * FROM mikrotik_deployment_questions WHERE router_id = %s AND question_key = %s", (router_id, payload.question_key))
    if not row:
        raise HTTPException(status_code=404, detail="Deployment question not found")
    value = sanitize_routeros_text(payload.value if payload.value is not None else (row.get("suggested_value") or row.get("answer_value") or ""), max_length=2000)
    if not value:
        raise HTTPException(status_code=400, detail="Cannot approve an empty planning answer.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_questions
                SET answer_value = %s,
                    approved_value = %s,
                    answer_status = CASE WHEN locked THEN 'LOCKED' ELSE 'APPROVED' END,
                    answered_by_admin_id = %s,
                    answered_at = now(),
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE router_id = %s AND question_key = %s
                RETURNING *
                """,
                (value, value, admin["id"], admin["id"], router_id, payload.question_key),
            )
            updated = cur.fetchone()
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    validation = validate_mikrotik_question_answers(questions, router_id)
    update_question_validation_metadata(router_id, validation)
    audit(admin["id"], "approve_mikrotik_deployment_question", "mikrotik_deployment_questions", str(updated["id"]), {"router_id": router_id, "question_key": payload.question_key})
    return {"question": public_mikrotik_deployment_question(updated), "validation": validation}


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/reject")
def reject_mikrotik_deployment_question(router_id: str, payload: MikrotikDeploymentQuestionAction, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_questions
                SET suggested_value = NULL,
                    answer_value = CASE
                        WHEN locked THEN answer_value
                        WHEN answer_status = 'AI_SUGGESTED' OR COALESCE(answer_value, '') = COALESCE(suggested_value, '') THEN NULL
                        ELSE answer_value
                    END,
                    approved_value = CASE
                        WHEN locked THEN approved_value
                        WHEN answer_status = 'AI_SUGGESTED' OR COALESCE(answer_value, '') = COALESCE(suggested_value, '') THEN NULL
                        ELSE approved_value
                    END,
                    suggestion_reason = NULL,
                    suggestion_confidence = NULL,
                    suggestion_requires_review = true,
                    answer_status = CASE
                        WHEN locked THEN 'LOCKED'
                        WHEN answer_status = 'AI_SUGGESTED' OR COALESCE(answer_value, '') = COALESCE(suggested_value, '') THEN 'EMPTY'
                        ELSE 'REJECTED'
                    END,
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE router_id = %s AND question_key = %s
                RETURNING *
                """,
                (admin["id"], router_id, payload.question_key),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Deployment question not found")
    audit(admin["id"], "reject_mikrotik_deployment_question", "mikrotik_deployment_questions", str(row["id"]), {"router_id": router_id, "question_key": payload.question_key})
    return public_mikrotik_deployment_question(row)


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/lock")
def lock_mikrotik_deployment_question(router_id: str, payload: MikrotikDeploymentQuestionAction, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    locked = bool(payload.locked)
    row = fetch_one("SELECT * FROM mikrotik_deployment_questions WHERE router_id = %s AND question_key = %s", (router_id, payload.question_key))
    if not row:
        raise HTTPException(status_code=404, detail="Deployment question not found")
    value = row.get("approved_value") or row.get("answer_value")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_questions
                SET locked = %s,
                    approved_value = CASE WHEN %s THEN COALESCE(approved_value, answer_value) ELSE approved_value END,
                    answer_status = CASE
                        WHEN %s THEN 'LOCKED'
                        WHEN approved_value IS NOT NULL THEN 'APPROVED'
                        WHEN suggested_value IS NOT NULL THEN 'AI_SUGGESTED'
                        WHEN answer_value IS NOT NULL THEN 'USER_EDITED'
                        ELSE 'EMPTY'
                    END,
                    updated_by_admin_id = %s,
                    updated_at = now()
                WHERE router_id = %s AND question_key = %s
                RETURNING *
                """,
                (locked, locked, locked, admin["id"], router_id, payload.question_key),
            )
            updated = cur.fetchone()
    audit(admin["id"], "lock_mikrotik_deployment_question", "mikrotik_deployment_questions", str(updated["id"]), {"router_id": router_id, "question_key": payload.question_key, "locked": locked, "had_value": bool(value)})
    return public_mikrotik_deployment_question(updated)


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/apply-safe-suggestions")
def apply_safe_mikrotik_suggestions(router_id: str, admin=Depends(current_admin)):
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="Planning questions are currently enabled only for the selected pilot router.")
    ensure_mikrotik_deployment_questions(router_id)
    applied = []
    skipped = []
    rows = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    for question in rows:
        value = question.get("suggested_value")
        if not value or question.get("locked") or question.get("suggestion_requires_review"):
            skipped.append({"question_key": question["question_key"], "reason": "No safe auto-approval suggestion or manual review required."})
            continue
        trial = []
        for item in rows:
            clone = dict(item)
            if item["question_key"] == question["question_key"]:
                clone["answer_value"] = value
                clone["approved_value"] = value
                clone["answer_status"] = "APPROVED"
            trial.append(clone)
        validation = validate_mikrotik_question_answers(trial, router_id)
        related_errors = [err for err in validation.get("errors") or [] if question["question_key"].replace("_", " ") in err.lower() or question["question_key"].split("_")[0] in err.lower()]
        if related_errors:
            skipped.append({"question_key": question["question_key"], "reason": "; ".join(related_errors)})
            continue
        approved = approve_mikrotik_deployment_question(router_id, MikrotikDeploymentQuestionAction(question_key=question["question_key"], value=value), admin)
        applied.append(approved["question"])
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    validation = validate_mikrotik_question_answers(questions, router_id)
    update_question_validation_metadata(router_id, validation)
    return {"applied": applied, "skipped": skipped, "questions": questions, "validation": validation}


@app.post("/api/captive-portal/mikrotik/{router_id}/deployment-questions/ai-suggest")
def suggest_mikrotik_deployment_answers(router_id: str, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    active_pilot = active_mikrotik_pilot_selection()
    if not active_pilot or str(active_pilot["router_id"]) != str(router_id):
        raise HTTPException(status_code=400, detail="AI planning suggestions are currently enabled only for the selected pilot router.")
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row or scan_row.get("scan_status") != "SUCCESS":
        raise HTTPException(status_code=400, detail="A successful preflight scan is required before AI suggestions.")
    if not openai_api_status().get("configured"):
        raise HTTPException(status_code=400, detail="OpenAI is not configured. Manual planning and deterministic derivation still work.")
    questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
    interface_candidates = mikrotik_interface_candidates(router_id)
    context = mikrotik_ai_planning_suggestion_context(router, router_id, questions, interface_candidates)
    prompt_summary = "Suggest missing MikroTik captive portal planning answers. Do not generate RouterOS commands."
    payload = {
        "task": prompt_summary,
        "router_id": router_id,
        "question_keys": [item["question_key"] for item in questions],
        "existing_answers": {item["question_key"]: item.get("answer_value") for item in questions},
        "sanitized_planning_context": context,
        "required_json_shape": {
            "router_id": router_id,
            "suggestions": [{"question_key": "customer_vlan_id", "suggested_value": "777", "reason": "short reason", "confidence": "medium", "requires_user_review": True}],
            "assumptions": [],
            "warnings": [],
            "questions_still_needing_user_input": [],
        },
        "rules": [
            "Return JSON only. No markdown.",
            "Suggest planning answers only.",
            "Return one suggestion object for every question_key.",
            "Prefer a concrete suggested_value when scan data and safety policy make a reasonable safe default possible.",
            "Do not include RouterOS commands.",
            "Do not invent interface names not present in interface_candidates.",
            "If unsure, use suggested_value null and requires_user_review true, but still include the question_key.",
            "Avoid PPPoE, OSPF, WireGuard, core/WAN interfaces unless explicitly needed.",
        ],
    }
    suggestions_json_schema = {
        "type": "json_schema",
        "name": "mikrotik_planning_suggestions",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "router_id": {"type": "string"},
                "suggestions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "question_key": {"type": "string"},
                            "suggested_value": {"type": ["string", "null"]},
                            "reason": {"type": "string"},
                            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                            "requires_user_review": {"type": "boolean"},
                        },
                        "required": ["question_key", "suggested_value", "reason", "confidence", "requires_user_review"],
                    },
                },
                "assumptions": {"type": "array", "items": {"type": "string"}},
                "warnings": {"type": "array", "items": {"type": "string"}},
                "questions_still_needing_user_input": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["router_id", "suggestions", "assumptions", "warnings", "questions_still_needing_user_input"],
        },
    }
    try:
        output_text = call_openai_responses(
            mikrotik_ai_system_prompt("planning_suggestions"),
            payload,
            max_output_tokens=3000,
            user_agent="3JCentralPisowifi/0.1 mikrotik-ai-planning-suggestions",
            text_format=suggestions_json_schema,
            reasoning_effort_override="low",
        )
        if mikrotik_plan_has_routeros_commands(output_text):
            raise HTTPException(status_code=400, detail="RouterOS commands are not allowed in MT-3.2. Command preview will be generated in MT-4 only.")
        parsed = json.loads(strip_json_markdown(output_text))
        parsed = sanitize_routeros_object(parsed)
        suggestions = parsed.get("suggestions") if isinstance(parsed, dict) else None
        if not isinstance(suggestions, list):
            raise HTTPException(status_code=400, detail="AI suggestions response did not include a suggestions list.")
        suggestions = complete_mikrotik_planning_suggestions(router_id, questions, suggestions, interface_candidates)
        parsed["suggestions"] = suggestions
        apply_mikrotik_ai_suggestions_to_questions(router_id, suggestions, admin["id"])
        row = save_mikrotik_ai_planning_suggestions(admin["id"], router_id, "SUCCESS", prompt_summary, suggestions=parsed, warnings=parsed.get("warnings") or [])
        updated_questions = [public_mikrotik_deployment_question(row) for row in ensure_mikrotik_deployment_questions(router_id)]
        validation = validate_mikrotik_question_answers(updated_questions, router_id)
        update_question_validation_metadata(router_id, validation)
        audit(admin["id"], "suggest_mikrotik_deployment_answers", "mikrotik_ai_planning_suggestions", str(row["id"]), {"router_id": router_id, "suggestion_count": len(suggestions)})
        return {"suggestion_run_id": row["id"], "suggestions": parsed, "questions": updated_questions, "validation": validation}
    except HTTPException as exc:
        save_mikrotik_ai_planning_suggestions(admin["id"], router_id, "FAILED", prompt_summary, error_message=str(exc.detail))
        raise
    except Exception as exc:
        save_mikrotik_ai_planning_suggestions(admin["id"], router_id, "FAILED", prompt_summary, error_message=str(exc))
        raise HTTPException(status_code=400, detail=f"AI suggestions failed: {exc}") from exc


@app.post("/api/captive-portal/mikrotik/{router_id}/ai/generate-draft-plan")
def generate_mikrotik_ai_draft_plan(router_id: str, payload: MikrotikDraftPlanGenerateRequest, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    readiness = build_mikrotik_mt4_readiness(router_id)
    if not readiness.get("ready_for_draft_plan"):
        missing = list(readiness.get("missing_requirements") or [])
        if not readiness.get("openai", {}).get("configured"):
            missing.append("OpenAI must be configured before AI draft-plan generation.")
        raise HTTPException(status_code=400, detail={"message": "Draft plan generation is not ready.", "missing_requirements": sorted(set(missing))})
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row or scan_row["scan_status"] != "SUCCESS":
        raise HTTPException(status_code=400, detail="A successful preflight scan is required before generating a draft plan.")
    policy_row = latest_mikrotik_policy_row(router_id, scan_row["id"]) or evaluate_and_store_mikrotik_policy(router, scan_row)
    context = mikrotik_ai_safe_context(router_id)
    required_fields = [
        "router_id",
        "router_name",
        "proposed_deployment_mode",
        "proposed_customer_vlan_id",
        "proposed_vlan_parent_interface",
        "proposed_vlan_interface_name",
        "proposed_client_network_cidr",
        "proposed_gateway_ip",
        "proposed_pool_start",
        "proposed_pool_end",
        "proposed_pool_name",
        "proposed_dhcp_server_name",
        "proposed_dns_servers",
        "proposed_hotspot_dns_name",
        "proposed_portal_url",
        "proposed_nat_enabled",
        "proposed_wan_interface",
        "objects_to_create",
        "objects_to_avoid",
        "protected_existing_config",
        "risks",
        "assumptions",
        "questions_still_needed",
        "ai_confidence",
        "requires_human_confirmation",
    ]
    ai_payload = {
        "task": "Generate a structured draft deployment plan for MT-4 readiness. Do not include RouterOS commands.",
        "required_fields": required_fields,
        "admin_note": payload.note,
        "sanitized_context": context,
    }
    output_text = call_openai_responses(mikrotik_ai_system_prompt("draft_plan"), ai_payload, max_output_tokens=1800)
    plan = parse_ai_draft_plan(output_text)
    plan["router_id"] = str(router["id"])
    plan.setdefault("router_name", router["router_name"])
    for field in required_fields:
        plan.setdefault(field, None)
    validation = validate_mikrotik_draft_plan(router, plan, scan_row, policy_row)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_draft_deployment_plans(
                    router_id, scan_id, created_by_admin_id, ai_generated, plan_json,
                    validation_status, validation_result_json, status
                )
                VALUES (%s, %s, %s, true, %s, %s, %s, 'DRAFT')
                RETURNING *
                """,
                (
                    router_id,
                    scan_row["id"],
                    admin["id"],
                    Json(json_safe(plan)),
                    validation["validation_status"],
                    Json(json_safe(validation)),
                ),
            )
            row = cur.fetchone()
    audit(admin["id"], "generate_mikrotik_ai_draft_plan", "mikrotik_draft_deployment_plans", str(row["id"]), {"router_id": router_id, "validation_status": validation["validation_status"]})
    return public_mikrotik_draft_plan(row)


@app.get("/api/captive-portal/mikrotik/{router_id}/draft-plans")
def list_mikrotik_draft_plans(router_id: str, admin=Depends(current_admin)):
    if not fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,)):
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    rows = fetch_all("SELECT * FROM mikrotik_draft_deployment_plans WHERE router_id = %s ORDER BY created_at DESC LIMIT 25", (router_id,))
    return [public_mikrotik_draft_plan(row) for row in rows]


@app.get("/api/captive-portal/mikrotik/{router_id}/draft-plans/{plan_id}")
def get_mikrotik_draft_plan(router_id: str, plan_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_draft_deployment_plans WHERE id = %s AND router_id = %s", (plan_id, router_id))
    if not row:
        raise HTTPException(status_code=404, detail="Draft deployment plan not found")
    return public_mikrotik_draft_plan(row)


@app.post("/api/captive-portal/mikrotik/{router_id}/draft-plans/{plan_id}/validate")
def validate_mikrotik_draft_plan_endpoint(router_id: str, plan_id: str, admin=Depends(current_admin)):
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    row = fetch_one("SELECT * FROM mikrotik_draft_deployment_plans WHERE id = %s AND router_id = %s", (plan_id, router_id))
    if not router or not row:
        raise HTTPException(status_code=404, detail="Draft deployment plan not found")
    validation = validate_mikrotik_draft_plan(router, row["plan_json"])
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_draft_deployment_plans
                SET validation_status = %s,
                    validation_result_json = %s,
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (validation["validation_status"], Json(json_safe(validation)), plan_id),
            )
            updated = cur.fetchone()
    audit(admin["id"], "validate_mikrotik_draft_plan", "mikrotik_draft_deployment_plans", plan_id, {"router_id": router_id, "validation_status": validation["validation_status"]})
    return public_mikrotik_draft_plan(updated)


@app.post("/api/captive-portal/mikrotik/{router_id}/draft-plans/{plan_id}/mark-ready")
def mark_mikrotik_draft_plan_ready(router_id: str, plan_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_draft_deployment_plans WHERE id = %s AND router_id = %s", (plan_id, router_id))
    if not row:
        raise HTTPException(status_code=404, detail="Draft deployment plan not found")
    validation = row.get("validation_result_json") or {}
    if row["validation_status"] not in ("PASS", "WARNING") or not validation.get("eligible_for_mt4"):
        raise HTTPException(status_code=400, detail="Blocked plans cannot be marked ready for MT-4 command preview.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_draft_deployment_plans
                SET status = 'SUPERSEDED',
                    updated_at = now()
                WHERE router_id = %s AND id <> %s AND status = 'READY_FOR_COMMAND_PREVIEW'
                """,
                (router_id, plan_id),
            )
            cur.execute(
                """
                UPDATE mikrotik_draft_deployment_plans
                SET status = 'READY_FOR_COMMAND_PREVIEW',
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (plan_id,),
            )
            updated = cur.fetchone()
    audit(admin["id"], "mark_mikrotik_draft_plan_ready", "mikrotik_draft_deployment_plans", plan_id, {"router_id": router_id})
    return public_mikrotik_draft_plan(updated)


@app.get("/api/captive-portal/mikrotik/preflight/summary")
def mikrotik_preflight_summary(admin=Depends(current_admin)):
    return build_mikrotik_preflight_summary()


@app.get("/api/captive-portal/mikrotik/preflight/batches")
def list_mikrotik_preflight_batches(admin=Depends(current_admin)):
    rows = fetch_all("SELECT * FROM mikrotik_preflight_scan_batches ORDER BY created_at DESC LIMIT 25")
    return [public_mikrotik_preflight_batch(row) for row in rows]


@app.get("/api/captive-portal/mikrotik/preflight/batches/{batch_id}")
def get_mikrotik_preflight_batch(batch_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_preflight_scan_batches WHERE id = %s", (batch_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Preflight scan batch not found")
    return public_mikrotik_preflight_batch(row)


@app.post("/api/captive-portal/mikrotik/preflight/scan-all")
def scan_all_mikrotik_preflight(admin=Depends(current_admin)):
    routers = fetch_all("SELECT * FROM mikrotik_routers ORDER BY created_at DESC")
    max_concurrency = max(1, min(MIKROTIK_PRESCAN_MAX_CONCURRENCY, 3))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mikrotik_preflight_scan_batches(status, started_by_admin_id, total_routers, max_concurrency)
                VALUES ('RUNNING', %s, %s, %s)
                RETURNING *
                """,
                (admin["id"], len(routers), max_concurrency),
            )
            batch = cur.fetchone()
            for router in routers:
                cur.execute(
                    """
                    INSERT INTO mikrotik_preflight_scan_batch_items(batch_id, router_id, status)
                    VALUES (%s, %s, 'PENDING')
                    """,
                    (batch["id"], router["id"]),
                )
    batch_id = batch["id"]

    def scan_one(router):
        item = fetch_one(
            """
            SELECT *
            FROM mikrotik_preflight_scan_batch_items
            WHERE batch_id = %s AND router_id = %s
            ORDER BY created_at ASC
            LIMIT 1
            """,
            (batch_id, router["id"]),
        )
        if not router.get("host") or not router.get("username") or not router.get("password_encrypted"):
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE mikrotik_preflight_scan_batch_items
                        SET status = 'SKIPPED', completed_at = now(), error_message = %s, updated_at = now()
                        WHERE id = %s
                        """,
                        ("Router host, username, and saved password are required.", item["id"]),
                    )
            return {"status": "SKIPPED", "router_id": router["id"]}
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE mikrotik_preflight_scan_batch_items SET status = 'RUNNING', started_at = now(), updated_at = now() WHERE id = %s", (item["id"],))
            scan_row = perform_mikrotik_preflight_scan(router, admin["id"], batch_id)
            status = "SUCCESS" if scan_row["scan_status"] == "SUCCESS" else "FAILED"
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE mikrotik_preflight_scan_batch_items
                        SET status = %s, scan_id = %s, completed_at = now(), error_message = %s, updated_at = now()
                        WHERE id = %s
                        """,
                        (status, scan_row["id"], scan_row.get("last_error"), item["id"]),
                    )
            return {"status": status, "router_id": router["id"], "scan_id": scan_row["id"]}
        except Exception as exc:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE mikrotik_preflight_scan_batch_items
                        SET status = 'FAILED', completed_at = now(), error_message = %s, updated_at = now()
                        WHERE id = %s
                        """,
                        (str(exc), item["id"]),
                    )
            return {"status": "FAILED", "router_id": router["id"], "error": str(exc)}

    if routers:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrency) as executor:
            list(executor.map(scan_one, routers))

    items = fetch_all("SELECT status FROM mikrotik_preflight_scan_batch_items WHERE batch_id = %s", (batch_id,))
    success_count = sum(1 for item in items if item["status"] == "SUCCESS")
    failed_count = sum(1 for item in items if item["status"] == "FAILED")
    skipped_count = sum(1 for item in items if item["status"] == "SKIPPED")
    scanned_count = success_count + failed_count
    if success_count and not failed_count and not skipped_count:
        status = "SUCCESS"
    elif success_count:
        status = "PARTIAL_SUCCESS"
    else:
        status = "FAILED" if routers else "SUCCESS"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_preflight_scan_batches
                SET status = %s,
                    scanned_count = %s,
                    success_count = %s,
                    failed_count = %s,
                    skipped_count = %s,
                    completed_at = now(),
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (status, scanned_count, success_count, failed_count, skipped_count, batch_id),
            )
            batch = cur.fetchone()
    summary = build_mikrotik_preflight_summary()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_preflight_scan_batches
                SET summary_json = %s,
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (Json(json_safe(summary)), batch_id),
            )
            batch = cur.fetchone()
    audit(admin["id"], "scan_all_mikrotik_preflight", "mikrotik_preflight_scan_batches", str(batch_id), {"status": status, "total_routers": len(routers), "success_count": success_count, "failed_count": failed_count, "skipped_count": skipped_count})
    return public_mikrotik_preflight_batch(batch)


@app.get("/api/captive-portal/mikrotik/{router_id}/preflight/latest")
def latest_mikrotik_preflight(router_id: str, admin=Depends(current_admin)):
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    latest = fetch_one(
        """
        SELECT *
        FROM mikrotik_preflight_scans
        WHERE router_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (router_id,),
    )
    history = fetch_all(
        """
        SELECT *
        FROM mikrotik_preflight_scans
        WHERE router_id = %s
        ORDER BY created_at DESC
        LIMIT 10
        """,
        (router_id,),
    )
    return {
        "router": public_mikrotik_router(router),
        "scan": public_mikrotik_preflight_scan(latest) if latest else None,
        "policy": public_mikrotik_policy_result(latest_mikrotik_policy_row(router_id, latest["id"] if latest else None)),
        "history": [public_mikrotik_preflight_scan(row, include_snapshot=False) for row in history],
    }


@app.get("/api/captive-portal/mikrotik/{router_id}/preflight/history")
def mikrotik_preflight_history(router_id: str, admin=Depends(current_admin)):
    router = fetch_one("SELECT id FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    rows = fetch_all(
        """
        SELECT *
        FROM mikrotik_preflight_scans
        WHERE router_id = %s
        ORDER BY created_at DESC
        LIMIT 25
        """,
        (router_id,),
    )
    return [public_mikrotik_preflight_scan(row, include_snapshot=False) for row in rows]


@app.post("/api/captive-portal/mikrotik/{router_id}/preflight/scan")
def run_mikrotik_preflight_scan(router_id: str, admin=Depends(current_admin)):
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    try:
        latest = perform_mikrotik_preflight_scan(router, admin["id"])
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(admin["id"], "run_mikrotik_preflight_scan", "mikrotik_preflight_scans", str(latest["id"]), {"router_id": router_id, "status": latest["scan_status"], "risk_level": latest["risk_level"]})
    return public_mikrotik_preflight_scan(latest)


@app.post("/api/captive-portal/mikrotik/{router_id}/preflight/evaluate-policy")
def evaluate_mikrotik_preflight_policy(router_id: str, admin=Depends(current_admin)):
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row:
        raise HTTPException(status_code=400, detail="Run a preflight scan before evaluating policy.")
    policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
    audit(admin["id"], "evaluate_mikrotik_deployment_policy", "mikrotik_deployment_policy_results", str(policy_row["id"]), {"router_id": router_id, "scan_id": str(scan_row["id"]), "setup_allowed": policy_row["setup_allowed"]})
    return {"scan": public_mikrotik_preflight_scan(fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_row["id"],))), "policy": public_mikrotik_policy_result(policy_row)}


@app.put("/api/captive-portal/mikrotik/{router_id}/deployment-mode")
def save_mikrotik_deployment_mode(router_id: str, payload: MikrotikDeploymentModePayload, admin=Depends(current_admin)):
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row or scan_row["scan_status"] != "SUCCESS":
        raise HTTPException(status_code=400, detail="A successful preflight scan is required before confirming deployment mode.")
    confirmed_role = normalize_mikrotik_router_role(payload.confirmed_router_role)
    confirmed_mode = normalize_mikrotik_deployment_mode(payload.confirmed_deployment_mode)
    if confirmed_mode not in MIKROTIK_DEPLOYMENT_MODES:
        raise HTTPException(status_code=400, detail="Invalid deployment mode.")
    existing_policy = latest_mikrotik_policy_row(router_id, scan_row["id"])
    provisional_policy = evaluate_mikrotik_deployment_policy(
        router,
        {**dict(scan_row), "confirmed_router_role": confirmed_role, "confirmed_deployment_mode": confirmed_mode},
        existing_policy,
    )
    if confirmed_mode == "HOTSPOT_GATEWAY" and provisional_policy.get("requires_expert_override") and not payload.sensitive_confirmation:
        raise HTTPException(status_code=400, detail="This router has sensitive/high-risk indicators. Confirm that you only intend to use a new dedicated captive portal VLAN/network.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_preflight_scans
                SET confirmed_router_role = %s,
                    confirmed_deployment_mode = %s,
                    deployment_mode_confirmed_by_admin_id = %s,
                    deployment_mode_confirmed_at = now(),
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (confirmed_role, confirmed_mode, admin["id"], scan_row["id"]),
            )
            scan_row = cur.fetchone()
    policy_row = evaluate_and_store_mikrotik_policy(router, scan_row)
    audit(admin["id"], "save_mikrotik_deployment_mode", "mikrotik_preflight_scans", str(scan_row["id"]), {"router_id": router_id, "confirmed_router_role": confirmed_role, "confirmed_deployment_mode": confirmed_mode})
    return {"scan": public_mikrotik_preflight_scan(scan_row), "policy": public_mikrotik_policy_result(policy_row)}


@app.post("/api/captive-portal/mikrotik/{router_id}/expert-override")
def save_mikrotik_expert_override(router_id: str, payload: MikrotikExpertOverridePayload, admin=Depends(current_admin)):
    if payload.confirmation_phrase.strip() != "I UNDERSTAND THE RISK":
        raise HTTPException(status_code=400, detail="Type exactly: I UNDERSTAND THE RISK")
    router = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not router:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    scan_row = latest_mikrotik_scan_row(router_id)
    if not scan_row or scan_row["scan_status"] != "SUCCESS":
        raise HTTPException(status_code=400, detail="A successful preflight scan is required before expert override.")
    base_policy = latest_mikrotik_policy_row(router_id, scan_row["id"]) or evaluate_and_store_mikrotik_policy(router, scan_row)
    if not base_policy["requires_expert_override"]:
        raise HTTPException(status_code=400, detail="This policy result does not require expert override.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mikrotik_deployment_policy_results
                SET expert_override_enabled = true,
                    expert_override_reason = %s,
                    expert_override_by_admin_id = %s,
                    expert_override_at = now(),
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (payload.reason.strip(), admin["id"], base_policy["id"]),
            )
            override_policy = cur.fetchone()
    recalculated = evaluate_mikrotik_deployment_policy(router, scan_row, override_policy)
    policy_row = save_mikrotik_policy_result(router_id, scan_row, recalculated, override_policy)
    audit(admin["id"], "save_mikrotik_expert_override", "mikrotik_deployment_policy_results", str(policy_row["id"]), {"router_id": router_id, "scan_id": str(scan_row["id"])})
    return {"scan": public_mikrotik_preflight_scan(fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_row["id"],))), "policy": public_mikrotik_policy_result(policy_row)}


@app.get("/api/captive-portal/mikrotik/{router_id}/preflight/{scan_id}")
def get_mikrotik_preflight_scan(router_id: str, scan_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s AND router_id = %s", (scan_id, router_id))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik preflight scan not found")
    return public_mikrotik_preflight_scan(row)


@app.post("/api/captive-portal/mikrotik/{router_id}/preflight/{scan_id}/ai-explain")
def explain_mikrotik_preflight_scan(router_id: str, scan_id: str, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    row = fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s AND router_id = %s", (scan_id, router_id))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik preflight scan not found")
    scan = public_mikrotik_preflight_scan(row)
    if scan["scan_status"] != "SUCCESS":
        raise HTTPException(status_code=400, detail="AI explanation is available only after a successful preflight scan.")
    store = openai_store()
    api_key = decrypt_secret(store.get("api_key_encrypted"))
    if not normalize_openai_text(api_key):
        raise HTTPException(status_code=400, detail="OpenAI API key is not configured. The scanner still works without AI.")
    model_id = normalize_openai_model(store.get("selected_model"))
    reasoning_effort = normalize_openai_reasoning_effort(model_id, store.get("reasoning_effort"))
    ai_input = mikrotik_preflight_ai_payload(scan)
    prompt = (
        "You are a cautious MikroTik captive portal deployment copilot. Explain this sanitized preflight scan in plain language. "
        "Do not generate executable RouterOS commands. Do not recommend applying configuration yet. "
        "Do not invent missing router details. If uncertain, ask confirmation questions. "
        "Focus on router role, major risks, whether HotSpot Gateway mode looks safe, and next questions for the user."
    )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "3JCentralPisowifi/0.1 mikrotik-preflight-ai",
    }
    organization_id = normalize_openai_text(store.get("organization_id"))
    project_id = normalize_openai_text(store.get("project_id"))
    if organization_id:
        headers["OpenAI-Organization"] = organization_id
    if project_id:
        headers["OpenAI-Project"] = project_id
    body = {
        "model": model_id,
        "input": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(ai_input, default=str)[:16000]},
        ],
        "max_output_tokens": 900,
    }
    if reasoning_effort:
        body["reasoning"] = {"effort": reasoning_effort}
    try:
        response = requests.post("https://api.openai.com/v1/responses", headers=headers, json=body, timeout=45)
        response_data = response.json() if response.content else {}
        if response.status_code >= 400:
            error_message = response_data.get("error", {}).get("message") if isinstance(response_data, dict) else None
            raise RuntimeError(error_message or f"OpenAI API returned HTTP {response.status_code}")
        summary = extract_openai_response_text(response_data if isinstance(response_data, dict) else {})
        if not summary:
            raise RuntimeError("OpenAI returned an empty explanation.")
    except Exception as exc:
        message = f"AI explanation unavailable: {exc}"
        audit(admin["id"], "explain_mikrotik_preflight_scan", "mikrotik_preflight_scans", scan_id, {"router_id": router_id, "status": "FAILED", "error": str(exc)})
        raise HTTPException(status_code=400, detail=message)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE mikrotik_preflight_scans SET ai_summary = %s, updated_at = now() WHERE id = %s",
                (summary, scan_id),
            )
    audit(admin["id"], "explain_mikrotik_preflight_scan", "mikrotik_preflight_scans", scan_id, {"router_id": router_id, "status": "SUCCESS", "model": model_id})
    latest = fetch_one("SELECT * FROM mikrotik_preflight_scans WHERE id = %s", (scan_id,))
    return public_mikrotik_preflight_scan(latest)


@app.get("/api/captive-portal/mikrotik/{router_id}/managed-configuration-status")
def mikrotik_managed_configuration_status_endpoint(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    status = mikrotik_managed_configuration_status(row)
    audit(admin["id"], "check_mikrotik_managed_configuration", "mikrotik_routers", router_id, {"status": status.get("status"), "found_count": status.get("found_count", 0)})
    return status


@app.get("/api/captive-portal/mikrotik/{router_id}/configuration-preview")
def preview_mikrotik_configuration(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    settings = ensure_captive_portal_settings()
    plan = mikrotik_configuration_plan(row, settings)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE mikrotik_routers SET last_configuration_review_at = now(), last_configuration_error = NULL, updated_at = now() WHERE id = %s",
                (router_id,),
            )
    log_captive_portal_test("REVIEW_MIKROTIK_CONFIGURATION", "SUCCESS", "MikroTik configuration reviewed.", {"router_id": router_id, "plan": plan})
    audit(admin["id"], "review_mikrotik_configuration", "mikrotik_routers", router_id, {"host": row["host"], "can_apply": plan["can_apply"]})
    return plan


def find_mikrotik_plan_step(plan: dict, step_key: str):
    for action in plan.get("actions") or []:
        if action.get("key") == step_key:
            return action
    return None


@app.post("/api/captive-portal/mikrotik/{router_id}/apply-configuration-step")
def apply_mikrotik_configuration_step(router_id: str, payload: MikrotikConfigurationStepApply, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    settings = ensure_captive_portal_settings()
    plan = mikrotik_configuration_plan(row, settings)
    action = find_mikrotik_plan_step(plan, payload.step_key)
    if not action:
        raise HTTPException(status_code=404, detail="MikroTik configuration step not found")
    if action.get("apply_mode") == "routeros_commands":
        raise HTTPException(
            status_code=400,
            detail="RouterOS write apply is disabled in MT-2. Use Preflight Summary and deployment mode confirmation first; command preview/apply is reserved for a later phase.",
        )
    if not action.get("apply_supported"):
        raise HTTPException(status_code=400, detail=f"{action.get('step')} is not ready for automatic apply yet.")
    if not plan["can_apply"]:
        message = "Router host, username, and password are required before applying configuration."
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE mikrotik_routers SET configuration_status = 'FAILED', last_configuration_error = %s, updated_at = now() WHERE id = %s",
                    (message, router_id),
                )
        raise HTTPException(status_code=400, detail=message)
    try:
        password = decrypt_secret(row.get("password_encrypted"))
        if action.get("apply_mode") == "api_login":
            result = test_mikrotik_api_login(row["host"], row["api_port"], row.get("username"), password, row.get("use_tls"))
            if result.get("status") != "REACHABLE":
                raise RuntimeError(result.get("message") or "MikroTik API login failed")
        elif action.get("apply_mode") == "routeros_commands":
            result = routeros_execute_commands(
                row["host"],
                row["api_port"],
                row.get("username"),
                password,
                row.get("use_tls"),
                action.get("commands") or [],
            )
        else:
            raise RuntimeError("This MikroTik configuration step has no supported apply mode.")
        message = result.get("message") if isinstance(result, dict) and result.get("message") else f"{action.get('step')} applied."
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE mikrotik_routers
                    SET status = 'REACHABLE',
                        last_test_at = now(),
                        last_error = NULL,
                        last_configuration_apply_at = now(),
                        last_configuration_error = NULL,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (router_id,),
                )
        updated_after_apply = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
        update_mikrotik_step_status(router_id, updated_after_apply, payload.step_key, "SUCCESS", message)
        log_captive_portal_test("APPLY_MIKROTIK_CONFIGURATION_STEP", "SUCCESS", message, {"router_id": router_id, "step_key": payload.step_key, "step": action, "result": result})
        audit(admin["id"], "apply_mikrotik_configuration_step", "mikrotik_routers", router_id, {"host": row["host"], "step_key": payload.step_key, "status": "SUCCESS"})
        updated = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
        return {"status": "SUCCESS", "message": message, "step": action, "result": sanitize_summary(result), "plan": mikrotik_configuration_plan(updated, settings)}
    except Exception as exc:
        message = str(exc)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE mikrotik_routers SET configuration_status = 'FAILED', last_configuration_error = %s, updated_at = now() WHERE id = %s",
                    (message, router_id),
                )
        latest = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
        update_mikrotik_step_status(router_id, latest, payload.step_key, "FAILED", message)
        log_captive_portal_test("APPLY_MIKROTIK_CONFIGURATION_STEP", "FAILED", message, {"router_id": router_id, "step_key": payload.step_key, "step": action})
        audit(admin["id"], "apply_mikrotik_configuration_step", "mikrotik_routers", router_id, {"host": row["host"], "step_key": payload.step_key, "status": "FAILED"})
        raise HTTPException(status_code=400, detail=message)


@app.post("/api/captive-portal/mikrotik/{router_id}/remove-configuration")
@app.post("/api/captive-portal/mikrotik/{router_id}/revert-configuration")
def revert_mikrotik_configuration(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    if not row.get("host") or not row.get("username") or not row.get("password_encrypted"):
        raise HTTPException(status_code=400, detail="Router host, username, and password are required before removing configuration.")
    revert_plan = mikrotik_revert_configuration_plan(row)
    try:
        password = decrypt_secret(row.get("password_encrypted"))
        managed_status = routeros_detect_remove_targets(
            row["host"],
            row["api_port"],
            row.get("username"),
            password,
            row.get("use_tls"),
            revert_plan["commands"],
        )
        if not managed_status.get("has_managed_config"):
            message = "No 3JCentralPisowifi-managed MikroTik configuration was found to remove."
            log_captive_portal_test("REMOVE_MIKROTIK_CONFIGURATION", "WARNING", message, {"router_id": router_id, "managed_status": managed_status})
            audit(admin["id"], "remove_mikrotik_configuration", "mikrotik_routers", router_id, {"host": row["host"], "status": "NO_CONFIGURATION"})
            return {"status": "NO_CONFIGURATION", "message": message, "managed_configuration_status": managed_status, "plan": mikrotik_configuration_plan(row, ensure_captive_portal_settings())}
        result = routeros_execute_remove_commands(
            row["host"],
            row["api_port"],
            row.get("username"),
            password,
            row.get("use_tls"),
            revert_plan["commands"],
        )
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE mikrotik_routers
                    SET status = 'REACHABLE',
                        configuration_status = 'NOT_REVIEWED',
                        configuration_step_status = '{}'::jsonb,
                        last_configuration_error = NULL,
                        updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (router_id,),
                )
                updated = cur.fetchone()
        message = "3JCentralPisowifi-managed MikroTik configuration was removed."
        log_captive_portal_test("REMOVE_MIKROTIK_CONFIGURATION", "SUCCESS", message, {"router_id": router_id, "revert_plan": revert_plan, "result": result})
        audit(admin["id"], "remove_mikrotik_configuration", "mikrotik_routers", router_id, {"host": row["host"], "status": "SUCCESS"})
        return {"status": "SUCCESS", "message": message, "result": sanitize_summary(result), "plan": mikrotik_configuration_plan(updated, ensure_captive_portal_settings())}
    except Exception as exc:
        message = str(exc)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE mikrotik_routers SET configuration_status = 'FAILED', last_configuration_error = %s, updated_at = now() WHERE id = %s",
                    (message, router_id),
                )
        log_captive_portal_test("REMOVE_MIKROTIK_CONFIGURATION", "FAILED", message, {"router_id": router_id, "revert_plan": revert_plan})
        audit(admin["id"], "remove_mikrotik_configuration", "mikrotik_routers", router_id, {"host": row["host"], "status": "FAILED"})
        raise HTTPException(status_code=400, detail=message)


@app.post("/api/captive-portal/mikrotik/{router_id}/apply-configuration")
def apply_mikrotik_configuration(router_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM mikrotik_routers WHERE id = %s", (router_id,))
    if not row:
        raise HTTPException(status_code=404, detail="MikroTik router not found")
    message = "Full MikroTik apply is disabled for transparency. Use Start Setup and apply each displayed step after reviewing its exact RouterOS commands."
    audit(admin["id"], "blocked_apply_mikrotik_configuration", "mikrotik_routers", router_id, {"host": row["host"], "reason": "step_by_step_required"})
    raise HTTPException(status_code=400, detail=message)


@app.get("/api/captive-portal/design")
def get_portal_design(admin=Depends(current_admin)):
    row = fetch_one("SELECT * FROM portal_design_templates ORDER BY updated_at DESC LIMIT 1")
    if not row:
        return {
            "html_template": '<div class="portal-template-brand">{{brand}}</div>\n{{voucher_form}}\n{{help}}',
            "css_template": "",
        }
    return {
        "id": row["id"],
        "template_name": row["template_name"],
        "html_template": row["html_template"],
        "css_template": row["css_template"],
        "updated_at": row["updated_at"],
    }


@app.put("/api/captive-portal/design")
def save_portal_design(payload: PortalDesignUpdate, admin=Depends(current_admin)):
    current = fetch_one("SELECT * FROM portal_design_templates ORDER BY updated_at DESC LIMIT 1")
    if current:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE portal_design_templates
                    SET html_template = %s, css_template = %s, updated_by_admin_id = %s, updated_at = now()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (payload.html_template, payload.css_template or "", admin["id"], current["id"]),
                )
                row = cur.fetchone()
    else:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO portal_design_templates(html_template, css_template, updated_by_admin_id)
                    VALUES (%s, %s, %s)
                    RETURNING *
                    """,
                    (payload.html_template, payload.css_template or "", admin["id"]),
                )
                row = cur.fetchone()
    audit(admin["id"], "save_portal_design", "portal_design_templates", str(row["id"]), {"html_length": len(payload.html_template), "css_length": len(payload.css_template or "")})
    return {"id": row["id"], "html_template": row["html_template"], "css_template": row["css_template"], "updated_at": row["updated_at"]}


@app.post("/api/captive-portal/test-omada")
def captive_portal_test_omada(admin=Depends(current_admin)):
    try:
        settings, client = omada_api_client_from_settings()
        login_result = client.test_login()
        version_result = {}
        try:
            version_result = client.detect_controller_version()
        except Exception as exc:
            version_result = {"error": str(exc)}
        log_captive_portal_test("TEST_OMADA_API", "SUCCESS", "Omada API login succeeded.", {"login": login_result, "version": version_result})
        audit(admin["id"], "test_captive_portal_omada_api", "omada_api_settings", str(settings["id"]))
        return {"status": "SUCCESS", "message": "Omada API login succeeded.", "details": sanitize_summary({"login": login_result, "version": version_result})}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        log_captive_portal_test("TEST_OMADA_API", "FAILED", "Omada API login failed.", {"error": str(exc), "response": response_summary})
        return {"status": "FAILED", "message": "Omada API login failed.", "error": str(exc), "details": sanitize_summary(response_summary)}


@app.post("/api/captive-portal/omada/create-open-ssid")
def captive_portal_create_open_ssid(payload: OmadaPortalConfigureRequest = OmadaPortalConfigureRequest(), admin=Depends(current_admin)):
    settings = ensure_captive_portal_settings()
    _, site_id, site_name = omada_selected_site(settings)
    ssid_name = payload.ssid_name or captive_portal_ssid_from_ap_configuration()["primary_ssid"]
    if not site_id:
        message = "Select an Omada site before creating the open SSID."
        log_captive_portal_test("CREATE_OPEN_SSID", "FAILED", message, {"ssid": ssid_name})
        return {"status": "FAILED", "message": message, "manual_fallback": True}
    try:
        _, client = omada_api_client_from_settings()
        result = client.create_open_ssid_if_supported(site_id, ssid_name)
        log_captive_portal_test("CREATE_OPEN_SSID", "SUCCESS", "Open SSID created or already exists.", {"ssid": ssid_name, "site_id": site_id, "result": result})
        audit(admin["id"], "create_captive_portal_open_ssid", "captive_portal_settings", str(settings["id"]), {"ssid": ssid_name, "site_id": site_id, "site_name": site_name})
        return {"status": "SUCCESS", "message": "Open SSID created or already exists.", "result": sanitize_summary(result)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        log_captive_portal_test("CREATE_OPEN_SSID", "FAILED", "Open SSID automation failed.", {"ssid": ssid_name, "site_id": site_id, "error": str(exc), "response": response_summary})
        return {"status": "FAILED", "message": "Open SSID automation failed. Use the manual setup guide.", "error": str(exc), "manual_fallback": True, "details": sanitize_summary(response_summary)}


@app.post("/api/captive-portal/omada/configure-external-portal")
def captive_portal_configure_external_portal(payload: OmadaPortalConfigureRequest = OmadaPortalConfigureRequest(), admin=Depends(current_admin)):
    settings = ensure_captive_portal_settings()
    _, site_id, site_name = omada_selected_site(settings)
    portal_url = payload.portal_url or settings["portal_url_staging"]
    ssid_name = payload.ssid_name or captive_portal_ssid_from_ap_configuration()["primary_ssid"]
    if not site_id:
        message = "Select an Omada site before configuring the external portal."
        log_captive_portal_test("CONFIGURE_EXTERNAL_PORTAL", "FAILED", message, {"portal_url": portal_url})
        return {"status": "FAILED", "message": message, "manual_fallback": True}
    omada_payload = {
        "name": "3JCentralPisowifi External Portal",
        "type": "EXTERNAL",
        "portalUrl": portal_url,
        "externalPortalUrl": portal_url,
        "ssidName": ssid_name,
        "authType": "EXTERNAL_PORTAL",
        "walledGarden": ["192.168.50.70", "192.168.50.70:8080"],
    }
    try:
        _, client = omada_api_client_from_settings()
        result = client.configure_external_portal_if_supported(site_id, omada_payload)
        log_captive_portal_test("CONFIGURE_EXTERNAL_PORTAL", "SUCCESS", "External portal profile created or updated.", {"portal_url": portal_url, "site_id": site_id, "result": result})
        audit(admin["id"], "configure_captive_portal_external_portal", "captive_portal_settings", str(settings["id"]), {"portal_url": portal_url, "site_id": site_id, "site_name": site_name})
        return {"status": "SUCCESS", "message": "External portal profile created or updated.", "result": sanitize_summary(result)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        log_captive_portal_test("CONFIGURE_EXTERNAL_PORTAL", "FAILED", "External portal automation failed.", {"portal_url": portal_url, "site_id": site_id, "error": str(exc), "response": response_summary})
        return {"status": "FAILED", "message": "External portal automation failed. Use the manual setup guide.", "error": str(exc), "manual_fallback": True, "details": sanitize_summary(response_summary)}


@app.post("/api/captive-portal/omada/verify")
def captive_portal_verify(admin=Depends(current_admin)):
    settings = ensure_captive_portal_settings()
    api_settings, site_id, site_name = omada_selected_site(settings)
    result = {
        "portal_settings": public_captive_portal_settings(settings),
        "omada_api_configured": bool(api_settings.get("username") and api_settings.get("password_encrypted")),
        "selected_site_id": site_id,
        "selected_site_name": site_name,
        "portal_reachable": True,
    }
    status = "SUCCESS" if result["omada_api_configured"] and site_id else "WARNING"
    message = "Captive portal setup has the required API and site settings." if status == "SUCCESS" else "Captive portal setup still needs Omada API credentials or a selected site."
    log_captive_portal_test("VERIFY_CAPTIVE_PORTAL", status, message, result)
    return {"status": status, "message": message, "details": sanitize_summary(result)}


@app.get("/api/captive-portal/sessions")
def captive_portal_sessions(admin=Depends(current_admin)):
    rows = fetch_all(
        """
        SELECT s.*, u.username, v.code AS voucher_code
        FROM portal_sessions s
        LEFT JOIN users u ON u.id = s.user_id
        LEFT JOIN vouchers v ON v.id = s.voucher_id
        ORDER BY s.updated_at DESC
        LIMIT 200
        """
    )
    for row in rows:
        row["client_mac_masked"] = mask_mac(row.get("client_mac") or row.get("omada_client_mac") or row.get("mikrotik_client_mac"))
        row["ap_mac_masked"] = mask_mac(row.get("ap_mac") or row.get("omada_ap_mac"))
        row.pop("omada_token_encrypted", None)
    return rows


@app.get("/api/captive-portal/authorizations")
def captive_portal_authorizations(admin=Depends(current_admin)):
    omada_rows = fetch_all(
        """
        SELECT 'OMADA' AS gateway_type, a.*, s.public_session_id, v.code AS voucher_code, u.username
        FROM omada_portal_authorizations a
        LEFT JOIN portal_sessions s ON s.id = a.portal_session_id
        LEFT JOIN vouchers v ON v.id = a.voucher_id
        LEFT JOIN users u ON u.id = a.user_id
        ORDER BY a.created_at DESC
        LIMIT 200
        """
    )
    mikrotik_rows = fetch_all(
        """
        SELECT 'MIKROTIK' AS gateway_type,
               a.id, a.portal_session_id, a.voucher_id, a.user_id, a.client_mac, NULL::text AS ap_mac, NULL::text AS gateway_mac,
               NULL::text AS site_name, a.station_id::text AS site_id, NULL::text AS ssid,
               a.authorization_duration_seconds, a.access_expires_at,
               a.mikrotik_request_summary AS omada_request_summary,
               a.mikrotik_response_summary AS omada_response_summary,
               a.status, a.error_message, a.created_at, a.updated_at,
               s.public_session_id, v.code AS voucher_code, u.username
        FROM mikrotik_portal_authorizations a
        LEFT JOIN portal_sessions s ON s.id = a.portal_session_id
        LEFT JOIN vouchers v ON v.id = a.voucher_id
        LEFT JOIN users u ON u.id = a.user_id
        ORDER BY a.created_at DESC
        LIMIT 200
        """
    )
    rows = sorted([*omada_rows, *mikrotik_rows], key=lambda row: row.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)[:200]
    for row in rows:
        row["client_mac_masked"] = mask_mac(row.get("client_mac"))
        row["ap_mac_masked"] = mask_mac(row.get("ap_mac"))
        if row.get("voucher_code"):
            row["voucher_code_masked"] = mask_voucher_code(row["voucher_code"])
            row.pop("voucher_code", None)
    return rows


@app.post("/api/captive-portal/authorizations/{authorization_id}/retry")
def retry_captive_portal_authorization(authorization_id: str, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.*, s.public_session_id, s.source, s.client_ip, s.redirect_url, s.raw_query_params, s.gateway, s.nas_id,
                       v.*, u.id AS retry_user_id, u.username AS retry_username
                FROM omada_portal_authorizations a
                JOIN portal_sessions s ON s.id = a.portal_session_id
                JOIN vouchers v ON v.id = a.voucher_id
                JOIN users u ON u.id = a.user_id
                WHERE a.id = %s
                """,
                (authorization_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Authorization log not found")
            session = {
                "id": row["portal_session_id"],
                "public_session_id": row["public_session_id"],
                "source": row["source"],
                "client_mac": row["client_mac"],
                "ap_mac": row["ap_mac"],
                "gateway_mac": row["gateway_mac"],
                "ssid": row["ssid"],
                "site": row["site_name"],
                "client_ip": row["client_ip"],
                "redirect_url": row["redirect_url"],
                "gateway": row["gateway"],
                "nas_id": row["nas_id"],
            }
            voucher = {key: row[key] for key in row.keys() if key in {"id", "voucher_type", "time_value_seconds", "valid_until", "unlimited_expires_at"}}
            voucher["id"] = row["voucher_id"]
            user = {"id": row["retry_user_id"], "username": row["retry_username"]}
            retry_payload = PortalRedeemRequest(
                portal_session_id=row["public_session_id"],
                voucher_code="RETRY",
                client_mac=row["client_mac"],
                ap_mac=row["ap_mac"],
                gateway_mac=row["gateway_mac"],
                ssid=row["ssid"],
                site=row["site_name"],
                raw_query_params=row["raw_query_params"] or {},
            )
            result = attempt_omada_authorization(cur, session, voucher, user, row["authorization_duration_seconds"] or 0, row["access_expires_at"], retry_payload)
    audit(admin["id"], "retry_omada_portal_authorization", "omada_portal_authorization", authorization_id, {"result": result["status"]})
    return {"status": result["status"], "message": "Retry completed." if result["status"] == "SUCCESS" else "Retry failed. Use the manual setup guide.", "details": sanitize_summary(result)}


@app.post("/api/voucher-batches")
def create_voucher_batch(payload: VoucherBatchCreate, admin=Depends(current_admin)):
    voucher_type = validate_voucher_payload(payload.voucher_type, payload.time_value_seconds, payload.valid_until)
    created = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO voucher_batches(batch_name, description, voucher_type, quantity, time_value_seconds, valid_until,
                                            unlimited_expires_at, price, code_prefix, code_length, created_by_admin_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (payload.batch_name, payload.description, voucher_type, payload.quantity, payload.time_value_seconds, payload.valid_until, payload.unlimited_expires_at, payload.price, payload.code_prefix, payload.code_length, admin["id"]),
            )
            batch = cur.fetchone()
            for _ in range(payload.quantity):
                voucher_payload = VoucherCreate(
                    voucher_type=voucher_type,
                    time_value_seconds=payload.time_value_seconds,
                    valid_until=payload.valid_until,
                    unlimited_expires_at=payload.unlimited_expires_at,
                    expires_at=payload.expires_at,
                    note=payload.note,
                    max_redemptions=payload.max_redemptions,
                    code_prefix=payload.code_prefix,
                    code_length=payload.code_length,
                )
                created.append(create_single_voucher(cur, voucher_payload, admin["id"], batch["id"]))
            cur.execute("UPDATE voucher_batches SET status = 'COMPLETED', updated_at = now() WHERE id = %s", (batch["id"],))
    audit(admin["id"], "bulk_generate_vouchers", "voucher_batch", str(batch["id"]), {"quantity": payload.quantity, "voucher_type": voucher_type})
    return {"batch": batch, "generated_count": len(created), "vouchers": created[:200]}


@app.get("/api/voucher-batches")
def get_voucher_batches(admin=Depends(current_admin)):
    return fetch_all(
        """
        SELECT b.*,
               a.username AS created_by,
               count(v.id) AS voucher_count,
               count(v.id) FILTER (WHERE v.status = 'UNUSED') AS unused,
               count(v.id) FILTER (WHERE v.status = 'USED') AS used,
               count(v.id) FILTER (WHERE v.status = 'EXPIRED') AS expired,
               count(v.id) FILTER (WHERE v.status = 'DISABLED') AS disabled
        FROM voucher_batches b
        LEFT JOIN vouchers v ON v.batch_id = b.id
        LEFT JOIN admins a ON a.id = b.created_by_admin_id
        GROUP BY b.id, a.username
        ORDER BY b.created_at DESC
        LIMIT 500
        """
    )


@app.get("/api/voucher-batches/{batch_id}")
def get_voucher_batch(batch_id: str, admin=Depends(current_admin)):
    batch = fetch_one("SELECT * FROM voucher_batches WHERE id = %s", (batch_id,))
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return {"batch": batch, "vouchers": voucher_rows("WHERE v.batch_id = %s", (batch_id,))}


@app.get("/api/vouchers/{voucher_id}")
def get_voucher_detail(voucher_id: str, admin=Depends(current_admin)):
    rows = voucher_rows("WHERE v.id = %s", (voucher_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Voucher not found")
    redemptions = fetch_all(
        "SELECT r.*, v.code AS voucher_code FROM voucher_redemptions r LEFT JOIN vouchers v ON v.id = r.voucher_id WHERE r.voucher_id = %s ORDER BY r.created_at DESC",
        (voucher_id,),
    )
    return {"voucher": rows[0], "redemptions": redemptions}


@app.put("/api/vouchers/{voucher_id}")
def update_voucher(voucher_id: str, payload: VoucherUpdate, admin=Depends(current_admin)):
    current = fetch_one("SELECT * FROM vouchers WHERE id = %s", (voucher_id,))
    if not current:
        raise HTTPException(status_code=404, detail="Voucher not found")
    voucher_type = validate_voucher_payload(payload.voucher_type or current["voucher_type"], payload.time_value_seconds if payload.time_value_seconds is not None else current["time_value_seconds"], payload.valid_until if payload.valid_until is not None else current["valid_until"])
    status = (payload.status or current["status"]).upper()
    if status not in VOUCHER_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid voucher status")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE vouchers
                SET voucher_type = %s,
                    time_value_seconds = %s,
                    valid_until = %s,
                    is_unlimited = %s,
                    unlimited_expires_at = %s,
                    expires_at = %s,
                    note = %s,
                    status = %s,
                    max_redemptions = %s,
                    updated_at = now()
                WHERE id = %s
                RETURNING *
                """,
                (
                    voucher_type,
                    payload.time_value_seconds if payload.time_value_seconds is not None else current["time_value_seconds"],
                    payload.valid_until if payload.valid_until is not None else current["valid_until"],
                    voucher_type == "UNLIMITED",
                    payload.unlimited_expires_at if payload.unlimited_expires_at is not None else current["unlimited_expires_at"],
                    payload.expires_at if payload.expires_at is not None else current["expires_at"],
                    payload.note if payload.note is not None else current["note"],
                    status,
                    payload.max_redemptions if payload.max_redemptions is not None else current["max_redemptions"],
                    voucher_id,
                ),
            )
            row = cur.fetchone()
    audit(admin["id"], "update_voucher", "voucher", voucher_id, payload.model_dump(exclude_none=True, mode="json"))
    return row


def set_voucher_status(voucher_id: str, status: str, admin, action: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE vouchers SET status = %s, updated_at = now() WHERE id = %s RETURNING *", (status, voucher_id))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Voucher not found")
    audit(admin["id"], action, "voucher", voucher_id, {"status": status})
    return row


@app.post("/api/vouchers/{voucher_id}/disable")
def disable_voucher(voucher_id: str, admin=Depends(current_admin)):
    return set_voucher_status(voucher_id, "DISABLED", admin, "disable_voucher")


@app.post("/api/vouchers/{voucher_id}/enable")
def enable_voucher(voucher_id: str, admin=Depends(current_admin)):
    row = fetch_one("SELECT redemption_count, max_redemptions FROM vouchers WHERE id = %s", (voucher_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Voucher not found")
    return set_voucher_status(voucher_id, "USED" if row["redemption_count"] >= row["max_redemptions"] else "UNUSED", admin, "enable_voucher")


@app.post("/api/vouchers/{voucher_id}/void")
def void_voucher(voucher_id: str, admin=Depends(current_admin)):
    return set_voucher_status(voucher_id, "VOIDED", admin, "void_voucher")


@app.delete("/api/vouchers/{voucher_id}")
def delete_voucher_if_unused(voucher_id: str, admin=Depends(current_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status, redemption_count FROM vouchers WHERE id = %s", (voucher_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Voucher not found")
            if row["status"] != "UNUSED" or row["redemption_count"] > 0:
                raise HTTPException(status_code=400, detail="Only unused vouchers with no redemptions can be deleted")
            cur.execute("DELETE FROM vouchers WHERE id = %s", (voucher_id,))
    audit(admin["id"], "delete_unused_voucher", "voucher", voucher_id)
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


@app.get("/api/omada/settings")
def get_omada_settings(admin=Depends(current_admin)):
    return public_omada_settings()


@app.put("/api/omada/settings")
def save_omada_settings(payload: OmadaSettingsUpdate, admin=Depends(current_admin)):
    current = ensure_omada_settings()
    allowed = {
        "controller_name", "host", "http_port", "https_port", "api_base_url", "api_username",
        "ssh_host", "ssh_port", "ssh_username", "ssh_auth_type", "sudo_mode", "install_method",
        "network_mode", "docker_image", "checklist_progress",
    }
    updates = {key: value for key, value in payload.model_dump(exclude_none=True).items() if key in allowed}
    if "ssh_auth_type" in updates and updates["ssh_auth_type"] not in {"PASSWORD", "PRIVATE_KEY"}:
        raise HTTPException(status_code=400, detail="Unsupported SSH auth type")
    if "install_method" in updates and updates["install_method"] != "DOCKER":
        raise HTTPException(status_code=400, detail="Only Docker install method is supported in Phase 1D")
    if "network_mode" in updates and updates["network_mode"] not in {"bridge", "host"}:
        raise HTTPException(status_code=400, detail="Unsupported network mode")
    if payload.api_password:
        updates["api_password_encrypted"] = encrypt_secret(payload.api_password)
    if payload.api_token:
        updates["api_token_encrypted"] = encrypt_secret(payload.api_token)
    if payload.ssh_password:
        updates["ssh_password_encrypted"] = encrypt_secret(payload.ssh_password)
    if payload.ssh_private_key:
        updates["ssh_private_key_encrypted"] = encrypt_secret(payload.ssh_private_key)
    if payload.ssh_private_key_passphrase:
        updates["ssh_private_key_passphrase_encrypted"] = encrypt_secret(payload.ssh_private_key_passphrase)
    if not updates:
        return public_omada_settings(current)
    assignments = ", ".join([f"{key} = %s" for key in updates] + ["updated_at = now()"])
    params = [Json(value) if key == "checklist_progress" else value for key, value in updates.items()]
    params.append(current["id"])
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE omada_controller_settings SET {assignments} WHERE id = %s", tuple(params))
    audit(admin["id"], "save_omada_settings", "omada_controller", str(current["id"]), {k: ("[secret]" if "encrypted" in k else v) for k, v in updates.items()})
    return public_omada_settings()


@app.post("/api/omada/test-web")
def test_omada_web(payload: OmadaWebTestRequest, admin=Depends(current_admin)):
    settings = ensure_omada_settings()
    host = payload.host or settings["host"]
    http_port = payload.http_port or settings["http_port"]
    https_port = payload.https_port or settings["https_port"]
    result = {
        "host": host,
        "http": tcp_check(host, http_port),
        "https": tcp_check(host, https_port),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if result["http"]["status"] == "Reachable" or result["https"]["status"] == "Reachable":
        current_status = settings["install_status"]
        update_omada_status("RUNNING" if current_status != "NOT_INSTALLED" else current_status)
    log_id = create_omada_log(admin["id"], "TEST_WEB")
    finish_omada_log(log_id, "SUCCESS", json.dumps(result, indent=2))
    audit(admin["id"], "test_omada_web", "omada_controller", str(settings["id"]), result)
    return result


@app.post("/api/omada/test-ssh")
def test_omada_ssh(admin=Depends(current_admin)):
    settings = ensure_omada_settings()
    log_id = create_omada_log(admin["id"], "TEST_SSH")
    try:
        with omada_ssh_client(settings) as client:
            code, out = run_ssh(client, "echo SSH_OK && uname -a", sudo_mode="NONE", timeout=30)
        if code != 0:
            raise RuntimeError(out)
        finish_omada_log(log_id, "SUCCESS", out)
        audit(admin["id"], "test_omada_ssh", "omada_controller", str(settings["id"]))
        return {"status": "Reachable", "output": out}
    except Exception as exc:
        finish_omada_log(log_id, "FAILED", str(exc))
        audit(admin["id"], "test_omada_ssh_failed", "omada_controller", str(settings["id"]), {"error": str(exc)})
        raise HTTPException(status_code=400, detail=f"SSH failed: {exc}")


@app.post("/api/omada/detect")
def omada_detect(admin=Depends(current_admin)):
    return run_omada_action("DETECT", admin["id"])


@app.post("/api/omada/install")
def omada_install(admin=Depends(current_admin)):
    existing = fetch_one("SELECT id FROM omada_install_logs WHERE action = 'INSTALL' AND status = 'RUNNING' ORDER BY created_at DESC LIMIT 1")
    if existing:
        return {"status": "running", "log_id": existing["id"], "settings": public_omada_settings()}
    settings = ensure_omada_settings()
    log_id = create_omada_log(admin["id"], "INSTALL")
    update_omada_log(log_id, "Install queued.", 2, "Queued")
    update_omada_status("INSTALLING")
    audit(admin["id"], "omada_install_started", "omada_controller", str(settings["id"]), {"log_id": str(log_id)})

    def worker():
        try:
            run_omada_action("INSTALL", admin["id"], log_id=log_id)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()
    return {"status": "running", "log_id": log_id, "settings": public_omada_settings(ensure_omada_settings())}


@app.post("/api/omada/start")
def omada_start(admin=Depends(current_admin)):
    return run_omada_action("START", admin["id"])


@app.post("/api/omada/stop")
def omada_stop(admin=Depends(current_admin)):
    return run_omada_action("STOP", admin["id"])


@app.post("/api/omada/restart")
def omada_restart(admin=Depends(current_admin)):
    return run_omada_action("RESTART", admin["id"])


@app.post("/api/omada/apply-host-network")
def omada_apply_host_network(admin=Depends(current_admin)):
    return run_omada_action("APPLY_HOST_NETWORK", admin["id"])


@app.post("/api/omada/backup")
def omada_backup(admin=Depends(current_admin)):
    return run_omada_action("BACKUP", admin["id"])


@app.get("/api/omada/logs")
def omada_logs(admin=Depends(current_admin)):
    return fetch_all("SELECT id, action, status, progress_percent, current_step, output_text, created_at, completed_at FROM omada_install_logs ORDER BY created_at DESC LIMIT 50")


@app.get("/api/omada/api-settings")
def get_omada_api_settings(admin=Depends(current_admin)):
    return public_omada_api_settings()


@app.put("/api/omada/api-settings")
def save_omada_api_settings(payload: OmadaApiSettingsUpdate, admin=Depends(current_admin)):
    current = ensure_omada_api_settings()
    updates = {
        key: value for key, value in payload.model_dump(exclude_none=True).items()
        if key in {"controller_host", "https_port", "api_base_url", "verify_tls", "username", "controller_id"}
    }
    if updates.get("controller_host") and "api_base_url" not in updates:
        port = updates.get("https_port") or current["https_port"]
        updates["api_base_url"] = f"https://{updates['controller_host']}:{port}"
    if updates.get("https_port") and "api_base_url" not in updates:
        host = updates.get("controller_host") or current["controller_host"]
        updates["api_base_url"] = f"https://{host}:{updates['https_port']}"
    if payload.remember_credentials is False:
        updates["password_encrypted"] = None
    elif payload.password:
        updates["password_encrypted"] = encrypt_secret(payload.password)
    if not updates:
        return public_omada_api_settings(current)
    assignments = ", ".join([f"{key} = %s" for key in updates] + ["updated_at = now()"])
    params = list(updates.values()) + [current["id"]]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE omada_api_settings SET {assignments} WHERE id = %s", tuple(params))
    audit(admin["id"], "save_omada_api_settings", "omada_api_settings", str(current["id"]), {k: ("[secret]" if "password" in k else v) for k, v in updates.items()})
    return public_omada_api_settings()


@app.post("/api/omada/test-api-login")
def test_omada_api_login(admin=Depends(current_admin)):
    settings = ensure_omada_api_settings()
    try:
        _, client = omada_api_client_from_settings()
        result = client.test_login()
        controller_id = result.get("controller_id")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE omada_api_settings
                    SET controller_id = COALESCE(%s, controller_id),
                        last_login_success_at = now(),
                        last_login_error = NULL,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (controller_id, settings["id"]),
                )
        log_omada_automation(admin["id"], "TEST_API_LOGIN", "SUCCESS", {"base_url": settings["api_base_url"], "username": settings["username"]}, result.get("response_summary"))
        audit(admin["id"], "test_omada_api_login", "omada_api_settings", str(settings["id"]))
        return {"status": "SUCCESS", "message": "Omada API login succeeded.", "settings": public_omada_api_settings(), "details": sanitize_summary(result)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_api_settings SET last_login_error = %s, updated_at = now() WHERE id = %s", (str(exc), settings["id"]))
        log_omada_automation(admin["id"], "TEST_API_LOGIN", "FAILED", {"base_url": settings["api_base_url"], "username": settings["username"]}, response_summary, str(exc))
        audit(admin["id"], "test_omada_api_login_failed", "omada_api_settings", str(settings["id"]), {"error": str(exc)})
        raise HTTPException(status_code=400, detail=f"Omada API login failed: {exc}")


@app.post("/api/omada/detect-sites")
def detect_omada_sites(admin=Depends(current_admin)):
    settings = ensure_omada_api_settings()
    try:
        _, client = omada_api_client_from_settings()
        result = client.get_sites()
        sites = result.get("sites", [])
        if len(sites) == 1 and not settings.get("selected_site_id"):
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE omada_api_settings SET selected_site_id = %s, selected_site_name = %s, updated_at = now() WHERE id = %s",
                        (sites[0]["site_id"], sites[0]["site_name"], settings["id"]),
                    )
        log_omada_automation(admin["id"], "DETECT_SITES", "SUCCESS", {"base_url": settings["api_base_url"]}, result.get("response_summary"))
        audit(admin["id"], "detect_omada_sites", "omada_api_settings", str(settings["id"]), {"site_count": len(sites)})
        return {"status": "SUCCESS", "sites": sites, "settings": public_omada_api_settings(), "details": sanitize_summary(result)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        log_omada_automation(admin["id"], "DETECT_SITES", "FAILED", {"base_url": settings["api_base_url"]}, response_summary, str(exc))
        return {"status": "FAILED", "sites": [], "message": "Omada site detection failed. Use the manual fallback instructions.", "error": str(exc), "manual_fallback": manual_fallback_payload("STAGING")}


@app.put("/api/omada/select-site")
def select_omada_site(payload: OmadaSiteSelect, admin=Depends(current_admin)):
    settings = ensure_omada_api_settings()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE omada_api_settings SET selected_site_id = %s, selected_site_name = %s, updated_at = now() WHERE id = %s",
                (payload.site_id, payload.site_name, settings["id"]),
            )
    audit(admin["id"], "select_omada_site", "omada_api_settings", str(settings["id"]), payload.model_dump())
    return public_omada_api_settings()


@app.get("/api/omada/radius-profile-builder")
def get_radius_profile_builder(environment: str = "STAGING", admin=Depends(current_admin)):
    env = normalize_environment(environment)
    latest = fetch_one("SELECT * FROM omada_radius_profiles WHERE environment = %s ORDER BY created_at DESC LIMIT 1", (env,))
    secret = decrypt_secret(latest["shared_secret_encrypted"]) if latest else None
    defaults = radius_defaults(env, secret)
    if latest:
        defaults.update({
            "profile_name": latest["profile_name"],
            "radius_server_ip": latest["radius_server_ip"],
            "auth_port": latest["auth_port"],
            "accounting_port": latest["accounting_port"],
            "accounting_enabled": latest["accounting_enabled"],
            "interim_update_seconds": latest["interim_update_seconds"],
            "omada_profile_id": latest["omada_profile_id"],
            "status": latest["status"],
            "last_error": latest["last_error"],
        })
    return defaults


def manual_fallback_payload(environment: str, shared_secret: Optional[str] = None):
    defaults = radius_defaults(environment, shared_secret)
    return {
        **defaults,
        "create_radius_profile": {
            "profile_name": defaults["profile_name"],
            "authentication_server": defaults["radius_server_ip"],
            "authentication_port": defaults["auth_port"],
            "authentication_secret": defaults["shared_secret"],
            "accounting": "Enabled",
            "accounting_server": defaults["radius_server_ip"],
            "accounting_port": defaults["accounting_port"],
            "accounting_secret": defaults["shared_secret"],
            "interim_update": defaults["interim_update_seconds"],
        },
        "create_ssid": {
            "ssid": defaults["ssid_name"],
            "security": "WPA2-Enterprise",
            "radius_profile": defaults["profile_name"],
            "vlan": "Disabled for Phase 1E",
            "captive_portal": "Disabled for Phase 1E",
            "guest_network": "Disabled for Phase 1E",
        },
        "note": "For Phase 1E, use staging first. Do not configure production WiFi until staging real-device testing passes.",
    }


@app.get("/api/omada/manual-fallback-settings")
def manual_fallback_settings(environment: str = "STAGING", shared_secret: Optional[str] = None, admin=Depends(current_admin)):
    env = normalize_environment(environment)
    latest = fetch_one("SELECT shared_secret_encrypted FROM omada_radius_profiles WHERE environment = %s ORDER BY created_at DESC LIMIT 1", (env,))
    return manual_fallback_payload(env, shared_secret or (decrypt_secret(latest["shared_secret_encrypted"]) if latest else None))


@app.post("/api/omada/create-matching-nas")
def create_omada_matching_nas(payload: OmadaMatchingNasRequest, admin=Depends(current_admin)):
    env = normalize_environment(payload.environment)
    defaults = radius_defaults(env, payload.shared_secret)
    name = payload.name or f"Omada Controller {'Staging' if env == 'STAGING' else 'Production'}"
    shortname = payload.shortname or f"omada-{'staging' if env == 'STAGING' else 'production'}"
    secret = payload.shared_secret or defaults["shared_secret"]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO nas_clients(name, nas_ip, shortname, secret, type, notes)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (shortname) DO UPDATE
                SET name = EXCLUDED.name,
                    nas_ip = EXCLUDED.nas_ip,
                    secret = EXCLUDED.secret,
                    type = EXCLUDED.type,
                    notes = EXCLUDED.notes,
                    status = 'active',
                    updated_at = now()
                RETURNING id
                """,
                (name, payload.ip_address, shortname, secret, payload.type, "Created from Omada RADIUS Profile Automation."),
            )
            nas_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO nas(nasname, shortname, type, secret, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (shortname) DO UPDATE SET nasname = EXCLUDED.nasname, secret = EXCLUDED.secret, type = EXCLUDED.type, description = EXCLUDED.description
                """,
                (payload.ip_address, shortname, payload.type, secret, name),
            )
    log_omada_automation(admin["id"], "CREATE_MATCHING_NAS", "SUCCESS", {"environment": env, "ip_address": payload.ip_address, "shortname": shortname, "shared_secret": mask_secret(secret)}, {"nas_id": str(nas_id)})
    audit(admin["id"], "create_omada_matching_nas", "nas_client", str(nas_id), {"environment": env, "shortname": shortname, "ip_address": payload.ip_address})
    return {"id": nas_id, "environment": env, "name": name, "ip_address": payload.ip_address, "shortname": shortname, "secret": secret}


@app.post("/api/omada/create-radius-profile")
def create_omada_radius_profile(payload: OmadaRadiusProfileRequest, admin=Depends(current_admin)):
    env = normalize_environment(payload.environment)
    defaults = radius_defaults(env, payload.shared_secret)
    secret = payload.shared_secret or defaults["shared_secret"]
    profile = {
        "name": payload.profile_name or defaults["profile_name"],
        "radius_server_ip": payload.radius_server_ip,
        "auth_port": payload.auth_port or defaults["auth_port"],
        "accounting_port": payload.accounting_port or defaults["accounting_port"],
        "accounting_enabled": payload.accounting_enabled,
        "interim_update_seconds": payload.interim_update_seconds,
    }
    api_settings = ensure_omada_api_settings()
    site_id = api_settings.get("selected_site_id")
    row_id = None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO omada_radius_profiles(environment, profile_name, radius_server_ip, auth_port, accounting_port, shared_secret_encrypted, accounting_enabled, interim_update_seconds, omada_site_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (env, profile["name"], profile["radius_server_ip"], profile["auth_port"], profile["accounting_port"], encrypt_secret(secret), profile["accounting_enabled"], profile["interim_update_seconds"], site_id),
            )
            row_id = cur.fetchone()["id"]
    if not site_id:
        error = "Select an Omada site before creating a RADIUS profile."
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_radius_profiles SET status = 'FAILED', last_error = %s, updated_at = now() WHERE id = %s", (error, row_id))
        log_omada_automation(admin["id"], "CREATE_RADIUS_PROFILE", "FAILED", {**profile, "shared_secret": mask_secret(secret)}, {}, error)
        return {"status": "FAILED", "message": "Omada API could not create the RADIUS profile automatically. Use the manual fallback settings below.", "error": error, "manual_fallback": manual_fallback_payload(env, secret)}
    omada_payload = {
        "name": profile["name"],
        "wirelessVlanAssignment": False,
        "authServer": [
            {
                "radiusServerIp": profile["radius_server_ip"],
                "radiusPort": profile["auth_port"],
                "radiusPwd": secret,
            }
        ],
        "radiusAccountingEnable": profile["accounting_enabled"],
        "interimUpdateEnable": profile["accounting_enabled"],
        "interimUpdateInterval": profile["interim_update_seconds"],
        "acctServer": [
            {
                "accountingServerIp": profile["radius_server_ip"],
                "accountingServerPort": profile["accounting_port"],
                "accountingServerPwd": secret,
            }
        ],
    }
    try:
        _, client = omada_api_client_from_settings()
        result = client.create_radius_profile(site_id, omada_payload)
        profile_id = result.get("profile_id")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_radius_profiles SET status = 'CREATED', omada_profile_id = %s, updated_at = now() WHERE id = %s", (profile_id, row_id))
        log_omada_automation(admin["id"], "CREATE_RADIUS_PROFILE", "SUCCESS", {**profile, "shared_secret": mask_secret(secret), "site_id": site_id}, result.get("response_summary"))
        audit(admin["id"], "create_omada_radius_profile", "omada_radius_profile", str(row_id), {"environment": env, "site_id": site_id})
        return {"status": "SUCCESS", "message": "Omada RADIUS Profile created successfully.", "profile_id": row_id, "omada_profile_id": profile_id, "manual_fallback": manual_fallback_payload(env, secret)}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_radius_profiles SET status = 'FAILED', last_error = %s, updated_at = now() WHERE id = %s", (str(exc), row_id))
        log_omada_automation(admin["id"], "CREATE_RADIUS_PROFILE", "FAILED", {**profile, "shared_secret": mask_secret(secret), "site_id": site_id}, response_summary, str(exc))
        return {"status": "FAILED", "message": "Omada API could not create the RADIUS profile automatically. Use the manual fallback settings below.", "error": str(exc), "profile_id": row_id, "manual_fallback": manual_fallback_payload(env, secret)}


@app.post("/api/omada/create-test-ssid")
def create_omada_test_ssid(payload: OmadaTestSsidRequest, admin=Depends(current_admin)):
    env = normalize_environment(payload.environment)
    api_settings = ensure_omada_api_settings()
    site_id = api_settings.get("selected_site_id")
    profile = fetch_one(
        "SELECT * FROM omada_radius_profiles WHERE environment = %s AND status = 'CREATED' ORDER BY created_at DESC LIMIT 1",
        (env,),
    )
    if payload.radius_profile_id:
        profile = fetch_one("SELECT * FROM omada_radius_profiles WHERE id = %s", (payload.radius_profile_id,))
    row_id = None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO omada_test_ssids(environment, ssid_name, security_type, omada_site_id, radius_profile_id)
                VALUES (%s, %s, 'WPA2-Enterprise', %s, %s)
                RETURNING id
                """,
                (env, payload.ssid_name, site_id, profile["id"] if profile else None),
            )
            row_id = cur.fetchone()["id"]
    if not site_id or not profile:
        error = "Select an Omada site and create the Omada RADIUS profile before creating the test SSID."
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_test_ssids SET status = 'FAILED', last_error = %s, updated_at = now() WHERE id = %s", (error, row_id))
        log_omada_automation(admin["id"], "CREATE_TEST_SSID", "FAILED", {"environment": env, "ssid": payload.ssid_name}, {}, error)
        return {"status": "FAILED", "message": "Omada API could not create the test SSID automatically. Use the manual fallback settings below.", "error": error, "manual_fallback": manual_fallback_payload(env)}
    if not profile.get("omada_profile_id"):
        error = "The selected RADIUS profile does not have an Omada profile ID. Create the Omada RADIUS profile first."
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_test_ssids SET status = 'FAILED', last_error = %s, updated_at = now() WHERE id = %s", (error, row_id))
        log_omada_automation(admin["id"], "CREATE_TEST_SSID", "FAILED", {"environment": env, "ssid": payload.ssid_name, "site_id": site_id}, {}, error)
        return {"status": "FAILED", "message": "Omada API could not create the test SSID automatically. Use the manual fallback settings below.", "error": error, "manual_fallback": manual_fallback_payload(env, decrypt_secret(profile["shared_secret_encrypted"]))}
    omada_payload = {
        "name": payload.ssid_name,
        "band": 3,
        "security": 2,
        "guestNetEnable": False,
        "portalEnable": False,
        "accessEnable": False,
        "vlanEnable": False,
        "vlanId": 1,
        "greEnable": False,
        "broadcast": True,
        "macFilterEnable": False,
        "wlanScheduleEnable": False,
        "rateLimit": {
            "downLimitEnable": False,
            "upLimitEnable": False,
        },
        "wpaSetting": {
            "versionEnt": 2,
            "encryptionEnt": 3,
            "gikRekeyEnable": False,
            "rekeyInterval": 0,
            "intervalType": 0,
            "radiusProfileId": profile.get("omada_profile_id"),
        },
        "rateAndBeaconCtrl": {
            "rate2gCtrlEnable": False,
            "rate5gCtrlEnable": False,
            "rate6gCtrlEnable": False,
        },
    }
    try:
        _, client = omada_api_client_from_settings()
        result = client.create_wpa_enterprise_ssid(site_id, omada_payload)
        wlan_id = result.get("wlan_id")
        ssid_id = result.get("ssid_id")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_test_ssids SET status = 'CREATED', omada_wlan_id = %s, updated_at = now() WHERE id = %s", (wlan_id, row_id))
        log_omada_automation(admin["id"], "CREATE_TEST_SSID", "SUCCESS", {"environment": env, "ssid": payload.ssid_name, "site_id": site_id, "radius_profile_id": str(profile["id"])}, result.get("response_summary"))
        audit(admin["id"], "create_omada_test_ssid", "omada_test_ssid", str(row_id), {"environment": env, "site_id": site_id})
        return {"status": "SUCCESS", "message": "Test WPA2-Enterprise SSID created successfully.", "ssid_id": row_id, "omada_ssid_id": ssid_id, "omada_wlan_id": wlan_id, "manual_fallback": manual_fallback_payload(env, decrypt_secret(profile["shared_secret_encrypted"]))}
    except Exception as exc:
        response_summary = exc.response_summary if isinstance(exc, OmadaApiError) else {}
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE omada_test_ssids SET status = 'FAILED', last_error = %s, updated_at = now() WHERE id = %s", (str(exc), row_id))
        log_omada_automation(admin["id"], "CREATE_TEST_SSID", "FAILED", {"environment": env, "ssid": payload.ssid_name, "site_id": site_id}, response_summary, str(exc))
        return {"status": "FAILED", "message": "Omada API could not create the test SSID automatically. Use the manual fallback settings below.", "error": str(exc), "manual_fallback": manual_fallback_payload(env, decrypt_secret(profile["shared_secret_encrypted"]))}


@app.get("/api/omada/automation-logs")
def omada_automation_logs(admin=Depends(current_admin)):
    return fetch_all("SELECT id, action, status, request_summary, response_summary, error_message, created_at FROM omada_automation_logs ORDER BY created_at DESC LIMIT 50")


@app.post("/api/omada/create-test-nas")
def omada_create_test_nas(payload: OmadaNasCreate, admin=Depends(current_admin)):
    nas_payload = NasCreate(
        name=payload.name,
        nas_ip=payload.ip_address,
        shortname=payload.shortname,
        secret=payload.secret or secrets.token_urlsafe(24),
        type=payload.type,
        notes="Created from Omada Controller setup page for Phase 1D real AP/RADIUS testing.",
    )
    created = create_nas(nas_payload, admin)
    audit(admin["id"], "create_omada_test_nas_client", "nas_client", str(created["id"]), {"shortname": payload.shortname, "ip_address": payload.ip_address})
    return {
        **created,
        "radius_staging": {"server": "192.168.50.70", "auth_port": 11812, "accounting_port": 11813, "secret": created["secret"]},
        "radius_production": {"server": "192.168.50.70", "auth_port": 1812, "accounting_port": 1813, "secret": created["secret"]},
    }


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
        "general": {
            "country_region": "Philippines",
            "time_zone": "Asia/Manila",
            **value.get("general", {}),
        },
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
        "general": {**current.get("general", {}), **(payload.general or {})},
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


def raise_ai_feature_removed():
    raise HTTPException(
        status_code=410,
        detail="AI/OpenAI features were removed from the active workflow. Use the MikroTik Preflight Scanner for read-only validation data and MikroTik Configuration for manual setup.",
    )


@app.get("/api/system-settings/openai")
def get_openai_settings(admin=Depends(current_admin)):
    raise_ai_feature_removed()
    return public_openai_settings()


@app.patch("/api/system-settings/openai")
def update_openai_settings(payload: OpenAISettingsPayload, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    store = openai_store()
    data = payload.model_dump(exclude_unset=True)
    if data.get("clear_api_key"):
        store.pop("api_key_encrypted", None)
    elif "api_key" in data:
        api_key = normalize_openai_text(data.get("api_key"))
        if api_key:
            if not api_key.startswith("sk-"):
                raise HTTPException(status_code=400, detail="OpenAI API key should start with sk-")
            store["api_key_encrypted"] = encrypt_secret(api_key)

    model_id = normalize_openai_model(store.get("selected_model"))
    if data.get("selected_model") is not None:
        model_id = normalize_openai_model(data.get("selected_model"))
        store["selected_model"] = model_id
    if data.get("reasoning_effort") is not None:
        store["reasoning_effort"] = normalize_openai_reasoning_effort(model_id, data.get("reasoning_effort"), strict=True)
    else:
        store["reasoning_effort"] = normalize_openai_reasoning_effort(model_id, store.get("reasoning_effort"))
    if "organization_id" in data:
        store["organization_id"] = normalize_openai_text(data.get("organization_id"))
    if "project_id" in data:
        store["project_id"] = normalize_openai_text(data.get("project_id"))

    save_openai_store(store)
    audit(
        admin["id"],
        "system_openai_settings_updated",
        "system_openai",
        "openai",
        {
            "selected_model": store.get("selected_model"),
            "reasoning_effort": store.get("reasoning_effort"),
            "api_key_configured": bool(store.get("api_key_encrypted")),
            "organization_id_configured": bool(normalize_openai_text(store.get("organization_id"))),
            "project_id_configured": bool(normalize_openai_text(store.get("project_id"))),
        },
    )
    return public_openai_settings()


@app.post("/api/system-settings/openai/test")
def test_openai_settings(payload: OpenAITestPayload, admin=Depends(current_admin)):
    raise_ai_feature_removed()
    store = openai_store()
    api_key = decrypt_secret(store.get("api_key_encrypted"))
    if not normalize_openai_text(api_key):
        raise HTTPException(status_code=400, detail="Save an OpenAI API key before running a test")

    model_id = normalize_openai_model(payload.model_id or store.get("selected_model"))
    reasoning_effort = normalize_openai_reasoning_effort(
        model_id,
        payload.reasoning_effort or store.get("reasoning_effort"),
        strict=True,
    )
    prompt = normalize_openai_text(payload.prompt)
    if not prompt:
        raise HTTPException(status_code=400, detail="Test prompt is required")

    request_body = {
        "model": model_id,
        "reasoning": {"effort": reasoning_effort},
        "input": prompt,
        "max_output_tokens": payload.max_output_tokens,
    }
    request_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "3JCentralPisowifi/0.1 system-settings-openai-test",
    }
    organization_id = normalize_openai_text(store.get("organization_id"))
    project_id = normalize_openai_text(store.get("project_id"))
    if organization_id:
        request_headers["OpenAI-Organization"] = organization_id
    if project_id:
        request_headers["OpenAI-Project"] = project_id

    started_at = time.perf_counter()
    try:
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers=request_headers,
            json=request_body,
            timeout=45,
        )
        response_data = response.json() if response.content else {}
        if response.status_code >= 400:
            message = response_data.get("error", {}).get("message") if isinstance(response_data, dict) else None
            raise HTTPException(status_code=400, detail=f"OpenAI test failed: {message or response.text or response.status_code}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"OpenAI test failed: {exc}") from exc

    latency_ms = int(round((time.perf_counter() - started_at) * 1000))
    output_text = extract_openai_response_text(response_data if isinstance(response_data, dict) else {})
    audit(
        admin["id"],
        "system_openai_tested",
        "system_openai",
        model_id,
        {"model": model_id, "reasoning_effort": reasoning_effort, "latency_ms": latency_ms, "usage": sanitize_summary(response_data.get("usage") if isinstance(response_data, dict) else {})},
    )
    return {
        "status": "ok",
        "model": model_id,
        "reasoning_effort": reasoning_effort,
        "latency_ms": latency_ms,
        "response_id": response_data.get("id") if isinstance(response_data, dict) else None,
        "output_text": output_text,
        "usage": response_data.get("usage") if isinstance(response_data, dict) else None,
    }


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
