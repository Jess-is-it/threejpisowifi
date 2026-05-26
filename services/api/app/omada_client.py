import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, urlparse

import requests
from requests import Session
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class OmadaApiError(RuntimeError):
    def __init__(self, message: str, response_summary: Optional[dict] = None):
        super().__init__(message)
        self.response_summary = response_summary or {}


OMADA_SITE_SCENARIO_TYPES = {
    "office": 0,
    "hotel": 1,
    "restaurant": 2,
    "store": 2,
    "retail": 2,
    "school": 3,
    "campus": 3,
    "community": 4,
    "apartment": 4,
    "home": 5,
    "airport": 0,
    "dormitory": 0,
    "factory": 0,
    "hospital": 0,
    "shopping mall": 0,
    "other": 0,
}


def omada_site_scenario_type(scenario: Optional[str]) -> int:
    return OMADA_SITE_SCENARIO_TYPES.get(str(scenario or "Office").strip().lower(), 0)


def omada_site_scenario_name(site: dict) -> Optional[str]:
    value = (
        site.get("scenario")
        or site.get("applicationScenario")
        or site.get("applicationScenarioName")
        or site.get("scenarioName")
    )
    if value:
        return str(value)
    if site.get("type") == 0:
        return "Office"
    return None


def omada_mac_variants(mac: Optional[str]) -> list[str]:
    original = str(mac or "").strip()
    clean = re.sub(r"[^A-Fa-f0-9]", "", original).upper()
    variants = []
    for value in [
        original,
        clean,
        ":".join(clean[i:i + 2] for i in range(0, 12, 2)) if len(clean) == 12 else "",
        "-".join(clean[i:i + 2] for i in range(0, 12, 2)) if len(clean) == 12 else "",
    ]:
        value = str(value or "").strip()
        if value and value not in variants:
            variants.append(value)
    return variants


@dataclass
class OmadaLoginResult:
    controller_id: Optional[str]
    token: Optional[str]
    response_summary: dict


def summarize_response(response: requests.Response) -> dict:
    body: Any
    try:
        body = response.json()
    except Exception:
        body = response.text[:1000]
    return {
        "status_code": response.status_code,
        "url": response.url,
        "body": body,
    }


def _extract_controller_id(text: str) -> Optional[str]:
    patterns = [
        r"omadacId[\"']?\s*[:=]\s*[\"']([a-fA-F0-9]{16,64})[\"']",
        r"controllerId[\"']?\s*[:=]\s*[\"']([a-fA-F0-9]{16,64})[\"']",
        r"/([a-fA-F0-9]{16,64})/api/",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


class OmadaApiClient:
    """
    Small adapter around Omada SDN controller API variants.

    Omada controller endpoints vary by version. This adapter keeps endpoint
    guesses in one place and returns structured failures when a version rejects
    automation, so the application can show manual fallback values.
    """

    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = False, controller_id: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.controller_id = controller_id
        self.session: Session = requests.Session()
        self.session.verify = verify_tls
        self.token: Optional[str] = None

    def discover_controller_id(self) -> Optional[str]:
        if self.controller_id:
            return self.controller_id
        try:
            response = self.session.get(f"{self.base_url}/", timeout=15)
        except requests.RequestException:
            return None
        self.controller_id = _extract_controller_id(response.text)
        return self.controller_id

    def _candidate_paths(self, suffix: str) -> list[str]:
        controller_id = self.discover_controller_id()
        paths = []
        if controller_id:
            paths.extend([
                f"/{controller_id}/api/v2/{suffix}",
                f"/{controller_id}/api/v1/{suffix}",
            ])
        paths.extend([
            f"/api/v2/{suffix}",
            f"/api/v1/{suffix}",
        ])
        return paths

    def _post_json_candidates(self, paths: list[str], payload: dict, timeout: int = 20) -> tuple[requests.Response, dict]:
        last_summary = {}
        first_api_rejection = None
        for path in paths:
            try:
                response = self.session.post(f"{self.base_url}{path}", json=payload, timeout=timeout)
            except requests.RequestException as exc:
                last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                continue
            last_summary = summarize_response(response)
            if response.status_code < 400:
                try:
                    body = response.json()
                    if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                        if body.get("errorCode") != -1600 and first_api_rejection is None:
                            first_api_rejection = last_summary
                        continue
                except Exception:
                    pass
                return response, last_summary
        raise OmadaApiError("Omada API rejected all known endpoint paths.", first_api_rejection or last_summary)

    def _put_json_candidates(self, paths: list[str], payload: dict, timeout: int = 20) -> tuple[requests.Response, dict]:
        last_summary = {}
        first_api_rejection = None
        for path in paths:
            try:
                response = self.session.put(f"{self.base_url}{path}", json=payload, timeout=timeout)
            except requests.RequestException as exc:
                last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                continue
            last_summary = summarize_response(response)
            if response.status_code < 400:
                try:
                    body = response.json()
                    if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                        if body.get("errorCode") != -1600 and first_api_rejection is None:
                            first_api_rejection = last_summary
                        continue
                except Exception:
                    pass
                return response, last_summary
        raise OmadaApiError("Omada API rejected all known endpoint paths.", first_api_rejection or last_summary)

    def _patch_json_candidates(self, paths: list[str], payload: dict, timeout: int = 20) -> tuple[requests.Response, dict]:
        last_summary = {}
        first_api_rejection = None
        for path in paths:
            try:
                response = self.session.patch(f"{self.base_url}{path}", json=payload, timeout=timeout)
            except requests.RequestException as exc:
                last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                continue
            last_summary = summarize_response(response)
            if response.status_code < 400:
                try:
                    body = response.json()
                    if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                        if body.get("errorCode") != -1600 and first_api_rejection is None:
                            first_api_rejection = last_summary
                        continue
                except Exception:
                    pass
                return response, last_summary
        raise OmadaApiError("Omada API rejected all known endpoint paths.", first_api_rejection or last_summary)

    def _get_json_candidates(self, paths: list[str], timeout: int = 20) -> tuple[Any, dict]:
        last_summary = {}
        for path in paths:
            try:
                response = self.session.get(f"{self.base_url}{path}", timeout=timeout)
            except requests.RequestException as exc:
                last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                continue
            last_summary = summarize_response(response)
            if response.status_code < 400:
                try:
                    body = response.json()
                    if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                        continue
                    return body, last_summary
                except Exception:
                    return response.text, last_summary
        raise OmadaApiError("Omada API rejected all known endpoint paths.", last_summary)

    def login(self) -> OmadaLoginResult:
        payload = {"username": self.username, "password": self.password}
        paths = self._candidate_paths("login")
        response, summary = self._post_json_candidates(paths, payload)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        result = data.get("result") if isinstance(data, dict) else {}
        self.token = (
            data.get("token") if isinstance(data, dict) else None
        ) or (
            result.get("token") if isinstance(result, dict) else None
        ) or (
            result.get("csrfToken") if isinstance(result, dict) else None
        )
        if self.token:
            self.session.headers.update({"Csrf-Token": self.token, "Authorization": f"AccessToken={self.token}"})
        if isinstance(result, dict):
            self.controller_id = self.controller_id or result.get("omadacId") or result.get("controllerId")
        return OmadaLoginResult(controller_id=self.controller_id, token=self.token, response_summary=summary)

    def hotspot_login(self) -> OmadaLoginResult:
        if not self.controller_id:
            self.discover_controller_id()
        paths = []
        if self.controller_id:
            paths.append(f"/{self.controller_id}/api/v2/hotspot/login")
        paths.append("/api/v2/hotspot/login")
        payloads = [
            {"name": self.username, "password": self.password},
            {"username": self.username, "password": self.password},
        ]
        last_error = None
        for payload in payloads:
            try:
                response, summary = self._post_json_candidates(paths, payload)
            except OmadaApiError as exc:
                last_error = exc
                continue
            data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            result = data.get("result") if isinstance(data, dict) else {}
            self.token = (
                data.get("token") if isinstance(data, dict) else None
            ) or (
                result.get("token") if isinstance(result, dict) else None
            ) or (
                result.get("csrfToken") if isinstance(result, dict) else None
            )
            if self.token:
                self.session.headers.update({"Csrf-Token": self.token, "Authorization": f"AccessToken={self.token}"})
            if isinstance(result, dict):
                self.controller_id = self.controller_id or result.get("omadacId") or result.get("controllerId")
            return OmadaLoginResult(controller_id=self.controller_id, token=self.token, response_summary=summary)
        raise last_error or OmadaApiError("Omada hotspot login failed.")

    def test_login(self) -> dict:
        login = self.login()
        return {"ok": True, "controller_id": login.controller_id, "response_summary": login.response_summary}

    def get_sites(self) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        paths = []
        if controller_id:
            paths.extend([
                f"/{controller_id}/api/v2/user/sites?currentPage=1&currentPageSize=100",
                f"/{controller_id}/api/v2/sites?currentPage=1&currentPageSize=100",
                f"/{controller_id}/api/v2/user/sites",
            ])
        paths.extend(self._candidate_paths("sites"))
        payload, summary = self._get_json_candidates(paths)
        sites = []
        data = payload
        if isinstance(payload, dict):
            data = payload.get("result", payload.get("data", payload))
        if isinstance(data, dict):
            data = data.get("data", data.get("sites", data.get("list", [])))
        if isinstance(data, list):
            for site in data:
                if not isinstance(site, dict):
                    continue
                site_id = site.get("siteId") or site.get("id") or site.get("key")
                site_name = site.get("name") or site.get("siteName") or site.get("label") or "Unnamed Site"
                sites.append({
                    "site_id": site_id,
                    "site_name": site_name,
                    "is_default": bool(site.get("isDefault") or site.get("default")),
                    "application_scenario": omada_site_scenario_name(site),
                    "site_type": site.get("type"),
                })
        return {"sites": sites, "response_summary": summary}

    def get_site_ap_summary(self, site_id: str) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        paths = [
            f"/{controller_id}/api/v2/sites/{site_id}/devices?currentPage=1&currentPageSize=1000",
            f"/{controller_id}/api/v2/sites/{site_id}/devices",
        ]
        payload, summary = self._get_json_candidates(paths, timeout=20)
        data = payload
        if isinstance(payload, dict):
            data = payload.get("result", payload.get("data", payload))
        if isinstance(data, dict):
            data = data.get("data", data.get("devices", data.get("list", data.get("rows", []))))
        ap_rows = []
        if isinstance(data, list):
            ap_rows = [item for item in data if isinstance(item, dict) and str(item.get("type") or "").lower() == "ap"]
        connected = []
        for item in ap_rows:
            normalized = self._normalize_ap(item, site_id=site_id)
            status_text = str(normalized.get("status") or "").lower()
            status_code = normalized.get("status_code")
            if status_code in (10, 11, 12, 13, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33):
                continue
            if status_text in {"connected", "online", "normal"} or status_code in (14, 15, 16, 17):
                connected.append(item)
                continue
            if (
                (item.get("ip") or item.get("publicIp"))
                and item.get("site")
                and str(item.get("site")).upper() != "PENDING-SITE"
                and item.get("statusCategory") == 1
                and (
                    item.get("uptime")
                    or item.get("uptimeLong")
                    or item.get("wp2g")
                    or item.get("radio2g")
                    or item.get("radioSetting2g")
                    or item.get("wp5g")
                    or item.get("radio5g")
                    or item.get("radioSetting5g")
                    or int(item.get("clientNum") or 0) > 0
                )
            ):
                connected.append(item)
        return {
            "ap_total_count": len(ap_rows),
            "ap_connected_count": len(connected),
            "response_summary": summary,
        }

    def _extract_result_rows(self, payload: Any) -> list[dict]:
        data = payload
        if isinstance(payload, dict):
            data = payload.get("result", payload.get("data", payload))
        if isinstance(data, dict):
            data = data.get("data", data.get("devices", data.get("list", data.get("rows", []))))
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    def _ap_name_from_mac(self, mac: Optional[str]) -> str:
        normalized = re.sub(r"[^A-Fa-f0-9]", "", mac or "").upper()
        if len(normalized) >= 6:
            return f"AP-{normalized[-6:]}"
        return "AP-UNKNOWN"

    def _normalize_ap(self, item: dict, site_id: Optional[str] = None, site_name: Optional[str] = None, adoptable: bool = False) -> dict:
        status_value = item.get("status")
        status_category = item.get("statusCategory")
        mac = item.get("mac")
        generated_name = self._ap_name_from_mac(mac)
        raw_name = item.get("customName") or item.get("name")
        display_name = raw_name if raw_name and str(raw_name).strip().upper() != str(mac or "").strip().upper() else generated_name
        status_text = (
            item.get("statusText")
            or item.get("state")
            or item.get("connectStatus")
            or ("Configuring" if status_value in (10, 11, 12, 13) else None)
            or ("Connected" if status_value in (14, 15, 16, 17) else None)
            or ("Pending" if status_value in (20, 21) or status_category == 0 else None)
            or ("Adopting" if status_value in (22, 23) else None)
            or ("Adopt Failed" if status_value in (24, 25) or status_category == 4 else None)
            or ("Managed by Others" if status_value in (26, 27) or status_category == 3 else None)
            or ("Disconnected" if status_value in (0, 1, 30, 31, 32, 33) or status_category == 5 else None)
            or str(status_value or "Unknown")
        )
        return {
            "mac": mac,
            "name": display_name,
            "mac_bound_name": generated_name,
            "model": item.get("showModel") or item.get("compoundModel") or item.get("model"),
            "model_version": item.get("modelVersion") or item.get("hwVersion"),
            "firmware_version": item.get("firmwareVersion") or item.get("version"),
            "ip": item.get("ip") or item.get("publicIp"),
            "site_id": item.get("site") or site_id,
            "site_name": item.get("siteName") or site_name,
            "status": status_text,
            "status_code": status_value,
            "status_category": status_category,
            "client_count": item.get("clientNum"),
            "client_count_2g": item.get("clientNum2g"),
            "client_count_5g": item.get("clientNum5g"),
            "client_count_5g2": item.get("clientNum5g2"),
            "client_count_6g": item.get("clientNum6g"),
            "cpu_util": item.get("cpuUtil"),
            "mem_util": item.get("memUtil"),
            "download": item.get("download"),
            "upload": item.get("upload"),
            "tx_rate": item.get("txRate"),
            "rx_rate": item.get("rxRate"),
            "uptime_seconds": item.get("uptimeLong"),
            "radio_2g": item.get("wp2g") or item.get("radio2g") or item.get("radioSetting2g"),
            "radio_5g": item.get("wp5g") or item.get("radio5g") or item.get("radioSetting5g"),
            "radio_5g2": item.get("wp5g2") or item.get("radio5g2") or item.get("radioSetting5g2"),
            "radio_6g": item.get("wp6g") or item.get("radio6g") or item.get("radioSetting6g"),
            "uptime": item.get("uptime"),
            "last_seen": item.get("lastSeen"),
            "serial_number": item.get("sn"),
            "adoptable": bool(adoptable),
            "adopt_fail_type": item.get("adoptFailType"),
            "device_series_type": item.get("deviceSeriesType"),
        }

    def get_site_aps(self, site_id: str, site_name: Optional[str] = None) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        paths = [
            f"/{controller_id}/api/v2/sites/{site_id}/grid/devices?currentPage=1&currentPageSize=1000",
            f"/{controller_id}/api/v2/sites/{site_id}/devices?currentPage=1&currentPageSize=1000",
            f"/{controller_id}/api/v2/sites/{site_id}/devices",
        ]
        payload, summary = self._get_json_candidates(paths, timeout=20)
        aps = [
            self._normalize_ap(item, site_id=site_id, site_name=site_name)
            for item in self._extract_result_rows(payload)
            if str(item.get("type") or "").lower() == "ap"
        ]
        return {"aps": aps, "response_summary": summary}

    def detect_adoptable_aps(self, site_id: Optional[str] = None) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        paths = [
            f"/{controller_id}/api/v2/grid/devices/pending?currentPage=1&currentPageSize=1000",
            f"/{controller_id}/api/v2/devices/pending?currentPage=1&currentPageSize=1000",
        ]
        if site_id:
            paths.insert(0, f"/{controller_id}/api/v2/sites/{site_id}/grid/devices/pending?currentPage=1&currentPageSize=1000")
        payload, summary = self._get_json_candidates(paths, timeout=20)
        aps = []
        for item in self._extract_result_rows(payload):
            if str(item.get("type") or "").lower() != "ap":
                continue
            status_value = item.get("status")
            status_category = item.get("statusCategory")
            adoptable = status_value in (20, 21, 24, 25, 26, 27) or status_category in (0, 3, 4)
            aps.append(self._normalize_ap(item, site_id=item.get("site") or site_id, site_name=item.get("siteName"), adoptable=adoptable))
        return {"aps": aps, "response_summary": summary}

    def adopt_aps_if_supported(self, site_id: str, ap_macs: list[str], username: Optional[str] = None, password: Optional[str] = None) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        macs = [mac for mac in ap_macs if mac]
        if not macs:
            raise OmadaApiError("Select at least one AP to add.")
        payload = {"macs": macs}
        username = (username or "").strip()
        password = password or ""
        if username:
            payload["username"] = username
        if password:
            payload["password"] = password
        paths = [
            f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/batchAdopt",
            f"/{controller_id}/api/v2/cmd/devices/batchAdopt",
            f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/adopt",
            f"/api/v2/sites/{site_id}/cmd/devices/batchAdopt",
            f"/api/v2/cmd/devices/batchAdopt",
        ]
        response, summary = self._post_json_candidates(paths, payload, timeout=600)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        return {
            "status": "SUCCESS",
            "message": "Omada AP adoption was submitted.",
            "ap_macs": macs,
            "response_summary": summary,
            "result": data.get("result") if isinstance(data, dict) else data,
        }

    def configure_ap_device_account_if_supported(self, site_id: str, mac: str, username: str, password: str) -> dict:
        return {
            "configured": False,
            "skipped": True,
            "message": "AP device-account automation is disabled. Adoption credentials are only passed transiently to Omada adopt requests.",
        }

    def configure_ap_management_vlan_if_supported(self, site_id: str, mac: str, vlan_id: int) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        vlan_id = int(vlan_id)
        if vlan_id < 1 or vlan_id > 4094:
            raise OmadaApiError("AP management VLAN must be between 1 and 4094.")
        network_ref = self._ap_management_vlan_network_ref(site_id, vlan_id)
        single_payload = {
            "mvlanSetting": {
                "mode": 1,
                "lanNetworkId": network_ref["lan_network_id"],
            },
        }
        if network_ref.get("bridge_vlan") is not None:
            single_payload["mvlanSetting"]["bridgeVlan"] = network_ref["bridge_vlan"]
        single_paths = [
            f"/{controller_id}/api/v2/sites/{site_id}/eaps/{mac}/config/services",
            f"/{controller_id}/api/v1/sites/{site_id}/eaps/{mac}/config/services",
            f"/api/v2/sites/{site_id}/eaps/{mac}/config/services",
            f"/api/v1/sites/{site_id}/eaps/{mac}/config/services",
        ]
        try:
            response, summary = self._put_json_candidates(single_paths, single_payload, timeout=45)
            data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            return {
                "configured": True,
                "mac": mac,
                "vlan_id": vlan_id,
                "lan_network_id": network_ref["lan_network_id"],
                "lan_network_name": network_ref.get("lan_network_name"),
                "lan_network_created": bool(network_ref.get("created")),
                "lan_network_response_summary": network_ref.get("response_summary"),
                "bridge_vlan": network_ref.get("bridge_vlan"),
                "response_summary": summary,
                "result": data.get("result") if isinstance(data, dict) else data,
            }
        except OmadaApiError as single_exc:
            single_summary = single_exc.response_summary

        encoded_mac = quote(mac or "", safe="")
        services_payload = {
            "apMacList": [mac],
            "mvlanSetting": single_payload["mvlanSetting"],
        }
        service_paths = [
            f"/{controller_id}/api/v2/sites/{site_id}/cmd/eaps/config/services",
            f"/{controller_id}/api/v1/sites/{site_id}/cmd/eaps/config/services",
            f"/api/v2/sites/{site_id}/cmd/eaps/config/services",
            f"/api/v1/sites/{site_id}/cmd/eaps/config/services",
        ]
        try:
            response, summary = self._put_json_candidates(service_paths, services_payload, timeout=45)
            data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            return {
                "configured": True,
                "mac": mac,
                "vlan_id": vlan_id,
                "lan_network_id": network_ref["lan_network_id"],
                "lan_network_name": network_ref.get("lan_network_name"),
                "lan_network_created": bool(network_ref.get("created")),
                "lan_network_response_summary": network_ref.get("response_summary"),
                "bridge_vlan": network_ref.get("bridge_vlan"),
                "response_summary": summary,
                "result": data.get("result") if isinstance(data, dict) else data,
            }
        except OmadaApiError as service_exc:
            service_summary = {
                "single_ap_response": single_summary,
                "batch_response": service_exc.response_summary,
            }

        payloads = [
            {"mac": mac, "mgmtVlanEnable": True, "mgmtVlanId": vlan_id},
            {"macs": [mac], "mgmtVlanEnable": True, "mgmtVlanId": vlan_id},
            {"mac": mac, "managementVlanEnable": True, "managementVlanId": vlan_id},
            {"macs": [mac], "managementVlanEnable": True, "managementVlanId": vlan_id},
            {"deviceMac": mac, "managementVlan": {"enable": True, "id": vlan_id}},
            {"deviceMacs": [mac], "managementVlan": {"enable": True, "id": vlan_id}},
            {"mac": mac, "managementVlan": {"enabled": True, "vlanId": vlan_id}},
            {"macs": [mac], "managementVlan": {"enabled": True, "vlanId": vlan_id}},
            {"mac": mac, "deviceConfig": {"managementVlanEnable": True, "managementVlanId": vlan_id}},
            {"macs": [mac], "deviceConfig": {"managementVlanEnable": True, "managementVlanId": vlan_id}},
        ]
        paths = [
            ("POST", f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/configManagementVlan"),
            ("POST", f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/setManagementVlan"),
            ("POST", f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/mgmtVlan"),
            ("POST", f"/{controller_id}/api/v2/cmd/devices/configManagementVlan"),
            ("POST", f"/{controller_id}/api/v2/cmd/devices/setManagementVlan"),
            ("PUT", f"/{controller_id}/api/v2/sites/{site_id}/devices/{encoded_mac}/config"),
            ("PUT", f"/{controller_id}/api/v2/sites/{site_id}/setting/devices/{encoded_mac}"),
            ("PUT", f"/{controller_id}/api/v2/sites/{site_id}/setting/devices/{encoded_mac}/config"),
            ("PUT", f"/{controller_id}/api/v2/sites/{site_id}/setting/managementVlan"),
            ("PUT", f"/{controller_id}/api/v2/sites/{site_id}/setting/mgmtVlan"),
        ]
        last_summary = service_summary
        first_api_rejection = None
        for payload in payloads:
            for method, path in paths:
                try:
                    if method == "PUT":
                        response = self.session.put(f"{self.base_url}{path}", json=payload, timeout=30)
                    else:
                        response = self.session.post(f"{self.base_url}{path}", json=payload, timeout=30)
                except requests.RequestException as exc:
                    last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                    continue
                last_summary = summarize_response(response)
                if response.status_code < 400:
                    try:
                        body = response.json()
                        if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                            if body.get("errorCode") != -1600 and first_api_rejection is None:
                                first_api_rejection = last_summary
                            continue
                    except Exception:
                        body = {}
                    return {
                        "configured": True,
                        "mac": mac,
                        "vlan_id": vlan_id,
                        "response_summary": last_summary,
                        "result": body.get("result") if isinstance(body, dict) else body,
                    }
        raise OmadaApiError("Omada API could not configure AP management VLAN using known endpoint paths.", first_api_rejection or last_summary)

    def _lan_networks_split(self, site_id: str) -> tuple[list[dict], dict]:
        if not self.controller_id:
            self.discover_controller_id()
        paths = [
            f"/{self.controller_id}/api/v2/sites/{site_id}/setting/lan/networks-split",
            f"/{self.controller_id}/api/v1/sites/{site_id}/setting/lan/networks-split",
            f"/api/v2/sites/{site_id}/setting/lan/networks-split",
            f"/api/v1/sites/{site_id}/setting/lan/networks-split",
        ]
        try:
            body, summary = self._get_json_candidates(paths, timeout=30)
        except OmadaApiError as exc:
            raise OmadaApiError("Omada LAN network list is unavailable, so AP management VLAN cannot be selected.", exc.response_summary) from exc
        result = body.get("result") if isinstance(body, dict) else {}
        rows = result.get("data") if isinstance(result, dict) else []
        if not isinstance(rows, list):
            rows = []
        return rows, summary

    def _create_lan_vlan_network_if_supported(self, site_id: str, vlan_id: int) -> dict:
        if not self.controller_id:
            self.discover_controller_id()
        name = f"3J AP Management VLAN {vlan_id}"
        payload = {
            "name": name,
            "purpose": "vlan",
            "vlan": int(vlan_id),
            "application": 0,
            "dhcpL2RelayEnable": False,
            "igmpSnoopEnable": False,
            "mldSnoopEnable": False,
            "dhcpGuard": {"enable": False, "dhcpSvr1": None, "dhcpSvr2": None},
            "dhcpv6Guard": {"enable": False, "dhcpv6Svr1": None, "dhcpv6Svr2": None},
        }
        paths = [
            f"/{self.controller_id}/api/v2/sites/{site_id}/setting/lan/networks",
            f"/{self.controller_id}/api/v1/sites/{site_id}/setting/lan/networks",
            f"/api/v2/sites/{site_id}/setting/lan/networks",
            f"/api/v1/sites/{site_id}/setting/lan/networks",
        ]
        response, summary = self._post_json_candidates(paths, payload, timeout=30)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        result = data.get("result") if isinstance(data, dict) else None
        return {
            "id": result if isinstance(result, str) else (result or {}).get("id") if isinstance(result, dict) else None,
            "name": name,
            "vlan": vlan_id,
            "created": True,
            "response_summary": summary,
        }

    def _ap_management_vlan_network_ref(self, site_id: str, vlan_id: int) -> dict:
        rows, list_summary = self._lan_networks_split(site_id)
        default_network = None
        default_vlan_match = None
        for row in rows:
            if not isinstance(row, dict):
                continue
            lan_id = row.get("id")
            if not lan_id:
                continue
            is_default_network = bool(row.get("primary") or row.get("allLan") or row.get("interface"))
            if int(row.get("vlan") or 0) == int(vlan_id):
                if is_default_network:
                    default_vlan_match = row
                    continue
                return {
                    "lan_network_id": lan_id,
                    "lan_network_name": row.get("name"),
                    "bridge_vlan": row.get("bridgeVlan"),
                    "created": False,
                    "response_summary": list_summary,
                }
            if is_default_network or default_network is None:
                default_network = lan_id
        if default_vlan_match is not None:
            raise OmadaApiError(
                (
                    f"Omada VLAN {vlan_id} is assigned to the Default LAN network. "
                    "Omada rejects the Default LAN network for AP management VLAN. "
                    "Move Default LAN off this VLAN in Omada, then create/select a dedicated "
                    f"AP management VLAN {vlan_id} LAN network."
                ),
                list_summary,
            )
        try:
            created = self._create_lan_vlan_network_if_supported(site_id, vlan_id)
        except OmadaApiError as exc:
            raise OmadaApiError(
                f"Omada site has no VLAN {vlan_id} LAN network and the controller rejected automatic creation.",
                exc.response_summary,
            ) from exc
        rows, refresh_summary = self._lan_networks_split(site_id)
        for row in rows:
            if isinstance(row, dict) and int(row.get("vlan") or 0) == int(vlan_id) and row.get("id"):
                return {
                    "lan_network_id": row["id"],
                    "lan_network_name": row.get("name") or created.get("name"),
                    "bridge_vlan": row.get("bridgeVlan"),
                    "created": True,
                    "response_summary": {
                        "create": created.get("response_summary"),
                        "refresh": refresh_summary,
                    },
                }
        if created.get("id"):
            return {
                "lan_network_id": created["id"],
                "lan_network_name": created.get("name"),
                "created": True,
                "response_summary": created.get("response_summary"),
            }
        raise OmadaApiError(f"Omada VLAN {vlan_id} network was created but could not be found in the LAN network list.")

    def _deployment_ssid_payload(self, ssid_name: str, band: int, config: dict) -> dict:
        security_mode = (config.get("security_mode") or "OPEN").upper()
        raw_vlan_tag = config.get("vlan_tag")
        vlan_tag = int(raw_vlan_tag) if raw_vlan_tag not in (None, "") else None
        security_password = config.get("security_password") or ""
        payload = {
            "name": ssid_name,
            "ssidName": ssid_name,
            "band": band,
            "security": 0 if security_mode == "OPEN" else 3,
            "securityMode": security_mode,
            "psk": security_password if security_mode != "OPEN" else None,
            "password": security_password if security_mode != "OPEN" else None,
            "wpaMode": 3 if security_mode != "OPEN" else 0,
            "encryption": 3 if security_mode != "OPEN" else 0,
            "guestNetEnable": False,
            "portalEnable": False,
            "accessEnable": False,
            "vlanEnable": vlan_tag is not None,
            "vlanId": vlan_tag,
            "vlan": vlan_tag,
            "greEnable": False,
            "broadcast": True,
            "bandSteeringEnable": bool(config.get("band_steering_enabled") and config.get("use_same_ssid")),
            "macFilterEnable": False,
            "wlanScheduleEnable": False,
            "rateLimit": {"downLimitEnable": False, "upLimitEnable": False},
            "rateAndBeaconCtrl": {
                "rate2gCtrlEnable": False,
                "rate5gCtrlEnable": False,
                "rate6gCtrlEnable": False,
            },
        }
        return {key: value for key, value in payload.items() if value is not None}

    def _upsert_deployment_ssid(self, site_id: str, ssid_name: str, band: int, config: dict) -> dict:
        existing = self._find_ssid(site_id, ssid_name)
        wlan_id = existing.get("wlan_id") if existing else None
        if not wlan_id:
            wlan_id, _ = self._primary_wlan_id(site_id)
        payload = self._deployment_ssid_payload(ssid_name, band, config)
        if existing and existing.get("ssid_id"):
            update_paths = [
                f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{existing['ssid_id']}",
                f"/{self.controller_id}/api/v2/sites/{site_id}/setting/ssids/{existing['ssid_id']}",
            ]
            try:
                response, summary = self._put_json_candidates(update_paths, payload, timeout=30)
                data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                return {"ssid": ssid_name, "wlan_id": wlan_id, "ssid_id": existing.get("ssid_id"), "band": band, "created": False, "updated": True, "response_summary": summary, "result": data.get("result") if isinstance(data, dict) else data}
            except OmadaApiError as exc:
                update_summary = exc.response_summary or existing.get("response_summary")
                try:
                    delete_result = self.delete_ssid_if_supported(site_id, wlan_id, existing["ssid_id"], ssid_name)
                    create_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans/{wlan_id}/ssids"
                    response, create_summary = self._post_json_candidates([create_path], payload, timeout=30)
                    data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                    result = data.get("result") if isinstance(data, dict) else {}
                    ssid_id = result.get("ssidId") or result.get("id") if isinstance(result, dict) else result
                    return {
                        "ssid": ssid_name,
                        "wlan_id": wlan_id,
                        "ssid_id": ssid_id,
                        "band": band,
                        "created": True,
                        "updated": False,
                        "recreated": True,
                        "deleted_existing": True,
                        "update_unsupported": True,
                        "delete_result": delete_result,
                        "response_summary": create_summary,
                        "previous_update_response_summary": update_summary,
                    }
                except OmadaApiError as replace_exc:
                    return {
                        "ssid": ssid_name,
                        "wlan_id": wlan_id,
                        "ssid_id": existing.get("ssid_id"),
                        "band": band,
                        "created": False,
                        "updated": False,
                        "response_summary": replace_exc.response_summary or update_summary,
                        "previous_update_response_summary": update_summary,
                        "message": "SSID already exists; Omada update and managed replacement endpoints are unsupported, so the existing SSID was left unchanged.",
                        "existing": True,
                        "update_unsupported": True,
                        "replace_unsupported": True,
                    }
        create_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans/{wlan_id}/ssids"
        response, summary = self._post_json_candidates([create_path], payload, timeout=30)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        result = data.get("result") if isinstance(data, dict) else {}
        ssid_id = result.get("ssidId") or result.get("id") if isinstance(result, dict) else result
        return {"ssid": ssid_name, "wlan_id": wlan_id, "ssid_id": ssid_id, "band": band, "created": True, "updated": False, "response_summary": summary}

    def delete_ssid_if_supported(self, site_id: str, wlan_id: str, ssid_id: str, ssid_name: str = None) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        if not ssid_id:
            raise OmadaApiError("SSID ID is required before deleting an Omada SSID.")
        paths = []
        if wlan_id:
            paths.extend([
                f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
                f"/{self.controller_id}/api/v1/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
            ])
        paths.extend([
            f"/{self.controller_id}/api/v2/sites/{site_id}/setting/ssids/{ssid_id}",
            f"/{self.controller_id}/api/v1/sites/{site_id}/setting/ssids/{ssid_id}",
        ])
        last_summary = {}
        first_api_rejection = None
        for path in paths:
            try:
                response = self.session.delete(f"{self.base_url}{path}", timeout=30)
            except requests.RequestException as exc:
                last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                continue
            last_summary = summarize_response(response)
            if response.status_code < 400:
                try:
                    body = response.json()
                    if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                        if body.get("errorCode") != -1600 and first_api_rejection is None:
                            first_api_rejection = last_summary
                        continue
                except Exception:
                    pass
                return {"deleted": True, "ssid": ssid_name, "ssid_id": ssid_id, "wlan_id": wlan_id, "response_summary": last_summary}
        raise OmadaApiError("Omada API could not delete the old managed SSID using known endpoint paths.", first_api_rejection or last_summary)

    def configure_site_wlan_defaults_if_supported(self, site_id: str, config: dict) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        if config.get("use_same_ssid"):
            ssid_name = config.get("same_ssid_name") or "3J-FreeWiFi"
            ssids = [self._upsert_deployment_ssid(site_id, ssid_name, 3, config)]
        else:
            ssids = [
                self._upsert_deployment_ssid(site_id, config.get("ssid_2g") or "3J-FreeWiFi-2G", 1, config),
                self._upsert_deployment_ssid(site_id, config.get("ssid_5g") or "3J-FreeWiFi-5G", 2, config),
            ]
        return {
            "configured": True,
            "site_id": site_id,
            "vlan_tag": config.get("vlan_tag"),
            "ssid_mode": "same" if config.get("use_same_ssid") else "separate",
            "ssids": ssids,
        }

    def delete_ap_if_supported(self, site_id: str, mac: str) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        last_summary = {}
        for mac_variant in omada_mac_variants(mac):
            mac_path = quote(mac_variant, safe="")
            payloads = [
                {"mac": mac_variant},
                {"macs": [mac_variant]},
                {"deviceMacs": [mac_variant]},
            ]
            paths = [
                ("DELETE", f"/{controller_id}/api/v2/sites/{site_id}/devices/{mac_path}", {}),
                ("POST", f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/{mac_path}/forget", {"mac": mac_variant}),
                ("POST", f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/forget", {"macs": [mac_variant]}),
                ("POST", f"/{controller_id}/api/v2/cmd/devices/{mac_path}/forget", {"mac": mac_variant}),
                ("POST", f"/{controller_id}/api/v2/cmd/devices/forget", {"macs": [mac_variant]}),
            ]
            for method, path, payload in paths:
                try:
                    if method == "DELETE":
                        response = self.session.delete(f"{self.base_url}{path}", timeout=30)
                    else:
                        response = self.session.post(f"{self.base_url}{path}", json=payload, timeout=30)
                except requests.RequestException as exc:
                    last_summary = {"url": f"{self.base_url}{path}", "error": str(exc), "mac_variant": mac_variant}
                    continue
                last_summary = summarize_response(response)
                last_summary["mac_variant"] = mac_variant
                if response.status_code < 400:
                    try:
                        body = response.json()
                        if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                            continue
                    except Exception:
                        pass
                    return {"deleted": True, "mac": mac, "used_mac": mac_variant, "response_summary": last_summary}
            for payload in payloads:
                try:
                    response, summary = self._post_json_candidates(
                        [
                            f"/{controller_id}/api/v2/sites/{site_id}/cmd/devices/delete",
                            f"/{controller_id}/api/v2/cmd/devices/delete",
                        ],
                        payload,
                        timeout=30,
                    )
                    summary["mac_variant"] = mac_variant
                    data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                    return {"deleted": True, "mac": mac, "used_mac": mac_variant, "response_summary": summary, "result": data.get("result") if isinstance(data, dict) else data}
                except OmadaApiError as exc:
                    last_summary = exc.response_summary
        raise OmadaApiError("Omada API could not delete or forget the AP using known endpoint paths.", last_summary)

    def delete_site_if_supported(self, site_id: str) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        if not controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        paths = [
            f"/{controller_id}/api/v2/sites/{site_id}",
            f"/{controller_id}/api/v1/sites/{site_id}",
            f"/api/v2/sites/{site_id}",
            f"/api/v1/sites/{site_id}",
        ]

        def attempt_delete() -> dict:
            last_summary = {}
            first_api_rejection = None
            for path in paths:
                try:
                    response = self.session.delete(f"{self.base_url}{path}", timeout=25)
                except requests.RequestException as exc:
                    last_summary = {"url": f"{self.base_url}{path}", "error": str(exc)}
                    continue
                last_summary = summarize_response(response)
                if response.status_code < 400:
                    try:
                        body = response.json()
                        if isinstance(body, dict) and body.get("errorCode") not in (None, 0):
                            error_code = body.get("errorCode")
                            if error_code == -33105:
                                raise OmadaApiError("Omada requires all devices in this site to be forgotten before deleting the site.", last_summary)
                            if error_code != -1600 and first_api_rejection is None:
                                first_api_rejection = last_summary
                            continue
                    except OmadaApiError:
                        raise
                    except Exception:
                        pass
                    return {"deleted": True, "site_id": site_id, "response_summary": last_summary}
            raise OmadaApiError("Omada API could not delete the site using known endpoint paths.", first_api_rejection or last_summary)

        try:
            return attempt_delete()
        except OmadaApiError as exc:
            body = exc.response_summary.get("body") if isinstance(exc.response_summary, dict) else None
            if not (isinstance(body, dict) and body.get("errorCode") == -33105):
                raise
            aps = self.get_site_aps(site_id).get("aps", [])
            forgotten_devices = []
            forget_errors = []
            for ap in aps:
                mac = ap.get("mac")
                if not mac:
                    continue
                try:
                    forgotten_devices.append(self.delete_ap_if_supported(site_id, mac))
                except OmadaApiError as forget_exc:
                    forget_errors.append({
                        "mac": mac,
                        "error": str(forget_exc),
                        "response_summary": forget_exc.response_summary,
                    })
            result = attempt_delete()
            result["forgotten_devices"] = forgotten_devices
            result["forget_errors"] = forget_errors
            return result

    def get_application_scenarios(self) -> dict:
        self.login()
        controller_id = self.discover_controller_id()
        paths = []
        if controller_id:
            paths.extend([
                f"/{controller_id}/api/v2/scenarios",
                f"/{controller_id}/api/v1/scenarios",
            ])
        paths.extend([
            "/api/v2/scenarios",
            "/api/v1/scenarios",
        ])
        payload, summary = self._get_json_candidates(paths, timeout=20)
        data = payload
        if isinstance(payload, dict):
            data = payload.get("result", payload.get("data", payload))
        scenarios = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    scenarios.append(item)
                elif isinstance(item, dict):
                    value = item.get("name") or item.get("value") or item.get("scenario")
                    if value:
                        scenarios.append(str(value))
        return {"scenarios": sorted(set(scenarios), key=lambda value: value.lower()), "response_summary": summary}

    def _site_creation_defaults(self) -> dict:
        if not self.controller_id:
            self.discover_controller_id()
        paths = []
        if self.controller_id:
            paths.append(f"/{self.controller_id}/api/v2/sites?currentPage=1&currentPageSize=100")
        paths.append("/api/v2/sites?currentPage=1&currentPageSize=100")
        try:
            payload, summary = self._get_json_candidates(paths, timeout=20)
        except OmadaApiError:
            return {}
        for site in self._extract_result_rows(payload):
            device_account = site.get("deviceAccount") if isinstance(site, dict) else None
            defaults = {
                "region": site.get("region"),
                "timeZone": site.get("timeZone"),
                "scenario": site.get("scenario"),
                "response_summary": summary,
            }
            if isinstance(device_account, dict) and device_account.get("username") and device_account.get("password"):
                defaults["deviceAccountSetting"] = {
                    "username": device_account.get("username"),
                    "password": device_account.get("password"),
                }
            return {key: value for key, value in defaults.items() if value}
        return {}

    def create_site_if_supported(
        self,
        site_name: str,
        application_scenario: str = "Office",
        country_region: str = "Philippines",
        time_zone: str = "Asia/Manila",
        device_account_username: Optional[str] = None,
        device_account_password: Optional[str] = None,
    ) -> dict:
        self.login()
        site_name = site_name.strip()
        application_scenario = (application_scenario or "Office").strip() or "Office"
        country_region = (country_region or "Philippines").strip() or "Philippines"
        time_zone = (time_zone or "Asia/Manila").strip() or "Asia/Manila"
        existing = self.get_sites()
        for site in existing.get("sites", []):
            if str(site.get("site_name") or "").strip().lower() == site_name.lower():
                return {
                    "site_id": site.get("site_id"),
                    "site_name": site.get("site_name"),
                    "application_scenario": site.get("application_scenario"),
                    "created": False,
                    "response_summary": existing.get("response_summary"),
                }

        if not self.controller_id:
            self.discover_controller_id()
        creation_defaults = self._site_creation_defaults()
        country_region = creation_defaults.get("region") or country_region
        time_zone = creation_defaults.get("timeZone") or time_zone
        device_account_setting = creation_defaults.get("deviceAccountSetting") or {}
        device_account_username = (device_account_username or device_account_setting.get("username") or "admin").strip()
        device_account_password = device_account_password or device_account_setting.get("password") or "admin"
        paths = []
        if self.controller_id:
            paths.extend([
                f"/{self.controller_id}/api/v2/sites",
                f"/{self.controller_id}/api/v2/user/sites",
                f"/{self.controller_id}/api/v2/sites/create",
                f"/{self.controller_id}/api/v1/sites",
            ])
        paths.extend([
            "/api/v2/sites",
            "/api/v2/user/sites",
            "/api/v2/sites/create",
            "/api/v1/sites",
        ])
        scenario_type = omada_site_scenario_type(application_scenario)
        optional_fields = {
            "scenario": application_scenario,
            "applicationScenario": application_scenario,
            "applicationScenarioName": application_scenario,
            "country": country_region,
            "countryRegion": country_region,
            "region": country_region,
            "timeZone": time_zone,
            "timezone": time_zone,
            "deviceAccountSetting": {
                "username": device_account_username,
                "password": device_account_password,
            },
        }
        payloads = [
            {"name": site_name, "region": country_region, "timeZone": time_zone, "scenario": application_scenario, "deviceAccountSetting": optional_fields["deviceAccountSetting"]},
            {"name": site_name, **optional_fields, "type": scenario_type},
            {"siteName": site_name, **optional_fields, "type": scenario_type},
            {"name": site_name, "siteName": site_name, **optional_fields, "type": scenario_type},
            {"name": site_name, "scenario": application_scenario},
            {"siteName": site_name, "scenario": application_scenario},
            {"name": site_name, "applicationScenario": application_scenario},
            {"siteName": site_name, "applicationScenario": application_scenario},
            {"name": site_name, "type": scenario_type},
            {"siteName": site_name, "type": scenario_type},
            {"name": site_name, "siteName": site_name, "type": scenario_type},
            {"name": site_name},
            {"siteName": site_name},
            {"name": site_name, "siteName": site_name},
        ]
        last_summary = {}
        for payload in payloads:
            try:
                response, summary = self._post_json_candidates(paths, payload, timeout=25)
            except OmadaApiError as exc:
                last_summary = exc.response_summary
                body = last_summary.get("body") if isinstance(last_summary, dict) else None
                if isinstance(body, dict):
                    error_code = body.get("errorCode")
                    message = body.get("msg") or body.get("message") or body.get("error")
                    # Omada returns -1001 when a candidate payload shape is invalid.
                    # Controller versions differ, so keep trying the remaining site
                    # creation payloads instead of failing on the first shape.
                    if error_code not in (None, 0, -1001, -1600) and message:
                        raise OmadaApiError(f"Omada API rejected site creation: {message} (errorCode {error_code}).", last_summary) from exc
                continue
            data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            result = data.get("result") if isinstance(data, dict) else {}
            site_id = None
            if isinstance(result, dict):
                site_id = result.get("siteId") or result.get("siteID") or result.get("id") or result.get("key")
            elif isinstance(result, str):
                site_id = result
            refreshed = self.get_sites()
            for site in refreshed.get("sites", []):
                if str(site.get("site_name") or "").strip().lower() == site_name.lower():
                    site_id = site.get("site_id") or site_id
                    return {"site_id": site_id, "site_name": site.get("site_name"), "application_scenario": site.get("application_scenario") or application_scenario, "created": True, "response_summary": summary}
            return {"site_id": site_id, "site_name": site_name, "application_scenario": application_scenario, "created": True, "response_summary": summary}
        raise OmadaApiError("Omada API could not create the site using known endpoint paths.", last_summary)

    def detect_controller_version(self) -> dict:
        self.login()
        paths = []
        if self.controller_id:
            paths.extend([
                f"/{self.controller_id}/api/v2/system/info",
                f"/{self.controller_id}/api/v2/controller/info",
            ])
        paths.extend([
            "/api/v2/system/info",
            "/api/v2/controller/info",
            "/api/info",
        ])
        payload, summary = self._get_json_candidates(paths, timeout=15)
        result = payload.get("result", payload) if isinstance(payload, dict) else payload
        version = None
        if isinstance(result, dict):
            version = result.get("controllerVer") or result.get("version") or result.get("omadacVer")
        return {"version": version, "response_summary": summary}

    def _primary_wlan_id(self, site_id: str) -> tuple[str, dict]:
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        wlans_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans"
        wlans_payload, wlans_summary = self._get_json_candidates([wlans_path], timeout=20)
        wlan_rows = []
        if isinstance(wlans_payload, dict):
            wlans_result = wlans_payload.get("result", {})
            if isinstance(wlans_result, dict):
                wlan_rows = wlans_result.get("data", [])
            elif isinstance(wlans_result, list):
                wlan_rows = wlans_result
        if not wlan_rows:
            raise OmadaApiError("No Omada WLAN group was found for the selected site.", wlans_summary)
        primary_wlan = next((wlan for wlan in wlan_rows if isinstance(wlan, dict) and wlan.get("primary")), None)
        primary_wlan = primary_wlan or next((wlan for wlan in wlan_rows if isinstance(wlan, dict)), None)
        wlan_id = primary_wlan.get("id") or primary_wlan.get("wlanId") if isinstance(primary_wlan, dict) else None
        if not wlan_id:
            raise OmadaApiError("Omada WLAN group did not include an ID.", wlans_summary)
        return wlan_id, wlans_summary

    def _find_ssid(self, site_id: str, ssid_name: str) -> Optional[dict]:
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            return None
        ssids_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/ssids"
        existing_payload, existing_summary = self._get_json_candidates([ssids_path], timeout=20)
        existing_groups = []
        if isinstance(existing_payload, dict):
            existing_result = existing_payload.get("result", {})
            if isinstance(existing_result, dict):
                existing_groups = existing_result.get("ssids", [])
            elif isinstance(existing_result, list):
                existing_groups = existing_result
        if isinstance(existing_groups, list):
            for group in existing_groups:
                if not isinstance(group, dict):
                    continue
                for ssid in group.get("ssidList", []) or []:
                    if isinstance(ssid, dict) and (ssid.get("ssidName") == ssid_name or ssid.get("name") == ssid_name):
                        return {
                            "wlan_id": group.get("wlanId") or group.get("id"),
                            "ssid_id": ssid.get("ssidId") or ssid.get("id"),
                            "response_summary": existing_summary,
                        }
        return None

    def create_open_ssid_if_supported(self, site_id: str, ssid_name: str, vlan_id: int = None) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        existing = self._find_ssid(site_id, ssid_name)
        if existing:
            return {**existing, "created": False, "requested_vlan_id": vlan_id}
        wlan_id, _ = self._primary_wlan_id(site_id)
        vlan_enabled = vlan_id is not None
        payload = {
            "name": ssid_name,
            "band": 3,
            "security": 0,
            "guestNetEnable": True,
            "portalEnable": True,
            "accessEnable": False,
            "vlanEnable": vlan_enabled,
            "vlanId": int(vlan_id) if vlan_enabled else 1,
            "greEnable": False,
            "broadcast": True,
            "macFilterEnable": False,
            "wlanScheduleEnable": False,
            "rateLimit": {"downLimitEnable": False, "upLimitEnable": False},
            "rateAndBeaconCtrl": {
                "rate2gCtrlEnable": False,
                "rate5gCtrlEnable": False,
                "rate6gCtrlEnable": False,
            },
        }
        create_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans/{wlan_id}/ssids"
        response, summary = self._post_json_candidates([create_path], payload)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        result = data.get("result") if isinstance(data, dict) else {}
        ssid_id = result.get("ssidId") or result.get("id") if isinstance(result, dict) else result
        return {"wlan_id": wlan_id, "ssid_id": ssid_id, "created": True, "vlan_enabled": vlan_enabled, "vlan_id": int(vlan_id) if vlan_enabled else None, "response_summary": summary}

    def configure_external_portal_if_supported(self, site_id: str, payload: dict) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")

        portal_name = payload.get("name") or "3JCentralPisowifi External Portal"
        requested_ssids = payload.get("ssidNames") or payload.get("ssid_names") or []
        if payload.get("ssidName"):
            requested_ssids.append(payload.get("ssidName"))
        requested_ssids = [str(item).strip() for item in requested_ssids if str(item or "").strip()]
        if not requested_ssids:
            raise OmadaApiError("At least one SSID name is required before configuring Omada External Portal.")

        candidates_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/portal/candidates"
        candidates_body, candidates_summary = self._get_json_candidates([candidates_path], timeout=25)
        candidates = candidates_body.get("result") if isinstance(candidates_body, dict) else {}
        ssid_ids = []
        found_ssids = []
        for wlan in (candidates or {}).get("wlanList", []) or []:
            for ssid in wlan.get("ssidList", []) or []:
                if ssid.get("name") in requested_ssids and ssid.get("id"):
                    ssid_ids.append(ssid["id"])
                    found_ssids.append(ssid.get("name"))
        missing_ssids = [name for name in requested_ssids if name not in found_ssids]
        if not ssid_ids:
            raise OmadaApiError(
                "Omada External Portal cannot be configured because none of the configured SSIDs exist in the selected site.",
                {"requested_ssids": requested_ssids, "candidates": candidates_summary},
            )

        portal_url = payload.get("portalUrl") or payload.get("externalPortalUrl") or payload.get("portal_url")
        if not portal_url:
            raise OmadaApiError("Portal URL is required before configuring Omada External Portal.")
        parsed = urlparse(portal_url if "://" in str(portal_url) else f"http://{portal_url}")
        server_url = f"{parsed.netloc}{parsed.path or ''}".strip("/")
        if parsed.query:
            server_url = f"{server_url}?{parsed.query}"
        portal_payload = {
            "enable": True,
            "name": portal_name,
            "ssidList": ssid_ids,
            "networkList": [],
            "authType": 4,
            "httpsRedirectEnable": bool(payload.get("httpsRedirectEnable", False)),
            "landingPage": 1,
            "pageType": 1,
            "externalPortal": {
                "hostType": 2,
                "serverUrlScheme": parsed.scheme or "http",
                "serverUrl": server_url,
            },
        }

        portals_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/portals"
        existing_body, existing_summary = self._get_json_candidates([portals_path], timeout=25)
        existing_portals = existing_body.get("result") if isinstance(existing_body, dict) else []
        existing = next((item for item in existing_portals or [] if item.get("name") == portal_name), None)
        if existing and existing.get("id"):
            response, summary = self._patch_json_candidates([f"{portals_path}/{existing['id']}"], portal_payload, timeout=25)
            operation = "UPDATED"
            portal_id = existing["id"]
        else:
            response, summary = self._post_json_candidates([portals_path], portal_payload, timeout=25)
            operation = "CREATED"
            portal_id = None
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if isinstance(data, dict):
            portal_id = data.get("result") or portal_id
        return {
            "operation": operation,
            "portal_id": portal_id,
            "portal_name": portal_name,
            "requested_ssids": requested_ssids,
            "found_ssids": found_ssids,
            "missing_ssids": missing_ssids,
            "ssid_ids": ssid_ids,
            "portal_payload": portal_payload,
            "candidate_summary": candidates_summary,
            "existing_summary": existing_summary,
            "response_summary": summary,
            "result": data.get("result") if isinstance(data, dict) else data,
        }

    def external_portal_ssid_status_if_supported(self, site_id: str, ssid_names: list[str], portal_name: Optional[str] = None) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")

        requested = [str(item).strip() for item in ssid_names or [] if str(item or "").strip()]
        candidates_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/portal/candidates"
        candidates_body, candidates_summary = self._get_json_candidates([candidates_path], timeout=25)
        candidates = candidates_body.get("result") if isinstance(candidates_body, dict) else {}
        ssid_name_to_id = {}
        for wlan in (candidates or {}).get("wlanList", []) or []:
            for ssid in wlan.get("ssidList", []) or []:
                name = ssid.get("name")
                ssid_id = ssid.get("id")
                if name and ssid_id:
                    ssid_name_to_id[str(name)] = str(ssid_id)

        portals_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/portals"
        portals_body, portals_summary = self._get_json_candidates([portals_path], timeout=25)
        portals = portals_body.get("result") if isinstance(portals_body, dict) else []
        portal_ids = set()
        active_portals = []
        for portal in portals or []:
            if not isinstance(portal, dict):
                continue
            if portal_name and portal.get("name") != portal_name:
                continue
            if portal.get("enable") is False:
                continue
            is_external = bool(portal.get("externalPortal")) or int(portal.get("authType") or 0) == 4
            if not is_external and portal_name is None:
                continue
            active_portals.append({"id": portal.get("id"), "name": portal.get("name"), "authType": portal.get("authType")})
            for key in ("ssidList", "ssidIds", "ssidIdList", "wlanSsidList"):
                raw = portal.get(key)
                if not isinstance(raw, list):
                    continue
                for item in raw:
                    if isinstance(item, dict):
                        value = item.get("id") or item.get("ssidId") or item.get("ssid_id")
                    else:
                        value = item
                    if value not in (None, ""):
                        portal_ids.add(str(value))

        ssids = []
        for name in requested:
            ssid_id = ssid_name_to_id.get(name)
            ssids.append({
                "ssid": name,
                "ssid_id": ssid_id,
                "exists": bool(ssid_id),
                "portal_enabled": bool(ssid_id and ssid_id in portal_ids),
            })
        return {
            "site_id": site_id,
            "requested_ssids": requested,
            "ssids": ssids,
            "all_present": all(item["exists"] for item in ssids) if ssids else False,
            "all_portal_enabled": all(item["portal_enabled"] for item in ssids) if ssids else False,
            "active_portals": active_portals,
            "candidate_summary": candidates_summary,
            "portal_summary": portals_summary,
        }

    def ensure_controller_portal_url_manual_if_supported(self) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        controller_host = urlparse(self.base_url).hostname
        if not controller_host:
            raise OmadaApiError("Omada controller host could not be detected for manual portal URL.")
        setting_path = f"/{self.controller_id}/api/v2/controller/setting"
        current_body, read_summary = self._get_json_candidates([setting_path], timeout=20)
        current = current_body.get("result") if isinstance(current_body, dict) else {}
        web_port = dict((current or {}).get("webPort") or {})
        web_port.update({
            "hostName": controller_host,
            "autoRefresh": False,
            "autoPortalIpEnable": False,
            "portalHttpsRedirect": False,
        })
        response, patch_summary = self._patch_json_candidates([setting_path], {"webPort": web_port}, timeout=25)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        return {
            "controller_host": controller_host,
            "manual_portal_url": True,
            "portal_https_redirect": False,
            "web_port": web_port,
            "read_summary": read_summary,
            "response_summary": patch_summary,
            "result": data.get("result") if isinstance(data, dict) else data,
        }

    def delete_ssids_by_name_if_supported(self, site_id: str, ssid_names: list[str]) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        results = []
        for ssid_name in [str(item).strip() for item in ssid_names or [] if str(item or "").strip()]:
            existing = self._find_ssid(site_id, ssid_name)
            if not existing:
                results.append({"ssid": ssid_name, "status": "ABSENT"})
                continue
            if not existing.get("ssid_id"):
                results.append({"ssid": ssid_name, "status": "SKIPPED", "message": "SSID ID is not available from Omada."})
                continue
            try:
                deleted = self.delete_ssid_if_supported(site_id, existing.get("wlan_id"), existing.get("ssid_id"), ssid_name)
                results.append({"ssid": ssid_name, "status": "REMOVED", "result": deleted})
            except OmadaApiError as exc:
                results.append({"ssid": ssid_name, "status": "FAILED", "message": str(exc), "response_summary": exc.response_summary})
        return {"results": results, "failed": [item for item in results if item.get("status") == "FAILED"]}

    def ensure_pre_auth_access_for_portal(self, site_id: str, portal_url: str) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")
        parsed = urlparse(portal_url if "://" in str(portal_url or "") else f"http://{portal_url or ''}")
        portal_host = parsed.hostname
        if not portal_host:
            raise OmadaApiError("Portal host could not be detected for Omada Pre-Auth Access.")
        controller_host = urlparse(self.base_url).hostname
        required_hosts = []
        for host in (portal_host, controller_host):
            clean_host = str(host or "").strip()
            if clean_host and clean_host not in required_hosts:
                required_hosts.append(clean_host)

        access_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/accessControl"
        current_body, read_summary = self._get_json_candidates([access_path], timeout=20)
        current = current_body.get("result") if isinstance(current_body, dict) else {}
        if not isinstance(current, dict):
            current = {}
        policies = list(current.get("preAuthAccessPolicies") or [])
        existing_hosts = {
            str(item.get("ip") or "")
            for item in policies
            if isinstance(item, dict)
            and int(item.get("type") or 0) == 1
            and str(item.get("subnetMask") or "") in {"32", "255.255.255.255"}
        }
        added_hosts = []
        for host in required_hosts:
            if host in existing_hosts:
                continue
            policies.append({"type": 1, "ip": host, "subnetMask": "32"})
            existing_hosts.add(host)
            added_hosts.append(host)
        payload = {
            "preAuthAccessEnable": True,
            "preAuthAccessPolicies": policies,
            "freeAuthClientEnable": bool(current.get("freeAuthClientEnable")),
            "freeAuthClientPolicies": current.get("freeAuthClientPolicies") or [],
        }
        response, patch_summary = self._patch_json_candidates([access_path], payload, timeout=25)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        return {
            "portal_host": portal_host,
            "controller_host": controller_host,
            "required_hosts": required_hosts,
            "added_hosts": added_hosts,
            "added": bool(added_hosts),
            "pre_auth_access_enable": True,
            "pre_auth_policy_count": len(policies),
            "response_summary": patch_summary,
            "read_summary": read_summary,
            "result": data.get("result") if isinstance(data, dict) else data,
        }

    def authorize_portal_client(self, site_id: str, payload: dict) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        official_payload = {
            key: payload.get(key)
            for key in ("clientMac", "apMac", "ssidName", "radioId", "authType", "time")
            if payload.get(key) is not None
        }
        official_payload["authType"] = official_payload.get("authType") or 4
        official_paths = []
        compatibility_paths = []
        if self.controller_id:
            official_paths.append(f"/{self.controller_id}/api/v2/hotspot/extPortal/auth")
            compatibility_paths.extend([
                f"/{self.controller_id}/api/v2/hotspot/extPortal/auth",
                f"/{self.controller_id}/api/v2/sites/{site_id}/cmd/hotspot/extPortal/auth",
                f"/{self.controller_id}/api/v2/sites/{site_id}/hotspot/extPortal/auth",
                f"/{self.controller_id}/api/v2/sites/{site_id}/portal/auth",
            ])
        official_paths.append("/api/v2/hotspot/extPortal/auth")
        compatibility_paths.extend([
            f"/api/v2/sites/{site_id}/cmd/hotspot/extPortal/auth",
            f"/api/v2/sites/{site_id}/hotspot/extPortal/auth",
            f"/api/v2/sites/{site_id}/portal/auth",
            "/api/v2/hotspot/extPortal/auth",
            "/api/v2/portal/auth",
        ])
        try:
            response, summary = self._post_json_candidates(official_paths, official_payload, timeout=25)
        except OmadaApiError as first_error:
            try:
                self.hotspot_login()
                response, summary = self._post_json_candidates(official_paths, official_payload, timeout=25)
            except OmadaApiError as second_error:
                try:
                    response, summary = self._post_json_candidates(compatibility_paths, payload, timeout=25)
                except OmadaApiError as third_error:
                    raise OmadaApiError(str(third_error), third_error.response_summary or second_error.response_summary or first_error.response_summary)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        return {"response_summary": summary, "result": data.get("result") if isinstance(data, dict) else data}

    def get_client_status_if_supported(self, site_id: str, client_mac: str) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        paths = []
        if self.controller_id:
            paths.extend([
                f"/{self.controller_id}/api/v2/sites/{site_id}/clients/{client_mac}",
                f"/{self.controller_id}/api/v2/sites/{site_id}/clients?mac={client_mac}",
            ])
        paths.extend([
            f"/api/v2/sites/{site_id}/clients/{client_mac}",
            f"/api/v2/sites/{site_id}/clients?mac={client_mac}",
        ])
        payload, summary = self._get_json_candidates(paths, timeout=15)
        return {"client": payload, "response_summary": summary}

    def get_clients_if_supported(self, site_id: str, site_name: Optional[str] = None) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        paths = []
        encoded_site_name = quote(site_name, safe="") if site_name else None
        if self.controller_id:
            paths.extend([
                f"/{self.controller_id}/api/v2/sites/{site_id}/clients?currentPage=1&currentPageSize=1000",
                f"/{self.controller_id}/api/v2/sites/{site_id}/clients?currentPage=1&currentPageSize=1000&filters.active=true",
                f"/{self.controller_id}/api/v2/sites/{site_id}/clients",
                f"/{self.controller_id}/api/v2/sites/{site_id}/clients/connected?currentPage=1&currentPageSize=1000",
                f"/{self.controller_id}/api/v2/sites/{site_id}/insight/clients?currentPage=1&currentPageSize=1000",
            ])
            if encoded_site_name:
                paths.extend([
                    f"/{self.controller_id}/api/v2/sites/{encoded_site_name}/clients?currentPage=1&currentPageSize=1000",
                    f"/{self.controller_id}/api/v2/sites/{encoded_site_name}/clients?currentPage=1&currentPageSize=1000&filters.active=true",
                    f"/{self.controller_id}/api/v2/sites/{encoded_site_name}/clients",
                    f"/{self.controller_id}/api/v2/sites/{encoded_site_name}/insight/clients?currentPage=1&currentPageSize=1000",
                ])
        paths.extend([
            f"/api/v2/sites/{site_id}/clients?currentPage=1&currentPageSize=1000",
            f"/api/v2/sites/{site_id}/clients",
            f"/api/v2/sites/{site_id}/clients/connected?currentPage=1&currentPageSize=1000",
            f"/api/v2/sites/{site_id}/insight/clients?currentPage=1&currentPageSize=1000",
        ])
        if encoded_site_name:
            paths.extend([
                f"/api/v2/sites/{encoded_site_name}/clients?currentPage=1&currentPageSize=1000",
                f"/api/v2/sites/{encoded_site_name}/clients",
                f"/api/v2/sites/{encoded_site_name}/insight/clients?currentPage=1&currentPageSize=1000",
            ])
        payload, summary = self._get_json_candidates(paths, timeout=20)
        data = payload
        if isinstance(payload, dict):
            data = payload.get("result", payload.get("data", payload))
        if isinstance(data, dict):
            data = data.get("data", data.get("clients", data.get("list", data.get("rows", []))))
        clients = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                mac = item.get("mac") or item.get("clientMac") or item.get("client_mac")
                ip = item.get("ip") or item.get("ipAddress") or item.get("clientIp")
                hostname = item.get("hostname") or item.get("hostName") or item.get("name") or item.get("clientName")
                ap_mac = item.get("apMac") or item.get("ap_mac") or item.get("uplinkDeviceMac") or item.get("apMAC")
                ap_name = item.get("apName") or item.get("deviceName") or item.get("uplinkDeviceName") or item.get("apOrPort")
                ssid = item.get("ssid") or item.get("ssidName") or item.get("wlanName") or item.get("ssidOrNetwork")
                status_value = item.get("status") or item.get("state") or item.get("connectStatus") or item.get("authStatus")
                active = bool(
                    item.get("active")
                    or item.get("online")
                    or item.get("connected")
                    or item.get("authStatus") in (0, 2, 3)
                    or str(status_value or "").lower() in {"connected", "online", "active", "1", "true"}
                )
                clients.append({
                    "client_mac": mac,
                    "client_ip": ip,
                    "hostname": hostname,
                    "device_type": item.get("deviceType") or item.get("deviceCategory"),
                    "ap_mac": ap_mac,
                    "ap_name": ap_name,
                    "ssid": ssid,
                    "active": active,
                    "last_seen": item.get("lastSeen") or item.get("lastSeenTime") or item.get("last_seen"),
                    "uptime_seconds": item.get("uptime") or item.get("duration") or item.get("upTime"),
                    "radio_id": item.get("radioId"),
                    "band": item.get("band"),
                    "channel": item.get("channel"),
                    "rssi": item.get("rssi"),
                    "snr": item.get("snr"),
                    "rx_rate": item.get("rxRate"),
                    "tx_rate": item.get("txRate"),
                    "activity": item.get("activity"),
                    "traffic_down": item.get("trafficDown") or item.get("download"),
                    "traffic_up": item.get("trafficUp") or item.get("upload"),
                    "vid": item.get("vid"),
                    "guest": item.get("guest"),
                    "raw_status": status_value,
                })
        return {"clients": clients, "response_summary": summary}

    def create_radius_profile(self, site_id: str, payload: dict) -> dict:
        self.login()
        paths = []
        if self.controller_id:
            paths.extend([
                f"/{self.controller_id}/api/v2/sites/{site_id}/setting/radiusProfiles",
                f"/{self.controller_id}/api/v2/sites/{site_id}/setting/radiusprofiles",
                f"/{self.controller_id}/api/v2/sites/{site_id}/radiusprofiles",
                f"/{self.controller_id}/api/v2/sites/{site_id}/profiles/radius",
            ])
        paths.extend([
            f"/api/v2/sites/{site_id}/setting/radiusprofiles",
            f"/api/v2/sites/{site_id}/radiusprofiles",
            f"/api/v2/sites/{site_id}/profiles/radius",
        ])
        existing_payload, existing_summary = self._get_json_candidates(paths, timeout=20)
        existing = existing_payload.get("result") if isinstance(existing_payload, dict) else []
        if isinstance(existing, list):
            for item in existing:
                if isinstance(item, dict) and item.get("name") == payload.get("name"):
                    return {"profile_id": item.get("radiusProfileId") or item.get("id"), "response_summary": existing_summary}
        response, summary = self._post_json_candidates(paths, payload)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        result = data.get("result") if isinstance(data, dict) else {}
        profile_id = None
        if isinstance(result, dict):
            profile_id = result.get("id") or result.get("profileId") or result.get("radiusProfileId")
        elif isinstance(result, str):
            profile_id = result
        return {"profile_id": profile_id, "response_summary": summary}

    def create_wpa_enterprise_ssid(self, site_id: str, payload: dict) -> dict:
        self.login()
        if not self.controller_id:
            self.discover_controller_id()
        if not self.controller_id:
            raise OmadaApiError("Omada controller ID could not be detected.")

        ssid_name = payload.get("name") or payload.get("ssid")
        ssids_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/ssids"
        existing_payload, existing_summary = self._get_json_candidates([ssids_path], timeout=20)
        existing_groups = []
        if isinstance(existing_payload, dict):
            existing_result = existing_payload.get("result", {})
            if isinstance(existing_result, dict):
                existing_groups = existing_result.get("ssids", [])
        if isinstance(existing_groups, list):
            for group in existing_groups:
                if not isinstance(group, dict):
                    continue
                for ssid in group.get("ssidList", []) or []:
                    if isinstance(ssid, dict) and ssid.get("ssidName") == ssid_name:
                        return {
                            "wlan_id": group.get("wlanId"),
                            "ssid_id": ssid.get("ssidId"),
                            "response_summary": existing_summary,
                        }

        wlan_id, _ = self._primary_wlan_id(site_id)

        create_path = f"/{self.controller_id}/api/v2/sites/{site_id}/setting/wlans/{wlan_id}/ssids"
        response, summary = self._post_json_candidates([create_path], payload)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        result = data.get("result") if isinstance(data, dict) else {}
        ssid_id = None
        if isinstance(result, dict):
            ssid_id = result.get("ssidId") or result.get("id") or result.get("wlanId")
        elif isinstance(result, str):
            ssid_id = result
        return {"wlan_id": wlan_id, "ssid_id": ssid_id, "response_summary": summary}
