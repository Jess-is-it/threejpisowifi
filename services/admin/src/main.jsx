import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { createRoot } from 'react-dom/client';
import '@tabler/core/dist/css/tabler.min.css';
import {
  IconActivity,
  IconAlertTriangle,
  IconBan,
  IconBrandOpenai,
  IconCash,
  IconChevronDown,
  IconChevronLeft,
  IconChevronUp,
  IconCircleCheck,
  IconClock,
  IconCloudUpload,
  IconCpu,
  IconDashboard,
  IconDatabase,
  IconDeviceFloppy,
  IconEdit,
  IconHistory,
  IconId,
  IconInfoCircle,
  IconKey,
  IconListDetails,
  IconLock,
  IconLogout,
  IconMapPin,
  IconArchive,
  IconExternalLink,
  IconEye,
  IconPlayerPlay,
  IconPlayerStop,
  IconRefresh,
  IconRouter,
  IconRobot,
  IconSearch,
  IconSettings,
  IconShieldLock,
  IconServer,
  IconSparkles,
  IconUser,
  IconUserCog,
  IconUserPlus,
  IconUsers,
  IconWallet,
  IconTrash,
  IconWifi,
  IconX
} from '@tabler/icons-react';
import './styles.css';

const API = '/api';

const MAP_TILE_SIZE = 256;
const DEFAULT_MAP_CENTER = { latitude: 17.5259771, longitude: 121.6882655 };
const DEFAULT_MAP_ZOOM = 16;

const DEFAULT_AP_SITE_CONFIG = {
  auto_apply_enabled: true,
  device_account_username: '',
  device_account_password: '',
  use_same_ssid: true,
  same_ssid_name: '3J-FreeWiFi',
  ssid_2g: '3J-FreeWiFi-2G',
  ssid_5g: '3J-FreeWiFi-5G',
  band_steering_enabled: true,
  security_mode: 'OPEN',
  security_password: '',
  site_vlans: {}
};

const DEV_LOGIN_PREFILL = {
  username: 'admin',
  password: 'DevAdmin2026!'
};

function shouldPrefillDevLogin() {
  return import.meta.env.DEV || window.location.port === '8080';
}

function request(path, options = {}) {
  const token = localStorage.getItem('centralwifi_token');
  return fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {})
    }
  }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail;
      const message = typeof detail === 'string'
        ? detail
        : detail?.message
          ? `${detail.message}${detail.missing_requirements?.length ? ` ${detail.missing_requirements.join('; ')}` : ''}${detail.blockers?.length ? ` ${detail.blockers.join('; ')}` : ''}`
          : 'Request failed';
      throw new Error(message);
    }
    return data;
  });
}

function publicRequest(path) {
  return fetch(`${API}${path}`).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || 'Request failed');
    return data;
  });
}

function publicApi(path, options = {}) {
  return fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || 'Request failed');
    return data;
  });
}

function uploadRequest(path, field, file) {
  const token = localStorage.getItem('centralwifi_token');
  const body = new FormData();
  body.append(field, file);
  return fetch(`${API}${path}`, {
    method: 'POST',
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body
  }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || 'Upload failed');
    return data;
  });
}

function fmt(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function truncateWithEllipsis(value, maxLength = 10) {
  const text = fmt(value);
  if (!text || text.length <= maxLength) return text || 'n/a';
  return `${text.slice(0, maxLength)}...`;
}

function IconWrap({ children }) {
  return <span className="nav-link-icon d-md-none d-lg-inline-block">{children}</span>;
}

function formatUptime(seconds = 0) {
  const total = Number(seconds) || 0;
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function slugify(page) {
  return page.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'dashboard';
}

const routePages = {
  '': 'Dashboard',
  dashboard: 'Dashboard',
  'ap-client-map': 'AP & Client Map',
  users: 'Connected Devices',
  'customers-accounts': 'Connected Devices',
  'connected-devices': 'Connected Devices',
  'sites-deployments': 'Sites',
  'aps-deployment': 'Sites',
  'aps-deployment/sites': 'Sites',
  'aps-deployment/list-of-aps': 'List of APs',
  'aps-deployment/long-lat': 'Long Lat',
  'list-of-aps': 'List of APs',
  'long-lat': 'Long Lat',
  'location-management': 'Location Management',
  vouchers: 'Vouchers',
  'wallet-manual-top-up': 'Wallet / Manual Top-Up',
  sessions: 'Sessions',
  'captive-portal': 'Captive Portal',
  'captive-portal/editor': 'Portal Editor',
  network: 'Network',
  'network/mikrotik/scan-result': 'MikroTik Scan Result',
  'nas-router-ap-clients': 'Network',
  'radius-test-guide': 'Advanced RADIUS Lab',
  'system-settings': 'System Settings',
  'settings/omada-controller': 'Omada Controller',
  'omada-controller': 'Omada Controller',
  logs: 'Logs',
  'view-profile': 'View Profile',
  'change-password': 'Change Password',
  'user-detail': 'Connected Devices'
};

function pageFromLocation() {
  const path = window.location.pathname.replace(/\/+$/, '');
  const slug = path.replace(/^\/admin\/?/, '');
  return routePages[slug] || 'Dashboard';
}

function routeForPage(page) {
  if (page === 'Omada Controller') return '/admin/settings/omada-controller';
  if (page === 'AP & Client Map') return '/admin/ap-client-map';
  if (page === 'Portal Editor') return '/admin/captive-portal/editor';
  if (page === 'MikroTik Scan Result') return '/admin/network/mikrotik/scan-result';
  if (page === 'Connected Devices') return '/admin/users';
  if (page === 'Advanced RADIUS Lab') return '/admin/radius-test-guide';
  if (page === 'Sites' || page === 'Sites Deployments') return '/admin/aps-deployment/sites';
  if (page === 'List of APs') return '/admin/aps-deployment/list-of-aps';
  if (page === 'Long Lat') return '/admin/aps-deployment/long-lat';
  return `/admin/${slugify(page)}`;
}

function collectLongLatSites(data = {}) {
  const sites = new Map();
  const addSite = (siteId, siteName) => {
    if (!siteId && !siteName) return;
    const key = siteId || `name:${siteName}`;
    if (!sites.has(key)) {
      sites.set(key, {
        site_id: siteId || '',
        site_name: siteName || siteId || 'Unnamed Site'
      });
    }
  };
  (data.sites || []).forEach((site) => addSite(site.site_id || site.omada_site_id, site.site_name));
  (data.site_centers || []).forEach((site) => addSite(site.site_id, site.site_name));
  (data.aps || []).forEach((ap) => addSite(ap.site_id, ap.site_name));
  return Array.from(sites.values()).sort((a, b) => (a.site_name || '').localeCompare(b.site_name || ''));
}

function longLatFilterFromLocation() {
  const params = new URLSearchParams(window.location.search);
  return {
    site_id: params.get('site_id') || '',
    site_name: params.get('site_name') || ''
  };
}

function longLatRouteForSite(site) {
  const base = '/admin/aps-deployment/long-lat';
  if (!site) return base;
  const params = new URLSearchParams();
  if (site.site_id) params.set('site_id', site.site_id);
  if (site.site_name) params.set('site_name', site.site_name);
  const query = params.toString();
  return query ? `${base}?${query}` : base;
}

function apClientMapRouteForSite(site) {
  const base = '/admin/ap-client-map';
  if (!site) return base;
  const params = new URLSearchParams();
  if (site.site_id) params.set('site_id', site.site_id);
  if (site.site_name) params.set('site_name', site.site_name);
  const query = params.toString();
  return query ? `${base}?${query}` : base;
}

function matchesLongLatSite(item, filter) {
  if (!filter?.site_id && !filter?.site_name) return true;
  if (filter.site_id && item.site_id === filter.site_id) return true;
  if (filter.site_name && item.site_name === filter.site_name) return true;
  return false;
}

function longLatFilterLabel(filter, sites = []) {
  if (!filter?.site_id && !filter?.site_name) return 'All Sites';
  const site = sites.find((item) => matchesLongLatSite(item, filter));
  return site?.site_name || filter.site_name || filter.site_id || 'Selected Site';
}

function bestLongLatCenter(data, filter) {
  const aps = (data.aps || []).filter((ap) => matchesLongLatSite(ap, filter));
  const firstMapped = aps.find((ap) => ap.mapped && ap.map_latitude !== null && ap.map_latitude !== undefined && ap.map_longitude !== null && ap.map_longitude !== undefined);
  if (firstMapped) {
    return { center: { latitude: Number(firstMapped.map_latitude), longitude: Number(firstMapped.map_longitude) }, zoom: 17 };
  }
  const firstSite = (data.site_centers || []).find((site) => matchesLongLatSite(site, filter) && site.latitude !== null && site.latitude !== undefined && site.longitude !== null && site.longitude !== undefined);
  if (firstSite) {
    return { center: { latitude: Number(firstSite.latitude), longitude: Number(firstSite.longitude) }, zoom: 16 };
  }
  const firstApWithSite = aps.find((ap) => ap.site_latitude !== null && ap.site_latitude !== undefined && ap.site_longitude !== null && ap.site_longitude !== undefined);
  if (firstApWithSite) {
    return { center: { latitude: Number(firstApWithSite.site_latitude), longitude: Number(firstApWithSite.site_longitude) }, zoom: 16 };
  }
  return null;
}

function formatSeconds(seconds) {
  const total = Number(seconds || 0);
  if (total <= 0) return '0m';
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatCountdown(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds || 0)));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (days > 0) return `${days}d ${hours}h ${minutes}m ${secs}s`;
  return `${hours}h ${minutes}m ${secs}s`;
}

function formatPortalDateTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function formatUsdPerMTok(value) {
  if (value === null || value === undefined || value === '') return '-';
  const numeric = Number(value);
  const precision = numeric < 1 ? 3 : 2;
  return `$${numeric.toFixed(precision).replace(/\.?0+$/, '')}`;
}

function formatDataRate(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount) || amount <= 0) return '0 B/s';
  if (amount >= 1024 * 1024 * 1024) return `${(amount / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
  if (amount >= 1024 * 1024) return `${(amount / (1024 * 1024)).toFixed(2)} MB/s`;
  if (amount >= 1024) return `${(amount / 1024).toFixed(1)} KB/s`;
  return `${amount.toFixed(0)} B/s`;
}

function formatClientRate(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount) || amount <= 0) return '0 Mbps';
  return `${(amount / 1000).toFixed(2)} Mbps`;
}

function formatPercent(value) {
  if (value === null || value === undefined || value === '') return 'n/a';
  const amount = Number(value);
  if (!Number.isFinite(amount)) return fmt(value);
  return `${amount.toFixed(0)}%`;
}

function hasValidUntil(user) {
  if (!user.valid_until) return false;
  return new Date(user.valid_until).getTime() > Date.now();
}

function needsBalance(user) {
  return user.status === 'active' && !user.is_unlimited && Number(user.time_remaining_seconds || 0) <= 0 && !hasValidUntil(user);
}

function generateSharedSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const values = new Uint32Array(24);
  window.crypto.getRandomValues(values);
  return Array.from(values, (value) => chars[value % chars.length]).join('');
}

function generateSessionId() {
  return `acct-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function latLngToWorldPixel(latitude, longitude, zoom) {
  const sinLat = Math.sin((clamp(Number(latitude), -85.05112878, 85.05112878) * Math.PI) / 180);
  const scale = MAP_TILE_SIZE * 2 ** zoom;
  return {
    x: ((Number(longitude) + 180) / 360) * scale,
    y: (0.5 - Math.log((1 + sinLat) / (1 - sinLat)) / (4 * Math.PI)) * scale
  };
}

function worldPixelToLatLng(x, y, zoom) {
  const scale = MAP_TILE_SIZE * 2 ** zoom;
  const longitude = (x / scale) * 360 - 180;
  const n = Math.PI - (2 * Math.PI * y) / scale;
  const latitude = (180 / Math.PI) * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n)));
  return {
    latitude: clamp(latitude, -85.05112878, 85.05112878),
    longitude: ((longitude + 540) % 360) - 180
  };
}

function formatCoordinate(value) {
  if (value === null || value === undefined || value === '') return 'n/a';
  return Number(value).toFixed(6);
}

function apMapTone(ap) {
  if (ap?.map_health === 'ERROR' || ap?.map_error) return 'red';
  if (Number(ap?.client_count || 0) > 0) return 'green';
  return 'gray';
}

function apMapStatusText(ap) {
  if (ap?.map_error) return ap.map_error;
  if (Number(ap?.client_count || 0) > 0) return `${ap.client_count} connected client${Number(ap.client_count) === 1 ? '' : 's'}`;
  return 'No connected clients';
}

function streetViewEmbedUrl(ap) {
  const latitude = Number(ap?.map_latitude);
  const longitude = Number(ap?.map_longitude);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return '';
  return `https://www.google.com/maps?layer=c&cbll=${latitude},${longitude}&cbp=12,0,0,0,0&output=svembed`;
}

function mapsSearchUrl(ap) {
  const latitude = Number(ap?.map_latitude);
  const longitude = Number(ap?.map_longitude);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return '';
  return `https://www.google.com/maps/search/?api=1&query=${latitude},${longitude}`;
}

function renderPortalTemplate(template, slots) {
  const parts = String(template || '').split(/(\{\{[a-zA-Z0-9_]+\}\})/g);
  return parts.map((part, index) => {
    const match = part.match(/^\{\{([a-zA-Z0-9_]+)\}\}$/);
    if (match) return <React.Fragment key={`${match[1]}-${index}`}>{slots[match[1]] || null}</React.Fragment>;
    if (!part) return null;
    return <span key={`html-${index}`} dangerouslySetInnerHTML={{ __html: part }} />;
  });
}

function PortalApp() {
  const [settings, setSettings] = useState(null);
  const [sessionId, setSessionId] = useState(() => localStorage.getItem('centralwifi_portal_session') || '');
  const [voucherCode, setVoucherCode] = useState('');
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState(null);
  const [timerRemaining, setTimerRemaining] = useState(0);
  const [localTimerExpired, setLocalTimerExpired] = useState(false);
  const [loading, setLoading] = useState(false);
  const params = new URLSearchParams(window.location.search);
  const rawQueryParams = Object.fromEntries(params.entries());
  const context = {
    portal_session_id: sessionId || null,
    mac: params.get('mac') || null,
    ip: params.get('ip') || null,
    client_mac: params.get('client_mac') || params.get('clientMac') || null,
    clientMac: params.get('clientMac') || null,
    client_ip: params.get('client_ip') || null,
    ap_mac: params.get('ap_mac') || params.get('apMac') || null,
    apMac: params.get('apMac') || null,
    gateway_mac: params.get('gateway_mac') || params.get('gatewayMac') || null,
    gatewayMac: params.get('gatewayMac') || null,
    vlan_id: params.get('vlan_id') || params.get('vid') || null,
    vid: params.get('vid') || null,
    ssid: params.get('ssid') || null,
    site: params.get('site') || null,
    gateway: params.get('gateway') || null,
    redirect_url: params.get('redirect_url') || params.get('redirectUrl') || null,
    redirectUrl: params.get('redirectUrl') || null,
    nas_id: params.get('nas_id') || null,
    server_name: params.get('server-name') || params.get('server_name') || params.get('server') || null,
    link_login: params.get('link-login') || params.get('link_login') || null,
    link_login_only: params.get('link-login-only') || params.get('link_login_only') || null,
    link_orig: params.get('link-orig') || params.get('link_orig') || null,
    chap_id: params.get('chap-id') || params.get('chap_id') || null,
    chap_challenge: params.get('chap-challenge') || params.get('chap_challenge') || null,
    token: params.get('token') || params.get('t') || null,
    authToken: params.get('authToken') || null,
    raw_query_params: rawQueryParams
  };
  const deviceDetected = Boolean(context.client_mac || context.mac || context.ip || context.ap_mac || context.gateway_mac || context.ssid || context.site || context.token || context.authToken || context.link_login_only || context.server_name);

  async function loadPortal() {
    const portalSettings = await publicRequest('/portal/settings');
    setSettings(portalSettings);
    const session = await publicApi('/portal/session', { method: 'POST', body: JSON.stringify(context) });
    setSessionId(session.portal_session_id);
    localStorage.setItem('centralwifi_portal_session', session.portal_session_id);
    const nextStatus = await publicRequest(`/portal/status?portal_session_id=${encodeURIComponent(session.portal_session_id)}`);
    setStatus(nextStatus);
  }
  useEffect(() => { loadPortal().catch((err) => setResult({ status: 'FAILED', message: err.message })); }, []);
  useEffect(() => {
    if (settings?.accent_color) document.documentElement.style.setProperty('--tblr-primary', settings.accent_color);
  }, [settings]);

  async function redeem(e) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try {
      const data = await publicApi('/portal/redeem', {
        method: 'POST',
        body: JSON.stringify({ ...context, portal_session_id: sessionId, voucher_code: voucherCode })
      });
      setResult(data);
      if (data.portal_session_id) {
        localStorage.setItem('centralwifi_portal_session', data.portal_session_id);
        setSessionId(data.portal_session_id);
        setStatus(await publicRequest(`/portal/status?portal_session_id=${encodeURIComponent(data.portal_session_id)}`));
      }
    } catch (err) {
      setResult({ status: 'FAILED', message: 'Something went wrong. Please try again or contact the operator.' });
    } finally {
      setLoading(false);
    }
  }

  async function checkStatus() {
    const id = sessionId || localStorage.getItem('centralwifi_portal_session');
    if (!id) return;
    setLoading(true);
    try {
      setStatus(await publicRequest(`/portal/status?portal_session_id=${encodeURIComponent(id)}`));
    } finally {
      setLoading(false);
    }
  }

  const title = settings?.portal_title || '3J WiFi';
  const subtitle = settings?.portal_subtitle || 'Enter your voucher to connect';
  const sourceRemaining = Math.max(0, Number(result?.remaining_time_seconds ?? status?.remaining_time_seconds ?? 0) || 0);
  const validUntil = result?.valid_until ?? status?.valid_until;
  const unlimited = result?.unlimited ?? status?.unlimited;
  const authorizationStatus = result?.authorization_status || status?.mikrotik_authorization_status || status?.omada_authorization_status;
  const accessExpiresAt = result?.access_expires_at ?? status?.access_expires_at;
  const backendExpired = Boolean(result?.access_expired || status?.access_expired || status?.status === 'EXPIRED');
  const hasAccessWindow = Boolean(unlimited || accessExpiresAt || validUntil || sourceRemaining > 0 || localTimerExpired || backendExpired);
  const countdownActive = hasAccessWindow && !unlimited && !localTimerExpired && !backendExpired && timerRemaining > 0;
  const timerExpired = Boolean(!unlimited && (localTimerExpired || backendExpired));
  const connected = Boolean((result?.connected ?? status?.connected ?? authorizationStatus === 'AUTHORIZED') && !timerExpired);
  const continueUrl = result?.redirect_url || status?.redirect_url;

  useEffect(() => {
    setTimerRemaining(sourceRemaining);
    setLocalTimerExpired(backendExpired);
  }, [sourceRemaining, accessExpiresAt, backendExpired]);

  useEffect(() => {
    if (!countdownActive) return undefined;
    const intervalId = window.setInterval(() => {
      setTimerRemaining((current) => {
        if (current <= 1) {
          setLocalTimerExpired(true);
          return 0;
        }
        return current - 1;
      });
    }, 1000);
    return () => window.clearInterval(intervalId);
  }, [countdownActive]);

  useEffect(() => {
    if (!localTimerExpired || !sessionId) return;
    publicRequest(`/portal/status?portal_session_id=${encodeURIComponent(sessionId)}`)
      .then((nextStatus) => setStatus(nextStatus))
      .catch(() => {});
  }, [localTimerExpired, sessionId]);

  const brandSlot = (
    <div className="client-portal-brand">
      {settings?.company_logo_url ? <img src={settings.company_logo_url} alt={title} /> : <div className="client-portal-logo">3J</div>}
      <h1>{title}</h1>
      <p>{subtitle}</p>
    </div>
  );
  const voucherFormSlot = (
    <form className="client-portal-card" onSubmit={redeem}>
      <div className="mb-3">
        <div className="client-portal-welcome">{settings?.welcome_message || 'Welcome. Please enter your voucher code to start using the internet.'}</div>
      </div>
      {deviceDetected && <div className="alert alert-info py-2 mb-3">Device detected. Enter your voucher to continue.</div>}
      <label className="form-label">Voucher Code</label>
      <input className="form-control form-control-lg text-center voucher-input" autoComplete="one-time-code" value={voucherCode} onChange={(e) => setVoucherCode(e.target.value.toUpperCase())} placeholder="3J-ABCD-2345" required />
      <button className="btn btn-primary btn-lg w-100 mt-3" disabled={loading}>{loading ? 'Checking...' : 'Redeem / Connect'}</button>
      {result && !(timerExpired && result.status === 'SUCCESS') && <div className={`alert mt-3 mb-0 ${result.status === 'SUCCESS' ? 'alert-success' : 'alert-danger'}`}>{result.message}</div>}
      {result?.authorization_status === 'FAILED' && <button className="btn btn-outline-primary w-100 mt-3" type="button" onClick={() => setResult(null)}>Try Again</button>}
      {result?.status === 'SUCCESS' && continueUrl && !timerExpired && <a className="btn btn-success w-100 mt-3" href={continueUrl}>Continue to Internet</a>}
      <button className="btn btn-outline-secondary w-100 mt-2" type="button" onClick={checkStatus} disabled={loading}>Check Status</button>
      {hasAccessWindow && <div className={`client-portal-status client-portal-timer-card mt-3 ${timerExpired ? 'is-expired' : connected ? 'is-connected' : 'is-loaded'}`}>
        <div className="client-portal-timer-icon"><IconClock size={34} /></div>
        <div className="client-portal-timer-copy">
          <div className="client-portal-timer-label">{unlimited ? 'Access Status' : 'Remaining Time'}</div>
          <div className="client-portal-timer-value">{unlimited ? 'Unlimited' : formatCountdown(timerRemaining)}</div>
          <div className={`client-portal-timer-state ${timerExpired ? 'text-danger' : connected ? 'text-success' : 'text-blue'}`}>
            {timerExpired ? 'Time fully consumed' : connected ? 'Connected' : 'Access loaded'}
          </div>
        </div>
        {validUntil && <div className="client-portal-timer-valid">Valid until {formatPortalDateTime(validUntil)}</div>}
        {timerExpired && <div className="alert alert-warning py-2 mt-3 mb-0">Your voucher time has been fully consumed. Enter a new voucher to continue.</div>}
      </div>}
    </form>
  );
  const helpSlot = (
    <div className="client-portal-help">
      <p>{settings?.support_text || 'Need a voucher? Ask the nearest vendo/operator.'}</p>
      <p>If your voucher is valid but internet does not start, disconnect and reconnect to WiFi.</p>
      {settings?.terms_note && <p>{settings.terms_note}</p>}
      {settings?.show_powered_by !== false && <div className="client-portal-powered">Powered by 3JCentralPisowifi</div>}
    </div>
  );
  const template = settings?.custom_html;

  return (
    <div className="client-portal-page">
      {settings?.custom_css && <style>{settings.custom_css}</style>}
      <div className="client-portal-shell">
        {template
          ? renderPortalTemplate(template, { brand: brandSlot, voucher_form: voucherFormSlot, help: helpSlot })
          : <>{brandSlot}{voucherFormSlot}{helpSlot}</>}
      </div>
    </div>
  );
}

function Login({ onLogin, branding }) {
  const [form, setForm] = useState(() => (shouldPrefillDevLogin() ? DEV_LOGIN_PREFILL : { username: '', password: '' }));
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    setError('');
    try {
      const data = await request('/auth/login', { method: 'POST', body: JSON.stringify(form) });
      localStorage.setItem('centralwifi_token', data.token);
      onLogin();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="login-page">
      <div className="login-bg">
        <div className="login-grid" />
        <div className="login-orb login-orb-a" />
        <div className="login-orb login-orb-b" />
      </div>
      <div className="page page-center login-shell">
        <div className="container-tight py-4">
          <div className="text-center mb-4 login-title">
            <span className="avatar avatar-xl bg-blue-lt text-blue mb-3">3J</span>
            <h1>{branding.display_name}</h1>
            <p>{branding.portal_subtitle}</p>
          </div>
          <form className="card card-md login-card" onSubmit={submit}>
            <div className="card-body">
              <h2 className="h2 text-center mb-4">Sign in to your account</h2>
              {error && <div className="alert alert-danger">{error}</div>}
              <div className="mb-3">
                <label className="form-label">Username</label>
                <input className="form-control" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
              </div>
              <div className="mb-3">
                <label className="form-label">Password</label>
                <input className="form-control" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              </div>
              <button className="btn btn-primary w-100" type="submit">
                <IconKey size={18} className="me-2" /> Sign in
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

function Card({ title, subtitle, children, footer }) {
  return (
    <div className="card">
      <div className="card-header">
        {React.isValidElement(title) && title.type === CardHeaderContent ? title : (
          <div>
            <h3 className="card-title">{title}</h3>
            {subtitle && <div className="text-muted small mt-1">{subtitle}</div>}
          </div>
        )}
      </div>
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  );
}

function CardHeaderContent({ children }) {
  return children;
}

function AutoDismissAlert({ message, tone = 'success', onDismiss, timeoutMs = 6000 }) {
  useEffect(() => {
    if (!message || !onDismiss) return undefined;
    const timer = window.setTimeout(() => onDismiss(), timeoutMs);
    return () => window.clearTimeout(timer);
  }, [message, onDismiss, timeoutMs]);
  if (!message) return null;
  return (
    <div className={`alert alert-${tone} auto-dismiss-alert mb-0 d-flex align-items-start justify-content-between gap-3`}>
      <div>{message}</div>
      {onDismiss && (
        <button className="btn-close" type="button" aria-label="Close" onClick={onDismiss} />
      )}
    </div>
  );
}

function Table({ rows, columns }) {
  if (!rows.length) return <div className="empty">No records yet.</div>;
  return (
    <div className="table-responsive table-sticky-wrap">
      <table className="table card-table table-vcenter text-nowrap">
        <thead>
          <tr>{columns.map((column) => <th key={column}>{column.replaceAll('_', ' ')}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>{columns.map((column) => <td key={column}>{fmt(row[column])}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function KpiCard({ icon: Icon, label, value, tone }) {
  return (
    <div className="col-sm-6 col-lg-3">
      <div className="card">
        <div className="card-body">
          <div className="d-flex align-items-center">
            <span className={`badge bg-${tone}-lt text-${tone} me-3 header-icon-badge`}><Icon size={20} /></span>
            <div>
              <div className="text-muted small">{label}</div>
              <div className="h2 mb-0">{value}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Dashboard({ data }) {
  const stats = data?.stats || {};
  const health = data?.health || {};
  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          Current build focus: Captive Portal + Voucher access. WPA2-Enterprise testing is available under Advanced Tools.
        </div>
      </div>
      <KpiCard icon={IconDatabase} label="System Status" value={health.database ? 'Online' : 'Offline'} tone="green" />
      <KpiCard icon={IconActivity} label="Active Sessions" value={stats.active_sessions || 0} tone="red" />
      <KpiCard icon={IconWifi} label="Connected Devices" value={stats.active_sessions || 0} tone="purple" />
      <KpiCard icon={IconKey} label="Vouchers" value="Next" tone="yellow" />
      <KpiCard icon={IconWallet} label="Wallet Credits" value="Tracked" tone="green" />
      <KpiCard icon={IconWifi} label="Captive Portal Status" value="Planned" tone="blue" />
      <KpiCard icon={IconServer} label="Omada Controller Status" value="Operational" tone="cyan" />
      <KpiCard icon={IconRouter} label="Network Devices" value={stats.nas_clients || 0} tone="orange" />
      <div className="col-12">
        <Card title="Recent Access Events" subtitle="Recent backend access decisions and test outcomes">
          <Table rows={data?.recent_auth || []} columns={['username', 'nas_ip', 'calling_station_id', 'result', 'reply_message', 'created_at']} />
        </Card>
      </div>
    </div>
  );
}

function UsersPage({ refresh }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: '', password: '', phone_number: '' });
  const [manage, setManage] = useState({ user_id: '', status: 'active', password: '' });
  const [tab, setTab] = useState('all');
  const [query, setQuery] = useState('');
  const [pageNo, setPageNo] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);
  const pageSize = 25;

  async function load() { setUsers(await request('/users')); }
  useEffect(() => { load(); }, []);

  async function create(e) {
    e.preventDefault();
    await request('/users', { method: 'POST', body: JSON.stringify(form) });
    setForm({ username: '', password: '', phone_number: '' });
    setCreateOpen(false);
    await load(); refresh();
  }

  async function updateUser(e) {
    e.preventDefault();
    const body = { status: manage.status };
    if (manage.password) body.password = manage.password;
    await request(`/users/${manage.user_id}`, { method: 'PATCH', body: JSON.stringify(body) });
    setManage({ user_id: '', status: 'active', password: '' });
    setManageOpen(false);
    await load(); refresh();
  }

  function openManage(user) {
    setManage({ user_id: user.id, status: user.status || 'active', password: '' });
    setManageOpen(true);
  }

  const counts = {
    all: users.length,
    active: users.filter((user) => user.status === 'active').length,
    disabled: users.filter((user) => user.status === 'disabled').length,
    balance: users.filter(needsBalance).length
  };
  const filtered = users.filter((user) => {
    const text = `${user.username || ''} ${user.phone_number || ''} ${user.status || ''}`.toLowerCase();
    const matchesSearch = !query.trim() || text.includes(query.trim().toLowerCase());
    const matchesTab = tab === 'all'
      || (tab === 'active' && user.status === 'active')
      || (tab === 'disabled' && user.status === 'disabled')
      || (tab === 'balance' && needsBalance(user));
    return matchesSearch && matchesTab;
  });
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(pageNo, totalPages);
  const visibleRows = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

  return (
    <>
      <div className="card users-card">
        <div className="card-body">
          <div className="d-flex flex-wrap align-items-center justify-content-between mb-3 gap-2">
            <div>
              <h4 className="mb-1">Customers / Accounts <span className="badge bg-azure-lt">{filtered.length}</span></h4>
              <div className="text-muted small">Create, search, disable, and manage customer accounts used by the system.</div>
            </div>
            <div className="d-flex flex-wrap gap-2 align-items-center">
              <span className="badge bg-blue-lt">Total: {counts.all}</span>
              <span className="badge bg-green-lt">Active: {counts.active}</span>
              <span className="badge bg-red-lt">Disabled: {counts.disabled}</span>
              <span className="badge bg-yellow-lt">Needs Balance: {counts.balance}</span>
              <button className="btn btn-primary" type="button" onClick={() => setCreateOpen(true)}><IconUserPlus size={18} className="me-2" />Create Account</button>
            </div>
          </div>

          <ul className="nav nav-tabs users-tabs">
            {[
              ['all', 'All Accounts', 'blue', counts.all],
              ['active', 'Active', 'green', counts.active],
              ['disabled', 'Disabled', 'red', counts.disabled],
              ['balance', 'Needs Balance', 'yellow', counts.balance]
            ].map(([key, label, tone, count]) => (
              <li className="nav-item" key={key}>
                <button className={`nav-link ${tab === key ? 'active' : ''}`} onClick={() => { setTab(key); setPageNo(1); }}>
                  {label} <span className={`badge bg-${tone}-lt ms-1`}>{count}</span>
                </button>
              </li>
            ))}
            <li className="nav-item ms-auto users-search-item">
              <div className="px-2 py-2">
                <div className="input-icon">
                  <input className="form-control form-control-sm" value={query} onChange={(e) => { setQuery(e.target.value); setPageNo(1); }} placeholder="Search" />
                  <span className="input-icon-addon"><IconSearch size={16} /></span>
                </div>
              </div>
            </li>
          </ul>

          <div className="tab-content pt-3">
            <div className="rto-table-shell">
              <div className="rto-table-wrap users-table-wrap">
                <table className="table table-vcenter rto-table users-table">
                  <thead>
                    <tr>
                      <th className="user-col-username">Username</th>
                      <th className="user-col-phone">Phone</th>
                      <th className="user-col-status">Status</th>
                      <th className="user-col-balance">Time Remaining</th>
                      <th className="user-col-valid">Valid Until</th>
                      <th className="user-col-access">Access</th>
                      <th className="user-col-created">Created</th>
                      <th className="text-end user-col-actions">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleRows.map((user) => (
                      <tr key={user.id} className={needsBalance(user) ? 'table-warning' : ''}>
                        <td className="user-col-username"><span className="users-cell-truncate" title={user.username}>{user.username}</span></td>
                        <td className="user-col-phone"><span className="users-cell-truncate" title={user.phone_number || ''}>{user.phone_number || 'n/a'}</span></td>
                        <td className="user-col-status"><span className={`badge ${user.status === 'active' ? 'bg-green-lt' : 'bg-red-lt'}`}>{user.status}</span></td>
                        <td className="user-col-balance">{formatSeconds(user.time_remaining_seconds)}</td>
                        <td className="user-col-valid"><span className="users-cell-truncate" title={user.valid_until || ''}>{user.valid_until || 'n/a'}</span></td>
                        <td className="user-col-access">{user.is_unlimited ? <span className="badge bg-blue-lt">Unlimited</span> : needsBalance(user) ? <span className="badge bg-yellow-lt">Needs Balance</span> : <span className="badge bg-green-lt">Limited</span>}</td>
                        <td className="user-col-created"><span className="users-cell-truncate" title={user.created_at || ''}>{user.created_at || ''}</span></td>
                        <td className="text-end user-col-actions"><button className="btn btn-sm btn-outline-primary" type="button" onClick={() => openManage(user)}>Manage</button></td>
                      </tr>
                    ))}
                    {!visibleRows.length && (
                      <tr><td colSpan="8" className="text-muted p-3">No users found for the selected filter.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="d-flex flex-wrap align-items-center justify-content-between mt-2 gap-2">
              <div className="text-muted small">Showing {filtered.length ? ((safePage - 1) * pageSize) + 1 : 0}-{Math.min(safePage * pageSize, filtered.length)} of {filtered.length}</div>
              <div className="d-flex align-items-center gap-2">
                <span className="text-muted small">Page {safePage} of {totalPages}</span>
                <ul className="pagination pagination-sm mb-0">
                  <li className={`page-item ${safePage <= 1 ? 'disabled' : ''}`}><button className="page-link" onClick={() => setPageNo(Math.max(1, safePage - 1))}>Prev</button></li>
                  <li className={`page-item ${safePage >= totalPages ? 'disabled' : ''}`}><button className="page-link" onClick={() => setPageNo(Math.min(totalPages, safePage + 1))}>Next</button></li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      {createOpen && (
        <Modal title="Create Customer Account" onClose={() => setCreateOpen(false)}>
          <form onSubmit={create}>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Username</label><input className="form-control" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Password</label><input className="form-control" required type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Phone Number</label><input className="form-control" value={form.phone_number} onChange={(e) => setForm({ ...form, phone_number: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0"><button type="button" className="btn" onClick={() => setCreateOpen(false)}>Cancel</button><button className="btn btn-primary"><IconUserPlus size={18} className="me-2" />Create Account</button></div>
          </form>
        </Modal>
      )}

      {manageOpen && (
        <Modal title="Manage Customer Account" onClose={() => setManageOpen(false)}>
          <form onSubmit={updateUser}>
            <div className="row g-3">
              <div className="col-12">
                <label className="form-label">User</label>
                <select className="form-select" value={manage.user_id} onChange={(e) => setManage({ ...manage, user_id: e.target.value })}>
                  <option value="">Select user</option>{users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
                </select>
              </div>
              <div className="col-md-6"><label className="form-label">Status</label><select className="form-select" value={manage.status} onChange={(e) => setManage({ ...manage, status: e.target.value })}><option value="active">Active</option><option value="disabled">Disabled</option></select></div>
              <div className="col-md-6"><label className="form-label">New Password</label><input className="form-control" type="password" value={manage.password} onChange={(e) => setManage({ ...manage, password: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0"><button type="button" className="btn" onClick={() => setManageOpen(false)}>Cancel</button><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save User</button></div>
          </form>
        </Modal>
      )}
    </>
  );
}

function ConnectedDevicesPage() {
  const [data, setData] = useState({ summary: {}, active: [], inactive: [] });
  const [tab, setTab] = useState('active');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const tabs = [
    ['active', 'Active', data.summary?.active || 0, 'green'],
    ['inactive', 'Inactive', data.summary?.inactive || 0, 'secondary']
  ];
  async function load() {
    setLoading(true);
    try {
      setData(await request('/connected-devices'));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); }, []);
  const rows = data[tab] || [];
  const filtered = rows.filter((device) => {
    const text = [
      device.hostname,
      device.username,
      device.client_mac,
      device.client_mac_masked,
      device.client_ip,
      device.ap_name,
      device.ap_ip,
      device.ssid,
      device.site,
      device.source,
      device.raw_status
    ].join(' ').toLowerCase();
    return !query.trim() || text.includes(query.trim().toLowerCase());
  });
  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          Connected Devices shows devices detected from Omada/AP client data when available, plus local RADIUS accounting and portal session records. Voucher management is now the main customer workflow; account management is parked for later.
        </div>
      </div>
      <KpiCard icon={IconWifi} label="Active Devices" value={data.summary?.active || 0} tone="green" />
      <KpiCard icon={IconClock} label="Inactive Devices" value={data.summary?.inactive || 0} tone="secondary" />
      <KpiCard icon={IconRouter} label="Omada Site" value={data.summary?.omada_site_name || data.summary?.omada_site_id || 'Not selected'} tone="blue" />
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title mb-1">Connected Devices</h3>
              <div className="text-muted small">Active means the device is currently detected as connected. Inactive means it was detected before but is no longer currently active.</div>
            </div>
            <div className="card-actions">
              <button className="btn btn-outline-primary" type="button" onClick={load} disabled={loading}><IconRefresh size={18} className="me-2" />Refresh</button>
            </div>
          </div>
          {data.summary?.omada_error && <div className="alert alert-warning m-3 mb-0">Omada client list is not available from the API yet: {data.summary.omada_error}. Showing local detected sessions instead.</div>}
          <div className="card-body border-bottom py-2">
            <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
              <ul className="nav nav-tabs" role="tablist">
                {tabs.map(([key, label, count, tone]) => (
                  <li className="nav-item" role="presentation" key={key}>
                    <button type="button" className={`nav-link ${tab === key ? 'active' : ''}`} onClick={() => setTab(key)} role="tab" aria-selected={tab === key}>
                      {label} <span className={`badge bg-${tone}-lt ms-1`}>{count}</span>
                    </button>
                  </li>
                ))}
              </ul>
              <div className="input-icon connected-devices-search">
                <input className="form-control form-control-sm" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search devices" />
                <span className="input-icon-addon"><IconSearch size={16} /></span>
              </div>
            </div>
          </div>
          <div className="table-responsive">
            <table className="table card-table table-vcenter text-nowrap">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>MAC</th>
                  <th>IP</th>
                  <th>AP / Antenna</th>
                  <th>SSID</th>
                  <th>Site</th>
                  <th>Source</th>
                  <th>Last Seen</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((device, index) => (
                  <tr key={`${device.client_mac || device.id || index}-${device.source || ''}`}>
                    <td>
                      <div className="fw-semibold">{device.hostname || device.username || 'Unknown device'}</div>
                      {device.session_id && <div className="text-muted small">{device.session_id}</div>}
                    </td>
                    <td><code>{device.client_mac_masked || device.client_mac || 'n/a'}</code></td>
                    <td>{device.client_ip || 'n/a'}</td>
                    <td>{device.ap_name || device.ap_ip || device.ap_mac || 'n/a'}</td>
                    <td>{device.ssid || 'n/a'}</td>
                    <td>{device.site || 'n/a'}</td>
                    <td><span className="badge bg-blue-lt">{device.source || 'LOCAL'}</span></td>
                    <td>{fmt(device.last_seen || device.connected_since)}</td>
                    <td><span className={`badge ${device.active ? 'bg-green-lt' : 'bg-secondary-lt'}`}>{device.status || (device.active ? 'ACTIVE' : 'INACTIVE')}</span></td>
                  </tr>
                ))}
                {!filtered.length && <tr><td colSpan="9" className="text-muted p-4">No {tab} devices detected yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function LocationMapPreview({ location }) {
  const hasCoordinates = location && location.latitude !== null && location.latitude !== undefined && location.longitude !== null && location.longitude !== undefined;
  if (!location) {
    return <div className="alert alert-info mb-0">Select a location to preview it on the map.</div>;
  }
  if (!hasCoordinates) {
    return <div className="alert alert-warning mb-0">This location has no latitude and longitude yet. Add coordinates in Location Management to show the map.</div>;
  }
  const lat = Number(location.latitude);
  const lon = Number(location.longitude);
  const delta = 0.01;
  const src = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - delta}%2C${lat - delta}%2C${lon + delta}%2C${lat + delta}&layer=mapnik&marker=${lat}%2C${lon}`;
  return (
    <div>
      <div className="ratio ratio-16x9 rounded border overflow-hidden location-map-frame">
        <iframe title="Selected location map" src={src} loading="lazy" />
      </div>
      <div className="text-muted small mt-2">
        {location.address || 'Saved location'} {location.barangay || location.municipality ? `- ${[location.barangay, location.municipality].filter(Boolean).join(', ')}` : ''}
      </div>
    </div>
  );
}

function sitesDeploymentInitialTab() {
  return new URLSearchParams(window.location.search).get('tab') === 'configurations' ? 'Configurations' : 'Sites';
}

function SitesDeploymentsPage() {
  const [activeTab, setActiveTab] = useState(sitesDeploymentInitialTab);
  const [sites, setSites] = useState([]);
  const [locations, setLocations] = useState([]);
  const [options, setOptions] = useState({ general: { country_region: 'Philippines', time_zone: 'Asia/Manila' }, application_scenarios: ['Office'] });
  const [deploymentConfig, setDeploymentConfig] = useState({ configuration: DEFAULT_AP_SITE_CONFIG, sites: [], logs: [] });
  const [configForm, setConfigForm] = useState(DEFAULT_AP_SITE_CONFIG);
  const [configBusy, setConfigBusy] = useState('');
  const [configResult, setConfigResult] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editSite, setEditSite] = useState(null);
  const [deleteSiteTarget, setDeleteSiteTarget] = useState(null);
  const [deleteSiteAps, setDeleteSiteAps] = useState([]);
  const [deleteSiteLoading, setDeleteSiteLoading] = useState(false);
  const [deleteSiteError, setDeleteSiteError] = useState('');
  const [deletingSite, setDeletingSite] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [form, setForm] = useState({
    site_name: '',
    application_scenario: 'Office',
    device_account_username: 'threejap',
    device_account_password: '',
    location_id: '',
    location: '',
    address: '',
    municipality: '',
    barangay: '',
    latitude: '',
    longitude: '',
    contact_name: '',
    contact_phone: '',
    notes: ''
  });
  const [editForm, setEditForm] = useState({
    location_id: '',
    contact_name: '',
    contact_phone: '',
    notes: ''
  });
  async function load() {
    const [siteRows, locationRows, optionRows, configRows] = await Promise.all([
      request('/site-deployments'),
      request('/locations'),
      request('/site-deployments/options'),
      request('/site-deployments/configuration')
    ]);
    setSites(siteRows);
    setLocations(locationRows);
    setOptions(optionRows);
    setDeploymentConfig(configRows);
    const site_vlans = {};
    (configRows.sites || []).forEach((site) => {
      site_vlans[site.id] = site.vlan_tag ?? '';
    });
    setConfigForm({
      ...DEFAULT_AP_SITE_CONFIG,
      ...(configRows.configuration || {}),
      device_account_password: '',
      security_password: '',
      site_vlans
    });
  }
  useEffect(() => { load(); }, []);
  const selectedLocation = locations.find((item) => item.id === form.location_id);
  const selectedEditLocation = locations.find((item) => item.id === editForm.location_id);
  function goToAddLocation() {
    setModalOpen(false);
    window.history.pushState({ page: 'Location Management' }, '', '/admin/location-management?add=1');
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
  function applyLocation(locationId) {
    if (locationId === '__add_location__') {
      goToAddLocation();
      return;
    }
    const location = locations.find((item) => item.id === locationId);
    setForm({
      ...form,
      location_id: locationId,
      location: location?.location_name || '',
      address: location?.address || form.address,
      municipality: location?.municipality || '',
      barangay: location?.barangay || '',
      latitude: location?.latitude ?? '',
      longitude: location?.longitude ?? ''
    });
  }
  function applyEditLocation(locationId) {
    if (locationId === '__add_location__') {
      setEditSite(null);
      goToAddLocation();
      return;
    }
    setEditForm({ ...editForm, location_id: locationId });
  }
  function startEditSite(site) {
    setError('');
    setMessage('');
    setEditSite(site);
    setEditForm({
      location_id: site.location_id || '',
      contact_name: site.contact_name || '',
      contact_phone: site.contact_phone || '',
      notes: site.notes || ''
    });
  }
  function generateDevicePassword() {
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower = 'abcdefghijkmnopqrstuvwxyz';
    const digits = '23456789';
    const symbols = '!@#$%*';
    const all = upper + lower + digits + symbols;
    const bytes = new Uint32Array(14);
    window.crypto.getRandomValues(bytes);
    const chars = [
      upper[bytes[0] % upper.length],
      lower[bytes[1] % lower.length],
      digits[bytes[2] % digits.length],
      symbols[bytes[3] % symbols.length],
      ...Array.from(bytes.slice(4), (value) => all[value % all.length])
    ];
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = bytes[i % bytes.length] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    setForm({ ...form, device_account_password: chars.join('') });
  }
  async function createSite(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    if (!form.location_id) {
      setError('Select a location first. Use + Add Location if the address is not saved yet.');
      return;
    }
    if (!form.device_account_username || !form.device_account_password) {
      setError('Enter the Omada Device Account username and password. Omada requires these when creating a site.');
      return;
    }
    try {
      const body = {
        ...form,
        latitude: form.latitude === '' ? null : Number(form.latitude),
        longitude: form.longitude === '' ? null : Number(form.longitude),
        country_region: options.general?.country_region || 'Philippines',
        time_zone: options.general?.time_zone || 'Asia/Manila'
      };
      const created = await request('/site-deployments', { method: 'POST', body: JSON.stringify(body) });
      setForm({ site_name: '', application_scenario: 'Office', device_account_username: 'threejap', device_account_password: '', location_id: '', location: '', address: '', municipality: '', barangay: '', latitude: '', longitude: '', contact_name: '', contact_phone: '', notes: '' });
      setModalOpen(false);
      setMessage(created.omada_created ? 'Site created in Omada and saved locally.' : 'Site linked to Omada and saved locally.');
      await load();
    } catch (err) {
      setError(err.message);
    }
  }
  async function updateSite(e) {
    e.preventDefault();
    if (!editSite) return;
    setError('');
    setMessage('');
    try {
      await request(`/site-deployments/${editSite.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          ...editForm,
          location_id: editForm.location_id || null
        })
      });
      setEditSite(null);
      setMessage('Site deployment details updated.');
      await load();
    } catch (err) {
      setError(err.message);
    }
  }
  async function openDeleteSiteModal(site) {
    setError('');
    setMessage('');
    setDeleteSiteTarget(site);
    setDeleteSiteAps([]);
    setDeleteSiteError('');
    setDeleteSiteLoading(true);
    try {
      const data = await request('/ap-deployments/sites');
      const matchedSite = (data.sites || []).find((row) => (
        (site.omada_site_id && row.omada_site_id === site.omada_site_id)
        || row.id === site.id
        || row.site_name === site.site_name
      ));
      setDeleteSiteAps((matchedSite?.aps || []).filter((ap) => ap.local_status !== 'DELETED'));
    } catch (err) {
      setDeleteSiteError(err.message || 'Could not load AP details for this site.');
    } finally {
      setDeleteSiteLoading(false);
    }
  }
  async function confirmDeleteSite() {
    if (!deleteSiteTarget) return;
    setDeletingSite(true);
    setDeleteSiteError('');
    try {
      const query = new URLSearchParams();
      if (deleteSiteTarget.site_name) query.set('site_name', deleteSiteTarget.site_name);
      const data = await request(`/site-deployments/${deleteSiteTarget.id}${query.toString() ? `?${query.toString()}` : ''}`, { method: 'DELETE' });
      const baseMessage = data.omada_deleted
        ? 'Site deleted from Omada and removed locally.'
        : 'Site removed from the Sites list locally.';
      setMessage(`${baseMessage} AP deployment history remains in the system.${data.warning ? ` ${data.warning}` : ''}`);
      setDeleteSiteTarget(null);
      setDeleteSiteAps([]);
      await load();
    } catch (err) {
      setDeleteSiteError(err.message);
    } finally {
      setDeletingSite(false);
    }
  }
  async function saveDeploymentConfig(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    setConfigResult(null);
    setConfigBusy('save');
    try {
      const site_vlans = {};
      (deploymentConfig.sites || []).forEach((site) => {
        const value = configForm.site_vlans?.[site.id];
        site_vlans[site.id] = value === '' || value === null || value === undefined ? null : Number(value);
      });
      const payload = {
        ...configForm,
        site_vlans
      };
      const data = await request('/site-deployments/configuration', { method: 'PUT', body: JSON.stringify(payload) });
      setMessage(data.message || 'Sites configuration saved.');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setConfigBusy('');
    }
  }
  async function applyDeploymentConfigNow() {
    setError('');
    setMessage('');
    setConfigResult(null);
    setConfigBusy('apply');
    try {
      const data = await request('/site-deployments/configuration/apply', { method: 'POST', body: JSON.stringify({}) });
      setConfigResult(data);
      if (data.status === 'SUCCESS') setMessage(data.message || 'Configuration apply completed.');
      else setError(data.message || 'Configuration apply completed with errors.');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setConfigBusy('');
    }
  }
  function setSiteVlan(siteId, value) {
    setConfigForm({
      ...configForm,
      site_vlans: {
        ...(configForm.site_vlans || {}),
        [siteId]: value
      }
    });
  }
  const counts = {
    total: sites.length,
    omadaLinked: sites.filter((site) => site.omada_site_id).length,
    savedLocations: locations.length,
    withCoordinates: sites.filter((site) => site.latitude !== null && site.latitude !== undefined && site.longitude !== null && site.longitude !== undefined).length
  };
  const deleteConnectedAps = deleteSiteAps.filter((ap) => ap.local_status === 'CONNECTED').length;
  const deleteClientTotal = deleteSiteAps.reduce((sum, ap) => sum + Number(ap.client_count || 0), 0);
  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          Sites shows Omada Controller sites plus the local address and map coordinates used for planning WiFi locations. Manage reusable addresses in Location Management first.
        </div>
      </div>
      {message && <div className="col-12"><div className="alert alert-success">{message}</div></div>}
      {error && <div className="col-12"><div className="alert alert-danger">{error}</div></div>}
      <div className="col-12">
        <div className="card">
          <div className="card-body py-2">
            <ul className="nav nav-tabs card-header-tabs">
              {['Sites', 'Configurations'].map((tab) => (
                <li className="nav-item" key={tab}>
                  <button className={`nav-link ${activeTab === tab ? 'active' : ''}`} type="button" onClick={() => setActiveTab(tab)}>{tab}</button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      {activeTab === 'Sites' && <>
      <KpiCard icon={IconRouter} label="Total Sites" value={counts.total} tone="blue" />
      <KpiCard icon={IconWifi} label="Omada Linked" value={counts.omadaLinked} tone="green" />
      <KpiCard icon={IconMapPin} label="Saved Locations" value={counts.savedLocations} tone="cyan" />
      <KpiCard icon={IconDatabase} label="With Coordinates" value={counts.withCoordinates} tone="purple" />
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title mb-1">Sites</h3>
              <div className="text-muted small">Omada sites and their physical address details.</div>
            </div>
            <div className="card-actions">
              <button className="btn btn-primary" type="button" onClick={() => setModalOpen(true)}><IconUserPlus size={18} className="me-2" />Add Site</button>
            </div>
          </div>
          <div className="table-responsive">
            <table className="table card-table table-vcenter text-nowrap site-deployments-table">
              <thead>
                <tr>
                  <th>Site Name</th>
                  <th>Scenario</th>
                  <th>Connected APs</th>
                  <th>VLAN</th>
                  <th>Address</th>
                  <th>Municipality</th>
                  <th>Barangay</th>
                  <th>Coordinates</th>
                  <th>Omada Site ID</th>
                  <th>Source</th>
                  <th>Contact</th>
                  <th>Notes</th>
                  <th>Created At</th>
                  <th className="site-actions-col text-end">Action</th>
                </tr>
              </thead>
              <tbody>
                {sites.map((site) => (
                  <tr key={site.id}>
                    <td>
                      <div className="fw-semibold">{site.site_name}</div>
                      {site.location && <div className="text-muted small">{site.location}</div>}
                    </td>
                    <td>{site.application_scenario || 'n/a'}</td>
                    <td>
                      <span className="badge bg-green-lt">{site.ap_connected_count ?? 0}</span>
                      {site.ap_total_count !== undefined && site.ap_total_count !== null && site.ap_total_count !== site.ap_connected_count && <span className="text-muted small ms-1">of {site.ap_total_count}</span>}
                      {site.ap_error && <span className="text-muted small ms-1">unavailable</span>}
                    </td>
                    <td>{site.vlan_tag ? <span className="badge bg-blue-lt text-blue">VLAN {site.vlan_tag}</span> : <span className="badge bg-secondary-lt text-secondary">No VLAN</span>}</td>
                    <td>{site.address || 'n/a'}</td>
                    <td>{site.municipality || 'n/a'}</td>
                    <td>{site.barangay || 'n/a'}</td>
                    <td>{site.latitude !== null && site.latitude !== undefined && site.longitude !== null && site.longitude !== undefined ? <code>{Number(site.latitude).toFixed(6)}, {Number(site.longitude).toFixed(6)}</code> : <span className="text-muted">n/a</span>}</td>
                    <td>{site.omada_site_id ? <code>{site.omada_site_id}</code> : <span className="text-muted">Not linked</span>}</td>
                    <td><span className={`badge ${site.is_omada_detected ? 'bg-cyan-lt' : site.omada_site_id ? 'bg-green-lt' : 'bg-blue-lt'}`}>{site.is_omada_detected ? 'Omada' : site.omada_site_id ? 'Local + Omada' : 'Local'}</span></td>
                    <td>{site.contact_name || site.contact_phone ? <><div>{site.contact_name || 'n/a'}</div><div className="text-muted small">{site.contact_phone || ''}</div></> : 'n/a'}</td>
                    <td><span className="text-muted">{site.notes || ''}</span></td>
                    <td>{fmt(site.created_at)}</td>
                    <td className="site-actions-col text-end">
                      <div className="btn-list justify-content-end flex-nowrap">
                        <button className="btn btn-icon" type="button" title="Edit site" onClick={() => startEditSite(site)}><IconEdit size={18} /></button>
                        <button className="btn btn-icon btn-outline-danger" type="button" title="Delete site" onClick={() => openDeleteSiteModal(site)}><IconTrash size={18} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
                {!sites.length && <tr><td colSpan="14" className="text-muted p-4">No sites added yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      </>}
      {activeTab === 'Configurations' && (
        <div className="col-12">
          <form className="card" onSubmit={saveDeploymentConfig}>
            <div className="card-header">
              <div>
                <h3 className="card-title mb-1">AP Deployment Configurations</h3>
                <div className="text-muted small">These settings are stored once and applied to APs after they are adopted and connected. Adoption credentials are not changed before adoption.</div>
              </div>
              <div className="card-actions">
                <button className="btn btn-outline-primary me-2" type="button" onClick={applyDeploymentConfigNow} disabled={!!configBusy}>
                  <IconRefresh size={18} className="me-2" />Apply Now
                </button>
                <button className="btn btn-primary" disabled={!!configBusy}>
                  <IconDeviceFloppy size={18} className="me-2" />Save Configurations
                </button>
              </div>
            </div>
            <div className="card-body">
              <div className="alert alert-info">
                After an AP is added and Omada reports it as connected, 3JCentralPisowifi will apply the device account, SSID, security, and site VLAN tag. For captive portal, the AP site VLAN must match the Customer VLAN ID configured on the MikroTik router serving that site.
              </div>
              {configResult && <div className={`alert ${configResult.status === 'SUCCESS' ? 'alert-success' : 'alert-warning'}`}>{configResult.message}</div>}
              <div className="row g-4">
                <div className="col-lg-6">
                  <div className="border rounded p-3 h-100">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <div>
                        <div className="fw-semibold">Device Account Credentials</div>
                        <div className="text-muted small">Applied only after the AP is adopted and connected.</div>
                      </div>
                      <label className="form-check form-switch mb-0">
                        <input className="form-check-input" type="checkbox" checked={configForm.auto_apply_enabled} onChange={(e) => setConfigForm({ ...configForm, auto_apply_enabled: e.target.checked })} />
                        <span className="form-check-label">Auto apply</span>
                      </label>
                    </div>
                    <div className="row g-3">
                      <div className="col-md-6">
                        <label className="form-label">Device Account Username</label>
                        <input className="form-control" value={configForm.device_account_username || ''} onChange={(e) => setConfigForm({ ...configForm, device_account_username: e.target.value })} placeholder="threejap" />
                      </div>
                      <div className="col-md-6">
                        <label className="form-label">Device Account Password</label>
                        <input className="form-control" type="text" value={configForm.device_account_password || ''} onChange={(e) => setConfigForm({ ...configForm, device_account_password: e.target.value })} placeholder={deploymentConfig.configuration?.has_device_account_password ? 'Saved - enter to replace' : 'Enter password'} />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-lg-6">
                  <div className="border rounded p-3 h-100">
                    <div className="fw-semibold mb-1">SSID and Security</div>
                    <div className="text-muted small mb-3">Use one SSID for both bands to enable band steering, or separate names for 2.4GHz and 5GHz.</div>
                    <div className="row g-3">
                      <div className="col-12">
                        <label className="form-check">
                          <input className="form-check-input" type="checkbox" checked={configForm.use_same_ssid} onChange={(e) => setConfigForm({ ...configForm, use_same_ssid: e.target.checked, band_steering_enabled: e.target.checked ? true : configForm.band_steering_enabled })} />
                          <span className="form-check-label">Use the same SSID for 2.4GHz and 5GHz</span>
                        </label>
                      </div>
                      {configForm.use_same_ssid ? (
                        <div className="col-12">
                          <label className="form-label">SSID Name</label>
                          <input className="form-control" value={configForm.same_ssid_name || ''} onChange={(e) => setConfigForm({ ...configForm, same_ssid_name: e.target.value })} />
                          <div className="text-muted small mt-1">Band steering will be requested from Omada for this SSID.</div>
                        </div>
                      ) : (
                        <>
                          <div className="col-md-6"><label className="form-label">2.4GHz SSID</label><input className="form-control" value={configForm.ssid_2g || ''} onChange={(e) => setConfigForm({ ...configForm, ssid_2g: e.target.value })} /></div>
                          <div className="col-md-6"><label className="form-label">5GHz SSID</label><input className="form-control" value={configForm.ssid_5g || ''} onChange={(e) => setConfigForm({ ...configForm, ssid_5g: e.target.value })} /></div>
                        </>
                      )}
                      <div className="col-md-6">
                        <label className="form-label">Security</label>
                        <select className="form-select" value={configForm.security_mode || 'OPEN'} onChange={(e) => setConfigForm({ ...configForm, security_mode: e.target.value })}>
                          <option value="OPEN">Open</option>
                          <option value="WPA2_PSK">WPA2 Personal</option>
                          <option value="WPA_WPA2_PSK">WPA/WPA2 Personal</option>
                        </select>
                      </div>
                      {configForm.security_mode !== 'OPEN' && (
                        <div className="col-md-6">
                          <label className="form-label">WiFi Password</label>
                          <input className="form-control" type="text" value={configForm.security_password || ''} onChange={(e) => setConfigForm({ ...configForm, security_password: e.target.value })} placeholder={deploymentConfig.configuration?.has_security_password ? 'Saved - enter to replace' : 'Enter WiFi password'} />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                <div className="col-12">
                  <div className="border rounded">
	                    <div className="p-3 border-bottom">
	                      <div className="fw-semibold">Site VLAN Tags</div>
	                      <div className="text-muted small">Set each site to the same VLAN used by its MikroTik router. This VLAN is what the AP SSID will tag for customer captive portal traffic.</div>
	                      {!!(deploymentConfig.mikrotik_vlans || []).length && (
	                        <div className="mt-2 d-flex flex-wrap gap-2">
	                          {(deploymentConfig.mikrotik_vlans || []).map((router) => (
	                            <span className="badge bg-blue-lt text-blue" key={router.router_id}>
	                              {router.router_name || router.host}: VLAN {router.vlan_id}
	                            </span>
	                          ))}
	                        </div>
	                      )}
	                    </div>
                    <div className="table-responsive">
                      <table className="table table-vcenter mb-0">
                        <thead><tr><th>Site</th><th>Omada Site ID</th><th style={{ width: '14rem' }}>VLAN Tag</th></tr></thead>
                        <tbody>
                          {(deploymentConfig.sites || []).map((site) => (
                            <tr key={site.id}>
                              <td className="fw-semibold">{site.site_name}</td>
                              <td>{site.omada_site_id ? <code>{site.omada_site_id}</code> : <span className="text-muted">Not linked</span>}</td>
                              <td><input className="form-control" type="number" min="1" max="4094" placeholder="Match MikroTik VLAN" value={configForm.site_vlans?.[site.id] ?? ''} onChange={(e) => setSiteVlan(site.id, e.target.value)} /></td>
                            </tr>
                          ))}
                          {!(deploymentConfig.sites || []).length && <tr><td colSpan="3" className="text-muted p-4">No saved sites yet.</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
                <div className="col-12">
                  <div className="border rounded">
                    <div className="p-3 border-bottom">
                      <div className="fw-semibold">Recent Configuration Logs</div>
                    </div>
                    <div className="table-responsive">
                      <table className="table table-vcenter mb-0">
                        <thead><tr><th>Time</th><th>Site</th><th>AP</th><th>Status</th><th>Message</th></tr></thead>
                        <tbody>
                          {(deploymentConfig.logs || []).map((log) => (
                            <tr key={log.id}>
                              <td>{fmt(log.created_at)}</td>
                              <td>{log.site_name || log.omada_site_id || 'n/a'}</td>
                              <td>{log.ap_mac_masked || 'n/a'}</td>
                              <td><span className={`badge ${log.status === 'SUCCESS' ? 'bg-green-lt text-green' : log.status === 'FAILED' ? 'bg-red-lt text-red' : 'bg-blue-lt text-blue'}`}>{log.status}</span></td>
                              <td>{log.message || ''}</td>
                            </tr>
                          ))}
                          {!(deploymentConfig.logs || []).length && <tr><td colSpan="5" className="text-muted p-4">No AP configuration logs yet.</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </form>
        </div>
      )}
      {modalOpen && (
        <Modal title="Add Site" onClose={() => setModalOpen(false)}>
          <form onSubmit={createSite}>
            {error && <div className="alert alert-danger">{error}</div>}
            <div className="alert alert-info">Saving a new site creates it in Omada Controller first. The Omada Site ID is returned by Omada and saved automatically.</div>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Site Name</label><input className="form-control" required value={form.site_name} onChange={(e) => setForm({ ...form, site_name: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Application Scenario</label><select className="form-select" required value={form.application_scenario} onChange={(e) => setForm({ ...form, application_scenario: e.target.value })}>{(options.application_scenarios || ['Office']).map((scenario) => <option key={scenario} value={scenario}>{scenario}</option>)}</select></div>
              <div className="col-12"><div className="alert alert-secondary mb-0">Country / Region and Time Zone come from System Settings - General: {options.general?.country_region || 'Philippines'} / {options.general?.time_zone || 'Asia/Manila'}.</div></div>
              <div className="col-12">
                <div className="border rounded p-3">
                  <div className="fw-semibold mb-1">Omada Device Account</div>
                  <div className="text-muted small mb-3">Omada requires this per-site device account when creating a site. It is sent to Omada for site creation and is not displayed after saving.</div>
                  <div className="row g-3">
                    <div className="col-md-5"><label className="form-label">Device Account Username</label><input className="form-control" required value={form.device_account_username} onChange={(e) => setForm({ ...form, device_account_username: e.target.value })} /></div>
                    <div className="col-md-5"><label className="form-label">Device Account Password</label><input className="form-control" type="text" required value={form.device_account_password} onChange={(e) => setForm({ ...form, device_account_password: e.target.value })} /></div>
                    <div className="col-md-2 d-flex align-items-end"><button type="button" className="btn w-100" onClick={generateDevicePassword}>Generate</button></div>
                    <div className="col-12"><div className="text-muted small">Password must include uppercase, lowercase, number, and symbol.</div></div>
                  </div>
                </div>
              </div>
              <div className="col-12">
                <label className="form-label">Location</label>
                <select className="form-select" required value={form.location_id} onChange={(e) => applyLocation(e.target.value)}>
                  <option value="" disabled>Select location</option>
                  {locations.map((location) => <option key={location.id} value={location.id}>{location.location_name || location.address}</option>)}
                  <option value="__add_location__">+ Add Location</option>
                </select>
              </div>
              <div className="col-12">
                <LocationMapPreview location={selectedLocation} />
              </div>
              <div className="col-md-6"><label className="form-label">Contact Name</label><input className="form-control" value={form.contact_name} onChange={(e) => setForm({ ...form, contact_name: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Contact Phone</label><input className="form-control" value={form.contact_phone} onChange={(e) => setForm({ ...form, contact_phone: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Notes</label><textarea className="form-control" rows="3" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0"><button type="button" className="btn" onClick={() => setModalOpen(false)}>Cancel</button><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Site</button></div>
          </form>
        </Modal>
      )}
      {editSite && (
        <Modal title="Edit Site" onClose={() => setEditSite(null)}>
          <form onSubmit={updateSite}>
            {error && <div className="alert alert-danger">{error}</div>}
            <div className="alert alert-info">This edits local deployment details for the selected Omada site. Omada site name and application scenario remain managed by Omada.</div>
            <div className="row g-3">
              <div className="col-md-6">
                <label className="form-label">Site Name</label>
                <input className="form-control" value={editSite.site_name || ''} readOnly />
              </div>
              <div className="col-md-6">
                <label className="form-label">Omada Site ID</label>
                <input className="form-control" value={editSite.omada_site_id || 'Not linked'} readOnly />
              </div>
              <div className="col-12">
                <label className="form-label">Location</label>
                <select className="form-select" value={editForm.location_id} onChange={(e) => applyEditLocation(e.target.value)}>
                  <option value="">No saved location</option>
                  {locations.map((location) => <option key={location.id} value={location.id}>{location.location_name || location.address}</option>)}
                  <option value="__add_location__">+ Add Location</option>
                </select>
              </div>
              <div className="col-12">
                <LocationMapPreview location={selectedEditLocation} />
              </div>
              <div className="col-md-6"><label className="form-label">Contact Name</label><input className="form-control" value={editForm.contact_name} onChange={(e) => setEditForm({ ...editForm, contact_name: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Contact Phone</label><input className="form-control" value={editForm.contact_phone} onChange={(e) => setEditForm({ ...editForm, contact_phone: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Notes</label><textarea className="form-control" rows="3" value={editForm.notes} onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0"><button type="button" className="btn" onClick={() => setEditSite(null)}>Cancel</button><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Changes</button></div>
          </form>
        </Modal>
      )}
      {deleteSiteTarget && (
        <Modal title={`Delete Site: ${deleteSiteTarget.site_name}`} onClose={() => !deletingSite && setDeleteSiteTarget(null)}>
          <div className="alert alert-danger">
            Confirm that you want to delete this site. {deleteSiteTarget.omada_site_id ? 'This will attempt to delete the site from Omada Controller. If Omada does not support remote deletion, the site will still be hidden from this system and the Omada limitation will be shown as a warning.' : 'This site is local only.'}
          </div>
          {deleteSiteError && <div className="alert alert-warning">{deleteSiteError}</div>}
          <div className="row g-3 mb-3">
            <div className="col-md-4">
              <div className="border rounded p-3 h-100">
                <div className="text-muted small">APs in this Site</div>
                <div className="h2 mb-0">{deleteSiteLoading ? '...' : deleteSiteAps.length}</div>
              </div>
            </div>
            <div className="col-md-4">
              <div className="border rounded p-3 h-100">
                <div className="text-muted small">Connected APs</div>
                <div className="h2 mb-0">{deleteSiteLoading ? '...' : deleteConnectedAps}</div>
              </div>
            </div>
            <div className="col-md-4">
              <div className="border rounded p-3 h-100">
                <div className="text-muted small">Connected Clients</div>
                <div className="h2 mb-0">{deleteSiteLoading ? '...' : deleteClientTotal}</div>
              </div>
            </div>
          </div>
          <div className="alert alert-info">
            Deleting a site does not erase AP history from 3JCentralPisowifi. AP records, custom AP names, previous site data, and configuration history remain in the system. The APs may disconnect when the Omada site is deleted, but if those APs are adopted again later, the system will continue from the saved AP identity and can show both previous and new site associations.
          </div>
          <div className="border rounded mb-3">
            <div className="p-3 border-bottom">
              <div className="fw-semibold">APs affected by this site deletion</div>
              <div className="text-muted small">Client count is the latest value reported by Omada or the local AP deployment cache.</div>
            </div>
            <div className="table-responsive">
              <table className="table table-vcenter mb-0">
                <thead>
                  <tr>
                    <th>AP</th>
                    <th>MAC</th>
                    <th>Status</th>
                    <th>Clients</th>
                    <th>Configuration</th>
                  </tr>
                </thead>
                <tbody>
                  {deleteSiteAps.map((ap) => (
                    <tr key={ap.id || ap.mac}>
                      <td>
                        <div className="fw-semibold">{ap.display_name || ap.name || 'Unnamed AP'}</div>
                        {ap.model && <div className="text-muted small">{ap.model}</div>}
                      </td>
                      <td><code>{ap.mac || 'n/a'}</code></td>
                      <td>{apStatusBadge(ap.status)}</td>
                      <td>{ap.client_count ?? 0}</td>
                      <td>
                        <span className={`badge ${ap.configuration_status === 'APPLIED' ? 'bg-green-lt text-green' : ap.configuration_status === 'FAILED' ? 'bg-red-lt text-red' : 'bg-blue-lt text-blue'}`}>
                          {ap.configuration_status || 'PENDING'}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {!deleteSiteLoading && !deleteSiteAps.length && <tr><td colSpan="5" className="text-muted p-4">No APs are currently recorded for this site.</td></tr>}
                  {deleteSiteLoading && <tr><td colSpan="5" className="text-muted p-4">Loading AP details...</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
          <div className="modal-footer px-0 pb-0">
            <button type="button" className="btn" disabled={deletingSite} onClick={() => setDeleteSiteTarget(null)}>Cancel</button>
            <button type="button" className="btn btn-danger" disabled={deletingSite} onClick={confirmDeleteSite}>
              <IconTrash size={18} className="me-2" />{deletingSite ? 'Deleting...' : 'Delete Site'}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function formatOmadaTimestamp(value) {
  if (value === null || value === undefined || value === '') return 'n/a';
  if (typeof value === 'number') return new Date(value).toLocaleString();
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 1000000000) return new Date(numeric).toLocaleString();
  return fmt(value);
}

function apStatusBadge(status) {
  const text = String(status || 'Unknown');
  const lower = text.toLowerCase();
  if (lower.includes('connected') || lower.includes('online')) return <span className="badge bg-green-lt text-green">{text}</span>;
  if (lower.includes('pending')) return <span className="badge bg-yellow-lt text-yellow">{text}</span>;
  if (lower.includes('failed')) return <span className="badge bg-red-lt text-red">{text}</span>;
  if (lower.includes('managed')) return <span className="badge bg-orange-lt text-orange">{text}</span>;
  if (lower.includes('disconnected')) return <span className="badge bg-secondary-lt text-secondary">{text}</span>;
  return <span className="badge bg-blue-lt text-blue">{text}</span>;
}

function isConnectedAp(ap) {
  const status = String(ap?.status || '').toLowerCase();
  return status === 'connected' || status === 'online' || ap?.status_code === 14 || ap?.status_category === 1;
}

function isVisibleAp(ap) {
  return isConnectedAp(ap) || ['ADOPTING', 'ADOPT_FAILED'].includes(ap?.local_status);
}

function ListOfApsPage() {
  const [sites, setSites] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalSite, setModalSite] = useState(null);
  const [editAp, setEditAp] = useState(null);
  const [editName, setEditName] = useState('');
  const [detected, setDetected] = useState([]);
  const [selected, setSelected] = useState({});
  const [apNames, setApNames] = useState({});
  const [detecting, setDetecting] = useState(false);
  const [adopting, setAdopting] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [detectError, setDetectError] = useState('');
  const [adoptCredentials, setAdoptCredentials] = useState({ username: '', password: '' });

  async function load(silent = false) {
    if (!silent) setLoading(true);
    if (!silent) setError('');
    try {
      const data = await request('/ap-deployments/sites');
      setSites(data.sites || []);
      if (data.omada_error) setError(`Omada API is not ready: ${data.omada_error}`);
    } catch (err) {
      if (!silent) setError(err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }

  async function detectAps(site) {
    setDetecting(true);
    setDetectError('');
    setSelected({});
    try {
      const query = site?.omada_site_id ? `?site_id=${encodeURIComponent(site.omada_site_id)}` : '';
      const data = await request(`/ap-deployments/detected${query}`);
      const rows = data.aps || [];
      setDetected(rows);
      const names = {};
      rows.forEach((ap) => {
        if (ap.mac) names[ap.mac] = ap.display_name || ap.name || ap.mac_bound_name || '';
      });
      setApNames(names);
      if (data.status === 'FAILED') setDetectError(data.error || data.message || 'Omada AP auto-detection failed.');
    } catch (err) {
      setDetected([]);
      setDetectError(err.message);
    } finally {
      setDetecting(false);
    }
  }

  function openAddAps(site) {
    setModalSite(site);
    setDetected([]);
    setSelected({});
    setApNames({});
    setDetectError('');
    setAdoptCredentials({ username: '', password: '' });
    detectAps(site);
  }

  function toggleAp(mac, checked) {
    setSelected((current) => ({ ...current, [mac]: checked }));
  }

  function toggleAll(checked) {
    const next = {};
    detected.forEach((ap) => {
      if (ap.mac && ap.adoptable !== false) next[ap.mac] = checked;
    });
    setSelected(next);
  }

  async function adoptSelectedAps() {
    const ap_macs = Object.entries(selected).filter(([, value]) => value).map(([mac]) => mac);
    if (!modalSite?.omada_site_id || !ap_macs.length) return;
    setAdopting(true);
    setDetectError('');
    try {
      await request('/ap-deployments/adopt', {
        method: 'POST',
        body: JSON.stringify({
          site_id: modalSite.omada_site_id,
          ap_macs,
          ap_names: apNames,
          username: adoptCredentials.username || null,
          password: adoptCredentials.password || null
        })
      });
      setMessage(`Adoption submitted for ${ap_macs.length} AP${ap_macs.length === 1 ? '' : 's'} in ${modalSite.site_name}.`);
      setModalSite(null);
      await load();
    } catch (err) {
      setDetectError(err.message);
    } finally {
      setAdopting(false);
    }
  }

  function openEditAp(ap) {
    setEditAp(ap);
    setEditName(ap.display_name || ap.name || ap.mac_bound_name || '');
  }

  async function saveApName(e) {
    e.preventDefault();
    if (!editAp) return;
    setError('');
    try {
      await request(`/ap-deployments/${editAp.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ display_name: editName })
      });
      setEditAp(null);
      setMessage('AP name updated.');
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function retryAp(ap) {
    setError('');
    try {
      const result = await request(`/ap-deployments/${ap.id}/retry`, { method: 'POST' });
      if (result.status === 'FAILED') setError(result.message);
      else setMessage('AP adoption retry submitted.');
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function deleteAp(ap) {
    if (!window.confirm(`Delete AP "${ap.display_name || ap.name}" from this site?`)) return;
    setError('');
    try {
      const result = await request(`/ap-deployments/${ap.id}`, { method: 'DELETE' });
      if (result.omada_error) setError(`AP was removed from this system, but Omada delete/forget was not confirmed: ${result.omada_error}`);
      else setMessage('AP deleted.');
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => { load(); }, []);
  useEffect(() => {
    const timer = window.setInterval(() => {
      load(true).catch(() => {});
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const totalSites = sites.length;
  const connectedAps = sites.reduce((sum, site) => sum + (site.aps || []).filter(isConnectedAp).length, 0);
  const provisioningAps = sites.reduce((sum, site) => sum + (site.aps || []).filter((ap) => ap.local_status === 'ADOPTING').length, 0);
  const pendingAps = sites.reduce((sum, site) => sum + Number(site.pending_ap_count || 0), 0);
  const selectedCount = Object.values(selected).filter(Boolean).length;
  const adoptableDetectedCount = detected.filter((ap) => ap.adoptable !== false).length;

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          List of APs shows connected Omada access points grouped by site. APs that are pending adoption are only shown after clicking Add APs.
        </div>
      </div>
      {message && <div className="col-12"><div className="alert alert-success">{message}</div></div>}
      {error && <div className="col-12"><div className="alert alert-warning">{error}</div></div>}
      <KpiCard icon={IconMapPin} label="Sites" value={totalSites} tone="blue" />
      <KpiCard icon={IconActivity} label="Connected APs" value={connectedAps} tone="green" />
      <KpiCard icon={IconRefresh} label="Provisioning APs" value={provisioningAps} tone="orange" />
      <KpiCard icon={IconWifi} label="Pending APs" value={pendingAps} tone="yellow" />
      <div className="col-12">
        <div className="d-flex justify-content-end mb-2">
          <button className="btn btn-outline-primary" type="button" onClick={load} disabled={loading}><IconRefresh size={18} className="me-2" />Refresh</button>
        </div>
      </div>
      {sites.map((site) => (
        <div className="col-12" key={site.id || site.omada_site_id || site.site_name}>
          <div className="card ap-site-card">
            <div className="card-header">
              <div>
                <h3 className="card-title mb-1">{site.site_name}</h3>
                <div className="text-muted small">{site.address || site.location || 'No saved address'}{site.omada_site_id ? ` · Omada site ${site.omada_site_id}` : ''}</div>
              </div>
              <div className="card-actions">
                <button className="btn btn-primary" type="button" onClick={() => openAddAps(site)} disabled={!site.omada_site_id}>
                  <IconWifi size={18} className="me-2" />Add APs | Pending: {site.pending_ap_count ?? 0}
                </button>
              </div>
            </div>
            {site.ap_error && <div className="alert alert-warning m-3 mb-0">AP list unavailable from Omada: {site.ap_error}</div>}
            {site.pending_ap_error && <div className="alert alert-warning m-3 mb-0">Pending AP count unavailable from Omada: {site.pending_ap_error}</div>}
            <div className="ap-table-wrap">
              <table className="table card-table table-vcenter ap-table">
                <thead>
                  <tr>
                    <th className="ap-col-name">AP</th>
                    <th className="ap-col-mac">MAC</th>
                    <th className="ap-col-model">Model</th>
                    <th className="ap-col-ip">IP</th>
                    <th className="ap-col-status">Status</th>
                    <th className="ap-col-clients text-center">Clients</th>
                    <th className="ap-col-firmware">Firmware</th>
                    <th className="ap-col-uptime">Uptime</th>
                    <th className="ap-col-last-seen">Last Seen</th>
                    <th className="ap-col-actions text-end">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(site.aps || []).filter(isVisibleAp).map((ap) => (
                    <tr key={ap.id || ap.mac || ap.name} className={ap.local_status === 'ADOPTING' ? 'ap-row-provisioning' : ''}>
                      <td>
                        <div className="fw-semibold">{ap.display_name || ap.name || ap.mac_bound_name || 'Unnamed AP'}</div>
                        {ap.serial_number && <div className="text-muted small">SN {ap.serial_number}</div>}
                        {ap.last_error && <div className="text-danger small">{ap.last_error}</div>}
                      </td>
                      <td><code>{ap.mac || 'n/a'}</code></td>
                      <td>{ap.model || 'n/a'}</td>
                      <td>{ap.ip || 'n/a'}</td>
                      <td>{apStatusBadge(ap.status)}</td>
                      <td className="text-center">{ap.client_count ?? 0}</td>
                      <td title={ap.firmware_version || 'n/a'}>
                        <span className="ap-firmware-text">{truncateWithEllipsis(ap.firmware_version, 10)}</span>
                      </td>
                      <td>{ap.uptime || 'n/a'}</td>
                      <td>{formatOmadaTimestamp(ap.last_seen)}</td>
                      <td className="text-end">
                        <div className="ap-action-list" aria-label="AP actions">
                          <button className="ap-action-badge" type="button" onClick={() => openEditAp(ap)} title="Edit AP name" aria-label="Edit AP name">
                            <IconEdit size={15} />
                          </button>
                          {ap.local_status === 'ADOPT_FAILED' && (
                            <button className="ap-action-badge ap-action-badge-warning" type="button" onClick={() => retryAp(ap)} title="Retry adoption" aria-label="Retry adoption">
                              <IconRefresh size={15} />
                            </button>
                          )}
                          <button className="ap-action-badge ap-action-badge-danger" type="button" onClick={() => deleteAp(ap)} title="Delete AP" aria-label="Delete AP">
                            <IconTrash size={15} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {!(site.aps || []).filter(isVisibleAp).length && <tr><td colSpan="10" className="text-muted p-4">No connected or provisioning APs for this site yet. Pending APs are available through Add APs.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ))}
      {!sites.length && !loading && <div className="col-12"><div className="card"><div className="card-body text-muted">No Omada sites found yet. Add a site under APs Deployment &gt; Sites first.</div></div></div>}
      {modalSite && (
        <Modal title={`Add APs to ${modalSite.site_name}`} onClose={() => setModalSite(null)}>
          <div className="alert alert-info">
            Automatic detection checks Omada for APs waiting to be adopted. Factory-reset APs must be powered on and reachable on the same management network.
          </div>
          {detectError && <div className="alert alert-danger">{detectError}</div>}
          <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
            <div>
              <div className="fw-semibold">Detected APs</div>
              <div className="text-muted small">{detected.length ? `${detected.length} AP${detected.length === 1 ? '' : 's'} found` : 'No adoptable APs detected yet'}</div>
            </div>
            <button className="btn btn-outline-primary" type="button" onClick={() => detectAps(modalSite)} disabled={detecting}>
              <IconRefresh size={18} className="me-2" />{detecting ? 'Detecting...' : 'Run Detection'}
            </button>
          </div>
          <div className="table-responsive border rounded mb-3">
            <table className="table table-vcenter text-nowrap mb-0">
              <thead>
                <tr>
                  <th className="w-1"><input className="form-check-input m-0" type="checkbox" checked={adoptableDetectedCount > 0 && selectedCount === adoptableDetectedCount} onChange={(e) => toggleAll(e.target.checked)} /></th>
                  <th>AP Name</th>
                  <th>MAC</th>
                  <th>Model</th>
                  <th>IP</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {detected.map((ap) => (
                  <tr key={ap.mac || ap.name}>
                    <td><input className="form-check-input m-0" type="checkbox" checked={Boolean(selected[ap.mac])} disabled={ap.adoptable === false || !ap.mac} onChange={(e) => toggleAp(ap.mac, e.target.checked)} /></td>
                    <td>
                      <div className="d-flex align-items-center gap-2">
                        <input className="form-control form-control-sm" value={apNames[ap.mac] || ''} onChange={(e) => setApNames({ ...apNames, [ap.mac]: e.target.value })} placeholder="AP name" />
                        {ap.known_ap && (
                          <span
                            className="known-ap-indicator"
                            title={`Known AP${ap.last_known_site_name ? ` from ${ap.last_known_site_name}` : ''}${ap.last_known_status ? ` · Last status: ${ap.last_known_status}` : ''}`}
                            aria-label={`Known AP${ap.last_known_site_name ? ` from ${ap.last_known_site_name}` : ''}`}
                          >
                            <IconInfoCircle size={16} />
                          </span>
                        )}
                      </div>
                    </td>
                    <td><code>{ap.mac || 'n/a'}</code></td>
                    <td>{ap.model || 'n/a'}</td>
                    <td>{ap.ip || 'n/a'}</td>
                    <td>{apStatusBadge(ap.status)}</td>
                  </tr>
                ))}
                {!detected.length && <tr><td colSpan="6" className="text-muted p-4">No APs are currently pending adoption in Omada.</td></tr>}
              </tbody>
            </table>
          </div>
          <div className="border rounded p-3 mb-3">
            <div className="fw-semibold mb-1">Device Account Credentials</div>
            <div className="text-muted small mb-3">Optional for adoption only. The deployment device account from Sites &gt; Configurations is applied after the AP is adopted and connected.</div>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Username</label><input className="form-control" value={adoptCredentials.username} onChange={(e) => setAdoptCredentials({ ...adoptCredentials, username: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Password</label><input className="form-control" type="text" value={adoptCredentials.password} onChange={(e) => setAdoptCredentials({ ...adoptCredentials, password: e.target.value })} /></div>
            </div>
          </div>
          <div className="modal-footer px-0 pb-0">
            <button type="button" className="btn" onClick={() => setModalSite(null)}>Cancel</button>
            <button type="button" className="btn btn-primary" disabled={!selectedCount || adopting} onClick={adoptSelectedAps}>
              <IconWifi size={18} className="me-2" />{adopting ? 'Submitting...' : `Add Selected APs${selectedCount ? ` (${selectedCount})` : ''}`}
            </button>
          </div>
        </Modal>
      )}
      {editAp && (
        <Modal title="Edit AP Name" onClose={() => setEditAp(null)}>
          <form onSubmit={saveApName}>
            <div className="mb-3">
              <label className="form-label">AP Name</label>
              <input className="form-control" required value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="text-muted small mb-3">MAC: <code>{editAp.mac}</code></div>
            <div className="modal-footer px-0 pb-0">
              <button type="button" className="btn" onClick={() => setEditAp(null)}>Cancel</button>
              <button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save AP Name</button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}

function LongLatMap({ aps, center, zoom, setCenter, setZoom, selectedApId, onSelectAp, onPlaceAp, editable = true, canDragAp = () => true, editingApId = '' }) {
  const mapRef = useRef(null);
  const [size, setSize] = useState({ width: 1024, height: 640 });
  const panRef = useRef(null);

  useEffect(() => {
    if (!mapRef.current) return undefined;
    const updateSize = () => {
      const rect = mapRef.current.getBoundingClientRect();
      setSize({ width: Math.max(320, rect.width), height: Math.max(320, rect.height) });
    };
    updateSize();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateSize);
      return () => window.removeEventListener('resize', updateSize);
    }
    const observer = new ResizeObserver(updateSize);
    observer.observe(mapRef.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const mapEl = mapRef.current;
    if (!mapEl) return undefined;
    const wheelZoom = (e) => {
      e.preventDefault();
      e.stopPropagation();
      setZoom((current) => clamp(current + (e.deltaY < 0 ? 1 : -1), 5, 19));
    };
    mapEl.addEventListener('wheel', wheelZoom, { passive: false });
    return () => mapEl.removeEventListener('wheel', wheelZoom);
  }, [setZoom]);

  const centerPixel = latLngToWorldPixel(center.latitude, center.longitude, zoom);
  const topLeft = {
    x: centerPixel.x - size.width / 2,
    y: centerPixel.y - size.height / 2
  };
  const maxTile = 2 ** zoom;
  const tiles = [];
  const minTileX = Math.floor(topLeft.x / MAP_TILE_SIZE) - 1;
  const maxTileX = Math.floor((topLeft.x + size.width) / MAP_TILE_SIZE) + 1;
  const minTileY = Math.max(0, Math.floor(topLeft.y / MAP_TILE_SIZE) - 1);
  const maxTileY = Math.min(maxTile - 1, Math.floor((topLeft.y + size.height) / MAP_TILE_SIZE) + 1);
  for (let x = minTileX; x <= maxTileX; x += 1) {
    const wrappedX = ((x % maxTile) + maxTile) % maxTile;
    for (let y = minTileY; y <= maxTileY; y += 1) {
      tiles.push({
        key: `${x}-${y}`,
        url: `https://tile.openstreetmap.org/${zoom}/${wrappedX}/${y}.png`,
        left: x * MAP_TILE_SIZE - topLeft.x,
        top: y * MAP_TILE_SIZE - topLeft.y
      });
    }
  }

  function screenToLatLng(clientX, clientY) {
    const rect = mapRef.current.getBoundingClientRect();
    return worldPixelToLatLng(topLeft.x + clientX - rect.left, topLeft.y + clientY - rect.top, zoom);
  }

  function startMapDrag(e) {
    if (e.button !== 0 || e.target.closest('.longlat-map-marker') || e.target.closest('.longlat-map-control')) return;
    panRef.current = { x: e.clientX, y: e.clientY };
    e.currentTarget.setPointerCapture?.(e.pointerId);
  }

  function moveMap(e) {
    if (!panRef.current) return;
    const dx = e.clientX - panRef.current.x;
    const dy = e.clientY - panRef.current.y;
    panRef.current = { x: e.clientX, y: e.clientY };
    setCenter((current) => {
      const currentPixel = latLngToWorldPixel(current.latitude, current.longitude, zoom);
      return worldPixelToLatLng(currentPixel.x - dx, currentPixel.y - dy, zoom);
    });
  }

  function stopMapDrag() {
    panRef.current = null;
  }

  function handleDrop(e) {
    e.preventDefault();
    if (!editable || !onPlaceAp) return;
    const apId = e.dataTransfer.getData('text/ap-id') || e.dataTransfer.getData('text/plain');
    if (!apId) return;
    onPlaceAp(apId, screenToLatLng(e.clientX, e.clientY));
  }

  return (
    <div
      className="longlat-map"
      ref={mapRef}
      onDragOver={editable ? (e) => e.preventDefault() : undefined}
      onDrop={editable ? handleDrop : undefined}
      onPointerDown={startMapDrag}
      onPointerMove={moveMap}
      onPointerUp={stopMapDrag}
      onPointerCancel={stopMapDrag}
    >
      {tiles.map((tile) => (
        <img className="longlat-map-tile" key={tile.key} src={tile.url} alt="" style={{ left: tile.left, top: tile.top }} draggable={false} />
      ))}
      {aps.filter((ap) => ap.mapped).map((ap) => {
        const point = latLngToWorldPixel(ap.map_latitude, ap.map_longitude, zoom);
        const left = point.x - topLeft.x;
        const top = point.y - topLeft.y;
        const tone = apMapTone(ap);
        const markerDraggable = editable && canDragAp(ap);
        const markerEditing = editingApId === ap.id;
        return (
          <button
            key={ap.id}
            type="button"
            draggable={markerDraggable}
            className={`longlat-map-marker longlat-marker-${tone} ${markerDraggable ? 'is-draggable' : 'is-locked'} ${markerEditing ? 'is-editing' : ''} ${selectedApId === ap.id ? 'is-selected' : ''}`}
            style={{ left, top }}
            title={`${ap.display_name || ap.name || 'AP'} · ${apMapStatusText(ap)}`}
            onClick={() => onSelectAp(ap)}
            onDragStart={markerDraggable ? (e) => {
              e.dataTransfer.effectAllowed = 'move';
              e.dataTransfer.setData('text/ap-id', ap.id);
              e.dataTransfer.setData('text/plain', ap.id);
            } : undefined}
          >
            <span className="longlat-marker-pulse" />
            <span className="longlat-marker-core"><IconWifi size={15} /></span>
          </button>
        );
      })}
      <div className="longlat-map-controls">
        <button className="longlat-map-control" type="button" onClick={() => setZoom((current) => clamp(current + 1, 5, 19))}>+</button>
        <button className="longlat-map-control" type="button" onClick={() => setZoom((current) => clamp(current - 1, 5, 19))}>-</button>
      </div>
      <div className="longlat-map-legend">
        <span><i className="legend-dot legend-green" />With clients</span>
        <span><i className="legend-dot legend-gray" />No clients</span>
        <span><i className="legend-dot legend-red" />AP error</span>
      </div>
    </div>
  );
}

function LongLatApCard({ ap, mapped, selected, onSelect, compact = false, canDrag = true, action = null, locked = false }) {
  const tone = apMapTone(ap);
  return (
    <div
      role="button"
      tabIndex={0}
      className={`longlat-ap-card ${compact ? 'longlat-ap-card-compact' : ''} ${locked ? 'longlat-ap-card-locked' : ''} ${selected ? 'active' : ''}`}
      draggable={canDrag}
      onClick={() => onSelect(ap)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(ap);
        }
      }}
      onDragStart={canDrag ? (e) => {
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/ap-id', ap.id);
        e.dataTransfer.setData('text/plain', ap.id);
      } : undefined}
    >
      <span className={`longlat-ap-status-dot longlat-status-${tone}`} />
      <span className="longlat-ap-card-body">
        <span className="fw-semibold">{ap.display_name || ap.name || ap.mac_bound_name || 'Unnamed AP'}</span>
        <span className="text-muted small">{ap.site_name || 'No site'}</span>
        {!compact && (
          <>
            <span className="small">{apMapStatusText(ap)}</span>
            {mapped && <span className="text-muted small">{formatCoordinate(ap.map_latitude)}, {formatCoordinate(ap.map_longitude)}</span>}
            {ap.map_error && <span className="text-danger small">{ap.map_error}</span>}
          </>
        )}
      </span>
      {action ? <span className="longlat-ap-card-action" onClick={(e) => e.stopPropagation()}>{action}</span> : (!compact && <span className="longlat-ap-drag-hint">{mapped ? 'Move' : 'Drag'}</span>)}
    </div>
  );
}

function LongLatDetailsPanel({ ap, onClose, onCenter }) {
  if (!ap?.mapped) return null;
  const tone = apMapTone(ap);
  const streetViewUrl = streetViewEmbedUrl(ap);
  const mapsUrl = mapsSearchUrl(ap);
  return (
    <div className="longlat-detail-panel card">
      <div className="card-header">
        <div className="d-flex align-items-center gap-2 min-w-0">
          <span className={`longlat-ap-status-dot longlat-status-${tone}`} />
          <div className="min-w-0">
            <h3 className="card-title mb-1 text-truncate">{ap.display_name || ap.name || 'Mapped AP'}</h3>
            <div className="text-muted small text-truncate">{ap.site_name || 'No site'} · {ap.mac || 'No MAC'}</div>
          </div>
        </div>
        <button className="btn-close" type="button" aria-label="Close AP details" onClick={onClose} />
      </div>
      <div className="card-body">
        {ap.map_error && <div className="alert alert-danger py-2">{ap.map_error}</div>}
        <div className="longlat-detail-grid">
          <div><span>Status</span><strong>{ap.status || ap.local_status || 'Unknown'}</strong></div>
          <div><span>Clients</span><strong>{ap.client_count ?? 0}</strong></div>
          <div><span>Ping</span><strong>{ap.map_ping_status || 'UNKNOWN'}</strong></div>
          <div><span>Model</span><strong>{ap.model || 'n/a'}</strong></div>
          <div><span>IP</span><strong>{ap.ip || 'n/a'}</strong></div>
          <div><span>Firmware</span><strong title={ap.firmware_version || ''}>{truncateWithEllipsis(ap.firmware_version, 18)}</strong></div>
          <div><span>Latitude</span><strong>{formatCoordinate(ap.map_latitude)}</strong></div>
          <div><span>Longitude</span><strong>{formatCoordinate(ap.map_longitude)}</strong></div>
        </div>
        <div className="longlat-streetview mt-3">
          <div className="d-flex align-items-center justify-content-between mb-2">
            <div className="fw-semibold">Street View</div>
            {mapsUrl && <a className="btn btn-sm btn-outline-primary" href={mapsUrl} target="_blank" rel="noreferrer"><IconExternalLink size={15} className="me-1" />Open</a>}
          </div>
          {streetViewUrl ? (
            <iframe title={`Street view for ${ap.display_name || ap.name || 'AP'}`} src={streetViewUrl} loading="lazy" referrerPolicy="no-referrer-when-downgrade" />
          ) : (
            <div className="empty">Street view needs mapped coordinates.</div>
          )}
        </div>
      </div>
      <div className="card-footer d-flex gap-2">
        <button className="btn btn-primary flex-fill" type="button" onClick={() => onCenter(ap)}><IconMapPin size={18} className="me-2" />Center Map</button>
      </div>
    </div>
  );
}

function BandwidthLineChart({ samples = [] }) {
  const points = samples.length ? samples : [{ download: 0, upload: 0 }];
  const width = 340;
  const height = 112;
  const pad = 12;
  const maxValue = Math.max(1, ...points.map((item) => Number(item.download || 0)), ...points.map((item) => Number(item.upload || 0)));
  const buildPath = (key) => points.map((item, index) => {
    const x = points.length === 1 ? width - pad : pad + (index * (width - (pad * 2))) / (points.length - 1);
    const y = height - pad - ((Number(item[key] || 0) / maxValue) * (height - (pad * 2)));
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
  return (
    <div className="ap-client-chart">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="AP bandwidth usage line chart">
        <path className="ap-client-chart-grid" d={`M ${pad} ${height - pad} H ${width - pad} M ${pad} ${height / 2} H ${width - pad} M ${pad} ${pad} H ${width - pad}`} />
        <path className="ap-client-chart-download" d={buildPath('download')} />
        <path className="ap-client-chart-upload" d={buildPath('upload')} />
      </svg>
      <div className="ap-client-chart-legend">
        <span><i className="legend-line legend-download" />Download</span>
        <span><i className="legend-line legend-upload" />Upload</span>
      </div>
    </div>
  );
}

function ApClientMapDetailsPanel({ ap, samples, onClose, onCenter }) {
  if (!ap?.mapped) return null;
  const tone = apMapTone(ap);
  const clients = ap.clients || [];
  const activeClients = clients.filter((client) => client.active);
  const radio2g = ap.radio_stats?.['2g'] || ap.radio_2g || {};
  const radio5g = ap.radio_stats?.['5g'] || ap.radio_5g || {};
  const streetViewUrl = streetViewEmbedUrl(ap);
  const mapsUrl = mapsSearchUrl(ap);
  const infoItems = [
    { icon: IconActivity, label: 'Status', value: ap.status || ap.local_status || 'Unknown' },
    { icon: IconUsers, label: 'Active Clients', value: activeClients.length || ap.active_client_count || ap.client_count || 0 },
    { icon: IconRouter, label: 'Model', value: ap.model || 'n/a' },
    { icon: IconServer, label: 'IP Address', value: ap.ip || 'n/a' },
    { icon: IconClock, label: 'Uptime', value: ap.uptime || (ap.uptime_seconds ? formatUptime(ap.uptime_seconds) : 'n/a') },
    { icon: IconCpu, label: 'CPU', value: formatPercent(ap.cpu_util) },
    { icon: IconDatabase, label: 'Memory', value: formatPercent(ap.mem_util) },
    { icon: IconSettings, label: 'VLAN', value: ap.vlan_tag ? `VLAN ${ap.vlan_tag}` : 'No VLAN' }
  ];
  const panel = (
    <div className="longlat-detail-panel card ap-client-detail-panel">
      <div className="card-header ap-client-detail-header">
        <div className="d-flex align-items-center gap-2 min-w-0">
          <span className={`longlat-ap-status-dot longlat-status-${tone}`} />
          <div className="min-w-0">
            <h3 className="card-title mb-1 text-truncate">{ap.display_name || ap.name || 'Mapped AP'}</h3>
            <div className="text-muted small text-truncate">{ap.site_name || 'No site'} · {ap.mac || 'No MAC'}</div>
          </div>
        </div>
        <button className="btn btn-icon btn-outline-secondary ap-client-detail-close" type="button" aria-label="Close AP details" title="Close AP details" onClick={onClose}>
          <IconX size={18} />
        </button>
      </div>
      <div className="card-body">
        {ap.map_error && <div className="alert alert-danger py-2">{ap.map_error}</div>}
        <div className="ap-client-info-card">
          {infoItems.map((item) => {
            const InfoIcon = item.icon;
            return (
              <div className="ap-client-info-item" key={item.label}>
                <span className="ap-client-info-icon"><InfoIcon size={17} /></span>
                <span className="ap-client-info-text">
                  <span>{item.label}</span>
                  <strong title={String(item.value)}>{item.value}</strong>
                </span>
              </div>
            );
          })}
        </div>

        <div className="ap-client-section">
          <div className="fw-semibold mb-2">SSID Broadcast</div>
          <div className="ap-client-ssid-grid">
            <div><span>2.4GHz</span><strong>{ap.ssid_2g || 'Not configured'}</strong><small>{ap.client_count_2g ?? 0} clients</small></div>
            <div><span>5GHz</span><strong>{ap.ssid_5g || 'Not configured'}</strong><small>{(Number(ap.client_count_5g || 0) + Number(ap.client_count_5g2 || 0)) || 0} clients</small></div>
          </div>
          <div className="ap-client-radio-row">
            <span>2.4GHz channel: <strong>{radio2g.actualChannel || radio2g.channel || 'Auto'}</strong></span>
            <span>5GHz channel: <strong>{radio5g.actualChannel || radio5g.channel || 'Auto'}</strong></span>
          </div>
        </div>

        <div className="ap-client-section">
          <div className="d-flex align-items-center justify-content-between mb-2">
            <div className="fw-semibold">Bandwidth Usage</div>
            <div className="text-muted small">{formatDataRate(ap.download)} down · {formatDataRate(ap.upload)} up</div>
          </div>
          <BandwidthLineChart samples={samples} />
        </div>

        <div className="ap-client-section">
          <div className="d-flex align-items-center justify-content-between mb-2">
            <div className="fw-semibold">Street View</div>
            {mapsUrl && <a className="btn btn-sm btn-outline-primary" href={mapsUrl} target="_blank" rel="noreferrer"><IconExternalLink size={15} className="me-1" />Open</a>}
          </div>
          <div className="longlat-streetview ap-client-streetview">
            {streetViewUrl ? (
              <iframe title={`Street view for ${ap.display_name || ap.name || 'AP'}`} src={streetViewUrl} loading="lazy" referrerPolicy="no-referrer-when-downgrade" />
            ) : (
              <div className="empty">Street view needs mapped coordinates.</div>
            )}
          </div>
        </div>

        <div className="ap-client-section">
          <div className="d-flex align-items-center justify-content-between mb-2">
            <div className="fw-semibold">Connected Clients</div>
            <span className="badge bg-green-lt text-green">{activeClients.length} active</span>
          </div>
          <div className="ap-client-list">
            {clients.map((client) => (
              <div className="ap-client-row" key={`${client.client_mac || client.client_ip || client.hostname}-${client.source}`}>
                <div className="min-w-0">
                  <div className="fw-semibold text-truncate">{client.hostname || 'Unknown device'}</div>
                  <div className="text-muted small text-truncate">{client.client_ip || 'No IP'} · {client.client_mac_masked || client.client_mac || 'No MAC'}</div>
                  <div className="text-muted small text-truncate">{client.ssid || 'No SSID'}{client.rssi ? ` · ${client.rssi} dBm` : ''}{client.channel ? ` · Ch ${client.channel}` : ''}</div>
                </div>
                <div className="text-end">
                  <span className={`badge ${client.active ? 'bg-green-lt text-green' : 'bg-secondary-lt text-secondary'}`}>{client.active ? 'Active' : 'Inactive'}</span>
                  <div className="text-muted small mt-1">{formatClientRate(client.rx_rate)} / {formatClientRate(client.tx_rate)}</div>
                </div>
              </div>
            ))}
            {!clients.length && <div className="empty p-3">{Number(ap.client_count || 0) > 0 ? `Omada reports ${ap.client_count} connected client${Number(ap.client_count) === 1 ? '' : 's'}, but detailed client rows are not available from the controller API yet.` : 'No clients are currently reported for this AP.'}</div>}
          </div>
        </div>
      </div>
      <div className="card-footer d-flex gap-2">
        <button className="btn btn-primary flex-fill" type="button" onClick={() => onCenter(ap)}><IconMapPin size={18} className="me-2" />Center Map</button>
      </div>
    </div>
  );
  return createPortal(panel, document.body);
}

function LongLatPage() {
  const [data, setData] = useState({ aps: [], mapped: [], unmapped: [], site_centers: [], summary: {} });
  const [siteRows, setSiteRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [savingId, setSavingId] = useState('');
  const [tab, setTab] = useState('unmapped');
  const [selectedApId, setSelectedApId] = useState('');
  const [siteFilter, setSiteFilter] = useState(() => longLatFilterFromLocation());
  const [floatingMenuVisible, setFloatingMenuVisible] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [relocatingApId, setRelocatingApId] = useState('');
  const [pendingRelocation, setPendingRelocation] = useState(null);
  const [center, setCenter] = useState(DEFAULT_MAP_CENTER);
  const [zoom, setZoom] = useState(DEFAULT_MAP_ZOOM);
  const [bandwidthHistory, setBandwidthHistory] = useState({});
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const centeredFilterKey = useRef('');
  const siteFilterRef = useRef(siteFilter);
  const pendingRelocationRef = useRef(pendingRelocation);

  function centerForFilter(nextData, filter, force = false) {
    const key = `${filter.site_id || 'all'}:${filter.site_name || 'all'}`;
    if (!force && centeredFilterKey.current === key) return;
    const target = bestLongLatCenter(nextData, filter);
    if (!target) return;
    setCenter(target.center);
    setZoom(target.zoom);
    centeredFilterKey.current = key;
  }

  function appendBandwidthSamples(nextData) {
    const timestamp = Date.now();
    setBandwidthHistory((current) => {
      const updated = { ...current };
      (nextData.aps || []).forEach((ap) => {
        const key = ap.id;
        if (!key) return;
        const previous = updated[key] || [];
        updated[key] = [
          ...previous,
          {
            timestamp,
            download: Number(ap.download || ap.traffic?.download || 0),
            upload: Number(ap.upload || ap.traffic?.upload || 0)
          }
        ].slice(-24);
      });
      return updated;
    });
  }

  async function load(silent = false) {
    if (!silent) setLoading(true);
    if (!silent) setError('');
    try {
      const next = await request('/ap-deployments/map');
      setData(next);
      appendBandwidthSamples(next);
      centerForFilter(next, siteFilterRef.current);
      if (next.omada_error) setError(`Omada API is not ready: ${next.omada_error}`);
    } catch (err) {
      if (!silent) setError(err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }

  useEffect(() => {
    load();
    request('/site-deployments').then(setSiteRows).catch(() => setSiteRows([]));
  }, []);
  useEffect(() => {
    document.documentElement.classList.add('longlat-scroll-lock');
    document.body.classList.add('longlat-scroll-lock');
    window.scrollTo(0, 0);
    return () => {
      document.documentElement.classList.remove('longlat-scroll-lock');
      document.body.classList.remove('longlat-scroll-lock');
    };
  }, []);
  useEffect(() => {
    siteFilterRef.current = siteFilter;
  }, [siteFilter.site_id, siteFilter.site_name]);
  useEffect(() => {
    pendingRelocationRef.current = pendingRelocation;
  }, [pendingRelocation]);
  useEffect(() => {
    const syncFilter = () => setSiteFilter(longLatFilterFromLocation());
    window.addEventListener('popstate', syncFilter);
    window.addEventListener('longlat-site-filter-change', syncFilter);
    return () => {
      window.removeEventListener('popstate', syncFilter);
      window.removeEventListener('longlat-site-filter-change', syncFilter);
    };
  }, []);
  useEffect(() => {
    setSelectedApId('');
    setRelocatingApId('');
    setPendingRelocation(null);
    centerForFilter(data, siteFilter, true);
  }, [siteFilter.site_id, siteFilter.site_name]);
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (!pendingRelocationRef.current) load(true).catch(() => {});
    }, 8000);
    return () => window.clearInterval(timer);
  }, []);

  const siteOptions = collectLongLatSites({ ...data, sites: siteRows });
  const selectedSiteValue = siteFilter.site_id ? `id:${siteFilter.site_id}` : (siteFilter.site_name ? `name:${siteFilter.site_name}` : 'all');
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const filteredAps = data.aps.filter((ap) => {
    if (!matchesLongLatSite(ap, siteFilter)) return false;
    if (!normalizedSearch) return true;
    return [
      ap.display_name,
      ap.name,
      ap.mac_bound_name,
      ap.site_name,
      ap.model,
      ap.ip
    ].filter(Boolean).some((value) => String(value).toLowerCase().includes(normalizedSearch));
  });
  const mapped = filteredAps.filter((ap) => ap.mapped);
  const unmapped = filteredAps.filter((ap) => !ap.mapped);
  const visiblePanelAps = tab === 'mapped' ? mapped : unmapped;
  const selectedAp = filteredAps.find((ap) => ap.id === selectedApId);
  const filteredErrorCount = filteredAps.filter((ap) => ap.map_error).length;

  function selectAp(ap) {
    setSelectedApId(ap.id);
    if (ap.mapped) {
      setCenter({ latitude: Number(ap.map_latitude), longitude: Number(ap.map_longitude) });
      setZoom((current) => Math.max(current, 17));
    }
  }

  function changeSiteFilter(e) {
    if (pendingRelocation) revertPendingRelocation(pendingRelocation);
    const value = e.target.value;
    const nextSite = value === 'all'
      ? null
      : siteOptions.find((site) => (site.site_id ? `id:${site.site_id}` : `name:${site.site_name}`) === value);
    const nextFilter = nextSite ? { site_id: nextSite.site_id || '', site_name: nextSite.site_name || '' } : { site_id: '', site_name: '' };
    setSiteFilter(nextFilter);
    setSelectedApId('');
    setRelocatingApId('');
    setPendingRelocation(null);
    window.history.pushState({ page: 'Long Lat' }, '', longLatRouteForSite(nextSite));
  }

  function revertPendingRelocation(pending = pendingRelocation) {
    if (!pending?.original) return;
    setData((current) => ({
      ...current,
      aps: current.aps.map((item) => item.id === pending.apId ? {
        ...item,
        map_latitude: pending.original.latitude,
        map_longitude: pending.original.longitude
      } : item)
    }));
  }

  function startRelocate(ap) {
    if (pendingRelocation) revertPendingRelocation(pendingRelocation);
    setRelocatingApId(ap.id);
    setPendingRelocation(null);
    setSelectedApId(ap.id);
    setCenter({ latitude: Number(ap.map_latitude), longitude: Number(ap.map_longitude) });
    setZoom((current) => Math.max(current, 17));
    setMessage(`${ap.display_name || ap.name || 'AP'} is unlocked for relocation. Drag its blue marker, then click Save Location.`);
    setError('');
  }

  function cancelRelocation() {
    if (pendingRelocation) revertPendingRelocation(pendingRelocation);
    setRelocatingApId('');
    setPendingRelocation(null);
    setMessage('Relocation cancelled.');
    setError('');
  }

  async function saveRelocation() {
    if (!pendingRelocation) {
      setError('Drag the unlocked AP marker to a new position before saving.');
      return;
    }
    const ap = filteredAps.find((item) => item.id === pendingRelocation.apId);
    setSavingId(pendingRelocation.apId);
    setError('');
    setMessage('');
    try {
      await request(`/ap-deployments/${pendingRelocation.apId}/map`, {
        method: 'PATCH',
        body: JSON.stringify({ latitude: pendingRelocation.latitude, longitude: pendingRelocation.longitude })
      });
      setRelocatingApId('');
      setPendingRelocation(null);
      setSelectedApId(pendingRelocation.apId);
      setMessage(`${ap?.display_name || ap?.name || 'AP'} relocated at ${formatCoordinate(pendingRelocation.latitude)}, ${formatCoordinate(pendingRelocation.longitude)}.`);
      await load(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setSavingId('');
    }
  }

  async function placeAp(apId, coordinates) {
    const ap = filteredAps.find((item) => item.id === apId);
    if (!ap) return;
    if (ap.mapped && relocatingApId !== ap.id) {
      setError('Mapped AP locations are locked. Click Relocate before changing coordinates.');
      return;
    }
    const wasMapped = Boolean(ap.mapped);
    if (wasMapped) {
      const existingPending = pendingRelocation?.apId === apId ? pendingRelocation : null;
      const original = existingPending?.original || {
        latitude: Number(ap.map_latitude),
        longitude: Number(ap.map_longitude)
      };
      setPendingRelocation({
        apId,
        latitude: coordinates.latitude,
        longitude: coordinates.longitude,
        original
      });
      setData((current) => ({
        ...current,
        aps: current.aps.map((item) => item.id === apId ? {
          ...item,
          map_latitude: coordinates.latitude,
          map_longitude: coordinates.longitude
        } : item)
      }));
      setSelectedApId(apId);
      setMessage(`New location staged at ${formatCoordinate(coordinates.latitude)}, ${formatCoordinate(coordinates.longitude)}. Click Save Location to apply.`);
      setError('');
      return;
    }
    setSavingId(apId);
    setError('');
    setMessage('');
    try {
      await request(`/ap-deployments/${apId}/map`, {
        method: 'PATCH',
        body: JSON.stringify({ latitude: coordinates.latitude, longitude: coordinates.longitude })
      });
      setData((current) => ({
        ...current,
        aps: current.aps.map((item) => item.id === apId ? {
          ...item,
          mapped: true,
          map_latitude: coordinates.latitude,
          map_longitude: coordinates.longitude,
          map_source: 'MANUAL_MAP',
          mapped_at: new Date().toISOString()
        } : item)
      }));
      setSelectedApId(apId);
      setTab('mapped');
      setRelocatingApId('');
      setMessage(`${ap.display_name || ap.name || 'AP'} ${wasMapped ? 'relocated' : 'mapped'} at ${formatCoordinate(coordinates.latitude)}, ${formatCoordinate(coordinates.longitude)}.`);
      await load(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setSavingId('');
    }
  }

  return (
    <div className={`longlat-page ${floatingMenuVisible ? '' : 'longlat-menu-hidden'}`}>
      <LongLatMap
        aps={filteredAps}
        center={center}
        zoom={zoom}
        setCenter={setCenter}
        setZoom={setZoom}
        selectedApId={selectedApId}
        onSelectAp={selectAp}
        onPlaceAp={placeAp}
        canDragAp={(ap) => relocatingApId === ap.id}
        editingApId={relocatingApId}
      />
      <div className="ap-client-map-kpi-overlay longlat-map-kpi-overlay" aria-label="Long Lat map summary">
        <span className="ap-client-kpi-chip ap-client-kpi-aps"><i><IconWifi size={15} /></i><strong>APs</strong><em>({filteredAps.length})</em></span>
        <span className="ap-client-kpi-chip ap-client-kpi-mapped"><i><IconMapPin size={15} /></i><strong>Mapped</strong><em>({mapped.length})</em></span>
        <span className="ap-client-kpi-chip ap-client-kpi-unmapped"><i><IconInfoCircle size={15} /></i><strong>Unmapped</strong><em>({unmapped.length})</em></span>
        <span className="ap-client-kpi-chip ap-client-kpi-errors"><i><IconAlertTriangle size={15} /></i><strong>Errors</strong><em>({filteredErrorCount})</em></span>
      </div>
      {!floatingMenuVisible && (
        <button
          className="btn btn-primary longlat-floating-toggle"
          type="button"
          onClick={() => setFloatingMenuVisible(true)}
          title="Show Long Lat menu"
        >
          <IconEye size={18} className="me-2" />Show Menu
        </button>
      )}
      {floatingMenuVisible && <div className="longlat-floating-panel card">
        <div className="card-header longlat-panel-header">
          <button className="btn btn-icon btn-outline-secondary longlat-panel-hide" type="button" onClick={() => setFloatingMenuVisible(false)} title="Hide Long Lat menu" aria-label="Hide Long Lat menu">
            <IconChevronLeft size={18} />
          </button>
          <div className="longlat-panel-title">
            <h3 className="card-title mb-1">Long Lat</h3>
            <div className="text-muted small">Map new APs, or unlock mapped APs before relocation.</div>
          </div>
        </div>
        <div className="card-body p-0">
          {(message || error || savingId) && (
            <div className="p-3 pb-0">
              {message && <div className="alert alert-success mb-2">{message}</div>}
              {error && <div className="alert alert-warning mb-2">{error}</div>}
              {savingId && <div className="alert alert-info mb-2">Saving AP coordinates...</div>}
            </div>
          )}
          <div className="ap-client-map-tools">
            <select className="form-select form-select-sm ap-client-filter-select" value={selectedSiteValue} onChange={changeSiteFilter} aria-label="Filter Long Lat map by site">
              <option value="all">Filter: All Sites</option>
              {siteOptions.map((site) => (
                <option key={site.site_id || site.site_name} value={site.site_id ? `id:${site.site_id}` : `name:${site.site_name}`}>
                  {`Filter: ${site.site_name}`}
                </option>
              ))}
            </select>
            <div className="input-icon">
              <span className="input-icon-addon"><IconSearch size={16} /></span>
              <input
                className="form-control form-control-sm"
                type="search"
                placeholder="Search AP or site"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>
          <ul className="nav nav-tabs longlat-tabs">
            <li className="nav-item"><button className={`nav-link ${tab === 'mapped' ? 'active' : ''}`} onClick={() => setTab('mapped')}>Mapped <span className="badge bg-green-lt ms-1">{mapped.length}</span></button></li>
            <li className="nav-item"><button className={`nav-link ${tab === 'unmapped' ? 'active' : ''}`} onClick={() => setTab('unmapped')}>Unmapped <span className="badge bg-yellow-lt ms-1">{unmapped.length}</span></button></li>
          </ul>
          <div className="longlat-panel-list">
            {visiblePanelAps.map((ap) => (
              <LongLatApCard
                key={ap.id}
                ap={ap}
                mapped={tab === 'mapped'}
                selected={selectedApId === ap.id}
                onSelect={selectAp}
                compact
                locked={tab === 'mapped' && relocatingApId !== ap.id}
                canDrag={tab === 'unmapped' || relocatingApId === ap.id}
                action={tab === 'mapped' ? (
                  relocatingApId === ap.id ? (
                    <span className="longlat-relocate-actions">
                      <button className="btn btn-sm btn-primary longlat-relocate-btn" type="button" disabled={!pendingRelocation || pendingRelocation.apId !== ap.id || savingId === ap.id} onClick={saveRelocation}>
                        <IconDeviceFloppy size={14} className="me-1" />Save Location
                      </button>
                      <button className="btn btn-sm btn-outline-secondary longlat-relocate-btn" type="button" disabled={savingId === ap.id} onClick={cancelRelocation}>
                        Cancel
                      </button>
                    </span>
                  ) : (
                    <button className="btn btn-sm btn-outline-primary longlat-relocate-btn" type="button" onClick={() => startRelocate(ap)}>
                      <IconMapPin size={14} className="me-1" />Relocate
                    </button>
                  )
                ) : null}
              />
            ))}
            {!visiblePanelAps.length && <div className="empty p-4">{tab === 'mapped' ? 'No APs are mapped yet.' : 'All detected APs already have coordinates.'}</div>}
          </div>
        </div>
        {selectedAp && (
          <div className="card-footer">
            <div className="fw-semibold">{selectedAp.display_name || selectedAp.name}</div>
            <div className="text-muted small">{selectedAp.site_name || 'No site'} · {selectedAp.mac}</div>
            <div className="small mt-1">{selectedAp.mapped ? `${formatCoordinate(selectedAp.map_latitude)}, ${formatCoordinate(selectedAp.map_longitude)}` : 'Not mapped yet'}</div>
          </div>
        )}
      </div>}
      <ApClientMapDetailsPanel
        ap={selectedAp?.mapped ? selectedAp : null}
        samples={bandwidthHistory[selectedApId] || []}
        onClose={() => setSelectedApId('')}
        onCenter={selectAp}
      />
    </div>
  );
}

function ApClientMapPage() {
  const [data, setData] = useState({ aps: [], mapped: [], unmapped: [], site_centers: [], summary: {} });
  const [siteRows, setSiteRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedApId, setSelectedApId] = useState('');
  const [siteFilter, setSiteFilter] = useState(() => longLatFilterFromLocation());
  const [floatingMenuVisible, setFloatingMenuVisible] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [center, setCenter] = useState(DEFAULT_MAP_CENTER);
  const [zoom, setZoom] = useState(DEFAULT_MAP_ZOOM);
  const [bandwidthHistory, setBandwidthHistory] = useState({});
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const centeredFilterKey = useRef('');
  const siteFilterRef = useRef(siteFilter);

  function centerForFilter(nextData, filter, force = false) {
    const key = `${filter.site_id || 'all'}:${filter.site_name || 'all'}`;
    if (!force && centeredFilterKey.current === key) return;
    const target = bestLongLatCenter(nextData, filter);
    if (!target) return;
    setCenter(target.center);
    setZoom(target.zoom);
    centeredFilterKey.current = key;
  }

  function appendBandwidthSamples(nextData) {
    const timestamp = Date.now();
    setBandwidthHistory((current) => {
      const updated = { ...current };
      (nextData.aps || []).forEach((ap) => {
        const key = ap.id;
        if (!key) return;
        const previous = updated[key] || [];
        updated[key] = [
          ...previous,
          {
            timestamp,
            download: Number(ap.download || ap.traffic?.download || 0),
            upload: Number(ap.upload || ap.traffic?.upload || 0)
          }
        ].slice(-24);
      });
      return updated;
    });
  }

  async function load(silent = false) {
    if (!silent) setLoading(true);
    if (!silent) setError('');
    try {
      const next = await request('/ap-client-map');
      setData(next);
      appendBandwidthSamples(next);
      centerForFilter(next, siteFilterRef.current);
      const errors = next.omada_client_errors || [];
      if (next.omada_error) setError(`Omada API is not ready: ${next.omada_error}`);
      else if (errors.length && !silent) setError('Some Omada client endpoints were not available. Local session data is shown when available.');
    } catch (err) {
      if (!silent) setError(err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }

  useEffect(() => {
    load();
    request('/site-deployments').then(setSiteRows).catch(() => setSiteRows([]));
  }, []);
  useEffect(() => {
    document.documentElement.classList.add('longlat-scroll-lock');
    document.body.classList.add('longlat-scroll-lock');
    window.scrollTo(0, 0);
    return () => {
      document.documentElement.classList.remove('longlat-scroll-lock');
      document.body.classList.remove('longlat-scroll-lock');
    };
  }, []);
  useEffect(() => {
    siteFilterRef.current = siteFilter;
  }, [siteFilter.site_id, siteFilter.site_name]);
  useEffect(() => {
    const syncFilter = () => setSiteFilter(longLatFilterFromLocation());
    window.addEventListener('popstate', syncFilter);
    return () => window.removeEventListener('popstate', syncFilter);
  }, []);
  useEffect(() => {
    setSelectedApId('');
    centerForFilter(data, siteFilter, true);
  }, [siteFilter.site_id, siteFilter.site_name]);
  useEffect(() => {
    const timer = window.setInterval(() => load(true).catch(() => {}), 8000);
    return () => window.clearInterval(timer);
  }, []);

  const siteOptions = collectLongLatSites({ ...data, sites: siteRows });
  const selectedSiteValue = siteFilter.site_id ? `id:${siteFilter.site_id}` : (siteFilter.site_name ? `name:${siteFilter.site_name}` : 'all');
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const filteredAps = data.aps.filter((ap) => {
    if (!ap.mapped) return false;
    if (!matchesLongLatSite(ap, siteFilter)) return false;
    if (!normalizedSearch) return true;
    return [
      ap.display_name,
      ap.name,
      ap.mac_bound_name,
      ap.site_name,
      ap.model,
      ap.ip
    ].filter(Boolean).some((value) => String(value).toLowerCase().includes(normalizedSearch));
  });
  const mapped = filteredAps.filter((ap) => ap.mapped);
  const visiblePanelAps = mapped;
  const selectedAp = mapped.find((ap) => ap.id === selectedApId);
  const filteredClientCount = filteredAps.reduce((sum, ap) => sum + Number(ap.active_client_count ?? ap.client_count ?? 0), 0);
  const filteredErrorCount = filteredAps.filter((ap) => ap.map_error).length;

  function selectAp(ap) {
    setSelectedApId(ap.id);
    if (ap.mapped) {
      setCenter({ latitude: Number(ap.map_latitude), longitude: Number(ap.map_longitude) });
      setZoom((current) => Math.max(current, 17));
    }
  }

  function changeSiteFilter(e) {
    const value = e.target.value;
    const nextSite = value === 'all'
      ? null
      : siteOptions.find((site) => (site.site_id ? `id:${site.site_id}` : `name:${site.site_name}`) === value);
    const nextFilter = nextSite ? { site_id: nextSite.site_id || '', site_name: nextSite.site_name || '' } : { site_id: '', site_name: '' };
    setSiteFilter(nextFilter);
    setSelectedApId('');
    window.history.pushState({ page: 'AP & Client Map' }, '', apClientMapRouteForSite(nextSite));
  }

  return (
    <div className={`longlat-page ap-client-map-page ${floatingMenuVisible ? '' : 'longlat-menu-hidden'}`}>
      <LongLatMap
        aps={filteredAps}
        center={center}
        zoom={zoom}
        setCenter={setCenter}
        setZoom={setZoom}
        selectedApId={selectedApId}
        onSelectAp={selectAp}
        editable={false}
      />
      <div className="ap-client-map-kpi-overlay" aria-label="AP and client map summary">
        <span className="ap-client-kpi-chip ap-client-kpi-aps"><i><IconWifi size={15} /></i><strong>APs</strong><em>({filteredAps.length})</em></span>
        <span className="ap-client-kpi-chip ap-client-kpi-clients"><i><IconUsers size={15} /></i><strong>Clients</strong><em>({filteredClientCount})</em></span>
        <span className="ap-client-kpi-chip ap-client-kpi-mapped"><i><IconMapPin size={15} /></i><strong>Mapped</strong><em>({mapped.length})</em></span>
        <span className="ap-client-kpi-chip ap-client-kpi-errors"><i><IconAlertTriangle size={15} /></i><strong>Errors</strong><em>({filteredErrorCount})</em></span>
      </div>
      {!floatingMenuVisible && (
        <button
          className="btn btn-primary longlat-floating-toggle"
          type="button"
          onClick={() => setFloatingMenuVisible(true)}
          title="Show AP & Client Map menu"
        >
          <IconEye size={18} className="me-2" />Show Menu
        </button>
      )}
      {floatingMenuVisible && <div className="longlat-floating-panel card">
        <div className="card-header longlat-panel-header ap-client-map-panel-header">
          <button className="btn btn-icon btn-outline-secondary longlat-panel-hide" type="button" onClick={() => setFloatingMenuVisible(false)} title="Hide AP & Client Map menu" aria-label="Hide AP & Client Map menu">
            <IconChevronLeft size={18} />
          </button>
          <div className="longlat-panel-title">
            <h3 className="card-title mb-1">AP & Client Map</h3>
            <div className="text-muted small">Map APs, filter by site, and inspect connected clients.</div>
          </div>
        </div>
        <div className="card-body p-0">
          {(message || error || loading) && (
            <div className="p-3 pb-0">
              {message && <div className="alert alert-success mb-2">{message}</div>}
              {error && <div className="alert alert-warning mb-2">{error}</div>}
              {loading && <div className="alert alert-info mb-2">Loading AP and client map...</div>}
            </div>
          )}
          <div className="ap-client-map-tools">
            <select className="form-select form-select-sm ap-client-filter-select" value={selectedSiteValue} onChange={changeSiteFilter} aria-label="Filter AP map by site">
              <option value="all">Filter: All Sites</option>
              {siteOptions.map((site) => (
                <option key={site.site_id || site.site_name} value={site.site_id ? `id:${site.site_id}` : `name:${site.site_name}`}>
                  {`Filter: ${site.site_name}`}
                </option>
              ))}
            </select>
            <div className="input-icon">
              <span className="input-icon-addon"><IconSearch size={16} /></span>
              <input
                className="form-control form-control-sm"
                type="search"
                placeholder="Search AP or site"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>
          <div className="longlat-panel-list">
            {visiblePanelAps.map((ap) => (
              <LongLatApCard key={ap.id} ap={ap} mapped selected={selectedApId === ap.id} onSelect={selectAp} compact canDrag={false} />
            ))}
            {!visiblePanelAps.length && <div className="empty p-4">No mapped APs match the current filter. Use the Long Lat page to map AP coordinates.</div>}
          </div>
        </div>
      </div>}
      <ApClientMapDetailsPanel
        ap={selectedAp?.mapped ? selectedAp : null}
        samples={bandwidthHistory[selectedApId] || []}
        onClose={() => setSelectedApId('')}
        onCenter={selectAp}
      />
    </div>
  );
}

function LocationManagementPage() {
  const emptyForm = {
    location_name: '',
    address: '',
    municipality: '',
    barangay: '',
    province: '',
    region: '',
    latitude: '',
    longitude: '',
    geocode_source: '',
    raw_geocode: null,
    notes: ''
  };
  const [locations, setLocations] = useState([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [searching, setSearching] = useState(false);
  const [saving, setSaving] = useState(false);

  async function load() {
    setLocations(await request('/locations'));
  }

  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('add') === '1') {
      setModalOpen(true);
    }
  }, []);

  async function searchAddress(e) {
    e.preventDefault();
    setError('');
    setSearching(true);
    try {
      const data = await request(`/locations/search?q=${encodeURIComponent(searchQuery)}`);
      setSearchResults(data.results || []);
      if (!(data.results || []).length) setMessage('No address suggestions found. You can enter the address manually.');
    } catch (err) {
      setError(`${err.message}. You can still enter the location manually.`);
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }

  function selectSuggestion(result) {
    setForm({
      ...form,
      location_name: form.location_name || result.barangay || result.municipality || '',
      address: result.address || result.display_name || '',
      municipality: result.municipality || '',
      barangay: result.barangay || '',
      province: result.province || '',
      region: result.region || '',
      latitude: result.latitude ?? '',
      longitude: result.longitude ?? '',
      geocode_source: result.geocode_source || 'NOMINATIM',
      raw_geocode: result.raw_geocode || result
    });
    setSearchResults([]);
  }

  async function createLocation(e) {
    e.preventDefault();
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const body = {
        ...form,
        latitude: form.latitude === '' ? null : Number(form.latitude),
        longitude: form.longitude === '' ? null : Number(form.longitude)
      };
      await request('/locations', { method: 'POST', body: JSON.stringify(body) });
      setForm(emptyForm);
      setSearchQuery('');
      setSearchResults([]);
      setModalOpen(false);
      setMessage('Location saved.');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function deleteLocation(location) {
    if (!window.confirm(`Delete location "${location.location_name || location.address}"?`)) return;
    setError('');
    setMessage('');
    try {
      await request(`/locations/${location.id}`, { method: 'DELETE' });
      setMessage('Location deleted.');
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  const counts = {
    total: locations.length,
    withCoordinates: locations.filter((location) => location.latitude !== null && location.latitude !== undefined && location.longitude !== null && location.longitude !== undefined).length,
    municipalities: new Set(locations.map((location) => location.municipality).filter(Boolean)).size,
    barangays: new Set(locations.map((location) => location.barangay).filter(Boolean)).size
  };

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          Location Management stores reusable addresses for site planning. Search can auto-fill municipality, barangay, latitude, and longitude when the geocoder has a match; manual entry is always available.
        </div>
      </div>
      {message && <div className="col-12"><div className="alert alert-success">{message}</div></div>}
      {error && <div className="col-12"><div className="alert alert-danger">{error}</div></div>}
      <KpiCard icon={IconMapPin} label="Locations" value={counts.total} tone="blue" />
      <KpiCard icon={IconDatabase} label="With Coordinates" value={counts.withCoordinates} tone="green" />
      <KpiCard icon={IconRouter} label="Municipalities" value={counts.municipalities} tone="cyan" />
      <KpiCard icon={IconWifi} label="Barangays" value={counts.barangays} tone="purple" />
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title mb-1">Locations</h3>
              <div className="text-muted small">Saved deployment addresses with municipality, barangay, and coordinates.</div>
            </div>
            <div className="card-actions">
              <button className="btn btn-primary" type="button" onClick={() => setModalOpen(true)}><IconUserPlus size={18} className="me-2" />Add Location</button>
            </div>
          </div>
          <div className="table-responsive">
            <table className="table card-table table-vcenter text-nowrap">
              <thead>
                <tr>
                  <th>Location</th>
                  <th>Address</th>
                  <th>Municipality</th>
                  <th>Barangay</th>
                  <th>Coordinates</th>
                  <th>Source</th>
                  <th>Created At</th>
                  <th className="w-1">Management</th>
                </tr>
              </thead>
              <tbody>
                {locations.map((location) => (
                  <tr key={location.id}>
                    <td className="fw-semibold">{location.location_name || 'Unnamed location'}</td>
                    <td>{location.address}</td>
                    <td>{location.municipality || 'n/a'}</td>
                    <td>{location.barangay || 'n/a'}</td>
                    <td>{location.latitude !== null && location.latitude !== undefined && location.longitude !== null && location.longitude !== undefined ? <code>{Number(location.latitude).toFixed(6)}, {Number(location.longitude).toFixed(6)}</code> : <span className="text-muted">n/a</span>}</td>
                    <td><span className="badge bg-blue-lt">{location.geocode_source || 'MANUAL'}</span></td>
                    <td>{fmt(location.created_at)}</td>
                    <td>
                      <button className="btn btn-icon btn-outline-danger" type="button" onClick={() => deleteLocation(location)} title="Delete location" aria-label="Delete location">
                        <IconTrash size={18} />
                      </button>
                    </td>
                  </tr>
                ))}
                {!locations.length && <tr><td colSpan="8" className="text-muted p-4">No locations saved yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {modalOpen && (
        <Modal title="Add Location" onClose={() => setModalOpen(false)}>
          <form onSubmit={searchAddress} className="mb-3">
            <label className="form-label">Search Address</label>
            <div className="input-group">
              <input className="form-control" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Search address, municipality, or barangay" />
              <button className="btn btn-outline-primary" type="submit" disabled={searching || searchQuery.trim().length < 3}><IconSearch size={18} className="me-2" />{searching ? 'Searching...' : 'Search'}</button>
            </div>
          </form>
          {searchResults.length > 0 && (
            <div className="list-group mb-3">
              {searchResults.map((result, index) => (
                <button className="list-group-item list-group-item-action" type="button" key={`${result.display_name}-${index}`} onClick={() => selectSuggestion(result)}>
                  <div className="fw-semibold">{result.display_name}</div>
                  <div className="text-muted small">{[result.barangay, result.municipality, result.province].filter(Boolean).join(' / ') || 'Address suggestion'}</div>
                </button>
              ))}
            </div>
          )}
          <form onSubmit={createLocation}>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Location Name</label><input className="form-control" value={form.location_name} onChange={(e) => setForm({ ...form, location_name: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Municipality</label><input className="form-control" value={form.municipality} onChange={(e) => setForm({ ...form, municipality: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Address</label><input className="form-control" required value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Barangay</label><input className="form-control" value={form.barangay} onChange={(e) => setForm({ ...form, barangay: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Province</label><input className="form-control" value={form.province} onChange={(e) => setForm({ ...form, province: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Latitude</label><input className="form-control" type="number" step="any" value={form.latitude} onChange={(e) => setForm({ ...form, latitude: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Longitude</label><input className="form-control" type="number" step="any" value={form.longitude} onChange={(e) => setForm({ ...form, longitude: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Region</label><input className="form-control" value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Source</label><input className="form-control" value={form.geocode_source || 'MANUAL'} onChange={(e) => setForm({ ...form, geocode_source: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Notes</label><textarea className="form-control" rows="3" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0"><button type="button" className="btn" onClick={() => setModalOpen(false)}>Cancel</button><button className="btn btn-primary" disabled={saving}><IconDeviceFloppy size={18} className="me-2" />{saving ? 'Saving...' : 'Save Location'}</button></div>
          </form>
        </Modal>
      )}
    </div>
  );
}

function Modal({ title, children, onClose, size = 'lg' }) {
  useEffect(() => {
    document.body.classList.add('modal-open');
    return () => document.body.classList.remove('modal-open');
  }, []);

  return createPortal(
    <>
      <div className="modal-backdrop fade show app-modal-backdrop" onClick={onClose} />
      <div className="modal modal-blur fade show d-block app-modal-layer" tabIndex="-1" role="dialog">
        <div className={`modal-dialog modal-${size} modal-dialog-centered`}>
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">{title}</h5>
              <button type="button" className="btn-close" aria-label="Close" onClick={onClose} />
            </div>
            <div className="modal-body">{children}</div>
          </div>
        </div>
      </div>
    </>,
    document.body
  );
}

function WalletPage({ refresh }) {
  const [users, setUsers] = useState([]);
  const [topup, setTopup] = useState({ user_id: '', hours: 1, valid_until: '', is_unlimited: false, note: '' });
  const [summary, setSummary] = useState(null);
  async function load() { setUsers(await request('/users')); }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!topup.user_id) {
      setSummary(null);
      return;
    }
    request(`/users/${topup.user_id}/wallet-accounting-summary`).then(setSummary).catch(() => setSummary(null));
  }, [topup.user_id]);

  async function addBalance(e) {
    e.preventDefault();
    await request(`/users/${topup.user_id}/top-up`, {
      method: 'POST',
      body: JSON.stringify({
        amount_seconds: Number(topup.hours) * 3600,
        valid_until: topup.valid_until ? new Date(topup.valid_until).toISOString() : null,
        is_unlimited: topup.is_unlimited,
        note: topup.note
      })
    });
    setTopup({ user_id: '', hours: 1, valid_until: '', is_unlimited: false, note: '' });
    await load(); refresh();
  }

  return (
    <div className="row row-cards">
      <div className="col-12">
        <Card title="Wallet / Manual Top-Up" subtitle="Add time balance, valid-until, or unlimited access">
          <div className="alert alert-info">
            Manual top-up is used by admins to add time or access directly. In the next phase, vouchers will also add time to wallets automatically.
          </div>
          <form onSubmit={addBalance}>
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label">User</label>
                <select className="form-select" required value={topup.user_id} onChange={(e) => setTopup({ ...topup, user_id: e.target.value })}>
                  <option value="">Select user</option>{users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
                </select>
              </div>
              <div className="col-md-2"><label className="form-label">Hours</label><input className="form-control" type="number" min="1" value={topup.hours} onChange={(e) => setTopup({ ...topup, hours: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Valid Until</label><input className="form-control" type="datetime-local" value={topup.valid_until} onChange={(e) => setTopup({ ...topup, valid_until: e.target.value })} /></div>
              <div className="col-md-3 d-flex align-items-end"><label className="form-check mb-2"><input className="form-check-input" type="checkbox" checked={topup.is_unlimited} onChange={(e) => setTopup({ ...topup, is_unlimited: e.target.checked })} /><span className="form-check-label">Unlimited</span></label></div>
              <div className="col-12"><label className="form-label">Admin Note</label><input className="form-control" value={topup.note} onChange={(e) => setTopup({ ...topup, note: e.target.value })} /></div>
            </div>
            <div className="mt-3"><button className="btn btn-primary"><IconWallet size={18} className="me-2" />Add Balance</button></div>
          </form>
        </Card>
      </div>
      <div className="col-12">
        <Card title="Current User Balances">
          <Table rows={users} columns={['username', 'status', 'time_remaining_seconds', 'valid_until', 'is_unlimited']} />
        </Card>
      </div>
      {summary && (
        <div className="col-12">
          <Card title="Wallet Accounting Summary">
            <div className="row g-3 mb-3">
              <div className="col-md-3"><div className="text-muted">Current Time Remaining</div><div className="h3">{formatSeconds(summary.user.time_remaining_seconds)}</div></div>
              <div className="col-md-3"><div className="text-muted">Unlimited</div><div className="h3">{summary.user.is_unlimited ? 'Yes' : 'No'}</div></div>
              <div className="col-md-3"><div className="text-muted">Valid Until</div><div className="h3">{fmt(summary.user.valid_until) || 'Not set'}</div></div>
              <div className="col-md-3"><div className="text-muted">Active Session</div><div className="h3">{summary.active_session ? 'Online' : 'Offline'}</div></div>
            </div>
            {summary.last_accounting_deduction && <div className="alert alert-info">Last accounting deduction: {summary.last_accounting_deduction.amount_seconds} seconds at {summary.last_accounting_deduction.created_at}</div>}
            <Table rows={summary.recent_accounting_debits || []} columns={['amount_seconds', 'reference', 'note', 'created_at']} />
          </Card>
        </div>
      )}
    </div>
  );
}

function VouchersPage() {
  const [tab, setTab] = useState('Overview');
  const [data, setData] = useState({ summary: {}, vouchers: [] });
  const [batches, setBatches] = useState([]);
  const [redemptions, setRedemptions] = useState([]);
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [created, setCreated] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const [redeemResult, setRedeemResult] = useState(null);
  const [filters, setFilters] = useState({ search: '', status: '', voucher_type: '', batch_id: '' });
  const [redemptionFilter, setRedemptionFilter] = useState({ source: '', result: '', search: '' });
  const [single, setSingle] = useState({ voucher_type: 'TIME_BASED', code: '', time_value: 1, time_unit: 'hours', valid_until: '', unlimited_expires_at: '', expires_at: '', note: '', status: 'UNUSED', code_prefix: '3J', code_length: 8 });
  const [bulk, setBulk] = useState({ batch_name: '', description: '', voucher_type: 'TIME_BASED', quantity: 10, time_value: 1, time_unit: 'hours', valid_until: '', unlimited_expires_at: '', expires_at: '', code_prefix: '3J', code_length: 8, note: '' });
  const [redeem, setRedeem] = useState({ voucher_code: '', user_id: '', device_identifier: '' });
  const tabs = ['Overview', 'Create Voucher', 'Bulk Generate', 'Voucher List', 'Batches', 'Redemption Logs', 'Test Redeem'];

  function seconds(value, unit) {
    const amount = Number(value || 0);
    if (unit === 'minutes') return Math.max(0, Math.round(amount * 60));
    if (unit === 'days') return Math.max(0, Math.round(amount * 86400));
    return Math.max(0, Math.round(amount * 3600));
  }
  function dt(value) {
    return value ? new Date(value).toISOString() : null;
  }
  function randomVoucher(prefix = '3J', length = 8) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const values = new Uint32Array(Number(length) || 8);
    window.crypto.getRandomValues(values);
    const body = Array.from(values, (value) => alphabet[value % alphabet.length]).join('');
    return `${prefix ? `${prefix}-` : ''}${body.slice(0, 4)}-${body.slice(4)}`;
  }
  function voucherPayload(form) {
    return {
      voucher_type: form.voucher_type,
      time_value_seconds: form.voucher_type === 'TIME_BASED' ? seconds(form.time_value, form.time_unit) : null,
      valid_until: form.voucher_type === 'DATE_BASED' ? dt(form.valid_until) : null,
      unlimited_expires_at: form.voucher_type === 'UNLIMITED' ? dt(form.unlimited_expires_at) : null,
      expires_at: dt(form.expires_at),
      note: form.note || null,
      code_prefix: form.code_prefix || null,
      code_length: Number(form.code_length) || 8
    };
  }
  function valueLabel(row) {
    if (row.voucher_type === 'TIME_BASED') return formatSeconds(row.time_value_seconds);
    if (row.voucher_type === 'DATE_BASED') return `Until ${fmt(row.valid_until)}`;
    if (row.voucher_type === 'UNLIMITED') return row.unlimited_expires_at ? `Unlimited until ${fmt(row.unlimited_expires_at)}` : 'Unlimited';
    return '';
  }
  async function load() {
    const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value)).toString();
    const redemptionQuery = new URLSearchParams(Object.entries(redemptionFilter).filter(([, value]) => value)).toString();
    const [voucherData, batchData, redemptionData, userData] = await Promise.all([
      request(`/vouchers${query ? `?${query}` : ''}`),
      request('/voucher-batches'),
      request(`/voucher-redemptions${redemptionQuery ? `?${redemptionQuery}` : ''}`),
      request('/users')
    ]);
    setData(voucherData);
    setBatches(Array.isArray(batchData) ? batchData : []);
    setRedemptions(Array.isArray(redemptionData) ? redemptionData : []);
    setUsers(Array.isArray(userData) ? userData : []);
  }
  useEffect(() => { load().catch((err) => setError(err.message)); }, []);
  async function createVoucher(e) {
    e.preventDefault();
    setError('');
    const payload = { ...voucherPayload(single), code: single.code || null, status: single.status };
    const row = await request('/vouchers', { method: 'POST', body: JSON.stringify(payload) });
    setCreated(row);
    setSingle({ ...single, code: '' });
    setMessage('Voucher created.');
    await load();
  }
  async function generateBatch(e) {
    e.preventDefault();
    setError('');
    const payload = { ...voucherPayload(bulk), batch_name: bulk.batch_name, description: bulk.description || null, quantity: Number(bulk.quantity) || 1 };
    const result = await request('/voucher-batches', { method: 'POST', body: JSON.stringify(payload) });
    setBatchResult(result);
    setMessage(`Generated ${result.generated_count} vouchers.`);
    await load();
  }
  async function voucherAction(id, action) {
    setError('');
    await request(`/vouchers/${id}/${action}`, { method: 'POST' });
    setMessage(`Voucher ${action} completed.`);
    await load();
  }
  async function deleteVoucher(id) {
    if (!window.confirm('Delete this unused voucher?')) return;
    await request(`/vouchers/${id}`, { method: 'DELETE' });
    setMessage('Voucher deleted.');
    await load();
  }
  async function testRedeem(e) {
    e.preventDefault();
    setError('');
    const selected = users.find((user) => user.id === redeem.user_id);
    const result = await request('/vouchers/redeem-test', { method: 'POST', body: JSON.stringify({ ...redeem, username: selected?.username }) });
    setRedeemResult(result);
    await load();
  }
  async function exportCsv(batchId = '') {
    const token = localStorage.getItem('centralwifi_token');
    const res = await fetch(`/api/vouchers/export.csv${batchId ? `?batch_id=${batchId}` : ''}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'vouchers.csv';
    link.click();
    URL.revokeObjectURL(url);
  }
  function printCodes(rows) {
    const win = window.open('', '_blank');
    if (!win) return;
    win.document.write(`<html><head><title>Vouchers</title><style>body{font-family:Arial;padding:24px}.voucher{border:1px solid #ccc;display:inline-block;margin:8px;padding:14px;min-width:180px;text-align:center}.code{font-size:20px;font-weight:700}</style></head><body>${rows.map((row) => `<div class="voucher"><div>3JCentralPisowifi</div><div class="code">${row.code}</div><div>${row.voucher_type}</div></div>`).join('')}</body></html>`);
    win.document.close();
    win.print();
  }
  const vouchers = data.vouchers || [];
  const summary = data.summary || {};
  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">Vouchers are prepaid access codes. You can create one voucher or generate many at once. A customer will later enter the voucher in the captive portal to receive internet time or access.</div>
      </div>
      {message && <div className="col-12"><div className="alert alert-success">{message}</div></div>}
      {error && <div className="col-12"><div className="alert alert-danger">{error}</div></div>}
      <div className="col-12">
        <ul className="nav nav-tabs">
          {tabs.map((item) => <li className="nav-item" key={item}><button className={`nav-link ${tab === item ? 'active' : ''}`} onClick={() => setTab(item)}>{item}</button></li>)}
        </ul>
      </div>

      {tab === 'Overview' && <>
        <KpiCard icon={IconKey} label="Total Vouchers" value={summary.total_vouchers || 0} tone="blue" />
        <KpiCard icon={IconClock} label="Unused" value={summary.unused || 0} tone="green" />
        <KpiCard icon={IconWallet} label="Used" value={summary.used || 0} tone="purple" />
        <KpiCard icon={IconAlertTriangle} label="Expired" value={summary.expired || 0} tone="orange" />
        <KpiCard icon={IconShieldLock} label="Disabled" value={summary.disabled || 0} tone="red" />
        <KpiCard icon={IconClock} label="Total Time Issued" value={formatSeconds(summary.total_time_issued)} tone="cyan" />
        <KpiCard icon={IconActivity} label="Total Time Redeemed" value={formatSeconds(summary.total_time_redeemed)} tone="green" />
        <div className="col-12"><Card title="Recent Redemptions"><Table rows={redemptions.slice(0, 8)} columns={['voucher_code', 'result', 'username', 'source', 'redeemed_time_seconds', 'failure_reason', 'created_at']} /></Card></div>
      </>}

      {tab === 'Create Voucher' && <div className="col-12">
        <Card title="Create Voucher">
          <form onSubmit={createVoucher}>
            <div className="row g-3">
              <div className="col-md-3"><label className="form-label">Voucher Type</label><select className="form-select" value={single.voucher_type} onChange={(e) => setSingle({ ...single, voucher_type: e.target.value })}><option value="TIME_BASED">Time-based</option><option value="DATE_BASED">Date-based</option><option value="UNLIMITED">Unlimited</option></select></div>
              {single.voucher_type === 'TIME_BASED' && <><div className="col-md-2"><label className="form-label">Time Value</label><input className="form-control" type="number" min="1" value={single.time_value} onChange={(e) => setSingle({ ...single, time_value: e.target.value })} /></div><div className="col-md-2"><label className="form-label">Unit</label><select className="form-select" value={single.time_unit} onChange={(e) => setSingle({ ...single, time_unit: e.target.value })}><option value="minutes">Minutes</option><option value="hours">Hours</option><option value="days">Days</option></select></div></>}
              {single.voucher_type === 'DATE_BASED' && <div className="col-md-4"><label className="form-label">Valid Until</label><input className="form-control" type="datetime-local" value={single.valid_until} onChange={(e) => setSingle({ ...single, valid_until: e.target.value })} /></div>}
              {single.voucher_type === 'UNLIMITED' && <div className="col-md-4"><label className="form-label">Optional Unlimited Expiry</label><input className="form-control" type="datetime-local" value={single.unlimited_expires_at} onChange={(e) => setSingle({ ...single, unlimited_expires_at: e.target.value })} /></div>}
              <div className="col-md-3"><label className="form-label">Voucher Code</label><div className="input-group"><input className="form-control" value={single.code} onChange={(e) => setSingle({ ...single, code: e.target.value })} /><button className="btn" type="button" onClick={() => setSingle({ ...single, code: randomVoucher(single.code_prefix, single.code_length) })}>Generate</button></div></div>
              <div className="col-md-2"><label className="form-label">Prefix</label><input className="form-control" value={single.code_prefix} onChange={(e) => setSingle({ ...single, code_prefix: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Code Length</label><input className="form-control" type="number" min="4" max="32" value={single.code_length} onChange={(e) => setSingle({ ...single, code_length: Number(e.target.value) })} /></div>
              <div className="col-md-3"><label className="form-label">Expires At</label><input className="form-control" type="datetime-local" value={single.expires_at} onChange={(e) => setSingle({ ...single, expires_at: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Status</label><select className="form-select" value={single.status} onChange={(e) => setSingle({ ...single, status: e.target.value })}><option>UNUSED</option><option>DISABLED</option></select></div>
              <div className="col-12"><label className="form-label">Note</label><input className="form-control" value={single.note} onChange={(e) => setSingle({ ...single, note: e.target.value })} /></div>
              <div className="col-12"><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Create Voucher</button></div>
            </div>
          </form>
          {created && <div className="alert alert-success mt-3 mb-0">Created voucher: <code>{created.code}</code> <button className="btn btn-sm ms-2" type="button" onClick={() => navigator.clipboard?.writeText(created.code)}>Copy</button><button className="btn btn-sm ms-2" type="button" onClick={() => printCodes([created])}>Print</button></div>}
        </Card>
      </div>}

      {tab === 'Bulk Generate' && <div className="col-12">
        <Card title="Bulk Generate">
          <form onSubmit={generateBatch}>
            <div className="row g-3">
              <div className="col-md-4"><label className="form-label">Batch Name</label><input className="form-control" required value={bulk.batch_name} onChange={(e) => setBulk({ ...bulk, batch_name: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Quantity</label><input className="form-control" type="number" min="1" max="5000" value={bulk.quantity} onChange={(e) => setBulk({ ...bulk, quantity: Number(e.target.value) })} /></div>
              <div className="col-md-3"><label className="form-label">Voucher Type</label><select className="form-select" value={bulk.voucher_type} onChange={(e) => setBulk({ ...bulk, voucher_type: e.target.value })}><option value="TIME_BASED">Time-based</option><option value="DATE_BASED">Date-based</option><option value="UNLIMITED">Unlimited</option></select></div>
              {bulk.voucher_type === 'TIME_BASED' && <><div className="col-md-2"><label className="form-label">Time Value</label><input className="form-control" type="number" min="1" value={bulk.time_value} onChange={(e) => setBulk({ ...bulk, time_value: e.target.value })} /></div><div className="col-md-1"><label className="form-label">Unit</label><select className="form-select" value={bulk.time_unit} onChange={(e) => setBulk({ ...bulk, time_unit: e.target.value })}><option value="minutes">Min</option><option value="hours">Hr</option><option value="days">Day</option></select></div></>}
              {bulk.voucher_type === 'DATE_BASED' && <div className="col-md-3"><label className="form-label">Valid Until</label><input className="form-control" type="datetime-local" value={bulk.valid_until} onChange={(e) => setBulk({ ...bulk, valid_until: e.target.value })} /></div>}
              {bulk.voucher_type === 'UNLIMITED' && <div className="col-md-3"><label className="form-label">Optional Unlimited Expiry</label><input className="form-control" type="datetime-local" value={bulk.unlimited_expires_at} onChange={(e) => setBulk({ ...bulk, unlimited_expires_at: e.target.value })} /></div>}
              <div className="col-md-2"><label className="form-label">Code Prefix</label><input className="form-control" value={bulk.code_prefix} onChange={(e) => setBulk({ ...bulk, code_prefix: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Code Length</label><input className="form-control" type="number" min="4" max="32" value={bulk.code_length} onChange={(e) => setBulk({ ...bulk, code_length: Number(e.target.value) })} /></div>
              <div className="col-md-3"><label className="form-label">Expires At</label><input className="form-control" type="datetime-local" value={bulk.expires_at} onChange={(e) => setBulk({ ...bulk, expires_at: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Description / Note</label><input className="form-control" value={bulk.description} onChange={(e) => setBulk({ ...bulk, description: e.target.value, note: e.target.value })} /></div>
              <div className="col-12 d-flex gap-2"><button className="btn" type="button" onClick={() => setBatchResult({ preview: Array.from({ length: Math.min(10, Number(bulk.quantity) || 1) }, () => ({ code: randomVoucher(bulk.code_prefix, bulk.code_length), voucher_type: bulk.voucher_type })) })}>Preview</button><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Generate Batch</button></div>
            </div>
          </form>
          {batchResult?.preview && <div className="mt-3"><h4>Preview</h4><div className="d-flex flex-wrap gap-2">{batchResult.preview.map((row) => <code key={row.code}>{row.code}</code>)}</div></div>}
          {batchResult?.generated_count && <div className="alert alert-success mt-3 mb-0">Generated {batchResult.generated_count} vouchers. <button className="btn btn-sm ms-2" type="button" onClick={() => exportCsv(batchResult.batch.id)}>Export CSV</button><button className="btn btn-sm ms-2" type="button" onClick={() => printCodes(batchResult.vouchers)}>Print</button></div>}
        </Card>
      </div>}

      {tab === 'Voucher List' && <div className="col-12">
        <Card title="Voucher List">
          <div className="row g-2 mb-3">
            <div className="col-md-3"><input className="form-control" placeholder="Search code" value={filters.search} onChange={(e) => setFilters({ ...filters, search: e.target.value })} /></div>
            <div className="col-md-2"><select className="form-select" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="">All Status</option><option>UNUSED</option><option>USED</option><option>EXPIRED</option><option>DISABLED</option><option>VOIDED</option></select></div>
            <div className="col-md-2"><select className="form-select" value={filters.voucher_type} onChange={(e) => setFilters({ ...filters, voucher_type: e.target.value })}><option value="">All Types</option><option>TIME_BASED</option><option>DATE_BASED</option><option>UNLIMITED</option></select></div>
            <div className="col-md-3"><select className="form-select" value={filters.batch_id} onChange={(e) => setFilters({ ...filters, batch_id: e.target.value })}><option value="">All Batches</option>{batches.map((batch) => <option key={batch.id} value={batch.id}>{batch.batch_name}</option>)}</select></div>
            <div className="col-md-2 d-flex gap-2"><button className="btn" type="button" onClick={load}>Filter</button><button className="btn" type="button" onClick={() => exportCsv(filters.batch_id)}>CSV</button></div>
          </div>
          <div className="table-responsive"><table className="table card-table table-vcenter text-nowrap"><thead><tr><th>Code</th><th>Type</th><th>Value</th><th>Status</th><th>Expires At</th><th>Redeemed By</th><th>Redeemed At</th><th>Batch</th><th>Created At</th><th className="text-end">Actions</th></tr></thead><tbody>{vouchers.map((row) => <tr key={row.id}><td><code>{row.code}</code></td><td>{row.voucher_type}</td><td>{valueLabel(row)}</td><td><span className="badge bg-blue-lt text-blue">{row.status}</span></td><td>{fmt(row.expires_at)}</td><td>{fmt(row.redeemed_by_username)}</td><td>{fmt(row.redeemed_at)}</td><td>{fmt(row.batch_name)}</td><td>{fmt(row.created_at)}</td><td className="text-end"><button className="btn btn-sm me-1" onClick={() => navigator.clipboard?.writeText(row.code)}>Copy</button>{row.status === 'DISABLED' ? <button className="btn btn-sm me-1" onClick={() => voucherAction(row.id, 'enable')}>Enable</button> : <button className="btn btn-sm me-1" onClick={() => voucherAction(row.id, 'disable')}>Disable</button>}<button className="btn btn-sm btn-warning me-1" onClick={() => voucherAction(row.id, 'void')}>Void</button>{row.status === 'UNUSED' && row.redemption_count === 0 && <button className="btn btn-sm btn-danger" onClick={() => deleteVoucher(row.id)}>Delete</button>}</td></tr>)}</tbody></table></div>
        </Card>
      </div>}

      {tab === 'Batches' && <div className="col-12">
        <Card title="Batches">
          <Table rows={batches} columns={['batch_name', 'voucher_type', 'quantity', 'unused', 'used', 'expired', 'disabled', 'created_by', 'created_at']} />
          <div className="mt-3 d-flex gap-2"><button className="btn" type="button" onClick={() => exportCsv()}>Export All CSV</button><button className="btn" type="button" onClick={() => printCodes(vouchers)}>Print Current List</button></div>
        </Card>
      </div>}

      {tab === 'Redemption Logs' && <div className="col-12">
        <Card title="Redemption Logs">
          <div className="row g-2 mb-3">
            <div className="col-md-3"><input className="form-control" placeholder="Voucher or user" value={redemptionFilter.search} onChange={(e) => setRedemptionFilter({ ...redemptionFilter, search: e.target.value })} /></div>
            <div className="col-md-3"><select className="form-select" value={redemptionFilter.source} onChange={(e) => setRedemptionFilter({ ...redemptionFilter, source: e.target.value })}><option value="">All Sources</option><option>ADMIN_TEST</option><option>CLIENT_PORTAL</option><option>SYSTEM</option></select></div>
            <div className="col-md-3"><select className="form-select" value={redemptionFilter.result} onChange={(e) => setRedemptionFilter({ ...redemptionFilter, result: e.target.value })}><option value="">All Results</option><option>SUCCESS</option><option>FAILED</option></select></div>
            <div className="col-md-3"><button className="btn" type="button" onClick={load}>Filter</button></div>
          </div>
          <Table rows={redemptions} columns={['voucher_code', 'result', 'username', 'source', 'redeemed_time_seconds', 'failure_reason', 'ip_address', 'created_at']} />
        </Card>
      </div>}

      {tab === 'Test Redeem' && <div className="col-12">
        <Card title="Test Redeem">
          <div className="alert alert-warning">Test Redeem is for admin validation only. It simulates what the customer portal will do later.</div>
          <form onSubmit={testRedeem}>
            <div className="row g-3">
              <div className="col-md-4"><label className="form-label">Voucher Code</label><input className="form-control" required value={redeem.voucher_code} onChange={(e) => setRedeem({ ...redeem, voucher_code: e.target.value })} /></div>
              <div className="col-md-4"><label className="form-label">Existing Customer / Account</label><select className="form-select" required value={redeem.user_id} onChange={(e) => setRedeem({ ...redeem, user_id: e.target.value })}><option value="">Select customer</option>{users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}</select></div>
              <div className="col-md-4"><label className="form-label">Device Identifier</label><input className="form-control" value={redeem.device_identifier} onChange={(e) => setRedeem({ ...redeem, device_identifier: e.target.value })} /></div>
              <div className="col-12"><button className="btn btn-primary"><IconKey size={18} className="me-2" />Test Redeem Voucher</button></div>
            </div>
          </form>
          {redeemResult && <div className={`alert mt-3 mb-0 ${redeemResult.status === 'SUCCESS' ? 'alert-success' : 'alert-danger'}`}><div className="fw-semibold">{redeemResult.status === 'SUCCESS' ? 'Voucher accepted' : redeemResult.reason}</div>{redeemResult.status === 'SUCCESS' ? <div>Time added: {formatSeconds(redeemResult.time_added_seconds)}. Transaction: <code>{redeemResult.transaction_id}</code></div> : <div>Suggested fix: check voucher status, expiry, and selected customer.</div>}<pre className="mt-2 mb-0"><code>{JSON.stringify(redeemResult, null, 2)}</code></pre></div>}
        </Card>
      </div>}
    </div>
  );
}

function portalPreviewSrcDoc(htmlTemplate = '', cssTemplate = '') {
  const brand = '<div class="client-portal-brand"><div class="client-portal-logo">3J</div><h1>3J WiFi</h1><p>Enter your voucher to connect</p></div>';
  const voucherForm = '<form class="client-portal-card"><div class="client-portal-welcome">Welcome to 3J WiFi. Please enter your voucher code to start using the internet.</div><label class="form-label">Voucher Code</label><input class="form-control form-control-lg text-center voucher-input" value="3J-ABCD-2345" readonly><button class="btn btn-primary btn-lg w-100 mt-3" type="button">Redeem / Connect</button></form>';
  const help = '<div class="client-portal-help"><p>Need a voucher? Ask the nearest vendo/operator.</p><p>If your voucher is valid but internet does not start, disconnect and reconnect to WiFi.</p><div class="client-portal-powered">Powered by 3JCentralPisowifi</div></div>';
  const body = String(htmlTemplate || '').replaceAll('{{brand}}', brand).replaceAll('{{voucher_form}}', voucherForm).replaceAll('{{help}}', help);
  const baseCss = `body{margin:0;font-family:Inter,Arial,sans-serif;background:#eef4fb;color:#1f2937}.client-portal-page{min-height:100vh;display:grid;place-items:center;padding:24px}.client-portal-shell{width:min(420px,100%)}.client-portal-brand{text-align:center;margin-bottom:18px}.client-portal-logo{display:inline-grid;place-items:center;width:64px;height:64px;border-radius:18px;background:#206bc4;color:white;font-weight:800;font-size:26px;margin-bottom:10px}.client-portal-brand h1{margin:0;font-size:30px}.client-portal-brand p{margin:6px 0 0;color:#64748b}.client-portal-card{background:white;border:1px solid #dbe3ed;border-radius:14px;box-shadow:0 18px 48px rgba(15,23,42,.12);padding:22px}.client-portal-welcome{color:#475569;margin-bottom:16px}.form-label{display:block;font-weight:700;margin-bottom:8px}.form-control{box-sizing:border-box;width:100%;border:1px solid #cbd5e1;border-radius:10px;padding:13px;font-size:18px}.text-center{text-align:center}.btn{border:0;border-radius:10px;padding:13px 16px;font-weight:800}.btn-primary{background:#206bc4;color:white}.w-100{width:100%}.mt-3{margin-top:16px}.client-portal-help{text-align:center;color:#64748b;font-size:14px;margin-top:16px}.client-portal-powered{font-weight:700;color:#206bc4}`;
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>${baseCss}${cssTemplate || ''}</style></head><body><div class="client-portal-page"><div class="client-portal-shell">${body}</div></div></body></html>`;
}

function CaptivePortalEditorPage() {
  const [design, setDesign] = useState({ html_template: '', css_template: '' });
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  async function load() { setDesign(await request('/captive-portal/design')); }
  useEffect(() => { load().catch((err) => setError(err.message)); }, []);
  async function save(e) {
    e.preventDefault();
    setMessage('');
    setError('');
    try {
      const saved = await request('/captive-portal/design', { method: 'PUT', body: JSON.stringify(design) });
      setDesign(saved);
      setMessage('Portal design saved.');
    } catch (err) {
      setError(err.message);
    }
  }
  function goBack() {
    window.history.pushState({}, '', '/admin/captive-portal');
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="d-flex align-items-center justify-content-between gap-2">
          <div>
            <h2 className="page-title mb-1">Portal Design Editor</h2>
            <div className="text-muted">Edit customer portal HTML and CSS. Keep <code>{'{{voucher_form}}'}</code> in the template so voucher redemption remains available.</div>
          </div>
          <button className="btn btn-outline-secondary" type="button" onClick={goBack}>Back</button>
        </div>
      </div>
      {message && <div className="col-12"><div className="alert alert-success">{message}</div></div>}
      {error && <div className="col-12"><div className="alert alert-danger">{error}</div></div>}
      <div className="col-lg-6">
        <form onSubmit={save}>
          <Card title="HTML Template">
            <textarea className="form-control portal-code-editor" value={design.html_template || ''} onChange={(e) => setDesign({ ...design, html_template: e.target.value })} spellCheck={false} />
            <div className="text-muted small mt-2">Placeholders: <code>{'{{brand}}'}</code>, <code>{'{{voucher_form}}'}</code>, <code>{'{{help}}'}</code>.</div>
          </Card>
          <Card title="CSS" className="mt-3">
            <textarea className="form-control portal-code-editor portal-css-editor" value={design.css_template || ''} onChange={(e) => setDesign({ ...design, css_template: e.target.value })} spellCheck={false} />
            <button className="btn btn-primary mt-3"><IconDeviceFloppy size={18} className="me-2" />Save Design</button>
          </Card>
        </form>
      </div>
      <div className="col-lg-6">
        <Card title="Preview">
          <iframe className="portal-design-preview" title="Portal design preview" srcDoc={portalPreviewSrcDoc(design.html_template, design.css_template)} />
        </Card>
      </div>
    </div>
  );
}

function CaptivePortalPage({ mode = 'full' }) {
  const isMikrotikOnly = mode === 'mikrotik-only';
  const [activeTab, setActiveTab] = useState(isMikrotikOnly ? 'MikroTik' : 'Portal');
  const [settings, setSettings] = useState(null);
  const [portalSettings, setPortalSettings] = useState(null);
  const [mikrotiks, setMikrotiks] = useState([]);
  const [mikrotikRows, setMikrotikRows] = useState([]);
  const [portalEvents, setPortalEvents] = useState([]);
  const [redemptions, setRedemptions] = useState([]);
  const [voucherSummary, setVoucherSummary] = useState({});
  const [sessions, setSessions] = useState([]);
  const [authorizations, setAuthorizations] = useState([]);
  const [actionResult, setActionResult] = useState(null);
  const [message, setMessage] = useState('');
  const [mikrotikTab, setMikrotikTab] = useState('Overview');
  const [mikrotikPlan, setMikrotikPlan] = useState(null);
  const [mikrotikPlanRouterId, setMikrotikPlanRouterId] = useState(null);
  const [mikrotikStepIndex, setMikrotikStepIndex] = useState(0);
  const [mikrotikStepReview, setMikrotikStepReview] = useState(null);
  const [mikrotikApplyingStep, setMikrotikApplyingStep] = useState(null);
  const [mikrotikReverting, setMikrotikReverting] = useState(false);
  const [mikrotikCheckingConfig, setMikrotikCheckingConfig] = useState(null);
  const [mikrotikManagedConfig, setMikrotikManagedConfig] = useState({});
  const [mikrotikOptions, setMikrotikOptions] = useState({});
  const [preflightRouterId, setPreflightRouterId] = useState('');
  const [preflightScan, setPreflightScan] = useState(null);
  const [preflightHistory, setPreflightHistory] = useState([]);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightScanning, setPreflightScanning] = useState(false);
  const [preflightExplaining, setPreflightExplaining] = useState(false);
  const [preflightView, setPreflightView] = useState('summary');
  const [preflightSummary, setPreflightSummary] = useState(null);
  const [preflightBatch, setPreflightBatch] = useState(null);
  const [preflightScanningAll, setPreflightScanningAll] = useState(false);
  const [preflightSummaryFilter, setPreflightSummaryFilter] = useState('ALL');
  const [deploymentForm, setDeploymentForm] = useState({ confirmed_router_role: '', confirmed_deployment_mode: '', sensitive_confirmation: false });
  const [expertOverrideForm, setExpertOverrideForm] = useState({ confirmation_phrase: '', reason: '' });
  const [aiSummary, setAiSummary] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiRouterId, setAiRouterId] = useState('');
  const [aiConversation, setAiConversation] = useState(null);
  const [aiInput, setAiInput] = useState('');
  const [aiSending, setAiSending] = useState(false);
  const [aiQuestions, setAiQuestions] = useState([]);
  const [aiQuestionAnswers, setAiQuestionAnswers] = useState({});
  const [aiDraftPlans, setAiDraftPlans] = useState([]);
  const [aiSelectedDraftPlanId, setAiSelectedDraftPlanId] = useState('');
  const [aiGeneratingPlan, setAiGeneratingPlan] = useState(false);
  const [aiValidatingPlan, setAiValidatingPlan] = useState(false);
  const [aiSmokeTest, setAiSmokeTest] = useState(null);
  const [aiSmokeTesting, setAiSmokeTesting] = useState(false);
  const [pilotSelection, setPilotSelection] = useState(null);
  const [pilotForm, setPilotForm] = useState({ router_id: '', reason: '', physical_recovery_confidence: 'MODERATE', operator_note: '' });
  const [pilotSaving, setPilotSaving] = useState(false);
  const [aiSavingQuestions, setAiSavingQuestions] = useState(false);
  const [aiQuestionValidation, setAiQuestionValidation] = useState(null);
  const [mt4Readiness, setMt4Readiness] = useState(null);
  const [aiSuggestingAnswers, setAiSuggestingAnswers] = useState(false);
  const [aiValidatingAnswers, setAiValidatingAnswers] = useState(false);
  const [planningNetworkPreview, setPlanningNetworkPreview] = useState(null);
  const [interfaceCandidates, setInterfaceCandidates] = useState(null);
  const [vlanPathPlan, setVlanPathPlan] = useState(null);
  const [vlanPathValidation, setVlanPathValidation] = useState(null);
  const [vlanPathSaving, setVlanPathSaving] = useState(false);
  const [interfacePicker, setInterfacePicker] = useState(null);
  const [aiSmokeModalOpen, setAiSmokeModalOpen] = useState(false);
  const [pilotModalOpen, setPilotModalOpen] = useState(false);
  const [questionsModalOpen, setQuestionsModalOpen] = useState(false);
  const [questionsPhaseTab, setQuestionsPhaseTab] = useState('vlan-path');
  const [draftPlanModalOpen, setDraftPlanModalOpen] = useState(false);
  const [aiChatOpen, setAiChatOpen] = useState(false);
  const [mikrotikStations, setMikrotikStations] = useState([]);
  const [stationModalOpen, setStationModalOpen] = useState(false);
  const [stationSaving, setStationSaving] = useState(false);
  const [stationReview, setStationReview] = useState(null);
  const [stationEditingId, setStationEditingId] = useState('');
  const [stationImplementation, setStationImplementation] = useState(null);
  const [stationImplementationSteps, setStationImplementationSteps] = useState([]);
  const [stationImplementing, setStationImplementing] = useState(false);
  const [stationImplementationMessage, setStationImplementationMessage] = useState('');
  const [stationPushCompleted, setStationPushCompleted] = useState(false);
  const [stationPushCloseCountdown, setStationPushCloseCountdown] = useState(10);
  const [stationRemove, setStationRemove] = useState(null);
  const [stationRemoveSteps, setStationRemoveSteps] = useState([]);
  const [stationRemoving, setStationRemoving] = useState(false);
  const [stationRemoveMessage, setStationRemoveMessage] = useState('');
  const [stationRemoveCompleted, setStationRemoveCompleted] = useState(false);
  const [stationRemoveCloseCountdown, setStationRemoveCloseCountdown] = useState(10);
  const [stationManagedStatus, setStationManagedStatus] = useState(null);
  const [stationCheckingManaged, setStationCheckingManaged] = useState(false);
  const [stationCommandLogs, setStationCommandLogs] = useState([]);
  const [stationDiagnostics, setStationDiagnostics] = useState(null);
  const [stationDiagnosticsClientIp, setStationDiagnosticsClientIp] = useState('');
  const [stationDiagnosticsLoading, setStationDiagnosticsLoading] = useState(false);
  const [hotspotLoginSync, setHotspotLoginSync] = useState({ summary: {}, stations: [] });
  const [hotspotLoginChecking, setHotspotLoginChecking] = useState(false);
  const [hotspotLoginSyncing, setHotspotLoginSyncing] = useState(false);
  const [apManagementConfig, setApManagementConfig] = useState(null);
  const [apManagementModalOpen, setApManagementModalOpen] = useState(false);
  const [apManagementSaving, setApManagementSaving] = useState(false);
  const [apManagementError, setApManagementError] = useState('');
  const [apManagementImplementation, setApManagementImplementation] = useState(null);
  const [apManagementImplementationSteps, setApManagementImplementationSteps] = useState([]);
  const [apManagementImplementing, setApManagementImplementing] = useState(false);
  const [apManagementImplementationMessage, setApManagementImplementationMessage] = useState('');
  const [apManagementPushCompleted, setApManagementPushCompleted] = useState(false);
  const [apManagementPushCloseCountdown, setApManagementPushCloseCountdown] = useState(10);
  const [apManagementManagedStatus, setApManagementManagedStatus] = useState(null);
  const [apManagementCheckingManaged, setApManagementCheckingManaged] = useState(false);
  const [apManagementActiveRouterIndex, setApManagementActiveRouterIndex] = useState(0);
  const [apManagementPortSearch, setApManagementPortSearch] = useState({});
  const [apManagementDragIndex, setApManagementDragIndex] = useState(null);
  const apManagementStepRefs = useRef({});
  const [apManagementForm, setApManagementForm] = useState({
    config_name: 'Central AP Management',
    vlan_id: '111',
    vlan_interface_name: 'VLAN111-AP-MGMT',
    network_cidr: '10.111.0.0/24',
    gateway_ip: '10.111.0.1',
    pool_start_ip: '10.111.0.10',
    pool_end_ip: '10.111.0.254',
    pool_name: 'POOL-AP-MGMT-V111',
    dhcp_server_name: 'DHCP-AP-MGMT-V111',
    dhcp_lease_time: '1h',
    dns_servers: '8.8.8.8,1.1.1.1',
    local_interface_list: 'LOCAL',
    routers: []
  });
  const [stationProgressMap, setStationProgressMap] = useState({});
  const stationStepRefs = useRef({});
  const [stationError, setStationError] = useState('');
  const [stationDragIndex, setStationDragIndex] = useState(null);
  const [stationActiveRouterIndex, setStationActiveRouterIndex] = useState(0);
  const [stationPortSearch, setStationPortSearch] = useState({});
  const [stationForm, setStationForm] = useState({
    station_name: '',
    station_code: '',
    description: '',
    vlan_id: '77',
    vlan_interface_name: 'VLAN77-3J-HOTSPOT',
    client_network_cidr: '10.77.0.0/24',
    gateway_ip: '10.77.0.1',
    pool_start_ip: '10.77.0.2',
    pool_end_ip: '10.77.0.254',
    pool_name: 'POOL-3J-HOTSPOT-V77',
    create_dhcp_server: true,
    dhcp_server_name: 'DHCP-3J-HOTSPOT-V77',
    dhcp_lease_time: '1h',
    dns_servers: '8.8.8.8,1.1.1.1',
    local_interface_list: 'LOCAL',
    create_hotspot_profile: true,
    create_hotspot_server: true,
    create_walled_garden: true,
    hotspot_profile_name: 'PROFILE-3J-HOTSPOT-V77',
    hotspot_html_directory: 'hotspot',
    hotspot_dns_name: 'wifi.3j.3jportal.test',
    hotspot_server_name: 'HS-3J-HOTSPOT-V77',
    portal_url: 'http://192.168.50.70:8080/portal',
    routers: []
  });
  const tabs = isMikrotikOnly ? ['MikroTik'] : ['Portal', 'Portal Settings', 'Sanity Check', 'Portal Sessions', 'Authorization Logs', 'Manual Setup Guide'];
  function editableMikrotikRows(rows) {
    return rows.map((router) => ({
      ...router,
      password: '',
      notes: router.notes || '',
      hotspot_vlan_id: router.hotspot_vlan_id || '',
      hotspot_vlan_parent_interface: router.hotspot_vlan_parent_interface || '',
      hotspot_vlan_interface_name: router.hotspot_vlan_interface_name || '',
      hotspot_interface: router.hotspot_interface || '',
      hotspot_profile_name: router.hotspot_profile_name || '',
      hotspot_server_name: router.hotspot_server_name || '',
      hotspot_dns_name: router.hotspot_dns_name || '',
      hotspot_html_directory: router.hotspot_html_directory || 'hotspot',
      hotspot_client_network_cidr: router.hotspot_client_network_cidr || '',
      hotspot_gateway_ip: router.hotspot_gateway_ip || '',
      hotspot_pool_start_ip: router.hotspot_pool_start_ip || '',
      hotspot_pool_end_ip: router.hotspot_pool_end_ip || '',
      hotspot_pool_name: router.hotspot_pool_name || '',
      hotspot_dhcp_server_name: router.hotspot_dhcp_server_name || '',
      hotspot_dhcp_lease_time: router.hotspot_dhcp_lease_time || '1h',
      hotspot_dns_servers: router.hotspot_dns_servers || '',
      hotspot_wan_interface: router.hotspot_wan_interface || '',
      hotspot_enable_nat: Boolean(router.hotspot_enable_nat),
      _isNew: false,
      _remove: false
    }));
  }
  function stationRouterTemplate(router = null) {
    return {
      router_id: router?.id || '',
      bridge_name: '',
      tagged_ports: '',
      notes: ''
    };
  }
  function stationRouterDisplay(row, index) {
    const router = mikrotiks.find((item) => item.id === row?.router_id);
    return row?.router_name || router?.router_name || row?.router_id || `Router ${index + 1}`;
  }
  function apManagementRouterTemplate(router = null) {
    return {
      router_id: router?.id || '',
      bridge_name: '',
      tagged_ports: '',
      notes: ''
    };
  }
  function apManagementRouterDisplay(row, index) {
    const router = mikrotiks.find((item) => item.id === row?.router_id);
    return row?.router_name || router?.router_name || row?.router_id || `Router ${index + 1}`;
  }
  function apManagementToForm(config = {}) {
    const vlan = config.vlan_id ? String(config.vlan_id) : '111';
    return {
      config_name: config.config_name || 'Central AP Management',
      vlan_id: vlan,
      vlan_interface_name: config.vlan_interface_name || `VLAN${vlan}-AP-MGMT`,
      network_cidr: config.network_cidr || '10.111.0.0/24',
      gateway_ip: config.gateway_ip || '10.111.0.1',
      pool_start_ip: config.pool_start_ip || '10.111.0.10',
      pool_end_ip: config.pool_end_ip || '10.111.0.254',
      pool_name: config.pool_name || `POOL-AP-MGMT-V${vlan}`,
      dhcp_server_name: config.dhcp_server_name || `DHCP-AP-MGMT-V${vlan}`,
      dhcp_lease_time: config.dhcp_lease_time || '1h',
      dns_servers: config.dns_servers || '8.8.8.8,1.1.1.1',
      local_interface_list: config.local_interface_list || 'LOCAL',
      routers: (config.routers || []).map((router) => ({
        router_id: router.router_id || '',
        bridge_name: router.bridge_name || '',
        tagged_ports: router.tagged_ports || '',
        notes: router.notes || ''
      }))
    };
  }
  function stationToForm(station) {
    return {
      station_name: station.station_name || '',
      station_code: station.station_code || '',
      description: station.description || '',
      vlan_id: String(station.vlan_id || ''),
      vlan_interface_name: station.vlan_interface_name || '',
      client_network_cidr: station.client_network_cidr || '',
      gateway_ip: station.gateway_ip || '',
      pool_start_ip: station.pool_start_ip || '',
      pool_end_ip: station.pool_end_ip || '',
      pool_name: station.pool_name || '',
      create_dhcp_server: station.create_dhcp_server !== false,
      dhcp_server_name: station.dhcp_server_name || '',
      dhcp_lease_time: station.dhcp_lease_time || '1h',
      dns_servers: station.dns_servers || '',
      local_interface_list: station.local_interface_list || 'LOCAL',
      create_hotspot_profile: station.create_hotspot_profile !== false,
      create_hotspot_server: station.create_hotspot_server !== false,
      create_walled_garden: station.create_walled_garden !== false,
      hotspot_profile_name: station.hotspot_profile_name || '',
      hotspot_html_directory: station.hotspot_html_directory || 'hotspot',
      hotspot_dns_name: station.hotspot_dns_name || 'wifi.3j.3jportal.test',
      hotspot_server_name: station.hotspot_server_name || '',
      portal_url: station.portal_url || portalSettings.portal_url_staging || 'http://192.168.50.70:8080/portal',
      routers: (station.routers || []).map((router) => ({
        router_id: router.router_id || '',
        bridge_name: router.bridge_name || '',
        tagged_ports: router.tagged_ports || '',
        notes: router.notes || ''
      }))
    };
  }
  function openEditStation(station) {
    setStationEditingId(station.id);
    setStationForm(stationToForm(station));
    setStationActiveRouterIndex(0);
    setStationPortSearch({});
    setStationReview(null);
    setStationError('');
    setStationModalOpen(true);
    (station.routers || []).forEach((router) => {
      if (router.router_id && !mikrotikOptions[router.router_id]) loadMikrotikRouterOptions(router.router_id);
    });
  }
  function openStationModal() {
    setStationForm({
      station_name: '',
      station_code: '',
      description: '',
      vlan_id: '77',
      vlan_interface_name: 'VLAN77-3J-HOTSPOT',
      client_network_cidr: '10.77.0.0/24',
      gateway_ip: '10.77.0.1',
      pool_start_ip: '10.77.0.2',
      pool_end_ip: '10.77.0.254',
      pool_name: 'POOL-3J-HOTSPOT-V77',
      create_dhcp_server: true,
      dhcp_server_name: 'DHCP-3J-HOTSPOT-V77',
      dhcp_lease_time: '1h',
      dns_servers: '8.8.8.8,1.1.1.1',
      local_interface_list: 'LOCAL',
      create_hotspot_profile: true,
      create_hotspot_server: true,
      create_walled_garden: true,
      hotspot_profile_name: 'PROFILE-3J-HOTSPOT-V77',
      hotspot_html_directory: 'hotspot',
      hotspot_dns_name: 'wifi.3j.3jportal.test',
      hotspot_server_name: 'HS-3J-HOTSPOT-V77',
      portal_url: portalSettings.portal_url_staging || 'http://192.168.50.70:8080/portal',
      routers: []
    });
    setStationActiveRouterIndex(0);
    setStationPortSearch({});
    setStationReview(null);
    setStationEditingId('');
    setStationError('');
    setStationModalOpen(true);
  }
  function updateStationField(key, value) {
    setStationForm((current) => {
      const next = { ...current, [key]: value };
      if (key === 'station_name' && (!current.station_code || /^[a-z0-9-]+$/.test(current.station_code))) {
        next.station_code = String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
      }
      return next;
    });
  }
  function updateStationVlan(value) {
    setStationForm((current) => {
      const next = { ...current, vlan_id: value };
      const vlanNumber = Number(value);
      if (!current.vlan_interface_name || /^VLAN\d+-3J-HOTSPOT$/i.test(current.vlan_interface_name)) {
        next.vlan_interface_name = value ? `VLAN${value}-3J-HOTSPOT` : '';
      }
      if (!current.pool_name || /^POOL-3J-HOTSPOT-V\d+$/i.test(current.pool_name)) {
        next.pool_name = value ? `POOL-3J-HOTSPOT-V${value}` : '';
      }
      if (!current.dhcp_server_name || /^DHCP-3J-HOTSPOT-V\d+$/i.test(current.dhcp_server_name)) {
        next.dhcp_server_name = value ? `DHCP-3J-HOTSPOT-V${value}` : '';
      }
      if (!current.hotspot_profile_name || /^PROFILE-3J-HOTSPOT-V\d+$/i.test(current.hotspot_profile_name)) {
        next.hotspot_profile_name = value ? `PROFILE-3J-HOTSPOT-V${value}` : '';
      }
      if (!current.hotspot_server_name || /^HS-3J-HOTSPOT-V\d+$/i.test(current.hotspot_server_name)) {
        next.hotspot_server_name = value ? `HS-3J-HOTSPOT-V${value}` : '';
      }
      if (Number.isInteger(vlanNumber) && vlanNumber > 0 && vlanNumber < 255) {
        if (!current.client_network_cidr || /^10\.\d+\.0\.0\/24$/.test(current.client_network_cidr)) next.client_network_cidr = `10.${vlanNumber}.0.0/24`;
        if (!current.gateway_ip || /^10\.\d+\.0\.1$/.test(current.gateway_ip)) next.gateway_ip = `10.${vlanNumber}.0.1`;
        if (!current.pool_start_ip || /^10\.\d+\.0\.2$/.test(current.pool_start_ip)) next.pool_start_ip = `10.${vlanNumber}.0.2`;
        if (!current.pool_end_ip || /^10\.\d+\.0\.254$/.test(current.pool_end_ip)) next.pool_end_ip = `10.${vlanNumber}.0.254`;
        if (!current.dns_servers || /^(10\.\d+\.0\.1,)?8\.8\.8\.8,1\.1\.1\.1$/.test(current.dns_servers)) next.dns_servers = '8.8.8.8,1.1.1.1';
      }
      return next;
    });
  }
  function updateStationApManagementVlan(value) {
    setStationForm((current) => {
      const next = { ...current, ap_management_vlan_id: value };
      if (!current.ap_management_vlan_interface_name || /^VLAN\d+-AP-MGMT$/i.test(current.ap_management_vlan_interface_name)) {
        next.ap_management_vlan_interface_name = value ? `VLAN${value}-AP-MGMT` : '';
      }
      if (!current.ap_management_pool_name || /^POOL-AP-MGMT-V\d+$/i.test(current.ap_management_pool_name)) {
        next.ap_management_pool_name = value ? `POOL-AP-MGMT-V${value}` : '';
      }
      if (!current.ap_management_dhcp_server_name || /^DHCP-AP-MGMT-V\d+$/i.test(current.ap_management_dhcp_server_name)) {
        next.ap_management_dhcp_server_name = value ? `DHCP-AP-MGMT-V${value}` : '';
      }
      return next;
    });
  }
  function updateStationApManagementCidr(value) {
    setStationForm((current) => {
      const next = { ...current, ap_management_network_cidr: value };
      const preview = localNetworkPreview(value);
      if (preview.status === 'SUCCESS') {
        if (!current.ap_management_gateway_ip || /^10\.\d+\.\d+\.1$/.test(current.ap_management_gateway_ip)) next.ap_management_gateway_ip = preview.gateway_ip;
        if (!current.ap_management_pool_start_ip || /^10\.\d+\.\d+\.10$/.test(current.ap_management_pool_start_ip)) next.ap_management_pool_start_ip = preview.pool_start_ip;
        if (!current.ap_management_pool_end_ip || /^10\.\d+\.\d+\.254$/.test(current.ap_management_pool_end_ip)) next.ap_management_pool_end_ip = preview.pool_end_ip;
      }
      return next;
    });
  }
  function updateStationRouter(index, patch) {
    setStationForm((current) => ({
      ...current,
      routers: current.routers.map((router, routerIndex) => routerIndex === index ? { ...router, ...patch } : router)
    }));
  }
  function toggleStationTaggedPort(index, portName, checked) {
    setStationForm((current) => ({
      ...current,
      routers: current.routers.map((router, routerIndex) => {
        if (routerIndex !== index) return router;
        const existing = String(router.tagged_ports || '').split(',').map((item) => item.trim()).filter(Boolean);
        const next = checked
          ? Array.from(new Set([...existing, portName]))
          : existing.filter((item) => item !== portName);
        return { ...router, tagged_ports: next.join(',') };
      })
    }));
  }
  function addStationRouter() {
    setStationForm((current) => {
      setStationActiveRouterIndex(current.routers.length);
      return { ...current, routers: [...current.routers, stationRouterTemplate()] };
    });
  }
  function removeStationRouter(index) {
    setStationForm((current) => {
      const routers = current.routers.filter((_, routerIndex) => routerIndex !== index);
      setStationActiveRouterIndex((active) => Math.max(0, Math.min(active >= index ? active - 1 : active, Math.max(routers.length - 1, 0))));
      return { ...current, routers };
    });
  }
  function moveStationRouter(fromIndex, toIndex) {
    setStationForm((current) => {
      if (toIndex < 0 || toIndex >= current.routers.length || fromIndex === toIndex) return current;
      const routers = [...current.routers];
      const [item] = routers.splice(fromIndex, 1);
      routers.splice(toIndex, 0, item);
      setStationActiveRouterIndex(toIndex);
      return { ...current, routers };
    });
  }
  async function saveStation(e) {
    e.preventDefault();
    setStationSaving(true);
    setStationError('');
    try {
      const saved = await request(
        stationEditingId ? `/network/mikrotik/stations/${stationEditingId}` : '/network/mikrotik/stations',
        { method: stationEditingId ? 'PUT' : 'POST', body: JSON.stringify(stationForm) }
      );
      setStationReview(saved);
      setStationModalOpen(false);
      setStationEditingId('');
      setMessage(stationEditingId ? 'MikroTik station plan updated.' : 'MikroTik station plan saved.');
      try {
        await load();
      } catch (refreshError) {
        setActionResult({ status: 'FAILED', message: `Station saved, but refresh failed: ${refreshError.message}` });
      }
    } catch (error) {
      setStationError(error.message || 'MikroTik station plan could not be saved.');
    } finally {
      setStationSaving(false);
    }
  }
  async function downloadStationLoginHtml(station) {
    if (!station?.id) return;
    const token = localStorage.getItem('centralwifi_token');
    const res = await fetch(`/api/network/mikrotik/stations/${station.id}/hotspot-login.html`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'Could not download HotSpot login.html');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${station.station_code || station.station_name || 'station'}-login.html`;
    link.click();
    URL.revokeObjectURL(url);
  }
  async function checkHotspotLoginSync() {
    if (hotspotLoginChecking) return;
    setHotspotLoginChecking(true);
    try {
      const data = await request('/network/mikrotik/stations/hotspot-login-sync-status?remote=true');
      setHotspotLoginSync(data || { summary: {}, stations: [] });
      setMessage('HotSpot login.html sync status checked.');
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message || 'Could not check HotSpot login.html sync status.' });
    } finally {
      setHotspotLoginChecking(false);
    }
  }
  async function syncHotspotLoginHtml(stationId = '') {
    if (hotspotLoginSyncing) return null;
    setHotspotLoginSyncing(true);
    try {
      const data = stationId
        ? await request(`/network/mikrotik/stations/${stationId}/sync-hotspot-login`, { method: 'POST', body: JSON.stringify({}) })
        : await request('/network/mikrotik/stations/sync-hotspot-login', { method: 'POST', body: JSON.stringify({}) });
      setMessage(data.message || 'Managed HotSpot login.html synced.');
      const status = await request('/network/mikrotik/stations/hotspot-login-sync-status?remote=true').catch(() => null);
      if (status) setHotspotLoginSync(status);
      await loadStationCommandLogs(stationId || stationImplementation?.id || stationReview?.id);
      return data;
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message || 'Managed HotSpot login.html sync failed.' });
      return null;
    } finally {
      setHotspotLoginSyncing(false);
    }
  }
  function hotspotLoginStatusClass(status) {
    if (status === 'SYNCED' || status === 'SUCCESS') return 'bg-green-lt text-green';
    if (status === 'MISSING' || status === 'OUTDATED' || status === 'DETECTED' || status === 'UNKNOWN' || status === 'NEVER_SYNCED') return 'bg-yellow-lt text-yellow';
    if (status === 'ERROR' || status === 'FAILED' || status === 'NOT_READY') return 'bg-red-lt text-red';
    return 'bg-secondary-lt text-secondary';
  }
  function stationLoginSyncRow(stationId) {
    return (hotspotLoginSync.stations || []).find((item) => item.station_id === stationId);
  }
  function openApManagementModal() {
    setApManagementForm(apManagementToForm(apManagementConfig || {}));
    setApManagementActiveRouterIndex(0);
    setApManagementPortSearch({});
    setApManagementError('');
    setApManagementModalOpen(true);
    (apManagementConfig?.routers || []).forEach((router) => {
      if (router.router_id && !mikrotikOptions[router.router_id]) loadMikrotikRouterOptions(router.router_id);
    });
  }
  function updateApManagementField(key, value) {
    setApManagementForm((current) => ({ ...current, [key]: value }));
  }
  function updateApManagementVlan(value) {
    setApManagementForm((current) => {
      const next = { ...current, vlan_id: value };
      if (!current.vlan_interface_name || /^VLAN\d+-AP-MGMT$/i.test(current.vlan_interface_name)) next.vlan_interface_name = value ? `VLAN${value}-AP-MGMT` : '';
      if (!current.pool_name || /^POOL-AP-MGMT-V\d+$/i.test(current.pool_name)) next.pool_name = value ? `POOL-AP-MGMT-V${value}` : '';
      if (!current.dhcp_server_name || /^DHCP-AP-MGMT-V\d+$/i.test(current.dhcp_server_name)) next.dhcp_server_name = value ? `DHCP-AP-MGMT-V${value}` : '';
      return next;
    });
  }
  function updateApManagementCidr(value) {
    setApManagementForm((current) => {
      const next = { ...current, network_cidr: value };
      const preview = localNetworkPreview(value);
      if (preview.status === 'SUCCESS') {
        if (!current.gateway_ip || /^10\.\d+\.\d+\.1$/.test(current.gateway_ip)) next.gateway_ip = preview.gateway_ip;
        if (!current.pool_start_ip || /^10\.\d+\.\d+\.10$/.test(current.pool_start_ip)) next.pool_start_ip = preview.pool_start_ip;
        if (!current.pool_end_ip || /^10\.\d+\.\d+\.254$/.test(current.pool_end_ip)) next.pool_end_ip = preview.pool_end_ip;
      }
      return next;
    });
  }
  function updateApManagementRouter(index, patch) {
    setApManagementForm((current) => ({
      ...current,
      routers: current.routers.map((router, routerIndex) => routerIndex === index ? { ...router, ...patch } : router)
    }));
  }
  function addApManagementRouter() {
    setApManagementForm((current) => {
      setApManagementActiveRouterIndex(current.routers.length);
      return { ...current, routers: [...current.routers, apManagementRouterTemplate()] };
    });
  }
  function removeApManagementRouter(index) {
    setApManagementForm((current) => {
      const routers = current.routers.filter((_, routerIndex) => routerIndex !== index);
      setApManagementActiveRouterIndex((active) => Math.max(0, Math.min(active >= index ? active - 1 : active, Math.max(routers.length - 1, 0))));
      return { ...current, routers };
    });
  }
  function moveApManagementRouter(fromIndex, toIndex) {
    setApManagementForm((current) => {
      if (toIndex < 0 || toIndex >= current.routers.length || fromIndex === toIndex) return current;
      const routers = [...current.routers];
      const [item] = routers.splice(fromIndex, 1);
      routers.splice(toIndex, 0, item);
      setApManagementActiveRouterIndex(toIndex);
      return { ...current, routers };
    });
  }
  function toggleApManagementTaggedPort(index, portName, checked) {
    setApManagementForm((current) => ({
      ...current,
      routers: current.routers.map((router, routerIndex) => {
        if (routerIndex !== index) return router;
        const existing = String(router.tagged_ports || '').split(',').map((item) => item.trim()).filter(Boolean);
        const next = checked
          ? Array.from(new Set([...existing, portName]))
          : existing.filter((item) => item !== portName);
        return { ...router, tagged_ports: next.join(',') };
      })
    }));
  }
  async function saveApManagement(e) {
    e.preventDefault();
    setApManagementSaving(true);
    setApManagementError('');
    try {
      const saved = await request('/network/mikrotik/ap-management', { method: 'PUT', body: JSON.stringify(apManagementForm) });
      setApManagementConfig(saved);
      setApManagementModalOpen(false);
      setMessage('Central AP management plan saved.');
      await load();
    } catch (error) {
      setApManagementError(error.message || 'AP management details could not be saved.');
    } finally {
      setApManagementSaving(false);
    }
  }
  function apManagementStepList(config) {
    return (config?.plan?.router_plans || []).flatMap((routerPlan) => (
      (routerPlan.commands || []).map((command, commandIndex) => ({
        id: `ap-management-${routerPlan.router_id}-${commandIndex}`,
        router_id: routerPlan.router_id,
        router_name: routerPlan.router_name,
        router_role: routerPlan.role,
        host: routerPlan.host,
        command_index: commandIndex,
        label: command.label || `Command ${commandIndex + 1}`,
        preview: command.preview || '',
        status: 'PENDING',
        message: '',
        result: null
      }))
    ));
  }
  function apManagementStepsWithDetectedProgress(steps, progress) {
    if (!progress) return steps;
    const foundKeys = new Set();
    (progress.routers || []).forEach((router) => {
      (router.items || []).forEach((item) => {
        if (item.status === 'FOUND') foundKeys.add(`${router.router_id}-${item.command_index}`);
      });
    });
    return steps.map((step) => {
      if (foundKeys.has(`${step.router_id}-${step.command_index}`)) {
        return { ...step, status: 'SKIPPED', detected: true, message: 'Detected on MikroTik. This step will be skipped/kept during push.' };
      }
      return step.status === 'SKIPPED' && step.detected ? { ...step, status: 'PENDING', detected: false, message: '' } : step;
    });
  }
  function apManagementProgressSummary(config = apManagementConfig) {
    const progress = apManagementManagedStatus?.push_progress || config?.push_progress;
    const fallbackTotal = apManagementStepList(config).length;
    if (progress) return { pushed: progress.pushed_steps || 0, total: progress.total_steps || fallbackTotal };
    return { pushed: 0, total: fallbackTotal };
  }
  function scrollApManagementStepIntoView(stepId) {
    setTimeout(() => {
      const node = apManagementStepRefs.current[stepId];
      if (node?.scrollIntoView) node.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 80);
  }
  async function checkApManagementConfiguration(config = apManagementImplementation || apManagementConfig, options = {}) {
    if (!config?.id || apManagementCheckingManaged) return null;
    setApManagementCheckingManaged(true);
    try {
      const status = await request(`/network/mikrotik/ap-management/${config.id}/managed-configuration-status${options.quiet ? '?quiet=true' : ''}`);
      setApManagementManagedStatus(status);
      if (status.push_progress && options.updatePushSteps) {
        setApManagementImplementationSteps((current) => apManagementStepsWithDetectedProgress(
          current.length ? current : apManagementStepList(config),
          status.push_progress
        ));
      }
      return status;
    } catch (error) {
      const status = { status: 'ERROR', message: error.message || 'AP management config check failed.', found_count: 0, routers: [] };
      setApManagementManagedStatus(status);
      return status;
    } finally {
      setApManagementCheckingManaged(false);
    }
  }
  function openApManagementImplementation() {
    if (!apManagementConfig?.id) return;
    setApManagementImplementation(apManagementConfig);
    setApManagementImplementationSteps(apManagementStepList(apManagementConfig));
    setApManagementImplementationMessage('Validating already pushed AP management config...');
    setApManagementPushCompleted(false);
    setApManagementPushCloseCountdown(10);
    setApManagementManagedStatus(null);
    checkApManagementConfiguration(apManagementConfig, { updatePushSteps: true });
  }
  function closeApManagementPushSuccess() {
    setApManagementImplementation(null);
    setApManagementPushCompleted(false);
    setApManagementPushCloseCountdown(10);
    setApManagementImplementationMessage('');
    setActionResult({ status: 'SUCCESS', message: 'Central AP management configuration push completed successfully.' });
    load().catch(() => null);
  }
  async function runApManagementImplementation() {
    if (!apManagementImplementation || apManagementImplementing) return;
    const progress = apManagementManagedStatus?.push_progress;
    const steps = apManagementStepsWithDetectedProgress(apManagementStepList(apManagementImplementation), progress);
    if (!steps.length) {
      setApManagementImplementationMessage('No RouterOS commands are available for AP management.');
      return;
    }
    setApManagementImplementing(true);
    setApManagementImplementationMessage('AP management config push started. Commands are sent one at a time.');
    setApManagementImplementationSteps(steps);
    let failed = false;
    for (let index = 0; index < steps.length; index += 1) {
      const step = steps[index];
      if (step.status === 'SKIPPED') continue;
      setApManagementImplementationSteps((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, status: 'RUNNING', message: 'Sending to MikroTik...' } : item));
      scrollApManagementStepIntoView(step.id);
      try {
        const result = await request(`/network/mikrotik/ap-management/${apManagementImplementation.id}/implement-command`, {
          method: 'POST',
          body: JSON.stringify({ router_id: step.router_id, command_index: step.command_index })
        });
        const status = result.status || 'SUCCESS';
        setApManagementImplementationSteps((current) => current.map((item, itemIndex) => itemIndex === index ? {
          ...item,
          status,
          message: result.message || (status === 'SKIPPED' ? 'Existing AP management config found; skipped.' : 'Command completed.'),
          result
        } : item));
      } catch (error) {
        failed = true;
        setApManagementImplementationSteps((current) => current.map((item, itemIndex) => itemIndex === index ? {
          ...item,
          status: 'FAILED',
          message: error.message || 'Command failed.',
          result: null
        } : item));
        setApManagementImplementationMessage(`Stopped at ${step.router_name || 'router'}: ${error.message || 'command failed.'}`);
        break;
      }
    }
    setApManagementImplementing(false);
    if (!failed) {
      setApManagementImplementationMessage('Central AP management config push completed. Existing matching objects may have been skipped safely.');
      setApManagementPushCompleted(true);
      setApManagementPushCloseCountdown(10);
      await checkApManagementConfiguration(apManagementImplementation, { updatePushSteps: true });
      await load().catch(() => null);
    }
  }
  function stationRouterTooltip(station, router, index) {
    const ports = String(router.tagged_ports || '').split(',').map((item) => item.trim()).filter(Boolean);
    const lines = [
      index === 0 ? 'Root gateway' : `Hop ${index + 1}`,
      `${router.router_name || 'Router'}${router.host ? ` (${router.host})` : ''}`,
      router.bridge_name ? `Bridge/interface: ${router.bridge_name}` : '',
      ports.length ? `Tagged ports: ${ports.join(', ')}` : ''
    ].filter(Boolean);
    return lines.join('\n');
  }
  function stationPortBadges(value, prefix) {
    const ports = String(value || '').split(',').map((item) => item.trim()).filter(Boolean);
    if (!ports.length) return <span className="text-muted small">No tagged ports selected</span>;
    return ports.map((port) => (
      <span className="badge bg-blue-lt text-blue station-link-port-badge" key={`${prefix}-${port}`}>
        {port}
      </span>
    ));
  }
  function stationImplementationStepList(station) {
    const routerSteps = (station?.plan?.router_plans || []).flatMap((routerPlan) => (
      (routerPlan.commands || []).map((command, commandIndex) => ({
        id: `${routerPlan.router_id}-${commandIndex}`,
        router_id: routerPlan.router_id,
        router_name: routerPlan.router_name,
        router_role: routerPlan.role,
        host: routerPlan.host,
        command_index: commandIndex,
        label: command.label || `Command ${commandIndex + 1}`,
        preview: command.preview || '',
        status: 'PENDING',
        message: '',
        result: null
      }))
    ));
    if (!station?.id) return routerSteps;
    const rootRouter = (station.plan?.router_plans || [])[0] || (station.routers || [])[0] || {};
    return [
      ...routerSteps,
      {
        id: `${station.id}-sync-login-html`,
        action: 'sync_login_html',
        router_id: rootRouter.router_id,
        router_name: rootRouter.router_name,
        router_role: 'ROOT_GATEWAY',
        host: rootRouter.host,
        command_index: null,
        label: 'Upload managed HotSpot login.html',
        preview: `/file set-or-add name=${station.hotspot_login_file_path || 'hotspot/login.html'} contents=<3J managed redirect template>`,
        status: 'PENDING',
        message: '',
        result: null
      }
    ];
  }
  function stepsWithDetectedProgress(steps, progress) {
    if (!progress) return steps;
    const foundKeys = new Set();
    (progress.routers || []).forEach((router) => {
      (router.items || []).forEach((item) => {
        if (item.status === 'FOUND') foundKeys.add(`${router.router_id}-${item.command_index}`);
      });
    });
    const loginSynced = progress.login_html_status?.status === 'SYNCED';
    return steps.map((step) => {
      if (step.action === 'sync_login_html' && loginSynced) {
        return { ...step, status: 'SKIPPED', detected: true, message: 'Managed login.html is already synced on the root gateway.' };
      }
      if (foundKeys.has(`${step.router_id}-${step.command_index}`)) {
        return { ...step, status: 'SKIPPED', detected: true, message: 'Detected on MikroTik. This step will be skipped/kept during push.' };
      }
      return step.status === 'SKIPPED' && step.detected ? { ...step, status: 'PENDING', detected: false, message: '' } : step;
    });
  }
  function stationProgressSummary(station) {
    const progress = stationProgressMap[station.id] || station.push_progress;
    const fallbackTotal = stationImplementationStepList(station).length;
    if (progress) return { pushed: progress.pushed_steps || 0, total: progress.total_steps || fallbackTotal };
    const synced = station.hotspot_login_sync?.is_current ? 1 : 0;
    return { pushed: synced, total: fallbackTotal };
  }
  function scrollStationStepIntoView(stepId) {
    setTimeout(() => {
      const node = stationStepRefs.current[stepId];
      if (node?.scrollIntoView) node.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 80);
  }
  function stationRemoveStepList(station) {
    return (station?.remove_plan?.router_plans || []).flatMap((routerPlan) => (
      (routerPlan.commands || []).map((command, commandIndex) => ({
        id: `${routerPlan.router_id}-remove-${commandIndex}`,
        router_id: routerPlan.router_id,
        router_name: routerPlan.router_name,
        router_role: routerPlan.role,
        host: routerPlan.host,
        command_index: commandIndex,
        label: command.label || `Remove ${commandIndex + 1}`,
        preview: command.preview || '',
        status: 'PENDING',
        message: '',
        result: null
      }))
    ));
  }
  async function loadStationCommandLogs(stationId) {
    if (!stationId) return;
    try {
      const logs = await request(`/network/mikrotik/stations/${stationId}/command-logs`);
      setStationCommandLogs(Array.isArray(logs) ? logs : []);
    } catch {
      setStationCommandLogs([]);
    }
  }
  async function checkStationManagedConfiguration(station = stationImplementation || stationRemove, options = {}) {
    if (!station?.id || stationCheckingManaged) return null;
    setStationCheckingManaged(true);
    try {
      const status = await request(`/network/mikrotik/stations/${station.id}/managed-configuration-status`);
      setStationManagedStatus(status);
      if (status.push_progress) {
        setStationProgressMap((current) => ({ ...current, [station.id]: status.push_progress }));
        setMikrotikStations((current) => current.map((item) => item.id === station.id ? { ...item, push_progress: status.push_progress } : item));
        if (options.updatePushSteps) {
          setStationImplementationSteps((current) => stepsWithDetectedProgress(
            current.length ? current : stationImplementationStepList(station),
            status.push_progress
          ));
        }
      }
      await loadStationCommandLogs(station.id);
      return status;
    } catch (error) {
      const status = { status: 'ERROR', message: error.message || 'Station config check failed.', found_count: 0, routers: [] };
      setStationManagedStatus(status);
      return status;
    } finally {
      setStationCheckingManaged(false);
    }
  }
  async function refreshStationProgressSummaries(stations) {
    const rows = Array.isArray(stations) ? stations.filter((station) => station?.id) : [];
    for (const station of rows) {
      try {
        const status = await request(`/network/mikrotik/stations/${station.id}/managed-configuration-status?quiet=true`);
        if (status.push_progress) {
          setStationProgressMap((current) => ({ ...current, [station.id]: status.push_progress }));
          setMikrotikStations((current) => current.map((item) => item.id === station.id ? { ...item, push_progress: status.push_progress } : item));
        }
      } catch {
        // Keep the last visible progress if a background refresh cannot reach a router.
      }
    }
  }
  function openStationImplementation(station) {
    setStationImplementation(station);
    const cachedProgress = stationProgressMap[station.id] || station.push_progress;
    setStationImplementationSteps(stepsWithDetectedProgress(stationImplementationStepList(station), cachedProgress));
    setStationImplementationMessage('Validating already pushed RouterOS config...');
    setStationPushCompleted(false);
    setStationPushCloseCountdown(10);
    setStationManagedStatus(null);
    loadStationCommandLogs(station.id);
    checkStationManagedConfiguration(station, { updatePushSteps: true });
  }
  function closeStationPushSuccess() {
    const stationName = stationImplementation?.station_name || 'Station';
    const station = stationImplementation;
    setStationImplementation(null);
    setStationPushCompleted(false);
    setStationPushCloseCountdown(10);
    setStationImplementationMessage('');
    setActionResult({ status: 'SUCCESS', message: `${stationName} configuration push completed successfully.` });
    if (station) refreshStationProgressSummaries([station]);
  }
  function openStationRemove(station) {
    setStationRemove(station);
    setStationRemoveSteps(stationRemoveStepList(station));
    setStationRemoveMessage('Validating station-created RouterOS config before remove is enabled...');
    setStationRemoveCompleted(false);
    setStationRemoveCloseCountdown(10);
    setStationManagedStatus(null);
    loadStationCommandLogs(station.id);
    checkStationManagedConfiguration(station).then((status) => {
      if (!status) return;
      setStationRemoveMessage(status.has_managed_config
        ? `${status.found_count || 0} station-created object(s) detected. Review the remove steps before starting.`
        : 'No station-created RouterOS config was detected for this station.');
    });
  }
  function closeStationRemoveSuccess() {
    const stationName = stationRemove?.station_name || 'Station';
    const station = stationRemove;
    setStationRemove(null);
    setStationRemoveCompleted(false);
    setStationRemoveCloseCountdown(10);
    setStationRemoveMessage('');
    setStationManagedStatus(null);
    setActionResult({ status: 'SUCCESS', message: `${stationName} configuration was removed successfully.` });
    if (station) refreshStationProgressSummaries([station]);
  }
  function stationDiagnosticStatusClass(status) {
    if (status === 'OK' || status === 'READY') return 'bg-green-lt text-green';
    if (status === 'FAILED') return 'bg-red-lt text-red';
    return 'bg-yellow-lt text-yellow';
  }
  async function runStationHotspotDiagnostics(station = stationDiagnostics?.station, clientIp = stationDiagnosticsClientIp) {
    if (!station?.id || stationDiagnosticsLoading) return;
    setStationDiagnosticsLoading(true);
    try {
      const query = clientIp ? `?client_ip=${encodeURIComponent(clientIp)}` : '';
      const result = await request(`/network/mikrotik/stations/${station.id}/hotspot-diagnostics${query}`);
      setStationDiagnostics({ station, result });
    } catch (error) {
      setStationDiagnostics({ station, result: { status: 'FAILED', checks: [], summary: {}, station, message: error.message } });
    } finally {
      setStationDiagnosticsLoading(false);
    }
  }
  function openStationDiagnostics(station) {
    setStationDiagnostics({ station, result: null });
    setStationDiagnosticsClientIp('');
    runStationHotspotDiagnostics(station, '');
  }
  function stationImplementationStatusIcon(status) {
    if (status === 'SUCCESS' || status === 'SKIPPED') return <IconCircleCheck size={17} />;
    if (status === 'FAILED') return <IconAlertTriangle size={17} />;
    if (status === 'RUNNING') return <IconRefresh size={17} />;
    return <IconClock size={17} />;
  }
  function renderStationManagedStatus() {
    if (!stationManagedStatus) return <div className="text-muted small">Run Check Existing Config before applying or removing station RouterOS objects.</div>;
    return (
      <div className={`alert py-2 mb-0 ${stationManagedStatus.status === 'ERROR' ? 'alert-danger' : stationManagedStatus.has_managed_config ? 'alert-warning' : 'alert-info'}`}>
        <div className="fw-semibold">{stationManagedStatus.found_count || 0} station-managed object(s) detected</div>
        {stationManagedStatus.message && <div className="small">{stationManagedStatus.message}</div>}
        {!!(stationManagedStatus.routers || []).length && (
          <div className="d-flex flex-wrap gap-1 mt-2">
            {stationManagedStatus.routers.map((router) => (
              <span className={`badge ${router.status === 'ERROR' ? 'bg-red-lt text-red' : router.found_count ? 'bg-yellow-lt text-yellow' : 'bg-secondary-lt text-secondary'}`} key={`station-managed-${router.router_id}`}>
                {router.router_name || 'Router'}: {router.found_count || 0}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }
  function renderStationCommandHistory() {
    if (!stationCommandLogs.length) return <div className="text-muted small">No station command history yet.</div>;
    return (
      <div className="station-history-list">
        {stationCommandLogs.slice(0, 8).map((log) => (
          <div className="station-history-item" key={log.id}>
            <span className={`badge ${log.command_status === 'FAILED' ? 'bg-red-lt text-red' : log.command_status === 'SUCCESS' || log.command_status === 'SKIPPED' ? 'bg-green-lt text-green' : 'bg-secondary-lt text-secondary'}`}>
              {log.operation}
            </span>
            <div className="min-w-0">
              <div className="fw-semibold text-truncate">{log.command_label || 'Station operation'}</div>
              <div className="text-muted small text-truncate">{log.router_name || 'Station'} · {log.command_status} · {fmt(log.created_at)}</div>
              {log.message && <div className="text-muted small text-truncate">{log.message}</div>}
            </div>
          </div>
        ))}
      </div>
    );
  }
  async function runStationImplementation() {
    if (!stationImplementation || stationImplementing) return;
    const progress = stationProgressMap[stationImplementation.id] || stationManagedStatus?.push_progress;
    const steps = stepsWithDetectedProgress(stationImplementationStepList(stationImplementation), progress);
    if (!steps.length) {
      setStationImplementationMessage('No RouterOS commands are available for this station plan.');
      return;
    }
    setStationImplementing(true);
    setStationImplementationMessage('Config push started. Commands are sent one at a time.');
    setStationImplementationSteps(steps);
    let failed = false;
    for (let index = 0; index < steps.length; index += 1) {
      const step = steps[index];
      if (step.status === 'SKIPPED') continue;
      setStationImplementationSteps((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, status: 'RUNNING', message: step.action === 'sync_login_html' ? 'Uploading managed login.html...' : 'Sending to MikroTik...' } : item));
      scrollStationStepIntoView(step.id);
      try {
        const result = step.action === 'sync_login_html'
          ? await request(`/network/mikrotik/stations/${stationImplementation.id}/sync-hotspot-login`, { method: 'POST', body: JSON.stringify({}) })
          : await request(`/network/mikrotik/stations/${stationImplementation.id}/implement-command`, {
            method: 'POST',
            body: JSON.stringify({ router_id: step.router_id, command_index: step.command_index })
          });
        const status = result.status || 'SUCCESS';
        setStationImplementationSteps((current) => current.map((item, itemIndex) => itemIndex === index ? {
          ...item,
          status,
          message: result.message || (step.action === 'sync_login_html' ? 'Managed login.html uploaded.' : status === 'SKIPPED' ? 'Existing configuration found; skipped.' : 'Command completed.'),
          result
        } : item));
      } catch (error) {
        failed = true;
        setStationImplementationSteps((current) => current.map((item, itemIndex) => itemIndex === index ? {
          ...item,
          status: 'FAILED',
          message: error.message || 'Command failed.',
          result: null
        } : item));
        setStationImplementationMessage(`Stopped at ${step.router_name || 'router'}: ${error.message || 'command failed.'}`);
        break;
      }
    }
    setStationImplementing(false);
    if (!failed) {
      setStationImplementationMessage('Station config push completed. Existing matching objects may have been skipped safely.');
      setStationPushCompleted(true);
      setStationPushCloseCountdown(10);
      try {
        await load();
      } catch (refreshError) {
        setActionResult({ status: 'FAILED', message: `Config push completed, but refresh failed: ${refreshError.message}` });
      }
      const syncStatus = await request('/network/mikrotik/stations/hotspot-login-sync-status?remote=true').catch(() => null);
      if (syncStatus) setHotspotLoginSync(syncStatus);
      await checkStationManagedConfiguration(stationImplementation);
      await loadStationCommandLogs(stationImplementation.id);
    }
  }
  async function runStationRemove() {
    if (!stationRemove || stationRemoving) return;
    const steps = stationRemoveStepList(stationRemove);
    if (!steps.length) {
      setStationRemoveMessage('No remove commands are available for this station plan.');
      return;
    }
    setStationRemoving(true);
    setStationRemoveMessage('Remove config started. Commands are sent one at a time in reverse order.');
    setStationRemoveSteps(steps);
    let failed = false;
    for (let index = 0; index < steps.length; index += 1) {
      const step = steps[index];
      setStationRemoveSteps((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, status: 'RUNNING', message: 'Removing from MikroTik...' } : item));
      scrollStationStepIntoView(step.id);
      try {
        const result = await request(`/network/mikrotik/stations/${stationRemove.id}/remove-command`, {
          method: 'POST',
          body: JSON.stringify({ router_id: step.router_id, command_index: step.command_index })
        });
        const status = result.status || 'SUCCESS';
        setStationRemoveSteps((current) => current.map((item, itemIndex) => itemIndex === index ? {
          ...item,
          status,
          message: result.message || (status === 'SKIPPED' ? 'No matching station-created object found.' : 'Remove command completed.'),
          result
        } : item));
      } catch (error) {
        failed = true;
        setStationRemoveSteps((current) => current.map((item, itemIndex) => itemIndex === index ? {
          ...item,
          status: 'FAILED',
          message: error.message || 'Remove command failed.',
          result: null
        } : item));
        setStationRemoveMessage(`Stopped at ${step.router_name || 'router'}: ${error.message || 'remove command failed.'}`);
        break;
      }
    }
    setStationRemoving(false);
    if (!failed) {
      setStationRemoveMessage('Station remove config completed. Existing shared objects may have been skipped safely.');
      setStationRemoveCompleted(true);
      setStationRemoveCloseCountdown(10);
      setStationManagedStatus(null);
      try {
        await load();
        await loadStationCommandLogs(stationRemove.id);
      } catch (refreshError) {
        setActionResult({ status: 'FAILED', message: `Remove completed, but refresh failed: ${refreshError.message}` });
      }
    }
  }
  function renderStationChainPath(station) {
    const routers = station.routers || [];
    if (!routers.length) return <span className="text-muted small">No routers</span>;
    return (
      <div className="station-table-chain" aria-label={`${station.station_name} router chain`}>
        {routers.map((router, index) => (
          <React.Fragment key={router.id || `${station.id}-${router.router_id}`}>
            <div className="station-table-chain-item" aria-label={stationRouterTooltip(station, router, index)}>
              <span className={`station-chain-node station-table-chain-node ${index === 0 ? 'root' : ''}`}><IconRouter size={16} /></span>
              <span className="station-table-chain-text">
                <strong>{router.router_name || `Router ${index + 1}`}</strong>
                <small>{index === 0 ? 'Root' : `Hop ${index + 1}`} · {router.bridge_name || 'No bridge'}</small>
              </span>
              <div className="station-router-popover">
                <div className="station-chain-popover-header">
                  <IconRouter size={16} />
                  <span>{router.router_name || `Router ${index + 1}`}</span>
                </div>
                <div className="station-chain-popover-section">
                  <div className="station-chain-popover-label"><IconActivity size={14} /> Router details</div>
                  <div className="station-chain-popover-badges">
                    <span className={`badge ${index === 0 ? 'bg-green-lt text-green' : 'bg-cyan-lt text-cyan'}`}>{index === 0 ? 'Root gateway' : `Hop ${index + 1}`}</span>
                    <span className="badge bg-secondary-lt text-secondary">{router.station_role || (index === 0 ? 'ROOT_GATEWAY' : 'TRUNK_HELPER')}</span>
                    {router.api_status && <span className={`badge ${router.api_status === 'REACHABLE' ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{router.api_status}</span>}
                  </div>
                  <div className="station-chain-popover-meta">
                    {router.host && <span><IconServer size={13} /> {router.host}{router.api_port ? `:${router.api_port}` : ''}</span>}
                    <span><IconWifi size={13} /> {index === 0 ? `Creates HotSpot VLAN ${station.vlan_id}` : `Carries HotSpot VLAN ${station.vlan_id}`}</span>
                  </div>
                </div>
                <div className="station-chain-popover-section mb-0">
                  <div className="station-chain-popover-label"><IconRouter size={14} /> Selected bridge and tags</div>
                  <div className="station-chain-popover-route">
                    <span className="badge bg-secondary-lt text-secondary">{router.bridge_name || 'No bridge/interface'}</span>
                    {stationPortBadges(router.tagged_ports, `${station.id}-${router.router_id}-router`)}
                  </div>
                </div>
              </div>
            </div>
            {index < routers.length - 1 && (
              <div className="station-table-chain-link">
                <span className="station-table-chain-rail"><span /></span>
                <button
                  className="station-table-chain-dot"
                  type="button"
                  aria-label={`View VLAN path between ${router.router_name || 'router'} and ${routers[index + 1]?.router_name || 'next router'}`}
                />
                <div className="station-chain-popover">
                  <div className="station-chain-popover-header">
                    <IconRouter size={16} />
                    <span>{router.router_name || 'Router'} to {routers[index + 1]?.router_name || 'Next router'}</span>
                  </div>
                  <div className="station-chain-popover-section">
                    <div className="station-chain-popover-label"><IconWifi size={14} /> Customer HotSpot VLAN</div>
                    <div className="station-chain-popover-badges">
                      <span className="badge bg-green-lt text-green">VLAN {station.vlan_id}</span>
                      {station.vlan_interface_name && <span className="badge bg-cyan-lt text-cyan">{station.vlan_interface_name}</span>}
                      <span className="badge bg-purple-lt text-purple">{station.client_network_cidr}</span>
                    </div>
                    <div className="station-chain-popover-meta">
                      <span><IconServer size={13} /> Gateway {station.gateway_ip}</span>
                      <span><IconDatabase size={13} /> Pool {station.pool_start_ip}-{station.pool_end_ip}</span>
                    </div>
                  </div>
                  <div className="station-chain-popover-section">
                    <div className="station-chain-popover-label"><IconRouter size={14} /> From router tags</div>
                    <div className="station-chain-popover-route">
                      <span className="badge bg-secondary-lt text-secondary">{router.bridge_name || 'No bridge/interface'}</span>
                      {stationPortBadges(router.tagged_ports, `${station.id}-${router.router_id}-from`)}
                    </div>
                  </div>
                  <div className="station-chain-popover-section mb-0">
                    <div className="station-chain-popover-label"><IconRouter size={14} /> To router tags</div>
                    <div className="station-chain-popover-route">
                      <span className="badge bg-secondary-lt text-secondary">{routers[index + 1]?.bridge_name || 'No bridge/interface'}</span>
                      {stationPortBadges(routers[index + 1]?.tagged_ports, `${station.id}-${routers[index + 1]?.router_id}-to`)}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    );
  }
  async function load() {
    const [system, portalCfg, routerRows, stationRows, apManagementRow, loginSyncRows, events, voucherData, voucherLogs, portalSessions, authLogs] = await Promise.all([
      request('/system/settings'),
      request('/captive-portal/settings'),
      request('/captive-portal/mikrotik'),
      request('/network/mikrotik/stations'),
      request('/network/mikrotik/ap-management').catch(() => null),
      request('/network/mikrotik/stations/hotspot-login-sync-status').catch(() => ({ summary: {}, stations: [] })),
      request('/portal/events'),
      request('/vouchers'),
      request('/voucher-redemptions?source=CLIENT_PORTAL'),
      request('/captive-portal/sessions'),
      request('/captive-portal/authorizations')
    ]);
    setSettings(system);
    setPortalSettings(portalCfg);
    const safeRouterRows = Array.isArray(routerRows) ? routerRows : [];
    setMikrotiks(safeRouterRows);
    setMikrotikRows(editableMikrotikRows(safeRouterRows));
    const safeStationRows = Array.isArray(stationRows) ? stationRows : [];
    setMikrotikStations(safeStationRows);
    refreshStationProgressSummaries(safeStationRows);
    if (apManagementRow) {
      setApManagementConfig(apManagementRow);
      if (apManagementRow.id) checkApManagementConfiguration(apManagementRow, { quiet: true });
    }
    setHotspotLoginSync(loginSyncRows || { summary: {}, stations: [] });
    setPreflightRouterId((current) => current || safeRouterRows[0]?.id || '');
    setAiRouterId((current) => safeRouterRows.some((router) => router.id === current) ? current : '');
    setPortalEvents(Array.isArray(events) ? events : []);
    setVoucherSummary(voucherData?.summary || {});
    setRedemptions(Array.isArray(voucherLogs) ? voucherLogs : []);
    setSessions(Array.isArray(portalSessions) ? portalSessions : []);
    setAuthorizations(Array.isArray(authLogs) ? authLogs : []);
  }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!apManagementPushCompleted || !apManagementImplementation) return undefined;
    if (apManagementPushCloseCountdown <= 0) {
      closeApManagementPushSuccess();
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setApManagementPushCloseCountdown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [apManagementPushCompleted, apManagementPushCloseCountdown, apManagementImplementation]);
  useEffect(() => {
    if (!stationPushCompleted || !stationImplementation) return undefined;
    if (stationPushCloseCountdown <= 0) {
      closeStationPushSuccess();
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setStationPushCloseCountdown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [stationPushCompleted, stationPushCloseCountdown, stationImplementation]);
  useEffect(() => {
    if (!stationRemoveCompleted || !stationRemove) return undefined;
    if (stationRemoveCloseCountdown <= 0) {
      closeStationRemoveSuccess();
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setStationRemoveCloseCountdown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [stationRemoveCompleted, stationRemoveCloseCountdown, stationRemove]);
  useEffect(() => {
    if (activeTab === 'MikroTik' && (mikrotikTab === 'Overview' || mikrotikTab === 'Configuration')) {
      loadPreflightSummary();
    }
    if (activeTab === 'MikroTik' && mikrotikTab === 'Scan Result' && preflightView) {
      loadPreflightLatest(preflightView);
    }
  }, [activeTab, mikrotikTab, preflightView]);
  async function saveBranding(e) {
    e.preventDefault();
    await request('/system/settings', { method: 'PATCH', body: JSON.stringify({ branding: settings.branding }) });
    setMessage('Portal branding saved.');
    await load();
  }
  async function savePortalSettings(e) {
    e.preventDefault();
    const saved = await request('/captive-portal/settings', { method: 'PUT', body: JSON.stringify(portalSettings) });
    setPortalSettings(saved);
    setMessage('Portal settings saved.');
  }
  function addMikrotikRow() {
    const existingNumbers = mikrotikRows
      .map((row) => String(row.router_name || '').match(/^Router\s+(\d+)$/i)?.[1])
      .filter(Boolean)
      .map(Number);
    const nextNumber = existingNumbers.length ? Math.max(...existingNumbers) + 1 : mikrotikRows.length + 1;
    setMikrotikRows([
      ...mikrotikRows,
      {
        id: `new-${Date.now()}`,
        router_name: `Router ${nextNumber}`,
        host: '',
        api_port: 8728,
        use_tls: false,
        username: '',
        password: '',
        account_privilege: 'FULL',
        notes: '',
        hotspot_vlan_id: '',
        hotspot_vlan_parent_interface: '',
        hotspot_vlan_interface_name: '',
        hotspot_interface: '',
        hotspot_profile_name: '',
        hotspot_server_name: '',
        hotspot_dns_name: '',
        hotspot_html_directory: 'hotspot',
        hotspot_client_network_cidr: '',
        hotspot_gateway_ip: '',
        hotspot_pool_start_ip: '',
        hotspot_pool_end_ip: '',
        hotspot_pool_name: '',
        hotspot_dhcp_server_name: '',
        hotspot_dhcp_lease_time: '1h',
        hotspot_dns_servers: '',
        hotspot_wan_interface: '',
        hotspot_enable_nat: false,
        status: 'NOT_SAVED',
        last_test_at: null,
        last_error: null,
        _isNew: true,
        _remove: false
      }
    ]);
  }
	  function updateMikrotikRow(rowId, patch) {
	    setMikrotikRows((rows) => rows.map((row) => {
	      if (row.id !== rowId) return row;
	      const next = { ...row, ...patch };
	      if (Object.prototype.hasOwnProperty.call(patch, 'use_tls')) {
	        next.api_port = patch.use_tls ? 8729 : 8728;
	      }
	      return next;
	    }));
	  }
	  function mikrotikPayload(row) {
	    return {
	      router_name: row.router_name || 'Router',
	      host: row.host || '',
	      api_port: Number(row.api_port || 8728),
	      use_tls: Boolean(row.use_tls),
	      username: row.username || '',
	      account_privilege: 'FULL',
	      notes: row.notes || '',
	      hotspot_vlan_id: row.hotspot_vlan_id === '' || row.hotspot_vlan_id === null || row.hotspot_vlan_id === undefined ? null : Number(row.hotspot_vlan_id),
	      hotspot_vlan_parent_interface: row.hotspot_vlan_parent_interface || '',
	      hotspot_vlan_interface_name: row.hotspot_vlan_interface_name || '',
	      hotspot_interface: row.hotspot_interface || '',
	      hotspot_profile_name: row.hotspot_profile_name || '',
	      hotspot_server_name: row.hotspot_server_name || '',
	      hotspot_dns_name: row.hotspot_dns_name || '',
	      hotspot_html_directory: row.hotspot_html_directory || 'hotspot',
	      hotspot_client_network_cidr: row.hotspot_client_network_cidr || '',
	      hotspot_gateway_ip: row.hotspot_gateway_ip || '',
	      hotspot_pool_start_ip: row.hotspot_pool_start_ip || '',
	      hotspot_pool_end_ip: row.hotspot_pool_end_ip || '',
	      hotspot_pool_name: row.hotspot_pool_name || '',
	      hotspot_dhcp_server_name: row.hotspot_dhcp_server_name || '',
	      hotspot_dhcp_lease_time: row.hotspot_dhcp_lease_time || '1h',
	      hotspot_dns_servers: row.hotspot_dns_servers || '',
	      hotspot_wan_interface: row.hotspot_wan_interface || '',
	      hotspot_enable_nat: Boolean(row.hotspot_enable_nat)
	    };
	  }
  function firstIncompleteMikrotikStepIndex(actions = []) {
    const index = actions.findIndex((item) => !item.is_applied);
    return index >= 0 ? index : Math.max(0, actions.length - 1);
  }
  async function saveMikrotikRows(e) {
    e.preventDefault();
    setActionResult({ status: 'RUNNING', message: 'Saving MikroTik routers...' });
    let savedCount = 0;
    let removedCount = 0;
    for (const row of mikrotikRows) {
      if (row._remove) {
        if (!row._isNew) {
          await request(`/captive-portal/mikrotik/${row.id}`, { method: 'DELETE' });
          removedCount += 1;
        }
        continue;
      }
	      const payload = mikrotikPayload(row);
      if (row.password) payload.password = row.password;
      if (row._isNew) {
        await request('/captive-portal/mikrotik', { method: 'POST', body: JSON.stringify(payload) });
      } else {
        await request(`/captive-portal/mikrotik/${row.id}`, { method: 'PATCH', body: JSON.stringify(payload) });
      }
      savedCount += 1;
    }
    setMessage(`MikroTik routers saved. ${savedCount} updated, ${removedCount} removed.`);
    setActionResult(null);
    await load();
  }
	  async function testMikrotik(routerId) {
	    setActionResult({ status: 'RUNNING', message: 'Testing MikroTik connection...' });
	    const result = await request(`/captive-portal/mikrotik/${routerId}/test`, { method: 'POST', body: JSON.stringify({}) });
	    setActionResult(result);
	    await load();
	  }
  function mergePreflightScan(data) {
    const mergedPolicy = data?.scan ? { ...(data.scan.policy_result || {}), ...(data.policy || {}) } : null;
    const scan = data?.scan ? { ...data.scan, policy_result: Object.keys(mergedPolicy || {}).length ? mergedPolicy : null } : null;
    setPreflightScan(scan);
    setPreflightHistory(Array.isArray(data?.history) ? data.history : []);
    setDeploymentForm({
      confirmed_router_role: scan?.confirmed_router_role || data?.policy?.confirmed_router_role || '',
      confirmed_deployment_mode: scan?.confirmed_deployment_mode || data?.policy?.confirmed_deployment_mode || '',
      sensitive_confirmation: false
    });
    setExpertOverrideForm({ confirmation_phrase: '', reason: '' });
    return scan;
  }
  async function loadPreflightSummary() {
    try {
      const data = await request('/captive-portal/mikrotik/preflight/summary');
      setPreflightSummary(data);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  function openPreflightRouter(routerId) {
    if (!routerId) return;
    setPreflightView(routerId);
    setPreflightRouterId(routerId);
  }
  async function loadPreflightLatest(routerId = preflightRouterId) {
    if (!routerId) return;
    setPreflightRouterId(routerId);
    setPreflightLoading(true);
    try {
      const data = await request(`/captive-portal/mikrotik/${routerId}/preflight/latest`);
      mergePreflightScan(data);
    } catch (error) {
      setPreflightScan(null);
      setPreflightHistory([]);
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setPreflightLoading(false);
    }
  }
  async function runPreflightScan(routerId = preflightRouterId) {
    if (!routerId) {
      setActionResult({ status: 'FAILED', message: 'Choose a MikroTik router first.' });
      return;
    }
    setPreflightRouterId(routerId);
    setPreflightScanning(true);
    setActionResult({ status: 'RUNNING', message: 'Running read-only MikroTik preflight scan...' });
    try {
      const scan = await request(`/captive-portal/mikrotik/${routerId}/preflight/scan`, { method: 'POST', body: JSON.stringify({}) });
      setPreflightScan(scan);
      setActionResult({ status: scan.scan_status === 'SUCCESS' ? 'SUCCESS' : 'FAILED', message: scan.scan_status === 'SUCCESS' ? 'Preflight scan completed.' : (scan.last_error || 'Preflight scan failed.') });
      await loadPreflightLatest(routerId);
      await loadPreflightSummary();
      await load();
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setPreflightScanning(false);
    }
  }
  async function prescanAllRouters() {
    setPreflightScanningAll(true);
    setActionResult({ status: 'RUNNING', message: 'Running read-only preflight scan for all MikroTik routers...' });
    try {
      const batch = await request('/captive-portal/mikrotik/preflight/scan-all', { method: 'POST', body: JSON.stringify({}) });
      setPreflightBatch(batch);
      setActionResult({ status: batch.status === 'SUCCESS' || batch.status === 'PARTIAL_SUCCESS' ? 'SUCCESS' : 'FAILED', message: `Prescan All finished: ${batch.success_count || 0} success, ${batch.failed_count || 0} failed, ${batch.skipped_count || 0} skipped.` });
      await loadPreflightSummary();
      await load();
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setPreflightScanningAll(false);
    }
  }
  async function explainPreflightScan(routerId = preflightRouterId, scanId = preflightScan?.id) {
    if (!routerId || !scanId) return;
    setPreflightRouterId(routerId);
    setPreflightExplaining(true);
    setActionResult({ status: 'RUNNING', message: 'Preparing AI explanation from sanitized scan data...' });
    try {
      const scan = await request(`/captive-portal/mikrotik/${routerId}/preflight/${scanId}/ai-explain`, { method: 'POST', body: JSON.stringify({}) });
      setPreflightScan(scan);
      setActionResult({ status: 'SUCCESS', message: 'AI explanation saved.' });
      await loadPreflightLatest(routerId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setPreflightExplaining(false);
    }
  }
  async function evaluatePreflightPolicy(routerId = preflightRouterId) {
    if (!routerId) return;
    try {
      const data = await request(`/captive-portal/mikrotik/${routerId}/preflight/evaluate-policy`, { method: 'POST', body: JSON.stringify({}) });
      mergePreflightScan(data);
      setActionResult({ status: 'SUCCESS', message: 'Preflight policy evaluated.' });
      await loadPreflightSummary();
      await load();
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function saveDeploymentMode() {
    if (!preflightRouterId) return;
    try {
      const data = await request(`/captive-portal/mikrotik/${preflightRouterId}/deployment-mode`, { method: 'PUT', body: JSON.stringify(deploymentForm) });
      mergePreflightScan(data);
      setActionResult({ status: 'SUCCESS', message: 'Deployment mode saved. No MikroTik configuration was changed.' });
      await loadPreflightSummary();
      await load();
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function saveExpertOverride() {
    if (!preflightRouterId) return;
    try {
      const data = await request(`/captive-portal/mikrotik/${preflightRouterId}/expert-override`, { method: 'POST', body: JSON.stringify(expertOverrideForm) });
      mergePreflightScan(data);
      setActionResult({ status: 'SUCCESS', message: 'Expert override recorded. It does not apply RouterOS configuration.' });
      await loadPreflightSummary();
      await load();
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function loadAiNetworkAssistant() {
    setAiLoading(true);
    try {
      const data = await request('/captive-portal/mikrotik/ai/summary');
      setAiSummary(data);
      setAiSmokeTest(data.smoke_test || null);
      setPilotSelection(data.pilot_selection || null);
      setPilotForm((current) => ({
        ...current,
        router_id: data.pilot_selection?.router_id || current.router_id || aiRouterId || ''
      }));
      if (!aiRouterId && data.pilot_selection?.router_id) {
        setAiRouterId(data.pilot_selection.router_id);
      }
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiLoading(false);
    }
  }
  async function loadAiRouterPlanning(routerId = aiRouterId) {
    if (!routerId) return;
    try {
      const [questions, plans, readiness, preview, vlanPath] = await Promise.all([
        request(`/captive-portal/mikrotik/${routerId}/deployment-questions`),
        request(`/captive-portal/mikrotik/${routerId}/draft-plans`),
        request(`/captive-portal/mikrotik/${routerId}/mt4-readiness`),
        request(`/captive-portal/mikrotik/${routerId}/planning-network-preview`),
        request(`/captive-portal/mikrotik/${routerId}/vlan-path-plan`)
      ]);
      setAiQuestions(Array.isArray(questions) ? questions : []);
      setAiQuestionAnswers(Object.fromEntries((Array.isArray(questions) ? questions : []).map((item) => [item.question_key, item.answer_value || ''])));
      setAiDraftPlans(Array.isArray(plans) ? plans : []);
      setAiSelectedDraftPlanId((current) => current || plans?.[0]?.id || '');
      setAiQuestionValidation(readiness?.answer_validation || null);
      setMt4Readiness(readiness || null);
      setPlanningNetworkPreview(preview?.preview || null);
      setInterfaceCandidates(preview?.interface_candidates || null);
      setVlanPathPlan(vlanPath?.plan || null);
      setVlanPathValidation(vlanPath?.validation || null);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function runAiSmokeTest() {
    setAiSmokeTesting(true);
    setActionResult({ status: 'RUNNING', message: 'Running AI smoke test with sanitized preflight summary...' });
    try {
      const data = await request('/captive-portal/mikrotik/ai/smoke-test', { method: 'POST', body: JSON.stringify({}) });
      setAiSmokeTest(data.last_smoke_test || null);
      setAiSummary((current) => current ? { ...current, smoke_test: data.last_smoke_test, openai: data.openai || current.openai } : current);
      setActionResult({ status: data.last_smoke_test?.status === 'SUCCESS' ? 'SUCCESS' : 'FAILED', message: data.message || `AI smoke test: ${data.last_smoke_test?.status || 'unknown'}` });
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiSmokeTesting(false);
    }
  }
  async function selectPilotRouter(routerId = pilotForm.router_id || aiRouterId) {
    if (!routerId) return;
    setPilotSaving(true);
    try {
      const data = await request('/captive-portal/mikrotik/pilot-selection', {
        method: 'PUT',
        body: JSON.stringify({
          ...pilotForm,
          router_id: routerId
        })
      });
      setPilotSelection(data.pilot_selection || null);
      setPilotForm((current) => ({
        ...current,
        router_id: data.pilot_selection?.router_id || routerId
      }));
      setActionResult({ status: 'SUCCESS', message: 'Pilot router selected. No MikroTik configuration was changed.' });
      await loadAiNetworkAssistant();
      await loadAiRouterPlanning(routerId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setPilotSaving(false);
    }
  }
  async function clearPilotRouter() {
    setPilotSaving(true);
    try {
      await request('/captive-portal/mikrotik/pilot-selection', { method: 'DELETE' });
      setPilotSelection(null);
      setActionResult({ status: 'SUCCESS', message: 'Pilot selection cleared. No MikroTik configuration was changed.' });
      await loadAiNetworkAssistant();
      if (aiRouterId) await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setPilotSaving(false);
    }
  }
  async function ensureAiConversation() {
    if (aiConversation?.id) return aiConversation;
    const conversation = await request('/captive-portal/mikrotik/ai/conversations', {
      method: 'POST',
      body: JSON.stringify({ router_id: aiRouterId || null, title: 'Removed MikroTik assistant' })
    });
    setAiConversation(conversation);
    return conversation;
  }
  async function sendAiMessage(e) {
    e.preventDefault();
    const text = aiInput.trim();
    if (!text) return;
    setAiSending(true);
    try {
      const conversation = await ensureAiConversation();
      const updated = await request(`/captive-portal/mikrotik/ai/conversations/${conversation.id}/messages`, {
        method: 'POST',
        body: JSON.stringify({ message_text: text, router_id: aiRouterId || null })
      });
      setAiConversation(updated);
      setAiInput('');
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiSending(false);
    }
  }
  async function saveAiQuestion(questionKey) {
    if (!aiRouterId) return;
    try {
      const saved = await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/${questionKey}`, {
        method: 'PUT',
        body: JSON.stringify({ answer_value: aiQuestionAnswers[questionKey] || '' })
      });
      setAiQuestions((items) => items.map((item) => item.question_key === questionKey ? saved : item));
      setActionResult({ status: 'SUCCESS', message: 'Deployment answer saved.' });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function saveAllAiQuestions() {
    if (!aiRouterId) return;
    setAiSavingQuestions(true);
    try {
      const data = await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/save-all`, {
        method: 'POST',
        body: JSON.stringify({ answers: aiQuestionAnswers })
      });
      setAiQuestions(data.questions || []);
      setAiQuestionValidation(data.validation || null);
      await loadAiRouterPlanning(aiRouterId);
      setActionResult({ status: data.validation?.complete ? 'SUCCESS' : 'FAILED', message: data.validation?.complete ? 'Planning answers saved and valid.' : 'Planning answers saved, but some values need correction.' });
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiSavingQuestions(false);
    }
  }
  function updateAiQuestionAnswer(questionKey, value) {
    const next = { ...aiQuestionAnswers, [questionKey]: value };
    const question = aiQuestions.find((item) => item.question_key === questionKey);
    if (question?.answer_status === 'AI_SUGGESTED' && String(value || '') !== String(question.suggested_value || '')) {
      setAiQuestions((items) => items.map((item) => item.question_key === questionKey ? { ...item, answer_status: 'USER_EDITED' } : item));
    }
    if (questionKey === 'client_network_cidr') {
      const preview = localNetworkPreview(value);
      setPlanningNetworkPreview(preview);
      if (preview.status === 'SUCCESS') {
        if (!questionLocked('gateway_ip')) next.gateway_ip = preview.gateway_ip;
        if (!questionLocked('dhcp_pool')) next.dhcp_pool = preview.dhcp_pool;
      }
    }
    if (questionKey === 'customer_vlan_id' && !questionLocked('vlan_interface_name')) {
      const vlan = String(value || '').trim();
      if (/^\d+$/.test(vlan)) next.vlan_interface_name = `3j-wifi-vlan${vlan}`;
    }
    if (questionKey === 'nat_enabled' && ['no', 'false', '0', 'disabled', 'off'].includes(String(value || '').trim().toLowerCase()) && !questionLocked('wan_interface')) {
      next.wan_interface = '';
    }
    setAiQuestionAnswers(next);
  }
  async function suggestAiAnswers() {
    if (!aiRouterId) return;
    setAiSuggestingAnswers(true);
    setActionResult({ status: 'RUNNING', message: 'Requesting AI planning suggestions from sanitized preflight data...' });
    try {
      const data = await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/ai-suggest`, { method: 'POST', body: JSON.stringify({}) });
      setAiQuestions(data.questions || []);
      setAiQuestionValidation(data.validation || null);
      setAiQuestionAnswers(Object.fromEntries((data.questions || []).map((item) => [item.question_key, item.answer_value || ''])));
      setActionResult({ status: 'SUCCESS', message: `AI answered ${(data.suggestions?.suggestions || []).filter((item) => item.suggested_value).length} planning field(s). Review, edit, clear, then Save All before MT-4.` });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiSuggestingAnswers(false);
    }
  }
  async function validateAiAnswers() {
    if (!aiRouterId) return;
    setAiValidatingAnswers(true);
    try {
      const data = await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/validate`, {
        method: 'POST',
        body: JSON.stringify({ answers: aiQuestionAnswers })
      });
      setAiQuestions(data.questions || aiQuestions);
      setAiQuestionValidation(data.validation || null);
      setPlanningNetworkPreview(data.network_preview || planningNetworkPreview);
      setActionResult({ status: data.validation?.complete ? 'SUCCESS' : 'FAILED', message: data.validation?.complete ? 'Planning answers are valid.' : 'Planning answers need correction or approval.' });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiValidatingAnswers(false);
    }
  }
  function updateVlanPathPlan(patch) {
    setVlanPathPlan((current) => ({ ...(current || {}), ...patch }));
  }
  function openInterfacePicker(field, label, options = {}) {
    setInterfacePicker({
      field,
      label,
      multiple: Boolean(options.multiple),
      description: options.description || 'Choose from scanned MikroTik interfaces. Confirm the physical VLAN path before saving.',
      preferredGroups: options.preferredGroups || []
    });
  }
  function chooseInterfaceCandidate(item) {
    if (!interfacePicker || !item?.name) return;
    const field = interfacePicker.field;
    if (field === 'vlan_parent_interface') {
      updateAiQuestionAnswer('vlan_parent_interface', item.name);
      updateVlanPathPlan({ gateway_parent_interface: item.name });
      setInterfacePicker(null);
      return;
    }
    if (interfacePicker.multiple) {
      const current = String(vlanPathPlan?.[field] || '');
      const values = current.split(',').map((value) => value.trim()).filter(Boolean);
      if (!values.includes(item.name)) values.push(item.name);
      updateVlanPathPlan({ [field]: values.join(', ') });
      return;
    }
    updateVlanPathPlan({ [field]: item.name });
    setInterfacePicker(null);
  }
  async function saveVlanPathPlan() {
    if (!aiRouterId || !vlanPathPlan) return;
    setVlanPathSaving(true);
    try {
      const data = await request(`/captive-portal/mikrotik/${aiRouterId}/vlan-path-plan`, {
        method: 'PUT',
        body: JSON.stringify({
          hotspot_gateway_router_id: vlanPathPlan.hotspot_gateway_router_id || aiRouterId,
          gateway_parent_interface: vlanPathPlan.gateway_parent_interface || '',
          next_hop_type: vlanPathPlan.next_hop_type || 'UNKNOWN',
          crs_involved: Boolean(vlanPathPlan.crs_involved),
          crs_router_id: vlanPathPlan.crs_router_id || null,
          crs_port_to_gateway: vlanPathPlan.crs_port_to_gateway || '',
          crs_ports_to_olt_ap: vlanPathPlan.crs_ports_to_olt_ap || '',
          olts_involved: Boolean(vlanPathPlan.olts_involved),
          olt_notes: vlanPathPlan.olt_notes || '',
          olt_vlan_behavior: vlanPathPlan.olt_vlan_behavior || 'UNKNOWN',
          ap_vlan_mode: vlanPathPlan.ap_vlan_mode || 'UNKNOWN',
          ssid_vlan_id: null,
          confirmation_status: vlanPathPlan.confirmation_status || 'DRAFT'
        })
      });
      setVlanPathPlan(data.plan || null);
      setVlanPathValidation(data.validation || null);
      setMt4Readiness(data.mt4_readiness || mt4Readiness);
      setActionResult({ status: data.validation?.complete ? 'SUCCESS' : 'FAILED', message: data.validation?.complete ? 'VLAN path plan saved and confirmed.' : 'VLAN path plan saved, but still needs review.' });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setVlanPathSaving(false);
    }
  }
  async function approveAiQuestion(question, value = undefined) {
    if (!aiRouterId || !question) return;
    try {
      const data = await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/approve`, {
        method: 'POST',
        body: JSON.stringify({ question_key: question.question_key, value: value ?? aiQuestionAnswers[question.question_key] ?? question.suggested_value ?? '' })
      });
      setAiQuestionValidation(data.validation || null);
      await loadAiRouterPlanning(aiRouterId);
      setActionResult({ status: 'SUCCESS', message: 'Planning answer approved.' });
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function clearAiQuestion(question) {
    if (!aiRouterId || !question) return;
    try {
      await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/reject`, {
        method: 'POST',
        body: JSON.stringify({ question_key: question.question_key })
      });
      await loadAiRouterPlanning(aiRouterId);
      setActionResult({ status: 'SUCCESS', message: 'AI answer cleared.' });
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function lockAiQuestion(question, locked) {
    if (!aiRouterId || !question) return;
    try {
      await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/lock`, {
        method: 'POST',
        body: JSON.stringify({ question_key: question.question_key, locked })
      });
      await loadAiRouterPlanning(aiRouterId);
      setActionResult({ status: 'SUCCESS', message: locked ? 'Planning answer locked.' : 'Planning answer unlocked.' });
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function applySafeAiSuggestions() {
    if (!aiRouterId) return;
    try {
      const data = await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/apply-safe-suggestions`, { method: 'POST', body: JSON.stringify({}) });
      setAiQuestions(data.questions || []);
      setAiQuestionValidation(data.validation || null);
      setAiQuestionAnswers(Object.fromEntries((data.questions || []).map((item) => [item.question_key, item.answer_value || ''])));
      setActionResult({ status: 'SUCCESS', message: `Applied ${data.applied?.length || 0} safe suggestion(s). ${data.skipped?.length || 0} still need review.` });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function resetAiSuggestions() {
    if (!aiRouterId) return;
    try {
      const suggested = aiQuestions.filter((question) => question.suggested_value);
      for (const question of suggested) {
        await request(`/captive-portal/mikrotik/${aiRouterId}/deployment-questions/reject`, {
          method: 'POST',
          body: JSON.stringify({ question_key: question.question_key })
        });
      }
      await loadAiRouterPlanning(aiRouterId);
      setActionResult({ status: 'SUCCESS', message: 'AI suggestions reset.' });
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  async function generateAiDraftPlan() {
    if (!aiRouterId) return;
    setAiGeneratingPlan(true);
    setActionResult({ status: 'RUNNING', message: 'Generating draft deployment plan from sanitized preflight data...' });
    try {
      const plan = await request(`/captive-portal/mikrotik/${aiRouterId}/ai/generate-draft-plan`, {
        method: 'POST',
        body: JSON.stringify({})
      });
      setAiDraftPlans((plans) => [plan, ...plans.filter((item) => item.id !== plan.id)]);
      setAiSelectedDraftPlanId(plan.id);
      setActionResult({ status: plan.validation_status === 'BLOCKED' ? 'FAILED' : 'SUCCESS', message: plan.validation_status === 'BLOCKED' ? 'Draft plan generated but blocked by safety validation.' : 'Draft plan generated and validated.' });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiGeneratingPlan(false);
    }
  }
  async function validateAiDraftPlan(planId = aiSelectedDraftPlanId) {
    if (!aiRouterId || !planId) return;
    setAiValidatingPlan(true);
    try {
      const plan = await request(`/captive-portal/mikrotik/${aiRouterId}/draft-plans/${planId}/validate`, { method: 'POST', body: JSON.stringify({}) });
      setAiDraftPlans((plans) => plans.map((item) => item.id === plan.id ? plan : item));
      setActionResult({ status: plan.validation_status === 'BLOCKED' ? 'FAILED' : 'SUCCESS', message: `Safety validation: ${plan.validation_status}` });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setAiValidatingPlan(false);
    }
  }
  async function markAiDraftReady(planId = aiSelectedDraftPlanId) {
    if (!aiRouterId || !planId) return;
    try {
      const plan = await request(`/captive-portal/mikrotik/${aiRouterId}/draft-plans/${planId}/mark-ready`, { method: 'POST', body: JSON.stringify({}) });
      setAiDraftPlans((plans) => plans.map((item) => item.id === plan.id ? plan : item));
      setActionResult({ status: 'SUCCESS', message: 'Draft plan marked ready for MT-4 command preview. No commands were generated.' });
      await loadAiRouterPlanning(aiRouterId);
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    }
  }
  function openAiPlanningModal(routerId, openModal) {
    if (routerId) {
      if (routerId !== aiRouterId) {
        setAiQuestions([]);
        setAiQuestionAnswers({});
        setAiDraftPlans([]);
        setAiSelectedDraftPlanId('');
        setAiQuestionValidation(null);
        setMt4Readiness(null);
        setPlanningNetworkPreview(null);
        setInterfaceCandidates(null);
        setVlanPathPlan(null);
        setVlanPathValidation(null);
        setInterfacePicker(null);
      }
      setAiRouterId(routerId);
      setPilotForm((current) => ({ ...current, router_id: routerId }));
      loadAiRouterPlanning(routerId);
    }
    openModal(true);
  }
	  async function loadMikrotikRouterOptions(routerId) {
	    if (!routerId) return;
	    try {
	      const data = await request(`/captive-portal/mikrotik/${routerId}/routeros-options`);
	      setMikrotikOptions((current) => ({ ...current, [routerId]: data }));
	    } catch (error) {
	      setMikrotikOptions((current) => ({ ...current, [routerId]: { status: 'FAILED', error: error.message, interfaces: [], interface_lists: [] } }));
	    }
	  }
	  async function reviewMikrotikConfiguration(routerId) {
	    setActionResult({ status: 'RUNNING', message: 'Preparing MikroTik integration setup...' });
	    const plan = await request(`/captive-portal/mikrotik/${routerId}/configuration-preview`);
	    setMikrotikPlan(plan);
	    setMikrotikPlanRouterId(routerId);
	    setMikrotikStepIndex(firstIncompleteMikrotikStepIndex(plan.actions || []));
	    if (plan.managed_configuration_status) {
	      setMikrotikManagedConfig((current) => ({ ...current, [routerId]: plan.managed_configuration_status }));
	    }
	    loadMikrotikRouterOptions(routerId);
	    setActionResult({ status: 'SUCCESS', message: 'MikroTik integration setup is ready. Apply each step in order.' });
	    await load();
	  }
	  async function saveMikrotikSetupFields() {
	    const row = mikrotikRows.find((item) => item.id === mikrotikPlanRouterId);
	    if (!row || row._isNew) return;
	    if (!row.hotspot_vlan_id || !row.hotspot_vlan_parent_interface) {
	      setActionResult({ status: 'FAILED', message: 'Customer VLAN ID and VLAN Parent Interface are required before Step 2 commands can be generated.' });
	      return;
	    }
	    setActionResult({ status: 'RUNNING', message: 'Saving MikroTik setup fields...' });
	    const saved = await request(`/captive-portal/mikrotik/${row.id}`, { method: 'PATCH', body: JSON.stringify(mikrotikPayload(row)) });
	    setMikrotiks((rows) => rows.map((item) => item.id === saved.id ? saved : item));
	    setMikrotikRows((rows) => editableMikrotikRows(rows.map((item) => item.id === saved.id ? saved : item)));
	    const plan = await request(`/captive-portal/mikrotik/${row.id}/configuration-preview`);
	    setMikrotikPlan(plan);
	    setMikrotikStepIndex(firstIncompleteMikrotikStepIndex(plan.actions || []));
	    if (plan.managed_configuration_status) {
	      setMikrotikManagedConfig((current) => ({ ...current, [row.id]: plan.managed_configuration_status }));
	    }
	    setActionResult({ status: 'SUCCESS', message: 'MikroTik setup fields saved. Review the updated Step 2 commands.' });
	  }
  async function applyMikrotikConfigurationStep(stepKey, options = {}) {
    if (!mikrotikPlanRouterId) return;
    setMikrotikApplyingStep(stepKey);
    setActionResult({ status: 'RUNNING', message: 'Applying selected MikroTik configuration...' });
    try {
      const result = await request(`/captive-portal/mikrotik/${mikrotikPlanRouterId}/apply-configuration-step`, {
        method: 'POST',
        body: JSON.stringify({ step_key: stepKey })
      });
      if (result.plan) setMikrotikPlan(result.plan);
      if (options.advance && result.plan?.actions) {
        const currentIndex = result.plan.actions.findIndex((item) => item.key === stepKey);
        setMikrotikStepIndex(Math.min(currentIndex + 1, Math.max(result.plan.actions.length - 1, 0)));
        setMikrotikStepReview(null);
      }
      if (result.plan?.managed_configuration_status) {
        setMikrotikManagedConfig((current) => ({ ...current, [mikrotikPlanRouterId]: result.plan.managed_configuration_status }));
      }
      setActionResult(result);
      setMessage(result.message || 'MikroTik configuration step applied.');
      await load();
      return result;
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
      return null;
    } finally {
      setMikrotikApplyingStep(null);
    }
  }
  function previousMikrotikStep() {
    setMikrotikStepIndex((index) => Math.max(0, index - 1));
  }
  function nextMikrotikStep() {
    const actions = mikrotikPlan?.actions || [];
    const item = actions[mikrotikStepIndex];
    if (!item) return;
    if (item.is_applied) {
      setMikrotikStepIndex((index) => Math.min(index + 1, Math.max(actions.length - 1, 0)));
      return;
    }
    if (!item.apply_supported) {
      setActionResult({ status: 'BLOCKED', message: item.apply_label || 'This step is not ready to apply yet.' });
      return;
    }
    setMikrotikStepReview({ item, index: mikrotikStepIndex });
  }
  async function checkMikrotikManagedConfiguration(routerId) {
    if (!routerId) return null;
    setMikrotikCheckingConfig(routerId);
    try {
      const status = await request(`/captive-portal/mikrotik/${routerId}/managed-configuration-status`);
      setMikrotikManagedConfig((current) => ({ ...current, [routerId]: status }));
      if (routerId === mikrotikPlanRouterId) {
        setMikrotikPlan((current) => current ? { ...current, managed_configuration_status: status } : current);
      }
      setActionResult({ status: status.status, message: status.message || 'Managed configuration check completed.' });
      return status;
    } catch (error) {
      const status = { status: 'ERROR', message: error.message, has_managed_config: false, found_count: 0 };
      setMikrotikManagedConfig((current) => ({ ...current, [routerId]: status }));
      setActionResult(status);
      return status;
    } finally {
      setMikrotikCheckingConfig(null);
    }
  }
  async function removeMikrotikConfiguration(routerId = mikrotikPlanRouterId, routerLabel = mikrotikPlan?.router?.router_name) {
    if (!routerId) return;
    const currentStatus = mikrotikManagedConfig[routerId] || (routerId === mikrotikPlanRouterId ? mikrotikPlan?.managed_configuration_status : null);
    if (!currentStatus?.has_managed_config) {
      setActionResult({ status: 'NO_CONFIGURATION', message: 'No 3JCentralPisowifi-managed MikroTik configuration was detected. Run Check Config first if the router was changed outside this page.' });
      return;
    }
    const routerName = routerLabel || 'this MikroTik';
    const confirmed = window.confirm(`Remove all 3JCentralPisowifi-managed configuration from ${routerName}? This only removes objects created with the system-managed names/comments shown in the remove-config preview.`);
    if (!confirmed) return;
    setMikrotikReverting(true);
    setActionResult({ status: 'RUNNING', message: 'Removing 3JCentralPisowifi-managed MikroTik configuration...' });
    try {
      const result = await request(`/captive-portal/mikrotik/${routerId}/remove-configuration`, { method: 'POST', body: JSON.stringify({}) });
      setMikrotikPlanRouterId(routerId);
      if (result.plan) setMikrotikPlan(result.plan);
      if (result.plan?.managed_configuration_status) {
        setMikrotikManagedConfig((current) => ({ ...current, [routerId]: result.plan.managed_configuration_status }));
      } else if (result.managed_configuration_status) {
        setMikrotikManagedConfig((current) => ({ ...current, [routerId]: result.managed_configuration_status }));
      }
      setActionResult(result);
      setMessage(result.message || 'MikroTik configuration removed.');
      await load();
    } catch (error) {
      setActionResult({ status: 'FAILED', message: error.message });
    } finally {
      setMikrotikReverting(false);
    }
  }
  function openSsidConfiguration() {
    window.history.pushState({ page: 'Sites' }, '', '/admin/aps-deployment/sites?tab=configurations');
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
  async function toggleChecklist(key) {
    const progress = { ...(portalSettings?.test_checklist_progress || {}) };
    progress[key] = !progress[key];
    const saved = await request('/captive-portal/settings', { method: 'PUT', body: JSON.stringify({ test_checklist_progress: progress }) });
    setPortalSettings(saved);
  }
  const reachableMikrotiks = mikrotiks.filter((router) => router.status === 'REACHABLE').length;
  const portalSsid = portalSettings?.portal_ssid || {
    primary_ssid: portalSettings?.open_ssid_name || '3J-FreeWiFi',
    display_ssid: portalSettings?.open_ssid_name || '3J-FreeWiFi',
    source: 'AP_DEPLOYMENT_CONFIGURATION',
    use_same_ssid: true,
    ssid_2g: portalSettings?.open_ssid_name || '3J-FreeWiFi',
    ssid_5g: portalSettings?.open_ssid_name || '3J-FreeWiFi',
    security_mode: 'OPEN'
  };
  const portalSsidDisplay = portalSsid.display_ssid || portalSsid.primary_ssid || '3J-FreeWiFi';
  const portalSsidPrimary = portalSsid.primary_ssid || '3J-FreeWiFi';
  const sanityProgress = portalSettings?.test_checklist_progress || {};
  const hasPortalUrl = Boolean(portalSettings?.portal_url_staging || portalSettings?.portal_url_production);
  const hasUnusedVouchers = Number(voucherSummary?.unused || 0) > 0;
  const hasSuccessfulPortalRedemption = redemptions.some((row) => row.result === 'SUCCESS');
  const hasPortalSession = sessions.length > 0;
  const hasGatewayAuthorizationSuccess = authorizations.some((row) => row.status === 'SUCCESS');
  const hasStartedMikrotikSetup = mikrotiks.some((router) => router.last_configuration_review_at || Number(router.configuration_progress?.completed || 0) > 0);
  const hasAppliedMikrotik = mikrotiks.some((router) => Number(router.configuration_progress?.completed || 0) > 0 || router.last_configuration_apply_at);
  const mikrotiksWithCustomerVlan = mikrotiks.filter((router) => router.hotspot_vlan_id && router.hotspot_vlan_parent_interface).length;
  const setupMikrotikRow = mikrotikRows.find((router) => router.id === mikrotikPlanRouterId);
  const setupMikrotikOptions = mikrotikOptions[mikrotikPlanRouterId] || {};
  const setupInterfaces = setupMikrotikOptions.interfaces || [];
  const planManagedStatus = mikrotikPlan?.managed_configuration_status || mikrotikManagedConfig[mikrotikPlanRouterId] || null;
  const mikrotikActions = mikrotikPlan?.actions || [];
  const currentMikrotikStepIndex = Math.min(mikrotikStepIndex, Math.max(mikrotikActions.length - 1, 0));
  const currentMikrotikStep = mikrotikActions[currentMikrotikStepIndex] || null;
  const preflightRouter = mikrotiks.find((router) => router.id === preflightRouterId) || null;
  const preflightSnapshot = preflightScan?.sanitized_snapshot || {};
  const preflightPaths = preflightSnapshot.paths || {};
  const preflightAnalysis = preflightSnapshot.analysis || {};
  const preflightItems = (key) => preflightPaths[key]?.items || [];
  const preflightCounts = preflightAnalysis.summary?.counts || {};
  const preflightVlanRows = [
    ...preflightItems('interface_vlans').map((item) => ({ source: 'Interface VLAN', name: item.name, vlan_id: item['vlan-id'], interface: item.interface, comment: item.comment })),
    ...preflightItems('bridge_vlans').map((item) => ({ source: 'Bridge VLAN', name: item.bridge, vlan_id: item['vlan-ids'], interface: item.tagged || item.untagged, comment: item.comment }))
  ];
  const preflightSubnetRows = preflightItems('ip_addresses').map((item) => ({ address: item.address, network: item.network, interface: item.interface, disabled: item.disabled, comment: item.comment }));
  const preflightPoolRows = preflightItems('ip_pools').map((item) => ({ name: item.name, ranges: item.ranges, comment: item.comment }));
  const preflightDhcpRows = preflightItems('dhcp_servers').map((item) => ({ name: item.name, interface: item.interface, address_pool: item['address-pool'], disabled: item.disabled, lease_time: item['lease-time'] }));
  const preflightHotspotRows = preflightItems('hotspots').map((item) => ({ name: item.name, interface: item.interface, profile: item.profile, address_pool: item['address-pool'], disabled: item.disabled }));
  const preflightPolicy = preflightScan?.policy_result || null;
  const preflightBatchProgress = preflightBatch ? `${preflightBatch.success_count || 0}/${preflightBatch.total_routers || 0} scanned` : null;
  const preflightReadinessRows = preflightSummary?.readiness || [];
  const routersWithPreflight = mikrotiks.filter((router) => router.latest_preflight_scan);
  const successfulPreflightRouters = routersWithPreflight.filter((router) => router.latest_preflight_scan?.scan_status === 'SUCCESS');
  const preflightEngaged = routersWithPreflight.length > 0;
  const failedPreflightRouters = routersWithPreflight.filter((router) => router.latest_preflight_scan?.scan_status === 'FAILED');
  const highRiskPreflightRouters = routersWithPreflight.filter((router) => ['HIGH', 'BLOCKED'].includes(router.latest_preflight_scan?.risk_level));
  const notScannedMikrotiks = Math.max(mikrotiks.length - routersWithPreflight.length, 0);
  const latestPreflightTimestamp = routersWithPreflight
    .map((router) => router.latest_preflight_scan?.created_at)
    .filter(Boolean)
    .sort()
    .at(-1);
  const filteredPreflightReadinessRows = preflightReadinessRows.filter((row) => {
    if (preflightSummaryFilter === 'FAILED') return row.scan_status === 'FAILED' || row.api_status === 'UNREACHABLE' || row.api_status === 'ERROR' || row.api_status === 'AUTH_FAILED';
    if (preflightSummaryFilter === 'BLOCKED') return Number(row.blocking_conflicts || 0) > 0 || row.risk_level === 'BLOCKED';
    if (preflightSummaryFilter === 'CANDIDATES') return row.pilot_suitability === 'GOOD_PILOT' || row.pilot_suitability === 'POSSIBLE_WITH_CAUTION' || row.role_guess === 'HOTSPOT_GATEWAY_CANDIDATE' || row.role_guess === 'PPPoE_ACCESS_CONCENTRATOR';
    if (preflightSummaryFilter === 'READ_ONLY') return row.role_guess === 'CORE_ROUTER_READ_ONLY' || row.confirmed_deployment_mode === 'READ_ONLY_CORE';
    if (preflightSummaryFilter === 'TRUNK') return row.role_guess === 'SWITCH_TRUNK_HELPER' || row.recommended_deployment_mode === 'VLAN_TRUNK_HELPER';
    if (preflightSummaryFilter === 'CONFIRMATION') return row.confirmation_status !== 'CONFIRMED';
    return true;
  });
  const preflightFindingClass = (severity) => severity === 'BLOCKER' ? 'bg-red-lt text-red' : severity === 'DANGER' ? 'bg-orange-lt text-orange' : severity === 'WARNING' ? 'bg-yellow-lt text-yellow' : 'bg-blue-lt text-blue';
  const preflightRiskClass = (risk) => risk === 'BLOCKED' ? 'bg-red-lt text-red' : risk === 'HIGH' ? 'bg-orange-lt text-orange' : risk === 'MEDIUM' ? 'bg-yellow-lt text-yellow' : risk === 'LOW' ? 'bg-green-lt text-green' : 'bg-secondary-lt text-secondary';
  const pilotSuitabilityClass = (value) => value === 'GOOD_PILOT' ? 'bg-green-lt text-green' : value === 'POSSIBLE_WITH_CAUTION' ? 'bg-yellow-lt text-yellow' : value === 'NOT_RECOMMENDED' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary';
  const pilotSuitabilityLabel = (value) => ({
    GOOD_PILOT: 'Good Pilot',
    POSSIBLE_WITH_CAUTION: 'Possible With Caution',
    NOT_RECOMMENDED: 'Not Recommended',
    UNKNOWN: 'Unknown'
  }[value] || value || 'Unknown');
  const deploymentModeLabel = (mode) => ({
    HOTSPOT_GATEWAY: 'HotSpot Gateway',
    VLAN_TRUNK_HELPER: 'VLAN Trunk Helper',
    READ_ONLY_CORE: 'Read-only/Core',
    ISP_BACKUP_TRANSPORT: 'ISP Backup/Transport',
    UNKNOWN_NEEDS_REVIEW: 'Unknown/Needs Review'
  }[mode] || mode || 'Not confirmed');
  const routerRoleLabel = (role) => ({
    PPPoE_ACCESS_CONCENTRATOR: 'PPPoE Access Concentrator',
    HOTSPOT_GATEWAY_CANDIDATE: 'HotSpot Gateway Candidate',
    CORE_ROUTER_READ_ONLY: 'Core Router',
    SWITCH_TRUNK_HELPER: 'Switch/CRS/Trunk',
    ISP_BACKUP_TRANSPORT: 'ISP Backup/Transport',
    UNKNOWN_NEEDS_REVIEW: 'Unknown'
  }[role] || role || 'Not confirmed');
  const validationClass = (status) => status === 'PASS' ? 'bg-green-lt text-green' : status === 'WARNING' ? 'bg-yellow-lt text-yellow' : status === 'BLOCKED' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary';
  const aiCards = aiSummary?.summary?.cards || {};
  const aiOpenAi = aiSummary?.openai || {};
  const aiPilotCandidates = aiSummary?.pilot_candidates || [];
  const aiQuestionProgress = aiSummary?.question_progress || {};
  const selectedPilot = pilotSelection || aiSummary?.pilot_selection || null;
  const aiCandidateByRouterId = Object.fromEntries(aiPilotCandidates.map((item) => [item.router_id, item]));
  const aiRouterRows = mikrotiks.map((router) => {
    const candidate = aiCandidateByRouterId[router.id] || {};
    const questionProgress = aiQuestionProgress[router.id] || { answered_required: 0, total_required: 0, label: '0/0', complete: false };
    return {
      ...router,
      candidate,
      question_progress: questionProgress,
      isPilot: selectedPilot?.router_id === router.id,
      role_guess: candidate.role_guess || router.role_guess,
      risk_level: candidate.risk_level || router.risk_level || 'UNKNOWN',
      pilot_suitability: candidate.pilot_suitability || 'UNKNOWN',
      recommended_action: candidate.recommended_action || 'Review preflight',
      reason: candidate.reason || ''
    };
  });
  const aiMessages = aiConversation?.messages || [];
  const aiActiveRouter = mikrotiks.find((router) => router.id === aiRouterId) || null;
  const aiActiveRouterLabel = aiActiveRouter ? `${aiActiveRouter.router_name} (${aiActiveRouter.host}:${aiActiveRouter.api_port})` : '';
  const aiSelectedDraftPlan = aiDraftPlans.find((plan) => plan.id === aiSelectedDraftPlanId) || aiDraftPlans[0] || null;
  const aiValidation = aiSelectedDraftPlan?.validation_result || {};
  const aiSmoke = aiSmokeTest || aiSummary?.smoke_test || null;
  const questionValidation = aiQuestionValidation || mt4Readiness?.answer_validation || null;
  const questionGroups = aiQuestions.reduce((groups, question) => {
    const category = question.category || 'Planning';
    groups[category] = groups[category] || [];
    groups[category].push(question);
    return groups;
  }, {});
  const answeredRequired = questionValidation?.answered_required || aiQuestions.filter((item) => item.required_for_preview && (aiQuestionAnswers[item.question_key] || '').trim()).length;
  const totalRequired = questionValidation?.total_required || aiQuestions.filter((item) => item.required_for_preview).length;
  const readinessChecks = mt4Readiness?.checks || [];
  const readyForDraftPlan = Boolean(mt4Readiness?.ready_for_draft_plan);
  const readyForMt4 = Boolean(mt4Readiness?.ready_for_mt4);
  const questionStatusLabel = totalRequired ? `${answeredRequired}/${totalRequired} answered` : 'Not loaded';
  const questionStatusTone = questionValidation?.complete ? 'bg-green-lt text-green' : answeredRequired ? 'bg-yellow-lt text-yellow' : 'bg-secondary-lt text-secondary';
  const draftStatusLabel = aiSelectedDraftPlan ? `${aiSelectedDraftPlan.validation_status} / ${aiSelectedDraftPlan.status}` : 'No draft';
  const draftStatusTone = aiSelectedDraftPlan ? validationClass(aiSelectedDraftPlan.validation_status) : 'bg-secondary-lt text-secondary';
  const smokeStatusTone = aiSmoke?.status === 'SUCCESS' ? 'bg-green-lt text-green' : aiSmoke?.status === 'FAILED' ? 'bg-red-lt text-red' : 'bg-yellow-lt text-yellow';
  const activeQuestionContextIsPilot = Boolean(selectedPilot?.router_id && aiRouterId === selectedPilot.router_id);
  const pilotDraftStatusLabel = selectedPilot ? (activeQuestionContextIsPilot ? draftStatusLabel : 'Open to load') : 'No pilot selected';
  const pilotDraftStatusTone = selectedPilot ? (activeQuestionContextIsPilot ? draftStatusTone : 'bg-secondary-lt text-secondary') : 'bg-secondary-lt text-secondary';
  const guidedAiPrompts = [
    'Which router should I use as the first pilot?',
    'Why is this router high risk?',
    'Explain VLAN parent interface.',
    'Why should core routers remain read-only?',
    'What questions must I answer before command preview?'
  ];
  function ipToInt(value) {
    const parts = String(value || '').split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
  }
  function intToIp(value) {
    return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
  }
  function localNetworkPreview(cidr) {
    const text = String(cidr || '').trim();
    const match = text.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
    if (!match) return { status: text ? 'ERROR' : 'EMPTY', errors: text ? ['CIDR is not valid.'] : [] };
    const base = ipToInt(match[1]);
    const prefix = Number(match[2]);
    if (base === null || prefix < 0 || prefix > 32) return { status: 'ERROR', errors: ['CIDR is not valid.'] };
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = base & mask;
    const size = 2 ** (32 - prefix);
    if (size < 16) return { status: 'ERROR', cidr: text, errors: ['CIDR is too small for a practical DHCP pool.'] };
    const broadcast = (network + size - 1) >>> 0;
    const first = network + 1;
    const last = broadcast - 1;
    const poolStart = Math.min(network + 10, last);
    return {
      status: 'SUCCESS',
      cidr: `${intToIp(network)}/${prefix}`,
      network_address: intToIp(network),
      broadcast_address: intToIp(broadcast),
      first_usable_ip: intToIp(first),
      last_usable_ip: intToIp(last),
      gateway_ip: intToIp(first),
      pool_start_ip: intToIp(poolStart),
      pool_end_ip: intToIp(last),
      usable_hosts: Math.max(size - 2, 0),
      range: `${intToIp(network)} - ${intToIp(broadcast)}`,
      dhcp_pool: `${intToIp(poolStart)}-${intToIp(last)}`
    };
  }
  const liveNetworkPreview = localNetworkPreview(aiQuestionAnswers.client_network_cidr || '');
  const effectiveNetworkPreview = liveNetworkPreview.status !== 'EMPTY' ? liveNetworkPreview : planningNetworkPreview;
  const questionByKey = Object.fromEntries(aiQuestions.map((question) => [question.question_key, question]));
  const phaseOneQuestionKeys = new Set(['pilot_router_confirmed', 'router_role_confirmed', 'deployment_mode_confirmed', 'customer_vlan_id', 'vlan_interface_name', 'vlan_parent_interface']);
  const phaseOneQuestionPanels = [
    { title: 'Pilot / Router Role', description: 'Confirm what this router is and how 3JCentralPisowifi is allowed to use it.', keys: ['pilot_router_confirmed', 'router_role_confirmed', 'deployment_mode_confirmed'] },
    { title: 'Customer VLAN Prerequisites', description: 'These values are needed before the VLAN path and Phase 2 network answers make sense.', keys: ['customer_vlan_id', 'vlan_interface_name'] }
  ].map((panel) => ({ ...panel, questions: panel.keys.map((key) => questionByKey[key]).filter(Boolean) })).filter((panel) => panel.questions.length);
  const phaseTwoQuestionGroups = aiQuestions
    .filter((question) => !phaseOneQuestionKeys.has(question.question_key))
    .reduce((groups, question) => {
      const category = question.category || 'Planning';
      groups[category] = groups[category] || [];
      groups[category].push(question);
      return groups;
    }, {});
  function questionLocked(key) {
    return Boolean(questionByKey[key]?.locked);
  }
  function isQuestionAiFilled(question) {
    return question?.answer_status === 'AI_SUGGESTED'
      && String(aiQuestionAnswers[question.question_key] || '') === String(question.suggested_value || '');
  }
  function renderPlanningQuestionField(question) {
    if (!question) return null;
    return (
      <div key={`modal-question-${question.question_key}`}>
        <label className="form-label mb-1 d-flex align-items-center gap-2 flex-wrap">
          <span>{question.question_text}</span>
          {question.required_for_preview && <span className="badge bg-blue-lt text-blue">Required</span>}
          <span className={`badge ${question.answer_status === 'APPROVED' || question.answer_status === 'LOCKED' ? 'bg-green-lt text-green' : question.answer_status === 'AI_SUGGESTED' ? 'bg-purple-lt text-purple' : question.answer_status === 'REJECTED' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary'}`}>{question.answer_status || 'EMPTY'}</span>
          {question.locked && <span className="badge bg-yellow-lt text-yellow">Locked</span>}
          {question.helper_text && <span className="text-muted d-inline-flex" title={question.helper_text}><IconInfoCircle size={14} /></span>}
        </label>
        {question.helper_text && <div className="text-muted small mb-1">{question.helper_text}</div>}
        {question.suggested_value && question.suggestion_reason && <div className="text-muted small mb-1">AI reason: {question.suggestion_reason}</div>}
        {(question.validation_errors || []).length > 0 && <div className="text-red small mb-1">{question.validation_errors.join('; ')}</div>}
        <div className="input-group">
          {isQuestionAiFilled(question) && <span className="input-group-text bg-purple-lt text-purple" title={`Answered by AI${question.suggestion_confidence ? ` (${question.suggestion_confidence})` : ''}`}><IconRobot size={16} /></span>}
          <input className="form-control" value={aiQuestionAnswers[question.question_key] || ''} onChange={(e) => updateAiQuestionAnswer(question.question_key, e.target.value)} placeholder="Answer for this router" disabled={question.locked} />
          {question.suggested_value && <button className="btn btn-outline-danger" type="button" onClick={() => clearAiQuestion(question)} title="Clear AI answer"><IconX size={16} /></button>}
        </div>
      </div>
    );
  }
  const stationFieldHints = {
    stationName: 'Friendly name for this deployment path. Example: CCR2116-Roma to CRS317 or Roma/Batu/GK HotSpot VLAN.',
    stationCode: 'Short unique code for this substation/station. It helps keep VLAN, HotSpot, logs, and future reports tied to one location.',
    stationDescription: 'Optional note describing where the VLAN travels, for example root gateway to CRS, OLT, ONU, and APs.',
    routerChain: 'Add routers in the exact order customer VLAN traffic travels. The first router is the root gateway; following routers only carry the same VLAN downstream.',
    mikrotikRouter: 'Choose one of the MikroTik routers already saved in the system. The system uses read-only scan/API data to list its ports and bridges.',
    rootBridge: 'This is the bridge/interface on the root gateway where the VLAN interface is created. In your working example this is SwAC. PPPoE interfaces are hidden because this must not be a customer PPPoE session.',
    downstreamBridge: 'This is the downstream router bridge where the same VLAN should be carried. In your CRS317 example this is SwBridge.',
    taggedPortsRoot: 'Select the root bridge itself plus the trunk port going to the next router. In your working example this was SwAC and sfp-sfpplus3. PPPoE interfaces are hidden here.',
    taggedPortsDownstream: 'Select the port from the previous router and the ports going toward OLTs/APs. In your CRS317 example these were sfp-sfpplus2, sfp-sfpplus3, and the OLT/AP-facing ports. PPPoE interfaces are hidden here.',
    vlanId: 'Customer VLAN used by the open captive portal SSID. In your tested setup this is VLAN 77.',
    vlanInterfaceName: 'RouterOS VLAN interface name created on the root gateway. In your example this is VLAN77-3J-HOTSPOT.',
    clientNetwork: 'Network used by WiFi voucher clients. In your example this is 10.77.0.0/24.',
    gatewayIp: 'IP address of the root MikroTik on the customer VLAN. In your example this is 10.77.0.1.',
    poolStart: 'First DHCP address given to WiFi clients. In your example this is 10.77.0.2.',
    poolEnd: 'Last DHCP address given to WiFi clients. In your example this is 10.77.0.254.',
    poolName: 'RouterOS IP pool name for customer devices. In your example this is POOL-3J-HOTSPOT-V77.',
    createDhcpServer: 'Keep this enabled when the root gateway should hand IP addresses to voucher WiFi clients. CRS/trunk routers do not create DHCP servers.',
    dhcpServerName: 'RouterOS DHCP server name created on the root gateway for this station VLAN. In your example this maps to /ip dhcp-server add using the VLAN interface and pool.',
    dhcpLeaseTime: 'How long voucher clients keep their DHCP address before renewal. A short value such as 1h is practical during pilot testing.',
    localInterfaceList: 'Interface list where the new VLAN interface is added so existing LAN/local firewall logic can recognize it. In your example this is LOCAL.',
    dnsServers: 'Router upstream DNS servers. Captive clients receive only the MikroTik gateway as DNS; the router forwards lookups to these upstream servers after controlling captive detection.',
    createHotspotProfile: 'Keep this enabled to create a station-specific MikroTik HotSpot profile on the root gateway.',
    createHotspotServer: 'Keep this enabled to create the MikroTik HotSpot server on the root gateway VLAN interface. CRS/trunk routers do not create HotSpot servers.',
    createWalledGarden: 'Adds pre-login allow rules so clients can reach the 3J portal server and DNS before they redeem a voucher.',
    hotspotProfileName: 'RouterOS HotSpot profile name for this station. The HotSpot server uses this profile.',
    hotspotHtmlDirectory: 'RouterOS HotSpot HTML directory. Use hotspot unless you have uploaded a custom directory to the MikroTik.',
    hotspotDnsName: 'MikroTik HotSpot DNS name for this station. Clients can be redirected to this local name during HotSpot login.',
    hotspotServerName: 'MikroTik HotSpot server name for the root gateway. This is not used by CRS/trunk routers.',
    portalUrl: 'Customer portal URL clients should reach before login. Staging usually uses http://192.168.50.70:8080/portal.',
    apManagementEnabled: 'Enable this when APs should receive management IPs from a dedicated AP management VLAN instead of the customer HotSpot VLAN.',
    apManagementVlanId: 'VLAN tag used by AP management. Configure the same management VLAN on Omada/APs. Default for new stations is VLAN 111.',
    apManagementInterfaceName: 'RouterOS VLAN interface name for AP management on the root gateway and monitoring interfaces on trunk routers.',
    apManagementNetwork: 'Dedicated subnet for AP management IP addresses. Default is 10.111.0.0/24. Do not reuse the customer HotSpot subnet.',
    apManagementGateway: 'Root MikroTik IP address inside the AP management subnet. APs use this as their gateway.',
    apManagementPoolStart: 'First DHCP address for AP management. Leave room before this range for static AP/router addresses.',
    apManagementPoolEnd: 'Last DHCP address for AP management.',
    apManagementPoolName: 'RouterOS IP pool name for AP management leases.',
    apManagementDhcpServerName: 'RouterOS DHCP server name for AP management. This is root-gateway-only.',
    apManagementDnsServers: 'DNS servers handed to APs on the management VLAN. AP adoption should still use the Omada controller IP or inform URL.'
  };
  function StationLabel({ children, hint }) {
    return (
      <label className="form-label station-field-label">
        <span>{children}</span>
        {hint && <FieldHint text={hint} />}
      </label>
    );
  }
  function isPppoeInterface(iface = {}) {
    const text = [iface.name, iface.type, iface.comment].map((value) => String(value || '').toLowerCase()).join(' ');
    return text.includes('pppoe');
  }
  function interfaceOptionLabel(iface = {}) {
    return [iface.name, iface.type, iface.bridge ? `bridge: ${iface.bridge}` : '', iface.comment].filter(Boolean).join(' - ');
  }
  const stationChainReady = stationForm.routers.length > 0;
  const stationRouterPathReady = stationForm.routers.length > 0 && stationForm.routers.every((router) => router.router_id && router.bridge_name && router.tagged_ports);
  const stationRootReady = Boolean(
    stationForm.vlan_id
    && stationForm.client_network_cidr
    && stationForm.gateway_ip
    && stationForm.pool_start_ip
    && stationForm.pool_end_ip
    && (!stationForm.create_dhcp_server || stationForm.dhcp_server_name)
    && (!stationForm.create_hotspot_profile || stationForm.hotspot_profile_name)
    && (!stationForm.create_hotspot_server || stationForm.hotspot_server_name)
    && stationForm.portal_url
  );
  const stationStepItems = [
    { label: '1. Name Station', ready: Boolean(stationForm.station_name.trim() && stationForm.station_code.trim()), detail: 'Identify this substation network.' },
    { label: '2. Build Router Chain', ready: stationChainReady, detail: 'Root gateway first, downstream routers after.' },
    { label: '3. Fill Router Fields', ready: stationRouterPathReady && stationRootReady, detail: 'Select bridges/ports plus customer VLAN values.' },
    { label: '4. Review Plan', ready: false, detail: 'Generated commands open after save.' }
  ];
  const mikrotikFieldHints = {
    vlanId: 'VLAN number for voucher customers. This must match the VLAN configured on the AP SSID.',
    vlanParent: 'The MikroTik bridge, trunk, or port where tagged AP customer traffic arrives. Do not choose the WAN or internet interface here.',
    vlanInterfaceName: 'Optional MikroTik VLAN interface label. Leave blank to let the system generate one from your system name and VLAN ID.',
    clientNetwork: 'Private network for voucher users, for example 10.30.0.0/24. Do not reuse your office LAN, AP management network, or another existing subnet.',
    gatewayIp: 'MikroTik IP address inside the voucher-user network, for example 10.30.0.1. Keep it outside the client pool.',
    poolStart: 'First IP address MikroTik can give to voucher users.',
    poolEnd: 'Last IP address MikroTik can give to voucher users.',
    poolName: 'Optional MikroTik pool label. Leave blank for a system-generated name.',
    dhcpServerName: 'Optional MikroTik DHCP server label. Leave blank for a system-generated name.',
    leaseTime: 'How long a client keeps its assigned IP address, for example 1h.',
    dnsServers: 'DNS servers sent to clients after they connect, for example 1.1.1.1,8.8.8.8.',
    hotspotDnsName: 'Optional local HotSpot DNS name. Leave blank if you are not sure.',
    wanInterface: 'Internet or uplink side of the MikroTik. Used only when NAT masquerade is enabled.',
    nat: 'Enable this when this MikroTik will send voucher users to the internet directly.'
  };
  function FieldHint({ text }) {
    return (
      <span className="text-muted d-inline-flex align-items-center" title={text} aria-label={text}>
        <IconInfoCircle size={14} />
      </span>
    );
  }
  const sanityChecks = [
    { key: 'portal-page', group: 'Portal', title: 'Portal URL is configured', details: portalSettings?.portal_url_staging || 'Set the staging portal URL first.', mode: 'auto', state: hasPortalUrl ? 'ready' : 'needs_action' },
    { key: 'portal-design', group: 'Portal', title: 'Portal design is available', details: 'Customer voucher page template and branding can load from Portal Settings.', mode: 'auto', state: settings?.branding ? 'ready' : 'needs_action' },
    { key: 'ssid-source', group: 'WiFi', title: 'SSID source is APs Deployment', details: `Current SSID: ${portalSsidDisplay}. Edit it in APs Deployment -> Sites -> Configurations.`, mode: 'auto', state: portalSsidPrimary ? 'ready' : 'needs_action' },
    { key: 'router-added', group: 'MikroTik', title: 'At least one MikroTik router is added', details: `${mikrotiks.length} router record${mikrotiks.length === 1 ? '' : 's'} saved.`, mode: 'auto', state: mikrotiks.length ? 'ready' : 'needs_action' },
    { key: 'router-vlan', group: 'MikroTik', title: 'MikroTik customer VLAN is assigned', details: `${mikrotiksWithCustomerVlan}/${mikrotiks.length || 0} router${mikrotiks.length === 1 ? '' : 's'} have a customer VLAN ID and VLAN parent interface. This VLAN must also be used on the AP SSID.`, mode: 'auto', state: mikrotiks.length && mikrotiksWithCustomerVlan === mikrotiks.length ? 'ready' : 'needs_action' },
    { key: 'router-reachable', group: 'MikroTik', title: 'MikroTik API connection works', details: `${reachableMikrotiks}/${mikrotiks.length || 0} router${mikrotiks.length === 1 ? '' : 's'} reachable.`, mode: 'auto', state: reachableMikrotiks > 0 ? 'ready' : 'needs_action' },
    { key: 'station-plan', group: 'MikroTik', title: 'MikroTik station plan exists', details: `${mikrotikStations.length} station plan${mikrotikStations.length === 1 ? '' : 's'} saved under Network -> MikroTik -> Configuration.`, mode: 'auto', state: mikrotikStations.length ? 'ready' : 'needs_action' },
    { key: 'router-applied', group: 'MikroTik', title: 'MikroTik apply phase', details: 'RouterOS write/apply is not the primary action in this screen yet. Station plans must be reviewed first.', mode: 'auto', state: hasAppliedMikrotik ? 'ready' : 'placeholder' },
    { key: 'voucher-stock', group: 'Voucher', title: 'Unused voucher exists for testing', details: `${voucherSummary?.unused || 0} unused voucher${Number(voucherSummary?.unused || 0) === 1 ? '' : 's'} available.`, mode: 'auto', state: hasUnusedVouchers ? 'ready' : 'needs_action' },
    { key: 'portal-redemption', group: 'Voucher', title: 'Portal voucher redemption has succeeded before', details: hasSuccessfulPortalRedemption ? 'At least one CLIENT_PORTAL redemption exists.' : 'Create a test voucher and redeem it from /portal.', mode: 'auto', state: hasSuccessfulPortalRedemption ? 'ready' : 'needs_action' },
    { key: 'portal-session', group: 'Session', title: 'Portal sessions are being recorded', details: `${sessions.length} portal session${sessions.length === 1 ? '' : 's'} recorded.`, mode: 'auto', state: hasPortalSession ? 'ready' : 'needs_action' },
    { key: 'gateway-auth', group: 'Gateway', title: 'Gateway authorization has succeeded', details: hasGatewayAuthorizationSuccess ? 'At least one gateway authorization log succeeded.' : 'Redeem a voucher from a MikroTik HotSpot redirect to test gateway authorization.', mode: 'auto', state: hasGatewayAuthorizationSuccess ? 'ready' : 'needs_action' },
    { key: 'phone-redirect', group: 'Field Test', title: 'Phone redirects to the portal from the test SSID', details: 'Manual operator check. Connect a phone to the AP SSID and confirm it opens the voucher portal.', mode: 'manual', state: sanityProgress['phone-redirect'] ? 'ready' : 'manual' },
    { key: 'internet-after-voucher', group: 'Field Test', title: 'Internet works after a valid voucher', details: 'Manual operator check. This remains blocked until MikroTik enforcement/authorization is fully wired.', mode: 'manual', state: sanityProgress['internet-after-voucher'] ? 'ready' : 'placeholder' },
    { key: 'expired-blocked', group: 'Field Test', title: 'Expired or invalid voucher stays blocked', details: 'Manual operator check after gateway enforcement is active.', mode: 'manual', state: sanityProgress['expired-blocked'] ? 'ready' : 'placeholder' },
    { key: 'payments', group: 'Future', title: 'Payments integration', details: 'Placeholder only. Payments are not part of the current captive portal phase.', mode: 'placeholder', state: 'placeholder' },
    { key: 'sms', group: 'Future', title: 'SMS integration', details: 'Placeholder only. SMS is not part of the current captive portal phase.', mode: 'placeholder', state: 'placeholder' },
    { key: 'coinslot', group: 'Future', title: 'Coinslot / vendo integration', details: 'Placeholder only. Vendo hardware integration is not part of the current captive portal phase.', mode: 'placeholder', state: 'placeholder' }
  ];
  const requiredSanityChecks = sanityChecks.filter((item) => item.mode !== 'placeholder' && item.state !== 'placeholder');
  const readySanityChecks = requiredSanityChecks.filter((item) => item.state === 'ready').length;
  function sanityBadge(item) {
    if (item.state === 'ready') return <span className="badge bg-green-lt text-green">Ready</span>;
    if (item.state === 'manual') return <span className="badge bg-blue-lt text-blue">Manual check</span>;
    if (item.state === 'placeholder') return <span className="badge bg-yellow-lt text-yellow">Coming soon</span>;
    return <span className="badge bg-red-lt text-red">Needs action</span>;
  }
  return (
    <div className="row row-cards">
      {message && (
        <div className="col-12">
          <AutoDismissAlert message={message} onDismiss={() => setMessage('')} />
        </div>
      )}
      <div className="col-12">
          <div className="card captive-portal-panel">
            <div className="card-header">
              <div>
              <h3 className="card-title mb-1">{isMikrotikOnly ? 'MikroTik Gateway Management' : 'Captive Portal'}</h3>
              <div className="text-muted small">
                {isMikrotikOnly
                  ? 'Plan station router chains, run preflight scans, and manage MikroTik gateway setup from the Network workspace.'
                  : 'Manage portal URLs, customer portal design, sessions, and integration tools from one workspace.'}
              </div>
            </div>
          </div>
          {!isMikrotikOnly && <div className="card-body border-bottom py-2">
            <ul className="nav nav-tabs flex-nowrap overflow-auto" role="tablist">
              {tabs.map((tab) => (
                <li className="nav-item" role="presentation" key={tab}>
                  <button
                    type="button"
                    className={`nav-link ${activeTab === tab ? 'active' : ''}`}
                    role="tab"
                    aria-selected={activeTab === tab}
                    onClick={() => setActiveTab(tab)}
                  >
                    {tab}
                  </button>
                </li>
              ))}
            </ul>
          </div>}
          <div className="card-body">
            <div className="alert alert-info">
              {isMikrotikOnly
                ? 'MikroTik is the preferred gateway/enforcement layer. Use stations to model root gateway and downstream trunk routers before any RouterOS change is reviewed.'
                : 'Captive Portal + Voucher is the primary customer flow. MikroTik is now the preferred gateway for redirect, allow/block, and future substation tunnel setups. Omada remains for AP/SSID management.'}
            </div>
            <div className="row row-cards">
      {activeTab === 'Portal' && <>
        <div className="col-md-6">
          <Card title="Portal URL">
            <div className="mb-2"><span className="text-muted">Staging</span><div className="h3 mb-0">{portalSettings?.portal_url_staging || 'http://192.168.50.70:8080/portal'}</div></div>
            <div className="mb-2"><span className="text-muted">Production</span><div className="h3 mb-0">{portalSettings?.portal_url_production || 'http://192.168.50.70/portal'}</div></div>
            <div>
              <div className="d-flex align-items-center gap-2">
                <span className="text-muted">SSID Names</span>
                <button className="btn btn-icon btn-sm" type="button" title="Edit SSID and Security" aria-label="Edit SSID and Security" onClick={openSsidConfiguration}>
                  <IconEdit size={15} />
                </button>
              </div>
              {portalSsid.use_same_ssid ? (
                <div className="h3 mb-0">{portalSsidDisplay}</div>
              ) : (
                <div className="d-flex flex-wrap gap-2 mt-1">
                  <span className="badge bg-blue-lt text-blue">2.4GHz: {portalSsid.ssid_2g}</span>
                  <span className="badge bg-cyan-lt text-cyan">5GHz: {portalSsid.ssid_5g}</span>
                </div>
              )}
              <div className="text-muted small mt-1">Managed in APs Deployment - Sites - Configurations - SSID and Security.</div>
            </div>
          </Card>
        </div>
        <div className="col-md-6">
          <Card title={<CardHeaderContent><div className="d-flex align-items-center justify-content-between gap-2 w-100"><h3 className="card-title mb-0">MikroTik Status</h3>
              <span className={`badge ${reachableMikrotiks === mikrotiks.length && mikrotiks.length ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>
                {reachableMikrotiks}/{mikrotiks.length} reachable
              </span></div></CardHeaderContent>}>
            {!mikrotiks.length ? <div className="empty">No MikroTik routers connected yet. Add one under Network - MikroTik - Add Router.</div> : (
              <div className="list-group list-group-flush">
                {mikrotiks.map((router) => (
                  <div className="list-group-item d-flex align-items-center justify-content-between px-0" key={router.id}>
                    <div>
                      <div className="fw-semibold">{router.router_name}</div>
                      <div className="text-muted small">{router.host}:{router.api_port}</div>
                    </div>
                    <span className={`badge ${router.status === 'REACHABLE' ? 'bg-green-lt text-green' : router.status === 'AUTH_FAILED' ? 'bg-yellow-lt text-yellow' : 'bg-red-lt text-red'}`}>{router.status}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
        <div className="col-12">
          <Card title="Portal Design">
            <div className="d-flex align-items-center justify-content-between gap-2 mb-3">
              <div className="text-muted">This is the customer-facing voucher portal design. Edit HTML/CSS only if you keep the required voucher form placeholder.</div>
              <button className="btn btn-primary" type="button" onClick={() => { window.history.pushState({}, '', '/admin/captive-portal/editor'); window.dispatchEvent(new PopStateEvent('popstate')); }}><IconEdit size={18} className="me-2" />Edit Portal Design</button>
            </div>
            <iframe className="portal-design-preview portal-design-preview-wide" title="Portal design preview" srcDoc={portalPreviewSrcDoc(portalSettings?.custom_html, portalSettings?.custom_css)} />
          </Card>
        </div>
      </>}
      {activeTab === 'MikroTik' && <>
        <div className="col-12">
          <div className="card">
            <div className="card-body border-bottom py-2">
              <ul className="nav nav-tabs flex-nowrap overflow-auto" role="tablist">
                {['Overview', 'Configuration', ...(mikrotikTab === 'Scan Result' ? ['Scan Result'] : []), 'Add Router'].map((item) => (
                  <li className="nav-item" role="presentation" key={item}>
                    <button type="button" className={`nav-link ${mikrotikTab === item ? 'active' : ''}`} onClick={() => setMikrotikTab(item)}>
                      {item}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div className="card-body">
              {mikrotikTab === 'Overview' && <>
                <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                  <div>
                    <h3 className="card-title mb-1">MikroTik Overview</h3>
                    <div className="text-muted small">Review router readiness, latest preflight status, and scan results before building or editing station plans.</div>
                  </div>
                  <div className="btn-list">
                    <button className="btn btn-outline-secondary btn-sm" type="button" onClick={loadPreflightSummary}>
                      <IconRefresh size={15} className="me-1" />Refresh Status
                    </button>
                    <button className="btn btn-primary btn-sm" type="button" onClick={prescanAllRouters} disabled={preflightScanningAll || !mikrotiks.length}>
                      <IconSearch size={15} className="me-1" />{preflightScanningAll ? 'Scanning...' : 'Prescan All Routers'}
                    </button>
                  </div>
                </div>
                <div className="row g-3 mb-3">
                  {[
                    { label: 'Routers', value: mikrotiks.length, detail: 'Configured MikroTik routers', icon: IconRouter, badgeClass: 'bg-blue-lt text-blue' },
                    { label: 'Reachable', value: reachableMikrotiks, detail: 'Routers with reachable API status', icon: IconCircleCheck, badgeClass: 'bg-green-lt text-green' },
                    { label: 'Scanned', value: routersWithPreflight.length, detail: 'Routers with latest preflight data', icon: IconSearch, badgeClass: 'bg-cyan-lt text-cyan' },
                    { label: 'Successful Scans', value: successfulPreflightRouters.length, detail: 'Latest successful scans', icon: IconShieldLock, badgeClass: 'bg-teal-lt text-teal' },
                    { label: 'Not Scanned', value: notScannedMikrotiks, detail: 'Routers without preflight data', icon: IconClock, badgeClass: 'bg-yellow-lt text-yellow' },
                    { label: 'High / Blocked Risk', value: highRiskPreflightRouters.length, detail: 'Routers flagged high risk or blocked', icon: IconAlertTriangle, badgeClass: 'bg-orange-lt text-orange' },
                    { label: 'Failed Scans', value: failedPreflightRouters.length, detail: 'Latest failed preflight scans', icon: IconBan, badgeClass: 'bg-red-lt text-red' },
                    { label: 'Station Plans', value: mikrotikStations.length, detail: 'Saved station-based plans', icon: IconListDetails, badgeClass: 'bg-purple-lt text-purple' }
                  ].map((item) => {
                    const KpiIcon = item.icon;
                    return (
                    <div className="col-sm-6 col-lg-3" key={`mikrotik-overview-kpi-${item.label}`}>
                      <div className="border rounded p-3 h-100 d-flex align-items-start gap-3">
                        <span className={`mikrotik-overview-kpi-icon ${item.badgeClass}`}>
                          <KpiIcon size={28} />
                        </span>
                        <div className="min-w-0">
                          <div className="text-muted small">{item.label}</div>
                          <div className="h2 mb-1">{item.value}</div>
                          <div className="text-muted small">{item.detail}</div>
                        </div>
                      </div>
                    </div>
                    );
                  })}
                </div>
                <div className={`alert ${preflightEngaged ? 'alert-info' : 'alert-warning'}`}>
                  <div className="d-flex align-items-start justify-content-between gap-3 flex-wrap">
                    <div>
                      <div className="fw-semibold mb-1">{preflightEngaged ? 'Latest preflight data detected' : 'No read-only preflight data yet'}</div>
                      <div>
                        {preflightEngaged
                          ? `${successfulPreflightRouters.length}/${mikrotiks.length} routers have a successful latest scan. Latest scan: ${fmt(latestPreflightTimestamp) || 'Unknown'}. Use the router list below to review scan details or re-scan a router.`
                          : 'Run Prescan All Routers or scan one router from the list below before adding a station. The scan is read-only and lets the system validate VLANs, subnets, pools, DHCP, HotSpot, PPPoE, OSPF, WireGuard, routing, and firewall conflict indicators.'}
                      </div>
                    </div>
                  </div>
                  {preflightSummary?.latest_batch && (
                    <div className="small mt-2">
                      Last batch: <strong>{preflightSummary.latest_batch.status}</strong> · {preflightSummary.latest_batch.success_count || 0} success · {preflightSummary.latest_batch.failed_count || 0} failed
                    </div>
                  )}
                </div>
                <div className="table-responsive">
                  <table className="table table-vcenter">
                    <thead>
                      <tr>
                        <th>MikroTik Router</th>
                        <th>API Status</th>
                        <th>Latest Preflight</th>
                        <th>Detected Details</th>
                        <th className="text-end">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mikrotiks.map((router) => (
                        <tr key={router.id}>
                          <td>
                            <div className="fw-semibold">{router.router_name}</div>
                            <div className="text-muted small">{router.host}:{router.api_port}{router.use_tls ? ' TLS' : ''}</div>
                          </td>
                          <td>
                            <span className={`badge ${router.status === 'REACHABLE' ? 'bg-green-lt text-green' : router.status === 'AUTH_FAILED' ? 'bg-yellow-lt text-yellow' : router.status === 'UNREACHABLE' || router.status === 'ERROR' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary'}`}>{router.status || 'NOT_TESTED'}</span>
                            {router.last_error && <div className="text-muted small text-truncate mt-1" title={router.last_error}>{router.last_error}</div>}
                          </td>
                          <td>
                            {router.latest_preflight_scan ? (
                              <div>
                                <span className={`badge ${preflightRiskClass(router.latest_preflight_scan.risk_level || 'NEW')}`}>{router.latest_preflight_scan.risk_level || 'SCANNED'}</span>
                                <div className="text-muted small">{router.latest_preflight_scan.scan_status} · {fmt(router.latest_preflight_scan.created_at)}</div>
                                {router.latest_preflight_scan.last_error && <div className="text-danger small text-truncate" title={router.latest_preflight_scan.last_error}>{router.latest_preflight_scan.last_error}</div>}
                              </div>
                            ) : <span className="badge bg-yellow-lt text-yellow">Not scanned</span>}
                          </td>
                          <td>
                            <div>{router.latest_preflight_scan?.router_role_guess || 'Unknown'}</div>
                            <div className="text-muted small">Read-only scan data is used to validate station fields.</div>
                          </td>
                          <td className="text-end">
                            <div className="btn-list justify-content-end flex-nowrap">
                              <button className="btn btn-sm btn-outline-secondary" type="button" disabled={!router.latest_preflight_scan} onClick={() => window.open(`/admin/network/mikrotik/scan-result?router_id=${encodeURIComponent(router.id)}`, '_blank', 'noopener,noreferrer')} title={router.latest_preflight_scan ? 'View scanned result' : 'Run a scan first'}>
                                <IconEye size={16} className="me-1" />View Scan Result
                              </button>
                              <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => runPreflightScan(router.id)} disabled={preflightScanning}>
                                <IconSearch size={16} className="me-1" />{preflightScanning && preflightRouterId === router.id ? 'Scanning...' : 'Run Scan'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {!mikrotiks.length && <tr><td colSpan="5" className="text-muted p-4">No MikroTik routers added yet. Open Network - MikroTik - Add Router first.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </>}
              {mikrotikTab === 'Configuration' && <>
                <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                  <div>
                    <h3 className="card-title mb-1">MikroTik Configuration</h3>
	                    <div className="text-muted small">Station-based MikroTik setup is the active path. Build the root-to-downstream router chain first, then review the station plan before any RouterOS configuration is applied.</div>
                  </div>
                  <button className="btn btn-primary" type="button" onClick={openStationModal} disabled={!preflightEngaged} title={preflightEngaged ? 'Create a station router chain.' : 'Run at least one read-only preflight scan before adding a station.'}>
                    <IconRouter size={18} className="me-2" />Add Station
                  </button>
                </div>
                <div className="border rounded p-3 mb-3">
                  <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                    <div>
                      <div className="fw-semibold">HTML and AP Management</div>
                      <div className="text-muted small">The system uses one managed redirect file named <code>login.html</code> on every station root gateway. Central AP management VLAN/subnet is configured here once and pushed through the selected root/trunk routers.</div>
                    </div>
                    <div className="btn-list justify-content-end flex-nowrap">
                      <button className="btn btn-outline-secondary btn-sm" type="button" onClick={openApManagementModal} disabled={!preflightEngaged}>
                        <IconSettings size={15} className="me-1" />AP Management Details
                      </button>
                      <button className="btn btn-outline-primary btn-sm" type="button" onClick={openApManagementImplementation} disabled={!apManagementConfig?.id}>
                        <IconCloudUpload size={15} className="me-1" />Push AP Management Config
                      </button>
                      <button className="btn btn-outline-primary btn-sm" type="button" onClick={checkHotspotLoginSync} disabled={hotspotLoginChecking || hotspotLoginSyncing || !mikrotikStations.length}>
                        <IconSearch size={15} className="me-1" />{hotspotLoginChecking ? 'Checking...' : 'Check Sync'}
                      </button>
                      <button className="btn btn-primary btn-sm" type="button" onClick={() => syncHotspotLoginHtml()} disabled={hotspotLoginSyncing || !mikrotikStations.length}>
                        <IconRefresh size={15} className="me-1" />{hotspotLoginSyncing ? 'Syncing...' : 'Sync login.html to MikroTik'}
                      </button>
                    </div>
                  </div>
                  <div className="row g-2 mb-3">
                    {[
                      { label: 'Stations', value: hotspotLoginSync.summary?.total ?? mikrotikStations.length, tone: 'bg-blue-lt text-blue' },
                      { label: 'Synced', value: hotspotLoginSync.summary?.synced ?? 0, tone: 'bg-green-lt text-green' },
                      { label: 'Needs Sync', value: hotspotLoginSync.summary?.needs_sync ?? 0, tone: 'bg-yellow-lt text-yellow' },
                      { label: 'Errors', value: hotspotLoginSync.summary?.failed ?? 0, tone: 'bg-red-lt text-red' }
                    ].map((item) => (
                      <div className="col-6 col-md-3" key={`login-sync-kpi-${item.label}`}>
                        <div className="border rounded p-2 h-100">
                          <div className="text-muted small">{item.label}</div>
                          <span className={`badge fs-6 ${item.tone}`}>{item.value}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="border rounded p-3 mb-3 bg-light">
                    {(() => {
                      const progress = apManagementProgressSummary(apManagementConfig);
                      return (
                        <div className="d-flex flex-column flex-lg-row align-items-start align-items-lg-center justify-content-between gap-3">
                          <div>
                            <div className="fw-semibold">{apManagementConfig?.config_name || 'Central AP Management'}</div>
                            <div className="text-muted small">
                              VLAN {apManagementConfig?.vlan_id || 111} · {apManagementConfig?.network_cidr || '10.111.0.0/24'} · {apManagementConfig?.routers?.length || 0} router(s) in path
                            </div>
                            <div className="text-muted small">Use this for Omada/AP management traffic. Customer voucher traffic stays in station HotSpot VLANs.</div>
                          </div>
                          <div className="d-flex flex-wrap align-items-center gap-2">
                            <span className={`badge ${apManagementConfig?.id ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{apManagementConfig?.id ? apManagementConfig.status || 'READY' : 'Not saved'}</span>
                            <span className="badge bg-blue-lt text-blue">{progress.pushed}/{progress.total || 0} pushed</span>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                  {!!(hotspotLoginSync.stations || []).length && (
                    <div className="table-responsive">
                      <table className="table table-sm table-vcenter mb-0">
                        <thead>
                          <tr>
                            <th>Station</th>
                            <th>Root Gateway</th>
                            <th>File</th>
                            <th>Status</th>
                            <th className="text-end">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(hotspotLoginSync.stations || []).map((row) => (
                            <tr key={`login-sync-${row.station_id}`}>
                              <td>
                                <div className="fw-semibold">{row.station_name}</div>
                                <div className="text-muted small">{row.latest_sync?.created_at ? `Last sync: ${fmt(row.latest_sync.created_at)}` : 'Not synced yet'}</div>
                              </td>
                              <td>{row.router_name || '-'}</td>
                              <td><code>{row.file_path || 'hotspot/login.html'}</code></td>
                              <td>
                                <span className={`badge ${hotspotLoginStatusClass(row.status)}`}>{row.status || 'UNKNOWN'}</span>
                                {row.message && <div className="text-muted small text-truncate mt-1" title={row.message}>{row.message}</div>}
                              </td>
                              <td className="text-end">
                                <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => syncHotspotLoginHtml(row.station_id)} disabled={hotspotLoginSyncing}>
                                  <IconRefresh size={15} className="me-1" />Sync
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  {!mikrotikStations.length && <div className="text-muted small">Create a station first. Sync status appears here after the station root gateway is saved.</div>}
                </div>
                <div className="border rounded p-3 mb-3">
                  <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                    <div>
                      <div className="fw-semibold">Station-based MikroTik planning</div>
                      <div className="text-muted small">
                        A station is the customer captive portal VLAN path: root gateway first, then CRS/switch/transport routers toward OLTs and APs. Central AP management is configured separately in HTML and AP Management.
                      </div>
                    </div>
                    <span className="badge bg-blue-lt text-blue">Router chain</span>
                  </div>
                  {mikrotikStations.length ? (
                    <div className="station-card-list">
                      {mikrotikStations.map((station) => (
                        <div className="station-plan-card" key={station.id}>
                          {(() => {
                            const progress = stationProgressSummary(station);
                            const pct = progress.total ? Math.round((progress.pushed / progress.total) * 100) : 0;
                            return (
                              <div className="station-plan-progress">
                                <div className="station-plan-progress-bar" style={{ width: `${pct}%` }} />
                              </div>
                            );
                          })()}
                          <div className="station-plan-card-header">
                            <div className="station-plan-card-title">
                              <span className="station-chain-node root"><IconRouter size={18} /></span>
                              <div>
                                <div className="fw-semibold">{station.station_name}</div>
                                <div className="text-muted small">{station.station_code ? `${station.station_code} · ` : ''}Hover the router links to view customer VLAN, gateway, and pool details.</div>
                              </div>
                            </div>
                            <div className="btn-list justify-content-end flex-nowrap">
                              <span className="badge bg-secondary-lt text-secondary align-self-center">{station.status}</span>
                              {(() => {
                                const progress = stationProgressSummary(station);
                                return <span className={`badge align-self-center ${progress.pushed >= progress.total && progress.total ? 'bg-green-lt text-green' : progress.pushed ? 'bg-yellow-lt text-yellow' : 'bg-secondary-lt text-secondary'}`}>{progress.pushed}/{progress.total} pushed</span>;
                              })()}
                              {(() => {
                                const syncRow = stationLoginSyncRow(station.id) || station.hotspot_login_sync || {};
                                return <span className={`badge align-self-center ${hotspotLoginStatusClass(syncRow.status)}`}>login.html {syncRow.status || 'UNKNOWN'}</span>;
                              })()}
                              <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => setStationReview(station)} title="View generated station plan">
                                <IconEye size={16} className="me-1" />View
                              </button>
                              <button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => openEditStation(station)} title="Edit station plan">
                                <IconEdit size={16} className="me-1" />Edit
                              </button>
                              <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => openStationDiagnostics(station)} title="Run HotSpot diagnostics">
                                <IconActivity size={16} className="me-1" />Diagnostics
                              </button>
                              <button className="btn btn-sm btn-primary" type="button" onClick={() => openStationImplementation(station)} title="Open config push workflow">
                                <IconPlayerPlay size={16} className="me-1" />Push Config
                              </button>
                              {station.status === 'ACTIVE' && (
                                <button className="btn btn-sm btn-outline-danger" type="button" onClick={() => openStationRemove(station)} title="Remove station-created RouterOS config">
                                  <IconTrash size={16} className="me-1" />Remove Config
                                </button>
                              )}
                            </div>
                          </div>
                          <div className="station-plan-card-body">
                            {renderStationChainPath(station)}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty py-3">No station plans yet. Add a station to model root gateway and downstream VLAN trunk routers before applying MikroTik setup.</div>
                  )}
                </div>
                {false && mikrotikPlan && <div className="border rounded p-3 mt-3">
                  <div className="d-flex align-items-start justify-content-between gap-2 mb-3">
	                    <div>
		                      <div className="fw-semibold">MikroTik Integration Setup: {mikrotikPlan.router?.router_name}</div>
		                      <div className="text-muted small">Follow these steps from top to bottom. Open each item, review the exact RouterOS configuration, then apply that step before moving to the next prerequisite.</div>
		                      {actionResult && (
		                        <div className={`alert mt-2 mb-0 py-2 ${actionResult.status === 'REACHABLE' || actionResult.status === 'SUCCESS' ? 'alert-success' : actionResult.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>
		                          {actionResult.message || actionResult.status}
		                        </div>
		                      )}
	                    </div>
	                    <div className="btn-list justify-content-end">
	                      <span className={`badge ${mikrotikPlan.progress?.complete ? 'bg-green-lt text-green' : 'bg-blue-lt text-blue'}`}>
	                        {mikrotikPlan.progress?.complete && <IconCircleCheck size={14} className="me-1" />}
	                        {mikrotikPlan.progress?.label || '0/5'}
	                      </span>
	                      <span className={`badge ${planManagedStatus?.has_managed_config ? 'bg-red-lt text-red' : planManagedStatus?.status === 'ERROR' ? 'bg-yellow-lt text-yellow' : 'bg-secondary-lt text-secondary'}`}>
	                        {planManagedStatus?.has_managed_config ? `${planManagedStatus.found_count || 0} managed object(s)` : planManagedStatus?.status === 'ERROR' ? 'Check failed' : 'No managed config detected'}
	                      </span>
	                      <button className="btn btn-outline-secondary btn-sm" type="button" onClick={() => checkMikrotikManagedConfiguration(mikrotikPlanRouterId)} disabled={mikrotikCheckingConfig === mikrotikPlanRouterId || !mikrotikPlan.can_apply} title="Check RouterOS for 3JCentralPisowifi-managed objects.">
	                        <IconSearch size={15} className="me-1" />{mikrotikCheckingConfig === mikrotikPlanRouterId ? 'Checking...' : 'Check Config'}
	                      </button>
	                      <button className="btn btn-outline-danger btn-sm" type="button" onClick={() => removeMikrotikConfiguration()} disabled={mikrotikReverting || !mikrotikPlan.can_apply || !planManagedStatus?.has_managed_config} title={planManagedStatus?.has_managed_config ? 'Remove only detected 3JCentralPisowifi-managed MikroTik objects by managed names/comments.' : 'Disabled until Check Config detects managed MikroTik objects.'}>
	                        <IconTrash size={15} className="me-1" />{mikrotikReverting ? 'Removing...' : 'Remove Config'}
	                      </button>
	                    </div>
	                  </div>
	                  <div className="alert alert-warning">
	                    <div className="fw-semibold mb-1">Step-by-step MikroTik changes</div>
	                    <div>Use Next to continue. If the current step is not complete yet, Next opens a review modal with the exact RouterOS configuration before anything is applied.</div>
	                  </div>
                    {mikrotikPlan.policy_gate && (
                      <div className={`alert ${mikrotikPlan.policy_gate.setup_allowed ? 'alert-info' : 'alert-danger'}`}>
                        <div className="fw-semibold mb-1">{mikrotikPlan.policy_gate.setup_allowed ? 'Preflight Policy: ready for future command preview' : 'HotSpot setup is blocked by Preflight Policy'}</div>
                        <div className="small mb-2">RouterOS writes are not applied from this view. Use the scan result view to inspect read-only router data before station planning.</div>
                        {(mikrotikPlan.policy_gate.blocking_reasons || []).length > 0 && (
                          <ul className="mb-2">
                            {mikrotikPlan.policy_gate.blocking_reasons.map((reason, index) => <li key={`plan-policy-blocker-${index}`}>{reason}</li>)}
                          </ul>
                        )}
                        <button className="btn btn-outline-primary btn-sm" type="button" onClick={() => { setMikrotikTab('Scan Result'); openPreflightRouter(mikrotikPlanRouterId); }}>
                          View Scan Result
                        </button>
                      </div>
                    )}
	                  <details className="border rounded mb-2">
	                    <summary className="p-3">
	                      <span className="d-flex align-items-center justify-content-between gap-3">
	                        <span>
	                          <span className="fw-semibold text-danger">Remove config preview</span>
	                          <span className="text-muted small d-block">Use this if the MikroTik setup conflicts or does not work. The button only enables after Check Config detects matching system-managed objects.</span>
	                        </span>
	                        <span className="badge bg-red-lt text-red">Managed objects only</span>
	                      </span>
	                    </summary>
	                    <div className="border-top p-3">
	                      <div className="row g-3">
	                        {(mikrotikPlan.revert?.commands || []).map((command, commandIndex) => (
	                          <div className="col-12" key={`revert-command-${commandIndex}`}>
	                            <div className="border rounded p-2 bg-light">
	                              <div className="fw-semibold small mb-1">{command.label || `Remove ${commandIndex + 1}`}</div>
	                              <pre className="mb-0 small"><code>{command.preview || 'No remove command preview available.'}</code></pre>
	                            </div>
	                          </div>
	                        ))}
	                      </div>
	                    </div>
	                  </details>
	                  <div className="d-flex flex-wrap gap-2 mb-3">
	                    {mikrotikActions.map((item, index) => (
	                      <button key={`mikrotik-step-pill-${item.key || index}`} type="button" className={`btn btn-sm ${index === currentMikrotikStepIndex ? 'btn-primary' : item.is_applied ? 'btn-outline-success' : 'btn-outline-secondary'}`} onClick={() => setMikrotikStepIndex(index)}>
	                        {item.is_applied && <IconCircleCheck size={14} className="me-1" />}
	                        Step {item.step_number || index + 1}
	                      </button>
	                    ))}
	                  </div>
	                  <div className="d-flex flex-column gap-2">
	                    {[currentMikrotikStep].filter(Boolean).map((item) => (
	                      <details className="border rounded" key={`${item.step}-${currentMikrotikStepIndex}`} open>
	                        <summary className="p-3">
	                          <span className="d-flex align-items-start justify-content-between gap-3">
	                            <span>
	                              <span className="d-flex align-items-center gap-2 mb-1">
	                                <span className="badge bg-blue-lt text-blue">Step {item.step_number || currentMikrotikStepIndex + 1}</span>
	                                <span className="fw-semibold">{item.step}</span>
	                              </span>
	                              <span className="text-muted small">{item.details}</span>
	                              {item.applied_status?.message && <span className="text-muted small d-block mt-1">{item.applied_status.message}</span>}
	                            </span>
		                            <span className={`badge ${item.is_applied ? 'bg-green-lt text-green' : item.status === 'failed' ? 'bg-red-lt text-red' : item.status === 'ready' ? 'bg-green-lt text-green' : item.status === 'needs_required_fields' || item.status === 'placeholder' ? 'bg-yellow-lt text-yellow' : 'bg-blue-lt text-blue'}`}>
	                              {item.is_applied && <IconCircleCheck size={14} className="me-1" />}
	                              {item.is_applied ? 'Applied' : item.status === 'needs_required_fields' ? 'Needs fields' : item.status}
	                            </span>
	                          </span>
	                        </summary>
	                        <div className="border-top p-3">
	                          {item.key === 'prepare_hotspot_profile' && setupMikrotikRow && (
	                            <div className="border rounded p-3 mb-3">
	                              <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
	                                <div>
	                                  <div className="fw-semibold">Dedicated customer VLAN and captive portal network fields</div>
	                                  <div className="text-muted small">Fill these values here, then save. The system will create a MikroTik VLAN interface and HotSpot network from these fields; the AP SSID must use the same VLAN ID.</div>
	                                  {setupMikrotikOptions.error && <div className="text-danger small mt-1">{setupMikrotikOptions.error}</div>}
	                                </div>
	                                <div className="btn-list">
	                                  <button className="btn btn-outline-primary btn-sm" type="button" onClick={() => loadMikrotikRouterOptions(mikrotikPlanRouterId)}>
	                                    <IconRefresh size={15} className="me-1" />Refresh Dropdowns
	                                  </button>
	                                </div>
	                              </div>
	                              <div className="row g-2">
	                                <div className="col-md-3">
	                                  <label className="form-label small d-flex align-items-center gap-1">Customer VLAN ID <span className="text-danger">*</span><FieldHint text={mikrotikFieldHints.vlanId} /></label>
	                                  <input className="form-control" type="number" min="1" max="4094" value={setupMikrotikRow.hotspot_vlan_id || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_vlan_id: e.target.value })} placeholder="30" />
	                                </div>
	                                <div className="col-md-3">
	                                  <label className="form-label small d-flex align-items-center gap-1">VLAN Parent Interface <span className="text-danger">*</span><FieldHint text={mikrotikFieldHints.vlanParent} /></label>
	                                  <select className="form-select" value={setupMikrotikRow.hotspot_vlan_parent_interface || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_vlan_parent_interface: e.target.value })}>
	                                    <option value="">Choose AP trunk/bridge</option>
	                                    {setupMikrotikRow.hotspot_vlan_parent_interface && !setupInterfaces.some((iface) => iface.name === setupMikrotikRow.hotspot_vlan_parent_interface) && <option value={setupMikrotikRow.hotspot_vlan_parent_interface}>{setupMikrotikRow.hotspot_vlan_parent_interface}</option>}
	                                    {setupInterfaces.map((iface) => <option value={iface.name} key={`vlan-parent-${iface.name}`}>{iface.name}{iface.type ? ` (${iface.type})` : ''}{iface.disabled ? ' - disabled' : ''}{iface.running ? ' - running' : ''}</option>)}
	                                  </select>
	                                </div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">VLAN Interface Name <FieldHint text={mikrotikFieldHints.vlanInterfaceName} /></label><input className="form-control" value={setupMikrotikRow.hotspot_vlan_interface_name || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_vlan_interface_name: e.target.value })} placeholder="auto: system-vlan-30" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">Client Network CIDR <FieldHint text={mikrotikFieldHints.clientNetwork} /></label><input className="form-control" value={setupMikrotikRow.hotspot_client_network_cidr || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_client_network_cidr: e.target.value })} placeholder="10.30.0.0/24" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">Gateway IP <FieldHint text={mikrotikFieldHints.gatewayIp} /></label><input className="form-control" value={setupMikrotikRow.hotspot_gateway_ip || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_gateway_ip: e.target.value })} placeholder="10.30.0.1" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">Pool Start IP <FieldHint text={mikrotikFieldHints.poolStart} /></label><input className="form-control" value={setupMikrotikRow.hotspot_pool_start_ip || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_pool_start_ip: e.target.value })} placeholder="10.30.0.10" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">Pool End IP <FieldHint text={mikrotikFieldHints.poolEnd} /></label><input className="form-control" value={setupMikrotikRow.hotspot_pool_end_ip || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_pool_end_ip: e.target.value })} placeholder="10.30.0.254" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">Pool Name <FieldHint text={mikrotikFieldHints.poolName} /></label><input className="form-control" value={setupMikrotikRow.hotspot_pool_name || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_pool_name: e.target.value })} placeholder="auto: system-name-pool" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">DHCP Server Name <FieldHint text={mikrotikFieldHints.dhcpServerName} /></label><input className="form-control" value={setupMikrotikRow.hotspot_dhcp_server_name || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_dhcp_server_name: e.target.value })} placeholder="auto: system-name-dhcp" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">Lease Time <FieldHint text={mikrotikFieldHints.leaseTime} /></label><input className="form-control" value={setupMikrotikRow.hotspot_dhcp_lease_time || '1h'} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_dhcp_lease_time: e.target.value })} placeholder="1h" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">DNS Servers <FieldHint text={mikrotikFieldHints.dnsServers} /></label><input className="form-control" value={setupMikrotikRow.hotspot_dns_servers || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_dns_servers: e.target.value })} placeholder="1.1.1.1,8.8.8.8" /></div>
	                                <div className="col-md-3"><label className="form-label small d-flex align-items-center gap-1">HotSpot DNS Name <FieldHint text={mikrotikFieldHints.hotspotDnsName} /></label><input className="form-control" value={setupMikrotikRow.hotspot_dns_name || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_dns_name: e.target.value })} placeholder="wifi.3j.3jportal.test" /></div>
	                                <div className="col-md-3">
	                                  <label className="form-label small d-flex align-items-center gap-1">WAN/Internet Interface <FieldHint text={mikrotikFieldHints.wanInterface} /></label>
	                                  <select className="form-select" value={setupMikrotikRow.hotspot_wan_interface || ''} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_wan_interface: e.target.value })}>
	                                    <option value="">Choose if NAT is enabled</option>
	                                    {setupMikrotikRow.hotspot_wan_interface && !setupInterfaces.some((iface) => iface.name === setupMikrotikRow.hotspot_wan_interface) && <option value={setupMikrotikRow.hotspot_wan_interface}>{setupMikrotikRow.hotspot_wan_interface}</option>}
	                                    {setupInterfaces.map((iface) => <option value={iface.name} key={`wan-${iface.name}`}>{iface.name}{iface.type ? ` (${iface.type})` : ''}{iface.disabled ? ' - disabled' : ''}{iface.running ? ' - running' : ''}</option>)}
	                                  </select>
	                                </div>
	                                <div className="col-md-3 d-flex align-items-end"><label className="form-check mb-2"><input className="form-check-input" type="checkbox" checked={Boolean(setupMikrotikRow.hotspot_enable_nat)} onChange={(e) => updateMikrotikRow(setupMikrotikRow.id, { hotspot_enable_nat: e.target.checked })} /><span className="form-check-label d-inline-flex align-items-center gap-1">Create NAT masquerade <FieldHint text={mikrotikFieldHints.nat} /></span></label></div>
	                              </div>
	                              <div className="d-flex justify-content-end mt-3">
	                                <button className="btn btn-primary btn-sm" type="button" onClick={saveMikrotikSetupFields}>
	                                  <IconDeviceFloppy size={15} className="me-1" />Save Fields and Refresh Commands
	                                </button>
	                              </div>
	                            </div>
	                          )}
	                          {item.key === 'prepare_hotspot_profile' && item.status === 'needs_required_fields' ? (
	                            <div className="text-muted small">
	                              Complete the fields above, then click <strong>Save Fields and Refresh Commands</strong> to generate the exact RouterOS configuration for this step.
	                            </div>
	                          ) : (
	                            <div className="row g-3">
	                              {(item.commands || []).map((command, commandIndex) => (
	                                <div className="col-12" key={`${item.key || item.step}-command-${commandIndex}`}>
	                                  <div className="border rounded p-2 bg-light">
	                                    <div className="fw-semibold small mb-1">{command.label || `Command ${commandIndex + 1}`}</div>
	                                    <pre className="mb-0 small"><code>{command.preview || command.path || 'No RouterOS command preview available yet.'}</code></pre>
	                                  </div>
	                                </div>
	                              ))}
	                              {!(item.commands || []).length && <div className="col-12 text-muted">No RouterOS commands are available for this step yet.</div>}
	                            </div>
	                          )}
	                          <div className="d-flex align-items-center justify-content-between gap-3 mt-3">
	                            <button className="btn btn-outline-secondary btn-sm" type="button" onClick={previousMikrotikStep} disabled={currentMikrotikStepIndex <= 0}>
	                              <IconChevronLeft size={15} className="me-1" />Previous
	                            </button>
	                            <div className="text-muted small text-center">
	                              {item.is_applied ? 'This step is complete. Next will move to the next step.' : item.apply_supported ? 'Next will show a warning and the exact RouterOS commands before applying this step.' : (item.apply_label || 'This step is a placeholder for a later phase.')}
	                            </div>
	                            <button className="btn btn-primary btn-sm" type="button" onClick={nextMikrotikStep} disabled={(!item.is_applied && !item.apply_supported) || mikrotikApplyingStep === item.key}>
	                              {mikrotikApplyingStep === item.key ? 'Applying...' : currentMikrotikStepIndex >= mikrotikActions.length - 1 && item.is_applied ? 'Complete' : 'Next'}<IconPlayerPlay size={15} className="ms-1" />
	                            </button>
	                          </div>
	                        </div>
	                      </details>
	                    ))}
	                  </div>
	                </div>}
                {false && mikrotikStepReview && (
                  <Modal title={`Review Step ${mikrotikStepReview.item.step_number || mikrotikStepReview.index + 1}: ${mikrotikStepReview.item.step}`} onClose={() => mikrotikApplyingStep ? null : setMikrotikStepReview(null)}>
                    <div className="alert alert-danger">
                      <div className="fw-semibold mb-1">Review before applying</div>
                      <div>Clicking <strong>Apply and Next</strong> will immediately send the RouterOS configuration below to MikroTik. Confirm the interface names, VLAN, IP range, gateway, DNS, and comments are correct before continuing.</div>
                    </div>
                    <div className="mb-3">
                      <div className="fw-semibold mb-1">{mikrotikStepReview.item.step}</div>
                      <div className="text-muted small">{mikrotikStepReview.item.details}</div>
                    </div>
                    <div className="row g-3">
                      {(mikrotikStepReview.item.commands || []).map((command, commandIndex) => (
                        <div className="col-12" key={`modal-mikrotik-command-${commandIndex}`}>
                          <div className="border rounded p-2 bg-light">
                            <div className="fw-semibold small mb-1">{command.label || `Command ${commandIndex + 1}`}</div>
                            <pre className="mb-0 small"><code>{command.preview || command.path || 'No RouterOS command preview available yet.'}</code></pre>
                          </div>
                        </div>
                      ))}
                      {!(mikrotikStepReview.item.commands || []).length && <div className="col-12 text-muted">No RouterOS commands are available for this step.</div>}
                    </div>
                    <div className="modal-footer px-0 pb-0">
                      <button type="button" className="btn" onClick={() => setMikrotikStepReview(null)} disabled={!!mikrotikApplyingStep}>Cancel</button>
                      <button type="button" className="btn btn-danger" disabled={mikrotikApplyingStep === mikrotikStepReview.item.key} onClick={() => applyMikrotikConfigurationStep(mikrotikStepReview.item.key, { advance: true })}>
                        <IconDeviceFloppy size={18} className="me-2" />{mikrotikApplyingStep === mikrotikStepReview.item.key ? 'Applying...' : 'Apply and Next'}
                      </button>
                    </div>
                  </Modal>
                )}
                {false && !mikrotikPlan && actionResult && <div className={`alert mt-3 mb-0 ${actionResult.status === 'REACHABLE' || actionResult.status === 'SUCCESS' ? 'alert-success' : actionResult.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>{actionResult.message || actionResult.status}</div>}
                {apManagementModalOpen && (
                  <Modal title="HTML and AP Management Setup" size="xl" onClose={() => apManagementSaving ? null : setApManagementModalOpen(false)}>
                    <form onSubmit={saveApManagement}>
                      <div className="alert alert-info">
                        <div className="fw-semibold mb-1">Central AP management plan only</div>
                        <div>This saves the AP management VLAN/subnet and router path. It does not configure MikroTik until you use Push AP Management Config.</div>
                      </div>
                      {apManagementError && <div className="alert alert-danger">{apManagementError}</div>}
                      <div className="row g-3">
                        <div className="col-md-4">
                          <StationLabel hint="Friendly name for this central AP management setup.">Config Name</StationLabel>
                          <input className="form-control" value={apManagementForm.config_name} onChange={(e) => updateApManagementField('config_name', e.target.value)} required />
                        </div>
                        <div className="col-md-2">
                          <StationLabel hint="One centralized VLAN tag used only for AP/Omada management traffic.">AP Mgmt VLAN</StationLabel>
                          <input className="form-control" type="number" min="1" max="4094" value={apManagementForm.vlan_id} onChange={(e) => updateApManagementVlan(e.target.value)} required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="RouterOS VLAN interface name created on the root gateway and monitoring interfaces on trunk routers.">VLAN Interface Name</StationLabel>
                          <input className="form-control" value={apManagementForm.vlan_interface_name} onChange={(e) => updateApManagementField('vlan_interface_name', e.target.value)} required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="Central subnet used by APs for management IP addresses.">AP Mgmt Subnet</StationLabel>
                          <input className="form-control" value={apManagementForm.network_cidr} onChange={(e) => updateApManagementCidr(e.target.value)} placeholder="10.111.0.0/24" required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="Root MikroTik IP address inside the AP management subnet.">Gateway IP</StationLabel>
                          <input className="form-control" value={apManagementForm.gateway_ip} onChange={(e) => updateApManagementField('gateway_ip', e.target.value)} required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="First DHCP IP that APs can receive. Leave room for static AP/router addresses.">Pool Start</StationLabel>
                          <input className="form-control" value={apManagementForm.pool_start_ip} onChange={(e) => updateApManagementField('pool_start_ip', e.target.value)} required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="Last DHCP IP that APs can receive.">Pool End</StationLabel>
                          <input className="form-control" value={apManagementForm.pool_end_ip} onChange={(e) => updateApManagementField('pool_end_ip', e.target.value)} required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="RouterOS IP pool name for AP management leases.">Pool Name</StationLabel>
                          <input className="form-control" value={apManagementForm.pool_name} onChange={(e) => updateApManagementField('pool_name', e.target.value)} required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="RouterOS DHCP server name. This is created only on the root gateway.">DHCP Server Name</StationLabel>
                          <input className="form-control" value={apManagementForm.dhcp_server_name} onChange={(e) => updateApManagementField('dhcp_server_name', e.target.value)} required />
                        </div>
                        <div className="col-md-2">
                          <StationLabel hint="DHCP lease time for AP management addresses.">Lease Time</StationLabel>
                          <input className="form-control" value={apManagementForm.dhcp_lease_time} onChange={(e) => updateApManagementField('dhcp_lease_time', e.target.value)} placeholder="1h" />
                        </div>
                        <div className="col-md-4">
                          <StationLabel hint="Upstream DNS servers the root MikroTik uses for AP management clients.">DNS Servers</StationLabel>
                          <input className="form-control" value={apManagementForm.dns_servers} onChange={(e) => updateApManagementField('dns_servers', e.target.value)} placeholder="8.8.8.8,1.1.1.1" />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint="RouterOS interface list where the AP management VLAN interface is added on the root gateway.">Local Interface List</StationLabel>
                          {(() => {
                            const root = apManagementForm.routers[0];
                            const routerOptions = root?.router_id ? (mikrotikOptions[root.router_id] || {}) : {};
                            const lists = routerOptions.interface_lists || [];
                            return (
                              <select className="form-select" value={apManagementForm.local_interface_list} onChange={(e) => updateApManagementField('local_interface_list', e.target.value)} disabled={!root?.router_id}>
                                <option value="">{root?.router_id ? 'Choose detected interface list' : 'Choose root router first'}</option>
                                {apManagementForm.local_interface_list && !lists.some((item) => item.name === apManagementForm.local_interface_list) && <option value={apManagementForm.local_interface_list}>{apManagementForm.local_interface_list} (current/default)</option>}
                                {lists.map((item) => <option value={item.name} key={`ap-mgmt-interface-list-${item.name}`}>{item.name}{item.comment ? ` - ${item.comment}` : ''}</option>)}
                              </select>
                            );
                          })()}
                        </div>
                      </div>
                      <div className="border rounded p-3 mt-3">
                        <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                          <div>
                            <div className="fw-semibold">Router Chain</div>
                            <div className="text-muted small">Add the root gateway first, then CRS/switch/transport routers in the order the AP management VLAN travels toward OLTs and APs.</div>
                          </div>
                          <button className="btn btn-outline-primary btn-sm" type="button" onClick={addApManagementRouter}>
                            <IconRouter size={16} className="me-1" />Add Router
                          </button>
                        </div>
                        {apManagementForm.routers.length ? (
                          <div className="station-chain-editor">
                            <div className="station-chain-tabs">
                              {apManagementForm.routers.map((row, index) => (
                                <button
                                  className={`station-chain-tab ${apManagementActiveRouterIndex === index ? 'active' : ''}`}
                                  type="button"
                                  draggable
                                  onClick={() => {
                                    setApManagementActiveRouterIndex(index);
                                    if (row.router_id && !mikrotikOptions[row.router_id]) loadMikrotikRouterOptions(row.router_id);
                                  }}
                                  onDragStart={() => setApManagementDragIndex(index)}
                                  onDragOver={(e) => e.preventDefault()}
                                  onDrop={() => {
                                    if (apManagementDragIndex !== null) moveApManagementRouter(apManagementDragIndex, index);
                                    setApManagementDragIndex(null);
                                  }}
                                  key={`ap-management-router-tab-${index}`}
                                >
                                  <span className={`station-chain-node ${index === 0 ? 'root' : ''}`}><IconRouter size={18} /></span>
                                  <span className="station-chain-tab-text">
                                    <span className="fw-semibold">{apManagementRouterDisplay(row, index)}</span>
                                    <span className="text-muted small">{index === 0 ? 'Root gateway' : `Hop ${index + 1}`}</span>
                                  </span>
                                  <span className="station-chain-drag-indicator" title="Drag to reorder">::</span>
                                </button>
                              ))}
                            </div>
                            {(() => {
                              const activeIndex = Math.min(apManagementActiveRouterIndex, apManagementForm.routers.length - 1);
                              const row = apManagementForm.routers[activeIndex];
                              const routerOptions = row?.router_id ? (mikrotikOptions[row.router_id] || {}) : {};
                              const routerInterfaces = routerOptions.interfaces || [];
                              const safeInterfaces = routerInterfaces.filter((iface) => !isPppoeInterface(iface));
                              const selectedTaggedPorts = String(row?.tagged_ports || '').split(',').map((item) => item.trim()).filter(Boolean);
                              const selectedTaggedPortSet = new Set(selectedTaggedPorts);
                              const portSearchKey = row?.router_id || `ap-management-index-${activeIndex}`;
                              const portSearchText = apManagementPortSearch[portSearchKey] || '';
                              const visibleTaggedInterfaces = safeInterfaces.filter((iface) => {
                                const haystack = [iface.name, iface.type, iface.bridge, iface.comment].map((value) => String(value || '').toLowerCase()).join(' ');
                                return !portSearchText.trim() || haystack.includes(portSearchText.trim().toLowerCase());
                              });
                              return (
                                <div className="station-router-panel">
                                  <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                                    <div>
                                      <div className="fw-semibold">{activeIndex === 0 ? 'Root Gateway AP Management Setup' : `AP Management Trunk Setup - Hop ${activeIndex + 1}`}</div>
                                      <div className="text-muted small">
                                        {activeIndex === 0
                                          ? 'This router creates the AP management VLAN interface, gateway IP, DHCP pool/server, and tagged trunk.'
                                          : 'This router carries the same AP management VLAN through its bridge/tagged ports toward OLTs and APs.'}
                                      </div>
                                    </div>
                                    <button className="btn btn-outline-danger btn-sm" type="button" onClick={() => removeApManagementRouter(activeIndex)}>
                                      <IconTrash size={15} className="me-1" />Remove Router
                                    </button>
                                  </div>
                                  <div className="row g-3">
                                    <div className="col-md-5">
                                      <StationLabel hint="Select one of the MikroTik routers already saved in the system.">Router</StationLabel>
                                      <select
                                        className="form-select"
                                        value={row.router_id}
                                        onChange={(e) => {
                                          updateApManagementRouter(activeIndex, { router_id: e.target.value, bridge_name: '', tagged_ports: '' });
                                          if (e.target.value) loadMikrotikRouterOptions(e.target.value);
                                        }}
                                        required
                                      >
                                        <option value="">Choose router</option>
                                        {mikrotiks.map((router) => <option value={router.id} key={`ap-management-router-${router.id}`}>{router.router_name} · {router.host}</option>)}
                                      </select>
                                    </div>
                                    <div className="col-md-5">
                                      <StationLabel hint="Bridge/interface where AP management VLAN traffic is carried. PPPoE interfaces are hidden.">Bridge / Interface</StationLabel>
                                      <select className="form-select" value={row.bridge_name} onChange={(e) => updateApManagementRouter(activeIndex, { bridge_name: e.target.value })} disabled={!row.router_id} required>
                                        <option value="">{row.router_id ? 'Choose detected bridge/interface' : 'Choose router first'}</option>
                                        {safeInterfaces.map((iface) => <option value={iface.name} key={`ap-management-bridge-${activeIndex}-${iface.name}`}>{interfaceOptionLabel(iface)}</option>)}
                                      </select>
                                    </div>
                                    <div className="col-md-2 d-flex align-items-end">
                                      <button className="btn btn-outline-primary w-100" type="button" onClick={() => row.router_id && loadMikrotikRouterOptions(row.router_id)} disabled={!row.router_id}>
                                        <IconSearch size={15} className="me-1" />Detect Ports
                                      </button>
                                    </div>
                                    <div className="col-12">
                                      <StationLabel hint="Check every detected RouterOS interface that should carry the centralized AP management VLAN on this router.">Tagged Ports</StationLabel>
                                      <div className="input-icon mb-2">
                                        <span className="input-icon-addon"><IconSearch size={16} /></span>
                                        <input
                                          className="form-control"
                                          value={portSearchText}
                                          onChange={(e) => setApManagementPortSearch((current) => ({ ...current, [portSearchKey]: e.target.value }))}
                                          placeholder="Search tagged ports"
                                          disabled={!row.router_id}
                                        />
                                        {portSearchText && (
                                          <button className="btn btn-icon input-icon-addon end-0" type="button" onClick={() => setApManagementPortSearch((current) => ({ ...current, [portSearchKey]: '' }))} title="Clear search">
                                            <IconX size={14} />
                                          </button>
                                        )}
                                      </div>
                                      <div className="station-port-checkbox-grid">
                                        {visibleTaggedInterfaces.map((iface) => (
                                          <label className="form-check station-port-check" key={`ap-management-port-${activeIndex}-${iface.name}`}>
                                            <input
                                              className="form-check-input"
                                              type="checkbox"
                                              checked={selectedTaggedPortSet.has(iface.name)}
                                              onChange={(e) => toggleApManagementTaggedPort(activeIndex, iface.name, e.target.checked)}
                                            />
                                            <span className="form-check-label">
                                              <span className="fw-semibold">{iface.name}</span>
                                              <span className="text-muted small">{iface.type || 'interface'}{iface.bridge ? ` · ${iface.bridge}` : ''}</span>
                                            </span>
                                          </label>
                                        ))}
                                        {!visibleTaggedInterfaces.length && <div className="text-muted small">No detected non-PPPoE interfaces match this search.</div>}
                                      </div>
                                      {!!selectedTaggedPorts.length && (
                                        <div className="d-flex flex-wrap gap-1 mt-2">
                                          {selectedTaggedPorts.map((port) => (
                                            <span className="badge bg-blue-lt text-blue station-selected-port-badge" key={`ap-management-selected-port-${activeIndex}-${port}`}>
                                              <span>{port}</span>
                                              <button className="station-selected-port-remove" type="button" onClick={() => toggleApManagementTaggedPort(activeIndex, port, false)} title={`Remove ${port}`} aria-label={`Remove ${port}`}>
                                                <IconX size={12} />
                                              </button>
                                            </span>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                        ) : (
                          <div className="empty py-4">
                            <div className="empty-icon"><IconRouter size={32} /></div>
                            <p className="empty-title">Add the root AP management router</p>
                            <p className="empty-subtitle text-muted">Start with the root gateway, then add CRS/transport routers in the same order AP management VLAN traffic travels toward OLTs/APs.</p>
                            <button className="btn btn-primary" type="button" onClick={addApManagementRouter}><IconRouter size={18} className="me-2" />Add Router</button>
                          </div>
                        )}
                      </div>
                      <div className="modal-footer px-0 pb-0">
                        <button type="button" className="btn" onClick={() => setApManagementModalOpen(false)} disabled={apManagementSaving}>Close</button>
                        <button type="submit" className="btn btn-primary" disabled={apManagementSaving}>
                          <IconDeviceFloppy size={18} className="me-2" />{apManagementSaving ? 'Saving...' : 'Save AP Management Plan'}
                        </button>
                      </div>
                    </form>
                  </Modal>
                )}
                {apManagementImplementation && (
                  <Modal title={`Push AP Management Config: ${apManagementImplementation.config_name}`} size="xl" onClose={() => { if (!apManagementImplementing) { apManagementPushCompleted ? closeApManagementPushSuccess() : setApManagementImplementation(null); } }}>
                    <div className="alert alert-danger">
                      <div className="fw-semibold mb-1">RouterOS write action</div>
                      <div>Review every AP management command below before starting. When you click Start Push, the system sends these commands to the listed MikroTik routers one at a time and stops on the first error.</div>
                    </div>
                    <div className="row g-3 mb-3">
                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">AP Management VLAN</div><div className="h3 mb-0">VLAN {apManagementImplementation.vlan_id}</div></div></div>
                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Management Network</div><div className="h4 mb-0">{apManagementImplementation.network_cidr}</div></div></div>
                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Gateway</div><div className="h4 mb-0">{apManagementImplementation.gateway_ip}</div></div></div>
                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Routers</div><div className="h3 mb-0">{(apManagementImplementation.routers || []).length}</div></div></div>
                    </div>
                    {(() => {
                      const totalSteps = apManagementImplementationSteps.length || apManagementStepList(apManagementImplementation).length;
                      const completedSteps = apManagementImplementationSteps.filter((item) => ['SUCCESS', 'SKIPPED', 'FAILED'].includes(item.status)).length;
                      const successSteps = apManagementImplementationSteps.filter((item) => ['SUCCESS', 'SKIPPED'].includes(item.status)).length;
                      const failedSteps = apManagementImplementationSteps.filter((item) => item.status === 'FAILED').length;
                      const progressPct = totalSteps ? Math.round((completedSteps / totalSteps) * 100) : 0;
                      return (
                        <div className="border rounded p-3 mb-3">
                          <div className="d-flex align-items-center justify-content-between gap-3 mb-2">
                            <div>
                              <div className="fw-semibold">Push progress</div>
                              <div className="text-muted small">{successSteps}/{totalSteps} successful or already existing{failedSteps ? ` · ${failedSteps} failed` : ''}</div>
                            </div>
                            <span className={`badge ${failedSteps ? 'bg-red-lt text-red' : completedSteps === totalSteps && totalSteps ? 'bg-green-lt text-green' : apManagementImplementing ? 'bg-blue-lt text-blue' : 'bg-secondary-lt text-secondary'}`}>
                              {apManagementImplementing ? 'Running' : failedSteps ? 'Stopped' : completedSteps === totalSteps && totalSteps ? 'Complete' : 'Ready'}
                            </span>
                          </div>
                          <div className="progress"><div className={`progress-bar ${failedSteps ? 'bg-danger' : 'bg-primary'}`} style={{ width: `${progressPct}%` }} /></div>
                        </div>
                      );
                    })()}
                    {apManagementImplementationMessage && <div className={`alert ${apManagementPushCompleted ? 'alert-success' : 'alert-info'} py-2`}>{apManagementImplementationMessage}</div>}
                    {apManagementPushCompleted && (
                      <div className="text-center border rounded p-4 mb-3">
                        <IconCircleCheck size={54} className="text-success mb-2" />
                        <div className="h3 mb-1">AP management config pushed</div>
                        <div className="text-muted">The modal will close automatically unless you keep reviewing the command results.</div>
                      </div>
                    )}
                    <div className="station-command-list mb-3">
                      {apManagementImplementationSteps.map((step, index) => (
                        <div
                          className={`station-command-step ${step.status === 'SUCCESS' || step.status === 'SKIPPED' ? 'is-success' : step.status === 'FAILED' ? 'is-failed' : step.status === 'RUNNING' ? 'is-running' : ''}`}
                          key={step.id}
                          ref={(node) => { apManagementStepRefs.current[step.id] = node; }}
                        >
                          <div className="station-command-step-icon">{stationImplementationStatusIcon(step.status)}</div>
                          <div className="station-command-step-body">
                            <div className="d-flex align-items-start justify-content-between gap-3">
                              <div>
                                <div className="fw-semibold">{index + 1}. {step.label}</div>
                                <div className="text-muted small">{step.router_name || 'Router'} · {step.router_role || 'Router'}{step.detected ? ' · already detected' : ''}</div>
                              </div>
                              <span className={`badge ${step.status === 'SUCCESS' || step.status === 'SKIPPED' ? 'bg-green-lt text-green' : step.status === 'FAILED' ? 'bg-red-lt text-red' : step.status === 'RUNNING' ? 'bg-blue-lt text-blue' : 'bg-secondary-lt text-secondary'}`}>{step.status}</span>
                            </div>
                            {step.message && <div className="small mt-1">{step.message}</div>}
                            <pre className="mt-2 mb-0 small"><code>{step.preview || 'No command preview available.'}</code></pre>
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="modal-footer px-0 pb-0">
                      <button type="button" className="btn" onClick={() => apManagementPushCompleted ? closeApManagementPushSuccess() : setApManagementImplementation(null)} disabled={apManagementImplementing}>
                        {apManagementPushCompleted ? `Close (${apManagementPushCloseCountdown}s)` : 'Close'}
                      </button>
                      <button type="button" className="btn btn-primary" onClick={runApManagementImplementation} disabled={apManagementImplementing || apManagementPushCompleted}>
                        <IconCloudUpload size={18} className="me-2" />{apManagementImplementing ? 'Pushing...' : 'Start Push'}
                      </button>
                    </div>
                  </Modal>
                )}
                {stationModalOpen && (
                  <Modal title={stationEditingId ? 'Edit MikroTik Station' : 'Add MikroTik Station'} size="xl" onClose={() => stationSaving ? null : setStationModalOpen(false)}>
                    <form onSubmit={saveStation}>
	                      <div className="alert alert-info">
	                        <div className="fw-semibold mb-1">Station plan only</div>
	                        <div>This does not configure MikroTik yet. It saves the root-to-downstream router chain and generates the same pattern as your tested VLAN 77 setup for customer HotSpot traffic. Central AP management is handled from HTML and AP Management.</div>
	                      </div>
	                      {stationError && <div className="alert alert-danger">{stationError}</div>}
	                      <div className="station-process-steps mb-3">
                        {stationStepItems.map((step) => (
                          <div className={`station-process-step ${step.ready ? 'ready' : ''}`} key={`station-step-${step.label}`}>
                            <span className="station-process-step-icon">{step.ready ? <IconCircleCheck size={18} /> : <IconClock size={18} />}</span>
                            <span>
                              <strong>{step.label}</strong>
                              <small>{step.detail}</small>
                            </span>
                          </div>
                        ))}
                      </div>
                      <div className="row g-3 mb-3">
                        <div className="col-md-5">
                          <StationLabel hint={stationFieldHints.stationName}>Station Name</StationLabel>
                          <input className="form-control" value={stationForm.station_name} onChange={(e) => updateStationField('station_name', e.target.value)} placeholder="CCR2116-Roma/Batu/GK" required />
                        </div>
                        <div className="col-md-3">
                          <StationLabel hint={stationFieldHints.stationCode}>Station Code</StationLabel>
                          <input className="form-control" value={stationForm.station_code} onChange={(e) => updateStationField('station_code', e.target.value)} placeholder="roma-batu-gk" required />
                        </div>
                        <div className="col-md-4">
                          <StationLabel hint={stationFieldHints.stationDescription}>Description</StationLabel>
                          <input className="form-control" value={stationForm.description} onChange={(e) => updateStationField('description', e.target.value)} placeholder="Root router to CRS/OLT/AP captive portal VLAN path" />
                        </div>
                      </div>
                      <div className="border rounded p-3">
                        <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                          <div>
                            <div className="fw-semibold d-flex align-items-center gap-1">Router Chain <FieldHint text={stationFieldHints.routerChain} /></div>
                            <div className="text-muted small">Add routers in the same order as the network path. The first router is the root gateway; each next router carries the VLAN downstream.</div>
                          </div>
                          <button className="btn btn-outline-primary btn-sm" type="button" onClick={addStationRouter}>
                            <IconRouter size={15} className="me-1" />Add Router to Chain
                          </button>
                        </div>
                        {stationForm.routers.length ? (
                          <div className="station-chain-builder">
                            <div className="station-chain-sidebar">
                              <div className="station-chain-flow-line"><span /></div>
                              {stationForm.routers.map((row, index) => (
                                <button
                                  className={`station-chain-tab ${stationActiveRouterIndex === index ? 'active' : ''}`}
                                  type="button"
                                  draggable
                                  onClick={() => {
                                    setStationActiveRouterIndex(index);
                                    if (row.router_id && !mikrotikOptions[row.router_id]) loadMikrotikRouterOptions(row.router_id);
                                  }}
                                  onDragStart={() => setStationDragIndex(index)}
                                  onDragOver={(e) => e.preventDefault()}
                                  onDrop={() => {
                                    if (stationDragIndex !== null) moveStationRouter(stationDragIndex, index);
                                    setStationDragIndex(null);
                                  }}
                                  key={`station-router-tab-${index}`}
                                >
                                  <span className={`station-chain-node ${index === 0 ? 'root' : ''}`}><IconRouter size={18} /></span>
                                  <span className="station-chain-tab-text">
                                    <span className="fw-semibold">{stationRouterDisplay(row, index)}</span>
                                    <span className="text-muted small">{index === 0 ? 'Root gateway' : `Hop ${index + 1}`}</span>
                                  </span>
                                  <span className="station-chain-drag-indicator" title="Drag to reorder">::</span>
                                </button>
                              ))}
                            </div>
                            {(() => {
                              const activeIndex = Math.min(stationActiveRouterIndex, stationForm.routers.length - 1);
                              const row = stationForm.routers[activeIndex];
                              const routerOptions = row?.router_id ? (mikrotikOptions[row.router_id] || {}) : {};
                              const routerInterfaces = routerOptions.interfaces || [];
                              const safeStationInterfaces = routerInterfaces.filter((iface) => !isPppoeInterface(iface));
                              const bridgeInterfaceChoices = safeStationInterfaces;
                              const routerInterfaceLists = routerOptions.interface_lists || [];
                              const selectedTaggedPorts = String(row?.tagged_ports || '').split(',').map((item) => item.trim()).filter(Boolean);
                              const selectedTaggedPortSet = new Set(selectedTaggedPorts);
                              const portSearchKey = row?.router_id || `index-${activeIndex}`;
                              const portSearchText = stationPortSearch[portSearchKey] || '';
                              const visibleTaggedInterfaces = safeStationInterfaces.filter((iface) => {
                                const haystack = [iface.name, iface.type, iface.bridge, iface.comment].map((value) => String(value || '').toLowerCase()).join(' ');
                                return !portSearchText.trim() || haystack.includes(portSearchText.trim().toLowerCase());
                              });
                              return (
                                <div className="station-router-panel">
                                  <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                                    <div>
                                      <div className="fw-semibold">{activeIndex === 0 ? 'Root Gateway Setup' : `Downstream Router Setup - Hop ${activeIndex + 1}`}</div>
                                      <div className="text-muted small">
                                        {activeIndex === 0
                                          ? 'This router creates the VLAN interface, gateway IP, DHCP pool, and first tagged trunk.'
                                          : 'This router carries the same customer VLAN through its bridge/tagged ports toward OLTs and APs.'}
                                      </div>
                                    </div>
                                    <div className="btn-list">
                                      <button className="btn btn-outline-primary btn-sm" type="button" onClick={() => loadMikrotikRouterOptions(row.router_id)} disabled={!row.router_id}>
                                        <IconRefresh size={15} className="me-1" />Detect Ports
                                      </button>
                                      <button className="btn btn-icon btn-outline-danger" type="button" title="Remove router" onClick={() => removeStationRouter(activeIndex)}><IconTrash size={16} /></button>
                                    </div>
                                  </div>
                                  <div className="row g-3">
                                    <div className="col-12">
                                      <div className="station-subpanel">
                                        <div className="station-subpanel-title">Step 3A: Select Router</div>
                                        <div className="row g-3">
                                          <div className="col-md-6">
                                            <StationLabel hint={stationFieldHints.mikrotikRouter}>MikroTik Router</StationLabel>
                                            <select className="form-select" value={row.router_id} onChange={(e) => {
                                              updateStationRouter(activeIndex, { router_id: e.target.value, bridge_name: '', tagged_ports: '' });
                                              loadMikrotikRouterOptions(e.target.value);
                                            }} required>
                                              <option value="">Choose router</option>
                                              {mikrotiks.map((router) => <option value={router.id} key={`station-router-option-${router.id}`}>{router.router_name} ({router.host})</option>)}
                                            </select>
                                            {routerOptions.error && <div className="text-danger small mt-1">{routerOptions.error}</div>}
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                    <div className="col-12">
                                      <div className="station-subpanel">
                                        <div className="station-subpanel-title">{activeIndex === 0 ? 'Step 3B: Select Root Bridge and Tagged Ports' : 'Step 3B: Select Bridge and Tagged Ports'}</div>
                                        <div className="row g-3">
                                          <div className="col-md-6">
                                            <StationLabel hint={activeIndex === 0 ? stationFieldHints.rootBridge : stationFieldHints.downstreamBridge}>{activeIndex === 0 ? 'Root Bridge / Interface' : 'Bridge'}</StationLabel>
                                            <select className="form-select" value={row.bridge_name} onChange={(e) => updateStationRouter(activeIndex, { bridge_name: e.target.value })} required disabled={!row.router_id}>
                                              <option value="">{row.router_id ? 'Choose detected bridge/interface' : 'Choose router first'}</option>
                                              {bridgeInterfaceChoices.map((iface) => <option value={iface.name} key={`station-bridge-${activeIndex}-${iface.name}`}>{iface.name}{iface.type ? ` (${iface.type})` : ''}{iface.bridge ? ` - in ${iface.bridge}` : ''}{iface.disabled ? ' - disabled' : ''}{iface.running ? ' - running' : ''}</option>)}
                                            </select>
                                            {!!(routerOptions.warnings || []).length && <div className="text-warning small mt-1">Some optional RouterOS option lists were unavailable, but interfaces loaded.</div>}
                                          </div>
                                          <div className="col-12">
                                            <StationLabel hint={activeIndex === 0 ? stationFieldHints.taggedPortsRoot : stationFieldHints.taggedPortsDownstream}>Tagged Ports</StationLabel>
                                            <div className="station-port-picker">
                                              <div className="input-group station-port-search-group">
                                                <input
                                                  className="form-control station-port-search"
                                                  value={portSearchText}
                                                  onChange={(e) => setStationPortSearch((current) => ({ ...current, [portSearchKey]: e.target.value }))}
                                                  placeholder="Search port, bridge, type, or comment"
                                                  disabled={!row.router_id}
                                                />
                                                <button
                                                  className="btn btn-outline-secondary station-port-search-clear"
                                                  type="button"
                                                  onClick={() => setStationPortSearch((current) => ({ ...current, [portSearchKey]: '' }))}
                                                  disabled={!row.router_id || !portSearchText}
                                                  title="Clear tagged port search"
                                                  aria-label="Clear tagged port search"
                                                >
                                                  <IconX size={15} />
                                                </button>
                                              </div>
                                              <div className="station-port-checkbox-list">
                                                {visibleTaggedInterfaces.map((iface) => (
                                                  <label className={`station-port-checkbox-item ${selectedTaggedPortSet.has(iface.name) ? 'selected' : ''}`} key={`station-tagged-${activeIndex}-${iface.name}`}>
                                                    <input
                                                      className="form-check-input"
                                                      type="checkbox"
                                                      checked={selectedTaggedPortSet.has(iface.name)}
                                                      onChange={(e) => toggleStationTaggedPort(activeIndex, iface.name, e.target.checked)}
                                                      disabled={!row.router_id}
                                                    />
                                                    <span className="station-port-checkbox-text">
                                                      <strong>{iface.name}</strong>
                                                      <small>
                                                        {[
                                                          iface.type,
                                                          iface.bridge ? `in ${iface.bridge}` : '',
                                                          iface.disabled ? 'disabled' : '',
                                                          iface.running ? 'running' : ''
                                                        ].filter(Boolean).join(' · ') || 'interface'}
                                                      </small>
                                                    </span>
                                                  </label>
                                                ))}
                                                {!visibleTaggedInterfaces.length && (
                                                  <div className="text-muted small p-3">
                                                    {row.router_id ? 'No matching non-PPPoE ports found.' : 'Choose a router first.'}
                                                  </div>
                                                )}
                                              </div>
                                            </div>
                                            <div className="text-muted small">Check every detected RouterOS interface that should carry VLAN {stationForm.vlan_id || 'x'} on this router. PPPoE interfaces are hidden.</div>
                                            {!!selectedTaggedPorts.length && (
                                              <div className="d-flex flex-wrap gap-1 mt-2">
                                                {selectedTaggedPorts.map((port) => (
                                                  <span className="badge bg-blue-lt text-blue station-selected-port-badge" key={`selected-port-${activeIndex}-${port}`}>
                                                    <span>{port}</span>
                                                    <button
                                                      className="station-selected-port-remove"
                                                      type="button"
                                                      onClick={() => toggleStationTaggedPort(activeIndex, port, false)}
                                                      title={`Remove ${port}`}
                                                      aria-label={`Remove ${port}`}
                                                    >
                                                      <IconX size={12} />
                                                    </button>
                                                  </span>
                                                ))}
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                    {activeIndex === 0 && (
                                      <div className="col-12">
                                        <div className="station-subpanel">
                                          <div className="station-subpanel-title">Step 3B: Root Gateway VLAN Networks</div>
                                          <div className="station-field-group">
                                            <div className="station-field-group-header">Customer HotSpot VLAN identity</div>
                                            <div className="row g-3">
                                              <div className="col-md-3">
                                                <StationLabel hint={stationFieldHints.vlanId}>Customer VLAN</StationLabel>
                                                <input className="form-control" type="number" min="1" max="4094" value={stationForm.vlan_id} onChange={(e) => updateStationVlan(e.target.value)} required />
                                              </div>
                                              <div className="col-md-5">
                                                <StationLabel hint={stationFieldHints.vlanInterfaceName}>VLAN Interface Name</StationLabel>
                                                <input className="form-control" value={stationForm.vlan_interface_name} onChange={(e) => updateStationField('vlan_interface_name', e.target.value)} placeholder="VLAN77-3J-HOTSPOT" />
                                              </div>
                                            </div>
                                          </div>
                                          <div className="station-field-group">
                                            <div className="station-field-group-header">Client IP and DHCP</div>
                                            <div className="row g-3">
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.clientNetwork}>Client Network CIDR</StationLabel>
                                                <input className="form-control" value={stationForm.client_network_cidr} onChange={(e) => updateStationField('client_network_cidr', e.target.value)} placeholder="10.77.0.0/24" required />
                                              </div>
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.gatewayIp}>Gateway IP</StationLabel>
                                                <input className="form-control" value={stationForm.gateway_ip} onChange={(e) => updateStationField('gateway_ip', e.target.value)} placeholder="10.77.0.1" required />
                                              </div>
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.poolName}>Pool Name</StationLabel>
                                                <input className="form-control" value={stationForm.pool_name} onChange={(e) => updateStationField('pool_name', e.target.value)} placeholder="POOL-3J-HOTSPOT-V77" />
                                              </div>
                                              <div className="col-md-6">
                                                <StationLabel hint={stationFieldHints.poolStart}>Pool Start</StationLabel>
                                                <input className="form-control" value={stationForm.pool_start_ip} onChange={(e) => updateStationField('pool_start_ip', e.target.value)} placeholder="10.77.0.2" required />
                                              </div>
                                              <div className="col-md-6">
                                                <StationLabel hint={stationFieldHints.poolEnd}>Pool End</StationLabel>
                                                <input className="form-control" value={stationForm.pool_end_ip} onChange={(e) => updateStationField('pool_end_ip', e.target.value)} placeholder="10.77.0.254" required />
                                              </div>
                                              <div className="col-md-4">
                                                <label className="form-check form-switch mt-4">
                                                  <input
                                                    className="form-check-input"
                                                    type="checkbox"
                                                    checked={stationForm.create_dhcp_server}
                                                    onChange={(e) => updateStationField('create_dhcp_server', e.target.checked)}
                                                  />
                                                  <span className="form-check-label d-inline-flex align-items-center gap-1">
                                                    Create DHCP server on root gateway
                                                    <FieldHint text={stationFieldHints.createDhcpServer} />
                                                  </span>
                                                </label>
                                              </div>
                                              {stationForm.create_dhcp_server && (
                                                <>
                                                  <div className="col-md-4">
                                                    <StationLabel hint={stationFieldHints.dhcpServerName}>DHCP Server Name</StationLabel>
                                                    <input className="form-control" value={stationForm.dhcp_server_name} onChange={(e) => updateStationField('dhcp_server_name', e.target.value)} placeholder="DHCP-3J-HOTSPOT-V77" required />
                                                  </div>
                                                  <div className="col-md-4">
                                                    <StationLabel hint={stationFieldHints.dhcpLeaseTime}>DHCP Lease Time</StationLabel>
                                                    <input className="form-control" value={stationForm.dhcp_lease_time} onChange={(e) => updateStationField('dhcp_lease_time', e.target.value)} placeholder="1h" />
                                                  </div>
                                                </>
                                              )}
                                              <div className="col-12">
                                                <div className="text-muted small">DHCP is created only on the first/root gateway. Downstream CRS/trunk routers only carry VLAN {stationForm.vlan_id || '-'}.</div>
                                              </div>
                                            </div>
                                          </div>
                                          <div className="station-field-group">
                                            <div className="station-field-group-header">Captive DNS and firewall-list context</div>
                                            <div className="row g-3">
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.localInterfaceList}>Local Interface List</StationLabel>
                                                <select className="form-select" value={stationForm.local_interface_list} onChange={(e) => updateStationField('local_interface_list', e.target.value)} disabled={!row.router_id}>
                                                  <option value="">{row.router_id ? 'Choose detected interface list' : 'Choose root router first'}</option>
                                                  {stationForm.local_interface_list && !routerInterfaceLists.some((item) => item.name === stationForm.local_interface_list) && <option value={stationForm.local_interface_list}>{stationForm.local_interface_list} (current/default)</option>}
                                                  {routerInterfaceLists.map((item) => <option value={item.name} key={`station-interface-list-${item.name}`}>{item.name}{item.comment ? ` - ${item.comment}` : ''}</option>)}
                                                </select>
                                                <div className="text-muted small">Loaded from RouterOS /interface/list/print on the root gateway.</div>
                                              </div>
                                              <div className="col-md-8">
                                                <StationLabel hint={stationFieldHints.dnsServers}>Router Upstream DNS</StationLabel>
                                                <input className="form-control" value={stationForm.dns_servers} onChange={(e) => updateStationField('dns_servers', e.target.value)} placeholder="8.8.8.8,1.1.1.1" />
                                                <div className="text-muted small">Phones on this HotSpot receive only {stationForm.gateway_ip || 'the gateway IP'} as DNS. MikroTik forwards DNS to these upstream servers.</div>
                                              </div>
                                            </div>
                                          </div>
                                          <div className="station-field-group mb-0">
                                            <div className="station-field-group-header">Root HotSpot and portal enforcement</div>
                                            <div className="row g-3">
                                              <div className="col-md-4">
                                                <label className="form-check form-switch">
                                                  <input
                                                    className="form-check-input"
                                                    type="checkbox"
                                                    checked={stationForm.create_hotspot_profile}
                                                    onChange={(e) => updateStationField('create_hotspot_profile', e.target.checked)}
                                                  />
                                                  <span className="form-check-label d-inline-flex align-items-center gap-1">
                                                    Create HotSpot profile
                                                    <FieldHint text={stationFieldHints.createHotspotProfile} />
                                                  </span>
                                                </label>
                                              </div>
                                              <div className="col-md-4">
                                                <label className="form-check form-switch">
                                                  <input
                                                    className="form-check-input"
                                                    type="checkbox"
                                                    checked={stationForm.create_hotspot_server}
                                                    onChange={(e) => updateStationField('create_hotspot_server', e.target.checked)}
                                                  />
                                                  <span className="form-check-label d-inline-flex align-items-center gap-1">
                                                    Create HotSpot server
                                                    <FieldHint text={stationFieldHints.createHotspotServer} />
                                                  </span>
                                                </label>
                                              </div>
                                              <div className="col-md-4">
                                                <label className="form-check form-switch">
                                                  <input
                                                    className="form-check-input"
                                                    type="checkbox"
                                                    checked={stationForm.create_walled_garden}
                                                    onChange={(e) => updateStationField('create_walled_garden', e.target.checked)}
                                                  />
                                                  <span className="form-check-label d-inline-flex align-items-center gap-1">
                                                    Allow portal before login
                                                    <FieldHint text={stationFieldHints.createWalledGarden} />
                                                  </span>
                                                </label>
                                              </div>
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.hotspotProfileName}>HotSpot Profile Name</StationLabel>
                                                <input className="form-control" value={stationForm.hotspot_profile_name} onChange={(e) => updateStationField('hotspot_profile_name', e.target.value)} placeholder="PROFILE-3J-HOTSPOT-V77" disabled={!stationForm.create_hotspot_profile && !stationForm.create_hotspot_server} required={stationForm.create_hotspot_profile || stationForm.create_hotspot_server} />
                                              </div>
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.hotspotDnsName}>HotSpot DNS Name</StationLabel>
                                                <input className="form-control" value={stationForm.hotspot_dns_name} onChange={(e) => updateStationField('hotspot_dns_name', e.target.value)} placeholder="wifi.3j.3jportal.test" disabled={!stationForm.create_hotspot_profile} />
                                              </div>
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.hotspotHtmlDirectory}>HotSpot HTML Directory</StationLabel>
                                                <input className="form-control" value={stationForm.hotspot_html_directory} onChange={(e) => updateStationField('hotspot_html_directory', e.target.value)} placeholder="hotspot" disabled={!stationForm.create_hotspot_profile} />
                                              </div>
                                              <div className="col-md-4">
                                                <StationLabel hint={stationFieldHints.hotspotServerName}>HotSpot Server Name</StationLabel>
                                                <input className="form-control" value={stationForm.hotspot_server_name} onChange={(e) => updateStationField('hotspot_server_name', e.target.value)} placeholder="HS-3J-HOTSPOT-V77" disabled={!stationForm.create_hotspot_server} required={stationForm.create_hotspot_server} />
                                              </div>
                                              <div className="col-md-8">
                                                <StationLabel hint={stationFieldHints.portalUrl}>Portal URL</StationLabel>
                                                <input className="form-control" value={stationForm.portal_url} onChange={(e) => updateStationField('portal_url', e.target.value)} placeholder="http://192.168.50.70:8080/portal" required />
                                              </div>
                                              <div className="col-12">
                                                <div className="text-muted small">HotSpot profile/server and walled garden rules are created only on the first/root gateway. This prepares MikroTik enforcement; voucher validation still stays in 3JCentralPisowifi.</div>
                                              </div>
                                            </div>
                                          </div>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                        ) : (
                          <div className="empty py-4">
                            <div className="empty-icon"><IconRouter size={32} /></div>
                            <p className="empty-title">Add the first router in the chain</p>
                            <p className="empty-subtitle text-muted">Start with the root gateway, for example CCR2116-Roma/Batu/GK. Then add CRS/transport routers in the order the VLAN travels toward OLTs and APs.</p>
                            <button className="btn btn-primary" type="button" onClick={addStationRouter}><IconRouter size={18} className="me-2" />Add Router to Chain</button>
                          </div>
                        )}
                      </div>
	                      <div className="border rounded p-3 mt-3 station-review-placeholder">
	                        <div className="fw-semibold mb-1">Step 4: Review Plan</div>
	                        <div className="text-muted small">Click Save & Review Station Plan to save this station and open the generated RouterOS preview in a separate review window. Saving still does not apply configuration to MikroTik.</div>
	                      </div>
                      <div className="modal-footer px-0 pb-0">
                        <button type="button" className="btn" onClick={() => setStationModalOpen(false)} disabled={stationSaving}>Close</button>
                        <button type="submit" className="btn btn-primary" disabled={stationSaving}>
                          <IconDeviceFloppy size={18} className="me-2" />{stationSaving ? 'Saving...' : stationEditingId ? 'Update & Review Station Plan' : 'Save & Review Station Plan'}
                        </button>
                      </div>
                    </form>
	                  </Modal>
	                )}
	                {stationReview && (
	                  <Modal title={`Review Station Plan: ${stationReview.station_name}`} size="xl" onClose={() => setStationReview(null)}>
	                    <div className="alert alert-warning">
	                      <div className="fw-semibold mb-1">Preview only</div>
	                      <div>This is the generated RouterOS plan for review. The managed HotSpot <code>login.html</code> is uploaded during implementation or from the sync action; no manual file upload is needed.</div>
	                    </div>
	                    <div className="row g-3 mb-3">
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">VLAN</div><div className="h3 mb-0">{stationReview.vlan_id}</div></div></div>
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Client Network</div><div className="h3 mb-0">{stationReview.client_network_cidr}</div></div></div>
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Gateway</div><div className="h3 mb-0">{stationReview.gateway_ip}</div></div></div>
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Status</div><div className="h3 mb-0">{stationReview.status}</div></div></div>
	                    </div>
	                    <div className="row g-3 mb-3">
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Station Code</div><div className="fw-semibold">{stationReview.station_code || '-'}</div></div></div>
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">HotSpot DNS</div><div className="fw-semibold">{stationReview.hotspot_dns_name || '-'}</div></div></div>
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">HotSpot Server</div><div className="fw-semibold">{stationReview.hotspot_server_name || '-'}</div></div></div>
	                      <div className="col-md-3"><div className="border rounded p-3 h-100"><div className="text-muted small">Portal URL</div><div className="fw-semibold text-truncate" title={stationReview.portal_url || ''}>{stationReview.portal_url || '-'}</div></div></div>
	                    </div>
	                    <div className="row g-3 mb-3">
	                      <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">Root DHCP Server</div><div className="fw-semibold">{stationReview.create_dhcp_server ? (stationReview.dhcp_server_name || '-') : 'Disabled'}</div></div></div>
	                      <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">DHCP Lease Time</div><div className="fw-semibold">{stationReview.create_dhcp_server ? (stationReview.dhcp_lease_time || '1h') : '-'}</div></div></div>
	                      <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">DHCP Ownership</div><div className="fw-semibold">Root gateway only</div></div></div>
	                    </div>
	                    <div className="row g-3 mb-3">
	                      <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">HotSpot Profile</div><div className="fw-semibold">{stationReview.create_hotspot_profile ? (stationReview.hotspot_profile_name || '-') : 'Disabled'}</div></div></div>
	                      <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">HotSpot Server</div><div className="fw-semibold">{stationReview.create_hotspot_server ? (stationReview.hotspot_server_name || '-') : 'Disabled'}</div></div></div>
	                      <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">Pre-login Portal/DNS</div><div className="fw-semibold">{stationReview.create_walled_garden ? 'Enabled' : 'Disabled'}</div></div></div>
	                    </div>
	                    <div className="text-muted small mb-3">{stationReview.plan?.summary || 'Root router creates the customer VLAN gateway/DHCP network. Downstream routers carry the same VLAN as a tagged trunk toward OLT/AP paths.'}</div>
	                    {(stationReview.plan?.router_plans || []).map((routerPlan) => (
	                      <details className="border rounded mb-2" key={`station-review-plan-${routerPlan.router_id}`} open>
	                        <summary className="p-2 fw-semibold">{routerPlan.router_name} · {routerPlan.role}</summary>
	                        <div className="border-top p-2">
	                          {(routerPlan.commands || []).map((command, commandIndex) => (
	                            <div className="border rounded p-2 bg-light mb-2" key={`station-review-command-${routerPlan.router_id}-${commandIndex}`}>
	                              <div className="fw-semibold small mb-1">{command.label}</div>
	                              <pre className="mb-0 small"><code>{command.preview}</code></pre>
	                            </div>
	                          ))}
	                          {!(routerPlan.commands || []).length && <div className="text-muted small">No RouterOS preview commands were generated for this router.</div>}
	                        </div>
	                      </details>
	                    ))}
	                    <div className="modal-footer px-0 pb-0">
	                      <button type="button" className="btn btn-outline-primary" onClick={() => syncHotspotLoginHtml(stationReview.id)} disabled={hotspotLoginSyncing}>
	                        <IconRefresh size={18} className="me-2" />{hotspotLoginSyncing ? 'Syncing...' : 'Sync HotSpot login.html'}
	                      </button>
	                      <button type="button" className="btn btn-primary" onClick={() => setStationReview(null)}>Close Review</button>
	                    </div>
	                  </Modal>
	                )}
                  {stationImplementation && (
                    <Modal title={`Push Config: ${stationImplementation.station_name}`} size="xl" onClose={() => { if (!stationImplementing) { stationPushCompleted ? closeStationPushSuccess() : setStationImplementation(null); } }}>
                      <div className="alert alert-danger">
                        <div className="fw-semibold mb-1">RouterOS write action</div>
                        <div>Review every command below before starting. When you click Start Push, the system sends these commands to the listed MikroTik routers one at a time, uploads the managed HotSpot login.html, and stops on the first error.</div>
                      </div>
                      <div className="row g-3 mb-3">
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Customer VLAN</div>
                            <div className="h3 mb-0">VLAN {stationImplementation.vlan_id}</div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Customer Network</div>
                            <div className="h4 mb-0">{stationImplementation.client_network_cidr}</div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Portal URL</div>
                            <div className="h4 mb-0 text-truncate" title={stationImplementation.portal_url || ''}>{stationImplementation.portal_url || '-'}</div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Routers</div>
                            <div className="h3 mb-0">{(stationImplementation.routers || []).length}</div>
                          </div>
                        </div>
                      </div>
                      {(() => {
                        const totalSteps = stationImplementationSteps.length || stationImplementationStepList(stationImplementation).length;
                        const completedSteps = stationImplementationSteps.filter((item) => ['SUCCESS', 'SKIPPED', 'FAILED'].includes(item.status)).length;
                        const successSteps = stationImplementationSteps.filter((item) => ['SUCCESS', 'SKIPPED'].includes(item.status)).length;
                        const failedSteps = stationImplementationSteps.filter((item) => item.status === 'FAILED').length;
                        const progressPct = totalSteps ? Math.round((completedSteps / totalSteps) * 100) : 0;
                        return (
                          <div className="border rounded p-3 mb-3">
                            <div className="d-flex align-items-center justify-content-between gap-3 mb-2">
                              <div>
                                <div className="fw-semibold">Push progress</div>
                                <div className="text-muted small">{successSteps}/{totalSteps} successful or already existing{failedSteps ? ` · ${failedSteps} failed` : ''}</div>
                              </div>
                              <span className={`badge ${failedSteps ? 'bg-red-lt text-red' : completedSteps === totalSteps && totalSteps ? 'bg-green-lt text-green' : stationImplementing ? 'bg-blue-lt text-blue' : 'bg-secondary-lt text-secondary'}`}>
                                {stationImplementing ? 'Running' : failedSteps ? 'Stopped' : completedSteps === totalSteps && totalSteps ? 'Complete' : 'Ready'}
                              </span>
                            </div>
                            <div className="progress">
                              <div className={`progress-bar ${failedSteps ? 'bg-danger' : 'bg-primary'}`} style={{ width: `${progressPct}%` }} />
                            </div>
                            {stationImplementationMessage && <div className="text-muted small mt-2">{stationImplementationMessage}</div>}
                          </div>
                        );
                      })()}
                      {stationPushCompleted ? (
                        <div className="station-push-success">
                          <div className="station-push-success-icon">
                            <IconCircleCheck size={56} />
                          </div>
                          <div>
                            <div className="h2 mb-2">Configuration pushed successfully</div>
                            <div className="text-muted">
                              All planned station configuration steps completed or were already detected on MikroTik. The managed HotSpot login.html sync step is also complete.
                            </div>
                          </div>
                          <button type="button" className="btn btn-success btn-lg" onClick={closeStationPushSuccess}>
                            Close ({stationPushCloseCountdown}s)
                          </button>
                        </div>
                      ) : (
                        <>
                      <div className="mb-3">
                        <div className="fw-semibold mb-2">Router path</div>
                        {renderStationChainPath(stationImplementation)}
                      </div>
                      <div className="station-implementation-list">
                        {(stationImplementationSteps.length ? stationImplementationSteps : stationImplementationStepList(stationImplementation)).map((step, stepIndex) => (
                          <div className={`station-implementation-step ${step.status?.toLowerCase() || 'pending'} ${step.detected ? 'detected' : ''}`} key={`${step.id}-${stepIndex}`} ref={(node) => { if (node) stationStepRefs.current[step.id] = node; }}>
                            <div className="station-implementation-step-header">
                              <span className="station-implementation-status-icon">{stationImplementationStatusIcon(step.status)}</span>
                              <div className="min-w-0">
                                <div className="fw-semibold">{stepIndex + 1}. {step.label}</div>
                                <div className="text-muted small">{step.router_name || 'Router'}{step.host ? ` · ${step.host}` : ''} · {step.router_role}</div>
                              </div>
                              <span className={`badge ms-auto ${step.status === 'SUCCESS' || step.status === 'SKIPPED' ? 'bg-green-lt text-green' : step.status === 'FAILED' ? 'bg-red-lt text-red' : step.status === 'RUNNING' ? 'bg-blue-lt text-blue' : 'bg-secondary-lt text-secondary'}`}>
                                {step.detected ? 'Already pushed' : step.status === 'SKIPPED' ? 'Already exists' : step.status}
                              </span>
                            </div>
                            <pre className="station-implementation-command mb-0"><code>{step.preview}</code></pre>
                            {step.message && <div className={`small mt-2 ${step.status === 'FAILED' ? 'text-danger' : 'text-muted'}`}>{step.message}</div>}
                          </div>
                        ))}
                      </div>
                      <div className="modal-footer px-0 pb-0">
                        <button type="button" className="btn" onClick={() => setStationImplementation(null)} disabled={stationImplementing}>Close</button>
                        <button
                          type="button"
                          className="btn btn-outline-primary"
                          disabled={stationImplementing}
                          onClick={() => {
                            setStationReview(stationImplementation);
                            setStationImplementation(null);
                          }}
                        >
                          <IconEye size={18} className="me-2" />Review Plan First
                        </button>
                        <button type="button" className="btn btn-danger" disabled={stationImplementing || !stationManagedStatus || stationCheckingManaged || !(stationImplementationSteps.length || stationImplementationStepList(stationImplementation).length)} onClick={runStationImplementation} title={!stationManagedStatus ? 'Checking existing config first.' : 'Start station config push'}>
                          <IconPlayerPlay size={18} className="me-2" />{stationImplementing ? 'Pushing...' : stationCheckingManaged && !stationManagedStatus ? 'Checking...' : 'Start Push'}
                        </button>
                      </div>
                      <div className="border-top pt-3 mt-3">
                        <div className="fw-semibold mb-2">Recent station history</div>
                        {renderStationCommandHistory()}
                      </div>
                        </>
                      )}
                    </Modal>
                  )}
                  {stationRemove && (
                    <Modal title={`Remove Config: ${stationRemove.station_name}`} size="xl" onClose={() => { if (!stationRemoving) { stationRemoveCompleted ? closeStationRemoveSuccess() : setStationRemove(null); } }}>
                      <div className="alert alert-danger">
                        <div className="fw-semibold mb-1">Remove station-created RouterOS config</div>
                        <div>This removes only objects matching this station plan by exact generated names/comments. Shared bridge VLAN rows are not deleted unless they carry the station-created comment.</div>
                      </div>
                      <div className="row g-3 mb-3">
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Customer VLAN</div>
                            <div className="h3 mb-0">VLAN {stationRemove.vlan_id}</div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Customer Network</div>
                            <div className="h4 mb-0">{stationRemove.client_network_cidr}</div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Portal URL</div>
                            <div className="h4 mb-0 text-truncate" title={stationRemove.portal_url || ''}>{stationRemove.portal_url || '-'}</div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Routers</div>
                            <div className="h3 mb-0">{(stationRemove.routers || []).length}</div>
                          </div>
                        </div>
                      </div>
                      {(() => {
                        const totalSteps = stationRemoveSteps.length || stationRemoveStepList(stationRemove).length;
                        const completedSteps = stationRemoveSteps.filter((item) => ['SUCCESS', 'SKIPPED', 'FAILED'].includes(item.status)).length;
                        const successSteps = stationRemoveSteps.filter((item) => ['SUCCESS', 'SKIPPED'].includes(item.status)).length;
                        const failedSteps = stationRemoveSteps.filter((item) => item.status === 'FAILED').length;
                        const progressPct = totalSteps ? Math.round((completedSteps / totalSteps) * 100) : 0;
                        return (
                          <div className="border rounded p-3 mb-3">
                            <div className="d-flex align-items-center justify-content-between gap-3 mb-2">
                              <div>
                                <div className="fw-semibold">Remove progress</div>
                                <div className="text-muted small">{successSteps}/{totalSteps} removed or not found{failedSteps ? ` · ${failedSteps} failed` : ''}</div>
                              </div>
                              <span className={`badge ${failedSteps ? 'bg-red-lt text-red' : completedSteps === totalSteps && totalSteps ? 'bg-green-lt text-green' : stationRemoving ? 'bg-blue-lt text-blue' : 'bg-secondary-lt text-secondary'}`}>
                                {stationRemoving ? 'Running' : failedSteps ? 'Stopped' : completedSteps === totalSteps && totalSteps ? 'Complete' : 'Ready'}
                              </span>
                            </div>
                            <div className="progress">
                              <div className={`progress-bar ${failedSteps ? 'bg-danger' : 'bg-primary'}`} style={{ width: `${progressPct}%` }} />
                            </div>
                            {stationRemoveMessage && <div className="text-muted small mt-2">{stationRemoveMessage}</div>}
                          </div>
                        );
                      })()}
                      {stationRemoveCompleted ? (
                        <div className="station-push-success">
                          <div className="station-push-success-icon">
                            <IconCircleCheck size={56} />
                          </div>
                          <div>
                            <div className="h2 mb-2">Configuration removed successfully</div>
                            <div className="text-muted">
                              The station-created RouterOS configuration steps completed or were already absent. Shared objects that did not match the station plan were left untouched.
                            </div>
                          </div>
                          <button type="button" className="btn btn-success btn-lg" onClick={closeStationRemoveSuccess}>
                            Close ({stationRemoveCloseCountdown}s)
                          </button>
                        </div>
                      ) : (
                        <>
                      <div className="station-implementation-list">
                        {(stationRemoveSteps.length ? stationRemoveSteps : stationRemoveStepList(stationRemove)).map((step, stepIndex) => (
                          <div className={`station-implementation-step ${step.status?.toLowerCase() || 'pending'}`} key={`${step.id}-${stepIndex}`} ref={(node) => { if (node) stationStepRefs.current[step.id] = node; }}>
                            <div className="station-implementation-step-header">
                              <span className="station-implementation-status-icon">{stationImplementationStatusIcon(step.status)}</span>
                              <div className="min-w-0">
                                <div className="fw-semibold">{stepIndex + 1}. {step.label}</div>
                                <div className="text-muted small">{step.router_name || 'Router'}{step.host ? ` · ${step.host}` : ''} · {step.router_role}</div>
                              </div>
                              <span className={`badge ms-auto ${step.status === 'SUCCESS' || step.status === 'SKIPPED' ? 'bg-green-lt text-green' : step.status === 'FAILED' ? 'bg-red-lt text-red' : step.status === 'RUNNING' ? 'bg-blue-lt text-blue' : 'bg-secondary-lt text-secondary'}`}>
                                {step.status === 'SKIPPED' ? 'Not found' : step.status}
                              </span>
                            </div>
                            <pre className="station-implementation-command mb-0"><code>{step.preview}</code></pre>
                            {step.message && <div className={`small mt-2 ${step.status === 'FAILED' ? 'text-danger' : 'text-muted'}`}>{step.message}</div>}
                          </div>
                        ))}
                      </div>
                      <div className="modal-footer px-0 pb-0">
                        <button type="button" className="btn" onClick={() => setStationRemove(null)} disabled={stationRemoving}>Close</button>
                        <button type="button" className="btn btn-danger" disabled={stationRemoving || stationCheckingManaged || !stationManagedStatus?.has_managed_config || !(stationRemoveSteps.length || stationRemoveStepList(stationRemove).length)} onClick={runStationRemove} title={!stationManagedStatus ? 'Checking station-created config first.' : !stationManagedStatus?.has_managed_config ? 'No station-created config detected.' : 'Remove station-created config'}>
                          <IconTrash size={18} className="me-2" />{stationRemoving ? 'Removing...' : stationCheckingManaged && !stationManagedStatus ? 'Checking...' : 'Start Remove Config'}
                        </button>
                      </div>
                      <div className="border-top pt-3 mt-3">
                        <div className="fw-semibold mb-2">Recent station history</div>
                        {renderStationCommandHistory()}
                      </div>
                        </>
                      )}
                    </Modal>
                  )}
                  {stationDiagnostics && (
                    <Modal title={`HotSpot Diagnostics: ${stationDiagnostics.station?.station_name || 'Station'}`} size="xl" onClose={() => setStationDiagnostics(null)}>
                      <div className="alert alert-info">
                        <div className="fw-semibold mb-1">Live MikroTik HotSpot checks</div>
                        <div>This is read-only. It checks the station root gateway for HotSpot server/profile, managed login.html, walled garden, DHCP, and whether a phone/client IP is visible in the MikroTik HotSpot host table.</div>
                      </div>
                      <div className="row g-3 mb-3">
                        <div className="col-md-4">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Station VLAN</div>
                            <div className="h3 mb-0">VLAN {stationDiagnostics.station?.vlan_id}</div>
                          </div>
                        </div>
                        <div className="col-md-4">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Client Network</div>
                            <div className="h4 mb-0">{stationDiagnostics.station?.client_network_cidr}</div>
                          </div>
                        </div>
                        <div className="col-md-4">
                          <div className="border rounded p-3 h-100">
                            <div className="text-muted small">Portal URL</div>
                            <div className="fw-semibold text-truncate" title={stationDiagnostics.result?.station?.portal_url || stationDiagnostics.station?.portal_url || ''}>{stationDiagnostics.result?.station?.portal_url || stationDiagnostics.station?.portal_url || '-'}</div>
                          </div>
                        </div>
                      </div>
                      <div className="border rounded p-3 mb-3">
                        <label className="form-label">Phone / client IP to check</label>
                        <div className="input-group">
                          <input className="form-control" value={stationDiagnosticsClientIp} onChange={(e) => setStationDiagnosticsClientIp(e.target.value)} placeholder="Example: 10.77.0.8" />
                          <button className="btn btn-primary" type="button" onClick={() => runStationHotspotDiagnostics()} disabled={stationDiagnosticsLoading}>
                            <IconRefresh size={16} className="me-1" />{stationDiagnosticsLoading ? 'Checking...' : 'Run Diagnostics'}
                          </button>
                        </div>
                        <div className="text-muted small mt-2">Use the phone IP shown on the WiFi client, for example the current `10.77.0.8` test client.</div>
                      </div>
                      {stationDiagnostics.result ? (
                        <>
                          <div className="d-flex flex-wrap align-items-center gap-2 mb-3">
                            <span className={`badge ${stationDiagnosticStatusClass(stationDiagnostics.result.status)}`}>Overall: {stationDiagnostics.result.status}</span>
                            <span className="badge bg-green-lt text-green">Ready {stationDiagnostics.result.summary?.ready || 0}</span>
                            <span className="badge bg-yellow-lt text-yellow">Warnings {stationDiagnostics.result.summary?.warnings || 0}</span>
                            <span className="badge bg-red-lt text-red">Failed {stationDiagnostics.result.summary?.failed || 0}</span>
                          </div>
                          <div className="station-implementation-list">
                            {(stationDiagnostics.result.checks || []).map((check) => (
                              <div className={`station-implementation-step ${check.status === 'OK' ? 'success' : check.status === 'FAILED' ? 'failed' : 'pending'}`} key={check.key}>
                                <div className="station-implementation-step-header">
                                  <span className="station-implementation-status-icon">{check.status === 'OK' ? <IconCircleCheck size={17} /> : check.status === 'FAILED' ? <IconAlertTriangle size={17} /> : <IconInfoCircle size={17} />}</span>
                                  <div className="min-w-0">
                                    <div className="fw-semibold">{check.title}</div>
                                    <div className="text-muted small">{check.message}</div>
                                  </div>
                                  <span className={`badge ms-auto ${stationDiagnosticStatusClass(check.status)}`}>{check.status}</span>
                                </div>
                                {!!Object.keys(check.details || {}).length && (
                                  <details>
                                    <summary className="small text-muted">Details</summary>
                                    <pre className="station-implementation-command mt-2 mb-0"><code>{JSON.stringify(check.details, null, 2)}</code></pre>
                                  </details>
                                )}
                              </div>
                            ))}
                          </div>
                        </>
                      ) : (
                        <div className="text-muted small">Diagnostics are loading...</div>
                      )}
                      <div className="modal-footer px-0 pb-0">
                        <button type="button" className="btn" onClick={() => setStationDiagnostics(null)}>Close</button>
                      </div>
                    </Modal>
                  )}
	              </>}
              {mikrotikTab === 'Scan Result' && <>
                <div className="alert alert-info">
                  <div className="fw-semibold mb-1">Preflight scan is read-only</div>
                  <div>It checks the MikroTik router before setup and does not change VLANs, DHCP, HotSpot, firewall, routing, WireGuard, or any other RouterOS configuration.</div>
                </div>
                {false && <ul className="nav nav-tabs flex-nowrap overflow-auto mb-3" role="tablist">
                  <li className="nav-item" role="presentation">
                    <button className={`nav-link ${preflightView === 'summary' ? 'active' : ''}`} type="button" onClick={() => setPreflightView('summary')}>
                      <IconListDetails size={16} className="me-1" />Summary
                    </button>
                  </li>
                  {mikrotiks.map((router) => {
                    const risk = router.latest_policy_result?.risk_level || router.latest_preflight_scan?.risk_level || 'NEW';
                    return (
                      <li className="nav-item" role="presentation" key={`preflight-tab-${router.id}`}>
                        <button className={`nav-link ${preflightView === router.id ? 'active' : ''}`} type="button" onClick={() => openPreflightRouter(router.id)}>
                          <span>{router.router_name || router.host}</span>
                          <span className={`badge ms-2 ${preflightRiskClass(risk)}`}>{risk}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>}
                {false && preflightView === 'summary' && <>
                  <div className="d-flex align-items-start justify-content-between gap-3 flex-wrap mb-3">
                    <div>
                      <h3 className="card-title mb-1">Multi-Router Preflight Summary</h3>
                      <div className="text-muted small">Prescan All runs read-only checks across every saved MikroTik router. One failed or unreachable router does not stop the rest of the batch.</div>
                    </div>
                    <div className="btn-list">
                      <button className="btn btn-outline-secondary" type="button" onClick={loadPreflightSummary}>
                        <IconRefresh size={18} className="me-2" />Refresh Summary
                      </button>
                      <button className="btn btn-primary" type="button" onClick={prescanAllRouters} disabled={preflightScanningAll || !mikrotiks.length}>
                        <IconSearch size={18} className="me-2" />{preflightScanningAll ? 'Scanning Routers...' : 'Prescan All Routers'}
                      </button>
                    </div>
                  </div>
                  {preflightBatch && (
                    <div className={`alert ${preflightBatch.status === 'SUCCESS' || preflightBatch.status === 'PARTIAL_SUCCESS' ? 'alert-success' : preflightBatch.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>
                      <div className="fw-semibold">Latest batch: {preflightBatch.status}</div>
                      <div>{preflightBatchProgress}. Failed: {preflightBatch.failed_count || 0}. Skipped: {preflightBatch.skipped_count || 0}.</div>
                    </div>
                  )}
                  {(preflightSummary?.latest_batch?.items || preflightBatch?.items || []).length > 0 && (
                    <div className="card mb-3">
                      <div className="card-header"><h3 className="card-title">Last Prescan Batch Progress</h3></div>
                      <div className="table-responsive">
                        <table className="table table-vcenter mb-0">
                          <thead><tr><th>Router</th><th>Host</th><th>Status</th><th>Started</th><th>Completed</th><th>Error</th></tr></thead>
                          <tbody>
                            {(preflightSummary?.latest_batch?.items || preflightBatch?.items || []).map((item) => (
                              <tr key={`batch-item-${item.id}`}>
                                <td>{item.router_name || item.router_id}</td>
                                <td>{item.host}</td>
                                <td><span className={`badge ${item.status === 'SUCCESS' ? 'bg-green-lt text-green' : item.status === 'RUNNING' ? 'bg-blue-lt text-blue' : item.status === 'PENDING' ? 'bg-secondary-lt text-secondary' : 'bg-red-lt text-red'}`}>{item.status}</span></td>
                                <td>{fmt(item.started_at)}</td>
                                <td>{fmt(item.completed_at)}</td>
                                <td className="text-muted small">{item.error_message || '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                  <div className="row row-cards mb-3">
                    <KpiCard icon={IconRouter} label="Total Routers" value={preflightSummary?.cards?.total_routers || 0} tone="blue" />
                    <KpiCard icon={IconSearch} label="Scanned" value={preflightSummary?.cards?.scanned || 0} tone="green" />
                    <KpiCard icon={IconRefresh} label="Reachable" value={preflightSummary?.cards?.reachable || 0} tone="purple" />
                    <KpiCard icon={IconAlertTriangle} label="Failed / Unreachable" value={preflightSummary?.cards?.failed_unreachable || 0} tone="red" />
                    <KpiCard icon={IconWifi} label="Potential HotSpot Candidates" value={preflightSummary?.cards?.hotspot_gateway_candidates || 0} tone="green" />
                    <KpiCard icon={IconShieldLock} label="Requires Confirmation" value={preflightSummary?.cards?.requires_confirmation || 0} tone="yellow" />
                    <KpiCard icon={IconLock} label="Read-only/Core" value={preflightSummary?.cards?.read_only_core || 0} tone="secondary" />
                    <KpiCard icon={IconListDetails} label="VLAN Trunk Helpers" value={preflightSummary?.cards?.vlan_trunk_helpers || 0} tone="blue" />
                    <KpiCard icon={IconAlertTriangle} label="Failed Scans" value={preflightSummary?.cards?.failed_scans || 0} tone="red" />
                    <KpiCard icon={IconBan} label="Blocked by Conflicts" value={preflightSummary?.cards?.blocked_by_conflicts || 0} tone="red" />
                  </div>
                  <Card title="Router Deployment Readiness" subtitle={`Last full prescan: ${fmt(preflightSummary?.last_full_prescan) || 'Never'}`}>
                    <div className="btn-list mb-3">
                      {[
                        ['ALL', 'All'],
                        ['FAILED', 'Failed scans'],
                        ['BLOCKED', 'Blocked'],
                        ['CANDIDATES', 'Potential HotSpot candidates'],
                        ['READ_ONLY', 'Read-only/core'],
                        ['TRUNK', 'VLAN trunk helpers'],
                        ['CONFIRMATION', 'Requires confirmation']
                      ].map(([key, label]) => (
                        <button className={`btn btn-sm ${preflightSummaryFilter === key ? 'btn-primary' : 'btn-outline-secondary'}`} type="button" onClick={() => setPreflightSummaryFilter(key)} key={`preflight-filter-${key}`}>
                          {label}
                        </button>
                      ))}
                    </div>
                    <div className="table-responsive">
                      <table className="table table-vcenter">
                        <thead>
                          <tr>
                            <th>Router</th>
                            <th>Host</th>
                            <th>API Status</th>
                            <th>Last Scan</th>
                            <th>Risk</th>
                            <th>Role Guess</th>
                            <th>Recommended Mode</th>
                            <th>Confirmation</th>
                            <th>Pilot</th>
                            <th>Blockers</th>
                            <th>Next Action</th>
                            <th className="text-end">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredPreflightReadinessRows.map((row) => (
                            <tr key={`preflight-readiness-${row.router_id}`}>
                              <td className="fw-semibold">{row.router}</td>
                              <td>{row.host}</td>
                              <td><span className={`badge ${row.api_status === 'REACHABLE' ? 'bg-green-lt text-green' : row.api_status === 'NOT_TESTED' ? 'bg-secondary-lt text-secondary' : 'bg-red-lt text-red'}`}>{row.api_status}</span></td>
                              <td>{fmt(row.last_scan) || 'Not scanned'}</td>
                              <td><span className={`badge ${preflightRiskClass(row.risk_level)}`}>{row.risk_level}</span></td>
                              <td>{routerRoleLabel(row.role_guess)}</td>
                              <td>{deploymentModeLabel(row.recommended_deployment_mode)}</td>
                              <td><span className={`badge ${row.confirmation_status === 'CONFIRMED' ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{row.confirmation_status || 'NEEDS_CONFIRMATION'}</span></td>
                              <td><span className={`badge ${pilotSuitabilityClass(row.pilot_suitability)}`} title={row.pilot_reason || ''}>{pilotSuitabilityLabel(row.pilot_suitability)}</span></td>
                              <td>{row.blocking_conflicts}</td>
                              <td>{row.next_action}</td>
                              <td className="text-end">
                                <div className="btn-list justify-content-end flex-nowrap">
                                  <button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => openPreflightRouter(row.router_id)} title="View Router Scan">
                                    <IconEye size={16} />
                                  </button>
                                  <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => runPreflightScan(row.router_id)} title="Run Scan">
                                    <IconSearch size={16} />
                                  </button>
                                  <button className="btn btn-sm btn-outline-warning" type="button" onClick={() => openPreflightRouter(row.router_id)} title="Set Deployment Mode">
                                    <IconShieldLock size={16} />
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))}
                          {!filteredPreflightReadinessRows.length && <tr><td colSpan="12" className="text-muted p-4">No routers match this filter.</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </Card>
                  <div className="row row-cards mt-3">
                    <div className="col-lg-6">
                      <Card title="Existing VLAN Usage / Network-wide Warnings">
                        {(preflightSummary?.duplicate_vlan_usage || []).map((item) => (
                          <div className="alert alert-warning mb-2" key={`dup-vlan-${item.vlan_id}`}>
                            <div className="fw-semibold">VLAN {item.vlan_id}</div>
                            <div className="small">{item.message} Routers: {(item.routers || []).join(', ')}</div>
                          </div>
                        ))}
                        {(preflightSummary?.network_conflicts || []).slice(0, 8).map((item, index) => (
                          <div className="border rounded p-2 mb-2" key={`network-conflict-${index}`}>
                            <div className="fw-semibold">{item.router}: {item.title}</div>
                            <div className="text-muted small">{item.message}</div>
                          </div>
                        ))}
                        {!(preflightSummary?.duplicate_vlan_usage || []).length && !(preflightSummary?.network_conflicts || []).length && <div className="text-muted">No network-wide VLAN warnings or hard conflict signals from the latest scans.</div>}
                      </Card>
                    </div>
                    <div className="col-lg-6">
                      <Card title="Recommended Rollout Order">
                        <ol className="mb-0">
                          {(preflightSummary?.recommended_rollout_order || []).map((item, index) => <li key={`rollout-${index}`}>{item}</li>)}
                        </ol>
                        <div className="alert alert-info mt-3 mb-0">Prescan All is read-only. It does not change any MikroTik configuration.</div>
                      </Card>
                    </div>
                  </div>
                  {actionResult && <div className={`alert mt-3 mb-0 ${actionResult.status === 'SUCCESS' ? 'alert-success' : actionResult.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>{actionResult.message || actionResult.status}</div>}
                </>}
                {preflightView !== 'summary' && <>
                <div className="d-flex align-items-end justify-content-between gap-3 mb-3 flex-wrap">
                  <div className="flex-fill" style={{ minWidth: 260 }}>
                    <label className="form-label">MikroTik Router</label>
                    <select className="form-select" value={preflightRouterId} onChange={(e) => openPreflightRouter(e.target.value)}>
                      <option value="">Choose router</option>
                      {mikrotiks.map((router) => (
                        <option value={router.id} key={`preflight-router-${router.id}`}>{router.router_name} - {router.host}:{router.api_port}</option>
                      ))}
                    </select>
                    {preflightRouter?.latest_preflight_scan && <div className="text-muted small mt-1">Last scan: {fmt(preflightRouter.latest_preflight_scan.created_at)} ({preflightRouter.latest_preflight_scan.risk_level})</div>}
                  </div>
                  <div className="btn-list">
                    <button className="btn btn-outline-secondary" type="button" onClick={() => loadPreflightLatest()} disabled={!preflightRouterId || preflightLoading}>
                      <IconRefresh size={18} className="me-2" />{preflightLoading ? 'Loading...' : 'Load Latest'}
                    </button>
                    <button className="btn btn-primary" type="button" onClick={() => runPreflightScan()} disabled={!preflightRouterId || preflightScanning}>
                      <IconSearch size={18} className="me-2" />{preflightScanning ? 'Scanning...' : 'Run Preflight Scan'}
                    </button>
                  </div>
                </div>
                {!mikrotiks.length && <div className="empty">Add a MikroTik router first, then run a read-only preflight scan.</div>}
                {preflightRouterId && !preflightScan && !preflightLoading && <div className="empty">No scan result is loaded for this router yet. Run Scan from the Configuration table, then open View Scan Result.</div>}
                {preflightScan && <>
                  <div className="row row-cards mb-3">
                    <KpiCard icon={IconRouter} label="Router Identity" value={preflightScan.router_identity || preflightRouter?.router_name || 'Unknown'} tone="blue" />
                    <KpiCard icon={IconCpu} label="Model / Version" value={`${preflightScan.router_model || 'Unknown'} ${preflightScan.router_version || ''}`.trim()} tone="green" />
                    <KpiCard icon={IconShieldLock} label="Risk Level" value={preflightScan.risk_level || 'Unknown'} tone={preflightScan.risk_level === 'LOW' ? 'green' : preflightScan.risk_level === 'MEDIUM' ? 'yellow' : 'red'} />
                    <KpiCard icon={IconListDetails} label="Findings" value={`${(preflightScan.findings || []).length} total`} tone="purple" />
                  </div>
                  <div className="card mb-3">
                    <div className="card-body">
                      <div className="d-flex align-items-start justify-content-between gap-3 flex-wrap">
                        <div>
                          <div className="d-flex flex-wrap gap-2 mb-2">
                            <span className={`badge ${preflightRiskClass(preflightScan.risk_level)}`}>Risk: {preflightScan.risk_level}</span>
                            <span className="badge bg-blue-lt text-blue">Role guess: {preflightScan.router_role_guess || 'UNKNOWN'}</span>
                            <span className={`badge ${preflightScan.scan_status === 'SUCCESS' ? 'bg-green-lt text-green' : 'bg-red-lt text-red'}`}>{preflightScan.scan_status}</span>
                          </div>
                          <div className="text-muted small">Last scan timestamp: {fmt(preflightScan.created_at)}. Use this read-only data to check existing VLANs, subnets, pools, DHCP, HotSpot, and sensitive routing services before creating a station plan.</div>
                        </div>
                      </div>
                      {preflightScan.last_error && <div className="alert alert-danger mt-3 mb-0">{preflightScan.last_error}</div>}
                    </div>
                  </div>
                  <div className="card mb-3">
                    <div className="card-header"><h3 className="card-title">Role Explanation</h3></div>
                    <div className="card-body">
                      {preflightScan.router_role_guess === 'PPPoE_ACCESS_CONCENTRATOR' && (
                        <div className="alert alert-warning">
                          This router has PPPoE services. The system will not touch PPPoE bridges, pools, profiles, or access networks. Captive portal setup is only possible on a new dedicated VLAN/subnet after confirmation.
                        </div>
                      )}
                      {preflightScan.router_role_guess === 'CORE_ROUTER_READ_ONLY' && (
                        <div className="alert alert-danger">
                          This router appears to be core/routing infrastructure. HotSpot setup is blocked by default.
                        </div>
                      )}
                      {preflightScan.router_role_guess === 'SWITCH_TRUNK_HELPER' && (
                        <div className="alert alert-info">
                          This device appears to be a VLAN trunk/switch device. It should not host HotSpot, but it may later help carry a customer VLAN.
                        </div>
                      )}
                      <div className="row g-3">
                        <div className="col-lg-6">
                          <div className="fw-semibold mb-1">Why this role was guessed</div>
                          <ul className="mb-0">
                            {(preflightScan.role_reasoning || ['No role reasoning saved for this scan yet.']).map((item, index) => <li key={`role-reason-${index}`}>{item}</li>)}
                          </ul>
                        </div>
                        <div className="col-12">
                          <span className={`badge ${pilotSuitabilityClass(preflightScan.pilot_suitability)}`}>Pilot suitability: {pilotSuitabilityLabel(preflightScan.pilot_suitability)}</span>
                          {preflightScan.pilot_reason && <div className="text-muted small mt-1">{preflightScan.pilot_reason}</div>}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="row row-cards mb-3">
                    <div className="col-md-3"><div className="card"><div className="card-body"><div className="text-muted small">VLANs</div><div className="h2 mb-0">{preflightVlanRows.length}</div></div></div></div>
                    <div className="col-md-3"><div className="card"><div className="card-body"><div className="text-muted small">Subnets</div><div className="h2 mb-0">{preflightSubnetRows.length}</div></div></div></div>
                    <div className="col-md-3"><div className="card"><div className="card-body"><div className="text-muted small">DHCP / HotSpot</div><div className="h2 mb-0">{preflightCounts.dhcp_servers || 0} / {preflightCounts.hotspots || 0}</div></div></div></div>
                    <div className="col-md-3"><div className="card"><div className="card-body"><div className="text-muted small">PPPoE / OSPF / WG</div><div className="h2 mb-0">{preflightCounts.pppoe_servers || 0} / {preflightCounts.ospf_entries || 0} / {preflightCounts.wireguard || 0}</div></div></div></div>
                  </div>
                  <div className="row row-cards">
                    <div className="col-12">
                      <Card title="Conflict Warnings" subtitle="Blockers must be resolved before future configuration preview or apply phases.">
                        {(preflightScan.conflicts || []).length ? (
                          <div className="list-group list-group-flush">
                            {preflightScan.conflicts.map((item, index) => (
                              <div className="list-group-item px-0" key={`preflight-conflict-${index}`}>
                                <div className="d-flex justify-content-between gap-3">
                                  <div>
                                    <div className="fw-semibold">{item.title}</div>
                                    <div className="text-muted small">{item.message}</div>
                                    {item.recommendation && <div className="small mt-1">{item.recommendation}</div>}
                                  </div>
                                  <span className={`badge align-self-start ${preflightFindingClass(item.severity)}`}>{item.severity}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : <div className="text-muted">No blocking conflicts detected in the latest scan.</div>}
                      </Card>
                    </div>
                    <div className="col-lg-6"><Card title="Existing VLANs"><Table rows={preflightVlanRows} columns={['source', 'name', 'vlan_id', 'interface', 'comment']} /></Card></div>
                    <div className="col-lg-6"><Card title="Existing Subnets"><Table rows={preflightSubnetRows} columns={['address', 'network', 'interface', 'disabled', 'comment']} /></Card></div>
                    <div className="col-lg-6"><Card title="Existing IP Pools"><Table rows={preflightPoolRows} columns={['name', 'ranges', 'comment']} /></Card></div>
                    <div className="col-lg-6"><Card title="Existing DHCP Servers"><Table rows={preflightDhcpRows} columns={['name', 'interface', 'address_pool', 'disabled', 'lease_time']} /></Card></div>
                    <div className="col-lg-6"><Card title="Existing HotSpot Servers"><Table rows={preflightHotspotRows} columns={['name', 'interface', 'profile', 'address_pool', 'disabled']} /></Card></div>
                    <div className="col-lg-6">
                      <Card title="Sensitive Config Indicators">
                        <div className="d-flex flex-column gap-2">
                          <div className="d-flex justify-content-between"><span>PPPoE servers</span><span className={`badge ${(preflightCounts.pppoe_servers || 0) ? 'bg-red-lt text-red' : 'bg-green-lt text-green'}`}>{preflightCounts.pppoe_servers || 0}</span></div>
                          <div className="d-flex justify-content-between"><span>OSPF entries</span><span className={`badge ${(preflightCounts.ospf_entries || 0) ? 'bg-red-lt text-red' : 'bg-green-lt text-green'}`}>{preflightCounts.ospf_entries || 0}</span></div>
                          <div className="d-flex justify-content-between"><span>WireGuard interfaces</span><span className={`badge ${(preflightCounts.wireguard || 0) ? 'bg-yellow-lt text-yellow' : 'bg-green-lt text-green'}`}>{preflightCounts.wireguard || 0}</span></div>
                          <div className="d-flex justify-content-between"><span>Firewall filter rules</span><span className="badge bg-blue-lt text-blue">{preflightCounts.firewall_filter || 0}</span></div>
                          <div className="d-flex justify-content-between"><span>NAT rules</span><span className="badge bg-blue-lt text-blue">{preflightCounts.firewall_nat || 0}</span></div>
                          <div className="d-flex justify-content-between"><span>Routes</span><span className="badge bg-blue-lt text-blue">{preflightCounts.routes || 0}</span></div>
                          <div className="d-flex justify-content-between"><span>Unsupported read-only paths</span><span className="badge bg-secondary-lt text-secondary">{preflightCounts.unsupported_paths || 0}</span></div>
                        </div>
                      </Card>
                    </div>
                    <div className="col-12">
                      <Card title="Findings by Category">
                        <div className="row g-2">
                          {(preflightScan.findings || []).map((item, index) => (
                            <div className="col-md-6" key={`preflight-finding-${index}`}>
                              <div className="border rounded p-3 h-100">
                                <div className="d-flex align-items-start justify-content-between gap-2 mb-1">
                                  <div className="fw-semibold">{item.title}</div>
                                  <span className={`badge ${preflightFindingClass(item.severity)}`}>{item.category} / {item.severity}</span>
                                </div>
                                <div className="text-muted small">{item.message}</div>
                                {item.related_object && <div className="small mt-1"><strong>Related:</strong> {item.related_object}</div>}
                                {item.recommendation && <div className="small mt-1"><strong>Recommendation:</strong> {item.recommendation}</div>}
                              </div>
                            </div>
                          ))}
                          {!(preflightScan.findings || []).length && <div className="col-12 text-muted">No findings recorded.</div>}
                        </div>
                      </Card>
                    </div>
                    <div className="col-12">
                      <Card title="Scan History">
                        <Table rows={preflightHistory} columns={['created_at', 'scan_status', 'risk_level', 'router_role_guess', 'recommended_deployment_mode', 'last_error']} />
                      </Card>
                    </div>
                  </div>
                </>}
                {!preflightScan && actionResult && <div className={`alert mt-3 mb-0 ${actionResult.status === 'SUCCESS' ? 'alert-success' : actionResult.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>{actionResult.message || actionResult.status}</div>}
                </>}
              </>}
              {false && <>
                <div className="alert alert-info">
                  <div className="fw-semibold mb-1">AI guidance only</div>
                  <div>The AI Network Assistant explains scan results and helps prepare a draft pilot plan. It cannot apply MikroTik changes, generate final RouterOS commands, or bypass the safety policy engine.</div>
                </div>
                <div className="d-flex align-items-center justify-content-between gap-3 flex-wrap mb-3">
                  <div>
                    <h3 className="card-title mb-1">Overview</h3>
                    <div className="text-muted small">Choose a router from the table actions to open pilot selection, missing questions, or draft planning. Router selection is handled inside each workflow.</div>
                  </div>
                  <div className="btn-list">
                    <button className="btn btn-outline-secondary" type="button" onClick={loadAiNetworkAssistant} disabled={aiLoading}>
                      <IconRefresh size={18} className="me-2" />{aiLoading ? 'Refreshing...' : 'Refresh Overview'}
                    </button>
                    <button className="btn btn-primary" type="button" onClick={() => setAiChatOpen(true)}>
                      <IconRobot size={18} className="me-2" />Chat with AI
                    </button>
                  </div>
                </div>
                <div className="row row-cards mb-3">
                  <KpiCard icon={IconRouter} label="Total Routers" value={aiCards.total_routers || 0} tone="blue" />
                  <KpiCard icon={IconSearch} label="Scanned" value={aiCards.scanned || 0} tone="green" />
                  <KpiCard icon={IconAlertTriangle} label="Failed Scans" value={aiCards.failed_scans || 0} tone="red" />
                  <KpiCard icon={IconWifi} label="HotSpot Candidates" value={aiCards.hotspot_gateway_candidates || 0} tone="green" />
                  <KpiCard icon={IconLock} label="Read-only/Core" value={aiCards.read_only_core || 0} tone="secondary" />
                  <KpiCard icon={IconShieldLock} label="Needs Confirmation" value={aiCards.requires_confirmation || 0} tone="yellow" />
                </div>
                <ul className="nav nav-tabs mb-3">
                  <li className="nav-item">
                    <button className="nav-link active" type="button">Overview</button>
                  </li>
                </ul>
                <div className="row row-cards mb-3">
                  <div className="col-lg-4">
                    <Card title="AI Health">
                      <div className="d-flex flex-column gap-2">
                        <div className="d-flex justify-content-between"><span>Status</span><span className={`badge ${aiOpenAi.configured ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{aiOpenAi.configured ? 'Configured' : 'Not configured'}</span></div>
                        <div className="d-flex justify-content-between"><span>Smoke test</span><span className={`badge ${smokeStatusTone}`}>{aiSmoke?.status || 'Not run'}</span></div>
                        <div className="text-muted small">Model: {aiOpenAi.model || 'Not set'}</div>
                        {aiSmoke?.created_at && <div className="text-muted small">Last run: {fmt(aiSmoke.created_at)}</div>}
                        <button className="btn btn-outline-primary mt-2" type="button" onClick={() => setAiSmokeModalOpen(true)}>
                          <IconBrandOpenai size={18} className="me-2" />Run AI Smoke Test
                        </button>
                      </div>
                    </Card>
                  </div>
                  <div className="col-lg-4">
                    <Card title="Pilot Router">
                      <div className="d-flex flex-column gap-2">
                        <span className={`badge align-self-start ${selectedPilot ? 'bg-blue-lt text-blue' : 'bg-yellow-lt text-yellow'}`}>{selectedPilot ? 'Selected' : 'Not selected'}</span>
                        <div className="fw-semibold">{selectedPilot?.router_name || 'No pilot selected'}</div>
                        <div className="text-muted small">{selectedPilot?.host || 'Select exactly one pilot before MT-4.'}</div>
                        <button className="btn btn-outline-primary mt-2" type="button" onClick={() => openAiPlanningModal(selectedPilot?.router_id || aiRouterId || mikrotiks[0]?.id, setPilotModalOpen)}>
                          <IconCircleCheck size={18} className="me-2" />Pilot Router Selection
                        </button>
                      </div>
                    </Card>
                  </div>
                  <div className="col-lg-4">
                    <Card title="Draft Deployment Plan">
                      <div className="d-flex flex-column gap-2">
                        <span className={`badge align-self-start ${pilotDraftStatusTone}`}>{pilotDraftStatusLabel}</span>
                        <div className="text-muted small">{activeQuestionContextIsPilot && readyForMt4 ? 'Ready for MT-4 command preview.' : 'Pilot draft planning is router-specific. No RouterOS commands are generated here.'}</div>
                        <button className="btn btn-outline-primary mt-2" type="button" onClick={() => openAiPlanningModal(selectedPilot?.router_id, setDraftPlanModalOpen)} disabled={!selectedPilot?.router_id}>
                          <IconSparkles size={18} className="me-2" />Open Draft Plan
                        </button>
                      </div>
                    </Card>
                  </div>
                  <div className="col-12">
                    <Card title="Routers Overview" subtitle="All saved MikroTik routers with pilot, planning, and draft-plan actions.">
                      <div className="d-flex justify-content-between align-items-center gap-2 flex-wrap mb-3">
                        <div className="text-muted small">Use this table as the MT-3 planning control center. Actions open modal workflows; no RouterOS configuration is applied.</div>
                        <div className="btn-list">
                          <button className="btn btn-outline-secondary" type="button" onClick={loadAiNetworkAssistant} disabled={aiLoading}>
                            <IconRefresh size={18} className="me-2" />{aiLoading ? 'Refreshing...' : 'Refresh'}
                          </button>
                          <button className="btn btn-primary" type="button" onClick={() => setAiChatOpen(true)}>
                            <IconRobot size={18} className="me-2" />Chat with AI
                          </button>
                        </div>
                      </div>
                      <div className="table-responsive">
                        <table className="table table-vcenter">
                          <thead>
                            <tr>
                              <th>Router</th>
                              <th>Host</th>
                              <th>Role</th>
                              <th>Risk</th>
                              <th>Pilot</th>
                              <th>Questions</th>
                              <th>Recommended Action</th>
                              <th className="text-end">Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {aiRouterRows.map((router) => (
                              <tr key={`ai-overview-router-${router.id}`} className={router.isPilot ? 'table-primary' : ''}>
                                <td>
                                  <div className="fw-semibold">{router.router_name}</div>
                                  {router.isPilot && <span className="badge bg-blue-lt text-blue mt-1">Selected pilot</span>}
                                </td>
                                <td className="text-muted small">{router.host}:{router.api_port}</td>
                                <td>{routerRoleLabel(router.role_guess)}</td>
                                <td><span className={`badge ${preflightRiskClass(router.risk_level)}`}>{router.risk_level}</span></td>
                                <td><span className={`badge ${pilotSuitabilityClass(router.pilot_suitability)}`}>{pilotSuitabilityLabel(router.pilot_suitability)}</span></td>
                                <td>
                                  {router.isPilot ? (
                                    <button
                                      className={`badge border-0 ${router.question_progress?.complete ? 'bg-green-lt text-green' : Number(router.question_progress?.answered_required || 0) ? 'bg-yellow-lt text-yellow' : 'bg-secondary-lt text-secondary'}`}
                                      type="button"
                                      onClick={() => openAiPlanningModal(router.id, setQuestionsModalOpen)}
                                      title="Open this pilot router's Missing Questions"
                                    >
                                      {router.question_progress?.label || '0/0'}
                                    </button>
                                  ) : (
                                    <span className="badge bg-secondary-lt text-secondary" title="Planning questions are enabled only for the selected pilot router.">Pilot only</span>
                                  )}
                                </td>
                                <td className="text-muted small" style={{ maxWidth: 300 }}>{router.recommended_action}</td>
                                <td className="text-end">
                                  <div className="btn-list justify-content-end flex-nowrap">
                                    <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => openAiPlanningModal(router.id, setPilotModalOpen)}>Pilot</button>
                                    <button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => openAiPlanningModal(router.id, setQuestionsModalOpen)} disabled={!router.isPilot}>Questions</button>
                                    <button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => openAiPlanningModal(router.id, setDraftPlanModalOpen)} disabled={!router.isPilot}>Draft</button>
                                  </div>
                                </td>
                              </tr>
                            ))}
                            {!aiRouterRows.length && <tr><td colSpan="8" className="text-muted p-4">No MikroTik routers added yet.</td></tr>}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  </div>
                </div>
                <div className="row row-cards d-none">
                  <div className="col-xl-7">
                    <Card title="Router Recommendation" subtitle="Pilot ranking combines preflight suitability, risk, role, reachability, and blockers.">
                      <div className="table-responsive">
                        <table className="table table-vcenter">
                          <thead>
                            <tr><th>Router</th><th>Role</th><th>Risk</th><th>Pilot</th><th>Reason</th><th>Action</th></tr>
                          </thead>
                          <tbody>
                            {aiPilotCandidates.slice(0, 10).map((item) => (
                              <tr key={`ai-candidate-${item.router_id}`} className={selectedPilot?.router_id === item.router_id ? 'table-primary' : ''}>
                                <td className="fw-semibold">
                                  <div>{item.router}</div>
                                  {selectedPilot?.router_id === item.router_id && <span className="badge bg-blue-lt text-blue mt-1">Selected pilot</span>}
                                </td>
                                <td>{routerRoleLabel(item.role_guess)}</td>
                                <td><span className={`badge ${preflightRiskClass(item.risk_level)}`}>{item.risk_level}</span></td>
                                <td><span className={`badge ${pilotSuitabilityClass(item.pilot_suitability)}`}>{pilotSuitabilityLabel(item.pilot_suitability)}</span></td>
                                <td className="text-muted small" style={{ maxWidth: 300 }}>{item.reason}</td>
                                <td>
                                  <div className="btn-list flex-nowrap">
                                    <button className="btn btn-sm btn-outline-primary" type="button" onClick={() => setAiRouterId(item.router_id)}>View</button>
                                    <button className="btn btn-sm btn-primary" type="button" onClick={() => { setAiRouterId(item.router_id); setPilotForm((current) => ({ ...current, router_id: item.router_id, reason: current.reason || item.reason || item.recommended_action || '' })); selectPilotRouter(item.router_id); }} disabled={pilotSaving}>
                                      Select
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))}
                            {!aiPilotCandidates.length && <tr><td colSpan="6" className="text-muted p-4">Run Prescan All Routers first to populate pilot recommendations.</td></tr>}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  </div>
                  <div className="col-xl-5">
                    <Card title="AI Health / Smoke Test" subtitle="Confirms OpenAI works without asking for RouterOS commands.">
                      <div className="d-flex flex-column gap-3">
                        <div className="d-flex justify-content-between align-items-center">
                          <span>OpenAI</span>
                          <span className={`badge ${aiOpenAi.configured ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{aiOpenAi.configured ? 'Configured' : 'Not configured'}</span>
                        </div>
                        <div className="d-flex justify-content-between align-items-center">
                          <span>Model</span>
                          <span className="text-muted">{aiOpenAi.model || 'Not set'}</span>
                        </div>
                        <div className="d-flex justify-content-between align-items-center">
                          <span>Last smoke test</span>
                          <span className={`badge ${aiSmoke?.status === 'SUCCESS' ? 'bg-green-lt text-green' : aiSmoke?.status === 'FAILED' ? 'bg-red-lt text-red' : 'bg-yellow-lt text-yellow'}`}>{aiSmoke?.status || 'Not run'}</span>
                        </div>
                        {aiSmoke?.created_at && <div className="text-muted small">Last run: {fmt(aiSmoke.created_at)}</div>}
                        {aiSmoke?.response_summary && <div className="alert alert-success mb-0 small">{aiSmoke.response_summary}</div>}
                        {aiSmoke?.error_message && <div className="alert alert-warning mb-0 small">{aiSmoke.error_message}</div>}
                        <button className="btn btn-outline-primary" type="button" onClick={runAiSmokeTest} disabled={!aiOpenAi.configured || aiSmokeTesting}>
                          <IconBrandOpenai size={18} className="me-2" />{aiSmokeTesting ? 'Testing...' : 'Run AI Smoke Test'}
                        </button>
                        <div className="alert alert-secondary mb-0">
                          AI receives sanitized scan summaries only. Passwords, API secrets, RADIUS secrets, WireGuard keys, and tokens are redacted before AI use.
                        </div>
                      </div>
                    </Card>
                    <div className="mt-3">
                      <Card title="Pilot Router Selection" subtitle="Choose exactly one pilot before MT-4 planning. No MikroTik configuration is applied.">
                        <div className="d-flex flex-column gap-3">
                          {selectedPilot ? (
                            <div className="alert alert-info mb-0">
                              <div className="fw-semibold">Selected pilot: {selectedPilot.router_name}</div>
                              <div className="small">{selectedPilot.host}</div>
                              {selectedPilot.reason && <div className="small mt-1">Reason: {selectedPilot.reason}</div>}
                            </div>
                          ) : (
                            <div className="alert alert-warning mb-0">No pilot router selected yet.</div>
                          )}
                          <div>
                            <label className="form-label">Selected Pilot Router</label>
                            <select className="form-select" value={pilotForm.router_id || aiRouterId || ''} onChange={(e) => { setPilotForm({ ...pilotForm, router_id: e.target.value }); setAiRouterId(e.target.value); }}>
                              <option value="">Choose router</option>
                              {mikrotiks.map((router) => <option value={router.id} key={`pilot-${router.id}`}>{router.router_name} - {router.host}:{router.api_port}</option>)}
                            </select>
                          </div>
                          <div>
                            <label className="form-label">Reason for pilot selection</label>
                            <textarea className="form-control" rows="2" value={pilotForm.reason} onChange={(e) => setPilotForm({ ...pilotForm, reason: e.target.value })} placeholder="Example: office router, easy to recover, good first test site" />
                          </div>
                          <div>
                            <label className="form-label">Physical recovery confidence</label>
                            <select className="form-select" value={pilotForm.physical_recovery_confidence} onChange={(e) => setPilotForm({ ...pilotForm, physical_recovery_confidence: e.target.value })}>
                              <option value="EASY_TO_RECOVER">Easy to recover</option>
                              <option value="MODERATE">Moderate</option>
                              <option value="HARD_REMOTE_SITE">Hard remote site</option>
                            </select>
                          </div>
                          <div>
                            <label className="form-label">Operator note</label>
                            <textarea className="form-control" rows="2" value={pilotForm.operator_note} onChange={(e) => setPilotForm({ ...pilotForm, operator_note: e.target.value })} placeholder="Optional note for the next engineer/operator" />
                          </div>
                          <div className="btn-list">
                            <button className="btn btn-primary" type="button" onClick={() => selectPilotRouter()} disabled={pilotSaving || !(pilotForm.router_id || aiRouterId)}>
                              <IconCircleCheck size={18} className="me-2" />Select as Pilot
                            </button>
                            <button className="btn btn-outline-secondary" type="button" onClick={clearPilotRouter} disabled={pilotSaving || !selectedPilot}>
                              <IconX size={18} className="me-2" />Clear Pilot Selection
                            </button>
                          </div>
                        </div>
                      </Card>
                    </div>
                  </div>
                  <div className="col-xl-6">
                    <Card title="Chat Panel" subtitle="Ask for explanations. The assistant will not output RouterOS commands in MT-3.">
                      {!aiOpenAi.configured && <div className="alert alert-warning">AI is not configured. Configure OpenAI in System Settings to use chat and draft-plan generation.</div>}
                      <div className="d-flex flex-wrap gap-2 mb-3">
                        {guidedAiPrompts.map((prompt) => (
                          <button className="btn btn-sm btn-outline-secondary" type="button" key={prompt} onClick={() => setAiInput(prompt)}>
                            {prompt}
                          </button>
                        ))}
                      </div>
                      <div className="border rounded p-3 mb-3" style={{ minHeight: 220, maxHeight: 360, overflowY: 'auto', background: '#f8fafc' }}>
                        {aiMessages.map((item) => (
                          <div className={`mb-3 ${item.role === 'USER' ? 'text-end' : ''}`} key={item.id}>
                            <div className={`d-inline-block p-2 rounded ${item.role === 'USER' ? 'bg-primary text-white' : 'bg-white border'}`} style={{ maxWidth: '85%', whiteSpace: 'pre-wrap' }}>
                              {item.message_text}
                            </div>
                          </div>
                        ))}
                        {!aiMessages.length && <div className="text-muted">Try asking: “Which router should I configure first?” or “Why is this router high risk?”</div>}
                      </div>
                      <form onSubmit={sendAiMessage}>
                        <div className="input-group">
                          <input className="form-control" value={aiInput} onChange={(e) => setAiInput(e.target.value)} placeholder="Ask about scan results, router role, VLANs, NAT, or pilot choice" disabled={!aiOpenAi.configured || aiSending} />
                          <button className="btn btn-primary" disabled={!aiOpenAi.configured || aiSending || !aiInput.trim()}>
                            <IconRobot size={18} className="me-2" />{aiSending ? 'Asking...' : 'Ask AI'}
                          </button>
                        </div>
                      </form>
                    </Card>
                  </div>
                  <div className="col-xl-6">
                    <Card title="Missing Questions" subtitle="Save answers here. MT-4 will use these planning values for command preview.">
                      {!aiRouterId && <div className="empty">Select a router first.</div>}
                      {aiRouterId && (
                        <div className="d-flex flex-column gap-3">
                          <div className="d-flex align-items-center justify-content-between gap-2 flex-wrap">
                            <div>
                              <div className="fw-semibold">Answered {answeredRequired} of {totalRequired} required questions</div>
                              <div className="progress mt-2" style={{ width: 260, maxWidth: '100%' }}>
                                <div className="progress-bar" style={{ width: `${totalRequired ? Math.round((answeredRequired / totalRequired) * 100) : 0}%` }} />
                              </div>
                            </div>
                            <div className="btn-list">
                              <button className="btn btn-outline-primary" type="button" onClick={suggestAiAnswers} disabled={!aiOpenAi.configured || aiSuggestingAnswers}>
                                <IconSparkles size={18} className="me-2" />{aiSuggestingAnswers ? 'Suggesting...' : 'Suggest Answers with AI'}
                              </button>
                              <button className="btn btn-outline-secondary" type="button" onClick={validateAiAnswers} disabled={aiValidatingAnswers}>
                                <IconShieldLock size={18} className="me-2" />{aiValidatingAnswers ? 'Validating...' : 'Validate Answers'}
                              </button>
                              <button className="btn btn-primary" type="button" onClick={saveAllAiQuestions} disabled={aiSavingQuestions}>
                                <IconDeviceFloppy size={18} className="me-2" />{aiSavingQuestions ? 'Saving...' : 'Save All'}
                              </button>
                              <button className="btn btn-outline-danger" type="button" onClick={resetAiSuggestions} disabled={!aiQuestions.some((question) => question.suggested_value)}>
                                <IconX size={18} className="me-2" />Reset Suggestions
                              </button>
                            </div>
                          </div>
                          <div className="border rounded p-3 bg-light">
                            <div className="fw-semibold mb-2">Network Preview</div>
                            {effectiveNetworkPreview?.status === 'SUCCESS' ? (
                              <div className="row g-2 small">
                                <div className="col-md-6"><span className="text-muted">CIDR:</span> <span className="fw-semibold">{effectiveNetworkPreview.cidr}</span></div>
                                <div className="col-md-6"><span className="text-muted">Range:</span> <span className="fw-semibold">{effectiveNetworkPreview.range}</span></div>
                                <div className="col-md-6"><span className="text-muted">Gateway:</span> <span className="fw-semibold">{effectiveNetworkPreview.gateway_ip}</span></div>
                                <div className="col-md-6"><span className="text-muted">DHCP Pool:</span> <span className="fw-semibold">{effectiveNetworkPreview.dhcp_pool}</span></div>
                                <div className="col-md-6"><span className="text-muted">Usable hosts:</span> <span className="fw-semibold">{effectiveNetworkPreview.usable_hosts}</span></div>
                                <div className="col-md-6"><span className="text-muted">Conflict status:</span> <span className={`badge ${(questionValidation?.errors || []).length ? 'bg-red-lt text-red' : 'bg-green-lt text-green'}`}>{(questionValidation?.errors || []).length ? 'Needs review' : 'No validation blocker'}</span></div>
                              </div>
                            ) : (
                              <div className="text-muted small">{effectiveNetworkPreview?.errors?.[0] || 'Enter a client network CIDR to preview gateway and DHCP pool values.'}</div>
                            )}
                          </div>
                          {(questionValidation?.errors || []).length > 0 && (
                            <details className="alert alert-danger mb-0">
                              <summary className="fw-semibold cursor-pointer">Fix these answers ({questionValidation.errors.length})</summary>
                              <ul className="mb-0">{questionValidation.errors.map((item, index) => <li key={`answer-error-${index}`}>{item}</li>)}</ul>
                            </details>
                          )}
                          {(questionValidation?.warnings || []).length > 0 && (
                            <div className="alert alert-warning mb-0">
                              <div className="fw-semibold mb-1">Warnings</div>
                              <ul className="mb-0">{questionValidation.warnings.map((item, index) => <li key={`answer-warning-${index}`}>{item}</li>)}</ul>
                            </div>
                          )}
                          {Object.entries(questionGroups).map(([category, questions]) => (
                            <div className="border rounded p-3" key={`question-group-${category}`}>
                              <div className="fw-semibold mb-3">{category}</div>
                              <div className="d-flex flex-column gap-3">
                                {questions.map((question) => (
                                  <div key={question.question_key}>
                                    <label className="form-label mb-1 d-flex align-items-center gap-2">
                                      <span>{question.question_text}</span>
                                      {question.required_for_preview && <span className="badge bg-blue-lt text-blue">Required</span>}
                                      <span className={`badge ${question.answer_status === 'APPROVED' || question.answer_status === 'LOCKED' ? 'bg-green-lt text-green' : question.answer_status === 'AI_SUGGESTED' ? 'bg-purple-lt text-purple' : question.answer_status === 'REJECTED' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary'}`}>{question.answer_status || 'EMPTY'}</span>
                                      {question.locked && <span className="badge bg-yellow-lt text-yellow">Locked</span>}
                                      {question.helper_text && <span className="text-muted d-inline-flex" title={question.helper_text}><IconInfoCircle size={14} /></span>}
                                    </label>
                                    {question.helper_text && <div className="text-muted small mb-1">{question.helper_text}</div>}
                                    {question.suggested_value && question.suggestion_reason && <div className="text-muted small mb-1">AI reason: {question.suggestion_reason}</div>}
                                    {(question.validation_errors || []).length > 0 && <div className="text-red small mb-1">{question.validation_errors.join('; ')}</div>}
                                    <div className="input-group">
                                      {isQuestionAiFilled(question) && <span className="input-group-text bg-purple-lt text-purple" title={`Answered by AI${question.suggestion_confidence ? ` (${question.suggestion_confidence})` : ''}`}><IconRobot size={16} /></span>}
                                      <input className="form-control" value={aiQuestionAnswers[question.question_key] || ''} onChange={(e) => updateAiQuestionAnswer(question.question_key, e.target.value)} placeholder="Answer for this router" disabled={question.locked} />
                                      {question.suggested_value && <button className="btn btn-outline-danger" type="button" onClick={() => clearAiQuestion(question)} title="Clear AI answer"><IconX size={16} /></button>}
                                    </div>
                                    {question.question_key === 'vlan_parent_interface' && interfaceCandidates?.groups?.length > 0 && (
                                      <details className="mt-2">
                                        <summary className="small text-muted">Show scanned interface candidates</summary>
                                        <div className="mt-2 d-flex flex-column gap-2">
                                          {interfaceCandidates.groups.map((group) => (
                                            <div key={`iface-group-${group.group}`}>
                                              <div className="fw-semibold small">{group.group}</div>
                                              <div className="d-flex flex-wrap gap-1">
                                                {group.items.slice(0, 12).map((item) => (
                                                  <button className={`badge border-0 ${item.avoid ? 'bg-red-lt text-red' : 'bg-blue-lt text-blue'}`} type="button" key={`${group.group}-${item.name}`} onClick={() => updateAiQuestionAnswer(question.question_key, item.name)} title={(item.labels || []).join(', ')}>
                                                    {item.name}
                                                  </button>
                                                ))}
                                              </div>
                                            </div>
                                          ))}
                                        </div>
                                      </details>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                          {!aiQuestions.length && <div className="text-muted">No questions loaded yet.</div>}
                        </div>
                      )}
                    </Card>
                  </div>
                  <div className="col-xl-6">
                    <Card title="Draft Deployment Plan" subtitle="Draft only. This is not a RouterOS command list.">
                      <div className="border rounded p-3 mb-3">
                        <div className="fw-semibold mb-2">Draft plan readiness</div>
                        <div className="row g-2">
                          {readinessChecks.map((check) => (
                            <div className="col-md-6" key={`draft-ready-${check.key}`}>
                              <div className="d-flex align-items-start gap-2 small">
                                <span className={`badge ${check.passed ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{check.passed ? <IconCircleCheck size={14} /> : <IconAlertTriangle size={14} />}</span>
                                <div>
                                  <div className="fw-semibold">{check.label}</div>
                                  {!check.passed && <div className="text-muted">{check.message}</div>}
                                </div>
                              </div>
                            </div>
                          ))}
                          {!readinessChecks.length && <div className="text-muted small">Select a router to load readiness checks.</div>}
                        </div>
                        <div className={`alert mt-3 mb-0 ${readyForDraftPlan ? 'alert-success' : 'alert-warning'}`}>
                          {readyForDraftPlan ? 'Ready to generate a draft plan. No RouterOS commands will be generated.' : (mt4Readiness?.message || 'Complete readiness requirements before generating a draft plan.')}
                        </div>
                      </div>
                      <div className="btn-list mb-3">
                        <button className="btn btn-primary" type="button" onClick={generateAiDraftPlan} disabled={!aiOpenAi.configured || !aiRouterId || aiGeneratingPlan || !readyForDraftPlan}>
                          <IconSparkles size={18} className="me-2" />{aiGeneratingPlan ? 'Generating...' : 'Generate Draft Plan'}
                        </button>
                        <button className="btn btn-outline-secondary" type="button" onClick={() => loadAiRouterPlanning()} disabled={!aiRouterId}>
                          <IconRefresh size={18} className="me-2" />Refresh Plans
                        </button>
                      </div>
                      <div className="list-group list-group-flush mb-3">
                        {aiDraftPlans.map((plan) => (
                          <button className={`list-group-item list-group-item-action ${aiSelectedDraftPlan?.id === plan.id ? 'active' : ''}`} type="button" key={plan.id} onClick={() => setAiSelectedDraftPlanId(plan.id)}>
                            <div className="d-flex justify-content-between gap-2">
                              <span>{fmt(plan.created_at)}</span>
                              <span className={`badge ${validationClass(plan.validation_status)}`}>{plan.validation_status}</span>
                            </div>
                            <div className="small">Status: {plan.status}</div>
                          </button>
                        ))}
                        {!aiDraftPlans.length && <div className="text-muted">No draft plans yet.</div>}
                      </div>
                      {aiSelectedDraftPlan && (
                        <pre className="bg-dark text-white rounded p-3 mb-0" style={{ maxHeight: 360, overflow: 'auto', fontSize: 12 }}>{JSON.stringify(aiSelectedDraftPlan.plan_json, null, 2)}</pre>
                      )}
                    </Card>
                  </div>
                  <div className="col-xl-6">
                    <Card title="Safety Validation" subtitle="Deterministic validation checks the AI draft against policy and latest preflight data.">
                      {aiSelectedDraftPlan ? (
                        <div className="d-flex flex-column gap-3">
                          <div className="d-flex flex-wrap gap-2">
                            <span className={`badge ${validationClass(aiSelectedDraftPlan.validation_status)}`}>Validation: {aiSelectedDraftPlan.validation_status}</span>
                            <span className="badge bg-blue-lt text-blue">Plan: {aiSelectedDraftPlan.status}</span>
                            <span className={`badge ${readyForMt4 ? 'bg-green-lt text-green' : 'bg-secondary-lt text-secondary'}`}>MT-4: {readyForMt4 ? 'Ready' : 'Not ready'}</span>
                          </div>
                          {(aiValidation.blockers || []).length > 0 && (
                            <div>
                              <div className="fw-semibold text-red mb-1">Blockers</div>
                              <ul className="mb-0">{aiValidation.blockers.map((item, index) => <li key={`ai-blocker-${index}`}>{item}</li>)}</ul>
                            </div>
                          )}
                          {(aiValidation.warnings || []).length > 0 && (
                            <div>
                              <div className="fw-semibold text-yellow mb-1">Warnings</div>
                              <ul className="mb-0">{aiValidation.warnings.slice(0, 8).map((item, index) => <li key={`ai-warning-${index}`}>{item}</li>)}</ul>
                            </div>
                          )}
                          {(aiValidation.questions_still_needed || []).length > 0 && (
                            <div>
                              <div className="fw-semibold mb-1">Required fixes / questions still needed</div>
                              <ul className="mb-0">{aiValidation.questions_still_needed.map((item, index) => <li key={`ai-question-needed-${index}`}>{item}</li>)}</ul>
                            </div>
                          )}
                          <div className="btn-list">
                            <button className="btn btn-outline-primary" type="button" onClick={() => validateAiDraftPlan()} disabled={aiValidatingPlan}>
                              <IconShieldLock size={18} className="me-2" />{aiValidatingPlan ? 'Validating...' : 'Validate Again'}
                            </button>
                            <button className="btn btn-success" type="button" onClick={() => markAiDraftReady()} disabled={!aiValidation.eligible_for_mt4 || aiSelectedDraftPlan.validation_status === 'BLOCKED'}>
                              <IconCircleCheck size={18} className="me-2" />Mark Ready for MT-4
                            </button>
                          </div>
                          {aiSelectedDraftPlan.validation_status === 'BLOCKED' && <div className="alert alert-danger mb-0">This plan is blocked. The system will not generate RouterOS commands until the issues are fixed.</div>}
                          {aiSelectedDraftPlan.validation_status !== 'BLOCKED' && aiValidation.eligible_for_mt4 && <div className="alert alert-success mb-0">Ready for MT-4 Command Preview. No RouterOS commands are generated or applied yet.</div>}
                        </div>
                      ) : (
                        <div className="empty">Validation status: Not generated. Generate or select a draft plan to see safety validation.</div>
                      )}
                    </Card>
                  </div>
                  <div className="col-12">
                    <Card title="Next Step / MT-4 Readiness">
                      <div className={`alert mb-0 ${readyForMt4 ? 'alert-success' : 'alert-secondary'}`}>
                        {readyForMt4 ? 'Ready for MT-4 Command Preview. No RouterOS commands are generated or applied yet.' : 'MT-3.1 stops at advisory guidance, pilot selection, planning answers, and draft validation. MT-4 will generate exact RouterOS command previews only after readiness and safety checks pass. RouterOS write apply remains disabled.'}
                      </div>
                    </Card>
                  </div>
                </div>
                {aiSmokeModalOpen && (
                  <Modal title="AI Health / Smoke Test" size="lg" onClose={() => setAiSmokeModalOpen(false)}>
                    <div className="d-flex flex-column gap-3">
                      <div className="alert alert-info mb-0">This test sends a small sanitized planning summary to OpenAI. It does not request RouterOS commands.</div>
                      <div className="row g-3">
                        <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">OpenAI</div><div className="fw-semibold">{aiOpenAi.configured ? 'Configured' : 'Not configured'}</div></div></div>
                        <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">Model</div><div className="fw-semibold">{aiOpenAi.model || 'Not set'}</div></div></div>
                        <div className="col-md-4"><div className="border rounded p-3 h-100"><div className="text-muted small">Last result</div><span className={`badge ${smokeStatusTone}`}>{aiSmoke?.status || 'Not run'}</span></div></div>
                      </div>
                      {aiSmoke?.created_at && <div className="text-muted small">Last run: {fmt(aiSmoke.created_at)}</div>}
                      {aiSmoke?.response_summary && <div className="alert alert-success mb-0 small">{aiSmoke.response_summary}</div>}
                      {aiSmoke?.error_message && <div className="alert alert-warning mb-0 small">{aiSmoke.error_message}</div>}
                      <div className="modal-footer px-0 pb-0">
                        <button className="btn" type="button" onClick={() => setAiSmokeModalOpen(false)}>Close</button>
                        <button className="btn btn-primary" type="button" onClick={runAiSmokeTest} disabled={!aiOpenAi.configured || aiSmokeTesting}>
                          <IconBrandOpenai size={18} className="me-2" />{aiSmokeTesting ? 'Testing...' : 'Run AI Smoke Test'}
                        </button>
                      </div>
                    </div>
                  </Modal>
                )}
                {pilotModalOpen && (
                  <Modal title="Pilot Router Selection" size="lg" onClose={() => setPilotModalOpen(false)}>
                    <div className="d-flex flex-column gap-3">
                      <div className="alert alert-info mb-0">Choose exactly one pilot router before MT-4. This does not apply MikroTik configuration.</div>
                      {selectedPilot && (
                        <div className="alert alert-primary mb-0">
                          <div className="fw-semibold">Current pilot: {selectedPilot.router_name}</div>
                          <div className="small">{selectedPilot.host}</div>
                        </div>
                      )}
                      <div>
                        <label className="form-label">Selected Pilot Router</label>
                        <select className="form-select" value={pilotForm.router_id || aiRouterId || ''} onChange={(e) => { setPilotForm({ ...pilotForm, router_id: e.target.value }); setAiRouterId(e.target.value); loadAiRouterPlanning(e.target.value); }}>
                          <option value="">Choose router</option>
                          {mikrotiks.map((router) => <option value={router.id} key={`pilot-modal-${router.id}`}>{router.router_name} - {router.host}:{router.api_port}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="form-label">Reason for pilot selection</label>
                        <textarea className="form-control" rows="2" value={pilotForm.reason} onChange={(e) => setPilotForm({ ...pilotForm, reason: e.target.value })} placeholder="Example: office router, easy to recover, good first test site" />
                      </div>
                      <div>
                        <label className="form-label">Physical recovery confidence</label>
                        <select className="form-select" value={pilotForm.physical_recovery_confidence} onChange={(e) => setPilotForm({ ...pilotForm, physical_recovery_confidence: e.target.value })}>
                          <option value="EASY_TO_RECOVER">Easy to recover</option>
                          <option value="MODERATE">Moderate</option>
                          <option value="HARD_REMOTE_SITE">Hard remote site</option>
                        </select>
                      </div>
                      <div>
                        <label className="form-label">Operator note</label>
                        <textarea className="form-control" rows="2" value={pilotForm.operator_note} onChange={(e) => setPilotForm({ ...pilotForm, operator_note: e.target.value })} placeholder="Optional note for the next engineer/operator" />
                      </div>
                      <div className="modal-footer px-0 pb-0">
                        <button className="btn" type="button" onClick={() => setPilotModalOpen(false)}>Close</button>
                        <button className="btn btn-outline-secondary" type="button" onClick={clearPilotRouter} disabled={pilotSaving || !selectedPilot}>Clear Pilot Selection</button>
                        <button className="btn btn-primary" type="button" onClick={() => selectPilotRouter()} disabled={pilotSaving || !(pilotForm.router_id || aiRouterId)}>
                          <IconCircleCheck size={18} className="me-2" />Select as Pilot
                        </button>
                      </div>
                    </div>
                  </Modal>
                )}
                {questionsModalOpen && (
                  <Modal title={aiActiveRouter ? `Missing Questions - ${aiActiveRouter.router_name}` : 'Missing Questions'} size="xl" onClose={() => setQuestionsModalOpen(false)}>
                    {!aiRouterId && <div className="empty">Select a router first.</div>}
                    {aiRouterId && (
                      <div className="d-flex flex-column gap-3">
                        <div className="alert alert-info mb-0">
                          <div className="fw-semibold">Router selected: {aiActiveRouterLabel || aiRouterId}</div>
                          <div className="small">These planning questions are bound to this MikroTik router only. Use the Routers Overview table to open questions for a different router.</div>
                        </div>
                        <div className="alert alert-warning mb-0">
                          <div className="fw-semibold">PPPoE AC policy and VLAN path reminder</div>
                          <div className="small">PPPoE access concentrator does not automatically mean read-only. It means the router is sensitive. Captive portal can still be planned here only if the new HotSpot network uses a dedicated VLAN/subnet and does not touch PPPoE, OSPF, WireGuard, routing, or existing production objects.</div>
                          <div className="small mt-1">The VLAN parent interface is the bridge or trunk on the HotSpot gateway that carries customer VLAN traffic toward CRS/OLT/APs. Do not choose a physical port like ether1 unless the AP/customer VLAN path is confirmed.</div>
                        </div>
                        <div className="d-flex align-items-center justify-content-between gap-2 flex-wrap">
                          <div>
                            <div className="fw-semibold">Answered {answeredRequired} of {totalRequired} required questions</div>
                            <div className="progress mt-2" style={{ width: 260, maxWidth: '100%' }}>
                              <div className="progress-bar" style={{ width: `${totalRequired ? Math.round((answeredRequired / totalRequired) * 100) : 0}%` }} />
                            </div>
                          </div>
                          <div className="btn-list">
                            <button className="btn btn-outline-primary" type="button" onClick={suggestAiAnswers} disabled={!aiOpenAi.configured || aiSuggestingAnswers}><IconSparkles size={18} className="me-2" />{aiSuggestingAnswers ? 'Suggesting...' : 'Suggest Answers with AI'}</button>
                            <button className="btn btn-outline-secondary" type="button" onClick={validateAiAnswers} disabled={aiValidatingAnswers}><IconShieldLock size={18} className="me-2" />{aiValidatingAnswers ? 'Validating...' : 'Validate Answers'}</button>
                            <button className="btn btn-primary" type="button" onClick={saveAllAiQuestions} disabled={aiSavingQuestions}><IconDeviceFloppy size={18} className="me-2" />{aiSavingQuestions ? 'Saving...' : 'Save All'}</button>
                          </div>
                        </div>
                        <ul className="nav nav-tabs">
                          <li className="nav-item">
                            <button className={`nav-link ${questionsPhaseTab === 'vlan-path' ? 'active' : ''}`} type="button" onClick={() => setQuestionsPhaseTab('vlan-path')}>
                              Phase 1: VLAN Path
                              <span className={`badge ms-2 ${vlanPathValidation?.complete ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{vlanPathValidation?.complete ? 'Ready' : 'Needs review'}</span>
                            </button>
                          </li>
                          <li className="nav-item">
                            <button className={`nav-link ${questionsPhaseTab === 'planning' ? 'active' : ''}`} type="button" onClick={() => setQuestionsPhaseTab('planning')}>
                              Phase 2: Planning Answers
                              <span className={`badge ms-2 ${questionValidation?.complete ? 'bg-green-lt text-green' : answeredRequired ? 'bg-yellow-lt text-yellow' : 'bg-secondary-lt text-secondary'}`}>{answeredRequired}/{totalRequired}</span>
                            </button>
                          </li>
                        </ul>
                        {questionsPhaseTab === 'vlan-path' && (
                          <>
                        <div className="border rounded p-3">
                          <div className="d-flex justify-content-between gap-2 flex-wrap mb-3">
                            <div>
                              <div className="text-muted small text-uppercase">Phase 1 of 2</div>
                              <div className="fw-semibold">VLAN Path Planner</div>
                              <div className="text-muted small">Complete this first. It describes how the customer VLAN leaves the HotSpot gateway and travels toward CRS, OLTs, ONU/APs, and the Omada SSID. This is planning only; no MikroTik configuration is applied.</div>
                            </div>
                            <div className="d-flex align-items-start gap-2 flex-wrap">
                              <button className="btn btn-outline-primary btn-sm" type="button" onClick={suggestAiAnswers} disabled={!aiOpenAi.configured || aiSuggestingAnswers}><IconSparkles size={16} className="me-1" />{aiSuggestingAnswers ? 'Suggesting...' : 'Suggest Answers with AI'}</button>
                              <button className="btn btn-outline-secondary btn-sm" type="button" onClick={validateAiAnswers} disabled={aiValidatingAnswers}><IconShieldLock size={16} className="me-1" />Validate</button>
                              <span className={`badge ${vlanPathValidation?.complete ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{vlanPathPlan?.confirmation_status || 'DRAFT'}</span>
                            </div>
                          </div>
                          <div className="row g-2 mb-3">
                            {[
                              ['1', 'Pilot + VLAN', aiQuestionAnswers.customer_vlan_id ? `Customer VLAN ${aiQuestionAnswers.customer_vlan_id}` : 'Customer VLAN unanswered'],
                              ['2', 'Gateway parent', vlanPathPlan?.gateway_parent_interface || 'Choose bridge/trunk'],
                              ['3', 'Next hop', vlanPathPlan?.next_hop_type && vlanPathPlan.next_hop_type !== 'UNKNOWN' ? vlanPathPlan.next_hop_type : 'Choose next device'],
                              ['4', 'CRS / OLT path', vlanPathPlan?.crs_involved || vlanPathPlan?.olts_involved ? 'Path details started' : 'Path not described'],
                              ['5', 'Confirm', vlanPathPlan?.confirmation_status === 'CONFIRMED' ? 'Confirmed' : 'Needs review']
                            ].map(([number, title, detail]) => (
                              <div className="col-md" key={`vlan-path-step-${number}`}>
                                <div className="border rounded p-2 h-100 bg-light">
                                  <div className="d-flex align-items-center gap-2">
                                    <span className="badge bg-blue-lt text-blue">{number}</span>
                                    <span className="fw-semibold small">{title}</span>
                                  </div>
                                  <div className="text-muted small mt-1 text-truncate" title={detail}>{detail}</div>
                                </div>
                              </div>
                            ))}
                          </div>
                          {(vlanPathValidation?.errors || []).length > 0 && <div className="alert alert-danger py-2"><ul className="mb-0">{vlanPathValidation.errors.map((item, index) => <li key={`vlan-path-error-${index}`}>{item}</li>)}</ul></div>}
                          {(vlanPathValidation?.warnings || []).length > 0 && <div className="alert alert-warning py-2"><ul className="mb-0">{vlanPathValidation.warnings.map((item, index) => <li key={`vlan-path-warning-${index}`}>{item}</li>)}</ul></div>}
                          <div className="row g-3 mb-3">
                            {phaseOneQuestionPanels.map((panel) => (
                              <div className="col-lg-6" key={`phase-one-panel-${panel.title}`}>
                                <div className="border rounded p-3 h-100 bg-light">
                                  <div className="fw-semibold">{panel.title}</div>
                                  <div className="text-muted small mb-3">{panel.description}</div>
                                  <div className="d-flex flex-column gap-3">
                                    {panel.questions.map((question) => renderPlanningQuestionField(question))}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                          <div className="row g-3">
                            <div className="col-lg-6">
                              <div className="border rounded p-3 h-100">
                                <div className="fw-semibold mb-1">Gateway And First Hop</div>
                                <div className="text-muted small mb-3">Identify the HotSpot gateway and the first device carrying customer VLAN traffic away from it.</div>
                                <div className="row g-3">
                                  <div className="col-12">
                                    <label className="form-label">HotSpot Gateway Router</label>
                                    <input className="form-control" value={aiActiveRouterLabel || aiRouterId} disabled />
                                  </div>
                                  <div className="col-12">
                                    <label className="form-label">Gateway VLAN Parent Interface / Bridge</label>
                                    <input className="form-control" value={vlanPathPlan?.gateway_parent_interface || ''} onFocus={() => openInterfacePicker('vlan_parent_interface', 'Choose gateway VLAN parent interface / bridge', { preferredGroups: ['bridge interfaces', 'vlan-filtered bridges', 'likely trunks', 'bridge ports', 'physical interfaces'] })} onChange={(e) => { updateVlanPathPlan({ gateway_parent_interface: e.target.value }); updateAiQuestionAnswer('vlan_parent_interface', e.target.value); }} placeholder="Click to choose bridge/trunk" />
                                    <div className="text-muted small mt-1">Choose the bridge or trunk on the HotSpot gateway that carries the customer VLAN toward the AP path.</div>
                                  </div>
                                  <div className="col-12">
                                    <label className="form-label d-flex align-items-center gap-1">Next Hop Device <span className="text-muted" title="This is the first device after the HotSpot gateway on the path to AP clients. Example: MikroTik gateway -> CRS -> OLT -> ONU/AP means the next hop is CRS. If the AP is directly connected to the gateway, choose Direct AP."><IconInfoCircle size={14} /></span></label>
                                    <select className="form-select" value={vlanPathPlan?.next_hop_type || 'UNKNOWN'} onChange={(e) => updateVlanPathPlan({ next_hop_type: e.target.value })}>
                                      <option value="UNKNOWN">Unknown</option>
                                      <option value="CRS">CRS</option>
                                      <option value="OLT">OLT</option>
                                      <option value="SWITCH">Switch</option>
                                      <option value="DIRECT_AP">Direct AP</option>
                                    </select>
                                  </div>
                                  <div className="col-12">
                                    <label className="form-label">Customer VLAN used by Open SSID</label>
                                    <input className="form-control" value={aiQuestionAnswers.customer_vlan_id ? `Uses customer VLAN ${aiQuestionAnswers.customer_vlan_id}` : 'Answer the customer VLAN question above'} disabled />
                                    <div className="text-muted small mt-1">No separate Omada/Open SSID VLAN ID is needed. The open captive portal SSID uses the customer VLAN ID from the prerequisite answer.</div>
                                  </div>
                                </div>
                              </div>
                            </div>
                            <div className="col-lg-6">
                              <div className="border rounded p-3 h-100">
                                <div className="fw-semibold mb-1">CRS / Switch Path</div>
                                <div className="text-muted small mb-3">Fill this only when traffic passes through a CRS or switch before OLTs/APs.</div>
                                <div className="row g-3">
                                  <div className="col-md-6">
                                    <label className="form-label">CRS Involved?</label>
                                    <select className="form-select" value={vlanPathPlan?.crs_involved ? 'yes' : 'no'} onChange={(e) => updateVlanPathPlan({ crs_involved: e.target.value === 'yes' })}>
                                      <option value="no">No</option>
                                      <option value="yes">Yes</option>
                                    </select>
                                  </div>
                                  <div className="col-md-6">
                                    <label className="form-label">CRS Device</label>
                                    <select className="form-select" value={vlanPathPlan?.crs_router_id || ''} onChange={(e) => updateVlanPathPlan({ crs_router_id: e.target.value })}>
                                      <option value="">Unknown / not selected</option>
                                      {mikrotiks.map((router) => <option value={router.id} key={`vlan-crs-${router.id}`}>{router.router_name}</option>)}
                                    </select>
                                  </div>
                                  <div className="col-md-6">
                                    <label className="form-label">CRS Port Toward Gateway</label>
                                    <input className="form-control" value={vlanPathPlan?.crs_port_to_gateway || ''} onFocus={() => openInterfacePicker('crs_port_to_gateway', 'Choose CRS port toward HotSpot gateway', { preferredGroups: ['likely trunks', 'bridge ports', 'physical interfaces'] })} onChange={(e) => updateVlanPathPlan({ crs_port_to_gateway: e.target.value })} placeholder="Click to choose or type" />
                                  </div>
                                  <div className="col-md-6">
                                    <label className="form-label">CRS Port(s) Toward OLT/AP</label>
                                    <input className="form-control" value={vlanPathPlan?.crs_ports_to_olt_ap || ''} onFocus={() => openInterfacePicker('crs_ports_to_olt_ap', 'Choose CRS ports toward OLT/AP', { multiple: true, preferredGroups: ['likely trunks', 'bridge ports', 'physical interfaces'] })} onChange={(e) => updateVlanPathPlan({ crs_ports_to_olt_ap: e.target.value })} placeholder="Click to choose multiple or type" />
                                  </div>
                                </div>
                              </div>
                            </div>
                            <div className="col-lg-7">
                              <div className="border rounded p-3 h-100">
                                <div className="fw-semibold mb-1">OLT / AP Handoff</div>
                                <div className="text-muted small mb-3">Describe how the VLAN behaves after it leaves the MikroTik/CRS path.</div>
                                <div className="row g-3">
                                  <div className="col-md-4">
                                    <label className="form-label">OLTs Involved?</label>
                                    <select className="form-select" value={vlanPathPlan?.olts_involved ? 'yes' : 'no'} onChange={(e) => updateVlanPathPlan({ olts_involved: e.target.value === 'yes' })}>
                                      <option value="no">No</option>
                                      <option value="yes">Yes</option>
                                    </select>
                                  </div>
                                  <div className="col-md-4">
                                    <label className="form-label">OLT VLAN Behavior</label>
                                    <select className="form-select" value={vlanPathPlan?.olt_vlan_behavior || 'UNKNOWN'} onChange={(e) => updateVlanPathPlan({ olt_vlan_behavior: e.target.value })}>
                                      <option value="UNKNOWN">Unknown</option>
                                      <option value="TRANSPARENT">Passes VLAN transparently</option>
                                      <option value="TRANSLATED">Translates VLAN</option>
                                    </select>
                                  </div>
                                  <div className="col-md-4">
                                    <label className="form-label">AP Receives VLAN As</label>
                                    <select className="form-select" value={vlanPathPlan?.ap_vlan_mode || 'UNKNOWN'} onChange={(e) => updateVlanPathPlan({ ap_vlan_mode: e.target.value })}>
                                      <option value="UNKNOWN">Unknown</option>
                                      <option value="TAGGED">Tagged VLAN</option>
                                      <option value="UNTAGGED">Untagged / access VLAN</option>
                                    </select>
                                  </div>
                                  <div className="col-12">
                                    <label className="form-label">OLT Names / Notes</label>
                                    <textarea className="form-control" rows="2" value={vlanPathPlan?.olt_notes || ''} onChange={(e) => updateVlanPathPlan({ olt_notes: e.target.value })} placeholder="Describe CRS -> OLT -> ONU/AP path, VLAN pass-through, or unknown areas." />
                                  </div>
                                </div>
                              </div>
                            </div>
                            <div className="col-lg-5">
                              <div className="border rounded p-3 h-100">
                                <div className="fw-semibold mb-1">Review And Save Path</div>
                                <div className="text-muted small mb-3">Save this phase before moving to Phase 2. Confirm only after the physical path is reviewed.</div>
                                <label className="form-label">Confirmation Status</label>
                                <select className="form-select mb-3" value={vlanPathPlan?.confirmation_status || 'DRAFT'} onChange={(e) => updateVlanPathPlan({ confirmation_status: e.target.value })}>
                                  <option value="DRAFT">Draft</option>
                                  <option value="NEEDS_REVIEW">Needs Review</option>
                                  <option value="CONFIRMED">Confirmed</option>
                                </select>
                                <button className="btn btn-outline-primary w-100" type="button" onClick={saveVlanPathPlan} disabled={vlanPathSaving}>
                                  <IconDeviceFloppy size={18} className="me-2" />{vlanPathSaving ? 'Saving...' : 'Save VLAN Path Plan'}
                                </button>
                              </div>
                            </div>
                          </div>
                          {interfacePicker && interfaceCandidates?.groups?.length > 0 && (
                            <div className="border rounded p-3 mt-3 bg-light">
                              <div className="d-flex justify-content-between align-items-start gap-2 mb-2">
                                <div>
                                  <div className="fw-semibold">{interfacePicker.label}</div>
                                  <div className="text-muted small">{interfacePicker.description}</div>
                                  <div className="text-muted small">{interfacePicker.multiple ? 'Multiple selection is allowed. Click more than one port to add it to the field.' : 'Single selection. Click one item to fill the field.'}</div>
                                </div>
                                <button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => setInterfacePicker(null)}><IconX size={14} /></button>
                              </div>
                              <div className="row g-2">
                                {interfaceCandidates.groups
                                  .filter((group) => !interfacePicker.preferredGroups.length || interfacePicker.preferredGroups.includes(group.group) || group.group === 'sensitive / avoid')
                                  .map((group) => (
                                  <div className="col-md-6" key={`picker-interface-${group.group}`}>
                                    <div className="border rounded p-2 h-100 bg-white">
                                      <div className="fw-semibold small mb-2">{group.group}</div>
                                      <div className="d-flex flex-column gap-2">
                                        {group.items.slice(0, 12).map((item) => (
                                          <button className={`btn btn-sm text-start ${item.avoid ? 'btn-outline-danger' : 'btn-outline-secondary'}`} type="button" key={`${group.group}-${item.name}`} onClick={() => chooseInterfaceCandidate(item)}>
                                            <div className="fw-semibold">{item.name} <span className="text-muted">({item.type || 'unknown'})</span></div>
                                            <div className="small text-muted">{[item.bridge_membership ? `bridge: ${item.bridge_membership}` : '', item.vlan_filtering ? 'VLAN filtering' : '', ...(item.existing_vlans || []).map((vlan) => `VLAN ${vlan}`)].filter(Boolean).join(' / ') || 'No extra path details found'}</div>
                                            <div className="mt-1 d-flex flex-wrap gap-1">{(item.labels || []).slice(0, 5).map((label) => <span className={`badge ${item.avoid ? 'bg-red-lt text-red' : 'bg-blue-lt text-blue'}`} key={`${item.name}-${label}`}>{label}</span>)}</div>
                                          </button>
                                        ))}
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                          </>
                        )}
                        {questionsPhaseTab === 'planning' && (
                          <>
                        <div className="d-flex align-items-center justify-content-between gap-2 flex-wrap">
                          <div>
                            <div className="text-muted small text-uppercase">Phase 2 of 2</div>
                            <div className="fw-semibold">Remaining Planning Questions</div>
                            <div className="text-muted small">After the VLAN path is described, review the rest of the pilot values and save them for MT-4 readiness.</div>
                          </div>
                        </div>
                        <div className="border rounded p-3 bg-light">
                          <div className="fw-semibold mb-2">Network Preview</div>
                          {effectiveNetworkPreview?.status === 'SUCCESS' ? (
                            <div className="row g-2 small">
                              <div className="col-md-6"><span className="text-muted">CIDR:</span> <span className="fw-semibold">{effectiveNetworkPreview.cidr}</span></div>
                              <div className="col-md-6"><span className="text-muted">Range:</span> <span className="fw-semibold">{effectiveNetworkPreview.range}</span></div>
                              <div className="col-md-6"><span className="text-muted">Gateway:</span> <span className="fw-semibold">{effectiveNetworkPreview.gateway_ip}</span></div>
                              <div className="col-md-6"><span className="text-muted">DHCP Pool:</span> <span className="fw-semibold">{effectiveNetworkPreview.dhcp_pool}</span></div>
                              <div className="col-md-6"><span className="text-muted">Usable hosts:</span> <span className="fw-semibold">{effectiveNetworkPreview.usable_hosts}</span></div>
                              <div className="col-md-6"><span className="text-muted">Conflict status:</span> <span className={`badge ${(questionValidation?.errors || []).length ? 'bg-red-lt text-red' : 'bg-green-lt text-green'}`}>{(questionValidation?.errors || []).length ? 'Needs review' : 'No validation blocker'}</span></div>
                            </div>
                          ) : (
                            <div className="text-muted small">{effectiveNetworkPreview?.errors?.[0] || 'Enter a client network CIDR to preview gateway and DHCP pool values.'}</div>
                          )}
                        </div>
                        {(questionValidation?.errors || []).length > 0 && (
                          <details className="alert alert-danger mb-0">
                            <summary className="fw-semibold cursor-pointer">Fix these answers ({questionValidation.errors.length})</summary>
                            <ul className="mb-0 mt-2">{questionValidation.errors.map((item, index) => <li key={`modal-answer-error-${index}`}>{item}</li>)}</ul>
                          </details>
                        )}
                        <div className="ai-question-modal-list">
                          {Object.entries(phaseTwoQuestionGroups).map(([category, questions]) => (
                            <div className="border rounded p-3" key={`modal-question-group-${category}`}>
                              <div className="fw-semibold mb-3">{category}</div>
                              <div className="d-flex flex-column gap-3">
                                {questions.map((question) => renderPlanningQuestionField(question))}
                              </div>
                            </div>
                          ))}
                          {!Object.keys(phaseTwoQuestionGroups).length && <div className="empty">No Phase 2 questions loaded yet.</div>}
                        </div>
                          </>
                        )}
                      </div>
                    )}
                  </Modal>
                )}
                {draftPlanModalOpen && (
                  <Modal title="Draft Deployment Plan" size="xl" onClose={() => setDraftPlanModalOpen(false)}>
                    <div className="row g-3">
                      <div className="col-lg-6">
                        <div className="border rounded p-3 mb-3">
                          <div className="fw-semibold mb-2">Draft plan readiness</div>
                          <div className="row g-2">
                            {readinessChecks.map((check) => (
                              <div className="col-md-6" key={`modal-draft-ready-${check.key}`}>
                                <div className="d-flex align-items-start gap-2 small">
                                  <span className={`badge ${check.passed ? 'bg-green-lt text-green' : 'bg-yellow-lt text-yellow'}`}>{check.passed ? <IconCircleCheck size={14} /> : <IconAlertTriangle size={14} />}</span>
                                  <div><div className="fw-semibold">{check.label}</div>{!check.passed && <div className="text-muted">{check.message}</div>}</div>
                                </div>
                              </div>
                            ))}
                          </div>
                          <div className={`alert mt-3 mb-0 ${readyForDraftPlan ? 'alert-success' : 'alert-warning'}`}>{readyForDraftPlan ? 'Ready to generate a draft plan. No RouterOS commands will be generated.' : (mt4Readiness?.message || 'Complete readiness requirements before generating a draft plan.')}</div>
                        </div>
                        <div className="btn-list mb-3">
                          <button className="btn btn-primary" type="button" onClick={generateAiDraftPlan} disabled={!aiOpenAi.configured || !aiRouterId || aiGeneratingPlan || !readyForDraftPlan}><IconSparkles size={18} className="me-2" />{aiGeneratingPlan ? 'Generating...' : 'Generate Draft Plan'}</button>
                          <button className="btn btn-outline-secondary" type="button" onClick={() => loadAiRouterPlanning()} disabled={!aiRouterId}><IconRefresh size={18} className="me-2" />Refresh Plans</button>
                        </div>
                        <div className="list-group list-group-flush mb-3">
                          {aiDraftPlans.map((plan) => (
                            <button className={`list-group-item list-group-item-action ${aiSelectedDraftPlan?.id === plan.id ? 'active' : ''}`} type="button" key={`modal-plan-${plan.id}`} onClick={() => setAiSelectedDraftPlanId(plan.id)}>
                              <div className="d-flex justify-content-between gap-2"><span>{fmt(plan.created_at)}</span><span className={`badge ${validationClass(plan.validation_status)}`}>{plan.validation_status}</span></div>
                              <div className="small">Status: {plan.status}</div>
                            </button>
                          ))}
                          {!aiDraftPlans.length && <div className="text-muted">No draft plans yet.</div>}
                        </div>
                      </div>
                      <div className="col-lg-6">
                        <div className="border rounded p-3 h-100">
                          <div className="fw-semibold mb-2">Safety Validation</div>
                          {aiSelectedDraftPlan ? (
                            <div className="d-flex flex-column gap-3">
                              <div className="d-flex flex-wrap gap-2"><span className={`badge ${validationClass(aiSelectedDraftPlan.validation_status)}`}>Validation: {aiSelectedDraftPlan.validation_status}</span><span className={`badge ${readyForMt4 ? 'bg-green-lt text-green' : 'bg-secondary-lt text-secondary'}`}>MT-4: {readyForMt4 ? 'Ready' : 'Not ready'}</span></div>
                              {(aiValidation.blockers || []).length > 0 && <div><div className="fw-semibold text-red mb-1">Blockers</div><ul>{aiValidation.blockers.map((item, index) => <li key={`modal-ai-blocker-${index}`}>{item}</li>)}</ul></div>}
                              {(aiValidation.warnings || []).length > 0 && <div><div className="fw-semibold text-yellow mb-1">Warnings</div><ul>{aiValidation.warnings.slice(0, 8).map((item, index) => <li key={`modal-ai-warning-${index}`}>{item}</li>)}</ul></div>}
                              <div className="btn-list">
                                <button className="btn btn-outline-primary" type="button" onClick={() => validateAiDraftPlan()} disabled={aiValidatingPlan}><IconShieldLock size={18} className="me-2" />{aiValidatingPlan ? 'Validating...' : 'Validate Again'}</button>
                                <button className="btn btn-success" type="button" onClick={() => markAiDraftReady()} disabled={!aiValidation.eligible_for_mt4 || aiSelectedDraftPlan.validation_status === 'BLOCKED'}><IconCircleCheck size={18} className="me-2" />Mark Ready for MT-4</button>
                              </div>
                              <pre className="bg-dark text-white rounded p-3 mb-0" style={{ maxHeight: 320, overflow: 'auto', fontSize: 12 }}>{JSON.stringify(aiSelectedDraftPlan.plan_json, null, 2)}</pre>
                            </div>
                          ) : <div className="empty">No draft plan selected.</div>}
                        </div>
                      </div>
                    </div>
                  </Modal>
                )}
                {aiChatOpen && (
                  <div className="ai-chat-drawer">
                    <div className="ai-chat-drawer-header">
                      <div><div className="fw-semibold">AI Network Chat</div><div className="text-muted small">Guidance only. No RouterOS commands.</div></div>
                      <button className="btn-close" type="button" aria-label="Close" onClick={() => setAiChatOpen(false)} />
                    </div>
                    <div className="ai-chat-drawer-body">
                      {!aiOpenAi.configured && <div className="alert alert-warning">AI is not configured.</div>}
                      <div className="d-flex flex-wrap gap-2 mb-3">
                        {guidedAiPrompts.map((prompt) => <button className="btn btn-sm btn-outline-secondary" type="button" key={`drawer-prompt-${prompt}`} onClick={() => setAiInput(prompt)}>{prompt}</button>)}
                      </div>
                      <div className="ai-chat-messages">
                        {aiMessages.map((item) => (
                          <div className={`mb-3 ${item.role === 'USER' ? 'text-end' : ''}`} key={`drawer-message-${item.id}`}>
                            <div className={`d-inline-block p-2 rounded ${item.role === 'USER' ? 'bg-primary text-white' : 'bg-white border'}`} style={{ maxWidth: '90%', whiteSpace: 'pre-wrap' }}>{item.message_text}</div>
                          </div>
                        ))}
                        {!aiMessages.length && <div className="text-muted">Click a prompt or ask a planning question.</div>}
                      </div>
                    </div>
                    <form className="ai-chat-drawer-footer" onSubmit={sendAiMessage}>
                      <input className="form-control" value={aiInput} onChange={(e) => setAiInput(e.target.value)} placeholder="Ask about scan results, VLANs, NAT, or pilot choice" disabled={!aiOpenAi.configured || aiSending} />
                      <button className="btn btn-primary" disabled={!aiOpenAi.configured || aiSending || !aiInput.trim()}><IconRobot size={18} /></button>
                    </form>
                  </div>
                )}
                {actionResult && <div className={`alert mt-3 mb-0 ${actionResult.status === 'SUCCESS' ? 'alert-success' : actionResult.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>{actionResult.message || actionResult.status}</div>}
              </>}
              {mikrotikTab === 'Add Router' && <form onSubmit={saveMikrotikRows}>
                <div className="alert alert-warning">
                  <div className="fw-semibold mb-1">MikroTik account requirement</div>
                  <div>A dedicated <strong>full/write RouterOS API account is required</strong>. The system will need write access to configure HotSpot, walled garden, client authorization, and portal enforcement. Do not use your main MikroTik admin account; create a dedicated automation account with only the required RouterOS policies.</div>
                </div>
                <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
                  <div>
                    <h3 className="card-title mb-1">MikroTik Routers</h3>
                    <div className="text-muted small">Add each gateway once here. Use the inline rows, then save the router list.</div>
                  </div>
                  <button className="btn btn-outline-primary" type="button" onClick={addMikrotikRow}>
                    <IconRouter size={18} className="me-2" />Add Router
                  </button>
                </div>
	                <div className="text-muted small mb-3">
	                  Add only the RouterOS API connection details here. Dedicated captive portal network values are configured later in a station plan after read-only scan data is available.
	                </div>
                <div className="table-responsive">
                  <table className="table table-vcenter mikrotik-router-table">
                    <thead>
                      <tr>
                        <th title="Friendly label for this MikroTik gateway.">Name</th>
                        <th title="Router IP or hostname for RouterOS API.">Host</th>
                        <th title="API port 8728 or API-SSL port 8729.">Port</th>
                        <th title="RouterOS API username.">Username</th>
	                        <th title="RouterOS API password.">Password</th>
		                        <th title="Use API-SSL only if configured on the router.">TLS</th>
		                        <th>Status</th>
		                        <th title="Try connecting to the RouterOS API.">Test</th>
		                        <th title="Mark for removal, then save.">Remove</th>
                      </tr>
                    </thead>
                    <tbody>
	                      {mikrotikRows.map((router) => (
	                        <React.Fragment key={router.id}>
	                        <tr className={router._remove ? 'table-danger' : ''}>
	                          <td><input className="form-control" value={router.router_name || ''} onChange={(e) => updateMikrotikRow(router.id, { router_name: e.target.value })} placeholder="Router Name" /></td>
	                          <td><input className="form-control" value={router.host || ''} onChange={(e) => updateMikrotikRow(router.id, { host: e.target.value })} placeholder="192.168.50.1" /></td>
	                          <td><input className="form-control" type="number" min="1" max="65535" value={router.api_port || 8728} onChange={(e) => updateMikrotikRow(router.id, { api_port: Number(e.target.value) })} /></td>
	                          <td><input className="form-control" value={router.username || ''} onChange={(e) => updateMikrotikRow(router.id, { username: e.target.value })} placeholder="api-user" /></td>
	                          <td><input className="form-control" type="password" value={router.password || ''} onChange={(e) => updateMikrotikRow(router.id, { password: e.target.value })} placeholder={router.has_password ? 'Leave blank to keep saved' : 'Password'} /></td>
	                          <td><label className="form-check form-switch mb-0"><input className="form-check-input" type="checkbox" checked={Boolean(router.use_tls)} onChange={(e) => updateMikrotikRow(router.id, { use_tls: e.target.checked })} /></label></td>
	                          <td>
                            <div className="d-flex flex-column gap-1">
                              <span className={`badge ${router.status === 'REACHABLE' ? 'bg-green-lt text-green' : router.status === 'AUTH_FAILED' ? 'bg-yellow-lt text-yellow' : router.status === 'UNREACHABLE' || router.status === 'ERROR' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary'}`}>{router.status || 'NOT_TESTED'}</span>
                              {router.last_error && <span className="text-muted small text-truncate" title={router.last_error}>{router.last_error}</span>}
                            </div>
                          </td>
                          <td><button className="btn btn-outline-primary btn-sm" type="button" onClick={() => testMikrotik(router.id)} disabled={router._isNew || router._remove} title={router._isNew ? 'Save this router before testing.' : 'Test RouterOS API connection'}><IconRefresh size={15} className="me-1" />Test</button></td>
                          <td><label className="form-check mb-0"><input className="form-check-input" type="checkbox" checked={Boolean(router._remove)} onChange={(e) => updateMikrotikRow(router.id, { _remove: e.target.checked })} /><span className="form-check-label text-muted">Remove</span></label></td>
                        </tr>
	                        </React.Fragment>
                      ))}
	                      {!mikrotikRows.length && <tr><td colSpan="9" className="text-muted p-4">No MikroTik routers added yet.</td></tr>}
	                    </tbody>
	                  </table>
	                </div>
	                <div className="text-muted small mt-2">Saved passwords are kept when the password field is left blank. Use port <code>8728</code> for normal API or <code>8729</code> for API-SSL. After saving, return to Configuration and run a read-only scan from the router table before adding station network values.</div>
                {actionResult && <div className={`alert mt-3 mb-0 ${actionResult.status === 'REACHABLE' || actionResult.status === 'SUCCESS' ? 'alert-success' : actionResult.status === 'RUNNING' ? 'alert-info' : 'alert-warning'}`}>{actionResult.message || actionResult.status}</div>}
                <div className="d-flex justify-content-end mt-3">
                  <button className="btn btn-primary" type="submit"><IconDeviceFloppy size={18} className="me-2" />Save Routers</button>
                </div>
              </form>}
            </div>
          </div>
        </div>
      </>}
      {activeTab === 'Portal Settings' && <>
        <div className="col-12">
          <Card title="Portal Settings">
            {portalSettings ? <form onSubmit={savePortalSettings}>
              <div className="row g-3">
                <div className="col-md-4"><label className="form-label">Default Unlimited Duration</label><input className="form-control" type="number" value={portalSettings.default_access_duration_seconds || 86400} onChange={(e) => setPortalSettings({ ...portalSettings, default_access_duration_seconds: Number(e.target.value) })} /></div>
                <div className="col-md-6"><label className="form-label">Staging Portal URL</label><input className="form-control" value={portalSettings.portal_url_staging || ''} onChange={(e) => setPortalSettings({ ...portalSettings, portal_url_staging: e.target.value })} /></div>
                <div className="col-md-6"><label className="form-label">Production Portal URL</label><input className="form-control" value={portalSettings.portal_url_production || ''} onChange={(e) => setPortalSettings({ ...portalSettings, portal_url_production: e.target.value })} /></div>
                <div className="col-12"><label className="form-label">Post-login Redirect URL</label><input className="form-control" value={portalSettings.post_login_redirect_url || ''} onChange={(e) => setPortalSettings({ ...portalSettings, post_login_redirect_url: e.target.value })} /></div>
                <div className="col-12"><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Settings</button></div>
              </div>
            </form> : <div className="empty">Loading portal settings...</div>}
          </Card>
        </div>
        <div className="col-12">
          <Card title="Portal Branding">
            {settings ? <form onSubmit={saveBranding}>
              <div className="row g-3">
                <div className="col-md-4"><label className="form-label">Portal Title</label><input className="form-control" value={settings.branding?.portal_title || '3J WiFi'} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_title: e.target.value } })} /></div>
                <div className="col-md-4"><label className="form-label">Portal Subtitle</label><input className="form-control" value={settings.branding?.portal_subtitle || 'Enter your voucher to connect'} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_subtitle: e.target.value } })} /></div>
                <div className="col-md-4"><label className="form-label">Accent Color</label><input className="form-control form-control-color" type="color" value={settings.branding?.accent_color || '#206bc4'} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, accent_color: e.target.value } })} /></div>
                <div className="col-12"><label className="form-label">Welcome Message</label><input className="form-control" value={settings.branding?.portal_welcome_message || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_welcome_message: e.target.value } })} /></div>
                <div className="col-md-6"><label className="form-label">Support / Help Text</label><input className="form-control" value={settings.branding?.portal_support_text || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_support_text: e.target.value } })} /></div>
                <div className="col-md-6"><label className="form-label">Terms Note</label><input className="form-control" value={settings.branding?.portal_terms_note || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_terms_note: e.target.value } })} /></div>
                <div className="col-md-4"><label className="form-check"><input className="form-check-input" type="checkbox" checked={settings.branding?.portal_show_powered_by !== false} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_show_powered_by: e.target.checked } })} /><span className="form-check-label">Show powered-by footer</span></label></div>
                <div className="col-12"><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Portal Branding</button></div>
              </div>
            </form> : <div className="empty">Loading portal branding...</div>}
          </Card>
        </div>
      </>}
      {activeTab === 'Sanity Check' && <div className="col-12">
        <Card title="Captive Portal Sanity Check">
          <div className="d-flex flex-wrap align-items-center justify-content-between gap-3 mb-3">
            <div>
              <div className="text-muted">Use this checklist before field testing the voucher captive portal.</div>
              <div className="small text-muted">Automatic checks use the current system data. Manual checks are for the operator to confirm during one-AP or one-router testing.</div>
            </div>
            <div className="d-flex gap-2 flex-wrap">
              <span className="badge bg-green-lt text-green">Ready {readySanityChecks}/{requiredSanityChecks.length}</span>
              <span className="badge bg-yellow-lt text-yellow">Placeholders {sanityChecks.filter((item) => item.state === 'placeholder').length}</span>
            </div>
          </div>
          <div className="table-responsive">
            <table className="table table-vcenter">
              <thead>
                <tr>
                  <th>Area</th>
                  <th>Check</th>
                  <th>Details</th>
                  <th>Status</th>
                  <th className="text-end">Manual</th>
                </tr>
              </thead>
              <tbody>
                {sanityChecks.map((item) => (
                  <tr key={item.key} className={item.state === 'placeholder' ? 'table-warning' : ''}>
                    <td><span className="badge bg-secondary-lt text-secondary">{item.group}</span></td>
                    <td>
                      <div className="fw-semibold">{item.title}</div>
                      <div className="small text-muted">{item.mode === 'auto' ? 'Automatic' : item.mode === 'manual' ? 'Operator check' : 'Placeholder'}</div>
                    </td>
                    <td className="text-muted">{item.details}</td>
                    <td>{sanityBadge(item)}</td>
                    <td className="text-end">
                      {item.mode === 'manual' ? (
                        <label className="form-check form-switch d-inline-flex align-items-center mb-0">
                          <input className="form-check-input" type="checkbox" checked={Boolean(sanityProgress[item.key])} onChange={() => toggleChecklist(item.key)} />
                        </label>
                      ) : <span className="text-muted small">-</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="alert alert-info mb-0">
            Required live path: SSID from APs Deployment, MikroTik gateway reachable, voucher stock available, portal redemption working, and sessions/logs visible. Items marked coming soon are intentionally not blocking this development stage.
          </div>
        </Card>
      </div>}
      {activeTab === 'Portal Sessions' && <div className="col-12">
        <Card title="Portal Sessions">
          <Table rows={sessions} columns={['created_at', 'source', 'client_mac_masked', 'ssid', 'site', 'voucher_code', 'status', 'omada_authorization_status', 'access_expires_at', 'last_error']} />
        </Card>
      </div>
      }
      {activeTab === 'Authorization Logs' && <>
        <div className="col-12"><Card title="Gateway Authorization Logs"><Table rows={authorizations} columns={['created_at', 'gateway_type', 'client_mac_masked', 'voucher_code_masked', 'username', 'status', 'authorization_duration_seconds', 'access_expires_at', 'error_message']} /></Card></div>
        <div className="col-12"><Card title="Recent Portal Events"><Table rows={portalEvents.slice(0, 20)} columns={['event_type', 'voucher_code_masked', 'message', 'public_session_id', 'ip_address', 'created_at']} /></Card></div>
        <div className="col-12"><Card title="Recent Portal Redemptions"><Table rows={redemptions.slice(0, 20)} columns={['voucher_code', 'result', 'username', 'source', 'redeemed_time_seconds', 'failure_reason', 'created_at']} /></Card></div>
      </>}
      {activeTab === 'Manual Setup Guide' && <div className="col-12">
        <Card title="Manual MikroTik Setup Guide">
          <ol className="mb-0 manual-guide">
            <li>Confirm the APs are broadcasting <code>{portalSsidDisplay}</code> from APs Deployment - Sites - Configurations.</li>
            <li>Open the test MikroTik router and configure HotSpot/captive portal on the correct test interface or VLAN.</li>
            <li>Use a dedicated full/write RouterOS API account for automation and review the configuration plan before applying.</li>
            <li>Set staging portal URL to <code>http://192.168.50.70:8080/portal</code>. Production will use <code>http://192.168.50.70/portal</code>.</li>
            <li>Add walled garden / pre-auth access for <code>192.168.50.70</code>, the portal URL, and DNS.</li>
            <li>Apply this to one test router/interface only, connect a phone to <code>{portalSsidPrimary}</code>, and redeem a test voucher.</li>
            <li>Confirm Portal Sessions and Authorization Logs update here before rolling out wider.</li>
          </ol>
          <div className="alert alert-warning mt-3 mb-0">Do not roll this out to all substations until one AP test passes.</div>
        </Card>
      </div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function NasClients({ refresh }) {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState({ name: '', nas_ip: '', shortname: '', secret: generateSharedSecret(), type: 'other', notes: '' });
  const [autoGenerateSecret, setAutoGenerateSecret] = useState(true);
  const [editForm, setEditForm] = useState(null);
  const [secret, setSecret] = useState('');
  const [showExplanation, setShowExplanation] = useState(false);
  async function load() { setRows(await request('/nas-clients')); }
  useEffect(() => { load(); }, []);
  async function create(e) {
    e.preventDefault();
    const data = await request('/nas-clients', { method: 'POST', body: JSON.stringify(form) });
    setSecret(data.secret);
    setForm({ name: '', nas_ip: '', shortname: '', secret: autoGenerateSecret ? generateSharedSecret() : '', type: 'other', notes: '' });
    await load(); refresh();
  }
  function openEdit(row) {
    setEditForm({
      id: row.id,
      name: row.name || '',
      nas_ip: row.nas_ip || '',
      shortname: row.shortname || '',
      secret: row.secret || '',
      type: row.type || 'other',
      status: row.status || 'active',
      notes: row.notes || ''
    });
  }
  async function saveEdit(e) {
    e.preventDefault();
    await request(`/nas-clients/${editForm.id}`, { method: 'PATCH', body: JSON.stringify(editForm) });
    setEditForm(null);
    await load(); refresh();
  }

  return (
    <>
      <div className="row row-cards">
        <div className="col-12">
          <div className="alert alert-info nas-note">
            <div className="d-flex align-items-start gap-2">
              <span className="badge bg-blue-lt text-blue header-icon-badge flex-shrink-0"><IconRouter size={18} /></span>
              <div>
                <div className="fw-semibold mb-1">NAS / Router / AP Clients</div>
                <div>These are trusted network devices allowed to communicate with the system. For Captive Portal, this may include Omada Controller, APs, or MikroTik routers depending on the final enforcement method.</div>
                <button className="nas-readmore mt-2" type="button" onClick={() => setShowExplanation(!showExplanation)}>
                  {showExplanation ? 'Close explanation' : 'Read more'}
                </button>
                {showExplanation && (
                  <div className="nas-note-long mt-3">
                    <h4>What is this page for?</h4>
                    <p>This page is where you add the routers, access points, or controllers that are allowed to ask this system if a WiFi customer can connect.</p>
                    <p>Think of each device here as a trusted “gatekeeper” at a branch or substation. When a customer tries to connect to WiFi, that device asks 3JCentralPisowifi: “Should this customer be allowed online?”</p>
                    <p>Only devices added here will be trusted by the system. If a router or access point is not listed here, it may not be able to authenticate customers.</p>
                    <p>You do not need to add WiFi customers here. Customer access is currently managed through vouchers, while detected AP clients are monitored under Connected Devices.</p>
                    <p className="mb-0">The Shared Secret is the private key between this system and the router/access point. It must match on both sides. Keep it safe and do not share it publicly.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
        <div className="col-12">
          <Card title="Add NAS / Router / AP Client">
            <form onSubmit={create}>
              <div className="row g-3 align-items-end">
                <div className="col-md-3"><label className="form-label">Name</label><input className="form-control" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
                <div className="col-md-3"><label className="form-label">IP Address</label><input className="form-control" value={form.nas_ip} onChange={(e) => setForm({ ...form, nas_ip: e.target.value })} /></div>
                <div className="col-md-2"><label className="form-label">Shortname</label><input className="form-control" value={form.shortname} onChange={(e) => setForm({ ...form, shortname: e.target.value })} /></div>
                <div className="col-md-2"><label className="form-label">Type</label><input className="form-control" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} /></div>
                <div className="col-md-2"><label className="form-label">Auto Generate</label><label className="form-check mb-2"><input className="form-check-input" type="checkbox" checked={autoGenerateSecret} onChange={(e) => { const checked = e.target.checked; setAutoGenerateSecret(checked); setForm({ ...form, secret: checked ? generateSharedSecret() : '' }); }} /><span className="form-check-label">Shared secret</span></label></div>
                <div className="col-md-10"><label className="form-label">Shared Secret</label><input className="form-control" required value={form.secret} readOnly={autoGenerateSecret} onChange={(e) => setForm({ ...form, secret: e.target.value })} /></div>
                <div className="col-md-2"><button className="btn btn-primary w-100"><IconRouter size={18} className="me-2" />Add</button></div>
              </div>
            </form>
            {secret && <div className="alert alert-info mt-3">Shared secret for Phase 1 testing: <code>{secret}</code></div>}
          </Card>
        </div>
        <div className="col-12">
          <Card title="Configuration Guidance">
            <div className="text-muted">For current advanced RADIUS testing, set your router/AP RADIUS server IP to this Ubuntu server. Use staging ports <code>11812</code> and <code>11813</code> plus the shared secret. For the Captive Portal path, these trusted devices may also enforce portal redirects or accounting depending on the final integration.</div>
          </Card>
        </div>
        <div className="col-12">
          <Card title="NAS / Router / AP Clients">
            {!rows.length ? <div className="empty">No records yet.</div> : (
              <div className="table-responsive table-sticky-wrap">
                <table className="table card-table table-vcenter text-nowrap">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>IP Address</th>
                      <th>Shortname</th>
                      <th>Shared Secret</th>
                      <th>Type</th>
                      <th>Status</th>
                      <th>Notes</th>
                      <th>Created At</th>
                      <th className="text-end">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.id}>
                        <td>{fmt(row.name)}</td>
                        <td>{fmt(row.nas_ip)}</td>
                        <td>{fmt(row.shortname)}</td>
                        <td><code>{fmt(row.secret)}</code></td>
                        <td>{fmt(row.type)}</td>
                        <td>{fmt(row.status)}</td>
                        <td>{fmt(row.notes)}</td>
                        <td>{fmt(row.created_at)}</td>
                        <td className="text-end">
                          <button className="badge bg-blue-lt text-blue border-0 nas-action-badge" type="button" onClick={() => openEdit(row)}>
                            <IconEdit size={15} className="me-1" />Edit
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      </div>
      {editForm && (
        <Modal title="Edit NAS / Router / AP Client" onClose={() => setEditForm(null)}>
          <form onSubmit={saveEdit}>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Name</label><input className="form-control" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">IP Address</label><input className="form-control" value={editForm.nas_ip} onChange={(e) => setEditForm({ ...editForm, nas_ip: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Shortname</label><input className="form-control" value={editForm.shortname} onChange={(e) => setEditForm({ ...editForm, shortname: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Shared Secret</label><input className="form-control" value={editForm.secret} onChange={(e) => setEditForm({ ...editForm, secret: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Type</label><input className="form-control" value={editForm.type} onChange={(e) => setEditForm({ ...editForm, type: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Status</label><select className="form-select" value={editForm.status} onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}><option value="active">Active</option><option value="disabled">Disabled</option></select></div>
              <div className="col-12"><label className="form-label">Notes</label><textarea className="form-control" rows="3" value={editForm.notes} onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0">
              <button type="button" className="btn" onClick={() => setEditForm(null)}>Cancel</button>
              <button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Changes</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function RadiusTestGuide({ refresh }) {
  const [users, setUsers] = useState([]);
  const [nasClients, setNasClients] = useState([]);
  const [form, setForm] = useState({
    username: '',
    password: '',
    nas_ip: '127.0.0.1',
    nas_identifier: 'portal-simulator',
    calling_station_id: 'SIMULATED-DEVICE'
  });
  const [realForm, setRealForm] = useState({
    username: '',
    password: '',
    nas_ip: '172.18.0.1',
    nas_identifier: 'portal-real-test',
    calling_station_id: 'REAL-TEST-DEVICE',
    shared_secret: '',
    radius_host: 'radius',
    radius_port: 1812
  });
  const [acctForm, setAcctForm] = useState({
    username: '',
    nas_ip: '172.18.0.1',
    nas_identifier: 'Docker API Test NAS',
    calling_station_id: 'REAL-ACCT-DEVICE',
    framed_ip_address: '10.10.10.10',
    acct_session_id: generateSessionId(),
    acct_unique_session_id: '',
    shared_secret: '',
    radius_host: 'radius',
    accounting_port: 1813,
    acct_session_time: 0,
    input_octets: 0,
    output_octets: 0
  });
  const [realDefaults, setRealDefaults] = useState(null);
  const [testing, setTesting] = useState(false);
  const [realTesting, setRealTesting] = useState(false);
  const [acctTesting, setAcctTesting] = useState('');
  const [result, setResult] = useState(null);
  const [realResult, setRealResult] = useState(null);
  const [acctResult, setAcctResult] = useState(null);
  const [error, setError] = useState('');
  const [realError, setRealError] = useState('');
  const [acctError, setAcctError] = useState('');
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [showAcctDetails, setShowAcctDetails] = useState(false);

  useEffect(() => {
    request('/users').then((data) => setUsers(Array.isArray(data) ? data : [])).catch(() => setUsers([]));
    request('/radius/real-packet-defaults').then((data) => {
      setRealDefaults(data);
      setRealForm((current) => ({
        ...current,
        nas_ip: data.packet_nas_ip || current.nas_ip,
        nas_identifier: data.client_name || current.nas_identifier,
        shared_secret: data.shared_secret || current.shared_secret,
        radius_host: data.radius_host || current.radius_host,
        radius_port: data.radius_port || current.radius_port
      }));
      setAcctForm((current) => ({
        ...current,
        nas_ip: data.packet_nas_ip || current.nas_ip,
        nas_identifier: data.client_name || current.nas_identifier,
        shared_secret: data.shared_secret || current.shared_secret,
        radius_host: data.radius_host || current.radius_host,
        accounting_port: data.accounting_port || current.accounting_port
      }));
    }).catch(() => {});
    request('/nas-clients').then((data) => {
      const rows = Array.isArray(data) ? data : [];
      setNasClients(rows);
      const firstActive = rows.find((row) => row.status === 'active') || rows[0];
      if (firstActive?.nas_ip) {
        setForm((current) => ({ ...current, nas_ip: firstActive.nas_ip, nas_identifier: firstActive.shortname || current.nas_identifier }));
      }
    }).catch(() => setNasClients([]));
  }, []);

  async function runTest(e) {
    e.preventDefault();
    setTesting(true);
    setError('');
    setResult(null);
    try {
      const data = await request('/radius/simulate-auth', { method: 'POST', body: JSON.stringify(form) });
      setResult(data);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setTesting(false);
    }
  }
  async function runRealTest(e) {
    e.preventDefault();
    setRealTesting(true);
    setRealError('');
    setRealResult(null);
    try {
      const data = await request('/radius/real-packet-test', { method: 'POST', body: JSON.stringify(realForm) });
      setRealResult(data);
      refresh();
    } catch (err) {
      setRealError(err.message);
    } finally {
      setRealTesting(false);
    }
  }
  async function runAccountingTest(statusType) {
    setAcctTesting(statusType);
    setAcctError('');
    setAcctResult(null);
    try {
      const endpoint = statusType === 'Start' ? 'start' : statusType === 'Stop' ? 'stop' : 'interim';
      const data = await request(`/radius-test/accounting/${endpoint}`, { method: 'POST', body: JSON.stringify(acctForm) });
      setAcctResult({ ...data, statusType });
      refresh();
    } catch (err) {
      setAcctError(err.message);
    } finally {
      setAcctTesting('');
    }
  }

  const resultTone = result?.result === 'accept' ? 'success' : 'danger';
  const realTone = realResult?.result === 'Access-Accept' ? 'success' : (realResult?.result === 'Wrong Secret' || realResult?.result === 'Database Error' ? 'warning' : 'danger');
  const suggestionMap = {
    'Unknown user': 'Create the user or verify username spelling.',
    'Invalid password': 'Reset the user password and test again.',
    'User disabled': 'Enable the user account.',
    'No active wallet balance': 'Add manual balance or set unlimited access.',
    'Account expired': 'Extend valid-until date.',
    'Active session already exists': 'Stop the active session or wait for session timeout.',
    'Database lookup failed': 'Check API/PostgreSQL/FreeRADIUS SQL connectivity.',
    'Unknown authorization failure': 'Check FreeRADIUS logs.',
    'No Reply': 'Check RADIUS host, port, firewall, and FreeRADIUS client configuration.',
    'Wrong Secret': 'Use the internal Docker test client shared secret for this test.'
  };
  const realReason = realResult?.diagnostic_reason || realResult?.reply_message || realResult?.detail || realResult?.result;
  const realSuggestion = suggestionMap[realReason] || suggestionMap[realResult?.result] || 'Check FreeRADIUS logs.';
  const acctReason = acctResult?.diagnostic_reason || acctResult?.detail || acctResult?.result;
  const checkLabels = {
    user_exists: 'User exists',
    password_valid: 'Password is correct',
    user_active: 'User is active',
    has_balance: 'User has active balance',
    single_device_clear: 'No active session conflict'
  };

  return (
    <div className="row row-cards">
      <div className="col-12">
        <Card title="Advanced RADIUS Lab" subtitle="Advanced / Lab Testing">
          <div className="alert alert-warning">This page is for developer and network validation only. Customers will not use this flow. The current customer access direction is Captive Portal + Voucher.</div>
          <div className="text-muted mb-3">These tests validate the source-of-truth checks used by FreeRADIUS: account status, password, manual balance, valid-until, unlimited flag, and single-device active-session rejection.</div>
          <pre className="mb-0"><code>radtest testuser password SERVER-IP:11812 0 shared-secret</code></pre>
        </Card>
      </div>
      <div className="col-12">
        <Card title="Simulated RADIUS Decision Test" subtitle="Advanced / Lab Testing">
          <form onSubmit={runTest}>
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label">WiFi Username</label>
                <input className="form-control" list="radius-test-users" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
                <datalist id="radius-test-users">
                  {users.map((user) => <option key={user.id} value={user.username} />)}
                </datalist>
              </div>
              <div className="col-md-4">
                <label className="form-label">WiFi Password</label>
                <input className="form-control" type="password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">NAS / Router / AP IP</label>
                <select className="form-select" required value={form.nas_ip} onChange={(e) => {
                  const selected = nasClients.find((nas) => nas.nas_ip === e.target.value);
                  setForm({ ...form, nas_ip: e.target.value, nas_identifier: selected?.shortname || form.nas_identifier });
                }}>
                  {!nasClients.length && <option value="">No NAS clients added</option>}
                  {nasClients.map((nas) => <option key={nas.id} value={nas.nas_ip}>{nas.name} - {nas.nas_ip}</option>)}
                </select>
              </div>
              <div className="col-md-6">
                <label className="form-label">NAS Identifier</label>
                <input className="form-control" value={form.nas_identifier} onChange={(e) => setForm({ ...form, nas_identifier: e.target.value })} />
              </div>
              <div className="col-md-6">
                <label className="form-label">Calling Station ID / Test Device</label>
                <input className="form-control" value={form.calling_station_id} onChange={(e) => setForm({ ...form, calling_station_id: e.target.value })} />
              </div>
              <div className="col-12">
                <button className="btn btn-primary" disabled={testing}>
                  <IconWifi size={18} className="me-2" />{testing ? 'Testing...' : 'Run RADIUS Test'}
                </button>
              </div>
            </div>
          </form>
          {error && <div className="alert alert-danger mt-3 mb-0">{error}</div>}
          {result && (
            <div className={`alert alert-${resultTone} radius-test-result mt-3 mb-0`}>
              <div className="d-flex align-items-center justify-content-between flex-wrap gap-2">
                <div>
                  <div className="fw-bold">{result.access}</div>
                  <div>{result.reply_message}</div>
                </div>
                {result.session_timeout && <span className="badge bg-green-lt text-green">Session Timeout: {result.session_timeout}s</span>}
              </div>
              <div className="row g-2 mt-3">
                {Object.entries(checkLabels).map(([key, label]) => (
                  <div className="col-md-4" key={key}>
                    <span className={`badge ${result.checks?.[key] ? 'bg-green-lt text-green' : 'bg-red-lt text-red'} radius-check-badge`}>
                      {result.checks?.[key] ? 'Pass' : 'Fail'} · {label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>
      <div className="col-12">
        <Card title="Real FreeRADIUS Packet Test" subtitle="Advanced / Lab Testing">
          <div className="alert alert-info mb-3">
            <div className="fw-semibold">Internal Docker RADIUS Test Client</div>
            <div>Client: {realDefaults?.client_name || 'Docker API Test NAS'}</div>
            <div>IP/Subnet: {realDefaults?.client_subnet || '172.18.0.0/16'}</div>
            <div>Shared Secret: <code>{realForm.shared_secret}</code></div>
            <div className="mt-2">This test is sent from the API container to the FreeRADIUS container. It uses the internal Docker test client secret, not the router/AP NAS shared secret.</div>
          </div>
          <form onSubmit={runRealTest}>
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label">Username</label>
                <input className="form-control" list="radius-real-test-users" required value={realForm.username} onChange={(e) => setRealForm({ ...realForm, username: e.target.value })} />
                <datalist id="radius-real-test-users">
                  {users.map((user) => <option key={user.id} value={user.username} />)}
                </datalist>
              </div>
              <div className="col-md-4">
                <label className="form-label">Password</label>
                <input className="form-control" type="password" required value={realForm.password} onChange={(e) => setRealForm({ ...realForm, password: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">NAS Client</label>
                <input className="form-control" value="Internal Docker RADIUS Test Client" readOnly />
                <div className="form-hint">FreeRADIUS sees the API container/Docker network as the client source.</div>
              </div>
              <div className="col-md-4">
                <label className="form-label">Shared Secret</label>
                <input className="form-control" required value={realForm.shared_secret} onChange={(e) => setRealForm({ ...realForm, shared_secret: e.target.value })} />
                <div className="form-hint">This must match the Docker-network client secret configured in FreeRADIUS, not the selected router/AP shared secret.</div>
              </div>
              <div className="col-md-4">
                <label className="form-label">RADIUS Host</label>
                <input className="form-control" required value={realForm.radius_host} onChange={(e) => setRealForm({ ...realForm, radius_host: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">RADIUS Port</label>
                <input className="form-control" type="number" min="1" max="65535" required value={realForm.radius_port} onChange={(e) => setRealForm({ ...realForm, radius_port: Number(e.target.value) })} />
              </div>
              <div className="col-12">
                <button className="btn btn-primary" disabled={realTesting}>
                  <IconWifi size={18} className="me-2" />{realTesting ? 'Testing...' : 'Run Real RADIUS Test'}
                </button>
              </div>
            </div>
          </form>
          <div className="text-muted small mt-3">
            Possible real results: Access-Accept, Access-Reject, No Reply, Unknown Client, Wrong Secret, Database Error.
          </div>
          {realError && <div className="alert alert-danger mt-3 mb-0">{realError}</div>}
          {realResult && (
            <div className={`alert alert-${realTone} radius-test-result mt-3 mb-0`}>
              <div className="d-flex align-items-center justify-content-between flex-wrap gap-2">
                <div>
                  <div className="fw-bold">{realResult.result}</div>
                  {realResult.result === 'Access-Reject' && <div>Reason: {realReason}</div>}
                  {realResult.result !== 'Access-Reject' && <div>{realResult.detail}</div>}
                  {realResult.result !== 'Access-Accept' && <div>Suggestion: {realSuggestion}</div>}
                </div>
                {realResult.remote && <span className="badge bg-blue-lt text-blue">Reply From: {realResult.remote}</span>}
              </div>
              <button className="nas-readmore mt-3" type="button" onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}>
                {showTechnicalDetails ? 'Hide technical details' : 'Show technical details'}
              </button>
              {showTechnicalDetails && (
                <div className="mt-3">
                  <pre className="mb-0"><code>{JSON.stringify({
                    raw_radius_response_attributes: realResult.raw_attributes || [],
                    request_username: realForm.username,
                    radius_host: realForm.radius_host,
                    radius_port: realForm.radius_port,
                    nas_client_source: realDefaults?.nas_client_source || 'Internal Docker RADIUS Test Client',
                    selected_shared_secret_name: 'Internal Docker RADIUS Test Client Secret',
                    selected_shared_secret_masked_value: realForm.shared_secret ? `${realForm.shared_secret.slice(0, 4)}...${realForm.shared_secret.slice(-4)}` : '',
                    timestamp: new Date().toISOString()
                  }, null, 2)}</code></pre>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
      <div className="col-12">
        <Card title="Real RADIUS Accounting Test" subtitle="Advanced / Lab Testing">
          <div className="alert alert-info">
            Accounting tells the system when a customer starts using the internet, whether they are still online, and when they disconnect. This is how the system tracks active devices, deducts time, and prevents the same account from being used on more than one device.
          </div>
          <form onSubmit={(e) => e.preventDefault()}>
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label">Username</label>
                <input className="form-control" list="radius-acct-users" required value={acctForm.username} onChange={(e) => setAcctForm({ ...acctForm, username: e.target.value })} />
                <datalist id="radius-acct-users">{users.map((user) => <option key={user.id} value={user.username} />)}</datalist>
              </div>
              <div className="col-md-4">
                <label className="form-label">NAS Client / Internal Docker RADIUS Test Client</label>
                <input className="form-control" value="Docker API Test NAS" readOnly />
              </div>
              <div className="col-md-4">
                <label className="form-label">Calling Station ID / Test Device</label>
                <input className="form-control" value={acctForm.calling_station_id} onChange={(e) => setAcctForm({ ...acctForm, calling_station_id: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Framed IP Address</label>
                <input className="form-control" value={acctForm.framed_ip_address} onChange={(e) => setAcctForm({ ...acctForm, framed_ip_address: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Acct Session ID</label>
                <div className="input-group">
                  <input className="form-control" value={acctForm.acct_session_id} onChange={(e) => setAcctForm({ ...acctForm, acct_session_id: e.target.value })} />
                  <button className="btn" type="button" onClick={() => setAcctForm({ ...acctForm, acct_session_id: generateSessionId(), acct_session_time: 0, input_octets: 0, output_octets: 0 })}>Auto-generate</button>
                </div>
              </div>
              <div className="col-md-4">
                <label className="form-label">RADIUS Host</label>
                <input className="form-control" value={acctForm.radius_host} onChange={(e) => setAcctForm({ ...acctForm, radius_host: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Accounting Port</label>
                <input className="form-control" type="number" value={acctForm.accounting_port} onChange={(e) => setAcctForm({ ...acctForm, accounting_port: Number(e.target.value) })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Shared Secret</label>
                <input className="form-control" value={acctForm.shared_secret} onChange={(e) => setAcctForm({ ...acctForm, shared_secret: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Session Time</label>
                <input className="form-control" type="number" min="0" value={acctForm.acct_session_time} onChange={(e) => setAcctForm({ ...acctForm, acct_session_time: Number(e.target.value) })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Input Octets</label>
                <input className="form-control" type="number" min="0" value={acctForm.input_octets} onChange={(e) => setAcctForm({ ...acctForm, input_octets: Number(e.target.value) })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Output Octets</label>
                <input className="form-control" type="number" min="0" value={acctForm.output_octets} onChange={(e) => setAcctForm({ ...acctForm, output_octets: Number(e.target.value) })} />
              </div>
              <div className="col-12 d-flex gap-2 flex-wrap">
                <button type="button" className="btn btn-primary" disabled={!!acctTesting} onClick={() => runAccountingTest('Start')}>Send Accounting Start</button>
                <button type="button" className="btn btn-warning" disabled={!!acctTesting} onClick={() => runAccountingTest('Interim-Update')}>Send Interim Update</button>
                <button type="button" className="btn btn-danger" disabled={!!acctTesting} onClick={() => runAccountingTest('Stop')}>Send Accounting Stop</button>
                <button type="button" className="btn" onClick={() => { setAcctResult(null); setAcctForm({ ...acctForm, acct_session_id: generateSessionId(), acct_session_time: 0, input_octets: 0, output_octets: 0 }); }}>Reset Test Session ID</button>
              </div>
            </div>
          </form>
          {acctError && <div className="alert alert-danger mt-3 mb-0">{acctError}</div>}
          {acctResult && (
            <div className={`alert alert-${acctResult.result === 'Accounting-Response' ? 'success' : 'danger'} radius-test-result mt-3 mb-0`}>
              <div className="fw-bold">{acctResult.result}</div>
              <div>{acctReason}</div>
              {acctResult.remote && <div>Reply From: {acctResult.remote}</div>}
              <button className="nas-readmore mt-3" type="button" onClick={() => setShowAcctDetails(!showAcctDetails)}>
                {showAcctDetails ? 'Hide technical details' : 'Show technical details'}
              </button>
              {showAcctDetails && (
                <pre className="mt-3 mb-0"><code>{JSON.stringify({
                  raw_attributes_sent: acctResult.raw_request_attributes || [],
                  raw_response: acctResult.raw_response_attributes || [],
                  username: acctForm.username,
                  radius_host: acctForm.radius_host,
                  accounting_port: acctForm.accounting_port,
                  acct_session_id: acctForm.acct_session_id,
                  timestamp: new Date().toISOString()
                }, null, 2)}</code></pre>
              )}
            </div>
          )}
        </Card>
      </div>
      <div className="col-12">
        <Card title="External NAS Test Instructions" subtitle="Use this when testing a real MikroTik, Omada AP/controller, hostapd device, or radtest from another machine.">
          <div className="text-muted mb-3">External routers and APs must be added in NAS / Router / AP Clients. Their shared secret is different from the internal Docker test client secret above.</div>
          <div className="row g-3">
            <div className="col-md-4"><strong>MikroTik</strong><div className="text-muted">Set RADIUS server to this Ubuntu server IP, auth port 11812 on staging, accounting port 11813, and use the NAS record shared secret.</div></div>
            <div className="col-md-4"><strong>Omada / AP</strong><div className="text-muted">Configure external RADIUS server with the staging or production ports and the NAS record shared secret.</div></div>
            <div className="col-md-4"><strong>radtest</strong><pre className="mt-2 mb-0"><code>radtest USER PASS SERVER-IP:11812 0 NAS_SECRET</code></pre></div>
          </div>
        </Card>
      </div>
    </div>
  );
}

function MikroTikScanResultPage() {
  const initialRouterId = new URLSearchParams(window.location.search).get('router_id') || '';
  const [routers, setRouters] = useState([]);
  const [routerId, setRouterId] = useState(initialRouterId);
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [activeSection, setActiveSection] = useState('overview');

  const riskClass = (risk) => risk === 'BLOCKED' ? 'bg-red-lt text-red' : risk === 'HIGH' ? 'bg-orange-lt text-orange' : risk === 'MEDIUM' ? 'bg-yellow-lt text-yellow' : risk === 'LOW' ? 'bg-green-lt text-green' : 'bg-secondary-lt text-secondary';
  const findingClass = (severity) => severity === 'BLOCKER' ? 'bg-red-lt text-red' : severity === 'DANGER' ? 'bg-orange-lt text-orange' : severity === 'WARNING' ? 'bg-yellow-lt text-yellow' : 'bg-blue-lt text-blue';
  const pilotClass = (value) => value === 'GOOD_PILOT' ? 'bg-green-lt text-green' : value === 'POSSIBLE_WITH_CAUTION' ? 'bg-yellow-lt text-yellow' : value === 'NOT_RECOMMENDED' ? 'bg-red-lt text-red' : 'bg-secondary-lt text-secondary';
  const pilotLabel = (value) => ({
    GOOD_PILOT: 'Good Pilot',
    POSSIBLE_WITH_CAUTION: 'Possible With Caution',
    NOT_RECOMMENDED: 'Not Recommended',
    UNKNOWN: 'Unknown'
  }[value] || value || 'Unknown');

  async function loadRouters() {
    const rows = await request('/captive-portal/mikrotik');
    setRouters(Array.isArray(rows) ? rows : []);
    if (!routerId && rows?.[0]?.id) setRouterId(rows[0].id);
  }

  async function loadScan(nextRouterId = routerId) {
    if (!nextRouterId) return;
    setLoading(true);
    setError('');
    try {
      const data = await request(`/captive-portal/mikrotik/${nextRouterId}/preflight/latest`);
      setScan(data.scan || null);
      setHistory(Array.isArray(data.history) ? data.history : []);
    } catch (err) {
      setScan(null);
      setHistory([]);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function runScan() {
    if (!routerId) return;
    setScanning(true);
    setError('');
    try {
      const result = await request(`/captive-portal/mikrotik/${routerId}/preflight/scan`, { method: 'POST', body: JSON.stringify({}) });
      setScan(result || null);
      await loadScan(routerId);
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  }

  function changeRouter(nextRouterId) {
    setRouterId(nextRouterId);
    const url = `/admin/network/mikrotik/scan-result?router_id=${encodeURIComponent(nextRouterId)}`;
    window.history.replaceState({ page: 'MikroTik Scan Result' }, '', url);
    loadScan(nextRouterId);
  }

  useEffect(() => { loadRouters().catch((err) => setError(err.message)); }, []);
  useEffect(() => { if (routerId) loadScan(routerId); }, [routerId]);

  const router = routers.find((item) => item.id === routerId) || null;
  const snapshot = scan?.sanitized_snapshot || {};
  const paths = snapshot.paths || {};
  const analysis = snapshot.analysis || {};
  const counts = analysis.summary?.counts || {};
  const items = (key) => paths[key]?.items || [];
  const vlanRows = [
    ...items('interface_vlans').map((item) => ({ source: 'Interface VLAN', name: item.name, vlan_id: item['vlan-id'], interface: item.interface, comment: item.comment })),
    ...items('bridge_vlans').map((item) => ({ source: 'Bridge VLAN', name: item.bridge, vlan_id: item['vlan-ids'], interface: item.tagged || item.untagged, comment: item.comment }))
  ];
  const subnetRows = items('ip_addresses').map((item) => ({ address: item.address, network: item.network, interface: item.interface, disabled: item.disabled, comment: item.comment }));
  const poolRows = items('ip_pools').map((item) => ({ name: item.name, ranges: item.ranges, comment: item.comment }));
  const dhcpRows = items('dhcp_servers').map((item) => ({ name: item.name, interface: item.interface, address_pool: item['address-pool'], disabled: item.disabled, lease_time: item['lease-time'] }));
  const hotspotRows = items('hotspots').map((item) => ({ name: item.name, interface: item.interface, profile: item.profile, address_pool: item['address-pool'], disabled: item.disabled }));
  const findings = scan?.findings || [];
  const conflicts = scan?.conflicts || [];

  const sections = [
    { key: 'overview', label: 'Overview', detail: 'Identity and scan status', icon: IconDashboard, tone: 'blue', count: scan?.scan_status || 'NEW' },
    { key: 'conflicts', label: 'Conflicts', detail: 'Warnings and blockers', icon: IconAlertTriangle, tone: conflicts.length ? 'red' : 'green', count: conflicts.length },
    { key: 'vlans', label: 'VLANs', detail: 'Existing VLAN usage', icon: IconListDetails, tone: 'blue', count: vlanRows.length },
    { key: 'subnets', label: 'Subnets', detail: 'Existing IP addresses', icon: IconDatabase, tone: 'cyan', count: subnetRows.length },
    { key: 'pools', label: 'Pools', detail: 'Existing IP pools', icon: IconArchive, tone: 'orange', count: poolRows.length },
    { key: 'dhcp', label: 'DHCP', detail: 'Servers and pools', icon: IconServer, tone: 'green', count: dhcpRows.length },
    { key: 'hotspot', label: 'HotSpot', detail: 'Existing HotSpot config', icon: IconWifi, tone: 'yellow', count: hotspotRows.length },
    { key: 'sensitive', label: 'Sensitive', detail: 'PPPoE, OSPF, WG, routes', icon: IconLock, tone: 'red', count: (counts.pppoe_servers || 0) + (counts.ospf_entries || 0) + (counts.wireguard || 0) }
  ];

  const roleOverview = (
    <Card title="Role Explanation">
      {scan?.router_role_guess === 'PPPoE_ACCESS_CONCENTRATOR' && <div className="alert alert-warning">This router has PPPoE services. Captive portal setup should only use a new dedicated VLAN/subnet and must not touch PPPoE objects.</div>}
      {scan?.router_role_guess === 'CORE_ROUTER_READ_ONLY' && <div className="alert alert-danger">This router appears to be core/routing infrastructure. Do not use it for HotSpot setup without expert review.</div>}
      {scan?.router_role_guess === 'SWITCH_TRUNK_HELPER' && <div className="alert alert-info">This device appears to be a VLAN trunk/switch device. It can carry VLANs but should not host HotSpot/DHCP/NAT.</div>}
      <div className="fw-semibold mb-2">Why this role was guessed</div>
      <ul className="mb-3">{(scan?.role_reasoning || ['No role reasoning saved for this scan yet.']).map((item, index) => <li key={`scan-role-${index}`}>{item}</li>)}</ul>
      <span className={`badge ${pilotClass(scan?.pilot_suitability)}`}>Pilot suitability: {pilotLabel(scan?.pilot_suitability)}</span>
      {scan?.pilot_reason && <div className="text-muted small mt-2">{scan.pilot_reason}</div>}
    </Card>
  );

  const findingsOverview = (
    <Card title="Findings by Category">
      <div className="row g-2">
        {findings.map((item, index) => (
          <div className="col-md-6" key={`scan-finding-${index}`}>
            <div className="border rounded p-3 h-100">
              <div className="d-flex align-items-start justify-content-between gap-2 mb-1">
                <div className="fw-semibold">{item.title}</div>
                <span className={`badge ${findingClass(item.severity)}`}>{item.category} / {item.severity}</span>
              </div>
              <div className="text-muted small">{item.message}</div>
              {item.related_object && <div className="small mt-1"><strong>Related:</strong> {item.related_object}</div>}
              {item.recommendation && <div className="small mt-1"><strong>Recommendation:</strong> {item.recommendation}</div>}
            </div>
          </div>
        ))}
        {!findings.length && <div className="col-12 text-muted">No findings recorded.</div>}
      </div>
    </Card>
  );

  const historyOverview = (
    <Card title="Scan History">
      <Table rows={history} columns={['created_at', 'scan_status', 'risk_level', 'router_role_guess', 'recommended_deployment_mode', 'last_error']} />
    </Card>
  );

  const sectionContent = {
    overview: (
      <div className="row row-cards">
        <KpiCard icon={IconRouter} label="Router Identity" value={scan?.router_identity || router?.router_name || 'Unknown'} tone="blue" />
        <KpiCard icon={IconCpu} label="Model / Version" value={`${scan?.router_model || 'Unknown'} ${scan?.router_version || ''}`.trim()} tone="green" />
        <KpiCard icon={IconShieldLock} label="Risk Level" value={scan?.risk_level || 'Unknown'} tone={scan?.risk_level === 'LOW' ? 'green' : scan?.risk_level === 'MEDIUM' ? 'yellow' : 'red'} />
        <KpiCard icon={IconListDetails} label="Findings" value={`${findings.length} total`} tone="purple" />
        <div className="col-12">
          <div className="card"><div className="card-body">
            <div className="d-flex flex-wrap gap-2 mb-2">
              <span className={`badge ${riskClass(scan?.risk_level)}`}>Risk: {scan?.risk_level || 'Unknown'}</span>
              <span className="badge bg-blue-lt text-blue">Role guess: {scan?.router_role_guess || 'UNKNOWN'}</span>
              <span className={`badge ${scan?.scan_status === 'SUCCESS' ? 'bg-green-lt text-green' : 'bg-red-lt text-red'}`}>{scan?.scan_status || 'NO_SCAN'}</span>
            </div>
            <div className="text-muted small">Last scan timestamp: {fmt(scan?.created_at)}. This page is read-only and does not change RouterOS configuration.</div>
            {scan?.last_error && <div className="alert alert-danger mt-3 mb-0">{scan.last_error}</div>}
          </div></div>
        </div>
        <div className="col-12">{roleOverview}</div>
        <div className="col-12">{findingsOverview}</div>
        <div className="col-12">{historyOverview}</div>
      </div>
    ),
    conflicts: (
      <Card title="Conflict Warnings" subtitle="Resolve warnings before future configuration preview or apply phases.">
        {conflicts.length ? (
          <div className="list-group list-group-flush">
            {conflicts.map((item, index) => (
              <div className="list-group-item px-0" key={`scan-conflict-${index}`}>
                <div className="d-flex justify-content-between gap-3">
                  <div>
                    <div className="fw-semibold">{item.title}</div>
                    <div className="text-muted small">{item.message}</div>
                    {item.recommendation && <div className="small mt-1">{item.recommendation}</div>}
                  </div>
                  <span className={`badge align-self-start ${findingClass(item.severity)}`}>{item.severity}</span>
                </div>
              </div>
            ))}
          </div>
        ) : <div className="text-muted">No blocking conflicts detected in the latest scan.</div>}
      </Card>
    ),
    vlans: <Card title="Existing VLANs"><Table rows={vlanRows} columns={['source', 'name', 'vlan_id', 'interface', 'comment']} /></Card>,
    subnets: <Card title="Existing Subnets"><Table rows={subnetRows} columns={['address', 'network', 'interface', 'disabled', 'comment']} /></Card>,
    pools: <Card title="Existing IP Pools"><Table rows={poolRows} columns={['name', 'ranges', 'comment']} /></Card>,
    dhcp: <Card title="Existing DHCP Servers"><Table rows={dhcpRows} columns={['name', 'interface', 'address_pool', 'disabled', 'lease_time']} /></Card>,
    hotspot: <Card title="Existing HotSpot Servers"><Table rows={hotspotRows} columns={['name', 'interface', 'profile', 'address_pool', 'disabled']} /></Card>,
    sensitive: (
      <Card title="Sensitive Config Indicators">
        <div className="d-flex flex-column gap-2">
          <div className="d-flex justify-content-between"><span>PPPoE servers</span><span className={`badge ${(counts.pppoe_servers || 0) ? 'bg-red-lt text-red' : 'bg-green-lt text-green'}`}>{counts.pppoe_servers || 0}</span></div>
          <div className="d-flex justify-content-between"><span>OSPF entries</span><span className={`badge ${(counts.ospf_entries || 0) ? 'bg-red-lt text-red' : 'bg-green-lt text-green'}`}>{counts.ospf_entries || 0}</span></div>
          <div className="d-flex justify-content-between"><span>WireGuard interfaces</span><span className={`badge ${(counts.wireguard || 0) ? 'bg-yellow-lt text-yellow' : 'bg-green-lt text-green'}`}>{counts.wireguard || 0}</span></div>
          <div className="d-flex justify-content-between"><span>Firewall filter rules</span><span className="badge bg-blue-lt text-blue">{counts.firewall_filter || 0}</span></div>
          <div className="d-flex justify-content-between"><span>NAT rules</span><span className="badge bg-blue-lt text-blue">{counts.firewall_nat || 0}</span></div>
          <div className="d-flex justify-content-between"><span>Routes</span><span className="badge bg-blue-lt text-blue">{counts.routes || 0}</span></div>
          <div className="d-flex justify-content-between"><span>Unsupported read-only paths</span><span className="badge bg-secondary-lt text-secondary">{counts.unsupported_paths || 0}</span></div>
        </div>
      </Card>
    )
  };

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="d-flex align-items-end justify-content-between gap-3 flex-wrap">
          <div className="flex-fill" style={{ minWidth: 260 }}>
            <label className="form-label">MikroTik Router</label>
            <select className="form-select" value={routerId} onChange={(e) => changeRouter(e.target.value)}>
              <option value="">Choose router</option>
              {routers.map((item) => <option value={item.id} key={`scan-page-router-${item.id}`}>{item.router_name} - {item.host}:{item.api_port}</option>)}
            </select>
          </div>
          <div className="btn-list">
            <button className="btn btn-outline-secondary" type="button" onClick={() => loadScan()} disabled={!routerId || loading}>
              <IconRefresh size={18} className="me-2" />{loading ? 'Loading...' : 'Reload'}
            </button>
            <button className="btn btn-primary" type="button" onClick={runScan} disabled={!routerId || scanning}>
              <IconSearch size={18} className="me-2" />{scanning ? 'Scanning...' : 'Run Scan'}
            </button>
          </div>
        </div>
      </div>
      {error && <div className="col-12"><div className="alert alert-danger mb-0">{error}</div></div>}
      {!routerId && <div className="col-12"><div className="empty">Choose a MikroTik router to view scan results.</div></div>}
      {routerId && !scan && !loading && <div className="col-12"><div className="empty">No scan result is loaded for this router yet. Run Scan to create a read-only result.</div></div>}
      {scan && (
        <div className="col-12">
          <div className="scan-result-layout">
            <div className="scan-result-tabs" role="tablist" aria-label="Scan result sections">
              {sections.map((section) => {
                const Icon = section.icon;
                return (
                  <button className={`scan-result-tab ${activeSection === section.key ? 'active' : ''}`} type="button" onClick={() => setActiveSection(section.key)} key={`scan-section-${section.key}`}>
                    <span className={`scan-result-tab-icon bg-${section.tone}-lt text-${section.tone}`}><Icon size={24} /></span>
                    <span className="scan-result-tab-text">
                      <strong>{section.label}</strong>
                      <small>{section.detail}</small>
                    </span>
                    <span className={`badge scan-result-tab-count bg-${section.tone}-lt text-${section.tone}`}>{section.count}</span>
                  </button>
                );
              })}
            </div>
            <div className="scan-result-panel">
              {sectionContent[activeSection]}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function NetworkPage({ refresh }) {
  const [tab, setTab] = useState('MikroTik');
  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          Network tools are for trusted infrastructure devices and advanced validation. MikroTik handles gateway/enforcement planning, while customer-facing access stays Captive Portal + Voucher.
        </div>
      </div>
      <div className="col-12">
        <ul className="nav nav-tabs">
          {['MikroTik', 'NAS / Router / AP Clients', 'Advanced RADIUS Lab'].map((item) => (
            <li className="nav-item" key={item}>
              <button className={`nav-link ${tab === item ? 'active' : ''}`} type="button" onClick={() => setTab(item)}>{item}</button>
            </li>
          ))}
        </ul>
      </div>
      <div className="col-12">
        {tab === 'MikroTik' && <CaptivePortalPage mode="mikrotik-only" />}
        {tab === 'NAS / Router / AP Clients' && <NasClients refresh={refresh} />}
        {tab === 'Advanced RADIUS Lab' && <RadiusTestGuide refresh={refresh} />}
      </div>
    </div>
  );
}

function SimplePage({ title, endpoint, columns, children }) {
  const [rows, setRows] = useState([]);
  useEffect(() => { request(endpoint).then((data) => setRows(Array.isArray(data) ? data : [])); }, [endpoint]);
  return <Card title={title}>{children}<Table rows={rows} columns={columns} /></Card>;
}

function SessionsPage({ refresh }) {
  const [rows, setRows] = useState([]);
  const [detail, setDetail] = useState(null);
  async function load() { setRows(await request('/sessions')); }
  useEffect(() => { load(); }, []);
  const grouped = {
    active: rows.filter((row) => row.display_status === 'ACTIVE'),
    stale: rows.filter((row) => row.display_status === 'STALE'),
    stopped: rows.filter((row) => !['ACTIVE', 'STALE'].includes(row.display_status))
  };
  async function viewDetails(row) {
    setDetail(await request(`/sessions/${row.id}`));
  }
  async function action(row, type) {
    await request(`/sessions/${row.id}/${type}`, { method: 'POST' });
    await load(); refresh();
  }
  function sessionTable(items) {
    if (!items.length) return <div className="empty">No sessions in this section.</div>;
    return (
      <div className="table-responsive">
        <table className="table card-table table-vcenter text-nowrap">
          <thead><tr><th>Username</th><th>Current Device</th><th>NAS / Router / AP</th><th>Framed IP</th><th>Start Time</th><th>Last Seen</th><th>Session Time</th><th>Input / Output Octets</th><th>Status</th><th className="text-end">Actions</th></tr></thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <td>{row.username}</td>
                <td>{fmt(row.calling_station_id)}</td>
                <td>{fmt(row.nas_identifier || row.nas_ip)}</td>
                <td>{fmt(row.framed_ip_address)}</td>
                <td>{fmt(row.start_time)}</td>
                <td>{fmt(row.last_update_time)}</td>
                <td>{formatSeconds(row.acct_session_time)}</td>
                <td>{fmt(row.input_octets)} / {fmt(row.output_octets)}</td>
                <td><span className="badge bg-blue-lt text-blue">{row.display_status || row.status}</span></td>
                <td className="text-end">
                  <button className="btn btn-sm me-1" onClick={() => viewDetails(row)}>View Details</button>
                  {row.display_status === 'ACTIVE' && <button className="btn btn-sm btn-warning me-1" onClick={() => action(row, 'mark-stale')}>Mark Stale</button>}
                  {['ACTIVE', 'STALE'].includes(row.display_status) && <button className="btn btn-sm btn-danger" onClick={() => action(row, 'force-stop-local')}>Force Stop Locally</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <div className="row row-cards">
      <div className="col-12"><div className="alert alert-info">An active session means the system believes this customer is currently online. If single-device protection is enabled, another login using the same account will be rejected until this session stops or becomes stale.</div></div>
      <div className="col-12"><Card title="Active Sessions">{sessionTable(grouped.active)}</Card></div>
      <div className="col-12"><Card title="Stale Sessions">{sessionTable(grouped.stale)}</Card></div>
      <div className="col-12"><Card title="Stopped Sessions / History">{sessionTable(grouped.stopped)}</Card></div>
      <div className="col-12"><div className="alert alert-warning">Force Stop Locally does not disconnect the user from the AP/router yet. It only clears the local active-session record.</div></div>
      {detail && (
        <Modal title="Session Details" onClose={() => setDetail(null)}>
          <pre><code>{JSON.stringify(detail, null, 2)}</code></pre>
        </Modal>
      )}
    </div>
  );
}

function ProfilePage({ onSaved }) {
  const [profile, setProfile] = useState({});
  const [passwords, setPasswords] = useState({ current_password: '', new_password: '', confirm_password: '' });
  const [message, setMessage] = useState('');
  useEffect(() => { request('/me').then(setProfile); }, []);

  async function saveProfile(e) {
    e.preventDefault();
    await request('/me', { method: 'PATCH', body: JSON.stringify({ full_name: profile.full_name, email: profile.email }) });
    setMessage('Profile saved.');
    onSaved();
  }

  async function changePassword(e) {
    e.preventDefault();
    await request('/me/change-password', { method: 'POST', body: JSON.stringify(passwords) });
    setPasswords({ current_password: '', new_password: '', confirm_password: '' });
    setMessage('Password changed.');
  }

  return (
    <div className="row justify-content-center row-cards">
      <div className="col-12 col-md-7 col-lg-5">
        <Card title="View Profile">
          {message && <div className="alert alert-info">{message}</div>}
          <form onSubmit={saveProfile}>
            <div className="mb-3"><label className="form-label">Username</label><input className="form-control" value={profile.username || ''} readOnly /></div>
            <div className="mb-3"><label className="form-label">Full Name</label><input className="form-control" value={profile.full_name || ''} onChange={(e) => setProfile({ ...profile, full_name: e.target.value })} /></div>
            <div className="mb-3"><label className="form-label">Email</label><input className="form-control" value={profile.email || ''} onChange={(e) => setProfile({ ...profile, email: e.target.value })} /></div>
            <div className="text-end"><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Profile</button></div>
          </form>
        </Card>
      </div>
      <div className="col-12 col-md-7 col-lg-5">
        <Card title="Change Password">
          <form onSubmit={changePassword}>
            <div className="mb-3"><label className="form-label">Current Password</label><input className="form-control" type="password" value={passwords.current_password} onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })} /></div>
            <div className="mb-3"><label className="form-label">New Password</label><input className="form-control" type="password" value={passwords.new_password} onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })} /></div>
            <div className="mb-3"><label className="form-label">Confirm New Password</label><input className="form-control" type="password" value={passwords.confirm_password} onChange={(e) => setPasswords({ ...passwords, confirm_password: e.target.value })} /></div>
            <div className="text-end"><button className="btn btn-primary"><IconKey size={18} className="me-2" />Save Password</button></div>
          </form>
        </Card>
      </div>
    </div>
  );
}

function SystemSettingsPage({ refresh }) {
  const tabs = ['General', 'Access', 'System Update', 'Backup', 'Danger'];
  const [tab, setTab] = useState('General');
  const [settings, setSettings] = useState(null);
  const [admins, setAdmins] = useState([]);
  const [newAdmin, setNewAdmin] = useState({ username: '', password: '', full_name: '', email: '', role: 'admin' });
  const [danger, setDanger] = useState({ action: 'clear_auth_logs', confirmation: '', current_password: '' });
  const [companyLogo, setCompanyLogo] = useState(null);
  const [browserLogo, setBrowserLogo] = useState(null);
  const [message, setMessage] = useState('');

  async function load() {
    setSettings(await request('/system/settings'));
    setAdmins(await request('/system/access/admins'));
  }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!tabs.includes(tab)) setTab('General');
  }, [tab]);
  if (!settings) return <div className="empty">Loading settings...</div>;

  async function saveSettings(e) {
    e.preventDefault();
    await request('/system/settings', { method: 'PATCH', body: JSON.stringify(settings) });
    setMessage('Settings saved.');
    refresh();
  }

  async function uploadLogo(e, type) {
    e.preventDefault();
    const file = type === 'company' ? companyLogo : browserLogo;
    if (!file) {
      setMessage('Choose a file first.');
      return;
    }
    const data = await uploadRequest(
      type === 'company' ? '/system/branding/company-logo' : '/system/branding/browser-logo',
      type === 'company' ? 'company_logo' : 'browser_logo',
      file
    );
    setSettings({
      ...settings,
      branding: {
        ...settings.branding,
        company_logo_url: data.company_logo_url,
        browser_logo_url: data.browser_logo_url
      }
    });
    if (type === 'company') setCompanyLogo(null);
    if (type === 'browser') setBrowserLogo(null);
    setMessage(type === 'company' ? 'Company logo uploaded.' : 'Browser page logo uploaded.');
    refresh();
  }

  async function createAdmin(e) {
    e.preventDefault();
    await request('/system/access/admins', { method: 'POST', body: JSON.stringify(newAdmin) });
    setNewAdmin({ username: '', password: '', full_name: '', email: '', role: 'admin' });
    await load();
  }

  async function runDanger(e) {
    e.preventDefault();
    await request('/system/danger', { method: 'POST', body: JSON.stringify(danger) });
    setDanger({ action: 'clear_auth_logs', confirmation: '', current_password: '' });
    setMessage('Danger action completed.');
  }

  return (
    <>
      {message && <div className="alert alert-info auto-dismiss-alert">{message}</div>}
      <ul className="nav nav-tabs mb-3">
        {tabs.map((item) => <li className="nav-item" key={item}><button className={`nav-link ${tab === item ? 'active' : ''}`} onClick={() => setTab(item)}>{item}</button></li>)}
      </ul>

      {tab === 'General' && (
        <div className="row row-cards">
          <div className="col-12">
            <Card title="Deployment Defaults" subtitle="Used when creating Omada sites from Sites Deployments.">
              <form onSubmit={saveSettings}>
                <div className="row g-3 align-items-end">
                  <div className="col-md-5"><label className="form-label">Country / Region</label><input className="form-control" value={settings.general?.country_region || 'Philippines'} onChange={(e) => setSettings({ ...settings, general: { ...settings.general, country_region: e.target.value } })} /></div>
                  <div className="col-md-5"><label className="form-label">Time Zone</label><input className="form-control" value={settings.general?.time_zone || 'Asia/Manila'} onChange={(e) => setSettings({ ...settings, general: { ...settings.general, time_zone: e.target.value } })} /></div>
                  <div className="col-md-2"><button type="submit" className="btn btn-primary w-100"><IconDeviceFloppy size={18} className="me-2" />Save</button></div>
                </div>
              </form>
            </Card>
          </div>
          <div className="col-12">
            <Card title="Branding">
              <div className="row g-4">
                <div className="col-12 col-lg-6">
                  <form onSubmit={(e) => uploadLogo(e, 'company')}>
                    <label className="form-label">Company Logo <span className="info" title="Displayed in the left navigation header. Image files only.">i</span></label>
                    <input className="form-control" type="file" accept="image/*" onChange={(e) => setCompanyLogo(e.target.files?.[0] || null)} />
                    <div className="text-muted small mt-1">Recommended: transparent PNG, height 32-40px.</div>
                    <div className="mt-3 d-flex align-items-center gap-3 flex-wrap">
                      <button type="submit" className="btn btn-primary"><IconCloudUpload size={18} className="me-2" />Upload Company Logo</button>
                      {settings.branding?.company_logo_url ? (
                        <div className="border rounded p-2 d-inline-block bg-white">
                          <img src={settings.branding.company_logo_url} alt="Company Logo" className="company-logo-preview" />
                        </div>
                      ) : <div className="text-muted small">No logo uploaded yet.</div>}
                    </div>
                  </form>
                </div>

                <div className="col-12 col-lg-6">
                  <form onSubmit={(e) => uploadLogo(e, 'browser')}>
                    <label className="form-label">Browser Page Logo <span className="info" title="Used as the browser tab icon. PNG/JPG/WebP/GIF/ICO supported.">i</span></label>
                    <input className="form-control" type="file" accept="image/*,.ico" onChange={(e) => setBrowserLogo(e.target.files?.[0] || null)} />
                    <div className="text-muted small mt-1">Recommended: square icon (e.g. 64x64 or 128x128 PNG).</div>
                    <div className="mt-3 d-flex align-items-center gap-3 flex-wrap">
                      <button type="submit" className="btn btn-primary"><IconCloudUpload size={18} className="me-2" />Upload Browser Logo</button>
                      {settings.branding?.browser_logo_url ? (
                        <div className="border rounded p-2 d-inline-block bg-white">
                          <img src={settings.branding.browser_logo_url} alt="Browser Logo" className="browser-logo-preview" />
                        </div>
                      ) : <div className="text-muted small">No browser logo uploaded yet.</div>}
                    </div>
                  </form>
                </div>

                <div className="col-12">
                  <form onSubmit={saveSettings}>
                    <label className="form-label">System Display Name <span className="info" title="Used throughout the admin portal.">i</span></label>
                    <div className="row g-2 align-items-end">
                      <div className="col-12 col-lg">
                        <input className="form-control" value={settings.branding?.display_name || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, display_name: e.target.value } })} />
                      </div>
                      <div className="col-12 col-lg-auto">
                        <button type="submit" className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Display Name</button>
                      </div>
                    </div>
                    <div className="text-muted small mt-1">Example: this changes portal labels and page titles.</div>
                  </form>
                </div>

                <div className="col-12">
                  <form onSubmit={saveSettings}>
                    <div className="row g-3 align-items-end">
                      <div className="col-md-6"><label className="form-label">Portal Subtitle</label><input className="form-control" value={settings.branding?.portal_subtitle || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_subtitle: e.target.value } })} /></div>
                      <div className="col-md-3"><label className="form-label">Accent Color</label><input className="form-control form-control-color" type="color" value={settings.branding?.accent_color || '#206bc4'} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, accent_color: e.target.value } })} /></div>
                      <div className="col-md-3"><button type="submit" className="btn btn-primary w-100"><IconDeviceFloppy size={18} className="me-2" />Save Branding</button></div>
                    </div>
                  </form>
                </div>
              </div>
            </Card>
          </div>
        </div>
      )}

      {tab === 'Access' && (
        <div className="row row-cards">
          <div className="col-12">
            <Card title="Create Admin">
              <form onSubmit={createAdmin}>
                <div className="row g-3 align-items-end">
                  <div className="col-md-2"><label className="form-label">Username</label><input className="form-control" value={newAdmin.username} onChange={(e) => setNewAdmin({ ...newAdmin, username: e.target.value })} /></div>
                  <div className="col-md-2"><label className="form-label">Password</label><input className="form-control" type="password" value={newAdmin.password} onChange={(e) => setNewAdmin({ ...newAdmin, password: e.target.value })} /></div>
                  <div className="col-md-3"><label className="form-label">Full Name</label><input className="form-control" value={newAdmin.full_name} onChange={(e) => setNewAdmin({ ...newAdmin, full_name: e.target.value })} /></div>
                  <div className="col-md-3"><label className="form-label">Email</label><input className="form-control" value={newAdmin.email} onChange={(e) => setNewAdmin({ ...newAdmin, email: e.target.value })} /></div>
                  <div className="col-md-2"><button className="btn btn-primary w-100"><IconUserCog size={18} className="me-2" />Add Admin</button></div>
                </div>
              </form>
            </Card>
          </div>
          <div className="col-12"><Card title="Admins"><Table rows={admins} columns={['username', 'full_name', 'email', 'role', 'status', 'created_at']} /></Card></div>
        </div>
      )}

      {tab === 'System Update' && <UpdatePanel />}
      {tab === 'Backup' && <BackupPanel />}
      {tab === 'Danger' && (
        <Card title="Danger">
          <form onSubmit={runDanger}>
            <div className="row g-3 align-items-end">
              <div className="col-md-4"><label className="form-label">Action</label><select className="form-select" value={danger.action} onChange={(e) => setDanger({ ...danger, action: e.target.value })}><option value="clear_auth_logs">Clear authentication logs</option><option value="clear_sessions">Clear session records</option></select></div>
              <div className="col-md-3"><label className="form-label">Confirmation</label><input className="form-control" placeholder={danger.action === 'clear_sessions' ? 'CLEAR SESSIONS' : 'CLEAR AUTH LOGS'} value={danger.confirmation} onChange={(e) => setDanger({ ...danger, confirmation: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Current Password</label><input className="form-control" type="password" value={danger.current_password} onChange={(e) => setDanger({ ...danger, current_password: e.target.value })} /></div>
              <div className="col-md-2"><button className="btn btn-danger w-100"><IconAlertTriangle size={18} className="me-2" />Run</button></div>
            </div>
          </form>
        </Card>
      )}
    </>
  );
}

function BackupPanel() {
  const [data, setData] = useState(null);
  useEffect(() => { request('/system/backup').then(setData); }, []);
  if (!data) return null;
  return (
    <Card title="Backup">
      <div className="mb-3"><label className="form-label">Backup Command</label><pre><code>{data.backup_command}</code></pre></div>
      <div className="mb-3"><label className="form-label">Restore Command</label><pre><code>{data.restore_command}</code></pre></div>
      <div className="text-muted">{data.note}</div>
    </Card>
  );
}

function UpdatePanel() {
  const [data, setData] = useState(null);
  useEffect(() => { request('/system/update').then(setData); }, []);
  if (!data) return null;
  return (
    <Card title="System Update">
      <div className="mb-3"><label className="form-label">Local Update</label><pre><code>{data.update_command}</code></pre></div>
      <div className="mb-3"><label className="form-label">One-line Update</label><pre><code>{data.one_line_update}</code></pre></div>
      <div className="text-muted">Environment: {data.environment}. Branch: {data.branch}.</div>
    </Card>
  );
}

const DEFAULT_OPENAI_TEST_PROMPT = 'Reply with one short sentence confirming this OpenAI API key works for 3JCentralPisowifi.';

const OPENAI_REASONING_FALLBACK_LABELS = {
  none: 'None',
  minimal: 'Minimal',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  xhigh: 'Extra high'
};

function reasoningEffortsForModel(model, allEfforts = []) {
  const ids = Array.isArray(model?.reasoning_efforts) && model.reasoning_efforts.length
    ? model.reasoning_efforts
    : String(model?.reasoning || '')
      .split(',')
      .map((effort) => effort.trim())
      .filter(Boolean);
  const effortById = new Map((allEfforts || []).map((effort) => [effort.id, effort]));
  return ids.map((id) => effortById.get(id) || {
    id,
    label: OPENAI_REASONING_FALLBACK_LABELS[id] || id,
    description: ''
  });
}

function defaultReasoningEffortForModel(model, allEfforts = []) {
  const efforts = reasoningEffortsForModel(model, allEfforts);
  if (efforts.some((effort) => effort.id === 'medium')) return 'medium';
  return efforts[0]?.id || '';
}

function OpenAISettingsTab() {
  const [config, setConfig] = useState(null);
  const [form, setForm] = useState({
    api_key: '',
    selected_model: '',
    reasoning_effort: '',
    organization_id: '',
    project_id: ''
  });
  const [testPrompt, setTestPrompt] = useState(DEFAULT_OPENAI_TEST_PROMPT);
  const [maxOutputTokens, setMaxOutputTokens] = useState(120);
  const [testResult, setTestResult] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  async function loadOpenAISettings() {
    setLoading(true);
    try {
      const nextConfig = await request('/system-settings/openai');
      setConfig(nextConfig);
      setForm({
        api_key: '',
        selected_model: nextConfig.selected_model || '',
        reasoning_effort: nextConfig.selected_reasoning_effort || '',
        organization_id: nextConfig.organization_id || '',
        project_id: nextConfig.project_id || ''
      });
      setError('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadOpenAISettings();
  }, []);

  const selectedModel = config?.models?.find((model) => model.id === form.selected_model)
    || config?.selected_model_config
    || config?.models?.[0]
    || null;
  const selectedReasoningEfforts = reasoningEffortsForModel(selectedModel, config?.reasoning_efforts);
  const selectedReasoningEffort = selectedReasoningEfforts.find((effort) => effort.id === form.reasoning_effort)
    || selectedReasoningEfforts.find((effort) => effort.id === defaultReasoningEffortForModel(selectedModel, config?.reasoning_efforts))
    || selectedReasoningEfforts[0]
    || null;
  const activeReasoningEffortId = selectedReasoningEffort?.id || form.reasoning_effort || '';
  const pricingSource = config?.pricing_source || {};

  function updateSelectedModel(modelId) {
    const nextModel = config?.models?.find((model) => model.id === modelId);
    const nextEfforts = reasoningEffortsForModel(nextModel, config?.reasoning_efforts);
    const currentEffortStillSupported = nextEfforts.some((effort) => effort.id === form.reasoning_effort);
    setForm({
      ...form,
      selected_model: modelId,
      reasoning_effort: currentEffortStillSupported
        ? form.reasoning_effort
        : defaultReasoningEffortForModel(nextModel, config?.reasoning_efforts)
    });
  }

  async function saveOpenAISettings(event) {
    event.preventDefault();
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const payload = {
        selected_model: form.selected_model,
        reasoning_effort: activeReasoningEffortId,
        organization_id: form.organization_id,
        project_id: form.project_id
      };
      if (form.api_key.trim()) payload.api_key = form.api_key.trim();
      const nextConfig = await request('/system-settings/openai', {
        method: 'PATCH',
        body: JSON.stringify(payload)
      });
      setConfig(nextConfig);
      setForm({
        api_key: '',
        selected_model: nextConfig.selected_model || '',
        reasoning_effort: nextConfig.selected_reasoning_effort || '',
        organization_id: nextConfig.organization_id || '',
        project_id: nextConfig.project_id || ''
      });
      setMessage('OpenAI settings saved.');
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function clearOpenAIKey() {
    if (!window.confirm('Remove the saved OpenAI API key?')) return;
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const nextConfig = await request('/system-settings/openai', {
        method: 'PATCH',
        body: JSON.stringify({ clear_api_key: true })
      });
      setConfig(nextConfig);
      setForm((current) => ({ ...current, api_key: '' }));
      setMessage('OpenAI API key removed.');
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function runOpenAITest(event) {
    event.preventDefault();
    setTesting(true);
    setError('');
    setMessage('');
    setTestResult(null);
    try {
      const result = await request('/system-settings/openai/test', {
        method: 'POST',
        body: JSON.stringify({
          model_id: form.selected_model,
          reasoning_effort: activeReasoningEffortId,
          prompt: testPrompt,
          max_output_tokens: Number(maxOutputTokens)
        })
      });
      setTestResult(result);
      setMessage('OpenAI API test completed.');
    } catch (err) {
      setError(err.message);
    } finally {
      setTesting(false);
    }
  }

  if (loading) return <div className="empty">Loading OpenAI settings...</div>;

  return (
    <div className="row row-cards system-settings-openai">
      <div className="col-12">
        <div className="alert alert-info">
          OpenAI settings are stored server-side and the saved API key is masked after saving. Pricing shown is {pricingSource.unit || 'USD per 1M tokens'} from {pricingSource.label || 'OpenAI pricing'}.
        </div>
      </div>
      {message && <div className="col-12"><AutoDismissAlert message={message} onDismiss={() => setMessage('')} /></div>}
      {error && <div className="col-12"><div className="alert alert-danger">{error}</div></div>}
      <KpiCard icon={IconKey} label="API Key" value={config?.api_key_configured ? 'Saved' : 'Missing'} tone={config?.api_key_configured ? 'green' : 'orange'} />
      <KpiCard icon={IconRobot} label="Selected Model" value={selectedModel?.id || '-'} tone="blue" />
      <KpiCard icon={IconSparkles} label="Reasoning" value={selectedReasoningEffort?.label || '-'} tone="cyan" />
      <KpiCard icon={IconShieldLock} label="Output Price" value={`${formatUsdPerMTok(selectedModel?.prices?.output)} / 1M`} tone="purple" />

      <div className="col-lg-5">
        <Card title={<CardHeaderContent><div><h3 className="card-title mb-0"><IconBrandOpenai size={18} className="me-2 text-muted" />API Configuration</h3></div></CardHeaderContent>}>
          <form onSubmit={saveOpenAISettings}>
            <div className="row g-3">
              <div className="col-12">
                <label className="form-label">OpenAI API Key</label>
                <input
                  className="form-control"
                  type="password"
                  autoComplete="off"
                  value={form.api_key}
                  onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                  placeholder={config?.api_key_configured ? `Saved key: ${config.api_key_hint}` : 'sk-...'}
                />
                <div className="form-hint">Leave blank to keep the saved key.</div>
              </div>
              <div className="col-md-6">
                <label className="form-label">Model</label>
                <select className="form-select" value={form.selected_model} onChange={(e) => updateSelectedModel(e.target.value)}>
                  {(config?.models || []).map((model) => (
                    <option value={model.id} key={model.id}>{model.label} - {model.category}</option>
                  ))}
                </select>
              </div>
              <div className="col-md-6">
                <label className="form-label">Reasoning Effort</label>
                <select className="form-select" value={activeReasoningEffortId} onChange={(e) => setForm({ ...form, reasoning_effort: e.target.value })}>
                  {selectedReasoningEfforts.map((effort) => (
                    <option value={effort.id} key={effort.id}>{effort.label}</option>
                  ))}
                </select>
                <div className="form-hint">{selectedReasoningEffort?.description || 'Controls reasoning token use for supported models.'}</div>
              </div>
              <div className="col-md-6">
                <label className="form-label">Organization ID</label>
                <input className="form-control" value={form.organization_id} onChange={(e) => setForm({ ...form, organization_id: e.target.value })} placeholder="Optional" />
              </div>
              <div className="col-md-6">
                <label className="form-label">Project ID</label>
                <input className="form-control" value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })} placeholder="Optional" />
              </div>
              {selectedModel && (
                <div className="col-12">
                  <div className="system-settings-openai-model-summary">
                    <span className="badge bg-blue-lt text-blue">{selectedModel.category}</span>
                    <div className="fw-semibold mt-2">{selectedModel.label}</div>
                    <div className="text-muted small">{selectedModel.recommended_for}</div>
                    <div className="system-settings-openai-model-meta">
                      <span>Context: {selectedModel.context_window}</span>
                      <span>Max output: {selectedModel.max_output}</span>
                      <span>Reasoning choices: {selectedModel.reasoning}</span>
                      <span>Selected effort: {selectedReasoningEffort?.label || '-'}</span>
                    </div>
                  </div>
                </div>
              )}
              <div className="col-12">
                <div className="btn-list justify-content-end">
                  {config?.api_key_configured && (
                    <button className="btn btn-outline-danger" type="button" onClick={clearOpenAIKey} disabled={saving}>
                      <IconTrash size={18} className="me-2" />Clear Key
                    </button>
                  )}
                  <button className="btn btn-primary" disabled={saving}>
                    <IconDeviceFloppy size={18} className="me-2" />{saving ? 'Saving...' : 'Save OpenAI Settings'}
                  </button>
                </div>
              </div>
            </div>
          </form>
        </Card>
      </div>

      <div className="col-lg-7">
        <Card title={<CardHeaderContent><div><h3 className="card-title mb-0"><IconPlayerPlay size={18} className="me-2 text-muted" />Test API</h3></div></CardHeaderContent>}>
          <form onSubmit={runOpenAITest}>
            <div className="row g-3">
              <div className="col-12">
                <label className="form-label">Test Prompt</label>
                <textarea className="form-control" rows="4" value={testPrompt} onChange={(e) => setTestPrompt(e.target.value)} />
              </div>
              <div className="col-md-4">
                <label className="form-label">Max Output Tokens</label>
                <input className="form-control" type="number" min="16" max="512" value={maxOutputTokens} onChange={(e) => setMaxOutputTokens(e.target.value)} />
              </div>
              <div className="col-md-8 d-flex align-items-end justify-content-end">
                <button className="btn btn-primary" disabled={testing || !config?.api_key_configured || !testPrompt.trim()}>
                  <IconPlayerPlay size={18} className="me-2" />{testing ? 'Testing...' : 'Run Test'}
                </button>
              </div>
              {!config?.api_key_configured && (
                <div className="col-12">
                  <div className="alert alert-warning mb-0">Save an OpenAI API key before running a test.</div>
                </div>
              )}
              {testResult && (
                <div className="col-12">
                  <div className="system-settings-openai-test-result">
                    <div className="d-flex flex-wrap gap-2 mb-2">
                      <span className="badge bg-green-lt text-green">Connected</span>
                      <span className="badge bg-blue-lt text-blue">{testResult.model}</span>
                      <span className="badge bg-purple-lt text-purple">{testResult.reasoning_effort}</span>
                      <span className="badge bg-secondary-lt">{testResult.latency_ms} ms</span>
                    </div>
                    <pre>{testResult.output_text || 'No text output returned.'}</pre>
                    {testResult.usage && (
                      <div className="text-muted small">Usage: {JSON.stringify(testResult.usage)}</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </form>
        </Card>
      </div>

      <div className="col-12">
        <Card title={<CardHeaderContent><div className="d-flex align-items-center justify-content-between gap-2 w-100"><h3 className="card-title mb-0"><IconDatabase size={18} className="me-2 text-muted" />Model Pricing</h3>{pricingSource.url && <a className="btn btn-sm btn-outline-primary" href={pricingSource.url} target="_blank" rel="noreferrer">Open Pricing</a>}</div></CardHeaderContent>}>
          <div className="table-responsive">
            <table className="table card-table table-vcenter system-settings-openai-pricing-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Category</th>
                  <th>Input</th>
                  <th>Cached Input</th>
                  <th>Output</th>
                  <th>Context</th>
                  <th>Reasoning</th>
                  <th>Recommended For</th>
                </tr>
              </thead>
              <tbody>
                {(config?.models || []).map((model) => (
                  <tr key={model.id} className={model.id === form.selected_model ? 'table-active' : undefined}>
                    <td className="fw-semibold">{model.id}</td>
                    <td><span className="badge bg-blue-lt text-blue">{model.category}</span></td>
                    <td>{formatUsdPerMTok(model.prices?.input)}</td>
                    <td>{formatUsdPerMTok(model.prices?.cached_input)}</td>
                    <td>{formatUsdPerMTok(model.prices?.output)}</td>
                    <td>{model.context_window}</td>
                    <td>{model.reasoning}</td>
                    <td className="system-settings-openai-recommendation">{model.recommended_for}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="text-muted small mt-3">
            Source checked {pricingSource.checked_at || 'recently'}. {pricingSource.note}
          </div>
        </Card>
      </div>
    </div>
  );
}

function StatusBadge({ value }) {
  const tone = value === 'RUNNING' || value === 'Reachable' || value === 'Installed' ? 'green' : value === 'ERROR' || value === 'Not reachable' ? 'red' : 'yellow';
  return <span className={`badge bg-${tone}-lt text-${tone}`}>{value || 'Not Configured'}</span>;
}

function OmadaControllerPage({ refresh }) {
  const [settings, setSettings] = useState(null);
  const [logs, setLogs] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [tab, setTab] = useState('Status');
  const [apiTab, setApiTab] = useState('Connection');
  const [autoChecked, setAutoChecked] = useState(false);
  const [installLog, setInstallLog] = useState(null);
  const [webResult, setWebResult] = useState(null);
  const [sshResult, setSshResult] = useState(null);
  const [nasResult, setNasResult] = useState(null);
  const [apiSettings, setApiSettings] = useState(null);
  const [sites, setSites] = useState([]);
  const [automationLogs, setAutomationLogs] = useState([]);
  const [automationResult, setAutomationResult] = useState(null);
  const [environment, setEnvironment] = useState('STAGING');
  const [profileForm, setProfileForm] = useState({ environment: 'STAGING', profile_name: '3JCentralPisowifi Staging RADIUS', radius_server_ip: '192.168.50.70', auth_port: 11812, accounting_port: 11813, shared_secret: generateSharedSecret(), accounting_enabled: true, interim_update_seconds: 300 });
  const [ssidForm, setSsidForm] = useState({ environment: 'STAGING', ssid_name: '3J-Test-WiFi' });
  const [fallback, setFallback] = useState(null);
  const [nasForm, setNasForm] = useState({ name: 'Omada Controller Staging', ip_address: '192.168.50.71', shortname: 'omada-staging', secret: generateSharedSecret(), type: 'Omada Controller' });
  const checklist = [
    'Omada API login works.',
    'Omada site selected.',
    'Matching NAS client created in 3JCentralPisowifi.',
    'Omada RADIUS profile created.',
    'Test SSID created.',
    'One AP is adopted and broadcasting SSID.',
    'Test user exists in 3JCentralPisowifi.',
    'Test user has wallet balance.',
    'Phone/laptop connects using test credentials.',
    'Access-Accept appears in RADIUS logs.',
    'Accounting Start creates active session.',
    'Interim update deducts wallet time.',
    'Second device using same account is rejected.',
    'Disconnect creates Stop packet or session becomes stale.',
    'Install and open Omada Controller.',
    'Complete Omada first-time setup.',
    'Adopt one Omada AP.',
    'Create SSID 3J-Test-WiFi with WPA2-Enterprise.',
    'Add RADIUS profile using 192.168.50.70 and staging ports 11812 / 11813.',
    'Enable accounting if available.',
    'Create a test user in 3JCentralPisowifi.',
    'Add manual wallet balance.',
    'Connect phone or laptop to 3J-Test-WiFi.',
    'Confirm Access-Accept in RADIUS logs.',
    'Confirm Accounting Start creates active session.',
    'Confirm Interim updates deduct wallet time.',
    'Confirm second device with same account is rejected.'
  ];
  const installed = Boolean(settings && ['INSTALLED', 'RUNNING', 'STOPPED', 'ERROR'].includes(settings.install_status));
  const webReachable = Boolean(webResult && (webResult.http?.status === 'Reachable' || webResult.https?.status === 'Reachable'));
  const canOpenOmada = installed && settings?.install_status !== 'NOT_INSTALLED' && webReachable;

  async function load() {
    setSettings(await request('/omada/settings'));
    setLogs(await request('/omada/logs'));
    setApiSettings(await request('/omada/api-settings'));
    setAutomationLogs(await request('/omada/automation-logs'));
    setFallback(await request(`/omada/manual-fallback-settings?environment=${environment}&shared_secret=${encodeURIComponent(profileForm.shared_secret)}`));
  }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    const staging = environment === 'STAGING';
    const nextSecret = profileForm.shared_secret || generateSharedSecret();
    setProfileForm({
      ...profileForm,
      environment,
      profile_name: `3JCentralPisowifi ${staging ? 'Staging' : 'Production'} RADIUS`,
      auth_port: staging ? 11812 : 1812,
      accounting_port: staging ? 11813 : 1813,
      shared_secret: nextSecret
    });
    setSsidForm({ ...ssidForm, environment });
    setNasForm({
      ...nasForm,
      name: `Omada Controller ${staging ? 'Staging' : 'Production'}`,
      shortname: `omada-${staging ? 'staging' : 'production'}`,
      secret: nextSecret
    });
    request(`/omada/manual-fallback-settings?environment=${environment}&shared_secret=${encodeURIComponent(nextSecret)}`).then(setFallback).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [environment]);
  useEffect(() => {
    if (installLog?.status !== 'RUNNING') return undefined;
    const timer = window.setInterval(async () => {
      try {
        const nextLogs = await request('/omada/logs');
        setLogs(nextLogs);
        const current = nextLogs.find((row) => row.id === installLog.id) || nextLogs.find((row) => row.action === 'INSTALL');
        if (current) {
          setInstallLog(current);
          if (current.status !== 'RUNNING') {
            setBusy('');
            const saved = await request('/omada/settings');
            setSettings(saved);
          }
        }
      } catch (_err) {
        // Keep polling on transient network/API errors.
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [installLog?.id, installLog?.status]);
  useEffect(() => {
    if (!settings || !['INSTALLED', 'RUNNING'].includes(settings.install_status) || webReachable) return undefined;
    let cancelled = false;
    const checkReachability = async () => {
      try {
        const data = await request('/omada/test-web', { method: 'POST', body: JSON.stringify({ host: settings.host, http_port: settings.http_port, https_port: settings.https_port }) });
        if (!cancelled) {
          setWebResult(data);
          if (data.http?.status === 'Reachable' || data.https?.status === 'Reachable') {
            setSettings(await request('/omada/settings'));
          }
        }
      } catch (_err) {
        // Keep the existing result; the next interval will retry.
      }
    };
    checkReachability();
    const timer = window.setInterval(checkReachability, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [settings?.install_status, settings?.host, settings?.http_port, settings?.https_port, webReachable]);
  useEffect(() => {
    if (webReachable && installLog) {
      setInstallLog(null);
      setBusy('');
    }
  }, [webReachable, installLog]);
  useEffect(() => {
    if (!settings || autoChecked) return;
    setAutoChecked(true);
    async function runAutoDetect() {
      try {
        const data = await request('/omada/test-web', { method: 'POST', body: JSON.stringify({ host: settings.host, http_port: settings.http_port, https_port: settings.https_port }) });
        setWebResult(data);
      } catch (_err) {
        setWebResult(null);
      }
      if (settings.ssh_username && (settings.has_ssh_password || settings.has_ssh_private_key)) {
        try {
          const data = await request('/omada/detect', { method: 'POST' });
          if (data.settings) setSettings(data.settings);
          setLogs(await request('/omada/logs'));
        } catch (_err) {
          await load().catch(() => {});
        }
      }
    }
    runAutoDetect();
  }, [settings, autoChecked]);
  if (!settings) return <div className="empty">Loading Omada Controller settings...</div>;

  async function save(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    try {
      const saved = await request('/omada/settings', { method: 'PUT', body: JSON.stringify(settings) });
      setSettings(saved);
      setMessage('Omada settings saved.');
      refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  async function action(name, confirmText) {
    if (confirmText && !window.confirm(confirmText)) return;
    setBusy(name);
    setError('');
    setMessage('');
    try {
      const data = await request(`/omada/${name}`, { method: 'POST' });
      if (data.settings) setSettings(data.settings);
      if (name === 'install') {
        setInstallLog({ id: data.log_id, action: 'INSTALL', status: 'RUNNING', progress_percent: 2, current_step: 'Queued' });
        setMessage('Omada install started.');
        await load();
        return;
      }
      setMessage(`Omada ${name} completed.`);
      await load();
    } catch (err) {
      setError(err.message);
      await load().catch(() => {});
    } finally {
      if (name !== 'install') setBusy('');
    }
  }

  async function testWeb() {
    setBusy('test-web');
    setError('');
    try {
      const data = await request('/omada/test-web', { method: 'POST', body: JSON.stringify({ host: settings.host, http_port: settings.http_port, https_port: settings.https_port }) });
      setWebResult(data);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function testSsh() {
    setBusy('test-ssh');
    setError('');
    try {
      const data = await request('/omada/test-ssh', { method: 'POST' });
      setSshResult(data);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function createNas(e) {
    e.preventDefault();
    setError('');
    const data = await request('/omada/create-matching-nas', { method: 'POST', body: JSON.stringify({ environment, name: nasForm.name, ip_address: nasForm.ip_address, shortname: nasForm.shortname, type: nasForm.type, shared_secret: nasForm.secret }) });
    setNasResult(data);
    setProfileForm({ ...profileForm, shared_secret: data.secret });
    setMessage('Matching RADIUS trust entry created.');
    setAutomationLogs(await request('/omada/automation-logs'));
    refresh();
  }

  async function saveApiSettings(e) {
    e.preventDefault();
    setBusy('save-api-settings');
    setError('');
    setMessage('');
    try {
      const saved = await request('/omada/api-settings', { method: 'PUT', body: JSON.stringify(apiSettings) });
      setApiSettings(saved);
      setMessage('Omada API settings saved.');
      setAutomationLogs(await request('/omada/automation-logs'));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function clearApiCredentials() {
    setBusy('clear-api-settings');
    setError('');
    try {
      const saved = await request('/omada/api-settings', { method: 'PUT', body: JSON.stringify({ remember_credentials: false }) });
      setApiSettings(saved);
      setMessage('Saved Omada API credentials cleared.');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function testApiLogin() {
    setBusy('test-api-login');
    setError('');
    setAutomationResult(null);
    try {
      const data = await request('/omada/test-api-login', { method: 'POST' });
      setAutomationResult(data);
      if (data.settings) setApiSettings(data.settings);
      setMessage(data.message || 'Omada API login succeeded.');
    } catch (err) {
      setError(err.message);
    } finally {
      setAutomationLogs(await request('/omada/automation-logs').catch(() => []));
      setBusy('');
    }
  }

  async function detectSites() {
    setBusy('detect-sites');
    setError('');
    setAutomationResult(null);
    try {
      const data = await request('/omada/detect-sites', { method: 'POST' });
      setAutomationResult(data);
      setSites(data.sites || []);
      if (data.settings) setApiSettings(data.settings);
      if (data.manual_fallback) setFallback(data.manual_fallback);
      setMessage(data.status === 'SUCCESS' ? 'Omada sites detected.' : data.message);
    } catch (err) {
      setError(err.message);
    } finally {
      setAutomationLogs(await request('/omada/automation-logs').catch(() => []));
      setBusy('');
    }
  }

  async function selectSite(site) {
    setBusy('select-site');
    setError('');
    try {
      const saved = await request('/omada/select-site', { method: 'PUT', body: JSON.stringify({ site_id: site.site_id, site_name: site.site_name }) });
      setApiSettings(saved);
      setMessage(`Selected Omada site: ${site.site_name}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  }

  async function createRadiusProfile() {
    setBusy('create-radius-profile');
    setError('');
    setAutomationResult(null);
    try {
      const data = await request('/omada/create-radius-profile', { method: 'POST', body: JSON.stringify(profileForm) });
      setAutomationResult(data);
      if (data.manual_fallback) setFallback(data.manual_fallback);
      setMessage(data.message);
    } catch (err) {
      setError(err.message);
    } finally {
      setAutomationLogs(await request('/omada/automation-logs').catch(() => []));
      setBusy('');
    }
  }

  async function createTestSsid() {
    setBusy('create-test-ssid');
    setError('');
    setAutomationResult(null);
    try {
      const data = await request('/omada/create-test-ssid', { method: 'POST', body: JSON.stringify(ssidForm) });
      setAutomationResult(data);
      if (data.manual_fallback) setFallback(data.manual_fallback);
      setMessage(data.message);
    } catch (err) {
      setError(err.message);
    } finally {
      setAutomationLogs(await request('/omada/automation-logs').catch(() => []));
      setBusy('');
    }
  }

  async function toggleChecklist(index) {
    const next = { ...(settings.checklist_progress || {}), [index]: !settings.checklist_progress?.[index] };
    const saved = await request('/omada/settings', { method: 'PUT', body: JSON.stringify({ checklist_progress: next }) });
    setSettings(saved);
  }

  const visibleInstallLog = webReachable ? null : (installLog || logs.find((row) => row.action === 'INSTALL' && row.status === 'RUNNING'));
  const installProgress = Math.min(100, Math.max(0, Number(visibleInstallLog?.progress_percent || 0)));
  const latestLog = logs[0];
  const radiusSecret = nasResult?.secret || nasForm.secret;

  return (
    <div className="row row-cards">
      {message && <div className="col-12"><div className="alert alert-info">{message}</div></div>}
      {error && <div className="col-12"><div className="alert alert-danger">{error}</div></div>}
      <div className="col-12">
        <div className="alert alert-info">
          Omada Controller is used to manage TP-Link Omada access points, open SSIDs, and WiFi settings. Captive Portal + Voucher is now the main customer access direction. WPA2-Enterprise/RADIUS automation remains available under Advanced for lab validation.
        </div>
      </div>

      <div className="col-12">
        <ul className="nav nav-tabs">
          {['Status', 'Settings', 'Portal Setup', 'AP / SSID Setup', 'Advanced', 'Logs'].map((item) => (
            <li className="nav-item" key={item}>
              <button className={`nav-link ${tab === item ? 'active' : ''}`} type="button" onClick={() => setTab(item)}>
                {item}
              </button>
            </li>
          ))}
        </ul>
      </div>

      {tab === 'Status' && <div className="col-12">
        <Card title="Controller Overview">
          <div className="row g-3">
            <div className="col-md-3"><div className="text-muted">Controller Server</div><div className="h3">{settings.host}</div></div>
            <div className="col-md-3">
              <div className="text-muted">Install Status</div>
              <div className="d-flex align-items-center gap-2 flex-wrap">
                <div className="h3 mb-0"><StatusBadge value={settings.install_status} /></div>
                {['NOT_INSTALLED', 'ERROR'].includes(settings.install_status) && (
                  <button className="btn btn-sm btn-primary" disabled={!!busy || !settings.ssh_username} onClick={() => action('install', 'Omada Controller will be installed on 192.168.50.71, not on the 3JCentralPisowifi server. Continue?')}>
                    <IconCloudUpload size={16} className="me-1" />Install Omada
                  </button>
                )}
              </div>
            </div>
            <div className="col-md-3"><div className="text-muted">RADIUS Server</div><div className="h3">192.168.50.70</div></div>
            <div className="col-md-3"><div className="text-muted">Last Check</div><div className="h3">{settings.last_status_check_at || 'Not checked'}</div></div>
          </div>
          {webResult && <div className="mt-3 d-flex gap-2 flex-wrap"><StatusBadge value={webResult.http.status} /><span>HTTP {webResult.http.port}</span><StatusBadge value={webResult.https.status} /><span>HTTPS {webResult.https.port}</span></div>}
          {visibleInstallLog && (
            <div className="mt-3 border rounded p-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <div className="fw-semibold">{visibleInstallLog.current_step || 'Installing Omada'}</div>
                <span className="badge bg-blue-lt text-blue">{installProgress}%</span>
              </div>
              <div className="progress">
                <div className={`progress-bar ${visibleInstallLog.status === 'FAILED' ? 'bg-danger' : 'bg-primary'}`} style={{ width: `${installProgress}%` }} />
              </div>
              <div className="text-muted small mt-2">
                {visibleInstallLog.status === 'RUNNING' ? 'Installation is running. Logs refresh automatically.' : `Install ${String(visibleInstallLog.status || '').toLowerCase()}.`}
              </div>
            </div>
          )}
          {settings.last_error && <div className="alert alert-warning mt-3 mb-0">{settings.last_error}</div>}
        </Card>
      </div>}

      {tab === 'Settings' && <div className="col-12">
        <Card title="Connection Settings">
          <form onSubmit={save}>
            <div className="row g-3">
              <div className="col-md-3"><label className="form-label">Controller Name</label><input className="form-control" value={settings.controller_name || ''} onChange={(e) => setSettings({ ...settings, controller_name: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Host</label><input className="form-control" value={settings.host || ''} onChange={(e) => setSettings({ ...settings, host: e.target.value, api_base_url: `https://${e.target.value}:${settings.https_port || 8043}` })} /></div>
              <div className="col-md-2"><label className="form-label">HTTP Port</label><input className="form-control" type="number" value={settings.http_port || 8088} onChange={(e) => setSettings({ ...settings, http_port: Number(e.target.value) })} /></div>
              <div className="col-md-2"><label className="form-label">HTTPS Port</label><input className="form-control" type="number" value={settings.https_port || 8043} onChange={(e) => setSettings({ ...settings, https_port: Number(e.target.value), api_base_url: `https://${settings.host}:${e.target.value}` })} /></div>
              <div className="col-md-2"><label className="form-label">API Username</label><input className="form-control" value={settings.api_username || ''} onChange={(e) => setSettings({ ...settings, api_username: e.target.value })} /></div>
              <div className="col-md-8"><label className="form-label">API Base URL</label><input className="form-control" value={settings.api_base_url || ''} onChange={(e) => setSettings({ ...settings, api_base_url: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">API Password</label><input className="form-control" type="password" placeholder={settings.has_api_password ? 'Saved, enter to replace' : 'Optional'} onChange={(e) => setSettings({ ...settings, api_password: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">API Token</label><input className="form-control" type="password" placeholder={settings.has_api_token ? 'Saved, enter to replace' : 'Optional'} onChange={(e) => setSettings({ ...settings, api_token: e.target.value })} /></div>
              <div className="col-12 d-flex gap-2 flex-wrap">
                <button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Settings</button>
                <button className="btn" type="button" disabled={!!busy} onClick={testWeb}>Test Web UI Reachability</button>
                {canOpenOmada ? <a className="btn" href={`http://${settings.host}:${settings.http_port}`} target="_blank" rel="noreferrer"><IconExternalLink size={18} className="me-2" />Open Omada HTTP UI</a> : <button className="btn" type="button" disabled><IconExternalLink size={18} className="me-2" />Open Omada HTTP UI</button>}
                {canOpenOmada ? <a className="btn" href={`https://${settings.host}:${settings.https_port}`} target="_blank" rel="noreferrer"><IconExternalLink size={18} className="me-2" />Open Omada HTTPS UI</a> : <button className="btn" type="button" disabled><IconExternalLink size={18} className="me-2" />Open Omada HTTPS UI</button>}
              </div>
            </div>
          </form>
          {webResult && <div className="mt-3 d-flex gap-2 flex-wrap"><StatusBadge value={webResult.http.status} /><span>HTTP {webResult.http.port}</span><StatusBadge value={webResult.https.status} /><span>HTTPS {webResult.https.port}</span></div>}
        </Card>
      </div>}

      {tab === 'Settings' && <div className="col-12">
        <Card title="SSH Installation Settings">
          <form onSubmit={save}>
            <div className="row g-3">
              <div className="col-md-3"><label className="form-label">SSH Host</label><input className="form-control" value={settings.ssh_host || ''} onChange={(e) => setSettings({ ...settings, ssh_host: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">SSH Port</label><input className="form-control" type="number" value={settings.ssh_port || 22} onChange={(e) => setSettings({ ...settings, ssh_port: Number(e.target.value) })} /></div>
              <div className="col-md-3"><label className="form-label">SSH Username</label><input className="form-control" value={settings.ssh_username || ''} onChange={(e) => setSettings({ ...settings, ssh_username: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Auth Type</label><select className="form-select" value={settings.ssh_auth_type || 'PASSWORD'} onChange={(e) => setSettings({ ...settings, ssh_auth_type: e.target.value })}><option value="PASSWORD">Password</option><option value="PRIVATE_KEY">Private Key</option></select></div>
              <div className="col-md-2"><label className="form-label">Sudo Mode</label><select className="form-select" value={settings.sudo_mode || 'PASSWORDLESS'} onChange={(e) => setSettings({ ...settings, sudo_mode: e.target.value })}><option value="PASSWORDLESS">passwordless sudo</option><option value="SUDO_PASSWORD">sudo with password</option><option value="NONE">no sudo</option></select></div>
              {settings.ssh_auth_type === 'PASSWORD' && <div className="col-md-4"><label className="form-label">SSH Password</label><input className="form-control" type="password" placeholder={settings.has_ssh_password ? 'Saved, enter to replace' : ''} onChange={(e) => setSettings({ ...settings, ssh_password: e.target.value })} /></div>}
              {settings.ssh_auth_type === 'PRIVATE_KEY' && <><div className="col-md-8"><label className="form-label">Private Key</label><textarea className="form-control" rows="5" placeholder={settings.has_ssh_private_key ? 'Saved, enter to replace' : ''} onChange={(e) => setSettings({ ...settings, ssh_private_key: e.target.value })} /></div><div className="col-md-4"><label className="form-label">Private Key Passphrase</label><input className="form-control" type="password" placeholder={settings.has_ssh_private_key_passphrase ? 'Saved, enter to replace' : 'Optional'} onChange={(e) => setSettings({ ...settings, ssh_private_key_passphrase: e.target.value })} /></div></>}
              <div className="col-md-3"><label className="form-label">Install Method</label><input className="form-control" value="DOCKER" readOnly /></div>
              <div className="col-md-3"><label className="form-label">Network Mode</label><select className="form-select" value={settings.network_mode || 'bridge'} onChange={(e) => setSettings({ ...settings, network_mode: e.target.value })}><option value="bridge">bridge</option><option value="host">host</option></select></div>
              <div className="col-md-6"><label className="form-label">Omada Docker Image</label><input className="form-control" value={settings.docker_image || ''} onChange={(e) => setSettings({ ...settings, docker_image: e.target.value })} /></div>
              <div className="col-12"><div className="alert alert-warning mb-0">Omada will be installed on the separate server you provide. For your setup, the Omada server is 192.168.50.71. Make sure this server is newly installed, reachable by SSH, and dedicated for Omada Controller.</div></div>
              <div className="col-12 d-flex gap-2 flex-wrap">
                <button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save SSH Settings</button>
                <button className="btn" type="button" disabled={!!busy} onClick={testSsh}>Test SSH Connection</button>
              </div>
            </div>
          </form>
          {sshResult && <div className="alert alert-success mt-3 mb-0">SSH reachable. Secrets were not displayed or logged.</div>}
        </Card>
      </div>}

      {tab === 'Portal Setup' && <div className="col-12">
        <Card title="Omada Portal Setup">
          <div className="alert alert-info">
            Captive Portal mode lets customers connect to an open WiFi network and enter a voucher on a web page. This avoids WPA2-Enterprise username/password prompts and is closer to the PisoWiFi experience.
          </div>
          <div className="row g-3">
            {[
              ['Open SSID', 'From APs Deployment configuration'],
              ['Portal URL', 'http://192.168.50.70/portal'],
              ['Staging Admin', 'http://192.168.50.70:8080/admin'],
              ['Portal Server', '3JCentralPisowifi'],
              ['Voucher Source', '3JCentralPisowifi Database'],
              ['Access Decision', 'Voucher + Wallet + Session rules']
            ].map(([label, value]) => (
              <div className="col-md-4" key={label}>
                <div className="border rounded p-3 h-100">
                  <div className="text-muted">{label}</div>
                  <div className="h3 mb-0">{value}</div>
                </div>
              </div>
            ))}
          </div>
          <div className="d-flex gap-2 flex-wrap mt-3">
            {['Create Open SSID', 'Configure External Portal', 'Configure Walled Garden', 'Test Portal Redirect'].map((label) => (
              <button className="btn" type="button" disabled key={label}>{label} <span className="badge bg-yellow-lt text-yellow ms-2">Coming in Captive Portal Integration Phase</span></button>
            ))}
          </div>
        </Card>
      </div>}

      {tab === 'AP / SSID Setup' && <div className="col-12">
        <Card title="AP / SSID Setup">
          <div className="row g-3">
            <div className="col-md-6">
              <div className="border rounded p-3 h-100">
                <h4>Current Direction</h4>
                <p className="text-muted mb-0">Create the open SSID from <strong>APs Deployment - Sites - Configurations</strong> and use captive portal enforcement in the next integration phase. Omada remains responsible for AP adoption, SSID configuration, and AP monitoring.</p>
              </div>
            </div>
            <div className="col-md-6">
              <div className="border rounded p-3 h-100">
                <h4>Parked Lab Feature</h4>
                <p className="text-muted mb-0">WPA2-Enterprise profile and test SSID automation are still available in Advanced. They are no longer the primary customer login path.</p>
              </div>
            </div>
          </div>
        </Card>
      </div>}

      {tab === 'Status' && <div className="col-12">
        <Card title="Detection & Status">
          <div className="row g-3">
            {['8088/tcp HTTP UI', '8043/tcp HTTPS UI', '8843/tcp future portal', '29810/udp discovery', '29811/tcp adoption', '29812/tcp adoption', '29813/tcp upgrade', '29814/tcp management'].map((item) => <div className="col-md-3" key={item}><span className="badge bg-blue-lt text-blue">{item}</span></div>)}
          </div>
        </Card>
      </div>}

      {tab === 'Status' && <div className="col-12">
        <Card title="Manage Omada">
          {settings.network_mode !== 'host' && (
            <div className="alert alert-warning">
              AP adoption can fail when Omada runs in Docker bridge mode because the controller may advertise its container IP. Apply host network mode so APs use {settings.host}.
            </div>
          )}
          <div className="d-flex gap-2 flex-wrap">
            <button className="btn" disabled={!!busy || !installed} onClick={() => action('start')}><IconPlayerPlay size={18} className="me-2" />Start Omada</button>
            <button className="btn btn-warning" disabled={!!busy || !installed} onClick={() => action('stop', 'Stop Omada Controller on 192.168.50.71?')}><IconPlayerStop size={18} className="me-2" />Stop Omada</button>
            <button className="btn" disabled={!!busy || !installed} onClick={() => action('restart', 'Restart Omada Controller on 192.168.50.71?')}><IconRefresh size={18} className="me-2" />Restart Omada</button>
            <button className="btn" disabled={!!busy || !installed} onClick={() => action('backup')}><IconArchive size={18} className="me-2" />Backup Omada</button>
            <button className="btn btn-primary" disabled={!!busy || !installed} onClick={() => action('apply-host-network', 'This will recreate Omada Controller on 192.168.50.71 using Docker host network mode. Continue?')}><IconSettings size={18} className="me-2" />Apply Host Network Fix</button>
            {canOpenOmada ? <a className="btn" href={`https://${settings.host}:${settings.https_port}`} target="_blank" rel="noreferrer"><IconExternalLink size={18} className="me-2" />Open Omada UI</a> : <button className="btn" type="button" disabled><IconExternalLink size={18} className="me-2" />Open Omada UI</button>}
          </div>
          {busy && <div className="text-muted mt-3">Running {busy}...</div>}
        </Card>
      </div>}

      {tab === 'Advanced' && <div className="col-12">
        <div className="alert alert-warning">
          Advanced tools are for engineering and network validation. The operator-facing customer flow is Captive Portal + Voucher.
        </div>
        <ul className="nav nav-pills">
          {['Connection', 'Sites', 'Profile & NAS', 'SSID', 'Fallback', 'RADIUS & AP Test', 'Automation Logs'].map((item) => (
            <li className="nav-item" key={item}>
              <button className={`nav-link ${apiTab === item ? 'active' : ''}`} type="button" onClick={() => setApiTab(item)}>
                {item}
              </button>
            </li>
          ))}
        </ul>
      </div>}

      {tab === 'Advanced' && apiTab === 'Connection' && <div className="col-12">
        <Card title="Omada API Connection">
          <form onSubmit={saveApiSettings}>
            <div className="row g-3">
              <div className="col-md-3"><label className="form-label">Controller Host</label><input className="form-control" value={apiSettings?.controller_host || '192.168.50.71'} onChange={(e) => setApiSettings({ ...apiSettings, controller_host: e.target.value, api_base_url: `https://${e.target.value}:${apiSettings?.https_port || 8043}` })} /></div>
              <div className="col-md-2"><label className="form-label">HTTPS Port</label><input className="form-control" type="number" value={apiSettings?.https_port || 8043} onChange={(e) => setApiSettings({ ...apiSettings, https_port: Number(e.target.value), api_base_url: `https://${apiSettings?.controller_host || '192.168.50.71'}:${e.target.value}` })} /></div>
              <div className="col-md-4"><label className="form-label">API Base URL</label><input className="form-control" value={apiSettings?.api_base_url || 'https://192.168.50.71:8043'} onChange={(e) => setApiSettings({ ...apiSettings, api_base_url: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Controller ID / Omada ID</label><input className="form-control" placeholder="Auto-detect if possible" value={apiSettings?.controller_id || ''} onChange={(e) => setApiSettings({ ...apiSettings, controller_id: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Username</label><input className="form-control" value={apiSettings?.username || ''} onChange={(e) => setApiSettings({ ...apiSettings, username: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Password</label><input className="form-control" type="password" placeholder={apiSettings?.has_password ? 'Saved, enter to replace' : ''} onChange={(e) => setApiSettings({ ...apiSettings, password: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">Remember Credentials</label><label className="form-check"><input className="form-check-input" type="checkbox" checked={apiSettings?.remember_credentials !== false} onChange={(e) => setApiSettings({ ...apiSettings, remember_credentials: e.target.checked })} /><span className="form-check-label">Encrypt and save password</span></label></div>
              <div className="col-md-3"><label className="form-label">Verify TLS Certificate</label><label className="form-check"><input className="form-check-input" type="checkbox" checked={!!apiSettings?.verify_tls} onChange={(e) => setApiSettings({ ...apiSettings, verify_tls: e.target.checked })} /><span className="form-check-label">Require trusted certificate</span></label></div>
              {!apiSettings?.verify_tls && <div className="col-12"><div className="alert alert-warning mb-0">TLS verification is disabled for lab testing with the Omada self-signed certificate.</div></div>}
              <div className="col-12"><div className="alert alert-info mb-0">Omada credentials are used only to configure AP and SSID settings. Customer accounts and balances are still managed by 3JCentralPisowifi.</div></div>
              <div className="col-12 d-flex gap-2 flex-wrap">
                <button className="btn btn-primary" disabled={!!busy}><IconDeviceFloppy size={18} className="me-2" />Save API Settings</button>
                <button className="btn" type="button" disabled={!!busy} onClick={testApiLogin}><IconShieldLock size={18} className="me-2" />Test API Login</button>
                <button className="btn" type="button" disabled={!!busy} onClick={clearApiCredentials}>Clear Saved Credentials</button>
                {canOpenOmada ? <a className="btn" href={`https://${settings.host}:${settings.https_port}`} target="_blank" rel="noreferrer"><IconExternalLink size={18} className="me-2" />Open Omada Controller</a> : <button className="btn" type="button" disabled><IconExternalLink size={18} className="me-2" />Open Omada Controller</button>}
              </div>
            </div>
          </form>
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'Sites' && <div className="col-12">
        <Card title="Omada Site Detection">
          <div className="d-flex gap-2 flex-wrap mb-3">
            <button className="btn btn-primary" disabled={!!busy} onClick={detectSites}><IconSearch size={18} className="me-2" />Refresh Sites</button>
            {apiSettings?.selected_site_id && <span className="badge bg-green-lt text-green align-self-center">Selected: {apiSettings.selected_site_name || apiSettings.selected_site_id}</span>}
          </div>
          {sites.length > 0 ? <Table rows={sites.map((site) => ({ ...site, select: <button className="btn btn-sm" onClick={() => selectSite(site)}>Select</button> }))} columns={['site_name', 'site_id', 'is_default', 'select']} /> : <div className="empty">No sites detected yet. Use Refresh Sites after API login succeeds.</div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'Profile & NAS' && <div className="col-12">
        <Card title="3JCentralPisowifi RADIUS Profile Builder">
          <div className="row g-3">
            <div className="col-md-2"><label className="form-label">Environment</label><select className="form-select" value={environment} onChange={(e) => setEnvironment(e.target.value)}><option value="STAGING">Staging</option><option value="PRODUCTION">Production</option></select></div>
            <div className="col-md-4"><label className="form-label">Profile Name</label><input className="form-control" value={profileForm.profile_name} onChange={(e) => setProfileForm({ ...profileForm, profile_name: e.target.value })} /></div>
            <div className="col-md-2"><label className="form-label">RADIUS Server</label><input className="form-control" value={profileForm.radius_server_ip} onChange={(e) => setProfileForm({ ...profileForm, radius_server_ip: e.target.value })} /></div>
            <div className="col-md-2"><label className="form-label">Auth Port</label><input className="form-control" type="number" value={profileForm.auth_port} onChange={(e) => setProfileForm({ ...profileForm, auth_port: Number(e.target.value) })} /></div>
            <div className="col-md-2"><label className="form-label">Accounting Port</label><input className="form-control" type="number" value={profileForm.accounting_port} onChange={(e) => setProfileForm({ ...profileForm, accounting_port: Number(e.target.value) })} /></div>
            <div className="col-md-4"><label className="form-label">Shared Secret</label><input className="form-control" value={profileForm.shared_secret} onChange={(e) => { setProfileForm({ ...profileForm, shared_secret: e.target.value }); setNasForm({ ...nasForm, secret: e.target.value }); }} /></div>
            <div className="col-md-2"><label className="form-label">Accounting</label><label className="form-check"><input className="form-check-input" type="checkbox" checked={profileForm.accounting_enabled} onChange={(e) => setProfileForm({ ...profileForm, accounting_enabled: e.target.checked })} /><span className="form-check-label">Enabled</span></label></div>
            <div className="col-md-2"><label className="form-label">Interim Update</label><input className="form-control" type="number" value={profileForm.interim_update_seconds} onChange={(e) => setProfileForm({ ...profileForm, interim_update_seconds: Number(e.target.value) })} /></div>
            <div className="col-md-4 d-flex align-items-end gap-2 flex-wrap"><button className="btn" type="button" onClick={() => { const secret = generateSharedSecret(); setProfileForm({ ...profileForm, shared_secret: secret }); setNasForm({ ...nasForm, secret }); }}>Generate Secret</button></div>
          </div>
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'Profile & NAS' && <div className="col-12">
        <Card title="Matching NAS Client">
          <form onSubmit={createNas}>
            <div className="row g-3 align-items-end">
              <div className="col-md-3"><label className="form-label">Name</label><input className="form-control" value={nasForm.name} onChange={(e) => setNasForm({ ...nasForm, name: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">IP Address</label><input className="form-control" value={nasForm.ip_address} onChange={(e) => setNasForm({ ...nasForm, ip_address: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Shortname</label><input className="form-control" value={nasForm.shortname} onChange={(e) => setNasForm({ ...nasForm, shortname: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Type</label><select className="form-select" value={nasForm.type} onChange={(e) => setNasForm({ ...nasForm, type: e.target.value })}><option>Omada Controller</option><option>Omada AP</option></select></div>
              <div className="col-md-2"><label className="form-label">Shared Secret</label><input className="form-control" value={nasForm.secret} onChange={(e) => { setNasForm({ ...nasForm, secret: e.target.value }); setProfileForm({ ...profileForm, shared_secret: e.target.value }); }} /></div>
              <div className="col-md-1"><button className="btn btn-primary w-100" disabled={!!busy}>Create</button></div>
            </div>
          </form>
          <div className="alert alert-info mt-3 mb-0">This creates the trusted client entry in 3JCentralPisowifi. It allows Omada or the AP to ask FreeRADIUS if a customer can connect. If FreeRADIUS logs show requests coming from the AP IP instead of the Omada Controller IP, create another NAS client for that AP IP using the same secret.</div>
          {nasResult && <div className="alert alert-success mt-3 mb-0">Created matching RADIUS trust entry. Shared secret: <code>{nasResult.secret}</code></div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'Profile & NAS' && <div className="col-12">
        <Card title="Create Omada RADIUS Profile">
          <div className="d-flex gap-2 flex-wrap">
            <button className="btn btn-primary" disabled={!!busy} onClick={createRadiusProfile}><IconWifi size={18} className="me-2" />Create Omada RADIUS Profile</button>
          </div>
          {automationResult && <div className={`alert mt-3 mb-0 ${automationResult.status === 'SUCCESS' ? 'alert-success' : 'alert-warning'}`}>
            <div className="fw-semibold">{automationResult.message || automationResult.status}</div>
            {automationResult.error && <div>{automationResult.error}</div>}
            <details className="mt-2"><summary>Technical details</summary><pre className="omada-log-output mt-2"><code>{JSON.stringify(automationResult.details || automationResult, null, 2)}</code></pre></details>
          </div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'SSID' && <div className="col-12">
        <Card title="Create Test WPA2-Enterprise SSID">
          <div className="row g-3 align-items-end">
            <div className="col-md-3"><label className="form-label">Environment</label><input className="form-control" value={environment} readOnly /></div>
            <div className="col-md-5"><label className="form-label">SSID Name</label><input className="form-control" value={ssidForm.ssid_name} onChange={(e) => setSsidForm({ ...ssidForm, ssid_name: e.target.value })} /></div>
            <div className="col-md-4"><button className="btn btn-primary" disabled={!!busy} onClick={createTestSsid}><IconRouter size={18} className="me-2" />Create Test WPA2-Enterprise SSID</button></div>
          </div>
          <div className="alert alert-info mt-3 mb-0">Advanced lab feature only. Captive Portal + Voucher is now the priority customer access path.</div>
          {automationResult && <div className={`alert mt-3 mb-0 ${automationResult.status === 'SUCCESS' ? 'alert-success' : 'alert-warning'}`}>
            <div className="fw-semibold">{automationResult.message || automationResult.status}</div>
            {automationResult.error && <div>{automationResult.error}</div>}
            <details className="mt-2"><summary>Technical details</summary><pre className="omada-log-output mt-2"><code>{JSON.stringify(automationResult.details || automationResult, null, 2)}</code></pre></details>
          </div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'Fallback' && <div className="col-12">
        <Card title="Manual Fallback Instructions">
          {fallback ? <div className="row g-3">
            <div className="col-md-6"><div className="border rounded p-3"><h4>Create RADIUS Profile in Omada</h4><pre><code>{`Profile Name: ${fallback.create_radius_profile.profile_name}\nAuthentication Server: ${fallback.create_radius_profile.authentication_server}\nAuthentication Port: ${fallback.create_radius_profile.authentication_port}\nAuthentication Secret: ${fallback.create_radius_profile.authentication_secret}\nAccounting: ${fallback.create_radius_profile.accounting}\nAccounting Server: ${fallback.create_radius_profile.accounting_server}\nAccounting Port: ${fallback.create_radius_profile.accounting_port}\nAccounting Secret: ${fallback.create_radius_profile.accounting_secret}\nInterim Update: ${fallback.create_radius_profile.interim_update} seconds`}</code></pre></div></div>
            <div className="col-md-6"><div className="border rounded p-3"><h4>Create SSID</h4><pre><code>{`SSID: ${fallback.create_ssid.ssid}\nSecurity: ${fallback.create_ssid.security}\nRADIUS Profile: ${fallback.create_ssid.radius_profile}\nVLAN: ${fallback.create_ssid.vlan}\nCaptive Portal: ${fallback.create_ssid.captive_portal}\nGuest Network: ${fallback.create_ssid.guest_network}`}</code></pre></div></div>
            <div className="col-12"><div className="alert alert-warning mb-0">{fallback.note}</div></div>
          </div> : <div className="empty">Fallback settings are loading.</div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'Automation Logs' && <div className="col-12">
        <Card title="Automation Logs">
          {automationLogs.length > 0 ? <Table rows={automationLogs.slice(0, 10)} columns={['action', 'status', 'error_message', 'created_at']} /> : <div className="empty">No Omada automation logs yet.</div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'RADIUS & AP Test' && <div className="col-12">
        <Card title="RADIUS Settings for Omada">
          <div className="row g-3">
            <div className="col-md-6"><div className="border rounded p-3"><h4>Staging RADIUS Test</h4><pre><code>{`RADIUS Server: 192.168.50.70\nAuthentication Port: 11812\nAccounting Port: 11813\nShared Secret: ${radiusSecret}\nAccounting: Enabled\nInterim Update: 300 seconds`}</code></pre></div></div>
            <div className="col-md-6"><div className="border rounded p-3"><h4>Production</h4><pre><code>{`RADIUS Server: 192.168.50.70\nAuthentication Port: 1812\nAccounting Port: 1813\nShared Secret: ${radiusSecret}\nAccounting: Enabled\nInterim Update: 300 seconds`}</code></pre></div></div>
          </div>
          <div className="alert alert-info mt-3 mb-0">Create a NAS / Router / AP Client entry in 3JCentralPisowifi for the Omada Controller or AP source IP before testing. The IP to register as NAS must be the IP that FreeRADIUS sees as the source of the RADIUS request. This may be the Omada Controller IP or the AP IP depending on Omada/AP behavior.</div>
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'RADIUS & AP Test' && <div className="col-12">
        <Card title="Create Matching RADIUS Trust Entry">
          <form onSubmit={createNas}>
            <div className="row g-3 align-items-end">
              <div className="col-md-3"><label className="form-label">Name</label><input className="form-control" value={nasForm.name} onChange={(e) => setNasForm({ ...nasForm, name: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">IP Address</label><input className="form-control" value={nasForm.ip_address} onChange={(e) => setNasForm({ ...nasForm, ip_address: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Shortname</label><input className="form-control" value={nasForm.shortname} onChange={(e) => setNasForm({ ...nasForm, shortname: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Type</label><select className="form-select" value={nasForm.type} onChange={(e) => setNasForm({ ...nasForm, type: e.target.value })}><option>Omada Controller</option><option>Omada AP</option></select></div>
              <div className="col-md-2"><label className="form-label">Shared Secret</label><input className="form-control" value={nasForm.secret} onChange={(e) => setNasForm({ ...nasForm, secret: e.target.value })} /></div>
              <div className="col-md-1"><button className="btn btn-primary w-100">Create</button></div>
            </div>
          </form>
          <div className="alert alert-info mt-3 mb-0">This creates the trusted client entry in 3JCentralPisowifi. It allows Omada or the AP to ask FreeRADIUS if a customer can connect.</div>
          {nasResult && <div className="alert alert-success mt-3 mb-0">Created matching RADIUS trust entry. Shared secret: <code>{nasResult.secret}</code></div>}
        </Card>
      </div>}

      {tab === 'Advanced' && apiTab === 'RADIUS & AP Test' && <div className="col-12">
        <Card title="Real AP Test Checklist">
          <div className="row g-2">
            {checklist.map((item, index) => (
              <div className="col-md-6" key={item}>
                <label className="form-check">
                  <input className="form-check-input" type="checkbox" checked={!!settings.checklist_progress?.[index]} onChange={() => toggleChecklist(index)} />
                  <span className="form-check-label">{index + 1}. {item}</span>
                </label>
              </div>
            ))}
          </div>
        </Card>
      </div>}

      {tab === 'Logs' && <div className="col-12">
        <Card title="Logs / Install Output">
          {latestLog ? <pre className="omada-log-output"><code>{latestLog.output_text || `${latestLog.action} ${latestLog.status}`}</code></pre> : <div className="empty">No Omada logs yet.</div>}
          <Table rows={logs.slice(0, 10).map(({ output_text, ...row }) => row)} columns={['action', 'status', 'created_at', 'completed_at']} />
        </Card>
      </div>}

      {tab === 'Logs' && <div className="col-12">
        <Card title="Automation Logs">
          {automationLogs.length > 0 ? <Table rows={automationLogs.slice(0, 10)} columns={['action', 'status', 'error_message', 'created_at']} /> : <div className="empty">No Omada automation logs yet.</div>}
        </Card>
      </div>}
    </div>
  );
}

const nav = [
  { page: 'Dashboard', icon: IconDashboard, tone: 'blue' },
  { page: 'AP & Client Map', icon: IconMapPin, tone: 'teal' },
  { page: 'Connected Devices', icon: IconWifi, tone: 'azure' },
  {
    page: 'APs Deployment',
    icon: IconRouter,
    tone: 'cyan',
    children: [
      { page: 'Sites', icon: IconMapPin, tone: 'cyan' },
      { page: 'List of APs', icon: IconWifi, tone: 'blue' },
      { page: 'Long Lat', icon: IconMapPin, tone: 'green' }
    ]
  },
  { page: 'Location Management', icon: IconMapPin, tone: 'green' },
  { page: 'Vouchers', icon: IconKey, tone: 'yellow' },
  { page: 'Wallet / Manual Top-Up', icon: IconCash, tone: 'green' },
  { page: 'Sessions', icon: IconHistory, tone: 'orange' },
  { page: 'Captive Portal', icon: IconWifi, tone: 'blue' },
  { page: 'Network', icon: IconRouter, tone: 'purple' },
  { page: 'Omada Controller', icon: IconServer, tone: 'cyan' },
  { page: 'System Settings', icon: IconSettings, tone: 'secondary' },
  { page: 'Logs', icon: IconListDetails, tone: 'yellow' }
];

const profilePages = {
  'View Profile': { icon: IconId, tone: 'blue' },
  'Change Password': { icon: IconKey, tone: 'blue' },
  'Advanced RADIUS Lab': { icon: IconWifi, tone: 'teal' },
  'MikroTik Scan Result': { icon: IconSearch, tone: 'blue' }
};

const flatNav = nav.flatMap((item) => item.children ? [item, ...item.children] : [item]);

function pageMeta(page) {
  return flatNav.find((item) => item.page === page) || profilePages[page] || { icon: IconShieldLock, tone: 'blue' };
}

function Sidebar({ page, setPage, me, logout, branding, collapsed }) {
  const [open, setOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [openGroups, setOpenGroups] = useState({ 'APs Deployment': true });
  const setActivePage = (nextPage) => {
    setPage(nextPage);
    setOpen(false);
    setProfileOpen(false);
  };
  const toggleGroup = (item) => {
    if (collapsed && item.children?.length) {
      setActivePage(item.children[0].page);
      return;
    }
    setOpenGroups((current) => ({ ...current, [item.page]: !current[item.page] }));
  };
  return (
    <aside className="navbar navbar-vertical navbar-expand-lg" data-bs-theme="dark">
      <div className="container-fluid">
        <button className="navbar-toggler" type="button" onClick={() => setOpen(!open)}><span className="navbar-toggler-icon" /></button>
        <h1 className="navbar-brand navbar-brand-autodark">
          <button className="brand-button" onClick={() => setActivePage('Dashboard')}>
            {collapsed ? <span className="brand-compact"><IconShieldLock size={22} /></span> : (branding.company_logo_url ? <img src={branding.company_logo_url} className="navbar-brand-logo" alt="Company Logo" /> : branding.display_name)}
          </button>
        </h1>
        <div className={`collapse navbar-collapse d-lg-flex flex-lg-column ${open ? 'show' : ''}`} id="sidebar-menu">
          <ul className="navbar-nav pt-lg-3">
            {nav.map((item) => {
              const Icon = item.icon;
              const hasChildren = Boolean(item.children?.length);
              const groupActive = hasChildren && item.children.some((child) => child.page === page);
              if (hasChildren) {
                const expanded = openGroups[item.page] || groupActive;
                return (
                  <li className={`nav-item nav-group ${groupActive ? 'active' : ''}`} key={item.page}>
                    <button className={`nav-link nav-group-toggle ${groupActive ? 'active' : ''}`} type="button" onClick={() => toggleGroup(item)} aria-expanded={expanded}>
                      <IconWrap><Icon size={20} /></IconWrap>
                      <span className="nav-link-title">{item.page}</span>
                      <span className="nav-group-chevron">{expanded ? <IconChevronDown size={16} /> : <IconChevronUp size={16} />}</span>
                    </button>
                    {!collapsed && expanded && (
                      <ul className="nav-submenu">
                        {item.children.map((child) => {
                          const ChildIcon = child.icon;
                          return (
                            <li className="nav-item" key={child.page}>
                              <button className={`nav-link nav-sub-link ${page === child.page ? 'active' : ''}`} onClick={() => setActivePage(child.page)}>
                                <IconWrap><ChildIcon size={18} /></IconWrap>
                                <span className="nav-link-title">{child.page}</span>
                              </button>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </li>
                );
              }
              return (
                <li className="nav-item" key={item.page}>
                  <button className={`nav-link ${page === item.page ? 'active' : ''}`} onClick={() => setActivePage(item.page)}>
                    <IconWrap><Icon size={20} /></IconWrap>
                    <span className="nav-link-title">{item.page}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="sidebar-user mt-auto">
            <div className="dropdown">
              <button className="sidebar-user-trigger" type="button" aria-expanded={!collapsed && profileOpen} onClick={() => !collapsed && setProfileOpen(!profileOpen)}>
                <span className="avatar avatar-sm bg-blue-lt text-blue"><IconUser size={18} /></span>
                <span className="sidebar-user-text">
                  <span className="sidebar-user-name">{me?.full_name || me?.username || 'Admin'}</span>
                  <span className="sidebar-user-role">{me?.role || 'admin'}</span>
                </span>
                <span className="sidebar-user-chevron">{profileOpen ? <IconChevronDown size={18} /> : <IconChevronUp size={18} />}</span>
              </button>
              {!collapsed && profileOpen && (
                <div className="sidebar-user-menu">
                  <button className="dropdown-item" onClick={() => setActivePage('View Profile')}><IconId size={18} className="me-2" />View Profile</button>
                  <button className="dropdown-item" onClick={() => setActivePage('Change Password')}><IconKey size={18} className="me-2" />Change Password</button>
                  <div className="dropdown-divider" />
                  <button className="dropdown-item text-danger" onClick={logout}><IconLogout size={18} className="me-2" />Logout</button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}

function Header({ page, dashboard, resources, onToggleSidebar, sidebarCollapsed }) {
  const meta = pageMeta(page);
  const PageIcon = meta.icon;
  const ramAllocated = resources?.ram_used_incl_cache_pct;
  return (
    <header className="navbar navbar-expand-md navbar-light d-print-none sticky-top">
      <div className="container-xl">
        <div className="d-flex w-100 align-items-center">
          <button className="topnav-title" type="button" onClick={onToggleSidebar} aria-pressed={sidebarCollapsed} title={sidebarCollapsed ? 'Expand side navigation' : 'Collapse side navigation'}>
            <span className={`badge bg-${meta.tone}-lt text-${meta.tone} header-icon-badge`}><PageIcon size={18} /></span>
            <div className="h3 m-0">{page}</div>
          </button>
          <div className="sys-metrics d-none d-lg-flex ms-auto gap-4">
            <div className="sys-metric text-muted"><IconCpu size={18} /><span>CPU {resources?.cpu_pct ?? 0}%</span></div>
            <div className="sys-metric text-muted"><IconServer size={18} /><span>RAM {resources?.ram_pressure_pct ?? 0}%{ramAllocated !== undefined ? ` · Alloc ${ramAllocated}%` : ''}</span></div>
            <div className="sys-metric text-muted"><IconDatabase size={18} /><span>DISK {resources?.disk_pct ?? 0}%</span></div>
            <div className="sys-metric text-muted"><IconClock size={18} /><span>UPTIME {formatUptime(resources?.uptime_seconds)}</span></div>
          </div>
        </div>
      </div>
    </header>
  );
}

function App() {
  const isPortalRoute = window.location.pathname.startsWith('/portal');
  const [authed, setAuthed] = useState(Boolean(localStorage.getItem('centralwifi_token')));
  const [page, setPage] = useState(() => pageFromLocation());
  const [dashboard, setDashboard] = useState(null);
  const [me, setMe] = useState(null);
  const [resources, setResources] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [branding, setBranding] = useState({ display_name: '3JCentralPisowifi', portal_subtitle: 'Source of Truth + Manual RADIUS Test MVP', accent_color: '#206bc4', company_logo_url: null, browser_logo_url: null });

  async function refresh() {
    if (localStorage.getItem('centralwifi_token')) {
      setDashboard(await request('/dashboard'));
      setMe(await request('/me'));
      setBranding(await publicRequest('/public/branding'));
    }
  }

  function navigatePage(nextPage, replace = false, explicitPath = null) {
    setPage(nextPage);
    const nextPath = explicitPath || routeForPage(nextPage);
    const currentPath = `${window.location.pathname}${window.location.search}`;
    if (currentPath !== nextPath) {
      window.history[replace ? 'replaceState' : 'pushState']({ page: nextPage }, '', nextPath);
    }
    if (nextPage === 'Long Lat') {
      window.dispatchEvent(new CustomEvent('longlat-site-filter-change'));
    }
  }

  useEffect(() => { publicRequest('/public/branding').then(setBranding).catch(() => {}); }, []);
  useEffect(() => {
    if (window.location.pathname === '/admin/' || window.location.pathname === '/admin') {
      window.history.replaceState({ page }, '', routeForPage(page));
    }
    const onPopState = () => setPage(pageFromLocation());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);
  useEffect(() => { if (authed) refresh().catch(() => setAuthed(false)); }, [authed]);
  useEffect(() => { document.documentElement.style.setProperty('--tblr-primary', branding.accent_color || '#206bc4'); }, [branding]);
  useEffect(() => {
    if (!branding.browser_logo_url) return;
    let link = document.querySelector("link[rel='icon']");
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      document.head.appendChild(link);
    }
    link.href = branding.browser_logo_url;
  }, [branding.browser_logo_url]);
  useEffect(() => {
    if (!authed) return undefined;
    let mounted = true;
    const loadResources = async () => {
      try {
        const data = await request('/system/resources');
        if (mounted) setResources(data);
      } catch (_err) {
        if (mounted) setResources(null);
      }
    };
    loadResources();
    const timer = window.setInterval(loadResources, 15000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [authed]);
  if (isPortalRoute) return <PortalApp />;
  if (!authed) return <Login onLogin={() => setAuthed(true)} branding={branding} />;

  const logout = () => {
    localStorage.removeItem('centralwifi_token');
    setAuthed(false);
  };

  return (
    <div className={`page ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <Sidebar page={page} setPage={navigatePage} me={me} logout={logout} branding={branding} collapsed={sidebarCollapsed} />
      <div className="page-wrapper">
        <Header page={page} dashboard={dashboard} resources={resources} onToggleSidebar={() => setSidebarCollapsed(!sidebarCollapsed)} sidebarCollapsed={sidebarCollapsed} />
        {page === 'Long Lat' ? (
          <LongLatPage />
        ) : page === 'AP & Client Map' ? (
          <ApClientMapPage />
        ) : (
          <div className="page-body">
            <div className="container-xl">
            {page === 'Dashboard' && <Dashboard data={dashboard} />}
            {page === 'Connected Devices' && <ConnectedDevicesPage />}
            {page === 'Sites' && <SitesDeploymentsPage />}
            {page === 'List of APs' && <ListOfApsPage />}
            {page === 'Location Management' && <LocationManagementPage />}
            {page === 'Vouchers' && <VouchersPage />}
            {page === 'Wallet / Manual Top-Up' && <WalletPage refresh={refresh} />}
            {page === 'Sessions' && <SessionsPage refresh={refresh} />}
            {page === 'Captive Portal' && <CaptivePortalPage />}
            {page === 'Portal Editor' && <CaptivePortalEditorPage />}
            {page === 'Network' && <NetworkPage refresh={refresh} />}
            {page === 'MikroTik Scan Result' && <MikroTikScanResultPage />}
            {page === 'Advanced RADIUS Lab' && <RadiusTestGuide refresh={refresh} />}
            {page === 'System Settings' && <SystemSettingsPage refresh={refresh} />}
            {page === 'Omada Controller' && <OmadaControllerPage refresh={refresh} />}
            {page === 'Logs' && <SimplePage title="Logs" endpoint="/audit-logs" columns={['action', 'target_type', 'target_id', 'details', 'created_at']} />}
            {['View Profile', 'Change Password'].includes(page) && <ProfilePage onSaved={refresh} />}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
