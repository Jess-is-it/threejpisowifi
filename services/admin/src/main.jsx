import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@tabler/core/dist/css/tabler.min.css';
import {
  IconActivity,
  IconAlertTriangle,
  IconCash,
  IconChevronDown,
  IconChevronUp,
  IconClock,
  IconCloudUpload,
  IconCpu,
  IconDashboard,
  IconDatabase,
  IconDeviceFloppy,
  IconHistory,
  IconId,
  IconKey,
  IconListDetails,
  IconLogout,
  IconRouter,
  IconSearch,
  IconSettings,
  IconShieldLock,
  IconServer,
  IconUser,
  IconUserCog,
  IconUserPlus,
  IconUsers,
  IconWallet,
  IconWifi
} from '@tabler/icons-react';
import './styles.css';

const API = '/api';

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
    if (!res.ok) throw new Error(data.detail || 'Request failed');
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
  users: 'Users',
  'wallet-manual-top-up': 'Wallet / Manual Top-Up',
  sessions: 'Sessions',
  'nas-router-ap-clients': 'NAS / Router / AP Clients',
  'radius-test-guide': 'RADIUS Test Guide',
  'system-settings': 'System Settings',
  logs: 'Logs',
  'view-profile': 'View Profile',
  'change-password': 'Change Password',
  'user-detail': 'Users'
};

function pageFromLocation() {
  const path = window.location.pathname.replace(/\/+$/, '');
  const slug = path.replace(/^\/admin\/?/, '');
  return routePages[slug] || 'Dashboard';
}

function routeForPage(page) {
  return `/admin/${slugify(page)}`;
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

function hasValidUntil(user) {
  if (!user.valid_until) return false;
  return new Date(user.valid_until).getTime() > Date.now();
}

function needsBalance(user) {
  return user.status === 'active' && !user.is_unlimited && Number(user.time_remaining_seconds || 0) <= 0 && !hasValidUntil(user);
}

function Login({ onLogin, branding }) {
  const [form, setForm] = useState({ username: '', password: '' });
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
        <div>
          <h3 className="card-title">{title}</h3>
          {subtitle && <div className="text-muted small mt-1">{subtitle}</div>}
        </div>
      </div>
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
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
      <KpiCard icon={IconDatabase} label="Database" value={health.database ? 'Online' : 'Offline'} tone="green" />
      <KpiCard icon={IconWifi} label="RADIUS" value="Managed" tone="blue" />
      <KpiCard icon={IconUsers} label="Users" value={stats.total_users || 0} tone="purple" />
      <KpiCard icon={IconRouter} label="NAS / Router / AP" value={stats.nas_clients || 0} tone="orange" />
      <KpiCard icon={IconActivity} label="Active Sessions" value={stats.active_sessions || 0} tone="red" />
      <div className="col-12">
        <Card title="Recent Auth Results" subtitle="Latest manual RADIUS Access-Accept and Access-Reject outcomes">
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
              <h4 className="mb-1">Users <span className="badge bg-azure-lt">{filtered.length}</span></h4>
              <div className="text-muted small">Create, search, disable, and reset Phase 1 RADIUS test users.</div>
            </div>
            <div className="d-flex flex-wrap gap-2 align-items-center">
              <span className="badge bg-blue-lt">Total: {counts.all}</span>
              <span className="badge bg-green-lt">Active: {counts.active}</span>
              <span className="badge bg-red-lt">Disabled: {counts.disabled}</span>
              <span className="badge bg-yellow-lt">Needs Balance: {counts.balance}</span>
              <button className="btn btn-primary" type="button" onClick={() => setCreateOpen(true)}><IconUserPlus size={18} className="me-2" />Create User</button>
            </div>
          </div>

          <ul className="nav nav-tabs users-tabs">
            {[
              ['all', 'All Users', 'blue', counts.all],
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
        <Modal title="Create User" onClose={() => setCreateOpen(false)}>
          <form onSubmit={create}>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Username</label><input className="form-control" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Password</label><input className="form-control" required type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Phone Number</label><input className="form-control" value={form.phone_number} onChange={(e) => setForm({ ...form, phone_number: e.target.value })} /></div>
            </div>
            <div className="modal-footer px-0 pb-0"><button type="button" className="btn" onClick={() => setCreateOpen(false)}>Cancel</button><button className="btn btn-primary"><IconUserPlus size={18} className="me-2" />Create User</button></div>
          </form>
        </Modal>
      )}

      {manageOpen && (
        <Modal title="Manage User" onClose={() => setManageOpen(false)}>
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

function Modal({ title, children, onClose }) {
  return (
    <>
      <div className="modal modal-blur fade show d-block" tabIndex="-1" role="dialog">
        <div className="modal-dialog modal-lg modal-dialog-centered">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">{title}</h5>
              <button type="button" className="btn-close" aria-label="Close" onClick={onClose} />
            </div>
            <div className="modal-body">{children}</div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show" onClick={onClose} />
    </>
  );
}

function WalletPage({ refresh }) {
  const [users, setUsers] = useState([]);
  const [topup, setTopup] = useState({ user_id: '', hours: 1, valid_until: '', is_unlimited: false, note: '' });
  async function load() { setUsers(await request('/users')); }
  useEffect(() => { load(); }, []);

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
    </div>
  );
}

function NasClients({ refresh }) {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState({ name: '', nas_ip: '', shortname: '', type: 'other', notes: '' });
  const [secret, setSecret] = useState('');
  async function load() { setRows(await request('/nas-clients')); }
  useEffect(() => { load(); }, []);
  async function create(e) {
    e.preventDefault();
    const data = await request('/nas-clients', { method: 'POST', body: JSON.stringify(form) });
    setSecret(data.secret);
    setForm({ name: '', nas_ip: '', shortname: '', type: 'other', notes: '' });
    await load(); refresh();
  }

  return (
    <div className="row row-cards">
      <div className="col-12">
        <Card title="Add NAS / Router / AP Client">
          <form onSubmit={create}>
            <div className="row g-3 align-items-end">
              <div className="col-md-3"><label className="form-label">Name</label><input className="form-control" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
              <div className="col-md-3"><label className="form-label">IP Address</label><input className="form-control" value={form.nas_ip} onChange={(e) => setForm({ ...form, nas_ip: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Shortname</label><input className="form-control" value={form.shortname} onChange={(e) => setForm({ ...form, shortname: e.target.value })} /></div>
              <div className="col-md-2"><label className="form-label">Type</label><input className="form-control" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} /></div>
              <div className="col-md-2"><button className="btn btn-primary w-100"><IconRouter size={18} className="me-2" />Add</button></div>
            </div>
          </form>
          {secret && <div className="alert alert-info mt-3">Shared secret for Phase 1 testing: <code>{secret}</code></div>}
        </Card>
      </div>
      <div className="col-12">
        <Card title="Configuration Guidance">
          <div className="text-muted">Set your router/AP RADIUS server IP to this Ubuntu server. Use staging ports <code>11812</code> and <code>11813</code> plus the shared secret.</div>
        </Card>
      </div>
      <div className="col-12">
        <Card title="NAS / Router / AP Clients">
          <Table rows={rows} columns={['name', 'nas_ip', 'shortname', 'type', 'status', 'notes', 'created_at']} />
        </Card>
      </div>
    </div>
  );
}

function SimplePage({ title, endpoint, columns, children }) {
  const [rows, setRows] = useState([]);
  useEffect(() => { request(endpoint).then((data) => setRows(Array.isArray(data) ? data : [])); }, [endpoint]);
  return <Card title={title}>{children}<Table rows={rows} columns={columns} /></Card>;
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

const nav = [
  { page: 'Dashboard', icon: IconDashboard, tone: 'blue' },
  { page: 'Users', icon: IconUsers, tone: 'azure' },
  { page: 'Wallet / Manual Top-Up', icon: IconCash, tone: 'green' },
  { page: 'Sessions', icon: IconHistory, tone: 'orange' },
  { page: 'NAS / Router / AP Clients', icon: IconRouter, tone: 'purple' },
  { page: 'RADIUS Test Guide', icon: IconWifi, tone: 'teal' },
  { page: 'System Settings', icon: IconSettings, tone: 'secondary' },
  { page: 'Logs', icon: IconListDetails, tone: 'yellow' }
];

const profilePages = {
  'View Profile': { icon: IconId, tone: 'blue' },
  'Change Password': { icon: IconKey, tone: 'blue' }
};

function pageMeta(page) {
  return nav.find((item) => item.page === page) || profilePages[page] || { icon: IconShieldLock, tone: 'blue' };
}

function Sidebar({ page, setPage, me, logout, branding, collapsed }) {
  const [open, setOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const setActivePage = (nextPage) => {
    setPage(nextPage);
    setOpen(false);
    setProfileOpen(false);
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

  function navigatePage(nextPage, replace = false) {
    setPage(nextPage);
    const nextPath = routeForPage(nextPage);
    if (window.location.pathname !== nextPath) {
      window.history[replace ? 'replaceState' : 'pushState']({ page: nextPage }, '', nextPath);
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
        <div className="page-body">
          <div className="container-xl">
            {page === 'Dashboard' && <Dashboard data={dashboard} />}
            {page === 'Users' && <UsersPage refresh={refresh} />}
            {page === 'Wallet / Manual Top-Up' && <WalletPage refresh={refresh} />}
            {page === 'NAS / Router / AP Clients' && <NasClients refresh={refresh} />}
            {page === 'Sessions' && <SimplePage title="Sessions" endpoint="/sessions" columns={['username', 'calling_station_id', 'nas_ip', 'framed_ip_address', 'start_time', 'last_update_time', 'stop_time', 'status']} />}
            {page === 'RADIUS Test Guide' && <Card title="Manual RADIUS Test"><div className="text-muted mb-3">Use radtest with a test user, password, server IP, port, and shared secret.</div><pre><code>radtest testuser password SERVER-IP:11812 0 shared-secret</code></pre></Card>}
            {page === 'System Settings' && <SystemSettingsPage refresh={refresh} />}
            {page === 'Logs' && <SimplePage title="Logs" endpoint="/audit-logs" columns={['action', 'target_type', 'target_id', 'details', 'created_at']} />}
            {['View Profile', 'Change Password'].includes(page) && <ProfilePage onSaved={refresh} />}
          </div>
        </div>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
