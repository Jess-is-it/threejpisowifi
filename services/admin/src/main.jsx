import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@tabler/core/dist/css/tabler.min.css';
import {
  IconActivity,
  IconAlertTriangle,
  IconCloudUpload,
  IconDashboard,
  IconDatabase,
  IconDeviceFloppy,
  IconHistory,
  IconId,
  IconKey,
  IconListDetails,
  IconLogout,
  IconRouter,
  IconSettings,
  IconShieldLock,
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

function fmt(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function IconWrap({ children }) {
  return <span className="nav-link-icon d-md-none d-lg-inline-block">{children}</span>;
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
      <div className="col-12">
        <div className="card hero-card">
          <div className="card-body">
            <div className="d-flex align-items-start justify-content-between gap-3 flex-wrap">
              <div>
                <div className="text-blue fw-bold text-uppercase small">Phase 1</div>
                <h2 className="mb-1">{(data?.environment || 'staging').toUpperCase()} Source of Truth</h2>
                <div className="text-muted">Manual RADIUS testing, users, balance, NAS clients, sessions, logs, and system settings.</div>
              </div>
              <div className="d-flex gap-2 flex-wrap">
                <span className={`badge ${health.database ? 'bg-green-lt text-green' : 'bg-red-lt text-red'}`}>Database {health.database ? 'Online' : 'Offline'}</span>
                <span className={`badge ${health.redis ? 'bg-green-lt text-green' : 'bg-red-lt text-red'}`}>Redis {health.redis ? 'Online' : 'Offline'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
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
  const [topup, setTopup] = useState({ user_id: '', hours: 1, valid_until: '', is_unlimited: false, note: '' });
  const [manage, setManage] = useState({ user_id: '', status: 'active', password: '' });

  async function load() { setUsers(await request('/users')); }
  useEffect(() => { load(); }, []);

  async function create(e) {
    e.preventDefault();
    await request('/users', { method: 'POST', body: JSON.stringify(form) });
    setForm({ username: '', password: '', phone_number: '' });
    await load(); refresh();
  }

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

  async function updateUser(e) {
    e.preventDefault();
    const body = { status: manage.status };
    if (manage.password) body.password = manage.password;
    await request(`/users/${manage.user_id}`, { method: 'PATCH', body: JSON.stringify(body) });
    setManage({ user_id: '', status: 'active', password: '' });
    await load(); refresh();
  }

  return (
    <div className="row row-cards">
      <div className="col-12 col-lg-6">
        <Card title="Create User" subtitle="Create a test account for manual RADIUS authentication">
          <form onSubmit={create}>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">Username</label><input className="form-control" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Password</label><input className="form-control" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
              <div className="col-12"><label className="form-label">Phone Number</label><input className="form-control" value={form.phone_number} onChange={(e) => setForm({ ...form, phone_number: e.target.value })} /></div>
            </div>
            <div className="mt-3"><button className="btn btn-primary"><IconUserPlus size={18} className="me-2" />Create User</button></div>
          </form>
        </Card>
      </div>
      <div className="col-12 col-lg-6">
        <Card title="Wallet / Manual Top-Up" subtitle="Add time balance, valid-until, or unlimited access">
          <form onSubmit={addBalance}>
            <div className="row g-3">
              <div className="col-md-6">
                <label className="form-label">User</label>
                <select className="form-select" value={topup.user_id} onChange={(e) => setTopup({ ...topup, user_id: e.target.value })}>
                  <option value="">Select user</option>{users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
                </select>
              </div>
              <div className="col-md-6"><label className="form-label">Hours</label><input className="form-control" type="number" min="1" value={topup.hours} onChange={(e) => setTopup({ ...topup, hours: e.target.value })} /></div>
              <div className="col-md-6"><label className="form-label">Valid Until</label><input className="form-control" type="datetime-local" value={topup.valid_until} onChange={(e) => setTopup({ ...topup, valid_until: e.target.value })} /></div>
              <div className="col-md-6 d-flex align-items-end"><label className="form-check mb-2"><input className="form-check-input" type="checkbox" checked={topup.is_unlimited} onChange={(e) => setTopup({ ...topup, is_unlimited: e.target.checked })} /><span className="form-check-label">Unlimited</span></label></div>
              <div className="col-12"><label className="form-label">Admin Note</label><input className="form-control" value={topup.note} onChange={(e) => setTopup({ ...topup, note: e.target.value })} /></div>
            </div>
            <div className="mt-3"><button className="btn btn-primary"><IconWallet size={18} className="me-2" />Add Balance</button></div>
          </form>
        </Card>
      </div>
      <div className="col-12">
        <Card title="Edit / Disable / Reset Password" subtitle="Basic Phase 1 user maintenance">
          <form onSubmit={updateUser}>
            <div className="row g-3 align-items-end">
              <div className="col-md-4">
                <label className="form-label">User</label>
                <select className="form-select" value={manage.user_id} onChange={(e) => setManage({ ...manage, user_id: e.target.value })}>
                  <option value="">Select user</option>{users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
                </select>
              </div>
              <div className="col-md-3"><label className="form-label">Status</label><select className="form-select" value={manage.status} onChange={(e) => setManage({ ...manage, status: e.target.value })}><option value="active">Active</option><option value="disabled">Disabled</option></select></div>
              <div className="col-md-3"><label className="form-label">New Password</label><input className="form-control" type="password" value={manage.password} onChange={(e) => setManage({ ...manage, password: e.target.value })} /></div>
              <div className="col-md-2"><button className="btn btn-primary w-100">Save User</button></div>
            </div>
          </form>
        </Card>
      </div>
      <div className="col-12">
        <Card title="Users">
          <Table rows={users} columns={['username', 'phone_number', 'status', 'time_remaining_seconds', 'valid_until', 'is_unlimited', 'created_at']} />
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
  const tabs = ['Branding', 'Access', 'System Update', 'Backup', 'Danger'];
  const [tab, setTab] = useState('Branding');
  const [settings, setSettings] = useState(null);
  const [admins, setAdmins] = useState([]);
  const [newAdmin, setNewAdmin] = useState({ username: '', password: '', full_name: '', email: '', role: 'admin' });
  const [danger, setDanger] = useState({ action: 'clear_auth_logs', confirmation: '', current_password: '' });
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

      {tab === 'Branding' && (
        <Card title="Branding">
          <form onSubmit={saveSettings}>
            <div className="row g-3">
              <div className="col-md-6"><label className="form-label">System Display Name</label><input className="form-control" value={settings.branding?.display_name || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, display_name: e.target.value } })} /></div>
              <div className="col-md-6"><label className="form-label">Portal Subtitle</label><input className="form-control" value={settings.branding?.portal_subtitle || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_subtitle: e.target.value } })} /></div>
              <div className="col-md-3"><label className="form-label">Accent Color</label><input className="form-control form-control-color" type="color" value={settings.branding?.accent_color || '#206bc4'} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, accent_color: e.target.value } })} /></div>
            </div>
            <div className="mt-3"><button className="btn btn-primary"><IconDeviceFloppy size={18} className="me-2" />Save Branding</button></div>
          </form>
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
  { page: 'Dashboard', icon: IconDashboard },
  { page: 'Users', icon: IconUsers },
  { page: 'User Detail', icon: IconUser },
  { page: 'Wallet / Manual Top-Up', icon: IconWallet },
  { page: 'Sessions', icon: IconHistory },
  { page: 'NAS / Router / AP Clients', icon: IconRouter },
  { page: 'RADIUS Test Guide', icon: IconWifi },
  { page: 'System Settings', icon: IconSettings },
  { page: 'Logs', icon: IconListDetails }
];

function Sidebar({ page, setPage, me, logout, branding }) {
  const [open, setOpen] = useState(false);
  return (
    <aside className="navbar navbar-vertical navbar-expand-lg" data-bs-theme="dark">
      <div className="container-fluid">
        <button className="navbar-toggler" type="button" onClick={() => setOpen(!open)}><span className="navbar-toggler-icon" /></button>
        <h1 className="navbar-brand navbar-brand-autodark">
          <button className="brand-button" onClick={() => setPage('Dashboard')}>{branding.display_name}</button>
        </h1>
        <div className={`collapse navbar-collapse d-lg-flex flex-lg-column ${open ? 'show' : ''}`} id="sidebar-menu">
          <ul className="navbar-nav pt-lg-3">
            {nav.map((item) => {
              const Icon = item.icon;
              return (
                <li className="nav-item" key={item.page}>
                  <button className={`nav-link ${page === item.page ? 'active' : ''}`} onClick={() => { setPage(item.page); setOpen(false); }}>
                    <IconWrap><Icon size={20} /></IconWrap>
                    <span className="nav-link-title">{item.page}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="sidebar-user mt-auto">
            <div className="dropdown">
              <button className="sidebar-user-trigger" type="button">
                <span className="avatar avatar-sm bg-blue-lt text-blue"><IconUser size={18} /></span>
                <span className="sidebar-user-text">
                  <span className="sidebar-user-name">{me?.full_name || me?.username || 'Admin'}</span>
                  <span className="sidebar-user-role">{me?.role || 'admin'}</span>
                </span>
              </button>
              <div className="sidebar-user-menu">
                <button className="dropdown-item" onClick={() => setPage('View Profile')}><IconId size={18} className="me-2" />View Profile</button>
                <button className="dropdown-item" onClick={() => setPage('Change Password')}><IconKey size={18} className="me-2" />Change Password</button>
                <div className="dropdown-divider" />
                <button className="dropdown-item text-danger" onClick={logout}><IconLogout size={18} className="me-2" />Logout</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}

function Header({ page, dashboard }) {
  return (
    <header className="navbar navbar-expand-md navbar-light d-print-none sticky-top">
      <div className="container-xl">
        <div className="d-flex w-100 align-items-center">
          <div className="d-flex align-items-center gap-2">
            <span className="badge bg-blue-lt text-blue header-icon-badge"><IconShieldLock size={18} /></span>
            <div className="h3 m-0">{page}</div>
          </div>
          <div className="sys-metrics d-none d-lg-flex ms-auto gap-4">
            <div className="sys-metric text-muted"><IconActivity size={18} /><span>ENV {(dashboard?.environment || 'staging').toUpperCase()}</span></div>
            <div className="sys-metric text-muted"><IconDatabase size={18} /><span>DB {dashboard?.health?.database ? 'OK' : 'ERR'}</span></div>
            <div className="sys-metric text-muted"><IconCloudUpload size={18} /><span>API {dashboard ? 'OK' : '...'}</span></div>
          </div>
        </div>
      </div>
    </header>
  );
}

function App() {
  const [authed, setAuthed] = useState(Boolean(localStorage.getItem('centralwifi_token')));
  const [page, setPage] = useState('Dashboard');
  const [dashboard, setDashboard] = useState(null);
  const [me, setMe] = useState(null);
  const [branding, setBranding] = useState({ display_name: '3JCentralPisowifi', portal_subtitle: 'Source of Truth + Manual RADIUS Test MVP', accent_color: '#206bc4' });

  async function refresh() {
    if (localStorage.getItem('centralwifi_token')) {
      setDashboard(await request('/dashboard'));
      setMe(await request('/me'));
      setBranding(await publicRequest('/public/branding'));
    }
  }

  useEffect(() => { publicRequest('/public/branding').then(setBranding).catch(() => {}); }, []);
  useEffect(() => { if (authed) refresh().catch(() => setAuthed(false)); }, [authed]);
  useEffect(() => { document.documentElement.style.setProperty('--tblr-primary', branding.accent_color || '#206bc4'); }, [branding]);
  if (!authed) return <Login onLogin={() => setAuthed(true)} branding={branding} />;

  const logout = () => {
    localStorage.removeItem('centralwifi_token');
    setAuthed(false);
  };

  return (
    <div className="page">
      <Sidebar page={page} setPage={setPage} me={me} logout={logout} branding={branding} />
      <div className="page-wrapper">
        <Header page={page} dashboard={dashboard} />
        <div className="page-body">
          <div className="container-xl">
            {page === 'Dashboard' && <Dashboard data={dashboard} />}
            {['Users', 'User Detail', 'Wallet / Manual Top-Up'].includes(page) && <UsersPage refresh={refresh} />}
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
