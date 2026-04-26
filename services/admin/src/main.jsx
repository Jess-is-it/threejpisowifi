import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  AlertTriangle,
  Archive,
  BookOpen,
  ClipboardList,
  Database,
  Download,
  History,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  Radio,
  RefreshCcw,
  Router,
  Save,
  Settings,
  Shield,
  User,
  UserCog,
  UserPlus,
  Users,
  Wallet
} from 'lucide-react';
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

function fmt(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function Login({ onLogin }) {
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
    <main className="login-page">
      <div className="login-bg" />
      <section className="login-shell">
        <div className="login-copy">
          <span className="logo-mark">3J</span>
          <h1>3JCentralPisowifi</h1>
          <p>Source of Truth + Manual RADIUS Test MVP</p>
        </div>
        <form className="login-card" onSubmit={submit}>
          <p className="kicker">Admin access</p>
          <h2>Sign in</h2>
          <label>Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          {error && <div className="alert danger">{error}</div>}
          <button className="btn primary" type="submit"><KeyRound size={16} /> Sign in</button>
        </form>
      </section>
    </main>
  );
}

function Card({ title, subtitle, children, footer }) {
  return (
    <section className="card">
      <div className="card-header">
        <div>
          <h3>{title}</h3>
          {subtitle && <p>{subtitle}</p>}
        </div>
      </div>
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </section>
  );
}

function Table({ rows, columns }) {
  if (!rows.length) return <div className="empty">No records yet.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{columns.map((c) => <th key={c}>{c.replaceAll('_', ' ')}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr key={idx}>{columns.map((c) => <td key={c}>{fmt(row[c])}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Stat({ icon: Icon, label, value, tone = 'blue' }) {
  return (
    <div className={`stat ${tone}`}>
      <span><Icon size={18} /></span>
      <div><p>{label}</p><strong>{value}</strong></div>
    </div>
  );
}

function Dashboard({ data }) {
  const stats = data?.stats || {};
  const health = data?.health || {};
  return (
    <div className="stack">
      <div className="hero-card">
        <div>
          <p className="kicker">Phase 1</p>
          <h2>{(data?.environment || 'staging').toUpperCase()} Source of Truth</h2>
          <p>Use this portal to manually test RADIUS users, balance, NAS clients, sessions, and audit trails.</p>
        </div>
        <div className="hero-badges">
          <span className={health.database ? 'badge green' : 'badge red'}>Database {health.database ? 'Online' : 'Offline'}</span>
          <span className={health.redis ? 'badge green' : 'badge red'}>Redis {health.redis ? 'Online' : 'Offline'}</span>
        </div>
      </div>
      <div className="stats-grid">
        <Stat icon={Database} label="Database" value={health.database ? 'Online' : 'Offline'} tone="green" />
        <Stat icon={Radio} label="RADIUS" value="Managed" tone="blue" />
        <Stat icon={Users} label="Users" value={stats.total_users || 0} tone="indigo" />
        <Stat icon={Router} label="NAS / Router / AP" value={stats.nas_clients || 0} tone="orange" />
        <Stat icon={Activity} label="Active Sessions" value={stats.active_sessions || 0} tone="red" />
      </div>
      <Card title="Recent Auth Results" subtitle="Latest manual RADIUS authentication outcomes">
        <Table rows={data?.recent_auth || []} columns={['username', 'nas_ip', 'calling_station_id', 'result', 'reply_message', 'created_at']} />
      </Card>
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
    <div className="stack">
      <div className="grid-2">
        <Card title="Create User" subtitle="Create a test user for manual RADIUS authentication">
          <form className="form-grid" onSubmit={create}>
            <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            <input placeholder="Password" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <input placeholder="Phone number (optional)" value={form.phone_number} onChange={(e) => setForm({ ...form, phone_number: e.target.value })} />
            <button className="btn primary" type="submit"><UserPlus size={16} /> Create User</button>
          </form>
        </Card>
        <Card title="Wallet / Manual Top-Up" subtitle="Add balance, valid-until, or unlimited access">
          <form className="form-grid" onSubmit={addBalance}>
            <select value={topup.user_id} onChange={(e) => setTopup({ ...topup, user_id: e.target.value })}>
              <option value="">Select user</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
            </select>
            <input type="number" min="1" value={topup.hours} onChange={(e) => setTopup({ ...topup, hours: e.target.value })} />
            <input type="datetime-local" value={topup.valid_until} onChange={(e) => setTopup({ ...topup, valid_until: e.target.value })} />
            <label className="check"><input type="checkbox" checked={topup.is_unlimited} onChange={(e) => setTopup({ ...topup, is_unlimited: e.target.checked })} /> Unlimited</label>
            <input placeholder="Admin note" value={topup.note} onChange={(e) => setTopup({ ...topup, note: e.target.value })} />
            <button className="btn primary" type="submit"><Wallet size={16} /> Add Balance</button>
          </form>
        </Card>
      </div>
      <Card title="Edit / Disable / Reset Password" subtitle="Basic Phase 1 user maintenance">
        <form className="form-row" onSubmit={updateUser}>
          <select value={manage.user_id} onChange={(e) => setManage({ ...manage, user_id: e.target.value })}>
            <option value="">Select user</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <select value={manage.status} onChange={(e) => setManage({ ...manage, status: e.target.value })}>
            <option value="active">Active</option><option value="disabled">Disabled</option>
          </select>
          <input placeholder="New password (optional)" type="password" value={manage.password} onChange={(e) => setManage({ ...manage, password: e.target.value })} />
          <button className="btn primary" type="submit">Save User</button>
        </form>
      </Card>
      <Card title="Users">
        <Table rows={users} columns={['username', 'phone_number', 'status', 'time_remaining_seconds', 'valid_until', 'is_unlimited', 'created_at']} />
      </Card>
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
    <div className="stack">
      <Card title="Add NAS / Router / AP Client">
        <form className="form-row" onSubmit={create}>
          <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input placeholder="IP address" value={form.nas_ip} onChange={(e) => setForm({ ...form, nas_ip: e.target.value })} />
          <input placeholder="Shortname" value={form.shortname} onChange={(e) => setForm({ ...form, shortname: e.target.value })} />
          <input placeholder="Type" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} />
          <button className="btn primary" type="submit"><Router size={16} /> Add Client</button>
        </form>
        {secret && <div className="alert info">Shared secret for Phase 1 testing: <code>{secret}</code></div>}
      </Card>
      <Card title="Configuration Guidance">
        <p className="muted">Set your router/AP RADIUS server IP to this Ubuntu server. Use staging ports <code>11812</code> and <code>11813</code> plus the shared secret.</p>
      </Card>
      <Card title="NAS / Router / AP Clients">
        <Table rows={rows} columns={['name', 'nas_ip', 'shortname', 'type', 'status', 'notes', 'created_at']} />
      </Card>
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
    <div className="grid-2">
      <Card title="View Profile" subtitle="Admin account details">
        {message && <div className="alert info">{message}</div>}
        <form className="form-grid" onSubmit={saveProfile}>
          <input value={profile.username || ''} readOnly />
          <input placeholder="Full name" value={profile.full_name || ''} onChange={(e) => setProfile({ ...profile, full_name: e.target.value })} />
          <input placeholder="Email" value={profile.email || ''} onChange={(e) => setProfile({ ...profile, email: e.target.value })} />
          <input value={profile.role || ''} readOnly />
          <button className="btn primary" type="submit"><Save size={16} /> Save Profile</button>
        </form>
      </Card>
      <Card title="Change Password" subtitle="Confirm your current password before saving">
        <form className="form-grid" onSubmit={changePassword}>
          <input type="password" placeholder="Current password" value={passwords.current_password} onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })} />
          <input type="password" placeholder="New password" value={passwords.new_password} onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })} />
          <input type="password" placeholder="Confirm new password" value={passwords.confirm_password} onChange={(e) => setPasswords({ ...passwords, confirm_password: e.target.value })} />
          <button className="btn primary" type="submit"><Lock size={16} /> Save Password</button>
        </form>
      </Card>
    </div>
  );
}

function SystemSettingsPage({ refresh }) {
  const tabs = ['Branding', 'Access', 'Backup', 'Danger', 'System Update'];
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
    <div className="stack">
      {message && <div className="alert info">{message}</div>}
      <div className="tabs">{tabs.map((t) => <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>{t}</button>)}</div>

      {tab === 'Branding' && (
        <Card title="Branding" subtitle="New project naming and portal labels">
          <form className="form-grid" onSubmit={saveSettings}>
            <input value={settings.branding?.display_name || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, display_name: e.target.value } })} />
            <input value={settings.branding?.portal_subtitle || ''} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, portal_subtitle: e.target.value } })} />
            <input type="color" value={settings.branding?.accent_color || '#206bc4'} onChange={(e) => setSettings({ ...settings, branding: { ...settings.branding, accent_color: e.target.value } })} />
            <button className="btn primary" type="submit"><Save size={16} /> Save Branding</button>
          </form>
        </Card>
      )}

      {tab === 'Access' && (
        <div className="stack">
          <Card title="Create Admin" subtitle="Basic admin access management for Phase 1">
            <form className="form-row" onSubmit={createAdmin}>
              <input placeholder="Username" value={newAdmin.username} onChange={(e) => setNewAdmin({ ...newAdmin, username: e.target.value })} />
              <input placeholder="Password" type="password" value={newAdmin.password} onChange={(e) => setNewAdmin({ ...newAdmin, password: e.target.value })} />
              <input placeholder="Full name" value={newAdmin.full_name} onChange={(e) => setNewAdmin({ ...newAdmin, full_name: e.target.value })} />
              <input placeholder="Email" value={newAdmin.email} onChange={(e) => setNewAdmin({ ...newAdmin, email: e.target.value })} />
              <button className="btn primary" type="submit"><UserCog size={16} /> Add Admin</button>
            </form>
          </Card>
          <Card title="Admins">
            <Table rows={admins} columns={['username', 'full_name', 'email', 'role', 'status', 'created_at']} />
          </Card>
        </div>
      )}

      {tab === 'Backup' && <BackupPanel />}
      {tab === 'System Update' && <UpdatePanel />}

      {tab === 'Danger' && (
        <Card title="Danger" subtitle="Password-confirmed destructive maintenance actions">
          <form className="form-grid" onSubmit={runDanger}>
            <select value={danger.action} onChange={(e) => setDanger({ ...danger, action: e.target.value })}>
              <option value="clear_auth_logs">Clear authentication logs</option>
              <option value="clear_sessions">Clear session records</option>
            </select>
            <input placeholder={danger.action === 'clear_sessions' ? 'Type CLEAR SESSIONS' : 'Type CLEAR AUTH LOGS'} value={danger.confirmation} onChange={(e) => setDanger({ ...danger, confirmation: e.target.value })} />
            <input type="password" placeholder="Current admin password" value={danger.current_password} onChange={(e) => setDanger({ ...danger, current_password: e.target.value })} />
            <button className="btn danger" type="submit"><AlertTriangle size={16} /> Run Danger Action</button>
          </form>
        </Card>
      )}
    </div>
  );
}

function BackupPanel() {
  const [data, setData] = useState(null);
  useEffect(() => { request('/system/backup').then(setData); }, []);
  if (!data) return null;
  return (
    <Card title="Backup" subtitle="Run backups from the Ubuntu host">
      <div className="command-list">
        <label>Backup command<code>{data.backup_command}</code></label>
        <label>Restore command<code>{data.restore_command}</code></label>
      </div>
      <p className="muted">{data.note}</p>
    </Card>
  );
}

function UpdatePanel() {
  const [data, setData] = useState(null);
  useEffect(() => { request('/system/update').then(setData); }, []);
  if (!data) return null;
  return (
    <Card title="System Update" subtitle="Use staging updates before production">
      <div className="command-list">
        <label>Local update<code>{data.update_command}</code></label>
        <label>One-line update<code>{data.one_line_update}</code></label>
      </div>
      <p className="muted">Environment: {data.environment}. Branch: {data.branch}.</p>
    </Card>
  );
}

const nav = [
  { page: 'Dashboard', icon: LayoutDashboard },
  { page: 'Users', icon: Users },
  { page: 'Sessions', icon: History },
  { page: 'NAS / Router / AP Clients', icon: Router },
  { page: 'RADIUS Test Guide', icon: Radio },
  { page: 'System Health', icon: Activity },
  { page: 'System Settings', icon: Settings },
  { page: 'Audit Logs', icon: ClipboardList }
];

function Sidebar({ page, setPage, me, logout }) {
  return (
    <aside className="sidebar">
      <div className="brand"><span className="logo-mark small">3J</span><strong>CentralPisowifi</strong></div>
      <nav>{nav.map((item) => {
        const Icon = item.icon;
        return <button key={item.page} className={page === item.page ? 'active' : ''} onClick={() => setPage(item.page)}><Icon size={18} /> {item.page}</button>;
      })}</nav>
      <div className="sidebar-user">
        <button onClick={() => setPage('View Profile')}><User size={18} /><span>{me?.full_name || me?.username || 'Admin'}<small>{me?.role || 'admin'}</small></span></button>
        <button onClick={() => setPage('Change Password')}><KeyRound size={18} /> Change Password</button>
        <button className="logout" onClick={logout}><LogOut size={18} /> Logout</button>
      </div>
    </aside>
  );
}

function Header({ page, dashboard }) {
  return (
    <header className="topbar">
      <div><p className="kicker">3JCentralPisowifi</p><h1>{page}</h1></div>
      <div className="sys-metrics">
        <span>ENV {(dashboard?.environment || 'staging').toUpperCase()}</span>
        <span>DB {dashboard?.health?.database ? 'OK' : 'ERR'}</span>
        <span>API {dashboard ? 'OK' : '...'}</span>
      </div>
    </header>
  );
}

function App() {
  const [authed, setAuthed] = useState(Boolean(localStorage.getItem('centralwifi_token')));
  const [page, setPage] = useState('Dashboard');
  const [dashboard, setDashboard] = useState(null);
  const [me, setMe] = useState(null);

  async function refresh() {
    if (localStorage.getItem('centralwifi_token')) {
      setDashboard(await request('/dashboard'));
      setMe(await request('/me'));
    }
  }
  useEffect(() => { if (authed) refresh().catch(() => setAuthed(false)); }, [authed]);
  if (!authed) return <Login onLogin={() => setAuthed(true)} />;

  const logout = () => {
    localStorage.removeItem('centralwifi_token');
    setAuthed(false);
  };

  return (
    <main className="page">
      <Sidebar page={page} setPage={setPage} me={me} logout={logout} />
      <section className="page-wrapper">
        <Header page={page} dashboard={dashboard} />
        <div className="page-body">
          {page === 'Dashboard' && <Dashboard data={dashboard} />}
          {page === 'Users' && <UsersPage refresh={refresh} />}
          {page === 'NAS / Router / AP Clients' && <NasClients refresh={refresh} />}
          {page === 'Sessions' && <SimplePage title="Sessions" endpoint="/sessions" columns={['username', 'calling_station_id', 'nas_ip', 'framed_ip_address', 'start_time', 'last_update_time', 'stop_time', 'status']} />}
          {page === 'RADIUS Test Guide' && <Card title="Manual RADIUS Test"><p className="muted">Use radtest with a test user, password, server IP, port, and shared secret.</p><code>radtest testuser password SERVER-IP:11812 0 shared-secret</code></Card>}
          {page === 'System Health' && <Dashboard data={dashboard} />}
          {page === 'Audit Logs' && <SimplePage title="Audit Logs" endpoint="/audit-logs" columns={['action', 'target_type', 'target_id', 'details', 'created_at']} />}
          {page === 'System Settings' && <SystemSettingsPage refresh={refresh} />}
          {['View Profile', 'Change Password'].includes(page) && <ProfilePage onSaved={refresh} />}
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
