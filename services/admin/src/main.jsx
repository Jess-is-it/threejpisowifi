import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  Bell,
  BookOpen,
  CircleAlert,
  CircleCheck,
  ClipboardList,
  Database,
  History,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Radio,
  Router,
  Search,
  Server,
  Settings as SettingsIcon,
  ShieldCheck,
  UserPlus,
  Users,
  Wallet,
  Wifi
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

function formatValue(value) {
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
    <main className="auth-page">
      <section className="auth-art">
        <span className="brand-mark">3J</span>
        <p className="eyebrow">Phase 1 Admin Portal</p>
        <h1>Central WiFi control, built for manual RADIUS testing.</h1>
        <p className="muted">
          Manage users, manual balance, NAS / Router / AP clients, sessions, and auth logs from
          one source-of-truth portal.
        </p>
      </section>

      <section className="auth-card">
        <div>
          <p className="eyebrow">Sign in</p>
          <h2>Welcome back</h2>
          <p className="muted">Use the admin account created during install.</p>
        </div>
        <form onSubmit={submit} className="stack">
          <label>
            Username
            <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </label>
          <label>
            Password
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </label>
          {error && <p className="error">{error}</p>}
          <button className="primary" type="submit">
            <KeyRound size={17} /> Log in
          </button>
        </form>
      </section>
    </main>
  );
}

function MetricCard({ icon: Icon, label, value, tone = 'blue', hint }) {
  return (
    <article className={`metric-card tone-${tone}`}>
      <div className="metric-icon"><Icon size={22} /></div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        {hint && <small>{hint}</small>}
      </div>
    </article>
  );
}

function Panel({ title, subtitle, action, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p className="muted">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function StatusPill({ ok, children }) {
  return (
    <span className={`status-pill ${ok ? 'ok' : 'bad'}`}>
      {ok ? <CircleCheck size={14} /> : <CircleAlert size={14} />}
      {children}
    </span>
  );
}

function Table({ rows, columns }) {
  if (!rows.length) return <p className="empty-state">No records yet.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((c) => <th key={c}>{c.replaceAll('_', ' ')}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => <td key={c}>{formatValue(row[c])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Dashboard({ data }) {
  const stats = data?.stats || {};
  const health = data?.health || {};
  return (
    <section className="stack">
      <div className="welcome-panel">
        <div>
          <p className="eyebrow">Source of Truth + Manual RADIUS Test MVP</p>
          <h1>{(data?.environment || 'staging').toUpperCase()} Control Center</h1>
          <p>Keep Phase 1 focused: create test users, add manual balance, configure RADIUS clients, and verify sessions.</p>
        </div>
        <div className="welcome-health">
          <StatusPill ok={health.database}>Database {health.database ? 'Online' : 'Offline'}</StatusPill>
          <StatusPill ok={health.redis}>Redis {health.redis ? 'Online' : 'Offline'}</StatusPill>
        </div>
      </div>

      <div className="metric-grid">
        <MetricCard icon={Server} label="Environment" value={(data?.environment || 'unknown').toUpperCase()} tone="blue" />
        <MetricCard icon={Database} label="Database Status" value={health.database ? 'Online' : 'Offline'} tone="green" />
        <MetricCard icon={Radio} label="FreeRADIUS Status" value="Managed" tone="purple" hint="Docker service" />
        <MetricCard icon={Users} label="Total Users" value={stats.total_users || 0} tone="orange" />
        <MetricCard icon={Router} label="NAS / Router / AP Clients" value={stats.nas_clients || 0} tone="cyan" />
        <MetricCard icon={Activity} label="Active Sessions" value={stats.active_sessions || 0} tone="red" />
      </div>

      <div className="content-grid">
        <Panel title="Recent Auth Results" subtitle="Latest Access-Accept and Access-Reject outcomes" className="wide">
          <Table rows={data?.recent_auth || []} columns={['username', 'nas_ip', 'calling_station_id', 'result', 'reply_message', 'created_at']} />
        </Panel>
        <Panel title="RADIUS Ports" subtitle="Use these values for staging tests">
          <div className="port-list">
            <div><span>Authentication</span><strong>{health.radius_ports?.auth || 11812}/udp</strong></div>
            <div><span>Accounting</span><strong>{health.radius_ports?.accounting || 11813}/udp</strong></div>
          </div>
        </Panel>
      </div>
    </section>
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
    await load();
    refresh();
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
    await load();
    refresh();
  }

  async function updateUser(e) {
    e.preventDefault();
    const body = { status: manage.status };
    if (manage.password) body.password = manage.password;
    await request(`/users/${manage.user_id}`, { method: 'PATCH', body: JSON.stringify(body) });
    setManage({ user_id: '', status: 'active', password: '' });
    await load();
    refresh();
  }

  return (
    <section className="stack">
      <div className="content-grid">
        <Panel title="Create User" subtitle="Create a test login for radtest or a router/AP client">
          <form className="form-grid" onSubmit={create}>
            <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            <input placeholder="Password (8+ chars)" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <input placeholder="Phone number (optional)" value={form.phone_number} onChange={(e) => setForm({ ...form, phone_number: e.target.value })} />
            <button className="primary" type="submit"><UserPlus size={17} /> Create user</button>
          </form>
        </Panel>

        <Panel title="Manual Balance" subtitle="Add time, valid-until, or unlimited access">
          <form className="form-grid" onSubmit={addBalance}>
            <select value={topup.user_id} onChange={(e) => setTopup({ ...topup, user_id: e.target.value })}>
              <option value="">Select user</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
            </select>
            <input type="number" min="1" value={topup.hours} onChange={(e) => setTopup({ ...topup, hours: e.target.value })} />
            <input type="datetime-local" value={topup.valid_until} onChange={(e) => setTopup({ ...topup, valid_until: e.target.value })} />
            <label className="inline-check"><input type="checkbox" checked={topup.is_unlimited} onChange={(e) => setTopup({ ...topup, is_unlimited: e.target.checked })} /> Unlimited</label>
            <input placeholder="Admin note" value={topup.note} onChange={(e) => setTopup({ ...topup, note: e.target.value })} />
            <button className="primary" type="submit"><Wallet size={17} /> Add balance</button>
          </form>
        </Panel>
      </div>

      <Panel title="Edit / Disable / Reset Password" subtitle="Keep Phase 1 user changes explicit and auditable">
        <form className="form-row" onSubmit={updateUser}>
          <select value={manage.user_id} onChange={(e) => setManage({ ...manage, user_id: e.target.value })}>
            <option value="">Select user</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <select value={manage.status} onChange={(e) => setManage({ ...manage, status: e.target.value })}>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          <input placeholder="New password (optional)" type="password" value={manage.password} onChange={(e) => setManage({ ...manage, password: e.target.value })} />
          <button className="primary" type="submit">Update user</button>
        </form>
      </Panel>

      <Panel title="Users" subtitle="Manual Balance, Time Remaining, Valid Until, and Unlimited are shown here">
        <Table rows={users} columns={['username', 'phone_number', 'status', 'time_remaining_seconds', 'valid_until', 'is_unlimited', 'created_at']} />
      </Panel>
    </section>
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
    await load();
    refresh();
  }

  return (
    <section className="stack">
      <Panel title="Add NAS / Router / AP Client" subtitle="Use plain labels for routers, APs, and test RADIUS clients">
        <form className="form-row" onSubmit={create}>
          <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input placeholder="IP address" value={form.nas_ip} onChange={(e) => setForm({ ...form, nas_ip: e.target.value })} />
          <input placeholder="Shortname" value={form.shortname} onChange={(e) => setForm({ ...form, shortname: e.target.value })} />
          <input placeholder="Type" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} />
          <button className="primary" type="submit"><Router size={17} /> Add client</button>
        </form>
        {secret && <p className="success">Shared secret for Phase 1 testing: <code>{secret}</code>. Save it now.</p>}
      </Panel>

      <Panel title="Configuration Guidance" subtitle="MikroTik, Omada standalone AP, hostapd, and radtest use these same fields">
        <div className="guide-card">
          <Wifi />
          <p>Set your router/AP RADIUS server IP to this Ubuntu server. Use staging ports `11812/11813` and the shared secret shown when you create the client.</p>
        </div>
      </Panel>

      <Panel title="NAS / Router / AP Clients">
        <Table rows={rows} columns={['name', 'nas_ip', 'shortname', 'type', 'status', 'notes', 'created_at']} />
      </Panel>
    </section>
  );
}

function SimplePage({ title, endpoint, columns, children }) {
  const [rows, setRows] = useState([]);
  useEffect(() => { request(endpoint).then((data) => setRows(Array.isArray(data) ? data : [])); }, [endpoint]);
  return <Panel title={title}>{children}<Table rows={rows} columns={columns} /></Panel>;
}

function Settings() {
  const [data, setData] = useState({});
  useEffect(() => { request('/settings').then(setData); }, []);
  return <Panel title="Settings" subtitle="Environment settings from the API"><pre>{JSON.stringify(data, null, 2)}</pre></Panel>;
}

const navigationGroups = [
  {
    heading: 'Home',
    items: [
      { name: 'Dashboard', icon: LayoutDashboard },
      { name: 'System Health', icon: Activity }
    ]
  },
  {
    heading: 'Management',
    items: [
      { name: 'Users', icon: Users },
      { name: 'User Detail', icon: UserPlus },
      { name: 'Wallet / Manual Top-Up', icon: Wallet },
      { name: 'NAS / Router / AP Clients', icon: Router }
    ]
  },
  {
    heading: 'RADIUS',
    items: [
      { name: 'Sessions', icon: History },
      { name: 'RADIUS Test Guide', icon: Radio },
      { name: 'Audit Logs', icon: ClipboardList },
      { name: 'Settings', icon: SettingsIcon }
    ]
  }
];

function Sidebar({ page, setPage, environment, logout }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark small">3J</span>
        <div>
          <h1>3JCentral</h1>
          <p>Pisowifi Admin</p>
        </div>
      </div>
      <span className="env-badge">{environment.toUpperCase()}</span>
      <nav>
        {navigationGroups.map((group) => (
          <div className="nav-group" key={group.heading}>
            <h5>{group.heading}</h5>
            {group.items.map((item) => {
              const Icon = item.icon;
              return (
                <button key={item.name} className={page === item.name ? 'active' : ''} onClick={() => setPage(item.name)}>
                  <Icon size={18} />
                  <span>{item.name}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>
      <button className="logout-card" onClick={logout}>
        <LogOut size={18} />
        <span>Logout</span>
      </button>
    </aside>
  );
}

function Header({ page, dashboard, toggleMobile }) {
  return (
    <header className="topbar">
      <button className="icon-button mobile-menu" onClick={toggleMobile}><Menu size={20} /></button>
      <div>
        <p className="eyebrow">Phase 1</p>
        <h1>{page}</h1>
      </div>
      <div className="topbar-actions">
        <div className="search-box"><Search size={17} /><span>Search is parked for Phase 1</span></div>
        <button className="icon-button"><Bell size={18} /></button>
        <div className="profile-chip">
          <ShieldCheck size={17} />
          <span>{(dashboard?.environment || 'staging').toUpperCase()}</span>
        </div>
      </div>
    </header>
  );
}

function App() {
  const [authed, setAuthed] = useState(Boolean(localStorage.getItem('centralwifi_token')));
  const [page, setPage] = useState('Dashboard');
  const [dashboard, setDashboard] = useState(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  async function refresh() {
    if (localStorage.getItem('centralwifi_token')) setDashboard(await request('/dashboard'));
  }

  useEffect(() => { if (authed) refresh().catch(() => setAuthed(false)); }, [authed]);
  if (!authed) return <Login onLogin={() => setAuthed(true)} />;

  const logout = () => {
    localStorage.removeItem('centralwifi_token');
    setAuthed(false);
  };

  return (
    <main className={`app-shell ${mobileOpen ? 'sidebar-open' : ''}`}>
      <Sidebar
        page={page}
        setPage={(next) => { setPage(next); setMobileOpen(false); }}
        environment={dashboard?.environment || 'staging'}
        logout={logout}
      />
      <section className="content">
        <Header page={page} dashboard={dashboard} toggleMobile={() => setMobileOpen(!mobileOpen)} />
        <div className="page-content">
          {page === 'Dashboard' && <Dashboard data={dashboard} />}
          {['Users', 'User Detail', 'Wallet / Manual Top-Up'].includes(page) && <UsersPage refresh={refresh} />}
          {page === 'NAS / Router / AP Clients' && <NasClients refresh={refresh} />}
          {page === 'Sessions' && <SimplePage title="Sessions" endpoint="/sessions" columns={['username', 'calling_station_id', 'nas_ip', 'framed_ip_address', 'start_time', 'last_update_time', 'stop_time', 'status']} />}
          {page === 'RADIUS Test Guide' && (
            <Panel title="Manual RADIUS Test" subtitle="Use staging port 11812 unless testing production">
              <div className="guide-card">
                <BookOpen />
                <div>
                  <p>Use radtest with a test user, password, server IP, port, and shared secret.</p>
                  <code>radtest testuser password SERVER-IP:11812 0 shared-secret</code>
                </div>
              </div>
            </Panel>
          )}
          {page === 'System Health' && <Dashboard data={dashboard} />}
          {page === 'Settings' && <Settings />}
          {page === 'Audit Logs' && <SimplePage title="Audit Logs" endpoint="/audit-logs" columns={['action', 'target_type', 'target_id', 'details', 'created_at']} />}
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
