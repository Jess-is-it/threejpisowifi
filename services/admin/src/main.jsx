import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, Database, KeyRound, Radio, Router, UserPlus, Wallet } from 'lucide-react';
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
    <main className="login-shell">
      <section className="login-card">
        <div>
          <p className="eyebrow">Phase 1 Admin Portal</p>
          <h1>3JCentralPisowifi</h1>
          <p className="muted">Source of Truth + Manual RADIUS Test MVP</p>
        </div>
        <form onSubmit={submit} className="stack">
          <label>Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          {error && <p className="error">{error}</p>}
          <button className="primary">Log in</button>
        </form>
      </section>
    </main>
  );
}

function Card({ icon: Icon, label, value }) {
  return <div className="card"><Icon size={20} /><span>{label}</span><strong>{value}</strong></div>;
}

function Dashboard({ data }) {
  const stats = data?.stats || {};
  return (
    <section className="stack">
      <div className="grid">
        <Card icon={Activity} label="Environment" value={(data?.environment || 'unknown').toUpperCase()} />
        <Card icon={Database} label="Database Status" value={data?.health?.database ? 'Online' : 'Offline'} />
        <Card icon={Radio} label="FreeRADIUS Status" value="Container managed" />
        <Card icon={UserPlus} label="Total Users" value={stats.total_users || 0} />
        <Card icon={Router} label="NAS / Router / AP Clients" value={stats.nas_clients || 0} />
        <Card icon={Activity} label="Active Sessions" value={stats.active_sessions || 0} />
      </div>
      <Panel title="Recent Auth Results">
        <Table rows={data?.recent_auth || []} columns={['username', 'nas_ip', 'calling_station_id', 'result', 'reply_message', 'created_at']} />
      </Panel>
    </section>
  );
}

function Panel({ title, children }) {
  return <section className="panel"><h2>{title}</h2>{children}</section>;
}

function Table({ rows, columns }) {
  if (!rows.length) return <p className="muted">No records yet.</p>;
  return <div className="table-wrap"><table><thead><tr>{columns.map((c) => <th key={c}>{c.replaceAll('_', ' ')}</th>)}</tr></thead><tbody>{rows.map((row, i) => <tr key={i}>{columns.map((c) => <td key={c}>{String(row[c] ?? '')}</td>)}</tr>)}</tbody></table></div>;
}

function Users({ refresh }) {
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
    <section className="stack">
      <Panel title="Create User">
        <form className="form-row" onSubmit={create}>
          <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input placeholder="Password (8+ chars)" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <input placeholder="Phone number (optional)" value={form.phone_number} onChange={(e) => setForm({ ...form, phone_number: e.target.value })} />
          <button className="primary">Create</button>
        </form>
      </Panel>
      <Panel title="Manual Balance">
        <form className="form-row" onSubmit={addBalance}>
          <select value={topup.user_id} onChange={(e) => setTopup({ ...topup, user_id: e.target.value })}>
            <option value="">Select user</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <input type="number" min="1" value={topup.hours} onChange={(e) => setTopup({ ...topup, hours: e.target.value })} />
          <input type="datetime-local" value={topup.valid_until} onChange={(e) => setTopup({ ...topup, valid_until: e.target.value })} />
          <label className="inline-check"><input type="checkbox" checked={topup.is_unlimited} onChange={(e) => setTopup({ ...topup, is_unlimited: e.target.checked })} /> Unlimited</label>
          <input placeholder="Admin note" value={topup.note} onChange={(e) => setTopup({ ...topup, note: e.target.value })} />
          <button className="primary"><Wallet size={16} /> Add hours</button>
        </form>
      </Panel>
      <Panel title="Edit / Disable / Reset Password">
        <form className="form-row" onSubmit={updateUser}>
          <select value={manage.user_id} onChange={(e) => setManage({ ...manage, user_id: e.target.value })}>
            <option value="">Select user</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <select value={manage.status} onChange={(e) => setManage({ ...manage, status: e.target.value })}>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          <input placeholder="New password (optional)" type="password" value={manage.password} onChange={(e) => setManage({ ...manage, password: e.target.value })} />
          <button className="primary">Update user</button>
        </form>
      </Panel>
      <Panel title="Users">
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
    await load(); refresh();
  }
  return (
    <section className="stack">
      <Panel title="Add NAS / Router / AP Client">
        <form className="form-row" onSubmit={create}>
          <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input placeholder="IP address" value={form.nas_ip} onChange={(e) => setForm({ ...form, nas_ip: e.target.value })} />
          <input placeholder="Shortname" value={form.shortname} onChange={(e) => setForm({ ...form, shortname: e.target.value })} />
          <input placeholder="Type" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} />
          <button className="primary">Add client</button>
        </form>
        {secret && <p className="success">Generated shared secret: <code>{secret}</code>. Save it now.</p>}
      </Panel>
      <Panel title="Configuration Guidance">
        <p>Set your router/AP RADIUS server IP to this Ubuntu server. Use the environment auth/accounting ports and the shared secret shown when you create the client.</p>
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
  return <Panel title="Settings"><pre>{JSON.stringify(data, null, 2)}</pre></Panel>;
}

function App() {
  const [authed, setAuthed] = useState(Boolean(localStorage.getItem('centralwifi_token')));
  const [page, setPage] = useState('Dashboard');
  const [dashboard, setDashboard] = useState(null);
  async function refresh() {
    if (localStorage.getItem('centralwifi_token')) setDashboard(await request('/dashboard'));
  }
  useEffect(() => { if (authed) refresh().catch(() => setAuthed(false)); }, [authed]);
  if (!authed) return <Login onLogin={() => setAuthed(true)} />;
  const nav = ['Dashboard', 'Users', 'User Detail', 'Wallet / Manual Top-Up', 'Sessions', 'NAS / Router / AP Clients', 'RADIUS Test Guide', 'System Health', 'Settings', 'Audit Logs'];
  return (
    <main className="app-shell">
      <aside>
        <h1>3JCentralPisowifi</h1>
        <span className="badge">{(dashboard?.environment || 'unknown').toUpperCase()}</span>
        {nav.map((n) => <button key={n} className={page === n ? 'active' : ''} onClick={() => setPage(n)}>{n}</button>)}
        <button onClick={() => { localStorage.removeItem('centralwifi_token'); setAuthed(false); }}>Logout</button>
      </aside>
      <section className="content">
        <header><p className="eyebrow">Phase 1</p><h1>{page}</h1></header>
        {page === 'Dashboard' && <Dashboard data={dashboard} />}
        {['Users', 'User Detail', 'Wallet / Manual Top-Up'].includes(page) && <Users refresh={refresh} />}
        {page === 'NAS / Router / AP Clients' && <NasClients refresh={refresh} />}
        {page === 'Sessions' && <SimplePage title="Sessions" endpoint="/sessions" columns={['username', 'calling_station_id', 'nas_ip', 'framed_ip_address', 'start_time', 'last_update_time', 'stop_time', 'status']} />}
        {page === 'RADIUS Test Guide' && <Panel title="Manual RADIUS Test"><p>Use radtest with a test user, password, server IP, port, and shared secret. Production auth port is 1812. Staging auth port is 11812.</p><code>radtest testuser password SERVER-IP:11812 0 shared-secret</code></Panel>}
        {page === 'System Health' && <Dashboard data={dashboard} />}
        {page === 'Settings' && <Settings />}
        {page === 'Audit Logs' && <SimplePage title="Audit Logs" endpoint="/audit-logs" columns={['action', 'target_type', 'target_id', 'details', 'created_at']} />}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
