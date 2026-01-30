/* Central WiFi Admin - lightweight SPA (no build tool / no runtime deps). */

const $ = (sel) => document.querySelector(sel);
const app = $("#app");
const title = $("#pageTitle");

function tokenGet() {
  return window.localStorage.getItem("cw_admin_token");
}
function tokenSet(t) {
  window.localStorage.setItem("cw_admin_token", t);
}
function tokenClear() {
  window.localStorage.removeItem("cw_admin_token");
}

async function apiFetch(path, init) {
  const headers = new Headers((init && init.headers) || {});
  headers.set("Content-Type", "application/json");
  const t = tokenGet();
  if (t) headers.set("Authorization", `Bearer ${t}`);
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let body = {};
    try { body = await res.json(); } catch {}
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

function setActiveNav(route) {
  document.querySelectorAll(".links a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
}

function html(strings, ...vals) {
  return strings.map((s, i) => s + (vals[i] ?? "")).join("");
}

function errBox(msg) {
  return `<div class="err">${escapeHtml(msg)}</div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));
}

function route() {
  const h = window.location.hash || "#/dashboard";
  // Hash routes look like `#/users`. In a JS regex literal, `/` must be escaped as `\/`.
  const m = h.match(/^#\/([a-z-]+)/);
  return m ? m[1] : "dashboard";
}

async function viewLogin() {
  title.textContent = "Sign in";
  setActiveNav("");
  app.innerHTML = html`
    <div class="row">
      <div class="muted">Use the credentials printed by <span class="mono">deploy/install.sh</span>.</div>
      <form id="loginForm" class="row" style="max-width:520px">
        <div class="grid2">
          <div class="field">
            <label>USERNAME</label>
            <input id="loginUser" value="admin" autocomplete="username" />
          </div>
          <div class="field">
            <label>PASSWORD</label>
            <input id="loginPass" type="password" autocomplete="current-password" />
          </div>
        </div>
        <div id="loginErr"></div>
        <div>
          <button class="btn" type="submit">Sign in</button>
        </div>
      </form>
    </div>
  `;

  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#loginErr").innerHTML = "";
    const username = $("#loginUser").value.trim();
    const password = $("#loginPass").value;
    try {
      const res = await apiFetch("/api/v1/admin/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      tokenSet(res.token);
      window.location.hash = "#/dashboard";
    } catch (e2) {
      $("#loginErr").innerHTML = errBox(e2.message);
    }
  });
}

async function viewDashboard() {
  title.textContent = "Dashboard";
  setActiveNav("dashboard");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const users = await apiFetch("/api/v1/admin/users");
    const sessions = await apiFetch("/api/v1/admin/sessions");
    app.innerHTML = html`
      <div class="grid2">
        <div class="card" style="box-shadow:none">
          <div class="kicker">USERS</div>
          <div style="font-size:34px;font-weight:900">${users.length}</div>
        </div>
        <div class="card" style="box-shadow:none">
          <div class="kicker">ACTIVE SESSIONS</div>
          <div style="font-size:34px;font-weight:900">${sessions.length}</div>
        </div>
      </div>
      <div style="margin-top:12px" class="muted">
        Tip: for lab testing, run <span class="mono">docker compose exec -T radius radclient ...</span>.
      </div>
    `;
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewUsers() {
  title.textContent = "Users & Wallet";
  setActiveNav("users");
  app.innerHTML = "<div class='muted'>Loading...</div>";

  let users = [];
  try {
    users = await apiFetch("/api/v1/admin/users");
  } catch (e) {
    app.innerHTML = errBox(e.message);
    return;
  }

  app.innerHTML = html`
    <div class="grid2">
      <div class="row">
        <div class="kicker">CREATE USER</div>
        <form id="createUserForm" class="row">
          <div class="field">
            <label>PHONE (E.164)</label>
            <input id="newPhone" value="+15551234567" />
          </div>
          <div id="createUserErr"></div>
          <button class="btn" type="submit">Create</button>
        </form>

        <div style="margin-top:10px" class="kicker">USERS</div>
        <table class="table" id="usersTable">
          <thead><tr><th>PHONE</th><th>STATUS</th></tr></thead>
          <tbody>
            ${users.map((u) => `<tr class="click" data-id="${u.id}"><td><b>${escapeHtml(u.phone)}</b></td><td>${escapeHtml(u.status)}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>

      <div class="row">
        <div class="kicker">WALLET</div>
        <div id="walletPane" class="muted">Select a user to view and credit their wallet.</div>
      </div>
    </div>
  `;

  $("#createUserForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#createUserErr").innerHTML = "";
    const phone = $("#newPhone").value.trim();
    try {
      await apiFetch("/api/v1/admin/users", { method: "POST", body: JSON.stringify({ phone }) });
      window.location.hash = "#/users";
      await viewUsers();
    } catch (e2) {
      $("#createUserErr").innerHTML = errBox(e2.message);
    }
  });

  $("#usersTable").addEventListener("click", async (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    const id = Number(tr.dataset.id);
    const u = users.find((x) => x.id === id);
    await loadWalletPane(u);
  });
}

async function loadWalletPane(u) {
  const pane = $("#walletPane");
  pane.innerHTML = "<div class='muted'>Loading wallet...</div>";
  try {
    const w = await apiFetch(`/api/v1/admin/users/${u.id}/wallet`);
    pane.innerHTML = html`
      <div class="row">
        <div><b>${escapeHtml(u.phone)}</b> <span class="tag sea">${escapeHtml(u.status)}</span></div>
        <div class="grid2">
          <div class="card" style="box-shadow:none">
            <div class="kicker">TIME LEFT (SECONDS)</div>
            <div style="font-size:28px;font-weight:900">${w.time_remaining_seconds}</div>
          </div>
          <div class="card" style="box-shadow:none">
            <div class="kicker">UNLIMITED</div>
            <div style="font-size:22px;font-weight:900">${w.is_unlimited ? "YES" : "NO"}</div>
          </div>
        </div>

        <form id="creditForm" class="grid2">
          <div class="field">
            <label>CREDIT SECONDS</label>
            <input id="creditSeconds" value="3600" />
          </div>
          <div style="display:flex;align-items:end">
            <button class="btn" type="submit">Credit</button>
          </div>
        </form>
        <div id="walletErr"></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button id="btnResetPw" class="btn ghost" type="button">Reset WiFi Password</button>
          <button id="btnSuspend" class="btn danger" type="button">Suspend User</button>
        </div>
      </div>
    `;

    $("#creditForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#walletErr").innerHTML = "";
      const amountSeconds = Number($("#creditSeconds").value);
      try {
        await apiFetch("/api/v1/admin/wallet/credit", {
          method: "POST",
          body: JSON.stringify({ user_id: u.id, source: "ADMIN", amount_seconds: amountSeconds }),
        });
        await loadWalletPane(u);
      } catch (e2) {
        $("#walletErr").innerHTML = errBox(e2.message);
      }
    });

    $("#btnResetPw").addEventListener("click", async () => {
      $("#walletErr").innerHTML = "";
      try {
        const res = await apiFetch(`/api/v1/admin/users/${u.id}/reset-password`, { method: "POST" });
        alert(`New WiFi credentials:\n${res.username}\n${res.new_password}`);
      } catch (e2) {
        $("#walletErr").innerHTML = errBox(e2.message);
      }
    });

    $("#btnSuspend").addEventListener("click", async () => {
      if (!confirm("Suspend this user? They will be rejected on re-auth.")) return;
      $("#walletErr").innerHTML = "";
      try {
        await apiFetch(`/api/v1/admin/users/${u.id}/status`, { method: "POST", body: JSON.stringify({ status: "SUSPENDED" }) });
        await viewUsers();
      } catch (e2) {
        $("#walletErr").innerHTML = errBox(e2.message);
      }
    });
  } catch (e) {
    pane.innerHTML = errBox(e.message);
  }
}

async function viewSessions() {
  title.textContent = "Sessions";
  setActiveNav("sessions");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/sessions");
    app.innerHTML = html`
      <table class="table">
        <thead><tr><th>USER</th><th>MAC</th><th>NAS</th><th>LAST UPDATE</th><th></th></tr></thead>
        <tbody>
          ${rows
            .map(
              (s) =>
                `<tr>
                  <td>${s.user_id}</td>
                  <td class="mono">${escapeHtml(s.calling_station_id)}</td>
                  <td>${s.nas_id ?? "-"}</td>
                  <td>${escapeHtml(String(s.last_update))}</td>
                  <td style="text-align:right">
                    <button class="btn danger" data-action="terminate" data-id="${s.id}" type="button">Terminate</button>
                  </td>
                </tr>`
            )
            .join("")}
        </tbody>
      </table>
      <div class="muted" style="margin-top:10px">
        Note: Terminate marks the session stopped in the central DB; immediate disconnect depends on NAS CoA/Disconnect support.
      </div>
    `;
    app.querySelectorAll("button[data-action='terminate']").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.id);
        if (!confirm(`Terminate session ${id}?`)) return;
        try {
          await apiFetch(`/api/v1/admin/sessions/${id}/terminate`, { method: "POST" });
          await viewSessions();
        } catch (e2) {
          alert(e2.message);
        }
      });
    });
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewTransactions() {
  title.textContent = "Transactions";
  setActiveNav("transactions");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/transactions?limit=200");
    app.innerHTML = html`
      <table class="table">
        <thead><tr><th>ID</th><th>USER</th><th>SOURCE</th><th>SECONDS</th><th>MONEY</th><th>REF</th><th>CREATED</th></tr></thead>
        <tbody>
          ${rows
            .map(
              (t) =>
                `<tr>
                  <td class="mono">${t.id}</td>
                  <td>${t.user_id}</td>
                  <td>${escapeHtml(t.source)}</td>
                  <td class="mono">${t.amount_seconds}</td>
                  <td class="mono">${t.amount_money}</td>
                  <td class="mono">${escapeHtml(t.ref || "")}</td>
                  <td>${escapeHtml(String(t.created_at))}</td>
                </tr>`
            )
            .join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewPlans() {
  title.textContent = "Plans & Pricing";
  setActiveNav("plans");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/plans");
    app.innerHTML = html`
      <div class="row">
        <form id="planForm" class="grid2">
          <div class="field">
            <label>TYPE</label>
            <select id="planType">
              <option value="TIME">TIME</option>
              <option value="DATE">DATE</option>
              <option value="UNLIMITED">UNLIMITED</option>
            </select>
          </div>
          <div class="field">
            <label>DURATION SECONDS (TIME ONLY)</label>
            <input id="planDuration" value="3600" />
          </div>
          <div class="field">
            <label>PRICE</label>
            <input id="planPrice" value="10" />
          </div>
          <div class="field">
            <label>METADATA (JSON)</label>
            <input id="planMeta" value="{}" />
          </div>
          <div style="display:flex;align-items:end">
            <button class="btn" type="submit">Create Plan</button>
          </div>
        </form>
        <div id="planErr"></div>
        <table class="table">
          <thead><tr><th>ID</th><th>TYPE</th><th>DURATION</th><th>PRICE</th><th>METADATA</th><th></th></tr></thead>
          <tbody>
            ${rows
              .map(
                (p) =>
                  `<tr>
                    <td class="mono">${p.id}</td>
                    <td>${escapeHtml(p.type)}</td>
                    <td class="mono">${p.duration_seconds ?? "-"}</td>
                    <td class="mono">${p.price}</td>
                    <td><pre class="mono" style="white-space:pre-wrap;margin:0">${escapeHtml(JSON.stringify(p.metadata || {}, null, 2))}</pre></td>
                    <td style="text-align:right"><button class="btn danger" data-action="del" data-id="${p.id}" type="button">Delete</button></td>
                  </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
    `;

    $("#planForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#planErr").innerHTML = "";
      const type = $("#planType").value;
      const durationSeconds = $("#planDuration").value.trim() ? Number($("#planDuration").value.trim()) : null;
      const price = Number($("#planPrice").value);
      let meta = {};
      try {
        meta = JSON.parse($("#planMeta").value || "{}");
      } catch {
        $("#planErr").innerHTML = errBox("Invalid metadata JSON");
        return;
      }
      try {
        await apiFetch("/api/v1/admin/plans", {
          method: "POST",
          body: JSON.stringify({ type, duration_seconds: durationSeconds, price, metadata: meta }),
        });
        await viewPlans();
      } catch (e2) {
        $("#planErr").innerHTML = errBox(e2.message);
      }
    });

    app.querySelectorAll("button[data-action='del']").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.id);
        if (!confirm(`Delete plan ${id}?`)) return;
        try {
          await apiFetch(`/api/v1/admin/plans/${id}`, { method: "DELETE" });
          await viewPlans();
        } catch (e2) {
          alert(e2.message);
        }
      });
    });
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewVendoEvents() {
  title.textContent = "Vendo Events";
  setActiveNav("vendo-events");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/device-events?limit=200");
    app.innerHTML = html`
      <table class="table">
        <thead><tr><th>ID</th><th>DEVICE</th><th>NONCE</th><th>TIMESTAMP</th><th>RAW</th><th>CREATED</th></tr></thead>
        <tbody>
          ${rows
            .map(
              (e) =>
                `<tr>
                  <td class="mono">${e.id}</td>
                  <td class="mono">${escapeHtml(e.device_id)}</td>
                  <td class="mono">${escapeHtml(e.nonce)}</td>
                  <td>${escapeHtml(String(e.timestamp))}</td>
                  <td><pre class="mono" style="white-space:pre-wrap;margin:0">${escapeHtml(e.raw)}</pre></td>
                  <td>${escapeHtml(String(e.created_at))}</td>
                </tr>`
            )
            .join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewAuditLogs() {
  title.textContent = "Audit Logs";
  setActiveNav("audit-logs");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/audit-logs");
    app.innerHTML = html`
      <table class="table">
        <thead><tr><th>WHEN</th><th>ACTOR</th><th>ACTION</th><th>OBJECT</th><th>DETAILS</th></tr></thead>
        <tbody>
          ${rows
            .map(
              (a) =>
                `<tr>
                  <td>${escapeHtml(String(a.created_at))}</td>
                  <td class="mono">${escapeHtml(a.actor)}</td>
                  <td>${escapeHtml(a.action)}</td>
                  <td class="mono">${escapeHtml(a.object_type)}:${escapeHtml(a.object_id)}</td>
                  <td><pre class="mono" style="white-space:pre-wrap;margin:0">${escapeHtml(a.details)}</pre></td>
                </tr>`
            )
            .join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewNAS() {
  title.textContent = "NAS (RADIUS Clients)";
  setActiveNav("nas");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/nas");
    app.innerHTML = html`
      <div class="row">
        <form id="nasForm" class="grid2">
          <div class="field">
            <label>NAME</label><input id="nasName" value="omada-1" />
          </div>
          <div class="field">
            <label>IP</label><input id="nasIp" value="192.168.1.2" />
          </div>
          <div class="field">
            <label>SHARED SECRET</label><input id="nasSecret" value="" />
          </div>
          <div style="display:flex;align-items:end">
            <button class="btn" type="submit">Add NAS</button>
          </div>
        </form>
        <div id="nasErr"></div>
        <table class="table">
          <thead><tr><th>NAME</th><th>IP</th><th>SECRET</th></tr></thead>
          <tbody>
            ${rows.map((n) => `<tr><td>${escapeHtml(n.name)}</td><td class="mono">${escapeHtml(n.ip)}</td><td class="mono">${escapeHtml(n.secret)}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    `;
    $("#nasForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#nasErr").innerHTML = "";
      try {
        await apiFetch("/api/v1/admin/nas", {
          method: "POST",
          body: JSON.stringify({ name: $("#nasName").value.trim(), ip: $("#nasIp").value.trim(), secret: $("#nasSecret").value }),
        });
        await viewNAS();
      } catch (e2) {
        $("#nasErr").innerHTML = errBox(e2.message);
      }
    });
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewDevices() {
  title.textContent = "Vendo Devices";
  setActiveNav("devices");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/devices");
    app.innerHTML = html`
      <div class="row">
        <form id="devForm" class="grid2">
          <div class="field">
            <label>DEVICE ID</label><input id="devId" value="vendo-001" />
          </div>
          <div class="field">
            <label>WALLET USER ID (OPTIONAL)</label><input id="devUser" value="" />
          </div>
          <div style="display:flex;align-items:end">
            <button class="btn" type="submit">Add Device</button>
          </div>
        </form>
        <div id="devErr"></div>
        <table class="table">
          <thead><tr><th>DEVICE</th><th>STATUS</th><th>WALLET USER</th><th>CREATED</th></tr></thead>
          <tbody>
            ${rows.map((d) => `<tr><td class="mono">${escapeHtml(d.device_id)}</td><td>${escapeHtml(d.status)}</td><td>${d.wallet_user_id ?? "-"}</td><td>${escapeHtml(String(d.created_at))}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    `;
    $("#devForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#devErr").innerHTML = "";
      try {
        const res = await apiFetch("/api/v1/admin/devices", {
          method: "POST",
          body: JSON.stringify({
            device_id: $("#devId").value.trim(),
            wallet_user_id: $("#devUser").value.trim() ? Number($("#devUser").value.trim()) : null,
          }),
        });
        alert(`Device token (save in firmware):\n${res.device_token}`);
        await viewDevices();
      } catch (e2) {
        $("#devErr").innerHTML = errBox(e2.message);
      }
    });
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewPayments() {
  title.textContent = "Payment Logs";
  setActiveNav("payments");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const rows = await apiFetch("/api/v1/admin/webhooks");
    const pay = rows.filter((w) => w.kind === "PAYMENT");
    app.innerHTML = html`
      <table class="table">
        <thead><tr><th>IDEMPOTENCY</th><th>CREATED</th><th>PAYLOAD</th></tr></thead>
        <tbody>
          ${pay.map((w) => `<tr><td class="mono">${escapeHtml(w.idempotency_key)}</td><td>${escapeHtml(String(w.created_at))}</td><td><pre class="mono" style="white-space:pre-wrap;margin:0">${escapeHtml(w.payload)}</pre></td></tr>`).join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function viewSMS() {
  title.textContent = "SMS Tool";
  setActiveNav("sms");
  app.innerHTML = "<div class='muted'>Loading...</div>";
  try {
    const logs = await apiFetch("/api/v1/sms/logs");
    app.innerHTML = html`
      <div class="row">
        <form id="smsForm" class="grid2">
          <div class="field">
            <label>TO (E.164)</label><input id="smsTo" value="+15551234567" />
          </div>
          <div class="field">
            <label>MESSAGE</label><input id="smsMsg" value="Test message from Central WiFi" />
          </div>
          <div style="display:flex;align-items:end">
            <button class="btn" type="submit">Send</button>
          </div>
        </form>
        <div id="smsErr"></div>
        <table class="table">
          <thead><tr><th>TO</th><th>MESSAGE</th><th>CREATED</th></tr></thead>
          <tbody>
            ${logs.map((l) => `<tr><td class="mono">${escapeHtml(l.to_phone)}</td><td>${escapeHtml(l.message)}</td><td>${escapeHtml(String(l.created_at))}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    `;
    $("#smsForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#smsErr").innerHTML = "";
      try {
        await apiFetch("/api/v1/sms/test", { method: "POST", body: JSON.stringify({ to_phone: $("#smsTo").value.trim(), message: $("#smsMsg").value }) });
        await viewSMS();
      } catch (e2) {
        $("#smsErr").innerHTML = errBox(e2.message);
      }
    });
  } catch (e) {
    app.innerHTML = errBox(e.message);
  }
}

async function render() {
  $("#btnSignOut").onclick = () => {
    tokenClear();
    window.location.hash = "#/login";
  };

  const r = route();
  const isLoggedIn = !!tokenGet();
  if (!isLoggedIn && r !== "login") {
    window.location.hash = "#/login";
    return;
  }

  if (r === "login") return viewLogin();
  if (r === "dashboard") return viewDashboard();
  if (r === "users") return viewUsers();
  if (r === "transactions") return viewTransactions();
  if (r === "plans") return viewPlans();
  if (r === "sessions") return viewSessions();
  if (r === "nas") return viewNAS();
  if (r === "devices") return viewDevices();
  if (r === "vendo-events") return viewVendoEvents();
  if (r === "payments") return viewPayments();
  if (r === "sms") return viewSMS();
  if (r === "audit-logs") return viewAuditLogs();

  window.location.hash = "#/dashboard";
}

window.addEventListener("hashchange", render);
render();
