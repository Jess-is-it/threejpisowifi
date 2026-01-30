/* Central WiFi Admin (Flowbite-styled, zero-runtime-deps SPA). */

const root = document.getElementById("appRoot");

const $ = (sel, el = document) => el.querySelector(sel);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
}

function tokenGet() {
  return window.localStorage.getItem("cw_admin_token");
}
function tokenSet(t) {
  window.localStorage.setItem("cw_admin_token", t);
}
function tokenClear() {
  window.localStorage.removeItem("cw_admin_token");
}

function routeGet() {
  const h = window.location.hash || "";
  const m = h.match(/^#\/([a-z-]+)/);
  const r = m ? m[1] : "";
  if (r) return r;
  // Default landing page is always the login screen.
  return "login";
}
function routeGo(r) {
  window.location.hash = `#/${r}`;
}

function errBox(msg) {
  return `
    <div class="p-3 rounded-lg border border-red-200 bg-red-50 text-red-800 text-sm">
      ${escapeHtml(msg)}
    </div>
  `;
}

async function apiFetch(path, init) {
  const headers = new Headers((init && init.headers) || {});
  headers.set("Content-Type", "application/json");
  const t = tokenGet();
  if (t) headers.set("Authorization", `Bearer ${t}`);
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      tokenClear();
      if (routeGet() !== "login") routeGo("login");
    }
    let body = {};
    try {
      body = await res.json();
    } catch {}
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return await res.json();
}

function layoutLogin(inner) {
  return `
    <div class="min-h-screen flex items-center justify-center px-4">
      <div class="w-full max-w-md">
        <div class="mb-6 text-center">
          <div class="text-xs tracking-widest font-semibold text-slate-500">CENTRAL WIFI</div>
          <div class="text-2xl font-bold text-slate-900">Admin</div>
          <div class="mt-2 text-sm text-slate-600">Sign in to manage RADIUS + Wallet.</div>
        </div>
        <div class="bg-white border border-slate-200 shadow-sm rounded-xl p-6">
          ${inner}
        </div>
        <div class="mt-4 text-center text-xs text-slate-500">
          RADIUS is authoritative. Wallet is SQL truth.
        </div>
      </div>
    </div>
  `;
}

function layoutApp(active, inner) {
  const link = (id, label) => `
    <a href="#/${id}" data-route="${id}"
       class="flex items-center px-3 py-2 rounded-lg text-sm font-medium ${
         active === id ? "bg-slate-100 text-slate-900" : "text-slate-700 hover:bg-slate-50"
       }">
      ${escapeHtml(label)}
    </a>
  `;

  return `
    <div class="min-h-screen bg-slate-50">
      <header class="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur">
        <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-slate-900 text-white flex items-center justify-center font-black">CW</div>
            <div>
              <div class="text-sm tracking-widest font-semibold text-slate-500">CENTRAL WIFI</div>
              <div class="text-lg font-bold text-slate-900">Admin</div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-1 rounded-full">RADIUS + Wallet</span>
            <button id="btnSignOut" class="text-sm font-semibold px-3 py-2 rounded-lg border border-slate-200 hover:bg-slate-50">Sign out</button>
          </div>
        </div>
      </header>

      <div class="max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-6">
        <aside class="bg-white border border-slate-200 rounded-xl p-3 h-fit">
          <div class="text-xs font-semibold text-slate-500 tracking-widest px-2 py-2">NAVIGATION</div>
          <nav class="grid gap-1">
            ${link("dashboard", "Dashboard")}
            ${link("users", "Users & Wallet")}
            ${link("transactions", "Transactions")}
            ${link("plans", "Plans & Pricing")}
            ${link("sessions", "Sessions")}
            ${link("nas", "NAS (RADIUS Clients)")}
            ${link("devices", "Vendo Devices")}
            ${link("vendo-events", "Vendo Events")}
            ${link("payments", "Payment Logs")}
            ${link("sms", "SMS Tool")}
            ${link("audit-logs", "Audit Logs")}
          </nav>
        </aside>

        <main class="bg-white border border-slate-200 rounded-xl p-5">
          ${inner}
        </main>
      </div>
    </div>
  `;
}

function pageTitle(t) {
  return `<div class="mb-4">
    <div class="text-xs tracking-widest font-semibold text-slate-500">CENTRAL WIFI</div>
    <div class="text-2xl font-bold text-slate-900">${escapeHtml(t)}</div>
  </div>`;
}

function input(id, label, type = "text", value = "", placeholder = "") {
  return `
    <div>
      <label for="${id}" class="block mb-2 text-sm font-medium text-slate-900">${escapeHtml(label)}</label>
      <input id="${id}" type="${type}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}"
        class="bg-slate-50 border border-slate-300 text-slate-900 text-sm rounded-lg focus:ring-emerald-500 focus:border-emerald-500 block w-full p-2.5" />
    </div>
  `;
}

function btn(label, extra = "") {
  return `<button class="text-white bg-slate-900 hover:bg-black focus:ring-4 focus:outline-none focus:ring-slate-300 font-semibold rounded-lg text-sm px-4 py-2.5 ${extra}">${escapeHtml(label)}</button>`;
}
function btnGhost(label, extra = "") {
  return `<button class="text-slate-800 bg-white hover:bg-slate-50 border border-slate-200 focus:ring-4 focus:outline-none focus:ring-slate-100 font-semibold rounded-lg text-sm px-4 py-2.5 ${extra}">${escapeHtml(label)}</button>`;
}
function btnDanger(label, extra = "") {
  return `<button class="text-white bg-red-600 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-200 font-semibold rounded-lg text-sm px-4 py-2.5 ${extra}">${escapeHtml(label)}</button>`;
}

function table(headers, rowsHtml) {
  return `
    <div class="relative overflow-x-auto border border-slate-200 rounded-lg">
      <table class="w-full text-sm text-left text-slate-700">
        <thead class="text-xs text-slate-600 uppercase bg-slate-50">
          <tr>${headers.map((h) => `<th class="px-4 py-3">${escapeHtml(h)}</th>`).join("")}</tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>
  `;
}

async function viewLogin() {
  const already = !!tokenGet();
  root.innerHTML = layoutLogin(`
    ${already ? `
      <div class="mb-4 p-3 rounded-lg border border-slate-200 bg-slate-50 text-slate-700 text-sm">
        You are already signed in on this browser. You can continue to the dashboard or sign in again.
        <div class="mt-3 flex gap-2">
          <button id="btnContinue" class="text-white bg-slate-900 hover:bg-black font-semibold rounded-lg text-sm px-4 py-2.5">Continue</button>
          <button id="btnClear" class="text-slate-800 bg-white hover:bg-slate-50 border border-slate-200 font-semibold rounded-lg text-sm px-4 py-2.5">Sign out</button>
        </div>
      </div>
    ` : ``}
    <form id="loginForm" class="space-y-4">
      ${input("loginUser", "Username", "text", "admin")}
      ${input("loginPass", "Password", "password", "")}
      <div id="loginErr"></div>
      <div class="flex items-center justify-between gap-3">
        ${btn("Sign in", "w-full")}
      </div>
      <div class="text-xs text-slate-500">
        Use the credentials printed by <span class="font-mono">deploy/install.sh</span>.
      </div>
    </form>
  `);

  const c = $("#btnContinue");
  if (c) c.onclick = () => routeGo("dashboard");
  const clr = $("#btnClear");
  if (clr) clr.onclick = () => {
    tokenClear();
    // Reload the login view to remove the "already signed in" banner.
    viewLogin();
  };

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
      routeGo("dashboard");
    } catch (e2) {
      $("#loginErr").innerHTML = errBox(e2.message);
    }
  });
}

async function viewDashboard() {
  root.innerHTML = layoutApp("dashboard", `${pageTitle("Dashboard")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const [users, sessions] = await Promise.all([apiFetch("/api/v1/admin/users"), apiFetch("/api/v1/admin/sessions")]);
    root.innerHTML = layoutApp(
      "dashboard",
      `
        ${pageTitle("Dashboard")}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="p-4 rounded-xl border border-slate-200 bg-white">
            <div class="text-xs tracking-widest font-semibold text-slate-500">USERS</div>
            <div class="mt-2 text-4xl font-extrabold text-slate-900">${users.length}</div>
          </div>
          <div class="p-4 rounded-xl border border-slate-200 bg-white">
            <div class="text-xs tracking-widest font-semibold text-slate-500">ACTIVE SESSIONS</div>
            <div class="mt-2 text-4xl font-extrabold text-slate-900">${sessions.length}</div>
          </div>
        </div>
        <div class="mt-4 text-sm text-slate-600">
          Tip: for lab testing, use <span class="font-mono">radclient</span> examples in <span class="font-mono">docs/RADIUS_TESTING.md</span>.
        </div>
      `
    );
  } catch (e) {
    root.innerHTML = layoutApp("dashboard", `${pageTitle("Dashboard")}${errBox(e.message)}`);
  }
}

async function viewUsers() {
  root.innerHTML = layoutApp("users", `${pageTitle("Users & Wallet")}<div class="text-slate-600 text-sm">Loading…</div>`);
  let users = [];
  try {
    users = await apiFetch("/api/v1/admin/users");
  } catch (e) {
    root.innerHTML = layoutApp("users", `${pageTitle("Users & Wallet")}${errBox(e.message)}`);
    return;
  }

  const rows = users
    .map(
      (u) => `
      <tr class="border-t border-slate-100 hover:bg-slate-50 cursor-pointer" data-id="${u.id}">
        <td class="px-4 py-3 font-semibold text-slate-900">${escapeHtml(u.phone)}</td>
        <td class="px-4 py-3">${escapeHtml(u.status)}</td>
      </tr>
    `
    )
    .join("");

  root.innerHTML = layoutApp(
    "users",
    `
      ${pageTitle("Users & Wallet")}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="space-y-4">
          <div class="p-4 rounded-xl border border-slate-200">
            <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">CREATE USER</div>
            <form id="createUserForm" class="space-y-3">
              ${input("newPhone", "Phone (E.164)", "text", "+15551234567")}
              <div id="createUserErr"></div>
              ${btn("Create", "w-full")}
            </form>
          </div>

          <div>
            <div class="text-xs tracking-widest font-semibold text-slate-500 mb-2">USERS</div>
            ${table(["Phone", "Status"], rows || `<tr><td class="px-4 py-3" colspan="2">No users</td></tr>`)}
          </div>
        </div>

        <div>
          <div class="text-xs tracking-widest font-semibold text-slate-500 mb-2">WALLET</div>
          <div id="walletPane" class="p-4 rounded-xl border border-slate-200 text-sm text-slate-600">
            Select a user to view and credit their wallet.
          </div>
        </div>
      </div>
    `
  );

  $("#createUserForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#createUserErr").innerHTML = "";
    const phone = $("#newPhone").value.trim();
    try {
      await apiFetch("/api/v1/admin/users", { method: "POST", body: JSON.stringify({ phone }) });
      await viewUsers();
    } catch (e2) {
      $("#createUserErr").innerHTML = errBox(e2.message);
    }
  });

  const tbl = root.querySelector("tbody");
  tbl.addEventListener("click", async (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    const id = Number(tr.dataset.id);
    const u = users.find((x) => x.id === id);
    await loadWalletPane(u);
  });
}

async function loadWalletPane(u) {
  const pane = $("#walletPane");
  pane.innerHTML = `<div class="text-slate-600 text-sm">Loading…</div>`;
  try {
    const w = await apiFetch(`/api/v1/admin/users/${u.id}/wallet`);
    pane.innerHTML = `
      <div class="space-y-4">
        <div class="flex items-center justify-between gap-2">
          <div>
            <div class="font-bold text-slate-900">${escapeHtml(u.phone)}</div>
            <div class="text-xs text-slate-500">${escapeHtml(u.status)}</div>
          </div>
          <div class="text-xs font-semibold px-2 py-1 rounded-full border border-slate-200 bg-slate-50">user_id: ${u.id}</div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div class="p-3 rounded-lg border border-slate-200 bg-white">
            <div class="text-xs tracking-widest font-semibold text-slate-500">TIME LEFT (SECONDS)</div>
            <div class="mt-1 text-2xl font-extrabold text-slate-900">${w.time_remaining_seconds}</div>
          </div>
          <div class="p-3 rounded-lg border border-slate-200 bg-white">
            <div class="text-xs tracking-widest font-semibold text-slate-500">VALID UNTIL</div>
            <div class="mt-1 font-mono text-xs text-slate-800 break-all">${escapeHtml(String(w.valid_until_ts ?? "-"))}</div>
          </div>
          <div class="p-3 rounded-lg border border-slate-200 bg-white">
            <div class="text-xs tracking-widest font-semibold text-slate-500">UNLIMITED</div>
            <div class="mt-1 text-xl font-extrabold text-slate-900">${w.is_unlimited ? "YES" : "NO"}</div>
          </div>
        </div>

        <form id="creditForm" class="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3">
          ${input("creditSeconds", "Credit Seconds", "number", "3600")}
          ${btn("Credit", "self-end")}
        </form>

        <form id="extendForm" class="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3">
          ${input("extendSeconds", "Extend Valid Until (seconds)", "number", "86400")}
          ${btn("Extend", "self-end")}
        </form>

        <div id="walletErr"></div>

        <div class="flex flex-wrap gap-2">
          <button id="btnResetPw" class="text-slate-800 bg-white hover:bg-slate-50 border border-slate-200 font-semibold rounded-lg text-sm px-4 py-2.5">Reset WiFi Password</button>
          <button id="btnUnlimited" class="text-slate-800 bg-white hover:bg-slate-50 border border-slate-200 font-semibold rounded-lg text-sm px-4 py-2.5">Set Unlimited</button>
          <button id="btnSuspend" class="text-white bg-red-600 hover:bg-red-700 font-semibold rounded-lg text-sm px-4 py-2.5">Suspend User</button>
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

    $("#extendForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#walletErr").innerHTML = "";
      const extendSeconds = Number($("#extendSeconds").value);
      try {
        await apiFetch("/api/v1/admin/wallet/credit", {
          method: "POST",
          body: JSON.stringify({ user_id: u.id, source: "ADMIN", extend_valid_until_seconds: extendSeconds }),
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
        alert(`New WiFi credentials:\\n${res.username}\\n${res.new_password}`);
      } catch (e2) {
        $("#walletErr").innerHTML = errBox(e2.message);
      }
    });

    $("#btnUnlimited").addEventListener("click", async () => {
      if (!confirm("Set this wallet to UNLIMITED?")) return;
      $("#walletErr").innerHTML = "";
      try {
        await apiFetch("/api/v1/admin/wallet/credit", {
          method: "POST",
          body: JSON.stringify({ user_id: u.id, source: "ADMIN", set_unlimited: true }),
        });
        await loadWalletPane(u);
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

async function viewTransactions() {
  root.innerHTML = layoutApp("transactions", `${pageTitle("Transactions")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/transactions?limit=200");
    const tbody = rows
      .map(
        (t) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3 font-mono text-xs">${t.id}</td>
          <td class="px-4 py-3">${t.user_id}</td>
          <td class="px-4 py-3">${escapeHtml(t.source)}</td>
          <td class="px-4 py-3 font-mono text-xs">${t.amount_seconds}</td>
          <td class="px-4 py-3 font-mono text-xs">${t.amount_money}</td>
          <td class="px-4 py-3 font-mono text-xs break-all">${escapeHtml(t.ref || "")}</td>
          <td class="px-4 py-3">${escapeHtml(String(t.created_at))}</td>
        </tr>
      `
      )
      .join("");
    root.innerHTML = layoutApp("transactions", `${pageTitle("Transactions")}${table(["ID", "User", "Source", "Seconds", "Money", "Ref", "Created"], tbody)}`);
  } catch (e) {
    root.innerHTML = layoutApp("transactions", `${pageTitle("Transactions")}${errBox(e.message)}`);
  }
}

async function viewPlans() {
  root.innerHTML = layoutApp("plans", `${pageTitle("Plans & Pricing")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/plans");
    const tbody = rows
      .map(
        (p) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3 font-mono text-xs">${p.id}</td>
          <td class="px-4 py-3">${escapeHtml(p.type)}</td>
          <td class="px-4 py-3 font-mono text-xs">${p.duration_seconds ?? "-"}</td>
          <td class="px-4 py-3 font-mono text-xs">${p.price}</td>
          <td class="px-4 py-3 font-mono text-xs"><pre class="whitespace-pre-wrap m-0">${escapeHtml(JSON.stringify(p.metadata || {}, null, 2))}</pre></td>
          <td class="px-4 py-3 text-right"><button class="btnPlanDel text-white bg-red-600 hover:bg-red-700 font-semibold rounded-lg text-xs px-3 py-2" data-id="${p.id}">Delete</button></td>
        </tr>
      `
      )
      .join("");

    root.innerHTML = layoutApp(
      "plans",
      `
        ${pageTitle("Plans & Pricing")}
        <div class="p-4 rounded-xl border border-slate-200 mb-4">
          <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">CREATE PLAN</div>
          <form id="planForm" class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label class="block mb-2 text-sm font-medium text-slate-900">Type</label>
              <select id="planType" class="bg-slate-50 border border-slate-300 text-slate-900 text-sm rounded-lg focus:ring-emerald-500 focus:border-emerald-500 block w-full p-2.5">
                <option value="TIME">TIME</option>
                <option value="DATE">DATE</option>
                <option value="UNLIMITED">UNLIMITED</option>
              </select>
            </div>
            ${input("planDuration", "Duration seconds (TIME only)", "number", "3600")}
            ${input("planPrice", "Price", "number", "10")}
            ${input("planMeta", "Metadata (JSON)", "text", "{}")}
            <div id="planErr" class="md:col-span-2"></div>
            <div class="md:col-span-2">${btn("Create plan")}</div>
          </form>
        </div>
        ${table(["ID", "Type", "Duration", "Price", "Metadata", ""], tbody || `<tr><td class="px-4 py-3" colspan="6">No plans</td></tr>`)}
      `
    );

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

    root.querySelectorAll(".btnPlanDel").forEach((b) => {
      b.addEventListener("click", async () => {
        const id = Number(b.dataset.id);
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
    root.innerHTML = layoutApp("plans", `${pageTitle("Plans & Pricing")}${errBox(e.message)}`);
  }
}

async function viewSessions() {
  root.innerHTML = layoutApp("sessions", `${pageTitle("Sessions")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/sessions");
    const tbody = rows
      .map(
        (s) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3">${s.user_id}</td>
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(s.calling_station_id)}</td>
          <td class="px-4 py-3">${s.nas_id ?? "-"}</td>
          <td class="px-4 py-3">${escapeHtml(String(s.last_update))}</td>
          <td class="px-4 py-3 text-right">
            <button class="btnSessTerm text-white bg-red-600 hover:bg-red-700 font-semibold rounded-lg text-xs px-3 py-2" data-id="${s.id}">Terminate</button>
          </td>
        </tr>
      `
      )
      .join("");
    root.innerHTML = layoutApp("sessions", `${pageTitle("Sessions")}${table(["User", "MAC", "NAS", "Last update", ""], tbody)}`);
    root.querySelectorAll(".btnSessTerm").forEach((b) => {
      b.addEventListener("click", async () => {
        const id = Number(b.dataset.id);
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
    root.innerHTML = layoutApp("sessions", `${pageTitle("Sessions")}${errBox(e.message)}`);
  }
}

async function viewNAS() {
  root.innerHTML = layoutApp("nas", `${pageTitle("NAS (RADIUS Clients)")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/nas");
    const tbody = rows
      .map(
        (n) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3">${escapeHtml(n.name)}</td>
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(n.ip)}</td>
          <td class="px-4 py-3 font-mono text-xs break-all">${escapeHtml(n.secret)}</td>
        </tr>
      `
      )
      .join("");

    root.innerHTML = layoutApp(
      "nas",
      `
        ${pageTitle("NAS (RADIUS Clients)")}
        <div class="p-4 rounded-xl border border-slate-200 mb-4">
          <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">ADD NAS</div>
          <form id="nasForm" class="grid grid-cols-1 md:grid-cols-2 gap-3">
            ${input("nasName", "Name", "text", "omada-1")}
            ${input("nasIp", "IP", "text", "192.168.1.2")}
            ${input("nasSecret", "Shared secret", "text", "")}
            <div id="nasErr" class="md:col-span-2"></div>
            <div class="md:col-span-2">${btn("Add NAS")}</div>
          </form>
        </div>
        ${table(["Name", "IP", "Secret"], tbody || `<tr><td class="px-4 py-3" colspan="3">No NAS</td></tr>`)}
      `
    );

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
    root.innerHTML = layoutApp("nas", `${pageTitle("NAS (RADIUS Clients)")}${errBox(e.message)}`);
  }
}

async function viewDevices() {
  root.innerHTML = layoutApp("devices", `${pageTitle("Vendo Devices")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/devices");
    const tbody = rows
      .map(
        (d) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(d.device_id)}</td>
          <td class="px-4 py-3">${escapeHtml(d.status)}</td>
          <td class="px-4 py-3">${d.wallet_user_id ?? "-"}</td>
          <td class="px-4 py-3">${escapeHtml(String(d.created_at))}</td>
        </tr>
      `
      )
      .join("");

    root.innerHTML = layoutApp(
      "devices",
      `
        ${pageTitle("Vendo Devices")}
        <div class="p-4 rounded-xl border border-slate-200 mb-4">
          <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">ADD DEVICE</div>
          <form id="devForm" class="grid grid-cols-1 md:grid-cols-2 gap-3">
            ${input("devId", "Device ID", "text", "vendo-001")}
            ${input("devUser", "Wallet user id (optional)", "text", "")}
            <div id="devErr" class="md:col-span-2"></div>
            <div class="md:col-span-2">${btn("Add device")}</div>
          </form>
        </div>
        ${table(["Device", "Status", "Wallet user", "Created"], tbody || `<tr><td class="px-4 py-3" colspan="4">No devices</td></tr>`)}
      `
    );

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
        alert(`Device token (save in firmware):\\n${res.device_token}`);
        await viewDevices();
      } catch (e2) {
        $("#devErr").innerHTML = errBox(e2.message);
      }
    });
  } catch (e) {
    root.innerHTML = layoutApp("devices", `${pageTitle("Vendo Devices")}${errBox(e.message)}`);
  }
}

async function viewVendoEvents() {
  root.innerHTML = layoutApp("vendo-events", `${pageTitle("Vendo Events")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/device-events?limit=200");
    const tbody = rows
      .map(
        (e) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3 font-mono text-xs">${e.id}</td>
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(e.device_id)}</td>
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(e.nonce)}</td>
          <td class="px-4 py-3">${escapeHtml(String(e.timestamp))}</td>
          <td class="px-4 py-3 font-mono text-xs"><pre class="whitespace-pre-wrap m-0">${escapeHtml(e.raw)}</pre></td>
        </tr>
      `
      )
      .join("");
    root.innerHTML = layoutApp("vendo-events", `${pageTitle("Vendo Events")}${table(["ID", "Device", "Nonce", "Timestamp", "Raw"], tbody)}`);
  } catch (e) {
    root.innerHTML = layoutApp("vendo-events", `${pageTitle("Vendo Events")}${errBox(e.message)}`);
  }
}

async function viewPayments() {
  root.innerHTML = layoutApp("payments", `${pageTitle("Payment Logs")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/webhooks");
    const pay = rows.filter((w) => w.kind === "PAYMENT");
    const tbody = pay
      .map(
        (w) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3 font-mono text-xs break-all">${escapeHtml(w.idempotency_key)}</td>
          <td class="px-4 py-3">${escapeHtml(String(w.created_at))}</td>
          <td class="px-4 py-3 font-mono text-xs"><pre class="whitespace-pre-wrap m-0">${escapeHtml(w.payload)}</pre></td>
        </tr>
      `
      )
      .join("");
    root.innerHTML = layoutApp("payments", `${pageTitle("Payment Logs")}${table(["Idempotency", "Created", "Payload"], tbody || `<tr><td class="px-4 py-3" colspan="3">No payment webhooks</td></tr>`)} `);
  } catch (e) {
    root.innerHTML = layoutApp("payments", `${pageTitle("Payment Logs")}${errBox(e.message)}`);
  }
}

async function viewSMS() {
  root.innerHTML = layoutApp("sms", `${pageTitle("SMS Tool")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const logs = await apiFetch("/api/v1/sms/logs");
    const tbody = logs
      .map(
        (l) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(l.to_phone)}</td>
          <td class="px-4 py-3">${escapeHtml(l.message)}</td>
          <td class="px-4 py-3">${escapeHtml(String(l.created_at))}</td>
        </tr>
      `
      )
      .join("");

    root.innerHTML = layoutApp(
      "sms",
      `
        ${pageTitle("SMS Tool")}
        <div class="p-4 rounded-xl border border-slate-200 mb-4">
          <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">SEND TEST SMS (MOCK)</div>
          <form id="smsForm" class="grid grid-cols-1 md:grid-cols-2 gap-3">
            ${input("smsTo", "To (E.164)", "text", "+15551234567")}
            ${input("smsMsg", "Message", "text", "Test message from Central WiFi")}
            <div id="smsErr" class="md:col-span-2"></div>
            <div class="md:col-span-2">${btn("Send")}</div>
          </form>
        </div>
        ${table(["To", "Message", "Created"], tbody || `<tr><td class="px-4 py-3" colspan="3">No logs</td></tr>`)}
      `
    );

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
    root.innerHTML = layoutApp("sms", `${pageTitle("SMS Tool")}${errBox(e.message)}`);
  }
}

async function viewAuditLogs() {
  root.innerHTML = layoutApp("audit-logs", `${pageTitle("Audit Logs")}<div class="text-slate-600 text-sm">Loading…</div>`);
  try {
    const rows = await apiFetch("/api/v1/admin/audit-logs");
    const tbody = rows
      .map(
        (a) => `
        <tr class="border-t border-slate-100">
          <td class="px-4 py-3">${escapeHtml(String(a.created_at))}</td>
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(a.actor)}</td>
          <td class="px-4 py-3">${escapeHtml(a.action)}</td>
          <td class="px-4 py-3 font-mono text-xs">${escapeHtml(a.object_type)}:${escapeHtml(a.object_id)}</td>
          <td class="px-4 py-3 font-mono text-xs"><pre class="whitespace-pre-wrap m-0">${escapeHtml(a.details)}</pre></td>
        </tr>
      `
      )
      .join("");
    root.innerHTML = layoutApp("audit-logs", `${pageTitle("Audit Logs")}${table(["When", "Actor", "Action", "Object", "Details"], tbody)}`);
  } catch (e) {
    root.innerHTML = layoutApp("audit-logs", `${pageTitle("Audit Logs")}${errBox(e.message)}`);
  }
}

async function render() {
  const r = routeGet();
  const authed = !!tokenGet();

  if (!authed && r !== "login") {
    routeGo("login");
    return;
  }

  // Wire sign-out after each render (button only exists in authed layout).
  const signOut = () => {
    tokenClear();
    routeGo("login");
  };

  if (r === "login") return viewLogin();
  if (r === "dashboard") {
    await viewDashboard();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "users") {
    await viewUsers();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "transactions") {
    await viewTransactions();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "plans") {
    await viewPlans();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "sessions") {
    await viewSessions();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "nas") {
    await viewNAS();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "devices") {
    await viewDevices();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "vendo-events") {
    await viewVendoEvents();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "payments") {
    await viewPayments();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "sms") {
    await viewSMS();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }
  if (r === "audit-logs") {
    await viewAuditLogs();
    const b = $("#btnSignOut");
    if (b) b.onclick = signOut;
    return;
  }

  routeGo(authed ? "dashboard" : "login");
}

window.addEventListener("hashchange", () => void render());
window.addEventListener("error", (ev) => {
  // Show errors even if rendering fails.
  try {
    root.innerHTML = layoutLogin(errBox(ev?.error?.message || ev?.message || "Unknown error"));
  } catch {}
});
window.addEventListener("unhandledrejection", (ev) => {
  try {
    root.innerHTML = layoutLogin(errBox(ev?.reason?.message || String(ev?.reason || "Unhandled rejection")));
  } catch {}
});

render();
