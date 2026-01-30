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
            ${link("setup", "Setup Wizard")}
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
      // First-time admins should land in the setup wizard; returning admins can go straight to dashboard.
      try {
        const setup = await apiFetch("/api/v1/admin/system/setup");
        routeGo(setup && setup.completed ? "dashboard" : "setup");
      } catch {
        routeGo("setup");
      }
    } catch (e2) {
      $("#loginErr").innerHTML = errBox(e2.message);
    }
  });
}

function pill(text) {
  return `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold border border-slate-200 bg-slate-50 text-slate-700">${escapeHtml(text)}</span>`;
}

function callout(kind, title, bodyHtml) {
  const styles =
    kind === "danger"
      ? "border-red-200 bg-red-50 text-red-900"
      : kind === "warn"
        ? "border-amber-200 bg-amber-50 text-amber-900"
        : kind === "ok"
          ? "border-emerald-200 bg-emerald-50 text-emerald-900"
          : "border-slate-200 bg-slate-50 text-slate-900";
  return `
    <div class="p-4 rounded-xl border ${styles}">
      <div class="font-bold">${escapeHtml(title)}</div>
      <div class="mt-2 text-sm leading-6">${bodyHtml}</div>
    </div>
  `;
}

function codeBlock(text) {
  return `<pre class="mt-2 p-3 rounded-lg bg-slate-900 text-slate-100 text-xs overflow-x-auto"><code>${escapeHtml(text)}</code></pre>`;
}

async function viewSetupWizard() {
  root.innerHTML = layoutApp("setup", `${pageTitle("Setup Wizard")}<div class="text-slate-600 text-sm">Loading…</div>`);

  let info = null;
  let setup = { completed: false, completed_at: null, state: {} };
  try {
    [info, setup] = await Promise.all([apiFetch("/api/v1/admin/system/info"), apiFetch("/api/v1/admin/system/setup")]);
  } catch (e) {
    root.innerHTML = layoutApp("setup", `${pageTitle("Setup Wizard")}${errBox(e.message)}`);
    const b = $("#btnSignOut");
    if (b) b.onclick = () => {
      tokenClear();
      routeGo("login");
    };
    return;
  }

  const state = setup.state || {};
  const current = Number(state.current_step ?? 0);
  const done = state.done || {};
  const serverHost = String(info.cw_public_base_url || "")
    .replace("https://", "")
    .replace("http://", "")
    .split("/")[0];

  const steps = [
    {
      id: "welcome",
      title: "Welcome & How It Works",
      priority: "REQUIRED",
      body: () =>
        `
          ${callout(
            "info",
            "Architecture in 60 seconds",
            `
              <ul class="list-disc pl-5">
                <li><b>FreeRADIUS</b> is the only authority for WiFi access (WPA2-Enterprise / 802.1X).</li>
                <li><b>PostgreSQL</b> is the source of truth for users, wallets, sessions, and accounting.</li>
                <li>Users authenticate using <b>E.164 phone</b> as username (e.g. <span class="font-mono">+15551234567</span>).</li>
                <li>Single-device enforcement: if a user has an active session, a new device is rejected.</li>
              </ul>
            `
          )}
          ${callout(
            "warn",
            "What you must do before real WiFi clients can connect",
            `
              <ol class="list-decimal pl-5">
                <li>Add your NAS/APs as RADIUS clients (shared secret).</li>
                <li>Configure Omada SSID security to WPA2-Enterprise and point it at this RADIUS server.</li>
                <li>Create a user and credit their wallet (time/date/unlimited).</li>
              </ol>
            `
          )}
        `,
    },
    {
      id: "prereq",
      title: "Server & Network Prerequisites",
      priority: "REQUIRED",
      body: () =>
        `
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${callout(
              "info",
              "Your current server settings",
              `
                <div class="text-sm">
                  <div><span class="font-semibold">Base URL:</span> <span class="font-mono">${escapeHtml(info.cw_public_base_url)}</span></div>
                  <div class="mt-1"><span class="font-semibold">RADIUS ports:</span> UDP ${info.radius.auth_port_udp} (auth), UDP ${info.radius.acct_port_udp} (acct)</div>
                  <div class="mt-1"><span class="font-semibold">Session grace:</span> ${info.active_session_grace_seconds}s</div>
                </div>
              `
            )}
            ${callout(
              "warn",
              "Firewall & reachability checklist",
              `
                <ul class="list-disc pl-5 text-sm">
                  <li>Open <b>80/tcp</b> and <b>443/tcp</b> for the Admin UI / API.</li>
                  <li>Open <b>1812/udp</b> and <b>1813/udp</b> from every Omada site/device.</li>
                  <li>Ensure APs can route to this server IP (no double-NAT surprises).</li>
                </ul>
              `
            )}
          </div>
        `,
    },
    {
      id: "domain",
      title: "Domain & HTTPS (No CLI)",
      priority: "RECOMMENDED",
      body: () =>
        `
          ${callout(
            "info",
            "Goal",
            `Switch from IP-based access (<span class="font-mono">http://${escapeHtml(String(info.cw_public_base_url || ""))}</span>) to a real domain and HTTPS without using the server CLI.`
          )}
          ${callout(
            "warn",
            "You still must set DNS (outside this app)",
            `
	              Create an <b>A record</b> pointing your domain to this server IP.
	              <div class="mt-2">Example:</div>
	              ${codeBlock(`centralwifi.example.com  A  ${serverHost}`)}
	              After DNS propagates, click “Apply HTTPS” below.
	            `
	          )}
          <div class="mt-4 p-4 rounded-xl border border-slate-200">
            <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">CONFIGURE</div>
            <form id="wizDomainForm" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              ${input("wizDomainName", "Domain (example.com)", "text", "")}
              <div>
                <label class="block mb-2 text-sm font-medium text-slate-900">Mode</label>
                <select id="wizDomainMode" class="bg-slate-50 border border-slate-300 text-slate-900 text-sm rounded-lg focus:ring-emerald-500 focus:border-emerald-500 block w-full p-2.5">
                  <option value="https">HTTPS (recommended)</option>
                  <option value="http">HTTP only (testing)</option>
                </select>
              </div>
              ${input("wizPublicUrl", "Public Base URL (informational)", "text", "", "https://example.com")}
              <div class="flex items-end">${btn("Apply", "w-full")}</div>
              <div id="wizDomainErr" class="md:col-span-2"></div>
            </form>
          </div>
          <div class="mt-4" id="wizDomainOut"></div>
          ${callout(
            "info",
            "What happens when you click Apply",
            `
              <ul class="list-disc pl-5 text-sm">
                <li>The reverse proxy (Caddy) configuration is updated and reloaded automatically.</li>
                <li>Caddy will attempt to issue a TLS certificate in HTTPS mode.</li>
                <li>If DNS is not correct yet, HTTPS provisioning will fail; you can retry later.</li>
              </ul>
            `
          )}
        `,
      afterRender: async () => {
        $("#wizDomainOut").innerHTML = "<div class='text-slate-600 text-sm'>Loading current proxy config…</div>";
        try {
          const cur = await apiFetch("/api/v1/ops/domain");
          $("#wizDomainOut").innerHTML = callout(
            "info",
            "Current reverse-proxy site label",
            `<span class="font-mono">${escapeHtml(cur.site || "(unknown)")}</span>`
          );
        } catch (e) {
          $("#wizDomainOut").innerHTML = errBox(e.message);
        }

        $("#wizDomainForm").addEventListener("submit", async (e) => {
          e.preventDefault();
          $("#wizDomainErr").innerHTML = "";
          $("#wizDomainOut").innerHTML = "";
          try {
            const domain = $("#wizDomainName").value.trim();
            const mode = $("#wizDomainMode").value;
            const public_base_url = $("#wizPublicUrl").value.trim() || (mode === "https" ? `https://${domain}` : `http://${domain}`);
            const res = await apiFetch("/api/v1/ops/domain", {
              method: "PUT",
              body: JSON.stringify({ domain, mode, public_base_url }),
            });
            $("#wizDomainOut").innerHTML = callout("ok", "Applied", `Reverse proxy updated: <span class="font-mono">${escapeHtml(res.site)}</span>`);
            done["domain"] = true;
          } catch (e2) {
            $("#wizDomainErr").innerHTML = errBox(e2.message);
          }
        });
      },
    },
    {
      id: "radius",
      title: "Add NAS / RADIUS Clients (Omada APs)",
      priority: "REQUIRED",
      body: () =>
        `
          ${callout(
            "info",
            "RADIUS shared secret",
            `Use this shared secret in Omada and when adding NAS entries here: <span class="font-mono break-all">${escapeHtml(info.radius.shared_secret)}</span>`
          )}
          <div class="mt-4 p-4 rounded-xl border border-slate-200">
            <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">ADD NAS</div>
            <form id="wizNasForm" class="grid grid-cols-1 md:grid-cols-3 gap-3">
              ${input("wizNasName", "Name", "text", "omada-site-1")}
              ${input("wizNasIp", "IP", "text", "192.168.1.2")}
              ${input("wizNasSecret", "Shared secret", "text", info.radius.shared_secret)}
              <div id="wizNasErr" class="md:col-span-3"></div>
              <div class="md:col-span-3">${btn("Add NAS")}</div>
            </form>
          </div>
          <div class="mt-4" id="wizNasList"></div>
          ${callout(
            "warn",
            "Omada settings you must apply",
            `
              <ul class="list-disc pl-5 text-sm">
                <li>SSID security: <b>WPA2-Enterprise</b> (802.1X).</li>
                <li>RADIUS server: this server IP, port ${info.radius.auth_port_udp}, shared secret above.</li>
                <li>Accounting: enabled to port ${info.radius.acct_port_udp} (Interim updates recommended).</li>
              </ul>
              <div class="mt-2 text-sm">See <span class="font-mono">docs/OMADA_SETUP.md</span> for the exact screens.</div>
            `
          )}
        `,
      afterRender: async () => {
        const renderList = async () => {
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
          $("#wizNasList").innerHTML = table(["Name", "IP", "Secret"], tbody || `<tr><td class="px-4 py-3" colspan="3">No NAS yet</td></tr>`);
        };
        await renderList();

        $("#wizNasForm").addEventListener("submit", async (e) => {
          e.preventDefault();
          $("#wizNasErr").innerHTML = "";
          try {
            await apiFetch("/api/v1/admin/nas", {
              method: "POST",
              body: JSON.stringify({
                name: $("#wizNasName").value.trim(),
                ip: $("#wizNasIp").value.trim(),
                secret: $("#wizNasSecret").value,
              }),
            });
            await renderList();
          } catch (e2) {
            $("#wizNasErr").innerHTML = errBox(e2.message);
          }
        });
      },
    },
    {
      id: "plans",
      title: "Plans & Pricing",
      priority: "RECOMMENDED",
      body: () =>
        `
          ${callout(
            "info",
            "Why plans matter",
            `Plans standardize pricing and duration. You can still credit wallets manually any time.`
          )}
          ${callout(
            "warn",
            "Recommended starter plans",
            `
              <ul class="list-disc pl-5 text-sm">
                <li>TIME: 1 hour (3600s)</li>
                <li>TIME: 1 day (86400s)</li>
                <li>UNLIMITED (for VIP / staff)</li>
                <li>DATE: valid until a date/time (use wallet “valid until” extension)</li>
              </ul>
            `
          )}
          <div class="mt-4" id="wizPlans"></div>
        `,
      afterRender: async () => {
        const rows = await apiFetch("/api/v1/admin/plans");
        const tbody = rows
          .map(
            (p) => `
            <tr class="border-t border-slate-100">
              <td class="px-4 py-3 font-mono text-xs">${p.id}</td>
              <td class="px-4 py-3">${escapeHtml(p.type)}</td>
              <td class="px-4 py-3 font-mono text-xs">${p.duration_seconds ?? "-"}</td>
              <td class="px-4 py-3 font-mono text-xs">${p.price}</td>
            </tr>
          `
          )
          .join("");
        $("#wizPlans").innerHTML = table(["ID", "Type", "Duration", "Price"], tbody || `<tr><td class="px-4 py-3" colspan="4">No plans yet (OK)</td></tr>`);
      },
    },
    {
      id: "test-user",
      title: "Create a Test User + Credit Wallet",
      priority: "REQUIRED",
      body: () =>
        `
          ${callout(
            "info",
            "What this step enables",
            `After this, you can authenticate via RADIUS and confirm Access-Accept/Reject rules (including single-device enforcement).`
          )}
          <div class="mt-4 p-4 rounded-xl border border-slate-200">
            <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">CREATE TEST USER</div>
            <form id="wizUserForm" class="grid grid-cols-1 md:grid-cols-3 gap-3">
              ${input("wizUserPhone", "Phone (E.164)", "text", "+15551234567")}
              ${input("wizUserSeconds", "Initial credit (seconds)", "number", "3600")}
              <div class="flex items-end">${btn("Create + Credit", "w-full")}</div>
              <div id="wizUserErr" class="md:col-span-3"></div>
            </form>
          </div>
          <div class="mt-4" id="wizUserOut"></div>
          ${callout(
            "info",
            "RADIUS test example (run on server)",
            `Inside <span class="font-mono">/opt/centralwifi/app</span>, you can run:`
          )}
          ${codeBlock(
            `docker compose exec -T radius bash -lc "printf 'User-Name = +15551234567\\nUser-Password = <WIFI_PASSWORD>\\nCalling-Station-Id = AA-BB-CC-DD-EE-FF\\n' | radclient -x 127.0.0.1:1812 auth '${info.radius.shared_secret}'"`
          )}
        `,
      afterRender: async () => {
        $("#wizUserForm").addEventListener("submit", async (e) => {
          e.preventDefault();
          $("#wizUserErr").innerHTML = "";
          $("#wizUserOut").innerHTML = "";
          const phone = $("#wizUserPhone").value.trim();
          const seconds = Number($("#wizUserSeconds").value);
          try {
            const u = await apiFetch("/api/v1/admin/users", { method: "POST", body: JSON.stringify({ phone }) });
            const reset = await apiFetch(`/api/v1/admin/users/${u.id}/reset-password`, { method: "POST" });
            await apiFetch("/api/v1/admin/wallet/credit", {
              method: "POST",
              body: JSON.stringify({ user_id: u.id, source: "ADMIN", amount_seconds: seconds }),
            });
            $("#wizUserOut").innerHTML = callout(
              "ok",
              "Test user created",
              `
                <div class="text-sm">
                  <div><span class="font-semibold">Username:</span> <span class="font-mono">${escapeHtml(reset.username)}</span></div>
                  <div class="mt-1"><span class="font-semibold">WiFi password:</span> <span class="font-mono">${escapeHtml(reset.new_password)}</span></div>
                  <div class="mt-1"><span class="font-semibold">Wallet credited:</span> ${seconds} seconds</div>
                </div>
              `
            );
          } catch (e2) {
            $("#wizUserErr").innerHTML = errBox(e2.message);
          }
        });
      },
    },
    {
      id: "vendo",
      title: "Vendo (JuanFi) Integration",
      priority: "OPTIONAL",
      body: () =>
        `
          ${callout(
            "info",
            "When to do this",
            `Do this only if you are deploying coin vendo machines. The rest of the WiFi system works without it.`
          )}
          ${callout(
            "warn",
            "Security model (important)",
            `Each vendo device has a one-time token. Firmware signs credit events using HMAC-SHA256; the backend validates signature + nonce idempotency.`
          )}
          <div class="mt-4 p-4 rounded-xl border border-slate-200">
            <div class="text-xs tracking-widest font-semibold text-slate-500 mb-3">REGISTER VENDO DEVICE</div>
            <form id="wizDevForm" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              ${input("wizDevId", "Device ID", "text", "vendo-001")}
              ${input("wizDevUser", "Wallet user id (optional)", "text", "")}
              <div id="wizDevErr" class="md:col-span-2"></div>
              <div class="md:col-span-2">${btn("Create device (shows token once)")}</div>
            </form>
          </div>
          <div class="mt-4" id="wizDevOut"></div>
          ${callout("info", "Docs", `See <span class="font-mono">docs/VENDO_INTEGRATION.md</span> for firmware flashing and payload details.`)}
        `,
      afterRender: async () => {
        $("#wizDevForm").addEventListener("submit", async (e) => {
          e.preventDefault();
          $("#wizDevErr").innerHTML = "";
          $("#wizDevOut").innerHTML = "";
          try {
            const res = await apiFetch("/api/v1/admin/devices", {
              method: "POST",
              body: JSON.stringify({
                device_id: $("#wizDevId").value.trim(),
                wallet_user_id: $("#wizDevUser").value.trim() ? Number($("#wizDevUser").value.trim()) : null,
              }),
            });
            $("#wizDevOut").innerHTML = callout(
              "ok",
              "Device created",
              `Save this token in the firmware (shown once): <span class="font-mono break-all">${escapeHtml(res.device_token)}</span>`
            );
          } catch (e2) {
            $("#wizDevErr").innerHTML = errBox(e2.message);
          }
        });
      },
    },
    {
      id: "integrations",
      title: "SMS + Payments (Optional for now)",
      priority: "OPTIONAL",
      body: () =>
        `
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${callout(
              "info",
              "SMS delivery",
              `
                <div class="text-sm">Current provider: ${pill(info.sms_provider)}</div>
                <div class="mt-2 text-sm text-slate-700">Default is mock (logs to database). You can test it in <b>SMS Tool</b>.</div>
                <div class="mt-2 text-sm">Docs: <span class="font-mono">docs/SMS.md</span></div>
              `
            )}
            ${callout(
              "info",
              "Payments gateway",
              `
                <div class="text-sm">Current provider: ${pill(info.payment_provider)}</div>
                <div class="mt-2 text-sm text-slate-700">Default is mock webhook. Real gateway adapters can be configured later.</div>
                <div class="mt-2 text-sm">Docs: <span class="font-mono">docs/PAYMENT.md</span></div>
              `
            )}
          </div>
        `,
    },
    {
      id: "finish",
      title: "Finish & Test",
      priority: "REQUIRED",
      body: () =>
        `
          ${setup.completed ? callout("ok", "Setup marked complete", `Completed at: <span class="font-mono">${escapeHtml(String(setup.completed_at || ""))}</span>`) : ""}
          ${callout(
            "warn",
            "Ready-to-test checklist",
            `
              <ol class="list-decimal pl-5 text-sm">
                <li>NAS added in this UI and Omada points to the same shared secret.</li>
                <li>SSID is WPA2-Enterprise and accounting is enabled.</li>
                <li>At least one user has wallet credit (time/date/unlimited).</li>
                <li>Connect with one device → should work; second device → should reject.</li>
              </ol>
            `
          )}
          ${callout(
            "info",
            "If you want to re-run the wizard later",
            `Use “Edit mode” (keep changes) or “Reset wizard” (does not delete data; only resets the completion flag).`
          )}
          <div class="mt-4 flex flex-wrap gap-2">
            <button id="btnCompleteSetup" class="text-white bg-emerald-600 hover:bg-emerald-700 font-semibold rounded-lg text-sm px-4 py-2.5">Mark setup complete</button>
            <button id="btnEditSetup" class="text-slate-800 bg-white hover:bg-slate-50 border border-slate-200 font-semibold rounded-lg text-sm px-4 py-2.5">Edit mode (re-run wizard)</button>
            <button id="btnResetSetup" class="text-white bg-red-600 hover:bg-red-700 font-semibold rounded-lg text-sm px-4 py-2.5">Reset wizard</button>
          </div>
        `,
      afterRender: async () => {
        const complete = $("#btnCompleteSetup");
        complete.onclick = async () => {
          await apiFetch("/api/v1/admin/system/setup/complete", { method: "POST" });
          await apiFetch("/api/v1/admin/system/setup", { method: "GET" });
          alert("Setup marked complete. You can now use the dashboard.");
          routeGo("dashboard");
        };
        const edit = $("#btnEditSetup");
        edit.onclick = async () => {
          // No-op: wizard is always editable; keep completion flag.
          alert("Edit mode: navigate steps and update settings. You can always return here from the sidebar.");
        };
        const reset = $("#btnResetSetup");
        reset.onclick = async () => {
          if (!confirm("Reset setup wizard completion flag? (Does NOT delete users/NAS/plans.)")) return;
          await apiFetch("/api/v1/admin/system/setup/reset", { method: "POST" });
          alert("Wizard reset. It will appear after next login.");
        };
      },
    },
  ];

  const clamp = (n) => Math.max(0, Math.min(steps.length - 1, n));
  let idx = clamp(current);

  const saveState = async (partial) => {
    const next = {
      ...state,
      ...partial,
      current_step: idx,
      done: { ...(state.done || {}), ...(partial.done || {}) },
    };
    await apiFetch("/api/v1/admin/system/setup", { method: "PUT", body: JSON.stringify({ state: next }) });
  };

  const renderStep = async () => {
    const s = steps[idx];
    const badge =
      s.priority === "REQUIRED"
        ? `<span class="ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-200">REQUIRED</span>`
        : s.priority === "RECOMMENDED"
          ? `<span class="ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">RECOMMENDED</span>`
          : `<span class="ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-slate-50 text-slate-700 border border-slate-200">OPTIONAL</span>`;

    const left = `
      <div class="space-y-2">
        <div class="text-xs tracking-widest font-semibold text-slate-500">STEPS</div>
        <ol class="space-y-1">
          ${steps
            .map((x, i) => {
              const isActive = i === idx;
              const isDone = !!done[x.id];
              return `
                <li>
                  <button data-step="${i}" class="w-full text-left px-3 py-2 rounded-lg text-sm ${
                    isActive ? "bg-slate-100 text-slate-900" : "hover:bg-slate-50 text-slate-700"
                  }">
                    <div class="flex items-center justify-between gap-2">
                      <span>${escapeHtml(x.title)}</span>
                      <span class="text-xs ${isDone ? "text-emerald-700" : "text-slate-400"}">${isDone ? "DONE" : ""}</span>
                    </div>
                  </button>
                </li>
              `;
            })
            .join("")}
        </ol>
      </div>
    `;

    const content = `
      ${pageTitle("Setup Wizard")}
      ${setup.completed ? callout("ok", "Already configured", `This system was previously marked as setup complete. You can re-run steps in edit mode anytime.`) : ""}
      <div class="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6">
        <aside class="bg-white border border-slate-200 rounded-xl p-4">${left}</aside>
        <section class="space-y-4">
          <div class="flex items-center justify-between gap-3">
            <div class="text-xl font-bold text-slate-900">${escapeHtml(s.title)} ${badge}</div>
            <div class="text-sm text-slate-500">${idx + 1} / ${steps.length}</div>
          </div>
          <div class="space-y-4">${s.body()}</div>
          <div class="pt-2 flex flex-wrap gap-2 justify-between">
            <div class="flex gap-2">
              <button id="btnPrev" class="text-slate-800 bg-white hover:bg-slate-50 border border-slate-200 font-semibold rounded-lg text-sm px-4 py-2.5" ${
                idx === 0 ? "disabled" : ""
              }>Back</button>
              <button id="btnNext" class="text-white bg-slate-900 hover:bg-black font-semibold rounded-lg text-sm px-4 py-2.5">${
                idx === steps.length - 1 ? "Go to Dashboard" : "Next"
              }</button>
            </div>
            <div class="flex gap-2">
              <button id="btnMarkDone" class="text-white bg-emerald-600 hover:bg-emerald-700 font-semibold rounded-lg text-sm px-4 py-2.5">Mark step done</button>
            </div>
          </div>
        </section>
      </div>
    `;

    root.innerHTML = layoutApp("setup", content);
    const signOut = $("#btnSignOut");
    if (signOut) signOut.onclick = () => {
      tokenClear();
      routeGo("login");
    };

    root.querySelectorAll("button[data-step]").forEach((b) => {
      b.addEventListener("click", async () => {
        idx = clamp(Number(b.dataset.step));
        await saveState({ current_step: idx });
        await renderStep();
      });
    });

    $("#btnPrev").onclick = async () => {
      idx = clamp(idx - 1);
      await saveState({ current_step: idx });
      await renderStep();
    };
    $("#btnNext").onclick = async () => {
      if (idx === steps.length - 1) {
        routeGo("dashboard");
        return;
      }
      idx = clamp(idx + 1);
      await saveState({ current_step: idx });
      await renderStep();
    };
    $("#btnMarkDone").onclick = async () => {
      done[s.id] = true;
      await saveState({ done });
      alert("Marked done.");
      if (idx < steps.length - 1) {
        idx = clamp(idx + 1);
        await saveState({ current_step: idx });
        await renderStep();
      }
    };

    if (s.afterRender) await s.afterRender();
  };

  await renderStep();
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
  if (r === "setup") {
    await viewSetupWizard();
    const b = $("#btnSignOut");
    if (b) b.onclick = () => {
      tokenClear();
      routeGo("login");
    };
    return;
  }
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
