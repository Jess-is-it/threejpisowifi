/* Central WiFi Top-Up Portal (Flowbite-styled, zero-runtime-deps SPA). */

const root = document.getElementById("appRoot");
const $ = (sel, el = document) => el.querySelector(sel);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
}

function tokenGet() {
  return window.localStorage.getItem("cw_portal_token");
}
function tokenSet(t) {
  window.localStorage.setItem("cw_portal_token", t);
}
function tokenClear() {
  window.localStorage.removeItem("cw_portal_token");
}

function errBox(msg) {
  return `<div class="p-3 rounded-lg border border-red-200 bg-red-50 text-red-800 text-sm">${escapeHtml(msg)}</div>`;
}
function okBox(msg) {
  return `<div class="p-3 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-900 text-sm">${msg}</div>`;
}

async function apiFetch(path, init) {
  const headers = new Headers((init && init.headers) || {});
  headers.set("Content-Type", "application/json");
  const t = tokenGet();
  if (t) headers.set("Authorization", `Bearer ${t}`);
  const res = await fetch(path, { ...init, headers });
  let body = {};
  try {
    body = await res.json();
  } catch {}
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
}

function card(title, body) {
  return `
    <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
      <div class="text-xs tracking-widest font-semibold text-slate-500">CENTRAL WIFI</div>
      <div class="mt-1 text-xl font-bold text-slate-900">${escapeHtml(title)}</div>
      <div class="mt-3 text-sm text-slate-700 leading-6">${body}</div>
    </div>
  `;
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

function fmtSeconds(n) {
  const s = Math.max(0, Number(n || 0));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
}

async function render() {
  root.innerHTML = `
    <header class="border-b border-slate-200 bg-white">
      <div class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between gap-4">
        <div>
          <div class="text-xs tracking-widest font-semibold text-slate-500">CENTRAL WIFI</div>
          <div class="text-2xl font-black text-slate-900">Top-Up Portal</div>
          <div class="mt-1 text-sm text-slate-600">Get credentials, check wallet, and buy time plans.</div>
        </div>
        <div class="flex items-center gap-2">
          <a href="/" class="text-sm font-semibold px-3 py-2 rounded-lg border border-slate-200 hover:bg-slate-50">Admin</a>
          <button id="btnLogout" class="text-sm font-semibold px-3 py-2 rounded-lg border border-slate-200 hover:bg-slate-50">Sign out</button>
        </div>
      </div>
    </header>
    <main class="max-w-5xl mx-auto px-4 py-6 space-y-6">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        ${card(
          "Get WiFi Credentials (SMS)",
          `
            <div class="text-sm text-slate-700">Enter your phone number in E.164 format (starts with <span class="font-mono">+</span>).</div>
            <form id="credForm" class="mt-4 space-y-3">
              ${input("credPhone", "Phone (E.164)", "text", "+639171234567")}
              <div id="credOut"></div>
              ${btn("Send credentials via SMS", "w-full")}
              <div class="text-xs text-slate-500">If SMS provider is mock, the admin can view messages in Admin → SMS Tool.</div>
            </form>
          `
        )}
        ${card(
          "Check Wallet Status",
          `
            <form id="loginForm" class="mt-1 space-y-3">
              ${input("loginPhone", "Phone (E.164)", "text", "+639171234567")}
              ${input("loginPass", "Password", "password", "")}
              <div id="loginOut"></div>
              ${btn("Sign in", "w-full")}
            </form>
            <div class="mt-4 p-3 rounded-lg border border-slate-200 bg-slate-50 text-sm text-slate-700" id="meBox">
              Not signed in.
            </div>
          `
        )}
      </div>

      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div class="text-xs tracking-widest font-semibold text-slate-500">PLANS</div>
        <div class="mt-1 text-xl font-bold text-slate-900">Buy a plan (mock payment by default)</div>
        <div class="mt-3 text-sm text-slate-600">After purchase, your wallet is credited immediately in mock mode.</div>
        <div class="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4" id="plansGrid">
          <div class="text-sm text-slate-600">Loading plans…</div>
        </div>
        <div class="mt-4" id="payOut"></div>
      </div>

      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div class="text-xs tracking-widest font-semibold text-slate-500">HOW TO CONNECT</div>
        <div class="mt-1 text-xl font-bold text-slate-900">WiFi access is WPA2-Enterprise (802.1X)</div>
        <div class="mt-3 text-sm text-slate-700 leading-6">
          <ol class="list-decimal pl-5">
            <li>Get credentials via SMS above.</li>
            <li>Connect to your WiFi SSID configured for WPA2-Enterprise.</li>
            <li>Username is your phone (E.164). Password is the SMS password.</li>
            <li>If your wallet has no credit, you may be rejected (or placed in a restricted network if walled garden is enabled).</li>
          </ol>
        </div>
      </div>
    </main>
  `;

  $("#btnLogout").onclick = () => {
    tokenClear();
    render();
  };

  $("#credForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#credOut").innerHTML = "";
    try {
      const phone = $("#credPhone").value.trim();
      const res = await apiFetch("/api/v1/portal/credentials/request", {
        method: "POST",
        body: JSON.stringify({ phone }),
      });
      $("#credOut").innerHTML = okBox(`Sent. Provider: <span class="font-mono">${escapeHtml(res.provider)}</span>`);
    } catch (e2) {
      $("#credOut").innerHTML = errBox(e2.message);
    }
  });

  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#loginOut").innerHTML = "";
    try {
      const phone = $("#loginPhone").value.trim();
      const password = $("#loginPass").value;
      const res = await apiFetch("/api/v1/portal/auth/login", {
        method: "POST",
        body: JSON.stringify({ phone, password }),
      });
      tokenSet(res.token);
      $("#loginOut").innerHTML = okBox("Signed in.");
      await refreshMe();
      await refreshPlans(); // enable buy buttons
    } catch (e2) {
      $("#loginOut").innerHTML = errBox(e2.message);
    }
  });

  async function refreshMe() {
    const t = tokenGet();
    if (!t) {
      $("#meBox").textContent = "Not signed in.";
      return;
    }
    try {
      const me = await apiFetch("/api/v1/portal/me");
      const w = me.wallet || {};
      const credit = w.is_unlimited ? "Unlimited" : w.valid_until_ts ? `Valid until: ${escapeHtml(String(w.valid_until_ts))}` : `Time left: ${fmtSeconds(w.time_remaining_seconds)}`;
      $("#meBox").innerHTML = `
        <div class="font-semibold text-slate-900">${escapeHtml(me.username || "")}</div>
        <div class="mt-1 text-sm text-slate-700">${escapeHtml(credit)}</div>
        <div class="mt-1 text-sm ${w.has_credit ? "text-emerald-700" : "text-red-700"}">${w.has_credit ? "Has active access" : "No active access"}</div>
      `;
    } catch (e) {
      $("#meBox").innerHTML = errBox(e.message);
    }
  }

  async function refreshPlans() {
    $("#plansGrid").innerHTML = `<div class="text-sm text-slate-600">Loading plans…</div>`;
    try {
      const plans = await apiFetch("/api/v1/portal/plans");
      const authed = !!tokenGet();
      const cards = (plans || []).map((p) => {
        const dur = p.type === "UNLIMITED" ? "Unlimited" : p.duration_seconds ? fmtSeconds(p.duration_seconds) : "-";
        return `
          <div class="p-4 rounded-xl border border-slate-200 bg-white">
            <div class="text-xs font-semibold text-slate-500">${escapeHtml(p.type)}</div>
            <div class="mt-1 text-lg font-bold text-slate-900">${escapeHtml(dur)}</div>
            <div class="mt-2 text-sm text-slate-700">Price: <span class="font-mono">${escapeHtml(String(p.price))}</span></div>
            <div class="mt-3">
              <button data-plan="${p.id}" class="w-full ${authed ? "text-white bg-emerald-600 hover:bg-emerald-700" : "text-slate-400 bg-slate-100"} font-semibold rounded-lg text-sm px-4 py-2.5" ${authed ? "" : "disabled"}>
                ${authed ? "Buy (mock)" : "Sign in to buy"}
              </button>
            </div>
          </div>
        `;
      });
      $("#plansGrid").innerHTML = cards.join("") || `<div class="text-sm text-slate-600">No plans configured yet.</div>`;
      root.querySelectorAll("button[data-plan]").forEach((b) => {
        b.addEventListener("click", async () => {
          $("#payOut").innerHTML = "";
          const plan_id = Number(b.dataset.plan);
          try {
            const idempotency_key = `portal-${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const res = await apiFetch("/api/v1/portal/topup", {
              method: "POST",
              body: JSON.stringify({ plan_id, idempotency_key }),
            });
            $("#payOut").innerHTML = okBox(`Payment complete. Ref: <span class="font-mono">${escapeHtml(res.ref || "")}</span>`);
            await refreshMe();
          } catch (e2) {
            $("#payOut").innerHTML = errBox(e2.message);
          }
        });
      });
    } catch (e) {
      $("#plansGrid").innerHTML = errBox(e.message);
    }
  }

  await refreshMe();
  await refreshPlans();
}

render();

