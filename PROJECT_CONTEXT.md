# 3JCentralPisowifi Project Context

Every future AI agent, developer, or maintainer must read this file before changing the project. Update it whenever architecture, deployment, features, commands, branches, workflows, or decisions change.

## Shared screenshot location
When the project owner references an attached screenshot/image by filename only, immediately check `/mnt/windows_vod/3jmain_ss/` for matching files. Example: if the user says `payment1`, inspect `/mnt/windows_vod/3jmain_ss/payment1*` before asking for the image path.

## Captive Portal Modal Scroll Stability — 2026-06-05
- `PortalApp` re-renders frequently because remaining-time countdowns and store purchase polling update state while customer modals are open.
- Do not render modal helpers defined inside `PortalApp` as nested React component elements such as `<BagModal />` or `<CategoryProductsModal />`. React treats that inline function identity as a new component type after each parent render, remounting the modal and resetting mobile scroll back to the top.
- If a modal helper stays inside `PortalApp` and does not use hooks, call it as a render helper, for example `{BagModal()}`. If hooks are needed, move the modal component outside `PortalApp` and pass props explicitly.
- Custom three-row modals with fixed header, scrollable middle content, and fixed footer must wire back-to-top buttons to the real scroll container, such as `.portal-store-scroll-area`, not the generic modal body.
- Current captive portal modal helpers inside `PortalApp` are rendered as function calls, not JSX component tags, so countdown/polling re-renders do not remount them.
- Physical store item selection is intentionally a full in-page store detail screen, not a modal, because the store item list and sticky purchase footer are easier to control with normal page scrolling on mobile.

## 1. Project overview
3JCentralPisowifi is now focused on Omada Captive Portal + WiFi Pass access. Product Items, PayMongo, Physical Stores, welcome gifts, and optional vouchers create customer WiFi Bag items. 3JCentralPisowifi tracks customer profiles, WiFi Bag access, portal sessions, and Omada authorization state. MikroTik remains for station VLAN/DHCP/NAT transport and read-only preflight validation.

## 2. Business goal
Create a dependable central system where operators can manage product items, physical stores, vouchers for events/refunds/gifts, customer WiFi Bag access, Omada AP/site/SSID readiness, MikroTik station transport, and customer-facing captive portal access.

## 3. Current phase
Active cleanup phase: remove the old Wallet feature completely and retire RADIUS/WPA2-Enterprise lab tooling, AI/OpenAI assistant surfaces, MikroTik HotSpot enforcement surfaces, and Office AP Path transport from the active system.

## Active Product Direction — May 2026 Cleanup
- Primary customer flow: Omada open SSID captive portal -> `/portal` -> Product Items / Physical Stores / optional voucher claim -> customer WiFi Bag item -> Omada client authorization.
- MikroTik flow: station VLAN/DHCP/NAT/trunk transport only. MikroTik HotSpot enforcement, login.html sync, HotSpot diagnostics, and Office AP Path transport are removed from the active system.
- Wallet is removed completely. Do not reintroduce `wallets`, `transactions`, Wallet / Manual Top-Up UI, or wallet crediting. Use `customer_bag_items`, `customer_bag_events`, `sales`, `store_purchase_requests`, `vouchers`, `voucher_redemptions`, and `portal_sessions`.
- Old Omada install/manage automation must remain. The Omada Controller page still supports controller install/start/stop/restart/backup/host-network management and API settings.
- RADIUS/FreeRADIUS, NAS client management, RADIUS packet tests, RADIUS accounting sessions, Omada RADIUS profile automation, WPA2-Enterprise test SSID automation, and AI/OpenAI assistant workflows are retired and should not be restored unless the project owner explicitly asks.
- Read-only MikroTik preflight scanning remains because it is needed to validate VLAN, subnet, pool, DHCP, routing, PPPoE, OSPF, WireGuard, and firewall risks before station transport changes.
- Migration `117_cleanup_retired_wallet_ai_radius_hotspot.sql` drops retired Wallet, RADIUS/NAS, AI/OpenAI planning, MikroTik HotSpot sync/authorization, Office AP Path, Omada RADIUS lab, and legacy portal template tables. The legacy `sessions` table is temporarily retained only as a Customer Devices fallback until that page is fully moved to `portal_sessions` and WiFi Bag records.
- Any older historical section below that says Wallet, RADIUS, AI, MikroTik HotSpot, or Office AP Path remains active is superseded by this cleanup section.

## Random MAC Handling — Device Session Token
- Random/private WiFi MAC handling uses a 3J device-session token, not Google login, browser fingerprinting, or a user prompt.
- After a successful voucher redemption, `/portal` returns a secure random `device_token`; the browser stores it locally and sends it on later portal loads.
- PostgreSQL stores only a hash of the device token. Raw device tokens must not be logged, returned to admin APIs, or stored in clear text.
- If the same token returns with a different Omada/MikroTik client MAC while access time remains, the backend silently re-authorizes the new MAC for the remaining time.
- The voucher is not redeemed again and no new time is credited during a MAC rebind.
- MAC rebinds are limited and logged in `portal_mac_rebind_events` and `portal_events`.
- If the phone/browser loses local storage, the system cannot prove it is the same device; the operator can handle that manually later.
- Google login remains a future optional account feature only. It is not required for voucher random-MAC handling.

## Captive Portal — Portal Notifs
- Admin -> Captive Portal -> Portal Notifs configures customer-facing notification messages.
- Notifications include WiFi pass activation, voucher claim success, remaining-time reminder, time-consumed, and restored-session messages.
- Template tags include `<TIME>`, `<REMAINING>`, `<VOUCHER>`, `<SSID>`, `<EXPIRES_AT>`, `<BRAND>`, and `<STATUS>`.
- The portal attempts browser/Web Notifications where the phone browser allows them and always shows an in-portal fallback message.
- The system cannot customize the Android/iOS built-in `Sign in to WiFi network` notification text.

## Store Owner Purchase Request Alerts
- Store owner purchase request alerts must use browser/phone Web Push notifications, not Smart A2P SMS.
- The store owner must log in to `/store` on the target phone/browser and enable alerts once so the browser push subscription can be saved.
- When a customer submits a store purchase request, the backend sends a Web Push notification to active subscriptions for that store owner. The store portal may still show in-page live updates while open.
- SMS for store owners remains limited to account activation, login/device verification, password reset, and PIN verification. Do not use SMS for every customer purchase request.
- Web Push requires HTTPS and browser support. Android Chrome supports the intended flow; unsupported browsers must still rely on the live store portal page.

## Captive Portal — Message Defaults
- Admin -> Captive Portal -> Message Defaults owns portal SMS confirmation defaults.
- The default Sender ID is selected from the provisioned Smart A2P Sender IDs. Do not show or edit the Sender ID list in this tab.
- Portal SMS confirmation tracking is separate from global A2P tracking and counts only captive-portal profile verification and Report Missing Time verification codes.
- System Settings -> A2P Messaging remains for Smart provider credentials, API paths, direct credits check, and test SMS only.
- Never include `https://` or `http://` in SMS message bodies. Smart may block SMS containing full URL schemes, so customer/owner SMS must use bare domains such as `net.3jhotspot.com` or `net.3jhotspot.com/store`.
- This bare-domain SMS rule applies only to SMS text. Browser links, Cloudflare Tunnel, PayMongo webhooks, Omada external portal configuration, and API calls may still use full HTTPS URLs where required.

## Contact Number Normalization
- Any contact number entered anywhere in the system must be normalized before SMS/API use.
- Philippine mobile numbers entered as local `09XXXXXXXXX` must be converted to international Smart A2P format `63XXXXXXXXXX` for SMS delivery.
- For database/customer display, keep the readable local form when useful, but backend matching should store a normalized contact key such as `+63XXXXXXXXXX`.
- Do not expose this conversion as editable text to customers; normalize silently in the backend to reduce confusion and input errors.
- Physical store owner login usernames must use the owner contact number, for example `09055726415`. Do not generate dotted usernames from store names. Store owner login should accept the local contact number and the backend may also match the normalized contact key.

## Public HTTPS Endpoint — Cloudflare Tunnel
- Production public HTTPS should use Cloudflare Tunnel instead of MikroTik inbound port-forwarding.
- Current production domain: `3jhotspot.com`; active portal hostname: `net.3jhotspot.com`.
- Admin -> System Settings -> Public HTTPS stores the Cloudflare tunnel connector token encrypted and can start/stop/restart the local `cloudflared` connector.
- The connector runs from the 3JCentralPisowifi API container and reaches the app reverse proxy at `http://proxy:80`.
- In Cloudflare Tunnel Public Hostname, use subdomain `net`, domain `3jhotspot.com`, service type `HTTP`, and service URL `http://proxy:80`.
- Public portal URL target: `https://net.3jhotspot.com/portal`.
- PayMongo webhook target: `https://net.3jhotspot.com/api/payments/paymongo/webhook`.
- Do not commit Cloudflare tunnel tokens, API tokens, or connector commands containing secrets.
- MikroTik public NAT/port-forward rules are not required for this Cloudflare Tunnel path.

## IPTV Integration — XUI Reusable Active Lines
- IPTV products provision XUI lines when a WiFi Bag item is activated, not when the item is bought and queued. If the customer already has active IPTV time, activation must reuse the existing provisioned XUI line. If the previous IPTV item already expired before the queued item is activated, create a new XUI line at activation time.
- The XUI line must be created as non-trial, non-restreamer, `Never Expire`, and with customer playback Access Outputs enabled. Do not send `exp_date` or `duration` to the XUI access-code API.
- On this XUI.ONE install, the access-code `create_line` / `edit_line` endpoint can report success while still saving `is_restreamer=1` and `allowed_outputs=[]`. The backend must read the line back and, when the configured limited XUI line-repair DB account is enabled, patch only `xui.lines.is_restreamer` and `xui.lines.allowed_outputs` for the just-created username before marking IPTV provisioned.
- 3JCentralPisowifi local state is the access timer. `customer_bag_items.active_until` controls whether a customer may watch IPTV; XUI account expiry is intentionally `NULL`.
- When an IPTV bag item is consumed, cancelled, deleted from Customer Devices, or otherwise removed by an operator, the backend must expire that item locally. Delete the linked XUI line only when no other active IPTV item still references it.
- IPTV web receives only short-lived 3J watch tokens. The IPTV web app stores the original 3J token in its local session and polls `/api/iptv/session/status` through its `/api/auth/threej-status` proxy. If 3J reports the pass deleted/expired/restricted, IPTV web must show a restriction modal and clear playback even if the user is already watching.
- IPTV web must warn before expiry using hotspot-controlled settings. Default behavior: show an IPTV warning toast at 10 minutes remaining, stop playback at 10 seconds remaining, show a clear expired modal, and return the customer to the configured portal URL (`https://net.3jhotspot.com/portal`) instead of exposing `/login`, `192.168.50.15/login`, or `tv.3jhotspot.com/login`.
- Do not rely on XUI expiry to stop IPTV access. Enforcement is: 3J bag item active state -> IPTV status endpoint -> IPTV web restriction and XUI line deletion.
- IPTV web must also have a RouterOS path to XUI/player API. In the Roma/Batu/GK topology, IPTV web is `192.168.50.15` and XUI is `10.100.100.100`; the root CCR needs scoped RAW tracking exceptions plus scoped `srcnat masquerade` for that path. If a broad `/ip firewall raw action=notrack` exists, include a NAT-return RAW exception for the CCR address on the XUI subnet, for example `10.100.100.1`, otherwise IPTV web can time out while the hotspot API still reaches XUI.

## 4. Historical Phase 1 scope
The Phase 1 notes below are historical context. The active May 2026 product direction above supersedes any old RADIUS/WPA2/NAS/session workflow references.

- One-line Ubuntu installer and updater.
- Separate production and staging deployments on the same server.
- PostgreSQL as the source of truth.
- Admin Portal at `/admin`.
- Admin login, customer devices, vouchers, Product Items, Physical Stores, Omada management, and MikroTik station transport.

## 5. Phase 1 exclusions
- Coinslot integration.
- Vendo device integration.
- SMS delivery.
- Online payments.
- Client self-registration portal.
- Dynamic VLAN.
- Omada OC300 API integration.
- WireGuard automation.
- Substation tunnel management.
- Captive portal production flow.
- Multi-role staff permissions beyond a basic admin.
- HA clustering.

## 6. GitHub repository details
Repository URL:
REPLACE_WITH_GITHUB_REPO_URL

Branches:
- master = Production
- staging = Staging

Recommended workflow:
- Developers work on staging branch.
- Test deployment uses staging branch.
- Once tested, merge staging into master.
- Production deployment updates from master.

## 7. Branch strategy
`staging` is the active development and test branch. `master` is production and should only receive tested changes from staging.

## 8. Deployment environments
Production:
- Branch: master
- Install path: `/opt/3jcentralpisowifi-production`
- Compose project: `centralwifi_prod`
- Database: `centralwifi_prod`
- Volumes: `centralwifi_prod_postgres_data`, `centralwifi_prod_redis_data`
- Web: `80/tcp`
- RADIUS service: removed from active compose runtime.

Staging:
- Branch: staging
- Install path: `/opt/3jcentralpisowifi-staging`
- Compose project: `centralwifi_staging`
- Database: `centralwifi_staging`
- Volumes: `centralwifi_staging_postgres_data`, `centralwifi_staging_redis_data`
- Web: `8080/tcp`
- RADIUS service: removed from active compose runtime.

## 9. Production server details
Production runs from `/opt/3jcentralpisowifi-production` using `/opt/3jcentralpisowifi-production/.env`. It tracks `master` and exposes the Admin Portal at `http://SERVER-IP/admin`.

## 10. Staging server details
Staging runs from `/opt/3jcentralpisowifi-staging` using `/opt/3jcentralpisowifi-staging/.env`. It tracks `staging` and exposes the Admin Portal at `http://SERVER-IP:8080/admin`.

## 11. Technical architecture
Nginx reverse proxy routes `/admin` to the React admin portal, `/portal` to the customer portal, and `/api` to FastAPI. FastAPI manages source-of-truth data in PostgreSQL, serves uploaded branding assets from an environment-specific Docker volume, and uses Redis for health/cache readiness. Omada handles captive portal enforcement and client authorization; MikroTik handles station VLAN/DHCP/NAT transport.

## 12. Source of truth explanation
PostgreSQL is the only source of truth for admins, users/customer profiles, customer WiFi Bag items/events, vouchers, sales, store purchase requests, portal sessions, portal authorization logs, MikroTik station plans, Omada site/AP records, and audit logs. Network devices must not become the customer access database.

## 13. Tech stack
- Ubuntu 22.04+
- Docker and Docker Compose
- FastAPI on Python 3.11+
- PostgreSQL
- Redis
- React with Tabler UI (`@tabler/core`) and Tabler Icons (`@tabler/icons-react`)
- Nginx

## 14. One-line install commands
Production:
`curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- install production`

Staging:
`curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- install staging`

## 15. One-line update commands
Production:
`curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- update production`

Staging:
`curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- update staging`

## 16. Admin portal features
- Login
- Dashboard
- Connected Devices
- AP & Client Map
- APs Deployment
- Vouchers
- Product Items
- Physical Stores
- Sales
- Captive Portal
- Network -> MikroTik station transport/preflight/AP management
- Omada Controller install/manage/API settings
- System Health
- Settings
- Audit Logs

UI direction:
- Admin Portal uses installed/imported Tabler UI packages, not the removed temporary template.
- Admin Portal follows the project owner's previous common UI order for shared admin features: dark vertical sidebar, sticky top header with CPU/RAM/DISK/UPTIME metrics, card-based pages, profile/password/logout behind a sidebar account dropdown, and tabbed System Settings.
- System Settings tab order is General, Access, System Update, Backup, Danger. The General tab contains Branding, including Company Logo, Browser Page Logo, System Display Name, Portal Subtitle, and Accent Color.
- Success messages should display above the page's main panel/card, not inside nested tab content. They should use a dismissible Tabler alert and auto-close after 6 seconds unless the message requires operator action.
- Do not copy old-system product names.
- Keep the UI focused on Phase 1 workflows instead of importing unrelated old-system modules.


## Phase 1C — Real RADIUS Accounting & Session Tracking
Phase 1C adds real RADIUS Accounting Start, Interim-Update, and Stop handling on top of the working Phase 1B real authentication test.

What this phase adds:
- Real UDP RADIUS Accounting-Request tests from the API container to the FreeRADIUS container.
- Accounting Start creates ACTIVE sessions without deducting wallet time.
- Accounting Interim-Update refreshes last seen/session counters and deducts elapsed wallet time safely.
- Accounting Stop performs final deduction and marks sessions STOPPED.
- `radius_accounting_logs` stores accounting diagnostics and raw packet payload context.
- ACCOUNTING DEBIT transactions record wallet time deductions.
- Sessions page separates Active, Stale, and Stopped sessions and supports View Details, Mark Stale, and Force Stop Locally.
- Wallet page shows accounting deduction summary for the selected user.

Accounting behavior:
- Start finds the user, creates or updates a session as ACTIVE, and replies Accounting-Response.
- Interim-Update finds the active session and deducts elapsed time using the delta since the previous update/session time, preventing double-deduction and negative balances.
- Stop performs one final deduction, records stop time, and marks the session STOPPED.
- Unlimited users are tracked but wallet time is not deducted.
- Valid-until access is not deducted unless the user also has a time balance.

Single-device behavior:
- Real authentication rejects with `Active session already exists` when the same user has a session with `status = ACTIVE`, `stop_time IS NULL`, and `last_update_time` within `ACTIVE_SESSION_GRACE_SECONDS`.
- Sessions outside the grace window are displayed as STALE and do not block login forever.

Test types:
- Simulated RADIUS Decision Test: API-only source-of-truth decision check, no UDP packet.
- Real FreeRADIUS Authentication Test: real Access-Request packet from API container to FreeRADIUS auth port.
- Real RADIUS Accounting Test: real Accounting-Request packet from API container to FreeRADIUS accounting port.

Ports:
- Staging web: `8080/tcp`; auth external: `11812/udp`; accounting external: `11813/udp`; internal Docker auth/accounting: `radius:1812` and `radius:1813`.
- Production web: `80/tcp`; auth: `1812/udp`; accounting: `1813/udp`.

Implementation choice:
- FreeRADIUS accounting calls `/opt/radius/radius_acct.py`, which writes directly to PostgreSQL application tables and logs diagnostics. This keeps PostgreSQL as source of truth while preserving FreeRADIUS compatibility tables.

Known limitations:
- Force Stop Locally does not disconnect clients from routers/APs because CoA disconnect is not implemented yet.
- Accounting packet tests are PAP/lab-focused and intended for Phase 1 validation.
- No vouchers, client portal, SMS, payments, captive portal, WireGuard automation, or controller integration in this phase.

Next planned phase:
- Add the next owner-approved feature after Phase 1C validation, likely voucher/client-facing flow only when explicitly requested.

## Phase 1D — External Omada Controller Server
Phase 1D adds an Admin Portal setup page for a separate Omada Software Controller server used for real TP-Link Omada AP/RADIUS test preparation.

Environment:
- 3JCentralPisowifi server: `192.168.50.70`.
- Omada Controller server: `192.168.50.71`.
- Omada is installed on a separate server for isolation.
- RADIUS authentication and accounting are still handled by FreeRADIUS on `192.168.50.70`.
- Staging RADIUS ports: auth `11812/udp`, accounting `11813/udp`.
- Production RADIUS ports: auth `1812/udp`, accounting `1813/udp`.

Architecture rules:
- Omada Controller is not the source of truth.
- 3JCentralPisowifi remains the source of truth for users, wallets, sessions, accounting, active device tracking, single-device rejection, and access decisions.
- Omada manages AP adoption, SSIDs, WiFi profiles, RADIUS profile assignment, and AP monitoring only.
- Do not store WiFi users, wallet state, vouchers, payment state, or access decisions in Omada.

Implementation scope:
- Admin Portal page: Settings / Omada Controller at `/admin/settings/omada-controller`.
- Store Omada controller settings and install logs in PostgreSQL.
- Use SSH only for controlled install/status/service actions against the Omada server.
- No arbitrary shell command execution is allowed.
- Omada install runs as a controlled background job with progress saved to `omada_install_logs`.
- Default install method is Docker on `/opt/omada-controller` with Compose project `omada_controller`.
- This phase does not automate AP adoption or deep Omada API automation.
- This phase prepares real AP testing and provides RADIUS settings/checklists.

## 17. RADIUS behavior
Access-Accept requires an active user, valid password, usable balance or valid-until or unlimited flag, and no active session inside `ACTIVE_SESSION_GRACE_SECONDS`. Access-Reject is returned for unknown users, invalid passwords, disabled users, no balance/expired access, or active single-device conflict. Accounting Start, Interim-Update, and Stop update the sessions table; Interim-Update decrements time balance without allowing negative balance.

The Admin Portal has three different RADIUS test paths:
- Simulated backend decision test: runs the same source-of-truth decision rules through the API without sending a UDP RADIUS packet.
- Internal real FreeRADIUS packet test: sends a real UDP Access-Request from the API container to the FreeRADIUS container using the fixed internal Docker test client `Docker API Test NAS`, subnet `172.18.0.0/16`, and the environment `RADIUS_DEFAULT_SECRET`.
- External router/AP RADIUS test: uses a real MikroTik, Omada, hostapd, or radtest client from outside Docker and must use the NAS/router/AP record shared secret and production/staging UDP ports.

Every FreeRADIUS reject path should include a `Reply-Message` so the Admin Portal can show a human-readable diagnostic reason and troubleshooting suggestion.

## 18. Database tables
Application tables: `admins`, `users`, `wallets`, `transactions`, `nas_clients`, `radius_auth_logs`, `sessions`, `audit_logs`, `omada_controller_settings`, `omada_install_logs`.

`radius_auth_logs` stores `diagnostic_reason` for RADIUS troubleshooting in addition to `reply_message`.

FreeRADIUS-compatible tables: `radcheck`, `radreply`, `radacct`, `radusergroup`, `radgroupcheck`, `radgroupreply`, `nas`.

## 19. User/session/wallet flow
An admin creates a test user, adds manual time balance, creates a NAS/router/AP client, configures the device with the RADIUS server and shared secret, then tests authentication. Accounting Start creates a session, Interim-Update refreshes last seen and decrements balance, and Stop closes the session.

## 20. Current assumptions
- Phase 1 tests PAP-style `radtest` credentials.
- Admin passwords and user passwords are hashed in application tables.
- `radcheck` stores RADIUS-compatible test credentials for standard tooling compatibility.
- RADIUS client records are stored in PostgreSQL; Phase 1 NAS creation defaults to the generated environment shared secret so manual `radtest` works immediately.

## 21. Parked features
Coinslot, vendo device, SMS, online payment, self-registration, dynamic VLAN, controller API automation, WireGuard automation, tunnel automation, production captive portal flow, advanced staff roles, and HA clustering are parked until the owner explicitly requests them.

## 22. User special requests
- The system must be installable using one command on Ubuntu.
- The system must be updateable using one command.
- Docker may be used internally, but the user should not need to manually run Docker commands.
- Project context must always be updated.
- Admin account must be created during install.
- README.txt must exist in GitHub showing one-line install and one-line update commands.
- GitHub details, branch strategy, and deployment workflow must be documented in PROJECT_CONTEXT.md.
- There must be separate production and staging local deployments.
- Production must track master branch.
- Staging must track staging branch.
- Phase 1 priority is source of truth and manual RADIUS testing.

## 23. Development rules for future AI agents
- Read `/PROJECT_CONTEXT.md` before making changes.
- Update `/PROJECT_CONTEXT.md` when architecture, deployment, features, commands, branches, workflows, or decisions change.
- Preserve production/staging isolation.
- Do not implement parked features unless the project owner explicitly asks.
- Keep Phase 1 focused on Source of Truth + Manual RADIUS Test MVP.
- Do not commit generated secrets, `.env` files, SSH keys, database dumps, or build artifacts.
- Do not add arbitrary remote shell execution for Omada; only predefined install/status/service actions are allowed.

## Project Direction Update — Captive Portal Priority

The project priority has shifted from customer WPA2-Enterprise username/password WiFi login to a PisoWiFi-style Captive Portal flow.

Direction:
- WPA2-Enterprise testing is now parked as an advanced/lab feature.
- Captive Portal is now the main customer access direction.
- Main customer experience should be open SSID + portal + voucher.
- Customer-facing login should not ask for WPA2 identity, anonymous identity, or WPA2 password.
- Voucher system is the next major feature.

Architecture:
- Omada Controller remains useful for AP adoption, SSID configuration, WiFi profile management, and AP monitoring.
- FreeRADIUS and accounting remain useful as the backend session/accounting foundation and should not be deleted.
- PostgreSQL remains the source of truth.
- 3JCentralPisowifi remains the source of truth for customers, vouchers, wallets, sessions, accounting, single-device policy, and access decisions.
- Omada must not store WiFi customer accounts or voucher logic.

Implementation notes:
- Existing Phase 1C RADIUS authentication/accounting tests must remain working.
- Phase 1D/1E Omada API and WPA2-Enterprise tools should remain available under Advanced Tools for engineering validation.
- Admin Portal main navigation should emphasize Dashboard, Customers / Accounts, Vouchers, Wallet, Sessions, Captive Portal, Network, Omada Controller, System Settings, and Logs.
- Vouchers and Captive Portal pages are currently placeholders until the next implementation phase.

## Phase 2A — Voucher Management System

Voucher Management is now the next core feature for the Captive Portal direction.

Scope:
- Admins can create single vouchers and bulk voucher batches.
- Vouchers add access/time to customer wallets when redeemed.
- Voucher types are `TIME_BASED`, `DATE_BASED`, and `UNLIMITED`.
- Voucher statuses are `UNUSED`, `USED`, `EXPIRED`, `DISABLED`, and `VOIDED`.
- Voucher redemption records success/failure history in PostgreSQL.
- Admin Test Redeem simulates future captive portal redemption.

Architecture rules:
- Captive Portal will later redeem vouchers.
- Vouchers do not replace PostgreSQL wallet/session source of truth.
- Voucher redemption credits wallet/access and creates a `transactions` row with `source = VOUCHER`.
- Wallets remain the source of truth for time remaining, valid-until, and unlimited access.
- Sessions/accounting remain the source of truth for active usage.
- Existing RADIUS/auth/accounting remains active and must not be removed.

Not included in Phase 2A:
- Actual captive portal enforcement.
- Public customer portal redemption UI.
- Omada external portal integration.
- Payments, SMS, coinslot, or vendo integration.

## Phase 2B — Client Portal / Voucher Redemption Page

The client portal is the customer-facing page for voucher entry.

Scope:
- Public `/portal` page loads without admin login.
- Customers can manually test voucher redemption at `/portal`.
- Public APIs are limited to portal settings, portal session creation/update, voucher redemption, and portal status.
- Voucher redemption uses the existing voucher service and credits wallet/access through PostgreSQL.
- Portal sessions and portal events are stored for future captive portal integration.
- Admin -> Captive Portal manages basic portal branding and shows recent portal events/redemptions.

Architecture notes:
- Customers will later be redirected here by Omada or MikroTik captive portal.
- Captive portal enforcement is still not implemented in Phase 2B.
- Browser JavaScript cannot reliably detect device MAC address by itself.
- Device identifiers such as `client_mac`, `client_ip`, `ssid`, `site`, `gateway`, and `nas_id` are captured from optional query parameters for future Omada/MikroTik integration.
- If no parameters exist, the portal creates a browser-based temporary portal session ID and marks the source as `MANUAL_TEST`.
- Phase 2C is expected to integrate portal redirect/enforcement.

Not included:
- Omada external portal automation.
- MikroTik hotspot integration.
- Payments, SMS, coinslot, vendo, or production rollout automation.

## 24. Changelog section
- 2026-04-30: Added Phase 1D External Omada Controller Server setup page, encrypted Omada/SSH settings, controlled SSH install/manage endpoints, Omada install logs, NAS helper, RADIUS copy settings, real AP checklist, and Omada setup documentation.
- 2026-04-30: Added Omada install progress tracking with background install jobs, current step labels, and Admin Portal progress bar polling.
- 2026-04-28: Completed Phase 1C real RADIUS accounting with Start/Interim/Stop packet tests, session tracking, wallet deduction, accounting logs, improved Sessions and Wallet UI, and updated documentation.
- 2026-04-28: Reworked Real FreeRADIUS Packet Test to use a fixed Internal Docker RADIUS Test Client, added reject diagnostic reasons, technical details, troubleshooting suggestions, and documented separate simulated/internal/external RADIUS test flows.
- 2026-04-28: Fixed Real FreeRADIUS Packet Test defaults so the Shared Secret uses the API-container/Docker-network FreeRADIUS client secret instead of the selected router/AP NAS record secret.
- 2026-04-28: Clarified the Real FreeRADIUS Packet Test NAS client source as API container / Docker network in the admin UI.
- 2026-04-28: Added a Real FreeRADIUS Packet Test section that sends an actual UDP RADIUS Access-Request and reports Access-Accept, Access-Reject, No Reply, Wrong Secret, or Database Error results.
- 2026-04-28: Changed the RADIUS Test Guide NAS / Router / AP IP field to a dropdown populated from existing NAS client records.
- 2026-04-28: Added an admin portal RADIUS Test Guide simulation tool that tests Phase 1 RADIUS accept/reject rules from the browser and logs results to `radius_auth_logs`.
- 2026-04-28: Added NAS / Router / AP Client edit support with an Actions column in the admin table and a backend PATCH flow that synchronizes app NAS records with FreeRADIUS `nas` entries.
- 2026-04-26: Updated NAS page read-more control to a seamless underlined text link and added visible shared secret creation/listing with auto-generate support.
- 2026-04-26: Added short and expandable long explanatory guidance to the NAS / Router / AP Clients page.
- 2026-04-26: Removed the User Detail page from navigation, added URL-aware Admin Portal routes under `/admin/<page>`, and rebuilt the Users page with Optical-style tabs, search, table layout, pagination, and Create/Manage user modals.
- 2026-04-26: Reduced expanded side panel width by 40px and reduced the company logo max display width by 24px.
- 2026-04-26: Added top navigation title/badge click behavior to collapse and expand the side navigation, with collapsed mode shrinking the side panel and showing icons only; removed the Phase 1 hero section from the dashboard.
- 2026-04-26: Adjusted Tabler sidebar sizing to avoid sidebar scrollbars, fixed active nav highlight clipping, and aligned top navigation/content spacing to a 48px left offset from the side panel.
- 2026-04-26: Added Branding logo uploads, browser favicon upload, environment-isolated uploads Docker volume, CPU/RAM/DISK/UPTIME top metrics, wider sidebar, page-specific top badge icons, and click-only profile dropdown behavior.
- 2026-04-26: Installed real Tabler dependencies (`@tabler/core`, `@tabler/icons-react`), removed the previous icon/template dependency path, and rebuilt the Admin Portal on Tabler classes while preserving new 3JCentralPisowifi naming.
- 2026-04-26: Removed the previous third-party admin template direction, adopted the owner's old-system UI language without old naming, and added common profile, password, access, backup, danger, and system update surfaces.
- 2026-04-26: Restyled the Admin Portal to follow a template-style dashboard layout while preserving the Phase 1 API-backed workflows.
- 2026-04-25: Created Phase 1 foundation with Docker Compose production/staging overlays, FastAPI API, React admin portal, PostgreSQL schema, FreeRADIUS helper scripts, installer/updater scripts, and documentation.

## Phase 1E — Omada RADIUS Profile Automation
Phase 1E adds optional Omada API automation on top of the operational external Omada Controller server.

Purpose:
- Connect 3JCentralPisowifi to the Omada Controller API at `https://192.168.50.71:8043`.
- Save Omada API settings and encrypted Omada password separately from SSH install credentials.
- Test Omada API login, detect Omada sites, and save the selected site.
- Build a 3JCentralPisowifi RADIUS profile using staging or production values.
- Create the matching NAS / Router / AP Client entry inside 3JCentralPisowifi.
- Attempt to create the Omada-side RADIUS profile and test WPA2-Enterprise SSID.
- Always show manual fallback instructions if Omada API endpoints differ or automation fails.

Environment:
- 3JCentralPisowifi host: `192.168.50.70`.
- Omada host: `192.168.50.71`.
- Omada remains external and optional.
- RADIUS staging ports: authentication `11812/udp`, accounting `11813/udp`.
- RADIUS production ports: authentication `1812/udp`, accounting `1813/udp`.

Architecture rules:
- 3JCentralPisowifi remains the source of truth for users, wallets, sessions, balances, accounting, and access decisions.
- Omada only manages APs, WLAN/SSID settings, RADIUS profiles, and AP monitoring.
- Matching NAS client entries must exist in 3JCentralPisowifi using the same shared secret configured in Omada.
- Omada API behavior may vary by controller version; automation must fail gracefully and show manual values.
- This phase does not add vouchers, captive portal, SMS, payments, WireGuard, AP mass deployment, or production rollout automation.

New data areas:
- `omada_api_settings` stores API URL, username, TLS mode, controller/site identifiers, and encrypted password.
- `omada_radius_profiles` stores local profile builder values, encrypted shared secret, Omada profile ID if returned, and status.
- `omada_test_ssids` stores test WPA2-Enterprise SSID attempts and Omada WLAN ID if returned.
- `omada_automation_logs` stores sanitized request/response summaries for API login, site detection, NAS creation, RADIUS profile creation, and SSID creation.

Changelog:
- 2026-04-30: Added Phase 1E Omada API settings, site detection, matching NAS creation, RADIUS profile automation adapter, test WPA2-Enterprise SSID automation adapter, sanitized automation logs, and manual fallback instructions.
- 2026-04-30: Updated project direction to Captive Portal + Voucher priority, parked WPA2-Enterprise as an advanced/lab feature, cleaned Admin Portal navigation, added Vouchers and Captive Portal placeholders, moved RADIUS lab tools under Network/Advanced, and added Omada Portal Setup preparation UI.
- 2026-04-30: Began Phase 2A Voucher Management with voucher batches, voucher records, redemption logs, wallet-credit redemption rules, admin voucher UI, CSV export, and admin test redemption.
- 2026-04-30: Added Phase 2B Client Portal with public `/portal`, portal session/event tracking, client voucher redemption source, portal branding settings, and admin portal monitoring panels.

## Phase 2C — Omada Captive Portal Integration
Phase 2C makes Captive Portal the primary customer access path for Omada test deployments.

Purpose:
- Customers connect to the open SSID configured in APs Deployment -> Sites -> Configurations -> SSID and Security.
- Omada redirects customers to `http://192.168.50.70:8080/portal` for staging.
- 3JCentralPisowifi validates vouchers and remains the access decision system.
- After a valid voucher is submitted from an Omada-sourced portal session, 3JCentralPisowifi attempts Omada client authorization through the Omada API.
- Omada manages APs, SSIDs, captive portal redirect, and device authorization only.

Architecture rules:
- 3JCentralPisowifi remains the source of truth for vouchers, customers/accounts, wallets, portal sessions, access decisions, and logs.
- Omada is not the source of truth and does not store customer wallet/account logic.
- Portal sessions now capture Omada-style query parameters including `clientMac`, `client_mac`, `apMac`, `ap_mac`, `gatewayMac`, `vid`, `site`, `ssid`, `redirectUrl`, `token`, and `authToken`.
- Omada API behavior may differ by controller version. Automation must fail gracefully and manual setup instructions must always remain visible.
- This phase tests one SSID and one AP first. It does not include payment, SMS, coinslot, vendo, WireGuard, or production rollout automation.
- AP identity is tracked by normalized MAC address and must survive site deletion or AP movement between Omada sites. Deleting a site must not erase AP deployment history, custom AP names, or configuration history from 3JCentralPisowifi. If an AP later appears in a new site, the UI/data model should show both previous and current site associations so operators can understand where that AP was used before and where it is connected now.
- Site deletion uses a local deletion tombstone for Omada-detected sites. If Omada Controller rejects or does not support remote site deletion through its API, 3JCentralPisowifi still hides the site locally, preserves AP history, and reports the Omada limitation as a warning instead of blocking the operator.
- AP map placement is stored on `ap_deployments` using manually captured latitude/longitude fields. The AP identity remains the normalized MAC plus deployment history; mapping an AP does not replace Omada as the AP runtime/status source.

Voucher/authorization behavior:
- Manual `/portal` testing still redeems vouchers without Omada authorization and marks the session as manual test.
- For Omada-sourced portal sessions, the system validates the voucher first, attempts Omada authorization, and only consumes/credits the voucher after Omada authorization succeeds.
- If Omada authorization fails, the voucher is not marked used and the customer sees an operator-friendly authorization failure message.

New data areas:
- `portal_sessions` stores normalized Omada context, raw query parameters, authorization status, authorization error, and access timestamps.
- `omada_portal_authorizations` stores sanitized Omada authorization attempts, masked device identifiers in admin views, and success/failure details.
- `captive_portal_settings` stores portal mode, portal URLs, selected Omada site, default unlimited authorization duration, and Captive Portal Sanity Check progress. The active SSID value is derived from AP Deployment configuration, not edited in Captive Portal.
- `captive_portal_test_logs` stores sanitized setup/test automation results.

Changelog:
- 2026-05-01: Added Phase 2C Omada captive portal settings, Omada open SSID/external portal automation adapters, Omada client authorization attempt after voucher validation, portal query parameter capture, authorization logs, portal sessions table view, and manual Omada setup guide.
- 2026-05-04: Renamed the main Customers / Accounts navigation surface to Connected Devices. The page now focuses on active/inactive AP client detection using Omada client data when available, with local RADIUS accounting and portal session records as fallback sources. Customer/account management is parked while voucher-first access remains the priority.
- 2026-05-04: Added Sites Deployments admin page and `site_deployments` table for locally tracking planned Omada-managed WiFi locations. The first version supports listing sites and adding sites from an Add Sites modal, with optional Omada Site ID linkage reserved for later controller automation.
- 2026-05-04: Added Location Management with reusable addresses, municipality/barangay fields, latitude/longitude storage, optional address search/geocoding, and delete management controls. Sites Deployments now hides deployment status and focuses on site address, municipality, barangay, and coordinates.
- 2026-05-04: Refined the Add Site modal so site address entry comes only from saved Location Management records. The modal now shows a Location dropdown with a `+ Add Location` redirect and an OpenStreetMap preview for the selected saved location.

## Captive Portal Direction Update — MikroTik Gateway Priority

The recommended production captive portal path is now MikroTik as the gateway/enforcement layer and Omada as AP/SSID management only.

Architecture direction:
- Omada continues to manage TP-Link AP adoption, SSIDs, AP monitoring, radio settings, and VLAN tagging.
- MikroTik should handle captive portal redirect, internet allow/block enforcement, RADIUS accounting, per-substation gateway control, queues/rate limits, routing, and future WireGuard tunnel integration.
- 3JCentralPisowifi remains the source of truth for vouchers, wallets, portal sessions, access decisions, logs, and future tunnel-aware central management.
- Multiple MikroTik routers are expected because future substations will have their own gateway/router.
- Admin -> Captive Portal now uses `Portal` as the first tab instead of `Overview`.
- MikroTik infrastructure management now lives under `Admin -> Network -> MikroTik` for storing RouterOS API records, running read-only scans, planning stations, and testing API login/reachability.
- The Network `MikroTik` workspace has nested `Configuration` and `Add Router` tabs. Router details are managed under `Add Router`; station plans and scan access are handled under `Configuration`.
- MikroTik configuration must be station-first. The active UI should model a full VLAN path across root gateway plus CRS/switch/transport routers before any RouterOS write action is offered.
- Every future MikroTik configuration push must be reviewed first. The UI must show the exact planned RouterOS configuration and only allow applying an explicitly reviewed step. Do not push hidden configuration changes or show raw summary dumps as the main review surface.
- Captive Portal must not maintain a separate editable Open SSID field. The SSID source is APs Deployment -> Sites -> Configurations -> SSID and Security. Captive Portal should display/use that SSID configuration for portal setup and MikroTik review/apply.
- Admin -> Captive Portal no longer exposes separate `Omada Integration` or `MikroTik` setup tabs. Omada-specific AP, SSID, controller, and lab automation belongs in Omada Controller and APs Deployment; MikroTik gateway setup belongs in Network; Captive Portal focuses on portal settings/design, portal sessions, authorization logs, and operator guidance.
- Admin -> Captive Portal uses a `Sanity Check` tab instead of `Test Flow`. The tab should show automatic readiness checks where system data is available, manual operator checks for field testing, and clear `Coming soon` placeholders for incomplete features such as full MikroTik HotSpot write automation, payments, SMS, and coinslot/vendo integration.
- The MikroTik configuration review must not show a `Set captive portal mode` step. Portal mode is no longer a user-facing setting; MikroTik is the assumed gateway path for Captive Portal.
- The old single-router `Start Setup`, `Check Config`, and `Remove Config` controls are no longer part of the main Configuration table. Station planning replaces that operator workflow.
- The station modal must treat the operator as non-expert: first add routers to the chain, then click each vertical router tab to fill bridge/tagged-port values, then set root station network values.
- The Add Station modal should be organized as an operator checklist: name the station, build the router chain, fill detected router bridge/tagged-port fields, fill root gateway network fields, then review the generated plan. Field-level info icons should explain each value in plain language.
- Each station has one customer VLAN ID. The first router creates the managed MikroTik VLAN interface and uses it for captive portal gateway/DHCP/client traffic. Downstream routers carry that same VLAN as tagged trunk configuration. The same VLAN ID must be configured on the AP SSID/site VLAN so AP customer traffic reaches the correct MikroTik captive portal network.
- MikroTik automation must use the System Display Name as the identifier for system-owned RouterOS objects where possible. New HotSpot profile/server and walled-garden records must include clear managed comments so operators can distinguish 3JCentralPisowifi-created configuration from existing MikroTik configuration.
- MikroTik setup must create only system-owned RouterOS objects from the values entered in Add Router. It must not silently reuse existing RouterOS pools, subnets, profiles, speed-plan configuration, management interfaces, or WAN settings.
- Future remove/apply phases must target only system-generated names and managed comments, and must not delete unrelated existing MikroTik configuration.
- MikroTik API passwords are encrypted at rest and never returned to the browser.
- A dedicated full/write RouterOS API account is required for MikroTik captive portal automation because the system must configure HotSpot, walled garden, client authorization, and portal enforcement. Do not use the main MikroTik admin account; create a dedicated automation account with only the required RouterOS policies.
- Portal design can now be edited through `/admin/captive-portal/editor` using HTML/CSS placeholders. The required `{{voucher_form}}` placeholder must remain in the template so voucher redemption still works.
- This update implements early MikroTik setup steps for API validation, HotSpot profile/server creation, and walled garden portal access. It does not yet implement full MikroTik HotSpot client authorization, generated login page upload, payments, SMS, coinslot/vendo, or WireGuard automation.

New data areas:
- `mikrotik_routers` stores multiple MikroTik gateway/API connection settings, HotSpot setup fields, API test status, and per-step configuration progress.
- `portal_design_templates` stores the editable customer portal HTML/CSS template.
- 2026-05-04: Removed manual Omada Site ID input from Add Site. New site records now always attempt Omada site creation first, then store the Omada-returned site ID automatically. Added Application Scenario, Country / Region, and Time Zone fields for Omada site creation.
- 2026-05-04: Moved Omada site Country / Region and Time Zone defaults to System Settings -> General. Add Site now retrieves Application Scenario options from Omada `/api/v2/scenarios`, including custom scenarios configured in Omada Software Controller.
- 2026-05-07: Added a Sites delete confirmation modal that shows affected APs, connected AP count, and total connected clients before deleting a site. The modal explicitly warns that AP data remains in the system, APs may disconnect after Omada site deletion, and future AP re-adoption should continue from the saved AP identity/history.
- 2026-05-07: Added `site_deployment_tombstones` so Omada-detected sites can be removed from the local Sites Deployments view even when the Omada Controller API cannot delete the remote site using known endpoint paths.
- 2026-05-08: Added APs Deployment -> Long Lat with a full-bleed OpenStreetMap tile view, mapped/unmapped AP panel, drag-and-drop AP coordinate capture, best-effort AP ping status, pulsing AP markers colored by client/error state, and a right-side AP details panel with street-view embed for mapped APs.
- 2026-05-11: Added System Settings -> OPENAI tab copied from the `threejmain` project. The tab stores OpenAI API settings server-side, keeps the API key encrypted in PostgreSQL `app_settings` under key `openai`, exposes only masked key metadata to the browser, supports model and reasoning-effort selection, optional organization/project IDs, model pricing reference, and a live Responses API test through `/api/system-settings/openai/test`.

## System Settings — OPENAI Integration (Retired)

Retired: System Settings no longer shows an `OPENAI` tab. The notes below are historical only and are superseded by `AI Network Assistant Removal — Manual MikroTik Setup Refocus`.

Behavior:
- Admins can save an OpenAI API key, selected model, reasoning effort, optional organization ID, and optional project ID.
- The API key is encrypted at rest using the existing application secret encryption helper and stored in PostgreSQL `app_settings` under the `openai` key.
- API responses never return the full API key. The frontend only receives whether a key is configured and a masked key hint.
- Admins can clear the saved API key.
- Admins can run a live OpenAI Responses API test from the tab.
- The test sends the selected model, selected reasoning effort, prompt, and max output token limit.
- Test audit logs store model, reasoning effort, latency, and sanitized usage only. They must not store API keys.
- The tab includes model summary cards and a pricing/reference table copied from the `threejmain` implementation.

Endpoints:
- `GET /api/system-settings/openai`
- `PATCH /api/system-settings/openai`
- `POST /api/system-settings/openai/test`

Data:
- Migration `029_openai_system_settings.sql` seeds the default OpenAI settings row.
- OpenAI settings are separate from the normal `system` settings JSON so General/Branding saves do not overwrite AI configuration.

## Phase MT-1 — MikroTik Preflight Scanner + Safe Deployment Foundation

Purpose:
- MT-1 originally added a read-only MikroTik preflight scanner. The current UI surfaces scan controls under Admin -> Network -> MikroTik -> Configuration instead of a standalone Preflight Scanner tab.
- The scanner prepares safe captive portal deployment by discovering existing RouterOS configuration and identifying risks before any configuration is generated or applied.
- The scanner must work generically for other ISPs and must not assume the current 3J topology.

Safety rules:
- MT-1 does not apply MikroTik configuration.
- MT-1 does not generate final RouterOS apply commands.
- MikroTik configuration must follow this safety model: scan -> policy/risk engine -> user confirmation -> exact command preview -> step-by-step apply.
- AI/OpenAI is no longer part of the active MikroTik setup workflow.

Scanner coverage:
- Read-only RouterOS API print calls scan identity, resources, interfaces, bridges, VLANs, IP addresses/subnets, pools, DHCP, HotSpot, NAT/firewall summaries, routes, OSPF indicators, RADIUS entries, WireGuard indicators, and PPPoE servers where supported by the RouterOS version.
- Unsupported RouterOS paths are stored as warnings and do not fail the full scan.
- Findings are stored in `mikrotik_preflight_scans` and `mikrotik_preflight_findings`.
- Scanner output includes router identity/model/version, role guess, recommended deployment mode, risk level, findings, conflicts, recommendations, and sanitized snapshot data.

Risk model:
- VLAN conflicts, subnet overlaps, pool overlaps, DHCP conflicts, existing HotSpot, PPPoE, OSPF/routing sensitivity, WireGuard sensitivity, public/core router indicators, and CRS/VLAN-switching risks are detected conservatively.
- Role guesses are advisory: `HOTSPOT_GATEWAY_CANDIDATE`, `PPPoE_ACCESS_CONCENTRATOR`, `CORE_ROUTER_READ_ONLY`, `SWITCH_TRUNK_HELPER`, `ISP_BACKUP_TRANSPORT`, or `UNKNOWN_NEEDS_REVIEW`.
- Deployment recommendations are advisory: `HotSpot Gateway`, `VLAN Trunk Helper`, `Read-only / Core Router`, or `ISP Backup / Transport Router`.

AI behavior:
- Retired. The scanner no longer exposes AI Explain or OpenAI-dependent actions.
- The scanner remains fully usable for deterministic validation without AI.

Future phases:
- MT-2 Safe Deployment Mode / Policy Engine
- MT-4 RouterOS Command Preview
- MT-5 Step-by-step Apply
- MT-6 Pilot Router Validation

## Phase MT-2 — Multi-Router Preflight Summary + Safe Deployment Mode

Purpose:
- MT-2 extends MikroTik preflight scanning to work across all saved MikroTik routers.
- Historical MT-2 UI had a `Summary` tab plus one tab per MikroTik router. The current UI removed that standalone tab and shows scan status/actions in the Configuration table.
- `Prescan All Routers` runs read-only RouterOS API scans across all configured MikroTik routers with safe limited concurrency and stores one scan batch plus one scan result per router.
- The Summary tab aggregates scan status, reachability, risk, role guesses, deployment readiness, VLAN/subnet conflict signals, missing scans, failed routers, high-risk routers, HotSpot candidates, read-only/core routers, VLAN trunk helpers, and rollout-order guidance.

Safe deployment mode:
- MT-2 adds a deterministic Safe Deployment Mode / Policy Engine.
- Deployment modes are `HOTSPOT_GATEWAY`, `VLAN_TRUNK_HELPER`, `READ_ONLY_CORE`, `ISP_BACKUP_TRANSPORT`, and `UNKNOWN_NEEDS_REVIEW`.
- Router role and deployment-mode confirmation fields are no longer shown in the active operator UI.
- Network -> MikroTik -> Add Router captures RouterOS API connection details only. Dedicated captive portal network fields such as customer VLAN, parent interface, client subnet, gateway IP, DHCP pool, DNS, and WAN/NAT are not required when adding a router; they are only required later when a router is confirmed as `HOTSPOT_GATEWAY`.
- HotSpot setup is blocked or strongly warned when policy detects no scan, core/router risk, CRS/switch risk, PPPoE/OSPF/WireGuard sensitivity, VLAN conflicts, subnet conflicts, pool conflicts, missing required HotSpot fields, or NAT without a WAN interface.
- Expert override can record risk acceptance, but it does not apply MikroTik configuration and must not bypass hard blockers such as VLAN/subnet/pool overlap or missing required fields.

Safety:
- MT-2 still does not apply RouterOS configuration.
- MT-2 disables RouterOS write apply paths; command preview/apply remains for later phases.
- AI/OpenAI is no longer part of the active setup workflow.

Future phases:
- MT-4 RouterOS Command Preview
- MT-5 Step-by-step Apply / Managed Rollback
- MT-6 Pilot Router Validation

## Phase MT-2.1 — Preflight Scanner Stabilization + Router Role Tuning

Purpose:
- MT-2.1 stabilizes the read-only MikroTik scanner and tunes router classification after multi-router prescan exposed failed scans and overly conservative read-only/core recommendations.
- The scanner now sanitizes RouterOS text before database storage. Null bytes, invalid surrogate characters, and non-printable control characters are removed or replaced before JSON serialization and PostgreSQL insert/update.
- Sanitization applies to RouterOS response strings, interface names, comments, routes, firewall/NAT comments, DHCP/bridge/VLAN fields, findings, conflicts, recommendations, raw snapshots, sanitized snapshots, and AI-ready summaries.
- Failed scans caused by invalid RouterOS text should be prevented; if a scan still fails, the failure record is stored with clean text and the UI can direct the operator to retry.

Role tuning:
- PPPoE access concentrators are no longer automatically recommended as read-only/core.
- PPPoE AC routers remain high risk, but may be possible HotSpot Gateway candidates only with a new dedicated VLAN/subnet/interface and explicit operator review.
- Core routers remain read-only/core, but the classifier now requires multiple strong core indicators instead of treating every PPPoE/public-IP router as core.
- CRS/switch/trunk devices are recommended as `VLAN_TRUNK_HELPER`, not HotSpot gateways.
- Failed or incomplete scans remain `UNKNOWN_NEEDS_REVIEW` and are blocked until successful re-scan or manual review.

UI:
- Current Configuration table shows latest scan state per router and provides `Run Scan` and `View Scan Result` actions. `View Scan Result` opens `/admin/network/mikrotik/scan-result?router_id=...` in a new browser tab/page.
- The scan-result page uses a vertical section navigator with large icon badges for Overview, Conflicts, VLANs, Subnets, Pools, DHCP, HotSpot, and Sensitive indicators.
- The Overview section now contains router role explanation, findings by category, and scan history so operators can read the main scan context in one place.
- The active scan-result view no longer shows `Policy Decision`, `Deployment Mode Confirmation`, or expert override cards.

Safety:
- MT-2.1 still does not apply RouterOS configuration.
- RouterOS write apply remains disabled until a future command preview/apply phase.

## Phase MT-3 — AI Network Assistant + Pilot Deployment Planner (Retired)

Retired: the AI Network Assistant is no longer part of the active product workflow. This section is historical only and is superseded by `AI Network Assistant Removal — Manual MikroTik Setup Refocus`.

Purpose:
- MT-3 adds an `AI Network Assistant` tab under `Admin -> Captive Portal -> MikroTik`.
- The assistant helps non-technical operators understand sanitized multi-router preflight results, choose a safer first pilot router, answer missing deployment questions, and create a draft deployment plan.
- AI is advisory only. It can explain scan results, explain risk, ask clarifying questions, recommend a pilot router, and propose a structured draft plan.
- AI cannot apply MikroTik configuration, cannot generate final RouterOS apply commands, cannot bypass the deterministic policy engine, and cannot approve unsafe setup.

Safety boundary:
- MT-3 still does not perform RouterOS write actions.
- MT-3 does not generate final RouterOS command previews. MT-4 is the future command-preview phase.
- AI uses sanitized preflight summary, selected-router scan/policy data, saved planning answers, role reasoning, deployment reasoning, and pilot suitability.
- Secrets are redacted before AI use, including MikroTik passwords, API secrets, RADIUS secrets, WireGuard private keys, certificates/private keys, tokens, and private credentials.
- Draft deployment plans are stored as structured JSON in `mikrotik_draft_deployment_plans`.
- Draft plans must pass deterministic backend validation before they can be marked `READY_FOR_COMMAND_PREVIEW`.
- Validation checks VLAN conflicts, subnet overlap, pool overlap, missing required fields, protected PPPoE/OSPF/WireGuard/core objects, read-only/core mode, CRS/switch HotSpot blocks, NAT/WAN safety, and command-content leakage.
- Blocked plans cannot proceed to MT-4.

Data model:
- `mikrotik_ai_conversations` stores admin AI sessions.
- `mikrotik_ai_messages` stores user/assistant messages with sanitized context metadata.
- `mikrotik_deployment_questions` stores per-router answers needed before future command preview.
- `mikrotik_draft_deployment_plans` stores AI-generated draft plans and deterministic validation results.

Future phase:
- MT-4 will generate exact RouterOS command previews only after a draft plan passes or warns through policy validation.
- MT-5 will handle step-by-step apply/managed rollback after explicit user approval.

## Phase MT-3.1 — Pilot Selection + Planning Readiness (Retired)

Retired: AI pilot/planning readiness UI is no longer active. This section is historical only and is superseded by `AI Network Assistant Removal — Manual MikroTik Setup Refocus`.

Purpose:
- MT-3.1 focuses on the main `Admin -> Captive Portal -> MikroTik -> AI Network Assistant` page.
- AI remains advisory only. It can run a small smoke test, explain scan/planning status, and help the operator answer planning questions.
- RouterOS commands are still not generated or applied in MT-3.1.
- One pilot MikroTik router must be selected before MT-4 command preview readiness.
- Pilot selection is saved separately and does not change any MikroTik router configuration.
- Core/read-only routers cannot be selected as a pilot without expert override, and CRS/switch trunk helpers cannot be selected as HotSpot Gateway pilots.
- Missing planning questions are grouped by router role, AP/customer VLAN, client IP network, HotSpot/portal, NAT/internet, and protected routers.
- Required planning answers must validate before draft-plan generation readiness: numeric VLAN, valid CIDR, gateway inside CIDR, DHCP pool inside CIDR, DNS IP list, NAT decision, and WAN interface when NAT is enabled.
- Historical draft plan generation was gated by readiness such as successful preflight scan, selected pilot router, complete planning answers, no hard policy blockers, and OpenAI configured when AI generation was used.
- Draft plans must pass deterministic safety validation before MT-4 readiness.

Safety boundary:
- AI smoke test sends sanitized summary only and asks for a short paragraph, not RouterOS commands.
- If AI returns RouterOS-like command text, the system warns that command previews are not allowed until MT-4.
- No RouterOS write/apply occurs in MT-3.1.

## Phase MT-3.2 — AI Suggested Planning Answers + Auto-Derived Network Fields (Retired)

Retired: AI suggested planning answers are no longer active. This section is historical only and is superseded by `AI Network Assistant Removal — Manual MikroTik Setup Refocus`.

Purpose:
- MT-3.2 improves `Admin -> Captive Portal -> MikroTik -> AI Network Assistant` planning so operators do not manually fill every missing question from scratch.
- AI can suggest missing planning answers from sanitized preflight scan data, selected router policy data, existing operator answers, and scanned interface candidates.
- AI suggestions are draft suggestions only. They do not apply MikroTik configuration, do not generate RouterOS command previews, and do not bypass policy validation.
- Each planning question now has a lifecycle status: `EMPTY`, `AI_SUGGESTED`, `USER_EDITED`, `APPROVED`, `LOCKED`, or `REJECTED`.
- AI suggestions now auto-fill the planning text fields when the field is empty or already AI-suggested. A bot icon marks values filled by AI.
- If the operator manually edits an AI-filled field, the bot marker is removed and the status changes to `USER_EDITED`.
- Per-field approve/reject buttons are no longer used in the Missing Questions modal. The operator reviews or edits the values, uses `Clear` to remove an AI-filled answer when needed, and uses `Save All` as the review/approval step.
- Locked values are not overwritten by future AI suggestions or deterministic derivation.

Deterministic derivation:
- Dependent network fields are calculated by backend and previewed in the UI.
- `client_network_cidr` derives network address, broadcast address, first usable IP, last usable IP, gateway IP, DHCP pool start/end, and usable host count.
- Default derivation uses first usable IP as gateway, network + 10 as pool start where valid, and last usable IP as pool end.
- Changing CIDR auto-updates gateway and DHCP pool unless those fields are locked.
- Changing customer VLAN ID can auto-suggest the system-owned VLAN interface name.
- Portal URL and HotSpot DNS name can be auto-filled from system defaults when blank.

Validation:
- Backend validation checks IPv4 CIDR format, CIDR size, gateway inside CIDR, gateway not network/broadcast, pool inside CIDR, pool ordering, pool excluding gateway, DNS IP list, NAT/WAN requirements, VLAN conflicts, subnet overlaps, and pool overlaps.
- Draft plan readiness remains locked until required answers are approved/locked and validation passes.
- MT-4 command preview remains locked until approved answers pass deterministic safety validation.

Safety:
- OpenAI receives sanitized planning context only.
- AI must not invent interface names not found in scanned interface candidates. If uncertain, it should return `null` and require user review.
- AI must not suggest touching PPPoE, OSPF, WireGuard, core routes, production bridges, or non-system-managed objects.
- No RouterOS configuration is applied in MT-3.2.

UI update:
- `Admin -> Captive Portal -> MikroTik -> AI Network Assistant` now opens on an `Overview` workspace.
- The Overview shows all MikroTik routers, pilot status, role/risk/pilot suitability, KPIs, AI health, missing-question status, and latest draft-plan status.
- AI health/smoke test, pilot router selection, missing questions, and draft deployment plan are modal workflows launched from the Overview.
- The AI chat is a right-side floating panel opened from `Chat with AI`, keeping the overview table visible while the operator asks questions.
- The visible `Selected Router` dropdown was removed from the Overview because router choice now happens from table action buttons or inside each modal workflow.
- Missing Questions are explicitly pilot-router-bound for now. The standalone Overview Missing Questions card was removed; only the selected pilot router row shows question progress such as `7/12` and enables `Questions` / `Draft` actions. Non-pilot routers show `Pilot only`.
- When a pilot router is selected, planning answers/suggestions on non-pilot routers are cleared so operators do not accidentally prepare multiple routers before MT-4.
- `Save All` must respect intentionally cleared HotSpot DNS and Portal URL fields. Defaults such as `wifi.3j.3jportal.test` and `http://192.168.50.70:8080/portal` should come from suggestion/default derivation workflows, not be silently re-added after the operator clears and saves.
- The Missing Questions validation warning (`Fix these answers`) is collapsible so large validation output can be hidden while editing.
- These UI changes are workflow-only. They do not generate RouterOS command previews and do not apply MikroTik configuration.

## Phase MT-3.3 — AI Planning Policy Fix + VLAN Path Planner (Retired)

Retired: AI planning policy and Missing Questions/VLAN Path Planner workflows are no longer active. This section is historical only and is superseded by `AI Network Assistant Removal — Manual MikroTik Setup Refocus`.

Purpose:
- MT-3.3 corrects MikroTik AI planning policy before MT-4 command preview.
- PPPoE access concentrators are high-risk but valid HotSpot Gateway candidates when the captive portal uses a new dedicated VLAN/subnet and existing PPPoE services remain untouched.
- PPPoE AC routers must not automatically become `READ_ONLY_CORE`; they should be explained as possible with caution unless strong core-only indicators exist.
- Router role and deployment mode are separate: role describes what the MikroTik currently does, while deployment mode describes what 3JCentralPisowifi plans to do on it.

VLAN path planning:
- AI must not guess the AP/customer VLAN parent interface without evidence.
- The AP/customer VLAN may pass through MikroTik -> CRS -> OLT -> ONU/AP before reaching Omada APs.
- The Missing Questions modal now starts with a step-by-step VLAN Path Planner before the remaining planning questions.
- The Missing Questions modal uses two tabs: Phase 1 for pilot/router role, customer VLAN, and VLAN path prerequisites; Phase 2 for dependent network, portal, NAT, and protected-router planning answers.
- The planner records gateway parent interface, CRS involvement, CRS ports, OLT involvement, OLT VLAN behavior, AP VLAN mode, and confirmation status.
- The open captive portal SSID uses the same customer VLAN ID answered in the planning questions; there is no separate Omada/Open SSID VLAN ID field.
- `Next Hop Device` means the first device after the HotSpot gateway on the way to AP clients, for example CRS in MikroTik -> CRS -> OLT -> ONU/AP.
- VLAN path planning is stored in `mikrotik_vlan_path_plans`.
- MT-4 readiness requires a confirmed VLAN path plan.
- If AP receives tagged VLAN, the SSID should use the customer VLAN ID. If AP receives untagged/access VLAN, downstream conversion must be confirmed as a warning.

Retired AI planning notes:
- The AI planning/VLAN Path Planner notes in older sections are historical only.
- AI must not be reintroduced unless explicitly requested.
- Current MikroTik setup is deterministic station transport plus AP-management planning.

## AI Network Assistant Removal — Manual MikroTik Setup Refocus

Decision:
- The AI Network Assistant is removed from the active product workflow because it made the MikroTik captive portal setup too complicated for operators.
- Admin -> Network -> MikroTik no longer shows the `AI Network Assistant` tab.
- Read-only preflight scan data remains required because it provides RouterOS data for deterministic validation, but it is no longer a standalone MikroTik tab.
- Manual setup under Admin -> Network -> MikroTik -> Configuration is the active path for MikroTik station transport and AP-management work.

Removed from active UI/workflow:
- AI Network Assistant overview.
- AI chat.
- AI health/smoke test.
- AI Explain Scan.
- AI suggested planning answers.
- AI draft deployment plan generation.
- System Settings -> OPENAI tab.

Backend/API behavior:
- AI/OpenAI API endpoints now return HTTP 410 with a removal message.
- Existing AI-related migrations/tables are retained to avoid destructive schema changes on staging/production databases.
- OpenAI settings data may remain in PostgreSQL if previously saved, but it is no longer exposed in the admin UI or used by the MikroTik workflow.

Current MikroTik workflow:
1. Open `Network -> MikroTik`.
2. Add MikroTik router API credentials under `Add Router`.
3. Return to `Configuration`.
4. Run `Prescan All Routers` or run a scan from a router row.
5. Click `View Scan Result` from the Configuration router table to open the scan result in a new browser tab/page and inspect existing VLANs, subnets, pools, DHCP, legacy HotSpot, PPPoE, OSPF, WireGuard, routing, and firewall indicators.
6. Use `Add Station` to build the ordered router chain. The button remains disabled until the operator has engaged read-only preflight scanning.
7. Set per-router bridge/tagged-port values from the station modal.
8. Set station network values such as customer VLAN, client CIDR, gateway, DHCP pool, DNS, and local interface list.
9. Use preflight scan data to validate that VLANs, subnets, and pools are not already used.
10. Open `Push Config` to review and push station transport steps one at a time.

Safety:
- AI must not be reintroduced unless explicitly requested.
- No AI output may approve, generate, or apply MikroTik configuration.
- Deterministic preflight validation remains the authority for conflict detection.
- The active UI no longer shows `Deployment Mode Confirmation` or `Policy Decision` cards. Operators review raw scan results and station planning fields directly from the Configuration workflow.

## MikroTik Station Deployment Planning

The MikroTik workspace has moved from `Captive Portal -> MikroTik` into `Network -> MikroTik` because MikroTik is infrastructure/gateway management, not portal content management.

## Station/Substation Captive Portal Network Model

Long-term network direction:
- One station/substation should have its own captive portal customer VLAN and client subnet.
- Roaming is seamless inside one station when APs use the same Omada open SSID, VLAN, subnet, and root MikroTik station gateway path.
- Moving between stations may give the customer a new DHCP address, but vouchers/wallet/access remain global in 3JCentralPisowifi so the experience can still be seamless at the account/device layer.
- DHCP/NAT transport belongs only on the root gateway router for that station. Captive portal redirect/enforcement belongs to Omada.
- CRS/switch/trunk/transport routers must only carry the VLAN and may expose a VLAN monitoring interface for visibility; they must not own DHCP/HotSpot for the station.
- Station plans now include a unique station code, customer VLAN, client subnet, HotSpot DNS/server planning fields, and portal URL.
- Active station plans must not reuse the same station code, customer VLAN, or client subnet.
- Saving a station validates selected router bridge/tagged ports against latest successful MikroTik preflight scan data, rejects PPPoE-related interfaces, and checks VLAN/subnet/pool conflicts before the RouterOS implementation modal is used.

## Station Backup Reachability / WireGuard Model

Use WireGuard for station-to-central controller reachability when a station has its own local ISP backup. Publicly exposing Omada/controller ports is a fallback only, not the preferred production design.

Rules:
- A station with `LOCAL_STATION_GATEWAY` owns its station VLAN, DHCP, NAT, queues, and AP/client path locally on the station root router. The central/root network should not be required for customer internet when the main fiber is cut.
- WireGuard is used only for management/control-plane reachability back to central services such as Omada/controller and system APIs. It is not the default customer internet path.
- Current direction is a dedicated WireGuard server with its own public IP/DNS, not CORE1 as the WireGuard hub. CORE1 may still be the public edge that forwards UDP 51820 from the IGATE/static public IP to the dedicated WireGuard server. Do not treat CORE1 as the tunnel hub unless the owner explicitly returns to a MikroTik-hub design.
- Admin path is `Settings -> WireGuard`. The page has `Overview` for station status and `Settings` for the dedicated WireGuard server endpoint, key, and SSH installation credentials.
- Do not reintroduce the CORE1 station local-ISP public endpoint / hub return gateway fields unless the owner explicitly asks to return to a MikroTik-hub design.
- Station WireGuard interfaces are created without storing or exposing a station private key in the system. RouterOS generates the station private key locally; the system reads and stores only the station public key.
- Station WireGuard routes should be narrow. Route central service subnets such as the Omada/system subnet, not `0.0.0.0/0`, unless the operator explicitly designs a full-tunnel backup.
- The system hub peer should allow only the station tunnel address and station/customer management subnets that must reach central services.
- RouterOS WireGuard apply/remove commands must follow the same station safety workflow: preflight scan, exact preview, explicit user review, then step-by-step push. Do not apply live MikroTik changes outside that reviewed workflow.

Validated station pattern from `CCR1009-Centro` failover testing on 2026-07-02:
- Dedicated WireGuard server is the hub. Current production server is `192.168.50.25` with public endpoint `wg.3jhotspot.com:51820`.
- Public edge forwarding belongs on the router that owns the static public IP/IGATE. Current deployment uses CORE1 IGATE to dst-nat UDP `51820` to `192.168.50.25` and route WireGuard replies out the selected IGATE routing table.
- Each station root MikroTik gets its own WireGuard interface and tunnel IP, normally derived from the station VLAN such as `10.250.<vlan>.2/32`.
- Each station root must have a narrow `/32` route to the public WireGuard endpoint through the station local ISP gateway. For `CCR1009-Centro`, this is `122.52.255.214/32 -> 192.168.5.1`. This prevents the station from trying to reach the WireGuard endpoint through the cut mainline/core path.
- The dedicated WireGuard server peer allowed IPs must include the station tunnel host and station client/management subnets that central services must reach. For `CCR1009-Centro`, allowed IPs are `10.250.78.2/32,10.78.0.0/24`.
- The central office/default LAN gateway must route station tunnel/client subnets back to the dedicated WireGuard server LAN IP. In the current office this means `CCR2116-Roma/Batu/GK` needs routes like `10.250.78.2/32 -> 192.168.50.25` and `10.78.0.0/24 -> 192.168.50.25`.
- Do not put these central return routes on CORE1 unless CORE1 is also the actual default gateway for the central services that need to reach the station. In the current network, the missing routes on `CCR2116-Roma/Batu/GK` caused the tunnel to handshake while Winbox/API/UI fallback to `10.250.78.2` timed out.
- Validation after cutting the mainline must include: WireGuard server can ping station tunnel IP; hotspot host and API container can ping station tunnel IP; TCP `8291` Winbox and RouterOS API port, currently `1219`, are open on station tunnel IP; `Settings -> WireGuard` reports `HANDSHAKE_OK`.
- If `Settings -> WireGuard` reports `Station interface check failed: timed out; tunnel fallback <station tunnel IP> failed: timed out`, first check central LAN return routes to the dedicated WireGuard server before changing peer keys, endpoint DNS, or station firewall rules.
- Future WireGuard page work should manage these central return routes per station so new substations do not require manual CCR route additions.

## Station Implementation History + Remove Config

Phase 2 station safety foundation:
- Station implementation and removal now write per-command history to `mikrotik_station_command_logs`.
- The station action is labeled `Push Config` in the UI. It checks existing station config before `Start Push` is enabled, then sends RouterOS commands one at a time.
- The config check detects station-created RouterOS objects per router using exact generated names/comments from the station remove plan.
- Dynamic RouterOS `/interface bridge vlan` rows are treated as read-only. If a station VLAN already appears only as a dynamic bridge VLAN row, Push Config creates a static station-managed bridge VLAN row instead of trying to modify the dynamic row.
- Push Config now detects station apply progress before pushing. Previously pushed objects are marked as already existing, the station card shows pushed-step progress such as `1/16`, and retries continue from the next missing step instead of visually resetting to zero.
- During Push Config, the running command is scrolled into view so the operator can watch each RouterOS step being sent and completed.
- The `Remove Config` workflow is station-specific and runs in reverse order with the same progress/status UI as implementation.
- The `Remove Config` action is shown only after a station is active so draft station plans do not look removable before anything has been pushed.
- Removal is conservative: it removes only objects matching station-generated names/comments. Shared bridge VLAN rows are not deleted unless they carry the station-created comment; existing shared bridge VLAN rows updated during implementation are not blindly removed.
- Command history is visible from the station implementation/remove modals so operators can review previous apply/check/remove results after refresh.
- This phase still keeps DHCP/HotSpot ownership on the station root gateway. CRS/trunk routers remain VLAN carriers only.

Station planning:
- A station models one captive portal VLAN path from the root gateway to downstream routers/switches/CRS/OLT/AP paths.
- The first router in the station chain is the root/primary gateway. It owns the VLAN interface, gateway IP, DHCP pool/network options, and local interface-list membership.
- Each following router is a trunk helper. It carries the same customer VLAN through its bridge/tagged ports toward OLTs and APs.
- Operators can reorder routers in the station chain; order matters because the VLAN path follows the listed sequence.
- The Add Station modal starts with an empty router chain. Operators add routers one at a time, then configure each selected router from vertical router tabs on the left side of the modal.
- The vertical router tabs show router icons and an animated root-to-downstream pulse so operators can see the intended VLAN flow path.
- Router tabs use a grey drag indicator and grab cursor to show that router order can be rearranged by dragging.
- The modal shows a step summary: `Name Station`, `Build Router Chain`, `Fill Router Fields`, and `Review Plan`.
- The selected router panel is split into `Step 3A: Select Router`, `Step 3B: Select Root Bridge and Tagged Ports`, and, for the root gateway only, `Step 3C: Root Gateway Network Values`.
- `Step 4: Review Plan` appears in the modal after the operator clicks `Save & Review Station Plan`; this creates the saved plan and shows generated RouterOS preview text only. Saving and reviewing still do not apply MikroTik configuration.
- Field labels use info icons/tooltips so non-MikroTik operators can understand values such as root bridge, tagged ports, customer VLAN, gateway IP, DHCP pool, DNS, and local interface list.
- Root gateway network fields are shown inside the root gateway tab because only the root gateway owns the VLAN interface, gateway IP, DHCP pool/network options, DNS options, and local interface-list membership.
- Router bridge/interface and tagged-port fields must use detected RouterOS interfaces from the saved MikroTik router record. Operators should select ports from dropdown/multi-select controls instead of typing interface names manually.
- The station bridge/interface and tagged-port selectors must hide PPPoE interfaces because captive portal VLANs should be created/carried on bridges, trunks, or physical ports, not on dynamic/customer PPPoE sessions.
- Tagged ports should use a searchable checkbox list instead of a multi-select requiring Ctrl/Command, because operators often need to choose several trunk/OLT/AP-facing ports safely.
- The root gateway local interface-list field should also use detected RouterOS interface lists when available, because `LOCAL`/LAN membership is an existing router object and should not be typed manually if the router can report it.
- The old single-router `Start Setup`, `Check Config`, and `Remove Config` controls are no longer shown in the main Configuration table. Their underlying backend primitives are retained for future reviewed apply/remove phases, but the active operator workflow is station-first.
- This is based on the validated `ACroma -> CRS317` VLAN 77 pattern:
  - Root gateway creates `VLAN77-3J-HOTSPOT` on `SwAC`, assigns `10.77.0.1/24`, creates `POOL-3J-HOTSPOT-V77`, adds DHCP network options, and adds the VLAN interface to `LOCAL`.
  - CRS/trunk routers add a VLAN interface on the selected bridge and add `/interface bridge vlan` records for VLAN 77 on the ports that must carry the captive portal VLAN. The bridge itself is included as a tagged member so the VLAN interface is visible in RouterOS Interfaces for monitoring/bandwidth visibility.
- Station plans are saved in PostgreSQL and generate reviewable RouterOS command previews. The `Implement` button opens a separate RouterOS write modal that displays every command, shows a progress bar, sends commands one at a time, marks each command success/skipped/error, and stops on the first error.
- Station apply steps use station plans so multi-device paths such as `CCR2116 -> CRS317 -> CCR1009 -> OLT/APs` are handled as one deployment workflow instead of isolated single-router setup.

## Phase 3 — Root Gateway DHCP Server Foundation

Purpose:
- Phase 3 completes the per-station VLAN/DHCP foundation for the long-term model where each station/substation owns its own captive portal customer VLAN and subnet.
- The root gateway router is the only router that creates DHCP ownership for the station.
- CRS/switch/trunk/transport routers remain VLAN carriers only. They may add VLAN monitoring interfaces and bridge VLAN trunk rows, but they must not create DHCP servers for the station.

Root gateway behavior:
- Station plans now include `create_dhcp_server`, `dhcp_server_name`, and `dhcp_lease_time`.
- `Create DHCP server on root gateway` is enabled by default in the Add Station modal.
- The generated root gateway plan now includes `/ip dhcp-server add` using the station VLAN interface and DHCP pool.
- The DHCP server name defaults to `DHCP-3J-HOTSPOT-V{vlan_id}` and the lease time defaults to `1h`.
- Existing DHCP servers on the proposed station VLAN interface are checked during station validation so the operator does not accidentally place two DHCP servers on the same interface.

Removal behavior:
- Station remove plans now remove the station-managed root DHCP server by exact generated name before removing DHCP network options, pools, IP addresses, bridge VLAN rows, and VLAN interfaces.
- Remove Config remains conservative and station-scoped. It removes only objects created by the station plan using exact names/comments.

UI behavior:
- The root gateway tab in Add Station now shows a DHCP server toggle, DHCP server name, and lease time inside `Step 3C: Root Gateway Network Values`.
- The station review modal shows DHCP ownership explicitly so operators can verify that DHCP is root-gateway-only before implementation.

## Phase 4 — Root Gateway HotSpot Enforcement Foundation

Purpose:
- Phase 4 adds the first station-based MikroTik HotSpot enforcement objects on top of the VLAN/DHCP foundation.
- The root gateway remains the only router that owns HotSpot enforcement for a station/substation.
- CRS/switch/trunk/transport routers remain VLAN carriers only; they must not create HotSpot profiles, HotSpot servers, DHCP servers, or portal allow rules for the station.

Root gateway behavior:
- Station plans now include `create_hotspot_profile`, `create_hotspot_server`, `create_walled_garden`, `hotspot_profile_name`, and `hotspot_html_directory`.
- The generated root gateway plan can create:
  - `/ip hotspot profile` for the station.
  - `/ip hotspot` server bound to the station VLAN interface.
  - `/ip hotspot walled-garden ip` entries that allow the 3J portal server and DNS before login.
- Defaults:
  - HotSpot profile: `PROFILE-3J-HOTSPOT-V{vlan_id}`
  - HotSpot server: `HS-3J-HOTSPOT-V{vlan_id}`
  - HTML directory: `hotspot`
  - Portal URL: staging `/portal` URL unless overridden.
- Station validation checks the latest root-router preflight scan for conflicting HotSpot profiles or servers before saving the station.

Removal behavior:
- Station remove plans now remove station-managed HotSpot server, HotSpot profile, and walled garden entries by exact generated names/comments before removing VLAN/DHCP objects.
- Remove Config remains conservative and station-scoped. Shared or unrelated MikroTik HotSpot objects are not removed.

UI behavior:
- Superseded by OCP-1/OCP-2: Add Station no longer shows MikroTik HotSpot enforcement controls in the active UI.
- Superseded by OCP-1/OCP-2: Operators no longer create MikroTik HotSpot profile/server or pre-login walled-garden rules from Station Push Config.
- Superseded by OCP-1/OCP-2: Station review now focuses on VLAN/DHCP/NAT/trunk transport; Omada handles captive portal redirect/enforcement.

## Phase 5 — MikroTik HotSpot Portal Handoff + Voucher Authorization

Purpose:
- Phase 5 connects the MikroTik HotSpot redirect flow to the existing `/portal` voucher redemption flow.
- MikroTik remains the gateway/enforcement layer.
- 3JCentralPisowifi remains the source of truth for vouchers, wallets, portal sessions, and access decisions.

MikroTik portal session capture:
- `/portal` now captures common MikroTik HotSpot variables such as `mac`, `ip`, `server-name`, `link-login`, `link-login-only`, `link-orig`, `chap-id`, and `chap-challenge`.
- Portal sessions store MikroTik context separately from Omada context.
- If MikroTik HotSpot variables are present, the portal session source is `MIKROTIK`.

Voucher authorization behavior:
- For MikroTik portal sessions, voucher validation happens before consuming the voucher.
- After validation, the system attempts to authorize the client on the station root gateway through RouterOS API.
- The system creates or reuses a portal HotSpot user for the internal portal account and calls the MikroTik HotSpot active login action for the detected client IP/MAC.
- If MikroTik authorization fails, the voucher is not redeemed/consumed and the customer sees a friendly operator-contact message.
- If MikroTik authorization succeeds, the voucher is redeemed, the wallet/access is credited, the portal session becomes `ACCESS_GRANTED`, and an authorization log is saved.

HotSpot login page:
- The MikroTik HotSpot `login.html` file is now system-managed instead of manually uploaded by the operator.
- One generic managed redirect template is used for all stations. It always writes to the same filename, `login.html`, inside the station HotSpot HTML directory, normally `hotspot/login.html`.
- The template redirects MikroTik HotSpot clients to the configured Captive Portal URL with MikroTik query parameters preserved.
- Station implementation includes a final step that uploads/overwrites the managed `login.html` on the station root gateway.
- Network -> MikroTik -> Configuration -> `HTML and AP Management` includes the HotSpot login sync checker and a `Sync login.html to MikroTik` action. Operators should use this after Captive Portal URL/template changes so all station root gateways receive the current managed file.
- Sync status is tracked per station/root gateway so the UI can show whether the file is synced, missing, outdated, detected without hash verification, or failed.

Logs and UI:
- `mikrotik_portal_authorizations` stores MikroTik authorization attempts and outcomes.
- Captive Portal authorization logs now include gateway type so Omada and MikroTik authorization events are distinguishable.
- Sanity Check now treats gateway authorization as testable through a MikroTik HotSpot redirect voucher redemption.

Safety:
- RouterOS write actions during redemption are limited to the selected station root gateway.
- CRS/trunk routers are not used for client authorization.
- Voucher consumption is gated behind successful MikroTik authorization for MikroTik portal sessions.

## Phase 5.1 — Live HotSpot Diagnostics + Redirect Hardening

- Phase 5.1 stabilizes the first real phone test on VLAN 77 before moving to broader rollout phases.
- `/api/portal/redeem` portal-session creation was hardened so MikroTik and manual station-client visits no longer fail before voucher validation.
- If a customer manually opens `/portal` from a station client subnet, such as `10.77.0.0/24`, the portal can classify the session as MikroTik-backed even when the MikroTik login page did not provide query parameters.
- Station matching can use the HotSpot server name, station VLAN, or client IP subnet. This supports field testing when HotSpot redirect parameters are missing.
- Active station records should store explicit `portal_url` and `hotspot_server_name` values. Migration `044_station_field_test_defaults.sql` backfills these for existing active station plans.
- Network -> MikroTik -> Configuration now includes a station HotSpot diagnostics action. Diagnostics are read-only and check root gateway API login, HotSpot profile/server, managed `login.html`, DHCP server, walled garden portal access, and whether a client IP is visible in MikroTik HotSpot host/active tables.
- Successful DHCP on a station client, for example a phone receiving `10.77.0.8`, proves VLAN/DHCP path readiness but does not by itself prove HotSpot redirect or internet authorization readiness.
- Redirect troubleshooting should first confirm the client appears in `/ip hotspot host` on the root gateway and that managed `hotspot/login.html` is synced.

## Phase 5.2 — Station Internet NAT + HotSpot Address Translation

- Real MikroTik HotSpot tests showed that the customer device DHCP address and the HotSpot Active session address can differ.
- Example: the phone may show `10.77.0.11`, while MikroTik HotSpot Active shows `10.77.0.12` as the translated `to-address`.
- The portal authorization flow must therefore look up `/ip hotspot host` by both `address` and `to-address`, then authorize using the HotSpot `to-address` while keeping the real client/MAC stored in logs.
- The station HotSpot server should use `address-pool=none` because DHCP is already owned by the station root gateway. This avoids confusing HotSpot address translation for new client sessions.
- If the portal detects an old HotSpot host where `to-address` differs from the client `address` while the server is now `address-pool=none`, it clears only that client's HotSpot active/host state and asks the customer to reconnect before redeeming. The voucher is not consumed in this stale-state cleanup path.
- RouterOS HotSpot users accumulate `uptime`; reusing the same portal HotSpot username after a voucher expires can trigger `your uptime limit is reached`.
- The MikroTik authorization flow now updates an existing portal HotSpot user's `limit-uptime` to current RouterOS uptime plus the new voucher duration before calling active login.
- A voucher can authorize the HotSpot session successfully while the phone still has no internet if the station client subnet is not NATed or routed upstream.
- Station root gateway plans now include a managed WAN-only NAT masquerade rule for station client internet access.
- The managed NAT rule uses comment `3J Station - NAT for VLAN {vlan_id} clients` and must include `out-interface-list=WAN`.
- Omada captive portal requires the client IP to remain visible when the client reaches Omada/controller and the 3J portal server. Station plans therefore add a no-NAT `srcnat accept` rule before the station masquerade: `3J Station - preserve client IP for VLAN {vlan_id} to portal office subnet`.
- Do not use broad source NAT from station client VLANs to the office subnet. It can make Omada see the gateway IP instead of the real phone IP and break portal popup/session matching.
- Station diagnostics now checks both the WAN-only NAT rule and the no-NAT office portal exception.

## Phase 5.3 — Live Portal Countdown Status

- The public `/portal` page now shows a large live countdown timer for the current voucher access window.
- For MikroTik/Omada-backed sessions, the customer-facing remaining time is based on `portal_sessions.access_expires_at`, not the wallet's stored remaining seconds. This prevents stale displays such as `Time remaining: 15m Connected` after the HotSpot session has already consumed its time.
- Time-based vouchers now store an access expiry of `now + voucher duration` during gateway authorization.
- `/api/portal/status` recalculates remaining time from the access expiry and marks the portal session `EXPIRED` when the countdown reaches zero.
- When time is fully consumed, the portal shows `Time fully consumed` and asks the customer to enter a new voucher instead of showing connected.

## Phase 5.4 — Captive Popup Detection Hardening

- Station Push Config now includes a root-gateway DNS readiness step: `/ip dns set allow-remote-requests=yes`.
- This is needed because Android/iOS/Windows captive network detection first resolves OS captive-check hostnames. If DNS fails before login, the phone may stay connected without opening the WiFi sign-in popup.
- Station Push Config now creates DHCP option 114 (`3J-CAPPORT-V{vlan_id}`) and attaches it to the station DHCP network. This advertises the captive portal API URL to phones that support RFC 8910/CAPPORT.
- `/api/portal/capport` is a public captive portal API endpoint that returns `application/captive+json` with `captive=true` for unauthenticated station clients and points them to the configured `/portal` URL.
- The managed MikroTik HotSpot `login.html` now includes a meta refresh fallback in addition to JavaScript redirect. This helps captive popup mini-browsers that do not execute JavaScript reliably.
- The JavaScript redirect still preserves MikroTik variables such as client MAC/IP when available; the meta refresh fallback opens the portal without those variables, and `/portal` can still classify station clients by source IP/subnet.
- HotSpot diagnostics now checks RouterOS DNS remote request status and DHCP DNS options in addition to API login, HotSpot profile/server, DHCP server, NAT, walled garden, managed `login.html`, and client host/active state.
- HotSpot diagnostics also checks DHCP option 114 so operators can confirm whether modern phones are being explicitly told where the captive portal is.
- The station remove workflow does not disable RouterOS DNS remote requests because it is a shared router-level setting and may be required by other active station VLANs.

## Phase 5.5 — Captive DNS Enforcement for MikroTik HotSpot

- Station Push Config now treats DNS as part of captive portal enforcement.
- Captive clients must receive only the station HotSpot gateway IP as DHCP DNS, for example `10.77.0.1` on VLAN 77.
- Public DNS servers are configured as MikroTik upstream resolver servers instead of being handed directly to unauthenticated phones.
- Station Push Config updates the DHCP network DNS option to the gateway-only value and keeps RouterOS DNS remote requests enabled.
- Station Push Config adds station-scoped DNS redirect rules for TCP/UDP port 53 so clients that manually try public DNS are redirected back to the MikroTik resolver.
- This improves Android/iOS/Windows captive portal popup detection by preventing clients from bypassing the HotSpot DNS path before voucher login.
- The station form labels the DNS field as router upstream DNS to avoid confusing it with client DHCP DNS.
- HotSpot diagnostics now warns if DHCP DNS is not gateway-only or if the station DNS redirect rules are missing.

## Phase 5.6 — HotSpot Redirect Tracking Exceptions

- Live testing on the CCR2116 root gateway found a broad enabled `/ip firewall raw action=notrack` rule.
- Broad raw notrack rules can prevent normal connection tracking for station client traffic, which can stop MikroTik HotSpot from reliably redirecting unauthenticated HTTP captive-check traffic.
- Station Push Config now adds station-scoped raw accept exceptions before broad raw notrack rules:
  - source client subnet, for example `10.77.0.0/24`
  - destination client subnet, for example `10.77.0.0/24`
- The same protection is also required for central AP Management subnets because AP GUI traffic can fail when a broad raw `notrack` rule bypasses connection tracking. Push Config auto-detects active broad raw `notrack` rules and only shows/adds the managed raw accept exceptions when needed.
- The system does not disable or remove existing non-3J raw/notrack rules. It only adds managed exceptions for the station or AP management subnet.
- Station/AP Management remove config removes only the system-managed raw accept exceptions by exact comment.
- HotSpot diagnostics now checks whether broad raw notrack exists and whether station tracking exceptions are present.

## Phase 5.7 — Captive-Check DNS Probe Mapping

- Live Android/Realme testing showed the phone was detecting `no internet access` but was not opening the captive portal assistant.
- RouterOS counters showed DNS captive-check activity but little/no unauthenticated HTTP redirect traffic, meaning the phone was not reaching the normal HotSpot HTTP redirect path.
- Station Push Config now creates station-managed DNS static records for common OS captive-check hostnames and points them to the station HotSpot gateway IP.
- Initial managed hostnames include Android, Apple, Windows, Huawei/Honor, Unisoc, and MIUI captive-check domains such as `connectivitycheck.gstatic.com`, `captive.apple.com`, `www.msftconnecttest.com`, and `connectivitycheck.platform.hicloud.com`.
- These static records are exact-name records only. The system avoids broad wildcard hijacks and avoids generic domains such as `google.com` so normal authenticated browsing is not broken.
- Station remove config removes these captive-check DNS records by exact station-managed comments.
- HotSpot diagnostics now checks whether common captive-check hostnames resolve to the HotSpot gateway.

## Phase 5.8 — Direct Portal Redirect for Unauthenticated HTTP Checks

- Live testing showed Android phones were finally hitting MikroTik HotSpot HTTP/HTTPS local redirect counters, but the phone still did not open the voucher portal assistant.
- The staging reverse proxy previously sent unknown/root paths to `/admin/`. For captive-check requests that reach `192.168.50.70:8080`, unknown paths now redirect to `/portal` instead.
- Common captive-check paths such as `/generate_204`, `/gen_204`, `/hotspot-detect.html`, `/connecttest.txt`, and `/ncsi.txt` explicitly return `302 /portal`.
- The direct `pre-hotspot` dst-nat experiment was removed after live testing because it bypassed the normal MikroTik HotSpot login flow and did not reliably deliver phone browser requests to the portal server.
- Station Push Config now relies on the standard MikroTik HotSpot HTTP redirect to serve the managed `hotspot/login.html`, which then opens `/portal`.

## Phase 5.9 — Standard MikroTik HotSpot Redirect Flow

- Captive popup testing returned to the safer standard MikroTik HotSpot flow:
  1. DHCP gives clients only the station gateway as DNS.
  2. MikroTik DNS resolves normal public hostnames through upstream DNS.
  3. MikroTik HotSpot intercepts unauthenticated HTTP traffic.
  4. MikroTik serves the managed `hotspot/login.html`.
  5. The managed login file redirects the customer to the 3J `/portal`.
- Station Push Config no longer creates static DNS records that point captive-check domains to the HotSpot gateway. Live testing showed this can make phones try HTTPS against the gateway and display `site can't be reached` instead of opening the portal.
- Station Push Config no longer creates the station-scoped `pre-hotspot` direct portal dst-nat rule.
- Station remove config still removes the old experimental captive-check DNS records and direct redirect rule by exact managed comments if they exist.
- HotSpot diagnostics now focuses on the stable requirements: HotSpot profile/server, synced `login.html`, DHCP gateway-only DNS, DNS redirect, DHCP option 114, NAT, raw tracking exceptions, walled garden, and client HotSpot host visibility.
- HotSpot DNS names must avoid `.local`. Many phones reserve `.local` for mDNS and may not resolve it through MikroTik DNS, causing `site can't be reached` after HotSpot redirects to the login page.
- The default HotSpot DNS name is now `wifi.<station-code>.3jportal.test`, for example `wifi.station-roma-batu-gk.3jportal.test`. MikroTik serves this name locally for captive clients; it is not a public internet hostname.
- Captive portal does not use MikroTik Web Proxy as the enforcement design. A legacy global NAT redirect from TCP `80,443` to web-proxy port `8081` was found on the live CCR and disabled because it can interfere with standard HotSpot redirects.
- HotSpot diagnostics now flags enabled global TCP `80,443 -> 8081` web-proxy redirect rules as a warning.
- Station HotSpot enforcement is IPv4-only for now. Station Push Config suppresses IPv6 router advertisements on the HotSpot VLAN with a station-scoped `/ipv6 nd` rule (`ra-lifetime=0s`, `advertise-dns=no`) because phones may otherwise try IPv6/HTTPS captive checks that MikroTik IPv4 HotSpot cannot intercept.
- HotSpot diagnostics now checks for station IPv6 RA suppression.

## Phase 5.10 — Android Private DNS Captive Fallback

- Live testing on VLAN 77 showed an unauthenticated Android phone being discovered by MikroTik HotSpot through `TCP -> 10.77.0.1:853`, which is DNS-over-TLS / Android Private DNS behavior.
- DNS-over-TLS to the HotSpot gateway can stop the phone from falling back to normal captive DNS and HTTP checks, leaving the WiFi status at `Connected / No internet access` without opening the voucher portal.
- Station Push Config now adds a station-scoped firewall filter rule that rejects TCP `853` from the captive client subnet with `tcp-reset`.
- The rule is managed by exact comment, for example `3J Hotspot - reject Private DNS TLS for VLAN 77`, and is inserted before the RouterOS HotSpot input jump when possible.
- This does not enable general internet access before voucher redemption. It only makes unsupported Private DNS fail fast so Android can continue with normal captive portal detection.
- HotSpot diagnostics now checks for the station Private DNS fallback rule.

## Phase 5.11 — Port 80 Captive Portal Exposure

- Live testing showed that both the 3J managed HotSpot login and an isolated VLAN 66 default MikroTik HotSpot test could see unauthenticated phones in `/ip hotspot host`, but phones still did not reliably open the captive browser.
- To remove non-standard port behavior from the phone captive path, the staging proxy now exposes the same web app on normal HTTP port `80` in addition to `8080`.
- The active station portal URL was changed to `http://192.168.50.70/portal`.
- The MikroTik managed `hotspot/login.html`, DHCP CAPPORT option 114, and walled garden portal URL rule were updated to use port `80`.
- Admin/staging access on `http://192.168.50.70:8080` remains available, but captive portal clients should be directed to the port-80 URL for the most reliable phone captive-assistant behavior.

## Phase 5.12 — Gateway-Hosted Voucher Login

- Captive portal testing showed the first page should be served by the MikroTik HotSpot gateway/local DNS name, not immediately redirected away to the central server.
- The managed MikroTik `hotspot/login.html` now displays the voucher entry form directly on the gateway-served HotSpot page, for example `http://wifi.station-roma-batu-gk.3jportal.test/login`.
- The gateway-hosted page calls `http://192.168.50.70/api/portal/redeem` in the background using CORS, passing MikroTik variables such as client MAC, client IP, HotSpot server name, and original link.
- `/api/portal/capport` now points station clients to the gateway-local HotSpot login URL as the user portal URL when a station can be identified from the client IP.
- The full React `/portal` page remains available as a fallback and operator/manual test page, but the field captive popup path should prefer the gateway-hosted page.

## Phase 5.13 — CAPPORT Gateway Masquerade Detection

- Live testing showed station client requests to the central portal server can arrive with the MikroTik root gateway IP because the station NAT masquerade rule applies to the captive subnet.
- `/api/portal/capport` now maps both direct station client IPs and station root gateway IPs back to the active MikroTik station.
- When CAPPORT sees the root gateway IP, it returns the gateway-hosted HotSpot login URL, for example `http://wifi.station-roma-batu-gk.3jportal.test/login`, instead of the generic `/portal` URL.
- This improves standards-based captive assistant discovery without changing RouterOS enforcement or applying additional router configuration.

## Phase 5.14 — Captive VLAN Isolation Diagnostics

- Live testing showed the same phone MAC can receive both a station HotSpot VLAN lease, for example `10.77.0.x`, and a normal management LAN lease, for example `192.168.50.x`.
- When this happens, the phone is not isolated to the captive SSID/VLAN path and may bypass the MikroTik HotSpot popup detection flow even though the manual gateway login link works.
- Station HotSpot diagnostics now checks for duplicate MAC leases between the station DHCP server and other DHCP servers on the root gateway.
- Diagnostics also warns when AP-looking devices such as EAP/AP hostnames receive leases from the captive client DHCP server, because AP management should normally stay on the management/native network while SSID client traffic uses the HotSpot VLAN.
- The operational fix is in the network/AP path: the open customer SSID must tag the station VLAN, such as VLAN 77, while AP management remains on the management/native network. A phone connected to the customer SSID should have only the captive VLAN address before voucher login.

## Phase 5.15 — Centralized AP Management VLAN

- AP management is now centralized instead of being configured inside each Add Station plan.
- Network -> MikroTik -> Configuration renames the managed `login.html` panel to `HTML and AP Management`.
- The `HTML and AP Management` panel owns the central AP management VLAN/subnet details and provides an AP Management Details modal plus a Push AP Management Config modal.
- Default central AP management values are VLAN `111`, subnet `10.111.0.0/24`, gateway `10.111.0.1`, DHCP pool `10.111.0.10-10.111.0.254`, and RouterOS names such as `VLAN111-AP-MGMT`, `POOL-AP-MGMT-V111`, and `DHCP-AP-MGMT-V111`.
- The first/root router creates the AP management VLAN interface, gateway IP, DHCP pool/server, DHCP network options, and local interface-list membership.
- Downstream CRS/switch/trunk routers carry the AP management VLAN as tagged trunk configuration and create a VLAN monitoring interface for visibility.
- Add Station returns to customer HotSpot VLAN planning only. Station plans no longer ask for AP management VLAN values.
- The customer captive portal VLAN remains separate, for example VLAN 77 with `10.77.0.0/24`, and continues to own HotSpot, captive DNS, voucher authorization, and NAT behavior.
- AP management is not a HotSpot network. It exists so Omada/AP control traffic stays off the customer captive VLAN while the open SSID still tags the customer VLAN.
- Validation rejects AP management VLANs/subnets that overlap station customer HotSpot VLAN/subnet or existing scanned router VLAN/subnet/pool state.
- AP management config is not pushed automatically. It uses the same step-by-step RouterOS push pattern as Station Push Config: detect existing matching objects, show every command, push one command at a time, and stop on the first error.
- AP Management Push Config now detects broad active raw `notrack` rules and, when present, adds managed raw accept exceptions for source/destination AP management subnet traffic before the broad `notrack`. This allows AP GUI/control traffic such as `10.88.0.10` to remain connection-tracked without disabling the operator's existing raw rule.
- AP Management Push Config no longer creates office-to-AP GUI masquerade/NAT. AP management transport should focus on VLAN interface, DHCP, Omada discovery/control reachability, and raw tracking exceptions only.

## Phase 5.16 — Tested MikroTik HotSpot Pattern Alignment

- Live TestRouter validation proved the captive portal works with MikroTik HotSpot when the AP/client path is correctly isolated and bound to the HotSpot interface.
- The verified no-VLAN test used `ether2` as the client side, `10.88.0.0/24`, DHCP DNS set to the MikroTik gateway, NAT, walled garden access to the portal server, `address-pool=none`, and the managed `login.html`.
- The verified VLAN test used VLAN `33` for HotSpot clients and VLAN `222` for AP management. Phones received `10.33.0.x`, AP management received `10.222.0.x`, and the captive portal still opened.
- Station Push Config keeps the proven rules: client DHCP DNS must be the HotSpot gateway only, RouterOS DNS remote requests must be enabled, HotSpot server `address-pool` must be `none`, and the managed `login.html` is uploaded as part of the push workflow.
- RouterOS 6 hEX rejected API `/file` upload for `login.html`, but FTP upload to `flash/hotspot/login.html` worked. The system now attempts RouterOS API file upload first and falls back to FTP for older RouterOS devices.
- Station-created DHCP servers are matched by name instead of relying on RouterOS `comment` support because RouterOS parameters vary by version.
- Add Station remains focused on the customer HotSpot VLAN. Separate AP management VLAN setup remains in the HTML and AP Management workflow and will be refined next.
- Station plans can now be deleted/archived from the system UI. Deleting a station plan does not remove RouterOS configuration; operators should use Remove Config first when router cleanup is needed.

## OCP-1 — Omada Captive Portal Pivot Foundation

- The project has pivoted away from MikroTik HotSpot as the primary captive portal enforcement layer.
- MikroTik Stations now represent gateway/transport configuration only: customer VLAN interface, bridge VLAN trunk path, gateway IP, DHCP pool/server/network, local interface-list membership, NAT, and station-scoped raw tracking exceptions.
- Station Push Config no longer creates MikroTik HotSpot profiles, HotSpot servers, walled garden entries, DHCP CAPPORT option 114, forced DNS redirect rules, Private DNS reject rules, IPv6 RA suppression rules, or managed `login.html` upload steps.
- Omada Controller/AP captive portal will become the redirect/enforcement layer. The open SSID should use the station customer VLAN, while Omada will redirect unauthenticated clients to the 3J portal.
- 3JCentralPisowifi remains the source of truth for vouchers, wallet/access, portal sessions, and logs. MikroTik remains the routed VLAN/DHCP/NAT transport for each station.
- Existing legacy MikroTik HotSpot diagnostics and cleanup endpoints are retained for old test objects, but they are no longer part of the main Station push workflow.
- Remove Config remains station-scoped and now removes both older `3J Hotspot` comments and new `3J Station` comments where applicable, so previous test objects can still be cleaned.
- AP Management remains a separate workflow and will be refined after the Omada captive portal station flow is stable.

## OCP-2 — Station Omada Captive Portal Readiness

- Network -> MikroTik -> Configuration now exposes an `Omada Portal` action per station plan.
- The station Omada portal plan binds together the station customer VLAN, MikroTik transport push progress, AP Deployment SSID, selected Omada site, Omada API status, portal URL, and connected AP count.
- The readiness plan checks that the selected Omada site VLAN matches the station VLAN. The AP/open SSID must tag the same customer VLAN that the station root gateway serves with DHCP/NAT.
- Omada automation actions are available from the station plan modal: test Omada API, create/update the open SSID, configure the external portal, and verify the captive portal setup.
- Omada API automation remains best-effort because controller versions expose different API paths. The modal always includes manual fallback steps.
- OCP-2 does not apply RouterOS configuration and does not reintroduce MikroTik HotSpot. Station Push Config remains the only explicit RouterOS write path and still handles VLAN/DHCP/NAT/trunk transport only.
- 3JCentralPisowifi remains the source of truth for vouchers, wallet/access, portal sessions, and authorization logs. Omada handles AP/SSID captive portal redirect and device authorization.
- Omada External Portal should use an HTTPS public URL such as `https://net.3jhotspot.com/portal`, but Omada's own HTTPS Redirect should stay disabled unless the Omada controller entry page has a trusted certificate/domain. Field testing on 2026-06-07 showed Android captive portal warnings when Omada redirected to `https://192.168.50.71:8843/portal/entry` using TP-Link's self-signed `localhost` certificate.

## OCP-3 — Station Omada Site Binding

- MikroTik stations can now store their own Omada site binding with `omada_site_id`, `omada_site_name`, binding timestamp/admin, and a saved VLAN-match flag.
- Add/Edit MikroTik Station includes a Station Omada Site selector. The selected Omada site should be the site that owns the APs for that station.
- The station Omada Portal modal now requires a station-bound Omada site instead of relying only on the global captive portal selected site.
- Omada readiness and automation actions target the station-bound Omada site where possible. The global selected Omada site is only a fallback/reference.
- Station readiness checks still require the Omada/local site VLAN tag to match the MikroTik station customer VLAN.
- New station saves no longer auto-generate MikroTik HotSpot profile/server/DNS names. The active station workflow is VLAN/DHCP/NAT/trunk transport plus Omada portal binding.
- RouterOS HotSpot legacy cleanup/diagnostic code remains available only for previous field-test objects; it is not part of the active OCP station setup.

## OCP-4 — Station Omada Action Tracking + VLAN-Aware SSID Automation

- Station Omada automation now runs through station-scoped endpoints instead of only the global captive portal endpoints.
- Omada action logs store the station, Omada site, SSID name, status, sanitized details, and timestamp so operators can see what was attempted per station.
- The station `Omada Portal` modal shows recent station Omada action history and disables actions until prerequisites such as API credentials and station site binding are ready.
- Create/Update Open SSID now passes the station customer VLAN ID to the Omada adapter. New Omada SSIDs should be created as open guest/portal SSIDs with VLAN enabled for the station VLAN where the controller API supports it.
- If an SSID already exists, the system records the requested VLAN but operators must still verify the existing SSID VLAN directly in Omada because controller update paths can differ by version.
- OCP-4 still does not reintroduce MikroTik HotSpot. MikroTik remains VLAN/DHCP/NAT/trunk transport; Omada handles captive portal redirect/enforcement; 3JCentralPisowifi remains voucher/wallet/session source of truth.

## OCP-4.1 — AP Management Omada Discovery

- AP Management now adds a MikroTik DHCP option 138 command when the Omada Controller host is an IPv4 address, normally `192.168.50.71`; RouterOS receives it in hex form, for example `0xC0A83247`.
- The option name is `3J-OMADA-CONTROLLER-V{vlan}` and it is attached to the AP management DHCP network so APs on `10.111.0.0/24` can learn the controller address during DHCP.
- AP Management and any remaining station AP-management push plan must also add managed MikroTik forward allow rules from the AP management subnet to the Omada Controller: UDP `29810` for discovery and TCP `29811-29817` for adoption, management, transfer, RTT/TTY, and device monitor features. Remove Config must remove those rules by exact `3J AP Management` comments.
- The AP management root gateway already creates the connected route by having both the office-side network and AP management VLAN interface on the MikroTik. No static route is needed when the Omada server/default gateway can route back through the same MikroTik.
- If the Omada server is not using the MikroTik/CCR as its default gateway, the office network still needs a return route to `10.111.0.0/24` via the CCR office IP.
- The station Omada Portal readiness now labels AP count source as live Omada API vs local saved AP records, so stale local AP rows do not look like confirmed connected APs.

## OCP-4.2 — AP Management VLAN Scope

- Central AP Management now focuses only on tagged AP management VLAN transport between MikroTik routers, CRS, OLT, ONU, and AP paths.
- Native/untagged AP-facing port automation is disabled for now because it adds too much complexity while captive portal work is the priority.
- The system no longer asks operators to select native/untagged AP-facing ports and no longer generates bridge-port PVID or untagged bridge VLAN commands for AP Management pushes.
- Operators will manually enable the AP management VLAN inside each AP before deploying it to the station path.
- The root gateway still owns the single AP management VLAN interface, gateway IP, DHCP pool/server, DHCP network options, Omada option 138, LOCAL membership, and raw tracking exceptions.

## OCP-4.3 — Omada AP Adoption and Configuration Apply Behavior

- AP adoption status must mirror explicit Omada failures. If Omada reports `Adopt Failed` or `Managed by Others`, the List of APs page must show `ADOPT_FAILED` immediately instead of keeping the row in `ADOPTING`.
- The List of APs page can show Omada-reported `ADOPTING`/`CONFIGURING` states, but 3JCentralPisowifi does not submit adoption anymore.
- Sites -> Configuration saves global/per-site SSID, security, and site VLAN configuration only. It must not automatically push WiFi changes to APs.
- AP Deployment Configurations no longer manages AP Device Account Credentials. Device account configuration is not required for the current Omada-managed AP/SSID/captive-portal flow.
- AP adoption is handled manually inside Omada Controller. The List of APs page must not provide Add APs/adoption controls.
- Omada site creation must not include `deviceAccountSetting`; site creation only creates/links the site and leaves AP local login/device credentials untouched.
- After a user-triggered Push WiFi Config sync records an AP in PostgreSQL, the system displays it in List of APs. Operators manually click `Push WiFi Config` to refresh/apply managed SSIDs and the station/customer VLAN on those SSIDs.
- The List of APs table shows an AP implementation progress badge, for example `2/2`. The AP details side panel shows the same checklist with each component status and message.
- Connected APs are marked `PENDING` before the apply attempt. A successful Omada API apply marks them `APPLIED`; a partially successful apply marks them `PARTIAL`; a failed API apply marks them `FAILED` and stores the Omada error.
- Omada WLAN automation remains controller-version dependent. If Omada rejects an existing SSID update endpoint, the system must show an AP configuration failure instead of silently marking the AP applied.
- Central AP Management VLAN transport is handled by Network -> MikroTik -> AP Management. Device-side AP management VLAN changes are not pushed through Omada for now; operators manually set the AP management VLAN in the AP before station deployment.

## OCP-4.4 — Omada AP Device Credential Safety Patch

- The system can send AP adoption username/password fields only in the Omada adopt request when the operator enters them. It still does not include Omada `deviceAccountSetting` during site creation.
- Historical `ap_deployments.adoption_device_account_*` tracking is cleared because those fields could imply that the system intentionally changed AP local credentials.
- If an AP GUI login no longer accepts the expected credentials after earlier testing, factory-reset the AP, remove/re-add the AP row, and adopt again manually in Omada Controller. The corrected 3JCentralPisowifi flow must not change AP GUI/device credentials after adoption.
- Device account credential changes, if ever needed in the future, must be implemented as a separate explicit feature with a preview, warning, and user confirmation. It must not be hidden inside Add Site, Add APs, or auto-apply.

## OCP-4.5 — AP Adoption Status Truthfulness

- The local AP deployment status must not mask Omada adoption failures with an adopting grace window.
- If the controller API returns `Adopt Failed`, failed status/category/type, or `Managed by Others`, PostgreSQL and the List of APs UI must show `ADOPT_FAILED`.
- AP adoption is now manual in Omada, so system retry/adopt endpoints are disabled and return that adoption must be completed in Omada Controller.

## OCP-4.6 — Manual Omada Adoption + Manual WiFi Push

- The List of APs page is now a local cached AP inventory grouped by saved site. It does not adopt APs and does not poll/read Omada while the page is open.
- AP adoption must be performed manually in Omada Controller. 3JCentralPisowifi refreshes the selected site/AP from Omada only when the operator explicitly clicks `Push WiFi Config`.
- WiFi/SSID/customer VLAN configuration is no longer auto-applied when an AP connects or when Sites -> Configuration is saved.
- Operators explicitly push saved WiFi configuration from List of APs using `Push WiFi Config` at the site level or AP level.
- This keeps AP adoption and AP configuration separated so Omada adoption problems do not accidentally trigger SSID/VLAN changes.
- Omada AP detection, AP adopt, retry adopt, and live AP list polling from List of APs are disabled in this manual workflow.
- List of APs delete now explicitly calls Omada delete/forget for the selected AP before marking the local row deleted. If Omada cannot confirm forget/delete, the UI must show a warning and the audit log must record the Omada failure details.
- Cached AP statuses such as `CONFIGURING` are historical database values until a user-triggered Push WiFi Config refreshes the selected site from Omada.

## OCP-4.4 — Manual AP Management VLAN on APs

- Live field testing showed SSIDs can disappear or APs can fall into `Managed by Others` when the system changes the AP's own management VLAN through Omada after adoption while the AP was already manually configured for AP management VLAN.
- The system no longer auto-applies device-side AP management VLAN settings to APs after adoption.
- Network -> MikroTik -> AP Management remains responsible for MikroTik-side transport only: management VLAN interface, DHCP, option 138, raw tracking exceptions, and tagged trunk carrying through router/CRS/OLT/AP paths.
- Operators will manually enable the AP management VLAN in the TP-Link/Omada AP before deploying it to the station path until the Omada AP-side workflow is proven safe.
- AP auto-configuration after adoption is disabled. Managed SSIDs and the station/customer VLAN are pushed only by explicit Push WiFi Config actions.
- AP implementation progress now counts only required AP-side system actions currently managed by 3JCentralPisowifi, typically `2/2`: WiFi SSIDs and SSID Customer VLAN.
- Existing old `ap_management_vlan` checklist entries are ignored and removed by migration so stale `3/3` progress does not hide the current operating model.
- When an AP is factory-reset and manually adopted again in Omada, operators should use Push WiFi Config to recreate the saved SSID/VLAN state.
- Omada AP status code `11` is treated as `CONFIGURING`, not connected. The List of APs page keeps cached configuring APs visible without an active provisioning animation, and the backend does not mark AP configuration `APPLIED` until an explicit Push WiFi Config sync sees a real connected/normal state.
- Omada `CONFIGURING` must not reset an already-applied AP implementation checklist. Otherwise a transient Connected -> Configuring -> Connected cycle can repeatedly reapply/delete/recreate SSIDs and keep the AP stuck in configuration sync.
- Omada `Managed by Others` status/code/category is treated as `ADOPT_FAILED`, not connected. The controller can see the AP, but it cannot push site SSIDs/config until the AP is reset or adopted with the correct credentials.
- A stale Omada IP or stale DHCP lease does not mean the AP is reachable. For AP management troubleshooting, compare the AP MAC in MikroTik bridge host tables against the expected management VLAN. If the AP is expected on VLAN `88` but is learned on another VID such as `201`, fix the VLAN/OLT/ONU/AP management path before expecting Omada to finish Configuring or broadcast managed SSIDs.

## MikroTik IP/VLAN Safety Validation + Replacement Cleanup

- All saved MikroTik Station and central AP Management plans must validate proposed IPs, subnets, pools, and VLAN IDs against the latest successful Prescan All Routers data before any plan can be saved.
- Validation also checks MikroTik router API/management hosts. A planned gateway/subnet must not duplicate or contain an existing MikroTik router host IP, which prevents mistakes such as using `10.111.0.1` for AP management when that IP is already saved as a router access address.
- Station customer VLAN/subnet, AP management VLAN/subnet, DHCP pools, and gateway IP fields are treated as critical network fields and must be rejected on overlap or duplicate with existing scanned RouterOS state unless the existing item is clearly marked as the same system-managed object.
- MikroTik router host add/edit now rejects exact duplicate hosts and rejects router hosts that fall inside active Station or AP Management client subnets.
- When a saved Station or AP Management plan is changed after a previous plan may have been pushed, the system stores a pending cleanup plan for the old system-managed RouterOS objects.
- If an AP Management edit happened before cleanup tracking existed, the system can infer older AP Management cleanup from successful AP Management command history, so old pushed VLANs such as VLAN `111` still appear as remove steps before the current plan is pushed.
- Push Config now shows old cleanup steps first, removes old managed objects one by one, and then pushes the updated config one by one. The modal must show cleanup/apply phases, progress, and stop on first error.
- Central AP Management uses the root gateway for IP-layer objects: VLAN interface IP, DHCP pool, DHCP server, DHCP network, option 138, and LOCAL membership. Downstream CRS/trunk routers only carry the AP management VLAN tag and optional monitoring VLAN interface. If the subnet changes but the VLAN ID remains the same, the CRS should still show that VLAN after the updated config is pushed.
- Configuration cards must show a visible cleanup-pending state after Station or AP Management edits, so operators know the next Push Config will remove old managed objects before applying the new plan.
- Cleanup must only target 3JCentralPisowifi-managed names/comments/objects. The system must not remove unmanaged MikroTik configuration.

## MikroTik Configuration Safety Rule

- Any task that involves writing, changing, removing, enabling, disabling, or otherwise applying MikroTik/RouterOS configuration must be handled as a two-step process.
- Codex must first show the exact RouterOS configuration, command, or API-backed action that will be run, including the target router and the purpose of the change.
- Codex must not apply the MikroTik configuration until the user gives an explicit go signal after seeing the proposed configuration.
- Read-only MikroTik checks, scans, diagnostics, and status queries can still run without this apply approval because they do not change RouterOS state.
- Temporary test configuration must still follow the same rule and must include the cleanup/removal command if a rollback is expected.

## Active Workflow Cleanup — 2026-06-05

- Wallet / Manual Top-Up is removed completely. Do not use or recreate `wallets` or `transactions`; customer access time is represented by WiFi Bag items/events and portal sessions.
- Old Omada Controller install/manage automation remains active. Keep controller install, start, stop, restart, backup, host-network fix, SSH settings, API settings, site detection, and automation logs.
- The active customer access flow is Omada captive portal redirect/enforcement plus Product Items, Physical Store approvals, optional voucher claims, customer WiFi Bag validation, and Omada authorization. Customers should not use WPA2-Enterprise/RADIUS credentials.
- The active MikroTik flow is station transport: VLAN, DHCP, NAT, AP management transport, and raw tracking exceptions. MikroTik HotSpot enforcement is retired.
- The admin UI removes active RADIUS/WPA2-Enterprise lab pages, old Sessions navigation, NAS/RADIUS client management, OpenAI settings, AI Network Assistant, AI explain/chat/smoke-test/draft-plan workflows, MikroTik HotSpot login.html sync, and legacy single-router MikroTik HotSpot setup controls.
- The backend returns `410 Gone` for removed RADIUS, NAS, AI/OpenAI assistant, Omada RADIUS automation, WPA2-Enterprise test SSID, MikroTik HotSpot login.html sync, HotSpot diagnostics, and legacy single-router HotSpot apply endpoints.
- Docker Compose no longer runs the FreeRADIUS service in active staging/production compose files.
- Migration `117_cleanup_retired_wallet_ai_radius_hotspot.sql` drops the retired Wallet, RADIUS/NAS, AI/OpenAI planning, MikroTik HotSpot sync/authorization, Office AP Path, Omada RADIUS lab, and legacy portal template tables. The `sessions` table is temporarily retained only for Customer Devices fallback/history.
- Read-only MikroTik preflight scanning remains active and should continue to label old `/ip hotspot` findings as legacy HotSpot objects for conflict awareness only.

## Office AP Path Transport Retired — 2026-05-25

- The Network -> MikroTik -> Office AP Path tab is removed from the active UI. The working adoption process is now: connect the AP directly to the office subnet, adopt it in Omada, then set the AP management VLAN after successful adoption before moving the AP to the field path.
- Dedicated AP Management remains active for production transport planning. Office-subnet path transport is parked because it adds unnecessary complexity to the current workflow.
- Existing RouterOS objects previously created by Office AP Path must be cleaned up only after Codex previews the exact removal commands and the operator explicitly approves the cleanup. Do not remove unmanaged MikroTik configuration.

## Omada Site Sync — 2026-05-25

- Sites Deployments local records are treated as the system planning source of truth. After an Omada Controller reinstall, those local sites may no longer exist in Omada.
- The Sites page includes a Sync Omada Sites action. It relinks local sites by name when they already exist in Omada, or creates the missing Omada site and saves the new Omada site ID locally.
- Site list rows expose Omada sync status so stale links are visible instead of silently showing old controller IDs.

## Station Voucher Fairness / Anti-Tethering — 2026-05-25

- One voucher is intended for one directly connected customer device. A phone that redeems a voucher must not be able to share that access to other phones through its own hotspot.
- Omada cannot reliably enforce this by itself because tethered devices are hidden behind the authorized phone's NAT. Enforcement belongs on the MikroTik station root gateway where the customer VLAN traffic exits.
- Station Push Config now includes managed one-device voucher fairness rules on the root gateway:
  - `/ip firewall mangle` postrouting TTL clamp to set return traffic to `TTL=1` toward the station client VLAN.
  - `/ip firewall filter` drops for common tethered source TTL values `63` and `127`.
  - If an active forward FastTrack rule exists, station-scoped established/related accept rules are inserted before it so the TTL guard is not bypassed.
- These rules are station-scoped by customer subnet, VLAN interface, and exact `3J Station - ... VLAN {id}` comments.
- Station Remove Config removes only those managed anti-tethering rules by exact comments.
- This blocks normal phone hotspot sharing but is not a cryptographic guarantee. A rooted or deliberately modified client may still attempt TTL manipulation, so future abuse monitoring/counters may be added.

## Captive Portal Product Items — 2026-05-26

- Online Store is the active admin page for defining reusable customer-facing WiFi/IPTV package items with name, price, duration value, duration unit, access type, discounts, status, and sort order. Older code/API names may still use `product_items`, but the user-facing admin page label is `Online Store`.
- Product Categories control what appears in the customer captive portal. Operators create reusable Items first, then assign one or more Items to each Product Category.
- Unassigned Product Items remain in the admin catalog but are not shown in the captive portal.
- Product category/item assignments are stored separately in `product_category_item_assignments` so the same reusable Item can be assigned to multiple categories without duplicating package definitions.
- PayMongo checkout receives both `product_item_id` and `product_category_id` when a customer buys from a category. The backend validates that the selected item is actively assigned to that active category before applying category scope such as Barangay-only access.
- Product Items remain the source of purchasable WiFi/IPTV package duration and pricing for PayMongo hosted checkout. Manual vouchers remain available for events, refunds, and gifts.
- Captive Portal now displays one current portal URL instead of separate staging/production labels. Portal Settings keeps the backend-compatible staging/production columns synchronized to that current URL.
- The Captive Portal Sanity Check tab is retired from the active UI.

## Payment Gateway Phase 1 — PayMongo Settings Foundation — 2026-05-26

- System Settings -> Payments is the active place to configure PayMongo for future GCash purchases.
- Phase 1 stores only gateway settings: enabled flag, PayMongo active mode, API base URL, separate TEST and LIVE public/secret key pairs, separate TEST and LIVE webhook signing secrets, currency, enabled payment methods, success URL, cancel URL, and notes.
- No payment orders, GCash checkout redirect, webhook fulfillment, voucher issuance, wallet top-up, or Omada authorization are performed in Phase 1.
- PayMongo secret keys and webhook signing secrets must never be returned to the frontend in plain text. The UI only shows masked hints and configured/missing status.
- PayMongo webhook signing secrets are created from PayMongo's Webhooks module after a webhook endpoint exists. They may be blank during the settings-only phase.
- Phase 1 was superseded by Phase 2 checkout foundation. Keep the same credential safety rules.

## Payment Gateway Phase 2 — PayMongo GCash Checkout Foundation — 2026-05-26

- System Settings -> Payments now uses tabs for separate Test Keys and Live Keys while keeping a single active checkout mode selector.
- Captive portal Product Items can start PayMongo hosted checkout for GCash when payments are enabled and the active mode has a public key, secret key, and GCash enabled.
- Checkout creates a local `payment_orders` record first, then sends the customer to PayMongo. Redirect return URLs are only status hints and must never grant internet access by themselves.
- PayMongo webhook endpoint: `/api/payments/paymongo/webhook`.
- Webhook fulfillment verifies the `Paymongo-Signature` header with the configured test/live webhook signing secret, checks the paid amount against the local order, creates a system voucher for the Product Item duration, and then uses the existing Omada/MikroTik portal authorization path to grant access.
- If the webhook secret is missing, invalid, delayed outside the tolerance window, or the paid amount does not match the order, the order is not fulfilled.
- PayMongo secret keys, webhook secrets, and raw sensitive payment details must not be returned to the frontend. Stored webhook/API responses must remain sanitized.
- Next payment phase should add an admin payment orders/reconciliation view, refund/manual resolution controls, and live-mode operational checks.

## Captive Portal Customer Profile, Welcome Gift, and Support — 2026-05-28

- The customer portal first screen is a No Internet page with operator-managed connected/disconnected avatar images, editable headline text, Buy Now action, and disabled Login placeholder.
- Portal Design is its own Captive Portal admin tab. It owns No Internet page settings, avatar uploads, profile welcome gift settings, avatar notes, and the editable marketing SMS consent text shown during customer profile registration.
- Customer profile save requires name, unique verified contact number, optional email, terms/data consent, and optional marketing SMS consent. Contact verification uses the existing A2P Messaging integration with a 4-character code.
- Saving a verified customer profile creates a one-time welcome gift voucher using the operator-configured Portal Design -> Welcome Gift duration and copy. It does not activate automatically. The portal shows a clickable gift below the avatar until the customer unwraps and redeems it.
- Contact number uniqueness is the anti-abuse control for welcome gifts and is also used by the Report Missing Time flow to recover active remaining time after random MAC/device changes.
- Message Admin is in-system support chat, not SMS. Customers send messages from the portal Help button; admins answer from the Support Inbox page.
- PayMongo checkout orders now store customer profile name/email/contact when available and include those values in sanitized PayMongo metadata. PayMongo-hosted checkout may still ask for customer information if PayMongo does not prefill it from metadata.
- Captive portal page backgrounds must cover the full viewport in both desktop and mobile dark/light modes so no white page strip appears around the portal shell.

## Captive Portal Customer Bag and Seamless Auto Activation — 2026-06-01

- Paid Product Items are no longer treated as one merged timer. A successful PayMongo payment creates a separate customer bag item with its own duration, product/category, priority, status, and history.
- Customers can open My WiFi Bag from the portal, see the active item, queued items, and consumed history, and drag queued items to choose activation priority.
- Auto Activate can be enabled per customer bag. When enabled, the next queued item is activated 10 seconds before the current item ends so the customer should not feel the package transition.
- Bag history records whether Auto Activate was enabled when an item was consumed.
- Purchases made outside a 3J AP can be saved to the bag. Omada/MikroTik authorization still only happens when the customer is connected through a supported 3J captive portal session.
- The deterministic backend still performs gateway authorization. The frontend bag UI cannot grant internet access by itself.
- If an Omada client is redirected back to the captive portal while the local DB still shows active bag time, do not trust only the latest local `omada_portal_authorizations` success row. Verify the live Omada hotspot authorized-client row is still `valid` and covers the target expiry; if Omada marks it invalid or too short, re-authorize the client with the full redirect context (`site`, `siteId`, `siteName`, `clientMac`, `clientIp`, `apMac`, `ssidName`, `radioId`, `token`/`t`, and millisecond `time`).

## Shared Device Pass / Multi-Pass Removed — 2026-06-07

- Shared Device Pass / Multi-Pass is retired and must not be reintroduced without a new approved design. Product Items, Physical Store Items, PayMongo orders, store purchase requests, vouchers, and My WiFi Bag items are now single-customer-device access products.
- The captive portal must not show Single Pass vs Multi-Pass selection, share icons, QR/code/phone sharing flows, saved shared-device lists, or shared-access status panels.
- Customer Devices and admin time management must operate on customer-owned product/voucher bag items only. There is no shared-access revoke endpoint or shared owner/pass relationship in the active workflow.
- Vouchers remain active for events, refunds, welcome gifts, and manual customer support. Claiming a voucher adds/activates a normal single-device WiFi Bag item.
- Anti-tethering/fairness rules remain active at the MikroTik station root gateway. Removing Multi-Pass does not remove the TTL guard that blocks phone hotspot sharing.
- Migration `125_remove_shared_device_pass.sql` normalizes historical records to single-device values, drops `customer_bag_item_shares`, and removes `device_scope` / `allowed_devices` columns from active product, payment, bag, and store-purchase tables. Historical migrations may still contain those old columns because they document past schema evolution.

## IPTV-1 / IPTV-2 — IPTV Web + XUI Auto-Provisioning — 2026-06-07

- IPTV is now modeled as a Product Item access type. Paid purchases create queued WiFi Bag items; XUI provisioning waits until the customer activates an IPTV-capable item.
- Current IPTV topology: IPTV web app/player runs internally at `192.168.50.15:3000`, private XUI server is `10.100.100.100`, public hostname is `tv.3jhotspot.com`, and local diagnostic access uses `http://192.168.50.15` through a port-80 reverse proxy.
- On 2026-06-07, the IPTV web app was verified reachable from both the app host and the API container at `http://192.168.50.15:3000`; the CCR also reached it from source `10.77.0.1`.
- On 2026-06-07, `tv.3jhotspot.com` was confirmed working.
- Customers connected to a 3J/AP network should normally watch IPTV through the local URL `http://192.168.50.15/watch` so IPTV-only playback stays inside the local network and does not consume public tunnel/internet bandwidth. Do not send captive clients directly to `:3000`; Omada Pre-Auth Access can allow the IPTV web server IP, but not an IP plus port, so nginx on the IPTV web server must proxy `192.168.50.15:80 -> 127.0.0.1:3000`.
- Customers outside the 3J/AP network use the public fallback `https://tv.3jhotspot.com/watch`. If local IPTV times out while connected to a 3J AP, first verify Omada Pre-Auth Access includes `192.168.50.15`, WiFi guest/LAN isolation is not blocking the office-local host, and the station root allows `10.77.0.0/24 -> 192.168.50.15:80`.
- XUI admin/provisioning endpoints must stay private/internal and must not be exposed through MikroTik NAT or customer-facing JavaScript. Customer browser playback may use a dedicated Cloudflare Tunnel hostname for XUI media/artwork, currently `https://xui.3jhotspot.com`, when the customer is outside the 3J AP network.
- Admin -> IPTV is the primary UI for IPTV public hostname setup, IPTV web reachability, optional IPTV web SSH diagnostics, XUI connectivity, and XUI provisioning review. IPTV is intentionally separate from System Settings.
- Cloudflare Tunnel public hostname for IPTV should be: hostname `tv.3jhotspot.com`, service type `HTTP`, service URL `http://192.168.50.15:3000`. The existing Cloudflare connector can route to this URL because the API/container side can reach it.
- Long-term IPTV HTTPS uses a dedicated Cloudflare Tunnel connector running on the IPTV web server itself. In the IPTV web app admin portal, Settings -> Public HTTPS manages `tv.3jhotspot.com` and points Cloudflare to `http://127.0.0.1:3000` on that IPTV server. Keep `net.3jhotspot.com` on the hotspot server tunnel and keep XUI private.
- XUI browser/media HTTPS is separate from IPTV web HTTPS. In the IPTV web app admin portal, Settings -> XUI HTTPS manages the `xui.3jhotspot.com` Cloudflare Tunnel connector by SSHing into the XUI One server, storing the connector token and SSH secrets encrypted, and installing/running `3j-xui-https-cloudflared.service` on the XUI host. Do not run the `xui.3jhotspot.com` connector from the hotspot server or expose XUI through MikroTik NAT.
- IPTV web SSH credentials are optional diagnostics only. The page follows the Omada SSH settings pattern for host, port, username, auth type, sudo mode, password/private key, and passphrase. Secrets are encrypted, masked in the frontend, and only used by the `Test SSH Login` action. The system must not log or display the raw SSH/root password/private key.
- Admin -> IPTV stores IPTV web URL, IPTV web SSH host/port/user/auth/sudo settings, IPTV web integration secret, watch-token TTL, XUI base URL, XUI public browser tunnel URL, XUI public tunnel connector token, XUI server host, optional XUI admin username/password, optional XUI API key, optional XUI access code/path, max connections, and optional disposable XUI player test line. The IPTV page uses top-level `Status`, `Provisioning`, `Settings`, and `Logs` tabs; inside `Settings`, IPTV Web and XUI are separated into nested tabs. XUI passwords/API keys, XUI tunnel tokens, and IPTV web integration secrets are encrypted and only masked hints are returned to the frontend.
- Retire legacy XUI playback server lists such as `https://tv1.3jxentro.net/` and `https://tv2.3jxentro.net/`. Do not manage XUI playback origins from the IPTV web Secrets page. Use the XUI Integration/Public Playback Tunnel URL instead.
- IPTV web must normalize stale customer/session `streamBase` values that still point to retired `tv*.3jxentro.net` hosts into the configured XUI public playback tunnel, currently `https://xui.3jhotspot.com`, before calling `player_api.php`. On 2026-06-09, `tv2.3jxentro.net` no longer resolved and caused `/api/xuione/series` 502s until the IPTV web app normalized old stream bases and `.env.local` `XUIONE_URLS` was updated.
- The IPTV web production service runs with `NEXT_DIST_DIR=.next-runtime`. After source edits on the IPTV web server, build with the safe runtime sequence: stop `3j-tv.service`, run `RUNTIME_SERVICE_NAME=3j-tv.service npm run build:runtime`, then start `3j-tv.service`. A plain `npm run build` updates `.next` only and will not affect production.
- IPTV connection tests verify the IPTV web app URL, public IPTV URL, XUI playback base URL, optional IPTV web SSH, optional `player_api.php` test account, and read-only XUI access-code API by calling `get_bouquets`. Actual XUI account create/sync happens only from IPTV item activation/provisioning jobs or explicit admin retry/run actions.
- XUI playback and XUI admin provisioning can use different URL schemes on the same host. In the current deployment, `player_api.php` is kept on `http://10.100.100.100`, while the access-code admin API is reached through the HTTPS scheme variant. The provisioning worker must try the access-code API scheme variant without changing the playback base returned to the IPTV web app.
- XUI access-code `create_line` / `edit_line` rejects Unix timestamps for `exp_date` with `STATUS_INVALID_DATE`. Send `exp_date` as an ISO UTC string such as `2026-06-08T08:12:19Z`. Do not send `is_trial=0` to this API path; use `trial=0` only, because this panel can convert `is_trial=0` back into trial behavior.
- Customer flow: buy IPTV product -> system stores the item in My WiFi Bag without creating a line yet -> customer activates the IPTV item in My WiFi Bag or through auto-activate -> the backend reuses an active customer XUI line when one exists, otherwise creates a new never-expire non-restreamer line with Access Outputs enabled -> IPTV entitlement time displays as its own remaining-time card -> customer clicks Watch IPTV from Google Chrome -> hotspot portal creates a short-lived 3J token -> customer is redirected to `http://192.168.50.15/watch?threej_token=...` when connected to a 3J AP, otherwise `https://tv.3jhotspot.com/watch?threej_token=...` -> IPTV web app resolves the token server-to-server and logs the customer into the existing IPTV web session. If the customer taps Watch IPTV inside a captive sign-in browser/WebView, the portal must show a Chrome reminder modal and must not redirect to IPTV.
- IPTV Chrome reminder logic must block actual captive sign-in browsers/WebViews only. Omada/captive query parameters can remain in a normal Chrome URL after redirect, so captive query parameters alone must not trigger the Chrome reminder modal.
- IPTV watch-session expiry UX is configured in Admin -> IPTV -> Settings -> IPTV Web. `Expiry Warning` defaults to 10 minutes and `Player Stop Window` defaults to 10 seconds. The IPTV web app must poll the hotspot status endpoint, show a top overlay toast during the warning window, exit/stop playback during the stop window, and send the customer back to the portal URL.
- Cloudflare Turnstile on the IPTV web app must protect manual public/admin login flows only. Do not require Turnstile for `GET /watch?threej_token=...`, `POST /api/auth/threej-token`, or `POST /api/auth/threej-status`; these are trusted server-issued 3J token handoff paths. If token handoff fails, the customer fallback must return to `https://net.3jhotspot.com/portal`, not `/login`.
- IPTV token handoff must trust a valid 3J-issued token after the hotspot API resolves it. The IPTV web app must not run a blocking XUI `player_api.php` precheck during `POST /api/auth/threej-token`; XUI reachability/precheck timeout must not block session creation when the 3J token has already resolved to a provisioned active line. Let normal playback/catalog calls surface any remaining upstream issue.
- IPTV web XUI routing must not blindly remap public XUI hostnames to private DNS addresses for local requests. Only use a private remap when the IPTV web server can actually connect to that private origin; otherwise keep the configured public XUI hostname so the token handoff does not store a dead `10.x.x.x` stream server.
- Product Items support access types: `WIFI`, `IPTV`, and `WIFI_IPTV`. Existing products default to `WIFI`.
- IPTV-capable products no longer use an XUI package/bouquet selector. By project decision, all bouquets are assigned by the XUI panel default for newly provisioned lines.
- PayMongo checkout snapshots the Product Item access type into `payment_orders`; successful payment creates a customer bag item with the same access type. IPTV provisioning waits until activation.
- `WIFI` products continue normal Omada hotspot authorization. `WIFI_IPTV` products continue normal WiFi authorization and also provision IPTV during activation. `IPTV`-only products activate IPTV entitlement time only; they do not grant general hotspot internet and must not call the Omada/MikroTik internet authorization path.
- Omada Pre-Auth Access must include the captive portal/payment hosts plus IPTV web hosts (`192.168.50.15` and `tv.3jhotspot.com`) so IPTV-only users can open the local/public IPTV player while general internet remains blocked.
- New IPTV provisioning tables are `iptv_accounts`, `iptv_provisioning_jobs`, and `iptv_login_tokens`. `customer_bag_items` now references the IPTV account and provisioning/watch state.
- IPTV XUI lines are reusable while the customer still has active IPTV time. `iptv_accounts.user_id` must not be unique. `iptv_accounts.bag_item_id` identifies the item that originally created the line, but later active items may reference the same `iptv_account_id`. Consumed or admin-removed IPTV items must stop local 3J access immediately and expire watch tokens. Mark the account `PENDING_DELETE` only when no other active IPTV item still uses that account, then delete the XUI line after a short grace period before marking the local IPTV account `DELETED`.
- XUI.ONE flood protection can block the IPTV web server or router source IP when stale player/browser retries keep requesting a deleted line. On 2026-06-09, XUI `blocked_ips` contained `192.168.50.15` and `10.100.100.1` with reason `FLOOD ATTACK`; this was caused by repeated `AUTH_FAILED` requests for deleted disposable line credentials. If IPTV web cannot reach XUI while other clients can, inspect XUI blocked IPs first. The internal XUI setting `flood_ips_exclude` may act as a whitelist in some builds but may not be exposed in the GUI; do not edit it directly without a DB backup and rollback plan.
- IPTV web `/watch` token handoff must have a timeout fallback. If token login cannot finish in time, show a clear server-unreachable message, a 10-second return-to-portal countdown, and a manual return button instead of leaving the customer on an endless checking screen.
- IPTV customer login failures must notify admins through `admin_notifications` with category `IPTV_LOGIN_FAILED`. These alerts must appear in the top-right Notifications drawer and the full Admin Profile -> Notifications page. The IPTV web server reports token-handoff failures to `/api/iptv/session/login-failure` using the IPTV integration secret when the hotspot API is reachable; the hotspot token resolve endpoint also creates notifications for valid-secret token/account/provisioning failures.
- The customer frontend cannot grant IPTV or WiFi access by itself. WiFi access still requires deterministic backend authorization. IPTV access requires a provisioned XUI account plus a server-issued short-lived watch token.
- The IPTV web app now has a `/watch` token handoff and `/api/auth/threej-token` resolver. The resolver calls the hotspot API `/api/iptv/session/resolve` with the saved integration secret and then stores the same session shape used by the existing IPTV login flow.
- The hotspot portal must never expose raw XUI credentials. The IPTV web app currently reuses its existing session model after token resolution; a future hardening phase can move IPTV playback session storage fully server-side.

## Global UI Success Messages — 2026-06-07

- All transient user-facing messages should use toaster/toast UI components by default, not inline banners.
- Admin success messages should use the shared `AutoDismissAlert` success path, which renders a green Tabler-style toast in the upper-right corner.
- Default toast duration is 6 seconds and every toast must include a close button.
- Keep long-running progress panels, command review panels, and interactive result panels inline when the user needs to inspect steps or use actions such as copy/print.

## 2026-06-18 — 3JTV Customer/IPTV API
- The 3JTV API documentation/status page moved from the main sidebar into `System Settings -> API`.
- Token-protected local-network endpoints under `/api/integrations/3jtv` are used by the 3J TV project for customer sync:
  - `GET /health` returns API status plus contactable, active-IPTV, and inactive-IPTV counts.
  - `GET /customers` returns Profiled Customers with contact numbers only.
  - `GET /iptv-customers?status=all|active|inactive` returns only contactable customers with IPTV provisioning history. Active rows have current IPTV time and an XUI username; inactive rows have IPTV history but no current active IPTV access.
- XUI lines are not treated as customers. They are exposed only as access-status fields linked to profiled customers from Customer Devices -> Profiled Customers and IPTV -> Provisioning.
- 2026-06-18 update: `/api/integrations/3jtv/iptv-customers` now includes an `iptv_accounts` array for each profiled customer so 3J TV can show one inactive customer row and a View modal listing all historical XUI usernames/accounts.

## 2026-06-28 — Monthly Subscriber Captive Portal Login

- Monthly subscriber hotspot access is sourced from 3J Main Account Admin. Pisowifi is the captive portal target and must not be treated as the source of monthly subscription truth.
- New admin navigation: `Monthly Subscribers`. It shows inbound integration settings, subscriber/contact KPIs, synced subscriber rows, device bindings, and recent sync logs.
- Inbound signed endpoint:
  - `GET /api/integrations/monthly-subscribers/health`
  - `POST /api/integrations/monthly-subscribers/upsert`
- Signed requests use `X-3J-Integration-Key`, `X-3J-Timestamp`, `X-3J-Signature`, and `X-3J-Idempotency-Key`. The signature is HMAC-SHA256 over `<timestamp>.<raw request body>` using the Monthly Subscribers API secret.
- The upsert payload supports `sync_mode`. `FULL`/`SYNC_ALL`/`AUTHORITATIVE` means 3J Main is sending the complete current subscriber list, so Pisowifi marks missing subscribers inactive, disables their contacts, and revokes monthly subscriber gateway authorization. `PARTIAL` only updates submitted rows.
- When a monthly contact is disabled, removed, or reset, Pisowifi clears monthly subscriber authorization for linked portal sessions and then syncs gateway access to any active paid WiFi Bag item before revoking Omada access.
- The Monthly Subscribers admin page surfaces the latest sync mode plus disabled subscriber/contact and revoked-session counts from recent sync logs. Use this page to verify whether a full sync actually removed stale monthly access.
- Monthly Subscribers now includes an `Active Monthly Sessions` operations table. It shows currently bound monthly subscriber devices, device/network details, remaining rolling authorization, gateway status, and actions to re-authorize, revoke monthly access, or reset the contact's device binding.
- New tables are `monthly_subscriber_settings`, `monthly_subscribers`, `monthly_subscriber_contacts`, `monthly_subscriber_login_challenges`, and `monthly_subscriber_sync_logs`. `portal_sessions` now stores the monthly contact binding and rolling authorization state.
- Captive portal Login is enabled for monthly subscribers. The user enters a registered contact number, receives an A2P OTP, and on success the contact number is bound to the current portal device.
- One monthly contact number equals one allowed device. If the same contact is already bound to another device, the portal rejects login until an admin resets the binding from `Monthly Subscribers`.
- Monthly subscriber access displays as unlimited to the customer, but Omada still receives a rolling authorization duration configured in Monthly Subscribers settings.
- Monthly subscriber login must still use Omada captive portal authorization. The frontend cannot grant access by itself.
