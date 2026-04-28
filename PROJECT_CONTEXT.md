# 3JCentralPisowifi Project Context

Every future AI agent, developer, or maintainer must read this file before changing the project. Update it whenever architecture, deployment, features, commands, branches, workflows, or decisions change.

## 1. Project overview
3JCentralPisowifi is an admin-managed WiFi access control foundation for manual RADIUS testing. Phase 1 establishes the source-of-truth database, admin portal, installer/updater, and FreeRADIUS integration.

## 2. Business goal
Create a dependable central system where operators can manage test WiFi users, manual time balance, NAS/router/AP clients, RADIUS authentication, and accounting records before later commercial integrations are considered.

## 3. Current phase
Phase 1: Source of Truth + Manual RADIUS Test MVP.

## 4. Phase 1 scope
- One-line Ubuntu installer and updater.
- Separate production and staging deployments on the same server.
- PostgreSQL as the source of truth.
- FreeRADIUS connected to PostgreSQL-backed application rules.
- Admin Portal at `/admin`.
- Admin login, manual user creation, manual balance top-up, NAS/router/AP client management.
- RADIUS authentication testing and accounting/session tracking.
- Single-device rejection using active session grace logic.

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
- RADIUS: `1812/udp`, `1813/udp`

Staging:
- Branch: staging
- Install path: `/opt/3jcentralpisowifi-staging`
- Compose project: `centralwifi_staging`
- Database: `centralwifi_staging`
- Volumes: `centralwifi_staging_postgres_data`, `centralwifi_staging_redis_data`
- Web: `8080/tcp`
- RADIUS: `11812/udp`, `11813/udp`

## 9. Production server details
Production runs from `/opt/3jcentralpisowifi-production` using `/opt/3jcentralpisowifi-production/.env`. It tracks `master` and exposes the Admin Portal at `http://SERVER-IP/admin`.

## 10. Staging server details
Staging runs from `/opt/3jcentralpisowifi-staging` using `/opt/3jcentralpisowifi-staging/.env`. It tracks `staging` and exposes the Admin Portal at `http://SERVER-IP:8080/admin`.

## 11. Technical architecture
Nginx reverse proxy routes `/admin` to the React admin portal and `/api` to FastAPI. FastAPI manages source-of-truth data in PostgreSQL, serves uploaded branding assets from an environment-specific Docker volume, and uses Redis for health/cache readiness. FreeRADIUS handles UDP RADIUS auth/accounting and calls local helper scripts that enforce rules using PostgreSQL.

## 12. Source of truth explanation
PostgreSQL is the only source of truth for admins, users, wallets, NAS/router/AP clients, transactions, sessions, audit logs, and auth logs. Network devices are clients of the RADIUS service and must not become the user database.

## 13. Tech stack
- Ubuntu 22.04+
- Docker and Docker Compose
- FastAPI on Python 3.11+
- PostgreSQL
- Redis
- FreeRADIUS 3.x
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
- Users
- Wallet / Manual Top-Up
- Sessions
- NAS / Router / AP Clients
- RADIUS Test Guide
- System Health
- Settings
- Audit Logs

UI direction:
- Admin Portal uses installed/imported Tabler UI packages, not the removed temporary template.
- Admin Portal follows the project owner's previous common UI order for shared admin features: dark vertical sidebar, sticky top header with CPU/RAM/DISK/UPTIME metrics, card-based pages, profile/password/logout behind a sidebar account dropdown, and tabbed System Settings.
- System Settings tab order is General, Access, System Update, Backup, Danger. The General tab contains Branding, including Company Logo, Browser Page Logo, System Display Name, Portal Subtitle, and Accent Color.
- Do not copy old-system product names.
- Keep the UI focused on Phase 1 workflows instead of importing unrelated old-system modules.

## 17. RADIUS behavior
Access-Accept requires an active user, valid password, usable balance or valid-until or unlimited flag, and no active session inside `ACTIVE_SESSION_GRACE_SECONDS`. Access-Reject is returned for unknown users, invalid passwords, disabled users, no balance/expired access, or active single-device conflict. Accounting Start, Interim-Update, and Stop update the sessions table; Interim-Update decrements time balance without allowing negative balance.

## 18. Database tables
Application tables: `admins`, `users`, `wallets`, `transactions`, `nas_clients`, `radius_auth_logs`, `sessions`, `audit_logs`.

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

## 24. Changelog section
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
