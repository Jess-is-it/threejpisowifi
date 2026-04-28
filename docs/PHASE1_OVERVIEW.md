# Phase 1 Overview

Phase 1 builds the operational foundation for 3JCentralPisowifi.

It includes:
- One-line Ubuntu install and update.
- Separate production and staging deployments.
- PostgreSQL source-of-truth schema.
- FastAPI backend.
- React Admin Portal.
- FreeRADIUS authentication and accounting helpers.
- Manual user creation and manual time balance.
- NAS / Router / AP client records.
- Session tracking and single-device rejection.

Phase 1C adds real RADIUS Accounting Start, Interim-Update, and Stop support. Accounting packets create active sessions, update last seen/device metadata, deduct wallet time through ACCOUNTING DEBIT transactions, and close sessions on Stop. Active accounting sessions are now the basis for single-device rejection.

Admin test paths:
- Simulated RADIUS Decision Test: backend-only source-of-truth decision check.
- Real FreeRADIUS Authentication Test: real Access-Request from API container to FreeRADIUS.
- Real RADIUS Accounting Test: real Accounting-Request packets for Start, Interim-Update, and Stop.

It does not include coinslot, vendo, SMS, online payments, self-registration, dynamic VLAN, controller automation, WireGuard automation, production captive portal flow, or HA clustering.
