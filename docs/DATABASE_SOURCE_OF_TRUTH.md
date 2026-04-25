# Database Source Of Truth

PostgreSQL is the source of truth for Phase 1.

The system stores admins, users, wallets, NAS/router/AP clients, transactions, RADIUS auth logs, sessions, and audit logs in PostgreSQL. FreeRADIUS reads and updates PostgreSQL through helper scripts and compatible SQL tables.

Network devices are RADIUS clients. They must not become the user database.
