# Database Source Of Truth

PostgreSQL is the source of truth for Phase 1.

The system stores admins, users, wallets, NAS/router/AP clients, transactions, RADIUS auth logs, sessions, and audit logs in PostgreSQL. FreeRADIUS reads and updates PostgreSQL through helper scripts and compatible SQL tables.

Phase 1C accounting source-of-truth rules:
- `sessions` records the current and historical online state for users.
- `radius_accounting_logs` stores every Accounting Start, Interim-Update, and Stop diagnostic.
- `wallets.time_remaining_seconds` is deducted only from accounting elapsed time.
- `transactions` records ACCOUNTING DEBIT rows for wallet time deductions.
- `radacct` may remain available for FreeRADIUS compatibility, but application session state is bridged into the custom `sessions` table.

Network devices are RADIUS clients. They must not become the user database.
