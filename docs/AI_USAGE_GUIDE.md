# AI Usage Guide

Future AI agents must read `/PROJECT_CONTEXT.md` before making changes.

Rules:
- Always update `/PROJECT_CONTEXT.md` whenever architecture, deployment, features, commands, branches, workflows, or decisions change.
- Never implement parked features unless the project owner explicitly asks.
- Keep Phase 1 focused on Source of Truth + Manual RADIUS Test MVP.
- Preserve the production/staging deployment model.
- Production tracks `master`; staging tracks `staging`.
- Keep secrets in environment-specific `.env` files and never commit generated secrets.
