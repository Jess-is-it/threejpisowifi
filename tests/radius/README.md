# RADIUS Tests

Manual Phase 1 RADIUS tests are documented in `docs/RADIUS_TESTING.md`.

Acceptance cases:
- Correct username/password with manual balance returns Access-Accept.
- Wrong password returns Access-Reject.
- Disabled user returns Access-Reject.
- No balance returns Access-Reject.
- Active session causes same-user second login rejection.
- Accounting Start, Interim-Update, and Stop update sessions.
