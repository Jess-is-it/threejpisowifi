"""init schema + radius functions

Revision ID: 0001_init
Revises:
Create Date: 2026-01-29
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enums
    # Create enums explicitly (checkfirst) and prevent SQLAlchemy from trying again during table creation.
    user_status = postgresql.ENUM("ACTIVE", "SUSPENDED", name="userstatus", create_type=False)
    plan_type = postgresql.ENUM("TIME", "DATE", "UNLIMITED", name="plantype", create_type=False)
    txn_source = postgresql.ENUM("PAYMENT", "COIN", "ADMIN", name="transactionsource", create_type=False)
    device_status = postgresql.ENUM("ACTIVE", "DISABLED", name="devicestatus", create_type=False)
    admin_status = postgresql.ENUM("ACTIVE", "DISABLED", name="adminstatus", create_type=False)

    user_status.create(op.get_bind(), checkfirst=True)
    plan_type.create(op.get_bind(), checkfirst=True)
    txn_source.create(op.get_bind(), checkfirst=True)
    device_status.create(op.get_bind(), checkfirst=True)
    admin_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "admins",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("status", admin_status, nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("phone", sa.String(length=32), nullable=False, unique=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("radius_password", sa.String(length=128), nullable=False),
        sa.Column("status", user_status, nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "wallets",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("time_remaining_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("valid_until_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_unlimited", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    op.create_table(
        "plans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("type", plan_type, nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("price", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column("metadata", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
    )

    op.create_table(
        "transactions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", txn_source, nullable=False),
        sa.Column("amount_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("amount_money", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column("ref", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_transactions_user_id", "transactions", ["user_id"])

    op.create_table(
        "nas",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False, unique=True),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("nasname", sa.String(length=64), nullable=False, unique=True),
        sa.Column("shortname", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("type", sa.String(length=30), nullable=False, server_default="other"),
        sa.Column("ports", sa.Integer(), nullable=True),
        sa.Column("server", sa.String(length=64), nullable=True),
        sa.Column("community", sa.String(length=50), nullable=True),
        sa.Column("description", sa.String(length=200), nullable=True),
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("nas_id", sa.Integer(), sa.ForeignKey("nas.id", ondelete="SET NULL"), nullable=True),
        sa.Column("calling_station_id", sa.String(length=64), nullable=False),
        sa.Column("acct_session_id", sa.String(length=128), nullable=True),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_update", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("stop", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_last_update", "sessions", ["last_update"])
    op.create_index(
        "ix_sessions_active_user",
        "sessions",
        ["user_id"],
        postgresql_where=sa.text("stop IS NULL"),
    )
    op.create_index(
        "ix_sessions_active_user_mac",
        "sessions",
        ["user_id", "calling_station_id"],
        postgresql_where=sa.text("stop IS NULL"),
    )

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(length=128), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("token_enc", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", device_status, nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("wallet_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "device_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("device_id", "nonce", name="uq_device_nonce"),
    )

    op.create_table(
        "webhook_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("kind", "idempotency_key", name="uq_webhook_kind_idempo"),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=False),
        sa.Column("object_id", sa.String(length=64), nullable=False),
        sa.Column("details", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "sms_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("to_phone", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="SENT"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # RADIUS functions (FreeRADIUS uses these via SQL expansions).
    op.execute(
        sa.text(
            r"""
CREATE OR REPLACE FUNCTION cw_wallet_is_valid(p_user_id int)
RETURNS boolean
LANGUAGE sql
AS $$
  SELECT
    COALESCE(w.is_unlimited, false)
    OR (w.valid_until_ts IS NOT NULL AND w.valid_until_ts > now())
    OR COALESCE(w.time_remaining_seconds, 0) > 0
  FROM wallets w
  WHERE w.user_id = p_user_id;
$$;

CREATE OR REPLACE FUNCTION cw_radius_is_allowed(p_username text, p_calling_station_id text, p_grace_seconds int)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  uid int;
  other_session boolean;
  ok_wallet boolean;
BEGIN
  SELECT u.id INTO uid FROM users u WHERE u.username = p_username AND u.status = 'ACTIVE'::userstatus;
  IF uid IS NULL THEN
    RETURN false;
  END IF;

  SELECT cw_wallet_is_valid(uid) INTO ok_wallet;
  IF NOT ok_wallet THEN
    RETURN false;
  END IF;

  SELECT EXISTS(
    SELECT 1
    FROM sessions s
    WHERE s.user_id = uid
      AND s.stop IS NULL
      AND s.last_update >= (now() - make_interval(secs => p_grace_seconds))
      AND s.calling_station_id <> p_calling_station_id
  ) INTO other_session;

  IF other_session THEN
    RETURN false;
  END IF;

  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION cw_radius_reject_message(p_username text, p_calling_station_id text, p_grace_seconds int)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
  uid int;
  ok_wallet boolean;
  other_session boolean;
BEGIN
  SELECT u.id INTO uid FROM users u WHERE u.username = p_username;
  IF uid IS NULL THEN
    RETURN 'Unknown user';
  END IF;

  IF (SELECT u.status FROM users u WHERE u.id = uid) <> 'ACTIVE'::userstatus THEN
    RETURN 'User disabled';
  END IF;

  SELECT cw_wallet_is_valid(uid) INTO ok_wallet;
  IF NOT ok_wallet THEN
    RETURN 'No active plan';
  END IF;

  SELECT EXISTS(
    SELECT 1
    FROM sessions s
    WHERE s.user_id = uid
      AND s.stop IS NULL
      AND s.last_update >= (now() - make_interval(secs => p_grace_seconds))
      AND s.calling_station_id <> p_calling_station_id
  ) INTO other_session;
  IF other_session THEN
    RETURN 'Already logged in on another device';
  END IF;

  RETURN 'Rejected';
END;
$$;

CREATE OR REPLACE FUNCTION cw_radius_session_timeout_seconds(p_username text)
RETURNS int
LANGUAGE plpgsql
AS $$
DECLARE
  uid int;
  w wallets%ROWTYPE;
BEGIN
  SELECT u.id INTO uid FROM users u WHERE u.username = p_username;
  IF uid IS NULL THEN
    RETURN 0;
  END IF;
  SELECT * INTO w FROM wallets WHERE user_id = uid;
  IF w.is_unlimited OR (w.valid_until_ts IS NOT NULL AND w.valid_until_ts > now()) THEN
    RETURN 0;
  END IF;
  RETURN LEAST(GREATEST(COALESCE(w.time_remaining_seconds, 0), 0), 3600);
END;
$$;

CREATE OR REPLACE FUNCTION cw_radius_touch_session(
  p_username text,
  p_calling_station_id text,
  p_nas_ip text,
  p_acct_session_id text
)
RETURNS int
LANGUAGE plpgsql
AS $$
DECLARE
  uid int;
  nasid int;
  sid int;
BEGIN
  SELECT u.id INTO uid FROM users u WHERE u.username = p_username AND u.status = 'ACTIVE'::userstatus;
  IF uid IS NULL THEN
    RETURN NULL;
  END IF;

  SELECT n.id INTO nasid FROM nas n WHERE n.ip = p_nas_ip;

  SELECT s.id INTO sid
  FROM sessions s
  WHERE s.user_id = uid AND s.stop IS NULL AND s.calling_station_id = p_calling_station_id
  ORDER BY s.last_update DESC
  LIMIT 1
  FOR UPDATE;

  IF sid IS NOT NULL THEN
    UPDATE sessions
      SET last_update = now(),
          nas_id = nasid,
          acct_session_id = COALESCE(p_acct_session_id, acct_session_id)
      WHERE id = sid;
    RETURN sid;
  END IF;

  INSERT INTO sessions(user_id, nas_id, calling_station_id, acct_session_id, start, last_update, stop)
    VALUES(uid, nasid, p_calling_station_id, p_acct_session_id, now(), now(), NULL)
    RETURNING id INTO sid;
  RETURN sid;
END;
$$;

CREATE OR REPLACE FUNCTION cw_radius_accounting(
  p_username text,
  p_calling_station_id text,
  p_nas_ip text,
  p_acct_session_id text,
  p_status_type text
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  uid int;
  nasid int;
  sid int;
  prev_last timestamptz;
  delta_seconds int;
  w wallets%ROWTYPE;
BEGIN
  SELECT u.id INTO uid FROM users u WHERE u.username = p_username;
  IF uid IS NULL THEN
    RETURN;
  END IF;

  SELECT n.id INTO nasid FROM nas n WHERE n.ip = p_nas_ip;

  -- Find an existing active session for this device (preferred), else by acct_session_id.
  SELECT s.id, s.last_update INTO sid, prev_last
  FROM sessions s
  WHERE s.user_id = uid
    AND s.stop IS NULL
    AND (s.calling_station_id = p_calling_station_id OR (p_acct_session_id IS NOT NULL AND s.acct_session_id = p_acct_session_id))
  ORDER BY s.last_update DESC
  LIMIT 1
  FOR UPDATE;

  IF sid IS NULL THEN
    -- Create a new session on Start/Interim if missing.
    INSERT INTO sessions(user_id, nas_id, calling_station_id, acct_session_id, start, last_update, stop)
      VALUES(uid, nasid, p_calling_station_id, p_acct_session_id, now(), now(), NULL)
      RETURNING id, last_update INTO sid, prev_last;
  END IF;

  -- Lock wallet for atomic debit.
  SELECT * INTO w FROM wallets WHERE user_id = uid FOR UPDATE;

  delta_seconds := GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (now() - prev_last)))::int);

  IF NOT (w.is_unlimited OR (w.valid_until_ts IS NOT NULL AND w.valid_until_ts > now())) THEN
    w.time_remaining_seconds := GREATEST(0, COALESCE(w.time_remaining_seconds, 0) - delta_seconds);
    UPDATE wallets SET time_remaining_seconds = w.time_remaining_seconds WHERE user_id = uid;
  END IF;

  IF p_status_type = 'Stop' THEN
    UPDATE sessions SET last_update = now(), stop = now(), nas_id = nasid, acct_session_id = COALESCE(p_acct_session_id, acct_session_id)
    WHERE id = sid;
  ELSIF p_status_type = 'Start' THEN
    UPDATE sessions SET start = now(), last_update = now(), stop = NULL, nas_id = nasid, acct_session_id = COALESCE(p_acct_session_id, acct_session_id)
    WHERE id = sid;
  ELSE
    UPDATE sessions SET last_update = now(), nas_id = nasid, acct_session_id = COALESCE(p_acct_session_id, acct_session_id)
    WHERE id = sid;
  END IF;
END;
$$;
"""
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_radius_accounting(text,text,text,text,text)"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_radius_touch_session(text,text,text,text)"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_radius_session_timeout_seconds(text)"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_radius_reject_message(text,text,int)"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_radius_is_allowed(text,text,int)"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_wallet_is_valid(int)"))

    op.drop_table("sms_logs")
    op.drop_table("audit_logs")
    op.drop_table("webhook_logs")
    op.drop_table("device_events")
    op.drop_table("devices")
    op.drop_index("ix_sessions_active_user_mac", table_name="sessions")
    op.drop_index("ix_sessions_active_user", table_name="sessions")
    op.drop_index("ix_sessions_last_update", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("nas")
    op.drop_index("ix_transactions_user_id", table_name="transactions")
    op.drop_table("transactions")
    op.drop_table("plans")
    op.drop_table("wallets")
    op.drop_table("users")
    op.drop_table("admins")

    op.execute("DROP TYPE IF EXISTS adminstatus")
    op.execute("DROP TYPE IF EXISTS devicestatus")
    op.execute("DROP TYPE IF EXISTS transactionsource")
    op.execute("DROP TYPE IF EXISTS plantype")
    op.execute("DROP TYPE IF EXISTS userstatus")
