from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_radius_walled_garden"
down_revision = "0002_system_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            r"""
CREATE OR REPLACE FUNCTION cw_radius_policy(
  p_username text,
  p_calling_station_id text,
  p_grace_seconds int,
  p_allow_garden int
)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
  uid int;
  other_session boolean;
  ok_wallet boolean;
BEGIN
  SELECT u.id INTO uid FROM users u WHERE u.username = p_username AND u.status = 'ACTIVE'::userstatus;
  IF uid IS NULL THEN
    RETURN 'REJECT';
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
    RETURN 'REJECT';
  END IF;

  SELECT cw_wallet_is_valid(uid) INTO ok_wallet;
  IF ok_wallet THEN
    RETURN 'ALLOW';
  END IF;

  IF COALESCE(p_allow_garden, 0) = 1 THEN
    RETURN 'GARDEN';
  END IF;

  RETURN 'REJECT';
END;
$$;
"""
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP FUNCTION IF EXISTS cw_radius_policy(text,text,int,int)"))

