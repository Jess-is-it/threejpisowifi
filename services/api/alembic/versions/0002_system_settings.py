from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_system_settings"
down_revision = "0001_init"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(length=128), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    # Initialize setup wizard flags (absence is treated as false, but explicit keys help operators).
    op.execute(
        sa.text(
            "INSERT INTO system_settings(key,value) VALUES "
            "('setup_completed','false'),"
            "('setup_completed_at',''),"
            "('setup_state','{}') "
            "ON CONFLICT (key) DO NOTHING"
        )
    )


def downgrade() -> None:
    op.drop_table("system_settings")

