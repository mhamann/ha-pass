"""Per-token proximity ("near home") policy and proximity audit columns.

Revision ID: 003
Revises: 002
Create Date: 2026-11-27
"""
from typing import Sequence, Union

from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TOKEN_COLUMNS = [
    # 0 = no proximity check (pre-003 behaviour)
    ("proximity_required", "INTEGER NOT NULL DEFAULT 0"),
    ("geofence_radius_m", "INTEGER NOT NULL DEFAULT 150"),
    # Being on the home network (public WAN IP) satisfies the check
    ("allow_home_network", "INTEGER NOT NULL DEFAULT 1"),
]
_LOG_COLUMNS = [
    ("proximity_method", "TEXT"),  # 'network' | 'gps' | NULL (not required)
    ("distance_m", "INTEGER"),
]


def upgrade() -> None:
    for name, ddl in _TOKEN_COLUMNS:
        op.execute(f"ALTER TABLE tokens ADD COLUMN {name} {ddl}")
    for name, ddl in _LOG_COLUMNS:
        op.execute(f"ALTER TABLE access_log ADD COLUMN {name} {ddl}")


def downgrade() -> None:
    # SQLite >= 3.35 supports DROP COLUMN
    for name, _ in reversed(_LOG_COLUMNS):
        op.execute(f"ALTER TABLE access_log DROP COLUMN {name}")
    for name, _ in reversed(_TOKEN_COLUMNS):
        op.execute(f"ALTER TABLE tokens DROP COLUMN {name}")
