from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '8b3c40359e65'
down_revision: Union[str, Sequence[str], None] = 'be5b40dc2ce3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('agent_token', sa.Unicode(255), nullable=True))
    op.add_column('devices', sa.Column('last_seen_at', sa.DateTime(), nullable=True))
    op.add_column('devices', sa.Column('confirmed_status', sa.Unicode(50), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'confirmed_status')
    op.drop_column('devices', 'last_seen_at')
    op.drop_column('devices', 'agent_token')
