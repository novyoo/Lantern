from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

LongText = sa.UnicodeText().with_variant(mssql.NVARCHAR(None), "mssql")


revision: str = 'c71d4e9a2b58'
down_revision: Union[str, Sequence[str], None] = 'a62e8814af4b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rentals', sa.Column('key_epoch', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('sites', sa.Column('network_index', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('devices', sa.Column('asset_tag', sa.Unicode(100), nullable=True))
    op.add_column('devices', sa.Column('wg_key_epoch', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('devices', sa.Column('autopilot_id', sa.Unicode(100), nullable=True))
    op.add_column('devices', sa.Column('autopilot_deregistered_at', sa.DateTime(), nullable=True))
    op.add_column('devices', sa.Column('bios_password_cleared_at', sa.DateTime(), nullable=True))
    op.drop_table('sync_files')
    op.create_table('sync_files',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rental_id', sa.Integer(), nullable=False),
    sa.Column('site_id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.Unicode(255), nullable=False),
    sa.Column('blob', LongText, nullable=False),
    sa.Column('uploaded_by_device_id', sa.Integer(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['rental_id'], ['rentals.id'], ),
    sa.ForeignKeyConstraint(['site_id'], ['sites.id'], ),
    sa.ForeignKeyConstraint(['uploaded_by_device_id'], ['devices.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('site_id', 'filename')
    )


def downgrade() -> None:
    op.drop_table('sync_files')
    op.create_table('sync_files',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rental_id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.Unicode(255), nullable=False),
    sa.Column('blob', LongText, nullable=False),
    sa.Column('uploaded_by_device_id', sa.Integer(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['rental_id'], ['rentals.id'], ),
    sa.ForeignKeyConstraint(['uploaded_by_device_id'], ['devices.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('rental_id', 'filename')
    )
    op.drop_column('devices', 'bios_password_cleared_at')
    op.drop_column('devices', 'autopilot_deregistered_at')
    op.drop_column('devices', 'autopilot_id')
    op.drop_column('devices', 'wg_key_epoch')
    op.drop_column('devices', 'asset_tag')
    op.drop_column('sites', 'network_index')
    op.drop_column('rentals', 'key_epoch')
