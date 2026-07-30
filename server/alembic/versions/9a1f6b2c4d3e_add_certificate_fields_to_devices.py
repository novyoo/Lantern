from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

LongText = sa.UnicodeText().with_variant(mssql.NVARCHAR(None), "mssql")

revision: str = '9a1f6b2c4d3e'
down_revision: Union[str, Sequence[str], None] = '2fd3789b0017'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column('devices', sa.Column('public_key', sa.Unicode(255), nullable=True))
    op.add_column('devices', sa.Column('certificate_payload', LongText, nullable=True))
    op.add_column('devices', sa.Column('certificate_signature', sa.Unicode(255), nullable=True))

def downgrade() -> None:
    op.drop_column('devices', 'certificate_signature')
    op.drop_column('devices', 'certificate_payload')
    op.drop_column('devices', 'public_key')
