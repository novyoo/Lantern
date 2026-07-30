from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

LongText = sa.UnicodeText().with_variant(mssql.NVARCHAR(None), "mssql")

revision: str = '2fd3789b0017'
down_revision: Union[str, Sequence[str], None] = '8b3c40359e65'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column('devices', sa.Column('wrapped_key_blob', LongText, nullable=True))

def downgrade() -> None:
    op.drop_column('devices', 'wrapped_key_blob')
