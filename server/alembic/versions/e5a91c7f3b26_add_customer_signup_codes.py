from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5a91c7f3b26'
down_revision: Union[str, Sequence[str], None] = 'd4f7c1b9e380'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('customers', sa.Column('signup_code', sa.Unicode(100), nullable=True))
    op.create_index(
        'ix_customers_signup_code',
        'customers',
        ['signup_code'],
        unique=True,
        mssql_where=sa.text('signup_code IS NOT NULL'),
    )


def downgrade() -> None:
    op.drop_index('ix_customers_signup_code', table_name='customers')
    op.drop_column('customers', 'signup_code')
