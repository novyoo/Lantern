from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4f7c1b9e380'
down_revision: Union[str, Sequence[str], None] = 'c71d4e9a2b58'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.Unicode(255), nullable=False),
    sa.Column('name', sa.Unicode(255), nullable=False),
    sa.Column('role', sa.Unicode(50), nullable=False),
    sa.Column('customer_id', sa.Integer(), nullable=True),
    sa.Column('password_hash', sa.Unicode(255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('user_sessions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.Unicode(255), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.add_column('rentals', sa.Column('join_code', sa.Unicode(100), nullable=True))
    op.create_index(
        'ix_rentals_join_code',
        'rentals',
        ['join_code'],
        unique=True,
        mssql_where=sa.text('join_code IS NOT NULL'),
    )


def downgrade() -> None:
    op.drop_index('ix_rentals_join_code', table_name='rentals')
    op.drop_column('rentals', 'join_code')
    op.drop_table('user_sessions')
    op.drop_table('users')
