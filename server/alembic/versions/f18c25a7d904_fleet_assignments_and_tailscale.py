"""Fleet devices, assignments, Tailscale, key commitments, file_id sync

A device stops being "a row that belongs to a rental" and becomes a durable
fleet asset that rentals borrow. WireGuard columns give way to Tailscale ones.
Sites gain a key commitment and a network tag; rentals gain an erasure nonce.

sync_files is dropped and recreated rather than migrated: the envelope format
changed (the filename now lives inside the ciphertext), so old blobs cannot be
read by the new agent under any circumstances.

Revision ID: f18c25a7d904
Revises: e5a91c7f3b26
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f18c25a7d904'
down_revision: Union[str, Sequence[str], None] = 'e5a91c7f3b26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- rentals -----------------------------------------------------------
    with op.batch_alter_table("rentals") as batch:
        batch.add_column(sa.Column("erasure_nonce", sa.Unicode(100), nullable=True))
        batch.add_column(sa.Column("erasure_confirmed_at", sa.DateTime(), nullable=True))

    # --- sites -------------------------------------------------------------
    with op.batch_alter_table("sites") as batch:
        batch.add_column(sa.Column("tailnet_index", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("key_commitment", sa.Unicode(100), nullable=True))

    # --- devices -----------------------------------------------------------
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("owner_note", sa.Unicode(255), nullable=True))
        batch.add_column(sa.Column("hostname", sa.Unicode(255), nullable=True))
        batch.add_column(sa.Column("enrollment_key", sa.Unicode(100), nullable=True))
        batch.add_column(sa.Column("state", sa.Unicode(50), nullable=False, server_default="UNCLAIMED"))
        batch.add_column(sa.Column("enrolled_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("wrap_public_key", sa.Unicode(255), nullable=True))
        batch.add_column(sa.Column("tailscale_node_id", sa.Unicode(100), nullable=True))
        batch.add_column(sa.Column("tailscale_ip", sa.Unicode(100), nullable=True))
        batch.add_column(sa.Column("tailscale_auth_key_issued_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("key_epoch", sa.Integer(), nullable=False, server_default="1"))
        # A device in the pool has no rental.
        batch.alter_column("rental_id", existing_type=sa.Integer(), nullable=True)

    # Existing devices were all enrolled and placed, so carry them over as
    # ASSIGNED with their old WireGuard key epoch.
    op.execute("UPDATE devices SET state = 'ASSIGNED' WHERE rental_id IS NOT NULL")
    op.execute("UPDATE devices SET wrap_public_key = wg_public_key WHERE wg_public_key IS NOT NULL")
    op.execute("UPDATE devices SET key_epoch = wg_key_epoch")

    with op.batch_alter_table("devices") as batch:
        batch.create_index("ix_devices_enrollment_key", ["enrollment_key"], unique=True)
        batch.drop_column("wg_public_key")
        batch.drop_column("wg_ip")
        batch.drop_column("wg_key_epoch")

    # --- audit events ------------------------------------------------------
    # Fleet-level events (device added, retired) belong to no rental.
    with op.batch_alter_table("audit_events") as batch:
        batch.alter_column("rental_id", existing_type=sa.Integer(), nullable=True)

    # --- assignments -------------------------------------------------------
    op.create_table(
        "assignments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("rental_id", sa.Integer(), sa.ForeignKey("rentals.id"), nullable=False),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=True),
        sa.Column("assigned_at", sa.DateTime(), nullable=True),
        sa.Column("released_at", sa.DateTime(), nullable=True),
        sa.Column("end_state", sa.Unicode(50), nullable=True),
    )
    # Give every device already in a rental an open assignment record so history
    # starts from today rather than from nothing.
    op.execute(
        "INSERT INTO assignments (device_id, rental_id, site_id, assigned_at) "
        "SELECT id, rental_id, site_id, created_at FROM devices WHERE rental_id IS NOT NULL"
    )

    # --- sync files --------------------------------------------------------
    op.drop_table("sync_files")
    op.create_table(
        "sync_files",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rental_id", sa.Integer(), sa.ForeignKey("rentals.id"), nullable=False),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=False),
        sa.Column("file_id", sa.Unicode(64), nullable=False),
        sa.Column("blob", sa.UnicodeText(), nullable=False),
        sa.Column("uploaded_by_device_id", sa.Integer(), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("site_id", "file_id", name="uq_sync_files_site_file"),
    )


def downgrade() -> None:
    op.drop_table("sync_files")
    op.create_table(
        "sync_files",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rental_id", sa.Integer(), sa.ForeignKey("rentals.id"), nullable=False),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id"), nullable=False),
        sa.Column("filename", sa.Unicode(255), nullable=False),
        sa.Column("blob", sa.UnicodeText(), nullable=False),
        sa.Column("uploaded_by_device_id", sa.Integer(), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("site_id", "filename", name="uq_sync_files_site_filename"),
    )
    op.drop_table("assignments")

    # Fleet-level events (device added, device retired) belong to no rental and
    # cannot exist once the column is NOT NULL again. Drop them rather than fail.
    op.execute("DELETE FROM audit_events WHERE rental_id IS NULL")
    with op.batch_alter_table("audit_events") as batch:
        batch.alter_column("rental_id", existing_type=sa.Integer(), nullable=False)

    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("wg_public_key", sa.Unicode(255), nullable=True))
        batch.add_column(sa.Column("wg_ip", sa.Unicode(50), nullable=True))
        batch.add_column(sa.Column("wg_key_epoch", sa.Integer(), nullable=False, server_default="1"))
        batch.drop_index("ix_devices_enrollment_key")
        batch.drop_column("key_epoch")
        batch.drop_column("tailscale_auth_key_issued_at")
        batch.drop_column("tailscale_ip")
        batch.drop_column("tailscale_node_id")
        batch.drop_column("wrap_public_key")
        batch.drop_column("enrolled_at")
        batch.drop_column("state")
        batch.drop_column("enrollment_key")
        batch.drop_column("hostname")
        batch.drop_column("owner_note")
        batch.alter_column("rental_id", existing_type=sa.Integer(), nullable=False)

    with op.batch_alter_table("sites") as batch:
        batch.drop_column("key_commitment")
        batch.drop_column("tailnet_index")

    with op.batch_alter_table("rentals") as batch:
        batch.drop_column("erasure_confirmed_at")
        batch.drop_column("erasure_nonce")
