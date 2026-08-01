import datetime

from sqlalchemy import Boolean, Column, Integer, Unicode, UnicodeText, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects import mssql
from sqlalchemy.orm import relationship

from database import Base

LongText = UnicodeText().with_variant(mssql.NVARCHAR(None), "mssql")

class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True)
    name = Column(Unicode(255), nullable=False)
    email = Column(Unicode(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    signup_code = Column(Unicode(100), nullable=True, unique=True, index=True)

    rentals = relationship("Rental", back_populates="customer")

class Rental(Base):
    __tablename__ = "rentals"

    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    label = Column(Unicode(255), nullable=False)
    status = Column(Unicode(50), nullable=False, default="ACTIVE")
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    key_epoch = Column(Integer, nullable=False, default=1)
    join_code = Column(Unicode(100), nullable=True, unique=True, index=True)
    # Issued only when a human confirms erasure. A device must quote it inside its
    # signed certificate, so no agent can pre-sign proof of an erasure that has not
    # happened yet.
    erasure_nonce = Column(Unicode(100), nullable=True)
    erasure_confirmed_at = Column(DateTime, nullable=True)

    customer = relationship("Customer", back_populates="rentals")
    sites = relationship("Site", back_populates="rental")
    devices = relationship("Device", back_populates="rental")
    audit_events = relationship("AuditEvent", back_populates="rental")
    assignments = relationship("Assignment", back_populates="rental")

class Site(Base):
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    name = Column(Unicode(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    network_index = Column(Integer, nullable=False, default=0)
    # Index into the Tailscale tag pool (tag:lantern-N). Globally unique among
    # live sites and handed back when the rental is erased, so the pool is reused
    # rather than growing forever.
    tailnet_index = Column(Integer, nullable=True)
    # SHA-256 of this site's workspace key, published by the device that created the
    # key and recorded here at the START of the rental. The erasure certificate quotes
    # it, so anyone can check the key that died is the key that guarded the data.
    # The commitment is a one-way hash: holding it does not help decrypt anything.
    key_commitment = Column(Unicode(100), nullable=True)

    rental = relationship("Rental", back_populates="sites")
    devices = relationship("Device", back_populates="site")

class Device(Base):
    """A physical laptop. Lives in the fleet forever, across many rentals.

    Columns split into three groups: the permanent asset identity, the current
    placement (all null while the device sits in the pool), and key material.
    """
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)

    # --- permanent asset identity -------------------------------------------
    # The fleet owner's name for this laptop. The agent never overwrites it -
    # "Rahul's ThinkPad" is more use on a fleet page than a machine hostname.
    label = Column(Unicode(255), nullable=False)
    model = Column(Unicode(255), nullable=False)
    asset_tag = Column(Unicode(100), nullable=True)
    owner_note = Column(Unicode(255), nullable=True)
    # What the machine calls itself, reported at enrollment. Useful for
    # confirming the expected laptop is the one that claimed the key.
    hostname = Column(Unicode(255), nullable=True)
    # One-time bearer secret that lets a laptop claim this row. After first
    # contact the device is pinned to its public_key, so a leaked enrollment key
    # cannot be replayed onto a different machine.
    enrollment_key = Column(Unicode(100), nullable=True, unique=True, index=True)
    # UNCLAIMED -> AVAILABLE -> ASSIGNED -> AVAILABLE ... -> RETIRED
    state = Column(Unicode(50), nullable=False, default="UNCLAIMED")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    enrolled_at = Column(DateTime, nullable=True)
    # Ed25519 identity key, pinned on first check-in. Verifies erasure certificates.
    public_key = Column(Unicode(255), nullable=True)

    # --- current placement (null while in the pool) -------------------------
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=True)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True)
    # IDLE while unassigned, then ACTIVE / LOCKED / REVOKED / ERASED / LEFT
    status = Column(Unicode(50), nullable=False, default="IDLE")
    agent_token = Column(Unicode(255), nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    confirmed_status = Column(Unicode(50), nullable=True)

    # --- key material and network -------------------------------------------
    # X25519 public key used only to receive the sealed workspace key from a peer.
    # Deliberately separate from the Tailscale node identity: transport identity
    # and key-agreement identity should not be the same key.
    wrap_public_key = Column(Unicode(255), nullable=True)
    tailscale_node_id = Column(Unicode(100), nullable=True)
    tailscale_ip = Column(Unicode(100), nullable=True)
    # We hand the auth key to the device once and never store it. This only
    # records that we did, so a reissue is deliberate rather than every check-in.
    tailscale_auth_key_issued_at = Column(DateTime, nullable=True)
    has_workspace_key = Column(Boolean, nullable=False, default=False)
    pending_key_offer_blob = Column(LongText, nullable=True)
    pending_key_offer_from = Column(Unicode(255), nullable=True)
    key_epoch = Column(Integer, nullable=False, default=1)
    wrapped_key_blob = Column(LongText, nullable=True)

    # --- end of rental -------------------------------------------------------
    certificate_payload = Column(LongText, nullable=True)
    certificate_signature = Column(Unicode(255), nullable=True)
    autopilot_id = Column(Unicode(100), nullable=True)
    autopilot_deregistered_at = Column(DateTime, nullable=True)
    bios_password_cleared_at = Column(DateTime, nullable=True)

    rental = relationship("Rental", back_populates="devices")
    site = relationship("Site", back_populates="devices")
    assignments = relationship("Assignment", back_populates="device")

class Assignment(Base):
    """One placement of one device into one rental.

    Kept as history after the placement ends, which is what makes "this laptop
    served three customers and none of them can read the others' files" a fact
    on record rather than a claim.
    """
    __tablename__ = "assignments"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True)
    assigned_at = Column(DateTime, default=datetime.datetime.utcnow)
    released_at = Column(DateTime, nullable=True)
    # How the placement ended: ERASED, REVOKED, LEFT or RELEASED.
    end_state = Column(Unicode(50), nullable=True)

    device = relationship("Device", back_populates="assignments")
    rental = relationship("Rental", back_populates="assignments")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    action = Column(Unicode(100), nullable=False)
    actor = Column(Unicode(255), nullable=False)
    details = Column(LongText, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    rental = relationship("Rental", back_populates="audit_events")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(Unicode(255), nullable=False, unique=True)
    name = Column(Unicode(255), nullable=False)
    role = Column(Unicode(50), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    password_hash = Column(Unicode(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    customer = relationship("Customer")

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True)
    token = Column(Unicode(255), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

class SyncFile(Base):
    """An encrypted blob in the shared workspace.

    Identified by a random file_id, never by name. The real filename lives inside
    the encrypted envelope, so the server stores a list of opaque UUIDs and cannot
    tell you what any of these files are called.
    """
    __tablename__ = "sync_files"
    __table_args__ = (UniqueConstraint("site_id", "file_id"),)

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=False)
    file_id = Column(Unicode(64), nullable=False)
    blob = Column(LongText, nullable=False)
    uploaded_by_device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
