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

    customer = relationship("Customer", back_populates="rentals")
    sites = relationship("Site", back_populates="rental")
    devices = relationship("Device", back_populates="rental")
    audit_events = relationship("AuditEvent", back_populates="rental")

class Site(Base):
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    name = Column(Unicode(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    network_index = Column(Integer, nullable=False, default=0)

    rental = relationship("Rental", back_populates="sites")
    devices = relationship("Device", back_populates="site")

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True)
    label = Column(Unicode(255), nullable=False)
    model = Column(Unicode(255), nullable=False)
    status = Column(Unicode(50), nullable=False, default="ACTIVE")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    agent_token = Column(Unicode(255), nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    confirmed_status = Column(Unicode(50), nullable=True)
    wrapped_key_blob = Column(LongText, nullable=True)
    public_key = Column(Unicode(255), nullable=True)
    certificate_payload = Column(LongText, nullable=True)
    certificate_signature = Column(Unicode(255), nullable=True)
    wg_public_key = Column(Unicode(255), nullable=True)
    wg_ip = Column(Unicode(50), nullable=True)
    has_workspace_key = Column(Boolean, nullable=False, default=False)
    pending_key_offer_blob = Column(LongText, nullable=True)
    pending_key_offer_from = Column(Unicode(255), nullable=True)
    asset_tag = Column(Unicode(100), nullable=True)
    wg_key_epoch = Column(Integer, nullable=False, default=1)
    autopilot_id = Column(Unicode(100), nullable=True)
    autopilot_deregistered_at = Column(DateTime, nullable=True)
    bios_password_cleared_at = Column(DateTime, nullable=True)

    rental = relationship("Rental", back_populates="devices")
    site = relationship("Site", back_populates="devices")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
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
    __tablename__ = "sync_files"
    __table_args__ = (UniqueConstraint("site_id", "filename"),)

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=False)
    filename = Column(Unicode(255), nullable=False)
    blob = Column(LongText, nullable=False)
    uploaded_by_device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
