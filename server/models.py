import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from database import Base

class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    rentals = relationship("Rental", back_populates="customer")

class Rental(Base):
    __tablename__ = "rentals"

    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    label = Column(String, nullable=False)
    status = Column(String, nullable=False, default="ACTIVE")
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    customer = relationship("Customer", back_populates="rentals")
    sites = relationship("Site", back_populates="rental")
    devices = relationship("Device", back_populates="rental")
    audit_events = relationship("AuditEvent", back_populates="rental")

class Site(Base):
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    rental = relationship("Rental", back_populates="sites")
    devices = relationship("Device", back_populates="site")

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True)
    label = Column(String, nullable=False)
    model = Column(String, nullable=False)
    status = Column(String, nullable=False, default="ACTIVE")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    agent_token = Column(String, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    confirmed_status = Column(String, nullable=True)
    wrapped_key_blob = Column(String, nullable=True)

    rental = relationship("Rental", back_populates="devices")
    site = relationship("Site", back_populates="devices")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    action = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    details = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    rental = relationship("Rental", back_populates="audit_events")
