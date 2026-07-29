import datetime
import json
import secrets
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    Request,
    Depends,
    HTTPException,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
import models
import certificates
from scheduler import start_scheduler

MAX_BLAST_RADIUS = 10
AGENT_OFFLINE_AFTER_SECONDS = 15

@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

def jst(value):
    return value + datetime.timedelta(hours=9)

templates.env.filters["jst"] = jst

class ConnectionManager:
    def __init__(self):
        self.rooms = {}

    async def connect(self, rental_id, websocket):
        await websocket.accept()
        self.rooms.setdefault(rental_id, []).append(websocket)

    def disconnect(self, rental_id, websocket):
        if websocket in self.rooms.get(rental_id, []):
            self.rooms[rental_id].remove(websocket)

    async def broadcast(self, rental_id, html):
        for websocket in list(self.rooms.get(rental_id, [])):
            try:
                await websocket.send_text(html)
            except Exception:
                self.disconnect(rental_id, websocket)

manager = ConnectionManager()

def guard_blast_radius(devices):
    if len(devices) > MAX_BLAST_RADIUS:
        raise HTTPException(
            status_code=400,
            detail=f"This action would affect {len(devices)} devices at once, "
            f"over the safety limit of {MAX_BLAST_RADIUS}. Refusing.",
        )

def apply_lock(db, rental, actor):
    affected = [d for d in rental.devices if d.status == "ACTIVE"]
    guard_blast_radius(affected)
    for device in affected:
        device.status = "LOCKED"
    rental.status = "LOCKED"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="auto_lock" if actor == "system" else "lock",
        actor=actor,
        details=f"{len(affected)} device(s) locked.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_unlock(db, rental, actor):
    affected = [d for d in rental.devices if d.status == "LOCKED"]
    guard_blast_radius(affected)
    for device in affected:
        device.status = "ACTIVE"
    rental.status = "ACTIVE"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="unlock",
        actor=actor,
        details=f"{len(affected)} device(s) unlocked.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_erasure(db, rental, actor):
    affected = list(rental.devices)
    guard_blast_radius(affected)
    for device in affected:
        device.status = "ERASED"
    rental.status = "ERASED"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="erasure_confirmed",
        actor=actor,
        details=f"Erasure confirmed. {len(affected)} device(s) erased.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_revoke(db, device, actor):
    device.status = "REVOKED"
    event = models.AuditEvent(
        rental_id=device.rental_id,
        device_id=device.id,
        action="revoke",
        actor=actor,
        details=f"{device.label} revoked.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def render_broadcast_fragments(rental, events):
    fragments = templates.env.get_template("_fragments.html").module
    now = datetime.datetime.utcnow()
    pieces = [str(fragments.status_panel(rental, oob=True))]
    for device in rental.devices:
        pieces.append(str(fragments.device_row(rental, device, now, oob=True)))
    for event in events:
        pieces.append(str(fragments.audit_item(event, oob=True)))
    return pieces

async def broadcast_rental_update(rental, events):
    for piece in render_broadcast_fragments(rental, events):
        await manager.broadcast(rental.id, piece)

async def broadcast_device_row(rental, device):
    fragments = templates.env.get_template("_fragments.html").module
    now = datetime.datetime.utcnow()
    piece = str(fragments.device_row(rental, device, now, oob=True))
    await manager.broadcast(rental.id, piece)

class AgentRegisterRequest(BaseModel):
    label: str
    model: str

class AgentCheckinRequest(BaseModel):
    device_id: int
    agent_token: str
    applied_status: str | None = None
    public_key: str | None = None
    certificate_payload: str | None = None
    certificate_signature: str | None = None

def get_or_create_live_devices_rental(db):
    rental = (
        db.query(models.Rental).filter(models.Rental.label == "Live Devices").first()
    )
    if rental:
        return rental
    customer = (
        db.query(models.Customer)
        .filter(models.Customer.name == "Live Devices")
        .first()
    )
    if customer is None:
        customer = models.Customer(name="Live Devices", email="live@lantern.local")
        db.add(customer)
        db.commit()
        db.refresh(customer)
    now = datetime.datetime.utcnow()
    rental = models.Rental(
        customer_id=customer.id,
        label="Live Devices",
        status="ACTIVE",
        start_date=now,
        end_date=now + datetime.timedelta(days=365),
    )
    db.add(rental)
    db.commit()
    db.refresh(rental)
    return rental

def apply_checkin(db, device, payload):
    device.last_seen_at = datetime.datetime.utcnow()
    events = []
    if payload.applied_status and payload.applied_status != device.confirmed_status:
        device.confirmed_status = payload.applied_status
        events.append(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="agent_confirmed",
            actor=device.label,
            details=f"Agent confirmed status: {payload.applied_status}.",
        ))
    if payload.public_key and not device.public_key:
        device.public_key = payload.public_key
    if payload.certificate_payload and payload.certificate_signature and not device.certificate_payload:
        if certificates.verify_signature(
            device.public_key, payload.certificate_payload, payload.certificate_signature
        ):
            device.certificate_payload = payload.certificate_payload
            device.certificate_signature = payload.certificate_signature
            events.append(models.AuditEvent(
                rental_id=device.rental_id,
                device_id=device.id,
                action="certificate_issued",
                actor=device.label,
                details="Signed erasure certificate received and verified.",
            ))
        else:
            events.append(models.AuditEvent(
                rental_id=device.rental_id,
                device_id=device.id,
                action="certificate_rejected",
                actor=device.label,
                details="Signature did not verify - certificate discarded.",
            ))
    for event in events:
        db.add(event)
    db.commit()
    for event in events:
        db.refresh(event)
    return events

@app.get("/")
def list_rentals(request: Request, db: Session = Depends(get_db)):
    rentals = db.query(models.Rental).order_by(models.Rental.end_date).all()
    return templates.TemplateResponse(
        request, "rentals.html", {"rentals": rentals}
    )

@app.get("/rentals/{rental_id}")
def rental_detail(rental_id: int, request: Request, db: Session = Depends(get_db)):
    rental = db.get(models.Rental, rental_id)
    if rental is None:
        raise HTTPException(status_code=404)
    devices = sorted(rental.devices, key=lambda d: d.label)
    events = sorted(rental.audit_events, key=lambda e: e.id, reverse=True)
    return templates.TemplateResponse(
        request,
        "rental.html",
        {
            "rental": rental,
            "devices": devices,
            "events": events,
            "now": datetime.datetime.utcnow(),
        },
    )

@app.post("/rentals/{rental_id}/lock")
async def lock_rental(rental_id: int, db: Session = Depends(get_db)):
    rental = db.get(models.Rental, rental_id)
    if rental is None:
        raise HTTPException(status_code=404)
    if rental.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Rental must be ACTIVE to lock.")
    event = apply_lock(db, rental, actor="Admin (demo)")
    await broadcast_rental_update(rental, [event])
    return Response(status_code=204)

@app.post("/rentals/{rental_id}/unlock")
async def unlock_rental(rental_id: int, db: Session = Depends(get_db)):
    rental = db.get(models.Rental, rental_id)
    if rental is None:
        raise HTTPException(status_code=404)
    if rental.status != "LOCKED":
        raise HTTPException(status_code=400, detail="Rental must be LOCKED to unlock.")
    event = apply_unlock(db, rental, actor="Admin (demo)")
    await broadcast_rental_update(rental, [event])
    return Response(status_code=204)

@app.post("/rentals/{rental_id}/confirm_erasure")
async def confirm_erasure(rental_id: int, db: Session = Depends(get_db)):
    rental = db.get(models.Rental, rental_id)
    if rental is None:
        raise HTTPException(status_code=404)
    if rental.status != "LOCKED":
        raise HTTPException(
            status_code=400, detail="Rental must be LOCKED before erasure."
        )
    event = apply_erasure(db, rental, actor="Customer Manager (demo)")
    await broadcast_rental_update(rental, [event])
    return Response(status_code=204)

@app.post("/devices/{device_id}/revoke")
async def revoke_device(device_id: int, db: Session = Depends(get_db)):
    device = db.get(models.Device, device_id)
    if device is None:
        raise HTTPException(status_code=404)
    if device.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Device must be ACTIVE to revoke.")
    rental = device.rental
    event = apply_revoke(db, device, actor="Admin (demo)")
    await broadcast_rental_update(rental, [event])
    return Response(status_code=204)

@app.post("/agent/register")
def agent_register(payload: AgentRegisterRequest, db: Session = Depends(get_db)):
    rental = get_or_create_live_devices_rental(db)
    device = models.Device(
        rental_id=rental.id,
        site_id=None,
        label=payload.label,
        model=payload.model,
        status="ACTIVE",
        agent_token=secrets.token_hex(32),
        last_seen_at=datetime.datetime.utcnow(),
    )
    db.add(device)
    db.flush()
    event = models.AuditEvent(
        rental_id=rental.id,
        device_id=device.id,
        action="agent_registered",
        actor=payload.label,
        details=f"{payload.label} registered as a live agent.",
    )
    db.add(event)
    db.commit()
    db.refresh(device)
    return {
        "device_id": device.id,
        "agent_token": device.agent_token,
        "rental_id": rental.id,
    }

@app.post("/agent/checkin")
async def agent_checkin(payload: AgentCheckinRequest, db: Session = Depends(get_db)):
    device = db.get(models.Device, payload.device_id)
    if device is None or not secrets.compare_digest(
        device.agent_token or "", payload.agent_token
    ):
        raise HTTPException(status_code=401, detail="Unknown device or bad token.")
    rental = device.rental
    events = apply_checkin(db, device, payload)
    if events:
        await broadcast_rental_update(rental, events)
    else:
        await broadcast_device_row(rental, device)
    return {"device_status": device.status, "rental_status": rental.status}

@app.get("/devices/{device_id}/certificate")
def device_certificate(device_id: int, request: Request, db: Session = Depends(get_db)):
    device = db.get(models.Device, device_id)
    if device is None or not device.certificate_payload:
        raise HTTPException(status_code=404, detail="No certificate issued for this device yet.")
    verify_url = certificates.build_verify_url(
        request, device.id, device.certificate_payload, device.certificate_signature
    )
    return templates.TemplateResponse(
        request, "certificate.html", {"device": device, "verify_url": verify_url}
    )

@app.get("/devices/{device_id}/certificate/qr.png")
def device_certificate_qr(device_id: int, request: Request, db: Session = Depends(get_db)):
    device = db.get(models.Device, device_id)
    if device is None or not device.certificate_payload:
        raise HTTPException(status_code=404)
    verify_url = certificates.build_verify_url(
        request, device.id, device.certificate_payload, device.certificate_signature
    )
    return Response(content=certificates.qr_png_bytes(verify_url), media_type="image/png")

@app.get("/verify")
def verify_certificate(
    device_id: int, data: str, sig: str, request: Request, db: Session = Depends(get_db)
):
    device = db.get(models.Device, device_id)
    if device is None or not device.public_key:
        return templates.TemplateResponse(
            request,
            "verify.html",
            {"valid": False, "error": "Unknown device - no certificate on record.", "payload": None},
        )
    try:
        payload_json = certificates.decode_payload(data)
    except Exception:
        return templates.TemplateResponse(
            request,
            "verify.html",
            {"valid": False, "error": "This certificate link is malformed.", "payload": None},
        )
    valid = certificates.verify_signature(device.public_key, payload_json, sig)
    if valid:
        return templates.TemplateResponse(
            request, "verify.html", {"valid": True, "error": None, "payload": json.loads(payload_json)}
        )
    return templates.TemplateResponse(
        request,
        "verify.html",
        {
            "valid": False,
            "error": "Signature does not match - this certificate has been tampered with.",
            "payload": None,
        },
    )

@app.websocket("/ws/rentals/{rental_id}")
async def rental_ws(websocket: WebSocket, rental_id: int):
    await manager.connect(rental_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(rental_id, websocket)
