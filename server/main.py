import base64
import datetime
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

from fastapi import (
    FastAPI,
    Request,
    Depends,
    Header,
    HTTPException,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from database import get_db, SessionLocal, engine_name
import models
import auth
import certificates
import tailnet
from scheduler import start_scheduler

MAX_BLAST_RADIUS = 10
AGENT_OFFLINE_AFTER_SECONDS = 15
WORKSPACE_KEY_ORIGINATOR_WINDOW_SECONDS = 60
MAX_EVENTS_SHOWN = 50
MAX_SITES_PER_RENTAL = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s %(name)s %(message)s",
)
logging.Formatter.converter = time.gmtime
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
log = logging.getLogger("lantern")

started_at = datetime.datetime.utcnow()

def utcnow():
    return datetime.datetime.utcnow()

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "startup database=%s tailscale=%s https_cookies=%s public_url=%s",
        engine_name(),
        "configured" if tailnet.is_configured() else "NOT CONFIGURED (network layer disabled)",
        os.environ.get("LANTERN_HTTPS") == "1",
        os.environ.get("PUBLIC_URL_BASE") or "from request",
    )
    if not tailnet.is_configured():
        log.warning(
            "TAILSCALE_API_KEY is not set. Devices will still enrol, sync files, lock "
            "and erase - they just will not join a private network."
        )
    start_scheduler()
    yield

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

@app.middleware("http")
async def log_request(request: Request, call_next):
    began = time.perf_counter()
    response = await call_next(request)
    log.info(
        "%s %s %s %sms",
        request.method,
        request.url.path,
        response.status_code,
        round((time.perf_counter() - began) * 1000),
    )
    return response

@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception as problem:
        log.error("health check could not reach the database: %s", problem)
        database = "unreachable"
    body = {
        "status": "ok" if database == "ok" else "degraded",
        "database": database,
        "engine": engine_name(),
        "tailscale": tailnet.status_summary(),
        "uptime_seconds": round((utcnow() - started_at).total_seconds()),
    }
    return JSONResponse(body, status_code=200 if database == "ok" else 503)

def jst(value):
    return value + datetime.timedelta(hours=9)

templates.env.filters["jst"] = jst

class NeedsLogin(Exception):
    pass

@app.exception_handler(NeedsLogin)
async def send_to_login(request: Request, exc: NeedsLogin):
    if request.method == "GET":
        return RedirectResponse("/login", status_code=303)
    return Response("Your session has expired. Reload the page and sign in again.", status_code=401)

def signed_in_user(request: Request, db: Session = Depends(get_db)):
    user = auth.user_for_token(db, request.cookies.get(auth.SESSION_COOKIE_NAME))
    if user is None:
        raise NeedsLogin()
    return user

def admin_only(user: models.User = Depends(signed_in_user)):
    if user.role != auth.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Only a YRL Admin can do this.",
        )
    return user

def actor_name(user):
    return f"{user.name} ({user.role})"

def rental_for_user(db, rental_id, user):
    rental = db.get(models.Rental, rental_id)
    if rental is None or not auth.can_see_rental(user, rental):
        raise HTTPException(status_code=404)
    return rental

def device_for_user(db, device_id, user):
    device = db.get(models.Device, device_id)
    if device is None:
        raise HTTPException(status_code=404)
    if device.rental is None:
        # A device sitting in the pool belongs to the fleet owner, not a customer.
        if user.role != auth.ADMIN:
            raise HTTPException(status_code=404)
        return device
    if not auth.can_see_rental(user, device.rental):
        raise HTTPException(status_code=404)
    return device

async def form_body(request):
    body = (await request.body()).decode()
    return {key: values[0] for key, values in parse_qs(body).items()}

async def form_or_query(request, field):
    value = request.query_params.get(field)
    if value is not None:
        return value
    body = (await request.body()).decode()
    submitted = parse_qs(body).get(field)
    return submitted[0] if submitted else None

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

# ---------------------------------------------------------------------------
# sites and the Tailscale tag pool
# ---------------------------------------------------------------------------

def allocate_tailnet_index(db):
    """Take the lowest free tag from the pool.

    Tags cannot be invented at runtime - every one must already be declared in
    the tailnet policy file - so sites draw from a fixed pool and hand the tag
    back when the rental is erased.
    """
    used = {
        index
        for (index,) in db.query(models.Site.tailnet_index)
        .filter(models.Site.tailnet_index.isnot(None))
        .all()
    }
    for candidate in range(tailnet.TAG_POOL_SIZE):
        if candidate not in used:
            return candidate
    log.warning("tailnet tag pool of %s is exhausted", tailnet.TAG_POOL_SIZE)
    return None

def get_or_create_default_site(db, rental):
    site = (
        db.query(models.Site)
        .filter(models.Site.rental_id == rental.id)
        .order_by(models.Site.network_index)
        .first()
    )
    if site:
        return site
    site = models.Site(
        rental_id=rental.id,
        name="Main",
        network_index=0,
        tailnet_index=allocate_tailnet_index(db),
    )
    db.add(site)
    db.commit()
    db.refresh(site)
    return site

def release_tailnet_indexes(db, rental):
    for site in rental.sites:
        site.tailnet_index = None
    db.commit()

def issue_auth_key(device, rental, site):
    """Mint a Tailscale auth key scoped to this site's tag and this rental's term.

    Handed to the device once and never stored here.
    """
    if site is None or site.tailnet_index is None:
        return None
    remaining = (rental.end_date - utcnow()).total_seconds()
    return tailnet.create_auth_key(
        site.tailnet_index,
        remaining,
        f"Lantern device {device.id} rental {rental.id} site {site.id}",
    )

def kick_device_off_tailnet(device):
    """Remove the node from the tailnet. Works even if the laptop is powered off."""
    if device.tailscale_node_id:
        tailnet.delete_device(device.tailscale_node_id)
    else:
        found = tailnet.find_device_by_hostname(f"lantern-{device.id}")
        if found:
            tailnet.delete_device(found.get("nodeId") or found.get("id"))
    device.tailscale_node_id = None
    device.tailscale_ip = None

# ---------------------------------------------------------------------------
# assignment lifecycle
# ---------------------------------------------------------------------------

def current_assignment(db, device):
    return (
        db.query(models.Assignment)
        .filter(
            models.Assignment.device_id == device.id,
            models.Assignment.released_at.is_(None),
        )
        .order_by(models.Assignment.id.desc())
        .first()
    )

def assign_device(db, device, rental, site, actor):
    device.rental_id = rental.id
    device.site_id = site.id
    device.state = "ASSIGNED"
    device.status = "ACTIVE"
    device.key_epoch = rental.key_epoch
    device.has_workspace_key = False
    device.pending_key_offer_blob = None
    device.pending_key_offer_from = None
    device.tailscale_auth_key_issued_at = None
    device.certificate_payload = None
    device.certificate_signature = None
    device.confirmed_status = None
    db.add(models.Assignment(device_id=device.id, rental_id=rental.id, site_id=site.id))
    event = models.AuditEvent(
        rental_id=rental.id,
        device_id=device.id,
        action="device_assigned",
        actor=actor,
        details=f"{device.label} assigned to '{rental.label}', site '{site.name}'. "
        f"It joins by itself on its next check-in - nobody touches the laptop.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def release_device(db, device, end_state, actor):
    """Return a device to the pool, closing its assignment record."""
    assignment = current_assignment(db, device)
    rental_id = device.rental_id
    if assignment:
        assignment.released_at = utcnow()
        assignment.end_state = end_state
    kick_device_off_tailnet(device)
    device.rental_id = None
    device.site_id = None
    device.status = "IDLE"
    device.state = "AVAILABLE"
    device.has_workspace_key = False
    device.pending_key_offer_blob = None
    device.pending_key_offer_from = None
    device.tailscale_auth_key_issued_at = None
    event = models.AuditEvent(
        rental_id=rental_id,
        device_id=device.id,
        action="device_released",
        actor=actor,
        details=f"{device.label} returned to the fleet pool ({end_state}). "
        f"It is available for the next customer.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def devices_in_site(rental, site):
    return [d for d in rental.devices if d.site_id == site.id]

def guard_blast_radius(devices, confirmed):
    if len(devices) > MAX_BLAST_RADIUS and not confirmed:
        raise HTTPException(
            status_code=409,
            detail=f"This action would affect {len(devices)} devices at once, "
            f"over the safety limit of {MAX_BLAST_RADIUS}. "
            f"Resend it with confirm=yes to go ahead.",
        )

def apply_lock(db, rental, actor, confirmed=False):
    affected = [d for d in rental.devices if d.status == "ACTIVE"]
    guard_blast_radius(affected, confirmed)
    for device in affected:
        device.status = "LOCKED"
        kick_device_off_tailnet(device)
    rental.status = "LOCKED"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="auto_lock" if actor == "system" else "lock",
        actor=actor,
        details=f"{len(affected)} device(s) locked. Files became unreadable ciphertext "
        f"on each one. Reversible - no key was destroyed.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_unlock(db, rental, actor, confirmed=False):
    affected = [d for d in rental.devices if d.status == "LOCKED"]
    guard_blast_radius(affected, confirmed)
    for device in affected:
        device.status = "ACTIVE"
        device.tailscale_auth_key_issued_at = None
    rental.status = "ACTIVE"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="unlock",
        actor=actor,
        details=f"{len(affected)} device(s) unlocked and rejoining the network.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_erasure(db, rental, actor, confirmed=False):
    """Destroy the keys. Only ever reached by a human pressing the button.

    The nonce minted here is what makes each certificate provably fresh: an
    agent cannot sign proof of an erasure before the erasure is ordered.
    """
    affected = list(rental.devices)
    guard_blast_radius(affected, confirmed)
    now = utcnow()
    rental.erasure_nonce = secrets.token_hex(16)
    rental.erasure_confirmed_at = now
    deregistered = 0
    for device in affected:
        device.status = "ERASED"
        kick_device_off_tailnet(device)
        if device.autopilot_id and not device.autopilot_deregistered_at:
            device.autopilot_deregistered_at = now
            deregistered += 1
    rental.status = "ERASED"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="erasure_confirmed",
        actor=actor,
        details=f"Erasure confirmed by a human. {len(affected)} device(s) instructed to "
        f"destroy their keys. Verification nonce issued.",
    )
    db.add(event)
    db.add(models.AuditEvent(
        rental_id=rental.id,
        action="autopilot_deregistered",
        actor="system",
        details=f"{deregistered} device ID(s) removed from Autopilot enrolment (simulated).",
    ))
    db.commit()
    db.refresh(event)
    release_tailnet_indexes(db, rental)
    return event

def apply_extend(db, rental, actor, days, confirmed=False):
    affected = [d for d in rental.devices if d.status == "LOCKED"]
    guard_blast_radius(affected, confirmed)
    now = utcnow()
    base = rental.end_date if rental.end_date > now else now
    rental.end_date = base + datetime.timedelta(days=days)
    rental.key_epoch = rental.key_epoch + 1
    for device in affected:
        device.status = "ACTIVE"
    for device in rental.devices:
        device.tailscale_auth_key_issued_at = None
    rental.status = "ACTIVE"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="extend",
        actor=actor,
        details=f"Extended by {days} day(s). New end date {rental.end_date.isoformat()}Z. "
        f"Network keys reissued (epoch {rental.key_epoch}). {len(affected)} device(s) unlocked.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_revoke(db, device, actor):
    device.status = "REVOKED"
    kick_device_off_tailnet(device)
    event = models.AuditEvent(
        rental_id=device.rental_id,
        device_id=device.id,
        action="revoke",
        actor=actor,
        details=f"{device.label} revoked. Removed from the private network immediately "
        f"and its local keys destroyed. Everyone else keeps working.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def apply_leave(db, device, actor):
    device.status = "LEFT"
    kick_device_off_tailnet(device)
    event = models.AuditEvent(
        rental_id=device.rental_id,
        device_id=device.id,
        action="left",
        actor=actor,
        details=f"{device.label} left the rental and will fully uninstall.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def recent_events(rental):
    return sorted(rental.audit_events, key=lambda e: e.id, reverse=True)[:MAX_EVENTS_SHOWN]

def render_broadcast_fragments(rental):
    fragments = templates.env.get_template("_fragments.html").module
    now = utcnow()
    pieces = [
        str(fragments.status_panel(rental, oob=True)),
        str(fragments.return_checklist_panel(rental, return_checklist(rental), oob=True)),
        str(fragments.audit_log_panel(recent_events(rental), oob=True)),
    ]
    for device in rental.devices:
        pieces.append(str(fragments.device_row(rental, device, now, oob=True)))
    return pieces

async def broadcast_rental_update(rental):
    for piece in render_broadcast_fragments(rental):
        await manager.broadcast(rental.id, piece)

async def broadcast_device_row(rental, device):
    fragments = templates.env.get_template("_fragments.html").module
    piece = str(fragments.device_row(rental, device, utcnow(), oob=True))
    await manager.broadcast(rental.id, piece)

# ---------------------------------------------------------------------------
# agent protocol
# ---------------------------------------------------------------------------

class AgentEnrollRequest(BaseModel):
    label: str
    model: str
    public_key: str | None = None
    enrollment_key: str | None = None
    join_code: str | None = None

class KeyOffer(BaseModel):
    for_device_id: int
    blob: str

class AgentCheckinRequest(BaseModel):
    device_id: int
    agent_token: str
    applied_status: str | None = None
    public_key: str | None = None
    wrap_public_key: str | None = None
    key_epoch: int = 1
    has_workspace_key: bool = False
    key_commitment: str | None = None
    tailscale_node_id: str | None = None
    tailscale_ip: str | None = None
    certificate_payload: str | None = None
    certificate_signature: str | None = None
    key_offers: list[KeyOffer] | None = None
    autopilot_id: str | None = None
    bios_password_cleared: bool = False

class AgentLeaveRequest(BaseModel):
    device_id: int
    agent_token: str

def certificate_is_trustworthy(db, device, payload_json):
    """Check a certificate says what it should before we store it.

    A valid signature only proves the device wrote it. These two checks prove it
    wrote it about the right key, after a real erasure order.
    """
    try:
        payload = json.loads(payload_json)
    except ValueError:
        return False, "certificate payload was not valid JSON"
    assignment = current_assignment(db, device)
    rental = device.rental or (assignment.rental if assignment else None)
    if rental is None:
        return False, "device is not attached to a rental"
    if not rental.erasure_nonce:
        return False, "no erasure has been ordered for this rental"
    if payload.get("erasure_nonce") != rental.erasure_nonce:
        return False, "certificate quotes the wrong erasure nonce - it may have been pre-signed"
    site = device.site or (db.get(models.Site, assignment.site_id) if assignment else None)
    expected_commitment = site.key_commitment if site else None
    if expected_commitment and payload.get("key_commitment") != expected_commitment:
        return False, "certificate is about a different key than the one this site used"
    return True, None

def apply_checkin(db, device, payload):
    device.last_seen_at = utcnow()
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

    # Trust on first use: the first key we ever see is the one we keep, so a
    # leaked enrollment key cannot re-point this row at another machine.
    if payload.public_key and not device.public_key:
        device.public_key = payload.public_key
    if payload.wrap_public_key and payload.wrap_public_key != device.wrap_public_key:
        device.wrap_public_key = payload.wrap_public_key

    if payload.tailscale_node_id:
        device.tailscale_node_id = payload.tailscale_node_id
    if payload.tailscale_ip:
        device.tailscale_ip = payload.tailscale_ip

    # The first device to hold a site's key publishes its fingerprint. First
    # writer wins - it is recorded at the START of the rental, long before any
    # erasure, which is what makes it evidence.
    if payload.key_commitment and device.site and not device.site.key_commitment:
        device.site.key_commitment = payload.key_commitment
        events.append(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="key_committed",
            actor=device.label,
            details=f"Workspace key created for site '{device.site.name}'. "
            f"Fingerprint {payload.key_commitment[:16]}... published for later verification.",
        ))

    if payload.certificate_payload and payload.certificate_signature and not device.certificate_payload:
        signature_ok = certificates.verify_signature(
            device.public_key, payload.certificate_payload, payload.certificate_signature
        )
        trustworthy, problem = certificate_is_trustworthy(db, device, payload.certificate_payload)
        if signature_ok and trustworthy:
            device.certificate_payload = payload.certificate_payload
            device.certificate_signature = payload.certificate_signature
            events.append(models.AuditEvent(
                rental_id=device.rental_id,
                device_id=device.id,
                action="certificate_issued",
                actor=device.label,
                details="Signed erasure certificate received. Signature, key fingerprint "
                "and erasure nonce all verified.",
            ))
        else:
            reason = "signature did not verify" if not signature_ok else problem
            events.append(models.AuditEvent(
                rental_id=device.rental_id,
                device_id=device.id,
                action="certificate_rejected",
                actor=device.label,
                details=f"Certificate discarded - {reason}.",
            ))

    if payload.autopilot_id and not device.autopilot_id:
        device.autopilot_id = payload.autopilot_id
    if payload.bios_password_cleared and not device.bios_password_cleared_at:
        device.bios_password_cleared_at = utcnow()
        events.append(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="bios_password_cleared",
            actor=device.label,
            details="BIOS/UEFI supervisor password removed for return (simulated).",
        ))

    device.has_workspace_key = bool(payload.has_workspace_key)

    # Relay sealed key offers. The blob is opaque to us - we are a postbox.
    if device.has_workspace_key and payload.key_offers:
        for offer in payload.key_offers:
            target = db.get(models.Device, offer.for_device_id)
            if target and target.site_id == device.site_id and not target.has_workspace_key:
                target.pending_key_offer_blob = offer.blob
                target.pending_key_offer_from = device.wrap_public_key

    for event in events:
        db.add(event)
    db.commit()
    for event in events:
        db.refresh(event)
    return events

def build_assignment_payload(device):
    if device.rental is None or device.site is None:
        return None
    return {
        "rental_id": device.rental_id,
        "site_id": device.site_id,
        "site_name": device.site.name,
        "key_epoch": device.rental.key_epoch,
    }

def build_network_payload(db, device):
    """Hand over a Tailscale auth key when the device needs one.

    Issued once per assignment, and again after an extension bumps the epoch.
    """
    if device.status != "ACTIVE" or device.rental is None or device.site is None:
        return None
    if not tailnet.is_configured():
        return {"auth_key": None, "tailnet_ready": False}
    if device.tailscale_auth_key_issued_at is not None:
        return {"auth_key": None, "tailnet_ready": True}
    key = issue_auth_key(device, device.rental, device.site)
    if key:
        device.tailscale_auth_key_issued_at = utcnow()
        db.add(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="network_key_issued",
            actor="system",
            details=f"Tailscale auth key issued for site '{device.site.name}' "
            f"({tailnet.site_tag(device.site.tailnet_index)}).",
        ))
        db.commit()
    return {"auth_key": key, "tailnet_ready": bool(key)}

def build_workspace_payload(db, device):
    """Work out how this device gets the site's workspace key.

    Either a peer that already holds it seals a copy for us, or - if nobody in
    the site has one yet - the lowest-numbered device online creates it.
    """
    if device.status != "ACTIVE" or device.rental is None or device.site is None:
        return None
    site_devices = [d for d in device.rental.devices if d.site_id == device.site_id]
    key_requests = []
    originate_key = False
    if device.has_workspace_key:
        key_requests = [
            {"device_id": d.id, "wrap_public_key": d.wrap_public_key}
            for d in site_devices
            if d.status == "ACTIVE" and d.wrap_public_key and not d.has_workspace_key and d.id != device.id
        ]
    else:
        cutoff = utcnow() - datetime.timedelta(seconds=WORKSPACE_KEY_ORIGINATOR_WINDOW_SECONDS)
        candidates = [
            d for d in site_devices
            if d.status == "ACTIVE"
            and d.wrap_public_key
            and not d.has_workspace_key
            and d.last_seen_at
            and d.last_seen_at >= cutoff
        ]
        any_holder = any(d.has_workspace_key for d in site_devices if d.status == "ACTIVE")
        if not any_holder and candidates and min(d.id for d in candidates) == device.id:
            originate_key = True
    pending_offer = None
    if device.pending_key_offer_blob:
        pending_offer = {
            "blob": device.pending_key_offer_blob,
            "from_wrap_public_key": device.pending_key_offer_from,
        }
        device.pending_key_offer_blob = None
        device.pending_key_offer_from = None
        db.commit()
    return {
        "needs_key": not device.has_workspace_key,
        "originate_key": originate_key,
        "pending_key_offer": pending_offer,
        "key_requests": key_requests,
    }

@app.post("/agent/enroll")
def agent_enroll(payload: AgentEnrollRequest, db: Session = Depends(get_db)):
    """Claim a fleet device row, once, in the life of a laptop.

    Two ways in. An enrollment key claims a row the fleet owner created in
    advance - the laptop then waits in the pool doing nothing. A join code is
    the self-service path: it enrols and assigns to that rental in one go.
    """
    device = None
    rental = None

    if payload.enrollment_key:
        device = (
            db.query(models.Device)
            .filter(models.Device.enrollment_key == payload.enrollment_key.strip())
            .first()
        )
        if device is None:
            raise HTTPException(status_code=400, detail="That enrollment key is not valid.")
        if device.state == "RETIRED":
            raise HTTPException(status_code=400, detail="That device has been retired from the fleet.")
        if device.public_key and payload.public_key and device.public_key != payload.public_key:
            # The row is already pinned to a different machine's identity key.
            raise HTTPException(
                status_code=409,
                detail="That enrollment key already belongs to another machine.",
            )

    if payload.join_code:
        rental = (
            db.query(models.Rental)
            .filter(models.Rental.join_code == payload.join_code.strip())
            .first()
        )
        if rental is None or rental.status != "ACTIVE":
            raise HTTPException(status_code=400, detail="Invalid or inactive join code.")

    if device is None and rental is None:
        raise HTTPException(
            status_code=400,
            detail="Send either an enrollment key or a join code.",
        )

    if device is None:
        # Self-service via join code: no row existed, so the machine names itself.
        device = models.Device(
            label=payload.label,
            model=payload.model,
            state="UNCLAIMED",
            status="IDLE",
            enrollment_key=secrets.token_urlsafe(12),
        )
        db.add(device)
        db.flush()

    # The label and model belong to whoever built the fleet. A laptop reporting
    # its hostname must not rename the row someone deliberately called
    # "Rahul's ThinkPad" - the hostname is recorded separately instead.
    device.hostname = payload.label or device.hostname
    device.agent_token = secrets.token_hex(32)
    device.enrolled_at = device.enrolled_at or utcnow()
    device.last_seen_at = utcnow()
    if payload.public_key and not device.public_key:
        device.public_key = payload.public_key
    if device.state == "UNCLAIMED":
        device.state = "AVAILABLE"
    db.flush()

    db.add(models.AuditEvent(
        rental_id=device.rental_id,
        device_id=device.id,
        action="device_enrolled",
        actor=device.label,
        details=f"'{device.label}' claimed by a machine calling itself "
        f"'{device.hostname}'. Pinned to that machine's signing key - the "
        f"enrollment key cannot now be used anywhere else.",
    ))

    if rental is not None:
        site = get_or_create_default_site(db, rental)
        db.commit()
        assign_device(db, device, rental, site, actor=payload.label)

    db.commit()
    db.refresh(device)
    return {
        "device_id": device.id,
        "agent_token": device.agent_token,
        "label": device.label,
        "rental_id": device.rental_id,
        "site_id": device.site_id,
        "key_epoch": device.key_epoch,
    }

@app.post("/agent/checkin")
async def agent_checkin(payload: AgentCheckinRequest, db: Session = Depends(get_db)):
    device = db.get(models.Device, payload.device_id)
    if device is None or not secrets.compare_digest(
        device.agent_token or "", payload.agent_token
    ):
        raise HTTPException(status_code=401, detail="Unknown device or bad token.")
    rental = device.rental
    events = await run_in_threadpool(apply_checkin, db, device, payload)
    body = {
        "device_status": device.status,
        "rental_status": rental.status if rental else None,
        "assignment": build_assignment_payload(device),
        "network": await run_in_threadpool(build_network_payload, db, device),
        "workspace": build_workspace_payload(db, device),
        "erasure_nonce": rental.erasure_nonce if rental else None,
    }
    if rental is not None:
        if events:
            await broadcast_rental_update(rental)
        else:
            await broadcast_device_row(rental, device)
    return body

@app.post("/agent/leave")
async def agent_leave(payload: AgentLeaveRequest, db: Session = Depends(get_db)):
    device = db.get(models.Device, payload.device_id)
    if device is None or not secrets.compare_digest(
        device.agent_token or "", payload.agent_token
    ):
        raise HTTPException(status_code=401, detail="Unknown device or bad token.")
    rental = device.rental
    if rental is not None:
        await run_in_threadpool(apply_leave, db, device, actor=device.label)
        await broadcast_rental_update(rental)
    else:
        kick_device_off_tailnet(device)
        db.commit()
    return {"ok": True}

# ---------------------------------------------------------------------------
# encrypted file sync
# ---------------------------------------------------------------------------

def authenticate_device_for_rental(db, device_id, agent_token, rental_id):
    device = db.get(models.Device, device_id)
    if device is None or not secrets.compare_digest(device.agent_token or "", agent_token):
        raise HTTPException(status_code=401, detail="Unknown device or bad token.")
    if device.rental_id != rental_id:
        raise HTTPException(status_code=403, detail="Device does not belong to this rental.")
    if device.status != "ACTIVE":
        raise HTTPException(status_code=403, detail="Device is not active in this rental.")
    return device

def is_valid_file_id(file_id):
    return bool(file_id) and len(file_id) <= 64 and all(c in "0123456789abcdef" for c in file_id)

@app.get("/rentals/{rental_id}/sync")
def list_sync_files(
    rental_id: int, device_id: int, db: Session = Depends(get_db),
    agent_token: str = Header(alias="X-Agent-Token"),
):
    device = authenticate_device_for_rental(db, device_id, agent_token, rental_id)
    files = db.query(models.SyncFile).filter(models.SyncFile.site_id == device.site_id).all()
    return [{"file_id": f.file_id, "updated_at": f.updated_at.isoformat()} for f in files]

@app.post("/rentals/{rental_id}/sync/{file_id}")
async def upload_sync_file(
    rental_id: int,
    file_id: str,
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
    agent_token: str = Header(alias="X-Agent-Token"),
):
    device = authenticate_device_for_rental(db, device_id, agent_token, rental_id)
    if not is_valid_file_id(file_id):
        raise HTTPException(status_code=400, detail="Malformed file id.")
    blob_b64 = base64.b64encode(await request.body()).decode()
    existing = db.query(models.SyncFile).filter(
        models.SyncFile.site_id == device.site_id, models.SyncFile.file_id == file_id
    ).first()
    if existing:
        existing.blob = blob_b64
        existing.uploaded_by_device_id = device.id
        existing.updated_at = utcnow()
    else:
        db.add(models.SyncFile(
            rental_id=rental_id, site_id=device.site_id, file_id=file_id,
            blob=blob_b64, uploaded_by_device_id=device.id,
        ))
    db.commit()
    return {"ok": True}

@app.get("/rentals/{rental_id}/sync/{file_id}")
def download_sync_file(
    rental_id: int, file_id: str, device_id: int, db: Session = Depends(get_db),
    agent_token: str = Header(alias="X-Agent-Token"),
):
    device = authenticate_device_for_rental(db, device_id, agent_token, rental_id)
    record = db.query(models.SyncFile).filter(
        models.SyncFile.site_id == device.site_id, models.SyncFile.file_id == file_id
    ).first()
    if record is None:
        raise HTTPException(status_code=404)
    return Response(content=base64.b64decode(record.blob), media_type="application/octet-stream")

# ---------------------------------------------------------------------------
# auth pages
# ---------------------------------------------------------------------------

@app.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    if auth.user_for_token(db, request.cookies.get(auth.SESSION_COOKIE_NAME)):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None, "email": ""})

@app.post("/login")
async def sign_in(request: Request, db: Session = Depends(get_db)):
    form = await form_body(request)
    email = (form.get("email") or "").strip().lower()
    password = form.get("password") or ""
    client_ip = request.client.host if request.client else "unknown"

    def refuse(message):
        return templates.TemplateResponse(
            request, "login.html", {"error": message, "email": email}, status_code=401
        )

    if auth.login_is_blocked(client_ip, email):
        wait = auth.minutes_until_unblocked(client_ip, email)
        log.warning("login blocked by rate limit for %s from %s", email, client_ip)
        return refuse(
            f"Too many failed sign-in attempts. Try again in about {wait} minute(s)."
        )
    user = auth.find_user(db, email)
    if user is None or not auth.verify_password(password, user.password_hash):
        auth.record_failed_login(client_ip, email)
        log.warning("login failed for %s from %s", email, client_ip)
        remaining = auth.MAX_LOGIN_ATTEMPTS - len(auth.recent_failures(client_ip, email))
        if remaining <= 0:
            return refuse(
                f"Too many failed sign-in attempts. Try again in about "
                f"{auth.LOGIN_WINDOW_MINUTES} minute(s)."
            )
        return refuse(
            f"That email and password do not match. {remaining} attempt(s) left "
            f"before this address is locked out for {auth.LOGIN_WINDOW_MINUTES} minutes."
        )
    auth.clear_failed_logins(client_ip, email)
    log.info("login succeeded for %s (%s) from %s", email, user.role, client_ip)
    token = auth.create_session(db, user)
    response = RedirectResponse("/", status_code=303)
    auth.set_session_cookie(request, response, token)
    return response

SIGNUP_RATE_LIMIT_KEY = "__signup__"

@app.get("/signup")
def signup_page(request: Request, db: Session = Depends(get_db)):
    if auth.user_for_token(db, request.cookies.get(auth.SESSION_COOKIE_NAME)):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "signup.html", {"error": None, "name": "", "email": ""}
    )

@app.post("/signup")
async def sign_up(request: Request, db: Session = Depends(get_db)):
    form = await form_body(request)
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    password = form.get("password") or ""
    code = (form.get("company_code") or "").strip()
    client_ip = request.client.host if request.client else "unknown"

    def refuse(message):
        return templates.TemplateResponse(
            request, "signup.html", {"error": message, "name": name, "email": email}, status_code=400
        )

    if auth.login_is_blocked(client_ip, SIGNUP_RATE_LIMIT_KEY):
        wait = auth.minutes_until_unblocked(client_ip, SIGNUP_RATE_LIMIT_KEY)
        log.warning("signup blocked by rate limit from %s", client_ip)
        return refuse(f"Too many signup attempts from this address. Try again in about {wait} minute(s).")

    def fail(message):
        auth.record_failed_login(client_ip, SIGNUP_RATE_LIMIT_KEY)
        return refuse(message)

    if not name or not email:
        return fail("Name and email are required.")
    if auth.find_user(db, email):
        return fail("An account with that email already exists. Try signing in instead.")
    customer = db.query(models.Customer).filter(models.Customer.signup_code == code).first()
    if not code or customer is None or not secrets.compare_digest(customer.signup_code or "", code):
        log.warning("signup rejected: bad company code from %s", client_ip)
        return fail(
            "That company invite code is not valid. Ask a teammate who already has an "
            "account for the current one, on their Account page."
        )
    problem = auth.password_problem(password)
    if problem:
        return fail(problem)
    user = models.User(
        email=email,
        name=name,
        role=auth.MANAGER,
        customer_id=customer.id,
        password_hash=auth.hash_password(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    auth.clear_failed_logins(client_ip, SIGNUP_RATE_LIMIT_KEY)
    log.info("signup succeeded for %s at customer %s from %s", email, customer.name, client_ip)
    token = auth.create_session(db, user)
    response = RedirectResponse("/", status_code=303)
    auth.set_session_cookie(request, response, token)
    return response

@app.post("/logout")
def sign_out(request: Request, db: Session = Depends(get_db)):
    auth.delete_session(db, request.cookies.get(auth.SESSION_COOKIE_NAME))
    response = RedirectResponse("/login", status_code=303)
    auth.clear_session_cookie(response)
    return response

@app.get("/account")
def account_page(request: Request, user: models.User = Depends(signed_in_user)):
    return templates.TemplateResponse(
        request, "account.html", {"user": user, "error": None, "done": False}
    )

@app.post("/account/password")
async def change_password(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    form = await form_body(request)
    current = form.get("current_password") or ""
    new_password = form.get("new_password") or ""

    def show(error=None, done=False):
        return templates.TemplateResponse(
            request, "account.html", {"user": user, "error": error, "done": done}
        )

    if not auth.verify_password(current, user.password_hash):
        return show(error="Your current password is not correct.")
    problem = auth.password_problem(new_password)
    if problem:
        return show(error=problem)
    user.password_hash = auth.hash_password(new_password)
    db.commit()
    auth.delete_all_sessions_for_user(db, user)
    token = auth.create_session(db, user)
    response = show(done=True)
    auth.set_session_cookie(request, response, token)
    return response

# ---------------------------------------------------------------------------
# the fleet
# ---------------------------------------------------------------------------

@app.get("/fleet")
def fleet_page(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    devices = db.query(models.Device).order_by(models.Device.label).all()
    now = utcnow()
    return templates.TemplateResponse(
        request,
        "fleet.html",
        {
            "devices": devices,
            "now": now,
            "user": user,
            "tailscale": tailnet.status_summary(),
            "server_url": os.environ.get("PUBLIC_URL_BASE") or str(request.base_url).rstrip("/"),
            "offline_after": AGENT_OFFLINE_AFTER_SECONDS,
        },
    )

@app.post("/fleet/devices")
async def add_fleet_device(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    form = await form_body(request)
    label = (form.get("label") or "").strip()
    device_model = (form.get("model") or "").strip() or "Laptop"
    owner_note = (form.get("owner_note") or "").strip() or None
    asset_tag = (form.get("asset_tag") or "").strip() or None
    if not label:
        raise HTTPException(status_code=400, detail="A device needs a label.")
    device = models.Device(
        label=label,
        model=device_model,
        owner_note=owner_note,
        asset_tag=asset_tag,
        state="UNCLAIMED",
        status="IDLE",
        enrollment_key=secrets.token_urlsafe(12),
    )
    db.add(device)
    db.flush()
    db.add(models.AuditEvent(
        rental_id=None,
        device_id=device.id,
        action="device_created",
        actor=actor_name(user),
        details=f"{label} added to the fleet. Enrollment key issued.",
    ))
    db.commit()
    log.info("fleet device %s created by %s", label, actor_name(user))
    return RedirectResponse("/fleet", status_code=303)

@app.post("/fleet/devices/{device_id}/retire")
async def retire_fleet_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    device = db.get(models.Device, device_id)
    if device is None:
        raise HTTPException(status_code=404)
    if device.rental_id is not None:
        raise HTTPException(
            status_code=400,
            detail="Release this device from its rental before retiring it.",
        )
    kick_device_off_tailnet(device)
    device.state = "RETIRED"
    device.enrollment_key = None
    device.agent_token = None
    db.add(models.AuditEvent(
        rental_id=None,
        device_id=device.id,
        action="device_retired",
        actor=actor_name(user),
        details=f"{device.label} retired from the fleet.",
    ))
    db.commit()
    return RedirectResponse("/fleet", status_code=303)

@app.get("/fleet/tailnet-policy")
def tailnet_policy(user: models.User = Depends(admin_only)):
    """The policy file to paste into the Tailscale admin console.

    Declares the tag pool and gives each tag exactly one rule: it may reach
    itself and nothing else. That single rule is what isolates one rental's
    devices from every other device on the tailnet.
    """
    return Response(content=tailnet.policy_file_json(), media_type="application/json")

# ---------------------------------------------------------------------------
# rentals
# ---------------------------------------------------------------------------

@app.get("/")
def list_rentals(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    query = db.query(models.Rental)
    if user.role != auth.ADMIN:
        query = query.filter(models.Rental.customer_id == user.customer_id)
    rentals = query.order_by(models.Rental.end_date).all()
    customers = (
        db.query(models.Customer).order_by(models.Customer.name).all()
        if user.role == auth.ADMIN
        else []
    )
    return templates.TemplateResponse(
        request, "rentals.html", {"rentals": rentals, "customers": customers, "user": user}
    )

@app.post("/customers")
async def create_customer(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    form = await form_body(request)
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    if not name or not email:
        raise HTTPException(status_code=400, detail="A company needs a name and a contact email.")
    customer = models.Customer(name=name, email=email, signup_code=secrets.token_urlsafe(9))
    db.add(customer)
    db.commit()
    log.info("company created: %s by %s", name, actor_name(user))
    return RedirectResponse("/", status_code=303)

@app.post("/customers/{customer_id}/rentals")
async def create_rental(
    customer_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    customer = db.get(models.Customer, customer_id)
    if customer is None:
        raise HTTPException(status_code=404)
    form = await form_body(request)
    label = (form.get("label") or "").strip()
    try:
        minutes = int(form.get("minutes") or 0)
    except ValueError:
        raise HTTPException(status_code=400, detail="Duration must be a whole number of minutes.")
    if not label:
        raise HTTPException(status_code=400, detail="A rental needs a label.")
    if minutes < 1 or minutes > 43200:
        raise HTTPException(status_code=400, detail="Duration must be between 1 minute and 30 days (43200 minutes).")
    now = utcnow()
    rental = models.Rental(
        customer_id=customer.id,
        label=label,
        status="ACTIVE",
        start_date=now,
        end_date=now + datetime.timedelta(minutes=minutes),
        join_code=secrets.token_urlsafe(9),
    )
    db.add(rental)
    db.flush()
    db.add(models.AuditEvent(
        rental_id=rental.id,
        action="rental_created",
        actor=actor_name(user),
        details=f"Rental created for {customer.name}, ending in {minutes} minute(s).",
    ))
    db.commit()
    db.refresh(rental)
    get_or_create_default_site(db, rental)
    return RedirectResponse(f"/rentals/{rental.id}", status_code=303)

@app.get("/rentals/{rental_id}")
def rental_detail(
    rental_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    devices = sorted(rental.devices, key=lambda d: d.label)
    available = (
        db.query(models.Device)
        .filter(models.Device.state == "AVAILABLE", models.Device.rental_id.is_(None))
        .order_by(models.Device.label)
        .all()
        if user.role == auth.ADMIN
        else []
    )
    return templates.TemplateResponse(
        request,
        "rental.html",
        {
            "rental": rental,
            "devices": devices,
            "available": available,
            "events": recent_events(rental),
            "checklist": return_checklist(rental),
            "now": utcnow(),
            "user": user,
        },
    )

@app.post("/rentals/{rental_id}/assign")
async def assign_devices(
    rental_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    """Place one or more pooled devices into this rental.

    This is the whole "rental starts" step. The laptops are not touched - they
    find out on their next check-in, seconds later.
    """
    rental = rental_for_user(db, rental_id, user)
    if rental.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Only an ACTIVE rental can take devices.")
    body = (await request.body()).decode()
    submitted = parse_qs(body)
    device_ids = [int(v) for v in submitted.get("device_id", []) if v.isdigit()]
    raw_site = (submitted.get("site_id") or [None])[0]
    if not device_ids:
        raise HTTPException(status_code=400, detail="Pick at least one device to assign.")
    site = None
    if raw_site and str(raw_site).isdigit():
        site = db.get(models.Site, int(raw_site))
        if site is None or site.rental_id != rental.id:
            raise HTTPException(status_code=400, detail="That site does not belong to this rental.")
    if site is None:
        site = get_or_create_default_site(db, rental)
    guard_blast_radius(device_ids, len(device_ids) <= MAX_BLAST_RADIUS)
    for device_id in device_ids:
        device = db.get(models.Device, device_id)
        if device is None or device.rental_id is not None or device.state != "AVAILABLE":
            continue
        assign_device(db, device, rental, site, actor_name(user))
    await broadcast_rental_update(rental)
    return RedirectResponse(f"/rentals/{rental.id}", status_code=303)

@app.post("/devices/{device_id}/release")
async def release_to_pool(
    device_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    """Return a finished device to the fleet.

    Refused unless the device has a verified erasure certificate - a laptop
    cannot go back out to another customer on trust alone.
    """
    device = db.get(models.Device, device_id)
    if device is None:
        raise HTTPException(status_code=404)
    if device.rental_id is None:
        raise HTTPException(status_code=400, detail="That device is already in the pool.")
    if device.status not in ("ERASED", "LEFT", "REVOKED"):
        raise HTTPException(
            status_code=400,
            detail="A device can only go back to the pool after it is erased, revoked or has left.",
        )
    if device.status == "ERASED" and not device.certificate_payload:
        raise HTTPException(
            status_code=400,
            detail="No erasure certificate on record yet. The device is offline - it will "
            "sign one on next boot. Until then it cannot be re-rented.",
        )
    rental = device.rental
    await run_in_threadpool(release_device, db, device, device.status, actor_name(user))
    await broadcast_rental_update(rental)
    return RedirectResponse(f"/rentals/{rental.id}", status_code=303)

@app.post("/rentals/{rental_id}/lock")
async def lock_rental(
    rental_id: int,
    confirm: str = "",
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    if rental.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Rental must be ACTIVE to lock.")
    await run_in_threadpool(apply_lock, db, rental, actor_name(user), confirm == "yes")
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/rentals/{rental_id}/unlock")
async def unlock_rental(
    rental_id: int,
    confirm: str = "",
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    if rental.status != "LOCKED":
        raise HTTPException(status_code=400, detail="Rental must be LOCKED to unlock.")
    await run_in_threadpool(apply_unlock, db, rental, actor_name(user), confirm == "yes")
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/rentals/{rental_id}/confirm_erasure")
async def confirm_erasure(
    rental_id: int,
    confirm: str = "",
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    if rental.status != "LOCKED":
        raise HTTPException(
            status_code=400, detail="Rental must be LOCKED before erasure."
        )
    await run_in_threadpool(apply_erasure, db, rental, actor_name(user), confirm == "yes")
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/rentals/{rental_id}/extend")
async def extend_rental(
    rental_id: int,
    days: int = 30,
    confirm: str = "",
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    if rental.status == "ERASED":
        raise HTTPException(status_code=400, detail="An erased rental cannot be extended.")
    if days < 1 or days > 3650:
        raise HTTPException(status_code=400, detail="Extend by between 1 and 3650 days.")
    await run_in_threadpool(apply_extend, db, rental, actor_name(user), days, confirm == "yes")
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/rentals/{rental_id}/sites")
async def create_site(
    rental_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    name = (await form_or_query(request, "name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="A site needs a name.")
    if len(rental.sites) >= MAX_SITES_PER_RENTAL:
        raise HTTPException(
            status_code=400,
            detail=f"A rental can hold at most {MAX_SITES_PER_RENTAL} sites.",
        )
    if any(s.name == name for s in rental.sites):
        raise HTTPException(status_code=400, detail="That site name is already used in this rental.")
    tailnet_index = allocate_tailnet_index(db)
    if tailnet_index is None and tailnet.is_configured():
        raise HTTPException(
            status_code=400,
            detail=f"All {tailnet.TAG_POOL_SIZE} network tags are in use. Erase an old "
            f"rental to free one, or widen the pool in tailnet.py and update the policy file.",
        )
    used = {s.network_index for s in rental.sites}
    next_index = next(i for i in range(MAX_SITES_PER_RENTAL) if i not in used)
    site = models.Site(
        rental_id=rental.id, name=name,
        network_index=next_index, tailnet_index=tailnet_index,
    )
    db.add(site)
    event = models.AuditEvent(
        rental_id=rental.id,
        action="site_created",
        actor=actor_name(user),
        details=f"Site '{name}' created on its own network tag with its own workspace key.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/devices/{device_id}/site")
async def move_device_to_site(
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    device = device_for_user(db, device_id, user)
    raw_site_id = await form_or_query(request, "site_id")
    if raw_site_id is None or not str(raw_site_id).isdigit():
        raise HTTPException(status_code=400, detail="Send a site_id to move this device.")
    site = db.get(models.Site, int(raw_site_id))
    if site is None or site.rental_id != device.rental_id:
        raise HTTPException(status_code=400, detail="That site does not belong to this rental.")
    if device.site_id == site.id:
        return Response(status_code=204)
    rental = device.rental
    previous = device.site.name if device.site else "-"
    device.site_id = site.id
    device.has_workspace_key = False
    device.pending_key_offer_blob = None
    device.pending_key_offer_from = None
    # Force a fresh auth key so the node picks up the new site's tag.
    device.tailscale_auth_key_issued_at = None
    kick_device_off_tailnet(device)
    assignment = current_assignment(db, device)
    if assignment:
        assignment.site_id = site.id
    event = models.AuditEvent(
        rental_id=rental.id,
        device_id=device.id,
        action="site_moved",
        actor=actor_name(user),
        details=f"{device.label} moved from site '{previous}' to '{site.name}'. "
        f"It gets the new site's network tag and workspace key.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/devices/{device_id}/revoke")
async def revoke_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    device = device_for_user(db, device_id, user)
    if device.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Device must be ACTIVE to revoke.")
    rental = device.rental
    await run_in_threadpool(apply_revoke, db, device, actor_name(user))
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/devices/{device_id}/leave")
async def leave_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    device = device_for_user(db, device_id, user)
    if device.status in ("ERASED", "LEFT"):
        raise HTTPException(status_code=400, detail="Device has already left or been erased.")
    rental = device.rental
    await run_in_threadpool(apply_leave, db, device, actor_name(user))
    await broadcast_rental_update(rental)
    return Response(status_code=204)

# ---------------------------------------------------------------------------
# certificates and verification
# ---------------------------------------------------------------------------

@app.get("/devices/{device_id}/certificate")
def device_certificate(
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    device = device_for_user(db, device_id, user)
    if not device.certificate_payload:
        raise HTTPException(status_code=404, detail="No certificate issued for this device yet.")
    verify_url = certificates.build_verify_url(
        request, device.id, device.certificate_payload, device.certificate_signature
    )
    return templates.TemplateResponse(
        request, "certificate.html", {"device": device, "verify_url": verify_url, "user": user}
    )

@app.get("/devices/{device_id}/certificate/qr.png")
def device_certificate_qr(
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    device = device_for_user(db, device_id, user)
    if not device.certificate_payload:
        raise HTTPException(status_code=404)
    verify_url = certificates.build_verify_url(
        request, device.id, device.certificate_payload, device.certificate_signature
    )
    return Response(content=certificates.qr_png_bytes(verify_url), media_type="image/png")

def verification_checks(db, device, payload):
    """Everything a stranger with a phone gets to see.

    The signature is the part they can verify without trusting us at all. The
    other two are cross-checks against records written before the erasure.
    """
    assignment = (
        db.query(models.Assignment)
        .filter(
            models.Assignment.device_id == device.id,
            models.Assignment.rental_id == payload.get("rental_id"),
        )
        .order_by(models.Assignment.id.desc())
        .first()
    )
    rental = db.get(models.Rental, payload.get("rental_id"))
    site = db.get(models.Site, payload.get("site_id")) if payload.get("site_id") else None
    if site is None and assignment is not None:
        site = db.get(models.Site, assignment.site_id)
    checks = []
    checks.append({
        "label": "Nonce matches the erasure this customer ordered",
        "ok": bool(rental and rental.erasure_nonce
                   and payload.get("erasure_nonce") == rental.erasure_nonce),
        "detail": "Proves the certificate was signed after a human confirmed erasure, "
                  "not prepared in advance.",
    })
    checks.append({
        "label": "Key fingerprint matches the key recorded at rental start",
        "ok": bool(site and site.key_commitment
                   and payload.get("key_commitment") == site.key_commitment),
        "detail": "Proves the key that was destroyed is the key that guarded this "
                  "customer's files, published before anyone knew how the rental would end.",
    })
    return checks

@app.get("/verify")
def verify_certificate(
    device_id: int, data: str, sig: str, request: Request, db: Session = Depends(get_db)
):
    def refuse(message):
        return templates.TemplateResponse(
            request, "verify.html",
            {"valid": False, "error": message, "payload": None, "checks": []},
        )

    device = db.get(models.Device, device_id)
    if device is None or not device.public_key:
        return refuse("Unknown device - no certificate on record.")
    try:
        payload_json = certificates.decode_payload(data)
        payload = json.loads(payload_json)
    except Exception:
        return refuse("This certificate link is malformed.")
    if not certificates.verify_signature(device.public_key, payload_json, sig):
        return refuse("Signature does not match - this certificate has been tampered with.")
    checks = verification_checks(db, device, payload)
    return templates.TemplateResponse(
        request, "verify.html",
        {
            "valid": all(check["ok"] for check in checks),
            "error": None,
            "payload": payload,
            "checks": checks,
        },
    )

# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def return_checklist(rental):
    devices = list(rental.devices)
    total = len(devices)
    return [
        {
            "step": "Encryption key destroyed on the device",
            "done": len([d for d in devices if d.status == "ERASED"]),
            "total": total,
            "simulated": False,
        },
        {
            "step": "Signed erasure certificate issued",
            "done": len([d for d in devices if d.certificate_payload]),
            "total": total,
            "simulated": False,
        },
        {
            "step": "Removed from the private network",
            "done": len([d for d in devices if not d.tailscale_node_id]),
            "total": total,
            "simulated": False,
        },
        {
            "step": "Autopilot device ID deregistered",
            "done": len([d for d in devices if d.autopilot_deregistered_at]),
            "total": total,
            "simulated": True,
        },
        {
            "step": "BIOS/UEFI password removed",
            "done": len([d for d in devices if d.bios_password_cleared_at]),
            "total": total,
            "simulated": True,
        },
    ]

def build_report(request, rental):
    devices = sorted(rental.devices, key=lambda d: d.label)
    events = sorted(rental.audit_events, key=lambda e: e.id)
    generated_at = utcnow()
    device_lines = []
    for device in devices:
        verify_url = None
        if device.certificate_payload:
            verify_url = certificates.build_verify_url(
                request, device.id, device.certificate_payload, device.certificate_signature
            )
        device_lines.append({"device": device, "verify_url": verify_url})
    summary = {
        "device_count": len(devices),
        "erased": len([d for d in devices if d.status == "ERASED"]),
        "certificates": len([d for d in devices if d.certificate_payload]),
        "revoked": len([d for d in devices if d.status == "REVOKED"]),
        "left": len([d for d in devices if d.status == "LEFT"]),
        "event_count": len(events),
    }
    payload = {
        "report_of": "Lantern rental audit report",
        "rental_id": rental.id,
        "rental_label": rental.label,
        "customer": rental.customer.name,
        "rental_status": rental.status,
        "start_date": rental.start_date.isoformat() + "Z",
        "end_date": rental.end_date.isoformat() + "Z",
        "key_epoch": rental.key_epoch,
        "generated_at": generated_at.isoformat() + "Z",
        "summary": summary,
    }
    payload_json, signature = certificates.sign_report(payload)
    return {
        "rental": rental,
        "device_lines": device_lines,
        "events": events,
        "checklist": return_checklist(rental),
        "summary": summary,
        "generated_at": generated_at,
        "signature": signature,
        "report_public_key": certificates.report_public_key_base64(),
        "report_verify_url": certificates.build_report_verify_url(request, payload_json, signature),
    }

@app.get("/rentals/{rental_id}/report")
def rental_report(
    rental_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    context = build_report(request, rental)
    context["as_pdf"] = False
    return templates.TemplateResponse(request, "report.html", context)

@app.get("/rentals/{rental_id}/report.pdf")
def rental_report_pdf(
    rental_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(signed_in_user),
):
    rental = rental_for_user(db, rental_id, user)
    context = build_report(request, rental)
    context["as_pdf"] = True
    html = templates.env.get_template("report.html").render(request=request, **context)
    try:
        from weasyprint import HTML
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="PDF engine unavailable on this machine: "
            f"{error}. Open /rentals/{rental_id}/report and use the browser's "
            "Save as PDF button instead, or install the GTK3 runtime to enable WeasyPrint.",
        )
    pdf_bytes = HTML(string=html, base_url=str(request.base_url)).write_pdf()
    filename = f"lantern-audit-rental-{rental.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )

@app.get("/verify-report")
def verify_report(data: str, sig: str, request: Request):
    try:
        payload_json = certificates.decode_payload(data)
    except Exception:
        return templates.TemplateResponse(
            request, "verify.html",
            {"valid": False, "error": "This report link is malformed.",
             "payload": None, "kind": "report", "checks": []},
        )
    valid = certificates.verify_signature(
        certificates.report_public_key_base64(), payload_json, sig
    )
    if valid:
        return templates.TemplateResponse(
            request, "verify.html",
            {"valid": True, "error": None, "payload": json.loads(payload_json),
             "kind": "report", "checks": []},
        )
    return templates.TemplateResponse(
        request, "verify.html",
        {
            "valid": False,
            "error": "Signature does not match - this report has been tampered with.",
            "payload": None,
            "kind": "report",
            "checks": [],
        },
    )

@app.get("/metrics")
def reuse_metrics(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    """Reuse metrics now read from assignment history rather than guessing from
    asset tags, because one laptop is now one row across all its rentals."""
    devices = db.query(models.Device).order_by(models.Device.label).all()
    assignments = db.query(models.Assignment).all()
    by_device = {}
    for assignment in assignments:
        by_device.setdefault(assignment.device_id, []).append(assignment)

    turnarounds = []
    for placements in by_device.values():
        ordered = sorted(placements, key=lambda a: a.assigned_at or utcnow())
        for earlier, later in zip(ordered, ordered[1:]):
            if earlier.released_at and later.assigned_at:
                gap = (later.assigned_at - earlier.released_at).days
                if gap >= 0:
                    turnarounds.append(gap)

    erased = [a for a in assignments if a.end_state == "ERASED"]
    certified = len([d for d in devices if d.certificate_payload])
    reused = sorted(
        (
            {
                "label": device.label,
                "asset_tag": device.asset_tag or "-",
                "rentals": len(by_device.get(device.id, [])),
                "customers": sorted({
                    a.rental.customer.name for a in by_device.get(device.id, []) if a.rental
                }),
                "latest": max(
                    (a.assigned_at for a in by_device.get(device.id, []) if a.assigned_at),
                    default=None,
                ),
            }
            for device in devices
            if len(by_device.get(device.id, [])) > 1
        ),
        key=lambda row: (-row["rentals"], row["label"]),
    )
    device_count = len(devices)
    placement_count = len(assignments)
    return templates.TemplateResponse(
        request,
        "metrics.html",
        {
            "asset_count": device_count,
            "placement_count": placement_count,
            "rentals_per_asset": round(placement_count / device_count, 2) if device_count else 0,
            "erased_count": len(erased),
            "certified_count": certified,
            "certified_percent": round(100 * certified / len(erased)) if erased else 0,
            "turnaround_count": len(turnarounds),
            "average_turnaround": round(sum(turnarounds) / len(turnarounds), 1) if turnarounds else 0,
            "fastest_turnaround": min(turnarounds) if turnarounds else 0,
            "slowest_turnaround": max(turnarounds) if turnarounds else 0,
            "reused": reused,
            "user": user,
        },
    )

def websocket_visitor_may_watch(rental_id, websocket):
    db = SessionLocal()
    try:
        user = auth.user_for_token(db, websocket.cookies.get(auth.SESSION_COOKIE_NAME))
        if user is None:
            return False
        rental = db.get(models.Rental, rental_id)
        return rental is not None and auth.can_see_rental(user, rental)
    finally:
        db.close()

@app.websocket("/ws/rentals/{rental_id}")
async def rental_ws(websocket: WebSocket, rental_id: int):
    if not websocket_visitor_may_watch(rental_id, websocket):
        await websocket.close(code=1008)
        return
    await manager.connect(rental_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(rental_id, websocket)
