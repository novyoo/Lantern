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

from database import get_db, SessionLocal, engine_name
import models
import auth
import certificates
import network
from scheduler import start_scheduler

MAX_BLAST_RADIUS = 10
AGENT_OFFLINE_AFTER_SECONDS = 15
WORKSPACE_KEY_ORIGINATOR_WINDOW_SECONDS = 60
MAX_EVENTS_SHOWN = 50

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s %(name)s %(message)s",
)
logging.Formatter.converter = time.gmtime
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
log = logging.getLogger("lantern")

started_at = datetime.datetime.utcnow()

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "startup database=%s wireguard_tools=%s https_cookies=%s public_url=%s",
        engine_name(),
        network.wg_tools_available(),
        os.environ.get("LANTERN_HTTPS") == "1",
        os.environ.get("PUBLIC_URL_BASE") or "from request",
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
        "wireguard_tools": network.wg_tools_available(),
        "uptime_seconds": round((datetime.datetime.utcnow() - started_at).total_seconds()),
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
    if device is None or not auth.can_see_rental(user, device.rental):
        raise HTTPException(status_code=404)
    return device

async def form_body(request):
    body = (await request.body()).decode()
    return {key: values[0] for key, values in parse_qs(body).items()}

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

def get_or_create_default_site(db, rental):
    site = (
        db.query(models.Site)
        .filter(models.Site.rental_id == rental.id)
        .order_by(models.Site.network_index)
        .first()
    )
    if site:
        return site
    site = models.Site(rental_id=rental.id, name="Main", network_index=0)
    db.add(site)
    db.commit()
    db.refresh(site)
    return site

def devices_in_site(rental, site):
    return [d for d in rental.devices if d.site_id == site.id]

def sync_rental_network(rental):
    for site in rental.sites:
        network.sync_hub_peers(rental.id, site.network_index, devices_in_site(rental, site))

def next_free_site_ip(db, device):
    taken = {
        other.wg_ip
        for other in db.query(models.Device).filter(models.Device.site_id == device.site_id).all()
        if other.wg_ip
    }
    for index in range(250):
        candidate = network.assign_device_ip(
            device.rental_id, device.site.network_index, index
        )
        if candidate not in taken:
            return candidate
    return None

def teardown_rental_network(rental):
    for site in rental.sites:
        network.teardown_hub_interface(rental.id, site.network_index)

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
    sync_rental_network(rental)
    return event

def apply_unlock(db, rental, actor, confirmed=False):
    affected = [d for d in rental.devices if d.status == "LOCKED"]
    guard_blast_radius(affected, confirmed)
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
    sync_rental_network(rental)
    return event

def apply_erasure(db, rental, actor, confirmed=False):
    affected = list(rental.devices)
    guard_blast_radius(affected, confirmed)
    now = datetime.datetime.utcnow()
    deregistered = 0
    for device in affected:
        device.status = "ERASED"
        if device.autopilot_id and not device.autopilot_deregistered_at:
            device.autopilot_deregistered_at = now
            deregistered += 1
    rental.status = "ERASED"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="erasure_confirmed",
        actor=actor,
        details=f"Erasure confirmed. {len(affected)} device(s) erased.",
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
    teardown_rental_network(rental)
    return event

def apply_extend(db, rental, actor, days, confirmed=False):
    affected = [d for d in rental.devices if d.status == "LOCKED"]
    guard_blast_radius(affected, confirmed)
    now = datetime.datetime.utcnow()
    base = rental.end_date if rental.end_date > now else now
    rental.end_date = base + datetime.timedelta(days=days)
    rental.key_epoch = rental.key_epoch + 1
    for device in affected:
        device.status = "ACTIVE"
    rental.status = "ACTIVE"
    event = models.AuditEvent(
        rental_id=rental.id,
        action="extend",
        actor=actor,
        details=f"Extended by {days} day(s). New end date {rental.end_date.isoformat()}Z. "
        f"Keys reissued (epoch {rental.key_epoch}). {len(affected)} device(s) unlocked.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    sync_rental_network(rental)
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
    sync_rental_network(device.rental)
    return event

def apply_leave(db, device, actor):
    device.status = "LEFT"
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
    sync_rental_network(device.rental)
    return event

def recent_events(rental):
    return sorted(rental.audit_events, key=lambda e: e.id, reverse=True)[:MAX_EVENTS_SHOWN]

def render_broadcast_fragments(rental):
    fragments = templates.env.get_template("_fragments.html").module
    now = datetime.datetime.utcnow()
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
    now = datetime.datetime.utcnow()
    piece = str(fragments.device_row(rental, device, now, oob=True))
    await manager.broadcast(rental.id, piece)

class AgentRegisterRequest(BaseModel):
    label: str
    model: str
    join_code: str | None = None
    site: str | None = None

class KeyOffer(BaseModel):
    for_device_id: int
    blob: str

class AgentCheckinRequest(BaseModel):
    device_id: int
    agent_token: str
    applied_status: str | None = None
    public_key: str | None = None
    certificate_payload: str | None = None
    certificate_signature: str | None = None
    wg_public_key: str | None = None
    wg_key_epoch: int = 1
    has_workspace_key: bool = False
    key_offers: list[KeyOffer] | None = None
    autopilot_id: str | None = None
    bios_password_cleared: bool = False

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
        join_code=secrets.token_urlsafe(9),
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
    if payload.autopilot_id and not device.autopilot_id:
        device.autopilot_id = payload.autopilot_id
    if payload.bios_password_cleared and not device.bios_password_cleared_at:
        device.bios_password_cleared_at = datetime.datetime.utcnow()
        events.append(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="bios_password_cleared",
            actor=device.label,
            details="BIOS/UEFI supervisor password removed for return (simulated).",
        ))
    if device.site is None:
        device.site = get_or_create_default_site(db, device.rental)
    network_changed = False
    rental_epoch = device.rental.key_epoch
    rotating = (
        payload.wg_public_key
        and device.wg_key_epoch < rental_epoch
        and payload.wg_key_epoch == rental_epoch
    )
    if payload.wg_public_key and not device.wg_public_key:
        device.wg_public_key = payload.wg_public_key
        device.wg_key_epoch = rental_epoch
        network_changed = True
    elif rotating:
        device.wg_public_key = payload.wg_public_key
        device.wg_key_epoch = rental_epoch
        network_changed = True
        events.append(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="key_reissued",
            actor=device.label,
            details=f"Network key rotated for key epoch {rental_epoch} after the rental was extended.",
        ))
    if device.status == "ACTIVE" and device.wg_public_key and not device.wg_ip:
        device.wg_ip = next_free_site_ip(db, device)
        network_changed = True
        events.append(models.AuditEvent(
            rental_id=device.rental_id,
            device_id=device.id,
            action="network_joined",
            actor=device.label,
            details=f"Assigned {device.wg_ip} on site '{device.site.name}'.",
        ))
    device.has_workspace_key = bool(payload.has_workspace_key)
    if device.has_workspace_key and device.wg_public_key and payload.key_offers:
        for offer in payload.key_offers:
            target = db.get(models.Device, offer.for_device_id)
            if target and target.site_id == device.site_id and not target.has_workspace_key:
                target.pending_key_offer_blob = offer.blob
                target.pending_key_offer_from = device.wg_public_key
    for event in events:
        db.add(event)
    db.commit()
    for event in events:
        db.refresh(event)
    if network_changed:
        sync_rental_network(device.rental)
    return events

def build_network_payload(db, device, rental):
    if device.status != "ACTIVE" or not device.wg_ip:
        return None
    _, hub_public_key = network.get_or_create_hub_keypair()
    site = device.site
    site_devices = [d for d in rental.devices if d.site_id == device.site_id]
    key_requests = []
    originate_workspace_key = False
    if device.has_workspace_key:
        key_requests = [
            {"device_id": d.id, "wg_public_key": d.wg_public_key}
            for d in site_devices
            if d.status == "ACTIVE" and d.wg_public_key and not d.has_workspace_key and d.id != device.id
        ]
    else:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(
            seconds=WORKSPACE_KEY_ORIGINATOR_WINDOW_SECONDS
        )
        candidates = [
            d for d in site_devices
            if d.status == "ACTIVE"
            and d.wg_public_key
            and not d.has_workspace_key
            and d.last_seen_at
            and d.last_seen_at >= cutoff
        ]
        any_holder = any(d.has_workspace_key for d in site_devices if d.status == "ACTIVE")
        if not any_holder and candidates and min(d.id for d in candidates) == device.id:
            originate_workspace_key = True
    pending_offer = None
    if device.pending_key_offer_blob:
        pending_offer = {
            "blob": device.pending_key_offer_blob,
            "from_wg_public_key": device.pending_key_offer_from,
        }
        device.pending_key_offer_blob = None
        device.pending_key_offer_from = None
        db.commit()
    return {
        "wg_ip": device.wg_ip,
        "site_id": site.id,
        "site_name": site.name,
        "key_epoch": rental.key_epoch,
        "hub_public_key": hub_public_key,
        "hub_endpoint": network.hub_endpoint(rental.id, site.network_index),
        "allowed_ips": f"{network.site_subnet(rental.id, site.network_index)}.0/24",
        "needs_workspace_key": not device.has_workspace_key,
        "originate_workspace_key": originate_workspace_key,
        "pending_key_offer": pending_offer,
        "key_requests": key_requests,
    }

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
def account_page(
    request: Request,
    user: models.User = Depends(signed_in_user),
):
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
    now = datetime.datetime.utcnow()
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
    events = recent_events(rental)
    return templates.TemplateResponse(
        request,
        "rental.html",
        {
            "rental": rental,
            "devices": devices,
            "events": events,
            "checklist": return_checklist(rental),
            "now": datetime.datetime.utcnow(),
            "user": user,
        },
    )

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
    apply_lock(db, rental, actor=actor_name(user), confirmed=confirm == "yes")
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
    apply_unlock(db, rental, actor=actor_name(user), confirmed=confirm == "yes")
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
    apply_erasure(db, rental, actor=actor_name(user), confirmed=confirm == "yes")
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
    apply_extend(db, rental, actor=actor_name(user), days=days, confirmed=confirm == "yes")
    await broadcast_rental_update(rental)
    return Response(status_code=204)

async def form_or_query(request, field):
    value = request.query_params.get(field)
    if value is not None:
        return value
    body = (await request.body()).decode()
    submitted = parse_qs(body).get(field)
    return submitted[0] if submitted else None

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
    if len(rental.sites) >= network.MAX_SITES_PER_RENTAL:
        raise HTTPException(
            status_code=400,
            detail=f"A rental can hold at most {network.MAX_SITES_PER_RENTAL} sites.",
        )
    if any(s.name == name for s in rental.sites):
        raise HTTPException(status_code=400, detail="That site name is already used in this rental.")
    used = {s.network_index for s in rental.sites}
    next_index = next(i for i in range(network.MAX_SITES_PER_RENTAL) if i not in used)
    site = models.Site(rental_id=rental.id, name=name, network_index=next_index)
    db.add(site)
    event = models.AuditEvent(
        rental_id=rental.id,
        action="site_created",
        actor=actor_name(user),
        details=f"Site '{name}' created with its own isolated network.",
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
    device.wg_ip = None
    device.has_workspace_key = False
    device.pending_key_offer_blob = None
    device.pending_key_offer_from = None
    event = models.AuditEvent(
        rental_id=rental.id,
        device_id=device.id,
        action="site_moved",
        actor=actor_name(user),
        details=f"{device.label} moved from site '{previous}' to '{site.name}'. "
        f"It gets a new address and the new site's workspace key.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    sync_rental_network(rental)
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
    apply_revoke(db, device, actor=actor_name(user))
    await broadcast_rental_update(rental)
    return Response(status_code=204)

@app.post("/agent/register")
def agent_register(payload: AgentRegisterRequest, db: Session = Depends(get_db)):
    if payload.join_code:
        rental = (
            db.query(models.Rental)
            .filter(models.Rental.join_code == payload.join_code.strip())
            .first()
        )
        if rental is None or rental.status != "ACTIVE":
            raise HTTPException(status_code=400, detail="Invalid or inactive join code.")
        joined_with_code = True
    else:
        rental = get_or_create_live_devices_rental(db)
        joined_with_code = False
    site = None
    if payload.site:
        site = (
            db.query(models.Site)
            .filter(models.Site.rental_id == rental.id, models.Site.name == payload.site)
            .first()
        )
    if site is None:
        site = get_or_create_default_site(db, rental)
    device = models.Device(
        rental_id=rental.id,
        site_id=site.id,
        label=payload.label,
        model=payload.model,
        status="ACTIVE",
        agent_token=secrets.token_hex(32),
        last_seen_at=datetime.datetime.utcnow(),
        wg_key_epoch=rental.key_epoch,
    )
    db.add(device)
    db.flush()
    details = (
        f"{payload.label} joined '{rental.label}' (site '{site.name}') using its join code."
        if joined_with_code
        else f"{payload.label} registered as a live agent in site '{site.name}'."
    )
    event = models.AuditEvent(
        rental_id=rental.id,
        device_id=device.id,
        action="agent_registered",
        actor=payload.label,
        details=details,
    )
    db.add(event)
    db.commit()
    db.refresh(device)
    return {
        "device_id": device.id,
        "agent_token": device.agent_token,
        "rental_id": rental.id,
        "site_id": site.id,
        "key_epoch": rental.key_epoch,
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
    network_info = build_network_payload(db, device, rental)
    if events:
        await broadcast_rental_update(rental)
    else:
        await broadcast_device_row(rental, device)
    return {"device_status": device.status, "rental_status": rental.status, "network": network_info}

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
    apply_leave(db, device, actor=actor_name(user))
    await broadcast_rental_update(rental)
    return Response(status_code=204)

def authenticate_device_for_rental(db, device_id, agent_token, rental_id):
    device = db.get(models.Device, device_id)
    if device is None or not secrets.compare_digest(device.agent_token or "", agent_token):
        raise HTTPException(status_code=401, detail="Unknown device or bad token.")
    if device.rental_id != rental_id:
        raise HTTPException(status_code=403, detail="Device does not belong to this rental.")
    if device.status != "ACTIVE":
        raise HTTPException(status_code=403, detail="Device is not active in this rental.")
    return device

@app.get("/rentals/{rental_id}/sync")
def list_sync_files(rental_id: int, device_id: int, agent_token: str, db: Session = Depends(get_db)):
    device = authenticate_device_for_rental(db, device_id, agent_token, rental_id)
    files = db.query(models.SyncFile).filter(models.SyncFile.site_id == device.site_id).all()
    return [{"filename": f.filename, "updated_at": f.updated_at.isoformat()} for f in files]

@app.post("/rentals/{rental_id}/sync/{filename}")
async def upload_sync_file(
    rental_id: int, filename: str, device_id: int, agent_token: str, request: Request, db: Session = Depends(get_db)
):
    device = authenticate_device_for_rental(db, device_id, agent_token, rental_id)
    blob = await request.body()
    blob_b64 = base64.b64encode(blob).decode()
    existing = db.query(models.SyncFile).filter(
        models.SyncFile.site_id == device.site_id, models.SyncFile.filename == filename
    ).first()
    if existing:
        existing.blob = blob_b64
        existing.uploaded_by_device_id = device.id
        existing.updated_at = datetime.datetime.utcnow()
    else:
        db.add(models.SyncFile(
            rental_id=rental_id, site_id=device.site_id, filename=filename,
            blob=blob_b64, uploaded_by_device_id=device.id,
        ))
    db.commit()
    return {"ok": True}

@app.get("/rentals/{rental_id}/sync/{filename}")
def download_sync_file(rental_id: int, filename: str, device_id: int, agent_token: str, db: Session = Depends(get_db)):
    device = authenticate_device_for_rental(db, device_id, agent_token, rental_id)
    record = db.query(models.SyncFile).filter(
        models.SyncFile.site_id == device.site_id, models.SyncFile.filename == filename
    ).first()
    if record is None:
        raise HTTPException(status_code=404)
    return Response(content=base64.b64decode(record.blob), media_type="application/octet-stream")

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
    generated_at = datetime.datetime.utcnow()
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
            request,
            "verify.html",
            {"valid": False, "error": "This report link is malformed.", "payload": None, "kind": "report"},
        )
    valid = certificates.verify_signature(
        certificates.report_public_key_base64(), payload_json, sig
    )
    if valid:
        return templates.TemplateResponse(
            request, "verify.html",
            {"valid": True, "error": None, "payload": json.loads(payload_json), "kind": "report"},
        )
    return templates.TemplateResponse(
        request,
        "verify.html",
        {
            "valid": False,
            "error": "Signature does not match - this report has been tampered with.",
            "payload": None,
            "kind": "report",
        },
    )

@app.get("/metrics")
def reuse_metrics(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(admin_only),
):
    devices = db.query(models.Device).filter(models.Device.asset_tag.isnot(None)).all()
    placements_by_asset = {}
    for device in devices:
        placements_by_asset.setdefault(device.asset_tag, []).append(device)
    turnarounds = []
    for asset_tag, placements in placements_by_asset.items():
        ordered = sorted(placements, key=lambda d: d.rental.start_date)
        for earlier, later in zip(ordered, ordered[1:]):
            if earlier.status == "ERASED":
                gap = (later.rental.start_date - earlier.rental.end_date).days
                if gap >= 0:
                    turnarounds.append(gap)
    erased = [d for d in devices if d.status == "ERASED"]
    certified = [d for d in erased if d.certificate_payload]
    reused = sorted(
        (
            {
                "asset_tag": tag,
                "rentals": len(placements),
                "customers": sorted({d.rental.customer.name for d in placements}),
                "latest": max(d.rental.start_date for d in placements),
            }
            for tag, placements in placements_by_asset.items()
            if len(placements) > 1
        ),
        key=lambda row: (-row["rentals"], row["asset_tag"]),
    )
    asset_count = len(placements_by_asset)
    return templates.TemplateResponse(
        request,
        "metrics.html",
        {
            "asset_count": asset_count,
            "placement_count": len(devices),
            "rentals_per_asset": round(len(devices) / asset_count, 2) if asset_count else 0,
            "erased_count": len(erased),
            "certified_count": len(certified),
            "certified_percent": round(100 * len(certified) / len(erased)) if erased else 0,
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
