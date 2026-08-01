import datetime
import hashlib
import itertools
import secrets
import uuid

from database import SessionLocal
import models
import auth
import crypto
import certificates

DEMO_PASSWORD = "lantern-demo-2026!"

db = SessionLocal()

db.query(models.SyncFile).delete()
db.query(models.AuditEvent).delete()
db.query(models.Assignment).delete()
db.query(models.Device).delete()
db.query(models.Site).delete()
db.query(models.UserSession).delete()
db.query(models.User).delete()
db.query(models.Rental).delete()
db.query(models.Customer).delete()
db.commit()

now = datetime.datetime.utcnow()

cp = models.Customer(name="CP Manufacturing", email="it@cp-manufacturing.example.com")
logicality = models.Customer(name="Logicality Inc", email="it@logicality.example.com")
dm_locs = models.Customer(name="DM locs", email="it@dm-locs.example.com")
project_inc = models.Customer(name="Project Inc", email="it@project-inc.example.com")
db.add_all([cp, logicality, dm_locs, project_inc])
db.commit()

def add_user(email, name, role, customer):
    db.add(models.User(
        email=email,
        name=name,
        role=role,
        customer_id=customer.id if customer else None,
        password_hash=auth.hash_password(DEMO_PASSWORD),
    ))

add_user("admin@yrl.example.com", "Tanaka", auth.ADMIN, None)
add_user(cp.email, "CP Manufacturing IT", auth.MANAGER, cp)
add_user(logicality.email, "Logicality IT", auth.MANAGER, logicality)
add_user(dm_locs.email, "DM locs IT", auth.MANAGER, dm_locs)
add_user(project_inc.email, "Project Inc IT", auth.MANAGER, project_inc)
db.commit()

def add_audit(rental, action, actor, details, device=None):
    event = models.AuditEvent(
        rental_id=rental.id,
        device_id=device.id if device else None,
        action=action,
        actor=actor,
        details=details,
    )
    db.add(event)

rental1 = models.Rental(
    customer_id=cp.id,
    label="CP Manufacturing HQ Rollout",
    status="ACTIVE",
    start_date=now - datetime.timedelta(days=30),
    end_date=now + datetime.timedelta(days=60),
)
rental2 = models.Rental(
    customer_id=cp.id,
    label="CP Manufacturing Field Team",
    status="ACTIVE",
    start_date=now - datetime.timedelta(days=10),
    end_date=now + datetime.timedelta(days=5),
)
rental3 = models.Rental(
    customer_id=logicality.id,
    label="Logicality Inc Warehouse",
    status="ACTIVE",
    start_date=now - datetime.timedelta(days=5),
    end_date=now + datetime.timedelta(days=90),
)
rental4 = models.Rental(
    customer_id=dm_locs.id,
    label="DM locs Line 2",
    status="LOCKED",
    start_date=now - datetime.timedelta(days=100),
    end_date=now - datetime.timedelta(days=2),
)
rental5 = models.Rental(
    customer_id=project_inc.id,
    label="Project Inc Pilot",
    status="ERASED",
    start_date=now - datetime.timedelta(days=200),
    end_date=now - datetime.timedelta(days=45),
)
rental6 = models.Rental(
    customer_id=project_inc.id,
    label="Project Inc Expansion",
    status="ACTIVE",
    start_date=now,
    end_date=now + datetime.timedelta(days=120),
)
db.add_all([rental1, rental2, rental3, rental4, rental5, rental6])
db.commit()

for rental in [rental1, rental2, rental3, rental4, rental5, rental6]:
    rental.join_code = secrets.token_urlsafe(9)
db.commit()

for rental in [rental1, rental2, rental3, rental4, rental5, rental6]:
    add_audit(rental, "rental_created", "system", "Rental created and devices assigned.")

add_audit(rental4, "auto_lock", "system", "Rental term ended, all devices locked automatically.")
add_audit(rental5, "auto_lock", "system", "Rental term ended, all devices locked automatically.")
add_audit(rental5, "erasure_confirmed", "Customer Manager", "Customer confirmed erasure, keys destroyed fleet-wide.")
db.commit()

tailnet_counter = itertools.count()

def add_site(rental, name, index):
    site = models.Site(
        rental_id=rental.id, name=name, network_index=index,
        tailnet_index=next(tailnet_counter),
        # Published when the site's workspace key was created, at the start of
        # the rental. Erasure certificates are checked against it.
        key_commitment=hashlib.sha256(
            b"lantern-key-commitment-v1" + secrets.token_bytes(32)
        ).hexdigest(),
    )
    db.add(site)
    return site

tokyo1 = add_site(rental1, "Tokyo HQ", 0)
osaka1 = add_site(rental1, "Osaka Branch", 1)
main2 = add_site(rental2, "Main", 0)
main3 = add_site(rental3, "Main", 0)
main4 = add_site(rental4, "Main", 0)
main5 = add_site(rental5, "Main", 0)
tokyo6 = add_site(rental6, "Tokyo HQ", 0)
contractor6 = add_site(rental6, "Contractor", 1)
db.commit()

device_models = [
    "Dell Latitude 5420",
    "Lenovo ThinkPad T14",
    "HP EliteBook 840 G8",
    "Panasonic Toughbook CF-33",
    "Microsoft Surface Laptop 5",
    "Yokogawa DL350 ScopeCorder",
    "Dell Precision 3571",
    "Lenovo ThinkCentre M70q",
]

device_plan = [
    (rental5, main5, "ERASED", 20),
    (rental1, tokyo1, "ACTIVE", 10),
    (rental1, osaka1, "ACTIVE", 8),
    (rental2, main2, "ACTIVE", 14),
    (rental3, main3, "ACTIVE", 16),
    (rental4, main4, "LOCKED", 15),
    (rental6, tokyo6, "ACTIVE", 9),
    (rental6, contractor6, "ACTIVE", 8),
]

CERTIFICATES_ON_ERASED_RENTAL = 17
returning_assets = []
# asset tag -> the rental it was erased from, so a re-rented laptop carries a
# real placement history rather than an implied one.
previously_erased_assets = {}
# The nonce a human's erasure confirmation issued. Certificates quote it, and
# the public verify page checks it, so they cannot have been signed in advance.
rental5.erasure_nonce = secrets.token_hex(16)
rental5.erasure_confirmed_at = rental5.end_date
db.commit()
reuse_plan = {tokyo1.id: 8, main3.id: 7, tokyo6.id: 5}

recovery_keys_by_rental = {}

def get_recovery_key(rental):
    if rental.id not in recovery_keys_by_rental:
        key = crypto.generate_key()
        recovery_keys_by_rental[rental.id] = key
        print(f"Recovery key for '{rental.label}' (customer downloads this once, the server keeps only the wrapped blob): {crypto.to_base64(key)}")
    return recovery_keys_by_rental[rental.id]

next_asset_number = 100001
devices_per_rental = {}

def next_asset_tag():
    global next_asset_number
    tag = f"YRL-{next_asset_number}"
    next_asset_number += 1
    return tag

def simulated_autopilot_id(asset_tag):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"lantern-autopilot-{asset_tag}"))

device_count = 0
for rental, site, status, count in device_plan:
    recovery_key = get_recovery_key(rental)
    reuse_remaining = reuse_plan.get(site.id, 0)
    for i in range(count):
        device_count += 1
        seq = devices_per_rental.get(rental.id, 0) + 1
        devices_per_rental[rental.id] = seq
        if reuse_remaining > 0 and returning_assets:
            asset_tag = returning_assets.pop(0)
            reuse_remaining -= 1
        else:
            asset_tag = next_asset_tag()
        device_key = crypto.generate_key()
        wrapped_blob = crypto.wrap_device_key(recovery_key, device_key)
        reused_asset = asset_tag in previously_erased_assets
        device = models.Device(
            rental_id=rental.id,
            site_id=site.id,
            label=f"{rental.label} - {seq:02d}",
            model=device_models[device_count % len(device_models)],
            status=status,
            state="ASSIGNED",
            enrollment_key=secrets.token_urlsafe(12),
            enrolled_at=rental.start_date,
            asset_tag=asset_tag,
            autopilot_id=simulated_autopilot_id(asset_tag),
            wrapped_key_blob=crypto.to_base64(wrapped_blob),
            key_epoch=rental.key_epoch,
        )
        db.add(device)
        db.flush()

        # A laptop that already served an erased rental carries that history, so
        # the reuse metrics count real placements rather than guessing from tags.
        if reused_asset:
            db.add(models.Assignment(
                device_id=device.id,
                rental_id=previously_erased_assets[asset_tag].id,
                site_id=main5.id,
                assigned_at=previously_erased_assets[asset_tag].start_date,
                released_at=previously_erased_assets[asset_tag].end_date,
                end_state="ERASED",
            ))
        db.add(models.Assignment(
            device_id=device.id,
            rental_id=rental.id,
            site_id=site.id,
            assigned_at=rental.start_date,
        ))

        if status == "ERASED":
            returning_assets.append(asset_tag)
            previously_erased_assets[asset_tag] = rental
            if i < CERTIFICATES_ON_ERASED_RENTAL:
                signing_key = certificates.generate_signing_key()
                payload_json, signature = certificates.sign_certificate(signing_key, {
                    "device_id": device.id,
                    "rental_id": rental.id,
                    "site_id": site.id,
                    "device_label": device.label,
                    "agent_version": "2.0",
                    "erased_at": rental.end_date.isoformat() + "Z",
                    "reason": "Rental erasure confirmed",
                    "key_commitment": site.key_commitment,
                    "erasure_nonce": rental.erasure_nonce,
                })
                device.public_key = certificates.public_key_base64(signing_key)
                device.certificate_payload = payload_json
                device.certificate_signature = signature
                device.autopilot_deregistered_at = rental.end_date
                device.bios_password_cleared_at = rental.end_date
                add_audit(rental, "certificate_issued", device.label,
                          "Signed erasure certificate received and verified.", device=device)
db.commit()

add_audit(rental5, "autopilot_deregistered", "system",
          f"{CERTIFICATES_ON_ERASED_RENTAL} device ID(s) removed from Autopilot enrolment (simulated).")
db.commit()

print()
print(f"Sign in at http://127.0.0.1:8000 with password: {DEMO_PASSWORD}")
for user in db.query(models.User).order_by(models.User.id).all():
    scope = user.customer.name if user.customer else "every customer"
    print(f"  {user.email:38} {user.role:18} sees {scope}")
print()
print(f"Seeded {db.query(models.Customer).count()} customers")
print(f"Seeded {db.query(models.User).count()} users")
print(f"Seeded {db.query(models.Rental).count()} rentals")
print(f"Seeded {db.query(models.Site).count()} sites")
print(f"Seeded {db.query(models.Device).count()} devices")
print(f"Seeded {db.query(models.Device.asset_tag).distinct().count()} distinct physical assets")
print(f"Seeded {db.query(models.AuditEvent).count()} audit events")

db.close()
