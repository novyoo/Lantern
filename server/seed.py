import datetime

from database import SessionLocal
import models
import crypto

db = SessionLocal()

db.query(models.AuditEvent).delete()
db.query(models.Device).delete()
db.query(models.Site).delete()
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

def add_audit(rental, action, actor, details):
    event = models.AuditEvent(
        rental_id=rental.id,
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
    end_date=now - datetime.timedelta(days=30),
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
    add_audit(rental, "rental_created", "system", "Rental created and devices assigned.")

add_audit(rental4, "auto_lock", "system", "Rental term ended, all devices locked automatically.")
add_audit(rental5, "auto_lock", "system", "Rental term ended, all devices locked automatically.")
add_audit(rental5, "erasure_confirmed", "Customer Manager", "Customer confirmed erasure, keys destroyed fleet-wide.")
db.commit()

tokyo1 = models.Site(rental_id=rental1.id, name="Tokyo HQ")
osaka1 = models.Site(rental_id=rental1.id, name="Osaka Branch")
main2 = models.Site(rental_id=rental2.id, name="Main")
main3 = models.Site(rental_id=rental3.id, name="Main")
main4 = models.Site(rental_id=rental4.id, name="Main")
main5 = models.Site(rental_id=rental5.id, name="Main")
tokyo6 = models.Site(rental_id=rental6.id, name="Tokyo HQ")
contractor6 = models.Site(rental_id=rental6.id, name="Contractor")
db.add_all([tokyo1, osaka1, main2, main3, main4, main5, tokyo6, contractor6])
db.commit()

device_models = [
    "Dell Latitude 5420",
    "Lenovo ThinkPad T14",
    "HP EliteBook 840 G8",
    "Panasonic Toughbook CF-33",
    "Microsoft Surface Laptop 5",
]

device_plan = [
    (rental1, tokyo1, "ACTIVE", 3),
    (rental1, osaka1, "ACTIVE", 2),
    (rental2, main2, "ACTIVE", 3),
    (rental3, main3, "ACTIVE", 4),
    (rental4, main4, "LOCKED", 4),
    (rental5, main5, "ERASED", 4),
    (rental6, tokyo6, "ACTIVE", 2),
    (rental6, contractor6, "ACTIVE", 2),
]

recovery_keys_by_rental = {}

def get_recovery_key(rental):
    if rental.id not in recovery_keys_by_rental:
        key = crypto.generate_key()
        recovery_keys_by_rental[rental.id] = key
        print(f"Recovery key for '{rental.label}' (customer downloads this once, the server keeps only the wrapped blob): {crypto.to_base64(key)}")
    return recovery_keys_by_rental[rental.id]

device_count = 0
for rental, site, status, count in device_plan:
    recovery_key = get_recovery_key(rental)
    for i in range(count):
        device_count += 1
        device_key = crypto.generate_key()
        wrapped_blob = crypto.wrap_device_key(recovery_key, device_key)
        device = models.Device(
            rental_id=rental.id,
            site_id=site.id,
            label=f"{rental.label} - Device {i + 1}",
            model=device_models[device_count % len(device_models)],
            status=status,
            wrapped_key_blob=crypto.to_base64(wrapped_blob),
        )
        db.add(device)
db.commit()

print(f"Seeded {db.query(models.Customer).count()} customers")
print(f"Seeded {db.query(models.Rental).count()} rentals")
print(f"Seeded {db.query(models.Site).count()} sites")
print(f"Seeded {db.query(models.Device).count()} devices")
print(f"Seeded {db.query(models.AuditEvent).count()} audit events")

db.close()
