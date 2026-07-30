import datetime
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from database import SessionLocal
import models

CHECK_INTERVAL_SECONDS = 10

log = logging.getLogger("lantern")


async def check_expired_rentals():
    import main

    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        expired_rentals = (
            db.query(models.Rental)
            .filter(models.Rental.status == "ACTIVE", models.Rental.end_date <= now)
            .all()
        )
        for rental in expired_rentals:
            log.info(
                "rental %s term ended at %sZ, locking automatically",
                rental.id,
                rental.end_date,
            )
            main.apply_lock(db, rental, actor="system", confirmed=True)
            await main.broadcast_rental_update(rental)
    except Exception:
        log.exception("expiry check failed")
    finally:
        db.close()


def start_scheduler():
    scheduler = AsyncIOScheduler()
    scheduler.add_job(check_expired_rentals, "interval", seconds=CHECK_INTERVAL_SECONDS)
    scheduler.start()
    return scheduler
