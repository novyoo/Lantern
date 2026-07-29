import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from database import SessionLocal
import models

CHECK_INTERVAL_SECONDS = 10


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
            event = main.apply_lock(db, rental, actor="system")
            await main.broadcast_rental_update(rental, event)
    finally:
        db.close()


def start_scheduler():
    scheduler = AsyncIOScheduler()
    scheduler.add_job(check_expired_rentals, "interval", seconds=CHECK_INTERVAL_SECONDS)
    scheduler.start()
    return scheduler
