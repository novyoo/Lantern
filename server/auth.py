import datetime
import hashlib
import os
import secrets

import requests

import models

ADMIN = "YRL Admin"
MANAGER = "Customer Manager"

SESSION_COOKIE_NAME = "lantern_session"
SESSION_HOURS = 12

PASSWORD_MINIMUM_LENGTH = 12
PBKDF2_ROUNDS = 600000

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_MINUTES = 15

failed_logins = {}

def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2:{PBKDF2_ROUNDS}:{salt.hex()}:{digest.hex()}"

def verify_password(password, stored):
    parts = (stored or "").split(":")
    if len(parts) != 4 or parts[0] != "pbkdf2":
        return False
    rounds = int(parts[1])
    salt = bytes.fromhex(parts[2])
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return secrets.compare_digest(digest.hex(), parts[3])

def times_password_was_breached(password):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = digest[:5]
    rest = digest[5:]
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
        )
        response.raise_for_status()
    except Exception:
        return None
    for line in response.text.splitlines():
        suffix, _, count = line.partition(":")
        if suffix.strip() == rest:
            return int(count)
    return 0

def password_problem(password):
    if len(password) < PASSWORD_MINIMUM_LENGTH:
        return (
            f"Password must be at least {PASSWORD_MINIMUM_LENGTH} characters long. "
            f"That one is {len(password)}."
        )
    breaches = times_password_was_breached(password)
    if breaches is None:
        return None
    if breaches > 0:
        return (
            f"That password has appeared in {breaches:,} known data breaches. "
            "Pick one that has not."
        )
    return None

def attempt_key(ip, email):
    return f"{ip}|{email.lower()}"

def recent_failures(ip, email):
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=LOGIN_WINDOW_MINUTES)
    attempts = [t for t in failed_logins.get(attempt_key(ip, email), []) if t > cutoff]
    failed_logins[attempt_key(ip, email)] = attempts
    return attempts

def login_is_blocked(ip, email):
    return len(recent_failures(ip, email)) >= MAX_LOGIN_ATTEMPTS

def record_failed_login(ip, email):
    recent_failures(ip, email)
    failed_logins.setdefault(attempt_key(ip, email), []).append(datetime.datetime.utcnow())

def clear_failed_logins(ip, email):
    failed_logins.pop(attempt_key(ip, email), None)

def minutes_until_unblocked(ip, email):
    attempts = recent_failures(ip, email)
    if not attempts:
        return 0
    unblocks_at = min(attempts) + datetime.timedelta(minutes=LOGIN_WINDOW_MINUTES)
    seconds = (unblocks_at - datetime.datetime.utcnow()).total_seconds()
    return max(1, round(seconds / 60))

def find_user(db, email):
    return (
        db.query(models.User)
        .filter(models.User.email == (email or "").strip().lower())
        .first()
    )

def create_session(db, user):
    session = models.UserSession(
        token=secrets.token_urlsafe(32),
        user_id=user.id,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=SESSION_HOURS),
    )
    db.add(session)
    db.commit()
    return session.token

def delete_session(db, token):
    if not token:
        return
    session = db.query(models.UserSession).filter(models.UserSession.token == token).first()
    if session:
        db.delete(session)
        db.commit()

def delete_all_sessions_for_user(db, user):
    db.query(models.UserSession).filter(models.UserSession.user_id == user.id).delete()
    db.commit()

def user_for_token(db, token):
    if not token:
        return None
    session = db.query(models.UserSession).filter(models.UserSession.token == token).first()
    if session is None or not secrets.compare_digest(session.token, token):
        return None
    if session.expires_at < datetime.datetime.utcnow():
        db.delete(session)
        db.commit()
        return None
    return db.get(models.User, session.user_id)

def connection_is_secure(request):
    if os.environ.get("LANTERN_HTTPS") == "1":
        return True
    return request.url.scheme == "https"

def set_session_cookie(request, response, token):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=connection_is_secure(request),
        max_age=SESSION_HOURS * 3600,
        path="/",
    )

def clear_session_cookie(response):
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")

def can_see_rental(user, rental):
    if user.role == ADMIN:
        return True
    return user.customer_id is not None and rental.customer_id == user.customer_id
