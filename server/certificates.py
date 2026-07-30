import base64
import io
import json
import os
from urllib.parse import urlencode

import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

REPORT_KEY_FILE = os.path.join(os.path.dirname(__file__), "report_key.txt")

def generate_signing_key():
    return ed25519.Ed25519PrivateKey.generate()

def get_or_create_report_key():
    if os.path.exists(REPORT_KEY_FILE):
        with open(REPORT_KEY_FILE) as f:
            raw = bytes.fromhex(f.read().strip())
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    private_key = generate_signing_key()
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(REPORT_KEY_FILE, "w") as f:
        f.write(raw.hex())
    return private_key

def report_public_key_base64():
    return public_key_base64(get_or_create_report_key())

def sign_report(payload):
    return sign_certificate(get_or_create_report_key(), payload)

def build_report_verify_url(request, payload_json, signature_b64):
    base = os.environ.get("PUBLIC_URL_BASE") or str(request.base_url).rstrip("/")
    base = base.rstrip("/")
    data = base64.urlsafe_b64encode(payload_json.encode()).decode()
    query = urlencode({"data": data, "sig": signature_b64})
    return f"{base}/verify-report?{query}"

def public_key_base64(private_key):
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()

def sign_certificate(private_key, payload):
    payload_json = json.dumps(payload, sort_keys=True)
    signature = private_key.sign(payload_json.encode())
    return payload_json, base64.b64encode(signature).decode()

def verify_signature(public_key_b64, payload_json, signature_b64):
    if not public_key_b64 or not payload_json or not signature_b64:
        return False
    try:
        raw_key = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        public_key.verify(base64.b64decode(signature_b64), payload_json.encode())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def decode_payload(data):
    return base64.urlsafe_b64decode(data.encode()).decode()

def build_verify_url(request, device_id, payload_json, signature_b64):
    base = os.environ.get("PUBLIC_URL_BASE") or str(request.base_url).rstrip("/")
    base = base.rstrip("/")
    data = base64.urlsafe_b64encode(payload_json.encode()).decode()
    query = urlencode({"device_id": device_id, "data": data, "sig": signature_b64})
    return f"{base}/verify?{query}"

def qr_png_bytes(url):
    image = qrcode.make(url)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
