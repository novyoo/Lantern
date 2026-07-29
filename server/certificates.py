import base64
import io
import json
from urllib.parse import urlencode

import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def generate_signing_key():
    return ed25519.Ed25519PrivateKey.generate()

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
    base = str(request.base_url).rstrip("/")
    data = base64.urlsafe_b64encode(payload_json.encode()).decode()
    query = urlencode({"device_id": device_id, "data": data, "sig": signature_b64})
    return f"{base}/verify?{query}"

def qr_png_bytes(url):
    image = qrcode.make(url)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
