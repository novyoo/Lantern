import base64
import datetime
import json
import os
import sys
from pathlib import Path

import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

VAULT_DIR = Path("C:/Lantern")
SERVICE_NAME = "Lantern"
DEMO_FILENAME = "welcome.txt"
AGENT_VERSION = "1.0"

def generate_key():
    return os.urandom(32)

def encrypt_bytes(key, plaintext):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt_bytes(key, blob):
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)

def derive_file_key(vault_key, filename):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=filename.encode())
    return hkdf.derive(vault_key)

def encrypt_file_bytes(vault_key, filename, plaintext):
    file_key = derive_file_key(vault_key, filename)
    return encrypt_bytes(file_key, plaintext)

def decrypt_file_bytes(vault_key, filename, blob):
    file_key = derive_file_key(vault_key, filename)
    return decrypt_bytes(file_key, blob)

def keyring_username(device_id):
    return f"device-{device_id}"

def get_vault_key(device_id):
    stored = keyring.get_password(SERVICE_NAME, keyring_username(device_id))
    if stored is None:
        return None
    return bytes.fromhex(stored)

def get_or_create_vault_key(device_id):
    key = get_vault_key(device_id)
    if key is not None:
        return key
    key = generate_key()
    keyring.set_password(SERVICE_NAME, keyring_username(device_id), key.hex())
    return key

def destroy_vault_key(device_id, reason, dry_run=False):
    if dry_run:
        print(f"[DRY RUN] Would destroy vault key for device {device_id} now, because: {reason}. Nothing was touched.")
        return
    try:
        keyring.delete_password(SERVICE_NAME, keyring_username(device_id))
        print(f"Vault key for device {device_id} destroyed, because: {reason}. Its files are now permanently unreadable.")
    except keyring.errors.PasswordDeleteError:
        pass

def setup_workspace(device_id):
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    vault_key = get_or_create_vault_key(device_id)
    demo_path = VAULT_DIR / f"{DEMO_FILENAME}.enc"
    if not demo_path.exists():
        plaintext = f"Welcome to Lantern. This file belongs to device {device_id}.".encode()
        blob = encrypt_file_bytes(vault_key, DEMO_FILENAME, plaintext)
        demo_path.write_bytes(blob)
    return demo_path

def read_workspace_file(device_id, filename=DEMO_FILENAME):
    vault_key = get_vault_key(device_id)
    if vault_key is None:
        return None
    blob = (VAULT_DIR / f"{filename}.enc").read_bytes()
    return decrypt_file_bytes(vault_key, filename, blob)

def signing_key_username(device_id):
    return f"device-{device_id}-signing-key"

def get_or_create_signing_key(device_id):
    stored = keyring.get_password(SERVICE_NAME, signing_key_username(device_id))
    if stored is not None:
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(stored))
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    keyring.set_password(SERVICE_NAME, signing_key_username(device_id), raw.hex())
    return private_key

def signing_public_key_base64(device_id):
    private_key = get_or_create_signing_key(device_id)
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()

def build_and_sign_certificate(device_id, rental_id, device_label, reason):
    private_key = get_or_create_signing_key(device_id)
    payload = {
        "device_id": device_id,
        "rental_id": rental_id,
        "device_label": device_label,
        "agent_version": AGENT_VERSION,
        "erased_at": datetime.datetime.utcnow().isoformat() + "Z",
        "reason": reason,
    }
    payload_json = json.dumps(payload, sort_keys=True)
    signature = private_key.sign(payload_json.encode())
    return payload_json, base64.b64encode(signature).decode()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python vault.py read <device_id>")
        print("       python vault.py dry-run-erase <device_id> <reason>")
        sys.exit(1)

    command = sys.argv[1]
    device_id = sys.argv[2]

    if command == "read":
        content = read_workspace_file(device_id)
        if content is None:
            print("Cannot decrypt - vault key has been destroyed. This device's data is permanently unreadable.")
        else:
            print(content.decode())
    elif command == "dry-run-erase":
        reason = sys.argv[3] if len(sys.argv) > 3 else "manual dry run"
        destroy_vault_key(device_id, reason, dry_run=True)
    else:
        print(f"Unknown command: {command}")
