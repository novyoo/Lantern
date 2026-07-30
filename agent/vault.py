import base64
import datetime
import hashlib
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path

import keyring
import keyring.errors
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

VAULT_DIR = Path("C:/Lantern")
SERVICE_NAME = "Lantern"
DEMO_FILENAME = "welcome.txt"
AGENT_VERSION = "1.0"

def _app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent

FALLBACK_DIR = _app_dir() / ".secrets_fallback"
STORE_DIR = _app_dir() / ".lantern_store"
MANIFEST_FILE = STORE_DIR / "manifest.json"

def _set_secret(service, username, value):
    try:
        keyring.set_password(service, username, value)
        return
    except keyring.errors.KeyringError:
        pass
    FALLBACK_DIR.mkdir(exist_ok=True)
    (FALLBACK_DIR / f"{service}__{username}").write_text(value)

def _get_secret(service, username):
    try:
        stored = keyring.get_password(service, username)
        if stored is not None:
            return stored
    except keyring.errors.KeyringError:
        pass
    path = FALLBACK_DIR / f"{service}__{username}"
    return path.read_text() if path.exists() else None

def _delete_secret(service, username):
    try:
        keyring.delete_password(service, username)
    except keyring.errors.KeyringError:
        pass
    path = FALLBACK_DIR / f"{service}__{username}"
    if path.exists():
        path.unlink()

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
    stored = _get_secret(SERVICE_NAME, keyring_username(device_id))
    if stored is None:
        return None
    return bytes.fromhex(stored)

def get_or_create_vault_key(device_id):
    key = get_vault_key(device_id)
    if key is not None:
        return key
    key = generate_key()
    _set_secret(SERVICE_NAME, keyring_username(device_id), key.hex())
    return key

def destroy_vault_key(device_id, reason, dry_run=False):
    if dry_run:
        print(f"[DRY RUN] Would destroy vault key for device {device_id} now, because: {reason}. Nothing was touched.")
        return
    _delete_secret(SERVICE_NAME, keyring_username(device_id))
    print(f"Vault key for device {device_id} destroyed, because: {reason}. Its files are now permanently unreadable.")

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
    stored = _get_secret(SERVICE_NAME, signing_key_username(device_id))
    if stored is not None:
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(stored))
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _set_secret(SERVICE_NAME, signing_key_username(device_id), raw.hex())
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

def wg_key_username(device_id):
    return f"device-{device_id}-wg-key"

def get_or_create_wg_keypair(device_id):
    stored = _get_secret(SERVICE_NAME, wg_key_username(device_id))
    if stored is None:
        private_key = x25519.X25519PrivateKey.generate()
        raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        stored = base64.b64encode(raw).decode()
        _set_secret(SERVICE_NAME, wg_key_username(device_id), stored)
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(stored))
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return stored, base64.b64encode(public_raw).decode()

def wg_public_key_base64(device_id):
    _, public_b64 = get_or_create_wg_keypair(device_id)
    return public_b64

def destroy_wg_keypair(device_id):
    _delete_secret(SERVICE_NAME, wg_key_username(device_id))

def wrap_key_for_peer(my_wg_private_b64, peer_wg_public_b64, key_bytes):
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(my_wg_private_b64))
    peer_public = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(peer_wg_public_b64))
    shared_secret = private_key.exchange(peer_public)
    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"lantern-workspace-key").derive(shared_secret)
    return base64.b64encode(encrypt_bytes(wrap_key, key_bytes)).decode()

def unwrap_key_from_peer(my_wg_private_b64, peer_wg_public_b64, blob_b64):
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(my_wg_private_b64))
    peer_public = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(peer_wg_public_b64))
    shared_secret = private_key.exchange(peer_public)
    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"lantern-workspace-key").derive(shared_secret)
    return decrypt_bytes(wrap_key, base64.b64decode(blob_b64))

def workspace_scope(rental_id, site_id):
    return f"r{rental_id}s{site_id}"

def workspace_key_username(scope):
    return f"workspace-{scope}"

def get_workspace_key(scope):
    if scope is None:
        return None
    stored = _get_secret(SERVICE_NAME, workspace_key_username(scope))
    return bytes.fromhex(stored) if stored else None

def save_workspace_key(scope, key_bytes):
    _set_secret(SERVICE_NAME, workspace_key_username(scope), key_bytes.hex())

def create_workspace_key():
    return generate_key()

def destroy_workspace_key(scope, reason, dry_run=False):
    if scope is None:
        return
    if dry_run:
        print(f"[DRY RUN] Would destroy the workspace key for {scope} now, because: {reason}. Nothing was touched.")
        return
    _delete_secret(SERVICE_NAME, workspace_key_username(scope))
    wipe_shared_folder()
    print(f"Workspace key for {scope} destroyed, because: {reason}. The shared folder is now permanently unreadable on this device.")

def wipe_shared_folder():
    manifest = _load_manifest()
    for filename in manifest:
        plaintext_path = VAULT_DIR / filename
        if plaintext_path.exists():
            plaintext_path.unlink()
    if STORE_DIR.exists():
        for path in STORE_DIR.glob("*.enc"):
            path.unlink()
    if MANIFEST_FILE.exists():
        MANIFEST_FILE.unlink()

def simulated_autopilot_id():
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"lantern-autopilot-{socket.gethostname()}"))

def clear_bios_password():
    print("Return step: BIOS/UEFI supervisor password removed (simulated - a real agent would call the vendor's management tool here).")
    return True

def ensure_shared_folder():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    STORE_DIR.mkdir(parents=True, exist_ok=True)

def running_inside_shared_folder():
    return _app_dir().resolve() == VAULT_DIR.resolve()

def _hash(data):
    return hashlib.sha256(data).hexdigest()

def _load_manifest():
    if MANIFEST_FILE.exists():
        return json.loads(MANIFEST_FILE.read_text())
    return {}

def _save_manifest(manifest):
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(manifest))

def list_local_shared_files():
    if not STORE_DIR.exists():
        return []
    return sorted(p.stem for p in STORE_DIR.glob("*.enc"))

def put_shared_file(scope, filename, plaintext_bytes):
    key = get_workspace_key(scope)
    if key is None:
        return False
    ensure_shared_folder()
    blob = encrypt_file_bytes(key, filename, plaintext_bytes)
    (STORE_DIR / f"{filename}.enc").write_bytes(blob)
    manifest = _load_manifest()
    manifest[filename] = {"hash": _hash(plaintext_bytes), "materialized": True}
    _save_manifest(manifest)
    (VAULT_DIR / filename).write_bytes(plaintext_bytes)
    return True

def read_shared_file(scope, filename):
    key = get_workspace_key(scope)
    if key is None:
        return None
    path = STORE_DIR / f"{filename}.enc"
    if not path.exists():
        return None
    return decrypt_file_bytes(key, filename, path.read_bytes())

def save_shared_file_ciphertext(filename, blob):
    ensure_shared_folder()
    (STORE_DIR / f"{filename}.enc").write_bytes(blob)

def read_shared_file_ciphertext(filename):
    path = STORE_DIR / f"{filename}.enc"
    return path.read_bytes() if path.exists() else None

RESERVED_FILENAMES = {
    "lantern-agent.exe", "identity.json", "lantern0.conf",
    "config.txt", "join lantern.bat", "agent.log",
}

def list_dropped_plaintext_files():
    if not VAULT_DIR.exists():
        return []
    dropped = []
    for path in VAULT_DIR.iterdir():
        if not path.is_file() or path.suffix == ".enc" or path.name.startswith("."):
            continue
        if path.name.lower() in RESERVED_FILENAMES:
            continue
        try:
            if time.time() - path.stat().st_mtime < 2:
                continue
        except OSError:
            continue
        dropped.append(path)
    return dropped

def ingest_dropped_files(scope):
    key = get_workspace_key(scope)
    if key is None:
        return []
    manifest = _load_manifest()
    ingested = []
    for path in list_dropped_plaintext_files():
        try:
            plaintext = path.read_bytes()
        except OSError:
            continue
        digest = _hash(plaintext)
        if manifest.get(path.name, {}).get("hash") == digest:
            continue
        ensure_shared_folder()
        blob = encrypt_file_bytes(key, path.name, plaintext)
        (STORE_DIR / f"{path.name}.enc").write_bytes(blob)
        manifest[path.name] = {"hash": digest, "materialized": True}
        ingested.append(path.name)
    if ingested:
        _save_manifest(manifest)
    return ingested

def materialize_synced_files(scope):
    key = get_workspace_key(scope)
    if key is None:
        return []
    manifest = _load_manifest()
    materialized = []
    for enc_path in STORE_DIR.glob("*.enc"):
        filename = enc_path.stem
        if manifest.get(filename, {}).get("materialized"):
            continue
        try:
            plaintext = decrypt_file_bytes(key, filename, enc_path.read_bytes())
        except Exception:
            continue
        ensure_shared_folder()
        (VAULT_DIR / filename).write_bytes(plaintext)
        manifest[filename] = {"hash": _hash(plaintext), "materialized": True}
        materialized.append(filename)
    if materialized:
        _save_manifest(manifest)
    return materialized

def current_scope():
    identity_path = _app_dir() / "identity.json"
    if not identity_path.exists():
        return None
    identity = json.loads(identity_path.read_text())
    if identity.get("workspace_scope"):
        return identity["workspace_scope"]
    if identity.get("site_id"):
        return workspace_scope(identity["rental_id"], identity["site_id"])
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vault.py read <device_id>")
        print("       python vault.py dry-run-erase <device_id> <reason>")
        print("       python vault.py put <filename> <local_path>")
        print("       python vault.py read-shared <filename>")
        print("       python vault.py list-shared")
        print("       python vault.py scope")
        sys.exit(1)

    command = sys.argv[1]

    if command == "read":
        content = read_workspace_file(sys.argv[2])
        if content is None:
            print("Cannot decrypt - vault key has been destroyed. This device's data is permanently unreadable.")
        else:
            print(content.decode())
    elif command == "dry-run-erase":
        reason = sys.argv[3] if len(sys.argv) > 3 else "manual dry run"
        destroy_vault_key(sys.argv[2], reason, dry_run=True)
    elif command == "put":
        filename, local_path = sys.argv[2], sys.argv[3]
        with open(local_path, "rb") as f:
            data = f.read()
        if put_shared_file(current_scope(), filename, data):
            print(f"{filename} encrypted with this site's workspace key and saved to {VAULT_DIR}.")
        else:
            print("No workspace key on this device yet - join the rental first (run agent.py).")
    elif command == "read-shared":
        content = read_shared_file(current_scope(), sys.argv[2])
        if content is None:
            print("Cannot decrypt - no workspace key, or the file has not synced here yet.")
        else:
            print(content.decode(errors="replace"))
    elif command == "list-shared":
        for name in list_local_shared_files():
            print(name)
    elif command == "scope":
        scope = current_scope()
        print(scope or "This device has not joined a rental site yet.")
    else:
        print(f"Unknown command: {command}")
