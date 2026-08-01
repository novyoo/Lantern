"""Local key storage, file encryption and the visible shared folder.

Three ideas hold this file together.

1. One key ladder. A site's workspace key is the root; every file gets its own
   key derived from it. Destroy the root and every file in the site dies at once.

2. Files are addressed by a random file_id, never by name. The real filename
   travels inside the encrypted envelope, so the server sees a list of opaque
   UUIDs. Renaming a file locally cannot break decryption, because the name was
   never part of the key derivation.

3. Locking is reversible, erasure is not. Lock swaps the readable copy for its
   own ciphertext - same filename, so opening it shows a wall of garbage - while
   the key stays put. Erasure destroys the key and leaves that ciphertext behind
   permanently, which is the proof rather than the loss.
"""

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

SERVICE_NAME = "Lantern"
AGENT_VERSION = "2.0"


def _preferred_vault_dir():
    """Where the visible shared folder should live.

    Decided but not created - importing this module must not leave folders on
    someone's machine, not least because `lantern-agent.exe leave` imports it
    purely to delete things.
    """
    override = os.environ.get("LANTERN_FOLDER")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path("C:/Lantern")
    return Path.home() / "Lantern"


def _fallback_vault_dir():
    if sys.platform == "win32":
        return Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Lantern"
    return Path.home() / "Lantern"


VAULT_DIR = _preferred_vault_dir()


def _app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


FALLBACK_DIR = _app_dir() / ".secrets_fallback"
STORE_DIR = _app_dir() / ".lantern_store"
MANIFEST_FILE = STORE_DIR / "manifest.json"

RESERVED_FILENAMES = {
    "lantern-agent.exe", "identity.json", "config.txt",
    "join lantern.bat", "agent.log", "manifest.json",
}

# ---------------------------------------------------------------------------
# secret storage
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------

def generate_key():
    return os.urandom(32)

def encrypt_bytes(key, plaintext):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt_bytes(key, blob):
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)

def derive_file_key(workspace_key, file_id):
    """Per-file key from the site root. Keyed on the immutable file_id, so a
    rename never costs anyone their data."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=file_id.encode())
    return hkdf.derive(workspace_key)

def key_commitment(key_bytes):
    """A one-way fingerprint of a workspace key.

    Published when the key is born and quoted in the erasure certificate, so a
    stranger can check the key that was destroyed is the key that guarded the
    data. Being a hash, it reveals nothing that helps decrypt anything.
    """
    return hashlib.sha256(b"lantern-key-commitment-v1" + key_bytes).hexdigest()

def _hash(data):
    return hashlib.sha256(data).hexdigest()

# ---------------------------------------------------------------------------
# file envelope: the name travels inside the ciphertext
# ---------------------------------------------------------------------------

def pack_envelope(filename, content):
    header = json.dumps({"name": filename}).encode()
    return len(header).to_bytes(4, "big") + header + content

def unpack_envelope(data):
    header_length = int.from_bytes(data[:4], "big")
    header = json.loads(data[4:4 + header_length])
    return header["name"], data[4 + header_length:]

def encrypt_file(workspace_key, file_id, filename, content):
    return encrypt_bytes(derive_file_key(workspace_key, file_id), pack_envelope(filename, content))

def decrypt_file(workspace_key, file_id, blob):
    return unpack_envelope(decrypt_bytes(derive_file_key(workspace_key, file_id), blob))

# ---------------------------------------------------------------------------
# device identity: signing key (certificates) and wrap key (receiving the
# workspace key). Deliberately two different keys for two different jobs.
# ---------------------------------------------------------------------------

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

def wrap_key_username(device_id):
    return f"device-{device_id}-wrap-key"

def get_or_create_wrap_keypair(device_id):
    stored = _get_secret(SERVICE_NAME, wrap_key_username(device_id))
    if stored is None:
        private_key = x25519.X25519PrivateKey.generate()
        raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        stored = base64.b64encode(raw).decode()
        _set_secret(SERVICE_NAME, wrap_key_username(device_id), stored)
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(stored))
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return stored, base64.b64encode(public_raw).decode()

def wrap_public_key_base64(device_id):
    _, public_b64 = get_or_create_wrap_keypair(device_id)
    return public_b64

def destroy_wrap_keypair(device_id):
    _delete_secret(SERVICE_NAME, wrap_key_username(device_id))

def _shared_wrap_key(my_private_b64, peer_public_b64):
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(my_private_b64))
    peer_public = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_b64))
    shared_secret = private_key.exchange(peer_public)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"lantern-workspace-key",
    ).derive(shared_secret)

def wrap_key_for_peer(my_private_b64, peer_public_b64, key_bytes):
    """Seal the workspace key for one specific peer. The server relays this blob
    without ever being able to open it."""
    wrap = _shared_wrap_key(my_private_b64, peer_public_b64)
    return base64.b64encode(encrypt_bytes(wrap, key_bytes)).decode()

def unwrap_key_from_peer(my_private_b64, peer_public_b64, blob_b64):
    wrap = _shared_wrap_key(my_private_b64, peer_public_b64)
    return decrypt_bytes(wrap, base64.b64decode(blob_b64))

# ---------------------------------------------------------------------------
# workspace key
# ---------------------------------------------------------------------------

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
    """Crypto-shredding: the key goes, the ciphertext stays.

    Deleting the files would be weaker AND less convincing. Leaving unreadable
    ciphertext on disk is the evidence - you can point at the file and open it.
    """
    if scope is None:
        return
    if dry_run:
        print(f"[DRY RUN] Would destroy the workspace key for {scope} now, because: {reason}. Nothing was touched.")
        return
    seal_shared_folder()
    _delete_secret(SERVICE_NAME, workspace_key_username(scope))
    print(f"Workspace key for {scope} destroyed, because: {reason}.")
    print(f"The files in {VAULT_DIR} are still there and are now permanently unreadable - open one and look.")

# ---------------------------------------------------------------------------
# manifest: file_id -> {name, hash, materialized}
# ---------------------------------------------------------------------------

def ensure_shared_folder():
    """Create the shared folder, dropping to the user's profile if the drive
    root refuses us - a locked-down laptop should degrade, not crash."""
    global VAULT_DIR
    try:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        fallback = _fallback_vault_dir()
        if fallback == VAULT_DIR:
            raise
        print(f"Could not create {VAULT_DIR} - using {fallback} instead.")
        VAULT_DIR = fallback
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
    STORE_DIR.mkdir(parents=True, exist_ok=True)

def _load_manifest():
    if MANIFEST_FILE.exists():
        try:
            return json.loads(MANIFEST_FILE.read_text())
        except ValueError:
            return {}
    return {}

def _save_manifest(manifest):
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2))

def _entries(manifest):
    return {k: v for k, v in manifest.items() if not k.startswith("__")}

def is_locked():
    return bool(_load_manifest().get("__locked__"))

def list_local_file_ids():
    if not STORE_DIR.exists():
        return []
    return sorted(p.stem for p in STORE_DIR.glob("*.enc"))

def read_ciphertext(file_id):
    path = STORE_DIR / f"{file_id}.enc"
    return path.read_bytes() if path.exists() else None

def save_ciphertext(file_id, blob):
    ensure_shared_folder()
    (STORE_DIR / f"{file_id}.enc").write_bytes(blob)

def running_inside_shared_folder():
    try:
        return _app_dir().resolve() == VAULT_DIR.resolve()
    except OSError:
        return False

def _file_id_for_name(manifest, name):
    for file_id, entry in _entries(manifest).items():
        if entry.get("name") == name:
            return file_id
    return None

def list_dropped_plaintext_files():
    """Files a human put in the shared folder that we have not encrypted yet."""
    if not VAULT_DIR.exists():
        return []
    dropped = []
    for path in VAULT_DIR.iterdir():
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.name.lower() in RESERVED_FILENAMES:
            continue
        try:
            # Skip files still being written - a half-copied file would encrypt
            # to a truncated blob and sync that truncation to everyone.
            if time.time() - path.stat().st_mtime < 2:
                continue
        except OSError:
            continue
        dropped.append(path)
    return dropped

def ingest_dropped_files(scope):
    """Encrypt anything new in the visible folder. Returns the names ingested."""
    key = get_workspace_key(scope)
    if key is None or is_locked():
        return []
    manifest = _load_manifest()
    ingested = []
    for path in list_dropped_plaintext_files():
        try:
            content = path.read_bytes()
        except OSError:
            continue
        digest = _hash(content)
        file_id = _file_id_for_name(manifest, path.name)
        if file_id and manifest[file_id].get("hash") == digest:
            continue
        if file_id is None:
            file_id = uuid.uuid4().hex
        ensure_shared_folder()
        save_ciphertext(file_id, encrypt_file(key, file_id, path.name, content))
        manifest[file_id] = {"name": path.name, "hash": digest, "materialized": True}
        ingested.append(path.name)
    if ingested:
        _save_manifest(manifest)
    return ingested

def materialize_synced_files(scope):
    """Decrypt anything that arrived from another device. Returns names written."""
    key = get_workspace_key(scope)
    if key is None or is_locked():
        return []
    manifest = _load_manifest()
    materialized = []
    for file_id in list_local_file_ids():
        entry = manifest.get(file_id) or {}
        if entry.get("materialized"):
            continue
        blob = read_ciphertext(file_id)
        if blob is None:
            continue
        try:
            name, content = decrypt_file(key, file_id, blob)
        except Exception:
            # Wrong key or a corrupt blob. Leave it alone and try again later.
            continue
        ensure_shared_folder()
        (VAULT_DIR / name).write_bytes(content)
        manifest[file_id] = {"name": name, "hash": _hash(content), "materialized": True}
        materialized.append(name)
    if materialized:
        _save_manifest(manifest)
    return materialized

# ---------------------------------------------------------------------------
# lock / unlock: the reversible half
# ---------------------------------------------------------------------------

def seal_shared_folder():
    """Replace every readable file with its own ciphertext, keeping the name.

    This is what "the files become unreadable garbage" actually means on disk.
    report.pdf stays called report.pdf and stops opening.
    """
    manifest = _load_manifest()
    sealed = []
    for file_id, entry in _entries(manifest).items():
        name = entry.get("name")
        blob = read_ciphertext(file_id)
        if not name or blob is None:
            continue
        try:
            (VAULT_DIR / name).write_bytes(blob)
        except OSError:
            continue
        entry["materialized"] = False
        sealed.append(name)
    manifest["__locked__"] = True
    _save_manifest(manifest)
    return sealed

def unseal_shared_folder(scope):
    """Undo a lock: decrypt everything back into place."""
    key = get_workspace_key(scope)
    if key is None:
        return []
    manifest = _load_manifest()
    manifest["__locked__"] = False
    restored = []
    for file_id, entry in _entries(manifest).items():
        blob = read_ciphertext(file_id)
        if blob is None:
            continue
        try:
            name, content = decrypt_file(key, file_id, blob)
        except Exception:
            continue
        try:
            (VAULT_DIR / name).write_bytes(content)
        except OSError:
            continue
        entry.update({"name": name, "hash": _hash(content), "materialized": True})
        restored.append(name)
    _save_manifest(manifest)
    return restored

def purge_everything():
    """Full uninstall - unlike erasure, this really does remove the files."""
    manifest = _load_manifest()
    for entry in _entries(manifest).values():
        name = entry.get("name")
        if not name:
            continue
        path = VAULT_DIR / name
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
    if STORE_DIR.exists():
        for path in STORE_DIR.glob("*.enc"):
            try:
                path.unlink()
            except OSError:
                pass
    if MANIFEST_FILE.exists():
        MANIFEST_FILE.unlink()

# ---------------------------------------------------------------------------
# erasure certificate
# ---------------------------------------------------------------------------

def build_and_sign_certificate(device_id, rental_id, site_id, device_label,
                               reason, commitment, erasure_nonce):
    """Sign proof that this device destroyed its own key.

    The payload carries two things the device cannot invent: the key commitment
    published when the key was born, and a nonce the server only issues once a
    human confirms erasure. Together they stop a certificate being pre-signed
    for an erasure that never happened.
    """
    private_key = get_or_create_signing_key(device_id)
    payload = {
        "device_id": device_id,
        "rental_id": rental_id,
        "site_id": site_id,
        "device_label": device_label,
        "agent_version": AGENT_VERSION,
        "erased_at": datetime.datetime.utcnow().isoformat() + "Z",
        "reason": reason,
        "key_commitment": commitment,
        "erasure_nonce": erasure_nonce,
    }
    payload_json = json.dumps(payload, sort_keys=True)
    signature = private_key.sign(payload_json.encode())
    return payload_json, base64.b64encode(signature).decode()

def simulated_autopilot_id():
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"lantern-autopilot-{socket.gethostname()}"))

def clear_bios_password():
    print("Return step: BIOS/UEFI supervisor password removed (simulated - a real agent would call the vendor's management tool here).")
    return True

# ---------------------------------------------------------------------------
# command line helpers
# ---------------------------------------------------------------------------

def current_scope():
    identity_path = _app_dir() / "identity.json"
    if not identity_path.exists():
        return None
    identity = json.loads(identity_path.read_text())
    if identity.get("workspace_scope"):
        return identity["workspace_scope"]
    if identity.get("site_id") and identity.get("rental_id"):
        return workspace_scope(identity["rental_id"], identity["site_id"])
    return None

def read_shared_file(scope, filename):
    key = get_workspace_key(scope)
    if key is None:
        return None
    manifest = _load_manifest()
    file_id = _file_id_for_name(manifest, filename)
    if file_id is None:
        return None
    blob = read_ciphertext(file_id)
    if blob is None:
        return None
    _, content = decrypt_file(key, file_id, blob)
    return content

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vault.py list-shared")
        print("       python vault.py read-shared <filename>")
        print("       python vault.py scope")
        print("       python vault.py status")
        sys.exit(1)

    command = sys.argv[1]

    if command == "list-shared":
        for file_id, entry in _entries(_load_manifest()).items():
            state = "readable" if entry.get("materialized") else "locked"
            print(f"{entry.get('name')}  [{file_id[:8]}]  {state}")
    elif command == "read-shared":
        content = read_shared_file(current_scope(), sys.argv[2])
        if content is None:
            print("Cannot decrypt - no workspace key, or that file has not synced here yet.")
        else:
            print(content.decode(errors="replace"))
    elif command == "scope":
        print(current_scope() or "This device has not joined a rental site yet.")
    elif command == "status":
        scope = current_scope()
        print(f"Shared folder: {VAULT_DIR}")
        print(f"Scope:         {scope or 'not joined'}")
        print(f"Workspace key: {'present' if get_workspace_key(scope) else 'absent'}")
        print(f"Locked:        {is_locked()}")
        print(f"Files:         {len(_entries(_load_manifest()))}")
    else:
        print(f"Unknown command: {command}")
