import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

import vault

SCOPE = "r999s999"
TEST_DEVICE_ID = "test-erasure-device"
DRY_RUN_DEVICE_ID = "test-dry-run-device"


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Point the vault at a throwaway folder so tests never touch C:\\Lantern
    or the real credential store."""
    folder = tmp_path / "Lantern"
    store = tmp_path / "store"
    secrets_dir = tmp_path / "secrets"
    folder.mkdir()
    store.mkdir()
    secrets_dir.mkdir()
    monkeypatch.setattr(vault, "VAULT_DIR", folder)
    monkeypatch.setattr(vault, "STORE_DIR", store)
    monkeypatch.setattr(vault, "MANIFEST_FILE", store / "manifest.json")
    monkeypatch.setattr(vault, "FALLBACK_DIR", secrets_dir)
    # Force the file fallback rather than the OS keyring, so a test run cannot
    # leave keys behind in the developer's real credential manager.
    monkeypatch.setattr(vault.keyring, "set_password", _raise_keyring_error)
    monkeypatch.setattr(vault.keyring, "get_password", _raise_keyring_error)
    monkeypatch.setattr(vault.keyring, "delete_password", _raise_keyring_error)
    return folder


def _raise_keyring_error(*args, **kwargs):
    raise vault.keyring.errors.KeyringError("disabled in tests")


# ---------------------------------------------------------------------------
# the core promise: destroying the key destroys the data
# ---------------------------------------------------------------------------

def test_encrypt_then_destroy_key_makes_decrypt_fail(sandbox):
    key = vault.create_workspace_key()
    vault.save_workspace_key(SCOPE, key)

    blob = vault.encrypt_file(key, "abc123", "secret.txt", b"top secret rental data")
    name, content = vault.decrypt_file(key, "abc123", blob)
    assert (name, content) == ("secret.txt", b"top secret rental data")

    vault.destroy_workspace_key(SCOPE, reason="erasure confirmed", dry_run=False)

    assert vault.get_workspace_key(SCOPE) is None
    with pytest.raises(Exception):
        vault.decrypt_file(vault.generate_key(), "abc123", blob)


def test_dry_run_does_not_destroy_key(sandbox):
    key = vault.create_workspace_key()
    vault.save_workspace_key(SCOPE, key)

    vault.destroy_workspace_key(SCOPE, reason="dry run check", dry_run=True)

    assert vault.get_workspace_key(SCOPE) == key


def test_erasure_leaves_ciphertext_on_disk(sandbox):
    """Crypto-shredding, not deletion. The unreadable file IS the evidence."""
    key = vault.create_workspace_key()
    vault.save_workspace_key(SCOPE, key)
    (sandbox / "report.txt").write_bytes(b"quarterly numbers")
    _age_files(sandbox)
    vault.ingest_dropped_files(SCOPE)

    vault.destroy_workspace_key(SCOPE, reason="erasure confirmed", dry_run=False)

    survivor = sandbox / "report.txt"
    assert survivor.exists(), "the file should still be there"
    assert survivor.read_bytes() != b"quarterly numbers", "but it must be unreadable"


# ---------------------------------------------------------------------------
# lock is reversible, and visibly so
# ---------------------------------------------------------------------------

def test_lock_replaces_plaintext_with_ciphertext_and_unlock_restores(sandbox):
    key = vault.create_workspace_key()
    vault.save_workspace_key(SCOPE, key)
    (sandbox / "report.txt").write_bytes(b"quarterly numbers")
    _age_files(sandbox)
    vault.ingest_dropped_files(SCOPE)

    vault.seal_shared_folder()

    assert vault.is_locked()
    assert (sandbox / "report.txt").exists(), "the filename must survive a lock"
    assert (sandbox / "report.txt").read_bytes() != b"quarterly numbers"

    vault.unseal_shared_folder(SCOPE)

    assert not vault.is_locked()
    assert (sandbox / "report.txt").read_bytes() == b"quarterly numbers"


def test_locked_folder_does_not_ingest_new_files(sandbox):
    key = vault.create_workspace_key()
    vault.save_workspace_key(SCOPE, key)
    vault.seal_shared_folder()

    (sandbox / "sneaky.txt").write_bytes(b"added while locked")
    _age_files(sandbox)

    assert vault.ingest_dropped_files(SCOPE) == []


# ---------------------------------------------------------------------------
# file_id addressing
# ---------------------------------------------------------------------------

def test_rename_does_not_break_decryption(sandbox):
    """The old build derived the file key from the filename, so renaming a file
    made it permanently unreadable. The key now comes from an immutable id."""
    key = vault.create_workspace_key()
    blob = vault.encrypt_file(key, "deadbeef", "original.txt", b"payload")

    name, content = vault.decrypt_file(key, "deadbeef", blob)

    assert name == "original.txt"
    assert content == b"payload"


def test_filename_is_not_visible_in_the_ciphertext(sandbox):
    key = vault.create_workspace_key()
    blob = vault.encrypt_file(key, "cafe0001", "payroll-2026.xlsx", b"x")

    assert b"payroll" not in blob


def test_envelope_round_trip_preserves_binary_content(sandbox):
    content = bytes(range(256))
    packed = vault.pack_envelope("weird\u00e9.bin", content)

    name, unpacked = vault.unpack_envelope(packed)

    assert name == "weird\u00e9.bin"
    assert unpacked == content


# ---------------------------------------------------------------------------
# key commitment: what makes an erasure certificate checkable
# ---------------------------------------------------------------------------

def test_key_commitment_is_stable_and_hides_the_key(sandbox):
    key = vault.create_workspace_key()

    first = vault.key_commitment(key)
    second = vault.key_commitment(key)

    assert first == second
    assert first != vault.key_commitment(vault.create_workspace_key())
    assert key.hex() not in first


# ---------------------------------------------------------------------------
# peer to peer key handover, which the server relays but cannot open
# ---------------------------------------------------------------------------

def test_workspace_key_travels_sealed_between_two_devices(sandbox):
    workspace_key = vault.create_workspace_key()
    alice_private, alice_public = vault.get_or_create_wrap_keypair("alice")
    bob_private, bob_public = vault.get_or_create_wrap_keypair("bob")

    sealed = vault.wrap_key_for_peer(alice_private, bob_public, workspace_key)
    opened = vault.unwrap_key_from_peer(bob_private, alice_public, sealed)

    assert opened == workspace_key


def test_a_third_device_cannot_open_someone_elses_offer(sandbox):
    workspace_key = vault.create_workspace_key()
    alice_private, alice_public = vault.get_or_create_wrap_keypair("alice")
    _, bob_public = vault.get_or_create_wrap_keypair("bob")
    eve_private, _ = vault.get_or_create_wrap_keypair("eve")

    sealed = vault.wrap_key_for_peer(alice_private, bob_public, workspace_key)

    with pytest.raises(Exception):
        vault.unwrap_key_from_peer(eve_private, alice_public, sealed)


# ---------------------------------------------------------------------------

def _age_files(folder: Path):
    """ingest_dropped_files skips files touched in the last 2 seconds, so a
    half-copied file is never encrypted. Backdate them for the tests."""
    old = 1600000000
    for path in folder.iterdir():
        if path.is_file():
            os.utime(path, (old, old))
