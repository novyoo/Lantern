import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

import vault

TEST_DEVICE_ID = "test-erasure-device"
DRY_RUN_DEVICE_ID = "test-dry-run-device"

def test_encrypt_then_destroy_key_makes_decrypt_fail():
    vault.destroy_vault_key(TEST_DEVICE_ID, reason="test setup", dry_run=False)

    key = vault.get_or_create_vault_key(TEST_DEVICE_ID)
    plaintext = b"top secret rental data"
    blob = vault.encrypt_bytes(key, plaintext)
    assert vault.decrypt_bytes(key, blob) == plaintext

    vault.destroy_vault_key(TEST_DEVICE_ID, reason="erasure confirmed", dry_run=False)

    assert vault.get_vault_key(TEST_DEVICE_ID) is None
    with pytest.raises(Exception):
        vault.decrypt_bytes(vault.generate_key(), blob)

def test_dry_run_does_not_destroy_key():
    vault.destroy_vault_key(DRY_RUN_DEVICE_ID, reason="test setup", dry_run=False)

    key = vault.get_or_create_vault_key(DRY_RUN_DEVICE_ID)
    vault.destroy_vault_key(DRY_RUN_DEVICE_ID, reason="dry run check", dry_run=True)
    assert vault.get_vault_key(DRY_RUN_DEVICE_ID) == key

    vault.destroy_vault_key(DRY_RUN_DEVICE_ID, reason="test cleanup", dry_run=False)
