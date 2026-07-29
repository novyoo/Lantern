import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key():
    return os.urandom(32)

def encrypt(key, plaintext):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt(key, blob):
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)

def wrap_device_key(recovery_key, device_key):
    return encrypt(recovery_key, device_key)

def unwrap_device_key(recovery_key, wrapped_blob):
    return decrypt(recovery_key, wrapped_blob)

def to_base64(data):
    return base64.b64encode(data).decode()

def from_base64(text):
    return base64.b64decode(text)
