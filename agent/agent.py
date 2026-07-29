import json
import os
import socket
import time

import requests

import vault

SERVER_URL = "http://127.0.0.1:8000"
IDENTITY_FILE = os.path.join(os.path.dirname(__file__), "identity.json")
CHECKIN_INTERVAL_SECONDS = 5

def load_identity():
    if not os.path.exists(IDENTITY_FILE):
        return None
    with open(IDENTITY_FILE) as f:
        return json.load(f)

def save_identity(identity):
    with open(IDENTITY_FILE, "w") as f:
        json.dump(identity, f)

def register():
    label = socket.gethostname()
    response = requests.post(
        f"{SERVER_URL}/agent/register",
        json={"label": label, "model": "Agent Laptop (Live)"},
    )
    response.raise_for_status()
    identity = response.json()
    save_identity(identity)
    print(f"Registered as device #{identity['device_id']} in rental #{identity['rental_id']}.")
    return identity

def apply_local_status(new_status, current_status, device_id):
    if new_status == current_status:
        return current_status
    print(f"[{time.strftime('%H:%M:%S')}] Status changed: {current_status} -> {new_status}")
    if new_status == "ACTIVE":
        vault.setup_workspace(device_id)
        print("Workspace ready at C:\\Lantern -- files there are encrypted with this device's own vault key.")
    elif new_status == "LOCKED":
        print("Rental locked. This is reversible -- the vault key is untouched.")
    elif new_status == "REVOKED":
        print("This device has been revoked. Workspace access removed.")
    elif new_status == "ERASED":
        vault.destroy_vault_key(device_id, reason="Rental erasure confirmed", dry_run=False)
    return new_status

def checkin(identity, current_status):
    response = requests.post(
        f"{SERVER_URL}/agent/checkin",
        json={
            "device_id": identity["device_id"],
            "agent_token": identity["agent_token"],
            "applied_status": current_status,
        },
        timeout=5,
    )
    if response.status_code == 401:
        print("Server rejected this device's identity. Delete identity.json and restart to re-register.")
        return current_status
    response.raise_for_status()
    data = response.json()
    return apply_local_status(data["device_status"], current_status, identity["device_id"])

def main():
    identity = load_identity() or register()
    current_status = None
    print(f"Agent running, checking in every {CHECKIN_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.")
    while True:
        try:
            current_status = checkin(identity, current_status)
        except requests.exceptions.RequestException as error:
            print(f"Could not reach server ({error}). Staying in last known state and retrying.")
        time.sleep(CHECKIN_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
