import json
import os
import shutil
import socket
import sys
import time

import requests

import tunnel
import vault

def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)

SERVER_URL = os.environ.get("LANTERN_SERVER_URL", "http://127.0.0.1:8000")
IDENTITY_FILE = os.path.join(app_dir(), "identity.json")
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
    join_code = os.environ.get("LANTERN_JOIN_CODE")
    site = os.environ.get("LANTERN_SITE")
    body = {"label": label, "model": "Agent Laptop (Live)"}
    if join_code:
        body["join_code"] = join_code
    if site:
        body["site"] = site
    response = requests.post(f"{SERVER_URL}/agent/register", json=body)
    response.raise_for_status()
    identity = response.json()
    identity["workspace_scope"] = vault.workspace_scope(identity["rental_id"], identity["site_id"])
    save_identity(identity)
    print(f"Registered as device #{identity['device_id']} in rental #{identity['rental_id']}, site #{identity['site_id']}.")
    return identity

def destroy_all_local_keys(identity, reason):
    vault.destroy_vault_key(identity["device_id"], reason=reason, dry_run=False)
    vault.destroy_wg_keypair(identity["device_id"])
    vault.destroy_workspace_key(identity.get("workspace_scope"), reason=reason, dry_run=False)

def apply_local_status(new_status, current_status, identity, joined_as):
    if new_status == current_status:
        return current_status, None, joined_as, False
    print(f"[{time.strftime('%H:%M:%S')}] Status changed: {current_status} -> {new_status}")
    certificate = None
    bios_cleared = False
    if new_status == "ACTIVE":
        vault.ensure_shared_folder()
        print("Shared folder ready at C:\\Lantern - files there are encrypted with this site's workspace key.")
    elif new_status == "LOCKED":
        if joined_as:
            tunnel.bring_down()
            joined_as = None
        print("Rental locked. This is reversible - your keys are untouched, only the network connection drops.")
    elif new_status == "REVOKED":
        if joined_as:
            tunnel.bring_down()
            joined_as = None
        destroy_all_local_keys(identity, reason="Device revoked")
        print("This device has been revoked. Its local keys are destroyed - the shared folder is unreadable here now.")
    elif new_status == "ERASED":
        if joined_as:
            tunnel.bring_down()
            joined_as = None
        destroy_all_local_keys(identity, reason="Rental erasure confirmed")
        bios_cleared = vault.clear_bios_password()
        certificate = vault.build_and_sign_certificate(
            identity["device_id"], identity["rental_id"], socket.gethostname(),
            reason="Rental erasure confirmed",
        )
        print("Erasure certificate signed with this device's own key - sending it to the server next check-in.")
    elif new_status == "LEFT":
        if joined_as:
            tunnel.bring_down()
            joined_as = None
    return new_status, certificate, joined_as, bios_cleared

def update_scope(identity, network_info):
    if network_info is None or not network_info.get("site_id"):
        return
    scope = vault.workspace_scope(identity["rental_id"], network_info["site_id"])
    if identity.get("workspace_scope") != scope:
        identity["workspace_scope"] = scope
        identity["site_id"] = network_info["site_id"]
        save_identity(identity)
        print(f"This device now belongs to site '{network_info['site_name']}' - it uses that site's shared folder key.")

def maybe_rotate_network_key(identity, network_info):
    if network_info is None:
        return
    server_epoch = network_info.get("key_epoch", 1)
    local_epoch = identity.get("key_epoch")
    if local_epoch is None:
        identity["key_epoch"] = server_epoch
        save_identity(identity)
        return
    if server_epoch <= local_epoch:
        return
    vault.destroy_wg_keypair(identity["device_id"])
    vault.get_or_create_wg_keypair(identity["device_id"])
    identity["key_epoch"] = server_epoch
    save_identity(identity)
    print(f"Rental extended - generated a fresh network key for key epoch {server_epoch}. The old key is gone.")

def maybe_join_network(identity, network_info, joined_as):
    if network_info is None:
        return joined_as
    target = (network_info["wg_ip"], network_info["key_epoch"])
    if joined_as == target:
        return joined_as
    if joined_as is not None:
        tunnel.bring_down()
    private_b64, _ = vault.get_or_create_wg_keypair(identity["device_id"])
    tunnel.write_config(
        private_key_b64=private_b64,
        own_ip=network_info["wg_ip"],
        hub_public_key_b64=network_info["hub_public_key"],
        hub_endpoint=network_info["hub_endpoint"],
        allowed_ips=network_info["allowed_ips"],
    )
    if tunnel.bring_up():
        print(f"Joined site '{network_info['site_name']}' at {network_info['wg_ip']} via hub {network_info['hub_endpoint']}.")
    return target

def maybe_bootstrap_workspace_key(identity, network_info):
    if network_info is None or not network_info["needs_workspace_key"]:
        return
    scope = identity.get("workspace_scope")
    offer = network_info.get("pending_key_offer")
    if offer:
        private_b64, _ = vault.get_or_create_wg_keypair(identity["device_id"])
        key = vault.unwrap_key_from_peer(private_b64, offer["from_wg_public_key"], offer["blob"])
        vault.save_workspace_key(scope, key)
        print("Received this site's workspace key securely from another device - shared folder unlocked.")
        return
    if network_info.get("originate_workspace_key"):
        key = vault.create_workspace_key()
        vault.save_workspace_key(scope, key)
        print("No other device in this site holds its workspace key yet - generated a new one.")

def collect_key_offers(identity, network_info):
    if network_info is None:
        return None
    key_requests = network_info.get("key_requests") or []
    if not key_requests:
        return None
    key = vault.get_workspace_key(identity.get("workspace_scope"))
    if key is None:
        return None
    private_b64, _ = vault.get_or_create_wg_keypair(identity["device_id"])
    offers = []
    for request in key_requests:
        blob = vault.wrap_key_for_peer(private_b64, request["wg_public_key"], key)
        offers.append({"for_device_id": request["device_id"], "blob": blob})
    return offers

def sync_shared_files(identity):
    if vault.get_workspace_key(identity.get("workspace_scope")) is None:
        return
    rental_id = identity["rental_id"]
    params = {"device_id": identity["device_id"], "agent_token": identity["agent_token"]}
    try:
        response = requests.get(f"{SERVER_URL}/rentals/{rental_id}/sync", params=params, timeout=5)
        response.raise_for_status()
        remote_files = {entry["filename"] for entry in response.json()}
    except requests.exceptions.RequestException:
        return
    local_files = set(vault.list_local_shared_files())
    for filename in remote_files - local_files:
        download = requests.get(f"{SERVER_URL}/rentals/{rental_id}/sync/{filename}", params=params, timeout=10)
        if download.status_code == 200:
            vault.save_shared_file_ciphertext(filename, download.content)
            print(f"Synced new shared file from another device: {filename}")
    for filename in local_files - remote_files:
        blob = vault.read_shared_file_ciphertext(filename)
        if blob:
            requests.post(f"{SERVER_URL}/rentals/{rental_id}/sync/{filename}", params=params, data=blob, timeout=10)
            print(f"Uploaded shared file for other devices to sync: {filename}")

def full_uninstall(identity):
    destroy_all_local_keys(identity, reason="Left the rental - uninstalling")
    if vault.VAULT_DIR.exists():
        shutil.rmtree(vault.VAULT_DIR, ignore_errors=True)
    if os.path.exists(tunnel.CONFIG_PATH):
        os.remove(tunnel.CONFIG_PATH)
    if os.path.exists(IDENTITY_FILE):
        os.remove(IDENTITY_FILE)
    print("Fully uninstalled - no keys, no shared folder, no identity left on this machine.")

def cli_leave():
    identity = load_identity()
    if identity is None:
        print("No identity.json found - nothing to leave.")
        return
    try:
        requests.post(f"{SERVER_URL}/devices/{identity['device_id']}/leave", timeout=5)
    except requests.exceptions.RequestException:
        print("Could not reach the server - leaving locally anyway.")
    tunnel.bring_down()
    full_uninstall(identity)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "leave":
        cli_leave()
        return

    identity = load_identity()
    while identity is None:
        try:
            identity = register()
        except requests.exceptions.RequestException as error:
            print(f"Could not reach server to register ({error}). Retrying in {CHECKIN_INTERVAL_SECONDS}s.")
            time.sleep(CHECKIN_INTERVAL_SECONDS)
    current_status = None
    certificate = None
    joined_as = None
    network_info = None
    bios_cleared = False
    print(f"Agent running, checking in every {CHECKIN_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.")
    while True:
        try:
            key_offers = collect_key_offers(identity, network_info)
            body = {
                "device_id": identity["device_id"],
                "agent_token": identity["agent_token"],
                "applied_status": current_status,
                "public_key": vault.signing_public_key_base64(identity["device_id"]),
                "wg_public_key": vault.wg_public_key_base64(identity["device_id"]),
                "wg_key_epoch": identity.get("key_epoch", 1),
                "has_workspace_key": vault.get_workspace_key(identity.get("workspace_scope")) is not None,
                "autopilot_id": vault.simulated_autopilot_id(),
                "bios_password_cleared": bios_cleared,
            }
            if certificate:
                body["certificate_payload"], body["certificate_signature"] = certificate
            if key_offers:
                body["key_offers"] = key_offers
            response = requests.post(f"{SERVER_URL}/agent/checkin", json=body, timeout=5)
            if response.status_code == 401:
                print("Server rejected this device's identity. Delete identity.json and restart to re-register.")
                time.sleep(CHECKIN_INTERVAL_SECONDS)
                continue
            response.raise_for_status()
            data = response.json()
            network_info = data.get("network")
            update_scope(identity, network_info)
            maybe_rotate_network_key(identity, network_info)
            current_status, new_certificate, joined_as, newly_cleared = apply_local_status(
                data["device_status"], current_status, identity, joined_as
            )
            certificate = certificate or new_certificate
            bios_cleared = bios_cleared or newly_cleared
            if current_status == "ACTIVE":
                joined_as = maybe_join_network(identity, network_info, joined_as)
                maybe_bootstrap_workspace_key(identity, network_info)
                sync_shared_files(identity)
            if current_status == "LEFT":
                full_uninstall(identity)
                print("Leave complete. This agent will now exit.")
                return
        except requests.exceptions.RequestException as error:
            print(f"Could not reach server ({error}). Staying in last known state and retrying.")
        time.sleep(CHECKIN_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
