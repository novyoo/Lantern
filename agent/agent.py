"""The Lantern device agent.

Runs on a rented laptop. Talks to the Lantern server every few seconds and does
four things: joins the rental's private network, keeps the shared folder in
sync, locks itself when told, and signs proof when its key is destroyed.

The laptop enrolls ONCE, using a key issued by the fleet owner, and then sits
idle in the pool. Assignment to a rental happens on the server - the person
holding the laptop does nothing at all when a rental starts.
"""

import json
import os
import shutil
import socket
import sys
import time
import traceback

import requests

import tailnet
import vault

def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)

def load_config_file():
    """Read config.txt sitting next to the program into the environment.

    The launcher script also does this, but people double-click the .exe
    directly and then wonder why nothing happens. Reading it here means the
    agent works however it is started. Real environment variables win, so
    systemd units and containers can still override the file.
    """
    path = os.path.join(app_dir(), "config.txt")
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.readlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        # A placeholder left in the template is not a real setting.
        if not value or value.startswith("<"):
            continue
        os.environ.setdefault(name, value)

load_config_file()

SERVER_URL = os.environ.get("LANTERN_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
IDENTITY_FILE = os.path.join(app_dir(), "identity.json")
CHECKIN_INTERVAL_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 20

def describe_request_error(error):
    response = getattr(error, "response", None)
    if response is not None:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = None
        if detail:
            return f"server said: {detail}"
    return str(error)

def load_identity():
    if not os.path.exists(IDENTITY_FILE):
        return None
    try:
        with open(IDENTITY_FILE) as f:
            return json.load(f)
    except ValueError:
        return None

def save_identity(identity):
    with open(IDENTITY_FILE, "w") as f:
        json.dump(identity, f, indent=2)

# ---------------------------------------------------------------------------
# enrollment
# ---------------------------------------------------------------------------

def enroll():
    """Claim a device row using the enrollment key the fleet owner issued.

    Happens once in the life of the laptop. A join code is still accepted as a
    self-service path - it enrolls and assigns in one step.
    """
    enrollment_key = os.environ.get("LANTERN_ENROLLMENT_KEY", "").strip()
    join_code = os.environ.get("LANTERN_JOIN_CODE", "").strip()
    if not enrollment_key and not join_code:
        print("No enrollment key found. Put LANTERN_ENROLLMENT_KEY=... in config.txt")
        print("next to this program - the person who owns the fleet issues it for you.")
        return None
    body = {
        "label": socket.gethostname(),
        "model": "Agent Laptop (Live)",
        "public_key": vault.signing_public_key_base64("pending"),
    }
    if enrollment_key:
        body["enrollment_key"] = enrollment_key
    if join_code:
        body["join_code"] = join_code
    response = requests.post(f"{SERVER_URL}/agent/enroll", json=body, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    identity = response.json()
    save_identity(identity)
    print(f"Enrolled as device #{identity['device_id']} ({identity['label']}).")
    print("This laptop is now in the fleet. It will sit idle until someone assigns it to a rental.")
    return identity

def migrate_identity_keys(identity):
    """The signing key is created before we know our device id, under the name
    'pending'. Once enrolled, move it to the real id so it stays stable."""
    device_id = identity["device_id"]
    pending = vault._get_secret(vault.SERVICE_NAME, vault.signing_key_username("pending"))
    if pending and not vault._get_secret(vault.SERVICE_NAME, vault.signing_key_username(device_id)):
        vault._set_secret(vault.SERVICE_NAME, vault.signing_key_username(device_id), pending)
        vault._delete_secret(vault.SERVICE_NAME, vault.signing_key_username("pending"))

# ---------------------------------------------------------------------------
# status transitions
# ---------------------------------------------------------------------------

def destroy_all_local_keys(identity, reason):
    vault.destroy_workspace_key(identity.get("workspace_scope"), reason=reason, dry_run=False)
    vault.destroy_wrap_keypair(identity["device_id"])

def apply_local_status(new_status, current_status, identity, state):
    """React to a status change from the server. Returns the new status."""
    if new_status == current_status:
        return current_status
    print(f"[{time.strftime('%H:%M:%S')}] Status: {current_status or 'starting'} -> {new_status}")
    scope = identity.get("workspace_scope")

    if new_status == "ACTIVE":
        vault.ensure_shared_folder()
        if vault.is_locked():
            restored = vault.unseal_shared_folder(scope)
            print(f"Unlocked - {len(restored)} file(s) readable again in {vault.VAULT_DIR}.")
        else:
            print(f"Shared folder ready at {vault.VAULT_DIR} - drop a file in and everyone else in this site gets it.")

    elif new_status == "LOCKED":
        sealed = vault.seal_shared_folder()
        state["joined"] = None
        tailnet.down()
        print(f"Rental locked. {len(sealed)} file(s) in {vault.VAULT_DIR} are now unreadable ciphertext.")
        print("Open one and look - same filename, garbage inside. This is reversible: your key is untouched.")

    elif new_status == "REVOKED":
        state["joined"] = None
        tailnet.down()
        destroy_all_local_keys(identity, reason="Device revoked")
        print("This device has been revoked. Its keys are gone and the shared folder is unreadable here.")

    elif new_status == "ERASED":
        state["joined"] = None
        tailnet.down()
        # Capture the commitment BEFORE destroying the key - the certificate has
        # to quote the fingerprint of the key it is about to destroy.
        key = vault.get_workspace_key(scope)
        state["commitment"] = vault.key_commitment(key) if key else None
        destroy_all_local_keys(identity, reason="Rental erasure confirmed")
        state["bios_cleared"] = vault.clear_bios_password()
        state["awaiting_certificate"] = True

    elif new_status == "LEFT":
        state["joined"] = None
        tailnet.down()

    return new_status

def maybe_sign_certificate(identity, state, erasure_nonce):
    """Sign the erasure certificate once the server has issued a nonce."""
    if not state.get("awaiting_certificate") or state.get("certificate"):
        return
    if not erasure_nonce:
        print("Waiting for the erasure nonce from the server before signing the certificate.")
        return
    state["certificate"] = vault.build_and_sign_certificate(
        device_id=identity["device_id"],
        rental_id=identity.get("rental_id"),
        site_id=identity.get("site_id"),
        device_label=socket.gethostname(),
        reason="Rental erasure confirmed",
        commitment=state.get("commitment"),
        erasure_nonce=erasure_nonce,
    )
    state["awaiting_certificate"] = False
    print("Erasure certificate signed with this device's own key - sending it on the next check-in.")

# ---------------------------------------------------------------------------
# assignment, network and workspace key
# ---------------------------------------------------------------------------

def update_assignment(identity, assignment):
    """Track which rental and site this laptop currently belongs to."""
    if assignment is None:
        if identity.get("rental_id") is not None:
            identity["rental_id"] = None
            identity["site_id"] = None
            identity["workspace_scope"] = None
            save_identity(identity)
        return
    scope = vault.workspace_scope(assignment["rental_id"], assignment["site_id"])
    if identity.get("workspace_scope") == scope:
        return
    identity["rental_id"] = assignment["rental_id"]
    identity["site_id"] = assignment["site_id"]
    identity["workspace_scope"] = scope
    identity["key_epoch"] = assignment.get("key_epoch", 1)
    save_identity(identity)
    print(f"Assigned to rental #{assignment['rental_id']}, site '{assignment['site_name']}'.")

def maybe_rotate_on_extend(identity, assignment):
    """A rental extension bumps the key epoch. Old network keys stop working."""
    if assignment is None:
        return
    server_epoch = assignment.get("key_epoch", 1)
    local_epoch = identity.get("key_epoch")
    if local_epoch is None:
        identity["key_epoch"] = server_epoch
        save_identity(identity)
        return
    if server_epoch <= local_epoch:
        return
    identity["key_epoch"] = server_epoch
    save_identity(identity)
    print(f"Rental extended - rejoining the network on key epoch {server_epoch}.")

def maybe_join_network(identity, assignment, network, state):
    """Join the tailnet if we are not already on it for this rental and epoch."""
    if assignment is None or network is None:
        return
    target = (assignment["rental_id"], assignment["site_id"], assignment.get("key_epoch", 1))
    if state.get("joined") == target and tailnet.is_up():
        return
    auth_key = network.get("auth_key")
    if not auth_key:
        return
    if tailnet.up(auth_key, identity["device_id"]):
        state["joined"] = target
        node_id, ip = tailnet.status()
        state["node_id"], state["ip"] = node_id, ip
        print(f"Joined the private network for site '{assignment['site_name']}' as {ip}.")
    else:
        state["joined"] = None

def maybe_bootstrap_workspace_key(identity, workspace):
    """Get the site's workspace key: either a peer hands it over sealed, or we
    are the first device here and create it."""
    if workspace is None or not workspace.get("needs_key"):
        return
    scope = identity.get("workspace_scope")
    offer = workspace.get("pending_key_offer")
    if offer:
        private_b64, _ = vault.get_or_create_wrap_keypair(identity["device_id"])
        try:
            key = vault.unwrap_key_from_peer(private_b64, offer["from_wrap_public_key"], offer["blob"])
        except Exception:
            print("A workspace key offer arrived but could not be opened - waiting for another.")
            return
        vault.save_workspace_key(scope, key)
        print("Received this site's workspace key from another device - shared folder unlocked.")
        return
    if workspace.get("originate_key"):
        key = vault.create_workspace_key()
        vault.save_workspace_key(scope, key)
        print("First device in this site - generated its workspace key.")

def collect_key_offers(identity, workspace):
    """Seal our workspace key for each device that still needs it."""
    if workspace is None:
        return None
    requests_for_key = workspace.get("key_requests") or []
    if not requests_for_key:
        return None
    key = vault.get_workspace_key(identity.get("workspace_scope"))
    if key is None:
        return None
    private_b64, _ = vault.get_or_create_wrap_keypair(identity["device_id"])
    offers = []
    for request in requests_for_key:
        if not request.get("wrap_public_key"):
            continue
        offers.append({
            "for_device_id": request["device_id"],
            "blob": vault.wrap_key_for_peer(private_b64, request["wrap_public_key"], key),
        })
    return offers or None

# ---------------------------------------------------------------------------
# file sync
# ---------------------------------------------------------------------------

def sync_shared_files(identity):
    """Exchange encrypted blobs with the server.

    The server only ever sees a file_id and a blob. It cannot tell you what any
    of these files are called, let alone what is in them.
    """
    scope = identity.get("workspace_scope")
    if vault.get_workspace_key(scope) is None or vault.is_locked():
        return
    rental_id = identity.get("rental_id")
    if rental_id is None:
        return
    params = {"device_id": identity["device_id"]}
    headers = {"X-Agent-Token": identity["agent_token"]}
    try:
        response = requests.get(
            f"{SERVER_URL}/rentals/{rental_id}/sync",
            params=params, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        remote_ids = {entry["file_id"] for entry in response.json()}
    except requests.exceptions.RequestException:
        return
    local_ids = set(vault.list_local_file_ids())
    for file_id in remote_ids - local_ids:
        try:
            download = requests.get(
                f"{SERVER_URL}/rentals/{rental_id}/sync/{file_id}",
                params=params, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.exceptions.RequestException:
            continue
        if download.status_code == 200:
            vault.save_ciphertext(file_id, download.content)
    for file_id in local_ids - remote_ids:
        blob = vault.read_ciphertext(file_id)
        if not blob:
            continue
        try:
            requests.post(
                f"{SERVER_URL}/rentals/{rental_id}/sync/{file_id}",
                params=params, headers=headers, data=blob, timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.exceptions.RequestException:
            continue

# ---------------------------------------------------------------------------
# leave / uninstall
# ---------------------------------------------------------------------------

def full_uninstall(identity):
    destroy_all_local_keys(identity, reason="Left the rental - uninstalling")
    vault.purge_everything()
    tailnet.down()
    if vault.STORE_DIR.exists():
        shutil.rmtree(vault.STORE_DIR, ignore_errors=True)
    if vault.FALLBACK_DIR.exists():
        shutil.rmtree(vault.FALLBACK_DIR, ignore_errors=True)
    if os.path.exists(IDENTITY_FILE):
        os.remove(IDENTITY_FILE)
    print("Fully uninstalled - no keys, no shared files, no identity left on this machine.")

def cli_leave():
    identity = load_identity()
    if identity is None:
        print("No identity.json found - nothing to leave.")
        return
    try:
        requests.post(
            f"{SERVER_URL}/agent/leave",
            json={"device_id": identity["device_id"], "agent_token": identity["agent_token"]},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException:
        print("Could not reach the server - leaving locally anyway.")
    full_uninstall(identity)

# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------

def build_checkin_body(identity, current_status, state, workspace):
    scope = identity.get("workspace_scope")
    key = vault.get_workspace_key(scope)
    node_id, ip = state.get("node_id"), state.get("ip")
    body = {
        "device_id": identity["device_id"],
        "agent_token": identity["agent_token"],
        "applied_status": current_status,
        "public_key": vault.signing_public_key_base64(identity["device_id"]),
        "wrap_public_key": vault.wrap_public_key_base64(identity["device_id"]),
        "key_epoch": identity.get("key_epoch", 1),
        "has_workspace_key": key is not None,
        "key_commitment": vault.key_commitment(key) if key else None,
        "tailscale_node_id": node_id,
        "tailscale_ip": ip,
        "autopilot_id": vault.simulated_autopilot_id(),
        "bios_password_cleared": bool(state.get("bios_cleared")),
    }
    certificate = state.get("certificate")
    if certificate:
        body["certificate_payload"], body["certificate_signature"] = certificate
    offers = collect_key_offers(identity, workspace)
    if offers:
        body["key_offers"] = offers
    return body

def warn_if_running_inside_shared_folder():
    if not vault.running_inside_shared_folder():
        return
    print("=" * 70)
    print(f"WARNING: this program is running from {vault.VAULT_DIR} itself.")
    print("That folder is the SHARED FOLDER - it should hold only files you want")
    print("to share. Move lantern-agent.exe somewhere else, e.g. your Desktop.")
    print("=" * 70)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "leave":
        cli_leave()
        return

    warn_if_running_inside_shared_folder()

    if not tailnet.available():
        tailnet.explain_missing()

    identity = load_identity()
    while identity is None:
        try:
            identity = enroll()
            if identity is None:
                return
        except requests.exceptions.RequestException as error:
            print(f"Could not enroll ({describe_request_error(error)}). Retrying in {CHECKIN_INTERVAL_SECONDS}s.")
            time.sleep(CHECKIN_INTERVAL_SECONDS)
    migrate_identity_keys(identity)

    current_status = None
    workspace = None
    state = {
        "joined": None, "node_id": None, "ip": None,
        "certificate": None, "commitment": None,
        "awaiting_certificate": False, "bios_cleared": False,
    }
    print(f"Agent running, checking in every {CHECKIN_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.")

    while True:
        try:
            body = build_checkin_body(identity, current_status, state, workspace)
            response = requests.post(
                f"{SERVER_URL}/agent/checkin", json=body, timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code == 401:
                print("Server rejected this device's identity. Delete identity.json and restart to re-enroll.")
                time.sleep(CHECKIN_INTERVAL_SECONDS)
                continue
            response.raise_for_status()
            data = response.json()

            assignment = data.get("assignment")
            workspace = data.get("workspace")
            update_assignment(identity, assignment)
            maybe_rotate_on_extend(identity, assignment)

            current_status = apply_local_status(
                data["device_status"], current_status, identity, state
            )
            maybe_sign_certificate(identity, state, data.get("erasure_nonce"))

            if current_status == "ACTIVE":
                maybe_join_network(identity, assignment, data.get("network"), state)
                maybe_bootstrap_workspace_key(identity, workspace)
                for name in vault.ingest_dropped_files(identity.get("workspace_scope")):
                    print(f"Encrypted and shared: {name}")
                sync_shared_files(identity)
                for name in vault.materialize_synced_files(identity.get("workspace_scope")):
                    print(f"Arrived from another device: {name}")

            if current_status == "LEFT":
                full_uninstall(identity)
                print("Leave complete. This agent will now exit.")
                return

        except requests.exceptions.RequestException as error:
            print(f"Could not reach server ({describe_request_error(error)}). Staying in the last known state.")
        except Exception:
            print("Unexpected error this cycle - staying up and retrying instead of exiting.")
            traceback.print_exc()
        time.sleep(CHECKIN_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
