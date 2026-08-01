"""Tailscale control-plane client.

Replaces the hand-rolled WireGuard hub. Lantern no longer assigns IPs, runs a
hub interface or needs root on the server - it asks Tailscale for a tagged,
pre-authorized auth key and lets the device join by itself.

Isolation between sites is enforced by Tailscale ACLs on tags, not by us. Each
site holds one tag from a fixed pool (tag:lantern-0 ... tag:lantern-19) and the
policy file only lets a tag talk to itself. That is the "members-only clubhouse":
a device in site 3 cannot route to a device in site 4, and neither can reach
anything else on the tailnet.

Everything here degrades gracefully. With no API key configured, every call
becomes a no-op and Lantern keeps working without the network layer - files
still sync, lock and erase still work. The demo must never hard-fail because a
third-party API is down.
"""

import json
import logging
import os

import requests

log = logging.getLogger("lantern.tailnet")

API_BASE = "https://api.tailscale.com/api/v2"
TAG_PREFIX = "tag:lantern"
# Size of the pre-declared tag pool. Every tag in this range must exist in the
# tailnet policy file before an auth key can reference it - Tailscale rejects
# tags that are not declared under tagOwners.
TAG_POOL_SIZE = 20
REQUEST_TIMEOUT_SECONDS = 15
# Tailscale caps auth-key lifetime at 90 days.
MAX_KEY_LIFETIME_SECONDS = 90 * 24 * 3600
MIN_KEY_LIFETIME_SECONDS = 600


def api_key():
    return os.environ.get("TAILSCALE_API_KEY", "").strip()


def tailnet_name():
    # "-" means "the default tailnet for this API key" and is right for almost
    # everyone. An org with several tailnets sets the name explicitly.
    return os.environ.get("TAILSCALE_TAILNET", "-").strip() or "-"


def is_configured():
    return bool(api_key())


def site_tag(tailnet_index):
    return f"{TAG_PREFIX}-{tailnet_index}"


def _headers():
    return {"Authorization": f"Bearer {api_key()}", "Content-Type": "application/json"}


def _request(method, path, **kwargs):
    """Every Tailscale call funnels through here so a network blip can never
    take the dashboard down - callers get None and carry on."""
    if not is_configured():
        return None
    kwargs.setdefault("timeout", REQUEST_TIMEOUT_SECONDS)
    try:
        response = requests.request(method, f"{API_BASE}{path}", headers=_headers(), **kwargs)
    except requests.exceptions.RequestException as error:
        log.warning("tailscale %s %s failed: %s", method, path, error)
        return None
    if response.status_code >= 400:
        log.warning(
            "tailscale %s %s returned %s: %s",
            method, path, response.status_code, response.text[:400],
        )
        return None
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return {}


def create_auth_key(tailnet_index, lifetime_seconds, description):
    """Mint a pre-authorized auth key locked to one site's tag.

    preauthorized=True is what makes the join automatic - without it a human
    would have to approve each device in the Tailscale admin console, which is
    exactly the manual step Lantern exists to remove.
    """
    lifetime = max(MIN_KEY_LIFETIME_SECONDS, min(int(lifetime_seconds), MAX_KEY_LIFETIME_SECONDS))
    body = {
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": True,
                    "ephemeral": False,
                    "preauthorized": True,
                    "tags": [site_tag(tailnet_index)],
                }
            }
        },
        "expirySeconds": lifetime,
        "description": description[:200],
    }
    result = _request("POST", f"/tailnet/{tailnet_name()}/keys", data=json.dumps(body))
    if not result:
        return None
    return result.get("key")


def list_devices():
    result = _request("GET", f"/tailnet/{tailnet_name()}/devices")
    if not result:
        return []
    return result.get("devices", [])


def find_device_by_hostname(hostname):
    for device in list_devices():
        if device.get("hostname") == hostname or device.get("name", "").split(".")[0] == hostname:
            return device
    return None


def delete_device(node_id):
    """Kick a node off the tailnet immediately. This is the revoke button - it
    works even if the laptop is powered off, and it cannot be undone from the
    device side because the node record is gone."""
    if not node_id:
        return False
    return _request("DELETE", f"/device/{node_id}") is not None


def expire_key(key_id):
    if not key_id:
        return False
    return _request("DELETE", f"/tailnet/{tailnet_name()}/keys/{key_id}") is not None


def build_policy_file():
    """Generate the tailnet policy file Lantern needs.

    Served to the admin to paste into the Tailscale console once. Two things
    matter here: tagOwners declares the tag pool (auth keys cannot reference an
    undeclared tag), and the acls list gives each tag exactly one rule - it may
    talk to itself and nothing else.
    """
    tag_owners = {site_tag(i): ["autogroup:admin"] for i in range(TAG_POOL_SIZE)}
    acls = [
        {
            "action": "accept",
            "src": [site_tag(i)],
            "dst": [f"{site_tag(i)}:*"],
        }
        for i in range(TAG_POOL_SIZE)
    ]
    return {
        "tagOwners": tag_owners,
        "acls": acls,
        "ssh": [],
    }


def policy_file_json():
    return json.dumps(build_policy_file(), indent=2)


def status_summary():
    """Small dict for /health and the fleet page."""
    return {
        "configured": is_configured(),
        "tailnet": tailnet_name() if is_configured() else None,
        "tag_pool_size": TAG_POOL_SIZE,
    }
