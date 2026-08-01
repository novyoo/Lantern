"""Device-side Tailscale control.

Replaces the old WireGuard tunnel.py. The device no longer writes an interface
config, installs a tunnel service or needs its own subnet - it hands Tailscale a
pre-authorized auth key and Tailscale does NAT traversal, key exchange and
routing for us.

Every function here degrades gracefully. If Tailscale is missing or refuses to
start, we log something a human can act on and return False; the caller carries
on. Encryption, the shared folder, lock and erasure never depend on this file.
"""

import json
import os
import platform
import shutil
import subprocess

COMMAND_TIMEOUT_SECONDS = 45
HOSTNAME_PREFIX = "lantern"


def is_windows():
    return platform.system() == "Windows"


def find_tailscale():
    found = shutil.which("tailscale")
    if found:
        return found
    candidates = [
        r"C:\Program Files\Tailscale\tailscale.exe",
        r"C:\Program Files (x86)\Tailscale\tailscale.exe",
        "/usr/bin/tailscale",
        "/usr/local/bin/tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def available():
    return find_tailscale() is not None


def hostname_for(device_id):
    """Deterministic name so the server can find this node in the tailnet even
    if the agent never reports its node ID back."""
    return f"{HOSTNAME_PREFIX}-{device_id}"


def _run(args, timeout=COMMAND_TIMEOUT_SECONDS):
    binary = find_tailscale()
    if binary is None:
        return None
    try:
        return subprocess.run(
            [binary] + args,
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Tailscale command {' '.join(args)} did not complete: {error}")
        return None


def explain_missing():
    print("=" * 70)
    print("Tailscale is not installed on this machine, so this device cannot join")
    print("the private network. Everything else still works - the shared folder,")
    print("encryption, lock and erasure all keep running.")
    print()
    print("To join the network: install Tailscale from https://tailscale.com/download")
    print("then start this agent again. You do NOT need a Tailscale account or")
    print("login - Lantern supplies the key.")
    print("=" * 70)


def up(auth_key, device_id):
    """Join the tailnet using a key minted by the Lantern server.

    --reset clears any state from a previous rental, which matters when the same
    laptop is re-rented to a different customer: it must not keep the old tags.
    """
    if not available():
        explain_missing()
        return False
    if not auth_key:
        return False
    result = _run([
        "up",
        f"--authkey={auth_key}",
        f"--hostname={hostname_for(device_id)}",
        "--accept-routes=false",
        "--accept-dns=false",
        "--reset",
    ])
    if result is None:
        return False
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        print(f"Could not join the private network: {message}")
        if "access denied" in message.lower() or "permission" in message.lower():
            print("Tailscale needs Administrator rights for the first connection on Windows.")
            print("Right-click the Lantern shortcut and pick 'Run as administrator' once,")
            print("or open the Tailscale app and sign in there. Everything else keeps working.")
        return False
    return True


def down():
    """Leave the network but keep the machine's Tailscale install intact."""
    if not available():
        return False
    result = _run(["logout"])
    return result is not None and result.returncode == 0


def status():
    """Return (node_id, tailscale_ip) or (None, None)."""
    if not available():
        return None, None
    result = _run(["status", "--json"], timeout=20)
    if result is None or result.returncode != 0:
        return None, None
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        return None, None
    self_node = data.get("Self") or {}
    ips = self_node.get("TailscaleIPs") or []
    ipv4 = next((ip for ip in ips if ":" not in ip), None)
    return self_node.get("ID"), ipv4


def is_up():
    node_id, ip = status()
    return bool(node_id and ip)
