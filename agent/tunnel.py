import os
import platform
import shutil
import subprocess
import sys

INTERFACE_NAME = "lantern0"
COMMAND_TIMEOUT_SECONDS = 20

def _app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)

CONFIG_PATH = os.path.join(_app_dir(), f"{INTERFACE_NAME}.conf")

def is_windows():
    return platform.system() == "Windows"

def find_wireguard_exe():
    found = shutil.which("wireguard.exe")
    if found:
        return found
    default_path = r"C:\Program Files\WireGuard\wireguard.exe"
    if os.path.exists(default_path):
        return default_path
    return None

def wg_available():
    if is_windows():
        return find_wireguard_exe() is not None
    return shutil.which("wg-quick") is not None

def write_config(private_key_b64, own_ip, hub_public_key_b64, hub_endpoint, allowed_ips):
    text = (
        "[Interface]\n"
        f"PrivateKey = {private_key_b64}\n"
        f"Address = {own_ip}/24\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {hub_public_key_b64}\n"
        f"Endpoint = {hub_endpoint}\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )
    with open(CONFIG_PATH, "w") as f:
        f.write(text)
    return CONFIG_PATH

def _windows_tunnel_service_exists():
    result = subprocess.run(
        ["sc", "query", f"WireGuardTunnel${INTERFACE_NAME}"],
        capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS,
    )
    return result.returncode == 0

def bring_up():
    if not wg_available():
        print("WireGuard is not installed on this machine - network join simulated only.")
        return False
    try:
        if is_windows():
            if _windows_tunnel_service_exists():
                subprocess.run(
                    [find_wireguard_exe(), "/uninstalltunnelservice", INTERFACE_NAME],
                    check=False, timeout=COMMAND_TIMEOUT_SECONDS,
                )
            subprocess.run(
                [find_wireguard_exe(), "/installtunnelservice", CONFIG_PATH],
                check=True, timeout=COMMAND_TIMEOUT_SECONDS,
            )
        else:
            subprocess.run(
                ["wg-quick", "up", CONFIG_PATH],
                check=True, timeout=COMMAND_TIMEOUT_SECONDS,
            )
        return True
    except subprocess.TimeoutExpired:
        print("WireGuard did not respond within 20 seconds - it is probably waiting on an Administrator prompt.")
        print("Close any WireGuard permission dialog, then rerun this agent from a terminal opened as Administrator.")
        print("Everything else (encryption, shared folder, erasure, certificates) keeps working without it.")
        return False
    except subprocess.CalledProcessError:
        print("Could not start the tunnel. Installing a WireGuard tunnel service needs Administrator rights -")
        print("close this window, reopen the terminal as Administrator, and run the agent again.")
        print("Everything else (encryption, shared folder, erasure, certificates) keeps working without it.")
        return False
    except OSError as error:
        print(f"Could not run WireGuard ({error}). Network join skipped - everything else keeps working.")
        return False

def bring_down():
    if not wg_available():
        return False
    try:
        if is_windows():
            subprocess.run(
                [find_wireguard_exe(), "/uninstalltunnelservice", INTERFACE_NAME],
                check=False, timeout=COMMAND_TIMEOUT_SECONDS,
            )
        else:
            subprocess.run(
                ["wg-quick", "down", CONFIG_PATH],
                check=False, timeout=COMMAND_TIMEOUT_SECONDS,
            )
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False

def is_up():
    try:
        if is_windows():
            result = subprocess.run(
                ["sc", "query", f"WireGuardTunnel${INTERFACE_NAME}"],
                capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS,
            )
            return "RUNNING" in result.stdout
        result = subprocess.run(
            ["ip", "link", "show", INTERFACE_NAME],
            capture_output=True, timeout=COMMAND_TIMEOUT_SECONDS,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
