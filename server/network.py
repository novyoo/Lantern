import base64
import os
import shutil
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

HUB_KEY_FILE = os.path.join(os.path.dirname(__file__), "wg_hub_key.txt")
LISTEN_PORT_BASE = 51000
MAX_SITES_PER_RENTAL = 10
COMMAND_TIMEOUT_SECONDS = 5

def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    return _encode_private(private_key), _encode_public(private_key.public_key())

def _encode_private(private_key):
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()

def _encode_public(public_key):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()

def get_or_create_hub_keypair():
    if os.path.exists(HUB_KEY_FILE):
        with open(HUB_KEY_FILE) as f:
            private_b64 = f.read().strip()
    else:
        private_b64, _ = generate_keypair()
        with open(HUB_KEY_FILE, "w") as f:
            f.write(private_b64)
    private_key = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return private_b64, _encode_public(private_key.public_key())

def site_subnet(rental_id, site_index):
    rental_octet = 50 + (rental_id % 200)
    return f"10.{rental_octet}.{site_index % MAX_SITES_PER_RENTAL}"

def hub_ip(rental_id, site_index):
    return f"{site_subnet(rental_id, site_index)}.1"

def assign_device_ip(rental_id, site_index, device_index):
    return f"{site_subnet(rental_id, site_index)}.{device_index + 2}"

def hub_listen_port(rental_id, site_index):
    return LISTEN_PORT_BASE + rental_id * MAX_SITES_PER_RENTAL + (site_index % MAX_SITES_PER_RENTAL)

def interface_name(rental_id, site_index):
    return f"wg-r{rental_id}s{site_index % MAX_SITES_PER_RENTAL}"

def hub_endpoint(rental_id, site_index):
    host = os.environ.get("LANTERN_HUB_HOST", "127.0.0.1")
    return f"{host}:{hub_listen_port(rental_id, site_index)}"

def wg_tools_available():
    return shutil.which("wg") is not None and shutil.which("ip") is not None

def _run(args, **kwargs):
    kwargs.setdefault("timeout", COMMAND_TIMEOUT_SECONDS)
    try:
        return subprocess.run(args, capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="timed out")

def ensure_hub_interface(rental_id, site_index):
    if not wg_tools_available():
        return False
    name = interface_name(rental_id, site_index)
    existing = _run(["ip", "link", "show", name])
    if existing.returncode == 0:
        return True
    private_b64, _ = get_or_create_hub_keypair()
    key_path = f"/tmp/{name}-hub-private.key"
    with open(key_path, "w") as f:
        f.write(private_b64)
    os.chmod(key_path, 0o600)
    _run(["ip", "link", "add", name, "type", "wireguard"], check=False)
    _run(["wg", "set", name, "listen-port", str(hub_listen_port(rental_id, site_index)), "private-key", key_path], check=False)
    _run(["ip", "address", "add", f"{hub_ip(rental_id, site_index)}/24", "dev", name], check=False)
    _run(["ip", "link", "set", name, "up"], check=False)
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    os.remove(key_path)
    return True

def sync_hub_peers(rental_id, site_index, devices):
    if not wg_tools_available():
        return False
    ensure_hub_interface(rental_id, site_index)
    name = interface_name(rental_id, site_index)
    dump = _run(["wg", "show", name, "dump"])
    current_peers = set()
    for line in dump.stdout.splitlines()[1:]:
        parts = line.split("\t")
        if parts:
            current_peers.add(parts[0])
    wanted = {
        device.wg_public_key: device
        for device in devices
        if device.wg_public_key and device.wg_ip and device.status == "ACTIVE"
    }
    for public_key in current_peers - set(wanted.keys()):
        _run(["wg", "set", name, "peer", public_key, "remove"], check=False)
    for public_key, device in wanted.items():
        _run(["wg", "set", name, "peer", public_key, "allowed-ips", f"{device.wg_ip}/32"], check=False)
    return True

def teardown_hub_interface(rental_id, site_index):
    if not wg_tools_available():
        return False
    name = interface_name(rental_id, site_index)
    _run(["ip", "link", "del", name], check=False)
    return True
