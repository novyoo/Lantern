"""Build the agent .exe and package one folder per person.

Run this, then hand each friend their own zip. Pass their enrollment keys (from
the Fleet page) and you get a ready-to-send folder each, with config.txt already
filled in - so nobody has to paste a key into a text file:

    python build_distribute.py --server https://lantern.example.com \
        --device "Rahul=KEY1" --device "Aisha=KEY2" --device "Sam=KEY3"

With no --device arguments it just refreshes the generic folder and zip.
"""
import argparse
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(ROOT, "distribute", "LanternAgentApp")
OUT_DIR = os.path.join(ROOT, "distribute")
EXE_NAME = "lantern-agent.exe"
SHARED_FILES = ["Join Lantern.bat", "README - READ FIRST.txt"]


def build_exe():
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "lantern-agent.spec", "--noconfirm"],
        cwd=ROOT, check=True,
    )
    built = os.path.join(ROOT, "dist", EXE_NAME)
    if not os.path.exists(built):
        raise SystemExit(f"PyInstaller did not produce {built}")
    os.makedirs(APP_DIR, exist_ok=True)
    shutil.copy(built, os.path.join(APP_DIR, EXE_NAME))
    return built


def write_zip(zip_path, folder_name, config_text):
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(os.path.join(APP_DIR, EXE_NAME), f"{folder_name}/{EXE_NAME}")
        for name in SHARED_FILES:
            archive.write(os.path.join(APP_DIR, name), f"{folder_name}/{name}")
        archive.writestr(f"{folder_name}/config.txt", config_text)
    return zip_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=None,
                        help="Lantern server URL baked into each config.txt")
    parser.add_argument("--device", action="append", default=[],
                        metavar="NAME=ENROLLMENT_KEY",
                        help="repeat once per person; makes one zip each")
    args = parser.parse_args()

    build_exe()
    print(f"Built {EXE_NAME}.")

    if not args.device:
        with open(os.path.join(APP_DIR, "config.txt")) as f:
            config_text = f.read()
        path = write_zip(os.path.join(OUT_DIR, "distribute.zip"),
                         "LanternAgentApp", config_text)
        print(f"Wrote {path} using the existing config.txt.")
        print("For per-person zips with keys already filled in, pass --server and --device.")
        return

    if not args.server:
        raise SystemExit("--server is required when using --device")

    for entry in args.device:
        if "=" not in entry:
            raise SystemExit(f"--device needs NAME=KEY, got: {entry}")
        name, key = entry.split("=", 1)
        safe = "".join(c for c in name.strip() if c.isalnum() or c in "-_") or "device"
        config_text = (
            f"LANTERN_SERVER_URL={args.server.rstrip('/')}\n"
            f"LANTERN_ENROLLMENT_KEY={key.strip()}\n"
        )
        path = write_zip(os.path.join(OUT_DIR, f"Lantern-{safe}.zip"),
                         "LanternAgentApp", config_text)
        print(f"  {name.strip():20} -> {os.path.basename(path)}")

    print()
    print("Send each person their own zip. Their key is already in it - they")
    print("unzip, install Tailscale once, and double-click 'Join Lantern.bat'.")


if __name__ == "__main__":
    main()
