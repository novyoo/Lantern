import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(ROOT, "distribute", "LanternAgentApp")
ZIP_PATH = os.path.join(ROOT, "distribute.zip")

subprocess.run([sys.executable, "-m", "PyInstaller", "lantern-agent.spec", "--noconfirm"], cwd=ROOT, check=True)

os.makedirs(APP_DIR, exist_ok=True)
shutil.copy(os.path.join(ROOT, "dist", "lantern-agent.exe"), os.path.join(APP_DIR, "lantern-agent.exe"))

if os.path.exists(ZIP_PATH):
    os.remove(ZIP_PATH)
with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zip_file:
    for name in os.listdir(APP_DIR):
        zip_file.write(os.path.join(APP_DIR, name), arcname=os.path.join("LanternAgentApp", name))

print("Built lantern-agent.exe and refreshed distribute/LanternAgentApp and distribute.zip.")
print("config.txt, the README and the batch file were left untouched - edit config.txt by hand for a new join code.")
