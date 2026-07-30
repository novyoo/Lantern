#!/bin/bash
set -e

APP_DIR="$HOME/Lantern"
VENV_DIR="$HOME/lantern-venv"
UBUNTU_VERSION=$(lsb_release -rs)

echo "== Installing system packages =="
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip curl gnupg \
    wireguard-tools iproute2 \
    unixodbc \
    libpango-1.0-0 libpangoft2-1.0-0

echo "== Installing the Microsoft ODBC driver for SQL Server =="
curl -sSL -O "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18

echo "== Turning on IP forwarding for the WireGuard hub =="
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-lantern.conf
sudo sysctl --system

echo "== Creating the Python environment =="
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "== Installing the lantern service =="
sudo cp "$APP_DIR/deploy/lantern.service" /etc/systemd/system/lantern.service
sudo systemctl daemon-reload

echo
echo "Setup finished."
echo "Next: create /etc/lantern.env, then run:"
echo "  sudo systemctl enable --now lantern"
