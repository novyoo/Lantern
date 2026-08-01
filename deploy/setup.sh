#!/bin/bash
# Server setup for the Lantern coordination server (Ubuntu).
#
# No WireGuard, no IP forwarding, no CAP_NET_ADMIN - Tailscale handles the
# network now, so this box is an ordinary web server again.
set -e

APP_DIR="$HOME/Lantern"
VENV_DIR="$HOME/lantern-venv"
UBUNTU_VERSION=$(lsb_release -rs)

echo "== Installing system packages =="
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip curl gnupg \
    unixodbc \
    libpango-1.0-0 libpangoft2-1.0-0 \
    debian-keyring debian-archive-keyring apt-transport-https

echo "== Installing the Microsoft ODBC driver for SQL Server =="
curl -sSL -O "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18

echo "== Installing Caddy for automatic HTTPS =="
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
sudo apt-get update
sudo apt-get install -y caddy

echo "== Creating the Python environment =="
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "== Installing the lantern service =="
sudo cp "$APP_DIR/deploy/lantern.service" /etc/systemd/system/lantern.service
sudo systemctl daemon-reload

echo
echo "Setup finished. Three things left:"
echo
echo "1. Put your domain in $APP_DIR/deploy/Caddyfile, then:"
echo "     sudo cp $APP_DIR/deploy/Caddyfile /etc/caddy/Caddyfile"
echo "     sudo systemctl reload caddy"
echo
echo "2. Create /etc/lantern.env with at least:"
echo "     DATABASE_URL=..."
echo "     TAILSCALE_API_KEY=tskey-api-..."
echo "     TAILSCALE_TAILNET=-"
echo "     PUBLIC_URL_BASE=https://your-domain"
echo "     LANTERN_HTTPS=1"
echo
echo "3. Migrate and start:"
echo "     cd $APP_DIR/server && $VENV_DIR/bin/alembic upgrade head"
echo "     sudo systemctl enable --now lantern"
echo
echo "Then close port 8000 in your cloud firewall - only 80 and 443 stay open."
