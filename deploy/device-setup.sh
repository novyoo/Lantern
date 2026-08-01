#!/bin/bash
# Device setup for a Linux machine joining a rental.
#
# Windows laptops use the LanternAgentApp folder instead - this is for Linux
# devices (edge servers, instruments) that run the agent as a service.
set -e

APP_DIR="$HOME/Lantern"
VENV_DIR="$HOME/lantern-agent-venv"

echo "== Installing system packages =="
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip curl

echo "== Installing Tailscale =="
# No account needed. Lantern issues this device a pre-authorized key when it is
# assigned to a rental, so nobody ever logs in to Tailscale here.
if ! command -v tailscale >/dev/null 2>&1; then
    curl -fsSL https://tailscale.com/install.sh | sh
fi

echo "== Creating the Python environment =="
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install requests cryptography keyring

echo "== Installing the lantern-agent service =="
sudo cp "$APP_DIR/deploy/lantern-agent.service" /etc/systemd/system/lantern-agent.service
sudo systemctl daemon-reload

echo
echo "Setup finished."
echo "Next: create /etc/lantern-agent.env with"
echo "    LANTERN_SERVER_URL=https://your-domain"
echo "    LANTERN_ENROLLMENT_KEY=...   (issued on the Fleet page)"
echo "then run:"
echo "  sudo systemctl enable --now lantern-agent"
echo "Watch it with: journalctl -u lantern-agent -f"
