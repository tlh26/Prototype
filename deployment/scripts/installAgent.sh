#!/usr/bin/env bash

set -euo pipefail


APP_DIR="/opt/evidence-agent"
CONFIG_DIR="/etc/evidence-agent"
DATA_DIR="/var/lib/evidence-agent"


echo "[1/8] Creating directories"

mkdir -p "$APP_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR/state"
mkdir -p "$DATA_DIR/spool"


echo "[2/8] Extracting agent"

tar -xzf \
    /tmp/evidence-agent.tar.gz \
    -C "$APP_DIR"


echo "[3/8] Creating virtual environment"

python3 -m venv \
    "$APP_DIR/.venv"


echo "[4/8] Installing dependencies"

"$APP_DIR/.venv/bin/pip" install \
    --upgrade pip

"$APP_DIR/.venv/bin/pip" install \
    -r "$APP_DIR/requirements.txt"


echo "[5/8] Installing systemd service"

install \
    -m 0644 \
    /tmp/evidence-agent.service \
    /etc/systemd/system/evidence-agent.service


echo "[6/8] Validating configuration"

if [[ ! -f "$CONFIG_DIR/agent.env" ]]; then
    echo "ERROR: missing $CONFIG_DIR/agent.env"
    exit 1
fi


echo "[7/8] Reloading systemd"

systemctl daemon-reload


echo "[8/8] Enabling agent"

systemctl enable evidence-agent

systemctl restart evidence-agent


echo
echo "Evidence agent installed."
echo

systemctl --no-pager status \
    evidence-agent