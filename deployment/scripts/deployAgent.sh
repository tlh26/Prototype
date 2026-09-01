#!/usr/bin/env bash

set -euo pipefail


if [[ $# -ne 5 ]]; then
    echo "Usage:"
    echo
    echo "  $0 <project> <instance> <agent_id> <central_url> <api_key>"
    echo
    exit 1
fi


PROJECT="$1"
INSTANCE="$2"
AGENT_ID="$3"
CENTRAL_URL="$4"
API_KEY="$5"


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"


ARCHIVE="/tmp/evidence-agent.tar.gz"
ENV_FILE="/tmp/evidence-agent.env"


echo "=========================================="
echo " Evidence Agent Deployment"
echo "=========================================="
echo
echo "Project:       $PROJECT"
echo "Instance:      $INSTANCE"
echo "Agent ID:      $AGENT_ID"
echo "Central URL:   $CENTRAL_URL"
echo


echo "[1/7] Packaging agent"

tar \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='tests' \
    -czf "$ARCHIVE" \
    -C "$PROJECT_ROOT" \
    agent \
    common \
    requirements.txt


echo "[2/7] Copying agent archive"

incus file push \
    "$ARCHIVE" \
    "$INSTANCE/tmp/evidence-agent.tar.gz" \
    --project "$PROJECT"


echo "[3/7] Copying service"

incus file push \
    "$PROJECT_ROOT/deployment/agent/evidence-agent.service" \
    "$INSTANCE/tmp/evidence-agent.service" \
    --project "$PROJECT"


echo "[4/7] Copying installer"

incus file push \
    "$PROJECT_ROOT/deployment/scripts/install_agent.sh" \
    "$INSTANCE/tmp/install-agent.sh" \
    --project "$PROJECT"


echo "[5/7] Creating configuration"

cat > "$ENV_FILE" <<EOF
EVIDENCE_TENANT_ID=$PROJECT
EVIDENCE_INSTANCE_NAME=$INSTANCE
EVIDENCE_AGENT_ID=$AGENT_ID

EVIDENCE_CENTRAL_URL=$CENTRAL_URL
EVIDENCE_API_KEY=$API_KEY

EVIDENCE_STATE_DIR=/var/lib/evidence-agent/state
EVIDENCE_SPOOL_DIR=/var/lib/evidence-agent/spool

EVIDENCE_COLLECTION_INTERVAL=10
EVIDENCE_LOG_LEVEL=INFO
EOF


incus file push \
    "$ENV_FILE" \
    "$INSTANCE/tmp/evidence-agent.env" \
    --project "$PROJECT"


echo "[6/7] Installing"

incus exec "$INSTANCE" \
    --project "$PROJECT" -- \
    bash -c '
        mkdir -p /etc/evidence-agent

        cp \
            /tmp/evidence-agent.env \
            /etc/evidence-agent/agent.env

        chmod 600 \
            /etc/evidence-agent/agent.env

        bash /tmp/install-agent.sh
    '


echo "[7/7] Verifying"

incus exec "$INSTANCE" \
    --project "$PROJECT" -- \
    systemctl --no-pager status \
    evidence-agent


echo
echo "=========================================="
echo " Deployment complete"
echo "=========================================="