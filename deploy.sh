#!/bin/bash
# ============================================================
# PDKS Security Intelligence — Build & Deploy
# Run from your laptop, deploys to amrv1p000005873
# ============================================================

set -e

JUMP_SERVER="amrv1p000005873"
DEPLOY_DIR="/home/ec2-user/pdks-security"
BINARY_NAME="pdks-security"

echo "╔══════════════════════════════════════════╗"
echo "║   PDKS Security Intelligence Deploy      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Step 1 — Build for Linux
echo "→ Building Go binary for Linux/amd64..."
GOOS=linux GOARCH=amd64 go build -o ${BINARY_NAME} .
echo "✓ Built: ${BINARY_NAME} ($(du -sh ${BINARY_NAME} | cut -f1))"
echo ""

# Step 2 — Create deploy directory on jump server
echo "→ Creating deploy directory on ${JUMP_SERVER}..."
ssh ${JUMP_SERVER} "mkdir -p ${DEPLOY_DIR}"
echo "✓ Directory ready"
echo ""

# Step 3 — Copy files
echo "→ Copying files to ${JUMP_SERVER}:${DEPLOY_DIR}..."
scp ${BINARY_NAME} ${JUMP_SERVER}:${DEPLOY_DIR}/
scp dashboard.html ${JUMP_SERVER}:${DEPLOY_DIR}/
scp pdks-security.service ${JUMP_SERVER}:${DEPLOY_DIR}/
echo "✓ Files copied"
echo ""

# Step 4 — Set permissions
echo "→ Setting permissions..."
ssh ${JUMP_SERVER} "chmod +x ${DEPLOY_DIR}/${BINARY_NAME}"
echo "✓ Executable set"
echo ""

# Step 5 — Ask for config
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Configure environment on ${JUMP_SERVER}:"
echo ""
echo "  ssh ${JUMP_SERVER}"
echo "  export SYSDIG_TOKEN=your_token_here"
echo "  export SYSDIG_BASE=https://us2.app.sysdig.com"
echo "  export EMAIL_TO=ssachin.kumar@pfizer.com"
echo "  export SMTP_HOST=smtp.pfizer.com"
echo "  export SMTP_USER=your_email"
echo "  export SMTP_PASS=your_password"
echo ""
echo "Then run:"
echo ""
echo "  cd ${DEPLOY_DIR}"
echo "  nohup ./${BINARY_NAME} > pdks.log 2>&1 &"
echo "  echo \$! > pdks.pid"
echo ""
echo "  # Or as systemd service:"
echo "  sudo cp pdks-security.service /etc/systemd/system/"
echo "  sudo systemctl enable pdks-security"
echo "  sudo systemctl start pdks-security"
echo ""
echo "Dashboard: http://localhost:8080"
echo "API:       http://localhost:8080/api/data"
echo "Digest:    http://localhost:8080/api/digest (send now)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✓ Deploy complete"
