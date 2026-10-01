#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-/opt/trintech-guardian}"
SERVICE_NAME="trintech-guardian"
echo "[*] Uninstalling TrinTech-Guardian..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop ${SERVICE_NAME} 2>/dev/null || true
  systemctl disable ${SERVICE_NAME} 2>/dev/null || true
  rm -f /etc/systemd/system/${SERVICE_NAME}.service
  systemctl daemon-reload 2>/dev/null || true
fi
rm -f /usr/local/bin/guardian
rm -rf "$PREFIX"
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /etc/trintech-guardian
  echo "[+] Config purged."
else
  echo "[*] Config left at /etc/trintech-guardian (use --purge to remove)"
fi
echo "[+] Removed."
