#!/usr/bin/env bash
# TrinTech-Guardian installer
set -euo pipefail

PREFIX="${PREFIX:-/opt/trintech-guardian}"
SERVICE_NAME="trintech-guardian"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "[*] Installing TrinTech-Guardian to $PREFIX"
mkdir -p "$PREFIX/incident_reports" /etc/trintech-guardian

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -a "$SCRIPT_DIR/guardian" "$PREFIX/"
cp -a "$SCRIPT_DIR/README.md" "$PREFIX/" 2>/dev/null || true
cp -a "$SCRIPT_DIR/docs" "$PREFIX/" 2>/dev/null || true

if [[ ! -f /etc/trintech-guardian/config.json ]]; then
  cp "$PREFIX/guardian/config.json" /etc/trintech-guardian/config.json
  python3 - <<'PY'
import json
p = "/etc/trintech-guardian/config.json"
with open(p) as f:
    cfg = json.load(f)
cfg["dry_run"] = True
cfg["version"] = "1.3.0"
with open(p, "w") as f:
    json.dump(cfg, f, indent=2)
print("[+] Wrote /etc/trintech-guardian/config.json (dry-run=true)")
PY
fi

cat > /usr/local/bin/guardian <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$PREFIX"
exec python3 -m guardian --config /etc/trintech-guardian/config.json "\$@"
EOF
chmod +x /usr/local/bin/guardian

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=TrinTech-Guardian Active Defense Grid
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PREFIX
Environment=PYTHONPATH=$PREFIX
ExecStart=/usr/bin/python3 -m guardian --config /etc/trintech-guardian/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  echo "[+] systemd unit: ${SERVICE_NAME}.service"
  echo "    Enable: sudo systemctl enable --now ${SERVICE_NAME}"
fi

echo ""
echo "[+] Installed. Run: guardian --status"
echo "    Config: /etc/trintech-guardian/config.json"
echo "    Uninstall: sudo bash $SCRIPT_DIR/uninstall.sh"
echo "IMPORTANT: Default is DRY-RUN. Enable live only after signed ROE."
