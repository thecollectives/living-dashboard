#!/usr/bin/env bash
# living-agent universal installer — Linux and macOS.
# Served from http://100.104.7.48:8092/install/install.sh (self-hosted, tailnet-only).
# This is a TEMPLATE: __LIVING_JWT__ is injected by build-dist.sh on the spark.
# The repo never carries the real JWT.
#
# Usage:
#   curl -fsSL http://100.104.7.48:8092/install/install.sh \
#     | sudo bash -s -- --token <enrollment-token> [--label myhost]
#
set -euo pipefail

API="http://100.104.7.48:8092/living/api"
INSTALL_BASE="http://100.104.7.48:8092/install"
TOKEN=""
LABEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="${2:?}"; shift 2;;
    --label) LABEL="${2:?}"; shift 2;;
    --api)   API="${2:?}";   shift 2;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done
[ -z "$TOKEN" ] && { echo "living-install: missing --token" >&2; exit 1; }
[ "$(id -u)" -ne 0 ] && { echo "living-install: run as root (sudo)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "living-install: python3 required" >&2; exit 1; }
command -v curl >/dev/null || { echo "living-install: curl required" >&2; exit 1; }

OS="$(uname -s)"
[ -z "$LABEL" ] && LABEL="$(hostname -s 2>/dev/null || hostname)"
CONF_DIR="/etc/living-agent"
[ "$OS" = "Darwin" ] && CONF_DIR="/usr/local/etc/living-agent"
# Re-enroll reuse: keep the existing host_id so the dashboard sees the same
# host instead of a duplicate. Missing/corrupt config falls back to a new uuid.
HOST_ID=""
if [ -f "$CONF_DIR/config.json" ]; then
  HOST_ID="$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("host_id") or "")
except Exception:
    print("")' "$CONF_DIR/config.json" 2>/dev/null)"
  [ -n "$HOST_ID" ] && echo "living-install: reusing existing host_id=$HOST_ID"
fi
[ -z "$HOST_ID" ] && HOST_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

echo "living-install: OS=$OS label=$LABEL host_id=$HOST_ID"

# --- fetch agent ---
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$INSTALL_BASE/living-agent.py" -o "$TMP/living-agent.py"
python3 -m py_compile "$TMP/living-agent.py" || { echo "living-install: agent download corrupt" >&2; exit 1; }

# --- config (0600: carries the writer JWT + one-time token) ---
mkdir -p "$CONF_DIR"
cat > "$CONF_DIR/config.json" <<EOF
{
  "api": "$API",
  "host_id": "$HOST_ID",
  "label": "$LABEL",
  "jwt": "__LIVING_JWT__",
  "install_token": "$TOKEN"
}
EOF
chmod 600 "$CONF_DIR/config.json"
install -m 0755 "$TMP/living-agent.py" /usr/local/bin/living-agent.py

# --- persistent service ---
if [ "$OS" = "Linux" ]; then
  cat > /etc/systemd/system/living-agent.service <<EOF
[Unit]
Description=Living Dashboard watcher agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/living-agent.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now living-agent.service
  echo "living-install: systemd service enabled and started"
elif [ "$OS" = "Darwin" ]; then
  cat > /Library/LaunchDaemons/us.brrew.living-agent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>us.brrew.living-agent</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>/usr/local/bin/living-agent.py</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/living-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/living-agent.log</string>
</dict>
</plist>
EOF
  launchctl load /Library/LaunchDaemons/us.brrew.living-agent.plist 2>/dev/null \
    || launchctl bootstrap system /Library/LaunchDaemons/us.brrew.living-agent.plist
  echo "living-install: LaunchDaemon loaded"
else
  echo "living-install: unsupported OS: $OS" >&2; exit 1
fi

# --- verify check-in (agent claims token on first run, creating the host row) ---
echo "living-install: waiting for first check-in..."
for i in $(seq 1 18); do
  if curl -fsSL "$API/hosts?host_id=eq.$HOST_ID&select=host_id" 2>/dev/null \
       | grep -q "$HOST_ID"; then
    echo "living-install: OK — host '$LABEL' checked in as $HOST_ID"
    exit 0
  fi
  sleep 10
done
echo "living-install: WARNING — installed but no check-in seen after 3 min." >&2
echo "living-install: check service logs and the enrollment token." >&2
exit 0
