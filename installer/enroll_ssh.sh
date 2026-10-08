#!/usr/bin/env bash
# enroll_ssh.sh — SSH-push enrollment. RUNS ON THE SPARK (operator).
# Usage: enroll_ssh.sh <user@host> [label]
#   1. mints a single-use enrollment token
#   2. detects the remote OS over SSH
#   3. runs the matching one-liner remotely
#   4. verifies the host checks in
#
# Needs: the operator's SSH access to the target (key or agent).
# The token is passed on the remote command line (visible in remote
# process list briefly) — acceptable: single-use, 1h expiry, tailnet-only.
set -euo pipefail
LIVING_DIR="/home/brrew/srv/living"
TARGET="${1:?usage: enroll_ssh.sh <user@host> [label]}"
LABEL="${2:-$TARGET}"
API="http://100.104.7.48:8092/living/api"
INSTALL_BASE="http://100.104.7.48:8092/install"

# 1. mint token (1h, single-use)
TOKEN="$("$LIVING_DIR/mint-token.sh" "ssh-push:$LABEL" 1 | sed 's/.*TOKEN=\([0-9a-f]*\).*/\1/')"
[ -n "$TOKEN" ] || { echo "token mint failed" >&2; exit 1; }
echo "enroll: token minted for '$LABEL'"

# 2. detect OS
OS="$(ssh -o BatchMode=yes -o ConnectTimeout=15 "$TARGET" "uname -s" 2>/dev/null || true)"
if [ -z "$OS" ]; then
  # maybe Windows (OpenSSH -> cmd.exe): uname fails, try ver via powershell
  if ssh -o BatchMode=yes -o ConnectTimeout=15 "$TARGET" \
       "powershell -NoProfile -Command \"\$PSVersionTable.PSVersion.Major\"" \
       2>/dev/null | grep -qE '^[0-9]+$'; then
    OS="Windows"
  fi
fi
[ -z "$OS" ] && { echo "enroll: cannot reach $TARGET over SSH" >&2; exit 1; }
echo "enroll: remote OS detected: $OS"

# 3. run installer
if [ "$OS" = "Linux" ] || [ "$OS" = "Darwin" ]; then
  ssh -o BatchMode=yes "$TARGET" \
    "curl -fsSL $INSTALL_BASE/install.sh | sudo bash -s -- --token '$TOKEN' --label '$LABEL'"
else
  # Windows: download + run elevated. Assumes the SSH user can elevate
  # (UAC prompt may appear on the console for non-elevated sessions).
  ssh -o BatchMode=yes "$TARGET" \
    "powershell -NoProfile -ExecutionPolicy Bypass -Command \"& { \
      Invoke-WebRequest -UseBasicParsing '$INSTALL_BASE/install.ps1' \
        -OutFile \\\$env:TEMP\\living-install.ps1; \
      & \\\$env:TEMP\\living-install.ps1 -Token '$TOKEN' -Label '$LABEL' }\""
fi

# 4. verify check-in
echo "enroll: verifying check-in..."
for i in $(seq 1 12); do
  if curl -fsSL "$API/hosts?label=eq.$LABEL&select=host_id,label,last_seen" 2>/dev/null \
       | grep -q "$LABEL"; then
    echo "enroll: OK — '$LABEL' is enrolled and checking in"
    exit 0
  fi
  sleep 10
done
echo "enroll: WARNING — no check-in seen after 2 min; token was single-use." >&2
exit 1
