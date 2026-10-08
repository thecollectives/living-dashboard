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
#
# Programmatic use (the enroll service behind the dashboard Add-host flow)
# drives this script via env vars — see the SSH transport options block
# below. The token is never printed; progress goes to stdout as
# "enroll: ..." lines for the caller to stream.
set -euo pipefail
LIVING_DIR="${LIVING_DIR:-/home/brrew/srv/living}"
TARGET="${1:?usage: enroll_ssh.sh <user@host> [label]}"
LABEL="${2:-$TARGET}"
API="${LIVING_API:-http://100.104.7.48:8092/living/api}"
INSTALL_BASE="${LIVING_INSTALL_BASE:-http://100.104.7.48:8092/install}"

# --- SSH transport options (env-overridable for programmatic use, e.g. the
# enroll service behind the dashboard's Add-host flow). Defaults preserve the
# original operator behavior (local keys/agent, BatchMode).
#   LIVING_SSH_PORT      SSH port (default 22)
#   LIVING_SSH_KEYFILE   path to a private key for -i (default: none)
#   LIVING_SSH_ASKPASS   path to an SSH_ASKPASS helper script for password auth
#                        (default: none; when set, BatchMode is forced off)
#   LIVING_SSH_BATCHMODE yes|no, only when no ASKPASS (default yes)
#   LIVING_SSH_STRICT    StrictHostKeyChecking value, e.g. accept-new
#                        (default: ssh default)
#   LIVING_SSH_TIMEOUT   ConnectTimeout seconds (default 15)
LIVING_SSH_PORT="${LIVING_SSH_PORT:-22}"
LIVING_SSH_KEYFILE="${LIVING_SSH_KEYFILE:-}"
LIVING_SSH_ASKPASS="${LIVING_SSH_ASKPASS:-}"
LIVING_SSH_BATCHMODE="${LIVING_SSH_BATCHMODE:-yes}"
LIVING_SSH_STRICT="${LIVING_SSH_STRICT:-}"
LIVING_SSH_TIMEOUT="${LIVING_SSH_TIMEOUT:-15}"

SSH_ARGS=(-o "ConnectTimeout=$LIVING_SSH_TIMEOUT" -o NumberOfPasswordPrompts=1 -p "$LIVING_SSH_PORT")
[ -n "$LIVING_SSH_KEYFILE" ] && SSH_ARGS+=(-i "$LIVING_SSH_KEYFILE")
[ -n "$LIVING_SSH_STRICT" ] && SSH_ARGS+=(-o "StrictHostKeyChecking=$LIVING_SSH_STRICT")
if [ -n "$LIVING_SSH_ASKPASS" ]; then
  export SSH_ASKPASS="$LIVING_SSH_ASKPASS" SSH_ASKPASS_REQUIRE=force
  export DISPLAY="${DISPLAY:-:0}"
  SSH_ARGS+=(-o BatchMode=no)
else
  SSH_ARGS+=(-o "BatchMode=$LIVING_SSH_BATCHMODE")
fi

# 1. mint token (1h, single-use)
# mint-token.sh lives next to this script (installer/), not in LIVING_DIR.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKEN="$("$SCRIPT_DIR/mint-token.sh" "ssh-push:$LABEL" 1 | sed 's/.*TOKEN=\([0-9a-f]*\).*/\1/')"
[ -n "$TOKEN" ] || { echo "token mint failed" >&2; exit 1; }
echo "enroll: token minted for '$LABEL'"

# 2. detect OS
OS="$(ssh "${SSH_ARGS[@]}" "$TARGET" "uname -s" 2>/dev/null || true)"
if [ -z "$OS" ]; then
  # maybe Windows (OpenSSH -> cmd.exe): uname fails, try ver via powershell
  if ssh "${SSH_ARGS[@]}" "$TARGET" \
       "powershell -NoProfile -Command \"\$PSVersionTable.PSVersion.Major\"" \
       2>/dev/null | grep -qE '^[0-9]+$'; then
    OS="Windows"
  fi
fi
[ -z "$OS" ] && { echo "enroll: cannot reach $TARGET over SSH" >&2; exit 1; }
echo "enroll: remote OS detected: $OS"

# 3. run installer
if [ "$OS" = "Linux" ] || [ "$OS" = "Darwin" ]; then
  ssh "${SSH_ARGS[@]}" "$TARGET" \
    "curl -fsSL $INSTALL_BASE/install.sh | sudo bash -s -- --token '$TOKEN' --label '$LABEL'"
else
  # Windows: download + run elevated. Assumes the SSH user can elevate
  # (UAC prompt may appear on the console for non-elevated sessions).
  ssh "${SSH_ARGS[@]}" "$TARGET" \
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
