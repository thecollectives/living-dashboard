#!/usr/bin/env bash
# build-dist.sh — build the served installer files from templates.
# Runs ON THE SPARK ONLY (it injects the writer JWT from /home/brrew/srv/living/).
# Output: /home/brrew/srv/dashboards/install/{install.sh,install.ps1,living-agent.py,living-agent.ps1}
# The repo's templates/ keep the __LIVING_JWT__ placeholder; dist/ is git-ignored.
set -euo pipefail

LIVING_DIR="/home/brrew/srv/living"
DIST_DIR="/home/brrew/srv/dashboards/install"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

[ -f "$LIVING_DIR/writer.jwt" ] || { echo "missing $LIVING_DIR/writer.jwt" >&2; exit 1; }
JWT="$(cat "$LIVING_DIR/writer.jwt")"
mkdir -p "$DIST_DIR"

for f in install.sh install.ps1; do
  sed "s|__LIVING_JWT__|$JWT|g" "$REPO_DIR/installer/templates/$f" > "$DIST_DIR/$f"
  chmod 644 "$DIST_DIR/$f"
  grep -q "__LIVING_JWT__" "$DIST_DIR/$f" && { echo "JWT injection failed for $f" >&2; exit 1; }
  echo "built $DIST_DIR/$f"
done

cp "$REPO_DIR/agent/living-agent.py" "$DIST_DIR/living-agent.py"
cp "$REPO_DIR/agent/living-agent.ps1" "$DIST_DIR/living-agent.ps1"
chmod 644 "$DIST_DIR/living-agent."*
echo "copied agents"
echo "dist ready at $DIST_DIR — served as http://100.104.7.48:8092/install/"
