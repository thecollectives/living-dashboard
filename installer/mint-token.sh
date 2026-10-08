#!/usr/bin/env bash
# mint-token.sh — create a single-use enrollment token. RUNS ON THE SPARK.
# Usage: mint-token.sh [label] [hours-valid]
# Prints the PLAINTEXT token once (it is stored hashed; it cannot be recovered).
set -euo pipefail
LIVING_DIR="/home/brrew/srv/living"
LABEL="${1:-}"
HOURS="${2:-24}"

TOKEN="$(openssl rand -hex 16)"
HASH="$(printf '%s' "$TOKEN" | sha256sum | awk '{print $1}')"
EXP="$(date -u -d "+${HOURS} hours" +%Y-%m-%dT%H:%M:%SZ)"

set -a; . "$LIVING_DIR/.env"; set +a
PGPASSWORD="$POSTGRES_PASSWORD" docker exec -i living-postgres psql \
  -h 127.0.0.1 -U living_admin -d livingdb -v ON_ERROR_STOP=1 \
  -c "INSERT INTO enrollment_tokens (token_hash, label, expires_at)
      VALUES ('$HASH', '$LABEL', '$EXP'::timestamptz)" >/dev/null \
  && echo "TOKEN=$TOKEN  (label='$LABEL', valid ${HOURS}h, single-use)"
