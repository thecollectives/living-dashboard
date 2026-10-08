# Living Dashboard

Fleet monitoring that *lives*: every enrolled host gets a deep scan on install
(CPU, GPU, processes, cron/scheduled tasks, software, users, disks, network,
listening ports, web services, serial, log sources), then every subsequent
scan is diffed — anything **new**, **gone**, or **changed** surfaces in the
What's New feed automatically. A newly detected web service becomes a
dashboard bookmark on that host's page by itself.

## Layout

| Dir | What |
|---|---|
| `agent/` | Watcher agents: `living-agent.py` (Linux/macOS, stdlib-only Python), `living-agent.ps1` (Windows PowerShell). Deep scan hourly, metrics every 5 min, POST to `/living/api/scan_staging`. |
| `installer/` | `templates/` — `install.sh` / `install.ps1` (universal one-liners, `__LIVING_JWT__` placeholder); `build-dist.sh` (spark-only: injects the JWT, publishes to `/install/`); `mint-token.sh` (single-use enrollment tokens); `enroll_ssh.sh` (SSH-push enrollment). `dist/` is git-ignored build output. |
| `server/` | `living-sync/` — the differ engine (systemd timer, 5 min): staging → inventory → events → auto-bookmarks → rollups. `postgrest/` — container notes. |
| `db/` | `schema.sql` (tables + `claim_enrollment_token`), `roles.sql.template` (placeholders substituted on the spark). |
| `web/` | Dashboard SPA (`index.html`, vanilla JS, fleet dark theme) → served at `http://<tailnet-ip>:8092/living/`. |

## Runtime (spark)

| Piece | Where |
|---|---|
| Postgres `livingdb` | `living-postgres` container (`postgres:16-alpine`), `living-net` |
| REST API | `living-postgrest` (`postgrest:v12.0.2` arm64) → `http://<tailnet-ip>:8092/living/api/` via `dash-nginx` |
| Installer files | `http://<tailnet-ip>:8092/install/` (no auth) |
| Differ | `living-sync.timer` (user systemd, 5 min) |
| Secrets | `/home/brrew/srv/living/.env` (600) + `writer.jwt` (600) — never in this repo |

## Enroll a host (all three methods)

```bash
# 1. SSH push (from the spark, operator):
bash /home/brrew/srv/living/repo/installer/enroll_ssh.sh user@newhost [label]

# 2. One-time token one-liner (run ON the host):
TOKEN=$(bash /home/brrew/srv/living/repo/installer/mint-token.sh "label" 24 | sed 's/.*TOKEN=\([0-9a-f]*\).*/\1/')
# Linux/macOS:
curl -fsSL http://100.104.7.48:8092/install/install.sh | sudo bash -s -- --token "$TOKEN" --label myhost
# Windows (elevated PowerShell):
# irm http://100.104.7.48:8092/install/install.ps1 -OutFile $env:TEMP\install.ps1
# & $env:TEMP\install.ps1 -Token "<token>" -Label myhost

# 3. Manual download: fetch the files from http://100.104.7.48:8092/install/
#    and run install.sh / install.ps1 by hand with a minted token.
```

## Push to GitHub

Repo target: `github.com/thecollectives/living-dashboard` (org created 2026-10-08).
`dist/` and any `*.jwt` / `.env` are git-ignored — verify with `git status`
before the first push.
