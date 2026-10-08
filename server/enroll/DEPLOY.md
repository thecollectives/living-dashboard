# enroll service — deploy notes

Backend for the dashboard's Add-host flow (`web/index.html` → `#/add`).

## File map (repo → spark)

| repo path | spark path | how |
|---|---|---|
| `server/enroll/enroll-svc.py` | `/home/brrew/srv/living/enroll-svc.py` | copy |
| `server/enroll/living-enroll.service` | `~/.config/systemd/user/living-enroll.service` | copy |
| `installer/enroll_ssh.sh` | `/home/brrew/srv/living/repo/installer/enroll_ssh.sh` | copy (env-drivable SSH opts) |
| `web/index.html` | `/home/brrew/srv/dashboards/living/index.html` | copy |

## nginx (`/home/brrew/srv/dash-nginx/nginx.conf`, inside dash-nginx)

Backup the config first. Add inside the `:8092` server block, next to the
`/living/api/` location:

```nginx
# Living dashboard enrollment service (Add-host flow).
# Inherits the dashboard basic auth — do NOT add auth_basic off here.
location /living/enroll/ {
    proxy_pass http://127.0.0.1:8097/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
}
```

Reload: `docker exec dash-nginx nginx -s reload` (after `nginx -t`).

## Service

```bash
systemctl --user daemon-reload
systemctl --user enable --now living-enroll.service
systemctl --user status living-enroll.service
curl -s http://127.0.0.1:8097/health   # {"ok": true}
```

Runs as the brrew user (needs docker access for mint-token.sh).
Listens on a unix socket at /home/brrew/srv/living/sock/enroll.sock
(LIVING_ENROLL_SOCK) — no TCP surface at all. Rationale: a container's
127.0.0.1 is not the host's loopback, and the host firewall drops
container→host TCP, so no TCP bind is reachable from dash-nginx. This
mirrors the teamchat/litellm-proxy socket pattern.
dash-nginx needs the mount `/home/brrew/srv/living/sock` →
`/run/living-enroll` (added when the container was recreated 2026-10-08;
see the recreate notes below). Reachable solely through the nginx proxy,
which keeps basic auth in front.

## dash-nginx recreate (2026-10-08 — one extra mount)

The original container predates the enroll socket. Recreated with
identical parameters plus the new mount; the old container was kept as
`dash-nginx-bak` until the new one verified (then removed):

```bash
docker rename dash-nginx dash-nginx-bak
docker run -d --name dash-nginx --restart unless-stopped \
  -p 100.104.7.48:8092:80 \
  -v /home/brrew/srv/dashboards:/usr/share/nginx/html:ro \
  -v /home/brrew/srv/dash-nginx/.htpasswd:/etc/nginx/.htpasswd:ro \
  -v /home/brrew/srv/dash-nginx/nginx.conf:/etc/nginx/nginx.conf:ro \
  -v /home/brrew/srv/litellm-proxy:/run/litellm-proxy \
  -v /home/brrew/srv/teamchat:/run/teamchat \
  -v /home/brrew/srv/living/sock:/run/living-enroll \
  nginx:1.27-alpine
docker network connect living-net dash-nginx
docker exec dash-nginx nginx -t
# verify :8092 pages, /living/api/, /living/enroll/health, /install/
# then: docker rm dash-nginx-bak
```

## Test notes (2026-10-08)

- Error path live-tested: POST /jobs for an unreachable host
  (192.0.2.1) → job fails cleanly with "cannot reach" in the log,
  surfaced in the UI.
- Happy path: service machinery (validation, mint, job lifecycle, temp
  credential cleanup) tested with a stub enroll script; the real remote
  install was NOT live-tested (needs sudo on the target).
- `enroll_ssh.sh` env opts are backward compatible — the operator
  `enroll_ssh.sh <user@host> [label]` flow is unchanged.
