# living-postgrest + living-postgres (spark)

Running on the spark as Docker containers on the `living-net` network.

| Container | Image | Port | Purpose |
|---|---|---|---|
| `living-postgres` | `postgres:16-alpine` | `127.0.0.1:5433:5432` | `livingdb` database |
| `living-postgrest` | `postgrest/postgrest:v12.0.2` (arm64) | `127.0.0.1:8096:3000` | REST API for `livingdb` |

Public surface is via the `dash-nginx` container (attached to `living-net`):
- `http://<tailnet-ip>:8092/living/api/` → PostgREST (no basic auth; JWT-gated)
- `http://<tailnet-ip>:8092/install/` → static installer files (no auth)

## Secrets

All secrets live in `/home/brrew/srv/living/.env` (mode 600) on the spark.
They are NEVER in this repo. Contents:

```
POSTGRES_PASSWORD=<living_admin password>
AUTH_PASSWORD=<living_authenticator password>
JWT_SECRET=<PostgREST HS256 secret>
```

The installer-baked writer JWT is at `/home/brrew/srv/living/writer.jwt`
(mode 600), minted by `mint-writer-jwt.py` (role `living_writer`, 10y expiry).

## Recreate

```bash
cd /home/brrew/srv/living && set -a && . ./.env && set +a
docker run -d --name living-postgres --restart unless-stopped \
  --network living-net -v living-pgdata:/var/lib/postgresql/data \
  -p 127.0.0.1:5433:5432 \
  -e POSTGRES_DB=livingdb -e POSTGRES_USER=living_admin \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" postgres:16-alpine
docker run -d --name living-postgrest --restart unless-stopped \
  --network living-net -p 127.0.0.1:8096:3000 \
  -e PGRST_DB_URI="postgres://living_authenticator:$AUTH_PASSWORD@living-postgres:5432/livingdb" \
  -e PGRST_DB_SCHEMAS="public" -e PGRST_DB_ANON_ROLE="living_reader" \
  -e PGRST_JWT_SECRET="$JWT_SECRET" postgrest/postgrest:v12.0.2
docker network connect living-net dash-nginx   # if not already attached
```

Schema: `db/schema.sql`. Roles: `db/roles.sql.template` (substitute
`__AUTH_PASSWORD__` from `.env` at apply time).
