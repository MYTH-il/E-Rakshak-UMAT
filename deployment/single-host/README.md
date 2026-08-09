# Single-host development deployment

UMAT deliberately avoids CAPE's conventional ports. The control-plane API uses `8080`, while
its dedicated PostgreSQL endpoint uses `55432`. CAPE/WinST-DT may continue using `8000` and the
system PostgreSQL cluster on `5432`.

## PostgreSQL with Docker

The UMAT control-plane database is pinned to PostgreSQL 18.4. Its volume is deliberately named
`umat-postgres-18` so Docker cannot attach an older major-version data directory by accident. The
volume mounts `/var/lib/postgresql`, matching the version-specific `PGDATA` layout introduced by
the official PostgreSQL 18 image.

```bash
docker compose -f deployment/single-host/compose.yaml up -d postgres
cp .env.example .env
uv run alembic upgrade head
```

The compose port is loopback-only. Executors must never receive this database DSN.

## PostgreSQL without Docker (Ubuntu)

Create a separate native cluster rather than modifying CAPE's cluster:

```bash
sudo pg_createcluster 18 umat --port 55432 --start
sudo -u postgres psql -p 55432 -d postgres
```

Then create a dedicated development role/database inside the `psql` prompt:

```sql
CREATE ROLE umat LOGIN PASSWORD 'replace-with-a-development-password';
CREATE DATABASE umat OWNER umat;
```

Set the matching password in `UMAT_DATABASE_URL` in `.env`, then run migrations. Production must
use a generated secret, encrypted transport where applicable, and a separately managed database
credential.

Useful native-cluster commands:

```bash
pg_lsclusters
sudo pg_ctlcluster 18 umat start
sudo pg_ctlcluster 18 umat stop
```

## Starting UMAT

After creating the first administrator, start these in separate terminals:

```bash
uv run umat-api
```

```bash
uv run umat-report-worker run
```

```bash
uv run umat-adapter-worker run
```

```bash
uv run umat-scheduler run
```

Open `http://127.0.0.1:8080`. Readiness is available at
`http://127.0.0.1:8080/health/ready`.
