# CloudPulse Platform

CloudPulse is a web console for running a Windows server estate and its Microsoft 365 / Entra ID tenant from one place. It combines live server metrics from Elasticsearch, capacity history and forecasts, Microsoft Teams alert handling, Jira ticketing, and identity and security posture from Microsoft Graph, with scheduled reports and an assistant that answers questions over all of it.

It is a FastAPI application with a single-page front end, backed by PostgreSQL, and is designed to run as rootless Podman containers managed by systemd (Quadlet).

## Features

| Area | What it does |
|---|---|
| **Dashboard and Capacity** | Fleet CPU, memory and disk from Elasticsearch, top servers, per-server detail with disks and top processes |
| **Teams Alerts** | Polls a Teams monitoring chat, parses alerts, groups repeats per host and type, clears them automatically when metrics recover or the source reports resolved, and drafts Jira tickets |
| **Security Posture, Threats, Devices, Patching** | Microsoft Secure Score, Defender incidents and alerts, risky users, device health, missing updates, vulnerabilities and end-of-support software |
| **Identity** | Directory sync and domain controllers, app secrets, privileged roles, MFA (requirement vs. registration), accounts, sign-ins, audit log, licences and groups |
| **Forecasting** | Per-server linear capacity models in vCPU and GB, rolled up per project, with a risk matrix and narrative summary |
| **Reports** | Branded HTML reports with CSV attachments: capacity, operations, security and identity; run on demand or on a schedule by e-mail |
| **Assistant** | Chat interface with read-only tools over servers, capacity, inventory, Entra ID, Defender and Teams alerts; answers include tables and charts |
| **Admin** | Users, all integration settings, Teams options and the server inventory (CSV import and export) |

## Architecture

```
            browser
               │ HTTPS
          ┌────▼─────┐
          │  nginx   │  deploy/nginx/cloudpulse.conf
          └────┬─────┘
               │ 127.0.0.1:8694
     ┌─────────▼──────────┐         Elasticsearch   (server metrics)
     │  cloudpulse (app)  │ ──────▶ Microsoft Graph (Entra ID, Defender, Intune, Teams)
     │  FastAPI + uvicorn │         Jira, SMTP, OpenAI-compatible LLM
     └─────────┬──────────┘
               │ 5432
     ┌─────────▼──────────┐
     │ cloudpulse-db      │  PostgreSQL 16, schema in db/init
     └────────────────────┘
```

Background work runs inside the app process (APScheduler). The app runs two uvicorn workers, and jobs that must run only once take PostgreSQL advisory locks:

| Job | Schedule |
|---|---|
| Server metric collection from Elasticsearch | hourly at :05 |
| Daily capacity aggregation | daily at 01:00 |
| Teams polling and alert clearing | every 15 s tick; intervals set in Admin Settings |
| Identity and security collection (Microsoft Graph) | every 60 s tick; collects every `ad.refresh_minutes` |
| Scheduled reports | every 60 s tick |

More detail is in [docs/architecture.md](docs/architecture.md).

## Repository layout

```
app/                    FastAPI application
  main.py               app factory, scheduler, static file serving
  routers/              REST endpoints (/api/...)
  services/             integrations and business logic
static/                 single-page front end (app.html, login.html, ds.css, brand/)
scripts/                operational helpers (connectivity check)
db/
  Containerfile         PostgreSQL 16 image that initialises the CloudPulse database
  init/                 00-init.sh, 10-schema.sql, 20-settings.sql
  db.env.example        database container environment
deploy/
  quadlet/              systemd Quadlet units (app, database, network)
  quadlet/shared-postgres/  unit for hosts with an existing PostgreSQL container
  nginx/                reverse proxy example
docs/                   architecture, configuration, Graph permissions, operations
Containerfile           application image
Containerfile.update    code-only rebuild on top of an existing image
.env.example            application environment
```

## Requirements

- Podman 4.4 or later with Quadlet (rootless is fine) and systemd
- Network access from the app container to Elasticsearch, `graph.microsoft.com`, `login.microsoftonline.com`, Jira, your SMTP relay and the LLM endpoint you configure
- An Entra ID app registration for Microsoft Graph (see [docs/graph-permissions.md](docs/graph-permissions.md))
- nginx or another reverse proxy for TLS

## Quick start (Podman Quadlet)

```bash
git clone <repository-url> cloudpulse-platform
cd cloudpulse-platform

# 1. Build the images
podman build -t localhost/cloudpulse:latest .
podman build -t localhost/cloudpulse-db:latest db/

# 2. Create the environment files
mkdir -p ~/.config/cloudpulse
cp .env.example        ~/.config/cloudpulse/cloudpulse.env
cp db/db.env.example   ~/.config/cloudpulse/db.env
chmod 600 ~/.config/cloudpulse/*.env
# Edit both files: set passwords, JWT_SECRET (openssl rand -hex 32) and a matching DATABASE_URL.

# 3. Install the units and start
cp deploy/quadlet/cloudpulse.network deploy/quadlet/cloudpulse-db.container \
   deploy/quadlet/cloudpulse.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start cloudpulse-db.service cloudpulse.service

# 4. Check
curl -s http://127.0.0.1:8694/health
```

On its first start the database container creates the `cloudpulse` role and database, applies the schema and default settings, and creates the web user `admin` with the password from `CLOUDPULSE_ADMIN_PASSWORD`. Sign in, change that password under **Admin Settings → Users**, then fill in the integrations.

For rootless Podman, run `loginctl enable-linger <user>` so the services start at boot.

### Using an existing PostgreSQL server

Create a role and database, apply `db/init/10-schema.sql` and `db/init/20-settings.sql` as that role, point `DATABASE_URL` at it, and skip the database container. `deploy/quadlet/shared-postgres/cloudpulse.container` is a unit for hosts where PostgreSQL and nginx already run in containers sharing one network namespace. See [docs/operations.md](docs/operations.md).

## Configuration

Only `DATABASE_URL` and `JWT_SECRET` come from the environment. Everything else, including Elasticsearch, Microsoft Graph, Jira, SMTP, the LLM endpoint, Teams and thresholds, is stored in the database and edited in **Admin Settings**; changes apply without a restart. The full list is in [docs/configuration.md](docs/configuration.md).

| Integration | Minimum to set |
|---|---|
| Elasticsearch | `es.url`, `es.username`, `es.password`, `es.index_pattern` |
| Microsoft Graph | `entra.tenant_id`, `entra.client_id`, `entra.client_secret` |
| Teams alerts | `teams.chat_id`, `teams.enabled = true` |
| Identity and security | `ad.enabled = true` |
| Jira | `jira.base_url`, `jira.username`, `jira.api_token`, `jira.project_key` |
| Mail | `mail.host`, `mail.port`, `mail.from` (plus credentials if the relay needs them) |
| Assistant and drafts | `llm.base_url`, `llm.model`, `llm.api_key` (any OpenAI-compatible endpoint with tool calling) |

### Agent API

Other automation (n8n, Zabbix webhooks and similar) can query live server data at `/api/v1/agent/...` with the header `X-CloudPulse-Key`, whose value is the `agent.api_key` setting. `agent.allowed_ips` optionally restricts callers.

## Upgrading

```bash
git pull
podman build -t localhost/cloudpulse:latest .
systemctl --user restart cloudpulse.service
```

On hosts without access to OS package mirrors, rebuild only the code on top of the previous image:

```bash
podman build -f Containerfile.update --build-arg BASE=localhost/cloudpulse:<previous> -t localhost/cloudpulse:<new> .
podman tag localhost/cloudpulse:<new> localhost/cloudpulse:latest
systemctl --user restart cloudpulse.service
```

Schema changes are additive: on startup the app creates any missing tables and columns. Back up the database before upgrading (see [docs/operations.md](docs/operations.md)).

## Security notes

- Keep `cloudpulse.env` and `db.env` out of version control (`.gitignore` covers `*.env`) and readable only by the service user.
- Secret settings are stored in the database and are never returned to the browser.
- The Graph app registration only needs read permissions; CloudPulse never writes to the tenant.
- The assistant's tools are read-only.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration reference](docs/configuration.md)
- [Microsoft Graph permissions](docs/graph-permissions.md)
- [Operations: backup, restore, upgrades, troubleshooting](docs/operations.md)
