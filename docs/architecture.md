# Architecture

## Components

| Component | Technology | Notes |
|---|---|---|
| Web application | FastAPI, uvicorn (2 workers), Python 3.12 | Serves the API under `/api` and the front end from `static/` |
| Front end | Single HTML page with vanilla JavaScript and Chart.js | `static/app.html`; design tokens and components in `static/ds.css`; light, dark and automatic appearance |
| Database | PostgreSQL 16 | All state: settings, users, metric history, alerts, snapshots, reports, chats |
| Scheduler | APScheduler inside the app | Jobs that must not run twice take PostgreSQL advisory locks |

## Code layout

| Path | Responsibility |
|---|---|
| `app/main.py` | Application start-up, schema checks, scheduler jobs, static routes |
| `app/auth.py` | Local users (bcrypt) and JWT sessions; Entra ID single sign-on |
| `app/config.py` | Cached access to the `cloudpulse_settings` table |
| `app/services/es_service.py` | Elasticsearch queries for server metrics, disks and processes |
| `app/services/capacity_forecast.py`, `prediction_service.py` | Capacity history and forecasts |
| `app/services/inventory_service.py` | Server inventory: IP, OS, vCPU, project and environment mapping |
| `app/services/teams_service.py`, `teams_alert_service.py` | Teams chat polling, alert parsing, grouping, clearing and Jira drafts |
| `app/services/graph_service.py` | Microsoft Graph client with paging, batching and throttling retry |
| `app/services/ad_service.py` | Identity collectors (accounts, MFA, roles, secrets, sign-ins, audit, licences, devices, groups) |
| `app/services/security_service.py` | Secure Score, Defender incidents and alerts, risky users, device health, vulnerabilities, Intune |
| `app/services/report_service.py` | Report definitions, HTML rendering, CSV export, scheduled delivery |
| `app/services/assistant_service.py` | Assistant tools and the tool-calling loop |
| `app/services/llm_service.py` | OpenAI-compatible chat completion client |
| `app/services/mail_service.py`, `jira_service.py` | SMTP delivery and Jira Service Management |

## Data model

All tables use the `cloudpulse_` prefix. The full definition is in `db/init/10-schema.sql`.

| Table | Contents |
|---|---|
| `cloudpulse_settings` | Integration settings and thresholds (key, value, category, secret flag) |
| `cloudpulse_users` | Local and Entra ID users |
| `cloudpulse_capacity_hourly`, `cloudpulse_capacity_daily` | Metric history per server |
| `cloudpulse_server_inventory` | Server inventory with project and environment |
| `cloudpulse_alerts`, `cloudpulse_jira_tickets`, `cloudpulse_audit_log` | Threshold alerts, tickets raised, audit trail |
| `cloudpulse_teams_alerts`, `cloudpulse_teams_seen`, `cloudpulse_teams_jobs` | Teams alerts and incident grouping, processed message IDs, job state |
| `cloudpulse_ad_snapshots`, `cloudpulse_ad_kpi_daily` | Latest identity and security collection per section, daily KPI history |
| `cloudpulse_scheduled_reports`, `cloudpulse_report_history` | Report schedules and generated reports |
| `cloudpulse_ai_chats`, `cloudpulse_ai_messages` | Assistant conversations |

Identity and security data are stored as one JSON snapshot per collector section. Findings and health scores are computed when the page is read, so changing a threshold takes effect immediately.

## Background jobs and locking

Each uvicorn worker runs a scheduler. Ticks that touch shared state (Teams polling, alert clearing, identity collection, scheduled reports) take a PostgreSQL advisory lock on a dedicated connection, so only one worker does the work. The last run of each job is recorded in `cloudpulse_teams_jobs`, which makes intervals configurable at runtime.

## Teams alert lifecycle

1. New chat messages are read through Microsoft Graph (`Chat.Read.All`).
2. Structured alerts from Dynatrace, Elastic and similar sources are parsed directly; others are extracted with the LLM.
3. Alerts are grouped into incidents by host and alert type. A repeat increases the occurrence count on the latest event instead of adding a new row.
4. An incident clears when the source posts a resolved message, when CloudPulse metrics for the host fall back under `teams.resolve_threshold`, or after `teams.stale_clear_hours` without a repeat.
