# Configuration

CloudPulse reads two kinds of configuration:

1. **Environment variables** for the container: the database connection and the token signing key.
2. **Settings** stored in the `cloudpulse_settings` table and edited in **Admin Settings**. Changes apply without a restart.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | yes | Async SQLAlchemy URL, e.g. `postgresql+asyncpg://cloudpulse:<password>@cloudpulse-db:5432/cloudpulse` |
| `JWT_SECRET` | yes | Key that signs session tokens. Generate with `openssl rand -hex 32`. Changing it signs every user out. |
| `TZ` | no | Time zone used in logs and reports, e.g. `Asia/Dubai` |

The database image (`db/Containerfile`) reads `POSTGRES_USER`, `POSTGRES_PASSWORD`, `CLOUDPULSE_DB`, `CLOUDPULSE_DB_USER`, `CLOUDPULSE_DB_PASSWORD` and `CLOUDPULSE_ADMIN_PASSWORD`; see `db/db.env.example`.

## Settings reference

Secret settings are write-only in the UI: their values are never sent back to the browser.

### Identity (Entra ID)

| Key | Secret | Description |
|---|---|---|
| `ad.audit_lookback_days` |  | Days of directory audit logs to analyse |
| `ad.dc_servers` |  | Comma-separated domain controller hostnames (empty = auto-detect *dc<N> from CloudPulse inventory) |
| `ad.enabled` |  | Collect AD / Entra ID health from Microsoft Graph (true/false) |
| `ad.failed_signin_warn` |  | Warn when genuine failed sign-ins in the look-back window exceed this |
| `ad.home_country` |  | Two-letter country code treated as home for sign-in analysis |
| `ad.licence_warn_pct` |  | Warn when a paid licence SKU is at least this % assigned |
| `ad.max_global_admins` |  | Warn when more accounts than this hold Global Administrator |
| `ad.mfa_target_pct` |  | Target % of enabled member users with MFA registered |
| `ad.refresh_minutes` |  | Minutes between automatic collections (min 15) |
| `ad.secret_crit_days` |  | Critical when an app secret / certificate expires within this many days |
| `ad.secret_warn_days` |  | Warn when an app secret / certificate expires within this many days |
| `ad.signin_lookback_hours` |  | Hours of sign-in logs to analyse |
| `ad.stale_days` |  | Account / device is stale after this many days without sign-in |
| `ad.sync_stale_hours` |  | Warn when Entra Connect has not synced for this many hours |
| `ad.user_failure_threshold` |  | Flag a single account with at least this many failed sign-ins |

### Agent API

| Key | Secret | Description |
|---|---|---|
| `agent.allowed_ips` |  | Allowed IPs |
| `agent.api_key` | yes | Agent API key |

### Capacity thresholds

| Key | Secret | Description |
|---|---|---|
| `capacity.cpu_crit` |  | CPU crit % |
| `capacity.cpu_warn` |  | CPU warn % |
| `capacity.disk_crit` |  | Disk crit % |
| `capacity.disk_warn` |  | Disk warn % |
| `capacity.mem_warn` |  | Mem warn % |
| `capacity.stale_days` |  | Stale days |

### Elasticsearch

| Key | Secret | Description |
|---|---|---|
| `es.index_pattern` |  | Index pattern |
| `es.password` | yes | ES password |
| `es.ssl_verify` |  | Verify SSL for ES |
| `es.url` |  | Elasticsearch endpoint |
| `es.username` |  | ES username |

### Entra ID app registration and SSO

| Key | Secret | Description |
|---|---|---|
| `entra.client_id` |  | Client ID |
| `entra.client_secret` | yes | Client Secret |
| `entra.sso_enabled` |  | Enable SSO |
| `entra.tenant_id` |  | Tenant ID |

### Server inventory

| Key | Secret | Description |
|---|---|---|
| `inventory.env_map` |  | Elastic namespace environment code = environment name (comma-separated) |
| `inventory.project_map` |  | Elastic namespace project code = project name (comma-separated) — used to suggest projects |

### Jira

| Key | Secret | Description |
|---|---|---|
| `jira.api_token` | yes | Jira API token |
| `jira.base_url` |  | Jira base URL |
| `jira.default_assignee` |  | Jira username assigned when the signed-in user has no Jira account |
| `jira.project_key` |  | Jira project key |
| `jira.service_desk_id` |  | Service Desk ID |
| `jira.username` |  | Jira username |

### Language model (assistant, ticket drafts, alert analysis)

| Key | Secret | Description |
|---|---|---|
| `llm.api_key` | yes | LLM API key |
| `llm.base_url` |  | LLM (OpenAI-compatible) base URL |
| `llm.max_tokens` |  | Max response tokens |
| `llm.model` |  | LLM model name |
| `llm.ssl_verify` |  | Verify SSL for LLM |
| `llm.temperature` |  | Temperature |

### Mail (SMTP)

| Key | Secret | Description |
|---|---|---|
| `mail.from` |  | From address |
| `mail.host` |  | SMTP host |
| `mail.password` | yes | SMTP password |
| `mail.port` |  | SMTP port |
| `mail.ssl` |  | Use SSL |
| `mail.username` |  | SMTP username |

### Security posture

| Key | Secret | Description |
|---|---|---|
| `sec.patch_months_warn` |  | Warn when a Windows server is missing updates this many months old |
| `sec.secure_score_target_pct` |  | Warn when Microsoft Secure Score is below this % of maximum |

### Teams alerts

| Key | Secret | Description |
|---|---|---|
| `teams.chat_id` |  | Teams chat ID to read alerts from (uses Entra app credentials) |
| `teams.enabled` |  | Poll the Teams alert chat (true/false) |
| `teams.poll_interval` |  | Poll interval in seconds (min 15) |
| `teams.resolve_interval_min` |  | Minutes between auto-resolve re-checks of active alerts |
| `teams.resolve_threshold` |  | Host CPU/memory/disk alert auto-resolves when every metric is below this % |
| `teams.stale_clear_hours` |  | Auto-resolve non-metric incidents with no new occurrence for this many hours (0 = never) |
