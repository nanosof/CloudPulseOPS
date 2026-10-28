# Operations

Commands assume rootless Podman with the units from `deploy/quadlet` and the container names `cloudpulse` and `cloudpulse-db`.

## Service control

```bash
systemctl --user status cloudpulse.service cloudpulse-db.service
systemctl --user restart cloudpulse.service
journalctl --user -u cloudpulse.service -f      # or: podman logs -f cloudpulse
curl -s http://127.0.0.1:8694/health
```

## Backup and restore

```bash
# Backup
podman exec cloudpulse-db pg_dump -U postgres -d cloudpulse | gzip > cloudpulse-$(date +%Y%m%d-%H%M).sql.gz

# Restore into an empty database
systemctl --user stop cloudpulse.service
gunzip -c cloudpulse-YYYYMMDD-HHMM.sql.gz | podman exec -i cloudpulse-db psql -U postgres -d cloudpulse
systemctl --user start cloudpulse.service
```

Back up before every upgrade. The dump contains secret settings, so store it accordingly.

## Using an existing PostgreSQL instance

```sql
CREATE ROLE cloudpulse LOGIN PASSWORD '<password>';
CREATE DATABASE cloudpulse OWNER cloudpulse;
```

Then, connected as `cloudpulse` to the new database:

```bash
psql -h <host> -U cloudpulse -d cloudpulse -f db/init/10-schema.sql
psql -h <host> -U cloudpulse -d cloudpulse -f db/init/20-settings.sql
```

Create the first administrator (replace the password; requires the `pgcrypto` extension, or set the password from **Admin Settings → Users** of an existing admin):

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO cloudpulse_users (username, full_name, hashed_pw, is_active, is_admin)
VALUES ('admin', 'Administrator', crypt('<password>', gen_salt('bf', 12)), TRUE, TRUE);
```

Set `DATABASE_URL=postgresql+asyncpg://cloudpulse:<password>@<host>:5432/cloudpulse` in `cloudpulse.env`.

## Upgrades

1. Back up the database.
2. `git pull`, rebuild the image (or use `Containerfile.update` for a code-only rebuild), tag it `latest`.
3. `systemctl --user restart cloudpulse.service`.
4. Check `/health` and the logs. To roll back, re-tag the previous image as `latest` and restart.

Tag every build with a version so a rollback is one `podman tag` away.

## Rotating secrets

| Secret | How |
|---|---|
| `JWT_SECRET` | Edit `cloudpulse.env`, restart. All users sign in again. |
| Database password | `ALTER ROLE cloudpulse PASSWORD '...'`, update `DATABASE_URL`, restart. |
| Entra client secret | Create a new secret in the app registration, paste it in **Admin Settings → Azure/Entra**. The Identity page shows when the current one expires. |
| Agent API key | Change `agent.api_key` and update the callers. |

## Troubleshooting

| Symptom | Check |
|---|---|
| App exits at start with `DATABASE_URL is not set` or `JWT_SECRET is not set` | The environment file path in the unit and its contents |
| Dashboard shows no servers | `es.url` and credentials; `podman exec cloudpulse python scripts/check_connectivity.py` |
| An Identity or Security view says a permission is missing | Grant the listed Graph permission with admin consent; it is picked up on the next collection |
| Graph `429` messages in the logs | Throttling; collections retry automatically, and hunting queries are limited per minute by Microsoft |
| Teams alerts stop | `teams.enabled`, `teams.chat_id`, the `Chat.Read.All` permission, and `podman logs cloudpulse` for poll errors |
| Scheduled report e-mails not arriving | **Scheduled Reports → History** shows the e-mail status of each run; check the `mail.*` settings and use **Test** in **Admin Settings → Email** |
