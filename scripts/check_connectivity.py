#!/usr/bin/env python3
"""
CloudPulse connectivity checker
Run inside the cloudpulse container:
    python3 scripts/check_connectivity.py
"""
import asyncio, sys, os

# ── path setup ────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# DB URL must be set (same as app)
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://automation:automation@127.0.0.1:5432/automation"
)
os.environ.setdefault("SECRET_KEY", "diag-only")

SEP = "─" * 60


async def check_db_schema():
    print(f"\n{SEP}")
    print("1. DATABASE SCHEMA")
    print(SEP)
    from app.database import AsyncSessionLocal
    from sqlalchemy import text

    async with AsyncSessionLocal() as db:
        # Tables
        rows = await db.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        ))
        tables = [r[0] for r in rows.fetchall()]
        print(f"  Tables: {', '.join(tables)}")

        # cloudpulse_jira_tickets columns
        rows = await db.execute(text(
            "SELECT column_name, data_type, column_default "
            "FROM information_schema.columns "
            "WHERE table_name='cloudpulse_jira_tickets' ORDER BY ordinal_position"
        ))
        print("\n  cloudpulse_jira_tickets columns:")
        for col, dtype, default in rows.fetchall():
            print(f"    {col:<28} {dtype:<20} default={default}")

        # Constraints
        rows = await db.execute(text(
            "SELECT conname, contype FROM pg_constraint "
            "WHERE conrelid='cloudpulse_jira_tickets'::regclass"
        ))
        print("\n  Constraints:")
        for name, ctype in rows.fetchall():
            print(f"    {name}  (type={ctype})")

        # Entra settings
        rows = await db.execute(text(
            "SELECT key, CASE WHEN is_secret THEN '***' ELSE value END as val "
            "FROM cloudpulse_settings WHERE category='entra' ORDER BY key"
        ))
        print("\n  Entra settings:")
        for key, val in rows.fetchall():
            masked = val if val != '***' else '(secret — hidden)'
            # Check if client_secret is actually set
            if key == 'entra.client_secret':
                real = (await db.execute(text(
                    "SELECT LENGTH(value) FROM cloudpulse_settings WHERE key='entra.client_secret'"
                ))).scalar()
                masked = f"(SET, {real} chars)" if real else "(EMPTY — SSO will fail)"
            print(f"    {key:<30} = {masked}")

        # Jira settings
        rows = await db.execute(text(
            "SELECT key, CASE WHEN is_secret THEN '***' ELSE value END as val "
            "FROM cloudpulse_settings WHERE category='jira' ORDER BY key"
        ))
        print("\n  Jira settings:")
        for key, val in rows.fetchall():
            if val == '***':
                real = (await db.execute(text(
                    f"SELECT LENGTH(value) FROM cloudpulse_settings WHERE key='{key}'"
                ))).scalar()
                val = f"(SET, {real} chars)" if real else "(EMPTY)"
            print(f"    {key:<30} = {val}")

    print("  ✓ DB schema OK")


async def check_jira():
    print(f"\n{SEP}")
    print("2. JIRA CONNECTIVITY")
    print(SEP)
    import httpx, base64
    from app.database import AsyncSessionLocal
    from sqlalchemy import text

    async with AsyncSessionLocal() as db:
        def _get(k): return db.execute(text(
            "SELECT value FROM cloudpulse_settings WHERE key=:k"), {"k": k})
        base_url = (await (await _get("jira.base_url"))).scalar() or ""
        username = (await (await _get("jira.username"))).scalar() or ""
        token    = (await (await _get("jira.api_token"))).scalar() or ""

    if not base_url:
        print("  ✗ jira.base_url is empty — configure in Admin → Jira")
        return

    base_url = base_url.rstrip("/")
    print(f"  URL      : {base_url}")
    print(f"  Username : {username}")
    print(f"  Token    : {'(set)' if token else '(EMPTY)'}")

    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers = {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        try:
            # Test auth
            r = await client.get(f"{base_url}/rest/api/2/myself", headers=headers)
            if r.status_code == 200:
                data = r.json()
                print(f"  ✓ Auth OK — logged in as: {data.get('displayName')} ({data.get('emailAddress')})")
                print(f"    Jira username (key): {data.get('name')} | active: {data.get('active')}")
            else:
                print(f"  ✗ Auth failed: HTTP {r.status_code}")
                print(f"    Response: {r.text[:300]}")
                return

            # Test project
            r2 = await client.get(f"{base_url}/rest/api/2/project/SD", headers=headers)
            if r2.status_code == 200:
                pd = r2.json()
                print(f"  ✓ Project SD exists: {pd.get('name')}")
            else:
                print(f"  ⚠ Project SD check: HTTP {r2.status_code} — {r2.text[:200]}")

            # Test service desk
            r3 = await client.get(f"{base_url}/rest/servicedeskapi/servicedesk", headers=headers)
            if r3.status_code == 200:
                sds = r3.json().get("values", [])
                for sd in sds[:5]:
                    print(f"  ✓ Service desk: {sd.get('projectKey')} — {sd.get('projectName')}")
            else:
                print(f"  ⚠ Service desk list: HTTP {r3.status_code}")

        except Exception as e:
            print(f"  ✗ Connection error: {e}")


async def check_azure():
    print(f"\n{SEP}")
    print("3. AZURE / ENTRA CONNECTIVITY")
    print(SEP)
    import msal
    from app.database import AsyncSessionLocal
    from sqlalchemy import text

    async with AsyncSessionLocal() as db:
        def _get(k): return db.execute(text(
            "SELECT value FROM cloudpulse_settings WHERE key=:k"), {"k": k})
        tenant   = (await (await _get("entra.tenant_id"))).scalar() or ""
        client_id= (await (await _get("entra.client_id"))).scalar() or ""
        secret   = (await (await _get("entra.client_secret"))).scalar() or ""
        redir    = (await (await _get("entra.redirect_uri"))).scalar() or ""

    print(f"  Tenant ID   : {tenant}")
    print(f"  Client ID   : {client_id}")
    print(f"  Redirect URI: {redir}")
    print(f"  Secret      : {'(set, ' + str(len(secret)) + ' chars)' if secret else '(EMPTY — fix this first)'}")

    if not (tenant and client_id and secret):
        print("  ✗ Missing config — cannot test. Set entra.client_secret in Admin → Azure/Entra")
        return

    authority = f"https://login.microsoftonline.com/{tenant}"
    print(f"\n  Testing client credentials flow (app-level token)…")
    try:
        app_ = msal.ConfidentialClientApplication(
            client_id, authority=authority, client_credential=secret,
        )
        # Use .default scope for client_credentials (tests secret validity)
        result = app_.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" in result:
            import json, base64 as b64
            # Decode JWT payload (middle part)
            payload = result["access_token"].split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            claims = json.loads(b64.b64decode(payload))
            print(f"  ✓ Client credentials token acquired!")
            print(f"    App display name : {claims.get('app_displayname', '?')}")
            print(f"    Tenant           : {claims.get('tid', '?')}")
            expires_in = result.get("expires_in", 0)
            print(f"    Expires in       : {expires_in}s")
            print(f"\n  Testing authorization URL generation (for SSO redirect)…")
            url = app_.get_authorization_request_url(
                scopes=["User.Read"],
                state="test",
                redirect_uri=redir,
            )
            print(f"  ✓ Auth URL built: {url[:80]}…")
            print(f"\n  ✓ Azure config is VALID. SSO will work once client_secret is saved and app is restarted.")
        else:
            err = result.get("error", "unknown")
            desc = result.get("error_description", "")
            print(f"  ✗ Token failed: {err}")
            print(f"    {desc[:300]}")
            if "AADSTS700016" in desc:
                print("    → Client ID not found in this tenant. Check entra.client_id.")
            elif "AADSTS7000215" in desc or "Invalid client secret" in desc:
                print("    → Client secret is wrong or expired. Rotate it in Azure App Registration.")
            elif "AADSTS700082" in desc:
                print("    → Client secret has expired. Create a new one in Azure App Registration.")
    except Exception as e:
        print(f"  ✗ MSAL error: {e}")


async def main():
    print("=" * 60)
    print("  CloudPulse Connectivity Check")
    print("=" * 60)
    await check_db_schema()
    await check_jira()
    await check_azure()
    print(f"\n{SEP}")
    print("Done.")
    print(SEP)

asyncio.run(main())
