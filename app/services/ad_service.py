"""
AD / Entra ID health — collected from Microsoft Graph with the Entra app registration
(Application permissions: Directory.Read.All, User.Read.All, AuditLog.Read.All,
Reports.Read.All, Organization.Read.All) plus on-prem DC metrics from CloudPulse.

Each section is collected independently into cloudpulse_ad_snapshots (one JSONB
row per section) so a failing Graph call never blanks the others. Key numbers are
also written daily to cloudpulse_ad_kpi_daily for trend lines. Findings and the
health score are derived on read from the snapshots + current ad.* settings.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import text

from app.database import AsyncSessionLocal
from app.services import graph_service as g
from app.services import teams_alert_service as tas
import app.config as cfg

log = logging.getLogger(__name__)

AD_LOCK_ID = 86940010
_SCHEMA_LOCK_ID = 86940011
DUBAI = timezone(timedelta(hours=4))

# ─────────────────────────────────────────────────────────────────────────────
# Schema + settings
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS cloudpulse_ad_snapshots (
        section      VARCHAR(40) PRIMARY KEY,
        data         JSONB,
        ok           BOOLEAN,
        error        TEXT,
        duration_ms  INTEGER,
        collected_at TIMESTAMPTZ,
        attempted_at TIMESTAMPTZ
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cloudpulse_ad_kpi_daily (
        day    DATE        NOT NULL,
        kpi    VARCHAR(60) NOT NULL,
        value  NUMERIC,
        PRIMARY KEY (day, kpi)
    )
    """,
    """
    INSERT INTO cloudpulse_settings (key, value, category, description, is_secret) VALUES
    ('ad.enabled',                'true', 'ad', 'Collect AD / Entra ID health from Microsoft Graph (true/false)', FALSE),
    ('ad.refresh_minutes',        '60',   'ad', 'Minutes between automatic collections (min 15)', FALSE),
    ('ad.stale_days',             '90',   'ad', 'Account / device is stale after this many days without sign-in', FALSE),
    ('ad.secret_warn_days',       '30',   'ad', 'Warn when an app secret / certificate expires within this many days', FALSE),
    ('ad.secret_crit_days',       '7',    'ad', 'Critical when an app secret / certificate expires within this many days', FALSE),
    ('ad.max_global_admins',      '5',    'ad', 'Warn when more accounts than this hold Global Administrator', FALSE),
    ('ad.sync_stale_hours',       '3',    'ad', 'Warn when Entra Connect has not synced for this many hours', FALSE),
    ('ad.mfa_target_pct',         '95',   'ad', 'Target % of enabled member users with MFA registered', FALSE),
    ('ad.failed_signin_warn',     '500',  'ad', 'Warn when genuine failed sign-ins in the look-back window exceed this', FALSE),
    ('ad.user_failure_threshold', '25',   'ad', 'Flag a single account with at least this many failed sign-ins', FALSE),
    ('ad.signin_lookback_hours',  '24',   'ad', 'Hours of sign-in logs to analyse', FALSE),
    ('ad.audit_lookback_days',    '7',    'ad', 'Days of directory audit logs to analyse', FALSE),
    ('ad.home_country',           'AE',   'ad', 'Two-letter country code treated as home for sign-in analysis', FALSE),
    ('ad.dc_servers',             '',     'ad', 'Comma-separated domain controller hostnames (empty = auto-detect *dc<N> from CloudPulse inventory)', FALSE),
    ('ad.licence_warn_pct',       '98',   'ad', 'Warn when a paid licence SKU is at least this % assigned', FALSE)
    ON CONFLICT (key) DO NOTHING
    """,
]


async def ensure_schema() -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _SCHEMA_LOCK_ID})
        for stmt in _SCHEMA:
            await db.execute(text(stmt))
        await db.commit()
    await cfg.invalidate_cache()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _days_since(value: Optional[str]) -> Optional[float]:
    d = _dt(value)
    return round((_now() - d).total_seconds() / 86400, 1) if d else None


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _top(counter: Counter, n: int = 10) -> list[dict]:
    return [{"name": k, "count": v} for k, v in counter.most_common(n)]


async def _settings() -> dict:
    return {
        "stale_days":             await cfg.get_int("ad.stale_days", 90),
        "secret_warn_days":       await cfg.get_int("ad.secret_warn_days", 30),
        "secret_crit_days":       await cfg.get_int("ad.secret_crit_days", 7),
        "max_global_admins":      await cfg.get_int("ad.max_global_admins", 5),
        "sync_stale_hours":       await cfg.get_float("ad.sync_stale_hours", 3),
        "mfa_target_pct":         await cfg.get_float("ad.mfa_target_pct", 95),
        "failed_signin_warn":     await cfg.get_int("ad.failed_signin_warn", 500),
        "user_failure_threshold": await cfg.get_int("ad.user_failure_threshold", 25),
        "signin_lookback_hours":  max(1, min(168, await cfg.get_int("ad.signin_lookback_hours", 24))),
        "audit_lookback_days":    max(1, min(30, await cfg.get_int("ad.audit_lookback_days", 7))),
        "home_country":           (await cfg.get("ad.home_country", "AE")).strip().upper() or "AE",
        "dc_servers":             [s.strip() for s in (await cfg.get("ad.dc_servers", "")).split(",") if s.strip()],
        "licence_warn_pct":       await cfg.get_float("ad.licence_warn_pct", 98),
        "app_client_id":          (await cfg.get("entra.client_id", "")).strip().lower(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Collectors — each returns a JSON-able dict with a "summary" key
# ─────────────────────────────────────────────────────────────────────────────

async def c_tenant(ctx: dict) -> dict:
    s = ctx["settings"]
    org = (await g.get("/organization", {"$select": "id,displayName,onPremisesSyncEnabled,"
                       "onPremisesLastSyncDateTime,verifiedDomains,createdDateTime,countryLetterCode"}))["value"][0]
    last_sync = org.get("onPremisesLastSyncDateTime")
    sync_age = round((_now() - _dt(last_sync)).total_seconds() / 3600, 2) if last_sync else None

    # On-prem domain controllers — live metrics from CloudPulse
    inventory = await tas._load_ig_hosts()
    if s["dc_servers"]:
        dc_names = [inventory.get(tas._short(n), n) for n in s["dc_servers"]]
    else:
        dc_names = sorted(v for k, v in inventory.items() if re.search(r"dc\d+$", k))
    dcs = []
    for name in dc_names[:20]:
        d = await tas.get_server_metrics(name)
        rt = d.get("realtime") or {}
        has = tas._has_metrics(d)
        disks = rt.get("disk") or []
        dcs.append({
            "name": name, "has_data": has, "os": d.get("os_name"), "ip": d.get("host_ip"),
            "cpu": (rt.get("cpu") or {}).get("avg_pct") if has else None,
            "mem": (rt.get("memory") or {}).get("used_pct") if has else None,
            "disk": max((x.get("used_pct") or 0) for x in disks) if disks else None,
            "severity": d.get("overall_severity") if has else "unknown",
        })

    domains = [{"name": d["name"], "default": d.get("isDefault"), "initial": d.get("isInitial"),
                "type": d.get("type")} for d in org.get("verifiedDomains", [])]
    return {
        "summary": {
            "tenant_name": org.get("displayName"), "tenant_id": org.get("id"),
            "country": org.get("countryLetterCode"), "created": org.get("createdDateTime"),
            "sync_enabled": bool(org.get("onPremisesSyncEnabled")), "last_sync": last_sync,
            "sync_age_hours": sync_age, "domains": len(domains),
            "dcs": len(dcs), "dcs_unhealthy": sum(1 for d in dcs if d["severity"] in ("warning", "critical")),
            "dcs_no_data": sum(1 for d in dcs if not d["has_data"]),
        },
        "domains": domains,
        "dcs": dcs,
    }


async def c_accounts(ctx: dict) -> dict:
    s = ctx["settings"]
    users = await g.get_all("/users", {
        "$select": "id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,signInActivity,"
                   "assignedLicenses,onPremisesSyncEnabled,department,jobTitle,lastPasswordChangeDateTime,"
                   "externalUserState,companyName,officeLocation,employeeId,usageLocation,city,country",
        "$top": "500",
    })
    sku_names = await _sku_names()
    rows, by_id = [], {}
    for u in users:
        sia = u.get("signInActivity") or {}
        stamps = [sia.get(k) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime",
                                       "lastSuccessfulSignInDateTime") if sia.get(k)]
        last = max(stamps, key=lambda x: _dt(x)) if stamps else None
        r = {
            "id": u["id"], "name": u.get("displayName"), "upn": u.get("userPrincipalName"),
            "mail": u.get("mail"), "enabled": bool(u.get("accountEnabled")), "type": u.get("userType") or "Member",
            "dept": u.get("department"), "title": u.get("jobTitle"),
            "created": u.get("createdDateTime"), "created_days": _days_since(u.get("createdDateTime")),
            "last_signin": last, "inactive_days": _days_since(last),
            "licences": [l["skuId"] for l in u.get("assignedLicenses") or []],
            "company": u.get("companyName"), "office": u.get("officeLocation"), "employee_id": u.get("employeeId"),
            "usage_location": u.get("usageLocation"), "city": u.get("city"), "country": u.get("country"),
            "synced": bool(u.get("onPremisesSyncEnabled")),
            "pwd_changed": u.get("lastPasswordChangeDateTime"),
            "pwd_age_days": _days_since(u.get("lastPasswordChangeDateTime")),
            "guest_state": u.get("externalUserState"),
        }
        names = [sku_names.get(x, ("Unknown SKU", False)) for x in r["licences"]]
        r["licence_names"] = sorted(n for n, _ in names)
        r["paid_licences"] = sorted(n for n, free in names if not free)
        rows.append(r)
        by_id[r["id"]] = r
    ctx["users"] = by_id

    sd = s["stale_days"]
    def slim(r: dict) -> dict:
        return {k: r[k] for k in ("id", "name", "upn", "mail", "enabled", "type", "dept", "title", "company", "office",
                                  "employee_id", "usage_location", "created", "created_days", "last_signin", "inactive_days",
                                  "synced", "pwd_changed", "pwd_age_days", "guest_state", "licence_names", "paid_licences")} \
               | {"licence_count": len(r["licences"]), "paid_licence_count": len(r["paid_licences"])}

    enabled = [r for r in rows if r["enabled"]]
    stale = [r for r in enabled if (r["inactive_days"] is not None and r["inactive_days"] > sd)
             or (r["inactive_days"] is None and (r["created_days"] or 0) > sd)]
    never = [r for r in enabled if r["last_signin"] is None]
    disabled_lic = [r for r in rows if not r["enabled"] and r["licences"]]
    guests = [r for r in rows if r["type"] == "Guest"]
    new7 = [r for r in rows if (r["created_days"] or 999) <= 7]
    pwd_old = [r for r in enabled if r["type"] == "Member" and (r["pwd_age_days"] or 0) > 365]

    cap = 3000
    return {
        "summary": {
            "total": len(rows), "enabled": len(enabled), "disabled": len(rows) - len(enabled),
            "members": sum(1 for r in rows if r["type"] == "Member"), "guests": len(guests),
            "synced": sum(1 for r in rows if r["synced"]), "cloud_only": sum(1 for r in rows if not r["synced"]),
            "licensed": sum(1 for r in rows if r["licences"]),
            "stale": len(stale), "never_signed_in": len(never), "disabled_licensed": len(disabled_lic),
            "new_7d": len(new7), "pwd_over_365d": len(pwd_old), "stale_days": sd,
        },
        "stale":             [slim(r) for r in sorted(stale, key=lambda r: -(r["inactive_days"] or r["created_days"] or 0))][:cap],
        "never_signed_in":   [slim(r) for r in sorted(never, key=lambda r: -(r["created_days"] or 0))][:cap],
        "disabled_licensed": [slim(r) for r in disabled_lic][:cap],
        "guests":            [slim(r) for r in sorted(guests, key=lambda r: -(r["inactive_days"] or 9999))][:cap],
        "new_7d":            [slim(r) for r in sorted(new7, key=lambda r: r["created_days"] or 0)][:cap],
        "pwd_over_365d":     [slim(r) for r in sorted(pwd_old, key=lambda r: -(r["pwd_age_days"] or 0))][:cap],
        "by_department":     _top(Counter((r["dept"] or "(none)") for r in enabled), 15),
        "disabled_by_licence": _top(Counter(n for r in disabled_lic for n in r["licence_names"]), 30),
        "stale_by_licence":  _top(Counter(n for r in stale for n in r["paid_licences"]), 30),
    }


PER_USER_MFA_PERMISSION = "Policy.Read.All (Application, admin consent)"


async def _per_user_mfa(user_ids: list[str]) -> tuple[Optional[dict[str, str]], Optional[str]]:
    """
    Legacy per-user MFA state (disabled / enabled / enforced) for each user, via batched
    GET /users/{id}/authentication/requirements (beta). Returns (states, error).
    """
    if not user_ids:
        return {}, None
    paths = [f"/users/{uid}/authentication/requirements" for uid in user_ids]
    try:
        res = await g.batch_get(paths, beta=True)
    except Exception as exc:
        return None, str(exc)[:200]
    states, denied = {}, 0
    for uid, path in zip(user_ids, paths):
        r = res.get(path) or {}
        if r.get("status") == 200:
            states[uid] = (r["body"].get("perUserMfaState") or "unknown").lower()
        elif r.get("status") in (401, 403):
            denied += 1
    if not states and denied:
        return None, f"Microsoft Graph denied per-user MFA state — grant {PER_USER_MFA_PERMISSION}"
    return states, None


async def _mfa_requirements(member_ids: list[str]) -> dict:
    """
    Who is REQUIRED to use MFA (independent of whether they registered a method):
      security defaults · Conditional Access policies requiring MFA / an authentication strength.
    Needs Policy.Read.All. Returns {available, errors, security_defaults, policies, required: {user_id: [reasons]}}.
    """
    out: dict[str, Any] = {"available": False, "errors": [], "security_defaults": None, "policies": [], "required": defaultdict(list)}
    try:
        sd = await g.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        out["security_defaults"] = bool(sd.get("isEnabled"))
        if out["security_defaults"]:
            for uid in member_ids:
                out["required"][uid].append("Security defaults")
        out["available"] = True
    except Exception as exc:
        out["errors"].append(f"security defaults: {exc}")
    try:
        policies = await g.get_all("/identity/conditionalAccess/policies")
    except Exception as exc:
        out["errors"].append(f"conditional access: {exc}")
        return out
    out["available"] = True
    group_cache: dict[str, set] = {}
    role_cache: dict[str, set] = {}

    async def group_members(gid: str) -> set:
        if gid not in group_cache:
            try:
                group_cache[gid] = {m["id"] for m in await g.get_all(f"/groups/{gid}/transitiveMembers/microsoft.graph.user", {"$select": "id"})}
            except Exception:
                group_cache[gid] = set()
        return group_cache[gid]

    async def role_members(tid: str) -> set:
        if tid not in role_cache:
            try:
                role_cache[tid] = {m["id"] for m in await g.get_all(f"/directoryRoles(roleTemplateId='{tid}')/members", {"$select": "id"})}
            except Exception:
                role_cache[tid] = set()
        return role_cache[tid]

    members = set(member_ids)
    for pol in policies:
        gc = pol.get("grantControls") or {}
        needs_mfa = "mfa" in (gc.get("builtInControls") or []) or bool(gc.get("authenticationStrength"))
        cond = pol.get("conditions") or {}
        users = cond.get("users") or {}
        apps = (cond.get("applications") or {}).get("includeApplications") or []
        locs = cond.get("locations") or {}
        qualifiers = []
        if apps and "All" not in apps:
            qualifiers.append("some apps")
        if locs.get("includeLocations") and locs.get("includeLocations") != ["All"] or locs.get("excludeLocations"):
            qualifiers.append("location-based")
        row = {"name": pol.get("displayName"), "state": pol.get("state"), "requires_mfa": needs_mfa,
               "strength": (gc.get("authenticationStrength") or {}).get("displayName"),
               "scope": "All users" if "All" in (users.get("includeUsers") or []) else
                        f"{len(users.get('includeUsers') or [])} users, {len(users.get('includeGroups') or [])} groups, {len(users.get('includeRoles') or [])} roles",
               "excludes": f"{len(users.get('excludeUsers') or [])} users, {len(users.get('excludeGroups') or [])} groups, {len(users.get('excludeRoles') or [])} roles",
               "apps": "All apps" if "All" in apps else f"{len(apps)} apps", "conditions": ", ".join(qualifiers) or "—", "covers": 0}
        out["policies"].append(row)
        if pol.get("state") != "enabled" or not needs_mfa:
            continue          # report-only / disabled policies don't force anything
        inc = set()
        if "All" in (users.get("includeUsers") or []):
            inc = set(members)
        else:
            inc |= members & set(users.get("includeUsers") or [])
            for gid in users.get("includeGroups") or []:
                inc |= members & await group_members(gid)
            for tid in users.get("includeRoles") or []:
                inc |= members & await role_members(tid)
        exc = members & set(users.get("excludeUsers") or [])
        for gid in users.get("excludeGroups") or []:
            exc |= members & await group_members(gid)
        for tid in users.get("excludeRoles") or []:
            exc |= members & await role_members(tid)
        covered = inc - exc
        row["covers"] = len(covered)
        reason = f"CA: {pol.get('displayName')}" + (f" ({', '.join(qualifiers)})" if qualifiers else "")
        for uid in covered:
            out["required"][uid].append(reason)
    return out


async def c_mfa(ctx: dict) -> dict:
    """
    Three views of MFA for enabled member accounts:
      1. synced users without a registered MFA method (all on-prem synced accounts)
      2. users with a mailbox without a registered MFA method
      3. legacy per-user MFA state (disabled / enabled / enforced) — preferred for reporting
    Coverage headline uses view 3 when Graph allows reading it, else registration (view 2 scope).
    """
    regs = await g.get_all("/reports/authenticationMethods/userRegistrationDetails")
    users = ctx.get("users") or {}
    enabled = [r for r in regs if r.get("userType") != "guest" and users.get(r["id"], {}).get("enabled", True)]

    def has_mailbox(r: dict) -> bool:
        return not users or bool(users.get(r["id"], {}).get("mail"))

    def synced(r: dict) -> bool:
        return bool(users.get(r["id"], {}).get("synced"))

    # Reporting scope: accounts with a mailbox, plus admins (an admin without MFA is always a risk).
    # Accounts without a mailbox are typically on-prem service accounts that never sign in interactively.
    excluded = [r for r in enabled if not has_mailbox(r) and not r.get("isAdmin")]
    members = [r for r in enabled if has_mailbox(r) or r.get("isAdmin")]
    admins = [r for r in members if r.get("isAdmin")]
    methods = Counter(m for r in members for m in (r.get("methodsRegistered") or []))
    not_registered = [r for r in members if not r.get("isMfaRegistered")]

    states, per_user_error = await _per_user_mfa([r["id"] for r in members])
    per_user = states is not None
    state = (lambda r: (states or {}).get(r["id"], "unknown"))

    # MFA requirement vs registration → protected / pending registration / unprotected / unknown
    req = await _mfa_requirements([r["id"] for r in members])
    if per_user:
        for r in members:
            if state(r) in ("enabled", "enforced"):
                req["required"][r["id"]].append(f"Per-user MFA {state(r)}")
    # Business rule: "System preferred MFA" feature status Enabled counts as MFA enabled for the user
    for r in members:
        if r.get("isSystemPreferredAuthenticationMethodEnabled"):
            req["required"][r["id"]].append("System-preferred MFA enabled")
    requirement_known = req["available"] or per_user or any(
        r.get("isSystemPreferredAuthenticationMethodEnabled") is not None for r in members)
    reasons = lambda r: req["required"].get(r["id"], [])

    def category(r: dict) -> str:
        if r.get("isMfaRegistered"):
            return "protected"
        if reasons(r):
            return "pending_registration"
        return "unprotected" if requirement_known else "unknown"

    def slim(r: dict) -> dict:
        u = users.get(r["id"], {})
        return {"id": r["id"], "name": r.get("userDisplayName"), "upn": r.get("userPrincipalName"),
                "category": category(r), "required_by": "; ".join(reasons(r)) or None, "inactive_days": u.get("inactive_days"),
                "mail": u.get("mail"), "admin": bool(r.get("isAdmin")), "methods": r.get("methodsRegistered") or [],
                "registered": bool(r.get("isMfaRegistered")), "per_user": state(r) if per_user else None,
                "sspr": bool(r.get("isSsprRegistered")), "dept": u.get("dept"),
                "last_signin": u.get("last_signin"), "synced": u.get("synced"),
                "title": u.get("title"), "company": u.get("company"), "office": u.get("office"),
                "licence_names": u.get("licence_names") or [], "created": u.get("created")}

    def lst(rows: list[dict]) -> list[dict]:
        return [slim(r) for r in sorted(rows, key=lambda r: (not r.get("isAdmin"), r.get("userDisplayName") or ""))][:3000]

    # "Without MFA" views leave out users whose MFA is enabled but not yet enrolled — they are listed
    # under pending_registration instead (system-preferred / per-user / policy).
    def mfa_enabled(r: dict) -> bool:
        return bool(reasons(r)) or bool(r.get("isSystemPreferredAuthenticationMethodEnabled"))

    n = len(members) or 1
    registered_pct = round(100 * (len(members) - len(not_registered)) / n, 1)
    if per_user:
        on = [r for r in members if state(r) in ("enabled", "enforced")]
        off = [r for r in members if state(r) not in ("enabled", "enforced")]
        mfa_pct, covered = round(100 * len(on) / n, 1), len(on)
        admins_gap = [r for r in admins if state(r) not in ("enabled", "enforced") and not r.get("isMfaRegistered")]
    else:
        off, mfa_pct, covered = [r for r in not_registered if not mfa_enabled(r)], registered_pct, len(members) - len(not_registered)
        admins_gap = [r for r in admins if not r.get("isMfaRegistered")]

    synced_gap = [r for r in enabled if synced(r) and not r.get("isMfaRegistered") and not mfa_enabled(r)]
    mailbox_gap = [r for r in enabled if has_mailbox(r) and not r.get("isMfaRegistered") and not mfa_enabled(r)]
    per_state = Counter(state(r) for r in members) if per_user else Counter()
    return {
        "summary": {
            "users": len(members), "method": "per_user" if per_user else "registration",
            "per_user_available": per_user, "per_user_error": per_user_error,
            "mfa_registered": covered, "mfa_pct": mfa_pct, "registered_pct": registered_pct,
            "without_mfa": len(off),
            "per_user_disabled": per_state.get("disabled", 0), "per_user_enabled": per_state.get("enabled", 0),
            "per_user_enforced": per_state.get("enforced", 0),
            "enforced_not_registered": sum(1 for r in members if per_user and state(r) == "enforced" and not r.get("isMfaRegistered")),
            "synced_without_mfa": len(synced_gap), "mailbox_without_mfa": len(mailbox_gap),
            "mfa_capable": sum(1 for r in members if r.get("isMfaCapable")),
            "sspr_registered": sum(1 for r in members if r.get("isSsprRegistered")),
            "sspr_pct": round(100 * sum(1 for r in members if r.get("isSsprRegistered")) / n, 1),
            "passwordless": sum(1 for r in members if r.get("isPasswordlessCapable")),
            "admins": len(admins), "admins_without_mfa": len(admins_gap),
            "excluded_no_mailbox": len(excluded),
            "requirement_known": requirement_known, "requirement_errors": req["errors"],
            "security_defaults": req["security_defaults"],
            "ca_mfa_policies": sum(1 for p in req["policies"] if p["requires_mfa"] and p["state"] == "enabled"),
            "protected": sum(1 for r in members if category(r) == "protected"),
            "pending_registration": sum(1 for r in members if category(r) == "pending_registration"),
            "pending_inactive_90d": sum(1 for r in members if category(r) == "pending_registration"
                                        and (users.get(r["id"], {}).get("inactive_days") or 9999) > 90),
            "unprotected": sum(1 for r in members if category(r) == "unprotected"),
            "requirement_unknown": sum(1 for r in members if category(r) == "unknown"),
        },
        "methods": _top(methods, 15),
        # View 1 / 2 — registration based
        "synced_without_mfa": lst(synced_gap),
        "mailbox_without_mfa": lst(mailbox_gap),
        # View 3 — per-user MFA state (empty until Graph permission is granted)
        "per_user_disabled": lst([r for r in members if per_user and state(r) == "disabled"]),
        "per_user_enabled": lst([r for r in members if per_user and state(r) == "enabled"]),
        "per_user_enforced": lst([r for r in members if per_user and state(r) == "enforced"]),
        "enforced_not_registered": lst([r for r in members if per_user and state(r) == "enforced" and not r.get("isMfaRegistered")]),
        # Headline gap list (view 3 when available) and admins
        "without_mfa": lst(off),
        "admins_without_mfa": lst(admins_gap),
        "admins": lst(admins),
        "excluded_no_mailbox": lst(excluded),
        # Requirement vs registration
        "pending_registration": lst([r for r in members if category(r) == "pending_registration"]),
        "unprotected": lst([r for r in members if category(r) == "unprotected"]),
        "requirement_unknown": lst([r for r in members if category(r) == "unknown"]),
        "ca_policies": req["policies"],
    }


# Directory role templates treated as highly privileged
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
}
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


async def c_privileged(ctx: dict) -> dict:
    roles = await g.get_all("/directoryRoles", {"$select": "id,displayName,roleTemplateId,description"})
    sem = asyncio.Semaphore(5)

    async def members(role: dict) -> list[dict]:
        async with sem:
            return await g.get_all(f"/directoryRoles/{role['id']}/members",
                                   {"$select": "id,displayName,userPrincipalName,accountEnabled,appId"})

    results = await asyncio.gather(*(members(r) for r in roles))
    users = ctx.get("users") or {}
    assignments, role_rows = [], []
    for role, mem in zip(roles, results):
        tpl = role.get("roleTemplateId")
        priv = tpl in PRIVILEGED_ROLES
        role_rows.append({"role": role["displayName"], "template": tpl, "privileged": priv,
                          "members": len(mem), "description": role.get("description")})
        for m in mem:
            kind = (m.get("@odata.type") or "").split(".")[-1] or "user"
            u = users.get(m["id"], {})
            assignments.append({
                "role": role["displayName"], "privileged": priv, "global_admin": tpl == GLOBAL_ADMIN,
                "kind": kind, "id": m["id"], "name": m.get("displayName"),
                "upn": m.get("userPrincipalName") or m.get("appId"),
                "enabled": m.get("accountEnabled", u.get("enabled")),
                "last_signin": u.get("last_signin"), "inactive_days": u.get("inactive_days"),
                "synced": u.get("synced"), "title": u.get("title"), "dept": u.get("dept"), "company": u.get("company"),
                "licence_names": u.get("licence_names") or [], "pwd_age_days": u.get("pwd_age_days"),
            })
    priv_assign = [a for a in assignments if a["privileged"]]
    global_admins = [a for a in assignments if a["global_admin"]]
    return {
        "summary": {
            "roles_in_use": sum(1 for r in role_rows if r["members"]),
            "assignments": len(assignments),
            "privileged_assignments": len(priv_assign),
            "privileged_principals": len({a["id"] for a in priv_assign}),
            "global_admins": len(global_admins),
            "disabled_with_roles": sum(1 for a in assignments if a["enabled"] is False),
            "service_principals_privileged": sum(1 for a in priv_assign if a["kind"] == "servicePrincipal"),
            "synced_privileged": sum(1 for a in priv_assign if a["synced"]),
            "stale_privileged": sum(1 for a in priv_assign
                                    if (a["inactive_days"] or 0) > ctx["settings"]["stale_days"]),
        },
        "roles": sorted(role_rows, key=lambda r: (not r["privileged"], -r["members"])),
        "assignments": sorted(assignments, key=lambda a: (not a["global_admin"], not a["privileged"], a["role"], a["name"] or "")),
    }


async def c_secrets(ctx: dict) -> dict:
    s = ctx["settings"]
    apps = await g.get_all("/applications", {"$select": "id,appId,displayName,passwordCredentials,keyCredentials,createdDateTime",
                                             "$top": "999"})
    rows, per_app = [], defaultdict(list)
    for a in apps:
        for kind, creds in (("Secret", a.get("passwordCredentials") or []), ("Certificate", a.get("keyCredentials") or [])):
            for c in creds:
                end = _dt(c.get("endDateTime"))
                if not end:
                    continue
                days = round((end - _now()).total_seconds() / 86400, 1)
                rec = {"app": a.get("displayName"), "app_id": a.get("appId"), "kind": kind,
                       "name": c.get("displayName") or (c.get("keyId") or "")[:8], "start": c.get("startDateTime"),
                       "end": c.get("endDateTime"), "days_left": days,
                       "this_app": (a.get("appId") or "").lower() == s["app_client_id"]}
                per_app[a["appId"]].append(rec)
                rows.append(rec)
    for rec in rows:
        siblings = per_app[rec["app_id"]]
        rec["app_has_valid"] = any(x["days_left"] > s["secret_warn_days"] for x in siblings if x is not rec)
        rec["status"] = ("expired" if rec["days_left"] < 0 else
                         "critical" if rec["days_left"] <= s["secret_crit_days"] else
                         "warning" if rec["days_left"] <= s["secret_warn_days"] else "ok")

    # Credentials that need action: expiring soon, or expired with no replacement on the app
    attention = [r for r in rows if r["status"] in ("critical", "warning")
                 or (r["status"] == "expired" and not r["app_has_valid"] and r["days_left"] > -90)]
    own = [r for r in rows if r["this_app"]]
    return {
        "summary": {
            "apps": len(apps), "apps_with_credentials": len(per_app), "credentials": len(rows),
            "expired_unreplaced": sum(1 for r in attention if r["status"] == "expired"),
            "critical": sum(1 for r in attention if r["status"] == "critical"),
            "warning": sum(1 for r in attention if r["status"] == "warning"),
            "this_app_days_left": max((r["days_left"] for r in own), default=None),
            "warn_days": s["secret_warn_days"], "crit_days": s["secret_crit_days"],
        },
        "attention": sorted(attention, key=lambda r: r["days_left"]),
        "upcoming": sorted([r for r in rows if 0 <= r["days_left"] <= 180], key=lambda r: r["days_left"]),
        "this_app": own,
    }


INTERRUPT_CODES = {50140, 50074, 50076, 50079, 50072, 50058, 16000, 16001, 50199, 81010, 81012,
                   70044, 50132, 50133, 50173, 700082, 50089, 65001, 50097, 530032}
LEGACY_CLIENTS = {"Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Authenticated SMTP", "Exchange Web Services",
                  "Other clients", "MAPI Over HTTP", "Offline Address Book", "AutoDiscover",
                  "Exchange Online PowerShell", "Outlook Anywhere (RPC over HTTP)", "Reporting Web Services",
                  "Universal Outlook"}


async def c_signins(ctx: dict) -> dict:
    s = ctx["settings"]
    hours = s["signin_lookback_hours"]
    since = _now() - timedelta(hours=hours)
    events = await g.get_all("/auditLogs/signIns", {
        "$filter": f"createdDateTime ge {_iso(since)} and status/errorCode ne 0",
        "$top": "999",
    }, max_items=20000)

    home = s["home_country"]
    genuine, interrupts = [], 0
    by_hour = Counter()
    users, ips, reasons, countries, apps = Counter(), Counter(), Counter(), Counter(), Counter()
    user_detail: dict[str, dict] = {}
    ip_users: dict[str, set] = defaultdict(set)
    ip_country: dict[str, str] = {}
    legacy = foreign = risky = 0
    for e in events:
        st = e.get("status") or {}
        code = st.get("errorCode") or 0
        if code in INTERRUPT_CODES:
            interrupts += 1
            continue
        genuine.append(e)
        t = _dt(e.get("createdDateTime"))
        if t:
            by_hour[t.astimezone(DUBAI).strftime("%Y-%m-%d %H:00")] += 1
        upn = e.get("userPrincipalName") or "(unknown)"
        country = ((e.get("location") or {}).get("countryOrRegion") or "").upper()
        users[upn] += 1
        ips[e.get("ipAddress") or "?"] += 1
        ip_users[e.get("ipAddress") or "?"].add(upn)
        ip_country[e.get("ipAddress") or "?"] = country
        reasons[f"{code} — {st.get('failureReason') or 'Unknown'}"] += 1
        countries[country or "??"] += 1
        apps[e.get("appDisplayName") or "?"] += 1
        if e.get("clientAppUsed") in LEGACY_CLIENTS:
            legacy += 1
        if country and country != home:
            foreign += 1
        if (e.get("riskLevelDuringSignIn") or "none") in ("medium", "high"):
            risky += 1
        d = user_detail.setdefault(upn, {"upn": upn, "name": e.get("userDisplayName"), "count": 0,
                                         "last": None, "reasons": Counter(), "countries": set(), "ips": set()})
        d["count"] += 1
        d["last"] = max(filter(None, [d["last"], e.get("createdDateTime")]), default=None)
        d["reasons"][st.get("failureReason") or str(code)] += 1
        if country:
            d["countries"].add(country)
        d["ips"].add(e.get("ipAddress"))

    # Hour buckets for the whole window, oldest first (zero-filled)
    start = since.astimezone(DUBAI).replace(minute=0, second=0, microsecond=0)
    hours_axis = [(start + timedelta(hours=i)).strftime("%Y-%m-%d %H:00") for i in range(hours + 1)]
    top_users = []
    for upn, _ in users.most_common(50):
        d = user_detail[upn]
        top_users.append({"upn": upn, "name": d["name"], "count": d["count"], "last": d["last"],
                          "top_reason": d["reasons"].most_common(1)[0][0] if d["reasons"] else "",
                          "countries": sorted(d["countries"]), "ips": len(d["ips"])})
    recent = sorted(genuine, key=lambda e: e.get("createdDateTime") or "", reverse=True)[:500]
    return {
        "summary": {
            "window_hours": hours, "events": len(events), "failures": len(genuine), "interrupts": interrupts,
            "users_affected": len(users), "ips": len(ips), "legacy_auth": legacy, "foreign": foreign,
            "risky": risky, "home_country": home, "truncated": len(events) >= 20000,
            "top_user_failures": users.most_common(1)[0][1] if users else 0,
        },
        "by_hour": [{"hour": h, "count": by_hour.get(h, 0)} for h in hours_axis],
        "top_users": top_users,
        "top_ips": [{"ip": ip, "count": c, "users": len(ip_users[ip]), "country": ip_country.get(ip)}
                    for ip, c in ips.most_common(30)],
        "reasons": _top(reasons, 15),
        "countries": _top(countries, 20),
        "apps": _top(apps, 15),
        "recent": [{
            "time": e.get("createdDateTime"), "upn": e.get("userPrincipalName"), "app": e.get("appDisplayName"),
            "ip": e.get("ipAddress"), "client": e.get("clientAppUsed"),
            "country": (e.get("location") or {}).get("countryOrRegion"),
            "city": (e.get("location") or {}).get("city"),
            "code": (e.get("status") or {}).get("errorCode"),
            "reason": (e.get("status") or {}).get("failureReason"),
            "risk": e.get("riskLevelDuringSignIn"), "ca": e.get("conditionalAccessStatus"),
        } for e in recent],
    }


_IMPORTANT_AUDIT = re.compile(
    r"add member to role|remove member from role|add eligible member|add user|delete user|hard delete user|"
    r"restore user|reset password|change user password|disable account|enable account|consent to application|"
    r"add service principal credentials|certificates and secrets|add owner to (?:application|service principal)|"
    r"add app role assignment|add delegated permission grant|conditional access|add policy|update policy|"
    r"delete policy|set federation|add domain|verify domain|update company|set directory feature",
    re.I,
)


async def c_audit(ctx: dict) -> dict:
    s = ctx["settings"]
    days = s["audit_lookback_days"]
    since = _now() - timedelta(days=days)
    events = await g.get_all("/auditLogs/directoryAudits",
                             {"$filter": f"activityDateTime ge {_iso(since)}", "$top": "999"}, max_items=25000)

    def initiator(e: dict) -> str:
        ib = e.get("initiatedBy") or {}
        u, a = ib.get("user") or {}, ib.get("app") or {}
        return u.get("userPrincipalName") or u.get("displayName") or a.get("displayName") or "System"

    def targets(e: dict) -> str:
        return ", ".join(filter(None, ((t.get("userPrincipalName") or t.get("displayName"))
                                       for t in e.get("targetResources") or [])))[:300]

    def slim(e: dict) -> dict:
        return {"time": e.get("activityDateTime"), "category": e.get("category"),
                "activity": e.get("activityDisplayName"), "result": e.get("result"),
                "by": initiator(e), "target": targets(e), "service": e.get("loggedByService")}

    by_day = Counter()
    for e in events:
        t = _dt(e.get("activityDateTime"))
        if t:
            by_day[t.astimezone(DUBAI).strftime("%Y-%m-%d")] += 1
    day_axis = [(since.astimezone(DUBAI) + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days + 1)]
    important = [e for e in events if _IMPORTANT_AUDIT.search(e.get("activityDisplayName") or "")
                 or e.get("category") == "RoleManagement"]
    role_changes = [e for e in events if e.get("category") == "RoleManagement"
                    and re.search(r"member", e.get("activityDisplayName") or "", re.I)]
    events_sorted = sorted(events, key=lambda e: e.get("activityDateTime") or "", reverse=True)
    return {
        "summary": {
            "window_days": days, "events": len(events), "important": len(important),
            "role_changes": len(role_changes), "failed": sum(1 for e in events if e.get("result") != "success"),
            "initiators": len({initiator(e) for e in events}), "truncated": len(events) >= 25000,
        },
        "by_day": [{"day": d, "count": by_day.get(d, 0)} for d in day_axis],
        "top_activities": _top(Counter(e.get("activityDisplayName") for e in events), 12),
        "top_initiators": _top(Counter(initiator(e) for e in events), 12),
        "categories": _top(Counter(e.get("category") for e in events), 12),
        "important": [slim(e) for e in sorted(important, key=lambda e: e.get("activityDateTime") or "", reverse=True)][:500],
        "role_changes": [slim(e) for e in sorted(role_changes, key=lambda e: e.get("activityDateTime") or "", reverse=True)][:200],
        "recent": [slim(e) for e in events_sorted[:1000]],
    }


SKU_NAMES = {
    "STANDARDPACK": "Office 365 E1", "ENTERPRISEPACK": "Office 365 E3", "ENTERPRISEPREMIUM": "Office 365 E5",
    "SPE_E3": "Microsoft 365 E3", "SPE_E5": "Microsoft 365 E5", "SPE_F1": "Microsoft 365 F3",
    "SPB": "Microsoft 365 Business Premium", "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
    "O365_BUSINESS_ESSENTIALS": "Microsoft 365 Business Basic", "EXCHANGESTANDARD": "Exchange Online (Plan 1)",
    "EXCHANGEENTERPRISE": "Exchange Online (Plan 2)", "ATP_ENTERPRISE": "Defender for Office 365 (Plan 1)",
    "THREAT_INTELLIGENCE": "Defender for Office 365 (Plan 2)", "EMS": "Enterprise Mobility + Security E3",
    "EMSPREMIUM": "Enterprise Mobility + Security E5", "AAD_PREMIUM": "Entra ID P1", "AAD_PREMIUM_P2": "Entra ID P2",
    "Microsoft_365_Copilot": "Microsoft 365 Copilot", "PROJECTPROFESSIONAL": "Project Plan 3",
    "PROJECTPREMIUM": "Project Plan 5", "VISIOONLINE_PLAN1": "Visio Plan 1", "VISIOCLIENT": "Visio Plan 2",
    "POWER_BI_PRO": "Power BI Pro", "POWER_BI_STANDARD": "Power BI (free)", "PBI_PREMIUM_PER_USER": "Power BI Premium Per User",
    "FLOW_FREE": "Power Automate Free", "POWERAUTOMATE_ATTENDED_RPA": "Power Automate Premium",
    "POWERAPPS_DEV": "Power Apps Developer", "POWERAPPS_VIRAL": "Power Apps Trial", "STREAM": "Microsoft Stream",
    "Teams_Premium_(for_Departments)": "Teams Premium", "MCOEV": "Teams Phone", "MCOMEETADV": "Audio Conferencing",
    "DYN365_FINANCE": "Dynamics 365 Finance", "DYN365_TEAM_MEMBERS": "Dynamics 365 Team Members",
    "DYN365_SCM_ATTACH": "Dynamics 365 SCM Attach", "DYN365_AI_SERVICE_INSIGHTS": "D365 Customer Service Insights",
    "CCIBOTS_PRIVPREV_VIRAL": "Copilot Studio Trial", "WINDOWS_STORE": "Windows Store for Business",
    "WIN_DEF_ATP": "Defender for Endpoint P2", "INTUNE_A": "Intune Plan 1", "Microsoft_Teams_Rooms_Pro": "Teams Rooms Pro",
}
_FREE_SKU = re.compile(r"FREE|VIRAL|TRIAL|DEV|STREAM|WINDOWS_STORE|POWER_BI_STANDARD|INSIGHTS|PRIVPREV", re.I)


async def _sku_names() -> dict[str, tuple[str, bool]]:
    """skuId -> (friendly name e.g. 'Office 365 E3', is_free)."""
    try:
        skus = (await g.get("/subscribedSkus"))["value"]
    except Exception as e:  # licence names are a nice-to-have; never fail the accounts collector
        log.warning("subscribedSkus lookup failed: %s", e)
        return {}
    out = {}
    for k in skus:
        part = k.get("skuPartNumber") or ""
        enabled = (k.get("prepaidUnits") or {}).get("enabled") or 0
        out[k.get("skuId")] = (SKU_NAMES.get(part, part.replace("_", " ").title()), bool(_FREE_SKU.search(part)) or enabled >= 10000)
    return out


async def c_licences(ctx: dict) -> dict:
    s = ctx["settings"]
    skus = (await g.get("/subscribedSkus"))["value"]
    users = ctx.get("users") or {}
    disabled_by_sku = Counter(sku for u in users.values() if not u["enabled"] for sku in u["licences"])
    rows = []
    for k in skus:
        pu = k.get("prepaidUnits") or {}
        enabled, consumed = pu.get("enabled") or 0, k.get("consumedUnits") or 0
        part = k.get("skuPartNumber") or ""
        free = bool(_FREE_SKU.search(part)) or enabled >= 10000
        rows.append({
            "sku_id": k.get("skuId"), "part": part,
            "name": SKU_NAMES.get(part, part.replace("_", " ").title()),
            "enabled": enabled, "consumed": consumed, "available": enabled - consumed,
            "warning": pu.get("warning") or 0, "suspended": pu.get("suspended") or 0,
            "pct": round(100 * consumed / enabled, 1) if enabled else None,
            "status": k.get("capabilityStatus"), "free": free,
            "disabled_users": disabled_by_sku.get(k.get("skuId"), 0),
        })
    paid = [r for r in rows if not r["free"] and r["enabled"] > 0]
    return {
        "summary": {
            "skus": len(rows), "paid_skus": len(paid),
            "paid_enabled": sum(r["enabled"] for r in paid), "paid_consumed": sum(r["consumed"] for r in paid),
            "paid_unused": sum(max(0, r["available"]) for r in paid),
            "near_capacity": sum(1 for r in paid if (r["pct"] or 0) >= s["licence_warn_pct"]),
            "over_assigned": sum(1 for r in paid if r["available"] < 0),
            "on_disabled_users": sum(r["disabled_users"] for r in paid),
            "in_grace": sum(1 for r in rows if r["warning"] or r["suspended"]),
        },
        "skus": sorted(rows, key=lambda r: (r["free"], -(r["consumed"] or 0))),
    }


def _os_family(os_name: str) -> str:
    o = (os_name or "").lower()
    if o.startswith("windows"):
        return "Windows"
    if o in ("ios", "ipados") or "iphone" in o or "ipad" in o:
        return "iOS / iPadOS"
    if "android" in o:
        return "Android"
    if "mac" in o:
        return "macOS"
    if "linux" in o:
        return "Linux"
    return os_name or "Unknown"


async def c_devices(ctx: dict) -> dict:
    s = ctx["settings"]
    devices = await g.get_all("/devices", {
        "$select": "id,displayName,operatingSystem,operatingSystemVersion,approximateLastSignInDateTime,"
                   "accountEnabled,trustType,isManaged,isCompliant,registrationDateTime,manufacturer,model,profileType",
        "$expand": "registeredOwners($select=userPrincipalName,displayName)",
        "$top": "100",
    })
    trust_names = {"AzureAd": "Entra joined", "ServerAd": "Hybrid joined", "Workplace": "Registered"}
    rows = []
    for d in devices:
        rows.append({
            "name": d.get("displayName"), "os": _os_family(d.get("operatingSystem")),
            "version": d.get("operatingSystemVersion"), "trust": trust_names.get(d.get("trustType"), d.get("trustType") or "Unknown"),
            "enabled": d.get("accountEnabled"), "managed": d.get("isManaged"), "compliant": d.get("isCompliant"),
            "last_signin": d.get("approximateLastSignInDateTime"),
            "inactive_days": _days_since(d.get("approximateLastSignInDateTime")),
            "registered": d.get("registrationDateTime"),
            "owner": ", ".join(o.get("userPrincipalName") or o.get("displayName") or "" for o in d.get("registeredOwners") or []) or None,
            "owner_name": ", ".join(o.get("displayName") or "" for o in d.get("registeredOwners") or []) or None,
            "manufacturer": d.get("manufacturer"), "model": d.get("model"),
        })
    sd = s["stale_days"]
    stale = [r for r in rows if r["enabled"] and (r["inactive_days"] is None or r["inactive_days"] > sd)]
    win_versions = Counter(r["version"] for r in rows if r["os"] == "Windows" and r["version"])
    return {
        "summary": {
            "total": len(rows), "enabled": sum(1 for r in rows if r["enabled"]),
            "stale": len(stale), "managed": sum(1 for r in rows if r["managed"]),
            "compliant": sum(1 for r in rows if r["compliant"] is True),
            "non_compliant": sum(1 for r in rows if r["compliant"] is False),
            "hybrid_joined": sum(1 for r in rows if r["trust"] == "Hybrid joined"),
            "stale_days": sd,
        },
        "by_os": _top(Counter(r["os"] for r in rows), 10),
        "by_trust": _top(Counter(r["trust"] for r in rows), 6),
        "windows_versions": _top(win_versions, 12),
        "stale": sorted(stale, key=lambda r: -(r["inactive_days"] or 99999))[:3000],
        "non_compliant": [r for r in rows if r["compliant"] is False][:3000],
    }


async def c_groups(ctx: dict) -> dict:
    groups = await g.get_all("/groups", {
        "$select": "id,displayName,groupTypes,securityEnabled,mailEnabled,createdDateTime,onPremisesSyncEnabled,"
                   "membershipRule,visibility,mail",
        "$expand": "owners($select=id)",
    })

    def kind(gr: dict) -> str:
        t = gr.get("groupTypes") or []
        if "Unified" in t:
            return "Microsoft 365"
        if gr.get("securityEnabled") and gr.get("mailEnabled"):
            return "Mail-enabled security"
        if gr.get("securityEnabled"):
            return "Security"
        return "Distribution"

    rows = [{
        "name": gr.get("displayName"), "kind": kind(gr), "dynamic": "DynamicMembership" in (gr.get("groupTypes") or []),
        "synced": bool(gr.get("onPremisesSyncEnabled")), "owners": len(gr.get("owners") or []),
        "created": gr.get("createdDateTime"), "visibility": gr.get("visibility"), "mail": gr.get("mail"),
    } for gr in groups]
    ownerless = [r for r in rows if not r["synced"] and r["owners"] == 0]
    return {
        "summary": {
            "total": len(rows), "synced": sum(1 for r in rows if r["synced"]),
            "cloud": sum(1 for r in rows if not r["synced"]), "dynamic": sum(1 for r in rows if r["dynamic"]),
            "m365": sum(1 for r in rows if r["kind"] == "Microsoft 365"),
            "ownerless": len(ownerless),
            "public_m365": sum(1 for r in rows if r["kind"] == "Microsoft 365" and r["visibility"] == "Public"),
        },
        "by_kind": _top(Counter(r["kind"] for r in rows), 6),
        "ownerless": sorted(ownerless, key=lambda r: r["name"] or "")[:2000],
    }


async def c_usage(ctx: dict) -> dict:
    apps = await g.get("/reports/getM365AppUserCounts(period='D30')", {"$format": "application/json"}, beta=True)
    teams = await g.get("/reports/getTeamsUserActivityCounts(period='D30')", {"$format": "application/json"}, beta=True)
    app_rows = sorted(((apps.get("value") or [{}])[0].get("userCounts") or []), key=lambda r: r.get("reportDate") or "")
    team_rows = sorted(teams.get("value") or [], key=lambda r: r.get("reportDate") or "")
    latest = app_rows[-1] if app_rows else {}
    return {
        "summary": {
            "report_date": latest.get("reportDate"),
            "teams_dau": latest.get("teams"), "outlook_dau": latest.get("outlook"),
            "excel_dau": latest.get("excel"), "word_dau": latest.get("word"),
            "chat_messages_30d": sum(r.get("privateChatMessages") or 0 for r in team_rows),
            "meetings_30d": sum(r.get("meetings") or 0 for r in team_rows),
            "calls_30d": sum(r.get("calls") or 0 for r in team_rows),
        },
        "apps": [{"date": r.get("reportDate"), "outlook": r.get("outlook"), "teams": r.get("teams"),
                  "excel": r.get("excel"), "word": r.get("word"), "powerpoint": r.get("powerPoint"),
                  "onenote": r.get("oneNote")} for r in app_rows],
        "teams": [{"date": r.get("reportDate"), "chats": r.get("privateChatMessages"), "calls": r.get("calls"),
                   "meetings": r.get("meetings")} for r in team_rows],
    }


# Order matters: accounts first (others join on its user map)
COLLECTORS: list[tuple[str, Callable]] = [
    ("tenant", c_tenant), ("accounts", c_accounts), ("mfa", c_mfa), ("privileged", c_privileged),
    ("secrets", c_secrets), ("signins", c_signins), ("audit", c_audit), ("licences", c_licences),
    ("devices", c_devices), ("groups", c_groups), ("usage", c_usage),
]
# Security collectors (Defender, Secure Score, Identity Protection, Intune, service health) share the run
from app.services import security_service as _sec   # noqa: E402
COLLECTORS += _sec.COLLECTORS
SECTIONS = [n for n, _ in COLLECTORS]


async def _save(section: str, data: Optional[dict], ok: bool, error: Optional[str], ms: int) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO cloudpulse_ad_snapshots (section, data, ok, error, duration_ms, collected_at, attempted_at)
            VALUES (:s, CAST(:d AS JSONB), :ok, :err, :ms, CASE WHEN :ok THEN NOW() END, NOW())
            ON CONFLICT (section) DO UPDATE SET
                data         = COALESCE(EXCLUDED.data, cloudpulse_ad_snapshots.data),
                ok           = EXCLUDED.ok,
                error        = EXCLUDED.error,
                duration_ms  = EXCLUDED.duration_ms,
                collected_at = COALESCE(EXCLUDED.collected_at, cloudpulse_ad_snapshots.collected_at),
                attempted_at = NOW()
        """), {"s": section, "d": json.dumps(data, default=str) if data is not None else None,
               "ok": ok, "err": error, "ms": ms})
        await db.commit()


async def collect_all() -> int:
    """Collect every section. Returns the number of sections collected successfully."""
    ctx: dict[str, Any] = {"settings": await _settings()}
    done = 0
    t_all = time.monotonic()
    for name, fn in COLLECTORS:
        t0 = time.monotonic()
        try:
            data = await fn(ctx)
            await _save(name, data, True, None, int((time.monotonic() - t0) * 1000))
            done += 1
        except Exception as exc:
            log.warning("AD collector %s failed: %s", name, exc)
            await _save(name, None, False, str(exc)[:500], int((time.monotonic() - t0) * 1000))
    await _record_kpis()
    log.info("AD health collection: %d/%d sections in %.1fs", done, len(COLLECTORS), time.monotonic() - t_all)
    return done


# ─────────────────────────────────────────────────────────────────────────────
# Reading: snapshots, KPIs, findings
# ─────────────────────────────────────────────────────────────────────────────

async def load_snapshots(with_data: bool = True) -> dict[str, dict]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text(f"""
            SELECT section, {'data' if with_data else "data->'summary' AS data"}, ok, error, duration_ms,
                   collected_at, attempted_at
            FROM cloudpulse_ad_snapshots
        """))).fetchall()
    out = {}
    for r in rows:
        d = r.data
        if isinstance(d, str):
            d = json.loads(d)
        out[r.section] = {"data": d, "ok": r.ok, "error": r.error, "duration_ms": r.duration_ms,
                          "collected_at": r.collected_at, "attempted_at": r.attempted_at}
    return out


async def load_section(section: str) -> Optional[dict]:
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text("""
            SELECT data, ok, error, collected_at, attempted_at FROM cloudpulse_ad_snapshots WHERE section = :s
        """), {"s": section})).fetchone()
    if not row:
        return None
    d = json.loads(row.data) if isinstance(row.data, str) else row.data
    return {"data": d, "ok": row.ok, "error": row.error, "collected_at": row.collected_at,
            "attempted_at": row.attempted_at}


def _kpis_from(summaries: dict) -> dict[str, float]:
    def v(section: str, key: str):
        return (summaries.get(section) or {}).get(key)
    k = {
        "mfa_pct": v("mfa", "mfa_pct"), "users_without_mfa": (v("mfa", "users") or 0) - (v("mfa", "mfa_registered") or 0)
            if v("mfa", "users") is not None else None,
        "stale_accounts": v("accounts", "stale"), "enabled_users": v("accounts", "enabled"),
        "guests": v("accounts", "guests"), "failed_signins": v("signins", "failures"),
        "global_admins": v("privileged", "global_admins"),
        "privileged_principals": v("privileged", "privileged_principals"),
        "secrets_attention": None if v("secrets", "critical") is None else
            (v("secrets", "critical") or 0) + (v("secrets", "warning") or 0) + (v("secrets", "expired_unreplaced") or 0),
        "unused_licences": v("licences", "paid_unused"), "stale_devices": v("devices", "stale"),
        "ownerless_groups": v("groups", "ownerless"), "audit_events": v("audit", "events"),
        "sync_age_hours": v("tenant", "sync_age_hours"),
        "secure_score_pct": v("sec_score", "pct"), "incidents_open": v("sec_threats", "incidents_open"),
        "alerts_open": v("sec_threats", "alerts_open"), "risky_users": v("sec_risk", "at_risk"),
        "devices_critical_cves": v("sec_devices", "with_critical"), "devices_exploitable": v("sec_devices", "with_exploitable"),
        "servers_behind_2m": v("sec_devices", "servers_behind_2m"), "av_sig_outdated": v("sec_devices", "av_sig_outdated"),
        "intune_compliance_pct": v("sec_intune", "compliance_pct"),
    }
    return {a: float(b) for a, b in k.items() if b is not None}


async def _record_kpis() -> None:
    snaps = await load_snapshots(with_data=False)
    kpis = _kpis_from({s: (x["data"] or {}) for s, x in snaps.items()})
    today = datetime.now(DUBAI).date()
    async with AsyncSessionLocal() as db:
        for k, val in kpis.items():
            await db.execute(text("""
                INSERT INTO cloudpulse_ad_kpi_daily (day, kpi, value) VALUES (:d, :k, :v)
                ON CONFLICT (day, kpi) DO UPDATE SET value = EXCLUDED.value
            """), {"d": today, "k": k, "v": val})
        await db.commit()


async def kpi_trends(days: int = 30) -> dict[str, list[dict]]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT day, kpi, value FROM cloudpulse_ad_kpi_daily
            WHERE day >= CURRENT_DATE - CAST(:n AS INTEGER) ORDER BY day
        """), {"n": days})).fetchall()
    out: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        out[r.kpi].append({"day": r.day.isoformat(), "value": float(r.value)})
    return out


def _finding(sev: str, section: str, title: str, detail: str, count: Optional[int] = None,
             ticket: Optional[str] = None) -> dict:
    return {"severity": sev, "section": section, "title": title, "detail": detail, "count": count,
            "ticket": ticket or f"{title}. {detail}"}


async def findings(snaps: dict[str, dict]) -> list[dict]:
    """Evaluate snapshots against the ad.* thresholds. Severity: critical > warning > info."""
    s = await _settings()
    d = {k: (v.get("data") or {}) for k, v in snaps.items()}
    sm = {k: (v.get("summary") or {}) for k, v in d.items()}
    out: list[dict] = []

    t = sm.get("tenant", {})
    if t.get("sync_enabled"):
        age = t.get("sync_age_hours")
        if age is None or age > 24:
            out.append(_finding("critical", "tenant", "Entra Connect sync has stopped",
                                f"Last directory sync was {age:.1f} h ago." if age else "No sync time reported."))
        elif age > s["sync_stale_hours"]:
            out.append(_finding("warning", "tenant", "Entra Connect sync is delayed",
                                f"Last directory sync was {age:.1f} h ago (threshold {s['sync_stale_hours']:g} h)."))
    dcs = d.get("tenant", {}).get("dcs", [])
    hot = [x for x in dcs if x["severity"] in ("warning", "critical")]
    if hot:
        out.append(_finding("critical" if any(x["severity"] == "critical" for x in hot) else "warning", "tenant",
                            f"{len(hot)} domain controller(s) above capacity thresholds",
                            "; ".join(f"{x['name'].split('.')[0]} (CPU {x['cpu'] or 0:.0f}%, mem {x['mem'] or 0:.0f}%, disk {x['disk'] or 0:.0f}%)"
                                      for x in hot[:6]), len(hot)))
    silent = [x["name"] for x in dcs if not x["has_data"]]
    if silent:
        out.append(_finding("warning", "tenant", f"No metrics from {len(silent)} domain controller(s)",
                            f"{', '.join(silent[:6])} — CloudPulse has no live data; check the Elastic agent.", len(silent)))

    sec = d.get("secrets", {})
    own = sm.get("secrets", {}).get("this_app_days_left")
    if own is not None and own <= s["secret_warn_days"]:
        out.append(_finding("critical" if own <= s["secret_crit_days"] else "warning", "secrets",
                            "CloudPulse's own Entra app secret is expiring",
                            f"Expires in {own:.0f} days — SSO, Teams polling and this AD console stop when it lapses."))
    others = [r for r in sec.get("attention", []) if not r["this_app"]]
    def _apps(rows: list[dict]) -> str:
        return ", ".join(f"{r['app']} ({r['days_left']:.0f}d)" for r in rows[:5]) + (" …" if len(rows) > 5 else "")
    for status, sev, title in (("critical", "critical", "App credentials expiring within {n} days"),
                               ("expired", "critical", "Expired app credentials with no replacement"),
                               ("warning", "warning", "App credentials expiring within {n} days")):
        rows = [r for r in others if r["status"] == status]
        if rows:
            n = s["secret_crit_days"] if status == "critical" else s["secret_warn_days"]
            out.append(_finding(sev, "secrets", title.format(n=n), f"{len(rows)} credential(s): {_apps(rows)}", len(rows)))

    p = sm.get("privileged", {})
    if p:
        ga = p.get("global_admins", 0)
        if ga > s["max_global_admins"]:
            out.append(_finding("warning", "privileged", "Too many Global Administrators",
                                f"{ga} accounts hold Global Administrator (target ≤ {s['max_global_admins']}).", ga))
        elif ga < 2:
            out.append(_finding("warning", "privileged", "Fewer than two Global Administrators",
                                "Keep at least two (including a break-glass account) to avoid lock-out.", ga))
        if p.get("disabled_with_roles"):
            out.append(_finding("info", "privileged", "Disabled accounts still hold admin roles",
                                f"{p['disabled_with_roles']} role assignment(s) on disabled accounts.", p["disabled_with_roles"]))
        if p.get("stale_privileged"):
            out.append(_finding("warning", "privileged", "Inactive privileged accounts",
                                f"{p['stale_privileged']} privileged assignment(s) on accounts with no sign-in for "
                                f"{s['stale_days']}+ days.", p["stale_privileged"]))

    m = sm.get("mfa", {})
    if m:
        if m.get("admins_without_mfa"):
            out.append(_finding("critical", "mfa", "Administrators without MFA",
                                f"{m['admins_without_mfa']} admin account(s) have no MFA method registered.",
                                m["admins_without_mfa"]))
        how = "have per-user MFA enabled or enforced" if m.get("method") == "per_user" else "have an MFA method registered"
        if (m.get("mfa_pct") or 0) < s["mfa_target_pct"]:
            out.append(_finding("warning", "mfa", "MFA coverage below target",
                                f"{m['mfa_pct']}% of enabled mailbox users {how} (target {s['mfa_target_pct']:g}%) — "
                                f"{m['users'] - m['mfa_registered']} users without MFA.", m["users"] - m["mfa_registered"]))
        if m.get("requirement_known") and m.get("unprotected"):
            out.append(_finding("critical" if m["unprotected"] > 20 else "warning", "mfa", "Users not required to use MFA and not registered",
                                f"{m['unprotected']} enabled mailbox user(s) have no MFA method and no policy forces MFA — they can sign in with a password only.",
                                m["unprotected"]))
        if m.get("pending_registration"):
            out.append(_finding("warning", "mfa", "MFA enabled but not enrolled",
                                f"{m['pending_registration']} user(s) have MFA enabled but no method enrolled — they will be asked to register at next sign-in"
                                + (f" ({m['pending_inactive_90d']} haven't signed in for 90+ days)" if m.get("pending_inactive_90d") else "") + ".",
                                m["pending_registration"]))
        if m.get("enforced_not_registered"):
            out.append(_finding("info", "mfa", "MFA enforced but not yet registered",
                                f"{m['enforced_not_registered']} user(s) are Enforced but have no method registered — "
                                "they will be forced to register at next sign-in.", m["enforced_not_registered"]))
        if m.get("per_user_available") is False:
            out.append(_finding("info", "mfa", "Per-user MFA state not readable",
                                f"Grant the app {PER_USER_MFA_PERMISSION} to report on Disabled / Enabled / Enforced state."))

    a = sm.get("accounts", {})
    if a:
        if a.get("stale"):
            out.append(_finding("warning" if a["stale"] > 50 else "info", "accounts", "Stale enabled accounts",
                                f"{a['stale']} enabled account(s) with no sign-in for {a['stale_days']}+ days.", a["stale"]))
        if a.get("disabled_licensed"):
            out.append(_finding("warning", "accounts", "Licences assigned to disabled accounts",
                                f"{a['disabled_licensed']} disabled account(s) still hold licences.", a["disabled_licensed"]))
        if a.get("never_signed_in"):
            out.append(_finding("info", "accounts", "Accounts that never signed in",
                                f"{a['never_signed_in']} enabled account(s) have never signed in.", a["never_signed_in"]))

    si = sm.get("signins", {})
    if si:
        if si.get("failures", 0) > s["failed_signin_warn"]:
            out.append(_finding("warning", "signins", "High volume of failed sign-ins",
                                f"{si['failures']} genuine failures in {si['window_hours']} h "
                                f"(threshold {s['failed_signin_warn']}).", si["failures"]))
        hot = [u for u in d.get("signins", {}).get("top_users", []) if u["count"] >= s["user_failure_threshold"]]
        if hot:
            out.append(_finding("warning", "signins", "Accounts with repeated sign-in failures",
                                f"{len(hot)} account(s) failed ≥ {s['user_failure_threshold']} times — top: "
                                f"{hot[0]['upn']} ({hot[0]['count']}, {hot[0]['top_reason']}). Possible lock-out or password spray.",
                                len(hot)))
        if si.get("risky"):
            out.append(_finding("warning", "signins", "Risky sign-in attempts",
                                f"{si['risky']} failed sign-in(s) flagged medium/high risk.", si["risky"]))
        if si.get("legacy_auth"):
            out.append(_finding("info", "signins", "Legacy authentication attempts",
                                f"{si['legacy_auth']} failed attempts used legacy protocols (IMAP/POP/SMTP/EAS…).",
                                si["legacy_auth"]))
        if si.get("foreign"):
            out.append(_finding("info", "signins", "Failed sign-ins from outside home country",
                                f"{si['foreign']} failures originated outside {si['home_country']}.", si["foreign"]))

    au = sm.get("audit", {})
    if au.get("role_changes"):
        out.append(_finding("info", "audit", "Directory role membership changed",
                            f"{au['role_changes']} role membership change(s) in the last {au['window_days']} days.",
                            au["role_changes"]))

    for r in d.get("licences", {}).get("skus", []):
        if r["free"] or not r["enabled"]:
            continue
        if r["available"] < 0:
            out.append(_finding("warning", "licences", f"Over-assigned licence: {r['name']}",
                                f"{r['consumed']} assigned of {r['enabled']} purchased."))
        elif (r["pct"] or 0) >= s["licence_warn_pct"]:
            out.append(_finding("info", "licences", f"Licence nearly exhausted: {r['name']}",
                                f"{r['consumed']} of {r['enabled']} assigned ({r['pct']}%) — {r['available']} left."))
        if r["warning"] or r["suspended"]:
            out.append(_finding("warning", "licences", f"Subscription in grace / suspended: {r['name']}",
                                f"{r['warning']} units in warning, {r['suspended']} suspended."))

    dv, gr = sm.get("devices", {}), sm.get("groups", {})
    if dv.get("stale"):
        out.append(_finding("info", "devices", "Stale devices",
                            f"{dv['stale']} enabled device(s) inactive for {dv['stale_days']}+ days.", dv["stale"]))
    if dv.get("non_compliant"):
        out.append(_finding("info", "devices", "Non-compliant devices",
                            f"{dv['non_compliant']} device(s) reported non-compliant.", dv["non_compliant"]))
    if gr.get("ownerless"):
        out.append(_finding("info", "devices", "Cloud groups without owners",
                            f"{gr['ownerless']} cloud group(s) have no owner.", gr["ownerless"]))

    order = {"critical": 0, "warning": 1, "info": 2}
    return sorted(out, key=lambda f: order.get(f["severity"], 3))


def health_score(items: list[dict]) -> int:
    """100 minus weighted findings, each section capped so one noisy area can't zero the score."""
    w = {"critical": 10, "warning": 4, "info": 1}
    per_section: dict[str, int] = defaultdict(int)
    for f in items:
        per_section[f["section"]] += w.get(f["severity"], 0)
    return max(0, 100 - sum(min(15, v) for v in per_section.values()))


async def is_running() -> bool:
    async with AsyncSessionLocal() as db:
        return bool((await db.execute(text("""
            SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = 0
                           AND objid = :k AND granted)
        """), {"k": AD_LOCK_ID})).scalar())


async def last_run() -> Optional[datetime]:
    async with AsyncSessionLocal() as db:
        return (await db.execute(text("SELECT last_run FROM cloudpulse_teams_jobs WHERE job = 'ad_collect'"))).scalar()


# ─────────────────────────────────────────────────────────────────────────────
# Scheduling
# ─────────────────────────────────────────────────────────────────────────────

async def run_now() -> Optional[int]:
    return await tas._run_locked(AD_LOCK_ID, "ad_collect", collect_all)


async def scheduled_tick() -> None:
    if not await cfg.get_bool("ad.enabled", True):
        return
    every = max(15, await cfg.get_int("ad.refresh_minutes", 60)) * 60
    await tas._run_locked(AD_LOCK_ID, "ad_collect", collect_all, every_seconds=every - 5)
