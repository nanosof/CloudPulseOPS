"""
Security collectors (Microsoft Graph, read-only Application permissions):

  sec_score     Secure Score trend + improvement actions        SecurityEvents.Read.All
  sec_threats   Defender XDR incidents and alerts (30 days)     SecurityIncident/SecurityAlert.Read.All
  sec_risk      Entra ID Protection risky users + detections    IdentityRiskyUser/IdentityRiskEvent.Read.All
  sec_service   M365 service health + message center           ServiceHealth/ServiceMessage.Read.All
  sec_intune    Intune managed devices + compliance policies    DeviceManagement*.Read.All
  sec_devices   Defender device inventory, vulnerabilities, missing updates, antivirus,
                secure configuration, end-of-support software  ThreatHunting.Read.All (advanced hunting)

Snapshots share infraguardian_ad_snapshots with the identity collectors (same collection run,
lock and schedule). Security findings and the security score are derived on read.
"""
from __future__ import annotations
import asyncio
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.services import graph_service as g
import app.config as cfg

log = logging.getLogger(__name__)
SECTIONS = ["sec_score", "sec_threats", "sec_risk", "sec_service", "sec_intune", "sec_devices"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _dt(v: Optional[str]) -> Optional[datetime]:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _age_days(v: Optional[str]) -> Optional[float]:
    d = _dt(v)
    return round((_now() - d).total_seconds() / 86400, 1) if d else None


def _short(name: str) -> str:
    return (name or "").split(".")[0].lower()


def _strip_html(s: Optional[str], n: int = 600) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()[:n]


# ─────────────────────────────────────────────────────────────────────────────
# Secure Score
# ─────────────────────────────────────────────────────────────────────────────

async def c_score(ctx: dict) -> dict:
    scores = (await g.get("/security/secureScores", {"$top": "90"})).get("value", [])
    profiles = await g.get_all("/security/secureScoreControlProfiles")
    if not scores:
        return {"summary": {"available": False}}
    latest = scores[0]
    prof = {p["id"]: p for p in profiles}
    actions = []
    for cs in latest.get("controlScores", []):
        p = prof.get(cs.get("controlName"), {})
        mx = float(p.get("maxScore") or 0)
        cur = float(cs.get("score") or 0)
        if p.get("deprecated") or mx <= 0:
            continue
        actions.append({
            "id": cs.get("controlName"), "title": p.get("title") or cs.get("controlName"),
            "category": p.get("controlCategory") or cs.get("controlCategory"), "service": p.get("service"),
            "score": round(cur, 2), "max": round(mx, 2), "gain": round(mx - cur, 2),
            "pct": round(100 * cur / mx, 1), "status": "Completed" if cur >= mx else "Partial" if cur > 0 else "To address",
            "cost": p.get("implementationCost"), "user_impact": p.get("userImpact"), "tier": p.get("tier"),
            "rank": p.get("rank"), "remediation": _strip_html(p.get("remediation"), 900), "url": p.get("actionUrl"),
            "description": _strip_html(cs.get("description"), 400),
        })
    cur, mx = float(latest.get("currentScore") or 0), float(latest.get("maxScore") or 0)
    comps = {c.get("basis"): c.get("averageScore") for c in latest.get("averageComparativeScores", [])}
    cats = defaultdict(lambda: {"score": 0.0, "max": 0.0})
    for a in actions:
        cats[a["category"] or "Other"]["score"] += a["score"]
        cats[a["category"] or "Other"]["max"] += a["max"]
    return {
        "summary": {
            "available": True, "current": round(cur, 1), "max": round(mx, 1), "pct": round(100 * cur / mx, 1) if mx else None,
            "all_tenants_avg": comps.get("AllTenants"), "similar_size_avg": comps.get("TotalSeats"),
            "licensed_users": latest.get("licensedUserCount"), "active_users": latest.get("activeUserCount"),
            "as_of": latest.get("createdDateTime"),
            "actions_open": sum(1 for a in actions if a["status"] != "Completed"),
            "points_available": round(sum(a["gain"] for a in actions), 1),
            "change_30d": round(cur - float(scores[min(29, len(scores) - 1)].get("currentScore") or 0), 1),
        },
        "trend": [{"date": s.get("createdDateTime", "")[:10], "score": round(float(s.get("currentScore") or 0), 1),
                   "max": round(float(s.get("maxScore") or 0), 1),
                   "pct": round(100 * float(s.get("currentScore") or 0) / float(s.get("maxScore") or 1), 1)}
                  for s in reversed(scores)],
        "categories": [{"name": k, "score": round(v["score"], 1), "max": round(v["max"], 1),
                        "pct": round(100 * v["score"] / v["max"], 1) if v["max"] else None} for k, v in sorted(cats.items())],
        "actions": sorted(actions, key=lambda a: (a["status"] == "Completed", -a["gain"])),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Defender XDR incidents + alerts
# ─────────────────────────────────────────────────────────────────────────────

def _evidence(alert: dict) -> tuple[list[str], list[str]]:
    devices, users = set(), set()
    for e in alert.get("evidence") or []:
        t = (e.get("@odata.type") or "").lower()
        if "deviceevidence" in t:
            devices.add(e.get("deviceDnsName") or e.get("hostName") or "?")
        elif "userevidence" in t:
            ua = e.get("userAccount") or {}
            users.add(ua.get("userPrincipalName") or ua.get("accountName") or "?")
    return sorted(devices), sorted(users)


async def c_threats(ctx: dict) -> dict:
    since = _iso(_now() - timedelta(days=30))
    # No $top: on these APIs $top caps the result instead of setting the page size
    incidents = await g.get_all("/security/incidents", {"$filter": f"lastUpdateDateTime ge {since}"}, max_items=5000)
    alerts = await g.get_all("/security/alerts_v2", {"$filter": f"lastUpdateDateTime ge {since} and status ne 'resolved'"},
                             max_items=10000)
    alerts_by_incident = defaultdict(list)
    arows = []
    for a in alerts:
        devs, users = _evidence(a)
        row = {"id": a.get("id"), "title": a.get("title"), "severity": a.get("severity"), "status": a.get("status"),
               "source": a.get("serviceSource"), "detection": a.get("detectionSource"), "category": a.get("category"),
               "created": a.get("createdDateTime"), "updated": a.get("lastUpdateDateTime"), "incident": a.get("incidentId"),
               "assigned": a.get("assignedTo"), "classification": a.get("classification"),
               "devices": devs, "users": users, "url": a.get("alertWebUrl"),
               "mitre": ", ".join((a.get("mitreTechniques") or [])[:4])}
        arows.append(row)
        alerts_by_incident[str(a.get("incidentId"))].append(row)
    irows = []
    for i in incidents:
        al = alerts_by_incident.get(str(i.get("id")), [])
        irows.append({"id": i.get("id"), "name": i.get("displayName"), "severity": i.get("severity"), "status": i.get("status"),
                      "created": i.get("createdDateTime"), "updated": i.get("lastUpdateDateTime"),
                      "assigned": i.get("assignedTo"), "classification": i.get("classification"),
                      "determination": i.get("determination"), "url": i.get("incidentWebUrl"),
                      "alerts": len(al), "devices": sorted({d for x in al for d in x["devices"]})[:30],
                      "users": sorted({u for x in al for u in x["users"]})[:30],
                      "tags": (i.get("customTags") or []) + (i.get("systemTags") or [])})
    open_i = [i for i in irows if i["status"] not in ("resolved",)]
    open_a = [a for a in arows if a["status"] not in ("resolved",)]
    sev = lambda rows: Counter(r["severity"] for r in rows)
    order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    return {
        "summary": {
            "incidents_30d": len(irows), "incidents_open": len(open_i),
            "incidents_open_high": sev(open_i).get("high", 0), "incidents_open_medium": sev(open_i).get("medium", 0),
            "incidents_unassigned": sum(1 for i in open_i if not i["assigned"]),
            "alerts_open": len(open_a), "alerts_open_high": sev(open_a).get("high", 0), "alerts_capped": len(arows) >= 10000,
            "incidents_resolved_30d": sum(1 for i in irows if i["status"] == "resolved"),
            "devices_in_alerts": len({d for a in open_a for d in a["devices"]}),
            "users_in_alerts": len({u for a in open_a for u in a["users"]}),
        },
        "incidents": sorted(irows, key=lambda i: (i["status"] == "resolved", order.get(i["severity"], 9), -(_dt(i["updated"]) or _now()).timestamp())),
        "alerts": sorted(arows, key=lambda a: a["updated"] or "", reverse=True)[:5000],
        "by_source": [{"name": k, "count": v} for k, v in Counter(a["source"] for a in open_a).most_common(12)],
        "by_category": [{"name": k, "count": v} for k, v in Counter(a["category"] for a in open_a).most_common(12)],
        "by_day": [{"day": d, "count": c} for d, c in sorted(Counter((a["created"] or "")[:10] for a in arows).items()) if d],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Identity Protection
# ─────────────────────────────────────────────────────────────────────────────

async def c_risk(ctx: dict) -> dict:
    users = await g.get_all("/identityProtection/riskyUsers", {"$top": "500"}, max_items=10000)
    since = _iso(_now() - timedelta(days=30))
    dets = await g.get_all("/identityProtection/riskDetections", {"$filter": f"detectedDateTime ge {since}", "$top": "500"}, max_items=10000)
    active = [u for u in users if u.get("riskState") in ("atRisk", "confirmedCompromised")]
    urows = [{"name": u.get("userDisplayName"), "upn": u.get("userPrincipalName"), "level": u.get("riskLevel"),
              "state": u.get("riskState"), "detail": u.get("riskDetail"), "updated": u.get("riskLastUpdatedDateTime")}
             for u in users]
    drows = [{"type": d.get("riskEventType"), "level": d.get("riskLevel"), "state": d.get("riskState"),
              "upn": d.get("userPrincipalName"), "name": d.get("userDisplayName"), "ip": d.get("ipAddress"),
              "city": (d.get("location") or {}).get("city"), "country": (d.get("location") or {}).get("countryOrRegion"),
              "detected": d.get("detectedDateTime"), "source": d.get("source"), "timing": d.get("detectionTimingType"),
              "activity": d.get("activity")} for d in dets]
    lv = Counter(u.get("riskLevel") for u in active)
    return {
        "summary": {"at_risk": len(active), "high": lv.get("high", 0), "medium": lv.get("medium", 0), "low": lv.get("low", 0),
                    "confirmed_compromised": sum(1 for u in active if u.get("riskState") == "confirmedCompromised"),
                    "detections_30d": len(drows), "detections_high": sum(1 for d in drows if d["level"] == "high"),
                    "users_with_detections": len({d["upn"] for d in drows})},
        "risky_users": sorted([r for r in urows if r["state"] in ("atRisk", "confirmedCompromised")],
                              key=lambda r: ({"high": 0, "medium": 1, "low": 2}.get(r["level"], 9), r["updated"] or "")),
        "history_users": [r for r in urows if r["state"] not in ("atRisk", "confirmedCompromised")][:2000],
        "detections": sorted(drows, key=lambda d: d["detected"] or "", reverse=True),
        "by_type": [{"name": k, "count": v} for k, v in Counter(d["type"] for d in drows).most_common(12)],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Service health + message center
# ─────────────────────────────────────────────────────────────────────────────

async def c_service(ctx: dict) -> dict:
    overview = await g.get_all("/admin/serviceAnnouncement/healthOverviews")
    issues = await g.get_all("/admin/serviceAnnouncement/issues",
                             {"$filter": f"lastModifiedDateTime ge {_iso(_now() - timedelta(days=14))}"}, max_items=2000)
    messages = await g.get_all("/admin/serviceAnnouncement/messages",
                               {"$filter": f"lastModifiedDateTime ge {_iso(_now() - timedelta(days=45))}"}, max_items=2000)
    irows = [{"id": i.get("id"), "title": i.get("title"), "service": i.get("service"), "feature": i.get("feature"),
              "classification": i.get("classification"), "status": i.get("status"), "resolved": i.get("isResolved"),
              "start": i.get("startDateTime"), "updated": i.get("lastModifiedDateTime"),
              "impact": _strip_html(i.get("impactDescription"), 500)} for i in issues]
    mrows = [{"id": m.get("id"), "title": m.get("title"), "category": m.get("category"), "severity": m.get("severity"),
              "major": m.get("isMajorChange"), "act_by": m.get("actionRequiredByDateTime"),
              "services": ", ".join(m.get("services") or []), "updated": m.get("lastModifiedDateTime"),
              "tags": ", ".join(m.get("tags") or [])} for m in messages]
    svc = [{"service": o.get("service"), "status": o.get("status")} for o in overview]
    bad = [s for s in svc if s["status"] not in ("serviceOperational", "serviceRestored", "postIncidentReviewPublished")]
    active = [i for i in irows if not i["resolved"]]
    return {
        "summary": {"services": len(svc), "degraded": len(bad),
                    "active_incidents": sum(1 for i in active if i["classification"] == "incident"),
                    "active_advisories": sum(1 for i in active if i["classification"] == "advisory"),
                    "messages_45d": len(mrows), "major_changes": sum(1 for m in mrows if m["major"]),
                    "action_required": sum(1 for m in mrows if m["act_by"])},
        "services": sorted(svc, key=lambda s: (s["status"] == "serviceOperational", s["service"] or "")),
        "issues": sorted(irows, key=lambda i: (bool(i["resolved"]), i["updated"] or ""), reverse=False),
        "messages": sorted(mrows, key=lambda m: m["updated"] or "", reverse=True),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Intune
# ─────────────────────────────────────────────────────────────────────────────

async def c_intune(ctx: dict) -> dict:
    devices = await g.get_all("/deviceManagement/managedDevices", {
        "$select": "id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,isEncrypted,managedDeviceOwnerType,"
                   "userPrincipalName,model,manufacturer,jailBroken,azureADDeviceId,enrolledDateTime,managementAgent,serialNumber",
        "$top": "999"}, max_items=50000)
    policies = await g.get_all("/deviceManagement/deviceCompliancePolicies", {"$select": "id,displayName,lastModifiedDateTime,version"})
    rows = [{"name": d.get("deviceName"), "os": d.get("operatingSystem"), "version": d.get("osVersion"),
             "compliance": d.get("complianceState"), "encrypted": d.get("isEncrypted"), "owner": d.get("managedDeviceOwnerType"),
             "user": d.get("userPrincipalName"), "model": d.get("model"), "maker": d.get("manufacturer"),
             "jailbroken": d.get("jailBroken"), "last_sync": d.get("lastSyncDateTime"), "sync_age": _age_days(d.get("lastSyncDateTime")),
             "enrolled": d.get("enrolledDateTime"), "agent": d.get("managementAgent"), "serial": d.get("serialNumber")}
            for d in devices]
    comp = Counter(r["compliance"] for r in rows)
    win = [r for r in rows if (r["os"] or "").lower().startswith("windows")]
    return {
        "summary": {"devices": len(rows), "compliant": comp.get("compliant", 0), "noncompliant": comp.get("noncompliant", 0),
                    "in_grace": comp.get("inGracePeriod", 0), "unknown": comp.get("unknown", 0) + comp.get("error", 0) + comp.get("conflict", 0),
                    "compliance_pct": round(100 * comp.get("compliant", 0) / len(rows), 1) if rows else None,
                    "not_encrypted": sum(1 for r in win if r["encrypted"] is False),
                    "stale_30d": sum(1 for r in rows if (r["sync_age"] or 0) > 30),
                    "jailbroken": sum(1 for r in rows if str(r["jailbroken"]).lower() == "true"),
                    "policies": len(policies)},
        "devices": rows,
        "by_os": [{"name": k, "count": v} for k, v in Counter(r["os"] for r in rows).most_common(10)],
        "by_compliance": [{"name": k, "count": v} for k, v in comp.most_common()],
        "policies": [{"name": p.get("displayName"), "type": (p.get("@odata.type") or "").split(".")[-1].replace("CompliancePolicy", ""),
                      "modified": p.get("lastModifiedDateTime"), "version": p.get("version")} for p in policies],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Defender devices via advanced hunting
# ─────────────────────────────────────────────────────────────────────────────

Q_DEVICES = """
DeviceInfo | where Timestamp > ago(7d) and DeviceCategory == "Endpoint"
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OSVersion, OSBuild, DeviceType, SensorHealthState, OnboardingStatus,
          ExposureLevel, MachineGroup, JoinType, LastSeen = Timestamp, PublicIP
"""
Q_DEVICE_VULNS = """
let kb = DeviceTvmSoftwareVulnerabilitiesKB | project CveId, IsExploitAvailable;
DeviceTvmSoftwareVulnerabilities
| join kind=leftouter kb on CveId
| summarize Critical = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"), High = dcountif(CveId, VulnerabilitySeverityLevel == "High"),
            Medium = dcountif(CveId, VulnerabilitySeverityLevel == "Medium"), Total = dcount(CveId),
            Exploitable = dcountif(CveId, IsExploitAvailable == 1),
            MissingUpdates = dcountif(RecommendedSecurityUpdateId, isnotempty(RecommendedSecurityUpdateId)),
            Updates = make_set_if(RecommendedSecurityUpdate, isnotempty(RecommendedSecurityUpdate), 40)
  by DeviceId
"""
Q_UPDATES = """
DeviceTvmSoftwareVulnerabilities | where isnotempty(RecommendedSecurityUpdateId)
| summarize Devices = dcount(DeviceId), Cves = dcount(CveId), Critical = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
            Platforms = make_set(OSPlatform, 6), DeviceNames = make_set(DeviceName, 300)
  by RecommendedSecurityUpdateId, RecommendedSecurityUpdate
| order by Critical desc, Devices desc | take 400
"""
Q_CVES = """
let kb = DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable, PublishedDate, VulnerabilityDescription;
DeviceTvmSoftwareVulnerabilities | where VulnerabilitySeverityLevel in ("Critical", "High")
| summarize Devices = dcount(DeviceId), Software = make_set(SoftwareName, 4), Platforms = make_set(OSPlatform, 5),
            Fix = make_set_if(RecommendedSecurityUpdate, isnotempty(RecommendedSecurityUpdate), 3)
  by CveId, Severity = VulnerabilitySeverityLevel
| join kind=leftouter kb on CveId
| project CveId, Severity, CvssScore, IsExploitAvailable, PublishedDate, Devices, Software, Platforms, Fix,
          Description = substring(VulnerabilityDescription, 0, 280)
| order by IsExploitAvailable desc, CvssScore desc, Devices desc | take 1500
"""
Q_EOS = """
DeviceTvmSoftwareInventory | where isnotempty(EndOfSupportStatus)
| summarize Devices = dcount(DeviceId), Versions = make_set(SoftwareVersion, 8), EndOfSupportDate = max(EndOfSupportDate)
  by SoftwareVendor, SoftwareName, EndOfSupportStatus
| order by Devices desc | take 500
"""
Q_AV = """
DeviceTvmInfoGathering | where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by DeviceId
| extend f = AdditionalFields
| project DeviceId, AvMode = tostring(f.AvMode), AvSigVersion = tostring(f.AvSignatureVersion),
          AvSigTime = tostring(f.AvSignatureUpdateTime), AvSigUpToDate = tostring(f.AvIsSignatureUptoDate),
          AvEngineUpToDate = tostring(f.AvIsEngineUptodate), AvPlatformUpToDate = tostring(f.AvIsPlatformUptodate),
          AvEngine = tostring(f.AvEngineVersion), Cloud = tostring(f.CloudProtectionState), AvScan = tostring(f.AvScanResults)
"""
Q_CONFIG = """
let kb = DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationImpact,
          ConfigurationCategory, ConfigurationSubcategory, RiskDescription;
DeviceTvmSecureConfigurationAssessment | where IsApplicable == 1 and IsCompliant == 0
| summarize Devices = dcount(DeviceId), Platforms = make_set(OSPlatform, 5) by ConfigurationId
| join kind=leftouter kb on ConfigurationId
| project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact, Devices, Platforms,
          Risk = substring(RiskDescription, 0, 260)
| order by ConfigurationImpact desc, Devices desc | take 400
"""
Q_CONFIG_DEVICE = """
DeviceTvmSecureConfigurationAssessment | where IsApplicable == 1
| summarize Failed = countif(IsCompliant == 0), Passed = countif(IsCompliant == 1) by DeviceId
"""

AV_MODE = {"0": "Active", "1": "Passive", "2": "Disabled", "4": "EDR in block mode", "5": "Passive (audit)"}
_MONTHS = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july", "august",
                                       "september", "october", "november", "december"], 1)}


def _update_month(name: str) -> Optional[tuple[int, int]]:
    m = re.match(r"(\w+)\s+(\d{4})\s+Security Updates", name or "", re.I)
    if m and m.group(1).lower() in _MONTHS:
        return int(m.group(2)), _MONTHS[m.group(1).lower()]
    return None


def _platform_group(p: str) -> str:
    p = p or ""
    if p.startswith("WindowsServer") or p == "Windows":
        return "Windows Server"
    if p.startswith("Windows"):
        return "Windows client"
    if p == "Linux":
        return "Linux"
    if p == "macOS":
        return "macOS"
    if p in ("iOS", "Android"):
        return "Mobile"
    return p or "Other"


async def c_devices(ctx: dict) -> dict:
    devices, vulns, updates, cves, eos, av, cfg_items, cfg_dev = await asyncio.gather(
        g.hunt(Q_DEVICES), g.hunt(Q_DEVICE_VULNS), g.hunt(Q_UPDATES), g.hunt(Q_CVES),
        g.hunt(Q_EOS), g.hunt(Q_AV), g.hunt(Q_CONFIG), g.hunt(Q_CONFIG_DEVICE))
    from app.services import inventory_service as inv
    lookup = await inv.project_lookup()
    v_by = {r["DeviceId"]: r for r in vulns}
    av_by = {r["DeviceId"]: r for r in av}
    cfg_by = {r["DeviceId"]: r for r in cfg_dev}
    now = _now()
    latest_month = max(filter(None, (_update_month(u["RecommendedSecurityUpdate"]) for u in updates)), default=(now.year, now.month))

    rows = []
    for d in devices:
        v, a, c = v_by.get(d["DeviceId"], {}), av_by.get(d["DeviceId"], {}), cfg_by.get(d["DeviceId"], {})
        months = [m for m in (_update_month(u) for u in (v.get("Updates") or [])) if m]
        oldest = min(months) if months else None
        behind = (latest_month[0] - oldest[0]) * 12 + latest_month[1] - oldest[1] + 1 if oldest else 0
        sig_age = _age_days(a.get("AvSigTime")) if a.get("AvSigTime") else None
        mode = AV_MODE.get(a.get("AvMode") or "", "Not reported" if not a.get("AvMode") else f"Mode {a.get('AvMode')}")
        rows.append({
            "id": d["DeviceId"], "name": d["DeviceName"], "platform": d.get("OSPlatform") or "",
            "group": _platform_group(d.get("OSPlatform")), "type": d.get("DeviceType"), "build": d.get("OSBuild"),
            "sensor": d.get("SensorHealthState"), "onboarding": d.get("OnboardingStatus"), "exposure": d.get("ExposureLevel"),
            "machine_group": d.get("MachineGroup"), "join": d.get("JoinType"), "last_seen": d.get("LastSeen"),
            "public_ip": d.get("PublicIP"),
            "project": (lookup.get(_short(d["DeviceName"])) or {}).get("project", "Unassigned"),
            "critical": v.get("Critical", 0), "high": v.get("High", 0), "medium": v.get("Medium", 0),
            "cves": v.get("Total", 0), "exploitable": v.get("Exploitable", 0),
            "missing_updates": v.get("MissingUpdates", 0), "updates": v.get("Updates") or [],
            "months_behind": behind, "oldest_missing": f"{oldest[0]}-{oldest[1]:02d}" if oldest else None,
            "av_mode": mode, "av_sig_version": a.get("AvSigVersion"), "av_sig_time": a.get("AvSigTime") or None,
            "av_sig_age": sig_age, "av_sig_uptodate": {"true": True, "false": False}.get((a.get("AvSigUpToDate") or "").lower()),
            "av_engine_uptodate": {"true": True, "false": False}.get((a.get("AvEngineUpToDate") or "").lower()),
            "av_platform_uptodate": {"true": True, "false": False}.get((a.get("AvPlatformUpToDate") or "").lower()),
            "av_cloud": a.get("Cloud") or None,
            "cfg_failed": c.get("Failed", 0), "cfg_passed": c.get("Passed", 0),
        })
    win_servers = [r for r in rows if r["group"] == "Windows Server"]
    av_reported = [r for r in rows if r["av_mode"] != "Not reported"]
    by_group = defaultdict(lambda: {"devices": 0, "critical": 0, "exploitable": 0, "missing_updates": 0, "devices_behind": 0})
    for r in rows:
        bg = by_group[r["group"]]
        bg["devices"] += 1
        bg["critical"] += 1 if r["critical"] else 0
        bg["exploitable"] += 1 if r["exploitable"] else 0
        bg["missing_updates"] += 1 if r["missing_updates"] else 0
        bg["devices_behind"] += 1 if r["months_behind"] >= 2 else 0

    def slim_update(u: dict) -> dict:
        return {"id": u["RecommendedSecurityUpdateId"], "name": u["RecommendedSecurityUpdate"], "devices": u["Devices"],
                "cves": u["Cves"], "critical": u["Critical"], "platforms": u.get("Platforms") or [],
                "device_names": u.get("DeviceNames") or [], "month": "-".join(map(str, _update_month(u["RecommendedSecurityUpdate"]) or ()))}

    return {
        "summary": {
            "devices": len(rows), "windows_servers": len(win_servers), "linux_servers": sum(1 for r in rows if r["group"] == "Linux" and r["type"] == "Server"),
            "workstations": sum(1 for r in rows if r["type"] == "Workstation"),
            "with_critical": sum(1 for r in rows if r["critical"]), "with_exploitable": sum(1 for r in rows if r["exploitable"]),
            "critical_cves": len({c["CveId"] for c in cves if c.get("Severity") == "Critical"}),
            "exploitable_cves": sum(1 for c in cves if c.get("IsExploitAvailable") == 1),
            "missing_update_devices": sum(1 for r in rows if r["missing_updates"]),
            "servers_behind_2m": sum(1 for r in win_servers if r["months_behind"] >= 2),
            "servers_up_to_date": sum(1 for r in win_servers if not r["missing_updates"]),
            "latest_update_month": f"{latest_month[0]}-{latest_month[1]:02d}",
            "high_exposure": sum(1 for r in rows if r["exposure"] == "High"),
            "sensor_inactive": sum(1 for r in rows if r["onboarding"] == "Onboarded" and r["sensor"] not in ("Active",)),
            "av_reported": len(av_reported),
            "av_not_active": sum(1 for r in av_reported if r["av_mode"] not in ("Active", "EDR in block mode")),
            "av_sig_outdated": sum(1 for r in av_reported if r["av_sig_uptodate"] is False or (r["av_sig_age"] or 0) > 3),
            "misconfigured_devices": sum(1 for r in rows if r["cfg_failed"]),
            "eos_software": len({(e["SoftwareVendor"], e["SoftwareName"]) for e in eos if e.get("EndOfSupportStatus") == "EOS Version"}),
        },
        "devices": rows,
        "by_group": [{"group": k, **v} for k, v in sorted(by_group.items(), key=lambda x: -x[1]["devices"])],
        "updates": [slim_update(u) for u in updates],
        "cves": [{"cve": c["CveId"], "severity": c.get("Severity"), "cvss": c.get("CvssScore"), "exploit": c.get("IsExploitAvailable") == 1,
                  "published": c.get("PublishedDate"), "devices": c.get("Devices"), "software": c.get("Software") or [],
                  "platforms": c.get("Platforms") or [], "fix": c.get("Fix") or [], "description": c.get("Description")} for c in cves],
        "eos": [{"vendor": e.get("SoftwareVendor"), "software": e.get("SoftwareName"), "status": e.get("EndOfSupportStatus"),
                 "devices": e.get("Devices"), "versions": e.get("Versions") or [], "eos_date": e.get("EndOfSupportDate")} for e in eos],
        "config": [{"id": c.get("ConfigurationId"), "name": c.get("ConfigurationName") or c.get("ConfigurationId"),
                    "category": c.get("ConfigurationCategory"), "subcategory": c.get("ConfigurationSubcategory"),
                    "impact": c.get("ConfigurationImpact"), "devices": c.get("Devices"), "platforms": c.get("Platforms") or [],
                    "risk": c.get("Risk")} for c in cfg_items],
    }


COLLECTORS = [("sec_score", c_score), ("sec_threats", c_threats), ("sec_risk", c_risk),
              ("sec_service", c_service), ("sec_intune", c_intune), ("sec_devices", c_devices)]


# ─────────────────────────────────────────────────────────────────────────────
# Device drill-down (live)
# ─────────────────────────────────────────────────────────────────────────────

def _kql_str(s: str) -> str:
    return '"' + re.sub(r'[^A-Za-z0-9._\-]', "", s or "") + '"'


async def device_detail(device_id: str) -> dict:
    did = _kql_str(device_id)
    vulns, cfg_fail, alerts = await asyncio.gather(
        g.hunt(f"""let kb = DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable;
DeviceTvmSoftwareVulnerabilities | where DeviceId == {did}
| join kind=leftouter kb on CveId
| project CveId, Severity = VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable, SoftwareVendor, SoftwareName, SoftwareVersion,
          Fix = RecommendedSecurityUpdate, FixId = RecommendedSecurityUpdateId
| order by IsExploitAvailable desc, CvssScore desc | take 2000"""),
        g.hunt(f"""let kb = DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationImpact, ConfigurationCategory;
DeviceTvmSecureConfigurationAssessment | where DeviceId == {did} and IsApplicable == 1 and IsCompliant == 0
| join kind=leftouter kb on ConfigurationId
| project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationImpact | order by ConfigurationImpact desc"""),
        g.hunt(f"""AlertEvidence | where Timestamp > ago(30d) and DeviceId == {did}
| summarize arg_max(Timestamp, Title, Severity, ServiceSource, Categories) by AlertId | order by Timestamp desc | take 100"""),
    )
    updates = defaultdict(lambda: {"cves": 0, "critical": 0})
    for v in vulns:
        if v.get("FixId"):
            u = updates[(v["FixId"], v["Fix"])]
            u["cves"] += 1
            u["critical"] += 1 if v.get("Severity") == "Critical" else 0
    return {
        "vulns": vulns,
        "updates": sorted([{"id": k[0], "name": k[1], **v} for k, v in updates.items()], key=lambda u: (-u["critical"], -u["cves"])),
        "config": cfg_fail, "alerts": alerts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Findings (security area)
# ─────────────────────────────────────────────────────────────────────────────

def _f(sev: str, section: str, title: str, detail: str, count: Optional[int] = None) -> dict:
    return {"severity": sev, "section": section, "title": title, "detail": detail, "count": count, "ticket": f"{title}. {detail}"}


async def findings(snaps: dict[str, dict]) -> list[dict]:
    d = {k: (v.get("data") or {}) for k, v in snaps.items()}
    sm = {k: (v.get("summary") or {}) for k, v in d.items()}
    target = await cfg.get_float("sec.secure_score_target_pct", 60)
    behind = await cfg.get_int("sec.patch_months_warn", 2)
    out = []
    t = sm.get("sec_threats", {})
    if t.get("incidents_open_high"):
        out.append(_f("critical", "sec_threats", "High-severity Defender incidents open",
                      f"{t['incidents_open_high']} high-severity incident(s) are open ({t.get('incidents_unassigned', 0)} unassigned overall).",
                      t["incidents_open_high"]))
    elif t.get("incidents_open"):
        out.append(_f("warning", "sec_threats", "Defender incidents open", f"{t['incidents_open']} incident(s) are open.", t["incidents_open"]))
    r = sm.get("sec_risk", {})
    if r.get("high") or r.get("confirmed_compromised"):
        out.append(_f("critical", "sec_risk", "High-risk or compromised users",
                      f"{r.get('high', 0)} high-risk user(s), {r.get('confirmed_compromised', 0)} confirmed compromised.",
                      (r.get("high") or 0) + (r.get("confirmed_compromised") or 0)))
    elif r.get("at_risk"):
        out.append(_f("warning", "sec_risk", "Users at risk", f"{r['at_risk']} user(s) flagged at risk by Entra ID Protection.", r["at_risk"]))
    s = sm.get("sec_score", {})
    if s.get("available") and (s.get("pct") or 0) < target:
        out.append(_f("warning", "sec_score", "Secure Score below target",
                      f"Microsoft Secure Score is {s['pct']}% ({s['current']}/{s['max']}); target {target:g}%. "
                      f"{s.get('points_available', 0)} points available from open improvement actions.", None))
    dv = sm.get("sec_devices", {})
    dc_names = {x["name"].split(".")[0].lower() for x in (d.get("tenant", {}).get("dcs") or [])}
    dc_crit = [x["name"] for x in d.get("sec_devices", {}).get("devices", []) if x["name"].split(".")[0].lower() in dc_names and x["critical"]]
    if dc_crit:
        out.append(_f("critical", "sec_devices", "Domain controllers with critical vulnerabilities",
                      f"{len(dc_crit)} DC(s): {', '.join(n.split('.')[0] for n in dc_crit[:6])}.", len(dc_crit)))
    if dv.get("servers_behind_2m"):
        out.append(_f("warning", "sec_devices", f"Windows servers {behind}+ months behind on updates",
                      f"{dv['servers_behind_2m']} of {dv.get('windows_servers', 0)} Windows servers are missing updates from {behind}+ months ago.",
                      dv["servers_behind_2m"]))
    if dv.get("with_exploitable"):
        out.append(_f("warning", "sec_devices", "Devices with exploitable vulnerabilities",
                      f"{dv['with_exploitable']} device(s) have vulnerabilities with a public exploit ({dv.get('exploitable_cves', 0)} high/critical CVEs).",
                      dv["with_exploitable"]))
    if dv.get("av_sig_outdated"):
        out.append(_f("warning", "sec_devices", "Antivirus signatures out of date",
                      f"{dv['av_sig_outdated']} device(s) have outdated Defender signatures.", dv["av_sig_outdated"]))
    if dv.get("av_not_active"):
        out.append(_f("info", "sec_devices", "Antivirus not in active mode",
                      f"{dv['av_not_active']} device(s) run Defender in passive / disabled mode.", dv["av_not_active"]))
    if dv.get("sensor_inactive"):
        out.append(_f("warning", "sec_devices", "Defender sensor not healthy",
                      f"{dv['sensor_inactive']} onboarded device(s) report an inactive or impaired sensor.", dv["sensor_inactive"]))
    it = sm.get("sec_intune", {})
    if it.get("noncompliant"):
        out.append(_f("info", "sec_intune", "Intune non-compliant devices", f"{it['noncompliant']} device(s) are non-compliant.", it["noncompliant"]))
    if it.get("not_encrypted"):
        out.append(_f("warning", "sec_intune", "Windows devices without encryption", f"{it['not_encrypted']} Windows device(s) are not encrypted.", it["not_encrypted"]))
    sv = sm.get("sec_service", {})
    if sv.get("active_incidents"):
        out.append(_f("info", "sec_service", "Microsoft 365 service incidents", f"{sv['active_incidents']} active service incident(s).", sv["active_incidents"]))
    if sv.get("action_required"):
        out.append(_f("info", "sec_service", "Message center: action required", f"{sv['action_required']} message(s) require action.", sv["action_required"]))
    order = {"critical": 0, "warning": 1, "info": 2}
    return sorted(out, key=lambda f: order.get(f["severity"], 3))


async def ensure_settings() -> None:
    from sqlalchemy import text
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO infraguardian_settings (key, value, category, description, is_secret) VALUES
            ('sec.secure_score_target_pct', '60', 'sec', 'Warn when Microsoft Secure Score is below this % of maximum', FALSE),
            ('sec.patch_months_warn',       '2',  'sec', 'Warn when a Windows server is missing updates this many months old', FALSE)
            ON CONFLICT (key) DO NOTHING
        """))
        await db.commit()
    await cfg.invalidate_cache()
