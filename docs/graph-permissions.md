# Microsoft Graph permissions

CloudPulse uses one Entra ID app registration with **application** permissions (client credentials flow). All permissions are read-only. Grant admin consent after adding them.

| Permission | Used for |
|---|---|
| `User.Read.All`, `Directory.Read.All` | Accounts, groups, devices, directory roles, sync status |
| `Organization.Read.All` | Tenant details and subscribed licences |
| `AuditLog.Read.All` | Sign-in activity, failed sign-ins, directory audit log |
| `Reports.Read.All` | MFA registration details and Microsoft 365 usage |
| `UserAuthenticationMethod.Read.All` | Registered authentication methods and system-preferred MFA status |
| `Policy.Read.All` | Per-user MFA state (Disabled / Enabled / Enforced), Conditional Access policies, security defaults |
| `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` | Risky users and risk detections |
| `SecurityEvents.Read.All` | Microsoft Secure Score and improvement actions |
| `SecurityIncident.Read.All`, `SecurityAlert.Read.All` | Defender incidents and alerts |
| `ThreatHunting.Read.All` | Advanced hunting queries: device health, missing updates, vulnerabilities, antivirus |
| `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` | Intune devices and compliance |
| `ServiceHealth.Read.All`, `ServiceMessage.Read.All` | Microsoft 365 service health and message center |
| `Chat.Read.All` | Reading the Teams monitoring chat |

Single sign-on uses the same app registration with the redirect URI configured in `entra.redirect_uri` (`https://<host>/api/auth/entra/callback`).

## Missing permissions

Each collector records its own error, so a missing permission affects only the views that need it. The Identity → MFA tab, for example, works from registered methods and the system-preferred MFA status until `Policy.Read.All` is granted, and then adds per-user MFA state and Conditional Access coverage on the next collection.

To check which permissions the app's token actually carries, decode the `roles` claim of an app-only token, for example:

```bash
podman exec cloudpulse python -c "import asyncio,base64,json; from app.services import teams_service as t; tok=asyncio.run(t._get_token()); p=tok.split('.')[1]; print(sorted(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4)))['roles']))"
```
