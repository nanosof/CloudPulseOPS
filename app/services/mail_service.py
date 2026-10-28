"""SMTP mail service for Mdaemon / internal mail servers."""
from __future__ import annotations
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import app.config as cfg


async def send_alert_email(to: str, subject: str, body_html: str) -> dict:
    host     = await cfg.get("mail.host", "")
    port     = await cfg.get_int("mail.port", 587)
    username = await cfg.get("mail.username", "")
    password = await cfg.get("mail.password", "")
    from_    = await cfg.get("mail.from", "")
    use_ssl  = await cfg.get_bool("mail.ssl", False)

    if not password:
        return {"ok": False, "error": "Mail password not configured"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"CloudPulse Platform <{from_}>"
    msg["To"]      = to
    msg.attach(MIMEText(body_html, "html"))

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with smtplib.SMTP_SSL(host, port, context=ctx) as smtp:
                smtp.login(username, password)
                smtp.sendmail(from_, to, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.ehlo()
                try:
                    smtp.starttls()
                    smtp.ehlo()
                except Exception:
                    pass
                smtp.login(username, password)
                smtp.sendmail(from_, to, msg.as_string())
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def send_capacity_alert(server: str, metric: str, value: float, details: str) -> dict:
    subject   = f"🚨 Windows Ops Alert: {metric} Critical on {server}"
    body_html = f"""
<html><body style="font-family:Arial,sans-serif;background:#0a0f1e;color:#e2e8f0;padding:20px">
<div style="max-width:600px;margin:0 auto;background:#111827;border-radius:12px;padding:24px;border:1px solid #374151">
  <h2 style="color:#ef4444;margin:0 0 16px">🚨 Capacity Alert</h2>
  <table style="width:100%;border-collapse:collapse">
    <tr><td style="padding:8px;color:#9ca3af">Server</td><td style="padding:8px;color:#f9fafb;font-weight:bold">{server}</td></tr>
    <tr><td style="padding:8px;color:#9ca3af">Metric</td><td style="padding:8px;color:#f9fafb">{metric}</td></tr>
    <tr><td style="padding:8px;color:#9ca3af">Value</td><td style="padding:8px;color:#ef4444;font-size:1.2em;font-weight:bold">{value:.1f}%</td></tr>
  </table>
  <pre style="background:#1e2540;padding:12px;border-radius:8px;font-size:12px;overflow-x:auto">{details}</pre>
  <p style="color:#6b7280;font-size:12px;margin-top:16px">Sent by CloudPulse Platform · emaratech</p>
</div></body></html>"""
    admin_email = await cfg.get("mail.from", "")
    return await send_alert_email(admin_email, subject, body_html)


def _smtp_send(host: str, port: int, username: str, password: str, use_ssl: bool,
               from_: str, recipients: list[str], raw: str) -> None:
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as smtp:
            smtp.login(username, password)
            smtp.sendmail(from_, recipients, raw)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls()
                smtp.ehlo()
            except Exception:
                pass
            smtp.login(username, password)
            smtp.sendmail(from_, recipients, raw)


async def send_report_email(recipients: list[str], subject: str, body_html: str,
                            inline_images: dict[str, bytes] | None = None,
                            attachments: list[tuple[str, bytes]] | None = None) -> dict:
    """HTML email with inline images (referenced as cid:<name>) and file attachments."""
    import asyncio
    from email.mime.application import MIMEApplication
    from email.mime.image import MIMEImage

    host     = await cfg.get("mail.host", "")
    port     = await cfg.get_int("mail.port", 587)
    username = await cfg.get("mail.username", "")
    password = await cfg.get("mail.password", "")
    from_    = await cfg.get("mail.from", "")
    use_ssl  = await cfg.get_bool("mail.ssl", False)
    if not password:
        return {"ok": False, "error": "Mail password not configured"}

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"]    = f"CloudPulse Platform <{from_}>"
    msg["To"]      = ", ".join(recipients)
    related = MIMEMultipart("related")
    related.attach(MIMEText(body_html, "html", "utf-8"))
    for cid, data in (inline_images or {}).items():
        img = MIMEImage(data, "png")
        img.add_header("Content-ID", f"<{cid}>")
        img.add_header("Content-Disposition", "inline", filename=f"{cid}.png")
        related.attach(img)
    msg.attach(related)
    for name, data in attachments or []:
        part = MIMEApplication(data, Name=name)
        part["Content-Disposition"] = f'attachment; filename="{name}"'
        msg.attach(part)

    try:
        await asyncio.to_thread(_smtp_send, host, port, username, password, use_ssl, from_, recipients, msg.as_string())
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
