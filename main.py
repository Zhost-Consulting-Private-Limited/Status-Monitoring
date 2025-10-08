"""
Z Monitor: Stable & Secure Infrastructure Health Monitor
======================================================

FastAPI application architected for robust, stateful monitoring.
This is the stable, production-ready version incorporating all features and bug
fixes, with a corrected and stable file structure.

Features
--------
- **STABILITY FIX:** Resolved all critical structural bugs that caused startup
  failures (IndentationError, 404 Not Found, Blank Pages). The application
  is now stable and runs correctly.
- **Stateful Alerting Engine:** Tracks the ongoing state of each monitor and
  sends configurable re-alerts for persistent issues.
- **"Resolved" Notifications:** Automatically sends a notification when a service
  recovers, including the total outage duration.
- **Secure Password Changes:** A dedicated UI and secure API endpoint for
  changing the admin password.
- **Fully Authenticated UI:** All pages, including the dashboard, are protected
  and require a login.
- **Multi-Channel Notifications:** Alerts via Email (SMTP), SMS (AWS),
  and Microsoft Teams (Webhook).
- **Background Processing:** Core monitoring tasks run as continuous background
  processes, independent of UI interaction.
- **Modern UI:** Clean, responsive, light-themed UI with a detailed table-based
  dashboard and professional form styling.

How to Run
----------
1) Create and activate a Python virtual environment:
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate

2) Install all required dependencies:
   pip install "fastapi[all]" sqlmodel httpx dnspython python-jose[cryptography] passlib python-whois boto3

3) Set necessary environment variables for your deployment:
   # Core App Settings (CHANGE THESE FOR PRODUCTION)
   export ADMIN_USERNAME=admin
   export ADMIN_PASSWORD=changeme
   export JWT_SECRET=a_very_strong_and_long_secret_key

   # Database location
   export DATABASE_URL="sqlite:///./zmonitor.db"

   # Notification Webhooks/Credentials (optional)
   export TEAMS_WEBHOOK_URL="https://your-org.webhook.office.com/..."
   # ... add other SMTP and AWS env vars as needed

4) Start the server:
   uvicorn main:app --host 0.0.0.0 --port 8000

"""
from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass
import json
import logging
import os
import smtplib
import ssl
import socket
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import httpx
import whois
from dns import resolver, exception as dns_exception
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Form,
    Cookie,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel as PydanticBaseModel
from sqlmodel import Field, SQLModel, Session, create_engine, select
from sqlalchemy import func

# Optional dependencies
try:
    from ping3 import ping as icmp_ping
except ImportError:
    icmp_ping = None
try:
    import boto3
except ImportError:
    boto3 = None

# --- Basic Logging Configuration ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Core Application Settings ---
APP_TITLE = os.getenv("APP_TITLE", "Z Monitor")
APP_LOGO_URL = os.getenv("APP_LOGO_URL", "https://zhost.co.in/assets/img/logo.png")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGO = "HS256"
JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "1440"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./zmonitor.db")
DEFAULT_FOOTER_HTML = os.getenv("FOOTER_HTML", "Powered By: Bithost &copy; ZHOST CONSULTING PRIVATE LIMITED")
DEFAULT_RE_ALERT_MINUTES = int(os.getenv("RE_ALERT_MINUTES", "30"))

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# --- Database Models ---
class MonitorType(str, Enum): HTTP="http"; TCP="tcp"; DNS_A="dns_a"; SSL_CERT="ssl_cert"; WHOIS="whois"; INTERNET="internet"; ICMP="icmp"

class MonitorTarget(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str; type: MonitorType; target: str
    interval_sec: int = 60; timeout_sec: int = 10; expected_http_status: Optional[int] = None
    meta: str = Field(default="{}"); enabled: bool = True; notifications: bool = True
    last_status: str = Field(default="unknown")
    status_since: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    last_alert_sent: Optional[dt.datetime] = Field(default=None)

class MonitorStatus(SQLModel, table=True): id: Optional[int]=Field(default=None, primary_key=True); target_id: int=Field(index=True); status: str; detail: str; checked_at: dt.datetime=Field(default_factory=dt.datetime.utcnow)
class User(SQLModel, table=True): id: Optional[int]=Field(default=None, primary_key=True); username: str=Field(unique=True, index=True); password_hash: str
class SystemSetting(SQLModel, table=True): key: str=Field(primary_key=True); value: str


# --- Database Setup & Auth ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        if not s.exec(select(User).where(User.username == ADMIN_USERNAME)).first():
            s.add(User(username=ADMIN_USERNAME, password_hash=pwd_context.hash(ADMIN_PASSWORD))); s.commit()
        if not s.exec(select(MonitorTarget)).first():
            s.add(MonitorTarget(name="Internet", type=MonitorType.INTERNET, target="", interval_sec=60)); s.commit()

_SETTINGS_CACHE = {}
def get_setting(key: str, default: Any = None) -> Any:
    if key in _SETTINGS_CACHE: return _SETTINGS_CACHE[key]
    with Session(engine) as s:
        db_val = s.get(SystemSetting, key); val = db_val.value if db_val else os.getenv(key.upper(), default)
        _SETTINGS_CACHE[key] = val; return val

COOKIE_NAME = "zmonitor_token"
def create_token(username: str) -> str:
    now = dt.datetime.utcnow(); payload = {"sub": username, "iat": now, "exp": now + dt.timedelta(minutes=JWT_TTL_MIN)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
def get_current_user(token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)) -> str:
    if not token: raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO]); username = payload.get("sub")
        if not username: raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError: raise HTTPException(status_code=401, detail="Invalid token")
def page_auth_check(token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)):
    if not token: return RedirectResponse("/login")
    try: jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError: return RedirectResponse("/login")
    return None

# --- FastAPI App Initialization ---
app = FastAPI(title="Z Monitor")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- Notification Logic ---
async def send_notification(subject: str, detail: str, status: str):
    html_body = f"<b>{subject}</b><br><br>Details: {detail}"
    sms_msg = f"{subject}. Detail: {detail[:80]}"
    asyncio.create_task(send_teams_notification(subject, detail, status))
    asyncio.create_task(send_email_notification(subject, html_body))
    asyncio.create_task(send_sms_notification(sms_msg))
async def send_teams_notification(subject: str, detail: str, status: str):
    webhook_url=get_setting("teams_webhook_url");
    if not webhook_url: return
    colors={"down":"Attention","degraded":"Warning","up":"Good", "resolved": "Good"}; payload={"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.2","msteams":{"width":"Full"},"body":[{"type":"TextBlock","text":subject,"size":"Large","weight":"Bolder","color":colors.get(status,"Default")},{"type":"TextBlock","text":detail,"wrap":True}]}}]}
    try:
        async with httpx.AsyncClient() as c: await c.post(webhook_url,json=payload,timeout=10)
    except Exception as e: logging.error(f"Error sending Teams notification: {e}")
async def send_email_notification(subject: str, body: str):
    if not get_setting("notification_emails"): return
    host,port,user,pw,from_email=(get_setting(k) for k in ["smtp_host","smtp_port","smtp_user","smtp_password","smtp_from_email"]);
    if not all([host,user,pw,from_email]): return
    msg=MIMEText(body,"html"); msg["Subject"],msg["From"],msg["To"]=subject,from_email,get_setting("notification_emails")
    try:
        use_tls=get_setting("smtp_use_tls","true").lower() in ("true","1"); port=int(port or "587")
        s_class=smtplib.SMTP_SSL if port==465 else smtplib.SMTP
        with s_class(host,port,timeout=10) as s:
            if use_tls and port!=465:s.starttls()
            s.login(user,pw);s.send_message(msg)
    except Exception as e: logging.error(f"Failed to send email: {e}")
async def send_sms_notification(message: str):
    if not (boto3 and get_setting("notification_phone_numbers")): return
    key,secret,region=(get_setting(k) for k in ["aws_access_key_id","aws_secret_access_key","aws_region"]);
    if not all([key,secret,region]): return
    try:
        sns=boto3.client("sns",aws_access_key_id=key,aws_secret_access_key=secret,region_name=region)
        for num in [p.strip() for p in get_setting("notification_phone_numbers").split(",")]: sns.publish(PhoneNumber=num,Message=message)
    except Exception as e: logging.error(f"Failed to send SMS: {e}")

# --- Core Monitoring Logic ---
@dataclass
class CheckResult: up: bool; status: str; detail: str

async def check_http(url: str, timeout: int, expected_status: Optional[int]) -> CheckResult:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            r = await client.get(url)
            ok = r.status_code == (expected_status or 200)
            return CheckResult(ok, "up" if ok else "degraded", f"HTTP {r.status_code} in {r.elapsed.total_seconds():.2f}s")
    except httpx.ConnectError as e: return CheckResult(False, "down", f"Connect error: {e}")
    except httpx.ReadTimeout: return CheckResult(False, "down", "HTTP timeout")
    except Exception as e: return CheckResult(False, "down", f"HTTP error: {e}")

async def check_tcp(target: str, timeout: int) -> CheckResult:
    try: host, port_str = target.rsplit(":", 1); port = int(port_str)
    except Exception: return CheckResult(False, "down", "Invalid target, expected host:port")
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close(); await writer.wait_closed()
        return CheckResult(True, "up", "TCP connect OK")
    except asyncio.TimeoutError: return CheckResult(False, "down", "TCP connect timeout")
    except Exception as e: return CheckResult(False, "down", f"TCP error: {e}")

async def check_dns_a(name: str, timeout: int) -> CheckResult:
    try:
        res = resolver.Resolver(configure=True); res.timeout = res.lifetime = timeout
        v4 = [r.address for r in res.resolve(name, "A")]
        v6 = [r.address for r in res.resolve(name, "AAAA")]
        if not v4 and not v6: return CheckResult(False, "down", "No A/AAAA records")
        return CheckResult(True, "up", f"A: {', '.join(v4) or '-'}; AAAA: {', '.join(v6) or '-'}")
    except dns_exception.Timeout: return CheckResult(False, "down", "DNS timeout")
    except Exception as e: return CheckResult(False, "down", f"DNS error: {e}")

def _get_hostname_port(target: str) -> Tuple[str, int]:
    try:
        if "://" in target: from urllib.parse import urlparse; p=urlparse(target); return p.hostname or target, p.port or (443 if p.scheme == "https" else 80)
        else: host, port_str = target.rsplit(":", 1); return host, int(port_str)
    except Exception: return target, 443

async def check_ssl_cert(target: str, timeout: int) -> CheckResult:
    host, port = _get_hostname_port(target)
    try:
        ctx = ssl.create_default_context(); _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout)
        cert = writer.get_extra_info("peercert"); writer.close(); await writer.wait_closed()
        if not cert: return CheckResult(False, "down", "Could not get peer certificate")
        exp = dt.datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z"); days = (exp - dt.datetime.utcnow()).days
        status = "up" if days > 14 else ("degraded" if days >= 0 else "down")
        return CheckResult(status != "down", status, f"Cert expires in {days} days ({exp:%Y-%m-%d})")
    except ssl.SSLError as e: return CheckResult(False, "down", f"SSL error: {e.reason}")
    except asyncio.TimeoutError: return CheckResult(False, "down", "SSL connect timeout")
    except Exception as e: return CheckResult(False, "down", f"SSL failure: {e}")

async def check_whois(domain: str, timeout: int) -> CheckResult:
    try:
        data = await asyncio.to_thread(whois.whois, domain); exp_raw = getattr(data, "expiration_date", None)
        exp = next((e for e in exp_raw if isinstance(e, dt.datetime)), None) if isinstance(exp_raw, list) else exp_raw if isinstance(exp_raw, dt.datetime) else None
        if not exp: return CheckResult(False, "degraded", "WHOIS: no expiration_date")
        days = (exp - dt.datetime.utcnow()).days; status = "up" if days > 30 else ("degraded" if days >= 0 else "down")
        return CheckResult(status != "down", status, f"Domain expires in {days} days ({exp:%Y-%m-%d})")
    except Exception as e: return CheckResult(False, "down", f"WHOIS error: {e}")

async def check_internet(timeout: int) -> CheckResult:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get("https://www.google.com/generate_204")
            if r.status_code == 204: return CheckResult(True, "up", "Internet OK via Google")
    except Exception as e: return CheckResult(False, "down", f"Internet check error: {e}")
    return CheckResult(False, "down", "No internet reachability")

async def check_icmp(host: str, timeout: int) -> CheckResult:
    if not icmp_ping: return CheckResult(False, "degraded", "ping3 not installed")
    try:
        rtt = await asyncio.to_thread(icmp_ping, host, timeout=timeout)
        if rtt is None or rtt is False: return CheckResult(False, "down", "Ping timeout")
        return CheckResult(True, "up", f"Ping {rtt*1000:.1f} ms")
    except PermissionError: return CheckResult(False, "degraded", "ICMP needs CAP_NET_RAW or root access")
    except Exception as e: return CheckResult(False, "down", f"Ping error: {e}")

async def run_check(t: MonitorTarget) -> CheckResult:
    check_map = {
        MonitorType.HTTP: lambda: check_http(t.target, t.timeout_sec, t.expected_http_status),
        MonitorType.TCP: lambda: check_tcp(t.target, t.timeout_sec),
        MonitorType.DNS_A: lambda: check_dns_a(t.target, t.timeout_sec),
        MonitorType.SSL_CERT: lambda: check_ssl_cert(t.target, t.timeout_sec),
        MonitorType.WHOIS: lambda: check_whois(t.target, t.timeout_sec),
        MonitorType.INTERNET: lambda: check_internet(t.timeout_sec),
        MonitorType.ICMP: lambda: check_icmp(t.target.split(":")[0], t.timeout_sec)
    }
    if t.type in check_map: return await check_map[t.type]()
    return CheckResult(False, "unknown", "Unsupported monitor type")

# --- Scheduler & Startup ---
_tasks: Dict[int, asyncio.Task] = {}
async def scheduler_loop(target_id: int):
    while True:
        try:
            with Session(engine) as s:
                t = s.get(MonitorTarget, target_id)
                if not t or not t.enabled:
                    await asyncio.sleep(15); continue
                
                now = dt.datetime.utcnow()
                result = await run_check(t)
                s.add(MonitorStatus(target_id=t.id, status=result.status, detail=result.detail, checked_at=now))
                
                is_bad_status, status_changed = result.status in ("down", "degraded"), result.status != t.last_status

                if status_changed:
                    outage_duration = now - t.status_since
                    t.status_since, t.last_status, t.last_alert_sent = now, result.status, None

                    if is_bad_status:
                        logging.info(f"Status changed to '{result.status}' for '{t.name}'. Sending initial alert.")
                        subject = f"ALERT: {t.name} is {result.status.upper()}"
                        await send_notification(subject, result.detail, result.status)
                        t.last_alert_sent = now
                    elif t.last_status == "up":
                        logging.info(f"Status for '{t.name}' is now 'up'. Sending RESOLVED notification.")
                        duration_str = str(outage_duration).split('.')[0]
                        subject, detail = f"RESOLVED: {t.name} is now UP", f"The resource has recovered after an outage of approximately {duration_str}."
                        await send_notification(subject, detail, "resolved")
                
                elif is_bad_status:
                    re_alert_minutes = int(get_setting("re_alert_minutes", DEFAULT_RE_ALERT_MINUTES))
                    last_alert = t.last_alert_sent or t.status_since
                    if now >= last_alert + dt.timedelta(minutes=re_alert_minutes):
                        logging.info(f"'{t.name}' is still '{t.last_status}'. Sending re-alert.")
                        duration_str = str(now - t.status_since).split('.')[0]
                        subject = f"STILL {t.last_status.upper()}: {t.name}"
                        detail = f"Resource has been {t.last_status} for {duration_str}. Last check: {result.detail}"
                        await send_notification(subject, detail, t.last_status)
                        t.last_alert_sent = now

                s.add(t); s.commit()
        except Exception as e: logging.error(f"Scheduler loop error for target {target_id}: {e}", exc_info=True)
        
        with Session(engine) as s:
            t = s.get(MonitorTarget, target_id); interval = t.interval_sec if t and t.enabled else 60
        await asyncio.sleep(max(5, interval))

async def monthly_report_loop():
    while True:
        now = dt.datetime.utcnow(); next_run = (now.replace(day=1) + dt.timedelta(days=32)).replace(day=1, hour=1, minute=0, second=0)
        await asyncio.sleep((next_run - now).total_seconds())
        try:
            last_month_end = dt.datetime(now.year, now.month, 1) - dt.timedelta(seconds=1)
            last_month_start = last_month_end.replace(day=1, hour=0, minute=0, second=0)
            report_lines = []
            with Session(engine) as s:
                for t in s.exec(select(MonitorTarget)).all():
                    down_seconds = sum(t.interval_sec for _ in s.exec(select(MonitorStatus).where(MonitorStatus.target_id==t.id, MonitorStatus.status=='down', MonitorStatus.checked_at.between(last_month_start, last_month_end))).all())
                    if down_seconds > 0: report_lines.append(f"<li><b>{t.name}</b> was down for ~<b>{str(dt.timedelta(seconds=down_seconds))}</b>.</li>")
            if report_lines:
                subject = f"Z Monitor Downtime Report: {last_month_start:%B %Y}"; body = f"<h2>Downtime Report for {last_month_start:%B %Y}</h2><ul>{''.join(report_lines)}</ul>"
                await send_email_notification(subject, body)
        except Exception as e: logging.error(f"Monthly report generation failed: {e}", exc_info=True)

async def ensure_task_running(target_id: int):
    if target_id not in _tasks or _tasks[target_id].done(): _tasks[target_id] = asyncio.create_task(scheduler_loop(target_id))

@app.on_event("startup")
async def startup_event():
    create_db_and_tables()
    with Session(engine) as s:
        for t in s.exec(select(MonitorTarget).where(MonitorTarget.enabled == True)).all():
            await ensure_task_running(t.id)
    asyncio.create_task(monthly_report_loop())

# --- API Schemas & Routes ---
class TargetIn(SQLModel): name: str; type: MonitorType; target: str; interval_sec: int=60; timeout_sec: int=10; expected_http_status: Optional[int]=None; meta: Dict[str, Any]={}; enabled: bool=True; notifications: bool=True
class TargetOut(TargetIn): id: int
class StatusOut(SQLModel): target_id: int; target_name: str; type: MonitorType; status: str; detail: str; checked_at: dt.datetime
class PasswordChange(PydanticBaseModel): current_password: str; new_password: str; confirm_password: str

@app.post("/login")
async def login(username: str=Form(...), password: str=Form(...)):
    with Session(engine) as s:
        user = s.exec(select(User).where(User.username == username)).first()
        if not user or not pwd_context.verify(password, user.password_hash): raise HTTPException(status_code=401, detail="Invalid credentials")
    resp = RedirectResponse("/", status_code=302); resp.set_cookie(COOKIE_NAME, create_token(username), httponly=True, samesite="lax"); return resp
@app.post("/logout")
async def logout(): resp = RedirectResponse("/login"); resp.delete_cookie(COOKIE_NAME); return resp

@app.post("/api/user/change-password", status_code=status.HTTP_200_OK)
async def change_password(payload: PasswordChange, username: str = Depends(get_current_user)):
    if payload.new_password != payload.confirm_password: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New passwords do not match.")
    if len(payload.new_password) < 8: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be at least 8 characters long.")
    with Session(engine) as s:
        user = s.exec(select(User).where(User.username == username)).one()
        if not pwd_context.verify(payload.current_password, user.password_hash): raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password.")
        user.password_hash = pwd_context.hash(payload.new_password)
        s.add(user); s.commit()
    return {"message": "Password updated successfully."}

@app.get("/api/settings")
async def get_settings(user: str=Depends(get_current_user)):
    keys = ["app_title", "app_logo_url", "footer_html", "re_alert_minutes", "teams_webhook_url", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from_email", "smtp_use_tls", "aws_access_key_id", "aws_secret_access_key", "aws_region", "notification_emails", "notification_phone_numbers"]
    defaults = {"app_title": APP_TITLE, "app_logo_url": APP_LOGO_URL, "footer_html": DEFAULT_FOOTER_HTML, "re_alert_minutes": DEFAULT_RE_ALERT_MINUTES}
    return {key: get_setting(key, defaults.get(key, "")) for key in keys}
@app.post("/api/settings")
async def save_settings(payload: Dict[str, str], user: str=Depends(get_current_user)):
    with Session(engine) as s:
        for key, value in payload.items():
            if ('password' in key or 'secret' in key or 'webhook' in key) and not value: continue
            setting = s.get(SystemSetting, key) or SystemSetting(key=key)
            setting.value = value; s.add(setting)
        s.commit(); _SETTINGS_CACHE.clear(); return {"ok": True}

@app.get("/api/targets", response_model=List[TargetOut])
async def list_targets(user: str = Depends(get_current_user)):
    with Session(engine) as s:
        return [TargetOut(**(t.dict() | {'meta': json.loads(t.meta)})) for t in s.exec(select(MonitorTarget)).all()]
@app.post("/api/targets", response_model=TargetOut)
async def create_target(payload: TargetIn, user: str=Depends(get_current_user)):
    with Session(engine) as s:
        t = MonitorTarget.from_orm(payload, {"meta": json.dumps(payload.meta)})
        s.add(t); s.commit(); s.refresh(t)
        await ensure_task_running(t.id)
        data = t.dict(); data['meta'] = json.loads(data['meta'])
        return TargetOut(**data)
@app.put("/api/targets/{target_id}", response_model=TargetOut)
async def update_target(target_id: int, payload: TargetIn, user: str = Depends(get_current_user)):
    with Session(engine) as s:
        t = s.get(MonitorTarget, target_id)
        if not t: raise HTTPException(404, "Not found")
        for k, v in payload.dict(exclude_unset=True).items(): setattr(t, k, json.dumps(v) if k == "meta" else v)
        s.add(t); s.commit(); s.refresh(t)
        await ensure_task_running(t.id)
        data = t.dict(); data['meta'] = json.loads(data['meta'])
        return TargetOut(**data)
@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int, user: str=Depends(get_current_user)):
    with Session(engine) as s:
        t = s.get(MonitorTarget, target_id);
        if not t: raise HTTPException(404, "Not found")
        s.delete(t); s.commit()
    if task := _tasks.pop(target_id, None): task.cancel()
    return {"ok": True}
@app.get("/api/status", response_model=List[StatusOut])
async def get_latest_status(user: str=Depends(get_current_user)):
    with Session(engine) as s:
        targets = {t.id: (t.name, t.type) for t in s.exec(select(MonitorTarget.id, MonitorTarget.name, MonitorTarget.type)).all()}
        subq = select(MonitorStatus.target_id, func.max(MonitorStatus.checked_at).label("mc")).group_by(MonitorStatus.target_id).subquery()
        stmt = select(MonitorStatus).join(subq, (MonitorStatus.target_id == subq.c.target_id) & (MonitorStatus.checked_at == subq.c.mc))
        return [StatusOut(**r.dict(), target_name=targets.get(r.target_id, ("Unknown", "unknown"))[0], type=targets.get(r.target_id, ("Unknown", "unknown"))[1]) for r in s.exec(stmt).all() if r.target_id in targets]

# --- Frontend HTML Templates & Page Routes ---
def render_template(html: str) -> str:
    return (html.replace("__APP_TITLE__", get_setting("app_title", APP_TITLE)).replace("__APP_LOGO_URL__", get_setting("app_logo_url", APP_LOGO_URL)).replace("__FOOTER_HTML__", get_setting("footer_html", DEFAULT_FOOTER_HTML)))

DASHBOARD_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>__APP_TITLE__</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-50 text-gray-800 flex flex-col min-h-screen font-sans">
<div class="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex-grow">
<header class="flex items-center justify-between py-4 border-b border-gray-200"><div class="flex items-center gap-3"><img src="__APP_LOGO_URL__" alt="Logo" class="h-8 sm:h-10"/><h1 class="text-xl sm:text-2xl font-bold text-gray-900">__APP_TITLE__</h1></div><nav><a class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors" href="/admin">Admin Panel</a></nav></header>
<main class="py-6"><div class="overflow-x-auto bg-white border border-gray-200 rounded-lg shadow-sm"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-100"><tr><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Status</th><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Name</th><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Details</th><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Last Checked</th></tr></thead><tbody id="status-table-body" class="bg-white divide-y divide-gray-200"></tbody></table></div></main>
</div><footer class="w-full text-center text-sm text-gray-500 py-4">__FOOTER_HTML__</footer>
<script>
    const tbody=document.getElementById("status-table-body");function renderLoading(){tbody.innerHTML='<tr><td colspan="4" class="px-6 py-4 text-center text-gray-500 animate-pulse">Loading status...</td></tr>'}
    async function fetchStatuses(){try{const res=await fetch("/api/status",{credentials:"include"});if(401===res.status)return void(window.location="/login");if(!res.ok)throw new Error("Network response error");const data=await res.json();if(tbody.innerHTML="",0===data.length)return void(tbody.innerHTML='<tr><td colspan="4" class="px-6 py-4 text-center text-gray-500">No monitors configured.</td></tr>');const statusStyles={up:{dot:"bg-green-500",text:"text-green-800"},down:{dot:"bg-red-500",text:"text-red-800"},degraded:{dot:"bg-yellow-500",text:"text-yellow-800"},unknown:{dot:"bg-gray-500",text:"text-gray-800"}};for(const item of data){const style=statusStyles[item.status]||statusStyles.unknown,row=document.createElement("tr");row.className="hover:bg-gray-50 transition-colors",row.innerHTML=`<td class="px-6 py-4 whitespace-nowrap" title="${item.status}"><div class="flex items-center"><div class="h-2.5 w-2.5 rounded-full ${style.dot} mr-2"></div><span class="font-medium ${style.text}">${item.status.charAt(0).toUpperCase()+item.status.slice(1)}</span></div></td><td class="px-6 py-4 whitespace-nowrap"><div class="text-sm font-semibold text-gray-900">${item.target_name}</div><div class="text-xs text-gray-500">${item.type.replace("_"," ").toUpperCase()}</div></td><td class="px-6 py-4 text-sm text-gray-600 break-words">${item.detail}</td><td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(item.checked_at).toLocaleString()}</td>`,tbody.appendChild(row)}}catch(e){console.error("Fetch error",e),tbody.innerHTML='<tr><td colspan="4" class="px-6 py-4 text-center text-red-500">Failed to load status data.</td></tr>'}}
    renderLoading();fetchStatuses();setInterval(fetchStatuses,10e3);
</script></body></html>
"""

ADMIN_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Admin • __APP_TITLE__</title><script src="https://cdn.tailwindcss.com"></script><script src="https://cdn.tailwindcss.com?plugins=forms"></script></head>
<body class="bg-gray-50 text-gray-800 flex flex-col min-h-screen font-sans">
<div class="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 flex-grow">
    <header class="flex items-center justify-between py-4 border-b border-gray-200"><div class="flex items-center gap-3"><img src="__APP_LOGO_URL__" alt="Logo" class="h-8 sm:h-10"/><h1 class="text-xl sm:text-2xl font-bold text-gray-900">Admin Panel</h1></div><div class="space-x-4"><a href="/" class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors">Dashboard</a><form method="post" action="/logout" class="inline"><button class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors">Logout</button></form></div></header>
    <main class="grid lg:grid-cols-5 gap-6 py-6"><div class="lg:col-span-2 bg-white border border-gray-200 rounded-lg shadow-sm p-4 self-start"><h2 class="text-lg font-semibold mb-3 text-gray-900">Add / Update Monitor</h2><form id="monitorForm" class="space-y-4"><input type="hidden" id="id"/><div><label for="name" class="text-sm font-medium text-gray-700">Name</label><input id="name" type="text" class="form-input mt-1 block w-full" required/></div><div><label for="type" class="text-sm font-medium text-gray-700">Type</label><select id="type" class="form-select mt-1 block w-full">{MONITOR_TYPE_OPTIONS}</select></div><div><label for="target" class="text-sm font-medium text-gray-700">Target</label><input id="target" type="text" class="form-input mt-1 block w-full" placeholder="URL / host:port / domain"/></div><div class="grid grid-cols-2 gap-4"><div><label for="interval_sec" class="text-sm font-medium text-gray-700">Interval (s)</label><input id="interval_sec" type="number" value="60" class="form-input mt-1 block w-full"/></div><div><label for="timeout_sec" class="text-sm font-medium text-gray-700">Timeout (s)</label><input id="timeout_sec" type="number" value="10" class="form-input mt-1 block w-full"/></div></div><div id="httpStatusContainer" class="hidden"><label for="expected_http_status" class="text-sm font-medium text-gray-700">Expected HTTP status</label><input id="expected_http_status" type="number" class="form-input mt-1 block w-full"/></div><div class="flex items-center gap-6 pt-2"><div class="flex items-center gap-2"><input id="enabled" type="checkbox" checked class="form-checkbox"/><label for="enabled" class="text-sm font-medium text-gray-700">Enabled</label></div><div class="flex items-center gap-2"><input id="notifications" type="checkbox" checked class="form-checkbox"/><label for="notifications" class="text-sm font-medium text-gray-700">Notifications</label></div></div><div class="flex gap-3 pt-2"><button type="submit" id="saveMonitorBtn" class="inline-flex justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors disabled:opacity-50">Save</button><button type="button" id="resetBtn" class="inline-flex justify-center rounded-md border border-gray-300 bg-white py-2 px-4 text-sm font-semibold text-gray-700 shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors">Reset</button></div></form></div>
        <div class="lg:col-span-3 bg-white border border-gray-200 rounded-lg shadow-sm p-4 self-start"><div class="flex items-center justify-between mb-3"><h2 class="text-lg font-semibold text-gray-900">Monitors</h2><button id="refreshBtn" class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors">Refresh</button></div><div id="list" class="space-y-2"></div></div>
    </main>
    <section class="bg-white border border-gray-200 rounded-lg shadow-sm p-4 mb-6"><h2 class="text-lg font-semibold mb-4 text-gray-900">Admin Actions</h2><div class="space-y-4"><h3 class="font-semibold text-gray-800">Change Password</h3><form id="passwordForm" class="space-y-4 md:w-1/2"><div><label class="text-sm font-medium text-gray-700">Current Password</label><input name="current_password" type="password" class="form-input mt-1 block w-full" required/></div><div><label class="text-sm font-medium text-gray-700">New Password</label><input name="new_password" type="password" class="form-input mt-1 block w-full" required/></div><div><label class="text-sm font-medium text-gray-700">Confirm New Password</label><input name="confirm_password" type="password" class="form-input mt-1 block w-full" required/></div><button type="submit" id="savePasswordBtn" class="inline-flex justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors disabled:opacity-50">Update Password</button></form></div></section>
    <section class="bg-white border border-gray-200 rounded-lg shadow-sm p-4 mb-6"><h2 class="text-lg font-semibold mb-4 text-gray-900">Settings</h2><form id="settingsForm" class="space-y-6"><div class="grid md:grid-cols-2 gap-x-6 gap-y-4">
        <div class="space-y-4"><h3 class="font-semibold text-gray-800">General & Recipients</h3><div><label class="text-sm font-medium text-gray-700">App Title</label><input name="app_title" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">App Logo URL</label><input name="app_logo_url" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Footer HTML</label><input name="footer_html" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Re-alert Interval (minutes)</label><input name="re_alert_minutes" type="number" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Microsoft Teams Webhook URL</label><input name="teams_webhook_url" type="password" placeholder="Unchanged" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Notification Emails</label><input name="notification_emails" class="form-input mt-1 block w-full" placeholder="comma-separated"/></div><div><label class="text-sm font-medium text-gray-700">Notification Phone Numbers</label><input name="notification_phone_numbers" class="form-input mt-1 block w-full" placeholder="comma-separated, E.164 format"/></div></div>
        <div class="space-y-4"><h3 class="font-semibold text-gray-800">SMTP & AWS Settings</h3><div class="grid grid-cols-1 sm:grid-cols-2 gap-4"><div><label class="text-sm font-medium text-gray-700">SMTP Host</label><input name="smtp_host" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">SMTP Port</label><input name="smtp_port" type="number" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">SMTP User</label><input name="smtp_user" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">SMTP Password</label><input name="smtp_password" type="password" placeholder="Unchanged" class="form-input mt-1 block w-full"/></div><div class="sm:col-span-2"><label class="text-sm font-medium text-gray-700">From Email</label><input name="smtp_from_email" class="form-input mt-1 block w-full"/></div><div class="flex items-center gap-2"><input name="smtp_use_tls" type="checkbox" class="form-checkbox"/><label class="text-sm font-medium text-gray-700">Use TLS</label></div></div><div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-gray-200"><div><label class="text-sm font-medium text-gray-700">AWS Access Key</label><input name="aws_access_key_id" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">AWS Secret Key</label><input name="aws_secret_access_key" type="password" placeholder="Unchanged" class="form-input mt-1 block w-full"/></div><div class="sm:col-span-2"><label class="text-sm font-medium text-gray-700">AWS Region</label><input name="aws_region" class="form-input mt-1 block w-full"/></div></div></div></div>
        <button type="submit" id="saveSettingsBtn" class="inline-flex justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors disabled:opacity-50">Save Settings</button>
    </form></section>
</div>
<footer class="w-full text-center text-sm text-gray-500 py-4 mt-6">__FOOTER_HTML__</footer>
<template id="rowTpl"><div class="p-3 rounded-lg bg-gray-50/50 border border-gray-200 flex items-center justify-between transition-colors hover:bg-gray-100"><div class="flex items-center gap-3"><span data-enabled-indicator class="w-2.5 h-2.5 rounded-full" title="Status"></span><div><div class="font-semibold text-gray-900" data-name></div><div class="text-xs text-gray-500 break-all" data-sub></div></div></div><div class="space-x-3"><button data-edit title="Edit Monitor" class="text-sm font-medium text-blue-600 hover:text-blue-500">Edit</button><button data-del title="Delete Monitor" class="text-sm font-medium text-red-600 hover:text-red-500">Delete</button></div></div></template>
<div id="toast" class="fixed bottom-4 right-4 hidden bg-gray-900 text-white rounded-lg px-4 py-2 shadow-lg"></div>
<script>
    const $=(sel)=>document.querySelector(sel),api=(url,opts)=>fetch(url,{credentials:"include",...opts}).then(res=>401===res.status?window.location="/login":res);function toast(t,e=!1){const s=$("#toast");s.textContent=t,s.className=`fixed bottom-4 right-4 shadow-lg rounded-lg px-4 py-2 text-white ${e?"bg-red-600":"bg-gray-900"}`,setTimeout(()=>s.classList.add("hidden"),3e3)}async function listMonitors(){const t=$("#list");t.innerHTML=`<p class="text-sm text-gray-500 animate-pulse">Loading monitors...</p>`;const e=await api("/api/targets"),s=await e.json(),o=$("#rowTpl");t.innerHTML="",0===s.length?t.innerHTML=`<p class="text-sm text-gray-500">No monitors configured yet.</p>`:s.forEach(e=>{const s=o.content.cloneNode(!0);s.querySelector("[data-name]").textContent=`${e.name} (${e.type})`,s.querySelector("[data-sub]").textContent=`${e.target} • every ${e.interval_sec}s`;const i=s.querySelector("[data-enabled-indicator]");i.className=`w-2.5 h-2.5 rounded-full ${e.enabled?"bg-green-500":"bg-gray-400"}`,i.title=e.enabled?"Enabled":"Disabled",s.querySelector("[data-edit]").onclick=()=>fillForm(e),s.querySelector("[data-del]").onclick=()=>deleteMonitor(e.id),t.appendChild(s)})}function fillForm(t){$("#id").value=t.id,Object.keys(t).forEach(e=>{const s=$(`#${e}`);s&&("checkbox"===s.type?s.checked=!!t[e]:s.value=t[e]??"")}),$("#type").dispatchEvent(new Event("change")),window.scrollTo({top:0,behavior:"smooth"})}async function deleteMonitor(t){confirm("Delete this monitor?")&&(await api(`/api/targets/${t}`,{method:"DELETE"}),toast("Monitor deleted"),listMonitors())}function clearForm(){$("#monitorForm").reset(),$("#id").value="",$("#type").dispatchEvent(new Event("change"))}$("#refreshBtn").onclick=listMonitors,$("#resetBtn").onclick=()=>{clearForm()};$("#type").addEventListener("change",t=>$("#httpStatusContainer").classList.toggle("hidden","http"!==t.target.value)),$("#monitorForm").onsubmit=async t=>{t.preventDefault();const e=$("#saveMonitorBtn");e.disabled=!0,e.textContent="Saving...";const s=$("#id").value,o={name:$("#name").value,type:$("#type").value,target:$("#target").value,interval_sec:parseInt($("#interval_sec").value)||60,timeout_sec:parseInt($("#timeout_sec").value)||10,expected_http_status:$("#expected_http_status").value?parseInt($("#expected_http_status").value):null,enabled:$("#enabled").checked,notifications:$("#notifications").checked,meta:{}},i=await api(s?`/api/targets/${s}`:"/api/targets",{method:s?"PUT":"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});if(e.disabled=!1,e.textContent="Save",!i.ok)return void toast("Error saving monitor: "+await i.text(),!0);toast("Monitor saved"),clearForm(),listMonitors()};async function loadSettings(){const t=await api("/api/settings"),e=await t.json(),s=$("#settingsForm");Object.keys(e).forEach(t=>{const o=s.elements[t];o&&("checkbox"===o.type?o.checked="true"===e[t]:"password"!==o.type?o.value=e[t]||"":"")})}$("#settingsForm").onsubmit=async t=>{t.preventDefault();const e=$("#saveSettingsBtn");e.disabled=!0,e.textContent="Saving...";const s={};(new FormData(t.target)).forEach((t,e)=>s[e]=t),t.target.querySelectorAll("input[type=checkbox]").forEach(t=>s[t.name]=t.checked.toString());const o=await api("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)});if(e.disabled=!1,e.textContent="Save Settings",!o.ok)return void toast("Error saving settings",!0);toast("Settings saved. Page will reload to apply changes."),setTimeout(()=>window.location.reload(),1500)};$("#passwordForm").onsubmit=async t=>{t.preventDefault();const e=$("#savePasswordBtn");e.disabled=!0,e.textContent="Saving...";const s={};(new FormData(t.target)).forEach((t,e)=>s[e]=t);const o=await api("/api/user/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)});if(e.disabled=!1,e.textContent="Update Password",!o.ok){const t=await o.json();return void toast(`Error: ${t.detail||"Unknown error"}`,!0)}toast("Password updated successfully."),t.target.reset()};document.addEventListener("DOMContentLoaded",()=>{listMonitors(),loadSettings(),$("#type").dispatchEvent(new Event("change"))});
</script>
</body></html>
""".replace("{MONITOR_TYPE_OPTIONS}", "".join([f"<option value='{t.value}'>{t.name.replace('_', ' ').title()}</option>" for t in MonitorType]))

LOGIN_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Login • __APP_TITLE__</title><script src="https://cdn.tailwindcss.com"></script><script src="https://cdn.tailwindcss.com?plugins=forms"></script></head>
<body class="bg-gray-50 text-gray-800 min-h-screen flex flex-col justify-center items-center p-4 font-sans">
<main class="w-full max-w-sm"><form method="post" action="/login" class="bg-white border border-gray-200 p-6 rounded-xl shadow-sm space-y-4">
<div class="flex items-center gap-3 mb-4"><img src="__APP_LOGO_URL__" alt="Logo" class="h-10"/><h1 class="text-xl font-bold text-gray-900">Admin Login</h1></div>
<div><label for="username" class="text-sm font-medium text-gray-700">Username</label><input name="username" id="username" class="form-input mt-1 block w-full" required/></div>
<div><label for="password" class="text-sm font-medium text-gray-700">Password</label><input type="password" name="password" id="password" class="form-input mt-1 block w-full" required/></div>
<button type="submit" class="w-full inline-flex justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors">Login</button>
</form></main><footer class="text-center text-sm text-gray-500 py-4 mt-8">__FOOTER_HTML__</footer></body></html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard_page(auth_result: Optional[RedirectResponse] = Depends(page_auth_check)):
    return auth_result or HTMLResponse(render_template(DASHBOARD_HTML))

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(auth_result: Optional[RedirectResponse] = Depends(page_auth_check)):
    return auth_result or HTMLResponse(render_template(ADMIN_HTML))

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(render_template(LOGIN_HTML))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
