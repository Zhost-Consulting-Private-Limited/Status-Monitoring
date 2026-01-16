"""
Z Monitor: Stable & Secure Infrastructure Health Monitor
======================================================

A single-file FastAPI application architected for robust, stateful monitoring with
multi-client management. This is the final, stable, production-ready version
incorporating all features and critical bug fixes.

Features
--------
- **STABLE & RELIABLE:** All known startup and runtime bugs have been resolved,
  including structural flaws and missing imports.
- **On-Demand Report Export:** Generate and download downtime reports in CSV
  format for any custom date range from the admin panel.
- **Automated Database Migrations:** On startup, the application automatically
  checks for and adds new columns to existing tables.
- **Paginated Log Viewer:** View the detailed status history for any monitor,
  with pagination (25 logs per page).
- **Client Management (CRUD):** Add, edit, and delete clients; the dashboard is
  now grouped by client.
- **Stateful Alerting Engine:** Sends configurable re-alerts for persistent issues
  and "resolved" notifications upon recovery.
- **Secure Password Changes:** A dedicated UI and secure API endpoint for
  changing the admin password.
- **Fully Authenticated UI:** All pages are protected and require a login.
- **Multi-Channel Notifications:** Alerts via Email (SMTP), SMS (AWS),
  and Microsoft Teams (Webhook).

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
   export DATABASE_URL="sqlite:///./zmonitor.db"

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
import io
import csv
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
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel as PydanticBaseModel
from sqlmodel import Field, SQLModel, Session, create_engine, select
from sqlalchemy import inspect, text, func  # **CRITICAL FIX**: Added missing 'func' import
from sqlalchemy.exc import OperationalError

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
APP_LOGO_URL = os.getenv("APP_LOGO_URL", "https://xicon.co.in/assets/img/logo.png")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./zmonitor.db")
DEFAULT_FOOTER_HTML = os.getenv("FOOTER_HTML", "Powered By: Bithost &copy; ZHOST CONSULTING PRIVATE LIMITED")
DEFAULT_RE_ALERT_MINUTES = int(os.getenv("RE_ALERT_MINUTES", "30"))
DEFAULT_REPORT_FREQUENCY = os.getenv("REPORT_FREQUENCY", "monthly")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# --- Database Models ---
class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)

class MonitorType(str, Enum): HTTP="http"; TCP="tcp"; DNS_A="dns_a"; SSL_CERT="ssl_cert"; WHOIS="whois"; INTERNET="internet"; ICMP="icmp"

class MonitorTarget(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str; type: MonitorType; target: str
    interval_sec: int = 60; timeout_sec: int = 10; expected_http_status: Optional[int] = None
    meta: str = Field(default="{}"); enabled: bool = True; notifications: bool = True
    client_id: Optional[int] = Field(default=None, foreign_key="client.id")
    last_status: str = Field(default="unknown")
    status_since: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    last_alert_sent: Optional[dt.datetime] = Field(default=None)

class MonitorStatus(SQLModel, table=True): id: Optional[int]=Field(default=None, primary_key=True); target_id: int=Field(index=True); status: str; detail: str; checked_at: dt.datetime=Field(default_factory=dt.datetime.utcnow)
class User(SQLModel, table=True): id: Optional[int]=Field(default=None, primary_key=True); username: str=Field(unique=True, index=True); password_hash: str
class SystemSetting(SQLModel, table=True): key: str=Field(primary_key=True); value: str


# --- Database Setup & Migration ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, echo=False)

def run_migrations():
    logging.info("Running database schema check...")
    inspector = inspect(engine)
    table_name = "monitortarget"
    if not inspector.has_table(table_name):
        logging.info("Table 'monitortarget' not found. Will be created by SQLModel.")
        return

    columns = [col['name'] for col in inspector.get_columns(table_name)]
    migrations_to_run = {
        'client_id': 'ALTER TABLE monitortarget ADD COLUMN client_id INTEGER REFERENCES client(id)',
        'last_status': "ALTER TABLE monitortarget ADD COLUMN last_status VARCHAR DEFAULT 'unknown' NOT NULL",
        'status_since': "ALTER TABLE monitortarget ADD COLUMN status_since DATETIME",
        'last_alert_sent': 'ALTER TABLE monitortarget ADD COLUMN last_alert_sent DATETIME',
    }
    
    with engine.connect() as connection:
        for column, alter_sql in migrations_to_run.items():
            if column not in columns:
                try:
                    logging.info(f"Column '{column}' not found in '{table_name}'. Running migration...")
                    connection.execute(text(alter_sql))
                    logging.info(f"Successfully added column '{column}'.")
                except OperationalError as e:
                    logging.error(f"Failed to run migration for column '{column}': {e}")
        if 'status_since' not in columns:
            try:
                connection.execute(text(f"UPDATE {table_name} SET status_since = '{dt.datetime.utcnow()}' WHERE status_since IS NULL"))
            except Exception: pass
        connection.commit()
    logging.info("Database schema check complete.")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        if not s.exec(select(User).where(User.username == ADMIN_USERNAME)).first():
            s.add(User(username=ADMIN_USERNAME, password_hash=pwd_context.hash(ADMIN_PASSWORD))); s.commit()
        if not s.exec(select(MonitorTarget)).first():
            s.add(MonitorTarget(name="Internet", type=MonitorType.INTERNET, target="", interval_sec=60)); s.commit()

# --- Auth Helpers ---
_SETTINGS_CACHE = {}
def get_setting(key: str, default: Any = None) -> Any:
    if key in _SETTINGS_CACHE: return _SETTINGS_CACHE[key]
    with Session(engine) as s:
        db_val = s.get(SystemSetting, key); val = db_val.value if db_val else os.getenv(key.upper(), default)
        _SETTINGS_CACHE[key] = val; return val

COOKIE_NAME = "zmonitor_token"
JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "1440"))
def create_token(username: str) -> str:
    now = dt.datetime.utcnow(); payload = {"sub": username, "iat": now, "exp": now + dt.timedelta(minutes=JWT_TTL_MIN)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
def get_current_user(token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)) -> str:
    if not token: raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"]); username = payload.get("sub")
        if not username: raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError: raise HTTPException(status_code=401, detail="Invalid token")
def page_auth_check(token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)):
    if not token: return RedirectResponse("/login")
    try: jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except JWTError: return RedirectResponse("/login")
    return None

# --- FastAPI App Initialization ---
app = FastAPI(title="Z Monitor")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- Notification Logic ---
async def send_notification(subject: str, detail: str, status: str):
    html_body = f"<b>{subject}</b><br><br>Details: {detail}"; sms_msg = f"{subject}. Detail: {detail[:80]}"
    asyncio.create_task(send_teams_notification(subject, detail, status)); asyncio.create_task(send_email_notification(subject, html_body)); asyncio.create_task(send_sms_notification(sms_msg))
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

async def report_scheduler_loop():
    while True:
        now = dt.datetime.utcnow()
        frequency = get_setting("report_frequency", DEFAULT_REPORT_FREQUENCY)
        if frequency == 'weekly':
            days_until_monday = (7 - now.weekday()) % 7
            next_run_date = now.date() + dt.timedelta(days=days_until_monday or 7)
            next_run = dt.datetime.combine(next_run_date, dt.time(hour=1))
            report_start_date = next_run_date - dt.timedelta(days=7)
            period_name = f"Week of {report_start_date:%B %d, %Y}"
        else: # monthly
            next_run = (now.replace(day=1) + dt.timedelta(days=32)).replace(day=1, hour=1)
            report_start_date = (next_run - dt.timedelta(days=1)).replace(day=1)
            period_name = f"{report_start_date:%B %Y}"
        
        sleep_duration = (next_run - now).total_seconds()
        if sleep_duration < 0: sleep_duration = 60 # Safeguard against loop
        logging.info(f"Report scheduler sleeping for {sleep_duration/3600:.2f} hours (frequency: {frequency}).")
        await asyncio.sleep(sleep_duration)

        try:
            report_end_date = next_run - dt.timedelta(seconds=1)
            logging.info(f"Generating {frequency} report for period ending {report_end_date:%Y-%m-%d}")
            report_lines = []
            with Session(engine) as s:
                for t in s.exec(select(MonitorTarget)).all():
                    down_seconds = sum(t.interval_sec for _ in s.exec(select(MonitorStatus).where(MonitorStatus.target_id==t.id, MonitorStatus.status=='down', MonitorStatus.checked_at.between(report_start_date, report_end_date))).all())
                    if down_seconds > 0: report_lines.append(f"<li><b>{t.name}</b> was down for ~<b>{str(dt.timedelta(seconds=down_seconds))}</b>.</li>")
            if report_lines:
                subject = f"Z Monitor Downtime Report: {period_name}"; body = f"<h2>Downtime Report for {period_name}</h2><ul>{''.join(report_lines)}</ul>"
                await send_email_notification(subject, body)
        except Exception as e: logging.error(f"Report generation failed: {e}", exc_info=True)

async def cleanup_old_logs(days_to_keep: int = 30):
    """
    Delete log entries older than the specified number of days.
    This helps keep the database size manageable.
    """
    try:
        cutoff_date = dt.datetime.utcnow() - dt.timedelta(days=days_to_keep)
        with Session(engine) as s:
            # Delete old log entries
            delete_stmt = text("DELETE FROM monitorstatus WHERE checked_at < :cutoff")
            result = s.execute(delete_stmt, {"cutoff": cutoff_date})
            s.commit()
            deleted_count = result.rowcount
            
            if deleted_count > 0:
                logging.info(f"Cleaned up {deleted_count} log entries older than {days_to_keep} days")
            else:
                logging.info(f"No log entries older than {days_to_keep} days to clean up")
                
            return deleted_count
    except Exception as e:
        logging.error(f"Error during log cleanup: {e}")
        return 0

async def simple_cleanup_scheduler_loop():
    """
    Simple version that runs cleanup every 24 hours from startup.
    """
    while True:
        try:
            # Run cleanup once a day
            await asyncio.sleep(24 * 3600)  # 24 hours
            deleted_count = await cleanup_old_logs(31)
            logging.info(f"Daily log cleanup completed. Deleted {deleted_count} old records.")
        except asyncio.CancelledError:
            logging.info("Cleanup scheduler cancelled")
            break
        except Exception as e:
            logging.error(f"Cleanup scheduler error: {e}", exc_info=True)
            # Wait 1 hour before retrying on error
            await asyncio.sleep(3600)

async def ensure_task_running(target_id: int):
    if target_id not in _tasks or _tasks[target_id].done(): _tasks[target_id] = asyncio.create_task(scheduler_loop(target_id))

@app.on_event("startup")
async def startup_event():
    run_migrations()
    create_db_and_tables()
    with Session(engine) as s:
        for t in s.exec(select(MonitorTarget).where(MonitorTarget.enabled == True)).all():
            await ensure_task_running(t.id)
    asyncio.create_task(report_scheduler_loop())
    asyncio.create_task(simple_cleanup_scheduler_loop())

# --- API Schemas & Routes ---
class ClientIn(PydanticBaseModel): name: str
class ClientOut(ClientIn): id: int
class TargetIn(SQLModel): name: str; type: MonitorType; target: str; interval_sec: int=60; timeout_sec: int=10; expected_http_status: Optional[int]=None; meta: Dict[str, Any]={}; enabled: bool=True; notifications: bool=True; client_id: Optional[int] = None
class TargetOut(TargetIn): id: int
class StatusOut(SQLModel): target_id: int; target_name: str; type: MonitorType; status: str; detail: str; checked_at: dt.datetime; client_id: Optional[int]
class ClientGroupOut(PydanticBaseModel): client_id: Optional[int]; client_name: str; monitors: List[StatusOut]
class LogsOut(PydanticBaseModel): logs: List[MonitorStatus]; total: int; page: int; size: int
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
    keys = ["app_title", "app_logo_url", "footer_html", "re_alert_minutes", "report_frequency", "teams_webhook_url", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from_email", "smtp_use_tls", "aws_access_key_id", "aws_secret_access_key", "aws_region", "notification_emails", "notification_phone_numbers"]
    defaults = {"app_title": APP_TITLE, "app_logo_url": APP_LOGO_URL, "footer_html": DEFAULT_FOOTER_HTML, "re_alert_minutes": DEFAULT_RE_ALERT_MINUTES, "report_frequency": DEFAULT_REPORT_FREQUENCY}
    return {key: get_setting(key, defaults.get(key, "")) for key in keys}
@app.post("/api/settings")
async def save_settings(payload: Dict[str, str], user: str=Depends(get_current_user)):
    with Session(engine) as s:
        for key, value in payload.items():
            if ('password' in key or 'secret' in key or 'webhook' in key) and not value: continue
            setting = s.get(SystemSetting, key) or SystemSetting(key=key)
            setting.value = value; s.add(setting)
        s.commit(); _SETTINGS_CACHE.clear(); return {"ok": True}
@app.get("/api/clients", response_model=List[ClientOut])
async def list_clients(user: str = Depends(get_current_user)):
    with Session(engine) as s: return s.exec(select(Client)).all()
@app.post("/api/clients", response_model=ClientOut)
async def create_client(payload: ClientIn, user: str = Depends(get_current_user)):
    with Session(engine) as s:
        client = Client.from_orm(payload); s.add(client); s.commit(); s.refresh(client); return client
@app.put("/api/clients/{client_id}", response_model=ClientOut)
async def update_client(client_id: int, payload: ClientIn, user: str = Depends(get_current_user)):
    with Session(engine) as s:
        client = s.get(Client, client_id); client.name = payload.name; s.add(client); s.commit(); s.refresh(client); return client
@app.delete("/api/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(client_id: int, user: str = Depends(get_current_user)):
    with Session(engine) as s:
        for target in s.exec(select(MonitorTarget).where(MonitorTarget.client_id == client_id)).all():
            target.client_id = None; s.add(target)
        client = s.get(Client, client_id); s.delete(client); s.commit()
    return
@app.get("/api/targets", response_model=List[TargetOut])
async def list_targets(user: str = Depends(get_current_user)):
    with Session(engine) as s: return [TargetOut(**(t.dict() | {'meta': json.loads(t.meta)})) for t in s.exec(select(MonitorTarget)).all()]
@app.post("/api/targets", response_model=TargetOut)
async def create_target(payload: TargetIn, user: str=Depends(get_current_user)):
    with Session(engine) as s:
        t = MonitorTarget.from_orm(payload, {"meta": json.dumps(payload.meta)}); s.add(t); s.commit(); s.refresh(t)
        await ensure_task_running(t.id); data = t.dict(); data['meta'] = json.loads(data['meta']); return TargetOut(**data)
@app.put("/api/targets/{target_id}", response_model=TargetOut)
async def update_target(target_id: int, payload: TargetIn, user: str = Depends(get_current_user)):
    with Session(engine) as s:
        t = s.get(MonitorTarget, target_id)
        for k, v in payload.dict(exclude_unset=True).items(): setattr(t, k, json.dumps(v) if k == "meta" else v)
        s.add(t); s.commit(); s.refresh(t)
        await ensure_task_running(t.id); data = t.dict(); data['meta'] = json.loads(data['meta']); return TargetOut(**data)
@app.delete("/api/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, user: str=Depends(get_current_user)):
    with Session(engine) as s:
        t = s.get(MonitorTarget, target_id); s.delete(t); s.commit()
    if task := _tasks.pop(target_id, None): task.cancel()
    return
@app.get("/api/status", response_model=List[ClientGroupOut])
async def get_latest_status(user: str=Depends(get_current_user)):
    with Session(engine) as s:
        groups = {c.id: ClientGroupOut(client_id=c.id, client_name=c.name, monitors=[]) for c in s.exec(select(Client)).all()}
        groups[None] = ClientGroupOut(client_id=None, client_name="Uncategorized Monitors", monitors=[])
        targets = {t.id: (t.name, t.type, t.client_id) for t in s.exec(select(MonitorTarget.id, MonitorTarget.name, MonitorTarget.type, MonitorTarget.client_id)).all()}
        subq = select(MonitorStatus.target_id, func.max(MonitorStatus.checked_at).label("mc")).group_by(MonitorStatus.target_id).subquery()
        stmt = select(MonitorStatus).join(subq, (MonitorStatus.target_id == subq.c.target_id) & (MonitorStatus.checked_at == subq.c.mc))
        for r in s.exec(stmt).all():
            if r.target_id in targets:
                target_info = targets[r.target_id]
                status_out = StatusOut(**r.dict(), target_name=target_info[0], type=target_info[1], client_id=target_info[2])
                (groups.get(target_info[2]) or groups[None]).monitors.append(status_out)
    return [group for group in sorted(groups.values(), key=lambda g: g.client_name) if group.monitors]

# @app.get("/api/monitors/{target_id}/logs", response_model=LogsOut)
# async def get_monitor_logs(target_id: int, user: str=Depends(get_current_user), page: int = 1, size: int = 25):
#     with Session(engine) as s:
#         query = select(MonitorStatus).where(MonitorStatus.target_id == target_id).order_by(MonitorStatus.checked_at.desc())
#         total = s.exec(select(func.count()).select_from(query.subquery())).one()
#         logs = s.exec(query.offset((page - 1) * size).limit(size)).all()
#         return LogsOut(logs=logs, total=total, page=page, size=size)

@app.get("/api/monitors/{target_id}/logs", response_model=LogsOut)
async def get_monitor_logs(target_id: int, user: str=Depends(get_current_user), page: int = 1, size: int = 25):
    with Session(engine) as s:
        # Fix 1: Check if the monitor exists first
        target = s.get(MonitorTarget, target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Monitor not found")
        
        # Fix 2: Proper count query - count all logs for this target
        count_query = select(func.count()).select_from(MonitorStatus).where(MonitorStatus.target_id == target_id)
        total = s.exec(count_query).one()
        
        # Get paginated logs
        query = select(MonitorStatus).where(MonitorStatus.target_id == target_id).order_by(MonitorStatus.checked_at.desc())
        logs = s.exec(query.offset((page - 1) * size).limit(size)).all()
        
        return LogsOut(logs=logs, total=total, page=page, size=size)
        
@app.get("/api/reports/export")
async def export_report(user: str = Depends(get_current_user), start_date: dt.date = Query(...), end_date: dt.date = Query(...)):
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["Monitor Name", "Client Name", "Total Downtime (HH:MM:SS)"])
    start_dt, end_dt = dt.datetime.combine(start_date, dt.time.min), dt.datetime.combine(end_date, dt.time.max)
    with Session(engine) as s:
        monitors = s.exec(select(MonitorTarget)).all(); clients = {c.id: c.name for c in s.exec(select(Client)).all()}
        for t in monitors:
            down_count = s.exec(select(func.count()).select_from(select(MonitorStatus).where(MonitorStatus.target_id==t.id, MonitorStatus.status=='down', MonitorStatus.checked_at.between(start_dt, end_dt)))).one()
            if (down_seconds := down_count * t.interval_sec) > 0:
                writer.writerow([t.name, clients.get(t.client_id, "Uncategorized"), str(dt.timedelta(seconds=down_seconds))])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=downtime_report_{start_date}_to_{end_date}.csv"})

# --- Frontend HTML Templates & Page Routes ---
def render_template(html: str) -> str:
    return (html.replace("__APP_TITLE__", get_setting("app_title", APP_TITLE)).replace("__APP_LOGO_URL__", get_setting("app_logo_url", APP_LOGO_URL)).replace("__FOOTER_HTML__", get_setting("footer_html", DEFAULT_FOOTER_HTML)))

DASHBOARD_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>__APP_TITLE__</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-50 text-gray-800 flex flex-col min-h-screen font-sans">
<div class="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex-grow">
<header class="flex items-center justify-between py-4 border-b border-gray-200"><div class="flex items-center gap-3"><img src="__APP_LOGO_URL__" alt="Logo" class="h-8 sm:h-10"/><h1 class="text-xl sm:text-2xl font-bold text-gray-900">__APP_TITLE__</h1></div><nav><a class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors" href="/admin">Admin Panel</a></nav></header>
<main id="dashboard-groups" class="py-6 space-y-8"></main>
</div><footer class="w-full text-center text-sm text-gray-500 py-4">__FOOTER_HTML__</footer>
<script>
    const groupsContainer=document.getElementById("dashboard-groups");function renderLoading(){groupsContainer.innerHTML='<p class="text-center text-gray-500 animate-pulse">Loading status...</p>'}
    async function fetchStatuses(){try{const res=await fetch("/api/status",{credentials:"include"});if(401===res.status)return void(window.location="/login");if(!res.ok)throw new Error("Network response error");const clientGroups=await res.json();if(groupsContainer.innerHTML="",0===clientGroups.length)return void(groupsContainer.innerHTML='<p class="text-center text-gray-500">No monitors configured.</p>');const statusStyles={up:{dot:"bg-green-500",text:"text-green-800"},down:{dot:"bg-red-500",text:"text-red-800"},degraded:{dot:"bg-yellow-500",text:"text-yellow-800"},unknown:{dot:"bg-gray-500",text:"text-gray-800"}};for(const group of clientGroups){const groupEl=document.createElement("div");let tableRows="";for(const item of group.monitors){const style=statusStyles[item.status]||statusStyles.unknown;tableRows+=`<tr class="hover:bg-gray-50 transition-colors"><td class="px-6 py-4 whitespace-nowrap" title="${item.status}"><div class="flex items-center"><div class="h-2.5 w-2.5 rounded-full ${style.dot} mr-2"></div><span class="font-medium ${style.text}">${item.status.charAt(0).toUpperCase()+item.status.slice(1)}</span></div></td><td class="px-6 py-4 whitespace-nowrap"><div class="text-sm font-semibold text-gray-900">${item.target_name}</div><div class="text-xs text-gray-500">${item.type.replace("_"," ").toUpperCase()}</div></td><td class="px-6 py-4 text-sm text-gray-600 break-words">${item.detail}</td><td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(item.checked_at).toLocaleString()}</td></tr>`}
    groupEl.innerHTML=`<h2 class="text-lg font-semibold text-gray-900 mb-2">${group.client_name}</h2><div class="overflow-x-auto bg-white border border-gray-200 rounded-lg shadow-sm"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-100"><tr><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Status</th><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Name</th><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Details</th><th scope="col" class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">Last Checked</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">${tableRows}</tbody></table></div>`,groupsContainer.appendChild(groupEl)}}catch(e){console.error("Fetch error",e),groupsContainer.innerHTML='<p class="text-center text-red-500">Failed to load status data.</p>'}}
    renderLoading();fetchStatuses();setInterval(fetchStatuses,10e3);
</script></body></html>
"""
ADMIN_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Admin • __APP_TITLE__</title><script src="https://cdn.tailwindcss.com"></script><script src="https://cdn.tailwindcss.com?plugins=forms"></script></head>
<body class="bg-gray-50 text-gray-800 flex flex-col min-h-screen font-sans">
<div class="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 flex-grow">
    <header class="flex items-center justify-between py-4 border-b border-gray-200"><div class="flex items-center gap-3"><img src="__APP_LOGO_URL__" alt="Logo" class="h-8 sm:h-10"/><h1 class="text-xl sm:text-2xl font-bold text-gray-900">Admin Panel</h1></div><div class="space-x-4"><a href="/" class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors">Dashboard</a><form method="post" action="/logout" class="inline"><button class="text-sm font-medium text-blue-600 hover:text-blue-500 transition-colors">Logout</button></form></div></header>
    <main class="grid lg:grid-cols-5 gap-6 py-6"><div class="lg:col-span-2 space-y-6 self-start"><div class="bg-white border border-gray-200 rounded-lg shadow-sm p-4"><h2 class="text-lg font-semibold mb-3 text-gray-900">Add / Update Monitor</h2><form id="monitorForm" class="space-y-4"><input type="hidden" id="id"/><div><label class="text-sm font-medium text-gray-700">Client</label><select id="client_id" class="form-select mt-1 block w-full"><option value="">Uncategorized</option></select></div><div><label class="text-sm font-medium text-gray-700">Name</label><input id="name" type="text" class="form-input mt-1 block w-full" required/></div><div><label class="text-sm font-medium text-gray-700">Type</label><select id="type" class="form-select mt-1 block w-full">{MONITOR_TYPE_OPTIONS}</select></div><div><label class="text-sm font-medium text-gray-700">Target</label><input id="target" type="text" class="form-input mt-1 block w-full" placeholder="URL / host:port / domain"/></div><div class="grid grid-cols-2 gap-4"><div><label class="text-sm font-medium text-gray-700">Interval (s)</label><input id="interval_sec" type="number" value="60" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Timeout (s)</label><input id="timeout_sec" type="number" value="10" class="form-input mt-1 block w-full"/></div></div><div id="httpStatusContainer" class="hidden"><label class="text-sm font-medium text-gray-700">Expected HTTP status</label><input id="expected_http_status" type="number" class="form-input mt-1 block w-full"/></div><div class="flex items-center gap-6 pt-2"><div class="flex items-center gap-2"><input id="enabled" type="checkbox" checked class="form-checkbox"/><label for="enabled" class="text-sm font-medium text-gray-700">Enabled</label></div><div class="flex items-center gap-2"><input id="notifications" type="checkbox" checked class="form-checkbox"/><label for="notifications" class="text-sm font-medium text-gray-700">Notifications</label></div></div><div class="flex gap-3 pt-2"><button type="submit" id="saveMonitorBtn" class="btn-primary">Save Monitor</button><button type="button" id="resetMonitorBtn" class="btn-secondary">Reset</button></div></form></div></div>
        <div class="lg:col-span-3 space-y-6 self-start"><div class="bg-white border border-gray-200 rounded-lg shadow-sm p-4"><div class="flex items-center justify-between mb-3"><h2 class="text-lg font-semibold text-gray-900">Monitors</h2><button id="refreshMonitorsBtn" class="text-sm font-medium text-blue-600 hover:text-blue-500">Refresh</button></div><div id="monitorsList" class="space-y-2"></div></div><div class="bg-white border border-gray-200 rounded-lg shadow-sm p-4"><h2 class="text-lg font-semibold mb-3 text-gray-900">Manage Clients</h2><form id="clientForm" class="flex items-end gap-2 mb-4"><input type="hidden" id="clientId"/><div class="flex-grow"><label class="text-sm font-medium text-gray-700">Client Name</label><input id="clientName" type="text" class="form-input mt-1 block w-full" required/></div><div class="flex-shrink-0 flex gap-2"><button type="submit" id="saveClientBtn" class="btn-primary">Save</button><button type="button" id="resetClientBtn" class="btn-secondary">Clear</button></div></form><div id="clientsList" class="space-y-2"></div></div></div>
    </main>
    <section class="bg-white border border-gray-200 rounded-lg shadow-sm p-4 mb-6"><h2 class="text-lg font-semibold mb-4 text-gray-900">Admin Actions</h2><div class="grid md:grid-cols-2 gap-x-8 gap-y-6"><div class="space-y-4"><h3 class="font-semibold text-gray-800">Change Password</h3><form id="passwordForm" class="space-y-4"><div><label class="text-sm font-medium text-gray-700">Current Password</label><input name="current_password" type="password" class="form-input mt-1 block w-full" required/></div><div><label class="text-sm font-medium text-gray-700">New Password</label><input name="new_password" type="password" class="form-input mt-1 block w-full" required/></div><div><label class="text-sm font-medium text-gray-700">Confirm New Password</label><input name="confirm_password" type="password" class="form-input mt-1 block w-full" required/></div><button type="submit" id="savePasswordBtn" class="btn-primary">Update Password</button></form></div><div class="space-y-4"><h3 class="font-semibold text-gray-800">Generate Report</h3><form id="reportForm" class="space-y-4"><div><label class="text-sm font-medium text-gray-700">Start Date</label><input name="start_date" type="date" class="form-input mt-1 block w-full" required/></div><div><label class="text-sm font-medium text-gray-700">End Date</label><input name="end_date" type="date" class="form-input mt-1 block w-full" required/></div><button type="submit" id="exportBtn" class="btn-primary">Export CSV</button></form></div></div></section>
    <section class="bg-white border border-gray-200 rounded-lg shadow-sm p-4 mb-6"><h2 class="text-lg font-semibold mb-4 text-gray-900">Settings</h2><form id="settingsForm" class="space-y-6"><div class="grid md:grid-cols-2 gap-x-6 gap-y-4"><div class="space-y-4"><h3 class="font-semibold text-gray-800">General & Recipients</h3><div><label class="text-sm font-medium text-gray-700">App Title</label><input name="app_title" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">App Logo URL</label><input name="app_logo_url" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Footer HTML</label><input name="footer_html" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Re-alert Interval (minutes)</label><input name="re_alert_minutes" type="number" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Report Frequency</label><select name="report_frequency" class="form-select mt-1 block w-full"><option value="monthly">Monthly</option><option value="weekly">Weekly</option></select></div><div><label class="text-sm font-medium text-gray-700">MS Teams Webhook</label><input name="teams_webhook_url" type="password" placeholder="Unchanged" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">Notification Emails</label><input name="notification_emails" class="form-input mt-1 block w-full" placeholder="comma-separated"/></div><div><label class="text-sm font-medium text-gray-700">Notification Phones</label><input name="notification_phone_numbers" class="form-input mt-1 block w-full" placeholder="comma-separated, E.164"/></div></div><div class="space-y-4"><h3 class="font-semibold text-gray-800">SMTP & AWS</h3><div class="grid grid-cols-1 sm:grid-cols-2 gap-4"><div><label class="text-sm font-medium text-gray-700">SMTP Host</label><input name="smtp_host" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">SMTP Port</label><input name="smtp_port" type="number" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">SMTP User</label><input name="smtp_user" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">SMTP Password</label><input name="smtp_password" type="password" placeholder="Unchanged" class="form-input mt-1 block w-full"/></div><div class="sm:col-span-2"><label class="text-sm font-medium text-gray-700">From Email</label><input name="smtp_from_email" class="form-input mt-1 block w-full"/></div><div class="flex items-center gap-2"><input name="smtp_use_tls" type="checkbox" class="form-checkbox"/><label class="text-sm font-medium text-gray-700">Use TLS</label></div></div><div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-gray-200"><div><label class="text-sm font-medium text-gray-700">AWS Access Key</label><input name="aws_access_key_id" class="form-input mt-1 block w-full"/></div><div><label class="text-sm font-medium text-gray-700">AWS Secret Key</label><input name="aws_secret_access_key" type="password" placeholder="Unchanged" class="form-input mt-1 block w-full"/></div><div class="sm:col-span-2"><label class="text-sm font-medium text-gray-700">AWS Region</label><input name="aws_region" class="form-input mt-1 block w-full"/></div></div></div></div><button type="submit" id="saveSettingsBtn" class="btn-primary">Save Settings</button></form></section>
</div>
<footer class="w-full text-center text-sm text-gray-500 py-4 mt-6">__FOOTER_HTML__</footer>
<template id="rowTpl"><div class="p-3 rounded-lg bg-gray-50/50 border border-gray-200 flex items-center justify-between transition-colors hover:bg-gray-100"><div class="flex items-center gap-3"><span data-indicator class="w-2.5 h-2.5 rounded-full"></span><div class="flex-grow"><div class="font-semibold text-gray-900" data-name></div><div class="text-xs text-gray-500 break-all" data-sub></div></div></div><div class="space-x-3 flex-shrink-0" data-actions></div></div></template>
<div id="toast" class="fixed bottom-4 right-4 hidden bg-gray-900 text-white rounded-lg px-4 py-2 shadow-lg"></div>
<style>.btn-primary{display:inline-flex;justify-content:center;border-radius:0.375rem;border:1px solid transparent;background-color:#4f46e5;padding:0.5rem 1rem;font-size:0.875rem;font-weight:600;color:white;box-shadow:0 1px 2px 0 rgba(0,0,0,0.05);transition:background-color 0.2s;}.btn-primary:hover{background-color:#4338ca;}.btn-primary:focus{outline:2px solid transparent;outline-offset:2px;box-shadow:0 0 0 2px #a5b4fc;}.btn-primary:disabled{opacity:0.5;}.btn-secondary{display:inline-flex;justify-content:center;border-radius:0.375rem;border:1px solid #d1d5db;background-color:white;padding:0.5rem 1rem;font-size:0.875rem;font-weight:600;color:#374151;box-shadow:0 1px 2px 0 rgba(0,0,0,0.05);transition:background-color 0.2s;}.btn-secondary:hover{background-color:#f9fafb;}</style>
<script>
    const $=(sel)=>document.querySelector(sel);const api=(url,opts)=>fetch(url,{credentials:"include",...opts}).then(res=>401===res.status?window.location="/login":res);function toast(t,e=!1){const s=$("#toast");s.textContent=t,s.className=`fixed bottom-4 right-4 shadow-lg rounded-lg px-4 py-2 text-white ${e?"bg-red-600":"bg-gray-900"}`,setTimeout(()=>s.classList.add("hidden"),3e3)}
    async function initAdminPage(){listMonitors();listClients();loadSettings();$("#type").dispatchEvent(new Event("change"))}
    async function listClients(){const t=$("#clientsList");t.innerHTML=`<p class="text-sm text-gray-500 animate-pulse">Loading clients...</p>`;const e=await api("/api/clients"),s=await e.json(),o=$("#rowTpl");t.innerHTML="",0===s.length?t.innerHTML=`<p class="text-sm text-gray-500">No clients configured yet.</p>`:s.forEach(e=>{const s=o.content.cloneNode(!0);s.querySelector("[data-name]").textContent=e.name,s.querySelector("[data-sub]").remove(),s.querySelector("[data-indicator]").remove();const i=s.querySelector("[data-actions]");i.innerHTML=`<button title="Edit Client" class="text-sm font-medium text-blue-600 hover:text-blue-500">Edit</button><button title="Delete Client" class="text-sm font-medium text-red-600 hover:text-red-500">Delete</button>`;i.children[0].onclick=()=>fillClientForm(e),i.children[1].onclick=()=>deleteClient(e.id),t.appendChild(s)});const i=$("#client_id");i.innerHTML='<option value="">Uncategorized</option>',s.forEach(t=>{const e=document.createElement("option");e.value=t.id,e.textContent=t.name,i.appendChild(e)})}
    function fillClientForm(t){$("#clientId").value=t.id,$("#clientName").value=t.name}async function deleteClient(t){confirm("Delete this client? Any assigned monitors will become uncategorized.")&&(await api(`/api/clients/${t}`,{method:"DELETE"}),toast("Client deleted"),listClients(),listMonitors())}
    function clearClientForm(){$("#clientForm").reset(),$("#clientId").value=""}
    $("#clientForm").onsubmit=async t=>{t.preventDefault();const e=$("#saveClientBtn");e.disabled=!0,e.textContent="Saving...";const s=$("#clientId").value,o={name:$("#clientName").value},i=await api(s?`/api/clients/${s}`:"/api/clients",{method:s?"PUT":"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});if(e.disabled=!1,e.textContent="Save",!i.ok)return void toast("Error saving client",!0);toast("Client saved"),clearClientForm(),listClients()};$("#resetClientBtn").onclick=()=>{clearClientForm()};
    async function listMonitors(){const t=$("#monitorsList");t.innerHTML=`<p class="text-sm text-gray-500 animate-pulse">Loading monitors...</p>`;const e=await api("/api/targets"),s=await e.json(),o=$("#rowTpl");t.innerHTML="",0===s.length?t.innerHTML=`<p class="text-sm text-gray-500">No monitors configured yet.</p>`:s.forEach(e=>{const s=o.content.cloneNode(!0);s.querySelector("[data-name]").textContent=e.name,s.querySelector("[data-sub]").textContent=`${e.target} • every ${e.interval_sec}s`;const i=s.querySelector("[data-indicator]");i.className=`w-2.5 h-2.5 rounded-full ${e.enabled?"bg-green-500":"bg-gray-400"}`,i.title=e.enabled?"Enabled":"Disabled";const n=s.querySelector("[data-actions]");n.innerHTML=`<a href="/monitors/${e.id}/logs" title="View Logs" class="text-sm font-medium text-gray-600 hover:text-gray-900">Logs</a><button title="Edit Monitor" class="text-sm font-medium text-blue-600 hover:text-blue-500">Edit</button><button title="Delete Monitor" class="text-sm font-medium text-red-600 hover:text-red-500">Delete</button>`;n.children[1].onclick=()=>fillMonitorForm(e),n.children[2].onclick=()=>deleteMonitor(e.id),t.appendChild(s)})}
    function fillMonitorForm(t){$("#id").value=t.id,Object.keys(t).forEach(e=>{const s=$(`#${e}`);s&&("checkbox"===s.type?s.checked=!!t[e]:s.value=t[e]??"")}),$("#type").dispatchEvent(new Event("change")),window.scrollTo({top:0,behavior:"smooth"})}async function deleteMonitor(t){confirm("Delete this monitor?")&&(await api(`/api/targets/${t}`,{method:"DELETE"}),toast("Monitor deleted"),listMonitors())}function clearMonitorForm(){$("#monitorForm").reset(),$("#id").value="",$("#type").dispatchEvent(new Event("change"))}
    $("#refreshMonitorsBtn").onclick=listMonitors,$("#resetMonitorBtn").onclick=()=>{clearMonitorForm()};$("#type").addEventListener("change",t=>$("#httpStatusContainer").classList.toggle("hidden","http"!==t.target.value)),$("#monitorForm").onsubmit=async t=>{t.preventDefault();const e=$("#saveMonitorBtn");e.disabled=!0,e.textContent="Saving...";const s=$("#id").value,o={name:$("#name").value,type:$("#type").value,target:$("#target").value,interval_sec:parseInt($("#interval_sec").value)||60,timeout_sec:parseInt($("#timeout_sec").value)||10,expected_http_status:$("#expected_http_status").value?parseInt($("#expected_http_status").value):null,client_id:$("#client_id").value?parseInt($("#client_id").value):null,enabled:$("#enabled").checked,notifications:$("#notifications").checked,meta:{}},i=await api(s?`/api/targets/${s}`:"/api/targets",{method:s?"PUT":"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});if(e.disabled=!1,e.textContent="Save Monitor",!i.ok)return void toast("Error saving monitor: "+await i.text(),!0);toast("Monitor saved"),clearMonitorForm(),listMonitors(),listClients()};
    async function loadSettings(){const t=await api("/api/settings"),e=await t.json(),s=$("#settingsForm");Object.keys(e).forEach(t=>{const o=s.elements[t];o&&("checkbox"===o.type?o.checked="true"===e[t]:"password"!==o.type?o.value=e[t]||"":"")})}
    $("#settingsForm").onsubmit=async t=>{t.preventDefault();const e=$("#saveSettingsBtn");e.disabled=!0,e.textContent="Saving...";const s={};(new FormData(t.target)).forEach((t,e)=>s[e]=t),t.target.querySelectorAll("input[type=checkbox]").forEach(t=>s[t.name]=t.checked.toString());const o=await api("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)});if(e.disabled=!1,e.textContent="Save Settings",!o.ok)return void toast("Error saving settings",!0);toast("Settings saved."),setTimeout(()=>window.location.reload(),1e3)};
    $("#passwordForm").onsubmit=async t=>{t.preventDefault();const e=$("#savePasswordBtn");e.disabled=!0,e.textContent="Saving...";const s={};(new FormData(t.target)).forEach((t,e)=>s[e]=t);const o=await api("/api/user/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)});if(e.disabled=!1,e.textContent="Update Password",!o.ok){const t=await o.json();return void toast(`Error: ${t.detail||"Unknown error"}`,!0)}toast("Password updated successfully."),t.target.reset()};
    $("#reportForm").onsubmit=t=>{t.preventDefault();const e=new FormData(t.target),s=e.get("start_date"),o=e.get("end_date");s&&o&&(window.location.href=`/api/reports/export?start_date=${s}&end_date=${o}`)};
    document.addEventListener("DOMContentLoaded",initAdminPage);
</script>
</body></html>
"""
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
LOG_VIEWER_HTML  = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Logs • __APP_TITLE__</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-50 text-gray-800 flex flex-col min-h-screen font-sans">
<div class="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex-grow">
<header class="flex items-center justify-between py-4 border-b border-gray-200"><div class="flex items-center gap-3"><img src="__APP_LOGO_URL__" alt="Logo" class="h-8 sm:h-10"/><h1 class="text-xl sm:text-2xl font-bold text-gray-900">__APP_TITLE__</h1></div><div class="space-x-4"><a class="text-sm font-medium text-blue-600 hover:text-blue-500" href="/">Dashboard</a><a class="text-sm font-medium text-blue-600 hover:text-blue-500" href="/admin">Admin Panel</a></div></header>
<main class="py-6"><div class="flex justify-between items-center mb-4"><h2 id="log-title" class="text-lg font-semibold text-gray-900">Logs</h2><div id="pagination-controls" class="space-x-2"></div></div><div class="overflow-x-auto bg-white border border-gray-200 rounded-lg shadow-sm"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-100"><tr><th class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase">Timestamp</th><th class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase">Status</th><th class="px-6 py-3 text-left text-xs font-bold text-gray-600 uppercase">Details</th></tr></thead><tbody id="logs-table-body" class="bg-white divide-y divide-gray-200"></tbody></table></div></main>
</div><footer class="w-full text-center text-sm text-gray-500 py-4">__FOOTER_HTML__</footer>
<script>
    const monitorId = window.location.pathname.split("/")[2];
    const tbody = document.getElementById("logs-table-body");
    const statusStyles = {
        up: { badge: "bg-green-100 text-green-800" },
        down: { badge: "bg-red-100 text-red-800" },
        degraded: { badge: "bg-yellow-100 text-yellow-800" },
        unknown: { badge: "bg-gray-100 text-gray-800" }
    };

    async function fetchLogs(page = 1) {
        tbody.innerHTML = `<tr><td colspan="3" class="px-6 py-4 text-center text-gray-500 animate-pulse">Loading logs...</td></tr>`;
        try {
            const res = await fetch(`/api/monitors/${monitorId}/logs?page=${page}`, { credentials: "include" });
            if (res.status === 401) {
                window.location.href = "/login";
                return;
            }
            if (!res.ok) {
                throw new Error("Failed to fetch logs");
            }
            const data = await res.json();
            tbody.innerHTML = "";
            if (data.logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" class="px-6 py-4 text-center text-gray-500">No logs found for this monitor.</td></tr>`;
                return;
            }
            for (const log of data.logs) {
                const style = statusStyles[log.status] || statusStyles.unknown;
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(log.checked_at).toLocaleString()}</td>
                    <td class="px-6 py-4 whitespace-nowrap">
                        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${style.badge}">
                            ${log.status.toUpperCase()}
                        </span>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-600">${log.detail}</td>
                `;
                tbody.appendChild(row);
            }
            updatePagination(data);
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="3" class="px-6 py-4 text-center text-red-500">Error loading logs.</td></tr>`;
            console.error(e);
        }
    }

    function updatePagination(data) {
        const { total, page, size } = data;
        const totalPages = Math.ceil(total / size);
        const paginationControls = document.getElementById("pagination-controls");
        paginationControls.innerHTML = "";
        if (totalPages <= 1) return;
        let html = `<span class="text-sm text-gray-700">Page ${page} of ${totalPages}</span>`;
        if (page > 1) {
            html += `<button onclick="fetchLogs(${page - 1})" class="ml-2 inline-flex items-center px-3 py-1 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">Previous</button>`;
        }
        if (page < totalPages) {
            html += `<button onclick="fetchLogs(${page + 1})" class="ml-2 inline-flex items-center px-3 py-1 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">Next</button>`;
        }
        paginationControls.innerHTML = html;
    }

    document.addEventListener("DOMContentLoaded", () => fetchLogs(1));
</script>
</body></html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard_page(auth_result: Optional[RedirectResponse] = Depends(page_auth_check)): return auth_result or HTMLResponse(render_template(DASHBOARD_HTML))
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(auth_result: Optional[RedirectResponse] = Depends(page_auth_check)):
    if auth_result: return auth_result
    options_html = "".join([f"<option value='{t.value}'>{t.name.replace('_', ' ').title()}</option>" for t in MonitorType])
    final_html = render_template(ADMIN_HTML).replace("{MONITOR_TYPE_OPTIONS}", options_html)
    return HTMLResponse(final_html)
@app.get("/monitors/{target_id}/logs", response_class=HTMLResponse)
async def logs_page(target_id: int, auth_result: Optional[RedirectResponse] = Depends(page_auth_check)):
    return auth_result or HTMLResponse(render_template(LOG_VIEWER_HTML))
@app.get("/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(render_template(LOGIN_HTML))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
