## Z Monitor: Stable & Secure Infrastructure Health Monitor
======================================================

FastAPI application architected for robust, stateful monitoring.
This is the stable, production-ready version incorporating all features and bug
fixes, with a corrected and stable file structure.

## Features
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

## How to Run
----------
1) Create and activate a Python virtual environment:
   `python -m venv .venv`
   `source .venv/bin/activate`  # On Windows: .venv\Scripts\activate

2) Install all required dependencies:
   `pip install "fastapi[all]" sqlmodel httpx dnspython python-jose[cryptography] passlib python-whois boto3`

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
