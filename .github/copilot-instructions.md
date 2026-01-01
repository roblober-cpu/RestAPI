# Copilot Instructions for Visitor Tracking App

## Project Overview
This is a Flask-based web application for tracking visitors, authenticating users, and visualizing network data. It uses PostgreSQL for persistence and provides dashboards and authentication workflows. The codebase is modular, with clear separation between web, database, authentication, network analysis, and utility logic.

## Architecture & Key Components
- **app.py**: Main Flask app. Handles routing, session management, and coordinates between modules.
- **database.py**: All database CRUD operations. Uses PostgreSQL via `psycopg2`. Connection string is set via the `DATABASE_URL` environment variable.
- **auth.py**: Password hashing, geographic authentication, and user verification. Uses salted SHA-256 hashes and haversine formula for location checks.
- **network.py**: IP geolocation, ASN lookup, VPN/proxy detection. Integrates with `ipapi.co` for network info.
- **utils.py**: Utility functions for IP extraction, email/phone validation, and code generation.
- **templates/**: Jinja2 HTML templates for UI (dashboard, login, register, etc).

## Developer Workflows
- **Run Locally**: `python3 app.py` or `gunicorn app:app` (see Procfile for deployment).
- **Database Setup**: On startup, `init_database()` creates tables if needed. Uses environment variable `DATABASE_URL`.
- **Dependencies**: Install from `requirements.txt` (Flask, Gunicorn, Requests, Psycopg2).
- **Debugging**: If DB is unavailable, app falls back to in-memory storage. Check for `DB_AVAILABLE` in `app.py`.
- **Environment**: Set `SECRET_KEY` and `DATABASE_URL` in your environment for production.

## Patterns & Conventions
- **Modular Imports**: All business logic is separated into modules. Route handlers in `app.py` delegate to these modules.
- **Fallbacks**: If database is not available, the app uses in-memory lists/dicts for visitors and users.
- **Geographic Auth**: Location-based authentication uses a config (`system_config_db`) for reference points.
- **Network Analysis**: Visitor IPs are analyzed and cached for 1 hour. External API calls are wrapped with error handling.
- **Validation**: Email and phone validation use regexes in `utils.py`.
- **Sensitive Data**: Do not hardcode secrets. Use environment variables for credentials and keys.

## Integration Points
- **PostgreSQL**: Connection via `psycopg2` and `DATABASE_URL`.
- **ipapi.co**: Used for IP geolocation and ASN info in `network.py`.
- **Gunicorn**: Used for deployment (see Procfile).

## Example Patterns
- To add a new route, define it in `app.py` and delegate logic to a module.
- To add a new database field, update the table creation in `database.py` and adjust CRUD functions.
- For new authentication methods, extend `auth.py` and update relevant route handlers.

## References
- See `app.py` for routing and session logic.
- See `database.py` for DB schema and persistence.
- See `network.py` for external API integration.
- See `templates/` for UI structure.

---
For questions or unclear conventions, review module docstrings and comments, or ask for clarification.
