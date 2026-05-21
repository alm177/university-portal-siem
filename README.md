# University Portal SIEM

A security-focused university portal built as a graduation project. The system combines a Flask-based academic portal with centralized SIEM logging, OpenSearch dashboards, abuse prevention controls, and local AI-assisted threat analysis through Ollama.

## Project Overview

This project demonstrates how common university portal workflows can be protected and monitored using practical cybersecurity controls. Students and teachers can use normal academic features, while administrators can review users, monitor security events, and trigger AI analysis of suspicious activity.

Core goals:

- Provide role-based access for admin, teacher, and student users.
- Protect authentication and registration flows from brute force, bot, and abuse patterns.
- Forward structured security events to OpenSearch for SIEM-style visibility.
- Detect suspicious activity with dashboard counters, timelines, and AI-generated alerts.
- Include attack simulation scripts for validation and demonstration.

## Features

- Authentication and account lifecycle:
  - Login and logout
  - Student and teacher registration
  - Email verification for new accounts
  - Admin approval and role management
  - Password reset with verification codes
  - Authenticated password change with email verification

- Security controls:
  - Password policy enforcement
  - CAPTCHA-style registration challenge
  - IP-based rate limiting for login, registration, and password reset
  - In-memory DoS detection and temporary IP blocking
  - Idle and absolute session timeout handling
  - HTTP security headers including CSP, clickjacking protection, MIME sniffing protection, and no-cache headers
  - Role-based access control for admin, teacher, and student pages

- SIEM and monitoring:
  - Structured event forwarding to OpenSearch
  - OpenSearch Dashboards integration
  - Admin dashboard counters and live log APIs
  - Attack reason breakdowns, top IPs, event timelines, and DoS stats

- AI-assisted security analysis:
  - Pulls recent security logs from OpenSearch
  - Builds behavioral summaries by IP, username, and attack pattern
  - Uses a local Ollama model to classify suspicious activity
  - Stores AI alerts in SQLite for admin review

- Demonstration scripts:
  - Brute force simulation
  - Mass registration simulation
  - Password reset abuse simulation
  - Unauthorized access checks
  - DoS request burst simulation
  - SIEM and AI alert validation

## Tech Stack

- Python
- Flask
- SQLite
- OpenSearch
- OpenSearch Dashboards
- Ollama with `llama3.1:8b`
- Docker Compose

## Project Structure

```text
.
+-- app/
|   +-- app.py                    # Flask application factory and middleware
|   +-- config.py                 # Environment-based configuration
|   +-- models.py                 # SQLite schema and admin seeding
|   +-- routes/                   # Auth, admin, teacher, and student routes
|   +-- services/                 # SIEM, AI analysis, rate limiting, sessions, email
|   +-- static/                   # CSS
|   +-- templates/                # Jinja templates
|   +-- attack_*.py               # Individual attack simulations
|   +-- test_attacks.py           # End-to-end security test script
+-- docker/
|   +-- docker-compose.yml        # OpenSearch and Dashboards
+-- export_docker_data.bat        # Optional backup helper
+-- setup_new_pc.bat              # Optional restore/setup helper
```

## Getting Started

### Prerequisites

- Python 3
- Docker Desktop
- Ollama, optional but required for AI alert analysis

### 1. Configure the app

Copy the example environment file and edit values for your machine:

```powershell
Copy-Item app\.env.example app\.env
```

At minimum, set a strong `SECRET_KEY`. If using OpenSearch or SMTP, update the matching values.

### 2. Install Python dependencies

```powershell
cd app
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start OpenSearch

Copy the Docker environment template and set the same password used by `OS_PASS` in `app/.env`:

```powershell
Copy-Item docker\.env.example docker\.env
```

```powershell
cd ..\docker
docker compose up -d
```

OpenSearch runs on `https://localhost:9200`, and OpenSearch Dashboards runs on `http://localhost:5601`.

### 4. Start the portal

```powershell
cd ..\app
venv\Scripts\activate
python app.py
```

The portal runs at:

```text
http://127.0.0.1:5000
```

## Default Admin Account

On first run, the app seeds an admin account from environment variables:

- `DEFAULT_ADMIN_USERNAME`
- `DEFAULT_ADMIN_EMAIL`
- `DEFAULT_ADMIN_PASSWORD`

For a public repository or live demo, change the default password before publishing or presenting.

## Attack Simulation

With the Flask app running, use:

```powershell
cd app
venv\Scripts\activate
python test_attacks.py
```

The script tests brute force lockout, registration abuse, password reset abuse, unauthorized access, CAPTCHA checks, SIEM logs, AI alerts, and DoS blocking. The DoS tests intentionally run last because they temporarily block the local IP in memory.

## GitHub Publishing Notes

Do not publish local runtime or private backup data. The `.gitignore` is configured to exclude:

- `app/.env`
- `app/database.db`
- `app/venv/`
- OpenSearch volume backups
- exported Docker images
- local Ollama models and SSH keys

Recommended repository description:

```text
Graduation project: a Flask university portal with SIEM logging, OpenSearch dashboards, abuse detection, DoS protection, and local AI threat analysis using Ollama.
```

Suggested topics:

```text
flask, cybersecurity, siem, opensearch, ollama, sqlite, university-portal, threat-detection, rate-limiting, graduation-project
```

## Security Notice

This is an academic graduation project and demonstration lab. Review configuration, credentials, deployment settings, email delivery, TLS, database storage, and secret management before using it outside a controlled local environment.
