# GitHub Repository Content

## Repository Name Ideas

- university-portal-siem
- secure-university-portal
- graduation-siem-portal
- ai-siem-university-portal

## Short Description

Graduation project: a Flask university portal with SIEM logging, OpenSearch dashboards, abuse detection, DoS protection, and local AI threat analysis using Ollama.

## Topics

```text
flask
cybersecurity
siem
opensearch
ollama
sqlite
university-portal
threat-detection
rate-limiting
graduation-project
```

## Project Post

I built this graduation project as a secure university portal with integrated SIEM monitoring and AI-assisted threat analysis.

The system is built with Flask and SQLite for the portal, OpenSearch and OpenSearch Dashboards for centralized security logging, and Ollama for local AI analysis of suspicious activity. It supports admin, teacher, and student roles, while also demonstrating practical security controls such as password policy enforcement, email verification, IP-based rate limiting, DoS protection, session timeout management, role-based access control, and HTTP security headers.

For the cybersecurity side, the application forwards structured events to OpenSearch and includes dashboards, live security APIs, attack counters, top IP analysis, and AI-generated alerts. I also included attack simulation scripts for brute force login attempts, mass registration, password reset abuse, unauthorized access, SIEM verification, and DoS testing.

This project helped me connect software engineering with security monitoring, defensive controls, and incident detection in a realistic academic portal scenario.

## Highlights

- Flask university portal with admin, teacher, and student roles
- OpenSearch SIEM logging and dashboard integration
- AI-assisted threat analysis using local Ollama
- CSRF protection plus brute force, registration abuse, password reset abuse, and DoS protection
- Attack simulation scripts for validation and demonstration
- GitHub-safe setup with environment templates and ignored private runtime files

## Suggested First Commit Message

```text
Initial release of university portal SIEM graduation project
```
