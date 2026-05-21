# Security Policy

## Scope

This repository is an academic graduation project and local demonstration lab. It is not intended to be deployed on the public internet without a full production security review.

## Supported Use

The project is designed for local execution with:

- Flask on `127.0.0.1:5000`
- OpenSearch on `localhost:9200`
- OpenSearch Dashboards on `localhost:5601`
- Optional local Ollama analysis

## Reporting Issues

If you find a vulnerability or unsafe default, open a GitHub issue with:

- A clear description of the problem
- Steps to reproduce it
- The affected route, file, or configuration
- Suggested remediation if available

Do not include real credentials, private tokens, or personal data in public issues.

## Important Notes

- Never commit `.env`, SQLite databases, Docker volume backups, Ollama model data, or private keys.
- Change all secrets before running the project.
- Keep `TRUST_PROXY_HEADERS=false` unless a trusted reverse proxy controls forwarded headers.
- Use HTTPS and `SESSION_COOKIE_SECURE=true` for non-local deployments.
