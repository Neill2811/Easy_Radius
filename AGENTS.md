# Agent notes

Easy Radius is a LAN-only Flask app for FreeRADIUS and MikroTik admin on Ubuntu. It listens on port 8088 of the server. Keep it on the LAN.

## Secrets

Do not put secrets in the repo, commits, logs, or chat output. That includes the admin password, RADIUS secrets, user passwords, router API credentials, SMTP passwords, Telegram tokens, and backup passphrases. Runtime state stays in `data/` (mode `0700`), which is gitignored. Tests use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and sample names such as `ExampleSite`.

## UI

Keep the current design. The background is dark charcoal (`#232323`, sidebar `#1b1b1b`) with orange accents (`#f57c00`, `#c4530a`). Navigation is the grouped left sidebar: Dashboard, Access, Configuration, Monitoring, Reports & audit, and System. Do not restyle or replace that layout.

## Tests

From the repo root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

## Pull requests

One pull request per feature. Open it and leave it for review. Never merge.
