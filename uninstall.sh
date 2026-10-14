#!/usr/bin/env bash
# Stop Easy Radius. This does not delete FreeRADIUS or its backups.

set -euo pipefail

APP_DIR="${EASY_RADIUS_APP_DIR:-/opt/radius-admin}"
REMOVE_APP=0
YES=0

usage() {
  cat <<'EOF'
Usage: sudo ./uninstall.sh [--remove-app --yes]

Stops the Easy Radius container. FreeRADIUS, /etc/freeradius, and the
timestamped backups under /root are left as they are.

  --remove-app   Delete /opt/radius-admin after the container stops.
                 This also deletes the data directory (admin hash, router
                 secrets, and user passwords). Requires --yes.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-app) REMOVE_APP=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -f "$APP_DIR/docker-compose.yml" ]] && command -v docker >/dev/null 2>&1; then
  docker compose -f "$APP_DIR/docker-compose.yml" down
  echo "Stopped the Easy Radius container."
else
  echo "No Easy Radius compose file at $APP_DIR, or docker is not installed."
fi

cat <<EOF

FreeRADIUS was not removed and /etc/freeradius was not changed.
Backups made by install.sh are in /root/freeradius-backup-* .
Apply backups are in $APP_DIR/data/backups/ .
Automation exports are in $APP_DIR/data/automation/ .

Restore a backup:
  sudo systemctl stop freeradius
  sudo cp -a /root/freeradius-backup-TIMESTAMP/freeradius/. /etc/freeradius/3.0/
  sudo systemctl start freeradius

Remove the app files yourself with:
  sudo rm -rf $APP_DIR

Review firewall rules with:
  sudo ufw status numbered
Delete a rule with:
  sudo ufw delete NUMBER

Packages are left installed. To remove them:
  sudo apt-get remove freeradius freeradius-utils
EOF

if [[ "$REMOVE_APP" -eq 1 ]]; then
  if [[ "$YES" -ne 1 ]]; then
    echo "Refusing to delete $APP_DIR without --yes." >&2
    exit 1
  fi
  rm -rf "$APP_DIR"
  echo "Removed $APP_DIR"
fi
