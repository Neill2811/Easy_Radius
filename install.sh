#!/usr/bin/env bash
# Install Easy Radius and FreeRADIUS 3.0 on Ubuntu 24.04.
# Safe to run more than once. An existing FreeRADIUS config is backed up
# and left in place. Nothing is imported into the web UI.

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${EASY_RADIUS_APP_DIR:-/opt/radius-admin}"
FREERADIUS_DIR="${EASY_RADIUS_FREERADIUS_DIR:-/etc/freeradius/3.0}"
BACKUP_ROOT="${EASY_RADIUS_BACKUP_ROOT:-/root}"
SKIP_PACKAGES="${EASY_RADIUS_SKIP_PACKAGES:-0}"
SKIP_DOCKER="${EASY_RADIUS_SKIP_DOCKER:-0}"

ADMIN_SUBNETS="${EASY_RADIUS_ADMIN_SUBNETS:-}"
ROUTER_SUBNETS="${EASY_RADIUS_ROUTER_SUBNETS:-}"
ENABLE_UFW=0

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [--ufw] [--admin-subnets CIDRS] [--router-subnets CIDRS]

Installs FreeRADIUS 3.0, freeradius-utils, Docker, and Easy Radius.
The web UI listens on port 8088.

  --ufw                 Add firewall rules, then enable ufw.
  --admin-subnets LIST  Comma-separated CIDRs for SSH (22/tcp) and the UI (8088/tcp).
                        Default: the current SSH client as a /32 or /128.
  --router-subnets LIST Comma-separated CIDRs for RADIUS (1812/udp and 1813/udp).
                        Default: none. Router subnets are not opened until you set them.

Example (documentation addresses only — use your own ranges):
  sudo ./install.sh --ufw \
    --admin-subnets 192.0.2.0/24 \
    --router-subnets 198.51.100.0/24

If FreeRADIUS is already installed, its config is copied to
/root/freeradius-backup-TIMESTAMP and is not overwritten or imported.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ufw) ENABLE_UFW=1; shift ;;
    --admin-subnets)
      ADMIN_SUBNETS="${2:-}"
      shift 2
      ;;
    --router-subnets)
      ROUTER_SUBNETS="${2:-}"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

need_root=0
case "$APP_DIR" in
  /opt|/opt/*) need_root=1 ;;
esac
case "$FREERADIUS_DIR" in
  /etc|/etc/*) need_root=1 ;;
esac
if [[ "$need_root" -eq 1 && "$(id -u)" -ne 0 ]]; then
  echo "Run this script as root: sudo ./install.sh" >&2
  exit 1
fi

log() { printf '%s\n' "$*"; }

backup_freeradius() {
  if [[ ! -d "$FREERADIUS_DIR" ]]; then
    return 0
  fi
  local stamp dest
  stamp="$(date -u +%Y%m%dT%H%M%S%NZ)"
  dest="$BACKUP_ROOT/freeradius-backup-$stamp"
  mkdir -p "$dest"
  cp -a "$FREERADIUS_DIR" "$dest/freeradius"
  log "Backed up $FREERADIUS_DIR to $dest"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    freeradius \
    freeradius-utils \
    docker.io \
    docker-compose-v2 \
    python3 \
    ca-certificates
  systemctl enable --now docker
}

copy_app() {
  if [[ "$SRC" == "$APP_DIR" ]]; then
    log "Source is already $APP_DIR"
    return 0
  fi
  mkdir -p "$APP_DIR"
  python3 - "$SRC" "$APP_DIR" <<'PY'
import shutil
import sys
from pathlib import Path

src = Path(sys.argv[1]).resolve()
dest = Path(sys.argv[2]).resolve()
skip_dirs = {".git", "data", ".venv", "venv", "__pycache__", ".pytest_cache", ".cursor"}
for path in src.rglob("*"):
    rel = path.relative_to(src)
    if any(part in skip_dirs for part in rel.parts):
        continue
    if path.is_dir():
        continue
    if path.name == ".env" or path.suffix in {".tgz"} or path.name.endswith(".tar.gz"):
        continue
    target = dest / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)
PY
  log "Copied Easy Radius to $APP_DIR"
}

ensure_mikrotik_dictionary() {
  local etc_dict="$FREERADIUS_DIR/dictionary"
  local share_dict="/usr/share/freeradius/dictionary.mikrotik"
  local share_main="/usr/share/freeradius/dictionary"
  if [[ ! -f "$etc_dict" ]]; then
    log "No $etc_dict yet; skipping the MikroTik dictionary check."
    return 0
  fi
  if [[ -f "$share_dict" ]] && grep -q "Mikrotik-Group" "$share_dict"; then
    if grep -q "dictionary.mikrotik" "$etc_dict" "$share_main" 2>/dev/null; then
      log "MikroTik dictionary is already available."
      return 0
    fi
    printf '\n$INCLUDE %s\n' "$share_dict" >> "$etc_dict"
    log "Added an include for the packaged MikroTik dictionary."
    return 0
  fi
  local local_dict="$FREERADIUS_DIR/dictionary.easy-radius-mikrotik"
  local snippet="$SRC/deploy/mikrotik-group.dictionary"
  if [[ ! -f "$snippet" ]]; then
    snippet="$APP_DIR/deploy/mikrotik-group.dictionary"
  fi
  cp "$snippet" "$local_dict"
  if ! grep -q "dictionary.easy-radius-mikrotik" "$etc_dict"; then
    printf '\n$INCLUDE %s\n' "$local_dict" >> "$etc_dict"
  fi
  chmod 644 "$local_dict"
  log "Installed a MikroTik-Group dictionary include."
}

ensure_files_module() {
  local enabled="$FREERADIUS_DIR/mods-enabled/files"
  local available="$FREERADIUS_DIR/mods-available/files"
  if [[ -e "$enabled" ]]; then
    log "files module already enabled."
    return 0
  fi
  if [[ -e "$available" ]]; then
    mkdir -p "$FREERADIUS_DIR/mods-enabled"
    ln -s ../mods-available/files "$enabled"
    log "Enabled the files module."
    return 0
  fi
  log "mods-available/files was not found. The FreeRADIUS package normally provides it."
}

detect_ssh_ip() {
  local from_who
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    printf '%s\n' "${SSH_CONNECTION%% *}"
    return 0
  fi
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    printf '%s\n' "${SSH_CLIENT%% *}"
    return 0
  fi
  from_who="$(who -m 2>/dev/null || true)"
  printf '%s\n' "$from_who" | sed -n 's/.*(\([0-9A-Fa-f:.]*\)).*/\1/p' | head -n 1 || true
}

configure_ufw() {
  local ssh_ip admin_was_set
  ssh_ip="$(detect_ssh_ip || true)"
  admin_was_set=1
  if [[ -z "$ADMIN_SUBNETS" ]]; then
    admin_was_set=0
    if [[ -z "$ssh_ip" ]]; then
      echo "Refusing to enable ufw: no SSH client IP was detected and --admin-subnets was not set." >&2
      echo "No firewall changes were made." >&2
      exit 1
    fi
    if [[ "$ssh_ip" == *:* ]]; then
      ADMIN_SUBNETS="$ssh_ip/128"
    else
      ADMIN_SUBNETS="$ssh_ip/32"
    fi
    log "Admin subnets default to the current SSH client: $ADMIN_SUBNETS"
  fi

  if [[ -n "$ssh_ip" ]]; then
    local check
    set +e
    check="$(PYTHONPATH="$APP_DIR" python3 -m easy_radius.netcheck --ip "$ssh_ip" --subnets "$ADMIN_SUBNETS" 2>&1)"
    local check_code=$?
    set -e
    if [[ "$check_code" -ne 0 ]]; then
      echo "Refusing to enable ufw: SSH client $ssh_ip is not inside the admin subnets ($ADMIN_SUBNETS)." >&2
      echo "$check" >&2
      echo "No firewall changes were made." >&2
      exit 1
    fi
  elif [[ "$admin_was_set" -eq 1 ]]; then
    log "No SSH client IP detected. Continuing because --admin-subnets was set."
    log "Confirm you can still open SSH before you disconnect."
  fi

  if ! command -v ufw >/dev/null 2>&1; then
    apt-get install -y ufw
  fi

  ufw default deny incoming
  ufw default allow outgoing

  local net
  local old_ifs="$IFS"
  local -a admin_array=()
  local -a router_array=()
  IFS=', ' read -r -a admin_array <<< "$ADMIN_SUBNETS" || true
  IFS="$old_ifs"
  for net in "${admin_array[@]}"; do
    if [[ -z "$net" ]]; then
      continue
    fi
    ufw allow from "$net" to any port 22 proto tcp comment "Easy Radius SSH"
    ufw allow from "$net" to any port 8088 proto tcp comment "Easy Radius web"
  done

  if [[ -n "$ROUTER_SUBNETS" ]]; then
    IFS=', ' read -r -a router_array <<< "$ROUTER_SUBNETS" || true
    IFS="$old_ifs"
    for net in "${router_array[@]}"; do
      if [[ -z "$net" ]]; then
        continue
      fi
      ufw allow from "$net" to any port 1812 proto udp comment "Easy Radius auth"
      ufw allow from "$net" to any port 1813 proto udp comment "Easy Radius accounting"
    done
  else
    log "No --router-subnets given. UDP 1812 and 1813 were not opened."
  fi

  ufw --force enable
  ufw status verbose
  log "ufw is enabled. Allow rules were added before it was turned on."
}

PREEXISTING=0
if [[ -f "$FREERADIUS_DIR/clients.conf" ]]; then
  PREEXISTING=1
  log "Existing FreeRADIUS config found. It will be backed up and left unchanged."
  backup_freeradius
fi

if [[ "$SKIP_PACKAGES" != "1" ]]; then
  install_packages
else
  log "Skipping package installation."
fi

if [[ "$PREEXISTING" -eq 0 && -d "$FREERADIUS_DIR" ]]; then
  log "Saving the stock FreeRADIUS config before writing the starter files."
  backup_freeradius
fi

copy_app
mkdir -p "$APP_DIR/data"
chmod 700 "$APP_DIR/data"
export PYTHONPATH="$APP_DIR${PYTHONPATH:+:$PYTHONPATH}"

ensure_mikrotik_dictionary
ensure_files_module

USERS_FILE="$FREERADIUS_DIR/mods-config/files/authorize"
if [[ -L "$USERS_FILE" ]]; then
  log "Users file symlink target: $(readlink -f "$USERS_FILE")"
fi

if [[ "$PREEXISTING" -eq 1 ]]; then
  python3 -m easy_radius.bootstrap --data-dir "$APP_DIR/data"
  log "Existing clients.conf and users file were not overwritten and were not imported."
  log "Add routers and users in the web UI, then click Apply."
else
  python3 -m easy_radius.bootstrap \
    --data-dir "$APP_DIR/data" \
    --write-starter \
    --clients-conf "$FREERADIUS_DIR/clients.conf" \
    --users-file "$USERS_FILE"
  log "Wrote a starter clients.conf with a new localhost secret, and an empty users file."
  if [[ "$SKIP_PACKAGES" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now freeradius
    systemctl restart freeradius
  fi
fi

if [[ "$SKIP_DOCKER" != "1" ]]; then
  docker compose -f "$APP_DIR/docker-compose.yml" up -d --build
  log "Easy Radius is starting on port 8088."
  log "Read the admin password once from: docker logs radius-admin"
  log "A root-only copy is also at $APP_DIR/data/initial-admin-password.txt"
else
  log "Skipping docker compose."
fi

if [[ "$ENABLE_UFW" -eq 1 ]]; then
  configure_ufw
fi

log "Done."
