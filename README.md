#!/usr/bin/env bash
# Heritage Vault 2.0 — Advanced Linux Automation
# Purpose: Automate system updates, backups, deployment (via Ansible), and monitoring checks.
# Usage:
#   sudo ./heritage_automation.sh [--all | update | backup | deploy | monitor]
# Notes:
#   - Designed to be easy to read/modify and safe to run unattended via cron.
#   - Logs to /var/log/heritage_automation.log and syslog.

set -Eeuo pipefail

# --------------- Config (EDIT AS NEEDED) ------------------
BACKUP_SRC="/srv/heritage/data"           # Source data directory
BACKUP_DEST="/var/backups/heritage"       # Local backup root
BACKUP_RETENTION=7                        # How many daily backups to keep
ANSIBLE_INVENTORY="/etc/ansible/hosts"    # Or project inventory file
ANSIBLE_PLAYBOOK="/opt/heritage/ansible/playbooks/deploy_app.yml"
LOCK_FILE="/var/lock/heritage_automation.lock"
LOG_FILE="/var/log/heritage_automation.log"
HEALTH_THRESHOLD_DISK=85                  # % usage to warn
HEALTH_THRESHOLD_LOAD=6.0                 # 1-min load to warn (tune per CPU cores)
# ----------------------------------------------------------

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "[$ts] [$level] $msg" | tee -a "$LOG_FILE" | logger -t heritage_automation -p "user.${level,,}" || true
}

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Please run as root (sudo)." >&2
    exit 1
  fi
}

with_lock() {
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    log WARNING "Another instance is running; exiting."
    exit 0
  fi
}

trap 'rc=$?; log ERROR "Script aborted (exit $rc) at line $LINENO"; exit $rc' ERR
trap 'log INFO "Script finished."' EXIT

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"; return
  elif command -v yum >/dev/null 2>&1; then echo "yum"; return
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"; return
  else
    log ERROR "No supported package manager found"; exit 2
  fi
}

update_system() {
  log INFO "Starting system update"
  local pmgr; pmgr="$(detect_pkg_mgr)"
  case "$pmgr" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >>"$LOG_FILE" 2>&1
      apt-get -o Dpkg::Options::="--force-confnew" dist-upgrade -y >>"$LOG_FILE" 2>&1
      apt-get autoremove -y >>"$LOG_FILE" 2>&1
      ;;
    dnf) dnf -y upgrade --refresh >>"$LOG_FILE" 2>&1 ;;
    yum) yum -y update >>"$LOG_FILE" 2>&1 ;;
    zypper) zypper --non-interactive refresh >>"$LOG_FILE" 2>&1 && zypper --non-interactive update >>"$LOG_FILE" 2>&1 ;;
  esac
  log INFO "System update completed using $pmgr"
}

timestamp() { date +'%Y-%m-%d_%H-%M-%S'; }

ensure_dir() {
  mkdir -p "$1"
}

backup_data() {
  log INFO "Starting backup of $BACKUP_SRC -> $BACKUP_DEST"
  ensure_dir "$BACKUP_DEST"
  local ts target
  ts="$(timestamp)"
  target="$BACKUP_DEST/${ts}"
  ensure_dir "$target"
  # rsync with hard-links for incremental efficiency if previous exists
  local last="$(ls -1dt "$BACKUP_DEST"/* 2>/dev/null | head -n1 || true)"
  if [[ -n "$last" && -d "$last" ]]; then
    rsync -aHAX --delete --numeric-ids --info=stats2 --link-dest="$last" "$BACKUP_SRC"/ "$target"/ >>"$LOG_FILE" 2>&1
  else
    rsync -aHAX --delete --numeric-ids --info=stats2 "$BACKUP_SRC"/ "$target"/ >>"$LOG_FILE" 2>&1
  fi

  # Create manifest for integrity auditing
  (cd "$target" && find . -type f -print0 | xargs -0 sha256sum) > "${target}.sha256" 2>>"$LOG_FILE" || true

  # Retention policy
  local count
  count="$(ls -1dt "$BACKUP_DEST"/* | wc -l || echo 0)"
  if (( count > BACKUP_RETENTION )); then
    ls -1dt "$BACKUP_DEST"/* | tail -n +$((BACKUP_RETENTION+1)) | xargs -r rm -rf
    log INFO "Applied retention (kept last $BACKUP_RETENTION backups)"
  fi
  log INFO "Backup completed to $target"
}

deploy_with_ansible() {
  log INFO "Starting deployment via Ansible: inventory=$ANSIBLE_INVENTORY playbook=$ANSIBLE_PLAYBOOK"
  if ! command -v ansible-playbook >/dev/null 2>&1; then
    log ERROR "ansible-playbook not found. Install Ansible first."
    exit 3
  fi
  ansible-playbook -i "$ANSIBLE_INVENTORY" "$ANSIBLE_PLAYBOOK" >>"$LOG_FILE" 2>&1
  log INFO "Ansible deployment completed"
}

monitor_health() {
  log INFO "Starting health checks"
  # Disk usage
  local disk_alerts=0
  while read -r line; do
    usage=$(echo "$line" | awk '{print $5}' | tr -d '%')
    mountp=$(echo "$line" | awk '{print $6}')
    if (( usage >= HEALTH_THRESHOLD_DISK )); then
      log WARNING "High disk usage: ${usage}% on ${mountp}"
      disk_alerts=1
    fi
  done < <(df -PTH --output=pcent,target | tail -n +2 | sed 's/% /% /')

  # Load average (1 min)
  load_1=$(awk '{print $1}' /proc/loadavg)
  # Convert to float compare using python fallback if needed
  python3 - <<PY || load_ok=$? >/dev/null
import sys
load=float("$load_1"); thr=float("$HEALTH_THRESHOLD_LOAD")
sys.exit(0 if load<=thr else 1)
PY
  if [[ "${load_ok:-1}" -ne 0 ]]; then
    log WARNING "High load average (1 min): $load_1"
  fi

  # Failed systemd services
  if command -v systemctl >/dev/null 2>&1; then
    failed="$(systemctl --failed --no-legend | wc -l || echo 0)"
    if (( failed > 0 )); then
      log WARNING "Systemd reports $failed failed unit(s)"; systemctl --failed >>"$LOG_FILE" 2>&1 || true
    fi
  fi

  # Security updates (Debian/Ubuntu)
  if command -v apt-get >/dev/null 2>&1 && command -v unattended-upgrades >/dev/null 2>&1; then
    sec_count="$(/usr/lib/update-notifier/apt-check --security 2>/dev/null | cut -d';' -f2 || echo 0)"
    [[ -n "$sec_count" ]] && log INFO "Pending security updates: $sec_count"
  fi

  log INFO "Health checks completed"
}

main() {
  require_root
  with_lock
  touch "$LOG_FILE"; chmod 640 "$LOG_FILE"

  case "${1:---all}" in
    --all) update_system; backup_data; deploy_with_ansible; monitor_health ;;
    update) update_system ;;
    backup) backup_data ;;
    deploy) deploy_with_ansible ;;
    monitor) monitor_health ;;
    *) echo "Usage: $0 [--all|update|backup|deploy|monitor]"; exit 64 ;;
  esac
}

main "$@"
