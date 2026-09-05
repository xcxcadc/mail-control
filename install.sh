#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

APP_NAME="mail-control"
INSTALL_DIR="${MAIL_CONTROL_INSTALL_DIR:-/opt/mail-control}"
SERVICE_NAME="mail-control.service"
MAILU_DIR="${MAIL_CONTROL_MAILU_DIR:-}"
MAIL_ROOT="${MAIL_CONTROL_MAIL_ROOT:-}"
DB_PATH="${MAIL_CONTROL_DB:-}"
RSPAMD_DIR="${MAIL_CONTROL_RSPAMD_DIR:-}"
RSPAMD_ACTIONS_FILE=""
RSPAMD_GREYLIST_FILE=""
RSPAMD_FORCE_ACTIONS_FILE=""
RSPAMD_MULTIMAP_FILE=""
DOVECOT_DIR="${MAIL_CONTROL_DOVECOT_DIR:-}"
DOVECOT_OVERRIDE=""
DOVECOT_VIRTUAL_RULE=""
OVERRIDE_DIR="${MAIL_CONTROL_OVERRIDE_DIR:-}"
FRONT_CONTAINER="${MAIL_CONTROL_FRONT_CONTAINER:-}"
MAIL_CONTROL_BIND="${MAIL_CONTROL_BIND:-}"
MAIL_CONTROL_PORT="${MAIL_CONTROL_PORT:-18080}"
REF="${MAIL_CONTROL_REF:-master}"
SOURCE_DIR="${MAIL_CONTROL_SOURCE_DIR:-}"
PROXY_SECRET="${MAIL_CONTROL_PROXY_SECRET:-}"
TMP_DIR=""
BACKUP_DIR=""
CHANGES_APPLIED=0
SERVICE_WAS_ACTIVE=0
NGINX_CONFIG_WAS_TESTED=0

RAW_BASE="https://raw.githubusercontent.com/xcxcadc/mail-control/$REF"

log() {
    printf '[mail-control] %s\n' "$*"
}

fail() {
    printf '[mail-control] ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Install or upgrade Mailu Mail Control on a Mailu Docker host.

Usage:
  install.sh [options]

Options:
  --mailu-dir PATH          Mailu compose directory
  --mail-root PATH          Host path mounted as /mail in the imap container
  --db PATH                 Host path to Mailu's SQLite main.db
  --rspamd-dir PATH         Host path mounted as Rspamd override.d
  --dovecot-dir PATH        Host path mounted as Dovecot /overrides
  --override-dir PATH       Host path mounted as /overrides in front
  --front-container NAME    Mailu front container name
  --source-dir PATH         Use a local checkout instead of downloading source
  --ref REF                 Git ref for the GitHub download (default: master)
  --bind IP                 Host Docker gateway address used by the front proxy
  --port PORT               Internal service port (default: 18080)
  --help                    Show this help

The installer is repeatable. Existing application files and generated configs
are backed up before replacement. Mailu mailbox and database data are never
deleted by this script.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mailu-dir|--mail-root|--db|--rspamd-dir|--dovecot-dir|--override-dir|--front-container|--source-dir|--ref|--bind|--port)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            case "$1" in
                --mailu-dir) MAILU_DIR="$2" ;;
                --mail-root) MAIL_ROOT="$2" ;;
                --db) DB_PATH="$2" ;;
                --rspamd-dir) RSPAMD_DIR="$2" ;;
                --dovecot-dir) DOVECOT_DIR="$2" ;;
                --override-dir) OVERRIDE_DIR="$2" ;;
                --front-container) FRONT_CONTAINER="$2" ;;
                --source-dir) SOURCE_DIR="$2" ;;
                --ref) REF="$2"; RAW_BASE="https://raw.githubusercontent.com/xcxcadc/mail-control/$REF" ;;
                --bind) MAIL_CONTROL_BIND="$2" ;;
                --port) MAIL_CONTROL_PORT="$2" ;;
            esac
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1 (use --help)"
            ;;
    esac
done

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

has_compose_file() {
    [[ -f "$1/docker-compose.yml" || -f "$1/docker-compose.yaml" ||
        -f "$1/compose.yml" || -f "$1/compose.yaml" ]]
}

find_service_container() {
    local service="$1"
    local pattern="$2"
    local name=""
    name="$(docker ps -a --filter "label=com.docker.compose.service=$service" --format '{{.Names}}' | awk 'NF {print; exit}' || true)"
    if [[ -n "$name" ]]; then
        printf '%s' "$name"
        return 0
    fi
    docker ps -a --format '{{.Names}}' | awk -v pattern="$pattern" 'tolower($0) ~ pattern {print; exit}' || true
}

mount_source() {
    local container="$1"
    local destination="$2"
    case "$destination" in
        /mail)
            docker inspect -f '{{range .Mounts}}{{if eq .Destination "/mail"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$container" 2>/dev/null | awk 'NF {print; exit}' || true
            ;;
        /data)
            docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$container" 2>/dev/null | awk 'NF {print; exit}' || true
            ;;
        /overrides)
            docker inspect -f '{{range .Mounts}}{{if eq .Destination "/overrides"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$container" 2>/dev/null | awk 'NF {print; exit}' || true
            ;;
        /etc/rspamd/override.d)
            docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/rspamd/override.d"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$container" 2>/dev/null | awk 'NF {print; exit}' || true
            ;;
        *)
            return 1
            ;;
    esac
}

first_existing_file() {
    local candidate
    for candidate in "$@"; do
        if [[ -f "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

first_existing_dir() {
    local candidate
    for candidate in "$@"; do
        if [[ -d "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

systemd_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

restore_target() {
    local target="$1"
    local backup="$BACKUP_DIR/$(basename "$target")"
    if [[ -e "$backup" || -L "$backup" ]]; then
        cp -a -- "$backup" "$target"
    else
        rm -f -- "$target"
    fi
}

rollback() {
    [[ "$CHANGES_APPLIED" -eq 1 ]] || return 0
    CHANGES_APPLIED=0
    set +e
    log "installation failed; restoring previous generated files"
    restore_target "$INSTALL_DIR/mail_control.py"
    restore_target "/etc/systemd/system/$SERVICE_NAME"
    restore_target "$OVERRIDE_DIR/mail-control.conf"
    restore_target "$OVERRIDE_DIR/mail-control-admin.conf"
    restore_target "$RSPAMD_ACTIONS_FILE"
    restore_target "$RSPAMD_GREYLIST_FILE"
    restore_target "$RSPAMD_FORCE_ACTIONS_FILE"
    restore_target "$RSPAMD_MULTIMAP_FILE"
    restore_target "$DOVECOT_OVERRIDE"
    restore_target "$DOVECOT_VIRTUAL_RULE"
    systemctl daemon-reload >/dev/null 2>&1
    if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
        systemctl restart "$SERVICE_NAME" >/dev/null 2>&1
    else
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1
    fi
    if [[ "$NGINX_CONFIG_WAS_TESTED" -eq 1 ]]; then
        docker exec "$FRONT_CONTAINER" nginx -t >/dev/null 2>&1
        docker exec "$FRONT_CONTAINER" nginx -s reload >/dev/null 2>&1
    fi
    if [[ -n "$ANTISPAM_CONTAINER" ]]; then
        docker kill -s HUP "$ANTISPAM_CONTAINER" >/dev/null 2>&1
    fi
    set -e
}

on_exit() {
    local status=$?
    if [[ "$status" -ne 0 ]]; then
        rollback
    fi
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
    exit "$status"
}
trap on_exit EXIT

[[ "$EUID" -eq 0 ]] || fail "run as root, for example: curl -fsSL ... | sudo bash"
require_command docker
require_command systemctl
require_command install
require_command python3
docker info >/dev/null 2>&1 || fail "Docker daemon is not available"

if [[ -z "$FRONT_CONTAINER" ]]; then
    FRONT_CONTAINER="$(find_service_container front '(^|[-_])front([-_]|$)')"
fi
[[ -n "$FRONT_CONTAINER" ]] || fail "Mailu front container not found; use --front-container"
docker inspect "$FRONT_CONTAINER" >/dev/null 2>&1 || fail "cannot inspect front container: $FRONT_CONTAINER"
[[ "$(docker inspect -f '{{.State.Running}}' "$FRONT_CONTAINER")" == "true" ]] || fail "Mailu front container is not running: $FRONT_CONTAINER"

COMPOSE_WORKDIR="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$FRONT_CONTAINER" 2>/dev/null || true)"
[[ "$COMPOSE_WORKDIR" == "<no value>" ]] && COMPOSE_WORKDIR=""
if [[ -z "$MAILU_DIR" ]]; then
    if [[ -n "$COMPOSE_WORKDIR" && -d "$COMPOSE_WORKDIR" ]]; then
        MAILU_DIR="$COMPOSE_WORKDIR"
    else
        MAILU_DIR="$(first_existing_dir /opt/mailu /mailu /srv/mailu /root/mailu || true)"
    fi
fi
[[ -n "$MAILU_DIR" ]] || fail "Mailu compose directory not found; use --mailu-dir"
[[ -d "$MAILU_DIR" ]] || fail "Mailu directory does not exist: $MAILU_DIR"
has_compose_file "$MAILU_DIR" || fail "no Docker Compose file found in $MAILU_DIR"

IMAP_CONTAINER="$(find_service_container imap '(^|[-_])(imap|dovecot)([-_]|$)')"
ADMIN_CONTAINER="$(find_service_container admin '(^|[-_])admin([-_]|$)')"
ANTISPAM_CONTAINER="$(find_service_container antispam '(^|[-_])(antispam|rspamd)([-_]|$)')"

if [[ -z "$MAIL_ROOT" && -n "$IMAP_CONTAINER" ]]; then
    MAIL_ROOT="$(mount_source "$IMAP_CONTAINER" /mail)"
fi
if [[ -z "$MAIL_ROOT" ]]; then
    MAIL_ROOT="$(first_existing_dir "$MAILU_DIR/mail" "$MAILU_DIR/data/mail" "$MAILU_DIR/volumes/mail" || true)"
fi
[[ -n "$MAIL_ROOT" && -d "$MAIL_ROOT" ]] || fail "Maildir path was not found; use --mail-root"

ADMIN_DATA_DIR=""
if [[ -n "$ADMIN_CONTAINER" ]]; then
    ADMIN_DATA_DIR="$(mount_source "$ADMIN_CONTAINER" /data)"
fi
if [[ -z "$DB_PATH" ]]; then
    DB_PATH="$(first_existing_file \
        "$ADMIN_DATA_DIR/main.db" \
        "$ADMIN_DATA_DIR/data/main.db" \
        "$MAILU_DIR/data/main.db" \
        "$MAILU_DIR/data/data/main.db" \
        "$MAILU_DIR/main.db" || true)"
fi
[[ -n "$DB_PATH" && -f "$DB_PATH" ]] || fail "Mailu SQLite database was not found; use --db"

if [[ -z "$RSPAMD_DIR" && -n "$ANTISPAM_CONTAINER" ]]; then
    RSPAMD_DIR="$(mount_source "$ANTISPAM_CONTAINER" /etc/rspamd/override.d)"
    [[ -n "$RSPAMD_DIR" ]] || RSPAMD_DIR="$(mount_source "$ANTISPAM_CONTAINER" /overrides)"
fi
if [[ -z "$RSPAMD_DIR" ]]; then
    RSPAMD_DIR="$(first_existing_dir \
        "$MAILU_DIR/overrides/rspamd" \
        "$MAILU_DIR/data/overrides/rspamd" \
        "$MAILU_DIR/override/rspamd" || true)"
fi
[[ -n "$RSPAMD_DIR" ]] || fail "Rspamd override directory was not found; use --rspamd-dir"
mkdir -p -- "$RSPAMD_DIR"
RSPAMD_ACTIONS_FILE="$RSPAMD_DIR/actions.conf"
RSPAMD_GREYLIST_FILE="$RSPAMD_DIR/greylist.conf"
RSPAMD_FORCE_ACTIONS_FILE="$RSPAMD_DIR/force_actions.conf"
RSPAMD_MULTIMAP_FILE="$RSPAMD_DIR/multimap.conf"

if [[ -z "$DOVECOT_DIR" && -n "$IMAP_CONTAINER" ]]; then
    DOVECOT_DIR="$(mount_source "$IMAP_CONTAINER" /overrides)"
fi
if [[ -z "$DOVECOT_DIR" ]]; then
    DOVECOT_DIR="$(first_existing_dir \
        "$MAILU_DIR/overrides/dovecot" \
        "$MAILU_DIR/data/overrides/dovecot" \
        "$MAILU_DIR/override/dovecot" || true)"
fi
[[ -n "$DOVECOT_DIR" ]] || fail "Dovecot override directory was not found; use --dovecot-dir"
mkdir -p -- "$DOVECOT_DIR"
DOVECOT_OVERRIDE="$DOVECOT_DIR/dovecot.conf"
# Dovecot stores non-ASCII fs-layout mailbox names as IMAP modified UTF-7.
# This decodes to the "全部邮件" label for IMAP clients while remaining portable on disk.
DOVECOT_VIRTUAL_DIR="&UWiQ6JCuTvY-"
DOVECOT_VIRTUAL_RULE="$DOVECOT_DIR/virtual/$DOVECOT_VIRTUAL_DIR/dovecot-virtual"

if [[ -z "$OVERRIDE_DIR" ]]; then
    OVERRIDE_DIR="$(mount_source "$FRONT_CONTAINER" /overrides)"
fi
[[ -n "$OVERRIDE_DIR" ]] || fail "Mailu front does not expose /overrides; add an overrides/nginx:/overrides mount and rerun"
mkdir -p -- "$OVERRIDE_DIR"

if [[ -z "$MAIL_CONTROL_BIND" ]]; then
    MAIL_CONTROL_BIND="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{"\n"}}{{end}}' "$FRONT_CONTAINER" 2>/dev/null | awk 'NF {print; exit}' || true)"
fi
[[ -n "$MAIL_CONTROL_BIND" ]] || fail "Docker gateway was not detected; use --bind with the front container's host gateway"
[[ "$MAIL_CONTROL_PORT" =~ ^[0-9]+$ ]] || fail "port must be numeric"
(( MAIL_CONTROL_PORT >= 1024 && MAIL_CONTROL_PORT <= 65535 )) || fail "port must be between 1024 and 65535"

mkdir -p -- "$INSTALL_DIR"

PYTHON_BIN="$(command -v python3)"
if ! "$PYTHON_BIN" -c 'import bcrypt' >/dev/null 2>&1; then
    VENV_DIR="$INSTALL_DIR/venv"
    if [[ ! -x "$VENV_DIR/bin/python" ]] && ! "$PYTHON_BIN" -m venv "$VENV_DIR" >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            log "Python bcrypt support is unavailable; installing python3-venv"
            apt-get update -qq
            apt-get install -y -qq python3-venv
            "$PYTHON_BIN" -m venv "$VENV_DIR"
        else
            fail "Python crypt/bcrypt support is unavailable and a virtual environment could not be created"
        fi
    fi
    "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --quiet bcrypt || fail "unable to install Python bcrypt dependency"
    PYTHON_BIN="$VENV_DIR/bin/python"
fi
"$PYTHON_BIN" -c 'import bcrypt' >/dev/null 2>&1 || fail "unable to load Python bcrypt dependency"
if [[ -z "$PROXY_SECRET" ]]; then
    PROXY_SECRET="$($PYTHON_BIN -c 'import secrets; print(secrets.token_hex(32))')"
fi
[[ "$PROXY_SECRET" =~ ^[A-Fa-f0-9]{64}$ ]] || fail "MAIL_CONTROL_PROXY_SECRET must be a 64-character hexadecimal value"

TMP_DIR="$(mktemp -d -t mail-control-install.XXXXXX)"
SOURCE_FILE="$TMP_DIR/mail_control.py"
if [[ -n "$SOURCE_DIR" ]]; then
    [[ -f "$SOURCE_DIR/mail_control.py" ]] || fail "mail_control.py not found in $SOURCE_DIR"
    cp -- "$SOURCE_DIR/mail_control.py" "$SOURCE_FILE"
else
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --connect-timeout 15 "$RAW_BASE/mail_control.py" -o "$SOURCE_FILE"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$SOURCE_FILE" "$RAW_BASE/mail_control.py"
    else
        fail "curl or wget is required to download the application source"
    fi
fi
[[ -s "$SOURCE_FILE" ]] || fail "application source is empty"
"$PYTHON_BIN" -m py_compile "$SOURCE_FILE"

BACKUP_DIR="$INSTALL_DIR/backups/$(date +%Y%m%d-%H%M%S)"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
CONTROL_OVERRIDE="$OVERRIDE_DIR/mail-control.conf"
ADMIN_OVERRIDE="$OVERRIDE_DIR/mail-control-admin.conf"
backup_file() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        mkdir -p -- "$BACKUP_DIR"
        cp -a -- "$path" "$BACKUP_DIR/"
        log "backed up $path"
    fi
}

backup_file "$INSTALL_DIR/mail_control.py"
backup_file "$SERVICE_PATH"
backup_file "$CONTROL_OVERRIDE"
backup_file "$ADMIN_OVERRIDE"
backup_file "$RSPAMD_ACTIONS_FILE"
backup_file "$RSPAMD_GREYLIST_FILE"
backup_file "$RSPAMD_FORCE_ACTIONS_FILE"
backup_file "$RSPAMD_MULTIMAP_FILE"
backup_file "$DOVECOT_OVERRIDE"
backup_file "$DOVECOT_VIRTUAL_RULE"

if systemctl is-active --quiet "$SERVICE_NAME"; then
    SERVICE_WAS_ACTIVE=1
fi
CHANGES_APPLIED=1

SERVICE_TMP="$TMP_DIR/mail-control.service"
CONTROL_TMP="$TMP_DIR/mail-control.conf"
ADMIN_TMP="$TMP_DIR/mail-control-admin.conf"
RSPAMD_ACTIONS_TMP="$TMP_DIR/actions.conf"
RSPAMD_GREYLIST_TMP="$TMP_DIR/greylist.conf"
RSPAMD_FORCE_ACTIONS_TMP="$TMP_DIR/force_actions.conf"
DOVECOT_TMP="$TMP_DIR/dovecot.conf"
DOVECOT_VIRTUAL_RULE_TMP="$TMP_DIR/dovecot-virtual"

cat > "$SERVICE_TMP" <<EOF
[Unit]
Description=Mailu Mail Control API
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=MAIL_CONTROL_MAIL_ROOT=$(systemd_quote "$MAIL_ROOT")
Environment=MAIL_CONTROL_DB=$(systemd_quote "$DB_PATH")
Environment=MAIL_CONTROL_RSPAMD_DIR=$(systemd_quote "$RSPAMD_DIR")
Environment=MAIL_CONTROL_BIND=$(systemd_quote "$MAIL_CONTROL_BIND")
Environment=MAIL_CONTROL_PORT=$(systemd_quote "$MAIL_CONTROL_PORT")
Environment=MAIL_CONTROL_PROXY_SECRET=$(systemd_quote "$PROXY_SECRET")
ExecStart=$PYTHON_BIN $INSTALL_DIR/mail_control.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat > "$CONTROL_TMP" <<EOF
location = /mail-control {
    return 301 /admin/mail-control/;
}

location = /mail-control/accounts {
    return 301 /admin/mail-control/accounts/;
}

location = /mail-control/ {
    return 301 /admin/mail-control/;
}

location = /mail-control/accounts/ {
    return 301 /admin/mail-control/accounts/;
}

location ^~ /mail-control/ {
    auth_request /internal/auth/user;
    auth_request_set \$mail_control_user \$upstream_http_x_user;
    error_page 401 403 = @sso_login;
    proxy_set_header X-Remote-User \$mail_control_user;
    proxy_set_header X-Mail-Control-Proxy-Secret "__MAIL_CONTROL_PROXY_SECRET__";
    proxy_set_header Authorization "";
    proxy_hide_header WWW-Authenticate;
    proxy_pass http://$MAIL_CONTROL_BIND:$MAIL_CONTROL_PORT/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Prefix /mail-control;
    proxy_read_timeout 60s;
    client_max_body_size 32m;
}

location = /admin/mail-control {
    return 301 /admin/mail-control/;
}

location = /admin/mail-control/accounts {
    return 301 /admin/mail-control/accounts/;
}

location ^~ /admin/mail-control/ {
    auth_request /internal/auth/user;
    auth_request_set \$mail_control_user \$upstream_http_x_user;
    error_page 401 403 = @sso_login;
    proxy_set_header X-Remote-User \$mail_control_user;
    proxy_set_header X-Mail-Control-Proxy-Secret "__MAIL_CONTROL_PROXY_SECRET__";
    proxy_set_header Authorization "";
    proxy_hide_header WWW-Authenticate;
    proxy_pass http://$MAIL_CONTROL_BIND:$MAIL_CONTROL_PORT/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Prefix /admin/mail-control;
    proxy_read_timeout 60s;
    client_max_body_size 32m;
}
EOF
sed -i "s/__MAIL_CONTROL_PROXY_SECRET__/$PROXY_SECRET/g" "$CONTROL_TMP"

cat > "$RSPAMD_ACTIONS_TMP" <<'EOF'
# Mail Control policy: only explicit manual maps may reject mail.
# Keep thresholds ordered as required by Rspamd while effectively disabling
# score-based reject, add-header, and greylist actions.
reject = 9999.0;
add_header = 9998.0;
greylist = 9997.0;
EOF

cat > "$RSPAMD_GREYLIST_TMP" <<'EOF'
# Do not issue SMTP soft rejects for greylisting.
action = "no action";
EOF

cat > "$RSPAMD_FORCE_ACTIONS_TMP" <<'EOF'
# Do not turn automatic anti-spoof/antivirus findings into SMTP rejects.
# Explicit manual sender/domain blacklist maps remain enforced by multimap.
rules {
    ANTISPOOF_NOAUTH { action = "no action"; }
    ANTISPOOF_DMARC_ENFORCE_LOCAL { action = "no action"; }
    ANTISPOOF_AUTH_FAILED { action = "no action"; }
    ANTIVIRUS_FLAGGED { action = "no action"; }
    ANTIVIRUS_FAILED { action = "no action"; }
}
EOF

install -m 0644 "$RSPAMD_ACTIONS_TMP" "$RSPAMD_ACTIONS_FILE"
install -m 0644 "$RSPAMD_GREYLIST_TMP" "$RSPAMD_GREYLIST_FILE"
install -m 0644 "$RSPAMD_FORCE_ACTIONS_TMP" "$RSPAMD_FORCE_ACTIONS_FILE"
if ! grep -q '^FORBIDDEN_FILE_EXTENSION[[:space:]]*{' "$RSPAMD_MULTIMAP_FILE" 2>/dev/null; then
    cat >> "$RSPAMD_MULTIMAP_FILE" <<'EOF'

# Do not reject based on attachment extension.
FORBIDDEN_FILE_EXTENSION {
    action = "no action";
}
EOF
fi

cat > "$ADMIN_TMP" <<'EOF'
location = /admin/client {
    auth_request /internal/auth/user;
    error_page 401 403 = @sso_login;
    include /etc/nginx/proxy.conf;
    proxy_pass http://$admin;
    expires $expires;
}

location = /apple.mobileconfig {
    auth_request /internal/auth/user;
    error_page 401 403 = @sso_login;
    rewrite ^ /internal/autoconfig/apple break;
    include /etc/nginx/proxy.conf;
    proxy_pass http://$admin;
}

location = /mobileconfig {
    auth_request /internal/auth/user;
    error_page 401 403 = @sso_login;
    rewrite ^ /internal/autoconfig/apple break;
    include /etc/nginx/proxy.conf;
    proxy_pass http://$admin;
}

location = /admin/antispam {
    return 301 /admin/antispam/;
}

location ^~ /admin/antispam/ {
    rewrite ^/admin/antispam/(.*) /$1 break;
    auth_request /internal/auth/admin;
    error_page 401 403 = @sso_login;
    proxy_set_header X-Real-IP "";
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Forwarded-By "";
    proxy_set_header Accept-Encoding "";
    sub_filter_once on;
    sub_filter "</head>" "<style>#mail-control-rspamd-nav{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin:0 12px 0 0;padding:3px 8px;border:1px solid rgba(0,0,0,.12);border-radius:4px;background:#fff}#mail-control-rspamd-nav .mail-control-label{font-size:12px;color:#6c757d;margin-right:2px}#mail-control-rspamd-nav button{border:0;border-radius:3px;background:transparent;color:#495057;padding:5px 8px;font-size:13px;cursor:pointer}#mail-control-rspamd-nav button:hover,#mail-control-rspamd-nav button:focus{background:#e9ecef;color:#212529;outline:0}#mail-control-rspamd-panel{position:fixed;z-index:2000;inset:64px 18px 18px;background:#fff;border:1px solid #ced4da;box-shadow:0 8px 32px rgba(0,0,0,.24);display:flex;flex-direction:column}#mail-control-rspamd-panel[hidden]{display:none}#mail-control-rspamd-panel .mail-control-panel-head{display:flex;align-items:center;justify-content:space-between;min-height:44px;padding:0 12px;border-bottom:1px solid #dee2e6;background:#f8f9fa;color:#343a40;font-size:14px}#mail-control-rspamd-panel .mail-control-panel-close{border:0;background:transparent;color:#495057;font-size:24px;line-height:1;cursor:pointer;padding:2px 8px}#mail-control-rspamd-panel iframe{width:100%;height:100%;border:0;background:#f5f7f9}@media(max-width:767px){#mail-control-rspamd-nav{margin:8px 0;max-width:100%}#mail-control-rspamd-panel{inset:8px;z-index:3000}}</style></head>";
    sub_filter "</body>" "<script>(function(){var items=[{label:'邮件控制',href:'/admin/mail-control/'},{label:'批量邮箱',href:'/admin/mail-control/accounts/'},{label:'邮件营销',href:'/admin/mail-control/marketing/'},{label:'发件 API',href:'/admin/mail-control/marketing/?tab=api'}];var panelRequest=0;async function openPanel(item){var request=++panelRequest,panel=document.getElementById('mail-control-rspamd-panel');if(!panel){panel=document.createElement('section');panel.id='mail-control-rspamd-panel';panel.hidden=true;panel.innerHTML='<div class=\"mail-control-panel-head\"><span></span><button type=\"button\" class=\"mail-control-panel-close\" aria-label=\"关闭\">×</button></div>';document.body.appendChild(panel);panel.querySelector('.mail-control-panel-close').onclick=function(){++panelRequest;panel.hidden=true}}panel.hidden=true;try{var auth=await fetch('/admin/mail-control/api/status',{cache:'no-store',redirect:'error'});if(!auth.ok)throw Error('请重新登录');var state=await auth.json();if(!state.ok)throw Error('请重新登录')}catch(e){panel.querySelectorAll('iframe').forEach(function(f){f.remove()});if(request===panelRequest)location.href='/sso/login';return}if(request!==panelRequest)return;var frame=null;panel.querySelectorAll('iframe').forEach(function(f){f.hidden=true;if(f.dataset.menu===item.href)frame=f});if(!frame){frame=document.createElement('iframe');frame.title=item.label;frame.dataset.menu=item.href;frame.src=item.href+(item.href.indexOf('?')>=0?'&':'?')+'embedded=1';panel.appendChild(frame)}else{try{frame.contentWindow.dispatchEvent(new frame.contentWindow.Event('mail-control-activate'))}catch(e){}}frame.hidden=false;panel.querySelector('.mail-control-panel-head span').textContent=item.label;panel.hidden=false}function init(){if(document.getElementById('mail-control-rspamd-nav'))return;var nav=document.createElement('nav');nav.id='mail-control-rspamd-nav';var label=document.createElement('span');label.className='mail-control-label';label.textContent='中控菜单';nav.appendChild(label);items.forEach(function(item){var b=document.createElement('button');b.type='button';b.textContent=item.label;b.onclick=function(){openPanel(item)};nav.appendChild(b)});var tabs=document.getElementById('tablist');if(tabs&&tabs.parentNode)tabs.parentNode.insertBefore(nav,tabs);else document.body.insertBefore(nav,document.body.firstChild)}if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init()})()</script></body>";
    proxy_pass http://$antispam;
}
EOF

cat > "$DOVECOT_TMP" <<'EOF'
# Mail Control aggregate mailbox for webmail and IMAP clients.
# The virtual plugin indexes existing mail in place; it does not copy, move,
# or delete messages from the physical Maildir folders.
protocol imap {
    mail_plugins = $mail_plugins virtual

    namespace virtual {
        prefix = virtual.
        separator = .
        location = virtual:/overrides/virtual:INDEX=~/virtual:LAYOUT=fs
        list = yes
        hidden = no
        subscriptions = yes

        mailbox "全部邮件" {
            auto = subscribe
            special_use = \All
        }
    }
}
EOF

cat > "$DOVECOT_VIRTUAL_RULE_TMP" <<'EOF'
# Gmail-style all-mail view: include every physical mailbox in the inbox
# namespace, including INBOX, Sent, Drafts, Junk, Trash, and Notes.
*
    all
EOF

install -d -m 0755 "$(dirname "$DOVECOT_VIRTUAL_RULE")"
install -m 0644 "$DOVECOT_TMP" "$DOVECOT_OVERRIDE"
install -m 0644 "$DOVECOT_VIRTUAL_RULE_TMP" "$DOVECOT_VIRTUAL_RULE"

install -m 0750 "$SOURCE_FILE" "$INSTALL_DIR/mail_control.py"
install -m 0644 "$SERVICE_TMP" "$SERVICE_PATH"
install -m 0644 "$CONTROL_TMP" "$CONTROL_OVERRIDE"
install -m 0644 "$ADMIN_TMP" "$ADMIN_OVERRIDE"
systemctl daemon-reload

log "validating Mailu Nginx configuration"
docker exec "$FRONT_CONTAINER" nginx -t
NGINX_CONFIG_WAS_TESTED=1
if [[ -n "$IMAP_CONTAINER" ]]; then
    log "validating Dovecot configuration"
    docker exec "$IMAP_CONTAINER" doveconf -n >/dev/null || fail "Dovecot configuration validation failed"
    docker exec "$IMAP_CONTAINER" doveconf -f protocol=imap -h mail_plugins | grep -qw virtual ||
        fail "Dovecot virtual plugin is not active for IMAP"
    if docker exec "$IMAP_CONTAINER" doveconf -f protocol=lmtp -h namespace | grep -q '^namespace virtual '; then
        fail "Dovecot virtual namespace leaked into LMTP delivery"
    fi
fi
if [[ -n "$ANTISPAM_CONTAINER" ]]; then
    log "reloading Rspamd configuration"
    docker kill -s HUP "$ANTISPAM_CONTAINER" >/dev/null 2>&1 || fail "unable to reload Rspamd configuration"
fi
if [[ -n "$IMAP_CONTAINER" ]]; then
    log "reloading Dovecot virtual mailbox configuration"
    docker exec "$IMAP_CONTAINER" doveadm reload >/dev/null 2>&1 || fail "unable to reload Dovecot configuration"
fi

systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
systemctl is-active --quiet "$SERVICE_NAME" || fail "mail-control service did not start"

HEALTH_HOST="$MAIL_CONTROL_BIND"
[[ "$HEALTH_HOST" == "0.0.0.0" || "$HEALTH_HOST" == "::" ]] && HEALTH_HOST="127.0.0.1"
for attempt in {1..20}; do
    if "$PYTHON_BIN" - "$HEALTH_HOST" "$MAIL_CONTROL_PORT" <<'PY' >/dev/null 2>&1
import sys
import urllib.request

host, port = sys.argv[1:]
with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=2) as response:
    if response.status != 200:
        raise SystemExit(1)
PY
    then
        break
    fi
    [[ "$attempt" -eq 20 ]] && fail "mail-control health check failed"
    sleep 1
done

docker exec "$FRONT_CONTAINER" nginx -s reload
CHANGES_APPLIED=0

log "installed $APP_NAME"
log "Mailu directory: $MAILU_DIR"
log "Maildir: $MAIL_ROOT"
log "Database: $DB_PATH"
log "Mailu front container: $FRONT_CONTAINER"
log "Internal service: $MAIL_CONTROL_BIND:$MAIL_CONTROL_PORT"
[[ -d "$BACKUP_DIR" ]] && log "backup directory: $BACKUP_DIR"
log "Open the public Mailu URL followed by /mail-control/"
