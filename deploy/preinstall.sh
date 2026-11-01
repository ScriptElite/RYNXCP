#!/usr/bin/env bash
# RYNXCP one-shot pre-installer for Debian/Ubuntu.
#
# Installs the full service stack (Nginx, PHP 8.5 from the security-maintained
# repository, MariaDB, BIND9, Pure-FTPd, OpenDKIM tooling, ClamAV, fail2ban, nftables,
# Node.js, Python, Ruby, Java, Go and .NET when available), builds RYNXCP,
# installs the panel, asks for the panel host, admin email and password, and
# publishes the panel behind Nginx with optional Let's Encrypt TLS. It also
# enables panel notifications through local Postfix with outbound SPF/DKIM/DMARC.
#
# Usage:
#   sudo bash deploy/preinstall.sh
#   sudo RYNX_ADMIN_PASSWORD='...' bash deploy/preinstall.sh --host panel.example.com --email admin@example.com --yes
#
# This script never logs the admin password.

set -Eeuo pipefail

PANEL_USER="admin"
HOST_ARG=""
EMAIL_ARG=""
PASSWORD_ARG="${RYNX_ADMIN_PASSWORD:-}"
PANEL_PORT="${RYNX_PANEL_PORT:-2083}"
AGENT_LLM="${RYNX_AGENT_LLM:-rules}"
AGENT_MODEL="${RYNX_AGENT_MODEL:-}"
AGENT_API_URL="${RYNX_AGENT_API_URL:-}"
AGENT_API_MODEL="${RYNX_AGENT_API_MODEL:-}"
AGENT_API_KEY_FILE="${RYNX_AGENT_API_KEY_FILE:-}"
ASSUME_YES=0
NO_TLS=0
SSH_PORT=""
DISTRO_ID=""
DISTRO_CODENAME=""
PUBLIC_IP=""
HOST=""
DKIM_SELECTOR=""
PANEL_SCHEME="http"
TLS_OK=0
LOG="/var/log/rynxcp/preinstall.log"

usage() {
  cat <<'EOF'
RYNXCP pre-installer

Options:
  --host <fqdn|ip>      Panel hostname or public IP. Auto-detected and offered
                        as the default when omitted.
  --email <address>     Admin email. Defaults to admin@<host> for domains.
  --password <value>    Admin password. Prefer RYNX_ADMIN_PASSWORD env var to
                        avoid exposing it in the process list.
  --panel-port <port>   Publish the panel on this TCP port (default 2083).
                        Port 80 is still used for the ACME challenge.
  --agent-llm <mode>    rules (default), local, api or hybrid. local/hybrid
                        install Ollama and a loopback-only service; api uses the
                        external provider.
  --agent-model <name>  Ollama model for local/hybrid. Defaults to a size based
                        on host RAM.
  --agent-api-url URL   External OpenAI-compatible HTTPS endpoint for api/hybrid.
  --agent-api-model M   External model name for api/hybrid.
  --agent-api-key-file F File containing the external API key (mode 0600).
  --no-tls              Do not request a Let's Encrypt certificate.
  --yes                 Assume yes for confirmations (non-interactive).
  -h, --help            Show this help.

Environment:
  RYNX_ADMIN_PASSWORD  Admin password (recommended over --password).
  RYNX_HOST            Same as --host.
  RYNX_ADMIN_EMAIL     Same as --email.
  RYNX_PANEL_PORT      Same as --panel-port.
  RYNX_AGENT_LLM       Same as --agent-llm.
  RYNX_AGENT_MODEL     Same as --agent-model.
  RYNX_AGENT_API_URL   Same as --agent-api-url.
  RYNX_AGENT_API_MODEL Same as --agent-api-model.
  RYNX_AGENT_API_KEY_FILE Same as --agent-api-key-file.
EOF
}

log() { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST_ARG="${2:-}"; shift 2 ;;
    --email) EMAIL_ARG="${2:-}"; shift 2 ;;
    --password) PASSWORD_ARG="${2:-}"; shift 2 ;;
    --panel-port) PANEL_PORT="${2:-}"; shift 2 ;;
    --agent-llm) AGENT_LLM="${2:-}"; shift 2 ;;
    --agent-model) AGENT_MODEL="${2:-}"; shift 2 ;;
    --agent-api-url) AGENT_API_URL="${2:-}"; shift 2 ;;
    --agent-api-model) AGENT_API_MODEL="${2:-}"; shift 2 ;;
    --agent-api-key-file) AGENT_API_KEY_FILE="${2:-}"; shift 2 ;;
    --no-tls) NO_TLS=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (use --help)" ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || die "run this script as root (sudo bash deploy/preinstall.sh)"

mkdir -p /var/log/rynxcp
exec > >(tee -a "$LOG") 2>&1
trap 'code=$?; printf "\n\033[1;31mFAILED\033[0m at line %s (exit %s). Log: %s\n" "$LINENO" "$code" "$LOG" >&2; exit "$code"' ERR

[[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || die "--panel-port must be numeric"
PANEL_PORT=$((10#$PANEL_PORT))
(( PANEL_PORT >= 1 && PANEL_PORT <= 65535 )) || die "--panel-port must be between 1 and 65535"

case "$AGENT_LLM" in
  rules|local|api|hybrid) ;;
  *) die "--agent-llm must be rules, local, api or hybrid" ;;
esac
if [[ -n "$AGENT_MODEL" ]]; then
  [[ "$AGENT_MODEL" =~ ^[A-Za-z0-9._:/-]+$ ]] || die "--agent-model contains invalid characters"
  [[ "$AGENT_MODEL" != -* ]] || die "--agent-model must not start with '-'"
fi
if [[ -n "$AGENT_API_MODEL" ]]; then
  [[ "$AGENT_API_MODEL" =~ ^[A-Za-z0-9._:/-]+$ ]] || die "--agent-api-model contains invalid characters"
  [[ "$AGENT_API_MODEL" != -* ]] || die "--agent-api-model must not start with '-'"
fi
if [[ -n "$AGENT_API_URL" && ! "$AGENT_API_URL" =~ ^https://[^[:space:]]+$ ]]; then
  die "--agent-api-url must be an https URL"
fi
if [[ -n "$AGENT_API_KEY_FILE" && ( ! -r "$AGENT_API_KEY_FILE" || ! -s "$AGENT_API_KEY_FILE" ) ]]; then
  die "--agent-api-key-file must point to a readable, non-empty file"
fi
external_fields=0
[[ -z "$AGENT_API_URL" ]] || external_fields=$((external_fields + 1))
[[ -z "$AGENT_API_MODEL" ]] || external_fields=$((external_fields + 1))
[[ -z "$AGENT_API_KEY_FILE" ]] || external_fields=$((external_fields + 1))
if [[ "$AGENT_LLM" == "api" ]] && (( external_fields != 3 )); then
  die "--agent-llm api requires --agent-api-url, --agent-api-model and --agent-api-key-file"
fi
if [[ "$AGENT_LLM" == "hybrid" ]] && (( external_fields != 0 && external_fields != 3 )); then
  die "--agent-llm hybrid needs all three external options or none"
fi
if [[ "$AGENT_LLM" != "api" && "$AGENT_LLM" != "hybrid" ]]; then
  AGENT_API_URL=""
  AGENT_API_MODEL=""
  AGENT_API_KEY_FILE=""
fi

# ---------------------------------------------------------------------------
# Distribution detection
# ---------------------------------------------------------------------------
[[ -r /etc/os-release ]] || die "/etc/os-release not found; Debian or Ubuntu required"
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-}"
DISTRO_CODENAME="${VERSION_CODENAME:-}"
[[ -n "$DISTRO_CODENAME" ]] || DISTRO_CODENAME="$(lsb_release -sc 2>/dev/null || true)"

case "$DISTRO_ID" in
  ubuntu|debian) ;;
  *) die "unsupported distribution '$DISTRO_ID'; Debian or Ubuntu required" ;;
esac
[[ -n "$DISTRO_CODENAME" ]] || die "cannot determine the distribution codename"

log "Detected ${PRETTY_NAME:-$DISTRO_ID} (${DISTRO_CODENAME})"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
is_ipv4() {
  local ip="$1" octet
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a parts <<<"$ip"
  for octet in "${parts[@]}"; do
    (( octet >= 0 && octet <= 255 )) || return 1
  done
  return 0
}

is_domain() {
  [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

is_email() {
  [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$ ]]
}

normalize_host() {
  local value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  value="${value,,}"
  printf '%s' "$value"
}

detect_public_ip() {
  local ip
  ip="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  if is_ipv4 "$ip"; then
    printf '%s' "$ip"
    return 0
  fi
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
  if is_ipv4 "$ip"; then
    printf '%s' "$ip"
    return 0
  fi
  hostname -I 2>/dev/null | awk '{print $1}' || true
}

detect_host_default() {
  local fqdn
  fqdn="$(hostname -f 2>/dev/null || true)"
  fqdn="${fqdn,,}"
  if is_domain "$fqdn" && [[ "$fqdn" != *.localhost ]]; then
    printf '%s' "$fqdn"
    return 0
  fi
  PUBLIC_IP="$(detect_public_ip || true)"
  if is_ipv4 "$PUBLIC_IP"; then
    printf '%s' "$PUBLIC_IP"
    return 0
  fi
  printf '%s' "127.0.0.1"
}

prompt_default() {
  local prompt="$1" default="$2" value=""
  if [[ -t 0 ]]; then
    read -r -p "$prompt [$default]: " value || true
    value="${value:-$default}"
  else
    value="$default"
  fi
  printf '%s' "$value"
}

confirmation() {
  local prompt="$1" answer=""
  if (( ASSUME_YES )); then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    return 0
  fi
  read -r -p "$prompt [Y/n]: " answer || true
  [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
}

validate_password() {
  local password="$1" classes=0 lower email_local
  (( ${#password} >= 12 )) || die "the admin password must be at least 12 characters"
  (( ${#password} <= 256 )) || die "the admin password is too long"
  [[ "$password" =~ [a-z] ]] && classes=$((classes + 1))
  [[ "$password" =~ [A-Z] ]] && classes=$((classes + 1))
  [[ "$password" =~ [0-9] ]] && classes=$((classes + 1))
  [[ "$password" =~ [^A-Za-z0-9] ]] && classes=$((classes + 1))
  (( classes >= 3 )) || die "the admin password must combine at least 3 character classes"
  lower="${password,,}"
  [[ "$lower" != *"$PANEL_USER"* ]] || die "the admin password must not contain the username"
  email_local="${EMAIL%%@*}"
  email_local="${email_local,,}"
  if (( ${#email_local} >= 3 )) && [[ "$lower" == *"$email_local"* ]]; then
    die "the admin password must not contain the email mailbox"
  fi
}

set_php_ini() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || return 0
  if grep -qE "^[;[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[;[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >>"$file"
  fi
}

set_toml() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || return 0
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >>"$file"
  fi
}

ensure_toml_section() {
  local file="$1" section="$2"
  [[ -f "$file" ]] || return 0
  grep -qE "^[[:space:]]*\[${section}\][[:space:]]*$" "$file" || \
    printf '\n[%s]\n' "$section" >>"$file"
}

install_local_agent() {
  local model="$1" ollama_bin installer
  ollama_bin="$(command -v ollama || true)"
  if [[ -z "$ollama_bin" ]]; then
    installer="$(mktemp)"
    if ! curl -fsSL --max-time 120 https://ollama.com/install.sh -o "$installer"; then
      rm -f "$installer"
      return 1
    fi
    if ! bash "$installer"; then
      rm -f "$installer"
      return 1
    fi
    rm -f "$installer"
    ollama_bin="$(command -v ollama || true)"
  fi
  [[ -n "$ollama_bin" ]] || return 1

  # Loopback-only inference, unload idle models and keep one worker to avoid
  # competing with hosted sites on small VPS instances.
  install -d -m 0755 /etc/systemd/system/ollama.service.d
  cat >/etc/systemd/system/ollama.service.d/rynxcp.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_KEEP_ALIVE=15m"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now ollama >/dev/null 2>&1 || \
    systemctl restart ollama >/dev/null 2>&1 || return 1

  local attempt
  for attempt in {1..30}; do
    if curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 || return 1

  if ! "$ollama_bin" show "$model" >/dev/null 2>&1; then
    "$ollama_bin" pull "$model" || return 1
  fi
  "$ollama_bin" show "$model" >/dev/null 2>&1 || return 1
  return 0
}

write_agent_key() {
  local source="$1" key tmp
  [[ -r "$source" && -s "$source" ]] || return 1
  key="$(tr -d '\r\n' < "$source")"
  [[ -n "$key" ]] || return 1
  [[ "$key" != *[[:space:]]* ]] || return 1
  tmp="$(mktemp)"
  printf 'RYNXCP_AGENT_API_KEY=%s\n' "$key" > "$tmp"
  install -m 0640 -g rynx "$tmp" /etc/rynxcp/agent.env
  rm -f "$tmp"
}

configure_external_agent() {
  local url="$1" model="$2" keyfile="$3"
  if [[ -z "$url" || -z "$model" || -z "$keyfile" ]]; then
    set_toml "$API_CONF" "external_enabled" "false"
    rm -f /etc/rynxcp/agent.env
    return 0
  fi
  if ! write_agent_key "$keyfile"; then
    warn "the external agent API key could not be stored; external provider disabled"
    set_toml "$API_CONF" "external_enabled" "false"
    rm -f /etc/rynxcp/agent.env
    return 1
  fi
  set_toml "$API_CONF" "external_enabled" "true"
  set_toml "$API_CONF" "external_base_url" "\"$url\""
  set_toml "$API_CONF" "external_model" "\"$model\""
  set_toml "$API_CONF" "external_api_key_env" "\"RYNXCP_AGENT_API_KEY\""
  set_toml "$API_CONF" "external_timeout_secs" "120"
  set_toml "$API_CONF" "external_max_tokens" "1200"
  return 0
}

configure_agent() {
  local mode="$1" model="$2" mem_kb
  ensure_toml_section "$API_CONF" "agent"
  set_toml "$API_CONF" "enabled" "true"
  set_toml "$API_CONF" "interval_secs" "300"
  set_toml "$API_CONF" "max_events" "200"
  set_toml "$API_CONF" "email_alerts" "true"
  set_toml "$API_CONF" "mode" "\"$mode\""
  set_toml "$API_CONF" "external_enabled" "false"

  if [[ "$mode" == "api" ]]; then
    log "Configuring the external AI agent (${AGENT_API_MODEL})"
    if ! configure_external_agent "$AGENT_API_URL" "$AGENT_API_MODEL" "$AGENT_API_KEY_FILE"; then
      die "the external AI agent could not be configured"
    fi
    return 0
  fi

  if [[ "$mode" == "hybrid" ]]; then
    configure_external_agent "$AGENT_API_URL" "$AGENT_API_MODEL" "$AGENT_API_KEY_FILE" || true
  else
    rm -f /etc/rynxcp/agent.env
  fi

  [[ "$mode" != "rules" ]] || return 0

  if [[ -z "$model" ]]; then
    mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    if (( mem_kb >= 24 * 1024 * 1024 )); then
      model="qwen3:8b"
    elif (( mem_kb >= 8 * 1024 * 1024 )); then
      model="qwen2.5:3b"
    else
      model="qwen2.5:1.5b"
    fi
  fi

  log "Configuring the local AI agent (Ollama, model ${model})"
  if install_local_agent "$model"; then
    set_toml "$API_CONF" "local_base_url" "\"http://127.0.0.1:11434/v1\""
    set_toml "$API_CONF" "local_model" "\"$model\""
    set_toml "$API_CONF" "local_timeout_secs" "120"
  else
    if [[ "$mode" == "hybrid" && -f /etc/rynxcp/agent.env ]]; then
      warn "the local AI model could not be provisioned; hybrid mode will use the external provider"
    else
      warn "the local AI model could not be provisioned; the agent falls back to rules"
      set_toml "$API_CONF" "mode" "\"rules\""
    fi
  fi
}

# ---------------------------------------------------------------------------
# Interactive input (host / email / password)
# ---------------------------------------------------------------------------
DEFAULT_HOST="$(detect_host_default)"
HOST="$(normalize_host "${HOST_ARG:-${RYNX_HOST:-}}")"
if [[ -z "$HOST" ]]; then
  HOST="$(normalize_host "$(prompt_default 'Panel hostname or public IP' "$DEFAULT_HOST")")"
fi
[[ -n "$HOST" ]] || die "the panel host is required"
is_domain "$HOST" || is_ipv4 "$HOST" || die "invalid host '$HOST' (use a FQDN or an IPv4 address)"

if is_domain "$HOST"; then
  [[ -n "$PUBLIC_IP" ]] || PUBLIC_IP="$(detect_public_ip || true)"
  resolved="$(getent ahostsv4 "$HOST" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
  if [[ -z "$resolved" ]]; then
    warn "DNS for $HOST does not resolve yet; Let's Encrypt issuance will probably fail"
  elif is_ipv4 "$PUBLIC_IP" && [[ "$resolved" != "$PUBLIC_IP" ]]; then
    warn "$HOST resolves to $resolved but this server's public IP is $PUBLIC_IP"
  fi
fi

EMAIL="$(normalize_host "${EMAIL_ARG:-${RYNX_ADMIN_EMAIL:-}}")"
EMAIL="${EMAIL,,}"
if [[ -z "$EMAIL" ]]; then
  if is_domain "$HOST"; then
    EMAIL="$(prompt_default 'Admin email' "admin@$HOST")"
  else
    EMAIL="$(prompt_default 'Admin email' "admin@example.com")"
  fi
fi
is_email "$EMAIL" || die "invalid admin email '$EMAIL'"

if [[ -z "$PASSWORD_ARG" ]]; then
  if [[ ! -t 0 ]]; then
    die "set RYNX_ADMIN_PASSWORD or pass --password when running non-interactively"
  fi
  while true; do
    read -r -s -p "Admin password: " PASSWORD_ARG || true
    printf '\n'
    read -r -s -p "Repeat admin password: " password_confirm || true
    printf '\n'
    [[ "$PASSWORD_ARG" == "$password_confirm" ]] || { warn "passwords do not match"; continue; }
    break
  done
fi
validate_password "$PASSWORD_ARG"

if ! confirmation "Install RYNXCP and the full service stack on this server now?"; then
  die "aborted by the user"
fi

SSH_PORT="$(
  grep -rhE '^[[:space:]]*Port[[:space:]]+[0-9]+' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
    | awk '{print $2; exit}' || true
)"
SSH_PORT="${SSH_PORT:-22}"

log "Panel host: $HOST"
log "Admin: $PANEL_USER <$EMAIL>"
log "SSH port kept open in the firewall: $SSH_PORT"

# ---------------------------------------------------------------------------
# Base system and security updates
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive

# Wait for unattended-upgrades or other apt clients instead of failing.
install -d -m 0755 /etc/apt/apt.conf.d
printf 'DPkg::Lock::Timeout "600";\n' >/etc/apt/apt.conf.d/99rynxcp-lock

log "Refreshing APT metadata and applying security updates"
apt-get update
apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade

log "Installing base tooling"
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release apt-transport-https \
  software-properties-common build-essential pkg-config git openssl libssl-dev \
  nftables fail2ban logrotate unattended-upgrades

# ---------------------------------------------------------------------------
# PHP 8.5 package source
#
# Ubuntu 26.04 LTS (resolute) and newer already ship PHP 8.5 in the
# distribution repositories. The Ondrej PPA does not publish a resolute
# suite (its maintainer moved 26.04+ to packages.sury.org), so adding it
# there makes "apt-get update" fail and aborts this script. Only add a
# third-party repository when the distribution does not provide PHP 8.5.
# ---------------------------------------------------------------------------
log "Configuring the PHP 8.5 package source"
if apt-cache show php8.5-fpm >/dev/null 2>&1; then
  log "PHP 8.5 is provided by ${PRETTY_NAME:-$DISTRO_ID}; no third-party repository needed"
else
  if [[ "$DISTRO_ID" == "ubuntu" ]]; then
    if [[ "$DISTRO_CODENAME" == "resolute" ]]; then
      die "PHP 8.5 is not available from the Ubuntu 26.04 repositories; enable the 'universe' component and retry"
    fi
    apt-get install -y software-properties-common
    add-apt-repository -y ppa:ondrej/php
  else
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL --max-time 60 https://packages.sury.org/php/apt.gpg \
      -o /usr/share/keyrings/sury-php.gpg
    printf 'deb [signed-by=/usr/share/keyrings/sury-php.gpg] https://packages.sury.org/php/ %s main\n' \
      "$DISTRO_CODENAME" > /etc/apt/sources.list.d/sury-php.list
  fi
  apt-get update
fi
apt-cache show php8.5-fpm >/dev/null 2>&1 || die "PHP 8.5 is not available for $DISTRO_CODENAME; check the PHP repository"

log "Installing web, database, DNS, FTP, mail tooling, firewall and runtimes"
# PHP 8.5 compiles OPcache into the runtime: there is no php8.5-opcache package.
apt-get install -y --no-install-recommends \
  nginx certbot python3-certbot-nginx openssh-server restic \
  php8.5-fpm php8.5-cli php8.5-common php8.5-mysql php8.5-curl php8.5-mbstring \
  php8.5-xml php8.5-zip php8.5-gd php8.5-intl php8.5-bcmath \
  composer unzip mariadb-server bind9 bind9-utils bind9-dnsutils \
  pure-ftpd opendkim opendkim-tools cron quota xfsprogs \
  clamav clamav-daemon clamav-freshclam clamav-milter \
  spamassassin spamd spamc spamass-milter \
  nodejs npm python3 python3-venv python3-pip ruby-full default-jre-headless golang-go

# WP-CLI powers the WordPress one-click installer. Install the official phar
# when the distribution does not provide it.
if ! command -v wp >/dev/null 2>&1; then
  log "Installing WP-CLI for the WordPress installer"
  wp_tmp="$(mktemp)"
  if curl -fsSL --max-time 120 \
      https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
      -o "$wp_tmp" && php8.5 "$wp_tmp" --info >/dev/null 2>&1; then
    install -m 0755 "$wp_tmp" /usr/local/bin/wp
  else
    warn "WP-CLI could not be installed; the WordPress installer will not be available"
  fi
  rm -f "$wp_tmp"
fi

# .NET is best-effort: package availability differs between releases.
# Ubuntu 26.04 ships dotnet-sdk-10.0 in its own feed; the Microsoft feed is
# only a fallback for older releases and Debian.
if ! command -v dotnet >/dev/null 2>&1; then
  dotnet_pkg=""
  for candidate in dotnet-sdk-10.0 dotnet-sdk-9.0 dotnet-sdk-8.0; do
    if apt-cache show "$candidate" >/dev/null 2>&1; then
      dotnet_pkg="$candidate"
      break
    fi
  done
  if [[ -z "$dotnet_pkg" ]]; then
    if curl -fsSL --max-time 60 \
      "https://packages.microsoft.com/config/${DISTRO_ID}/${VERSION_ID}/packages-microsoft-prod.deb" \
      -o /tmp/packages-microsoft-prod.deb 2>/dev/null; then
      dpkg -i /tmp/packages-microsoft-prod.deb >/dev/null 2>&1 || true
      apt-get update >/dev/null 2>&1 || true
      for candidate in dotnet-sdk-10.0 dotnet-sdk-9.0 dotnet-sdk-8.0; do
        if apt-cache show "$candidate" >/dev/null 2>&1; then
          dotnet_pkg="$candidate"
          break
        fi
      done
    fi
  fi
  if [[ -n "$dotnet_pkg" ]]; then
    apt-get install -y "$dotnet_pkg" || warn "$dotnet_pkg could not be installed automatically"
  else
    warn ".NET SDK is not available for $DISTRO_ID $VERSION_ID; install it manually if needed"
  fi
fi

# ---------------------------------------------------------------------------
# Per-account disk quotas
# ---------------------------------------------------------------------------
configure_disk_quotas() {
  local target="" source="" fstype=""
  command -v findmnt >/dev/null 2>&1 || return 1
  read -r target source fstype < <(findmnt -n -o TARGET,SOURCE,FSTYPE -T /home 2>/dev/null || true)
  if [[ -z "$target" ]]; then
    read -r target source fstype < <(findmnt -n -o TARGET,SOURCE,FSTYPE -T / 2>/dev/null || true)
  fi
  [[ -n "$target" && -n "$source" && -n "$fstype" ]] || return 1
  case "$fstype" in
    ext2|ext3|ext4)
      command -v tune2fs >/dev/null 2>&1 || return 1
      command -v setquota >/dev/null 2>&1 || return 1
      if ! tune2fs -l "$source" 2>/dev/null | grep -q 'quota'; then
        tune2fs -O quota "$source" >/dev/null 2>&1 || {
          warn "the quota feature could not be enabled on $source"
          return 1
        }
      fi
      mount -o remount,quota "$target" >/dev/null 2>&1 || {
        warn "the filesystem $target could not be remounted with quotas"
        return 1
      }
      quotaon "$target" >/dev/null 2>&1 || true
      ;;
    xfs)
      command -v xfs_quota >/dev/null 2>&1 || return 1
      mount -o remount,uquota "$target" >/dev/null 2>&1 || {
        warn "the XFS filesystem $target could not be remounted with quotas"
        return 1
      }
      ;;
    *)
      warn "disk quotas are not available on $fstype ($target)"
      return 1
      ;;
  esac
}

log "Configuring filesystem disk quotas"
if configure_disk_quotas; then
  log "Disk quotas are enabled for hosting accounts"
else
  warn "disk quotas are unavailable; account_mb will not be enforced by the kernel"
fi

# ---------------------------------------------------------------------------
# PHP security hardening and unattended security updates
# ---------------------------------------------------------------------------
log "Hardening PHP 8.5 defaults"
for ini in /etc/php/8.5/fpm/php.ini /etc/php/8.5/cli/php.ini; do
  set_php_ini "$ini" "expose_php" "Off"
  set_php_ini "$ini" "display_errors" "Off"
  set_php_ini "$ini" "log_errors" "On"
  set_php_ini "$ini" "session.cookie_httponly" "1"
  set_php_ini "$ini" "session.cookie_samesite" "Strict"
  set_php_ini "$ini" "session.use_strict_mode" "1"
  set_php_ini "$ini" "allow_url_include" "Off"
  set_php_ini "$ini" "opcache.enable" "1"
done

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || warn "unattended-upgrades could not be enabled"

# ---------------------------------------------------------------------------
# Enable services
# ---------------------------------------------------------------------------
log "Enabling services"
systemctl enable --now nginx
systemctl enable --now php8.5-fpm
systemctl enable --now mariadb
systemctl enable --now ssh >/dev/null 2>&1 || warn "the SSH service could not be enabled"
# On current Debian/Ubuntu, named.service is the real unit and bind9.service
# is an alias, so "systemctl enable bind9" fails with "linked unit file".
systemctl enable --now named 2>/dev/null || \
  systemctl enable --now bind9 2>/dev/null || \
  warn "BIND9 could not be enabled automatically"
systemctl enable --now pure-ftpd
systemctl enable --now cron >/dev/null 2>&1 || warn "cron could not be enabled"
systemctl enable --now fail2ban
systemctl enable --now nftables >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Rust toolchain and RYNXCP build
# ---------------------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing the Rust toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || die "cargo is not available after installing Rust"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
log "Building RYNXCP (release)"
CARGO_NET_RETRY=3 cargo build --release

log "Installing RYNXCP (daemon, API, CLI, web UI, units, timers)"
bash "$ROOT_DIR/deploy/install.sh"

if command -v named-checkconf >/dev/null 2>&1; then
  named-checkconf || warn "BIND configuration check failed"
  systemctl reload bind9 >/dev/null 2>&1 || warn "BIND could not be reloaded"
fi

# ---------------------------------------------------------------------------
# Configure the panel host and security policy
# ---------------------------------------------------------------------------
DAEMON_CONF="/etc/rynxcp/rynxd.toml"
API_CONF="/etc/rynxcp/api.toml"
[[ -f "$DAEMON_CONF" ]] || die "$DAEMON_CONF was not created by the installer"
[[ -f "$API_CONF" ]] || die "$API_CONF was not created by the installer"

log "Configuring RYNXCP for $HOST"
if [[ -n "$PUBLIC_IP" ]] && is_ipv4 "$PUBLIC_IP"; then
  set_toml "$DAEMON_CONF" "default_ipv4" "\"$PUBLIC_IP\""
fi
set_toml "$DAEMON_CONF" "simulate" "false"
set_toml "$DAEMON_CONF" "dns_enabled" "true"
set_toml "$DAEMON_CONF" "db_enabled" "true"
set_toml "$DAEMON_CONF" "ftp_enabled" "true"
set_toml "$DAEMON_CONF" "firewall_enabled" "true"
set_toml "$DAEMON_CONF" "firewall_backend" "\"nftables\""
set_toml "$DAEMON_CONF" "firewall_ssh_port" "$SSH_PORT"
set_toml "$DAEMON_CONF" "panel_port" "$PANEL_PORT"
set_toml "$DAEMON_CONF" "tls_email" "\"$EMAIL\""
# Email DNS requires a mail server; keep it disabled until one exists.
set_toml "$DAEMON_CONF" "mail_enabled" "false"
if [[ "${RYNX_SKIP_MAIL:-0}" != "1" ]]; then
  log "Installing the Postfix/Dovecot/Roundcube mail stack"
  bash "$ROOT_DIR/deploy/mail-setup.sh"
  DKIM_SELECTOR="mail"
fi

# ---------------------------------------------------------------------------
# Antivirus: system files and SMTP messages
# ---------------------------------------------------------------------------
log "Configuring ClamAV antivirus"
[[ -d /var/vmail ]] || install -d -m 0750 /var/vmail
systemctl enable --now clamav-freshclam >/dev/null 2>&1 || warn "clamav-freshclam could not be enabled"
freshclam_ready=0
for _ in {1..30}; do
  if [[ -e /var/lib/clamav/main.cvd || -e /var/lib/clamav/main.cld ]]; then
    freshclam_ready=1
    break
  fi
  sleep 2
done
if (( freshclam_ready == 0 )); then
  warn "ClamAV database is not ready yet; freshclam will retry in the background"
fi
systemctl enable clamav-daemon >/dev/null 2>&1 || warn "clamav-daemon could not be enabled"
systemctl restart clamav-daemon >/dev/null 2>&1 || warn "clamav-daemon could not be started"
for _ in {1..30}; do
  [[ -S /var/run/clamav/clamd.ctl ]] && break
  sleep 1
done
if command -v postfix >/dev/null 2>&1 && [[ -f /etc/clamav/clamav-milter.conf ]]; then
  systemctl enable clamav-milter >/dev/null 2>&1 || warn "clamav-milter could not be enabled"
  systemctl restart clamav-milter >/dev/null 2>&1 || warn "clamav-milter could not be started"
fi
systemctl enable --now rynxcp-antivirus.timer >/dev/null 2>&1 || warn "the antivirus timer could not be enabled"

log "Configuring SpamAssassin antispam"
spam_defaults_seen=0
for spam_defaults in /etc/default/spamd /etc/default/spamassassin; do
  [[ -f "$spam_defaults" ]] || continue
  spam_defaults_seen=1
  if grep -q '^ENABLED=' "$spam_defaults"; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' "$spam_defaults"
  else
    printf '\nENABLED=1\n' >>"$spam_defaults"
  fi
done
if (( spam_defaults_seen == 0 )); then
  printf 'ENABLED=1\n' >/etc/default/spamd
fi
cat >/etc/default/spamass-milter <<'EOF'
# managed-by: RYNXCP
ENABLED=1
SOCKET="/var/spool/postfix/spamass/spamass.sock"
SOCKETOWNER="postfix:postfix"
SOCKETMODE="0660"
OPTIONS="-u spamass-milter -r 15 -m"
EOF
chmod 0644 /etc/default/spamass-milter
install -d -o spamass-milter -g postfix -m 0750 /var/spool/postfix/spamass
spamd_unit=""
if systemctl cat spamd.service >/dev/null 2>&1; then
  spamd_unit="spamd"
elif systemctl cat spamassassin.service >/dev/null 2>&1; then
  spamd_unit="spamassassin"
fi
if [[ -n "$spamd_unit" ]]; then
  systemctl enable --now "$spamd_unit" >/dev/null 2>&1 || warn "$spamd_unit could not be enabled"
  systemctl restart "$spamd_unit" >/dev/null 2>&1 || warn "$spamd_unit could not be started"
else
  warn "SpamAssassin daemon unit was not found"
fi
if command -v postfix >/dev/null 2>&1; then
  systemctl enable spamass-milter >/dev/null 2>&1 || warn "spamass-milter could not be enabled"
  systemctl restart spamass-milter >/dev/null 2>&1 || warn "spamass-milter could not be started"
fi
if [[ "${RYNX_SKIP_PHPMYADMIN:-0}" != "1" ]]; then
  log "Installing phpMyAdmin behind the panel login"
  bash "$ROOT_DIR/deploy/phpmyadmin-setup.sh"
fi
if [[ -z "$PUBLIC_IP" ]]; then
  PUBLIC_IP="$(detect_public_ip || true)"
fi
if is_domain "$HOST"; then
  set_toml "$DAEMON_CONF" "dns_nameservers" "[\"ns1.$HOST\", \"ns2.$HOST\"]"
  if is_ipv4 "$PUBLIC_IP"; then
    log "Creating the panel DNS zone for $HOST"
    bash "$ROOT_DIR/deploy/panel-dns-zone.sh" "$HOST" "$PUBLIC_IP" "$DKIM_SELECTOR" || \
      warn "the panel DNS zone could not be created; configure ns1.$HOST manually"
  else
    warn "no public IPv4 detected; the panel DNS zone for $HOST was not created"
  fi
fi

# Refresh every panel-managed zone so DKIM/DNS fixes are applied on each run,
# even when the panel host is an IP or differs from the signed mail domain.
if is_ipv4 "$PUBLIC_IP" && [[ -d /etc/bind/zones ]]; then
  for panel_zone in /etc/bind/zones/*.db; do
    [[ -f "$panel_zone" ]] || continue
    grep -q 'managed-by: RYNXCP panel' "$panel_zone" 2>/dev/null || continue
    panel_zone_domain="$(basename "$panel_zone" .db)"
    [[ "$panel_zone_domain" == "$HOST" ]] && continue
    is_domain "$panel_zone_domain" || continue
    log "Refreshing the panel DNS zone for $panel_zone_domain"
    bash "$ROOT_DIR/deploy/panel-dns-zone.sh" "$panel_zone_domain" "$PUBLIC_IP" "$DKIM_SELECTOR" || \
      warn "the panel DNS zone for $panel_zone_domain could not be refreshed"
  done
fi

# Repair DKIM key ownership and modes on every run. Keys created by an older
# install or copied from a backup can end up unreadable by the OpenDKIM milter,
# which makes Postfix reject all signed mail with 451 4.7.1.
if id opendkim >/dev/null 2>&1 && [[ -d /etc/opendkim ]]; then
  log "Repairing OpenDKIM key permissions"
  chown opendkim:opendkim /etc/opendkim 2>/dev/null || true
  chmod 0750 /etc/opendkim
  if [[ -d /etc/opendkim/keys ]]; then
    chown -R opendkim:opendkim /etc/opendkim/keys 2>/dev/null || true
    find /etc/opendkim/keys -type d -exec chmod 0750 {} +
    find /etc/opendkim/keys -type f -name '*.private' -exec chmod 0600 {} +
    find /etc/opendkim/keys -type f -name '*.public' -exec chmod 0644 {} +
  fi
  for dkim_table in KeyTable SigningTable TrustedHosts; do
    if [[ -f "/etc/opendkim/$dkim_table" ]]; then
      chown opendkim:opendkim "/etc/opendkim/$dkim_table" 2>/dev/null || true
      chmod 0640 "/etc/opendkim/$dkim_table"
    fi
  done
  systemctl try-restart opendkim >/dev/null 2>&1 || warn "opendkim could not be restarted"
fi

set_toml "$API_CONF" "trust_proxy_headers" "true"

# ---------------------------------------------------------------------------
# Panel vhost
#
# Port 80 is always kept for the ACME HTTP-01 challenge. When --panel-port is
# different from 80, the panel itself listens on that port (TLS when possible)
# and port 80 only redirects.
# ---------------------------------------------------------------------------
PANEL_SITE="/etc/nginx/sites-available/rynxcp-panel"

panel_pma_include() {
  if [[ -f /etc/nginx/snippets/rynxcp-phpmyadmin.conf ]]; then
    printf '    include /etc/nginx/snippets/rynxcp-phpmyadmin.conf;\n'
  fi
}

panel_proxy_block() {
  cat <<EOF
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
    }
EOF
}

panel_vhost_default() {
  {
    cat <<EOF
# managed-by: RYNXCP
server {
    listen 80;
    listen [::]:80;
    server_name $HOST;

    client_max_body_size 32m;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/_acme;
        default_type "text/plain";
    }

EOF
    panel_proxy_block
    panel_pma_include
    cat <<EOF
}
EOF
  } >"$PANEL_SITE"
}

panel_vhost_http_custom() {
  local http_suffix=""
  if [[ "$PANEL_PORT" != "80" ]]; then
    http_suffix=":$PANEL_PORT"
  fi
  {
    cat <<EOF
# managed-by: RYNXCP
server {
    listen 80;
    listen [::]:80;
    server_name $HOST;

    client_max_body_size 32m;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/_acme;
        default_type "text/plain";
    }

    location / {
        return 301 http://\$host${http_suffix}\$request_uri;
    }
}

server {
    listen ${PANEL_PORT};
    listen [::]:${PANEL_PORT};
    server_name $HOST;

    client_max_body_size 32m;

EOF
    panel_proxy_block
    panel_pma_include
    cat <<EOF
}
EOF
  } >"$PANEL_SITE"
}

panel_vhost_tls_custom() {
  local https_suffix=""
  if [[ "$PANEL_PORT" != "443" ]]; then
    https_suffix=":$PANEL_PORT"
  fi
  {
    cat <<EOF
# managed-by: RYNXCP
server {
    listen 80;
    listen [::]:80;
    server_name $HOST;

    client_max_body_size 32m;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/_acme;
        default_type "text/plain";
    }

    location / {
        return 301 https://\$host${https_suffix}\$request_uri;
    }
}

server {
    listen ${PANEL_PORT} ssl;
    listen [::]:${PANEL_PORT} ssl;
    server_name $HOST;
    server_tokens off;
    client_max_body_size 32m;

    ssl_certificate     /etc/letsencrypt/live/$HOST/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$HOST/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:RYNXCP:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=31536000" always;

EOF
    panel_proxy_block
    panel_pma_include
    cat <<EOF
}
EOF
  } >"$PANEL_SITE"
}

panel_reload() {
  ln -sfn "$PANEL_SITE" /etc/nginx/sites-enabled/rynxcp-panel
  nginx -t
  systemctl reload nginx
}

if [[ "$PANEL_PORT" == "80" ]]; then
  panel_vhost_default
  panel_reload

  if is_domain "$HOST" && (( NO_TLS == 0 )); then
    log "Requesting the Let's Encrypt certificate for $HOST"
    if certbot --nginx -d "$HOST" --non-interactive --agree-tos -m "$EMAIL" \
        --redirect --keep-until-expiring; then
      TLS_OK=1
      PANEL_SCHEME="https"
    elif [[ -f "/etc/letsencrypt/live/$HOST/fullchain.pem" ]]; then
      TLS_OK=1
      PANEL_SCHEME="https"
      warn "reusing the existing certificate for $HOST"
    else
      warn "certbot failed; the panel stays on HTTP. Fix DNS and run certbot later."
    fi
  elif ! is_domain "$HOST"; then
    warn "the panel host is an IP address; Let's Encrypt is not available and the panel will use HTTP"
  fi
else
  if is_domain "$HOST" && (( NO_TLS == 0 )); then
    if [[ -f "/etc/letsencrypt/live/$HOST/fullchain.pem" ]]; then
      TLS_OK=1
      PANEL_SCHEME="https"
    else
      log "Publishing HTTP on port 80 for the ACME challenge"
      panel_vhost_http_custom
      panel_reload

      log "Requesting the Let's Encrypt certificate for $HOST"
      if certbot certonly --webroot -w /var/www/_acme -d "$HOST" \
          --non-interactive --agree-tos -m "$EMAIL" \
          --keep-until-expiring --deploy-hook "systemctl reload nginx"; then
        TLS_OK=1
        PANEL_SCHEME="https"
      else
        warn "certbot failed; the panel stays on HTTP. Fix DNS and run certbot later."
      fi
    fi

    if (( TLS_OK == 1 )); then
      panel_vhost_tls_custom
    else
      panel_vhost_http_custom
    fi
    panel_reload
  else
    if ! is_domain "$HOST"; then
      warn "the panel host is an IP address; Let's Encrypt is not available and the panel will use HTTP"
    fi
    panel_vhost_http_custom
    panel_reload
  fi
fi

if (( TLS_OK == 1 )); then
  set_toml "$API_CONF" "secure_cookies" "true"
  if [[ "$PANEL_PORT" == "443" ]]; then
    set_toml "$API_CONF" "public_url" "\"https://$HOST\""
  else
    set_toml "$API_CONF" "public_url" "\"https://$HOST:$PANEL_PORT\""
  fi
else
  set_toml "$API_CONF" "secure_cookies" "false"
  if [[ "$PANEL_PORT" == "80" ]]; then
    set_toml "$API_CONF" "public_url" "\"http://$HOST\""
  else
    set_toml "$API_CONF" "public_url" "\"http://$HOST:$PANEL_PORT\""
  fi
fi

# Transactional panel email through local Postfix. Only domains can have a
# DKIM-signing sender, so IP-based installs keep SMTP disabled.
if is_domain "$HOST" && [[ -n "$DKIM_SELECTOR" ]]; then
  set_toml "$API_CONF" "smtp_enabled" "true"
  set_toml "$API_CONF" "smtp_host" "\"127.0.0.1\""
  set_toml "$API_CONF" "smtp_port" "25"
  set_toml "$API_CONF" "smtp_from" "\"noreply@$HOST\""
  set_toml "$API_CONF" "smtp_alert_to" "\"$EMAIL\""
  set_toml "$API_CONF" "smtp_tls" "\"none\""
  if [[ "${EMAIL##*@}" == "$HOST" ]]; then
    warn "the admin email is in $HOST, which has no MX by design; certificate alerts may bounce. Use --email with an external mailbox or change smtp_alert_to."
  fi
else
  set_toml "$API_CONF" "smtp_enabled" "false"
fi

configure_agent "$AGENT_LLM" "$AGENT_MODEL"

PANEL_URL="${PANEL_SCHEME}://${HOST}"
if { [[ "$PANEL_SCHEME" == "https" && "$PANEL_PORT" != "443" ]] || \
     [[ "$PANEL_SCHEME" == "http" && "$PANEL_PORT" != "80" ]]; }; then
  PANEL_URL="${PANEL_URL}:${PANEL_PORT}"
fi

log "Restarting RYNXCP"
systemctl restart rynxd
systemctl restart rynx-api
sleep 2
systemctl is-active --quiet rynxd || die "rynxd failed to start (journalctl -u rynxd)"
systemctl is-active --quiet rynx-api || die "rynx-api failed to start (journalctl -u rynx-api)"

log "Applying the initial reconcile"
rynxctl --config "$API_CONF" reconcile >/dev/null 2>&1 || \
  warn "the initial reconcile failed; rynxd will retry on its next start"

# ---------------------------------------------------------------------------
# Create or update the administrator
# ---------------------------------------------------------------------------
log "Creating the panel administrator"
export RYNXCTL_PASSWORD="$PASSWORD_ARG"
if rynxctl --config "$API_CONF" admin list 2>/dev/null | awk '{print $1}' | grep -qx "$PANEL_USER"; then
  rynxctl --config "$API_CONF" admin passwd "$PANEL_USER"
else
  rynxctl --config "$API_CONF" admin create "$PANEL_USER" --email "$EMAIL" --role owner
fi
unset RYNXCTL_PASSWORD

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
log "Verifying the installation"
rynxctl --config "$API_CONF" daemon ping >/dev/null
curl -fsS --max-time 10 "http://127.0.0.1:8080/api/v1/health" >/dev/null

for _ in $(seq 1 10); do
  if nft list table inet rynxcp >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! nft list table inet rynxcp >/dev/null 2>&1; then
  warn "the nftables table was not applied yet; open the Firewall view once and save a rule"
fi

if (( TLS_OK == 1 )); then
  panel_ok=0
  for _ in $(seq 1 10); do
    if curl -fsS --max-time 5 "$PANEL_URL/api/v1/health" >/dev/null 2>&1; then
      panel_ok=1
      break
    fi
    sleep 1
  done
  if (( panel_ok == 0 )); then
    warn "HTTPS health check failed; verify DNS, the certificate and the firewall"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
PHP_VERSION="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
PANEL_MAIL_SUMMARY="disabled"
if is_domain "$HOST" && [[ -n "$DKIM_SELECTOR" ]]; then
  PANEL_MAIL_SUMMARY="noreply@$HOST via 127.0.0.1:25 (SPF/DKIM/DMARC)"
fi
cat <<EOF

RYNXCP is ready.

  Panel:    ${PANEL_URL}
  User:     ${PANEL_USER}
  Email:    ${EMAIL}
  Password: (the value you entered; it was not logged)
  PHP:      ${PHP_VERSION:-8.5}
  SSH port: ${SSH_PORT} (always allowed by the firewall)
  Panel mail: ${PANEL_MAIL_SUMMARY}

Installed:
  Nginx, PHP 8.5 (security-maintained repo), MariaDB, BIND9, Pure-FTPd,
  OpenDKIM, ClamAV (system + SMTP), SpamAssassin antispam, fail2ban,
  nftables, unattended-upgrades, Node.js, Python, Ruby, Java,
  Go${DOTNET_NOTE:-}, Postfix, Dovecot, Roundcube and phpMyAdmin

Timers:
  rynxcp-cert-renew.timer  daily Let's Encrypt renewal
  rynxcp-backup.timer      nightly account backups
  rynxcp-antivirus.timer   daily filesystem antivirus scan

Next steps:
  1. Point the NS records of each hosted domain to ns1.$HOST / ns2.$HOST or
     use your provider's DNS. Create glue/A records for ns1 and ns2.
  2. The reverse PTR of ${PUBLIC_IP:-your public IP} must resolve to your mail
     hostname before sending email, and outbound TCP/25 must be open.
  3. Create a website, open "Correo" and activate mail for its domain. RYNXCP
     provisions MX/SPF/DKIM/DMARC/SRV/TLS-RPT and starts the webmail SSL job.
  4. Log in, open "Programas" to review updates and "Consola" for diagnostics.
  5. Open "Sistema > Correo del panel" and send a test message; then use
     "¿Olvidaste tu contraseña?" to verify password-reset delivery.
  6. Use "Bases de datos > phpMyAdmin": it requires the active panel session
     and your MariaDB credentials.

Log: $LOG
EOF
if [[ -f /var/run/reboot-required ]]; then
  warn "a reboot is recommended to finish kernel/library updates"
fi


