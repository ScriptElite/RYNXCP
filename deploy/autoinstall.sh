#!/usr/bin/env bash
# RYNXCP fully automated installer.
#
# Direct download from GitHub:
#   curl -fsSL https://raw.githubusercontent.com/ScriptElite/RYNXCP/main/deploy/autoinstall.sh -o /root/autoinstall.sh
#   sudo bash /root/autoinstall.sh
#
# Target: a clean Debian or Ubuntu server (Debian 13 / Ubuntu 26.04 or newer
# recommended). Run as root. With no arguments the script auto-detects the
# panel host, admin email and a strong admin password, then installs and
# configures the complete stack without further prompts:
#
#   - system packages, security updates and the Rust toolchain
#   - RYNXCP daemon, API, CLI and web panel
#   - Nginx panel vhost and Let's Encrypt when DNS already points here
#   - Postfix + Dovecot (2.3 and 2.4 compatible), quotas, Sieve, Roundcube
#   - OpenDKIM with panel DKIM, SPF and DMARC records
#   - BIND authoritative zone for the panel host
#   - panel transactional email through loopback Postfix
#   - hosting packages under Administración > Paquetes, seeded with an editable
#     "Por defecto" plan on first API start
#   - the per-site file manager and phpMyAdmin behind the panel login gate
#   - fail2ban, nftables, certificate renewal and backup timers
#
# Usage:
#   sudo bash autoinstall.sh
#   sudo bash autoinstall.sh --host panel.example.com --email admin@example.com
#   sudo RYNX_ADMIN_PASSWORD='...' bash autoinstall.sh --host panel.example.com
#
# The script is non-interactive. It never passes the admin password on the
# command line and prints a generated password once at the end.

set -Eeuo pipefail

REPO="${RYNXCP_REPO:-https://github.com/ScriptElite/RYNXCP.git}"
REF="${RYNXCP_REF:-main}"
SOURCE_DIR="${RYNX_SOURCE_DIR:-}"
DIR="${RYNXCP_DIR:-/opt/rynxcp-src}"

HOST_ARG="${RYNX_HOST:-}"
EMAIL_ARG="${RYNX_ADMIN_EMAIL:-}"
PASSWORD_ARG="${RYNX_ADMIN_PASSWORD:-}"
PANEL_PORT="${RYNX_PANEL_PORT:-2083}"
AGENT_LLM="${RYNX_AGENT_LLM:-rules}"
AGENT_MODEL="${RYNX_AGENT_MODEL:-}"
AGENT_API_URL="${RYNX_AGENT_API_URL:-}"
AGENT_API_MODEL="${RYNX_AGENT_API_MODEL:-}"
AGENT_API_KEY_FILE="${RYNX_AGENT_API_KEY_FILE:-}"
NO_TLS=0

LOG="/var/log/rynxcp/autoinstall.log"
REPO_DIR=""
PUBLIC_IP=""
HOST=""
EMAIL=""
PASSWORD=""
GENERATED_PASSWORD=0

usage() {
  cat <<'EOF'
RYNXCP automated installer

Options:
  --host <fqdn|ip>      Panel hostname or public IP. Auto-detected when omitted.
  --email <address>     Admin email. Defaults to admin@<host> for domains.
  --password <value>    Admin password. Prefer RYNX_ADMIN_PASSWORD instead.
  --panel-port <port>   Public panel port (default 2083; 80 stays for ACME).
  --agent-llm <mode>    rules (default), local, api or hybrid. local/hybrid
                        install Ollama; api uses the external provider.
  --agent-model <name>  Ollama model for local/hybrid. Defaults to a size based
                        on host RAM.
  --agent-api-url URL   External OpenAI-compatible HTTPS endpoint for api/hybrid.
  --agent-api-model M   External model name for api/hybrid.
  --agent-api-key-file F File containing the external API key (mode 0600).
  --no-tls              Do not request a Let's Encrypt certificate.
  --repo <url>          RYNXCP Git repository.
  --ref <ref>           Branch or tag to install (default main).
  --dir <path>          Clone/update directory (default /opt/rynxcp-src).
  --source-dir <path>   Use an existing checkout instead of cloning.
  --yes                 Accepted for compatibility; the script is non-interactive.
  -h, --help            Show this help.

Environment:
  RYNX_HOST, RYNX_ADMIN_EMAIL, RYNX_ADMIN_PASSWORD, RYNX_PANEL_PORT,
  RYNX_AGENT_LLM, RYNX_AGENT_MODEL, RYNX_AGENT_API_URL, RYNX_AGENT_API_MODEL,
  RYNX_AGENT_API_KEY_FILE, RYNXCP_REPO, RYNXCP_REF, RYNXCP_DIR, RYNX_SOURCE_DIR.
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
    --repo) REPO="${2:-}"; shift 2 ;;
    --ref) REF="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --source-dir) SOURCE_DIR="${2:-}"; shift 2 ;;
    --yes) shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (use --help)" ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || die "run this script as root (sudo bash autoinstall.sh)"

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

[[ -r /etc/os-release ]] || die "/etc/os-release not found; Debian or Ubuntu required"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "unsupported distribution '${ID:-unknown}'; Debian or Ubuntu required" ;;
esac

[[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || die "--panel-port must be numeric"
PANEL_PORT=$((10#$PANEL_PORT))
(( PANEL_PORT >= 1 && PANEL_PORT <= 65535 )) || die "--panel-port must be between 1 and 65535"

[[ -n "$REPO" ]] || die "the repository URL is empty"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || die "invalid --ref '$REF'"
[[ "$DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "invalid --dir '$DIR'"

mkdir -p /var/log/rynxcp
exec > >(tee -a "$LOG") 2>&1
trap 'code=$?; printf "\n\033[1;31mFAILED\033[0m at line %s (exit %s). Log: %s\n" "$LINENO" "$code" "$LOG" >&2; exit "$code"' ERR

export DEBIAN_FRONTEND=noninteractive
export GIT_TERMINAL_PROMPT=0

# Wait for unattended-upgrades or other apt clients instead of failing.
install -d -m 0755 /etc/apt/apt.conf.d
printf 'DPkg::Lock::Timeout "600";\n' >/etc/apt/apt.conf.d/99rynxcp-lock

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
}

is_domain() {
  [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

normalize_host() {
  local value="${1,,}"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  value="${value%.}"
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
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if is_ipv4 "$ip"; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
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
  [[ "$lower" != *"admin"* ]] || die "the admin password must not contain the username"
  email_local="${EMAIL%%@*}"
  email_local="${email_local,,}"
  if (( ${#email_local} >= 3 )) && [[ "$lower" == *"$email_local"* ]]; then
    die "the admin password must not contain the email mailbox"
  fi
}

generate_password() {
  local candidate email_local
  while true; do
    candidate="Rynx$(openssl rand -hex 16)Aa1!"
    [[ "$candidate" =~ [a-z] && "$candidate" =~ [A-Z] && "$candidate" =~ [0-9] && "$candidate" =~ [^A-Za-z0-9] ]] || continue
    [[ "${candidate,,}" != *"admin"* ]] || continue
    email_local="${EMAIL%%@*}"
    email_local="${email_local,,}"
    if (( ${#email_local} >= 3 )) && [[ "${candidate,,}" == *"$email_local"* ]]; then
      continue
    fi
    printf '%s' "$candidate"
    return 0
  done
}

# ---------------------------------------------------------------------------
# Base prerequisites and host detection
# ---------------------------------------------------------------------------
log "Installing base prerequisites"
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git openssl patch iproute2

HOST="$(normalize_host "${HOST_ARG}")"
if [[ -z "$HOST" ]]; then
  detected="$(hostname -f 2>/dev/null || true)"
  detected="${detected,,}"
  if is_domain "$detected" && [[ "$detected" != *.localhost && "$detected" != *.local && "$detected" != *.internal ]]; then
    HOST="$detected"
  else
    PUBLIC_IP="$(detect_public_ip || true)"
    if is_ipv4 "$PUBLIC_IP"; then
      HOST="$PUBLIC_IP"
    else
      HOST="127.0.0.1"
    fi
  fi
fi
is_domain "$HOST" || is_ipv4 "$HOST" || die "invalid host '$HOST' (use an FQDN or IPv4 address)"

if is_domain "$HOST"; then
  PUBLIC_IP="${PUBLIC_IP:-$(detect_public_ip || true)}"
  resolved="$(getent ahostsv4 "$HOST" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
  if [[ -z "$resolved" ]]; then
    warn "DNS for $HOST does not resolve yet; Let's Encrypt will probably fail"
  elif is_ipv4 "$PUBLIC_IP" && [[ "$resolved" != "$PUBLIC_IP" ]]; then
    warn "$HOST resolves to $resolved but the public IP is $PUBLIC_IP; TLS may fail"
  fi
fi

if [[ -z "$EMAIL_ARG" ]]; then
  if is_domain "$HOST"; then
    EMAIL="admin@$HOST"
  else
    EMAIL="admin@example.com"
  fi
else
  EMAIL="$(normalize_host "$EMAIL_ARG")"
fi
EMAIL="${EMAIL,,}"
[[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$ ]] || die "invalid admin email '$EMAIL'"

if [[ -n "$PASSWORD_ARG" ]]; then
  PASSWORD="$PASSWORD_ARG"
  validate_password "$PASSWORD"
else
  PASSWORD="$(generate_password)"
  GENERATED_PASSWORD=1
fi

log "Panel host: $HOST"
log "Admin email: $EMAIL"
if is_ipv4 "$HOST"; then
  warn "installing on an IP address: mail DNS, DKIM and panel SMTP notifications stay disabled"
fi

# ---------------------------------------------------------------------------
# Source checkout
# ---------------------------------------------------------------------------
if [[ -n "$SOURCE_DIR" ]]; then
  [[ -d "$SOURCE_DIR" ]] || die "--source-dir '$SOURCE_DIR' does not exist"
  REPO_DIR="$(cd "$SOURCE_DIR" && pwd)"
  log "Using source checkout at $REPO_DIR"
else
  REPO_DIR="$DIR"
  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Updating RYNXCP source in $REPO_DIR ($REF)"
    git -C "$REPO_DIR" remote set-url origin "$REPO" 2>/dev/null || \
      git -C "$REPO_DIR" remote add origin "$REPO"
    git -C "$REPO_DIR" fetch --depth 1 origin "$REF"
    git -C "$REPO_DIR" checkout -f -B "$REF" FETCH_HEAD
    git -C "$REPO_DIR" clean -fdx -e target
  else
    log "Cloning RYNXCP from $REPO ($REF)"
    rm -rf "$REPO_DIR"
    mkdir -p "$(dirname "$REPO_DIR")"
    git clone --depth 1 --branch "$REF" "$REPO" "$REPO_DIR"
  fi
fi

[[ -f "$REPO_DIR/Cargo.toml" && -f "$REPO_DIR/deploy/preinstall.sh" ]] || \
  die "$REPO_DIR is not a RYNXCP checkout"

# Older checkouts imported the std MetadataExt trait, which does not apply to
# cap-std metadata. Repair them before building so installs keep working until
# the checkout is updated.
apply_linux_metadata_fix() {
  local file="$REPO_DIR/crates/rynxd/src/executor/unix.rs"
  [[ -f "$file" ]] || return 0
  grep -q 'use std::os::unix::fs::MetadataExt;' "$file" || return 0
  log "Applying the Linux metadata build fix to the checkout"
  sed -i '/^use std::os::unix::fs::MetadataExt;$/d' "$file"
  sed -i 's|^use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};$|use cap_std::fs::{Dir, MetadataExt, OpenOptions as CapOpenOptions};|' "$file"
  sed -i 's|OffsetDateTime::from(value)\.format|OffsetDateTime::from(value.into_std()).format|' "$file"
  grep -q 'MetadataExt' "$file" || die "could not repair the Linux metadata imports in $file"
  grep -q 'value.into_std()' "$file" || die "could not repair the Linux metadata time conversion in $file"
  return 0
}

apply_linux_metadata_fix

# ---------------------------------------------------------------------------
# Run the upstream one-shot installer
# ---------------------------------------------------------------------------
preinstall_args=(--host "$HOST" --email "$EMAIL" --panel-port "$PANEL_PORT" --yes)
preinstall_args+=(--agent-llm "$AGENT_LLM")
[[ -z "$AGENT_MODEL" ]] || preinstall_args+=(--agent-model "$AGENT_MODEL")
[[ -z "$AGENT_API_URL" ]] || preinstall_args+=(--agent-api-url "$AGENT_API_URL")
[[ -z "$AGENT_API_MODEL" ]] || preinstall_args+=(--agent-api-model "$AGENT_API_MODEL")
[[ -z "$AGENT_API_KEY_FILE" ]] || preinstall_args+=(--agent-api-key-file "$AGENT_API_KEY_FILE")
(( NO_TLS )) && preinstall_args+=(--no-tls)

log "Installing RYNXCP and the full service stack (this takes a while)"
(
  cd "$REPO_DIR"
  RYNX_ADMIN_PASSWORD="$PASSWORD" RYNX_SKIP_MAIL=0 bash deploy/preinstall.sh "${preinstall_args[@]}"
)

# ---------------------------------------------------------------------------
# Final reconcile and verification
# ---------------------------------------------------------------------------
log "Running the initial reconcile"
systemctl restart rynxd >/dev/null 2>&1 || true
systemctl restart rynx-api >/dev/null 2>&1 || true
sleep 2
if rynxctl reconcile >/dev/null 2>&1; then
  log "Reconcile completed"
else
  warn "the initial reconcile failed; the panel will retry after the next change"
fi

log "Verifying services"
for svc in nginx mariadb rynxd rynx-api fail2ban; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    log "$svc: active"
  else
    warn "$svc is not active"
  fi
done
if systemctl is-active --quiet named 2>/dev/null || systemctl is-active --quiet bind9 2>/dev/null; then
  log "BIND: active"
else
  warn "BIND is not active"
fi
if [[ "$AGENT_LLM" == "local" || "$AGENT_LLM" == "hybrid" ]]; then
  if systemctl is-active --quiet ollama 2>/dev/null; then
    log "ollama: active"
  else
    warn "ollama is not active; the AI agent will keep using deterministic rules"
  fi
fi
if [[ "$AGENT_LLM" == "api" || "$AGENT_LLM" == "hybrid" ]]; then
  if [[ -f /etc/rynxcp/agent.env ]]; then
    log "external agent key: stored in /etc/rynxcp/agent.env"
  elif [[ "$AGENT_LLM" == "api" ]]; then
    warn "the external agent key file is missing"
  fi
fi
if command -v doveconf >/dev/null 2>&1; then
  if doveconf -n >/dev/null 2>&1; then
    log "Dovecot configuration: valid"
  else
    die "doveconf -n failed; check /etc/dovecot/conf.d/99-rynxcp.conf"
  fi
fi
if command -v postfix >/dev/null 2>&1; then
  postfix check >/dev/null 2>&1 || warn "postfix check failed"
fi

PANEL_URL="$(sed -n 's/^[[:space:]]*public_url[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' /etc/rynxcp/api.toml 2>/dev/null | tail -n1)"
[[ -n "$PANEL_URL" ]] || PANEL_URL="http://$HOST"

printf '\n\033[1;32mRYNXCP installation finished\033[0m\n\n'
cat <<EOF
  Panel URL:   $PANEL_URL
  Admin user:  admin
EOF

if (( GENERATED_PASSWORD )); then
  if [[ -w /dev/tty ]]; then
    printf '  Admin pass:  %s\n' "$PASSWORD" >/dev/tty
    secret_note="The password is printed above (not in the installer log) and"
  else
    secret_note="The password is"
  fi
  umask 077
  {
    printf 'Panel URL: %s\n' "$PANEL_URL"
    printf 'Admin user: admin\n'
    printf 'Admin password: %s\n' "$PASSWORD"
  } >/root/rynxcp-credentials.txt
  chmod 0600 /root/rynxcp-credentials.txt
  cat <<EOF
  Credentials: /root/rynxcp-credentials.txt (mode 0600)

$secret_note saved in that root-only file. Remove the file after storing the
password.
EOF
else
  cat <<EOF
  Admin pass:  the password you supplied
EOF
fi

cat <<EOF

  Install log: $LOG
  Preinstall:  /var/log/rynxcp/preinstall.log

EOF

if is_domain "$HOST"; then
  cat <<EOF
DNS reminder: keep $HOST (and the ns1.$HOST / ns2.$HOST glue) pointing at
this server so Let's Encrypt can issue and renew the panel certificate.
EOF
fi
