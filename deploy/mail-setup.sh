#!/usr/bin/env bash
# RYNXCP mail stack: Postfix + Dovecot + OpenDKIM + Roundcube.
#
# This script installs the packages and base configuration. Per-domain
# certificates, virtual domains, mailboxes, DNS records and webmail vhosts are
# reconciled by rynxd from the panel state.
#
# Usage:
#   sudo bash deploy/mail-setup.sh
#
# It is idempotent. Set ROUNDCUBE_VERSION to pin another release.

set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 1; }

ROUNDCUBE_VERSION="${ROUNDCUBE_VERSION:-1.7.5}"
ROUNDCUBE_ROOT="/usr/share/roundcube"
ROUNDCUBE_DATA="/var/lib/roundcube"
VMAIL_ROOT="/var/vmail"
MAIL_UID="5000"
MAIL_GID="5000"
POSTFIX_MAIL_DIR="/etc/postfix/rynxcp"
DOVECOT_MAIL_DIR="/etc/dovecot/rynxcp"
DOVECOT_CONF="/etc/dovecot/conf.d/99-rynxcp.conf"
MAIL_CERT_DIR="/etc/ssl/rynxcp/mail"
DAEMON_CONF="/etc/rynxcp/rynxd.toml"

log() { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Dovecot 2.4 split mail_location into mail_driver/mail_path, renamed the SSL
# settings and removed the plugin{} section. Emit a config for the installed
# major.minor so the mail stack works on both 2.3 and 2.4.
dovecot_is_v24() {
  local version major minor
  version="$(dovecot --version 2>/dev/null | awk '{print $1}' || true)"
  [[ -n "$version" ]] || return 0
  major="${version%%.*}"
  version="${version#*.}"
  minor="${version%%.*}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 0
  (( major > 2 || (major == 2 && minor >= 4) ))
}

[[ -f "$DAEMON_CONF" ]] || die "$DAEMON_CONF not found; install RYNXCP first"
command -v hostname >/dev/null || die "hostname not found"

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
[[ -n "$HOSTNAME_FQDN" ]] || HOSTNAME_FQDN="$(hostname)"
if [[ "$HOSTNAME_FQDN" == mail.* ]]; then
  MAIL_HOST="$HOSTNAME_FQDN"
elif [[ "$HOSTNAME_FQDN" == "localhost" || "$HOSTNAME_FQDN" =~ ^[0-9.]+$ ]]; then
  MAIL_HOST="mail.localhost"
else
  MAIL_HOST="mail.${HOSTNAME_FQDN}"
fi

log "Installing mail packages"
export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/apt/apt.conf.d
printf 'DPkg::Lock::Timeout "600";\n' >/etc/apt/apt.conf.d/99rynxcp-lock
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string ${HOSTNAME_FQDN}" | debconf-set-selections
apt-get update
apt-get install -y --no-install-recommends \
  postfix \
  dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sieve dovecot-managesieved \
  opendkim opendkim-tools \
  clamav clamav-daemon clamav-freshclam clamav-milter \
  spamassassin spamd spamc spamass-milter \
  sqlite3 curl ca-certificates openssl \
  php8.5-sqlite3

log "Creating the vmail service account"
if ! getent group vmail >/dev/null; then
  groupadd -g "$MAIL_GID" vmail
fi
if ! getent passwd vmail >/dev/null; then
  useradd -u "$MAIL_UID" -g "$MAIL_GID" -d "$VMAIL_ROOT" -s /usr/sbin/nologin -M vmail
fi
install -d -o vmail -g vmail -m 0700 "$VMAIL_ROOT"
chown "$MAIL_UID:$MAIL_GID" "$VMAIL_ROOT"
chmod 0700 "$VMAIL_ROOT"
while IFS= read -r -d '' existing_domain; do
  chown "$MAIL_UID:$MAIL_GID" "$existing_domain"
  chmod 0750 "$existing_domain"
done < <(find "$VMAIL_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

log "Creating mail directories and default TLS certificate"
install -d -m 0755 /etc/ssl/rynxcp "$MAIL_CERT_DIR"
install -d -m 0750 "$POSTFIX_MAIL_DIR" "$DOVECOT_MAIL_DIR"
chown root:postfix "$POSTFIX_MAIL_DIR" 2>/dev/null || true
chown root:dovecot "$DOVECOT_MAIL_DIR" 2>/dev/null || true
install -d -m 0750 /etc/opendkim /etc/opendkim/keys
if [[ ! -s "$MAIL_CERT_DIR/default.crt" || ! -s "$MAIL_CERT_DIR/default.key" ]]; then
  openssl req -x509 -nodes -newkey rsa:3072 -days 3650 \
    -keyout "$MAIL_CERT_DIR/default.key" \
    -out "$MAIL_CERT_DIR/default.crt" \
    -subj "/CN=${MAIL_HOST}" \
    -addext "subjectAltName=DNS:${MAIL_HOST}" >/dev/null 2>&1
fi
chmod 0640 "$MAIL_CERT_DIR/default.crt" "$MAIL_CERT_DIR/default.key"
chown root:postfix "$MAIL_CERT_DIR/default.crt" "$MAIL_CERT_DIR/default.key" 2>/dev/null || true

log "Configuring Postfix virtual delivery and submission"
postconf -e "myhostname = ${HOSTNAME_FQDN}"
MAIL_DOMAIN="$(hostname -d 2>/dev/null || true)"
[[ -n "$MAIL_DOMAIN" ]] || MAIL_DOMAIN="${HOSTNAME_FQDN#*.}"
postconf -e "mydomain = ${MAIL_DOMAIN}"
postconf -e "myorigin = \$myhostname"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"
# Prefer IPv4 for outbound mail so SPF and PTR match the server's A record.
postconf -e "smtp_address_preference = ipv4"
postconf -e "mydestination = localhost, localhost.localdomain"
# The panel submits transactional mail over loopback. Keep relay rights
# limited to localhost so this is not an open relay.
postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"
postconf -e "alias_maps = hash:/etc/aliases"
postconf -e "alias_database = hash:/etc/aliases"
postconf -e "virtual_mailbox_domains = hash:${POSTFIX_MAIL_DIR}/domains"
postconf -e "virtual_mailbox_maps = hash:${POSTFIX_MAIL_DIR}/mailboxes"
postconf -e "virtual_alias_maps = hash:${POSTFIX_MAIL_DIR}/aliases"
postconf -e "virtual_mailbox_base = ${VMAIL_ROOT}"
postconf -e "virtual_uid_maps = static:${MAIL_UID}"
postconf -e "virtual_gid_maps = static:${MAIL_GID}"
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_security_options = noanonymous"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_cert_file = ${MAIL_CERT_DIR}/default.crt"
postconf -e "smtpd_tls_key_file = ${MAIL_CERT_DIR}/default.key"
postconf -e "tls_server_sni_maps = hash:${POSTFIX_MAIL_DIR}/sni"
postconf -e "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination"
postconf -e "smtpd_sender_login_maps = hash:${POSTFIX_MAIL_DIR}/senders"
postconf -e "smtpd_sender_restrictions = reject_authenticated_sender_login_mismatch, permit_mynetworks, permit_sasl_authenticated, reject_unknown_sender_domain"
postconf -e "smtpd_helo_required = yes"
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_milters = unix:/var/spool/postfix/spamass/spamass.sock inet:127.0.0.1:7357 inet:127.0.0.1:8891"
postconf -e "non_smtpd_milters = \$smtpd_milters"
postconf -e "milter_default_action = accept"
postconf -e "message_size_limit = 52428800"
postconf -e "smtp_tls_security_level = may"

log "Configuring ClamAV SMTP milter"
install -d -m 0755 /etc/clamav
install -d -o clamav -g clamav -m 0755 /run/clamav
cat >/etc/clamav/clamav-milter.conf <<'EOF'
# managed-by: RYNXCP
PidFile /run/clamav/clamav-milter.pid
MilterSocket inet:7357@127.0.0.1
ClamdSocket unix:/var/run/clamav/clamd.ctl
User clamav
OnInfected Reject
OnClean Accept
AddHeader Replace
EOF
chmod 0644 /etc/clamav/clamav-milter.conf
install -d -o spamass-milter -g postfix -m 0750 /var/spool/postfix/spamass


if ! grep -q '^submission inet' /etc/postfix/master.cf; then
  cat >>/etc/postfix/master.cf <<'EOF'
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
EOF
fi

log "Configuring Dovecot authentication, LMTP, Sieve and TLS"
if dovecot_is_v24; then
cat >"$DOVECOT_CONF" <<EOF
# managed-by: RYNXCP
# Dovecot 2.4 configuration.
protocols = imap pop3 lmtp sieve
mail_driver = maildir
mail_home = ${VMAIL_ROOT}/%{user | domain}/%{user | username}
mail_path = ${VMAIL_ROOT}/%{user | domain}/%{user | username}/Maildir
mail_inbox_path = ${VMAIL_ROOT}/%{user | domain}/%{user | username}/Maildir
mail_uid = ${MAIL_UID}
mail_gid = ${MAIL_GID}
first_valid_uid = ${MAIL_UID}
auth_mechanisms = plain login
passdb passwd-file {
  passwd_file_path = ${DOVECOT_MAIL_DIR}/users
  default_password_scheme = SHA512-CRYPT
  auth_username_format = %{user}
}
userdb passwd-file {
  passwd_file_path = ${DOVECOT_MAIL_DIR}/users
  auth_username_format = %{user}
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
mail_plugins {
  quota = yes
}
protocol lmtp {
  auth_username_format = %{user}
  mail_plugins {
    sieve = yes
  }
}
protocol imap {
  mail_plugins {
    imap_quota = yes
  }
}
quota "User quota" {
}
sieve_script personal {
  driver = file
  path = ${VMAIL_ROOT}/%{user | domain}/%{user | username}/sieve
  active_path = ${VMAIL_ROOT}/%{user | domain}/%{user | username}/sieve/roundcube.sieve
}
ssl = required
ssl_server_cert_file = ${MAIL_CERT_DIR}/default.crt
ssl_server_key_file = ${MAIL_CERT_DIR}/default.key
EOF
else
cat >"$DOVECOT_CONF" <<EOF
# managed-by: RYNXCP
# Dovecot 2.3 configuration.
protocols = imap pop3 lmtp sieve
mail_location = maildir:${VMAIL_ROOT}/%d/%n/Maildir
mail_uid = ${MAIL_UID}
mail_gid = ${MAIL_GID}
first_valid_uid = ${MAIL_UID}
auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u ${DOVECOT_MAIL_DIR}/users
}
userdb {
  driver = passwd-file
  args = username_format=%u ${DOVECOT_MAIL_DIR}/users
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  auth_username_format = %u
  mail_plugins = \$mail_plugins quota sieve
}
protocol imap { mail_plugins = \$mail_plugins quota }
protocol pop3 { mail_plugins = \$mail_plugins quota }
plugin {
  quota = maildir:User quota
  sieve = ${VMAIL_ROOT}/%d/%n/sieve/roundcube.sieve
  sieve_dir = ${VMAIL_ROOT}/%d/%n/sieve
}
ssl = required
ssl_cert = <${MAIL_CERT_DIR}/default.crt
ssl_key = <${MAIL_CERT_DIR}/default.key
EOF
fi
chmod 0644 "$DOVECOT_CONF"
[[ -f "$DOVECOT_MAIL_DIR/users" ]] || : >"$DOVECOT_MAIL_DIR/users"
chmod 0640 "$DOVECOT_MAIL_DIR/users"
chown root:dovecot "$DOVECOT_MAIL_DIR/users" 2>/dev/null || true

log "Configuring OpenDKIM"
if [[ -f /etc/opendkim.conf && ! -f /etc/opendkim.conf.rynxcp.bak ]]; then
  cp -a /etc/opendkim.conf /etc/opendkim.conf.rynxcp.bak
fi
cat >/etc/opendkim.conf <<'EOF'
# managed-by: RYNXCP
Syslog                  yes
SyslogSuccess           yes
LogWhy                  yes
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
AutoRestart             yes
AutoRestartRate         10/1h
Background              yes
DNSTimeout              5
SignatureAlgorithm      rsa-sha256
UserID                  opendkim
UMask                   007
Socket                  inet:8891@localhost
PidFile                 /run/opendkim/opendkim.pid
KeyTable                /etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
EOF
printf '127.0.0.1\nlocalhost\n::1\n' >/etc/opendkim/TrustedHosts
[[ -f /etc/opendkim/KeyTable ]] || : >/etc/opendkim/KeyTable
[[ -f /etc/opendkim/SigningTable ]] || : >/etc/opendkim/SigningTable
chown -R opendkim:opendkim /etc/opendkim
chmod 0750 /etc/opendkim /etc/opendkim/keys
chmod 0640 /etc/opendkim/KeyTable /etc/opendkim/SigningTable /etc/opendkim/TrustedHosts
if [[ -f /etc/default/opendkim ]]; then
  sed -i -E 's|^SOCKET=.*|SOCKET="inet:8891@localhost"|' /etc/default/opendkim || true
fi

log "Preparing empty Postfix maps"
for map in domains mailboxes aliases senders sni; do
  [[ -f "${POSTFIX_MAIL_DIR}/${map}" ]] || : >"${POSTFIX_MAIL_DIR}/${map}"
done
chmod 0644 "${POSTFIX_MAIL_DIR}/domains" "${POSTFIX_MAIL_DIR}/mailboxes" "${POSTFIX_MAIL_DIR}/aliases" "${POSTFIX_MAIL_DIR}/senders"
chmod 0640 "${POSTFIX_MAIL_DIR}/sni"
if [[ ! -s "${POSTFIX_MAIL_DIR}/sni" ]]; then
  cat "$MAIL_CERT_DIR/default.key" "$MAIL_CERT_DIR/default.crt" >"$MAIL_CERT_DIR/default.pem"
  chmod 0640 "$MAIL_CERT_DIR/default.pem"
  chown root:postfix "$MAIL_CERT_DIR/default.pem" 2>/dev/null || true
  echo "default.invalid $MAIL_CERT_DIR/default.pem" >"${POSTFIX_MAIL_DIR}/sni"
fi
for map in domains mailboxes aliases senders; do
  postmap "hash:${POSTFIX_MAIL_DIR}/${map}"
done
if ! postmap -F "hash:${POSTFIX_MAIL_DIR}/sni"; then
  warn "empty SNI map; Postfix will use the default certificate until the first mail domain is enabled"
fi

log "Installing Roundcube ${ROUNDCUBE_VERSION}"
if [[ ! -f "$ROUNDCUBE_ROOT/index.php" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  url="https://github.com/roundcube/roundcubemail/releases/download/${ROUNDCUBE_VERSION}/roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz"
  curl -fsSL --retry 3 --max-time 180 "$url" -o "$tmp/roundcube.tar.gz"
  tar -xzf "$tmp/roundcube.tar.gz" -C "$tmp"
  install -d -m 0755 "$ROUNDCUBE_ROOT"
  cp -a "$tmp/roundcubemail-${ROUNDCUBE_VERSION}/." "$ROUNDCUBE_ROOT/"
  rm -rf "$tmp"
  trap - EXIT
fi

install -d -o www-data -g www-data -m 0750 \
  "$ROUNDCUBE_DATA" "$ROUNDCUBE_DATA/db" "$ROUNDCUBE_DATA/temp" "$ROUNDCUBE_DATA/logs"
if [[ ! -s "$ROUNDCUBE_DATA/db/sqlite.db" ]]; then
  sqlite3 "$ROUNDCUBE_DATA/db/sqlite.db" <"$ROUNDCUBE_ROOT/SQL/sqlite.initial.sql"
fi
chown -R www-data:www-data "$ROUNDCUBE_DATA"
chmod 0640 "$ROUNDCUBE_DATA/db/sqlite.db" 2>/dev/null || true

des_key="$(openssl rand -hex 24)"
(
  umask 027
  cat >"$ROUNDCUBE_ROOT/config/config.inc.php" <<EOF
<?php
if (!empty(\$_SERVER['HTTPS']) && \$_SERVER['HTTPS'] !== 'off') {
  ini_set('session.cookie_secure', '1');
}
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
\$config = [];
\$config['session_samesite'] = 'Lax';
\$config['db_dsnw'] = 'sqlite:///${ROUNDCUBE_DATA}/db/sqlite.db?mode=0660';
\$config['des_key'] = '${des_key}';
\$config['imap_host'] = 'ssl://mail.%s:993';
\$config['smtp_host'] = 'tls://%h:587';
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['username_domain'] = '%d';
\$config['managesieve_host'] = 'tls://%h:4190';
\$config['temp_dir'] = '${ROUNDCUBE_DATA}/temp/';
\$config['log_dir'] = '${ROUNDCUBE_DATA}/logs/';
\$config['log_driver'] = 'file';
\$config['enable_installer'] = false;
\$config['plugins'] = ['archive', 'managesieve', 'markasjunk', 'zipdownload'];
\$config['skin'] = 'elastic';
\$config['product_name'] = 'RYNXCP Webmail';
\$config['language'] = 'es_ES';
\$config['default_charset'] = 'UTF-8';
EOF
)
chown root:www-data "$ROUNDCUBE_ROOT/config/config.inc.php"
chmod 0640 "$ROUNDCUBE_ROOT/config/config.inc.php"
chown -R www-data:www-data "$ROUNDCUBE_DATA"
rm -rf "$ROUNDCUBE_ROOT/installer" 2>/dev/null || true

log "Enabling services"
systemctl enable --now postfix dovecot opendkim php8.5-fpm
postfix check
doveconf -n >/dev/null
nginx_present=0
if command -v nginx >/dev/null 2>&1; then nginx_present=1; fi
if (( nginx_present )); then nginx -t >/dev/null 2>&1 || warn "nginx -t failed; webmail vhosts may need a domain first"; fi
systemctl reload postfix || systemctl restart postfix
systemctl reload dovecot || systemctl restart dovecot
systemctl restart opendkim

log "Enabling mail management in RYNXCP"
if grep -qE '^[[:space:]]*mail_enabled[[:space:]]*=' "$DAEMON_CONF"; then
  sed -i -E "s|^[[:space:]]*mail_enabled[[:space:]]*=.*|mail_enabled = true|" "$DAEMON_CONF"
else
  printf '\nmail_enabled = true\n' >>"$DAEMON_CONF"
fi
if grep -qE '^[[:space:]]*mail_hostname[[:space:]]*=' "$DAEMON_CONF"; then
  sed -i -E "s|^[[:space:]]*mail_hostname[[:space:]]*=.*|mail_hostname = \"${MAIL_HOST}\"|" "$DAEMON_CONF"
else
  printf 'mail_hostname = "%s"\n' "$MAIL_HOST" >>"$DAEMON_CONF"
fi
if grep -qE '^[[:space:]]*dkim_selector[[:space:]]*=' "$DAEMON_CONF"; then
  sed -i -E 's|^[[:space:]]*dkim_selector[[:space:]]*=.*|dkim_selector = "mail"|' "$DAEMON_CONF"
else
  printf 'dkim_selector = "mail"\n' >>"$DAEMON_CONF"
fi
systemctl restart rynxd
sleep 2
systemctl is-active --quiet rynxd || die "rynxd failed after enabling mail; journalctl -u rynxd"

log "Mail stack ready"
cat <<EOF

Postfix, Dovecot, OpenDKIM and Roundcube are installed.
Webmail is published by the panel at https://webmail.<domain>/ after enabling
mail for that domain and issuing its certificate.

Next:
  1. Create a website in RYNXCP.
  2. Open Correo and activate mail for the domain.
  3. Wait for the webmail SSL job to finish.
  4. Create mailboxes and open https://webmail.<domain>/.

Verify:
  systemctl status postfix dovecot opendkim php8.5-fpm
  journalctl -u postfix -u dovecot -u opendkim -n 80 --no-pager
  postconf -n
EOF
