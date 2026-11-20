#!/bin/sh
set -eu
: "${GATEWAY_HOSTNAME:?Set GATEWAY_HOSTNAME}"
: "${GATEWAY_RECIPIENT:?Set GATEWAY_RECIPIENT}"
name_pattern='[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+'
if ! printf '%s\n' "$GATEWAY_HOSTNAME" | grep -Exq "$name_pattern" ||
   ! printf '%s\n' "$GATEWAY_RECIPIENT" | grep -Exq "[a-zA-Z0-9_-][a-zA-Z0-9_.+-]*@$name_pattern"; then
    echo 'Invalid SMTP gateway hostname or recipient' >&2
    exit 78
fi
test -s /certs/fullchain.pem
test -s /certs/privkey.pem
postconf -e "myhostname = $GATEWAY_HOSTNAME" 'inet_interfaces = all' 'inet_protocols = ipv4' \
    'mydestination =' 'local_recipient_maps =' 'local_transport = error:local delivery disabled' \
    "relay_domains = ${GATEWAY_RECIPIENT#*@}" 'relay_recipient_maps = hash:/etc/postfix/scan-recipients' \
    'smtpd_relay_restrictions = reject_unauth_destination' \
    'smtpd_recipient_restrictions = check_recipient_access hash:/etc/postfix/scan-recipients, reject' \
    'smtpd_recipient_limit = 1' 'smtpd_client_connection_count_limit = 5' \
    'smtpd_client_message_rate_limit = 20' 'anvil_rate_time_unit = 60s' \
    'smtpd_timeout = 60s' 'message_size_limit = 26000000' \
    'smtpd_forbid_bare_newline = reject' 'smtpd_forbid_bare_newline_exclusions =' \
    'smtpd_proxy_filter = malicenx:2525' 'smtpd_proxy_options = speed_adjust' \
    'smtpd_tls_security_level = may' 'smtpd_tls_chain_files =' \
    'smtpd_tls_cert_file = /certs/fullchain.pem' 'smtpd_tls_key_file = /certs/privkey.pem' \
    'maillog_file = /dev/stdout'
postconf -M 'smtp/inet=smtp inet n - n - 20 smtpd'
printf '%s OK\n' "$GATEWAY_RECIPIENT" > /etc/postfix/scan-recipients
postmap /etc/postfix/scan-recipients
exec postfix start-fg
