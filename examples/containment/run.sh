#!/usr/bin/env bash
# Phase 8 containment demo (ADR-0030 §9): build, start, probe from INSIDE the agent container,
# tear down. Prints the probe's JSON and exits non-zero unless the agent is contained.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > secrets/smtp_password
export CT_PG_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export CT_MIGRATOR_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export CT_APP_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
dc() { docker compose -f docker-compose.yml "$@"; }
cleanup() { dc --profile agent down -v --remove-orphans >/dev/null 2>&1 || true; rm -f secrets/smtp_password; }
trap cleanup EXIT
dc build --quiet gateway agent
dc up -d --wait gateway mailpit public-api
ip() { docker inspect -f "{{(index .NetworkSettings.Networks \"agw-containment_$2\").IPAddress}}" "$(dc ps -q "$1")"; }
TARGETS="mailpit-ip=$(ip mailpit toolnet):1025 api-ip=$(ip public-api toolnet):8000 pg-ip=$(ip postgres dbnet):5432 gw-toolnet-ip=$(ip gateway toolnet):8080"
echo "tool/db container IPs probed from the agent: $TARGETS" >&2
# The gateway (not the agent) holds the relay credential:
dc exec -T gateway sh -c 'test -s /run/secrets/smtp_password && echo "gateway: SMTP credential present (/run/secrets)"' >&2
rc=0; dc run --rm -T agent $TARGETS || rc=$?
echo "containment probe exit=$rc" >&2
exit "$rc"
