#!/bin/sh
# Runs once on first container start (docker-entrypoint-initdb.d). Passwords come from env.
set -eu
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v migrator_password="$AGW_MIGRATOR_PASSWORD" \
  -v app_password="$AGW_APP_PASSWORD" \
  -f /agw/roles.sql
