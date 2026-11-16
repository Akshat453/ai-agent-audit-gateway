# Common environment for the "ui" profile containers (sourced). Secrets come from the compose
# environment (.env) or the private ui-state volume; nothing secret is printed.
export AGW_DATABASE_URL="postgresql+psycopg://agw_app:${AGW_APP_PASSWORD}@postgres:5432/agw_ui"
export AGW_MIGRATOR_DATABASE_URL="postgresql+psycopg://agw_migrator:${AGW_MIGRATOR_PASSWORD}@postgres:5432/agw_ui"
S=/var/lib/agw
export AGW_APPROVAL_SIGNING_KEY_FILE="$S/approval-signing.key"
export AGW_DELEGATION_SIGNING_KEY_FILE="$S/delegation-signing.key"
export AGW_KEK_DIR="$S/kek" AGW_KEK_ID=dev
export AGW_DEMO_SANDBOX_DIR=/var/lib/agw-sandbox AGW_DEMO_CORPUS_DIR=/app/examples/single-agent/corpus
export AGW_BLOB_ENDPOINT=minio:9000 AGW_BLOB_SECURE=false AGW_BLOB_BUCKET=agw-ui-payloads
export AGW_SMTP_HOST=mailpit AGW_SMTP_PORT=1025 AGW_SMTP_STARTTLS=false AGW_SMTP_USERNAME=agw-relay
export AGW_SMTP_PASSWORD_FILE="$S/smtp-relay.password" AGW_SMTP_FROM=gateway@corp.example
export AGW_SMTP_ALLOWED_DOMAINS=corp.example,partner.example
export AGW_ANCHOR_RPC_URL=http://anvil:8545 AGW_ANCHOR_CHAIN_ID=31337
export AGW_ANCHOR_SUBMITTER_KEY_FILE="$S/anchor-submitter.key"
export AGW_ANCHOR_DEPLOYMENT_SALT_FILE="$S/anchor-salt.hex"
export AGW_ANCHOR_FINALITY=confirmations:2 AGW_ANCHOR_ROUTINE_DELAY_SECONDS=5 AGW_ANCHOR_POLL_SECONDS=1
export AGW_PRE_ANCHOR_RULES='*' AGW_CRITICAL_ANCHOR_TIMEOUT_SECONDS=120
export AGW_EPOCH_MAX_AGE_SECONDS=30 AGW_EPOCH_MEDIUM_MAX_AGE_SECONDS=15
export AGW_MONITOR_INTERVAL_SECONDS=20 AGW_WORKER_METRICS_PORT=9464
if [ -f "$S/deployment.json" ]; then
  AGW_ANCHOR_CONTRACT="$(python -c "import json; print(json.load(open('$S/deployment.json'))['address'])")"
  export AGW_ANCHOR_CONTRACT
fi
