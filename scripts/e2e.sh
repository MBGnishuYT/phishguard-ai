#!/usr/bin/env bash
# Live end-to-end test: starts a throw-away server, drives the real extension code and dashboard JS against it.
set -euo pipefail
cd "$(dirname "$0")/.."
export DATABASE_PATH=$(mktemp -u)/e2e.db ADMIN_PASSWORD='E2eAdminPassw0rd' ADMIN_MASTER_KEY='e2e-master-key-0123456789' \
       JWT_SECRET='e2e-jwt-secret-0123456789-0123456789-xx' ENABLE_NETWORK_CHECKS=false
python -m uvicorn backend.app.main:app --port 8765 --log-level warning & PID=$!
trap 'kill $PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf localhost:8765/health >/dev/null && break; sleep 0.5; done
(cd tests/extension && PG_E2E_URL=http://127.0.0.1:8765 PG_ADMIN_PW="$ADMIN_PASSWORD" PG_MASTER="$ADMIN_MASTER_KEY" node --test e2e.test.mjs)
