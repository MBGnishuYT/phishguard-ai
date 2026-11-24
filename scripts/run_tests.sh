#!/usr/bin/env bash
# Runs the whole test suite: Python (ML, backend, SSRF) + JavaScript (extension logic, content script, fake-Chrome integration).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m ml.train > /dev/null
python -m pytest tests -q
(cd tests/extension && [ -d node_modules ] || npm install --silent)
(cd tests/extension && node --test)
echo "ALL TESTS PASSED"
