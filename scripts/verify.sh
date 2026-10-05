#!/usr/bin/env bash
# One-shot verification, same stages the `verify` compose service runs:
#   1) unit/integration tests  2) build sanity  3) live smoke (sign/gzip/concurrency)
# Exits non-zero if any stage fails.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m smoke.run_all --spawn "$@"
