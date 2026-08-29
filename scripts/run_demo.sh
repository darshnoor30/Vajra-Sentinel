#!/usr/bin/env bash
set -euo pipefail

export VAJRA_DEMO_MODE=true
export VAJRA_IPS_MODE=dry-run
export VAJRA_HOST=127.0.0.1
export VAJRA_PORT=8765
python -m app.main

