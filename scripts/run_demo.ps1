$ErrorActionPreference = "Stop"
$env:VAJRA_DEMO_MODE = "true"
$env:VAJRA_IPS_MODE = "dry-run"
$env:VAJRA_HOST = "127.0.0.1"
$env:VAJRA_PORT = "8765"
python -m app.main

