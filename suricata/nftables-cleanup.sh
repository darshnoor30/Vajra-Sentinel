#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root on the authorized Linux response host." >&2
  exit 1
fi

if nft list table inet vajra_sentinel >/dev/null 2>&1; then
  nft delete table inet vajra_sentinel
  echo "Removed the dedicated inet vajra_sentinel table."
else
  echo "Nothing to remove."
fi

