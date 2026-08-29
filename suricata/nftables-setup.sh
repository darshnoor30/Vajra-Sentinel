#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root on the authorized Linux sensor/response host." >&2
  exit 1
fi

nft list table inet vajra_sentinel >/dev/null 2>&1 || nft add table inet vajra_sentinel
nft list set inet vajra_sentinel blocklist_v4 >/dev/null 2>&1 || \
  nft add set inet vajra_sentinel blocklist_v4 '{ type ipv4_addr; flags timeout; }'
nft list set inet vajra_sentinel blocklist_v6 >/dev/null 2>&1 || \
  nft add set inet vajra_sentinel blocklist_v6 '{ type ipv6_addr; flags timeout; }'
nft list chain inet vajra_sentinel input_guard >/dev/null 2>&1 || \
  nft add chain inet vajra_sentinel input_guard '{ type filter hook input priority -10; policy accept; }'

if ! nft -a list chain inet vajra_sentinel input_guard | grep -q 'ip saddr @blocklist_v4 drop'; then
  nft add rule inet vajra_sentinel input_guard ip saddr @blocklist_v4 counter drop
fi
if ! nft -a list chain inet vajra_sentinel input_guard | grep -q 'ip6 saddr @blocklist_v6 drop'; then
  nft add rule inet vajra_sentinel input_guard ip6 saddr @blocklist_v6 counter drop
fi

echo "Vajra Sentinel nftables sets are ready. Active mode is still disabled in the app by default."

