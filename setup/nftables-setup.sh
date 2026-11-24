#!/usr/bin/env bash
# Run ONCE on the TEST gateway machine (never on a live hospital network).
# Creates a table 'tars' with a set 'blocklist'; any address TARS adds to the set
# is dropped when traffic passes through this gateway. Policy is 'accept', so if
# the set is empty or TARS stops, traffic flows normally (fail-open, NFR1).
set -euo pipefail
nft add table inet tars
nft add set inet tars blocklist '{ type ipv4_addr; }'
nft add chain inet tars forward '{ type filter hook forward priority 0; policy accept; }'
nft add rule inet tars forward ip saddr @blocklist drop
nft add rule inet tars forward ip daddr @blocklist drop
nft list table inet tars
