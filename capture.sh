#!/usr/bin/env bash
# capture.sh
# ----------
# Run on whichever host/bridge can see the IKE (UDP 500/4500) and ESP
# (proto 50) traffic between Ubuntu A and Ubuntu B. If capturing on
# one of the endpoints directly, run this on Ubuntu A.
#
# Usage: ./capture.sh <interface> <output_name> [duration_sec]
# Produces: ./captures/<output_name>.pcap
#
# Pair this with testbed/configs/generated/labels/<conn_name>.json so
# the backend's dataset builder can join capture -> ground truth.

set -euo pipefail
IFACE="${1:?interface required, e.g. ens33}"
OUT_NAME="${2:?output_name required, e.g. gen-000}"
DURATION="${3:-60}"

mkdir -p ./captures
OUT_FILE="./captures/${OUT_NAME}.pcap"

echo "[*] Capturing on $IFACE for ${DURATION}s -> $OUT_FILE"
echo "[*] Filter: udp port 500 or udp port 4500 or esp"

sudo timeout "$DURATION" tcpdump -i "$IFACE" \
    -w "$OUT_FILE" \
    'udp port 500 or udp port 4500 or esp' \
    -s 0

echo "[*] Capture complete: $OUT_FILE"
echo "[*] Upload this file to the backend via POST /api/upload"
echo "    or place it in backend/data/incoming_pcaps/ for batch import."
