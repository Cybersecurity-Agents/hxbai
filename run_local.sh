#!/usr/bin/env bash
set -euo pipefail
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

: "${BENCHMARK_BASE_URL:?set BENCHMARK_BASE_URL}"
: "${BENCHMARK_TOKEN:?set BENCHMARK_TOKEN}"
: "${SOLVER_API_KEY:?set SOLVER_API_KEY}"
: "${VPN_OVPN:?set VPN_OVPN=/abs/path/to/range.ovpn}"
VPN_AUTH="${VPN_AUTH:-}"
DEBUG_NAME="${DEBUG_NAME:-b02}"
CODES="${CODES:-b-02}"
IMG="${IMG:-hxbai:latest}"

TS=$(date +%Y%m%d-%H%M%S)
SAFE=$(printf '%s' "$DEBUG_NAME" | tr -c 'A-Za-z0-9_.-' '_')
NAME="hxbai_${SAFE}_${TS}"
WORK="$REPO/_runwork/$NAME"
LOG="$REPO/_runwork/${NAME}.log"
mkdir -p "$WORK"

AUTH_MNT=(); AUTH_ENV=()
[ -n "$VPN_AUTH" ] && { AUTH_MNT=(-v "$VPN_AUTH:/vpn/auth.txt:ro"); AUTH_ENV=(-e HXBAI_VPN_AUTH=/vpn/auth.txt); }

echo "[run] container=$NAME  codes=$CODES  workdir=$WORK  log=$LOG"

docker run --name "$NAME" \
  --cap-add=NET_ADMIN --device /dev/net/tun \
  -v "$WORK:/tmp/hxbai-work" \
  -v "$VPN_OVPN:/vpn/range.ovpn:ro" "${AUTH_MNT[@]}" \
  -e BENCHMARK_BASE_URL -e BENCHMARK_TOKEN \
  -e HXBAI_PROVIDER=deepseek -e SOLVER_API_KEY -e SOLVER_GATEWAY=0 \
  -e HXBAI_VPN_CONFIG=/vpn/range.ovpn "${AUTH_ENV[@]}" \
  -e HXBAI_ONLY_CODES="$CODES" \
  -e HXBAI_USE_HINTS=1 -e HXBAI_HINT_HARD_ROUND=1 \
  -e HXBAI_USE_PRO=0 \
  -e HXBAI_PERSIST_AUTOCARD=0 \
  "$IMG" 2>&1 | tee "$LOG"

echo "[done] 容器已保留: $NAME  (docker exec -it $NAME bash / docker cp $NAME:/tmp/hxbai-work .)"
echo "[done] workdir 已落盘: $WORK   日志: $LOG"
