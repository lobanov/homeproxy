#!/usr/bin/env bash
# Start/stop the Caddy LAN -> tailnet proxy.
#
# Usage: ./homeproxy.sh [run|tui|start|stop|reload|status]
#   run     foreground (default), logs to terminal
#   tui     foreground with a live dashboard of connections and requests
#   start   background daemon
#   stop    stop background daemon
#   reload  apply Caddyfile/.env changes without dropping connections
#   status  show config and upstream reachability

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CADDYFILE="$DIR/Caddyfile"

if [[ -f "$DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$DIR/.env"
  set +a
fi

: "${UPSTREAM:?UPSTREAM is not set (copy .env.example to .env)}"
: "${API_KEY:?API_KEY is not set (generate one: openssl rand -hex 32)}"
export UPSTREAM API_KEY LISTEN_PORT="${LISTEN_PORT:-8080}"

die() { echo "error: $*" >&2; exit 1; }

command -v caddy >/dev/null || die "caddy not found (brew install caddy)"

# Extract host and port from UPSTREAM for a reachability check.
upstream_hostport() {
  local u="${UPSTREAM#*://}"
  u="${u%%/*}"
  local host="${u%:*}" port="${u##*:}"
  if [[ "$host" == "$port" ]]; then
    [[ "$UPSTREAM" == https://* ]] && port=443 || port=80
  fi
  echo "$host $port"
}

check_upstream() {
  read -r host port <<<"$(upstream_hostport)"
  if nc -z -G 3 "$host" "$port" 2>/dev/null || nc -z -w 3 "$host" "$port" 2>/dev/null; then
    echo "upstream $host:$port reachable"
  else
    echo "warning: upstream $host:$port not reachable — is Tailscale up on this machine?" >&2
  fi
}

lan_ip() {
  ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null \
    || hostname -I 2>/dev/null | awk '{print $1}' || true
}

banner() {
  echo "proxy: http://$(lan_ip):$LISTEN_PORT -> $UPSTREAM"
}

cmd="${1:-run}"
case "$cmd" in
  run)
    caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null
    check_upstream
    banner
    exec caddy run --config "$CADDYFILE" --adapter caddyfile
    ;;
  tui)
    caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null
    check_upstream
    PROXY_URL="http://$(lan_ip):$LISTEN_PORT" exec python3 "$DIR/homeproxy-tui.py"
    ;;
  start)
    caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null
    check_upstream
    caddy start --config "$CADDYFILE" --adapter caddyfile
    banner
    ;;
  stop)
    caddy stop
    ;;
  reload)
    caddy reload --config "$CADDYFILE" --adapter caddyfile
    banner
    ;;
  status)
    banner
    check_upstream
    curl -fsS localhost:2019/config/ >/dev/null 2>&1 \
      && echo "caddy: running" || echo "caddy: not running"
    ;;
  *)
    die "unknown command: $cmd (run|tui|start|stop|reload|status)"
    ;;
esac
