# homeproxy

Caddy reverse proxy that exposes an HTTPS service on your tailnet to the local
network, tuned for streaming responses (SSE, chunked, token-by-token LLM output).

- Responses are flushed immediately; no read/write timeouts cut long streams.
- Clients must send `Authorization: Bearer <API_KEY>`; the key is stripped before forwarding.
- Only private/loopback client addresses are served.
- Plain HTTP on the LAN; TLS to the upstream.

## Setup

Requires Caddy (`brew install caddy`) and Tailscale running on this machine.

```bash
cp .env.example .env
```

Edit `.env`:

| Variable      | Meaning                                                              |
|---------------|----------------------------------------------------------------------|
| `UPSTREAM`    | Tailnet service, e.g. `https://box.tail1234.ts.net:8443`. Use the MagicDNS name so the certificate matches. |
| `LISTEN_PORT` | Port exposed on the LAN (default `8080`).                            |
| `API_KEY`     | Bearer key clients must send. Generate with `openssl rand -hex 32`.  |

## Usage

```bash
./homeproxy.sh          # run in foreground, logs to terminal
./homeproxy.sh tui      # run in foreground with a live dashboard
./homeproxy.sh start    # run in background
./homeproxy.sh reload   # apply Caddyfile/.env changes without dropping streams
./homeproxy.sh stop     # stop background instance
./homeproxy.sh status   # show address and upstream reachability
```

Clients connect to `http://<this-machine-lan-ip>:<LISTEN_PORT>`. For an
OpenAI-compatible upstream, use `.../v1` as the base URL and `API_KEY` as the key.

## Dashboard

`./homeproxy.sh tui` starts Caddy under a curses dashboard (macOS, Python 3
standard library only) showing:

- client and upstream connections as **streaming**, **waiting** (request sent,
  upstream still working) or **idle**, with bytes up/down and current rate;
- requests in flight to the upstream and upstream failures;
- recent completed requests with status, duration and size;
- the tail of Caddy's log. Full output is appended to `caddy.log`.

Keys: `q` quit, `r` reload Caddyfile, `c` clear request history.

Connection data comes from `nettop`, in-flight counts from Caddy's admin API
(`localhost:2019`), and requests from Caddy's JSON access log, which is written
when a request completes.
