# homeproxy

Caddy reverse proxy that exposes an HTTPS service on your tailnet to the local
network, tuned for streaming responses (SSE, chunked, token-by-token LLM output).

- Responses are flushed immediately; no read/write timeouts cut long streams.
- Clients must send `Authorization: Bearer <API_KEY>` (unless `API_KEY` is empty); the key is
  stripped before forwarding and replaced with `UPSTREAM_API_KEY` if one is set.
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
| `LISTEN_ADDR` | Address to bind (default `127.0.0.1`, this machine only). Use `0.0.0.0` to serve the LAN. |
| `LISTEN_PORT` | Port to listen on (default `8080`).                                  |
| `API_KEY`     | Bearer key clients must send. Generate with `openssl rand -hex 32`. Set it empty (`API_KEY=`) to disable auth; it must still be present. |
| `UPSTREAM_API_KEY` | Optional bearer key the proxy sends to the upstream. Leave empty if the upstream needs no auth. |
| `CADDY_ADMIN` | Caddy admin API address (default `localhost:2019`). Change it to run a second instance. |

## Usage

```bash
./homeproxy.sh          # run in foreground, logs to terminal
./homeproxy.sh tui      # run in foreground with a live dashboard
./homeproxy.sh start    # run in background
./homeproxy.sh reload   # apply Caddyfile/.env changes without dropping streams
./homeproxy.sh stop     # stop background instance
./homeproxy.sh status   # show address and upstream reachability
```

With `LISTEN_ADDR=0.0.0.0`, clients connect to `http://<this-machine-lan-ip>:<LISTEN_PORT>`. For an
OpenAI-compatible upstream, use `.../v1` as the base URL and `API_KEY` as the key.

## Dashboard

`./homeproxy.sh tui` starts Caddy under a curses dashboard (macOS, Python 3
standard library only) showing:

- client and upstream connections as **streaming**, **waiting** (request sent,
  upstream still working) or **idle**, with bytes up/down and current rate;
- requests in flight to the upstream and upstream failures;
- recent clients by IP: requests, open and peak concurrent connections, and
  bytes up/down of their completed requests;
- recent requests with status, duration and size, including ones still in flight;
- the tail of Caddy's log. Full output is appended to `caddy.log`.

Keys: `q` quit, `r` reload Caddyfile, `c` clear recent clients and requests,
`↑`/`↓` select a request, `Enter` open it.

The request view shows the headers as sent upstream, the request body and the
response headers and body (JSON pretty-printed, gzip decoded), updating live while
a response streams. Keys: `Esc` back, `↑`/`↓`/`PgUp`/`PgDn`/`g`/`G` scroll (`G` follows
a stream), `Tab` next section, `w` wrap long lines, `a` join the text deltas of an
OpenAI or Anthropic event stream, `s` save the request to `captures/` as JSON.

To capture payloads, the dashboard runs a small proxy on a random local port and
Caddy sends plain HTTP requests through it to the upstream; WebSockets still go
direct. Only the first 256 KB of each body, for the last 100 requests, is kept,
in memory. API keys and cookies in headers are shown as `REDACTED`, but bodies are
shown as is. `run`/`start` don't use the capture proxy.

Connection data comes from `nettop`, in-flight counts from Caddy's admin API
(`localhost:2019`), and requests from Caddy's JSON access log, which is written
when a request completes.
