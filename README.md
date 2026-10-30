# homeproxy

Caddy reverse proxy that exposes an HTTPS service on your tailnet to the local
network, tuned for streaming responses (SSE, chunked, token-by-token LLM output).

- Responses are flushed immediately; no read/write timeouts cut long streams.
- Clients authenticate with their own key (`API_KEY`), which is never forwarded; the
  proxy can send a separate key to the upstream (`UPSTREAM_API_KEY`). See [Authentication](#authentication).
- Listens on this machine only by default; opt in to serving the LAN. Only
  private/loopback client addresses are served. See [Listening address](#listening-address).
- Plain HTTP between clients and the proxy; TLS to the upstream.

## Setup

Requires Caddy (`brew install caddy`) and Tailscale running on this machine.

```bash
cp .env.example .env
```

Edit `.env`:

| Variable      | Meaning                                                              |
|---------------|----------------------------------------------------------------------|
| `UPSTREAM`    | Tailnet service, e.g. `https://box.tail1234.ts.net:8443`. Use the MagicDNS name so the certificate matches. |
| `LISTEN_ADDR` | Address(es) to bind, space-separated (default `127.0.0.1`, this machine only). Use `0.0.0.0` to serve the LAN. |
| `LISTEN_PORT` | Port to listen on (default `8080`).                                  |
| `API_KEY`     | Bearer key clients must send. Generate with `openssl rand -hex 32`. Must be present; set it empty (`API_KEY=`) to disable auth. |
| `UPSTREAM_API_KEY` | Bearer key the proxy sends to the upstream. Leave empty if the upstream needs no auth. |
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

`run`, `start`, `reload` and `status` print the address clients should use. For an
OpenAI-compatible upstream, use `<that address>/v1` as the base URL and `API_KEY`
as the key.

## Authentication

Two independent keys, one on each side of the proxy:

```
client --Authorization: Bearer <API_KEY>--> homeproxy --Authorization: Bearer <UPSTREAM_API_KEY>--> upstream
```

**Client side (`API_KEY`).** Every request must carry exactly
`Authorization: Bearer <API_KEY>`. Anything else gets a `401` with
`WWW-Authenticate: Bearer` and an OpenAI-style JSON error, so SDKs report it as an
auth failure. Generate a key with `openssl rand -hex 32`.

Setting `API_KEY=` (empty) turns auth off: any client that passes the address
check below can use the proxy, and `homeproxy.sh` prints a warning on start. The
variable must still be present in `.env`; leaving it out entirely is an error, so
auth can't be disabled by accident.

**Upstream side (`UPSTREAM_API_KEY`).** The client's `Authorization` header is
always removed before forwarding. If `UPSTREAM_API_KEY` is set, the proxy sends
`Authorization: Bearer <UPSTREAM_API_KEY>` instead; if it's empty, no
`Authorization` header reaches the upstream. Clients never need to know the
upstream key. Other headers, including any `X-Api-Key`, are passed through
unchanged.

**Changing keys.** Both keys are read when Caddy loads its config.
`./homeproxy.sh reload` re-reads `.env` and applies new keys without dropping open
streams. The dashboard's `r` reloads the Caddyfile but keeps the `.env` values it
started with, so restart the dashboard to change keys.

The dashboard never shows either key: `Authorization` and similar headers appear
as `REDACTED`.

## Listening address

`LISTEN_ADDR` and `LISTEN_PORT` set where the proxy accepts connections.

| `LISTEN_ADDR`                | Who can connect                                       |
|------------------------------|-------------------------------------------------------|
| `127.0.0.1` (default)        | Only programs on this machine.                         |
| `0.0.0.0`                    | Any device on your local network (all IPv4 interfaces). |
| A specific IP, e.g. `192.168.1.10` | Clients reaching that interface only.           |
| Several, e.g. `127.0.0.1 192.168.1.10` | Space-separated; each is bound.             |

Whatever is bound, clients from non-private addresses are refused with `403`
before auth is checked. Only loopback and private ranges (e.g. `192.168.x.x`,
`10.x.x.x`, `172.16–31.x.x`) are served. With the default loopback address, the
API key mainly guards against other local programs. With `0.0.0.0`, it is what
stops other devices on the network, so keep `API_KEY` set.

When bound to `0.0.0.0` (or `::`), the printed client address uses this machine's
LAN IP (from `en0`/`en1`). Otherwise it's the first address in `LISTEN_ADDR`. On
macOS the firewall may ask to allow incoming connections for `caddy` the first time
it listens on the LAN.

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

| Key           | Action                                   |
|---------------|------------------------------------------|
| `↑`/`↓`, `j`/`k` | select a request                      |
| `Enter`       | open the selected request                |
| `Esc`         | clear the selection                      |
| `r`           | reload the Caddyfile                     |
| `c`           | clear recent clients and requests        |
| `q`           | quit (waits briefly for open streams)    |

### Request view

Shows one request's headers as sent upstream, its request body, and the response
headers and body. JSON is pretty-printed and gzip/deflate responses are decoded.
While a response is streaming, the view fills in live.

| Key           | Action                                   |
|---------------|------------------------------------------|
| `↑`/`↓`, `PgUp`/`PgDn`, `g`/`G` | scroll; at the bottom (`G`) it follows a stream |
| `Tab`/`Shift-Tab` | next/previous section                |
| `w`           | wrap long lines on/off                   |
| `a`           | join the text deltas of an OpenAI (chat completions, responses) or Anthropic event stream |
| `s`           | save the request to `captures/<time>-<id>.json` |
| `Esc`, `q`, `←` | back to the dashboard                  |

Requests that never reached the upstream (e.g. rejected with 401) and WebSockets
show only the headers from Caddy's access log.

### How payloads are captured

In `tui` mode only, the dashboard runs a small HTTP proxy on a random local port
and passes its address to Caddy as `CAPTURE_URL`. Caddy then sends requests
through it, after auth and the key swap, and it forwards them to `UPSTREAM`,
streaming each response chunk straight back. WebSocket upgrades bypass it, and
`run`/`start` never use it.

- Only the first 256 KB of each body, for the last 100 requests, is kept, in
  memory. `c` drops them.
- `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` and `Api-Key` headers are
  shown and saved as `REDACTED`. Bodies (prompts, outputs) are shown and saved as
  they are; `captures/` is git-ignored.
- Request bodies are read fully before being forwarded, so very large uploads
  are held in memory while they are sent.

### Data sources

- Connections: `nettop`, for Caddy (client sockets) and the dashboard itself
  (capture proxy sockets to the upstream).
- In-flight requests and upstream failures: Caddy's admin API (`CADDY_ADMIN`).
- Requests: the capture proxy as they start, then Caddy's JSON access log when
  they complete. Each log entry carries an `id` that matches the two.
