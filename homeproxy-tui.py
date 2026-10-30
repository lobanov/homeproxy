#!/usr/bin/env python3
"""Terminal dashboard for the homeproxy Caddy instance.

Runs `caddy run` as a child process, parses its JSON logs, and polls the Caddy
admin API and macOS `nettop` to show live connections, whether each one is
streaming, waiting on the upstream or idle, and how many bytes it has moved.

Caddy forwards plain HTTP requests through a capture proxy in this process,
which records their headers and the start of their bodies (in memory only) so
they can be inspected in the request detail view. WebSockets go direct.

Started by `./homeproxy.sh tui`, which loads .env first.
Keys: q quit, r reload Caddyfile, c clear request and client history,
↑/↓ select a request, Enter show its headers and payloads.
Raw Caddy output is appended to caddy.log next to this script.
"""

import base64
import collections
import curses
import http.client
import http.server
import json
import locale
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
CADDYFILE = os.path.join(HERE, "Caddyfile")
LOG_FILE = os.path.join(HERE, "caddy.log")
CAPTURE_DIR = os.path.join(HERE, "captures")
ADMIN = "http://" + os.environ.get("CADDY_ADMIN", "localhost:2019")
CADDY_CMD = ["caddy", "run", "--config", CADDYFILE, "--adapter", "caddyfile"]

POLL_SECONDS = 1.0
STREAM_WINDOW = 1.5  # bytes sent within this many seconds = streaming
CLOSED_LINGER = 5.0  # keep closed connections on screen this long
SHUTDOWN_GRACE = 5.0  # wait for open streams before killing caddy
CAPTURE_LIMIT = 256 * 1024  # bytes kept of each request and response body
CAPTURE_KEEP = 100  # requests whose bodies are kept
IDLE_UPSTREAM = 8  # keep-alive connections the capture proxy keeps open

# Not forwarded by the capture proxy (RFC 9110 hop-by-hop headers).
HOP_HEADERS = {"connection", "keep-alive", "proxy-connection", "te", "trailer",
               "transfer-encoding", "upgrade"}
SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie",
                  "x-api-key", "api-key"}


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def human_age(s):
    s = int(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{s % 3600 // 60:02d}m"


def client_name(ip):
    return "localhost" if ip in ("::1", "127.0.0.1") else ip.replace("::ffff:", "")


def redact(headers):
    return [(k, "REDACTED" if k.lower() in SECRET_HEADERS else v) for k, v in headers]


def split_addr(addr, proto):
    # nettop separates the port with ':' for IPv4 and '.' for IPv6.
    host, _, port = addr.rpartition(":" if proto == "tcp4" else ".")
    host = host.replace("::ffff:", "")
    if host in ("::1", "127.0.0.1"):
        host = "localhost"
    return host, int(port) if port.isdigit() else 0


def sample_sockets(pid):
    """Return {socket id: (local, remote, tcp state, bytes_in, bytes_out)}."""
    out = subprocess.run(
        ["nettop", "-L", "1", "-n", "-m", "tcp", "-p", str(pid),
         "-J", "state,bytes_in,bytes_out", "-x"],
        capture_output=True, text=True, timeout=5,
    ).stdout
    socks = {}
    for line in out.splitlines():
        f = line.split(",")
        if len(f) < 4 or not f[0].startswith("tcp") or f[1] == "Listen":
            continue
        proto, _, pair = f[0].partition(" ")
        local, _, remote = pair.partition("<->")
        socks[pair] = (split_addr(local, proto), split_addr(remote, proto),
                       f[1], int(f[2] or 0), int(f[3] or 0))
    return socks


class Conn:
    """One TCP connection. `up` flows toward the upstream, `down` toward the client."""

    def __init__(self, kind, host, port, now):
        self.kind = kind
        self.host = host
        self.peer = f"{host}:{port}"
        self.first_seen = now
        self.up = self.down = 0
        self.last_up = self.last_down = None
        self.rate_down = 0.0
        self.tcp_state = ""
        self.closed_at = None
        self.seen = False

    def update(self, up, down, tcp_state, now, dt):
        if self.seen:
            if up > self.up:
                self.last_up = now
            if down > self.down:
                self.last_down = now
            self.rate_down = max(0, down - self.down) / dt if dt else 0
        self.up, self.down, self.tcp_state, self.seen = up, down, tcp_state, True

    def status(self, now, inflight):
        if self.closed_at:
            return "closed"
        if self.last_down and now - self.last_down < STREAM_WINDOW:
            return "streaming"
        if inflight:
            # Request bytes went out more recently than any response bytes came
            # back: the upstream is still working (e.g. prompt prefill).
            if self.last_up and (self.last_down is None or self.last_up > self.last_down):
                return "waiting"
            if self.last_up is None and self.down == 0 and self.up > 0:
                return "waiting"
        return "idle"

    def quiet_for(self, now):
        last = max(filter(None, (self.last_up, self.last_down)), default=self.first_seen)
        return now - last


# --- capture proxy ------------------------------------------------------------

class Capture:
    """Headers and the first CAPTURE_LIMIT bytes of each body of one request.

    Written by a capture proxy thread while the UI reads it; bytes/bytearray
    copies are atomic under the GIL, so no lock is needed.
    """

    def __init__(self, headers, body):
        self.req_headers = redact(headers)
        self.req_body = body[:CAPTURE_LIMIT]
        self.req_size = len(body)
        self.status = None
        self.reason = ""
        self.resp_headers = []
        self.resp_body = bytearray()
        self.resp_size = 0
        self.error = None
        self.dropped = False  # bodies evicted to bound memory

    def add_response(self, chunk):
        self.resp_size += len(chunk)
        room = CAPTURE_LIMIT - len(self.resp_body)
        if room > 0 and not self.dropped:
            self.resp_body += chunk[:room]

    def drop_bodies(self):
        self.dropped = True
        self.req_body = b""
        self.resp_body = bytearray()


class UpstreamPool:
    """Keep-alive connections from the capture proxy to UPSTREAM."""

    def __init__(self, upstream):
        u = urllib.parse.urlsplit(upstream if "://" in upstream else "http://" + upstream)
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.host_header = u.netloc.rpartition("@")[2]
        self.ctx = ssl.create_default_context() if self.https else None
        self.idle = []
        self.lock = threading.Lock()

    def connect(self):
        if self.https:
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=10, context=self.ctx)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        conn.connect()
        conn.sock.settimeout(None)  # the 10s is for connecting; streams may idle longer
        return conn

    def send(self, method, path, headers, body):
        """Send a request; return (response, connection) once its headers arrive."""
        while True:
            with self.lock:
                conn = self.idle.pop() if self.idle else None
            fresh = conn is None
            if fresh:
                conn = self.connect()
            try:
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                for k, v in headers:
                    conn.putheader(k, v)
                conn.endheaders(body or None)
                return conn.getresponse(), conn
            except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
                conn.close()
                if fresh:
                    raise
                # The upstream had closed this idle connection; retry on another.

    def release(self, conn, resp, reusable):
        with self.lock:
            if reusable and not resp.will_close and len(self.idle) < IDLE_UPSTREAM:
                self.idle.append(conn)
                return
        conn.close()


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    """Forward one request from Caddy to UPSTREAM, recording it along the way."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # requests come from Caddy's access log; stderr would garble the screen

    def read_body(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            parts = []
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    break
                parts.append(self.rfile.read(size))
                self.rfile.readline()
            while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                pass  # trailers
            return b"".join(parts)
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def proxy(self):
        st, pool = self.server.state, self.server.pool
        body = self.read_body()
        headers = [(k, v) for k, v in self.headers.items()
                   if k.lower() not in HOP_HEADERS
                   and k.lower() not in ("host", "content-length", "expect", "x-homeproxy-id")]
        headers.insert(0, ("Host", pool.host_header))
        if body or self.command in ("POST", "PUT", "PATCH"):
            headers.append(("Content-Length", str(len(body))))
        xff = self.headers.get("X-Forwarded-For", "")
        client = client_name(xff.split(",")[-1].strip()) if xff else "?"
        cap = st.start_capture(self.headers.get("X-Homeproxy-Id", ""), client,
                               self.command, self.path, headers, body)

        try:
            resp, conn = pool.send(self.command, self.path, headers, body)
        except Exception as exc:
            cap.error = f"upstream: {exc}"
            msg = json.dumps({"error": {"message": f"homeproxy capture: {exc}", "type": "bad_gateway"}})
            self.send_response_only(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg.encode())
            return

        cap.status, cap.reason = resp.status, resp.reason
        resp_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP_HEADERS]
        cap.resp_headers = redact(resp_headers)
        no_body = self.command == "HEAD" or resp.status in (204, 304) or resp.status < 200
        chunked = not no_body and resp.getheader("Content-Length") is None
        self.send_response_only(resp.status, resp.reason)
        for k, v in resp_headers:
            if not (chunked and k.lower() == "content-length"):
                self.send_header(k, v)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        reusable = False
        try:
            while not no_body:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                cap.add_response(chunk)
                # Unbuffered: each chunk reaches Caddy as soon as it arrives.
                if chunked:
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                else:
                    self.wfile.write(chunk)
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
            resp.close()  # marks it fully read, so the connection can be reused
            reusable = True
        except Exception as exc:
            # Upstream failed mid-body, or the client went away: drop both sides
            # so the upstream stops generating and Caddy sees the cut.
            cap.error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            self.close_connection = True
        finally:
            pool.release(conn, resp, reusable)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = proxy


class CaptureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state):
        super().__init__(("127.0.0.1", 0), CaptureHandler)
        self.state = state
        self.pool = UpstreamPool(state.upstream)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def handle_error(self, request, client_address):
        self.state.event("error", f"capture proxy: {sys.exc_info()[1]}")


# --- state ------------------------------------------------------------------

def new_request(rid, ts, client, method, uri):
    return {"id": rid, "ts": ts, "client": client, "method": method, "uri": uri,
            "status": 0, "duration": 0.0, "down": 0, "up": 0, "done": False,
            "cap": None, "req_headers": [], "resp_headers": []}


def log_headers(h):
    """Caddy logs headers as {name: [values]}."""
    return [(k, v) for k, vs in (h or {}).items() for v in vs]


class State:
    def __init__(self, logf):
        self.proc = None
        self.logf = logf
        self.lock = threading.Lock()
        self.started = time.time()
        self.requests = collections.deque(maxlen=500)  # newest first, see new_request()
        self.by_id = {}
        self.captured = collections.deque()  # requests whose bodies are kept
        self.events = collections.deque(maxlen=200)
        self.total_requests = 0
        self.total_down = 0
        self.total_up = 0
        self.conns = {}
        self.clients = {}  # client IP -> traffic summary, see client()
        self.last_poll = None
        self.inflight = 0
        self.fails = 0
        self.admin_ok = False

        self.listen_port = int(os.environ.get("LISTEN_PORT", "8080"))
        self.upstream = os.environ.get("UPSTREAM", "")
        u = urllib.parse.urlsplit(self.upstream if "://" in self.upstream else "http://" + self.upstream)
        self.upstream_port = u.port or (443 if u.scheme == "https" else 80)
        self.proxy_url = os.environ.get("PROXY_URL", f"http://localhost:{self.listen_port}")

    # --- caddy output -------------------------------------------------------

    def read_logs(self):
        for line in self.proc.stdout:
            self.logf.write(line)
            self.logf.flush()
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                self.event("info", line)
                continue
            logger = str(entry.get("logger", ""))
            if logger.startswith("http.log.access"):
                self.add_request(entry)
            elif logger == "admin.api" and entry.get("msg") == "received request":
                continue  # our own polling
            else:
                msg = entry.get("msg", "")
                if entry.get("error"):
                    msg += f": {entry['error']}"
                self.event(entry.get("level", "info"), msg, entry.get("ts"))

    def push(self, r):
        """Add a request to the history; call with the lock held."""
        if len(self.requests) == self.requests.maxlen:
            self.by_id.pop(self.requests[-1]["id"], None)
        self.requests.appendleft(r)
        if r["id"]:
            self.by_id[r["id"]] = r

    def start_capture(self, rid, client, method, uri, headers, body):
        """Called by the capture proxy when a request starts; returns its Capture."""
        cap = Capture(headers, body)
        r = new_request(rid, time.time(), client, method, uri)
        r["cap"] = cap
        with self.lock:
            self.push(r)
            self.captured.append(cap)
            while len(self.captured) > CAPTURE_KEEP:
                self.captured.popleft().drop_bodies()
        return cap

    def add_request(self, e):
        """An access log entry, written by Caddy once a request completes."""
        req = e.get("request", {})
        end = e.get("ts", time.time())
        duration = e.get("duration", 0.0)
        client = client_name(req.get("client_ip") or req.get("remote_ip", "?"))
        method, uri = req.get("method", "?"), req.get("uri", "")
        with self.lock:
            if e.get("id"):
                r = self.by_id.get(e["id"])
            else:
                # Caddy drops the id of requests the client cancelled: take the
                # oldest unfinished capture that looks the same.
                r = next((r for r in reversed(self.requests)
                          if not r["done"] and r["cap"] and r["method"] == method
                          and r["uri"] == uri and r["client"] == client), None)
            if r is None:  # not seen by the capture proxy, e.g. a WebSocket or a 401
                r = new_request(e.get("id", ""), end - duration, client, method, uri)
                self.push(r)
            r.update(status=e.get("status", 0), duration=duration, down=e.get("size", 0),
                     up=e.get("bytes_read", 0), done=True,
                     req_headers=redact(log_headers(req.get("headers"))),
                     resp_headers=redact(log_headers(e.get("resp_headers"))))
            self.total_requests += 1
            self.total_down += r["down"]
            self.total_up += r["up"]
            c = self.client(r["client"], end)
            c["requests"] += 1
            c["down"] += r["down"]
            c["up"] += r["up"]

    def client(self, ip, now):
        """Summary for one client IP; call with the lock held."""
        c = self.clients.get(ip)
        if c is None:
            c = self.clients[ip] = {"requests": 0, "up": 0, "down": 0,
                                    "conns": 0, "peak": 0, "last": now}
        c["last"] = max(c["last"], now)
        return c

    def clear_history(self):
        with self.lock:
            self.requests.clear()
            self.by_id.clear()
            for cap in self.captured:
                cap.drop_bodies()
            self.captured.clear()
            self.clients.clear()

    def event(self, level, msg, ts=None):
        with self.lock:
            self.events.append((ts or time.time(), level, msg))

    # --- polling ------------------------------------------------------------

    def poll(self, now):
        if self.proc.poll() is not None:
            return
        try:
            with urllib.request.urlopen(ADMIN + "/reverse_proxy/upstreams", timeout=0.5) as resp:
                ups = json.load(resp)
            self.inflight = sum(u.get("num_requests", 0) for u in ups)
            self.fails = sum(u.get("fails", 0) for u in ups)
            self.admin_ok = True
        except Exception:
            self.admin_ok = False

        try:
            # Caddy holds the client sockets (and WebSockets to the upstream),
            # the capture proxy in this process the other upstream sockets.
            socks = sample_sockets(self.proc.pid)
            socks.update(sample_sockets(os.getpid()))
        except Exception as exc:
            self.event("error", f"nettop failed: {exc}")
            return
        dt = now - self.last_poll if self.last_poll else 0
        self.last_poll = now

        for key, (local, remote, tcp_state, b_in, b_out) in socks.items():
            if local[1] == self.listen_port:
                kind, up, down = "client", b_in, b_out
            elif remote[1] == self.upstream_port:
                kind, up, down = "upstream", b_out, b_in
            else:
                continue  # admin API, Caddy <-> capture proxy and anything else
            conn = self.conns.get(key)
            if conn is None:
                conn = self.conns[key] = Conn(kind, remote[0], remote[1], now)
            conn.update(up, down, tcp_state, now, dt)

        for key, conn in list(self.conns.items()):
            if key not in socks and not conn.closed_at:
                conn.closed_at = now
            if conn.closed_at and now - conn.closed_at > CLOSED_LINGER:
                del self.conns[key]

        open_by_ip = collections.Counter(
            c.host for c in self.conns.values() if c.kind == "client" and not c.closed_at)
        with self.lock:
            for c in self.clients.values():
                c["conns"] = 0
            for ip, n in open_by_ip.items():
                c = self.client(ip, now)
                c["conns"] = n
                c["peak"] = max(c["peak"], n)

    def reload(self):
        def run():
            res = subprocess.run(
                ["caddy", "reload", "--config", CADDYFILE, "--adapter", "caddyfile"],
                capture_output=True, text=True,
            )
            if res.returncode == 0:
                self.event("info", "config reloaded")
            else:
                tail = (res.stderr or res.stdout).strip().splitlines()[-1:]
                self.event("error", "reload failed: " + (tail[0] if tail else "unknown error"))
        threading.Thread(target=run, daemon=True).start()


# --- payload formatting -----------------------------------------------------

# Control characters would move the cursor or garble the screen.
SAFE_TEXT = {c: "·" for c in range(32)}
SAFE_TEXT.update({9: "    ", 127: "·"})


def header(headers, name):
    name = name.lower()
    return next((v for k, v in headers if k.lower() == name), "")


def decode_body(data, headers):
    """Undo Content-Encoding; returns (bytes, note). Works on truncated gzip too."""
    enc = header(headers, "Content-Encoding").lower()
    if enc in ("gzip", "deflate", "x-gzip"):
        try:
            return zlib.decompressobj(47).decompress(bytes(data)), f"{enc}-decoded"
        except zlib.error:
            return None, f"undecodable {enc}"
    if enc and enc != "identity":
        return None, f"{enc}-compressed"
    return bytes(data), ""


def sse_text(text):
    """Join the text deltas of an OpenAI or Anthropic event stream."""
    reasoning, content = [], []
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            ev = json.loads(line[5:].strip())
        except ValueError:
            continue  # [DONE], or cut off by CAPTURE_LIMIT
        if not isinstance(ev, dict):
            continue
        for ch in ev.get("choices") or []:  # chat completions
            d = ch.get("delta") or {}
            reasoning.append(d.get("reasoning_content") or d.get("reasoning") or "")
            content.append(d.get("content") or "")
        t = ev.get("type", "")
        d = ev.get("delta")
        if t == "content_block_delta" and isinstance(d, dict):  # Anthropic messages
            reasoning.append(d.get("thinking") or "")
            content.append(d.get("text") or "")
        elif t.endswith("output_text.delta") and isinstance(d, str):  # OpenAI responses
            content.append(d)
        elif t.endswith("reasoning_text.delta") or t.endswith("reasoning_summary_text.delta"):
            reasoning.append(d if isinstance(d, str) else "")
    out = []
    for title, parts in (("reasoning", reasoning), ("content", content)):
        joined = "".join(p for p in parts if isinstance(p, str))
        if joined:
            out += [f"[{title}]"] + joined.splitlines() + [""]
    return out or ["(no text deltas in this stream)"]


def body_lines(data, size, headers, assemble):
    """Body as display lines plus a note for its section heading."""
    notes = [human_bytes(size)]
    ctype = header(headers, "Content-Type").split(";")[0].strip()
    if ctype:
        notes.append(ctype)
    if size > len(data):
        notes.append(f"first {human_bytes(len(data))} shown")
    if not size:
        return ["(empty)"], notes
    if not data:
        return ["(no longer kept, only the last %d requests are)" % CAPTURE_KEEP], notes
    raw, note = decode_body(data, headers)
    if note:
        notes.append(note)
    if raw is None:
        return ["(compressed, can't show)"], notes
    text = raw.decode("utf-8", "replace")
    if "\x00" in text or text.count("�") > len(text) // 100 + 3:
        return [f"(binary, {human_bytes(len(raw))})"], notes
    if ctype == "text/event-stream" and assemble:
        notes.append("assembled text")
        return sse_text(text), notes
    if "json" in ctype or text[:1] in "{[":
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass  # not JSON, or cut off
    return text.splitlines() or [""], notes


def detail_lines(r, width, wrap, assemble):
    """The detail view of one request as [(text, attr)] and section start rows."""
    bold, dim = curses.A_BOLD, curses.A_DIM
    cap = r["cap"]
    lines, sections = [], []

    def section(title, note=""):
        if lines:
            lines.append(("", 0))
        sections.append(len(lines))
        lines.append((title + (f"  ({note})" if note else ""), bold))

    def text(s, attr=0):
        s = "  " + s.translate(SAFE_TEXT)
        if wrap and len(s) > width - 1 > 4:
            step = width - 3
            lines.append((s[:width - 1], attr))
            for i in range(width - 1, len(s), step):
                lines.append(("  " + s[i:i + step], attr))
        else:
            lines.append((s, attr))

    def headers_block(hs):
        for k, v in hs or [("(none)", "")]:
            text(f"{k}: {v}" if v else k, 0 if v else dim)

    if cap is None:
        section("REQUEST HEADERS", "from the access log; no bodies for WebSockets or rejected requests")
        headers_block(r["req_headers"])
        section("RESPONSE HEADERS", "from the access log")
        headers_block(r["resp_headers"])
        return lines, sections

    if cap.error:
        section("ERROR")
        text(cap.error, color(RED))
    section("REQUEST HEADERS", "as sent upstream")
    headers_block(cap.req_headers)
    body, notes = body_lines(cap.req_body, cap.req_size, cap.req_headers, False)
    section("REQUEST BODY", ", ".join(notes))
    for s in body:
        text(s)
    section("RESPONSE HEADERS", "" if cap.status else "none" if cap.error else "waiting for upstream")
    headers_block(cap.resp_headers)
    if cap.status:
        body, notes = body_lines(cap.resp_body, cap.resp_size, cap.resp_headers, assemble)
        if not r["done"]:
            notes.append("receiving")
        section("RESPONSE BODY", ", ".join(notes))
        for s in body:
            text(s)
    return lines, sections


def save_request(r):
    """Write one captured request to captures/ and return its path."""
    cap = r["cap"]

    def body(data, size):
        out = {"size": size, "truncated": size > len(data)}
        try:
            out["text"] = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            out["base64"] = base64.b64encode(bytes(data)).decode()
        return out

    doc = {"id": r["id"], "time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(r["ts"])),
           "client": r["client"], "method": r["method"], "uri": r["uri"],
           "status": cap.status, "duration": r["duration"], "error": cap.error,
           "request": {"headers": cap.req_headers, "body": body(cap.req_body, cap.req_size)},
           "response": {"headers": cap.resp_headers, "body": body(cap.resp_body, cap.resp_size)}}
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    name = time.strftime("%Y%m%d-%H%M%S", time.localtime(r["ts"])) + f"-{(r['id'] or 'request')[:8]}.json"
    path = os.path.join(CAPTURE_DIR, name)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return path


# --- drawing ----------------------------------------------------------------

GREEN, YELLOW, RED, CYAN = 1, 2, 3, 4

STATUS_STYLE = {
    "streaming": ("●", GREEN, 0),
    "waiting": ("◐", YELLOW, 0),
    "idle": ("○", 0, curses.A_DIM),
    "closed": ("×", 0, curses.A_DIM),
}


class Painter:
    def __init__(self, scr):
        self.scr = scr
        self.h, self.w = scr.getmaxyx()
        self.y = 0

    def room(self, reserve=0):
        return self.h - 1 - reserve - self.y

    def line(self, *parts):
        """Draw (text, attr) parts on the next row, clipped to the screen."""
        if self.y >= self.h - 1:
            return
        x = 0
        for text, attr in parts:
            if x >= self.w - 1:
                break
            try:
                self.scr.addnstr(self.y, x, text, self.w - 1 - x, attr)
            except curses.error:
                pass
            x += len(text)
        self.y += 1

    def footer(self, text):
        try:
            self.scr.addnstr(self.h - 1, 0, text.ljust(self.w - 1), self.w - 1, curses.A_REVERSE)
        except curses.error:
            pass


class View:
    """What the user is looking at: the dashboard or one request's details."""

    def __init__(self):
        self.selected = None  # a request dict from State.requests
        self.detail = False
        self.scroll = 0
        self.page = 1  # rows the detail view showed last frame
        self.sections = []
        self.max_scroll = 0
        self.wrap = True
        self.assemble = False
        self.list_rows = 1  # request rows the dashboard showed last frame


def color(n, extra=0):
    return (curses.color_pair(n) if n else 0) | extra


def status_color(code):
    if code >= 500:
        return color(RED)
    if code >= 400:
        return color(YELLOW)
    return color(GREEN)


def request_status(r):
    """Status code and duration, for completed or in-flight requests."""
    if r["done"]:
        return r["status"], r["duration"]
    cap = r["cap"]
    return (cap.status if cap else 0) or 0, time.time() - r["ts"]


def request_sizes(r):
    cap = r["cap"]
    if r["done"] or not cap:
        return r["down"], r["up"]
    return cap.resp_size, cap.req_size


def draw(scr, st, view, now):
    scr.erase()
    p = Painter(scr)
    bold = curses.A_BOLD
    dim = curses.A_DIM

    with st.lock:
        requests = list(st.requests)
        recent_clients = sorted(((ip, dict(c)) for ip, c in st.clients.items()),
                                key=lambda kv: kv[1]["last"], reverse=True)
        events = list(st.events)
        totals = (st.total_requests, st.total_down, st.total_up)
    if view.selected is not None and not any(r is view.selected for r in requests):
        view.selected, view.detail = None, False  # cleared or aged out
    if view.detail:
        draw_detail(scr, p, view, now)
        return
    conns = sorted(st.conns.values(), key=lambda c: c.first_seen)
    clients = [c for c in conns if c.kind == "client"]
    upstreams = [c for c in conns if c.kind == "upstream"]

    # Header
    code = st.proc.poll()
    if code is None:
        caddy = (f"caddy pid {st.proc.pid}  up {human_age(now - st.started)}", color(GREEN))
    else:
        caddy = (f"caddy exited (code {code}), see log below", color(RED, bold))
    p.line(("homeproxy  ", bold), (f"{st.proxy_url} → {st.upstream}", color(CYAN)), ("   ", 0), caddy)
    if st.admin_ok:
        health = (f"in flight {st.inflight}   upstream fails {st.fails}",
                  color(YELLOW) if st.inflight else 0)
    else:
        health = ("admin API unreachable", color(RED))
    p.line(health, (f"   requests {totals[0]}   ↓ {human_bytes(totals[1])}   ↑ {human_bytes(totals[2])}", 0))
    p.line(("", 0))

    log_rows = 4
    # Client connections
    cols = f"  {'STATE':<11} {'CLIENT':<26} {'AGE':>7} {'QUIET':>7} {'↑ UP':>10} {'↓ DOWN':>10} {'↓ RATE':>11}"
    p.line((f"CLIENT CONNECTIONS ({sum(1 for c in clients if not c.closed_at)})", bold))
    p.line((cols, dim))
    max_clients = max(1, p.room(log_rows + 17))
    for c in clients[:max_clients]:
        p.line(*conn_row(c, now, st.inflight))
    if len(clients) > max_clients:
        p.line((f"  … {len(clients) - max_clients} more", dim))
    if not clients:
        p.line(("  none", dim))
    p.line(("", 0))

    # Upstream connections
    p.line((f"UPSTREAM CONNECTIONS ({sum(1 for c in upstreams if not c.closed_at)})", bold))
    for c in upstreams[:3]:
        p.line(*conn_row(c, now, st.inflight))
    if not upstreams:
        p.line(("  none", dim))
    p.line(("", 0))

    # Per-client summary
    p.line(("RECENT CLIENTS", bold))
    p.line((f"  {'CLIENT':<26} {'LAST SEEN':>9} {'REQUESTS':>8} {'CONNS':>5} {'PEAK':>4} {'↑ UP':>10} {'↓ DOWN':>10}", dim))
    max_recent = 5
    for ip, c in recent_clients[:max_recent]:
        attr = 0 if c["conns"] else dim
        p.line((f"  {ip:<26} {human_age(now - c['last']) + ' ago':>9} {c['requests']:>8} ", attr),
               (f"{c['conns']:>5}", color(GREEN) if c["conns"] else dim),
               (f" {c['peak']:>4} {human_bytes(c['up']):>10} {human_bytes(c['down']):>10}", attr))
    if len(recent_clients) > max_recent:
        p.line((f"  … {len(recent_clients) - max_recent} more", dim))
    if not recent_clients:
        p.line(("  none yet", dim))
    p.line(("", 0))

    # Recent requests, scrolled to keep the selected one visible
    p.line(("RECENT REQUESTS", bold))
    p.line((f"  {'TIME':<8} {'CLIENT':<16} {'METHOD':<7} {'CODE':>4} {'TIME':>8} {'↓ DOWN':>10} {'↑ UP':>10}  PATH", dim))
    n = view.list_rows = max(1, p.room(log_rows + 1))
    idx = next((i for i, r in enumerate(requests) if r is view.selected), -1)
    start = max(0, idx - n + 1)
    for r in requests[start:start + n]:
        sel = curses.A_REVERSE if r is view.selected else 0
        code, duration = request_status(r)
        down, up = request_sizes(r)
        p.line(
            (f"  {time.strftime('%H:%M:%S', time.localtime(r['ts']))} {r['client']:<16} {r['method']:<7} ", sel),
            (f"{code:>4}" if code else f"{'…':>4}", (status_color(code) if code else color(YELLOW)) | sel),
            (f" {duration:>7.2f}s {human_bytes(down):>10} {human_bytes(up):>10}  {r['uri']}", sel),
        )
    if not requests:
        p.line(("  none yet", dim))

    # Caddy log tail
    p.y = max(p.y, p.h - 1 - log_rows)
    p.line(("CADDY LOG", bold))
    for ts, level, msg in events[-(log_rows - 1):]:
        attr = {"error": color(RED), "warn": color(YELLOW)}.get(level, dim)
        p.line((f"  {time.strftime('%H:%M:%S', time.localtime(ts))} {level:<5} {msg}", attr))

    p.footer(" q quit   r reload   c clear   ↑↓ select request   ⏎ details   "
             "● streaming  ◐ waiting on upstream  ○ idle")
    scr.refresh()


def draw_detail(scr, p, view, now):
    r = view.selected
    code, duration = request_status(r)
    cap = r["cap"]
    reason = cap.reason if cap and cap.status else ""
    state = "" if r["done"] else "  in flight"
    p.line(("  ", 0), (f"{r['method']} {r['uri']}", curses.A_BOLD), ("   ", 0),
           (f"{code} {reason}".strip() if code else "…", status_color(code) if code else color(YELLOW)),
           (f"   {duration:.2f}s{state}   from {r['client']}   at "
            f"{time.strftime('%H:%M:%S', time.localtime(r['ts']))}   id {r['id'][:8] or '-'}", curses.A_DIM))
    p.line(("", 0))

    lines, view.sections = detail_lines(r, p.w, view.wrap, view.assemble)
    view.page = max(1, p.room())
    following = view.scroll >= view.max_scroll > 0  # keep the tail of a stream in view
    view.max_scroll = max(0, len(lines) - view.page)
    if following:
        view.scroll = view.max_scroll
    view.scroll = min(max(0, view.scroll), view.max_scroll)
    for text, attr in lines[view.scroll:view.scroll + view.page]:
        p.line((text, attr))

    pos = f"{view.scroll + 1}-{min(len(lines), view.scroll + view.page)}/{len(lines)}"
    p.footer(f" esc back   ↑↓ pgup pgdn g G scroll   tab next section   w wrap {'on' if view.wrap else 'off'}   "
             f"a assemble stream {'on' if view.assemble else 'off'}   s save   {pos}")
    scr.refresh()


def conn_row(c, now, inflight):
    status = c.status(now, inflight)
    icon, col, extra = STATUS_STYLE[status]
    rate = f"{human_bytes(c.rate_down)}/s" if status == "streaming" else ""
    attr = color(col, extra)
    return (
        (f"  {icon} {status:<9} ", attr),
        (f"{c.peer:<26} {human_age(now - c.first_seen):>7} {human_age(c.quiet_for(now)):>7} "
         f"{human_bytes(c.up):>10} {human_bytes(c.down):>10} {rate:>11}", extra),
    )


ENTER = (10, 13, curses.KEY_ENTER)
UP = (curses.KEY_UP, ord("k"))
DOWN = (curses.KEY_DOWN, ord("j"))


def list_key(ch, st, view):
    """Handle a key on the dashboard; returns False to quit."""
    if ch in (ord("q"), ord("Q")):
        return False
    if ch in (ord("r"), ord("R")):
        st.event("info", "reloading config…")
        st.reload()
    elif ch in (ord("c"), ord("C")):
        st.clear_history()
        view.selected = None
    elif ch in UP + DOWN:
        with st.lock:
            requests = list(st.requests)
        if not requests:
            return True
        idx = next((i for i, r in enumerate(requests) if r is view.selected), None)
        if idx is None:
            idx = 0
        else:
            idx = max(0, min(len(requests) - 1, idx + (1 if ch in DOWN else -1)))
        view.selected = requests[idx]
    elif ch == 27:  # Esc
        view.selected = None
    elif ch in ENTER + (curses.KEY_RIGHT, ord("l")) and view.selected is not None:
        view.detail, view.scroll, view.max_scroll = True, 0, 0
    return True


def detail_key(ch, st, view):
    if ch in (27, ord("q"), curses.KEY_LEFT, ord("h"), curses.KEY_BACKSPACE, 127):
        view.detail = False
    elif ch in UP:
        view.scroll -= 1
    elif ch in DOWN:
        view.scroll += 1
    elif ch in (curses.KEY_PPAGE, ord("b")):
        view.scroll -= view.page - 1
    elif ch in (curses.KEY_NPAGE, ord(" ")):
        view.scroll += view.page - 1
    elif ch in (curses.KEY_HOME, ord("g")):
        view.scroll = 0
    elif ch in (curses.KEY_END, ord("G")):
        view.scroll = view.max_scroll
    elif ch == ord("\t"):
        view.scroll = next((s for s in view.sections if s > view.scroll), view.scroll)
    elif ch == curses.KEY_BTAB:
        view.scroll = next((s for s in reversed(view.sections) if s < view.scroll), 0)
    elif ch in (ord("w"), ord("W")):
        view.wrap = not view.wrap
    elif ch in (ord("a"), ord("A")):
        view.assemble = not view.assemble
        view.scroll = 0
    elif ch in (ord("s"), ord("S")):
        if view.selected["cap"] is None:
            st.event("warn", "nothing captured for this request")
        else:
            try:
                st.event("info", "saved " + os.path.relpath(save_request(view.selected), HERE))
            except OSError as exc:
                st.event("error", f"save failed: {exc}")
    # Leaving follow mode when scrolling up is implicit: scroll < max_scroll.
    view.scroll = max(0, view.scroll)


def run_ui(scr, st):
    curses.curs_set(0)
    curses.use_default_colors()
    for n, c in ((GREEN, curses.COLOR_GREEN), (YELLOW, curses.COLOR_YELLOW),
                 (RED, curses.COLOR_RED), (CYAN, curses.COLOR_CYAN)):
        curses.init_pair(n, c, -1)
    scr.keypad(True)
    scr.timeout(200)

    view = View()
    next_poll = 0.0
    while True:
        now = time.time()
        if now >= next_poll:
            st.poll(now)
            next_poll = now + POLL_SECONDS
        draw(scr, st, view, now)
        ch = scr.getch()
        if ch == -1:
            continue
        if view.detail:
            detail_key(ch, st, view)
        elif not list_key(ch, st, view):
            return


def stop(proc):
    if proc.poll() is not None:
        return
    proc.terminate()  # graceful: caddy waits for open streams
    try:
        proc.wait(SHUTDOWN_GRACE)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main():
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")  # don't wait a second after Esc
    with open(LOG_FILE, "a") as logf:
        st = State(logf)
        capture = CaptureServer(st)
        threading.Thread(target=capture.serve_forever, daemon=True).start()
        # In os.environ, not just the child's env, so `caddy reload` sees them too.
        os.environ.update(LOG_FORMAT="json", CAPTURE_URL=capture.url)
        # Own session so Ctrl+C reaches only the dashboard, which then stops caddy.
        proc = st.proc = subprocess.Popen(CADDY_CMD, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                          text=True, bufsize=1, start_new_session=True)
        threading.Thread(target=st.read_logs, daemon=True).start()
        try:
            curses.wrapper(run_ui, st)
        except KeyboardInterrupt:
            pass
        finally:
            print("stopping caddy…")
            stop(proc)  # before the capture proxy, which carries its open streams
            capture.server_close()
    if proc.returncode not in (0, -15):
        print(f"caddy exited with code {proc.returncode}; last log lines:")
        for _, level, msg in list(st.events)[-5:]:
            print(f"  {level}: {msg}")


if __name__ == "__main__":
    main()
