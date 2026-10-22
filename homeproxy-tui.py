#!/usr/bin/env python3
"""Terminal dashboard for the homeproxy Caddy instance.

Runs `caddy run` as a child process, parses its JSON logs, and polls the Caddy
admin API and macOS `nettop` to show live connections, whether each one is
streaming, waiting on the upstream or idle, and how many bytes it has moved.

Started by `./homeproxy.sh tui`, which loads .env first.
Keys: q quit, r reload Caddyfile, c clear request history.
Raw Caddy output is appended to caddy.log next to this script.
"""

import collections
import curses
import json
import locale
import os
import subprocess
import threading
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CADDYFILE = os.path.join(HERE, "Caddyfile")
LOG_FILE = os.path.join(HERE, "caddy.log")
ADMIN = "http://localhost:2019"
CADDY_CMD = ["caddy", "run", "--config", CADDYFILE, "--adapter", "caddyfile"]

POLL_SECONDS = 1.0
STREAM_WINDOW = 1.5  # bytes sent within this many seconds = streaming
CLOSED_LINGER = 5.0  # keep closed connections on screen this long
SHUTDOWN_GRACE = 5.0  # wait for open streams before killing caddy


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

    def __init__(self, kind, peer, now):
        self.kind = kind
        self.peer = peer
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


class State:
    def __init__(self, proc, logf):
        self.proc = proc
        self.logf = logf
        self.lock = threading.Lock()
        self.started = time.time()
        self.requests = collections.deque(maxlen=500)
        self.events = collections.deque(maxlen=200)
        self.total_requests = 0
        self.total_down = 0
        self.total_up = 0
        self.conns = {}
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

    def add_request(self, e):
        req = e.get("request", {})
        client = req.get("client_ip") or req.get("remote_ip", "?")
        r = {
            "ts": e.get("ts", time.time()),
            "client": "localhost" if client in ("::1", "127.0.0.1") else client.replace("::ffff:", ""),
            "method": req.get("method", "?"),
            "uri": req.get("uri", ""),
            "status": e.get("status", 0),
            "duration": e.get("duration", 0.0),
            "down": e.get("size", 0),
            "up": e.get("bytes_read", 0),
        }
        with self.lock:
            self.requests.appendleft(r)
            self.total_requests += 1
            self.total_down += r["down"]
            self.total_up += r["up"]

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
            socks = sample_sockets(self.proc.pid)
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
                continue  # admin API and anything else
            conn = self.conns.get(key)
            if conn is None:
                conn = self.conns[key] = Conn(kind, f"{remote[0]}:{remote[1]}", now)
            conn.update(up, down, tcp_state, now, dt)

        for key, conn in list(self.conns.items()):
            if key not in socks and not conn.closed_at:
                conn.closed_at = now
            if conn.closed_at and now - conn.closed_at > CLOSED_LINGER:
                del self.conns[key]

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


def color(n, extra=0):
    return (curses.color_pair(n) if n else 0) | extra


def status_color(code):
    if code >= 500:
        return color(RED)
    if code >= 400:
        return color(YELLOW)
    return color(GREEN)


def draw(scr, st, now):
    scr.erase()
    p = Painter(scr)
    bold = curses.A_BOLD
    dim = curses.A_DIM

    with st.lock:
        requests = list(st.requests)
        events = list(st.events)
        totals = (st.total_requests, st.total_down, st.total_up)
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
    max_clients = max(1, p.room(log_rows + 8))
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

    # Recent requests
    p.line(("RECENT REQUESTS", bold))
    p.line((f"  {'TIME':<8} {'CLIENT':<16} {'METHOD':<7} {'CODE':>4} {'TIME':>8} {'↓ DOWN':>10} {'↑ UP':>10}  PATH", dim))
    n = max(0, p.room(log_rows + 1))
    for r in requests[:n]:
        p.line(
            (f"  {time.strftime('%H:%M:%S', time.localtime(r['ts']))} {r['client']:<16} {r['method']:<7} ", 0),
            (f"{r['status']:>4}", status_color(r["status"])),
            (f" {r['duration']:>7.2f}s {human_bytes(r['down']):>10} {human_bytes(r['up']):>10}  {r['uri']}", 0),
        )
    if not requests:
        p.line(("  none yet", dim))

    # Caddy log tail
    p.y = max(p.y, p.h - 1 - log_rows)
    p.line(("CADDY LOG", bold))
    for ts, level, msg in events[-(log_rows - 1):]:
        attr = {"error": color(RED), "warn": color(YELLOW)}.get(level, dim)
        p.line((f"  {time.strftime('%H:%M:%S', time.localtime(ts))} {level:<5} {msg}", attr))

    p.footer(" q quit   r reload Caddyfile   c clear requests   ● streaming  ◐ waiting on upstream  ○ idle")
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


def run_ui(scr, st):
    curses.curs_set(0)
    curses.use_default_colors()
    for n, c in ((GREEN, curses.COLOR_GREEN), (YELLOW, curses.COLOR_YELLOW),
                 (RED, curses.COLOR_RED), (CYAN, curses.COLOR_CYAN)):
        curses.init_pair(n, c, -1)
    scr.timeout(200)

    next_poll = 0.0
    while True:
        now = time.time()
        if now >= next_poll:
            st.poll(now)
            next_poll = now + POLL_SECONDS
        draw(scr, st, now)
        ch = scr.getch()
        if ch in (ord("q"), ord("Q")):
            return
        if ch in (ord("r"), ord("R")):
            st.event("info", "reloading config…")
            st.reload()
        if ch in (ord("c"), ord("C")):
            with st.lock:
                st.requests.clear()


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
    env = dict(os.environ, LOG_FORMAT="json")
    with open(LOG_FILE, "a") as logf:
        # Own session so Ctrl+C reaches only the dashboard, which then stops caddy.
        proc = subprocess.Popen(CADDY_CMD, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, env=env, start_new_session=True)
        st = State(proc, logf)
        threading.Thread(target=st.read_logs, daemon=True).start()
        try:
            curses.wrapper(run_ui, st)
        except KeyboardInterrupt:
            pass
        finally:
            print("stopping caddy…")
            stop(proc)
    if proc.returncode not in (0, -15):
        print(f"caddy exited with code {proc.returncode}; last log lines:")
        for _, level, msg in list(st.events)[-5:]:
            print(f"  {level}: {msg}")


if __name__ == "__main__":
    main()
