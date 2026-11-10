#!/usr/bin/env python3
"""vibebox trace mode: see exactly what the agent harness sends to the model.

Two halves, stdlib only:

* PROXY (runs INSIDE the box, `vibe -trace`). A tiny logging reverse proxy on
  127.0.0.1:<port>. opencode's baseURL points here; every request is forwarded
  to the real LLM (TRACE_UPSTREAM) over HTTPS -- through the box's HTTPS_PROXY,
  which urllib honours -- and the response is streamed back chunk by chunk.
  For each call NNN it writes into TRACE_DIR:
      NNN-http.json      method, path, status, timing, headers (auth REDACTED)
      NNN-request.json   the request body, pretty-printed (system prompt,
                         tools array with JSON schemas, messages...)
      NNN-response.sse   the raw streamed bytes, exactly as the model sent them
      NNN-response.json  the final assistant message assembled from the chunks
                         (text, tool_calls with parsed args, finish_reason, usage)

* VIEWER (runs on the host, `vibe -trace-show [dir] [N]`): a readable summary
  of the agent loop: model asks for a tool -> harness runs it -> the result is
  sent back as a message -> repeat until the model answers without tool calls.

Entry point in the box:  trace_proxy.py --exec opencode   (or bash)
  forks the proxy into the background, waits until it listens, then execs the
  command, so opencode becomes the main process as usual.
"""
import glob
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

DEFAULT_PORT = 4141
SECRET_HEADERS = {"authorization", "proxy-authorization", "api-key", "x-api-key", "cookie"}
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "host",
              "content-length", "accept-encoding", "content-encoding"}


# ----------------------------------------------------------------------------
# Pure helpers (unit-tested)
# ----------------------------------------------------------------------------

def redact_headers(headers):
    """dict of headers -> copy safe to write to disk (secrets replaced)."""
    out = {}
    for k, v in headers.items():
        if k.lower() in SECRET_HEADERS:
            scheme = v.split(" ", 1)[0] + " " if " " in v else ""
            out[k] = f"{scheme}<redacted>"
        else:
            out[k] = v
    return out


def upstream_url(upstream, path):
    """Real URL for a request path the local proxy received.
    upstream 'https://api.scaleway.ai/v1', path '/v1/chat/completions?x=1'
    -> 'https://api.scaleway.ai/v1/chat/completions?x=1'. The local base URL keeps
    the upstream's path (see local_base_url), so the path maps 1:1."""
    u = urlsplit(upstream)
    return f"{u.scheme}://{u.netloc}{path}"


def local_base_url(upstream, port=DEFAULT_PORT):
    """What opencode's baseURL becomes in trace mode: same path, local proxy."""
    path = urlsplit(upstream).path.rstrip("/")
    return f"http://127.0.0.1:{port}{path}"


def parse_sse(text):
    """Raw text/event-stream -> list of decoded JSON payloads of `data:` lines
    ([DONE] and non-JSON lines are skipped)."""
    events = []
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            events.append(json.loads(data))
        except ValueError:
            pass
    return events


def _parse_args(raw):
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return None  # model produced invalid JSON; the raw string is kept


def assemble_chunks(events):
    """OpenAI-style chat.completion.chunk events -> one final assistant message.

    Each chunk carries a *delta*: a few characters of text, or a fragment of a
    tool call (tool calls are identified by `index`; the first fragment has the
    id and function name, later ones append to `arguments`). Gluing them back
    together gives what a non-streaming call would have returned."""
    text, reasoning, calls = [], [], {}
    out = {"id": None, "model": None, "finish_reason": None, "usage": None}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        out["id"] = out["id"] or ev.get("id")
        out["model"] = out["model"] or ev.get("model")
        if ev.get("usage"):
            out["usage"] = ev["usage"]
        for ch in ev.get("choices") or []:
            d = ch.get("delta") or {}
            if d.get("content"):
                text.append(d["content"])
            r = d.get("reasoning_content") or d.get("reasoning")
            if isinstance(r, str):
                reasoning.append(r)
            for tc in d.get("tool_calls") or []:
                i = tc.get("index", len(calls))
                c = calls.setdefault(i, {"id": None, "type": "function",
                                         "function": {"name": "", "arguments": ""}})
                c["id"] = c["id"] or tc.get("id")
                fn = tc.get("function") or {}
                if fn.get("name"):
                    c["function"]["name"] += fn["name"]
                if fn.get("arguments"):
                    c["function"]["arguments"] += fn["arguments"]
            if ch.get("finish_reason"):
                out["finish_reason"] = ch["finish_reason"]
    msg = {"role": "assistant", "content": "".join(text) or None}
    if reasoning:
        msg["reasoning"] = "".join(reasoning)
    if calls:
        msg["tool_calls"] = []
        for i in sorted(calls):
            c = calls[i]
            c["arguments_parsed"] = _parse_args(c["function"]["arguments"])
            msg["tool_calls"].append(c)
    out["message"] = msg
    out["chunks"] = len(events)
    return out


def assemble_sse(text):
    return assemble_chunks(parse_sse(text))


# ----------------------------------------------------------------------------
# The proxy
# ----------------------------------------------------------------------------

class TraceProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream = ""
    trace_dir = "."
    counter = [0]
    lock = threading.Lock()

    def log_message(self, fmt, *args):  # quiet: never draw over opencode's TUI
        sys.stderr.write("trace_proxy: " + (fmt % args) + "\n")

    def _next(self):
        with self.lock:
            self.counter[0] += 1
            return f"{self.counter[0]:03d}"

    def _write(self, name, data):
        path = os.path.join(self.trace_dir, name)
        with open(path, "w" if isinstance(data, str) else "wb") as f:
            f.write(data)

    def _handle(self):
        n = self._next()
        t0 = time.time()
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        meta = {"call": int(n), "method": self.command, "path": self.path,
                "upstream": upstream_url(self.upstream, self.path),
                "request_headers": redact_headers(dict(self.headers)),
                "started": time.strftime("%H:%M:%S")}
        self._write(f"{n}-http.json", json.dumps(dict(meta, in_progress=True), indent=2) + "\n")
        if body:
            try:
                self._write(f"{n}-request.json",
                            json.dumps(json.loads(body), indent=2, ensure_ascii=False) + "\n")
            except ValueError:
                self._write(f"{n}-request.raw", body)
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        req = Request(meta["upstream"], data=body or None, headers=hdrs, method=self.command)
        try:
            resp = urlopen(req, timeout=600)  # honours HTTPS_PROXY / NO_PROXY
            status = resp.status
        except HTTPError as e:
            resp, status = e, e.code
        except Exception as e:  # upstream unreachable: tell opencode, log it
            msg = json.dumps({"error": {"message": f"trace proxy: {e}"}}).encode()
            meta.update(status=502, error=str(e))
            self._write(f"{n}-http.json", json.dumps(meta, indent=2) + "\n")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        ctype = resp.headers.get("Content-Type", "")
        sse = "event-stream" in ctype
        meta.update(status=status, response_headers=redact_headers(dict(resp.headers)))
        self.send_response(status)
        for k, v in resp.headers.items():
            if k.lower() not in HOP_BY_HOP:
                self.send_header(k, v)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        raw = bytearray()
        sink = open(os.path.join(self.trace_dir, f"{n}-response.sse"), "wb") if sse else None
        read = getattr(resp, "read1", None) or resp.read
        try:
            while True:
                chunk = read(65536)  # read1: whatever has arrived, no waiting for EOF
                if not chunk:
                    break
                raw += chunk
                if sink:
                    sink.write(chunk)
                    sink.flush()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            meta["client_aborted"] = True
            self.close_connection = True
        finally:
            if sink:
                sink.close()
            resp.close()
        text = raw.decode("utf-8", "replace")
        if sse:
            final = assemble_sse(text)
        else:
            try:
                final = json.loads(text)
            except ValueError:
                final = {"raw": text}
        self._write(f"{n}-response.json", json.dumps(final, indent=2, ensure_ascii=False) + "\n")
        meta["seconds"] = round(time.time() - t0, 2)
        self._write(f"{n}-http.json", json.dumps(meta, indent=2) + "\n")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle


def serve(upstream, trace_dir, port=DEFAULT_PORT):
    os.makedirs(trace_dir, exist_ok=True)
    TraceProxy.upstream, TraceProxy.trace_dir = upstream, trace_dir
    srv = ThreadingHTTPServer(("127.0.0.1", port), TraceProxy)
    srv.daemon_threads = True
    return srv


def _listening(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        return True
    except OSError:
        return False


def run_and_exec(cmd):
    """Fork the proxy into the background, wait for it, exec cmd (opencode/bash)."""
    upstream = os.environ["TRACE_UPSTREAM"]
    trace_dir = os.environ.get("TRACE_DIR", "/trace")
    port = int(os.environ.get("TRACE_PORT", DEFAULT_PORT))
    srv = serve(upstream, trace_dir, port)  # bind before forking: no race
    if os.fork() == 0:  # child: the proxy
        os.setsid()
        log = os.open(os.path.join(trace_dir, "proxy.log"),
                      os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        null = os.open(os.devnull, os.O_RDONLY)
        os.dup2(null, 0)
        os.dup2(log, 1)
        os.dup2(log, 2)
        srv.serve_forever()
        os._exit(0)
    srv.socket.close()  # parent: becomes opencode
    for _ in range(50):
        if _listening(port):
            break
        time.sleep(0.1)
    os.execvp(cmd[0], cmd)


# ----------------------------------------------------------------------------
# The viewer (host side)
# ----------------------------------------------------------------------------

class Style:
    def __init__(self, color):
        self.color = color

    def _c(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.color else s

    def bold(self, s): return self._c("1", s)
    def dim(self, s): return self._c("2", s)
    def red(self, s): return self._c("31", s)
    def green(self, s): return self._c("32", s)
    def yellow(self, s): return self._c("33", s)
    def blue(self, s): return self._c("34", s)
    def magenta(self, s): return self._c("35", s)
    def cyan(self, s): return self._c("36", s)


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_calls(trace_dir):
    """[{n, http, request, response}] for every call in a trace dir, in order."""
    calls = []
    for p in sorted(glob.glob(os.path.join(trace_dir, "*-http.json"))):
        n = os.path.basename(p).split("-")[0]
        resp = _load(os.path.join(trace_dir, f"{n}-response.json"))
        sse = os.path.join(trace_dir, f"{n}-response.sse")
        if resp is None and os.path.exists(sse):  # stream cut off (e.g. opencode exited)
            with open(sse, encoding="utf-8", errors="replace") as f:
                resp = dict(assemble_sse(f.read()), incomplete=True)
        calls.append({"n": n, "http": _load(p) or {},
                      "request": _load(os.path.join(trace_dir, f"{n}-request.json")),
                      "response": resp})
    return calls


def text_of(content):
    """Message content (string or list of parts) -> plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                parts.append(p.get("text") if p.get("type") == "text" else f"[{p.get('type')}]")
            else:
                parts.append(str(p))
        return "\n".join(x for x in parts if x)
    return json.dumps(content)


def _short(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 1] + "…"


def _args_str(fn, limit):
    args = fn.get("arguments", "")
    try:
        args = json.dumps(json.loads(args), ensure_ascii=False) if args else "{}"
    except ValueError:
        pass
    return args if limit is None else _short(args, limit)


def final_message(resp):
    """response.json (assembled stream or plain chat.completion) -> (msg, finish, usage)."""
    if not isinstance(resp, dict):
        return None, None, None
    if "message" in resp:  # assembled from SSE
        return resp["message"], resp.get("finish_reason"), resp.get("usage")
    ch = (resp.get("choices") or [{}])[0]
    return ch.get("message"), ch.get("finish_reason"), resp.get("usage")


def _new_messages(msgs, history):
    """Messages added since the latest earlier call whose list is a prefix of
    this one (the harness only ever appends; side calls like title generation
    have their own unrelated history)."""
    best = 0
    for prev in history:
        k = len(prev)
        if 0 < k <= len(msgs) and msgs[:k] == prev and k > best:
            best = k
    return msgs[best:], best


def _render_msg(m, S, full):
    role = m.get("role", "?")
    lim = None if full else 300
    out = []
    color = {"user": S.green, "assistant": S.magenta, "tool": S.yellow,
             "system": S.blue}.get(role, str)
    if role == "tool":
        body = text_of(m.get("content"))
        out.append(f"  {color('tool result')} {S.dim('(' + str(m.get('tool_call_id')) + ')')}: "
                   + (body if full else _short(body, 300)))
        return out
    t = text_of(m.get("content"))
    if t:
        out.append(f"  {color(role)}: " + (t if full else _short(t, lim)))
    for tc in m.get("tool_calls") or []:
        fn = tc.get("function") or {}
        out.append(f"  {color(role)} -> {S.bold('tool_call')} {S.cyan(fn.get('name'))}"
                   f"({_args_str(fn, None if full else 200)})")
    if not t and not m.get("tool_calls"):
        out.append(f"  {color(role)}: {S.dim('(empty)')}")
    return out


def render(calls, only=None, color=False):
    """Human-readable lines for a trace. only=N: that call in full detail."""
    S = Style(color)
    out = []
    history, prev_tools, prev_system = [], None, None
    for c in calls:
        h, req, resp = c["http"], c["request"], c["response"]
        full = only is not None and int(c["n"]) == int(only)
        show = only is None or full
        status = (f"-> {h.get('status')}  {h.get('seconds')}s" if "seconds" in h
                  else "-> (never finished)")
        head = f"━━ call {c['n']}  {h.get('method', '?')} {h.get('path', '?')}  {status} ━━"
        is_chat = isinstance(req, dict) and "messages" in req
        if not is_chat:
            if show:
                out.append(S.bold(head))
                if isinstance(resp, dict) and isinstance(resp.get("data"), list):
                    out.append(f"  (non-chat call: {len(resp['data'])} models listed)")
                elif full:
                    out.append(json.dumps(resp, indent=2)[:4000])
                out.append("")
            continue
        msgs = req.get("messages") or []
        system = "\n\n".join(text_of(m.get("content")) for m in msgs if m.get("role") == "system")
        tools = req.get("tools") or []
        tool_sig = json.dumps(tools, sort_keys=True)
        rest = [m for m in msgs if m.get("role") != "system"]
        new, kept = _new_messages(msgs, history)
        history.append(msgs)
        if show:
            out.append(S.bold(head))
            out.append(f"  model {S.cyan(req.get('model'))} | {len(msgs)} messages "
                       f"({len(rest)} non-system) | {len(tools)} tools | "
                       f"stream={req.get('stream', False)}")
            if not tools:
                out.append(S.dim("  (no tools offered: a side call, e.g. the harness asking "
                                 "the model for a session title; not part of the agent loop)"))
            if system and (full or system != prev_system):
                lines = system.splitlines()
                out.append(S.blue(f"  SYSTEM PROMPT ({len(system)} chars, {len(lines)} lines)"
                                  + ("" if full else ", first 15 lines:")))
                for ln in (lines if full else lines[:15]):
                    out.append(S.dim("  │ ") + ln)
                if not full and len(lines) > 15:
                    out.append(S.dim(f"  │ … {len(lines) - 15} more lines"))
            elif system:
                out.append(S.dim("  system prompt: unchanged"))
            if tools and (full or tool_sig != prev_tools):
                out.append(S.blue(f"  TOOLS offered to the model ({len(tools)}):"))
                for t in tools:
                    fn = t.get("function") or t
                    desc = (fn.get("description") or "").strip().splitlines()
                    out.append(f"    {S.cyan(fn.get('name', '?')):<24} "
                               + S.dim(_short(desc[0] if desc else "", 90)))
                    if full:
                        schema = json.dumps(fn.get("parameters", {}), indent=2)
                        out += ["      " + ln for ln in schema.splitlines()]
            elif tools:
                out.append(S.dim("  tools: same as before"))
            shown = msgs if full else [m for m in new if m.get("role") != "system"]
            label = "ALL MESSAGES" if full else (
                f"NEW MESSAGES since call with {kept} msgs" if kept else "MESSAGES")
            out.append(S.blue(f"  {label} ({len(shown)}):"))
            for m in shown:
                if full or m.get("role") != "system":
                    out += _render_msg(m, S, full)
            msg, finish, usage = final_message(resp)
            out.append(S.blue("  RESPONSE:"))
            if msg:
                if msg.get("reasoning"):
                    r = msg["reasoning"]
                    out.append(S.dim("  (reasoning) " + (r if full else _short(r, 200))))
                out += _render_msg(msg, S, full)
            else:
                out.append(S.red(f"  (no assistant message; status {h.get('status')})"))
            if isinstance(resp, dict) and resp.get("incomplete"):
                out.append(S.red("  (stream cut off before the end: the harness stopped "
                                 "listening, e.g. opencode exited)"))
            u = usage or {}
            out.append(f"  finish_reason={S.bold(str(finish))}  tokens: "
                       f"prompt={u.get('prompt_tokens', '?')} "
                       f"completion={u.get('completion_tokens', '?')} "
                       f"total={u.get('total_tokens', '?')}")
            ntc = len((msg or {}).get("tool_calls") or [])
            if ntc:
                out.append(S.yellow(f"  ↳ the model asked for {ntc} tool call(s): the harness "
                                    "runs them and sends each result back as a `tool` "
                                    "message in the next call"))
            elif msg:
                out.append(S.green("  ↳ no tool calls: the loop stops here; this text is the "
                                   "answer shown to the user"))
            out.append("")
        prev_tools, prev_system = tool_sig, system
    return out


def latest_trace_dir(root):
    try:
        dirs = [os.path.join(root, d) for d in os.listdir(root)
                if os.path.isdir(os.path.join(root, d))]
    except OSError:
        return ""
    return max(dirs, key=os.path.getmtime) if dirs else ""


def show(args, root, color=None):
    """`vibe -trace-show [dir] [N]` -> exit code."""
    trace_dir, n = "", None
    for a in args:
        if a.isdigit():
            n = int(a)
        else:
            trace_dir = a
    trace_dir = trace_dir or latest_trace_dir(root)
    if not trace_dir or not os.path.isdir(trace_dir):
        print(f"vibebox: no trace dir (looked in {root}); run `vibe -trace` first",
              file=sys.stderr)
        return 1
    calls = load_calls(trace_dir)
    if color is None:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    try:
        print(f"== {trace_dir}  ({len(calls)} calls)")
        for line in render(calls, n, color):
            print(line)
        if n is None and calls:
            print(f"(details: vibe -trace-show {trace_dir} N   raw files: {trace_dir}/NNN-*)")
    except BrokenPipeError:  # `| head`
        sys.stderr.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--exec":
        run_and_exec(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "--serve":
        s = serve(os.environ["TRACE_UPSTREAM"], os.environ.get("TRACE_DIR", "/trace"),
                  int(os.environ.get("TRACE_PORT", DEFAULT_PORT)))
        s.serve_forever()
    else:
        print("usage: trace_proxy.py --exec CMD... | --serve", file=sys.stderr)
        sys.exit(2)
