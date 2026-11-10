#!/usr/bin/env python3
"""Portable (Windows + Linux) launcher for the vibebox podman sandbox.
Security-critical logic is pure (build_podman_command, expand_allowlist, ...) and
unit-tested; main() is the thin I/O wrapper that shells out to podman.
Installed as the `vibe` command (vibebox.py -install symlinks ~/.local/bin/vibe)."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from trace_proxy import local_base_url

# Real repo dir even when run through the ~/.local/bin/vibe symlink.
REPO = os.path.dirname(os.path.realpath(__file__))
DEFAULT_IMAGE = "vibebox:latest"


def to_podman_size(value):
    """'5GB'/'512MB'/'2g'/'1 GB' -> podman size '5g'/'512m'/'2g'/'1g'."""
    s = re.sub(r"\s+", "", value).lower()
    m = re.fullmatch(r"(\d+)(g|gb|m|mb|k|kb)", s)
    if not m:
        raise ValueError(f"can't parse size {value!r} (use e.g. 5GB, 512MB)")
    return m.group(1) + m.group(2)[0]


@dataclass
class Options:
    work: str
    image: str = DEFAULT_IMAGE
    net: List[str] = field(default_factory=lambda: ["full"])
    ram: str = ""
    cpu: int = 0
    disk: str = ""
    gpu: bool = False
    interactive: bool = True  # tty; False = scriptable (piped stdin)
    hostname: str = "devbox"  # neutral name (hides the hex container-id tell)
    opencode: bool = False    # entry = opencode (local-model agent) instead of bash
    llm_url: str = ""         # OpenAI-compatible base URL -> LOCAL_LLM_URL
    llm_model: str = ""       # model id -> LOCAL_LLM_MODEL (image default: "local")
    llm_key: bool = False     # pass LOCAL_LLM_API_KEY by NAME (value via env, not argv)
    oc_config: str = ""       # inline JSON -> OPENCODE_CONFIG_CONTENT (extra models)
    trace_dir: str = ""       # host dir -> /trace; LLM calls go via the in-box trace proxy
    ro: Optional[List[str]] = None  # None: /work rw | []: whole /work ro | [subdirs]: only those ro


def build_podman_command(opts):
    cmd = [
        "podman", "run", "--rm",
        "-it" if opts.interactive else "-i",
        "-v", f"{opts.work}:/work:{'ro' if opts.ro == [] else 'rw'}",
    ]
    # Read-only subfolders: a second bind mount on top of the rw /work.
    for sub in opts.ro or []:
        cmd += ["-v", f"{os.path.join(opts.work, sub)}:/work/{sub}:ro"]
    cmd += [
        "-w", "/work",
        "--userns=keep-id",
    ] + HARDENING
    # Block dmesg (kernel-log leak) and shave the loudest container tells.
    cmd += ["--security-opt", f"seccomp={SECCOMP}",
            "--hostname", opts.hostname, "-e", "container="]
    cmd += _network_args(opts.net)
    cmd += _limit_args(opts)
    if opts.gpu:
        cmd += ["--device", "nvidia.com/gpu=all"]
    entry = ["opencode" if opts.opencode else "bash"]
    if opts.trace_dir and opts.llm_url:
        # opencode talks plain HTTP to the logging proxy on loopback; the proxy
        # forwards to the real URL (through HTTPS_PROXY in allowlist mode).
        cmd += ["-v", f"{opts.trace_dir}:{TRACE_MOUNT}:rw",
                "-e", f"LOCAL_LLM_URL={local_base_url(opts.llm_url, TRACE_PORT)}",
                "-e", f"TRACE_UPSTREAM={opts.llm_url}",
                "-e", f"TRACE_DIR={TRACE_MOUNT}", "-e", f"TRACE_PORT={TRACE_PORT}"]
        if "NO_PROXY=localhost,127.0.0.1" not in cmd:
            cmd += ["-e", "NO_PROXY=localhost,127.0.0.1", "-e", "no_proxy=localhost,127.0.0.1"]
        entry = ["python3", TRACE_PROXY_IN_BOX, "--exec"] + entry
    elif opts.llm_url:
        cmd += ["-e", f"LOCAL_LLM_URL={opts.llm_url}"]
    if opts.llm_model:
        cmd += ["-e", f"LOCAL_LLM_MODEL={opts.llm_model}"]
    if opts.llm_key:
        # No "=value": podman copies it from ITS env, so the secret never hits
        # argv (visible to every local user via `ps`).
        cmd += ["-e", "LOCAL_LLM_API_KEY"]
    if opts.oc_config:
        cmd += ["-e", f"OPENCODE_CONFIG_CONTENT={opts.oc_config}"]
    return cmd + [opts.image] + entry


LLM_KEYS = ("LOCAL_LLM_URL", "LOCAL_LLM_MODEL", "LOCAL_LLM_API_KEY")
LLM_ENV_TEMPLATE = """\
# vibebox LLM settings (KEY=VALUE). CLI flags beat host env vars, which beat this file.
# Keep it private: chmod 600. The key is never put on the podman command line.
#LOCAL_LLM_URL=https://api.scaleway.ai/v1
#LOCAL_LLM_MODEL=<model-id>
#LOCAL_LLM_API_KEY=<secret-key>
"""


def parse_llm_env(text):
    """KEY=VALUE lines -> dict of the LLM_KEYS present (comments/blanks/others ignored)."""
    vals = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if k.startswith("export "):
            k = k[7:].strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        if k in LLM_KEYS and v:
            vals[k] = v
    return vals


def resolve_llm(cli, environ, file_vals):
    """Per key: CLI flag > host env var > llm.env file. cli maps LLM_KEYS -> value/None."""
    return {k: cli.get(k) or environ.get(k) or file_vals.get(k, "") for k in LLM_KEYS}


def load_llm_env(path):
    """Read llm.env, creating a 0600 commented template if missing (never overwrites)."""
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(LLM_ENV_TEMPLATE)
    if os.name != "nt" and os.stat(path).st_mode & 0o044:
        print(f"vibebox: WARNING {path} is group/world-readable; run: chmod 600 {path}",
              file=sys.stderr)
    return parse_llm_env(Path(path).read_text(encoding="utf-8", errors="replace"))


# --- Model list: every chat model the endpoint serves, selectable via /models --- #

NON_CHAT = re.compile(r"embed|bge|whisper|ocr|rerank|tts|moderation|clip", re.I)
DEFAULT_LIMIT = {"context": 100000, "output": 8192}  # Scaleway rejects opencode's default output


def _model_context(entry):
    """Context window if the server reports one (vLLM max_model_len, llama.cpp
    meta.n_ctx_train, LM Studio/others context_length), else None."""
    for v in (entry.get("max_model_len"), entry.get("context_length"),
              (entry.get("meta") or {}).get("n_ctx_train")):
        if isinstance(v, int) and v > 0:
            return v
    return None


def parse_models(data):
    """GET /v1/models JSON -> [(id, context|None)] for chat models (embeddings,
    speech, OCR, rerankers dropped), in server order, de-duplicated."""
    out, seen = [], set()
    for e in (data or {}).get("data") or []:
        mid = e.get("id") if isinstance(e, dict) else None
        if not isinstance(mid, str) or not mid or mid in seen or NON_CHAT.search(mid):
            continue
        seen.add(mid)
        out.append((mid, _model_context(e)))
    return out


def opencode_models_config(models, default):
    """Inline config merged over opencode.json (OPENCODE_CONFIG_CONTENT): all listed
    models under provider `local`, `default` stays the selected model."""
    entries = {}
    for mid, ctx in models:
        limit = dict(DEFAULT_LIMIT)
        if ctx:
            limit["context"] = ctx
            limit["output"] = min(DEFAULT_LIMIT["output"], ctx // 4)
        entries[mid] = {"name": mid, "limit": limit}
    cfg = {"provider": {"local": {"models": entries}}}
    if default:
        cfg["model"] = f"local/{default}"
    return json.dumps(cfg, separators=(",", ":"))


def fetch_models(url, key, timeout=5):
    """List the endpoint's models from the host. Returns parse_models() or raises.
    The key only goes in the Authorization header, never in output."""
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    with urlopen(Request(url.rstrip("/") + "/models", headers=headers), timeout=timeout) as r:
        return parse_models(json.load(r))


def model_config(url, model, key):
    """(OPENCODE_CONFIG_CONTENT json or "", model count). Never raises: on any
    failure, one warning line and the single LOCAL_LLM_MODEL from opencode.json."""
    try:
        models = fetch_models(url, key)
    except Exception as e:
        reason = getattr(e, "code", None) or type(e).__name__
        print(f"vibebox: WARNING can't list models at {url}/models ({reason}); "
              f"only {model or 'the default model'} available", file=sys.stderr)
        return "", 0
    if not models:
        return "", 0
    return opencode_models_config(models, model), len(models)


# --- Install, image freshness, project-dir guard ---------------------------- #

def unsafe_workdir(path, home):
    """Refuse to mount / or the whole home dir (or anything above it)."""
    p, h = os.path.realpath(path), os.path.realpath(home)
    if p == os.path.dirname(p):
        return "/ (the filesystem root)"
    if p == h or h.startswith(p.rstrip(os.sep) + os.sep):
        return f"{p} (your home dir or above)"
    return ""


def resolve_ro(work, paths):
    """-ro arguments -> (list for Options.ro, error). [] = the whole folder read-only.
    Each path must be an existing directory INSIDE work (symlinks resolved, no ../ escapes)."""
    if paths is None:
        return None, ""
    w = os.path.realpath(work)
    subs = []
    for raw in paths:
        p = os.path.realpath(os.path.join(w, raw))
        if p == w:
            return [], ""                       # "-ro ." = everything read-only
        if not p.startswith(w + os.sep):
            return None, f"-ro {raw}: not inside {w}"
        if not os.path.isdir(p):
            return None, f"-ro {raw}: no such folder"
        rel = os.path.relpath(p, w)
        if rel not in subs:
            subs.append(rel)
    return subs, ""


def install(bin_dir=None, name="vibe"):
    """Symlink <bin_dir>/vibe -> this script (real path). Idempotent."""
    bin_dir = bin_dir or os.path.join(os.path.expanduser("~"), ".local", "bin")
    os.makedirs(bin_dir, exist_ok=True)
    target, link = os.path.realpath(__file__), os.path.join(bin_dir, name)
    os.chmod(target, os.stat(target).st_mode | 0o111)
    if os.path.islink(link) or os.path.exists(link):
        if os.path.realpath(link) == target:
            return link
        if not os.path.islink(link):
            raise FileExistsError(f"{link} exists and is not a symlink; not touching it")
        os.remove(link)
    os.symlink(target, link)
    return link


def image_hash(repo=None):
    """Hash of everything baked into the image (Containerfile, trace_proxy.py, opencode/)."""
    repo = repo or REPO
    h = hashlib.sha256()
    files = ["Containerfile", "trace_proxy.py"] + sorted(
        os.path.relpath(os.path.join(d, f), repo)
        for d, _, fs in os.walk(os.path.join(repo, "opencode")) for f in fs)
    for rel in files:
        h.update(rel.replace(os.sep, "/").encode() + b"\0")
        f = Path(repo, rel)
        h.update((f.read_bytes() if f.exists() else b"") + b"\0")
    return h.hexdigest()[:16]


def ensure_image(image):
    """Build (or rebuild when Containerfile/opencode/ changed) the default image."""
    if image != DEFAULT_IMAGE:
        return 0
    want = image_hash()
    got = subprocess.run(["podman", "image", "inspect", image, "--format",
                          '{{index .Config.Labels "vibebox.hash"}}'],
                         capture_output=True, text=True)
    if got.returncode == 0 and got.stdout.strip() == want:
        return 0
    why = "missing" if got.returncode else "out of date"
    print(f"vibebox: image {image} {why}; building from {REPO} (a few minutes)...",
          file=sys.stderr)
    return subprocess.run(["podman", "build", "--label", f"vibebox.hash={want}",
                           "-t", image, REPO]).returncode


# --- herdr (terminal workspace manager for agents) --------------------------- #

def herdr_metadata_args(pane, title, display, tokens):
    return ["pane", "report-metadata", pane, "--source", "user:vibe", "--agent", "opencode",
            "--title", title, "--display-agent", display] + \
           [a for k, v in tokens.items() for a in ("--token", f"{k}={v}")]


def herdr_report(environ, args, delay=0.0):
    """Best-effort, backgrounded `herdr <args>` when running inside a herdr pane."""
    hb = environ.get("HERDR_BIN_PATH")
    if environ.get("HERDR_ENV") != "1" or not hb or not environ.get("HERDR_PANE_ID"):
        return
    import threading

    def go():
        time.sleep(delay)
        try:
            subprocess.run([hb] + args, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass
    threading.Thread(target=go, daemon=True).start()


# --- I/O wrapper: resolves the host environment, then shells out to podman --- #

def _temp_root():
    return os.path.join(tempfile.gettempdir(), "vibebox")


def _ensure_network(name, internal=False):
    exists = subprocess.run(["podman", "network", "exists", name]).returncode == 0
    if exists and internal:
        # Pre-lockdown versions made this net WITH dns (aardvark forwards external
        # lookups = DNS exfil channel) and a random subnet. Recreate if so.
        out = subprocess.run(["podman", "network", "inspect", name, "--format",
                              "{{.DNSEnabled}} {{range .Subnets}}{{.Subnet}}{{end}}"],
                             capture_output=True, text=True).stdout.split()
        if out != ["false", INTERNAL_SUBNET]:
            subprocess.run(["podman", "rm", "-f", PROXY],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["podman", "network", "rm", name], check=True,
                           stdout=subprocess.DEVNULL)
            exists = False
    if not exists:
        args = ["podman", "network", "create"] + (INTERNAL_NET_ARGS if internal else []) + [name]
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def new_egress_log():
    """Fresh per-launch host log file the proxy appends to. World-writable because
    the proxy's uid 1000 maps to a subuid on the host; the 0700 dir keeps it private."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(LOG_DIR, time.strftime("egress-%Y%m%d-%H%M%S.log"))
    Path(path).touch()
    os.chmod(path, 0o666)
    return path


def project_name(work):
    return os.path.basename(os.path.normpath(work)) or "project"


def new_trace_dir(project):
    """Fresh per-launch host dir the in-box trace proxy writes into (0700; the box
    runs as the host uid via keep-id, so no world-writable perms needed)."""
    os.makedirs(TRACE_ROOT, mode=0o700, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", project) or "project"
    path = os.path.join(TRACE_ROOT, f"{safe}-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def latest_egress_log():
    try:
        logs = sorted(f for f in os.listdir(LOG_DIR) if f.startswith("egress-"))
    except OSError:
        return ""
    return os.path.join(LOG_DIR, logs[-1]) if logs else ""


def machine_resources():
    """Best-effort 'cpus=N ram=X.XGB' the box can use (the WSL VM caps these)."""
    try:
        out = subprocess.run(["podman", "info", "--format", "{{.Host.CPUs}} {{.Host.MemTotal}}"],
                             capture_output=True, text=True, timeout=10)
        cpus, mem = out.stdout.split()
        return f"cpus={cpus} ram={int(mem) / 1e9:.1f}GB"
    except Exception:
        return ""


def setup_allow_proxy(domains, image, log_file):
    _ensure_network(EGRESS)
    _ensure_network(INTERNAL, internal=True)
    troot = _temp_root()
    os.makedirs(troot, exist_ok=True)
    allow_file = os.path.join(troot, "allow.txt")
    Path(allow_file).write_text("\n".join(allowlist_regex_lines(domains)) + "\n",
                                encoding="ascii")
    conf = os.path.join(REPO, "tinyproxy.conf")
    subprocess.run(["podman", "rm", "-f", PROXY], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(build_proxy_command(image, allow_file, conf, log_file),
                   check=True, stdout=subprocess.DEVNULL)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="vibe", allow_abbrev=False,
        description="Run opencode in a locked-down podman box on the current dir. "
                    "Switch models inside opencode with /models.")
    p.add_argument("-sh", action="store_true",
                   help="bash shell instead of opencode (run 'opencode' inside)")
    p.add_argument("-opencode", action="store_true",
                   help="start opencode (the default when an LLM URL is configured)")
    p.add_argument("-net", nargs="+", default=None,
                   help="full | none | space/comma list of hosts/keywords (default: full; "
                        "with an LLM URL: only the LLM host)")
    p.add_argument("-ro", nargs="*", default=None, metavar="SUBDIR",
                   help="read-only: '-ro' alone = whole folder; '-ro docs data' = only "
                        "those subfolders, the rest stays writable")
    p.add_argument("-gpu", action="store_true")
    p.add_argument("-ram", default="")
    p.add_argument("-cpu", type=int, default=0)
    p.add_argument("-disk", default="")
    p.add_argument("-llm", default=None,
                   help="OpenAI-compatible base URL, e.g. http://100.x.y.z:8080/v1 "
                        f"(default: $LOCAL_LLM_URL, then {LLM_ENV})")
    p.add_argument("-model", default=None,
                   help=f"default model id (default: $LOCAL_LLM_MODEL, then {LLM_ENV})")
    p.add_argument("-image", default=DEFAULT_IMAGE)
    p.add_argument("-install", action="store_true",
                   help="symlink the 'vibe' command into ~/.local/bin and exit")
    p.add_argument("-clean", action="store_true", help="tear down all vibebox resources")
    p.add_argument("-stop-proxy", dest="stop_proxy", action="store_true")
    p.add_argument("-log", action="store_true",
                   help="print the most recent egress log (allowlist mode) and exit")
    p.add_argument("-trace", action="store_true",
                   help=f"log every LLM request/response to {TRACE_ROOT}/<project>-<time>/ "
                        "(learn what the harness sends the model)")
    p.add_argument("-trace-show", dest="trace_show", nargs="*", default=None,
                   metavar="DIR|N", help="summarise the latest (or given) trace; "
                                         "N = that call in full")
    args = p.parse_args(argv)

    if args.trace_show is not None:
        import trace_proxy
        return trace_proxy.show(args.trace_show, TRACE_ROOT)

    if args.install:
        try:
            link = install()
        except OSError as e:
            print(f"vibebox: install failed: {e}", file=sys.stderr)
            return 1
        on_path = os.path.dirname(link) in os.environ.get("PATH", "").split(os.pathsep)
        print(f"installed {link} -> {os.path.realpath(link)}"
              + ("" if on_path else f"\n(add {os.path.dirname(link)} to PATH)"))
        return 0

    if args.log:
        path = latest_egress_log()
        if not path:
            print(f"vibebox: no egress logs in {LOG_DIR}", file=sys.stderr)
            return 1
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        print(f"== {path}")
        for line in format_egress(text):
            print(line)
        print(egress_summary(text))
        return 0

    if args.stop_proxy:
        subprocess.run(["podman", "rm", "-f", PROXY])
        print("proxy removed")
        return 0
    if args.clean:
        for c in build_clean_commands(args.image):
            subprocess.run(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(_temp_root(), ignore_errors=True)
        print("vibebox: clean (machine + other projects untouched)")
        return 0

    work = os.getcwd()
    bad = unsafe_workdir(work, os.path.expanduser("~"))
    if bad:
        print(f"vibebox: refusing to mount {bad} into the box; "
              "cd into a project directory first", file=sys.stderr)
        return 2

    ro, err = resolve_ro(work, args.ro)
    if err:
        print(f"vibebox: {err}", file=sys.stderr)
        return 2

    cfg = resolve_llm({"LOCAL_LLM_URL": args.llm, "LOCAL_LLM_MODEL": args.model},
                      os.environ, load_llm_env(LLM_ENV))
    args.llm, model, key = cfg["LOCAL_LLM_URL"], cfg["LOCAL_LLM_MODEL"], cfg["LOCAL_LLM_API_KEY"]
    if not args.llm:
        print(f"vibebox: no LLM URL; set -llm, $LOCAL_LLM_URL or LOCAL_LLM_URL in {LLM_ENV}"
              " (starting a shell)", file=sys.stderr)
    # Default entry: opencode when an LLM is configured, else a shell.
    opencode = not args.sh and (args.opencode or bool(args.llm))
    llm = urlsplit(args.llm)
    llm_host = llm.hostname or ""
    if args.llm and not llm_host:
        print(f"vibebox: can't parse -llm URL {args.llm!r} "
              "(use e.g. http://100.x.y.z:8080/v1)", file=sys.stderr)
        return 2
    net, domains, unknown = resolve_net(args.net, opencode, llm_host)
    for u in unknown:
        print(f"vibebox: unknown -net '{u}' ignored (not a keyword or domain)", file=sys.stderr)
    tokens = [t.lower() for t in net]
    if llm_host and "none" in tokens:
        print("vibebox: -llm needs network but -net none is air-gapped; "
              "use -net full or add hosts to an allowlist", file=sys.stderr)
        return 2
    if ensure_image(args.image) != 0:
        print("vibebox: image build failed", file=sys.stderr)
        return 1
    oc_config, n_models = model_config(args.llm, model, key) if args.llm else ("", 0)
    trace_dir = ""
    if args.trace:
        if not args.llm:
            print("vibebox: -trace needs an LLM URL (-llm or llm.env)", file=sys.stderr)
            return 2
        trace_dir = new_trace_dir(project_name(work))
    log_file = ""
    if "none" not in tokens and "full" not in tokens:  # allow-list mode
        if llm_host and llm.scheme == "https" and llm.port not in (None, 443):
            print("vibebox: proxy only tunnels HTTPS on port 443; "
                  "use http:// or -net full for this -llm URL", file=sys.stderr)
        log_file = new_egress_log()
        setup_allow_proxy(domains, args.image, log_file)

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    project = project_name(work)
    host = re.sub(r"[^A-Za-z0-9-]", "-", project).strip("-") or "devbox"
    opts = Options(work=work, image=args.image, net=net, ram=args.ram,
                   cpu=args.cpu, disk=args.disk, gpu=args.gpu, interactive=interactive,
                   hostname=host, opencode=opencode, llm_url=args.llm,
                   llm_model=model, llm_key=bool(key), oc_config=oc_config,
                   trace_dir=trace_dir, ro=ro)
    cmd = build_podman_command(opts)
    res = machine_resources()
    entry = "opencode" if opencode else "shell (run 'opencode')"
    models = f" (+{n_models - 1} more: /models)" if n_models > 1 else ""
    print(f"vibe: {entry} | model={model or 'local'}{models} | net={net_mode(net)}")
    ro_note = "" if ro is None else (" (READ-ONLY)" if ro == [] else
                                     " (read-only: " + ", ".join(ro) + ")")
    print(f"      {work} -> /work{ro_note}{' | gpu' if args.gpu else ''}{' | ' + res if res else ''}"
          f"{' | log: ' + log_file if log_file else ''}"
          f"{' | trace: ' + trace_dir if trace_dir else ''}")
    env = dict(os.environ, LOCAL_LLM_API_KEY=key) if key else None
    herdr = opencode and os.environ.get("HERDR_ENV") == "1"
    if herdr:
        # herdr finds agents by the pane's foreground process (podman here); this
        # hint makes it read opencode's screen for idle/working/blocked state.
        env = dict(env or os.environ, HERDR_AGENT="opencode")
        reach = ", ".join(domains) if log_file else net_mode(net).split(" ")[0]
        herdr_report(os.environ, herdr_metadata_args(
            os.environ.get("HERDR_PANE_ID", ""),
            f"vibe {project} | {model or 'local'} | net: {reach}",
            f"vibe:{model or 'local'}",
            {"project": project, "model": model or "local", "net": reach}), delay=2)
    try:
        # The key reaches podman via its environment only (see -e LOCAL_LLM_API_KEY).
        return subprocess.run(cmd, env=env).returncode
    finally:
        if herdr:
            hb = os.environ.get("HERDR_BIN_PATH", "")
            try:
                subprocess.run([hb, "pane", "report-metadata", os.environ["HERDR_PANE_ID"],
                                "--source", "user:vibe", "--clear-title",
                                "--clear-display-agent", "--clear-token", "project",
                                "--clear-token", "model", "--clear-token", "net"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass
        if log_file and os.path.exists(log_file):
            text = Path(log_file).read_text(encoding="utf-8", errors="replace")
            print(f"vibebox: {egress_summary(text)}  [{log_file}]")
        if trace_dir:
            n = len([f for f in os.listdir(trace_dir) if f.endswith("-http.json")])
            print(f"vibebox: trace: {n} LLM call(s) in {trace_dir}  (view: vibe -trace-show)")


def _limit_args(opts):
    args = []
    if opts.ram:
        args += ["--memory", to_podman_size(opts.ram)]
    if opts.cpu:
        args += ["--cpus", str(opts.cpu)]
    if opts.disk:
        args += ["--storage-opt", f"size={to_podman_size(opts.disk).upper()}"]
    return args


INTERNAL = "vibe-internal"
EGRESS = "vibe-egress"
PROXY = "vibebox-proxy"
PROXY_PORT = 8080
# Internal net: no egress route AND no DNS (aardvark would forward arbitrary
# external lookups -> DNS exfil). So the proxy gets a fixed IP the box uses directly.
INTERNAL_SUBNET = "10.213.0.0/24"
PROXY_IP = "10.213.0.250"
INTERNAL_NET_ARGS = ["--internal", "--disable-dns", "--subnet", INTERNAL_SUBNET]
LOG_DIR = os.path.join(os.path.expanduser("~"), ".vibebox", "logs")
LLM_ENV = os.path.join(os.path.expanduser("~"), ".vibebox", "llm.env")
TRACE_ROOT = os.path.join(os.path.expanduser("~"), ".vibebox", "traces")
TRACE_MOUNT = "/trace"
TRACE_PORT = 4141
TRACE_PROXY_IN_BOX = "/usr/local/lib/vibebox/trace_proxy.py"  # see Containerfile
PROXY_LOG = "/var/log/vibebox/egress.log"  # must match LogFile in tinyproxy.conf

# Single source of truth for hardening — shared by the sandbox and the proxy.
HARDENING = ["--cap-drop=ALL", "--security-opt", "no-new-privileges"]

# Pinned seccomp: podman's default profile with the `syslog` syscall removed, so
# in-box code can't read the host kernel ring buffer (dmesg). Sandbox-only.
SECCOMP = os.path.join(REPO, "seccomp.json")


def build_proxy_command(image, allow_file, conf, log_file):
    """tinyproxy sidecar: bridges egress+internal nets (fixed IP on internal),
    hardened, allowlist mounted ro, request log written to a host file."""
    return [
        "podman", "run", "-d", "--name", PROXY,
        "--network", EGRESS, "--network", f"{INTERNAL}:ip={PROXY_IP}",
        *HARDENING,
        "-v", f"{allow_file}:/etc/tinyproxy/allow.txt:ro",
        "-v", f"{conf}:/etc/tinyproxy/tinyproxy.conf:ro",
        "-v", f"{log_file}:{PROXY_LOG}:rw",
        image, "tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf",
    ]


def build_clean_commands(image=DEFAULT_IMAGE):
    """Tear down ONLY vibebox-owned resources by name (no prune, no -a wildcard)."""
    return [
        ["podman", "rm", "-f", PROXY],
        ["podman", "network", "rm", INTERNAL],
        ["podman", "network", "rm", EGRESS],
        ["podman", "rmi", "-f", image],
    ]

NETMAP = {
    "duckduckgo": ["duckduckgo.com", "links.duckduckgo.com",
                   "html.duckduckgo.com", "lite.duckduckgo.com"],
    "github": ["github.com", "codeload.github.com",
               "objects.githubusercontent.com", "raw.githubusercontent.com"],
    "pypi": ["pypi.org", "files.pythonhosted.org"],
    "npm": ["registry.npmjs.org"],
}


def allowlist_regex_lines(domains):
    """Anchored, dot-boundary-safe filter lines (host or subdomain, never a
    lookalike suffix like 'example.com.attacker.io')."""
    return [r"(^|\.)" + re.escape(d) + r"$" for d in domains]


def expand_allowlist(tokens):
    """-net keywords/domains -> (allowed_domains, unknown_tokens). Unknowns are
    surfaced (not silently allowed); 'full'/'none' are modes, not hosts."""
    domains, unknown = [], []
    for t in tokens:
        t = t.lower()
        if t in ("full", "none"):
            continue
        if t in NETMAP:
            domains += NETMAP[t]
        elif "." in t:
            domains.append(t)
        else:
            unknown.append(t)
    seen = set()  # de-dup, preserve order
    domains = [d for d in domains if not (d in seen or seen.add(d))]
    return domains, unknown


def _network_args(net):
    tokens = [t.lower() for t in net]
    if "none" in tokens:
        return ["--network=none"]
    if "full" in tokens or not tokens:
        return []
    # allow-list mode: internal (no-egress, no-DNS) net; the proxy is the only way
    # out. --dns=none: no resolv.conf; the proxy resolves allowed hosts itself.
    proxy_url = f"http://{PROXY_IP}:{PROXY_PORT}"
    args = ["--network", INTERNAL, "--dns=none", "--add-host", f"{PROXY}:{PROXY_IP}"]
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        args += ["-e", f"{var}={proxy_url}"]
    return args + ["-e", "NO_PROXY=localhost,127.0.0.1", "-e", "no_proxy=localhost,127.0.0.1"]


def resolve_net(net_arg, opencode=False, llm_host=""):
    """-net tokens -> (net, allowed_domains, unknown). No -net + an LLM URL =
    locked down: allowlist of ONLY the LLM host. In any allowlist the LLM host is
    added automatically; an allowlist that ends up empty falls back to full."""
    if net_arg is None:
        if llm_host:
            return [llm_host], [llm_host], []
        net_arg = ["full"]
    # Flatten nargs list, splitting any element that itself holds a comma/space list.
    net = [t for chunk in net_arg for t in re.split(r"[ ,]+", chunk) if t]
    domains, unknown = expand_allowlist(net)
    tokens = [t.lower() for t in net]
    if tokens and "none" not in tokens and "full" not in tokens:  # allow-list mode
        if llm_host and llm_host not in domains:
            domains.append(llm_host)
        if not domains:
            print("vibebox: empty allowlist; using full network", file=sys.stderr)
            net = ["full"]
    return net, domains, unknown


def net_mode(net):
    """Human-readable effective network mode for the launch banner."""
    tokens = [t.lower() for t in net]
    if "none" in tokens:
        return "none (air-gapped)"
    if "full" in tokens or not tokens:
        return "FULL (unrestricted egress, not logged)"
    return f"allowlist [{', '.join(net)}] via proxy, no DNS, logged"


_REQ = re.compile(r"Request \(file descriptor \d+\): (\S+) (\S+)")
_DENY = re.compile(r'refused on filtered domain "([^"]+)"|Refused CONNECT method on port (\d+)')


def _req_host(method, target):
    if method.upper() == "CONNECT":
        return target                       # host:port (HTTPS shows host only)
    u = urlsplit(target)
    return f"{u.hostname}:{u.port or 80}" if u.hostname else target


def format_egress(text):
    """Request + refusal lines from the tinyproxy log; blocked ones marked DENIED."""
    out = []
    for line in text.splitlines():
        if _DENY.search(line):
            out.append("DENIED  " + line.strip())
        elif _REQ.search(line):
            out.append("        " + line.strip())
    return out


def egress_summary(text):
    """One line: hosts the box asked for, and how many requests were denied."""
    hosts, denied = [], 0
    for line in text.splitlines():
        m = _REQ.search(line)
        if m:
            h = _req_host(*m.groups())
            if h not in hosts:
                hosts.append(h)
        if _DENY.search(line):
            denied += 1
    return f"egress: {len(hosts)} host(s) requested [{', '.join(hosts)}], {denied} denied"


if __name__ == "__main__":
    sys.exit(main())
