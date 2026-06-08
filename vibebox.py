"""Portable (Windows + Linux) launcher for the vibebox podman sandbox.
Security-critical logic is pure (build_podman_command, expand_allowlist, ...) and
unit-tested; main() is the thin I/O wrapper that shells out to podman."""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


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
    image: str = "vibebox:latest"
    net: List[str] = field(default_factory=lambda: ["full"])
    ram: str = ""
    cpu: int = 0
    disk: str = ""
    gpu: bool = False
    claude: bool = False
    creds_home: str = ""  # temp home with throwaway .claude.json + .claude/
    api_key: str = ""     # if set, passed as ANTHROPIC_API_KEY instead of creds
    interactive: bool = True  # tty; False = scriptable (piped stdin)


def build_podman_command(opts):
    cmd = [
        "podman", "run", "--rm",
        "-it" if opts.interactive else "-i",
        "-v", f"{opts.work}:/work:rw",
        "-w", "/work",
        "--userns=keep-id",
    ] + HARDENING
    cmd += _network_args(opts.net)
    cmd += _limit_args(opts)
    if opts.gpu:
        cmd += ["--device", "nvidia.com/gpu=all"]
    if opts.api_key:
        cmd += ["-e", f"ANTHROPIC_API_KEY={opts.api_key}"]
    elif opts.creds_home:
        # Mount only the credential FILES so the image's baked-in ~/.claude isn't shadowed.
        h = opts.creds_home
        cmd += ["-v", f"{h}/.claude.json:/home/vibe/.claude.json:rw"]
        cmd += ["-v", f"{h}/.claude/.credentials.json:/home/vibe/.claude/.credentials.json:rw"]
    entry = ["claude", "--dangerously-skip-permissions"] if opts.claude else ["bash"]
    cmd += [opts.image] + entry
    return cmd


# --- I/O wrapper: resolves the host environment, then shells out to podman --- #

def _temp_root():
    return os.path.join(tempfile.gettempdir(), "vibebox")


def _ensure_network(name, internal=False):
    if subprocess.run(["podman", "network", "exists", name]).returncode != 0:
        args = ["podman", "network", "create"] + (["--internal"] if internal else []) + [name]
        subprocess.run(args, check=True)


def machine_resources():
    """Best-effort 'cpus=N ram=X.XGB' the box can use (the WSL VM caps these)."""
    try:
        out = subprocess.run(["podman", "info", "--format", "{{.Host.CPUs}} {{.Host.MemTotal}}"],
                             capture_output=True, text=True, timeout=10)
        cpus, mem = out.stdout.split()
        return f"cpus={cpus} ram={int(mem) / 1e9:.1f}GB"
    except Exception:
        return ""


def resolve_credentials(mount_login=False):
    """(api_key, creds_home, cleanup_dir). ANTHROPIC_API_KEY passes through if set.
    The host ~/.claude.json login is copied in ONLY when mount_login (-creds): a
    mounted credential is readable+exfiltratable by in-box code, so it's opt-in."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key, "", None
    if not mount_login:
        print("vibebox: no credentials in box -- pass -creds to mount your host "
              "login (and pair it with -net claude), or log in inside.", file=sys.stderr)
        return "", "", None
    host_json = Path.home() / ".claude.json"
    host_cred = Path.home() / ".claude" / ".credentials.json"
    if not host_json.exists():
        print("vibebox: -creds given but no ~/.claude.json found -- "
              "claude will ask you to log in inside the box.", file=sys.stderr)
        return "", "", None
    home = os.path.join(_temp_root(), f"home-{os.getpid()}")
    shutil.rmtree(home, ignore_errors=True)
    os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
    text = host_json.read_text(encoding="utf-8-sig", errors="replace")
    Path(os.path.join(home, ".claude.json")).write_text(
        patch_install_method(text), encoding="utf-8")
    if host_cred.exists():
        shutil.copyfile(host_cred, os.path.join(home, ".claude", ".credentials.json"))
    return "", home, home


def setup_allow_proxy(domains, image):
    _ensure_network(EGRESS)
    _ensure_network(INTERNAL, internal=True)
    troot = _temp_root()
    os.makedirs(troot, exist_ok=True)
    allow_file = os.path.join(troot, "allow.txt")
    Path(allow_file).write_text("\n".join(allowlist_regex_lines(domains)) + "\n",
                                encoding="ascii")
    conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tinyproxy.conf")
    subprocess.run(["podman", "rm", "-f", PROXY], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(build_proxy_command(image, allow_file, conf), check=True, stdout=subprocess.DEVNULL)


def main(argv=None):
    p = argparse.ArgumentParser(prog="vibebox", allow_abbrev=False)
    p.add_argument("-net", nargs="+", default=["full"],
                   help="full | none | space/comma list of hosts/keywords")
    p.add_argument("-gpu", action="store_true")
    p.add_argument("-ram", default="")
    p.add_argument("-cpu", type=int, default=0)
    p.add_argument("-disk", default="")
    p.add_argument("-claude", action="store_true", help="run the agent instead of a shell")
    p.add_argument("-creds", action="store_true",
                   help="mount your host Claude login (exfiltratable -- pair with -net claude)")
    p.add_argument("-image", default="vibebox:latest")
    p.add_argument("-clean", action="store_true", help="tear down all vibebox resources")
    p.add_argument("-stop-proxy", dest="stop_proxy", action="store_true")
    args = p.parse_args(argv)

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

    # Flatten nargs list, splitting any element that itself holds a comma/space list.
    net = [t for chunk in args.net for t in re.split(r"[ ,]+", chunk) if t]
    domains, unknown = expand_allowlist(net)
    for u in unknown:
        print(f"vibebox: unknown -net '{u}' ignored (not a keyword or domain)", file=sys.stderr)

    tokens = [t.lower() for t in net]
    if tokens and "none" not in tokens and "full" not in tokens:  # allow-list mode
        if not domains:
            print("vibebox: empty allowlist; using full network", file=sys.stderr)
            net = ["full"]
        else:
            setup_allow_proxy(domains, args.image)

    api_key, creds_home, cleanup = resolve_credentials(args.creds)
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    opts = Options(work=os.getcwd(), image=args.image, net=net, ram=args.ram,
                   cpu=args.cpu, disk=args.disk, gpu=args.gpu, claude=args.claude,
                   creds_home=creds_home, api_key=api_key, interactive=interactive)
    cmd = build_podman_command(opts)
    res = machine_resources()
    print(f"vibebox: net={' '.join(net)}{' | gpu' if args.gpu else ''}"
          f"{' | ' + res if res else ''} | {opts.work} -> /work")
    if not args.claude:
        print("         (run 'claude --dangerously-skip-permissions' inside to start the agent)")
    try:
        return subprocess.run(cmd).returncode
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


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

# Single source of truth for hardening — shared by the sandbox and the proxy.
HARDENING = ["--cap-drop=ALL", "--security-opt", "no-new-privileges"]


def build_proxy_command(image, allow_file, conf):
    """tinyproxy sidecar: bridges egress+internal nets, hardened, allowlist mounted ro."""
    return [
        "podman", "run", "-d", "--name", PROXY,
        "--network", EGRESS, "--network", INTERNAL,
        *HARDENING,
        "-v", f"{allow_file}:/etc/tinyproxy/allow.txt:ro",
        "-v", f"{conf}:/etc/tinyproxy/tinyproxy.conf:ro",
        image, "tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf",
    ]


def build_clean_commands(image="vibebox:latest"):
    """Tear down ONLY vibebox-owned resources by name (no prune, no -a wildcard)."""
    return [
        ["podman", "rm", "-f", PROXY],
        ["podman", "network", "rm", INTERNAL],
        ["podman", "network", "rm", EGRESS],
        ["podman", "rmi", "-f", image],
    ]

NETMAP = {
    "claude": ["api.anthropic.com", "statsig.anthropic.com"],
    "duckduckgo": ["duckduckgo.com", "links.duckduckgo.com",
                   "html.duckduckgo.com", "lite.duckduckgo.com"],
    "github": ["github.com", "codeload.github.com",
               "objects.githubusercontent.com", "raw.githubusercontent.com"],
    "pypi": ["pypi.org", "files.pythonhosted.org"],
    "npm": ["registry.npmjs.org"],
}


def patch_install_method(text):
    """Rewrite host .claude.json install method 'native' -> 'npm-global' (raw text,
    no JSON parse: host configs can have duplicate keys) to silence the /doctor nag."""
    return re.sub(r'"installMethod":(\s*)"native"',
                  r'"installMethod":\1"npm-global"', text)


def allowlist_regex_lines(domains):
    """Anchored, dot-boundary-safe filter lines (host or subdomain, never a
    lookalike suffix like 'anthropic.com.attacker.io')."""
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
    # allow-list mode: internal (no-egress) net; the proxy is the only way out.
    proxy_url = f"http://{PROXY}:{PROXY_PORT}"
    return [
        "--network", INTERNAL,
        "-e", f"HTTP_PROXY={proxy_url}",
        "-e", f"HTTPS_PROXY={proxy_url}",
        "-e", "NO_PROXY=localhost,127.0.0.1",
    ]


if __name__ == "__main__":
    sys.exit(main())
