# vibebox

A project-independent Podman sandbox. `cd` into any idea, launch, and vibe with
an agent **inside** the container — the host filesystem outside the current
folder is invisible, and the network mode is fixed by whoever launches it.

## What's protected
- **Filesystem:** only `$PWD` is mounted (`/work`). Host home, other projects,
  SSH keys, secrets — none of it is visible inside.
- **Network:** you choose `full` / `none` / an `allow`-list at launch. The agent
  inside has dropped caps, no podman socket, no new privileges — it **cannot
  change the network mode** you set.
- **Privilege:** runs as non-root uid 1000, `--cap-drop=ALL`,
  `--security-opt no-new-privileges`.

Because the container is the boundary, the agent runs with
`--dangerously-skip-permissions` — no in-app prompts, full freedom, contained.

## One-time build
```powershell
podman build -t vibebox:latest -f vibebox/Containerfile vibebox
```

## Use
The launcher is a single portable Python script — same command on Windows, Linux,
and macOS. It drops you into a `bash` shell by default; run
`claude --dangerously-skip-permissions` inside (or pass `-claude`) to start the agent.
```bash
cd /path/to/new-idea
python C:\Users\IT Logika\documents\projects\vibebox\vibebox.py            # shell, full internet
python C:\...\vibebox.py -claude                                          # straight into the agent
python C:\...\vibebox.py -net none                                        # air-gapped
python C:\...\vibebox.py -net claude,pypi -ram 5GB                        # allowlist + limits
python C:\...\vibebox.py -net claude -creds -claude                       # safe combo: agent, login mounted, egress locked
```

Make it a one-word command. **PowerShell** (`notepad $PROFILE`):
```powershell
function vibebox { python "C:\Users\IT Logika\documents\projects\vibebox\vibebox.py" @args }
```
**bash/zsh** (`~/.bashrc` / `~/.zshrc`):
```bash
vibebox() { python /path/to/vibebox/vibebox.py "$@"; }
```
Then just `vibebox` from any project dir.

## Auth
**Credentials are not put in the box by default** — you opt in.
- **API key:** set `$env:ANTHROPIC_API_KEY` on the host; it's passed through (no flag needed).
- **Subscription/OAuth:** pass `-creds` to copy your host `~/.claude.json` login into a
  throwaway per-process home and mount it. Without it (and without a key), claude
  prompts you to log in inside the box.
- **No flag, no key:** no credentials in the box at all.

> ⚠️ **Read this before using `-creds` or an API key.** The container protects your
> *host filesystem*, not the credential you hand *in*. Anything running inside the box
> (the agent runs `--dangerously-skip-permissions`, so it freely executes untrusted
> code) can read that token, and with full egress can send it anywhere. **If you mount
> a credential, lock the network: `-net claude`** — then the token has nowhere to go but
> Anthropic. Better still, use a **scoped, revocable** `ANTHROPIC_API_KEY` so a leak
> costs capped API spend, not your account. `-net full` + creds = exfiltration-ready.

## Network modes
| `-net`            | effect | when |
|-------------------|--------|------|
| `full`            | default bridge, full egress | normal vibing (pip/npm/git/API just work) |
| `none`            | `--network=none`, air-gapped | offline compute, max safety |
| comma list        | allowlisted egress (proxy) | only the named hosts reachable |

For the allowlist, pass a comma-separated list of keywords/domains, e.g.
`-net claude,pypi,github`. Keywords expand to known host sets
(`claude`, `duckduckgo`, `github`, `pypi`, `npm`); anything containing a `.` is
treated as a raw domain. The sandbox is forced onto an internal (no-egress)
network and its only way out is a hardened tinyproxy sidecar that CONNECT-filters
on host (no TLS interception, no CA needed). Tear it down with `-stop-proxy`.
