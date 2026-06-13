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
- **Privilege:** runs as non-root uid 1000, `--cap-drop=ALL` (zero capabilities),
  `--security-opt no-new-privileges`, plus a pinned **seccomp** profile.
- **Kernel:** with no capabilities, in-box code can't load modules, mount, create
  device nodes, touch `/dev/mem`, or write `/proc/sys` — the host kernel can't be
  modified. The seccomp profile (`seccomp.json`) is Podman's default with the
  `syslog` syscall removed, so `dmesg` can't read the host kernel ring buffer.

Because the container is the boundary, the agent runs with
`--dangerously-skip-permissions` — no in-app prompts, full freedom, contained.

### Blending in (cosmetic)
The agent tends to spot the sandbox from the first thing it looks at — a hex
container-id hostname, or `container=podman` in the environment — and then narrates
"I'm running in a container" instead of just getting on with the work. vibebox
quiets the two loudest signals: it sets a neutral `--hostname` (your project folder
name) and blanks the `container=podman` env var.

**This is cosmetic, not a security control. A determined agent will still figure it
out; this just stops it being the first thing it notices.** The boundary's strength
comes from the dropped capabilities, seccomp, and read-only kernel surfaces above —
*not* from being undetectable. Tells that remain, and that can't be hidden cheaply:

| Tell | Why it stays |
|------|--------------|
| `uname -r` → `...-microsoft-standard-WSL2` | containers share the host kernel; there's no separate kernel to rename |
| PID 1 is `bash` | a real host boots an init (`systemd`); we run a shell as pid 1 |
| `CapEff: 0000…0` | zero capabilities is itself a fingerprint of a locked-down container |
| seccomp filter active (`Seccomp: 2`) | the syscall filter we *want* is observable in `/proc/self/status` |
| `/run/.containerenv` exists | Podman writes this marker; removing it would mean fighting the runtime |

So treat detectability as a UX detail, not a defense. And note it can cut both ways:
Claude is often **more** willing to run things freely when it knows it's safely
contained, and more cautious when it thinks it's on a real machine — so hiding the
box too well can work against the "just vibe" goal. The middle ground here (don't
announce it loudly, don't fake `uname`) is deliberate.

## Install Podman
The launcher shells out to `podman`, so you need it once.
- **Windows:** `winget install RedHat.Podman-Desktop` (or `RedHat.Podman` for CLI
  only), then initialise + start the backing Linux VM:
  ```powershell
  podman machine init
  podman machine start
  ```
- **macOS:** `brew install podman` then the same `podman machine init/start`.
- **Linux:** `sudo apt install podman` (or your distro's package) — runs natively,
  no VM.

### Resources (Windows/macOS: mind the VM)
On Windows/macOS the container runs inside a Linux VM (WSL2 on Windows), and **that
VM — not your hardware — caps what the box can use.** vibebox prints the ceiling at
launch, e.g. `cpus=4 ram=7.8GB`. To raise it on Windows, create
`%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
memory=16GB
processors=8
```
then `wsl --shutdown` and `podman machine stop; podman machine start`.

## One-time build
```powershell
podman build -t vibebox:latest -f vibebox/Containerfile vibebox
```

### Updating the agent
The container is **ephemeral** (`--rm`) and the **image is the source of truth**, so
you update Claude Code by rebuilding the image — just re-run the build above. The
in-box auto-updater is disabled on purpose (`DISABLE_AUTOUPDATER=1`): it runs as a
non-root user that can't write npm's global prefix, so it could only ever fail with a
nag, and any update it did manage would vanish when the `--rm` container exits.

## Use
The launcher is a single portable Python script — same command on Windows, Linux,
and macOS. It drops you into a `bash` shell by default; run
`claude --dangerously-skip-permissions` inside (or pass `-claude`) to start the agent.
```bash
cd /path/to/new-idea
python C:\path\to\vibebox\vibebox.py            # shell, full internet
python C:\...\vibebox.py -claude                                          # straight into the agent
python C:\...\vibebox.py -net none                                        # air-gapped
python C:\...\vibebox.py -net claude,pypi -ram 5GB                        # allowlist + limits
python C:\...\vibebox.py -net claude -creds -claude                       # safe combo: agent, login mounted, egress locked
```


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
