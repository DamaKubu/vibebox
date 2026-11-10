# vibebox

A simple, secure Podman sandbox for running the [opencode](https://opencode.ai)
agent against a **local LLM**. `cd` into any project, launch, and let the agent
work **inside** the container — the host filesystem outside the current folder is
invisible, no credentials are put in the box, and the network mode is fixed by
whoever launches it (locked to just the LLM host by default).

## Quick start
```bash
python3 vibebox.py -install        # once: puts a `vibe` command in ~/.local/bin
$EDITOR ~/.vibebox/llm.env         # once: LOCAL_LLM_URL / LOCAL_LLM_MODEL / LOCAL_LLM_API_KEY
cd ~/some/project && vibe          # opencode in the box; builds the image if needed
```
`vibe -sh` gives a bash shell instead, `vibe -log` shows what the box tried to reach.
**Switch models inside opencode with `/models`**: at launch vibe asks the endpoint
for `GET <LOCAL_LLM_URL>/models` and offers every chat model (embedding, speech,
OCR and rerank models are left out); `LOCAL_LLM_MODEL` is the default. If the list
can't be fetched you get a one-line warning and just the default model.
vibe refuses to run in `$HOME` or `/`, so your whole home dir is never mounted.

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

Because the container is the boundary, opencode runs with every permission set to
`allow` — no in-app prompts, full freedom, contained.

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
an agent is often **more** willing to run things freely when it knows it's safely
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

## Image build
Automatic: `vibe` builds `vibebox:latest` on first use and rebuilds it whenever
the `Containerfile`, `trace_proxy.py` or `opencode/` changes (it labels the image
with a hash of them). By hand: `podman build -t vibebox:latest .`
The image is `debian:bookworm-slim` + apt dev tools + uv + the standalone opencode
binary (pinned, Bun bundled) + `ty` for Python diagnostics. **No Node/npm.**
opencode installs its plugin SDK (`@opencode-ai/plugin`) into its config dir on
every start; the build does that once so runs never call `registry.npmjs.org`.

### Updating
The container is **ephemeral** (`--rm`) and the **image is the source of truth**:
bump `OPENCODE_VERSION` / `TY_VERSION` in the `Containerfile` and rebuild. opencode's
self-update is disabled in the box.

## Use
The launcher is a single portable Python script (`vibe` after `-install`; on
Windows run `python vibebox.py ...`). With an LLM configured it starts opencode;
without one, or with `-sh`, you get a `bash` shell.
```bash
cd /path/to/new-idea
vibe                                                # opencode, only the LLM host reachable
vibe -sh                                            # bash shell (run `opencode` inside)
vibe -llm http://100.x.y.z:8080/v1 -net pypi -ram 5GB   # other LLM, + pypi, limits
vibe -sh -net none                                  # air-gapped shell (no LLM)
vibe -ro                                            # whole folder read-only (review, explain)
vibe -ro docs data/raw                              # only these subfolders read-only, rest writable
```
Other flags: `-model ID`, `-gpu`, `-cpu N`, `-disk 10GB`, `-log`, `-stop-proxy`, `-clean`.

### Trace mode (learn how the agent works)
`vibe -trace` records every call opencode makes to the model; `vibe -trace-show`
explains them. You see the system prompt, the tools array (JSON schemas), the
messages, the model's `tool_calls`, the tool results sent back and the streamed
chunks. That is the whole agent loop: **the model asks for a tool, the harness
runs it, the result goes back as a `tool` message, repeat until the model answers
without tool calls.**
```bash
vibe -trace                       # banner shows: trace: ~/.vibebox/traces/<project>-<time>
vibe -trace-show                  # summary of the latest trace, one block per call
vibe -trace-show 3                # call 3 in full: whole prompt, schemas, messages
vibe -trace-show <dir> [N]        # an older trace
```
How: the image carries `trace_proxy.py` (stdlib only). With `-trace` it starts in
the box on `127.0.0.1:4141` before opencode, opencode's `LOCAL_LLM_URL` points at it,
and it forwards each request to the real URL (`TRACE_UPSTREAM`) through the usual
egress proxy. Streams pass through chunk by chunk. The egress log still shows only
the LLM host. Per call `NNN` in the trace dir (mounted at `/trace`, not in `/work`):
`NNN-request.json` (request body), `NNN-response.sse` (raw stream),
`NNN-response.json` (assembled reply: text, tool calls with parsed args,
`finish_reason`, usage) and `NNN-http.json` (status, timing, headers with the
`Authorization` value redacted). Traces contain your prompts and code; delete them
when you're done. The box can write to its trace dir.

### herdr
Inside a [herdr](https://herdr.dev) pane, `vibe` marks the pane as an opencode
agent (`HERDR_AGENT=opencode` on the podman process, so herdr reads opencode's
idle/working/blocked state from the screen) and reports display metadata: name
`vibe:<model>`, title `vibe <project> | <model> | net: <host>`, and tokens
`project`, `model`, `net` you can use in herdr's sidebar rows. It is cleared on
exit. The model shown is the launch default; opencode's own terminal title
(`OC | <session title>`) doesn't include the model, so a `/models` switch isn't
reflected. Outside herdr nothing is sent.

## opencode + local model
opencode is preconfigured for a local OpenAI-compatible server (llama.cpp `llama-server`, Ollama, ...) — typically on
another machine on your LAN or tailnet. Build once (same command as above), then:
```bash
vibe -llm http://100.x.y.z:8080/v1             # llama-server
vibe -llm http://100.x.y.z:11434/v1            # Ollama
vibe -llm http://100.x.y.z:8080/v1 -net pypi,npm   # allowlist: LLM host auto-added
```
`-llm` sets `LOCAL_LLM_URL` and `-model` sets `LOCAL_LLM_MODEL` in the box. Each
falls back to the host env var, then to `~/.vibebox/llm.env` (see below).
Config lives in `opencode/opencode.json` (baked to `~/.config/opencode/`): provider
`local`, model `local/{env:LOCAL_LLM_MODEL}`; the launcher adds the rest of the
endpoint's models through `OPENCODE_CONFIG_CONTENT` (inline JSON opencode merges
over its config), each with `limit: {context: 100000, output: 8192}` (Scaleway
rejects opencode's larger default output; a server-reported context such as
llama.cpp's `n_ctx_train` is used when present) (opencode substitutes `{env:...}` as
raw text, so it works in the model key; the image defaults it to `local`), all
permissions `allow`, so the box is the boundary.
Python diagnostics come from Astral's `ty` (Rust, configured under `lsp`); the
built-in `pyright`/`typescript` servers are disabled and LSP downloads are off.
- **Listen on the LAN**, not loopback: `llama-server --host 0.0.0.0 ...` /
  `OLLAMA_HOST=0.0.0.0 ollama serve`.
- **Use the Tailscale 100.x IP**, not the MagicDNS name — it may not resolve
  inside the container.
- **Ollama:** the model id must be a real tag: `-model qwen2.5-coder:32b`.
  llama-server serves one model and ignores the id.
- **Network:** any LLM URL (flag, env or llm.env) with no `-net` is **locked down**: the only
  reachable host is the LLM server. `-net full` lifts that; `-net none` is refused;
  any other allowlist gets the LLM host added (plain `http://` works on any port;
  `https://` only on 443).

### Hosted provider (Scaleway)
Any OpenAI-compatible API works the same way. For
[Scaleway Generative APIs](https://www.scaleway.com/en/docs/generative-apis/) the
base URL is `https://api.scaleway.ai/v1` and the IAM **secret key** is sent as
`Authorization: Bearer <key>`. A Managed Inference deployment uses its own
endpoint URL instead (`https://<deployment-id>.ifr.fr-par.scaleway.com/v1`).
1. The first launch creates `~/.vibebox/llm.env` (mode 0600, commented template).
   Fill it in:
   ```ini
   LOCAL_LLM_URL=https://api.scaleway.ai/v1
   LOCAL_LLM_MODEL=<model-id>
   LOCAL_LLM_API_KEY=<secret-key>
   ```
2. `vibe`. The box is locked to `api.scaleway.ai:443`.

Precedence per key: CLI flag > host env var > file. The launcher warns if the file
is group/world-readable. The key is never printed and never put on the podman
command line (which `ps` shows): podman gets `-e LOCAL_LLM_API_KEY` by name and
copies the value from its own environment. Without a key the image default `local`
is used, which llama.cpp/Ollama ignore.

vibe lists these for you inside opencode (`/models`). By hand:
```bash
curl -s https://api.scaleway.ai/v1/models -H "Authorization: Bearer $SCW_SECRET_KEY" | jq -r '.data[].id'
```
**Privacy:** unlike a local model, every prompt, including the code and files the
agent reads, goes to the provider. Check their data-retention terms before using
it on code you can't share.

### What leaves the box
- **Locked down / allowlist:** the box sits on an internal network with no route
  out and **no DNS** (`--disable-dns` network + `--dns=none`, so DNS can't be used
  to tunnel data out). The only way out is the proxy, at a fixed IP. Tools that
  ignore `HTTP_PROXY` just fail. Allowed hosts are the only destinations, but
  **anything can be sent to them**, including your code: that's the LLM's job.
- **Egress log:** every proxied request is written to
  `~/.vibebox/logs/egress-<time>.log` (host:port for HTTPS, the full URL for plain
  HTTP), including blocked ones. The banner shows the path. On exit you get a
  one-line summary (hosts requested, number denied). `vibe -log` prints the
  latest log with blocked lines marked `DENIED`.
- **`-net full`:** unrestricted and **not logged**.
- **No phoning home:** the image sets `OPENCODE_DISABLE_MODELS_FETCH`,
  `OPENCODE_DISABLE_AUTOUPDATE`, `OPENCODE_DISABLE_DEFAULT_PLUGINS` and
  `OPENCODE_DISABLE_LSP_DOWNLOAD`. `opencode.json` has `share: disabled`.

**Default tools in the image:** git, python3 (+pip, venv), uv/uvx, ty,
build-essential (gcc/make), ripgrep, fd, tree, file, curl, wget, jq, less, nano,
unzip/zip, xz, patch, procps, sqlite3, openssh-client, opencode.

**Node/npm is not included** (it kept the image ~2.6x bigger). If a project needs
JS, add it per project — e.g. download a Node tarball into `/work` with
`-net full` (or allowlist `nodejs.org,npm`), or build a derived image
`FROM vibebox:latest` that installs it.


## Credentials
None by default. The box gets no logins from the host. The only things passed in
are `LOCAL_LLM_URL`, `LOCAL_LLM_MODEL` and, if you configured a hosted provider,
`LOCAL_LLM_API_KEY`. The agent can read that key, so use a scoped key you can revoke. Remember the agent can still send your code to any host you
allowlist — that's the LLM's job — so keep `-net` tight.

## Network modes
| `-net`            | effect | when |
|-------------------|--------|------|
| `full`            | default bridge, full egress | normal vibing (pip/git just work) |
| `none`            | `--network=none`, air-gapped | offline compute, max safety |
| comma list        | allowlisted egress (proxy) | only the named hosts reachable |

For the allowlist, pass a comma-separated list of keywords/domains, e.g.
`-net pypi,github`. Keywords expand to known host sets
(`duckduckgo`, `github`, `pypi`, `npm`); anything containing a `.` is
treated as a raw domain. The sandbox is forced onto an internal (no-egress)
network and its only way out is a hardened tinyproxy sidecar that CONNECT-filters
on host (no TLS interception, no CA needed). Tear it down with `-stop-proxy`.
The box gets no DNS in this mode; the proxy resolves allowed names itself.
