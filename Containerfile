# vibebox — simple, secure, project-independent sandbox for running the opencode
# agent against a local LLM inside Podman. The container IS the safety boundary:
# opencode runs with every permission set to "allow" (opencode/opencode.json),
# but only the single mounted project dir is visible, with whatever network the
# invoker granted. No Node/npm in the image (only opencode's plugin SDK, below).
#
# Build:  automatic (vibe builds/rebuilds it, labelled with a hash of this file
#         + opencode/), or by hand: podman build -t vibebox:latest .
# Also used (same image) for the allowlist proxy sidecar: `tinyproxy` below.

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        python3 python3-pip python3-venv \
        ripgrep fd-find tree file \
        build-essential \
        ca-certificates curl wget less jq \
        unzip zip xz-utils patch \
        procps sqlite3 nano openssh-client \
        tinyproxy \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*

# uv: fast Python package/venv manager (pip on bookworm refuses system installs).
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /usr/local/bin/

# opencode: standalone binary from the official GitHub release (Bun is bundled),
# pinned. glibc build; the "baseline" variant for CPUs without AVX2, same rule as
# the official install script (decided on the build host's CPU).
ARG OPENCODE_VERSION=1.19.5
RUN set -eu; \
    case "$(uname -m)" in \
        x86_64)  arch=x64; grep -qw avx2 /proc/cpuinfo || arch=x64-baseline ;; \
        aarch64) arch=arm64 ;; \
        *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/oc.tgz \
        "https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-${arch}.tar.gz"; \
    tar -xzf /tmp/oc.tgz -C /usr/local/bin opencode; \
    chmod 755 /usr/local/bin/opencode; rm /tmp/oc.tgz; \
    /usr/local/bin/opencode --version

# Python diagnostics without node: Astral's ty (Rust) as opencode's LSP. Tool env
# lives outside $HOME so the uid-1000 user sees it; binary lands on PATH.
ARG TY_VERSION=0.0.99
RUN UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin \
        uv tool install "ty==${TY_VERSION}" \
    && rm -rf /root/.cache/uv \
    && ty --version

# Language servers are preinstalled (ty), so never try to download others.
ENV OPENCODE_DISABLE_LSP_DOWNLOAD=true
# No phoning home. opencode names verified in the 1.19.5 linux-x64 binary:
# models.dev catalogue fetch, self-update, npm install of default auth plugins.
ENV OPENCODE_DISABLE_MODELS_FETCH=true \
    OPENCODE_DISABLE_AUTOUPDATE=true \
    OPENCODE_DISABLE_DEFAULT_PLUGINS=true

# LLM defaults for opencode.json's {env:...} placeholders (substituted as raw text
# before JSON parse, so they work in the model key too). Harmless for llama.cpp;
# the launcher overrides them (the API key by name only, never on argv).
ENV LOCAL_LLM_MODEL=local \
    LOCAL_LLM_API_KEY=local

# Non-root uid 1000 pairs with `podman run --userns=keep-id` so files in /work
# stay host-owned.
RUN useradd -m -u 1000 vibe

# opencode: global config (local OpenAI-compatible model, all permissions
# allowed, ty LSP) + global AGENTS.md (work autonomously, no needless questions).
COPY opencode/ /home/vibe/.config/opencode/
RUN chown -R 1000:1000 /home/vibe/.config

USER 1000:1000
WORKDIR /work

# opencode installs @opencode-ai/plugin (its plugin SDK, pinned to its own
# version) into every config dir on startup, from registry.npmjs.org. Do it once
# here so runs don't try npm (the allowlist proxy would deny it). `debug wait`
# loads the config, which starts that install; stop once it has landed.
RUN set -eu; cd /tmp; dir=/home/vibe/.config/opencode; \
    opencode debug wait >/dev/null 2>&1 & pid=$!; \
    for i in $(seq 90); do \
        [ -f "$dir/package-lock.json" ] && [ -f "$dir/node_modules/@opencode-ai/plugin/package.json" ] && break; \
        sleep 1; \
    done; sleep 2; kill $pid 2>/dev/null || true; \
    test -f "$dir/node_modules/@opencode-ai/plugin/package.json"; \
    rm -rf /home/vibe/.local/share/opencode /home/vibe/.local/state/opencode

# Trace mode (`vibe -trace`): a stdlib logging reverse proxy the launcher starts
# in front of opencode (trace_proxy.py --exec opencode). Last, so editing it
# only rebuilds this layer.
COPY trace_proxy.py /usr/local/lib/vibebox/trace_proxy.py

# The launcher picks the entry (opencode, or bash with `vibe -sh`).
CMD ["bash"]
