# vibebox — project-independent sandbox for vibing with agents inside Podman.
# Polyglot dev tools + the Claude Code CLI. The container IS the safety boundary,
# so the agent runs with in-app permission prompts skipped (--dangerously-skip-
# permissions, set by the launcher) — it can do anything it likes, but only to
# the single mounted project dir, with whatever network the invoker granted.
#
# Build:  podman build -t vibebox:latest -f vibebox/Containerfile vibebox

FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        python3 python3-pip python3-venv \
        ripgrep \
        build-essential \
        ca-certificates curl less jq \
        tinyproxy \
    && rm -rf /var/lib/apt/lists/*

# The agent itself, runnable in-container. Start it with
#   claude --dangerously-skip-permissions
# (safe here — the container is the boundary).
RUN npm install -g @anthropic-ai/claude-code

# The container is ephemeral (--rm) and runs as uid 1000, which can't write the
# root-owned npm prefix — so the in-box auto-updater only ever fails with a nag.
# The image is the source of truth: update by rebuilding, not in place. Disable it.
ENV DISABLE_AUTOUPDATER=1

# Non-root: claude refuses --dangerously-skip-permissions as root, and uid 1000
# pairs with `podman run --userns=keep-id` so files in /work stay host-owned.
# The node base image already ships a uid-1000 user; drop it before reusing the id.
RUN userdel -r node 2>/dev/null || true; useradd -m -u 1000 vibe

# Bake in agent skills (tdd, grill-me, codecard, grill-with-docs) and the
# context status bar. Lives at ~/.claude so claude auto-discovers it; the
# launcher mounts only the credential FILES so this dir is never shadowed.
COPY claude-home/ /home/vibe/.claude/
RUN chown -R 1000:1000 /home/vibe/.claude

USER 1000:1000
WORKDIR /work

# Land in a shell by default; run `claude --dangerously-skip-permissions` to start the agent.
CMD ["bash"]
