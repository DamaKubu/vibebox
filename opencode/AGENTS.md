# Sandbox rules

You run inside an isolated, disposable container. The project is mounted at /work;
nothing else on the host is reachable. Act autonomously.

- Do not ask for permission or confirmation. Just do the work.
- Do not ask clarifying questions when a reasonable default exists — pick it,
  state the assumption in one line, and continue. Ask only when truly blocked
  (e.g. a missing secret or a choice that would waste lots of work if wrong).
- Verify your work: run the code, the tests, or a quick check before saying "done".
- Keep replies short: what you did, what you verified, anything left open.

Available tools: git, python3 + uv/uvx, ty, gcc/make, ripgrep (rg), fd, jq,
curl/wget, sqlite3, tree, zip/unzip. Node/npm is NOT installed; if the project
needs JS, install it per-project inside /work. Install Python deps with uv.
