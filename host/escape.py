#!/usr/bin/env python3
"""vibe-off: a short-lived pass to leave Claude Code's sandbox without being asked.

    vibe-off             3 exits, at most 10 minutes
    vibe-off 5           next 5 exits (still max 10 minutes)
    vibe-off 15m         any number of exits for 15 minutes
    vibe-off 1h          any number of exits for 1 hour
    vibe-off off         end the pass now

How: your ask rule "Bash(dangerouslyDisableSandbox:true)" is what makes every exit
ask you. A pass removes that rule; hooks put it back when the pass is used up or
expired, and at the start of every new session. Only YOU grant passes (type it with
`!` or in a terminal): a hook refuses any agent command that mentions vibe-escape
or the pass file. While a pass is active, auto mode's classifier still judges exits.

Hook entry points (wired by `vibe -setup-claude`): hook-pre, hook-post, session-start.
"""
import json, os, re, sys, time

CLAUDE = os.path.join(os.path.expanduser("~"), ".claude")
SETTINGS = os.path.join(CLAUDE, "settings.json")
PASS = os.path.join(CLAUDE, "escape-pass.json")
RULE = "Bash(dangerouslyDisableSandbox:true)"
MAX_SECONDS = 600


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save_settings(cfg):
    tmp = SETTINGS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    os.replace(tmp, SETTINGS)


def set_rule(present):
    cfg = _load(SETTINGS, {})
    ask = cfg.setdefault("permissions", {}).setdefault("ask", [])
    if present and RULE not in ask:
        ask.insert(0, RULE)
    elif not present and RULE in ask:
        ask.remove(RULE)
    else:
        return
    _save_settings(cfg)


def restore(why):
    set_rule(True)
    if os.path.exists(PASS):
        os.remove(PASS)
        print(f"vibe-escape: pass ended ({why}); sandbox exits ask you again", file=sys.stderr)


def active_pass():
    p = _load(PASS, None)
    if not p:
        return None
    if time.time() > p["until"] or p.get("left", 1) <= 0:
        restore("expired" if time.time() > p["until"] else "used up")
        return None
    return p


def grant(arg):
    if arg == "off":
        restore("ended by you")
        return
    left, seconds = 3, MAX_SECONDS
    if arg and arg[-1] in "mh":
        left, seconds = 10**6, int(arg[:-1]) * (60 if arg[-1] == "m" else 3600)
    elif arg:
        left = int(arg)
    with open(PASS, "w", encoding="utf-8") as f:
        json.dump({"left": left, "until": time.time() + seconds}, f)
    set_rule(False)
    what = f"{seconds // 60} min" if left == 10**6 else f"{left} exit(s), max {seconds // 60} min"
    print(f"vibe-escape: pass granted: {what}. Ends by itself; `vibe-off off` to end now.")


def hook_pre():
    data = _load_stdin()
    cmd = json.dumps(data.get("tool_input", {}))
    if re.search(r"vibe-escape|vibe-off|escape-pass|escape\.py", cmd):   # agents can't grant passes
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "Only the user can grant sandbox escape passes."}}))
        return
    active_pass()                    # expire by time before the permission check


def hook_post():
    data = _load_stdin()
    if not data.get("tool_input", {}).get("dangerouslyDisableSandbox"):
        return
    p = active_pass()
    if p and p.get("left", 0) < 10**6:
        p["left"] -= 1
        with open(PASS, "w", encoding="utf-8") as f:
            json.dump(p, f)
        active_pass()                # restores the rule when it hits 0


def status():
    p = _load(PASS, None)
    if not p or time.time() > p["until"]:
        return
    mins = max(0, int((p["until"] - time.time()) // 60))
    left = "" if p["left"] >= 10**6 else f"{p['left']} left, "
    print(f"escape pass: {left}{mins}m", end="")


def session_start():
    # /compact also fires SessionStart: same session, so keep the pass
    if _load_stdin().get("source") != "compact":
        restore("new session")


def _load_stdin():
    try:
        return json.load(sys.stdin)
    except ValueError:
        return {}


if __name__ == "__main__":
    a = sys.argv[1:] or [""]
    {"hook-pre": hook_pre, "hook-post": hook_post, "status": status,
     "session-start": session_start}.get(a[0], lambda: grant(a[0]))()
