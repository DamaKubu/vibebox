import pytest
from vibebox import (Options, build_podman_command, expand_allowlist,
                     to_podman_size, build_clean_commands, build_proxy_command,
                     allowlist_regex_lines, patch_install_method)


def cmd(**kw):
    opts = Options(work="/home/me/proj", **kw)
    return build_podman_command(opts)


# --- Cycle 1: tracer bullet -------------------------------------------------

def test_default_run_is_hardened():
    c = cmd()
    assert c[0] == "podman" and c[1] == "run"
    assert "--rm" in c
    assert "--cap-drop=ALL" in c
    # no-new-privileges passed as a --security-opt pair
    assert "no-new-privileges" in c
    assert "--userns=keep-id" in c


# --- Cycle 2: network 'none' is air-gapped ----------------------------------

def test_net_none_is_airgapped():
    c = cmd(net=["none"])
    assert "--network=none" in c
    assert not any("PROXY" in a for a in c)  # no proxy env injected


# --- Cycle 3: allowlist mode routes through the proxy only -------------------

def test_net_allow_routes_through_proxy_only():
    c = cmd(net=["pypi", "claude"])
    i = c.index("--network")
    assert c[i + 1] == "vibe-internal"          # internal = no direct egress
    assert any(a.startswith("HTTP_PROXY=") for a in c)
    assert any(a.startswith("HTTPS_PROXY=") for a in c)
    assert "--network=none" not in c            # not air-gapped


def test_net_full_has_no_proxy_and_no_isolation():
    c = cmd(net=["full"])
    assert "--network=none" not in c
    assert "vibe-internal" not in c
    assert not any("PROXY" in a for a in c)      # plain default bridge


# --- Cycle 4: allowlist expansion -------------------------------------------

def test_expand_allowlist_keywords_domains_and_unknown():
    domains, unknown = expand_allowlist(["pypi", "claude", "example.com", "frobnicate"])
    assert "pypi.org" in domains and "files.pythonhosted.org" in domains
    assert "api.anthropic.com" in domains        # 'claude' keyword
    assert "example.com" in domains              # raw domain passes through
    assert "frobnicate" in unknown               # unknown reported, NOT allowed
    assert "frobnicate" not in domains


# --- Cycle 5: size parsing --------------------------------------------------

def test_to_podman_size_conversions():
    assert to_podman_size("5GB") == "5g"
    assert to_podman_size("512MB") == "512m"
    assert to_podman_size("2g") == "2g"
    assert to_podman_size("1 GB") == "1g"


def test_to_podman_size_rejects_garbage():
    with pytest.raises(ValueError):
        to_podman_size("banana")


# --- Cycle 6: resource limits gating ----------------------------------------

def test_limits_applied_when_set():
    c = cmd(ram="5GB", cpu=5, disk="10GB")
    assert c[c.index("--memory") + 1] == "5g"
    assert c[c.index("--cpus") + 1] == "5"
    assert c[c.index("--storage-opt") + 1] == "size=10G"


def test_no_limits_by_default():
    c = cmd()
    assert "--memory" not in c
    assert "--cpus" not in c
    assert "--storage-opt" not in c


# --- Cycle 7: GPU gating ----------------------------------------------------

def test_gpu_device_only_when_requested():
    assert not any("nvidia" in a for a in cmd())
    c = cmd(gpu=True)
    assert c[c.index("--device") + 1] == "nvidia.com/gpu=all"


# --- Cycle 8: entrypoint ----------------------------------------------------

def test_entry_shell_default_and_claude_switch():
    assert cmd()[-1] == "bash"
    c = cmd(claude=True)
    assert c[-2:] == ["claude", "--dangerously-skip-permissions"]


# --- Cycle 9: credential mounts (security: only work + creds are mounted) ----

def mounts_of(c):
    return [c[i + 1] for i, a in enumerate(c) if a == "-v"]


def test_only_work_mounted_by_default():
    assert mounts_of(cmd()) == ["/home/me/proj:/work:rw"]


def test_creds_mounts_are_files_not_the_whole_dir():
    # Mount only the credential FILES, never the whole ~/.claude dir, so the
    # image's baked-in skills + statusline are not shadowed.
    m = mounts_of(cmd(creds_home="/tmp/vbx/home-1"))
    assert "/home/me/proj:/work:rw" in m
    assert "/tmp/vbx/home-1/.claude.json:/home/vibe/.claude.json:rw" in m
    assert "/tmp/vbx/home-1/.claude/.credentials.json:/home/vibe/.claude/.credentials.json:rw" in m
    assert "/tmp/vbx/home-1/.claude:/home/vibe/.claude:rw" not in m  # NOT the dir
    assert len(m) == 3


# --- Cycle 10: negative-security invariant (everything-on kitchen sink) ------

def test_never_contains_dangerous_escapes():
    c = cmd(net=["pypi", "claude"], gpu=True, ram="5GB", cpu=5, disk="10GB",
            claude=True, creds_home="/tmp/vbx/home-9")
    assert "--privileged" not in c
    blob = "\n".join(c)
    assert "podman.sock" not in blob
    assert "docker.sock" not in blob
    assert "/var/run" not in blob
    # every bind mount lands under /work or /home/vibe — never host root, /etc, etc.
    for mnt in mounts_of(c):
        _src, target, _mode = mnt.rsplit(":", 2)
        assert target.startswith("/work") or target.startswith("/home/vibe")
    # hardening flags survive even with every feature enabled
    assert "--cap-drop=ALL" in c and "no-new-privileges" in c and "--userns=keep-id" in c


# --- Cycle 16: tty gating (scriptable when not attached to a terminal) -------

def test_interactive_default_allocates_tty():
    assert "-it" in cmd()


def test_non_interactive_drops_tty():
    c = cmd(interactive=False)
    assert "-it" not in c
    assert "-t" not in c
    assert "-i" in c            # stdin stays open for piped payloads


# --- Cycle 11: teardown safety ----------------------------------------------

def test_clean_only_targets_vibebox_resources():
    cmds = build_clean_commands(image="vibebox:latest")
    flat = [" ".join(c) for c in cmds]
    assert any("rmi" in f and "vibebox:latest" in f for f in flat)
    assert any("network rm vibe-internal" in f for f in flat)
    assert any("network rm vibe-egress" in f for f in flat)
    assert any("rm -f vibebox-proxy" in f for f in flat)
    blob = "\n".join(flat)
    assert "machine" not in blob          # never deletes the shared VM
    assert "prune" not in blob            # never blanket-prunes
    assert " -a" not in blob              # no rmi -a / wipe-all


# --- Cycle 12: proxy command (bridges egress<->internal, hardened) -----------

def test_proxy_bridges_both_networks_and_is_hardened():
    c = build_proxy_command(image="vibebox:latest",
                            allow_file="/tmp/allow.txt",
                            conf="/x/tinyproxy.conf")
    assert c[:3] == ["podman", "run", "-d"]
    assert "--cap-drop=ALL" in c and "no-new-privileges" in c
    nets = [c[i + 1] for i, a in enumerate(c) if a == "--network"]
    assert "vibe-egress" in nets and "vibe-internal" in nets
    binds = [c[i + 1] for i, a in enumerate(c) if a == "-v"]
    assert "/tmp/allow.txt:/etc/tinyproxy/allow.txt:ro" in binds   # read-only
    assert "tinyproxy" in c


# --- Cycle 13: allowlist regex is anchored + subdomain-safe ------------------

def test_allowlist_regex_anchored_and_escaped():
    lines = allowlist_regex_lines(["api.anthropic.com"])
    assert lines == [r"(^|\.)api\.anthropic\.com$"]


def test_allowlist_regex_blocks_lookalike_suffix():
    import re
    pat = re.compile(allowlist_regex_lines(["anthropic.com"])[0])
    assert pat.search("api.anthropic.com")             # real subdomain ok
    assert pat.search("anthropic.com")                 # apex ok
    assert not pat.search("anthropic.com.attacker.io") # lookalike blocked
    assert not pat.search("evilanthropic.com")         # prefix-glued blocked


# --- Cycle 14: API-key auth path --------------------------------------------

def test_api_key_passed_as_env():
    c = cmd(api_key="sk-ant-xyz")
    assert "ANTHROPIC_API_KEY=sk-ant-xyz" in c


def test_no_api_key_env_by_default():
    assert not any("ANTHROPIC_API_KEY" in a for a in cmd())


# --- Cycle 15: /doctor install-method patch ---------------------------------

def test_patch_install_method_native_to_npm():
    out = patch_install_method('{"installMethod": "native", "x": 1}')
    assert out == '{"installMethod": "npm-global", "x": 1}'


def test_patch_install_method_idempotent_when_already_npm():
    s = '{"installMethod": "npm-global"}'
    assert patch_install_method(s) == s

