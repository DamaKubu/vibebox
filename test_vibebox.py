import os
import re
import stat
from pathlib import Path

import pytest
from vibebox import (parse_llm_env, resolve_llm,
                     Options, build_podman_command, expand_allowlist,
                     to_podman_size, build_clean_commands, build_proxy_command,
                     allowlist_regex_lines, resolve_net,
                     net_mode, egress_summary, format_egress, PROXY_IP,
                     INTERNAL_NET_ARGS)


@pytest.fixture(autouse=True)
def _isolate_llm_config(monkeypatch, tmp_path):
    """Never read/create the real ~/.vibebox/llm.env or inherit host LLM vars."""
    import vibebox
    monkeypatch.setattr(vibebox, "LLM_ENV", str(tmp_path / "cfg" / "llm.env"))
    for k in vibebox.LLM_KEYS + ("HERDR_ENV",):
        monkeypatch.delenv(k, raising=False)


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
    c = cmd(net=["pypi", "github"])
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
    domains, unknown = expand_allowlist(["pypi", "github", "example.com", "frobnicate"])
    assert "pypi.org" in domains and "files.pythonhosted.org" in domains
    assert "github.com" in domains               # 'github' keyword
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

def test_entry_shell_default_and_opencode_switch():
    assert cmd()[-1] == "bash"
    assert cmd(opencode=True)[-1] == "opencode"


def test_claude_is_gone():
    assert "claude" not in expand_allowlist(["claude"])[0] and \
        expand_allowlist(["claude"])[1] == ["claude"]   # no longer a preset
    import vibebox
    for flag in ("-claude", "-creds"):
        with pytest.raises(SystemExit):
            vibebox.main([flag])


# --- Cycle 9: mounts (security: only the project dir is mounted) ------------

def mounts_of(c):
    return [c[i + 1] for i, a in enumerate(c) if a == "-v"]


def test_only_work_mounted_by_default():
    assert mounts_of(cmd()) == ["/home/me/proj:/work:rw"]


# --- Cycle 10: negative-security invariant (everything-on kitchen sink) ------

def test_never_contains_dangerous_escapes():
    c = cmd(net=["pypi", "github"], gpu=True, ram="5GB", cpu=5, disk="10GB",
            opencode=True, llm_url="http://100.64.0.5:8080/v1")
    assert "--privileged" not in c
    blob = "\n".join(c)
    assert "podman.sock" not in blob
    assert "docker.sock" not in blob
    assert "/var/run" not in blob
    # the project dir is the ONLY bind mount
    assert mounts_of(c) == ["/home/me/proj:/work:rw"]
    # hardening flags survive even with every feature enabled
    assert "--cap-drop=ALL" in c and "no-new-privileges" in c and "--userns=keep-id" in c


# --- Cycle 17: seccomp + blend-in (block dmesg, shave loudest container tells) -

def test_seccomp_profile_and_blend_flags():
    c = cmd(hostname="myproj")
    # custom seccomp profile (default minus syslog) is applied to the sandbox
    assert any(a.startswith("seccomp=") and a.endswith("seccomp.json") for a in c)
    # neutral hostname instead of the hex container id
    assert c[c.index("--hostname") + 1] == "myproj"
    # podman's container=podman tell is blanked
    assert "container=" in c


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
                            conf="/x/tinyproxy.conf",
                            log_file="/home/me/.vibebox/logs/egress-1.log")
    assert c[:3] == ["podman", "run", "-d"]
    assert "--cap-drop=ALL" in c and "no-new-privileges" in c
    nets = [c[i + 1] for i, a in enumerate(c) if a == "--network"]
    assert "vibe-egress" in nets
    assert f"vibe-internal:ip={PROXY_IP}" in nets   # fixed IP: box needs no DNS
    binds = [c[i + 1] for i, a in enumerate(c) if a == "-v"]
    assert "/tmp/allow.txt:/etc/tinyproxy/allow.txt:ro" in binds   # read-only
    assert "/home/me/.vibebox/logs/egress-1.log:/var/log/vibebox/egress.log:rw" in binds
    assert "tinyproxy" in c


# --- Cycle 13: allowlist regex is anchored + subdomain-safe ------------------

def test_allowlist_regex_anchored_and_escaped():
    lines = allowlist_regex_lines(["api.example.com"])
    assert lines == [r"(^|\.)api\.example\.com$"]


def test_allowlist_regex_blocks_lookalike_suffix():
    import re
    pat = re.compile(allowlist_regex_lines(["example.com"])[0])
    assert pat.search("api.example.com")             # real subdomain ok
    assert pat.search("example.com")                 # apex ok
    assert not pat.search("example.com.attacker.io") # lookalike blocked
    assert not pat.search("evilexample.com")         # prefix-glued blocked


# --- Cycle 18: opencode entry + local LLM URL --------------------------------

def test_opencode_entry_and_llm_env():
    c = cmd(opencode=True, llm_url="http://100.64.0.5:8080/v1")
    assert c[-1] == "opencode"
    assert "LOCAL_LLM_URL=http://100.64.0.5:8080/v1" in c


def test_no_llm_env_by_default():
    assert not any("LOCAL_LLM_URL" in a for a in cmd())


def test_llm_with_net_none_is_refused():
    import vibebox
    assert vibebox.main(["-net", "none", "-llm", "http://100.64.0.5:8080/v1"]) == 2


def _fake_host(monkeypatch, tmp_path):
    """Stub every podman/host side effect of main(); returns (calls, proxy_seen)."""
    import vibebox
    seen, ran = {}, []
    monkeypatch.setattr(vibebox, "LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setattr(vibebox, "setup_allow_proxy",
                        lambda domains, image, log_file: seen.update(domains=list(domains),
                                                                     log=log_file))
    monkeypatch.setattr(vibebox, "machine_resources", lambda: "")
    monkeypatch.setattr(vibebox, "ensure_image", lambda image: 0)
    monkeypatch.setattr(vibebox, "fetch_models", lambda url, key: [])
    def fake_run(c, **kw):
        ran.append(c)
        ran_env.append(kw.get("env"))
        return type("R", (), {"returncode": 0})()
    ran_env = []
    monkeypatch.setattr(vibebox.subprocess, "run", fake_run)
    monkeypatch.setattr(vibebox, "_last_env", ran_env, raising=False)
    return ran, seen


def test_llm_host_auto_added_to_allowlist(monkeypatch, tmp_path):
    import vibebox
    ran, seen = _fake_host(monkeypatch, tmp_path)
    vibebox.main(["-net", "pypi", "-opencode", "-llm", "http://100.64.0.5:8080/v1"])
    assert "100.64.0.5" in seen["domains"] and "pypi.org" in seen["domains"]
    assert ran[-1][-1] == "opencode"
    assert "LOCAL_LLM_URL=http://100.64.0.5:8080/v1" in ran[-1]


def test_llm_url_falls_back_to_host_env(monkeypatch, tmp_path):
    import vibebox
    monkeypatch.setenv("LOCAL_LLM_URL", "http://gpu-box:11434/v1")
    ran, seen = _fake_host(monkeypatch, tmp_path)
    vibebox.main(["-opencode"])
    assert "LOCAL_LLM_URL=http://gpu-box:11434/v1" in ran[-1]
    assert seen["domains"] == ["gpu-box"]          # locked down to the LLM host


# --- Cycle 19: opencode lockdown default + no-DNS allowlist + egress log -----

def test_opencode_with_llm_defaults_to_llm_only_allowlist():
    net, domains, unknown = resolve_net(None, opencode=True, llm_host="100.64.0.5")
    assert domains == ["100.64.0.5"] and not unknown   # no presets, just the LLM
    assert "full" not in net and "none" not in net


def test_default_net_stays_full_without_opencode_or_llm():
    assert resolve_net(None)[0] == ["full"]
    assert resolve_net(None, opencode=True)[0] == ["full"]          # no LLM url
    assert resolve_net(None, llm_host="100.64.0.5")[0] == ["100.64.0.5"]  # plain shell is locked too


def test_explicit_net_overrides_opencode_lockdown():
    assert resolve_net(["full"], opencode=True, llm_host="h")[0] == ["full"]
    net, domains, _ = resolve_net(["npm"], opencode=True, llm_host="gpu-box")
    assert domains == ["registry.npmjs.org", "gpu-box"]


def test_net_mode_banner_is_explicit():
    assert net_mode(["full"]).startswith("FULL")
    assert net_mode(["none"]).startswith("none")
    assert "100.64.0.5" in net_mode(["100.64.0.5"]) and "allowlist" in net_mode(["x.io"])


def test_allowlist_box_has_no_dns_and_uses_proxy_ip():
    c = cmd(net=["100.64.0.5"])
    assert "--dns=none" in c                        # no resolv.conf: no DNS exfil
    assert f"HTTP_PROXY=http://{PROXY_IP}:8080" in c
    assert f"https_proxy=http://{PROXY_IP}:8080" in c  # lowercase too (curl)
    assert "--dns=none" not in cmd() and "--dns=none" not in cmd(net=["none"])


def test_internal_network_is_created_without_dns():
    assert "--internal" in INTERNAL_NET_ARGS and "--disable-dns" in INTERNAL_NET_ARGS


def test_main_wires_fresh_log_file_into_proxy(monkeypatch, tmp_path, capsys):
    import vibebox
    ran, seen = _fake_host(monkeypatch, tmp_path)
    vibebox.main(["-opencode", "-llm", "http://100.64.0.5:8080/v1"])
    assert seen["log"].startswith(str(tmp_path / "logs" / "egress-"))
    out = capsys.readouterr().out
    assert seen["log"] in out and "allowlist" in out   # banner shows path + mode


LOG = """\
CONNECT   Nov 06 17:00:01.000 [7]: Request (file descriptor 7): CONNECT api.example.com:443 HTTP/1.1
CONNECT   Nov 06 17:00:02.000 [7]: Request (file descriptor 8): POST http://100.64.0.5:8080/v1/chat/completions HTTP/1.1
CONNECT   Nov 06 17:00:03.000 [7]: Request (file descriptor 9): CONNECT pastebin.com:443 HTTP/1.1
NOTICE    Nov 06 17:00:03.000 [7]: Proxying refused on filtered domain "pastebin.com"
"""


def test_egress_summary_and_denied_marker():
    s = egress_summary(LOG)
    assert "100.64.0.5:8080" in s and "pastebin.com:443" in s and "1 denied" in s
    lines = format_egress(LOG)
    assert [l for l in lines if l.startswith("DENIED")] == [
        'DENIED  NOTICE    Nov 06 17:00:03.000 [7]: Proxying refused on filtered domain "pastebin.com"']
    assert len(lines) == 4


# --- Cycle 20: hosted provider (llm.env, -model, API key off argv) ----------

def _write_env(text, mode=0o600):
    import vibebox
    os.makedirs(os.path.dirname(vibebox.LLM_ENV), exist_ok=True)
    Path(vibebox.LLM_ENV).write_text(text)
    os.chmod(vibebox.LLM_ENV, mode)


def test_parse_llm_env_ignores_comments_and_unknown_keys():
    v = parse_llm_env("# c\nLOCAL_LLM_URL=https://api.scaleway.ai/v1\n"
                      "export LOCAL_LLM_MODEL='m-1'\nOTHER=x\n#LOCAL_LLM_API_KEY=<k>\n")
    assert v == {"LOCAL_LLM_URL": "https://api.scaleway.ai/v1", "LOCAL_LLM_MODEL": "m-1"}


def test_precedence_cli_beats_env_beats_file():
    f = {"LOCAL_LLM_URL": "f-url", "LOCAL_LLM_MODEL": "f-model", "LOCAL_LLM_API_KEY": "f-key"}
    e = {"LOCAL_LLM_URL": "e-url", "LOCAL_LLM_MODEL": "e-model"}
    r = resolve_llm({"LOCAL_LLM_URL": "c-url", "LOCAL_LLM_MODEL": None}, e, f)
    assert r == {"LOCAL_LLM_URL": "c-url", "LOCAL_LLM_MODEL": "e-model",
                 "LOCAL_LLM_API_KEY": "f-key"}


def test_template_created_0600_and_never_overwritten(monkeypatch, tmp_path):
    import vibebox
    _fake_host(monkeypatch, tmp_path)
    vibebox.main([])
    st = os.stat(vibebox.LLM_ENV)
    assert stat.S_IMODE(st.st_mode) == 0o600
    text = Path(vibebox.LLM_ENV).read_text()
    assert "#LOCAL_LLM_API_KEY=" in text and parse_llm_env(text) == {}
    _write_env("LOCAL_LLM_URL=http://mine/v1\n")
    vibebox.main([])
    assert Path(vibebox.LLM_ENV).read_text() == "LOCAL_LLM_URL=http://mine/v1\n"


def test_missing_url_points_at_config_file(monkeypatch, tmp_path, capsys):
    import vibebox
    _fake_host(monkeypatch, tmp_path)
    vibebox.main(["-opencode"])
    assert vibebox.LLM_ENV in capsys.readouterr().err


def test_readable_config_warns(monkeypatch, tmp_path, capsys):
    import vibebox
    _fake_host(monkeypatch, tmp_path)
    _write_env("LOCAL_LLM_URL=http://h/v1\n", mode=0o644)
    vibebox.main([])
    assert "group/world-readable" in capsys.readouterr().err


def test_api_key_never_on_argv_or_stdout(monkeypatch, tmp_path, capsys):
    import vibebox
    ran, seen = _fake_host(monkeypatch, tmp_path)
    _write_env("LOCAL_LLM_URL=https://api.scaleway.ai/v1\n"
               "LOCAL_LLM_MODEL=qwen3-coder\nLOCAL_LLM_API_KEY=s3cr3t-key\n")
    vibebox.main(["-opencode"])
    c = ran[-1]
    assert not any("s3cr3t-key" in a for a in c)
    i = c.index("LOCAL_LLM_API_KEY")                # bare name: podman inherits
    assert c[i - 1] == "-e"
    assert "LOCAL_LLM_MODEL=qwen3-coder" in c
    assert vibebox._last_env[-1]["LOCAL_LLM_API_KEY"] == "s3cr3t-key"
    out = capsys.readouterr()
    assert "s3cr3t-key" not in out.out + out.err
    assert "model=qwen3-coder" in out.out
    assert seen["domains"] == ["api.scaleway.ai"]   # LLM-only allowlist


def test_model_flag_and_no_key_passthrough_by_default(monkeypatch, tmp_path):
    import vibebox
    ran, _ = _fake_host(monkeypatch, tmp_path)
    monkeypatch.setenv("LOCAL_LLM_MODEL", "from-env")
    vibebox.main(["-opencode", "-llm", "http://h:8080/v1", "-model", "from-cli"])
    assert "LOCAL_LLM_MODEL=from-cli" in ran[-1]
    assert not any(a.startswith("LOCAL_LLM_API_KEY") for a in ran[-1])  # image default
    assert vibebox._last_env[-1] is None


def test_allowlist_matches_exactly_the_https_llm_host():
    _, domains, _ = resolve_net(None, opencode=True, llm_host="api.scaleway.ai")
    rx = re.compile(allowlist_regex_lines(domains)[0])
    assert rx.search("api.scaleway.ai")
    assert not rx.search("scaleway.ai") and not rx.search("api.scaleway.ai.evil.io")


# --- Cycle 21: all endpoint models in opencode, `vibe` entry, home guard -----

MODELS = {"object": "list", "data": [
    {"id": "llama-3.3-70b-instruct"}, {"id": "bge-multilingual-gemma2"},
    {"id": "qwen3.6-35b-a3b"}, {"id": "whisper-large-v3"}, {"id": "qwen3-embedding-8b"},
    {"id": "lightonocr-3-0.8b"}, {"id": "bge-reranker"}, {"id": "gpt-oss-120b"},
    {"id": "qwen3.6-35b-a3b"}, {"no-id": 1}, "junk",
    {"id": "llama-cpp", "meta": {"n_ctx_train": 32768}},
]}


def test_parse_models_keeps_chat_models_only():
    from vibebox import parse_models
    assert parse_models(MODELS) == [("llama-3.3-70b-instruct", None), ("qwen3.6-35b-a3b", None),
                                    ("gpt-oss-120b", None), ("llama-cpp", 32768)]
    assert parse_models({}) == [] and parse_models(None) == []


def test_opencode_models_config_limits_and_default():
    import json
    from vibebox import opencode_models_config, parse_models
    cfg = json.loads(opencode_models_config(parse_models(MODELS), "llama-3.3-70b-instruct"))
    models = cfg["provider"]["local"]["models"]
    assert set(models) == {"llama-3.3-70b-instruct", "qwen3.6-35b-a3b", "gpt-oss-120b", "llama-cpp"}
    assert models["gpt-oss-120b"]["limit"] == {"context": 100000, "output": 8192}
    assert models["llama-cpp"]["limit"] == {"context": 32768, "output": 8192}
    assert cfg["model"] == "local/llama-3.3-70b-instruct"


def test_model_list_reaches_opencode_via_env(monkeypatch, tmp_path, capsys):
    import vibebox
    ran, _ = _fake_host(monkeypatch, tmp_path)
    monkeypatch.setattr(vibebox, "fetch_models",
                        lambda url, key: vibebox.parse_models(MODELS))
    vibebox.main(["-llm", "http://h:8080/v1", "-model", "gpt-oss-120b"])
    c = ran[-1]
    oc = [a for a in c if a.startswith("OPENCODE_CONFIG_CONTENT=")]
    assert len(oc) == 1 and "qwen3.6-35b-a3b" in oc[0] and "local/gpt-oss-120b" in oc[0]
    assert "/models" in capsys.readouterr().out


def test_model_list_failure_falls_back_with_one_warning(monkeypatch, tmp_path, capsys):
    import vibebox
    ran, _ = _fake_host(monkeypatch, tmp_path)
    def boom(url, key):
        raise OSError("down")
    monkeypatch.setattr(vibebox, "fetch_models", boom)
    _write_env("LOCAL_LLM_URL=https://api.scaleway.ai/v1\nLOCAL_LLM_MODEL=m\n"
               "LOCAL_LLM_API_KEY=s3cr3t-key\n")
    vibebox.main([])
    err = capsys.readouterr().err
    assert len([l for l in err.splitlines() if "WARNING" in l]) == 1 and "s3cr3t-key" not in err
    assert not any(a.startswith("OPENCODE_CONFIG_CONTENT") for a in ran[-1])
    assert "LOCAL_LLM_MODEL=m" in ran[-1] and ran[-1][-1] == "opencode"


def test_default_entry_is_opencode_with_llm_shell_otherwise(monkeypatch, tmp_path):
    import vibebox
    ran, _ = _fake_host(monkeypatch, tmp_path)
    vibebox.main([])
    assert ran[-1][-1] == "bash"                    # no LLM configured
    vibebox.main(["-llm", "http://h:8080/v1"])
    assert ran[-1][-1] == "opencode"                # plain `vibe`
    vibebox.main(["-sh", "-llm", "http://h:8080/v1"])
    assert ran[-1][-1] == "bash"                    # `vibe -sh`


def test_banner_is_short(monkeypatch, tmp_path, capsys):
    import vibebox
    _fake_host(monkeypatch, tmp_path)
    vibebox.main(["-llm", "http://h:8080/v1"])
    assert len(capsys.readouterr().out.strip().splitlines()) <= 3


def test_unsafe_workdir():
    from vibebox import unsafe_workdir
    assert unsafe_workdir("/", "/home/me")
    assert unsafe_workdir("/home/me", "/home/me")
    assert unsafe_workdir("/home/me/", "/home/me")
    assert unsafe_workdir("/home", "/home/me")       # parent of home also mounts it
    assert not unsafe_workdir("/home/me/proj", "/home/me")
    assert not unsafe_workdir("/home/meow", "/home/me")


def test_refuses_home_dir(monkeypatch, tmp_path, capsys):
    import vibebox
    ran, _ = _fake_host(monkeypatch, tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert vibebox.main([]) == 2 and ran == []
    assert "refusing" in capsys.readouterr().err


def test_install_symlinks_vibe_and_resolves_repo(tmp_path):
    import vibebox
    link = vibebox.install(str(tmp_path / "bin"))
    assert os.path.basename(link) == "vibe" and os.path.islink(link)
    assert os.path.realpath(link) == os.path.realpath(vibebox.__file__)
    assert vibebox.install(str(tmp_path / "bin")) == link       # idempotent
    assert open(link).readline().startswith("#!/usr/bin/env python3")
    assert os.path.isfile(vibebox.SECCOMP) and os.path.dirname(vibebox.SECCOMP) == vibebox.REPO


def test_image_hash_tracks_containerfile_and_opencode(tmp_path):
    from vibebox import image_hash
    (tmp_path / "opencode").mkdir()
    (tmp_path / "Containerfile").write_text("FROM x\n")
    (tmp_path / "opencode" / "opencode.json").write_text("{}")
    h = image_hash(str(tmp_path))
    assert h == image_hash(str(tmp_path))
    (tmp_path / "opencode" / "opencode.json").write_text('{"a":1}')
    assert image_hash(str(tmp_path)) != h


def test_herdr_hint_and_metadata_only_inside_herdr(monkeypatch, tmp_path):
    import vibebox
    ran, _ = _fake_host(monkeypatch, tmp_path)
    reports = []
    monkeypatch.setattr(vibebox, "herdr_report", lambda env, args, delay=0: reports.append(args))
    vibebox.main(["-llm", "http://h:8080/v1", "-model", "m1"])
    assert vibebox._last_env[-1] is None and reports == []
    monkeypatch.setenv("HERDR_ENV", "1")
    monkeypatch.setenv("HERDR_PANE_ID", "w1:p2")
    monkeypatch.setenv("HERDR_BIN_PATH", "/bin/true")
    vibebox.main(["-llm", "http://h:8080/v1", "-model", "m1"])
    assert vibebox._last_env[-2]["HERDR_AGENT"] == "opencode"
    a = reports[-1]
    assert a[:3] == ["pane", "report-metadata", "w1:p2"]
    title = a[a.index("--title") + 1]
    assert "m1" in title and "h" in title and os.path.basename(os.getcwd()) in title
