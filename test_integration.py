"""Integration / liveness tests — these actually spawn podman containers.

They are skipped unless VIBEBOX_INTEGRATION=1 so the unit suite stays fast and
pure. Run with:  VIBEBOX_INTEGRATION=1 pytest test_integration.py   (Linux)
or:  $env:VIBEBOX_INTEGRATION=1; pytest test_integration.py          (Windows)

Purpose: prove the sandbox is genuinely alive — it executes real compute and
returns correct results — because podman sessions have silently died before.
"""
import math
import os
import subprocess
import textwrap
from itertools import permutations

import pytest

from vibebox import Options, build_podman_command

pytestmark = pytest.mark.skipif(
    os.environ.get("VIBEBOX_INTEGRATION") != "1",
    reason="set VIBEBOX_INTEGRATION=1 to run podman integration tests",
)

CITIES = [(0, 0), (0, 1), (1, 1), (1, 0), (2, 0.5)]


def brute_force_tsp(cities):
    best = None
    for perm in permutations(range(1, len(cities))):
        order = [0] + list(perm) + [0]
        d = sum(math.dist(cities[order[i]], cities[order[i + 1]])
                for i in range(len(order) - 1))
        best = d if best is None else min(best, d)
    return best


def run_in_box(work, payload_argv, gpu=False, net=("none",)):
    """Build the real hardened command, swap the shell entry for a payload."""
    cmd = build_podman_command(Options(work=work, net=list(net), gpu=gpu))
    assert cmd[-1] == "bash"          # sanity: we're replacing the entrypoint
    cmd = cmd[:-1] + list(payload_argv)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180)


def test_container_is_alive_and_solves_tsp(tmp_path):
    """The box runs a brute-force TSP and returns the correct optimum."""
    expected = round(brute_force_tsp(CITIES), 6)
    (tmp_path / "tsp.py").write_text(textwrap.dedent("""
        import math
        from itertools import permutations
        cities = [(0, 0), (0, 1), (1, 1), (1, 0), (2, 0.5)]
        best = None
        for perm in permutations(range(1, len(cities))):
            order = [0] + list(perm) + [0]
            d = sum(math.dist(cities[order[i]], cities[order[i + 1]])
                    for i in range(len(order) - 1))
            best = d if best is None else min(best, d)
        print("OPTIMAL", round(best, 6))
    """))
    r = run_in_box(str(tmp_path), ["python3", "/work/tsp.py"])
    assert r.returncode == 0, f"container died: {r.stderr}"
    assert f"OPTIMAL {expected}" in r.stdout, r.stdout


def test_container_runs_as_nonroot_with_workdir(tmp_path):
    """Liveness + security in one: runs, is non-root, sees only /work."""
    r = run_in_box(str(tmp_path), ["bash", "-c", "id -u; pwd"])
    assert r.returncode == 0, r.stderr
    uid, pwd = r.stdout.split()
    assert uid == "1000"        # never root
    assert pwd == "/work"


@pytest.mark.skipif(os.environ.get("VIBEBOX_GPU") != "1",
                    reason="set VIBEBOX_GPU=1 on a CUDA host")
def test_gpu_visible_when_requested(tmp_path):
    r = run_in_box(str(tmp_path), ["nvidia-smi", "-L"], gpu=True)
    assert r.returncode == 0, r.stderr
    assert "GPU" in r.stdout


def test_runs_as_a_script_end_to_end(tmp_path):
    """Invoke the launcher as a real subprocess (catches def-ordering / __main__
    bugs that importing for unit tests hides). Scriptable mode: empty stdin -> the
    shell hits EOF and exits cleanly."""
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    r = subprocess.run(
        [sys.executable, os.path.join(here, "vibebox.py"), "-net", "none"],
        cwd=str(tmp_path), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=120,
    )
    assert r.returncode == 0, f"script failed: {r.stderr}"
    assert "NameError" not in r.stderr and "Traceback" not in r.stderr
