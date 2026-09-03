# -*- coding: utf-8 -*-
"""Running as a non-root user: refused up front, and for the stated reason.

The appliance's own login user is 'xoa', not root, so this is the first thing a new user
hits. Before the gate, a non-root XOA run said 'No host IP provided and no enabled hosts
found in xo-db' - on an appliance with five pools - because xo-server-db had failed with
EACCES and every lookup answered nothing. The two claims that must never be made off a
db that was not read are 'there are no pools' and 'that host is not in xo-db'; both are
pinned here, gate or no gate.
"""

import io
import os
import sys
import types

import pytest

import main
import transport
import xoa
import xodb


class Reached(Exception):
    """Raised by the stand-in for the step after the gate, to show the gate let it by."""


@pytest.fixture(autouse=True)
def fresh_db_cache():
    xodb.reset_cache()
    yield
    xodb.reset_cache()


def gate_run(monkeypatch, tmp_path, argv, run_env, root):
    """main() up to the root gate, with everything past it refusing to run.

    Returns (exit code or SystemExit code, stdout, stderr, what was attempted).
    """
    out, err = io.StringIO(), io.StringIO()
    attempted = []
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setattr(main, "detect_run_env", lambda: run_env)
    monkeypatch.setattr(xoa, "debian_version_ok", lambda: (True, "12"))
    monkeypatch.setattr(xoa, "running_as_root", lambda: root)
    monkeypatch.setattr(transport, "make_work_dir", lambda: str(tmp_path))
    monkeypatch.setattr(transport, "cleanup_work_dir", lambda path: None)
    # PATH above is the real one, so on an appliance xodb's redis fast path would find a
    # real xo-server-db and a real redis: 'attempted' has to mean attempted, everywhere
    monkeypatch.setattr(transport, "which", lambda binary: "")

    def record(name):
        def stand_in(*args, **kwargs):
            attempted.append(name)
            raise Reached(name)
        return stand_in

    # the step after the gate in each environment, and everything that would spend time
    # or talk to anything: none of it may be touched by a run that was refused
    monkeypatch.setattr(main, "resolve_target_xoa", record("resolve_target_xoa"))
    monkeypatch.setattr(main, "resolve_target_host_mode", record("resolve_target_host_mode"))
    monkeypatch.setattr(main, "discover", record("discover"))
    monkeypatch.setattr(transport, "run_local_cmd", record("run_local_cmd"))
    monkeypatch.setattr(xoa, "lines", record("xoa.lines"))
    try:
        code = main.main(list(argv))
    except SystemExit as exc:
        code = exc.code
    except Reached:
        code = "reached"
    return code, out.getvalue(), err.getvalue(), attempted


def test_a_non_root_xoa_run_stops_and_says_why(monkeypatch, tmp_path):
    code, out, err, attempted = gate_run(monkeypatch, tmp_path, [], "xoa", root=False)
    assert code == 1
    assert out == ""
    assert "ERROR: this must run as root on XOA" in err
    assert "xo-server-db" in err
    assert "sudo -i" in err
    # the documented one-liner under sudo fails in a way that looks unrelated, so the
    # message has to head that off
    assert "sudo python3 <(curl ...)" in err
    assert "no enabled hosts" not in err
    assert attempted == []


def test_it_stops_before_the_db_is_read_or_the_section_is_started(monkeypatch, tmp_path):
    """No 3.3s xo-server-db read, no xoa-updater, no thread: nothing was attempted."""
    _, _, _, attempted = gate_run(monkeypatch, tmp_path, ["-n", "sec"], "xoa", root=False)
    assert attempted == []


@pytest.mark.parametrize("argv", [["--json"], ["--json", "-n", "sec"], ["--json", "-f"]])
def test_json_keeps_stdout_empty_when_refused(monkeypatch, tmp_path, argv):
    """Under --json stdout is a whole document or nothing - never an error message."""
    code, out, err, _ = gate_run(monkeypatch, tmp_path, argv, "xoa", root=False)
    assert code == 1
    assert out == ""
    assert "must run as root" in err


def test_a_non_root_host_run_stops_with_the_host_wording(monkeypatch, tmp_path):
    code, out, err, attempted = gate_run(monkeypatch, tmp_path, [], "host", root=False)
    assert code == 1
    assert out == ""
    assert "must run as root on an XCP-ng host" in err
    assert "xo-server-db" not in err     # there is no xo-server-db on a hypervisor
    assert attempted == []


def test_root_goes_on_to_the_target(monkeypatch, tmp_path):
    for run_env, step in (("xoa", "resolve_target_xoa"), ("host", "resolve_target_host_mode")):
        code, _, err, attempted = gate_run(monkeypatch, tmp_path, [], run_env, root=True)
        assert code == "reached"
        assert attempted == [step]
        assert "must run as root" not in err


def test_help_and_usage_errors_do_not_need_root(monkeypatch, tmp_path):
    """-h answers on stdout with exit 0, a bad flag on stderr with exit 2, whoever asks:
    both happen before the gate, and neither needs anything root can read."""
    code, out, err, attempted = gate_run(monkeypatch, tmp_path, ["-h"], "xoa", root=False)
    assert code == 0
    assert out.startswith("Usage:")
    assert attempted == []

    code, out, err, attempted = gate_run(monkeypatch, tmp_path, ["--bogus"], "xoa", root=False)
    assert code == 2
    assert out == ""
    assert "Usage:" in err
    assert "must run as root" not in err
    assert attempted == []


# --------------------------------------------------------------------------------------
# the claims that were being made off a db nobody had read
# --------------------------------------------------------------------------------------
# These bypass the gate on purpose: xo-server-db can fail for a root user too - redis
# down, xo-server not installed, the binary missing from PATH - and every one of those
# used to read as 'no enabled hosts found in xo-db'.

EACCES = (
    "[Error: EACCES: permission denied, lstat '/etc/xo-server/config.toml'] {\n"
    "  errno: -13,\n"
    "  code: 'EACCES',\n"
    "  syscall: 'lstat',\n"
    "  path: '/etc/xo-server/config.toml'\n"
    "}\n"
)


def resolve(monkeypatch, argv, db_answer, name_filter=""):
    """resolve_target_xoa against a db that answers db_answer = (rc, stdout, stderr).

    Returns (SystemExit code or None, stdout, stderr, the run).
    """
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(main, "detect_run_env", lambda: "xoa")
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda argv_, timeout=None, env=None, stdin_text=None: db_answer)
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env: True)
    monkeypatch.setattr(xodb, "have_xo_server_db", lambda: True)
    run = main.Run()
    run.name_filter = name_filter
    run.transport = types.SimpleNamespace(ssh_port=22, password="")
    code = None
    try:
        main.resolve_target_xoa(run, list(argv))
    except SystemExit as exc:
        code = exc.code
    return code, out.getvalue(), err.getvalue(), run


@pytest.mark.parametrize("name_filter", ["", "sec"])
def test_an_unreadable_db_is_not_reported_as_having_no_pools(monkeypatch, name_filter):
    code, out, err, _ = resolve(monkeypatch, [], (1, "", EACCES), name_filter)
    assert code == 1
    assert out == ""
    assert "could not read xo-server-db" in err
    assert "EACCES: permission denied" in err
    assert "no enabled hosts" not in err


def test_a_missing_binary_is_reported_as_such(monkeypatch):
    # what the transport returns when the exec itself fails - the binary is not on PATH
    answer = (127, "", "xo-server-db: [Errno 2] No such file or directory")
    code, _, err, _ = resolve(monkeypatch, [], answer)
    assert code == 1
    assert "could not read xo-server-db (exit code 127: xo-server-db: [Errno 2]" in err
    assert "no enabled hosts" not in err


def test_a_db_that_really_has_no_enabled_pool_still_says_so(monkeypatch):
    """The old message is still the right one when it is true."""
    code, _, err, _ = resolve(monkeypatch, [], (0, "", ""))
    assert code == 1
    assert "no enabled hosts found in xo-db" in err
    assert "could not read" not in err


def test_a_host_argument_against_an_unreadable_db_is_not_called_unknown(monkeypatch):
    """'Host IP not found in xo-db' is a statement about the db's contents."""
    code, out, err, _ = resolve(monkeypatch, ["10.0.0.9"], (1, "", EACCES))
    assert code == 1
    assert "Checking host: 10.0.0.9" in out       # the banner still names the target
    assert "Host IP not found in xo-db" not in out
    assert "could not read xo-server-db" in err
    assert "no password could be looked up for 10.0.0.9" in err


def test_a_host_the_db_does_not_hold_still_gets_the_not_found_notice(monkeypatch):
    code, out, err, _ = resolve(monkeypatch, ["10.0.0.9"],
                                (0, "{ enabled: 'true', host: '10.0.0.1', password: 'p' }\n", ""))
    assert code == 1
    assert "Host IP not found in xo-db" in out
    assert "could not read" not in err


def test_a_host_and_a_password_do_not_need_the_db_at_all(monkeypatch):
    code, out, err, run = resolve(monkeypatch, ["10.0.0.9", "pw"], (1, "", EACCES))
    assert code is None
    assert run.password == "pw"
    assert run.seed == "10.0.0.9"
    assert "could not read" not in err
