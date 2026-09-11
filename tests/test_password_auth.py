# -*- coding: utf-8 -*-
"""How the password reaches ssh, and what is still reported when it cannot.

sshpass used to be a hard requirement, and an appliance with no internet access could not
install it: the run printed one line about that and exited, having checked nothing at all
- including the whole XOA section, which needs no pool access. Two things changed, and
both are pinned here: ssh is handed the password by its own askpass helper, which needs
nothing installed; and a run that genuinely cannot authenticate reports the appliance and
says Unknown about the pool, rather than reporting nothing.
"""

import io
import json
import os
import sys

import main
import result
import transport
import xoa


def unreachable(message):
    """A stub for something this path must never call."""
    raise AssertionError(message)


class FakeRun(object):
    """Stands in for run_local_cmd: records the argv and env, answers in call order."""

    def __init__(self, results):
        self.results = results
        self.calls = []
        self.envs = []

    def __call__(self, argv, timeout, env=None, stdin_text=None):
        self.calls.append(list(argv))
        self.envs.append(env or {})
        return self.results[min(len(self.calls) - 1, len(self.results) - 1)]


def a_transport(tmp_path):
    return transport.Transport("xoa", str(tmp_path))


# --------------------------------------------------------------------------------------
# the helper itself
# --------------------------------------------------------------------------------------

def test_the_helper_is_written_executable_and_proved_to_run(monkeypatch, tmp_path):
    """Proved, not assumed: a noexec /tmp would otherwise surface at the far end as an
    authentication failure, which reads as a wrong root password."""
    probe = FakeRun([(0, "health-askpass-probe\n", "")])
    monkeypatch.setattr(transport, "run_local_cmd", probe)
    path = transport.write_askpass(str(tmp_path))
    assert path == os.path.join(str(tmp_path), "askpass")
    assert probe.calls == [[path]]
    # the probe value, never a real password
    assert probe.envs[0][transport.ASKPASS_ENV] == "health-askpass-probe"
    with open(path) as fh:
        body = fh.read()
    assert body.startswith("#!/bin/sh\n")
    assert 'printf \'%s\\n\' "${HEALTH_SSH_PASSWORD}"' in body


def test_a_helper_that_cannot_be_executed_is_not_used(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "run_local_cmd",
                        FakeRun([(126, "", "Permission denied")]))
    assert transport.write_askpass(str(tmp_path)) == ""


def test_a_helper_that_answers_something_else_is_not_used(monkeypatch, tmp_path):
    """rc 0 and the wrong bytes is the shape of a wrapper or a profile that prints
    something of its own; ssh would send that as the password."""
    monkeypatch.setattr(transport, "run_local_cmd", FakeRun([(0, "", "")]))
    assert transport.write_askpass(str(tmp_path)) == ""


def test_a_work_dir_that_cannot_be_written_is_not_used(monkeypatch, tmp_path):
    assert transport.write_askpass(str(tmp_path / "does-not-exist")) == ""


# --------------------------------------------------------------------------------------
# choosing between the two
# --------------------------------------------------------------------------------------

def test_the_helper_is_preferred_and_installs_nothing(monkeypatch, tmp_path):
    """The whole point: the path that works on an offline appliance is the default one,
    so no run reaches an apt-get that cannot work."""
    monkeypatch.delenv("HEALTH_SSH_AUTH", raising=False)
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "/tmp/x/askpass")
    monkeypatch.setattr(transport, "ensure_sshpass",
                        lambda run_env: unreachable("sshpass must not be reached"))
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is True
    assert tr.auth == transport.AUTH_ASKPASS


def test_sshpass_is_the_fallback_when_the_helper_will_not_run(monkeypatch, tmp_path):
    monkeypatch.delenv("HEALTH_SSH_AUTH", raising=False)
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "")
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env: True)
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is True
    assert tr.auth == transport.AUTH_SSHPASS


def test_neither_working_names_both(monkeypatch, tmp_path):
    monkeypatch.delenv("HEALTH_SSH_AUTH", raising=False)
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "")
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env: False)
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is False
    assert tr.auth == ""
    assert "askpass helper would not run" in tr.auth_error
    assert "sshpass is not installed" in tr.auth_error


def test_the_choice_can_be_pinned_either_way(monkeypatch, tmp_path):
    """Both halves are live code on every box that has sshpass, so both have to be
    testable there - the same reason HEALTH_REMOTE_PYTHON exists."""
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "/tmp/x/askpass")
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env: True)

    monkeypatch.setenv("HEALTH_SSH_AUTH", "sshpass")
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is True
    assert tr.auth == transport.AUTH_SSHPASS

    monkeypatch.setenv("HEALTH_SSH_AUTH", "askpass")
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is True
    assert tr.auth == transport.AUTH_ASKPASS


def test_pinning_askpass_never_falls_back(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HEALTH_SSH_AUTH", "askpass")
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "")
    monkeypatch.setattr(transport, "ensure_sshpass",
                        lambda run_env: unreachable("sshpass must not be reached"))
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is False
    assert "sshpass" not in tr.auth_error


def test_an_unknown_pin_is_a_warning_and_not_a_silent_choice(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HEALTH_SSH_AUTH", "paramiko")
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "/tmp/x/askpass")
    tr = a_transport(tmp_path)
    assert tr.enable_password_auth("xoa") is True
    assert "ignoring HEALTH_SSH_AUTH=paramiko" in capsys.readouterr().err


# --------------------------------------------------------------------------------------
# what each mechanism hands to ssh
# --------------------------------------------------------------------------------------

def test_the_helper_run_passes_the_password_in_the_environment_only(tmp_path):
    tr = a_transport(tmp_path)
    tr.auth = transport.AUTH_ASKPASS
    tr.askpass = "/tmp/x/askpass"
    tr.password = "s3cr3t"
    env, prefix = tr._auth_env()
    assert prefix == []
    assert env[transport.ASKPASS_ENV] == "s3cr3t"
    assert env["SSH_ASKPASS"] == "/tmp/x/askpass"
    # 8.4+ settles it outright; 7.4 (both dom0 releases) only asks a helper when DISPLAY
    # is set and there is no controlling terminal, which start_new_session already ensures
    assert env["SSH_ASKPASS_REQUIRE"] == "force"
    assert env["DISPLAY"]
    assert "SSHPASS" not in env


def test_an_existing_display_is_left_alone(tmp_path, monkeypatch):
    monkeypatch.setenv("DISPLAY", "localhost:10.0")
    tr = a_transport(tmp_path)
    tr.auth = transport.AUTH_ASKPASS
    tr.password = "x"
    env, _prefix = tr._auth_env()
    assert env["DISPLAY"] == "localhost:10.0"


def test_the_sshpass_run_is_unchanged(tmp_path):
    tr = a_transport(tmp_path)
    tr.auth = transport.AUTH_SSHPASS
    tr.password = "s3cr3t"
    env, prefix = tr._auth_env()
    assert prefix == ["sshpass", "-e"]
    assert env["SSHPASS"] == "s3cr3t"
    assert transport.ASKPASS_ENV not in env


def test_the_password_is_never_in_the_argv(monkeypatch, tmp_path):
    for method in (transport.AUTH_ASKPASS, transport.AUTH_SSHPASS):
        calls = FakeRun([(0, "", "")])
        monkeypatch.setattr(transport, "run_local_cmd", calls)
        tr = a_transport(tmp_path)
        tr.auth = method
        tr.askpass = "/tmp/x/askpass"
        tr.password = "s3cr3t"
        tr._run_ssh_collector("10.0.0.9", "YmxvYg==")
        argv = calls.calls[0]
        assert "s3cr3t" not in " ".join(argv)
        # one prompt, so a wrong password fails now instead of three times over
        assert "NumberOfPasswordPrompts=1" in argv


# --------------------------------------------------------------------------------------
# the report a run with no way in can still produce
# --------------------------------------------------------------------------------------

def xoa_lines():
    return [result.ok("XOA Version", "6.7.1"),
            result.flag("XOA Check", "Problems found")]


def drive_no_auth(monkeypatch, tmp_path, argv):
    """main() on an appliance where no password mechanism could be established."""
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(main, "detect_run_env", lambda: "xoa")
    monkeypatch.setattr(xoa, "debian_version_ok", lambda: (True, "12"))
    monkeypatch.setattr(xoa, "running_as_root", lambda: True)
    monkeypatch.setattr(xoa, "lines", xoa_lines)
    monkeypatch.setattr(transport, "make_work_dir", lambda: str(tmp_path))
    monkeypatch.setattr(transport, "cleanup_work_dir", lambda path: None)
    monkeypatch.setattr(main, "discover",
                        lambda run: unreachable("nothing may be collected"))

    def fake_resolve(run, args):
        run.seed = "10.0.0.1"
        run.pool_name = "P"
        run.transport.auth_error = "ssh needs a password and there is no way to hand it one"
        return False

    monkeypatch.setattr(main, "resolve_target_xoa", fake_resolve)
    return main.main(list(argv)), out.getvalue()


def test_the_appliance_is_still_reported_when_the_pool_cannot_be_reached(monkeypatch, tmp_path):
    code, text = drive_no_auth(monkeypatch, tmp_path, [])
    assert "== XOA Status ==" in text
    assert "XOA Version: 6.7.1" in text
    # and the pool is Unknown, not absent: a run that could not look must not exit 0
    assert "Pool Access: Unknown" in text
    assert code == 1


def test_it_says_how_to_get_the_pool_checked(monkeypatch, tmp_path):
    _code, text = drive_no_auth(monkeypatch, tmp_path, [])
    assert "TMPDIR=/root" in text
    assert "apt-get install sshpass" in text


def test_the_suggested_command_can_never_carry_a_password(monkeypatch, tmp_path):
    """The hint is rebuilt from the run, not taken from sys.argv, which on a run given its
    password as an argument contains it."""
    monkeypatch.setattr(sys, "argv", ["health.py", "10.0.0.1", "hunter2"])
    _code, text = drive_no_auth(monkeypatch, tmp_path, ["10.0.0.1", "hunter2"])
    assert "hunter2" not in text


def test_filtered_output_keeps_it(monkeypatch, tmp_path):
    """-f is findings only, and 'the pool was not checked' is a finding."""
    _code, text = drive_no_auth(monkeypatch, tmp_path, ["-f"])
    assert "Pool Access: Unknown" in text
    assert "== Pool Status ==" in text
    assert "XOA Version" not in text


def test_the_document_says_it_too(monkeypatch, tmp_path):
    code, text = drive_no_auth(monkeypatch, tmp_path, ["--json"])
    doc = json.loads(text)
    assert code == 1 and doc["exit_code"] == 1 and doc["flagged"] is True
    assert doc["hosts"] == []
    entry = doc["pool"]["checks"][0]
    assert entry["key"] == "Pool Access"
    assert entry["status"] == result.UNKNOWN
    assert entry["flags"] is True
    assert doc["xoa"]["checks"][0]["key"] == "XOA Version"


def test_a_host_sweep_that_cannot_authenticate_still_checks_this_host(monkeypatch, capsys):
    """Host mode has always degraded rather than exited - it can check itself with no
    credentials at all - and it still names the reason."""
    run = main.Run()
    run.run_env = "host"
    run.pool_mode = True
    run.pool_size = 2
    run.transport = transport.Transport("host", "")
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "")
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env: False)
    monkeypatch.delenv("HEALTH_SSH_AUTH", raising=False)
    main.prepare_host_sweep(run, "a-password")
    assert run.host_sweep is False
    err = capsys.readouterr().err
    assert "no way to hand it one" in err
    assert "Continuing with this host only." in err


def test_a_solo_host_run_never_looks_for_a_way_to_authenticate(monkeypatch):
    """Nothing is installed and no helper is written on a single-host pool - that is the
    same invariant the sshpass install always had."""
    run = main.Run()
    run.run_env = "host"
    run.pool_size = 1
    run.transport = transport.Transport("host", "")
    monkeypatch.setattr(transport, "write_askpass",
                        lambda work_dir: unreachable("nothing to reach"))
    monkeypatch.setattr(transport, "ensure_sshpass",
                        lambda run_env: unreachable("nothing to reach"))
    main.prepare_host_sweep(run, "a-password")
    assert run.host_sweep is False
