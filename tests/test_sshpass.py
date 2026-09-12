# -*- coding: utf-8 -*-
"""ensure_sshpass has to say what it did.

It is the one thing the script installs on the machine it runs on, and on XOA it is the
first slow step of a run: an apt that stalls, or fails, is the last thing on the screen
for as long as it takes. The apt half used to print 'Installing via apt...' and then
nothing at all, either way - so a successful install looked exactly like a wedged one,
and a failed install surfaced only as the caller's one-line 'sshpass is required'.
"""

import transport


class FakeApt(object):
    """Stands in for run_local_cmd: records the argv, answers what it was told to."""

    def __init__(self, results):
        self.results = results        # list of (rc, out, err), in call order
        self.calls = []
        self.envs = []

    def __call__(self, argv, timeout, env=None, stdin_text=None):
        self.calls.append(list(argv))
        self.envs.append(env or {})
        return self.results[len(self.calls) - 1]


def install_run(monkeypatch, results, found_after):
    """One ensure_sshpass('xoa') where sshpass is missing until the install has run."""
    apt = FakeApt(results)
    monkeypatch.setattr(transport, "run_local_cmd", apt)
    monkeypatch.setattr(transport, "have", lambda binary: bool(apt.calls) and found_after)
    return apt


def test_an_install_that_worked_says_so(monkeypatch, capsys):
    apt = install_run(monkeypatch, [(0, "", ""), (0, "Setting up sshpass", "")], True)
    assert transport.ensure_sshpass("xoa") is True
    assert [c[0] for c in apt.calls] == ["apt-get", "apt-get"]
    assert apt.calls[1] == ["apt-get", "install", "-y", "sshpass"]
    assert capsys.readouterr().err.endswith("sshpass installed.\n")


def test_an_install_that_failed_prints_apt_and_its_exit_code(monkeypatch, capsys):
    install_run(monkeypatch, [(0, "", ""),
                              (100, "", "E: Unable to locate package sshpass")], False)
    assert transport.ensure_sshpass("xoa") is False
    err = capsys.readouterr().err
    assert "apt-get exit code 100" in err
    assert "E: Unable to locate package sshpass" in err


def test_a_failed_update_is_a_warning_and_the_install_is_still_tried(monkeypatch, capsys):
    """The package may well already be in the local index, so a mirror that would not
    answer is not on its own a reason to give up - but it is worth saying."""
    apt = install_run(monkeypatch, [(124, "", "timed out"), (0, "", "")], True)
    assert transport.ensure_sshpass("xoa") is True
    assert len(apt.calls) == 2
    err = capsys.readouterr().err
    assert "'apt-get update' exited 124" in err
    assert "sshpass installed." in err


def test_the_install_can_never_stop_to_ask(monkeypatch):
    """stdin is /dev/null, so a dpkg conffile or needrestart prompt would read EOF part
    way through an install nobody can see."""
    apt = install_run(monkeypatch, [(0, "", ""), (0, "", "")], True)
    transport.ensure_sshpass("xoa")
    assert all(env.get("DEBIAN_FRONTEND") == "noninteractive" for env in apt.envs)


def test_an_sshpass_already_there_installs_nothing(monkeypatch, capsys):
    apt = FakeApt([])
    monkeypatch.setattr(transport, "run_local_cmd", apt)
    monkeypatch.setattr(transport, "have", lambda binary: True)
    assert transport.ensure_sshpass("xoa") is True
    assert apt.calls == []
    assert capsys.readouterr().err == ""


def test_a_hypervisor_uses_yum_and_the_extras_repo(monkeypatch, capsys):
    """--enablerepo is a one-shot: 'extras' ships disabled in CentOS-Base.repo pointing at
    Vates' own mirror, and the host's yum config is left exactly as it was found."""
    apt = install_run(monkeypatch, [(0, "", "")], True)
    assert transport.ensure_sshpass("host") is True
    assert apt.calls == [["yum", "--enablerepo=extras", "install", "-y", "sshpass"]]
    assert capsys.readouterr().err.endswith("sshpass installed.\n")
