# -*- coding: utf-8 -*-
"""sshpass is used when it is there, and never installed.

It is the fallback for a work dir the askpass helper cannot run from. Until v3.28 a run
that got here installed it - yum --enablerepo=extras on a dom0, apt-get on an XOA - which
on the offline appliances health.py is routinely pasted onto meant up to ten minutes of
timeouts before a line printed, and left a package behind. Both sides now only look.
"""

import transport


def test_present_is_present(monkeypatch):
    monkeypatch.setattr(transport, "have", lambda binary: binary == "sshpass")
    assert transport.sshpass_present("xoa") is True
    assert transport.sshpass_present("host") is True


def test_absent_installs_nothing_on_either_side(monkeypatch):
    ran = []
    monkeypatch.setattr(transport, "have", lambda binary: False)
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda argv, timeout, env=None, stdin_text=None: ran.append(argv))
    assert transport.sshpass_present("xoa") is False
    assert transport.sshpass_present("host") is False
    assert ran == []


def test_without_either_mechanism_the_reason_names_both(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "write_askpass", lambda work_dir: "")
    monkeypatch.setattr(transport, "have", lambda binary: False)
    t = transport.Transport("xoa", str(tmp_path))
    assert t.enable_password_auth("xoa") is False
    assert "the askpass helper would not run" in t.auth_error
    assert "sshpass is not installed" in t.auth_error
    assert "could not be installed" not in t.auth_error
