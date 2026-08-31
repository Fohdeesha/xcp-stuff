# -*- coding: utf-8 -*-
"""The '== XOA Status ==' section runs beside the pool and prints after it.

It asks the appliance about itself: xoa-updater five times and 'xoa check' once, ~2.9s
measured, sharing nothing whatever with the hosts being checked. It used to run at render
time and print first, so those 2.9s were spent after every host had already answered, in
front of results that had been ready the whole time.

Two claims, and a fast implementation cannot fake either: the work really overlaps the
collection (the fake collect refuses to finish until the section has started, so a serial
implementation deadlocks rather than merely being slow), and the section's lines are
printed after the last host's.
"""

import io
import os
import sys
import threading

import pytest

import main
import model
import result
import transport
import xoa


def xoa_lines():
    return [result.ok("Registration", "someone@example.com"),
            result.flag("XOA Status", "Updates available")]


def payload_for(address):
    return {"hostname": {"ok": True, "value": "h-" + address.replace(".", "-")},
            "pool": {"pool_uuid": {"ok": True, "value": "u"}},
            "yum_check": {"ok": True, "value": 0}}


def drive(monkeypatch, tmp_path, argv, lines_fn=xoa_lines, addresses=("10.0.0.1",),
          run_env="xoa"):
    """Run main() end to end with everything that touches a host or the appliance faked.

    Returns (exit code, what landed on stdout).
    """
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    # host mode appends the sbin dirs to PATH; setenv puts it back afterwards
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setattr(main, "detect_run_env", lambda: run_env)
    monkeypatch.setattr(xoa, "debian_version_ok", lambda: (True, "12"))
    monkeypatch.setattr(xoa, "running_as_root", lambda: True)
    monkeypatch.setattr(xoa, "ping_silent", lambda ips: [])
    monkeypatch.setattr(xoa, "lines", lines_fn)
    monkeypatch.setattr(transport, "make_work_dir", lambda: str(tmp_path))
    monkeypatch.setattr(transport, "cleanup_work_dir", lambda path: None)
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env_: True)

    def fake_resolve(run, args):
        run.seed = addresses[0]
        run.password = "x"
        run.master_address = addresses[0]
        run.pool_name = "P"

    def fake_discover(run):
        hosts = [model.Host(a, "uuid-" + a, "h-" + a.replace(".", "-")) for a in addresses]
        run.pool_size = len(hosts)
        run.all_addresses = list(addresses)
        run.master_address = addresses[0]
        return hosts

    monkeypatch.setattr(main, "resolve_target_xoa", fake_resolve)
    monkeypatch.setattr(main, "discover", fake_discover)
    return main.main(list(argv)), out.getvalue()


# --------------------------------------------------------------------------------------
# the updater service gate
# --------------------------------------------------------------------------------------

def test_service_active_reads_systemctl_is_active(monkeypatch):
    calls = []

    def fake(argv, timeout, env=None, stdin_text=None):
        calls.append(argv)
        return (0, "active\n", "")

    monkeypatch.setattr(transport, "run_local_cmd", fake)
    assert xoa._service_active("xoa-updater") is True
    assert calls == [["systemctl", "is-active", "xoa-updater"]]


def test_service_active_false_on_inactive_or_failed_status(monkeypatch):
    def fake(argv, timeout, env=None, stdin_text=None):
        return (3, "inactive\n", "")

    monkeypatch.setattr(transport, "run_local_cmd", fake)
    assert xoa._service_active("xoa-updater") is False


def test_service_active_false_when_the_command_itself_fails(monkeypatch):
    def fake(argv, timeout, env=None, stdin_text=None):
        return (127, "", "systemctl: command not found")

    monkeypatch.setattr(transport, "run_local_cmd", fake)
    assert xoa._service_active("xoa-updater") is False


# --------------------------------------------------------------------------------------
# the background worker itself
# --------------------------------------------------------------------------------------

def test_it_answers_with_what_the_function_returned():
    assert main._Background(lambda: [1, 2, 3]).result() == [1, 2, 3]


def test_an_exception_crosses_the_thread_and_is_raised_by_result():
    """Inline, a section that blew up took the run with it. It still must.

    Swallowed here it would come back as None, and the report would fail somewhere else
    entirely with nothing left pointing at the cause.
    """
    def boom():
        raise ValueError("updater exploded")

    worker = main._Background(boom)
    with pytest.raises(ValueError, match="updater exploded"):
        worker.result()


def test_the_thread_is_a_daemon():
    """An early sys.exit - an unreadable xo-db, a seed that will not answer - must not be
    held up by a 'xoa check' with XOA_CHECK_TIMEOUT still to run."""
    started = threading.Event()
    release = threading.Event()

    def slow():
        started.set()
        release.wait(10)
        return []

    worker = main._Background(slow)
    assert started.wait(10)
    assert worker._thread.daemon is True
    release.set()
    worker.result()


# --------------------------------------------------------------------------------------
# it really runs beside the collection
# --------------------------------------------------------------------------------------

def test_the_section_is_already_running_before_the_hosts_are_collected(monkeypatch,
                                                                      tmp_path):
    """The fake collect will not finish until the section has started.

    Run inline at render time - the old shape - that never happens, the wait times out and
    the assertion fails. Being merely fast cannot pass this.
    """
    started = threading.Event()

    def lines_fn():
        started.set()
        return xoa_lines()

    def fake_collect(run):
        assert started.wait(10), "the XOA section had not started by collection time"
        for host in run.hosts:
            host.payload = payload_for(host.address)

    monkeypatch.setattr(main, "collect_hosts", fake_collect)
    code, text = drive(monkeypatch, tmp_path, ["-n", "p"], lines_fn=lines_fn)
    assert "== XOA Status ==" in text
    assert code in (0, 1)


# --------------------------------------------------------------------------------------
# ...and prints last
# --------------------------------------------------------------------------------------

def collect_ok(run):
    for host in run.hosts:
        host.payload = payload_for(host.address)


def test_the_xoa_section_prints_after_every_host(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "collect_hosts", collect_ok)
    _code, text = drive(monkeypatch, tmp_path, ["-n", "p"],
                        addresses=("10.0.0.1", "10.0.0.2"))
    order = [text.index(mark) for mark in
             ("== Pool Status ==", "== Individual Hosts ==", "---pool.conf contents---",
              "== XOA Status ==", "Health Script Version:")]
    assert order == sorted(order), text


def test_single_mode_puts_it_after_the_one_host_too(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "collect_hosts", collect_ok)
    _code, text = drive(monkeypatch, tmp_path, ["-s", "10.0.0.1"])
    assert text.index("== Health check on:") < text.index("== XOA Status ==")


def test_exactly_one_blank_line_precedes_the_section_in_both_modes(monkeypatch, tmp_path):
    """Every heading in the report is preceded by one blank line and no more.

    In pool mode the pool.conf block supplies it, in single mode nothing does - which is
    the whole reason that blank is conditional, and the reason it is worth a test.
    """
    monkeypatch.setattr(main, "collect_hosts", collect_ok)
    for argv in (["-n", "p"], ["-s", "10.0.0.1"]):
        _code, text = drive(monkeypatch, tmp_path, argv)
        lines = text.split("\n")
        i = lines.index("== XOA Status ==")
        assert lines[i - 1] == "", (argv, lines[i - 3:i + 1])
        assert lines[i - 2] != "", (argv, lines[i - 3:i + 1])


def test_host_mode_has_no_xoa_section_at_all(monkeypatch, tmp_path):
    """A hypervisor is not an appliance; there is nothing to ask and no thread to start."""
    monkeypatch.setattr(main, "collect_hosts", collect_ok)

    def fake_discover(run):
        run.pool_size = 1
        run.all_addresses = ["10.0.0.1"]
        run.master_address = "10.0.0.1"
        return [model.Host("10.0.0.1", "uuid-1", "h-1")]

    def exploding_lines():
        raise AssertionError("host mode must not run the XOA section")

    monkeypatch.setattr(main, "discover", fake_discover)
    monkeypatch.setattr(main, "resolve_target_host_mode", lambda run, args: "")
    monkeypatch.setattr(main, "prepare_host_sweep", lambda run, pw: None)
    _code, text = drive(monkeypatch, tmp_path, [], lines_fn=exploding_lines,
                        run_env="host")
    assert "== XOA Status ==" not in text
