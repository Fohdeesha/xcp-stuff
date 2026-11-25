# -*- coding: utf-8 -*-
"""Transport, main, report and result fixes from the 2026-11-24 audit (E findings).

Nothing here starts a real ssh or a real child: every process is faked, and anything a
test changes process-wide (signal handlers, PATH, the transport's stopping flag) is put
back by monkeypatch.
"""

import io
import os
import signal
import subprocess
import sys
import time

import pytest

import main
import model
import report
import result
import transport


# --------------------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------------------

def test_the_transports_own_timeout_is_124_and_still_told_apart():
    """Every existing `rc == 124` keeps working; a command that itself EXITED 124 (GNU
    timeout run by -c) is not mistaken for one this script gave up on."""
    assert transport.TIMED_OUT == 124
    assert transport.is_timeout(transport.TIMED_OUT)
    assert not transport.is_timeout(124)


def test_a_document_the_collector_gave_up_on_is_kept_and_marked():
    payload = {"hostname": {"ok": True, "value": "h"}, "__collector_stuck__": "df -hP",
               "collector": {"timings": []}}
    transport._mark_incomplete(payload, "192.0.2.1")
    assert "stuck in 'df -hP'" in payload["__incomplete__"]
    assert payload["hostname"]["ok"]          # what it established is kept


def test_a_collector_that_failed_part_way_says_why():
    payload = {"__collector_error__": "Traceback...\nKeyError: 'x'\n"}
    transport._mark_incomplete(payload, "192.0.2.1")
    assert payload["__incomplete__"].endswith("KeyError: 'x'")


def test_a_whole_document_is_not_marked():
    payload = {"hostname": {"ok": True, "value": "h"}}
    transport._mark_incomplete(payload, "192.0.2.1")
    assert "__incomplete__" not in payload


def test_close_masters_asks_each_control_socket_to_exit(monkeypatch, tmp_path):
    for name in ("cm-abc", "cm-def", "askpass.sh"):
        (tmp_path / name).write_text("")
    calls = []
    monkeypatch.setattr(subprocess, "call", lambda argv, **kw: calls.append(argv) or 0)
    transport.close_masters(str(tmp_path))
    assert sorted(c[2] for c in calls) == sorted(str(tmp_path / n) for n in ("cm-abc", "cm-def"))
    assert all(c[0] == "ssh" and c[3:5] == ["-O", "exit"] for c in calls)


def test_the_control_socket_is_named_by_a_fixed_length_hash():
    opts = transport.control_options("/tmp/healthpy-abcd1234")
    assert "ControlPath=%s" % os.path.join("/tmp/healthpy-abcd1234", "cm-%C") in opts
    assert "ControlMaster=auto" in opts


def test_a_work_dir_too_long_for_any_socket_turns_sharing_off():
    """ssh binds <ControlPath>.<16 chars>; past 107 bytes it exits 255 rather than
    falling back (measured with a long TMPDIR)."""
    fits = "/" + "d" * 45                 # 46 bytes: 46 + 61 = 107, the last that fits
    assert "ControlMaster=auto" in transport.control_options(fits)
    too_long = "/" + "d" * 46
    assert transport.control_options(too_long) == ["-o", "ControlMaster=no",
                                                   "-o", "ControlPath=none"]


def test_close_masters_on_a_dir_already_gone_is_quiet(tmp_path):
    transport.close_masters(str(tmp_path / "gone"))


def test_with_no_child_running_the_stop_costs_nothing(monkeypatch):
    """It is registered with atexit, so it runs at the end of EVERY run: the grace period
    may only be spent when there is something to wait for."""
    monkeypatch.setattr(transport, "_STOPPING", [False])
    monkeypatch.setattr(transport, "_LIVE", set())
    started = time.monotonic()
    transport.kill_all_children()
    assert time.monotonic() - started < 0.5


def test_nothing_new_starts_once_the_run_is_stopping(monkeypatch):
    monkeypatch.setattr(transport, "_STOPPING", [True])
    rc, _out, err = transport.run_local_cmd([sys.executable, "-c", "print(1)"], timeout=5)
    assert rc == 130 and "stopping" in err


# --------------------------------------------------------------------------------------
# main: arguments, PATH, signals
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [["-n", ""], ["-n", "  "], ["-c", ""], ["--name="]])
def test_an_empty_name_or_command_is_a_usage_error(argv, monkeypatch):
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    with pytest.raises(SystemExit) as exc:
        main.Run().parse_args(argv)
    assert exc.value.code == 2


def test_path_gains_the_sbin_and_local_dirs_before_anything_else(monkeypatch):
    """Under cron PATH is /usr/bin:/bin, and xo-server-db, xoa-updater and xoa live in
    /usr/local/bin: a cron run could not even read xo-db."""
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", "/bin"]))
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    with pytest.raises(SystemExit):
        main.main(["-h"])
    path = os.environ["PATH"].split(os.pathsep)
    assert path[:2] == ["/usr/bin", "/bin"]
    for extra in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/sbin"):
        assert extra in path


def test_a_bad_parallel_override_is_said_not_silently_ignored(monkeypatch):
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setenv("HEALTH_MAX_PARALLEL", "one")
    assert main.parallel_workers(3) >= 1
    assert "ignoring HEALTH_MAX_PARALLEL='one'" in err.getvalue()
    monkeypatch.setenv("HEALTH_MAX_PARALLEL", "1")
    assert main.parallel_workers(3) == 1


@pytest.mark.parametrize("signum, word", [(15, "Stopped"), (1, "Stopped")])
def test_sigterm_and_sighup_exit_like_a_signal_death(signum, word, monkeypatch):
    """Python's default for both is to die on the spot with no atexit handler, leaving
    the work dir, the askpass helper and every child behind."""
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            monkeypatch.setattr(signal, "signal", lambda *a: None)

    def stopped(argv=None):
        raise main.Stopped(signum)
    monkeypatch.setattr(main, "main", stopped)
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert main.entry() == 128 + signum
    assert word in err.getvalue()


def test_ctrl_c_is_still_130(monkeypatch):
    monkeypatch.setattr(signal, "signal", lambda *a: None)

    def interrupted(argv=None):
        raise KeyboardInterrupt()
    monkeypatch.setattr(main, "main", interrupted)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    assert main.entry() == 130


# --------------------------------------------------------------------------------------
# result and report
# --------------------------------------------------------------------------------------

def test_a_check_of_several_lines_that_raises_answers_every_line(monkeypatch):
    monkeypatch.setattr(sys, "stderr", io.StringIO())

    def boom():
        raise RuntimeError("nope")
    lines = result.guard(("XOSTOR Packages", "XOSTOR DRBD Module"), boom)
    assert [l.key for l in lines] == ["XOSTOR Packages", "XOSTOR DRBD Module"]
    assert all(l.status == result.UNKNOWN for l in lines)


def test_a_single_key_still_answers_one_line(monkeypatch):
    monkeypatch.setattr(sys, "stderr", io.StringIO())

    def boom():
        raise RuntimeError("nope")
    assert result.guard("Dmesg Content", boom).key == "Dmesg Content"


def _host(reachable, payload=None):
    """A host answered when it has a document (model.Host.reachable)."""
    h = model.Host("192.0.2.1", "uuid-1", "h1")
    h.payload = (payload if payload is not None else {}) if reachable else None
    return h


def test_the_document_says_reachable_as_it_is():
    """-s and a solo host run render their one host whether it answered or not; the
    document said reachable: true for it regardless."""
    rep = report.Report(json_mode=True, stream=io.StringIO())
    rep.begin_section("host", _host(False))
    assert rep._section["reachable"] is False
    rep.begin_section("host", _host(True, {"__incomplete__": "gave up"}))
    assert rep._section["reachable"] is True and rep._section["incomplete"] == "gave up"


def test_a_line_hidden_by_f_leaves_no_detail_behind():
    rep = report.Report(filter_output=True, stream=io.StringIO())
    rep.add(result.ok("Multipath Path Health", "OK").with_detail("Paths", "all fine"))
    assert rep._pool_details == [] and rep._host_details == []
    rep.add(result.flag("Log Errors", "Yes").with_detail("Log Errors", "evidence"))
    assert len(rep._pool_details) == 1


def test_pool_conf_is_not_in_the_document_under_f():
    rep = report.Report(filter_output=True, json_mode=True, stream=io.StringIO())
    rep.begin_section("host", _host(True, {}))
    rep.add_poolconf("h1", "master\n")
    assert "pool_conf" not in rep._section
    rep = report.Report(json_mode=True, stream=io.StringIO())
    rep.begin_section("host", _host(True, {}))
    rep.add_poolconf("h1", "master\n")
    assert rep._section["pool_conf"] == "master"
