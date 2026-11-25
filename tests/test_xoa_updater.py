# -*- coding: utf-8 -*-
"""The XOA section's own facts: each read for what it is, and a failure never read as an
answer (audit 2026-11-24, F03/F04/F16/F18/F22).

Every xoa-updater call used to be read without looking at its exit status, so the error
text of a failed call became the answer: the first word of an error was printed as a
green plan, any licence output that was not exactly '[]' read as Bound, and a failed
isRegistered was an 'Unregistered' finding the appliance never earned.
"""

import os

import pytest

import config
import parsers
import result
import transport
import xoa


MANIFEST = """{
  channel: 'stable',
  npm: {
    'xen-orchestra': '6.9.2',
    'xo-server-audit-premium': '0.15.1',
  }
}
"""

STATUS = "stable channel selected\nAll up to date\n"


def updater(answers):
    """A run_local_cmd that answers xoa-updater/xoa/systemctl from a table keyed by the
    argument tuple after the command name."""
    def fake(argv, timeout, env=None, stdin_text=None):
        key = tuple(argv)
        if key == ("systemctl", "is-active", "xoa-updater"):
            return (0, "active\n", "")
        if key in answers:
            return answers[key]
        raise AssertionError("unexpected command %r" % (argv,))
    return fake


def healthy(overrides=None):
    table = {
        ("xoa-updater",): (0, STATUS, ""),
        ("xoa-updater", "raw-api-call", "isRegistered"):
            (0, "{ registered: true, email: 'ops@example.com' }\n", ""),
        ("xoa-updater", "raw-api-call", "getLocalManifest"): (0, MANIFEST, ""),
        ("xoa-updater", "raw-api-call", "getXoaPlan"): (0, "Premium\n", ""),
        # the shape measured on 6.9.2: a newline and the updater's info glyph come first
        ("xoa-updater", "raw-api-call", "getSelfLicenses"):
            (0, u"\nℹ [\n  { created: 1, productId: 'premium' }\n]\n", ""),
        ("xoa", "check"): (0, "", ""),
    }
    table.update(overrides or {})
    return table


def section(monkeypatch, table):
    monkeypatch.setattr(transport, "run_local_cmd", updater(table))
    monkeypatch.setattr(xoa, "scan_plugins", lambda: ([], []))
    monkeypatch.setattr(xoa, "_plugin_autoload", lambda: ({}, False))
    monkeypatch.setattr(xoa, "_os_version", lambda: "Debian 12")
    monkeypatch.setattr(xoa, "_meminfo", lambda: None)
    monkeypatch.setattr(xoa, "_dmesg", lambda: None)
    return {ln.key: ln for ln in xoa.lines()}


def test_a_healthy_appliance_reads_every_line_green(monkeypatch):
    lines = section(monkeypatch, healthy())
    for key in ("Registration", "XOA Channel", "XOA Version", "XOA Plan", "XOA Status",
                "XOA Check"):
        assert not lines[key].flags, lines[key].render()
    assert "ops@example.com" in lines["Registration"].text
    assert "6.9.2" in lines["XOA Version"].text
    assert "Bound" in lines["XOA Plan"].text


def test_a_failed_plan_call_is_not_a_plan(monkeypatch):
    """The first word of an error message used to be printed, green, as the plan."""
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "getXoaPlan"):
            (1, "Error: connect ECONNREFUSED 127.0.0.1:9001\n", "")}))
    assert lines["XOA Plan"].flags
    assert "Error" not in lines["XOA Plan"].text.split("(")[0]
    assert "getXoaPlan exited 1" in lines["XOA Plan"].text


def test_a_failed_licence_call_is_not_bound(monkeypatch):
    """Anything but '[]' used to read as Bound - an error message included."""
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "getSelfLicenses"): (1, "Error: timeout\n", "")}))
    assert lines["XOA Plan"].flags
    assert "Bound" not in lines["XOA Plan"].text.replace("Unbound", "")


def test_licence_output_that_is_not_an_array_is_unknown(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "getSelfLicenses"): (0, "undefined\n", "")}))
    assert lines["XOA Plan"].flags
    assert "Unknown" in lines["XOA Plan"].text


def test_no_licence_bound_is_unbound(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "getSelfLicenses"): (0, u"\nℹ []\n", "")}))
    assert lines["XOA Plan"].flags and "Unbound" in lines["XOA Plan"].text


def test_a_failed_registration_call_is_unknown_not_unregistered(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "isRegistered"): (1, "Error: socket hang up\n", "")}))
    assert lines["Registration"].status == result.UNKNOWN
    assert "Unregistered" not in lines["Registration"].text
    assert "isRegistered exited 1" in lines["Registration"].text


def test_an_unregistered_appliance_still_flags(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "isRegistered"): (0, "{ registered: false }\n", "")}))
    assert lines["Registration"].status == result.FLAG
    assert "Unregistered" in lines["Registration"].text


@pytest.mark.parametrize("answer, email", [
    ("{ registered: true, email: \"o'brien@example.com\" }", "o'brien@example.com"),
    ("{ registered: true, email: `it's \"x\"@example.com` }", "it's \"x\"@example.com"),
])
def test_util_inspect_quotes_are_read_whichever_it_picked(monkeypatch, answer, email):
    """An address with an apostrophe is quoted with \" by util.inspect: it used to read as
    'Unregistered' (F21)."""
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "isRegistered"): (0, answer + "\n", "")}))
    assert not lines["Registration"].flags
    assert email in lines["Registration"].text


def test_registered_without_a_readable_email_is_still_registered(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "isRegistered"): (0, "{ registered: true }\n", "")}))
    assert not lines["Registration"].flags


def test_an_unreadable_registration_answer_is_unknown(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "isRegistered"): (0, "something new\n", "")}))
    assert lines["Registration"].status == result.UNKNOWN


def test_a_failed_status_call_is_not_updates_available(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater",): (1, "Error: something broke\n", "")}))
    assert lines["XOA Status"].status == result.UNKNOWN
    assert "Updates available" not in lines["XOA Status"].text


def test_a_failed_manifest_call_says_why(monkeypatch):
    lines = section(monkeypatch, healthy({
        ("xoa-updater", "raw-api-call", "getLocalManifest"): (1, "Error: nope\n", "")}))
    assert lines["XOA Version"].status == result.UNKNOWN
    assert "getLocalManifest exited 1" in lines["XOA Version"].text


def test_a_missing_xoa_command_is_unknown_not_all_ok(monkeypatch):
    """rc 127 has nothing on stderr, which used to read as 'All OK'."""
    lines = section(monkeypatch, healthy({("xoa", "check"): (127, "", "")}))
    assert lines["XOA Check"].status == result.UNKNOWN


# --------------------------------------------------------------------------------------
# XO-Server Memory Limit (F04)
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("args, want", [
    (["node", "/usr/local/bin/xo-server"], None),
    (["node", "--max-old-space-size=3584", "/usr/local/bin/xo-server"], 3584),
    (["node", "--max_old_space_size=2048", "x"], 2048),
    (["node", "--max-old-space-size", "4096", "x"], 4096),
    (["node", "--max-old-space-size=1000", "--max-old-space-size=3000", "x"], 3000),
    (["node", "--max-old-space-size-x=1000", "x"], None),
    ([], None),
])
def test_node_heap_flag(args, want):
    assert parsers.node_heap_flag(args) == want


def test_a_limit_below_seventy_percent_flags():
    line = xoa.heap_limit_line(3911, 2003, "node's default, nothing sets it", None)
    assert line.flags
    assert "2003 MB" in line.text and "51%" in line.text and "2737 MB" in line.text


def test_a_limit_at_or_above_seventy_percent_is_green():
    assert not xoa.heap_limit_line(3911, 3584, "set on its command line", None).flags
    assert not xoa.heap_limit_line(3911, 2737, "set on its command line", None).flags


def test_the_one_gib_floor_applies_on_a_small_appliance():
    assert xoa.heap_limit_line(1200, 900, "set on its command line", None).flags
    assert not xoa.heap_limit_line(1200, 1024, "set on its command line", None).flags


def test_an_unread_limit_is_unknown():
    line = xoa.heap_limit_line(3911, None, None, "xo-server is not running")
    assert line.status == result.UNKNOWN and "not running" in line.text


def _proc(monkeypatch, tmp_path, pid, argv, environ, main_pid=None, probe=(0, "", "")):
    procdir = tmp_path / "proc" / str(pid)
    procdir.mkdir(parents=True)
    (procdir / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (procdir / "environ").write_bytes(b"\0".join(e.encode() for e in environ) + b"\0")
    real_open = open

    def fake_open(path, *a, **kw):
        if isinstance(path, str) and path.startswith("/proc/"):
            path = str(tmp_path / path.lstrip("/"))
        return real_open(path, *a, **kw)

    calls = []

    def fake_run(argv_, timeout, env=None, stdin_text=None):
        calls.append((argv_, env))
        if argv_[0] == "systemctl":
            return (0, "%s\n" % (pid if main_pid is None else main_pid), "")
        return probe

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(os, "readlink", lambda p: "/usr/local/bin/node")
    monkeypatch.setattr(transport, "run_local_cmd", fake_run)
    return calls


def test_the_command_line_beats_node_options(monkeypatch, tmp_path):
    """node applies NODE_OPTIONS first and its own argv after, so argv wins."""
    _proc(monkeypatch, tmp_path, 4242,
          ["node", "--max-old-space-size=3000", "/usr/local/bin/xo-server"],
          ["NODE_OPTIONS=--max-old-space-size=1000"])
    assert xoa._xo_server_heap() == (3000, "set on its command line", None)


def test_node_options_is_read_when_the_command_line_has_none(monkeypatch, tmp_path):
    _proc(monkeypatch, tmp_path, 4242, ["node", "/usr/local/bin/xo-server"],
          ["PATH=/usr/bin", "NODE_OPTIONS=--trace-warnings --max-old-space-size=2500"])
    assert xoa._xo_server_heap() == (2500, "set in NODE_OPTIONS", None)


def test_with_nothing_set_node_s_default_is_measured(monkeypatch, tmp_path):
    """The number the process actually runs with, from the same node binary, with no
    NODE_OPTIONS of this run's own leaking into the probe."""
    monkeypatch.setenv("NODE_OPTIONS", "--max-old-space-size=99999")
    calls = _proc(monkeypatch, tmp_path, 4242, ["node", "/usr/local/bin/xo-server"],
                  ["PATH=/usr/bin"], probe=(0, str(2101346304), ""))
    limit, source, error = xoa._xo_server_heap()
    assert (limit, error) == (2004, None) and "default" in source
    probe_argv, probe_env = calls[-1]
    assert probe_argv[0] == "/usr/local/bin/node"
    assert "NODE_OPTIONS" not in probe_env


def test_a_stopped_xo_server_is_unknown(monkeypatch, tmp_path):
    _proc(monkeypatch, tmp_path, 4242, ["node"], [], main_pid=0)
    limit, _source, error = xoa._xo_server_heap()
    assert limit is None and error == "xo-server is not running"


def test_a_failed_probe_is_unknown(monkeypatch, tmp_path):
    _proc(monkeypatch, tmp_path, 4242, ["node", "/usr/local/bin/xo-server"], [],
          probe=(124, "", ""))
    limit, _source, error = xoa._xo_server_heap()
    assert limit is None and "timed out" in error


def test_no_meminfo_still_prints_the_limit_line_as_unknown(monkeypatch):
    """Skipping it would read as 'not applicable'."""
    lines = section(monkeypatch, healthy())
    assert lines["XO-Server Memory Limit"].status == result.UNKNOWN


# --------------------------------------------------------------------------------------
# ping, the Debian gate, OS Version (F16, F18, F22)
# --------------------------------------------------------------------------------------

def test_a_ping_that_never_finished_is_silent(monkeypatch):
    # ping_silent waits LOCAL_CMD_TIMEOUT + 5 for its probes: make that 0.2 s
    monkeypatch.setattr(config, "LOCAL_CMD_TIMEOUT", -4.8)

    def fake(argv, timeout, env=None, stdin_text=None):
        if argv[-1] == "192.0.2.9":
            import time
            time.sleep(1.0)
        return (0, "", "")
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    assert xoa.ping_silent(["192.0.2.1", "192.0.2.9"]) == ["192.0.2.9"]


def _os_release(monkeypatch, tmp_path, text):
    path = tmp_path / "os-release"
    path.write_text(text)
    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **kw: real_open(
        str(path) if p == "/etc/os-release" else p, *a, **kw))


@pytest.mark.parametrize("text, ok", [
    ('ID=debian\nVERSION_ID="12"\n', True),
    ('ID=debian\nVERSION_ID="10"\n', False),
    ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\n', True),
    ('ID=fedora\nVERSION_ID=40\n', False),
    ('ID=debian\n', False),
])
def test_the_debian_gate_needs_debian(monkeypatch, tmp_path, text, ok):
    _os_release(monkeypatch, tmp_path, text)
    assert xoa.debian_version_ok()[0] is ok


def test_os_version_comes_from_os_release_without_lsb_release(monkeypatch, tmp_path):
    _os_release(monkeypatch, tmp_path,
                'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\n')
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda *a, **kw: pytest.fail("lsb_release should not be needed"))
    assert xoa._os_version() == "Debian GNU/Linux 12 (bookworm)"
