# -*- coding: utf-8 -*-
"""--json is the same run, written as a document.

The point of these tests is that it is not a second opinion: the same Lines feed both, so
the two modes must agree about which checks appeared, what they said, whether each one
counts against the run, and what the run exits with. Anywhere they could disagree is a
place a monitoring consumer would silently be told something the report does not say.
"""

import io
import json

import colors
import config
import model
import report
import result


def build(rep):
    """One run's worth of lines, driven exactly the way main() drives a report."""
    host_a = model.Host("10.0.0.1", "uuid-a", "alpha")
    host_a.payload = {"hostname": {"ok": True, "value": "alpha"}}
    host_a.is_master = True
    host_b = model.Host("10.0.0.2", "uuid-b", "beta")
    host_b.error = "ssh to 10.0.0.2 failed (exit 255)"

    rep.begin_section("xoa")
    rep.heading("== XOA Status ==")
    rep.add(result.ok("Registration", "someone@example.com"))
    rep.add(result.flag("XOA Status", "Updates available"))
    rep.end_section()

    rep.heading("== Pool Status ==")
    rep.begin_section("pool")
    rep.add(result.info("Pool Master", "alpha (10.0.0.1)"))
    rep.add(result.flag("Unreachable Hosts", "10.0.0.2"))
    rep.add(result.info("XOSTOR In Use", "Yes"))       # yellow, but NOT a finding
    rep.end_section()

    rep.begin_section("host", host_a)
    rep.add(result.ok("Dom0 Disk Usage", "OK"))
    rep.add(result.unknown("Log Errors", "Unknown (could not read)"))
    rep.add(result.flag("Dmesg Content", "Issues Found").with_detail("Dmesg Issues", "  oops"))
    rep.add_poolconf(host_a.label, "master\nnoise\n")
    rep.end_section()

    rep.unreachable_host(host_b)
    rep.print_poolconf_section()
    return rep.finish()


def run_both(filter_output=False):
    colors.init(io.StringIO())
    text_rep = report.Report(filter_output, io.StringIO())
    text_rc = build(text_rep)

    json_rep = report.Report(filter_output, io.StringIO(), json_mode=True,
                             meta={"run": {"environment": "xoa", "filtered": filter_output}})
    json_rc = build(json_rep)
    doc = json.loads(json_rep.stream.getvalue())
    return text_rep.stream.getvalue(), text_rc, doc, json_rc


def entries(doc):
    out = list(doc.get("xoa", {}).get("checks", []))
    out += doc.get("pool", {}).get("checks", [])
    for host in doc.get("hosts", []):
        out += host.get("checks", [])
    return out


# --------------------------------------------------------------------------------------
# the two modes cannot disagree
# --------------------------------------------------------------------------------------

def test_the_document_lists_exactly_the_lines_the_report_printed():
    text, _rc, doc, _jrc = run_both()
    printed = [line for line in text.splitlines()
               if ": " in line and not line.startswith(" ")]
    rendered = ["%s: %s" % (e["key"], e["value"]) for e in entries(doc)]
    for line in rendered:
        assert line in printed, "%r is in the document but was never printed" % line
    # every 'Key: value' the report printed is a check, a heading, or the version line
    extra = [p for p in printed if p not in rendered]
    assert extra == ["Health Script Version: v" + config.SCRIPT_VERSION]


def test_f_narrows_both_the_same_way():
    text, _rc, doc, _jrc = run_both(filter_output=True)
    keys = [e["key"] for e in entries(doc)]
    # passing lines are gone from both
    assert "Dom0 Disk Usage" not in keys and "Dom0 Disk Usage" not in text
    assert "Registration" not in keys and "Registration" not in text
    # findings, unknowns and info lines survive in both
    for key in ("XOA Status", "Unreachable Hosts", "XOSTOR In Use", "Log Errors",
                "Dmesg Content", "Pool Master"):
        assert key in keys and key in text, key


def test_the_exit_code_is_the_same_in_both_modes():
    _text, text_rc, doc, json_rc = run_both()
    assert text_rc == json_rc == 1
    assert doc["exit_code"] == 1 and doc["flagged"] is True


def test_a_clean_run_exits_zero_in_both_modes():
    colors.init(io.StringIO())
    for json_mode in (False, True):
        rep = report.Report(False, io.StringIO(), json_mode=json_mode)
        rep.begin_section("pool")
        rep.add(result.ok("HA Enabled", "No"))
        rep.add(result.info("XOSTOR In Use", "Yes"))    # a fact, not a finding
        rep.end_section()
        assert rep.finish() == 0


# --------------------------------------------------------------------------------------
# the document's own shape
# --------------------------------------------------------------------------------------

def test_stdout_carries_the_document_and_nothing_else():
    colors.init(io.StringIO())
    rep = report.Report(False, io.StringIO(), json_mode=True)
    build(rep)
    raw = rep.stream.getvalue()
    # headings, blank lines, detail blobs and the pool.conf block are all suppressed at
    # write(), so a consumer can json.load() stdout directly
    assert raw.lstrip().startswith("{")
    assert "== Pool Status ==" not in raw.split('"value"')[0]
    json.loads(raw)


def test_flags_is_carried_not_left_to_be_derived_from_the_colour():
    _text, _rc, doc, _jrc = run_both()
    by_key = dict((e["key"], e) for e in entries(doc))
    assert by_key["Dom0 Disk Usage"]["status"] == "ok" and not by_key["Dom0 Disk Usage"]["flags"]
    assert by_key["XOA Status"]["status"] == "flag" and by_key["XOA Status"]["flags"]
    assert by_key["Log Errors"]["status"] == "unknown" and by_key["Log Errors"]["flags"]
    # yellow, always printed, and deliberately NOT counted against the run
    assert by_key["XOSTOR In Use"]["status"] == "info"
    assert by_key["XOSTOR In Use"]["flags"] is False


def test_an_unreachable_host_has_no_checks_key_at_all():
    """An empty list would be summed as zero findings, which is the exact claim the whole
    tool exists to avoid making."""
    _text, _rc, doc, _jrc = run_both()
    hosts = dict((h["address"], h) for h in doc["hosts"])
    assert hosts["10.0.0.1"]["reachable"] is True
    assert hosts["10.0.0.2"]["reachable"] is False
    assert "checks" not in hosts["10.0.0.2"]
    assert "checks" in hosts["10.0.0.1"]
    assert "exit 255" in hosts["10.0.0.2"]["error"]


def test_host_identity_and_pool_conf_ride_with_the_host():
    _text, _rc, doc, _jrc = run_both()
    alpha = doc["hosts"][0]
    assert alpha["name"] == "alpha" and alpha["address"] == "10.0.0.1"
    assert alpha["master"] is True
    # the rendered report defers this to a block at the end that a consumer would have to
    # re-attribute by matching host labels
    assert alpha["pool_conf"] == "master"


def test_detail_blobs_attach_to_the_line_that_produced_them():
    _text, _rc, doc, _jrc = run_both()
    by_key = dict((e["key"], e) for e in entries(doc))
    assert by_key["Dmesg Content"]["detail"] == {"title": "Dmesg Issues", "text": "  oops"}
    assert "detail" not in by_key["Dom0 Disk Usage"]


def test_the_head_of_the_document_says_what_the_run_was():
    _text, _rc, doc, _jrc = run_both()
    assert doc["script_version"] == config.SCRIPT_VERSION
    assert doc["run"]["environment"] == "xoa"


def test_the_host_counts_do_not_overclaim():
    """'checked' means answered, not attempted. A run that reached one host of a two-host
    pool must not be summarised as having checked two."""
    import main

    run = main.Run()
    run.run_env = "xoa"
    run.pool_size = 3                     # xapi says three members
    reached = model.Host("10.0.0.1")
    reached.payload = {}                  # a document arrived, however sparse
    run.hosts = [reached, model.Host("10.0.0.2")]   # ...and one never answered
    meta = main.run_meta(run)["run"]
    assert meta["hosts_in_pool"] == 3
    assert meta["hosts_attempted"] == 2
    assert meta["hosts_checked"] == 1


def test_odd_bytes_from_a_log_survive_the_document_unchanged():
    """Log excerpts arrive as whatever the host had, already decoded with a replacing
    error handler. The document must stay pure ASCII so no locale a cron job runs under
    can mangle it, and the text must come back out of a parser exactly as it went in."""
    colors.init(io.StringIO())
    host = model.Host("10.0.0.1")
    host.payload = {}
    rep = report.Report(False, io.StringIO(), json_mode=True)
    rep.begin_section("host", host)
    odd = u"xapi: café — \\xff\\xfe and a control  char\ttabbed"
    rep.add(result.flag("Log Errors", "Yes").with_detail("Log Errors", odd))
    rep.end_section()
    rep.finish()

    raw = rep.stream.getvalue()
    assert all(ord(c) < 128 for c in raw), "the document is not pure ASCII"
    doc = json.loads(raw)
    assert doc["hosts"][0]["checks"][0]["detail"]["text"] == odd


def test_no_timestamp_so_two_runs_of_a_stable_pool_diff_to_nothing():
    first = run_both()[2]
    second = run_both()[2]
    assert first == second


def test_colours_are_forced_off_even_when_the_environment_asks_for_them(monkeypatch):
    monkeypatch.setenv("HEALTH_FORCE_COLOR", "1")
    colors.init(force_off=True)
    try:
        rep = report.Report(False, io.StringIO(), json_mode=True)
        rep.begin_section("pool")
        rep.add(result.ok("HA Enabled", "No"))
        rep.end_section()
        rep.finish()
        doc = json.loads(rep.stream.getvalue())
        assert doc["pool"]["checks"][0]["value"] == "No"
        assert "\033" not in rep.stream.getvalue()
    finally:
        colors.init(io.StringIO())


def test_the_rendered_report_is_untouched_by_any_of_this():
    """The pool.conf block carries its own trailing spacing; putting it through the
    line-writer would have quietly reshaped the report."""
    colors.init(io.StringIO())
    rep = report.Report(False, io.StringIO())
    rep.add_poolconf("h (1.2.3.4)", "master\r\nsomething else\n")
    rep.add_poolconf("g (1.2.3.5)", "slave:1.2.3.4\n")
    rep.print_poolconf_section()
    assert rep.stream.getvalue().endswith("h (1.2.3.4)\nmaster\n\ng (1.2.3.5)\nslave:1.2.3.4\n\n")
