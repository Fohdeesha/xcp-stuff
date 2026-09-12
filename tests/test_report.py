# -*- coding: utf-8 -*-
"""Rendering, -f filtering, exit-code aggregation, and the crash guard."""

import io

import colors
import report
import result


def new_report(filter_output=False):
    colors.init(io.StringIO())        # no tty, so no escape codes in the assertions
    return report.Report(filter_output, io.StringIO())


def text(rep):
    return rep.stream.getvalue()


def test_passing_lines_are_hidden_by_f_and_findings_are_not():
    rep = new_report(filter_output=True)
    rep.add(result.ok("Green", "OK"))
    rep.add(result.flag("Yellow", "Fail"))
    rep.add(result.unknown("Grey", "Unknown"))
    out = text(rep)
    assert "Green" not in out
    assert "Yellow: Fail" in out
    assert "Grey: Unknown" in out


def test_f_hides_readings_and_keeps_warnings():
    """-f is 'show me what is wrong'. A green reading is not that; a yellow one is - it
    is a fact the run failed to establish, and hiding it is the silent green the whole
    tool is built against."""
    rep = new_report(filter_output=True)
    rep.add(result.info("Multipathing", "true"))
    rep.add(result.raw("Last Booted", "2026-08-24 07:08:20"))
    rep.add(result.info("Host Enabled", "Unknown", "yellow"))
    out = text(rep)
    assert "Multipathing" not in out and "Last Booted" not in out
    assert "Host Enabled: Unknown" in out
    assert rep.finish() == 0                  # ...and none of them flagged


def test_a_pinned_info_line_survives_f():
    rep = new_report(filter_output=True)
    rep.add(result.pinned(result.info("Hypervisor Version", "XCP-ng 8.3.0")))
    assert "Hypervisor Version: XCP-ng 8.3.0" in text(rep)
    assert rep.finish() == 0


def test_a_heading_over_nothing_is_dropped_under_f():
    """An empty '== Pool Status ==' reads as a section that passed, or as one whose
    findings went missing. Both are claims the section did not earn."""
    rep = new_report(filter_output=True)
    rep.heading("== Pool Status ==")
    rep.begin_section("pool")
    rep.add(result.ok("Green", "OK"))
    rep.blank()
    rep.end_section()

    rep.heading("== Individual Hosts ==")
    rep.begin_section("host")
    rep.add(result.flag("Yellow", "Fail"))
    rep.end_section()

    out = text(rep)
    assert "== Pool Status ==" not in out
    assert "== Individual Hosts ==" in out
    # the dropped section's own separator went with it, so nothing precedes the heading
    assert out.startswith("== Individual Hosts ==\n")


def test_headings_always_print_without_f():
    rep = new_report()
    rep.heading("== Pool Status ==")
    rep.begin_section("pool")
    rep.end_section()
    assert "== Pool Status ==" in text(rep)


def test_exit_code_is_one_when_anything_flagged_or_unknown():
    rep = new_report()
    rep.add(result.ok("A", "OK"))
    assert rep.finish() == 0

    rep = new_report()
    rep.add(result.unknown("B", "Unknown"))
    assert rep.finish() == 1

    rep = new_report()
    rep.add(result.flag("C", "Fail"))
    assert rep.finish() == 1


def test_the_version_is_the_last_line_of_every_run_even_under_f():
    rep = new_report(filter_output=True)
    rep.finish()
    lines = [l for l in text(rep).splitlines() if l.strip()]
    assert lines[-1].startswith("Health Script Version: v")


def test_details_are_deferred_pool_first_then_hosts():
    rep = new_report()
    rep.add(result.flag("A", "x").with_detail("Host Thing", "host body"), "hostx (1.2.3.4)")
    rep.add(result.flag("B", "y").with_detail("---pool thing---", "pool body"))
    rep.finish()
    out = text(rep)
    assert out.index("---pool thing---") < out.index("hostx (1.2.3.4) - Host Thing")
    assert "pool body" in out and "host body" in out


def test_a_check_that_raises_becomes_a_yellow_unknown_and_the_run_continues():
    def explode(_host):
        raise ValueError("boom")

    rep = new_report()
    rep.check("Wobbly", explode, None)
    rep.add(result.ok("After", "OK"))
    out = text(rep)
    assert "Wobbly: Unknown (internal error: boom)" in out
    assert "After: OK" in out             # the run carried on
    assert rep.finish() == 1              # ...and it still flags


def test_a_check_returning_several_lines():
    rep = new_report()
    rep.check("Pair", lambda: [result.ok("A", "1"), result.flag("B", "2")])
    out = text(rep)
    assert "A: 1" in out and "B: 2" in out
    assert rep.finish() == 1


def test_poolconf_summary_takes_only_the_first_line():
    rep = new_report()
    rep.add_poolconf("h (1.2.3.4)", "master\r\nsomething else\n")
    rep.print_poolconf_section()
    assert "h (1.2.3.4)\nmaster\n\n" in text(rep)


def test_poolconf_is_dropped_whole_under_f():
    """Every host's role, and no state of it is a finding - so -f has no use for it."""
    rep = new_report(filter_output=True)
    rep.add_poolconf("h (1.2.3.4)", "master\n")
    rep.print_poolconf_section()
    out = text(rep)
    assert "pool.conf" not in out and "master" not in out


def test_a_run_with_no_findings_under_f_is_just_the_version_line():
    rep = new_report(filter_output=True)
    rep.heading("== Pool Status ==")
    rep.begin_section("pool")
    rep.add(result.ok("Green", "OK"))
    rep.end_section()
    rep.finish()
    assert "== Pool Status ==" not in text(rep)
    lines = [l for l in text(rep).splitlines() if l.strip()]
    assert len(lines) == 1 and lines[0].startswith("Health Script Version: v")


def test_colours_only_when_asked():
    colors.init(io.StringIO())            # not a tty
    assert colors.green("x") == "x"
    import os
    os.environ["HEALTH_FORCE_COLOR"] = "1"
    try:
        colors.init(io.StringIO())
        assert colors.green("x") == "\033[32mx\033[0m"
    finally:
        del os.environ["HEALTH_FORCE_COLOR"]
        colors.init(io.StringIO())


def test_strip_ansi():
    assert colors.strip_ansi("\033[32mgreen\033[0m and \033[1;33mmore\033[0m") == "green and more"
