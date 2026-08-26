# -*- coding: utf-8 -*-
"""Collector logic that is pure enough to test off-host.

The collector itself has to run under Python 2.7 as well as 3.6; these tests run under
whatever the dev machine has, so they only cover the parts that do no I/O. The 2.7 side
is exercised for real by every run against an 8.2.1 pool, which has no python3.
"""

import collector


def test_patch_predicate_updated_always_counts():
    assert collector._is_patch_line("Updated", "zlib-1.2-3.x86_64") is True


def test_patch_predicate_installed_only_for_kernel_and_xen():
    # yum installs a new kernel BESIDE the old one rather than upgrading it, so that is
    # an XCP-ng update too
    assert collector._is_patch_line("Installed", "kernel-4.19.x86_64") is True
    assert collector._is_patch_line("Installed", "xen-dom0-tools-4.13.x86_64") is True
    # ...but a plain Installed of anything else is a NEW package, not a patch. This is
    # the line that stops the script's own sshpass install from redating the host.
    assert collector._is_patch_line("Installed", "sshpass-1.06-2.el7.x86_64") is False
    assert collector._is_patch_line("Installed", "tmux-1.8-4.el7.x86_64") is False


YUM_LOG = """Dec 16 05:02:09 Installed: tmux-1.8-4.el7.x86_64
Dec 16 05:04:12 Erased: tmux-1.8-4.el7.x86_64
Dec 15 03:14:25 Updated: xen-dom0-tools-4.13.5-9.49.4.xcpng8.2.x86_64
Dec 16 05:14:25 Updated: kernel-4.19.0-1.x86_64
"""


def test_find_last_update_line_takes_the_last_match_in_file_order():
    assert collector.find_last_update_line(YUM_LOG) == (
        "Dec", 16, "05:14:25", "kernel-4.19.0-1.x86_64")


def test_find_last_update_line_ignores_a_lone_sshpass_install():
    # exactly what the live 8.2.1 host's yum.log holds, left there by a host-mode run
    assert collector.find_last_update_line(
        "Aug 15 01:12:05 Installed: sshpass-1.06-2.el7.x86_64\n") is None


def test_find_last_update_line_handles_single_digit_days():
    assert collector.find_last_update_line(
        "Aug  5 01:12:05 Updated: zlib-1.2-3.x86_64\n") == ("Aug", 5, "01:12:05",
                                                            "zlib-1.2-3.x86_64")


def test_find_last_update_line_empty():
    assert collector.find_last_update_line("") is None
    assert collector.find_last_update_line("garbage\n") is None


def test_year_fallback_uses_the_log_file_mtime_not_today():
    import calendar
    import time

    # a file rotated 2026-01-05; its last line is from December, which belongs to 2025
    mtime = calendar.timegm(time.struct_time((2026, 1, 5, 12, 0, 0, 0, 5, 0)))
    mtime -= time.timezone if not time.daylight else time.timezone
    epoch = collector._year_from_logline("Dec", 20, "10:00:00", mtime)
    assert epoch is not None
    assert time.localtime(epoch).tm_year == 2025
    assert time.localtime(epoch).tm_mon == 12


def test_year_fallback_same_year_when_it_fits():
    import time
    mtime = time.mktime((2026, 8, 20, 12, 0, 0, 0, 0, -1))
    epoch = collector._year_from_logline("Aug", 15, "01:12:05", mtime)
    assert time.localtime(epoch).tm_year == 2026
    assert time.localtime(epoch).tm_mon == 8


YUM_CHECK = """Loaded plugins: fastestmirror

kernel.x86_64                    4.19.0-1.xcpng8.3            xcp-ng-updates
xapi-core.x86_64                 25.6.0-1.xcpng8.3            xcp-ng-updates
a-very-long-package-name-that-yum-wrapped.noarch
                                 1.2.3-4.xcpng8.3             xcp-ng-updates
"""


def test_count_yum_updates_counts_wrapped_rows_once():
    assert collector.count_yum_updates(YUM_CHECK) == 3


def test_count_yum_updates_stops_at_obsoleting_packages():
    text = YUM_CHECK + "Obsoleting Packages\nfoo.x86_64   1-1   repo\n"
    assert collector.count_yum_updates(text) == 3


def test_count_yum_updates_empty():
    assert collector.count_yum_updates("") == 0
    assert collector.count_yum_updates("Loaded plugins: x\n") == 0


TASK_TIMEOUT_CONF = """# a drop-in that support left behind
pending_task_timeout = 86400
#pending_task_timeout = 1
  pending_task_timeout=3600
other_setting = 5
xpending_task_timeout = 9
"""


def test_task_timeout_values_reads_only_live_settings():
    # leading whitespace is allowed, a commented-out line is not a setting, and the key
    # has to START the line - 'xpending_task_timeout' is a different setting entirely
    assert collector.task_timeout_values(TASK_TIMEOUT_CONF) == ["86400", "3600"]


def test_task_timeout_values_strips_all_whitespace_from_the_value():
    # '1 hour' becomes '1hour': the line is a verbatim echo of whatever is configured,
    # and this is what the bash script it was ported from does
    assert collector.task_timeout_values("pending_task_timeout = 1 hour\n") == ["1hour"]
    # a setting with no value at all is not a value
    assert collector.task_timeout_values("pending_task_timeout =   \n") == []


def test_task_timeout_values_on_nothing():
    assert collector.task_timeout_values("") == []
    assert collector.task_timeout_values("# nothing to see\n") == []


def test_task_timeout_values_tolerates_crlf():
    assert collector.task_timeout_values("pending_task_timeout = 42\r\n") == ["42"]


def test_task_timeout_collection_states(tmp_path, monkeypatch):
    # no drop-in directory at all is a real answer - 'no override' - not an error
    monkeypatch.setattr(collector, "TASK_TIMEOUT_CONF_DIR", str(tmp_path / "absent"))
    assert collector.collect_task_timeout_override() == {"ok": True, "value": []}

    conf = tmp_path / "xapi.conf.d"
    conf.mkdir()
    monkeypatch.setattr(collector, "TASK_TIMEOUT_CONF_DIR", str(conf))
    assert collector.collect_task_timeout_override() == {"ok": True, "value": []}

    # files are read in name order, so the reported values do not shuffle between runs
    (conf / "20-later.conf").write_text("pending_task_timeout = 2\n")
    (conf / "10-first.conf").write_text("pending_task_timeout = 1\n")
    (conf / ".10-first.conf.swp").write_text("pending_task_timeout = 999\n")
    (conf / "subdir").mkdir()
    assert collector.collect_task_timeout_override() == {"ok": True, "value": ["1", "2"]}


def test_other_config_parse_matches_the_local_one():
    import parsers
    text = "xo:clientInfo:ab-cd: {\"a\":1}; xo:backupNetwork: 1234"
    assert collector.parse_other_config(text) == parsers.parse_other_config(text)


def test_fact_envelope_shape():
    assert collector.fact(3) == {"ok": True, "value": 3}
    assert collector.err("why") == {"ok": False, "error": "why"}


def test_decode_never_raises_on_non_utf8():
    # a single mojibake line in a log must never abort a health check
    assert collector._decode(b"ok \xff\xfe bytes").startswith("ok ")
