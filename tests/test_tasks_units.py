# -*- coding: utf-8 -*-
"""Long-Running Tasks and Failed Systemd Units.

The fixtures are the shapes read off an 8.3 lab host: xe task-list's labelled records, and
'systemctl --failed --no-legend --plain' with an escaped SMGC instance name. Uuids are made up.
"""

import calendar
import time

import checks
import config
import model
import parsers
import result

OK, FLAG, UNKNOWN, INFO = result.OK, result.FLAG, result.UNKNOWN, result.INFO

NOW = calendar.timegm((2026, 11, 7, 12, 0, 0, 0, 0, 0))
HOST = "aaaaaaaa-0000-0000-0000-000000000001"


def task(uuid, name, status, created, progress="0.000", host=HOST):
    return ("uuid ( RO)           : %s\n     name-label ( RO): %s\n    resident-on ( RO): %s\n"
            "         status ( RO): %s\n       progress ( RO): %s\n        created ( RO): %s\n\n\n"
            % (uuid, name, host, status, progress, created))


def stamp(hours_ago):
    return "%04d%02d%02dT%02d:%02d:%02dZ" % time.gmtime(NOW - hours_ago * 3600)[:6]


def pool(**facts):
    p = model.Pool()
    p.payload = dict(facts)
    return p


def tasks_fact(text, now=NOW):
    return {"ok": True, "value": {"text": text, "now": now}}


MAX = config.TASK_PENDING_MAX_HOURS * 3600


# --------------------------------------------------------------------------------------
# Long-Running Tasks
# --------------------------------------------------------------------------------------

def test_the_stamp_xapi_prints_is_read_as_utc():
    assert parsers.xapi_utc("20261106T19:39:59Z") == calendar.timegm((2026, 11, 6, 19, 39, 59, 0, 0, 0))
    assert parsers.xapi_utc("2026-11-06 19:39") is None
    assert parsers.xapi_utc(None) is None


def test_no_task_at_all_is_none():
    assert parsers.parse_pending_tasks("", NOW, MAX) == []


def test_only_a_pending_task_over_the_limit_counts():
    text = (task("t-old", "VM.export", "pending", stamp(17), "0.420") +
            task("t-young", "VM.export", "pending", stamp(15)) +
            task("t-done", "VM.start", "success", stamp(30), "1.000") +
            task("t-older", "VDI.copy", "pending", stamp(20)))
    old = parsers.parse_pending_tasks(text, NOW, MAX)
    assert [t[1] for t in old] == ["t-older", "t-old"]
    assert old[1][3] == "0.420"


def test_a_record_missing_a_field_or_an_odd_stamp_is_not_read_as_anything():
    good = task("t-1", "VM.export", "pending", stamp(1))
    assert parsers.parse_pending_tasks(good.replace("       progress ( RO): 0.000\n", ""), NOW, MAX) is None
    assert parsers.parse_pending_tasks(task("t-2", "x", "pending", "yesterday"), NOW, MAX) is None


def test_a_finished_task_with_an_odd_stamp_is_no_reason_to_give_up():
    assert parsers.parse_pending_tasks(task("t-3", "x", "success", "<unknown>"), NOW, MAX) == []


def test_check_none_and_yes():
    assert checks.long_running_tasks(pool(tasks=tasks_fact(""))).status == OK
    line = checks.long_running_tasks(pool(tasks=tasks_fact(
        task("t-old", "Async.VM.migrate_send", "pending", stamp(18), "0.130"))))
    assert line.status == FLAG
    assert line.text.endswith(" - 1 pending over 16h: Async.VM.migrate_send")
    assert "pending for 18.0h, progress 0.130" in line.detail_text


def test_check_names_the_host_when_the_pool_listing_has_it():
    hosts = "uuid ( RO)                 : %s\n           name-label ( RW): xen-a\n" \
            "    host-metrics-live ( RO): true\n\n\n" % HOST
    line = checks.long_running_tasks(pool(
        tasks=tasks_fact(task("t-old", "VM.export", "pending", stamp(20))),
        sr_attachment={"ok": True, "value": {"pbds": "", "srs": "", "hosts": hosts}}))
    assert "on xen-a" in line.detail_text


def test_check_unknown_without_the_fact_off_an_error_or_without_a_clock():
    for p in (pool(), pool(tasks={"ok": False, "error": "xe task-list failed (exit 1)"}),
              pool(tasks={"ok": True, "value": {"text": ""}}),
              pool(tasks=tasks_fact(task("t", "x", "pending", "garbage")))):
        line = checks.long_running_tasks(p)
        assert line.status == UNKNOWN and line.flags, line.text


# --------------------------------------------------------------------------------------
# Failed Systemd Units
# --------------------------------------------------------------------------------------

SMGC = ("SMGC@bbbbbbbb\\x2d0000\\x2d0000\\x2d0000\\x2d000000000001.service loaded failed failed "
        "Garbage Collector for SR bbbbbbbb-0000-0000-0000-000000000001\n")
STATIC = "attach-static-vdis.service loaded failed failed Attach statically-configured VDIs to dom0\n"


def host(**facts):
    h = model.Host("10.0.0.1", "uuid-1", "hostx", "true", "false")
    h.payload = dict(facts)
    return h


def test_units_are_read_with_their_description():
    assert parsers.parse_failed_units(STATIC + SMGC) == [
        ("attach-static-vdis.service", "Attach statically-configured VDIs to dom0"),
        ("SMGC@bbbbbbbb\\x2d0000\\x2d0000\\x2d0000\\x2d000000000001.service",
         "Garbage Collector for SR bbbbbbbb-0000-0000-0000-000000000001")]


def test_a_bullet_from_a_systemd_that_ignores_plain_is_dropped():
    assert parsers.parse_failed_units("● " + STATIC)[0][0] == "attach-static-vdis.service"


def test_an_escaped_name_is_shown_unescaped():
    assert parsers.unit_display("dev\\x2dsda1.mount") == "dev-sda1.mount"


def test_check_none_when_systemd_lists_nothing():
    assert checks.failed_units(host(failed_units={"ok": True, "value": ""})).status == OK


def test_check_leaves_gc_runs_out():
    line = checks.failed_units(host(failed_units={"ok": True, "value": SMGC}))
    assert line.status == OK


def test_check_flags_any_other_failed_unit():
    line = checks.failed_units(host(failed_units={"ok": True, "value": STATIC + SMGC}))
    assert line.status == FLAG
    assert line.text.endswith(" - attach-static-vdis.service")
    assert "SMGC" not in line.detail_text
    assert "Attach statically-configured VDIs to dom0" in line.detail_text


def test_check_unknown_without_the_fact_or_off_an_error():
    for h in (host(), host(failed_units={"ok": False, "error": "systemctl --failed failed (exit 1)"})):
        line = checks.failed_units(h)
        assert line.status == UNKNOWN and line.flags


# attach-static-vdis: the shape read off .34 - booted at BOOT, the unit failed 14.6 s in, and
# both entries were created four days later when HA was enabled again
BOOT = 1793679599


def sv(*created, mono=14600553):
    return {"ok": True, "value": {"exit_mono_us": mono,
                                  "entries": [{"name": str(i), "created": c} for i, c in enumerate(created)]}}


def static_host(static_vdis, boot={"ok": True, "value": BOOT}):
    return host(failed_units={"ok": True, "value": STATIC}, static_vdis=static_vdis, boot_epoch=boot)


def test_a_failure_with_no_entry_or_only_later_ones_is_about_nothing():
    assert parsers.static_vdis_failure_moot(sv()["value"], BOOT) is True
    assert parsers.static_vdis_failure_moot(sv(1793994407, 1793994410)["value"], BOOT) is True


def test_a_failure_with_an_entry_already_there_is_real():
    assert parsers.static_vdis_failure_moot(sv(BOOT - 86400, 1793994410)["value"], BOOT) is False


def test_a_failure_whose_times_were_not_read_is_not_established():
    assert parsers.static_vdis_failure_moot(sv(None)["value"], BOOT) is None
    assert parsers.static_vdis_failure_moot(sv(mono=0)["value"], BOOT) is None
    assert parsers.static_vdis_failure_moot(sv()["value"], None) is None
    assert parsers.static_vdis_failure_moot(None, BOOT) is None


def test_check_leaves_out_a_static_vdis_failure_about_nothing():
    assert checks.failed_units(static_host(sv(1793994407, 1793994410))).status == OK


def test_check_reports_a_static_vdis_failure_with_an_entry_already_there():
    line = checks.failed_units(static_host(sv(BOOT - 3600)))
    assert line.status == FLAG
    assert "a VDI HA needs (statefile or metadata) did not attach at boot" in line.detail_text


def test_check_reports_a_static_vdis_failure_it_could_not_judge_and_says_why():
    for h in (static_host({"ok": False, "error": "systemctl show failed (exit 1)"}),
              host(failed_units={"ok": True, "value": STATIC}),
              static_host(sv(1793994407), boot={"ok": False, "error": "no btime in /proc/stat"})):
        line = checks.failed_units(h)
        assert line.status == FLAG
        assert "was not established" in line.detail_text, line.detail_text


def test_check_still_reports_other_units_next_to_a_moot_static_vdis_failure():
    other = "xapi-nbd.service loaded failed failed xapi NBD server\n"
    line = checks.failed_units(host(failed_units={"ok": True, "value": STATIC + other},
                                    static_vdis=sv(), boot_epoch={"ok": True, "value": BOOT}))
    assert line.text.endswith(" - xapi-nbd.service")
