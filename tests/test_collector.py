# -*- coding: utf-8 -*-
"""Collector logic that is pure enough to test off-host.

The collector itself has to run under Python 2.7 as well as 3.6; these tests run under
whatever the dev machine has, so they only cover the parts that do no I/O. The 2.7 side
is exercised for real by every run against an 8.2.1 pool, which has no python3.
"""

import json
import sys
import threading
import time

import pytest

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


LINSTOR_NODES = """+----------------------------------+
| Node       | NodeType | State   |
|==================================|
| xen-sec-01 | COMBINED | Online  |
| xen-sec-02 | COMBINED | OFFLINE |
+----------------------------------+
"""


def test_linstor_node_names_reads_the_node_column():
    assert collector._linstor_node_names(LINSTOR_NODES) == ["xen-sec-01", "xen-sec-02"]


def test_linstor_node_names_on_a_table_with_no_node_column():
    # the faulty-resources table shares the box-drawing style but has no 'Node' header
    other = "+------+\n| ResourceName |\n|======|\n| res1 |\n+------+\n"
    assert collector._linstor_node_names(other) == []


def test_linstor_table_column_reads_any_named_column():
    assert collector.linstor_table_column(LINSTOR_NODES, "State") == ["Online", "OFFLINE"]
    assert collector.linstor_table_column(LINSTOR_NODES, "NoSuchColumn") == []


def test_linstor_table_column_never_returns_a_rule_row_as_a_value():
    """A separator drawn any way at all is a separator. Returning its dashes as a node
    name would send an 'n lp ---' call that cannot match, and the node it displaced would
    silently never be asked about."""
    for rule in ("|-------------|", "|=============|", "| ----- | --- |", "+-------------+"):
        table = "%s\n| Node | State |\n%s\n| xen-01 | Online |\n%s\n" % (rule, rule, rule)
        assert collector.linstor_table_column(table, "Node") == ["xen-01"]


def test_linstor_node_names_strips_ansi():
    """A coloured Node cell would be a name no 'n lp <node>' call could ever match, so
    every node would read as unqueryable. checks._linstor_node_offline strips ANSI off
    this same table for the same reason."""
    coloured = LINSTOR_NODES.replace("xen-sec-01", "\x1b[32mxen-sec-01\x1b[0m")
    assert collector._linstor_node_names(coloured) == ["xen-sec-01", "xen-sec-02"]


def test_linstor_node_names_strips_ansi_from_the_header_too():
    coloured = LINSTOR_NODES.replace("| Node ", "| \x1b[1mNode\x1b[0m ")
    assert collector._linstor_node_names(coloured) == ["xen-sec-01", "xen-sec-02"]


# verified against 8.3.0, 2026-08-30: the outer list wraps ONE list of property objects
LINSTOR_PREFNIC_JSON = json.dumps([[
    {"key": "CurStltConnName", "value": "default"},
    {"key": "NodeUname", "value": "sltxxxxx3"},
    {"key": "PrefNic", "value": "bond0"},
]])


def test_parse_linstor_pref_nic_reads_the_value_cell():
    assert collector.parse_linstor_pref_nic(LINSTOR_PREFNIC_JSON) == "bond0"


def test_parse_linstor_pref_nic_missing_property_is_none():
    no_prefnic = json.dumps([[{"key": "NodeUname", "value": "sltxxxxx3"}]])
    assert collector.parse_linstor_pref_nic(no_prefnic) is None


def test_parse_linstor_pref_nic_unparseable_json_is_false():
    # distinct from 'property not set': the caller must not report a parse failure as
    # a missing PrefNic, since those two facts need different handling
    assert collector.parse_linstor_pref_nic("not json") is False
    assert collector.parse_linstor_pref_nic('{"unexpected": "shape"}') is False
    assert collector.parse_linstor_pref_nic("[]") is False
    # a bare (non-nested) property list is not the real shape and must not be guessed at
    assert collector.parse_linstor_pref_nic(
        json.dumps([{"key": "PrefNic", "value": "bond0"}])) is False


def test_linstor_pref_nics_omits_nodes_that_could_not_be_queried_or_parsed(monkeypatch):
    """The dict holds only what was READ. The caller pairs it with the list of nodes that
    were ASKED, and the check reports the difference - see
    test_xostor_pref_nic_never_says_all_nodes_off_a_partial_read. Dropping a node here is
    only safe because it stays visible there."""
    calls = []

    def fake(controllers, args, timeout=None):
        calls.append(args)
        if args[-1] == "bad-node":
            return collector.err("linstor failed")
        if args[-1] == "unparseable-node":
            return collector.fact("not json")
        return collector.fact(LINSTOR_PREFNIC_JSON)

    monkeypatch.setattr(collector, "_linstor", fake)
    asked = ["good-node", "bad-node", "unparseable-node"]
    result = collector._linstor_pref_nics([], asked)
    assert result == {"good-node": "bond0"}
    assert [n for n in asked if n not in result] == ["bad-node", "unparseable-node"]
    # -m: parsing depends on JSON, not on which border glyphs a non-interactive
    # linstor call happens to fall back to
    assert all(a[:3] == ["-m", "n", "lp"] for a in calls)


def test_linstor_pref_nics_uses_the_short_per_node_timeout(monkeypatch):
    """A whole-cluster listing gets LINSTOR_TIMEOUT; one node's properties must not, or a
    degraded controller can spend the collector's whole-run budget in this loop."""
    seen = []

    def fake(controllers, args, timeout=None):
        seen.append(timeout)
        return collector.fact(LINSTOR_PREFNIC_JSON)

    monkeypatch.setattr(collector, "_linstor", fake)
    collector._linstor_pref_nics([], ["a", "b"])
    assert seen == [collector.LINSTOR_PROP_TIMEOUT] * 2
    assert collector.LINSTOR_PROP_TIMEOUT < collector.LINSTOR_TIMEOUT


def test_collect_pool_pairs_the_asked_nodes_with_the_answers(monkeypatch):
    """The wire shape the check depends on: which nodes were asked travels with what came
    back, so a partial read cannot arrive looking like a complete one."""
    def fake(controllers, args, timeout=None):
        if args[:2] == ["n", "l"]:
            return collector.fact(LINSTOR_NODES)
        if args[-1] == "xen-sec-02":
            return collector.err("linstor failed")
        return collector.fact(LINSTOR_PREFNIC_JSON)

    monkeypatch.setattr(collector, "_linstor", fake)
    names = collector._linstor_node_names(LINSTOR_NODES)
    value = {"nodes": names, "nics": collector._linstor_pref_nics([], names)}
    assert value["nodes"] == ["xen-sec-01", "xen-sec-02"]
    assert value["nics"] == {"xen-sec-01": "bond0"}


# --------------------------------------------------------------------------------------
# where the time went
# --------------------------------------------------------------------------------------

def test_every_command_records_its_own_elapsed_time(monkeypatch):
    """run() is the only way a command reaches a host, so this is complete by
    construction rather than by remembering to instrument each caller."""
    del collector.TIMINGS[:]
    collector.run(["true"])
    collector.run(["true", "again"])
    assert len(collector.TIMINGS) == 2
    assert [row[1] for row in collector.TIMINGS] == ["true", "true again"]
    assert all(isinstance(row[0], float) for row in collector.TIMINGS)


def test_a_command_the_budget_refused_is_still_recorded(monkeypatch):
    """'run budget exhausted' at 0.0s is itself the finding: it says the budget was gone
    before this command, which is what points at the ones before it."""
    del collector.TIMINGS[:]
    monkeypatch.setattr(collector, "DEADLINE", [0.0])
    r = collector.run(["true"])
    assert r.timed_out is True
    assert [row[1] for row in collector.TIMINGS] == ["true"]


def test_a_long_argv_keeps_the_path_at_the_end():
    """The elision is in the middle for exactly this reason: 'a grep took 90 seconds' is
    not an answer without the file it was reading, and the phrases come first."""
    del collector.TIMINGS[:]
    argv = ["grep", "-ainF"]
    for i in range(6):
        argv += ["-e", "a phrase long enough to need eliding %d" % i]
    argv += ["--", "/var/log/xensource.log.1"]

    collector.timed(argv, 0)
    text = collector.TIMINGS[0][1]
    assert text.startswith("grep -ainF -e a phrase")
    assert text.endswith("/var/log/xensource.log.1")
    assert " ... " in text


def test_an_argv_carrying_newlines_stays_on_one_line():
    """rpm's --qf formats end in a literal newline, which split the debug output across
    lines and made the timing table unreadable."""
    del collector.TIMINGS[:]
    collector.timed(["rpm", "-qa", "--qf", "%{INSTALLTIME} %{NAME}\n"], 0)
    assert collector.TIMINGS[0][1] == "rpm -qa --qf %{INSTALLTIME} %{NAME}"


def test_timings_ride_along_only_when_the_spec_asks(monkeypatch):
    """They are debug output, not part of any check, so a normal run does not carry them
    across the wire at all."""
    monkeypatch.setattr(collector, "collect_identity",
                        lambda: {"self_uuid": collector.fact(""),
                                 "hostname": collector.fact("h")})
    del collector.TIMINGS[:]
    collector.TIMINGS.append([1.5, "slow thing"])

    assert "timings" not in collector.collect({"want": []})["collector"]
    assert collector.collect({"want": [], "timings": True})["collector"]["timings"] \
        == [[1.5, "slow thing"]]


def test_the_slowest_commands_come_first_and_the_list_is_capped(monkeypatch):
    """A host runs enough commands that the whole list would bury the answer, and the
    answer is always at the slow end."""
    monkeypatch.setattr(collector, "collect_identity",
                        lambda: {"self_uuid": collector.fact(""),
                                 "hostname": collector.fact("h")})
    del collector.TIMINGS[:]
    for i in range(30):
        collector.TIMINGS.append([float(i), "cmd%d" % i])

    ranked = collector.collect({"want": [], "timings": True})["collector"]["timings"]
    assert len(ranked) == 15
    assert ranked[0] == [29.0, "cmd29"]
    assert ranked[-1] == [15.0, "cmd15"]


# --------------------------------------------------------------------------------------
# the watchdog: answering when a command cannot be killed
# --------------------------------------------------------------------------------------

def reset_collector_state():
    del collector.TIMINGS[:]
    collector.PARTIAL.clear()
    collector.CURRENT[0] = ""
    collector._EMITTED[0] = False


def test_the_document_is_written_once_however_many_callers_try(capsys):
    """_extract takes the first BEGIN and the last END, so a second document on one
    stdout would be read as a truncated first."""
    reset_collector_state()
    assert collector.emit({"a": 1}) is True
    assert collector.emit({"b": 2}) is False
    out = capsys.readouterr().out
    assert out.count(collector.BEGIN_MARKER) == 1
    assert '"a": 1' in out
    assert '"b"' not in out


def test_the_watchdog_names_the_command_it_could_not_get_away_from(capsys, monkeypatch):
    reset_collector_state()
    collector.PARTIAL["hostname"] = collector.fact("athena")
    collector.CURRENT[0] = "df -hP"
    collector.TIMINGS.append([0.2, "timedatectl"])
    exited = []
    monkeypatch.setattr(collector.os, "_exit", lambda code: exited.append(code))
    monkeypatch.setattr(collector, "DEADLINE", [time.time() - 100])   # past the grace

    collector.watchdog(15)

    payload = json.loads(capsys.readouterr().out.split(collector.BEGIN_MARKER)[1]
                         .split(collector.END_MARKER)[0])
    assert payload["__collector_stuck__"] == "df -hP"
    # what it DID establish comes back too, rather than being lost with the host
    assert payload["hostname"] == {"ok": True, "value": "athena"}
    assert payload["collector"]["timings"] == [[0.2, "timedatectl"]]
    assert exited == [0]


def test_the_watchdog_says_so_when_nothing_was_running(capsys, monkeypatch):
    """An empty CURRENT is a different fact from a command that hung, and must not read
    as one - the collector was between commands, so the stall is somewhere else."""
    reset_collector_state()
    monkeypatch.setattr(collector.os, "_exit", lambda code: None)
    monkeypatch.setattr(collector, "DEADLINE", [time.time() - 100])

    collector.watchdog(15)

    payload = json.loads(capsys.readouterr().out.split(collector.BEGIN_MARKER)[1]
                         .split(collector.END_MARKER)[0])
    assert payload["__collector_stuck__"] == "(no command was running)"


def test_no_budget_means_no_watchdog(capsys, monkeypatch):
    """A collector run with no deadline set must simply leave, rather than read 'no
    budget' as 'budget exhausted' and abandon a run that was going fine."""
    reset_collector_state()
    monkeypatch.setattr(collector, "DEADLINE", [None])
    monkeypatch.setattr(collector.os, "_exit",
                        lambda code: pytest.fail("watchdog exited with no budget set"))

    collector.watchdog(15)      # returns rather than exiting the process

    assert capsys.readouterr().out == ""


def test_a_command_that_will_not_die_is_abandoned_rather_than_waited_on(monkeypatch):
    """The whole point: one unkillable command must cost one fact, not the whole host.

    A real D-state process cannot be made on demand, so _kill is neutered instead - which
    is exactly what the kernel does to SIGKILL for a process in uninterruptible sleep.
    """
    reset_collector_state()
    del collector.ABANDONED[:]
    monkeypatch.setattr(collector, "_kill", lambda proc: None)   # the signal never lands
    monkeypatch.setattr(collector, "KILL_GRACE", 0.3)

    started = time.time()
    r = collector.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    elapsed = time.time() - started

    assert r.timed_out is True
    assert r.ok is False
    assert "uninterruptible" in r.err
    # it gave up at timeout + grace rather than waiting out the command
    assert elapsed < 5, "waited %.1fs for a command it had given up on" % elapsed
    assert collector.ABANDONED == ["%s -c import time; time.sleep(30)" % sys.executable]
    # ...and the next command still runs, which is the fact that used to be lost
    assert collector.run([sys.executable, "-c", "print(1)"]).ok is True


def test_a_killable_command_that_overruns_is_still_reported_as_timed_out(monkeypatch):
    """The ordinary timeout path has to keep working: killed, reaped, and not abandoned."""
    reset_collector_state()
    del collector.ABANDONED[:]

    r = collector.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)

    assert r.timed_out is True
    assert collector.ABANDONED == []      # it died, so nothing was left behind


def test_a_command_that_hangs_is_named_while_it_hangs():
    """End to end against a real child: CURRENT has to be set BEFORE the command can
    block, since a command that never returns never reaches the line after it."""
    reset_collector_state()
    seen = []

    def watcher():
        # while run() is blocked in communicate(), which is exactly the watchdog's view
        time.sleep(0.4)
        seen.append(collector.CURRENT[0])

    thread = threading.Thread(target=watcher)
    thread.start()
    collector.run([sys.executable, "-c", "import time; time.sleep(1.2)"], timeout=30)
    thread.join()

    assert seen and "time.sleep(1.2)" in seen[0]
    # ...and cleared once it is no longer running, so a later stall is not blamed on it
    assert collector.CURRENT[0] == ""
