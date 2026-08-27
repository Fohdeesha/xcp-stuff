# -*- coding: utf-8 -*-
"""The multipath path-health checks.

Every fixture here has the byte shape of real `multipathd` output from the lab hosts
(0.4.9-136, XCP-ng 8.2.1 and 8.3.0, captured 2026-08-27) with the lab's own wwids and
device names replaced - including the degraded case, captured live by failing one path of
a two-path map with `multipathd fail path` and reinstating it.

The states themselves are not invented either: this build's printable state strings were
read out of libmultipath's own table -
  dm_st  undef | active | failed
  chk_st undef | ready | faulty | shaky | ghost | delayed
  dev_st unknown | running | offline | blocked | quiesce | dead | deleting | live
- which is why the check whitelists what is healthy instead of blacklisting what is not.
"""

import checks
import collector
import config
import model
import parsers
import result

OK, FLAG, UNKNOWN = result.OK, result.FLAG, result.UNKNOWN

WWID = "3600a09800000000000000000feedface"
WWID2 = "3600a09800000000000000000deadbeef"

# `multipathd show paths raw format "%m|%d|%D|%t|%T|%o|%p"` on a healthy two-path host.
# The two [orphan] rows are the host's own local disks and are on EVERY host: judging
# them would flag every server that has a boot disk.
PATHS_HEALTHY = """[orphan]|sda|8:0|undef|undef|unknown|1
[orphan]|sdb|8:16|undef|undef|unknown|1
%s|sdc|8:32|active|ready|running|50
%s|sdd|8:48|active|ready|running|10
""" % (WWID, WWID)

# the same host with sdd failed - captured live, not written by hand
PATHS_DEGRADED = """[orphan]|sda|8:0|undef|undef|unknown|1
[orphan]|sdb|8:16|undef|undef|unknown|1
%s|sdc|8:32|active|ready|running|50
%s|sdd|8:48|failed|faulty|running|10
""" % (WWID, WWID)

# `multipathd show maps raw format "%n|%N|%t|%Q|%x|%0|%f"`. %N is USABLE paths, so it
# drops to 1 while a path is failed, and %0 (path_faults) stays 1 after it comes back.
MAPS_HEALTHY = "%s|2|active|30 chk|0|0|1 queue_if_no_path\n" % WWID
MAPS_DEGRADED = "%s|1|active|30 chk|0|1|1 queue_if_no_path\n" % WWID
MAPS_RECOVERED = "%s|2|active|30 chk|0|1|1 queue_if_no_path\n" % WWID

DM_ONE_MAP = "%s\t(253, 0)\n" % WWID
DAEMON_OK = "pid 1305 running\n"

# how multipathd answers a query it does not understand: rc 0, and the whole help text
HELP_TEXT = """multipath-tools v0.4.9 (05/33, 2016)
CLI commands reference:
 list|show paths
 list|show paths format $format
"""

STATES = (config.MULTIPATH_OK_DM_STATES, config.MULTIPATH_OK_CHK_STATES,
          config.MULTIPATH_OK_DEV_STATES, config.MULTIPATH_STANDBY_CHK_STATES)


def mp(daemon=DAEMON_OK, dm=DM_ONE_MAP, maps=MAPS_HEALTHY, paths=PATHS_HEALTHY,
       rechecked=False):
    """A collector 'multipath' fact, sub-facts and all."""
    def wrap(value):
        return value if isinstance(value, dict) else {"ok": True, "value": value}
    return {"ok": True, "value": {"daemon": wrap(daemon), "dm": wrap(dm),
                                  "maps": wrap(maps), "paths": wrap(paths),
                                  "rechecked": {"ok": True, "value": rechecked}}}


def err(reason="could not look"):
    return {"ok": False, "error": reason}


def host(address="10.0.0.1", name="hostx", **facts):
    h = model.Host(address, "uuid-1", name, "true", "true")
    h.payload = dict(facts)
    return h


# --------------------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------------------

def test_paths_parse_and_unmapped_devices_are_dropped():
    rows = parsers.parse_multipath_paths(PATHS_HEALTHY)
    assert [r["dev"] for r in rows] == ["sdc", "sdd"]
    assert rows[0] == {"map": WWID, "dev": "sdc", "dev_t": "8:32", "dm_st": "active",
                       "chk_st": "ready", "dev_st": "running", "prio": "50"}


def test_every_bracketed_pseudo_map_is_unmapped():
    # multipathd has three of them, and a local disk sits under one on every host
    text = "\n".join("%s|sd%s|8:0|undef|undef|unknown|1" % (name, letter)
                     for name, letter in (("[orphan]", "a"), ("[undef]", "b"),
                                          ("[unknown]", "c")))
    assert parsers.parse_multipath_paths(text) == []


def test_malformed_lines_and_the_help_text_are_dropped_not_guessed_at():
    assert parsers.parse_multipath_paths(HELP_TEXT) == []
    assert parsers.parse_multipath_maps(HELP_TEXT) == []
    assert parsers.parse_multipath_paths("%s|sdc|8:32|active\n" % WWID) == []


def test_maps_parse_with_numeric_fields():
    row = parsers.parse_multipath_maps(MAPS_DEGRADED)[0]
    assert row["name"] == WWID
    assert row["usable"] == 1
    assert row["dm_st"] == "active"
    assert row["queueing"] == "30 chk"
    assert row["map_failures"] == 0
    assert row["path_faults"] == 1
    assert row["features"] == "1 queue_if_no_path"


def test_a_non_numeric_count_is_none_not_zero():
    row = parsers.parse_multipath_maps("%s|-|active|off|-|-|0\n" % WWID)[0]
    assert row["usable"] is None and row["path_faults"] is None


def test_dm_map_listing():
    assert parsers.parse_dm_multipath_maps(DM_ONE_MAP) == [WWID]
    # a host with no multipath prints nothing at all - not "No devices found"
    assert parsers.parse_dm_multipath_maps("") == []
    assert parsers.parse_dm_multipath_maps("No devices found\n") == []


def test_daemon_liveness_needs_a_positive_answer():
    assert parsers.multipathd_alive("pid 1305 running") is True
    assert parsers.multipathd_alive("") is False
    assert parsers.multipathd_alive("ux_socket_connect: No such file or directory") is False


# --------------------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------------------

def classify(dm_st, chk_st, dev_st):
    return parsers.classify_multipath_path(
        {"dm_st": dm_st, "chk_st": chk_st, "dev_st": dev_st}, *STATES)


def test_healthy_path():
    assert classify("active", "ready", "running") == "ok"


def test_ghost_is_standby_not_a_fault():
    # the passive path of an active/passive array. Flagging it would make every ALUA
    # array in the field report a permanent finding.
    assert classify("active", "ghost", "running") == "standby"


def test_the_states_the_lab_produced_when_a_path_was_failed():
    assert classify("failed", "faulty", "running") == "bad"


def test_every_other_printable_state_is_bad():
    for chk in ("faulty", "shaky", "delayed", "undef"):
        assert classify("active", chk, "running") == "bad", chk
    for dev in ("offline", "blocked", "quiesce", "dead", "deleting", "unknown"):
        assert classify("active", "ready", dev) == "bad", dev
    assert classify("failed", "ready", "running") == "bad"


def test_an_unknown_state_string_is_not_silently_healthy():
    # a newer multipath-tools inventing a state name must land in 'bad' and be looked at
    assert classify("active", "marginal", "running") == "bad"
    assert classify("degraded", "ready", "running") == "bad"


# --------------------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------------------

def summary(paths, maps):
    return parsers.multipath_summary(parsers.parse_multipath_paths(paths),
                                     parsers.parse_multipath_maps(maps), *STATES)


def test_summary_of_a_healthy_map():
    s = summary(PATHS_HEALTHY, MAPS_HEALTHY)
    assert s["total_paths"] == 2 and s["ok_paths"] == 2 and s["bad_paths"] == 0
    assert s["dead_maps"] == [] and s["suspended_maps"] == []


def test_summary_counts_a_failed_path_but_still_sees_both():
    s = summary(PATHS_DEGRADED, MAPS_DEGRADED)
    assert s["total_paths"] == 2 and s["ok_paths"] == 1 and s["bad_paths"] == 1
    assert s["dead_maps"] == []
    assert s["maps"][0]["path_faults"] == 1


def test_a_map_with_nothing_usable_is_its_own_state():
    paths = "%s|sdc|8:32|failed|faulty|running|0\n" % WWID
    s = summary(paths, "%s|0|active|off|1|2|1 queue_if_no_path\n" % WWID)
    assert s["dead_maps"] == [WWID]
    assert s["maps"][0]["map_failures"] == 1


def test_a_suspended_map_is_reported():
    s = summary(PATHS_HEALTHY, "%s|2|suspend|30 chk|0|0|1 queue_if_no_path\n" % WWID)
    assert s["suspended_maps"] == [WWID]


def test_a_map_multipathd_listed_with_no_paths_still_appears():
    s = summary("", MAPS_HEALTHY)
    assert [m["name"] for m in s["maps"]] == [WWID]
    assert s["dead_maps"] == [WWID] and s["maps"][0]["listed"] is True


def test_a_path_whose_map_was_not_listed_still_appears():
    s = summary(PATHS_HEALTHY, "")
    assert s["maps"][0]["listed"] is False and s["total_paths"] == 2


# --------------------------------------------------------------------------------------
# the per-host line
# --------------------------------------------------------------------------------------

def test_healthy_pool_host():
    line = checks.multipath_health(host(multipath=mp()))
    assert line.status == OK
    assert "OK - 2/2 paths usable on 1 map" in line.text


def test_standby_paths_are_named_in_the_value():
    paths = PATHS_HEALTHY.replace("|active|ready|running|10", "|active|ghost|running|10")
    line = checks.multipath_health(host(multipath=mp(paths=paths)))
    assert line.status == OK and "(1 standby)" in line.text


def test_a_failed_path_flags_with_the_evidence_below():
    line = checks.multipath_health(host(multipath=mp(maps=MAPS_DEGRADED,
                                                     paths=PATHS_DEGRADED)))
    assert line.status == FLAG
    assert "1 of 2 path(s) not usable" in line.text
    assert "NOT USABLE" in line.detail_text
    assert "sdd" in line.detail_text
    # the timestamped counterpart of the same event lives in its own line, but the
    # cumulative counter belongs here, as evidence rather than as a finding
    assert "1 path failure(s) since map load" in line.detail_text


def test_a_map_with_no_usable_path_says_so_in_different_words():
    # not "degraded": I/O is queueing or erroring on that map right now
    paths = "%s|sdc|8:32|failed|faulty|running|0\n" % WWID
    line = checks.multipath_health(host(multipath=mp(maps="%s|0|active|off|1|2|x\n" % WWID,
                                                     paths=paths)))
    assert line.status == FLAG
    assert line.text.startswith("Down - no usable path on 1 map")


def test_every_count_is_pluralised_off_its_own_number():
    # one dead map out of two once printed "no usable path on 1 maps"
    paths = ("%s|sdc|8:32|active|ready|running|50\n" % WWID +
             "%s|sdd|8:48|failed|faulty|running|10\n" % WWID2)
    maps = ("%s|1|active|30 chk|0|0|x\n" % WWID) + ("%s|0|active|off|1|1|x\n" % WWID2)
    line = checks.multipath_health(host(multipath=mp(maps=maps, paths=paths)))
    assert "no usable path on 1 map," in line.text
    assert "1 of 2 path(s) not usable" in line.text


def test_a_suspended_map_reaches_the_line():
    maps = "%s|2|suspend|30 chk|0|0|x\n" % WWID
    line = checks.multipath_health(host(multipath=mp(maps=maps)))
    assert line.status == FLAG and "1 map suspended" in line.text


def test_a_host_with_no_multipath_at_all_is_green_and_says_why():
    line = checks.multipath_health(host(multipath=mp(dm="", maps="", paths="")))
    assert line.status == OK and line.text.endswith("N/A - No multipath maps")


def test_no_maps_is_still_answerable_when_dmsetup_could_not_be_run():
    # multipathd is alive and says there is nothing; dmsetup was only corroboration
    line = checks.multipath_health(host(multipath=mp(dm=err(), maps="", paths="")))
    assert line.status == OK


def test_maps_in_the_kernel_that_multipathd_does_not_manage_flag():
    # a daemon that came up without adopting the maps: I/O still flows, nothing checks
    # or fails over the paths, and multipathd's own answer is a clean empty
    line = checks.multipath_health(host(multipath=mp(maps="", paths="")))
    assert line.status == FLAG
    assert "multipathd does not manage" in line.text
    assert WWID in line.detail_text


def test_a_dead_daemon_is_unknown_not_a_clean_green():
    # the whole reason `show daemon` is asked: this output is identical to a host that
    # simply has no multipath
    line = checks.multipath_health(host(multipath=mp(daemon="", dm="", maps="", paths="")))
    assert line.status == UNKNOWN
    assert "multipathd is not answering" in line.text


def test_a_dead_daemon_with_live_maps_says_how_many():
    line = checks.multipath_health(host(multipath=mp(daemon=err(), maps="", paths="")))
    assert line.status == UNKNOWN
    assert "1 map(s) present in device-mapper" in line.text


def test_a_refused_query_is_unknown():
    line = checks.multipath_health(host(multipath=mp(maps=HELP_TEXT, paths=HELP_TEXT)))
    assert line.status == UNKNOWN and "did not accept the query" in line.text


def test_each_missing_subfact_is_unknown():
    for kwargs in ({"maps": err("boom")}, {"paths": err("boom")}):
        line = checks.multipath_health(host(multipath=mp(**kwargs)))
        assert line.status == UNKNOWN and "boom" in line.text


def test_the_recheck_note_reaches_the_detail_block():
    line = checks.multipath_health(host(multipath=mp(maps=MAPS_DEGRADED,
                                                     paths=PATHS_DEGRADED,
                                                     rechecked=True)))
    assert "read a second time" in line.detail_text


# --------------------------------------------------------------------------------------
# the kern.log line
# --------------------------------------------------------------------------------------

# the ring, as `dmesg -T` renders it. Note the boot-time recompute: the ring stamps this
# failure at 01:58:55 and syslog's copy of the same event says 01:59:00.
# The two events are far enough apart that their +/-3 context windows do NOT overlap -
# otherwise "the newest hit is the one shown" is untestable, and a mutation that showed
# the OLDEST hit instead passed against a shorter version of this fixture.
DMESG_WITH_EVENT = """[Mon Aug 24 07:13:53 2026] device-mapper: multipath queue-length: version 0.2.0 loaded
[Thu Aug 27 01:58:52 2026] sd 2:0:0:0: [sdd] tag#0 FAILED Result: hostbyte=DID_OK
[Thu Aug 27 01:58:55 2026] device-mapper: multipath: Failing path 8:48.
[Thu Aug 27 01:59:00 2026] device-mapper: multipath: Reinstating path 8:48.
[Thu Aug 27 02:00:01 2026] filler 1
[Thu Aug 27 02:00:02 2026] filler 2
[Thu Aug 27 02:00:03 2026] filler 3
[Thu Aug 27 02:00:04 2026] filler 4
[Thu Aug 27 02:00:05 2026] filler 5
[Thu Aug 27 02:00:06 2026] filler 6
[Thu Aug 27 02:11:59 2026] sd 2:0:0:0: [sdd] tag#0 FAILED Result: hostbyte=DID_OK
[Thu Aug 27 02:12:02 2026] device-mapper: multipath: Failing path 8:48.
[Thu Aug 27 02:12:54 2026] device-mapper: multipath: Reinstating path 8:48.
"""
DMESG_CLEAN = """[Mon Aug 24 07:11:36 2026] Linux version 4.19.0
[Mon Aug 24 07:13:53 2026] device-mapper: multipath queue-length: version 0.2.0 loaded
"""
KERN_BLOCK = [{"phrase": "device-mapper: multipath: Failing path",
               "file": "/var/log/kern.log", "line": 12,
               "context": ["Aug 27 01:59:00 h kernel: device-mapper: multipath: "
                           "Failing path 8:48."]}]


def events(scan, dmesg):
    return checks.multipath_events(host(multipath_scan=scan, dmesg=dmesg))


def test_path_events_none_when_both_sources_are_clean():
    line = events({"ok": True, "value": []}, {"ok": True, "value": DMESG_CLEAN})
    assert line.status == OK and line.text.endswith("None")


def test_path_events_found_in_kern_log():
    line = events({"ok": True, "value": KERN_BLOCK}, {"ok": True, "value": DMESG_CLEAN})
    assert line.status == FLAG
    assert "/var/log/kern.log" in line.detail_text
    assert "Failing path 8:48" in line.detail_text


def test_path_events_found_in_the_dmesg_ring_alone():
    # the sighting that started all this was in dmesg, and `Dmesg Content` does not match
    # it: on the live host that line hits none of panic/crash/rip/kill/call trace/timed out
    line = events({"ok": True, "value": []}, {"ok": True, "value": DMESG_WITH_EVENT})
    assert line.status == FLAG
    assert "dmesg ring" in line.detail_text
    assert "Failing path 8:48" in line.detail_text


def test_the_ring_block_counts_the_occurrences_and_shows_the_newest():
    line = events({"ok": True, "value": []}, {"ok": True, "value": DMESG_WITH_EVENT})
    assert "2 occurrences, most recent shown" in line.detail_text
    # the newest hit, with its context - so the Reinstating line after it comes along
    assert "02:12:02" in line.detail_text and "02:12:54" in line.detail_text
    # ...and the older one is NOT what got shown
    assert "01:58:55" not in line.detail_text


def test_context_lines_are_indented_once_not_twice():
    line = events({"ok": True, "value": []}, {"ok": True, "value": DMESG_WITH_EVENT})
    body = [l for l in line.detail_text.splitlines() if "Failing path" in l and
            not l.startswith("---")]
    assert body and all(l.startswith("  [") for l in body), body


def test_both_sources_are_shown_and_the_drift_is_admitted():
    line = events({"ok": True, "value": KERN_BLOCK}, {"ok": True, "value": DMESG_WITH_EVENT})
    assert "/var/log/kern.log" in line.detail_text
    assert "dmesg ring" in line.detail_text
    # the same failure is stamped 01:59:00 by syslog and 01:58:55 by the ring, so nothing
    # merges them and the block says why
    assert "recomputes its timestamps" in line.detail_text


def test_a_finding_survives_the_other_source_being_unreadable():
    assert events(err(), {"ok": True, "value": DMESG_WITH_EVENT}).status == FLAG
    assert events({"ok": True, "value": KERN_BLOCK}, err()).status == FLAG


def test_a_clean_answer_needs_every_source_actually_read():
    # "None" off one source while the other could not be looked at is the silent green
    # this tool exists to prevent
    assert events(err("boom"), {"ok": True, "value": DMESG_CLEAN}).status == UNKNOWN
    line = events({"ok": True, "value": []}, err())
    assert line.status == UNKNOWN and "dmesg" in line.text


def test_path_events_unknown_when_nothing_was_collected():
    assert checks.multipath_events(host()).status == UNKNOWN


# --------------------------------------------------------------------------------------
# the pool line
# --------------------------------------------------------------------------------------

def two_hosts(paths_a=PATHS_HEALTHY, paths_b=PATHS_HEALTHY, **kw):
    return [host("10.0.0.1", "host-a", multipath=mp(paths=paths_a, **kw)),
            host("10.0.0.2", "host-b", multipath=mp(paths=paths_b, **kw))]


def test_counts_match_across_the_pool():
    line = checks.multipath_path_counts(two_hosts())
    assert line.status == OK and line.text.endswith("Matched")


def test_a_host_seeing_fewer_paths_than_its_peers_flags():
    # invisible from that host: one working path looks perfectly healthy there
    one_path = "%s|sdc|8:32|active|ready|running|50\n" % WWID
    line = checks.multipath_path_counts(two_hosts(paths_b=one_path))
    assert line.status == FLAG
    assert "Mismatched on 1 map(s)" in line.text
    assert "fewer than 2" in line.detail_text
    assert "host-b" in line.detail_text


def test_a_host_missing_the_map_entirely_flags():
    other = "%s|sdc|8:32|active|ready|running|50\n" % WWID2
    line = checks.multipath_path_counts(two_hosts(paths_b=other))
    assert line.status == FLAG and "map not present" in line.detail_text


def test_a_failed_path_does_not_also_move_the_pool_line():
    # counts CONFIGURED paths: the failed path is still a row, so the fault is reported
    # once, by the host line, instead of twice in different words
    line = checks.multipath_path_counts(two_hosts(paths_b=PATHS_DEGRADED))
    assert line.status == OK


def test_a_pool_with_no_multipath_says_so():
    hosts = [host("10.0.0.1", "a", multipath=mp(dm="", maps="", paths="")),
             host("10.0.0.2", "b", multipath=mp(dm="", maps="", paths=""))]
    line = checks.multipath_path_counts(hosts)
    assert line.status == OK and "N/A - No multipath maps in pool" in line.text


def test_one_host_is_nothing_to_compare():
    line = checks.multipath_path_counts([host(multipath=mp())])
    assert line.status == OK and "Nothing to compare" in line.text


def test_no_readable_host_is_unknown_not_matched():
    hosts = [host("10.0.0.1", "a", multipath=err()), host("10.0.0.2", "b", multipath=err())]
    assert checks.multipath_path_counts(hosts).status == UNKNOWN


def test_an_unreadable_host_is_admitted_in_the_value():
    hosts = two_hosts() + [host("10.0.0.3", "c", multipath=err())]
    line = checks.multipath_path_counts(hosts)
    assert line.status == OK and "2 of 3 hosts readable" in line.text


def test_an_uncollected_host_does_not_count_as_agreement():
    line = checks.multipath_path_counts([host(multipath=mp()), model.Host("10.0.0.9")])
    assert "1 of 2 hosts readable" in line.text


# --------------------------------------------------------------------------------------
# the collector's re-query decision
# --------------------------------------------------------------------------------------

def test_a_mapped_path_mid_check_triggers_one_requery():
    text = "%s|sdc|8:32|active|undef|running|50\n" % WWID
    assert collector._mp_transient(text, ["undef"]) is True


def test_a_local_disk_never_triggers_a_requery():
    # every host has one, and it is permanently undef: this is what keeps every run in
    # every pool from paying the re-query delay forever
    assert collector._mp_transient(PATHS_HEALTHY, ["undef"]) is False
    assert collector._mp_transient(PATHS_DEGRADED, ["undef"]) is False
