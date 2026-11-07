# -*- coding: utf-8 -*-
"""SR Attachment: a shared SR that some live host has not plugged.

The listings are in the shape xe prints them on 8.3 (labelled records, blank lines between
them), with every uuid and name made up.
"""

import checks
import model
import parsers
import result

OK, FLAG, UNKNOWN, INFO = result.OK, result.FLAG, result.UNKNOWN, result.INFO

H1, H2, H3 = ("aaaaaaaa-0000-0000-0000-00000000000%d" % i for i in (1, 2, 3))
NFS, ISO, LOCAL1, DVD1 = ("bbbbbbbb-0000-0000-0000-00000000000%d" % i for i in (1, 2, 3, 4))


def hosts(*rows):
    return "".join("uuid ( RO)                 : %s\n           name-label ( RW): %s\n"
                   "    host-metrics-live ( RO): %s\n\n\n" % r for r in rows)


def srs(*rows):
    return "".join("uuid ( RO)          : %s\n    name-label ( RW): %s\n          type ( RO): %s\n"
                   "        shared ( RW): %s\n\n\n" % r for r in rows)


def pbds(*rows):
    return "".join("uuid ( RO)                  : %s\n             host-uuid ( RO): %s\n"
                   "               sr-uuid ( RO): %s\n    currently-attached ( RO): %s\n\n\n" % r
                   for r in rows)


HOSTS = hosts((H1, "xen-a", "true"), (H2, "xen-b", "true"))
SRS = srs((NFS, "NFS-VMS", "nfs", "true"), (ISO, "ISOs", "iso", "true"),
          (LOCAL1, "Local storage", "ext", "false"), (DVD1, "DVD drives", "udev", "false"))


def all_pbds(**over):
    """Every PBD of a healthy two-host pool; over maps a pbd uuid to its attached value,
    or to None to leave it out."""
    rows = [("cccc-nfs-a", H1, NFS), ("cccc-nfs-b", H2, NFS), ("cccc-iso-a", H1, ISO),
            ("cccc-iso-b", H2, ISO), ("cccc-local-a", H1, LOCAL1), ("cccc-dvd-a", H1, DVD1)]
    out = []
    for uuid, host, sr in rows:
        att = over.get(uuid.replace("-", "_"), "true")
        if att is not None:
            out.append((uuid, host, sr, att))
    return pbds(*out)


def judge(pbd_text=None, sr_text=SRS, host_text=HOSTS):
    return parsers.parse_sr_attachment(all_pbds() if pbd_text is None else pbd_text, sr_text, host_text)


def pool(**facts):
    p = model.Pool()
    p.payload = dict(facts)
    return p


def att(pbd_text=None, sr_text=SRS, host_text=HOSTS):
    return {"ok": True, "value": {"pbds": all_pbds() if pbd_text is None else pbd_text,
                                  "srs": sr_text, "hosts": host_text}}


def check(pbd_text=None, sr_text=SRS, host_text=HOSTS):
    return checks.sr_attachment(pool(sr_attachment=att(pbd_text, sr_text, host_text)))


ONE_DOWN = hosts((H1, "xen-a", "true"), (H2, "xen-b", "false"))
NOTHING = {"shared": [], "local": [], "down": []}


# --------------------------------------------------------------------------------------
# the parser
# --------------------------------------------------------------------------------------

def test_a_healthy_pool_has_nothing_to_say():
    assert judge() == NOTHING


def test_a_shared_sr_unplugged_on_one_host_names_its_pbd():
    res = judge(all_pbds(cccc_nfs_b="false"))
    assert res["shared"] == [("NFS-VMS", NFS, False, [("xen-b", "not plugged", "cccc-nfs-b")])]


def test_a_shared_sr_with_no_pbd_on_a_host():
    res = judge(all_pbds(cccc_iso_b=None))
    assert res["shared"] == [("ISOs", ISO, False, [("xen-b", "no PBD", None)])]


def test_a_shared_sr_unplugged_on_every_live_host_is_marked_so():
    res = judge(all_pbds(cccc_nfs_a="false", cccc_nfs_b="false"))
    assert [(s[0], s[2]) for s in res["shared"]] == [("NFS-VMS", True)]


def test_a_shared_sr_with_no_pbd_at_all_is_missing_everywhere():
    res = judge(all_pbds(cccc_nfs_a=None, cccc_nfs_b=None))
    assert res["shared"] == [("NFS-VMS", NFS, True, [("xen-a", "no PBD", None),
                                                     ("xen-b", "no PBD", None)])]


def test_removable_media_srs_are_left_out():
    assert judge(all_pbds(cccc_dvd_a="false")) == NOTHING


def test_a_local_sr_unplugged_on_its_live_host():
    res = judge(all_pbds(cccc_local_a="false"))
    assert res["shared"] == []
    assert res["local"] == [("Local storage", LOCAL1, "xen-a", "cccc-local-a")]


def test_a_down_hosts_own_local_sr_is_not_judged():
    host_text = hosts((H1, "xen-a", "false"), (H2, "xen-b", "true"))
    res = judge(all_pbds(cccc_local_a="false"), host_text=host_text)
    assert res["local"] == []
    assert res["down"] == ["xen-a"]


def test_a_down_host_is_not_judged_for_shared_srs_either():
    res = judge(all_pbds(cccc_nfs_b="false"), host_text=ONE_DOWN)
    assert res == {"shared": [], "local": [], "down": ["xen-b"]}


def test_a_shared_sr_plugged_only_on_a_down_host_is_missing_on_every_live_one():
    res = judge(all_pbds(cccc_nfs_a="false"), host_text=ONE_DOWN)
    assert [(s[0], s[2]) for s in res["shared"]] == [("NFS-VMS", True)]


def test_a_third_host_with_no_pbds_is_missing_from_every_shared_sr():
    res = judge(host_text=HOSTS + hosts((H3, "xen-c", "true")))
    assert [(s[0], s[3]) for s in res["shared"]] == [
        ("ISOs", [("xen-c", "no PBD", None)]), ("NFS-VMS", [("xen-c", "no PBD", None)])]


def test_an_sr_with_no_name_is_named_by_its_uuid():
    sr_text = srs((NFS, "", "nfs", "true"), (ISO, "ISOs", "iso", "true"),
                  (LOCAL1, "Local storage", "ext", "false"))
    res = judge(all_pbds(cccc_nfs_b="false"), sr_text=sr_text)
    assert res["shared"][0][0] == NFS


def test_a_record_missing_a_field_is_not_read_as_anything():
    broken = all_pbds().replace("    currently-attached ( RO): true\n", "", 1)
    assert judge(broken) is None


def test_records_whose_uuid_is_not_printed_first_are_not_read_as_anything():
    swapped = []
    for rec in all_pbds().split("\n\n\n"):
        lines = rec.split("\n")
        if len(lines) == 4:
            lines = [lines[1], lines[0], lines[2], lines[3]]
        swapped.append("\n".join(lines))
    assert judge("\n\n\n".join(swapped)) is None


def test_no_host_at_all_or_no_live_host_is_not_read_as_anything():
    assert judge(host_text="") is None
    assert judge(host_text=hosts((H1, "xen-a", "false"), (H2, "xen-b", "<not in database>"))) is None


# --------------------------------------------------------------------------------------
# the check
# --------------------------------------------------------------------------------------

def test_check_ok():
    line = check()
    assert (line.status, line.text.endswith("OK")) == (OK, True)


def test_check_flags_a_partial_sr_with_the_command_to_plug_it():
    line = check(all_pbds(cccc_nfs_b="false"))
    assert line.status == FLAG
    assert line.text.endswith(" - NFS-VMS not plugged on xen-b")
    assert "xe pbd-plug uuid=cccc-nfs-b" in line.detail_text


def test_check_yellow_for_a_shared_sr_on_no_live_host():
    """The owner's call (2026-11-07): a shared SR detached on purpose must not fail the run,
    and one plugged on no live host cannot be told apart from it. Yellow keeps it on screen
    under -f without flagging the exit code."""
    line = check(all_pbds(cccc_nfs_a="false", cccc_nfs_b="false"))
    assert (line.status, line.keep, line.flags) == (INFO, True, False)
    assert line.text == "Detached - NFS-VMS (shared, on no live host)" or \
        line.text.endswith("Detached - NFS-VMS (shared, on no live host)")
    assert "shared, and plugged on no live host" in line.detail_text


def test_check_a_partial_sr_still_fails_next_to_a_detached_one():
    line = check(all_pbds(cccc_nfs_a="false", cccc_nfs_b="false", cccc_iso_b="false"))
    assert line.status == FLAG
    assert line.text.endswith(" - ISOs not plugged on xen-b")
    assert "NFS-VMS" in line.detail_text


def test_check_says_no_pbd_apart_from_not_plugged():
    line = check(all_pbds(cccc_iso_b=None, cccc_nfs_b="false"))
    assert line.text.endswith(" - ISOs has no PBD on xen-b; NFS-VMS not plugged on xen-b")


def test_check_yellow_for_a_detached_local_sr_and_never_says_ok():
    line = check(all_pbds(cccc_local_a="false"))
    assert (line.status, line.keep, line.flags) == (INFO, True, False)
    assert "Detached - Local storage on xen-a" in line.text
    assert "OK" not in line.text
    assert "xe pbd-plug uuid=cccc-local-a" in line.detail_text


def test_check_yellow_for_a_down_host_and_does_not_blame_its_local_sr():
    line = check(all_pbds(cccc_local_a="false"),
                 host_text=hosts((H1, "xen-a", "false"), (H2, "xen-b", "true")))
    assert (line.status, line.keep) == (INFO, True)
    assert line.text.endswith("Not judged on xen-a")
    assert "Local storage" not in line.detail_text


def test_check_unknown_without_the_fact_or_off_a_failed_or_unreadable_one():
    for p in (pool(), pool(sr_attachment={"ok": False, "error": "xe pbd-list failed (exit 1)"}),
              pool(sr_attachment=att(host_text="")),
              pool(sr_attachment=att(host_text=hosts((H1, "xen-a", "false"))))):
        line = checks.sr_attachment(p)
        assert line.status == UNKNOWN and line.flags, line.text


