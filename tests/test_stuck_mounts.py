# -*- coding: utf-8 -*-
"""A mount whose server stops answering, and the three lines that catch it.

This failure took a pool master out of every report for days and the script said nothing,
because nothing it ran ever came back to say anything: `df` went into uninterruptible
sleep on a dead CIFS mount and stayed there, and a process in D state cannot be killed by
any signal. These tests pin the three angles the checks take on it, and in particular the
rule that decides when NOT to probe - a probe of a dead mount becomes one more stuck
process, so the check must never be the thing that makes the host worse.

The lab cannot produce a wedged mount on demand, so the collector documents here are
synthetic and are meant to be reviewed by reading. They are modelled on the real one:
/proc/PID/stack from the live incident showed cifs_getattr -> smb2_query_path_info ->
open_shroot under vfs_statx.
"""

import checks
import collector
import config
import main
import model
from result import FLAG, OK, UNKNOWN


def host(**facts):
    h = model.Host("10.0.0.1", "uuid-1", "hostx", "true", "false")
    h.payload = dict(facts)
    h.local_now = 1000.0
    return h


def fact(value):
    return {"ok": True, "value": value}


def err(reason="nope"):
    return {"ok": False, "error": reason}


def stuck_row(pid, age, cmd, module="cifs", frame="open_shroot+0x43/0x210 [cifs]"):
    return {"pid": pid, "age": age, "cmd": cmd, "module": module, "frame": frame}


def mount_row(target, state, source="//10.10.10.11/XCP_ISO", fstype="cifs", **extra):
    row = {"source": source, "target": target, "type": fstype, "state": state}
    row.update(extra)
    return row


# --------------------------------------------------------------------------------------
# parsing what /proc says
# --------------------------------------------------------------------------------------

def test_proc_stat_survives_a_comm_containing_spaces_and_parens():
    """The field that breaks naive parsers. comm is unescaped and can hold both, so
    splitting on whitespace or on the FIRST ')' mis-numbers every field after it - and
    here that means reading some other number as the process state."""
    fields = ["1234", "((weird) proc name)", "D"] + [str(n) for n in range(4, 23)]
    state, starttime = collector.parse_proc_stat(" ".join(fields))
    assert state == "D"
    assert starttime == 22          # field 22 overall, whatever comm did


def test_proc_stat_on_a_truncated_or_empty_line():
    assert collector.parse_proc_stat("") == (None, None)
    assert collector.parse_proc_stat("123 (sh) D 1 2 3") == (None, None)
    assert collector.parse_proc_stat("no parens here at all") == (None, None)


MOUNTS = """\
/dev/sda1 / ext3 rw,relatime 0 0
//10.10.10.11/XCP_ISO /run/sr-mount/e512c88e cifs rw,vers=3.0,soft 0 0
10.10.10.11:/NFS_export /run/sr-mount/8bdf2ce0 nfs rw,vers=3,hard 0 0
tmpfs /run tmpfs rw 0 0
//nas/Some\\040Share /mnt/with\\040space cifs rw 0 0
"""


def test_only_network_mounts_are_returned_and_escapes_are_undone():
    rows = collector.parse_mounts(MOUNTS, config.NETWORK_FS_TYPES)
    assert [r[2] for r in rows] == ["cifs", "nfs", "cifs"]
    # ext3 and tmpfs cannot hang waiting on a server, so they are not this check's business
    assert all(r[2] not in ("ext3", "tmpfs") for r in rows)
    # a mount point with a space arrives octal-escaped and must not keep the escape
    assert rows[2] == ("//nas/Some Share", "/mnt/with space", "cifs")


def test_a_mounts_file_that_says_nothing_yields_nothing_rather_than_erroring():
    assert collector.parse_mounts("", config.NETWORK_FS_TYPES) == []
    assert collector.parse_mounts("garbage\nshort line\n", config.NETWORK_FS_TYPES) == []


def test_the_blocked_module_is_read_off_the_kernel_stack():
    """The real stack from the incident. This is what turns 'something is stuck' into
    'stuck in the SMB client' - and it is trustworthy where the wchan column was not."""
    stack = ("[<0>] open_shroot+0x43/0x210 [cifs]\n"
             "[<0>] smb2_query_path_info+0x7f/0x100 [cifs]\n"
             "[<0>] cifs_getattr+0x5a/0x1a0 [cifs]\n"
             "[<0>] vfs_statx+0x8b/0xe0\n")
    assert collector.fs_module_of(stack) == "cifs"
    assert collector.fs_module_of("[<0>] nfs_wait_bit_killable+0x1/0x2 [nfs]") == "nfs"
    # a stack entirely in the core kernel names no module, and must not invent one
    assert collector.fs_module_of("[<0>] ep_poll+0x304/0x3c0\n") == ""
    assert collector.fs_module_of("") == ""


# --------------------------------------------------------------------------------------
# Stuck Processes
# --------------------------------------------------------------------------------------

def test_no_stuck_processes_is_the_only_green():
    assert checks.stuck_processes(host(stuck_procs=fact({"total": 0, "rows": []}))).status == OK


def test_stuck_processes_names_the_count_the_age_and_the_module():
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 412,
        "rows": [stuck_row(3552973, 3783, "df -hP"),
                 stuck_row(2119, 274323, "/usr/lib64/sa/sadc -F -L -S DISK 1 1 -")],
    })))
    assert line.status == FLAG
    assert "412 stuck" in line.text
    assert "3d 4h" in line.text          # the oldest, not the first
    assert "cifs" in line.text


def test_stuck_processes_says_signals_will_not_help():
    """The single most useful thing to tell whoever reads this: do not go and try
    kill -9, it is not going to work, and that is the diagnosis rather than a nuisance."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 1, "rows": [stuck_row(1, 200, "df -hP")]})))
    assert "SIGKILL" in line.detail_text


def test_a_kernel_thread_is_listed_without_pretending_it_has_a_command():
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 1,
        "rows": [stuck_row(2715924, 500, "", module="cifs",
                           frame="smb2_reconnect+0x1/0x2 [cifs]")],
    })))
    assert "[kernel thread]" in line.detail_text


def test_stuck_processes_unknown_when_proc_could_not_be_read():
    line = checks.stuck_processes(host(stuck_procs=err("could not read /proc")))
    assert line.status == UNKNOWN
    assert line.flags


# --------------------------------------------------------------------------------------
# Network Mounts, and the rule about when not to probe
# --------------------------------------------------------------------------------------

def test_a_host_with_no_network_mounts_is_green():
    assert checks.network_mounts(host(network_mounts=fact([]))).status == OK


def test_mounts_that_all_answered_are_green():
    line = checks.network_mounts(host(network_mounts=fact([
        mount_row("/run/sr-mount/a", "ok", seconds=0.01),
        mount_row("/run/sr-mount/b", "ok", fstype="nfs", seconds=0.02)])))
    assert line.status == OK
    assert "2 responding" in line.text


def test_a_mount_that_never_answered_is_a_finding_naming_the_source():
    line = checks.network_mounts(host(network_mounts=fact([
        mount_row("/run/sr-mount/e512c88e", "no answer", why="did not die when killed"),
        mount_row("/run/sr-mount/8bdf2ce0", "ok", fstype="nfs", seconds=0.01)])))
    assert line.status == FLAG
    assert "1 of 2 not responding" in line.text
    assert "//10.10.10.11/XCP_ISO" in line.detail_text


def test_not_probed_is_unknown_and_never_green():
    """The load-bearing one. Skipping the probe is the right call on a host that already
    has stuck processes - but it means nothing was established about these mounts, and a
    green line there would be the exact overclaim this codebase exists to prevent."""
    line = checks.network_mounts(host(network_mounts=fact([
        mount_row("/run/sr-mount/e512c88e", "not probed",
                  why="this host already has 412 stuck process(es)")])))
    assert line.status == UNKNOWN
    assert line.flags
    assert "not probed" in line.text
    assert "412 stuck" in line.text       # and it says WHY it was not asked


def test_a_stat_that_failed_is_not_a_stat_that_hung():
    """Different facts: a mount point that is gone, or unreadable, is not a server that
    stopped answering, and folding them together would misdirect whoever reads it."""
    line = checks.network_mounts(host(network_mounts=fact([
        mount_row("/run/sr-mount/gone", "error", why="exit 1: No such file or directory")])))
    assert line.status == FLAG
    assert "could not be checked" in line.text
    assert "not responding" not in line.text


def test_network_mounts_unknown_when_mounts_could_not_be_read():
    line = checks.network_mounts(host(network_mounts=err("could not read /proc/mounts")))
    assert line.status == UNKNOWN
    assert line.flags


# --------------------------------------------------------------------------------------
# Mount Stalls
# --------------------------------------------------------------------------------------

def test_mount_stalls_reads_both_sources_and_needs_both_to_say_none():
    """Same rule as Multipath Path Events: neither source contains the other, so a clean
    answer requires that both were actually read."""
    clean = host(mount_stall_scan=fact([]), dmesg=fact("nothing to see here\n"))
    assert checks.mount_stalls(clean).status == OK

    assert checks.mount_stalls(
        host(mount_stall_scan=err(), dmesg=fact("clean\n"))).status == UNKNOWN
    assert checks.mount_stalls(
        host(mount_stall_scan=fact([]), dmesg=err())).status == UNKNOWN


def test_the_kernels_own_hung_task_line_is_caught():
    """It would otherwise be missed entirely: 'blocked for more than' matches none of
    DMESG_ISSUE_WORDS or DMESG_ISSUE_PHRASES, so Dmesg Content reads Clean straight past
    it - exactly how the multipath 'Failing path' line went unreported for so long."""
    ring = ("[Sun Sep  7 04:02:03 2026] INFO: task df:3552973 blocked for more than "
            "120 seconds.\n")
    line = checks.mount_stalls(host(mount_stall_scan=fact([]), dmesg=fact(ring)))
    assert line.status == FLAG
    assert "blocked for more than" in line.detail_text


def test_a_server_stall_from_either_filesystem_is_caught():
    for ring in ("[Sun Sep  7 04:02:03 2026] nfs: server 10.10.10.11 not responding, "
                 "still trying\n",
                 "[Sun Sep  7 04:02:03 2026] CIFS VFS: Server 10.10.10.11 has not "
                 "responded in 120 seconds. Reconnecting...\n"):
        line = checks.mount_stalls(host(mount_stall_scan=fact([]), dmesg=fact(ring)))
        assert line.status == FLAG, ring


# --------------------------------------------------------------------------------------
# the wiring
# --------------------------------------------------------------------------------------

def test_the_three_lines_are_in_the_report_table_with_toggles():
    table = dict((key, toggle) for toggle, key, _fn in main.per_host_checks())
    for key in ("Stuck Processes", "Mount Stalls", "Network Mounts"):
        assert key in table, "%s is not in the per-host table" % key
        assert table[key] in config.POOL_RUN


def test_the_collector_is_asked_for_what_the_checks_read():
    spec = main._host_spec(with_smapi=False)
    assert spec["stuck"]["recheck_delay"] == config.STUCK_RECHECK_DELAY
    assert spec["mount_probe"]["types"] == config.NETWORK_FS_TYPES
    assert spec["mount_stall_scan"]["phrases"] == config.MOUNT_STALL_PHRASES
