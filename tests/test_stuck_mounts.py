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
    state, starttime, cpu = collector.parse_proc_stat(" ".join(fields))
    assert state == "D"
    assert starttime == 22          # field 22 overall, whatever comm did
    assert cpu == 14 + 15           # utime and stime, the two that say it is getting on


def test_proc_stat_on_a_truncated_or_empty_line():
    assert collector.parse_proc_stat("") == (None, None, None)
    assert collector.parse_proc_stat("123 (sh) D 1 2 3") == (None, None, None)
    assert collector.parse_proc_stat("no parens here at all") == (None, None, None)


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
# what the collector will, and will not, call stuck
#
# The rule these pin is issue #70: D state is where a process waits on storage, so being
# in it - even at every sample - is not a fault. A finding needs the second, positive fact
# that the process got nowhere at all while it was watched.
# --------------------------------------------------------------------------------------

NOW = 100000.0                   # uptime at the first look, in seconds
SPEC = {"recheck_delay": 5, "samples": 3, "min_age": 60, "max_lines": 25}


def d_proc(age, cpu=0, io=""):
    """One process in D as a sample holds it: (starttime, cpu_ticks, /proc/PID/io).

    `age` is its age at the FIRST look; the collector reads the age it reports at the end,
    so a process watched through the whole window is reported that much older.
    """
    return (int((NOW - age) * 100), cpu, io)


class Clock(object):
    """A /proc/uptime that moves only when the collector sleeps, and remembers each wait."""

    def __init__(self):
        self.now = NOW
        self.slept = []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def watch(monkeypatch, scans, cmdline="df -hP"):
    """Run the collector against a scripted series of /proc scans. The last one repeats,
    so a single scan means 'nothing about this host changed while it was watched'."""
    clock = Clock()
    seq = list(scans)

    def scan(pids=None):
        current = seq.pop(0) if len(seq) > 1 else seq[0]
        if pids is None:
            return dict(current)
        return dict((pid, val) for pid, val in current.items() if pid in pids)

    monkeypatch.setattr(collector, "DEADLINE", [None])
    monkeypatch.setattr(collector, "_clock_ticks", lambda: 100.0)
    monkeypatch.setattr(collector, "_uptime", lambda: clock.now)
    monkeypatch.setattr(collector, "_d_state_procs", scan)
    if isinstance(cmdline, dict):
        monkeypatch.setattr(collector, "_proc_cmdline", lambda pid: cmdline.get(pid, ""))
    else:
        monkeypatch.setattr(collector, "_proc_cmdline", lambda pid: cmdline)
    monkeypatch.setattr(collector, "read_file", lambda path, limit=None: "")
    monkeypatch.setattr("time.sleep", clock.sleep)
    return collector.collect_stuck_processes(SPEC), clock


def test_a_process_that_is_working_is_not_stuck_however_long_it_sits_in_d(monkeypatch):
    """Issue #70, straight off a real report: a vhd-util coalesce one minute into its run,
    in D at two samples 5s apart, called stuck. It was copying data between VHDs, which is
    what D state IS, and its own CPU counter said so at the second look."""
    out, clock = watch(monkeypatch, [
        {931045: d_proc(62, cpu=4100)},
        {931045: d_proc(62, cpu=4160)},        # 0.6s of CPU in 5s: it is getting on
    ], cmdline="/usr/bin/vhd-util coalesce --debug -n /dev/VG_XenStorage-37ed224b/VHD-90")
    assert out["value"]["total"] == 0
    # and it cost one wait, not two: the second is only ever paid for a real suspect
    assert clock.slept == [5]


def test_progress_counts_even_when_none_of_it_is_cpu(monkeypatch):
    """The gap CPU time alone leaves open: a process can be almost purely I/O-bound, tick
    over a hundredth of a second of CPU in ten, and still be moving gigabytes."""
    out, _clock = watch(monkeypatch, [
        {4242: d_proc(300, cpu=7, io="read_bytes: 1048576\n")},
        {4242: d_proc(300, cpu=7, io="read_bytes: 9437184\n")},
    ])
    assert out["value"]["total"] == 0


def test_a_process_that_gets_nowhere_at_all_is_the_finding(monkeypatch):
    """The case the check exists for: same process, same counters, every look."""
    out, clock = watch(monkeypatch, [{3552973: d_proc(3783, cpu=12, io="read_bytes: 4096\n")}])
    assert out["value"]["total"] == 1
    assert out["value"]["watched"] == 10        # and it says how long it actually looked
    assert clock.slept == [5, 5]
    assert out["value"]["rows"][0]["age"] == 3793   # read at the end, so 10s older


def test_a_reused_pid_does_not_inherit_the_first_processes_wait(monkeypatch):
    """A pid freed and handed to something else is a different process, and must not be
    reported as one that has been waiting since the first sample."""
    out, _clock = watch(monkeypatch, [
        {700: d_proc(3000, cpu=5)},
        {700: d_proc(2, cpu=5)},                # same pid, started since: not the same wait
    ])
    assert out["value"]["total"] == 0


def test_nothing_old_enough_in_d_costs_no_wall_clock_at_all(monkeypatch):
    """The usual host: whatever is in D is a disk read a second old. The age floor is
    applied before the first wait for exactly that reason."""
    out, clock = watch(monkeypatch, [{99: d_proc(3, cpu=1)}])
    assert out["value"]["total"] == 0
    assert clock.slept == []


def test_the_scripts_own_parked_probes_are_counted_as_its_own(monkeypatch):
    """They are genuinely stuck and are not hidden - but every run leaves another one on a
    mount that has stopped answering, and a count that climbs on its own would read as the
    host degrading further when it is only this tool's own leavings."""
    probe_cmd = "stat -c %s %%i -- /run/sr-mount/e512c88e" % collector.MOUNT_PROBE_MARK
    out, _clock = watch(monkeypatch, [{101: d_proc(3000), 102: d_proc(2000)}],
                        cmdline={101: "df -hP", 102: probe_cmd})
    assert out["value"]["total"] == 2
    assert out["value"]["own_probes"] == 1


def test_a_process_on_the_age_floor_is_not_dropped_for_being_caught_early(monkeypatch):
    """The floor is 'old enough by the END of the window', so it is applied once and a
    process 52s old at the first look is reported at 62s rather than missed entirely."""
    out, _clock = watch(monkeypatch, [{800: d_proc(52, cpu=3)}])
    assert out["value"]["total"] == 1
    assert out["value"]["rows"][0]["age"] == 62


# --------------------------------------------------------------------------------------
# probing the mounts, and the one question that is still not asked
#
# Every mount is probed now, on every host, stuck processes or not: the cost the old gate
# was avoiding is one parked stat on a host that already has a pile of them, and it buys
# the only answer that names WHICH mount is dead.
# --------------------------------------------------------------------------------------

PROBE_SPEC = {"types": config.NETWORK_FS_TYPES, "probe_timeout": 10}
DEAD_MOUNT = "//10.10.10.11/XCP_ISO /run/sr-mount/e512c88e cifs rw,vers=3.0,soft 0 0\n"


def probe(monkeypatch, mounts, budget=None, answer=None, spec=None):
    """Run the mount collection over a /proc/mounts, capturing what it actually ran."""
    ran = []

    def fake_run(argv, timeout=None):
        ran.append((argv, timeout))
        if answer is not None:
            return answer
        return collector.Ran(0, "12345", "", False)

    monkeypatch.setattr(collector, "DEADLINE", [None] if budget is None
                        else [collector.time.time() + budget])
    monkeypatch.setattr(collector, "read_file", lambda path, limit=None: mounts)
    monkeypatch.setattr(collector, "run", fake_run)
    return collector.collect_network_mounts(spec or PROBE_SPEC), ran


def test_a_mount_is_probed_even_where_the_old_gate_would_have_skipped_it(monkeypatch):
    """There is no longer anything that can turn the probe off: the collector cannot pass
    it a reason to skip, so a host deep in stuck processes gets the same answer as any
    other. It is the only line that can say which mount is the dead one."""
    out, ran = probe(monkeypatch, DEAD_MOUNT)
    assert out["value"][0]["state"] == "ok"
    assert len(ran) == 1
    assert ran[0][0][-1] == "/run/sr-mount/e512c88e"


def test_the_probe_marks_itself_so_the_next_run_knows_whose_it_is(monkeypatch):
    """It is left in D state on a dead mount by design, and it will be found there. The
    mark is in stat's format string, which is argv, and so is readable from /proc."""
    _out, ran = probe(monkeypatch, DEAD_MOUNT)
    assert collector.MOUNT_PROBE_MARK in " ".join(ran[0][0])


def test_a_probe_with_no_budget_left_to_run_in_is_not_run_at_all(monkeypatch):
    """run() would clamp it to the sliver of budget left and report the timeout as 'no
    answer' - a mount that was merely slow, called dead. Nothing is asked instead."""
    out, ran = probe(monkeypatch, DEAD_MOUNT, budget=3)
    assert ran == []
    assert out["value"][0]["state"] == "not probed"
    assert "run budget" in out["value"][0]["why"]


def test_the_probes_leave_the_rest_of_the_run_enough_budget_to_finish(monkeypatch):
    """Every dead mount costs a full probe timeout now, so without a reserve a host with
    several of them would spend the whole run parked here and everything after - yum, the
    pool questions - would time out behind it with nothing to show for it."""
    spec = dict(PROBE_SPEC, probe_reserve=60)
    out, ran = probe(monkeypatch, DEAD_MOUNT, budget=40, spec=spec)
    assert ran == []
    assert out["value"][0]["state"] == "not probed"
    # and with the reserve intact it goes ahead
    out, ran = probe(monkeypatch, DEAD_MOUNT, budget=200, spec=spec)
    assert len(ran) == 1
    assert out["value"][0]["state"] == "ok"


def test_a_probe_that_hung_is_a_dead_mount_and_one_that_failed_is_not(monkeypatch):
    out, _ran = probe(monkeypatch, DEAD_MOUNT,
                      answer=collector.Ran(124, "", "timed out", True))
    assert out["value"][0]["state"] == "no answer"
    out, _ran = probe(monkeypatch, DEAD_MOUNT,
                      answer=collector.Ran(1, "", "No such file or directory", False))
    assert out["value"][0]["state"] == "error"


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


def test_the_summary_does_not_pass_process_age_off_as_time_spent_stuck():
    """The two are not the same number and the line must not imply they are: age is how
    long the process has existed, an upper bound on the wait. They coincide for a df that
    wedged the moment it ran, and are days apart for a daemon up since boot."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 1, "userspace": 1, "watched": 10,
        "rows": [stuck_row(3552973, 275000, "df -hP")]})))
    assert "1 stuck (oldest started 3d 4h ago)" in line.text


def test_kernel_threads_on_their_own_say_so_in_the_line():
    """A parked kworker and a host that has lost commands read identically otherwise, and
    they are not the same news."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 2, "userspace": 0, "watched": 10,
        "rows": [stuck_row(217, 4000, ""), stuck_row(218, 3000, "")]})))
    assert "2 stuck, all kernel threads" in line.text


def test_the_block_says_what_was_measured_and_what_was_not():
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 1, "userspace": 1, "watched": 10,
        "rows": [stuck_row(3552973, 3783, "df -hP")]})))
    assert "no CPU and completed no I/O for the whole 10s" in line.detail_text
    assert "upper bound" in line.detail_text


def test_the_block_names_the_probes_this_script_left_behind():
    """The self-footprint rule, applied where the footprint is deliberate: the probes are
    counted, and they are named, so nobody reads 28 of them as 28 separate problems."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 30, "userspace": 30, "watched": 10, "own_probes": 28,
        "rows": [stuck_row(1, 3000, "df -hP")]})))
    assert "28 of them are this script's own mount probes" in line.detail_text


def test_a_collector_that_did_not_time_its_window_claims_no_window():
    """An older collector, or one the budget cut short before it could watch at all."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 1, "userspace": 1,
        "rows": [stuck_row(3552973, 3783, "df -hP")]})))
    assert "was watched" not in line.detail_text
    assert "own mount probes" not in line.detail_text
    assert "upper bound" in line.detail_text      # the caveat is not conditional


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
    """The load-bearing one. A probe there is no time left to run is the right thing to
    skip - run() would clamp it to the last second of the budget and report a slow mount
    as a dead one - but it means nothing was established about this mount, and a green
    line there would be the exact overclaim this codebase exists to prevent."""
    line = checks.network_mounts(host(network_mounts=fact([
        mount_row("/run/sr-mount/e512c88e", "not probed",
                  why="no time left in the run budget to wait 10s for an answer")])))
    assert line.status == UNKNOWN
    assert line.flags
    assert "not probed" in line.text
    assert "run budget" in line.text      # and it says WHY it was not asked


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
    assert spec["stuck"]["samples"] == config.STUCK_SAMPLES
    assert spec["mount_probe"]["types"] == config.NETWORK_FS_TYPES
    assert spec["mount_probe"]["probe_reserve"] == config.MOUNT_PROBE_RESERVE
    assert spec["mount_stall_scan"]["phrases"] == config.MOUNT_STALL_PHRASES


def test_the_userspace_tally_counts_every_process_not_just_the_listed_ones():
    """Straight off a real report: 589 stuck, 25 listed, and the block said "24 of them
    userspace" - a count taken from the sample and printed as if it described the whole.
    The collector counts before it caps, and the check must use that number."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 589,
        "userspace": 24,
        "rows": [stuck_row(1000 + n, 300000 - n, "sadc") for n in range(25)],
    })))
    assert "589 process(es)" in line.detail_text
    assert "24 of them userspace" in line.detail_text
    # and the listing says outright that it is a slice
    assert "(oldest 25 of 589 shown)" in line.detail_text


def test_an_uncapped_listing_does_not_claim_to_be_a_slice():
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 2, "userspace": 2,
        "rows": [stuck_row(1, 300, "df -hP"), stuck_row(2, 200, "lsof")],
    })))
    assert "shown)" not in line.detail_text
    assert "(listed oldest first)" in line.detail_text


def test_a_collector_that_did_not_send_a_tally_says_nothing_about_one():
    """An older collector, or one that stopped early - the block must drop the sentence
    rather than guess a number for it."""
    line = checks.stuck_processes(host(stuck_procs=fact({
        "total": 3, "rows": [stuck_row(1, 300, "df -hP")]})))
    assert "userspace" not in line.detail_text
    assert "3 process(es) in uninterruptible sleep." in line.detail_text


def test_the_collector_counts_userspace_before_it_caps(monkeypatch):
    """The other half of the same rule, at the source."""
    monkeypatch.setattr(collector, "DEADLINE", [None])
    monkeypatch.setattr(collector, "_proc_pids", lambda: list(range(1, 31)))
    monkeypatch.setattr(collector, "_d_state_procs",
                        lambda pids=None: dict((n, (100, 0, "")) for n in range(1, 31)))
    monkeypatch.setattr(collector, "_proc_cmdline",
                        lambda pid: "cmd %d" % pid if pid % 2 else "")
    monkeypatch.setattr(collector, "read_file",
                        lambda path: "999999.0 0.0" if path == "/proc/uptime" else "")

    out = collector.collect_stuck_processes({"recheck_delay": 0, "min_age": 0,
                                             "max_lines": 5})
    assert out["ok"]
    assert out["value"]["total"] == 30
    assert out["value"]["userspace"] == 15      # counted over all 30, not the 5 kept
    assert len(out["value"]["rows"]) == 5
