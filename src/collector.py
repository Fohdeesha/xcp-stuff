# -*- coding: utf-8 -*-
"""The remote collector: everything that has to happen ON a hypervisor.

This file is shipped to the host over ssh stdin (or run locally in host mode) and
answers with one JSON document, so a whole host is one round trip instead of ~20.

Two hard rules govern it:

  * It must parse and run under **Python 2.7.5 and 3.6.8**. 8.2.1 dom0 has no python3
    at all and 8.3.0 has both (measured 2026-08-25), so the lowest common denominator
    is what keeps 8.2.1 pools checkable from XOA. No f-strings, no print(), no
    subprocess.run, no pathlib, no typing.
  * Every fact is wrapped by fact()/err() so the wire format itself distinguishes
    "we looked and this is the answer" from "we could not look". The report can then
    never print green off something that was never established - the single most
    important invariant this tool has.

It shells out for the things C is better at (grep over a 30 MB xensource.log, sed for
context extraction) and does everything else natively. It never uses a shell: every
command is an argv list, so quoting bugs are structurally impossible.
"""

import base64
import errno
import json
import os
import re
import subprocess
import sys
import threading
import time

BEGIN_MARKER = "<<<HEALTHPY-JSON-BEGIN>>>"
END_MARKER = "<<<HEALTHPY-JSON-END>>>"

DEFAULT_CMD_TIMEOUT = 60

# Whole-run budget. Every command's timeout is clamped to what is left of it, so a host
# whose xapi is wedged answers with a partial document full of explicit errors instead of
# hanging until the transport gives up and the report loses the host entirely.
DEADLINE = [None]

# Where a host's time actually went. Every command run on a host goes through run() or
# grep_scan(), so this is complete by construction rather than by remembering to
# instrument each caller. It is returned only when the spec asks for it (HEALTH_DEBUG),
# but it is always collected: a list append per command is nothing next to the command.
#
# The reason it exists: a host that takes four minutes used to be a host that took four
# minutes, with nothing to say which of its ~60 commands took them. Working that out from
# the outside costs one round trip per candidate, and a wrong guess looks exactly like a
# right one until you have run it.
TIMINGS = []

# The command running right now, and the document as it is built. Both exist for the
# watchdog: when a command cannot be killed, these are the only things left to answer with.
# One-element lists and a module dict rather than plain globals, so every writer can set
# them without a `global` statement (2.7 has no nonlocal).
CURRENT = [""]
PARTIAL = {}

# Commands that outlived their own SIGKILL. Not a report line - the fact each one was
# collecting already says Unknown with the reason, and the trap ledger is explicit about
# not reporting one thing twice in different words. It rides along only in the watchdog's
# payload, where "these had already been abandoned before the fatal one" is additive.
ABANDONED = []

# How long to wait for a killed command to actually die before giving up on it. A child
# that CAN be killed is gone in milliseconds; anything still there after this is in
# uninterruptible sleep and is not coming back on any timescale worth waiting for.
KILL_GRACE = 5

# How long past the budget the watchdog waits before giving up on the main thread. The
# transport allows REMOTE_CMD_TIMEOUT (300s) against a 240s budget, so this has to leave
# the abandoned document time to travel.
WATCHDOG_GRACE = 15


def _argv_text(argv):
    """Enough of an argv to identify it, on one line.

    The argv rather than a description of it, so the command can be pasted straight into a
    shell on the host. Whitespace is collapsed because rpm's --qf formats carry literal
    newlines, and a long one is elided in the MIDDLE rather than the tail: the path is at
    the end, and "a grep took 90 seconds" is not an answer without the file it was reading.
    """
    text = " ".join(" ".join(str(arg).split()) for arg in argv)
    if len(text) > 110:
        text = text[:60] + " ... " + text[-45:]
    return text


def timed(argv, started):
    """Record one command's elapsed seconds, with enough argv to identify it."""
    TIMINGS.append([round(time.time() - started, 2), _argv_text(argv)])


def budget_left():
    if DEADLINE[0] is None:
        return None
    return DEADLINE[0] - time.time()


# --------------------------------------------------------------------------------------
# fact envelope
# --------------------------------------------------------------------------------------

def fact(value):
    return {"ok": True, "value": value}


def err(reason):
    return {"ok": False, "error": reason}


# --------------------------------------------------------------------------------------
# process helpers
# --------------------------------------------------------------------------------------

class Ran(object):
    """Result of one subprocess: rc, decoded stdout/stderr, and whether it timed out."""

    def __init__(self, rc, out, error, timed_out):
        self.rc = rc
        self.out = out
        self.err = error
        self.timed_out = timed_out

    @property
    def ok(self):
        return self.rc == 0 and not self.timed_out

    def why(self):
        if self.timed_out:
            return "timed out"
        msg = self.err.strip().splitlines()
        if msg:
            return "exit %d: %s" % (self.rc, msg[0][:200])
        return "exit %d" % self.rc


def _decode(b):
    """Bytes to text, never raising. Remote logs are not guaranteed to be UTF-8."""
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return b


def _popen(argv, stdout=subprocess.PIPE):
    devnull = open(os.devnull, "rb")
    try:
        kwargs = {
            "stdout": stdout,
            "stderr": subprocess.PIPE,
            "stdin": devnull,
            "close_fds": True,
        }
        if hasattr(os, "setsid"):
            # own process group, so a timeout kills the whole tree and not just the
            # front of a pipeline - the same reason bash used 'timeout -k 5'
            kwargs["preexec_fn"] = os.setsid
        return subprocess.Popen(argv, **kwargs), devnull
    except Exception:
        devnull.close()
        raise


def _kill(proc):
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), 9)
        else:
            proc.kill()
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            pass


def run(argv, timeout=DEFAULT_CMD_TIMEOUT):
    """Run argv (no shell, ever) and return a Ran. Reads to EOF - see the xe/EPIPE note.

    A command that will not die is one we stop waiting for. The timeout used to be a
    threading.Timer firing SIGKILL while the main thread sat in communicate(), which
    assumes the signal lands: a process in uninterruptible sleep (D state) does NOT die on
    SIGKILL - the signal stays pending until it leaves D, which may be never - so
    communicate() never returned, the collector never finished, and the transport lost the
    WHOLE HOST to its own timeout.

    Measured: a dom0 with a dead CIFS mount parks `df -hP` in D state permanently (wchan
    open_shroot / smb2_reconnect). Five health check runs left five stuck df processes and
    not one of them produced a document; the host reported only "timed out after 300s",
    naming neither the command nor the mount.

    So communicate() happens on a daemon thread and this joins it with a deadline. When
    the kill does not take, the thread and its pipes are abandoned deliberately - the child
    cannot be reaped, so there is nothing to clean up - and the collector goes on to the
    next fact. One line then reads Unknown with the reason, instead of every line about
    that host disappearing.
    """
    started = time.time()
    timeout = _clamp(timeout)
    if timeout is None:
        timed(argv, started)
        return Ran(124, "", "run budget exhausted", True)
    try:
        proc, devnull = _popen(argv)
    except OSError as exc:
        timed(argv, started)
        return Ran(127, "", "%s: %s" % (argv[0], exc), False)

    # named before it can block, cleared after: if this one never returns, it is the only
    # record of what the collector was doing when it stopped
    CURRENT[0] = _argv_text(argv)
    box = {}

    def reader():
        try:
            box["out"], box["err"] = proc.communicate()
        except (IOError, OSError, ValueError) as exc:
            # the pipes are ours and nobody else touches them, so this is a broken pipe or
            # a closed file - never a command result, and never silently a success
            box["failed"] = "%s: %s" % (argv[0], exc)

    worker = threading.Thread(target=reader)
    worker.daemon = True
    worker.start()
    worker.join(timeout)

    killed = worker.is_alive()
    if killed:
        _kill(proc)
        worker.join(KILL_GRACE)      # a killable child dies here and the thread ends

    abandoned = worker.is_alive()
    timed(argv, started)
    CURRENT[0] = ""
    devnull.close()

    if abandoned:
        ABANDONED.append(_argv_text(argv))
        return Ran(124, "", "did not die when killed - uninterruptible, so the host's "
                            "storage or a mount is most likely wedged", True)
    if "failed" in box:
        return Ran(127, "", box["failed"], False)
    return Ran(proc.returncode, _decode(box.get("out")), _decode(box.get("err")), killed)


def _clamp(timeout):
    """Shrink a command timeout to whatever is left of the whole-run budget."""
    left = budget_left()
    if left is None:
        return timeout
    if left <= 0.5:
        return None
    return min(timeout, left)


def which(name):
    """PATH lookup without shutil.which (absent on 2.7) and without a shell."""
    for part in (os.environ.get("PATH") or "").split(os.pathsep):
        if not part:
            continue
        candidate = os.path.join(part, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def xe(args, timeout=DEFAULT_CMD_TIMEOUT):
    return run(["xe"] + list(args), timeout=timeout)


def read_file(path, limit=None):
    """Whole file as text, or None if it cannot be read."""
    try:
        f = open(path, "rb")
    except (IOError, OSError):
        return None
    try:
        data = f.read() if limit is None else f.read(limit)
    except (IOError, OSError):
        return None
    finally:
        f.close()
    return _decode(data)


# --------------------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------------------

def os_release():
    text = read_file("/etc/os-release")
    if text is None:
        return err("could not read /etc/os-release")
    out = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return fact(out)


def inventory_uuid():
    text = read_file("/etc/xensource-inventory")
    if text is None:
        return None
    m = re.search(r"^INSTALLATION_UUID='([^']*)'", text, re.M)
    return m.group(1) if m else None


def short_hostname():
    r = run(["hostname", "-s"], timeout=10)
    name = r.out.strip() if r.ok else ""
    if not name:
        r = run(["hostname"], timeout=10)
        name = r.out.strip() if r.ok else ""
    return name.split(".")[0] if name else ""


def collect_identity():
    out = {}
    out["now"] = fact(time.time())
    out["hostname"] = fact(short_hostname())
    out["os_release"] = os_release()

    uuid = inventory_uuid()
    if uuid and re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", uuid):
        out["self_uuid"] = fact(uuid)
        r = xe(["host-param-get", "uuid=" + uuid, "param-name=address"], timeout=20)
        if r.ok:
            out["self_address"] = fact(r.out.strip())
        else:
            out["self_address"] = err("xe host-param-get address failed (%s)" % r.why())
    else:
        out["self_uuid"] = err("no INSTALLATION_UUID in /etc/xensource-inventory")
        out["self_address"] = err("host uuid unknown")

    pc = read_file("/etc/xensource/pool.conf")
    if pc is None:
        out["pool_conf"] = err("could not read /etc/xensource/pool.conf")
    else:
        out["pool_conf"] = fact(pc.replace("\r", "").strip())
    return out


def collect_pool_hosts():
    """One labelled xe call for the whole pool.

    Deliberately NOT 'host-list params=... --minimal': --minimal with several params
    prints a single value and accepts unknown param names silently, which would fill
    every host map with garbage. The labelled form is parsed by label, never by
    position - the field order xapi prints is not the order asked for.
    """
    r = xe(["host-list", "params=uuid,name-label,hostname,address,enabled,multipathing"])
    if not r.ok:
        return err("xe host-list failed (%s)" % r.why())
    return fact(r.out)


# --------------------------------------------------------------------------------------
# per-host facts
# --------------------------------------------------------------------------------------

def collect_meminfo():
    text = read_file("/proc/meminfo")
    if text is None:
        return err("could not read /proc/meminfo")
    return fact(text)


def collect_timedatectl():
    r = run(["timedatectl"], timeout=20)
    if not r.ok:
        return err("timedatectl failed (%s)" % r.why())
    return fact(r.out)


def collect_dmesg():
    r = run(["dmesg", "-T"], timeout=60)
    if not r.ok:
        return err("could not read dmesg (%s)" % r.why())
    return fact(r.out)


def collect_df():
    r = run(["df", "-hP"], timeout=30)
    if not r.ok:
        return err("df failed (%s)" % r.why())
    return fact(r.out)


# --------------------------------------------------------------------------------------
# stuck mounts, and the processes they take down with them
# --------------------------------------------------------------------------------------

def parse_proc_stat(text):
    """(state, starttime_ticks, cpu_ticks) from one /proc/PID/stat, or (None, None, None).

    The comm field is the trap, and a real one rather than a hypothetical: it is the
    executable name in parentheses, unescaped, and may contain both spaces and
    parentheses - a process can genuinely be called `(foo) bar)`. Splitting on whitespace,
    or on the FIRST ')', mis-numbers every field after it, and here that would silently
    read some other number as the state. rfind(')') is the documented way round it: comm
    is the only parenthesised field, and nothing after it can contain one.

    Fields after that closing paren are 3..52, so state is [0], utime and stime are [11]
    and [12], and starttime is [19]. The CPU pair is read here rather than by a second
    reader because it has to come from the SAME line as the state: two reads would let the
    process move between them, and the entire value of the number is that it did not.

    starttime and cpu are answered together or not at all, so a caller that has a
    starttime always has a cpu figure to go with it.
    """
    close = text.rfind(")")
    if close < 0:
        return (None, None, None)
    rest = text[close + 1:].split()
    if len(rest) < 20:
        return (None, None, None)
    try:
        return (rest[0], int(rest[19]), int(rest[11]) + int(rest[12]))
    except ValueError:
        return (rest[0], None, None)


_MOUNT_ESCAPES = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


def _unescape_mount(field):
    """Undo /proc/mounts' octal escaping - a mount point with a space in it is written
    with a backslash and 040, and would otherwise arrive with the escape still in it."""
    if "\\" not in field:
        return field
    out = []
    i = 0
    while i < len(field):
        if field[i] == "\\" and field[i + 1:i + 4] in _MOUNT_ESCAPES:
            out.append(_MOUNT_ESCAPES[field[i + 1:i + 4]])
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def parse_mounts(text, network_types):
    """[(source, target, fstype)] for the network mounts in /proc/mounts, in file order.

    /proc/mounts is served by the kernel out of its own mount table, so reading it cannot
    block on a mount that has stopped answering - which stat() of the same path very much
    can. That difference is the whole basis of this check.
    """
    wanted = set(network_types or [])
    found = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] not in wanted:
            continue
        found.append((_unescape_mount(parts[0]), _unescape_mount(parts[1]), parts[2]))
    return found


def fs_module_of(stack_text):
    """The module a kernel stack is blocked in, e.g. 'cifs' or 'nfs'; "" if none.

    /proc/PID/stack prints module-owned frames as `symbol+0x1/0x2 [module]`, which turns
    "something is stuck" into "stuck in the SMB client" without any guessing. The wchan
    column is NOT a substitute: it resolves through a symbol table that can be wrong, and
    was - naming one cifs symbol for every stuck process on a host, kernel threads that
    never touch cifs included.
    """
    for line in (stack_text or "").splitlines():
        text = line.strip()
        # the module is a trailing [name]; every frame ALSO opens with an address column
        # spelled [<0>], and taking the last '[' without this ends up returning that
        if not text.endswith("]"):
            continue
        start = text.rfind("[")
        if start < 0:
            continue
        module = text[start + 1:-1].strip()
        if re.match(r"^\w+$", module):
            return module
    return ""


def _proc_pids():
    try:
        return sorted(int(name) for name in os.listdir("/proc") if name.isdigit())
    except (IOError, OSError):
        return None


def _clock_ticks():
    """USER_HZ - the unit /proc/PID/stat counts both of its times in. 100 on everything
    this runs on, but asked for rather than assumed, and defaulted rather than raising."""
    try:
        return float(os.sysconf("SC_CLK_TCK")) or 100.0
    except (ValueError, OSError, AttributeError):
        return 100.0


def _uptime():
    """Seconds since boot, the clock /proc/PID/stat's starttime is measured against."""
    text = read_file("/proc/uptime") or ""
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def _proc_io(pid):
    """/proc/PID/io as it stands, or "" - the byte and syscall counters, unparsed.

    Compared verbatim against a later reading, so there is nothing to parse: every counter
    in it only ever grows, and it grows only when the process gets somewhere. It is the
    half of the progress test that CPU time cannot cover, since a process can be almost
    purely I/O-bound and tick over a hundredth of a second of CPU in ten.

    "" when the kernel was built without CONFIG_TASK_IO_ACCOUNTING, which is not an error:
    it then contributes no evidence in either direction and the CPU figure decides alone.
    """
    return read_file("/proc/%d/io" % pid) or ""


def _d_state_procs(pids=None):
    """{pid: (starttime, cpu_ticks, io)} for the processes in uninterruptible sleep now.

    Everything read here is served out of kernel memory by procfs, so none of it can block
    on the very mount being investigated - which is the whole reason this is the primary
    signal rather than stat()ing mount points and seeing what hangs.

    The value carries the identity AND the progress evidence, so two samples compare with
    a single ==: the same process (starttime pins it - a pid freed and reused in between
    is a different process and must not inherit the first one's history), which has not
    consumed a tick of CPU or completed a byte of I/O since the last look.

    `pids` narrows the scan to a set already under suspicion, which is all the later
    samples need and saves re-reading every process on the host.
    """
    if pids is None:
        pids = _proc_pids()
        if pids is None:
            return None
    found = {}
    for pid in pids:
        text = read_file("/proc/%d/stat" % pid)
        if not text:
            continue                      # exited between listdir and open: not an error
        state, starttime, cpu = parse_proc_stat(text)
        if state == "D" and starttime is not None:
            found[pid] = (starttime, cpu, _proc_io(pid))
    return found


def _proc_cmdline(pid):
    """The command, or "" for a kernel thread - which is how kernel threads are told apart.

    NUL-separated, and deliberately not /proc/PID/cmdline's neighbours cwd/exe/root: those
    are symlinks INTO the filesystem, so resolving one belonging to a process stuck on a
    dead mount blocks this collector in exactly the way it is here to detect.
    """
    raw = read_file("/proc/%d/cmdline" % pid)
    if not raw:
        return ""
    return " ".join(part for part in raw.split("\0") if part).strip()


# The mount probe never returns on a dead mount, so it is left parked in D state and the
# NEXT run finds it - and would count the script's own leavings as if the host had
# degraded further on its own. stat's format string is part of its argv, so putting a mark
# in it makes those processes identifiable in /proc with certainty, rather than by
# guessing at what a bare `stat` in D state belongs to. Only stat's exit status is read,
# so the mark changes nothing else.
MOUNT_PROBE_MARK = "health-mount-probe"


def collect_stuck_processes(spec):
    """Processes wedged in uninterruptible sleep, watched long enough to tell them apart
    from processes doing work.

    D state is where a process waits on storage, so a healthy host is full of it in
    passing: every disk read, every coalesce, every backup is in D for some of its life.
    Two facts separate a wedge from work and BOTH are required.

    Persistence: the same process must be in D at every sample across the window.

    Progress: it must have got nowhere in that time - not one tick of CPU, not one byte
    through /proc/PID/io. That is a fact rather than a heuristic, and it is the one that
    matters: a process parked in D executes no instructions and completes no I/O, while
    anything making progress is being woken constantly to hand off the next buffer. Read
    live as a false positive (issue #70) before this existed: a vhd-util coalesce one
    minute into its run, in D at both samples, reported as stuck.

    The age floor is a noise filter and nothing more - a process's age is how long it has
    existed, an upper bound on how long it has been stuck. It is applied here, before the
    first wait, rather than at the end: whatever is in D on the usual host is a disk read
    a second old, and dropping it up front means that host pays no wall clock at all.

    Kernel threads are counted separately rather than dropped: some sit in D quite
    normally, but a kworker stuck in a filesystem's work queue is exactly the corroboration
    that the mount, and not the process, is the problem.
    """
    settings = spec or {}
    delay = settings.get("recheck_delay") or 0
    rounds = max(1, (settings.get("samples") or 2) - 1)
    min_age = settings.get("min_age") or 0
    cap = settings.get("max_lines") or 0

    ticks = _clock_ticks()
    started = _uptime()
    if started is None:
        return err("could not read /proc/uptime")
    procs = _d_state_procs()
    if procs is None:
        return err("could not read /proc")

    # "old enough by the END of the window", so the floor is applied exactly once and a
    # process on the boundary is not dropped for being seen a few seconds too early
    floor = min_age - (delay * rounds)
    watching = dict((pid, seen) for pid, seen in procs.items()
                    if started - (seen[0] / ticks) >= floor)

    watched = 0.0
    for _ in range(rounds):
        if not watching:
            break                         # nothing left to watch: stop paying for looks
        pause = min(delay, max(1, budget_left() or delay))
        time.sleep(pause)
        watched += pause
        again = _d_state_procs(sorted(watching))
        if again is None:
            return err("could not read /proc")
        # one == over the whole tuple: still in D, still the same process, and not a tick
        # of CPU or a byte of I/O since the last sample
        watching = dict((pid, seen) for pid, seen in watching.items()
                        if again.get(pid) == seen)

    now = _uptime()
    if now is None:
        return err("could not read /proc/uptime")

    rows = []
    for pid, seen in watching.items():
        stack = read_file("/proc/%d/stack" % pid) or ""
        rows.append({
            "pid": pid,
            "age": int(now - (seen[0] / ticks)),
            "cmd": _proc_cmdline(pid)[:120],
            "module": fs_module_of(stack),
            "frame": (stack.splitlines() or [""])[0].strip()[:120],
        })
    rows.sort(key=lambda row: row["age"], reverse=True)
    # counted here, over ALL of them, because the cap below is what the report sees: a
    # tally taken from the sample would be printed as if it described the whole, and on
    # the host this was built for that is 24 of 25 shown being reported as 24 of 589
    return fact({"total": len(rows),
                 "userspace": len([row for row in rows if row["cmd"]]),
                 # the script's own probes from earlier runs, counted rather than hidden:
                 # they really are stuck, and they really were left by this tool
                 "own_probes": len([row for row in rows
                                    if MOUNT_PROBE_MARK in (row["cmd"] or "")]),
                 "watched": int(watched),
                 "rows": rows[:cap] if cap else rows})


def collect_network_mounts(spec):
    """Whether each network mount still answers a stat().

    The probe is a separate short-lived process precisely because it may never return: a
    mount whose server has gone parks it in D state for good, and run() abandons it rather
    than waiting. That leaves one unkillable process behind per dead mount, and it is done
    knowingly. Until v3.12 it was skipped entirely on a host that already had stuck
    processes, so as not to add to the mess being reported - but by then the mess is made,
    one more parked stat changes nothing about a host in that state, and this is the only
    check that can say WHICH mount is the one to go and fix. That is worth a process.
    The probes mark themselves, so a later run reports them as what they are.

    The one question still not asked is the one there is no time left to answer. run()
    clamps a command's timeout to what remains of the whole-run budget, so a probe started
    with a second left would report a mount that was merely slow as one that never
    answered. That is a claim, and the mount is listed unprobed instead.

    The reserve is the other half of that: each dead mount costs a full probe_timeout, so
    a host with several of them could spend the entire run parked here and leave yum and
    the pool questions to time out behind it. Probing stops with the reserve intact and
    the rest of the mounts say they were not asked.
    """
    settings = spec or {}
    timeout = settings.get("probe_timeout") or 10
    reserve = settings.get("probe_reserve") or 0
    text = read_file("/proc/mounts")
    if text is None:
        return err("could not read /proc/mounts")
    mounts = parse_mounts(text, settings.get("types") or [])

    rows = []
    for source, target, fstype in mounts:
        row = {"source": source, "target": target, "type": fstype}
        left = budget_left()
        if left is not None and left < timeout + reserve:
            row["state"] = "not probed"
            row["why"] = ("not enough of the run budget left to wait %ds for an answer"
                          % timeout)
        else:
            started = time.time()
            r = run(["stat", "-c", MOUNT_PROBE_MARK + " %i", "--", target],
                    timeout=timeout)
            row["seconds"] = round(time.time() - started, 2)
            if r.ok:
                row["state"] = "ok"
            elif r.timed_out:
                row["state"] = "no answer"
                row["why"] = r.err.strip()[:160]
            else:
                # a stat that FAILED is not a stat that hung: permission, a path that is
                # gone. Reported as its own state rather than folded into either
                row["state"] = "error"
                row["why"] = r.why()[:160]
        rows.append(row)
    return fact(rows)


def collect_iplink():
    r = run(["ip", "-o", "link", "show"], timeout=20)
    if not r.ok:
        return err("ip link show failed (%s)" % r.why())
    return fact(r.out)


def collect_ipaddr():
    r = run(["ip", "-o", "-4", "addr", "show"], timeout=20)
    if not r.ok:
        return err("ip -4 addr show failed (%s)" % r.why())
    return fact(r.out)


def collect_lacp():
    """ovs-appctl answers rc 0 with empty output when there are simply no LACP bonds,
    and rc != 0 when it cannot reach ovs-vswitchd at all. Those are different facts."""
    r = run(["ovs-appctl", "lacp/show"], timeout=30)
    if r.timed_out:
        return err("could not query Open vSwitch (timed out)")
    if r.rc != 0:
        return err("could not query Open vSwitch")
    return fact(r.out)


# multipathd's own format wildcards. 'raw' is what omits the header row - verified on
# 0.4.9-136 on both 8.2.1 and 8.3.0, so every line that comes back is data.
#   paths: %m map  %d dev  %D dev_t  %t dm_st  %T chk_st  %o dev_st  %p prio
#   maps:  %n name %N usable-paths %t dm_st %Q queueing %x map-failures %0 path-faults
#          %f features
MP_PATH_FORMAT = "%m|%d|%D|%t|%T|%o|%p"
MP_MAP_FORMAT = "%n|%N|%t|%Q|%x|%0|%f"
MP_PATH_CHK_FIELD = 4       # index of %T in MP_PATH_FORMAT
MP_QUERY_TIMEOUT = 20


def _mp_transient(text, transient):
    """True when a path that BELONGS TO A MAP is still mid-check.

    A path in no map is reported under a bracketed pseudo-name ('[orphan]', '[undef]',
    '[unknown]') and is permanently 'undef' - every local disk on every host is one of
    those - so the bracket test is what keeps a boot disk from triggering a re-query on
    every host in the pool, forever.
    """
    if not transient:
        return False
    for line in text.splitlines():
        fields = line.split("|")
        if len(fields) <= MP_PATH_CHK_FIELD:
            continue
        if not fields[0] or fields[0].startswith("["):
            continue
        if fields[MP_PATH_CHK_FIELD].strip() in transient:
            return True
    return False


def collect_multipath(opts):
    """Path-level multipath state: from the daemon, cross-checked against the kernel.

    Four questions, ~9 ms each on the test hosts:

      * `multipathd show daemon` - a POSITIVE liveness answer ('pid N running'). Without
        it, "this host has no multipath" and "nobody answered" are the same empty output,
        and the first one is green. A host with no maps prints exactly nothing (measured
        on 8.2.1 and 8.3.0), so the difference has to be established somewhere else.
      * maps and paths, in `raw format`.
      * `dmsetup ls --target multipath` - what the KERNEL holds, which needs no daemon.
        multipathd reporting no maps while device-mapper has some means the daemon is not
        managing them: no failover, and precisely the silent case this check exists for.

    `multipath -ll` is deliberately NOT used. It re-runs the path checkers itself, so it
    does device I/O and can block on the dead path we are asking about, and it disagrees
    with the daemon that actually routes the I/O: with sdd failed, multipathd said
    'failed faulty running' while `multipath -ll` said 'failed ready running' (both
    measured on 8.3.0, 2026-08-27).
    """
    opts = opts or {}
    out = {}

    r = run(["multipathd", "show", "daemon"], timeout=MP_QUERY_TIMEOUT)
    out["daemon"] = fact(r.out) if r.ok else \
        err("multipathd show daemon failed (%s)" % r.why())

    r = run(["dmsetup", "ls", "--target", "multipath"], timeout=MP_QUERY_TIMEOUT)
    out["dm"] = fact(r.out) if r.ok else err("dmsetup ls failed (%s)" % r.why())

    r = run(["multipathd", "show", "maps", "raw", "format", MP_MAP_FORMAT],
            timeout=MP_QUERY_TIMEOUT)
    out["maps"] = fact(r.out) if r.ok else err("multipathd show maps failed (%s)" % r.why())

    r = run(["multipathd", "show", "paths", "raw", "format", MP_PATH_FORMAT],
            timeout=MP_QUERY_TIMEOUT)
    if not r.ok:
        out["paths"] = err("multipathd show paths failed (%s)" % r.why())
        return fact(out)

    text = r.out
    rechecked = False
    delay = opts.get("recheck_delay") or 0
    left = budget_left()
    if delay and _mp_transient(text, opts.get("transient") or []) \
            and (left is None or left > delay + 10):
        # one re-query, not a loop: the point is to let an in-flight check land, not to
        # wait for a path to come back. Still undef the second time is reported as found.
        time.sleep(delay)
        again = run(["multipathd", "show", "paths", "raw", "format", MP_PATH_FORMAT],
                    timeout=MP_QUERY_TIMEOUT)
        if again.ok:
            text = again.out
            rechecked = True
            r2 = run(["multipathd", "show", "maps", "raw", "format", MP_MAP_FORMAT],
                     timeout=MP_QUERY_TIMEOUT)
            if r2.ok:
                out["maps"] = fact(r2.out)
    out["paths"] = fact(text)
    out["rechecked"] = fact(rechecked)
    return fact(out)


TAP_CTL_TIMEOUT = 20


def collect_tap_status():
    """'tap-ctl list' talks to blktap over its control socket - a wedged tapdisk answers
    nothing and hangs the call, which is exactly the failure this exists to surface as its
    own fact rather than as a blank/missing one.

    The rows come back raw and are counted, not judged. Each is
    'pid=N minor=N state=N args=...', and the state field is NOT a health value: blktap
    exposes 'tap-ctl pause' / 'unpause' as ordinary operations (verified on blktap
    3.55.5, 8.3.0), so SMAPI parks tapdisks in non-zero states during snapshot and
    coalesce. Flagging on it would fire through every backup window. What this fact
    establishes is that blktap answered and how many tapdisks it named - so the check
    says exactly that, and nothing about whether each one is happy.
    """
    r = run(["tap-ctl", "list"], timeout=TAP_CTL_TIMEOUT)
    if r.timed_out:
        return err("tap-ctl list timed out after %ds" % TAP_CTL_TIMEOUT)
    if not r.ok:
        return err("tap-ctl list failed (%s)" % r.why())
    return fact(r.out)


def collect_crash_count(ignore_name):
    """Files under /var/crash, two levels deep - crash dumps live in subdirectories."""
    root = "/var/crash"
    if not os.path.isdir(root):
        return fact(0)
    count = 0
    try:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                if name != ignore_name:
                    count += 1
                continue
            if os.path.isdir(path):
                try:
                    for sub in os.listdir(path):
                        if sub == ignore_name:
                            continue
                        if os.path.isfile(os.path.join(path, sub)):
                            count += 1
                except OSError:
                    return err("could not list %s" % path)
    except OSError as exc:
        return err("could not list /var/crash (%s)" % exc)
    return fact(count)


def collect_coredumps(coredump_dir):
    """systemd names these core.<comm>.<...>.xz, so the filename says which process
    died - which is why the list is worth reporting and not just a count."""
    if not os.path.isdir(coredump_dir):
        return fact([])
    rows = []
    try:
        names = os.listdir(coredump_dir)
    except OSError as exc:
        return err("could not list %s (%s)" % (coredump_dir, exc))
    for name in names:
        path = os.path.join(coredump_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not os.path.isfile(path):
            continue
        rows.append("%s %12d  %s" % (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)), st.st_size, name))
    rows.sort(reverse=True)
    return fact(rows)


TASK_TIMEOUT_CONF_DIR = "/etc/xapi.conf.d"
_TASK_TIMEOUT_RE = re.compile(r"^\s*pending_task_timeout\s*=(.*)$")


def task_timeout_values(text):
    """The pending_task_timeout settings in one drop-in file's text.

    All whitespace is stripped out of the value rather than just trimmed, so a setting
    written as '1 hour' is reported as '1hour' - which is what the bash script this was
    ported from does, and the line is a verbatim echo of the override either way.
    A commented-out setting cannot match: the key has to start the line.
    """
    values = []
    for line in text.replace("\r", "").split("\n"):
        m = _TASK_TIMEOUT_RE.match(line)
        if not m:
            continue
        value = re.sub(r"\s+", "", m.group(1))
        if value:
            values.append(value)
    return values


def collect_task_timeout_override():
    """xapi's default pending_task_timeout lives in /etc/xapi.conf; a drop-in under
    /etc/xapi.conf.d/ can override it for this host.

    No directory and no matching line are both real answers ('no override'), which is why
    they return an empty list rather than an error - but a directory we cannot read is
    NOT, and says so, because 'no override found' would be a claim we did not establish.
    Dot-files are skipped: the shell glob this replaces did not match them either, and
    an editor's leftover .swp is not a live configuration file.
    """
    if not os.path.isdir(TASK_TIMEOUT_CONF_DIR):
        return fact([])
    try:
        names = sorted(os.listdir(TASK_TIMEOUT_CONF_DIR))
    except OSError as exc:
        return err("could not list %s (%s)" % (TASK_TIMEOUT_CONF_DIR, exc))
    values = []
    for name in names:
        if name.startswith("."):
            continue
        path = os.path.join(TASK_TIMEOUT_CONF_DIR, name)
        if not os.path.isfile(path):
            continue
        text = read_file(path)
        if text is None:
            return err("could not read %s" % path)
        values.extend(task_timeout_values(text))
    return fact(values)


def collect_smapi_hidden_leaves():
    """Live SMlog only - reading the rotated copy too was considered and declined."""
    path = "/var/log/SMlog"
    if not os.path.exists(path):
        return fact([])
    r = run(["grep", "-ai", "hidden leaf", path], timeout=60)
    if r.timed_out:
        return err("grep on SMlog timed out")
    if r.rc not in (0, 1):
        return err("grep on SMlog failed (%s)" % r.why())
    seen = {}
    out = []
    for line in r.out.splitlines():
        if line in seen:
            continue
        seen[line] = 1
        out.append(line)
    return fact(out)


def collect_rpm_manifest():
    """sshpass is filtered out on every host, because host mode installs it on the one
    host it sweeps from - otherwise the script reports its own footprint as pool drift."""
    r = run(["rpm", "-qa", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"],
            timeout=90)
    if not r.ok:
        return err("rpm -qa failed (%s)" % r.why())
    lines = [ln for ln in r.out.splitlines() if ln.strip() and not ln.startswith("sshpass ")]
    lines.sort()
    return fact("\n".join(lines))


def collect_yum_check_update():
    """yum check-update: rc 0 = nothing to do, rc 100 = updates listed, anything else
    means yum itself failed (broken repo, no network) - which must never read as zero."""
    r = run(["yum", "check-update", "-q"], timeout=180)
    if r.timed_out:
        return err("yum check-update timed out")
    if r.rc == 0:
        return fact(0)
    if r.rc != 100:
        return err("yum check-update failed (%s)" % r.why())
    return fact(count_yum_updates(r.out))


def count_yum_updates(text):
    """Count the update rows in 'yum check-update -q' output.

    yum wraps a long package name onto its own line with the version indented on the
    next one; those two lines are one update. Obsoleting Packages ends the list.
    """
    count = 0
    pending = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.startswith("Loaded plugins:"):
            continue
        if line.startswith("Obsoleting Packages"):
            break
        fields = line.split()
        if len(fields) == 1 and not line[0].isspace():
            pending = True
            continue
        if pending and line[0].isspace():
            pending = False
            count += 1
            continue
        count += 1
    return count


# --------------------------------------------------------------------------------------
# patch / boot facts - one event, three report lines
# --------------------------------------------------------------------------------------

_YUM_UPDATE_RE = re.compile(r"^(\S+)\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+(Updated|Installed):\s+(\S+)")


def _is_patch_line(action, pkg):
    """One predicate shared by Last Patched and Rebooted After Updates.

    An 'Updated:' of anything is a patch. An 'Installed:' only counts for kernel/xen,
    because yum installs a new kernel beside the old one instead of upgrading it. A
    plain 'Installed:' of anything else is a NEW package - installing sshpass must not
    redate the host.
    """
    if action == "Updated":
        return True
    return action == "Installed" and (pkg.startswith("kernel") or pkg.startswith("xen"))


def find_last_update_line(text):
    """Last line in a yum.log that the patch predicate accepts. (mon, day, tod, pkg)."""
    found = None
    for line in text.splitlines():
        m = _YUM_UPDATE_RE.match(line)
        if not m:
            continue
        if _is_patch_line(m.group(4), m.group(5)):
            found = (m.group(1), int(m.group(2)), m.group(3), m.group(5))
    return found


def _rpm_install_time(pkg_nvra):
    """rpm knows exactly when a package landed, with a year - yum.log does not."""
    name = re.sub(r"^\d+:", "", pkg_nvra)
    r = run(["rpm", "-q", "--qf", "%{INSTALLTIME}\n", name], timeout=30)
    if not r.ok:
        return None
    first = r.out.strip().splitlines()
    if not first or not first[0].strip().isdigit():
        return None
    return int(first[0].strip())


def _year_from_logline(mon, day, tod, log_mtime):
    """Fallback when rpm cannot resolve the package (erased since, odd epoch form).

    The year comes from the LOG FILE's mtime, never from today: a rotated .1 can be
    well over a year old. The last matching line always sits near the file's mtime, so
    this is exact - and if it lands after the mtime, it belongs to the year before.
    """
    year = time.localtime(log_mtime).tm_year
    for candidate in (year, year - 1):
        try:
            parsed = time.strptime("%s %d %d %s" % (mon, day, candidate, tod),
                                   "%b %d %Y %H:%M:%S")
        except ValueError:
            return None
        epoch = int(time.mktime(parsed))
        if epoch <= log_mtime + 1:
            return epoch
    return None


def collect_patch_facts():
    out = {}

    stat_text = read_file("/proc/stat")
    boot = None
    if stat_text is not None:
        m = re.search(r"^btime\s+(\d+)", stat_text, re.M)
        if m:
            boot = int(m.group(1))
    if boot is None:
        out["boot_epoch"] = err("no btime in /proc/stat")
    else:
        out["boot_epoch"] = fact(boot)

    # newest rpm install of any kind - a backstop only, and blind to our own footprint
    r = run(["rpm", "-qa", "--qf", "%{INSTALLTIME} %{NAME}\n"], timeout=90)
    if r.ok:
        newest = 0
        for line in r.out.splitlines():
            parts = line.split()
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            if parts[1] in ("sshpass", "gpg-pubkey"):
                continue
            if int(parts[0]) > newest:
                newest = int(parts[0])
        out["newest_rpm"] = fact(newest or None)
    else:
        out["newest_rpm"] = err("rpm -qa failed (%s)" % r.why())

    # yum.log is read together with its rotated copy: logrotate takes it at size 30k
    # with notifempty, so the live file can sit near-empty for months while the whole
    # update history waits in .1
    upd = None
    source = None
    for path in ("/var/log/yum.log", "/var/log/yum.log.1"):
        text = read_file(path)
        if text is None:
            continue
        hit = find_last_update_line(text)
        if hit is None:
            continue
        mon, day, tod, pkg = hit
        upd = _rpm_install_time(pkg)
        if upd is None:
            try:
                mtime = os.stat(path).st_mtime
            except OSError:
                mtime = time.time()
            upd = _year_from_logline(mon, day, tod, mtime)
            source = "%s (log timestamp)" % path
        else:
            source = "%s (rpm)" % path
        break

    if upd is None:
        out["update_epoch"] = err("no update found in yum.log or yum.log.1")
    else:
        out["update_epoch"] = fact(upd)
    out["update_source"] = fact(source)

    # rendered here, on the host, so both dates are in the host's own local time -
    # which is the whole reason the old rendered-timestamp parsing existed
    for src, dst in (("update_epoch", "update_disp"), ("boot_epoch", "boot_disp")):
        f = out[src]
        if f["ok"] and f["value"]:
            out[dst] = fact(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f["value"])))
        else:
            out[dst] = err("no timestamp")
    return out


# --------------------------------------------------------------------------------------
# log scanning
# --------------------------------------------------------------------------------------

def grep_scan(path, phrases, timeout=180):
    """Line numbers of the LAST hit of each phrase in one file.

    One grep pass for all phrases together (these files run to 30 MB+), then attribution
    over just the matched lines. Streamed, so a phrase that matches constantly cannot
    blow memory. Returns {phrase_index: lineno} or None if the file could not be read.
    """
    if not phrases:
        return {}
    try:
        if not os.path.exists(path) or not os.access(path, os.R_OK):
            return None
    except OSError:
        return None

    timeout = _clamp(timeout)
    if timeout is None:
        return None

    # -a is load-bearing, not defensive. A single NUL or non-UTF-8 byte anywhere in the
    # file makes grep call it binary: 2.20 (dom0) then prints "Binary file X matches"
    # instead of the line numbers, and 3.8 (XOA) prints nothing at all with rc 0 - a match
    # found and silently not reported, which reads as a clean log. Measured on both.
    argv = ["grep", "-ainF"]
    for p in phrases:
        argv += ["-e", p]
    argv += ["--", path]

    started = time.time()
    try:
        proc, devnull = _popen(argv)
    except OSError:
        return None

    state = {"killed": False}

    def on_timeout():
        state["killed"] = True
        _kill(proc)

    timer = threading.Timer(timeout, on_timeout)
    timer.start()
    CURRENT[0] = _argv_text(argv)
    lowered = [p.lower() for p in phrases]
    last = {}
    try:
        for raw in proc.stdout:
            line = _decode(raw)
            sep = line.find(":")
            if sep < 0:
                continue
            num = line[:sep]
            if not num.isdigit():
                continue
            body = line[sep + 1:].lower()
            for i, needle in enumerate(lowered):
                if needle and needle in body:
                    last[i] = int(num)
        proc.stdout.close()
        rc = proc.wait()
    finally:
        timer.cancel()
        devnull.close()
        # the attribution loop above runs once per MATCHED line, so this is grep's time
        # plus ours - which is the number that matters on a log full of hits
        timed(argv, started)
        CURRENT[0] = ""
    # rc 1 is grep's "no match", which is a real answer; 2+ means grep itself failed
    if state["killed"] or rc > 1:
        return None
    return last


def context_lines(path, lineno, ctx):
    """+/- ctx lines around lineno.

    sed with a trailing 'q' so it stops at the end of the range: without it sed reads
    on to EOF, and these files run to tens of MB with the interesting hits near the end.
    """
    start = max(1, lineno - ctx)
    end = lineno + ctx
    r = run(["sed", "-n", "%d,%dp;%dq" % (start, end, end), path], timeout=60)
    if not r.ok:
        return None
    return r.out.splitlines()


def collect_log_scan(files, phrases, ctx):
    """For every (file, phrase) pair, the most recent hit with context.

    Each base log is tried first and its rotated .1 only for phrases the live file
    lacks: these rotate daily around 04:00, so right after a rotation the live file is
    nearly empty - but reporting a stale .1 hit beside a current one would be worse.
    One block per phrase, so a phrase that matches constantly ('except') can never
    crowd out a rare, serious one.
    """
    if not files or not phrases:
        return fact([])
    blocks = []
    for base in files:
        live = grep_scan(base, phrases)
        rotated = None
        rotated_scanned = False
        for i, phrase in enumerate(phrases):
            path = base
            hit = live.get(i) if live is not None else None
            if hit is None:
                if not rotated_scanned:
                    rotated_scanned = True
                    rotated = grep_scan(base + ".1", phrases)
                path = base + ".1"
                hit = rotated.get(i) if rotated is not None else None
            if hit is None:
                continue
            lines = context_lines(path, hit, ctx)
            if lines is None:
                continue
            blocks.append({"phrase": phrase, "file": path, "line": hit, "context": lines})
    return fact(blocks)


# --------------------------------------------------------------------------------------
# pool-level facts (asked of one host; xapi answers pool-wide from any member)
# --------------------------------------------------------------------------------------

def _pif_ips(network_uuid):
    """--minimal with a SINGLE param across many objects is the form that works: it
    prints one comma-separated line with an empty field per PIF that has no IP."""
    r = xe(["pif-list", "network-uuid=" + network_uuid, "params=IP", "--minimal"])
    if not r.ok:
        return err("xe pif-list params=IP failed (%s)" % r.why())
    ips = []
    for piece in r.out.strip().split(","):
        piece = piece.strip()
        if not piece or piece == "0.0.0.0":
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", piece):
            ips.append(piece)
    return fact(ips)


def _network_info(network_uuid, want_ips):
    """bond-slave-of for every PIF on a network, plus (for backup) their IPs.

    A network uuid that no longer exists is answered rc 0 with NO output at all, which
    is neither 'is a bond member' nor 'is not' - it gets its own state so a stale
    other-config entry cannot read as a healthy 'Configured'.
    """
    info = {"uuid": network_uuid}
    r = xe(["pif-list", "network-uuid=" + network_uuid, "params=bond-slave-of"])
    if not r.ok:
        info["bond"] = err("xe pif-list bond-slave-of failed (%s)" % r.why())
    else:
        info["bond"] = fact(r.out)
    if want_ips:
        info["ips"] = _pif_ips(network_uuid)
    return info


LINSTOR_TIMEOUT = 120
LINSTOR_PROP_TIMEOUT = 30       # one node's properties, not a whole-cluster listing

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text):
    """Defensive, exactly as colors.strip_ansi is on the XOA side: some tools colourise
    even when their output is a pipe. The collector cannot import colors - it ships alone -
    so it carries its own."""
    return ANSI_RE.sub("", text)


def _linstor(controllers, args, timeout=LINSTOR_TIMEOUT):
    if which("linstor") is None:
        return err("linstor CLI not found")
    argv = ["linstor", "--controllers=" + ",".join(controllers)] + list(args)
    r = run(argv, timeout=timeout)
    if not r.ok:
        return err("linstor %s failed (%s)" % (" ".join(args), r.why()))
    return fact(r.out)


def linstor_table_column(text, header):
    """Values under `header` in one of linstor's ASCII tables, in row order.

    The header row is located by its own cell rather than assumed to be row one, since a
    faulty-nodes or resource table uses the same box-drawing style with different columns.
    ANSI is stripped from every cell: checks._linstor_node_offline, which reads the State
    column of this same 'n l' table on the XOA side, has always done so - a coloured Node
    cell here would be a name no subsequent 'n lp <node>' call could match, and every node
    would then read as unqueryable.

    That XOA-side twin cannot be shared with this one: it runs where the report is built
    and this runs on the hypervisor, so the two are deliberate duplicates. Keep the header
    location and the cell-splitting rule identical in both.
    """
    col = None
    values = []
    for raw in text.splitlines():
        line = strip_ansi(raw)
        if not line.startswith("|"):
            continue
        # Any rule row, however it is drawn. Testing for the '|===|' spelling alone let a
        # '|---|' separator through as a data row, and its dashes were then returned as a
        # node name - a name no 'n lp' call can match, which reads downstream as a node
        # that would not answer. Cheap to be exhaustive about instead.
        if not set(line) - set("|-=+ "):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if col is None:
            if header in cells:
                col = cells.index(header)
            continue
        if col < len(cells) and cells[col]:
            values.append(cells[col])
    return values


def _linstor_node_names(text):
    return linstor_table_column(text, "Node")


def _linstor_pref_nics(controllers, node_names):
    """PrefNic for every node, one 'linstor -m n lp <node>' call each - list-properties has
    no all-nodes form, unlike 'n l'.

    Returns {node_name: nic_or_None} holding ONLY the nodes that answered. Which nodes
    were asked is carried separately by the caller, because the difference between the two
    is the whole finding: a node whose properties could not be read is not a node with no
    PrefNic, and reporting agreement across the survivors of a partial read would be a
    green line claiming more than was established. The check compares the two sets.

    -m (machine-readable JSON) is used here rather than the plain-text property table:
    that table's border style depends on whether linstor thinks it has a terminal - piped
    through subprocess as this always is, it prints the same ASCII '+'/'|' borders as the
    'n l' node table, not the Unicode box the interactive CLI shows. Parsing JSON sidesteps
    having to track which glyph set a given linstor version/mode falls back to.

    Serial, one call per node: a cluster is a handful of nodes, and the per-call timeout is
    LINSTOR_PROP_TIMEOUT rather than the full LINSTOR_TIMEOUT so that a degraded controller
    cannot spend the whole-run budget here. If it does run out anyway, run() answers
    'run budget exhausted' and those nodes land in the unread set - visible, not silent.
    """
    out = {}
    for name in node_names:
        r = _linstor(controllers, ["-m", "n", "lp", name], timeout=LINSTOR_PROP_TIMEOUT)
        if not r["ok"]:
            continue
        nic = parse_linstor_pref_nic(r["value"])
        if nic is not False:
            out[name] = nic
    return out


def parse_linstor_pref_nic(text):
    """PrefNic out of 'linstor -m node list-properties' JSON.

    The real shape (verified against 8.3.0, 2026-08-30) is a list wrapping ONE list of
    {"key", "value"} property objects - [[{...}, {...}]] - not a bare property list.
    None means the node has no PrefNic property set (linstor omits it rather than
    printing an empty value); False means the JSON itself could not be parsed, which the
    caller treats as 'skip this node' rather than 'not set' - different facts that must
    not collapse into the same flag.
    """
    try:
        outer = json.loads(text)
    except ValueError:
        return False
    if not isinstance(outer, list) or not outer or not isinstance(outer[0], list):
        return False
    for entry in outer[0]:
        if isinstance(entry, dict) and entry.get("key") == "PrefNic":
            return entry.get("value")
    return None


def _qcow2_vdis(sr_uuids, cap):
    """qcow2-format VDIs on XOSTOR SRs.

    Every SR is asked separately: 'sr-list --minimal' answers with a comma-separated
    list when a pool has several linstor SRs, and sr-uuid= will not take that - it
    matches nothing and still answers rc 0, so the pools most likely to have qcow2 VDIs
    were exactly the ones that read as a clean 'None'.
    Records are split at their uuid line, not at blank lines.
    """
    rows = []
    for sr in sr_uuids:
        r = xe(["vdi-list", "sr-uuid=" + sr, "params=uuid,name-label,sm-config"])
        if not r.ok:
            return err("xe vdi-list failed (%s)" % r.why())
        uuid = name = smc = ""
        for line in r.out.splitlines():
            stripped = line.strip()
            if stripped.startswith("uuid ("):
                if uuid and "qcow2" in smc:
                    rows.append("%s  %s" % (uuid, name))
                uuid = line.split(":", 1)[1].strip() if ":" in line else ""
                name = ""
                smc = ""
            elif stripped.startswith("name-label ("):
                name = line.split(":", 1)[1].strip() if ":" in line else ""
            elif stripped.startswith("sm-config ("):
                smc = line
        if uuid and "qcow2" in smc:
            rows.append("%s  %s" % (uuid, name))
    return fact(rows[:cap] if cap and len(rows) > cap else rows), len(rows)


def collect_pool(spec, self_uuid):
    out = {}

    r = xe(["pool-list", "params=uuid", "--minimal"])
    pool_uuid = ""
    if r.ok:
        m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", r.out)
        pool_uuid = m.group(0) if m else ""
    if not pool_uuid:
        out["pool_uuid"] = err("could not read the pool uuid from xapi")
    else:
        out["pool_uuid"] = fact(pool_uuid)

    # Everything below needs the uuid. Asking xapi with an empty 'uuid=' makes it log a
    # Db_exn.Read_missing_uuid plus backtrace into xensource.log - which this tool then
    # greps and reports as a problem it caused itself. So they are simply not issued.
    if not pool_uuid:
        for key in ("ha_enabled", "migration_compression", "other_config"):
            out[key] = err("pool uuid not available")
    else:
        r = xe(["pool-param-get", "uuid=" + pool_uuid, "param-name=ha-enabled"])
        out["ha_enabled"] = fact(r.out.strip()) if r.ok else \
            err("xe pool-param-get ha-enabled failed (%s)" % r.why())

        # the list form, never 'pool-param-get param-name=migration-compression': the
        # param does not exist before 8.3 and param-get on a missing param logs a
        # CLI_failed_to_find_param exception every run. The list form answers empty,
        # quietly, which cleanly means "the feature is not there".
        r = xe(["pool-list", "uuid=" + pool_uuid, "params=migration-compression", "--minimal"])
        out["migration_compression"] = fact(r.out.strip()) if r.ok else \
            err("xe pool-list migration-compression failed (%s)" % r.why())

        # the whole other-config map, never 'param-key=': a missing key makes xapi log
        # a Cli_failure exception, same self-inflicted spam
        r = xe(["pool-param-get", "uuid=" + pool_uuid, "param-name=other-config"])
        out["other_config"] = fact(r.out) if r.ok else \
            err("xe pool-param-get other-config failed (%s)" % r.why())

    r = xe(["sr-list", "type=linstor", "--minimal"])
    if not r.ok:
        out["xostor_srs"] = err("xe sr-list type=linstor failed (%s)" % r.why())
        sr_uuids = []
    else:
        sr_uuids = [s.strip() for s in r.out.strip().split(",") if s.strip()]
        out["xostor_srs"] = fact(sr_uuids)

    if self_uuid:
        r = xe(["pif-list", "VLAN=0", "host-uuid=" + self_uuid, "--minimal"])
        out["vlan0"] = fact(r.out.strip()) if r.ok else \
            err("xe pif-list VLAN=0 failed (%s)" % r.why())
    else:
        out["vlan0"] = err("host uuid unknown")

    # networks named in other-config; resolved here so the whole chain is one round trip
    nets = spec.get("networks") or {}
    oc = out.get("other_config")
    if oc and oc["ok"]:
        parsed = parse_other_config(oc["value"])
        for key in ("xo:migrationNetwork", "xo:backupNetwork"):
            if parsed.get(key):
                nets[key] = parsed[key]
    resolved = {}
    for key, want_ips in (("xo:migrationNetwork", False), ("xo:backupNetwork", True)):
        uuid = nets.get(key)
        if uuid:
            resolved[key] = _network_info(uuid, want_ips)
    out["networks"] = resolved

    if sr_uuids:
        controllers = spec.get("controllers") or []
        nodes_r = _linstor(controllers, ["n", "l"])
        out["linstor_nodes"] = nodes_r
        out["linstor_faulty"] = _linstor(controllers, ["r", "l", "--faulty"])
        out["linstor_controller"] = _linstor(controllers, ["c", "which"])
        if not nodes_r["ok"]:
            out["linstor_pref_nics"] = err("could not list linstor nodes")
        else:
            names = _linstor_node_names(nodes_r["value"])
            if not names:
                # 'n l' answered, but nothing recognisable as a Node column came out of it
                # - a linstor that changed its table format, not a cluster with no nodes.
                # Saying "no nodes found" here would be a reading, and this is a failure.
                out["linstor_pref_nics"] = err(
                    "no node names in 'linstor n l' output")
            else:
                out["linstor_pref_nics"] = fact(
                    {"nodes": names, "nics": _linstor_pref_nics(controllers, names)})
        rows, total = _qcow2_vdis(sr_uuids, spec.get("qcow2_max") or 0)
        out["qcow2"] = rows
        out["qcow2_total"] = fact(total)
    return out


def parse_other_config(text):
    """The map prints as 'key: value; key: value'. Values looked up here are network
    UUIDs, so splitting records on ';' cannot cut one in half."""
    result = {}
    for entry in text.split(";"):
        entry = entry.strip()
        idx = entry.find(": ")
        if idx <= 0:
            continue
        result[entry[:idx].strip()] = entry[idx + 2:].strip()
    return result


# --------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------

def collect(spec):
    want = set(spec.get("want") or [])
    # built in place, so the watchdog can hand back what was established if this call
    # never returns
    out = PARTIAL
    out["collector"] = {"python": sys.version.split()[0], "pid": os.getpid()}
    ident = collect_identity()
    out.update(ident)

    self_uuid = ident["self_uuid"]["value"] if ident["self_uuid"]["ok"] else ""

    if "pool_hosts" in want:
        out["pool_hosts"] = collect_pool_hosts()

    if "host" in want:
        out["meminfo"] = collect_meminfo()
        out["timedatectl"] = collect_timedatectl()
        out["df"] = collect_df()
        out["dmesg"] = collect_dmesg()
        out["iplink"] = collect_iplink()
        out["ipaddr"] = collect_ipaddr()
        out["lacp"] = collect_lacp()
        out["multipath"] = collect_multipath(spec.get("multipath"))
        out["tap_status"] = collect_tap_status()
        out["crash_count"] = collect_crash_count(spec.get("crash_ignore_file") or "")
        out["coredumps"] = collect_coredumps(spec.get("coredump_dir") or "")
        out["task_timeout"] = collect_task_timeout_override()
        out["rpm_manifest"] = collect_rpm_manifest()
        out.update(collect_patch_facts())

        if self_uuid:
            r = xe(["pif-list", "params=gateway,DNS", "management=false",
                    "host-uuid=" + self_uuid])
            out["pifs_dns_gw"] = fact(r.out) if r.ok else \
                err("xe pif-list gateway,DNS failed (%s)" % r.why())
        else:
            out["pifs_dns_gw"] = err("host uuid unknown")

        scan = spec.get("log_scan") or {}
        out["log_scan"] = collect_log_scan(scan.get("files") or [],
                                           scan.get("phrases") or [],
                                           scan.get("context") or 3)
        lun = spec.get("lun_scan") or {}
        out["lun_scan"] = collect_log_scan(lun.get("files") or [],
                                           lun.get("phrases") or [],
                                           lun.get("context") or 3)
        mps = spec.get("multipath_scan") or {}
        out["multipath_scan"] = collect_log_scan(mps.get("files") or [],
                                                 mps.get("phrases") or [],
                                                 mps.get("context") or 3)
        mstall = spec.get("mount_stall_scan") or {}
        out["mount_stall_scan"] = collect_log_scan(mstall.get("files") or [],
                                                   mstall.get("phrases") or [],
                                                   mstall.get("context") or 3)

        # The order matters and is the only thing left of the old gate: the process scan
        # runs FIRST, so a probe this run parks on a dead mount is not then reported by
        # this same run as a process that was already stuck. It shows up on the next run,
        # marked, and counted as what it is.
        out["stuck_procs"] = collect_stuck_processes(spec.get("stuck"))
        out["network_mounts"] = collect_network_mounts(spec.get("mount_probe"))
        if spec.get("smapi"):
            out["smapi"] = collect_smapi_hidden_leaves()

    if "yumcheck" in want:
        out["yum_check"] = collect_yum_check_update()

    if "pool" in want:
        out["pool"] = collect_pool(spec, self_uuid)

    if spec.get("timings"):
        # slowest first: the question this answers is always "what took the time", and a
        # host runs enough commands that the whole list would bury the answer
        out["collector"]["timings"] = sorted(TIMINGS, reverse=True)[:15]
    return out


_EMITTED = [False]
_EMIT_LOCK = threading.Lock()


def emit(payload):
    """Write the document, once and whole. Answers whether this call was the one.

    The watchdog and the normal path race only in the instant the last command returns,
    but two documents on one stdout is not a document: _extract takes the first BEGIN and
    the last END, so a second one would be read as a truncated first.
    """
    with _EMIT_LOCK:
        if _EMITTED[0]:
            return False
        _EMITTED[0] = True
    sys.stdout.write(BEGIN_MARKER + "\n")
    sys.stdout.write(json.dumps(payload))
    sys.stdout.write("\n" + END_MARKER + "\n")
    sys.stdout.flush()
    return True


def watchdog(grace):
    """Answer anyway when a command cannot be killed.

    The whole-run budget works by SIGKILLing whatever is running when it expires. A
    process in uninterruptible sleep - D state, anything blocked on wedged storage - does
    NOT die on SIGKILL: the signal stays pending until it leaves D, which may be never.
    communicate() then never returns, collect() never finishes, and the collector writes
    nothing at all. The transport loses the whole host to its own timeout, and the report
    can only say "timed out after 300s", which names neither the host's problem nor the
    command that hit it.

    Measured on a pool with 18 XOSTOR volumes stuck in DELETING: three hosts, two
    answering in under 3s, the third producing no document at all across five runs and
    nothing whatsoever to say why.

    So this thread outlives the main one: at the deadline plus a grace period it emits
    what was gathered, names the command still running, and leaves. os._exit rather than
    sys.exit or a return, because the main thread is wedged in communicate() and any
    orderly shutdown would wait for it - which is the whole problem.
    """
    while True:
        left = budget_left()
        if left is None:
            return                      # no budget set: nothing to enforce
        if left <= -grace:
            break
        time.sleep(min(5.0, max(0.5, left + grace)))

    payload = dict(PARTIAL)
    payload["__collector_stuck__"] = CURRENT[0] or "(no command was running)"
    payload["collector"] = dict(payload.get("collector") or {})
    payload["collector"]["timings"] = sorted(TIMINGS, reverse=True)[:15]
    payload["collector"]["abandoned"] = list(ABANDONED)
    emit(payload)
    os._exit(0)


def main(argv):
    spec = {}
    if len(argv) > 1 and argv[1]:
        spec = json.loads(base64.b64decode(argv[1].encode("ascii")).decode("utf-8"))
    DEADLINE[0] = time.time() + float(spec.get("budget") or 240)

    guard = threading.Thread(target=watchdog, args=(WATCHDOG_GRACE,))
    guard.daemon = True
    guard.start()

    try:
        payload = collect(spec)
    except Exception:
        import traceback
        payload = {"__collector_error__": traceback.format_exc()}
    emit(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
