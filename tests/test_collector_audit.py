# -*- coding: utf-8 -*-
"""Collector fixes from the 2026-11-24 audit (findings A01-A24, B01-B17).

Pure enough to run off-host: every command and file the collector would touch is faked.
"""

import os
import threading

import pytest

import collector


def test_hidden_leaves_are_one_line_per_leaf_with_a_count():
    """Every SMlog line carries its own timestamp and [pid][thread], so de-duplicating
    whole lines never collapsed a leaf SM logs on every scan."""
    text = ("Nov 24 10:00:01 h SM: [111] Scan found hidden leaf (aaaa-1), ignoring\n"
            "Nov 24 10:05:01 h SM: [222] Scan found hidden leaf (bbbb-2), ignoring\n"
            "Nov 24 10:10:01 h SM: [333] Scan found hidden leaf (aaaa-1), ignoring\n")
    lines = collector.dedupe_hidden_leaves(text)
    assert len(lines) == 2
    assert lines[0].startswith("Nov 24 10:10:01") and "(logged 2 times)" in lines[0]
    assert "bbbb-2" in lines[1] and "logged" not in lines[1]


def test_an_empty_hostname_is_an_error_not_a_host_called_nothing(monkeypatch):
    monkeypatch.setattr(collector, "run", lambda argv, timeout=None:
                        collector.Ran(0, "\n", "", False))
    monkeypatch.setattr(collector, "read_file", lambda path, limit=None: None)
    ident = collector.collect_identity()
    assert ident["hostname"]["ok"] is False


# --------------------------------------------------------------------------------------
# Dom0 Disk Usage without df (A04)
# --------------------------------------------------------------------------------------

class _Statvfs(object):
    def __init__(self, blocks, bfree, bavail, frsize=4096):
        self.f_blocks, self.f_bfree, self.f_bavail = blocks, bfree, bavail
        self.f_frsize = self.f_bsize = frsize


class _Stat(object):
    def __init__(self, dev):
        self.st_dev = dev


MOUNTS = ("/dev/sda1 / ext3 rw 0 0\n"
          "proc /proc proc rw 0 0\n"
          "tmpfs /dev/shm tmpfs rw 0 0\n"
          "/dev/sda5 /var/log ext3 rw 0 0\n"
          "/dev/sda5 /srv/log-bind ext3 rw 0 0\n"
          "192.0.2.5:/export /run/sr-mount/abcd nfs rw 0 0\n"
          "192.0.2.6:/share /mnt/cifs-share cifs rw 0 0\n"
          "/dev/sdb1 /var/tmp/lost ext4 rw 0 0\n")


def _fs():
    return {"/": (_Statvfs(1000, 500, 450), 1),
            "/dev/shm": (_Statvfs(100, 100, 100), 2),
            "/var/log": (_Statvfs(1000, 100, 50), 3),
            "/srv/log-bind": (_Statvfs(1000, 100, 50), 3),
            "/var/tmp/lost": OSError(5, "Input/output error")}


def _df(monkeypatch, mounts=MOUNTS, fs=None, network_types=("nfs", "nfs4", "cifs")):
    """collect_df over a /proc/mounts text and a table of path -> (statvfs, dev), or an
    OSError for a path that cannot be read. Returns (fact, every path stat'ed)."""
    fs = fs if fs is not None else _fs()
    monkeypatch.setattr(collector, "read_file",
                        lambda path, limit=None: mounts if path == "/proc/mounts" else None)
    asked = []

    def statvfs(path):
        asked.append(path)
        entry = fs[path]
        if isinstance(entry, OSError):
            raise entry
        return entry[0]

    def stat(path):
        asked.append(path)
        return _Stat(fs[path][1])

    monkeypatch.setattr(os, "statvfs", statvfs, raising=False)
    monkeypatch.setattr(os, "stat", stat)
    return collector.collect_df(list(network_types)), asked


def _rows(f):
    return dict((line.split()[-1], line.split())
                for line in f["value"]["text"].splitlines()[1:])


def test_df_never_touches_a_network_mount(monkeypatch):
    """A dead server parks df in D state for good: the network types, the SR mounts and
    the pseudo filesystems are not stat'ed at all."""
    f, asked = _df(monkeypatch)
    assert f["ok"]
    assert not any("sr-mount" in p or "cifs" in p or p == "/proc" for p in asked)


def test_df_uses_dfs_own_arithmetic_and_rounds_up(monkeypatch):
    f, _asked = _df(monkeypatch)
    rows = _rows(f)
    assert rows["/"][4] == "53%"            # used 500 / (500 + avail 450) = 52.6 -> 53
    assert rows["/"][1] == "4000"           # 1000 blocks of 4 KiB, in 1K-blocks
    assert rows["/var/log"][4] == "95%"     # 900 / 950 = 94.7 -> 95


def test_df_lists_a_bind_mount_once_under_its_shorter_path(monkeypatch):
    f, _asked = _df(monkeypatch)
    targets = list(_rows(f))
    assert targets.count("/var/log") == 1 and "/srv/log-bind" not in targets


def test_df_names_a_local_mount_it_could_not_read(monkeypatch):
    """Left out, it would read as a filesystem with room on it."""
    f, _asked = _df(monkeypatch)
    assert f["value"]["failed"] == ["/var/tmp/lost (Input/output error)"]


def test_df_without_proc_mounts_is_an_error(monkeypatch):
    monkeypatch.setattr(collector, "read_file", lambda path, limit=None: None)
    assert collector.collect_df([])["ok"] is False


# --------------------------------------------------------------------------------------
# pool-side facts
# --------------------------------------------------------------------------------------

def test_pif_ips_counts_the_pifs_with_no_address(monkeypatch):
    """XO sends a host's exports to its backup-network PIF IP verbatim; a host whose PIF
    has none must not vanish and leave the others to answer the ping."""
    monkeypatch.setattr(collector, "xe", lambda args, timeout=None, canary=True:
                        collector.Ran(0, "192.0.2.1,,0.0.0.0,192.0.2.4\n", "", False))
    ips, missing = collector._pif_ips("net-uuid")
    assert ips == {"ok": True, "value": ["192.0.2.1", "192.0.2.4"]} and missing == 2


def test_pif_ips_failure_is_an_error(monkeypatch):
    monkeypatch.setattr(collector, "xe", lambda args, timeout=None, canary=True:
                        collector.Ran(1, "", "boom", False))
    ips, missing = collector._pif_ips("net-uuid")
    assert ips["ok"] is False and missing == 0


def test_a_failed_qcow2_listing_keeps_its_reason(monkeypatch):
    """A lone err() unpacked into the caller's two names lost the reason entirely."""
    monkeypatch.setattr(collector, "xe", lambda args, timeout=None, canary=True:
                        collector.Ran(1, "", "xapi says no", False))
    rows, total = collector._qcow2_vdis(["sr-1"], 0)
    assert rows["ok"] is False and "xapi says no" in rows["error"] and total is None


# --------------------------------------------------------------------------------------
# one bad collector costs one fact
# --------------------------------------------------------------------------------------

def test_guarded_turns_an_exception_into_that_facts_error():
    def boom():
        raise KeyError("version")
    f = collector.guarded(boom)
    assert f["ok"] is False and "KeyError" in f["error"]


def test_guarded_many_gives_every_key_the_error():
    def boom():
        raise ValueError("bad")
    out = collector.guarded_many(("a", "b"), boom)
    assert set(out) == {"a", "b"} and all(not v["ok"] for v in out.values())


def test_pvs_is_asked_only_with_evidence_of_xostor(monkeypatch, tmp_path):
    """pvs opens every block device LVM admits; one with all paths down and I/O queueing
    parks it in D state. Without the drbd module, the VG or its LVM backup it is not run."""
    monkeypatch.setattr(collector, "LVM_BACKUP_DIR", str(tmp_path))
    real_exists = os.path.exists
    monkeypatch.setattr(os.path, "isdir", lambda p: False)
    monkeypatch.setattr(os.path, "exists", lambda p: False if p.startswith("/dev/")
                        else real_exists(p))
    assert collector._xostor_here("linstor_group") is False
    (tmp_path / "linstor_group").write_text("x")
    assert collector._xostor_here("linstor_group") is True
    assert collector._xostor_here("../etc") is False       # never a path out of a name
    monkeypatch.setattr(os.path, "isdir", lambda p: p == "/sys/module/drbd")
    assert collector._xostor_here("") is True


# --------------------------------------------------------------------------------------
# Stuck Processes: what is ours, and reads that cannot hang
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("cmd, ours", [
    ("df -hP", True),                             # left behind by builds before v3.28
    ("yum --setopt=exit_on_lock=1 check-update -q", True),
    ("yum check-update -q", True),
    ("dmesg -T", True),
    ("sed -n 10,20p;20q /var/log/SMlog", True),
    ("sed -n 1p /etc/passwd", False),
    ("rpm -qa", False),
    ("df -h", False),
    ("", False),
])
def test_own_commands_are_recognised_by_their_exact_argv(cmd, ours):
    assert collector._own_command(cmd) is ours


def test_read_bounded_gives_up_on_a_read_that_never_returns(monkeypatch):
    release = threading.Event()

    def stuck(path, limit=None):
        release.wait(5)
        return "late"
    monkeypatch.setattr(collector, "read_file", stuck)
    try:
        assert collector.read_bounded("/proc/1/io", timeout=0.1) == (None, False)
    finally:
        release.set()


def test_read_bounded_returns_what_answered(monkeypatch):
    monkeypatch.setattr(collector, "read_file", lambda path, limit=None: "rchar: 1\n")
    assert collector.read_bounded("/proc/1/io") == ("rchar: 1\n", True)


def test_kill_live_children_signals_every_registered_child(monkeypatch):
    killed = []
    monkeypatch.setattr(collector, "_kill", lambda proc: killed.append(proc.pid) or True)

    class P(object):
        def __init__(self, pid):
            self.pid = pid
    monkeypatch.setattr(collector, "LIVE", {11: P(11), 12: P(12)})
    collector.kill_live_children()
    assert sorted(killed) == [11, 12]
