#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# J-Sands / D-Pollak - Vates
#
# XCP-ng / XOA pool health check.
#
#   on XOA:            python3 health.py [-f] [-s] [-n name] [host[:port] [password]]
#   on an XCP-ng host: python3 health.py [-f] [-s] [root_password]
#
# GENERATED FILE - built from src/ by build/stitch.py. Edit the sources, not this.
#
# Runs in two environments, decided by /etc/os-release:
#   XOA  - reaches every host of a pool over ssh (sshpass + xo-server-db)
#   host - runs directly on an XCP-ng/XenServer dom0; this host's commands run locally,
#          the other pool members are reached over ssh when a root password is available
#
# Whatever the environment, every host is asked exactly once: the collector below is
# shipped to it on stdin and answers with one JSON document. It has to parse under
# Python 2.7 as well as 3.6, because 8.2.1 dom0 has no python3 - that constraint applies
# to the collector alone, not to this file, which needs 3.6+.




from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait
from urllib.parse import urlsplit
import atexit
import base64
import calendar
import fnmatch
import getopt
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types
import unicodedata



# ======================================================================================
# --- config ----------------------------------------------------------------------------

SCRIPT_VERSION = "3.28"

SSH_TIMEOUT = 45                 # ssh connect timeout, seconds
REMOTE_CMD_TIMEOUT = 300         # max seconds one collector run may take on a host
MAX_PARALLEL_HOSTS = 8           # hosts collected at once (HEALTH_MAX_PARALLEL overrides)
PROGRESS_INTERVAL = 15           # seconds between 'still waiting on ...' lines, tty only
LOCAL_CMD_TIMEOUT = 10           # max seconds a local command may run (hung xoa-updater etc)
XO_REDIS_TIMEOUT = 2             # reading xo's server records straight from redis: 0.002s
                                 # measured, so this is only here to bound a wedged socket
XO_DNS_TIMEOUT = 5               # resolving xo-db host names to match an address against a
                                 # pool stored by name: all at once, this long for the lot
XOA_CHECK_TIMEOUT = 60           # 'xoa check' does real network probes, so it gets longer
RUN_CMD_TIMEOUT = 120            # -c: max seconds one arbitrary command may take on a host.
                                 # Separate from REMOTE_CMD_TIMEOUT because the two answer
                                 # different questions - that one bounds a whole collector
                                 # run (~20 operations), this one bounds a single command -
                                 # and sharing it would mean retuning a health sweep to
                                 # give -c longer, or the reverse. The bash script did
                                 # share it, having no other primitive to reuse.

DOM0_MAX_USED = 75               # dom0 disk use % allowed before flagging
DOM0_MEM_USED_MAX_PCT = 65       # dom0 memory use % allowed before flagging
XOSTOR_MIN_RAM_GB = 15           # minimum dom0 RAM (GB) when XOSTOR is in use
TIME_SYNC_ALLOWANCE_SECS = 300   # max clock difference between a host and this machine
RAM_MATCH_TOLERANCE_MB = 256     # dom0 MemTotal this close counts as the same allocation

# Read-Only Filesystems judges the root filesystem, what fstab mounts without asking for ro,
# and two kinds of mount that are only ever made writable: what SM mounts from a block device
# for a local SR, and the LINSTOR controller's database. Everything else is left alone, since a
# dom0 has read-only mounts on purpose (systemd's cgroup tmpfs, an ISO on a loop). It catches
# what the kernel remounts read-only (ext3/ext4 with errors=remount-ro, vfat); an XFS that hits
# an I/O error shuts down instead and stays rw in /proc/mounts, so that is not seen here.
RO_FS_SR_DIRS = ["/run/sr-mount/", "/var/run/sr-mount/"]
RO_FS_EXTRA = ["/var/lib/linstor"]
RO_FS_NATIVE_RO = ["iso9660", "udf", "squashfs", "cramfs", "erofs"]  # read-only by nature

# Long-Running Tasks: a xapi task not finished after this many hours. xapi destroys a task
# older than pending_task_timeout (86400 s by default) only when its progress has not moved
# since its previous GC pass (xen-api v26.1.19 db_gc_util.ml timeout_tasks) - a hung task
# goes at about 24 h, one that keeps creeping can live on and is seen here at any age. A
# pending_task_timeout override under this threshold destroys a hung task before it can be.
TASK_PENDING_MAX_HOURS = 16

# Leaf-Coalesce Disabled: a VDI with other-config:leaf-coalesce=false is not leaf-coalesced
# by SM's GC ("Leaf-coalesce disabled for <vdi>"). SM itself writes it (VDI.py
# disable_leaf_on_secondary) when a storage migration starts mirroring the disk, and again
# when the mirror is stopped; a migration that completes takes the source disk away with
# it, one that fails or is cancelled leaves the flag behind - until the disk's next
# snapshot, whose path removes the key before deciding whether to set it again (SM
# 1680f106 VDI.py:895-904), or until someone removes it. Nothing in xapi or XO sets it
# (xen-api and xen-orchestra master, 2026-11). A disk whose VM or VDI is in one of these
# operations right now is in the middle of that, and is not counted.
LEAF_COALESCE_BUSY_VM_OPS = ["migrate_send", "pool_migrate", "export", "import"]
LEAF_COALESCE_BUSY_VDI_OPS = ["mirror", "copy"]
LEAF_COALESCE_MAX_LINES = 40

# Windows VMs Not Optimized: the platform keys every 8.3 Windows template sets (read off the
# 8.3 templates on the lab, 2026-11-24) and "Other install media" sets none of. xapi passes
# them through to xenguest as they are; a VM made from an older Windows template carries
# viridian alone.
WINDOWS_PLATFORM_KEYS = ["viridian", "viridian_time_ref_count", "viridian_reference_tsc",
                         "viridian_apic_assist", "viridian_crash_ctl", "viridian_stimer"]
WINDOWS_MAX_LINES = 40

# Failed Systemd Units: units left out, as fnmatch patterns on the unescaped name (the one
# the report prints, 'SMGC@a112-...' rather than 'SMGC@a112\x2d...').
#   SMGC@*   one GC run of an SR; a failed one stays 'failed' until that SR's next GC run,
#            and GC health is judged from SMlog by storage-state-fixer (C19), not from a unit
#   *xcp-persistent-database.service   the units drbd-utils and drbd-reactor's promoter run
#            for XOSTOR's LINSTOR-database resource (drbd@..., drbd-promote@...), expected to
#            sit failed on the hosts that do not hold it; the controller's own health is
#            the XOSTOR lines' business
#   mcelog.service   fails at every boot on an AMD host by design: "mcelog: ERROR: AMD
#            Processor family 25: mcelog does not support this processor.  Please use the
#            edac_mce_amd module instead." (seen in the field, 2026-11). Left out on every
#            CPU, the maintainer's call - on Intel that hides a dead machine-check logger.
FAILED_UNITS_IGNORE = ["SMGC@*", "*xcp-persistent-database.service", "mcelog.service"]
# attach-static-vdis is left out only when no static-VDI entry existed when it failed: its
# script, before xen-api ae4d3ec4, fails on an empty directory (a host booted with HA off)
STATIC_VDIS_UNIT = "attach-static-vdis.service"
# dmesg lines quoted as evidence under a finding, case-insensitive; never part of the verdict.
# Not a bare "read-only": every boot prints "Write protecting the kernel read-only data".
RO_FS_DMESG = ["remounting filesystem read-only", "has been set read-only", "aborting journal"]

MTU_DMESG_KEYWORDS = ["mtu", "large", "fragment"]      # whole-word, case-insensitive
DMESG_ISSUE_WORDS = ["panic", "crash", "rip", "kill"]  # whole-word, case-insensitive
DMESG_ISSUE_PHRASES = ["call trace", "timed out"]      # substring, case-insensitive
OOM_PHRASE = "out of memory"

# A dmesg line is dropped from Dmesg Content AND from MTU Issues if it contains ALL of a
# rule's substrings (case-insensitive, whitespace collapsed). One list entry = one rule.
DMESG_IGNORE_RULES = [
    ["megaraid", "firmware crash dump"],   # megaraid driver load prints "... : no"
    # the PCI core reading a NIC's Vital Product Data at probe time, e.g.
    # "ixgbe 0000:82:00.0: invalid large VPD tag 7f at offset 25091" - a firmware quirk
    # of the card's EEPROM, nothing to do with MTUs or large frames
    ["invalid large vpd tag"],
]

# --- "Log Errors" check ---------------------------------------------------------------
# Plain case-insensitive substrings (grep -F), so nothing needs escaping. Each phrase is
# reported separately, so a noisy phrase can never hide a rare one.
LOG_ERROR_PHRASES = [
    "except",                    # python tracebacks / SMAPI exceptions
    "Input/output error",
    "XENAPI_PLUGIN_FAILURE",
    "TapdiskNotRunning",         # tapdisk died under it - pairs with a core.tapdisk.* dump
]
# Each is scanned together with its rotated ".1": these rotate daily around 04:00, so
# right after a rotation the live file is nearly empty and this morning's errors are in .1.
LOG_ERROR_FILES = [
    "/var/log/SMlog",
    "/var/log/xensource.log",
]
LOG_ERROR_CONTEXT = 3            # lines of context shown either side of a match
# A matched line is not a hit if it contains ALL of a rule's substrings (case-insensitive).
# Applied in the collector, while the last hit per phrase is picked: dropping the line
# afterwards would leave an earlier, real hit of the same phrase unreported.
LOG_ERROR_IGNORE_RULES = [
    # every xapi start: check_network_reset reads /var/tmp/network-reset, which exists only
    # after xe-reset-networking, and logs the ENOENT at error level (xen-api xapi.ml,
    # "Raises exception if the file is not there and no reset is required")
    ["check_network_reset", "/var/tmp/network-reset", "enoent"],
]

# --- multipath checks -----------------------------------------------------------------
# `Multipathing` reports the xapi SETTING. These describe the paths themselves, which is a
# different question: a host printed a green "Multipathing: true" while its dmesg said
# "device-mapper: multipath: Failing path 8:48".
#
# All three state whitelists, deliberately. multipath-tools 0.4.9 (both 8.2.1 and 8.3.0,
# same build, verified in the binary's own string table 2026-08-27) prints:
#   dm_st  (%t) undef | active | failed
#   chk_st (%T) undef | ready | faulty | shaky | ghost | delayed
#   dev_st (%o) unknown | running | offline | blocked | quiesce | dead | deleting | live
# A state that is not listed here is NOT healthy - a newer multipath-tools inventing a
# state name must read as "not established", never as a pass.
MULTIPATH_OK_DM_STATES = ["active"]
MULTIPATH_OK_CHK_STATES = ["ready", "ghost"]
MULTIPATH_OK_DEV_STATES = ["running", "live"]
# 'ghost' is the standby path of an active/passive (ALUA) array: healthy by design, and
# counted separately so the line can say how many there are. Move it out of OK_CHK_STATES
# to flag ghost paths instead - correct for an active/active array, wrong for the rest.
MULTIPATH_STANDBY_CHK_STATES = ["ghost"]
# 'undef' on a path that belongs to a map means the checker has not finished its first
# probe, not that the path is bad - likeliest right after a boot or an SR plug, i.e.
# exactly when someone runs a health check. Seeing one, the collector waits and asks once
# more; if it is still undef, that is reported as found.
MULTIPATH_TRANSIENT_CHK_STATES = ["undef"]
MULTIPATH_RECHECK_DELAY = 2.0    # seconds before that single re-query
MULTIPATH_MAX_LINES = 60         # path rows listed in a detail block

# Kernel-side, timestamped path events. Deliberately NOT the per-map path_faults counter,
# which never resets until the map reloads and would leave a permanent finding behind a
# switch reboot last month; both windows below close by themselves.
#
# Scanned in the FILES below (plus their .1) *and* in the dmesg ring, which is already
# collected for `Dmesg Content` and so costs nothing extra. Neither contains the other:
# kern.log survives a reboot but spans about two rotations, while the ring covers the
# whole uptime on a quiet dom0 and wraps on a busy one. Measured on 8.3.0: path failures
# sat in the ring that were in neither kern.log file.
MULTIPATH_EVENT_PHRASES = [
    "device-mapper: multipath: Failing path",
]
MULTIPATH_EVENT_FILES = [
    "/var/log/kern.log",
]

# --- stuck mounts and the processes they take down -------------------------------------
# A mount whose server stops answering parks anything that stats it in uninterruptible
# sleep (D state), where no signal can reach it - SIGKILL included. It is not a niche
# failure: it took a pool master out of every report for days, and the script said nothing,
# because nothing it ran ever came back to say anything.
#
# The kernel has its own detector for this and it is NOT enough on its own, which is why
# the D-state scan leads rather than a dmesg phrase. Measured twice over:
#
#   * It is enabled on 8.3.0 - hung_task_timeout_secs=120, CONFIG_DETECT_HUNG_TASK=y - but
#     kernel.hung_task_warnings defaults to 10 and COUNTS DOWN, so it stops logging for
#     the rest of the uptime after ten.
#   * On the host this was built for it never fired AT ALL. 589 processes had been in D
#     state for nearly four days, and there was not one "blocked for more than" line in
#     the dmesg ring, the live kern.log, or any of its 30 rotated archives. Inference, not
#     measurement, for the why: khungtaskd counts only a task that has not been scheduled
#     since its last sweep, and a CIFS reconnect loop wakes its waiters periodically - so
#     the failure this check exists for is one the kernel is structurally quiet about.
NETWORK_FS_TYPES = [             # the ones that can hang forever waiting on a server
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "fuse.glusterfs",
    "afs", "9p", "ncpfs", "lustre", "beegfs",
]
# D state on its own is NOT a fault, and reading it as one was a false positive in the
# field (issue #70, v3.11): a `vhd-util coalesce` a minute into its run was reported as
# stuck, because it was in D at two samples 5s apart - which is exactly what a process
# copying data between VHDs looks like. Every disk read is in D for some of its life.
#
# So a finding needs a second, positive fact: that the process got NOWHERE while it was
# watched. Its CPU ticks and its I/O counters must not move at all across the whole
# window - a process parked in D executes no instructions and completes no I/O, while
# anything doing real work is being woken constantly to hand off the next buffer.
#
# Age is not that fact and never was. It is how long the process has EXISTED, an upper
# bound on how long it has been wedged, so raising the floor would only have moved the
# same false positive to longer-running commands - and a backup can coalesce for an hour.
# The floor stays where it is, as a noise filter, and the report says what age means.
#
# Excluding vhd-util (or tapdisk, or dd) by name was considered and declined: a coalesce
# wedged on a dead SR is precisely the thing worth reporting, and a name list would hide
# it. The progress test keeps that case - a wedged coalesce burns no CPU.
STUCK_RECHECK_DELAY = 5          # seconds between D-state samples
STUCK_SAMPLES = 3                # samples that must ALL show it wedged, so a 10s window.
                                 # Only the first wait is paid by a host that is merely
                                 # busy: one look at its CPU counter drops it
STUCK_MIN_AGE = 60               # a process must also have existed this long to count
STUCK_MAX_LINES = 25             # stuck processes listed in the detail block, oldest first
MOUNT_PROBE_TIMEOUT = 10         # seconds a stat() of one mount point may take
MOUNT_PROBE_RESERVE = 60         # run-budget seconds kept back for everything that comes
                                 # after the probes. Every mount is probed now, dead ones
                                 # included, and each dead one costs the full timeout
                                 # above - so a host with several would leave yum and the
                                 # pool questions to time out behind it. Past this line
                                 # the rest read "not probed", which claims nothing

# Both halves of the same event, from the two sources that keep it - see the multipath
# event phrases above for why neither contains the other.
#
# These name the SERVER, which the process scan cannot. They also age out, and on the host
# above they already had: the only copies left were in kern.log.4.gz and .5.gz, four days
# back, with the ring wrapped clean past them (`dmesg | grep -i cifs` returned nothing at
# all). Reading the .gz archives was considered for exactly that case and declined - it is
# a zgrep of ~30 files on every host of every run to recover a server name that Network
# Mounts already prints from /proc/mounts, for a condition Stuck Processes already reports.
MOUNT_STALL_PHRASES = [
    # verbatim from a live 8.3.0 dom0 whose SMB server had stopped answering:
    # "CIFS VFS: Server 192.0.2.11 has not responded in 120 seconds. Reconnecting..."
    "has not responded in",
    "not responding",            # nfs: "server X not responding, still trying"
    "blocked for more than",     # the kernel's hung-task detector - see the note above on
                                 # why this one cannot be relied on, and is kept anyway
]
MOUNT_STALL_FILES = [
    "/var/log/kern.log",
]

# --- "LUN Assignments" check ----------------------------------------------------------
LUN_CHANGE_PHRASES = [
    "Warning! Received an indication that the LUN assignments on this target have changed",
]
LUN_CHANGE_FILES = [
    "/var/log/kern.log",
]

# --- "XO-Server Memory Limit" check ------------------------------------------------------
# Vates' sizing rule since XO 6.8 (docs, getting-started/troubleshooting.md): the heap limit
# is 70% of the VM's RAM, 1 GiB minimum. The docs say xo-server sets it itself; on the
# test XOA (6.9.2, xo-server 5.211.4, 2026-11-25) nothing did - no flag in the unit, its
# drop-in, the process' argv or NODE_OPTIONS, and no code in xo-server - so the process
# ran on node's own default (~50% of RAM, at most ~4 GB). The line therefore judges the
# limit the running process actually has, wherever it came from, against this rule.
XO_HEAP_TARGET_PCT = 70
XO_HEAP_MIN_MB = 1024

# --- "XOA Plugins" check ---------------------------------------------------------------
# Where xo-server looks for plugins, and what it accepts as one. Mirrors
# packages/xo-server/config.toml's `plugins.lookupPaths` and registerPlugins() in
# index.mjs: for every lookup path it takes each entry of `<path>/@xen-orchestra` starting
# `server-` and each entry of `<path>` starting `xo-server-`, and the remainder of the
# entry name IS the plugin's name. First path that has a name wins.
#
# In XO's OWN order - xo-server keeps the first path that has a name, so the scan must walk
# them as it does: config.toml's lookupPaths is ['./node_modules', '../',
# '/usr/local/lib/node_modules'] (checked on the test XOA), and two of those are relative
# to the process' cwd, which for a systemd unit with no WorkingDirectory - and
# xo-server.service sets none - is "/". Hence /node_modules and / first: neither holds a
# plugin on a stock appliance, and a copy there under a stock name is the one XO loads.
XO_PLUGIN_LOOKUP_PATHS = ["/node_modules", "/", "/usr/local/lib/node_modules"]
# where xoa-updater installs Vates' own plugins: a stock name anywhere else is not theirs
XO_PLUGIN_STOCK_DIR = "/usr/local/lib/node_modules"
XO_PLUGIN_PREFIX = "xo-server-"
XO_PLUGIN_SCOPE_DIR = "@xen-orchestra"
XO_PLUGIN_SCOPE_PREFIX = "server-"

# The plugin names Vates ships, as a FALLBACK and not as the answer. A run reads
# xoa-updater's own `getLocalManifest` first and unions those names in, so a plugin Vates
# adds after this list was written is not reported as somebody else's; this list is what
# is left when the updater is down, unregistered or timing out.
#
# Read off a stock appliance (XOA 6.7.1, xo-server 5.207.2, 2026-09-11) and cross-checked
# against packages/xo-server-* in vatesfr/xen-orchestra. `cloud` is a retired Vates plugin
# that is no longer installed but still leaves an `xo:plugin-metadata:cloud` record
# behind. `test-plugin` is deliberately absent: it is a development fixture in Vates' repo
# that XOA does not ship, so an appliance carrying it has had something done to it.
XOA_STOCK_PLUGINS = [
    "audit",
    "auth-github",
    "auth-google",
    "auth-ldap",
    "auth-oidc",
    "auth-saml",
    "backup-reports",
    "cloud",
    "ipmi-sensors",
    "load-balancer",
    "netbox",
    "netdata",
    "openmetrics",
    "perf-alert",
    "sdn-controller",
    "telemetry",
    "transport-email",
    "transport-icinga2",
    "transport-nagios",
    "transport-slack",
    "transport-xmpp",
    "usage-report",
    "web-hooks",
    "xoa",
]

CRASH_IGNORE_FILE = ".sacrificial-space-for-logs"   # file in /var/crash that is not a crash
COREDUMP_DIR = "/var/lib/systemd/coredump"          # anything here means a dom0 process died
COREDUMP_MAX_LINES = 50          # coredumps listed in the detail block (newest first)
PKG_DIFF_MAX_LINES = 100         # mismatched yum packages listed
XOSTOR_QCOW2_MAX_LINES = 50      # qcow2 VDIs on XOSTOR listed
# packages whose installed versions 'XOSTOR Packages' lists on every host, in print order
XOSTOR_PACKAGES = (
    "kmod-drbd", "drbd", "drbd-utils", "drbd-reactor", "linstor-satellite",
    "linstor-controller", "linstor-client", "python-linstor", "xcp-ng-linstor",
)
UPDATE_MIRROR_REDIRECTOR = "mirrors.xcp-ng.org"   # the mirrorbits host the XCP-ng repos use
UPDATE_MIRROR_TIMEOUT = 10       # seconds per request to the redirector or one mirror
UPDATE_MIRROR_BUDGET = 60        # seconds for the whole mirror probe on one host
UPDATE_MIRROR_MAX_PROBES = 6     # mirrors fetched from, of those the redirector hands out
XOSTOR_VG = "linstor_group"      # the LVM volume group XOSTOR builds its storage pool on
DMESG_MAX_LINES = 80             # lines of a dmesg detail block (Dmesg Content, OOM Events);
                                 # the newest are kept, and the rollup runs first
DMESG_ROLLUP_MIN = 3             # consecutive copies of one dmesg message folded into a
                                 # 'repeated N times' line from this many; fewer print in full

# Which per-host checks run on SLAVES in pool mode. The master always runs everything, and
# so does single mode / a solo host run; these toggles exist only to keep a sweep short.
POOL_RUN = {
    "dom0_disk_usage": True,
    "read_only_filesystems": True,
    "dom0_memory": True,
    "mtu_issues": True,
    "dmesg_content": True,
    "oom_events": True,
    "crash_logs_present": True,
    "coredumps_present": True,
    "failed_units": True,
    "tap_ctl_list": True,
    "task_timeout_override": True,
    "lacp_negotiation": True,
    "multipath_health": True,
    "multipath_events": True,
    "stuck_processes": True,
    "mount_stalls": True,
    "network_mounts": True,
    "silly_mtus": True,
    "dns_gw_non_mgmt_pifs": True,
    "overlapping_subnets": True,
    "duplicate_ips": True,
    "log_errors": True,
    "lun_assignments": True,
    "smapi_hidden_leaves": False,
    "rebooted_after_updates": True,
    "yum_patch_level": True,
    "xostor_versions": True,
    "xostor_missing_devices": True,
    "update_mirror_access": True,
}


# ======================================================================================
# --- colors ----------------------------------------------------------------------------

GREEN = ""
YELLOW = ""
CYAN = ""
RESET = ""


def init(stream=None, force_off=False):
    """Decide once whether this run is coloured. Called from main().

    force_off is --json: a document is not read by a terminal, and colouring it would
    mean every consumer had to strip the escape codes back out of every value. It beats
    HEALTH_FORCE_COLOR, which exists to colour output for a human.
    """
    global GREEN, YELLOW, CYAN, RESET
    if force_off:
        GREEN = YELLOW = CYAN = RESET = ""
        return
    stream = stream if stream is not None else sys.stdout
    forced = os.environ.get("HEALTH_FORCE_COLOR", "0") == "1"
    try:
        is_tty = bool(stream.isatty())
    except (AttributeError, ValueError):
        is_tty = False
    if is_tty or forced:
        GREEN, YELLOW, CYAN, RESET = "\033[32m", "\033[33m", "\033[36m", "\033[0m"
    else:
        GREEN = YELLOW = CYAN = RESET = ""


def green(text):
    return "%s%s%s" % (GREEN, text, RESET)


def yellow(text):
    return "%s%s%s" % (YELLOW, text, RESET)


def cyan(text):
    return "%s%s%s" % (CYAN, text, RESET)


def strip_ansi(text):
    """Defensive: some tools colourise even when told not to.

    An ECMA-48 control sequence is ESC [, parameter bytes 0x30-0x3F, intermediate bytes
    0x20-0x2F, then exactly ONE final byte 0x40-0x7E. Scanning for a final byte from a
    short list of letters instead ate real text after any other sequence - after ESC[2d
    a whole line of xoa-updater output vanished up to the next listed letter. The
    collector carries the same pattern (collector.ANSI_RE)."""
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


# ======================================================================================
# --- result ----------------------------------------------------------------------------

OK = "ok"
FLAG = "flag"
UNKNOWN = "unknown"
INFO = "info"


class Line(object):
    """One 'Key: value' line of the report, plus any detail blob it wants printed."""

    __slots__ = ("key", "text", "status", "detail_title", "detail_text", "label", "keep")

    def __init__(self, key, text, status, detail_title=None, detail_text=None):
        self.key = key
        self.text = text
        self.status = status
        self.detail_title = detail_title
        self.detail_text = detail_text
        self.label = key + ":"      # a couple of lines pad this for alignment
        self.keep = False           # an INFO line that survives -f anyway; see pinned()

    @property
    def flags(self):
        return self.status in (FLAG, UNKNOWN)

    @property
    def always_print(self):
        """Printed even under -f. A finding always is; an INFO line only if it says so."""
        return self.flags or self.keep

    def render(self):
        return "%s %s" % (self.label, self.text)

    def with_detail(self, title, text):
        self.detail_title = title
        self.detail_text = text
        return self


def ok(key, text):
    return Line(key, colors.green(text), OK)


def flag(key, text, extra=""):
    """A finding. 'extra' is appended outside the colouring, like 'Fail - /var is at 90%'."""
    return Line(key, colors.yellow(text) + extra, FLAG)


def unknown(key, text):
    """We could not establish the fact. Same weight as a finding, different meaning."""
    return Line(key, colors.yellow(text), UNKNOWN)


def info(key, text, color="green"):
    """A fact with no threshold behind it, so it can never flag.

    Yellow is the caller saying 'this one is worth a look' - a state that was not
    established, or one that is unusual without being wrong. Those survive -f; the green
    ones are just readings, and -f is not asking for readings.
    """
    painted = colors.yellow(text) if color == "yellow" else (
        colors.green(text) if color == "green" else text)
    line = Line(key, painted, INFO)
    line.keep = (color == "yellow")
    return line


def raw(key, text):
    """Uncoloured, exit-code neutral, hidden by -f."""
    return Line(key, text, INFO)


def pinned(line):
    """Print this line under -f even though it is not a finding.

    Deliberately rare, and every use has to earn it: a line that survives -f while
    claiming nothing is padding in a report someone asked to have narrowed.
    """
    line.keep = True
    return line


def guard(key, fn, *args, **kwargs):
    """Run a check; turn any escaped exception into a yellow Unknown for that line.

    A check that blows up must not kill the run and must never be silently skipped -
    a skipped line reads as 'not applicable', which is a claim of its own. `key` may be a
    tuple, for a check that prints several lines: each gets its Unknown, so the second
    line of a check that raised is not simply missing (from --json too).
    """
    keys = key if isinstance(key, tuple) else (key,)
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - deliberate: one bad check, one bad line
        import sys
        sys.stderr.write("internal error in %s:\n%s\n" % (" / ".join(keys),
                                                         traceback.format_exc()))
        lines = [unknown(k, "Unknown (internal error: %s)" % exc) for k in keys]
        return lines[0] if len(lines) == 1 else lines


class Fact(object):
    """One value from the collector, or the reason it is missing."""

    __slots__ = ("ok", "value", "error")

    def __init__(self, ok_, value=None, error=None):
        self.ok = ok_
        self.value = value
        self.error = error

    def __repr__(self):
        return "Fact(ok=%r, value=%r, error=%r)" % (self.ok, self.value, self.error)


MISSING = Fact(False, error="not collected")


def wrap(payload, key):
    """Pull one fact out of a collector document."""
    node = payload.get(key)
    if not isinstance(node, dict):
        return Fact(False, error="not collected")
    if node.get("ok"):
        return Fact(True, value=node.get("value"))
    return Fact(False, error=node.get("error") or "unavailable")


# ======================================================================================
# --- parsers ---------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# xe labelled output
# --------------------------------------------------------------------------------------

# The access tag is two letters for a plain field ('( RO)', '( RW)') and three for a map or
# set ('(MRW)', '(MRO)', '(SRO)'); matching only two silently dropped every map field.
_PARAM_RE = re.compile(r"^\s*([A-Za-z0-9_.:-]+)\s*\(\s*[A-Z]{2,3}\s*\)\s*:\s?(.*)$")


def parse_xe_records(text, start_key="uuid"):
    """Split xe's labelled output into records.

    A record starts at its start_key line and ends at the next one - NOT at a blank line.
    Output that has been through a strip() or been glued together from two calls has only
    a single newline between records, and paragraph splitting then merges the last record
    of one block into the first of the next and silently drops an object.
    """
    records = []
    current = None
    for line in text.splitlines():
        m = _PARAM_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if key == start_key:
            if current is not None:
                records.append(current)
            current = {}
        if current is None:
            continue
        current[key] = value
    if current is not None:
        records.append(current)
    return records


def split_host_port(text):
    """'10.0.0.5:3366' -> ('10.0.0.5', 3366); '[fd00::1]:3366' -> ('fd00::1', 3366);
    anything else -> (text, None).

    The one reading of 'address, maybe with a port' - a host argument's ssh port, the
    ':443' XO keeps on a server record, a linstor satellite's ':3366'. A bare IPv6 address
    has more than one colon and is left whole.
    """
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if text.count(":") == 1:
        host, port = text.split(":")
        if host and port.isdigit():
            return host, int(port)
    return text, None


# xen-api's own reading of a server record's `host` (packages/xen-api/_parseUrl.mjs): an
# optional http(s) scheme, optional user[:password]@, a bracketed IPv6 address or a name
# or IPv4 address, an optional :port and an optional /path
_XO_URL_RE = re.compile(r"^(?:(https?:)/*)?(?:(([^:]*)(?::([^@]*))?)@)?"
                        r"(\[[^\]]+\]|[^:/]+)(?::([0-9]+))?(/[^?#]*)?$")
# what is left of anything that pattern refuses once a scheme (in any case: XO matches it
# in lower case only), credentials, and whatever follows the host - a path, a query, a
# fragment - are taken off
_LOOSE_URL_RE = re.compile(r"^(?:https?:)?/*(?:[^@/?#]*@)?([^/?#]*)", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^\s*https?:", re.IGNORECASE)


def has_url_scheme(text):
    """True for an address written as a URL - 'https://10.0.0.5', copied out of XO's own
    list of servers or a browser - rather than as address[:port]."""
    return bool(_SCHEME_RE.match(text or ""))


def xo_server_address(text):
    """A server record's `host` -> (address, port), read the way XO reads it.

    XO takes more than an address there - 'https://', credentials before an '@', a path -
    and a record written that way used to reach ssh whole, as 'root@http://...', failing
    the run before it began. The port is the XAPI port XO connects on, never an ssh port.

    What XO's pattern refuses ('HTTPS://', a query string, an IPv6 address with a scheme
    and no brackets) is a record XO cannot connect with either, which may be the very
    reason the pool is being checked: it is read for whatever address is left once the
    scheme, credentials and anything after the host are off.
    """
    text = (text or "").strip()
    m = _XO_URL_RE.match(text)
    if not m:
        return split_host_port(_LOOSE_URL_RE.match(text).group(1))
    host = m.group(5)
    if host.startswith("["):
        host = host[1:-1]
    return host, (int(m.group(6)) if m.group(6) else None)


def ip_literal(text):
    """The canonical spelling of an IP address, or None for anything that is not one.

    Canonical, so two spellings of one IPv6 address compare equal. A '%scope' suffix is
    dropped: ipaddress reads one only from 3.9, and the floor here is 3.6.
    """
    try:
        return ipaddress.ip_address(str(text or "").split("%")[0].strip()).compressed
    except ValueError:
        return None


def pool_member_addresses(value):
    """A server record's `poolMembersAddresses` -> list of addresses.

    xo-server (July 2026, xen-orchestra #10016) keeps every member's address there, plus
    the address it connects to, so it can fail over to a survivor when the master dies. It
    is stored as a JSON string inside the record; older XO has no such field, and anything
    that does not read as a list of strings is no list at all.

    An IPv6 address is stored in brackets (xen-api's formatHostname, so it can go straight
    into a URL), which no address comparison would ever match; they are taken off.
    """
    if not value or not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
    except ValueError:
        return []
    if not isinstance(parsed, list):
        return []
    out = []
    for address in parsed:
        if not isinstance(address, str):
            continue
        if address.startswith("[") and address.endswith("]"):
            address = address[1:-1]
        if address:
            out.append(address)
    return out


def parse_host_list(text):
    """xe host-list params=uuid,name-label,hostname,address,enabled,multipathing.

    Parsed by label, never by position: xapi does not print the fields in the order they
    were asked for.
    """
    hosts = []
    for rec in parse_xe_records(text):
        if not rec.get("uuid"):
            continue
        hosts.append({
            "uuid": rec.get("uuid", ""),
            "name_label": rec.get("name-label", ""),
            "hostname": rec.get("hostname", ""),
            "address": rec.get("address", ""),
            "enabled": rec.get("enabled") or "Unknown",
            "multipathing": rec.get("multipathing") or "Unknown",
        })
    return hosts


SR_ATTACH_SKIP_TYPES = ("udev",)


def parse_sr_attachment(pbd_text, sr_text, host_text):
    """Where each SR is plugged, from xe's PBD, SR and host listings.

    Returns None when nothing can be judged: a listing that cannot be read as what xe
    prints (a record without a field it was asked for), no host at all, or no host xapi
    sees as live. Otherwise a dict:
      shared [(sr_name, sr_uuid, everywhere, [(host_name, why, pbd_uuid)])] - a shared SR
             that a live host cannot use; why is 'not plugged' (pbd_uuid names the PBD) or
             'no PBD' (pbd_uuid None); everywhere is True when that is every live host
      local  [(sr_name, sr_uuid, host_name, pbd_uuid)] - a local SR its own live host has
             not plugged (host_name and pbd_uuid None for a local SR with no PBD at all)
      down   [host_name] - hosts xapi does not see as live; their PBDs are not judged,
             a down host's own local SRs included
    sr_name is the name-label, or the uuid when the label is empty. udev SRs (DVD drives,
    removable storage) are left out: they come and go with media.
    """
    hosts = parse_xe_records(host_text)
    srs = parse_xe_records(sr_text)
    pbds = parse_xe_records(pbd_text)
    wants = ((hosts, {"uuid", "name-label", "host-metrics-live"}),
             (srs, {"uuid", "name-label", "type", "shared"}),
             (pbds, {"uuid", "host-uuid", "sr-uuid", "currently-attached"}))
    if not hosts or any(not want <= set(r) for recs, want in wants for r in recs):
        return None
    name = dict((h["uuid"], h["name-label"] or h["uuid"]) for h in hosts)
    live = [h["uuid"] for h in hosts if h["host-metrics-live"] == "true"]
    if not live:
        return None
    out = {"shared": [], "local": [],
           "down": sorted(name[h["uuid"]] for h in hosts if h["uuid"] not in live)}
    for sr in sorted(srs, key=lambda r: (r["name-label"], r["uuid"])):
        if sr["type"] in SR_ATTACH_SKIP_TYPES:
            continue
        label = sr["name-label"] or sr["uuid"]
        mine = [p for p in pbds if p["sr-uuid"] == sr["uuid"]]
        if sr["shared"] != "true":
            if not mine:
                out["local"].append((label, sr["uuid"], None, None))
            for p in mine:
                if p["host-uuid"] in live and p["currently-attached"] != "true":
                    out["local"].append((label, sr["uuid"], name[p["host-uuid"]], p["uuid"]))
            continue
        plugged = set(p["host-uuid"] for p in mine if p["currently-attached"] == "true")
        missing = []
        for h in live:
            here = [p for p in mine if p["host-uuid"] == h]
            if not here:
                missing.append((name[h], "no PBD", None))
            elif h not in plugged:
                missing.append((name[h], "not plugged", here[0]["uuid"]))
        if missing:
            out["shared"].append((label, sr["uuid"], len(missing) == len(live),
                                  sorted(missing, key=lambda m: (m[0], m[1]))))
    return out


def xapi_utc(text):
    """xapi's '20261106T19:39:59Z' (UTC) as an epoch, or None if it is not that."""
    try:
        return calendar.timegm(time.strptime(text, "%Y%m%dT%H:%M:%SZ"))
    except (TypeError, ValueError):
        return None


def parse_pending_tasks(text, now, max_age):
    """Pending xapi tasks older than max_age seconds, from xe task-list's labelled output.

    Returns None when the listing cannot be read as what xe prints - a record without a
    field it was asked for, or a pending task whose 'created' is not xapi's UTC stamp -
    else [(name_label, uuid, age_seconds, progress, resident_on, status)], oldest first.

    Every task xapi does not count as completed is judged - pending, and 'cancelling', a
    cancel that never finished and still holds its object. xapi's own partition is the same
    (xen-api v26.1.19 taskHelper.ml status_is_completed: success, failure, cancelled), so a
    finished task is xapi's to clean up and anything else is not finished.
    """
    old = []
    for rec in parse_xe_records(text):
        if not {"uuid", "name-label", "status", "created", "progress", "resident-on"} <= set(rec):
            return None
        if rec["status"] in TASK_COMPLETED:
            continue
        created = xapi_utc(rec["created"])
        if created is None:
            return None
        if now - created > max_age:
            old.append((rec["name-label"], rec["uuid"], now - created, rec["progress"],
                        rec["resident-on"], rec["status"]))
    return sorted(old, key=lambda t: -t[2])


TASK_COMPLETED = ("success", "failure", "cancelled")


def unit_display(name):
    """systemd's \\xHH escaping undone for display: 'SMGC@a112\\x2d8923' -> 'SMGC@a112-8923'."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), name)


def unit_ignored(name, patterns):
    """Does a unit match one of the fnmatch patterns? Matched on the unescaped name, which
    is the one the report prints, so a pattern reads the way the line it removes did."""
    shown = unit_display(name)
    return any(fnmatch.fnmatchcase(shown, p) for p in patterns)


def static_vdis_failure_moot(value, boot_epoch):
    """Was attach-static-vdis's last failure about nothing?

    True when no static-VDI entry existed when it failed: the directory empty or absent,
    or every entry created after the failure (HA enabled afterwards, as a rolling pool
    reboot does). False when an entry was already there - a VDI HA needs did not attach
    at boot. None when that is not established: no exit time, no boot time, or an entry
    whose creation time could not be read. value is the collector's static_vdis fact.
    """
    if not isinstance(value, dict) or not isinstance(boot_epoch, (int, float)):
        return None
    mono = value.get("exit_mono_us")
    entries = value.get("entries")
    if not isinstance(mono, int) or mono <= 0 or not isinstance(entries, list):
        return None
    failed_at = boot_epoch + mono / 1e6
    for entry in entries:
        created = entry.get("created") if isinstance(entry, dict) else None
        if not isinstance(created, (int, float)):
            return None
        if created <= failed_at:
            return False
    return True


def parse_failed_units(text):
    """[(unit, description)] from 'systemctl --failed --no-legend --plain', in its order.

    The columns are UNIT LOAD ACTIVE SUB DESCRIPTION; a systemd that ignores --plain puts
    a bullet in front, which is dropped. The unit name stays escaped, as systemctl takes it.
    """
    units = []
    for line in (text or "").splitlines():
        parts = line.replace("●", " ").split(None, 4)
        if not parts:
            continue
        units.append((parts[0], parts[4] if len(parts) > 4 else ""))
    return units


def parse_pvs(text):
    """[(pv name, vg name, attr, uuid)] from 'pvs --noheadings --separator | -o
    pv_name,vg_name,pv_attr,pv_uuid'. A line without the separators is a warning that
    landed on stdout, not a row; uuid is '' from an older collector that did not ask."""
    rows = []
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        rows.append((parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""))
    return rows


def parse_lvm_backup_pvs(text):
    """[(uuid, device hint)] out of the physical_volumes section of an LVM metadata
    backup, in file order. 'device' is LVM's 'Hint only' - where the PV was last seen,
    which a reboot can renumber - so the uuid is what identifies it."""
    pvs, cur = [], None
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r'^(\S+)\s*\{$', line)
        if m and m.group(1) != "physical_volumes":
            cur = {"id": "", "device": ""}
            pvs.append(cur)
            continue
        m = re.match(r'^(id|device)\s*=\s*"([^"]*)"', line)
        if m and cur is not None:
            cur[m.group(1)] = m.group(2)
    return [(p["id"], p["device"]) for p in pvs if p["id"]]


def pv_missing(name, attr):
    """The PV's device is gone: LVM names it '[unknown]' ('unknown device' before lvm2
    2.02.x) and sets the third attr character to 'm'. Either is enough."""
    return name in ("[unknown]", "unknown device") or (len(attr) > 2 and attr[2] == "m")


def host_records_from_state_db(rows):
    """The collector's state.db host rows, in parse_host_list's shape.

    enabled and multipathing are Unknown rather than read out of the file. The file is
    what xapi last saved, and when it is being read at all it is because xapi is not
    answering: 'enabled: true' from a toolstack that is down is a reading of the past,
    reported as the present.
    """
    hosts = []
    for row in rows or []:
        if not row.get("uuid"):
            continue
        hosts.append({
            "uuid": row.get("uuid", ""),
            "name_label": row.get("name_label", ""),
            "hostname": row.get("hostname", ""),
            "address": row.get("address", ""),
            "enabled": "Unknown",
            "multipathing": "Unknown",
        })
    return hosts


def parse_dns_gw_pifs(text):
    """True when any non-management PIF carries a gateway (IPv4 or IPv6) or a DNS server.
    An IPv6 default gateway on a storage or VM network is the same second-default-route
    problem as an IPv4 one."""
    for line in text.splitlines():
        if not re.match(r"^\s*(gateway|IPv6-gateway|DNS)\s*\([^)]*\)\s*:", line):
            continue
        value = line.split(":", 1)[1].strip() if ":" in line else ""
        if value:
            return True
    return False


BOND_MEMBER = 0
BOND_NOT_MEMBER = 1
BOND_NO_PIFS = 3


def parse_bond_slave_of(text):
    """Is the network a bond member?

    A network uuid that no longer exists is answered rc 0 with NO output at all (measured
    on 8.3.0, and quietly - no exception lands in xensource.log). Read as "no
    bond-slave-of line, therefore not a bond member", that printed a green 'Configured'
    for a pool whose xo:migrationNetwork points at a network somebody deleted. It gets its
    own state instead: nothing about the network was established.
    """
    if "bond-slave-of" not in text:
        return BOND_NO_PIFS
    for line in text.splitlines():
        if "bond-slave-of" not in line:
            continue
        value = line.split(":", 1)[1].strip() if ":" in line else ""
        if value and value != "<not in database>":
            return BOND_MEMBER
    return BOND_NOT_MEMBER


def parse_other_config(text):
    """The map prints as 'key: value; key: value'.

    Splitting records on ';' is safe for the keys looked up here, whose values are network
    UUIDs. Note keys themselves contain colons (xo:clientInfo:<uuid>), so the split is at
    the first ': ' - colon plus space - not at the first colon.
    """
    out = {}
    for entry in text.split(";"):
        entry = entry.strip()
        idx = entry.find(": ")
        if idx <= 0:
            continue
        out[entry[:idx].strip()] = entry[idx + 2:].strip()
    return out


# --------------------------------------------------------------------------------------
# /proc, timedatectl, df, ip
# --------------------------------------------------------------------------------------

_HEAP_FLAG_RE = re.compile(r"^--max[-_]old[-_]space[-_]size(?:=(\d+))?$")


def node_heap_flag(args):
    """The --max-old-space-size value (MB) in a list of node arguments, or None.

    V8 takes the flag with dashes or underscores, as `=N` or with N as the next argument,
    and the LAST occurrence wins - all three are honoured here, so a flag given twice is
    read the way node reads it."""
    value = None
    i = 0
    while i < len(args):
        m = _HEAP_FLAG_RE.match(args[i])
        if m:
            if m.group(1) is not None:
                value = int(m.group(1))
            elif i + 1 < len(args) and args[i + 1].isdigit():
                value = int(args[i + 1])
                i += 1
        i += 1
    return value


def parse_meminfo(text):
    """(total_mb, avail_mb), or None when the numbers are not there.

    None is the whole point: a percentage computed from a zero total is a green 0.0%,
    which reads exactly like a healthy host when it actually means we never looked.
    """
    total = avail = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "MemTotal:" and parts[1].isdigit():
            total = int(parts[1])
        elif len(parts) >= 2 and parts[0] == "MemAvailable:" and parts[1].isdigit():
            avail = int(parts[1])
    if not total:
        return None
    if avail is None:
        return None
    return (total // 1024, avail // 1024)


def parse_mem_total_mb(text):
    """MemTotal in MiB, or None when it is not there (never 0)."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "MemTotal:" and parts[1].isdigit():
            return int(parts[1]) // 1024 or None
    return None


def parse_timedatectl(text):
    """NTP enabled / synchronized, across both systemd label generations.

    Older systemd (xcp-ng 8.x dom0) says 'NTP enabled' / 'NTP synchronized'; newer says
    'NTP service' / 'System clock synchronized'. Both are accepted, and 'active' /
    'inactive' are normalised to yes / no.
    """
    ntp = sync = "Unknown"
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        value = value.strip()
        if label in ("NTP enabled", "NTP service"):
            ntp = value
        elif label in ("NTP synchronized", "System clock synchronized"):
            sync = value
    if ntp == "active":
        ntp = "yes"
    elif ntp == "inactive":
        ntp = "no"
    # 'n/a' is systemd's word for "no NTP service known to me" - an established no
    if ntp == "n/a":
        ntp = "no"
    if sync == "n/a":
        sync = "no"
    return {"ntp": ntp or "Unknown", "sync": sync or "Unknown"}


def round_1dp(value):
    """The one-decimal value the report prints.

    Thresholds are applied to this, not to the full-precision figure, so the number on
    the line and the number that decided the colour can never disagree.
    """
    return float("%.1f" % value)


SKIP_FILESYSTEMS = ("tmpfs", "devtmpfs", "xenstore")


def parse_df(text, max_used):
    """Mount points over max_used%.

    tmpfs/devtmpfs/xenstore are not disks, and /run/sr-mount/* are SRs rather than dom0
    storage - a filling shared SR would otherwise flag every host in the pool for a
    problem that is neither dom0's nor per-host.
    """
    bad = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        fs, _size, _used, _avail, usep, mount = parts
        if fs == "Filesystem":
            continue
        if fs in SKIP_FILESYSTEMS:
            continue
        if mount.startswith("/run/sr-mount/"):
            continue
        if not usep.endswith("%"):
            continue
        digits = usep[:-1]
        if not digits.isdigit():
            continue
        if int(digits) > max_used:
            bad.append("%s is at %s%%" % (mount, digits))
    return bad


_MOUNT_FIELD_ESCAPES = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


def mount_field(field):
    """Undo the octal escaping /proc/mounts and fstab both use: a space in a path is
    written as a backslash and 040."""
    if "\\" not in field:
        return field
    out = []
    i = 0
    while i < len(field):
        if field[i] == "\\" and field[i + 1:i + 4] in _MOUNT_FIELD_ESCAPES:
            out.append(_MOUNT_FIELD_ESCAPES[field[i + 1:i + 4]])
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def mount_table(text):
    """[(source, target, fstype, [options])] for each entry of /proc/mounts or fstab, in
    file order. A target loses a trailing slash, so fstab's '/var/log/' is /proc/mounts'
    '/var/log'; an entry with no options field reads as 'defaults', as mount reads it."""
    rows = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        target = mount_field(parts[1])
        if len(target) > 1:
            target = target.rstrip("/") or "/"
        opts = parts[3].split(",") if len(parts) > 3 else ["defaults"]
        rows.append((mount_field(parts[0]), target, parts[2], opts))
    return rows


def read_only_mounts(proc_text, fstab_text, sr_dirs, extra_targets, native_ro=()):
    """The filesystems that should be writable and are mounted read-only.

    Judged: the root filesystem, which the kernel mounts whatever fstab says; what fstab
    mounts at boot (not swap, not noauto, not asked to be ro); what is mounted from a block
    device under one of sr_dirs (SM's local SRs); and each of extra_targets when mounted
    from a block device. fstab_text None means fstab was not read, and then fstab's half is
    not judged. A type in native_ro (iso9660 and the like) is never judged: the kernel
    mounts it read-only whatever was asked.

    The LAST /proc/mounts entry for a mount point is the one in effect: a mount stacked on
    top of another hides it. Returns None when /proc/mounts has no root filesystem (it
    cannot be the table it claims to be), else [{target, source, type, options, fstab}] in
    /proc/mounts order; 'fstab' holds the options fstab asked for, or None.
    """
    current = {}
    order = []
    for source, target, fstype, opts in mount_table(proc_text):
        if target not in current:
            order.append(target)
        current[target] = (source, fstype, opts)
    if "/" not in current:
        return None
    asked = {}
    root_ro = False
    for _source, target, fstype, opts in mount_table(fstab_text):
        if target == "/" and "ro" in opts:
            root_ro = True
        if fstype == "swap" or not target.startswith("/") or "noauto" in opts or "ro" in opts:
            continue
        asked[target] = ",".join(opts)
    bad = []
    for target in order:
        source, fstype, opts = current[target]
        if fstype in native_ro:
            continue
        block = source.startswith("/dev/")
        judged = target in asked or (target == "/" and not root_ro) or (block and (
            any(target.startswith(d) for d in sr_dirs) or target in extra_targets))
        if judged and "ro" in opts:
            bad.append({"target": target, "source": source, "type": fstype,
                        "options": ",".join(opts), "fstab": asked.get(target)})
    return bad


_LINK_RE = re.compile(r"^\d+:\s+(\S+?):?\s")
_MTU_RE = re.compile(r"\smtu\s+(\d+)\s")


def parse_link_mtus(text):
    """[(ifname, mtu)] from 'ip -o link show', loopback excluded."""
    out = []
    for line in text.splitlines():
        m = _LINK_RE.match(line)
        if not m:
            continue
        name = m.group(1).rstrip(":")
        if name == "lo":
            continue
        mm = _MTU_RE.search(line)
        if not mm:
            continue
        out.append((name, mm.group(1)))
    return out


def parse_ipv4_addrs(text):
    """[(ifname, 'a.b.c.d/len')] from 'ip -o -4 addr show', loopback excluded."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        if name in ("lo", "lo0"):
            continue
        for i, token in enumerate(parts):
            if token == "inet" and i + 1 < len(parts):
                out.append((name, parts[i + 1]))
                break
    return out


def _cidr_range(cidr):
    if "/" not in cidr:
        return None
    ip, plen = cidr.split("/", 1)
    octets = ip.split(".")
    if len(octets) != 4:
        return None
    try:
        value = 0
        for o in octets:
            n = int(o)
            if n < 0 or n > 255:
                return None
            value = value * 256 + n
        bits = int(plen)
    except ValueError:
        return None
    if bits < 0 or bits > 32:
        return None
    size = 1 << (32 - bits)
    net = (value // size) * size
    return (net, net + size - 1)


def has_overlapping_subnets(entries):
    """True when two DIFFERENT interfaces carry overlapping IPv4 ranges.

    Several addresses on one interface are deliberate, not a fault, so same-interface
    pairs are skipped.
    """
    ranges = []
    for name, cidr in entries:
        r = _cidr_range(cidr)
        if r is not None:
            ranges.append((name, r[0], r[1]))
    if len(ranges) < 2:
        return False
    for i in range(len(ranges)):
        for j in range(i + 1, len(ranges)):
            if ranges[i][0] == ranges[j][0]:
                continue
            if not (ranges[i][2] < ranges[j][1] or ranges[j][2] < ranges[i][1]):
                return True
    return False


def parse_ip_addrs(text):
    """[(ifname, address)] from 'ip -o addr show', both families, for telling duplicates.

    Left out: loopback, and link-local in either family (169.254/16, fe80::/10). Those mean
    something only on their own link and dom0 repeats them legitimately: every bridge over
    one NIC carries that NIC's fe80 address, and the host-internal management network has
    the same 169.254/16 address on every host that has it. Addresses come back canonical,
    so two spellings of one IPv6 address are one address. A 'name@parent' interface is
    named without '@'.
    """
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1].rstrip(":").split("@")[0]
        if name in ("lo", "lo0"):
            continue
        for i, token in enumerate(parts):
            if token not in ("inet", "inet6") or i + 1 >= len(parts):
                continue
            addr = ip_literal(parts[i + 1].split("/")[0])
            if addr is None:
                break
            ip = ipaddress.ip_address(addr)
            if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
                out.append((name, addr))
            break
    return out


def duplicate_addresses(entries):
    """[(address, [ifname, ...])] for every address on more than one interface, sorted.

    The same address twice on ONE interface (a /24 and a /32, say) is not counted: it is
    one place, and the question is two places answering for one address."""
    places = {}
    for name, addr in entries:
        names = places.setdefault(addr, [])
        if name not in names:
            names.append(name)
    return sorted((addr, names) for addr, names in places.items() if len(names) > 1)


# --------------------------------------------------------------------------------------
# VMs and VDIs (xe labelled records)
# --------------------------------------------------------------------------------------

def xe_ops(text):
    """The operation names in an xe current-operations field, lower case.

    Read as words, whatever the field prints around them (a set of names, or a map of task
    ref to name), so 'export' is found and 'metadata_export' is not taken for it."""
    return set(re.findall(r"[a-z_]+", (text or "").lower()))


def _xe_map(text):
    """An xe map field as a dict; '<not in database>' and an absent field are both {}."""
    if not text or text.strip() == "<not in database>":
        return {}
    return parse_other_config(text)


def leaf_coalesce_vdis(vdi_text, vbd_text, vm_text, busy_vm_ops, busy_vdi_ops):
    """(disks, busy) for the VDIs whose other-config says leaf-coalesce: false.

    vdi_text is 'xe vdi-list other-config:leaf-coalesce=false', and each record is checked
    again here, so a filter xe ever ignored would show up as disks that do not qualify
    rather than as every disk in the pool. vbd_text is every VBD (None when it was not read,
    which leaves each disk's VMs unnamed), vm_text the VM list with current-operations (None
    when not read: the disk's own operations are still judged, its VMs' are not).

    disks: [{"uuid", "name", "sr", "snapshot", "vms": [(uuid, name)]}], ordered by first VM
    name and then disk name; busy: how many were left out because their VM or the disk
    itself is in one of the busy operations, which is when the flag belongs there.
    """
    vm_ops = {}
    for rec in parse_xe_records(vm_text or ""):
        vm_ops[rec.get("uuid", "")] = xe_ops(rec.get("current-operations"))
    by_vdi = {}
    for rec in parse_xe_records(vbd_text or ""):
        vdi = rec.get("vdi-uuid", "")
        if vdi and vdi != "<not in database>":
            by_vdi.setdefault(vdi, []).append((rec.get("vm-uuid", ""),
                                               rec.get("vm-name-label", "")))
    disks, busy = [], 0
    for rec in parse_xe_records(vdi_text or ""):
        if _xe_map(rec.get("other-config")).get("leaf-coalesce", "").lower() != "false":
            continue
        vms = sorted(by_vdi.get(rec.get("uuid", ""), []), key=lambda v: (v[1].lower(), v[0]))
        if (xe_ops(rec.get("current-operations")) & set(busy_vdi_ops) or
                any(vm_ops.get(u, set()) & set(busy_vm_ops) for u, _n in vms)):
            busy += 1
            continue
        disks.append({"uuid": rec.get("uuid", ""), "name": rec.get("name-label", ""),
                      "sr": rec.get("sr-name-label", ""),
                      "snapshot": rec.get("is-a-snapshot", "") == "true", "vms": vms})
    disks.sort(key=lambda d: ((d["vms"][0][1].lower() if d["vms"] else "￿"),
                              d["name"].lower(), d["uuid"]))
    return disks, busy


# The SR other-config switches SM's GC obeys (SM 1680f106 drivers/cleanup.py): each one,
# set to "false", stops leaf-coalesce on the whole SR - gc stops the GC run outright,
# coalesce stops every coalesce, leaf-coalesce the leaf ones.
GC_SR_SWITCHES = ("gc", "coalesce", "leaf-coalesce")


def leaf_coalesce_srs(sr_text):
    """[(uuid, name, [switch, ...])] of the SRs where GC will leaf-coalesce nothing: their
    own other-config sets one of GC_SR_SWITCHES to false."""
    out = []
    for rec in parse_xe_records(sr_text or ""):
        other = _xe_map(rec.get("other-config"))
        off = [k for k in GC_SR_SWITCHES if other.get(k, "").lower() == "false"]
        if off:
            out.append((rec.get("uuid", ""), rec.get("name-label", ""), off))
    return sorted(out, key=lambda s: (s[1].lower(), s[0]))


def windows_vm_findings(vm_text, keys):
    """(windows, findings) over 'xe vm-list' labelled records.

    A VM is a Windows VM when its guest agent says so (os-version distro 'windows', or a
    name starting 'Microsoft Windows') or when it was made from a Windows template
    (reference-label 'windows-...', or other-config base_template_name 'Windows ...'). A
    VM with no agent made from a non-Windows template cannot be told apart, and is not seen.
    XO replicas (other-config xo:backup:vm) are left out: each carries its source's
    platform, so it would repeat the source's finding.

    findings: [(name, uuid, [problem, ...])] for the ones that fall short:
      - the guest is Windows but the VM was made from a template that is not ('Other
        install media'); a VM whose origin is not recorded is not judged on this
      - a platform key of `keys` not set to true
    """
    windows, findings = 0, []
    for rec in parse_xe_records(vm_text or ""):
        if rec.get("is-control-domain") == "true":
            continue
        other = _xe_map(rec.get("other-config"))
        if "xo:backup:vm" in other:
            continue
        guest = _xe_map(rec.get("os-version"))
        guest_win = (guest.get("distro", "").lower() == "windows" or
                     guest.get("name", "").lower().startswith("microsoft windows"))
        ref = (rec.get("reference-label") or "").strip()
        base = other.get("base_template_name", "").strip()
        template_win = ref.lower().startswith("windows") or base.lower().startswith("windows")
        if not (guest_win or template_win):
            continue
        windows += 1
        problems = []
        # wrong template only on positive evidence: a stock template's reference-label
        # (xapi copies it on clone) that is not a Windows one, or, without a label, the
        # stock 'Other install media' by name. A custom golden template ('WS2022-gold',
        # built from an imported VM) carries no label and its own name - not judged.
        if guest_win and not template_win and (
                ref or base.lower() == "other install media"):
            problems.append("made from the '%s' template, not a Windows one" % (base or ref))
        platform = _xe_map(rec.get("platform"))
        # xapi's own reading of a platform boolean: true or 1 (vm_platform.ml is_true)
        short = [k for k in keys if platform.get(k, "").strip().lower() not in ("true", "1")]
        if short:
            problems.append("platform %s not set to true" % ", ".join(short))
        if problems:
            findings.append((rec.get("name-label", ""), rec.get("uuid", ""), problems))
    findings.sort(key=lambda f: (f[0].lower(), f[1]))
    return windows, findings


# --------------------------------------------------------------------------------------
# multipath
# --------------------------------------------------------------------------------------

# multipathd answers a query it does not understand with rc 0 and its whole help text, so
# rc alone cannot tell a bad query from a good one. This is the tell.
MP_HELP_MARKER = "CLI commands reference"

# multipathd's own placeholders for "this path is in no map": '[orphan]' for a device that
# belongs to none, '[undef]'/'[unknown]' when it cannot say. Every local disk on every host
# comes back as one of these, permanently undef/unknown - judging them would flag every
# host with a boot disk.
def _mp_unmapped(name):
    return not name or name.startswith("[")


def parse_multipath_paths(text):
    """Rows of `multipathd show paths raw format '%m|%d|%D|%t|%T|%o|%p'`.

    Only paths that belong to a map are returned; see _mp_unmapped. A line whose field
    count is wrong is dropped rather than guessed at - which is also what discards the
    help text if some future multipathd rejects the query with rc 0.
    """
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) != 7:
            continue
        if _mp_unmapped(fields[0]):
            continue
        rows.append({"map": fields[0], "dev": fields[1], "dev_t": fields[2],
                     "dm_st": fields[3], "chk_st": fields[4], "dev_st": fields[5],
                     "prio": fields[6]})
    return rows


def parse_multipath_maps(text):
    """Rows of `multipathd show maps raw format '%n|%N|%t|%Q|%x|%0|%f'`.

    `usable` (%N) is the count of paths device-mapper will actually send I/O down, not the
    number configured: failing one of a two-path map took it from 2 to 1 and reinstating
    the path took it back (measured on 8.3.0, 2026-08-27). `path_faults` (%0) is cumulative
    since the map was loaded and does NOT reset on recovery - it stayed 1 after the path
    came back - which is why it is evidence in the detail block and never a finding of its
    own.
    """
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) != 7:
            continue
        rows.append({"name": fields[0], "usable": _int_or_none(fields[1]),
                     "dm_st": fields[2], "queueing": fields[3],
                     "map_failures": _int_or_none(fields[4]),
                     "path_faults": _int_or_none(fields[5]), "features": fields[6]})
    return rows


def parse_dm_multipath_maps(text):
    """Map names from `dmsetup ls --target multipath`.

    With no multipath maps this prints NOTHING AT ALL - empty stdout, empty stderr, rc 0
    (measured on 8.2.1 and 8.3.0). The 'No devices found' line belongs to plain
    `dmsetup ls`, and is dropped here in case a version prints it anyway.
    """
    names = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("no devices found"):
            continue
        names.append(line.split("\t")[0].split()[0])
    return names


def multipathd_alive(text):
    """`multipathd show daemon` says 'pid 1305 running' - or 'idle', which is what newer
    multipath-tools print between checker passes (0.4.9-136 on both dom0s prints running,
    measured 20 of 20). startup/configure/shutdown, or anything else, is not an answer."""
    return bool(re.search(r"\bpid\s+\d+\s+(running|idle)\b", text or ""))


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def classify_multipath_path(row, ok_dm, ok_chk, ok_dev, standby_chk):
    """'ok' | 'standby' | 'bad' for one path row.

    Whitelists on all three states, so a state string this build does not print - a newer
    multipath-tools inventing one - lands in 'bad' and gets looked at, rather than passing
    because it was not on a list of known-bad words.
    """
    chk = row.get("chk_st", "")
    if row.get("dm_st", "") not in ok_dm or row.get("dev_st", "") not in ok_dev:
        return "bad"
    if chk in standby_chk:
        return "standby"
    if chk not in ok_chk:
        return "bad"
    return "ok"


def multipath_summary(path_rows, map_rows, ok_dm, ok_chk, ok_dev, standby_chk):
    """Per-map roll-up of paths and maps, keyed by map name.

    Both sides are used: a map multipathd lists with no path rows is still a map, and a
    path whose map multipathd did not list is still a path. Losing either would understate
    the topology, and the second is exactly what a half-loaded daemon looks like.
    """
    maps = {}

    def slot(name):
        if name not in maps:
            maps[name] = {"name": name, "paths": [], "ok": 0, "standby": 0, "bad": 0,
                          "usable": None, "dm_st": "", "queueing": "",
                          "path_faults": None, "map_failures": None, "listed": False}
        return maps[name]

    for row in map_rows:
        entry = slot(row["name"])
        entry["listed"] = True
        entry["usable"] = row["usable"]
        entry["dm_st"] = row["dm_st"]
        entry["queueing"] = row["queueing"]
        entry["path_faults"] = row["path_faults"]
        entry["map_failures"] = row["map_failures"]

    for row in path_rows:
        entry = slot(row["map"])
        state = classify_multipath_path(row, ok_dm, ok_chk, ok_dev, standby_chk)
        item = dict(row)
        item["state"] = state
        entry["paths"].append(item)
        entry[state] += 1

    order = sorted(maps.values(), key=lambda m: m["name"])
    return {
        "maps": order,
        "total_paths": sum(len(m["paths"]) for m in order),
        "ok_paths": sum(m["ok"] for m in order),
        "standby_paths": sum(m["standby"] for m in order),
        "bad_paths": sum(m["bad"] for m in order),
        # a map with nothing left to send I/O down: the failure this whole check exists
        # for, and worth saying in different words from "one path of four is down"
        "dead_maps": [m["name"] for m in order if (m["ok"] + m["standby"]) == 0],
        "suspended_maps": [m["name"] for m in order
                           if m["dm_st"] and m["dm_st"] != "active"],
    }


def parse_lacp(text):
    """True when any LACP port line is not 'current attached'.

    OVS <= 2.16 (XCP-ng 8.2) writes 'slave: eth0: current attached'; OVS 2.17 (XCP-ng 8.3)
    renamed it to 'member:'. Matching only 'slave:' made every 8.3 host a false green.
    """
    for line in text.splitlines():
        if not re.match(r"^\s*(slave|member):", line):
            continue
        if not line.rstrip().endswith(": current attached"):
            return True
    return False


def parse_pool_conf(text):
    """('master', None) | ('slave', address) | ('broken', None) | (None, None).

    Those three are every role xapi knows (Pool_role in xen-api's pool_role.ml). 'broken'
    is the one a failed master change leaves behind: the would-be master writes it before
    telling the others to commit, and keeps it if any of them fails to. xapi reads
    anything else - an empty file included - as broken too, but (None, None) is kept
    apart from it here, because a caller that could not read the file must not be told
    what the file says.
    """
    # read the way xapi reads it (xen-api v26.1.19 pool_role.ml read_pool_role): the WHOLE
    # file trimmed, split on ':', matched case-sensitively - so 'Master', or a role with a
    # second line under it, is a file xapi starts as broken, not a master
    whole = (text or "").replace("\r", "").strip()
    if not whole:
        return (None, None)
    parts = whole.split(":")
    if parts == ["master"]:
        return ("master", None)
    if parts == ["broken"]:
        return ("broken", None)
    if parts[0] == "slave" and len(parts) > 1:
        # xapi takes the rest verbatim, empty included (a slave of nothing). Whitespace is
        # dropped here as it always was - a pointer xapi might stumble on is still judged
        # by where it points
        return ("slave", re.sub(r"\s+", "", ":".join(parts[1:])))
    return (None, None)


# --------------------------------------------------------------------------------------
# dmesg scanning
# --------------------------------------------------------------------------------------

def _normalise(line):
    return re.sub(r"\s+", " ", line.lower())


def _word_re(word):
    """grep -iw: whole word, case-insensitive. Word characters are [A-Za-z0-9_], and a
    newline is not one, so this anchors at line starts as well as at the string's."""
    return re.compile(r"(^|[^A-Za-z0-9_])" + re.escape(word) + r"([^A-Za-z0-9_]|$)",
                      re.IGNORECASE)


def _ignore_rules(ignore_rules):
    """Each rule as its normalised substrings; an empty rule would match every line."""
    rules = []
    for rule in ignore_rules or ():
        subs = [_normalise(s).strip() for s in rule if s and s.strip()]
        if subs:
            rules.append(subs)
    return rules


def find_mtu_keywords(text, keywords, ignore_rules=()):
    """Whole-word, case-insensitive - and every match is collected, in keyword order.

    Returning on the first hit meant the line could not say WHICH keyword tripped it. A
    line containing ALL substrings of one ignore rule is skipped, as in dmesg_issue_lines:
    "invalid large VPD tag" is a NIC's EEPROM, not a large frame.
    """
    rules = _ignore_rules(ignore_rules)
    word_res = [(kw, _word_re(kw)) for kw in keywords]
    found = set()
    for line in (text or "").splitlines():
        if rules and any(all(sub in _normalise(line) for sub in rule) for rule in rules):
            continue
        for kw, r in word_res:
            if kw not in found and r.search(line):
                found.add(kw)
    return [kw for kw in keywords if kw in found]


def dmesg_issue_lines(text, words, phrases, ignore_rules):
    """1-based line numbers of dmesg lines that look like trouble.

    A line is exempted when it contains ALL substrings of any one ignore rule - the
    megaraid driver's "firmware crash dump : no" is the shipped example of a benign line
    that matches an issue word.
    """
    lowered_words = [w.lower() for w in words if w]
    lowered_phrases = [_normalise(p).strip() for p in phrases if p and p.strip()]
    rules = _ignore_rules(ignore_rules)
    word_res = [_word_re(w) for w in lowered_words]

    hits = []
    for idx, line in enumerate(text.splitlines(), 1):
        norm = _normalise(line)
        if any(all(sub in norm for sub in rule) for rule in rules):
            continue
        if any(p in norm for p in lowered_phrases):
            hits.append(idx)
            continue
        if any(r.search(norm) for r in word_res):
            hits.append(idx)
    return hits


def find_phrase_lines(text, phrase):
    """1-based numbers of the lines containing phrase - case and runs of whitespace
    ignored on both sides, the way every other dmesg match here is made."""
    want = _normalise(phrase).strip()
    return [i for i, line in enumerate(text.splitlines(), 1)
            if want and want in _normalise(line)]


def context_block(text, line_numbers, ctx=3, rollup=False, max_lines=None, rollup_min=3):
    """+/- ctx lines around each hit, overlapping ranges merged, each line indented by 2.

    Merged ranges are separated by a blank line, which is what makes a block with several
    distant hits readable.

    With rollup=True, each merged range is passed through rollup_repeats() first, so a
    range covering thousands of copies of one message prints as that message and a count
    (runs of rollup_min or more). The ranges themselves are unchanged: the rollup is a
    rendering of the same lines, so nothing a hit pointed at is dropped.

    With max_lines set, a rendered block longer than that keeps only its newest max_lines,
    under a line saying how much was cut - see truncate_block for why the rollup alone is
    not enough.
    """
    if not line_numbers:
        return ""
    lines = text.splitlines()
    total = len(lines)
    ranges = sorted((max(1, n - ctx), n + ctx) for n in line_numbers)
    merged = []
    start, end = ranges[0]
    for s, e in ranges[1:]:
        if s <= end + 1:
            end = max(end, e)
        else:
            merged.append((start, end))
            start, end = s, e
    merged.append((start, end))

    out = []
    for i, (s, e) in enumerate(merged):
        e = min(e, total)
        block = ["  " + lines[k - 1] for k in range(s, e + 1)]
        out.extend(rollup_repeats(block, rollup_min) if rollup else block)
        if i != len(merged) - 1:
            out.append("")
    return "\n".join(truncate_block(out, max_lines))


def truncate_block(lines, max_lines):
    """The newest max_lines of a rendered block, under a line saying what was cut.

    The rollup folds a ring full of ONE message. It does nothing for a ring full of
    thousands of DIFFERENT lines: a DRBD volume renegotiating its role every few minutes
    prints a fresh state-change id each time, and one host's block ran to thousands of
    lines and pushed the report itself out of the terminal's scrollback. So the block is
    bounded after rendering, and the newest lines are the ones kept - dmesg is
    chronological, and the current state of the storm is at the bottom. The note carries
    the whole block's size, so the scale of what was cut is still on the page.

    A cut can land inside a range: on its blank separator, or on a '... repeated N times'
    line whose first line was just cut away. Both belong to what came before, so the cut
    moves forward past them rather than leaving an orphan at the top.
    """
    if not max_lines or len(lines) <= max_lines:
        return list(lines)
    kept = lines[-max_lines:]
    while kept and (not kept[0].strip() or kept[0].lstrip().startswith("... repeated ")):
        kept = kept[1:]
    omitted = len(lines) - len(kept)
    note = "  ... %d earlier %s of this block not shown (%d in total; the newest %d follow)" % (
        omitted, "line" if omitted == 1 else "lines", len(lines), len(kept))
    return [note] + kept


# The dmesg ring is a ring: one stuck NFS server or one flapping path writes the SAME line
# thousands of times, and context_block then faithfully prints all of them. A real R630
# pool produced 24,689 dmesg lines across seven hosts that were 22 distinct messages - one
# of them repeated 24,668 times. The repetition is not the finding; the message, how many
# times, and over what window are. How many copies it takes is config.DMESG_ROLLUP_MIN,
# passed in by the checks; the default below mirrors it the way ctx mirrors
# LOG_ERROR_CONTEXT.

_TS_RE = re.compile(r"^(\s*)(\[[^]]*\])\s?(.*)$")


def split_timestamp(line):
    """('  ', '[Mon Jun  1 17:55:16 2026]', 'nfs: server ... timed out') for a dmesg -T
    line; ('', '', line) for anything else.

    Only the leading `dmesg -T` bracket counts. A kernel line may carry brackets of its
    own ("[<ffffffff81234567>]"), but never in front, so anchoring here is enough.
    """
    m = _TS_RE.match(line)
    if not m:
        return ("", "", line)
    return (m.group(1), m.group(2), m.group(3))


def rollup_repeats(lines, threshold=3):
    """Collapse each run of consecutive lines with the same message into one summary.

    Identity is the message with its `dmesg -T` timestamp removed, so lines that differ
    only in when they were printed are one run. Runs are consecutive only: an interleaved
    log keeps its order, and a message that returns after something else is a second run,
    which is what makes "it started again at 18:00" visible.

    A run of `threshold` or more prints its first line, then a count and the span:

        [Mon Jun  1 17:55:16 2026] nfs: server 192.0.2.251 not responding, timed out
        ... repeated 24668 times, through [Mon Jun  1 22:41:03 2026]

    Shorter runs print verbatim - a summary of two lines is longer than the two lines.
    """
    out = []
    i = 0
    n = len(lines)
    while i < n:
        indent, _ts, msg = split_timestamp(lines[i])
        j = i + 1
        while j < n and split_timestamp(lines[j])[2] == msg:
            j += 1
        run = j - i
        out.append(lines[i])
        if run >= threshold:
            first_ts = split_timestamp(lines[i])[1]
            last_ts = split_timestamp(lines[j - 1])[1]
            # a whole run inside one second spans nothing worth printing
            tail = ", through %s" % last_ts if last_ts and last_ts != first_ts else ""
            out.append("%s... repeated %d times%s" % (indent, run, tail))
        else:
            out.extend(lines[i + 1:j])
        i = j
    return out


# --------------------------------------------------------------------------------------
# rpm manifests
# --------------------------------------------------------------------------------------

def manifest_versions(text):
    """{name: 'v1, v2'} - a package NAME is NOT unique in an rpm manifest.

    gpg-pubkey is installed twice on every dom0 here, and a host carries two kernels
    between an update and the reboot that activates it. Keeping one entry per name
    silently dropped all but the last, so a difference confined to a duplicated name
    printed 'Mismatch, See Below' over a block that never mentioned it. Both manifests are
    sorted, so joining each name's versions compares them as an ordered multiset.
    """
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        name, version = line.split(" ", 1)
        if name in out:
            out[name] = out[name] + ", " + version
        else:
            out[name] = version
    return out


def manifest_packages(text):
    """{name: [version, ...]} with each version as a person reads it: the 0: epoch and
    the .arch suffix dropped, so 'kmod-drbd 0:9.2.11-1.xcpng8.3.x86_64' gives
    '9.2.11-1.xcpng8.3'. A list per name because kmod packages can be installed twice."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        name, version = line.split(" ", 1)
        if version.startswith("0:"):
            version = version[2:]
        version = re.sub(r"\.(x86_64|noarch|i686)$", "", version)
        out.setdefault(name, []).append(version)
    return out


def leading_version(text):
    """'9.2.11' out of '9.2.11-1.xcpng8.3', '9.2.11_4.19.0+1' or '9.2.11 (api:2)' -
    the part the module and its rpm both carry, so the two can be compared. An rpm epoch
    ('1:9.2.11-1') is skipped: the module has none, and '1' is not its version."""
    m = re.match(r"\s*(?:\d+:)?(\d+(?:\.\d+)*)", text or "")
    return m.group(1) if m else ""


def manifest_diff(master_text, slave_text):
    """The difference lines, sorted, exactly as the report prints them."""
    master = manifest_versions(master_text)
    slave = manifest_versions(slave_text)
    lines = []
    for name in slave:
        if name not in master:
            lines.append("Extra Package: %s %s" % (name, slave[name]))
        elif slave[name] != master[name]:
            lines.append("Does Not Match Master: %s %s (Master: %s %s)"
                         % (name, slave[name], name, master[name]))
    for name in master:
        if name not in slave:
            lines.append("Missing Package: %s %s" % (name, master[name]))
    lines.sort()
    return lines


_DIFF_KINDS = (
    ("Does Not Match Master:", "version differs", "versions differ"),
    ("Extra Package:", "extra", "extra"),
    ("Missing Package:", "missing", "missing"),
)


def manifest_diff_summary(lines):
    """'2 versions differ, 1 extra, 3 missing' - counted from the full diff before any
    cap, so the status line still gives the true totals when the list below is cut."""
    parts = []
    for prefix, one, many in _DIFF_KINDS:
        n = sum(1 for ln in lines if ln.startswith(prefix))
        if n:
            parts.append("%d %s" % (n, one if n == 1 else many))
    return ", ".join(parts)


def cap_lines(lines, limit, noun):
    """First `limit` lines plus a count of what was left out.

    A silent cut reads as 'these are all of them' when it is not - the same reasoning
    behind the coredump and package-difference caps.
    """
    if limit and len(lines) > limit:
        shown = list(lines[:limit])
        shown.append("(plus %d %s not listed)" % (len(lines) - limit, noun))
        return shown
    return list(lines)


def format_age(seconds):
    """A duration a person can compare at a glance: 3d 4h, 1h 3m, 19m, 45s."""
    seconds = int(seconds)
    if seconds < 0:
        seconds = 0
    if seconds >= 86400:
        return "%dd %dh" % (seconds // 86400, (seconds % 86400) // 3600)
    if seconds >= 3600:
        return "%dh %dm" % (seconds // 3600, (seconds % 3600) // 60)
    if seconds >= 60:
        return "%dm" % (seconds // 60)
    return "%ds" % seconds


# --------------------------------------------------------------------------------------
# XOA plugins
# --------------------------------------------------------------------------------------

# The manifest is node's util.inspect, so its npm map reads
#     'xo-server-audit-premium': '0.15.1',
# The prefix is spelled out here rather than built from config.XO_PLUGIN_PREFIX because a
# module body in the stitched health.py runs before the sibling aliases exist.
_MANIFEST_PKG_RE = re.compile(r"'(xo-server-[A-Za-z0-9._-]+)'\s*:")
_PREMIUM_SUFFIX = "-premium"


def manifest_plugin_names(text):
    """Plugin names out of `xoa-updater raw-api-call getLocalManifest`.

    This is what makes the check self-updating: the manifest is the appliance's own record
    of what Vates offers it on its channel and plan, so a plugin added to XOA after this
    script was written is recognised as Vates' without a code change.

    The registry package name is not the installed directory name - most carry a
    `-premium` suffix that `npm install -g` strips off (`xo-server-audit-premium` lands in
    `/usr/local/lib/node_modules/xo-server-audit`), so the suffix is stripped here and the
    two sides are compared by the plugin name xo-server itself uses.

    A set, possibly empty: the updater being down is not an error here, it just means the
    built-in list is all there is.
    """
    names = set()
    for package in _MANIFEST_PKG_RE.findall(text or ""):
        name = package[len("xo-server-"):]
        if name.endswith(_PREMIUM_SUFFIX):
            name = name[:-len(_PREMIUM_SUFFIX)]
        if name:
            names.add(name)
    return names


def classify_xo_plugins(found, vates_names):
    """Split the plugins found on disk into (vates, third_party), order preserved.

    `found` is scan_plugins()' list of dicts; `vates_names` the union of the manifest and
    the built-in list. Deliberately a whitelist and not a blacklist: an unrecognised name
    is reported, so the failure mode of a stale list is a plugin named for review rather
    than a plugin waved through.
    """
    vates, third_party = [], []
    for plugin in found:
        (vates if plugin["name"] in vates_names else third_party).append(plugin)
    return vates, third_party


def plugin_block(third_party, autoload, autoload_known):
    """The detail block under a `XOA Plugins` finding.

    `autoload` maps plugin name -> bool from xo's own metadata records. It is an
    annotation and nothing more: when it could not be read every plugin says `unknown`
    rather than the block quietly implying they are all inert.
    """
    out = []
    for plugin in third_party:
        version = plugin["version"] or "version unknown"
        if not autoload_known:
            state = "autoload unknown"
        elif plugin["name"] in autoload:
            state = "autoload on" if autoload[plugin["name"]] else "autoload off"
        else:
            state = "never loaded by XO"
        out.append("%s  (%s, %s)" % (plugin["name"], version, state))
        out.append("    %s" % plugin["path"])
        if plugin["link"]:
            out.append("    -> %s" % plugin["link"])
        if plugin.get("why"):
            out.append("    (%s)" % plugin["why"])
    return "\n".join(out)


# --------------------------------------------------------------------------------------
# which of XO's backup jobs move a pool's data, and from where
# --------------------------------------------------------------------------------------
# XO picks the machine that moves a pool's backup traffic per job: a job with a `proxy`
# runs on that XO Proxy, which reaches the hosts itself (xo-server backups-ng/index.mjs
# hands it the pool's credentials and the master's backup-network URL, and deliberately
# not the server's HTTP proxy), and every other job runs on the XOA. So whether the XOA
# needs to reach a pool's backup network is a question about the jobs that touch it.

def xo_pattern_match(pattern, value):
    """value-matcher's match() (xen-orchestra packages/value-matcher) for one plain value.

    That is all a job ever matches a pool id against: a string, or __and / __or / __not
    over strings. An array, or any other object, only ever matches an object, so it is
    False against a plain value - which is how XO evaluates it too. An __and or __or over
    something that is not a list makes XO's own evaluation throw; that raises ValueError
    here, for the caller to read as "cannot tell".
    """
    if isinstance(pattern, list):
        return False
    if isinstance(pattern, dict):
        if len(pattern) == 1:
            key = list(pattern)[0]
            sub = pattern[key]
            if key in ("__and", "__or"):
                if not isinstance(sub, list):
                    raise ValueError("%s is not a list" % key)
                hits = [xo_pattern_match(p, value) for p in sub]
                return all(hits) if key == "__and" else any(hits)
            if key == "__not":
                return not xo_pattern_match(sub, value)
        return False
    return pattern == value


def xo_simple_ids(pattern):
    """The ids of an explicit {id: ...} pattern, or None when it is not one.

    XO's extractIdsFromSimplePattern: {'id': 'x'} or {'id': {'__or': ['x', ...]}}. This is
    how a job lists VMs picked by hand, target SRs, and the pools of a metadata backup.
    """
    if not isinstance(pattern, dict) or list(pattern) != ["id"]:
        return None
    ids = pattern["id"]
    if isinstance(ids, str):
        return [ids]
    if (isinstance(ids, dict) and list(ids) == ["__or"] and isinstance(ids["__or"], list)
            and all(isinstance(i, str) for i in ids["__or"])):
        return list(ids["__or"])
    return None


def job_field(job, key):
    """One field of an XO job record, decoded the way XO decodes it.

    Jobs are stored with every non-string value JSON-encoded (JobsDb._serialize), and read
    back with a JSON.parse that keeps the raw string when it does not parse - which is
    what a plain string such as a proxy id is.
    """
    value = job.get(key)
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return value


def _ids_among(ids, known):
    """True/False against a set of uuids read off the pool; None when that set could not
    be read - unless there was nothing to look for in the first place."""
    if not ids:
        return False
    if known is None:
        return None
    return any(i in known for i in ids)


def job_touches_pool(job, pool_uuid, vm_uuids, sr_uuids, schedule_ids=None):
    """Does this XO job move data to or from this pool? True, False, or None when that
    cannot be told from here.

    A VM backup picks its VMs by uuid, or in smart mode by a pattern over their pool
    ($pool) and their tags; a replication writes into target SRs; a health check restores
    into an SR; a pool metadata backup names pools. Nothing on the XOA says which pool a
    VM or SR uuid lives in, so those are looked up in the pool's own uuids, read by the
    collector - and when those could not be read the answer is None, not a guess. A smart
    job that names no pool covers every pool's VMs: its tags may still leave this pool
    with nothing to back up, which cannot be told without the VMs, so it counts.
    """
    kind = job.get("type")
    if kind == "metadataBackup":
        pools = job_field(job, "pools")
        if pools is None:
            return False            # XO's own metadata only: no pool is read
        ids = xo_simple_ids(pools)
        if ids is None or not pool_uuid:
            return None
        return pool_uuid in ids
    if kind != "backup":
        return False                # a mirror backup copies between remotes

    answers = []
    vms = job_field(job, "vms")
    ids = xo_simple_ids(vms)
    if ids is not None:
        answers.append(_ids_among(ids, vm_uuids))
    elif isinstance(vms, dict):
        # smart mode: VMs matched by a pattern. Definitely this pool only when nothing but
        # the pool (if anything) narrows it; with tags or any other filter, this pool's
        # VMs may all fall outside it - "may touch", which can keep the XOA in the answer
        # but must never take it out (a proxied tag-only job used to read green)
        narrowed = [k for k in vms if k not in ("type", "$pool")]
        if "$pool" in vms:
            if not pool_uuid:
                answers.append(None)
            else:
                try:
                    hit = xo_pattern_match(vms["$pool"], pool_uuid)
                except ValueError:
                    hit = None
                answers.append(None if (hit and narrowed) else hit)
        else:
            answers.append(None if narrowed else True)
    else:
        answers.append(None)

    srs = job_field(job, "srs")
    if srs is not None:
        targets = xo_simple_ids(srs)
        answers.append(None if targets is None else _ids_among(targets, sr_uuids))

    settings = job_field(job, "settings")
    if isinstance(settings, dict):
        # XO restores into job.settings[schedule.id].healthCheckSr, falling back to the
        # job-wide '' entry: a match there is definite only for '' or a schedule that runs;
        # any other entry's is "may"
        for key, entry in settings.items():
            if not (isinstance(entry, dict) and isinstance(entry.get("healthCheckSr"), str)):
                continue
            hit = _ids_among([entry["healthCheckSr"]], sr_uuids)
            definite = key == "" or (schedule_ids is not None and key in schedule_ids)
            answers.append(hit if (hit is not True or definite) else None)

    if True in answers:
        return True
    if None in answers:
        return None
    return False


def backup_runners(jobs, schedules, pool_uuid, vm_uuids, sr_uuids):
    """(does the XOA itself move data for this pool, [ids of the XO Proxies that do]).

    A job counts when one of its schedules is enabled - a job whose every schedule is off
    moves nothing - and every job counts when the schedules could not be read
    (schedules=None). The XOA is the default: with no job touching the pool, what moves
    its data is whatever somebody starts from XOA - an export, a restore - so it is the
    XOA that needs the network.

    Three-valued, and asymmetric on purpose. An XOA-run job that touches the pool, or MAY
    (its reach cannot be told), keeps the XOA in the answer. Only a proxied job KNOWN to
    touch the pool takes it out: an unreadable or may-touch proxied job used to, so a pool
    whose VM list could not be read, or whose only job was a proxied tag-filtered one,
    read green off facts that were never established.
    """
    active = None
    if schedules is not None:
        active = set(s.get("jobId") for s in schedules
                     if s.get("enabled") is True or s.get("enabled") == "true")
        schedule_ids = set(s.get("id") for s in schedules
                           if s.get("enabled") is True or s.get("enabled") == "true")
    else:
        schedule_ids = None
    xoa, proxies = False, []
    for job in jobs:
        if active is not None and job.get("id") not in active:
            continue
        reach = job_touches_pool(job, pool_uuid, vm_uuids, sr_uuids, schedule_ids)
        if reach is False:
            continue
        proxy = job_field(job, "proxy")
        if isinstance(proxy, str) and proxy:
            if reach is True and proxy not in proxies:
                proxies.append(proxy)
        else:
            xoa = True
    return (xoa or not proxies), proxies


def http_proxy_address(url):
    """host[:port] of a server record's httpProxy URL - never the credentials it may
    carry - or '' when there is none. A URL that will not parse is shown as set rather
    than dropped, since it is still what XO routes the pool's traffic through."""
    if not url or not isinstance(url, str):
        return ""
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return "(set, address unreadable)"
    if not host:
        return "(set, address unreadable)"
    if ":" in host:
        host = "[%s]" % host
    return "%s:%d" % (host, port) if port else host


# ======================================================================================
# --- model -----------------------------------------------------------------------------

class Host(object):
    """One pool member: what xapi says about it, plus whatever the collector got."""

    def __init__(self, address, uuid="", hostname="", enabled="Unknown",
                 multipathing="Unknown"):
        self.address = address
        self.uuid = uuid
        self.hostname = hostname
        self.enabled = enabled
        self.multipathing = multipathing
        self.payload = None          # the collector document
        self.error = None            # why there isn't one
        self.local_now = None        # our clock when the document arrived
        self.is_master = False

    # -- naming -------------------------------------------------------------------
    @property
    def reachable(self):
        return self.payload is not None

    @property
    def label(self):
        return "%s (%s)" % (self.name, self.address)

    @property
    def name(self):
        if self.payload:
            f = self.fact("hostname")
            if f.ok and f.value:
                return f.value
        return self.hostname or self.address

    # -- facts --------------------------------------------------------------------
    def fact(self, key):
        if self.payload is None:
            return result.Fact(False, error="host was not collected")
        return result.wrap(self.payload, key)

    def memory(self):
        """(total_mb, used_mb) or None. None is a first-class answer, not a zero."""
        f = self.fact("meminfo")
        if not f.ok:
            return None
        parsed = parsers.parse_meminfo(f.value)
        if parsed is None:
            return None
        total_mb, avail_mb = parsed
        used_mb = total_mb - avail_mb if total_mb >= avail_mb else 0
        return (total_mb, used_mb)

    def mem_total_mb(self):
        """MemTotal in MiB, or None. Only MemTotal: comparing dom0 sizes across hosts needs
        nothing else, and memory() would also demand MemAvailable."""
        f = self.fact("meminfo")
        if not f.ok:
            return None
        return parsers.parse_mem_total_mb(f.value)

    def ntp_state(self):
        """{"ntp", "sync"} as timedatectl says them, plus "error" when it could not be read -
        the reason travels with the Unknown rather than being dropped here."""
        f = self.fact("timedatectl")
        if not f.ok:
            return {"ntp": "Unknown", "sync": "Unknown", "error": f.error}
        return parsers.parse_timedatectl(f.value)

    def clock_drift(self):
        """Seconds between this host's clock and ours, or None if unknown.

        Our reference time is taken per host, right when its document arrives, so
        transport latency to earlier hosts cannot accumulate into fake drift.
        """
        f = self.fact("now")
        if not f.ok or self.local_now is None:
            return None
        return abs(self.local_now - f.value)

    def pool_role(self):
        """('master', None) | ('slave', address) | ('broken', None) | (None, None) - the
        last for a file that could not be read or that xapi itself would read as broken."""
        f = self.fact("pool_conf")
        if not f.ok:
            return (None, None)
        return parsers.parse_pool_conf(f.value)

    def pool_conf_text(self):
        f = self.fact("pool_conf")
        return f.value if f.ok else "(unavailable)"


class Pool(object):
    """The pool-level document, gathered from POOL_CMD_HOST."""

    def __init__(self):
        self.payload = {}
        self.error = None

    def fact(self, key):
        node = self.payload.get(key)
        if node is None:
            if self.payload.get("ok") is False and self.payload.get("error"):
                # the whole pool collection failed: every pool fact carries its reason
                return result.Fact(False, error=self.payload["error"])
            return result.Fact(False, error="not collected")
        return result.wrap(self.payload, key)

    def networks(self):
        return self.payload.get("networks") or {}

    def xostor_in_use(self):
        f = self.fact("xostor_srs")
        return bool(f.ok and f.value)


# ======================================================================================
# --- collectorsrc ----------------------------------------------------------------------

EMBEDDED = None   # set by build/stitch.py in the published health.py


def collector_source():
    if EMBEDDED is not None:
        return EMBEDDED
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "collector.py")
    f = open(path, "rb")
    try:
        return f.read().decode("utf-8")
    finally:
        f.close()


EMBEDDED = r'''# -*- coding: utf-8 -*-
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
import signal
import subprocess
import sys
import threading
import time
from xml.etree import ElementTree

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


_TEXT = type(u"")


def _arg_text(arg):
    """One argv element as text. str() would ASCII-encode a 2.7 unicode argument - a mount
    point with an accented name - and raise."""
    if isinstance(arg, _TEXT):
        return arg
    if isinstance(arg, bytes):
        return arg.decode("utf-8", "replace")
    return str(arg)


def _argv_text(argv):
    """Enough of an argv to identify it, on one line.

    The argv rather than a description of it, so the command can be pasted straight into a
    shell on the host. Whitespace is collapsed because rpm's --qf formats carry literal
    newlines, and a long one is elided in the MIDDLE rather than the tail: the path is at
    the end, and "a grep took 90 seconds" is not an answer without the file it was reading.
    """
    text = " ".join(" ".join(_arg_text(arg).split()) for arg in argv)
    if len(text) > 110:
        text = text[:60] + " ... " + text[-45:]
    return text


def _mono():
    """Seconds on a clock nothing can step. The run budget is measured on it: chronyd or
    an admin correcting the wall clock mid-run - on exactly the hosts the NTP lines are
    about - would otherwise make the budget jump, refusing every later command at once or
    outliving the transport's own timeout. time.monotonic on 3.3+; on 2.7 the kernel's
    uptime, which is the same clock."""
    if hasattr(time, "monotonic"):
        return time.monotonic()
    try:
        f = open("/proc/uptime", "rb")
        try:
            return float(f.read().split()[0])
        finally:
            f.close()
    except (IOError, OSError, ValueError, IndexError):
        return time.time()


def timed(argv, started):
    """Record one command's elapsed seconds, with enough argv to identify it. `started`
    is a _mono() reading."""
    TIMINGS.append([round(_mono() - started, 2), _argv_text(argv)])


def budget_left():
    if DEADLINE[0] is None:
        return None
    return DEADLINE[0] - _mono()


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
        if self.rc is None:
            # never started - see xe() - so there is no exit status, only the reason
            return self.err
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


# Every child running right now, so a SIGTERM to the collector can take them with it: each
# is in its own session (setsid), so nothing else would. A dict used as a set, guarded by
# its lock - run() threads and the signal handler both touch it.
LIVE = {}
LIVE_LOCK = threading.Lock()


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
            # front of a pipeline - the same reason bash used 'timeout -k 5'. On 3.x the
            # setsid happens in C: preexec_fn runs Python between fork and exec, which is
            # not safe in a process that always has other threads (the watchdog)
            if sys.version_info[0] >= 3:
                kwargs["start_new_session"] = True
            else:
                kwargs["preexec_fn"] = os.setsid
        if os.name == "posix":
            # bytes, so an argument that is not ASCII (an accented mount point) reaches
            # exec whatever the locale: 2.7 would encode unicode as ASCII and raise, and
            # 3.6 under LANG=C encodes with the ascii filesystem codec and raises too
            argv = [a.encode("utf-8") if isinstance(a, _TEXT) else a for a in argv]
        proc = subprocess.Popen(argv, **kwargs)
        with LIVE_LOCK:
            LIVE[proc.pid] = proc
        return proc, devnull
    except Exception:
        devnull.close()
        raise


def _forget(proc):
    with LIVE_LOCK:
        LIVE.pop(proc.pid, None)


def _kill(proc):
    """SIGKILL the child's process group. True when the signal was delivered (or the group
    is already gone); False when it could not be sent, so run() does not blame the host's
    storage for a kill that never happened. setsid made the child its group's leader, so
    its pid is the group id."""
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, 9)
        else:
            proc.kill()
        return True
    except OSError as exc:
        return exc.errno == errno.ESRCH


def kill_live_children():
    """Every running child's group, SIGKILLed - for the SIGTERM/SIGHUP handler."""
    with LIVE_LOCK:
        procs = list(LIVE.values())
    for proc in procs:
        _kill(proc)


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
    started = _mono()
    timeout = _clamp(timeout)
    if timeout is None:
        timed(argv, started)
        # never started, so no exit status: rc None is why()'s "say the reason" shape, and
        # "timed out" would claim the command ran and hung
        return Ran(None, "", "not run - the run budget was used up", False)
    try:
        proc, devnull = _popen(argv)
    except (OSError, ValueError) as exc:
        # ValueError: an argument Popen could not encode (UnicodeEncodeError is one)
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
    delivered = True
    if killed:
        delivered = _kill(proc)
        worker.join(KILL_GRACE)      # a killable child dies here and the thread ends

    abandoned = worker.is_alive()
    timed(argv, started)
    CURRENT[0] = ""
    devnull.close()

    if abandoned:
        ABANDONED.append(_argv_text(argv))
        if not delivered:
            return Ran(124, "", "timed out, and the kill could not be sent", True)
        return Ran(124, "", "did not die when killed - uninterruptible, so the host's "
                            "storage or a mount is most likely wedged", True)
    _forget(proc)
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


# The first xe call xapi let run out its whole timeout, once one has. A one-element list
# for the same reason as CURRENT: written without a `global` statement.
XAPI_WEDGED = [""]


def xe(args, timeout=DEFAULT_CMD_TIMEOUT, canary=True):
    """One xe command - or, once xapi has sat on one until it timed out, not.

    A wedged xapi accepts the connection and never answers, so every call waits out its
    whole timeout: 60s apiece, a dozen of them on the host the pool questions ride on,
    and the host spends its entire run budget learning the same thing again. The calls
    after the first are therefore not made, and each fact says why rather than waiting to.

    A timeout only counts when it was the call's own. One the run budget cut short says
    the budget is gone, not that xapi is, and run() already answers every later call with
    exactly that. A refused connection does not count either: it fails in milliseconds,
    so every call can go on reporting its own reason, which is the more useful answer.

    canary=False is for the listings whose size grows with the pool (every VM, VDI, VBD,
    task): one of them taking its whole timeout on a big, busy pool says the pool is big,
    not that xapi is wedged, and must not cost every later question its answer.
    """
    if XAPI_WEDGED[0]:
        return Ran(None, "", "not asked - xapi did not answer %s" % XAPI_WEDGED[0], False)
    full = _clamp(timeout) == timeout
    r = run(["xe"] + list(args), timeout=timeout)
    if canary and r.timed_out and full:
        XAPI_WEDGED[0] = "'xe %s' within %ds" % (args[0], timeout)
    return r


def read_bounded(path, timeout=2.0, limit=None):
    """read_file on a thread given up after `timeout`: (text or None, answered).

    For the /proc files of a process in D state that take THAT process's locks - io and
    stack take its cred_guard_mutex, which execve holds while it opens the binary, and
    cmdline takes its mmap_sem (linux 4.19 fs/proc/base.c) - so a process exec'ing off a
    dead mount blocks a plain read of them, with no timeout, on the very host this is
    diagnosing. A read that does not answer is left behind on its daemon thread.
    """
    box = {}

    def reader():
        box["text"] = read_file(path) if limit is None else read_file(path, limit)

    worker = threading.Thread(target=reader)
    worker.daemon = True
    CURRENT[0] = "read " + path
    worker.start()
    worker.join(timeout)
    CURRENT[0] = ""
    if worker.is_alive():
        ABANDONED.append("read " + path)
        return None, False
    return box.get("text"), True


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
    name = short_hostname()
    # an empty name is "could not tell", not a host called ""
    out["hostname"] = fact(name) if name else err("hostname answered nothing")
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


# xapi's whole database, as it last saved it. Every member has one: a master writes its
# own, and a slave holds the copy its master last sent it - on the lab's two-host 8.3 pool
# the slave's was seconds older than the master's. Same path and format on 8.2.1 and 8.3.0.
STATE_DB = "/var/lib/xcp/state.db"


def parse_state_db_hosts(data):
    """(rows, None) from a state.db's bytes, or (None, why). Rows are the host table's
    uuid, name-label, hostname and address.

    The file is one line of XML, 0.7-1.8 MB on the lab pools and a great deal more on a
    big one, and only the host table is wanted - so that table is cut out by its markers
    and nothing else is parsed. That is exact as well as cheap: '<' cannot appear
    unescaped inside an attribute value, so the first '</table>' after the table opens is
    where it closes, whatever the rows hold. What is cut out goes through a real XML
    parser, so escaped names come back as the names they are.

    Bytes rather than text: 2.7's ElementTree will not take a unicode string holding
    anything outside ASCII, and a host's name-label may well.
    """
    start = data.find(b'<table name="host">')
    if start < 0:
        return None, "it has no host table"
    end = data.find(b"</table>", start)
    if end < 0:
        return None, "its host table never closes"
    try:
        table = ElementTree.fromstring(data[start:end + len(b"</table>")])
    except SyntaxError as exc:
        # ElementTree.ParseError is a SyntaxError on 2.7 and 3.x alike, and this is the
        # one thing fromstring raises for a fragment it cannot read
        return None, "its host table does not parse (%s)" % exc
    rows = []
    for row in table.findall("row"):
        uuid = row.get("uuid") or ""
        if not uuid:
            continue
        rows.append({"uuid": uuid,
                     "name_label": row.get("name__label") or "",
                     "hostname": row.get("hostname") or "",
                     "address": row.get("address") or ""})
    if not rows:
        return None, "its host table has no hosts in it"
    return rows, None


def collect_state_db_hosts():
    """The pool's members from xapi's database FILE, for when xapi will not answer.

    The file answers with the toolstack dead on every host, which is exactly what a failed
    master change leaves behind - and the report is then about hosts it can still ssh to,
    rather than nothing at all. What it cannot say is whether the copy is current, so the
    time it was last written travels with it, rendered here in the host's own clock.
    """
    try:
        f = open(STATE_DB, "rb")
    except (IOError, OSError) as exc:
        return err("could not read %s (%s)" % (STATE_DB, exc.strerror or exc))
    try:
        data = f.read()
        mtime = os.fstat(f.fileno()).st_mtime
    except (IOError, OSError) as exc:
        return err("could not read %s (%s)" % (STATE_DB, exc.strerror or exc))
    finally:
        f.close()
    rows, why = parse_state_db_hosts(data)
    if rows is None:
        return err("could not read the pool's hosts from %s: %s" % (STATE_DB, why))
    return fact({"path": STATE_DB, "hosts": rows,
                 "saved": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))})


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


# Filesystems df leaves out by default (no blocks, or not storage at all). tmpfs and
# devtmpfs stay in, as df shows them; the report skips them by name.
DF_PSEUDO = set(["proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs",
                 "tracefs", "pstore", "mqueue", "hugetlbfs", "configfs", "fusectl",
                 "binfmt_misc", "autofs", "rpc_pipefs", "nfsd", "bpf", "rootfs",
                 "selinuxfs", "xenfs", "efivarfs"])


def collect_df(network_types=None):
    """Every local filesystem's usage in df's own layout - without running df.

    df statfs()es every mount, network SRs included, and coreutils 8.22 also stat()s every
    mount point to tell duplicates apart - even under -l (measured on 8.3: three calls on
    /run/sr-mount NFS paths). A mount whose server has gone parks it in D state for good:
    the line is lost to a timeout, and every run leaves one more unkillable df that the
    next run counts as a stuck process. Network mounts are Network Mounts' business, which
    probes them deliberately and names the dead one. So this reads /proc/mounts - kernel
    memory, never blocking - and statvfs()es local filesystems only, whose counters are in
    memory too.

    Use% is df's own arithmetic: used / (used + available to non-root), rounded up. A
    local mount that cannot be read is listed in "failed" - not left out, which would read
    as a filesystem with room on it.
    """
    text = read_file("/proc/mounts")
    if text is None:
        return err("could not read /proc/mounts")
    network = set(network_types or [])
    rows, failed, by_dev = [], [], {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        source, target, fstype = parts[0], _unescape_mount(parts[1]), parts[2]
        if fstype in network or fstype in DF_PSEUDO or fstype.startswith("fuse"):
            continue
        if target.startswith("/run/sr-mount/") or target.startswith("/var/run/sr-mount/"):
            continue                      # SRs: storage, not dom0's (and the report agrees)
        try:
            st = os.statvfs(target)
            dev = os.stat(target).st_dev
        except OSError as exc:
            failed.append("%s (%s)" % (target, exc.strerror or exc))
            continue
        if not st.f_blocks:
            continue
        unit = float(st.f_frsize or st.f_bsize or 1024) / 1024
        used = st.f_blocks - st.f_bfree
        total = used + st.f_bavail
        pct = "-" if total <= 0 else "%d%%" % ((used * 100 + total - 1) // total)
        row = [source, int(st.f_blocks * unit), int(used * unit), int(st.f_bavail * unit),
               pct, target]
        # one filesystem mounted twice (a bind mount) is one row, under its shortest path
        # - df's own rule - so a full disk is not reported twice
        if dev in by_dev:
            index = by_dev[dev]
            if len(target) < len(rows[index][5]):
                rows[index] = row
            continue
        by_dev[dev] = len(rows)
        rows.append(row)
    lines = ["Filesystem 1K-blocks Used Available Use% Mounted on"]
    lines.extend("%s %d %d %d %s %s" % tuple(row) for row in rows)
    return fact({"text": "\n".join(lines) + "\n", "failed": failed})


def collect_failed_units():
    """systemctl's own list of failed units. rc 0 with no line is a real 'none'; a
    systemctl that fails is an error, never an empty list."""
    r = run(["systemctl", "--failed", "--no-legend", "--plain"], timeout=20)
    if not r.ok:
        return err("systemctl --failed failed (%s)" % r.why())
    return fact(r.out)


STATIC_VDIS_DIR = "/etc/xensource/static-vdis"
STATIC_VDIS_UNIT = "attach-static-vdis.service"


def collect_static_vdis():
    """When attach-static-vdis last exited, and when each entry it attaches was created.

    Before xen-api ae4d3ec4 (2026-08-03) its script loops over the directory without
    nullglob, so on an EMPTY directory - a host booted while HA was off, as a rolling pool
    reboot leaves it - it tries to attach a VDI with no uuid and fails, about nothing. Telling
    that apart from a statefile that really did not attach needs the two times: the exit as
    microseconds of uptime (no wall-clock string, so no timezone to parse), and each entry's
    vdi-uuid file mtime, which 'static-vdis add' writes once - the entry directory's own
    mtime moves whenever its disk link is made or removed. Dot names are skipped, as the
    script's glob skips them.
    """
    r = run(["systemctl", "show", STATIC_VDIS_UNIT, "-p", "ExecMainExitTimestampMonotonic"],
            timeout=20)
    if not r.ok:
        return err("systemctl show %s failed (%s)" % (STATIC_VDIS_UNIT, r.why()))
    m = re.search(r"^ExecMainExitTimestampMonotonic=(\d+)\s*$", r.out, re.M)
    if not m:
        return err("systemctl show %s gave no ExecMainExitTimestampMonotonic" % STATIC_VDIS_UNIT)
    entries = []
    if os.path.isdir(STATIC_VDIS_DIR):
        try:
            names = sorted(n for n in os.listdir(STATIC_VDIS_DIR) if not n.startswith("."))
        except OSError as exc:
            return err("could not list %s (%s)" % (STATIC_VDIS_DIR, exc))
        for name in names:
            try:
                created = os.stat(os.path.join(STATIC_VDIS_DIR, name, "vdi-uuid")).st_mtime
            except OSError:
                created = None
            entries.append({"name": name, "created": created})
    return fact({"exit_mono_us": int(m.group(1)), "entries": entries})


def collect_text_file(path):
    """A small file shipped whole, as text, to be judged on the other side.

    /proc/mounts is the kernel's own mount table, so reading it cannot block on a mount
    that has stopped answering; /etc/fstab is a plain file on the root filesystem.
    """
    text = read_file(path)
    if text is None:
        return err("could not read %s" % path)
    return fact(text)


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

    Read on a bounded thread: io takes the process's cred_guard_mutex, which a process
    exec'ing off a dead mount holds. One that does not answer reads as a fixed text, so
    two samples of it compare equal and the CPU figure decides - and a process whose io
    cannot be read is itself evidence of where it is stuck.
    """
    text, answered = read_bounded("/proc/%d/io" % pid)
    if not answered:
        return "(io not readable)"
    return text or ""


# PF_KTHREAD from include/linux/sched.h (4.19): the kernel's own word on what a kernel
# thread is. An empty cmdline is not the same thing - a userspace task that has already
# released its memory (stuck in exit on a dead mount, after a kill -9) has one too.
PF_KTHREAD = 0x00200000


def proc_flags(text):
    """The flags field (9th) of one /proc/PID/stat, or None."""
    close = (text or "").rfind(")")
    if close < 0:
        return None
    rest = text[close + 1:].split()
    try:
        return int(rest[6])
    except (IndexError, ValueError):
        return None


def proc_comm(text):
    """The comm field of /proc/PID/stat - the name between the parentheses."""
    text = text or ""
    start, close = text.find("("), text.rfind(")")
    return text[start + 1:close] if 0 <= start < close else ""


def _d_state_procs(pids=None):
    """{pid: (starttime, cpu_ticks, io)} for the processes in uninterruptible sleep now.

    /proc/PID/stat is served out of kernel memory without taking the process's locks, so
    the scan itself cannot block on the very mount being investigated - which is the whole
    reason this is the primary signal rather than stat()ing mount points and seeing what
    hangs. io is the exception, and is read on a bounded thread (see _proc_io).

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
    """The command line, or "" when it is empty or could not be read.

    NUL-separated, and deliberately not /proc/PID/cmdline's neighbours cwd/exe/root: those
    are symlinks INTO the filesystem, so resolving one belonging to a process stuck on a
    dead mount blocks this collector in exactly the way it is here to detect. cmdline
    itself takes the process's mmap_sem, so it is read on a bounded thread too.
    """
    raw, _answered = read_bounded("/proc/%d/cmdline" % pid)
    if not raw:
        return ""
    return " ".join(part for part in raw.split("\0") if part).strip()


# argv prefixes of the commands this collector runs that can be left parked in D state by
# a run - abandoned when their SIGKILL did not take. A later run names them as this tool's
# own leavings, the way it names the mount probe, rather than counting one more foreign
# stuck process per run.
# Each is anchored on the exact argv the collector builds (cmdline is NUL-separated, read
# back space-joined), so an admin's own `sed -n` or `rpm -qa` is never taken for ours.
OWN_COMMANDS = [re.compile(p) for p in (
    r"^df -hP$",
    r"^pvs --noheadings --separator \| -o pv_name,vg_name,pv_attr,pv_uuid$",
    r"^tap-ctl list$",
    r"^multipathd show (daemon|maps raw format|paths raw format) ",
    r"^multipathd show daemon$",
    r"^dmsetup ls --target multipath$",
    r"^grep -ainF -e .* -- /var/log/",
    r"^grep -ai hidden leaf /var/log/SMlog$",
    r"^sed -n \d+,\d+p;\d+q /var/log/",
    r"^yum (--setopt=exit_on_lock=1 )?check-update -q$",
    r"^rpm -qa? --qf ",
    r"^ovs-appctl lacp/show$",
    r"^dmesg -T$",
)]


def _own_command(cmd):
    return bool(cmd) and (MOUNT_PROBE_MARK in cmd or any(p.match(cmd) for p in OWN_COMMANDS))


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
        # stack takes the process's cred_guard_mutex, so bounded like io and cmdline
        stack, _answered = read_bounded("/proc/%d/stack" % pid)
        stack = stack or ""
        stat = read_file("/proc/%d/stat" % pid) or ""
        flags = proc_flags(stat)
        cmd = _proc_cmdline(pid)[:120]
        rows.append({
            "pid": pid,
            "age": int(now - (seen[0] / ticks)),
            "cmd": cmd,
            "comm": proc_comm(stat)[:40],
            # None when the flags could not be read: the report then falls back to the
            # empty-cmdline reading, saying which it used
            "kernel": (bool(flags & PF_KTHREAD) if flags is not None else None),
            "own": _own_command(cmd),
            "module": fs_module_of(stack),
            "frame": (stack.splitlines() or [""])[0].strip()[:120],
        })
    rows.sort(key=lambda row: row["age"], reverse=True)
    # counted here, over ALL of them, because the cap below is what the report sees: a
    # tally taken from the sample would be printed as if it described the whole, and on
    # the host this was built for that is 24 of 25 shown being reported as 24 of 589
    return fact({"total": len(rows),
                 "userspace": len([row for row in rows
                                   if not (row["kernel"] if row["kernel"] is not None
                                           else not row["cmd"])]),
                 # the script's own leavings from earlier runs, counted rather than hidden:
                 # they really are stuck, and they really were left by this tool
                 "own_probes": len([row for row in rows if row["own"]]),
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
            started = _mono()
            r = run(["stat", "-c", MOUNT_PROBE_MARK + " %i", "--", target],
                    timeout=timeout)
            row["seconds"] = round(_mono() - started, 2)
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
    """Both families: Overlapping Subnets reads the inet lines, Duplicate IPs all of them."""
    r = run(["ip", "-o", "addr", "show"], timeout=20)
    if not r.ok:
        return err("ip addr show failed (%s)" % r.why())
    return fact(r.out)


def collect_lacp():
    """ovs-appctl answers rc 0 with empty output when there are simply no LACP bonds,
    and rc != 0 when it cannot reach ovs-vswitchd at all. Those are different facts."""
    r = run(["ovs-appctl", "lacp/show"], timeout=30)
    if not r.ok:
        # ovs-vswitchd down, ovs-appctl missing, the control socket refusing: why() says
        # which, rather than one sentence for all of them
        return err("could not query Open vSwitch (%s)" % r.why())
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


def collect_crash_dumps(ignore_name, root="/var/crash"):
    """Files under /var/crash, two levels deep - crash dumps live in subdirectories.

    The newest mtime comes back with the count, so the report can say whether the dumps
    are from last night or from a crash someone already dealt with a year ago."""
    count = 0
    latest = None
    if not os.path.isdir(root):
        return fact({"count": 0, "latest": None})

    def counted(path):
        try:
            st = os.stat(path)
        except OSError:
            return 0, None
        if not os.path.isfile(path):
            return 0, None
        return 1, st.st_mtime

    try:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                if name != ignore_name:
                    n, mtime = counted(path)
                    count += n
                    if mtime is not None and (latest is None or mtime > latest):
                        latest = mtime
                continue
            if os.path.isdir(path):
                try:
                    for sub in os.listdir(path):
                        if sub == ignore_name:
                            continue
                        n, mtime = counted(os.path.join(path, sub))
                        count += n
                        if mtime is not None and (latest is None or mtime > latest):
                            latest = mtime
                except OSError:
                    return err("could not list %s" % path)
    except OSError as exc:
        return err("could not list %s (%s)" % (root, exc))
    if latest is not None:
        latest = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(latest))
    return fact({"count": count, "latest": latest})


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


TASK_TIMEOUT_CONF = "/etc/xapi.conf"
TASK_TIMEOUT_CONF_DIR = "/etc/xapi.conf.d"
_TASK_TIMEOUT_RE = re.compile(r"^\s*pending_task_timeout[ \t]*=[ \t]*(.*)$")


def task_timeout_values(text):
    """The pending_task_timeout settings in one xapi config file, read the way xapi
    reads it (xen-api v26.1.19 xcp_service.ml Config_file): everything from the first '#'
    is a comment - inline ones too - trailing whitespace goes, and one pair of surrounding
    quotes is stripped. A commented-out setting cannot match: the key has to start the
    line once the comment is gone.
    """
    values = []
    for line in text.replace("\r", "").split("\n"):
        m = _TASK_TIMEOUT_RE.match(line.split("#", 1)[0].rstrip())
        if not m:
            continue
        value = m.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value:
            values.append(value)
    return values


def collect_task_timeout_override():
    """Every pending_task_timeout xapi will read on this host, in the order it reads them -
    /etc/xapi.conf, then every entry of /etc/xapi.conf.d sorted, dot-files included
    (xen-api read_config_file parses everything Sys.readdir returns); the last one wins.

    A value from /etc/xapi.conf itself is labelled with that file: XCP-ng ships the line
    there commented out, so an uncommented one is an edit of the shipped file rather than
    a drop-in. No directory and no matching line are both real answers ('no override'),
    which is why they return an empty list rather than an error - but a file or directory
    we cannot read is NOT, and says so, because 'no override found' would be a claim we
    did not establish.
    """
    values = []
    if os.path.exists(TASK_TIMEOUT_CONF):
        text = read_file(TASK_TIMEOUT_CONF)
        if text is None:
            return err("could not read %s" % TASK_TIMEOUT_CONF)
        values.extend("%s (in %s)" % (v, TASK_TIMEOUT_CONF) for v in task_timeout_values(text))
    if not os.path.isdir(TASK_TIMEOUT_CONF_DIR):
        return fact(values)
    try:
        names = sorted(os.listdir(TASK_TIMEOUT_CONF_DIR))
    except OSError as exc:
        return err("could not list %s (%s)" % (TASK_TIMEOUT_CONF_DIR, exc))
    for name in names:
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
    return fact(dedupe_hidden_leaves(r.out))


def dedupe_hidden_leaves(text):
    """One line per hidden leaf, the latest, with how often SM logged it.

    Every SMlog line carries its timestamp and [pid][thread], so de-duplicating whole lines
    never collapsed anything: a leaf that stays hidden is logged by every scan of its SR,
    all day ("Scan found hidden leaf (<vdi>), ignoring" - SM 1680f106 LVMSR/FileSR). Keyed
    on the uuid in the parentheses, else on the text after the [pid][thread] prefix.
    """
    order, last, count = [], {}, {}
    for line in (text or "").splitlines():
        m = re.search(r"hidden leaf \(([^)]+)\)", line, re.I)
        if m:
            key = m.group(1)
        else:
            key = re.sub(r"^.*?SM: (\[[^\]]*\])*\s*", "", line)
        if key not in last:
            order.append(key)
        last[key] = line
        count[key] = count.get(key, 0) + 1
    return [last[k] + ("   (logged %d times)" % count[k] if count[k] > 1 else "")
            for k in order]


def collect_rpm_manifest():
    """sshpass is filtered out on every host: older builds installed it on the host a host
    mode sweep ran from, and the hosts that have it still differ from the ones that do not
    - otherwise the script reports its own footprint as pool drift."""
    r = run(["rpm", "-qa", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"],
            timeout=90)
    if not r.ok:
        return err("rpm -qa failed (%s)" % r.why())
    lines = [ln for ln in r.out.splitlines() if ln.strip() and not ln.startswith("sshpass ")]
    lines.sort()
    return fact("\n".join(lines))


def collect_drbd_module():
    """The DRBD kernel module's own version, which is what is actually running - the
    kmod-drbd rpm can be updated underneath it and stays inert until the next reboot.
    '' means the module is not loaded, which is an answer, not a failure to look."""
    if not os.path.isdir("/sys/module/drbd"):
        return fact("")
    text = read_file("/sys/module/drbd/version")
    if text is None or not text.strip():
        return err("could not read /sys/module/drbd/version")
    return fact(text.strip())


PVS_TIMEOUT = 30


def collect_pvs():
    """Every LVM physical volume this host's LVM knows of, one '|'-separated row each
    (name, VG, attr, uuid), and pvs's own warnings beside them.

    Collected on every host whether or not XOSTOR is in use - which hosts that applies to
    is a pool fact the collector does not have yet - and judged report-side. A PV that has
    gone away still has a row, read out of the VG metadata on the PVs that remain, named
    '[unknown]' with an 'm' in its attr, and its uuid; stderr says which uuid could not be
    found. pvs may exit non-zero over exactly that, so rows are the test of
    whether it answered, not the exit code.
    """
    if which("pvs") is None:
        return err("pvs not found")
    r = run(["pvs", "--noheadings", "--separator", "|",
             "-o", "pv_name,vg_name,pv_attr,pv_uuid"], timeout=PVS_TIMEOUT)
    if r.timed_out:
        return err("pvs timed out")
    if not r.ok and not r.out.strip():
        return err("pvs failed (%s)" % r.why())
    return fact({"rows": r.out, "warnings": r.err})


LVM_BACKUP_DIR = "/etc/lvm/backup"


def collect_lvm_backup(vg):
    """The physical_volumes section of LVM's own metadata backup for one VG.

    LVM rewrites /etc/lvm/backup/<vg> on every metadata change, so it is the list of PVs
    the VG is meant to have - and it survives the case pvs cannot speak to: when every
    disk of the VG is gone there is no metadata left to read, the VG vanishes from pvs,
    and only this file still says it existed. None means no backup file, which on a
    diskless node is the expected answer. Only the PV section is sent; the LV section of a
    busy XOSTOR VG runs to thousands of lines and is not asked about.
    """
    if not vg or "/" in vg:
        return err("bad volume group name %r" % vg)
    path = os.path.join(LVM_BACKUP_DIR, vg)
    if not os.path.exists(path):
        return fact(None)
    text = read_file(path)
    if text is None:
        return err("could not read %s" % path)
    return fact(lvm_section(text, "physical_volumes"))


def lvm_section(text, name):
    """The '<name> { ... }' block of an LVM metadata file, braces included; '' if absent.
    Depth is counted on braces outside quotes - device paths and tags never hold one, but
    a description string could."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(name) and line.rstrip().endswith("{"):
            depth = 0
            for j in range(i, len(lines)):
                bare = re.sub(r'"[^"]*"', "", lines[j].split("#", 1)[0])
                depth += bare.count("{") - bare.count("}")
                if depth <= 0:
                    return "\n".join(lines[i:j + 1])
            return "\n".join(lines[i:])
    return ""


YUM_CONF = "/etc/yum.conf"
YUM_REPOS_DIR = "/etc/yum.repos.d"


def parse_yum_ini(text):
    """[(section, {key: value})] from a yum .conf/.repo file, in file order.

    A list, not a dict: 2.7's dict order is hash order, so a python2 and a python3 run of
    the same host could otherwise pick different repos. yum's own parser takes only
    whole-line comments, so a '#' inside a value (a proxy password) is kept, and an
    indented line continues the previous key's value - a second baseurl on its own line.
    """
    out, cur, last = [], None, None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if raw[:1] in (" ", "\t") and cur is not None and last is not None:
            cur[last] = (cur[last] + " " + line).strip()
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            cur, last = {}, None
            out.append((m.group(1).strip(), cur))
            continue
        if cur is not None and "=" in line:
            k, v = line.split("=", 1)
            last = k.strip().lower()
            cur[last] = v.strip()
    return out


def yum_section(text, name):
    """One section's {key: value} from parse_yum_ini's list, or {}."""
    for section, kv in parse_yum_ini(text):
        if section == name:
            return kv
    return {}


def _yum_true(value):
    """yum's BoolOption: case-folded, and 1 / yes / true are true."""
    return (value or "").strip().lower() in ("1", "yes", "true")


def _url_host(url):
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)", url or "")
    return m.group(1).lower() if m else ""


def enabled_repo_urls():
    """[(repo id, url)] for every enabled repo's baseurl and mirrorlist, in file order."""
    try:
        names = sorted(n for n in os.listdir(YUM_REPOS_DIR) if n.endswith(".repo"))
    except OSError:
        return None
    urls = []
    for name in names:
        for section, kv in parse_yum_ini(read_file(os.path.join(YUM_REPOS_DIR, name))):
            if not _yum_true(kv.get("enabled", "1")):
                continue
            for key in ("baseurl", "mirrorlist", "metalink"):
                for u in re.split(r"[\s,]+", kv.get(key, "")):
                    if u:
                        urls.append((section, u))
    return urls


def yum_proxy():
    """yum's [main] proxy as a URL curl reads from its environment, credentials folded in,
    or ''. Credentials never go on an argv: argv is in ps, and in the debug timings."""
    main = yum_section(read_file(YUM_CONF), "main")
    proxy = main.get("proxy", "")
    if not proxy or proxy == "_none_":
        return ""
    user = main.get("proxy_username", "")
    if user and "@" not in proxy and "://" in proxy:
        scheme, rest = proxy.split("://", 1)
        proxy = "%s://%s:%s@%s" % (scheme, _url_quote(user),
                                   _url_quote(main.get("proxy_password", "")), rest)
    return proxy


def _url_quote(text):
    """Percent-encode every byte of a URL credential. 2.7's quote maps characters through a
    table keyed by byte strings, so a non-ASCII unicode argument raises KeyError (measured
    on 8.3's python2): it gets UTF-8 bytes, which is what the URL means anyway."""
    try:
        from urllib import quote              # 2.7
    except ImportError:
        from urllib.parse import quote        # 3
    if sys.version_info[0] < 3 and isinstance(text, _TEXT):
        text = text.encode("utf-8")
    return quote(text, "")


def _env_value(text):
    """A value os.environ can hold on both interpreters: 2.7's putenv needs bytes."""
    if sys.version_info[0] < 3 and isinstance(text, _TEXT):
        return text.encode("utf-8")
    return text


_MIRRORLIST_IP_RE = re.compile(r"connecting with IP address <i>([^<]+)</i>"
                               r"(?:, which belongs to autonomous system <i>([^<]+)</i>)?")
_MIRRORLIST_ROW_RE = re.compile(
    r"<td>([^<]+)</td>\s*<td[^>]*>\s*<a href=\"([^\"]+)\"(.*?)</tr>", re.S)
_MIRRORLIST_SHARE_RE = re.compile(r">\s*(\d+)%\s*<")


def parse_mirrorlist(html):
    """(public ip, asn, [(mirror host, url, share %)]) out of a mirrorbits '?mirrorlist'
    page. Only the 'Mirrors' table, not 'Excluded Mirrors'. share is the % of this
    client's redirects that mirror gets; None ('n/a') is a fallback that only serves when
    every one with a share fails, so those are the mirrors yum is actually sent to."""
    html = html or ""
    m = _MIRRORLIST_IP_RE.search(html)
    ip, asn = (m.group(1).strip(), (m.group(2) or "").strip()) if m else ("", "")
    start = html.find("<h3>Mirrors</h3>")
    if start < 0:
        return ip, asn, []
    end = html.find("<h3>Excluded Mirrors</h3>", start)
    table = html[start:end if end > 0 else len(html)]
    mirrors = []
    for row in _MIRRORLIST_ROW_RE.finditer(table):
        s = _MIRRORLIST_SHARE_RE.search(row.group(3))
        mirrors.append((row.group(1).strip(), row.group(2).strip(),
                        int(s.group(1)) if s else None))
    return ip, asn, mirrors


def _curl_fail(r):
    """curl's own one-line reason ('curl: (6) Could not resolve host: x'), or why()."""
    if r.timed_out:
        return "timed out"
    for line in r.err.splitlines():
        if line.strip():
            return line.strip().replace("curl: ", "")[:200]
    return r.why()


def _curl(args, timeout):
    return run(["curl", "-sS", "--connect-timeout", str(max(1, min(5, timeout))),
                "-m", str(timeout)] + args, timeout=timeout + 5)


def collect_update_mirror(opts):
    """Can this host reach the XCP-ng update mirrors yum would be sent to?

    The repos point at a mirrorbits redirector (mirrors.xcp-ng.org), which answers every
    file with a redirect to a mirror picked by the client's public IP - so two hosts
    behind different egress, or one behind a firewall that allows the redirector and not
    the mirror, see different things. Asked from the host itself, so the IP the redirector
    geolocates is the one yum is judged by and no '?fromip=' is needed:

      1. '?mirrorlist' - the public IP and ASN the redirector sees, and the mirrors it
         will hand this host, with their share of the redirects;
      2. the plain URL, unfollowed - the mirror it picks right now;
      3. repomd.xml from each mirror with a share (and the one picked), which is the
         first file yum fetches from a repo.

    Goes through yum's [main] proxy when one is set, as yum would. A host whose enabled
    repos do not use the redirector (a local mirror) is not asked about it at all.
    """
    opts = opts or {}
    redirector = (opts.get("redirector") or "").lower()
    if not redirector:
        return err("no redirector configured")
    if which("curl") is None:
        return err("curl not found")
    urls = enabled_repo_urls()
    if urls is None:
        return err("could not read %s" % YUM_REPOS_DIR)
    ours = [(s, u) for s, u in urls if _url_host(u) == redirector]
    if not ours:
        others = sorted(set(_url_host(u) for _s, u in urls if _url_host(u)))
        return fact({"skipped": True, "repo_hosts": others})

    # base repo's own path when it has no unexpanded yum variables in it, and its own URL
    path, repo_url, base_section = "", "", ""
    for section, u in ours:
        if "$" not in u and (section.endswith("-base") or not path):
            path = re.sub(r"^[a-zA-Z]+://[^/]+", "", u).rstrip("/") + "/repodata/repomd.xml"
            repo_url = u.rstrip("/") + "/repodata/repomd.xml"
            base_section = section
    if not path:
        osr = os_release()
        ver = osr["value"].get("VERSION_ID", "") if osr["ok"] else ""
        mm = re.match(r"^(\d+)\.(\d+)", ver)
        if not mm:
            return err("could not tell the XCP-ng version to build a repo URL from")
        path = "/%s/%s.%s/base/x86_64/repodata/repomd.xml" % (mm.group(1), mm.group(1),
                                                              mm.group(2))
    # The redirector answers a plain http request with a 301 to https (measured on 8.3),
    # so yum - whose stock baseurl is http:// - ends up on the https mirror set, which is
    # the set probed below. What it does first is the http hop, tested separately.
    url = "https://%s%s" % (redirector, path)
    # the base repo's other hosts (the stock files list http://updates.xcp-ng.org after the
    # redirector), which yum falls back to when the redirector cannot be reached
    fallbacks = [u.rstrip("/") + "/repodata/repomd.xml" for s, u in urls
                 if s == base_section and _url_host(u) and _url_host(u) != redirector
                 and "$" not in u]

    timeout = int(opts.get("timeout") or 10)
    budget_end = _mono() + int(opts.get("budget") or 60)
    proxy = yum_proxy()
    saved = dict((k, os.environ.get(k)) for k in ("http_proxy", "https_proxy"))
    out = {"url": url, "repo_url": repo_url, "proxy": bool(proxy), "public_ip": "",
           "asn": "", "selected": "", "redirector_error": "", "first_hop_error": "",
           "page_error": "", "fallbacks": [], "not_probed": 0, "mirrors": []}
    try:
        if proxy:
            os.environ["http_proxy"] = os.environ["https_proxy"] = _env_value(proxy)

        r = _curl(["-L", "--max-redirs", "3", url + "?mirrorlist"], timeout)
        if not r.ok:
            out["redirector_error"] = _curl_fail(r)
            for furl in fallbacks:
                row = {"host": _url_host(furl), "url": furl, "ok": False, "error": ""}
                out["fallbacks"].append(row)
                r = _curl(["-L", "--max-redirs", "3", "-w", "\n%{http_code}", furl], timeout)
                if not r.ok:
                    row["error"] = _curl_fail(r)
                    continue
                body, _, code = r.out.rpartition("\n")
                if code.strip() == "200" and "<repomd" in body:
                    row["ok"] = True
                else:
                    row["error"] = "HTTP %s" % code.strip()
            return fact(out)
        ip, asn, listed = parse_mirrorlist(r.out)
        out["public_ip"], out["asn"] = ip, asn

        # yum's own first request, when its repo URL is not https: unfollowed, since all
        # that is asked is whether that hop answers at all (port 80, a proxy's plain GET)
        if repo_url and not repo_url.lower().startswith("https://"):
            r = _curl(["-o", os.devnull, "-w", "%{http_code}", repo_url], timeout)
            if not r.ok:
                out["first_hop_error"] = _curl_fail(r)
            elif r.out.strip()[:1] not in ("2", "3"):
                # a proxy or a portal answering for it: an error status is not a path
                out["first_hop_error"] = "HTTP %s" % r.out.strip()

        r = _curl(["-o", os.devnull, "-w", "%{http_code} %{redirect_url}", url], timeout)
        picked = ""
        if r.ok:
            parts = r.out.strip().split(None, 1)
            if len(parts) == 2 and parts[0].startswith("3"):
                picked = parts[1].strip()
                out["selected"] = _url_host(picked)

        # no shares at all means the page changed shape, not that none are used
        probe = [(h, u, share) for h, u, share in listed if share] or listed[:3]
        if picked and _url_host(picked) not in [_url_host(u) for _h, u, _s in probe]:
            probe.insert(0, (_url_host(picked), picked, None))
        cap = int(opts.get("max_mirrors") or 6)
        out["not_probed"] = max(0, len(probe) - cap)
        probe = probe[:cap]
        if not probe and not listed:
            # it ANSWERED: a page whose mirror list cannot be read is not unreachability
            out["page_error"] = "%s answered, but no mirror list could be read from it" \
                                % redirector
            return fact(out)

        for host, murl, share in probe:
            left = int(budget_end - _mono())
            row = {"host": host, "url": murl, "share": share, "ok": False, "error": "",
                   "tried": True}
            out["mirrors"].append(row)
            if left < 2:
                row["tried"] = False
                row["error"] = "not tried - out of time"
                continue
            t = min(timeout, left)
            r = _curl(["-L", "--max-redirs", "3", "-w", "\n%{http_code}", murl], t)
            if not r.ok:
                row["error"] = _curl_fail(r)
                continue
            body, _, code = r.out.rpartition("\n")
            if code.strip() != "200":
                row["error"] = "HTTP %s" % code.strip()
            elif "<repomd" not in body:
                row["error"] = "HTTP 200 but not repo metadata (captive portal or proxy page?)"
            else:
                row["ok"] = True
        return fact(out)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def collect_yum_check_update():
    """yum check-update: rc 0 = nothing to do, rc 100 = updates listed, anything else
    means yum itself failed (broken repo, no network) - which must never read as zero.

    exit_on_lock: with another yum holding /var/run/yum.pid (an admin's yum update, a
    patch install from XO) yum otherwise waits for it, and this spent its whole timeout
    learning nothing. It now exits at once with its own reason, which why() carries."""
    r = run(["yum", "--setopt=exit_on_lock=1", "check-update", "-q"], timeout=180)
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


# Packages yum installs BESIDE the running version rather than over it, which only a
# reboot activates. XCP-ng ships installonlypkgs= empty (measured on 8.3), so these log
# as Updated anyway; the list matters for a host configured otherwise.
BOOT_PACKAGES = ("kernel", "kernel-alt", "xen-hypervisor")


def _is_patch_line(action, pkg):
    """One predicate shared by Last Patched and Rebooted After Updates.

    An 'Updated:' of anything is a patch. An 'Installed:' only counts for kernel/xen,
    because yum installs a new kernel beside the old one instead of upgrading it. A
    plain 'Installed:' of anything else is a NEW package - installing sshpass must not
    redate the host.
    """
    if action == "Updated":
        return True
    if action != "Installed":
        return False
    # yum.log writes a non-zero epoch in front of the name: 'Installed: 2:xen-...'; the
    # package name is everything before the first '-<digit>' (where the version starts)
    m = re.match(r"^(?:\d+:)?(.+?)-\d", pkg)
    # exact names, not prefixes: kernel-devel or xen-dom0-tools installed for the first
    # time is a new package, not a patch, and must not redate the host
    return bool(m) and m.group(1) in BOOT_PACKAGES


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

MISSING = "not found"


def grep_scan(path, phrases, timeout=180, ignore=None):
    """The LAST hit of each phrase in one file: (hits, why).

    hits is {phrase_index: (lineno, line)} - the matched line's text rides along, so a hit
    survives even when its context cannot be read afterwards. why is None when the file
    was read through, MISSING when it does not exist, or the reason it could not be read:
    every caller must keep "could not look" apart from "looked, nothing there".

    One grep pass for all phrases together (these files run to 30 MB+), then attribution
    over just the matched lines. Streamed, so a phrase that matches constantly cannot
    blow memory.

    ignore is a list of rules, each a list of substrings: a matched line containing ALL of
    one rule's is no hit at all. It has to be decided here, while the last hit is picked -
    dropped afterwards, it would hide an earlier, real hit of the same phrase.
    """
    rules = []
    for rule in ignore or []:
        subs = [s.lower() for s in rule if s]
        if subs:
            rules.append(subs)
    if not phrases:
        return {}, None
    try:
        if not os.path.exists(path):
            return {}, MISSING
        if not os.access(path, os.R_OK):
            return {}, "not readable"
    except OSError as exc:
        return {}, "could not look (%s)" % exc

    timeout = _clamp(timeout)
    if timeout is None:
        return {}, "not read - the run budget was used up"

    # -a is load-bearing, not defensive. A single NUL or non-UTF-8 byte anywhere in the
    # file makes grep call it binary: 2.20 (dom0) then prints "Binary file X matches"
    # instead of the line numbers, and 3.8 (XOA) prints nothing at all with rc 0 - a match
    # found and silently not reported, which reads as a clean log. Measured on both.
    argv = ["grep", "-ainF"]
    for p in phrases:
        argv += ["-e", p]
    argv += ["--", path]

    started = _mono()
    try:
        proc, devnull = _popen(argv)
    except (OSError, ValueError) as exc:
        return {}, "grep could not be run (%s)" % exc

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
            text = line[sep + 1:].rstrip("\r\n")
            body = text.lower()
            if rules and any(all(s in body for s in r) for r in rules):
                continue
            for i, needle in enumerate(lowered):
                if needle and needle in body:
                    last[i] = (int(num), text)
        proc.stdout.close()
        rc = proc.wait()
    finally:
        timer.cancel()
        devnull.close()
        _forget(proc)
        # the attribution loop above runs once per MATCHED line, so this is grep's time
        # plus ours - which is the number that matters on a log full of hits
        timed(argv, started)
        CURRENT[0] = ""
    if state["killed"]:
        return last, "grep did not finish within %ds" % int(timeout)
    # rc 1 is grep's "no match", which is a real answer; 2+ means grep itself failed
    if rc > 1:
        return last, "grep failed (exit %d)" % rc
    return last, None


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


def collect_log_scan(files, phrases, ctx, ignore=None):
    """For every (file, phrase) pair, the most recent hit with context: {"blocks", "failed"}.

    Each base log is tried first and its rotated .1 only for phrases the live file
    lacks: these rotate daily around 04:00, so right after a rotation the live file is
    nearly empty - but reporting a stale .1 hit beside a current one would be worse.
    One block per phrase, so a phrase that matches constantly ('except') can never
    crowd out a rare, serious one. ignore: see grep_scan.

    "failed" names every scan that did not happen - a live log missing or unreadable, a
    grep killed or refused for lack of budget, a .1 that exists and could not be read -
    so a scan that never ran cannot read as a clean log. A missing .1 is not a failure:
    the log has simply not rotated yet. A hit whose context could not be read is kept,
    with the matched line alone and a note saying so - a found hit is never dropped.
    """
    if not files or not phrases:
        return fact({"blocks": [], "failed": []})
    blocks, failed = [], []
    for base in files:
        live, why = grep_scan(base, phrases, ignore=ignore)
        if why:
            failed.append("%s: %s" % (base, why))
        rotated, rotated_scanned = {}, False
        for i, phrase in enumerate(phrases):
            path = base
            hit = live.get(i)
            if hit is None:
                if not rotated_scanned:
                    rotated_scanned = True
                    rotated, why = grep_scan(base + ".1", phrases, ignore=ignore)
                    if why and why != MISSING:
                        failed.append("%s.1: %s" % (base, why))
                path = base + ".1"
                hit = rotated.get(i)
            if hit is None:
                continue
            lineno, text = hit
            block = {"phrase": phrase, "file": path, "line": lineno}
            lines = context_lines(path, lineno, ctx)
            if lines is None:
                block["context"] = [text]
                block["note"] = "the lines around it could not be read"
            else:
                block["context"] = lines
            blocks.append(block)
    return fact({"blocks": blocks, "failed": failed})


# --------------------------------------------------------------------------------------
# pool-level facts (asked of one host; xapi answers pool-wide from any member)
# --------------------------------------------------------------------------------------

def _pif_ips(network_uuid):
    """(ips fact, number of PIFs with no IP) for one network.

    --minimal with a SINGLE param across many objects is the form that works: it prints
    one comma-separated line with an empty field per PIF that has no IP. Those empty
    fields are counted, not dropped: XO takes a host's backup-network PIF IP verbatim, so
    a host whose PIF has none has its exports sent to an empty address, and dropping it
    left the hosts that DO have one to answer the ping and read green.
    """
    r = xe(["pif-list", "network-uuid=" + network_uuid, "params=IP", "--minimal"])
    if not r.ok:
        return err("xe pif-list params=IP failed (%s)" % r.why()), 0
    ips, missing = [], 0
    out = r.out.strip()
    for piece in (out.split(",") if out else []):
        piece = piece.strip()
        if not piece or piece == "0.0.0.0":
            missing += 1
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", piece):
            ips.append(piece)
    return fact(ips), missing


def _backup_scope():
    """Every VM and SR uuid in the pool. The single-param --minimal form, which is the one
    that answers correctly across many objects (see the trap ledger on --minimal)."""
    scope = {}
    for key, command in (("vms", "vm-list"), ("srs", "sr-list")):
        r = xe([command, "params=uuid", "--minimal"])
        if r.ok:
            scope[key] = fact(sorted(set(u.strip() for u in r.out.split(",") if u.strip())))
        else:
            scope[key] = err("xe %s failed (%s)" % (command, r.why()))
    return scope


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
        info["ips"], info["pifs_without_ip"] = _pif_ips(network_uuid)
    return info


LINSTOR_TIMEOUT = 120
LINSTOR_PROP_TIMEOUT = 30       # one node's properties, not a whole-cluster listing

# ECMA-48 CSI: parameter bytes 0x30-0x3F, intermediates 0x20-0x2F, one final byte 0x40-0x7E
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(text):
    """Defensive, exactly as colors.strip_ansi is on the XOA side: some tools colourise
    even when their output is a pipe. The collector cannot import colors - it ships alone -
    so it carries its own."""
    return ANSI_RE.sub("", text)


# the first linstor call that ran out its whole timeout, once one has: a controller that
# accepts the connection and never answers would otherwise cost every later call its full
# timeout too, and starve the questions after them
LINSTOR_WEDGED = [""]


def _linstor(controllers, args, timeout=LINSTOR_TIMEOUT):
    if which("linstor") is None:
        return err("linstor CLI not found")
    if LINSTOR_WEDGED[0]:
        return err("not asked - linstor did not answer %s" % LINSTOR_WEDGED[0])
    # ASCII tables whatever the locale: linstor-client >= 1.29 draws UTF-8 box borders
    # under a UTF-8 locale even into a pipe, and the table readers key on '|'. Both options
    # exist back to linstor-client 1.13 (checked); LC_ALL=C alone would also do it.
    argv = (["linstor", "--no-utf8", "--no-color", "--controllers=" + ",".join(controllers)]
            + list(args))
    full = _clamp(timeout) == timeout
    r = run(argv, timeout=timeout)
    if not r.ok:
        if r.timed_out and full:
            LINSTOR_WEDGED[0] = "'linstor %s' within %ds" % (" ".join(args), timeout)
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
        r = xe(["vdi-list", "sr-uuid=" + sr, "params=uuid,name-label,sm-config"], canary=False)
        if not r.ok:
            # two values, like the success path: the caller unpacks a pair, and a lone
            # err() unpacked into its two KEYS lost the reason entirely
            return err("xe vdi-list failed (%s)" % r.why()), None
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


_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def collect_ha_statefile_srs(pool_uuid):
    """[{vdi, sr, name}] for each HA statefile VDI and the SR it lives on - the SR HA was
    enabled with, which every host has to keep reaching or it fences itself. Only uuids
    xapi handed back are ever asked about, so none of these can log a missing-uuid
    exception; a lookup that fails leaves '' in its field rather than losing the rest."""
    r = xe(["pool-param-get", "uuid=" + pool_uuid, "param-name=ha-statefiles"])
    if not r.ok:
        return err("xe pool-param-get ha-statefiles failed (%s)" % r.why())
    rows = []
    for vdi in _UUID_RE.findall(r.out):
        row = {"vdi": vdi, "sr": "", "name": ""}
        rows.append(row)
        v = xe(["vdi-list", "uuid=" + vdi, "params=sr-uuid", "--minimal"])
        m = _UUID_RE.search(v.out) if v.ok else None
        if not m:
            continue
        row["sr"] = m.group(0)
        s = xe(["sr-list", "uuid=" + row["sr"], "params=name-label", "--minimal"])
        if s.ok:
            row["name"] = s.out.strip()
    return fact(rows)


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
        if r.ok and r.out.strip() == "true":
            out["ha_statefile_srs"] = collect_ha_statefile_srs(pool_uuid)

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

    # SR Attachment: every PBD, SR and host, each in the labelled form (a multi-param
    # --minimal prints one value) and each with its uuid, which is what the records are
    # split on. None of them names a uuid, so none can make xapi log a missing-uuid
    # exception.
    att = {}
    for key, args in (("pbds", ["pbd-list", "params=uuid,host-uuid,sr-uuid,currently-attached"]),
                      ("srs", ["sr-list", "params=uuid,name-label,type,shared"]),
                      ("hosts", ["host-list", "params=uuid,name-label,host-metrics-live"])):
        r = xe(args)
        if not r.ok:
            att = None
            out["sr_attachment"] = err("xe %s failed (%s)" % (args[0], r.why()))
            break
        att[key] = r.out
    if att is not None:
        out["sr_attachment"] = fact(att)

    # Long-Running Tasks: every task, labelled, with this host's clock beside it - 'created'
    # is UTC, and the age is worked out against the clock of the host xapi answered on,
    # never the XOA's
    r = xe(["task-list", "params=uuid,name-label,status,created,progress,resident-on"],
           canary=False)
    out["tasks"] = fact({"text": r.out, "now": time.time()}) if r.ok else \
        err("xe task-list failed (%s)" % r.why())

    # Windows VMs Not Optimized, and what Leaf-Coalesce Disabled judges busy-ness by: every
    # VM in one labelled call. vm-list leaves templates and snapshots out by itself.
    # reference-label is not known to exist on 8.2 (no 8.2 host left to look), and the list
    # form answers a field that is not there with nothing, quietly (measured on 8.3 with a
    # made-up name: 0 exceptions)
    r = xe(["vm-list", "is-control-domain=false",
            "params=uuid,name-label,power-state,current-operations,platform,"
            "reference-label,other-config,os-version"], canary=False)
    out["vms"] = fact(r.out) if r.ok else err("xe vm-list failed (%s)" % r.why())

    # Leaf-Coalesce Disabled: xe filters on the map key itself (measured: 0 of 127 VDIs back
    # on a pool with none set, 0 exceptions), and the parser checks every record again. The
    # VBDs are only worth a call when there is a disk to name the VMs of.
    lc = {}
    r = xe(["vdi-list", "other-config:leaf-coalesce=false",
            "params=uuid,name-label,sr-name-label,is-a-snapshot,current-operations,other-config"],
           canary=False)
    if not r.ok:
        out["leaf_coalesce"] = err("xe vdi-list failed (%s)" % r.why())
    else:
        lc["vdis"] = r.out
        lc["vbds"] = ""
        if r.out.strip():
            r = xe(["vbd-list", "params=uuid,vdi-uuid,vm-uuid,vm-name-label"], canary=False)
            if r.ok:
                lc["vbds"] = r.out
            else:
                lc["vbds"] = None
                lc["vbd_error"] = "xe vbd-list failed (%s)" % r.why()
        # every SR's other-config, judged report-side: GC honours three SR switches -
        # leaf-coalesce=false, coalesce=false (no coalescing at all) and gc=false (GC
        # aborts for the SR) - SM 1680f106 cleanup.py leafCoalesceForbidden /
        # findCoalesceable / the gc switch. One call; SRs are few.
        r = xe(["sr-list", "params=uuid,name-label,other-config"])
        if r.ok:
            lc["srs"] = r.out
        else:
            lc["srs"] = None
            lc["sr_error"] = "xe sr-list failed (%s)" % r.why()
        out["leaf_coalesce"] = fact(lc)

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

    # asked for by the XOA only, and only worth asking with a backup network to judge:
    # which of its backup jobs move this pool's data is a question about uuids, since a
    # job names VMs and SRs by uuid and nothing on the XOA says which pool one lives in
    if spec.get("backup_scope") and "xo:backupNetwork" in resolved:
        out["backup_scope"] = _backup_scope()

    if sr_uuids:
        # xapi's own question first: it needs no controller, and a controller that does
        # not answer must not take it down with the linstor ones
        rows, total = _qcow2_vdis(sr_uuids, spec.get("qcow2_max") or 0)
        out["qcow2"] = rows
        out["qcow2_total"] = fact(total) if total is not None else rows

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

def guarded(fn, *args):
    """One collector's fact, or an error naming the exception it raised.

    The collector-side twin of result.guard: a collector that blows up on input nobody
    foresaw costs its own fact - which then reads Unknown with the reason - and not every
    fact the host had already established. Broad on purpose, and only here.
    """
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - deliberate: one bad collector, one bad fact
        return err("internal error in the collector: %s: %s" % (type(exc).__name__, exc))


def guarded_many(keys, fn, *args):
    """guarded() for a collector that answers several facts at once: on an exception each
    of its keys carries the error, so none of them is merely missing."""
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - see guarded()
        why = err("internal error in the collector: %s: %s" % (type(exc).__name__, exc))
        return dict((key, why) for key in keys)


IDENTITY_KEYS = ("now", "hostname", "os_release", "self_uuid", "self_address", "pool_conf")
PATCH_KEYS = ("boot_epoch", "boot_disp", "update_epoch", "update_disp", "update_source",
              "newest_rpm")


def _xostor_here(vg):
    """Positive evidence that XOSTOR has, or had, storage on this host: the DRBD module
    loaded, the LINSTOR volume group present, or LVM's backup of it. pvs is asked only
    then - it opens every block device LVM's filter admits, multipath SAN LUNs included,
    and one with all paths down and I/O queueing (queue_if_no_path, no_path_retry queue -
    measured in the lab's multipathd config) parks it in D state for good."""
    if os.path.isdir("/sys/module/drbd"):
        return True
    if vg and re.match(r"^[A-Za-z0-9_.+-]+$", vg):
        return os.path.exists("/dev/" + vg) or os.path.exists(LVM_BACKUP_DIR + "/" + vg)
    return False


def collect(spec):
    want = set(spec.get("want") or [])
    # built in place, so the watchdog can hand back what was established if this call
    # never returns
    out = PARTIAL
    out["collector"] = {"python": sys.version.split()[0], "pid": os.getpid()}
    ident = guarded_many(IDENTITY_KEYS, collect_identity)
    out.update(ident)

    self_uuid = ident["self_uuid"]["value"] if ident["self_uuid"]["ok"] else ""

    if "pool_hosts" in want:
        if spec.get("host_list") == "statedb":
            out["pool_hosts"] = err("not asked - the run asked for state.db instead")
        else:
            out["pool_hosts"] = guarded(collect_pool_hosts)
        if not out["pool_hosts"]["ok"]:
            # the toolstack did not answer, but what it would have answered from is a
            # file, and every member keeps a copy of it
            out["pool_hosts_db"] = guarded(collect_state_db_hosts)

    if "host" in want:
        out["meminfo"] = guarded(collect_meminfo)
        out["timedatectl"] = guarded(collect_timedatectl)
        out["df"] = guarded(collect_df, (spec.get("mount_probe") or {}).get("types"))
        out["proc_mounts"] = guarded(collect_text_file, "/proc/mounts")
        out["fstab"] = guarded(collect_text_file, "/etc/fstab")
        out["dmesg"] = guarded(collect_dmesg)
        out["iplink"] = guarded(collect_iplink)
        out["ipaddr"] = guarded(collect_ipaddr)
        out["lacp"] = guarded(collect_lacp)
        out["multipath"] = guarded(collect_multipath, spec.get("multipath"))
        out["tap_status"] = guarded(collect_tap_status)
        out["crash_dumps"] = guarded(collect_crash_dumps, spec.get("crash_ignore_file") or "")
        out["coredumps"] = guarded(collect_coredumps, spec.get("coredump_dir") or "")
        out["failed_units"] = guarded(collect_failed_units)
        if out["failed_units"]["ok"] and STATIC_VDIS_UNIT in out["failed_units"]["value"]:
            out["static_vdis"] = guarded(collect_static_vdis)
        out["task_timeout"] = guarded(collect_task_timeout_override)
        out["rpm_manifest"] = guarded(collect_rpm_manifest)
        out["drbd_module"] = guarded(collect_drbd_module)
        vg = spec.get("xostor_vg") or ""
        if _xostor_here(vg):
            out["pvs"] = guarded(collect_pvs)
        else:
            out["pvs"] = fact({"rows": "", "warnings": "",
                               "skipped": "no XOSTOR here (no drbd module, no %s volume "
                                          "group or LVM backup of one)" % (vg or "LINSTOR")})
        out["lvm_backup"] = guarded(collect_lvm_backup, vg)
        out.update(guarded_many(PATCH_KEYS, collect_patch_facts))
        if spec.get("update_mirror"):
            out["update_mirror"] = guarded(collect_update_mirror, spec.get("update_mirror"))

        if self_uuid:
            r = xe(["pif-list", "params=gateway,IPv6-gateway,DNS", "management=false",
                    "host-uuid=" + self_uuid])
            out["pifs_dns_gw"] = fact(r.out) if r.ok else \
                err("xe pif-list gateway,DNS failed (%s)" % r.why())
        else:
            out["pifs_dns_gw"] = err("host uuid unknown")

        scan = spec.get("log_scan") or {}
        out["log_scan"] = guarded(collect_log_scan, scan.get("files") or [],
                                  scan.get("phrases") or [], scan.get("context") or 3,
                                  scan.get("ignore") or [])
        lun = spec.get("lun_scan") or {}
        out["lun_scan"] = guarded(collect_log_scan, lun.get("files") or [],
                                  lun.get("phrases") or [], lun.get("context") or 3)
        mps = spec.get("multipath_scan") or {}
        out["multipath_scan"] = guarded(collect_log_scan, mps.get("files") or [],
                                        mps.get("phrases") or [], mps.get("context") or 3)
        mstall = spec.get("mount_stall_scan") or {}
        out["mount_stall_scan"] = guarded(collect_log_scan, mstall.get("files") or [],
                                          mstall.get("phrases") or [],
                                          mstall.get("context") or 3)

        # The order matters and is the only thing left of the old gate: the process scan
        # runs FIRST, so a probe this run parks on a dead mount is not then reported by
        # this same run as a process that was already stuck. It shows up on the next run,
        # marked, and counted as what it is.
        out["stuck_procs"] = guarded(collect_stuck_processes, spec.get("stuck"))
        out["network_mounts"] = guarded(collect_network_mounts, spec.get("mount_probe"))
        if spec.get("smapi"):
            out["smapi"] = guarded(collect_smapi_hidden_leaves)

    # The pool questions before yum: they are local xapi reads that take seconds, while
    # yum check-update is network-bound and can spend up to 180s on a host whose egress is
    # dropped - after which every pool line would read "run budget exhausted"
    if "pool" in want:
        out["pool"] = guarded(collect_pool, spec, self_uuid)

    if "yumcheck" in want:
        out["yum_check"] = guarded(collect_yum_check_update)

    # stamped at the END: the report compares this against its own clock when the document
    # arrives, so a stamp from the start would count the whole collection as clock drift
    out["now"] = fact(time.time())
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
    # serialised BEFORE the flag is taken and BEGIN is written: a value json cannot encode
    # would otherwise leave half a document on stdout that nothing could replace
    try:
        text = json.dumps(payload)
    except (TypeError, ValueError) as exc:
        text = json.dumps({"__collector_error__": "the document could not be encoded: %s"
                                                  % exc})
    with _EMIT_LOCK:
        if _EMITTED[0]:
            return False
        _EMITTED[0] = True
    sys.stdout.write(BEGIN_MARKER + "\n")
    sys.stdout.write(text)
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
    payload["now"] = fact(time.time())
    payload["collector"] = dict(payload.get("collector") or {})
    payload["collector"]["timings"] = sorted(TIMINGS, reverse=True)[:15]
    payload["collector"]["abandoned"] = list(ABANDONED)
    if emit(payload):
        os._exit(0)
    # the main thread got there first and is writing its own document: dying now would
    # cut that document off mid-write, so let it finish


def _on_signal(signum, _frame):
    """SIGTERM/SIGHUP: take every running child down too, then go. Each child is in its
    own session, so nothing else would - an xe left running with nobody reading its pipe
    gets EPIPE, which xapi logs as an exception this tool would later report."""
    kill_live_children()
    os._exit(128 + signum)


def main(argv):
    spec = {}
    if len(argv) > 1 and argv[1]:
        spec = json.loads(base64.b64decode(argv[1].encode("ascii")).decode("utf-8"))
    DEADLINE[0] = _mono() + float(spec.get("budget") or 240)

    # Every child gets the C locale. The ssh session brings the XOA user's LANG/LC_* along
    # (Debian's SendEnv LANG LC_*, dom0's AcceptEnv - measured: LC_ALL=en_US.UTF-8 arrives),
    # and yum translates the lines the parsers key on ('Obsoleting Packages'). Nothing here
    # depends on the inherited locale: output is decoded as UTF-8 by the collector itself.
    os.environ["LC_ALL"] = "C"
    os.environ.pop("LANGUAGE", None)

    for sig in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, sig):
            try:
                signal.signal(getattr(signal, sig), _on_signal)
            except ValueError:
                pass            # not the main thread (a test driving main()): no handler

    guard = threading.Thread(target=watchdog, args=(WATCHDOG_GRACE,))
    guard.daemon = True
    guard.start()

    try:
        payload = collect(spec)
    except Exception:  # noqa: BLE001 - deliberate: whatever escapes, the facts already
        # gathered still go back, with the reason beside them
        import traceback
        payload = dict(PARTIAL)
        payload["__collector_error__"] = traceback.format_exc()
        payload["now"] = fact(time.time())
    emit(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


# ======================================================================================
# --- transport -------------------------------------------------------------------------

# The remote side is one fixed string plus a base64 argument. python3 where it exists
# (8.3 dom0), python 2.7 otherwise (8.2.1 dom0 has no python3 at all) - which is why the
# collector is written to the 2.7/3.6 intersection.
_REMOTE_LAUNCH = (
    'p=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true); '
    '[ -n "$p" ] || { echo "health: no python interpreter found on this host" >&2; exit 127; }; '
    'exec "$p" - %s'
)

# Pin the remote interpreter (HEALTH_REMOTE_PYTHON=python2). The 2.7 half of the
# collector's compatibility is otherwise only exercised on 8.2.1 hosts, which are the
# ones going away - this is how it stays testable on an 8.3 box.
_REMOTE_LAUNCH_PINNED = 'exec %s - %%s'

BEGIN_MARKER = "<<<HEALTHPY-JSON-BEGIN>>>"
END_MARKER = "<<<HEALTHPY-JSON-END>>>"

AUTH_ASKPASS = "askpass"
AUTH_SSHPASS = "sshpass"

# The variable the helper prints. Deliberately not SSHPASS: the two mechanisms are
# mutually exclusive and reading one variable in a run that chose the other mechanism is
# the kind of half-configured state that authenticates with an empty password.
ASKPASS_ENV = "HEALTH_SSH_PASSWORD"

# Four lines of sh, written into the run's own work dir (mode 700, deleted at exit). It
# prints what is in the environment, so the password still never reaches a file or an
# argv - the same guarantee sshpass -e gives.
ASKPASS_SCRIPT = (
    "#!/bin/sh\n"
    "# health.py: hands ssh the root password it was already given, from the\n"
    "# environment only. Written per run into a temporary directory and deleted with it.\n"
    "printf '%s\\n' \"${" + ASKPASS_ENV + "}\"\n"
)


class CollectError(Exception):
    """Could not get a document out of a host. Never confused with 'the host is fine'."""


def _mark_incomplete(payload, host):
    """A document the collector sent back part way - stuck on a command it could not kill,
    or failed - keeps every fact it did establish, with "__incomplete__" saying why the
    rest is missing. Each missing fact then reads Unknown by construction, and the host
    block carries one flagged line naming the cause: the evidence gathered on exactly the
    host that is in trouble is not thrown away with it."""
    if "__collector_stuck__" in payload:
        # the host gave up on itself rather than being given up on: a command it could
        # not kill, named. The old shape of this was the transport's own 300s timeout,
        # which could say only that the host did not answer
        debug("%s abandoned its run in: %s" % (host, payload["__collector_stuck__"]))
        for elapsed, command in (payload.get("collector", {}).get("timings") or [])[:8]:
            debug("%s   %6.2fs  %s" % (host, elapsed, command))
        payload["__incomplete__"] = (
            "gave up after %ds stuck in '%s' - that command cannot be killed, so the host's "
            "storage or a driver is most likely wedged"
            % (config.REMOTE_CMD_TIMEOUT - 60, payload["__collector_stuck__"]))
    elif "__collector_error__" in payload:
        trace = payload["__collector_error__"].strip().splitlines()
        debug("collector failed on %s:\n%s" % (host, payload["__collector_error__"]))
        payload["__incomplete__"] = "the collector failed part way: %s" % (
            trace[-1] if trace else "no reason given")


_DEBUG_LOCK = threading.Lock()


def debug(msg):
    """Trace to stderr under HEALTH_DEBUG=1, one whole message at a time.

    Worker threads all write here, and a TextIOWrapper gives no atomicity guarantee, so
    the lock is what stops two hosts' traces from being spliced into one unreadable line.
    """
    if os.environ.get("HEALTH_DEBUG") == "1":
        with _DEBUG_LOCK:
            sys.stderr.write("[health-debug] %s\n" % msg)
            sys.stderr.flush()


# Every child process currently running, so an interrupted run can take the whole tree
# down with it. start_new_session puts each child in its own session, which is what makes
# the timeout killpg work - but it also means the terminal's ctrl-C never reaches them.
# Serially that left one orphan ssh behind; with hosts collected concurrently the worker
# threads cannot be interrupted at all, so without this an interrupt would sit for up to
# REMOTE_CMD_TIMEOUT waiting for the last collector to finish on its own.
_LIVE = set()
_LIVE_LOCK = threading.Lock()
# Set once the run is stopping: a thread still working (the XOA section's daemon thread, a
# collection worker between hosts) may not start a child after the kill that was meant to
# take every child with it - nothing would ever kill that one.
_STOPPING = [False]

# A polite kill first: SIGTERM lets a collector take its own children down with it (they
# are each in their own session, so nothing else reaches them); SIGKILL after this long.
TERM_GRACE = 2.0


class TimedOut(int):
    """run_local_cmd's own timeout: it compares equal to 124, as it always has, so every
    existing `rc == 124` keeps working - but a command that itself EXITED 124 (GNU timeout
    inside -c) is a plain int, and the two can be told apart where it matters."""


TIMED_OUT = TimedOut(124)


def is_timeout(rc):
    return isinstance(rc, TimedOut)


def _signal_group(proc, sig):
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, sig)          # start_new_session: pid is the group id
        else:
            proc.kill()
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def kill_all_children():
    """Stop every child still running, and any from starting. For an interrupted run, not
    for normal shutdown. SIGTERM to all, a short grace, then SIGKILL the rest."""
    with _LIVE_LOCK:
        _STOPPING[0] = True
        procs = list(_LIVE)
    if not procs:
        return
    for proc in procs:
        _signal_group(proc, getattr(signal, "SIGTERM", 15))
    deadline = time.monotonic() + TERM_GRACE
    for proc in procs:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    for proc in procs:
        if proc.poll() is None:
            _signal_group(proc, 9)


def _remote_launch(blob):
    pinned = os.environ.get("HEALTH_REMOTE_PYTHON")
    if pinned and re.match(r"^[A-Za-z0-9_./-]+$", pinned):
        return (_REMOTE_LAUNCH_PINNED % pinned) % blob
    if pinned:
        # a regression run that believes it is forcing python2 must not quietly test
        # python3 instead
        sys.stderr.write("Warning: ignoring HEALTH_REMOTE_PYTHON=%r (expected an "
                         "interpreter name or path).\n" % pinned)
    return _REMOTE_LAUNCH % blob


def _kill_tree(proc):
    """SIGTERM the child's group, then SIGKILL it if it is still there after TERM_GRACE."""
    _signal_group(proc, getattr(signal, "SIGTERM", 15))
    try:
        proc.wait(timeout=TERM_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    _signal_group(proc, 9)


def run_local_cmd(argv, timeout, env=None, stdin_text=None):
    """Run a local command. Returns (rc, stdout_text, stderr_text); rc is TIMED_OUT (== 124)
    when it ran out of time - see TimedOut."""
    with _LIVE_LOCK:
        if _STOPPING[0]:
            return (130, "", "%s: not started - the run is stopping" % argv[0])
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    except OSError as exc:
        return (127, "", "%s: %s" % (argv[0], exc))

    with _LIVE_LOCK:
        _LIVE.add(proc)
        stopping = _STOPPING[0]
    if stopping:
        # started in the instant the run was told to stop: it was never going to be killed
        _kill_tree(proc)
    payload = stdin_text.encode("utf-8") if stdin_text is not None else None
    try:
        out, err = proc.communicate(input=payload, timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = b"", b""
        rc = TIMED_OUT
    except KeyboardInterrupt:
        # only ever raised in the MAIN thread, so this is the serial path; the child is in
        # its own session and never saw the ctrl-C, so it has to be told
        _kill_tree(proc)
        raise
    finally:
        with _LIVE_LOCK:
            _LIVE.discard(proc)
    return (rc,
            out.decode("utf-8", "backslashreplace") if out else "",
            err.decode("utf-8", "backslashreplace") if err else "")


# ssh binds its master at '<ControlPath>.<16 random characters>' and exits 255 when that
# does not fit a unix socket's sun_path (108 bytes with its NUL: openssh mux.c
# muxserver_listen, misc.c unix_listener - the same in 7.4 and 9.2)
SOCKET_PATH_MAX = 107
CONTROL_NAME = "cm-%C"            # %C: a 40-character hash of the connection (OpenSSH 6.7+)


def control_options(work_dir):
    """ssh's connection-sharing options for this run's work dir.

    One master per host, its socket named by %C: a fixed length, where cm-%r@%h:%p grew
    with the host name and a pool stored by a long FQDN could not be reached at all. The
    work dir's own length still counts, though, and a long TMPDIR leaves no room for any
    socket (measured: exit 255, 'ControlPath too long'). Then sharing is switched off and
    every ssh makes its own connection - which costs one handshake, on the seed, since
    each host is otherwise asked once."""
    room = len(os.fsencode(work_dir)) + 1 + len(CONTROL_NAME) - 2 + 40 + 1 + 16
    if room > SOCKET_PATH_MAX:
        return ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    return ["-o", "ControlMaster=auto",
            "-o", "ControlPath=%s" % os.path.join(work_dir, CONTROL_NAME),
            "-o", "ControlPersist=60"]


def close_masters(work_dir):
    """Ask every ssh ControlMaster this run started to exit, so none outlives it.

    With ControlPersist the first ssh to a host forks a master into its own session (out of
    _LIVE's reach) that keeps the authenticated connection for 60 s after its last client;
    and once the work dir is gone its socket is too, so nothing could ever ask it to go.
    Measured: one per host, gone ~60 s after the run. `-O exit` over each socket ends them
    now. No host is contacted - the master is local.
    """
    try:
        names = os.listdir(work_dir)
    except OSError:
        return
    for name in names:
        if not name.startswith("cm-"):
            continue
        # not run_local_cmd: this runs at exit, after kill_all_children has closed it
        try:
            subprocess.call(["ssh", "-S", os.path.join(work_dir, name), "-O", "exit",
                             "health-master"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


class Transport(object):
    def __init__(self, run_env, work_dir, local_address=""):
        self.run_env = run_env
        self.work_dir = work_dir
        self.local_address = local_address
        self.password = ""
        self.ssh_port = 22
        self.source = collectorsrc.collector_source()
        self.auth = ""            # AUTH_ASKPASS / AUTH_SSHPASS, once one is established
        self.askpass = ""         # path to the helper, when that is the chosen one
        self.auth_error = ""      # why there is no way to authenticate, for the report

    def is_local(self, host):
        """Host mode runs its own commands locally: nothing is gained by logging into
        ourselves, and it works with no credentials at all."""
        if self.run_env != "host":
            return False
        return not self.local_address or host == self.local_address

    def collect(self, host, spec):
        """Run the collector on `host` and return its document. Raises CollectError."""
        spec = dict(spec)
        spec.setdefault("budget", config.REMOTE_CMD_TIMEOUT - 60)
        if os.environ.get("HEALTH_DEBUG") == "1":
            spec["timings"] = True
        blob = base64.b64encode(json.dumps(spec).encode("utf-8")).decode("ascii")
        debug("collect %s want=%s" % (host, spec.get("want")))

        if self.is_local(host):
            rc, out, err = self._run_local_collector(blob)
            what = "local command"
        else:
            if self.run_env == "host" and not self.password:
                # answering about the wrong machine is the failure mode worth killing
                raise CollectError(
                    "asked to run on %s from %s with no password for it" % (host, self.local_address))
            rc, out, err = self._run_ssh_collector(host, blob)
            what = "ssh to %s" % host

        # the document first: one that arrived whole is the answer whatever the exit code
        payload = self._extract(out)
        if payload is None:
            if is_timeout(rc):
                raise CollectError("%s timed out after %ds" % (what, config.REMOTE_CMD_TIMEOUT))
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("%s failed (exit %d)%s" % (what, rc, (": " + detail) if detail else ""))
        _mark_incomplete(payload, host)
        if err.strip():
            debug("stderr from %s:\n%s" % (host, err.strip()))
        info = payload.get("collector") or {}
        debug("%s answered from python %s" % (host, info.get("python", "?")))
        for elapsed, command in (info.get("timings") or [])[:8]:
            debug("%s   %6.2fs  %s" % (host, elapsed, command))
        return payload

    def collect_local(self, spec):
        """Explicitly this machine, before we know our own address.

        Only the discovery call needs it: from then on is_local() has an address to
        compare against, and answering about the wrong machine becomes impossible.
        """
        spec = dict(spec)
        spec.setdefault("budget", config.REMOTE_CMD_TIMEOUT - 60)
        blob = base64.b64encode(json.dumps(spec).encode("utf-8")).decode("ascii")
        rc, out, err = self._run_local_collector(blob)
        payload = self._extract(out)
        if payload is None:
            if is_timeout(rc):
                raise CollectError("local command timed out after %ds" % config.REMOTE_CMD_TIMEOUT)
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("local command failed (exit %d)%s"
                               % (rc, (": " + detail) if detail else ""))
        # the same reading as collect(): this path used to ignore the stuck marker and use
        # a partial document as if it were whole
        _mark_incomplete(payload, "this host")
        return payload

    def _run_local_collector(self, blob):
        return run_local_cmd([sys.executable, "-", blob],
                             timeout=config.REMOTE_CMD_TIMEOUT,
                             stdin_text=self.source)

    def _ssh_argv(self, host, remote_command):
        """The ssh invocation and the environment that authenticates it, in one place.

        Returns (argv, env). Both the collector and -c/--command go over it, and the
        options are the whole reason a run behaves the same on every host - one real
        connection per host, no host-key prompt, a bounded connect, and whichever
        password mechanism _auth_env() settled on. Built here so the two callers cannot
        drift apart on any of that; only the trailing command differs.
        """
        env, prefix = self._auth_env()
        return prefix + [
            "ssh",
            "-p", str(self.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=%d" % config.SSH_TIMEOUT,
            "-o", "NumberOfPasswordPrompts=1",
        ] + control_options(self.work_dir) + [
            "-o", "BatchMode=no",
            "root@" + host,
            remote_command,
        ], env

    def _run_ssh_collector(self, host, blob):
        argv, env = self._ssh_argv(host, _remote_launch(blob))
        return run_local_cmd(argv, timeout=config.REMOTE_CMD_TIMEOUT,
                             env=env, stdin_text=self.source)

    def run_command(self, host, cmd, timeout=None):
        """-c/--command: run the user's own command on `host`. Returns (rc, out, err).

        Always over ssh, with no local branch: -c is XOA-only (main rejects it on a
        hypervisor), and an XOA reaches every host including the master that way. If it
        ever gains a host mode, this needs an is_local() arm that runs the command
        through a shell - there would be no ssh to interpret it.

        Deliberately NOT a collector spec. The collector answers with a JSON document of
        facts between markers, which is the wrong shape for raw output: it would be
        base64'd in, JSON-encoded out, and clamped against a health sweep's budget, for
        no gain whatsoever. This is the path bash's run_remote took - the same ssh
        options, the same process-group timeout, the command handed over whole - and it
        is why nothing had to be added to the collector for this.

        Nothing here composes a command, so the no-shell rule the collector states does
        not apply: the string is the user's, it arrives whole, it leaves whole as the
        last argv element, and the remote login shell is the only thing that reads it -
        exactly as it was for bash.

        stdin is closed by run_local_cmd, which matters more here than anywhere: a
        command that tried to read it (an unguarded 'yum update') would otherwise be
        eating this script's own stdin.
        """
        timeout = config.RUN_CMD_TIMEOUT if timeout is None else timeout
        argv, env = self._ssh_argv(host, cmd)
        return run_local_cmd(argv, timeout=timeout, env=env)

    def _auth_env(self):
        """The environment and the argv prefix that hand ssh the password.

        Two variables for the askpass helper, because two generations of OpenSSH decide
        differently whether to use one. SSH_ASKPASS_REQUIRE is 8.4 and later (XOA's 9.2)
        and settles it outright. 7.4 - which is what both dom0 releases ship, so it is the
        host-mode sweep - consults the helper only when there is no controlling terminal
        AND DISPLAY is set: the first is already true of every child here (they are all
        started with start_new_session=True, so open("/dev/tty") fails in them), and the
        second is why a DISPLAY nothing will ever connect to is set. An existing DISPLAY
        is left alone; it is only ever read as a flag.
        """
        env = dict(os.environ)
        if self.auth == AUTH_ASKPASS:
            env[ASKPASS_ENV] = self.password
            env["SSH_ASKPASS"] = self.askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            if not env.get("DISPLAY"):
                env["DISPLAY"] = ":0"
            return env, []
        env["SSHPASS"] = self.password
        return env, ["sshpass", "-e"]

    def enable_password_auth(self, run_env):
        """Find a way to give ssh a password, or record why there is none. True if found.

        The helper is tried FIRST because it needs nothing installed and nothing from the
        network. That is not a corner: health.py is routinely pasted onto a customer's
        appliance over ssh precisely because the appliance has no internet access, and
        there 'apt-get install sshpass' cannot work - the run used to die on that before
        printing a line, including the whole XOA section, which needs no pool access at
        all. It also means the path that runs in the field is the path the lab runs on
        every test, rather than a fallback nothing exercises until it matters.

        sshpass remains the fallback for the one thing the helper depends on that can be
        missing: a work dir it is allowed to execute from (a noexec /tmp).

        HEALTH_SSH_AUTH=askpass|sshpass pins the choice, which is how each is regression
        tested against the other on hosts that have both.
        """
        pinned = os.environ.get("HEALTH_SSH_AUTH", "")
        if pinned not in ("", AUTH_ASKPASS, AUTH_SSHPASS):
            sys.stderr.write("Warning: ignoring HEALTH_SSH_AUTH=%s (expected %s or %s).\n"
                             % (pinned, AUTH_ASKPASS, AUTH_SSHPASS))
            pinned = ""

        tried = []
        if pinned != AUTH_SSHPASS:
            path = write_askpass(self.work_dir)
            if path:
                self.auth = AUTH_ASKPASS
                self.askpass = path
                debug("password auth: ssh askpass helper at %s" % path)
                return True
            tried.append("the askpass helper would not run from %s" % self.work_dir)
            debug("askpass helper unusable")

        if pinned != AUTH_ASKPASS:
            if sshpass_present(run_env):
                self.auth = AUTH_SSHPASS
                debug("password auth: sshpass")
                return True
            tried.append("sshpass is not installed")

        # named individually: 'no way to authenticate' with no reason is the kind of
        # message that gets read as 'wrong password' and sends someone after the pool
        self.auth_error = ("ssh needs a password and there is no way to hand it one (%s)"
                           % " and ".join(tried))
        return False

    @staticmethod
    def _extract(text):
        """Pull the JSON out from between the markers.

        Markers rather than 'the first {' so a login banner, a sudo notice or any other
        stray stdout cannot be mistaken for the document - and so truncation is detected
        instead of producing a confident half-answer.
        """
        start = text.find(BEGIN_MARKER)
        end = text.rfind(END_MARKER)
        if start < 0 or end < 0 or end < start:
            return None
        blob = text[start + len(BEGIN_MARKER):end].strip()
        if not blob:
            return None
        try:
            return json.loads(blob)
        except ValueError:
            return None


def make_work_dir():
    path = tempfile.mkdtemp(prefix="healthpy-")
    return path


def cleanup_work_dir(path):
    if path and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def which(binary):
    """Full path to `binary` on PATH, or "". The path matters as well as the answer:
    xo-server's application directory is derived from where xo-server-db really lives."""
    for part in (os.environ.get("PATH") or "").split(os.pathsep):
        if not part:
            continue
        candidate = os.path.join(part, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def have(binary):
    return bool(which(binary))


def write_askpass(work_dir):
    """Write the askpass helper and PROVE it runs. Returns its path, or "" if it does not.

    The proof is the point. Everything that can go wrong here - a noexec /tmp, a work dir
    on a filesystem that drops the execute bit, no /bin/sh - fails silently at the far
    end otherwise: ssh gets an empty password back and reports an authentication failure,
    which reads as a wrong root password and sends someone off to check xo-server-db.
    A probe value, never the real password, so the check costs nothing to be wrong about.
    """
    path = os.path.join(work_dir, "askpass")
    try:
        handle = open(path, "w")
        try:
            handle.write(ASKPASS_SCRIPT)
        finally:
            handle.close()
        os.chmod(path, 0o700)
    except (IOError, OSError) as exc:
        debug("askpass helper could not be written to %s: %s" % (path, exc))
        return ""
    probe = "health-askpass-probe"
    env = dict(os.environ)
    env[ASKPASS_ENV] = probe
    rc, out, err = run_local_cmd([path], timeout=config.LOCAL_CMD_TIMEOUT, env=env)
    if rc != 0 or out.strip() != probe:
        debug("askpass helper did not run (exit %d): %s"
              % (rc, ((err or out).strip() or "no output")[:200]))
        return ""
    return path


def sshpass_present(run_env):
    """Is sshpass already installed? It is the fallback, reached only when the askpass
    helper could not be run (a noexec work dir) - see enable_password_auth().

    Nothing is installed for it, on either side (the maintainer's call, 2026-11-25). The
    install this replaces ran yum --enablerepo=extras on a dom0 and apt-get on an XOA: on
    the offline appliances health.py is routinely pasted onto that was up to ten minutes
    of timeouts before anything printed, and it left a package behind on a box the tool
    is meant to leave as it found it. Without sshpass the run goes on to the XOA-only
    report, or this host alone, saying why.
    """
    return have("sshpass")


# ======================================================================================
# --- xoredis ---------------------------------------------------------------------------

DEFAULT_ADDR = ("127.0.0.1", 6379)   # node-redis' default, used when [redis] is unset
ENCRYPTION_PREFIX = "enc:"           # xo-server/src/xo-mixins/crypto-credentials.mjs
IDS_KEY = "xo:server_ids"
RECORD_PREFIX = "xo:server:"
PLUGIN_IDS_KEY = "xo:plugin-metadata_ids"
PLUGIN_RECORD_PREFIX = "xo:plugin-metadata:"


class RedisError(Exception):
    """The fast path declined, with the reason. Never a health finding: the caller falls
    back to xo-server-db and the run continues exactly as it did before."""


# --------------------------------------------------------------------------------------
# is the default endpoint the right endpoint?
# --------------------------------------------------------------------------------------

def _config_dirs(cli_path):
    """The directories app-conf searches for xo-server's config, in its own order.

    From its entries.js: the application directory first, then /etc/<appName>, then the
    XDG config dir. `cli_path` is <appDir>/dist/db-cli.mjs, and app-conf is handed
    `new URL('..', import.meta.url)` - so the app dir is two levels up from the real file,
    symlinks resolved (/usr/local/bin/xo-server-db is one).

    app-conf has a fourth entry, `.xo-server.*` in every directory from the cwd upwards.
    That is for running xo-server out of a source tree, it cannot exist on an appliance,
    and scanning it would mean walking to / on every health check. Not searched.
    """
    app_dir = os.path.dirname(os.path.dirname(os.path.realpath(cli_path)))
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return [app_dir, os.path.join("/etc", "xo-server"), os.path.join(xdg, "xo-server")]


def _config_files(directory):
    """Everything app-conf would glob as `config.*` there. Raises rather than returning an
    empty list for a directory that exists but cannot be listed - unreadable is not empty."""
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RedisError("cannot list %s: %s" % (directory, exc))
    return [os.path.join(directory, n) for n in sorted(names) if n.startswith("config.")]


def _mentions_redis(cli_path):
    """Does any config XO loads mention redis at all?

    A substring test over the raw bytes, deliberately, and not a parse: app-conf reads
    config.* as toml, json, json5, ini or yaml depending on the extension, and this has one
    yes/no question to answer - "could this install point redis somewhere other than the
    default, or turn on credential encryption?". A mention for any reason declines the fast
    path, which is the safe direction, and `encryptCredentialDatabase` is itself a mention.

    The appliance ships /etc/xo-server/config.toml, <appDir>/config.toml and
    <appDir>/config.xoa.json with no occurrence of the word.
    """
    for directory in _config_dirs(cli_path):
        for path in _config_files(directory):
            try:
                with open(path, "rb") as handle:
                    blob = handle.read()
            except OSError as exc:
                # a config we cannot read is a config we cannot rule out
                raise RedisError("cannot read %s: %s" % (path, exc))
            if b"redis" in blob.lower():
                return True
    return False


# --------------------------------------------------------------------------------------
# just enough RESP to ask two questions
# --------------------------------------------------------------------------------------

def _encode(args):
    """One command, as a RESP array of bulk strings."""
    out = [b"*%d\r\n" % len(args)]
    for arg in args:
        raw = arg.encode("utf-8")
        out.append(b"$%d\r\n" % len(raw))
        out.append(raw + b"\r\n")
    return b"".join(out)


def _read_reply(handle):
    """One RESP reply. Bulk strings decode strictly: a password decoded with 'replace'
    would be a password that authenticates nowhere, reported as a login failure a long way
    from its cause."""
    line = handle.readline()
    if not line:
        raise RedisError("connection closed by redis")
    tag, body = line[:1], line[1:-2]
    if tag == b"+":
        return body.decode("utf-8", "replace")
    if tag == b"-":
        raise RedisError("redis refused the command: %s" % body.decode("utf-8", "replace"))
    if tag == b":":
        return int(body)
    if tag == b"$":
        length = int(body)
        if length < 0:
            return None
        data = handle.read(length + 2)
        if len(data) != length + 2:
            raise RedisError("short read from redis")
        return data[:-2].decode("utf-8")
    if tag == b"*":
        count = int(body)
        if count < 0:
            return None
        return [_read_reply(handle) for _ in range(count)]
    raise RedisError("unexpected reply from redis: %r" % line[:40])


# --------------------------------------------------------------------------------------
# the records
# --------------------------------------------------------------------------------------

def _flatten(record, ident):
    """The same dict xodb.scan_records builds out of `xo-server-db ls server`.

    XO stores every field of a server record as a JSON string today - `enabled` is the
    string 'true', not a boolean - so the coercions below are a no-op on every record on
    the test appliance. They are here because the two paths have to stay interchangeable
    whatever XO does next: node's util.inspect prints a bare `true` / `null` / `42`, which
    the scanner records as those words, and prints an object or an array in a form the
    scanner skips outright.

    `id` is not stored in the record - it is the key - and XO's own RedisCollection mixes
    it back in the same way, so `xo-server-db` prints it too.
    """
    out = {}
    for key, value in record.items():
        if isinstance(value, str):
            out[key] = value
        elif value is True:
            out[key] = "true"
        elif value is False:
            out[key] = "false"
        elif value is None:
            out[key] = "null"
        elif isinstance(value, (int, float)):
            out[key] = str(value)
        # an object or an array is skipped, which is what the scanner does with one
    out["id"] = ident
    return out


def _fetch(addr, timeout):
    """SMEMBERS then one MGET, against an already-vetted endpoint."""
    sock = socket.create_connection(addr, timeout=timeout)
    try:
        handle = sock.makefile("rb")
        try:
            sock.sendall(_encode(["SMEMBERS", IDS_KEY]))
            ids = _read_reply(handle)
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                raise RedisError("%s is not a set of ids" % IDS_KEY)
            if not ids:
                # An appliance with no server registered is a real state - and so is
                # "this is not the redis xo-server uses". Nothing here can tell them
                # apart, and only one of them is safe to act on, so the CLI answers it.
                raise RedisError("%s is empty" % IDS_KEY)

            sock.sendall(_encode(["MGET"] + [RECORD_PREFIX + i for i in ids]))
            blobs = _read_reply(handle)
            if not isinstance(blobs, list) or len(blobs) != len(ids):
                # `len(blobs or [])` would be a TypeError on an integer reply, and a
                # TypeError is not a decline - xodb catches RedisError and nothing else,
                # so it would take the run down instead of costing it 3.3s
                got = len(blobs) if isinstance(blobs, list) else "a non-list of"
                raise RedisError("MGET answered %s value(s) for %d id(s)"
                                 % (got, len(ids)))
        finally:
            handle.close()
    finally:
        sock.close()

    records = []
    for ident, blob in zip(ids, blobs):
        if blob is None:
            raise RedisError("%s%s disappeared between the two calls" % (RECORD_PREFIX, ident))
        if blob.startswith(ENCRYPTION_PREFIX):
            raise RedisError("credential db is encrypted (%s%s is %s...)"
                             % (RECORD_PREFIX, ident, ENCRYPTION_PREFIX))
        record = json.loads(blob)
        if not isinstance(record, dict):
            raise RedisError("%s%s is not an object" % (RECORD_PREFIX, ident))
        records.append(_flatten(record, ident))
    return records


def read_server_records(cli_path, addr=DEFAULT_ADDR, timeout=None):
    """Every xo `server` record, in the shape xodb.scan_records produces.

    Raises RedisError - with a reason fit for the HEALTH_DEBUG trace - for every reason
    not to trust the answer. It never returns a partial one.

    `timeout` defaults inside the body and not in the signature: a default argument is
    evaluated when the `def` runs, and in the stitched health.py that is module-body time,
    before the `config` alias object exists. DEFAULT_ADDR is fine - same module, already
    bound - but `config.XO_REDIS_TIMEOUT` there is a NameError on the real artifact and
    nowhere else. build/stitch.py now fails the build on it.
    """
    if timeout is None:
        timeout = config.XO_REDIS_TIMEOUT
    if _mentions_redis(cli_path):
        raise RedisError("xo-server config mentions redis; not assuming %s:%d"
                         % DEFAULT_ADDR)
    try:
        return _fetch(addr, timeout)
    except OSError as exc:
        # connection refused, timeout, a socket that is not redis at all
        raise RedisError("%s:%d: %s" % (addr[0], addr[1], exc))
    except UnicodeDecodeError as exc:
        # before ValueError, which it subclasses
        raise RedisError("undecodable answer from redis: %s" % exc)
    except ValueError as exc:
        # json.loads on a record, or int() on a malformed RESP length prefix
        raise RedisError("unreadable answer from redis: %s" % exc)


# --------------------------------------------------------------------------------------
# any other collection: backup jobs, their schedules, XO Proxies
# --------------------------------------------------------------------------------------

def read_records(cli_path, namespace, addr=DEFAULT_ADDR, timeout=None):
    """Every record of one more xo collection, as the dicts XO stored, plus its `id`.

    The same two declines as the server records, for the same reasons: an endpoint not
    established from the config files, and `enc:` (jobs, schedules and proxy
    registrations are all encrypted along with the servers when encryption is on). Unlike
    the server ids, an empty set is an answer here - an appliance with no backup job or no
    proxy is the usual case, not a sign of the wrong redis.

    Values are left as XO wrote them, unlike _flatten: a schedule's `enabled` is a real
    boolean in redis, and a job's patterns are JSON strings the caller decodes.
    """
    if timeout is None:
        timeout = config.XO_REDIS_TIMEOUT
    if _mentions_redis(cli_path):
        raise RedisError("xo-server config mentions redis; not assuming %s:%d" % DEFAULT_ADDR)
    try:
        return _fetch_collection(addr, timeout, namespace)
    except OSError as exc:
        raise RedisError("%s:%d: %s" % (addr[0], addr[1], exc))
    except UnicodeDecodeError as exc:
        raise RedisError("undecodable answer from redis: %s" % exc)
    except ValueError as exc:
        raise RedisError("unreadable answer from redis: %s" % exc)


def _fetch_collection(addr, timeout, namespace):
    ids_key = "xo:%s_ids" % namespace
    prefix = "xo:%s:" % namespace
    sock = socket.create_connection(addr, timeout=timeout)
    try:
        handle = sock.makefile("rb")
        try:
            sock.sendall(_encode(["SMEMBERS", ids_key]))
            ids = _read_reply(handle)
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                raise RedisError("%s is not a set of ids" % ids_key)
            if not ids:
                return []
            sock.sendall(_encode(["MGET"] + [prefix + i for i in ids]))
            blobs = _read_reply(handle)
            if not isinstance(blobs, list) or len(blobs) != len(ids):
                got = len(blobs) if isinstance(blobs, list) else "a non-list of"
                raise RedisError("MGET answered %s value(s) for %d id(s)" % (got, len(ids)))
        finally:
            handle.close()
    finally:
        sock.close()

    records = []
    for ident, blob in zip(ids, blobs):
        if blob is None:
            # not necessarily deleted between the two calls: MGET answers nil for a key
            # holding a HASH too, and XO wrote every record that way until Dec 2023
            # (32afd5c46) with no migration since - an old job never edited is still one.
            # Skipping it could drop an XOA-run job and read Backup Network green, so
            # decline: xo-server-db reads hash records through XO's own code
            raise RedisError("%s%s has no string value (deleted mid-read, or stored the "
                             "pre-2024 way, as a hash)" % (prefix, ident))
        if blob.startswith(ENCRYPTION_PREFIX):
            raise RedisError("%s records are encrypted (%s%s)" % (namespace, prefix, ident))
        record = json.loads(blob)
        if not isinstance(record, dict):
            raise RedisError("%s%s is not an object" % (prefix, ident))
        record["id"] = ident
        records.append(record)
    return records


# --------------------------------------------------------------------------------------
# plugin metadata - an annotation, never a finding
# --------------------------------------------------------------------------------------

def read_plugin_autoload(cli_path, addr=DEFAULT_ADDR, timeout=None):
    """{plugin name: autoload bool} from xo's own `plugin-metadata` records.

    This is the only place XO records whether a plugin is switched on, and it is a
    RECORD OF WHAT XO HAS SEEN, not of what is installed: a plugin that was loaded once
    and then removed keeps its record (the appliance still carries `cloud`, retired
    years ago), and a plugin installed but never loaded has none. So it can annotate the
    `XOA Plugins` finding and it must never be the thing that produces one - the
    directory scan is what establishes installation.

    Raises RedisError on anything doubtful, exactly like read_server_records, and the
    caller degrades to saying autoload is unknown. There is deliberately no fallback to
    `xo-server-db` here: 3.3s of node for an annotation is not a trade worth making.
    """
    if timeout is None:
        timeout = config.XO_REDIS_TIMEOUT
    if _mentions_redis(cli_path):
        raise RedisError("xo-server config mentions redis; not assuming %s:%d" % DEFAULT_ADDR)
    try:
        return _fetch_autoload(addr, timeout)
    except OSError as exc:
        raise RedisError("%s:%d: %s" % (addr[0], addr[1], exc))
    except UnicodeDecodeError as exc:
        raise RedisError("undecodable answer from redis: %s" % exc)
    except ValueError as exc:
        raise RedisError("unreadable answer from redis: %s" % exc)


def _fetch_autoload(addr, timeout):
    sock = socket.create_connection(addr, timeout=timeout)
    try:
        handle = sock.makefile("rb")
        try:
            sock.sendall(_encode(["SMEMBERS", PLUGIN_IDS_KEY]))
            ids = _read_reply(handle)
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                raise RedisError("%s is not a set of ids" % PLUGIN_IDS_KEY)
            if not ids:
                # unlike the server ids, empty is a real and harmless answer here: an
                # appliance xo-server has never started on has no metadata yet
                return {}
            sock.sendall(_encode(["MGET"] + [PLUGIN_RECORD_PREFIX + i for i in ids]))
            blobs = _read_reply(handle)
            if not isinstance(blobs, list) or len(blobs) != len(ids):
                got = len(blobs) if isinstance(blobs, list) else "a non-list of"
                raise RedisError("MGET answered %s value(s) for %d id(s)" % (got, len(ids)))
        finally:
            handle.close()
    finally:
        sock.close()

    out = {}
    for ident, blob in zip(ids, blobs):
        if blob is None:
            continue                      # deleted between the two calls; not our record
        if blob.startswith(ENCRYPTION_PREFIX):
            raise RedisError("plugin metadata is encrypted (%s%s)"
                             % (PLUGIN_RECORD_PREFIX, ident))
        record = json.loads(blob)
        if not isinstance(record, dict):
            raise RedisError("%s%s is not an object" % (PLUGIN_RECORD_PREFIX, ident))
        # XO stores every field as a JSON string, so autoload is 'true'/'false' and not a
        # boolean; both spellings are accepted so this keeps working if that changes
        value = record.get("autoload")
        out[ident] = (value is True) or (value == "true")
    return out


# ======================================================================================
# --- xodb ------------------------------------------------------------------------------

QUOTES = "'\"`"

_ESCAPE_RE = re.compile(r"\\(u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|.)", re.S)
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
_KEY_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*")


def unescape(text):
    """Every escape form util.inspect can emit.

    The old line-oriented awk kept \\n and \\' verbatim and so returned a password that
    was subtly wrong - which fails as an authentication error a long way from the cause.
    """
    def replace(m):
        for group in (2, 3, 4):
            if m.group(group) is not None:
                return chr(int(m.group(group), 16))
        char = m.group(1)
        return _SIMPLE_ESCAPES.get(char, char)
    return _ESCAPE_RE.sub(replace, text)


def scan_records(text):
    """util.inspect output -> list of dicts, in db order."""
    records = []
    i = 0
    n = len(text)

    def read_quoted():
        """text[i] is an opening quote; consume through the matching close."""
        nonlocal_i = i
        quote = text[nonlocal_i]
        nonlocal_i += 1
        raw = []
        while nonlocal_i < n and text[nonlocal_i] != quote:
            if text[nonlocal_i] == "\\":
                raw.append(text[nonlocal_i])
                nonlocal_i += 1
                if nonlocal_i < n:
                    raw.append(text[nonlocal_i])
                    nonlocal_i += 1
                continue
            raw.append(text[nonlocal_i])
            nonlocal_i += 1
        nonlocal_i += 1
        return unescape("".join(raw)), nonlocal_i

    while i < n:
        char = text[i]
        if char in QUOTES:
            _, i = read_quoted()
            continue
        if char != "{":
            i += 1
            continue
        i += 1
        record = {}
        depth = 1
        while i < n and depth > 0:
            char = text[i]
            if char in QUOTES:
                _, i = read_quoted()
                continue
            if char in "{[":
                depth += 1
                i += 1
                continue
            if char in "}]":
                depth -= 1
                i += 1
                continue
            if depth == 1:
                m = _KEY_RE.match(text, i)
                if m:
                    i = m.end()
                    if i < n and text[i] in QUOTES:
                        value, i = read_quoted()
                        record[m.group(1)] = value
                    elif i < n and text[i] not in "{[":
                        bare = []
                        while i < n and text[i] not in ",}\n":
                            bare.append(text[i])
                            i += 1
                        record[m.group(1)] = "".join(bare).strip()
                    # a nested {/[ falls through to the depth tracking above
                    continue
            i += 1
        records.append(record)
    return records


def clean(value):
    """Collapse all whitespace. This is what guarantees no field can contain a tab, which
    is what lets the rows be tab separated - pool names may legitimately contain '|'."""
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _sort_key(name):
    """localeCompare(undefined, {numeric: true, sensitivity: 'base'}) in Python.

    Case- and accent-insensitive, with digit runs compared as numbers, so 'Pool 10' sorts
    after 'Pool 9'. The order matters beyond cosmetics: it is also the non-interactive
    fallback order, so a cron run with no -n takes entry #1 of THIS ordering.
    """
    folded = unicodedata.normalize("NFKD", clean(name).lower())
    folded = "".join(_FOLD.get(c, c) for c in folded if not unicodedata.combining(c))
    parts = []
    for chunk in re.findall(r"\d+|[^\W\d_]+|\s+|.", folded):
        if chunk.isdigit():
            # digits sort BEFORE letters in the root collation ICU gives localeCompare,
            # so a pool named '1st Avenue' is menu entry 1, not 3. Verified against node
            # on the live db - getting this backwards silently changes which pool a
            # no-args cron run checks.
            parts.append((1, int(chunk), ""))
        elif chunk.isspace():
            parts.append((0, -1, ""))
        elif re.match(r"[^\W\d_]", chunk):
            parts.append((2, 0, chunk))
        else:
            # punctuation and symbols sort before digits, in CLDR's own order (node, on
            # the test XOA: _infra < (old) pool < #1 site < ~lab < 1st Avenue < alpha)
            pos = _CLDR_PUNCT.find(chunk)
            parts.append((0, pos if pos >= 0 else len(_CLDR_PUNCT) + ord(chunk), ""))
    return parts


# CLDR root collation's order for the ASCII punctuation and symbols - all of which come
# before digits, which come before letters (alternate=non-ignorable, ICU's default)
_CLDR_PUNCT = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"
# letters NFKD does not decompose, which root collation sorts as their base letters
_FOLD = {u"ø": "o", u"æ": "ae", u"œ": "oe", u"ß": "ss",
         u"đ": "d", u"ł": "l", u"þ": "th", u"ð": "d"}


class Server(object):
    __slots__ = ("host", "name", "search", "record")

    def __init__(self, host, name, search, record=None):
        self.host = host
        self.name = name
        self.search = search
        self.record = record if record is not None else {}


def have_xo_server_db():
    return transport.have("xo-server-db")


_ALL_SERVERS = None     # the one `xo-server-db ls server` scan; None until it is read
_READ_ERROR = ""        # why that scan failed, when it did; "" while it has not
_RESOLVED = {}          # db host name -> frozenset of its addresses, looked up once a run
_COLLECTIONS = {}       # namespace -> (records, why not), for the collections read on demand


def _describe_failure(rc, err):
    """One line saying why xo-server-db answered nothing, for the messages that used to
    say 'no enabled hosts' instead.

    The stderr of a permission failure is a node error object spread over several lines,
    of which the first is the one that says what happened:
        [Error: EACCES: permission denied, lstat '/etc/xo-server/config.toml'] {
    """
    if rc == 124:
        return "timed out after %ds" % (config.LOCAL_CMD_TIMEOUT * 3)
    first = ""
    for line in err.splitlines():
        line = line.strip()
        if line:
            first = line
            break
    if first.endswith(" {"):
        first = first[:-2]
    if first.startswith("[") and first.endswith("]"):
        first = first[1:-1]
    if re.search(r"password|is not valid JSON|Unexpected token|in JSON at position", first,
                 re.I):
        # node's JSON.parse errors quote the text around the fault - a corrupt record's
        # own bytes, password field and all - and this line is printed, and pasted into
        # tickets. The error's class is enough to say what happened
        first = "%s (the rest is withheld: it quotes a record)" % first.split(":")[0]
    if first:
        return "exit code %d: %s" % (rc, first)
    return "exit code %d" % rc


_RECORDS_HEADER = re.compile(r"^(\d+) record\(s\) found$", re.M)


def _ls(args):
    """(output, "") or (None, why-not). rc 127 is the transport's own 'not found'.

    Only what follows db-cli's own 'N record(s) found' header is returned (packages/
    xo-server/src/db-cli.mjs writes it before the records): anything xo-server's startup
    logs to stdout ahead of it - @xen-orchestra/log sends INFO to console.info - could
    carry a lone quote that throws the record scanner off for the whole rest of the
    output. LOG_LEVEL=warn keeps those lines out to begin with (configure.js reads it).

    A non-zero exit after every record was printed is accepted when the count matches:
    the tool can die in its shutdown hook (ClientClosedError at Servers._add, measured on
    the test XOA) with its output already whole.
    """
    env = dict(os.environ)
    env["LOG_LEVEL"] = "warn"
    rc, out, err = transport.run_local_cmd(["xo-server-db", "ls"] + list(args),
                                           timeout=config.LOCAL_CMD_TIMEOUT * 3, env=env)
    m = _RECORDS_HEADER.search(out or "")
    body = out[m.end():] if m else out
    if rc != 0:
        if m and len(scan_records(body)) == int(m.group(1)):
            transport.debug("xo-server-db exited %d after printing all %s record(s); "
                            "using them" % (rc, m.group(1)))
            return body, ""
        return None, _describe_failure(rc, err)
    return body, ""


# util.inspect cuts any string over maxStringLength (10000) and says so after it
_INSPECT_CUT = re.compile(r"\.\.\. \d+ more characters?")


def _read_servers():
    """(records, why-it-failed). Redis directly when that can be trusted, else the CLI.

    The fast path is in xoredis and declines loudly: anything it cannot establish raises
    RedisError and we spend the 3.3s. Its reason is a debug trace and never a health
    finding - a decline is not a failure, it is this code choosing not to guess.
    """
    cli_path = transport.which("xo-server-db")
    if cli_path:
        try:
            records = xoredis.read_server_records(cli_path)
            transport.debug("xo-db: %d record(s) read straight from redis" % len(records))
            return records, ""
        except xoredis.RedisError as exc:
            transport.debug("xo-db: redis declined (%s); asking xo-server-db" % exc)
    out, why = _ls(["server"])
    return (scan_records(out) if out is not None else [], why)


def all_servers():
    """Every server record in the db, read once per run.

    One `xo-server-db ls server` costs ~3.3s on the test appliance, and a narrower query
    costs exactly the same: it is node starting up, importing xo.mjs and running
    `xo.hooks.startCore()`, not the query. It also answers with WHOLE records - password
    field included, disabled servers as well as enabled ones. Measured against the indexed
    `host=` lookup on the live db: 7/7 records, every field equal, passwords equal.

    So the second call the password lookup used to make spent 3.3s re-reading what was
    already in hand, and a run that also had to name its pool made a third. That was
    ~55% of the wall clock of a whole health check.

    That 3.3s is now itself avoidable: none of it is redis. See xoredis - when the
    endpoint and the plaintext can both be established, the same records come back in
    0.03s, and this drops from the biggest item in a run to nothing at all.

    Read from the main thread only, before any host is contacted; nothing else in a run
    touches it, so the cache needs no lock.
    """
    global _ALL_SERVERS, _READ_ERROR
    if _ALL_SERVERS is None:
        # a db that could not be read is cached as empty, with the reason kept beside it:
        # asking again would cost another 3.3s to fail again, and every lookup answers
        # 'nothing' either way - but the messages built on that answer must not. Run as a
        # non-root user, xo-server-db cannot even stat /etc/xo-server/config.toml, and
        # 'no enabled hosts found in xo-db' was what an appliance with five pools said.
        _ALL_SERVERS, _READ_ERROR = _read_servers()
    return _ALL_SERVERS


def read_error():
    """Why the scan produced nothing, or '' when it was read - so a caller holding an empty
    answer can tell an empty db from one it never got to see. Reads the db if needed."""
    all_servers()
    return _READ_ERROR


def reset_cache():
    """Forget the scan. For tests - a real run reads the db once and then exits."""
    global _ALL_SERVERS, _READ_ERROR
    _ALL_SERVERS = None
    _READ_ERROR = ""
    _RESOLVED.clear()
    _COLLECTIONS.clear()


def enabled_servers():
    """The enabled pools, sorted for display. [] if the db has none we can use."""
    rows = []
    for rec in all_servers():
        if str(rec.get("enabled")) != "true" or not rec.get("host"):
            continue
        # poolNameLabel only exists once XO has connected to the pool at least once, so
        # the label fallback is load-bearing rather than paranoia
        pool_name = clean(rec.get("poolNameLabel"))
        label = clean(rec.get("label"))
        name = pool_name or label or "(unnamed)"
        # -n matches EITHER name: a pool can show as XEN-PRIMARY while the server label a
        # user remembers it by is XEN-MAIN-01
        rows.append(Server(rec["host"], name, (pool_name + " " + label).lower(), rec))
    # a fixed tie-break after the name: two pools that compare equal (both "(unnamed)",
    # or equal once case and accents are folded) must not swap places between runs - the
    # first is what a cron run checks, and redis set order changes at every restart
    rows.sort(key=lambda r: (_sort_key(r.name), db_address(r.record),
                             str(r.record.get("id") or "")))
    return rows


# --------------------------------------------------------------------------------------
# which record an address belongs to
# --------------------------------------------------------------------------------------
# A record's `host` is whatever was typed into XO - an IP, a name, sometimes with a scheme
# or a port - and a pool stored by name used to be invisible to every lookup made with
# one of its addresses: '-n a01 192.0.2.60' took the master's own address for a
# password and failed as a login error, and 'health.py 192.0.2.60' said the master was
# not in xo-db. Three kinds of evidence are tried, strongest first, and a weaker one is
# only consulted when no record at all answers to a stronger one.

def db_address(rec):
    """The bare address in a record's `host`, as XO itself reads that field."""
    return parsers.xo_server_address(rec.get("host") or "")[0]


def _same_address(a, b):
    """Two spellings of one address: case-blind for names, canonical for IPs."""
    if not a or not b:
        return False
    if a.lower() == b.lower():
        return True
    ip = parsers.ip_literal(a)
    return ip is not None and ip == parsers.ip_literal(b)


def _resolve(names):
    """{name: frozenset of its addresses}, each name looked up at most once per run.

    Only ever handed xo-db's own host names - never anything a user typed in the password
    position, which would put a root password into a DNS query. The lookups run at once
    and the whole set gets config.XO_DNS_TIMEOUT: an XOA whose DNS has gone away must
    not hang the run, and a name that has not answered by then has no addresses, which
    makes a match less likely and never more. The threads are daemons, so one wedged in
    the resolver cannot hold the process at exit.
    """
    todo = sorted(set(n for n in names if n and n not in _RESOLVED))
    if todo:
        found = {}

        def lookup(name):
            try:
                infos = socket.getaddrinfo(name, None)
            except (OSError, UnicodeError, ValueError):
                # gaierror is an OSError; an IDNA-invalid name is a UnicodeError and an
                # embedded NUL a ValueError. Each means this name has no address to give.
                found[name] = frozenset()
                return
            found[name] = frozenset(a for a in (parsers.ip_literal(i[4][0]) for i in infos) if a)

        threads = []
        for name in todo:
            t = threading.Thread(target=lookup, args=(name,))
            t.daemon = True
            t.start()
            threads.append(t)
        deadline = time.time() + config.XO_DNS_TIMEOUT
        for t in threads:
            t.join(max(0.0, deadline - time.time()))
        for name in todo:
            _RESOLVED[name] = found.get(name, frozenset())
            if name not in found:
                transport.debug("xo-db: no DNS answer for %s within %ss"
                                % (name, config.XO_DNS_TIMEOUT))
    return dict((n, _RESOLVED.get(n, frozenset())) for n in names)


def match_record(want, records, resolve_want=False):
    """(record, how) for the first record `want` is an address of, or (None, "").

    `how` says what made it a match, for messages that have to explain one:
      "host"    the record's own host field names it
      "member"  it is one of the pool members' addresses XO recorded (poolMembersAddresses,
                xo-server since July 2026), slaves included - which is what lets a slave's
                address find the pool's password, since every member shares it
      "dns"     it and the record's host name resolve to a common address

    DNS is the last resort and only ever resolves xo-db's own names - plus `want` itself
    when the caller says it is a host (resolve_want), never when it may be a password.
    """
    want = (want or "").strip()
    if parsers.has_url_scheme(want):
        # written the way XO shows an address ('https://10.0.0.5/'), so read the way XO
        # reads one - as every record's host field is
        want = parsers.xo_server_address(want)[0]
    if not want:
        return None, ""
    # Within each kind of evidence the first match wins, so the order decides between two
    # records that both answer: an ENABLED record before a disabled one (a stale disabled
    # record must not supply the password while the banner names the live pool), then a
    # fixed order - redis 7.0 keeps the id set as a hashtable whose iteration order
    # changes at every restart, so db order is no tie-breaker.
    records = sorted(records, key=lambda r: (str(r.get("enabled")) != "true",
                                             db_address(r), str(r.get("id") or "")))
    for rec in records:
        if rec.get("host") == want or _same_address(db_address(rec), want):
            return rec, "host"
    for rec in records:
        if any(_same_address(m, want)
               for m in parsers.pool_member_addresses(rec.get("poolMembersAddresses"))):
            return rec, "member"

    want_ip = parsers.ip_literal(want)
    if want_ip is None and not resolve_want:
        return None, ""
    if want_ip is not None:
        wanted = frozenset([want_ip])
    else:
        wanted = _resolve([want])[want]
        if not wanted:
            return None, ""
        # a name that resolves to an address a record holds outright, or to one of its
        # members' addresses
        for rec in records:
            held = [db_address(rec)] + parsers.pool_member_addresses(
                rec.get("poolMembersAddresses"))
            if any(parsers.ip_literal(a) in wanted for a in held):
                return rec, "dns"
    named = [rec for rec in records if parsers.ip_literal(db_address(rec)) is None]
    resolved = _resolve([db_address(rec) for rec in named])
    for rec in named:
        if resolved.get(db_address(rec), frozenset()) & wanted:
            return rec, "dns"
    return None, ""


def server_for_host(host):
    """(record, how) for a host given as an argument, or (None, "").

    Searched across ALL records, not the enabled ones - a host given as an argument may
    well be a server XO has disabled, and its password must still be found.
    """
    return match_record(host, all_servers(), resolve_want=True)


def password_for(host):
    """(password, has_backslash) or (None, False).

    Answered out of the one scan rather than with a second `xo-server-db ls server
    host=...`: the indexed query returns the same record field for field and costs another
    3.3s (see all_servers).
    """
    rec, _how = server_for_host(host)
    return record_password(rec)


def record_user(rec):
    """The xapi user XO connects as for this record ('' when not recorded). XO logs in with
    `server.username` (xen-servers.mjs), and only root's password is root's."""
    return clean((rec or {}).get("username")) if rec else ""


def record_password(rec):
    """(password, has_backslash) or (None, False) for one record."""
    pwd = (rec or {}).get("password")
    if not pwd:
        return (None, False)
    return (pwd, "\\" in pwd)


def enabled_server_for(want, resolve_want=True):
    """(Server, how) among the enabled pools, or (None, ""). resolve_want=False for a
    value that may be a password: it is then matched against what xo-db holds, and only
    xo-db's own names are looked up."""
    if not have_xo_server_db():
        return None, ""
    rows = enabled_servers()
    rec, how = match_record(want, [row.record for row in rows], resolve_want)
    for row in rows:
        if row.record is rec:
            return row, how
    return None, ""


def pool_name_for_host(want, resolve_want=True):
    """The db's name for a host given as an argument, so every run can name its target.

    Quiet and never an error: a pool XO does not manage, or no xo-server-db at all, are
    both normal - it just means the banner prints the address.
    """
    row, _how = enabled_server_for(want, resolve_want)
    return row.name if row is not None else ""


# --------------------------------------------------------------------------------------
# the other collections, read only when a check needs one
# --------------------------------------------------------------------------------------

def collection(namespace):
    """(records, "" or why not) for one more xo collection - job, schedule, proxy.

    Read at most once per run and only when asked: nothing in an ordinary run needs them,
    and on an appliance whose credential db is encrypted each one costs another 3.3s of
    xo-server-db. Redis directly when that can be trusted, as for the servers.
    """
    if namespace not in _COLLECTIONS:
        records, why = None, ""
        cli_path = transport.which("xo-server-db")
        if cli_path:
            try:
                records = xoredis.read_records(cli_path, namespace)
            except xoredis.RedisError as exc:
                transport.debug("xo-db %s: redis declined (%s); asking xo-server-db"
                                % (namespace, exc))
        if records is None:
            out, why = _ls([namespace])
            if out is not None and _INSPECT_CUT.search(out):
                # a job's vms/settings longer than 10000 characters (a hand-picked job of
                # a few hundred VMs) arrives cut short: never parse half a value
                records, why = [], ("xo-server-db printed some %s values cut short, so "
                                    "they could not be read whole" % namespace)
            else:
                records = scan_records(out) if out is not None else []
        _COLLECTIONS[namespace] = (records, why)
    return _COLLECTIONS[namespace]


def backup_routes(server, pool_uuid, vm_uuids, sr_uuids):
    """Where XO moves this pool's backup traffic from, as XO is configured to.

      xoa         the XOA itself moves some of it (or nothing is configured to, which
                  leaves whatever somebody starts from XOA)
      proxies     the names of the XO Proxies that move the rest
      http_proxy  host[:port] of the HTTP proxy the XOA's own connection to this pool goes
                  through ('' for none) - xen-api sends every request through it, exports
                  to the backup network included
      error       why none of that could be told; the other keys are absent then
    """
    jobs, why = collection("job")
    if why:
        return {"error": "could not read XO's backup jobs (%s)" % why}
    schedules, why = collection("schedule")
    xoa, proxy_ids = parsers.backup_runners(jobs, None if why else schedules,
                                            pool_uuid, vm_uuids, sr_uuids)
    names = []
    if proxy_ids:
        proxies, why = collection("proxy")
        known = {} if why else dict((p.get("id"), p.get("name")) for p in proxies)
        if not why:
            dangling = [i for i in proxy_ids if i not in known]
            if dangling:
                # XO would fail those jobs (callProxyMethod on a proxy it no longer has),
                # so nothing moves that traffic: it must not read as "through a proxy"
                return {"error": "backup job(s) pinned to XO Proxy %s, which no longer "
                                 "exists" % ", ".join(dangling)}
        names = [known.get(i) or i for i in proxy_ids]
    return {"xoa": xoa, "proxies": names, "error": "",
            "http_proxy": parsers.http_proxy_address((server or {}).get("httpProxy"))}


SELECT_OK = 0
SELECT_NONE = 1         # the db was read and lists no enabled pool
SELECT_QUIT = 2
SELECT_NO_MATCH = 3
SELECT_UNREADABLE = 4   # the db could not be read at all - read_error() says why


def select_pool(name_filter, stdin=None, stderr=None):
    """Resolve which pool to check. Returns (code, Server or None).

    Only resolves it - main announces the choice, because the paths that pick silently
    (sole enabled pool, cron/pipe) are exactly the ones where the banner is the only
    record of which pool was taken.
    """
    stdin = stdin if stdin is not None else sys.stdin
    stderr = stderr if stderr is not None else sys.stderr

    rows = enabled_servers()
    if not rows:
        # an empty answer is two different facts, and only one of them is 'no pools'
        return (SELECT_UNREADABLE if read_error() else SELECT_NONE, None)

    if name_filter:
        needle = name_filter.lower()
        for row in rows:
            if needle in row.search:
                return (SELECT_OK, row)
        stderr.write("ERROR: no enabled pool in xo-server-db matches '%s'.\n" % name_filter)
        stderr.write("Enabled pools:\n")
        for row in rows:
            stderr.write("  %s (%s)\n" % (row.name, db_address(row.record)))
        return (SELECT_NO_MATCH, None)

    try:
        interactive = stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False

    if len(rows) == 1 or not interactive:
        return (SELECT_OK, rows[0])

    stderr.write("\n%s\n" % colors.cyan("== Multiple pools found in XOA =="))
    # each pool by the address the run will dial - the banner's - and never by the host
    # field itself, which may carry a password ('https://root:pw@10.0.0.5')
    for i, row in enumerate(rows, 1):
        stderr.write("%d - %s (%s)\n" % (i, row.name, db_address(row.record)))
    stderr.write("\n")

    while True:
        stderr.write("Select a pool [1-%d], or q to quit: " % len(rows))
        stderr.flush()
        choice = stdin.readline()
        if not choice:            # EOF (ctrl-d) reads as a quit
            return (SELECT_QUIT, None)
        choice = choice.strip()
        if choice in ("q", "Q"):
            return (SELECT_QUIT, None)
        if choice.isdigit() and 1 <= int(choice) <= len(rows):
            stderr.write("\n")
            return (SELECT_OK, rows[int(choice) - 1])
        stderr.write("%s\n" % colors.yellow("Invalid selection."))


# ======================================================================================
# --- checks ----------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# info block
# --------------------------------------------------------------------------------------

def hypervisor_version(host):
    """The line key is always 'Hypervisor Version:' and the product name rides in the
    value. Keying it on the parsed name meant the LABEL changed to 'Hypervisor Version:'
    exactly when os-release could not be read - so anything reading the report line by
    line lost the host on the one result it most needed to see."""
    f = host.fact("os_release")
    if not f.ok:
        return unknown("Hypervisor Version", "Unknown")
    name = f.value.get("NAME", "")
    version = f.value.get("VERSION", "")
    if not name or not version:
        return unknown("Hypervisor Version", "Unknown")

    parts = version.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        major, minor = int(parts[0]), int(parts[1])
        if major > 8 or (major == 8 and minor >= 3):
            # pinned, so -f prints it even though this branch cannot flag: it is the
            # identity anchor for the host block, and under -f every other line in that
            # block is a finding. Without it a findings-only report would not say which
            # version produced them - and now that -f hides informational lines
            # (Last Booted, Multipathing, NTP), it is the ONLY line that would.
            return pinned(info("Hypervisor Version", "%s %s" % (name, version)))
    # 8.2 reached end of life on 2025-09-16 and receives no security updates at all
    return flag("Hypervisor Version", "%s %s" % (name, version))


def last_booted(host):
    """/proc/stat btime, not 'uptime -s': btime is the boot second the kernel recorded,
    while uptime -s recomputes now-minus-uptime on every run and drifts with clock
    adjustments - the two disagreed by a second on two test hosts, so the report named
    two different boot times for the same boot."""
    f = host.fact("boot_disp")
    line = raw("Last Booted", f.value if f.ok and f.value else "Unknown")
    line.label = "Last Booted: "
    return line


def last_patched(host):
    f = host.fact("update_disp")
    if f.ok and f.value:
        return raw("Last Patched", f.value)
    upd = host.fact("update_epoch")
    return raw("Last Patched", "Unknown (%s)" % upd.error if not upd.ok and upd.error
               else "Unknown")


def host_enabled(host):
    value = host.enabled or "Unknown"
    if value == "true":
        return ok("Host Enabled", value)
    if value == "false":
        return flag("Host Enabled", value)
    # not a finding: the address simply was not one xapi knows
    return info("Host Enabled", value, "yellow")


def multipathing(host):
    """The xapi setting, which never flags - so it stays an always-printed fact, in the
    same class as Dom0 Memory."""
    value = host.multipathing or "Unknown"
    return info("Multipathing", value, "yellow" if value == "Unknown" else "green")


def xapi_status(host):
    """Whether this host's toolstack answers an API call.

    It is the line that explains the others: every xe-sourced fact in the block (Host
    Enabled, Multipathing, DNS/GW on Non-Mgmt PIFs, and the pool lines when this is the
    host they were asked of) is Unknown when xapi does not answer, and this is where the
    reason is. Everything that is not xe - the logs, dmesg, disks, memory, multipath,
    pool.conf - was still read, which is what makes a report on a broken pool possible.

    It reads the collector's identity call, so it costs nothing: every host is asked for
    its own address with `xe host-param-get` before anything else. A slave keeps no
    database of its own and reads through its master, so on a slave 'Responding' covers
    the master connection too - a slave whose master is gone does not answer, which is
    the reading wanted from a pool whose master change failed.
    """
    uuid = host.fact("self_uuid")
    if not uuid.ok:
        return unknown("XAPI Status", "Unknown (%s, so xapi was not asked)" % uuid.error)
    f = host.fact("self_address")
    if f.ok:
        return ok("XAPI Status", "Responding")
    return flag("XAPI Status", "Not responding", " - %s" % f.error)


def ntp(host):
    """One line, two facts. An explicit 'no' is a real finding, and so is a half that was
    not established: timedatectl unread or unparseable is a fact we failed to establish,
    which flags the exit code like any other (v3.28 - it used to be an exit-neutral
    yellow, on a reason left over from the bash script's xe-map source). systemd's 'n/a'
    (no NTP service known) arrives here as 'no'."""
    from colors import green, yellow
    state = host.ntp_state()
    enabled, synced = state["ntp"], state["sync"]
    text = "Enabled - %s Synced - %s" % (
        (green if enabled == "yes" else yellow)(enabled),
        (green if synced == "yes" else yellow)(synced))
    if state.get("error"):
        text += " (%s)" % state["error"]
    line = result.Line("NTP", text, result.OK)
    if enabled == "no" or synced == "no":
        line.status = result.FLAG
    elif enabled != "yes" or synced != "yes":
        line.status = result.UNKNOWN
    return line


def dom0_ram_allocations(hosts):
    """Every reachable host's dom0 MemTotal, compared.

    Within RAM_MATCH_TOLERANCE_MB counts as the same: MemTotal is dom0_mem less kernel
    reservations that differ with hardware by tens of MiB, and rounding to the nearest
    GiB (what this did) split two hosts 20 MiB apart across an N.5 GiB boundary while
    calling two 480 MiB apart equal. A host whose memory was not read is not a
    difference - but it is not agreement either, so a match then says Unknown and names
    it; and one reading compares nothing.
    """
    readings, unread = [], []
    for host in hosts:
        total = host.mem_total_mb()
        if total is None:
            unread.append(host.label)
        else:
            readings.append((host.label, total))
    if not readings:
        return unknown("Dom0 RAM Allocations", "Unknown (no host's memory could be read)")
    low, high = min(t for _l, t in readings), max(t for _l, t in readings)
    if high - low > config.RAM_MATCH_TOLERANCE_MB:
        return flag("Dom0 RAM Allocations", "Mismatched").with_detail(
            "Dom0 RAM Allocations", "\n".join("  %s  %.1fG" % (label, total / 1024.0)
                                              for label, total in readings))
    if unread:
        return unknown("Dom0 RAM Allocations", "Unknown - matched on %d of %d hosts, not "
                       "read: %s" % (len(readings), len(readings) + len(unread),
                                     ", ".join(unread)))
    if len(readings) < 2:
        return ok("Dom0 RAM Allocations", "N/A - Nothing to compare")
    return ok("Dom0 RAM Allocations", "Matched")


def pool_time_sync(hosts):
    """Every reachable host has NTP on, says it is synchronised, and agrees with this
    machine's clock inside TIME_SYNC_ALLOWANCE_SECS.

    "Mismatched" only for what was established - an explicit no, or a drift measured over
    the allowance - naming the host and why. A host whose state or clock was not read is
    Unknown with its reason: it was claimed as a mismatch before, which it was not known to
    be. With no host read at all there is nothing to call matched.
    """
    bad, unread = [], []
    for host in hosts:
        state = host.ntp_state()
        if state.get("error") or "Unknown" in (state["ntp"], state["sync"]):
            unread.append("%s (%s)" % (host.label, state.get("error") or
                                       "NTP state not in timedatectl's output"))
            continue
        if state["ntp"] != "yes" or state["sync"] != "yes":
            bad.append("%s: NTP enabled %s, synchronised %s"
                       % (host.label, state["ntp"], state["sync"]))
            continue
        drift = host.clock_drift()
        if drift is None:
            unread.append("%s (its clock was not read)" % host.label)
        elif drift > config.TIME_SYNC_ALLOWANCE_SECS:
            bad.append("%s: %ds from this machine's clock (allowed %ds)"
                       % (host.label, int(drift), config.TIME_SYNC_ALLOWANCE_SECS))
    if bad:
        detail = list(bad)
        if unread:
            detail.append("not read: " + "; ".join(unread))
        return flag("Pool Time Synchronization", "Mismatched").with_detail(
            "Pool Time Synchronization", "\n".join("  " + d for d in detail))
    if unread:
        return unknown("Pool Time Synchronization", "Unknown - not read: %s"
                       % "; ".join(unread))
    if not hosts:
        return unknown("Pool Time Synchronization", "Unknown (no host was read)")
    return ok("Pool Time Synchronization", "Matched")


# --------------------------------------------------------------------------------------
# gated per-host checks
# --------------------------------------------------------------------------------------

def dom0_disk_usage(host):
    """Local filesystems over DOM0_MAX_USED. The collector reads usage without df, from
    /proc/mounts and statvfs, so a dead network mount can neither hang this line nor
    leave a df behind; a local mount it could not read makes a clean answer Unknown."""
    f = host.fact("df")
    if not f.ok:
        return unknown("Dom0 Disk Usage", "Unknown (%s)" % f.error)
    v = f.value
    text, failed = ((v.get("text") or "", v.get("failed") or []) if isinstance(v, dict)
                    else (v or "", []))
    bad = parsers.parse_df(text, config.DOM0_MAX_USED)
    if bad:
        return flag("Dom0 Disk Usage", "Fail", " - " + ", ".join(bad))
    if failed:
        return unknown("Dom0 Disk Usage", "Unknown - could not read %s" % ", ".join(failed))
    return ok("Dom0 Disk Usage", "OK")


def read_only_filesystems(host):
    """A filesystem that should be writable and is mounted read-only.

    That is mostly the kernel's answer to an I/O error it could not get past
    (errors=remount-ro), and every write there fails from then on: /var/log stops logging,
    a local SR stops taking VM writes. /proc/mounts says what is in effect, and fstab says
    what was asked for, which is what keeps the read-only mounts a dom0 makes on purpose
    out of it. The root filesystem is judged whatever fstab says, and a /proc/mounts with
    no root in it is not read as a clean one. Without fstab the host's other filesystems
    are not judged, so a clean answer is Unknown, while a read-only mount found anyway is
    still reported.
    """
    mounts = host.fact("proc_mounts")
    if not mounts.ok:
        return unknown("Read-Only Filesystems", "Unknown (%s)" % mounts.error)
    fstab = host.fact("fstab")
    bad = parsers.read_only_mounts(mounts.value, fstab.value if fstab.ok else None,
                                   config.RO_FS_SR_DIRS, config.RO_FS_EXTRA,
                                   config.RO_FS_NATIVE_RO)
    if bad is None:
        return unknown("Read-Only Filesystems", "Unknown (/proc/mounts names no root filesystem)")
    if bad:
        return flag("Read-Only Filesystems", "Yes",
                    " - " + ", ".join(_ro_name(row) for row in bad)).with_detail(
            "Read-Only Filesystems", _ro_detail(bad, fstab, host.fact("dmesg")))
    if not fstab.ok:
        return unknown("Read-Only Filesystems", "Unknown (%s)" % fstab.error)
    return ok("Read-Only Filesystems", "None")


def _ro_name(row):
    for d in config.RO_FS_SR_DIRS:
        if row["target"].startswith(d):
            return "SR %s" % row["target"][len(d):][:8]
    return row["target"]


def _ro_detail(bad, fstab, dmesg):
    lines = []
    for row in bad:
        asked = "; fstab asks for %s" % row["fstab"] if row["fstab"] else ""
        lines.append("  %s  %s on %s, mounted %s%s"
                     % (row["target"], row["type"], row["source"], row["options"], asked))
    if not fstab.ok:
        lines.append("  fstab was not read (%s), so only /, SR mounts and %s were judged"
                     % (fstab.error, ", ".join(config.RO_FS_EXTRA)))
    lines.append("The kernel remounts a filesystem read-only after an I/O error it cannot get "
                 "past (errors=remount-ro); every write to it fails from then on.")
    if not dmesg.ok:
        lines.append("dmesg was not read (%s)." % dmesg.error)
        return "\n".join(lines)
    said = [l.strip() for l in dmesg.value.splitlines()
            if any(p in l.lower() for p in config.RO_FS_DMESG)]
    devs = sorted(set(row["source"].rsplit("/", 1)[-1] for row in bad))
    about = [l for l in said if set(devs) & set(
        l.replace("(", " ").replace(")", " ").replace("-", " ").replace(":", " ").split())]
    if about:
        lines.append("What dmesg says about %s:" % ", ".join(devs))
        lines.extend("  " + l for l in about[-6:])
    elif said:
        # a device-mapper source shows up in dmesg as dm-N, which /proc/mounts does not
        # name, so these may well be about it - or about something else entirely
        lines.append("dmesg has lines about a filesystem going read-only, none naming %s:"
                     % ", ".join(devs))
        lines.extend("  " + l for l in said[-6:])
    else:
        lines.append("dmesg holds no line about a filesystem going read-only: the ring may "
                     "have wrapped since, and kern.log may still have it.")
    return "\n".join(lines)


def dom0_memory(host):
    """Two lines from one fact. A percentage computed off a missing meminfo used to read
    exactly like a healthy host, with only an stderr line to say otherwise."""
    mem = host.memory()
    if mem is None:
        return [unknown("Dom0 Memory", "Unknown"),
                unknown("Dom0 Memory Usage", "Unknown (could not read host memory)")]
    total_mb, used_mb = mem
    total_gb = total_mb / 1024.0
    pct = (used_mb / float(total_mb)) * 100 if total_mb else 0.0
    lines = [info("Dom0 Memory", "%.1fG" % total_gb)]
    # rounded to one decimal FIRST, then to the nearest whole percent - the printed value
    # is what the threshold is applied to, so the two can never disagree at the boundary
    if int(round_1dp(pct) + 0.5) > config.DOM0_MEM_USED_MAX_PCT:
        lines.append(flag("Dom0 Memory Usage", "%.1f%%" % pct))
    else:
        lines.append(ok("Dom0 Memory Usage", "%.1f%%" % pct))
    return lines


def mtu_issues(host):
    f = host.fact("dmesg")
    if not f.ok:
        return unknown("MTU Issues", "Unknown (could not read dmesg)")
    found = parsers.find_mtu_keywords(f.value, config.MTU_DMESG_KEYWORDS,
                                      config.DMESG_IGNORE_RULES)
    if not found:
        return ok("MTU Issues", "None")
    # every matching keyword is named, so the line says which one tripped it
    listed = ", ".join("'%s'" % k for k in found)
    return flag("MTU Issues", "Detected (%s), check output from dmesg -T" % listed)


def dmesg_block(text, hits, rollup=True):
    """Every detail block cut from the dmesg ring is rendered one way: LOG_ERROR_CONTEXT
    lines of context, the rollup of repeated lines, and the cap - rolled up AND bounded,
    because the rollup folds a ring full of one message and the cap is for a ring full of
    thousands of different ones (see parsers.truncate_block). Both settings live in config
    and reach every line that reads the ring through here."""
    return parsers.context_block(text, hits, config.LOG_ERROR_CONTEXT, rollup=rollup,
                                 max_lines=config.DMESG_MAX_LINES,
                                 rollup_min=config.DMESG_ROLLUP_MIN)


def dmesg_content_of(text):
    """The 'Dmesg Content' line for a ring already in hand.

    The XOA section reads the appliance's own ring and used to carry a copy of this - one
    reading and one wording for the host line and the appliance line."""
    hits = parsers.dmesg_issue_lines(text, config.DMESG_ISSUE_WORDS,
                                     config.DMESG_ISSUE_PHRASES, config.DMESG_IGNORE_RULES)
    if not hits:
        return ok("Dmesg Content", "Clean")
    return flag("Dmesg Content", "Issues Found, See Output Below").with_detail(
        "Dmesg Issues", dmesg_block(text, hits))


def dmesg_content(host):
    f = host.fact("dmesg")
    if not f.ok:
        return unknown("Dmesg Content", "Unknown (could not read dmesg)")
    return dmesg_content_of(f.value)


def oom_events(host):
    f = host.fact("dmesg")
    if not f.ok:
        return unknown("OOM Events", "Unknown (could not read dmesg)")
    hits = parsers.find_phrase_lines(f.value, config.OOM_PHRASE)
    if not hits:
        return ok("OOM Events", "No")
    # the same ring, so the same bound: a host that has been killing processes all week
    # shows its most recent kills, not every one of them. No rollup: every kill names its
    # own pid, so there is nothing to fold
    return flag("OOM Events", "Yes, See Below").with_detail(
        "OOM Events", dmesg_block(f.value, hits, rollup=False))


def crash_logs(host):
    f = host.fact("crash_dumps")
    if not f.ok:
        return unknown("Crash Logs Present", "Unknown (%s)" % f.error)
    if f.value["count"]:
        if f.value["latest"]:
            return flag("Crash Logs Present",
                        "Yes (newest %s) - check /var/crash" % f.value["latest"])
        return flag("Crash Logs Present", "Yes - check /var/crash")
    return ok("Crash Logs Present", "No")


def task_timeout_override(host):
    """Is xapi's pending_task_timeout overridden by a drop-in on this host?

    A fact about the configuration, not a finding: an override is a normal thing for
    support to have set deliberately, so 'Yes' is yellow and exit-code neutral - the same
    class as 'XOSTOR In Use: Yes'. The values are echoed because which one it is, is the
    whole content of the line.

    'Unknown' is a departure from the bash script this came from, which printed no line at
    all when the read failed. A missing line reads as 'not applicable', which is a claim
    of its own - and there it also flagged the exit code while saying nothing.
    """
    f = host.fact("task_timeout")
    if not f.ok:
        return unknown("XAPI Task Timeout Override", "Unknown (%s)" % f.error)
    values = f.value or []
    if not values:
        return ok("XAPI Task Timeout Override", "No")
    return info("XAPI Task Timeout Override", "Yes - " + ",".join(values), "yellow")


def coredumps(host):
    """Anything in the systemd coredump drop dir means a dom0 process died. The filename
    is the payload - systemd names them core.<comm>.<...> - so the list says WHICH."""
    f = host.fact("coredumps")
    if not f.ok:
        return unknown("Coredumps Present", "Unknown (%s)" % f.error)
    rows = f.value or []
    if not rows:
        return ok("Coredumps Present", "No")
    shown = parsers.cap_lines(rows, config.COREDUMP_MAX_LINES, "older coredump(s)")
    return flag("Coredumps Present", "Yes - %d file(s), see below" % len(rows)).with_detail(
        "Coredumps (%s)" % config.COREDUMP_DIR, "\n".join(shown))


def host_collection(host):
    """Printed only when the host's collector stopped part way - stuck on a command it
    could not kill, or failed - and sent back what it had. A complete document prints
    nothing here: None is "no line", and a host that answered whole needs none."""
    why = (host.payload or {}).get("__incomplete__")
    if not why:
        return None
    return flag("Host Collection", "Incomplete", " - " + why)


def failed_units(host):
    """A systemd unit in the failed state: a service that did not start, or died since.

    systemctl's own answer, with the units FAILED_UNITS_IGNORE matches left out - SM's GC
    runs, whose health is judged from SMlog rather than from the state of the last run's
    unit, and the units expected to sit failed (XOSTOR's database resource on the hosts
    that do not hold it, mcelog on AMD). A unit stays failed until it is started again,
    reset or the host reboots, so the finding can be days old: the detail says what
    systemd says, and that is all it claims.

    attach-static-vdis is left out only when its failure was about nothing: no static-VDI
    entry existed when it failed (a host booted with HA off, which its script fails on
    before xen-api ae4d3ec4). When that is not established it stays in, and says why.
    """
    f = host.fact("failed_units")
    if not f.ok:
        return unknown("Failed Systemd Units", "Unknown (%s)" % f.error)
    units = [(u, d) for u, d in parsers.parse_failed_units(f.value)
             if not parsers.unit_ignored(u, config.FAILED_UNITS_IGNORE)]
    notes = []
    if any(u == config.STATIC_VDIS_UNIT for u, _d in units):
        sv, boot = host.fact("static_vdis"), host.fact("boot_epoch")
        moot = parsers.static_vdis_failure_moot(sv.value if sv.ok else None,
                                                boot.value if boot.ok else None)
        if moot:
            units = [x for x in units if x[0] != config.STATIC_VDIS_UNIT]
        elif moot is False:
            notes.append("%s failed while a static-VDI entry already existed: a VDI HA needs "
                         "(statefile or metadata) did not attach at boot" % config.STATIC_VDIS_UNIT)
        else:
            notes.append("whether %s failed about anything was not established (%s), so it is "
                         "reported" % (config.STATIC_VDIS_UNIT,
                                       sv.error if not sv.ok else boot.error if not boot.ok
                                       else "an entry's creation time or the exit time was not read"))
    if not units:
        return ok("Failed Systemd Units", "None")
    lines = ["  %s  %s" % (parsers.unit_display(u), d) for u, d in units]
    lines.extend("  " + n for n in notes)
    lines.append("systemctl status <unit> says when and why; systemctl reset-failed <unit> "
                 "clears one that no longer matters.")
    return flag("Failed Systemd Units", "Yes",
                " - " + ", ".join(parsers.unit_display(u) for u, _d in units)).with_detail(
        "Failed Systemd Units", "\n".join(lines))


def lacp(host):
    """rc 0 with empty output means 'no LACP bonds'; a failure means ovs-vswitchd is not
    answering. Collapsing those into one green 'No' made a host whose OVS was down read
    as healthy."""
    f = host.fact("lacp")
    if not f.ok:
        return unknown("LACP Negotiation Issues", "Unknown (could not query Open vSwitch)")
    text = f.value
    if not text.strip():
        return ok("LACP Negotiation Issues", "No")
    if parsers.parse_lacp(text):
        return flag("LACP Negotiation Issues", "Yes, See Below").with_detail(
            "LACP Output", text)
    return ok("LACP Negotiation Issues", "No")


def tap_status(host):
    """A timed-out 'tap-ctl list' means blktap itself is wedged - distinct from every
    other failure of that call, so it gets its own message rather than a generic Unknown.

    The green value says 'Responding' and counts the rows, because responding is the whole
    of what the call established. It deliberately does not read the per-tapdisk 'state='
    field: blktap offers 'tap-ctl pause'/'unpause' as ordinary operations, so SMAPI parks
    tapdisks in non-zero states during snapshot and coalesce, and judging that number would
    flag a healthy host through every backup window. The count is evidence rather than a
    verdict - a host that should have tapdisks and reports zero is visible in the report
    without this line having to guess what the right number is.
    """
    f = host.fact("tap_status")
    if f.ok:
        rows = [ln for ln in (f.value or "").splitlines() if ln.strip()]
        return ok("Tapdisk Status", "Responding (%d tapdisk(s))" % len(rows))
    if "timed out" in (f.error or ""):
        return unknown("Tapdisk Status", "Timeout issues, unable to determine tap status")
    return unknown("Tapdisk Status", "Unknown (%s)" % f.error)


def _maps(count):
    """'1 map' / '3 maps'. Each count gets its own word: pluralising every phrase off the
    total once printed 'no usable path on 1 maps'."""
    return "%d map" % count if count == 1 else "%d maps" % count


def _multipath_detail(summary, unmanaged, rechecked):
    """One block per map, then anything device-mapper holds that multipathd does not."""
    lines = []
    for entry in summary["maps"]:
        usable = entry["ok"] + entry["standby"]
        head = "%s (%d/%d path(s) usable" % (entry["name"], usable, len(entry["paths"]))
        if entry["dm_st"]:
            head += ", dm-st %s" % entry["dm_st"]
        if entry["queueing"]:
            head += ", queueing %s" % entry["queueing"]
        if entry["path_faults"]:
            head += ", %d path failure(s) since map load" % entry["path_faults"]
        if entry["map_failures"]:
            head += ", %d all-paths-down event(s)" % entry["map_failures"]
        if not entry["listed"]:
            head += ", NOT LISTED BY multipathd"
        lines.append("--- %s) ---" % head)
        rows = []
        for path in entry["paths"]:
            row = "  %-6s %-6s %-7s %-7s %-8s prio=%s" % (
                path["dev"], path["dev_t"], path["dm_st"], path["chk_st"],
                path["dev_st"], path["prio"])
            if path["state"] == "bad":
                row += "   <- NOT USABLE"
            elif path["state"] == "standby":
                row += "   (standby)"
            rows.append(row)
        if not rows:
            rows.append("  (no paths)")
        lines.extend(parsers.cap_lines(rows, config.MULTIPATH_MAX_LINES, "path(s) not listed"))
        lines.append("")
    if unmanaged:
        lines.append("--- in device-mapper but not managed by multipathd ---")
        lines.extend(["  " + name for name in unmanaged])
        lines.append("")
    if rechecked:
        lines.append("(a path was mid-check, so this state was read a second time)")
    return "\n".join(lines).rstrip("\n")


def _multipath_read(host):
    """(summary, unmanaged, rechecked, reason).

    summary is None when nothing could be established, and `reason` says why - the pool
    line needs exactly the same judgement as the per-host one, and two copies of it would
    be two chances to disagree about what counts as an answer.
    """
    f = host.fact("multipath")
    if not f.ok:
        return None, [], False, f.error
    node = f.value or {}
    daemon = result.wrap(node, "daemon")
    dm = result.wrap(node, "dm")
    maps_f = result.wrap(node, "maps")
    paths_f = result.wrap(node, "paths")
    rechecked = result.wrap(node, "rechecked")

    dm_maps = parsers.parse_dm_multipath_maps(dm.value) if dm.ok else None

    if not daemon.ok or not parsers.multipathd_alive(daemon.value):
        extra = ""
        if dm_maps:
            # the dangerous version of a dead daemon: the maps exist, so I/O is still
            # being routed down paths nothing is checking or failing over
            extra = "; %d map(s) present in device-mapper" % len(dm_maps)
        return None, [], False, "multipathd is not answering%s" % extra

    if not maps_f.ok:
        return None, [], False, maps_f.error
    if not paths_f.ok:
        return None, [], False, paths_f.error
    if parsers.MP_HELP_MARKER in (maps_f.value or "") or \
            parsers.MP_HELP_MARKER in (paths_f.value or ""):
        # rc 0 plus the help text is how multipathd rejects a query it does not
        # understand, so rc cannot be trusted to tell a refused query from an empty one
        return None, [], False, "multipathd did not accept the query"

    summary = parsers.multipath_summary(
        parsers.parse_multipath_paths(paths_f.value),
        parsers.parse_multipath_maps(maps_f.value),
        config.MULTIPATH_OK_DM_STATES, config.MULTIPATH_OK_CHK_STATES,
        config.MULTIPATH_OK_DEV_STATES, config.MULTIPATH_STANDBY_CHK_STATES)

    known = set(entry["name"] for entry in summary["maps"])
    if dm_maps is None:
        # the kernel's side was not read: unmanaged is None - "not looked for" - and never
        # an empty list, which would read as "looked, there are none"
        return (summary, None, bool(rechecked.ok and rechecked.value),
                "dmsetup ls --target multipath was not read (%s)" % dm.error)
    unmanaged = [name for name in dm_maps if name not in known]
    return summary, unmanaged, bool(rechecked.ok and rechecked.value), None


def multipath_health(host):
    """The paths themselves, as opposed to `Multipathing`, which is the xapi setting.

    Green here needs three things established: that multipathd answered at all, what it
    says about every path of every map, and - for the "there is simply no multipath here"
    answer - that the kernel agrees there are no maps. An empty answer from a daemon that
    is not running looks exactly like a host with no multipath, and that is the shape of
    every silent green this tool has ever shipped.
    """
    summary, unmanaged, rechecked, reason = _multipath_read(host)
    if summary is None:
        return unknown("Multipath Path Health", "Unknown (%s)" % reason)
    dm_unread = unmanaged is None
    unmanaged = unmanaged or []
    detail = _multipath_detail(summary, unmanaged, rechecked)

    if not summary["maps"]:
        if unmanaged:
            return flag("Multipath Path Health",
                        "%d device-mapper map(s) multipathd does not manage, See Below"
                        % len(unmanaged)).with_detail("Multipath Paths", detail)
        if dm_unread:
            # an alive multipathd answering empty is exactly what a daemon that came up
            # without adopting the kernel's maps looks like: without the kernel's side
            # there is no telling it from a host with no multipath, so no green
            return unknown("Multipath Path Health", "Unknown - multipathd lists no maps, "
                                                    "but %s" % reason)
        return ok("Multipath Path Health", "N/A - No multipath maps")

    usable = summary["ok_paths"] + summary["standby_paths"]
    total = summary["total_paths"]

    problems = []
    if summary["dead_maps"]:
        problems.append("no usable path on %s" % _maps(len(summary["dead_maps"])))
    if summary["bad_paths"]:
        problems.append("%d of %d path(s) not usable" % (summary["bad_paths"], total))
    if summary["suspended_maps"]:
        problems.append("%s suspended" % _maps(len(summary["suspended_maps"])))
    if unmanaged:
        problems.append("%s multipathd does not manage" % _maps(len(unmanaged)))
    if problems:
        # a map with nothing left to send I/O down is not degraded, it is down: I/O is
        # queueing or erroring on it right now, which is a different phone call
        lead = "Down" if summary["dead_maps"] else "Degraded"
        return flag("Multipath Path Health",
                    "%s - %s, See Below" % (lead, ", ".join(problems))
                    ).with_detail("Multipath Paths", detail)

    text = "OK - %d/%d paths usable on %s" % (usable, total, _maps(len(summary["maps"])))
    if summary["standby_paths"]:
        # normal on an active/passive array, and worth saying out loud so nobody reads
        # 4/4 and assumes four paths are carrying I/O
        text += " (%d standby)" % summary["standby_paths"]
    if dm_unread:
        # every path multipathd knows is fine; what it does not know was not looked for
        text += " - maps multipathd does not manage not looked for (dmsetup not read)"
    return ok("Multipath Path Health", text)


def multipath_path_counts(hosts):
    """Every host's view of the same LUN, compared.

    The per-host line can only say whether a path is up; it cannot know how many there
    are meant to be. Two hosts of one pool looking at one SAN can: a host that sees one
    path where its peers see two is a missing session, a dead HBA or a NIC that never came
    up - the "iSCSI multipath not connected on one host" case - and it is invisible from
    the host itself, where one working path looks perfectly healthy.

    Counts CONFIGURED paths, not usable ones: a failed path is still a row (measured), so
    a path failure moves the per-host line and leaves this one alone, which is what keeps
    the two lines from reporting the same fault twice in different words.
    """
    known, unreadable = [], []
    for host in hosts:
        summary, _unmanaged, _rechecked, _reason = _multipath_read(host)
        if summary is None:
            unreadable.append(host)
            continue
        known.append((host, dict((entry["name"], len(entry["paths"]))
                                 for entry in summary["maps"])))

    caveat = ""
    if unreadable:
        # every one of these already has its own Unknown in its host block, so this line
        # reports what it CAN compare rather than throwing the comparison away
        caveat = " (%d of %d hosts readable)" % (len(known), len(known) + len(unreadable))

    if not known:
        return unknown("Multipath Path Counts",
                       "Unknown (no host's multipath state could be read)")
    if not any(maps for _host, maps in known):
        return ok("Multipath Path Counts", "N/A - No multipath maps in pool" + caveat)
    if len(known) < 2:
        return ok("Multipath Path Counts", "N/A - Nothing to compare" + caveat)

    all_maps = sorted(set(name for _host, maps in known for name in maps))
    blocks, mismatched = [], 0
    for name in all_maps:
        counts = [(host, maps.get(name)) for host, maps in known]
        highest = max(count for _host, count in counts if count is not None)
        if all(count == highest for _host, count in counts):
            continue
        mismatched += 1
        blocks.append("--- %s ---" % name)
        for host, count in counts:
            if count is None:
                blocks.append("  %s: map not present" % host.label)
            elif count < highest:
                blocks.append("  %s: %d path(s)   <- fewer than %d" % (host.label, count,
                                                                       highest))
            else:
                blocks.append("  %s: %d path(s)" % (host.label, count))
        blocks.append("")
    if not mismatched:
        return ok("Multipath Path Counts", "Matched" + caveat)
    return flag("Multipath Path Counts",
                "Mismatched on %d map(s), See Below%s" % (mismatched, caveat)
                ).with_detail("Multipath Path Counts", "\n".join(blocks).rstrip("\n"))


def _dmesg_phrase_blocks(text, phrases, ctx):
    """The most recent hit of each phrase in the dmesg ring, shaped like a log-scan block.

    Same shape and same "last occurrence with context" rule as the file scanner, so both
    sources render through one renderer and read the same way.
    """
    text = text or ""
    lines = text.splitlines()
    blocks = []
    for phrase in phrases:
        hits = parsers.find_phrase_lines(text, phrase)
        if not hits:
            continue
        label = "dmesg ring"
        if len(hits) > 1:
            # the count is the point: one blip and a fabric that flaps daily look
            # identical when only the newest line is shown
            label += ", %d occurrences, most recent shown" % len(hits)
        n = hits[-1]
        start, end = max(1, n - ctx), min(len(lines), n + ctx)
        blocks.append({"phrase": phrase, "file": label, "line": n,
                       "context": lines[start - 1:end]})
    return blocks


def multipath_events(host):
    """Kernel-side, timestamped path failures - what the current-state check cannot see.

    Read from BOTH sources, because neither contains the other:

      * `kern.log` + its rotation - survives a reboot, but is a ~2-rotation window, and on
        a quiet dom0 the live file is routinely 0 bytes with everything in `.1`.
      * the **dmesg ring** - covers the whole uptime on a quiet host (measured on 8.3.0:
        70 KB, unwrapped, back to the boot three days earlier, holding path failures that
        were in NEITHER kern.log file), but wraps on a busy one and is gone after a reboot.

    So an event can be in either, or both. Both are shown, each labelled with where it came
    from, and no attempt is made to merge them: `dmesg -T` recomputes its timestamps from
    (now - uptime) on every run, so the same failure is stamped a second or two away from
    syslog's copy and cannot be matched on reliably.

    Deliberately not the per-map path_faults counter, which never resets until the map
    reloads: that would leave a permanent yellow behind a switch reboot last month. These
    two windows both close by themselves.
    """
    blocks, failed = _scan_result(host.fact("multipath_scan"))
    dmesg = host.fact("dmesg")

    if dmesg.ok:
        blocks = blocks + _dmesg_phrase_blocks(dmesg.value, config.MULTIPATH_EVENT_PHRASES,
                                               config.LOG_ERROR_CONTEXT)
    if blocks:
        # a finding is established whatever the other source did or did not manage to say
        detail = _render_scan_blocks(blocks, failed)
        if len(blocks) > 1:
            detail += ("\n\n(the same event can appear under both sources - dmesg -T "
                       "recomputes its timestamps each run, so they sit a second or two "
                       "from syslog's)")
        return flag("Multipath Path Events", "Yes, See Error Output").with_detail(
            "Multipath Path Events", detail)
    # nothing found, so every source has to have actually been read before this is a "None"
    if failed:
        return unknown("Multipath Path Events", "Unknown (%s)" % "; ".join(failed))
    if not dmesg.ok:
        return unknown("Multipath Path Events", "Unknown (could not read dmesg)")
    return ok("Multipath Path Events", "None")


def silly_mtus(host):
    f = host.fact("iplink")
    if not f.ok:
        return unknown("Silly MTUs", "Unknown (%s)" % f.error)
    odd = ["%s=%s" % (name, mtu) for name, mtu in parsers.parse_link_mtus(f.value)
           if mtu != "1500"]
    if odd:
        return flag("Silly MTUs", "Yes", " - Non-standard MTUs found: " + ", ".join(odd))
    return ok("Silly MTUs", "OK - All 1500")


def dns_gw_non_mgmt_pifs(host):
    f = host.fact("pifs_dns_gw")
    if not f.ok:
        return unknown("DNS/GW on Non-Mgmt PIFs", "Unknown (%s)" % f.error)
    if parsers.parse_dns_gw_pifs(f.value):
        return flag("DNS/GW on Non-Mgmt PIFs", "Yes")
    return ok("DNS/GW on Non-Mgmt PIFs", "No")


def overlapping_subnets(host):
    f = host.fact("ipaddr")
    if not f.ok:
        return unknown("Overlapping Subnets", "Unknown (%s)" % f.error)
    if parsers.has_overlapping_subnets(parsers.parse_ipv4_addrs(f.value)):
        return flag("Overlapping Subnets", "Yes")
    return ok("Overlapping Subnets", "No")


def duplicate_ips(host):
    """One address on two interfaces of this host - two NICs, or a NIC and a bridge, both
    answering for it. Overlapping Subnets trips on that too, but cannot say which address
    or where; this names both. Both families; loopback and link-local are left out (see
    parsers.parse_ip_addrs)."""
    f = host.fact("ipaddr")
    if not f.ok:
        return unknown("Duplicate IPs", "Unknown (%s)" % f.error)
    dups = parsers.duplicate_addresses(parsers.parse_ip_addrs(f.value))
    if not dups:
        return ok("Duplicate IPs", "None")
    return flag("Duplicate IPs", "Yes", " - " + "; ".join(
        "%s on %s" % (addr, ", ".join(names)) for addr, names in dups))


def duplicate_ips_across_hosts(hosts, xoa_addrs=None):
    """One address on two machines: two pool hosts, or a host and the XOA.

    hosts is every host in scope, reachable or not; an unreachable one is named as not
    compared (Unreachable Hosts flags it already), while a reachable host whose addresses
    could not be read leaves a clean answer Unknown - it is one of the machines the
    comparison is about. xoa_addrs is the appliance's own 'ip -o addr show' as a Fact, or
    None in a host run, which has no XOA. Each machine counts once per address: one address
    twice on one machine is the host line's finding, not this one's.
    """
    machines, unread, unreachable = [], [], []
    for h in hosts:
        if not h.reachable:
            unreachable.append(h.address)
            continue
        f = h.fact("ipaddr")
        if f.ok:
            machines.append((h.label, parsers.parse_ip_addrs(f.value)))
        else:
            unread.append("%s (%s)" % (h.label, f.error))
    host_count = len(machines)
    if xoa_addrs is not None:
        if xoa_addrs.ok:
            machines.append(("this XOA", parsers.parse_ip_addrs(xoa_addrs.value)))
        else:
            unread.append("this XOA (%s)" % xoa_addrs.error)

    owners = {}
    for label, entries in machines:
        for ifname, addr in entries:
            names = owners.setdefault(addr, {}).setdefault(label, [])
            if ifname not in names:
                names.append(ifname)
    clashes = sorted((addr, o) for addr, o in owners.items() if len(o) > 1)

    scope = _plural(host_count, "host") + (" + this XOA" if len(machines) > host_count else "")
    tail = ""
    if unreachable:
        tail = ", %s not compared (unreachable)" % " ".join(unreachable)
    if clashes:
        lines = []
        for addr, o in clashes:
            lines.append("  %s" % addr)
            for label in sorted(o):
                lines.append("    %s  (%s)" % (label, ", ".join(o[label])))
        if unread:
            lines.append("  not read: " + "; ".join(unread))
        return flag("Duplicate IPs Across Hosts", "Yes", " - " + ", ".join(addr for addr, _o in clashes)).with_detail(
            "Duplicate IPs Across Hosts", "\n".join(lines))
    if unread:
        return unknown("Duplicate IPs Across Hosts", "Unknown - none among %s, but not read: %s"
                       % (scope, "; ".join(unread)))
    if len(machines) < 2:
        return ok("Duplicate IPs Across Hosts", "N/A - Nothing to compare" + tail)
    return ok("Duplicate IPs Across Hosts", "None (%s, %d address%s)%s"
              % (scope, len(owners), "" if len(owners) == 1 else "es", tail))


def _scan_result(f):
    """(blocks, failed) of a log-scan fact. `failed` names every scan that did not happen;
    a fact that is itself an error is one failure with its reason. Nothing found plus
    anything failed is not "nothing found". (An older collector's plain list of blocks
    recorded no failures - it could not tell them apart.)"""
    if not f.ok:
        return [], [f.error]
    v = f.value
    if isinstance(v, dict):
        return list(v.get("blocks") or []), list(v.get("failed") or [])
    return list(v or []), []


def _render_scan_blocks(blocks, failed=None):
    """The scanner's blocks, laid out the way the report has always shown them, and the
    scans that did not happen after them - a finding stands, but the reader is told what
    was not looked at."""
    out = []
    for block in blocks:
        out.append("--- %s (%s) ---" % (block["phrase"], block["file"]))
        if block.get("note"):
            out.append("  (%s - the matching line alone)" % block["note"])
        for line in block["context"]:
            out.append("  " + line)
        out.append("")
    if failed:
        out.append("Not read: " + "; ".join(failed))
    # blocks are separated by a blank line, but the blob itself does not end with one:
    # the detail printer adds its own spacing
    return "\n".join(out).rstrip("\n")


def log_errors(host):
    blocks, failed = _scan_result(host.fact("log_scan"))
    if blocks:
        return flag("Log Errors", "Yes, See Error Output").with_detail(
            "Log Errors", _render_scan_blocks(blocks, failed))
    if failed:
        return unknown("Log Errors", "Unknown (%s)" % "; ".join(failed))
    return ok("Log Errors", "None")


def lun_assignments(host):
    blocks, failed = _scan_result(host.fact("lun_scan"))
    if blocks:
        return flag("LUN Assignments", "Changed - see below").with_detail(
            "LUN Assignment Changes", _render_scan_blocks(blocks, failed))
    if failed:
        return unknown("LUN Assignments", "Unknown (%s)" % "; ".join(failed))
    return ok("LUN Assignments", "Unchanged")


def smapi_hidden_leaves(host):
    f = host.fact("smapi")
    if not f.ok:
        return unknown("SMAPI Hidden Leaves", "Unknown (%s)" % f.error)
    if not f.value:
        return ok("SMAPI Hidden Leaves", "None")
    return flag("SMAPI Hidden Leaves", "Yes, See Error Output").with_detail(
        "SMAPI Hidden Leaves", "\n".join(f.value))


def rebooted_after_updates(host):
    """Both dates print as evidence: the pair IS the answer. A bare Yes/No beside a
    'Last Patched' line derived differently is what made this look self-contradictory."""
    boot = host.fact("boot_epoch")
    upd = host.fact("update_epoch")
    boot_disp = host.fact("boot_disp")
    upd_disp = host.fact("update_disp")

    if not boot.ok or not boot.value:
        return unknown("Rebooted After Updates", "Unknown (could not read boot time)")

    if not upd.ok or not upd.value:
        # rpm is still a backstop: if nothing at all has been installed since boot then
        # certainly no update has. If something HAS landed we cannot tell what kind it
        # was, and that is an Unknown, not a green Yes off no evidence.
        newest = host.fact("newest_rpm")
        if newest.ok and newest.value and boot.value >= newest.value:
            return ok("Rebooted After Updates",
                      "Yes (nothing installed since boot %s)" % (boot_disp.value or ""))
        return unknown("Rebooted After Updates",
                       "Unknown (no update found in yum.log or yum.log.1)")

    pair = "updated %s, booted %s" % (upd_disp.value or "?", boot_disp.value or "?")
    if boot.value >= upd.value:
        return ok("Rebooted After Updates", "Yes (%s)" % pair)
    return flag("Rebooted After Updates", "No (%s)" % pair)


def yum_patch_level(host, is_master, master_manifest):
    """Every host's manifest is fetched once and hashed here, so both sides of the
    comparison are always the same bytes through the same digest. Hashing remotely and
    re-fetching on mismatch meant two different snapshots, which produced a
    'Mismatch, See Below' over an empty difference block."""
    if is_master:
        own = host.fact("rpm_manifest")
        if not own.ok or not (own.value or "").strip():
            # the green value claims a baseline exists, and every slave is Unknown "no
            # baseline" for exactly this reason - the master's line has to say so too
            return unknown("Yum Patch Level", "Unknown (the master's package list could not "
                                              "be read, so no host was compared)")
        # guarded like the slaves' Match line: unguarded, -f showed the master's baseline
        # while hiding every slave's passing line, reading as though they were not checked
        return ok("Yum Patch Level", "Reference (Master)")
    if not master_manifest:
        return unknown("Yum Patch Level", "Unknown (no baseline)")
    f = host.fact("rpm_manifest")
    if not f.ok or not f.value.strip():
        return unknown("Yum Patch Level", "Unknown (could not retrieve)")
    if f.value == master_manifest:
        return ok("Yum Patch Level", "Match")
    diff = parsers.manifest_diff(master_manifest, f.value)
    shown = parsers.cap_lines(diff, config.PKG_DIFF_MAX_LINES, "more difference(s)")
    summary = parsers.manifest_diff_summary(diff)
    status = "Mismatch (%s), See Below" % summary if summary else "Mismatch, See Below"
    return flag("Yum Patch Level", status).with_detail(
        "Yum Patch Level Differences", "\n".join(shown))


def _xostor_signature(host):
    """(tracked package versions, loaded drbd version) for one host, or None when either
    fact is missing - unknown is not a difference, same rule as the RAM and NTP lines."""
    manifest = host.fact("rpm_manifest")
    module = host.fact("drbd_module")
    if not manifest.ok or not manifest.value.strip() or not module.ok:
        return None
    pkgs = parsers.manifest_packages(manifest.value)
    tracked = tuple((n, tuple(pkgs[n])) for n in config.XOSTOR_PACKAGES if n in pkgs)
    return tracked, module.value


def _drbd_stale(loaded, kmod_versions):
    """The running module is not any installed kmod-drbd - updated, not yet rebooted."""
    return parsers.leading_version(loaded) not in \
        [parsers.leading_version(v) for v in kmod_versions]


def xostor_version_consistency(hosts, details_shown=True):
    """One pool-level yes/no: do the hosts agree on XOSTOR package versions and the
    loaded DRBD module, and is each host running the kmod-drbd it has installed?

    Deliberately no detail - the per-host 'XOSTOR Packages' / 'XOSTOR DRBD Module' lines
    carry it. This line exists so a discrepancy is not missed by someone reading only
    the pool section. details_shown is False when those per-host lines are switched off
    for slaves, and then the line must not send the reader to look for them.
    """
    sigs = [s for s in (_xostor_signature(h) for h in hosts) if s is not None]
    if not sigs:
        return unknown("XOSTOR Version Consistency", "Unknown (could not read versions from any host)")
    stale = any(loaded and dict(tracked).get("kmod-drbd")
                and _drbd_stale(loaded, dict(tracked)["kmod-drbd"])
                for tracked, loaded in sigs)
    if stale or len(set(sigs)) > 1:
        return flag("XOSTOR Version Consistency", "Mismatched, See Host Results" if details_shown else "Mismatched")
    if len(sigs) < len(hosts):
        return unknown("XOSTOR Version Consistency", "Matched on %d of %d hosts (rest unreadable)"
                       % (len(sigs), len(hosts)))
    return ok("XOSTOR Version Consistency", "Matched")


def xostor_versions(host, pool_uses_xostor):
    """'XOSTOR Packages' and 'XOSTOR DRBD Module' for one host.

    Shown when the pool says XOSTOR is in use, or when this host carries DRBD/LINSTOR
    bits anyway - single mode has no pool view, and a host with a stray module loaded is
    worth seeing. The module line compares what is RUNNING (/sys/module/drbd/version)
    with what is INSTALLED (kmod-drbd): an updated kmod is inert until the next reboot,
    and a pool part-way through that is exactly when DRBD versions disagree.
    """
    manifest = host.fact("rpm_manifest")
    module = host.fact("drbd_module")
    pkgs = parsers.manifest_packages(manifest.value) if manifest.ok else {}
    tracked = [(n, pkgs[n]) for n in config.XOSTOR_PACKAGES if n in pkgs]
    loaded = module.value if module.ok else ""
    if not pool_uses_xostor and not tracked and not loaded:
        if module.ok:
            # DRBD established as not loaded on a pool that does not use XOSTOR: nothing to
            # say, whatever the manifest did (Yum Patch Level carries a failed one). The
            # mixed case used to fall through and FLAG "DRBD Module: Not Loaded" about a
            # feature this pool does not use
            return None
        if not manifest.ok:
            return None   # cannot tell whether XOSTOR applies; the pool line says if so
        # module unreadable means /sys/module/drbd exists: DRBD is here, so say so

    lines = []
    if not manifest.ok or not manifest.value.strip():
        lines.append(unknown("XOSTOR Packages", "Unknown (could not read rpm manifest)"))
    elif not tracked:
        lines.append(flag("XOSTOR Packages", "None Installed"))
    else:
        lines.append(info("XOSTOR Packages", ", ".join(
            "%s %s" % (n, " + ".join(v)) for n, v in tracked)))

    if not module.ok:
        lines.append(unknown("XOSTOR DRBD Module", "Unknown (%s)" % module.error))
        return lines
    kmod = pkgs.get("kmod-drbd") or []
    if not loaded:
        lines.append(flag("XOSTOR DRBD Module", "Not Loaded"))
        return lines
    if not manifest.ok:
        lines.append(unknown("XOSTOR DRBD Module", "Loaded %s (installed kmod-drbd unknown)" % loaded))
        return lines
    if not kmod:
        lines.append(flag("XOSTOR DRBD Module", "Loaded %s, but kmod-drbd is not installed" % loaded))
        return lines
    if not _drbd_stale(loaded, kmod):
        lines.append(ok("XOSTOR DRBD Module", "Loaded %s (matches kmod-drbd)" % loaded))
    else:
        lines.append(flag("XOSTOR DRBD Module", "Loaded %s, Installed kmod-drbd %s (reboot pending?)"
                          % (loaded, " + ".join(kmod))))
    return lines


# --------------------------------------------------------------------------------------
# pool-level
# --------------------------------------------------------------------------------------

def pool_host_list(state_db, seed, count):
    """Where the host list came from, when it was not xapi - and only then.

    Every 'Unreachable Hosts' and 'Hosts in Pool' figure is counted off this list, so a
    run that took it from a file has to say so: the file is a saved copy, and a host
    joined or ejected since it was written is not in it. A run whose list came from xapi
    has nothing to say here, and a green line saying so would be padding.
    """
    where = seed or "this host"
    path = state_db.get("path") or "state.db"
    if state_db.get("forced"):
        # asked for by name, so it is a warning worth keeping under -f, not a finding
        return info("Pool Host List",
                    "Read from %s on %s (HEALTH_HOST_LIST=statedb)" % (path, where), "yellow")
    # the variable parts - an error, a path, a timestamp - sit on lines of their own, so
    # the prose around them wraps the same whatever length they turn out to be
    detail = (
        "xapi on %s did not answer when asked for the pool's hosts:\n"
        "    %s\n"
        "\n"
        "so the hosts checked are the ones in its saved copy of the pool database:\n"
        "    %s, last written %s (%s's clock)\n"
        "\n"
        "A master writes that file itself and a slave holds the copy its master last sent\n"
        "it, so a host joined to or ejected from the pool since then is not reflected here.\n"
        "Host Enabled and Multipathing are only ever read from xapi, so they are Unknown\n"
        "for every host in this run."
        % (where, state_db.get("reason") or "no reason given", path,
           state_db.get("saved") or "at an unknown time", where))
    return unknown("Pool Host List",
                   "Unknown - xapi on %s did not answer, so %d host(s) were read from its "
                   "saved database, See Below" % (where, count)
                   ).with_detail("Pool Host List", detail)


def _pool_conf_target(pointer, hosts):
    """The member a slave's pool.conf points at, or None if it names none of them.

    xapi itself only ever writes an IP here: pool-join and emergency-reset-master resolve
    the address they were given first (Helpers.gethostbyname, via emergency_reset_master),
    and designate-new-master writes the new master's own address. So this is an address
    match in practice - but a hand-edited file may carry a name, and a slave pointing at
    its master by name must not read as pointing at nothing, so names are tried after the
    addresses. An FQDN is tried by its first label as well, since xapi's own hostname is
    usually the short one.
    """
    want = (pointer or "").strip().lower()
    if not want:
        return None
    for host in hosts:
        if host.address.lower() == want:
            return host
    parts = want.split(".")
    short = want if (len(parts) == 4 and all(p.isdigit() for p in parts)) else parts[0]
    for host in hosts:
        names = set(name.lower() for name in (host.hostname, host.name) if name)
        if want in names or short in names:
            return host
    return None


def _first_line(text):
    return ((text or "").replace("\r", "").strip().splitlines() or [""])[0].strip()


def pool_roles(hosts):
    """Every reachable member's pool.conf, judged against the others'.

    pool.conf is what xapi reads at startup to decide what it is - the master, a slave of
    some address, or broken - and it is a file, so this answers with the toolstack down on
    every host, which is exactly when it is wanted. A master change that failed part way
    leaves the pool in this state: hosts that disagree about who the master is, each xapi
    acting on its own copy, and none of them able to say so over the API.

    Only what holds whatever the addressing is flagged: more than one master; a host that
    says broken, or holds something xapi would read as broken; a slave pointing at itself,
    or at a host whose own pool.conf says it is not the master; slaves split between
    masters; and, when every host was reached, no master at all. A host that was not
    reached is not guessed at - 'Unreachable Hosts' already names it.

    The raw files are in the pool.conf block at the end of a full report. This line says
    whether they agree, and its detail carries them too, because -f drops that block.
    """
    reached = [h for h in hosts if h.reachable]
    if not reached:
        return unknown("Pool Roles", "Unknown (no host was reached)")

    entries, unread = [], []
    for host in reached:
        f = host.fact("pool_conf")
        if not f.ok:
            unread.append((host, f.error))
            continue
        role, pointer = parsers.parse_pool_conf(f.value)
        entries.append({"host": host, "role": role, "pointer": pointer,
                        "text": _first_line(f.value) or "(empty)",
                        "target": _pool_conf_target(pointer, hosts) if role == "slave"
                        else None})
    own = dict((e["host"], e) for e in entries)
    masters = [e["host"] for e in entries if e["role"] == "master"]
    slaves = [e for e in entries if e["role"] == "slave"]

    problems = []
    for e in entries:
        if e["role"] == "broken":
            problems.append("%s says broken" % e["host"].name)
        elif e["role"] is None:
            problems.append("%s holds '%s', which xapi reads as broken"
                            % (e["host"].name, e["text"]))
    if len(masters) > 1:
        problems.append("%d hosts say master (%s)"
                        % (len(masters), ", ".join(h.name for h in masters)))
    for e in slaves:
        target = e["target"]
        if not e["pointer"]:
            # 'slave:' with nothing after it: xapi reads it as a slave of no address
            problems.append("%s holds '%s', a slave of no address" % (e["host"].name, e["text"]))
            continue
        if target is e["host"]:
            problems.append("%s points at itself" % e["host"].name)
            continue
        theirs = own.get(target)
        if theirs is not None and theirs["role"] != "master":
            problems.append("%s points at %s, which says %s"
                            % (e["host"].name, target.name, theirs["text"]))
        elif len(masters) == 1 and target is not masters[0]:
            problems.append("%s points at %s, not at %s"
                            % (e["host"].name, e["pointer"], masters[0].name))
    if not masters:
        pointed_at = sorted(set(e["target"].address if e["target"] else e["pointer"]
                                for e in slaves))
        if len(pointed_at) > 1:
            problems.append("the slaves point at different masters (%s)"
                            % ", ".join(pointed_at))
        if not unread and len(reached) == len(hosts):
            problems.append("no host says master")

    if problems:
        summary = problems[0] + ("; and %d more" % (len(problems) - 1)
                                 if len(problems) > 1 else "")
        return flag("Pool Roles", "Mismatch - %s, See Below" % summary).with_detail(
            "Pool Roles", _pool_roles_detail(hosts, own, unread, problems))
    if unread:
        return unknown("Pool Roles", "Unknown (pool.conf could not be read on %s)"
                       % ", ".join(h.name for h, _error in unread)).with_detail(
            "Pool Roles", _pool_roles_detail(hosts, own, unread, []))
    if not masters:
        # the reachable hosts are all slaves and agree - on a host this run could not
        # read, or on an address that is no member's. Either way the master's own
        # pool.conf was never seen, so agreement is all that was established
        return unknown("Pool Roles", "Unknown (no reachable host says master; the slaves "
                                     "point at %s)" % slaves[0]["pointer"]).with_detail(
            "Pool Roles", _pool_roles_detail(hosts, own, unread, []))
    if len(reached) < len(hosts):
        return ok("Pool Roles", "Consistent (%d of %d hosts reached)"
                  % (len(reached), len(hosts)))
    return ok("Pool Roles", "Consistent")


def _pool_roles_detail(hosts, own, unread, problems):
    """What each host's pool.conf says, one line each, under whatever was wrong with it."""
    out = ["  - %s" % p for p in problems]
    if out:
        out.append("")
    why_unread = dict(unread)
    width = max(len(h.label) for h in hosts)
    for host in hosts:
        if host in own:
            said = own[host]["text"]
        elif host in why_unread:
            said = "(could not be read: %s)" % why_unread[host]
        else:
            said = "(not reached)"
        out.append("%s  %s" % (host.label.ljust(width), said))
    return "\n".join(out)


def ha_enabled(pool):
    f = pool.fact("ha_enabled")
    if not f.ok:
        return unknown("HA Enabled", "Unknown")
    value = f.value.strip()
    if value == "false":
        return ok("HA Enabled", "No")
    if value == "true":
        return flag("HA Enabled", "Yes (%s)" % _ha_statefile_sr_text(pool))
    return unknown("HA Enabled", "Unknown")


def _ha_statefile_sr_text(pool):
    """'SR: <name> (<uuid>)' for the SR(s) holding HA's statefile, or why it is not known."""
    f = pool.fact("ha_statefile_srs")
    if not f.ok:
        return "statefile SR unknown: %s" % f.error
    if not f.value:
        return "no statefile listed"
    named = []
    for row in f.value:
        if row.get("sr"):
            named.append("%s (%s)" % (row.get("name") or "?", row["sr"]))
        else:
            named.append("SR of statefile VDI %s unknown" % row.get("vdi", "?"))
    return "SR: %s" % ", ".join(sorted(set(named)))


def sr_attachment(pool):
    """A shared SR that a live host cannot use: VMs on it will not start there, migrate
    there or back up from there, and nothing else in the report says so.

    That flags when some live hosts have it and another does not. An SR plugged on no live
    host at all - shared or local - is yellow and does not flag: an SR detached on purpose
    reads exactly like one whose storage was down at boot, and the owner's call
    (2026-11-07) is that a deliberate detach must not fail the run. Yellow still survives
    -f, so the outage case is on screen. Hosts xapi does not see as live are not judged,
    their own local SRs included: their PBD state is the last one recorded, not the
    present. With no live host at all nothing was judged, which is Unknown.
    """
    f = pool.fact("sr_attachment")
    if not f.ok:
        return unknown("SR Attachment", "Unknown (%s)" % f.error)
    v = f.value if isinstance(f.value, dict) else {}
    res = parsers.parse_sr_attachment(v.get("pbds") or "", v.get("srs") or "", v.get("hosts") or "")
    if res is None:
        return unknown("SR Attachment", "Unknown (the PBD, SR or host listing from xe could not "
                                        "be read, or xapi sees no host as live)")
    lines = []
    for sr_name, sr_uuid, everywhere, missing in res["shared"]:
        if everywhere:
            lines.append("  %s (%s): shared, and plugged on no live host" % (sr_name, sr_uuid))
        for host_name, why, pbd in missing:
            lines.append("  %s (%s): %s on %s%s" % (
                sr_name, sr_uuid, why, host_name,
                "  ->  xe pbd-plug uuid=%s" % pbd if pbd else ""))
    for sr_name, sr_uuid, host_name, pbd in res["local"]:
        lines.append("  %s (%s): local, %s" % (
            sr_name, sr_uuid, "not plugged on %s  ->  xe pbd-plug uuid=%s" % (host_name, pbd)
            if host_name else "and it has no PBD at all"))
    if res["down"]:
        lines.append("  not judged on %s: xapi does not see %s as live"
                     % (", ".join(res["down"]), "it" if len(res["down"]) == 1 else "them"))
    detail = "\n".join(lines)
    partial = [s for s in res["shared"] if not s[2]]
    detached = ["%s (shared, on no live host)" % s[0] for s in res["shared"] if s[2]] + \
        ["%s on %s" % (n, h) if h else "%s (no PBD)" % n for n, _u, h, _p in res["local"]]
    if partial:
        names = []
        for sr_name, _uuid, _everywhere, missing in partial:
            for why in ("not plugged", "no PBD"):
                hosts = [m[0] for m in missing if m[1] == why]
                if hosts:
                    names.append("%s %s on %s" % (sr_name, "not plugged" if why == "not plugged"
                                                  else "has no PBD", ", ".join(hosts)))
        return flag("SR Attachment", "Fail", " - " + "; ".join(names)).with_detail(
            "SR Attachment", detail)
    if detached or res["down"]:
        parts = []
        if detached:
            parts.append("Detached - " + ", ".join(detached))
        if res["down"]:
            parts.append("not judged on %s" % ", ".join(res["down"]))
        text = "; ".join(parts)
        return info("SR Attachment", text[:1].upper() + text[1:], "yellow").with_detail(
            "SR Attachment", detail)
    return ok("SR Attachment", "OK")


def long_running_tasks(pool):
    """A xapi task not finished after TASK_PENDING_MAX_HOURS - pending, or cancelling.

    It holds whatever it was working on - a VM, a VDI, an SR operation - and every later
    operation on that object waits behind it or fails with an 'operation in progress'
    that names nothing. One reading only, so the line says how long a task has been
    unfinished, never that it is stuck: progress is shown, not judged. xapi destroys one
    older than pending_task_timeout (24 h by default) only if its progress has not moved
    since its previous GC pass (see config.TASK_PENDING_MAX_HOURS), so a task that keeps
    creeping can be seen here at any age.
    """
    f = pool.fact("tasks")
    if not f.ok:
        return unknown("Long-Running Tasks", "Unknown (%s)" % f.error)
    v = f.value if isinstance(f.value, dict) else {}
    now = v.get("now")
    old = parsers.parse_pending_tasks(v.get("text") or "", now,
                                      config.TASK_PENDING_MAX_HOURS * 3600) \
        if isinstance(now, (int, float)) else None
    if old is None:
        return unknown("Long-Running Tasks",
                       "Unknown (the task listing from xe could not be read)")
    if not old:
        return ok("Long-Running Tasks", "None")
    names = {}
    att = pool.fact("sr_attachment")
    if att.ok and isinstance(att.value, dict):
        for rec in parsers.parse_xe_records(att.value.get("hosts") or ""):
            names[rec.get("uuid")] = rec.get("name-label") or rec.get("uuid")
    lines = ["  %s (%s): %s for %.1fh, progress %s, on %s" % (
        name, uuid, status, age / 3600.0, progress, names.get(host, host))
        for name, uuid, age, progress, host, status in old]
    lines.append("A task xapi has not finished holds what it works on; if it is not "
                 "moving, xe task-cancel uuid=<uuid> asks it to stop (a 'cancelling' one "
                 "already was asked, and did not stop).")
    return flag("Long-Running Tasks", "Yes",
                " - %d pending over %dh: %s" % (len(old), config.TASK_PENDING_MAX_HOURS,
                                                ", ".join(t[0] for t in old[:3]) +
                                                (", ..." if len(old) > 3 else ""))).with_detail(
        "Long-Running Tasks", "\n".join(lines))


def leaf_coalesce_disabled(pool):
    """Disks SM's GC is not leaf-coalescing, and SRs where it leaf-coalesces nothing.

    other-config:leaf-coalesce=false on a VDI is written by SM when a storage migration
    starts mirroring that disk (see config.LEAF_COALESCE_BUSY_VM_OPS for the trace). A
    migration that fails or is cancelled leaves it there until the disk's next snapshot -
    SM's snapshot path removes the key before deciding whether to set it again - or until
    someone removes it; until then GC skips the disk. A disk whose VM or VDI is
    mid-migration, -export or -import right now is where the flag belongs, so it is
    counted aside. On an SR, any of three other-config switches set to false stops it for
    every disk there (parsers.GC_SR_SWITCHES), and only a person sets those.

    The VM list is what busy-ness is judged by; without it every flagged disk is reported
    and the detail says why. The VBD list only names the VMs, so without it the disks are
    still reported, unnamed.
    """
    f = pool.fact("leaf_coalesce")
    if not f.ok:
        return unknown("Leaf-Coalesce Disabled", "Unknown (%s)" % f.error)
    v = f.value if isinstance(f.value, dict) else {}
    vms = pool.fact("vms")
    disks, busy = parsers.leaf_coalesce_vdis(
        v.get("vdis") or "", v.get("vbds"), vms.value if vms.ok else None,
        config.LEAF_COALESCE_BUSY_VM_OPS, config.LEAF_COALESCE_BUSY_VDI_OPS)
    srs = parsers.leaf_coalesce_srs(v.get("srs") or "")
    aside = (" (%s mid-migration/export/import, as expected)" % _plural(busy, "disk")
             if busy else "")
    if not disks and not srs:
        if v.get("srs") is None:
            return unknown("Leaf-Coalesce Disabled", "Unknown - no disk has it%s, but the SRs were not read (%s)"
                           % (aside, v.get("sr_error") or "not collected"))
        return ok("Leaf-Coalesce Disabled", "None" + aside)

    lines = []
    what = {"gc": "garbage collection disabled for it - nothing is coalesced or cleaned up",
            "coalesce": "coalescing disabled for every disk on it",
            "leaf-coalesce": "leaf-coalesce disabled for every disk on it"}
    for uuid, name, off in srs:
        lines.append("  SR %s (%s): %s (other-config %s)"
                     % (name, uuid, what[off[0]], ", ".join("%s=false" % k for k in off)))
    rows = []
    for d in disks:
        where = ", ".join("%s (%s)" % (n or "?", u) for u, n in d["vms"]) or "no VM"
        rows.append("  %s: %s (%s) on %s%s" % (where, d["name"], d["uuid"], d["sr"] or "?",
                                               "  [snapshot]" if d["snapshot"] else ""))
    lines.extend(parsers.cap_lines(rows, config.LEAF_COALESCE_MAX_LINES, "disk(s)"))
    if busy:
        lines.append("  %s left out: mid-migration/export/import right now"
                     % _plural(busy, "flagged disk"))
    if v.get("vbds") is None and disks:
        lines.append("  the VBD list was not read (%s), so the disks' VMs are not named"
                     % (v.get("vbd_error") or "not collected"))
    if not vms.ok and disks:
        lines.append("  whether any of these is mid-migration was not established (%s), so "
                     "all are listed" % vms.error)
    if v.get("srs") is None:
        lines.append("  the SRs were not read (%s)" % (v.get("sr_error") or "not collected"))
    if disks:
        lines.append("Left behind by a storage migration that did not finish: GC skips the "
                     "disk until its next snapshot, or until the key goes - xe "
                     "vdi-param-remove uuid=<vdi> param-name=other-config "
                     "param-key=leaf-coalesce.")
    if srs:
        lines.append("An SR switch stays until removed: xe sr-param-remove uuid=<sr> "
                     "param-name=other-config param-key=<switch>.")
    vm_count = len(set(u for d in disks for u, _n in d["vms"]))
    parts = []
    if disks:
        parts.append(_plural(len(disks), "disk") +
                     (" on %s" % _plural(vm_count, "VM") if vm_count else ""))
    if srs:
        parts.append(_plural(len(srs), "SR"))
    return flag("Leaf-Coalesce Disabled", "Yes", " - %s, see below" % ", ".join(parts)).with_detail(
        "Leaf-Coalesce Disabled", "\n".join(lines))


def windows_vms_not_optimized(pool):
    """Windows VMs made from the wrong template, or missing the viridian enlightenments.

    The 8.3 Windows templates set every key in config.WINDOWS_PLATFORM_KEYS; 'Other install
    media' sets none, and a VM made from an older Windows template carries viridian alone.
    Without them Windows runs on emulated timers and interrupt paths. Halted VMs are judged
    too, since the platform is read at the next boot; XO replicas are not (see
    parsers.windows_vm_findings, which also says which VMs it cannot recognise).
    """
    f = pool.fact("vms")
    if not f.ok:
        return unknown("Windows VMs Not Optimized", "Unknown (%s)" % f.error)
    windows, findings = parsers.windows_vm_findings(f.value or "", config.WINDOWS_PLATFORM_KEYS)
    if not windows:
        return ok("Windows VMs Not Optimized", "N/A - No Windows VMs found")
    if not findings:
        return ok("Windows VMs Not Optimized", "None (%s checked)" % _plural(windows, "Windows VM"))
    rows = ["  %s (%s): %s" % (name or "?", uuid, "; ".join(problems))
            for name, uuid, problems in findings]
    lines = parsers.cap_lines(rows, config.WINDOWS_MAX_LINES, "VM(s)")
    lines.append("Platform keys take effect at the VM's next boot: xe vm-param-set uuid=<vm> "
                 + " ".join("platform:%s=true" % k for k in config.WINDOWS_PLATFORM_KEYS))
    return flag("Windows VMs Not Optimized", "Yes", " - %d of %s, see below"
                % (len(findings), _plural(windows, "Windows VM"))).with_detail(
        "Windows VMs Not Optimized", "\n".join(lines))


def migration_compression(pool):
    """Read with 'pool-list params=... --minimal', never 'pool-param-get param-name=':
    the param does not exist before 8.3, and param-get on a missing param makes xapi log
    a CLI_failed_to_find_param exception into the very log this tool greps."""
    if not pool.fact("pool_uuid").ok:
        return unknown("Migration Compression", "Unknown (pool UUID not available)")
    f = pool.fact("migration_compression")
    if not f.ok:
        return unknown("Migration Compression", "Unknown (could not read the pool record)")
    value = f.value.strip()
    if value == "false":
        return ok("Migration Compression", "Disabled")
    if value == "true":
        return flag("Migration Compression", "Enabled")
    if value == "":
        # pre-8.3 pool: the field is absent, so the feature cannot be on
        return ok("Migration Compression", "Not supported (pre-8.3)")
    return unknown("Migration Compression", "Unknown")


def missing_patches(pool):
    """'yum check-update' on the host the pool questions were asked of. A yum that could
    not reach its repos is Unknown with yum's own reason - which is usually the mirror,
    and 'Update Mirror Access' on that host says which part of the path failed."""
    f = pool.fact("yum_check")
    if not f.ok:
        return unknown("Missing Patches", "Unknown (%s)" % f.error if f.error else "Unknown")
    if f.value == 0:
        return ok("Missing Patches", "0")
    return flag("Missing Patches", "%d available" % f.value)


def update_mirror_access(host):
    """Whether this host can fetch repo metadata from the mirrors the XCP-ng redirector
    sends it to - the usual cause of a 'yum update' that cannot find anything, and one
    'Missing Patches' can only call Unknown. Every mirror with a share of this host's
    redirects is tried, not just the one picked this time: the pick is weighted-random,
    so a single bad mirror fails some yum runs and not others.

    A host whose repos point somewhere else (a local mirror) is said, not flagged.
    """
    f = host.fact("update_mirror")
    if not f.ok:
        return unknown("Update Mirror Access", "Unknown (%s)" % f.error)
    v = f.value or {}
    if v.get("skipped"):
        return info("Update Mirror Access", "N/A (repos use %s)" % (", ".join(v.get("repo_hosts") or [])
                                                  or "no enabled repos"))
    redirector = _url_host_of(v.get("url", "")) or config.UPDATE_MIRROR_REDIRECTOR
    seen = "Public IP: %s%s" % (v.get("public_ip") or "unknown",
                                " - %s" % v["asn"] if v.get("asn") else "")
    head = ["Repo URL:  %s" % (v.get("repo_url") or v.get("url", "?")), seen,
            "Via yum proxy: %s" % ("yes" if v.get("proxy") else "no")]
    if v.get("repo_url") and v.get("repo_url") != v.get("url"):
        head.insert(1, "Probed:    %s (the redirector sends http requests there)"
                    % v.get("url", "?"))
    if v.get("redirector_error"):
        # yum falls back to the repo's other hosts; the line still flags (the mirror
        # network is down for this host) and says whether the fallback answers
        fallbacks = v.get("fallbacks") or []
        answering = [x.get("host", "?") for x in fallbacks if x.get("ok")]
        text = "Cannot reach %s" % redirector
        if answering:
            text += " (yum falls back to %s, which answers)" % ", ".join(answering)
        elif fallbacks:
            text += " (nor its fallback %s)" % ", ".join(x.get("host", "?") for x in fallbacks)
        lines = head + ["", "%s: %s" % (redirector, v["redirector_error"])]
        for x in fallbacks:
            lines.append("fallback %s: %s" % (x.get("host", "?"),
                                              "OK" if x.get("ok") else x.get("error")))
        return flag("Update Mirror Access", text + ", See Below").with_detail(
            "---update mirror access---", "\n".join(lines))
    if v.get("page_error"):
        # it answered: an unreadable mirror list establishes nothing about reachability
        return unknown("Update Mirror Access", "Unknown (%s)" % v["page_error"])

    mirrors = v.get("mirrors") or []
    tried = [m for m in mirrors if m.get("tried", True)]
    bad = [m for m in tried if not m.get("ok")]
    untried = [m for m in mirrors if not m.get("tried", True)]
    first_hop = v.get("first_hop_error") or ""
    selected = v.get("selected") or ""
    if not mirrors:
        return unknown("Update Mirror Access", "Unknown (no mirror was tried)")
    rows = ["%-40s %-6s %s" % ("Mirror", "Share", "Result")]
    for m in mirrors:
        share = "%d%%" % m["share"] if m.get("share") is not None else "-"
        name = m.get("host", "?") + (" *" if m.get("host") == selected else "")
        rows.append("%-40s %-6s %s" % (name, share, "OK" if m.get("ok") else m.get("error")))
    if selected:
        rows.append("(* = the mirror %s picked for this host)" % redirector)
    if v.get("not_probed"):
        rows.append("(%d more with a share were not tried: at most %d are)"
                    % (v["not_probed"], len(mirrors)))
    if first_hop:
        rows = ["%s (yum's own first request): %s" % (v.get("repo_url"), first_hop), ""] + rows
    if bad or first_hop:
        parts = []
        if first_hop:
            parts.append("Cannot reach %s" % re.sub(r"^(\w+://[^/]+).*$", r"\1",
                                                    v.get("repo_url") or ""))
        if bad:
            parts.append(("All %s" % _plural(len(tried), "mirror") if len(bad) == len(tried)
                          else "%d of %s" % (len(bad), _plural(len(mirrors), "mirror")))
                         + " Unreachable")
        return flag("Update Mirror Access", "; ".join(parts) + ", See Below").with_detail(
            "---update mirror access---", "\n".join(head + [""] + rows))
    if untried:
        # a mirror the budget never let us try is not established either way
        return unknown("Update Mirror Access", "Unknown - %d of %s not tried (out of time)"
                       % (len(untried), _plural(len(mirrors), "mirror"))).with_detail(
            "---update mirror access---", "\n".join(head + [""] + rows))
    how_many = (("%d of %d mirrors" % (len(mirrors), len(mirrors) + v["not_probed"]))
                if v.get("not_probed") else _plural(len(mirrors), "mirror"))
    return ok("Update Mirror Access", "Yes (%s, via %s)" % (how_many, selected or mirrors[0].get("host")))


def _url_host_of(url):
    m = re.match(r"^[a-zA-Z]+://([^/:?#]+)", url or "")
    return m.group(1) if m else ""


def vlan0(pool):
    f = pool.fact("vlan0")
    if not f.ok:
        return unknown("VLAN 0 Check", "Unknown (%s)" % f.error)
    if f.value.strip():
        return flag("VLAN 0 Check", "Yes")
    return ok("VLAN 0 Check", "No")


def _plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def xostor_missing_devices(host):
    """PVs of the XOSTOR volume group whose device LVM can no longer find.

    Two sources, checked against each other. pvs: a disk that dropped out from under
    linstor_group leaves the VG partial, and LVM still lists the PV from the metadata on
    the disks that remain, as '[unknown]' / attr 'm'. /etc/lvm/backup/linstor_group: the
    PVs the VG is meant to have, by uuid - which is what catches every disk gone at once,
    when pvs has no metadata left to show the VG from at all. DRBD may be carrying on from
    the peers' replicas, so nothing else on the host need look wrong yet. Only asked when
    the pool uses XOSTOR.

    No PVs and no backup file is said, not flagged: a diskless XOSTOR node is a supported
    layout. No PVs and an unreadable backup is Unknown - that pair cannot tell a diskless
    node from one that lost everything.
    """
    vg = config.XOSTOR_VG
    f = host.fact("pvs")
    if not f.ok:
        return unknown("XOSTOR Missing Devices", "Unknown (%s)" % f.error)
    rows = [r for r in parsers.parse_pvs(f.value.get("rows")) if r[1] == vg]
    present = dict((r[3], r[0]) for r in rows if not parsers.pv_missing(r[0], r[2]))
    flagged = [r for r in rows if parsers.pv_missing(r[0], r[2])]

    b = host.fact("lvm_backup")
    known = parsers.parse_lvm_backup_pvs(b.value) if b.ok and b.value else []

    detail = []
    if known:
        lost = [(u, d) for u, d in known if u not in present]
        total = len(known)
        for u, d in known:
            state = "present as %s" % present[u] if u in present else "MISSING"
            detail.append("%-40s %-16s %s" % (u, d or "?", state))
        # a PV pvs calls missing that the backup does not know of is still missing
        extra = [r for r in flagged if r[3] not in dict(known)]
        for r in extra:
            detail.append("%-40s %-16s MISSING (not in %s backup)"
                          % (r[3] or "?", r[0], vg))
        n_missing = len(lost) + len(extra)
        total += len(extra)
    else:
        if not rows:
            if b.ok and b.value is None:
                # no backup file at all: the VG never lived here - a diskless node
                return info("XOSTOR Missing Devices", "None (no %s PVs on this host)" % vg)
            if b.ok:
                # the backup file exists, so the VG did live here, and it names no PV that
                # could be read: that pair cannot tell a diskless node from one that lost
                # every disk at once - the very case the backup half is for
                return unknown("XOSTOR Missing Devices", "Unknown (no %s PVs, and its LVM "
                               "backup names none)" % vg)
            return unknown("XOSTOR Missing Devices", "Unknown (no %s PVs, and %s)" % (vg, b.error))
        total, n_missing = len(rows), len(flagged)
        detail = ["%-40s %-16s %s" % (r[3] or "?", r[0], r[2]) for r in rows]
        if not b.ok:
            detail.append("(%s backup unreadable: %s)" % (vg, b.error))

    if not n_missing:
        return ok("XOSTOR Missing Devices", "None (%s present)" % _plural(total, "PV"))
    warnings = [w.strip() for w in (f.value.get("warnings") or "").splitlines() if w.strip()]
    if warnings:
        detail += [""] + warnings
    what = "All %s" % _plural(total, "PV") if n_missing == total and total > 1 else \
        "%d of %s" % (n_missing, _plural(total, "PV"))
    return flag("XOSTOR Missing Devices", "%s in %s Missing, See Below" % (what, vg)).with_detail(
        "---xostor missing devices---", "\n".join(["%-40s %-16s %s" % (
            "PV UUID", "Device (hint)", "State")] + detail))


def xostor_missing_devices_pool(hosts, details_shown=True):
    """One pool-level line rolling up every host's 'XOSTOR Missing Devices', so a lost
    disk is not missed by someone reading only the pool section - the same reason
    'XOSTOR Version Consistency' exists. Built from the host line itself, so the two can
    never disagree. Names the hosts, since that is the first thing to know; the PVs are
    in each host's own detail. details_shown is False when slaves do not print the
    per-host line, and then the reader is not sent to look for it.
    """
    return _pool_rollup("XOSTOR Missing Devices", hosts, xostor_missing_devices,
                        details_shown)


def _pool_rollup(key, hosts, host_check, details_shown=True, flagged_as="Yes, on",
                 clean="None", all_na=None):
    """One pool line built from each host's own line for the same check, so the two can
    never disagree: the hosts it flags, then the hosts it could not read, else clean.
    An INFO host line (not applicable there) counts as neither. 'See Host Results' only
    when every flagged host prints its line - the master always does, a slave only when
    details_shown (its POOL_RUN toggle) says so. With all_na given, a pool where EVERY
    host's line was not-applicable says that (green info) rather than the clean value,
    which would claim something no host was asked.
    """
    flagged, unread, na = [], [], 0
    for h in hosts:
        line = host_check(h)
        if line.status == result.FLAG:
            flagged.append(h)
        elif line.status == result.UNKNOWN:
            unread.append(h.name)
        elif line.status == result.INFO:
            na += 1
    if all_na and hosts and na == len(hosts):
        return info(key, all_na)
    if flagged:
        text = "%s: %s" % (flagged_as, ", ".join(h.name for h in flagged))
        if details_shown or all(h.is_master for h in flagged):
            text += " - See Host Results"
        if unread:
            text += " (unreadable on: %s)" % ", ".join(unread)
        return flag(key, text)
    if unread:
        return unknown(key, "Unknown on: %s" % ", ".join(unread))
    return ok(key, clean)


def pending_reboot_pool(hosts, details_shown=True):
    """Hosts that took updates after their last boot, named in the pool section so they
    are not missed by someone reading only that - each host's own 'Rebooted After
    Updates' line holds the dates."""
    return _pool_rollup("Hosts Pending Reboot", hosts, rebooted_after_updates,
                        details_shown, flagged_as="Yes")


def update_mirror_access_pool(hosts, details_shown=True):
    """Hosts that cannot reach the XCP-ng update mirrors. Hosts on a local mirror are
    left out rather than counted as fine or failing."""
    return _pool_rollup("Update Mirror Access", hosts, update_mirror_access,
                        details_shown, flagged_as="Failing on", clean="OK",
                        all_na="N/A (no host uses the XCP-ng mirrors)")


def xostor_in_use(pool):
    f = pool.fact("xostor_srs")
    if not f.ok:
        return unknown("XOSTOR In Use", "Unknown (%s)" % f.error)
    if not f.value:
        return ok("XOSTOR In Use", "No")
    # a fact about the pool, not a finding - printing it yellow while returning 0 was the
    # one place that broke the rule that anything yellow flags the exit code
    return info("XOSTOR In Use", "Yes")


def xostor_ram(hosts):
    """Every XOSTOR node's dom0 RAM against XOSTOR_MIN_RAM_GB - every node runs DRBD and a
    LINSTOR satellite. It judged only the host the pool questions were asked of, so a
    slave short of RAM printed a green value that read as the pool's."""
    short, unread, sizes = [], [], []
    for host in hosts:
        total = host.mem_total_mb()
        if total is None:
            unread.append(host.label)
            continue
        total_gb = total / 1024.0
        sizes.append(total_gb)
        if int(round_1dp(total_gb) + 0.00001) < config.XOSTOR_MIN_RAM_GB:
            short.append("%s %.1fG" % (host.label, total_gb))
    if short:
        return flag("XOSTOR RAM", "Not Enough on: %s (Need >=%dG)"
                    % (", ".join(short), config.XOSTOR_MIN_RAM_GB))
    if unread:
        return unknown("XOSTOR RAM", "Unknown (could not read dom0 memory on: %s)"
                       % ", ".join(unread))
    if not sizes:
        return unknown("XOSTOR RAM", "Unknown (no host's dom0 memory was read)")
    if len(sizes) == 1:
        return ok("XOSTOR RAM", "%.1fG" % sizes[0])
    return ok("XOSTOR RAM", "%.1fG or more on all %d hosts" % (min(sizes), len(sizes)))


def _linstor_unknown(label, f):
    """One wording for a linstor fact that did not come back, whichever line asked."""
    if "not found" in (f.error or ""):
        return unknown(label, "Unknown (linstor CLI not found)")
    return unknown(label, "Unknown (%s)" % f.error)


def _linstor_table(text):
    """(header cells, [row cells, ...]) of one of linstor's ASCII tables, ANSI stripped.

    Deliberate twin of collector.linstor_table_column, which reads the Node column of the
    same 'n l' table on the hypervisor: one runs where the report is built and one where
    linstor is, so they cannot be shared. Keep the rule-row test, the cell splitting and
    the ANSI stripping identical in both. The first row that is not a rule is the header.
    """
    header, rows = None, []
    for text_line in text.splitlines():
        line = colors.strip_ansi(text_line)
        if not line.startswith("|") or not set(line) - set("|-=+ "):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if header is None:
            header = cells
        else:
            rows.append(cells)
    return header or [], rows


def _linstor_column(text, name):
    """The values under one header, in row order; [] when the table has no such column."""
    header, rows = _linstor_table(text)
    if name not in header:
        return []
    col = header.index(name)
    return [row[col] for row in rows if col < len(row)]


def _linstor_node_offline(text):
    """Any node whose State column of 'linstor n l' says something other than Online."""
    return any(state != "Online" for state in _linstor_column(text, "State"))


def _linstor_has_rows(text):
    """'r l --faulty' prints its header whether or not anything is faulty; rows are the
    finding."""
    return bool(_linstor_table(text)[1])


def xostor_faulty_resources(pool):
    """Rows of 'linstor r l --faulty' are the finding. Its header prints whether or not
    anything is faulty, so output with no header is not a table at all - a banner, an
    error on rc 0, a client whose borders this does not read - and establishes nothing."""
    f = pool.fact("linstor_faulty")
    if not f.ok:
        return _linstor_unknown("XOSTOR Faulty Resources", f)
    header, rows = _linstor_table(f.value)
    if not header:
        return unknown("XOSTOR Faulty Resources",
                       "Unknown (no table in 'linstor r l --faulty' output)")
    if rows:
        return flag("XOSTOR Faulty Resources", "Yes, See Below").with_detail(
            "---xostor faulty resources---", f.value)
    return ok("XOSTOR Faulty Resources", "No")


def xostor_nodes(pool):
    """Any node whose State is not Online. Green needs a State column and at least one
    node: the line prints only on a pool that uses XOSTOR, so no nodes is never the right
    answer - it is a table this could not read (the collector's twin says the same)."""
    f = pool.fact("linstor_nodes")
    if not f.ok:
        return _linstor_unknown("XOSTOR Faulty Nodes", f)
    header, rows = _linstor_table(f.value)
    if "State" not in header or not rows:
        return unknown("XOSTOR Faulty Nodes",
                       "Unknown (no node rows with a State column in 'linstor n l' output)")
    if _linstor_node_offline(f.value):
        return flag("XOSTOR Faulty Nodes", "Yes, See Below").with_detail(
            "---xostor node status---", f.value)
    return ok("XOSTOR Faulty Nodes", "No")


def _linstor_node_addresses(text):
    """{address: node} out of the Addresses column of 'linstor n l'.

    A cell reads '192.0.2.84:3366 (PLAIN)' - the satellite's address, its port and the
    connection type. An older table without an Addresses column simply names nobody.
    """
    header, rows = _linstor_table(text)
    if "Node" not in header or "Addresses" not in header:
        return {}
    node_col, addr_col = header.index("Node"), header.index("Addresses")
    out = {}
    for row in rows:
        if max(node_col, addr_col) >= len(row) or not row[node_col]:
            continue
        for token in row[addr_col].replace(",", " ").split():
            if not token.startswith("("):        # '(PLAIN)' is the connection type
                out.setdefault(parsers.split_host_port(token)[0], row[node_col])
    return out


def xostor_controller(pool, host_names=None):
    """Where the linstor controller is - the address, and which host that is.

    The name comes from the pool's own xapi host list first: those are the names the host
    blocks carry, and the addresses the collector asked linstor through are those same
    management addresses. Then from the Addresses column of 'linstor n l', which names
    every node - a solo host run only knows its own name from xapi, and the controller may
    well be a host it never looks at. Neither answering leaves the address on its own: the
    line is about where the controller is, and a name is a convenience that must not turn
    a known address into an Unknown.
    """
    f = pool.fact("linstor_controller")
    if not f.ok:
        return _linstor_unknown("XOSTOR Controller IP", f)
    names = dict(host_names or {})
    nodes = pool.fact("linstor_nodes")
    node_names = _linstor_node_addresses(nodes.value) if nodes.ok else {}
    text = []
    for line in f.value.splitlines():
        if line.startswith("Error:"):
            continue
        address = line[len("linstor://"):] if line.startswith("linstor://") else line
        key = parsers.split_host_port(address)[0]
        name = names.get(key) or node_names.get(key)
        text.append("%s (%s)" % (address, name) if name else address)
    value = "\n".join(text)
    if not value.strip():
        return flag("XOSTOR Controller IP", "None")
    return ok("XOSTOR Controller IP", value)


def xostor_pref_nic(pool):
    """XOSTOR replication should run over the same dedicated NIC/bond on every node - a
    node missing PrefNic falls back to the default route, and nodes disagreeing means
    replication traffic for the same resource takes different paths depending on which
    node initiates it. Neither is visible from any single node's own report.

    The fact carries both the nodes that were ASKED and the answers that came back, and
    they are compared before anything green is printed. A node whose properties could not
    be read has not been shown to agree with the others, so a run that heard from two of
    five nodes cannot say 'all nodes' - it says which three it could not read. The unread
    set is what a partial linstor answer, a controller that went away mid-run, or the
    collector's whole-run budget running out all arrive as.

    A PrefNic genuinely absent on a node that DID answer stays a finding either way: it is
    established, so an unread peer elsewhere in the cluster does not suppress it. Every
    node appears in the detail block, unread ones included, so the reading is auditable.
    """
    f = pool.fact("linstor_pref_nics")
    if not f.ok:
        return unknown("XOSTOR PrefNic", "Unknown (%s)" % f.error)
    value = f.value or {}
    nodes = sorted(value.get("nodes") or [])
    nics = value.get("nics") or {}
    if not nodes:
        return unknown("XOSTOR PrefNic", "Unknown (no linstor nodes found)")

    unread = [name for name in nodes if name not in nics]
    detail = "\n".join(
        "%s: %s" % (name, "(could not read)" if name in unread else (nics[name] or "(not set)"))
        for name in nodes)

    if len(unread) == len(nodes):
        return unknown("XOSTOR PrefNic",
                       "Unknown (could not read PrefNic on any of %d node(s))" % len(nodes))
    missing = sorted(name for name in nics if not nics[name])
    values = set(nic for nic in nics.values() if nic)
    if missing and not values:
        # set on none of the nodes read: SM reads an absent PrefNic as 'default'
        # (linstorvolumemanager.py), so this is the cluster consistently using LINSTOR's
        # default interface - no dedicated storage NIC. Worth a look, not a finding (the
        # maintainer's call). With nodes unread, a mix cannot be ruled out.
        if unread:
            return unknown("XOSTOR PrefNic", "Unknown (not set on the nodes read; could "
                                             "not read: %s)" % ", ".join(unread)).with_detail(
                "---xostor prefnic---", detail)
        return info("XOSTOR PrefNic", "Default interface on all %d nodes (no PrefNic set)"
                    % len(nodes), "yellow")
    if missing:
        return flag("XOSTOR PrefNic", "Not set on: %s" % ", ".join(missing)).with_detail(
            "---xostor prefnic---", detail)
    values = set(nic for nic in nics.values() if nic)
    if len(values) > 1:
        return flag("XOSTOR PrefNic", "Inconsistent Across Nodes, See Below").with_detail(
            "---xostor prefnic---", detail)
    if unread:
        return unknown("XOSTOR PrefNic",
                       "Unknown (could not read: %s)" % ", ".join(unread)).with_detail(
            "---xostor prefnic---", detail)
    return ok("XOSTOR PrefNic", "%s (all %d nodes)" % (values.pop(), len(nodes)))


def xostor_qcow2(pool):
    f = pool.fact("qcow2")
    if not f.ok:
        return unknown("XOSTOR QCOW2 VDIs", "Unknown (%s)" % f.error)
    rows = f.value or []
    if not rows:
        return ok("XOSTOR QCOW2 VDIs", "None")
    total = pool.fact("qcow2_total")
    count = total.value if total.ok else len(rows)
    shown = list(rows)
    if count > len(rows):
        shown.append("(plus %d more qcow2 VDI(s) not listed)" % (count - len(rows)))
    return flag("XOSTOR QCOW2 VDIs", "Yes, See Below").with_detail(
        "---xostor qcow2 vdis---", "\n".join(shown))


def _network_line(pool, key, label, other_config_key):
    """Shared body of the Migration Network / Backup Network lines."""
    oc = pool.fact("other_config")
    if not oc.ok:
        return unknown(label, "Unknown (could not read pool other-config)"), None
    if other_config_key not in parsers.parse_other_config(oc.value):
        return ok(label, "Not configured"), None

    net = (pool.networks() or {}).get(other_config_key)
    if net is None:
        return unknown(label, "Unknown (could not check bond membership)"), None
    bond = result.wrap(net, "bond")
    if not bond.ok:
        return unknown(label, "Unknown (could not check bond membership)"), None

    state = parsers.parse_bond_slave_of(bond.value)
    if state == parsers.BOND_MEMBER:
        return flag(label, "Set to bond member"), None
    if state == parsers.BOND_NO_PIFS:
        return flag(label, "Configured, but that network has no PIFs (deleted network?)"), None
    return None, net


def migration_network(pool):
    line, _net = _network_line(pool, "migration", "Migration Network", "xo:migrationNetwork")
    if line is not None:
        return line
    return ok("Migration Network", "Configured")


def backup_network(pool, run_env, pinger, routes=None):
    """The ping half asks 'can the XOA reach every host on this network', because that is
    what XO needs to move backup traffic. Asking it from a pool host answers a different
    question, so host mode does not ask it at all rather than mislabelling the answer.

    For the same reason a silent ping is only a finding when it is the XOA that moves the
    traffic. A job pinned to an XO Proxy runs there and reaches the hosts from there, and
    an HTTP proxy on the pool's server record carries every request the XOA itself makes,
    exports included - so a pool whose backups all go one of those ways can be unreachable
    from the XOA by design (issue #71). `routes(pool_uuid, vm_uuids, sr_uuids)` says which
    it is; it is only asked once a ping has gone unanswered, so a pool the XOA reaches
    costs nothing more than it did.
    """
    line, net = _network_line(pool, "backup", "Backup Network", "xo:backupNetwork")
    if line is not None:
        return line

    if run_env == "host":
        return ok("Backup Network",
                  "Configured (reachability from XOA not checked - run this from XOA for that)")

    ips = result.wrap(net, "ips")
    if not ips.ok:
        return unknown("Backup Network", "Unknown (could not read backup network PIFs)")
    if not ips.value:
        return flag("Backup Network", "Configured but no usable IP was found on the network")
    missing = net.get("pifs_without_ip") or 0
    if missing:
        # XO sends that host's exports (and a proxy's) to its backup-network PIF IP, taken
        # verbatim: with none, there is nowhere to send them - whoever runs the job
        return flag("Backup Network", "Configured but %d PIF(s) on it have no IP" % missing,
                    " - those hosts' backups have no address on this network")

    silent = pinger(ips.value)
    if not silent:
        return ok("Backup Network", "Configured and reachable from XOA")
    elsewhere = _backup_moved_elsewhere(pool, routes)
    if elsewhere:
        # nothing was learned about the path the traffic really takes, and the line says
        # so: what is green is the configuration, the way host mode's line is
        return ok("Backup Network", "Configured, %s (not tested from here) - No ping answer "
                                    "from XOA itself for: %s" % (elsewhere, ", ".join(silent)))
    # ICMP only, so a ping-filtering network reads yellow - the wording claims exactly
    # what was tested and nothing more
    return flag("Backup Network", "Configured but not fully reachable",
                " - No ping answer from XOA for: " + ", ".join(silent))


def _backup_moved_elsewhere(pool, routes):
    """What carries this pool's backup traffic instead of the XOA's own connection, as a
    phrase - or '' when the XOA moves it itself, or when XO's configuration could not be
    read, which leaves the finding exactly as it was."""
    if routes is None:
        return ""
    scope = pool.payload.get("backup_scope") or {}
    vms, srs = result.wrap(scope, "vms"), result.wrap(scope, "srs")
    uuid = pool.fact("pool_uuid")
    info = routes(uuid.value if uuid.ok else "",
                  set(vms.value) if vms.ok else None,
                  set(srs.value) if srs.ok else None)
    if info.get("error") or (info["xoa"] and not info["http_proxy"]):
        return ""
    parts = []
    if info["proxies"]:
        parts.append("backups run through XO Proxy %s"
                     % ", ".join("'%s'" % name for name in info["proxies"]))
    if info["xoa"]:
        parts.append("XOA connects to this pool through HTTP proxy %s" % info["http_proxy"])
    return " and ".join(parts)


# --------------------------------------------------------------------------------------
# stuck mounts
# --------------------------------------------------------------------------------------

def stuck_processes(host):
    """Processes wedged in uninterruptible sleep - the consequence, whatever the cause.

    This is the primary signal for a mount that has stopped answering, and it is primary
    because it costs nothing and cannot itself hang: every input is served out of kernel
    memory by procfs. It is also filesystem-agnostic, which is the point - a dead NFS
    server, a dead SMB share, a dropped iSCSI LUN and a failing local disk all arrive
    here identically, and none of them needed to be anticipated by name.

    Kernel threads are reported separately from userspace processes. Some kernel threads
    sit in D quite normally, so the line says outright when that is all there is - but a
    kworker parked in a filesystem's work queue corroborates the rest, and dropping it
    would throw away the clearest evidence of which subsystem is stuck.

    What the collector establishes is that each of these was in D and made no progress at
    all for the whole window it watched. Age is NOT that: it is how long the process has
    existed, an upper bound on how long it has been wedged, and the wording keeps the two
    apart. They coincide for a `df` that wedged the moment it ran, and they are days apart
    for a daemon that has been up since boot.
    """
    facts = host.fact("stuck_procs")
    if not facts.ok:
        return unknown("Stuck Processes", "Unknown (%s)" % facts.error)

    rows = facts.value.get("rows") or []
    total = facts.value.get("total") or 0
    if not total:
        return ok("Stuck Processes", "None")

    user_count = facts.value.get("userspace")
    modules = sorted(set(row.get("module") or "" for row in rows) - set([""]))
    oldest = max((row.get("age") or 0) for row in rows)

    what = "%d stuck" % total
    if user_count == 0:
        # worth saying in the summary line rather than only in the block: it is the
        # difference between "this host has lost commands" and "one kworker is parked"
        what += ", all kernel threads"
    summary = "%s (oldest started %s ago)" % (what, parsers.format_age(oldest))
    if modules:
        summary += " in " + ", ".join(modules)
    # the userspace tally comes from the collector, which counted every one of them.
    # Counting it here would count only the capped sample and print that as the whole
    return flag("Stuck Processes", "Yes - " + summary).with_detail(
        "Stuck Processes", _stuck_detail(rows, total, user_count,
                                         facts.value.get("watched"),
                                         facts.value.get("own_probes")))


def _stuck_what(row):
    """What a stuck row is: its command, or for one with none, what the kernel says it is.

    The kernel's PF_KTHREAD flag decides (row["kernel"]) when the collector read it; an
    older collector's row has no such key, and then an empty command line is read as a
    kernel thread, as it always was. A userspace task can have an empty command line too
    - one stuck in exit on a dead mount has already released its memory - and is named by
    its comm instead."""
    frame = row.get("frame") or ""
    kernel = row.get("kernel")
    cmd = row.get("cmd") or ""
    if kernel is True or (kernel is None and not cmd):
        return "[kernel thread] " + frame
    if not cmd:
        return "[%s] (command line not readable) %s" % (row.get("comm") or "?", frame)
    if row.get("own"):
        return "%s   <- left by an earlier health check" % cmd
    return cmd


def _stuck_detail(rows, total, user_count, watched, own_probes):
    if user_count is None:
        head = "%d process(es) in uninterruptible sleep." % total
    else:
        head = ("%d process(es) in uninterruptible sleep; %d of them userspace, the rest "
                "kernel threads." % (total, user_count))
    lines = [head,
             "None of these can be killed - not even with SIGKILL - until whatever they "
             "are waiting on answers."]
    if watched:
        # the measured claim, and the one that says this is not just a busy disk
        lines.append("Each of them consumed no CPU and completed no I/O for the whole %s "
                     "it was watched." % parsers.format_age(watched))
    lines.append("Age is how long the process has existed, which is an upper bound on how "
                 "long it has been stuck, not a measurement of it.")
    if own_probes:
        # named rather than hidden, and counted rather than dropped: they are genuinely
        # stuck, and a reader who does not know where they came from would read a growing
        # count as the host getting worse on its own
        lines.append("%d of them were left by this script's earlier runs - mount probes "
                     "parked on a mount that stopped answering, or commands a run could "
                     "not kill - marked below. Each one names what it was asking about."
                     % own_probes)
    lines.append("")
    for row in rows:
        lines.append("  %-8s %-9s %-10s %s"
                     % (row.get("pid"), parsers.format_age(row.get("age") or 0),
                        row.get("module") or "-", _stuck_what(row)))
    if len(rows) < total:
        # never a silent cut: 25 rows under a heading saying 589 still reads as "here they
        # are" unless the block says outright that it is showing a slice
        lines.append("")
        lines.append("(oldest %d of %d shown)" % (len(rows), total))
    elif len(rows) > 1:
        lines.append("")
        lines.append("(listed oldest first)")
    return "\n".join(lines)


def mount_stalls(host):
    """The server-side half: what the kernel said when a mount stopped answering.

    Read from kern.log and the dmesg ring for the same reason Multipath Path Events reads
    both - neither contains the other. It names the SERVER, which the process scan cannot:
    a stuck process says a mount is wedged, this says which one and since when.

    It cannot be relied on alone, and the reason is worth writing down. The kernel's own
    hung-task detector is enabled on 8.3 (hung_task_timeout_secs=120) but
    kernel.hung_task_warnings defaults to 10 and counts DOWN - after ten it stops logging
    for the rest of the uptime. A host wedged for days can therefore be completely silent
    here while dozens of processes pile up, which is why the process scan leads.
    """
    blocks, failed = _scan_result(host.fact("mount_stall_scan"))
    dmesg = host.fact("dmesg")

    if dmesg.ok:
        blocks = blocks + _dmesg_phrase_blocks(dmesg.value, config.MOUNT_STALL_PHRASES,
                                               config.LOG_ERROR_CONTEXT)
    if blocks:
        return flag("Mount Stalls", "Yes, See Error Output").with_detail(
            "Mount Stalls", _render_scan_blocks(blocks, failed))
    if failed:
        return unknown("Mount Stalls", "Unknown (%s)" % "; ".join(failed))
    if not dmesg.ok:
        return unknown("Mount Stalls", "Unknown (could not read dmesg)")
    return ok("Mount Stalls", "None")


def network_mounts(host):
    """Does each network mount still answer a stat()?

    The only one of the three that can name a mount nothing has touched yet - and the only
    one with a cost, since the probe of a dead mount becomes a stuck process itself. It is
    run anyway, on every host, including one that is already full of stuck processes: this
    is the line that says WHICH mount to go and fix, and on a host in that state the cost
    it was once spared has already been paid many times over.

    A mount is left unprobed only when the run budget has no room to wait for an answer,
    and that reads Unknown rather than green - nothing was established about it.
    """
    facts = host.fact("network_mounts")
    if not facts.ok:
        return unknown("Network Mounts", "Unknown (%s)" % facts.error)

    rows = facts.value
    if not rows:
        return ok("Network Mounts", "None")

    dead = [row for row in rows if row.get("state") == "no answer"]
    unprobed = [row for row in rows if row.get("state") == "not probed"]
    errored = [row for row in rows if row.get("state") == "error"]

    if dead:
        return flag("Network Mounts",
                    "%d of %d not responding" % (len(dead), len(rows))).with_detail(
            "Network Mounts", _mount_detail(rows))
    if unprobed:
        # not probed is not "fine": there was not enough of the run budget left to wait
        # for an answer (MOUNT_PROBE_RESERVE) - the only reason since v3.12, never the
        # state of the host
        return unknown("Network Mounts",
                       "Unknown - %d mount(s) not probed (%s)"
                       % (len(unprobed), unprobed[0].get("why") or "no reason given")
                       ).with_detail("Network Mounts", _mount_detail(rows))
    if errored:
        return flag("Network Mounts",
                    "%d of %d could not be checked" % (len(errored), len(rows))).with_detail(
            "Network Mounts", _mount_detail(rows))
    return ok("Network Mounts", "%d responding" % len(rows))


def _mount_detail(rows):
    lines = []
    for row in rows:
        when = ""
        if row.get("seconds") is not None:
            when = "  %ss" % row["seconds"]
        lines.append("  %-10s %-11s %s on %s%s"
                     % (row.get("type") or "-", row.get("state") or "-",
                        row.get("source") or "-", row.get("target") or "-", when))
        if row.get("why"):
            lines.append("               %s" % row["why"])
    return "\n".join(lines)


# ======================================================================================
# --- xoa -------------------------------------------------------------------------------

def _updater(*args):
    rc, out, err = transport.run_local_cmd(["xoa-updater"] + list(args),
                                           timeout=config.LOCAL_CMD_TIMEOUT)
    return rc, colors.strip_ansi(out)


def _first_token(text):
    for line in text.splitlines():
        line = line.strip()
        if line:
            # non-ASCII spinner glyphs leak out of the updater even with colour off
            cleaned = "".join(c for c in line if ord(c) < 128).strip()
            if cleaned:
                return cleaned.split()[0]
    return ""


def _service_state(name):
    """systemd's word for the unit, or None if systemd could not be asked at all.

    'is-active' puts a state on stdout whether or not the unit is up, and the word is what
    is reported rather than a yes/no of our own. Measured on the XOA (Debian 12, systemd
    252): rc 0 + 'active' for a running unit, rc 3 + 'inactive' for one that is installed
    and stopped, and rc 3 + 'inactive' for a unit that does not exist at all - so the rc
    alone does not separate those, and none of them is the case this guards against.

    A missing systemctl (rc 127, nothing on stdout) and a timeout (rc 124) are NOT answers:
    they leave the unit's state unestablished, and reporting that as 'not running' would be
    a claim of its own. Those are the None.
    """
    rc, out, _err = transport.run_local_cmd(["systemctl", "is-active", name],
                                            timeout=config.LOCAL_CMD_TIMEOUT)
    state = out.strip()
    if rc == 124 or not state:
        return None
    return state


def _plugin_scan_targets():
    """Every (directory, prefix) pair xo-server would look in, in its own order."""
    pairs = []
    for path in config.XO_PLUGIN_LOOKUP_PATHS:
        pairs.append((os.path.join(path, config.XO_PLUGIN_SCOPE_DIR),
                      config.XO_PLUGIN_SCOPE_PREFIX))
        pairs.append((path, config.XO_PLUGIN_PREFIX))
    return pairs


def _plugin_version(directory):
    """The version out of the package's own package.json, or "".

    Best effort by design - a third-party plugin with no package.json, or a broken one, is
    still a third-party plugin, and the finding must not depend on it parsing.
    """
    try:
        with open(os.path.join(directory, "package.json"), "r") as handle:
            data = json.load(handle)
    except (IOError, OSError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    version = data.get("version")
    return version if isinstance(version, str) else ""


def scan_plugins():
    """Every plugin installed on this appliance, whether or not XO ever loaded it.

    Returns (plugins, errors). The filesystem is the source of truth here and redis is
    not, because the question is "what is installed", and a plugin that is installed,
    present and switched off in the UI is exactly the case this check exists for. XO's
    own metadata records answer a different question - what it has loaded at some point -
    and they go stale in both directions.

    A directory it could not list goes in `errors` and turns the line Unknown. A
    directory that is not there is an answer, not an error: two of the three lookup paths
    do not exist on a stock appliance.
    """
    plugins, errors, seen = [], [], set()
    for directory, prefix in _plugin_scan_targets():
        try:
            entries = sorted(os.listdir(directory))
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append("%s: %s" % (directory, exc))
            continue
        for entry in entries:
            if not entry.startswith(prefix) or entry == prefix:
                continue
            full = os.path.join(directory, entry)
            name = entry[len(prefix):]
            if name in seen:
                continue          # xo-server keeps the first path that has the name
            seen.add(name)
            plugin = {
                "name": name,
                "package": entry,
                "path": full,
                "version": _plugin_version(full),
                # an npm-linked or hand-symlinked plugin is worth naming outright: the
                # directory says nothing about where its code actually came from
                "link": os.path.realpath(full) if os.path.islink(full) else "",
            }
            if not os.path.isdir(full):
                # xo-server takes every ENTRY, not only directories (findPluginsInPath),
                # and loads it through require.resolve, which finds a plain file -
                # xo-server-x, or xo-server-x.js - and imports it. So a file here is
                # loaded as a plugin, and shadows a directory of the same name further
                # down the lookup paths (isdir follows a link, so a linked plugin is a
                # directory)
                plugin["why"] = ("a file, not a package directory - XO tries to load it"
                                 if os.path.exists(full)
                                 else "a link to nothing - XO tries to load it and fails")
            plugins.append(plugin)
    return plugins, errors


def _plugin_autoload():
    """(autoload map, was it established). Annotation only - never a finding of its own."""
    cli_path = transport.which("xo-server-db")
    if not cli_path:
        return {}, False
    try:
        return xoredis.read_plugin_autoload(cli_path), True
    except xoredis.RedisError:
        return {}, False


def collect_xoa():
    """Everything the section needs, gathered before anything is printed."""
    data = {}
    # Local reads, so they happen whatever state the updater is in - the plugin scan has
    # to survive an appliance whose updater is down, which is one of the states somebody
    # investigating odd behaviour is most likely to be in
    data["plugins"], data["plugin_errors"] = scan_plugins()
    data["plugin_autoload"], data["plugin_autoload_known"] = _plugin_autoload()

    # Asked before the updater is, because every xoa-updater call below talks to this
    # daemon: with it down they fail, and a failed call used to read as 'Unregistered' and
    # 'Updates available' - findings invented by the tool rather than found by it.
    data["updater_service_state"] = _service_state("xoa-updater")
    if data["updater_service_state"] != "active":
        return data

    rc, out = _updater()
    data["updater_timeout"] = (rc == 124)
    if rc == 124:
        return data
    # every call's own result is kept: one that failed is that line's Unknown with the
    # reason, never error text read as an answer (a failed getXoaPlan used to print a green
    # plan made of its first word, and a failed isRegistered an 'Unregistered' finding)
    data["status_error"] = "" if rc == 0 else _call_failure("xoa-updater", rc, out)

    channel = ""
    for line in out.splitlines():
        if "channel selected" in line:
            channel = line.split()[0] if line.split() else ""
            break
    data["channel"] = channel
    data["up_to_date"] = "All up to date" in out

    rc, reg = _updater("raw-api-call", "isRegistered")
    if rc != 0:
        data["registration_error"] = _call_failure("isRegistered", rc, reg)
    else:
        # util.inspect quotes with ', or " when the value holds a ' (o'brien@...), or `
        m = re.search(r"email:\s*(['\"`])(.*?)\1", reg)
        registered = re.search(r"registered:\s*(true|false)", reg)
        data["registration"] = m.group(2) if m else ""
        data["registered"] = (registered.group(1) == "true") if registered else None

    rc, manifest = _updater("raw-api-call", "getLocalManifest")
    version = ""
    if rc == 0:
        for line in manifest.splitlines():
            parts = line.split("'")
            if len(parts) >= 4 and parts[1] == "xen-orchestra":
                version = parts[3]
                break
        # the same call already paid for, read twice: it also lists every npm package
        # Vates offers this appliance, which is the golden list the plugin scan is judged
        # against
        data["manifest_plugins"] = parsers.manifest_plugin_names(manifest)
    else:
        data["version_error"] = _call_failure("getLocalManifest", rc, manifest)
    data["version"] = version

    rc, plan = _updater("raw-api-call", "getXoaPlan")
    data["plan"] = _first_token(plan) if rc == 0 else ""
    if rc != 0:
        data["plan_error"] = _call_failure("getXoaPlan", rc, plan)
    rc, lic = _updater("raw-api-call", "getSelfLicenses")
    if rc != 0:
        data["licenses"] = ""
        data["plan_error"] = data.get("plan_error") or _call_failure("getSelfLicenses", rc, lic)
    else:
        # util.inspect of an array: '[]' is none bound, '[ {' or '[\n' is some - anything
        # else is not an answer this can read. The updater prints its 'ℹ' glyph in front
        # (measured on 6.9.2: "\nℹ [\n  {"), so non-ASCII goes first, as in _first_token
        text = "".join(c for c in lic if ord(c) < 128).strip()
        data["licenses"] = ("[]" if text == "[]" else
                            "bound" if text.startswith("[") else "")

    # 'xoa check' does real network probes, so it gets its own longer timeout - and a
    # timed-out check produces no stderr, which used to read as a clean pass
    rc, _out, err = transport.run_local_cmd(["xoa", "check"], timeout=config.XOA_CHECK_TIMEOUT)
    data["check_timeout"] = (rc == 124)
    data["check_missing"] = (rc == 127)
    data["check_output"] = err.strip()
    return data


def _call_failure(what, rc, out):
    """One phrase for an updater call that did not answer: its exit status and the first
    line it printed."""
    first = next((line.strip() for line in (out or "").splitlines() if line.strip()), "")
    return "%s exited %d%s" % (what, rc, (": " + first[:120]) if first else "")


def _os_version():
    """os-release's PRETTY_NAME, which every systemd distribution carries; lsb_release
    is a separate package a minimal Debian does not have."""
    fields = _os_release()
    if fields and fields.get("PRETTY_NAME"):
        return fields["PRETTY_NAME"]
    rc, out, _err = transport.run_local_cmd(["lsb_release", "-a"],
                                            timeout=config.LOCAL_CMD_TIMEOUT)
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("Description:"):
                return line[len("Description:"):].strip()
    return ""


def _meminfo():
    try:
        with open("/proc/meminfo", "r") as fh:
            return parsers.parse_meminfo(fh.read())
    except (IOError, OSError):
        return None


_HEAP_PROBE = "process.stdout.write(String(require('v8').getHeapStatistics().heap_size_limit))"


def _xo_server_heap():
    """(limit_mb, source, error): the heap limit the RUNNING xo-server has.

    Read off the process rather than the unit file, which only says what the next start
    will do and misses a drop-in, NODE_OPTIONS, and a unit edited without a restart. On
    the command line (which node applies after NODE_OPTIONS, so it wins), else in
    NODE_OPTIONS, else node's own default - which is what xo-server gets when nobody sets
    one, and is measured by asking the same node binary with no options. V8 sizes the heap
    when the process starts, so nothing set later from inside it can change the number.

    The default is measured in this run's cgroup, not the service's; a MemoryMax on
    xo-server.service would make its real default smaller still (node sizes it from the
    constrained memory), never larger.
    """
    rc, out, err = transport.run_local_cmd(
        ["systemctl", "show", "-p", "MainPID", "--value", "xo-server"],
        timeout=config.LOCAL_CMD_TIMEOUT)
    pid = out.strip()
    if rc != 0 or not pid.isdigit():
        return None, None, "could not ask systemd for xo-server's process (%s)" % (
            "timed out" if rc == 124 else (err.strip() or "exit %d" % rc))
    if pid == "0":
        return None, None, "xo-server is not running"
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            argv = fh.read().decode("utf-8", "replace").split("\0")
        with open("/proc/%s/environ" % pid, "rb") as fh:
            environ = fh.read().decode("utf-8", "replace").split("\0")
    except (IOError, OSError) as exc:
        return None, None, "could not read xo-server's process %s (%s)" % (pid, exc)
    limit = parsers.node_heap_flag(argv)
    if limit is not None:
        return limit, "set on its command line", None
    node_options = next((e[len("NODE_OPTIONS="):] for e in environ
                         if e.startswith("NODE_OPTIONS=")), "")
    limit = parsers.node_heap_flag(node_options.split())
    if limit is not None:
        return limit, "set in NODE_OPTIONS", None
    try:
        node = os.readlink("/proc/%s/exe" % pid)
    except OSError:
        node = "node"
    env = dict(os.environ)
    env.pop("NODE_OPTIONS", None)
    rc, out, err = transport.run_local_cmd([node, "-e", _HEAP_PROBE],
                                           timeout=config.LOCAL_CMD_TIMEOUT, env=env)
    if rc != 0 or not out.strip().isdigit():
        return None, None, "could not read node's default heap limit (%s)" % (
            "timed out" if rc == 124 else (err.strip().splitlines() or ["exit %d" % rc])[0])
    return int(out.strip()) // (1024 * 1024), "node's default, nothing sets it", None


def heap_limit_line(total_mb, limit_mb, source, error):
    """XO-Server Memory Limit, judged against Vates' 70%-of-RAM rule (config)."""
    if error:
        return unknown("XO-Server Memory Limit", "Unknown (%s)" % error)
    target = max(config.XO_HEAP_MIN_MB, int(total_mb * config.XO_HEAP_TARGET_PCT / 100))
    pct = 100.0 * limit_mb / total_mb if total_mb else 0.0
    text = "%d MB, %s (%.0f%% of %d MB RAM" % (limit_mb, source, pct, total_mb)
    if limit_mb < target:
        return flag("XO-Server Memory Limit",
                    text + "; XO's rule is %d%%, %d MB)" % (config.XO_HEAP_TARGET_PCT, target))
    return ok("XO-Server Memory Limit", text + ")")


def _dmesg():
    rc, out, _err = transport.run_local_cmd(["dmesg", "-T"], timeout=60)
    return out if rc == 0 else None


def ip_addrs():
    """The appliance's own 'ip -o addr show', as a Fact, for Duplicate IPs Across Hosts:
    the same command the collector runs on a host, so both sides parse one way."""
    rc, out, err = transport.run_local_cmd(["ip", "-o", "addr", "show"],
                                           timeout=config.LOCAL_CMD_TIMEOUT)
    if rc != 0:
        return Fact(False, error="ip addr show failed (%s)" % (
            "timed out" if rc == 124 else (err.strip() or "exit %d" % rc)))
    return Fact(True, value=out)


def _plugins_line(data):
    """Is anything installed here that Vates did not ship?

    A plugin runs inside xo-server with xo-server's access to the pool, and nothing in
    XOA's own tooling ever mentions one it did not install - so an appliance behaving
    oddly can be carrying one with no sign of it anywhere else. That is the whole reason
    for the line, and it is why an unrecognised name is reported rather than assumed
    benign: the list is a whitelist, so a stale list names a plugin for a human to look at
    instead of waving one through.

    Vates' set is the union of two sources. This appliance's own xoa-updater manifest is
    the live one and covers whatever Vates ships next; config.XOA_STOCK_PLUGINS is what is
    left when the updater is down, unregistered or timing out - which are states this
    check has to keep working in.
    """
    if data.get("plugin_errors"):
        return unknown("XOA Plugins",
                       "Unknown (could not read %s)" % "; ".join(data["plugin_errors"]))
    found = data.get("plugins") or []
    vates_names = set(config.XOA_STOCK_PLUGINS) | set(data.get("manifest_plugins") or ())
    stock, third_party = parsers.classify_xo_plugins(found, vates_names)
    # a stock NAME outside the directory xoa-updater installs into is not Vates' copy: it
    # is the one XO loads (an earlier lookup path wins), and a hand-replaced stock plugin
    # is the stealthiest case this line exists for
    home = os.path.join(config.XO_PLUGIN_STOCK_DIR, "")
    for plugin in stock:
        if not plugin.get("why") and not plugin["path"].startswith(home):
            plugin["why"] = ("a stock plugin's name outside %s - XO loads this copy"
                             % config.XO_PLUGIN_STOCK_DIR)
        if plugin.get("why"):
            third_party.append(plugin)
    if not third_party:
        return ok("XOA Plugins", "%d installed, all shipped with XOA" % len(found))
    return flag("XOA Plugins",
                "%d of %d Not Shipped With XOA, See Below"
                % (len(third_party), len(found))).with_detail(
        "Plugins Not Shipped With XOA",
        parsers.plugin_block(third_party, data.get("plugin_autoload") or {},
                             bool(data.get("plugin_autoload_known"))))


def lines():
    """The section's lines, in order."""
    out = []
    data = collect_xoa()

    state = data.get("updater_service_state")
    if state is None:
        out.append(unknown("XOA-Updater",
                           "Could not query the service, unable to determine XOA status"))
    elif state != "active":
        out.append(unknown("XOA-Updater",
                           "Service is %s, unable to determine XOA status" % state))
    elif data.get("updater_timeout"):
        out.append(unknown("XOA-Updater",
                           "Timeout issues, unable to determine XOA status"))
    else:
        reg = data.get("registration")
        if data.get("registration_error"):
            out.append(unknown("Registration", "Unknown (%s)" % data["registration_error"]))
        elif data.get("registered") is False:
            out.append(flag("Registration", "Unregistered"))
        elif reg:
            out.append(ok("Registration", reg))
        elif data.get("registered") is True:
            out.append(ok("Registration", "Registered"))
        else:
            out.append(unknown("Registration", "Unknown (isRegistered's answer could not "
                                               "be read)"))

        channel = data.get("channel")
        out.append(ok("XOA Channel", channel) if channel else unknown("XOA Channel", "(Unknown)"))

        version = data.get("version")
        out.append(ok("XOA Version", version) if version else
                   unknown("XOA Version", "Unknown (%s)" % data["version_error"]
                           if data.get("version_error") else "Unknown"))

        # plan and licence binding share one printed line, so -f weighs them together:
        # deciding per half would drop a flagged licence along with a healthy plan
        plan, lic = data.get("plan"), data.get("licenses")
        flagged = False
        plan_txt = colors.green(plan) if plan else colors.yellow("Unknown")
        if not plan:
            flagged = True
        if not lic:
            lic_txt = colors.yellow("Unknown")
            flagged = True
        elif lic == "[]":
            lic_txt = colors.yellow("Unbound")
            flagged = True
        else:
            lic_txt = colors.green("Bound")
        combined = "%s (%s)" % (plan_txt, lic_txt)
        if data.get("plan_error"):
            combined += " - %s" % data["plan_error"]
        out.append(Line("XOA Plan", combined, FLAG if flagged else OK))

        if data.get("status_error"):
            out.append(unknown("XOA Status", "Unknown (%s)" % data["status_error"]))
        elif data.get("up_to_date"):
            out.append(ok("XOA Status", "Up to date"))
        else:
            out.append(flag("XOA Status", "Updates available"))

        if data.get("check_timeout"):
            out.append(unknown("XOA Check", "Timed out after %ds" % config.XOA_CHECK_TIMEOUT))
        elif data.get("check_missing"):
            out.append(unknown("XOA Check", "Unknown (the xoa command was not found)"))
        elif not data.get("check_output"):
            out.append(ok("XOA Check", "All OK"))
        else:
            out.append(flag("XOA Check", "Issues Found, See Output Below").with_detail(
                "XOA Check Issues", data["check_output"]))

    out.append(_plugins_line(data))

    osv = _os_version()
    out.append(ok("OS Version", osv) if osv else unknown("OS Version", "Unknown"))

    mem = _meminfo()
    if mem is None:
        # skipping the memory lines silently would hide that the XO-Server heap cap never
        # got checked at all
        out.append(unknown("Memory Usage", "Unknown (could not read /proc/meminfo)"))
        out.append(unknown("XO-Server Memory Limit",
                           "Unknown (no RAM total to judge it against)"))
    else:
        total_mb, avail_mb = mem
        total_gb = total_mb / 1024.0
        avail_gb = avail_mb / 1024.0
        used_gb = total_gb - avail_gb
        pct = (used_gb / total_gb) * 100 if total_gb > 0 else 0.0
        # a reading with no threshold behind it, so it can never flag - and -f hides it,
        # the same as every other reading. The heap cap below is the line with a rule
        out.append(Line("Memory Usage",
                        "%s GB used of %s GB (%s%%)" % (colors.green("%.1f" % used_gb),
                                                        colors.green("%.1f" % total_gb),
                                                        colors.green("%.1f" % pct)),
                        INFO))

        out.append(heap_limit_line(total_mb, *_xo_server_heap()))

    dmesg_text = _dmesg()
    if dmesg_text is None:
        out.append(unknown("Dmesg Content", "Unknown (could not read dmesg)"))
    else:
        # the appliance's ring, read the same way as a host's: same words, same rollup,
        # same cap, same wording - it used to be a second copy of that check
        out.append(checks.dmesg_content_of(dmesg_text))
    return out


def ping_silent(ips):
    """Which of these addresses did not answer one ICMP echo from here.

    Probed concurrently: a silent IP costs the whole -W 2 wait, so serially a wholly
    unreachable backup network cost 2s per pool host (measured: 8 silent IPs, 16s serial
    versus 2.0s here). The result list is rebuilt in the original order so the report
    stays stable between runs.

    A probe still running when the wait ends answered nothing, so it counts as silent: a
    False default read it as an answer it never gave.
    """
    results = [None] * len(ips)

    def probe(index, address):
        rc, _out, _err = transport.run_local_cmd(
            ["ping", "-c", "1", "-W", "2", "-n", address], timeout=config.LOCAL_CMD_TIMEOUT)
        results[index] = (rc != 0)

    threads = []
    for i, address in enumerate(ips):
        t = threading.Thread(target=probe, args=(i, address))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join(config.LOCAL_CMD_TIMEOUT + 5)
    return [ips[i] for i in range(len(ips)) if results[i] is not False]


def _os_release():
    """/etc/os-release as a dict, or None when it cannot be read."""
    try:
        with open("/etc/os-release", "r") as fh:
            text = fh.read()
    except (IOError, OSError):
        return None
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.lstrip().startswith("#"):
            fields[key.strip()] = value.strip().strip("\"'")
    return fields


def debian_version_ok():
    """XOA mode still has to be a Debian 11+ appliance - Debian, or a distribution that
    names Debian in ID_LIKE. VERSION_ID alone let any OS numbered 11 or more through (a
    Fedora 40 passed), and the run then failed somewhere far less clear."""
    fields = _os_release()
    if fields is None:
        return (False, "unknown")
    version = fields.get("VERSION_ID", "")
    debian = (fields.get("ID") == "debian"
              or "debian" in fields.get("ID_LIKE", "").split())
    if not version:
        return (False, "unknown")
    if not debian:
        return (False, "%s %s" % (fields.get("ID", "unknown"), version))
    major = version.split(".")[0]
    if not major.isdigit():
        return (False, version)
    return (int(major) >= 11, version)


def running_as_root():
    return os.geteuid() == 0


# ======================================================================================
# --- report ----------------------------------------------------------------------------

def _as_entry(line):
    """One Line as a document entry.

    'flags' is carried explicitly rather than left for the consumer to derive from the
    status. Whether a yellow line counts against the run is a real rule with real
    exceptions - 'XOSTOR In Use: Yes' and a backslash in the root password are facts, not
    findings - and a monitoring consumer that re-derived it from the colour would get
    those wrong in exactly the direction that raises false alarms.
    """
    entry = {"key": line.key, "value": line.text, "status": line.status,
             "flags": line.flags}
    if line.detail_text:
        entry["detail"] = {"title": line.detail_title, "text": line.detail_text}
    return entry


class Report(object):
    def __init__(self, filter_output=False, stream=None, json_mode=False, meta=None):
        self.filter_output = filter_output
        self.stream = stream if stream is not None else sys.stdout
        self.json_mode = json_mode
        self.meta = meta or {}
        self.flagged = False
        self._host_details = []
        self._pool_details = []
        self._poolconf = []
        self.host_label = None   # which detail bucket the current section writes into
        self._sections = []      # json only: the buckets, in the order the report makes them
        self._section = None
        self._pending = []       # headings and blanks no line has earned yet
        self._written = 0        # body lines out so far, so a section can tell if it said anything
        self._section_mark = 0

    # -- raw output ---------------------------------------------------------------
    def write(self, text=""):
        """One piece of report BODY. Anything held waiting for it goes out first.

        --json puts the document on stdout and nothing else, so the rendered report is
        suppressed at the single point that produces it rather than at every caller.
        """
        if self.json_mode:
            return
        self._flush_pending()
        self._written += 1
        self.stream.write(text + "\n")

    def write_raw(self, text):
        """Exactly these bytes, no newline added. The pool.conf block carries its own
        spacing, and putting it through write() would silently reshape the report."""
        if self.json_mode:
            return
        self._flush_pending()
        self._written += 1
        self.stream.write(text)

    def _structural(self, text):
        """A heading or a separator: it describes body rather than being body.

        Printed straight out in a full report, held back under -f until a line justifies
        it. See the module docstring for why an empty section may not keep its heading.
        """
        if self.json_mode:
            return
        if self.filter_output:
            self._pending.append(text)
        else:
            self.stream.write(text + "\n")

    def _flush_pending(self):
        if not self._pending:
            return
        held, self._pending = self._pending, []
        for text in held:
            self.stream.write(text + "\n")

    # -- sections -----------------------------------------------------------------
    def begin_section(self, kind, host=None):
        """Say which part of the report the lines that follow belong to.

        This is also what sets host_label, so the bucket a detail blob is filed under and
        the bucket the document lists a check in are decided in one place and cannot
        disagree.
        """
        self.host_label = "XOA" if kind == "xoa" else (host.label if host is not None else None)
        # where this section starts, so end_section can tell whether it printed anything.
        # The heading is already pending by now - it is written before the section opens -
        # which is exactly what makes it droppable along with the rest.
        self._section_mark = self._written
        if not self.json_mode:
            return
        section = {"kind": kind}
        if host is not None:
            section["name"] = host.name
            section["address"] = host.address
            section["master"] = bool(host.is_master)
            # -s and a solo host run render their one host whether it answered or not -
            # its checks are the report - so this must not simply say True
            section["reachable"] = bool(host.reachable)
            if not host.reachable and host.error:
                section["error"] = host.error
            if (host.payload or {}).get("__incomplete__"):
                section["incomplete"] = host.payload["__incomplete__"]
        section["checks"] = []
        self._sections.append(section)
        self._section = section

    def end_section(self):
        if self.filter_output and self._written == self._section_mark:
            # nothing in it printed, so its heading and its separator go with it rather
            # than being flushed by whatever section prints next
            self._pending = []
        self.host_label = None
        self._section = None

    def unreachable_host(self, host):
        """A host we could not collect, recorded with no 'checks' key at all.

        The rendered report gives such a host no block: there is nothing to say about it,
        and an empty block would read as a host that passed everything. That trap is
        sharper in a document a machine walks, where an empty checks list counts as zero
        findings - so the key is absent rather than empty, which cannot be summed.
        """
        if not self.json_mode:
            return
        self._sections.append({"kind": "host", "name": host.name, "address": host.address,
                               "master": bool(host.is_master), "reachable": False,
                               "error": host.error or "not collected"})

    def heading(self, text):
        """A heading prints when the section under it has something to say."""
        self._structural(colors.cyan(text))

    def blank(self):
        self._structural("")

    # -- lines --------------------------------------------------------------------
    def add(self, line, host_label=None):
        """Print one Line (subject to -f), bank its exit-code effect and its detail blob.

        host_label=None sends any detail into the pool bucket, which prints before the
        per-host one.
        """
        if line is None:
            return
        if isinstance(line, (list, tuple)):
            for item in line:
                self.add(item, host_label)
            return
        if line.flags:
            self.flagged = True
        if line.always_print or not self.filter_output:
            self.write(line.render())
            # recorded under the same guard, so --json and the rendered report answer
            # 'was this line in the output' identically, -f included
            if self.json_mode and self._section is not None:
                self._section["checks"].append(_as_entry(line))
            # the detail too: under -f a line that was hidden must not leave its evidence
            # printed at the end with nothing pointing at it
            if line.detail_text:
                if host_label is None:
                    self.add_pool_detail(line.detail_title, line.detail_text)
                else:
                    self.add_host_detail(host_label, line.detail_title, line.detail_text)

    def add_all(self, lines, host_label=None):
        for line in lines:
            self.add(line, host_label)

    # -- deferred blobs -----------------------------------------------------------
    def add_host_detail(self, host_label, title, content):
        self._host_details.append("\n\n\n%s\n%s\n"
                                  % (colors.yellow("%s - %s:" % (host_label, title)), content))

    def add_pool_detail(self, title, content):
        self._pool_details.append("\n\n\n%s\n%s\n" % (colors.yellow("%s:" % title), content))

    def add_poolconf(self, host_label, text):
        first = (text or "").replace("\r", "").split("\n")[0]
        self._poolconf.append("%s\n%s\n\n" % (host_label, first))
        # -f drops the block (no state of it is a finding), so it drops this too: "-f
        # narrows the document identically"
        if self.json_mode and self._section is not None and not self.filter_output:
            # in the document it belongs to the host it describes, rather than to a
            # separate block at the end that a consumer would have to re-attribute
            self._section["pool_conf"] = first

    # -- tail ---------------------------------------------------------------------
    def print_poolconf_section(self):
        """Every host's role, verbatim. -f drops the block whole: it is a reading of every
        host in the pool and there is no state of it that is a finding."""
        if self.filter_output:
            return
        self.blank()
        self.heading("---pool.conf contents---")
        self.write_raw("".join(self._poolconf))

    # The document's shape is fixed here rather than left to follow whatever order the
    # rendered report happens to print its sections in. The XOA section moved to the end
    # of the report - after the hosts it has nothing to do with - and the document did not
    # move with it. Anything not named here still lands, after these, rather than
    # vanishing because someone added a section and not a name.
    SECTION_ORDER = ("xoa", "pool")

    def document(self):
        """The whole run as one JSON-ready object.

        No timestamp: two runs of an unchanged pool should produce the same document, so
        that diffing one against another says something. A consumer that wants to know
        when it read this knows that better than the script does.
        """
        doc = {"script_version": config.SCRIPT_VERSION}
        doc.update(self.meta)
        hosts = []
        buckets = {}
        for section in self._sections:
            body = dict(section)
            kind = body.pop("kind")
            if kind == "host":
                hosts.append(body)
            else:
                buckets[kind] = body
        for kind in ([k for k in self.SECTION_ORDER if k in buckets]
                     + [k for k in buckets if k not in self.SECTION_ORDER]):
            doc[kind] = buckets[kind]
        doc["hosts"] = hosts
        doc["flagged"] = self.flagged
        doc["exit_code"] = 1 if self.flagged else 0
        return doc

    def finish(self):
        """Detail blobs, then the version line, which is the last line of every run.

        It can never flag, so -f prints it too - saying which script produced the report
        above is the entire point of it.
        """
        if self.json_mode:
            # ensure_ascii is the default, but it is stated because it is load-bearing:
            # log excerpts reach here as whatever the host had, and a pure-ASCII document
            # survives any locale a cron job runs under. Escaped characters are still
            # valid JSON and every parser turns them back into the same text.
            self.stream.write(
                json.dumps(self.document(), indent=2, ensure_ascii=True) + "\n")
            return 1 if self.flagged else 0
        # the last section may have printed nothing and left its heading held; the version
        # line is not what earns it, so drop it before anything below flushes
        self._pending = []
        for blob in (self._pool_details, self._host_details):
            text = "".join(blob)
            if text.strip():
                self.write(text)
        self.blank()
        self.write("Health Script Version: %s"
                   % colors.green("v" + config.SCRIPT_VERSION))
        return 1 if self.flagged else 0


    # -- checks -------------------------------------------------------------------
    def check(self, key, fn, *args):
        """Run a check and add its line, turning an escaped exception into a yellow
        Unknown for that line.

        A check that blows up must not take the run down with it, and must not be
        silently skipped either - a missing line reads as 'not applicable', which is a
        claim of its own.
        """
        self.add(result.guard(key, fn, *args), self.host_label)


# ======================================================================================
# --- runcmd ----------------------------------------------------------------------------

def _run_one(run, host):
    """Run the -c command on one host. Returns (rc, out, err); nothing is printed here.

    Same reason _collect_one returns its note instead of writing it: this is called from
    worker threads, and a thread printing as it finishes would interleave the hosts in
    whatever order they happened to answer.
    """
    try:
        return run.transport.run_command(host.address, run.run_cmd)
    except Exception as exc:                      # a transport that could not even start
        return (TRANSPORT_FAILED, "", str(exc))


# Not an exit code any process can produce: 0-255 are all reachable over ssh (255 is ssh's
# own 'the connection failed', a different thing from 'the transport never started'), and
# Popen reports a death by signal N as -N - so -1 was an ssh killed by SIGHUP. None is
# nothing a process returns. Printed as a reason, never as a number.
TRANSPORT_FAILED = None


def execute(run, workers):
    """Run the command on every host of the run and print what each said. Always 0.

    With several hosts there is no single exit code that could mean anything, and 1 and 2
    are already spoken for ('a check flagged' and 'you typed it wrong'), so a caller that
    needs per-host success reads the output.

    Hosts are labelled by address and not by name: the name is a fact this mode never
    collects, and fetching it would be a second round trip per host for a label.

    `workers` is passed in rather than worked out here: main owns that policy (it is the
    same cap a collection runs under), and reaching back into main for it would make this
    the one module that imports main - which on the stitched artifact is the function
    main(), not a module, so it would be an AttributeError there and nowhere else.
    """
    transport.debug("running -c on %d host(s), %d at a time" % (len(run.hosts), workers))
    if workers > 1:
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = [pool.submit(_run_one, run, host) for host in run.hosts]
            try:
                results = [f.result() for f in futures]
            except BaseException:
                # the workers are blocked in communicate() and never see the ctrl-C. The
                # hosts still QUEUED go first: shutdown(wait=True) runs pending work rather
                # than discarding it (cancel_futures is 3.9; the floor is 3.6), so without
                # this a ctrl-C meant to stop the wrong command ran it on every host the
                # pool had not reached yet. main's collection does the same.
                for future in futures:
                    future.cancel()
                transport.kill_all_children()
                raise
        finally:
            pool.shutdown(wait=True)
    else:
        results = [_run_one(run, host) for host in run.hosts]

    # printed in host order, whatever order they finished in
    for host, (rc, out, err) in zip(run.hosts, results):
        sys.stdout.write(colors.cyan("== %s ==" % host.address) + "\n")
        # stdout first either way: a command that failed part way through still said
        # something, and bash printed it too rather than throwing it away
        if out:
            sys.stdout.write(out if out.endswith("\n") else out + "\n")
        if rc != 0:
            if rc is TRANSPORT_FAILED:
                sys.stdout.write(colors.yellow("Could not run the command") + "\n")
            elif transport.is_timeout(rc):
                # the transport's own timeout - a command that itself EXITED 124 (GNU
                # timeout inside the command) is reported as the exit code it is
                sys.stdout.write(colors.yellow(
                    "Command timed out after %ds" % config.RUN_CMD_TIMEOUT) + "\n")
            elif rc < 0:
                sys.stdout.write(colors.yellow("Command killed by signal %d" % -rc) + "\n")
            else:
                sys.stdout.write(colors.yellow("Command failed (exit code %d)" % rc) + "\n")
        # stderr whatever the exit code - "print what each said", and a tool that warns and
        # exits 0 said something too. To stderr, where every other transport message goes,
        # so it cannot contaminate output being piped somewhere
        if err.strip():
            sys.stderr.write(err if err.endswith("\n") else err + "\n")
        sys.stdout.write("\n")
    return 0


# ======================================================================================
# --- main ------------------------------------------------------------------------------

# Laid out the way every other command-line tool on these boxes lays it out: the flag
# first and the sentence after it, so the switches can be read down the left edge in one
# glance. The prose that used to carry them ('Use -f to ...') read as a paragraph and had
# to be searched.
USAGE_XOA = """Usage: %(prog)s [OPTION]... [pool_master_or_host[:ssh_port] [root_password]]
Health-check every host of an XCP-ng pool, from a Xen Orchestra appliance.

All arguments are optional. With no host, the enabled pools in xo-server-db
are listed to pick from - a single enabled pool, or a non-interactive run,
takes the first. With no password, it is looked up in xo-server-db. Every host
in the pool is checked unless -s says otherwise. A host may also be given the
way XO shows it, https:// and all; the port in such an address is the one XO
reaches xapi on, so ssh still goes to port 22.

  -f, --filter          only print checks that flagged; passing and
                        informational lines are hidden, sections included
  -s, --single          check only the given host, not the other pool members
  -n, --name=NAME       pick the pool from xo-server-db by name instead of
                        being prompted: the first pool whose name contains
                        NAME, matched anywhere and ignoring case, so
                        '-n sec' matches 'XEN-SECONDARY'
  -c, --command=CMD     run CMD on every reachable pool host and print what
                        each one said, instead of the health report: no
                        checks are run and no verdict is reached, so the
                        exit status is always 0. Cannot be used with --json
      --json            print the run as one JSON document instead of a
                        report, for cron and monitoring: same checks, same
                        exit code, -f narrows it the same way, and anything
                        that is not the document goes to stderr
  -h, --help            print this help and exit

Exit status: 0 if every check passed, 1 if any flagged, 2 on a usage error.

Examples:
  %(prog)s 192.168.1.5
  %(prog)s 192.168.1.6 'mypass'
  %(prog)s -s 192.168.1.7 'mypass'
  %(prog)s -n sec
  %(prog)s -f -n 'xen-main'
  %(prog)s -c 'cat /etc/resolv.conf'
  %(prog)s --json -n sec
"""

USAGE_HOST = """Usage: %(prog)s [OPTION]... [root_password]
Health-check this XCP-ng host, and the rest of its pool given a root password.

This host is always checked, using local commands - no ssh and no password
needed. The other pool members are checked too if a root password is given:
they are reached over ssh, which needs nothing installed to be handed a
password. Pool members share the master's root password, so one
password covers the pool. With no password and a terminal you are asked for
one; blank, or no terminal (cron, pipe), just checks this host and says so in
the Pool Status section. Prefer the prompt over the argument - an argument is
visible in 'ps' and lands in your shell history. Pool-level results are
reported either way, since xapi answers those from any pool member.

  -f, --filter          only print checks that flagged; passing and
                        informational lines are hidden, sections included
  -s, --single          skip the pool-level section, report on this host alone
      --json            print the run as one JSON document instead of a
                        report, for cron and monitoring: same checks, same
                        exit code, -f narrows it the same way, and anything
                        that is not the document goes to stderr
  -h, --help            print this help and exit

Exit status: 0 if every check passed, 1 if any flagged, 2 on a usage error.

Examples:
  %(prog)s
  %(prog)s -f
  %(prog)s 'mypass'
  %(prog)s --json
"""


def usage(run_env, code=2):
    """-h goes to stdout and exits 0; usage ERRORS go to stderr and exit 2.

    2 rather than 1 matters: 1 is what a perfectly valid run returns when a check flags,
    so a wrapper or cron job could not otherwise tell a typo from a sick pool.
    """
    # Run as `python3 <(curl ...)` - the documented one-liner - argv[0] is /dev/fd/63, and
    # a usage block that calls itself '63' helps nobody
    prog = os.path.basename(sys.argv[0] or "")
    if not prog.endswith(".py"):
        prog = "health.py"
    text = (USAGE_HOST if run_env == "host" else USAGE_XOA) % {"prog": prog}
    (sys.stdout if code == 0 else sys.stderr).write(text)
    sys.exit(code)


def detect_run_env():
    """XCP-ng and XenServer dom0 both set ID=xenenterprise in /etc/os-release, which
    nothing else does. Deliberately not keyed on 'does xe exist': an XOA with the CLI
    installed would then be misread as a host, and a real host with a broken xe deserves
    a clear error rather than a silent fall-back into the XOA path."""
    try:
        with open("/etc/os-release", "r") as fh:
            text = fh.read()
    except (IOError, OSError):
        return "xoa"
    values = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    name = values.get("NAME", "")
    if (values.get("ID") == "xenenterprise"
            or name.startswith("XCP-ng") or name.startswith("XenServer")):
        return "host"
    return "xoa"


def _host_spec(with_smapi):
    return {
        "want": ["host"],
        "crash_ignore_file": config.CRASH_IGNORE_FILE,
        "coredump_dir": config.COREDUMP_DIR,
        "xostor_vg": config.XOSTOR_VG,
        "update_mirror": {"redirector": config.UPDATE_MIRROR_REDIRECTOR,
                          "timeout": config.UPDATE_MIRROR_TIMEOUT,
                          "budget": config.UPDATE_MIRROR_BUDGET,
                          "max_mirrors": config.UPDATE_MIRROR_MAX_PROBES},
        "smapi": bool(with_smapi),
        "log_scan": {"files": config.LOG_ERROR_FILES,
                     "phrases": config.LOG_ERROR_PHRASES,
                     "context": config.LOG_ERROR_CONTEXT,
                     "ignore": config.LOG_ERROR_IGNORE_RULES},
        "lun_scan": {"files": config.LUN_CHANGE_FILES,
                     "phrases": config.LUN_CHANGE_PHRASES,
                     "context": config.LOG_ERROR_CONTEXT},
        "multipath_scan": {"files": config.MULTIPATH_EVENT_FILES,
                           "phrases": config.MULTIPATH_EVENT_PHRASES,
                           "context": config.LOG_ERROR_CONTEXT},
        "multipath": {"transient": config.MULTIPATH_TRANSIENT_CHK_STATES,
                      "recheck_delay": config.MULTIPATH_RECHECK_DELAY},
        "mount_stall_scan": {"files": config.MOUNT_STALL_FILES,
                             "phrases": config.MOUNT_STALL_PHRASES,
                             "context": config.LOG_ERROR_CONTEXT},
        "stuck": {"recheck_delay": config.STUCK_RECHECK_DELAY,
                  "samples": config.STUCK_SAMPLES,
                  "min_age": config.STUCK_MIN_AGE,
                  "max_lines": config.STUCK_MAX_LINES},
        "mount_probe": {"types": config.NETWORK_FS_TYPES,
                        "probe_timeout": config.MOUNT_PROBE_TIMEOUT,
                        "probe_reserve": config.MOUNT_PROBE_RESERVE},
    }


def _pool_spec(controllers, backup_scope=False):
    return {
        "want": ["pool", "yumcheck"],
        "controllers": controllers,
        "qcow2_max": config.XOSTOR_QCOW2_MAX_LINES,
        # the pool's VM and SR uuids, for telling which XO backup jobs touch it - asked
        # only from XOA, the one place that has the jobs to compare them with
        "backup_scope": backup_scope,
    }


def _merge(a, b):
    merged = dict(a)
    for key, value in b.items():
        if key != "want":
            merged[key] = value
    merged["want"] = list(a.get("want", [])) + list(b.get("want", []))
    return merged


class Run(object):
    def __init__(self):
        self.run_env = detect_run_env()
        self.filter_output = False
        self.pool_mode = True
        self.name_filter = ""
        self.run_cmd = ""         # -c: a command to run on every host INSTEAD of the report
        self.json_output = False
        self.seed = ""
        self.seed_uuid = ""       # the seed's own INSTALLATION_UUID, from discovery
        self.server = None        # the pool's xo-db record, when there is one
        self.password = ""
        self.password_after_name = False   # the password was the argument after -n
        self.pw_has_backslash = False
        self.host_sweep = False
        self.transport = None
        self.hosts = []
        self.pool = model.Pool()
        self.master_address = ""
        self.master_name = ""
        self.pool_name = ""
        self.pool_cmd_host = ""
        self.pool_size = 0
        self.all_addresses = []
        self.host_names = {}      # address -> xapi hostname, for EVERY pool member
        self.state_db = None      # set when the host list came from a state.db, not xapi

    def host_solo(self):
        """On a hypervisor with nothing else reachable. This, not the run environment, is
        what the checks ask: a host WITH a password behaves exactly like an XOA run."""
        return self.run_env == "host" and not self.host_sweep

    def host_by_address(self, address):
        for host in self.hosts:
            if host.address == address:
                return host
        return None

    def master_manifest(self):
        master = self.host_by_address(self.master_address)
        if master is None:
            return ""
        f = master.fact("rpm_manifest")
        return f.value if f.ok else ""

    def parse_args(self, argv):
        try:
            opts, args = getopt.gnu_getopt(
                argv, "fhsn:c:",
                ["filter", "help", "single", "name=", "command=", "json"])
        except getopt.GetoptError as exc:
            sys.stderr.write("%s\n" % exc)
            usage(self.run_env)
        for opt, value in opts:
            if opt in ("-f", "--filter"):
                self.filter_output = True
            elif opt in ("-h", "--help"):
                usage(self.run_env, 0)
            elif opt in ("-s", "--single"):
                self.pool_mode = False
            elif opt in ("-n", "--name"):
                if not value.strip():
                    # every later test of -n is "if run.name_filter", so an empty one would
                    # read as no -n at all - and the password after it as the host, printed
                    # in the banner and handed to DNS
                    sys.stderr.write("ERROR: -n/--name needs a pool name.\n")
                    usage(self.run_env)
                self.name_filter = value
            elif opt in ("-c", "--command"):
                if not value.strip():
                    # an empty -c would read as no -c and run the whole health report
                    sys.stderr.write("ERROR: -c/--command needs a command to run.\n")
                    usage(self.run_env)
                self.run_cmd = value
            elif opt == "--json":
                self.json_output = True
        if len(args) > 2:
            usage(self.run_env)
        if self.run_cmd and self.json_output:
            # The document is a health check's shape: every entry is a Line with a status
            # and an explicit 'flags', and doc['flagged']/'exit_code' are summed from them.
            # -c reports no verdict by design, so it has nothing to put there - and a
            # consumer reading 'flagged': false off a document that judged nothing would
            # conclude the pool was healthy. Refuse rather than emit that.
            sys.stderr.write(
                "ERROR: --json describes a health check, and -c/--command runs a command "
                "and reaches\n       no verdict, so there is nothing for the document to "
                "report. Use -c on its own.\n")
            usage(self.run_env)
        return args


def notice(run, text):
    """A message the rendered report puts on stdout.

    Under --json stdout carries the document and nothing else, so these go to stderr
    instead: a consumer's stdout is then either a whole valid document or empty, never a
    mixture that fails to parse for a reason it cannot see.
    """
    (sys.stderr if run.json_output else sys.stdout).write(text)


_PROGRESS_LOCK = threading.Lock()


def progress_enabled():
    """Live progress is for a person watching a terminal, and for nobody else.

    stderr only, and only when it is a tty: stdout carries the report (or the --json
    document) and does not change, and a captured, piped or cron run gets exactly the bytes
    it got before - which is also what keeps the old-vs-new regression diffs honest.
    """
    try:
        return bool(sys.stderr.isatty())
    except (AttributeError, ValueError):
        return False


def progress(text):
    """One whole line at a time - every host worker writes here.

    Between the banner and the first line of the report the run makes one ssh call to
    discover the pool and then one per host, each of which may take REMOTE_CMD_TIMEOUT,
    and the report cannot start until the last one is in. Printing nothing in the
    meantime makes a slow host indistinguishable from a wedged script: it was read as one
    and killed twice before the collectors had run out of their own budget.
    """
    if not progress_enabled():
        return
    with _PROGRESS_LOCK:
        sys.stderr.write(text)
        sys.stderr.flush()


def print_banner(run, host, name):
    """Every run names what it is about to check, before any of the slow work.

    The paths that pick silently - the sole enabled pool, and cron/pipe runs - are exactly
    the ones where this line is the only record of which pool was taken.
    """
    if name:
        notice(run, "Checking pool: %s\n" % colors.green("%s (%s)" % (name, host)))
    else:
        notice(run, "Checking host: %s\n" % colors.green(host))
    # -f is asked for when the answer is wanted in as few lines as possible, and the very
    # next thing it prints is a heading; a full report keeps the separator
    if not run.filter_output:
        notice(run, "\n")


def require_root(run_env):
    """Both environments need root, for different reasons - and say which.

    On a hypervisor, xe / dmesg / the logs would otherwise fail one at a time and the run
    would blame the toolstack for what is really a missing sudo.

    On XOA the appliance's own login user is 'xoa', not root, so this is the FIRST thing a
    new user hits. Measured on the appliance (Debian 12): xo-server-db cannot stat
    /etc/xo-server/config.toml (EACCES - the directory has no execute bit for others), so
    every lookup answers nothing and the run used to conclude 'no enabled hosts found in
    xo-db' on an XOA with five pools; a bare host argument read as 'not in xo-db'; and
    with a host AND a password the pool was checked but the XOA section printed sudo's
    own 'a terminal is required' as an 'XOA Check' finding and could not read dmesg
    (kernel.dmesg_restrict), so no non-root run could ever be clean. Nothing here can be
    established without root, so nothing is attempted.

    'sudo python3 <(curl ...)' is not the fix, and the message says so: sudo closes the
    descriptor the process substitution opens, and python3 reports /dev/fd/63 as missing.
    """
    if xoa.running_as_root():
        return True
    if run_env == "host":
        sys.stderr.write("ERROR: this must run as root on an XCP-ng host (it reads dom0 "
                         "logs and talks to xapi).\n")
    else:
        sys.stderr.write(
            "ERROR: this must run as root on XOA: the pool list and root passwords come out of\n"
            "       xo-server-db, and 'xoa check' and dmesg need root too. Become root first\n"
            "       (sudo -i) and run it again - note that 'sudo python3 <(curl ...)' does not\n"
            "       work, because sudo closes the descriptor the <( ) opens.\n")
    return False


def _xodb_unreadable(consequence):
    """xo-server-db answered nothing and said why: report THAT - never 'no pools' or 'not
    in xo-db', which are claims about a db nobody read. Exits 1."""
    sys.stderr.write("ERROR: could not read xo-server-db (%s), so %s\n"
                     % (xodb.read_error(), consequence))
    sys.exit(1)


def _known_as(server, how):
    """How xo-db knows an address, for the message that refuses it as a password."""
    if how == "member":
        return "the address of a member of pool '%s' in xo-server-db" % server.name
    if how == "dns":
        return ("an address of pool '%s' (xo-server-db has it as %s, which resolves to it)"
                % (server.name, xodb.db_address(server.record)))
    return "the address of pool '%s' in xo-server-db" % server.name


def _server_record(run):
    """The pool's xo-db record, looked up the first time something needs it: a run given
    a host and its password never had to, and most runs never ask."""
    if run.server is None:
        run.server = xodb.server_for_host(run.seed)[0] or {}
    return run.server


def resolve_target_xoa(run, args):
    """Pick a pool / take the host argument, then find a password for it.

    False if there is no way to give ssh a password at all, which is not fatal: the
    appliance's own section is still worth printing, and is still the truth.
    """
    if run.name_filter and len(args) > 1:
        sys.stderr.write("ERROR: -n/--name looks the host up in xo-server-db, so it takes "
                         "at most a password after it.\n")
        usage(run.run_env)

    # With one trailing argument the two readings are indistinguishable by shape and it is
    # read as a password - so '-n sec 192.168.1.5' used to try to log into the -n-matched
    # pool using an address as the password, surfacing as an authentication failure a long
    # way from the cause. Only xo-db can tell them apart: nobody's root password is one of
    # their own pool addresses. Those include the addresses of a pool stored by name, and
    # its slaves': '-n a01 192.0.2.60' against a record holding xcp-a01... was
    # taken for a password. The argument itself is never looked up in DNS - it may be one.
    if run.name_filter and len(args) == 1:
        clash, how = xodb.enabled_server_for(args[0], resolve_want=False)
        if clash is not None:
            sys.stderr.write(
                "ERROR: '%s' is %s, but the value after\n"
                "       -n/--name is read as a password, not a host - -n already selects the pool.\n"
                "       Use either '-n %s' or the host '%s', not both.\n"
                % (args[0], _known_as(clash, how), run.name_filter, args[0]))
            usage(run.run_env)
        run.password_after_name = True

    selected = None
    if run.name_filter or not args:
        code, selected = xodb.select_pool(run.name_filter)
        if code == xodb.SELECT_QUIT:
            sys.stderr.write("Aborted.\n")
            sys.exit(0)
        if code == xodb.SELECT_NO_MATCH:
            sys.exit(1)
        if code == xodb.SELECT_UNREADABLE:
            _xodb_unreadable("there is no pool list to pick from.\n       Provide the pool "
                             "master's IP and root password as arguments instead.")
        if code == xodb.SELECT_NONE:
            sys.stderr.write("No host IP provided and no enabled hosts found in xo-db, "
                             "please provide a host IP as an argument\n")
            sys.exit(1)
        args = [selected.host] + list(args)

    if selected is not None:
        # a picker-chosen host is a server record's `host`, read the way XO reads it: it
        # may carry a scheme, and a ':port' that is the XAPI HTTPS port XO connects on -
        # not an ssh port, so it is stripped for ssh and we stay on 22
        host = parsers.xo_server_address(selected.host)[0]
        run.transport.ssh_port = 22
        run.server = selected.record
        if not host:
            # 'https://' with nothing after it: ssh handed an empty host prints its own
            # usage text, which says nothing about where the address came from
            sys.stderr.write("ERROR: the address xo-server-db holds for pool '%s' names no "
                             "host.\n       Fix it in XO, or give the master's IP as an "
                             "argument instead.\n" % selected.name)
            sys.exit(1)
    elif parsers.has_url_scheme(args[0]):
        # given the way XO shows a pool's address - 'https://10.0.0.5', copied out of its
        # list of servers - and read the way XO reads one. The port of such an address is
        # the one xapi answers on, not sshd's, so ssh stays on 22 here too
        host = parsers.xo_server_address(args[0])[0]
        run.transport.ssh_port = 22
        if not host:
            sys.stderr.write("ERROR: '%s' names no host.\n" % args[0])
            usage(run.run_env)
    else:
        host, port = parsers.split_host_port(args[0])
        run.transport.ssh_port = port or 22
    run.seed = host

    run.pool_name = selected.name if selected else xodb.pool_name_for_host(host)
    print_banner(run, host, run.pool_name)

    if not run.transport.enable_password_auth(run.run_env):
        # not an exit: the appliance's own section needs no pool access, and on the
        # offline XOA this fires on it is the half of the report that can still be
        # produced. main() takes it from here - see xoa_only_report().
        return False

    if len(args) == 2:
        run.password = args[1]
    else:
        # the picked record's own password, or the record this address belongs to - by
        # its host field, by XO's list of the pool's members, or by DNS for a pool stored
        # by name. A member's address finds the pool's password: every member shares it.
        if run.server is None:
            run.server = xodb.server_for_host(host)[0]
        user = xodb.record_user(run.server)
        if user and user != "root":
            # XO logs in to xapi as this user; its password is not root's, and sending it
            # to sshd as root's would read as a wrong root password (and hand that
            # account's password to a root login attempt)
            sys.stderr.write("ERROR: xo-db holds the credentials of xapi user '%s' for %s, "
                             "not root's.\n       Give the root password as an argument "
                             "instead.\n" % (user, host))
            sys.exit(1)
        password, has_backslash = xodb.record_password(run.server)
        run.pw_has_backslash = has_backslash
        if not password:
            if xodb.read_error():
                # the same distinction as the picker's: 'not found' is a statement about
                # the db's contents, which were never seen
                _xodb_unreadable("no password could be looked up for %s.\n       Provide "
                                 "the root password as a second argument instead." % host)
            notice(run, "Host IP not found in xo-db, please manually provide a "
                        "password, or check that the IP is the master host and not "
                        "a slave\n")
            sys.exit(1)
        run.password = password
    run.transport.password = run.password
    return True


def resolve_target_host_mode(run, args):
    """On a hypervisor the target is this machine, so the only positional that makes sense
    is the root password for the OTHER pool members. A second one would have been a host,
    which is not selectable - saying so beats failing later with an auth error."""
    if run.name_filter:
        sys.stderr.write("ERROR: -n/--name picks a pool out of xo-server-db, which only "
                         "exists on XOA.\n")
        usage(run.run_env)
    if run.run_cmd:
        # XOA-only, like -n. There it earns its place by carrying the pool selection and
        # the root password out of xo-server-db, so a sweep needs no inventory and no
        # credentials. On a hypervisor neither exists: the command would run on this one
        # host, or on the others only if a password were typed at the prompt - which is
        # an ssh loop with extra steps, from a machine that already has a root shell.
        sys.stderr.write("ERROR: -c/--command is an XOA feature: it runs a command across "
                         "a pool using the\n       host list and root password from "
                         "xo-server-db, neither of which exists here.\n"
                         "       You already have a root shell on this host.\n")
        usage(run.run_env)
    if len(args) > 1:
        sys.stderr.write("ERROR: running on an XCP-ng host, so the host to check is this "
                         "one and cannot be chosen.\n"
                         "       The only argument accepted here is the root password of "
                         "the other pool members.\n")
        usage(run.run_env)
    return args[0] if args else ""


def prepare_host_sweep(run, argument_password):
    """Decide whether this run can also check the other pool members, and with what.

    A hypervisor has no xo-server-db to look a password up in, so it comes from the
    command line or from asking - and asking only makes sense with a terminal, so cron and
    piped runs quietly check this host alone instead of hanging on a prompt. No password
    is not an error: it is the documented single-host behaviour, and Pool Status says so.
    """
    if not run.pool_mode or run.pool_size <= 1:
        return
    password = argument_password
    if not password:
        try:
            interactive = sys.stdin.isatty()
        except (AttributeError, ValueError):
            interactive = False
        if interactive:
            import getpass
            # to stderr, like the pool picker's prompt, so it never lands in redirected
            # output; getpass does not echo, so the newline the user typed is swallowed
            sys.stderr.write("This pool has %d hosts. Root password to check the others "
                             "(blank = this host only): " % run.pool_size)
            sys.stderr.flush()
            try:
                password = getpass.getpass("")
            except EOFError:
                # end of input is the blank answer; a ctrl-C is a stop, and goes on up to
                # entry() like one anywhere else
                password = ""
            sys.stderr.write("\n")
    if not password:
        return
    if not run.transport.enable_password_auth(run.run_env):
        sys.stderr.write("ERROR: %s.\n" % run.transport.auth_error)
        sys.stderr.write("Continuing with this host only.\n")
        return
    run.password = password
    run.transport.password = password
    run.host_sweep = True


def discovery_spec():
    """What the discovery call asks for.

    HEALTH_HOST_LIST=statedb takes the host list from the seed's state.db even when xapi
    would have answered. That path is otherwise only reached on a pool whose toolstack is
    down, so this is how it is diffed against xapi's answer on a healthy one - and the
    only way to exercise it on a multi-host pool without stopping anybody's xapi.
    """
    spec = {"want": ["pool_hosts"]}
    pinned = os.environ.get("HEALTH_HOST_LIST", "")
    if pinned not in ("", "xapi", "statedb"):
        sys.stderr.write("Warning: ignoring HEALTH_HOST_LIST=%s (expected xapi or statedb).\n"
                         % pinned)
    elif pinned == "statedb":
        spec["host_list"] = "statedb"
    return spec


def _host_records(run, payload, forced):
    """The pool's members: xapi's answer, or failing that the seed's saved database.

    xapi not answering used to end the run here, before a single host was looked at -
    on exactly the pools that most need looking at, since a master change that fails
    part way leaves xapi down or refusing on every member. The database xapi would have
    answered from is a file that every member keeps, so the run carries on from that,
    checks whatever it can on each host without xapi, and says where the list came from.
    """
    listed = result.wrap(payload, "pool_hosts")
    if listed.ok and not forced:
        return parsers.parse_host_list(listed.value)
    saved = result.wrap(payload, "pool_hosts_db")
    if not saved.ok:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s': %s\n"
                         "       and its saved copy of the pool database could not be read "
                         "either: %s\n"
                         % (run.seed or "this host", listed.error, saved.error))
        sys.exit(1)
    run.state_db = {"forced": forced, "reason": listed.error,
                    "path": saved.value.get("path"), "saved": saved.value.get("saved")}
    records = parsers.host_records_from_state_db(saved.value.get("hosts"))
    if not forced:
        progress("  xapi did not answer (%s)\n  read %d host(s) from its %s instead\n"
                 % (listed.error, len(records), saved.value.get("path")))
    return records


def _own_address(payload, records):
    """This host's address in host mode: xapi's answer, else its own row in the saved
    database - found by the INSTALLATION_UUID the collector read off disk, so it cannot
    be some other member's. None if neither says."""
    address = result.wrap(payload, "self_address")
    if address.ok and address.value:
        return address.value, None
    uuid = result.wrap(payload, "self_uuid")
    if uuid.ok:
        for rec in records:
            if rec["uuid"] == uuid.value and rec["address"]:
                return rec["address"], None
    return None, address.error


def discover(run):
    """Phase A: one call to the seed for the pool's host list and our own identity."""
    spec = discovery_spec()
    progress("Asking %s for the pool's host list...\n" % (run.seed or "this host"))
    try:
        if run.run_env == "host":
            payload = run.transport.collect_local(spec)
        else:
            payload = run.transport.collect(run.seed, spec)
    except transport.CollectError as exc:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s': %s\n"
                         % (run.seed or "this host", exc))
        if run.password_after_name and "Permission denied" in str(exc):
            # the one reading xo-db could not settle: an address it does not know - a
            # slave of a pool stored by name, on an XO too old to list members - went in
            # as the password. Said without echoing it, since it may really be one.
            sys.stderr.write("       With -n/--name the one argument after it is the root "
                             "password, not a host.\n")
        sys.exit(1)

    records = _host_records(run, payload, spec.get("host_list") == "statedb")
    self_uuid = result.wrap(payload, "self_uuid")
    if self_uuid.ok and self_uuid.value:
        run.seed_uuid = self_uuid.value

    if run.run_env == "host":
        address, why = _own_address(payload, records)
        if not address:
            sys.stderr.write("ERROR: could not get this host's address from xapi "
                             "(is the toolstack running?): %s\n"
                             "       and this host is not in its own saved copy of the pool "
                             "database either\n" % why)
            sys.exit(1)
        run.seed = address
        run.transport.local_address = address
        name = result.wrap(payload, "hostname")
        shown = ("%s (%s)" % (name.value, address)
                 if name.ok and name.value else address)
        print_banner(run, shown, "")

    hosts = []
    for rec in records:
        if not rec["address"]:
            sys.stderr.write("Warning: pool host %s has no address in the host list; "
                             "skipping it\n" % rec["uuid"])
            continue
        hosts.append(model.Host(rec["address"], rec["uuid"], rec["hostname"],
                                rec["enabled"], rec["multipathing"]))
    if not hosts:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s'.\n"
                         % run.seed)
        sys.exit(1)

    run.pool_size = len(hosts)
    run.all_addresses = [h.address for h in hosts]
    # every member's name while the whole pool is in hand: a solo run narrows the list
    # to this machine, and the XOSTOR controller may be a host it never looks at
    run.host_names = dict((h.address, h.hostname) for h in hosts if h.hostname)

    # the seed's own pool.conf names the master outright, whether we are it or not - and
    # it stays truthful when the toolstack is wedged, which is why it is read rather than
    # xapi being asked
    conf = result.wrap(payload, "pool_conf")
    role, master = parsers.parse_pool_conf(conf.value if conf.ok else "")
    if role == "master":
        # pool.conf says only "master" - it carries no address - so the seed stands in for
        # one. That address is whatever was dialled, which on a master with a secondary
        # network need not be the address xapi publishes in host-list; every later
        # comparison is against that published address, so resolve the seed to its own
        # host record and prefer what xapi calls it.
        run.master_address = run.seed
        if run.seed_uuid:
            for host in hosts:
                if host.uuid == run.seed_uuid:
                    run.master_address = host.address
                    break
    elif role == "slave":
        run.master_address = master

    # Name the master from xapi's host record here, while the WHOLE pool is still in hand:
    # a solo run narrows the list to this machine, and the master it names may be a host
    # this run never looks at - or cannot reach at all.
    for host in hosts:
        if host.address == run.master_address:
            run.master_name = host.hostname
    return hosts


def _collect_one(run, host, pool_spec):
    """Gather one host. Anything it wants said is RETURNED, not printed.

    A worker thread writing straight to stderr would interleave the messages in whatever
    order the hosts happened to finish, which is not reproducible between runs; the caller
    writes them out in host order instead.
    """
    # is_master is already settled (see main): it decides which checks run for this
    # host, and therefore what has to be collected for them
    spec = _host_spec(with_smapi=(not run.pool_mode or host.is_master
                                  or config.POOL_RUN["smapi_hidden_leaves"]))
    if run.pool_mode and host.address == run.pool_cmd_host:
        spec = _merge(spec, pool_spec)
    note = ""
    started = _now()
    try:
        host.payload = run.transport.collect(host.address, spec)
    except transport.CollectError as exc:
        host.error = str(exc)
        note = "Failed when trying to check %s: %s\n" % (host.address, exc)
    host.local_now = _now()
    incomplete = (host.payload or {}).get("__incomplete__")
    if incomplete:
        note = "Only part of %s was checked: %s\n" % (host.address, incomplete)
    # whichever way it went, say so now: the note is held back until every host is in, and
    # by then the thing worth knowing - which host the run was waiting on - has passed
    progress("  %s %s (%.1fs)\n" % (host.address,
                                    "failed" if host.error else
                                    "answered in part" if incomplete else "answered",
                                    host.local_now - started))
    return note


def parallel_workers(host_count):
    """How many hosts to gather at once.

    Capped because the win is had by the time a handful are in flight, while the cost of
    lifting the cap is real: every host in flight is an ssh process, a ControlMaster
    socket and a collector holding a whole host's document in memory. HEALTH_MAX_PARALLEL
    overrides it, and =1 restores the strictly sequential order - which is how the two are
    diffed against each other.
    """
    limit = config.MAX_PARALLEL_HOSTS
    override = os.environ.get("HEALTH_MAX_PARALLEL", "")
    if override.isdigit() and int(override) > 0:
        limit = int(override)
    elif override:
        # =1 is how the concurrent path is diffed against the sequential one: a typo must
        # not quietly run the concurrent path while claiming the sequential one
        sys.stderr.write("Warning: ignoring HEALTH_MAX_PARALLEL=%r (expected a whole "
                         "number of 1 or more).\n" % override)
    return max(1, min(limit, host_count))


def _wait_with_progress(futures, addresses):
    """Wait for the collectors, naming every so often the hosts that have not answered.

    A host that is merely slow - a wedged 'yum check-update' against an unreachable
    mirror is the usual one - holds the whole phase for up to REMOTE_CMD_TIMEOUT, and
    'answered' lines only appear as each host finishes. This is what fills the gap in
    between, so the run says what it is waiting for instead of appearing to hang.
    """
    if not progress_enabled():
        return
    started = _now()
    while True:
        _, not_done = futures_wait(futures, timeout=config.PROGRESS_INTERVAL)
        if not not_done:
            return
        waiting = [addresses[i] for i, f in enumerate(futures) if f in not_done]
        progress("  still waiting on %s (%ds)\n"
                 % (", ".join(waiting), _now() - started))


def _collect_in_parallel(run, pool_spec, workers):
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [pool.submit(_collect_one, run, host, pool_spec) for host in run.hosts]
        try:
            _wait_with_progress(futures, [h.address for h in run.hosts])
            return [f.result() for f in futures]
        except BaseException:
            # named and immediately re-raised, so this is not a swallowed error: the
            # workers are blocked in communicate() and cannot see a ctrl-C, so without
            # this the shutdown below would wait out every collector still running.
            # The hosts still QUEUED have to be dropped as well - shutdown(wait=True) does
            # not discard pending work, so with more hosts than workers a ctrl-C would
            # start a brand new ssh for every host it had not reached yet and then wait
            # out all of them. (shutdown(cancel_futures=True) is 3.9; the floor here is
            # 3.6.) Cancel before killing, so nothing is launched into the gap.
            for future in futures:
                future.cancel()
            transport.kill_all_children()
            raise
    finally:
        pool.shutdown(wait=True)


def collect_hosts(run):
    """Phase B: one call per host, several hosts at a time.

    The pool-level questions ride along on the host they are asked of, so the usual case
    is exactly one round trip per host. Hosts are wholly independent of each other - each
    is its own ssh connection, its own collector process and its own slice of the
    document - so gathering them concurrently changes nothing but the wall clock.
    """
    controllers = run.all_addresses if run.host_solo() else [h.address for h in run.hosts]
    pool_spec = _pool_spec(controllers, backup_scope=(run.run_env != "host"))

    workers = parallel_workers(len(run.hosts))
    transport.debug("collecting %d host(s), %d at a time" % (len(run.hosts), workers))
    progress("Collecting from %d host(s), %d at a time, up to %ds each: %s\n"
             % (len(run.hosts), workers, config.REMOTE_CMD_TIMEOUT,
                ", ".join(h.address for h in run.hosts)))
    if workers > 1:
        notes = _collect_in_parallel(run, pool_spec, workers)
    else:
        notes = [_collect_one(run, host, pool_spec) for host in run.hosts]
    for note in notes:
        if note:
            sys.stderr.write(note)

    if run.pool_mode:
        cmd_host = run.host_by_address(run.pool_cmd_host)
        if cmd_host is not None and cmd_host.reachable:
            pool_doc = cmd_host.payload.get("pool")
            stopped = cmd_host.payload.get("__incomplete__")
            if pool_doc is None and stopped:
                # the host stopped before the pool questions: every pool line says so
                pool_doc = {"ok": False, "error": "not asked - %s %s"
                                                  % (cmd_host.address, stopped)}
            run.pool.payload = pool_doc or {}
            run.pool.payload["yum_check"] = cmd_host.payload.get("yum_check") or {
                "ok": False, "error": ("not asked - %s %s" % (cmd_host.address, stopped)
                                       if stopped else "not collected")}
        else:
            # the host we meant to ask is unreachable - xapi answers pool-wide questions
            # from any member, so ask one we can reach rather than losing the section
            _collect_pool_elsewhere(run, pool_spec)


def _collect_pool_elsewhere(run, pool_spec):
    for host in run.hosts:
        if not host.reachable:
            continue
        try:
            payload = run.transport.collect(host.address, pool_spec)
        except transport.CollectError as exc:
            sys.stderr.write("Failed when trying to read pool state from %s: %s\n"
                             % (host.address, exc))
            continue
        run.pool.payload = payload.get("pool") or {}
        run.pool.payload["yum_check"] = payload.get("yum_check") or {
            "ok": False, "error": "not collected"}
        run.pool_cmd_host = host.address
        return
    run.pool.error = "no reachable pool member to ask"


def _now():
    import time
    return time.time()


def pool_status_section(run, rep):
    rep.heading("== Pool Status ==")
    rep.begin_section("pool")

    if run.master_address:
        name = run.master_name or run.master_address
        rep.add(result.info("Pool Master", "%s (%s)" % (name, run.master_address)))
    else:
        rep.add(result.info("Pool Master", "(unknown)", "yellow"))

    if run.state_db is not None:
        rep.check("Pool Host List", checks.pool_host_list, run.state_db, run.seed,
                  run.pool_size)

    if run.host_solo():
        # nothing else was probed, so there is no reachability result to report and
        # nothing to compare across hosts - the RAM and time-sync lines would be claims
        # about hosts we never looked at. Say how much of the pool this run covers instead.
        if run.pool_size > 1:
            rep.add(result.info("Hosts in Pool",
                                "%d (only this host checked - give the root password to "
                                "include the others)" % run.pool_size))
        else:
            rep.add(result.info("Hosts in Pool", str(run.pool_size)))
    else:
        unreachable = [h.address for h in run.hosts if not h.reachable]
        if unreachable:
            rep.add(result.flag("Unreachable Hosts", " ".join(unreachable)))
        else:
            rep.add(result.ok("Unreachable Hosts", "None"))
        # who each host thinks the master is, read off disk - so it still answers when
        # xapi is down everywhere, which is when a failed master change needs it most
        rep.check("Pool Roles", checks.pool_roles, run.hosts)

        reachable = [h for h in run.hosts if h.reachable]
        rep.check("Dom0 RAM Allocations", checks.dom0_ram_allocations, reachable)
        rep.check("Pool Time Synchronization", checks.pool_time_sync, reachable)
        # like the two above, a comparison ACROSS hosts, so it belongs to the pool rather
        # than to any one host and has nothing to say when only one host was looked at
        rep.check("Multipath Path Counts", checks.multipath_path_counts, reachable)
        # the XOA counts as one of the machines: an appliance holding a host's address
        # is the same fault as two hosts holding one
        rep.check("Duplicate IPs Across Hosts", checks.duplicate_ips_across_hosts, run.hosts,
                  xoa.ip_addrs() if run.run_env == "xoa" else None)

    rep.check("HA Enabled", checks.ha_enabled, run.pool)
    rep.check("SR Attachment", checks.sr_attachment, run.pool)
    rep.check("Long-Running Tasks", checks.long_running_tasks, run.pool)
    rep.check("Leaf-Coalesce Disabled", checks.leaf_coalesce_disabled, run.pool)
    rep.check("Windows VMs Not Optimized", checks.windows_vms_not_optimized, run.pool)
    rep.check("Migration Compression", checks.migration_compression, run.pool)
    rep.check("Missing Patches", checks.missing_patches, run.pool)
    if not run.host_solo():
        # roll-ups of per-host lines, next to the patch line they explain
        reachable = [h for h in run.hosts if h.reachable]
        rep.check("Hosts Pending Reboot", checks.pending_reboot_pool, reachable,
                  config.POOL_RUN.get("rebooted_after_updates", True))
        rep.check("Update Mirror Access", checks.update_mirror_access_pool, reachable,
                  config.POOL_RUN.get("update_mirror_access", True))

    if run.pw_has_backslash:
        rep.add(result.info("Root Password", "Contains Backslash", "yellow"))

    rep.check("XOSTOR In Use", checks.xostor_in_use, run.pool)
    if run.pool.xostor_in_use():
        # every node this run looked at: each one runs DRBD and a LINSTOR satellite
        rep.check("XOSTOR RAM", checks.xostor_ram, [h for h in run.hosts if h.reachable])
        if not run.host_solo():
            # the master always prints its own XOSTOR lines, but a slave's discrepancy
            # is only spelled out if slaves run them too
            rep.check("XOSTOR Version Consistency", checks.xostor_version_consistency,
                      [h for h in run.hosts if h.reachable],
                      config.POOL_RUN.get("xostor_versions", True))
            rep.check("XOSTOR Missing Devices", checks.xostor_missing_devices_pool,
                      [h for h in run.hosts if h.reachable],
                      config.POOL_RUN.get("xostor_missing_devices", True))
        rep.check("XOSTOR Faulty Resources", checks.xostor_faulty_resources, run.pool)
        rep.check("XOSTOR Faulty Nodes", checks.xostor_nodes, run.pool)
        rep.check("XOSTOR Controller IP", checks.xostor_controller, run.pool, run.host_names)
        rep.check("XOSTOR PrefNic", checks.xostor_pref_nic, run.pool)
        rep.check("XOSTOR QCOW2 VDIs", checks.xostor_qcow2, run.pool)

    rep.check("VLAN 0 Check", checks.vlan0, run.pool)
    rep.check("Migration Network", checks.migration_network, run.pool)
    rep.check("Backup Network", checks.backup_network, run.pool, run.run_env,
              xoa.ping_silent,
              lambda pool_uuid, vm_uuids, sr_uuids: xodb.backup_routes(
                  _server_record(run), pool_uuid, vm_uuids, sr_uuids))
    # inside the section, so that under -f a pool with nothing to report takes its own
    # separator with it instead of leaving a blank line where the section was
    rep.blank()
    rep.end_section()


_NO_POOL_ACCESS_HELP = """\
%(reason)s.

Every check except the XOA section logs into the pool hosts over ssh as root, and ssh
takes a password only from a terminal or from a helper program - so this run could report
on the appliance and on nothing else.

The helper is written into the run's temporary directory, so the fix that needs nothing
installed and no internet access is to point the run at one it may execute from:

    TMPDIR=/root python3 health.py %(args)s

Failing that, sshpass is used when it is already installed (nothing is installed for it).
An XCP-ng 8.3 host can also be checked by running health.py on the host itself, which
needs no credentials at all for the machine it is running on."""


def _target_hint(run):
    """How this run named its target, for the suggested command line.

    Rebuilt rather than taken from sys.argv, because the argv of a run given its password
    on the command line contains that password, and this text is printed.
    """
    if run.name_filter:
        name = run.name_filter
        return "-n %s" % (("'%s'" % name) if " " in name else name)
    return run.seed or ""


def xoa_only_report(run, rep_meta, xoa_worker):
    """Everything still establishable when the pool cannot be logged into at all.

    The appliance's own section shares nothing with the pool - version, updates, services,
    disk, plugins, backup networks - so it is a whole answer to half the question, and
    printing it beats the single line about sshpass that an appliance with no internet
    access used to get in place of a report.

    The pool is reported Unknown rather than left out: a run that could not look at the
    pool it was asked about must not exit 0, and a section that is simply absent reads as
    one that passed.
    """
    rep = report.Report(run.filter_output, json_mode=run.json_output, meta=rep_meta)
    rep.heading("== Pool Status ==")
    rep.begin_section("pool")
    reason = run.transport.auth_error or "the pool could not be reached over ssh"
    shown = run.pool_name or run.seed or "the pool"
    rep.add(result.unknown("Pool Access", "Unknown - %s was not checked: %s"
                           % (shown, reason))
            .with_detail("Pool Access",
                         _NO_POOL_ACCESS_HELP % {"reason": reason,
                                                 "args": _target_hint(run)}))
    rep.blank()
    rep.end_section()

    if xoa_worker is not None:          # none under -c, which reports no verdict
        rep.begin_section("xoa")
        rep.heading("== XOA Status ==")
        rep.add_all(xoa_worker.result(), "XOA")
        rep.end_section()
    return rep.finish()


def run_meta(run):
    """What the run itself was, for the head of a --json document.

    Three host counts, because they routinely differ and collapsing them would overclaim:
    the pool has N members, -s or a solo run may put fewer than N in scope, and of those
    some may not have answered. A consumer told only 'checked: 2' would read a run that
    reached one host of two as a clean pool. It is the same distinction the Pool Status
    section is careful to make in words.
    """
    return {"run": {
        "environment": run.run_env,
        "pool_mode": run.pool_mode,
        "filtered": run.filter_output,
        "target": run.seed,
        "pool_name": run.pool_name or None,
        "hosts_in_pool": run.pool_size,
        "hosts_attempted": len(run.hosts),
        "hosts_checked": len([h for h in run.hosts if h.reachable]),
    }}


def per_host_checks():
    """(POOL_RUN toggle, line key, check) for every gated per-host line, in print order.

    A function rather than a constant because in the stitched artifact every module body
    runs before the module aliases exist, so a top-level list mentioning `checks.x` would
    fail at import. It is also the table the tests enumerate, so a check added here cannot
    quietly skip the rule that a missing fact answers Unknown.
    """
    return [
        ("dom0_disk_usage", "Dom0 Disk Usage", checks.dom0_disk_usage),
        ("read_only_filesystems", "Read-Only Filesystems", checks.read_only_filesystems),
        ("dom0_memory", ("Dom0 Memory", "Dom0 Memory Usage"), checks.dom0_memory),
        ("mtu_issues", "MTU Issues", checks.mtu_issues),
        ("dmesg_content", "Dmesg Content", checks.dmesg_content),
        ("oom_events", "OOM Events", checks.oom_events),
        ("crash_logs_present", "Crash Logs Present", checks.crash_logs),
        ("coredumps_present", "Coredumps Present", checks.coredumps),
        ("failed_units", "Failed Systemd Units", checks.failed_units),
        ("tap_ctl_list", "Tapdisk Status", checks.tap_status),
        ("task_timeout_override", "XAPI Task Timeout Override", checks.task_timeout_override),
        ("lacp_negotiation", "LACP Negotiation Issues", checks.lacp),
        ("multipath_health", "Multipath Path Health", checks.multipath_health),
        ("multipath_events", "Multipath Path Events", checks.multipath_events),
        ("stuck_processes", "Stuck Processes", checks.stuck_processes),
        ("mount_stalls", "Mount Stalls", checks.mount_stalls),
        ("network_mounts", "Network Mounts", checks.network_mounts),
        ("silly_mtus", "Silly MTUs", checks.silly_mtus),
        ("dns_gw_non_mgmt_pifs", "DNS/GW on Non-Mgmt PIFs", checks.dns_gw_non_mgmt_pifs),
        ("overlapping_subnets", "Overlapping Subnets", checks.overlapping_subnets),
        ("duplicate_ips", "Duplicate IPs", checks.duplicate_ips),
        ("log_errors", "Log Errors", checks.log_errors),
        ("lun_assignments", "LUN Assignments", checks.lun_assignments),
        ("smapi_hidden_leaves", "SMAPI Hidden Leaves", checks.smapi_hidden_leaves),
        ("update_mirror_access", "Update Mirror Access", checks.update_mirror_access),
    ]


def gated(run, host, name):
    """Single mode and the master always run everything; a slave in a pool sweep runs only
    what its toggle turns on, which is the entire purpose of those toggles."""
    if not run.pool_mode or host.is_master:
        return True
    return config.POOL_RUN.get(name, True)


def host_section(run, rep, host):
    """One host's block.

    The list headings only make sense when there IS a list: a solo host run has one host,
    which may well be a slave, so it gets the single-host heading rather than one that
    would announce a lone '(Master)'.
    """
    if run.pool_mode and not run.host_solo():
        if host.is_master:
            rep.heading("== Individual Hosts ==")
            rep.heading("%s (Master) Results:" % host.label)
        else:
            rep.blank()
            rep.heading("%s Results:" % host.label)
    else:
        rep.heading("== Health check on: %s ==" % host.name)

    rep.begin_section("host", host)

    # pool mode prints this in the pool status section; single mode has nowhere else to
    if not run.pool_mode and run.pw_has_backslash:
        rep.add(result.info("Root Password", "Contains Backslash", "yellow"))

    rep.check("Hypervisor Version", checks.hypervisor_version, host)
    # a collector that stopped part way: what it gathered follows, everything it did not
    # reads Unknown, and this says why
    rep.check("Host Collection", checks.host_collection, host)
    rep.check("Last Booted", checks.last_booted, host)
    rep.check("Last Patched", checks.last_patched, host)
    # the conclusion drawn from the two dates above, so it prints beside them
    if gated(run, host, "rebooted_after_updates"):
        rep.check("Rebooted After Updates", checks.rebooted_after_updates, host)
    # ahead of the xe-sourced lines it explains
    rep.check("XAPI Status", checks.xapi_status, host)
    rep.check("Host Enabled", checks.host_enabled, host)
    rep.check("Multipathing", checks.multipathing, host)
    rep.check("NTP", checks.ntp, host)

    if run.pool_mode:
        rep.add_poolconf(host.label, host.pool_conf_text())

    for toggle, key, fn in per_host_checks():
        if gated(run, host, toggle):
            rep.check(key, fn, host)

    # needs a second host to compare against, so single mode and a solo run skip it
    if run.pool_mode and not run.host_solo() and gated(run, host, "yum_patch_level"):
        rep.check("Yum Patch Level", checks.yum_patch_level, host, host.is_master,
                  run.master_manifest())
    if gated(run, host, "xostor_versions"):
        rep.check(("XOSTOR Packages", "XOSTOR DRBD Module"), checks.xostor_versions, host,
                  run.pool.xostor_in_use())
    if run.pool.xostor_in_use() and gated(run, host, "xostor_missing_devices"):
        rep.check("XOSTOR Missing Devices", checks.xostor_missing_devices, host)
    rep.end_section()


class _Background(object):
    """Run one function on a thread now, collect what it returned later.

    Used for the '== XOA Status ==' section, which asks the appliance about itself and so
    shares nothing at all with the pool: not a command, not a file, not a connection. It
    used to run at render time, in front of everything it had no bearing on, and its ~2.9s
    of xoa-updater and 'xoa check' calls were 2.9s in which nothing else happened.

    Daemon, so an early sys.exit - an unreadable xo-db, a seed that would not answer -
    is not held up by a 'xoa check' with XOA_CHECK_TIMEOUT still to run. The exception is
    carried across the thread boundary and re-raised in result() rather than swallowed:
    the section blew the run up when it ran inline, and it still does - only now the host
    results are already on screen instead of being lost with it.
    """

    def __init__(self, fn):
        self._value = None
        self._error = None
        self._thread = threading.Thread(target=self._run, args=(fn,))
        self._thread.daemon = True
        self._thread.start()

    def _run(self, fn):
        try:
            self._value = fn()
        except Exception as exc:
            # not a swallowed error and not a decision: it is held so that result() can
            # raise it in the main thread, exactly as an inline call would have
            self._error = exc

    def result(self):
        """Wait for it and answer, or raise what it raised.

        Bounded by the timeouts on the individual commands - LOCAL_CMD_TIMEOUT each and
        XOA_CHECK_TIMEOUT for 'xoa check' - which are the section's designed defence
        against a wedged updater. A second deadline here would only be able to report an
        Unknown the section can already report for itself, and could cut off a slow but
        perfectly healthy answer.
        """
        self._thread.join()
        if self._error is not None:
            raise self._error
        return self._value


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    colors.init()
    run = Run()

    # PATH first, in both environments: under cron it is /usr/bin:/bin, and on the XOA
    # xo-server-db, xoa-updater and xoa live in /usr/local/bin (measured - a cron run could
    # not even read xo-db), while dom0 keeps several tools in sbin. Over ssh the remote
    # login shell does this for the hosts.
    path = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    for extra in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/sbin"):
        if extra not in path:
            path.append(extra)
    os.environ["PATH"] = os.pathsep.join(path)

    # arguments before any gate, so -h and a usage error answer on any machine, for anyone
    args = run.parse_args(argv)
    if run.json_output:
        colors.init(force_off=True)

    if run.run_env != "host":
        ok_version, detected = xoa.debian_version_ok()
        if not ok_version:
            sys.stderr.write("This script requires Debian 11 or later (or an XCP-ng host). "
                             "Detected version: %s\n" % detected)
            return 1

    # before the work dir, the db read and the XOA thread: a refused run attempts nothing
    if not require_root(run.run_env):
        return 1

    work_dir = transport.make_work_dir()
    # atexit runs LAST-registered FIRST, so these are registered in the reverse of the
    # order they must run in: kill every child (they hold the ControlPath sockets that
    # live in the work dir), then ask the ssh masters - which no kill reaches - to exit,
    # then remove the dir. On a run that finishes the kill is a no-op. It is for the exits
    # that do not: sys.exit on an unreadable xo-db or a seed that will not answer, with the
    # XOA section's daemon thread still part way through a 'xoa check'.
    atexit.register(transport.cleanup_work_dir, work_dir)
    atexit.register(transport.close_masters, work_dir)
    atexit.register(transport.kill_all_children)
    run.transport = transport.Transport(run.run_env, work_dir)

    argument_password = ""
    pool_reachable = True
    if run.run_env == "host":
        argument_password = resolve_target_host_mode(run, args)
    else:
        pool_reachable = resolve_target_xoa(run, args)

    # The appliance's own section starts here and is not looked at again until the report
    # has nothing left to say about the pool. Here, and not at the top of main(), on
    # measurement rather than taste - 5 runs of each, on the 2-core appliance an XOA
    # actually is:
    #
    #   -n sec (2 hosts)   6.33s from the top | 6.23s here      -n east (remote)  7.04 | 6.49
    #   -n primary (1 host)     5.52          | 6.19            -s slave + pw     6.29 | 6.15
    #   -n nomatch (error)      3.95          | 3.39  (old script: 3.40)
    #
    # A wash on average, and better here in four cases of five. Started at the top it
    # spends its first 3.3s fighting xo-server-db - both are node, and there are two
    # cores - whereas from here it runs against the host collection, which is waiting on
    # ssh and leaves the CPU idle. It also leaves every exit above untouched: a pool name
    # that matched nothing, an unreadable xo-db, the interactive picker, the sshpass
    # fallback. Those cost the run nothing, exactly as before.
    #
    # The one case it loses is a single fast host, where there is under 2s of collection
    # to hide 2.9s of appliance behind. Do not move it back without re-measuring all five.
    #
    # It is also started BEFORE the no-password-mechanism exit below, which is the one
    # case where this section is the entire report: there is nothing else left to overlap.
    #
    # Not under -c: its result is never read, and it would spend the appliance's two cores
    # on a 'xoa check' and five node start-ups while the command fans out, only to be
    # killed at exit.
    xoa_worker = (_Background(xoa.lines) if run.run_env != "host" and not run.run_cmd
                  else None)

    if not pool_reachable:
        return xoa_only_report(run, rep_meta=run_meta(run), xoa_worker=xoa_worker)

    hosts = discover(run)

    if run.run_env == "host":
        # now that the pool size is known, decide whether the other members can be checked
        prepare_host_sweep(run, argument_password)

    if not run.pool_mode or run.host_solo():
        hosts = _narrow_to_seed(run, hosts)
    run.hosts = hosts

    for host in hosts:
        host.is_master = bool(run.master_address and host.address == run.master_address)
    if not run.pool_mode or run.host_solo():
        # the one host we can look at gets every check, the way single mode runs them all:
        # the pool_run_* toggles exist to keep a pool SWEEP short, and there is no sweep
        # here. It may well be a slave, which is why this is not master detection.
        hosts[0].is_master = True

    # -c/--command: run the given command on every host and stop there. This is a raw
    # diagnostic dump, not the health report, so nothing below it runs - no collection,
    # no checks, and not the XOA section either: xoa_worker is a daemon thread with its
    # cleanup already registered with atexit, so it is simply never read.
    #
    # Here, and not earlier, so -c inherits the whole target-selection path exactly as the
    # report has it: the pool picked by -n or the picker, the password from xo-db, the
    # host list from discovery, and -s / a password-less host run narrowing that list.
    if run.run_cmd:
        return runcmd.execute(run, parallel_workers(len(run.hosts)))

    run.pool_cmd_host = run.seed if run.run_env == "host" else run.master_address
    if run.pool_cmd_host not in [h.address for h in run.hosts]:
        run.pool_cmd_host = run.hosts[0].address if run.hosts else ""

    collect_hosts(run)

    master = run.host_by_address(run.master_address)
    if master is not None:
        # what it calls itself, once we have actually spoken to it
        run.master_name = master.name

    rep = report.Report(run.filter_output, json_mode=run.json_output,
                        meta=run_meta(run))

    if run.pool_mode:
        pool_status_section(run, rep)
        if run.host_solo():
            host_section(run, rep, run.hosts[0])
        else:
            # A host we could not reach is named in 'Unreachable Hosts' and gets no block
            # of its own - there is nothing to report about it, and an empty block would
            # read as a host that passed everything.
            reachable = [h for h in run.hosts if h.reachable]
            ordered = ([master] if master in reachable else []) + \
                      [h for h in reachable if h is not master]
            if master not in reachable:
                # a host run names the master from the local pool.conf, so unlike the XOA
                # path it may be one we cannot reach - the heading the master carries on
                # its way past still has to appear
                rep.heading("== Individual Hosts ==")
            for host in ordered:
                host_section(run, rep, host)
            # named in 'Unreachable Hosts' and given no block of their own; the
            # document records them so a consumer walking hosts[] cannot simply not
            # see a host that was meant to be checked
            for host in run.hosts:
                if not host.reachable:
                    rep.unreachable_host(host)
        rep.print_poolconf_section()
    else:
        host_section(run, rep, run.hosts[0])

    # Last, and only now waited for. It is about the appliance rather than about the pool
    # that was asked about, so it has no business standing in front of the host results -
    # and by here it has almost always finished on its thread, making it free.
    if xoa_worker is not None:
        if not run.pool_mode or run.filter_output:
            # every section is preceded by exactly one blank line; in pool mode the
            # pool.conf block already ends in one - except under -f, which drops it
            rep.blank()
        rep.begin_section("xoa")
        rep.heading("== XOA Status ==")
        rep.add_all(xoa_worker.result(), "XOA")
        rep.end_section()

    return rep.finish()


def _narrow_to_seed(run, hosts):
    """Single mode, and a solo host run, check the seed alone - for different reasons.

    -s was asked to; a solo host run has no password for the others, and those members are
    not unreachable, they are simply not being checked. Probing them would report them as
    failures.
    """
    for host in hosts:
        if host.address == run.seed:
            return [host]
    # dialled in a form xapi does not publish - a pool stored by name in xo-db, or an
    # address on a second network. The seed's own uuid still says which member it is, so
    # its xapi values are kept; it is still reached the way it was dialled, the one way
    # it is known to answer.
    for host in hosts:
        if run.seed_uuid and host.uuid == run.seed_uuid:
            return [model.Host(run.seed, host.uuid, host.hostname, host.enabled,
                               host.multipathing)]
    return [model.Host(run.seed)]


def entry():
    """The process's exit code, with a ctrl-C answered as one rather than as a crash.

    Run the documented way - `python3 <(curl ...)` - the traceback an interrupt used to
    print could not even show its own source lines: the file is a descriptor that is
    already gone, so it was twenty lines of threading internals against a path called
    /dev/fd/63. 130 is the shell's own convention for a SIGINT death, and the atexit
    handlers still take the children and the work dir with them.
    """
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _stop_signal)
            except ValueError:
                pass            # not the main thread: a test driving entry()
    try:
        return main()
    except KeyboardInterrupt as exc:
        signum = getattr(exc, "signum", 2)
        try:
            sys.stderr.write("\n%s.\n" % ("Interrupted" if signum == 2 else "Stopped"))
        except (IOError, OSError, ValueError):
            pass                # SIGHUP: the terminal it would be written to is gone
        return 128 + signum


class Stopped(KeyboardInterrupt):
    """SIGTERM or SIGHUP, raised in the main thread so it takes the same path as a ctrl-C:
    queued work cancelled, every child killed, the work dir removed. Python's default for
    both is to die on the spot, running no atexit handler - which left the work dir, the
    askpass helper and every child behind (measured: a SIGTERM mid-run left the dir and two
    ssh clients). The dropped ssh session to an XOA is the common SIGHUP."""

    def __init__(self, signum):
        KeyboardInterrupt.__init__(self)
        self.signum = signum


def _stop_signal(signum, _frame):
    raise Stopped(signum)


# ======================================================================================
# --- module aliases --------------------------------------------------------------------

# The sources are separate modules; stitched together they share one namespace,
# so `config.X` and `from colors import green` are given something to resolve
# against. Registered in sys.modules too, for the imports inside functions.
#
# Read LIVE from the flat namespace, never copied: a module global rebound later
# (colors.init() sets the colour codes, xodb caches the db) must read the same
# through `colors.YELLOW` as it does inside colors itself - a copy taken here
# would go on serving the import-time value on the artifact alone.
class _AliasModule(types.ModuleType):
    def __init__(self, name, exported):
        types.ModuleType.__init__(self, name)
        object.__setattr__(self, '_exported', frozenset(exported))
        object.__setattr__(self, '__file__', __file__)

    def __getattr__(self, symbol):
        if symbol in self._exported and symbol in globals():
            return globals()[symbol]
        raise AttributeError('module %r has no attribute %r' % (self.__name__, symbol))

    def __setattr__(self, symbol, value):
        if symbol in self._exported:
            globals()[symbol] = value
        else:
            object.__setattr__(self, symbol, value)

    def __dir__(self):
        return sorted(self._exported)


def _module(name, exported):
    module = _AliasModule(name, exported)
    sys.modules[name] = module
    return module


config = _module('config', ['COREDUMP_DIR', 'COREDUMP_MAX_LINES', 'CRASH_IGNORE_FILE', 'DMESG_IGNORE_RULES', 'DMESG_ISSUE_PHRASES', 'DMESG_ISSUE_WORDS', 'DMESG_MAX_LINES', 'DMESG_ROLLUP_MIN', 'DOM0_MAX_USED', 'DOM0_MEM_USED_MAX_PCT', 'FAILED_UNITS_IGNORE', 'LEAF_COALESCE_BUSY_VDI_OPS', 'LEAF_COALESCE_BUSY_VM_OPS', 'LEAF_COALESCE_MAX_LINES', 'LOCAL_CMD_TIMEOUT', 'LOG_ERROR_CONTEXT', 'LOG_ERROR_FILES', 'LOG_ERROR_IGNORE_RULES', 'LOG_ERROR_PHRASES', 'LUN_CHANGE_FILES', 'LUN_CHANGE_PHRASES', 'MAX_PARALLEL_HOSTS', 'MOUNT_PROBE_RESERVE', 'MOUNT_PROBE_TIMEOUT', 'MOUNT_STALL_FILES', 'MOUNT_STALL_PHRASES', 'MTU_DMESG_KEYWORDS', 'MULTIPATH_EVENT_FILES', 'MULTIPATH_EVENT_PHRASES', 'MULTIPATH_MAX_LINES', 'MULTIPATH_OK_CHK_STATES', 'MULTIPATH_OK_DEV_STATES', 'MULTIPATH_OK_DM_STATES', 'MULTIPATH_RECHECK_DELAY', 'MULTIPATH_STANDBY_CHK_STATES', 'MULTIPATH_TRANSIENT_CHK_STATES', 'NETWORK_FS_TYPES', 'OOM_PHRASE', 'PKG_DIFF_MAX_LINES', 'POOL_RUN', 'PROGRESS_INTERVAL', 'RAM_MATCH_TOLERANCE_MB', 'REMOTE_CMD_TIMEOUT', 'RO_FS_DMESG', 'RO_FS_EXTRA', 'RO_FS_NATIVE_RO', 'RO_FS_SR_DIRS', 'RUN_CMD_TIMEOUT', 'SCRIPT_VERSION', 'SSH_TIMEOUT', 'STATIC_VDIS_UNIT', 'STUCK_MAX_LINES', 'STUCK_MIN_AGE', 'STUCK_RECHECK_DELAY', 'STUCK_SAMPLES', 'TASK_PENDING_MAX_HOURS', 'TIME_SYNC_ALLOWANCE_SECS', 'UPDATE_MIRROR_BUDGET', 'UPDATE_MIRROR_MAX_PROBES', 'UPDATE_MIRROR_REDIRECTOR', 'UPDATE_MIRROR_TIMEOUT', 'WINDOWS_MAX_LINES', 'WINDOWS_PLATFORM_KEYS', 'XOA_CHECK_TIMEOUT', 'XOA_STOCK_PLUGINS', 'XOSTOR_MIN_RAM_GB', 'XOSTOR_PACKAGES', 'XOSTOR_QCOW2_MAX_LINES', 'XOSTOR_VG', 'XO_DNS_TIMEOUT', 'XO_HEAP_MIN_MB', 'XO_HEAP_TARGET_PCT', 'XO_PLUGIN_LOOKUP_PATHS', 'XO_PLUGIN_PREFIX', 'XO_PLUGIN_SCOPE_DIR', 'XO_PLUGIN_SCOPE_PREFIX', 'XO_PLUGIN_STOCK_DIR', 'XO_REDIS_TIMEOUT'])
colors = _module('colors', ['CYAN', 'GREEN', 'RESET', 'YELLOW', 'cyan', 'green', 'init', 'strip_ansi', 'yellow'])
result = _module('result', ['FLAG', 'Fact', 'INFO', 'Line', 'MISSING', 'OK', 'UNKNOWN', 'flag', 'guard', 'info', 'ok', 'pinned', 'raw', 'unknown', 'wrap'])
parsers = _module('parsers', ['BOND_MEMBER', 'BOND_NOT_MEMBER', 'BOND_NO_PIFS', 'GC_SR_SWITCHES', 'MP_HELP_MARKER', 'SKIP_FILESYSTEMS', 'SR_ATTACH_SKIP_TYPES', 'TASK_COMPLETED', '_DIFF_KINDS', '_HEAP_FLAG_RE', '_LINK_RE', '_LOOSE_URL_RE', '_MANIFEST_PKG_RE', '_MOUNT_FIELD_ESCAPES', '_MTU_RE', '_PARAM_RE', '_PREMIUM_SUFFIX', '_SCHEME_RE', '_TS_RE', '_XO_URL_RE', '_cidr_range', '_ids_among', '_ignore_rules', '_int_or_none', '_mp_unmapped', '_normalise', '_word_re', '_xe_map', 'backup_runners', 'cap_lines', 'classify_multipath_path', 'classify_xo_plugins', 'context_block', 'dmesg_issue_lines', 'duplicate_addresses', 'find_mtu_keywords', 'find_phrase_lines', 'format_age', 'has_overlapping_subnets', 'has_url_scheme', 'host_records_from_state_db', 'http_proxy_address', 'ip_literal', 'job_field', 'job_touches_pool', 'leading_version', 'leaf_coalesce_srs', 'leaf_coalesce_vdis', 'manifest_diff', 'manifest_diff_summary', 'manifest_packages', 'manifest_plugin_names', 'manifest_versions', 'mount_field', 'mount_table', 'multipath_summary', 'multipathd_alive', 'node_heap_flag', 'parse_bond_slave_of', 'parse_df', 'parse_dm_multipath_maps', 'parse_dns_gw_pifs', 'parse_failed_units', 'parse_host_list', 'parse_ip_addrs', 'parse_ipv4_addrs', 'parse_lacp', 'parse_link_mtus', 'parse_lvm_backup_pvs', 'parse_mem_total_mb', 'parse_meminfo', 'parse_multipath_maps', 'parse_multipath_paths', 'parse_other_config', 'parse_pending_tasks', 'parse_pool_conf', 'parse_pvs', 'parse_sr_attachment', 'parse_timedatectl', 'parse_xe_records', 'plugin_block', 'pool_member_addresses', 'pv_missing', 'read_only_mounts', 'rollup_repeats', 'round_1dp', 'split_host_port', 'split_timestamp', 'static_vdis_failure_moot', 'truncate_block', 'unit_display', 'unit_ignored', 'windows_vm_findings', 'xapi_utc', 'xe_ops', 'xo_pattern_match', 'xo_server_address', 'xo_simple_ids'])
model = _module('model', ['Host', 'Pool'])
collectorsrc = _module('collectorsrc', ['EMBEDDED', 'collector_source'])
transport = _module('transport', ['ASKPASS_ENV', 'ASKPASS_SCRIPT', 'AUTH_ASKPASS', 'AUTH_SSHPASS', 'BEGIN_MARKER', 'CONTROL_NAME', 'CollectError', 'END_MARKER', 'SOCKET_PATH_MAX', 'TERM_GRACE', 'TIMED_OUT', 'TimedOut', 'Transport', '_DEBUG_LOCK', '_LIVE', '_LIVE_LOCK', '_REMOTE_LAUNCH', '_REMOTE_LAUNCH_PINNED', '_STOPPING', '_kill_tree', '_mark_incomplete', '_remote_launch', '_signal_group', 'cleanup_work_dir', 'close_masters', 'control_options', 'debug', 'have', 'is_timeout', 'kill_all_children', 'make_work_dir', 'run_local_cmd', 'sshpass_present', 'which', 'write_askpass'])
xoredis = _module('xoredis', ['DEFAULT_ADDR', 'ENCRYPTION_PREFIX', 'IDS_KEY', 'PLUGIN_IDS_KEY', 'PLUGIN_RECORD_PREFIX', 'RECORD_PREFIX', 'RedisError', '_config_dirs', '_config_files', '_encode', '_fetch', '_fetch_autoload', '_fetch_collection', '_flatten', '_mentions_redis', '_read_reply', 'read_plugin_autoload', 'read_records', 'read_server_records'])
xodb = _module('xodb', ['QUOTES', 'SELECT_NONE', 'SELECT_NO_MATCH', 'SELECT_OK', 'SELECT_QUIT', 'SELECT_UNREADABLE', 'Server', '_ALL_SERVERS', '_CLDR_PUNCT', '_COLLECTIONS', '_ESCAPE_RE', '_FOLD', '_INSPECT_CUT', '_KEY_RE', '_READ_ERROR', '_RECORDS_HEADER', '_RESOLVED', '_SIMPLE_ESCAPES', '_describe_failure', '_ls', '_read_servers', '_resolve', '_same_address', '_sort_key', 'all_servers', 'backup_routes', 'clean', 'collection', 'db_address', 'enabled_server_for', 'enabled_servers', 'have_xo_server_db', 'match_record', 'password_for', 'pool_name_for_host', 'read_error', 'record_password', 'record_user', 'reset_cache', 'scan_records', 'select_pool', 'server_for_host', 'unescape'])
checks = _module('checks', ['_backup_moved_elsewhere', '_dmesg_phrase_blocks', '_drbd_stale', '_first_line', '_ha_statefile_sr_text', '_linstor_column', '_linstor_has_rows', '_linstor_node_addresses', '_linstor_node_offline', '_linstor_table', '_linstor_unknown', '_maps', '_mount_detail', '_multipath_detail', '_multipath_read', '_network_line', '_plural', '_pool_conf_target', '_pool_roles_detail', '_pool_rollup', '_render_scan_blocks', '_ro_detail', '_ro_name', '_scan_result', '_stuck_detail', '_stuck_what', '_url_host_of', '_xostor_signature', 'backup_network', 'coredumps', 'crash_logs', 'dmesg_block', 'dmesg_content', 'dmesg_content_of', 'dns_gw_non_mgmt_pifs', 'dom0_disk_usage', 'dom0_memory', 'dom0_ram_allocations', 'duplicate_ips', 'duplicate_ips_across_hosts', 'failed_units', 'ha_enabled', 'host_collection', 'host_enabled', 'hypervisor_version', 'lacp', 'last_booted', 'last_patched', 'leaf_coalesce_disabled', 'log_errors', 'long_running_tasks', 'lun_assignments', 'migration_compression', 'migration_network', 'missing_patches', 'mount_stalls', 'mtu_issues', 'multipath_events', 'multipath_health', 'multipath_path_counts', 'multipathing', 'network_mounts', 'ntp', 'oom_events', 'overlapping_subnets', 'pending_reboot_pool', 'pool_host_list', 'pool_roles', 'pool_time_sync', 'read_only_filesystems', 'rebooted_after_updates', 'silly_mtus', 'smapi_hidden_leaves', 'sr_attachment', 'stuck_processes', 'tap_status', 'task_timeout_override', 'update_mirror_access', 'update_mirror_access_pool', 'vlan0', 'windows_vms_not_optimized', 'xapi_status', 'xostor_controller', 'xostor_faulty_resources', 'xostor_in_use', 'xostor_missing_devices', 'xostor_missing_devices_pool', 'xostor_nodes', 'xostor_pref_nic', 'xostor_qcow2', 'xostor_ram', 'xostor_version_consistency', 'xostor_versions', 'yum_patch_level'])
xoa = _module('xoa', ['_HEAP_PROBE', '_call_failure', '_dmesg', '_first_token', '_meminfo', '_os_release', '_os_version', '_plugin_autoload', '_plugin_scan_targets', '_plugin_version', '_plugins_line', '_service_state', '_updater', '_xo_server_heap', 'collect_xoa', 'debian_version_ok', 'heap_limit_line', 'ip_addrs', 'lines', 'ping_silent', 'running_as_root', 'scan_plugins'])
report = _module('report', ['Report', '_as_entry'])
runcmd = _module('runcmd', ['TRANSPORT_FAILED', '_run_one', 'execute'])



if __name__ == "__main__":
    sys.exit(entry())
