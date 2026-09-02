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
import atexit
import base64
import getopt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback
import unicodedata



# ======================================================================================
# --- config ----------------------------------------------------------------------------

SCRIPT_VERSION = "3.6"

SSH_TIMEOUT = 45                 # ssh connect timeout, seconds
REMOTE_CMD_TIMEOUT = 300         # max seconds one collector run may take on a host
MAX_PARALLEL_HOSTS = 8           # hosts collected at once (HEALTH_MAX_PARALLEL overrides)
LOCAL_CMD_TIMEOUT = 10           # max seconds a local command may run (hung xoa-updater etc)
XOA_CHECK_TIMEOUT = 60           # 'xoa check' does real network probes, so it gets longer

DOM0_MAX_USED = 75               # dom0 disk use % allowed before flagging
DOM0_MEM_USED_MAX_PCT = 65       # dom0 memory use % allowed before flagging
XOSTOR_MIN_RAM_GB = 15           # minimum dom0 RAM (GB) when XOSTOR is in use
TIME_SYNC_ALLOWANCE_SECS = 300   # max clock difference between a host and this machine

MTU_DMESG_KEYWORDS = ["mtu", "large", "fragment"]      # whole-word, case-insensitive
DMESG_ISSUE_WORDS = ["panic", "crash", "rip", "kill"]  # whole-word, case-insensitive
DMESG_ISSUE_PHRASES = ["call trace", "timed out"]      # substring, case-insensitive
OOM_PHRASE = "out of memory"

# A dmesg line that matched a word/phrase above is dropped only if it contains ALL of a
# rule's substrings (case-insensitive, whitespace collapsed). One list entry = one rule.
DMESG_IGNORE_RULES = [
    ["megaraid", "firmware crash dump"],   # megaraid driver load prints "... : no"
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

# --- "LUN Assignments" check ----------------------------------------------------------
LUN_CHANGE_PHRASES = [
    "Warning! Received an indication that the LUN assignments on this target have changed",
]
LUN_CHANGE_FILES = [
    "/var/log/kern.log",
]

CRASH_IGNORE_FILE = ".sacrificial-space-for-logs"   # file in /var/crash that is not a crash
COREDUMP_DIR = "/var/lib/systemd/coredump"          # anything here means a dom0 process died
COREDUMP_MAX_LINES = 50          # coredumps listed in the detail block (newest first)
PKG_DIFF_MAX_LINES = 100         # mismatched yum packages listed
XOSTOR_QCOW2_MAX_LINES = 50      # qcow2 VDIs on XOSTOR listed
DMESG_MAX_LINES = 80             # lines of a dmesg detail block (Dmesg Content, OOM Events);
                                 # the newest are kept, and the rollup runs first
DMESG_ROLLUP_MIN = 3             # consecutive copies of one dmesg message folded into a
                                 # 'repeated N times' line from this many; fewer print in full

# Which per-host checks run on SLAVES in pool mode. The master always runs everything, and
# so does single mode / a solo host run; these toggles exist only to keep a sweep short.
POOL_RUN = {
    "dom0_disk_usage": True,
    "dom0_memory": True,
    "mtu_issues": True,
    "dmesg_content": True,
    "oom_events": True,
    "crash_logs_present": True,
    "coredumps_present": True,
    "tap_ctl_list": True,
    "task_timeout_override": True,
    "lacp_negotiation": True,
    "multipath_health": True,
    "multipath_events": True,
    "silly_mtus": True,
    "dns_gw_non_mgmt_pifs": True,
    "overlapping_subnets": True,
    "log_errors": True,
    "lun_assignments": True,
    "smapi_hidden_leaves": False,
    "rebooted_after_updates": True,
    "yum_patch_level": True,
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
    """Defensive: some tools colourise even when told not to."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "\033" and i + 1 < n and text[i + 1] == "[":
            j = i + 2
            while j < n and text[j] not in "ABCDEFGHJKSTfmnsulh":
                j += 1
            i = j + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


# ======================================================================================
# --- result ----------------------------------------------------------------------------

OK = "ok"
FLAG = "flag"
UNKNOWN = "unknown"
INFO = "info"


class Line(object):
    """One 'Key: value' line of the report, plus any detail blob it wants printed."""

    __slots__ = ("key", "text", "status", "detail_title", "detail_text", "label")

    def __init__(self, key, text, status, detail_title=None, detail_text=None):
        self.key = key
        self.text = text
        self.status = status
        self.detail_title = detail_title
        self.detail_text = detail_text
        self.label = key + ":"      # a couple of lines pad this for alignment

    @property
    def flags(self):
        return self.status in (FLAG, UNKNOWN)

    @property
    def always_print(self):
        return self.status in (FLAG, UNKNOWN, INFO)

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
    """A fact with no threshold behind it, so it can never flag and always prints."""
    painted = colors.yellow(text) if color == "yellow" else (
        colors.green(text) if color == "green" else text)
    return Line(key, painted, INFO)


def raw(key, text):
    """Uncoloured, exit-code neutral, always printed."""
    return Line(key, text, INFO)


def guard(key, fn, *args, **kwargs):
    """Run a check; turn any escaped exception into a yellow Unknown for that line.

    A check that blows up must not kill the run and must never be silently skipped -
    a skipped line reads as 'not applicable', which is a claim of its own.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - deliberate: one bad check, one bad line
        import sys
        sys.stderr.write("internal error in %s:\n%s\n" % (key, traceback.format_exc()))
        return unknown(key, "Unknown (internal error: %s)" % exc)


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

_PARAM_RE = re.compile(r"^\s*([A-Za-z0-9_.:-]+)\s*\(\s*[A-Z]{2}\s*\)\s*:\s?(.*)$")


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


def parse_dns_gw_pifs(text):
    """True when any non-management PIF carries a gateway or a DNS server."""
    for line in text.splitlines():
        if not re.match(r"^\s*(gateway|DNS)\s*\([^)]*\)\s*:", line):
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
    """`multipathd show daemon` says 'pid 1305 running'. Anything else is not an answer."""
    return bool(re.search(r"\bpid\s+\d+\s+running\b", text or ""))


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
    """('master', None) | ('slave', address) | (None, None)."""
    first = (text or "").replace("\r", "").strip().splitlines()
    if not first:
        return (None, None)
    line = first[0].strip()
    low = line.lower()
    if low == "master":
        return ("master", None)
    if low.startswith("slave:"):
        addr = re.sub(r"\s+", "", line.split(":", 1)[1])
        return ("slave", addr) if addr else (None, None)
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


def find_mtu_keywords(text, keywords):
    """Whole-word, case-insensitive, on the raw text - and every match is collected.

    Returning on the first hit meant the line could not say WHICH keyword tripped it.
    """
    found = []
    for kw in keywords:
        if _word_re(kw).search(text):
            found.append(kw)
    return found


def dmesg_issue_lines(text, words, phrases, ignore_rules):
    """1-based line numbers of dmesg lines that look like trouble.

    A line is exempted when it contains ALL substrings of any one ignore rule - the
    megaraid driver's "firmware crash dump : no" is the shipped example of a benign line
    that matches an issue word.
    """
    lowered_words = [w.lower() for w in words if w]
    lowered_phrases = [p.lower().strip() for p in phrases if p and p.strip()]
    rules = []
    for rule in ignore_rules:
        subs = [_normalise(s).strip() for s in rule if s and s.strip()]
        if subs:
            rules.append(subs)
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
    low = phrase.lower()
    return [i for i, line in enumerate(text.splitlines(), 1) if low in line.lower()]


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

        [Mon Jun  1 17:55:16 2026] nfs: server 172.21.203.251 not responding, timed out
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

    def ntp_state(self):
        f = self.fact("timedatectl")
        if not f.ok:
            return {"ntp": "Unknown", "sync": "Unknown"}
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
        """('master', None) | ('slave', address) | (None, None)."""
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
            return result.Fact(False, error="not collected")
        return result.wrap(self.payload, key)

    def networks(self):
        return self.payload.get("networks") or {}

    def xostor_in_use(self):
        f = self.fact("xostor_srs")
        return bool(f.ok and f.value)


def ram_match(hosts):
    """True when every host we could read reports the same dom0 RAM, to the nearest GB.

    Hosts whose memory we could not read are skipped rather than counted as a mismatch:
    unknown is not a difference.
    """
    seen = set()
    for host in hosts:
        mem = host.memory()
        if mem is None:
            continue
        seen.add(int(mem[0] / 1024.0 + 0.5))
    return len(seen) <= 1


def ntp_match(hosts):
    """True when every collected host has NTP on, says it is synchronised, and agrees
    with our clock inside the allowance."""
    for host in hosts:
        if not host.reachable:
            continue
        state = host.ntp_state()
        if state["ntp"] != "yes" or state["sync"] != "yes":
            return False
        drift = host.clock_drift()
        if drift is None or drift > config.TIME_SYNC_ALLOWANCE_SECS:
            return False
    return True


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
    """Run argv (no shell, ever) and return a Ran. Reads to EOF - see the xe/EPIPE note."""
    timeout = _clamp(timeout)
    if timeout is None:
        return Ran(124, "", "run budget exhausted", True)
    try:
        proc, devnull = _popen(argv)
    except OSError as exc:
        return Ran(127, "", "%s: %s" % (argv[0], exc), False)

    state = {"killed": False}

    def on_timeout():
        state["killed"] = True
        _kill(proc)

    timer = threading.Timer(timeout, on_timeout)
    timer.start()
    try:
        out, error = proc.communicate()
    finally:
        timer.cancel()
        devnull.close()
    return Ran(proc.returncode, _decode(out), _decode(error), state["killed"])


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
    out = {"collector": {"python": sys.version.split()[0], "pid": os.getpid()}}
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
        if spec.get("smapi"):
            out["smapi"] = collect_smapi_hidden_leaves()

    if "yumcheck" in want:
        out["yum_check"] = collect_yum_check_update()

    if "pool" in want:
        out["pool"] = collect_pool(spec, self_uuid)

    return out


def main(argv):
    spec = {}
    if len(argv) > 1 and argv[1]:
        spec = json.loads(base64.b64decode(argv[1].encode("ascii")).decode("utf-8"))
    DEADLINE[0] = time.time() + float(spec.get("budget") or 240)
    try:
        payload = collect(spec)
    except Exception:
        import traceback
        payload = {"__collector_error__": traceback.format_exc()}
    sys.stdout.write(BEGIN_MARKER + "\n")
    sys.stdout.write(json.dumps(payload))
    sys.stdout.write("\n" + END_MARKER + "\n")
    sys.stdout.flush()
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


class CollectError(Exception):
    """Could not get a document out of a host. Never confused with 'the host is fine'."""


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


def kill_all_children():
    """Kill every child still running. For an interrupted run, not for normal shutdown."""
    with _LIVE_LOCK:
        procs = list(_LIVE)
    for proc in procs:
        _kill_tree(proc)


def _remote_launch(blob):
    pinned = os.environ.get("HEALTH_REMOTE_PYTHON")
    if pinned and re.match(r"^[A-Za-z0-9_./-]+$", pinned):
        return (_REMOTE_LAUNCH_PINNED % pinned) % blob
    return _REMOTE_LAUNCH % blob


def _kill_tree(proc):
    try:
        os.killpg(os.getpgid(proc.pid), 9)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def run_local_cmd(argv, timeout, env=None, stdin_text=None):
    """Run a local command. Returns (rc, stdout_text, stderr_text); rc 124 = timed out."""
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
        rc = 124
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


class Transport(object):
    def __init__(self, run_env, work_dir, local_address=""):
        self.run_env = run_env
        self.work_dir = work_dir
        self.local_address = local_address
        self.password = ""
        self.ssh_port = 22
        self.source = collectorsrc.collector_source()

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

        if rc == 124:
            raise CollectError("%s timed out after %ds" % (what, config.REMOTE_CMD_TIMEOUT))
        payload = self._extract(out)
        if payload is None:
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("%s failed (exit %d)%s" % (what, rc, (": " + detail) if detail else ""))
        if "__collector_error__" in payload:
            raise CollectError("collector crashed on %s:\n%s" % (host, payload["__collector_error__"]))
        if err.strip():
            debug("stderr from %s:\n%s" % (host, err.strip()))
        info = payload.get("collector") or {}
        debug("%s answered from python %s" % (host, info.get("python", "?")))
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
        if rc == 124:
            raise CollectError("local command timed out after %ds" % config.REMOTE_CMD_TIMEOUT)
        payload = self._extract(out)
        if payload is None:
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("local command failed (exit %d)%s"
                               % (rc, (": " + detail) if detail else ""))
        if "__collector_error__" in payload:
            raise CollectError("collector crashed:\n%s" % payload["__collector_error__"])
        return payload

    def _run_local_collector(self, blob):
        return run_local_cmd([sys.executable, "-", blob],
                             timeout=config.REMOTE_CMD_TIMEOUT,
                             stdin_text=self.source)

    def _run_ssh_collector(self, host, blob):
        env = dict(os.environ)
        env["SSHPASS"] = self.password
        argv = [
            "sshpass", "-e", "ssh",
            "-p", str(self.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=%d" % config.SSH_TIMEOUT,
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=%s" % os.path.join(self.work_dir, "cm-%r@%h:%p"),
            "-o", "ControlPersist=60",
            "-o", "BatchMode=no",
            "root@" + host,
            _remote_launch(blob),
        ]
        return run_local_cmd(argv, timeout=config.REMOTE_CMD_TIMEOUT,
                             env=env, stdin_text=self.source)

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


def have(binary):
    for part in (os.environ.get("PATH") or "").split(os.pathsep):
        if part and os.access(os.path.join(part, binary), os.X_OK):
            return True
    return False


def ensure_sshpass(run_env):
    """Make sshpass available, or say why it is not.

    On a hypervisor it comes from 'extras', a stock XCP-ng repo that ships in
    CentOS-Base.repo pointing at Vates' own mirror and is merely disabled by default.
    --enablerepo is a one-shot, so the host's yum config is left exactly as it was, and
    the package is 21KB with no dependencies. Note that plain 'yum list available sshpass'
    finds nothing - it only searches ENABLED repos, which is what made an earlier look
    conclude, wrongly, that it was not available.
    """
    if have("sshpass"):
        return True
    if run_env == "host":
        sys.stderr.write("sshpass not found - installing it from the XCP-ng 'extras' repo "
                         "to reach the other pool hosts...\n")
        rc, out, err = run_local_cmd(
            ["yum", "--enablerepo=extras", "install", "-y", "sshpass"], timeout=300)
        if not have("sshpass"):
            sys.stderr.write("ERROR: could not install sshpass (yum exit code %d).\n" % rc)
            for line in (out + err).splitlines()[-5:]:
                sys.stderr.write(line + "\n")
            return False
        sys.stderr.write("sshpass installed.\n")
        return True

    sys.stderr.write("sshpass not found. Installing via apt...\n")
    run_local_cmd(["apt-get", "update", "-y"], timeout=300)
    run_local_cmd(["apt-get", "install", "-y", "sshpass"], timeout=300)
    return have("sshpass")


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
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    parts = []
    for chunk in re.split(r"(\d+)", folded):
        if chunk.isdigit():
            # digits sort BEFORE letters in the root collation ICU gives localeCompare,
            # so a pool named '1st Avenue' is menu entry 1, not 3. Verified against node
            # on the live db - getting this backwards silently changes which pool a
            # no-args cron run checks.
            parts.append((0, int(chunk), ""))
        elif chunk:
            parts.append((1, 0, chunk))
    return parts


class Server(object):
    __slots__ = ("host", "name", "search")

    def __init__(self, host, name, search):
        self.host = host
        self.name = name
        self.search = search


def have_xo_server_db():
    return transport.have("xo-server-db")


_ALL_SERVERS = None     # the one `xo-server-db ls server` scan; None until it is read
_READ_ERROR = ""        # why that scan failed, when it did; "" while it has not


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
    if first:
        return "exit code %d: %s" % (rc, first)
    return "exit code %d" % rc


def _ls(args):
    """(output, "") or (None, why-not). rc 127 is the transport's own 'not found'."""
    rc, out, err = transport.run_local_cmd(["xo-server-db", "ls"] + list(args),
                                           timeout=config.LOCAL_CMD_TIMEOUT * 3)
    if rc != 0:
        return None, _describe_failure(rc, err)
    return out, ""


def all_servers():
    """Every server record in the db, read once per run.

    One `xo-server-db ls server` costs ~3.3s on the test appliance, and a narrower query
    costs exactly the same: it is node starting up, loading xo-server's app-conf and
    opening a redis connection, not the query. It also answers with WHOLE records -
    password field included, disabled servers as well as enabled ones. Measured against
    the indexed `host=` lookup on the live db: 7/7 records, every field equal, passwords
    equal.

    So the second call the password lookup used to make spent 3.3s re-reading what was
    already in hand, and a run that also had to name its pool made a third. That was
    ~55% of the wall clock of a whole health check.

    Read from the main thread only, before any host is contacted; nothing else in a run
    touches it, so the cache needs no lock.
    """
    global _ALL_SERVERS, _READ_ERROR
    if _ALL_SERVERS is None:
        out, why = _ls(["server"])
        # a db that could not be read is cached as empty, with the reason kept beside it:
        # asking again would cost another 3.3s to fail again, and every lookup answers
        # 'nothing' either way - but the messages built on that answer must not. Run as a
        # non-root user, xo-server-db cannot even stat /etc/xo-server/config.toml, and
        # 'no enabled hosts found in xo-db' was what an appliance with five pools said.
        _ALL_SERVERS = scan_records(out) if out is not None else []
        _READ_ERROR = why
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
        rows.append(Server(rec["host"], name, (pool_name + " " + label).lower()))
    rows.sort(key=lambda r: _sort_key(r.name))
    return rows


def password_for(host):
    """(password, has_backslash) or (None, False).

    Answered out of the one scan rather than with a second `xo-server-db ls server
    host=...`: the indexed query returns the same record field for field and costs another
    3.3s (see all_servers).

    Searched across ALL records, not the enabled ones - a host given as an argument may
    well be a server XO has disabled, and the indexed lookup found its password before.
    """
    for rec in all_servers():
        if rec.get("host") == host:
            pwd = rec.get("password")
            if not pwd:
                return (None, False)
            return (pwd, "\\" in pwd)
    return (None, False)


def pool_name_for_host(want):
    """The db's name for a host given as an argument, so every run can name its target.

    Quiet and never an error: a slave via -s, a pool XO does not manage, or no
    xo-server-db at all are all normal - it just means the banner prints the address.
    """
    if not have_xo_server_db():
        return ""
    for row in enabled_servers():
        # a db host may carry the ':port' XO connects to xapi on
        if row.host == want or parsers.split_host_port(row.host)[0] == want:
            return row.name
    return ""


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
            stderr.write("  %s (%s)\n" % (row.name, row.host))
        return (SELECT_NO_MATCH, None)

    try:
        interactive = stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False

    if len(rows) == 1 or not interactive:
        return (SELECT_OK, rows[0])

    stderr.write("\n%s\n" % colors.cyan("== Multiple pools found in XOA =="))
    for i, row in enumerate(rows, 1):
        stderr.write("%d - %s (%s)\n" % (i, row.name, row.host))
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
            # deliberately always printed, -f included, even though this line CAN flag:
            # under -f it is the identity anchor for the host block, and every other
            # always-printed line there (Last Booted, Multipathing, NTP) is info-only.
            # Suppressing it would leave a findings-only report that does not say which
            # version produced them.
            return info("Hypervisor Version", "%s %s" % (name, version))
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
    return raw("Last Patched", f.value if f.ok and f.value else "Unknown")


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


def ntp(host):
    """One line, two facts. An explicit 'no' is a real finding; 'Unknown' (address not in
    the xe maps) stays informational."""
    from colors import green, yellow
    state = host.ntp_state()
    enabled, synced = state["ntp"], state["sync"]
    text = "Enabled - %s Synced - %s" % (
        (green if enabled == "yes" else yellow)(enabled),
        (green if synced == "yes" else yellow)(synced))
    line = result.Line("NTP", text, result.OK)
    if enabled == "no" or synced == "no":
        line.status = result.FLAG
    elif enabled != "yes" or synced != "yes":
        line.status = result.INFO
    return line


# --------------------------------------------------------------------------------------
# gated per-host checks
# --------------------------------------------------------------------------------------

def dom0_disk_usage(host):
    f = host.fact("df")
    if not f.ok:
        return unknown("Dom0 Disk Usage", "Unknown (%s)" % f.error)
    bad = parsers.parse_df(f.value, config.DOM0_MAX_USED)
    if not bad:
        return ok("Dom0 Disk Usage", "OK")
    return flag("Dom0 Disk Usage", "Fail", " - " + ", ".join(bad))


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
    found = parsers.find_mtu_keywords(f.value, config.MTU_DMESG_KEYWORDS)
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
    f = host.fact("crash_count")
    if not f.ok:
        return unknown("Crash Logs Present", "Unknown (%s)" % f.error)
    if f.value:
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
    unmanaged = [name for name in (dm_maps or []) if name not in known]
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
    detail = _multipath_detail(summary, unmanaged, rechecked)

    if not summary["maps"]:
        if unmanaged:
            return flag("Multipath Path Health",
                        "%d device-mapper map(s) multipathd does not manage, See Below"
                        % len(unmanaged)).with_detail("Multipath Paths", detail)
        # dm could not be read here only means the corroboration was missing: multipathd
        # is alive and says there is nothing, which is itself an established answer
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
    scan = host.fact("multipath_scan")
    dmesg = host.fact("dmesg")

    blocks = list(scan.value) if (scan.ok and scan.value) else []
    if dmesg.ok:
        blocks = blocks + _dmesg_phrase_blocks(dmesg.value, config.MULTIPATH_EVENT_PHRASES,
                                               config.LOG_ERROR_CONTEXT)
    if blocks:
        # a finding is established whatever the other source did or did not manage to say
        detail = _render_scan_blocks(blocks)
        if len(blocks) > 1:
            detail += ("\n\n(the same event can appear under both sources - dmesg -T "
                       "recomputes its timestamps each run, so they sit a second or two "
                       "from syslog's)")
        return flag("Multipath Path Events", "Yes, See Error Output").with_detail(
            "Multipath Path Events", detail)
    # nothing found, so every source has to have actually been read before this is a "None"
    if not scan.ok:
        return unknown("Multipath Path Events", "Unknown (%s)" % scan.error)
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


def _render_scan_blocks(blocks):
    """The scanner's blocks, laid out the way the report has always shown them."""
    out = []
    for block in blocks:
        out.append("--- %s (%s) ---" % (block["phrase"], block["file"]))
        for line in block["context"]:
            out.append("  " + line)
        out.append("")
    # blocks are separated by a blank line, but the blob itself does not end with one:
    # the detail printer adds its own spacing
    return "\n".join(out).rstrip("\n")


def log_errors(host):
    f = host.fact("log_scan")
    if not f.ok:
        return unknown("Log Errors", "Unknown (%s)" % f.error)
    if not f.value:
        return ok("Log Errors", "None")
    return flag("Log Errors", "Yes, See Error Output").with_detail(
        "Log Errors", _render_scan_blocks(f.value))


def lun_assignments(host):
    f = host.fact("lun_scan")
    if not f.ok:
        return unknown("LUN Assignments", "Unknown (%s)" % f.error)
    if not f.value:
        return ok("LUN Assignments", "Unchanged")
    return flag("LUN Assignments", "Changed - see below").with_detail(
        "LUN Assignment Changes", _render_scan_blocks(f.value))


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
        return unknown("Rebooted After Updates", "Unknown (could not read update or boot time)")

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
    return flag("Yum Patch Level", "Mismatch, See Below").with_detail(
        "Yum Patch Level Differences", "\n".join(shown))


# --------------------------------------------------------------------------------------
# pool-level
# --------------------------------------------------------------------------------------

def ha_enabled(pool):
    f = pool.fact("ha_enabled")
    if not f.ok:
        return unknown("HA Enabled", "Unknown")
    value = f.value.strip()
    if value == "false":
        return ok("HA Enabled", "No")
    if value == "true":
        return flag("HA Enabled", "Yes")
    return unknown("HA Enabled", "Unknown")


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
    f = pool.fact("yum_check")
    if not f.ok:
        return unknown("Missing Patches", "Unknown")
    if f.value == 0:
        return ok("Missing Patches", "0")
    return flag("Missing Patches", str(f.value))


def vlan0(pool):
    f = pool.fact("vlan0")
    if not f.ok:
        return unknown("VLAN 0 Check", "Unknown (%s)" % f.error)
    if f.value.strip():
        return flag("VLAN 0 Check", "Yes")
    return ok("VLAN 0 Check", "No")


def xostor_in_use(pool):
    f = pool.fact("xostor_srs")
    if not f.ok:
        return unknown("XOSTOR In Use", "Unknown (%s)" % f.error)
    if not f.value:
        return ok("XOSTOR In Use", "No")
    # a fact about the pool, not a finding - printing it yellow while returning 0 was the
    # one place that broke the rule that anything yellow flags the exit code
    return info("XOSTOR In Use", "Yes")


def xostor_ram(pool, memory):
    if memory is None:
        return unknown("XOSTOR RAM", "Unknown (could not read dom0 memory)")
    total_gb = memory[0] / 1024.0
    if int(round_1dp(total_gb) + 0.00001) < config.XOSTOR_MIN_RAM_GB:
        return flag("XOSTOR RAM", "Not Enough: %.1fG (Need >=%dG)"
                    % (total_gb, config.XOSTOR_MIN_RAM_GB))
    return ok("XOSTOR RAM", "%.1fG" % total_gb)


def _linstor_unknown(label, f):
    """One wording for a linstor fact that did not come back, whichever line asked."""
    if "not found" in (f.error or ""):
        return unknown(label, "Unknown (linstor CLI not found)")
    return unknown(label, "Unknown (%s)" % f.error)


def _linstor_line(pool, key, label, predicate, detail_title):
    f = pool.fact(key)
    if not f.ok:
        return _linstor_unknown(label, f)
    if predicate(f.value):
        return flag(label, "Yes, See Below").with_detail(detail_title, f.value)
    return ok(label, "No")


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
    return _linstor_line(pool, "linstor_faulty", "XOSTOR Faulty Resources",
                         _linstor_has_rows, "---xostor faulty resources---")


def xostor_nodes(pool):
    return _linstor_line(pool, "linstor_nodes", "XOSTOR Faulty Nodes",
                         _linstor_node_offline, "---xostor node status---")


def _linstor_node_addresses(text):
    """{address: node} out of the Addresses column of 'linstor n l'.

    A cell reads '172.16.210.84:3366 (PLAIN)' - the satellite's address, its port and the
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


def backup_network(pool, run_env, pinger):
    """The ping half asks 'can the XOA reach every host on this network', because that is
    what XO needs to move backup traffic. Asking it from a pool host answers a different
    question, so host mode does not ask it at all rather than mislabelling the answer."""
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

    silent = pinger(ips.value)
    if not silent:
        return ok("Backup Network", "Configured and reachable from XOA")
    # ICMP only, so a ping-filtering network reads yellow - the wording claims exactly
    # what was tested and nothing more
    return flag("Backup Network", "Configured but not fully reachable",
                " - No ping answer from XOA for: " + ", ".join(silent))


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


def collect_xoa():
    """Everything the section needs, gathered before anything is printed."""
    data = {}
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

    channel = ""
    for line in out.splitlines():
        if "channel selected" in line:
            channel = line.split()[0] if line.split() else ""
            break
    data["channel"] = channel
    data["up_to_date"] = "All up to date" in out

    _, reg = _updater("raw-api-call", "isRegistered")
    m = re.search(r"email:\s*'([^']*)'", reg)
    data["registration"] = m.group(1) if m else ""

    _, manifest = _updater("raw-api-call", "getLocalManifest")
    version = ""
    for line in manifest.splitlines():
        parts = line.split("'")
        if len(parts) >= 4 and parts[1] == "xen-orchestra":
            version = parts[3]
            break
    data["version"] = version

    _, plan = _updater("raw-api-call", "getXoaPlan")
    data["plan"] = _first_token(plan)
    _, lic = _updater("raw-api-call", "getSelfLicenses")
    data["licenses"] = _first_token(lic)

    # 'xoa check' does real network probes, so it gets its own longer timeout - and a
    # timed-out check produces no stderr, which used to read as a clean pass
    rc, _out, err = transport.run_local_cmd(["xoa", "check"], timeout=config.XOA_CHECK_TIMEOUT)
    data["check_timeout"] = (rc == 124)
    data["check_output"] = err.strip()
    return data


def _os_version():
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


def _max_old_space():
    """The XO-Server heap cap, read out of the unit file."""
    try:
        with open("/etc/systemd/system/xo-server.service", "r") as fh:
            m = re.search(r"--max-old-space-size=(\d+)", fh.read())
    except (IOError, OSError):
        return None
    return int(m.group(1)) if m else None


def _dmesg():
    rc, out, _err = transport.run_local_cmd(["dmesg", "-T"], timeout=60)
    return out if rc == 0 else None


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
        out.append(ok("Registration", reg) if reg else flag("Registration", "Unregistered"))

        channel = data.get("channel")
        out.append(ok("XOA Channel", channel) if channel else unknown("XOA Channel", "(Unknown)"))

        version = data.get("version")
        out.append(ok("XOA Version", version) if version else unknown("XOA Version", "Unknown"))

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
        out.append(Line("XOA Plan", combined, FLAG if flagged else OK))

        if data.get("up_to_date"):
            out.append(ok("XOA Status", "Up to date"))
        else:
            out.append(flag("XOA Status", "Updates available"))

        if data.get("check_timeout"):
            out.append(unknown("XOA Check", "Timed out after %ds" % config.XOA_CHECK_TIMEOUT))
        elif not data.get("check_output"):
            out.append(ok("XOA Check", "All OK"))
        else:
            out.append(flag("XOA Check", "Issues Found, See Output Below").with_detail(
                "XOA Check Issues", data["check_output"]))

    osv = _os_version()
    out.append(ok("OS Version", osv) if osv else unknown("OS Version", "Unknown"))

    mem = _meminfo()
    if mem is None:
        # skipping the memory lines silently would hide that the XO-Server heap cap never
        # got checked at all
        out.append(unknown("Memory Usage", "Unknown (could not read /proc/meminfo)"))
    else:
        total_mb, avail_mb = mem
        total_gb = total_mb / 1024.0
        avail_gb = avail_mb / 1024.0
        used_gb = total_gb - avail_gb
        pct = (used_gb / total_gb) * 100 if total_gb > 0 else 0.0
        # an info line with no threshold behind it, so it prints under -f like uptime does
        out.append(Line("Memory Usage",
                        "%s GB used of %s GB (%s%%)" % (colors.green("%.1f" % used_gb),
                                                        colors.green("%.1f" % total_gb),
                                                        colors.green("%.1f" % pct)),
                        INFO))

        cap = _max_old_space()
        if cap is None:
            out.append(flag("XO-Server Memory Limit", "Not Set"))
        else:
            # total minus 500MB, in MB, is the sizing the appliance docs ask for
            adjusted = int(round(total_mb - 500))
            if cap < adjusted:
                out.append(flag("XO-Server Memory Limit", str(cap)))
            else:
                out.append(ok("XO-Server Memory Limit", str(cap)))

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
    """
    results = [False] * len(ips)

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
    return [ips[i] for i in range(len(ips)) if results[i]]


def debian_version_ok():
    """XOA mode still has to be a Debian 11+ appliance."""
    try:
        with open("/etc/os-release", "r") as fh:
            text = fh.read()
    except (IOError, OSError):
        return (False, "unknown")
    m = re.search(r"^VERSION_ID=\"?([^\"\n]+)", text, re.M)
    if not m:
        return (False, "unknown")
    major = m.group(1).split(".")[0]
    if not major.isdigit():
        return (False, m.group(1))
    return (int(major) >= 11, m.group(1))


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

    # -- raw output ---------------------------------------------------------------
    def write(self, text=""):
        """--json puts the document on stdout and nothing else, so the rendered report is
        suppressed at the single point that produces it rather than at every caller."""
        if self.json_mode:
            return
        self.stream.write(text + "\n")

    def write_raw(self, text):
        """Exactly these bytes, no newline added. The pool.conf block carries its own
        spacing, and putting it through write() would silently reshape the report."""
        if self.json_mode:
            return
        self.stream.write(text)

    # -- sections -----------------------------------------------------------------
    def begin_section(self, kind, host=None):
        """Say which part of the report the lines that follow belong to.

        This is also what sets host_label, so the bucket a detail blob is filed under and
        the bucket the document lists a check in are decided in one place and cannot
        disagree.
        """
        self.host_label = "XOA" if kind == "xoa" else (host.label if host is not None else None)
        if not self.json_mode:
            return
        section = {"kind": kind}
        if host is not None:
            section["name"] = host.name
            section["address"] = host.address
            section["master"] = bool(host.is_master)
            section["reachable"] = True
        section["checks"] = []
        self._sections.append(section)
        self._section = section

    def end_section(self):
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
        """Section headings always print: -f hides passing results, not structure."""
        self.write(colors.cyan(text))

    def blank(self):
        self.write("")

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
        if self.json_mode and self._section is not None:
            # in the document it belongs to the host it describes, rather than to a
            # separate block at the end that a consumer would have to re-attribute
            self._section["pool_conf"] = first

    # -- tail ---------------------------------------------------------------------
    def print_poolconf_section(self):
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
# --- main ------------------------------------------------------------------------------

USAGE_XOA = """Usage:
  %(prog)s [-f] [-s] [-n name] [pool_master_or_host[:ssh_port] [root_password]]

  - All parameters are optional
  - If a host is not supplied, the enabled pools in xo-server-db are listed to pick from
    (a single enabled pool, or non-interactive use, just takes the first one)
  - If a password is not supplied, it will be looked up locally in xo-server-db
  - By default, the script runs in pool mode (checks all hosts in the pool)
  - Use '-f' flag to filter output to only show issues found
  - Use '-s' flag to only check the specified host (do not check other pool members if present)
  - Use '-n' to pick a pool from xo-server-db by name instead of being prompted:
    the first pool whose name contains the text is used, matched anywhere in the
    name and ignoring case, so '-n sec' matches 'XEN-SECONDARY'
  - Use '--json' to print the results as a JSON document instead of a report, for
    cron and monitoring. Same checks, same exit code; '-f' narrows it the same way,
    and everything that is not the document goes to stderr

  Examples:
  %(prog)s 192.168.1.5
  %(prog)s 192.168.1.6 'mypass'
  %(prog)s -s 192.168.1.7 'mypass'
  %(prog)s -n sec
  %(prog)s -f -n 'xen-main'
  %(prog)s --json -n sec
"""

USAGE_HOST = """Usage (running on an XCP-ng host):
  %(prog)s [-f] [-s] [root_password]

  - This host is always checked, using local commands (no ssh, no password needed)
  - The other pool members are checked too if a root password is given: they are
    reached over ssh, and sshpass is installed from the stock 'extras' repo if missing.
    Pool members share the master's root password, so one password covers the pool
  - With no password and a terminal you are asked for one; blank, or no terminal
    (cron, pipe), just checks this host and says so in the Pool Status section
  - Prefer the prompt over the argument: an argument is visible in 'ps' and lands
    in your shell history
  - Pool-level results are reported either way, since xapi answers those from any
    pool member, slave included
  - Use '-f' flag to filter output to only show issues found
  - Use '-s' flag to skip the pool-level section and only report on this host
  - Use '--json' to print the results as a JSON document instead of a report, for
    cron and monitoring. Same checks, same exit code; '-f' narrows it the same way,
    and everything that is not the document goes to stderr

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
        "smapi": bool(with_smapi),
        "log_scan": {"files": config.LOG_ERROR_FILES,
                     "phrases": config.LOG_ERROR_PHRASES,
                     "context": config.LOG_ERROR_CONTEXT},
        "lun_scan": {"files": config.LUN_CHANGE_FILES,
                     "phrases": config.LUN_CHANGE_PHRASES,
                     "context": config.LOG_ERROR_CONTEXT},
        "multipath_scan": {"files": config.MULTIPATH_EVENT_FILES,
                           "phrases": config.MULTIPATH_EVENT_PHRASES,
                           "context": config.LOG_ERROR_CONTEXT},
        "multipath": {"transient": config.MULTIPATH_TRANSIENT_CHK_STATES,
                      "recheck_delay": config.MULTIPATH_RECHECK_DELAY},
    }


def _pool_spec(controllers):
    return {
        "want": ["pool", "yumcheck"],
        "controllers": controllers,
        "qcow2_max": config.XOSTOR_QCOW2_MAX_LINES,
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
        self.json_output = False
        self.seed = ""
        self.password = ""
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
                argv, "fhsn:", ["filter", "help", "single", "name=", "json"])
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
                self.name_filter = value
            elif opt == "--json":
                self.json_output = True
        if len(args) > 2:
            usage(self.run_env)
        return args


def notice(run, text):
    """A message the rendered report puts on stdout.

    Under --json stdout carries the document and nothing else, so these go to stderr
    instead: a consumer's stdout is then either a whole valid document or empty, never a
    mixture that fails to parse for a reason it cannot see.
    """
    (sys.stderr if run.json_output else sys.stdout).write(text)


def print_banner(run, host, name):
    """Every run names what it is about to check, before any of the slow work.

    The paths that pick silently - the sole enabled pool, and cron/pipe runs - are exactly
    the ones where this line is the only record of which pool was taken.
    """
    if name:
        notice(run, "Checking pool: %s\n" % colors.green("%s (%s)" % (name, host)))
    else:
        notice(run, "Checking host: %s\n" % colors.green(host))
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


def resolve_target_xoa(run, args):
    """Pick a pool / take the host argument, then find a password for it."""
    if run.name_filter and len(args) > 1:
        sys.stderr.write("ERROR: -n/--name looks the host up in xo-server-db, so it takes "
                         "at most a password after it.\n")
        usage(run.run_env)

    # With one trailing argument the two readings are indistinguishable by shape and it is
    # read as a password - so '-n sec 192.168.1.5' used to try to log into the -n-matched
    # pool using an address as the password, surfacing as an authentication failure a long
    # way from the cause. Only xo-db can tell them apart: nobody's root password is one of
    # their own pool addresses.
    if run.name_filter and len(args) == 1:
        clash = xodb.pool_name_for_host(args[0])
        if clash:
            sys.stderr.write(
                "ERROR: '%s' is the address of pool '%s' in xo-server-db, but the value after\n"
                "       -n/--name is read as a password, not a host - -n already selects the pool.\n"
                "       Use either '-n %s' or the host '%s', not both.\n"
                % (args[0], clash, run.name_filter, args[0]))
            usage(run.run_env)

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

    host, port = parsers.split_host_port(args[0])
    run.seed = host
    # a picker-chosen host may carry ':port' - that is the XAPI HTTPS port XO connects on,
    # not an ssh port, so it is stripped for ssh and we stay on 22
    run.transport.ssh_port = 22 if selected or not port else port

    run.pool_name = selected.name if selected else xodb.pool_name_for_host(host)
    print_banner(run, host, run.pool_name)

    if not transport.ensure_sshpass(run.run_env):
        sys.stderr.write("ERROR: sshpass is required to reach the pool over ssh.\n")
        sys.exit(1)

    if len(args) == 2:
        run.password = args[1]
    else:
        # look the password up under the exact string xo-db keys the record by: for a
        # picker-chosen host that is its host field verbatim, ':port' and all
        db_host = selected.host if selected else host
        password, has_backslash = xodb.password_for(db_host)
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


def resolve_target_host_mode(run, args):
    """On a hypervisor the target is this machine, so the only positional that makes sense
    is the root password for the OTHER pool members. A second one would have been a host,
    which is not selectable - saying so beats failing later with an auth error."""
    if run.name_filter:
        sys.stderr.write("ERROR: -n/--name picks a pool out of xo-server-db, which only "
                         "exists on XOA.\n")
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
            except (EOFError, KeyboardInterrupt):
                password = ""
            sys.stderr.write("\n")
    if not password:
        return
    if not transport.ensure_sshpass(run.run_env):
        sys.stderr.write("Continuing with this host only.\n")
        return
    run.password = password
    run.transport.password = password
    run.host_sweep = True


def discover(run):
    """Phase A: one call to the seed for the pool's host list and our own identity."""
    spec = {"want": ["pool_hosts"]}
    try:
        if run.run_env == "host":
            payload = run.transport.collect_local(spec)
        else:
            payload = run.transport.collect(run.seed, spec)
    except transport.CollectError as exc:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s': %s\n"
                         % (run.seed or "this host", exc))
        sys.exit(1)

    if run.run_env == "host":
        address = result.wrap(payload, "self_address")
        if not address.ok or not address.value:
            sys.stderr.write("ERROR: could not get this host's address from xapi "
                             "(is the toolstack running?): %s\n" % address.error)
            sys.exit(1)
        run.seed = address.value
        run.transport.local_address = address.value
        name = result.wrap(payload, "hostname")
        shown = ("%s (%s)" % (name.value, address.value)
                 if name.ok and name.value else address.value)
        print_banner(run, shown, "")

    hosts_fact = result.wrap(payload, "pool_hosts")
    if not hosts_fact.ok:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s': %s\n"
                         % (run.seed, hosts_fact.error))
        sys.exit(1)

    hosts = []
    for rec in parsers.parse_host_list(hosts_fact.value):
        if not rec["address"]:
            sys.stderr.write("Warning: pool host %s has no address in xapi; skipping it\n"
                             % rec["uuid"])
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
        self_uuid = result.wrap(payload, "self_uuid")
        if self_uuid.ok and self_uuid.value:
            for host in hosts:
                if host.uuid == self_uuid.value:
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
    try:
        host.payload = run.transport.collect(host.address, spec)
    except transport.CollectError as exc:
        host.error = str(exc)
        note = "Failed when trying to check %s: %s\n" % (host.address, exc)
    host.local_now = _now()
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
    return max(1, min(limit, host_count))


def _collect_in_parallel(run, pool_spec, workers):
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [pool.submit(_collect_one, run, host, pool_spec) for host in run.hosts]
        try:
            return [f.result() for f in futures]
        except BaseException:
            # named and immediately re-raised, so this is not a swallowed error: the
            # workers are blocked in communicate() and cannot see a ctrl-C, so without
            # this the shutdown below would wait out every collector still running
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
    pool_spec = _pool_spec(controllers)

    workers = parallel_workers(len(run.hosts))
    transport.debug("collecting %d host(s), %d at a time" % (len(run.hosts), workers))
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
            run.pool.payload = cmd_host.payload.get("pool") or {}
            run.pool.payload["yum_check"] = cmd_host.payload.get("yum_check") or {
                "ok": False, "error": "not collected"}
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

        reachable = [h for h in run.hosts if h.reachable]
        rep.add(result.ok("Dom0 RAM Allocations", "Matched") if model.ram_match(reachable)
                else result.flag("Dom0 RAM Allocations", "Mismatched"))
        rep.add(result.ok("Pool Time Synchronization", "Matched") if model.ntp_match(reachable)
                else result.flag("Pool Time Synchronization", "Mismatched"))
        # like the two above, a comparison ACROSS hosts, so it belongs to the pool rather
        # than to any one host and has nothing to say when only one host was looked at
        rep.check("Multipath Path Counts", checks.multipath_path_counts, reachable)

    rep.check("HA Enabled", checks.ha_enabled, run.pool)
    rep.check("Migration Compression", checks.migration_compression, run.pool)
    rep.check("Missing Patches", checks.missing_patches, run.pool)

    if run.pw_has_backslash:
        rep.add(result.info("Root Password", "Contains Backslash", "yellow"))

    cmd_host = run.host_by_address(run.pool_cmd_host)
    memory = cmd_host.memory() if cmd_host else None
    rep.check("XOSTOR In Use", checks.xostor_in_use, run.pool)
    if run.pool.xostor_in_use():
        rep.check("XOSTOR RAM", checks.xostor_ram, run.pool, memory)
        rep.check("XOSTOR Faulty Resources", checks.xostor_faulty_resources, run.pool)
        rep.check("XOSTOR Faulty Nodes", checks.xostor_nodes, run.pool)
        rep.check("XOSTOR Controller IP", checks.xostor_controller, run.pool, run.host_names)
        rep.check("XOSTOR PrefNic", checks.xostor_pref_nic, run.pool)
        rep.check("XOSTOR QCOW2 VDIs", checks.xostor_qcow2, run.pool)

    rep.check("VLAN 0 Check", checks.vlan0, run.pool)
    rep.check("Migration Network", checks.migration_network, run.pool)
    rep.check("Backup Network", checks.backup_network, run.pool, run.run_env,
              xoa.ping_silent)
    rep.end_section()
    rep.blank()


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
        ("dom0_memory", "Dom0 Memory", checks.dom0_memory),
        ("mtu_issues", "MTU Issues", checks.mtu_issues),
        ("dmesg_content", "Dmesg Content", checks.dmesg_content),
        ("oom_events", "OOM Events", checks.oom_events),
        ("crash_logs_present", "Crash Logs Present", checks.crash_logs),
        ("coredumps_present", "Coredumps Present", checks.coredumps),
        ("tap_ctl_list", "Tapdisk Status", checks.tap_status),
        ("task_timeout_override", "XAPI Task Timeout Override", checks.task_timeout_override),
        ("lacp_negotiation", "LACP Negotiation Issues", checks.lacp),
        ("multipath_health", "Multipath Path Health", checks.multipath_health),
        ("multipath_events", "Multipath Path Events", checks.multipath_events),
        ("silly_mtus", "Silly MTUs", checks.silly_mtus),
        ("dns_gw_non_mgmt_pifs", "DNS/GW on Non-Mgmt PIFs", checks.dns_gw_non_mgmt_pifs),
        ("overlapping_subnets", "Overlapping Subnets", checks.overlapping_subnets),
        ("log_errors", "Log Errors", checks.log_errors),
        ("lun_assignments", "LUN Assignments", checks.lun_assignments),
        ("smapi_hidden_leaves", "SMAPI Hidden Leaves", checks.smapi_hidden_leaves),
        ("rebooted_after_updates", "Rebooted After Updates", checks.rebooted_after_updates),
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
    rep.check("Last Booted", checks.last_booted, host)
    rep.check("Last Patched", checks.last_patched, host)
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

    if run.run_env == "host":
        # dom0's PATH is complete for an interactive root shell but not under cron, and
        # several tools live in sbin. Over ssh the remote login shell did this for us.
        os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/local/sbin"
    else:
        ok_version, detected = xoa.debian_version_ok()
        if not ok_version:
            sys.stderr.write("This script requires Debian 11 or later (or an XCP-ng host). "
                             "Detected version: %s\n" % detected)
            return 1

    args = run.parse_args(argv)
    if run.json_output:
        colors.init(force_off=True)

    work_dir = transport.make_work_dir()
    # Registered before the work dir's cleanup so it runs first (atexit is LIFO): the
    # children hold the ControlPath sockets that live in it. On a run that finishes this
    # is a no-op - nothing is left running by then. It is for the exits that do not:
    # sys.exit on an unreadable xo-db or a seed that will not answer, with the XOA
    # section's daemon thread still part way through a 'xoa check'.
    atexit.register(transport.kill_all_children)
    atexit.register(transport.cleanup_work_dir, work_dir)
    run.transport = transport.Transport(run.run_env, work_dir)

    if not require_root(run.run_env):
        return 1

    argument_password = ""
    if run.run_env == "host":
        argument_password = resolve_target_host_mode(run, args)
    else:
        resolve_target_xoa(run, args)

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
    # install. Those cost the run nothing, exactly as before.
    #
    # The one case it loses is a single fast host, where there is under 2s of collection
    # to hide 2.9s of appliance behind. Do not move it back without re-measuring all five.
    xoa_worker = _Background(xoa.lines) if run.run_env != "host" else None

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
        if not run.pool_mode:
            # every section is preceded by exactly one blank line; in pool mode the
            # pool.conf block already ends in one
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
    # the seed was given in a form xapi does not use (a hostname, say): keep it, with the
    # per-host map values left Unknown, exactly as before
    return [model.Host(run.seed)]


# ======================================================================================
# --- module aliases --------------------------------------------------------------------

# The sources are separate modules; stitched together they share one namespace,
# so `config.X` and `from colors import green` are given something to resolve
# against. Registered in sys.modules too, for the imports inside functions.
def _module(name, exported):
    import types
    module = types.ModuleType(name)
    module.__file__ = __file__
    for symbol in exported:
        setattr(module, symbol, globals()[symbol])
    sys.modules[name] = module
    return module


config = _module('config', ['COREDUMP_DIR', 'COREDUMP_MAX_LINES', 'CRASH_IGNORE_FILE', 'DMESG_IGNORE_RULES', 'DMESG_ISSUE_PHRASES', 'DMESG_ISSUE_WORDS', 'DMESG_MAX_LINES', 'DMESG_ROLLUP_MIN', 'DOM0_MAX_USED', 'DOM0_MEM_USED_MAX_PCT', 'LOCAL_CMD_TIMEOUT', 'LOG_ERROR_CONTEXT', 'LOG_ERROR_FILES', 'LOG_ERROR_PHRASES', 'LUN_CHANGE_FILES', 'LUN_CHANGE_PHRASES', 'MAX_PARALLEL_HOSTS', 'MTU_DMESG_KEYWORDS', 'MULTIPATH_EVENT_FILES', 'MULTIPATH_EVENT_PHRASES', 'MULTIPATH_MAX_LINES', 'MULTIPATH_OK_CHK_STATES', 'MULTIPATH_OK_DEV_STATES', 'MULTIPATH_OK_DM_STATES', 'MULTIPATH_RECHECK_DELAY', 'MULTIPATH_STANDBY_CHK_STATES', 'MULTIPATH_TRANSIENT_CHK_STATES', 'OOM_PHRASE', 'PKG_DIFF_MAX_LINES', 'POOL_RUN', 'REMOTE_CMD_TIMEOUT', 'SCRIPT_VERSION', 'SSH_TIMEOUT', 'TIME_SYNC_ALLOWANCE_SECS', 'XOA_CHECK_TIMEOUT', 'XOSTOR_MIN_RAM_GB', 'XOSTOR_QCOW2_MAX_LINES'])
colors = _module('colors', ['CYAN', 'GREEN', 'RESET', 'YELLOW', 'cyan', 'green', 'init', 'strip_ansi', 'yellow'])
result = _module('result', ['FLAG', 'Fact', 'INFO', 'Line', 'MISSING', 'OK', 'UNKNOWN', 'flag', 'guard', 'info', 'ok', 'raw', 'unknown', 'wrap'])
parsers = _module('parsers', ['BOND_MEMBER', 'BOND_NOT_MEMBER', 'BOND_NO_PIFS', 'MP_HELP_MARKER', 'SKIP_FILESYSTEMS', '_LINK_RE', '_MTU_RE', '_PARAM_RE', '_TS_RE', '_cidr_range', '_int_or_none', '_mp_unmapped', '_normalise', '_word_re', 'cap_lines', 'classify_multipath_path', 'context_block', 'dmesg_issue_lines', 'find_mtu_keywords', 'find_phrase_lines', 'has_overlapping_subnets', 'manifest_diff', 'manifest_versions', 'multipath_summary', 'multipathd_alive', 'parse_bond_slave_of', 'parse_df', 'parse_dm_multipath_maps', 'parse_dns_gw_pifs', 'parse_host_list', 'parse_ipv4_addrs', 'parse_lacp', 'parse_link_mtus', 'parse_meminfo', 'parse_multipath_maps', 'parse_multipath_paths', 'parse_other_config', 'parse_pool_conf', 'parse_timedatectl', 'parse_xe_records', 'rollup_repeats', 'round_1dp', 'split_host_port', 'split_timestamp', 'truncate_block'])
model = _module('model', ['Host', 'Pool', 'ntp_match', 'ram_match'])
collectorsrc = _module('collectorsrc', ['EMBEDDED', 'collector_source'])
transport = _module('transport', ['BEGIN_MARKER', 'CollectError', 'END_MARKER', 'Transport', '_DEBUG_LOCK', '_LIVE', '_LIVE_LOCK', '_REMOTE_LAUNCH', '_REMOTE_LAUNCH_PINNED', '_kill_tree', '_remote_launch', 'cleanup_work_dir', 'debug', 'ensure_sshpass', 'have', 'kill_all_children', 'make_work_dir', 'run_local_cmd'])
xodb = _module('xodb', ['QUOTES', 'SELECT_NONE', 'SELECT_NO_MATCH', 'SELECT_OK', 'SELECT_QUIT', 'SELECT_UNREADABLE', 'Server', '_ALL_SERVERS', '_ESCAPE_RE', '_KEY_RE', '_READ_ERROR', '_SIMPLE_ESCAPES', '_describe_failure', '_ls', '_sort_key', 'all_servers', 'clean', 'enabled_servers', 'have_xo_server_db', 'password_for', 'pool_name_for_host', 'read_error', 'reset_cache', 'scan_records', 'select_pool', 'unescape'])
checks = _module('checks', ['_dmesg_phrase_blocks', '_linstor_column', '_linstor_has_rows', '_linstor_line', '_linstor_node_addresses', '_linstor_node_offline', '_linstor_table', '_linstor_unknown', '_maps', '_multipath_detail', '_multipath_read', '_network_line', '_render_scan_blocks', 'backup_network', 'coredumps', 'crash_logs', 'dmesg_block', 'dmesg_content', 'dmesg_content_of', 'dns_gw_non_mgmt_pifs', 'dom0_disk_usage', 'dom0_memory', 'ha_enabled', 'host_enabled', 'hypervisor_version', 'lacp', 'last_booted', 'last_patched', 'log_errors', 'lun_assignments', 'migration_compression', 'migration_network', 'missing_patches', 'mtu_issues', 'multipath_events', 'multipath_health', 'multipath_path_counts', 'multipathing', 'ntp', 'oom_events', 'overlapping_subnets', 'rebooted_after_updates', 'silly_mtus', 'smapi_hidden_leaves', 'tap_status', 'task_timeout_override', 'vlan0', 'xostor_controller', 'xostor_faulty_resources', 'xostor_in_use', 'xostor_nodes', 'xostor_pref_nic', 'xostor_qcow2', 'xostor_ram', 'yum_patch_level'])
xoa = _module('xoa', ['_dmesg', '_first_token', '_max_old_space', '_meminfo', '_os_version', '_service_state', '_updater', 'collect_xoa', 'debian_version_ok', 'lines', 'ping_silent', 'running_as_root'])
report = _module('report', ['Report', '_as_entry'])



if __name__ == "__main__":
    sys.exit(main())
