# -*- coding: utf-8 -*-
"""Pure parsing. No I/O, no subprocesses, no globals.

Everything in here takes text in and gives structured data out, which is why it is also
where every unit test lives: this is where the bash script's real bugs were - the manifest
diff that dropped duplicate package names, the util.inspect scan, the timedatectl label
generations, the record splitting that merged two SRs' VDIs into one.
"""

import re

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


def context_block(text, line_numbers, ctx=3, rollup=False):
    """+/- ctx lines around each hit, overlapping ranges merged, each line indented by 2.

    Merged ranges are separated by a blank line, which is what makes a block with several
    distant hits readable.

    With rollup=True, each merged range is passed through rollup_repeats() first, so a
    range covering thousands of copies of one message prints as that message and a count.
    The ranges themselves are unchanged: the rollup is a rendering of the same lines, so
    nothing a hit pointed at is dropped.
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
        out.extend(rollup_repeats(block) if rollup else block)
        if i != len(merged) - 1:
            out.append("")
    return "\n".join(out)


# The dmesg ring is a ring: one stuck NFS server or one flapping path writes the SAME line
# thousands of times, and context_block then faithfully prints all of them. A real R630
# pool produced 24,689 dmesg lines across seven hosts that were 22 distinct messages - one
# of them repeated 24,668 times. The repetition is not the finding; the message, how many
# times, and over what window are.
DMESG_ROLLUP_MIN = 3             # runs shorter than this are cheaper to print in full

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


def rollup_repeats(lines, threshold=DMESG_ROLLUP_MIN):
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
