# -*- coding: utf-8 -*-
"""The '== XOA Status ==' section: the appliance checking itself.

All local commands, all timed out individually - a wedged xoa-updater that answers one
call and hangs on the next used to stall the whole run. A timeout degrades to a yellow
Unknown; it never kills the report.

lines() is called from a worker thread (main._Background) while the pool is being
collected, and its result is printed after the hosts. So nothing in here may write to
stdout or stderr, or mutate anything a check reads - it builds Lines and returns them,
and everything it runs goes through transport.run_local_cmd, which is thread-safe.
"""

import json
import os
import re
import threading

import checks
import colors
import config
import parsers
import transport
import xoredis
from result import FLAG, INFO, OK, Line, flag, ok, unknown


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
            name = entry[len(prefix):]
            if name in seen:
                continue          # xo-server keeps the first path that has the name
            seen.add(name)
            full = os.path.join(directory, entry)
            plugins.append({
                "name": name,
                "package": entry,
                "path": full,
                "version": _plugin_version(full),
                # an npm-linked or hand-symlinked plugin is worth naming outright: the
                # directory says nothing about where its code actually came from
                "link": os.path.realpath(full) if os.path.islink(full) else "",
            })
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
    # the same call already paid for, read twice: it also lists every npm package Vates
    # offers this appliance, which is the golden list the plugin scan is judged against
    data["manifest_plugins"] = parsers.manifest_plugin_names(manifest)

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
    _stock, third_party = parsers.classify_xo_plugins(found, vates_names)
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

    out.append(_plugins_line(data))

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
        # a reading with no threshold behind it, so it can never flag - and -f hides it,
        # the same as every other reading. The heap cap below is the line with a rule
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
