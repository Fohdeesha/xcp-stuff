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
from result import FLAG, INFO, OK, Fact, Line, flag, ok, unknown


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
