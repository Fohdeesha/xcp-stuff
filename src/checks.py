# -*- coding: utf-8 -*-
"""One function per report line. Facts in, a Line out. No I/O except the XOA-side pings.

Every one of these can be handed a fact that says "we could not look", and every one of
them answers that with UNKNOWN rather than with a pass. That is the invariant the whole
tool is built around, and here it is the only way the code is shaped.
"""

import config
import parsers
import result
from parsers import round_1dp
from result import flag, info, ok, raw, unknown


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


def dmesg_content(host):
    f = host.fact("dmesg")
    if not f.ok:
        return unknown("Dmesg Content", "Unknown (could not read dmesg)")
    hits = parsers.dmesg_issue_lines(f.value, config.DMESG_ISSUE_WORDS,
                                     config.DMESG_ISSUE_PHRASES, config.DMESG_IGNORE_RULES)
    if not hits:
        return ok("Dmesg Content", "Clean")
    return flag("Dmesg Content", "Issues Found, See Output Below").with_detail(
        "Dmesg Issues", parsers.context_block(f.value, hits))


def oom_events(host):
    f = host.fact("dmesg")
    if not f.ok:
        return unknown("OOM Events", "Unknown (could not read dmesg)")
    hits = parsers.find_phrase_lines(f.value, config.OOM_PHRASE)
    if not hits:
        return ok("OOM Events", "No")
    return flag("OOM Events", "Yes, See Below").with_detail(
        "OOM Events", parsers.context_block(f.value, hits))


def crash_logs(host):
    f = host.fact("crash_count")
    if not f.ok:
        return unknown("Crash Logs Present", "Unknown (%s)" % f.error)
    if f.value:
        return flag("Crash Logs Present", "Yes - check /var/crash")
    return ok("Crash Logs Present", "No")


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


def _linstor_line(pool, key, label, predicate, detail_title):
    f = pool.fact(key)
    if not f.ok:
        if "not found" in (f.error or ""):
            return unknown(label, "Unknown (linstor CLI not found)")
        return unknown(label, "Unknown (%s)" % f.error)
    if predicate(f.value):
        return flag(label, "Yes, See Below").with_detail(detail_title, f.value)
    return ok(label, "No")


def _linstor_node_offline(text):
    state_col = None
    for line in text.splitlines():
        if line.startswith("+") or line.startswith("|="):
            continue
        cells = [c.strip() for c in line.split("|")]
        if "Node" in cells and "State" in cells:
            state_col = cells.index("State")
            continue
        if line.startswith("|") and state_col is not None and state_col < len(cells):
            import colors
            if colors.strip_ansi(cells[state_col]).strip() != "Online":
                return True
    return False


def _linstor_has_rows(text):
    for line in text.splitlines():
        if line.startswith("| ") and "ResourceName" not in line:
            return True
    return False


def xostor_faulty_resources(pool):
    return _linstor_line(pool, "linstor_faulty", "XOSTOR Faulty Resources",
                         _linstor_has_rows, "---xostor faulty resources---")


def xostor_nodes(pool):
    return _linstor_line(pool, "linstor_nodes", "XOSTOR Faulty Nodes",
                         _linstor_node_offline, "---xostor node status---")


def xostor_controller(pool):
    f = pool.fact("linstor_controller")
    if not f.ok:
        if "not found" in (f.error or ""):
            return unknown("XOSTOR Controller IP", "Unknown (linstor CLI not found)")
        return unknown("XOSTOR Controller IP", "Unknown (%s)" % f.error)
    text = []
    for line in f.value.splitlines():
        if line.startswith("Error:"):
            continue
        text.append(line[len("linstor://"):] if line.startswith("linstor://") else line)
    value = "\n".join(text)
    if not value.strip():
        return flag("XOSTOR Controller IP", "None")
    return ok("XOSTOR Controller IP", value)


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
