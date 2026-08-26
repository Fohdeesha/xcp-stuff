# -*- coding: utf-8 -*-
"""Check-level tests, driven by synthetic collector documents.

This is where the paths the lab cannot produce get covered - no XOSTOR anywhere, no
backup network configured, no host with a failed LACP bond - and where the rule the whole
tool exists for is asserted directly: a fact we could not establish must never come back
green.
"""

import checks
import model
import result

OK, FLAG, UNKNOWN, INFO = result.OK, result.FLAG, result.UNKNOWN, result.INFO


def fact(value):
    return {"ok": True, "value": value}


def err(reason="could not look"):
    return {"ok": False, "error": reason}


def host(**facts):
    h = model.Host("10.0.0.1", "uuid-1", "hostx", "true", "false")
    h.payload = dict(facts)
    h.local_now = 1000.0
    return h


def pool(**facts):
    p = model.Pool()
    p.payload = dict(facts)
    return p


def no_ping(_ips):
    return []


def all_silent(ips):
    return list(ips)


# --------------------------------------------------------------------------------------
# never green off an unestablished fact
# --------------------------------------------------------------------------------------

UNCOLLECTED = [
    ("Dom0 Disk Usage", checks.dom0_disk_usage),
    ("MTU Issues", checks.mtu_issues),
    ("Dmesg Content", checks.dmesg_content),
    ("OOM Events", checks.oom_events),
    ("Crash Logs Present", checks.crash_logs),
    ("Coredumps Present", checks.coredumps),
    ("LACP Negotiation Issues", checks.lacp),
    ("Silly MTUs", checks.silly_mtus),
    ("DNS/GW on Non-Mgmt PIFs", checks.dns_gw_non_mgmt_pifs),
    ("Overlapping Subnets", checks.overlapping_subnets),
    ("Log Errors", checks.log_errors),
    ("LUN Assignments", checks.lun_assignments),
    ("SMAPI Hidden Leaves", checks.smapi_hidden_leaves),
    ("Rebooted After Updates", checks.rebooted_after_updates),
]


def test_every_host_check_says_unknown_when_the_fact_is_missing():
    empty = host()
    for key, fn in UNCOLLECTED:
        line = fn(empty)
        assert line.status == UNKNOWN, "%s answered %s off no fact" % (key, line.status)
        assert line.flags, "%s must flag the exit code" % key


def test_every_host_check_says_unknown_when_the_fact_is_an_error():
    broken = host(df=err(), dmesg=err(), crash_count=err(), coredumps=err(), lacp=err(),
                  iplink=err(), pifs_dns_gw=err(), ipaddr=err(), log_scan=err(),
                  lun_scan=err(), smapi=err(), boot_epoch=err())
    for key, fn in UNCOLLECTED:
        line = fn(broken)
        assert line.status == UNKNOWN, "%s answered %s off an error" % (key, line.status)


def test_dom0_memory_unknown_is_not_a_green_zero():
    lines = checks.dom0_memory(host(meminfo=err()))
    assert [l.status for l in lines] == [UNKNOWN, UNKNOWN]
    # the same when meminfo came back but was unusable
    lines = checks.dom0_memory(host(meminfo=fact("MemTotal: 0 kB\n")))
    assert [l.status for l in lines] == [UNKNOWN, UNKNOWN]


# --------------------------------------------------------------------------------------
# info block
# --------------------------------------------------------------------------------------

def test_hypervisor_version_flags_below_83_and_keeps_the_line_key():
    old = checks.hypervisor_version(host(os_release=fact({"NAME": "XCP-ng", "VERSION": "8.2.1"})))
    assert old.key == "Hypervisor Version" and old.status == FLAG
    assert "XCP-ng 8.2.1" in old.text

    new = checks.hypervisor_version(host(os_release=fact({"NAME": "XCP-ng", "VERSION": "8.3.0"})))
    assert new.key == "Hypervisor Version" and new.status == INFO
    assert new.always_print and not new.flags

    # the key never changes, even when os-release could not be read
    blind = checks.hypervisor_version(host(os_release=err()))
    assert blind.key == "Hypervisor Version" and blind.status == UNKNOWN


def test_hypervisor_version_future_major():
    line = checks.hypervisor_version(host(os_release=fact({"NAME": "XCP-ng", "VERSION": "9.0.0"})))
    assert line.status == INFO


def test_host_enabled_states():
    h = host()
    h.enabled = "true"
    assert checks.host_enabled(h).status == OK
    h.enabled = "false"
    assert checks.host_enabled(h).status == FLAG
    h.enabled = "Unknown"
    line = checks.host_enabled(h)
    assert line.status == INFO and not line.flags   # not a finding, just not in the maps


def test_multipathing_never_flags():
    h = host()
    for value in ("true", "false", "Unknown"):
        h.multipathing = value
        line = checks.multipathing(h)
        assert line.status == INFO and not line.flags and line.always_print


def test_ntp_states():
    good = host(timedatectl=fact("NTP enabled: yes\nNTP synchronized: yes\n"))
    assert checks.ntp(good).status == OK
    bad = host(timedatectl=fact("NTP enabled: no\nNTP synchronized: yes\n"))
    assert checks.ntp(bad).status == FLAG
    unknown = host(timedatectl=err())
    line = checks.ntp(unknown)
    assert line.status == INFO and line.always_print and not line.flags


# --------------------------------------------------------------------------------------
# rebooted after updates - all four branches
# --------------------------------------------------------------------------------------

def test_rebooted_yes_with_both_dates_as_evidence():
    line = checks.rebooted_after_updates(host(
        boot_epoch=fact(200), boot_disp=fact("B"),
        update_epoch=fact(100), update_disp=fact("U")))
    assert line.status == OK
    assert "updated U" in line.text and "booted B" in line.text


def test_rebooted_no_with_both_dates_as_evidence():
    line = checks.rebooted_after_updates(host(
        boot_epoch=fact(100), boot_disp=fact("B"),
        update_epoch=fact(200), update_disp=fact("U")))
    assert line.status == FLAG
    assert "updated U" in line.text and "booted B" in line.text


def test_rebooted_backstop_when_nothing_installed_since_boot():
    line = checks.rebooted_after_updates(host(
        boot_epoch=fact(500), boot_disp=fact("B"),
        update_epoch=err("no update found"), newest_rpm=fact(400)))
    assert line.status == OK
    assert "nothing installed since boot" in line.text


def test_rebooted_unknown_when_something_landed_since_boot_but_we_cannot_tell_what():
    # the old code printed a green Yes here, having established nothing at all
    line = checks.rebooted_after_updates(host(
        boot_epoch=fact(300), boot_disp=fact("B"),
        update_epoch=err("no update found"), newest_rpm=fact(400)))
    assert line.status == UNKNOWN


def test_rebooted_unknown_without_a_boot_time():
    line = checks.rebooted_after_updates(host(boot_epoch=err()))
    assert line.status == UNKNOWN


# --------------------------------------------------------------------------------------
# yum patch level
# --------------------------------------------------------------------------------------

def test_yum_patch_level_master_is_the_reference_and_is_suppressed_by_f():
    line = checks.yum_patch_level(host(), True, "")
    assert line.status == OK and not line.always_print


def test_yum_patch_level_without_a_baseline_is_unknown_not_a_mismatch():
    line = checks.yum_patch_level(host(rpm_manifest=fact("a 0:1\n")), False, "")
    assert line.status == UNKNOWN and "no baseline" in line.text


def test_yum_patch_level_unfetchable_slave_is_unknown_not_a_mismatch():
    line = checks.yum_patch_level(host(rpm_manifest=err()), False, "a 0:1\n")
    assert line.status == UNKNOWN and "could not retrieve" in line.text


def test_yum_patch_level_match_and_mismatch():
    same = checks.yum_patch_level(host(rpm_manifest=fact("a 0:1\n")), False, "a 0:1\n")
    assert same.status == OK
    diff = checks.yum_patch_level(host(rpm_manifest=fact("a 0:2\n")), False, "a 0:1\n")
    assert diff.status == FLAG
    assert "Does Not Match Master: a 0:2" in diff.detail_text


# --------------------------------------------------------------------------------------
# pool level
# --------------------------------------------------------------------------------------

def test_ha_states():
    assert checks.ha_enabled(pool(ha_enabled=fact("false"))).status == OK
    assert checks.ha_enabled(pool(ha_enabled=fact("true"))).status == FLAG
    assert checks.ha_enabled(pool(ha_enabled=err())).status == UNKNOWN
    assert checks.ha_enabled(pool(ha_enabled=fact("wat"))).status == UNKNOWN


def test_migration_compression_empty_means_pre_83_only_with_a_pool_uuid():
    p = pool(pool_uuid=fact("pu"), migration_compression=fact(""))
    assert checks.migration_compression(p).status == OK

    # without a uuid the list form ALSO answers empty, which is indistinguishable - that
    # used to print a green 'Not supported (pre-8.3)' on any version
    p = pool(pool_uuid=err(), migration_compression=err())
    line = checks.migration_compression(p)
    assert line.status == UNKNOWN and "pool UUID not available" in line.text


def test_migration_compression_true_and_false():
    assert checks.migration_compression(
        pool(pool_uuid=fact("pu"), migration_compression=fact("true"))).status == FLAG
    assert checks.migration_compression(
        pool(pool_uuid=fact("pu"), migration_compression=fact("false"))).status == OK


def test_missing_patches():
    assert checks.missing_patches(pool(yum_check=fact(0))).status == OK
    flagged = checks.missing_patches(pool(yum_check=fact(7)))
    assert flagged.status == FLAG and "7" in flagged.text
    # a yum that failed must never read as zero
    assert checks.missing_patches(pool(yum_check=err())).status == UNKNOWN


def test_vlan0():
    assert checks.vlan0(pool(vlan0=fact(""))).status == OK
    assert checks.vlan0(pool(vlan0=fact("uuid"))).status == FLAG
    assert checks.vlan0(pool(vlan0=err())).status == UNKNOWN


def test_xostor_in_use_is_a_fact_not_a_finding():
    off = checks.xostor_in_use(pool(xostor_srs=fact([])))
    assert off.status == OK
    on = checks.xostor_in_use(pool(xostor_srs=fact(["sr-1"])))
    # yellow-and-flagging would have marked every XOSTOR pool unhealthy forever
    assert on.status == INFO and not on.flags and on.always_print


def test_xostor_ram():
    assert checks.xostor_ram(pool(), None).status == UNKNOWN
    assert checks.xostor_ram(pool(), (8 * 1024, 0)).status == FLAG
    assert checks.xostor_ram(pool(), (16 * 1024, 0)).status == OK


def test_xostor_linstor_missing_is_unknown():
    p = pool(linstor_nodes=err("linstor CLI not found"),
             linstor_faulty=err("linstor CLI not found"),
             linstor_controller=err("linstor CLI not found"))
    for fn in (checks.xostor_nodes, checks.xostor_faulty_resources, checks.xostor_controller):
        line = fn(p)
        assert line.status == UNKNOWN and "linstor CLI not found" in line.text


LINSTOR_NODES = """+----------------------------------+
| Node       | NodeType | State   |
|==================================|
| xen-sec-01 | COMBINED | Online  |
| xen-sec-02 | COMBINED | OFFLINE |
+----------------------------------+
"""


def test_xostor_node_state_column():
    p = pool(linstor_nodes=fact(LINSTOR_NODES))
    assert checks.xostor_nodes(p).status == FLAG
    good = LINSTOR_NODES.replace("OFFLINE", "Online ")
    assert checks.xostor_nodes(pool(linstor_nodes=fact(good))).status == OK


def test_xostor_controller_none_is_a_failure():
    assert checks.xostor_controller(pool(linstor_controller=fact("\n"))).status == FLAG
    line = checks.xostor_controller(pool(linstor_controller=fact("linstor://10.0.0.5\n")))
    assert line.status == OK and "10.0.0.5" in line.text


def test_xostor_qcow2_cap_counts_the_remainder():
    rows = ["uuid%d  name%d" % (i, i) for i in range(50)]
    line = checks.xostor_qcow2(pool(qcow2=fact(rows), qcow2_total=fact(63)))
    assert line.status == FLAG
    assert "(plus 13 more qcow2 VDI(s) not listed)" in line.detail_text


def test_xostor_qcow2_none_and_unknown():
    assert checks.xostor_qcow2(pool(qcow2=fact([]), qcow2_total=fact(0))).status == OK
    assert checks.xostor_qcow2(pool(qcow2=err())).status == UNKNOWN


# --------------------------------------------------------------------------------------
# migration / backup network - every state, none of which the lab can produce
# --------------------------------------------------------------------------------------

def net_pool(key, bond_text, ips=None, oc=None):
    other = oc if oc is not None else "%s: net-1" % key
    payload = {"other_config": fact(other),
               "networks": {key: {"uuid": "net-1", "bond": fact(bond_text)}}}
    if ips is not None:
        payload["networks"][key]["ips"] = fact(ips)
    return pool(**payload)


def test_migration_network_not_configured():
    p = pool(other_config=fact("auto_poweron: true"))
    assert checks.migration_network(p).status == OK


def test_migration_network_unreadable_map():
    assert checks.migration_network(pool(other_config=err())).status == UNKNOWN


def test_migration_network_bond_member():
    p = net_pool("xo:migrationNetwork", "bond-slave-of ( RO): bond-1\n")
    assert checks.migration_network(p).status == FLAG


def test_migration_network_deleted_network_has_no_pifs():
    # rc 0 with no output at all - reading that as "not a bond member" printed a green
    # Configured for a pool whose migration network somebody had deleted
    p = net_pool("xo:migrationNetwork", "")
    line = checks.migration_network(p)
    assert line.status == FLAG and "no PIFs" in line.text


def test_migration_network_configured():
    p = net_pool("xo:migrationNetwork", "bond-slave-of ( RO): <not in database>\n")
    assert checks.migration_network(p).status == OK


def test_backup_network_reachable_and_not():
    good = net_pool("xo:backupNetwork", "bond-slave-of ( RO): <not in database>\n",
                    ips=["10.0.0.1", "10.0.0.2"])
    line = checks.backup_network(good, "xoa", no_ping)
    assert line.status == OK and "reachable from XOA" in line.text

    line = checks.backup_network(good, "xoa", all_silent)
    assert line.status == FLAG
    assert "No ping answer from XOA for: 10.0.0.1, 10.0.0.2" in line.text


def test_backup_network_no_usable_ip_differs_from_could_not_look():
    empty = net_pool("xo:backupNetwork", "bond-slave-of ( RO): <not in database>\n", ips=[])
    line = checks.backup_network(empty, "xoa", no_ping)
    assert line.status == FLAG and "no usable IP" in line.text

    # a transport failure must not print a claim about the network
    p = pool(other_config=fact("xo:backupNetwork: net-1"),
             networks={"xo:backupNetwork": {"uuid": "net-1",
                                            "bond": fact("bond-slave-of ( RO): \n"),
                                            "ips": err()}})
    line = checks.backup_network(p, "xoa", no_ping)
    assert line.status == UNKNOWN and "could not read backup network PIFs" in line.text


def test_backup_network_host_mode_says_what_it_did_not_test():
    good = net_pool("xo:backupNetwork", "bond-slave-of ( RO): <not in database>\n",
                    ips=["10.0.0.1"])
    line = checks.backup_network(good, "host", all_silent)
    assert line.status == OK
    assert "reachability from XOA not checked" in line.text


# --------------------------------------------------------------------------------------
# things that flag with detail blobs
# --------------------------------------------------------------------------------------

def test_lacp_states():
    assert checks.lacp(host(lacp=fact(""))).status == OK
    assert checks.lacp(host(lacp=fact("  member: eth0: current attached\n"))).status == OK
    bad = checks.lacp(host(lacp=fact("  member: eth0: defaulted detached\n")))
    assert bad.status == FLAG and bad.detail_title == "LACP Output"
    # rc != 0 means OVS is not answering, which is not "no bonds"
    assert checks.lacp(host(lacp=err("could not query Open vSwitch"))).status == UNKNOWN


def test_coredumps_cap_and_wording():
    rows = ["2026-01-0%d 00:00      100  core.tapdisk.%d" % (i % 9 + 1, i) for i in range(60)]
    line = checks.coredumps(host(coredumps=fact(rows)))
    assert line.status == FLAG and "60 file(s)" in line.text
    assert "(plus 10 older coredump(s) not listed)" in line.detail_text


def test_silly_mtus_names_the_offenders():
    links = "2: eth0: <UP> mtu 9000 qdisc mq state UP mode DEFAULT\\    link\n"
    line = checks.silly_mtus(host(iplink=fact(links)))
    assert line.status == FLAG and "eth0=9000" in line.text


def test_dom0_disk_usage_names_the_mounts():
    df = "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 1G 1G 0 91% /var/log\n"
    line = checks.dom0_disk_usage(host(df=fact(df)))
    assert line.status == FLAG and "/var/log is at 91%" in line.text
