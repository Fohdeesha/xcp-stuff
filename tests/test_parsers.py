# -*- coding: utf-8 -*-
"""Parser tests. Almost every case here is a bug that actually happened."""

import parsers

HOST_LIST_83 = """uuid ( RO)            : cab0f673-8369-4441-b6f1-9fc532f5c333
      name-label ( RW): xen-sec-01
         enabled ( RO): true
        hostname ( RO): xen-sec-01
         address ( RO): 192.168.1.13
    multipathing ( RW): true


uuid ( RO)            : 8edafca2-bf86-4705-8b8e-1db1463f74ff
      name-label ( RW): xen-sec-02
         enabled ( RO): false
        hostname ( RO): xen-sec-02
         address ( RO): 192.168.1.34
    multipathing ( RW): false

"""


def test_parse_host_list_reads_by_label_not_position():
    hosts = parsers.parse_host_list(HOST_LIST_83)
    assert len(hosts) == 2
    assert hosts[0]["address"] == "192.168.1.13"
    assert hosts[0]["multipathing"] == "true"
    assert hosts[1]["enabled"] == "false"
    assert hosts[1]["hostname"] == "xen-sec-02"


def test_parse_host_list_missing_param_is_unknown_not_blank():
    text = "uuid ( RO)            : abc\n         address ( RO): 10.0.0.1\n"
    hosts = parsers.parse_host_list(text)
    assert hosts[0]["multipathing"] == "Unknown"
    assert hosts[0]["enabled"] == "Unknown"


def test_records_split_at_uuid_not_at_blank_lines():
    # two SRs' output glued together has only ONE newline between them; paragraph
    # splitting merged the last record of one into the first of the next
    text = ("uuid ( RO): a\nname-label ( RW): one\n"
            "uuid ( RO): b\nname-label ( RW): two\n")
    recs = parsers.parse_xe_records(text)
    assert [r["uuid"] for r in recs] == ["a", "b"]
    assert [r["name-label"] for r in recs] == ["one", "two"]


# --------------------------------------------------------------------------------------

def test_timedatectl_old_labels():
    text = ("      Local time: Tue 2026-08-25 08:10:55 EDT\n"
            "     NTP enabled: yes\n"
            "NTP synchronized: yes\n")
    assert parsers.parse_timedatectl(text) == {"ntp": "yes", "sync": "yes"}


def test_timedatectl_new_labels_and_active_normalising():
    text = ("                NTP service: active\n"
            "System clock synchronized: yes\n")
    assert parsers.parse_timedatectl(text) == {"ntp": "yes", "sync": "yes"}


def test_timedatectl_inactive_becomes_no():
    assert parsers.parse_timedatectl("NTP service: inactive\n")["ntp"] == "no"


def test_timedatectl_missing_is_unknown_not_no():
    assert parsers.parse_timedatectl("")["ntp"] == "Unknown"


# --------------------------------------------------------------------------------------

DF = """Filesystem      Size  Used Avail Use% Mounted on
devtmpfs        2.0G   28K  2.0G  99% /dev
tmpfs           2.1G  420K  2.1G  95% /run
/dev/sda1        18G  5.2G   12G  32% /
xenstore        2.1G     0  2.1G  99% /var/lib/xenstored
/dev/sda5       3.9G  219M  3.5G  88% /var/log
/dev/mapper/x   838G  500G  296G  99% /run/sr-mount/a112e2ff-8923-186d-81bf-5125912752ca
"""


def test_parse_df_skips_pseudo_filesystems_and_sr_mounts():
    # a filling shared SR used to flag every host in the pool for a dom0 disk problem
    assert parsers.parse_df(DF, 75) == ["/var/log is at 88%"]


def test_parse_df_handles_mount_points_with_spaces():
    text = "/dev/sdb1 1G 1G 0 90% /mnt/my disk\n"
    assert parsers.parse_df(text, 75) == ["/mnt/my disk is at 90%"]


# --------------------------------------------------------------------------------------

def test_parse_meminfo_returns_none_when_unusable():
    # None is the point: a percentage off a zero total is a green 0.0%
    assert parsers.parse_meminfo("") is None
    assert parsers.parse_meminfo("MemTotal: 0 kB\n") is None
    assert parsers.parse_meminfo("MemTotal: 4194304 kB\n") is None  # no MemAvailable


def test_parse_meminfo_megabytes():
    text = "MemTotal:  4194304 kB\nMemFree: 1 kB\nMemAvailable:  1048576 kB\n"
    assert parsers.parse_meminfo(text) == (4096, 1024)


# --------------------------------------------------------------------------------------

LINKS = (
    "1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\\    link/loopback\n"
    "2: eth0: <BROADCAST,UP> mtu 1500 qdisc mq master ovs-system state UP mode DEFAULT\\    link/ether\n"
    "7: xapi1: <BROADCAST,UP> mtu 9000 qdisc noqueue state UNKNOWN mode DEFAULT\\    link/ether\n"
)


def test_parse_link_mtus_excludes_loopback():
    assert parsers.parse_link_mtus(LINKS) == [("eth0", "1500"), ("xapi1", "9000")]


ADDRS = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
    "6: xenbr1    inet 10.99.99.1/24 brd 10.99.99.255 scope global xenbr1\\       valid_lft forever\n"
    "7: xapi1    inet 192.168.1.13/24 brd 192.168.1.255 scope global xapi1\\       valid_lft forever\n"
)


def test_parse_ipv4_addrs():
    assert parsers.parse_ipv4_addrs(ADDRS) == [
        ("xenbr1", "10.99.99.1/24"), ("xapi1", "192.168.1.13/24")]


def test_overlapping_subnets_ignores_the_same_interface():
    same = [("eth0", "10.0.0.1/24"), ("eth0", "10.0.0.2/24")]
    assert parsers.has_overlapping_subnets(same) is False


def test_overlapping_subnets_across_interfaces():
    assert parsers.has_overlapping_subnets(
        [("eth0", "10.0.0.1/24"), ("eth1", "10.0.0.5/24")]) is True
    assert parsers.has_overlapping_subnets(
        [("eth0", "10.0.0.1/24"), ("eth1", "10.0.1.5/24")]) is False
    # a /16 that swallows a /24 on another interface still overlaps
    assert parsers.has_overlapping_subnets(
        [("eth0", "10.0.0.1/16"), ("eth1", "10.0.5.5/24")]) is True


def test_overlapping_subnets_needs_two_entries():
    assert parsers.has_overlapping_subnets([("eth0", "10.0.0.1/24")]) is False


# --------------------------------------------------------------------------------------

def test_lacp_matches_both_ovs_generations():
    # OVS <= 2.16 says slave:, 2.17 (XCP-ng 8.3) says member:. Matching only slave:
    # made every 8.3 host a false green.
    assert parsers.parse_lacp("  slave: eth0: current attached\n") is False
    assert parsers.parse_lacp("  member: eth0: current attached\n") is False
    assert parsers.parse_lacp("  member: eth0: defaulted detached\n") is True
    assert parsers.parse_lacp("  slave: eth1: expired attached\n") is True


def test_lacp_ignores_non_port_lines():
    assert parsers.parse_lacp("---- bond0 ----\n  status: active negotiated\n") is False


# --------------------------------------------------------------------------------------

def test_bond_slave_of_three_states():
    assert parsers.parse_bond_slave_of("") == parsers.BOND_NO_PIFS
    assert parsers.parse_bond_slave_of(
        "bond-slave-of ( RO): <not in database>\n") == parsers.BOND_NOT_MEMBER
    assert parsers.parse_bond_slave_of(
        "bond-slave-of ( RO): \n") == parsers.BOND_NOT_MEMBER
    assert parsers.parse_bond_slave_of(
        "bond-slave-of ( RO): abc-123\n") == parsers.BOND_MEMBER


def test_bond_no_pifs_is_not_read_as_not_a_member():
    # a deleted network answers rc 0 with no output; reading that as "no bond-slave-of
    # line, therefore not a bond member" printed a green Configured for a broken pool
    assert parsers.parse_bond_slave_of("") != parsers.BOND_NOT_MEMBER


# --------------------------------------------------------------------------------------

def test_other_config_splits_at_colon_space_not_first_colon():
    text = ("xo:clientInfo:ab90-cd: {\"a\":1}; auto_poweron: true; "
            "xo:migrationNetwork: 1234-5678")
    parsed = parsers.parse_other_config(text)
    assert parsed["xo:migrationNetwork"] == "1234-5678"
    assert parsed["auto_poweron"] == "true"


def test_other_config_missing_key():
    assert "xo:backupNetwork" not in parsers.parse_other_config("auto_poweron: true")


# --------------------------------------------------------------------------------------

def test_pool_conf():
    assert parsers.parse_pool_conf("master\n") == ("master", None)
    assert parsers.parse_pool_conf("slave:192.168.1.13\n") == ("slave", "192.168.1.13")
    assert parsers.parse_pool_conf("slave: 192.168.1.13 \n") == ("slave", "192.168.1.13")
    assert parsers.parse_pool_conf("") == (None, None)
    assert parsers.parse_pool_conf("garbage") == (None, None)


# --------------------------------------------------------------------------------------

def test_dmesg_word_match_is_whole_word():
    text = "line one\nsomething ripped\na kernel panic here\n"
    hits = parsers.dmesg_issue_lines(text, ["rip", "panic"], [], [])
    assert hits == [3]


def test_dmesg_phrase_match_is_substring():
    text = "a\nCPU stuck: Call Trace:\nb\n"
    assert parsers.dmesg_issue_lines(text, [], ["call trace"], []) == [2]


def test_dmesg_ignore_rule_needs_every_substring():
    text = "megaraid_sas 0000:01: firmware crash dump : no\nreal crash here\n"
    rules = [["megaraid", "firmware crash dump"]]
    assert parsers.dmesg_issue_lines(text, ["crash"], [], rules) == [2]
    # a rule only bites when ALL of its parts are present
    assert parsers.dmesg_issue_lines(text, ["crash"], [], [["megaraid", "nonesuch"]]) == [1, 2]


def test_dmesg_ignore_rule_collapses_whitespace():
    text = "megaraid_sas: firmware   crash    dump : no\n"
    assert parsers.dmesg_issue_lines(
        text, ["crash"], [], [["megaraid", "firmware crash dump"]]) == []


def test_mtu_keywords_reports_every_match():
    # returning on the first hit meant the line could not say which keyword tripped it
    text = "eth0: MTU too large\nfragmentation needed\n"
    assert parsers.find_mtu_keywords(text, ["mtu", "large", "fragment"]) == ["mtu", "large"]


# --------------------------------------------------------------------------------------

def test_context_block_merges_adjacent_ranges():
    text = "\n".join("l%d" % i for i in range(1, 21))
    block = parsers.context_block(text, [5, 7], 3)
    # 2..8 and 4..10 merge into 2..10, one run, no blank line inside
    assert block.splitlines() == ["  l%d" % i for i in range(2, 11)]


def test_context_block_separates_distant_ranges_with_a_blank_line():
    text = "\n".join("l%d" % i for i in range(1, 41))
    block = parsers.context_block(text, [5, 30], 3)
    lines = block.splitlines()
    assert lines[0] == "  l2"
    assert "" in lines
    assert lines[-1] == "  l33"


def test_context_block_clamps_to_the_file():
    text = "a\nb\nc\n"
    assert parsers.context_block(text, [1], 3).splitlines() == ["  a", "  b", "  c"]


def test_context_block_empty_when_nothing_matched():
    assert parsers.context_block("a\nb\n", []) == ""


# --------------------------------------------------------------------------------------

def test_manifest_versions_keeps_duplicate_names():
    # gpg-pubkey is installed twice on every dom0 here, and a host carries two kernels
    # between an update and the reboot that activates it
    text = "gpg-pubkey 0:aaa-1.noarch\ngpg-pubkey 0:bbb-2.noarch\nzlib 0:1.2-1.x86_64\n"
    versions = parsers.manifest_versions(text)
    assert versions["gpg-pubkey"] == "0:aaa-1.noarch, 0:bbb-2.noarch"
    assert versions["zlib"] == "0:1.2-1.x86_64"


def test_manifest_diff_control_case_all_names_unique():
    master = "a 0:1-1.x86_64\nb 0:2-1.x86_64\nc 0:3-1.x86_64\n"
    slave = "a 0:1-1.x86_64\nb 0:9-1.x86_64\nd 0:4-1.x86_64\n"
    assert parsers.manifest_diff(master, slave) == [
        "Does Not Match Master: b 0:9-1.x86_64 (Master: b 0:2-1.x86_64)",
        "Extra Package: d 0:4-1.x86_64",
        "Missing Package: c 0:3-1.x86_64",
    ]


def test_manifest_diff_sees_a_difference_confined_to_a_duplicated_name():
    # keeping one entry per name printed "Mismatch, See Below" over an empty block
    master = "gpg-pubkey 0:aaa-1.noarch\ngpg-pubkey 0:bbb-2.noarch\n"
    slave = "gpg-pubkey 0:aaa-1.noarch\n"
    assert parsers.manifest_diff(master, slave) == [
        "Does Not Match Master: gpg-pubkey 0:aaa-1.noarch "
        "(Master: gpg-pubkey 0:aaa-1.noarch, 0:bbb-2.noarch)",
    ]


def test_manifest_diff_no_stray_separator_on_single_version_packages():
    # testing "have we seen this name" against the value array put a ", " in front of
    # every single-version package, and only the control case caught it
    out = parsers.manifest_diff("a 0:1-1.x86_64\n", "a 0:2-1.x86_64\n")
    assert out == ["Does Not Match Master: a 0:2-1.x86_64 (Master: a 0:1-1.x86_64)"]


def test_manifest_diff_identical_is_empty():
    text = "a 0:1-1.x86_64\nb 0:2-1.x86_64\n"
    assert parsers.manifest_diff(text, text) == []


# --------------------------------------------------------------------------------------

def test_cap_lines_counts_the_remainder():
    # a silent cut reads as "these are all of them" when it is not
    out = parsers.cap_lines(["a", "b", "c", "d"], 2, "more thing(s)")
    assert out == ["a", "b", "(plus 2 more thing(s) not listed)"]


def test_cap_lines_below_the_cap_is_untouched():
    assert parsers.cap_lines(["a", "b"], 5, "x") == ["a", "b"]
    assert parsers.cap_lines(["a", "b"], 0, "x") == ["a", "b"]


# --------------------------------------------------------------------------------------

def test_dns_gw_pifs():
    empty = "gateway ( RO)    : \n        DNS ( RO): \n\n"
    assert parsers.parse_dns_gw_pifs(empty) is False
    assert parsers.parse_dns_gw_pifs(
        "gateway ( RO)    : 10.0.0.1\n        DNS ( RO): \n") is True
    assert parsers.parse_dns_gw_pifs(
        "gateway ( RO)    : \n        DNS ( RO): 8.8.8.8\n") is True
    assert parsers.parse_dns_gw_pifs("") is False
