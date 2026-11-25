# -*- coding: utf-8 -*-
"""Duplicate IPs (one host) and Duplicate IPs Across Hosts (the pool's hosts + the XOA).

The fixtures are the shape 'ip -o addr show' prints on an 8.3 dom0 and on the XOA (Debian
12), with documentation addresses in place of the lab's.
"""

import checks
import main
import model
import parsers
import result

OK, FLAG, UNKNOWN = result.OK, result.FLAG, result.UNKNOWN

TAIL = "\\       valid_lft forever preferred_lft forever"


def addr_line(idx, ifname, family, cidr, scope="global"):
    return "%d: %s    %s %s scope %s %s%s" % (idx, ifname, family, cidr, scope, ifname, TAIL)


def ipaddr(*lines):
    return {"ok": True, "value": "\n".join(
        [addr_line(1, "lo", "inet", "127.0.0.1/8", "host"),
         addr_line(1, "lo", "inet6", "::1/128", "host")] + list(lines)) + "\n"}


def host(address, name, ipaddr_fact=None, reachable=True):
    h = model.Host(address, "uuid-" + name, name, "true", "false")
    if reachable:
        h.payload = {"hostname": {"ok": True, "value": name}}
        if ipaddr_fact is not None:
            h.payload["ipaddr"] = ipaddr_fact
    return h


A = ipaddr(addr_line(6, "xenbr1", "inet", "198.51.100.1/24"),
           addr_line(7, "xapi1", "inet", "192.0.2.11/24"))
B = ipaddr(addr_line(6, "xenbr1", "inet", "198.51.100.2/24"),
           addr_line(7, "xapi1", "inet", "192.0.2.12/24"))
XOA = result.Fact(True, value=ipaddr(addr_line(2, "enX0", "inet", "192.0.2.7/24"),
                                     addr_line(2, "enX0", "inet6", "fe80::1/64", "link"))["value"])


# --------------------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------------------

def test_loopback_and_link_local_are_left_out_and_both_families_are_read():
    text = ipaddr(addr_line(2, "eth0", "inet", "192.0.2.5/24"),
                  addr_line(2, "eth0", "inet6", "2001:db8::5/64"),
                  addr_line(2, "eth0", "inet6", "fe80::5/64", "link"),
                  addr_line(9, "xenapi", "inet", "169.254.0.1/16", "link"))["value"]
    assert parsers.parse_ip_addrs(text) == [("eth0", "192.0.2.5"), ("eth0", "2001:db8::5")]


def test_an_ipv6_address_is_compared_in_its_canonical_spelling():
    text = ipaddr(addr_line(2, "eth0", "inet6", "2001:db8:0:0::5/64"),
                  addr_line(3, "eth1", "inet6", "2001:DB8::5/64"))["value"]
    assert parsers.duplicate_addresses(parsers.parse_ip_addrs(text)) == [
        ("2001:db8::5", ["eth0", "eth1"])]


def test_a_vlan_interface_is_named_without_its_parent():
    text = addr_line(5, "eth0.10@eth0", "inet", "192.0.2.5/24")
    assert parsers.parse_ip_addrs(text) == [("eth0.10", "192.0.2.5")]


def test_the_overlapping_subnets_reader_still_sees_only_ipv4():
    text = ipaddr(addr_line(2, "eth0", "inet", "192.0.2.5/24"),
                  addr_line(2, "eth0", "inet6", "2001:db8::5/64"))["value"]
    assert parsers.parse_ipv4_addrs(text) == [("eth0", "192.0.2.5/24")]


def test_one_address_twice_on_one_interface_is_not_two_places():
    entries = [("eth0", "192.0.2.5"), ("eth0", "192.0.2.5")]
    assert parsers.duplicate_addresses(entries) == []


# --------------------------------------------------------------------------------------
# Duplicate IPs (one host)
# --------------------------------------------------------------------------------------

def test_host_line_none_on_a_clean_host():
    line = checks.duplicate_ips(host("192.0.2.11", "xcp-a01", A))
    assert line.status == OK and line.key == "Duplicate IPs"


def test_host_line_names_the_address_and_both_interfaces():
    line = checks.duplicate_ips(host("192.0.2.11", "xcp-a01", ipaddr(
        addr_line(4, "eth1", "inet", "198.51.100.9/24"),
        addr_line(6, "xenbr1", "inet", "198.51.100.9/24"),
        addr_line(7, "xapi1", "inet", "192.0.2.11/24"))))
    assert line.status == FLAG
    assert line.text.endswith(" - 198.51.100.9 on eth1, xenbr1")


def test_host_line_unknown_without_the_fact_or_off_an_error():
    for fact in (None, {"ok": False, "error": "ip addr show failed (exit 1)"}):
        line = checks.duplicate_ips(host("192.0.2.11", "xcp-a01", fact))
        assert line.status == UNKNOWN and line.flags


def test_host_line_is_in_the_per_host_table():
    assert ("duplicate_ips", "Duplicate IPs", checks.duplicate_ips) in main.per_host_checks()


# --------------------------------------------------------------------------------------
# Duplicate IPs Across Hosts
# --------------------------------------------------------------------------------------

KEY = "Duplicate IPs Across Hosts"


def test_pool_line_none_counts_what_it_compared():
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", A), host("192.0.2.12", "xcp-a02", B)], XOA)
    assert line.status == OK and line.key == KEY
    assert "None (2 hosts + this XOA, 5 addresses)" in line.text


def test_two_hosts_holding_one_address_is_a_finding():
    clash = ipaddr(addr_line(6, "xenbr1", "inet", "198.51.100.1/24"),
                   addr_line(7, "xapi1", "inet", "192.0.2.12/24"))
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", A), host("192.0.2.12", "xcp-a02", clash)], XOA)
    assert line.status == FLAG
    assert line.text.endswith(" - 198.51.100.1")
    assert "xcp-a01 (192.0.2.11)  (xenbr1)" in line.detail_text
    assert "xcp-a02 (192.0.2.12)  (xenbr1)" in line.detail_text


def test_a_host_holding_the_xoa_address_is_a_finding():
    clash = ipaddr(addr_line(7, "xapi1", "inet", "192.0.2.7/24"))
    line = checks.duplicate_ips_across_hosts([host("192.0.2.11", "xcp-a01", clash)], XOA)
    assert line.status == FLAG
    assert "this XOA  (enX0)" in line.detail_text


def test_a_duplicate_inside_one_host_is_left_to_the_host_line():
    inside = ipaddr(addr_line(4, "eth1", "inet", "198.51.100.9/24"),
                    addr_line(6, "xenbr1", "inet", "198.51.100.9/24"))
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", inside), host("192.0.2.12", "xcp-a02", B)], XOA)
    assert line.status == OK


def test_a_reachable_host_whose_addresses_were_not_read_leaves_a_clean_answer_unknown():
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", A),
         host("192.0.2.12", "xcp-a02", {"ok": False, "error": "ip addr show failed (exit 1)"})],
        XOA)
    assert line.status == UNKNOWN and line.flags
    assert "xcp-a02 (192.0.2.12) (ip addr show failed (exit 1))" in line.text


def test_an_unread_xoa_leaves_a_clean_answer_unknown_but_not_a_finding():
    gone = result.Fact(False, error="ip addr show failed (timed out)")
    assert checks.duplicate_ips_across_hosts([host("192.0.2.11", "xcp-a01", A)],
                                             gone).status == UNKNOWN
    clash = ipaddr(addr_line(7, "xapi1", "inet", "192.0.2.11/24"))
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", A), host("192.0.2.12", "xcp-a02", clash)], gone)
    assert line.status == FLAG
    assert "not read: this XOA" in line.detail_text


def test_an_unreachable_host_is_named_as_not_compared():
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", A), host("192.0.2.12", "xcp-a02", reachable=False)], XOA)
    assert line.status == OK
    assert line.text.endswith(", 192.0.2.12 not compared (unreachable)")


def test_a_host_run_has_no_xoa_and_one_host_has_nothing_to_compare():
    line = checks.duplicate_ips_across_hosts([host("192.0.2.11", "xcp-a01", A)], None)
    assert line.status == OK and "Nothing to compare" in line.text
    line = checks.duplicate_ips_across_hosts(
        [host("192.0.2.11", "xcp-a01", A), host("192.0.2.12", "xcp-a02", B)], None)
    assert "None (2 hosts, 4 addresses)" in line.text
