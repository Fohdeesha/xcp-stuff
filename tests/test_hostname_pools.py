# -*- coding: utf-8 -*-
"""Pools xo-db stores by name (or with a scheme), and the addresses that belong to them.

A server record's `host` is whatever was typed into XO. A customer pool stored as
xcp-a01.example.net was invisible to every lookup made with one of its addresses:
'-n a01 192.0.2.60' took the master's own address for the root password and failed as
'Permission denied', '-n a01 192.0.2.61' (a slave) did the same, and
'health.py 192.0.2.60' said the master was not in xo-db.

Three kinds of evidence, strongest first: the host field, the member list xo-server keeps
since July 2026 (poolMembersAddresses), and DNS of xo-db's own names. The argument in the
password position is never resolved - that would put a root password in a DNS query.
"""

import io
import json
import socket
import sys
import time
import types

import pytest

import config
import main
import model
import parsers
import transport
import xodb

MASTER_IP = "192.0.2.60"
SLAVE_IP = "192.0.2.61"
NAME = "xcp-a01.example.net"
POOL = "Example-Pool-A"


def record(host, password="pwA01", members=None, enabled="true", name=POOL, label="a01"):
    rec = {"host": host, "password": password, "enabled": enabled,
           "poolNameLabel": name, "label": label}
    if members is not None:
        rec["poolMembersAddresses"] = json.dumps(members)
    return rec


OTHER = record("192.168.1.13", password="p13", name="XEN-SECONDARY", label="sec-01",
               members=["192.168.1.13", "192.168.1.34"])


@pytest.fixture(autouse=True)
def fresh_cache():
    xodb.reset_cache()
    yield
    xodb.reset_cache()


@pytest.fixture
def db(monkeypatch):
    """Install the records xo-db answers with, past both of its read paths."""
    def install(*records):
        monkeypatch.setattr(xodb, "_read_servers",
                            lambda: ([dict(r) for r in records], ""))
        monkeypatch.setattr(xodb, "have_xo_server_db", lambda: True)
    return install


@pytest.fixture
def dns(monkeypatch):
    """getaddrinfo answering from a table, and remembering every name it was asked."""
    state = types.SimpleNamespace(table={}, asked=[], delay=0.0)

    def fake(name, port, *args, **kwargs):
        state.asked.append(name)
        if state.delay:
            time.sleep(state.delay)
        if name not in state.table:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                for ip in state.table[name]]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return state


# --------------------------------------------------------------------------------------
# reading a record's host field the way XO does
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, want", [
    ("192.168.1.5", ("192.168.1.5", None)),
    ("192.168.1.5:443", ("192.168.1.5", 443)),
    (NAME, (NAME, None)),
    ("http://192.168.1.229", ("192.168.1.229", None)),
    ("https://xen.example.com:8443/", ("xen.example.com", 8443)),
    ("https://root:pw@10.0.0.5", ("10.0.0.5", None)),
    ("[fd00::1]:443", ("fd00::1", 443)),
    ("https://[fd00::1]", ("fd00::1", None)),
    # XO's own pattern takes no bare IPv6; the old reading leaves it whole
    ("fd00::1", ("fd00::1", None)),
])
def test_a_record_host_is_read_the_way_xo_reads_it(text, want):
    assert parsers.xo_server_address(text) == want


def test_ip_literal_is_canonical_and_refuses_names():
    assert parsers.ip_literal("10.0.0.1") == "10.0.0.1"
    assert parsers.ip_literal("FD00:0:0::1") == "fd00::1"
    assert parsers.ip_literal("fe80::1%eth0") == "fe80::1"
    assert parsers.ip_literal(NAME) is None
    assert parsers.ip_literal("") is None
    assert parsers.ip_literal(None) is None


def test_member_addresses_read_only_a_list_of_strings():
    assert parsers.pool_member_addresses('["10.0.0.1","10.0.0.2"]') == ["10.0.0.1", "10.0.0.2"]
    assert parsers.pool_member_addresses("") == []
    assert parsers.pool_member_addresses(None) == []
    assert parsers.pool_member_addresses("not json") == []
    assert parsers.pool_member_addresses('{"a": 1}') == []
    assert parsers.pool_member_addresses('["10.0.0.1", 7, ""]') == ["10.0.0.1"]


# --------------------------------------------------------------------------------------
# which record an address belongs to
# --------------------------------------------------------------------------------------

def test_the_host_field_answers_first_and_dns_is_never_asked(db, dns):
    db(record(NAME, members=[NAME, MASTER_IP, SLAVE_IP]))
    rec, how = xodb.match_record(NAME, xodb.all_servers(), resolve_want=True)
    assert how == "host" and rec["host"] == NAME
    assert xodb.match_record(NAME.upper(), xodb.all_servers())[1] == "host"
    assert dns.asked == []


def test_a_host_field_with_a_scheme_or_port_still_names_its_address(db, dns):
    db(record("https://10.0.0.5:443"))
    assert xodb.match_record("10.0.0.5", xodb.all_servers())[1] == "host"
    assert dns.asked == []


def test_a_slave_is_found_by_the_member_list_without_dns(db, dns):
    db(OTHER, record(NAME, members=[NAME, MASTER_IP, SLAVE_IP]))
    rec, how = xodb.match_record(SLAVE_IP, xodb.all_servers())
    assert how == "member" and rec["host"] == NAME
    assert dns.asked == []


def test_an_older_xo_with_no_member_list_falls_back_to_dns_of_its_own_names(db, dns):
    db(OTHER, record(NAME))
    dns.table[NAME] = [MASTER_IP]
    rec, how = xodb.match_record(MASTER_IP, xodb.all_servers())
    assert how == "dns" and rec["host"] == NAME
    # the address itself is an IP literal and is never handed to the resolver
    assert dns.asked == [NAME]


def test_a_value_that_may_be_a_password_is_never_resolved(db, dns):
    """Not even xo-db's names are looked up for it: a non-IP value can only ever match a
    record outright, so there is nothing for DNS to add."""
    db(record(NAME))
    dns.table[NAME] = [MASTER_IP]
    assert xodb.match_record("hunter2", xodb.all_servers(), resolve_want=False) == (None, "")
    assert xodb.match_record("secret.example", xodb.all_servers(), resolve_want=False) \
        == (None, "")
    assert dns.asked == []


def test_a_host_argument_given_by_name_finds_a_record_stored_by_ip(db, dns):
    db(record("192.168.4.16", password="p16", name="2028 East"))
    dns.table["east-master.lab"] = ["192.168.4.16"]
    rec, how = xodb.match_record("east-master.lab", xodb.all_servers(), resolve_want=True)
    assert how == "dns" and rec["password"] == "p16"


def test_a_name_finds_a_slave_in_the_member_list(db, dns):
    db(record(NAME, members=[NAME, MASTER_IP, SLAVE_IP]))
    dns.table["xcp-a02.example.net"] = [SLAVE_IP]
    rec, how = xodb.match_record("xcp-a02.example.net", xodb.all_servers(),
                                 resolve_want=True)
    assert how == "dns" and rec["host"] == NAME


def test_a_name_and_a_record_name_resolving_alike_match(db, dns):
    db(record("xcp-a01"))
    dns.table["xcp-a01"] = [MASTER_IP]
    dns.table[NAME] = [MASTER_IP]
    assert xodb.match_record(NAME, xodb.all_servers(), resolve_want=True)[1] == "dns"


def test_an_address_nobody_holds_matches_nothing(db, dns):
    db(OTHER, record(NAME))
    dns.table[NAME] = [MASTER_IP]
    assert xodb.match_record("10.9.9.9", xodb.all_servers()) == (None, "")


def test_a_name_that_does_not_resolve_is_no_match_and_no_error(db, dns):
    db(record(NAME))
    assert xodb.match_record(MASTER_IP, xodb.all_servers()) == (None, "")


def test_dns_is_bounded_by_one_deadline_for_the_lot(db, dns, monkeypatch):
    """An XOA whose resolver has gone away must not hang the run, one name at a time."""
    monkeypatch.setattr(config, "XO_DNS_TIMEOUT", 0.3)
    db(*[record("pool%d.example" % i) for i in range(6)])
    dns.delay = 3.0
    started = time.time()
    assert xodb.match_record(MASTER_IP, xodb.all_servers()) == (None, "")
    assert time.time() - started < 2.0


def test_each_name_is_looked_up_once_per_run(db, dns):
    db(record(NAME))
    dns.table[NAME] = [MASTER_IP]
    xodb.match_record(MASTER_IP, xodb.all_servers())
    xodb.match_record("10.9.9.9", xodb.all_servers())
    assert dns.asked == [NAME]


def test_the_password_follows_the_record_any_tier_found(db, dns):
    db(OTHER, record(NAME, members=[NAME, MASTER_IP, SLAVE_IP]))
    assert xodb.password_for(SLAVE_IP) == ("pwA01", False)
    assert xodb.password_for(MASTER_IP) == ("pwA01", False)
    assert xodb.password_for("192.168.1.34") == ("p13", False)


def test_a_disabled_record_still_yields_its_password_by_member(db, dns):
    db(record(NAME, members=[NAME, MASTER_IP], enabled="false"))
    assert xodb.password_for(MASTER_IP) == ("pwA01", False)
    # ...but names no pool for the banner, which lists enabled pools only, as before
    assert xodb.pool_name_for_host(MASTER_IP) == ""


def test_the_banner_names_a_pool_stored_by_name(db, dns):
    db(record(NAME))
    dns.table[NAME] = [MASTER_IP]
    assert xodb.pool_name_for_host(MASTER_IP) == POOL


# --------------------------------------------------------------------------------------
# resolve_target_xoa, end to end
# --------------------------------------------------------------------------------------

def resolve(monkeypatch, argv, name_filter="", single=False):
    """resolve_target_xoa as main runs it. (exit code or None, stdout, stderr, run)."""
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(main, "detect_run_env", lambda: "xoa")
    run = main.Run()
    run.name_filter = name_filter
    run.pool_mode = not single
    run.transport = types.SimpleNamespace(ssh_port=22, password="",
                                          enable_password_auth=lambda run_env: True)
    code = None
    try:
        main.resolve_target_xoa(run, list(argv))
    except SystemExit as exc:
        code = exc.code
    return code, out.getvalue(), err.getvalue(), run


def test_the_reported_case_the_master_ip_after_n_is_refused_by_dns(monkeypatch, db, dns):
    db(OTHER, record(NAME))
    dns.table[NAME] = [MASTER_IP]
    code, out, err, _ = resolve(monkeypatch, [MASTER_IP], name_filter="a01")
    assert code == 2
    assert ("'%s' is an address of pool '%s' (xo-server-db has it as %s, which resolves to it)"
            % (MASTER_IP, POOL, NAME)) in err
    assert "Use either '-n a01' or the host '%s', not both." % MASTER_IP in err
    assert out == ""


def test_the_reported_case_a_slave_ip_after_n_is_refused_by_the_member_list(
        monkeypatch, db, dns):
    db(OTHER, record(NAME, members=[NAME, MASTER_IP, SLAVE_IP]))
    code, _, err, _ = resolve(monkeypatch, [SLAVE_IP], name_filter="a01")
    assert code == 2
    assert "'%s' is the address of a member of pool '%s' in xo-server-db" % (SLAVE_IP, POOL) in err


def test_a_pool_stored_by_ip_gets_the_same_message_as_before(monkeypatch, db, dns):
    db(record("192.168.1.5", name="XEN-PRIMARY", label="XEN-MAIN-01"))
    code, _, err, _ = resolve(monkeypatch, ["192.168.1.5"], name_filter="main")
    assert code == 2
    assert err.startswith(
        "ERROR: '192.168.1.5' is the address of pool 'XEN-PRIMARY' in xo-server-db, but the "
        "value after\n       -n/--name is read as a password, not a host - -n already "
        "selects the pool.\n       Use either '-n main' or the host '192.168.1.5', not both.\n")
    assert dns.asked == []


def test_a_real_password_after_n_is_taken_and_never_looked_up(monkeypatch, db, dns):
    db(OTHER, record(NAME))
    dns.table[NAME] = [MASTER_IP]
    code, out, err, run = resolve(monkeypatch, ["s3cret.pw"], name_filter="a01")
    assert code is None
    assert run.password == "s3cret.pw"
    assert run.password_after_name is True
    assert run.seed == NAME
    assert "s3cret.pw" not in dns.asked


def test_the_master_ip_alone_finds_the_password_of_a_pool_stored_by_name(monkeypatch, db, dns):
    db(OTHER, record(NAME))
    dns.table[NAME] = [MASTER_IP]
    code, out, err, run = resolve(monkeypatch, [MASTER_IP])
    assert code is None
    assert run.password == "pwA01"
    assert run.seed == MASTER_IP
    assert "Checking pool: %s (%s)" % (POOL, MASTER_IP) in out
    assert "not found in xo-db" not in out


def test_a_slave_ip_alone_finds_the_pool_password_and_s_works_without_one(
        monkeypatch, db, dns):
    db(record(NAME, members=[NAME, MASTER_IP, SLAVE_IP]))
    code, out, _, run = resolve(monkeypatch, [SLAVE_IP], single=True)
    assert code is None
    assert run.password == "pwA01"
    assert run.seed == SLAVE_IP


def test_an_address_xo_db_does_not_hold_is_still_not_found(monkeypatch, db, dns):
    db(record(NAME))
    dns.table[NAME] = [MASTER_IP]
    code, out, _, _ = resolve(monkeypatch, ["10.9.9.9"])
    assert code == 1
    assert "Host IP not found in xo-db" in out


def test_a_picked_record_with_a_scheme_reaches_ssh_as_a_bare_address(monkeypatch, db, dns):
    db(record("https://10.0.0.5:443", name="Schemed"))
    code, out, _, run = resolve(monkeypatch, [], name_filter="schemed")
    assert code is None
    assert run.seed == "10.0.0.5"
    assert run.transport.ssh_port == 22
    assert run.password == "pwA01"
    assert run.server["host"] == "https://10.0.0.5:443"


def test_a_host_argument_keeps_its_ssh_port(monkeypatch, db, dns):
    db(record("10.0.0.5"))
    code, _, _, run = resolve(monkeypatch, ["10.0.0.5:2222"])
    assert code is None
    assert run.seed == "10.0.0.5" and run.transport.ssh_port == 2222
    assert run.password == "pwA01"


# --------------------------------------------------------------------------------------
# what is left ambiguous gets said
# --------------------------------------------------------------------------------------

class RefusingTransport(object):
    def __init__(self, message):
        self.message = message

    def collect(self, host, spec):
        raise transport.CollectError(self.message)


DENIED = ("ssh to %s failed (exit 255): root@%s: Permission denied (publickey,password)."
          % (NAME, NAME))


def discover_failing(monkeypatch, message, after_name):
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    run = main.Run()
    run.run_env = "xoa"
    run.seed = NAME
    run.password = "192.0.2.61"
    run.password_after_name = after_name
    run.transport = RefusingTransport(message)
    with pytest.raises(SystemExit) as exc:
        main.discover(run)
    return exc.value.code, err.getvalue()


def test_an_auth_failure_on_a_password_given_after_n_says_how_it_was_read(monkeypatch):
    code, err = discover_failing(monkeypatch, DENIED, after_name=True)
    assert code == 1
    assert "With -n/--name the one argument after it is the root password, not a host." in err
    # never echoed: it may really be a password
    assert "192.0.2.61" not in err


def test_no_note_without_n_or_for_another_kind_of_failure(monkeypatch):
    _, err = discover_failing(monkeypatch, DENIED, after_name=False)
    assert "-n/--name" not in err
    _, err = discover_failing(monkeypatch, "ssh to x failed (exit 255): Connection timed out",
                              after_name=True)
    assert "-n/--name" not in err


# --------------------------------------------------------------------------------------
# -s on a seed dialled by name keeps what xapi says about it
# --------------------------------------------------------------------------------------

HOSTS = """uuid ( RO)                : aaaa-1
          name-label ( RW): xcp-a01
            hostname ( RO): xcp-a01
             address ( RO): 192.0.2.60
             enabled ( RO): true
        multipathing ( RW): true


uuid ( RO)                : bbbb-2
          name-label ( RW): xcp-a02
            hostname ( RO): xcp-a02
             address ( RO): 192.0.2.61
             enabled ( RO): false
        multipathing ( RW): true
"""


class AnsweringTransport(object):
    def __init__(self, doc):
        self.doc = doc

    def collect(self, host, spec):
        return self.doc


def test_single_mode_on_a_name_keeps_the_hosts_xapi_values(monkeypatch):
    doc = {"pool_hosts": {"ok": True, "value": HOSTS},
           "pool_conf": {"ok": True, "value": "master"},
           "self_uuid": {"ok": True, "value": "aaaa-1"}}
    run = main.Run()
    run.run_env = "xoa"
    run.seed = NAME
    run.pool_mode = False
    run.transport = AnsweringTransport(doc)
    hosts = main.discover(run)
    narrowed = main._narrow_to_seed(run, hosts)
    assert len(narrowed) == 1
    seed = narrowed[0]
    # reached the way it was dialled...
    assert seed.address == NAME
    # ...with what xapi says about it, rather than Unknown
    assert (seed.uuid, seed.hostname, seed.enabled, seed.multipathing) == \
        ("aaaa-1", "xcp-a01", "true", "true")
    assert run.master_address == MASTER_IP


def test_single_mode_with_no_uuid_to_go_on_is_as_before():
    run = main.Run()
    run.seed = NAME
    narrowed = main._narrow_to_seed(run, [model.Host(MASTER_IP, "aaaa-1", "x", "true", "true")])
    assert narrowed[0].address == NAME
    assert narrowed[0].enabled == "Unknown"
