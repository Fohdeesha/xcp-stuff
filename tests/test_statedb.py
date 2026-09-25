# -*- coding: utf-8 -*-
"""A pool whose toolstack will not answer.

Discovery used to end at 'xe host-list failed' - exit 1, not one host looked at - on
exactly the pools that most need looking at: a master change that fails part way leaves
xapi down or refusing on every member. The host list now comes from the seed's saved
database when xapi will not give it, every host is checked for whatever does not need
xapi, and three lines say what that run could establish: Pool Host List, XAPI Status and
Pool Roles.

The lab can stop xapi on its one single-host 8.3 pool. Everything past that - a slave
whose master is gone, two hosts that both say master, a host left 'broken' by a
designate-new-master that failed in its commit phase - is exercised here and nowhere else.
"""

import io
import time

import pytest

import checks
import collector
import main
import model
import parsers
import report
import result

OK, FLAG, UNKNOWN, INFO = result.OK, result.FLAG, result.UNKNOWN, result.INFO

A_UUID = "11111111-1111-1111-1111-111111111111"
B_UUID = "22222222-2222-2222-2222-222222222222"

# The shape the lab's 8.3.0 and 8.2.1 hosts write (read off all four, 2026-09-25): a
# declaration line, then the whole database on ONE line, the uppercase tables first and
# 'host' among the lowercase ones after them. The VM's name holds the host table's own
# opening tag, escaped as xapi escapes it, to show it cannot be mistaken for the table.
STATE_DB = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<database><manifest><pair key="schema_major_vsn" value="5"/>'
    b'<pair key="generation_count" value="37199835"/></manifest>'
    b'<table name="Bond"/>'
    b'<table name="VM"><row ref="OpaqueRef:v" _ref="OpaqueRef:v" '
    b'uuid="33333333-3333-3333-3333-333333333333" '
    b'name__label="&lt;table name=&quot;host&quot;&gt; &lt;/table&gt;"/></table>'
    b'<table name="host">'
    b'<row ref="OpaqueRef:a" _ref="OpaqueRef:a" uuid="11111111-1111-1111-1111-111111111111" '
    b'name__label="xen-a &amp; co" hostname="xen-a" address="10.0.0.1" enabled="true" '
    b'multipathing="true"/>'
    b'<row ref="OpaqueRef:b" _ref="OpaqueRef:b" uuid="22222222-2222-2222-2222-222222222222" '
    b'name__label="caf\xc3\xa9" hostname="xen-b" address="10.0.0.2" enabled="true" '
    b'multipathing="false"/>'
    b'</table>'
    b'<table name="pool"><row ref="OpaqueRef:p" _ref="OpaqueRef:p" '
    b'uuid="44444444-4444-4444-4444-444444444444" master="OpaqueRef:a"/></table>'
    b'</database>')

ROWS = [
    {"uuid": A_UUID, "name_label": "xen-a & co", "hostname": "xen-a", "address": "10.0.0.1"},
    {"uuid": B_UUID, "name_label": u"caf\xe9", "hostname": "xen-b", "address": "10.0.0.2"},
]

REFUSED = "xe host-list failed (exit 1: Error: Connection refused (calling connect ))"


def fact(value):
    return {"ok": True, "value": value}


def err(reason="could not look"):
    return {"ok": False, "error": reason}


# --------------------------------------------------------------------------------------
# the collector: reading the host table out of the file
# --------------------------------------------------------------------------------------

def test_the_host_table_is_read_out_of_a_whole_database():
    rows, why = collector.parse_state_db_hosts(STATE_DB)
    assert why is None
    # escaped names come back as the names they are, non-ASCII included - the reason the
    # table goes through a real XML parser rather than a regex
    assert rows == ROWS


def test_no_host_table_is_a_reason_not_an_empty_pool():
    rows, why = collector.parse_state_db_hosts(b'<database><table name="VM"/></database>')
    assert rows is None and why == "it has no host table"
    # xapi writes an empty table self-closed; no pool has no hosts, and this is not one
    rows, why = collector.parse_state_db_hosts(b'<database><table name="host"/></database>')
    assert rows is None and why == "it has no host table"


def test_a_host_table_that_never_closes_is_a_reason():
    rows, why = collector.parse_state_db_hosts(b'<database><table name="host"><row uuid="x"/>')
    assert rows is None and "never closes" in why


def test_a_host_table_that_does_not_parse_is_a_reason_not_a_crash():
    rows, why = collector.parse_state_db_hosts(
        b'<table name="host"><row uuid="x" address="10.0.0.1></table>')
    assert rows is None and "does not parse" in why


def test_rows_with_no_uuid_are_not_hosts():
    rows, why = collector.parse_state_db_hosts(
        b'<table name="host"><row address="10.0.0.1"/></table>')
    assert rows is None and "no hosts" in why


def test_collect_state_db_hosts_says_when_the_file_was_written(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    path.write_bytes(STATE_DB)
    monkeypatch.setattr(collector, "STATE_DB", str(path))
    got = collector.collect_state_db_hosts()
    assert got["ok"]
    assert got["value"]["hosts"] == ROWS
    assert got["value"]["path"] == str(path)
    # rendered on the host, in its own clock, the same way Last Booted is
    time.strptime(got["value"]["saved"], "%Y-%m-%d %H:%M:%S")


def test_collect_state_db_hosts_names_the_file_it_could_not_read(tmp_path, monkeypatch):
    missing = str(tmp_path / "nope.db")
    monkeypatch.setattr(collector, "STATE_DB", missing)
    got = collector.collect_state_db_hosts()
    assert not got["ok"] and missing in got["error"]


# --------------------------------------------------------------------------------------
# the collector: when the file is read at all
# --------------------------------------------------------------------------------------

@pytest.fixture
def quiet_identity(monkeypatch):
    monkeypatch.setattr(collector, "collect_identity",
                        lambda: {"self_uuid": collector.fact(A_UUID),
                                 "hostname": collector.fact("h")})
    read = []
    monkeypatch.setattr(collector, "collect_state_db_hosts",
                        lambda: read.append(1) or collector.fact({"hosts": ROWS}))
    return read


def test_the_file_is_not_read_when_xapi_answers(quiet_identity, monkeypatch):
    monkeypatch.setattr(collector, "collect_pool_hosts", lambda: collector.fact("listing"))
    out = collector.collect({"want": ["pool_hosts"]})
    assert out["pool_hosts"] == collector.fact("listing")
    assert "pool_hosts_db" not in out and not quiet_identity


def test_the_file_is_read_when_xapi_does_not_answer(quiet_identity, monkeypatch):
    monkeypatch.setattr(collector, "collect_pool_hosts", lambda: collector.err(REFUSED))
    out = collector.collect({"want": ["pool_hosts"]})
    assert out["pool_hosts"] == collector.err(REFUSED)
    assert out["pool_hosts_db"]["value"]["hosts"] == ROWS


def test_the_run_can_ask_for_the_file_without_asking_xapi(quiet_identity, monkeypatch):
    asked = []
    monkeypatch.setattr(collector, "collect_pool_hosts",
                        lambda: asked.append(1) or collector.fact("listing"))
    out = collector.collect({"want": ["pool_hosts"], "host_list": "statedb"})
    assert not asked
    assert not out["pool_hosts"]["ok"] and "not asked" in out["pool_hosts"]["error"]
    assert out["pool_hosts_db"]["ok"]


# --------------------------------------------------------------------------------------
# the collector: a wedged xapi is asked once
# --------------------------------------------------------------------------------------

class FakeRun(object):
    """Stands in for collector.run: answers each command from `answers` in turn."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, argv, timeout=None):
        self.calls.append((list(argv), timeout))
        return self.answers.pop(0) if self.answers else collector.Ran(0, "", "", False)


@pytest.fixture
def fresh_xapi(monkeypatch):
    monkeypatch.setattr(collector, "XAPI_WEDGED", [""])
    monkeypatch.setattr(collector, "DEADLINE", [None])


def test_after_one_xe_call_times_out_the_rest_are_not_made(fresh_xapi, monkeypatch):
    fake = FakeRun(collector.Ran(124, "", "", True))
    monkeypatch.setattr(collector, "run", fake)
    first = collector.xe(["host-param-get", "uuid=x", "param-name=address"], timeout=20)
    assert first.timed_out
    second = collector.xe(["pif-list", "params=gateway,DNS"])
    assert len(fake.calls) == 1
    assert not second.ok and second.rc is None
    # the reason names what was not answered and how long it was given, and why() hands it
    # over whole rather than dressing it up as an exit status
    assert second.why() == "not asked - xapi did not answer 'xe host-param-get' within 20s"


def test_a_refused_connection_does_not_stop_later_calls(fresh_xapi, monkeypatch):
    """Refused fails in milliseconds, so every fact can keep its own reason."""
    fake = FakeRun(collector.Ran(1, "", "Error: Connection refused", False),
                   collector.Ran(1, "", "Error: Connection refused", False))
    monkeypatch.setattr(collector, "run", fake)
    collector.xe(["host-param-get"])
    collector.xe(["pif-list"])
    assert len(fake.calls) == 2


def test_a_timeout_the_run_budget_imposed_is_not_blamed_on_xapi(fresh_xapi, monkeypatch):
    """Five seconds left of the budget and a 60s call: when it times out, that is the
    budget speaking, and run() already answers every later call with exactly that."""
    monkeypatch.setattr(collector, "DEADLINE", [time.time() + 5])
    fake = FakeRun(collector.Ran(124, "", "", True))
    monkeypatch.setattr(collector, "run", fake)
    collector.xe(["pool-list"], timeout=60)
    assert collector.XAPI_WEDGED == [""]


def test_a_wedged_seed_still_hands_over_its_saved_host_list(fresh_xapi, monkeypatch):
    """The whole chain on the collector side: the identity call is the one that times
    out, host-list is not asked at all, and the file is read instead."""
    monkeypatch.setattr(collector, "inventory_uuid", lambda: A_UUID)
    monkeypatch.setattr(collector, "read_file", lambda path, limit=None: None)
    monkeypatch.setattr(collector, "collect_state_db_hosts",
                        lambda: collector.fact({"hosts": ROWS}))

    def fake(argv, timeout=None):
        if argv[0] == "xe":
            fake.xe += 1
            return collector.Ran(124, "", "", True)
        return collector.Ran(0, "h\n", "", False)
    fake.xe = 0
    monkeypatch.setattr(collector, "run", fake)

    out = collector.collect({"want": ["pool_hosts"]})
    assert fake.xe == 1
    assert out["self_address"] == collector.err(
        "xe host-param-get address failed (timed out)")
    assert out["pool_hosts"] == collector.err(
        "xe host-list failed (not asked - xapi did not answer 'xe host-param-get' within 20s)")
    assert out["pool_hosts_db"]["value"]["hosts"] == ROWS


# --------------------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------------------

def saved_db(rows=None):
    return fact({"path": "/var/lib/xcp/state.db", "saved": "2026-09-25 00:04:12",
                 "hosts": ROWS if rows is None else rows})


def doc(pool_conf="master", self_uuid=A_UUID, listed=None, saved=None, **extra):
    d = {"pool_hosts": listed or err(REFUSED),
         "pool_hosts_db": saved or saved_db(),
         "pool_conf": fact(pool_conf),
         "self_uuid": fact(self_uuid),
         "hostname": fact("xen-a")}
    d.update(extra)
    return d


class FakeTransport(object):
    def __init__(self, payload):
        self.payload = payload
        self.specs = []
        self.local_address = ""

    def collect(self, host, spec):
        self.specs.append(spec)
        return self.payload

    def collect_local(self, spec):
        self.specs.append(spec)
        return self.payload


def discover_with(payload, seed="10.0.0.1", run_env="xoa"):
    run = main.Run()
    run.run_env = run_env
    run.seed = seed
    run.transport = FakeTransport(payload)
    run.hosts = main.discover(run)
    return run


def test_a_refused_host_list_is_read_from_the_seeds_saved_database():
    run = discover_with(doc())
    assert [h.address for h in run.hosts] == ["10.0.0.1", "10.0.0.2"]
    assert run.pool_size == 2
    assert run.state_db["reason"] == REFUSED
    assert run.state_db["saved"] == "2026-09-25 00:04:12"
    assert run.state_db["forced"] is False
    # the master is still named from the seed's pool.conf, as it always was
    assert run.master_address == "10.0.0.1" and run.master_name == "xen-a"


def test_hosts_from_the_file_do_not_claim_live_xapi_state():
    run = discover_with(doc())
    assert all(h.enabled == "Unknown" and h.multipathing == "Unknown" for h in run.hosts)


def test_a_slave_seed_names_its_master_from_the_file_too():
    run = discover_with(doc("slave:10.0.0.1", self_uuid=B_UUID), seed="10.0.0.2")
    assert run.master_address == "10.0.0.1" and run.master_name == "xen-a"


def test_a_master_seed_on_a_second_network_resolves_through_the_file():
    run = discover_with(doc("master"), seed="192.168.50.1")
    assert run.master_address == "10.0.0.1"


def test_xapis_answer_wins_and_the_file_goes_unmentioned():
    listing = ("uuid ( RO)           : %s\n     address ( RO): 10.0.0.1\n"
               "     enabled ( RO): true\n" % A_UUID)
    run = discover_with(doc(listed=fact(listing)))
    assert [h.address for h in run.hosts] == ["10.0.0.1"]
    assert run.state_db is None
    assert run.hosts[0].enabled == "true"


def test_neither_xapi_nor_the_file_is_still_an_error_naming_both(capsys):
    with pytest.raises(SystemExit) as exc:
        discover_with(doc(saved=err("could not read /var/lib/xcp/state.db (Permission denied)")))
    assert exc.value.code == 1
    text = capsys.readouterr().err
    assert REFUSED in text and "Permission denied" in text


def test_the_knob_asks_the_collector_for_the_file_and_is_recorded(monkeypatch):
    monkeypatch.setenv("HEALTH_HOST_LIST", "statedb")
    listing = "uuid ( RO): %s\n address ( RO): 10.0.0.9\n" % A_UUID
    # even with an answer from xapi in hand, the file is what was asked for
    run = discover_with(doc(listed=fact(listing)))
    assert run.transport.specs[0]["host_list"] == "statedb"
    assert run.state_db["forced"] is True
    assert [h.address for h in run.hosts] == ["10.0.0.1", "10.0.0.2"]


def test_an_unknown_knob_value_is_a_warning_not_a_silent_choice(monkeypatch, capsys):
    monkeypatch.setenv("HEALTH_HOST_LIST", "db")
    run = discover_with(doc())
    assert "host_list" not in run.transport.specs[0]
    assert "ignoring HEALTH_HOST_LIST=db" in capsys.readouterr().err


def test_host_mode_finds_its_own_address_in_the_file(capsys):
    """xe host-param-get cannot answer on a host whose xapi is down, and host mode used
    to exit on that; its own row, found by INSTALLATION_UUID, says the same thing."""
    payload = doc("slave:10.0.0.1", self_uuid=B_UUID,
                  self_address=err("xe host-param-get address failed (exit 1: refused)"),
                  hostname=fact("xen-b"))
    run = discover_with(payload, seed="", run_env="host")
    assert run.seed == "10.0.0.2"
    assert run.transport.local_address == "10.0.0.2"
    assert run.master_address == "10.0.0.1"
    assert "xen-b (10.0.0.2)" in capsys.readouterr().out


def test_host_mode_not_in_its_own_file_is_still_an_error(capsys):
    payload = doc(self_uuid="99999999-9999-9999-9999-999999999999",
                  self_address=err("xe host-param-get address failed (exit 1: refused)"))
    with pytest.raises(SystemExit):
        discover_with(payload, seed="", run_env="host")
    assert "refused" in capsys.readouterr().err


# --------------------------------------------------------------------------------------
# XAPI Status
# --------------------------------------------------------------------------------------

def xhost(**facts):
    h = model.Host("10.0.0.1", A_UUID, "xen-a")
    h.payload = dict(facts)
    return h


def test_xapi_status_responding():
    line = checks.xapi_status(xhost(self_uuid=fact(A_UUID), self_address=fact("10.0.0.1")))
    assert line.status == OK and "Responding" in line.text


def test_xapi_status_not_responding_says_what_xe_said():
    line = checks.xapi_status(xhost(self_uuid=fact(A_UUID), self_address=err(
        "xe host-param-get address failed (exit 1: Error: Connection refused)")))
    assert line.status == FLAG
    assert "Connection refused" in line.text


def test_xapi_status_is_never_green_when_xapi_was_not_asked():
    for payload in ({}, {"self_uuid": err("no INSTALLATION_UUID in /etc/xensource-inventory"),
                         "self_address": err("host uuid unknown")}):
        line = checks.xapi_status(xhost(**payload))
        assert line.status == UNKNOWN and line.flags


def test_xapi_status_of_a_host_never_collected_is_unknown():
    assert checks.xapi_status(model.Host("10.0.0.1")).status == UNKNOWN


# --------------------------------------------------------------------------------------
# Pool Host List
# --------------------------------------------------------------------------------------

STATE = {"forced": False, "reason": REFUSED, "path": "/var/lib/xcp/state.db",
         "saved": "2026-09-25 00:04:12"}


def test_a_list_read_from_the_file_is_unknown_and_says_why_and_how_old():
    line = checks.pool_host_list(STATE, "10.0.0.4", 3)
    assert line.status == UNKNOWN and line.flags
    assert "xapi on 10.0.0.4 did not answer" in line.text and "3 host(s)" in line.text
    assert REFUSED in line.detail_text and "2026-09-25 00:04:12" in line.detail_text


def test_a_list_read_from_the_file_on_request_is_a_warning_not_a_finding():
    line = checks.pool_host_list(dict(STATE, forced=True), "10.0.0.1", 2)
    assert line.status == INFO and not line.flags
    assert line.always_print, "a yellow warning survives -f"
    assert "HEALTH_HOST_LIST=statedb" in line.text


# --------------------------------------------------------------------------------------
# Pool Roles
# --------------------------------------------------------------------------------------

def member(address, name, pool_conf=None, reachable=True, conf_error=None):
    h = model.Host(address, "uuid-" + address, name)
    if reachable:
        h.payload = {"hostname": fact(name)}
        if conf_error is not None:
            h.payload["pool_conf"] = err(conf_error)
        elif pool_conf is not None:
            h.payload["pool_conf"] = fact(pool_conf)
    return h


def roles(*hosts):
    return checks.pool_roles(list(hosts))


def test_a_healthy_pool_is_consistent():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.1"),
                 member("10.0.0.3", "xen-c", "slave:10.0.0.1"))
    assert line.status == OK and "Consistent" in line.text


def test_a_single_host_that_says_master_is_consistent():
    assert roles(member("10.0.0.1", "xen-a", "master")).status == OK


def test_a_pool_conf_naming_the_master_by_name_is_consistent():
    """xapi writes an IP here itself (pool-join resolves the address first), but a
    hand-edited file may carry the master's name - which is the master, not a stranger."""
    assert roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:xen-a")).status == OK
    assert roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:XEN-A.lab.example")).status == OK


def test_two_masters_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "master"))
    assert line.status == FLAG
    assert "2 hosts say master (xen-a, xen-b)" in line.text


def test_a_broken_host_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "broken"))
    assert line.status == FLAG and "xen-b says broken" in line.text


def test_a_role_xapi_would_not_recognise_is_a_finding():
    for conf, shown in (("slave:", "'slave:'"), ("", "'(empty)'"), ("mastr", "'mastr'")):
        line = roles(member("10.0.0.1", "xen-a", "master"),
                     member("10.0.0.2", "xen-b", conf))
        assert line.status == FLAG, conf
        assert shown in line.text and "reads as broken" in line.text


def test_a_slave_pointing_at_another_slave_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.3"),
                 member("10.0.0.3", "xen-c", "slave:10.0.0.1"))
    assert line.status == FLAG
    assert "xen-b points at xen-c, which says slave:10.0.0.1" in line.detail_text


def test_a_slave_pointing_at_itself_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.2"))
    assert line.status == FLAG and "xen-b points at itself" in line.text


def test_a_slave_pointing_past_the_master_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:10.9.9.9"))
    assert line.status == FLAG
    assert "xen-b points at 10.9.9.9, not at xen-a" in line.text


def test_no_master_anywhere_is_a_finding_when_every_host_was_read():
    line = roles(member("10.0.0.1", "xen-a", "slave:10.9.9.9"),
                 member("10.0.0.2", "xen-b", "slave:10.9.9.9"))
    assert line.status == FLAG and "no host says master" in line.text


def test_the_failed_master_change_this_was_built_for():
    """designate-new-master, broken in its commit phase: the new master wrote 'broken'
    and kept it, the old master had already pointed itself at the new one, and the host
    the commit never reached still points at the old one. xapi is down on all three, and
    this is the only line in the report that can say what state they are in."""
    line = roles(member("10.0.0.1", "old-master", "slave:10.0.0.2"),
                 member("10.0.0.2", "new-master", "broken"),
                 member("10.0.0.3", "xen-c", "slave:10.0.0.1"))
    assert line.status == FLAG
    assert result.colors.strip_ansi(line.text).startswith(
        "Mismatch - new-master says broken; and 4 more")
    for said in ("old-master points at new-master, which says broken",
                 "xen-c points at old-master, which says slave:10.0.0.2",
                 "the slaves point at different masters (10.0.0.1, 10.0.0.2)",
                 "no host says master"):
        assert said in line.detail_text, said
    # every host's pool.conf, verbatim, because -f drops the block that usually shows it
    for label, conf in (("old-master (10.0.0.1)", "slave:10.0.0.2"),
                        ("new-master (10.0.0.2)", "broken"),
                        ("xen-c (10.0.0.3)", "slave:10.0.0.1")):
        assert any(row.startswith(label) and row.endswith(conf)
                   for row in line.detail_text.splitlines()), label


def test_slaves_split_between_masters_nobody_reached_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", reachable=False),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.1"),
                 member("10.0.0.3", "xen-c", "slave:10.0.0.4"),
                 member("10.0.0.4", "xen-d", reachable=False))
    assert line.status == FLAG
    assert "the slaves point at different masters (10.0.0.1, 10.0.0.4)" in line.text


def test_slaves_agreeing_on_a_master_that_was_not_reached_is_unknown():
    """Agreement is all that was established; the master's own file was never seen."""
    line = roles(member("10.0.0.1", "xen-a", reachable=False),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.1"),
                 member("10.0.0.3", "xen-c", "slave:10.0.0.1"))
    assert line.status == UNKNOWN
    assert "no reachable host says master; the slaves point at 10.0.0.1" in line.text
    assert "(not reached)" in line.detail_text


def test_an_unreachable_slave_leaves_the_rest_consistent_and_says_how_many():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.1"),
                 member("10.0.0.3", "xen-c", reachable=False))
    assert line.status == OK
    assert "Consistent (2 of 3 hosts reached)" in line.text


def test_an_unreadable_pool_conf_is_unknown_never_green():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", conf_error="could not read /etc/xensource/pool.conf"))
    assert line.status == UNKNOWN
    assert "could not be read on xen-b" in line.text
    assert "(could not be read: could not read /etc/xensource/pool.conf)" in line.detail_text


def test_a_definite_finding_is_not_hidden_behind_an_unreadable_host():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", conf_error="could not read"),
                 member("10.0.0.3", "xen-c", "master"))
    assert line.status == FLAG


def test_pool_roles_with_nothing_reached_is_unknown():
    line = roles(member("10.0.0.1", "xen-a", reachable=False))
    assert line.status == UNKNOWN


def test_pool_roles_never_green_off_a_missing_or_failed_fact():
    """The house rule, enumerated: take a consistent pool and knock out the one fact
    the line is built from, on each host in turn."""
    for broken in range(2):
        hosts = [member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:10.0.0.1")]
        del hosts[broken].payload["pool_conf"]
        assert checks.pool_roles(hosts).status != OK
        hosts[broken].payload["pool_conf"] = err()
        assert checks.pool_roles(hosts).status != OK


# --------------------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------------------

def test_broken_is_a_role():
    assert parsers.parse_pool_conf("broken\n") == ("broken", None)


def test_state_db_rows_take_the_host_list_shape_with_live_state_unknown():
    assert parsers.host_records_from_state_db(ROWS + [{"uuid": ""}]) == [
        {"uuid": A_UUID, "name_label": "xen-a & co", "hostname": "xen-a",
         "address": "10.0.0.1", "enabled": "Unknown", "multipathing": "Unknown"},
        {"uuid": B_UUID, "name_label": u"caf\xe9", "hostname": "xen-b",
         "address": "10.0.0.2", "enabled": "Unknown", "multipathing": "Unknown"},
    ]


# --------------------------------------------------------------------------------------
# the section, rendered
# --------------------------------------------------------------------------------------

def broken_pool_run(state_db=STATE):
    run = main.Run()
    run.run_env = "xoa"
    run.seed = "10.0.0.1"
    run.state_db = state_db
    run.master_address = "10.0.0.1"
    run.master_name = "xen-a"
    run.hosts = [member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "broken")]
    run.pool_size = 2
    run.pool_cmd_host = "10.0.0.1"
    return run


def test_pool_status_says_where_the_hosts_came_from_and_what_they_think():
    out = io.StringIO()
    rep = report.Report(stream=out)
    main.pool_status_section(broken_pool_run(), rep)
    text = result.colors.strip_ansi(out.getvalue())
    lines = text.splitlines()
    assert lines[1] == "Pool Master: xen-a (10.0.0.1)"
    assert lines[2].startswith("Pool Host List: Unknown - xapi on 10.0.0.1 did not answer, "
                               "so 2 host(s) were read from its saved database")
    assert lines[3] == "Unreachable Hosts: None"
    assert lines[4].startswith("Pool Roles: Mismatch - xen-b says broken")
    assert rep.flagged


def test_pool_status_on_a_healthy_pool_has_no_host_list_line():
    run = broken_pool_run(state_db=None)
    run.hosts[1].payload["pool_conf"] = fact("slave:10.0.0.1")
    out = io.StringIO()
    main.pool_status_section(run, report.Report(stream=out))
    text = result.colors.strip_ansi(out.getvalue())
    assert "Pool Host List" not in text
    assert "Pool Roles: Consistent" in text


def test_the_json_document_carries_both_lines_in_the_pool_section():
    out = io.StringIO()
    rep = report.Report(stream=out, json_mode=True)
    main.pool_status_section(broken_pool_run(), rep)
    keys = dict((c["key"], c) for c in rep.document()["pool"]["checks"])
    assert keys["Pool Host List"]["status"] == UNKNOWN and keys["Pool Host List"]["flags"]
    assert keys["Pool Roles"]["status"] == FLAG
    assert "xen-b (10.0.0.2)  broken" in keys["Pool Roles"]["detail"]["text"]
