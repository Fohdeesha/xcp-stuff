# -*- coding: utf-8 -*-
"""Who discover() decides the pool master is.

pool.conf on a master is the single word 'master' - it carries no address - so the seed
has to stand in for one. The seed is whatever was dialled, and on a master with a second
network that is not necessarily the address xapi publishes in host-list. Everything
downstream compares against the published address (host.is_master, master_name,
pool_cmd_host, host_by_address), so a seed on a secondary network used to leave
is_master False on every host in the pool and the master unnameable.
"""

import pytest

import main
import model
import transport


MASTER_UUID = "11111111-1111-1111-1111-111111111111"
SLAVE_UUID = "22222222-2222-2222-2222-222222222222"

HOST_LIST = """uuid ( RO)                : %s
          name-label ( RW): master-box
            hostname ( RO): master-box
             address ( RO): 10.0.0.1
             enabled ( RO): true
        multipathing ( RW): true


uuid ( RO)                : %s
          name-label ( RW): slave-box
            hostname ( RO): slave-box
             address ( RO): 10.0.0.2
             enabled ( RO): true
        multipathing ( RW): true
""" % (MASTER_UUID, SLAVE_UUID)


def payload(pool_conf, self_uuid=MASTER_UUID, host_list=HOST_LIST):
    doc = {"pool_hosts": {"ok": True, "value": host_list},
           "pool_conf": {"ok": True, "value": pool_conf}}
    if self_uuid is None:
        doc["self_uuid"] = {"ok": False, "error": "no INSTALLATION_UUID"}
    else:
        doc["self_uuid"] = {"ok": True, "value": self_uuid}
    return doc


class FakeTransport(object):
    def __init__(self, doc):
        self.doc = doc

    def collect(self, host, spec):
        return self.doc

    def collect_local(self, spec):
        return self.doc


def discover_with(doc, seed, run_env="xoa"):
    run = main.Run()
    run.run_env = run_env
    run.seed = seed
    run.transport = FakeTransport(doc)
    hosts = main.discover(run)
    run.hosts = hosts
    return run, hosts


# --------------------------------------------------------------------------------------
# seeded on the master
# --------------------------------------------------------------------------------------

def test_master_seeded_on_management_address():
    run, _ = discover_with(payload("master"), "10.0.0.1")
    assert run.master_address == "10.0.0.1"
    assert run.master_name == "master-box"


def test_master_seeded_on_secondary_address_resolves_to_published_one():
    """The regression: dialled on a second network, xapi still calls the master 10.0.0.1."""
    run, _ = discover_with(payload("master"), "192.168.50.1")
    assert run.master_address == "10.0.0.1"
    assert run.master_name == "master-box"


def test_secondary_seed_leaves_a_master_among_the_hosts():
    """What actually broke: is_master is set by comparing against host.address."""
    run, hosts = discover_with(payload("master"), "192.168.50.1")
    assert run.host_by_address(run.master_address) is not None
    assert [h.address for h in hosts if h.address == run.master_address] == ["10.0.0.1"]


def test_master_falls_back_to_seed_when_self_uuid_is_unavailable():
    run, _ = discover_with(payload("master", self_uuid=None), "192.168.50.1")
    assert run.master_address == "192.168.50.1"


def test_master_falls_back_to_seed_when_uuid_matches_no_host():
    """A uuid absent from host-list must not blank the address out."""
    run, _ = discover_with(payload("master", self_uuid=SLAVE_UUID[:-1] + "9"),
                           "192.168.50.1")
    assert run.master_address == "192.168.50.1"


# --------------------------------------------------------------------------------------
# seeded on a slave, and the no-role case
# --------------------------------------------------------------------------------------

def test_slave_takes_the_address_pool_conf_names():
    doc = payload("slave:10.0.0.1", self_uuid=SLAVE_UUID)
    run, _ = discover_with(doc, "10.0.0.2")
    assert run.master_address == "10.0.0.1"
    assert run.master_name == "master-box"


def test_slave_seed_is_never_mistaken_for_the_master():
    """The self_uuid lookup is confined to the master branch."""
    doc = payload("slave:10.0.0.1", self_uuid=SLAVE_UUID)
    run, _ = discover_with(doc, "192.168.50.2")
    assert run.master_address == "10.0.0.1"


def test_unreadable_pool_conf_leaves_the_master_unset():
    doc = payload("")
    doc["pool_conf"] = {"ok": False, "error": "could not read /etc/xensource/pool.conf"}
    run, _ = discover_with(doc, "10.0.0.1")
    assert run.master_address == ""
    assert run.master_name == ""
