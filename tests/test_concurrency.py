# -*- coding: utf-8 -*-
"""Hosts are gathered several at a time, and nothing about the report may depend on it.

The whole value of the collect-then-render split is that the gathering order stops being
observable. These tests hold it to that: the same payloads land on the same hosts, the
stderr notes come out in host order however the hosts finished, and the concurrency is
real rather than a pool that quietly runs one at a time.
"""

import threading
import time

import pytest

import main
import model
import transport


class FakeTransport(object):
    """Stands in for the real one: records what it was asked, answers what it was told."""

    def __init__(self, behaviour):
        self.behaviour = behaviour       # address -> callable(address) -> payload
        self.seen = []
        self.lock = threading.Lock()

    def collect(self, address, spec):
        with self.lock:
            self.seen.append((address, tuple(spec.get("want", ()))))
        return self.behaviour[address](address)


def make_run(addresses, behaviour, pool_cmd_host=None):
    run = main.Run()
    run.run_env = "xoa"
    run.pool_mode = True
    run.hosts = [model.Host(addr) for addr in addresses]
    run.all_addresses = list(addresses)
    run.hosts[0].is_master = True
    run.pool_cmd_host = pool_cmd_host if pool_cmd_host is not None else addresses[0]
    run.transport = FakeTransport(behaviour)
    return run


def payload_for(address):
    return {"hostname": {"ok": True, "value": "h-" + address.replace(".", "-")},
            "pool": {"pool_uuid": {"ok": True, "value": "u"}},
            "yum_check": {"ok": True, "value": 0}}


# --------------------------------------------------------------------------------------
# the worker count
# --------------------------------------------------------------------------------------

def test_worker_count_never_exceeds_the_hosts_or_the_cap(monkeypatch):
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    monkeypatch.setattr(main.config, "MAX_PARALLEL_HOSTS", 8)
    assert main.parallel_workers(1) == 1
    assert main.parallel_workers(3) == 3
    assert main.parallel_workers(40) == 8      # a big pool is capped, not unleashed


def test_worker_count_honours_the_override(monkeypatch):
    monkeypatch.setattr(main.config, "MAX_PARALLEL_HOSTS", 8)
    monkeypatch.setenv("HEALTH_MAX_PARALLEL", "2")
    assert main.parallel_workers(40) == 2
    # =1 is the documented way back to strictly sequential collection, which is what the
    # concurrent path is diffed against
    monkeypatch.setenv("HEALTH_MAX_PARALLEL", "1")
    assert main.parallel_workers(40) == 1
    # an override above the cap is the user's call; the cap is a default, not a ceiling
    monkeypatch.setenv("HEALTH_MAX_PARALLEL", "20")
    assert main.parallel_workers(40) == 20


def test_nonsense_overrides_fall_back_to_the_cap(monkeypatch):
    monkeypatch.setattr(main.config, "MAX_PARALLEL_HOSTS", 8)
    for value in ("", "0", "-4", "lots", "3.5", " 2"):
        monkeypatch.setenv("HEALTH_MAX_PARALLEL", value)
        assert main.parallel_workers(40) == 8, value


def test_zero_hosts_still_asks_for_a_valid_pool_size(monkeypatch):
    # ThreadPoolExecutor rejects max_workers=0, and an empty host list is reachable
    # through -s against an address xapi does not know
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    assert main.parallel_workers(0) == 1


# --------------------------------------------------------------------------------------
# it is actually concurrent
# --------------------------------------------------------------------------------------

def test_hosts_really_are_collected_at_the_same_time(monkeypatch):
    """Each host waits for the other two before answering.

    If the pool ran them one at a time this deadlocks, the barrier times out and every
    collect raises - so a silently-serial implementation cannot pass by being fast.
    """
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    barrier = threading.Barrier(len(addresses), timeout=15)

    def rendezvous(address):
        barrier.wait()
        return payload_for(address)

    run = make_run(addresses, {a: rendezvous for a in addresses})
    main.collect_hosts(run)
    assert [h.reachable for h in run.hosts] == [True, True, True]


# --------------------------------------------------------------------------------------
# ...and nothing observable depends on that
# --------------------------------------------------------------------------------------

def test_payloads_land_on_the_right_hosts_however_they_finish(monkeypatch, capsys):
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    delays = {"10.0.0.1": 0.30, "10.0.0.2": 0.15, "10.0.0.3": 0.0}
    done = []
    lock = threading.Lock()

    def behave(address):
        # all three start together, so the delays decide the finishing order - the exact
        # reverse of the order the report will print them in
        time.sleep(delays[address])
        with lock:
            done.append(address)
        if address == "10.0.0.2":
            raise transport.CollectError("nope: %s" % address)
        return payload_for(address)

    run = make_run(addresses, {a: behave for a in addresses})
    main.collect_hosts(run)

    # the fake made them finish in the reverse of the report order, which is the point
    assert done == ["10.0.0.3", "10.0.0.2", "10.0.0.1"]
    assert run.hosts[0].name == "h-10-0-0-1"
    assert run.hosts[2].name == "h-10-0-0-3"
    # ...and the one that failed is the one that failed
    assert run.hosts[1].payload is None
    assert "nope: 10.0.0.2" in run.hosts[1].error
    assert run.hosts[0].error is None


def test_failure_notes_come_out_in_host_order_not_finishing_order(monkeypatch, capsys):
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def behave(address):
        # .3 fails immediately, .1 fails last: printed as they land, the order would be
        # the other way round and would differ between runs
        if address == "10.0.0.1":
            time.sleep(0.25)
        if address in ("10.0.0.1", "10.0.0.3"):
            raise transport.CollectError("down")
        return payload_for(address)

    run = make_run(addresses, {a: behave for a in addresses})
    main.collect_hosts(run)
    err = capsys.readouterr().err
    assert err == ("Failed when trying to check 10.0.0.1: down\n"
                   "Failed when trying to check 10.0.0.3: down\n")


def test_each_host_gets_its_own_reference_clock(monkeypatch):
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    addresses = ["10.0.0.1", "10.0.0.2"]

    def behave(address):
        time.sleep(0.2 if address == "10.0.0.1" else 0.0)
        return payload_for(address)

    run = make_run(addresses, {a: behave for a in addresses})
    main.collect_hosts(run)
    # taken when THAT host's document arrived, so the slow host's is the later one -
    # a single shared stamp would make the drift figures wrong by the collection time
    assert run.hosts[0].local_now > run.hosts[1].local_now


def test_only_the_pool_cmd_host_is_asked_the_pool_questions(monkeypatch):
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    run = make_run(addresses, {a: payload_for for a in addresses},
                   pool_cmd_host="10.0.0.2")
    main.collect_hosts(run)
    asked = dict(run.transport.seen)
    assert asked["10.0.0.1"] == ("host",)
    assert asked["10.0.0.2"] == ("host", "pool", "yumcheck")
    assert asked["10.0.0.3"] == ("host",)


def test_the_cap_actually_caps_and_the_rest_queue(monkeypatch):
    """More hosts than workers: every host is still collected, and never more than the
    cap at once. The cap is the whole reason a forty-host pool does not open forty ssh
    connections, so 'it finished' is not on its own evidence that it held."""
    monkeypatch.setenv("HEALTH_MAX_PARALLEL", "2")
    addresses = ["10.0.0.%d" % i for i in range(1, 7)]
    live = [0]
    peak = [0]
    lock = threading.Lock()

    def behave(address):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.05)
        with lock:
            live[0] -= 1
        return payload_for(address)

    run = make_run(addresses, {a: behave for a in addresses})
    main.collect_hosts(run)
    assert [h.reachable for h in run.hosts] == [True] * 6
    assert peak[0] == 2, "peak concurrency was %d, cap was 2" % peak[0]


def test_serial_and_concurrent_reach_the_same_state(monkeypatch):
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    seen = {}
    for workers in ("1", "4"):
        monkeypatch.setenv("HEALTH_MAX_PARALLEL", workers)
        run = make_run(addresses, {a: payload_for for a in addresses})
        main.collect_hosts(run)
        seen[workers] = [(h.address, h.name, h.error) for h in run.hosts]
        assert run.pool.payload["pool_uuid"] == {"ok": True, "value": "u"}
    assert seen["1"] == seen["4"]


# --------------------------------------------------------------------------------------
# interruption
# --------------------------------------------------------------------------------------

def test_an_interrupted_run_kills_the_children_it_left_behind(monkeypatch):
    """The workers are blocked in communicate() and never see the ctrl-C themselves.

    Without the kill, shutdown(wait=True) sits until the last collector finishes on its
    own - up to REMOTE_CMD_TIMEOUT, which is five minutes.
    """
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    killed = []
    monkeypatch.setattr(transport, "kill_all_children", lambda: killed.append(True))

    addresses = ["10.0.0.1", "10.0.0.2"]

    def behave(address):
        if address == "10.0.0.1":
            raise KeyboardInterrupt()
        return payload_for(address)

    run = make_run(addresses, {a: behave for a in addresses})
    with pytest.raises(KeyboardInterrupt):
        main.collect_hosts(run)
    assert killed == [True]


def test_an_unexpected_exception_still_stops_the_run(monkeypatch):
    """A CollectError is a host that could not be reached; anything else is a bug in us,
    and it must not be quietly turned into an unreachable host."""
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    monkeypatch.setattr(transport, "kill_all_children", lambda: None)
    addresses = ["10.0.0.1", "10.0.0.2"]

    def behave(address):
        if address == "10.0.0.2":
            raise ValueError("boom")
        return payload_for(address)

    run = make_run(addresses, {a: behave for a in addresses})
    with pytest.raises(ValueError):
        main.collect_hosts(run)
