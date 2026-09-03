# -*- coding: utf-8 -*-
"""Host mode never reads the xo-db, and therefore never reaches the redis fast path.

This is true today by code path alone: xodb is called only from resolve_target_xoa, and a
hypervisor has no xo-server-db on PATH for xoredis to find anyway. Nothing failed if that
stopped being true, which is the gap these tests close - a health check running ON a
hypervisor has no business opening a socket to look for an appliance's credential store,
and the day someone moves a db lookup up into the shared part of main() the only symptom
would be a stray connection attempt on a dom0.

Three levels are wired to trip, because a regression could enter at any of them:
the xodb entry point, the redis reader under it, and the CLI under that.
"""

import io
import sys

import pytest

import main
import transport
import xoa
import xodb
import xoredis


class Tripped(Exception):
    """Raised by whichever level was reached, naming it."""


class ReachedDiscover(Exception):
    """The run got all the way through target resolution without tripping anything."""


@pytest.fixture(autouse=True)
def fresh_cache():
    xodb.reset_cache()
    yield
    xodb.reset_cache()


@pytest.fixture
def tripwires(monkeypatch):
    """Every route to the credential db, rigged to raise instead of answer."""
    def trip(name):
        def stand_in(*args, **kwargs):
            raise Tripped(name)
        return stand_in

    monkeypatch.setattr(xodb, "all_servers", trip("xodb.all_servers"))
    monkeypatch.setattr(xoredis, "read_server_records", trip("xoredis.read_server_records"))
    monkeypatch.setattr(transport, "run_local_cmd", trip("transport.run_local_cmd"))
    # a dom0 has none of these; if some future PATH does, the fast path must still not run
    monkeypatch.setattr(transport, "which", lambda binary: "/usr/local/bin/" + binary)


def drive(monkeypatch, tmp_path, argv, run_env):
    """main() with everything past target resolution refusing to run.

    discover() is the first thing after the environment-specific resolve step, so reaching
    it means the whole of that step ran. Returns what stopped the run.
    """
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.setattr(main, "detect_run_env", lambda: run_env)
    monkeypatch.setattr(xoa, "debian_version_ok", lambda: (True, "12"))
    monkeypatch.setattr(xoa, "running_as_root", lambda: True)
    monkeypatch.setattr(transport, "make_work_dir", lambda: str(tmp_path))
    monkeypatch.setattr(transport, "cleanup_work_dir", lambda path: None)
    monkeypatch.setattr(xoa, "lines", lambda *a, **k: [])
    monkeypatch.setattr(main, "discover", lambda run: (_ for _ in ()).throw(ReachedDiscover()))
    try:
        main.main(list(argv))
    except (Tripped, ReachedDiscover, SystemExit) as exc:
        return exc
    return None


@pytest.mark.parametrize("argv", [
    [],                       # solo: this host, no password
    ["hunter2"],              # sweep: the other members, password on the command line
    ["-f"],
    ["-s"],
    ["--json"],
    ["-f", "--json", "hunter2"],
])
def test_a_host_mode_run_never_reads_the_db(monkeypatch, tmp_path, tripwires, argv):
    stopped = drive(monkeypatch, tmp_path, argv, "host")
    assert isinstance(stopped, ReachedDiscover), (
        "host mode reached the credential db: %r" % (stopped,))


def test_the_tripwires_actually_work(monkeypatch, tmp_path, tripwires):
    """The control. Without it the tests above would pass just as happily against a
    tripwire that never fires, which is the way this kind of test rots."""
    stopped = drive(monkeypatch, tmp_path, [], "xoa")
    assert isinstance(stopped, Tripped), (
        "an XOA run with no host argument must consult the db; got %r" % (stopped,))
    assert str(stopped) == "xodb.all_servers"


def test_prepare_host_sweep_never_reads_the_db(monkeypatch, tripwires):
    """The one host-mode step that happens AFTER discover, so `drive` cannot cover it.

    It is where a password would be wanted, which makes it the likeliest place for someone
    to reach for a lookup that only exists on an appliance.
    """
    monkeypatch.setattr(transport, "ensure_sshpass", lambda run_env: True)
    for pool_size, password in ((1, ""), (1, "pw"), (3, ""), (3, "pw")):
        run = main.Run()
        run.run_env = "host"
        run.pool_mode = True
        run.pool_size = pool_size
        run.transport = transport.Transport("host", "/tmp")
        # no tty, so the getpass branch is not taken and nothing blocks
        monkeypatch.setattr(sys, "stdin", io.StringIO())
        main.prepare_host_sweep(run, password)


def test_a_dom0_has_no_xo_server_db_so_the_fast_path_cannot_start(monkeypatch):
    """The second, independent reason: xoredis needs the CLI's real location to find
    xo-server's config dir, and a hypervisor has no xo-server. Measured on .13/.34/.16 -
    transport.which('xo-server-db') is '' there - and pinned here so the code keeps
    treating that as 'do not even try' rather than falling through to a default endpoint.
    """
    monkeypatch.setattr(transport, "which", lambda binary: "")
    called = []
    monkeypatch.setattr(xoredis, "read_server_records",
                        lambda *a, **k: called.append(a) or [])
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda *a, **k: (127, "", "xo-server-db: not found"))
    assert xodb.all_servers() == []
    assert called == [], "the fast path ran with no xo-server-db to locate a config from"
