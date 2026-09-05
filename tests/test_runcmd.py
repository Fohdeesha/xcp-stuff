# -*- coding: utf-8 -*-
"""-c/--command: one arbitrary command on every host, instead of the health report.

The feature is a raw diagnostic dump, and these hold it to the three things that makes
it: it prints in host order however the hosts finish, it reaches no verdict (so it never
touches the exit code), and it never collects a health fact - a one-line command must not
cost a full sweep.
"""

import threading
import time

import pytest

import colors
import config
import main
import model
import transport


class FakeTransport(object):
    """Records what it was asked, answers what it was told. Mirrors the real signature."""

    def __init__(self, behaviour):
        self.behaviour = behaviour     # address -> callable(address) -> (rc, out, err)
        self.seen = []
        self.collected = []            # any collector call at all is a bug in -c mode
        self.lock = threading.Lock()

    def run_command(self, address, cmd, timeout=None):
        with self.lock:
            self.seen.append((address, cmd))
        return self.behaviour[address](address)

    def collect(self, address, spec):
        with self.lock:
            self.collected.append((address, tuple(spec.get("want", ()))))
        raise AssertionError("-c must not collect health facts")


def make_run(addresses, behaviour, cmd="echo hi"):
    run = main.Run()
    run.run_env = "xoa"
    run.pool_mode = True
    run.run_cmd = cmd
    run.hosts = [model.Host(addr) for addr in addresses]
    run.all_addresses = list(addresses)
    run.transport = FakeTransport(behaviour)
    return run


def ok(out):
    return lambda address: (0, out, "")


@pytest.fixture(autouse=True)
def _no_colour():
    """Assert on text, not escape codes; the colouring itself is colors' own business."""
    colors.init(force_off=True)


# --------------------------------------------------------------------------------------
# argument handling
# --------------------------------------------------------------------------------------

def test_short_and_long_forms_both_land():
    for argv in (["-c", "uptime"], ["--command", "uptime"], ["--command=uptime"]):
        run = main.Run()
        run.parse_args(argv)
        assert run.run_cmd == "uptime", argv


def test_the_command_is_taken_whole():
    """A command with pipes, quotes and spaces is one argv element and must survive as
    typed - it is the point of the feature, and the shell on the far side is what reads
    it."""
    run = main.Run()
    run.parse_args(["-c", "ps aux | grep 'xapi' | wc -l"])
    assert run.run_cmd == "ps aux | grep 'xapi' | wc -l"


def test_c_composes_with_the_other_flags():
    run = main.Run()
    args = run.parse_args(["-f", "-s", "-c", "uptime", "10.0.0.5"])
    assert run.run_cmd == "uptime"
    assert run.pool_mode is False        # -s still narrows the host list
    assert args == ["10.0.0.5"]


def test_json_with_c_is_refused_as_a_usage_error(capsys):
    """--json's document is a health check's shape and -c reaches no verdict, so the two
    cannot be combined. Exit 2, not 1: a cron wrapper has to tell a typo from a sick pool.
    """
    run = main.Run()
    with pytest.raises(SystemExit) as exc:
        run.parse_args(["--json", "-c", "uptime"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--json" in err and "-c/--command" in err


# --------------------------------------------------------------------------------------
# what it prints
# --------------------------------------------------------------------------------------

def test_each_host_is_labelled_by_address_and_its_output_printed(capsys):
    run = make_run(["10.0.0.1", "10.0.0.2"],
                   {"10.0.0.1": ok("nameserver 1.1.1.1\n"),
                    "10.0.0.2": ok("nameserver 8.8.8.8\n")})
    rc = main.run_command_on_all_hosts(run)
    out = capsys.readouterr().out
    assert rc == 0
    assert "== 10.0.0.1 ==" in out and "== 10.0.0.2 ==" in out
    assert "nameserver 1.1.1.1" in out and "nameserver 8.8.8.8" in out
    # the command really did reach every host, and it is the one that was asked for
    assert sorted(run.transport.seen) == [("10.0.0.1", "echo hi"), ("10.0.0.2", "echo hi")]


def test_output_is_printed_in_host_order_however_the_hosts_finish(capsys):
    """The whole value of collecting concurrently is that the order stops being
    observable. -c is held to it too."""
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    delays = {"10.0.0.1": 0.30, "10.0.0.2": 0.15, "10.0.0.3": 0.0}

    def behave(address):
        time.sleep(delays[address])       # finishing order is the reverse of host order
        return (0, "out-" + address, "")

    run = make_run(addresses, dict((a, behave) for a in addresses))
    main.run_command_on_all_hosts(run)
    out = capsys.readouterr().out
    assert [line for line in out.splitlines() if line.startswith("== ")] == [
        "== 10.0.0.1 ==", "== 10.0.0.2 ==", "== 10.0.0.3 =="]
    assert out.index("out-10.0.0.1") < out.index("out-10.0.0.2") < out.index("out-10.0.0.3")


def test_hosts_really_do_run_at_the_same_time(monkeypatch):
    """Each host waits for the others before answering: run serially this deadlocks, the
    barrier times out and the calls raise, so a silently-serial version cannot pass."""
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    barrier = threading.Barrier(len(addresses), timeout=15)

    def rendezvous(address):
        barrier.wait()
        return (0, "ok", "")

    run = make_run(addresses, dict((a, rendezvous) for a in addresses))
    assert main.run_command_on_all_hosts(run) == 0


# --------------------------------------------------------------------------------------
# failure is reported, never fatal
# --------------------------------------------------------------------------------------

def test_a_failing_command_says_so_and_still_exits_zero(capsys):
    run = make_run(["10.0.0.1"], {"10.0.0.1": lambda a: (2, "", "no such file\n")})
    rc = main.run_command_on_all_hosts(run)
    captured = capsys.readouterr()
    assert rc == 0                                  # -c reaches no verdict
    assert "Command failed (exit code 2)" in captured.out
    assert "no such file" in captured.err           # the reason goes where failures go


def test_partial_output_from_a_failing_command_is_kept(capsys):
    """A command that printed something and then failed said something worth seeing."""
    run = make_run(["10.0.0.1"], {"10.0.0.1": lambda a: (1, "half a line\n", "boom\n")})
    main.run_command_on_all_hosts(run)
    captured = capsys.readouterr()
    assert "half a line" in captured.out
    assert "Command failed (exit code 1)" in captured.out


def test_a_timeout_is_named_as_a_timeout(capsys):
    run = make_run(["10.0.0.1"], {"10.0.0.1": lambda a: (124, "", "")})
    main.run_command_on_all_hosts(run)
    out = capsys.readouterr().out
    assert "timed out after %ds" % config.RUN_CMD_TIMEOUT in out
    assert "exit code 124" not in out


def test_one_unreachable_host_does_not_lose_the_others(capsys):
    def behave(address):
        if address == "10.0.0.2":
            raise transport.CollectError("ssh to 10.0.0.2 failed")
        return (0, "out-" + address, "")

    run = make_run(["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                   dict((a, behave) for a in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]))
    assert main.run_command_on_all_hosts(run) == 0
    captured = capsys.readouterr()
    assert "out-10.0.0.1" in captured.out and "out-10.0.0.3" in captured.out
    assert "== 10.0.0.2 ==" in captured.out          # named, not silently skipped
    assert "ssh to 10.0.0.2 failed" in captured.err


def test_no_health_facts_are_collected(capsys):
    """A one-line command must not cost a health sweep: FakeTransport.collect raises if
    -c ever routes through the collector."""
    run = make_run(["10.0.0.1", "10.0.0.2"],
                   {"10.0.0.1": ok("a"), "10.0.0.2": ok("b")})
    main.run_command_on_all_hosts(run)
    assert run.transport.collected == []


# --------------------------------------------------------------------------------------
# the transport path
# --------------------------------------------------------------------------------------

def test_ssh_hands_the_command_over_whole_as_the_last_argument(monkeypatch):
    """Over ssh nothing wraps the command: the remote login shell reads it, exactly as it
    did for the bash script. Anything else would change what a pipe means."""
    seen = {}

    def fake_run(argv, timeout=None, env=None, stdin_text=None):
        seen["argv"] = argv
        seen["timeout"] = timeout
        seen["env"] = env
        return (0, "", "")

    monkeypatch.setattr(transport, "run_local_cmd", fake_run)
    tr = transport.Transport("xoa", "/tmp/wd")
    tr.password = "secret"
    tr.run_command("10.0.0.1", "ps aux | grep xapi")

    assert seen["argv"][-1] == "ps aux | grep xapi"       # whole, and last
    assert seen["argv"][-2] == "root@10.0.0.1"
    assert "sh" not in seen["argv"][:-1]                  # nothing wrapped it
    assert seen["timeout"] == config.RUN_CMD_TIMEOUT
    assert seen["env"]["SSHPASS"] == "secret"             # never in argv
    assert "secret" not in " ".join(seen["argv"])


def test_ssh_options_match_the_collectors(monkeypatch):
    """Both go over _ssh_argv, so -c inherits the connection behaviour rather than
    restating it and drifting."""
    seen = []
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda argv, **kw: (seen.append(argv), (0, "", ""))[1])
    tr = transport.Transport("xoa", "/tmp/wd")
    tr.password = "p"
    tr.run_command("10.0.0.1", "uptime")
    tr._run_ssh_collector("10.0.0.1", "YmxvYg==")

    def options(argv):
        return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-o"]

    assert options(seen[0]) == options(seen[1])


# --------------------------------------------------------------------------------------
# XOA only
# --------------------------------------------------------------------------------------

def test_host_mode_rejects_c_as_a_usage_error(capsys):
    """-c earns its place on XOA by carrying the pool's host list and root password out of
    xo-server-db. On a hypervisor neither exists - and you already have a root shell - so
    it is refused the way -n is, with exit 2 rather than a later auth failure."""
    run = main.Run()
    run.run_env = "host"
    run.run_cmd = "uptime"
    with pytest.raises(SystemExit) as exc:
        main.resolve_target_host_mode(run, [])
    assert exc.value.code == 2
    assert "-c/--command" in capsys.readouterr().err


def test_host_mode_usage_does_not_advertise_c(capsys):
    """The host usage block must not offer a flag host mode refuses."""
    with pytest.raises(SystemExit):
        main.usage("host", 0)
    text = capsys.readouterr().out
    assert "-c" not in text and "--command" not in text


def test_xoa_usage_does_advertise_c(capsys):
    with pytest.raises(SystemExit):
        main.usage("xoa", 0)
    text = capsys.readouterr().out
    assert "-c 'command'" in text and "-c command" in text


def test_c_is_always_sent_over_ssh(monkeypatch):
    """No local branch: -c is XOA-only, and an XOA reaches every host over ssh - the
    master included. A local arm would be dead code claiming to handle a case that
    cannot arise."""
    seen = []
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda argv, **kw: (seen.append(argv), (0, "", ""))[1])
    tr = transport.Transport("xoa", "/tmp/wd", local_address="10.0.0.1")
    tr.password = "p"
    tr.run_command("10.0.0.1", "uptime")       # even our own address goes over ssh
    assert seen[0][0] == "sshpass"
    assert "sh" not in seen[0]
