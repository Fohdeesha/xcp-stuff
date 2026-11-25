# -*- coding: utf-8 -*-
"""The one choke point. Everything that talks to a host goes through Transport.collect().

The collector source is delivered on **stdin** - to ssh for a remote host, to a local
interpreter for this one - so there is no shell quoting anywhere in the path. The only
thing interpolated into a command string is a base64 blob, whose alphabet cannot be
mis-quoted by any shell. That is the whole reason the generated-awk/sed machinery the
bash script needed does not exist here.

Contract, unchanged from the bash run_remote it replaces:
  * stderr is captured separately and never merged into stdout
  * one overall timeout, killing the whole process GROUP (a plain child kill would leave
    the ssh multiplexing tree behind)
  * ControlMaster/ControlPersist so one real connection per host serves the whole run
  * the password lives in the child's environment only - never argv, never a file

The password reaches ssh through its own SSH_ASKPASS helper, which needs nothing
installed and nothing from the network - see enable_password_auth(). sshpass is the
fallback now, not the requirement it used to be: an appliance with no internet access
could not install it, and the run died before printing a single line.

Several hosts are collected at once, so everything here is called from worker threads.
Nothing in Transport is mutated during a collection - the password, port and collector
source are all set before the first call - and the one piece of shared state that is
written, the live-child registry below, has its own lock.
"""

import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

import collectorsrc
import config

# The remote side is one fixed string plus a base64 argument. python3 where it exists
# (8.3 dom0), python 2.7 otherwise (8.2.1 dom0 has no python3 at all) - which is why the
# collector is written to the 2.7/3.6 intersection.
_REMOTE_LAUNCH = (
    'p=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true); '
    '[ -n "$p" ] || { echo "health: no python interpreter found on this host" >&2; exit 127; }; '
    'exec "$p" - %s'
)

# Pin the remote interpreter (HEALTH_REMOTE_PYTHON=python2). The 2.7 half of the
# collector's compatibility is otherwise only exercised on 8.2.1 hosts, which are the
# ones going away - this is how it stays testable on an 8.3 box.
_REMOTE_LAUNCH_PINNED = 'exec %s - %%s'

BEGIN_MARKER = "<<<HEALTHPY-JSON-BEGIN>>>"
END_MARKER = "<<<HEALTHPY-JSON-END>>>"

AUTH_ASKPASS = "askpass"
AUTH_SSHPASS = "sshpass"

# The variable the helper prints. Deliberately not SSHPASS: the two mechanisms are
# mutually exclusive and reading one variable in a run that chose the other mechanism is
# the kind of half-configured state that authenticates with an empty password.
ASKPASS_ENV = "HEALTH_SSH_PASSWORD"

# Four lines of sh, written into the run's own work dir (mode 700, deleted at exit). It
# prints what is in the environment, so the password still never reaches a file or an
# argv - the same guarantee sshpass -e gives.
ASKPASS_SCRIPT = (
    "#!/bin/sh\n"
    "# health.py: hands ssh the root password it was already given, from the\n"
    "# environment only. Written per run into a temporary directory and deleted with it.\n"
    "printf '%s\\n' \"${" + ASKPASS_ENV + "}\"\n"
)


class CollectError(Exception):
    """Could not get a document out of a host. Never confused with 'the host is fine'."""


def _mark_incomplete(payload, host):
    """A document the collector sent back part way - stuck on a command it could not kill,
    or failed - keeps every fact it did establish, with "__incomplete__" saying why the
    rest is missing. Each missing fact then reads Unknown by construction, and the host
    block carries one flagged line naming the cause: the evidence gathered on exactly the
    host that is in trouble is not thrown away with it."""
    if "__collector_stuck__" in payload:
        # the host gave up on itself rather than being given up on: a command it could
        # not kill, named. The old shape of this was the transport's own 300s timeout,
        # which could say only that the host did not answer
        debug("%s abandoned its run in: %s" % (host, payload["__collector_stuck__"]))
        for elapsed, command in (payload.get("collector", {}).get("timings") or [])[:8]:
            debug("%s   %6.2fs  %s" % (host, elapsed, command))
        payload["__incomplete__"] = (
            "gave up after %ds stuck in '%s' - that command cannot be killed, so the host's "
            "storage or a driver is most likely wedged"
            % (config.REMOTE_CMD_TIMEOUT - 60, payload["__collector_stuck__"]))
    elif "__collector_error__" in payload:
        trace = payload["__collector_error__"].strip().splitlines()
        debug("collector failed on %s:\n%s" % (host, payload["__collector_error__"]))
        payload["__incomplete__"] = "the collector failed part way: %s" % (
            trace[-1] if trace else "no reason given")


_DEBUG_LOCK = threading.Lock()


def debug(msg):
    """Trace to stderr under HEALTH_DEBUG=1, one whole message at a time.

    Worker threads all write here, and a TextIOWrapper gives no atomicity guarantee, so
    the lock is what stops two hosts' traces from being spliced into one unreadable line.
    """
    if os.environ.get("HEALTH_DEBUG") == "1":
        with _DEBUG_LOCK:
            sys.stderr.write("[health-debug] %s\n" % msg)
            sys.stderr.flush()


# Every child process currently running, so an interrupted run can take the whole tree
# down with it. start_new_session puts each child in its own session, which is what makes
# the timeout killpg work - but it also means the terminal's ctrl-C never reaches them.
# Serially that left one orphan ssh behind; with hosts collected concurrently the worker
# threads cannot be interrupted at all, so without this an interrupt would sit for up to
# REMOTE_CMD_TIMEOUT waiting for the last collector to finish on its own.
_LIVE = set()
_LIVE_LOCK = threading.Lock()
# Set once the run is stopping: a thread still working (the XOA section's daemon thread, a
# collection worker between hosts) may not start a child after the kill that was meant to
# take every child with it - nothing would ever kill that one.
_STOPPING = [False]

# A polite kill first: SIGTERM lets a collector take its own children down with it (they
# are each in their own session, so nothing else reaches them); SIGKILL after this long.
TERM_GRACE = 2.0


class TimedOut(int):
    """run_local_cmd's own timeout: it compares equal to 124, as it always has, so every
    existing `rc == 124` keeps working - but a command that itself EXITED 124 (GNU timeout
    inside -c) is a plain int, and the two can be told apart where it matters."""


TIMED_OUT = TimedOut(124)


def is_timeout(rc):
    return isinstance(rc, TimedOut)


def _signal_group(proc, sig):
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, sig)          # start_new_session: pid is the group id
        else:
            proc.kill()
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def kill_all_children():
    """Stop every child still running, and any from starting. For an interrupted run, not
    for normal shutdown. SIGTERM to all, a short grace, then SIGKILL the rest."""
    with _LIVE_LOCK:
        _STOPPING[0] = True
        procs = list(_LIVE)
    if not procs:
        return
    for proc in procs:
        _signal_group(proc, getattr(signal, "SIGTERM", 15))
    deadline = time.monotonic() + TERM_GRACE
    for proc in procs:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    for proc in procs:
        if proc.poll() is None:
            _signal_group(proc, 9)


def _remote_launch(blob):
    pinned = os.environ.get("HEALTH_REMOTE_PYTHON")
    if pinned and re.match(r"^[A-Za-z0-9_./-]+$", pinned):
        return (_REMOTE_LAUNCH_PINNED % pinned) % blob
    if pinned:
        # a regression run that believes it is forcing python2 must not quietly test
        # python3 instead
        sys.stderr.write("Warning: ignoring HEALTH_REMOTE_PYTHON=%r (expected an "
                         "interpreter name or path).\n" % pinned)
    return _REMOTE_LAUNCH % blob


def _kill_tree(proc):
    """SIGTERM the child's group, then SIGKILL it if it is still there after TERM_GRACE."""
    _signal_group(proc, getattr(signal, "SIGTERM", 15))
    try:
        proc.wait(timeout=TERM_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    _signal_group(proc, 9)


def run_local_cmd(argv, timeout, env=None, stdin_text=None):
    """Run a local command. Returns (rc, stdout_text, stderr_text); rc is TIMED_OUT (== 124)
    when it ran out of time - see TimedOut."""
    with _LIVE_LOCK:
        if _STOPPING[0]:
            return (130, "", "%s: not started - the run is stopping" % argv[0])
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    except OSError as exc:
        return (127, "", "%s: %s" % (argv[0], exc))

    with _LIVE_LOCK:
        _LIVE.add(proc)
        stopping = _STOPPING[0]
    if stopping:
        # started in the instant the run was told to stop: it was never going to be killed
        _kill_tree(proc)
    payload = stdin_text.encode("utf-8") if stdin_text is not None else None
    try:
        out, err = proc.communicate(input=payload, timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = b"", b""
        rc = TIMED_OUT
    except KeyboardInterrupt:
        # only ever raised in the MAIN thread, so this is the serial path; the child is in
        # its own session and never saw the ctrl-C, so it has to be told
        _kill_tree(proc)
        raise
    finally:
        with _LIVE_LOCK:
            _LIVE.discard(proc)
    return (rc,
            out.decode("utf-8", "backslashreplace") if out else "",
            err.decode("utf-8", "backslashreplace") if err else "")


# ssh binds its master at '<ControlPath>.<16 random characters>' and exits 255 when that
# does not fit a unix socket's sun_path (108 bytes with its NUL: openssh mux.c
# muxserver_listen, misc.c unix_listener - the same in 7.4 and 9.2)
SOCKET_PATH_MAX = 107
CONTROL_NAME = "cm-%C"            # %C: a 40-character hash of the connection (OpenSSH 6.7+)


def control_options(work_dir):
    """ssh's connection-sharing options for this run's work dir.

    One master per host, its socket named by %C: a fixed length, where cm-%r@%h:%p grew
    with the host name and a pool stored by a long FQDN could not be reached at all. The
    work dir's own length still counts, though, and a long TMPDIR leaves no room for any
    socket (measured: exit 255, 'ControlPath too long'). Then sharing is switched off and
    every ssh makes its own connection - which costs one handshake, on the seed, since
    each host is otherwise asked once."""
    room = len(os.fsencode(work_dir)) + 1 + len(CONTROL_NAME) - 2 + 40 + 1 + 16
    if room > SOCKET_PATH_MAX:
        return ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    return ["-o", "ControlMaster=auto",
            "-o", "ControlPath=%s" % os.path.join(work_dir, CONTROL_NAME),
            "-o", "ControlPersist=60"]


def close_masters(work_dir):
    """Ask every ssh ControlMaster this run started to exit, so none outlives it.

    With ControlPersist the first ssh to a host forks a master into its own session (out of
    _LIVE's reach) that keeps the authenticated connection for 60 s after its last client;
    and once the work dir is gone its socket is too, so nothing could ever ask it to go.
    Measured: one per host, gone ~60 s after the run. `-O exit` over each socket ends them
    now. No host is contacted - the master is local.
    """
    try:
        names = os.listdir(work_dir)
    except OSError:
        return
    for name in names:
        if not name.startswith("cm-"):
            continue
        # not run_local_cmd: this runs at exit, after kill_all_children has closed it
        try:
            subprocess.call(["ssh", "-S", os.path.join(work_dir, name), "-O", "exit",
                             "health-master"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


class Transport(object):
    def __init__(self, run_env, work_dir, local_address=""):
        self.run_env = run_env
        self.work_dir = work_dir
        self.local_address = local_address
        self.password = ""
        self.ssh_port = 22
        self.source = collectorsrc.collector_source()
        self.auth = ""            # AUTH_ASKPASS / AUTH_SSHPASS, once one is established
        self.askpass = ""         # path to the helper, when that is the chosen one
        self.auth_error = ""      # why there is no way to authenticate, for the report

    def is_local(self, host):
        """Host mode runs its own commands locally: nothing is gained by logging into
        ourselves, and it works with no credentials at all."""
        if self.run_env != "host":
            return False
        return not self.local_address or host == self.local_address

    def collect(self, host, spec):
        """Run the collector on `host` and return its document. Raises CollectError."""
        spec = dict(spec)
        spec.setdefault("budget", config.REMOTE_CMD_TIMEOUT - 60)
        if os.environ.get("HEALTH_DEBUG") == "1":
            spec["timings"] = True
        blob = base64.b64encode(json.dumps(spec).encode("utf-8")).decode("ascii")
        debug("collect %s want=%s" % (host, spec.get("want")))

        if self.is_local(host):
            rc, out, err = self._run_local_collector(blob)
            what = "local command"
        else:
            if self.run_env == "host" and not self.password:
                # answering about the wrong machine is the failure mode worth killing
                raise CollectError(
                    "asked to run on %s from %s with no password for it" % (host, self.local_address))
            rc, out, err = self._run_ssh_collector(host, blob)
            what = "ssh to %s" % host

        # the document first: one that arrived whole is the answer whatever the exit code
        payload = self._extract(out)
        if payload is None:
            if is_timeout(rc):
                raise CollectError("%s timed out after %ds" % (what, config.REMOTE_CMD_TIMEOUT))
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("%s failed (exit %d)%s" % (what, rc, (": " + detail) if detail else ""))
        _mark_incomplete(payload, host)
        if err.strip():
            debug("stderr from %s:\n%s" % (host, err.strip()))
        info = payload.get("collector") or {}
        debug("%s answered from python %s" % (host, info.get("python", "?")))
        for elapsed, command in (info.get("timings") or [])[:8]:
            debug("%s   %6.2fs  %s" % (host, elapsed, command))
        return payload

    def collect_local(self, spec):
        """Explicitly this machine, before we know our own address.

        Only the discovery call needs it: from then on is_local() has an address to
        compare against, and answering about the wrong machine becomes impossible.
        """
        spec = dict(spec)
        spec.setdefault("budget", config.REMOTE_CMD_TIMEOUT - 60)
        blob = base64.b64encode(json.dumps(spec).encode("utf-8")).decode("ascii")
        rc, out, err = self._run_local_collector(blob)
        payload = self._extract(out)
        if payload is None:
            if is_timeout(rc):
                raise CollectError("local command timed out after %ds" % config.REMOTE_CMD_TIMEOUT)
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("local command failed (exit %d)%s"
                               % (rc, (": " + detail) if detail else ""))
        # the same reading as collect(): this path used to ignore the stuck marker and use
        # a partial document as if it were whole
        _mark_incomplete(payload, "this host")
        return payload

    def _run_local_collector(self, blob):
        return run_local_cmd([sys.executable, "-", blob],
                             timeout=config.REMOTE_CMD_TIMEOUT,
                             stdin_text=self.source)

    def _ssh_argv(self, host, remote_command):
        """The ssh invocation and the environment that authenticates it, in one place.

        Returns (argv, env). Both the collector and -c/--command go over it, and the
        options are the whole reason a run behaves the same on every host - one real
        connection per host, no host-key prompt, a bounded connect, and whichever
        password mechanism _auth_env() settled on. Built here so the two callers cannot
        drift apart on any of that; only the trailing command differs.
        """
        env, prefix = self._auth_env()
        return prefix + [
            "ssh",
            "-p", str(self.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=%d" % config.SSH_TIMEOUT,
            "-o", "NumberOfPasswordPrompts=1",
        ] + control_options(self.work_dir) + [
            "-o", "BatchMode=no",
            "root@" + host,
            remote_command,
        ], env

    def _run_ssh_collector(self, host, blob):
        argv, env = self._ssh_argv(host, _remote_launch(blob))
        return run_local_cmd(argv, timeout=config.REMOTE_CMD_TIMEOUT,
                             env=env, stdin_text=self.source)

    def run_command(self, host, cmd, timeout=None):
        """-c/--command: run the user's own command on `host`. Returns (rc, out, err).

        Always over ssh, with no local branch: -c is XOA-only (main rejects it on a
        hypervisor), and an XOA reaches every host including the master that way. If it
        ever gains a host mode, this needs an is_local() arm that runs the command
        through a shell - there would be no ssh to interpret it.

        Deliberately NOT a collector spec. The collector answers with a JSON document of
        facts between markers, which is the wrong shape for raw output: it would be
        base64'd in, JSON-encoded out, and clamped against a health sweep's budget, for
        no gain whatsoever. This is the path bash's run_remote took - the same ssh
        options, the same process-group timeout, the command handed over whole - and it
        is why nothing had to be added to the collector for this.

        Nothing here composes a command, so the no-shell rule the collector states does
        not apply: the string is the user's, it arrives whole, it leaves whole as the
        last argv element, and the remote login shell is the only thing that reads it -
        exactly as it was for bash.

        stdin is closed by run_local_cmd, which matters more here than anywhere: a
        command that tried to read it (an unguarded 'yum update') would otherwise be
        eating this script's own stdin.
        """
        timeout = config.RUN_CMD_TIMEOUT if timeout is None else timeout
        argv, env = self._ssh_argv(host, cmd)
        return run_local_cmd(argv, timeout=timeout, env=env)

    def _auth_env(self):
        """The environment and the argv prefix that hand ssh the password.

        Two variables for the askpass helper, because two generations of OpenSSH decide
        differently whether to use one. SSH_ASKPASS_REQUIRE is 8.4 and later (XOA's 9.2)
        and settles it outright. 7.4 - which is what both dom0 releases ship, so it is the
        host-mode sweep - consults the helper only when there is no controlling terminal
        AND DISPLAY is set: the first is already true of every child here (they are all
        started with start_new_session=True, so open("/dev/tty") fails in them), and the
        second is why a DISPLAY nothing will ever connect to is set. An existing DISPLAY
        is left alone; it is only ever read as a flag.
        """
        env = dict(os.environ)
        if self.auth == AUTH_ASKPASS:
            env[ASKPASS_ENV] = self.password
            env["SSH_ASKPASS"] = self.askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            if not env.get("DISPLAY"):
                env["DISPLAY"] = ":0"
            return env, []
        env["SSHPASS"] = self.password
        return env, ["sshpass", "-e"]

    def enable_password_auth(self, run_env):
        """Find a way to give ssh a password, or record why there is none. True if found.

        The helper is tried FIRST because it needs nothing installed and nothing from the
        network. That is not a corner: health.py is routinely pasted onto a customer's
        appliance over ssh precisely because the appliance has no internet access, and
        there 'apt-get install sshpass' cannot work - the run used to die on that before
        printing a line, including the whole XOA section, which needs no pool access at
        all. It also means the path that runs in the field is the path the lab runs on
        every test, rather than a fallback nothing exercises until it matters.

        sshpass remains the fallback for the one thing the helper depends on that can be
        missing: a work dir it is allowed to execute from (a noexec /tmp).

        HEALTH_SSH_AUTH=askpass|sshpass pins the choice, which is how each is regression
        tested against the other on hosts that have both.
        """
        pinned = os.environ.get("HEALTH_SSH_AUTH", "")
        if pinned not in ("", AUTH_ASKPASS, AUTH_SSHPASS):
            sys.stderr.write("Warning: ignoring HEALTH_SSH_AUTH=%s (expected %s or %s).\n"
                             % (pinned, AUTH_ASKPASS, AUTH_SSHPASS))
            pinned = ""

        tried = []
        if pinned != AUTH_SSHPASS:
            path = write_askpass(self.work_dir)
            if path:
                self.auth = AUTH_ASKPASS
                self.askpass = path
                debug("password auth: ssh askpass helper at %s" % path)
                return True
            tried.append("the askpass helper would not run from %s" % self.work_dir)
            debug("askpass helper unusable")

        if pinned != AUTH_ASKPASS:
            if sshpass_present(run_env):
                self.auth = AUTH_SSHPASS
                debug("password auth: sshpass")
                return True
            tried.append("sshpass is not installed")

        # named individually: 'no way to authenticate' with no reason is the kind of
        # message that gets read as 'wrong password' and sends someone after the pool
        self.auth_error = ("ssh needs a password and there is no way to hand it one (%s)"
                           % " and ".join(tried))
        return False

    @staticmethod
    def _extract(text):
        """Pull the JSON out from between the markers.

        Markers rather than 'the first {' so a login banner, a sudo notice or any other
        stray stdout cannot be mistaken for the document - and so truncation is detected
        instead of producing a confident half-answer.
        """
        start = text.find(BEGIN_MARKER)
        end = text.rfind(END_MARKER)
        if start < 0 or end < 0 or end < start:
            return None
        blob = text[start + len(BEGIN_MARKER):end].strip()
        if not blob:
            return None
        try:
            return json.loads(blob)
        except ValueError:
            return None


def make_work_dir():
    path = tempfile.mkdtemp(prefix="healthpy-")
    return path


def cleanup_work_dir(path):
    if path and os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def which(binary):
    """Full path to `binary` on PATH, or "". The path matters as well as the answer:
    xo-server's application directory is derived from where xo-server-db really lives."""
    for part in (os.environ.get("PATH") or "").split(os.pathsep):
        if not part:
            continue
        candidate = os.path.join(part, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def have(binary):
    return bool(which(binary))


def write_askpass(work_dir):
    """Write the askpass helper and PROVE it runs. Returns its path, or "" if it does not.

    The proof is the point. Everything that can go wrong here - a noexec /tmp, a work dir
    on a filesystem that drops the execute bit, no /bin/sh - fails silently at the far
    end otherwise: ssh gets an empty password back and reports an authentication failure,
    which reads as a wrong root password and sends someone off to check xo-server-db.
    A probe value, never the real password, so the check costs nothing to be wrong about.
    """
    path = os.path.join(work_dir, "askpass")
    try:
        handle = open(path, "w")
        try:
            handle.write(ASKPASS_SCRIPT)
        finally:
            handle.close()
        os.chmod(path, 0o700)
    except (IOError, OSError) as exc:
        debug("askpass helper could not be written to %s: %s" % (path, exc))
        return ""
    probe = "health-askpass-probe"
    env = dict(os.environ)
    env[ASKPASS_ENV] = probe
    rc, out, err = run_local_cmd([path], timeout=config.LOCAL_CMD_TIMEOUT, env=env)
    if rc != 0 or out.strip() != probe:
        debug("askpass helper did not run (exit %d): %s"
              % (rc, ((err or out).strip() or "no output")[:200]))
        return ""
    return path


def sshpass_present(run_env):
    """Is sshpass already installed? It is the fallback, reached only when the askpass
    helper could not be run (a noexec work dir) - see enable_password_auth().

    Nothing is installed for it, on either side (the maintainer's call, 2026-11-25). The
    install this replaces ran yum --enablerepo=extras on a dom0 and apt-get on an XOA: on
    the offline appliances health.py is routinely pasted onto that was up to ten minutes
    of timeouts before anything printed, and it left a package behind on a box the tool
    is meant to leave as it found it. Without sshpass the run goes on to the XOA-only
    report, or this host alone, saying why.
    """
    return have("sshpass")
