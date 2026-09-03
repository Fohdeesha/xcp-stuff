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
import subprocess
import sys
import tempfile
import threading

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


class CollectError(Exception):
    """Could not get a document out of a host. Never confused with 'the host is fine'."""


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


def kill_all_children():
    """Kill every child still running. For an interrupted run, not for normal shutdown."""
    with _LIVE_LOCK:
        procs = list(_LIVE)
    for proc in procs:
        _kill_tree(proc)


def _remote_launch(blob):
    pinned = os.environ.get("HEALTH_REMOTE_PYTHON")
    if pinned and re.match(r"^[A-Za-z0-9_./-]+$", pinned):
        return (_REMOTE_LAUNCH_PINNED % pinned) % blob
    return _REMOTE_LAUNCH % blob


def _kill_tree(proc):
    try:
        os.killpg(os.getpgid(proc.pid), 9)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def run_local_cmd(argv, timeout, env=None, stdin_text=None):
    """Run a local command. Returns (rc, stdout_text, stderr_text); rc 124 = timed out."""
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
        rc = 124
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


class Transport(object):
    def __init__(self, run_env, work_dir, local_address=""):
        self.run_env = run_env
        self.work_dir = work_dir
        self.local_address = local_address
        self.password = ""
        self.ssh_port = 22
        self.source = collectorsrc.collector_source()

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

        if rc == 124:
            raise CollectError("%s timed out after %ds" % (what, config.REMOTE_CMD_TIMEOUT))
        payload = self._extract(out)
        if payload is None:
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("%s failed (exit %d)%s" % (what, rc, (": " + detail) if detail else ""))
        if "__collector_error__" in payload:
            raise CollectError("collector crashed on %s:\n%s" % (host, payload["__collector_error__"]))
        if err.strip():
            debug("stderr from %s:\n%s" % (host, err.strip()))
        info = payload.get("collector") or {}
        debug("%s answered from python %s" % (host, info.get("python", "?")))
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
        if rc == 124:
            raise CollectError("local command timed out after %ds" % config.REMOTE_CMD_TIMEOUT)
        payload = self._extract(out)
        if payload is None:
            detail = (err.strip().splitlines() or [""])[-1][:300]
            raise CollectError("local command failed (exit %d)%s"
                               % (rc, (": " + detail) if detail else ""))
        if "__collector_error__" in payload:
            raise CollectError("collector crashed:\n%s" % payload["__collector_error__"])
        return payload

    def _run_local_collector(self, blob):
        return run_local_cmd([sys.executable, "-", blob],
                             timeout=config.REMOTE_CMD_TIMEOUT,
                             stdin_text=self.source)

    def _run_ssh_collector(self, host, blob):
        env = dict(os.environ)
        env["SSHPASS"] = self.password
        argv = [
            "sshpass", "-e", "ssh",
            "-p", str(self.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=%d" % config.SSH_TIMEOUT,
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=%s" % os.path.join(self.work_dir, "cm-%r@%h:%p"),
            "-o", "ControlPersist=60",
            "-o", "BatchMode=no",
            "root@" + host,
            _remote_launch(blob),
        ]
        return run_local_cmd(argv, timeout=config.REMOTE_CMD_TIMEOUT,
                             env=env, stdin_text=self.source)

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


def ensure_sshpass(run_env):
    """Make sshpass available, or say why it is not.

    On a hypervisor it comes from 'extras', a stock XCP-ng repo that ships in
    CentOS-Base.repo pointing at Vates' own mirror and is merely disabled by default.
    --enablerepo is a one-shot, so the host's yum config is left exactly as it was, and
    the package is 21KB with no dependencies. Note that plain 'yum list available sshpass'
    finds nothing - it only searches ENABLED repos, which is what made an earlier look
    conclude, wrongly, that it was not available.
    """
    if have("sshpass"):
        return True
    if run_env == "host":
        sys.stderr.write("sshpass not found - installing it from the XCP-ng 'extras' repo "
                         "to reach the other pool hosts...\n")
        rc, out, err = run_local_cmd(
            ["yum", "--enablerepo=extras", "install", "-y", "sshpass"], timeout=300)
        if not have("sshpass"):
            sys.stderr.write("ERROR: could not install sshpass (yum exit code %d).\n" % rc)
            for line in (out + err).splitlines()[-5:]:
                sys.stderr.write(line + "\n")
            return False
        sys.stderr.write("sshpass installed.\n")
        return True

    sys.stderr.write("sshpass not found. Installing via apt...\n")
    run_local_cmd(["apt-get", "update", "-y"], timeout=300)
    run_local_cmd(["apt-get", "install", "-y", "sshpass"], timeout=300)
    return have("sshpass")
