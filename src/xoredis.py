# -*- coding: utf-8 -*-
"""The 3.3s shortcut: xo-server's `server` records read straight out of redis.

`xo-server-db ls server` costs 3.3s on an appliance and none of it is the query. It is
`import('./xo.mjs')`, `new Xo({config})` and `await xo.hooks.startCore()` - booting the
whole application to answer one question. Vates' own `xo-xcppool-ssh`
(packages/xo-server/src/ssh-cli.mjs) skips all of that and talks to redis directly; it
answers the same question in 0.59s. With no node in the way at all it is 0.03s, of which
0.002s is redis. Measured on the test appliance, xo-server 5.207.2, three runs each.

This is an OPTIMISATION, so it may only ever produce the right answer or no answer. Every
uncertainty raises RedisError and xodb falls back to `xo-server-db`, which is untouched and
is still the thing that has to work. Two declines carry the weight:

  * **The endpoint is established, not guessed.** node-redis connects to 127.0.0.1:6379
    when xo-server's config sets no `[redis]`, so the fast path runs only when no config
    file app-conf would load mentions redis at all. That is a fact about files we read,
    not an assumption about how appliances are usually set up.
  * **An encrypted credential db is declined, not half-parsed.** With
    `redis.encryptCredentialDatabase` every record is stored as `enc:<base64>`
    (ENCRYPTION_PREFIX in xo-server's crypto-credentials.mjs) and the key lives half in
    xenstore. `enc:` is a positive tell, so we stop. Note that `xo-xcppool-ssh` gets this
    wrong - it builds its RedisCollection with no `crypto`, so `JSON.parse` throws on the
    ciphertext and the tool dies outright. Handling that case is exactly what makes
    `xo-server-db` slow, and it is right to be.

Reading is all this does. No key is written, and nothing here goes near XO's own
RedisCollection, whose constructor issues `sAdd('xo::namespaces', ...)` and can trigger
`rebuildIndexes()` - a health check has no business holding a write path into XO's db.
"""

import json
import os
import socket

import config

DEFAULT_ADDR = ("127.0.0.1", 6379)   # node-redis' default, used when [redis] is unset
ENCRYPTION_PREFIX = "enc:"           # xo-server/src/xo-mixins/crypto-credentials.mjs
IDS_KEY = "xo:server_ids"
RECORD_PREFIX = "xo:server:"


class RedisError(Exception):
    """The fast path declined, with the reason. Never a health finding: the caller falls
    back to xo-server-db and the run continues exactly as it did before."""


# --------------------------------------------------------------------------------------
# is the default endpoint the right endpoint?
# --------------------------------------------------------------------------------------

def _config_dirs(cli_path):
    """The directories app-conf searches for xo-server's config, in its own order.

    From its entries.js: the application directory first, then /etc/<appName>, then the
    XDG config dir. `cli_path` is <appDir>/dist/db-cli.mjs, and app-conf is handed
    `new URL('..', import.meta.url)` - so the app dir is two levels up from the real file,
    symlinks resolved (/usr/local/bin/xo-server-db is one).

    app-conf has a fourth entry, `.xo-server.*` in every directory from the cwd upwards.
    That is for running xo-server out of a source tree, it cannot exist on an appliance,
    and scanning it would mean walking to / on every health check. Not searched.
    """
    app_dir = os.path.dirname(os.path.dirname(os.path.realpath(cli_path)))
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return [app_dir, os.path.join("/etc", "xo-server"), os.path.join(xdg, "xo-server")]


def _config_files(directory):
    """Everything app-conf would glob as `config.*` there. Raises rather than returning an
    empty list for a directory that exists but cannot be listed - unreadable is not empty."""
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RedisError("cannot list %s: %s" % (directory, exc))
    return [os.path.join(directory, n) for n in sorted(names) if n.startswith("config.")]


def _mentions_redis(cli_path):
    """Does any config XO loads mention redis at all?

    A substring test over the raw bytes, deliberately, and not a parse: app-conf reads
    config.* as toml, json, json5, ini or yaml depending on the extension, and this has one
    yes/no question to answer - "could this install point redis somewhere other than the
    default, or turn on credential encryption?". A mention for any reason declines the fast
    path, which is the safe direction, and `encryptCredentialDatabase` is itself a mention.

    The appliance ships /etc/xo-server/config.toml, <appDir>/config.toml and
    <appDir>/config.xoa.json with no occurrence of the word.
    """
    for directory in _config_dirs(cli_path):
        for path in _config_files(directory):
            try:
                with open(path, "rb") as handle:
                    blob = handle.read()
            except OSError as exc:
                # a config we cannot read is a config we cannot rule out
                raise RedisError("cannot read %s: %s" % (path, exc))
            if b"redis" in blob.lower():
                return True
    return False


# --------------------------------------------------------------------------------------
# just enough RESP to ask two questions
# --------------------------------------------------------------------------------------

def _encode(args):
    """One command, as a RESP array of bulk strings."""
    out = [b"*%d\r\n" % len(args)]
    for arg in args:
        raw = arg.encode("utf-8")
        out.append(b"$%d\r\n" % len(raw))
        out.append(raw + b"\r\n")
    return b"".join(out)


def _read_reply(handle):
    """One RESP reply. Bulk strings decode strictly: a password decoded with 'replace'
    would be a password that authenticates nowhere, reported as a login failure a long way
    from its cause."""
    line = handle.readline()
    if not line:
        raise RedisError("connection closed by redis")
    tag, body = line[:1], line[1:-2]
    if tag == b"+":
        return body.decode("utf-8", "replace")
    if tag == b"-":
        raise RedisError("redis refused the command: %s" % body.decode("utf-8", "replace"))
    if tag == b":":
        return int(body)
    if tag == b"$":
        length = int(body)
        if length < 0:
            return None
        data = handle.read(length + 2)
        if len(data) != length + 2:
            raise RedisError("short read from redis")
        return data[:-2].decode("utf-8")
    if tag == b"*":
        count = int(body)
        if count < 0:
            return None
        return [_read_reply(handle) for _ in range(count)]
    raise RedisError("unexpected reply from redis: %r" % line[:40])


# --------------------------------------------------------------------------------------
# the records
# --------------------------------------------------------------------------------------

def _flatten(record, ident):
    """The same dict xodb.scan_records builds out of `xo-server-db ls server`.

    XO stores every field of a server record as a JSON string today - `enabled` is the
    string 'true', not a boolean - so the coercions below are a no-op on every record on
    the test appliance. They are here because the two paths have to stay interchangeable
    whatever XO does next: node's util.inspect prints a bare `true` / `null` / `42`, which
    the scanner records as those words, and prints an object or an array in a form the
    scanner skips outright.

    `id` is not stored in the record - it is the key - and XO's own RedisCollection mixes
    it back in the same way, so `xo-server-db` prints it too.
    """
    out = {}
    for key, value in record.items():
        if isinstance(value, str):
            out[key] = value
        elif value is True:
            out[key] = "true"
        elif value is False:
            out[key] = "false"
        elif value is None:
            out[key] = "null"
        elif isinstance(value, (int, float)):
            out[key] = str(value)
        # an object or an array is skipped, which is what the scanner does with one
    out["id"] = ident
    return out


def _fetch(addr, timeout):
    """SMEMBERS then one MGET, against an already-vetted endpoint."""
    sock = socket.create_connection(addr, timeout=timeout)
    try:
        handle = sock.makefile("rb")
        try:
            sock.sendall(_encode(["SMEMBERS", IDS_KEY]))
            ids = _read_reply(handle)
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                raise RedisError("%s is not a set of ids" % IDS_KEY)
            if not ids:
                # An appliance with no server registered is a real state - and so is
                # "this is not the redis xo-server uses". Nothing here can tell them
                # apart, and only one of them is safe to act on, so the CLI answers it.
                raise RedisError("%s is empty" % IDS_KEY)

            sock.sendall(_encode(["MGET"] + [RECORD_PREFIX + i for i in ids]))
            blobs = _read_reply(handle)
            if not isinstance(blobs, list) or len(blobs) != len(ids):
                # `len(blobs or [])` would be a TypeError on an integer reply, and a
                # TypeError is not a decline - xodb catches RedisError and nothing else,
                # so it would take the run down instead of costing it 3.3s
                got = len(blobs) if isinstance(blobs, list) else "a non-list of"
                raise RedisError("MGET answered %s value(s) for %d id(s)"
                                 % (got, len(ids)))
        finally:
            handle.close()
    finally:
        sock.close()

    records = []
    for ident, blob in zip(ids, blobs):
        if blob is None:
            raise RedisError("%s%s disappeared between the two calls" % (RECORD_PREFIX, ident))
        if blob.startswith(ENCRYPTION_PREFIX):
            raise RedisError("credential db is encrypted (%s%s is %s...)"
                             % (RECORD_PREFIX, ident, ENCRYPTION_PREFIX))
        record = json.loads(blob)
        if not isinstance(record, dict):
            raise RedisError("%s%s is not an object" % (RECORD_PREFIX, ident))
        records.append(_flatten(record, ident))
    return records


def read_server_records(cli_path, addr=DEFAULT_ADDR, timeout=None):
    """Every xo `server` record, in the shape xodb.scan_records produces.

    Raises RedisError - with a reason fit for the HEALTH_DEBUG trace - for every reason
    not to trust the answer. It never returns a partial one.

    `timeout` defaults inside the body and not in the signature: a default argument is
    evaluated when the `def` runs, and in the stitched health.py that is module-body time,
    before the `config` alias object exists. DEFAULT_ADDR is fine - same module, already
    bound - but `config.XO_REDIS_TIMEOUT` there is a NameError on the real artifact and
    nowhere else. build/stitch.py now fails the build on it.
    """
    if timeout is None:
        timeout = config.XO_REDIS_TIMEOUT
    if _mentions_redis(cli_path):
        raise RedisError("xo-server config mentions redis; not assuming %s:%d"
                         % DEFAULT_ADDR)
    try:
        return _fetch(addr, timeout)
    except OSError as exc:
        # connection refused, timeout, a socket that is not redis at all
        raise RedisError("%s:%d: %s" % (addr[0], addr[1], exc))
    except UnicodeDecodeError as exc:
        # before ValueError, which it subclasses
        raise RedisError("undecodable answer from redis: %s" % exc)
    except ValueError as exc:
        # json.loads on a record, or int() on a malformed RESP length prefix
        raise RedisError("unreadable answer from redis: %s" % exc)
