#!/usr/bin/env python3
"""xo-config-recover - export Xen Orchestra's configuration when xo-server cannot.

Produces the same file as *Settings > Config > Export* in the web UI, read straight out of
the two stores xo-server keeps its configuration in, so it works when the UI and the API
are dead:

    redis      16 of the 18 sections     xo:<namespace>_ids  ->  xo:<namespace>:<id>
    leveldb    resourceSets, ipPools     <datadir>/leveldb, sublevel keys !<name>!<id>

The output imports through *Settings > Config > Import* (or `xo-cli xo.importConfig`)
exactly like a web UI export, and is byte-identical to one for the same data: verified
record by record against a real export, with xo-server running, with xo-server and
xoa-updater stopped, and with redis stopped as well.

USAGE
    xo-config-recover.py                        write ./XO-config_<UTC>.json.gz
    xo-config-recover.py -o FILE | -o -         name the file, or stream plain bytes to stdout
    xo-config-recover.py --check                show what would be exported, write nothing
    xo-config-recover.py --bundle [FILE]        also write a recovery bundle (export + fresh
                                                redis dump + leveldb copy + config files)
    xo-config-recover.py --passphrase-file F    encrypt the export like the UI's .enc option
    xo-config-recover.py --entries a,b          a subset, dependencies added like the API does
    xo-config-recover.py --rdb /path/dump.rdb   redis is down: read this dump instead

WHAT IT NEEDS
    root, python3 >= 3.9, and either a reachable redis or a dump.rdb plus the redis-server
    binary. Nothing else: no xo-server, no node, no packages. Everything it does is
    read-only except writing the output: redis is only ever asked SMEMBERS / GET / TYPE /
    HGETALL / CONFIG GET, and leveldb is parsed from a private copy of its files with no
    lock taken and no library opened on the real directory.

WHEN REDIS IS DOWN TOO
    The redis service is separate from xo-server and usually survives an update that kills
    it. If it is unreachable, the last saved dump.rdb (see `save` in redis.conf: at most an
    hour old, at most 60 s under load) is read through a throw-away private redis-server on
    a unix socket in a temp dir, which is killed and deleted afterwards. That is said loudly
    on stderr, because anything changed in XO after that save is not in the export.

RESTORE
    Web UI: Settings > Config > Import, pick the file. CLI: `xo-cli xo.importConfig
    @XO-config_...json.gz`. Servers reconnect on import; plugin configurations apply only to
    plugins that are installed; authTokens are sessions and can be left out with
    `--entries` if unwanted.

EXIT CODES
    0 exported; 1 exported with --partial and something omitted; 2 nothing written.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import io
import json
import math
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib
from urllib.parse import unquote, urlparse

NAME = "xo-config-recover"
VERSION = "0.5"

# --------------------------------------------------------------------------------------
# what the web UI exports, in the order it exports it
#
# xo-server/src/xo-mixins/config-management.mjs: JSON.stringify(asyncMapValues(managers,
# exporter)). `managers` fills in registration order: the mixins are constructed in
# alphabetical file order and register on the 'core started' hook, except resource-sets
# and ip-pools, which register on 'start' and therefore come last. JSON.stringify keeps
# insertion order, so this list IS the key order of a web UI export.
# --------------------------------------------------------------------------------------

REDIS_SECTIONS = [
    # export key      redis namespace        unserializer   import dependencies
    ("roles",         "acl-v2-role",         None,          []),
    ("privileges",    "acl-v2-privilege",    None,          ["roles"]),
    ("userRole",      "acl-v2-user-role",    None,          ["users", "roles"]),
    ("groupRole",     "acl-v2-group-role",   None,          ["groups", "roles"]),
    ("acls",          "acl",                 "acl",         ["groups", "users"]),
    ("authTokens",    "token",               "token",       []),
    ("cloudConfigs",  "cloudConfig",         None,          []),
    ("jobs",          "job",                 "job",         ["users"]),
    ("plugins",       "plugin-metadata",     "plugin",      []),
    ("proxies",       "proxy",               None,          []),
    ("remotes",       "remote",              "remote",      []),
    ("schedules",     "schedule",            "schedule",    ["jobs"]),
    ("groups",        "group",               "group",       ["users"]),
    ("users",         "user",                "user",        []),
    ("tags",          "tag",                 None,          []),
    ("xenServers",    "server",              "server",      []),
]
LEVELDB_SECTIONS = [
    ("resourceSets",  "resourceSets",        "resourceSet", ["groups", "users"]),
    ("ipPools",       "ipPools",             "ipPool",      []),
]
ALL_SECTIONS = [s[0] for s in REDIS_SECTIONS] + [s[0] for s in LEVELDB_SECTIONS]
DEPENDENCIES = {s[0]: s[3] for s in REDIS_SECTIONS + LEVELDB_SECTIONS}

ENCRYPTION_PREFIX = "enc:"                        # xo-mixins/crypto-credentials.mjs
DEFAULT_DATADIR = "/var/lib/xo-server/data"
DEFAULT_REDIS_URI = "redis://localhost:6379/0"     # node-redis' default when [redis] is unset
DEFAULT_REDIS_CONF = "/etc/redis/redis.conf"
DEFAULT_RDB = "/var/lib/redis/dump.rdb"
PASSPHRASE_ENV = "XO_CONFIG_RECOVER_PASSPHRASE"


class ExportError(Exception):
    """Something this run cannot establish. Reported, never papered over."""


def log(msg):
    sys.stderr.write("%s: %s\n" % (NAME, msg))


# --------------------------------------------------------------------------------------
# xo-server's configuration: where redis is, where the datadir is, is the db encrypted
# --------------------------------------------------------------------------------------

def xo_server_dir(explicit=None):
    """<appDir> of the installed xo-server. /usr/local/bin/xo-server is a symlink into
    <appDir>/dist, and app-conf is handed new URL('..', import.meta.url) from there. None
    when nothing is installed any more, which a broken update can leave behind - the
    export then runs on /etc/xo-server + defaults, which is all it needs."""
    if explicit:
        return explicit
    exe = shutil.which("xo-server")
    if exe:
        return os.path.dirname(os.path.dirname(os.path.realpath(exe)))
    for cand in ("/usr/local/lib/node_modules/xo-server", "/opt/xo/xo-server", "/opt/xen-orchestra/packages/xo-server"):
        if os.path.isdir(cand):
            return cand
    return None


def config_dirs(app_dir):
    """app-conf's search order: the app dir, /etc/<app>, then the XDG config dir. Inside a
    directory every config.* file is merged in sorted name order - which is why xo-server
    names its own auto-generated file config.z-auto.json."""
    dirs = []
    if app_dir:
        dirs.append(app_dir)
    dirs.append("/etc/xo-server")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    dirs.append(os.path.join(xdg, "xo-server"))
    return dirs


def _deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def _parse_toml_minimal(text):
    """Enough TOML for xo-server's config files when tomllib (3.11+) is missing: bare
    `key = value` lines under `[section]` / `[a.b]` headers, quoted strings, booleans and
    integers. Anything fancier is ignored, which is fine for the three keys we need."""
    out = {}
    section = out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[([^\[\]]+)\]$", line)
        if m:
            section = out
            for part in m.group(1).strip().split("."):
                section = section.setdefault(part.strip().strip("'\""), {})
            continue
        m = re.match(r"^([A-Za-z0-9_.'\"-]+)\s*=\s*(.+?)\s*$", line)
        if not m:
            continue
        key, val = m.group(1).strip("'\""), m.group(2)
        if val[:1] in ("'", '"'):
            q = val[0]
            end = val.find(q, 1)
            val = val[1:end] if end > 0 else val[1:]
        else:
            val = val.split("#", 1)[0].strip()
            if val in ("true", "false"):
                val = val == "true"
            else:
                try:
                    val = int(val)
                except ValueError:
                    pass
        section[key] = val
    return out


def load_xo_config(app_dir, verbose=False):
    """The merged xo-server config, or as much of it as decides where this tool looks."""
    try:
        import tomllib  # 3.11+
    except ImportError:
        tomllib = None
    merged = {}
    files = []
    for d in config_dirs(app_dir):
        try:
            names = sorted(os.listdir(d))
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ExportError("cannot list config dir %s: %s" % (d, exc))
        for name in names:
            if not name.startswith("config."):
                continue
            path = os.path.join(d, name)
            ext = name.rsplit(".", 1)[-1].lower()
            try:
                with open(path, "rb") as fh:
                    blob = fh.read()
            except OSError as exc:
                raise ExportError("cannot read %s: %s" % (path, exc))
            if ext == "toml":
                if tomllib is not None:
                    data = tomllib.loads(blob.decode("utf-8"))
                else:
                    data = _parse_toml_minimal(blob.decode("utf-8", "replace"))
            elif ext == "json":
                data = json.loads(blob.decode("utf-8"))
            else:
                # yaml / json5 / ini: app-conf would load these; we cannot. Refuse to guess
                # only if the file could change where we look.
                if b"redis" in blob.lower() or b"datadir" in blob.lower():
                    raise ExportError("%s is a .%s config that mentions redis/datadir; pass --redis / --datadir explicitly" % (path, ext))
                continue
            if verbose:
                log("config: %s" % path)
            files.append(path)
            _deep_merge(merged, data)
    merged["_files"] = files
    return merged


def redis_conf_persistence(path=DEFAULT_REDIS_CONF):
    """`dir` and `dbfilename` from redis.conf, for finding the dump when redis is down."""
    d, name = "/var/lib/redis", "dump.rdb"
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0] == "dir":
                    d = parts[1].strip().strip('"')
                elif len(parts) == 2 and parts[0] == "dbfilename":
                    name = parts[1].strip().strip('"')
    except OSError:
        pass
    return os.path.join(d, name)


# --------------------------------------------------------------------------------------
# redis: just enough RESP, read-only by construction
# --------------------------------------------------------------------------------------

class RedisError(ExportError):
    pass


class Redis:
    """A RESP2 client that can only ask. Any command outside READ_ONLY is refused before it
    is sent, so a bug in this file cannot turn into a write to XO's database."""

    READ_ONLY = {"SMEMBERS", "GET", "TYPE", "HGETALL", "PING", "SELECT", "AUTH", "DBSIZE", "INFO", "CONFIG"}

    def __init__(self, uri=None, unix_socket=None, timeout=10.0, rename=None):
        self._sock = None
        self._fh = None
        self._rename = {k.upper(): v for k, v in (rename or {}).items()}
        if unix_socket:
            self.describe = "unix:%s" % unix_socket
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(unix_socket)
            self._sock = s
            user = password = None
            db = 0
        else:
            u = urlparse(uri or DEFAULT_REDIS_URI)
            if u.scheme not in ("redis", "rediss"):
                raise RedisError("unsupported redis URI scheme %r" % u.scheme)
            host = u.hostname or "localhost"
            port = u.port or 6379
            self.describe = "%s:%d" % (host, port)
            s = socket.create_connection((host, port), timeout=timeout)
            if u.scheme == "rediss":
                s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            self._sock = s
            user = unquote(u.username) if u.username else None
            password = unquote(u.password) if u.password else None
            db = int(u.path.strip("/")) if u.path and u.path.strip("/") else 0
        self._fh = self._sock.makefile("rb")
        if password is not None:
            if user:
                self.call("AUTH", user, password)
            else:
                self.call("AUTH", password)
        if db:
            self.call("SELECT", str(db))
        if self.call("PING") != "PONG":
            raise RedisError("%s did not answer PING" % self.describe)

    def close(self):
        try:
            if self._fh is not None:
                self._fh.close()
        finally:
            if self._sock is not None:
                self._sock.close()

    def call(self, *args):
        cmd = args[0].upper()
        if cmd not in self.READ_ONLY or (cmd == "CONFIG" and (len(args) < 2 or args[1].upper() != "GET")):
            raise RedisError("refusing non read-only command %s" % " ".join(str(a) for a in args[:2]))
        wire = [self._rename.get(cmd, args[0])] + list(args[1:])
        out = [b"*%d\r\n" % len(wire)]
        for a in wire:
            raw = a.encode("utf-8") if isinstance(a, str) else a
            out.append(b"$%d\r\n" % len(raw))
            out.append(raw + b"\r\n")
        self._sock.sendall(b"".join(out))
        return self._read()

    def _read(self):
        line = self._fh.readline()
        if not line:
            raise RedisError("connection closed by redis")
        tag, body = line[:1], line[1:-2]
        if tag == b"+":
            return body.decode("utf-8", "replace")
        if tag == b"-":
            raise RedisError("redis: %s" % body.decode("utf-8", "replace"))
        if tag == b":":
            return int(body)
        if tag == b"$":
            n = int(body)
            if n < 0:
                return None
            data = self._fh.read(n + 2)
            if len(data) != n + 2:
                raise RedisError("short read")
            return data[:-2]          # bytes; the caller decodes
        if tag == b"*":
            n = int(body)
            if n < 0:
                return None
            return [self._read() for _ in range(n)]
        raise RedisError("unexpected RESP reply %r" % line[:40])

    def config_get(self, key):
        reply = self.call("CONFIG", "GET", key)
        if isinstance(reply, list) and len(reply) == 2:
            return reply[1].decode("utf-8", "replace") if isinstance(reply[1], bytes) else reply[1]
        return None


class TempRedisFromRdb:
    """A throw-away redis-server on a private copy of a dump.rdb, for when the real one
    is down. `--save ''`, no appendonly, port 0 and a unix socket in a 0700 temp dir: it
    can neither be reached by anything else nor write anything but its own log line, and
    it is killed and its directory removed on close. The real dump file is only ever read."""

    def __init__(self, rdb_path, verbose=False):
        exe = shutil.which("redis-server")
        if not exe:
            raise ExportError("redis-server binary not found; cannot read %s without it" % rdb_path)
        self.tmp = tempfile.mkdtemp(prefix="%s-rdb-" % NAME)
        os.chmod(self.tmp, 0o700)
        self.proc = None
        try:
            shutil.copyfile(rdb_path, os.path.join(self.tmp, "dump.rdb"))
        except OSError as exc:
            shutil.rmtree(self.tmp, ignore_errors=True)
            raise ExportError("cannot read %s: %s" % (rdb_path, exc))
        self.sock_path = os.path.join(self.tmp, "redis.sock")
        args = [exe, "--port", "0", "--unixsocket", self.sock_path, "--unixsocketperm", "700",
                "--dir", self.tmp, "--dbfilename", "dump.rdb", "--save", "", "--appendonly", "no",
                "--daemonize", "no", "--loglevel", "warning", "--protected-mode", "yes"]
        self.proc = subprocess.Popen(args, stdout=None if verbose else subprocess.DEVNULL,
                                     stderr=None if verbose else subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.close()
                raise ExportError("temporary redis-server exited with %d (is %s a valid RDB?)" % (self.proc.returncode, rdb_path))
            if os.path.exists(self.sock_path):
                try:
                    Redis(unix_socket=self.sock_path, timeout=2).close()
                    return
                except (OSError, RedisError):
                    pass
            time.sleep(0.1)
        self.close()
        raise ExportError("temporary redis-server did not come up within 30 s")

    def close(self):
        try:
            if self.proc is not None and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(5)
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)


def connect_redis(args, redis_cfg, verbose=False):
    """(Redis, TempRedisFromRdb or None, description). Live redis first; a dump.rdb through a
    private server if the live one cannot be reached (or --rdb says so). Auth failures and
    the like are NOT reasons to fall back - only 'nobody is listening' is."""
    rename = redis_cfg.get("renameCommands") or {}
    rdb = args.rdb
    if rdb is None:
        sock = args.redis_socket or redis_cfg.get("socket")
        uri = args.redis or redis_cfg.get("uri")
        try:
            r = Redis(uri=uri, unix_socket=sock, rename=rename)
            return r, None, "redis %s" % r.describe
        except OSError as exc:
            rdb = redis_conf_persistence()
            if not os.path.exists(rdb):
                raise ExportError("cannot connect to redis (%s: %s) and there is no dump at %s; "
                                  "start redis-server, or point --rdb at a dump.rdb"
                                  % (sock or uri or DEFAULT_REDIS_URI, exc, rdb))
            log("WARNING: redis is not reachable (%s: %s)" % (sock or uri or DEFAULT_REDIS_URI, exc))
    try:
        st = os.stat(rdb)
    except OSError as exc:
        raise ExportError("cannot read %s: %s" % (rdb, exc))
    age = time.time() - st.st_mtime
    when = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    log("WARNING: reading %s (last saved %s, %s ago) through a temporary private redis-server. "
        "Anything changed in XO after that save is NOT in this export." % (rdb, when, _human_age(age)))
    temp = TempRedisFromRdb(rdb, verbose)
    r = Redis(unix_socket=temp.sock_path, rename=rename)
    return r, temp, "dump %s (saved %s)" % (rdb, when)


def _human_age(seconds):
    seconds = int(seconds)
    if seconds < 120:
        return "%d s" % seconds
    if seconds < 7200:
        return "%d min" % (seconds // 60)
    if seconds < 172800:
        return "%.1f h" % (seconds / 3600.0)
    return "%.1f days" % (seconds / 86400.0)


# --------------------------------------------------------------------------------------
# the encrypted credential database (redis.encryptCredentialDatabase)
#
# xo-mixins/crypto-credentials.mjs: every record value becomes
#     'enc:' + base64( iv[12] || AES-256-GCM(plaintext) || tag[16] )
# with the key derived by HKDF-SHA256 (empty salt, info 'xo-credentials-aes') from the
# concatenation of a 32-byte half kept in xenstore (vm-data/xo-encryption-key, hex) and a
# 32-byte half in <datadir>/xo-encryption-key. The secondary indexes use an HMAC key from
# the same HKDF with info 'xo-credentials-hmac' (WebCrypto's default HMAC-SHA256 length is
# the block size, 64 bytes). The key derivation below is implemented and tested against
# node's webcrypto; the AES-GCM step is not implemented in this version, so an encrypted
# database is reported precisely rather than half-read. The web UI refuses to export such
# a database without a passphrase for the same reason.
# --------------------------------------------------------------------------------------

XENSTORE_KEY_PATH = "vm-data/xo-encryption-key"
KEY_FILE_NAME = "xo-encryption-key"


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 with SHA-256."""
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_credential_keys(xenstore_half, file_half):
    """(aes_key[32], hmac_key[64]) exactly as CryptoCredentials._loadKey derives them."""
    ikm = xenstore_half + file_half
    return (hkdf_sha256(ikm, b"", b"xo-credentials-aes", 32),
            hkdf_sha256(ikm, b"", b"xo-credentials-hmac", 64))


class CredentialCrypto:
    def __init__(self, datadir):
        self.key_file = os.path.join(datadir, KEY_FILE_NAME)

    def status(self):
        """What is there to decrypt with, for the error message."""
        have_file = os.path.exists(self.key_file)
        have_xs = False
        xs = shutil.which("xenstore-read")
        if xs:
            try:
                res = subprocess.run([xs, XENSTORE_KEY_PATH], capture_output=True, timeout=10)
                have_xs = res.returncode == 0 and len(res.stdout.strip()) >= 64
            except (OSError, subprocess.TimeoutExpired):
                pass
        return have_xs, have_file

    def decrypt(self, value):
        have_xs, have_file = self.status()
        raise ExportError(
            "the credential database is encrypted (redis.encryptCredentialDatabase; values start with "
            "'enc:'). %s %s does not decrypt it yet: AES-256-GCM is not in Python's standard library. "
            "Key halves present: xenstore %s, %s %s. The web UI export requires a passphrase in this "
            "mode; if xo-server still starts, use it."
            % (NAME, VERSION, "yes" if have_xs else "no", self.key_file, "yes" if have_file else "no"))


# --------------------------------------------------------------------------------------
# the per-model _unserialize() of xo-server/src/models/*.mjs, mirrored line for line
#
# JS semantics that decide the bytes:
#   * assigning an existing key keeps its position, a new key is appended (Python dicts too)
#   * a key set to `undefined` is dropped by JSON.stringify: modelled by popping it
#   * JSON.parse of a non-string coerces with String(): numbers and booleans parse to
#     themselves, objects throw
# --------------------------------------------------------------------------------------

_UNDEF = object()


def js_json_parse(v):
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8")
    if isinstance(v, str):
        return json.loads(v)
    if v is None or isinstance(v, (bool, int, float)):
        return v
    raise ValueError("not parseable")


def parse_prop(obj, name, default):
    """models/utils.mjs parseProp: null / '' / absent -> default; unparsable -> default."""
    v = obj.get(name)
    if v is None or v == "":
        return default
    try:
        return js_json_parse(v)
    except (ValueError, TypeError):
        return default


def set_or_drop(obj, key, value):
    if value is _UNDEF:
        obj.pop(key, None)
    else:
        obj[key] = value


def js_truthy(v):
    if isinstance(v, float) and math.isnan(v):
        return False
    return bool(v)


def js_to_number(v):
    """Unary plus."""
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if v is None or v is _UNDEF:
        return float("nan")            # +undefined -> NaN -> JSON null
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return 0
        try:
            return int(s)
        except ValueError:
            try:
                return float(s)
            except ValueError:
                return float("nan")
    return float("nan")


def unser_user(u):
    if "permission" not in u:
        u["permission"] = "none"
    set_or_drop(u, "authProviders", parse_prop(u, "authProviders", _UNDEF))
    set_or_drop(u, "groups", parse_prop(u, "groups", []))
    set_or_drop(u, "preferences", parse_prop(u, "preferences", {}))


def unser_group(g):
    set_or_drop(g, "users", parse_prop(g, "users", []))


def unser_server(s):
    s["allowUnauthorized"] = s.get("allowUnauthorized") == "true"
    s["enabled"] = s.get("enabled") == "true"
    if js_truthy(s.get("error")):
        s["error"] = parse_prop(s, "error", "")
    else:
        s.pop("error", None)
    s["readOnly"] = s.get("readOnly") == "true"
    if js_truthy(s.get("poolMembersAddresses")):
        s["poolMembersAddresses"] = parse_prop(s, "poolMembersAddresses", [])
    else:
        s.pop("poolMembersAddresses", None)
    if s.get("httpProxy") == "":
        del s["httpProxy"]


def unser_remote(r):
    set_or_drop(r, "benchmarks", parse_prop(r, "benchmarks", _UNDEF))
    en = r.get("enabled")
    r["enabled"] = en if isinstance(en, bool) else en == "true"
    set_or_drop(r, "error", parse_prop(r, "error", r.get("error", _UNDEF)))


def unser_plugin(m):
    m["autoload"] = m.get("autoload") == "true"
    conf = m.get("configuration", _UNDEF)
    if conf is _UNDEF:
        m.pop("configuration", None)
    elif not js_truthy(conf):
        m["configuration"] = conf
    else:
        try:
            m["configuration"] = js_json_parse(conf)
        except (ValueError, TypeError):
            log("warning: cannot parse pluginMetadata.configuration of %r; exporting [] like xo-server does" % m.get("id"))
            m["configuration"] = []


def unser_token(t):
    if "client" in t:
        client = js_json_parse(t["client"])
        c = dict(client) if isinstance(client, dict) else {}
        if "client_id" in t:
            c["id"] = t["client_id"]
        else:
            c.pop("id", None)
        t["client"] = c
        t.pop("client_id", None)
    if "created_at" in t:
        t["created_at"] = js_to_number(t["created_at"])
    t["expiration"] = js_to_number(t.get("expiration", _UNDEF))


def unser_schedule(s):
    en = s.get("enabled")
    if not isinstance(en, bool):
        s["enabled"] = en == "true"
    if "job" in s:
        s["jobId"] = s["job"]
        del s["job"]


def unser_job(j):
    for k in list(j.keys()):
        try:
            v = js_json_parse(j[k])
        except (ValueError, TypeError):
            continue
        if k == "userId" and isinstance(v, (int, float)) and not isinstance(v, bool):
            v = js_number_str(v)
        j[k] = v


def unser_acl(a):
    # models/acl.mjs Acls.get() rewrites a record with no action (pre-2016 data) and
    # recomputes its id. Read-only here: default the action, keep the id, say so.
    if not js_truthy(a.get("action")):
        a["action"] = "admin"
        log("warning: acl %r had no action; xo-server would rewrite it with a new id on export" % a.get("id"))


UNSERIALIZERS = {
    "user": unser_user, "group": unser_group, "server": unser_server, "remote": unser_remote,
    "plugin": unser_plugin, "token": unser_token, "schedule": unser_schedule, "job": unser_job,
    "acl": unser_acl,
}


def read_redis_section(r, namespace, unserializer, crypto):
    """collection/redis.mjs _get({}): SMEMBERS <prefix>_ids, then _extract: GET <prefix>:<id>
    (HGETALL when it is a legacy hash), JSON.parse, _unserialize, model.id = id. A key that
    is gone is skipped, exactly as _extract skips undefined."""
    prefix = "xo:" + namespace
    ids = r.call("SMEMBERS", prefix + "_ids")
    if not isinstance(ids, list):
        raise RedisError("%s_ids is not a set" % prefix)
    ids = [i.decode("utf-8") for i in ids]
    out = []
    legacy = []   # node-redis answers a hash's GET with WRONGTYPE; _extract then issues
                  # hGetAll, a second round trip, so those resolve - and are pushed - after
                  # every string record. Same order here.
    for ident in ids:
        key = "%s:%s" % (prefix, ident)
        try:
            raw = r.call("GET", key)
        except RedisError as exc:
            if "WRONGTYPE" not in str(exc):
                raise
            legacy.append(ident)
            continue
        if raw is None:
            continue
        text = raw.decode("utf-8")
        if text.startswith(ENCRYPTION_PREFIX):
            text = crypto.decrypt(text)
        model = json.loads(text)
        if not isinstance(model, dict):
            raise RedisError("%s is not a JSON object" % key)
        if unserializer:
            UNSERIALIZERS[unserializer](model)
        model["id"] = ident
        out.append(model)
    for ident in legacy:
        flat = r.call("HGETALL", "%s:%s" % (prefix, ident))
        model = {}
        for i in range(0, len(flat), 2):
            model[flat[i].decode("utf-8")] = flat[i + 1].decode("utf-8")
        if unserializer:
            UNSERIALIZERS[unserializer](model)
        model["id"] = ident
        out.append(model)
    return out


# --------------------------------------------------------------------------------------
# leveldb, read from the files: varints, snappy, SSTable (.ldb), WAL (.log), MANIFEST
# --------------------------------------------------------------------------------------

def _varint(buf, pos):
    shift = 0
    result = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def snappy_decompress(src):
    n, pos = _varint(src, 0)
    out = bytearray()
    L = len(src)
    while pos < L:
        tag = src[pos]
        pos += 1
        t = tag & 3
        if t == 0:
            ln = tag >> 2
            if ln >= 60:
                nb = ln - 59
                ln = int.from_bytes(src[pos:pos + nb], "little")
                pos += nb
            ln += 1
            out += src[pos:pos + ln]
            pos += ln
            continue
        if t == 1:
            ln = 4 + ((tag >> 2) & 7)
            off = ((tag >> 5) << 8) | src[pos]
            pos += 1
        elif t == 2:
            ln = (tag >> 2) + 1
            off = int.from_bytes(src[pos:pos + 2], "little")
            pos += 2
        else:
            ln = (tag >> 2) + 1
            off = int.from_bytes(src[pos:pos + 4], "little")
            pos += 4
        if off == 0 or off > len(out):
            raise ValueError("bad snappy copy offset")
        start = len(out) - off
        if off >= ln:
            out += out[start:start + ln]
        else:
            pat = bytes(out[start:])
            out += (pat * (ln // off + 1))[:ln]
    if len(out) != n:
        raise ValueError("snappy length mismatch (%d != %d)" % (len(out), n))
    return bytes(out)


def _read_block(data, off, size):
    body = data[off:off + size]
    typ = data[off + size]
    if typ == 1:
        body = snappy_decompress(body)
    elif typ != 0:
        raise ValueError("unsupported block compression type %d" % typ)
    return body


def _block_entries(block):
    nrest = int.from_bytes(block[-4:], "little")
    end = len(block) - 4 - 4 * nrest
    pos = 0
    key = b""
    while pos < end:
        shared, pos = _varint(block, pos)
        nonshared, pos = _varint(block, pos)
        vlen, pos = _varint(block, pos)
        key = key[:shared] + block[pos:pos + nonshared]
        pos += nonshared
        val = block[pos:pos + vlen]
        pos += vlen
        yield key, val


_TABLE_MAGIC = bytes.fromhex("57fb808b247547db")  # 0xdb4775248b80fb57 little-endian


def table_entries(data):
    """(user_key, sequence, type, value) for every entry of an SSTable; type 1 = value, 0 = deletion."""
    if len(data) < 48 or data[-8:] != _TABLE_MAGIC:
        raise ValueError("not a leveldb table (bad footer magic)")
    footer = data[-48:]
    _, p = _varint(footer, 0)
    _, p = _varint(footer, p)
    ioff, p = _varint(footer, p)
    isz, p = _varint(footer, p)
    index = _read_block(data, ioff, isz)
    for _, handle in _block_entries(index):
        boff, q = _varint(handle, 0)
        bsz, q = _varint(handle, q)
        for ikey, val in _block_entries(_read_block(data, boff, bsz)):
            num = int.from_bytes(ikey[-8:], "little")
            yield ikey[:-8], num >> 8, num & 0xFF, val


def log_records(data):
    """Reassembled records of a leveldb log-format file (WAL and MANIFEST). A torn tail,
    which a copy taken while xo-server is appending can have, ends the stream cleanly."""
    BLOCK = 32768
    pos = 0
    L = len(data)
    buf = b""
    while pos + 7 <= L:
        left = BLOCK - (pos % BLOCK)
        if left < 7:
            pos += left
            continue
        ln = int.from_bytes(data[pos + 4:pos + 6], "little")
        typ = data[pos + 6]
        pos += 7
        if pos + ln > L:
            break
        frag = data[pos:pos + ln]
        pos += ln
        if typ == 1:
            yield frag
            buf = b""
        elif typ == 2:
            buf = frag
        elif typ == 3:
            buf += frag
        elif typ == 4:
            buf += frag
            yield buf
            buf = b""
        elif typ == 0 and ln == 0:
            continue                    # kZeroType padding
        else:
            break


def wal_entries(data):
    for rec in log_records(data):
        if len(rec) < 12:
            continue
        seq = int.from_bytes(rec[:8], "little")
        count = int.from_bytes(rec[8:12], "little")
        pos = 12
        for i in range(count):
            typ = rec[pos]
            pos += 1
            kl, pos = _varint(rec, pos)
            key = rec[pos:pos + kl]
            pos += kl
            val = None
            if typ == 1:
                vl, pos = _varint(rec, pos)
                val = rec[pos:pos + vl]
                pos += vl
            yield key, seq + i, typ, val


def manifest_live_tables(data):
    """The live table file numbers according to the MANIFEST (a log of VersionEdits)."""
    live = set()
    for rec in log_records(data):
        pos = 0
        while pos < len(rec):
            tag, pos = _varint(rec, pos)
            if tag == 1:                    # comparator name
                n, pos = _varint(rec, pos)
                pos += n
            elif tag in (2, 3, 4, 9):       # log number, next file, last sequence, prev log
                _, pos = _varint(rec, pos)
            elif tag == 5:                  # compact pointer
                _, pos = _varint(rec, pos)
                n, pos = _varint(rec, pos)
                pos += n
            elif tag == 6:                  # deleted file
                _, pos = _varint(rec, pos)
                f, pos = _varint(rec, pos)
                live.discard(f)
            elif tag == 7:                  # new file
                _, pos = _varint(rec, pos)
                f, pos = _varint(rec, pos)
                _, pos = _varint(rec, pos)
                n, pos = _varint(rec, pos)
                pos += n
                n, pos = _varint(rec, pos)
                pos += n
                live.add(f)
            else:
                raise ValueError("unknown MANIFEST tag %d" % tag)
    return live


class LevelDBSnapshot:
    """A private copy of a leveldb directory, merged to latest-value-per-key.

    Copying first is what makes this safe next to a running xo-server: it keeps appending
    to the .log and may compact at any moment; nothing here touches its files after the
    copy, and the copy's torn tail (if any) is handled by log_records. Sequence numbers are
    global and monotonic, so 'highest sequence wins' is correct across every table and log
    regardless of level or age; the MANIFEST decides which tables are live so a file that
    a compaction is about to delete is not read.
    """

    def __init__(self, directory, verbose=False):
        self.directory = directory
        self.tmp = None
        self.verbose = verbose
        self._best = None
        if not os.path.isdir(directory):
            raise ExportError("leveldb directory %s does not exist" % directory)
        try:
            listing = os.listdir(directory)     # EACCES here, before anything is created
        except OSError as exc:
            raise ExportError("cannot read leveldb directory: %s" % exc)
        self.tmp = tempfile.mkdtemp(prefix="%s-leveldb-" % NAME)
        os.chmod(self.tmp, 0o700)
        names = []
        try:
            for name in listing:
                if name.endswith((".ldb", ".sst", ".log")) or name == "CURRENT" or name.startswith("MANIFEST-"):
                    shutil.copyfile(os.path.join(directory, name), os.path.join(self.tmp, name))
                    names.append(name)
        except OSError as exc:
            self.close()
            raise ExportError("cannot copy leveldb files: %s" % exc)
        self.names = sorted(names)

    def close(self):
        if self.tmp is not None:
            shutil.rmtree(self.tmp, ignore_errors=True)
            self.tmp = None

    def _load(self):
        best = {}
        live = None
        try:
            with open(os.path.join(self.tmp, "CURRENT")) as fh:
                current = fh.read().strip()
            with open(os.path.join(self.tmp, current), "rb") as fh:
                live = manifest_live_tables(fh.read())
        except (OSError, ValueError, IndexError) as exc:
            log("warning: leveldb MANIFEST unreadable (%s); reading every table file present" % exc)
        ntab = nlog = 0
        for name in self.names:
            path = os.path.join(self.tmp, name)
            if name.endswith((".ldb", ".sst")):
                num = int(name.split(".")[0])
                if live is not None and num not in live:
                    if self.verbose:
                        log("leveldb: skipping %s (not live per MANIFEST)" % name)
                    continue
                with open(path, "rb") as fh:
                    data = fh.read()
                try:
                    entries = list(table_entries(data))
                except (ValueError, IndexError) as exc:
                    raise ExportError("leveldb table %s unreadable: %s" % (name, exc))
                ntab += 1
            elif name.endswith(".log"):
                with open(path, "rb") as fh:
                    data = fh.read()
                try:
                    entries = list(wal_entries(data))
                except (ValueError, IndexError) as exc:
                    raise ExportError("leveldb log %s unreadable: %s" % (name, exc))
                nlog += 1
            else:
                continue
            for ukey, seq, typ, val in entries:
                cur = best.get(ukey)
                if cur is None or seq > cur[0]:
                    best[ukey] = (seq, typ, val)
        if ntab == 0 and nlog == 0:
            raise ExportError("no leveldb table or log files in %s" % self.directory)
        if self.verbose:
            log("leveldb: %d table(s), %d log(s), %d distinct key(s)" % (ntab, nlog, len(best)))
        self._best = best

    def items(self, prefix):
        """(key-without-prefix, raw value bytes) in key order, live entries only."""
        if self._best is None:
            self._load()
        p = prefix.encode("utf-8")
        out = []
        for k in sorted(self._best):
            if k.startswith(p):
                seq, typ, val = self._best[k]
                if typ == 1:
                    out.append((k[len(p):].decode("utf-8"), val))
        return out


NODE_LEVELDB_READER = r"""
const M = process.env.XO_NODE_MODULES
const levelup = require(M + '/level-party')
const sublevel = require(M + '/subleveldown')
const db = levelup(process.env.XO_LEVELDB)
const names = process.env.XO_SUBLEVELS.split(',')
const out = {}
;(async () => {
  for (const ns of names) {
    out[ns] = await new Promise((resolve, reject) => {
      const a = []
      sublevel(db, ns, { valueEncoding: 'utf8' })
        .createReadStream()
        .on('data', d => a.push([String(d.key), String(d.value)]))
        .on('error', reject)
        .on('end', () => resolve(a))
    })
  }
  process.stdout.write(JSON.stringify(out))
  db.close(() => process.exit(0))
})().catch(e => { console.error(e); process.exit(1) })
"""


def leveldb_leader_alive(directory):
    """Is a level-party leader (xo-server) serving this directory right now?"""
    sock_path = os.path.join(directory, "level-party.sock")
    if not os.path.exists(sock_path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(2)
        s.connect(sock_path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def leveldb_via_node(app_dir, directory, sublevels):
    """Cross-check path only: read through xo-server's own level-party + subleveldown as a
    FOLLOWER of the running xo-server. Refused when no leader is alive, because level-party
    would then open the database itself and run leveldb recovery, which writes."""
    if not app_dir:
        raise ExportError("--leveldb node needs the xo-server directory (--xo-server-dir)")
    node = shutil.which("node")
    if not node:
        raise ExportError("node not found")
    if not leveldb_leader_alive(directory):
        raise ExportError("no level-party leader is serving %s (xo-server not running): the node reader "
                          "would open the database for writing. Use the default python reader." % directory)
    nm = os.path.join(app_dir, "node_modules")
    fd, path = tempfile.mkstemp(prefix="%s-lv-" % NAME, suffix=".cjs")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(NODE_LEVELDB_READER)
        env = dict(os.environ, XO_NODE_MODULES=nm, XO_LEVELDB=directory, XO_SUBLEVELS=",".join(sublevels))
        res = subprocess.run([node, path], env=env, capture_output=True, timeout=120)
    finally:
        os.unlink(path)
    if res.returncode != 0:
        raise ExportError("node leveldb reader failed: %s" % res.stderr.decode("utf-8", "replace").strip())
    data = json.loads(res.stdout.decode("utf-8"))
    return {ns: [(k, v.encode("utf-8")) for k, v in rows] for ns, rows in data.items()}


# --------------------------------------------------------------------------------------
# the leveldb sections' normalize(): resource-sets.mjs and ip-pools.mjs
# --------------------------------------------------------------------------------------

def js_or(v, default):
    return v if js_truthy(v) else default


def normalize_resource_set(s):
    limits = s.get("limits")
    if js_truthy(limits) and isinstance(limits, dict):
        out_limits = {}
        for k, limit in limits.items():
            if isinstance(limit, dict):
                nl = dict(limit)
                if nl.get("usage") is None:
                    nl["usage"] = 0
                out_limits[k] = nl
            else:
                out_limits[k] = {"total": limit, "usage": 0}
    else:
        out_limits = {}
    return {
        "id": s.get("id"),
        "ipPools": js_or(s.get("ipPools"), []),
        "limits": out_limits,
        "name": js_or(s.get("name"), ""),
        "objects": js_or(s.get("objects"), []),
        "subjects": js_or(s.get("subjects"), []),
        "shareByDefault": js_or(s.get("shareByDefault"), False),
        "tags": js_or(s.get("tags"), []),
    }


def normalize_ip_pool(p):
    if "id" not in p:
        raise ExportError("ipPool without id: %r" % p)
    out = {}
    if "addresses" in p:
        out["addresses"] = p["addresses"]
    out["id"] = p["id"]
    out["name"] = p["name"] if "name" in p else ""
    if "networks" in p:
        out["networks"] = p["networks"]
    if "resourceSets" in p:
        out["resourceSets"] = p["resourceSets"]
    return out


NORMALIZERS = {"resourceSet": normalize_resource_set, "ipPool": normalize_ip_pool}


# --------------------------------------------------------------------------------------
# JSON.stringify, byte for byte (verified against node on 2000+ generated cases)
# --------------------------------------------------------------------------------------

def js_number_str(x):
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if abs(x) < 2 ** 53:
            return str(x)
        x = float(x)                    # JS parsed it as a double and lost the same precision
    if math.isnan(x) or math.isinf(x):
        return "null"
    if x == 0:
        return "0"
    r = repr(x)
    sign = ""
    if r[0] == "-":
        sign = "-"
        r = r[1:]
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    k = len(digits)
    n = exp - len(fp) + k
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


_SHORT_ESC = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r", 34: '\\"', 92: "\\\\"}
_ESC_RE = re.compile("[\\x00-\\x1f\"\\\\\ud800-\udfff]")


def js_quote(s):
    def rep(m):
        o = ord(m.group(0))
        return _SHORT_ESC.get(o) or "\\u%04x" % o
    return '"' + _ESC_RE.sub(rep, s) + '"'


def _is_array_index(k):
    if not k or not k.isascii() or not k.isdigit():
        return False
    if len(k) > 1 and k[0] == "0":
        return False
    return int(k) < 4294967295


def js_key_order(d):
    idx = [k for k in d if _is_array_index(k)]
    if not idx:
        return list(d)
    idx.sort(key=int)
    return idx + [k for k in d if not _is_array_index(k)]


def js_stringify(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return js_number_str(v)
    if isinstance(v, str):
        return js_quote(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(js_stringify(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(js_quote(k) + ":" + js_stringify(v[k]) for k in js_key_order(v)) + "}"
    raise TypeError("cannot stringify %r" % type(v))


def gzip_like_node(data):
    """zlib's own gzip framing (mtime 0, OS 3 on unix), level 6 = node's default. A web UI
    export's header is byte-identical; the deflate payload may not be (different zlib
    builds), which is why comparisons are made on the content."""
    c = zlib.compressobj(6, zlib.DEFLATED, 31)
    return c.compress(data) + c.flush()


def gpg_symmetric(payload, passphrase):
    """The UI's .enc is openpgp.js symmetric encryption over the (gzipped) export; gpg
    produces an OpenPGP symmetric message openpgp.js decrypts (verified against xo-server's
    own openpgp 5.11 on the appliance). The passphrase travels over a pipe, never argv,
    and gpg works in a private empty home so it neither reads nor creates ~/.gnupg."""
    gpg = shutil.which("gpg") or shutil.which("gpg2")
    if not gpg:
        raise ExportError("gpg not found; cannot produce an encrypted export")
    home = tempfile.mkdtemp(prefix="%s-gpg-" % NAME)
    os.chmod(home, 0o700)
    rfd, wfd = os.pipe()
    try:
        os.write(wfd, passphrase.encode("utf-8"))
        os.close(wfd)
        args = [gpg, "--batch", "--yes", "--quiet", "--no-tty", "--pinentry-mode", "loopback",
                "--homedir", home, "--passphrase-fd", str(rfd),
                "--symmetric", "--cipher-algo", "AES256", "--digest-algo", "SHA256",
                "--s2k-mode", "3", "--s2k-digest-algo", "SHA256", "--s2k-count", "65011712",
                "--compress-algo", "none", "--output", "-"]
        res = subprocess.run(args, input=payload, capture_output=True, pass_fds=(rfd,), timeout=120)
    finally:
        os.close(rfd)
        shutil.rmtree(home, ignore_errors=True)
    if res.returncode != 0 or not res.stdout:
        raise ExportError("gpg failed: %s" % res.stderr.decode("utf-8", "replace").strip())
    return res.stdout


# --------------------------------------------------------------------------------------
# the recovery bundle: everything a rebuild might want, not only what importConfig reads
# --------------------------------------------------------------------------------------

def redis_fresh_dump(r, args, redis_cfg, dest):
    """A fresh RDB via `redis-cli --rdb` (the replication path: the server forks and streams
    a dump, its own files are untouched). None if redis-cli is missing or it fails."""
    cli = shutil.which("redis-cli")
    if not cli:
        return None
    cmd = [cli]
    sock = args.redis_socket or redis_cfg.get("socket")
    env = dict(os.environ)
    if sock:
        cmd += ["-s", sock]
    else:
        u = urlparse(args.redis or redis_cfg.get("uri") or DEFAULT_REDIS_URI)
        cmd += ["-h", u.hostname or "localhost", "-p", str(u.port or 6379)]
        if u.password:
            env["REDISCLI_AUTH"] = unquote(u.password)
        if u.username:
            cmd += ["--user", unquote(u.username)]
        if u.scheme == "rediss":
            cmd += ["--tls"]
    cmd += ["--rdb", dest]
    try:
        res = subprocess.run(cmd, env=env, capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if res.returncode != 0 or not os.path.exists(dest) or os.path.getsize(dest) == 0:
        return None
    return dest


def write_bundle(path, stamp, export_name, export_bytes, snap, redis_dump, config_files, app_dir, notes, verbose=False):
    """A tar.gz, mode 0600, with a MANIFEST.json naming and hashing every member."""
    top = "%s-bundle_%s" % (NAME, stamp)
    manifest = {"tool": NAME, "version": VERSION, "created": stamp, "hostname": platform.node(),
                "notes": notes, "items": []}

    def _sha(fp):
        h = hashlib.sha256()
        with open(fp, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        def add_bytes(arcname, data, note):
            ti = tarfile.TarInfo(top + "/" + arcname)
            ti.size = len(data)
            ti.mode = 0o600
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(data))
            manifest["items"].append({"path": arcname, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "note": note})

        def add_file(arcname, fp, note):
            st = os.stat(fp)
            ti = tar.gettarinfo(fp, top + "/" + arcname)
            ti.mode = 0o600
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            with open(fp, "rb") as fh:
                tar.addfile(ti, fh)
            manifest["items"].append({"path": arcname, "bytes": st.st_size, "sha256": _sha(fp),
                                      "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(), "note": note})

        add_bytes(export_name, export_bytes, "the config export, importable through the web UI")
        if redis_dump is not None:
            add_file("redis/dump.rdb", redis_dump[0], redis_dump[1])
        if snap is not None and snap.tmp is not None:
            for name in snap.names:
                add_file("leveldb/" + name, os.path.join(snap.tmp, name), "copy of %s" % os.path.join(snap.directory, name))
        for cf in config_files:
            add_file("config" + cf, cf, "xo-server config file (app-conf order)")
        versions = []
        if app_dir:
            try:
                with open(os.path.join(app_dir, "package.json")) as fh:
                    versions.append("xo-server %s (%s)" % (json.load(fh).get("version"), app_dir))
            except (OSError, ValueError):
                pass
        for exe, flag in (("redis-server", "--version"), ("node", "--version"), ("python3", "--version")):
            p = shutil.which(exe)
            if p:
                try:
                    res = subprocess.run([p, flag], capture_output=True, timeout=10)
                    versions.append((res.stdout or res.stderr).decode("utf-8", "replace").strip())
                except (OSError, subprocess.TimeoutExpired):
                    pass
        try:
            with open("/etc/os-release") as fh:
                versions.append(fh.read().strip())
        except OSError:
            pass
        versions.append("uname: %s %s" % (platform.system(), platform.release()))
        add_bytes("versions.txt", ("\n".join(versions) + "\n").encode("utf-8"), "what produced this bundle")
        mtext = json.dumps(manifest, indent=1).encode("utf-8")
        ti = tarfile.TarInfo(top + "/MANIFEST.json")
        ti.size = len(mtext)
        ti.mode = 0o600
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(mtext))
    return manifest


# --------------------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------------------

def expand_entries(entries):
    """exportConfig({entries}) adds each entry's dependencies, recursively."""
    out = []

    def add(e):
        if e not in ALL_SECTIONS:
            raise ExportError("unknown entry %r; known: %s" % (e, ", ".join(ALL_SECTIONS)))
        if e not in out:
            out.append(e)
            for d in DEPENDENCIES[e]:
                add(d)
    for e in entries:
        e = e.strip()
        if e:
            add(e)
    return [s for s in ALL_SECTIONS if s in out]


def read_passphrase(args):
    if args.passphrase_file:
        try:
            with open(args.passphrase_file, "rb") as fh:
                pw = fh.read()
        except OSError as exc:
            raise ExportError("cannot read passphrase file: %s" % exc)
        pw = pw.decode("utf-8").rstrip("\r\n")
    elif os.environ.get(PASSPHRASE_ENV):
        pw = os.environ[PASSPHRASE_ENV]
    else:
        return None
    if not pw:
        raise ExportError("empty passphrase")
    return pw


def build_parser():
    ap = argparse.ArgumentParser(prog=NAME, description=__doc__.split("\n\n")[0],
                                 epilog="Full notes: `pydoc %s` or the header of this file." % os.path.basename(sys.argv[0] or NAME),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", help="output file (default: ./XO-config_<UTC>.json.gz[.enc]); '-' for stdout")
    ap.add_argument("--no-gzip", action="store_true", help="write plain JSON (the web UI gzips by default)")
    ap.add_argument("--check", action="store_true", help="print what would be exported and from where; write nothing")
    ap.add_argument("--entries", metavar="A,B", help="subset of sections; dependencies are added like the API does")
    ap.add_argument("--bundle", nargs="?", const=True, metavar="FILE",
                    help="also write a recovery bundle tar.gz (export + fresh redis dump + leveldb copy + config files)")
    ap.add_argument("--passphrase-file", metavar="FILE",
                    help="encrypt the export with this passphrase (OpenPGP symmetric, like the web UI's .enc); or set $%s" % PASSPHRASE_ENV)
    ap.add_argument("--redis", metavar="URI", help="redis URI (default: xo-server's config, else %s)" % DEFAULT_REDIS_URI)
    ap.add_argument("--redis-socket", metavar="PATH", help="redis unix socket path")
    ap.add_argument("--rdb", metavar="DUMP.RDB", help="do not contact redis; read this dump through a temporary private redis-server "
                                                    "(happens automatically with %s when redis is unreachable)" % DEFAULT_RDB)
    ap.add_argument("--datadir", help="xo-server datadir (default: from config, else %s)" % DEFAULT_DATADIR)
    ap.add_argument("--xo-server-dir", help="installed xo-server package dir (default: resolved from `xo-server` on PATH)")
    ap.add_argument("--leveldb", choices=["python", "node", "both"], default="python",
                    help="resourceSets/ipPools reader: python (default, read-only file parser), node (xo-server's own "
                         "level-party, only while xo-server runs), both (cross-check, fail on mismatch)")
    ap.add_argument("--partial", action="store_true",
                    help="omit a section that cannot be read and continue, exit 1 (importConfig skips absent sections)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version="%s %s" % (NAME, VERSION))
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)

    if hasattr(os, "geteuid") and os.geteuid() != 0 and not (args.redis or args.redis_socket or args.rdb):
        # Measured as the appliance's `xoa` user: /etc/xo-server is mode 644 with no x bit,
        # so even config.toml is EACCES, and the leveldb directory is 0700 root.
        raise ExportError("run as root (`sudo -i` first): xo-server's config directory and its leveldb directory are "
                          "not readable otherwise. To read a redis you can reach anyway, pass --redis / --redis-socket "
                          "explicitly (and --partial to skip resourceSets/ipPools).")

    passphrase = read_passphrase(args)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    app_dir = xo_server_dir(args.xo_server_dir)
    cfg = {"_files": []}
    try:
        cfg = load_xo_config(app_dir, args.verbose)
    except ExportError as exc:
        if args.redis or args.redis_socket or args.rdb:
            log("note: %s (continuing on the explicit redis endpoint)" % exc)
        else:
            raise
    redis_cfg = cfg.get("redis") or {}
    datadir = args.datadir or cfg.get("datadir") or DEFAULT_DATADIR
    leveldb_dir = os.path.join(datadir, "leveldb")
    crypto = CredentialCrypto(datadir)
    if redis_cfg.get("encryptCredentialDatabase"):
        log("note: redis.encryptCredentialDatabase is set in xo-server's config")

    wanted = expand_entries(args.entries.split(",")) if args.entries else list(ALL_SECTIONS)
    want_bundle = args.bundle is not None

    result = {}
    failures = []
    notes = []
    sources = {}

    # -- redis half ------------------------------------------------------------------
    r = temp_redis = None
    redis_dump = None
    try:
        r, temp_redis, redis_desc = connect_redis(args, redis_cfg, args.verbose)
        notes.append(redis_desc)
        if args.verbose:
            log("source: %s" % redis_desc)
        for key, namespace, unser, _deps in REDIS_SECTIONS:
            if key not in wanted:
                continue
            try:
                result[key] = read_redis_section(r, namespace, unser, crypto)
                sources[key] = "redis xo:%s" % namespace
            except (ExportError, ValueError, UnicodeDecodeError, OSError) as exc:
                if not args.partial:
                    raise ExportError("%s: %s" % (key, exc))
                failures.append((key, str(exc)))
                log("PARTIAL: %s omitted: %s" % (key, exc))
        if want_bundle and not args.check:
            if temp_redis is None:
                dest = os.path.join(tempfile.mkdtemp(prefix="%s-dump-" % NAME), "dump.rdb")
                got = redis_fresh_dump(r, args, redis_cfg, dest)
                if got:
                    redis_dump = (got, "fresh RDB streamed from the live redis with `redis-cli --rdb` at %s" % stamp)
                else:
                    shutil.rmtree(os.path.dirname(dest), ignore_errors=True)
                    d = r.config_get("dir") or "/var/lib/redis"
                    n = r.config_get("dbfilename") or "dump.rdb"
                    fp = os.path.join(d, n)
                    if os.path.exists(fp):
                        redis_dump = (fp, "copy of the server's own %s (redis-cli --rdb unavailable); may be older than the export" % fp)
                    else:
                        notes.append("no redis dump in bundle: redis-cli --rdb failed and %s does not exist" % fp)
            else:
                redis_dump = (os.path.join(temp_redis.tmp, "dump.rdb"), "copy of the dump the export was read from (redis was down)")
        # -- leveldb half --------------------------------------------------------------
        lv_wanted = [(k, ns, norm) for k, ns, norm, _d in LEVELDB_SECTIONS if k in wanted]
        snap = None
        try:
            if lv_wanted or want_bundle:
                raw = {}
                try:
                    if args.leveldb in ("python", "both") or want_bundle:
                        snap = LevelDBSnapshot(leveldb_dir, args.verbose)
                        for _k, ns, _n in lv_wanted:
                            raw[ns] = snap.items("!%s!" % ns)
                    if lv_wanted and args.leveldb in ("node", "both"):
                        via_node = leveldb_via_node(app_dir, leveldb_dir, [ns for _k, ns, _n in lv_wanted])
                        if args.leveldb == "both":
                            for _k, ns, _n in lv_wanted:
                                if via_node.get(ns) != raw.get(ns):
                                    raise ExportError("leveldb cross-check mismatch on %s: python=%r node=%r" % (ns, raw.get(ns), via_node.get(ns)))
                            if args.verbose:
                                log("leveldb: python and node readers agree on %s" % ", ".join(ns for _k, ns, _n in lv_wanted))
                        else:
                            raw = via_node
                    for key, ns, norm in lv_wanted:
                        rows = []
                        for ident, val in raw[ns]:
                            rows.append(NORMALIZERS[norm](json.loads(val.decode("utf-8"))))
                        result[key] = rows
                        sources[key] = "leveldb !%s! (%s)" % (ns, "node" if args.leveldb == "node" else "files")
                    if lv_wanted:
                        notes.append("leveldb copy of %s" % leveldb_dir)
                except (ExportError, ValueError, OSError) as exc:
                    if not args.partial:
                        raise ExportError("leveldb: %s" % exc)
                    for key, _ns, _n in lv_wanted:
                        failures.append((key, str(exc)))
                        log("PARTIAL: %s omitted: %s" % (key, exc))
                    if want_bundle:
                        notes.append("no leveldb copy in bundle: %s" % exc)

            ordered = {k: result[k] for k in ALL_SECTIONS if k in result}

            # -- --check: say, do not write -------------------------------------------
            if args.check:
                width = max(len(k) for k in ALL_SECTIONS)
                print("%-*s  %7s  %s" % (width, "section", "records", "source"))
                for k in ALL_SECTIONS:
                    if k in ordered:
                        print("%-*s  %7d  %s" % (width, k, len(ordered[k]), sources.get(k, "")))
                    elif k in wanted:
                        print("%-*s  %7s  %s" % (width, k, "-", "FAILED: " + dict(failures).get(k, "?")))
                for n in notes:
                    print("note: " + n)
                print("%s %s: %d section(s), %d record(s); nothing written" % (
                    NAME, VERSION, len(ordered), sum(len(v) for v in ordered.values())))
                return 1 if failures else 0

            # -- the export -----------------------------------------------------------
            text = js_stringify(ordered)
            payload = text.encode("utf-8")
            suffix = ".json"
            if not args.no_gzip:
                payload = gzip_like_node(payload)
                suffix += ".gz"
            if passphrase is not None:
                payload = gpg_symmetric(payload, passphrase)
                suffix += ".enc"
            export_name = "XO-config_%s%s" % (stamp, suffix)

            if args.output == "-":
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.flush()
                out_name = "<stdout>"
            else:
                out_name = args.output or export_name
                try:
                    fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(payload)
                except OSError as exc:
                    raise ExportError("cannot write %s: %s" % (out_name, exc))

            bundle_name = None
            if want_bundle:
                bundle_name = args.bundle if isinstance(args.bundle, str) else "%s-bundle_%s.tar.gz" % (NAME, stamp)
                try:
                    manifest = write_bundle(bundle_name, stamp, export_name, payload, snap, redis_dump,
                                            cfg.get("_files", []), app_dir, notes, args.verbose)
                except OSError as exc:
                    raise ExportError("cannot write bundle %s: %s" % (bundle_name, exc))
                if args.verbose:
                    for it in manifest["items"]:
                        log("bundle: %-40s %9d B  %s" % (it["path"], it["bytes"], it["note"]))
        finally:
            if snap is not None:
                snap.close()
            if redis_dump is not None and temp_redis is None and redis_dump[0].startswith(tempfile.gettempdir()):
                shutil.rmtree(os.path.dirname(redis_dump[0]), ignore_errors=True)
    finally:
        if r is not None:
            r.close()
        if temp_redis is not None:
            temp_redis.close()

    log("%s %s: wrote %s (%d sections, %d record(s), %d bytes%s%s); sources: %s%s%s" % (
        NAME, VERSION, out_name, len(ordered), sum(len(v) for v in ordered.values()), len(payload),
        "" if args.no_gzip else " gzipped", ", encrypted" if passphrase is not None else "",
        "; ".join(notes) or "none",
        "; bundle %s" % bundle_name if bundle_name else "",
        "; PARTIAL, omitted: %s" % ", ".join(k for k, _ in failures) if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ExportError as exc:
        log("ERROR: %s" % exc)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
