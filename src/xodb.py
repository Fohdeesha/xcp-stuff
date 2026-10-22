# -*- coding: utf-8 -*-
"""Reading XOA's server records: the pool picker and the root-password lookup.

Deliberately goes through `xo-server-db` and not redis directly. When xo-server config
sets redis.encryptCredentialDatabase the WHOLE record is stored AES-encrypted under
xo:server:<id> (and the indexes are HMACed), so a raw redis GET returns ciphertext;
xo-server-db decrypts transparently and honours whatever redis connection the config
points at. Only `host` is indexed, so `enabled` cannot be filtered in the db either.

Its output is `console.log(sortKeys(record))` - node's util.inspect, NOT JSON. inspect
picks the quote character per value, so a pool named  Bob's Pool  comes out in double
quotes and one containing both kinds comes out in backticks; values also contain braces
(the `error` field holds raw JSON) and backslash escapes. So this is a small string-aware
scanner rather than a regex over {...} blocks - the block-regex approach silently reported
the wrong pool name, because it could not match non-single-quoted values and a `}` inside
a password split one record into two.

Values are only ever read as data. Nothing here evaluates anything.
"""

import re
import socket
import sys
import threading
import time
import unicodedata

import colors
import config
import parsers
import transport
import xoredis

QUOTES = "'\"`"

_ESCAPE_RE = re.compile(r"\\(u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|.)", re.S)
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
_KEY_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*")


def unescape(text):
    """Every escape form util.inspect can emit.

    The old line-oriented awk kept \\n and \\' verbatim and so returned a password that
    was subtly wrong - which fails as an authentication error a long way from the cause.
    """
    def replace(m):
        for group in (2, 3, 4):
            if m.group(group) is not None:
                return chr(int(m.group(group), 16))
        char = m.group(1)
        return _SIMPLE_ESCAPES.get(char, char)
    return _ESCAPE_RE.sub(replace, text)


def scan_records(text):
    """util.inspect output -> list of dicts, in db order."""
    records = []
    i = 0
    n = len(text)

    def read_quoted():
        """text[i] is an opening quote; consume through the matching close."""
        nonlocal_i = i
        quote = text[nonlocal_i]
        nonlocal_i += 1
        raw = []
        while nonlocal_i < n and text[nonlocal_i] != quote:
            if text[nonlocal_i] == "\\":
                raw.append(text[nonlocal_i])
                nonlocal_i += 1
                if nonlocal_i < n:
                    raw.append(text[nonlocal_i])
                    nonlocal_i += 1
                continue
            raw.append(text[nonlocal_i])
            nonlocal_i += 1
        nonlocal_i += 1
        return unescape("".join(raw)), nonlocal_i

    while i < n:
        char = text[i]
        if char in QUOTES:
            _, i = read_quoted()
            continue
        if char != "{":
            i += 1
            continue
        i += 1
        record = {}
        depth = 1
        while i < n and depth > 0:
            char = text[i]
            if char in QUOTES:
                _, i = read_quoted()
                continue
            if char in "{[":
                depth += 1
                i += 1
                continue
            if char in "}]":
                depth -= 1
                i += 1
                continue
            if depth == 1:
                m = _KEY_RE.match(text, i)
                if m:
                    i = m.end()
                    if i < n and text[i] in QUOTES:
                        value, i = read_quoted()
                        record[m.group(1)] = value
                    elif i < n and text[i] not in "{[":
                        bare = []
                        while i < n and text[i] not in ",}\n":
                            bare.append(text[i])
                            i += 1
                        record[m.group(1)] = "".join(bare).strip()
                    # a nested {/[ falls through to the depth tracking above
                    continue
            i += 1
        records.append(record)
    return records


def clean(value):
    """Collapse all whitespace. This is what guarantees no field can contain a tab, which
    is what lets the rows be tab separated - pool names may legitimately contain '|'."""
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _sort_key(name):
    """localeCompare(undefined, {numeric: true, sensitivity: 'base'}) in Python.

    Case- and accent-insensitive, with digit runs compared as numbers, so 'Pool 10' sorts
    after 'Pool 9'. The order matters beyond cosmetics: it is also the non-interactive
    fallback order, so a cron run with no -n takes entry #1 of THIS ordering.
    """
    folded = unicodedata.normalize("NFKD", clean(name).lower())
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    parts = []
    for chunk in re.split(r"(\d+)", folded):
        if chunk.isdigit():
            # digits sort BEFORE letters in the root collation ICU gives localeCompare,
            # so a pool named '1st Avenue' is menu entry 1, not 3. Verified against node
            # on the live db - getting this backwards silently changes which pool a
            # no-args cron run checks.
            parts.append((0, int(chunk), ""))
        elif chunk:
            parts.append((1, 0, chunk))
    return parts


class Server(object):
    __slots__ = ("host", "name", "search", "record")

    def __init__(self, host, name, search, record=None):
        self.host = host
        self.name = name
        self.search = search
        self.record = record if record is not None else {}


def have_xo_server_db():
    return transport.have("xo-server-db")


_ALL_SERVERS = None     # the one `xo-server-db ls server` scan; None until it is read
_READ_ERROR = ""        # why that scan failed, when it did; "" while it has not
_RESOLVED = {}          # db host name -> frozenset of its addresses, looked up once a run


def _describe_failure(rc, err):
    """One line saying why xo-server-db answered nothing, for the messages that used to
    say 'no enabled hosts' instead.

    The stderr of a permission failure is a node error object spread over several lines,
    of which the first is the one that says what happened:
        [Error: EACCES: permission denied, lstat '/etc/xo-server/config.toml'] {
    """
    if rc == 124:
        return "timed out after %ds" % (config.LOCAL_CMD_TIMEOUT * 3)
    first = ""
    for line in err.splitlines():
        line = line.strip()
        if line:
            first = line
            break
    if first.endswith(" {"):
        first = first[:-2]
    if first.startswith("[") and first.endswith("]"):
        first = first[1:-1]
    if first:
        return "exit code %d: %s" % (rc, first)
    return "exit code %d" % rc


def _ls(args):
    """(output, "") or (None, why-not). rc 127 is the transport's own 'not found'."""
    rc, out, err = transport.run_local_cmd(["xo-server-db", "ls"] + list(args),
                                           timeout=config.LOCAL_CMD_TIMEOUT * 3)
    if rc != 0:
        return None, _describe_failure(rc, err)
    return out, ""


def _read_servers():
    """(records, why-it-failed). Redis directly when that can be trusted, else the CLI.

    The fast path is in xoredis and declines loudly: anything it cannot establish raises
    RedisError and we spend the 3.3s. Its reason is a debug trace and never a health
    finding - a decline is not a failure, it is this code choosing not to guess.
    """
    cli_path = transport.which("xo-server-db")
    if cli_path:
        try:
            records = xoredis.read_server_records(cli_path)
            transport.debug("xo-db: %d record(s) read straight from redis" % len(records))
            return records, ""
        except xoredis.RedisError as exc:
            transport.debug("xo-db: redis declined (%s); asking xo-server-db" % exc)
    out, why = _ls(["server"])
    return (scan_records(out) if out is not None else [], why)


def all_servers():
    """Every server record in the db, read once per run.

    One `xo-server-db ls server` costs ~3.3s on the test appliance, and a narrower query
    costs exactly the same: it is node starting up, importing xo.mjs and running
    `xo.hooks.startCore()`, not the query. It also answers with WHOLE records - password
    field included, disabled servers as well as enabled ones. Measured against the indexed
    `host=` lookup on the live db: 7/7 records, every field equal, passwords equal.

    So the second call the password lookup used to make spent 3.3s re-reading what was
    already in hand, and a run that also had to name its pool made a third. That was
    ~55% of the wall clock of a whole health check.

    That 3.3s is now itself avoidable: none of it is redis. See xoredis - when the
    endpoint and the plaintext can both be established, the same records come back in
    0.03s, and this drops from the biggest item in a run to nothing at all.

    Read from the main thread only, before any host is contacted; nothing else in a run
    touches it, so the cache needs no lock.
    """
    global _ALL_SERVERS, _READ_ERROR
    if _ALL_SERVERS is None:
        # a db that could not be read is cached as empty, with the reason kept beside it:
        # asking again would cost another 3.3s to fail again, and every lookup answers
        # 'nothing' either way - but the messages built on that answer must not. Run as a
        # non-root user, xo-server-db cannot even stat /etc/xo-server/config.toml, and
        # 'no enabled hosts found in xo-db' was what an appliance with five pools said.
        _ALL_SERVERS, _READ_ERROR = _read_servers()
    return _ALL_SERVERS


def read_error():
    """Why the scan produced nothing, or '' when it was read - so a caller holding an empty
    answer can tell an empty db from one it never got to see. Reads the db if needed."""
    all_servers()
    return _READ_ERROR


def reset_cache():
    """Forget the scan. For tests - a real run reads the db once and then exits."""
    global _ALL_SERVERS, _READ_ERROR
    _ALL_SERVERS = None
    _READ_ERROR = ""
    _RESOLVED.clear()


def enabled_servers():
    """The enabled pools, sorted for display. [] if the db has none we can use."""
    rows = []
    for rec in all_servers():
        if str(rec.get("enabled")) != "true" or not rec.get("host"):
            continue
        # poolNameLabel only exists once XO has connected to the pool at least once, so
        # the label fallback is load-bearing rather than paranoia
        pool_name = clean(rec.get("poolNameLabel"))
        label = clean(rec.get("label"))
        name = pool_name or label or "(unnamed)"
        # -n matches EITHER name: a pool can show as XEN-PRIMARY while the server label a
        # user remembers it by is XEN-MAIN-01
        rows.append(Server(rec["host"], name, (pool_name + " " + label).lower(), rec))
    rows.sort(key=lambda r: _sort_key(r.name))
    return rows


# --------------------------------------------------------------------------------------
# which record an address belongs to
# --------------------------------------------------------------------------------------
# A record's `host` is whatever was typed into XO - an IP, a name, sometimes with a scheme
# or a port - and a pool stored by name used to be invisible to every lookup made with
# one of its addresses: '-n a01 192.0.2.60' took the master's own address for a
# password and failed as a login error, and 'health.py 192.0.2.60' said the master was
# not in xo-db. Three kinds of evidence are tried, strongest first, and a weaker one is
# only consulted when no record at all answers to a stronger one.

def db_address(rec):
    """The bare address in a record's `host`, as XO itself reads that field."""
    return parsers.xo_server_address(rec.get("host") or "")[0]


def _same_address(a, b):
    """Two spellings of one address: case-blind for names, canonical for IPs."""
    if not a or not b:
        return False
    if a.lower() == b.lower():
        return True
    ip = parsers.ip_literal(a)
    return ip is not None and ip == parsers.ip_literal(b)


def _resolve(names):
    """{name: frozenset of its addresses}, each name looked up at most once per run.

    Only ever handed xo-db's own host names - never anything a user typed in the password
    position, which would put a root password into a DNS query. The lookups run at once
    and the whole set gets config.XO_DNS_TIMEOUT: an XOA whose DNS has gone away must
    not hang the run, and a name that has not answered by then has no addresses, which
    makes a match less likely and never more. The threads are daemons, so one wedged in
    the resolver cannot hold the process at exit.
    """
    todo = sorted(set(n for n in names if n and n not in _RESOLVED))
    if todo:
        found = {}

        def lookup(name):
            try:
                infos = socket.getaddrinfo(name, None)
            except (OSError, UnicodeError, ValueError):
                # gaierror is an OSError; an IDNA-invalid name is a UnicodeError and an
                # embedded NUL a ValueError. Each means this name has no address to give.
                found[name] = frozenset()
                return
            found[name] = frozenset(a for a in (parsers.ip_literal(i[4][0]) for i in infos) if a)

        threads = []
        for name in todo:
            t = threading.Thread(target=lookup, args=(name,))
            t.daemon = True
            t.start()
            threads.append(t)
        deadline = time.time() + config.XO_DNS_TIMEOUT
        for t in threads:
            t.join(max(0.0, deadline - time.time()))
        for name in todo:
            _RESOLVED[name] = found.get(name, frozenset())
            if name not in found:
                transport.debug("xo-db: no DNS answer for %s within %ss"
                                % (name, config.XO_DNS_TIMEOUT))
    return dict((n, _RESOLVED.get(n, frozenset())) for n in names)


def match_record(want, records, resolve_want=False):
    """(record, how) for the first record `want` is an address of, or (None, "").

    `how` says what made it a match, for messages that have to explain one:
      "host"    the record's own host field names it
      "member"  it is one of the pool members' addresses XO recorded (poolMembersAddresses,
                xo-server since July 2026), slaves included - which is what lets a slave's
                address find the pool's password, since every member shares it
      "dns"     it and the record's host name resolve to a common address

    DNS is the last resort and only ever resolves xo-db's own names - plus `want` itself
    when the caller says it is a host (resolve_want), never when it may be a password.
    """
    want = (want or "").strip()
    if not want:
        return None, ""
    for rec in records:
        if rec.get("host") == want or _same_address(db_address(rec), want):
            return rec, "host"
    for rec in records:
        if any(_same_address(m, want)
               for m in parsers.pool_member_addresses(rec.get("poolMembersAddresses"))):
            return rec, "member"

    want_ip = parsers.ip_literal(want)
    if want_ip is None and not resolve_want:
        return None, ""
    if want_ip is not None:
        wanted = frozenset([want_ip])
    else:
        wanted = _resolve([want])[want]
        if not wanted:
            return None, ""
        # a name that resolves to an address a record holds outright, or to one of its
        # members' addresses
        for rec in records:
            held = [db_address(rec)] + parsers.pool_member_addresses(
                rec.get("poolMembersAddresses"))
            if any(parsers.ip_literal(a) in wanted for a in held):
                return rec, "dns"
    named = [rec for rec in records if parsers.ip_literal(db_address(rec)) is None]
    resolved = _resolve([db_address(rec) for rec in named])
    for rec in named:
        if resolved.get(db_address(rec), frozenset()) & wanted:
            return rec, "dns"
    return None, ""


def server_for_host(host):
    """(record, how) for a host given as an argument, or (None, "").

    Searched across ALL records, not the enabled ones - a host given as an argument may
    well be a server XO has disabled, and its password must still be found.
    """
    return match_record(host, all_servers(), resolve_want=True)


def password_for(host):
    """(password, has_backslash) or (None, False).

    Answered out of the one scan rather than with a second `xo-server-db ls server
    host=...`: the indexed query returns the same record field for field and costs another
    3.3s (see all_servers).
    """
    rec, _how = server_for_host(host)
    return record_password(rec)


def record_password(rec):
    """(password, has_backslash) or (None, False) for one record."""
    pwd = (rec or {}).get("password")
    if not pwd:
        return (None, False)
    return (pwd, "\\" in pwd)


def enabled_server_for(want, resolve_want=True):
    """(Server, how) among the enabled pools, or (None, ""). resolve_want=False for a
    value that may be a password: it is then matched against what xo-db holds, and only
    xo-db's own names are looked up."""
    if not have_xo_server_db():
        return None, ""
    rows = enabled_servers()
    rec, how = match_record(want, [row.record for row in rows], resolve_want)
    for row in rows:
        if row.record is rec:
            return row, how
    return None, ""


def pool_name_for_host(want, resolve_want=True):
    """The db's name for a host given as an argument, so every run can name its target.

    Quiet and never an error: a pool XO does not manage, or no xo-server-db at all, are
    both normal - it just means the banner prints the address.
    """
    row, _how = enabled_server_for(want, resolve_want)
    return row.name if row is not None else ""


SELECT_OK = 0
SELECT_NONE = 1         # the db was read and lists no enabled pool
SELECT_QUIT = 2
SELECT_NO_MATCH = 3
SELECT_UNREADABLE = 4   # the db could not be read at all - read_error() says why


def select_pool(name_filter, stdin=None, stderr=None):
    """Resolve which pool to check. Returns (code, Server or None).

    Only resolves it - main announces the choice, because the paths that pick silently
    (sole enabled pool, cron/pipe) are exactly the ones where the banner is the only
    record of which pool was taken.
    """
    stdin = stdin if stdin is not None else sys.stdin
    stderr = stderr if stderr is not None else sys.stderr

    rows = enabled_servers()
    if not rows:
        # an empty answer is two different facts, and only one of them is 'no pools'
        return (SELECT_UNREADABLE if read_error() else SELECT_NONE, None)

    if name_filter:
        needle = name_filter.lower()
        for row in rows:
            if needle in row.search:
                return (SELECT_OK, row)
        stderr.write("ERROR: no enabled pool in xo-server-db matches '%s'.\n" % name_filter)
        stderr.write("Enabled pools:\n")
        for row in rows:
            stderr.write("  %s (%s)\n" % (row.name, row.host))
        return (SELECT_NO_MATCH, None)

    try:
        interactive = stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False

    if len(rows) == 1 or not interactive:
        return (SELECT_OK, rows[0])

    stderr.write("\n%s\n" % colors.cyan("== Multiple pools found in XOA =="))
    for i, row in enumerate(rows, 1):
        stderr.write("%d - %s (%s)\n" % (i, row.name, row.host))
    stderr.write("\n")

    while True:
        stderr.write("Select a pool [1-%d], or q to quit: " % len(rows))
        stderr.flush()
        choice = stdin.readline()
        if not choice:            # EOF (ctrl-d) reads as a quit
            return (SELECT_QUIT, None)
        choice = choice.strip()
        if choice in ("q", "Q"):
            return (SELECT_QUIT, None)
        if choice.isdigit() and 1 <= int(choice) <= len(rows):
            stderr.write("\n")
            return (SELECT_OK, rows[int(choice) - 1])
        stderr.write("%s\n" % colors.yellow("Invalid selection."))
