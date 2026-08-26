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
import sys
import unicodedata

import colors
import config
import transport

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
    __slots__ = ("host", "name", "search")

    def __init__(self, host, name, search):
        self.host = host
        self.name = name
        self.search = search


def have_xo_server_db():
    return transport.have("xo-server-db")


_ALL_SERVERS = None     # the one `xo-server-db ls server` scan; None until it is read


def _ls(args):
    rc, out, err = transport.run_local_cmd(["xo-server-db", "ls"] + list(args),
                                           timeout=config.LOCAL_CMD_TIMEOUT * 3)
    if rc != 0:
        return None
    return out


def all_servers():
    """Every server record in the db, read once per run.

    One `xo-server-db ls server` costs ~3.3s on the test appliance, and a narrower query
    costs exactly the same: it is node starting up, loading xo-server's app-conf and
    opening a redis connection, not the query. It also answers with WHOLE records -
    password field included, disabled servers as well as enabled ones. Measured against
    the indexed `host=` lookup on the live db: 7/7 records, every field equal, passwords
    equal.

    So the second call the password lookup used to make spent 3.3s re-reading what was
    already in hand, and a run that also had to name its pool made a third. That was
    ~55% of the wall clock of a whole health check.

    Read from the main thread only, before any host is contacted; nothing else in a run
    touches it, so the cache needs no lock.
    """
    global _ALL_SERVERS
    if _ALL_SERVERS is None:
        out = _ls(["server"])
        # a db that could not be read is cached as empty: every caller already treats
        # "no such record" and "could not ask" the same way, and asking again would cost
        # another 3.3s to fail again
        _ALL_SERVERS = scan_records(out) if out is not None else []
    return _ALL_SERVERS


def reset_cache():
    """Forget the scan. For tests - a real run reads the db once and then exits."""
    global _ALL_SERVERS
    _ALL_SERVERS = None


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
        rows.append(Server(rec["host"], name, (pool_name + " " + label).lower()))
    rows.sort(key=lambda r: _sort_key(r.name))
    return rows


def password_for(host):
    """(password, has_backslash) or (None, False).

    Answered out of the one scan rather than with a second `xo-server-db ls server
    host=...`: the indexed query returns the same record field for field and costs another
    3.3s (see all_servers).

    Searched across ALL records, not the enabled ones - a host given as an argument may
    well be a server XO has disabled, and the indexed lookup found its password before.
    """
    for rec in all_servers():
        if rec.get("host") == host:
            pwd = rec.get("password")
            if not pwd:
                return (None, False)
            return (pwd, "\\" in pwd)
    return (None, False)


def pool_name_for_host(want):
    """The db's name for a host given as an argument, so every run can name its target.

    Quiet and never an error: a slave via -s, a pool XO does not manage, or no
    xo-server-db at all are all normal - it just means the banner prints the address.
    """
    if not have_xo_server_db():
        return ""
    for row in enabled_servers():
        # a db host may carry the ':port' XO connects to xapi on
        if row.host == want or row.host.rsplit(":", 1)[0] == want:
            return row.name
    return ""


SELECT_OK = 0
SELECT_NONE = 1
SELECT_QUIT = 2
SELECT_NO_MATCH = 3


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
        return (SELECT_NONE, None)

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
