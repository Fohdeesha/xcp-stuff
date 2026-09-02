# -*- coding: utf-8 -*-
"""The util.inspect scanner, and the one db read a run is allowed.

Every scanner case here is one that broke the old parsers.
"""

import pytest

import transport
import xodb


def test_plain_single_quoted():
    text = "{ host: '192.168.1.5', label: 'XEN-MAIN-01', enabled: 'true' }"
    recs = xodb.scan_records(text)
    assert recs == [{"host": "192.168.1.5", "label": "XEN-MAIN-01", "enabled": "true"}]


def test_double_quoted_when_value_has_an_apostrophe():
    # util.inspect switches quote character per value
    text = "{ label: \"Bob's Pool\", host: '10.0.0.1' }"
    recs = xodb.scan_records(text)
    assert recs[0]["label"] == "Bob's Pool"
    assert recs[0]["host"] == "10.0.0.1"


def test_backtick_when_value_has_both_quote_kinds():
    text = "{ label: `it's \"x\"`, host: '10.0.0.2' }"
    recs = xodb.scan_records(text)
    assert recs[0]["label"] == "it's \"x\""


def test_brace_inside_a_value_does_not_split_the_record():
    # the block-regex parser this replaced split here and lost the password
    text = "{ host: '10.0.0.3', password: 'a}b{c', label: 'P' }"
    recs = xodb.scan_records(text)
    assert len(recs) == 1
    assert recs[0]["password"] == "a}b{c"
    assert recs[0]["label"] == "P"


def test_nested_json_in_the_error_field():
    text = ("{ error: { code: 'ECONNREFUSED', data: { a: 1 } }, "
            "host: '10.0.0.4', label: 'P4' }")
    recs = xodb.scan_records(text)
    assert len(recs) == 1
    assert recs[0]["host"] == "10.0.0.4"
    assert recs[0]["label"] == "P4"


def test_bare_values():
    text = "{ host: '10.0.0.5', enabled: true, n: 42, x: null }"
    recs = xodb.scan_records(text)
    assert recs[0]["enabled"] == "true"
    assert recs[0]["n"] == "42"
    assert recs[0]["x"] == "null"


def test_escape_forms():
    cases = {
        r"a\nb": "a\nb",
        r"a\tb": "a\tb",
        r"a\'b": "a'b",
        r"a\\b": "a\\b",
        r"a\x41b": "aAb",
        r"aAb": "aAb",
        r"a\u{1F600}b": u"a\U0001F600b",
    }
    for raw, want in cases.items():
        recs = xodb.scan_records("{ password: '" + raw + "', host: 'h' }")
        assert recs[0]["password"] == want, raw


def test_multiple_records_in_one_stream():
    text = ("{ host: '1.1.1.1', label: 'A' }\n"
            "{ host: '2.2.2.2', label: 'B' }\n")
    recs = xodb.scan_records(text)
    assert [r["host"] for r in recs] == ["1.1.1.1", "2.2.2.2"]


def test_sort_is_numeric_and_case_insensitive():
    names = ["pool 10", "Pool 2", "POOL 1", "alpha"]
    assert sorted(names, key=xodb._sort_key) == ["alpha", "POOL 1", "Pool 2", "pool 10"]


def test_sort_puts_digits_before_letters():
    # ICU root collation, which is what node's localeCompare uses. This decides which
    # pool a no-args non-interactive run picks, so it is not cosmetic.
    names = ["XEN-PRIMARY", "1st Avenue", "XEN-SECONDARY"]
    assert sorted(names, key=xodb._sort_key) == ["1st Avenue", "XEN-PRIMARY", "XEN-SECONDARY"]


def test_clean_collapses_whitespace():
    assert xodb.clean("  a \t b\nc ") == "a b c"
    assert xodb.clean(None) == ""


# --------------------------------------------------------------------------------------
# one `xo-server-db ls server` per run
# --------------------------------------------------------------------------------------
# Measured on the live appliance: 3.3s per invocation, and a narrower query costs the same
# - it is node starting, loading xo-server's app-conf and opening a redis connection, not
# the query. A run used to make two (the picker, then the password) and sometimes three,
# which was over half its wall clock. Verified there too: `ls server` answers with whole
# records, so the indexed `host=` lookup returned nothing the first call had not.

DB = (
    r"{ enabled: 'true', host: '192.168.1.13', label: 'sec-01',"
    r" poolNameLabel: 'XEN-SECONDARY', password: 'p13' }" "\n"
    r"{ enabled: 'true', host: '192.168.4.16', label: 'east-01',"
    r" poolNameLabel: '2028 East', password: 'p16' }" "\n"
    r"{ host: 'http://192.168.1.229', label: 'never-connected', password: 'p229' }" "\n"
    r"{ enabled: 'false', host: '192.168.1.99', label: 'switched-off',"
    r" poolNameLabel: 'OFF', password: 'p\\99' }" "\n"
)


class FakeDb(object):
    """Stands in for the xo-server-db binary, counting how often it is really run."""

    def __init__(self, text=DB, rc=0, err=""):
        self.text = text
        self.rc = rc
        self.err = err
        self.calls = []

    def __call__(self, argv, timeout=None, env=None, stdin_text=None):
        self.calls.append(list(argv))
        return (self.rc, self.text if self.rc == 0 else "", self.err)


@pytest.fixture(autouse=True)
def fresh_cache():
    """The cache is per-run state; a test process is many runs."""
    xodb.reset_cache()
    yield
    xodb.reset_cache()


@pytest.fixture
def db(monkeypatch):
    fake = FakeDb()
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    monkeypatch.setattr(xodb, "have_xo_server_db", lambda: True)
    return fake


def test_the_db_is_read_once_however_many_questions_are_asked(db):
    xodb.enabled_servers()
    xodb.password_for("192.168.1.13")
    xodb.password_for("192.168.4.16")
    xodb.pool_name_for_host("192.168.1.13")
    xodb.select_pool("sec")
    assert db.calls == [["xo-server-db", "ls", "server"]]


def test_the_password_comes_out_of_that_scan_and_not_a_second_lookup(db):
    assert xodb.password_for("192.168.1.13") == ("p13", False)
    assert xodb.password_for("192.168.4.16") == ("p16", False)
    assert not [c for c in db.calls if any(a.startswith("host=") for a in c)]


def test_a_disabled_server_still_yields_its_password(db):
    """The picker's 'enabled' filter must not narrow the password lookup.

    The indexed lookup it replaces was not filtered, and a host named as an argument may
    perfectly well be one XO has disabled.
    """
    assert xodb.password_for("192.168.1.99") == ("p" + chr(92) + "99", True)
    assert xodb.password_for("http://192.168.1.229") == ("p229", False)
    # ...while the picker still lists only the enabled ones
    assert [r.host for r in xodb.enabled_servers()] == ["192.168.4.16", "192.168.1.13"]


def test_a_host_the_db_does_not_know_has_no_password(db):
    assert xodb.password_for("10.9.9.9") == (None, False)
    assert xodb.pool_name_for_host("10.9.9.9") == ""


# what `xo-server-db ls server` writes to stderr as a non-root user on the appliance
# (Debian 12): /etc/xo-server is mode 644, so even the stat of config.toml is refused
EACCES = (
    "[Error: EACCES: permission denied, lstat '/etc/xo-server/config.toml'] {\n"
    "  errno: -13,\n"
    "  code: 'EACCES',\n"
    "  syscall: 'lstat',\n"
    "  path: '/etc/xo-server/config.toml'\n"
    "}\n"
)


def test_a_db_that_cannot_be_read_is_not_asked_twice(monkeypatch):
    """Failure is cached like any other answer: every lookup answers 'nothing' either
    way, and asking again costs another 3.3s to fail again. But it is cached WITH its
    reason, and the picker reports that reason instead of an empty pool list."""
    fake = FakeDb(rc=1, err=EACCES)
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    monkeypatch.setattr(xodb, "have_xo_server_db", lambda: True)
    assert xodb.enabled_servers() == []
    assert xodb.password_for("192.168.1.13") == (None, False)
    assert xodb.select_pool("")[0] == xodb.SELECT_UNREADABLE
    assert xodb.select_pool("sec")[0] == xodb.SELECT_UNREADABLE
    assert xodb.read_error() == (
        "exit code 1: Error: EACCES: permission denied, lstat '/etc/xo-server/config.toml'")
    assert len(fake.calls) == 1


def test_an_unreadable_db_is_not_reported_as_an_empty_one():
    """'No enabled hosts found in xo-db' was what a non-root run said on an appliance
    with five pools. SELECT_NONE is a statement about the db's contents, so it needs the
    db to have been read."""
    assert xodb.SELECT_UNREADABLE != xodb.SELECT_NONE


def test_a_db_with_no_enabled_server_is_still_none_and_not_an_error(monkeypatch):
    fake = FakeDb(text="{ enabled: 'false', host: '10.0.0.1', label: 'off' }\n")
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    monkeypatch.setattr(xodb, "have_xo_server_db", lambda: True)
    assert xodb.select_pool("")[0] == xodb.SELECT_NONE
    assert xodb.read_error() == ""


def test_an_empty_db_is_none_too(monkeypatch):
    fake = FakeDb(text="")
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    assert xodb.select_pool("")[0] == xodb.SELECT_NONE
    assert xodb.read_error() == ""


def test_the_failure_description_names_the_cause():
    # the transport's own 'could not exec' - the binary is not on PATH at all
    assert xodb._describe_failure(127, "xo-server-db: [Errno 2] No such file or directory") \
        == "exit code 127: xo-server-db: [Errno 2] No such file or directory"
    # a timeout leaves no stderr behind, and 'exit code 124' would not say what happened
    assert xodb._describe_failure(124, "") == "timed out after 30s"
    # a failure that said nothing at all still reports as a failure, not as 'no pools'
    assert xodb._describe_failure(3, "") == "exit code 3"
    assert xodb._describe_failure(3, "\n  \n") == "exit code 3"
    # the first line is the informative one; the node object dump after it is not
    assert xodb._describe_failure(1, EACCES) == (
        "exit code 1: Error: EACCES: permission denied, lstat '/etc/xo-server/config.toml'")
    assert xodb._describe_failure(1, "  plain message  \nmore\n") == "exit code 1: plain message"


def test_reset_cache_forgets_the_failure_as_well(monkeypatch):
    fake = FakeDb(rc=1, err="boom")
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    assert xodb.select_pool("")[0] == xodb.SELECT_UNREADABLE
    xodb.reset_cache()
    monkeypatch.setattr(transport, "run_local_cmd", FakeDb())
    assert xodb.read_error() == ""
    assert xodb.select_pool("")[0] == xodb.SELECT_OK


def test_the_picker_order_is_the_sorted_one_the_cache_did_not_reorder(db):
    """2028 East is entry 1, not entry 3 - digits before letters, ICU root collation.
    This decides which pool a no-args cron run checks."""
    assert [r.name for r in xodb.enabled_servers()] == ["2028 East", "XEN-SECONDARY"]
    assert xodb.select_pool("")[1].name == "2028 East"


def test_reset_cache_really_forgets(db):
    xodb.enabled_servers()
    xodb.reset_cache()
    xodb.enabled_servers()
    assert len(db.calls) == 2
