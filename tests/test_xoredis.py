# -*- coding: utf-8 -*-
"""The redis fast path, and every reason it must decline.

The optimisation is only allowed to be right or absent, so most of this file is about
declining. The wire tests run against a real socket rather than a mock: the parser exists
to survive bytes, and a mock would only prove it survives the mock.
"""

import json
import os
import socket
import threading

import pytest

import xodb
import xoredis


# --------------------------------------------------------------------------------------
# a socket that speaks just enough RESP back
# --------------------------------------------------------------------------------------

def bulk(text):
    if text is None:
        return b"$-1\r\n"
    raw = text.encode("utf-8")
    return b"$%d\r\n" % len(raw) + raw + b"\r\n"


def array(items):
    return b"*%d\r\n" % len(items) + b"".join(items)


def read_command(handle):
    """The client's RESP array, as a list of strings."""
    line = handle.readline()
    if not line:
        return None
    assert line[:1] == b"*", line
    argv = []
    for _ in range(int(line[1:-2])):
        head = handle.readline()
        assert head[:1] == b"$", head
        argv.append(handle.read(int(head[1:-2]) + 2)[:-2].decode("utf-8"))
    return argv


class FakeRedis(object):
    """Replies with `replies[i]` to the i'th command, then hangs up."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.commands = []
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.addr = self._listener.getsockname()
        self._thread = threading.Thread(target=self._serve)
        self._thread.daemon = True
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._listener.accept()
        except OSError:          # closed before anyone connected
            return
        try:
            handle = conn.makefile("rb")
            for reply in self.replies:
                argv = read_command(handle)
                if argv is None:
                    break
                self.commands.append(argv)
                conn.sendall(reply)
            handle.close()
        finally:
            conn.close()

    def close(self):
        self._listener.close()
        self._thread.join(timeout=5)


@pytest.fixture
def serve():
    made = []

    def make(replies):
        server = FakeRedis(replies)
        made.append(server)
        return server

    yield make
    for server in made:
        server.close()


RECORDS = {
    "id-a": {"enabled": "true", "host": "192.168.1.13", "label": "sec-01",
             "poolNameLabel": "XEN-SECONDARY", "password": "p13"},
    "id-b": {"host": "192.168.4.16", "label": "2028 East", "enabled": "true",
             "password": "p16"},
}


def ok_replies(records=None):
    records = RECORDS if records is None else records
    ids = list(records)
    return [array([bulk(i) for i in ids]),
            array([bulk(json.dumps(records[i])) for i in ids])]


# --------------------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------------------

def test_the_records_come_back_whole(serve):
    server = serve(ok_replies())
    got = xoredis._fetch(server.addr, timeout=5)
    assert got == [
        {"enabled": "true", "host": "192.168.1.13", "label": "sec-01",
         "poolNameLabel": "XEN-SECONDARY", "password": "p13", "id": "id-a"},
        {"host": "192.168.4.16", "label": "2028 East", "enabled": "true",
         "password": "p16", "id": "id-b"},
    ]


def test_it_asks_smembers_then_one_mget(serve):
    """One MGET, not one GET per record - the whole point is to stop paying per question."""
    server = serve(ok_replies())
    xoredis._fetch(server.addr, timeout=5)
    assert server.commands == [
        ["SMEMBERS", "xo:server_ids"],
        ["MGET", "xo:server:id-a", "xo:server:id-b"],
    ]


def test_a_password_survives_the_wire_exactly(serve):
    """Every escape form that ever came back wrong out of the old awk scanner."""
    hard = "p\\ss'w\"o`rd\n\té\U0001F600"
    server = serve(ok_replies({"x": {"host": "h", "password": hard}}))
    assert xoredis._fetch(server.addr, timeout=5)[0]["password"] == hard


# --------------------------------------------------------------------------------------
# declining
# --------------------------------------------------------------------------------------

def test_an_encrypted_db_is_declined_not_half_parsed(serve):
    """redis.encryptCredentialDatabase stores `enc:<base64>` and the key is half in
    xenstore. xo-xcppool-ssh builds its RedisCollection with no `crypto` and dies on a
    JSON.parse here; this says so and lets xo-server-db answer."""
    server = serve([array([bulk("id-a")]),
                    array([bulk("enc:c29tZSBjaXBoZXJ0ZXh0")])])
    with pytest.raises(xoredis.RedisError, match="encrypted"):
        xoredis._fetch(server.addr, timeout=5)


def test_one_encrypted_record_declines_the_whole_read(serve):
    """A partial answer is the one thing this may never return."""
    server = serve([array([bulk("id-a"), bulk("id-b")]),
                    array([bulk(json.dumps(RECORDS["id-a"])), bulk("enc:AAAA")])])
    with pytest.raises(xoredis.RedisError, match="encrypted"):
        xoredis._fetch(server.addr, timeout=5)


def test_an_empty_id_set_is_declined(serve):
    """No server registered and 'this is not xo-server's redis' look identical from here,
    and only one of them is safe to act on."""
    server = serve([array([])])
    with pytest.raises(xoredis.RedisError, match="empty"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_redis_error_reply_is_declined(serve):
    """What a password-protected redis answers: -NOAUTH."""
    server = serve([b"-NOAUTH Authentication required.\r\n"])
    with pytest.raises(xoredis.RedisError, match="NOAUTH"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_truncated_bulk_string_is_declined(serve):
    server = serve([array([bulk("id-a")]), b"*1\r\n$500\r\nonly-this-much"])
    with pytest.raises(xoredis.RedisError, match="short read"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_hangup_mid_answer_is_declined(serve):
    server = serve([b""])
    with pytest.raises(xoredis.RedisError, match="closed by redis"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_missing_record_is_declined(serve):
    """An id in the set whose key is gone: MGET answers a nil for it."""
    server = serve([array([bulk("id-a")]), array([bulk(None)])])
    with pytest.raises(xoredis.RedisError, match="disappeared"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_short_mget_answer_is_declined(serve):
    server = serve([array([bulk("id-a"), bulk("id-b")]),
                    array([bulk(json.dumps(RECORDS["id-a"]))])])
    with pytest.raises(xoredis.RedisError, match="1 value"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_non_list_mget_reply_declines_rather_than_raising_typeerror(serve):
    """xodb catches RedisError and nothing else; anything else takes the run down instead
    of costing it 3.3s."""
    server = serve([array([bulk("id-a")]), b":7\r\n"])
    with pytest.raises(xoredis.RedisError, match="non-list"):
        xoredis._fetch(server.addr, timeout=5)


def test_a_record_that_is_not_an_object_is_declined(serve):
    server = serve([array([bulk("id-a")]), array([bulk('["not", "a", "record"]')])])
    with pytest.raises(xoredis.RedisError, match="not an object"):
        xoredis._fetch(server.addr, timeout=5)


def test_unparseable_json_is_declined(serve):
    server = serve([array([bulk("id-a")]), array([bulk("{not json")])])
    with pytest.raises(xoredis.RedisError, match="unreadable"):
        xoredis.read_server_records("/nonexistent/dist/db-cli.mjs", server.addr, timeout=5)


def test_a_set_of_non_strings_is_declined(serve):
    server = serve([array([b":7\r\n"])])
    with pytest.raises(xoredis.RedisError, match="not a set"):
        xoredis._fetch(server.addr, timeout=5)


def test_something_that_is_not_redis_at_all_is_declined(serve):
    server = serve([b"HTTP/1.1 200 OK\r\n"])
    with pytest.raises(xoredis.RedisError, match="unexpected reply"):
        xoredis._fetch(server.addr, timeout=5)


def test_nothing_listening_is_declined():
    """The ordinary shape of an install that moved redis: connection refused."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    addr = probe.getsockname()
    probe.close()               # nothing is listening there now
    with pytest.raises(xoredis.RedisError):
        xoredis.read_server_records("/nonexistent/dist/db-cli.mjs", addr, timeout=2)


# --------------------------------------------------------------------------------------
# the endpoint has to be established, not assumed
# --------------------------------------------------------------------------------------

def cli_in(tmp_path, *files):
    """A fake xo-server tree: <app>/dist/db-cli.mjs, with `files` written beside app."""
    app = tmp_path / "xo-server"
    (app / "dist").mkdir(parents=True)
    cli = app / "dist" / "db-cli.mjs"
    cli.write_text("// not really node\n")
    for name, text in files:
        (app / name).write_text(text)
    return str(cli)


@pytest.fixture
def only_app_dir(monkeypatch):
    """Search the fake tree alone - /etc/xo-server and the XDG dir are the real machine's."""
    real = xoredis._config_dirs
    monkeypatch.setattr(xoredis, "_config_dirs", lambda cli: real(cli)[:1])


def test_the_app_dir_is_two_levels_up_from_the_real_cli(tmp_path):
    cli = cli_in(tmp_path, ("config.toml", "[http]\n"))
    assert xoredis._config_dirs(cli)[0] == os.path.join(str(tmp_path), "xo-server")


def test_a_symlinked_cli_resolves_to_the_package(tmp_path):
    """/usr/local/bin/xo-server-db is a symlink into the package; app-conf resolves it."""
    cli = cli_in(tmp_path, ("config.toml", "[http]\n"))
    link = tmp_path / "xo-server-db"
    try:
        link.symlink_to(cli)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink support here")
    assert xoredis._config_dirs(str(link))[0] == os.path.join(str(tmp_path), "xo-server")


def test_a_config_with_no_mention_of_redis_allows_the_fast_path(tmp_path, only_app_dir):
    # what the appliance actually ships
    cli = cli_in(tmp_path,
                 ("config.toml", "[http]\nhostname = 'x'\n"),
                 ("config.xoa.json", '{"http": {"port": 80}}\n'))
    assert xoredis._mentions_redis(cli) is False


def test_any_mention_of_redis_declines(tmp_path, only_app_dir):
    cli = cli_in(tmp_path, ("config.toml", "[redis]\nuri = 'redis://elsewhere:6379'\n"))
    assert xoredis._mentions_redis(cli) is True


def test_encryption_being_switched_on_is_itself_a_mention(tmp_path, only_app_dir):
    """The records would be `enc:` anyway, so the two guards agree - but this one costs
    no connection."""
    cli = cli_in(tmp_path, ("config.toml", "[redis]\nencryptCredentialDatabase = true\n"))
    assert xoredis._mentions_redis(cli) is True


def test_a_mention_in_a_non_toml_config_declines_too(tmp_path, only_app_dir):
    """app-conf globs config.* and reads json/json5/ini/yaml as well, so this is a byte
    search and not a toml parse."""
    cli = cli_in(tmp_path, ("config.toml", "[http]\n"),
                 ("config.z-auto.json", '{"redis": {"socket": "/run/redis.sock"}}'))
    assert xoredis._mentions_redis(cli) is True


def test_the_search_is_case_insensitive(tmp_path, only_app_dir):
    cli = cli_in(tmp_path, ("config.toml", "[REDIS]\nURI = 'x'\n"))
    assert xoredis._mentions_redis(cli) is True


def test_files_that_are_not_config_star_are_not_read(tmp_path, only_app_dir):
    cli = cli_in(tmp_path, ("config.toml", "[http]\n"), ("notes.txt", "redis lives here"))
    assert xoredis._mentions_redis(cli) is False


def test_a_config_that_cannot_be_read_declines(tmp_path, only_app_dir, monkeypatch):
    """Unreadable is not the same as 'contains no redis'."""
    cli = cli_in(tmp_path, ("config.toml", "[http]\n"))

    def denied(path, mode="r", **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("builtins.open", denied)
    with pytest.raises(xoredis.RedisError, match="cannot read"):
        xoredis._mentions_redis(cli)


def test_a_directory_that_cannot_be_listed_declines(tmp_path, monkeypatch):
    def denied(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "listdir", denied)
    with pytest.raises(xoredis.RedisError, match="cannot list"):
        xoredis._config_files(str(tmp_path))


def test_a_missing_directory_is_simply_no_files(tmp_path):
    assert xoredis._config_files(str(tmp_path / "nope")) == []


def test_the_gate_runs_before_any_connection(tmp_path, only_app_dir, serve):
    """A config mentioning redis must not even be probed - the endpoint we would probe is
    the one it is telling us not to trust."""
    server = serve(ok_replies())
    cli = cli_in(tmp_path, ("config.toml", "[redis]\nuri = 'redis://elsewhere'\n"))
    with pytest.raises(xoredis.RedisError, match="mentions redis"):
        xoredis.read_server_records(cli, server.addr, timeout=5)
    assert server.commands == []


def test_the_gate_passing_reads_the_records(tmp_path, only_app_dir, serve):
    server = serve(ok_replies())
    cli = cli_in(tmp_path, ("config.toml", "[http]\n"))
    got = xoredis.read_server_records(cli, server.addr, timeout=5)
    assert [r["host"] for r in got] == ["192.168.1.13", "192.168.4.16"]


# --------------------------------------------------------------------------------------
# the two paths must stay interchangeable
# --------------------------------------------------------------------------------------

def test_flatten_produces_what_the_inspect_scanner_produces():
    """xodb's callers cannot be able to tell which path answered.

    node's util.inspect prints a bare true/null/42 and the scanner records those words;
    it skips a value that is an object. _flatten has to land on the same dict. XO stores
    every field as a string today, so this is future-proofing - but the day it changes,
    the picker's `str(rec.get("enabled")) != "true"` is what silently breaks.
    """
    inspect_text = ("{ enabled: true, host: '10.0.0.1', n: 42, z: null, "
                    "error: { code: 'ECONNREFUSED' }, id: 'abc' }")
    from_cli = xodb.scan_records(inspect_text)[0]
    from_redis = xoredis._flatten(
        {"enabled": True, "host": "10.0.0.1", "n": 42, "z": None,
         "error": {"code": "ECONNREFUSED"}}, "abc")
    assert from_redis == from_cli
    assert from_redis == {"enabled": "true", "host": "10.0.0.1", "n": "42", "z": "null",
                          "id": "abc"}


def test_flatten_keeps_false_apart_from_missing():
    """`enabled: false` must not arrive as the absent key that means the same thing by
    accident - the picker's filter is a string comparison."""
    assert xoredis._flatten({"enabled": False}, "x") == {"enabled": "false", "id": "x"}


def test_a_string_field_is_passed_through_untouched():
    """What every record on the appliance actually looks like: all strings, `enabled`
    included."""
    assert xoredis._flatten({"enabled": "true", "password": "p"}, "x") == {
        "enabled": "true", "password": "p", "id": "x"}
