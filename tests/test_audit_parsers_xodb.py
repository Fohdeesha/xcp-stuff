# -*- coding: utf-8 -*-
"""Parser and xo-db fixes from the 2026-11-24 audit (C, F findings)."""

import pytest

import colors
import parsers
import transport
import xodb

from test_backup_routes import POOL_UUID, PROXY, SR_HERE, VM_HERE, job, on, smart


@pytest.fixture(autouse=True)
def fresh_cache():
    xodb.reset_cache()
    yield
    xodb.reset_cache()


# --------------------------------------------------------------------------------------
# small parser corrections
# --------------------------------------------------------------------------------------

def test_a_phrase_matches_across_case_and_runs_of_whitespace():
    text = "a line\nDevice-Mapper:  multipath:   Failing path 8:48.\nother\n"
    assert parsers.find_phrase_lines(text, "device-mapper: multipath: failing path") == [2]
    assert parsers.find_phrase_lines(text, "   ") == []


def test_an_rpm_epoch_is_not_the_version():
    assert parsers.leading_version("1:9.2.11-1.xcpng8.3") == "9.2.11"
    assert parsers.leading_version("9.2.11-1") == "9.2.11"
    assert parsers.leading_version("") == ""


def test_multipathd_idle_is_alive_and_startup_is_not():
    assert parsers.multipathd_alive("pid 1305 running\n")
    assert parsers.multipathd_alive("pid 1305 idle\n")
    assert not parsers.multipathd_alive("pid 1305 startup\n")
    assert not parsers.multipathd_alive("")


def test_strip_ansi_removes_any_control_sequence_and_nothing_after_it():
    """A list of final letters ate text after any other sequence: after ESC[2d a whole
    line of xoa-updater output vanished up to the next listed letter."""
    assert colors.strip_ansi("\x1b[2dAll up to date") == "All up to date"
    assert colors.strip_ansi("\x1b[1;32mOK\x1b[0m done") == "OK done"
    assert colors.strip_ansi("\x1b[?25lspinner\x1b[?25h") == "spinner"
    assert colors.strip_ansi("plain") == "plain"


def test_timedatectl_n_a_is_an_established_no():
    assert parsers.parse_timedatectl("NTP service: n/a\nSystem clock synchronized: n/a\n") \
        == {"ntp": "no", "sync": "no"}


def test_an_ipv6_gateway_on_a_non_management_pif_counts():
    assert parsers.parse_dns_gw_pifs("IPv6-gateway ( RO): fd00::1\n") is True
    assert parsers.parse_dns_gw_pifs("IPv6-gateway ( RO): \n") is False


# --------------------------------------------------------------------------------------
# Backup Network: whose jobs move the pool's data (F01, F02, F10)
# --------------------------------------------------------------------------------------

def runners(jobs, schedules=None):
    return parsers.backup_runners(jobs, schedules, POOL_UUID, {VM_HERE}, {SR_HERE})


def test_a_proxied_job_that_only_may_touch_the_pool_keeps_the_xoa_in():
    """A tag-narrowed smart job can not be told to reach this pool or not: it must not
    take the XOA out of the answer, or a pool the XOA backs up reads green."""
    tagged = job("1", smart({"__or": [POOL_UUID]}, tags={"__and": ["prod"]}), proxy=PROXY)
    # and the proxy is not named as a route this pool's data is known to take
    assert runners([tagged], on("1")) == (True, [])


def test_a_proxied_tag_only_job_keeps_the_xoa_in():
    tagged = job("1", smart(tags={"__and": ["prod"]}), proxy=PROXY)
    assert runners([tagged], on("1"))[0] is True


def test_a_proxied_job_that_certainly_touches_the_pool_takes_the_xoa_out():
    certain = job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY)
    assert runners([certain], on("1")) == (False, [PROXY])


def test_a_job_pinned_to_a_deleted_proxy_is_an_error_not_a_route(monkeypatch):
    """XO fails such a job, so nothing moves that traffic: 'through a proxy' would be
    green over backups that do not run."""
    import xoredis
    store = {"job": [job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY)],
             "schedule": on("1"), "proxy": [{"id": "some-other-proxy", "name": "x"}]}
    monkeypatch.setattr(transport, "which", lambda b: "/usr/local/bin/" + b)
    monkeypatch.setattr(xoredis, "read_records",
                        lambda cli, ns, *a, **kw: [dict(r) for r in store.get(ns, [])])
    routes = xodb.backup_routes(None, POOL_UUID, {VM_HERE}, {SR_HERE})
    assert "no longer exists" in routes["error"] and PROXY in routes["error"]


# --------------------------------------------------------------------------------------
# xo-server-db's own output (F06, F14, F15, F19)
# --------------------------------------------------------------------------------------

RECORDS = ("{ enabled: 'true', host: '192.0.2.13', label: 'a', password: 'p1' }\n"
           "{ enabled: 'true', host: '192.0.2.14', label: 'b', password: 'p2' }\n")


def _cli(monkeypatch, rc, out, err=""):
    seen = {}

    def fake(argv, timeout=None, env=None, stdin_text=None):
        seen["argv"], seen["env"] = argv, env
        return (rc, out, err)
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    return seen


def test_ls_reads_only_what_follows_the_header_and_quiets_the_log(monkeypatch):
    """An INFO line from xo-server's startup with a lone quote in it would throw the
    record scanner off for the rest of the output."""
    seen = _cli(monkeypatch, 0, "INFO it's starting {\n2 record(s) found\n" + RECORDS)
    body, why = xodb._ls(["server"])
    assert why == "" and body.lstrip().startswith("{ enabled")
    assert len(xodb.scan_records(body)) == 2
    assert seen["env"]["LOG_LEVEL"] == "warn"


def test_ls_accepts_a_failed_exit_after_every_record_was_printed(monkeypatch):
    _cli(monkeypatch, 1, "2 record(s) found\n" + RECORDS, "ClientClosedError")
    body, why = xodb._ls(["server"])
    assert why == "" and len(xodb.scan_records(body)) == 2


def test_ls_refuses_a_failed_exit_with_records_missing(monkeypatch):
    _cli(monkeypatch, 1, "3 record(s) found\n" + RECORDS, "ClientClosedError: boom")
    body, why = xodb._ls(["server"])
    assert body is None and "ClientClosedError" in why


def test_a_value_util_inspect_cut_short_is_not_parsed(monkeypatch):
    monkeypatch.setattr(transport, "which", lambda b: "")
    _cli(monkeypatch, 0, "1 record(s) found\n{ id: 'j1', vms: '{\"id\":{\"__or\":[\"a\"'"
                         "... 4123 more characters }\n")
    records, why = xodb.collection("job")
    assert records == [] and "cut short" in why


def test_a_json_parse_error_quoting_a_record_is_withheld():
    why = xodb._describe_failure(
        1, "SyntaxError: Unexpected token } in JSON at position 41: {\"password\":\"hunter2\"")
    assert "hunter2" not in why and "withheld" in why


# --------------------------------------------------------------------------------------
# which record answers, and as whom (F11, F12, F13, F17)
# --------------------------------------------------------------------------------------

def test_an_enabled_record_wins_over_a_disabled_one_for_the_same_address():
    stale = {"id": "a", "enabled": "false", "host": "192.0.2.5", "password": "old"}
    live = {"id": "b", "enabled": "true", "host": "192.0.2.5", "password": "new"}
    assert xodb.match_record("192.0.2.5", [stale, live])[0] is live
    assert xodb.match_record("192.0.2.5", [live, stale])[0] is live


def test_ties_are_settled_the_same_way_whatever_order_redis_listed_them():
    one = {"id": "1", "enabled": "true", "host": "192.0.2.5"}
    two = {"id": "2", "enabled": "true", "host": "192.0.2.5"}
    assert xodb.match_record("192.0.2.5", [one, two])[0] is \
        xodb.match_record("192.0.2.5", [two, one])[0]


def test_the_record_user_is_read():
    assert xodb.record_user({"username": "root"}) == "root"
    assert xodb.record_user({"username": " xoauditor "}) == "xoauditor"
    assert xodb.record_user({}) == "" and xodb.record_user(None) == ""


def test_punctuation_sorts_before_digits_and_digits_before_letters():
    """node's localeCompare on the test XOA gave exactly this order."""
    names = ["Pool", "alpha", "1st Avenue", "~lab", "#1 site", "(old) pool", "_infra",
             u"Øst-Pool", u"Ärger"]
    assert sorted(names, key=xodb._sort_key) == [
        "_infra", "(old) pool", "#1 site", "~lab", "1st Avenue", "alpha", u"Ärger",
        u"Øst-Pool", "Pool"]
