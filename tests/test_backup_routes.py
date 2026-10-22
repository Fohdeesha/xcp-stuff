# -*- coding: utf-8 -*-
"""Backup Network when the backups do not come from the XOA (issue #71).

'Configured but not fully reachable - No ping answer from XOA for: ...' was reported for a
pool whose backups all run on an XO Proxy, which reaches the hosts itself: the XOA cannot
ping that network by design. XO picks the machine per job (xo-server backups-ng/index.mjs:
a job with `proxy` runs there; any other runs on the XOA, through the server record's HTTP
proxy if one is set), so the question is which jobs touch the pool - and the lab has no
proxy and no backup network, so every state is pinned here.
"""

import json

import pytest

import checks
import collector
import colors
import model
import parsers
import result
import transport
import xodb
import xoredis

OK, FLAG, UNKNOWN = result.OK, result.FLAG, result.UNKNOWN

POOL_UUID = "cab1ae78-be82-2e7c-3828-43c0a567881b"
OTHER_POOL = "55d4887f-c4e2-54c7-ecae-3bcab5599abc"
VM_HERE, VM_THERE = "vm-here-1", "vm-there-1"
SR_HERE, SR_THERE = "sr-here-1", "sr-there-1"
PROXY = "proxy-id-1"


def smart(pool_pattern=None, **extra):
    vms = {"type": "VM"}
    if pool_pattern is not None:
        vms["$pool"] = pool_pattern
    vms.update(extra)
    return json.dumps(vms)


def job(ident, vms=None, proxy=None, kind="backup", **fields):
    """A job record as XO stores it: every non-string field JSON-encoded."""
    rec = {"id": ident, "type": kind, "name": "job " + ident}
    if vms is not None:
        rec["vms"] = vms
    if proxy is not None:
        rec["proxy"] = proxy
    for key, value in fields.items():
        rec[key] = value if isinstance(value, str) else json.dumps(value)
    return rec


def touches(j, vm_uuids=frozenset([VM_HERE]), sr_uuids=frozenset([SR_HERE]),
            pool_uuid=POOL_UUID):
    return parsers.job_touches_pool(j, pool_uuid, vm_uuids, sr_uuids)


# --------------------------------------------------------------------------------------
# value-matcher, as XO evaluates a pool pattern
# --------------------------------------------------------------------------------------

def test_pattern_semantics_match_value_matcher():
    m = parsers.xo_pattern_match
    assert m("a", "a") and not m("a", "b")
    assert m({"__or": ["a", "b"]}, "b") and not m({"__or": ["a", "b"]}, "c")
    assert m({"__and": ["a", {"__not": "b"}]}, "a")
    assert m({"__not": {"__or": ["a"]}}, "b") and not m({"__not": {"__or": ["a"]}}, "a")
    assert m({"__or": []}, "a") is False
    assert m({"__and": []}, "a") is True
    # an array or any other object only ever matches an object or an array
    assert m(["a"], "a") is False
    assert m({"id": "a"}, "a") is False
    assert m({"__or": ["a"], "x": 1}, "a") is False
    assert m(None, "a") is False


def test_a_combinator_over_a_non_list_cannot_be_told():
    with pytest.raises(ValueError):
        parsers.xo_pattern_match({"__or": "a"}, "a")


def test_simple_ids_are_xos_explicit_lists():
    ids = parsers.xo_simple_ids
    assert ids({"id": "x"}) == ["x"]
    assert ids({"id": {"__or": ["x", "y"]}}) == ["x", "y"]
    assert ids({"id": {"__or": []}}) == []
    assert ids({"id": {"__or": ["x", 1]}}) is None
    assert ids({"id": "x", "type": "VM"}) is None
    assert ids({"type": "VM", "$pool": "x"}) is None
    assert ids(None) is None


def test_job_fields_decode_as_xo_decodes_them():
    rec = {"vms": '{"id":"x"}', "proxy": "c0ffee-1", "n": 3}
    assert parsers.job_field(rec, "vms") == {"id": "x"}
    assert parsers.job_field(rec, "proxy") == "c0ffee-1"     # not JSON: kept raw
    assert parsers.job_field(rec, "n") == 3
    assert parsers.job_field(rec, "missing") is None


# --------------------------------------------------------------------------------------
# does a job touch this pool
# --------------------------------------------------------------------------------------

def test_smart_mode_by_pool():
    assert touches(job("1", smart({"__or": [POOL_UUID]}))) is True
    assert touches(job("1", smart({"__or": [OTHER_POOL]}))) is False
    assert touches(job("1", smart({"__not": {"__or": [OTHER_POOL]}}))) is True
    assert touches(job("1", smart(POOL_UUID))) is True


def test_smart_mode_over_every_pool_counts():
    assert touches(job("1", smart(tags={"__or": [["prod"]]}))) is True


def test_vms_picked_by_hand_are_looked_up_in_the_pools_own_uuids():
    assert touches(job("1", json.dumps({"id": {"__or": [VM_THERE, VM_HERE]}}))) is True
    assert touches(job("1", json.dumps({"id": VM_THERE}))) is False
    # the pool's VM list could not be read: not a guess either way
    assert touches(job("1", json.dumps({"id": VM_HERE})), vm_uuids=None) is None


def test_a_replication_into_this_pool_touches_it():
    j = job("1", json.dumps({"id": VM_THERE}), srs={"id": {"__or": [SR_HERE]}})
    assert touches(j) is True
    j = job("1", json.dumps({"id": VM_THERE}), srs={"id": {"__or": []}})
    assert touches(j) is False


def test_a_health_check_restoring_into_this_pool_touches_it():
    j = job("1", json.dumps({"id": VM_THERE}),
            settings={"": {"reportWhen": "always"}, "sched": {"healthCheckSr": SR_HERE}})
    assert touches(j) is True


def test_pool_metadata_backups():
    assert touches(job("1", kind="metadataBackup", pools={"id": {"__or": [POOL_UUID]}})) is True
    assert touches(job("1", kind="metadataBackup", pools={"id": OTHER_POOL})) is False
    # XO's own metadata only - no pool is read
    assert touches(job("1", kind="metadataBackup", xoMetadata="true")) is False


def test_jobs_that_touch_no_pool():
    assert touches(job("1", kind="mirrorBackup")) is False
    assert touches(job("1", kind="call")) is False


def test_what_cannot_be_read_is_none():
    assert touches(job("1", "{not json")) is None
    assert touches(job("1")) is None                       # a VM backup with no pattern
    assert touches(job("1", smart({"__or": "x"}))) is None
    assert touches(job("1", smart({"__or": [POOL_UUID]})), pool_uuid="") is None


def test_the_lab_jobs_read_as_written():
    """Copied from the test appliance's redis (xo-server 5.208.3)."""
    full = {"id": "5bb158af", "type": "backup", "mode": "full",
            "srs": '{"id":{"__or":[]}}',
            "vms": '{"type":"VM","$pool":{"__or":["cab1ae78-be82-2e7c-3828-43c0a567881b"]},'
                   '"tags":{"__not":{"__or":[["usb"]]}}}',
            "settings": '{"31d1fb99":{"exportRetention":3},"":{"reportWhen":"always"}}'}
    meta = {"id": "06e34801", "type": "metadataBackup", "xoMetadata": "true",
            "pools": '{"id":{"__or":["a2650ca4-5d0e-d2ad-f273-fb7fc9b3afe4",'
                     '"55d4887f-c4e2-54c7-ecae-3bcab5599abc",'
                     '"cab1ae78-be82-2e7c-3828-43c0a567881b"]}}'}
    assert touches(full) is True
    assert touches(full, pool_uuid=OTHER_POOL) is False
    assert touches(meta) is True


# --------------------------------------------------------------------------------------
# who moves the pool's data
# --------------------------------------------------------------------------------------

def runners(jobs, schedules=None):
    return parsers.backup_runners(jobs, schedules, POOL_UUID, {VM_HERE}, {SR_HERE})


def on(*job_ids):
    return [{"id": "s-" + j, "jobId": j, "enabled": True} for j in job_ids]


def test_only_proxied_jobs_take_the_xoa_out():
    assert runners([job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY)]) == (False, [PROXY])


def test_a_job_on_the_xoa_keeps_it_in():
    jobs = [job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY),
            job("2", kind="metadataBackup", pools={"id": POOL_UUID})]
    assert runners(jobs) == (True, [PROXY])


def test_no_job_at_all_leaves_the_xoa_as_the_default():
    assert runners([]) == (True, [])
    assert runners([job("1", smart({"__or": [OTHER_POOL]}), proxy=PROXY)]) == (True, [])


def test_a_job_whose_reach_cannot_be_told_counts_on_both_sides():
    assert runners([job("1", json.dumps({"id": VM_HERE}), proxy=PROXY),
                    job("2", "{garbage")]) == (True, [PROXY])


def test_a_job_with_every_schedule_off_moves_nothing():
    jobs = [job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY),
            job("old", smart({"__or": [POOL_UUID]}))]
    schedules = on("1") + [{"id": "s-old", "jobId": "old", "enabled": False}]
    assert runners(jobs, schedules) == (False, [PROXY])
    # a job with no schedule at all does not run by itself either
    assert runners(jobs, on("1")) == (False, [PROXY])


def test_schedules_that_could_not_be_read_count_every_job():
    jobs = [job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY),
            job("old", smart({"__or": [POOL_UUID]}))]
    assert runners(jobs, None) == (True, [PROXY])


def test_the_cli_spelling_of_enabled_counts_too():
    jobs = [job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY)]
    assert runners(jobs, [{"jobId": "1", "enabled": "true"}]) == (False, [PROXY])


def test_each_proxy_is_named_once():
    jobs = [job("1", smart(), proxy=PROXY), job("2", smart(), proxy=PROXY),
            job("3", smart(), proxy="proxy-2")]
    assert runners(jobs) == (False, [PROXY, "proxy-2"])


@pytest.mark.parametrize("url, shown", [
    ("http://proxy.lan:3128", "proxy.lan:3128"),
    ("http://user:secret@proxy.lan:3128", "proxy.lan:3128"),
    ("proxy.lan:8080", "proxy.lan:8080"),
    ("https://[fd00::9]:3128", "[fd00::9]:3128"),
    ("http://10.0.0.9", "10.0.0.9"),
    ("", ""),
    (None, ""),
    ("http://:99999", "(set, address unreadable)"),
])
def test_an_http_proxy_is_shown_without_its_credentials(url, shown):
    assert parsers.http_proxy_address(url) == shown


# --------------------------------------------------------------------------------------
# reading the collections
# --------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_cache():
    xodb.reset_cache()
    yield
    xodb.reset_cache()


@pytest.fixture
def collections(monkeypatch):
    """The fast path answering from a dict of namespace -> records (or an exception)."""
    store = {}
    asked = []

    def read(cli_path, namespace, *args, **kwargs):
        asked.append(namespace)
        answer = store.get(namespace, [])
        if isinstance(answer, Exception):
            raise answer
        return [dict(r) for r in answer]

    monkeypatch.setattr(transport, "which",
                        lambda binary: "/usr/local/bin/" + binary if binary == "xo-server-db" else "")
    monkeypatch.setattr(xoredis, "read_records", read)
    return store, asked


def test_routes_name_the_proxy(collections):
    store, _ = collections
    store["job"] = [job("1", smart({"__or": [POOL_UUID]}), proxy=PROXY)]
    store["schedule"] = on("1")
    store["proxy"] = [{"id": PROXY, "name": "site-b"}]
    routes = xodb.backup_routes({"host": "x"}, POOL_UUID, {VM_HERE}, {SR_HERE})
    assert routes == {"xoa": False, "proxies": ["site-b"], "http_proxy": "", "error": ""}


def test_a_proxy_that_cannot_be_named_is_shown_by_id(collections):
    store, _ = collections
    store["job"] = [job("1", smart(), proxy=PROXY)]
    store["schedule"] = on("1")
    store["proxy"] = xoredis.RedisError("declined")
    # the CLI fallback answers nothing either
    xodb._COLLECTIONS["proxy"] = ([], "exit code 1: boom")
    assert xodb.backup_routes(None, POOL_UUID, None, None)["proxies"] == [PROXY]


def test_the_http_proxy_comes_off_the_pools_own_record(collections):
    store, _ = collections
    routes = xodb.backup_routes({"httpProxy": "http://u:p@proxy.lan:3128"}, POOL_UUID, set(), set())
    assert routes["xoa"] is True and routes["http_proxy"] == "proxy.lan:3128"


def test_jobs_that_cannot_be_read_are_an_error_not_an_answer(collections, monkeypatch):
    store, _ = collections
    store["job"] = xoredis.RedisError("credential db is encrypted")
    monkeypatch.setattr(transport, "run_local_cmd",
                        lambda argv, timeout=None, env=None, stdin_text=None: (1, "", "boom"))
    routes = xodb.backup_routes(None, POOL_UUID, set(), set())
    assert routes["error"].startswith("could not read XO's backup jobs (exit code 1: boom")


def test_a_decline_falls_back_to_xo_server_db_and_reads_its_output(collections, monkeypatch):
    store, _ = collections
    store["job"] = xoredis.RedisError("credential db is encrypted")
    store["schedule"] = xoredis.RedisError("credential db is encrypted")
    calls = []
    cli = {
        "job": ("1 record(s) found\n{\n  id: 'j1',\n  name: 'Nightly',\n  proxy: 'p1',\n"
                "  type: 'backup',\n  vms: '{\"type\":\"VM\",\"$pool\":{\"__or\":[\"%s\"]}}'\n}\n"
                % POOL_UUID),
        "schedule": "1 record(s) found\n{\n  enabled: true,\n  id: 's1',\n  jobId: 'j1'\n}\n",
        "proxy": "1 record(s) found\n{\n  id: 'p1',\n  name: 'site-b'\n}\n",
    }

    def fake(argv, timeout=None, env=None, stdin_text=None):
        calls.append(argv)
        return (0, cli[argv[2]], "")

    store["proxy"] = xoredis.RedisError("declined")
    monkeypatch.setattr(transport, "run_local_cmd", fake)
    routes = xodb.backup_routes(None, POOL_UUID, set(), set())
    assert routes == {"xoa": False, "proxies": ["site-b"], "http_proxy": "", "error": ""}
    assert calls == [["xo-server-db", "ls", "job"], ["xo-server-db", "ls", "schedule"],
                     ["xo-server-db", "ls", "proxy"]]


def test_each_collection_is_read_once(collections):
    store, asked = collections
    store["job"] = [job("1", smart(), proxy=PROXY)]
    store["schedule"] = on("1")
    xodb.backup_routes(None, POOL_UUID, set(), set())
    xodb.backup_routes(None, POOL_UUID, set(), set())
    assert asked == ["job", "schedule", "proxy"]


def test_no_proxy_means_the_proxies_are_never_read(collections):
    store, asked = collections
    store["job"] = [job("1", smart())]
    xodb.backup_routes(None, POOL_UUID, set(), set())
    assert "proxy" not in asked


# --------------------------------------------------------------------------------------
# the line
# --------------------------------------------------------------------------------------

def fact(value):
    return {"ok": True, "value": value}


def err(reason="could not look"):
    return {"ok": False, "error": reason}


def backup_pool(scope=None, pool_uuid=fact(POOL_UUID)):
    p = model.Pool()
    p.payload = {"other_config": fact("xo:backupNetwork: net-1"),
                 "pool_uuid": pool_uuid,
                 "networks": {"xo:backupNetwork": {
                     "uuid": "net-1",
                     "bond": fact("bond-slave-of ( RO): <not in database>\n"),
                     "ips": fact(["192.0.2.80", "192.0.2.81"])}}}
    if scope is not None:
        p.payload["backup_scope"] = scope
    return p


def silent(ips):
    return list(ips)


def answered(_ips):
    return []


class Routes(object):
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def __call__(self, pool_uuid, vm_uuids, sr_uuids):
        self.calls.append((pool_uuid, vm_uuids, sr_uuids))
        return self.answer


def test_the_issue_a_pool_backed_up_through_a_proxy_is_not_a_finding():
    routes = Routes({"xoa": False, "proxies": ["site-b"], "http_proxy": "", "error": ""})
    line = checks.backup_network(backup_pool(), "xoa", silent, routes)
    assert line.status == OK
    assert colors.strip_ansi(line.text) == (
        "Configured, backups run through XO Proxy 'site-b' (not tested from here) "
        "- No ping answer from XOA itself for: 192.0.2.80, 192.0.2.81")


def test_a_pool_the_xoa_backs_up_itself_still_flags_word_for_word():
    routes = Routes({"xoa": True, "proxies": ["site-b"], "http_proxy": "", "error": ""})
    line = checks.backup_network(backup_pool(), "xoa", silent, routes)
    assert line.status == FLAG
    assert "Configured but not fully reachable" in line.text
    assert line.text.endswith(" - No ping answer from XOA for: 192.0.2.80, 192.0.2.81")


def test_an_http_proxy_on_the_server_record_carries_the_xoas_own_traffic():
    routes = Routes({"xoa": True, "proxies": [], "http_proxy": "proxy.lan:3128", "error": ""})
    line = checks.backup_network(backup_pool(), "xoa", silent, routes)
    assert line.status == OK
    assert "XOA connects to this pool through HTTP proxy proxy.lan:3128 (not tested from here)" \
        in line.text


def test_both_ways_at_once_are_both_named():
    routes = Routes({"xoa": True, "proxies": ["a", "b"], "http_proxy": "p:1", "error": ""})
    line = checks.backup_network(backup_pool(), "xoa", silent, routes)
    assert line.status == OK
    assert ("backups run through XO Proxy 'a', 'b' and XOA connects to this pool through "
            "HTTP proxy p:1") in line.text


def test_configuration_that_cannot_be_read_leaves_the_finding_as_it_was():
    routes = Routes({"error": "could not read XO's backup jobs (exit code 1: boom)"})
    line = checks.backup_network(backup_pool(), "xoa", silent, routes)
    assert line.status == FLAG


def test_routes_are_not_asked_when_the_xoa_reaches_every_host():
    routes = Routes({"xoa": False, "proxies": ["x"], "http_proxy": "", "error": ""})
    line = checks.backup_network(backup_pool(), "xoa", answered, routes)
    assert line.status == OK and "reachable from XOA" in line.text
    assert routes.calls == []


def test_host_mode_never_asks_either():
    routes = Routes({"xoa": False, "proxies": ["x"], "http_proxy": "", "error": ""})
    line = checks.backup_network(backup_pool(), "host", silent, routes)
    assert "reachability from XOA not checked" in line.text
    assert routes.calls == []


def test_the_pools_uuids_reach_the_routes_and_an_unread_list_arrives_as_none():
    routes = Routes({"xoa": True, "proxies": [], "http_proxy": "", "error": ""})
    checks.backup_network(backup_pool({"vms": fact([VM_HERE]), "srs": err()}), "xoa",
                          silent, routes)
    assert routes.calls == [(POOL_UUID, {VM_HERE}, None)]
    routes.calls[:] = []
    checks.backup_network(backup_pool(None, pool_uuid=err()), "xoa", silent, routes)
    assert routes.calls == [("", None, None)]


def test_old_callers_without_routes_get_the_old_line():
    line = checks.backup_network(backup_pool(), "xoa", silent)
    assert line.status == FLAG


# --------------------------------------------------------------------------------------
# the collector half
# --------------------------------------------------------------------------------------

class FakeXe(object):
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        rc, out = self.answers.get(args[0], (0, ""))
        return collector.Ran(rc, out, "" if rc == 0 else "boom", False)


def test_the_scope_is_every_vm_and_sr_uuid(monkeypatch):
    fake = FakeXe({"vm-list": (0, "b, a,a\n"), "sr-list": (1, "")})
    monkeypatch.setattr(collector, "xe", fake)
    scope = collector._backup_scope()
    assert scope["vms"] == {"ok": True, "value": ["a", "b"]}
    assert scope["srs"]["ok"] is False and "xe sr-list failed" in scope["srs"]["error"]
    assert fake.calls == [["vm-list", "params=uuid", "--minimal"],
                          ["sr-list", "params=uuid", "--minimal"]]


class SpecRecorder(object):
    def __init__(self):
        self.specs = {}

    def collect(self, address, spec):
        self.specs[address] = spec
        return {"pool": {}, "yum_check": {"ok": True, "value": 0}}


@pytest.mark.parametrize("run_env, asked", [("xoa", True), ("host", False)])
def test_only_xoa_mode_asks_the_pool_for_its_uuids(monkeypatch, run_env, asked):
    import main
    monkeypatch.delenv("HEALTH_MAX_PARALLEL", raising=False)
    run = main.Run()
    run.run_env = run_env
    run.pool_mode = True
    run.host_sweep = True
    run.hosts = [model.Host("10.0.0.1")]
    run.all_addresses = ["10.0.0.1"]
    run.pool_cmd_host = "10.0.0.1"
    run.transport = SpecRecorder()
    main.collect_hosts(run)
    assert run.transport.specs["10.0.0.1"].get("backup_scope") is asked


POOL_UUID_OUT = "cab1ae78-be82-2e7c-3828-43c0a567881b"


def _pool_answers(other_config):
    return {"pool-list": (0, POOL_UUID_OUT),
            "pool-param-get": (0, other_config),
            "sr-list": (0, ""),
            "pif-list": (0, "bond-slave-of ( RO): <not in database>\n"),
            "vm-list": (0, "vm-1")}


@pytest.mark.parametrize("asked, other_config, expected", [
    (True, "xo:backupNetwork: net-1", True),
    (False, "xo:backupNetwork: net-1", False),     # host mode never asks
    (True, "auto_poweron: true", False),          # nothing to judge without a backup network
])
def test_the_scope_is_collected_only_when_asked_and_worth_it(monkeypatch, asked, other_config,
                                                             expected):
    monkeypatch.setattr(collector, "xe", FakeXe(_pool_answers(other_config)))
    monkeypatch.setattr(collector, "_pif_ips", lambda uuid: collector.fact(["10.0.0.1"]))
    out = collector.collect_pool({"backup_scope": asked}, "")
    assert ("backup_scope" in out) is expected


# --------------------------------------------------------------------------------------
# xoredis: the other collections
# --------------------------------------------------------------------------------------

from test_xoredis import array, bulk, serve  # noqa: E402,F401 - the real-socket fixture


def test_a_collection_comes_back_with_its_ids_and_types_untouched(serve):
    server = serve([array([bulk("s1")]),
                    array([bulk(json.dumps({"enabled": True, "jobId": "j1"}))])])
    got = xoredis._fetch_collection(server.addr, 5, "schedule")
    assert got == [{"enabled": True, "jobId": "j1", "id": "s1"}]
    assert server.commands == [["SMEMBERS", "xo:schedule_ids"], ["MGET", "xo:schedule:s1"]]


def test_an_empty_collection_is_an_answer(serve):
    server = serve([array([])])
    assert xoredis._fetch_collection(server.addr, 5, "proxy") == []


def test_an_encrypted_collection_is_declined(serve):
    server = serve([array([bulk("j1")]), array([bulk("enc:AAAA")])])
    with pytest.raises(xoredis.RedisError, match="encrypted"):
        xoredis._fetch_collection(server.addr, 5, "job")


def test_a_record_deleted_between_the_two_calls_is_skipped(serve):
    server = serve([array([bulk("j1"), bulk("j2")]),
                    array([bulk(None), bulk(json.dumps({"type": "backup"}))])])
    assert xoredis._fetch_collection(server.addr, 5, "job") == [{"type": "backup", "id": "j2"}]
