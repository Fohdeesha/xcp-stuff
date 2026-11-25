# -*- coding: utf-8 -*-
"""Check-level fixes from the 2026-11-24 audit, each pinned to the state it was about.

Helpers come from the suites that own each line, so the record shapes stay the ones those
suites were written against.
"""

import checks
import config
import model
import parsers
import result

from test_checks import _pool_host, err, fact, host
from test_statedb import member, roles
from test_tasks_units import HOST, NOW, stamp, task, tasks_fact
from test_vm_checks import FULL, OLD, OTHER_MEDIA, SR_X, VM_A, lc, leaf, rec, vm, win

OK, FLAG, UNKNOWN, INFO = result.OK, result.FLAG, result.UNKNOWN, result.INFO


def pool(**facts):
    p = model.Pool()
    p.payload = dict(facts)
    return p


# --------------------------------------------------------------------------------------
# Windows VMs Not Optimized (C08, C09)
# --------------------------------------------------------------------------------------

def test_a_platform_flag_of_1_is_true_as_xapi_reads_it():
    """xapi's vm_platform is_true takes "true" or "1"."""
    line = win(vm(VM_A, "Example-Win-A", platform=FULL.replace("viridian_stimer: true",
                                                                "viridian_stimer: 1")))
    assert line.status == OK


def test_a_custom_golden_template_is_not_called_the_wrong_template():
    """A golden image built from an imported VM carries no reference-label and its own
    name; only positive evidence of a non-Windows template is a finding."""
    line = win(vm(VM_A, "Example-Win-A", ref="", base="WS2022-gold"))
    assert line.status == OK


def test_other_install_media_without_a_reference_label_is_still_caught():
    line = win(vm(VM_A, "Example-Win-A", platform=OTHER_MEDIA, ref="",
                  base="Other install media"))
    assert line.status == FLAG and "'Other install media' template" in line.detail_text


def test_a_stock_non_windows_template_label_is_caught():
    line = win(vm(VM_A, "Example-Win-A", ref="debian-12", base=""))
    assert line.status == FLAG and "'debian-12' template" in line.detail_text


# --------------------------------------------------------------------------------------
# Leaf-Coalesce Disabled: the SR switches GC reads (B09)
# --------------------------------------------------------------------------------------

def test_an_sr_with_gc_off_is_reported():
    sr = rec(SR_X, name_label="Example-SR", other_config_map="gc: false")
    line = leaf(lc(srs=sr))
    assert line.status == FLAG and "garbage collection disabled" in line.detail_text


def test_an_sr_with_coalesce_off_is_reported():
    sr = rec(SR_X, name_label="Example-SR", other_config_map="coalesce: false; foo: bar")
    line = leaf(lc(srs=sr))
    assert line.status == FLAG and "coalescing disabled for every disk" in line.detail_text


def test_an_sr_switch_set_to_true_is_not_a_finding():
    sr = rec(SR_X, name_label="Example-SR", other_config_map="gc: true; leaf-coalesce: true")
    assert leaf(lc(srs=sr)).status == OK


def test_every_switch_on_one_sr_is_named():
    srs = parsers.leaf_coalesce_srs(rec(SR_X, name_label="Example-SR",
                                        other_config_map="leaf-coalesce: false; gc: false"))
    assert srs and srs[0][0] == SR_X and set(srs[0][2]) == {"gc", "leaf-coalesce"}
    assert srs[0][2][0] == "gc"           # the widest switch names the line


# --------------------------------------------------------------------------------------
# Dom0 Disk Usage (A04), Host Collection (A01/E19), log scans (B13)
# --------------------------------------------------------------------------------------

DF = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/sda1 100 50 50 50% /\n"
DF_FULL = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/sda1 100 95 5 95% /\n"


def test_disk_usage_green_needs_every_local_mount_read():
    line = checks.dom0_disk_usage(host(df=fact({"text": DF, "failed": ["/var/log (EIO)"]})))
    assert line.status == UNKNOWN and "/var/log" in line.text
    assert checks.dom0_disk_usage(host(df=fact({"text": DF, "failed": []}))).status == OK


def test_a_full_disk_is_reported_even_with_a_mount_unread():
    line = checks.dom0_disk_usage(host(df=fact({"text": DF_FULL, "failed": ["/x (EIO)"]})))
    assert line.status == FLAG


def test_disk_usage_still_reads_an_older_collectors_plain_text():
    assert checks.dom0_disk_usage(host(df=fact(DF))).status == OK


def test_host_collection_prints_only_for_a_partial_document():
    assert checks.host_collection(host(hostname=fact("x"))) is None
    h = host(hostname=fact("x"))
    h.payload["__incomplete__"] = "the collector stopped at 'yum check-update' (timed out)"
    line = checks.host_collection(h)
    assert line.status == FLAG and line.text.startswith("Incomplete")
    assert "yum check-update" in line.text


def _block(phrase="error", note=""):
    b = {"phrase": phrase, "file": "/var/log/xensource.log", "context": ["a line"]}
    if note:
        b["note"] = note
    return b


def test_a_log_scan_that_failed_is_unknown_not_none():
    line = checks.log_errors(host(log_scan=fact({"blocks": [],
                                                 "failed": ["/var/log/SMlog: timed out"]})))
    assert line.status == UNKNOWN and "SMlog" in line.text


def test_a_finding_stands_next_to_a_failed_scan_and_says_what_was_not_read():
    line = checks.log_errors(host(log_scan=fact({"blocks": [_block()],
                                                 "failed": ["/var/log/SMlog: timed out"]})))
    assert line.status == FLAG and "Not read: /var/log/SMlog: timed out" in line.detail_text


def test_a_hit_whose_context_failed_is_shown_alone_and_says_so():
    line = checks.log_errors(host(log_scan=fact({"blocks": [_block(note="context unread")],
                                                 "failed": []})))
    assert "(context unread - the matching line alone)" in line.detail_text


def test_an_older_collectors_plain_list_of_blocks_still_reads():
    assert checks.log_errors(host(log_scan=fact([_block()]))).status == FLAG
    assert checks.log_errors(host(log_scan=fact([]))).status == OK


# --------------------------------------------------------------------------------------
# Long-Running Tasks: every unfinished status (B05)
# --------------------------------------------------------------------------------------

def test_a_cancelling_task_counts_and_its_status_is_shown():
    text = (task("t-c", "VM.migrate_send", "cancelling", stamp(20)) +
            task("t-f", "VM.start", "failure", stamp(30)) +
            task("t-x", "VM.start", "cancelled", stamp(30)))
    old = parsers.parse_pending_tasks(text, NOW, config.TASK_PENDING_MAX_HOURS * 3600)
    assert [t[1] for t in old] == ["t-c"] and old[0][5] == "cancelling"
    line = checks.long_running_tasks(pool(tasks=tasks_fact(text)))
    assert line.status == FLAG and "cancelling for" in line.detail_text


# --------------------------------------------------------------------------------------
# pool roll-ups and Pool Roles
# --------------------------------------------------------------------------------------

def test_a_rollup_over_hosts_that_all_skip_says_so_rather_than_none():
    skipped = fact({"skipped": True, "repo_hosts": ["repo.example.net"]})
    a, b = _pool_host("192.0.2.1"), _pool_host("192.0.2.2")
    a.payload["update_mirror"] = skipped
    b.payload["update_mirror"] = skipped
    line = checks.update_mirror_access_pool([a, b])
    assert line.status == INFO and "N/A (no host uses the XCP-ng mirrors)" in line.text


def test_a_slave_pointing_at_no_address_is_a_finding():
    line = roles(member("10.0.0.1", "xen-a", "master"),
                 member("10.0.0.2", "xen-b", "slave:"))
    assert line.status == FLAG and "a slave of no address" in line.detail_text


# --------------------------------------------------------------------------------------
# XOSTOR lines that establish nothing are not green (D07-D09, D19)
# --------------------------------------------------------------------------------------

def test_faulty_resources_without_a_table_is_unknown():
    for text in ("", "Error: the controller is starting up\n", "some banner\n"):
        line = checks.xostor_faulty_resources(pool(linstor_faulty=fact(text)))
        assert line.status == UNKNOWN, text


def test_nodes_without_rows_or_a_state_column_is_unknown():
    empty = "+------+\n| Node | NodeType | State |\n|======|\n+------+\n"
    no_state = "+------+\n| Node | NodeType |\n|======|\n| a | COMBINED |\n+------+\n"
    for text in ("", empty, no_state):
        line = checks.xostor_nodes(pool(linstor_nodes=fact(text)))
        assert line.status == UNKNOWN, text


def test_prefnic_set_on_no_node_is_a_yellow_note_not_a_finding():
    """SM reads an absent PrefNic as 'default': consistently LINSTOR's default interface."""
    line = checks.xostor_pref_nic(pool(linstor_pref_nics=fact(
        {"nodes": ["a", "b"], "nics": {"a": None, "b": None}})))
    assert line.status == INFO and line.keep and not line.flags
    assert "Default interface on all 2 nodes" in line.text


def test_prefnic_unset_on_the_nodes_read_with_one_unread_is_unknown():
    line = checks.xostor_pref_nic(pool(linstor_pref_nics=fact(
        {"nodes": ["a", "b"], "nics": {"a": None}})))
    assert line.status == UNKNOWN and "b" in line.text


# --------------------------------------------------------------------------------------
# Backup Network: a PIF with no IP (B03)
# --------------------------------------------------------------------------------------

def test_a_backup_network_pif_without_an_ip_is_a_finding():
    """XO sends that host's exports to its backup-network PIF IP verbatim; with none, the
    other hosts answering the ping must not make the line green."""
    p = pool(other_config=fact("xo:backupNetwork: net-1"),
             networks={"xo:backupNetwork": {
                 "uuid": "net-1", "bond": fact("bond-slave-of ( RO): <not in database>\n"),
                 "ips": fact(["192.0.2.10"]), "pifs_without_ip": 1}})
    line = checks.backup_network(p, "xoa", lambda ips: [])
    assert line.status == FLAG and "1 PIF(s) on it have no IP" in line.text
