# -*- coding: utf-8 -*-
"""Leaf-Coalesce Disabled and Windows VMs Not Optimized - both judged off xe's labelled VM,
VDI, VBD and SR records, gathered once per pool.

The record shapes are xe's on 8.3: a plain field's access tag is two letters ('( RO)'), a
map's or set's three ('(MRW)', '(SRO)'). The platform strings are the 8.3 templates' as read
on the lab. Uuids and names are made up.
"""

import checks
import config
import model
import parsers
import result

OK, FLAG, UNKNOWN = result.OK, result.FLAG, result.UNKNOWN


def rec(uuid, **fields):
    """One labelled record; a field ending in '_map' or '_set' gets the 3-letter tag."""
    out = ["uuid ( RO)                : %s" % uuid]
    for name, value in fields.items():
        tag = "MRW" if name.endswith("_map") else "SRO" if name.endswith("_set") else " RO"
        label = name.replace("_map", "").replace("_set", "").replace("_", "-")
        out.append("    %s (%s): %s" % (label, tag, value))
    return "\n".join(out) + "\n\n\n"


def pool(**facts):
    p = model.Pool()
    p.payload = dict(facts)
    return p


def fact(value):
    return {"ok": True, "value": value}


def err(reason):
    return {"ok": False, "error": reason}


VM_A = "11111111-0000-0000-0000-00000000000a"
VM_B = "11111111-0000-0000-0000-00000000000b"
VDI_A = "22222222-0000-0000-0000-00000000000a"
VDI_B = "22222222-0000-0000-0000-00000000000b"
SR_X = "33333333-0000-0000-0000-00000000000a"

FULL = ("cores-per-socket: 2; device_id: 0002; viridian: true; viridian_time_ref_count: true; "
        "viridian_reference_tsc: true; viridian_apic_assist: true; viridian_crash_ctl: true; "
        "viridian_stimer: true; secureboot: auto; vga: std; videoram: 8; nx: true; acpi: 1; "
        "apic: true; pae: true; hpet: true")
# a VM made from an older Windows template: viridian alone
OLD = ("timeoffset: 7200; device-model: qemu-upstream-compat; viridian: true; nx: true; "
       "acpi: 1; vga: std; cores-per-socket: 1; videoram: 8; device_id: 0002; pae: true; apic: true")
OTHER_MEDIA = "secureboot: false; nx: true; acpi: 1; apic: true; pae: true; hpet: true; cores-per-socket: 1"
WIN_GUEST = ("name: Microsoft Windows Server 2022 Standard|C:\\Windows|\\Device\\Harddisk0\\Partition2; "
             "distro: windows; major: 10; minor: 0")
LINUX_GUEST = "name: Debian GNU/Linux 12 (bookworm); uname: 6.1.0-54-amd64; distro: debian; major: 12"


def vm(uuid, name, platform=FULL, ref="windows-server-2022-64bit",
       base="Windows Server 2022 (64-bit)", guest=WIN_GUEST, ops="", extra_oc=""):
    other = ("base_template_name: %s; " % base if base else "") + "mac_seed: x" + extra_oc
    return rec(uuid, name_label=name, power_state="running", current_operations_set=ops,
               platform_map=platform, reference_label=ref, other_config_map=other,
               os_version_map=guest)


# --------------------------------------------------------------------------------------
# the labelled-record reader now sees map and set fields
# --------------------------------------------------------------------------------------

def test_map_and_set_fields_are_read():
    r = parsers.parse_xe_records(vm(VM_A, "Example-Win-A", ops="export"))[0]
    assert r["platform"].startswith("cores-per-socket: 2")
    assert r["current-operations"] == "export"
    assert r["os-version"].startswith("name: Microsoft Windows")


def test_operations_are_read_as_words():
    assert parsers.xe_ops("export") == {"export"}
    assert "migrate_send" in parsers.xe_ops("OpaqueRef:1f2e: migrate_send")
    assert "export" not in parsers.xe_ops("metadata_export")
    assert parsers.xe_ops("") == set() and parsers.xe_ops(None) == set()


# --------------------------------------------------------------------------------------
# Windows VMs Not Optimized
# --------------------------------------------------------------------------------------

WKEY = "Windows VMs Not Optimized"


def win(text):
    return checks.windows_vms_not_optimized(pool(vms=fact(text)))


def test_a_vm_from_an_83_windows_template_passes():
    line = win(vm(VM_A, "Example-Win-A"))
    assert line.status == OK and line.key == WKEY
    assert "None (1 Windows VM checked)" in line.text


def test_a_vm_from_an_older_windows_template_is_missing_five_keys():
    line = win(vm(VM_A, "Example-Win-A", platform=OLD))
    assert line.status == FLAG
    assert line.text.endswith(" - 1 of 1 Windows VM, see below")
    assert ("platform viridian_time_ref_count, viridian_reference_tsc, viridian_apic_assist, "
            "viridian_crash_ctl, viridian_stimer not set to true") in line.detail_text
    # the command that fixes it, every key in it
    for k in config.WINDOWS_PLATFORM_KEYS:
        assert "platform:%s=true" % k in line.detail_text


def test_windows_installed_from_other_install_media_names_the_template():
    line = win(vm(VM_A, "Example-Win-A", platform=OTHER_MEDIA, ref="other-install-media",
                  base="Other install media"))
    assert line.status == FLAG
    assert "made from the 'Other install media' template, not a Windows one" in line.detail_text
    assert "platform viridian, viridian_time_ref_count" in line.detail_text


def test_a_key_set_to_false_counts_as_not_set():
    line = win(vm(VM_A, "Example-Win-A", platform=FULL.replace("viridian_stimer: true",
                                                                "viridian_stimer: false")))
    assert line.status == FLAG and "platform viridian_stimer not set to true" in line.detail_text


def test_a_windows_template_vm_with_no_guest_agent_is_still_judged():
    line = win(vm(VM_A, "Example-Win-A", platform=OLD, guest="<not in database>"))
    assert line.status == FLAG


def test_a_windows_guest_whose_origin_is_not_recorded_is_judged_on_its_platform_only():
    line = win(vm(VM_A, "Example-Win-A", ref="", base=""))
    assert line.status == OK
    line = win(vm(VM_A, "Example-Win-A", platform=OLD, ref="", base=""))
    assert line.status == FLAG and "template" not in line.detail_text.split("\n")[0]


def test_linux_vms_and_xo_replicas_are_not_judged():
    text = (vm(VM_A, "Example-Linux", platform=OTHER_MEDIA, ref="debian-12",
               base="Debian Bookworm 12", guest=LINUX_GUEST) +
            vm(VM_B, "[XO Backup Example] Example-Win-A", platform=OLD,
               extra_oc="; xo:backup:vm: %s" % VM_A))
    line = win(text)
    assert line.status == OK and "No Windows VMs found" in line.text


def test_findings_are_listed_by_name_and_counted_against_all_windows_vms():
    text = (vm(VM_B, "zeta", platform=OLD) + vm(VM_A, "Alpha", platform=OLD) +
            vm("11111111-0000-0000-0000-00000000000c", "beta"))
    line = win(text)
    assert line.text.endswith(" - 2 of 3 Windows VMs, see below")
    rows = [l for l in line.detail_text.splitlines() if l.startswith("  ")]
    assert rows[0].startswith("  Alpha (%s)" % VM_A) and rows[1].startswith("  zeta (%s)" % VM_B)


def test_windows_unknown_without_the_vm_list():
    for p in (pool(), pool(vms=err("xe vm-list failed (exit 1)"))):
        line = checks.windows_vms_not_optimized(p)
        assert line.status == UNKNOWN and line.flags


# --------------------------------------------------------------------------------------
# Leaf-Coalesce Disabled
# --------------------------------------------------------------------------------------

LKEY = "Leaf-Coalesce Disabled"


def vdi(uuid, name, oc="leaf-coalesce: false; content_id: x", ops="", snapshot="false"):
    return rec(uuid, name_label=name, sr_name_label="Example-SR", is_a_snapshot=snapshot,
               current_operations_set=ops, other_config_map=oc)


def vbd(vdi_uuid, vm_uuid, vm_name, uuid="44444444-0000-0000-0000-000000000000"):
    return rec(uuid, vm_uuid=vm_uuid, vm_name_label=vm_name, vdi_uuid=vdi_uuid)


def lc(vdis="", vbds="", srs="", **more):
    value = {"vdis": vdis, "vbds": vbds, "srs": srs}
    value.update(more)
    return fact(value)


def leaf(leaf_fact, vms_text=None, vms_fact=None):
    return checks.leaf_coalesce_disabled(pool(
        leaf_coalesce=leaf_fact,
        vms=vms_fact if vms_fact is not None else fact(vms_text or vm(VM_A, "Example-VM-A"))))


def test_none_when_no_disk_or_sr_has_it():
    line = leaf(lc())
    assert line.status == OK and line.key == LKEY and line.text.endswith("None")


def test_a_flagged_disk_is_listed_with_its_vm():
    line = leaf(lc(vdis=vdi(VDI_A, "Example-VM-A disk 0"),
                   vbds=vbd(VDI_A, VM_A, "Example-VM-A")))
    assert line.status == FLAG
    assert line.text.endswith(" - 1 disk on 1 VM, see below")
    assert ("  Example-VM-A (%s): Example-VM-A disk 0 (%s) on Example-SR" % (VM_A, VDI_A)
            in line.detail_text)
    assert "xe vdi-param-remove uuid=<vdi> param-name=other-config param-key=leaf-coalesce" \
        in line.detail_text


def test_a_disk_mid_migration_or_export_is_counted_aside():
    for ops in ("migrate_send", "pool_migrate", "export", "import"):
        line = leaf(lc(vdis=vdi(VDI_A, "Example-VM-A disk 0"),
                       vbds=vbd(VDI_A, VM_A, "Example-VM-A")),
                    vms_text=vm(VM_A, "Example-VM-A", ops=ops))
        assert line.status == OK, ops
        assert "(1 disk mid-migration/export/import, as expected)" in line.text
    line = leaf(lc(vdis=vdi(VDI_A, "Example-VM-A disk 0", ops="mirror"),
                   vbds=vbd(VDI_A, VM_A, "Example-VM-A")))
    assert line.status == OK


def test_an_unrelated_operation_does_not_excuse_it():
    line = leaf(lc(vdis=vdi(VDI_A, "Example-VM-A disk 0"),
                   vbds=vbd(VDI_A, VM_A, "Example-VM-A")),
                vms_text=vm(VM_A, "Example-VM-A", ops="metadata_export"))
    assert line.status == FLAG


def test_a_record_without_the_key_is_not_counted_whatever_xe_returned():
    line = leaf(lc(vdis=vdi(VDI_A, "x", oc="content_id: x") +
                   vdi(VDI_B, "y", oc="leaf-coalesce: force")))
    assert line.status == OK


def test_a_disk_with_no_vm_and_a_snapshot_are_both_reported():
    line = leaf(lc(vdis=vdi(VDI_A, "orphan") + vdi(VDI_B, "snap", snapshot="true"),
                   vbds=vbd(VDI_B, VM_B, "Example-VM-B")))
    assert line.status == FLAG
    assert line.text.endswith(" - 2 disks on 1 VM, see below")
    assert "  no VM: orphan (%s)" % VDI_A in line.detail_text
    assert "[snapshot]" in line.detail_text


def test_an_sr_with_leaf_coalesce_off_is_reported_in_the_same_line():
    sr = rec(SR_X, name_label="Example-SR", other_config_map="leaf-coalesce: false")
    line = leaf(lc(srs=sr))
    assert line.status == FLAG and line.text.endswith(" - 1 SR, see below")
    assert "SR Example-SR (%s): leaf-coalesce disabled for every disk on it" % SR_X \
        in line.detail_text


def test_without_the_vm_list_every_disk_is_reported_and_the_detail_says_why():
    line = leaf(lc(vdis=vdi(VDI_A, "d"), vbds=vbd(VDI_A, VM_A, "Example-VM-A")),
                vms_fact=err("xe vm-list failed (exit 1)"))
    assert line.status == FLAG
    assert "whether any of these is mid-migration was not established" in line.detail_text


def test_without_the_vbd_list_the_disks_are_still_reported_unnamed():
    line = leaf(lc(vdis=vdi(VDI_A, "d"), vbds=None, vbd_error="xe vbd-list failed (exit 1)"))
    assert line.status == FLAG
    assert "the disks' VMs are not named" in line.detail_text


def test_unknown_without_the_fact_and_a_clean_answer_needs_the_srs():
    for p in (pool(), pool(leaf_coalesce=err("xe vdi-list failed (exit 1)"))):
        line = checks.leaf_coalesce_disabled(p)
        assert line.status == UNKNOWN and line.flags
    line = leaf(lc(srs=None, sr_error="xe sr-list failed (exit 1)"))
    assert line.status == UNKNOWN and "the SRs were not read" in line.text
