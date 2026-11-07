# -*- coding: utf-8 -*-
"""Read-Only Filesystems: what should be writable and is mounted read-only.

The fixtures are the shape of a real 8.3 dom0 (four fstab lines, systemd's read-only cgroup
tmpfs, a local EXT SR and NFS SRs), with every name made up.
"""

import checks
import config
import parsers
import result

OK, FLAG, UNKNOWN = result.OK, result.FLAG, result.UNKNOWN

FSTAB = """LABEL=root-abcdef    /         ext3     defaults   1  1
LABEL=BOOT-ABCDEF    /boot/efi         vfat     defaults   0  2
LABEL=swap-abcdef          swap      swap   defaults   0  0
LABEL=logs-abcdef    /var/log         ext3     defaults   0  2
"""

SR_LOCAL = "11111111-2222-3333-4444-555555555555"
SR_NFS = "66666666-7777-8888-9999-000000000000"

MOUNTS = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=2087136k,nr_inodes=521784,mode=755 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
/dev/sda1 / ext3 rw,relatime 0 0
xenfs /proc/xen xenfs rw,relatime 0 0
/dev/sda5 /var/log ext3 rw,relatime 0 0
/dev/sda4 /boot/efi vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,shortname=mixed,errors=remount-ro 0 0
/dev/mapper/XSLocalEXT--1111-1111 /run/sr-mount/%s ext4 rw,relatime 0 0
192.0.2.10:/export/%s /run/sr-mount/%s nfs rw,relatime,vers=3,hard,proto=tcp 0 0
tmpfs /run/user/0 tmpfs rw,nosuid,nodev,relatime,size=420116k,mode=700 0 0
""" % (SR_LOCAL, SR_NFS, SR_NFS)


ROOT = "/dev/sda1 / ext3 rw,relatime 0 0\n"


def ro(text, target):
    """MOUNTS with one mount point's options turned read-only, as the kernel shows it."""
    out = []
    for line in text.splitlines():
        parts = line.split(" ")
        if parts[1] == target:
            parts[3] = "ro" + parts[3][2:]
        out.append(" ".join(parts))
    return "\n".join(out) + "\n"


def judge(mounts, fstab=FSTAB):
    return parsers.read_only_mounts(mounts, fstab, config.RO_FS_SR_DIRS, config.RO_FS_EXTRA,
                                    config.RO_FS_NATIVE_RO)


# --------------------------------------------------------------------------------------
# the parser
# --------------------------------------------------------------------------------------

def test_a_healthy_dom0_has_none_though_it_has_a_read_only_mount():
    assert "tmpfs /sys/fs/cgroup tmpfs ro," in MOUNTS
    assert judge(MOUNTS) == []


def test_each_fstab_filesystem_is_judged():
    for target in ("/", "/var/log", "/boot/efi"):
        bad = judge(ro(MOUNTS, target))
        assert [b["target"] for b in bad] == [target]
        assert bad[0]["fstab"] == "defaults"


def test_errors_remount_ro_in_the_options_is_not_ro():
    assert "errors=remount-ro" in MOUNTS
    assert judge(MOUNTS) == []


def test_a_local_sr_mount_is_judged():
    bad = judge(ro(MOUNTS, "/run/sr-mount/" + SR_LOCAL))
    assert [b["target"] for b in bad] == ["/run/sr-mount/" + SR_LOCAL]
    assert bad[0]["fstab"] is None
    assert bad[0]["source"].startswith("/dev/mapper/")


def test_an_sr_mount_that_is_not_a_block_device_is_left_alone():
    assert judge(ro(MOUNTS, "/run/sr-mount/" + SR_NFS)) == []


def test_the_old_sr_mount_path_is_judged_too():
    text = ROOT + "/dev/sdb1 /var/run/sr-mount/%s ext4 ro,relatime 0 0\n" % SR_LOCAL
    assert [b["target"] for b in judge(text, "")] == ["/var/run/sr-mount/" + SR_LOCAL]


def test_the_linstor_database_is_judged_from_a_block_device_only():
    assert [b["target"] for b in judge(ROOT + "/dev/drbd1000 /var/lib/linstor ext4 ro,noatime 0 0\n",
                                       "")] == ["/var/lib/linstor"]
    assert judge(ROOT + "tmpfs /var/lib/linstor tmpfs ro 0 0\n", "") == []


def test_what_fstab_asks_to_be_read_only_is_left_alone():
    fstab = FSTAB + "/opt/xensource/packages/iso/XenCenter.iso /var/xen/xc-install iso9660 loop,ro 0 0\n"
    mounts = MOUNTS + "/dev/loop0 /var/xen/xc-install iso9660 ro,relatime 0 0\n"
    assert judge(mounts, fstab) == []


def test_noauto_and_swap_entries_are_not_judged():
    fstab = FSTAB + "/dev/sdc1 /mnt/spare ext4 noauto 0 0\n"
    mounts = MOUNTS + "/dev/sdc1 /mnt/spare ext4 ro,relatime 0 0\n"
    assert judge(mounts, fstab) == []


def test_an_fstab_filesystem_that_is_not_mounted_is_not_a_finding():
    mounts = "\n".join(l for l in MOUNTS.splitlines() if " /boot/efi " not in l) + "\n"
    assert judge(mounts) == []


def test_a_mount_stacked_on_top_decides():
    under_ro = MOUNTS + "/dev/sda5 /var/log ext3 ro,relatime 0 0\n"
    assert [b["target"] for b in judge(under_ro)] == ["/var/log"]
    over_rw = ro(MOUNTS, "/var/log") + "/dev/sda5 /var/log ext3 rw,relatime 0 0\n"
    assert judge(over_rw) == []


def test_escaped_spaces_and_trailing_slashes_match():
    fstab = "/dev/sdc1 /srv/my\\040data/ ext4 defaults 0 0\n"
    mounts = ROOT + "/dev/sdc1 /srv/my\\040data ext4 ro,relatime 0 0\n"
    bad = judge(mounts, fstab)
    assert [b["target"] for b in bad] == ["/srv/my data"]


def test_an_fstab_line_without_options_reads_as_defaults():
    bad = judge(ROOT + "/dev/sdc1 /data ext4 ro 0 0\n", "/dev/sdc1 /data ext4\n")
    assert [b["fstab"] for b in bad] == ["defaults"]


def test_without_fstab_only_root_and_the_sr_and_linstor_mounts_are_judged():
    assert judge(ro(MOUNTS, "/var/log"), None) == []
    bad = judge(ro(MOUNTS, "/run/sr-mount/" + SR_LOCAL), None)
    assert [b["target"] for b in bad] == ["/run/sr-mount/" + SR_LOCAL]
    assert [b["target"] for b in judge(ro(MOUNTS, "/"), None)] == ["/"]


def test_root_is_judged_whatever_fstab_says():
    """The review's finding 2: an fstab with no usable entry used to judge nothing and
    answer None, root read-only or not."""
    assert [b["target"] for b in judge(ro(MOUNTS, "/"), "# nothing here\n")] == ["/"]
    assert judge(ro(MOUNTS, "/"), "LABEL=root / ext3 ro 1 1\n") == []


def test_a_mount_table_with_no_root_is_not_read_as_a_clean_one():
    assert judge("", FSTAB) is None
    assert judge("tmpfs /run tmpfs rw 0 0\n", FSTAB) is None


def test_a_filesystem_read_only_by_nature_is_not_judged():
    """The review's finding 4: the kernel mounts iso9660 read-only whatever fstab asks."""
    fstab = FSTAB + "/root/tools.iso /mnt/iso iso9660 loop 0 0\n"
    mounts = MOUNTS + "/dev/loop0 /mnt/iso iso9660 ro,relatime 0 0\n"
    assert judge(mounts, fstab) == []
    fstab = FSTAB + "/dev/sdc1 /mnt/data ext4 defaults 0 0\n"
    mounts = MOUNTS + "/dev/sdc1 /mnt/data ext4 ro,relatime 0 0\n"
    assert [b["target"] for b in judge(mounts, fstab)] == ["/mnt/data"]


def test_comments_and_blank_lines_are_skipped():
    fstab = "# a comment\n\n   \n" + FSTAB
    assert len(parsers.mount_table(fstab)) == 4


# --------------------------------------------------------------------------------------
# the check
# --------------------------------------------------------------------------------------

def fact(value):
    return {"ok": True, "value": value}


def err(reason="could not look"):
    return {"ok": False, "error": reason}


def host(**facts):
    import model
    h = model.Host("10.0.0.1", "uuid-1", "hostx", "true", "false")
    h.payload = dict(facts)
    return h


def test_check_none_on_a_healthy_host():
    line = checks.read_only_filesystems(host(proc_mounts=fact(MOUNTS), fstab=fact(FSTAB)))
    assert line.status == OK
    assert "None" in line.text


def test_check_names_what_is_read_only_and_quotes_dmesg():
    ring = ("[Fri Nov  6 03:00:00 2026] Write protecting the kernel read-only data: 12288k\n"
            "[Fri Nov  6 09:14:02 2026] Aborting journal on device sda5-8.\n"
            "[Fri Nov  6 09:14:02 2026] EXT4-fs (sda5): Remounting filesystem read-only\n")
    mounts = ro(ro(MOUNTS, "/var/log"), "/run/sr-mount/" + SR_LOCAL)
    line = checks.read_only_filesystems(host(proc_mounts=fact(mounts), fstab=fact(FSTAB),
                                             dmesg=fact(ring)))
    assert line.status == FLAG
    assert line.text.endswith(" - /var/log, SR 11111111")
    assert "Remounting filesystem read-only" in line.detail_text
    assert "Aborting journal" in line.detail_text
    assert "Write protecting" not in line.detail_text
    assert "fstab asks for defaults" in line.detail_text


def test_check_says_when_dmesg_has_nothing_or_was_not_read():
    mounts = ro(MOUNTS, "/var/log")
    quiet = checks.read_only_filesystems(host(proc_mounts=fact(mounts), fstab=fact(FSTAB),
                                              dmesg=fact("[x] nothing here\n")))
    assert "the ring may have wrapped" in quiet.detail_text
    unread = checks.read_only_filesystems(host(proc_mounts=fact(mounts), fstab=fact(FSTAB),
                                               dmesg=err("dmesg failed")))
    assert "dmesg was not read (dmesg failed)" in unread.detail_text


def test_check_does_not_present_another_devices_dmesg_lines_as_the_reason():
    """The review's finding 7: lines about some other device were printed under the
    finding as if they explained it."""
    ring = ("[Mon Nov  2 01:00:00 2026] EXT4-fs (sdb1): Remounting filesystem read-only\n"
            "[Fri Nov  6 09:14:02 2026] EXT4-fs (sda5): Remounting filesystem read-only\n")
    line = checks.read_only_filesystems(host(proc_mounts=fact(ro(MOUNTS, "/var/log")),
                                             fstab=fact(FSTAB), dmesg=fact(ring)))
    assert "What dmesg says about sda5:" in line.detail_text
    assert "(sda5)" in line.detail_text and "(sdb1)" not in line.detail_text
    other = checks.read_only_filesystems(host(proc_mounts=fact(ro(MOUNTS, "/var/log")),
                                              fstab=fact(FSTAB), dmesg=fact(ring.split("\n")[0] + "\n")))
    assert "none naming sda5" in other.detail_text


def test_check_unknown_off_a_mount_table_with_no_root():
    line = checks.read_only_filesystems(host(proc_mounts=fact("tmpfs /run tmpfs rw 0 0\n"),
                                             fstab=fact(FSTAB)))
    assert line.status == UNKNOWN and line.flags


def test_check_unknown_without_proc_mounts():
    line = checks.read_only_filesystems(host(proc_mounts=err("no proc"), fstab=fact(FSTAB)))
    assert line.status == UNKNOWN
    assert line.flags


def test_check_unknown_without_fstab_when_nothing_else_is_wrong():
    line = checks.read_only_filesystems(host(proc_mounts=fact(MOUNTS), fstab=err("no fstab")))
    assert line.status == UNKNOWN
    assert "no fstab" in line.text


def test_check_still_reports_an_sr_mount_found_without_fstab():
    mounts = ro(MOUNTS, "/run/sr-mount/" + SR_LOCAL)
    line = checks.read_only_filesystems(host(proc_mounts=fact(mounts), fstab=err("no fstab")))
    assert line.status == FLAG
    assert "fstab was not read (no fstab)" in line.detail_text
