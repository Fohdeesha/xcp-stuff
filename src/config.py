# -*- coding: utf-8 -*-
"""Every threshold, list and toggle, in one place. Same names and values as health.sh."""

SCRIPT_VERSION = "3.5"

SSH_TIMEOUT = 45                 # ssh connect timeout, seconds
REMOTE_CMD_TIMEOUT = 300         # max seconds one collector run may take on a host
MAX_PARALLEL_HOSTS = 8           # hosts collected at once (HEALTH_MAX_PARALLEL overrides)
LOCAL_CMD_TIMEOUT = 10           # max seconds a local command may run (hung xoa-updater etc)
XOA_CHECK_TIMEOUT = 60           # 'xoa check' does real network probes, so it gets longer

DOM0_MAX_USED = 75               # dom0 disk use % allowed before flagging
DOM0_MEM_USED_MAX_PCT = 65       # dom0 memory use % allowed before flagging
XOSTOR_MIN_RAM_GB = 15           # minimum dom0 RAM (GB) when XOSTOR is in use
TIME_SYNC_ALLOWANCE_SECS = 300   # max clock difference between a host and this machine

MTU_DMESG_KEYWORDS = ["mtu", "large", "fragment"]      # whole-word, case-insensitive
DMESG_ISSUE_WORDS = ["panic", "crash", "rip", "kill"]  # whole-word, case-insensitive
DMESG_ISSUE_PHRASES = ["call trace", "timed out"]      # substring, case-insensitive
OOM_PHRASE = "out of memory"

# A dmesg line that matched a word/phrase above is dropped only if it contains ALL of a
# rule's substrings (case-insensitive, whitespace collapsed). One list entry = one rule.
DMESG_IGNORE_RULES = [
    ["megaraid", "firmware crash dump"],   # megaraid driver load prints "... : no"
]

# --- "Log Errors" check ---------------------------------------------------------------
# Plain case-insensitive substrings (grep -F), so nothing needs escaping. Each phrase is
# reported separately, so a noisy phrase can never hide a rare one.
LOG_ERROR_PHRASES = [
    "except",                    # python tracebacks / SMAPI exceptions
    "Input/output error",
    "XENAPI_PLUGIN_FAILURE",
    "TapdiskNotRunning",         # tapdisk died under it - pairs with a core.tapdisk.* dump
]
# Each is scanned together with its rotated ".1": these rotate daily around 04:00, so
# right after a rotation the live file is nearly empty and this morning's errors are in .1.
LOG_ERROR_FILES = [
    "/var/log/SMlog",
    "/var/log/xensource.log",
]
LOG_ERROR_CONTEXT = 3            # lines of context shown either side of a match

# --- multipath checks -----------------------------------------------------------------
# `Multipathing` reports the xapi SETTING. These describe the paths themselves, which is a
# different question: a host printed a green "Multipathing: true" while its dmesg said
# "device-mapper: multipath: Failing path 8:48".
#
# All three state whitelists, deliberately. multipath-tools 0.4.9 (both 8.2.1 and 8.3.0,
# same build, verified in the binary's own string table 2026-08-27) prints:
#   dm_st  (%t) undef | active | failed
#   chk_st (%T) undef | ready | faulty | shaky | ghost | delayed
#   dev_st (%o) unknown | running | offline | blocked | quiesce | dead | deleting | live
# A state that is not listed here is NOT healthy - a newer multipath-tools inventing a
# state name must read as "not established", never as a pass.
MULTIPATH_OK_DM_STATES = ["active"]
MULTIPATH_OK_CHK_STATES = ["ready", "ghost"]
MULTIPATH_OK_DEV_STATES = ["running", "live"]
# 'ghost' is the standby path of an active/passive (ALUA) array: healthy by design, and
# counted separately so the line can say how many there are. Move it out of OK_CHK_STATES
# to flag ghost paths instead - correct for an active/active array, wrong for the rest.
MULTIPATH_STANDBY_CHK_STATES = ["ghost"]
# 'undef' on a path that belongs to a map means the checker has not finished its first
# probe, not that the path is bad - likeliest right after a boot or an SR plug, i.e.
# exactly when someone runs a health check. Seeing one, the collector waits and asks once
# more; if it is still undef, that is reported as found.
MULTIPATH_TRANSIENT_CHK_STATES = ["undef"]
MULTIPATH_RECHECK_DELAY = 2.0    # seconds before that single re-query
MULTIPATH_MAX_LINES = 60         # path rows listed in a detail block

# Kernel-side, timestamped path events. Deliberately NOT the per-map path_faults counter,
# which never resets until the map reloads and would leave a permanent finding behind a
# switch reboot last month; both windows below close by themselves.
#
# Scanned in the FILES below (plus their .1) *and* in the dmesg ring, which is already
# collected for `Dmesg Content` and so costs nothing extra. Neither contains the other:
# kern.log survives a reboot but spans about two rotations, while the ring covers the
# whole uptime on a quiet dom0 and wraps on a busy one. Measured on 8.3.0: path failures
# sat in the ring that were in neither kern.log file.
MULTIPATH_EVENT_PHRASES = [
    "device-mapper: multipath: Failing path",
]
MULTIPATH_EVENT_FILES = [
    "/var/log/kern.log",
]

# --- "LUN Assignments" check ----------------------------------------------------------
LUN_CHANGE_PHRASES = [
    "Warning! Received an indication that the LUN assignments on this target have changed",
]
LUN_CHANGE_FILES = [
    "/var/log/kern.log",
]

CRASH_IGNORE_FILE = ".sacrificial-space-for-logs"   # file in /var/crash that is not a crash
COREDUMP_DIR = "/var/lib/systemd/coredump"          # anything here means a dom0 process died
COREDUMP_MAX_LINES = 50          # coredumps listed in the detail block (newest first)
PKG_DIFF_MAX_LINES = 100         # mismatched yum packages listed
XOSTOR_QCOW2_MAX_LINES = 50      # qcow2 VDIs on XOSTOR listed

# Which per-host checks run on SLAVES in pool mode. The master always runs everything, and
# so does single mode / a solo host run; these toggles exist only to keep a sweep short.
POOL_RUN = {
    "dom0_disk_usage": True,
    "dom0_memory": True,
    "mtu_issues": True,
    "dmesg_content": True,
    "oom_events": True,
    "crash_logs_present": True,
    "coredumps_present": True,
    "tap_ctl_list": True,
    "task_timeout_override": True,
    "lacp_negotiation": True,
    "multipath_health": True,
    "multipath_events": True,
    "silly_mtus": True,
    "dns_gw_non_mgmt_pifs": True,
    "overlapping_subnets": True,
    "log_errors": True,
    "lun_assignments": True,
    "smapi_hidden_leaves": False,
    "rebooted_after_updates": True,
    "yum_patch_level": True,
}
