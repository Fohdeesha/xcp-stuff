# -*- coding: utf-8 -*-
"""Every threshold, list and toggle, in one place. Same names and values as health.sh."""

SCRIPT_VERSION = "3.1"

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
    "task_timeout_override": True,
    "lacp_negotiation": True,
    "silly_mtus": True,
    "dns_gw_non_mgmt_pifs": True,
    "overlapping_subnets": True,
    "log_errors": True,
    "lun_assignments": True,
    "smapi_hidden_leaves": False,
    "rebooted_after_updates": True,
    "yum_patch_level": True,
}
