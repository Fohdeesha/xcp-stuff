# -*- coding: utf-8 -*-
"""Every threshold, list and toggle, in one place. Same names and values as health.sh."""

SCRIPT_VERSION = "3.15"

SSH_TIMEOUT = 45                 # ssh connect timeout, seconds
REMOTE_CMD_TIMEOUT = 300         # max seconds one collector run may take on a host
MAX_PARALLEL_HOSTS = 8           # hosts collected at once (HEALTH_MAX_PARALLEL overrides)
PROGRESS_INTERVAL = 15           # seconds between 'still waiting on ...' lines, tty only
LOCAL_CMD_TIMEOUT = 10           # max seconds a local command may run (hung xoa-updater etc)
XO_REDIS_TIMEOUT = 2             # reading xo's server records straight from redis: 0.002s
                                 # measured, so this is only here to bound a wedged socket
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

# --- stuck mounts and the processes they take down -------------------------------------
# A mount whose server stops answering parks anything that stats it in uninterruptible
# sleep (D state), where no signal can reach it - SIGKILL included. It is not a niche
# failure: it took a pool master out of every report for days, and the script said nothing,
# because nothing it ran ever came back to say anything.
#
# The kernel has its own detector for this and it is NOT enough on its own, which is why
# the D-state scan leads rather than a dmesg phrase. Measured twice over:
#
#   * It is enabled on 8.3.0 - hung_task_timeout_secs=120, CONFIG_DETECT_HUNG_TASK=y - but
#     kernel.hung_task_warnings defaults to 10 and COUNTS DOWN, so it stops logging for
#     the rest of the uptime after ten.
#   * On the host this was built for it never fired AT ALL. 589 processes had been in D
#     state for nearly four days, and there was not one "blocked for more than" line in
#     the dmesg ring, the live kern.log, or any of its 30 rotated archives. Inference, not
#     measurement, for the why: khungtaskd counts only a task that has not been scheduled
#     since its last sweep, and a CIFS reconnect loop wakes its waiters periodically - so
#     the failure this check exists for is one the kernel is structurally quiet about.
NETWORK_FS_TYPES = [             # the ones that can hang forever waiting on a server
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "fuse.glusterfs",
    "afs", "9p", "ncpfs", "lustre", "beegfs",
]
# D state on its own is NOT a fault, and reading it as one was a false positive in the
# field (issue #70, v3.11): a `vhd-util coalesce` a minute into its run was reported as
# stuck, because it was in D at two samples 5s apart - which is exactly what a process
# copying data between VHDs looks like. Every disk read is in D for some of its life.
#
# So a finding needs a second, positive fact: that the process got NOWHERE while it was
# watched. Its CPU ticks and its I/O counters must not move at all across the whole
# window - a process parked in D executes no instructions and completes no I/O, while
# anything doing real work is being woken constantly to hand off the next buffer.
#
# Age is not that fact and never was. It is how long the process has EXISTED, an upper
# bound on how long it has been wedged, so raising the floor would only have moved the
# same false positive to longer-running commands - and a backup can coalesce for an hour.
# The floor stays where it is, as a noise filter, and the report says what age means.
#
# Excluding vhd-util (or tapdisk, or dd) by name was considered and declined: a coalesce
# wedged on a dead SR is precisely the thing worth reporting, and a name list would hide
# it. The progress test keeps that case - a wedged coalesce burns no CPU.
STUCK_RECHECK_DELAY = 5          # seconds between D-state samples
STUCK_SAMPLES = 3                # samples that must ALL show it wedged, so a 10s window.
                                 # Only the first wait is paid by a host that is merely
                                 # busy: one look at its CPU counter drops it
STUCK_MIN_AGE = 60               # a process must also have existed this long to count
STUCK_MAX_LINES = 25             # stuck processes listed in the detail block, oldest first
MOUNT_PROBE_TIMEOUT = 10         # seconds a stat() of one mount point may take
MOUNT_PROBE_RESERVE = 60         # run-budget seconds kept back for everything that comes
                                 # after the probes. Every mount is probed now, dead ones
                                 # included, and each dead one costs the full timeout
                                 # above - so a host with several would leave yum and the
                                 # pool questions to time out behind it. Past this line
                                 # the rest read "not probed", which claims nothing

# Both halves of the same event, from the two sources that keep it - see the multipath
# event phrases above for why neither contains the other.
#
# These name the SERVER, which the process scan cannot. They also age out, and on the host
# above they already had: the only copies left were in kern.log.4.gz and .5.gz, four days
# back, with the ring wrapped clean past them (`dmesg | grep -i cifs` returned nothing at
# all). Reading the .gz archives was considered for exactly that case and declined - it is
# a zgrep of ~30 files on every host of every run to recover a server name that Network
# Mounts already prints from /proc/mounts, for a condition Stuck Processes already reports.
MOUNT_STALL_PHRASES = [
    # verbatim from a live 8.3.0 dom0 whose SMB server had stopped answering:
    # "CIFS VFS: Server 10.10.10.11 has not responded in 120 seconds. Reconnecting..."
    "has not responded in",
    "not responding",            # nfs: "server X not responding, still trying"
    "blocked for more than",     # the kernel's hung-task detector - see the note above on
                                 # why this one cannot be relied on, and is kept anyway
]
MOUNT_STALL_FILES = [
    "/var/log/kern.log",
]

# --- "LUN Assignments" check ----------------------------------------------------------
LUN_CHANGE_PHRASES = [
    "Warning! Received an indication that the LUN assignments on this target have changed",
]
LUN_CHANGE_FILES = [
    "/var/log/kern.log",
]

# --- "XOA Plugins" check ---------------------------------------------------------------
# Where xo-server looks for plugins, and what it accepts as one. Mirrors
# packages/xo-server/config.toml's `plugins.lookupPaths` and registerPlugins() in
# index.mjs: for every lookup path it takes each entry of `<path>/@xen-orchestra` starting
# `server-` and each entry of `<path>` starting `xo-server-`, and the remainder of the
# entry name IS the plugin's name. First path that has a name wins.
#
# Two of the three shipped lookup paths are relative to the process' cwd, which for a
# systemd unit with no WorkingDirectory - and xo-server.service sets none - is "/". Hence
# /node_modules and / here: neither holds a plugin on a stock appliance, and both are a
# place somebody could put one. Listing "/" is one readdir.
XO_PLUGIN_LOOKUP_PATHS = ["/usr/local/lib/node_modules", "/node_modules", "/"]
XO_PLUGIN_PREFIX = "xo-server-"
XO_PLUGIN_SCOPE_DIR = "@xen-orchestra"
XO_PLUGIN_SCOPE_PREFIX = "server-"

# The plugin names Vates ships, as a FALLBACK and not as the answer. A run reads
# xoa-updater's own `getLocalManifest` first and unions those names in, so a plugin Vates
# adds after this list was written is not reported as somebody else's; this list is what
# is left when the updater is down, unregistered or timing out.
#
# Read off a stock appliance (XOA 6.7.1, xo-server 5.207.2, 2026-09-11) and cross-checked
# against packages/xo-server-* in vatesfr/xen-orchestra. `cloud` is a retired Vates plugin
# that is no longer installed but still leaves an `xo:plugin-metadata:cloud` record
# behind. `test-plugin` is deliberately absent: it is a development fixture in Vates' repo
# that XOA does not ship, so an appliance carrying it has had something done to it.
XOA_STOCK_PLUGINS = [
    "audit",
    "auth-github",
    "auth-google",
    "auth-ldap",
    "auth-oidc",
    "auth-saml",
    "backup-reports",
    "cloud",
    "ipmi-sensors",
    "load-balancer",
    "netbox",
    "netdata",
    "openmetrics",
    "perf-alert",
    "sdn-controller",
    "telemetry",
    "transport-email",
    "transport-icinga2",
    "transport-nagios",
    "transport-slack",
    "transport-xmpp",
    "usage-report",
    "web-hooks",
    "xoa",
]

CRASH_IGNORE_FILE = ".sacrificial-space-for-logs"   # file in /var/crash that is not a crash
COREDUMP_DIR = "/var/lib/systemd/coredump"          # anything here means a dom0 process died
COREDUMP_MAX_LINES = 50          # coredumps listed in the detail block (newest first)
PKG_DIFF_MAX_LINES = 100         # mismatched yum packages listed
XOSTOR_QCOW2_MAX_LINES = 50      # qcow2 VDIs on XOSTOR listed
DMESG_MAX_LINES = 80             # lines of a dmesg detail block (Dmesg Content, OOM Events);
                                 # the newest are kept, and the rollup runs first
DMESG_ROLLUP_MIN = 3             # consecutive copies of one dmesg message folded into a
                                 # 'repeated N times' line from this many; fewer print in full

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
    "stuck_processes": True,
    "mount_stalls": True,
    "network_mounts": True,
    "silly_mtus": True,
    "dns_gw_non_mgmt_pifs": True,
    "overlapping_subnets": True,
    "log_errors": True,
    "lun_assignments": True,
    "smapi_hidden_leaves": False,
    "rebooted_after_updates": True,
    "yum_patch_level": True,
}
