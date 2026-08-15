#!/usr/bin/env bash
# J-Sands / Vates
# V2.5
#
# Runs in two environments, decided by /etc/os-release (see detect_run_env):
#   XOA  - the normal case: reaches every host of a pool over ssh (sshpass + xo-server-db)
#   host - run directly on an XCP-ng/XenServer dom0: commands for THIS host run locally
#          instead of over ssh, and the XOA-only parts (updater status, pool picker,
#          password lookup) are gone. The other pool members are checked too as long as a
#          root password is available (argument, or a prompt when there is a terminal) -
#          dom0 ships no sshpass, so ensure_sshpass installs it from the stock 'extras'
#          repo, exactly like the apt install it does on XOA. With no password it checks
#          this host alone and says so; the pool-level section runs either way, since
#          those are 'xe' calls and xapi answers them from any pool member, slave included.
#
# NB dom0 ships bash 4.2, where "${empty_array[@]}" under 'set -u' is an unbound-variable
# error (fixed in 4.4, so XOA's bash 5.x never sees it). Array expansions that can legally
# be empty are count-guarded for that reason - keep it that way when adding checks.
set -euo pipefail
set +H 2>/dev/null || true   # make ! in args no explode

# =========================
# config
# =========================
ssh_timeout=45                                  # SSH connect timeout in secs
remote_cmd_timeout=180                          # max secs a single remote command may run before being killed (hung xe etc)
local_cmd_timeout=10                            # max secs a single local command may run before being killed (hung xoa-updater etc)
xoa_check_timeout=60                            # max secs 'xoa check' may run (it does real network probes, so it gets longer than local_cmd_timeout)
dom0_max_used=75                                # dom0 percent disk / storage use allowed before flagging as failed
dom0_mem_used_max_pct=65                        # dom0 percent memory allowed in use before flagging as failed
xostor_min_ram_gb=15                            # Minimum total RAM (GB) dom0 should have if xostor is in use
mtu_dmesg_keywords="mtu large fragment"         # keywords in dom0 to flag MTU issues
dmesg_issue_words="panic crash rip kill"        # words that trigger dmesg contents issues
dmesg_issue_phrases="call trace|timed out"      # matches that trigger dmesg contents issues (whole phrase matched, pipe separated)
# dmesg lines that match an issue word/phrase above but are known-benign false positives.
# Each array entry is one ignore rule: a matching line is exempted only if it contains ALL of
# the rule's "&&"-separated substrings (case-insensitive). Add new rules as new entries.
dmesg_ignore_rules=(
  "megaraid && firmware crash dump"             # megaraid driver load prints "firmware crash dump : no"
)
oom_phrase="out of memory"                      # phrase that flags OOM runs

# --- "Log Errors" check ---
# Phrases that flag a problem when found in the logs listed below. Matched as plain
# case-insensitive substrings (not regex), so no escaping needed - add new ones freely.
# Each phrase is reported separately, so a noisy phrase can't hide a rare one.
log_error_phrases=(
  "except"                                      # python tracebacks / SMAPI exceptions
  "Input/output error"
  "XENAPI_PLUGIN_FAILURE"
  "TapdiskNotRunning"                           # tapdisk died under it - pairs with a core.tapdisk.* in $coredump_dir
)
# Logs scanned for the phrases above. Each is searched together with its rotated ".1"
# copy, because these rotate daily (~04:00) - right after a rotation the live file is
# nearly empty and this morning's errors are already in .1.
log_error_files=(
  "/var/log/SMlog"
  "/var/log/xensource.log"
)
log_error_context=3                             # lines of context shown either side of a match

# --- "LUN Assignments" check ---
# Same scan machinery as above, pointed at the kernel log (also read with its .1 copy)
lun_change_phrases=(
  "Warning! Received an indication that the LUN assignments on this target have changed"
)
lun_change_files=(
  "/var/log/kern.log"
)

crash_ignore_file=".sacrificial-space-for-logs" # file in /var/crash to ignore (don't flag on crash logs cuz of this)
coredump_dir="/var/lib/systemd/coredump"        # systemd-coredump drop dir - anything in here means a dom0 process died (tapdisk etc)
coredump_max_lines=50                           # max amt of coredumps to list in the detail block (newest first)
pkg_diff_max_lines=100                          # max amt of mismatched yum packages to list
xostor_qcow2_max_lines=50                       # max amt of qcow2 VDIs on XOSTOR to list in the detail block
time_sync_allowance_secs=300                    # max allowed time difference between hosts in seconds

## which tests should run on ALL hosts when script is ran in pool mode (which is default)
## setting to 0 means the command is only ran on the master, not every single host
## these settings have no effect when the script is ran in single (not pool) mode, all checks are always done
pool_run_dom0_disk_usage=1
pool_run_dom0_memory=1
pool_run_mtu_issues=1
pool_run_dmesg_content=1
pool_run_oom_events=1
pool_run_crash_logs_present=1
pool_run_coredumps_present=1
pool_run_lacp_negotiation=1
pool_run_silly_mtus=1
pool_run_dns_gw_non_mgmt_pifs=1
pool_run_overlapping_subnets=1
pool_run_log_errors=1
pool_run_lun_assignments=1
pool_run_smapi_hidden_leaves=0
pool_run_rebooted_after_updates=1
pool_run_yum_patch_level=1

# petula clark - color my world
# only colorize when stdout is a terminal (or HEALTH_FORCE_COLOR=1), so piped/logged output
# stays clean (deliberately NOT named FORCE_COLOR - node tools like xoa-updater honor that
# one and would start colorizing the output we parse)
if [[ -t 1 || "${HEALTH_FORCE_COLOR:-0}" == "1" ]]; then
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  CYAN=$'\033[36m'
  RESET=$'\033[0m'
else
  GREEN=""
  YELLOW=""
  CYAN=""
  RESET=""
fi

# flag passes / fails with color
ok()        { printf "%sOK%s"   "$GREEN" "$RESET"; }
none()      { printf "%sNone%s" "$GREEN" "$RESET"; }
fail()      { printf "%sFail%s" "$YELLOW" "$RESET"; }
yes()       { printf "%sYes%s"  "$YELLOW" "$RESET"; }
green_text()  { printf "%s%s%s" "$GREEN" "$1" "$RESET"; }
yellow_text() { printf "%s%s%s" "$YELLOW" "$1" "$RESET"; }
cyan_text()   { printf "%s%s%s" "$CYAN" "$1" "$RESET"; }

# globals
RUN_ENV="xoa"                       # "xoa" or "host" - set by detect_run_env from /etc/os-release
LOCAL_HOST_IP=""                    # host mode: this host's address, as xapi spells it (map key)
LOCAL_HOST_NAME=""                  # host mode: this host's hostname, for the banner
LOCAL_HOST_UUID=""                  # host mode: this host's uuid, from /etc/xensource-inventory
POOL_CMD_HOST=""                    # host the pool-level xe questions are asked on: the master
                                    # over ssh from XOA, ourselves in host mode (xapi on a slave
                                    # forwards pool queries to the master anyway)
POOL_ALL_HOST_IPS=()                # every address xapi listed for the pool, kept before host
                                    # mode narrows POOL_HOST_IPS down to this machine
HOST_POOL_SWEEP=0                   # host mode: 1 = we have a password (and sshpass) and are
                                    # checking the rest of the pool too, 0 = this host alone
HOST_POOL_PASS=""                   # the password prepare_host_pool_sweep settled on
POOL_MODE=1
FILTER_OUTPUT=0
POOL_NAME_FILTER=""                 # -n: substring to match a pool by name in xo-db (case insensitive)
DETAILS_OUTPUT=""
POOLDETAILS_OUTPUT=""
POOLCONF_SUMMARY=""
POOL_HOST_IPS=()
POOL_HOST_NOACCESS_IPS=()
POOL_HOST_ACCESS_IPS=()
declare -A POOL_HOST_UUIDS=()
declare -A POOL_HOSTS_MEM=()
declare -A POOL_HOSTS_NTP=()
declare -A POOL_HOSTS_STATUS=()
SSH_PORT=22
PARSED_HOST=""
SELECTED_HOST=""                    # host chosen from the xo-db pool picker (set by select_host_from_xoa_db)
SELECTED_POOL_NAME=""               # xo-db name of that pool, as the picker menu would show it ("" if unknown)
MASTER_RPMLIST=""
MASTER_RPMHASH=""
POOL_RAM_MATCH=1
POOL_NTP_MATCH=1
POOL_MISSING_PATCHES=0
DETECTED_MASTER_IP=""
DETECTED_MASTER_HOSTNAME=""
XOSTOR_IN_USE=0                     # set by check_xostor_in_use_and_ram, read right after it
MASTER_XOSTOR_IN_USE=0
MASTER_POOL_UUID=""
MEM_TOTAL_GB="0.0"
MEM_USED_PCT="0.0"
MEM_KNOWN=0                         # 0 = memory for the current host could not be read, so
                                    # the dom0 memory lines must say Unknown, not a green 0.0%
PW_NOTIFY=0                         # flag to indicate we should print a warning about backslash in password
WORK_DIR=""                         # temp dir for ssh control sockets / stderr capture (set in main)

# Are we on a hypervisor or on XOA? XCP-ng and XenServer dom0 both set ID=xenenterprise
# in /etc/os-release (NAME is "XCP-ng" / "XenServer"), which nothing else does; anything
# else is treated as XOA and still has to pass the Debian version gate in main.
# Deliberately keyed on os-release rather than on "does /usr/bin/xe exist", so a machine
# that merely has the CLI installed (an XOA with xe-cli, a dev box) is not mistaken for a
# host - and so the failure when we are on a hypervisor without a working xe is a clear
# message rather than a silent fallback into the XOA path.
detect_run_env() {
  local id name
  id="$(awk -F= '/^ID=/ {gsub(/"/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null || true)"
  name="$(awk -F= '/^NAME=/ {gsub(/"/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null || true)"

  if [[ "$id" == "xenenterprise" || "$name" == XCP-ng* || "$name" == XenServer* ]]; then
    RUN_ENV="host"
  else
    RUN_ENV="xoa"
  fi
}

# Host mode: work out who we are, before anything else runs.
#
# The address has to be the exact string xapi uses, because every per-host map in this
# script is keyed by it (POOL_HOST_UUIDS, and through it memory / enabled / multipathing /
# NTP) - so it comes from xapi itself rather than from 'ip addr', which would spell a
# management address differently the moment there is more than one on the interface.
# The uuid comes from /etc/xensource-inventory, which is a local file and is exactly what
# xapi means by "this host" (INSTALLATION_UUID), so it is right even when the host is a
# slave and 'xe host-list' returns the whole pool.
# Returns 1 (with a message) if either could not be established - guessing here would
# silently check the wrong host or fill every map with misses.
resolve_local_host_identity() {
  LOCAL_HOST_UUID=""
  LOCAL_HOST_IP=""
  LOCAL_HOST_NAME=""

  if ! command -v xe >/dev/null 2>&1; then
    echo "ERROR: this looks like an XCP-ng/XenServer host, but 'xe' was not found in PATH." >&2
    return 1
  fi

  LOCAL_HOST_UUID="$(awk -F"'" '/^INSTALLATION_UUID=/ {print $2; exit}' /etc/xensource-inventory 2>/dev/null || true)"
  if [[ ! "$LOCAL_HOST_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "ERROR: could not read INSTALLATION_UUID from /etc/xensource-inventory." >&2
    return 1
  fi

  # same timeout the local xoa-updater calls get: a wedged xapi must not hang the run
  LOCAL_HOST_IP="$(timeout "$local_cmd_timeout" xe host-param-get uuid="$LOCAL_HOST_UUID" param-name=address 2>/dev/null | tr -d '\r' | head -n 1 || true)"
  LOCAL_HOST_IP="${LOCAL_HOST_IP//[[:space:]]/}"

  if [[ -z "$LOCAL_HOST_IP" ]]; then
    echo "ERROR: could not get this host's address from xapi (is the toolstack running?)." >&2
    return 1
  fi

  # cosmetic only (the banner), so a failure here just leaves the address to speak for itself
  LOCAL_HOST_NAME="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
  LOCAL_HOST_NAME="${LOCAL_HOST_NAME//[[:space:]]/}"

  return 0
}

usage() {
  # help asked for (-h, exit 0) goes to stdout; usage *errors* go to stderr
  local rc="${1:-2}" fd=1
  (( rc == 0 )) || fd=2
  {
  if [[ "$RUN_ENV" == "host" ]]; then
    # on a hypervisor there is no xo-server-db to name a pool or look a password up in,
    # and no sshpass to reach another host with, so the target is not selectable
    echo "Usage (running on an XCP-ng host):"
    echo "  $0 [-f] [-s] [root_password]"
    echo ""
    echo "  - This host is always checked, using local commands (no ssh, no password needed)"
    echo "  - The other pool members are checked too if a root password is given: they are"
    echo "    reached over ssh, and sshpass is installed from the stock 'extras' repo if missing."
    echo "    Pool members share the master's root password, so one password covers the pool"
    echo "  - With no password and a terminal you are asked for one; blank, or no terminal"
    echo "    (cron, pipe), just checks this host and says so in the Pool Status section"
    echo "  - Prefer the prompt over the argument: an argument is visible in 'ps' and lands"
    echo "    in your shell history"
    echo "  - Pool-level results are reported either way, since xapi answers those from any"
    echo "    pool member, slave included"
    echo "  - Use '-f' flag to filter output to only show issues found"
    echo "  - Use '-s' flag to skip the pool-level section and only report on this host"
    echo ""
    echo "  Examples:"
    echo "  $0"
    echo "  $0 -f"
    echo "  $0 'mypass'"
  else
    echo "Usage:"
    echo "  $0 [-f] [-s] [-n name] [pool_master_or_host[:ssh_port] [root_password]]"
    echo ""
    echo "  - All parameters are optional"
    echo "  - If a host is not supplied, the enabled pools in xo-server-db are listed to pick from"
    echo "    (a single enabled pool, or non-interactive use, just takes the first one)"
    echo "  - If a password is not supplied, it will be looked up locally in xo-server-db"
    echo "  - By default, the script runs in pool mode (checks all hosts in the pool)"
    echo "  - Use '-f' flag to filter output to only show issues found"
    echo "  - Use '-s' flag to only check the specified host (do not check other pool members if present)"
    echo "  - Use '-n' to pick a pool from xo-server-db by name instead of being prompted:"
    echo "    the first pool whose name contains the text is used, matched anywhere in the"
    echo "    name and ignoring case, so '-n sec' matches 'XEN-SECONDARY'"
    echo ""
    echo "  Examples:"
    echo "  $0 192.168.1.5"
    echo "  $0 192.168.1.6 'mypass'"
    echo "  $0 -s 192.168.1.7 'mypass'"
    echo "  $0 -n sec"
    echo "  $0 -f -n 'xen-main'"
  fi
  } >&"$fd"
  exit "$rc"
}

parse_target_host_and_port() {
  local target="$1"

  SSH_PORT=22
  PARSED_HOST="$target"

  if [[ "$target" =~ ^(.+):([0-9]+)$ ]] && [[ "$target" != *"["*"]"* ]]; then
    local h="${BASH_REMATCH[1]}"
    local p="${BASH_REMATCH[2]}"

    # rough IPv6 avoidance, todo
    if [[ "$h" != *:* ]]; then
      SSH_PORT="$p"
      PARSED_HOST="$h"
    fi
  fi
}

# True when we are on a hypervisor that cannot reach the rest of the pool (no password, or
# nothing else to reach). That is the one thing that decides whether a host-mode run reports
# on the pool or on this machine alone, so the checks that need a second host ask this
# rather than testing RUN_ENV - a host WITH a password behaves like an XOA run.
host_solo() {
  [[ "$RUN_ENV" == "host" ]] && (( HOST_POOL_SWEEP == 0 ))
}

ensure_sshpass() {
  if command -v sshpass >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$RUN_ENV" == "host" ]]; then
    # dom0 has no sshpass, but 'extras' is a stock XCP-ng repo - it ships in
    # /etc/yum.repos.d/CentOS-Base.repo pointing at Vates' own mirror
    # (repo.vates.tech/centos/$releasever/extras) - just disabled by default. --enablerepo
    # is a one-shot: the repo is still disabled afterwards, so the host's yum config is
    # left exactly as it was. The package is 21KB with no dependencies (verified on 8.2.1
    # and 8.3.0), which is why installing it automatically is defensible at all.
    #
    # Output is captured rather than printed: a page of yum in the middle of a health
    # report is noise, and it is only interesting when the install fails. Unlike the apt
    # branch this reports failure instead of pressing on, so the caller can fall back to
    # checking this host alone rather than dying.
    echo "sshpass not found - installing it from the XCP-ng 'extras' repo to reach the other pool hosts..." >&2

    local yum_out yum_rc=0
    yum_out="$(timeout "$remote_cmd_timeout" yum --enablerepo=extras install -y sshpass 2>&1)" || yum_rc=$?

    if ! command -v sshpass >/dev/null 2>&1; then
      {
        echo "ERROR: could not install sshpass (yum exit code $yum_rc)."
        printf '%s\n' "$yum_out" | tail -n 5
      } >&2
      return 1
    fi

    echo "sshpass installed." >&2
    return 0
  fi

  echo "sshpass not found. Installing via apt..." >&2
  apt-get update -y
  apt-get install -y sshpass

  # ezez
  return 0
}

# Host mode: decide whether this run can also check the other pool members, and with what.
# Called once, after get_pool_host_details has told us how big the pool is.
#
# A hypervisor has no xo-server-db to look a password up in, so it comes from the command
# line or from asking - and asking only makes sense with a terminal, so cron/pipe runs
# quietly check this host alone instead of hanging on a prompt. No password is not an
# error: it is the documented single-host behaviour, and the Pool Status section says so.
#
# Sets HOST_POOL_SWEEP and HOST_POOL_PASS (the caller adopts the latter as its password).
prepare_host_pool_sweep() {
  HOST_POOL_SWEEP=0
  HOST_POOL_PASS="$1"

  # -s asked for this host only, and a single-host pool has nothing else to check
  (( POOL_MODE == 1 )) || return 0
  (( ${#POOL_ALL_HOST_IPS[@]} > 1 )) || return 0

  if [[ -z "$HOST_POOL_PASS" && -t 0 ]]; then
    # to stderr, like the pool picker's prompt, so it never lands in redirected output.
    # -s so it is not echoed - which also means the newline the user typed is swallowed,
    # so the first echo ends the prompt line and the second separates it from the report.
    printf "This pool has %d hosts. Root password to check the others (blank = this host only): " \
      "${#POOL_ALL_HOST_IPS[@]}" >&2
    read -rs HOST_POOL_PASS || HOST_POOL_PASS=""
    echo "" >&2
    echo "" >&2
  fi

  [[ -n "$HOST_POOL_PASS" ]] || return 0

  if ! ensure_sshpass; then
    echo "Continuing with this host only." >&2
    HOST_POOL_PASS=""
    return 0
  fi

  HOST_POOL_SWEEP=1
  return 0
}

print_xoa_status_section() {
  local out DMESG_ISSUES_BLOCK XOA_CHANNEL XOA_CURRENT XOA_DEBIAN
  local XOA_PLAN XOA_REGIST XOA_VERSION XOA_UPDATER XOA_LICENSES

  # anything printed yellow in this section flips the return code, so XOA-side
  # problems count toward the script exit code like every other check
  local rc_any=0

  # every updater/xoa invocation gets a timeout, not just the first one - a wedged
  # updater daemon that answers one call and hangs on the next used to stall the run
  local rc=0
  out=$(timeout "$local_cmd_timeout" xoa-updater) || rc=$?
  if [ "$rc" -eq 124 ]; then
    XOA_UPDATER=0
  else
    XOA_UPDATER=1
    XOA_CHANNEL="$(awk '/channel selected/ {print $1; exit}' <<< "$out" || true)"
    XOA_CURRENT=""
    if grep -q 'All up to date' <<< "$out"; then
      XOA_CURRENT=1
    fi

    out=$(timeout "$local_cmd_timeout" xoa-updater raw-api-call isRegistered || true)
    XOA_REGIST=$(echo "$out" | awk -F"email: '" '{ if(NF>1){split($2,a,"'\'',"); print a[1]} }')

    XOA_VERSION=$(timeout "$local_cmd_timeout" xoa-updater raw-api-call getLocalManifest 2>/dev/null | awk -F"'" '$2=="xen-orchestra" {print $4}' || true)
    XOA_PLAN=$(timeout "$local_cmd_timeout" xoa-updater raw-api-call getXoaPlan 2>/dev/null | awk '{ gsub(/\x1B\[[0-9;]*[A-Za-z]/, "") } NF>0 { gsub(/[^\x00-\x7F]/, ""); print $1 }' || true)
    XOA_LICENSES=$(timeout "$local_cmd_timeout" xoa-updater raw-api-call getSelfLicenses 2>/dev/null | awk '{ gsub(/\x1B\[[0-9;]*[A-Za-z]/, "") } NF>0 { gsub(/[^\x00-\x7F]/, ""); print $1 }' || true)
  fi

  XOA_DEBIAN=$(lsb_release -a 2>/dev/null | awk '/Description:/ { sub(/^Description:[[:space:]]*/, ""); print }' || true)

  echo "$(cyan_text "== XOA Status ==")"

  if [ "$XOA_UPDATER" -eq 0 ]; then
    printf "XOA-Updater: %s\n" "$(yellow_text 'Timeout issues, unable to determine XOA status')"
    rc_any=1
  else

    if [[ -z "${XOA_REGIST:-}" ]]; then
      printf "Registration: %s\n" "$(yellow_text 'Unregistered')"
      rc_any=1
    else
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Registration: %s\n" "$(green_text "${XOA_REGIST}")"
    fi

    if [[ -z "${XOA_CHANNEL:-}" ]]; then
      printf "XOA Channel: %s\n" "$(yellow_text '(Unknown)')"
      rc_any=1
    else
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOA Channel: %s\n" "$(green_text "${XOA_CHANNEL}")"
    fi

    if [[ -z "${XOA_VERSION:-}" ]]; then
      printf "XOA Version: %s\n" "$(yellow_text 'Unknown')"
      rc_any=1
    else
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOA Version: %s\n" "$(green_text "${XOA_VERSION}")"
    fi

    # plan and license binding share one printed line, so -f has to weigh them together -
    # deciding per half would drop a flagged license along with a healthy plan
    local plan_txt lic_txt plan_flagged=0
    if [[ -z "${XOA_PLAN:-}" ]]; then
      plan_txt="$(yellow_text 'Unknown')"
      plan_flagged=1
    else
      plan_txt="$(green_text "${XOA_PLAN}")"
    fi

    if [[ -z "${XOA_LICENSES:-}" ]]; then
      lic_txt="$(yellow_text 'Unknown')"
      plan_flagged=1
    elif [[ "$XOA_LICENSES" == "[]" ]]; then
      lic_txt="$(yellow_text 'Unbound')"
      plan_flagged=1
    else
      lic_txt="$(green_text 'Bound')"
    fi

    if (( plan_flagged == 1 )); then
      printf "XOA Plan: %s (%s)\n" "$plan_txt" "$lic_txt"
      rc_any=1
    else
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOA Plan: %s (%s)\n" "$plan_txt" "$lic_txt"
    fi

    if [[ -z "${XOA_CURRENT:-}" ]]; then
      printf "XOA Status: %s\n" "$(yellow_text 'Updates available')"
      rc_any=1
    else
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOA Status: %s\n" "$(green_text 'Up to date')"
    fi

    # a timed-out 'xoa check' produces no stderr, which used to read as a green
    # "All OK" - tell the two apart via timeout's exit code 124
    local xoa_check_rc=0
    out=$(timeout "$xoa_check_timeout" xoa check 2>&1 >/dev/null) || xoa_check_rc=$?
    if (( xoa_check_rc == 124 )); then
      printf "XOA Check: %s\n" "$(yellow_text "Timed out after ${xoa_check_timeout}s")"
      rc_any=1
    elif [[ -z "${out//[[:space:]]/}" ]]; then
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOA Check: %s\n" "$(green_text 'All OK')"
    else
      printf "XOA Check: %s\n" "$(yellow_text 'Issues Found, See Output Below')"
      append_details "XOA" "XOA Check Issues" "$out"
      rc_any=1
    fi
  fi

  if [[ -z "${XOA_DEBIAN:-}" ]]; then
    printf "OS Version: %s\n" "$(yellow_text 'Unknown')"
    rc_any=1
  else
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "OS Version: %s\n" "$(green_text "${XOA_DEBIAN}")"
  fi

  local XOA_TOTAL_MEM XOA_AVAIL_MEM
  XOA_TOTAL_MEM="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)"
  XOA_AVAIL_MEM="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)"

  if [[ -z "$XOA_TOTAL_MEM" || -z "$XOA_AVAIL_MEM" ]]; then
    # skipping the memory lines silently would hide that the XO-Server memory limit
    # never got checked at all
    printf "Memory Usage: %s\n" "$(yellow_text 'Unknown (could not read /proc/meminfo)')"
    rc_any=1
  else
    local total_gb avail_gb used_gb used_pct
    total_gb="$(awk -v m="$XOA_TOTAL_MEM" 'BEGIN{printf "%.1f", m/1024/1024}')"
    avail_gb="$(awk -v m="$XOA_AVAIL_MEM" 'BEGIN{printf "%.1f", m/1024/1024}')"
    used_gb="$(awk -v t="$total_gb" -v a="$avail_gb" 'BEGIN{printf "%.1f", t - a}')"
    used_pct="$(awk -v t="$total_gb" -v u="$used_gb" 'BEGIN{ if (t<=0) printf "0.0"; else printf "%.1f", (u/t)*100 }')"

    # an info line with no threshold behind it, so it prints under -f like uptime does
    printf "Memory Usage: %s GB used of %s GB (%s%%)\n" "$(green_text "$used_gb")" "$(green_text "$total_gb")" "$(green_text "$used_pct")"

    local max_old_space
    max_old_space=$(grep -oP '(?<=--max-old-space-size=)\d+' /etc/systemd/system/xo-server.service 2>/dev/null || true)

    if [[ -z "$max_old_space" ]]; then
      printf "XO-Server Memory Limit: %s\n" "$(yellow_text 'Not Set')"
      rc_any=1
    else
      local adjtotal_mb
      adjtotal_mb="$(awk -v m="$XOA_TOTAL_MEM" 'BEGIN{printf "%.0f", m/1024-500}')"
      if [[ "$max_old_space" -lt "$adjtotal_mb" ]]; then
        printf "XO-Server Memory Limit: %s\n" "$(yellow_text "${max_old_space}")"
        rc_any=1
      else
        [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XO-Server Memory Limit: %s\n" "$(green_text "$max_old_space")"
      fi
    fi
  fi

  # a dmesg we couldn't read is not a clean dmesg - check_dmesg_content can't tell an
  # empty buffer from a failed read, so decide that here where the rc is still visible
  local dmesg_t dmesg_rc=0
  dmesg_t="$(dmesg -T 2>/dev/null)" || dmesg_rc=$?

  if (( dmesg_rc != 0 )); then
    printf "Dmesg Content: %s\n" "$(yellow_text 'Unknown (could not read dmesg)')"
    rc_any=1
  elif ! check_dmesg_content "$dmesg_t"; then
    rc_any=1
    if [[ -n "$DMESG_ISSUES_BLOCK" ]]; then
      append_details "XOA" "Dmesg Issues" "$DMESG_ISSUES_BLOCK"
    fi
  fi

  echo ""
  return "$rc_any"
}

# Shared node parser for 'xo-server-db ls' output, used by both the pool picker and
# the password lookup so they read records byte-identically.
#
# 'ls' prints each record with node's util.inspect, which is structured but NOT JSON:
# it picks the quote character per value, so a pool named  Bob's Pool  comes out as
# "Bob's Pool" and one with both quote kinds comes out `like this`. Values may also
# contain braces (the error field holds raw JSON). So we scan the text string-aware
# rather than regexing out {...} blocks - a quote or brace inside a value is otherwise
# indistinguishable from structure. Values are still only ever read as data, never eval'd.
#
# This fragment leaves the parsed records in a 'records' array; each caller appends its
# own single-quoted tail to decide what to print. Both this string and the tails sit
# inside bash single quotes, so they must contain no literal apostrophe or backtick -
# hence String.fromCharCode(39, 34, 96) for the quote set.
XO_DB_PARSER_JS='
    const text = require("fs").readFileSync(0, "utf8");
    // apostrophe(39), double quote(34), backtick(96)
    const QUOTES = String.fromCharCode(39, 34, 96);
    let i = 0;

    const unescape = (s) => s.replace(/\\(u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|.)/g,
      (m, all, ub, u, x) => {
        if (ub !== undefined) return String.fromCodePoint(parseInt(ub, 16));
        if (u !== undefined) return String.fromCharCode(parseInt(u, 16));
        if (x !== undefined) return String.fromCharCode(parseInt(x, 16));
        return { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", "0": "\0" }[all] ?? all;
      });

    // text[i] is an opening quote; consume through the matching close and return the value
    const readQuoted = () => {
      const q = text[i++];
      let raw = "";
      while (i < text.length && text[i] !== q) {
        if (text[i] === "\\") raw += text[i++];   // keep escape, take next char verbatim
        raw += text[i++];
      }
      i++;
      return unescape(raw);
    };

    const KEY = /([A-Za-z_$][\w$]*)\s*:\s*/y;
    const records = [];

    while (i < text.length) {
      if (QUOTES.includes(text[i])) { readQuoted(); continue; }
      if (text[i] !== "{") { i++; continue; }

      i++;
      const rec = {};
      let depth = 1;
      while (i < text.length && depth > 0) {
        const c = text[i];
        if (QUOTES.includes(c)) { readQuoted(); continue; }
        if (c === "{" || c === "[") { depth++; i++; continue; }
        if (c === "}" || c === "]") { depth--; i++; continue; }
        if (depth === 1) {
          KEY.lastIndex = i;
          const m = KEY.exec(text);
          if (m) {
            i = KEY.lastIndex;
            const v = text[i];
            if (QUOTES.includes(v)) rec[m[1]] = readQuoted();
            else if (v !== "{" && v !== "[") {     // bare value: true, 42, null ...
              let bare = "";
              while (i < text.length && !",}\n".includes(text[i])) bare += text[i++];
              rec[m[1]] = bare.trim();
            }
            continue;                             // nested {/[ falls through to depth tracking
          }
        }
        i++;
      }
      records.push(rec);
    }

    const clean = (s) => String(s ?? "").replace(/\s+/g, " ").trim();
'

# Look the root password for a host up in xo-server-db. Prints the password;
# returns 0 = found, 2 = found but it contains a backslash (caller warns via
# PW_NOTIFY - backslash passwords have tripped tooling before), nonzero/empty
# output otherwise. Goes through the shared node parser so every escape form
# util.inspect can emit (\n, \', \xHH, \uHHHH, \\ ...) is decoded correctly -
# the old line-oriented awk kept some escapes verbatim and silently returned a
# wrong password.
get_password_from_xoa_db_simple() {
  local host_only="$1"

  command -v xo-server-db >/dev/null 2>&1 || {
    echo "ERROR: xo-server-db not found in PATH (are you running this on XOA?)." >&2
    return 1
  }

  xo-server-db ls server "host=$host_only" 2>/dev/null |
  node -e "$XO_DB_PARSER_JS"'
    // host= is an indexed lookup, so at most one record comes back
    const pwd = records.length ? records[0].password : undefined;
    if (typeof pwd === "string" && pwd !== "") {
      process.stdout.write(pwd);
      process.exit(pwd.includes(String.fromCharCode(92)) ? 2 : 0);
    }
  '
}


# Emit one "host|poolname" line per *enabled* server in xo-server-db, sorted by pool name.
#
# Deliberately goes through xo-server-db rather than talking to redis directly: when
# xo-server config has redis.encryptCredentialDatabase set, the whole record is stored
# AES-encrypted under xo:server:<id> (and the indexes are HMACed), so a raw redis-cli
# GET returns ciphertext. xo-server-db decrypts transparently and also honors whatever
# redis connection the config points at. 'enabled' is not an indexed field either, so
# the filtering can't be pushed into the db - we do it here.
get_enabled_servers_from_xoa_db() {

  command -v xo-server-db >/dev/null 2>&1 || {
    echo "ERROR: xo-server-db not found in PATH (are you running this on XOA?)." >&2
    return 1
  }

  # parsing of the util.inspect output lives in XO_DB_PARSER_JS (shared with the
  # password lookup) - see the comments on that variable for why it exists
  xo-server-db ls server 2>/dev/null | node -e "$XO_DB_PARSER_JS"'
    const rows = records
      .filter((r) => String(r.enabled) === "true" && r.host)
      // poolNameLabel only exists once XO has connected to the pool at least once;
      // fall back to the user-set server label, then to a placeholder
      .map((r) => ({
        host: r.host,
        name: clean(r.poolNameLabel) || clean(r.label) || "(unnamed)",
        // -n matches either name, not just the displayed one: a pool can show as
        // XEN-PRIMARY while the server label a user remembers it by is XEN-MAIN-01
        search: (clean(r.poolNameLabel) + " " + clean(r.label)).toLowerCase(),
      }))
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }));

    // tab separated: clean() collapsed all whitespace, so no field can contain a tab
    for (const r of rows) console.log([r.host, r.name, r.search].join("\t"));
  '

}

# With no host argument: choose which pool to check from the enabled servers in xo-db.
# -n <str> picks the first name match outright; otherwise a single enabled server is
# used silently and several get a numbered menu.
# Sets SELECTED_HOST and SELECTED_POOL_NAME (main announces the choice - this function
# only resolves it). Returns 0 = chosen, 1 = nothing usable found, 2 = user aborted,
# 3 = -n matched nothing.
select_host_from_xoa_db() {
  SELECTED_HOST=""
  SELECTED_POOL_NAME=""

  local -a names=() hosts=() searches=()
  local name host search
  while IFS=$'\t' read -r host name search; do
    [[ -n "$host" ]] || continue
    hosts+=("$host")
    names+=("$name")
    searches+=("$search")
  done < <(get_enabled_servers_from_xoa_db || true)

  local n="${#hosts[@]}"
  (( n > 0 )) || return 1

  local i

  # -n: first case-insensitive substring match, anywhere in either name. Applied
  # before the menu so it works non-interactively too. Order is the sorted display
  # order, so "first match" is deterministic rather than however redis listed things.
  if [[ -n "$POOL_NAME_FILTER" ]]; then
    local needle="${POOL_NAME_FILTER,,}"
    for (( i = 0; i < n; i++ )); do
      if [[ "${searches[i]}" == *"$needle"* ]]; then
        SELECTED_HOST="${hosts[i]}"
        SELECTED_POOL_NAME="${names[i]}"
        return 0
      fi
    done
    {
      printf "ERROR: no enabled pool in xo-server-db matches '%s'.\n" "$POOL_NAME_FILTER"
      echo "Enabled pools:"
      for (( i = 0; i < n; i++ )); do
        printf "  %s (%s)\n" "${names[i]}" "${hosts[i]}"
      done
    } >&2
    return 3
  fi

  # nothing to choose from, or nobody at the keyboard (piped/cron) - keep the old
  # behaviour of just taking the first enabled server
  if (( n == 1 )) || [[ ! -t 0 ]]; then
    SELECTED_HOST="${hosts[0]}"
    SELECTED_POOL_NAME="${names[0]}"
    return 0
  fi

  {
    echo ""
    echo "$(cyan_text "== Multiple pools found in XOA ==")"
    for (( i = 0; i < n; i++ )); do
      printf "%d - %s (%s)\n" "$((i + 1))" "${names[i]}" "${hosts[i]}"
    done
    echo ""
  } >&2

  local choice
  while true; do
    printf "Select a pool [1-%d], or q to quit: " "$n" >&2

    # default IFS so surrounding whitespace is trimmed; EOF (ctrl-d) reads as a quit
    read -r choice || choice="q"

    case "$choice" in
      q|Q) return 2 ;;
    esac

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= n )); then
      SELECTED_HOST="${hosts[choice - 1]}"
      SELECTED_POOL_NAME="${names[choice - 1]}"
      echo "" >&2
      return 0
    fi

    printf "%s\n" "$(yellow_text 'Invalid selection.')" >&2
  done
}

# Pool name for a host that was given as an argument rather than picked from the menu,
# so every invocation can name what it is about to check. Reuses the picker's listing so
# the name printed is byte-for-byte the one the menu would have shown; that costs one
# extra 'xo-server-db ls' next to a run that is otherwise minutes of ssh.
#
# Quiet and always successful on purpose: a host xo-db has no enabled record for (a
# slave via -s, a pool XO does not manage, or no xo-server-db at all when a host and
# password were both passed) is a normal case, not an error - it just means the banner
# prints the address on its own.
get_pool_name_for_host() {
  local want="$1"

  command -v xo-server-db >/dev/null 2>&1 || return 0

  local host name search
  while IFS=$'\t' read -r host name search; do
    # a db host may carry the ':port' XO connects to xapi on; the caller passes a
    # port-stripped address, so compare against the stripped form too
    if [[ "$host" == "$want" || "${host%:*}" == "$want" ]]; then
      printf "%s\n" "$name"
      return 0
    fi
  done < <(get_enabled_servers_from_xoa_db 2>/dev/null || true)

  return 0
}

# Announce the target before any of the slow remote work starts, however it was arrived
# at: menu choice, the sole enabled pool, -n match, or a host argument. Naming the pool
# where we can is what makes the auto-picked and non-interactive (cron/pipe) runs
# auditable - those take entry #1 silently, and the printed name is the only record of
# which one that was.
print_target_banner() {
  local host="$1"
  local name="$2"

  if [[ -n "$name" ]]; then
    printf "Checking pool: %s\n" "$(green_text "$name ($host)")"
  else
    printf "Checking host: %s\n" "$(green_text "$host")"
  fi
  echo ""
}

# Host mode's half of run_remote: the same command, run straight through bash instead of
# ssh. Kept to the identical contract - stdout is the command's output, stderr is captured
# to a file so it can never contaminate what the parsers read, the timeout is the same one
# a remote command gets, and a failure is reported on stderr with the rc returned.
#
# bash (not sh) on purpose: the scripts build_log_scan_cmd generates use bash ANSI-C
# quoting, exactly as they do when ssh hands them to dom0 root's login shell.
# stdin is closed because nothing we run reads it, and a command that tried would
# otherwise eat the script's own stdin.
run_local() {
  local cmd="$1"

  local output rc
  local errfile="${WORK_DIR:-/tmp}/health-local-err.$$"

  output=$(timeout -k 5 "$remote_cmd_timeout" bash -c "$cmd" </dev/null 2>"$errfile")
  rc=$?

  if (( rc != 0 )); then
    if (( rc == 124 )); then
      echo "Local command timed out after ${remote_cmd_timeout}s" >&2
    else
      echo "Local command failed (exit code $rc)" >&2
    fi
    [[ -s "$errfile" ]] && cat "$errfile" >&2
    [[ -n "$output" ]] && echo "$output" >&2
    return "$rc"
  fi

  echo "$output"
}

run_remote() {
  local host="$1"
  local pass="$2"
  local cmd="$3"

  # Running on a hypervisor: our own commands skip ssh entirely (nothing to gain from
  # logging into ourselves, and it works with no credentials at all). Another pool member
  # still goes over ssh below, but only once prepare_host_pool_sweep has established that
  # we have a password and sshpass - otherwise the call is a bug in the caller, and
  # answering it here would report confidently about the wrong machine.
  if [[ "$RUN_ENV" == "host" ]]; then
    if [[ -z "$LOCAL_HOST_IP" || "$host" == "$LOCAL_HOST_IP" ]]; then
      run_local "$cmd"
      return $?
    fi
    if (( HOST_POOL_SWEEP == 0 )); then
      echo "ERROR: asked to run a command on $host from $LOCAL_HOST_IP with no password for it" >&2
      return 1
    fi
  fi

  local output rc
  local errfile="${WORK_DIR:-/tmp}/health-ssh-err.$$"

  # (the per-check messages that follow a failure say "Failed when trying to ..." rather
  # than naming a transport - whether it was ssh or a local command is said right here)
  # - stderr goes to a file instead of being merged into stdout, so remote warnings
  #   and noise can never contaminate the output our parsers read
  # - timeout guards against remote commands that hang forever (eg xe when xapi is wedged);
  #   it signals the whole process group so ssh dies with sshpass
  # - ControlMaster reuses one ssh connection per host instead of opening a new one per check
  # - sshpass -e (password via env) keeps the password out of the process list
  output=$(
    SSHPASS="$pass" timeout -k 5 "$remote_cmd_timeout" \
    sshpass -e ssh \
      -p "$SSH_PORT" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o ConnectTimeout="$ssh_timeout" \
      -o ControlMaster=auto \
      -o ControlPath="${WORK_DIR:-/tmp}/health-cm-%r@%h:%p" \
      -o ControlPersist=60 \
      -o BatchMode=no \
      root@"$host" \
      "$cmd" \
      2>"$errfile"
  )
  rc=$?

  if (( rc != 0 )); then
    if (( rc == 124 )); then
      echo "SSH command on host $host timed out after ${remote_cmd_timeout}s" >&2
    else
      echo "SSH failed on host $host (exit code $rc)" >&2
    fi
    [[ -s "$errfile" ]] && cat "$errfile" >&2
    [[ -n "$output" ]] && echo "$output" >&2
    return "$rc"
  fi

  echo "$output"
}

get_remote_hostname() {
  local host="$1"
  local pass="$2"

  local out rc
  if out=$(run_remote "$host" "$pass" "hostname -s 2>/dev/null || hostname"); then
    rc=0
    echo "$out" | head -n 1
  else
    rc=$?
    echo "Failed when trying to get hostname from $host (exit code $rc)" >&2
  fi

  return $rc
}

get_pool_uuid() {
  local host="$1"
  local pass="$2"

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pool-list params=uuid --minimal"); then
    rc=0
    out=$(tr -d '\r' <<< "$out")

    # Extract UUID
    if [[ "$out" =~ ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) ]]; then
      echo "${BASH_REMATCH[1]}"
    else
      echo ""
    fi
  else
    rc=$?
    echo "Failed when trying to get pool UUID from $host (exit code $rc)" >&2
  fi

  return $rc
}

check_pool_hosts_access() {
  local pass="$1"

  POOL_HOST_NOACCESS_IPS=()
  POOL_HOST_ACCESS_IPS=()

  local ip
  for ip in "${POOL_HOST_IPS[@]}"; do
    if ! run_remote "$ip" "$pass" "echo SSH_OK" | grep -q "SSH_OK"; then
      POOL_HOST_NOACCESS_IPS+=("$ip")
    else
      POOL_HOST_ACCESS_IPS+=("$ip")
    fi
  done

  if (( ${#POOL_HOST_NOACCESS_IPS[@]} > 0 )); then
    local ips_str
    # ips_str="$(printf "%s, " "${POOL_HOST_NOACCESS_IPS[@]}")"
    # ips_str="${ips_str%, }"
    ips_str="${POOL_HOST_NOACCESS_IPS[*]}"

    echo "Warning: SSH access failed for the following pool hosts: $ips_str" >&2
  fi
}

get_pool_host_details() {
  local host="$1"
  local pass="$2"

  # one pipe-separated line per host via xe param-get, instead of scraping the
  # human-readable host-list output (no label parsing, no field-order assumptions)
  #
  # Do NOT fold the three param-gets into one
  # 'xe host-list uuid=$u params=address,enabled,multipathing --minimal'. --minimal with
  # several params does not emit the values in order - it prints a single value ("true")
  # - and an unknown param name in the list is accepted silently, so the mistake would
  # populate every host map with garbage without erroring. Measured on 8.3.0.
  local out rc cmd
  cmd='for u in $(xe host-list --minimal | tr , " "); do
    a=$(xe host-param-get uuid=$u param-name=address 2>/dev/null)
    e=$(xe host-param-get uuid=$u param-name=enabled 2>/dev/null)
    m=$(xe host-param-get uuid=$u param-name=multipathing 2>/dev/null)
    printf "%s|%s|%s|%s\n" "$u" "$a" "$e" "$m"
  done'

  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
    out=$(tr -d '\r' <<<"$out")

    POOL_HOST_IPS=()
    POOL_ALL_HOST_IPS=()
    POOL_HOST_UUIDS=()
    POOL_HOSTS_STATUS=()

    local uuid addr en mp
    while IFS='|' read -r uuid addr en mp; do
      if [[ -z "$uuid" ]]; then
        continue
      fi
      if [[ -z "$addr" ]]; then
        echo "Warning: pool host $uuid has no address in xapi; skipping it" >&2
        continue
      fi
      POOL_HOST_UUIDS["$addr"]="$uuid"
      POOL_HOST_IPS+=("$addr")
      POOL_ALL_HOST_IPS+=("$addr")
      POOL_HOSTS_STATUS["${uuid}_enabled"]="${en:-Unknown}"
      POOL_HOSTS_STATUS["${uuid}_multipath"]="${mp:-Unknown}"
    done <<< "$out"
  else
    rc=$?
    echo "Failed when trying to get pool host list from $host (exit code $rc)" >&2
  fi

  return $rc
}

get_pool_missing_patches() {
  local pass="$1"

  # yum check-update exits 0 = no updates, 100 = updates available, anything else =
  # yum itself failed (broken repo config, no network, ...). Piping straight into
  # wc -l used to swallow that last case as a green "0 missing patches" - emit a
  # non-numeric sentinel instead so it lands in the existing Unknown (-1) path.
  local out cmd
  cmd="out=\$(sudo yum check-update -q); rc=\$?
if [ \"\$rc\" -eq 100 ]; then
  printf '%s\n' \"\$out\" | awk '/^Loaded plugins:/||NF==0{next} /^Obsoleting Packages/{exit} NF==1&&!/^[[:space:]]/{pkg=\$0;next} pkg&&/^[[:space:]]+/{sub(/^[[:space:]]+/,\"\");print pkg,\$0;pkg=\"\";next} {print}' | wc -l
elif [ \"\$rc\" -eq 0 ]; then
  echo 0
else
  echo YUMERR
fi"
  # Asked of POOL_CMD_HOST: the master over ssh from XOA, this machine on a host - locally
  # and for free even when sweeping the pool, rather than over ssh to the master. Pool
  # members are meant to be at the same patch level, and the per-host "Yum Patch Level"
  # check is what catches one that isn't.
  if out=$(run_remote "$POOL_CMD_HOST" "$pass" "$cmd"); then
    out="$(tr -d '\r' <<< "$out")"

    if [[ -z "$out" || ! "$out" =~ ^[0-9]+$ ]]; then
      POOL_MISSING_PATCHES=-1
    else
      POOL_MISSING_PATCHES=$out
    fi
  else
    POOL_MISSING_PATCHES=-1
  fi

  # the result is the global above, not an rc - print_pool_status_section reads it and
  # renders -1 as Unknown
  return 0
}

# Pool RAM match
# round to nearest GB for sanity
compute_pool_ram_match() {
  local seed_host="$1"
  local pass="$2"

  local expected_gb=""
  local mismatch=0

  local -a all_ips=()
  all_ips+=("$seed_host")
  local ip
  # count-guarded: on dom0's bash 4.2 an empty "${arr[@]}" under set -u aborts the script
  if (( ${#POOL_HOST_ACCESS_IPS[@]} > 0 )); then
    for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
      [[ "$ip" == "$seed_host" ]] && continue
      all_ips+=("$ip")
    done
  fi

  for ip in "${all_ips[@]}"; do
    local gb total_mb uuid
    uuid="${POOL_HOST_UUIDS[$ip]:-}"
    total_mb="${POOL_HOSTS_MEM[${uuid}_total]:-0}"

    # skip hosts we couldn't read memory from - unknown is not a mismatch
    if [[ -z "$uuid" || "$total_mb" == "0" ]]; then
      continue
    fi

    gb="$(awk -v m="$total_mb" 'BEGIN{printf "%d", m/1024+.5}')"

    if [[ -z "$gb" || ! "$gb" =~ ^[0-9]+$ ]]; then
      mismatch=1
      break
    fi

    if [[ -z "$expected_gb" ]]; then
      expected_gb="$gb"
    else
      if [[ "$gb" != "$expected_gb" ]]; then
        mismatch=1
      fi
    fi
  done

  if (( mismatch == 1 )); then
    POOL_RAM_MATCH=0
  else
    POOL_RAM_MATCH=1
  fi
}

# find pool master by pool.conf (dont rely on xapi, could be dead)
detect_pool_master_by_poolconf() {
  local pass="$1"

  DETECTED_MASTER_IP=""
  DETECTED_MASTER_HOSTNAME=""

  (( ${#POOL_HOST_ACCESS_IPS[@]} > 0 )) || return 1

  local ip
  for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
    local pc
    if pc=$(run_remote "$ip" "$pass" "cat /etc/xensource/pool.conf 2>/dev/null | tr -d '\r' | head -n 1 | awk '{\$1=\$1;print}'"); then

      if [[ "${pc,,}" == "master" ]]; then
        DETECTED_MASTER_IP="$ip"
        DETECTED_MASTER_HOSTNAME="$(get_remote_hostname "$ip" "$pass" | tr -d '\r' || true)"
        [[ -z "$DETECTED_MASTER_HOSTNAME" ]] && DETECTED_MASTER_HOSTNAME="$ip"
        return 0
      fi
    fi
  done

  return 1
}

# Host mode's version of the above. dom0 cannot ssh anywhere, so the answer comes from the
# local pool.conf alone: "master" means this machine is it, "slave:<address>" names the
# master outright - which is why pool.conf is worth reading rather than asking xapi, on top
# of it being the thing that stays truthful when the toolstack is wedged.
#
# The master's hostname then comes from its xapi host record ('hostname', which is what
# 'hostname -s' would have answered on it) instead of from a login we cannot make. When we
# are the master ourselves, no lookup is needed at all.
# Same contract as detect_pool_master_by_poolconf: 0 = master identified, 1 = not.
detect_pool_master_local() {
  DETECTED_MASTER_IP=""
  DETECTED_MASTER_HOSTNAME=""

  local pc
  pc="$(tr -d '\r' < /etc/xensource/pool.conf 2>/dev/null | head -n 1 | awk '{$1=$1;print}' || true)"

  case "${pc,,}" in
    master)
      DETECTED_MASTER_IP="$LOCAL_HOST_IP"
      DETECTED_MASTER_HOSTNAME="${LOCAL_HOST_NAME:-$LOCAL_HOST_IP}"
      return 0
      ;;
    slave:*)
      DETECTED_MASTER_IP="${pc#*:}"
      DETECTED_MASTER_IP="${DETECTED_MASTER_IP//[[:space:]]/}"
      [[ -n "$DETECTED_MASTER_IP" ]] || return 1

      local uuid="${POOL_HOST_UUIDS[$DETECTED_MASTER_IP]:-}"
      if [[ -n "$uuid" ]]; then
        DETECTED_MASTER_HOSTNAME="$(run_remote "$LOCAL_HOST_IP" "" "xe host-param-get uuid=$uuid param-name=hostname" || true)"
        DETECTED_MASTER_HOSTNAME="${DETECTED_MASTER_HOSTNAME//[[:space:]]/}"
      fi
      [[ -n "$DETECTED_MASTER_HOSTNAME" ]] || DETECTED_MASTER_HOSTNAME="$DETECTED_MASTER_IP"
      return 0
      ;;
  esac

  return 1
}

# --- RAM calculatios ---
load_mem_stats() {
  local host="$1"

  local uuid="${POOL_HOST_UUIDS[$host]:-}"

  local total_mb used_mb
  total_mb="${POOL_HOSTS_MEM[${uuid}_total]:-0}"
  used_mb="${POOL_HOSTS_MEM[${uuid}_used]:-0}"

  # a total of 0 means we never got this host's meminfo - either its address isn't one
  # xapi knows (so there's no uuid to key on) or the facts sweep failed for it. Say so
  # via MEM_KNOWN: computing a percentage from 0 yields a green "0.0%", which reads as
  # a healthy host when it actually means we never looked.
  if [[ "$total_mb" =~ ^[0-9]+$ ]] && (( total_mb > 0 )); then
    MEM_KNOWN=1
  else
    MEM_KNOWN=0
  fi

  MEM_TOTAL_GB="$(awk -v m="$total_mb" 'BEGIN{printf "%.1f", m/1024}')"
  MEM_USED_PCT="$(awk -v u="$used_mb" -v t="$total_mb" 'BEGIN{ if (t<=0) printf "0.0"; else printf "%.1f", (u/t)*100 }')"
}

# RPM/Yum patch level stuff
#
# Every host's manifest is fetched with this one call and hashed locally by the caller -
# master and slaves alike - so both sides of the comparison are always the same bytes
# through the same digest, and each host runs 'rpm -qa' exactly once per run.
# sshpass is filtered out on BOTH sides, so the comparison stays apples-to-apples: host mode
# installs it on the one host it runs from (ensure_sshpass) to reach the others, which
# otherwise shows up here as "Missing Package: sshpass" on every other host in the pool -
# the script reporting its own footprint as pool drift. Measured: that is exactly what a
# sweep from the master produced before this filter. Its presence on a dom0 says nothing
# about hypervisor health either way.
rpm_manifest_cmd() {
  printf "%s" "rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | grep -v '^sshpass ' | sort"
}

get_rpm_manifest_remote() {
  local host="$1"
  local pass="$2"

  local out rc
  if out=$(run_remote "$host" "$pass" "$(rpm_manifest_cmd)"); then
    echo "$out"
    rc=0
  else
    rc=$?
  fi

  return "$rc"
}

build_context_block() {
  local text="$1"
  local match_lines="$2"

  awk -v match_lines="$match_lines" '
    function add_range(s,e) {
      if (s<1) s=1
      rs[++nr]=s
      re[nr]=e
    }
    BEGIN{
      nr=0
      n=split(match_lines, a, "\n")
      # For each matched line number, create a range of +/- 3 lines for context
      for (i=1;i<=n;i++) if (a[i] ~ /^[0-9]+$/) add_range(a[i]-3, a[i]+3)
    }
    { lines[NR]=$0; max=NR }
    END{
      if (nr==0) exit

      # Sort ranges by start position using selection sort
      for (i=1;i<=nr;i++) {
        min=i
        for (j=i+1;j<=nr;j++) if (rs[j] < rs[min]) min=j
        # Swap range i with range min
        ts=rs[i]; te=re[i]
        rs[i]=rs[min]; re[i]=re[min]
        rs[min]=ts; re[min]=te
      }

      # Merge overlapping ranges and print output with context
      ms=rs[1]; me=re[1]
      for (i=2;i<=nr;i++) {
        if (rs[i] <= me+1) {
          # Ranges overlap or touch - extend the merged range
          if (re[i] > me) me=re[i]
        } else {
          # Gap between ranges - print current merged range and start new one
          if (me > max) me=max
          for (k=ms;k<=me;k++) print "  " lines[k]
          print ""
          ms=rs[i]; me=re[i]
        }
      }
      # Print final merged range
      if (me > max) me=max
      for (k=ms;k<=me;k++) print "  " lines[k]
    }
  ' <<< "$text"
}

# the actual tests
check_hyper_version() {
  local host="$1"
  local pass="$2"

  local cmd out hyper version rc

  cmd="awk -F= '
    /^NAME=/ {gsub(/\"/, \"\", \$2); n=\$2}
    /^VERSION=/ {gsub(/\"/, \"\", \$2); v=\$2}
    END {
      printf \"%s|%s\", n, v
    }' /etc/os-release"

  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to get hypervisor version from $host (exit code $rc)" >&2
    return "$rc"
  fi

  out="$(tr -d '\r' <<< "$out")"
  hyper="${out%%|*}"
  version="${out##*|}"

  if [[ -z "$hyper" || -z "$version" ]]; then
    printf "Hypervisor Version: %s\n" "$(yellow_text 'Unknown')"
    return 1
  fi

  # Compare version: extract major.minor (eg 8.3 from 8.3.0)
  local major minor
  major="$(echo "$version" | cut -d. -f1)"
  minor="$(echo "$version" | cut -d. -f2)"

  # Check if version >= 8.3 (8.2 is no longer supported)
  # The line key stays "Hypervisor Version:" whatever the outcome and the product name
  # rides in the value - keying it on $hyper meant the label itself changed to
  # "Hypervisor Version:" exactly when os-release couldn't be read, so anything reading
  # the output line by line lost the host on the one result it most needed to see.
  if [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]]; then
    if (( major > 8 )) || (( major == 8 && minor >= 3 )); then
      printf "Hypervisor Version: %s\n" "$(green_text "$hyper $version")"
      return 0
    fi
  fi

  printf "Hypervisor Version: %s\n" "$(yellow_text "$hyper $version")"
  return 1
}

check_uptime() {
  local host="$1"
  local pass="$2"

  # NOT 'if ! up=$(...)': $? after a negated pipeline is the negation's status (always
  # 0 here), so the failure message used to claim "exit code 0" for every failure
  local up rc
  if up=$(run_remote "$host" "$pass" "uptime -s 2>/dev/null || true"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to get uptime from $host (exit code $rc)" >&2
    up=""
  fi

  # strip CRs / keep the first line with builtins: piping into 'head -n 1' can SIGPIPE
  # the upstream command, which pipefail would then report as a failure of the ssh call
  up="${up//$'\r'/}"
  up="${up%%$'\n'*}"

  printf "Last Booted:  %s\n" "${up:-Unknown}"
  return 0
}

check_lastpatched() {
  local host="$1"
  local pass="$2"

  local out last rc
  if out=$(run_remote "$host" "$pass" "rpm -qa --last 2>/dev/null | head -n 1 || true"); then
    # rpm prints the install time as the host's strftime %c, so it carries the HOST's
    # zone - either an abbreviation (EDT, CEST, AEDT) or a numeric offset (+07, -05,
    # sometimes already UTC-prefixed). Both are stripped, and what is left is read as a
    # plain wall clock, so this line is reported in the host's own local time - the same
    # frame as the "Last Booted" line right above it, which is printed raw from
    # 'uptime -s' and never converted.
    #
    # Don't "fix" this back into a conversion by feeding the zone to date -d. It only
    # knows a fixed table of abbreviations, so anything outside it (AEST/AEDT/ACST/AWST,
    # ICT, HKT, PHT, WIB, COT, PET, IRST, NPT ...) fails outright and the whole line
    # became "Unknown" - an entire continent's worth of hosts never reported a patch
    # date. Worse, the ones it does accept are ambiguous: a Philippines host says PST
    # (UTC+8) and date -d reads US Pacific (UTC-8), which silently reported a time 16
    # hours off rather than failing. Stripping sidesteps that whole collision class
    # (PST, IST, CST and BST all mean two different things).
    #
    # The AM/PM guard is matched case-insensitively (the I): a locale that renders %c
    # with a lowercase "pm" and no zone would otherwise have the pm eaten as if it were
    # an abbreviation, turning 03:14 PM into 03:14 AM - a silent 12h error.
    last=$(echo "$out" | awk 'NF>1 {$1=""; sub(/^ /,""); print}' | sed -E -e 's/ (UTC)?[+-][0-9]{2}(:?[0-9]{2})?$//' -e '/ (AM|PM)$/I! s/ [A-Za-z]{2,6}$//' | xargs -I{} date -d "{}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)
    rc=0
  else
    rc=$?
    echo "Failed when trying to get last patched info from $host (exit code $rc)" >&2
  fi

  last="${last:-Unknown}"
  printf "Last Patched: %s\n" "$last"
  return 0
}

check_enabled() {
  local ip="$1"

  local uuid enabled
  uuid="${POOL_HOST_UUIDS[$ip]:-}"
  enabled="${POOL_HOSTS_STATUS[${uuid}_enabled]:-Unknown}"

  if [[ "$enabled" == "true" ]]; then
    printf "Host Enabled: %s\n" "$(green_text "$enabled")"
    return 0
  fi

  printf "Host Enabled: %s\n" "$(yellow_text "$enabled")"

  # a host xapi reports as disabled is a real finding; "Unknown" just means the seed
  # address wasn't in the xe host list (eg invoked by hostname) and stays informational
  if [[ "$enabled" == "false" ]]; then
    return 1
  fi
  return 0
}

check_multipath() {
  local ip="$1"

  local uuid mp
  uuid="${POOL_HOST_UUIDS[$ip]:-}"
  mp="${POOL_HOSTS_STATUS[${uuid}_multipath]:-Unknown}"

  if [[ "$mp" == "Unknown" ]]; then
    printf "Multipathing: %s\n" "$(yellow_text "$mp")"
  else
    printf "Multipathing: %s\n" "$(green_text "$mp")"
  fi

  return 0
}

check_host_timesync() {
  local ip="$1"

  local uuid ntp sync
  uuid="${POOL_HOST_UUIDS[$ip]:-}"
  ntp="${POOL_HOSTS_NTP[${uuid}_ntp]:-Unknown}"
  sync="${POOL_HOSTS_NTP[${uuid}_sync]:-Unknown}"

  if [[ "$ntp" != "yes" || "$sync" != "yes" || "$FILTER_OUTPUT" -eq 0 ]]; then
    if [[ "$ntp" != "yes" ]]; then
      printf "NTP: Enabled - %s" "$(yellow_text "$ntp")"
    else
      printf "NTP: Enabled - %s" "$(green_text "$ntp")"
    fi

    if [[ "$sync" != "yes" ]]; then
      printf " Synced - %s\n" "$(yellow_text "$sync")"
    else
      printf " Synced - %s\n" "$(green_text "$sync")"
    fi
  fi

  # an explicit "no" is a real finding either way; in pool mode POOL_NTP_MATCH also
  # catches it at pool level, but single mode used to exit 0 with NTP visibly broken.
  # "Unknown" (address not in the xe maps) stays informational.
  if [[ "$ntp" == "no" || "$sync" == "no" ]]; then
    return 1
  fi
  return 0
}

# One remote call per accessible host fetches both timedatectl and /proc/meminfo -
# these used to be two separate sweeps over the whole pool. Fills POOL_HOSTS_NTP /
# POOL_NTP_MATCH (time sync) and POOL_HOSTS_MEM (memory, MB).
get_pool_host_facts() {
  local pass="$1"

  # each half is || true-guarded so the only nonzero rc is transport failure;
  # a half that failed just parses as empty -> Unknown / zeros
  local cmd="timedatectl 2>/dev/null || true
printf '%s\n' '__HEALTH_FACTS_SEP__'
awk '
  /^MemTotal:/ {t=\$2}
  /^MemAvailable:/ {a=\$2}
  END {
    if (t==0) {print \"0 0\"; exit}
    printf \"%d %d\", int(t/1024), int(a/1024)
  }' /proc/meminfo 2>/dev/null || true"

  (( ${#POOL_HOST_ACCESS_IPS[@]} > 0 )) || return 0

  local ip out rc ts_out mi uuid utc ntp sync unix_time time_diff xo_time
  local tmb amb total_mb used_mb avail_mb
  for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
    if out=$(run_remote "$ip" "$pass" "$cmd"); then
      rc=0
    else
      rc=$?
      echo "Failed when trying to get time/memory info from $ip (exit code $rc)" >&2
      POOL_NTP_MATCH=0
      out=""
    fi

    out="$(tr -d '\r' <<< "$out")"
    ts_out="${out%%__HEALTH_FACTS_SEP__*}"
    mi="${out##*__HEALTH_FACTS_SEP__}"

    uuid="${POOL_HOST_UUIDS[$ip]:-}"

    # --- memory half (was get_pool_host_memory) ---
    tmb="$(awk 'NF {print $1; exit}' <<< "$mi")"
    amb="$(awk 'NF {print $2; exit}' <<< "$mi")"

    if [[ "$tmb" =~ ^[0-9]+$ ]] && [[ "$amb" =~ ^[0-9]+$ ]] && (( tmb > 0 )); then
      total_mb="$tmb"
      avail_mb="$amb"
      if (( total_mb >= avail_mb )); then
        used_mb=$(( total_mb - avail_mb ))
      else
        used_mb=0
      fi
    else
      total_mb=0; used_mb=0; avail_mb=0
    fi

    if [[ -n "$uuid" ]]; then
      POOL_HOSTS_MEM[${uuid}_total]=$total_mb
      POOL_HOSTS_MEM[${uuid}_used]=$used_mb
    fi

    # --- time sync half (was get_pool_timesync) ---
    if (( rc != 0 )); then
      continue   # transport failed; POOL_NTP_MATCH already cleared above
    fi

    # older systemd (xcp-ng 8.x dom0) says "NTP enabled" / "NTP synchronized",
    # newer systemd says "NTP service" / "System clock synchronized" - accept both
    utc="$(awk -F': ' '/Universal time:/ {print $2; exit}' <<< "$ts_out" || true)"
    ntp="$(awk -F': ' '/NTP enabled:|NTP service:/ {print $2; exit}' <<< "$ts_out" || true)"
    sync="$(awk -F': ' '/NTP synchronized:|System clock synchronized:/ {print $2; exit}' <<< "$ts_out" || true)"

    case "$ntp" in
      active) ntp="yes" ;;
      inactive) ntp="no" ;;
    esac

    if [[ -n "$uuid" ]]; then
      POOL_HOSTS_NTP[${uuid}_ntp]="$ntp"
      POOL_HOSTS_NTP[${uuid}_sync]="$sync"
    fi

    if [[ "$ntp" != "yes" || "$sync" != "yes" ]]; then
      POOL_NTP_MATCH=0
      continue
    fi

    # compare against local time taken right now (not at loop start), so ssh
    # latency from earlier hosts doesn't accumulate into fake clock drift
    xo_time=$(date +%s)
    unix_time="$(date -d "$utc" +%s 2>/dev/null || true)"
    if [[ ! "$unix_time" =~ ^[0-9]+$ ]]; then
      POOL_NTP_MATCH=0
      continue
    fi

    time_diff=$(( xo_time - unix_time ))
    if (( time_diff < 0 )); then
      time_diff=$(( -time_diff ))
    fi
    if (( time_diff > time_sync_allowance_secs )); then
      POOL_NTP_MATCH=0
    fi
  done
}

check_dom0_disk_usage() {
  local host="$1"
  local pass="$2"

  local df_out rc
  if df_out=$(run_remote "$host" "$pass" "df -hP"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to get disk usage from $host (exit code $rc)" >&2
    return "$rc"
  fi

  local -a bad=()
  while read -r fs size used avail usep mnt; do
    [[ "$fs" == "Filesystem" ]] && continue
    case "$fs" in tmpfs|devtmpfs|xenstore) continue ;; esac
    # SR mounts (local EXT SRs, NFS/SMB shares) aren't dom0 disks - a filling shared
    # SR would otherwise flag every host in the pool as a "dom0" disk problem
    case "$mnt" in /run/sr-mount/*) continue ;; esac

    usep="${usep%\%}"
    [[ "$usep" =~ ^[0-9]+$ ]] || continue

    if (( usep > dom0_max_used )); then
      bad+=("${mnt} is at ${usep}%")
    fi
  done <<< "$df_out"

  if (( ${#bad[@]} == 0 )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Dom0 Disk Usage: %s\n" "$(ok)"
    return 0
  else
    local msg
    msg="$(printf "%s, " "${bad[@]}")"
    msg="${msg%, }"
    printf "Dom0 Disk Usage: %s - %s\n" "$(fail)" "$msg"
    return 1
  fi
}

check_dom0_memory_lines() {
  # never looked = never green: a 0.0% built from a missing meminfo used to read exactly
  # like a healthy host, with only an stderr line to say otherwise
  if (( MEM_KNOWN == 0 )); then
    printf "Dom0 Memory: %s\n" "$(yellow_text 'Unknown')"
    printf "Dom0 Memory Usage: %s\n" "$(yellow_text 'Unknown (could not read host memory)')"
    return 1
  fi

  printf "Dom0 Memory: %s\n" "$(green_text "${MEM_TOTAL_GB}G")"

  local used_int
  used_int="$(awk -v p="$MEM_USED_PCT" 'BEGIN{printf "%d", p+0.5}')"

  if (( used_int > dom0_mem_used_max_pct )); then
    printf "Dom0 Memory Usage: %s\n" "$(yellow_text "${MEM_USED_PCT}%")"
    return 1
  else
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Dom0 Memory Usage: %s\n" "$(green_text "${MEM_USED_PCT}%")"
    return 0
  fi
}

check_mtu_issues() {
  local dmesg_out="$1"

  local kw
  local -a matched=()
  for kw in $mtu_dmesg_keywords; do
    if grep -qiFw -- "$kw" <<< "$dmesg_out"; then
      matched+=("$kw")
    fi
  done

  if (( ${#matched[@]} == 0 )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "MTU Issues: %s\n" "$(none)"
    return 0
  fi

  local msg
  msg="$(printf "'%s', " "${matched[@]}")"
  msg="${msg%, }"
  printf "MTU Issues: %s\n" "$(yellow_text "Detected (${msg}), check output from dmesg -T")"
  return 1
}

check_dmesg_content() {
  local dmesg_out="$1"
  DMESG_ISSUES_BLOCK=""

  # Flatten the ignore-rule array (one rule per line) for awk; safe when the array is empty.
  local ignore_rules_joined
  ignore_rules_joined="$(printf '%s\n' "${dmesg_ignore_rules[@]:-}")"

  local matches
  matches="$(
    awk -v words="$dmesg_issue_words" -v phrases="$dmesg_issue_phrases" -v ignores="$ignore_rules_joined" '
      function esc_re(s,    t) { t=s; gsub(/[][(){}.*+?^$\\|]/,"\\\\&",t); return t }
      function has_word(line, w,    ww, pat) {
        ww=esc_re(w)
        pat="(^|[^[:alnum:]_])" ww "([^[:alnum:]_]|$)"
        return line ~ pat
      }
      # A line is exempted if it contains ALL substrings of any single ignore rule.
      function line_ignored(line,    i, j, ok) {
        for (i=1;i<=nir;i++) {
          ok=1
          for (j=1;j<=IRC[i];j++) {
            if (!index(line, IR[i,j])) { ok=0; break }
          }
          if (ok) return 1
        }
        return 0
      }
      BEGIN{
        nw=split(words, W, /[[:space:]]+/)
        np=split(phrases, P, /\|/)
        for (i=1;i<=nw;i++) W[i]=tolower(W[i])
        for (i=1;i<=np;i++) { P[i]=tolower(P[i]); gsub(/^[[:space:]]+|[[:space:]]+$/,"",P[i]) }

        # Parse ignore rules: rules split on newline, substrings within a rule split on "&&".
        nir=0
        nlines=split(ignores, IRLINES, /\n/)
        for (i=1;i<=nlines;i++) {
          if (IRLINES[i] ~ /^[[:space:]]*$/) continue
          rc=0
          nc=split(IRLINES[i], SUBS, /&&/)
          for (j=1;j<=nc;j++) {
            s=tolower(SUBS[j])
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",s)
            gsub(/[[:space:]]+/," ",s)
            if (s=="") continue
            rc++
            IR[nir+1, rc]=s
          }
          if (rc>0) { nir++; IRC[nir]=rc }
        }
      }
      {
        l=tolower($0)
        gsub(/[[:space:]]+/, " ", l)

        if (line_ignored(l)) next

        hit=0
        for (i=1;i<=np;i++) {
          if (P[i] != "" && index(l, P[i])) { hit=1; break }
        }
        if (!hit) {
          for (i=1;i<=nw;i++) {
            if (W[i] != "" && has_word(l, W[i])) { hit=1; break }
          }
        }
        if (hit) print NR
      }
    ' <<< "$dmesg_out"
  )"

  if [[ -z "${matches:-}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Dmesg Content: %s\n" "$(green_text 'Clean')"
    return 0
  fi

  DMESG_ISSUES_BLOCK="$(build_context_block "$dmesg_out" "$matches")"
  printf "Dmesg Content: %s\n" "$(yellow_text 'Issues Found, See Output Below')"
  return 1
}

check_oom_events() {
  local dmesg_out="$1"
  OOM_EVENTS_BLOCK=""

  local matches
  matches="$(
    awk -v phrase="$oom_phrase" '
      BEGIN { p=tolower(phrase) }
      { l=tolower($0); if (index(l, p)) print NR }
    ' <<< "$dmesg_out"
  )"

  if [[ -z "${matches:-}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "OOM Events: %s\n" "$(green_text 'No')"
    return 0
  fi

  OOM_EVENTS_BLOCK="$(build_context_block "$dmesg_out" "$matches")"
  printf "OOM Events: %s\n" "$(yellow_text 'Yes, See Below')"
  return 1
}

check_crash_logs_present() {
  local host="$1"
  local pass="$2"

  local cnt rc
  # Use maxdepth 2 because crash files will be in subdirectories
  if cnt=$(run_remote "$host" "$pass" "test -d /var/crash || { echo 0; exit 0; }; find /var/crash -maxdepth 2 -type f ! -name '$crash_ignore_file' 2>/dev/null | wc -l"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check for crash logs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  cnt="${cnt//[[:space:]]/}"
  [[ -z "$cnt" ]] && cnt=0

  if (( cnt > 0 )); then
    printf "Crash Logs Present: %s\n" "$(yellow_text 'Yes - check /var/crash')"
    return 1
  else
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Crash Logs Present: %s\n" "$(green_text 'No')"
    return 0
  fi
}

check_coredumps_present() {
  local host="$1"
  local pass="$2"

  COREDUMPS_BLOCK=""

  # one line per dump - date, size, filename, newest first. systemd names these
  # core.<comm>.<uid>.<bootid>.<pid>.<usec>.xz, so the filename names the process that
  # died (core.tapdisk.* being the interesting one), which is why the list is worth printing
  local out rc
  if out=$(run_remote "$host" "$pass" "test -d '$coredump_dir' || exit 0; find '$coredump_dir' -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM %12s  %f\n' 2>/dev/null | sort -r"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check for coredumps on $host (exit code $rc)" >&2
    return "$rc"
  fi

  local dumps=() line
  while IFS= read -r line; do
    line="${line//$'\r'/}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    dumps+=("$line")
  done <<< "$out"

  local cnt="${#dumps[@]}"
  if (( cnt == 0 )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Coredumps Present: %s\n" "$(green_text 'No')"
    return 0
  fi

  local shown="$cnt"
  (( shown > coredump_max_lines )) && shown="$coredump_max_lines"
  COREDUMPS_BLOCK="$(printf '%s\n' "${dumps[@]:0:shown}")"
  (( cnt > shown )) && COREDUMPS_BLOCK+=$'\n'"(plus $((cnt - shown)) older coredump(s) not listed)"

  printf "Coredumps Present: %s\n" "$(yellow_text "Yes - $cnt file(s), see below")"
  return 1
}

check_lacp_negotiation_issues() {
  local host="$1"
  local pass="$2"

  LACP_OUTPUT_BLOCK=""

  local out rc
  if out=$(run_remote "$host" "$pass" "ovs-appctl lacp/show 2>/dev/null || true"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check LACP negotiation on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -z "${out//[[:space:]]/}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "LACP Negotiation Issues: %s\n" "$(green_text 'No')"
    return 0
  fi

  # per-port lines are "slave: eth0: current attached" on OVS <= 2.16 (XCP-ng 8.2)
  # but OVS 2.17 (XCP-ng 8.3) renamed them to "member: ..." - match both, or every
  # 8.3 host reads as a false green
  local bad
  bad="$(
    awk '
      /^[[:space:]]*(slave|member):/ {
        line=$0
        sub(/[[:space:]]+$/, "", line)
        if (line !~ /: current attached$/) { print "bad"; exit }
      }
    ' <<< "$out"
  )"

  if [[ -n "$bad" ]]; then
    LACP_OUTPUT_BLOCK="$out"
    printf "LACP Negotiation Issues: %s\n" "$(yellow_text 'Yes, See Below')"
    return 1
  fi

  [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "LACP Negotiation Issues: %s\n" "$(green_text 'No')"
  return 0
}

check_silly_mtus() {
  local host="$1"
  local pass="$2"

  local ip_out rc
  if ip_out=$(run_remote "$host" "$pass" "ip link show" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to get link MTUs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  local -a nonstandard=()
  local line
  while IFS= read -r line; do
    [[ "$line" =~ ^[0-9]+:\  ]] || continue

    local ifname mtu
    ifname="$(awk '{print $2}' <<< "$line")"
    ifname="${ifname%:}"
    [[ "$ifname" == "lo" ]] && continue

    mtu="$(sed -n 's/.* mtu \([0-9]\+\) .*/\1/p' <<< "$line")"
    [[ -n "$mtu" ]] || continue

    if [[ "$mtu" != "1500" ]]; then
      nonstandard+=("${ifname}=${mtu}")
    fi
  done <<< "$ip_out"

  if (( ${#nonstandard[@]} > 0 )); then
    local msg
    msg="$(printf "%s, " "${nonstandard[@]}")"
    msg="${msg%, }"
    printf "Silly MTUs: %s - Non-standard MTUs found: %s\n" "$(yes)" "$msg"
    return 1
  else
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Silly MTUs: %s\n" "$(green_text 'OK - All 1500')"
    return 0
  fi
}

check_dns_gw_non_mgmt_pifs() {
  local host="$1"
  local pass="$2"
  local host_uuid="$3"

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pif-list params=gateway,DNS management=false host-uuid=$host_uuid" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check DNS/GW on non-mgmt PIFs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  # Check if ANY gateway or DNS line has a non-empty value
  local found
  found="$(
    awk '
      /gateway[[:space:]]*\([^)]*\)[[:space:]]*:/ {
        # Extract everything after the colon
        sub(/^[^:]*:[[:space:]]*/, "")
        if (length($0) > 0) { print "found"; exit }
      }
      /DNS[[:space:]]*\([^)]*\)[[:space:]]*:/ {
        # Extract everything after the colon
        sub(/^[^:]*:[[:space:]]*/, "")
        if (length($0) > 0) { print "found"; exit }
      }
    ' <<< "$out"
  )"

  if [[ -n "$found" ]]; then
    printf "DNS/GW on Non-Mgmt PIFs: %s\n" "$(yellow_text 'Yes')"
    return 1
  fi

  [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "DNS/GW on Non-Mgmt PIFs: %s\n" "$(green_text 'No')"
  return 0
}

check_vlan0_exist() {
  local host="$1"
  local pass="$2"
  local host_uuid="$3"

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pif-list VLAN=0 host-uuid=$host_uuid --minimal" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check for VLAN PIFs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -n "${out//[[:space:]]/}" ]]; then
    printf "VLAN 0 Check: %s\n" "$(yellow_text 'Yes')"
    return 1
  fi

  [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "VLAN 0 Check: %s\n" "$(green_text 'No')"
  return 0
}

# Read one key out of the pool's other-config map.
# prints the value; returns 0 = key set, 1 = key not set, 2 = could not read the map
#
# Deliberately fetches the whole map rather than asking for the key with 'param-key=':
# when the key isn't set, xapi answers a param-key request with a Cli_failure AND logs
# an exception into xensource.log, so probing key by key made every run of this script
# leave two fresh "except" hits on the master - which check_log_errors would then dutifully
# report as a problem we caused ourselves. Fetching the whole map is quiet.
#
# It also lets us tell "key not set" apart from "xapi isn't answering": a map we read
# successfully that lacks the key is genuinely unconfigured, a map we couldn't read is
# unknown. The old param-key form swallowed both into an empty string.
get_pool_other_config_key() {
  local host="$1"
  local pass="$2"
  local key="$3"

  # An empty pool uuid (get_pool_uuid failed - exactly the wedged-xapi case the rest of
  # this script is built to survive) would go out as "uuid=" and make xapi log a
  # UUID_INVALID exception plus its backtrace into xensource.log on every call, twice per
  # run - the same self-inflicted spam this function exists to avoid, which check_log_errors
  # would then report back as a problem we caused ourselves.
  if [[ -z "${MASTER_POOL_UUID:-}" ]]; then
    return 2
  fi

  local out
  if ! out=$(run_remote "$host" "$pass" "xe pool-param-get uuid=${MASTER_POOL_UUID} param-name=other-config"); then
    return 2
  fi

  # the map prints as "key: value; key: value"; the values we look up are network
  # UUIDs, so splitting records on ';' can't cut one of them in half
  local val
  val="$(awk -v k="$key" '
    BEGIN { RS=";" }
    {
      entry=$0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", entry)
      i=index(entry, ": ")
      if (i==0) next
      name=substr(entry, 1, i-1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name==k) {
        v=substr(entry, i+2)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
        print v
        exit
      }
    }
  ' <<< "$out" || true)"

  [[ -n "${val//[[:space:]]/}" ]] || return 1

  printf '%s' "$val"
  return 0
}

check_migration_network() {
  local host="$1"
  local pass="$2"

  local out krc=0
  out="$(get_pool_other_config_key "$host" "$pass" "xo:migrationNetwork")" || krc=$?

  case "$krc" in
    1)
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Migration Network: %s\n" "$(green_text 'Not configured')"
      return 0
      ;;
    2)
      printf "Migration Network: %s\n" "$(yellow_text 'Unknown (could not read pool other-config)')"
      return 1
      ;;
  esac

  local network_uuid="${out//[[:space:]]/}"
  local member_rc=0
  check_is_bond_member "$host" "$pass" "$network_uuid" || member_rc=$?

  case "$member_rc" in
    0)
      # if this network is set to be a bond member, that's a problem for migration traffic
      printf "Migration Network: %s\n" "$(yellow_text 'Set to bond member')"
      return 1
      ;;
    2)
      printf "Migration Network: %s\n" "$(yellow_text 'Unknown (could not check bond membership)')"
      return 1
      ;;
    *)
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Migration Network: %s\n" "$(green_text 'Configured')"
      return 0
      ;;
  esac
}

# Ping every IPv4 address on the given network's PIFs (one per pool host) from the
# XOA itself: XO moves backup traffic over this network, so the XOA has to reach
# every host on it - "somebody answered" is not enough, one dead slave PIF still
# breaks that host's backups even while the rest of the pool responds. The probe is
# a single ICMP echo per IP, so a network that filters ping reads as unreachable -
# which is why the status line claims "answer ping", not "network down".
# prints the comma separated list of IPs that did not answer when returning 1
# returns 0 = every IP answered, 1 = one or more did not (list printed),
#         2 = could not check (SSH failed), 3 = no usable IPv4 on the network
check_backup_network_reachability_from_xoa() {
  local host="$1"
  local pass="$2"
  local network_uuid="$3"

  local pif_out
  if ! pif_out=$(run_remote "$host" "$pass" "xe pif-list network-uuid=${network_uuid} params=IP --minimal" | tr -d '\r'); then
    echo "Failed when trying to list backup network PIFs on $host" >&2
    return 2
  fi

  # --minimal prints one comma-separated line with an empty field for every PIF
  # that has no IP; keep only well-formed, non-placeholder IPv4 addresses
  local -a fields=() ips=()
  IFS=',' read -r -a fields <<< "$pif_out" || true
  local ip
  # count-guarded for bash 4.2 (see the note at the top of the file)
  if (( ${#fields[@]} > 0 )); then
    for ip in "${fields[@]}"; do
      ip="${ip//[[:space:]]/}"
      [[ -n "$ip" ]] || continue
      [[ "$ip" == "0.0.0.0" ]] && continue
      [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
      ips+=("$ip")
    done
  fi

  (( ${#ips[@]} > 0 )) || return 3

  # Probe all of them at once: a silent IP costs the full -W 2 wait, so probing serially
  # made a wholly unreachable backup network cost 2s per pool host. Each probe drops a
  # marker file for the address that didn't answer, and the list is rebuilt in the
  # original order afterwards so the reported order stays stable.
  local probe_dir="${WORK_DIR:-/tmp}/bnr.$$"
  rm -rf "$probe_dir"
  mkdir -p "$probe_dir"

  local i
  for (( i = 0; i < ${#ips[@]}; i++ )); do
    (
      timeout "$local_cmd_timeout" ping -c 1 -W 2 -n "${ips[i]}" >/dev/null 2>&1 \
        || : > "$probe_dir/$i"
    ) &
  done
  wait || true

  local -a unreachable=()
  for (( i = 0; i < ${#ips[@]}; i++ )); do
    [[ -e "$probe_dir/$i" ]] && unreachable+=("${ips[i]}")
  done
  rm -rf "$probe_dir"

  if (( ${#unreachable[@]} > 0 )); then
    local msg
    msg="$(printf "%s, " "${unreachable[@]}")"
    printf '%s' "${msg%, }"
    return 1
  fi

  return 0
}

# Deliberately reads the field with 'pool-list params=... --minimal' instead of
# 'pool-param-get param-name=...': the param does not exist before 8.3, and asking
# param-get for a missing param makes xapi log a CLI_failed_to_find_param exception
# into xensource.log on every run - which check_log_errors then flags as a problem
# this script caused itself (same trap get_pool_other_config_key documents for
# param-key). The list form answers an unknown field with empty output and rc 0,
# verified quiet on 8.2.1 - so empty cleanly means "feature not there", a real
# answer rather than an error we have to swallow.
check_migration_compression() {
  local host="$1"
  local pass="$2"

  # with an empty pool uuid the list form answers empty and rc 0 - indistinguishable from
  # "the field doesn't exist", so it used to print a green "Not supported (pre-8.3)" on
  # any version without having established anything
  if [[ -z "${MASTER_POOL_UUID:-}" ]]; then
    printf "Migration Compression: %s\n" "$(yellow_text 'Unknown (pool UUID not available)')"
    return 1
  fi

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pool-list uuid=${MASTER_POOL_UUID} params=migration-compression --minimal" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check migration compression on $host (exit code $rc)" >&2
    return "$rc"
  fi

  case "${out//[[:space:]]/}" in
    false)
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Migration Compression: %s\n" "$(green_text 'Disabled')"
      return 0
      ;;
    true)
      printf "Migration Compression: %s\n" "$(yellow_text 'Enabled')"
      return 1
      ;;
    "")
      # pre-8.3 pool: the field is absent, so the feature cannot be on
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Migration Compression: %s\n" "$(green_text 'Not supported (pre-8.3)')"
      return 0
      ;;
    *)
      printf "Migration Compression: %s\n" "$(yellow_text 'Unknown')"
      return 1
      ;;
  esac
}

check_backup_network() {
  local host="$1"
  local pass="$2"

  local out krc=0
  out="$(get_pool_other_config_key "$host" "$pass" "xo:backupNetwork")" || krc=$?

  case "$krc" in
    1)
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Backup Network: %s\n" "$(green_text 'Not configured')"
      return 0
      ;;
    2)
      printf "Backup Network: %s\n" "$(yellow_text 'Unknown (could not read pool other-config)')"
      return 1
      ;;
  esac

  local network_uuid="${out//[[:space:]]/}"
  local member_rc=0
  check_is_bond_member "$host" "$pass" "$network_uuid" || member_rc=$?

  case "$member_rc" in
    0)
      # if this network is set to be a bond member, that's a problem for backup traffic
      printf "Backup Network: %s\n" "$(yellow_text 'Set to bond member')"
      return 1
      ;;
    2)
      printf "Backup Network: %s\n" "$(yellow_text 'Unknown (could not check bond membership)')"
      return 1
      ;;
  esac

  # The ping half asks "can the XOA reach every host on this network", because that is what
  # XO needs to move backup traffic. Pinging the same addresses from a pool host answers a
  # different question, so in host mode it is not run at all rather than run and mislabelled.
  if [[ "$RUN_ENV" == "host" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Backup Network: %s\n" "$(green_text 'Configured (reachability from XOA not checked - run this from XOA for that)')"
    return 0
  fi

  local reach_out reach_rc=0
  reach_out="$(check_backup_network_reachability_from_xoa "$host" "$pass" "$network_uuid")" || reach_rc=$?

  case "$reach_rc" in
    0)
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Backup Network: %s\n" "$(green_text 'Configured and reachable from XOA')"
      return 0
      ;;
    1)
      printf "Backup Network: %s - No ping answer from XOA for: %s\n" "$(yellow_text 'Configured but not fully reachable')" "$reach_out"
      return 1
      ;;
    3)
      printf "Backup Network: %s\n" "$(yellow_text 'Configured but no usable IP was found on the network')"
      return 1
      ;;
    *)
      # 2 = transport trouble: we could not look, which is not the same thing as
      # looking and finding nothing - never claim a fact we did not establish
      printf "Backup Network: %s\n" "$(yellow_text 'Unknown (could not read backup network PIFs)')"
      return 1
      ;;
  esac
}

# returns 0 = network sits on a bond member, 1 = it doesn't, 2 = could not check
check_is_bond_member() {
  local host="$1"
  local pass="$2"
  local network_uuid="$3"

  local out
  if ! out=$(run_remote "$host" "$pass" "xe pif-list network-uuid=${network_uuid} params=bond-slave-of"); then
    echo "Failed when trying to check for bond members on $host" >&2
    return 2
  fi

  # Check if bond-slave-of has a non-empty, non-database value
  awk -F': ' '
    /bond-slave-of/ {
      val=$2
      gsub(/^[ \t]+|[ \t]+$/, "", val)
      if (val != "" && val != "<not in database>") { found=1 }
    }
    END { exit !found }
  ' <<< "$out"
}

# this is ipv4 only currently and will probably explode if fed v6
check_overlapping_subnets() {
  local host="$1"
  local pass="$2"

  local ip_out rc
  if ip_out=$(run_remote "$host" "$pass" "ip -o -4 addr show 2>/dev/null || ip -o -4 address show 2>/dev/null" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to get addresses on $host (exit code $rc)" >&2
    return "$rc"
  fi

  local lst
  lst="$(
    awk '
      $2=="lo" || $2=="lo0" {next}
      {
        for (i=1;i<=NF;i++) {
          if ($i=="inet") { print $2, $(i+1); break }
        }
      }
    ' <<< "$ip_out"
  )"

  if [[ -z "${lst//[[:space:]]/}" ]] || (( $(wc -l <<< "$lst") < 2 )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Overlapping Subnets: %s\n" "$(green_text 'No')"
    return 0
  fi

  local hit
  hit="$(
    awk '
      function ip2int(s,    a) {
        split(s,a,".")
        return (((a[1]*256)+a[2])*256+a[3])*256+a[4]
      }
      {
        ifname=$1
        cidr=$2
        split(cidr, p, "/")
        ip=p[1]; plen=p[2]+0
        if (plen<0 || plen>32 || ip=="") next

        ipi=ip2int(ip)
        # range size = 2^(32-plen)
        pow = 2^(32-plen)
        net = int(ipi/pow)*pow
        bcast = net + pow - 1

        n++
        IF[n]=ifname
        NET[n]=net
        BC[n]=bcast
      }
      END{
        for (i=1;i<=n;i++){
          for (j=i+1;j<=n;j++){
            if (IF[i]==IF[j]) continue  # only care about overlap across different interfaces, not multiple addr on one int
            if (!(BC[i] < NET[j] || BC[j] < NET[i])) { print "yes"; exit }
          }
        }
      }
    ' <<< "$lst"
  )"

  if [[ -n "$hit" ]]; then
    printf "Overlapping Subnets: %s\n" "$(yellow_text 'Yes')"
    return 1
  else
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Overlapping Subnets: %s\n" "$(green_text 'No')"
    return 0
  fi
}

# Build the remote script that scans logs for phrases. For every (log, phrase) pair it
# reports the most recent hit with a few lines of context either side.
#
#   $1 = newline separated base log paths   $2 = newline separated phrases   $3 = context lines
#
# All the work happens on the host - these logs run to tens of MB (xensource.log.1 is
# routinely 50MB+), so we never drag them over the wire, only the few matched lines.
# Each file is scanned ONCE for all phrases together (grep -iF -e p1 -e p2 ...), then a
# small awk pass over just the matched lines attributes the last hit to each phrase -
# scanning per phrase used to reread the same tens-of-MB file once per phrase. Fixed-
# string matching throughout, and one block per phrase, so a phrase that matches
# constantly can never crowd out a rare, more serious one.
# Each base log is tried first, then its rotated .1, per phrase: the live file holds the
# newest hit, and falling back to .1 only for phrases the live file lacks covers the
# daily rotation without reporting a stale hit alongside a current one.
build_log_scan_cmd() {
  local files_nl="$1"
  local phrases_nl="$2"
  local ctx="${3:-3}"

  local q_files="" q_ephrases="" x
  while IFS= read -r x; do
    [[ -n "$x" ]] || continue
    q_files+=" $(printf '%q' "$x")"
  done <<< "$files_nl"
  while IFS= read -r x; do
    [[ -n "$x" ]] || continue
    q_ephrases+=" -e $(printf '%q' "$x")"
  done <<< "$phrases_nl"

  # no phrases configured = nothing to scan for (and grep without -e would misread
  # the filename as its pattern)
  if [[ -z "$q_ephrases" ]]; then
    echo "exit 0"
    return
  fi

  # exits 0 no matter what: no match, an unreadable log and a missing log are all
  # "nothing to report" here, and a nonzero rc would be read as an SSH failure.
  # The phrase list travels to awk via the environment: -v would reprocess backslashes.
  # Note this script is bash-only, not POSIX sh: printf '%q' on a multi-line string emits
  # bash ANSI-C quoting ($'a\nb') for HEALTH_SCAN_PHRASES. Fine because ssh runs it under
  # dom0 root's login shell, which is bash - but keep that in mind before repointing this
  # at anything else.
  # scan_last_hits prints "phraseindex:lineno" for the LAST hit of each phrase in $1;
  # the phrase loop below indexes phrases the same way the awk BEGIN block does (blank
  # lines skipped), so the two stay aligned.
  cat <<EOF
CTX=$(printf '%q' "$ctx")
HEALTH_SCAN_PHRASES=$(printf '%q' "$phrases_nl")
export HEALTH_SCAN_PHRASES
scan_last_hits() {
  grep -inF$q_ephrases -- "\$1" 2>/dev/null | awk '
    BEGIN {
      n = split(ENVIRON["HEALTH_SCAN_PHRASES"], A, "\n")
      m = 0
      for (i = 1; i <= n; i++) if (A[i] != "") { m++; P[m] = tolower(A[i]) }
    }
    {
      num = \$0; sub(/:.*/, "", num)
      line = tolower(\$0); sub(/^[0-9]*:/, "", line)
      for (i = 1; i <= m; i++) if (index(line, P[i])) last[i] = num
    }
    END { for (i = 1; i <= m; i++) if (last[i]) print i ":" last[i] }
  '
}
for base in$q_files; do
  live_hits=""
  rot_hits=""
  rot_scanned=0
  [ -r "\$base" ] && live_hits=\$(scan_last_hits "\$base")
  i=0
  while IFS= read -r ph; do
    [ -n "\$ph" ] || continue
    i=\$((i + 1))
    cand="\$base"
    n=\$(printf '%s\n' "\$live_hits" | sed -n "s/^\$i:\(.*\)/\1/p")
    if [ -z "\$n" ]; then
      if [ "\$rot_scanned" -eq 0 ]; then
        rot_scanned=1
        [ -r "\$base.1" ] && rot_hits=\$(scan_last_hits "\$base.1")
      fi
      cand="\$base.1"
      n=\$(printf '%s\n' "\$rot_hits" | sed -n "s/^\$i:\(.*\)/\1/p")
    fi
    [ -n "\$n" ] || continue
    s=\$((n - CTX)); [ "\$s" -lt 1 ] && s=1
    e=\$((n + CTX))
    printf '%s\n' "--- \$ph (\$cand) ---"
    # the trailing q stops at the end of the range: without it sed reads on to EOF, and
    # these files run to tens of MB with the interesting hits usually near the end
    sed -n "\${s},\${e}p;\${e}q" "\$cand" 2>/dev/null | sed 's/^/  /'
    printf '\n'
  done <<HEALTH_PHRASES_EOF
\$HEALTH_SCAN_PHRASES
HEALTH_PHRASES_EOF
done
exit 0
EOF
}

check_log_errors() {
  local host="$1"
  local pass="$2"

  LOG_ERRORS_BLOCK=""

  local cmd
  # the ":-" forms keep an emptied config list from aborting the script on dom0's bash 4.2;
  # they yield a blank line, which build_log_scan_cmd already skips
  cmd="$(build_log_scan_cmd \
    "$(printf '%s\n' "${log_error_files[@]:-}")" \
    "$(printf '%s\n' "${log_error_phrases[@]:-}")" \
    "$log_error_context")"

  local out rc
  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check logs for errors on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -z "${out//[[:space:]]/}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Log Errors: %s\n" "$(none)"
    return 0
  fi

  LOG_ERRORS_BLOCK="$out"

  printf "Log Errors: %s\n" "$(yellow_text 'Yes, See Error Output')"
  return 1
}

check_lun_assignments() {
  local host="$1"
  local pass="$2"

  LUN_CHANGES_BLOCK=""

  local cmd
  cmd="$(build_log_scan_cmd \
    "$(printf '%s\n' "${lun_change_files[@]:-}")" \
    "$(printf '%s\n' "${lun_change_phrases[@]:-}")" \
    "$log_error_context")"

  local out rc
  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check LUN assignments on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -z "${out//[[:space:]]/}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "LUN Assignments: %s\n" "$(green_text 'Unchanged')"
    return 0
  fi

  LUN_CHANGES_BLOCK="$out"

  printf "LUN Assignments: %s\n" "$(yellow_text 'Changed - see below')"
  return 1
}

check_smapi_hidden_leaves() {
  local host="$1"
  local pass="$2"
  local hostlabel="$3"

  # dedupe remotely, first-seen order preserved (pipeline rc is awk's, so no-match grep is fine)
  local cmd="grep -i 'hidden leaf' /var/log/SMlog 2>/dev/null | awk '!seen[\$0]++'"

  local out rc
  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check SMlog hidden leaves on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -z "${out//[[:space:]]/}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "SMAPI Hidden Leaves: %s\n" "$(none)"
    return 0
  fi

  printf "SMAPI Hidden Leaves: %s\n" "$(yellow_text 'Yes, See Error Output')"
  append_details "$hostlabel" "SMAPI Hidden Leaves" "$out"
  return 1
}

check_xostor_qcow2_vdis() {
  local host="$1"
  local pass="$2"

  # The remote half is a script rather than one pipeline, for three reasons:
  #
  #  - 'xe sr-list --minimal' answers with a COMMA-SEPARATED list when a pool has more
  #    than one linstor SR, and sr-uuid= will not take that: it matches nothing and
  #    still answers rc 0, so the pools most likely to have qcow2 VDIs were the ones
  #    that read as a clean "None". Each SR is asked for separately instead.
  #  - a failed xe must not read as "none" either. The old form swallowed xe's rc with
  #    a trailing '|| true' (needed there, because a no-match grep exits 1 and run_remote
  #    would have reported that as a transport failure), which made a wedged xapi print
  #    a green None. Each xe rc is now checked and reported through a sentinel, and the
  #    awk that does the filtering always exits 0, so no '|| true' is needed at all.
  #  - it reports WHICH VDIs. sm-config alone does not name the VDI it belongs to, so
  #    uuid and name-label are fetched with it and paired up per record.
  #
  # NB: the awk reads xe's whole output, deliberately. Do NOT "optimise" this to
  # 'grep -q qcow2' or 'head -n': xe streams, so closing the pipe early hands xapi an
  # EPIPE that it logs as an exception into xensource.log - which is exactly what
  # check_log_errors greps. Measured on 8.3.0 at +4 exceptions per call, versus 0 for
  # reading to EOF. Same self-inflicted-spam trap as param-key.
  local cmd
  cmd="$(cat <<'HEALTH_QCOW2_EOF'
srs=$(xe sr-list type=linstor --minimal 2>/dev/null) || { echo XEERR; exit 0; }
[ -n "$srs" ] || { echo NOSR; exit 0; }
all=""
for sr in $(printf '%s' "$srs" | tr , ' '); do
  o=$(xe vdi-list sr-uuid="$sr" params=uuid,name-label,sm-config 2>/dev/null) || { echo XEERR; exit 0; }
  all="$all
$o"
done
printf '%s\n' "$all" | awk '
# A record starts at its uuid line and ends at the next one, rather than at a blank
# line: $(...) strips trailing newlines, so gluing two SRs together leaves only a
# single newline between them, and paragraph mode then merged the last record of one
# SR into the first of the next and dropped a VDI.
/^[[:space:]]*uuid [(]/ {
  if (uuid != "" && smc ~ /qcow2/) printf "%s  %s\n", uuid, name
  uuid = $0; sub(/^[^:]*:[[:space:]]*/, "", uuid)
  name = ""; smc = ""
  next
}
/^[[:space:]]*name-label [(]/ { name = $0; sub(/^[^:]*:[[:space:]]*/, "", name); next }
# matched on the sm-config line only, so a VDI merely *named* qcow2 is not a hit
/^[[:space:]]*sm-config [(]/  { smc = $0; next }
END { if (uuid != "" && smc ~ /qcow2/) printf "%s  %s\n", uuid, name }'
exit 0
HEALTH_QCOW2_EOF
)"

  local out rc
  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check XOSTOR qcow2 VDIs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  # the sentinels are emitted alone, so match the whole answer rather than a substring
  local trimmed="${out//[[:space:]]/}"

  if [[ "$trimmed" == "XEERR" ]]; then
    printf "XOSTOR QCOW2 VDIs: %s\n" "$(yellow_text 'Unknown (could not read the VDI list)')"
    return 1
  fi

  # only reachable if the linstor SR went away between check_xostor_in_use_and_ram and
  # here - still not something to call green, since nothing was actually established
  if [[ "$trimmed" == "NOSR" ]]; then
    printf "XOSTOR QCOW2 VDIs: %s\n" "$(yellow_text 'Unknown (no XOSTOR SR found)')"
    return 1
  fi

  if [[ -z "$trimmed" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOSTOR QCOW2 VDIs: %s\n" "$(none)"
    return 0
  fi

  # cap the list like the coredump/pkg-diff blocks do, counting the remainder rather
  # than cutting it silently
  local cnt show
  cnt="$(awk 'NF {c++} END {print c+0}' <<< "$out")"
  show="$out"
  if (( cnt > xostor_qcow2_max_lines )); then
    show="$(head -n "$xostor_qcow2_max_lines" <<< "$out")"
    show+=$'\n'"(plus $((cnt - xostor_qcow2_max_lines)) more qcow2 VDI(s) not listed)"
  fi

  printf "XOSTOR QCOW2 VDIs: %s\n" "$(yellow_text 'Yes, See Below')"
  append_pool_details "---xostor qcow2 vdis---" "$show"
  return 1
}

check_ha_enabled() {
  local host="$1"
  local pass="$2"
  local pool_uuid="$3"

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pool-param-get uuid=$pool_uuid param-name=ha-enabled" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check HA status on $host (exit code $rc)" >&2
    return "$rc"
  fi

  # Match on "true" or "false" anywhere in the output
  if [[ "$out" =~ false ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "HA Enabled: %s\n" "$(green_text 'No')"
    return 0
  elif [[ "$out" =~ true ]]; then
    printf "HA Enabled: %s\n" "$(yellow_text 'Yes')"
    return 1  # Return 1 to flag as warning/issue
  else
    printf "HA Enabled: %s\n" "$(yellow_text 'Unknown')"
    return 1
  fi
}

check_rebooted_after_updates() {
  local host="$1"
  local pass="$2"

  # yum.log records no year, so the year has to be guessed - but dom0 ships coreutils
  # 8.22, which rejects the "YYYY Mon DD HH:MM:SS" ordering outright ("invalid date").
  # Every parse here used to fail into a year-less fallback that silently assumed the
  # current year, and the "that landed in the future, so try last year" correction used
  # the same rejected ordering, so it produced nothing at all: a host last patched in
  # December then read as "not rebooted" for most of the following year. "Mon DD YYYY
  # HH:MM:SS" is the ordering coreutils 8.22 does accept, verified on 8.2.1 and 8.3.0.
  local out rc cmd
  cmd="line=\$(awk '\$4==\"Updated:\" || (\$4==\"Installed:\" && \$5 ~ /^(kernel|xen)/) {l=\$0} END{print l}' /var/log/yum.log 2>/dev/null || true)
if [ -z \"\$line\" ]; then
  echo NOUPDATES
  exit 0
fi

mon=\$(printf '%s\n' \"\$line\" | awk '{print \$1}')
day=\$(printf '%s\n' \"\$line\" | awk '{print \$2}')
tod=\$(printf '%s\n' \"\$line\" | awk '{print \$3}')
year=\$(date +%Y)
now=\$(date +%s)

upd=\$(date -d \"\$mon \$day \$year \$tod\" +%s 2>/dev/null || true)
if [ -n \"\$upd\" ] && [ \"\$upd\" -gt \$((now + 60)) ]; then
  upd=\$(date -d \"\$mon \$day \$((year - 1)) \$tod\" +%s 2>/dev/null || true)
fi

# /proc/stat btime is the exact boot second and always present; 'who -b' rounds to the
# minute, depends on a readable utmp, and prints in the locale's format
boot=\$(awk '/^btime/ {print \$2; exit}' /proc/stat 2>/dev/null || true)

# always two fields: an empty first one let the reader below shift the boot time into
# the update slot and report a confident wrong answer instead of an unknown
printf '%s %s\n' \"\${upd:-NONE}\" \"\${boot:-NONE}\""

  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check reboot status on $host (exit code $rc)" >&2
    return "$rc"
  fi

  out="$(tr -d '\r' <<< "$out")"

  if [[ "${out:-}" == "NOUPDATES" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Rebooted After Updates: %s\n" "$(green_text 'Yes')"
    return 0
  fi

  local upd_epoch boot_epoch
  upd_epoch="$(awk '{print $1}' <<< "$out")"
  boot_epoch="$(awk '{print $2}' <<< "$out")"

  # an unparseable timestamp is not the same finding as "did not reboot" - saying "No"
  # here claimed a fact about the host that was never established
  if [[ ! "${upd_epoch:-}" =~ ^[0-9]+$ || ! "${boot_epoch:-}" =~ ^[0-9]+$ ]]; then
    printf "Rebooted After Updates: %s\n" "$(yellow_text 'Unknown (could not read update or boot time)')"
    return 1
  fi

  if (( boot_epoch >= upd_epoch )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Rebooted After Updates: %s\n" "$(green_text 'Yes')"
    return 0
  else
    printf "Rebooted After Updates: %s\n" "$(yellow_text 'No')"
    return 1
  fi
}

check_xostor_in_use_and_ram() {
  local host="$1"
  local pass="$2"

  XOSTOR_IN_USE=0

  local out rc
  if out=$(run_remote "$host" "$pass" "xe sr-list type=linstor --minimal"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check XOSTOR usage on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -z "${out//[[:space:]]/}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOSTOR In Use: %s\n" "$(green_text 'No')"
    return 0
  fi

  XOSTOR_IN_USE=1
  # a fact about the pool, not a finding, so it's reported like "Multipathing: true" is -
  # printing it yellow while returning 0 was the one place that broke the rule that
  # anything yellow flags the exit code
  printf "XOSTOR In Use: %s\n" "$(green_text 'Yes')"

  # with memory unknown this used to read "Not Enough: 0.0G", which names a cause the
  # host may not have
  if (( MEM_KNOWN == 0 )); then
    printf "XOSTOR RAM: %s\n" "$(yellow_text 'Unknown (could not read dom0 memory)')"
    return 1
  fi

  local total_gb_int
  total_gb_int="$(awk -v g="$MEM_TOTAL_GB" 'BEGIN{printf "%d", g+0.00001}')"

  if (( total_gb_int < xostor_min_ram_gb )); then
    printf "XOSTOR RAM: %s\n" "$(yellow_text "Not Enough: ${MEM_TOTAL_GB}G (Need >=${xostor_min_ram_gb}G)")"
    return 1
  else
    printf "XOSTOR RAM: %s\n" "$(green_text "${MEM_TOTAL_GB}G")"
    return 0
  fi
}

check_xostor_nodes() {
  local host="$1"
  local pass="$2"
  local controllers_csv="$3"

  local out rc
  if out=$(run_remote "$host" "$pass" "command -v linstor >/dev/null 2>&1 || { echo NOLINSTOR; exit 0; }; linstor --controllers=${controllers_csv} n l"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check XOSTOR nodes on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ "$out" == *NOLINSTOR* ]]; then
    printf "XOSTOR Faulty Nodes: %s\n" "$(yellow_text 'Unknown (linstor CLI not found)')"
    return 1
  fi

  local node_not_online

  node_not_online="$(
      printf '%s\n' "$out" |
      awk -F '\\|' '
      # Skip borders and separators
      /^[+]/ || /^\|=/ { next }

      # Header row: find State column
      /Node/ && /State/ {
        for (i=1; i<=NF; i++) {
            gsub(/^[ \t]+|[ \t]+$/, "", $i)
            if ($i=="State") state=i
        }
        next
      }

      # Data rows
      /^\|/ && state {
        # strip ANSI escape codes
        gsub(/\x1B\[[0-9;]*[mK]/, "", $state)

        # trim whitespace
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $state)

        if ($state!="Online") {
            print "yes"
            exit
        }
      }
      '
  )"

  if [[ -n "$node_not_online" ]]; then
    printf "XOSTOR Faulty Nodes: %s\n" "$(yellow_text 'Yes, See Below')"
    append_pool_details "---xostor node status---" "$out"
    return 1
  fi

  [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOSTOR Faulty Nodes: %s\n" "$(green_text 'No')"
  return 0
}

check_xostor_faulty_resources() {
  local host="$1"
  local pass="$2"
  local controllers_csv="$3"

  local out rc
  if out=$(run_remote "$host" "$pass" "command -v linstor >/dev/null 2>&1 || { echo NOLINSTOR; exit 0; }; linstor --controllers=${controllers_csv} r l --faulty"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check XOSTOR faulty resources on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ "$out" == *NOLINSTOR* ]]; then
    printf "XOSTOR Faulty Resources: %s\n" "$(yellow_text 'Unknown (linstor CLI not found)')"
    return 1
  fi

  local has_rows
  has_rows="$(
    awk '
      /^\|[[:space:]]/ && $0 !~ /ResourceName/ { print "yes"; exit }
    ' <<< "$out"
  )"

  if [[ -n "$has_rows" ]]; then
    printf "XOSTOR Faulty Resources: %s\n" "$(yellow_text 'Yes, See Below')"
    append_pool_details "---xostor faulty resources---" "$out"
    return 1
  fi

  [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOSTOR Faulty Resources: %s\n" "$(green_text 'No')"
  return 0
}

check_xostor_controller() {
  local host="$1"
  local pass="$2"
  local controllers_csv="$3"

  local out ip rc
  if out=$(run_remote "$host" "$pass" "command -v linstor >/dev/null 2>&1 || { echo NOLINSTOR; exit 0; }; linstor --controllers=${controllers_csv} c which"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to check XOSTOR controller on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ "$out" == *NOLINSTOR* ]]; then
    printf "XOSTOR Controller IP: %s\n" "$(yellow_text 'Unknown (linstor CLI not found)')"
    return 1
  fi
  ip="$(echo "$out" | awk '!/^Error:/ {
    if ($0 ~ /^linstor:\/\//) {
      sub(/^linstor:\/\//, "")
    }
    print
  }')"

  if [[ -z "${ip//[[:space:]]/}" ]]; then
    printf "XOSTOR Controller IP: %s\n" "$(yellow_text "None")"
    return 1
  fi

  printf "XOSTOR Controller IP: %s\n" "$(green_text "$ip")"
  return 0
}

check_yum_patch_level() {
  local host="$1"
  local pass="$2"
  local is_master="$3"
  local hostlabel="$4"

  # this check compares a host against the pool master's package list, so it needs two
  # hosts: single mode has one by definition, and a solo host run cannot reach a second one
  if (( POOL_MODE == 0 )) || host_solo; then
    return 0
  fi

  if (( is_master == 1 )); then
    printf "Yum Patch Level: %s\n" "$(green_text 'Reference (Master)')"
    return 0
  fi

  if [[ -z "${MASTER_RPMHASH:-}" || -z "${MASTER_RPMLIST:-}" ]]; then
    printf "Yum Patch Level: %s\n" "$(yellow_text 'Unknown (no baseline)')"
    return 1
  fi

  # Fetch the package list once and hash it here, the same way the master's baseline is
  # built. Hashing remotely and then fetching the list on mismatch meant two separate
  # 'rpm -qa' runs, i.e. two different snapshots: a package landing between them produced
  # a "Mismatch, See Below" over an empty difference block. It also costs one less remote
  # rpm run on any host that does differ (measured ~223ms each), and the list is only a
  # few tens of KB over an already-open connection.
  local slave_list
  slave_list="$(get_rpm_manifest_remote "$host" "$pass" || true)"

  if [[ -z "${slave_list//[[:space:]]/}" ]]; then
    # couldn't fetch the list (transient ssh failure etc) - don't call that a mismatch
    printf "Yum Patch Level: %s\n" "$(yellow_text 'Unknown (could not retrieve)')"
    return 1
  fi

  # identical pipeline to the one main uses on MASTER_RPMLIST, so the digests compare
  local h
  h="$(printf '%s\n' "$slave_list" | sha256sum | cut -d' ' -f1)"

  if [[ "$h" == "$MASTER_RPMHASH" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Yum Patch Level: %s\n" "$(green_text 'Match')"
    return 0
  fi

  printf "Yum Patch Level: %s\n" "$(yellow_text 'Mismatch, See Below')"

  local diff_all
  diff_all="$(
    awk '
      NR==FNR {
        name=$1
        $1=""
        sub(/^[[:space:]]+/, "", $0)
        mline[name]=name " " $0
        next
      }
      {
        name=$1
        $1=""
        sub(/^[[:space:]]+/, "", $0)
        sline[name]=name " " $0
      }
      END {
        for (n in sline) {
          if (!(n in mline)) {
            print "Extra Package: " sline[n]
          } else if (sline[n] != mline[n]) {
            print "Does Not Match Master: " sline[n] " (Master: " mline[n] ")"
          }
        }
        for (n in mline) {
          if (!(n in sline)) {
            print "Missing Package: " mline[n]
          }
        }
      }
    ' <(printf "%s\n" "$MASTER_RPMLIST") <(printf "%s\n" "$slave_list") | sort
  )"

  # count what's there before truncating, and say so - a silent cut at the cap reads as
  # "these are all the differences" when it isn't (same reasoning as the coredump list)
  local diff_count diff_show
  diff_count="$(grep -c . <<< "$diff_all" || true)"
  [[ "$diff_count" =~ ^[0-9]+$ ]] || diff_count=0
  diff_show="$(head -n "$pkg_diff_max_lines" <<< "$diff_all")"
  if (( diff_count > pkg_diff_max_lines )); then
    diff_show+=$'\n'"(plus $((diff_count - pkg_diff_max_lines)) more difference(s) not listed)"
  fi

  append_details "$hostlabel" "Yum Patch Level Differences" "$diff_show"
  return 1
}

# pool mode control
should_run_in_pool_for_slave() {
  local var="$1"
  [[ "${!var}" == "1" ]]
}

append_details() {
  local hostlabel="$1"
  local title="$2"
  local content="$3"
  DETAILS_OUTPUT+=$'\n\n\n'"$(yellow_text "${hostlabel} - ${title}:")"$'\n'"${content}"$'\n'
}

append_pool_details() {
  local title="$1"
  local content="$2"
  POOLDETAILS_OUTPUT+=$'\n\n\n'"$(yellow_text "${title}:")"$'\n'"${content}"$'\n'
}

append_poolconf_summary() {
  local hn="$1"
  local ip="$2"
  local poolconf="$3"

  poolconf="${poolconf//$'\r'/}"
  poolconf="${poolconf%%$'\n'*}"

  POOLCONF_SUMMARY+="${hn} (${ip})"$'\n'
  POOLCONF_SUMMARY+="${poolconf}"$'\n\n'
}

# pool status stuff
print_pool_status_section() {
  local pass="$1"
  local rc_any=0

  echo "$(cyan_text "== Pool Status ==")"

  if [[ -n "$DETECTED_MASTER_HOSTNAME" && -n "$DETECTED_MASTER_IP" ]]; then
    printf "Pool Master: %s\n" "$(green_text "${DETECTED_MASTER_HOSTNAME} (${DETECTED_MASTER_IP})")"
  else
    printf "Pool Master: %s\n" "$(yellow_text '(unknown)')"
  fi

  if host_solo; then
    # Nothing was probed beyond this machine, so there is no reachability result to report
    # and nothing to compare across hosts: the RAM-match and pool-time-sync lines below
    # would be claims about hosts we never looked at. Say how much of the pool this run
    # covers instead - the count comes from xapi, so it is the whole pool either way.
    local pool_size="${#POOL_ALL_HOST_IPS[@]}"
    if (( pool_size > 1 )); then
      printf "Hosts in Pool: %s\n" "$(green_text "${pool_size} (only this host checked - give the root password to include the others)")"
    else
      printf "Hosts in Pool: %s\n" "$(green_text "$pool_size")"
    fi
  else
    # a pool member we couldn't SSH into is excluded from every per-host check below,
    # which used to leave only a stderr warning and a clean exit code - surface it here
    if (( ${#POOL_HOST_NOACCESS_IPS[@]} > 0 )); then
      printf "Unreachable Hosts: %s\n" "$(yellow_text "${POOL_HOST_NOACCESS_IPS[*]}")"
      rc_any=1
    else
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Unreachable Hosts: %s\n" "$(green_text 'None')"
    fi

    if (( POOL_RAM_MATCH == 1 )); then
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Dom0 RAM Allocations: %s\n" "$(green_text 'Matched')"
    else
      printf "Dom0 RAM Allocations: %s\n" "$(yellow_text 'Mismatched')"
      rc_any=1
    fi

    if (( POOL_NTP_MATCH == 1 )); then
      [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Pool Time Synchronization: %s\n" "$(green_text 'Matched')"
    else
      printf "Pool Time Synchronization: %s\n" "$(yellow_text 'Mismatched')"
      rc_any=1
    fi
  fi

  # Everything from here down is a question for xapi rather than for a specific machine, so
  # it goes to POOL_CMD_HOST: the master over ssh from XOA, this host when we are running on
  # one (a slave's xapi forwards pool-wide queries to the master, so the answers match).
  if [[ -n "$MASTER_POOL_UUID" ]]; then
    if ! check_ha_enabled "$POOL_CMD_HOST" "$pass" "$MASTER_POOL_UUID"; then rc_any=1; fi
  else
    printf "HA Enabled: %s\n" "$(yellow_text 'Unknown')"
    rc_any=1
  fi

  if ! check_migration_compression "$POOL_CMD_HOST" "$pass"; then rc_any=1; fi

  if (( POOL_MISSING_PATCHES == 0 )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Missing Patches: %s\n" "$(green_text "${POOL_MISSING_PATCHES}")"
  else
    printf "Missing Patches: %s\n" "$(yellow_text "${POOL_MISSING_PATCHES/-1/Unknown}")"
    rc_any=1
  fi

  if (( PW_NOTIFY == 1 )); then
    printf "Root Password: %s\n" "$(yellow_text 'Contains Backslash')"
  fi

  load_mem_stats "$POOL_CMD_HOST"
  if ! check_xostor_in_use_and_ram "$POOL_CMD_HOST" "$pass"; then rc_any=1; fi
  MASTER_XOSTOR_IN_USE=$(( XOSTOR_IN_USE ))

  if (( MASTER_XOSTOR_IN_USE == 1 )); then
    # Build comma-separated list of controllers for LINSTOR cmds. The linstor CLI reaches
    # the controller over the network from wherever it runs, so in host mode it gets every
    # pool address rather than the one host this run probed - the controller usually lives
    # on another host, and a one-entry list would just fail to find it.
    local -a controller_ips=()
    if host_solo && (( ${#POOL_ALL_HOST_IPS[@]} > 0 )); then
      controller_ips=("${POOL_ALL_HOST_IPS[@]}")
    elif (( ${#POOL_HOST_ACCESS_IPS[@]} > 0 )); then
      controller_ips=("${POOL_HOST_ACCESS_IPS[@]}")
    fi
    local IFS=,
    local controllers_csv="${controller_ips[*]:-}"
    unset IFS
    if ! check_xostor_faulty_resources "$POOL_CMD_HOST" "$pass" "$controllers_csv"; then rc_any=1; fi
    if ! check_xostor_nodes "$POOL_CMD_HOST" "$pass" "$controllers_csv"; then rc_any=1; fi
    if ! check_xostor_controller "$POOL_CMD_HOST" "$pass" "$controllers_csv"; then rc_any=1; fi
    if ! check_xostor_qcow2_vdis "$POOL_CMD_HOST" "$pass"; then rc_any=1; fi
  fi

  local host_uuid="${POOL_HOST_UUIDS[$POOL_CMD_HOST]:-}"
  if [[ -n "$host_uuid" ]]; then
    if ! check_vlan0_exist "$POOL_CMD_HOST" "$pass" "$host_uuid"; then rc_any=1; fi
  else
    # don't skip the check silently just because the address wasn't in the
    # xe maps - say so, like the DNS/GW check does
    printf "VLAN 0 Check: %s\n" "$(yellow_text 'Unknown (host address not in xe host list)')"
    rc_any=1
  fi
  if ! check_migration_network "$POOL_CMD_HOST" "$pass"; then rc_any=1; fi
  if ! check_backup_network "$POOL_CMD_HOST" "$pass"; then rc_any=1; fi
  echo
  return "$rc_any"
}

get_host_uuid_by_address() {
  local host="$1"   # run xe on THIS host
  local pass="$2"
  local ip="$3"     # the address we matching

  local out rc
  if out=$(run_remote "$host" "$pass" "xe host-list address=$ip params=uuid --minimal 2>/dev/null || true"); then
    rc=0
  else
    rc=$?
    echo "Failed when trying to get host UUIDs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  tr -d '\r' <<< "$out" | head -n 1
}

run_checks_for_host() {
  local ip="$1"
  local pass="$2"
  local is_master="$3"
  local controllers_csv="$4"       # optional: for XOSTOR checks

  local hn
  if [[ -n "$DETECTED_MASTER_IP" && "$ip" == "$DETECTED_MASTER_IP" && -n "$DETECTED_MASTER_HOSTNAME" ]]; then
    # detect_pool_master_by_poolconf already fetched the master's hostname
    hn="$DETECTED_MASTER_HOSTNAME"
  else
    hn="$(get_remote_hostname "$ip" "$pass" | tr -d '\r' || true)"
    [[ -z "$hn" ]] && hn="$ip"
  fi

  # The per-host banner only makes sense as a list heading when there is a list. A solo
  # host run has one host, which may well be a slave, so it gets the single-host heading
  # rather than one that would announce a lone "(Master)" - the master/slave fact is
  # already in the Pool Status section and the pool.conf summary. A host run that sweeps
  # the pool has a real list, so it gets the same headings an XOA run does.
  if (( POOL_MODE == 1 )) && ! host_solo; then
    if (( is_master == 1 )); then
      echo "$(cyan_text "== Individual Hosts ==")"
      echo "$(cyan_text "$hn ($ip) (Master) Results:")"
    else
      echo
      echo "$(cyan_text "$hn ($ip) Results:")"
    fi
  else
    echo "$(cyan_text "== Health check on: $hn ==")"
  fi

  local rc_any=0

  # pool mode prints this in the pool status section; single mode has nowhere else to
  if (( POOL_MODE == 0 && PW_NOTIFY == 1 )); then
    printf "Root Password: %s\n" "$(yellow_text 'Contains Backslash')"
  fi

  # info block - but an unsupported version, a disabled host, or NTP explicitly off
  # still count toward the exit code
  if ! check_hyper_version "$ip" "$pass"; then rc_any=1; fi
  check_uptime "$ip" "$pass"
  check_lastpatched "$ip" "$pass"
  if ! check_enabled "$ip"; then rc_any=1; fi
  check_multipath "$ip"
  if ! check_host_timesync "$ip"; then rc_any=1; fi

  # dmesg feeds the MTU/content/OOM checks - skip the fetch when none of them will run.
  # dmesg_ok carries the fetch result to all three: fed an empty string they cannot tell
  # a quiet kernel from one we never managed to ask, and all three reported green off a
  # failed fetch with nothing but an stderr line to contradict them.
  local dmesg_t="" rc
  local need_dmesg=0 dmesg_ok=1
  if (( POOL_MODE == 0 )) || (( is_master == 1 )) \
     || should_run_in_pool_for_slave pool_run_mtu_issues \
     || should_run_in_pool_for_slave pool_run_dmesg_content \
     || should_run_in_pool_for_slave pool_run_oom_events; then
    need_dmesg=1
  fi

  if (( need_dmesg == 1 )); then
    if dmesg_t=$(run_remote "$ip" "$pass" "dmesg -T"); then
      rc=0
    else
      rc=$?
      echo "Failed when trying to get dmesg on $ip (exit code $rc)" >&2
      dmesg_t=""
      dmesg_ok=0
    fi
  fi

  if (( POOL_MODE == 1 )); then
    local poolconf_line
    if poolconf_line=$(run_remote "$ip" "$pass" "cat /etc/xensource/pool.conf 2>/dev/null || true"); then
      rc=0
    else
      rc=$?
      echo "Failed when trying to get pool.conf on $ip (exit code $rc)" >&2
      poolconf_line="(unavailable)"
    fi

    append_poolconf_summary "$hn" "$ip" "$poolconf_line"
  fi

  load_mem_stats "$ip"

  local DMESG_ISSUES_BLOCK OOM_EVENTS_BLOCK LACP_OUTPUT_BLOCK LOG_ERRORS_BLOCK LUN_CHANGES_BLOCK COREDUMPS_BLOCK

  local hostlabel="${hn} (${ip})"

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dom0_disk_usage; then
    if ! check_dom0_disk_usage "$ip" "$pass"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dom0_memory; then
    if ! check_dom0_memory_lines; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_mtu_issues; then
    if (( dmesg_ok == 0 )); then
      printf "MTU Issues: %s\n" "$(yellow_text 'Unknown (could not read dmesg)')"
      rc_any=1
    elif ! check_mtu_issues "$dmesg_t"; then
      rc_any=1
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dmesg_content; then
    if (( dmesg_ok == 0 )); then
      printf "Dmesg Content: %s\n" "$(yellow_text 'Unknown (could not read dmesg)')"
      rc_any=1
    else
      if ! check_dmesg_content "$dmesg_t"; then rc_any=1; fi
      if [[ -n "$DMESG_ISSUES_BLOCK" ]]; then
        append_details "$hostlabel" "Dmesg Issues" "$DMESG_ISSUES_BLOCK"
      fi
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_oom_events; then
    if (( dmesg_ok == 0 )); then
      printf "OOM Events: %s\n" "$(yellow_text 'Unknown (could not read dmesg)')"
      rc_any=1
    else
      if ! check_oom_events "$dmesg_t"; then rc_any=1; fi
      if [[ -n "$OOM_EVENTS_BLOCK" ]]; then
        append_details "$hostlabel" "OOM Events" "$OOM_EVENTS_BLOCK"
      fi
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_crash_logs_present; then
    if ! check_crash_logs_present "$ip" "$pass"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_coredumps_present; then
    if ! check_coredumps_present "$ip" "$pass"; then rc_any=1; fi
    if [[ -n "$COREDUMPS_BLOCK" ]]; then
      append_details "$hostlabel" "Coredumps ($coredump_dir)" "$COREDUMPS_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_lacp_negotiation; then
    if ! check_lacp_negotiation_issues "$ip" "$pass"; then rc_any=1; fi
    if [[ -n "$LACP_OUTPUT_BLOCK" ]]; then
      append_details "$hostlabel" "LACP Output" "$LACP_OUTPUT_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_silly_mtus; then
    if ! check_silly_mtus "$ip" "$pass"; then rc_any=1; fi
  fi

if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dns_gw_non_mgmt_pifs; then
  local host_uuid="${POOL_HOST_UUIDS[$ip]:-}"


  if [[ -z "$host_uuid" ]]; then
    host_uuid="$(get_host_uuid_by_address "$ip" "$pass" "$ip")"
  fi

  if [[ -n "$host_uuid" ]]; then
    if ! check_dns_gw_non_mgmt_pifs "$ip" "$pass" "$host_uuid"; then rc_any=1; fi
  else
    printf "DNS/GW on Non-Mgmt PIFs: %s (could not resolve host identity for address=%s)\n" "$(yellow_text 'Unknown')" "$ip"
    rc_any=1
  fi
fi


  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_overlapping_subnets; then
    if ! check_overlapping_subnets "$ip" "$pass"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_log_errors; then
    if ! check_log_errors "$ip" "$pass"; then rc_any=1; fi
    if [[ -n "$LOG_ERRORS_BLOCK" ]]; then
      append_details "$hostlabel" "Log Errors" "$LOG_ERRORS_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_lun_assignments; then
    if ! check_lun_assignments "$ip" "$pass"; then rc_any=1; fi
    if [[ -n "$LUN_CHANGES_BLOCK" ]]; then
      append_details "$hostlabel" "LUN Assignment Changes" "$LUN_CHANGES_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_smapi_hidden_leaves; then
    if ! check_smapi_hidden_leaves "$ip" "$pass" "$hostlabel"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_rebooted_after_updates; then
    if ! check_rebooted_after_updates "$ip" "$pass"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 1 )); then
    if (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_yum_patch_level; then
      if ! check_yum_patch_level "$ip" "$pass" "$is_master" "$hostlabel"; then rc_any=1; fi
    fi
  fi

  return "$rc_any"
}

main() {
  # decides the whole shape of the run - see the note at the top of the file
  detect_run_env

  if [[ "$RUN_ENV" == "host" ]]; then
    # dom0's PATH is complete for an interactive root shell but not necessarily under cron,
    # and several checks live in sbin (ip, dmesg, ovs-appctl). Appended, so nothing that is
    # already found changes. Over ssh the remote login shell did this for us.
    export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
  else
    local debver debver_major
    debver=$(awk -F '=' '/^VERSION_ID=/ {gsub(/"/,"",$2); print $2}' /etc/os-release 2>/dev/null || true)
    debver_major="${debver%%.*}"
    if [[ ! "$debver_major" =~ ^[0-9]+$ ]] || (( debver_major < 11 )); then
      echo "This script requires Debian 11 or later (or an XCP-ng host). Detected version: ${debver:-unknown}" >&2
      exit 1
    fi
  fi

  # temp dir for ssh control sockets + stderr capture
  WORK_DIR="$(mktemp -d)"
  trap 'rm -rf "$WORK_DIR"' EXIT

  local VALID_ARGS
  # getopt has already printed its own "unrecognized option" to stderr; usage adds the
  # invocation summary and exits 2. It used to exit 1 here, which is the same code a
  # perfectly valid run returns when a check flags, so a wrapper or cron job could not
  # tell "you typed the flag wrong" from "the pool has a problem".
  if ! VALID_ARGS=$(getopt -o fhsn: --long filter,help,single,name: -- "$@"); then
      usage
  fi

  eval set -- "$VALID_ARGS"

  while true; do
    case "$1" in
      -f | --filter)
          FILTER_OUTPUT=1
          shift
          ;;
      -h | --help)
          usage 0
      ;;
      -s | --single)
          POOL_MODE=0
          shift
          ;;
      -n | --name)
          POOL_NAME_FILTER="$2"
          shift 2
          ;;
      --) shift;
          break
          ;;
    esac
  done

   [[ $# -le 2 ]] || usage

  local seed_host=""
  local pass=""
  local rc

  # ---- host mode: the target is fixed, there is nothing to select or log into ----
  if [[ "$RUN_ENV" == "host" ]]; then
    # From XOA every command arrived as root over ssh, so this is the first time the
    # question comes up. Without it, xe / dmesg / the logs all fail one by one and the run
    # blames the toolstack for what is really a missing sudo.
    if [[ "$(id -u 2>/dev/null || echo 0)" != "0" ]]; then
      echo "ERROR: this must run as root on an XCP-ng host (it reads dom0 logs and talks to xapi)." >&2
      exit 1
    fi

    if [[ -n "$POOL_NAME_FILTER" ]]; then
      echo "ERROR: -n/--name picks a pool out of xo-server-db, which only exists on XOA." >&2
      usage
    fi

    # The target is this machine, so the one positional that makes sense here is the root
    # password for the OTHER pool members. A second one would have been a host, which is
    # not selectable - saying so beats failing later with an authentication error.
    if (( $# > 1 )); then
      {
        echo "ERROR: running on an XCP-ng host, so the host to check is this one and cannot be chosen."
        echo "       The only argument accepted here is the root password of the other pool members."
      } >&2
      usage
    fi

    if (( $# == 1 )); then
      pass="$1"
    fi

    resolve_local_host_identity || exit 1
    seed_host="$LOCAL_HOST_IP"

    # no xo-db here, so there is no pool name to print - the address (with the hostname when
    # we have it) is what this run is about
    if [[ -n "$LOCAL_HOST_NAME" ]]; then
      print_target_banner "$LOCAL_HOST_NAME ($LOCAL_HOST_IP)" ""
    else
      print_target_banner "$LOCAL_HOST_IP" ""
    fi
  else
    # ---- XOA: pick a pool / take the host argument, then find a password for it ----

    # -n names a pool instead of giving a host, so only an optional password may follow it
    if [[ -n "$POOL_NAME_FILTER" && $# -gt 1 ]]; then
      echo "ERROR: -n/--name looks the host up in xo-server-db, so it takes at most a password after it." >&2
      usage
    fi

    # With one trailing argument the two readings are indistinguishable by shape, and the
    # script reads it as a password - so './health.sh -n sec 192.168.1.5' silently tried to
    # log into the -n-matched pool using an address as the password and surfaced as an
    # authentication failure. Only xo-db can tell the cases apart: an argument that is the
    # address of a pool it knows was meant as a host, since nobody's root password is one of
    # their own pool addresses.
    if [[ -n "$POOL_NAME_FILTER" && $# -eq 1 ]]; then
      local host_clash
      host_clash="$(get_pool_name_for_host "$1" || true)"
      if [[ -n "$host_clash" ]]; then
        {
          printf "ERROR: '%s' is the address of pool '%s' in xo-server-db, but the value after\n" "$1" "$host_clash"
          echo   "       -n/--name is read as a password, not a host - -n already selects the pool."
          printf "       Use either '-n %s' or the host '%s', not both.\n" "$POOL_NAME_FILTER" "$1"
        } >&2
        usage
      fi
    fi

    # -n, or no args at all = resolve a pool from xo-db (which prompts when more than
    # one is enabled and no -n narrowed it down)
    if [[ -n "$POOL_NAME_FILTER" ]] || [ "$#" -eq 0 ]; then
      local sel_rc=0
      select_host_from_xoa_db || sel_rc=$?
      case "$sel_rc" in
        0) ;;
        2) echo "Aborted." >&2; exit 0 ;;
        3) exit 1 ;;   # -n matched nothing; the pools it did find were already listed
        *)
          echo "No host IP provided and no enabled hosts found in xo-db, please provide a host IP as an argument" >&2
          exit 1
          ;;
      esac
      # keep any password the user passed after -n as the second positional
      set -- "$SELECTED_HOST" "$@"
    fi

    parse_target_host_and_port "$1"
    seed_host="$PARSED_HOST"

    # a host that came from the xo-db picker may carry ':port' - that's the XAPI HTTPS
    # port XO connects on, not an SSH port, so strip it for SSH but stay on 22
    if [[ -n "$SELECTED_HOST" ]]; then
      SSH_PORT=22
    fi

    # the picker already knows the name when it resolved the host; a host argument didn't
    # go through it, so look that one up (this is the only path that can leave it empty)
    if [[ -z "$SELECTED_POOL_NAME" ]]; then
      SELECTED_POOL_NAME="$(get_pool_name_for_host "$seed_host" || true)"
    fi
    print_target_banner "$seed_host" "$SELECTED_POOL_NAME"

    ensure_sshpass

    if [[ $# -eq 2 ]]; then
      pass="$2"
    else
      # look the password up under the exact string xo-db keys the record by: for a
      # picker-chosen host that's SELECTED_HOST verbatim (which may carry ':port' -
      # the port-stripped seed_host would miss such a record entirely)
      local db_host="$seed_host"
      [[ -n "$SELECTED_HOST" ]] && db_host="$SELECTED_HOST"
      if pass="$(get_password_from_xoa_db_simple "$db_host")"; then
        rc=0
      else
        rc=$?

        if [[ $rc -eq 2 ]]; then
          PW_NOTIFY=1
        fi
      fi

      if [[ -z "$pass" ]]; then
        echo "Host IP not found in xo-db, please manually provide a password, or check that the IP is the master host and not a slave"
        exit 1
      fi
    fi
  fi
  # ---- end of the two target-resolution paths ----

  get_pool_host_details "$seed_host" "$pass" || true

  if (( ${#POOL_HOST_IPS[@]} == 0 )); then
    echo "ERROR: Could not retrieve pool host addresses from '$seed_host'." >&2
    exit 1
  fi

  # On a hypervisor, decide here - now that we know how big the pool is - whether the other
  # members can be checked too, asking for a password if there is someone to ask. It may
  # install sshpass, so it deliberately runs after the cheap local work has succeeded.
  if [[ "$RUN_ENV" == "host" ]]; then
    prepare_host_pool_sweep "$pass"
    pass="$HOST_POOL_PASS"
  fi

  # in single mode only the seed host gets checked - don't probe the rest of the pool.
  # A solo host run narrows the list the same way, for a different reason: without a
  # password those members are not unreachable, they are simply not being checked, and
  # probing them would report them as failures.
  if (( POOL_MODE == 0 )) || host_solo; then
    POOL_HOST_IPS=("$seed_host")
  fi

  check_pool_hosts_access "$pass"

  local overall_rc=0
  get_pool_host_facts "$pass"

  # the XOA section is about the appliance itself - there is no appliance here
  if [[ "$RUN_ENV" != "host" ]]; then
    if ! print_xoa_status_section; then overall_rc=1; fi
  fi

  if (( POOL_MODE == 0 )); then
    if ! run_checks_for_host "$seed_host" "$pass" 1 ""; then overall_rc=1; fi
  else
    if [[ "$RUN_ENV" == "host" ]]; then
      # pool.conf is read locally, and names the master even when we are a slave
      if ! detect_pool_master_local; then
        echo "ERROR: Could not determine pool master (no 'master' or 'slave:<address>' in /etc/xensource/pool.conf)." >&2
        exit 1
      fi
      POOL_CMD_HOST="$seed_host"
    else
      if ! detect_pool_master_by_poolconf "$pass"; then
        echo "ERROR: Could not determine pool master (no host had 'master' in /etc/xensource/pool.conf)." >&2
        exit 1
      fi
      POOL_CMD_HOST="$DETECTED_MASTER_IP"
    fi

    MASTER_POOL_UUID="$(get_pool_uuid "$POOL_CMD_HOST" "$pass" || true)"
    get_pool_missing_patches "$pass"

    # both of these need a second host to compare against
    if ! host_solo; then
      compute_pool_ram_match "$DETECTED_MASTER_IP" "$pass"

      MASTER_RPMLIST="$(get_rpm_manifest_remote "$DETECTED_MASTER_IP" "$pass" || true)"
      # hash the manifest we just fetched instead of running rpm -qa on the master a
      # second time; check_yum_patch_level hashes each slave's manifest through this exact
      # pipeline, so the two digests are always comparable
      MASTER_RPMHASH=""
      if [[ -n "${MASTER_RPMLIST//[[:space:]]/}" ]]; then
        MASTER_RPMHASH="$(printf '%s\n' "$MASTER_RPMLIST" | sha256sum | cut -d' ' -f1)"
      fi
    fi

    if ! print_pool_status_section "$pass"; then overall_rc=1; fi

    if host_solo; then
      # this machine is the only one we can check, master or slave. is_master=1 so every
      # check runs, the way single mode runs them all - the pool_run_* toggles are about
      # keeping a pool sweep short, and there is no sweep here
      if ! run_checks_for_host "$seed_host" "$pass" 1 ""; then overall_rc=1; fi
    else
      # Shared by XOA runs and host runs that sweep the pool. The master goes first because
      # it carries the section heading and sets the yum baseline - but a host run names the
      # master from the local pool.conf, so unlike the XOA path (where detection can only
      # pick a host we already logged into) it may be one we cannot reach. It is listed as
      # unreachable above; here we just make sure the heading still gets printed.
      local ip master_reachable=0
      for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
        if [[ "$ip" == "$DETECTED_MASTER_IP" ]]; then master_reachable=1; break; fi
      done

      if (( master_reachable == 1 )); then
        if ! run_checks_for_host "$DETECTED_MASTER_IP" "$pass" 1 ""; then overall_rc=1; fi
      else
        echo "$(cyan_text "== Individual Hosts ==")"
      fi

      for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
        [[ "$ip" == "$DETECTED_MASTER_IP" ]] && continue
        if ! run_checks_for_host "$ip" "$pass" 0 ""; then overall_rc=1; fi
      done
    fi

    echo
    echo "$(cyan_text "---pool.conf contents---")"
    printf "%s" "$POOLCONF_SUMMARY"
  fi

  if [[ -n "${POOLDETAILS_OUTPUT//[[:space:]]/}" ]]; then
    printf "%s\n" "$POOLDETAILS_OUTPUT"
  fi

  if [[ -n "${DETAILS_OUTPUT//[[:space:]]/}" ]]; then
    printf "%s\n" "$DETAILS_OUTPUT"
  fi

  exit "$overall_rc"
}

main "$@"
