#!/usr/bin/env bash
# J-Sands / Vates
# V2.3
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
dmesg_issue_phrases="call trace|timed out"      # matches that trigger dmesg contents issues (whole phrase matched, pipe seperated)
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
pkg_diff_max_lines=100                          # max amt of mismatched yum packages to list
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
ORIGINAL_ARGS=()
MASTER_RPMLIST=""
MASTER_RPMHASH=""
POOL_RAM_MATCH=1
POOL_NTP_MATCH=1
POOL_MISSING_PATCHES=0
DETECTED_MASTER_IP=""
DETECTED_MASTER_HOSTNAME=""
MASTER_XOSTOR_IN_USE=0
MASTER_POOL_UUID=""
MEM_TOTAL_GB="0.0"
MEM_USED_PCT="0.0"
MEM_AVAIL_GB="0.0"
PW_NOTIFY=0                         # flag to indicate we should print a warning about backslash in password
WORK_DIR=""                         # temp dir for ssh control sockets / stderr capture (set in main)

usage() {
  # help asked for (-h, exit 0) goes to stdout; usage *errors* go to stderr
  local rc="${1:-2}" fd=1
  (( rc == 0 )) || fd=2
  {
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

ensure_sshpass() {
  if command -v sshpass >/dev/null 2>&1; then
    return 0
  fi

  echo "sshpass not found. Installing via apt..." >&2
  apt-get update -y
  apt-get install -y sshpass

  # ezez
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
      printf "Registration: %s\n" "$(green_text "${XOA_REGIST}")"
    fi

    if [[ -z "${XOA_CHANNEL:-}" ]]; then
      printf "XOA Channel: %s\n" "$(yellow_text '(Unknown)')"
      rc_any=1
    else
      printf "XOA Channel: %s\n" "$(green_text "${XOA_CHANNEL}")"
    fi

    if [[ -z "${XOA_VERSION:-}" ]]; then
      printf "XOA Version: %s\n" "$(yellow_text 'Unknown')"
      rc_any=1
    else
      printf "XOA Version: %s\n" "$(green_text "${XOA_VERSION}")"
    fi

    if [[ -z "${XOA_PLAN:-}" ]]; then
      printf "XOA Plan: %s" "$(yellow_text 'Unknown')"
      rc_any=1
    else
      printf "XOA Plan: %s" "$(green_text "${XOA_PLAN}")"
    fi

    if [[ -z "${XOA_LICENSES:-}" ]]; then
        printf " (%s)\n" "$(yellow_text "Unknown")"
        rc_any=1
    elif [[ "$XOA_LICENSES" == "[]" ]]; then
        printf " (%s)\n" "$(yellow_text "Unbound")"
        rc_any=1
    else
      printf " (%s)\n" "$(green_text "Bound")"
    fi

    if [[ -z "${XOA_CURRENT:-}" ]]; then
      printf "XOA Status: %s\n" "$(yellow_text 'Updates available')"
      rc_any=1
    else
      printf "XOA Status: %s\n" "$(green_text 'Up to date')"
    fi

    # a timed-out 'xoa check' produces no stderr, which used to read as a green
    # "All OK" - tell the two apart via timeout's exit code 124
    local xoa_check_rc=0
    out=$(timeout "$xoa_check_timeout" xoa check 2>&1 >/dev/null) || xoa_check_rc=$?
    if (( xoa_check_rc == 124 )); then
      printf "XOA Check: %s\n" "$(yellow_text "Timed out after ${xoa_check_timeout}s")"
      rc_any=1
    elif [[ -z "${out//[[:space:]]/}" ]]; then
      printf "XOA Check: %s\n" "$(green_text 'All OK')"
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
    printf "OS Version: %s\n" "$(green_text "${XOA_DEBIAN}")"
  fi

 local XOA_TOTAL_MEM XOA_AVAIL_MEM
  XOA_TOTAL_MEM="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)"
  XOA_AVAIL_MEM="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)"

  if [[ -n "$XOA_TOTAL_MEM" && -n "$XOA_AVAIL_MEM" ]]; then
    local total_gb avail_gb used_gb used_pct
    total_gb="$(awk -v m="$XOA_TOTAL_MEM" 'BEGIN{printf "%.1f", m/1024/1024}')"
    avail_gb="$(awk -v m="$XOA_AVAIL_MEM" 'BEGIN{printf "%.1f", m/1024/1024}')"
    used_gb="$(awk -v t="$total_gb" -v a="$avail_gb" 'BEGIN{printf "%.1f", t - a}')"
    used_pct="$(awk -v t="$total_gb" -v u="$used_gb" 'BEGIN{ if (t<=0) printf "0.0"; else printf "%.1f", (u/t)*100 }')"

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
        printf "XO-Server Memory Limit: %s\n" "$(green_text "$max_old_space")"
      fi
    fi
  fi

  local dmesg_t
  dmesg_t="$(dmesg -T 2>/dev/null || true)"

  if ! check_dmesg_content "$dmesg_t"; then
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

run_remote() {
  local host="$1"
  local pass="$2"
  local cmd="$3"

  local output rc
  local errfile="${WORK_DIR:-/tmp}/health-ssh-err.$$"

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
    echo "SSH failed when trying to get hostname from $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to get pool UUID from $host (exit code $rc)" >&2
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
      POOL_HOSTS_STATUS["${uuid}_enabled"]="${en:-Unknown}"
      POOL_HOSTS_STATUS["${uuid}_multipath"]="${mp:-Unknown}"
    done <<< "$out"
  else
    rc=$?
    echo "SSH failed when trying to get pool host list from $host (exit code $rc)" >&2
  fi

  return $rc
}

get_pool_missing_patches() {
  local pass="$1"

  # yum check-update exits 0 = no updates, 100 = updates available, anything else =
  # yum itself failed (broken repo config, no network, ...). Piping straight into
  # wc -l used to swallow that last case as a green "0 missing patches" - emit a
  # non-numeric sentinel instead so it lands in the existing Unknown (-1) path.
  local out rc cmd
  cmd="out=\$(sudo yum check-update -q); rc=\$?
if [ \"\$rc\" -eq 100 ]; then
  printf '%s\n' \"\$out\" | awk '/^Loaded plugins:/||NF==0{next} /^Obsoleting Packages/{exit} NF==1&&!/^[[:space:]]/{pkg=\$0;next} pkg&&/^[[:space:]]+/{sub(/^[[:space:]]+/,\"\");print pkg,\$0;pkg=\"\";next} {print}' | wc -l
elif [ \"\$rc\" -eq 0 ]; then
  echo 0
else
  echo YUMERR
fi"
  if out=$(run_remote "$DETECTED_MASTER_IP" "$pass" "$cmd"); then
    rc=0

    if [[ -z "$out" || ! "$out" =~ ^[0-9]+$ ]]; then
      POOL_MISSING_PATCHES=-1
    else
      POOL_MISSING_PATCHES=$out
    fi

  else
    rc=$?
    POOL_MISSING_PATCHES=-1
  fi

  return
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
  for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
    [[ "$ip" == "$seed_host" ]] && continue
    all_ips+=("$ip")
  done

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

# --- RAM calculatios ---
load_mem_stats() {
  local host="$1"

  local uuid="${POOL_HOST_UUIDS[$host]:-}"

  local total_mb used_mb avail_mb
  total_mb="${POOL_HOSTS_MEM[${uuid}_total]:-0}"
  used_mb="${POOL_HOSTS_MEM[${uuid}_used]:-0}"
  avail_mb="${POOL_HOSTS_MEM[${uuid}_avail]:-0}"

  MEM_TOTAL_GB="$(awk -v m="$total_mb" 'BEGIN{printf "%.1f", m/1024}')"
  MEM_USED_PCT="$(awk -v u="$used_mb" -v t="$total_mb" 'BEGIN{ if (t<=0) printf "0.0"; else printf "%.1f", (u/t)*100 }')"
  MEM_AVAIL_GB="$(awk -v a="$avail_mb" 'BEGIN{printf "%.1f", a/1024}')"
}

# RPM/Yum patch level stuff
rpm_manifest_cmd() {
  printf "%s" "rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort"
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

get_rpm_manifest_hash_remote() {
  local host="$1"
  local pass="$2"

  # sha256sum only (no md5 fallback): the master's hash is computed locally from the
  # fetched manifest, so slave hashes must use the same algorithm to be comparable.
  # A host somehow lacking sha256sum fails the call and lands in the Unknown path,
  # which beats a fake mismatch.
  local out rc
  if out=$(run_remote "$host" "$pass" "$(rpm_manifest_cmd) | sha256sum | cut -d' ' -f1"); then
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
    echo "SSH failed when trying to get hypervisor version from $host (exit code $rc)" >&2
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
  if [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]]; then
    if (( major > 8 )) || (( major == 8 && minor >= 3 )); then
      printf "%s Version: %s\n" "$hyper" "$(green_text "$version")"
      return 0
    fi
  fi

  printf "%s Version: %s\n" "$hyper" "$(yellow_text "$version")"
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
    echo "SSH failed when trying to get uptime from $host (exit code $rc)" >&2
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
    last=$(echo "$out" | awk 'NF>1 {$1=""; sub(/^ /,""); print}' | sed -E '/ UTC[+-]/! s/ ([+-][0-9]{2}(:?[0-9]{2})?)$/ UTC\1/' | xargs -I{} date -d "{}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to get last patched info from $host (exit code $rc)" >&2
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

  local uuid ntp sync utc
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

  local ip out rc ts_out mi uuid utc ntp sync unix_time time_diff xo_time
  local tmb amb total_mb used_mb avail_mb
  for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
    if out=$(run_remote "$ip" "$pass" "$cmd"); then
      rc=0
    else
      rc=$?
      echo "SSH failed when trying to get time/memory info from $ip (exit code $rc)" >&2
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
      POOL_HOSTS_MEM[${uuid}_avail]=$avail_mb
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
      POOL_HOSTS_NTP[${uuid}_utc]="$utc"
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
    echo "SSH failed when trying to get disk usage from $host (exit code $rc)" >&2
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
  for kw in $mtu_dmesg_keywords; do
    if grep -qiFw -- "$kw" <<< "$dmesg_out"; then
      printf "MTU Issues: %s\n" "$(yellow_text 'Detected, check output from dmesg -T')"
      return 1
    fi
  done

  [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "MTU Issues: %s\n" "$(none)"
  return 0
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
    echo "SSH failed when trying to check for crash logs on $host (exit code $rc)" >&2
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

check_lacp_negotiation_issues() {
  local host="$1"
  local pass="$2"

  LACP_OUTPUT_BLOCK=""

  local out rc
  if out=$(run_remote "$host" "$pass" "ovs-appctl lacp/show 2>/dev/null || true"); then
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to check LACP negotiation on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to get link MTUs on $host (exit code $rc)" >&2
    return "$rc"
  fi

  local -a nonstandard=()
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
    echo "SSH failed when trying to check DNS/GW on non-mgmt PIFs on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to check for VLAN PIFs on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to list backup network PIFs on $host" >&2
    return 2
  fi

  # --minimal prints one comma-separated line with an empty field for every PIF
  # that has no IP; keep only well-formed, non-placeholder IPv4 addresses
  local -a fields=() ips=()
  IFS=',' read -r -a fields <<< "$pif_out" || true
  local ip
  for ip in "${fields[@]}"; do
    ip="${ip//[[:space:]]/}"
    [[ -n "$ip" ]] || continue
    [[ "$ip" == "0.0.0.0" ]] && continue
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    ips+=("$ip")
  done

  (( ${#ips[@]} > 0 )) || return 3

  local -a unreachable=()
  for ip in "${ips[@]}"; do
    timeout "$local_cmd_timeout" ping -c 1 -W 2 -n "$ip" >/dev/null 2>&1 || unreachable+=("$ip")
  done

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

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pool-list uuid=${MASTER_POOL_UUID} params=migration-compression --minimal" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to check migration compression on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to check for bond members on $host" >&2
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
    echo "SSH failed when trying to get addresses on $host (exit code $rc)" >&2
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
    printf '%s\n' "--- \$ph (\$cand) ---"
    sed -n "\${s},\$((n + CTX))p" "\$cand" 2>/dev/null | sed 's/^/  /'
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
  cmd="$(build_log_scan_cmd \
    "$(printf '%s\n' "${log_error_files[@]}")" \
    "$(printf '%s\n' "${log_error_phrases[@]}")" \
    "$log_error_context")"

  local out rc
  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to check logs for errors on $host (exit code $rc)" >&2
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
    "$(printf '%s\n' "${lun_change_files[@]}")" \
    "$(printf '%s\n' "${lun_change_phrases[@]}")" \
    "$log_error_context")"

  local out rc
  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to check LUN assignments on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to check SMlog hidden leaves on $host (exit code $rc)" >&2
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

check_ha_enabled() {
  local host="$1"
  local pass="$2"
  local pool_uuid="$3"

  local out rc
  if out=$(run_remote "$host" "$pass" "xe pool-param-get uuid=$pool_uuid param-name=ha-enabled" | tr -d '\r'); then
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to check HA status on $host (exit code $rc)" >&2
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

  local out rc cmd
  cmd="bash -lc '
    line=\$(awk '\''\$4==\"Updated:\" || (\$4==\"Installed:\" && \$5 ~ /^(kernel|xen)/) {l=\$0} END{print l}'\'' /var/log/yum.log 2>/dev/null || true)
    if [ -z \"\$line\" ]; then
      echo \"NOUPDATES\"
      exit 0
    fi

    ts=\$(echo \"\$line\" | awk '\''{print \$1\" \"\$2\" \"\$3}'\'')
    year=\$(date +%Y)
    now=\$(date +%s)

    upd=\$(date -d \"\$year \$ts\" +%s 2>/dev/null || true)
    if [ -z \"\$upd\" ]; then
      upd=\$(date -d \"\$ts\" +%s 2>/dev/null || true)
    fi
    if [ -n \"\$upd\" ] && [ \"\$upd\" -gt \$((now+60)) ]; then
      upd=\$(date -d \"\$((year-1)) \$ts\" +%s 2>/dev/null || true)
    fi

    boot_str=\$(who -b 2>/dev/null | awk '\''{print \$3\" \"\$4}'\'')
    boot=\$(date -d \"\$boot_str\" +%s 2>/dev/null || true)

    echo \"\$upd \$boot\"
  '"

  if out=$(run_remote "$host" "$pass" "$cmd"); then
    rc=0
  else
    rc=$?
    echo "SSH failed when trying to check reboot status on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ "${out:-}" == "NOUPDATES" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Rebooted After Updates: %s\n" "$(green_text 'Yes')"
    return 0
  fi

  local upd_epoch boot_epoch
  upd_epoch="$(awk '{print $1}' <<< "$out")"
  boot_epoch="$(awk '{print $2}' <<< "$out")"

  if [[ -z "${upd_epoch:-}" || -z "${boot_epoch:-}" || ! "$upd_epoch" =~ ^[0-9]+$ || ! "$boot_epoch" =~ ^[0-9]+$ ]]; then
    printf "Rebooted After Updates: %s\n" "$(yellow_text 'No')"
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
    echo "SSH failed when trying to check XOSTOR usage on $host (exit code $rc)" >&2
    return "$rc"
  fi

  if [[ -z "${out//[[:space:]]/}" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "XOSTOR In Use: %s\n" "$(green_text 'No')"
    return 0
  fi

  XOSTOR_IN_USE=1
  printf "XOSTOR In Use: %s\n" "$(yellow_text 'Yes')"

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
    echo "SSH failed when trying to check XOSTOR nodes on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to check XOSTOR faulty resources on $host (exit code $rc)" >&2
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
    echo "SSH failed when trying to check XOSTOR controller on $host (exit code $rc)" >&2
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

  if (( POOL_MODE == 0 )); then
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

  local h
  h="$(get_rpm_manifest_hash_remote "$host" "$pass" | tr -d '\r' | head -n 1 || true)"

  if [[ -z "$h" ]]; then
    # couldn't fetch the hash (transient ssh failure etc) - don't call that a mismatch
    printf "Yum Patch Level: %s\n" "$(yellow_text 'Unknown (could not retrieve)')"
    return 1
  fi

  if [[ "$h" == "$MASTER_RPMHASH" ]]; then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Yum Patch Level: %s\n" "$(green_text 'Match')"
    return 0
  fi

  printf "Yum Patch Level: %s\n" "$(yellow_text 'Mismatch, See Below')"

  local slave_list
  slave_list="$(get_rpm_manifest_remote "$host" "$pass" || true)"

  if [[ -z "${slave_list//[[:space:]]/}" ]]; then
    append_details "$hostlabel" "Yum Patch Level Differences" "(could not retrieve package list from host)"
    return 1
  fi

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

  local diff_show
  diff_show="$(head -n "$pkg_diff_max_lines" <<< "$diff_all")"

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

  if [[ -n "$MASTER_POOL_UUID" ]]; then
    if ! check_ha_enabled "$DETECTED_MASTER_IP" "$pass" "$MASTER_POOL_UUID"; then rc_any=1; fi
  else
    printf "HA Enabled: %s\n" "$(yellow_text 'Unknown')"
    rc_any=1
  fi

  if ! check_migration_compression "$DETECTED_MASTER_IP" "$pass"; then rc_any=1; fi

  if (( POOL_MISSING_PATCHES == 0 )); then
    [[ "$FILTER_OUTPUT" -eq 0 ]] && printf "Missing Patches: %s\n" "$(green_text "${POOL_MISSING_PATCHES}")"
  else
    printf "Missing Patches: %s\n" "$(yellow_text "${POOL_MISSING_PATCHES/-1/Unknown}")"
    rc_any=1
  fi

  if (( PW_NOTIFY == 1 )); then
    printf "Root Password: %s\n" "$(yellow_text 'Contains Backslash')"
  fi

  load_mem_stats "$DETECTED_MASTER_IP"
  if ! check_xostor_in_use_and_ram "$DETECTED_MASTER_IP" "$pass"; then rc_any=1; fi
  MASTER_XOSTOR_IN_USE=$(( XOSTOR_IN_USE ))

  if (( MASTER_XOSTOR_IN_USE == 1 )); then
    # Build comma-separated list of controllers for LINSTOR cmds
    local IFS=,
    local controllers_csv="${POOL_HOST_ACCESS_IPS[*]}"
    unset IFS
    if ! check_xostor_faulty_resources "$DETECTED_MASTER_IP" "$pass" "$controllers_csv"; then rc_any=1; fi
    if ! check_xostor_nodes "$DETECTED_MASTER_IP" "$pass" "$controllers_csv"; then rc_any=1; fi
    if ! check_xostor_controller "$DETECTED_MASTER_IP" "$pass" "$controllers_csv"; then rc_any=1; fi
  fi

  local host_uuid="${POOL_HOST_UUIDS[$DETECTED_MASTER_IP]:-}"
  if [[ -n "$host_uuid" ]]; then
    if ! check_vlan0_exist "$DETECTED_MASTER_IP" "$pass" "$host_uuid"; then rc_any=1; fi
  else
    # don't skip the check silently just because the master's address wasn't in the
    # xe maps - say so, like the DNS/GW check does
    printf "VLAN 0 Check: %s\n" "$(yellow_text 'Unknown (master address not in xe host list)')"
    rc_any=1
  fi
  if ! check_migration_network "$DETECTED_MASTER_IP" "$pass"; then rc_any=1; fi
  if ! check_backup_network "$DETECTED_MASTER_IP" "$pass"; then rc_any=1; fi
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
    echo "SSH failed when trying to get host UUIDs on $host (exit code $rc)" >&2
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

  if (( POOL_MODE == 1 )); then
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

  # dmesg feeds the MTU/content/OOM checks - skip the fetch when none of them will run
  local dmesg_t="" rc
  local need_dmesg=0
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
      echo "SSH failed when trying to get dmesg on $ip (exit code $rc)" >&2
      dmesg_t=""
    fi
  fi

  if (( POOL_MODE == 1 )); then
    local poolconf_line
    if poolconf_line=$(run_remote "$ip" "$pass" "cat /etc/xensource/pool.conf 2>/dev/null || true"); then
      rc=0
    else
      rc=$?
      echo "SSH failed when trying to get pool.conf on $ip (exit code $rc)" >&2
      poolconf_line="(unavailable)"
    fi

    append_poolconf_summary "$hn" "$ip" "$poolconf_line"
  fi

  load_mem_stats "$ip"

  local DMESG_ISSUES_BLOCK OOM_EVENTS_BLOCK LACP_OUTPUT_BLOCK LOG_ERRORS_BLOCK LUN_CHANGES_BLOCK

  local hostlabel="${hn} (${ip})"

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dom0_disk_usage; then
    if ! check_dom0_disk_usage "$ip" "$pass"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dom0_memory; then
    if ! check_dom0_memory_lines; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_mtu_issues; then
    if ! check_mtu_issues "$dmesg_t"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_dmesg_content; then
    if ! check_dmesg_content "$dmesg_t"; then rc_any=1; fi
    if [[ -n "$DMESG_ISSUES_BLOCK" ]]; then
      append_details "$hostlabel" "Dmesg Issues" "$DMESG_ISSUES_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_oom_events; then
    if ! check_oom_events "$dmesg_t"; then rc_any=1; fi
    if [[ -n "$OOM_EVENTS_BLOCK" ]]; then
      append_details "$hostlabel" "OOM Events" "$OOM_EVENTS_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_crash_logs_present; then
    if ! check_crash_logs_present "$ip" "$pass"; then rc_any=1; fi
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
  ORIGINAL_ARGS=("$@")

  local debver debver_major
  debver=$(awk -F '=' '/^VERSION_ID=/ {gsub(/"/,"",$2); print $2}' /etc/os-release 2>/dev/null || true)
  debver_major="${debver%%.*}"
  if [[ ! "$debver_major" =~ ^[0-9]+$ ]] || (( debver_major < 11 )); then
    echo "This script requires Debian 11 or later. Detected version: ${debver:-unknown}" >&2
    exit 1
  fi

  # temp dir for ssh control sockets + stderr capture
  WORK_DIR="$(mktemp -d)"
  trap 'rm -rf "$WORK_DIR"' EXIT

  local VALID_ARGS
  if ! VALID_ARGS=$(getopt -o fhsn: --long filter,help,single,name: -- "$@"); then
      exit 1
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

  # -n names a pool instead of giving a host, so only an optional password may follow it
  if [[ -n "$POOL_NAME_FILTER" && $# -gt 1 ]]; then
    echo "ERROR: -n/--name looks the host up in xo-server-db, so it takes at most a password after it." >&2
    usage
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
  local seed_host="$PARSED_HOST"

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

  local pass=""
  local rc

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

  get_pool_host_details "$seed_host" "$pass" || true

  if (( ${#POOL_HOST_IPS[@]} == 0 )); then
    echo "ERROR: Could not retrieve pool host addresses from '$seed_host'." >&2
    exit 1
  fi

  # in single mode only the seed host gets checked - don't probe the rest of the pool
  if (( POOL_MODE == 0 )); then
    POOL_HOST_IPS=("$seed_host")
  fi

  check_pool_hosts_access "$pass"

  local overall_rc=0
  get_pool_host_facts "$pass"

  if ! print_xoa_status_section; then overall_rc=1; fi

  if (( POOL_MODE == 0 )); then
    if ! run_checks_for_host "$seed_host" "$pass" 1 ""; then overall_rc=1; fi
  else
    if ! detect_pool_master_by_poolconf "$pass"; then
      echo "ERROR: Could not determine pool master (no host had 'master' in /etc/xensource/pool.conf)." >&2
      exit 1
    fi

    MASTER_POOL_UUID="$(get_pool_uuid "$DETECTED_MASTER_IP" "$pass" || true)"
    compute_pool_ram_match "$DETECTED_MASTER_IP" "$pass"
    get_pool_missing_patches "$pass"

    MASTER_RPMLIST="$(get_rpm_manifest_remote "$DETECTED_MASTER_IP" "$pass" || true)"
    # hash the manifest we just fetched instead of running rpm -qa on the master a
    # second time; slaves hash remotely with the same sha256sum, so they compare
    MASTER_RPMHASH=""
    if [[ -n "${MASTER_RPMLIST//[[:space:]]/}" ]]; then
      MASTER_RPMHASH="$(printf '%s\n' "$MASTER_RPMLIST" | sha256sum | cut -d' ' -f1)"
    fi

    if ! print_pool_status_section "$pass"; then overall_rc=1; fi

    if ! run_checks_for_host "$DETECTED_MASTER_IP" "$pass" 1 ""; then overall_rc=1; fi

    local ip
    for ip in "${POOL_HOST_ACCESS_IPS[@]}"; do
      [[ "$ip" == "$DETECTED_MASTER_IP" ]] && continue
      if ! run_checks_for_host "$ip" "$pass" 0 ""; then overall_rc=1; fi
    done

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
