#!/usr/bin/env bash
# J-Sands / Vates
# V1.00
set -euo pipefail
set +H 2>/dev/null || true   # make ! in args no explode

# =========================
# config
# =========================
ssh_timeout=45                                  # SSH timeot in secs
dom0_max_used=75                                # dom0 percent disk / storage use allowed before flagging as failed
dom0_mem_used_max_pct=65                        # dom0 percent memory allowed in use before flagging as failed
xostor_min_avail_gb=15                          # Minimum RAM dom0 should have if xostor is in use
mtu_dmesg_keywords="mtu large fragment"         # keywords in dom0 to flag MTU issues
dmesg_issue_words="panic crash rip kill"        # words that trigger dmesg contents issues
dmesg_issue_phrases="call trace"                # matches that trigger dmesg contents issues (whole phrase matched, pipe seperated)
oom_phrase="out of memory"                      # phrase that flags OOM runs
crash_ignore_file=".sacrificial-space-for-logs" # file in /var/crash to ignore (don't flag on crash logs cuz of this)
pkg_diff_max_lines=100                          # max amt of mismatched yum packages to list

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
pool_run_smapi_exceptions=1
pool_run_smapi_hidden_leaves=1
pool_run_rebooted_after_updates=1
pool_run_yum_patch_level=1
pool_run_ha_enabled=0
pool_run_xostor_in_use=0
pool_run_xostor_faulty=0

# petula clark - color my world
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
CYAN=$'\033[36m'
RESET=$'\033[0m'

# flag passes / fails with color
ok()        { printf "%sOK%s"   "$GREEN" "$RESET"; }
none()      { printf "%sNone%s" "$GREEN" "$RESET"; }
fail()      { printf "%sFail%s" "$YELLOW" "$RESET"; }
yes()       { printf "%sYes%s"  "$YELLOW" "$RESET"; }
det_mtu()   { printf "%sDetected, check dmesg%s" "$YELLOW" "$RESET"; }
found()     { printf "%sFound:%s" "$YELLOW" "$RESET"; }
green_text()  { printf "%s%s%s" "$GREEN" "$1" "$RESET"; }
yellow_text() { printf "%s%s%s" "$YELLOW" "$1" "$RESET"; }
cyan_text()   { printf "%s%s%s" "$CYAN" "$1" "$RESET"; }

# globals
POOL_MODE=1
DETAILS_OUTPUT=""
POOLCONF_SUMMARY=""
POOL_HOST_IPS=()
declare -A POOL_HOST_UUIDS=()
SSH_PORT=22
PARSED_HOST=""
ORIGINAL_ARGS=()
MASTER_RPMLIST=""
MASTER_RPMHASH=""
POOL_RAM_MATCH=1
DETECTED_MASTER_IP=""
DETECTED_MASTER_HOSTNAME=""
MASTER_XOSTOR_IN_USE=0
MASTER_POOL_UUID=""
MEM_TOTAL_GB="0.0"
MEM_USED_PCT="0.0"
MEM_AVAIL_GB="0.0"

usage() {
  echo "Usage:"
  echo "  $0 pool_master_or_host[:ssh_port] [root_password] [single]"
  echo ""
  echo "  - SSH port, password, and single mode are optional "
  echo "  - If a password is not supplied, I will look it up locally in xo-server-db"
  echo "  - By default, the script runs in pool mode (checks all hosts in the pool)"
  echo "  - Use 'single' flag to only check the specified host"
  echo ""
  echo "  Examples:"
  echo "  $0 192.168.1.5"
  echo "  $0 192.168.1.6 'mypass'"
  echo "  $0 192.168.1.7 'mypass' single"
  exit 2
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

get_password_from_xoa_db_simple() {
  local host_only="$1"

  command -v xo-server-db >/dev/null 2>&1 || {
    echo "ERROR: xo-server-db not found in PATH (are you running this on XOA?)." >&2
    return 1
  }

  # AWK-only parsing so no match is not an error with pipefail
  xo-server-db ls server "host=$host_only" 2>/dev/null \
    | awk -F"'" 'tolower($0) ~ /password:/ {print $2; exit}'
}

run_remote() {
  local host="$1"
  local pass="$2"
  local cmd="$3"

  sshpass -p "$pass" ssh \
    -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout="$ssh_timeout" \
    -o BatchMode=no \
    root@"$host" \
    "$cmd"
}

get_remote_hostname() {
  local host="$1"
  local pass="$2"
  run_remote "$host" "$pass" "hostname -s 2>/dev/null || hostname" | head -n 1
}

get_pool_uuid() {
  local host="$1"
  local pass="$2"

  local out
  out="$(run_remote "$host" "$pass" "xe pool-list params=uuid" | tr -d '\r')"

  # Extract UUID
  if [[ "$out" =~ ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo ""
  fi
}

get_pool_host_addresses() {
  local host="$1"
  local pass="$2"

  # Ask for both fields; don't rely on ordering cuz it seems random ?
  local out
  out="$(run_remote "$host" "$pass" "xe host-list params=uuid,address 2>/dev/null || true" | tr -d '\r')"

  POOL_HOST_IPS=()
  POOL_HOST_UUIDS=()

  # Build address -> uuid mapping
  local u="" a=""
  while IFS= read -r line; do
    # Match UUID pattern (8-4-4-4-12 hex digits seperated by hyphens)
    if [[ "$line" =~ ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) ]]; then
      u="${BASH_REMATCH[1]}"
    fi
    # Match IPv4 pattern (v6 is definitely going to break this)
    if [[ "$line" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
      a="${BASH_REMATCH[1]}"
    fi

    # When we have both, store them
    if [[ -n "$u" && -n "$a" ]]; then
      if [[ -z "${POOL_HOST_UUIDS[$a]+x}" ]]; then
        POOL_HOST_IPS+=("$a")
      fi
      POOL_HOST_UUIDS["$a"]="$u"
      u=""
      a=""
    fi
  done <<< "$out"
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
  for ip in "${POOL_HOST_IPS[@]}"; do
    [[ "$ip" == "$seed_host" ]] && continue
    all_ips+=("$ip")
  done

  for ip in "${all_ips[@]}"; do
    local gb
    gb="$(run_remote "$ip" "$pass" "awk '
      /^MemTotal:/ {
        # MemTotal is kB; 1 GiB = 1048576 kB
        printf \"%d\", int(($2/1048576)+0.5);
        exit
      }
    ' /proc/meminfo 2>/dev/null || echo" | tr -d '\r' | head -n 1)"
    gb="${gb//[[:space:]]/}"

    if [[ -z "$gb" || ! "$gb" =~ ^[0-9]+$ ]]; then
      mismatch=1
      continue
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
  for ip in "${POOL_HOST_IPS[@]}"; do
    local pc
    pc="$(run_remote "$ip" "$pass" "cat /etc/xensource/pool.conf 2>/dev/null || true" | tr -d '\r' | head -n 1 | awk '{$1=$1;print}')"

    if [[ "${pc,,}" == "master" ]]; then
      DETECTED_MASTER_IP="$ip"
      DETECTED_MASTER_HOSTNAME="$(get_remote_hostname "$ip" "$pass" | tr -d '\r')"
      [[ -z "$DETECTED_MASTER_HOSTNAME" ]] && DETECTED_MASTER_HOSTNAME="$ip"
      return 0
    fi
  done

  return 1
}

# --- RAM calculatios ---
load_mem_stats() {
  local host="$1"
  local pass="$2"

  local free_m
  free_m="$(run_remote "$host" "$pass" "free -m" | tr -d '\r')"

  local total_mb used_mb avail_mb
  read -r total_mb used_mb avail_mb < <(
    awk '$1 ~ /^[Mm]em:$/ {print $2, $3, $NF; exit}' <<< "$free_m"
  )

  total_mb="${total_mb:-0}"
  used_mb="${used_mb:-0}"
  avail_mb="${avail_mb:-0}"

  # fallback if/when the above fails to calc correctly for some reason
  if [[ ! "$total_mb" =~ ^[0-9]+$ ]] || (( total_mb <= 0 )); then
    local mi
    mi="$(run_remote "$host" "$pass" "awk '
      /^MemTotal:/ {t=\$2}
      /^MemAvailable:/ {a=\$2}
      END {
        if (t==0) {print \"0 0\"; exit}
        printf \"%d %d\", int(t/1024), int(a/1024)
      }
    ' /proc/meminfo" | tr -d '\r')"

    local tmb amb
    tmb="$(awk '{print $1}' <<< "$mi")"
    amb="$(awk '{print $2}' <<< "$mi")"

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
  fi

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
  run_remote "$host" "$pass" "bash -lc \"$(rpm_manifest_cmd)\""
}

get_rpm_manifest_hash_remote() {
  local host="$1"
  local pass="$2"
  run_remote "$host" "$pass" "bash -lc \"$(rpm_manifest_cmd) | (command -v sha256sum >/dev/null 2>&1 && sha256sum || md5sum) | cut -d' ' -f1\""
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
check_xcpng_version() {
  local host="$1"
  local pass="$2"

  local version
  version="$(run_remote "$host" "$pass" "grep '^VERSION=' /etc/os-release 2>/dev/null | cut -d'\"' -f2 || echo 'unknown'" | tr -d '\r' | head -n 1)"

  if [[ "$version" == "unknown" ]]; then
    printf "XCP-ng Version: %s\n" "$(yellow_text 'Unknown')"
    return 1
  fi

  # Compare version: extract major.minor (eg 8.3 from 8.3.0)
  local major minor
  major="$(echo "$version" | cut -d. -f1)"
  minor="$(echo "$version" | cut -d. -f2)"

  # Check if version >= 8.3 (8.2 is no longer supported)
  if [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]]; then
    if (( major > 8 )) || (( major == 8 && minor >= 3 )); then
      printf "XCP-ng Version: %s\n" "$(green_text "$version")"
      return 0
    fi
  fi

  printf "XCP-ng Version: %s\n" "$(yellow_text "$version")"
  return 1
}

check_uptime() {
  local host="$1"
  local pass="$2"

  local up
  up="$(run_remote "$host" "$pass" "uptime -p 2>/dev/null || true" | tr -d '\r' | head -n 1)"
  up="${up:-unknown}"
  printf "Uptime: %s\n" "$up"
  return 0
}

check_dom0_disk_usage() {
  local host="$1"
  local pass="$2"

  local df_out
  df_out="$(run_remote "$host" "$pass" "df -hP")"

  local -a bad=()
  while read -r fs size used avail usep mnt; do
    [[ "$fs" == "Filesystem" ]] && continue
    case "$fs" in tmpfs|devtmpfs|xenstore) continue ;; esac

    usep="${usep%\%}"
    [[ "$usep" =~ ^[0-9]+$ ]] || continue

    if (( usep > dom0_max_used )); then
      bad+=("${mnt} is at ${usep}%")
    fi
  done <<< "$df_out"

  if (( ${#bad[@]} == 0 )); then
    printf "XCP-ng Dom0 Disk Usage: %s\n" "$(ok)"
    return 0
  else
    local msg
    msg="$(printf "%s, " "${bad[@]}")"
    msg="${msg%, }"
    printf "XCP-ng Dom0 Disk Usage: %s - %s\n" "$(fail)" "$msg"
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
    printf "Dom0 Memory Usage: %s\n" "$(green_text "${MEM_USED_PCT}%")"
    return 0
  fi
}

check_mtu_issues() {
  local dmesg_out="$1"

  local kw
  for kw in $mtu_dmesg_keywords; do
    if grep -qiF -- "$kw" <<< "$dmesg_out"; then
      printf "MTU Issues: %s\n" "$(det_mtu)"
      return 1
    fi
  done

  printf "MTU Issues: %s\n" "$(none)"
  return 0
}

check_dmesg_content() {
  local dmesg_out="$1"
  DMESG_ISSUES_BLOCK=""

  local matches
  matches="$(
    awk -v words="$dmesg_issue_words" -v phrases="$dmesg_issue_phrases" '
      function esc_re(s,    t) { t=s; gsub(/[][(){}.*+?^$\\|]/,"\\\\&",t); return t }
      function has_word(line, w,    ww, pat) {
        ww=esc_re(w)
        pat="(^|[^[:alnum:]_])" ww "([^[:alnum:]_]|$)"
        return line ~ pat
      }
      BEGIN{
        nw=split(words, W, /[[:space:]]+/)
        np=split(phrases, P, /\|/)
        for (i=1;i<=nw;i++) W[i]=tolower(W[i])
        for (i=1;i<=np;i++) { P[i]=tolower(P[i]); gsub(/^[[:space:]]+|[[:space:]]+$/,"",P[i]) }
      }
      {
        l=tolower($0)
        gsub(/[[:space:]]+/, " ", l)

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
    printf "Dmesg Content: %s\n" "$(green_text 'Clean')"
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
    printf "OOM Events: %s\n" "$(green_text 'No')"
    return 0
  fi

  OOM_EVENTS_BLOCK="$(build_context_block "$dmesg_out" "$matches")"
  printf "OOM Events: %s\n" "$(yellow_text 'Yes, See Below')"
  return 1
}

check_crash_logs_present() {
  local host="$1"
  local pass="$2"

  local cnt
  cnt="$(run_remote "$host" "$pass" "test -d /var/crash || { echo 0; exit 0; }; find /var/crash -maxdepth 1 -type f ! -name '$crash_ignore_file' 2>/dev/null | wc -l")"
  cnt="${cnt//[[:space:]]/}"
  [[ -z "$cnt" ]] && cnt=0

  if (( cnt > 0 )); then
    printf "Crash Logs Present: %s\n" "$(yellow_text 'Yes - check /var/crash')"
    return 1
  else
    printf "Crash Logs Present: %s\n" "$(green_text 'No')"
    return 0
  fi
}

check_lacp_negotiation_issues() {
  local host="$1"
  local pass="$2"

  LACP_OUTPUT_BLOCK=""

  local out
  out="$(run_remote "$host" "$pass" "ovs-appctl lacp/show 2>/dev/null || true")"

  if [[ -z "${out//[[:space:]]/}" ]]; then
    printf "LACP Negotiation Issues: %s\n" "$(green_text 'No')"
    return 0
  fi

  local bad
  bad="$(
    awk '
      /^[[:space:]]*slave:/ {
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

  printf "LACP Negotiation Issues: %s\n" "$(green_text 'No')"
  return 0
}

check_silly_mtus() {
  local host="$1"
  local pass="$2"

  local ip_out
  ip_out="$(run_remote "$host" "$pass" "ip link show")"

  local found_nonstandard=0
  while IFS= read -r line; do
    [[ "$line" =~ ^[0-9]+:\  ]] || continue

    local ifname mtu
    ifname="$(awk '{print $2}' <<< "$line")"
    ifname="${ifname%:}"
    [[ "$ifname" == "lo" ]] && continue

    mtu="$(sed -n 's/.* mtu \([0-9]\+\) .*/\1/p' <<< "$line")"
    [[ -n "$mtu" ]] || continue

    if [[ "$mtu" != "1500" ]]; then
      found_nonstandard=1
      break
    fi
  done <<< "$ip_out"

  if (( found_nonstandard == 1 )); then
    printf "Silly MTUs: %s - Non-standard MTUs found, check \"ip a\" output\n" "$(yes)"
    return 1
  else
    printf "Silly MTUs: %s\n" "$(green_text 'OK - All 1500')"
    return 0
  fi
}

check_dns_gw_non_mgmt_pifs() {
  local host="$1"
  local pass="$2"
  local host_uuid="$3"

  local out
  out="$(run_remote "$host" "$pass" "xe pif-list params=gateway,DNS management=false host-uuid=$host_uuid 2>/dev/null || true" | tr -d '\r')"

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

  printf "DNS/GW on Non-Mgmt PIFs: %s\n" "$(green_text 'No')"
  return 0
}






# this is ipv4 only currently and will probably explode if fed v6
check_overlapping_subnets() {
  local host="$1"
  local pass="$2"

  local ip_out
  ip_out="$(run_remote "$host" "$pass" "ip -o -4 addr show 2>/dev/null || ip -o -4 address show 2>/dev/null || true" | tr -d '\r')"

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
    printf "Overlapping Subnets: %s\n" "$(green_text 'No')"
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
    printf "Overlapping Subnets: %s\n" "$(green_text 'No')"
    return 0
  fi
}

check_smapi_exceptions() {
  local smlog_out="$1"
  SMLOG_EXCEPTIONS_BLOCK=""

  local last_line
  last_line="$(
    awk '
      { l=tolower($0) }
      index(l,"except") { n=NR }
      END { if (n>0) print n }
    ' <<< "$smlog_out"
  )"

  if [[ -z "${last_line:-}" ]]; then
    printf "SMAPI Exceptions: %s\n" "$(none)"
    return 0
  fi

  local start end
  start=$(( last_line - 3 )); (( start < 1 )) && start=1
  end=$(( last_line + 3 ))

  SMLOG_EXCEPTIONS_BLOCK="$(
    awk -v s="$start" -v e="$end" 'NR>=s && NR<=e { print "  " $0 }' <<< "$smlog_out"
  )"

  printf "SMAPI Exceptions: %s\n" "$(yellow_text 'Yes, See Error Output')"
  return 1
}

check_smapi_hidden_leaves() {
  local smlog_out="$1"

  local matches
  matches="$(
    awk '
      { l=tolower($0) }
      index(l,"hidden leaf") {
        if (!seen[$0]++) print $0
      }
    ' <<< "$smlog_out"
  )"

  if [[ -z "${matches:-}" ]]; then
    printf "SMAPI Hidden Leaves: %s\n" "$(none)"
    return 0
  fi

  printf "SMAPI Hidden Leaves: %s\n" "$(found)"
  while IFS= read -r line; do
    [[ -n "$line" ]] && printf "  %s\n" "$line"
  done <<< "$matches"
  return 1
}

check_ha_enabled() {
  local host="$1"
  local pass="$2"
  local pool_uuid="$3"

  local out
  out="$(run_remote "$host" "$pass" "xe pool-list uuid=$pool_uuid params=ha-enabled" | tr -d '\r')"

  # Match on "true" or "false" anywhere in the output
  if [[ "$out" =~ false ]]; then
    printf "HA Enabled: %s\n" "$(green_text 'No')"
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

  local out
  out="$(run_remote "$host" "$pass" "bash -lc '
    line=\$(awk '\''\$4==\"Updated:\"{l=\$0} END{print l}'\'' /var/log/yum.log 2>/dev/null || true)
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
  '")"

  if [[ "${out:-}" == "NOUPDATES" ]]; then
    printf "Rebooted After Updates: %s\n" "$(green_text 'Yes')"
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
    printf "Rebooted After Updates: %s\n" "$(green_text 'Yes')"
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

  local out
  out="$(run_remote "$host" "$pass" "xe sr-list type=linstor 2>/dev/null || true")"

  if [[ -z "${out//[[:space:]]/}" ]]; then
    printf "XOSTOR In Use: %s\n" "$(green_text 'No')"
    return 0
  fi

  XOSTOR_IN_USE=1
  printf "XOSTOR In Use: %s\n" "$(yellow_text 'Yes')"

  local total_gb_int
  total_gb_int="$(awk -v g="$MEM_TOTAL_GB" 'BEGIN{printf "%d", g+0.00001}')"

  if (( total_gb_int <= xostor_min_avail_gb )); then
    printf "XOSTOR RAM: %s\n" "$(yellow_text "Not Enough: ${MEM_TOTAL_GB}G (Need >${xostor_min_avail_gb}G)")"
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

  XOSTOR_FAULTY_NODES_BLOCK=""

  local out
  out="$(run_remote "$host" "$pass" "linstor --controllers=${controllers_csv} n l 2>/dev/null || true")"

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
    XOSTOR_FAULTY_NODES_BLOCK="$out"
    printf "XOSTOR Faulty Nodes: %s\n" "$(yellow_text 'Yes, See Below')"
    return 1
  fi

  printf "XOSTOR Faulty Nodes: %s\n" "$(green_text 'No')"
  return 0
}

check_xostor_faulty_resources() {
  local host="$1"
  local pass="$2"
  local controllers_csv="$3"

  XOSTOR_FAULTY_RESOURCES_BLOCK=""

  local out
  out="$(run_remote "$host" "$pass" "linstor --controllers=${controllers_csv} r l --faulty 2>/dev/null || true")"

  local has_rows
  has_rows="$(
    awk '
      /^[[:space:]]*┊/ && $0 !~ /ResourceName/ { print "yes"; exit }
    ' <<< "$out"
  )"

  if [[ -n "$has_rows" ]]; then
    XOSTOR_FAULTY_RESOURCES_BLOCK="$out"
    printf "XOSTOR Faulty Resources: %s\n" "$(yellow_text 'Yes, See Below')"
    return 1
  fi

  printf "XOSTOR Faulty Resources: %s\n" "$(green_text 'No')"
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
  h="$(get_rpm_manifest_hash_remote "$host" "$pass" | tr -d '\r' | head -n 1)"

  if [[ -n "$h" && "$h" == "$MASTER_RPMHASH" ]]; then
    printf "Yum Patch Level: %s\n" "$(green_text 'Match')"
    return 0
  fi

  printf "Yum Patch Level: %s\n" "$(yellow_text 'Mismatch, See Below')"

  local slave_list
  slave_list="$(get_rpm_manifest_remote "$host" "$pass")"

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

  echo "$(cyan_text "== Pool Status ==")"

  if [[ -n "$DETECTED_MASTER_HOSTNAME" && -n "$DETECTED_MASTER_IP" ]]; then
    printf "Pool Master: %s\n" "$(green_text "${DETECTED_MASTER_HOSTNAME} (${DETECTED_MASTER_IP})")"
  else
    printf "Pool Master: %s\n" "$(yellow_text '(unknown)')"
  fi

  if (( POOL_RAM_MATCH == 1 )); then
    printf "Dom0 RAM Allocations: %s\n" "$(green_text 'Matched')"
  else
    printf "Dom0 RAM Allocations: %s\n" "$(yellow_text 'Mismatched')"
  fi

  if [[ -n "$MASTER_POOL_UUID" ]]; then
    check_ha_enabled "$DETECTED_MASTER_IP" "$pass" "$MASTER_POOL_UUID" || true
  else
    printf "HA Enabled: %s\n" "$(yellow_text 'Unknown')"
  fi

  load_mem_stats "$DETECTED_MASTER_IP" "$pass"
  check_xostor_in_use_and_ram "$DETECTED_MASTER_IP" "$pass" || true
  MASTER_XOSTOR_IN_USE=$(( XOSTOR_IN_USE ))


  if (( MASTER_XOSTOR_IN_USE == 1 )); then
    # Build comma-separated list of controllers for LINSTOR cmds
    local IFS=,
    local controllers_csv="${POOL_HOST_IPS[*]}"
    unset IFS
    check_xostor_faulty_resources "$DETECTED_MASTER_IP" "$pass" "$controllers_csv" || true
    check_xostor_nodes "$DETECTED_MASTER_IP" "$pass" "$controllers_csv" || true
  fi

  echo
}

get_host_uuid_by_address() {
  local host="$1"   # run xe on THIS host
  local pass="$2"
  local ip="$3"     # the address we matching

  run_remote "$host" "$pass" "xe host-list params=uuid,address 2>/dev/null || true" \
    | awk -v want="$ip" -F': ' '
        function trim(s){ gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); return s }

        /^[[:space:]]*uuid[[:space:]]*\(/    { u=trim($2) }
        /^[[:space:]]*address[[:space:]]*\(/ { a=trim($2) }

        # when we have a full record, evaluate + reset
        (u != "" && a != "") {
          if (a == want) { print u; exit }
          u=""; a=""
        }
      ' | tr -d '\r' | head -n 1
}



run_checks_for_host() {
  local ip="$1"
  local pass="$2"
  local is_master="$3"             
  local controllers_csv="$4"       # optional: for XOSTOR checks

  local hn
  hn="$(get_remote_hostname "$ip" "$pass" | tr -d '\r')"
  [[ -z "$hn" ]] && hn="$ip"

  if (( POOL_MODE == 1 )); then
    if (( is_master == 1 )); then
      echo "$(cyan_text "== Individual Hosts ==")"
      echo "$(cyan_text "$hn ($ip) (Master) Results:")"
    else
      echo
      echo "$(cyan_text "$hn ($ip) Results:")"
    fi
  else
    echo "$(cyan_text "== XCP-ng health check on: $hn ==")"
  fi

  check_xcpng_version "$ip" "$pass" || true
  check_uptime "$ip" "$pass"

  local dmesg_t smlog
  dmesg_t="$(run_remote "$ip" "$pass" "dmesg -T")"
  smlog="$(run_remote "$ip" "$pass" "test -r /var/log/SMlog && cat /var/log/SMlog || true")"

  if (( POOL_MODE == 1 )); then
    local poolconf_line
    poolconf_line="$(run_remote "$ip" "$pass" "cat /etc/xensource/pool.conf 2>/dev/null || true")"
    append_poolconf_summary "$hn" "$ip" "$poolconf_line"
  fi

  load_mem_stats "$ip" "$pass"


  local DMESG_ISSUES_BLOCK OOM_EVENTS_BLOCK LACP_OUTPUT_BLOCK SMLOG_EXCEPTIONS_BLOCK XOSTOR_FAULTY_RESOURCES_BLOCK

  local hostlabel="${hn} (${ip})"
  local rc_any=0

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


  # NEW TEST call
  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_overlapping_subnets; then
    if ! check_overlapping_subnets "$ip" "$pass"; then rc_any=1; fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_smapi_exceptions; then
    if ! check_smapi_exceptions "$smlog"; then rc_any=1; fi
    if [[ -n "$SMLOG_EXCEPTIONS_BLOCK" ]]; then
      append_details "$hostlabel" "SMlog Exceptions" "$SMLOG_EXCEPTIONS_BLOCK"
    fi
  fi

  if (( POOL_MODE == 0 )) || (( is_master == 1 )) || should_run_in_pool_for_slave pool_run_smapi_hidden_leaves; then
    if ! check_smapi_hidden_leaves "$smlog"; then rc_any=1; fi
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

  if (( $# >= 2 )) && [[ "${!#}" == "single" ]]; then
    POOL_MODE=0
    set -- "${@:1:$(($#-1))}"
  fi

  [[ $# -ge 1 && $# -le 2 ]] || usage

  parse_target_host_and_port "$1"
  local seed_host="$PARSED_HOST"

  ensure_sshpass

  local pass=""
  if [[ $# -eq 2 ]]; then
    pass="$2"
  else
    pass="$(get_password_from_xoa_db_simple "$seed_host" || true)"
    if [[ -z "$pass" ]]; then
      echo "Host IP not found in xo-db, please manually provide a password, or check that the IP is the master host and not a slave"
      exit 1
    fi
  fi

  POOL_HOST_IPS=()
  get_pool_host_addresses "$seed_host" "$pass"

  if (( ${#POOL_HOST_IPS[@]} == 0 )); then
    echo "ERROR: Could not retrieve pool host addresses from '$seed_host'." >&2
    exit 1
  fi

  local overall_rc=0

  if (( POOL_MODE == 0 )); then
    if ! run_checks_for_host "$seed_host" "$pass" 1 ""; then overall_rc=1; fi
  else
    if ! detect_pool_master_by_poolconf "$pass"; then
      echo "ERROR: Could not determine pool master (no host had 'master' in /etc/xensource/pool.conf)." >&2
      exit 1
    fi

    MASTER_POOL_UUID="$(get_pool_uuid "$DETECTED_MASTER_IP" "$pass")"
    compute_pool_ram_match "$DETECTED_MASTER_IP" "$pass"

    MASTER_RPMLIST="$(get_rpm_manifest_remote "$DETECTED_MASTER_IP" "$pass")"
    MASTER_RPMHASH="$(get_rpm_manifest_hash_remote "$DETECTED_MASTER_IP" "$pass" | tr -d '\r' | head -n 1)"

    print_pool_status_section "$pass"

    if ! run_checks_for_host "$DETECTED_MASTER_IP" "$pass" 1 ""; then overall_rc=1; fi

    local ip
    for ip in "${POOL_HOST_IPS[@]}"; do
      [[ "$ip" == "$DETECTED_MASTER_IP" ]] && continue
      if ! run_checks_for_host "$ip" "$pass" 0 ""; then overall_rc=1; fi
    done

    echo
    echo "$(cyan_text "---pool.conf contents---")"
    printf "%s" "$POOLCONF_SUMMARY"
  fi

  if [[ -n "$XOSTOR_FAULTY_NODES_BLOCK" ]]; then
    echo "$(yellow_text "---xostor node status---")"
    printf "%s\n" "$XOSTOR_FAULTY_NODES_BLOCK"
  fi

  if [[ -n "${DETAILS_OUTPUT//[[:space:]]/}" ]]; then
    printf "%s\n" "$DETAILS_OUTPUT"
  fi

  exit "$overall_rc"
}

main "$@"
