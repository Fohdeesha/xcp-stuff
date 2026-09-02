# xcp-stuff
Home of the XCP-ng infra health check script & misc xcp tooling

## how to use
```
# from XOA as root (no args = interactive menu to choose pool):
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.py)

# With args:
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.py) -n mainpool
```
That first command works just the same run directly on an XCP-ng host as root - the script
looks at `/etc/os-release` to see where it is and adapts. See
[Running it on an XCP-ng host](#running-it-on-an-xcp-ng-host-instead-of-xoa) below for what
differs there (`-n` is the one flag that doesn't apply, it needs XOA's database).

It has to be root in both places. On XOA the pool list and root passwords come out of
`xo-server-db`, which only root can read, and `xoa check` needs root as well - so run as the
`xoa` user it stops and says so rather than guessing. Become root first with `sudo -i`, then
run the one-liner; `sudo python3 <(curl ...)` on its own does not work, because sudo closes
the file descriptor the `<( )` opens.

Run health.py on an XOA appliance with no arguments, it will pull pool/host information from XOA's database.

- If XOA is connected to more than one pool, it lists the enabled pools and asks which one to check
- You can also provide a pool's name or part of a name with "-n", (for example, "-n pri" would match XEN-PRIMARY) or by giving the IP of the pool master directly
- Providing the password is not necessary, it will be pulled from XOA
- If the host/pool is not in XOA, you can manually specify the pool master IP and password
- If the host it's checking is part of a pool, it will health check every pool member, unless you provide "-s" for single host check only
```
[03:34 14] xoa:~$ ./health.py --help
Usage:
  health.py [-f] [-s] [-n name] [pool_master_or_host[:ssh_port] [root_password]]

  - All parameters are optional
  - If a host is not supplied, the enabled pools in xo-server-db are listed to pick from
    (a single enabled pool, or non-interactive use, just takes the first one)
  - If a password is not supplied, it will be looked up locally in xo-server-db
  - By default, the script runs in pool mode (checks all hosts in the pool)
  - Use '-f' flag to filter output to only show issues found
  - Use '-s' flag to only check the specified host (do not check other pool members if present)
  - Use '-n' to pick a pool from xo-server-db by name instead of being prompted:
    the first pool whose name contains the text is used, matched anywhere in the
    name and ignoring case, so '-n sec' matches 'XEN-SECONDARY'
  - Use '--json' to print the results as a JSON document instead of a report, for
    cron and monitoring. Same checks, same exit code; '-f' narrows it the same way,
    and everything that is not the document goes to stderr

  Examples:
  health.py 192.168.1.5
  health.py 192.168.1.6 'mypass'
  health.py -s 192.168.1.7 'mypass'
  health.py -n sec
  health.py -f -n 'xen-main'
  health.py --json -n sec
  ```

Exit code is **0** when everything passed, **1** when any check flagged, **2** for a usage
error - so a wrapper or cron job can tell "you typed the flag wrong" from "the pool has a
problem". Nothing is installed and nothing is written on the hosts; the only exception is
`sshpass`, and only in the one case described below.

## Requirements

Python 3 only - no pip, no modules to install, nothing outside the standard library.

| | needs |
|---|---|
| XOA (Debian 11+) | `python3` (Debian ships it; XOA has 3.11) |
| XCP-ng / XenServer host, 8.3+ | `python3` (dom0 ships 3.6.8) |
| XCP-ng hosts being *checked from XOA* | nothing - the collector runs under the `python` that every dom0 has, 8.2.1 included |

**XCP-ng 8.2.1 dom0 has no `python3`**, so health.py cannot be run *on* an 8.2 host. Checking
an 8.2.1 **pool from XOA** works exactly as it always has. For host mode on 8.2.1, use the
frozen `health.sh` (v2.8) that lives beside it in this repo:

```
# on an 8.2.1 host only:
bash <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.sh)
```

## Running it on an XCP-ng host instead of XOA

The same script can be run directly on a host - it looks at `/etc/os-release` and adapts.
Useful when there is no XOA to hand, or when XOA cannot reach the pool.

```
# on the host, as root (8.3 or newer):
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.py)
```

- **This host is always checked**, using local commands - no ssh and no password involved.
- **The rest of the pool is checked too if you give a root password.** Pool members share
  the master's root password, so one covers the pool. With a terminal you are simply asked
  for it; you can also pass it as an argument, though the prompt is preferable since an
  argument is visible in `ps` and lands in your shell history. dom0 has no `sshpass`, so
  the script installs it the same way it does on XOA - from the stock `extras` repo
  (Vates' own mirror, already configured, just disabled), a 21KB package with no
  dependencies. `--enablerepo` is one-shot, so the host's yum config is left as it was.
- **With no password it checks this host alone and says so** - a `Hosts in Pool` line
  reports how much of the pool the run covered. Cron and piped runs take this path rather
  than hanging on a prompt.
- Pool-level results (pool master, HA, XOSTOR, VLAN 0, migration/backup network, migration
  compression, missing patches) are reported either way - those are `xe` queries, and xapi
  answers them from any pool member, slaves included.
- The XOA section is never printed (there is no appliance). Running on a host with a
  password otherwise produces the same report an XOA run does for that pool.
- `-f` and `-s` apply as usual; `-n` is XOA-only and is rejected with an explanation.

## Machine-readable output

`--json` prints the same run as one JSON document instead of a report. Same checks, same
exit code, and the document is the only thing on stdout - the banner, prompts and warnings
all go to stderr, so `health.py --json -n sec | jq` works with nothing to strip first.

```json
{
  "script_version": "3.1",
  "run": { "environment": "xoa", "pool_mode": true, "filtered": false,
           "target": "192.168.1.13", "pool_name": "XEN-SECONDARY",
           "hosts_in_pool": 2, "hosts_attempted": 2, "hosts_checked": 1 },
  "xoa":  { "checks": [ ... ] },
  "pool": { "checks": [ ... ] },
  "hosts": [
    { "name": "xen-sec-01", "address": "192.168.1.13", "master": true, "reachable": true,
      "pool_conf": "master",
      "checks": [
        { "key": "Dom0 Disk Usage", "value": "OK", "status": "ok", "flags": false },
        { "key": "Log Errors", "value": "Yes, See Error Output", "status": "flag",
          "flags": true, "detail": { "title": "Log Errors", "text": "..." } }
      ] },
    { "name": "xen-sec-02", "address": "192.168.1.34", "master": false,
      "reachable": false, "error": "ssh to 192.168.1.34 failed (exit 255): ..." }
  ],
  "flagged": true,
  "exit_code": 1
}
```

Worth knowing:

- **`flags` is the field to alert on**, not the colour and not `status`. A yellow line is
  usually a finding, but `XOSTOR In Use: Yes` and a backslash in the root password are
  facts rather than problems, and `flags` already encodes that rule.
- **A host that could not be reached has no `checks` key at all** - not an empty one. An
  empty list sums to zero findings, which is exactly the "looks healthy because we never
  looked" claim the whole script is built to avoid. Check `reachable` and `error`.
- **The three host counts are all reported** because they routinely differ: how many
  members the pool has, how many this run put in scope (`-s`, a solo host run), and how
  many actually answered.
- **`-f` narrows the document exactly as it narrows the report** - so it still contains the
  always-printed informational lines. For findings only, filter on `flags`, which is
  cheaper and does not depend on how the run was invoked.
- **There is no timestamp in the document**, deliberately: two runs of an unchanged pool
  produce identical output, so diffing one against the last one says something.
- On a usage error nothing is written to stdout at all, so stdout is always either a whole
  valid document or empty - never a fragment that fails to parse for an invisible reason.

## How it works

Every host is asked **once**, and the hosts are asked **at the same time** - up to eight at
a time by default (`HEALTH_MAX_PARALLEL` changes it, `=1` makes it strictly sequential).
The script ships a small collector to each host over ssh stdin (or runs it locally, in host
mode), and the collector answers with one JSON document holding every fact the report
needs. Nothing is written to the host, no shell quoting is involved, and each fact says
either "here is the value" or "here is why I could not get it" - which is what keeps the
report from ever printing a green line for something it never established.

Collecting and reporting are separate passes, so running the hosts concurrently changes
the wall clock and nothing else: the report is still written host by host, in order, and
reads identically either way.

The `== XOA Status ==` section - the appliance checking itself - runs on its own thread
alongside the pool and is printed **last**, after the hosts. It shares nothing with them,
so there is no reason for its `xoa-updater` and `xoa check` calls to stand in front of
results that are ready. Measured across three pools, that turned 2.9 s of blocking into a
0-1.3 s wait at the very end, depending on how much host work there was to hide it behind.
`xo-server-db` is likewise read exactly once per run: one `ls server` returns every record,
password field included, and costs the same as a narrower query, so the second call the
password lookup used to make was re-reading what was already in hand. Between them those
two changes took a typical run from 11-13 s to 6 s.

The collector is written to the Python 2.7 / 3.6 intersection on purpose: 8.2.1 dom0 has
only `python` (2.7.5), 8.3 has both, and that is what keeps 8.2.1 pools checkable from XOA.

## Repo layout

| | |
|---|---|
| `health.py` | the published artifact - one file, no install. **Generated**; do not edit |
| `src/` | the sources it is built from, one module per concern |
| `build/stitch.py` | builds `health.py` from `src/`; fails the build on a name collision or a collector that does not round-trip |
| `tests/` | pytest, no network or hosts needed |
| `health.sh` | the previous bash implementation, frozen at v2.8. Kept as the 8.2.1 host-mode fallback and the rollback path |

```
python build/stitch.py     # rebuild health.py after changing src/
python -m pytest tests/    # ~220 tests, all offline
```

You don't have to remember that first line. Push a change to `src/` and GitHub rebuilds
`health.py` and commits it back to the branch - merging a PR does it too. So `git pull`
after a push that touched `src/`.

  ## Example Output

![Alt text](example-output.png)
