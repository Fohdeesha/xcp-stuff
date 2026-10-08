# xcp-stuff
Home of the XCP-ng infra health check script & misc xcp tooling

## Repair Scripts
Both run as root on the pool master, look before they touch anything, and
ask first. Download the file and run it, don't pipe it in from curl.

**storage-state-fixer.py** (8.3 only) - for when exports, backups or VBD unplugs start failing
because of storage junk left behind (dead dom0 datapaths, stale dom0 VBDs, stuck GC flags).
`check` just reports, `fix` shows the list and asks y/N. Editing storage.db restarts xapi on
that host (VMs keep running), with HA turned off and back on around it.
```
curl -fsSLO https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/storage-state-fixer.py
python3 storage-state-fixer.py check
python3 storage-state-fixer.py fix
```
If a run gets cut off, `python3 storage-state-fixer.py recover` puts xapi and HA back. The first
time it reaches a pool host whose ssh key isn't already known, it shows the fingerprints and asks.

**snapshot-fixer.py** (8.2 and 8.3) - fixes broken snapshot links in xapi's database: a VM or
disk that isn't a snapshot but still claims to be a snapshot of something, or a disk that's a
snapshot of itself. `dry-run` shows what it would change, `rewrite` does it (stops xapi, backs
the database up, fixes it, starts xapi, HA handled), `restore-backup` puts the backup back.
```
curl -fsSLO https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/snapshot-fixer.py
python snapshot-fixer.py dry-run
python snapshot-fixer.py rewrite
```

# xo-config-recover

Exports Xen Orchestra's configuration from the command line - the same file as
*Settings → Config → Export* in the web UI - without needing xo-server. For when an update
has broken XOA and the UI you would normally export from is dead.

```
# on the XOA, as root
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/xo-config-recover.py)
```

That writes `XO-config_<UTC>.json.gz` in the current directory. Restore it later with
*Settings → Config → Import*, exactly like a web UI export.

It reads the two places xo-server keeps its config, redis and a small leveldb, straight
from the stores. Nothing has to be running except redis, and if redis is down too it reads
the last saved `dump.rdb` and tells you how old that is. One file, Python 3 standard
library only, read-only: the only thing it writes is the output.

| | |
|---|---|
| `--check` | show what would be exported and from where, write nothing |
| `--bundle` | also write a `.tar.gz` with a fresh redis dump, a copy of the leveldb and the config files - everything a rebuild might want |
| `--passphrase-file FILE` | encrypt the export like the web UI's passphrase option (imports the same way) |
| `--entries a,b` | only some sections, dependencies added like the API does |
| `-o FILE` / `-o -` | name the file, or stream it to stdout |

Exit code is **0** when the file was written, **1** with `--partial` when a section had to
be left out, **2** when nothing could be written. The export contains every pool's root
password, the same as the web UI's does - treat the file accordingly.

Verified against a real web UI export with xo-server running, with xo-server and
xoa-updater stopped, and with redis stopped: same records in every section. If XO's
credential database is encrypted (`redis.encryptCredentialDatabase`) the tool stops and
says so; decrypting it is not implemented yet.

## Infra Health Check
Checks for 100+ of the most common XOA and XCP-ng issues across entire pools. Paste this on XOA as root:

```
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.py)
```

With no args it grabs the pool list and root passwords from XOA's database and asks which
pool to check (with only one pool, or no terminal, it just takes the first). Every host in
the pool gets checked. Nothing gets installed on XOA or the hosts, not even sshpass, so an
XOA with no internet works fine too - just copy the file over.

It has to run as root. On XOA do `sudo -i` first: `sudo python3 <(curl ...)` won't work,
because sudo closes the file descriptor `<( )` opens.

Args go on the end of the one-liner:

| | |
|---|---|
| `-n NAME` | pick the pool by name instead of from the menu. Partial match, any case, so `-n sec` finds XEN-SECONDARY |
| `IP [password]` | check a pool by its master's IP (`IP:port` for a different ssh port). Password's only needed if XOA doesn't have it, e.g. `-s` on a slave |
| `-s` | only check the host you gave it, not the rest of the pool |
| `-f` | findings only. Everything that passed is hidden, so a healthy pool prints almost nothing |
| `-c CMD` | run a command on every host in the pool instead of the health check (see below) |
| `--json` | the same run as JSON, for cron/monitoring (see below) |
| `-h` | full help |

```
health.py -n sec
health.py -f -n xen-main
health.py -s 192.168.1.7 'mypass'
```

Exit code is 0 if everything passed, 1 if anything flagged, 2 if you got the arguments wrong.

### On an XCP-ng host
The same one-liner works as root on an 8.3 host, it figures out where it's running. It
always checks the host it's on, and if you give it the root password (it'll ask if you're at
a terminal) it checks the rest of the pool too. No password just means this host only. `-n`
and `-c` need XOA, so they don't work here.

8.2.1 hosts have no python3, so it can't run on them. Check 8.2 pools from XOA instead, that
works fine.

### Running a command across the pool
`-c` runs one command on every host and prints what each one said, using the same pool and
password lookup as the health check. Handy for eyeballing something pool-wide without
writing an ssh loop. XOA only.

```
$ health.py -n sec -c 'cat /etc/resolv.conf'
Checking pool: XEN-SECONDARY (192.168.1.13)

== 192.168.1.13 ==
nameserver 192.168.1.1

== 192.168.1.34 ==
nameserver 192.168.1.1
```

It hits up to 8 hosts at once with no confirmation, so use it for looking at things, not
changing them. Exit code is always 0, and it can't be combined with `--json`.

### JSON output
`--json` gives you the same checks and exit code as one JSON document. Only the JSON goes to
stdout (banner and prompts go to stderr), so `health.py --json -n sec | jq` works as is.

- Alert on each check's `flags` field, not `status` or the color
- A host it couldn't reach has `reachable: false` and no `checks` at all, so don't read a
  missing list as healthy
- `-f` trims it the same way it trims the report
- No timestamp, so two runs of an unchanged pool diff clean


### How it works
Each host gets one ssh call, up to 8 at a time. A small collector goes over ssh stdin, grabs
everything, and sends back one JSON blob, so nothing's written to the host. Every fact comes
back as either a value or the reason it couldn't get one, so the report never shows green
for something it didn't actually check. The collector also runs on python 2.7, which is how
8.2.1 pools get checked from XOA.

It only needs python3's standard library, which XOA and 8.3 hosts already have.

### Working on it
`health.py` is built from `src/`, so don't edit it directly.
```
python build/stitch.py     # rebuild health.py after changing src/
python -m pytest tests/    # all offline, no hosts needed
```
GitHub rebuilds `health.py` on every push anyway, so `git pull` after pushing a `src/`
change. The old bash `health.sh` is retired and just points here now.

### Example Output

![Alt text](example-output.png)

---

