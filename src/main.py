# -*- coding: utf-8 -*-
"""Argument handling and the shape of a run.

Collection and rendering are two phases: every host is gathered first, then the whole
report is written. That is what lets the Pool Status section state reachability before
the per-host blocks appear, and it is why one broken host cannot leave a half-printed
section behind it.

It is also what lets the gathering run several hosts at a time without moving a line of
output: the report is written afterwards, from run.hosts in order, so the concurrency is
a wall-clock change and nothing else.

The '== XOA Status ==' section is the same idea taken one step further. It asks the
appliance about itself and shares nothing with the pool, so it runs on its own thread from
the moment the target is known and is printed LAST, after the hosts. It used to run at
render time and print first: ~2.9s spent after every host had already answered, in front
of results that had been ready the whole time.
"""

import atexit
import getopt
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import checks
import colors
import config
import model
import parsers
import report
import result
import transport
import xoa
import xodb

USAGE_XOA = """Usage:
  %(prog)s [-f] [-s] [-n name] [-c 'command'] [pool_master_or_host[:ssh_port] [root_password]]

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
  - Use '-c command' to run an arbitrary command on every reachable pool host
    instead of the health report, and print each host's output
  - Use '--json' to print the results as a JSON document instead of a report, for
    cron and monitoring. Same checks, same exit code; '-f' narrows it the same way,
    and everything that is not the document goes to stderr

  Examples:
  %(prog)s 192.168.1.5
  %(prog)s 192.168.1.6 'mypass'
  %(prog)s -s 192.168.1.7 'mypass'
  %(prog)s -n sec
  %(prog)s -f -n 'xen-main'
  %(prog)s -c 'cat /etc/resolv.conf'
  %(prog)s --json -n sec
"""

USAGE_HOST = """Usage (running on an XCP-ng host):
  %(prog)s [-f] [-s] [root_password]

  - This host is always checked, using local commands (no ssh, no password needed)
  - The other pool members are checked too if a root password is given: they are
    reached over ssh, and sshpass is installed from the stock 'extras' repo if missing.
    Pool members share the master's root password, so one password covers the pool
  - With no password and a terminal you are asked for one; blank, or no terminal
    (cron, pipe), just checks this host and says so in the Pool Status section
  - Prefer the prompt over the argument: an argument is visible in 'ps' and lands
    in your shell history
  - Pool-level results are reported either way, since xapi answers those from any
    pool member, slave included
  - Use '-f' flag to filter output to only show issues found
  - Use '-s' flag to skip the pool-level section and only report on this host
  - Use '--json' to print the results as a JSON document instead of a report, for
    cron and monitoring. Same checks, same exit code; '-f' narrows it the same way,
    and everything that is not the document goes to stderr

  Examples:
  %(prog)s
  %(prog)s -f
  %(prog)s 'mypass'
  %(prog)s --json
"""


def usage(run_env, code=2):
    """-h goes to stdout and exits 0; usage ERRORS go to stderr and exit 2.

    2 rather than 1 matters: 1 is what a perfectly valid run returns when a check flags,
    so a wrapper or cron job could not otherwise tell a typo from a sick pool.
    """
    # Run as `python3 <(curl ...)` - the documented one-liner - argv[0] is /dev/fd/63, and
    # a usage block that calls itself '63' helps nobody
    prog = os.path.basename(sys.argv[0] or "")
    if not prog.endswith(".py"):
        prog = "health.py"
    text = (USAGE_HOST if run_env == "host" else USAGE_XOA) % {"prog": prog}
    (sys.stdout if code == 0 else sys.stderr).write(text)
    sys.exit(code)


def detect_run_env():
    """XCP-ng and XenServer dom0 both set ID=xenenterprise in /etc/os-release, which
    nothing else does. Deliberately not keyed on 'does xe exist': an XOA with the CLI
    installed would then be misread as a host, and a real host with a broken xe deserves
    a clear error rather than a silent fall-back into the XOA path."""
    try:
        with open("/etc/os-release", "r") as fh:
            text = fh.read()
    except (IOError, OSError):
        return "xoa"
    values = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    name = values.get("NAME", "")
    if (values.get("ID") == "xenenterprise"
            or name.startswith("XCP-ng") or name.startswith("XenServer")):
        return "host"
    return "xoa"


def _host_spec(with_smapi):
    return {
        "want": ["host"],
        "crash_ignore_file": config.CRASH_IGNORE_FILE,
        "coredump_dir": config.COREDUMP_DIR,
        "smapi": bool(with_smapi),
        "log_scan": {"files": config.LOG_ERROR_FILES,
                     "phrases": config.LOG_ERROR_PHRASES,
                     "context": config.LOG_ERROR_CONTEXT},
        "lun_scan": {"files": config.LUN_CHANGE_FILES,
                     "phrases": config.LUN_CHANGE_PHRASES,
                     "context": config.LOG_ERROR_CONTEXT},
        "multipath_scan": {"files": config.MULTIPATH_EVENT_FILES,
                           "phrases": config.MULTIPATH_EVENT_PHRASES,
                           "context": config.LOG_ERROR_CONTEXT},
        "multipath": {"transient": config.MULTIPATH_TRANSIENT_CHK_STATES,
                      "recheck_delay": config.MULTIPATH_RECHECK_DELAY},
    }


def _pool_spec(controllers):
    return {
        "want": ["pool", "yumcheck"],
        "controllers": controllers,
        "qcow2_max": config.XOSTOR_QCOW2_MAX_LINES,
    }


def _merge(a, b):
    merged = dict(a)
    for key, value in b.items():
        if key != "want":
            merged[key] = value
    merged["want"] = list(a.get("want", [])) + list(b.get("want", []))
    return merged


class Run(object):
    def __init__(self):
        self.run_env = detect_run_env()
        self.filter_output = False
        self.pool_mode = True
        self.name_filter = ""
        self.run_cmd = ""         # -c: a command to run on every host INSTEAD of the report
        self.json_output = False
        self.seed = ""
        self.password = ""
        self.pw_has_backslash = False
        self.host_sweep = False
        self.transport = None
        self.hosts = []
        self.pool = model.Pool()
        self.master_address = ""
        self.master_name = ""
        self.pool_name = ""
        self.pool_cmd_host = ""
        self.pool_size = 0
        self.all_addresses = []
        self.host_names = {}      # address -> xapi hostname, for EVERY pool member

    def host_solo(self):
        """On a hypervisor with nothing else reachable. This, not the run environment, is
        what the checks ask: a host WITH a password behaves exactly like an XOA run."""
        return self.run_env == "host" and not self.host_sweep

    def host_by_address(self, address):
        for host in self.hosts:
            if host.address == address:
                return host
        return None

    def master_manifest(self):
        master = self.host_by_address(self.master_address)
        if master is None:
            return ""
        f = master.fact("rpm_manifest")
        return f.value if f.ok else ""

    def parse_args(self, argv):
        try:
            opts, args = getopt.gnu_getopt(
                argv, "fhsn:c:",
                ["filter", "help", "single", "name=", "command=", "json"])
        except getopt.GetoptError as exc:
            sys.stderr.write("%s\n" % exc)
            usage(self.run_env)
        for opt, value in opts:
            if opt in ("-f", "--filter"):
                self.filter_output = True
            elif opt in ("-h", "--help"):
                usage(self.run_env, 0)
            elif opt in ("-s", "--single"):
                self.pool_mode = False
            elif opt in ("-n", "--name"):
                self.name_filter = value
            elif opt in ("-c", "--command"):
                self.run_cmd = value
            elif opt == "--json":
                self.json_output = True
        if len(args) > 2:
            usage(self.run_env)
        if self.run_cmd and self.json_output:
            # The document is a health check's shape: every entry is a Line with a status
            # and an explicit 'flags', and doc['flagged']/'exit_code' are summed from them.
            # -c reports no verdict by design, so it has nothing to put there - and a
            # consumer reading 'flagged': false off a document that judged nothing would
            # conclude the pool was healthy. Refuse rather than emit that.
            sys.stderr.write(
                "ERROR: --json describes a health check, and -c/--command runs a command "
                "and reaches\n       no verdict, so there is nothing for the document to "
                "report. Use -c on its own.\n")
            usage(self.run_env)
        return args


def notice(run, text):
    """A message the rendered report puts on stdout.

    Under --json stdout carries the document and nothing else, so these go to stderr
    instead: a consumer's stdout is then either a whole valid document or empty, never a
    mixture that fails to parse for a reason it cannot see.
    """
    (sys.stderr if run.json_output else sys.stdout).write(text)


def print_banner(run, host, name):
    """Every run names what it is about to check, before any of the slow work.

    The paths that pick silently - the sole enabled pool, and cron/pipe runs - are exactly
    the ones where this line is the only record of which pool was taken.
    """
    if name:
        notice(run, "Checking pool: %s\n" % colors.green("%s (%s)" % (name, host)))
    else:
        notice(run, "Checking host: %s\n" % colors.green(host))
    notice(run, "\n")


def require_root(run_env):
    """Both environments need root, for different reasons - and say which.

    On a hypervisor, xe / dmesg / the logs would otherwise fail one at a time and the run
    would blame the toolstack for what is really a missing sudo.

    On XOA the appliance's own login user is 'xoa', not root, so this is the FIRST thing a
    new user hits. Measured on the appliance (Debian 12): xo-server-db cannot stat
    /etc/xo-server/config.toml (EACCES - the directory has no execute bit for others), so
    every lookup answers nothing and the run used to conclude 'no enabled hosts found in
    xo-db' on an XOA with five pools; a bare host argument read as 'not in xo-db'; and
    with a host AND a password the pool was checked but the XOA section printed sudo's
    own 'a terminal is required' as an 'XOA Check' finding and could not read dmesg
    (kernel.dmesg_restrict), so no non-root run could ever be clean. Nothing here can be
    established without root, so nothing is attempted.

    'sudo python3 <(curl ...)' is not the fix, and the message says so: sudo closes the
    descriptor the process substitution opens, and python3 reports /dev/fd/63 as missing.
    """
    if xoa.running_as_root():
        return True
    if run_env == "host":
        sys.stderr.write("ERROR: this must run as root on an XCP-ng host (it reads dom0 "
                         "logs and talks to xapi).\n")
    else:
        sys.stderr.write(
            "ERROR: this must run as root on XOA: the pool list and root passwords come out of\n"
            "       xo-server-db, and 'xoa check' and dmesg need root too. Become root first\n"
            "       (sudo -i) and run it again - note that 'sudo python3 <(curl ...)' does not\n"
            "       work, because sudo closes the descriptor the <( ) opens.\n")
    return False


def _xodb_unreadable(consequence):
    """xo-server-db answered nothing and said why: report THAT - never 'no pools' or 'not
    in xo-db', which are claims about a db nobody read. Exits 1."""
    sys.stderr.write("ERROR: could not read xo-server-db (%s), so %s\n"
                     % (xodb.read_error(), consequence))
    sys.exit(1)


def resolve_target_xoa(run, args):
    """Pick a pool / take the host argument, then find a password for it."""
    if run.name_filter and len(args) > 1:
        sys.stderr.write("ERROR: -n/--name looks the host up in xo-server-db, so it takes "
                         "at most a password after it.\n")
        usage(run.run_env)

    # With one trailing argument the two readings are indistinguishable by shape and it is
    # read as a password - so '-n sec 192.168.1.5' used to try to log into the -n-matched
    # pool using an address as the password, surfacing as an authentication failure a long
    # way from the cause. Only xo-db can tell them apart: nobody's root password is one of
    # their own pool addresses.
    if run.name_filter and len(args) == 1:
        clash = xodb.pool_name_for_host(args[0])
        if clash:
            sys.stderr.write(
                "ERROR: '%s' is the address of pool '%s' in xo-server-db, but the value after\n"
                "       -n/--name is read as a password, not a host - -n already selects the pool.\n"
                "       Use either '-n %s' or the host '%s', not both.\n"
                % (args[0], clash, run.name_filter, args[0]))
            usage(run.run_env)

    selected = None
    if run.name_filter or not args:
        code, selected = xodb.select_pool(run.name_filter)
        if code == xodb.SELECT_QUIT:
            sys.stderr.write("Aborted.\n")
            sys.exit(0)
        if code == xodb.SELECT_NO_MATCH:
            sys.exit(1)
        if code == xodb.SELECT_UNREADABLE:
            _xodb_unreadable("there is no pool list to pick from.\n       Provide the pool "
                             "master's IP and root password as arguments instead.")
        if code == xodb.SELECT_NONE:
            sys.stderr.write("No host IP provided and no enabled hosts found in xo-db, "
                             "please provide a host IP as an argument\n")
            sys.exit(1)
        args = [selected.host] + list(args)

    host, port = parsers.split_host_port(args[0])
    run.seed = host
    # a picker-chosen host may carry ':port' - that is the XAPI HTTPS port XO connects on,
    # not an ssh port, so it is stripped for ssh and we stay on 22
    run.transport.ssh_port = 22 if selected or not port else port

    run.pool_name = selected.name if selected else xodb.pool_name_for_host(host)
    print_banner(run, host, run.pool_name)

    if not transport.ensure_sshpass(run.run_env):
        sys.stderr.write("ERROR: sshpass is required to reach the pool over ssh.\n")
        sys.exit(1)

    if len(args) == 2:
        run.password = args[1]
    else:
        # look the password up under the exact string xo-db keys the record by: for a
        # picker-chosen host that is its host field verbatim, ':port' and all
        db_host = selected.host if selected else host
        password, has_backslash = xodb.password_for(db_host)
        run.pw_has_backslash = has_backslash
        if not password:
            if xodb.read_error():
                # the same distinction as the picker's: 'not found' is a statement about
                # the db's contents, which were never seen
                _xodb_unreadable("no password could be looked up for %s.\n       Provide "
                                 "the root password as a second argument instead." % host)
            notice(run, "Host IP not found in xo-db, please manually provide a "
                        "password, or check that the IP is the master host and not "
                        "a slave\n")
            sys.exit(1)
        run.password = password
    run.transport.password = run.password


def resolve_target_host_mode(run, args):
    """On a hypervisor the target is this machine, so the only positional that makes sense
    is the root password for the OTHER pool members. A second one would have been a host,
    which is not selectable - saying so beats failing later with an auth error."""
    if run.name_filter:
        sys.stderr.write("ERROR: -n/--name picks a pool out of xo-server-db, which only "
                         "exists on XOA.\n")
        usage(run.run_env)
    if run.run_cmd:
        # XOA-only, like -n. There it earns its place by carrying the pool selection and
        # the root password out of xo-server-db, so a sweep needs no inventory and no
        # credentials. On a hypervisor neither exists: the command would run on this one
        # host, or on the others only if a password were typed at the prompt - which is
        # an ssh loop with extra steps, from a machine that already has a root shell.
        sys.stderr.write("ERROR: -c/--command is an XOA feature: it runs a command across "
                         "a pool using the\n       host list and root password from "
                         "xo-server-db, neither of which exists here.\n"
                         "       You already have a root shell on this host.\n")
        usage(run.run_env)
    if len(args) > 1:
        sys.stderr.write("ERROR: running on an XCP-ng host, so the host to check is this "
                         "one and cannot be chosen.\n"
                         "       The only argument accepted here is the root password of "
                         "the other pool members.\n")
        usage(run.run_env)
    return args[0] if args else ""


def prepare_host_sweep(run, argument_password):
    """Decide whether this run can also check the other pool members, and with what.

    A hypervisor has no xo-server-db to look a password up in, so it comes from the
    command line or from asking - and asking only makes sense with a terminal, so cron and
    piped runs quietly check this host alone instead of hanging on a prompt. No password
    is not an error: it is the documented single-host behaviour, and Pool Status says so.
    """
    if not run.pool_mode or run.pool_size <= 1:
        return
    password = argument_password
    if not password:
        try:
            interactive = sys.stdin.isatty()
        except (AttributeError, ValueError):
            interactive = False
        if interactive:
            import getpass
            # to stderr, like the pool picker's prompt, so it never lands in redirected
            # output; getpass does not echo, so the newline the user typed is swallowed
            sys.stderr.write("This pool has %d hosts. Root password to check the others "
                             "(blank = this host only): " % run.pool_size)
            sys.stderr.flush()
            try:
                password = getpass.getpass("")
            except (EOFError, KeyboardInterrupt):
                password = ""
            sys.stderr.write("\n")
    if not password:
        return
    if not transport.ensure_sshpass(run.run_env):
        sys.stderr.write("Continuing with this host only.\n")
        return
    run.password = password
    run.transport.password = password
    run.host_sweep = True


def discover(run):
    """Phase A: one call to the seed for the pool's host list and our own identity."""
    spec = {"want": ["pool_hosts"]}
    try:
        if run.run_env == "host":
            payload = run.transport.collect_local(spec)
        else:
            payload = run.transport.collect(run.seed, spec)
    except transport.CollectError as exc:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s': %s\n"
                         % (run.seed or "this host", exc))
        sys.exit(1)

    if run.run_env == "host":
        address = result.wrap(payload, "self_address")
        if not address.ok or not address.value:
            sys.stderr.write("ERROR: could not get this host's address from xapi "
                             "(is the toolstack running?): %s\n" % address.error)
            sys.exit(1)
        run.seed = address.value
        run.transport.local_address = address.value
        name = result.wrap(payload, "hostname")
        shown = ("%s (%s)" % (name.value, address.value)
                 if name.ok and name.value else address.value)
        print_banner(run, shown, "")

    hosts_fact = result.wrap(payload, "pool_hosts")
    if not hosts_fact.ok:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s': %s\n"
                         % (run.seed, hosts_fact.error))
        sys.exit(1)

    hosts = []
    for rec in parsers.parse_host_list(hosts_fact.value):
        if not rec["address"]:
            sys.stderr.write("Warning: pool host %s has no address in xapi; skipping it\n"
                             % rec["uuid"])
            continue
        hosts.append(model.Host(rec["address"], rec["uuid"], rec["hostname"],
                                rec["enabled"], rec["multipathing"]))
    if not hosts:
        sys.stderr.write("ERROR: Could not retrieve pool host addresses from '%s'.\n"
                         % run.seed)
        sys.exit(1)

    run.pool_size = len(hosts)
    run.all_addresses = [h.address for h in hosts]
    # every member's name while the whole pool is in hand: a solo run narrows the list
    # to this machine, and the XOSTOR controller may be a host it never looks at
    run.host_names = dict((h.address, h.hostname) for h in hosts if h.hostname)

    # the seed's own pool.conf names the master outright, whether we are it or not - and
    # it stays truthful when the toolstack is wedged, which is why it is read rather than
    # xapi being asked
    conf = result.wrap(payload, "pool_conf")
    role, master = parsers.parse_pool_conf(conf.value if conf.ok else "")
    if role == "master":
        # pool.conf says only "master" - it carries no address - so the seed stands in for
        # one. That address is whatever was dialled, which on a master with a secondary
        # network need not be the address xapi publishes in host-list; every later
        # comparison is against that published address, so resolve the seed to its own
        # host record and prefer what xapi calls it.
        run.master_address = run.seed
        self_uuid = result.wrap(payload, "self_uuid")
        if self_uuid.ok and self_uuid.value:
            for host in hosts:
                if host.uuid == self_uuid.value:
                    run.master_address = host.address
                    break
    elif role == "slave":
        run.master_address = master

    # Name the master from xapi's host record here, while the WHOLE pool is still in hand:
    # a solo run narrows the list to this machine, and the master it names may be a host
    # this run never looks at - or cannot reach at all.
    for host in hosts:
        if host.address == run.master_address:
            run.master_name = host.hostname
    return hosts


def _collect_one(run, host, pool_spec):
    """Gather one host. Anything it wants said is RETURNED, not printed.

    A worker thread writing straight to stderr would interleave the messages in whatever
    order the hosts happened to finish, which is not reproducible between runs; the caller
    writes them out in host order instead.
    """
    # is_master is already settled (see main): it decides which checks run for this
    # host, and therefore what has to be collected for them
    spec = _host_spec(with_smapi=(not run.pool_mode or host.is_master
                                  or config.POOL_RUN["smapi_hidden_leaves"]))
    if run.pool_mode and host.address == run.pool_cmd_host:
        spec = _merge(spec, pool_spec)
    note = ""
    try:
        host.payload = run.transport.collect(host.address, spec)
    except transport.CollectError as exc:
        host.error = str(exc)
        note = "Failed when trying to check %s: %s\n" % (host.address, exc)
    host.local_now = _now()
    return note


def parallel_workers(host_count):
    """How many hosts to gather at once.

    Capped because the win is had by the time a handful are in flight, while the cost of
    lifting the cap is real: every host in flight is an ssh process, a ControlMaster
    socket and a collector holding a whole host's document in memory. HEALTH_MAX_PARALLEL
    overrides it, and =1 restores the strictly sequential order - which is how the two are
    diffed against each other.
    """
    limit = config.MAX_PARALLEL_HOSTS
    override = os.environ.get("HEALTH_MAX_PARALLEL", "")
    if override.isdigit() and int(override) > 0:
        limit = int(override)
    return max(1, min(limit, host_count))


def _collect_in_parallel(run, pool_spec, workers):
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [pool.submit(_collect_one, run, host, pool_spec) for host in run.hosts]
        try:
            return [f.result() for f in futures]
        except BaseException:
            # named and immediately re-raised, so this is not a swallowed error: the
            # workers are blocked in communicate() and cannot see a ctrl-C, so without
            # this the shutdown below would wait out every collector still running
            transport.kill_all_children()
            raise
    finally:
        pool.shutdown(wait=True)


def collect_hosts(run):
    """Phase B: one call per host, several hosts at a time.

    The pool-level questions ride along on the host they are asked of, so the usual case
    is exactly one round trip per host. Hosts are wholly independent of each other - each
    is its own ssh connection, its own collector process and its own slice of the
    document - so gathering them concurrently changes nothing but the wall clock.
    """
    controllers = run.all_addresses if run.host_solo() else [h.address for h in run.hosts]
    pool_spec = _pool_spec(controllers)

    workers = parallel_workers(len(run.hosts))
    transport.debug("collecting %d host(s), %d at a time" % (len(run.hosts), workers))
    if workers > 1:
        notes = _collect_in_parallel(run, pool_spec, workers)
    else:
        notes = [_collect_one(run, host, pool_spec) for host in run.hosts]
    for note in notes:
        if note:
            sys.stderr.write(note)

    if run.pool_mode:
        cmd_host = run.host_by_address(run.pool_cmd_host)
        if cmd_host is not None and cmd_host.reachable:
            run.pool.payload = cmd_host.payload.get("pool") or {}
            run.pool.payload["yum_check"] = cmd_host.payload.get("yum_check") or {
                "ok": False, "error": "not collected"}
        else:
            # the host we meant to ask is unreachable - xapi answers pool-wide questions
            # from any member, so ask one we can reach rather than losing the section
            _collect_pool_elsewhere(run, pool_spec)


def _collect_pool_elsewhere(run, pool_spec):
    for host in run.hosts:
        if not host.reachable:
            continue
        try:
            payload = run.transport.collect(host.address, pool_spec)
        except transport.CollectError as exc:
            sys.stderr.write("Failed when trying to read pool state from %s: %s\n"
                             % (host.address, exc))
            continue
        run.pool.payload = payload.get("pool") or {}
        run.pool.payload["yum_check"] = payload.get("yum_check") or {
            "ok": False, "error": "not collected"}
        run.pool_cmd_host = host.address
        return
    run.pool.error = "no reachable pool member to ask"


def _run_command_one(run, host):
    """Run the -c command on one host. Returns (rc, out, err); nothing is printed here.

    Same reason _collect_one returns its note instead of writing it: this is called from
    worker threads, and a thread printing as it finishes would interleave the hosts in
    whatever order they happened to answer.
    """
    try:
        return run.transport.run_command(host.address, run.run_cmd)
    except Exception as exc:                      # a transport that could not even start
        return (255, "", str(exc))


def run_command_on_all_hosts(run):
    """-c/--command: run one command on every host being checked and print what each said.

    A reporting helper, not a check. It takes no part in the exit code and none in -f:
    the caller asked for raw output, not a pass/fail verdict, so this always exits 0 -
    with several hosts there is no single code that could mean anything, and 1 and 2 are
    already spoken for ('a check flagged' and 'you typed it wrong').

    Hosts are labelled by address and not by name: the name is a fact this mode never
    collects, and fetching it would be a second round trip per host for a label.

    The host list is whatever the run settled on, so -s and a host run with no password
    narrow this exactly as they narrow the report.
    """
    workers = parallel_workers(len(run.hosts))
    transport.debug("running -c on %d host(s), %d at a time" % (len(run.hosts), workers))
    if workers > 1:
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = [pool.submit(_run_command_one, run, host) for host in run.hosts]
            try:
                results = [f.result() for f in futures]
            except BaseException:
                # the workers are blocked in communicate() and never see the ctrl-C
                transport.kill_all_children()
                raise
        finally:
            pool.shutdown(wait=True)
    else:
        results = [_run_command_one(run, host) for host in run.hosts]

    # printed in host order, whatever order they finished in
    for host, (rc, out, err) in zip(run.hosts, results):
        sys.stdout.write(colors.cyan("== %s ==" % host.address) + "\n")
        if rc == 0:
            if out:
                sys.stdout.write(out if out.endswith("\n") else out + "\n")
        else:
            # stdout first: a command that failed part way through still said something,
            # and bash printed it too rather than throwing it away
            if out:
                sys.stdout.write(out if out.endswith("\n") else out + "\n")
            if rc == 124:
                sys.stdout.write(colors.yellow(
                    "Command timed out after %ds" % config.RUN_CMD_TIMEOUT) + "\n")
            else:
                sys.stdout.write(colors.yellow("Command failed (exit code %d)" % rc) + "\n")
            # the reason goes to stderr, where every other transport failure goes, so it
            # cannot contaminate output being piped somewhere
            if err.strip():
                sys.stderr.write(err if err.endswith("\n") else err + "\n")
        sys.stdout.write("\n")
    return 0


def _now():
    import time
    return time.time()


def pool_status_section(run, rep):
    rep.heading("== Pool Status ==")
    rep.begin_section("pool")

    if run.master_address:
        name = run.master_name or run.master_address
        rep.add(result.info("Pool Master", "%s (%s)" % (name, run.master_address)))
    else:
        rep.add(result.info("Pool Master", "(unknown)", "yellow"))

    if run.host_solo():
        # nothing else was probed, so there is no reachability result to report and
        # nothing to compare across hosts - the RAM and time-sync lines would be claims
        # about hosts we never looked at. Say how much of the pool this run covers instead.
        if run.pool_size > 1:
            rep.add(result.info("Hosts in Pool",
                                "%d (only this host checked - give the root password to "
                                "include the others)" % run.pool_size))
        else:
            rep.add(result.info("Hosts in Pool", str(run.pool_size)))
    else:
        unreachable = [h.address for h in run.hosts if not h.reachable]
        if unreachable:
            rep.add(result.flag("Unreachable Hosts", " ".join(unreachable)))
        else:
            rep.add(result.ok("Unreachable Hosts", "None"))

        reachable = [h for h in run.hosts if h.reachable]
        rep.add(result.ok("Dom0 RAM Allocations", "Matched") if model.ram_match(reachable)
                else result.flag("Dom0 RAM Allocations", "Mismatched"))
        rep.add(result.ok("Pool Time Synchronization", "Matched") if model.ntp_match(reachable)
                else result.flag("Pool Time Synchronization", "Mismatched"))
        # like the two above, a comparison ACROSS hosts, so it belongs to the pool rather
        # than to any one host and has nothing to say when only one host was looked at
        rep.check("Multipath Path Counts", checks.multipath_path_counts, reachable)

    rep.check("HA Enabled", checks.ha_enabled, run.pool)
    rep.check("Migration Compression", checks.migration_compression, run.pool)
    rep.check("Missing Patches", checks.missing_patches, run.pool)

    if run.pw_has_backslash:
        rep.add(result.info("Root Password", "Contains Backslash", "yellow"))

    cmd_host = run.host_by_address(run.pool_cmd_host)
    memory = cmd_host.memory() if cmd_host else None
    rep.check("XOSTOR In Use", checks.xostor_in_use, run.pool)
    if run.pool.xostor_in_use():
        rep.check("XOSTOR RAM", checks.xostor_ram, run.pool, memory)
        rep.check("XOSTOR Faulty Resources", checks.xostor_faulty_resources, run.pool)
        rep.check("XOSTOR Faulty Nodes", checks.xostor_nodes, run.pool)
        rep.check("XOSTOR Controller IP", checks.xostor_controller, run.pool, run.host_names)
        rep.check("XOSTOR PrefNic", checks.xostor_pref_nic, run.pool)
        rep.check("XOSTOR QCOW2 VDIs", checks.xostor_qcow2, run.pool)

    rep.check("VLAN 0 Check", checks.vlan0, run.pool)
    rep.check("Migration Network", checks.migration_network, run.pool)
    rep.check("Backup Network", checks.backup_network, run.pool, run.run_env,
              xoa.ping_silent)
    rep.end_section()
    rep.blank()


def run_meta(run):
    """What the run itself was, for the head of a --json document.

    Three host counts, because they routinely differ and collapsing them would overclaim:
    the pool has N members, -s or a solo run may put fewer than N in scope, and of those
    some may not have answered. A consumer told only 'checked: 2' would read a run that
    reached one host of two as a clean pool. It is the same distinction the Pool Status
    section is careful to make in words.
    """
    return {"run": {
        "environment": run.run_env,
        "pool_mode": run.pool_mode,
        "filtered": run.filter_output,
        "target": run.seed,
        "pool_name": run.pool_name or None,
        "hosts_in_pool": run.pool_size,
        "hosts_attempted": len(run.hosts),
        "hosts_checked": len([h for h in run.hosts if h.reachable]),
    }}


def per_host_checks():
    """(POOL_RUN toggle, line key, check) for every gated per-host line, in print order.

    A function rather than a constant because in the stitched artifact every module body
    runs before the module aliases exist, so a top-level list mentioning `checks.x` would
    fail at import. It is also the table the tests enumerate, so a check added here cannot
    quietly skip the rule that a missing fact answers Unknown.
    """
    return [
        ("dom0_disk_usage", "Dom0 Disk Usage", checks.dom0_disk_usage),
        ("dom0_memory", "Dom0 Memory", checks.dom0_memory),
        ("mtu_issues", "MTU Issues", checks.mtu_issues),
        ("dmesg_content", "Dmesg Content", checks.dmesg_content),
        ("oom_events", "OOM Events", checks.oom_events),
        ("crash_logs_present", "Crash Logs Present", checks.crash_logs),
        ("coredumps_present", "Coredumps Present", checks.coredumps),
        ("tap_ctl_list", "Tapdisk Status", checks.tap_status),
        ("task_timeout_override", "XAPI Task Timeout Override", checks.task_timeout_override),
        ("lacp_negotiation", "LACP Negotiation Issues", checks.lacp),
        ("multipath_health", "Multipath Path Health", checks.multipath_health),
        ("multipath_events", "Multipath Path Events", checks.multipath_events),
        ("silly_mtus", "Silly MTUs", checks.silly_mtus),
        ("dns_gw_non_mgmt_pifs", "DNS/GW on Non-Mgmt PIFs", checks.dns_gw_non_mgmt_pifs),
        ("overlapping_subnets", "Overlapping Subnets", checks.overlapping_subnets),
        ("log_errors", "Log Errors", checks.log_errors),
        ("lun_assignments", "LUN Assignments", checks.lun_assignments),
        ("smapi_hidden_leaves", "SMAPI Hidden Leaves", checks.smapi_hidden_leaves),
        ("rebooted_after_updates", "Rebooted After Updates", checks.rebooted_after_updates),
    ]


def gated(run, host, name):
    """Single mode and the master always run everything; a slave in a pool sweep runs only
    what its toggle turns on, which is the entire purpose of those toggles."""
    if not run.pool_mode or host.is_master:
        return True
    return config.POOL_RUN.get(name, True)


def host_section(run, rep, host):
    """One host's block.

    The list headings only make sense when there IS a list: a solo host run has one host,
    which may well be a slave, so it gets the single-host heading rather than one that
    would announce a lone '(Master)'.
    """
    if run.pool_mode and not run.host_solo():
        if host.is_master:
            rep.heading("== Individual Hosts ==")
            rep.heading("%s (Master) Results:" % host.label)
        else:
            rep.blank()
            rep.heading("%s Results:" % host.label)
    else:
        rep.heading("== Health check on: %s ==" % host.name)

    rep.begin_section("host", host)

    # pool mode prints this in the pool status section; single mode has nowhere else to
    if not run.pool_mode and run.pw_has_backslash:
        rep.add(result.info("Root Password", "Contains Backslash", "yellow"))

    rep.check("Hypervisor Version", checks.hypervisor_version, host)
    rep.check("Last Booted", checks.last_booted, host)
    rep.check("Last Patched", checks.last_patched, host)
    rep.check("Host Enabled", checks.host_enabled, host)
    rep.check("Multipathing", checks.multipathing, host)
    rep.check("NTP", checks.ntp, host)

    if run.pool_mode:
        rep.add_poolconf(host.label, host.pool_conf_text())

    for toggle, key, fn in per_host_checks():
        if gated(run, host, toggle):
            rep.check(key, fn, host)

    # needs a second host to compare against, so single mode and a solo run skip it
    if run.pool_mode and not run.host_solo() and gated(run, host, "yum_patch_level"):
        rep.check("Yum Patch Level", checks.yum_patch_level, host, host.is_master,
                  run.master_manifest())
    rep.end_section()


class _Background(object):
    """Run one function on a thread now, collect what it returned later.

    Used for the '== XOA Status ==' section, which asks the appliance about itself and so
    shares nothing at all with the pool: not a command, not a file, not a connection. It
    used to run at render time, in front of everything it had no bearing on, and its ~2.9s
    of xoa-updater and 'xoa check' calls were 2.9s in which nothing else happened.

    Daemon, so an early sys.exit - an unreadable xo-db, a seed that would not answer -
    is not held up by a 'xoa check' with XOA_CHECK_TIMEOUT still to run. The exception is
    carried across the thread boundary and re-raised in result() rather than swallowed:
    the section blew the run up when it ran inline, and it still does - only now the host
    results are already on screen instead of being lost with it.
    """

    def __init__(self, fn):
        self._value = None
        self._error = None
        self._thread = threading.Thread(target=self._run, args=(fn,))
        self._thread.daemon = True
        self._thread.start()

    def _run(self, fn):
        try:
            self._value = fn()
        except Exception as exc:
            # not a swallowed error and not a decision: it is held so that result() can
            # raise it in the main thread, exactly as an inline call would have
            self._error = exc

    def result(self):
        """Wait for it and answer, or raise what it raised.

        Bounded by the timeouts on the individual commands - LOCAL_CMD_TIMEOUT each and
        XOA_CHECK_TIMEOUT for 'xoa check' - which are the section's designed defence
        against a wedged updater. A second deadline here would only be able to report an
        Unknown the section can already report for itself, and could cut off a slow but
        perfectly healthy answer.
        """
        self._thread.join()
        if self._error is not None:
            raise self._error
        return self._value


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    colors.init()
    run = Run()

    if run.run_env == "host":
        # dom0's PATH is complete for an interactive root shell but not under cron, and
        # several tools live in sbin. Over ssh the remote login shell did this for us.
        os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/local/sbin"
    else:
        ok_version, detected = xoa.debian_version_ok()
        if not ok_version:
            sys.stderr.write("This script requires Debian 11 or later (or an XCP-ng host). "
                             "Detected version: %s\n" % detected)
            return 1

    args = run.parse_args(argv)
    if run.json_output:
        colors.init(force_off=True)

    work_dir = transport.make_work_dir()
    # Registered before the work dir's cleanup so it runs first (atexit is LIFO): the
    # children hold the ControlPath sockets that live in it. On a run that finishes this
    # is a no-op - nothing is left running by then. It is for the exits that do not:
    # sys.exit on an unreadable xo-db or a seed that will not answer, with the XOA
    # section's daemon thread still part way through a 'xoa check'.
    atexit.register(transport.kill_all_children)
    atexit.register(transport.cleanup_work_dir, work_dir)
    run.transport = transport.Transport(run.run_env, work_dir)

    if not require_root(run.run_env):
        return 1

    argument_password = ""
    if run.run_env == "host":
        argument_password = resolve_target_host_mode(run, args)
    else:
        resolve_target_xoa(run, args)

    # The appliance's own section starts here and is not looked at again until the report
    # has nothing left to say about the pool. Here, and not at the top of main(), on
    # measurement rather than taste - 5 runs of each, on the 2-core appliance an XOA
    # actually is:
    #
    #   -n sec (2 hosts)   6.33s from the top | 6.23s here      -n east (remote)  7.04 | 6.49
    #   -n primary (1 host)     5.52          | 6.19            -s slave + pw     6.29 | 6.15
    #   -n nomatch (error)      3.95          | 3.39  (old script: 3.40)
    #
    # A wash on average, and better here in four cases of five. Started at the top it
    # spends its first 3.3s fighting xo-server-db - both are node, and there are two
    # cores - whereas from here it runs against the host collection, which is waiting on
    # ssh and leaves the CPU idle. It also leaves every exit above untouched: a pool name
    # that matched nothing, an unreadable xo-db, the interactive picker, the sshpass
    # install. Those cost the run nothing, exactly as before.
    #
    # The one case it loses is a single fast host, where there is under 2s of collection
    # to hide 2.9s of appliance behind. Do not move it back without re-measuring all five.
    xoa_worker = _Background(xoa.lines) if run.run_env != "host" else None

    hosts = discover(run)

    if run.run_env == "host":
        # now that the pool size is known, decide whether the other members can be checked
        prepare_host_sweep(run, argument_password)

    if not run.pool_mode or run.host_solo():
        hosts = _narrow_to_seed(run, hosts)
    run.hosts = hosts

    for host in hosts:
        host.is_master = bool(run.master_address and host.address == run.master_address)
    if not run.pool_mode or run.host_solo():
        # the one host we can look at gets every check, the way single mode runs them all:
        # the pool_run_* toggles exist to keep a pool SWEEP short, and there is no sweep
        # here. It may well be a slave, which is why this is not master detection.
        hosts[0].is_master = True

    # -c/--command: run the given command on every host and stop there. This is a raw
    # diagnostic dump, not the health report, so nothing below it runs - no collection,
    # no checks, and not the XOA section either: xoa_worker is a daemon thread with its
    # cleanup already registered with atexit, so it is simply never read.
    #
    # Here, and not earlier, so -c inherits the whole target-selection path exactly as the
    # report has it: the pool picked by -n or the picker, the password from xo-db, the
    # host list from discovery, and -s / a password-less host run narrowing that list.
    if run.run_cmd:
        return run_command_on_all_hosts(run)

    run.pool_cmd_host = run.seed if run.run_env == "host" else run.master_address
    if run.pool_cmd_host not in [h.address for h in run.hosts]:
        run.pool_cmd_host = run.hosts[0].address if run.hosts else ""

    collect_hosts(run)

    master = run.host_by_address(run.master_address)
    if master is not None:
        # what it calls itself, once we have actually spoken to it
        run.master_name = master.name

    rep = report.Report(run.filter_output, json_mode=run.json_output,
                        meta=run_meta(run))

    if run.pool_mode:
        pool_status_section(run, rep)
        if run.host_solo():
            host_section(run, rep, run.hosts[0])
        else:
            # A host we could not reach is named in 'Unreachable Hosts' and gets no block
            # of its own - there is nothing to report about it, and an empty block would
            # read as a host that passed everything.
            reachable = [h for h in run.hosts if h.reachable]
            ordered = ([master] if master in reachable else []) + \
                      [h for h in reachable if h is not master]
            if master not in reachable:
                # a host run names the master from the local pool.conf, so unlike the XOA
                # path it may be one we cannot reach - the heading the master carries on
                # its way past still has to appear
                rep.heading("== Individual Hosts ==")
            for host in ordered:
                host_section(run, rep, host)
            # named in 'Unreachable Hosts' and given no block of their own; the
            # document records them so a consumer walking hosts[] cannot simply not
            # see a host that was meant to be checked
            for host in run.hosts:
                if not host.reachable:
                    rep.unreachable_host(host)
        rep.print_poolconf_section()
    else:
        host_section(run, rep, run.hosts[0])

    # Last, and only now waited for. It is about the appliance rather than about the pool
    # that was asked about, so it has no business standing in front of the host results -
    # and by here it has almost always finished on its thread, making it free.
    if xoa_worker is not None:
        if not run.pool_mode:
            # every section is preceded by exactly one blank line; in pool mode the
            # pool.conf block already ends in one
            rep.blank()
        rep.begin_section("xoa")
        rep.heading("== XOA Status ==")
        rep.add_all(xoa_worker.result(), "XOA")
        rep.end_section()

    return rep.finish()


def _narrow_to_seed(run, hosts):
    """Single mode, and a solo host run, check the seed alone - for different reasons.

    -s was asked to; a solo host run has no password for the others, and those members are
    not unreachable, they are simply not being checked. Probing them would report them as
    failures.
    """
    for host in hosts:
        if host.address == run.seed:
            return [host]
    # the seed was given in a form xapi does not use (a hostname, say): keep it, with the
    # per-host map values left Unknown, exactly as before
    return [model.Host(run.seed)]


if __name__ == "__main__":
    sys.exit(main())
