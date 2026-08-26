# -*- coding: utf-8 -*-
"""Argument handling and the shape of a run.

Collection and rendering are two phases: every host is gathered first, then the whole
report is written. That is what lets the Pool Status section state reachability before
the per-host blocks appear, and it is why one broken host cannot leave a half-printed
section behind it.
"""

import atexit
import getopt
import os
import sys

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
  %(prog)s [-f] [-s] [-n name] [pool_master_or_host[:ssh_port] [root_password]]

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

  Examples:
  %(prog)s 192.168.1.5
  %(prog)s 192.168.1.6 'mypass'
  %(prog)s -s 192.168.1.7 'mypass'
  %(prog)s -n sec
  %(prog)s -f -n 'xen-main'
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

  Examples:
  %(prog)s
  %(prog)s -f
  %(prog)s 'mypass'
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


def parse_host_port(target):
    """host[:port]. Rough IPv6 avoidance: more than one colon is left alone."""
    if target.count(":") == 1 and "[" not in target:
        host, port = target.rsplit(":", 1)
        if port.isdigit() and host:
            return host, int(port)
    return target, 22


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
        self.seed = ""
        self.password = ""
        self.pw_has_backslash = False
        self.host_sweep = False
        self.transport = None
        self.hosts = []
        self.pool = model.Pool()
        self.master_address = ""
        self.master_name = ""
        self.pool_cmd_host = ""
        self.pool_size = 0
        self.all_addresses = []

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
            opts, args = getopt.gnu_getopt(argv, "fhsn:",
                                           ["filter", "help", "single", "name="])
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
        if len(args) > 2:
            usage(self.run_env)
        return args


def print_banner(host, name):
    """Every run names what it is about to check, before any of the slow work.

    The paths that pick silently - the sole enabled pool, and cron/pipe runs - are exactly
    the ones where this line is the only record of which pool was taken.
    """
    if name:
        sys.stdout.write("Checking pool: %s\n" % colors.green("%s (%s)" % (name, host)))
    else:
        sys.stdout.write("Checking host: %s\n" % colors.green(host))
    sys.stdout.write("\n")


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
        if code == xodb.SELECT_NONE:
            sys.stderr.write("No host IP provided and no enabled hosts found in xo-db, "
                             "please provide a host IP as an argument\n")
            sys.exit(1)
        args = [selected.host] + list(args)

    host, port = parse_host_port(args[0])
    run.seed = host
    # a picker-chosen host may carry ':port' - that is the XAPI HTTPS port XO connects on,
    # not an ssh port, so it is stripped for ssh and we stay on 22
    run.transport.ssh_port = 22 if selected else port

    pool_name = selected.name if selected else xodb.pool_name_for_host(host)
    print_banner(host, pool_name)

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
            sys.stdout.write("Host IP not found in xo-db, please manually provide a "
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
        print_banner(shown, "")

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

    # the seed's own pool.conf names the master outright, whether we are it or not - and
    # it stays truthful when the toolstack is wedged, which is why it is read rather than
    # xapi being asked
    conf = result.wrap(payload, "pool_conf")
    role, master = parsers.parse_pool_conf(conf.value if conf.ok else "")
    if role == "master":
        run.master_address = run.seed
    elif role == "slave":
        run.master_address = master

    # Name the master from xapi's host record here, while the WHOLE pool is still in hand:
    # a solo run narrows the list to this machine, and the master it names may be a host
    # this run never looks at - or cannot reach at all.
    for host in hosts:
        if host.address == run.master_address:
            run.master_name = host.hostname
    return hosts


def collect_hosts(run):
    """Phase B: one call per host. The pool-level questions ride along on the host they
    are asked of, so the usual case is exactly one round trip per host."""
    controllers = run.all_addresses if run.host_solo() else [h.address for h in run.hosts]
    pool_spec = _pool_spec(controllers)

    for host in run.hosts:
        # is_master is already settled (see main): it decides which checks run for this
        # host, and therefore what has to be collected for them
        spec = _host_spec(with_smapi=(not run.pool_mode or host.is_master
                                      or config.POOL_RUN["smapi_hidden_leaves"]))
        if run.pool_mode and host.address == run.pool_cmd_host:
            spec = _merge(spec, pool_spec)
        try:
            host.payload = run.transport.collect(host.address, spec)
        except transport.CollectError as exc:
            host.error = str(exc)
            sys.stderr.write("Failed when trying to check %s: %s\n" % (host.address, exc))
        host.local_now = _now()

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


def _now():
    import time
    return time.time()


def pool_status_section(run, rep):
    rep.heading("== Pool Status ==")
    rep.host_label = None

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
        rep.check("XOSTOR Controller IP", checks.xostor_controller, run.pool)
        rep.check("XOSTOR QCOW2 VDIs", checks.xostor_qcow2, run.pool)

    rep.check("VLAN 0 Check", checks.vlan0, run.pool)
    rep.check("Migration Network", checks.migration_network, run.pool)
    rep.check("Backup Network", checks.backup_network, run.pool, run.run_env,
              xoa.ping_silent)
    rep.blank()


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

    rep.host_label = host.label

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

    order = [
        ("dom0_disk_usage", "Dom0 Disk Usage", checks.dom0_disk_usage),
        ("dom0_memory", "Dom0 Memory", checks.dom0_memory),
        ("mtu_issues", "MTU Issues", checks.mtu_issues),
        ("dmesg_content", "Dmesg Content", checks.dmesg_content),
        ("oom_events", "OOM Events", checks.oom_events),
        ("crash_logs_present", "Crash Logs Present", checks.crash_logs),
        ("coredumps_present", "Coredumps Present", checks.coredumps),
        ("lacp_negotiation", "LACP Negotiation Issues", checks.lacp),
        ("silly_mtus", "Silly MTUs", checks.silly_mtus),
        ("dns_gw_non_mgmt_pifs", "DNS/GW on Non-Mgmt PIFs", checks.dns_gw_non_mgmt_pifs),
        ("overlapping_subnets", "Overlapping Subnets", checks.overlapping_subnets),
        ("log_errors", "Log Errors", checks.log_errors),
        ("lun_assignments", "LUN Assignments", checks.lun_assignments),
        ("smapi_hidden_leaves", "SMAPI Hidden Leaves", checks.smapi_hidden_leaves),
        ("rebooted_after_updates", "Rebooted After Updates", checks.rebooted_after_updates),
    ]
    for toggle, key, fn in order:
        if gated(run, host, toggle):
            rep.check(key, fn, host)

    # needs a second host to compare against, so single mode and a solo run skip it
    if run.pool_mode and not run.host_solo() and gated(run, host, "yum_patch_level"):
        rep.check("Yum Patch Level", checks.yum_patch_level, host, host.is_master,
                  run.master_manifest())
    rep.host_label = None


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

    work_dir = transport.make_work_dir()
    atexit.register(transport.cleanup_work_dir, work_dir)
    run.transport = transport.Transport(run.run_env, work_dir)

    argument_password = ""
    if run.run_env == "host":
        # From XOA every command arrived as root over ssh, so this is new ground. Without
        # the check, xe / dmesg / the logs fail one at a time and the run blames the
        # toolstack for what is really a missing sudo.
        if not xoa.running_as_root():
            sys.stderr.write("ERROR: this must run as root on an XCP-ng host (it reads "
                             "dom0 logs and talks to xapi).\n")
            return 1
        argument_password = resolve_target_host_mode(run, args)
    else:
        resolve_target_xoa(run, args)

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

    run.pool_cmd_host = run.seed if run.run_env == "host" else run.master_address
    if run.pool_cmd_host not in [h.address for h in run.hosts]:
        run.pool_cmd_host = run.hosts[0].address if run.hosts else ""

    collect_hosts(run)

    master = run.host_by_address(run.master_address)
    if master is not None:
        # what it calls itself, once we have actually spoken to it
        run.master_name = master.name

    rep = report.Report(run.filter_output)
    if run.run_env != "host":
        rep.host_label = "XOA"
        rep.heading("== XOA Status ==")
        rep.add_all(xoa.lines(), "XOA")
        rep.blank()
        rep.host_label = None

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
        rep.print_poolconf_section()
    else:
        host_section(run, rep, run.hosts[0])

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
