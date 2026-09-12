# -*- coding: utf-8 -*-
"""-c/--command: one arbitrary command on every pool host, instead of the health report.

A raw diagnostic dump and nothing else. It reaches no verdict, so it takes no part in the
exit code and none in -f, and it collects no health facts - a one-line command costs one
round trip per host rather than a full sweep.

It is its own module because that is all it is. Everything that makes -c worth having
happens before it: the pool picked by -n or the picker, the root password out of
xo-server-db, the host list from discovery, and -s narrowing it. main owns all of that and
hands the finished Run over, so what is left here is the fan-out and the printing - which
is why this can be read, and tested, without the report.
"""

import sys

from concurrent.futures import ThreadPoolExecutor

import colors
import config
import transport


def _run_one(run, host):
    """Run the -c command on one host. Returns (rc, out, err); nothing is printed here.

    Same reason _collect_one returns its note instead of writing it: this is called from
    worker threads, and a thread printing as it finishes would interleave the hosts in
    whatever order they happened to answer.
    """
    try:
        return run.transport.run_command(host.address, run.run_cmd)
    except Exception as exc:                      # a transport that could not even start
        return (TRANSPORT_FAILED, "", str(exc))


# Not an exit code any command can return: 0-255 are all reachable over ssh, and 255 in
# particular is ssh's own 'the connection failed', which is a different thing from 'the
# transport never started'. Printed as a reason, never as a number.
TRANSPORT_FAILED = -1


def execute(run, workers):
    """Run the command on every host of the run and print what each said. Always 0.

    With several hosts there is no single exit code that could mean anything, and 1 and 2
    are already spoken for ('a check flagged' and 'you typed it wrong'), so a caller that
    needs per-host success reads the output.

    Hosts are labelled by address and not by name: the name is a fact this mode never
    collects, and fetching it would be a second round trip per host for a label.

    `workers` is passed in rather than worked out here: main owns that policy (it is the
    same cap a collection runs under), and reaching back into main for it would make this
    the one module that imports main - which on the stitched artifact is the function
    main(), not a module, so it would be an AttributeError there and nowhere else.
    """
    transport.debug("running -c on %d host(s), %d at a time" % (len(run.hosts), workers))
    if workers > 1:
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = [pool.submit(_run_one, run, host) for host in run.hosts]
            try:
                results = [f.result() for f in futures]
            except BaseException:
                # the workers are blocked in communicate() and never see the ctrl-C
                transport.kill_all_children()
                raise
        finally:
            pool.shutdown(wait=True)
    else:
        results = [_run_one(run, host) for host in run.hosts]

    # printed in host order, whatever order they finished in
    for host, (rc, out, err) in zip(run.hosts, results):
        sys.stdout.write(colors.cyan("== %s ==" % host.address) + "\n")
        # stdout first either way: a command that failed part way through still said
        # something, and bash printed it too rather than throwing it away
        if out:
            sys.stdout.write(out if out.endswith("\n") else out + "\n")
        if rc != 0:
            if rc == TRANSPORT_FAILED:
                sys.stdout.write(colors.yellow("Could not run the command") + "\n")
            elif rc == 124:
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
