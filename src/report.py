# -*- coding: utf-8 -*-
"""Turning Lines into the report.

The -f guard lives here and nowhere else, driven by each Line's status. In the bash
script it was a `[[ "$FILTER_OUTPUT" -eq 0 ]] &&` prefix repeated at ~50 call sites, and
four passing lines were missing it - including 'Yum Patch Level: Reference (Master)',
whose absence made -f show the master's baseline while hiding every slave's Match line,
reading as though the slaves had never been checked. Forgetting a guard is not possible
from here.
"""

import sys

import colors
import config
import result


class Report(object):
    def __init__(self, filter_output=False, stream=None):
        self.filter_output = filter_output
        self.stream = stream if stream is not None else sys.stdout
        self.flagged = False
        self._host_details = []
        self._pool_details = []
        self._poolconf = []
        self.host_label = None   # which detail bucket the current section writes into

    # -- raw output ---------------------------------------------------------------
    def write(self, text=""):
        self.stream.write(text + "\n")

    def heading(self, text):
        """Section headings always print: -f hides passing results, not structure."""
        self.write(colors.cyan(text))

    def blank(self):
        self.write("")

    # -- lines --------------------------------------------------------------------
    def add(self, line, host_label=None):
        """Print one Line (subject to -f), bank its exit-code effect and its detail blob.

        host_label=None sends any detail into the pool bucket, which prints before the
        per-host one.
        """
        if line is None:
            return
        if isinstance(line, (list, tuple)):
            for item in line:
                self.add(item, host_label)
            return
        if line.flags:
            self.flagged = True
        if line.always_print or not self.filter_output:
            self.write(line.render())
        if line.detail_text:
            if host_label is None:
                self.add_pool_detail(line.detail_title, line.detail_text)
            else:
                self.add_host_detail(host_label, line.detail_title, line.detail_text)

    def add_all(self, lines, host_label=None):
        for line in lines:
            self.add(line, host_label)

    # -- deferred blobs -----------------------------------------------------------
    def add_host_detail(self, host_label, title, content):
        self._host_details.append("\n\n\n%s\n%s\n"
                                  % (colors.yellow("%s - %s:" % (host_label, title)), content))

    def add_pool_detail(self, title, content):
        self._pool_details.append("\n\n\n%s\n%s\n" % (colors.yellow("%s:" % title), content))

    def add_poolconf(self, host_label, text):
        first = (text or "").replace("\r", "").split("\n")[0]
        self._poolconf.append("%s\n%s\n\n" % (host_label, first))

    # -- tail ---------------------------------------------------------------------
    def print_poolconf_section(self):
        self.blank()
        self.heading("---pool.conf contents---")
        self.stream.write("".join(self._poolconf))

    def finish(self):
        """Detail blobs, then the version line, which is the last line of every run.

        It can never flag, so -f prints it too - saying which script produced the report
        above is the entire point of it.
        """
        for blob in (self._pool_details, self._host_details):
            text = "".join(blob)
            if text.strip():
                self.write(text)
        self.blank()
        self.write("Health Script Version: %s"
                   % colors.green("v" + config.SCRIPT_VERSION))
        return 1 if self.flagged else 0


    # -- checks -------------------------------------------------------------------
    def check(self, key, fn, *args):
        """Run a check and add its line, turning an escaped exception into a yellow
        Unknown for that line.

        A check that blows up must not take the run down with it, and must not be
        silently skipped either - a missing line reads as 'not applicable', which is a
        claim of its own.
        """
        self.add(result.guard(key, fn, *args), self.host_label)
